package collector

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// MavenCollector collects Java packages from pom.xml files.
type MavenCollector struct{}

func (c *MavenCollector) Name() string { return "maven" }

func (c *MavenCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "target" || d.Name() == ".git" || d.Name() == ".m2" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "pom.xml" {
			return nil
		}

		p, err := parseMavenProject(path, verbose)
		if err != nil {
			if verbose {
				log.Printf("[maven] error parsing %s: %v", path, err)
			}
			return nil
		}
		pkgs = append(pkgs, p...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	if verbose {
		log.Printf("[maven] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// parseMavenProject attempts to extract dependencies from a pom.xml via command,
// falling back to direct XML parsing if the command fails.
func parseMavenProject(pomPath string, verbose bool) ([]inventory.Package, error) {
	// Try Primary: mvn dependency:tree first
	pkgs, err := mavenDependencyTree(pomPath, verbose)
	if err == nil && len(pkgs) > 0 {
		return pkgs, nil
	}
	if verbose && err != nil {
		log.Printf("[maven] mvn dependency:tree failed for %s, falling back to pom.xml parsing: %v", pomPath, err)
	}

	// Fallback: Direct pom.xml parsing
	return parsePomXml(pomPath, verbose)
}

// mavenDependencyTree runs "mvn dependency:tree" in the pom.xml directory
// and parses the output to extract all dependencies (direct + transitive).
// Returns error if Maven is not available or command fails.
func mavenDependencyTree(pomPath string, verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("mvn"); err != nil {
		return nil, fmt.Errorf("mvn not found in PATH")
	}

	dir := filepath.Dir(pomPath)

	// Try: mvn dependency:tree -DoutputFormat=json (Maven 3.6.1+)
	// Falls back to text format if JSON is not available
	cmd := exec.Command("mvn", "dependency:tree", "-DoutputFormat=json", "-q")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		// Attempt JSON parsing
		if pkgs, err := parseMavenDependencyJSON(string(out), pomPath, verbose); err == nil {
			return pkgs, nil
		}
		if verbose {
			log.Printf("[maven] JSON format failed, trying text format fallback")
		}
	}

	// Fallback: Try text format (older Maven versions)
	cmd = exec.Command("mvn", "dependency:tree", "-q")
	cmd.Dir = dir
	out, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mvn dependency:tree failed: %w", err)
	}

	return parseMavenDependencyText(string(out), pomPath, verbose)
}

// parseMavenDependencyJSON parses the JSON output from "mvn dependency:tree -DoutputFormat=json"
// and extracts all dependencies (both direct and transitive).
func parseMavenDependencyJSON(jsonStr string, pomPath string, verbose bool) ([]inventory.Package, error) {
	type MavenDep struct {
		GroupID    string     `json:"groupId"`
		ArtifactID string     `json:"artifactId"`
		Version    string     `json:"version"`
		Scope      string     `json:"scope"`
		Deps       []MavenDep `json:"dependencies"`
	}

	var root MavenDep
	if err := xml.Unmarshal([]byte(jsonStr), &root); err != nil {
		// Try simple JSON parsing as fallback (mvn dependency:tree might output differently)
		return nil, fmt.Errorf("parse maven json: %w", err)
	}

	// Flatten the tree into packages
	var pkgs []inventory.Package
	visited := make(map[string]bool)

	var walk func(dep MavenDep, isDirect bool)
	walk = func(dep MavenDep, isDirect bool) {
		if dep.GroupID == "" || dep.ArtifactID == "" || dep.Version == "" {
			return
		}

		// Skip test scope
		if dep.Scope == "test" {
			return
		}

		key := dep.GroupID + ":" + dep.ArtifactID + ":" + dep.Version
		if visited[key] {
			return
		}
		visited[key] = true

		// Store groupId in package Name as "groupId:artifactId" for PURL generation
		fullName := dep.GroupID + ":" + dep.ArtifactID
		pkgs = append(pkgs, inventory.Package{
			Name:       fullName,
			Version:    dep.Version,
			RawVersion: dep.Version,
			Ecosystem:  "Maven",
			Source:     "pom.xml",
			Location:   pomPath,
			Direct:     inventory.BoolPtr(isDirect),
			Deps:       []string{},
		})

		// Recursively process transitive dependencies
		for _, childDep := range dep.Deps {
			walk(childDep, false)
		}
	}

	// Process root and its direct dependencies
	for _, dep := range root.Deps {
		walk(dep, true)
	}

	// Now enrich with license info from pom.xml
	enrichLicenses(pomPath, pkgs, verbose)

	if verbose {
		log.Printf("[maven] mvn dependency:tree (JSON) extracted %d packages from %s", len(pkgs), pomPath)
	}
	return pkgs, nil
}

// parseMavenDependencyText parses the text output from "mvn dependency:tree"
// which uses a tree format like:
//
//	groupId:artifactId:type:version
//	+- groupId:artifactId:type:version:scope
//	|  +- groupId:artifactId:type:version:scope
//	\- groupId:artifactId:type:version:scope
func parseMavenDependencyText(output string, pomPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	visited := make(map[string]bool)

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue // Skip empty lines and Maven log prefixes
		}

		// Extract the dependency from tree format: remove tree chars (+-, |, \)
		dep := strings.TrimLeft(line, "+-|\\# \t")
		dep = strings.TrimSpace(dep)

		if dep == "" || !strings.Contains(dep, ":") {
			continue
		}

		// Parse groupId:artifactId:type:version[:scope]
		parts := strings.Split(dep, ":")
		if len(parts) < 4 {
			continue
		}

		groupID := parts[0]
		artifactID := parts[1]
		version := parts[3]
		scope := ""
		if len(parts) > 4 {
			scope = parts[4]
		}

		// Skip test scope
		if scope == "test" {
			continue
		}

		// Skip duplicates
		key := groupID + ":" + artifactID + ":" + version
		if visited[key] {
			continue
		}
		visited[key] = true

		// Determine if this is a direct dependency (heuristic: appears early in the tree)
		isDirect := !strings.Contains(line, "|") && !strings.HasPrefix(strings.TrimLeft(line, "+-| "), "|")

		// Store groupId in package Name as "groupId:artifactId" for PURL generation
		fullName := groupID + ":" + artifactID
		pkgs = append(pkgs, inventory.Package{
			Name:       fullName,
			Version:    version,
			RawVersion: version,
			Ecosystem:  "Maven",
			Source:     "pom.xml",
			Location:   pomPath,
			Direct:     inventory.BoolPtr(isDirect),
			Deps:       []string{},
		})
	}

	// Enrich with license info from pom.xml
	enrichLicenses(pomPath, pkgs, verbose)

	if verbose {
		log.Printf("[maven] mvn dependency:tree (text) extracted %d packages from %s", len(pkgs), pomPath)
	}
	return pkgs, nil
}

// parsePomXml directly parses a pom.xml file to extract basic dependency information.
// This is a fallback when Maven is not available.
func parsePomXml(pomPath string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, err
	}

	type Dependency struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}

	type POM struct {
		Dependencies struct {
			Dep []Dependency `xml:"dependency"`
		} `xml:"dependencies"`
	}

	var pom POM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	var pkgs []inventory.Package
	for _, dep := range pom.Dependencies.Dep {
		if dep.GroupID == "" || dep.ArtifactID == "" || dep.Version == "" {
			continue
		}

		// Skip test scope
		if dep.Scope == "test" {
			continue
		}

		// Store groupId in package Name as "groupId:artifactId" for PURL generation
		fullName := dep.GroupID + ":" + dep.ArtifactID
		pkgs = append(pkgs, inventory.Package{
			Name:       fullName,
			Version:    dep.Version,
			RawVersion: dep.Version,
			Ecosystem:  "Maven",
			Source:     "pom.xml",
			Location:   pomPath,
			Direct:     inventory.BoolPtr(true), // Direct parsing only gets root deps
		})
	}

	// Enrich with license info
	enrichLicenses(pomPath, pkgs, verbose)

	if verbose {
		log.Printf("[maven] pom.xml parsing extracted %d packages from %s", len(pkgs), pomPath)
	}
	return pkgs, nil
}

// enrichLicenses reads license information from pom.xml and populates the License field
// for matching packages.
func enrichLicenses(pomPath string, pkgs []inventory.Package, verbose bool) {
	licenseMap := parsePomXmlLicenses(pomPath, verbose)
	for i := range pkgs {
		if license, ok := licenseMap[pkgs[i].Name]; ok {
			pkgs[i].License = license
		}
	}
}

// parsePomXmlLicenses extracts the project's license information from pom.xml.
// This is typically only present in the root project, not in dependencies.
func parsePomXmlLicenses(pomPath string, verbose bool) map[string]string {
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil
	}

	type License struct {
		Name string `xml:"name"`
		URL  string `xml:"url"`
	}

	type POM struct {
		ArtifactID string `xml:"artifactId"`
		Licenses   struct {
			License []License `xml:"license"`
		} `xml:"licenses"`
	}

	var pom POM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil
	}

	licenseMap := make(map[string]string)
	if len(pom.Licenses.License) > 0 {
		var names []string
		for _, lic := range pom.Licenses.License {
			if lic.Name != "" {
				names = append(names, lic.Name)
			}
		}
		if len(names) > 0 {
			licenseMap[pom.ArtifactID] = strings.Join(names, " OR ")
		}
	}
	return licenseMap
}

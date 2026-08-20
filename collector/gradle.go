package collector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// GradleCollector collects Java packages from Gradle build files.
type GradleCollector struct{}

func (c *GradleCollector) Name() string { return "gradle" }

func (c *GradleCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "build" || d.Name() == ".gradle" || d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}

		switch d.Name() {
		case "gradle.lockfile":
			p, err := parseGradleLockfile(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[gradle] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)

		case "build.gradle":
			p, err := parseGradleBuild(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[gradle] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)

		case "build.gradle.kts":
			p, err := parseGradleBuildKts(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[gradle] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	enrichGradleLicensesFromCache(pkgs, verbose)

	if verbose {
		log.Printf("[gradle] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// parseGradleLockfile parses gradle.lockfile (Primary source, highest priority).
// Format: groupId:artifactId:version=resolved-version (one per line)
func parseGradleLockfile(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkgs []inventory.Package
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: groupId:artifactId:version=resolved-version
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		depPart := parts[0]
		depParts := strings.Split(depPart, ":")
		if len(depParts) < 3 {
			continue
		}

		groupID := depParts[0]
		artifactID := depParts[1]
		version := depParts[2]

		fullName := groupID + ":" + artifactID
		pkgs = append(pkgs, inventory.Package{
			Name:       fullName,
			Version:    version,
			RawVersion: version,
			Ecosystem:  "Maven",
			Source:     "gradle.lockfile",
			Location:   path,
			Direct:     nil, // Unknown from lockfile alone
			Deps:       []string{},
		})
	}

	if verbose {
		log.Printf("[gradle] gradle.lockfile extracted %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// parseGradleBuild parses build.gradle (Groovy DSL) for direct dependencies.
// Fallback when gradle.lockfile is unavailable.
func parseGradleBuild(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseGradleDependencies(string(data), path, verbose)
}

// parseGradleBuildKts parses build.gradle.kts (Kotlin DSL) for direct dependencies.
// Fallback when gradle.lockfile is unavailable.
func parseGradleBuildKts(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseGradleDependencies(string(data), path, verbose)
}

// parseGradleDependencies extracts dependencies from Gradle build script (Groovy or Kotlin).
// Supports: implementation, runtimeOnly, api, compileOnly (skips test dependencies).
func parseGradleDependencies(content string, path string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	// Regex patterns for different dependency declaration styles
	// Groovy: implementation 'group:artifact:version'
	// Kotlin: implementation("group:artifact:version")
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:implementation|runtimeOnly|api|compileOnly)\s+['"]([\w\-\.]+):([\w\-\.]+):([\w\-\.]+)['"]\s*`),
		regexp.MustCompile(`(?:implementation|runtimeOnly|api|compileOnly)\s*\(\s*"([\w\-\.]+):([\w\-\.]+):([\w\-\.]+)"\s*\)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 4 {
				continue
			}

			groupID := match[1]
			artifactID := match[2]
			version := match[3]

			fullName := groupID + ":" + artifactID
			pkgs = append(pkgs, inventory.Package{
				Name:       fullName,
				Version:    version,
				RawVersion: version,
				Ecosystem:  "Maven",
				Source:     "build.gradle",
				Location:   path,
				Direct:     inventory.BoolPtr(true), // Direct parsing only gets root deps
				Deps:       []string{},
			})
		}
	}

	if verbose {
		log.Printf("[gradle] build.gradle parsing extracted %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// gradleDependenciesJSON executes "gradle dependencies --format=json" (Gradle 7.1+).
// Secondary source when gradle.lockfile is unavailable.
// Returns error if Gradle is not available or command fails.
func gradleDependenciesJSON(buildDir string, verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("gradle"); err != nil {
		return nil, fmt.Errorf("gradle not found in PATH")
	}

	cmd := exec.Command("gradle", "dependencies", "--format=json", "-q", "--no-header", "--configuration", "compileClasspath")
	cmd.Dir = buildDir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gradle dependencies failed: %w", err)
	}

	type GradleDep struct {
		Name     string       `json:"name"`
		Children []GradleDep  `json:"children,omitempty"`
	}

	type GradleConfig struct {
		Name         string      `json:"name"`
		Dependencies []GradleDep `json:"dependencies"`
	}

	type GradleOutput struct {
		Configurations []GradleConfig `json:"configurations"`
	}

	var result GradleOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse gradle json: %w", err)
	}

	var pkgs []inventory.Package
	visited := make(map[string]bool)

	var walkDeps func(dep GradleDep, isDirect bool, path string)
	walkDeps = func(dep GradleDep, isDirect bool, buildPath string) {
		name := dep.Name
		if name == "" {
			return
		}

		// Parse: groupId:artifactId:version
		parts := strings.Split(name, ":")
		if len(parts) < 3 {
			return
		}

		groupID := parts[0]
		artifactID := parts[1]
		version := parts[2]

		// Skip test scope
		if strings.Contains(version, "test") {
			return
		}

		key := groupID + ":" + artifactID + ":" + version
		if visited[key] {
			return
		}
		visited[key] = true

		fullName := groupID + ":" + artifactID
		pkgs = append(pkgs, inventory.Package{
			Name:       fullName,
			Version:    version,
			RawVersion: version,
			Ecosystem:  "Maven",
			Source:     "build.gradle",
			Location:   buildPath,
			Direct:     inventory.BoolPtr(isDirect),
			Deps:       []string{},
		})

		// Recursively process child dependencies
		for _, child := range dep.Children {
			walkDeps(child, false, buildPath)
		}
	}

	buildPath := filepath.Join(buildDir, "build.gradle")
	for _, config := range result.Configurations {
		for _, dep := range config.Dependencies {
			walkDeps(dep, true, buildPath)
		}
	}

	return pkgs, nil
}

// gradleUserHome returns $GRADLE_USER_HOME, falling back to ~/.gradle (Gradle's
// own default). Returns "" if neither is resolvable.
func gradleUserHome() string {
	if home := os.Getenv("GRADLE_USER_HOME"); home != "" {
		return home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gradle")
}

// findGradleCachedPOM locates a dependency's POM inside Gradle's module cache:
//
//	{GRADLE_USER_HOME}/caches/modules-2/files-2.1/{groupId}/{artifactId}/{version}/{sha1-hash}/{artifactId}-{version}.pom
//
// The hash directory name varies per download, so its parent is listed and each
// entry checked for the expected POM filename. Returns "" if not cached locally.
func findGradleCachedPOM(gradleHome, groupID, artifactID, version string) string {
	dir := filepath.Join(gradleHome, "caches", "modules-2", "files-2.1", groupID, artifactID, version)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	pomName := artifactID + "-" + version + ".pom"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(dir, e.Name(), pomName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// enrichGradleLicensesFromCache fills in License for packages whose POM is present
// in the local Gradle module cache (~/.gradle by default). This only helps on a
// live host that has previously run a Gradle build — the cache isn't part of a
// container image, so this is a no-op there. Best-effort: missing cache directory
// or POM leaves License as-is.
func enrichGradleLicensesFromCache(pkgs []inventory.Package, verbose bool) {
	home := gradleUserHome()
	if home == "" {
		return
	}
	if _, err := os.Stat(home); err != nil {
		return
	}

	found := 0
	for i := range pkgs {
		if pkgs[i].License != "" {
			continue
		}
		groupID, artifactID, ok := strings.Cut(pkgs[i].Name, ":")
		if !ok {
			continue
		}
		pomPath := findGradleCachedPOM(home, groupID, artifactID, pkgs[i].Version)
		if pomPath == "" {
			continue
		}
		data, err := os.ReadFile(pomPath)
		if err != nil {
			continue
		}
		if lic := parseEmbeddedPomLicense(data); lic != "" {
			pkgs[i].License = lic
			found++
		}
	}

	if verbose {
		log.Printf("[gradle] enriched %d packages with license from Gradle cache (%s)", found, home)
	}
}

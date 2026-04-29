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
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// goExcludeDirs lists directory names to skip during filesystem walk.
var goExcludeDirs = map[string]bool{
	"vendor":   true,
	".git":     true,
	"testdata": true,
}

// GoCollector collects Go module dependencies from go.mod files.
type GoCollector struct{}

func (c *GoCollector) Name() string { return "go" }

func (c *GoCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	found := false

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if goExcludeDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}

		p, err := goModulePackages(path, verbose)
		if err != nil {
			if verbose {
				log.Printf("[go] error collecting %s: %v", path, err)
			}
			return nil
		}
		pkgs = append(pkgs, p...)
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	if !found {
		p, err := goListAllInDir(scanPath, verbose)
		if err != nil {
			if verbose {
				log.Printf("[go] go list fallback failed: %v", err)
			}
		} else {
			pkgs = append(pkgs, p...)
		}
	}

	if verbose {
		log.Printf("[go] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// goModulePackages returns all modules in the dependency graph for the module
// rooted at goModPath. It prefers "go list -m -json all" (run in the module
// directory) because that includes every transitive dependency — the same set
// that govulncheck / Dependabot use. Falls back to parsing go.mod directly
// when the go binary is unavailable or the command fails.
func goModulePackages(goModPath string, verbose bool) ([]inventory.Package, error) {
	dir := filepath.Dir(goModPath)
	pkgs, err := goListAllInDir(dir, verbose)
	if err == nil && len(pkgs) > 0 {
		return pkgs, nil
	}
	if verbose && err != nil {
		log.Printf("[go] go list failed for %s, falling back to go.mod parse: %v", dir, err)
	}
	return parseGoMod(goModPath, verbose)
}

// goListAllInDir runs "go list -m -json all" in dir and returns all modules
// in the resolved dependency graph (direct + indirect + transitive).
func goListAllInDir(dir string, verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return nil, fmt.Errorf("go not found in PATH")
	}

	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list in %s: %w", dir, err)
	}

	var pkgs []inventory.Package
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	for decoder.More() {
		var mod struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Main    bool   `json:"Main"`
		}
		if err := decoder.Decode(&mod); err != nil {
			break
		}
		if mod.Main || mod.Path == "" || mod.Version == "" {
			continue
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       mod.Path,
			Version:    mod.Version,
			RawVersion: mod.Version,
			Ecosystem:  "Go",
			Source:     "go.mod",
			Location:   filepath.Join(dir, "go.mod"),
		})
	}

	if verbose {
		log.Printf("[go] go list collected %d packages from %s", len(pkgs), dir)
	}
	return pkgs, nil
}

// parseGoMod parses a go.mod file and returns the declared dependencies.
// It handles both block require directives (require (...)) and single-line
// require statements (require name version).
func parseGoMod(path string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	inRequireBlock := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Strip inline comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		// Start of a require block
		if line == "require (" || line == "require(" {
			inRequireBlock = true
			continue
		}

		// End of a require block
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock {
			pkg := parseRequireLine(line, path)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
			continue
		}

		// Single-line require: "require github.com/foo/bar v1.2.3"
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			rest = strings.TrimSpace(rest)
			// Could still be "require (" on the same line — skip
			if rest == "(" {
				inRequireBlock = true
				continue
			}
			pkg := parseRequireLine(rest, path)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
		}
	}

	if verbose {
		log.Printf("[go] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// parseRequireLine parses a single "name version" line from a require block.
func parseRequireLine(line, location string) *inventory.Package {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	name := fields[0]
	version := fields[1]

	// Skip retract, replace, and exclude directives that may appear in go.mod
	if name == "=>" || version == "=>" {
		return nil
	}

	return &inventory.Package{
		Name:       name,
		Version:    version,
		RawVersion: version,
		Ecosystem:  "Go",
		Source:     "go.mod",
		Location:   location,
	}
}


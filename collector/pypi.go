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

// pypiExcludeDirs lists directory names to skip during filesystem walk.
var pypiExcludeDirs = map[string]bool{
	".git":        true,
	"__pycache__": true,
	".tox":        true,
}

// PyPICollector collects Python packages from lock files and pip.
type PyPICollector struct{}

func (c *PyPICollector) Name() string { return "pypi" }

func (c *PyPICollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	found := false

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if d.IsDir() {
			name := d.Name()
			if pypiExcludeDirs[name] {
				return fs.SkipDir
			}
			// Exclude .venv/lib subdirectories
			if name == "lib" && strings.Contains(path, ".venv") {
				return fs.SkipDir
			}
			return nil
		}

		switch d.Name() {
		case "requirements.txt":
			p, err := parseRequirementsTxt(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[pypi] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
			found = true

		case "Pipfile.lock":
			p, err := parsePipfileLock(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[pypi] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
			found = true

		case "poetry.lock":
			p, err := parsePoetryLock(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[pypi] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
			found = true

		case "uv.lock":
			p, err := parseUVLock(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[pypi] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
			found = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	// Fallback to pip list if no lock files found
	if !found {
		p, err := pipListFallback(verbose)
		if err != nil {
			if verbose {
				log.Printf("[pypi] pip fallback failed: %v", err)
			}
		} else {
			pkgs = append(pkgs, p...)
		}
	}

	if verbose {
		log.Printf("[pypi] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// parseRequirementsTxt parses a requirements.txt file for pinned versions.
func parseRequirementsTxt(path string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Handle name==version
		if idx := strings.Index(line, "=="); idx != -1 {
			name := strings.TrimSpace(line[:idx])
			version := strings.TrimSpace(line[idx+2:])
			if name == "" {
				continue // skip separator lines like ======
			}
			// Strip extras like [security]
			if bi := strings.Index(name, "["); bi != -1 {
				name = name[:bi]
			}
			// Strip environment markers after ;
			if si := strings.Index(version, ";"); si != -1 {
				version = strings.TrimSpace(version[:si])
			}
			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    version,
				RawVersion: version,
				Ecosystem:  "PyPI",
				Source:     "requirements.txt",
				Location:   path,
			})
		}
	}
	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// parsePipfileLock parses a Pipfile.lock (JSON) for package versions.
func parsePipfileLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	var pkgs []inventory.Package
	for name, info := range lockfile.Default {
		version := strings.TrimPrefix(info.Version, "==")
		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    version,
			RawVersion: version,
			Ecosystem:  "PyPI",
			Source:     "Pipfile.lock",
			Location:   path,
		})
	}
	for name, info := range lockfile.Develop {
		version := strings.TrimPrefix(info.Version, "==")
		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    version,
			RawVersion: version,
			Ecosystem:  "PyPI",
			Source:     "Pipfile.lock",
			Location:   path,
		})
	}

	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// parsePoetryLock parses a poetry.lock (TOML-like) for package versions.
// Uses a simple line-based parser to avoid adding a TOML dependency.
func parsePoetryLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkgs []inventory.Package
	var currentName, currentVersion string

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if currentName != "" && currentVersion != "" {
				pkgs = append(pkgs, inventory.Package{
					Name:       currentName,
					Version:    currentVersion,
					RawVersion: currentVersion,
					Ecosystem:  "PyPI",
					Source:     "poetry.lock",
					Location:   path,
				})
			}
			currentName = ""
			currentVersion = ""
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			currentName = unquoteTOML(strings.TrimPrefix(line, "name = "))
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = unquoteTOML(strings.TrimPrefix(line, "version = "))
		}
	}
	// Don't forget the last package
	if currentName != "" && currentVersion != "" {
		pkgs = append(pkgs, inventory.Package{
			Name:       currentName,
			Version:    currentVersion,
			RawVersion: currentVersion,
			Ecosystem:  "PyPI",
			Source:     "poetry.lock",
			Location:   path,
		})
	}

	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// parseUVLock parses a uv.lock (TOML) file for package versions.
// The format uses [[package]] blocks with name and version fields, similar to
// poetry.lock. Entries with a virtual source (the project root itself) are skipped.
func parseUVLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkgs []inventory.Package
	var currentName, currentVersion string
	var isVirtual bool

	flush := func() {
		if currentName != "" && currentVersion != "" && !isVirtual {
			pkgs = append(pkgs, inventory.Package{
				Name:       currentName,
				Version:    currentVersion,
				RawVersion: currentVersion,
				Ecosystem:  "PyPI",
				Source:     "uv.lock",
				Location:   path,
			})
		}
		currentName = ""
		currentVersion = ""
		isVirtual = false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			flush()
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			currentName = unquoteTOML(strings.TrimPrefix(line, "name = "))
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = unquoteTOML(strings.TrimPrefix(line, "version = "))
		} else if strings.HasPrefix(line, "source = ") {
			// Virtual source means this is the project root itself — skip it
			if strings.Contains(line, "virtual") {
				isVirtual = true
			}
		}
	}
	flush() // handle last package

	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// unquoteTOML removes surrounding quotes from a TOML string value.
func unquoteTOML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// pipListFallback uses pip list --format json as a fallback.
func pipListFallback(verbose bool) ([]inventory.Package, error) {
	pipCmd := "pip3"
	if _, err := exec.LookPath(pipCmd); err != nil {
		pipCmd = "pip"
		if _, err := exec.LookPath(pipCmd); err != nil {
			return nil, fmt.Errorf("pip not found")
		}
	}

	cmd := exec.Command(pipCmd, "list", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s list failed: %w", pipCmd, err)
	}

	var pipPkgs []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &pipPkgs); err != nil {
		return nil, fmt.Errorf("parse pip output: %w", err)
	}

	pkgs := make([]inventory.Package, 0, len(pipPkgs))
	for _, p := range pipPkgs {
		pkgs = append(pkgs, inventory.Package{
			Name:       p.Name,
			Version:    p.Version,
			RawVersion: p.Version,
			Ecosystem:  "PyPI",
			Source:     "pip",
		})
	}

	if verbose {
		log.Printf("[pypi] pip fallback collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

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

	// Enrich packages with license info from installed site-packages METADATA
	licenseMap := scanSitePackagesLicenses(scanPath, verbose)
	if len(licenseMap) > 0 {
		for i := range pkgs {
			if pkgs[i].License == "" {
				if lic, ok := licenseMap[normalizePyPIName(pkgs[i].Name)]; ok {
					pkgs[i].License = lic
				}
			}
		}
	}

	if verbose {
		log.Printf("[pypi] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// parseRequirementsTxt parses a requirements.txt file for pinned versions and hashes.
// Supports both inline and continuation-line --hash= formats:
//
//	requests==2.31.0 --hash=sha256:abc123
//	cryptography==3.4.8 \
//	    --hash=sha256:abc123 \
//	    --hash=sha256:def456
func parseRequirementsTxt(path string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	scanner := bufio.NewScanner(f)

	// joinLines merges backslash-continued lines into a single logical line.
	var logical string
	flush := func() {
		line := strings.TrimSpace(logical)
		logical = ""
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		// Skip option-only lines (e.g. --index-url) that have no package name
		if strings.HasPrefix(line, "-") && !strings.Contains(line, "==") {
			return
		}
		if idx := strings.Index(line, "=="); idx == -1 {
			return
		} else {
			name := strings.TrimSpace(line[:idx])
			rest := line[idx+2:]
			if name == "" {
				return
			}
			if bi := strings.Index(name, "["); bi != -1 {
				name = name[:bi]
			}
			// version is everything up to first space or --hash
			version := rest
			if si := strings.IndexAny(rest, " \t;"); si != -1 {
				version = strings.TrimSpace(rest[:si])
				rest = rest[si:]
			} else {
				rest = ""
			}

			// Extract first --hash=algo:value
			var integrity string
			if hi := strings.Index(rest, "--hash="); hi != -1 {
				h := rest[hi+len("--hash="):]
				if end := strings.IndexAny(h, " \t\\"); end != -1 {
					h = h[:end]
				}
				integrity = strings.TrimSpace(h)
			}

			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    version,
				RawVersion: version,
				Ecosystem:  "PyPI",
				Source:     "requirements.txt",
				Location:   path,
				Direct:     inventory.BoolPtr(true),
				Integrity:  integrity,
			})
		}
	}

	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimRight(raw, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			logical += strings.TrimSpace(trimmed[:len(trimmed)-1]) + " "
		} else {
			logical += strings.TrimSpace(trimmed)
			flush()
		}
	}
	flush() // handle file not ending with newline

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

	type pipfileEntry struct {
		Version string   `json:"version"`
		Hashes  []string `json:"hashes"` // newer Pipfile.lock format
		Hash    string   `json:"hash"`   // older single-hash format
	}
	var lockfile struct {
		Default map[string]pipfileEntry `json:"default"`
		Develop map[string]pipfileEntry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	pipfileIntegrity := func(e pipfileEntry) string {
		if len(e.Hashes) > 0 {
			return e.Hashes[0]
		}
		return e.Hash
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
			Direct:     inventory.BoolPtr(true),
			Integrity:  pipfileIntegrity(info),
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
			Direct:     inventory.BoolPtr(true),
			Integrity:  pipfileIntegrity(info),
		})
	}

	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// parsePoetryLock parses a poetry.lock (TOML-like) for package versions and deps.
// Uses a two-pass line-based parser to avoid adding a TOML dependency.
// Direct/indirect distinction is not set (would require reading pyproject.toml).
func parsePoetryLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	type poetryEntry struct {
		name     string
		version  string
		depNames []string // keys from [package.dependencies]
	}

	var entries []poetryEntry
	var cur poetryEntry
	inPkgDeps := false // inside [package.dependencies] sub-section

	flushEntry := func() {
		if cur.name != "" && cur.version != "" {
			entries = append(entries, cur)
		}
		cur = poetryEntry{}
		inPkgDeps = false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			flushEntry()
			continue
		}
		// Sub-section headers inside a package block
		if strings.HasPrefix(line, "[package.") {
			inPkgDeps = line == "[package.dependencies]"
			continue
		}
		// Any other top-level section resets the context
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[") {
			inPkgDeps = false
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			cur.name = unquoteTOML(strings.TrimPrefix(line, "name = "))
		} else if strings.HasPrefix(line, "version = ") {
			cur.version = unquoteTOML(strings.TrimPrefix(line, "version = "))
		} else if inPkgDeps && strings.Contains(line, " = ") {
			// "requests = \">=2.28.0\"" or "requests = {version = ...}"
			depName := strings.TrimSpace(strings.SplitN(line, " = ", 2)[0])
			if depName != "" && depName != "python" {
				cur.depNames = append(cur.depNames, depName)
			}
		}
	}
	flushEntry()

	// Pass 1: build name→version map
	nameVer := make(map[string]string, len(entries))
	for _, e := range entries {
		nameVer[e.name] = e.version
	}

	// Pass 2: build packages
	var pkgs []inventory.Package
	for _, e := range entries {
		var deps []string
		for _, depName := range e.depNames {
			if depVer, ok := nameVer[depName]; ok {
				deps = append(deps, pypiDepPURL(depName, depVer))
			}
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       e.name,
			Version:    e.version,
			RawVersion: e.version,
			Ecosystem:  "PyPI",
			Source:     "poetry.lock",
			Location:   path,
			// Direct is nil: distinguishing requires pyproject.toml
			Deps: deps,
		})
	}

	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// parseUVLock parses a uv.lock (TOML) file for package versions and dependency tree.
// Uses a two-pass approach: first collect all name→version, then resolve dep PURLs.
// Entries with a virtual source (the project root itself) are marked as direct.
func parseUVLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	type uvEntry struct {
		name      string
		version   string
		isVirtual bool
		depNames  []string // raw dep names from dependencies = [...]
		integrity string   // from sdist or first wheel hash
	}

	var entries []uvEntry
	var cur uvEntry
	inDeps := false // inside a dependencies = [...] block

	flushEntry := func() {
		if cur.name != "" && cur.version != "" {
			entries = append(entries, cur)
		}
		cur = uvEntry{}
		inDeps = false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			flushEntry()
			continue
		}
		if line == "]" {
			inDeps = false
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			cur.name = unquoteTOML(strings.TrimPrefix(line, "name = "))
		} else if strings.HasPrefix(line, "version = ") {
			cur.version = unquoteTOML(strings.TrimPrefix(line, "version = "))
		} else if strings.HasPrefix(line, "source = ") && strings.Contains(line, "virtual") {
			cur.isVirtual = true
		} else if strings.HasPrefix(line, "sdist = ") && cur.integrity == "" {
			// sdist = { url = "...", hash = "sha256:abc", size = N }
			cur.integrity = extractUVHash(line)
		} else if (line == "wheels = [" || strings.HasPrefix(line, "wheels = [{")) && cur.integrity == "" {
			// wheels = [{ url = "...", hash = "sha256:abc", ... }]
			cur.integrity = extractUVHash(line)
		} else if strings.HasPrefix(line, "{ url = ") && cur.integrity == "" {
			// continuation wheel entry
			cur.integrity = extractUVHash(line)
		} else if line == "dependencies = [" {
			inDeps = true
		} else if inDeps && strings.HasPrefix(line, "{ name = ") {
			// { name = "certifi" } or { name = "httpcore", version-range = "..." }
			if start := strings.Index(line, `"`); start >= 0 {
				rest := line[start+1:]
				if end := strings.Index(rest, `"`); end >= 0 {
					cur.depNames = append(cur.depNames, rest[:end])
				}
			}
		}
	}
	flushEntry()

	// Collect direct dep names from virtual root entries (project root packages).
	// The virtual root's dependencies are the project's direct dependencies.
	directSet := make(map[string]bool)
	for _, e := range entries {
		if e.isVirtual {
			for _, depName := range e.depNames {
				directSet[depName] = true
			}
		}
	}

	// Pass 1: build name→version map
	nameVer := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.isVirtual {
			nameVer[e.name] = e.version
		}
	}

	// Pass 2: build packages
	var pkgs []inventory.Package
	for _, e := range entries {
		if e.isVirtual {
			continue
		}
		isDirect := directSet[e.name]
		var deps []string
		for _, depName := range e.depNames {
			if depVer, ok := nameVer[depName]; ok {
				deps = append(deps, pypiDepPURL(depName, depVer))
			}
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       e.name,
			Version:    e.version,
			RawVersion: e.version,
			Ecosystem:  "PyPI",
			Source:     "uv.lock",
			Location:   path,
			Direct:     inventory.BoolPtr(isDirect),
			Deps:       deps,
			Integrity:  e.integrity,
		})
	}

	if verbose {
		log.Printf("[pypi] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// pypiDepPURL generates a PURL for a PyPI dependency.
func pypiDepPURL(name, version string) string {
	return fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(name), version)
}

// extractUVHash extracts the first "hash = \"sha256:...\"" value from a uv.lock line.
// Used for sdist and wheels entries.
func extractUVHash(line string) string {
	const marker = `hash = "`
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(marker):]
	if end := strings.Index(rest, `"`); end >= 0 {
		return rest[:end]
	}
	return ""
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
			Direct:     inventory.BoolPtr(true),
		})
	}

	if verbose {
		log.Printf("[pypi] pip fallback collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

func normalizePyPIName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "-", "_"))
}

// scanSitePackagesLicenses walks scanPath looking for Python site-packages/dist-packages
// directories and parses *.dist-info/METADATA for license information.
// Returns a map of normalized-name → SPDX license string.
func scanSitePackagesLicenses(scanPath string, verbose bool) map[string]string {
	licenseMap := map[string]string{}

	_ = filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		// Skip irrelevant directories early
		if name == ".git" || name == "node_modules" || name == "vendor" || name == "__pycache__" {
			return fs.SkipDir
		}
		if name != "site-packages" && name != "dist-packages" {
			return nil
		}
		// Found a site-packages directory — scan its *.dist-info/METADATA files
		entries, err := os.ReadDir(path)
		if err != nil {
			return fs.SkipDir
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
				continue
			}
			metadataPath := filepath.Join(path, e.Name(), "METADATA")
			pkgName, license := parseDistInfoMetadata(metadataPath)
			if pkgName != "" && license != "" {
				licenseMap[normalizePyPIName(pkgName)] = license
			}
		}
		return fs.SkipDir
	})

	if verbose && len(licenseMap) > 0 {
		log.Printf("[pypi] found licenses for %d packages from site-packages", len(licenseMap))
	}
	return licenseMap
}

// parseDistInfoMetadata reads a METADATA file and extracts the Name and License fields.
// License-Expression (PEP 639) takes priority over the legacy License header.
func parseDistInfoMetadata(path string) (name, license string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	var legacyLicense string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Stop at the first blank line (end of headers, start of description body)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Name: ") {
			name = strings.TrimPrefix(line, "Name: ")
		} else if strings.HasPrefix(line, "License-Expression: ") {
			license = strings.TrimPrefix(line, "License-Expression: ")
		} else if strings.HasPrefix(line, "License: ") {
			legacyLicense = strings.TrimPrefix(line, "License: ")
		}
	}
	if license == "" {
		license = legacyLicense
	}
	// Skip unhelpful values
	if license == "UNKNOWN" || license == "" {
		return name, ""
	}
	return name, license
}

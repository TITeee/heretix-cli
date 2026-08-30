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

// NPMCollector collects npm packages from lock files and global npm.
type NPMCollector struct{}

func (c *NPMCollector) Name() string { return "npm" }

func (c *NPMCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	found := false

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}

		switch d.Name() {
		case "package-lock.json":
			p, err := parsePackageLock(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[npm] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
			found = true

		case "yarn.lock":
			p, err := parseYarnLock(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[npm] error parsing %s: %v", path, err)
				}
				return nil
			}
			pkgs = append(pkgs, p...)
			found = true

		case "pnpm-lock.yaml":
			p, err := parsePnpmLock(path, verbose)
			if err != nil {
				if verbose {
					log.Printf("[npm] error parsing %s: %v", path, err)
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

	// Also scan pnpm virtual stores (node_modules/.pnpm/) which exist even when
	// pnpm-lock.yaml is absent from the image (e.g. multi-stage Docker builds).
	pnpmPkgs, err := findPnpmVirtualStorePackages(scanPath, verbose)
	if err == nil && len(pnpmPkgs) > 0 {
		pkgs = append(pkgs, pnpmPkgs...)
		found = true
	}

	// Fallback to global package managers. Skipped for container image scans
	// (isContainer) and for any scan not rooted at the live filesystem's root:
	// "npm"/"pnpm" here always query this host's own global environment,
	// regardless of scanPath, so a hit outside a whole-system scan would
	// misattribute the host's globally installed packages to whatever
	// narrower path was actually being scanned.
	if !found && !isContainer && isFilesystemRoot(scanPath) {
		p, err := npmGlobalFallback(verbose)
		if err != nil {
			if verbose {
				log.Printf("[npm] global fallback failed: %v", err)
			}
		} else {
			pkgs = append(pkgs, p...)
		}

		p, err = pnpmGlobalFallback(verbose)
		if err != nil {
			if verbose {
				log.Printf("[npm] pnpm global fallback failed: %v", err)
			}
		} else {
			pkgs = append(pkgs, p...)
		}
	}

	if verbose {
		log.Printf("[npm] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// parsePackageLock parses a package-lock.json (v2/v3 format with "packages" key).
// It uses a two-pass approach to resolve dependency names to PURLs:
//
//	Pass 1 – build a name→version map from all packages entries.
//	Pass 2 – build Package structs with Direct and Deps populated.
func parsePackageLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages     map[string]packageLockEntry `json:"packages"`
		Dependencies map[string]packageLockDep   `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	var pkgs []inventory.Package

	// v2/v3 format: "packages" field
	if len(lockfile.Packages) > 0 {
		// Pass 1: build name→version lookup (first occurrence wins for multi-version packages)
		nameVer := make(map[string]string, len(lockfile.Packages))
		for key, entry := range lockfile.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			name := pkgNameFromPath(key)
			if _, exists := nameVer[name]; !exists {
				nameVer[name] = entry.Version
			}
		}

		// Collect direct dependency names from the root package entry
		directSet := make(map[string]bool)
		if root, ok := lockfile.Packages[""]; ok {
			for name := range root.Dependencies {
				directSet[name] = true
			}
			for name := range root.DevDependencies {
				directSet[name] = true
			}
		}

		// Pass 2: build packages with Direct and Deps
		lockfileDir := filepath.Dir(path)
		for key, entry := range lockfile.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			name := pkgNameFromPath(key)
			if name == "" {
				continue
			}

			isDirect := directSet[name]

			// Resolve requires → PURLs (best-effort; unresolved names are skipped)
			var deps []string
			for depName := range entry.Requires {
				if depVer, ok := nameVer[depName]; ok {
					deps = append(deps, npmDepPURL(depName, depVer))
				}
			}

			scope := ""
			if entry.Dev {
				scope = "excluded"
			}

			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    entry.Version,
				RawVersion: entry.Version,
				Ecosystem:  "npm",
				Source:     "package-lock.json",
				Location:   path,
				Direct:     inventory.BoolPtr(isDirect),
				Deps:       deps,
				Integrity:  entry.Integrity,
				License:    readNodeModuleLicense(lockfileDir, name),
				Scope:      scope,
			})
		}
	} else if len(lockfile.Dependencies) > 0 {
		// v1 format: "dependencies" field (no Deps extraction, Direct unknown)
		pkgs = append(pkgs, flattenDeps("", lockfile.Dependencies, path)...)
	}

	if verbose {
		log.Printf("[npm] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

// pkgNameFromPath strips "node_modules/" prefixes from a package-lock.json path key.
// "node_modules/foo"                       → "foo"
// "node_modules/@scope/foo"                → "@scope/foo"
// "node_modules/bar/node_modules/baz"      → "baz"  (take the last component)
func pkgNameFromPath(key string) string {
	name := key
	for strings.Contains(name, "node_modules/") {
		idx := strings.LastIndex(name, "node_modules/")
		name = name[idx+len("node_modules/"):]
	}
	return name
}

// npmDepPURL generates a PURL for an npm dependency.
// Scoped packages (@scope/name) are percent-encoded as per the PURL spec.
func npmDepPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		if parts := strings.SplitN(name[1:], "/", 2); len(parts) == 2 {
			return fmt.Sprintf("pkg:npm/%%40%s/%s@%s", parts[0], parts[1], version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}

type packageLockEntry struct {
	Version         string            `json:"version"`
	Integrity       string            `json:"integrity"`
	Requires        map[string]string `json:"requires"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Dev             bool              `json:"dev"` // true when only reachable via devDependencies (npm computes this itself)
}

type packageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]packageLockDep `json:"dependencies"`
}

// flattenDeps recursively extracts packages from v1 dependencies tree.
func flattenDeps(prefix string, deps map[string]packageLockDep, location string) []inventory.Package {
	var pkgs []inventory.Package
	for name, dep := range deps {
		if dep.Version != "" {
			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    dep.Version,
				RawVersion: dep.Version,
				Ecosystem:  "npm",
				Source:     "package-lock.json",
				Location:   location,
			})
		}
		if len(dep.Dependencies) > 0 {
			pkgs = append(pkgs, flattenDeps(name+"/", dep.Dependencies, location)...)
		}
	}
	return pkgs
}

// parseYarnLock parses a yarn.lock file for package versions.
// yarn.lock uses a custom format:
//
//	"package@^1.0.0":
//	  version "1.2.3"
func parseYarnLock(path string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	var currentName string
	lockfileDir := filepath.Dir(path)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Package header line: "name@version-range", "name@version-range":
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") && strings.Contains(line, "@") {
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			// Remove quotes
			header = strings.Trim(header, "\"")
			// Get the package name (everything before the last @)
			if idx := strings.LastIndex(header, "@"); idx > 0 {
				currentName = header[:idx]
			}
			continue
		}

		// Version line:   version "1.2.3"
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") && currentName != "" {
			version := strings.TrimPrefix(trimmed, "version ")
			version = strings.Trim(version, "\"")
			pkgs = append(pkgs, inventory.Package{
				Name:       currentName,
				Version:    version,
				RawVersion: version,
				Ecosystem:  "npm",
				Source:     "yarn.lock",
				Location:   path,
				License:    readNodeModuleLicense(lockfileDir, currentName),
			})
			currentName = ""
		}
	}

	if verbose {
		log.Printf("[npm] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// parsePnpmLock parses a pnpm-lock.yaml file (v5/v6/v9 formats).
// It reads the "importers:" section to collect direct dependency names,
// then reads the "packages:" section for all resolved packages.
func parsePnpmLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	directSet, prodRootKeys := parsePnpmImporters(string(data))
	snapshotDeps := parsePnpmSnapshots(string(data))

	// Only trust the reachability computation when we actually found prod roots;
	// an empty result means the lockfile predates "importers:" (v5/v6) or genuinely
	// declares no prod deps, and we must not mark every package "excluded" in that case.
	knowsProdScope := len(prodRootKeys) > 0
	prodReachable := computeProdReachable(prodRootKeys, snapshotDeps)

	// State machine: track current package entry to capture integrity alongside name/version.
	type pnpmEntry struct {
		name      string
		version   string
		integrity string
	}
	var cur pnpmEntry
	var pkgs []inventory.Package
	inPackages := false

	lockfileDir := filepath.Dir(path)
	flushPnpm := func() {
		if cur.name != "" && cur.version != "" {
			key := cur.name + "@" + cur.version
			isDirect := directSet[cur.name]
			deps := snapshotDeps[key]
			scope := ""
			if knowsProdScope && !prodReachable[key] {
				scope = "excluded"
			}
			pkgs = append(pkgs, inventory.Package{
				Name:       cur.name,
				Version:    cur.version,
				RawVersion: cur.version,
				Ecosystem:  "npm",
				Source:     "pnpm-lock.yaml",
				Location:   path,
				Direct:     inventory.BoolPtr(isDirect),
				Integrity:  cur.integrity,
				Deps:       deps,
				License:    readNodeModuleLicense(lockfileDir, cur.name),
				Scope:      scope,
			})
		}
		cur = pnpmEntry{}
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()

		// Top-level section header (no leading whitespace)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if trimmedLine := strings.TrimSpace(line); trimmedLine != "" {
				if inPackages {
					flushPnpm()
				}
				inPackages = trimmedLine == "packages:"
			}
			continue
		}

		if !inPackages {
			continue
		}

		// Package key lines: indented with exactly 2 spaces, end with ":"
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, ":") && strings.Contains(trimmed, "@") {
				flushPnpm()
				key := strings.TrimSuffix(trimmed, ":")
				key = strings.Trim(key, "'")
				key = strings.TrimPrefix(key, "/")
				if idx := strings.Index(key, "("); idx > 0 {
					key = key[:idx]
				}
				if idx := strings.LastIndex(key, "@"); idx > 0 {
					cur.name = key[:idx]
					cur.version = key[idx+1:]
				}
			}
			continue
		}

		// Property lines: indented with 4 spaces inside a package block
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") && cur.name != "" {
			trimmed := strings.TrimSpace(line)
			// Standalone:  "integrity: sha512-..."
			if strings.HasPrefix(trimmed, "integrity: ") {
				cur.integrity = strings.TrimPrefix(trimmed, "integrity: ")
				continue
			}
			// Inline resolution block:  "resolution: {integrity: sha512-...}"
			if strings.HasPrefix(trimmed, "resolution: {integrity: ") {
				val := strings.TrimPrefix(trimmed, "resolution: {integrity: ")
				val = strings.TrimSuffix(val, "}")
				cur.integrity = val
			}
		}
	}
	flushPnpm()

	if verbose {
		log.Printf("[npm] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// parsePnpmSnapshots extracts the resolved dependency graph from the "snapshots:" section
// of a pnpm-lock.yaml (v9+). It returns a map of "name@version" to a slice of dependency
// PURLs. Peer-dependency suffixes in parentheses are stripped from both keys and values.
//
// Snapshot entry structure:
//
//	snapshots:
//	  '@auth/core@0.41.1':          ← 2-space key (may have peer suffix)
//	    dependencies:               ← 4-space section header
//	      '@panva/hkdf': 1.2.1     ← 6-space dep entry
//	      preact: 10.24.3(...)      ← peer suffix on version — stripped
//	    transitivePeerDependencies: ← ignored
func parsePnpmSnapshots(content string) map[string][]string {
	depsMap := make(map[string][]string)
	inSnapshots := false
	currentKey := ""
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()

		// Top-level section header
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if t := strings.TrimSpace(line); t != "" {
				inSnapshots = t == "snapshots:"
				currentKey = ""
				inDeps = false
			}
			continue
		}
		if !inSnapshots {
			continue
		}

		// 2-space indent: snapshot package key
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			t := strings.TrimSpace(line)
			// Keys end with ":" or ": {}" (no-deps shorthand)
			t = strings.TrimSuffix(t, ": {}")
			t = strings.TrimSuffix(t, ":")
			t = strings.TrimSpace(t)
			t = strings.Trim(t, "'\"")
			// Strip peer-dep suffix
			if idx := strings.Index(t, "("); idx > 0 {
				t = t[:idx]
			}
			if strings.Contains(t, "@") {
				currentKey = t
			} else {
				currentKey = ""
			}
			inDeps = false
			continue
		}

		if currentKey == "" {
			continue
		}

		// 4-space indent: section headers inside snapshot entry
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			t := strings.TrimSpace(line)
			inDeps = t == "dependencies:"
			if !inDeps {
				// transitivePeerDependencies: or other — stop collecting deps
				if t != "" && !strings.HasSuffix(t, ":") {
					inDeps = false
				}
			}
			continue
		}

		// 6-space indent: individual dependency entries
		if inDeps && strings.HasPrefix(line, "      ") && !strings.HasPrefix(line, "       ") {
			t := strings.TrimSpace(line)
			colonIdx := strings.Index(t, ": ")
			if colonIdx < 0 {
				continue
			}
			depName := strings.Trim(t[:colonIdx], "'\"")
			depVer := t[colonIdx+2:]
			// Strip peer-dep suffix from version: "6.5.11(preact@10.24.3)" → "6.5.11"
			if idx := strings.Index(depVer, "("); idx > 0 {
				depVer = depVer[:idx]
			}
			depVer = strings.TrimSpace(depVer)
			if depName != "" && depVer != "" {
				depsMap[currentKey] = append(depsMap[currentKey], npmDepPURL(depName, depVer))
			}
		}
	}
	return depsMap
}

// parsePnpmImporters extracts direct dependency info from the "importers:" section
// of a pnpm-lock.yaml. Only the root importer (".") is considered.
//
// Returns:
//   - directSet: names of all direct dependencies (dependencies: and devDependencies:
//     combined), used to populate Package.Direct.
//   - prodRootKeys: "name@version" keys (peer-dep suffix stripped) for dependencies:
//     entries only — the roots used to compute which packages are reachable from a
//     production-only install (see computeProdReachable). Empty when the lockfile has
//     no "importers:" section (older v5/v6 format) or declares no prod dependencies;
//     callers must treat that as "unknown" rather than "everything is dev-only".
func parsePnpmImporters(content string) (directSet map[string]bool, prodRootKeys []string) {
	directSet = make(map[string]bool)
	inImporters := false
	inRootImporter := false
	section := ""     // "" | "dependencies" | "devDependencies"
	pendingName := "" // name of the dependency whose "version:" line we're waiting for

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()

		// Top-level section
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if t := strings.TrimSpace(line); t != "" {
				inImporters = t == "importers:"
				inRootImporter = false
				section = ""
				pendingName = ""
			}
			continue
		}
		if !inImporters {
			continue
		}

		// 2-space indent: importer key (e.g. "  .:")
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			t := strings.TrimSpace(line)
			inRootImporter = t == ".:"
			section = ""
			pendingName = ""
			continue
		}
		if !inRootImporter {
			continue
		}

		// 4-space indent: section inside root importer
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			t := strings.TrimSpace(line)
			if t == "dependencies:" || t == "devDependencies:" {
				section = strings.TrimSuffix(t, ":")
			} else {
				section = ""
			}
			pendingName = ""
			continue
		}
		if section == "" {
			continue
		}

		// 6-space indent: individual dependency entry, e.g. "react:"
		if strings.HasPrefix(line, "      ") && !strings.HasPrefix(line, "       ") {
			t := strings.TrimSpace(line)
			name := strings.TrimSuffix(t, ":")
			name = strings.Trim(name, "'\"")
			pendingName = name
			if name != "" {
				directSet[name] = true
			}
			continue
		}

		// 8-space indent: "specifier:"/"version:" lines under a dependency entry
		if pendingName != "" && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         ") {
			t := strings.TrimSpace(line)
			if version, ok := strings.CutPrefix(t, "version: "); ok && section == "dependencies" {
				version = strings.Trim(version, "'\"")
				// Strip peer-dep suffix: "4.1.10(@types/node@25.0.8)" → "4.1.10"
				if idx := strings.Index(version, "("); idx > 0 {
					version = version[:idx]
				}
				prodRootKeys = append(prodRootKeys, pendingName+"@"+version)
			}
		}
	}
	return directSet, prodRootKeys
}

// purlToSnapshotKey converts a dependency PURL (as produced by npmDepPURL) back into
// the "name@version" form used as keys in the snapshots dependency graph.
// "pkg:npm/foo@1.2.3" → "foo@1.2.3"; "pkg:npm/%40scope/foo@1.2.3" → "@scope/foo@1.2.3"
func purlToSnapshotKey(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:npm/")
	return strings.ReplaceAll(s, "%40", "@")
}

// computeProdReachable performs a BFS over the snapshots dependency graph starting
// from prodRootKeys, returning the full set of packages reachable from a
// production-only (non-dev) install — i.e. what would survive `pnpm prune --prod`.
func computeProdReachable(prodRootKeys []string, snapshotDeps map[string][]string) map[string]bool {
	reachable := make(map[string]bool, len(prodRootKeys))
	queue := make([]string, 0, len(prodRootKeys))
	for _, k := range prodRootKeys {
		if !reachable[k] {
			reachable[k] = true
			queue = append(queue, k)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, depPURL := range snapshotDeps[cur] {
			depKey := purlToSnapshotKey(depPURL)
			if !reachable[depKey] {
				reachable[depKey] = true
				queue = append(queue, depKey)
			}
		}
	}
	return reachable
}

// npmGlobalFallback uses npm list -g --json to collect global packages.
func npmGlobalFallback(verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("npm"); err != nil {
		return nil, fmt.Errorf("npm not found")
	}

	cmd := exec.Command("npm", "list", "-g", "--json", "--depth=0")
	out, err := cmd.Output()
	if err != nil {
		// npm list returns exit code 1 if there are peer dep issues, but still outputs JSON
		if out == nil {
			return nil, fmt.Errorf("npm list failed: %w", err)
		}
	}

	var result struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse npm output: %w", err)
	}

	// Best-effort: license lookup requires the global node_modules root, which
	// "npm list" doesn't report. A failure here just means License stays empty.
	globalRoot := ""
	if out, err := exec.Command("npm", "root", "-g").Output(); err == nil {
		globalRoot = strings.TrimSpace(string(out))
	}

	var pkgs []inventory.Package
	for name, info := range result.Dependencies {
		var license string
		if globalRoot != "" {
			license = parsePackageJSONLicense(filepath.Join(globalRoot, name, "package.json"))
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    info.Version,
			RawVersion: info.Version,
			Ecosystem:  "npm",
			Source:     "npm-global",
			License:    license,
		})
	}

	if verbose {
		log.Printf("[npm] global fallback collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// pnpmGlobalFallback uses pnpm list -g --json to collect global packages.
func pnpmGlobalFallback(verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("pnpm"); err != nil {
		return nil, fmt.Errorf("pnpm not found")
	}

	cmd := exec.Command("pnpm", "list", "-g", "--json")
	out, err := cmd.Output()
	if err != nil {
		if out == nil {
			return nil, fmt.Errorf("pnpm list failed: %w", err)
		}
	}

	// pnpm list -g --json returns an array of objects
	var results []struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, fmt.Errorf("parse pnpm output: %w", err)
	}

	// Best-effort: license lookup requires the global node_modules root, which
	// "pnpm list" doesn't report. A failure here just means License stays empty.
	globalRoot := ""
	if out, err := exec.Command("pnpm", "root", "-g").Output(); err == nil {
		globalRoot = strings.TrimSpace(string(out))
	}

	var pkgs []inventory.Package
	for _, result := range results {
		for name, info := range result.Dependencies {
			var license string
			if globalRoot != "" {
				license = parsePackageJSONLicense(filepath.Join(globalRoot, name, "package.json"))
			}
			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    info.Version,
				RawVersion: info.Version,
				Ecosystem:  "npm",
				Source:     "pnpm-global",
				License:    license,
			})
		}
	}

	if verbose {
		log.Printf("[npm] pnpm global fallback collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// findPnpmVirtualStorePackages walks scanPath looking for node_modules/.pnpm directories
// and extracts installed packages from the pnpm virtual store layout.
// This handles Docker images where pnpm-lock.yaml was not copied into the final image.
func findPnpmVirtualStorePackages(scanPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if d.Name() == ".git" {
			return fs.SkipDir
		}
		if d.Name() == "node_modules" {
			pnpmStorePath := filepath.Join(path, ".pnpm")
			if _, statErr := os.Stat(pnpmStorePath); statErr == nil {
				p, scanErr := parsePnpmVirtualStore(pnpmStorePath, verbose)
				if scanErr == nil {
					pkgs = append(pkgs, p...)
				} else if verbose {
					log.Printf("[npm] error scanning pnpm virtual store at %s: %v", pnpmStorePath, scanErr)
				}
			}
			return fs.SkipDir
		}
		return nil
	})
	return pkgs, err
}

// parsePnpmVirtualStore reads package entries from a pnpm virtual store directory (.pnpm/).
// pnpm encodes directory names as:
//   - unscoped:  pkg@version  or  pkg@version_peer@peerVer
//   - scoped:    @scope+name@version  (slash encoded as +, peer suffix may follow)
//
// pnpm v9 shortens the version in the directory name when a peer-hash suffix is
// appended (e.g. "1.1." instead of "1.1.10"). The authoritative version is
// always read from the package.json inside the virtual store entry.
func parsePnpmVirtualStore(pnpmPath string, verbose bool) ([]inventory.Package, error) {
	entries, err := os.ReadDir(pnpmPath)
	if err != nil {
		return nil, err
	}

	var pkgs []inventory.Package
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pkgName, dirVersion, ok := parsePnpmStoreEntry(entry.Name())
		if !ok {
			continue
		}

		// Read the authoritative version from the package.json inside the store entry.
		// pnpm v9 truncates the version in the directory name when it appends a peer hash.
		pkgJSONPath := filepath.Join(pnpmPath, entry.Name(), "node_modules", pkgName, "package.json")
		version, err := readPackageJSONVersion(pkgJSONPath)
		if err != nil {
			version = dirVersion // fallback to directory-name version
		}

		pkgs = append(pkgs, inventory.Package{
			Name:       pkgName,
			Version:    version,
			RawVersion: entry.Name(),
			Ecosystem:  "npm",
			Source:     "pnpm-virtual-store",
			Location:   pnpmPath,
			License:    parsePackageJSONLicense(pkgJSONPath),
		})
	}

	if verbose {
		log.Printf("[npm] scanned %d packages from pnpm virtual store at %s", len(pkgs), pnpmPath)
	}
	return pkgs, nil
}

// readPackageJSONVersion reads the "version" field from a package.json file.
func readPackageJSONVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	if pkg.Version == "" {
		return "", fmt.Errorf("no version in %s", path)
	}
	return pkg.Version, nil
}

// readNodeModuleLicense reads the license from node_modules/{name}/package.json.
// Returns "" when the file does not exist or has no license field.
func readNodeModuleLicense(lockfileDir, pkgName string) string {
	return parsePackageJSONLicense(filepath.Join(lockfileDir, "node_modules", pkgName, "package.json"))
}

// parsePackageJSONLicense reads the license field from a package.json at pkgJSONPath.
// Returns "" when the file does not exist or has no license field.
func parsePackageJSONLicense(pkgJSONPath string) string {
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return ""
	}
	var pkg struct {
		License  json.RawMessage `json:"license"`
		Licenses []struct {
			Type string `json:"type"`
		} `json:"licenses"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ""
	}
	// Standard: "license": "MIT"
	if len(pkg.License) > 0 {
		var s string
		if json.Unmarshal(pkg.License, &s) == nil && s != "" {
			return s
		}
	}
	// Legacy: "licenses": [{"type":"MIT"}]
	if len(pkg.Licenses) > 0 {
		types := make([]string, 0, len(pkg.Licenses))
		for _, l := range pkg.Licenses {
			if l.Type != "" {
				types = append(types, l.Type)
			}
		}
		if len(types) > 0 {
			return strings.Join(types, " OR ")
		}
	}
	return ""
}

// parsePnpmStoreEntry extracts package name and version from a pnpm virtual store
// directory entry name.
//
// The correct "@" separator is the FIRST one that is not the leading "@" of a scoped
// package. Using LastIndex is wrong when the peer-dep suffix contains "@".
//
//	styled-jsx@5.1.6_@babel+core@7.29.0_react@19.2.3  →  styled-jsx, 5.1.6
//	@babel+core@7.29.0                                 →  @babel/core, 7.29.0
//	@babel+core@7.29.0_@types+node@20.0.0              →  @babel/core, 7.29.0
func parsePnpmStoreEntry(entryName string) (name, version string, ok bool) {
	// Locate the "@" that begins the version field.
	// Scoped packages start with "@", so we skip that leading character.
	searchFrom := 0
	if strings.HasPrefix(entryName, "@") {
		searchFrom = 1
	}
	rel := strings.Index(entryName[searchFrom:], "@")
	if rel < 0 {
		return "", "", false
	}
	atIdx := searchFrom + rel

	name = entryName[:atIdx]
	rawVer := entryName[atIdx+1:]

	// Strip peer-dep / patch suffixes: "4.18.2_peer@1.0.0" or "4.18.2(peer@1.0.0)" → "4.18.2"
	if idx := strings.IndexAny(rawVer, "_("); idx > 0 {
		rawVer = rawVer[:idx]
	}

	if name == "" || rawVer == "" {
		return "", "", false
	}

	// pnpm encodes "@scope/name" as "@scope+name" in directory names — restore the slash.
	if strings.HasPrefix(name, "@") {
		if plusIdx := strings.Index(name[1:], "+"); plusIdx >= 0 {
			name = "@" + name[1:plusIdx+1] + "/" + name[plusIdx+2:]
		}
	}

	return name, rawVer, true
}

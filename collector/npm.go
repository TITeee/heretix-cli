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

func (c *NPMCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
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

	// Fallback to global package managers
	if !found {
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
		for key, entry := range lockfile.Packages {
			if key == "" {
				continue // skip root package
			}
			name := key
			// Strip "node_modules/" prefix(es)
			for strings.HasPrefix(name, "node_modules/") {
				name = strings.TrimPrefix(name, "node_modules/")
			}
			if entry.Version == "" || name == "" {
				continue
			}
			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    entry.Version,
				RawVersion: entry.Version,
				Ecosystem:  "npm",
				Source:     "package-lock.json",
				Location:   path,
			})
		}
	} else if len(lockfile.Dependencies) > 0 {
		// v1 format: "dependencies" field
		pkgs = append(pkgs, flattenDeps("", lockfile.Dependencies, path)...)
	}

	if verbose {
		log.Printf("[npm] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

type packageLockEntry struct {
	Version string `json:"version"`
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
// It extracts packages from the "packages:" section only, skipping "snapshots:"
// and "importers:" to avoid duplicates and unresolved specifiers.
func parsePnpmLock(path string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	inPackages := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Top-level section header (no leading whitespace)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Blank lines between sections must not reset the current section
			if trimmedLine := strings.TrimSpace(line); trimmedLine != "" {
				inPackages = trimmedLine == "packages:"
			}
			continue
		}

		if !inPackages {
			continue
		}

		// Package key lines are indented with exactly 2 spaces and end with ":"
		// e.g. "  /express@4.18.2:" (v5/v6) or "  express@4.18.2:" (v9)
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") || !strings.Contains(trimmed, "@") {
			continue
		}

		key := strings.TrimSuffix(trimmed, ":")
		// Remove YAML single quotes wrapping scoped packages (e.g. '@scope/pkg@1.0.0')
		key = strings.Trim(key, "'")
		// Remove leading slash used in v5/v6 format
		key = strings.TrimPrefix(key, "/")
		// Strip parenthetical peer-dep suffixes present in pnpm v9 lockfiles:
		// "hono@4.11.4(@prisma/client@5.0.0)" → "hono@4.11.4"
		if idx := strings.Index(key, "("); idx > 0 {
			key = key[:idx]
		}

		// Split name and version at the last "@"
		if idx := strings.LastIndex(key, "@"); idx > 0 {
			name := key[:idx]
			version := key[idx+1:]
			if name != "" && version != "" {
				pkgs = append(pkgs, inventory.Package{
					Name:       name,
					Version:    version,
					RawVersion: version,
					Ecosystem:  "npm",
					Source:     "pnpm-lock.yaml",
					Location:   path,
				})
			}
		}
	}

	if verbose {
		log.Printf("[npm] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
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

	var pkgs []inventory.Package
	for name, info := range result.Dependencies {
		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    info.Version,
			RawVersion: info.Version,
			Ecosystem:  "npm",
			Source:     "npm-global",
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

	var pkgs []inventory.Package
	for _, result := range results {
		for name, info := range result.Dependencies {
			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    info.Version,
				RawVersion: info.Version,
				Ecosystem:  "npm",
				Source:     "pnpm-global",
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
// Each subdirectory is named "{pkg}@{version}" or "@scope/{pkg}@{version}", optionally
// followed by a peer-dep suffix separated by "_" or "(".
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
		entryName := entry.Name()

		// Find last "@" to split name and version (handles scoped packages like @scope/pkg@1.0.0)
		atIdx := strings.LastIndex(entryName, "@")
		if atIdx <= 0 {
			continue
		}
		pkgName := entryName[:atIdx]
		rawVersion := entryName[atIdx+1:]

		// Strip peer-dep / patch suffixes: "4.18.2_peer@1.0.0" → "4.18.2"
		version := rawVersion
		if idx := strings.IndexAny(rawVersion, "_(+"); idx > 0 {
			version = rawVersion[:idx]
		}

		if pkgName == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       pkgName,
			Version:    version,
			RawVersion: rawVersion,
			Ecosystem:  "npm",
			Source:     "pnpm-virtual-store",
			Location:   pnpmPath,
		})
	}

	if verbose {
		log.Printf("[npm] scanned %d packages from pnpm virtual store at %s", len(pkgs), pnpmPath)
	}
	return pkgs, nil
}

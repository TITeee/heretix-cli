package collector

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// ComposerCollector collects PHP packages from composer.lock files.
type ComposerCollector struct{}

func (c *ComposerCollector) Name() string { return "composer" }

func (c *ComposerCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "composer.lock" {
			return nil
		}

		p, err := parseComposerLock(path, verbose)
		if err != nil {
			if verbose {
				log.Printf("[composer] error parsing %s: %v", path, err)
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
		log.Printf("[composer] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

type composerLockEntry struct {
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Require  map[string]string `json:"require"`
	Licenses []string          `json:"license"`
}

func composerPURL(name, version string) string {
	return "pkg:composer/" + name + "@" + version
}

// loadComposerDirectSet reads composer.json in the same directory and returns
// the set of directly required package names. Returns nil if composer.json is absent.
func loadComposerDirectSet(lockPath string) map[string]bool {
	composerJSON := filepath.Join(filepath.Dir(lockPath), "composer.json")
	data, err := os.ReadFile(composerJSON)
	if err != nil {
		return nil
	}

	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}

	directSet := make(map[string]bool, len(manifest.Require)+len(manifest.RequireDev))
	for name := range manifest.Require {
		directSet[name] = true
	}
	for name := range manifest.RequireDev {
		directSet[name] = true
	}
	return directSet
}

// parseComposerLock parses a composer.lock (JSON) and returns all packages,
// including both runtime (packages) and development (packages-dev) dependencies.
func parseComposerLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages    []composerLockEntry `json:"packages"`
		PackagesDev []composerLockEntry `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	all := append(lockfile.Packages, lockfile.PackagesDev...)

	// Pass 1: build name→version lookup (first occurrence wins)
	nameVer := make(map[string]string, len(all))
	for _, entry := range all {
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		if _, exists := nameVer[entry.Name]; !exists {
			nameVer[entry.Name] = entry.Version
		}
	}

	// Direct set from composer.json (nil when absent → Direct stays nil)
	directSet := loadComposerDirectSet(path)

	// Pass 2: build packages with Deps and Direct
	var pkgs []inventory.Package
	for _, entry := range all {
		if entry.Name == "" || entry.Version == "" {
			continue
		}

		// Resolve require → PURLs; entries not found in nameVer (e.g. "php", "ext-*") are skipped
		var deps []string
		for depName := range entry.Require {
			if depVer, ok := nameVer[depName]; ok {
				deps = append(deps, composerPURL(depName, depVer))
			}
		}

		var direct *bool
		if directSet != nil {
			direct = inventory.BoolPtr(directSet[entry.Name])
		}

		pkgs = append(pkgs, inventory.Package{
			Name:       entry.Name,
			Version:    entry.Version,
			RawVersion: entry.Version,
			Ecosystem:  "composer",
			Source:     "composer.lock",
			Location:   path,
			Direct:     direct,
			Deps:       deps,
			License:    strings.Join(entry.Licenses, " OR "),
		})
	}

	if verbose {
		log.Printf("[composer] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

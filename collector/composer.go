package collector

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

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

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseComposerLock parses a composer.lock (JSON) and returns all packages,
// including both runtime (packages) and development (packages-dev) dependencies.
func parseComposerLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	var pkgs []inventory.Package
	for _, entry := range append(lockfile.Packages, lockfile.PackagesDev...) {
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       entry.Name,
			Version:    entry.Version,
			RawVersion: entry.Version,
			Ecosystem:  "composer",
			Source:     "composer.lock",
			Location:   path,
		})
	}

	if verbose {
		log.Printf("[composer] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// OSInfo holds operating system identification.
type OSInfo struct {
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
	Name      string `json:"name"`
}

// Package represents a single detected software package.
type Package struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	RawVersion string   `json:"rawVersion"`
	Ecosystem  string   `json:"ecosystem"`
	Source     string   `json:"source"`
	Location   string   `json:"location,omitempty"`
	Direct     *bool    `json:"direct,omitempty"`    // nil=unknown, true=direct dep, false=indirect dep
	Deps       []string `json:"deps,omitempty"`      // PURLs of this package's direct dependencies
	Integrity  string   `json:"integrity,omitempty"` // raw integrity string from lockfile (SRI or sha256:hex)
	License    string   `json:"license,omitempty"`   // SPDX expression (e.g. "MIT", "Apache-2.0 OR MIT")
	Scope      string   `json:"scope,omitempty"`     // ""=unknown/required, "excluded"=dev-only (unreachable in a prod build), mirrors CycloneDX component.scope
	// SourcePackage is the upstream source package this binary package was
	// built from (dpkg "Source:", rpm SourceRpm, apk "o:"). It is what lets
	// one CVE affecting one upstream project be reported once instead of once
	// per binary package it fans out into. Empty for non-OS ecosystems.
	SourcePackage string `json:"sourcePackage,omitempty"`
	// Category marks a package that is present in the image but is not part of
	// what it runs: "kernel" (kernel headers) or "build" (build toolchain).
	// "" means a normal runtime package. See collector.classifyNonRuntime.
	Category string `json:"category,omitempty"`
}

// BoolPtr returns a pointer to b, for use with Package.Direct.
func BoolPtr(b bool) *bool { return &b }

// Inventory is the top-level structure for the detection list JSON.
type Inventory struct {
	Version     string    `json:"version"`
	Type        string    `json:"type,omitempty"`
	Hostname    string    `json:"hostname"`
	ScannedAt   string    `json:"scannedAt"`
	OS          OSInfo    `json:"os"`
	Packages    []Package `json:"packages"`
	ImageDigest string    `json:"imageDigest,omitempty"` // set when Type == "docker_image"
}

// New creates an Inventory with metadata populated.
func New(hostname string, osInfo OSInfo) *Inventory {
	return &Inventory{
		Version:   "1.0",
		Hostname:  hostname,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		OS:        osInfo,
		Packages:  []Package{},
	}
}

// WriteToFile writes the inventory as JSON to the specified path.
func (inv *Inventory) WriteToFile(path string) error {
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write inventory file: %w", err)
	}
	return nil
}

// ReadFromFile reads an inventory JSON from the specified path.
func ReadFromFile(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory file: %w", err)
	}
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory file: %w", err)
	}
	return &inv, nil
}

// Deduplicate removes duplicate packages (same name+version+ecosystem).
// When a duplicate is found, metadata fields are merged using priority rules:
//   - Direct: true > false > nil  (direct knowledge wins over indirect or unknown)
//   - Integrity, Location, Deps:  non-empty wins over empty
func Deduplicate(pkgs []Package) []Package {
	merged, _ := DeduplicateBy(pkgs, func(p Package) string {
		return p.Name + "\t" + p.Version + "\t" + p.Ecosystem
	})
	return merged
}

// DeduplicateBy merges packages that share a key, using the same field-priority
// rules as Deduplicate. It returns the merged list and the keys that actually
// had more than one package collapsed into them.
//
// The key function is a parameter because identity is not the same question in
// every context. Deduplicate answers "is this the same installed package?" and
// keys on name+version+ecosystem. SBOM generation answers "is this the same
// component?" and keys on the PURL — a stricter requirement, since CycloneDX
// requires every bom-ref to be unique within the BOM and this tool derives
// bom-ref from the PURL. Passing the key in keeps that PURL logic in the sbom
// package, which would otherwise be an import cycle.
func DeduplicateBy(pkgs []Package, key func(Package) string) (merged []Package, collapsed []string) {
	index := make(map[string]int) // key → index in result
	dupes := map[string]bool{}
	result := []Package{}
	for _, p := range pkgs {
		k := key(p)
		if i, exists := index[k]; exists {
			result[i] = mergePkg(result[i], p)
			if !dupes[k] {
				dupes[k] = true
				collapsed = append(collapsed, k)
			}
		} else {
			index[k] = len(result)
			result = append(result, p)
		}
	}
	return result, collapsed
}

// mergePkg merges metadata from b into a, preferring the richer value per field.
func mergePkg(a, b Package) Package {
	// Direct: true > false > nil
	a.Direct = mergeDirectPtr(a.Direct, b.Direct)
	// Integrity: prefer non-empty
	if a.Integrity == "" {
		a.Integrity = b.Integrity
	}
	// License: prefer non-empty
	if a.License == "" {
		a.License = b.License
	}
	// Deps: prefer non-empty
	if len(a.Deps) == 0 {
		a.Deps = b.Deps
	}
	// Location: prefer non-empty
	if a.Location == "" {
		a.Location = b.Location
	}
	// Scope: prefer non-empty ("excluded" wins over unknown)
	if a.Scope == "" {
		a.Scope = b.Scope
	}
	// SourcePackage / Category: prefer non-empty
	if a.SourcePackage == "" {
		a.SourcePackage = b.SourcePackage
	}
	if a.Category == "" {
		a.Category = b.Category
	}
	return a
}

// mergeDirectPtr returns the higher-priority Direct pointer.
// Priority: true > false > nil.
func mergeDirectPtr(a, b *bool) *bool {
	if a == nil {
		return b
	}
	if b != nil && *b && !*a {
		return b // b is true, a is false → true wins
	}
	return a
}

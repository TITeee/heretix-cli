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
	index := make(map[string]int) // key → index in result
	result := []Package{}
	for _, p := range pkgs {
		key := p.Name + "\t" + p.Version + "\t" + p.Ecosystem
		if i, exists := index[key]; exists {
			result[i] = mergePkg(result[i], p)
		} else {
			index[key] = len(result)
			result = append(result, p)
		}
	}
	return result
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

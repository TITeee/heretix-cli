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
	Name       string `json:"name"`
	Version    string `json:"version"`
	RawVersion string `json:"rawVersion"`
	Ecosystem  string `json:"ecosystem"`
	Source     string `json:"source"`
	Location   string `json:"location,omitempty"`
}

// Inventory is the top-level structure for the detection list JSON.
type Inventory struct {
	Version   string    `json:"version"`
	Type      string    `json:"type,omitempty"`
	Hostname  string    `json:"hostname"`
	ScannedAt string    `json:"scannedAt"`
	OS        OSInfo    `json:"os"`
	Packages  []Package `json:"packages"`
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
func Deduplicate(pkgs []Package) []Package {
	seen := make(map[string]bool)
	result := []Package{}
	for _, p := range pkgs {
		key := p.Name + "\t" + p.Version + "\t" + p.Ecosystem
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}

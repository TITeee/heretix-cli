package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

// loadInventoryFile reads either a heretix inventory JSON or a
// heretix-generated CycloneDX SBOM (as produced by `collect --format
// cyclonedx`), detected via the top-level "bomFormat" field that only
// CycloneDX documents carry.
func loadInventoryFile(path string) (*inventory.Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory file: %w", err)
	}

	var probe struct {
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse inventory file: %w", err)
	}

	if probe.BOMFormat != "CycloneDX" {
		return inventory.ReadFromFile(path)
	}

	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX file: %w", err)
	}
	return sbom.FromCycloneDX(&bom), nil
}

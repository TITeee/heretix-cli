package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

// errInventoryJSON is returned for the heretix inventory JSON that older
// versions of collect wrote (--format json). It is no longer read.
var errInventoryJSON = errors.New("this is a heretix inventory JSON, which is no longer supported: re-run `heretix-cli collect` to write a CycloneDX SBOM")

// requireCycloneDX checks that data is a CycloneDX JSON document, telling a
// leftover heretix inventory JSON apart from anything else.
func requireCycloneDX(data []byte) error {
	var probe struct {
		BOMFormat string          `json:"bomFormat"`
		Packages  json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("not a JSON file: %w", err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return nil
	case probe.Packages != nil:
		return errInventoryJSON
	default:
		return errors.New(`not a CycloneDX SBOM (no "bomFormat": "CycloneDX")`)
	}
}

// loadSBOM reads a CycloneDX SBOM, as written by collect.
func loadSBOM(path string) (*inventory.Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := requireCycloneDX(data); err != nil {
		return nil, err
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX file: %w", err)
	}
	return sbom.FromCycloneDX(&bom), nil
}

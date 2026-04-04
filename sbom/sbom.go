package sbom

import (
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
)

var ecosystemToPURLType = map[string]string{
	"rpm":  "rpm",
	"dpkg": "deb",
	"apk":  "apk",
	"pypi": "pypi",
	"npm":  "npm",
}

// GenerateCycloneDX converts an Inventory to a CycloneDX BOM.
func GenerateCycloneDX(inv *inventory.Inventory) *cdx.BOM {
	components := make([]cdx.Component, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		purlType, ok := ecosystemToPURLType[p.Ecosystem]
		if !ok {
			purlType = p.Ecosystem
		}

		var purl string
		switch p.Ecosystem {
		case "rpm", "dpkg", "apk":
			purl = fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, inv.OS.ID, p.Name, p.Version)
		default:
			purl = fmt.Sprintf("pkg:%s/%s@%s", purlType, p.Name, p.Version)
		}

		components = append(components, cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: purl,
		})
	}

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Type:    cdx.ComponentTypeContainer,
			Name:    inv.Hostname,
			Version: inv.OS.Name,
		},
	}
	bom.Components = &components
	return bom
}

// WriteToFile writes a CycloneDX BOM as JSON to the specified path.
func WriteToFile(bom *cdx.BOM, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

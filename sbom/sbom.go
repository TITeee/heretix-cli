package sbom

import (
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
)

var ecosystemToPURLType = map[string]string{
	"rpm":                "rpm",
	"dpkg":               "deb",
	"apk-db":             "apk",
	"requirements.txt":   "pypi",
	"Pipfile.lock":       "pypi",
	"poetry.lock":        "pypi",
	"uv.lock":            "pypi",
	"pip":                "pypi",
	"package-lock.json":  "npm",
	"yarn.lock":          "npm",
	"pnpm-lock.yaml":     "npm",
	"npm-global":         "npm",
	"pnpm-global":        "npm",
	"pnpm-virtual-store": "npm",
	"go.mod":             "golang",
	"composer.lock":      "composer",
}

// GenerateCycloneDX converts an Inventory to a CycloneDX BOM.
// version is the heretix-cli version string recorded in metadata.tools.
func GenerateCycloneDX(inv *inventory.Inventory, version string) *cdx.BOM {
	components := make([]cdx.Component, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		purlType, ok := ecosystemToPURLType[p.Source]
		if !ok {
			purlType = p.Source
		}

		var purl string
		switch p.Source {
		case "rpm", "dpkg", "apk-db":
			ns := osIDToPURLNamespace(inv.OS.ID)
			if q := ecosystemToDistroQualifier(p.Ecosystem); q != "" {
				purl = fmt.Sprintf("pkg:%s/%s/%s@%s?distro=%s", purlType, ns, p.Name, p.Version, q)
			} else {
				purl = fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, ns, p.Name, p.Version)
			}
		case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-global", "pnpm-global", "pnpm-virtual-store":
			purl = npmPURL(p.Name, p.Version)
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

	legacyTools := []cdx.Tool{{Vendor: "heretix", Name: "heretix-cli", Version: version}}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: inv.ScannedAt,
		Tools:     &cdx.ToolsChoice{Tools: &legacyTools},
		Component: &cdx.Component{
			Type:    metadataComponentType(inv),
			Name:    inv.Hostname,
			Version: inv.OS.Name,
		},
	}
	bom.Components = &components
	return bom
}

// npmPURL returns the PURL for an npm package, correctly handling scoped packages.
// @scope/name → pkg:npm/%40scope/name@version
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:npm/%%40%s/%s@%s", parts[0], parts[1], version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}

// metadataComponentType returns the CycloneDX component type for the BOM metadata
// based on the inventory scan type.
func metadataComponentType(inv *inventory.Inventory) cdx.ComponentType {
	if inv.Type == "docker_image" {
		return cdx.ComponentTypeContainer
	}
	return cdx.ComponentTypeOS
}

// osIDToPURLNamespace maps os-release ID values to PURL-compliant namespace strings.
// Most distros match directly; Oracle Linux is the exception ("ol" → "oraclelinux").
func osIDToPURLNamespace(osID string) string {
	switch osID {
	case "ol":
		return "oraclelinux"
	default:
		return osID
	}
}

// ecosystemToDistroQualifier converts an OSV ecosystem string to a PURL distro qualifier value.
//
//	"AlmaLinux:9"      → "almalinux-9"
//	"Ubuntu:22.04:LTS" → "ubuntu-22.04"   (LTS suffix dropped)
//	"Alpine:v3.18"     → "alpine-3.18"    (leading 'v' stripped)
//	"Oracle Linux:8"   → "oraclelinux-8"  (spaces removed)
//	""                 → ""               (no qualifier emitted)
func ecosystemToDistroQualifier(ecosystem string) string {
	if ecosystem == "" {
		return ""
	}
	parts := strings.SplitN(ecosystem, ":", 3)
	// Normalise the distro name: lowercase and remove spaces (e.g. "Oracle Linux" → "oraclelinux")
	name := strings.ToLower(strings.ReplaceAll(parts[0], " ", ""))
	if len(parts) == 1 {
		return name
	}
	// Strip leading 'v' from version component (Alpine uses "v3.18")
	ver := strings.TrimPrefix(parts[1], "v")
	return name + "-" + ver
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

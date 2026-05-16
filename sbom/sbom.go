package sbom

import (
	"encoding/base64"
	"encoding/hex"
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

		hashes := parseIntegrity(p.Integrity)

		var props *[]cdx.Property
		if p.Direct != nil {
			val := "false"
			if *p.Direct {
				val = "true"
			}
			pp := []cdx.Property{{Name: "cdx:direct", Value: val}}
			props = &pp
		}

		components = append(components, cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: purl,
			Hashes:     hashes,
			Properties: props,
		})
	}

	// Build bom.Dependencies from packages that have Deps populated.
	var depItems []cdx.Dependency
	for _, p := range inv.Packages {
		if len(p.Deps) == 0 {
			continue
		}
		purl := PackagePURL(p, inv.OS.ID)
		deps := make([]string, len(p.Deps))
		copy(deps, p.Deps)
		depItems = append(depItems, cdx.Dependency{Ref: purl, Dependencies: &deps})
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
	if len(depItems) > 0 {
		bom.Dependencies = &depItems
	}
	return bom
}

// PackagePURL returns the Package URL (PURL) for a single inventory package.
// osID is the OS identifier from inventory.OSInfo (e.g. "almalinux", "debian").
func PackagePURL(p inventory.Package, osID string) string {
	purlType, ok := ecosystemToPURLType[p.Source]
	if !ok {
		purlType = p.Source
	}
	switch p.Source {
	case "rpm", "dpkg", "apk-db":
		ns := osIDToPURLNamespace(osID)
		if q := ecosystemToDistroQualifier(p.Ecosystem); q != "" {
			return fmt.Sprintf("pkg:%s/%s/%s@%s?distro=%s", purlType, ns, p.Name, p.Version, q)
		}
		return fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, ns, p.Name, p.Version)
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-global", "pnpm-global", "pnpm-virtual-store":
		return npmPURL(p.Name, p.Version)
	default:
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, p.Name, p.Version)
	}
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

// parseIntegrity converts a raw lockfile integrity string to a CycloneDX Hash slice.
//
// Supported formats:
//   - SRI:  "sha512-{base64}"  (npm / pnpm)  → base64-decode → hex → SHA-512
//   - hex:  "sha256:{hex}"     (PyPI)         → SHA-256
//   - hex:  "sha384:{hex}"     (PyPI)         → SHA-384
//
// Returns nil when the string is empty or cannot be parsed.
func parseIntegrity(s string) *[]cdx.Hash {
	if s == "" {
		return nil
	}

	// SRI format: "sha512-{base64}", "sha384-{base64}", "sha256-{base64}"
	for prefix, algo := range map[string]cdx.HashAlgorithm{
		"sha512-": cdx.HashAlgoSHA512,
		"sha384-": cdx.HashAlgoSHA384,
		"sha256-": cdx.HashAlgoSHA256,
	} {
		if strings.HasPrefix(s, prefix) {
			b64 := s[len(prefix):]
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil
			}
			h := []cdx.Hash{{Algorithm: algo, Value: hex.EncodeToString(raw)}}
			return &h
		}
	}

	// Colon-separated hex format: "sha256:{hex}", "sha384:{hex}", "sha512:{hex}"
	for prefix, algo := range map[string]cdx.HashAlgorithm{
		"sha256:": cdx.HashAlgoSHA256,
		"sha384:": cdx.HashAlgoSHA384,
		"sha512:": cdx.HashAlgoSHA512,
	} {
		if strings.HasPrefix(s, prefix) {
			h := []cdx.Hash{{Algorithm: algo, Value: s[len(prefix):]}}
			return &h
		}
	}

	return nil
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

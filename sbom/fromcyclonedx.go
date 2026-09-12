package sbom

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
)

// FromCycloneDX converts a heretix-generated CycloneDX BOM back into an
// Inventory. It relies on the heretix:* properties and evidence.occurrences
// GenerateCycloneDX writes, not on general CycloneDX parsing, so it only
// supports BOMs this package produced.
func FromCycloneDX(bom *cdx.BOM) *inventory.Inventory {
	inv := &inventory.Inventory{Version: "1.0"}

	if bom.Metadata != nil {
		if bom.Metadata.Timestamp != "" {
			inv.ScannedAt = bom.Metadata.Timestamp
		}
		if c := bom.Metadata.Component; c != nil {
			inv.Hostname = c.Name
			inv.OS.Name = c.Version
			inv.OS.ID = componentProperty(c, "heretix:os-id")
			inv.OS.VersionID = componentProperty(c, "heretix:os-version-id")
			if c.Type == cdx.ComponentTypeContainer {
				inv.Type = "docker_image"
				inv.ImageDigest = imageDigestFromPURL(c.PackageURL)
			}
		}
	}

	depsByRef := make(map[string][]string)
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if d.Dependencies != nil {
				depsByRef[d.Ref] = *d.Dependencies
			}
		}
	}

	if bom.Components == nil {
		return inv
	}
	inv.Packages = make([]inventory.Package, 0, len(*bom.Components))
	for _, c := range *bom.Components {
		p := inventory.Package{
			Version:   c.Version,
			Ecosystem: componentProperty(&c, "heretix:ecosystem"),
			Source:    componentProperty(&c, "heretix:source"),
			Deps:      depsByRef[c.BOMRef],
			// Scope has been written since SBOM generation existed but was
			// never read back, so every "check <sbom.json>" silently discarded
			// what the collectors had worked out — dev-only npm/composer/gradle
			// dependencies as well as non-runtime OS packages.
			SourcePackage: componentProperty(&c, "heretix:source-package"),
			Category:      componentProperty(&c, "heretix:category"),
		}
		if c.Scope == cdx.ScopeExcluded {
			p.Scope = "excluded"
		}

		p.Name = c.Name
		if ecosystemToPURLType[p.Source] == "maven" {
			if ns, name, ok := mavenNameFromPURL(c.PackageURL); ok {
				p.Name = ns + ":" + name
			}
		}

		if direct := componentProperty(&c, "cdx:direct"); direct != "" {
			p.Direct = inventory.BoolPtr(direct == "true")
		}

		if c.Evidence != nil && c.Evidence.Occurrences != nil && len(*c.Evidence.Occurrences) > 0 {
			p.Location = (*c.Evidence.Occurrences)[0].Location
		}

		inv.Packages = append(inv.Packages, p)
	}
	return inv
}

// componentProperty returns the value of the named property, or "" if absent.
func componentProperty(c *cdx.Component, name string) string {
	if c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// imageDigestFromPURL extracts the digest from a PURL built by containerPURL,
// i.e. the segment between "@" and the first following "?".
func imageDigestFromPURL(purl string) string {
	at := strings.Index(purl, "@")
	if at == -1 {
		return ""
	}
	rest := purl[at+1:]
	if q := strings.Index(rest, "?"); q != -1 {
		return rest[:q]
	}
	return rest
}

// mavenNameFromPURL extracts the namespace and name from a
// "pkg:maven/{namespace}/{name}@{version}" PURL built by PackagePURL.
func mavenNameFromPURL(purl string) (namespace, name string, ok bool) {
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	if at := strings.Index(rest, "@"); at != -1 {
		rest = rest[:at]
	}
	namespace, name, ok = strings.Cut(rest, "/")
	return namespace, name, ok
}

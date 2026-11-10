package sbom

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/google/uuid"
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
	"dist-info":          "pypi",
	"package-lock.json":  "npm",
	"yarn.lock":          "npm",
	"pnpm-lock.yaml":     "npm",
	"npm-global":         "npm",
	"pnpm-global":        "npm",
	"pnpm-virtual-store": "npm",
	"go.mod":             "golang",
	"gobinary":           "golang",
	"composer.lock":      "composer",
	"pom.xml":            "maven",
	"build.gradle":       "maven",
	"build.gradle.kts":   "maven",
	"gradle.lockfile":    "maven",
	"jar":                "maven",
}

// GenerateCycloneDX converts an Inventory to a CycloneDX BOM.
// version is the heretix-cli version string recorded in metadata.tools.
// Generator is what an SBOM says about how it was made: the tool and its version
// (CISA's 2026 minimum elements "SBOM Tool Name" and "SBOM Tool Version") and the
// stage of the software's life the data comes from ("SBOM Generation Context").
type Generator struct {
	// Name is the program that wrote the SBOM: heretix-cli, or a contrib tool
	// built on this package such as rpmqa2sbom.
	Name    string
	Version string
	// Lifecycle tells a reader how to take the list: "operations" is what a
	// running system has installed, "pre-build" what a build would pull in
	// (development dependencies included), "post-build" a built image that may
	// or may not be running. Omitted from the SBOM when empty.
	Lifecycle cdx.LifecyclePhase
	// Author is the organization responsible for the SBOM (CISA's "SBOM
	// Author"), which is whoever ran the scan, not the tool. heretix-cli cannot
	// know it, so it is written only when given (collect --author).
	Author string
}

// BuildRevision is the short commit this binary was built from, or "unknown".
// A release build carries its version instead; this is for "dev" builds and
// the contrib tools, which have no version of their own.
//
// A build from a working tree with uncommitted changes says so ("e0db3d4,
// modified"): it is not that commit, and an SBOM tested against it would
// otherwise be read as the commit's output.
func BuildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return buildRevision(info.Settings)
}

func buildRevision(settings []debug.BuildSetting) string {
	revision, modified := "", false
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 {
				revision = s.Value[:7]
			}
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "unknown"
	}
	if modified {
		return revision + ", modified"
	}
	return revision
}

func GenerateCycloneDX(inv *inventory.Inventory, gen Generator) *cdx.BOM {
	pkgs := uniqueByPURL(inv)

	components := make([]cdx.Component, 0, len(pkgs))
	for _, p := range pkgs {
		purl := PackagePURL(p, inv.OS.ID)
		hashes := parseIntegrity(p.Integrity)

		// heretix:ecosystem and heretix:source preserve the exact strings
		// checker.Check and depgraph.BuildSnapshot key on. They are round-tripped
		// verbatim rather than reconstructed from the PURL because that
		// reconstruction is lossy for OS packages (the distro qualifier drops
		// information, e.g. "Ubuntu:22.04:LTS" -> "ubuntu-22.04" loses "LTS").
		props := []cdx.Property{
			{Name: "heretix:ecosystem", Value: p.Ecosystem},
			{Name: "heretix:source", Value: p.Source},
		}
		if p.Direct != nil {
			val := "false"
			if *p.Direct {
				val = "true"
			}
			props = append(props, cdx.Property{Name: "heretix:direct", Value: val})
		}
		if p.SourcePackage != "" {
			props = append(props, cdx.Property{Name: "heretix:source-package", Value: p.SourcePackage})
		}
		if p.SourceVersion != "" {
			props = append(props, cdx.Property{Name: "heretix:source-version", Value: p.SourceVersion})
		}
		if p.Category != "" {
			props = append(props, cdx.Property{Name: "heretix:category", Value: p.Category})
		}
		// Comma-separated; written whenever known, even empty, since "none
		// installed" and "not read" mean different things to a consumer.
		if p.Features != nil {
			props = append(props, cdx.Property{Name: "heretix:windows-features", Value: strings.Join(p.Features, ",")})
		}

		var evidence *cdx.Evidence
		if p.Location != "" {
			evidence = &cdx.Evidence{
				Occurrences: &[]cdx.EvidenceOccurrence{{Location: p.Location}},
			}
		}

		var licenses *cdx.Licenses
		if p.License != "" {
			l := cdx.Licenses{licenseChoiceFor(p.License)}
			licenses = &l
		}

		var scope cdx.Scope
		if p.Scope == "excluded" {
			scope = cdx.ScopeExcluded
		}

		// Maven-family sources carry "groupId:artifactId" in Name; the component
		// name should show only the artifactId.
		displayName := p.Name
		if ecosystemToPURLType[p.Source] == "maven" {
			if _, artifactID, ok := strings.Cut(p.Name, ":"); ok {
				displayName = artifactID
			}
		}

		// CISA's "Component Producer": only what the package manager recorded
		// (inventory.Package.Supplier); an unknown producer is left out.
		var supplier *cdx.OrganizationalEntity
		if p.Supplier != "" {
			supplier = &cdx.OrganizationalEntity{Name: p.Supplier}
		}

		components = append(components, cdx.Component{
			Supplier:   supplier,
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       displayName,
			Version:    p.Version,
			PackageURL: purl,
			Licenses:   licenses,
			Hashes:     hashes,
			Properties: &props,
			Evidence:   evidence,
			Scope:      scope,
		})
	}

	if os := osComponent(inv); os != nil {
		components = append(components, *os)
	}

	root := metadataComponent(inv)

	// bom.dependencies lists what each package depends on, and CycloneDX reads an
	// empty list as "depends on nothing". That is only true where the collector
	// resolved a dependency graph; elsewhere (flat lockfiles, OS packages from a
	// list rather than a package database) nobody looked, so those packages get
	// no entry and are named in a composition with aggregate "unknown" instead
	// -- CISA's 2026 minimum elements ask for unknowns to be stated, not left to
	// look like facts.
	depItems := make([]cdx.Dependency, 0, len(pkgs)+1)
	var unknownDeps []cdx.BOMReference
	var directRefs []string
	directKnown := false
	for _, p := range pkgs {
		purl := PackagePURL(p, inv.OS.ID)
		if len(p.Deps) == 0 && !dependencyGraphSources[p.Source] && !p.DepsResolved {
			unknownDeps = append(unknownDeps, cdx.BOMReference(purl))
		} else {
			// The schema forbids a repeated dependsOn entry, and a package can
			// name the same dependency twice (a Requires-Dist per extra or marker).
			deps := make([]string, 0, len(p.Deps))
			seen := make(map[string]bool, len(p.Deps))
			for _, d := range p.Deps {
				if !seen[d] {
					seen[d] = true
					deps = append(deps, d)
				}
			}
			depItems = append(depItems, cdx.Dependency{Ref: purl, Dependencies: &deps})
		}
		if p.Direct != nil {
			directKnown = true
			if *p.Direct {
				directRefs = append(directRefs, purl)
			}
		}
	}
	// The standard CycloneDX way to say which packages are direct dependencies
	// is an edge from the root (metadata.component) to each of them — the
	// heretix:direct property above is heretix-specific, so tools other than
	// heretix read directness from this edge instead. It is omitted entirely
	// when no collector determined directness (a scan that found only flat
	// lockfiles), since an empty dependsOn would claim "depends on nothing"
	// rather than "unknown".
	if directKnown {
		if directRefs == nil {
			directRefs = []string{}
		}
		depItems = append(depItems, cdx.Dependency{Ref: root.BOMRef, Dependencies: &directRefs})
	}

	// tools.components is the CycloneDX 1.5+ form; the older tools[] array is
	// deprecated, and CISA's 2026 minimum elements ask for no deprecated format.
	tools := []cdx.Component{{Type: cdx.ComponentTypeApplication, Group: "heretix", Name: gen.Name, Version: gen.Version}}
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	// Every run describes the system as it is at that moment, so it is a new
	// SBOM, not a revision of an earlier one: a new random serial number and
	// version 1. heretix-cli keeps no state between runs, so it could not count
	// revisions honestly; SBOMs of the same host are tied together by
	// metadata.component, not by the serial number.
	bom.SerialNumber = uuid.New().URN()
	bom.Metadata = &cdx.Metadata{
		Timestamp: inv.ScannedAt,
		Tools:     &cdx.ToolsChoice{Components: &tools},
		Component: root,
	}
	if gen.Lifecycle != "" {
		bom.Metadata.Lifecycles = &[]cdx.Lifecycle{{Phase: gen.Lifecycle}}
	}
	if gen.Author != "" {
		bom.Metadata.Authors = &[]cdx.OrganizationalContact{{Name: gen.Author}}
	}
	bom.Components = &components
	bom.Dependencies = &depItems
	if len(unknownDeps) > 0 {
		bom.Compositions = &[]cdx.Composition{{Aggregate: cdx.CompositionAggregateUnknown, Dependencies: &unknownDeps}}
	}
	return bom
}

// dependencyGraphSources are the sources whose collectors always record each
// package's dependencies (docs/sbom.md, the "deps" column), so that a package
// from one of them with none really has none. package-lock.json v1,
// pnpm-lock.yaml v5/v6 and a go.mod read without the go binary share a source
// name with the formats that do record them, and are counted as known for that
// reason. The OS sources are not here: their collectors resolve dependencies
// when they read a package database and say so per package (DepsResolved),
// while an SBOM built from a package list by a contrib converter has none.
var dependencyGraphSources = map[string]bool{
	"package-lock.json": true,
	"pnpm-lock.yaml":    true,
	"uv.lock":           true,
	"poetry.lock":       true,
	"go.mod":            true,
	"dist-info":         true,
	"composer.lock":     true,
}

// uniqueByPURL collapses packages that resolve to the same PURL into a single
// entry, so that no two components can end up sharing a bom-ref.
//
// CycloneDX requires every bom-ref to be unique within the BOM, and this tool
// follows the spec's own recommendation of deriving bom-ref from the PURL. That
// only holds if PURLs are unique, which inventory.Deduplicate does not by
// itself guarantee: it keys on name+version+ecosystem, while the PURL is built
// from name+version+source (plus the distro qualifier for OS packages). Two
// entries differing only in ecosystem therefore survive deduplication yet
// produce one PURL. That is not hypothetical — the Gradle collector originally
// tagged packages with ecosystem "Gradle" while Maven used "Maven", and both
// map to the same `pkg:maven/...` PURL.
//
// Merging is the correct resolution rather than a workaround: a shared PURL
// means the entries describe the same package, discovered by different routes.
// The merge is confined to SBOM output — the inventory and the vulnerability
// API path keep every entry, because ecosystem is what the API matches on.
func uniqueByPURL(inv *inventory.Inventory) []inventory.Package {
	pkgs, collapsed := inventory.DeduplicateBy(inv.Packages, func(p inventory.Package) string {
		return PackagePURL(p, inv.OS.ID)
	})

	// A collision here means two collectors disagreed about a package's
	// ecosystem, or a collector emitted a PURL it should not have. The BOM is
	// still correct, but the operator should know a collector needs attention.
	for _, purl := range collapsed {
		log.Printf("Warning: multiple packages resolved to the same PURL %s — merged into one component "+
			"(collectors may disagree on this package's ecosystem)", purl)
	}
	return pkgs
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
		version := p.Version
		// Qualifiers in the lexical key order the PURL spec requires.
		var qualifiers []string
		if p.Source == "rpm" && p.Arch != "" {
			qualifiers = append(qualifiers, "arch="+p.Arch)
		}
		if q := ecosystemToDistroQualifier(p.Ecosystem); q != "" {
			qualifiers = append(qualifiers, "distro="+q)
		}
		// The PURL spec puts an RPM epoch in its own qualifier, not the
		// version. Left in the version ("1:3.0.7-24.el9"), a consumer that
		// doesn't know to split it back out compares the package as epoch 0 —
		// so every fix released under epoch 1 reads as not yet applied, a false
		// positive. The component's own version keeps the epoch, as rpm
		// displays it.
		if p.Source == "rpm" {
			if epoch, rest, ok := strings.Cut(version, ":"); ok {
				version = rest
				qualifiers = append(qualifiers, "epoch="+epoch)
			}
		}
		purl := fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, ns, p.Name, version)
		if len(qualifiers) > 0 {
			purl += "?" + strings.Join(qualifiers, "&")
		}
		return purl
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-global", "pnpm-global", "pnpm-virtual-store":
		return npmPURL(p.Name, p.Version)
	case "windows-registry":
		// PURL has no type for Windows itself. The name stays MSRC's product
		// name ("Windows Server 2022 (Server Core installation)"), which is
		// what heretix-api matches on, percent-encoded.
		//
		// Its component is a "library" like every other package, although
		// "operating-system" would describe it better: FromCycloneDX and
		// heretix-management's import both skip operating-system components
		// as the distro descriptor osComponent writes, so typed that way the
		// OS would never be checked.
		return fmt.Sprintf("pkg:generic/microsoft/%s@%s", url.PathEscape(p.Name), p.Version)
	}

	// Maven-family sources (pom.xml, Gradle build files, JAR archives) store the
	// coordinate as "groupId:artifactId"; PURL needs it as a namespace/name pair.
	if purlType == "maven" {
		if groupID, artifactID, ok := strings.Cut(p.Name, ":"); ok {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, p.Version)
		}
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, p.Name, p.Version)
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

// metadataComponent builds the CycloneDX metadata.component describing the scanned target.
// For container images it includes a PURL with the image digest.
func metadataComponent(inv *inventory.Inventory) *cdx.Component {
	comp := &cdx.Component{
		Name:    inv.Hostname,
		Version: inv.OS.Name,
		// heretix:os-id and heretix:os-version-id preserve inv.OS.ID/VersionID,
		// which depgraph.BuildSnapshot needs (via sbom.PackagePURL) to rebuild
		// OS package PURLs but which CycloneDX has no native field for.
		Properties: &[]cdx.Property{
			{Name: "heretix:os-id", Value: inv.OS.ID},
			{Name: "heretix:os-version-id", Value: inv.OS.VersionID},
		},
	}
	// A bom-ref is needed so bom.dependencies can point from the root to its
	// direct dependencies. A container with a digest uses its PURL; anything
	// else gets a heretix-namespaced ref, which cannot collide with a package
	// component (those are always "pkg:" PURLs).
	comp.BOMRef = "heretix:target:" + inv.Hostname
	if inv.Type == "docker_image" {
		comp.Type = cdx.ComponentTypeContainer
		if inv.ImageDigest != "" {
			purl := containerPURL(inv.Hostname, inv.ImageDigest)
			comp.BOMRef = purl
			comp.PackageURL = purl
		}
	} else {
		comp.Type = cdx.ComponentTypeOS
	}
	return comp
}

// osComponent describes the scanned target's OS as a component of type
// "operating-system" — the standard CycloneDX place for it. A tool evaluating
// OS packages from an SBOM looks the distro up there, not in heretix's own
// metadata.component properties. Returns nil when no OS was detected, e.g. for
// a scan of a project directory.
//
// Name and version are os-release's ID and VERSION_ID.
// metadata.component.version keeps carrying the OS pretty name too, for
// consumers of SBOMs produced before this component existed.
func osComponent(inv *inventory.Inventory) *cdx.Component {
	if inv.OS.ID == "" {
		return nil
	}
	return &cdx.Component{
		BOMRef:      "heretix:os:" + inv.OS.ID + "@" + inv.OS.VersionID,
		Type:        cdx.ComponentTypeOS,
		Name:        inv.OS.ID,
		Version:     inv.OS.VersionID,
		Description: inv.OS.Name,
	}
}

// containerPURL builds an OCI PURL for a container image reference and digest.
// imageRef examples: "nginx:latest", "registry.example.com/myapp:v1.2"
func containerPURL(imageRef, digest string) string {
	ref := imageRef
	tag := "latest"
	// Extract tag: last colon segment that contains no slash (avoids matching registry ports)
	if i := strings.LastIndex(ref, ":"); i != -1 && !strings.Contains(ref[i+1:], "/") {
		tag = ref[i+1:]
		ref = ref[:i]
	}
	// ref is now "nginx" or "registry.example.com/ns/name"
	imgName := ref
	repoURL := ""
	if i := strings.LastIndex(ref, "/"); i != -1 {
		repoURL = ref[:i]
		imgName = ref[i+1:]
	}
	q := "tag=" + tag
	if repoURL != "" {
		q += "&repository_url=" + repoURL
	}
	return fmt.Sprintf("pkg:oci/%s@%s?%s", imgName, digest, q)
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

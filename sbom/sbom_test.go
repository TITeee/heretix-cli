package sbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/inventory"
)

// CycloneDX requires every bom-ref to be unique within a BOM, and this package
// follows the spec's recommendation of deriving bom-ref from the PURL. These
// tests guard that derivation: the first checks the invariant structurally, so
// a new collector cannot quietly break it, and the second checks the behaviour
// that keeps the BOM valid when it is broken anyway.

// sourceEcosystem records the ecosystem string each collector pairs with a
// given Package.Source. It is maintained by hand on purpose: the pairing is a
// contract between the collectors and PURL generation that nothing else
// enforces, and writing it down is what makes a violation testable.
//
// OS sources are absent because their ecosystem varies per distro and is
// carried in the PURL's distro qualifier; TestOSEcosystemsProduceDistinctPURLs
// covers those instead.
var sourceEcosystem = map[string]string{
	"requirements.txt":   "PyPI",
	"Pipfile.lock":       "PyPI",
	"poetry.lock":        "PyPI",
	"uv.lock":            "PyPI",
	"pip":                "PyPI",
	"dist-info":          "PyPI",
	"package-lock.json":  "npm",
	"yarn.lock":          "npm",
	"pnpm-lock.yaml":     "npm",
	"npm-global":         "npm",
	"pnpm-global":        "npm",
	"pnpm-virtual-store": "npm",
	"go.mod":             "Go",
	"gobinary":           "Go",
	"composer.lock":      "composer",
	"pom.xml":            "Maven",
	"build.gradle":       "Maven",
	"build.gradle.kts":   "Maven",
	"gradle.lockfile":    "Maven",
	"jar":                "Maven",
}

// osSources have a per-distro ecosystem rather than a fixed one.
var osSources = map[string]bool{"rpm": true, "dpkg": true, "apk-db": true}

// TestSourcesSharingPURLTypeShareEcosystem is the structural guard.
//
// inventory.Deduplicate keys on name+version+ecosystem, while the PURL is built
// from name+version+source. Two entries differing only in ecosystem therefore
// survive deduplication but collapse to one PURL — which would put two
// components on the same bom-ref. The only way that happens is if two sources
// mapping to the same PURL type are tagged with different ecosystems, so that
// is what this asserts.
//
// This is not theoretical: the Gradle collector shipped tagging packages
// "Gradle" while Maven used "Maven", both resolving to pkg:maven/... PURLs.
func TestSourcesSharingPURLTypeShareEcosystem(t *testing.T) {
	byPURLType := map[string]map[string][]string{} // purlType → ecosystem → sources

	for source, purlType := range ecosystemToPURLType {
		if osSources[source] {
			continue
		}
		eco, ok := sourceEcosystem[source]
		if !ok {
			t.Errorf("source %q is in ecosystemToPURLType but not in this test's sourceEcosystem map; "+
				"add it so the PURL-uniqueness invariant stays checked", source)
			continue
		}
		if byPURLType[purlType] == nil {
			byPURLType[purlType] = map[string][]string{}
		}
		byPURLType[purlType][eco] = append(byPURLType[purlType][eco], source)
	}

	for purlType, byEco := range byPURLType {
		if len(byEco) > 1 {
			t.Errorf("PURL type %q is produced by sources with %d different ecosystems %v; "+
				"packages found by two of these would survive Deduplicate but share one PURL, "+
				"putting two components on the same bom-ref",
				purlType, len(byEco), byEco)
		}
	}
}

// TestOSEcosystemsProduceDistinctPURLs checks the OS side of the same
// invariant. There the ecosystem does reach the PURL, but only through
// ecosystemToDistroQualifier, which lowercases, strips spaces and drops a
// leading "v" — all lossy. Two ecosystem strings that normalise to one
// qualifier would collide the same way.
//
// The list below must mirror what detectRPMEcosystem, detectDPKGEcosystem and
// detectAlpineEcosystem actually emit; a form this tool never produces cannot
// collide with one it does. Ubuntu is the case that makes this worth stating:
// heretix-api and heretix-management use OSV's "Ubuntu:22.04:LTS" naming, which
// normalises to the same qualifier as "Ubuntu:22.04", but the collectors here
// only ever emit the latter. Should a collector start emitting the LTS form,
// both would have to be added here and this test would fail — correctly, since
// an inventory holding both would produce two entries sharing one PURL.
func TestOSEcosystemsProduceDistinctPURLs(t *testing.T) {
	ecosystems := []string{
		// detectRPMEcosystem
		"AlmaLinux:9", "Rocky Linux:9", "Red Hat:9", "CentOS:9", "Oracle Linux:9",
		// detectDPKGEcosystem
		"Ubuntu:22.04", "Ubuntu:24.04", "Debian:12",
		// detectAlpineEcosystem — including the version-less fallback
		"Alpine:v3.21", "Alpine:",
	}

	seen := map[string]string{} // qualifier → first ecosystem that produced it
	for _, eco := range ecosystems {
		q := ecosystemToDistroQualifier(eco)
		if prev, dup := seen[q]; dup {
			t.Errorf("ecosystems %q and %q both normalise to distro qualifier %q; "+
				"packages from these would share a PURL and therefore a bom-ref", prev, eco, q)
			continue
		}
		seen[q] = eco
	}
}

// TestGenerateCycloneDXMergesCollidingPURLs is the behavioural guard: even when
// the structural invariant is violated, the emitted BOM must stay valid.
func TestGenerateCycloneDXMergesCollidingPURLs(t *testing.T) {
	// The historical Gradle/Maven case: one artifact, two collectors, two
	// ecosystem strings — so Deduplicate keeps both — but one PURL.
	inv := &inventory.Inventory{
		OS: inventory.OSInfo{ID: "ubuntu"},
		Packages: []inventory.Package{
			{
				Name: "org.slf4j:slf4j-api", Version: "1.7.36",
				Ecosystem: "Maven", Source: "pom.xml",
				Direct: inventory.BoolPtr(true),
				Deps:   []string{"pkg:maven/org.slf4j/slf4j-simple@1.7.36"},
			},
			{
				Name: "org.slf4j:slf4j-api", Version: "1.7.36",
				Ecosystem: "Gradle", Source: "build.gradle",
				License: "MIT License",
			},
			{
				Name: "org.slf4j:slf4j-simple", Version: "1.7.36",
				Ecosystem: "Maven", Source: "pom.xml",
			},
		},
	}

	bom := GenerateCycloneDX(inv, "test")

	if bom.Components == nil {
		t.Fatal("BOM has no components")
	}
	seen := map[string]bool{}
	for _, c := range *bom.Components {
		if seen[c.BOMRef] {
			t.Errorf("duplicate bom-ref %q — invalid per the CycloneDX spec", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}

	if got, want := len(libraryComponents(bom)), 2; got != want {
		t.Errorf("got %d package components, want %d (the two slf4j-api entries should merge)", got, want)
	}

	// Merging must keep what each entry contributed, not just the first one.
	var merged bool
	for _, c := range *bom.Components {
		if c.PackageURL != "pkg:maven/org.slf4j/slf4j-api@1.7.36" {
			continue
		}
		merged = true
		if c.Licenses == nil {
			t.Error("merged component lost the license contributed by the second entry")
		}
		if c.Properties == nil {
			t.Error("merged component lost the cdx:direct property from the first entry")
		}
	}
	if !merged {
		t.Error("expected a component for pkg:maven/org.slf4j/slf4j-api@1.7.36")
	}

	// Every dependency edge must point at a component that exists, or a
	// consumer cannot resolve the graph.
	if bom.Dependencies == nil {
		t.Fatal("BOM has no dependencies section")
	}
	// The root (metadata.component) is a valid dependency ref too.
	seen[bom.Metadata.Component.BOMRef] = true
	if got, want := len(*bom.Dependencies), 3; got != want {
		t.Errorf("got %d dependency entries, want %d (one per package component, plus the root)", got, want)
	}
	for _, d := range *bom.Dependencies {
		if !seen[d.Ref] {
			t.Errorf("dependency ref %q has no matching component", d.Ref)
		}
		if d.Dependencies == nil {
			continue
		}
		for _, dep := range *d.Dependencies {
			if !seen[dep] {
				t.Errorf("dependsOn %q (from %q) has no matching component", dep, d.Ref)
			}
		}
	}
}

// TestGenerateCycloneDXLeavesInventoryUnchanged pins the boundary of the merge.
// The vulnerability API matches on ecosystem, so collapsing entries there would
// drop lookups; the merge must exist only in the emitted BOM.
func TestGenerateCycloneDXLeavesInventoryUnchanged(t *testing.T) {
	inv := &inventory.Inventory{
		OS: inventory.OSInfo{ID: "ubuntu"},
		Packages: []inventory.Package{
			{Name: "org.slf4j:slf4j-api", Version: "1.7.36", Ecosystem: "Maven", Source: "pom.xml"},
			{Name: "org.slf4j:slf4j-api", Version: "1.7.36", Ecosystem: "Gradle", Source: "build.gradle"},
		},
	}

	GenerateCycloneDX(inv, "test")

	if got, want := len(inv.Packages), 2; got != want {
		t.Errorf("inventory has %d packages after SBOM generation, want %d — "+
			"the merge must not reach the inventory or the vulnerability API path", got, want)
	}
}

// TestRoundTripThroughCycloneDX guards `check`/`submit`'s ability to read a
// heretix-generated CycloneDX file in place of inventory.json. It checks only
// the fields those two commands actually consume (see checker.Check and
// depgraph.BuildSnapshot) — not every Package field is expected to survive.
func TestRoundTripThroughCycloneDX(t *testing.T) {
	inv := &inventory.Inventory{
		Hostname:  "build-host",
		ScannedAt: "2026-01-01T00:00:00Z",
		OS:        inventory.OSInfo{ID: "ubuntu", VersionID: "22.04", Name: "Ubuntu 22.04"},
		Packages: []inventory.Package{
			{
				Name: "lodash", Version: "4.17.21",
				Ecosystem: "npm", Source: "package-lock.json",
				Direct: inventory.BoolPtr(true), Location: "package-lock.json",
				Deps: []string{"pkg:npm/other@1.0.0"},
			},
			{
				Name: "requests", Version: "2.31.0",
				Ecosystem: "PyPI", Source: "requirements.txt",
				Direct: inventory.BoolPtr(false), Location: "requirements.txt",
			},
			{
				Name: "org.slf4j:slf4j-api", Version: "1.7.36",
				Ecosystem: "Maven", Source: "pom.xml",
				Location: "pom.xml",
			},
			{
				Name: "openssl", Version: "3.0.2-0ubuntu1.15",
				Ecosystem: "Ubuntu:22.04:LTS", Source: "dpkg",
			},
		},
	}

	bom := GenerateCycloneDX(inv, "test")
	got := FromCycloneDX(bom)

	if got.Hostname != inv.Hostname {
		t.Errorf("Hostname = %q, want %q", got.Hostname, inv.Hostname)
	}
	if got.OS.ID != inv.OS.ID {
		t.Errorf("OS.ID = %q, want %q (depgraph.BuildSnapshot needs this to rebuild OS package PURLs)", got.OS.ID, inv.OS.ID)
	}

	if len(got.Packages) != len(inv.Packages) {
		t.Fatalf("got %d packages, want %d", len(got.Packages), len(inv.Packages))
	}
	for i, want := range inv.Packages {
		p := got.Packages[i]
		if p.Name != want.Name {
			t.Errorf("package %d: Name = %q, want %q", i, p.Name, want.Name)
		}
		if p.Version != want.Version {
			t.Errorf("package %d: Version = %q, want %q", i, p.Version, want.Version)
		}
		if p.Ecosystem != want.Ecosystem {
			t.Errorf("package %d: Ecosystem = %q, want %q", i, p.Ecosystem, want.Ecosystem)
		}
		if p.Source != want.Source {
			t.Errorf("package %d: Source = %q, want %q", i, p.Source, want.Source)
		}
		if p.Location != want.Location {
			t.Errorf("package %d: Location = %q, want %q", i, p.Location, want.Location)
		}
		gotDirect := "nil"
		if p.Direct != nil {
			gotDirect = fmtBool(*p.Direct)
		}
		wantDirect := "nil"
		if want.Direct != nil {
			wantDirect = fmtBool(*want.Direct)
		}
		if gotDirect != wantDirect {
			t.Errorf("package %d: Direct = %s, want %s", i, gotDirect, wantDirect)
		}
		if len(p.Deps) != len(want.Deps) {
			t.Errorf("package %d: Deps = %v, want %v", i, p.Deps, want.Deps)
		} else {
			for j := range want.Deps {
				if p.Deps[j] != want.Deps[j] {
					t.Errorf("package %d: Deps[%d] = %q, want %q", i, j, p.Deps[j], want.Deps[j])
				}
			}
		}
	}
}

func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestRoundTripPreservesScopeAndCategory covers the two fields the reporting
// pipeline needs back out of an SBOM. Scope was written but never read, so
// every "check <sbom.json>" silently lost the dev-only/non-runtime marking
// that collectors had worked out.
func TestRoundTripPreservesScopeAndCategory(t *testing.T) {
	inv := &inventory.Inventory{
		OS: inventory.OSInfo{ID: "debian", VersionID: "13"},
		Packages: []inventory.Package{
			{
				Name: "libbinutils", Version: "2.44-3",
				Ecosystem: "Debian:13", Source: "dpkg",
				SourcePackage: "binutils", Category: "build", Scope: "excluded",
			},
			{
				Name: "libc6", Version: "2.41-12",
				Ecosystem: "Debian:13", Source: "dpkg",
				SourcePackage: "glibc",
			},
			{
				Name: "mocha", Version: "10.0.0",
				Ecosystem: "npm", Source: "package-lock.json",
				Scope: "excluded",
			},
		},
	}

	got := FromCycloneDX(GenerateCycloneDX(inv, "test"))
	if len(got.Packages) != len(inv.Packages) {
		t.Fatalf("got %d packages, want %d", len(got.Packages), len(inv.Packages))
	}
	for i, want := range inv.Packages {
		p := got.Packages[i]
		if p.Scope != want.Scope {
			t.Errorf("%s: Scope = %q, want %q", want.Name, p.Scope, want.Scope)
		}
		if p.Category != want.Category {
			t.Errorf("%s: Category = %q, want %q", want.Name, p.Category, want.Category)
		}
		if p.SourcePackage != want.SourcePackage {
			t.Errorf("%s: SourcePackage = %q, want %q", want.Name, p.SourcePackage, want.SourcePackage)
		}
		_ = i
	}
}

// TestGenerateCycloneDXKeepsNonRuntimeComponents guards the CISA 2026 SBOM
// "coverage" expectation: classifying a package as non-runtime must mark it,
// never drop it from the component list.
func TestGenerateCycloneDXKeepsNonRuntimeComponents(t *testing.T) {
	inv := &inventory.Inventory{
		OS: inventory.OSInfo{ID: "debian", VersionID: "13"},
		Packages: []inventory.Package{
			{Name: "linux-libc-dev", Version: "6.12.43-1", Ecosystem: "Debian:13", Source: "dpkg",
				SourcePackage: "linux", Category: "kernel", Scope: "excluded"},
		},
	}
	bom := GenerateCycloneDX(inv, "test")
	pkgs := libraryComponents(bom)
	if len(pkgs) != 1 {
		t.Fatalf("expected the kernel-header component to still be present in the BOM, got %v", bom.Components)
	}
	c := pkgs[0]
	if c.Scope != cdx.ScopeExcluded {
		t.Errorf("Scope = %q, want %q", c.Scope, cdx.ScopeExcluded)
	}
	if got := componentProperty(&c, "heretix:category"); got != "kernel" {
		t.Errorf("heretix:category = %q, want %q", got, "kernel")
	}
}

// libraryComponents returns the BOM's package components, leaving out the
// operating-system component that describes the scanned target.
func libraryComponents(bom *cdx.BOM) []cdx.Component {
	var out []cdx.Component
	if bom.Components == nil {
		return out
	}
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeLibrary {
			out = append(out, c)
		}
	}
	return out
}

// TestGenerateCycloneDXEmitsStandardOSAndDirectEdges covers the two places
// other tools (Syft/Trivy consumers, heretix-management) read what heretix
// otherwise only records in its own properties: the operating-system component,
// and edges from the root to each direct dependency.
func TestGenerateCycloneDXEmitsStandardOSAndDirectEdges(t *testing.T) {
	inv := &inventory.Inventory{
		Hostname: "web-01",
		OS:       inventory.OSInfo{ID: "rocky", VersionID: "9.3", Name: "Rocky Linux 9.3 (Blue Onyx)"},
		Packages: []inventory.Package{
			{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", Source: "package-lock.json", Direct: inventory.BoolPtr(true)},
			{Name: "minimist", Version: "1.2.8", Ecosystem: "npm", Source: "package-lock.json", Direct: inventory.BoolPtr(false)},
			{Name: "openssl-libs", Version: "1:3.0.7-24.el9", Ecosystem: "Rocky Linux:9", Source: "rpm"},
		},
	}
	bom := GenerateCycloneDX(inv, "test")

	var os *cdx.Component
	for i, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeOS {
			os = &(*bom.Components)[i]
		}
	}
	if os == nil {
		t.Fatal("expected an operating-system component")
	}
	if os.Name != "rocky" || os.Version != "9.3" || os.Description != inv.OS.Name {
		t.Errorf("OS component = %s %s %q, want rocky 9.3 %q", os.Name, os.Version, os.Description, inv.OS.Name)
	}

	rootRef := bom.Metadata.Component.BOMRef
	if rootRef == "" {
		t.Fatal("metadata.component has no bom-ref for dependencies to point from")
	}
	var rootDeps []string
	found := false
	for _, d := range *bom.Dependencies {
		if d.Ref == rootRef {
			found = true
			rootDeps = *d.Dependencies
		}
	}
	if !found {
		t.Fatal("expected a dependency entry for the root")
	}
	if len(rootDeps) != 1 || rootDeps[0] != "pkg:npm/lodash@4.17.21" {
		t.Errorf("root dependsOn = %v, want only the direct dependency lodash", rootDeps)
	}

	// Reading the SBOM back must not turn the OS component into a package.
	if got := FromCycloneDX(bom); len(got.Packages) != len(inv.Packages) {
		t.Errorf("round trip: got %d packages, want %d", len(got.Packages), len(inv.Packages))
	}
}

func TestGenerateCycloneDXOmitsWhatIsUnknown(t *testing.T) {
	// A project-directory scan: no OS detected, and no collector that knows directness.
	inv := &inventory.Inventory{
		Hostname: "src",
		Packages: []inventory.Package{
			{Name: "requests", Version: "2.31.0", Ecosystem: "PyPI", Source: "requirements.txt"},
		},
	}
	bom := GenerateCycloneDX(inv, "test")
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeOS {
			t.Errorf("unexpected operating-system component %q with no OS detected", c.Name)
		}
	}
	for _, d := range *bom.Dependencies {
		if d.Ref == bom.Metadata.Component.BOMRef {
			t.Errorf("unexpected root dependency entry %v — an empty dependsOn would claim \"no dependencies\", not \"unknown\"", *d.Dependencies)
		}
	}
}

// TestPackagePURLRPMArchAndEpoch pins the RPM PURL shape Trivy needs to
// evaluate a heretix SBOM: an arch qualifier (Rocky/Oracle Linux advisories are
// matched on exact arch, so without it nothing matches) and the epoch as a
// qualifier rather than inside the version (Trivy drops an in-version epoch
// and false-positives every fix released under a higher epoch).
func TestPackagePURLRPMArchAndEpoch(t *testing.T) {
	tests := []struct {
		name string
		pkg  inventory.Package
		want string
	}{
		{
			name: "epoch and arch",
			pkg:  inventory.Package{Name: "openssl-libs", Version: "1:3.0.7-24.el9", Ecosystem: "Rocky Linux:9", Source: "rpm", Arch: "x86_64"},
			want: "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rockylinux-9&epoch=1",
		},
		{
			name: "no epoch",
			pkg:  inventory.Package{Name: "glibc", Version: "2.34-83.el9.7", Ecosystem: "Rocky Linux:9", Source: "rpm", Arch: "x86_64"},
			want: "pkg:rpm/rocky/glibc@2.34-83.el9.7?arch=x86_64&distro=rockylinux-9",
		},
		{
			name: "no arch recorded (inventory from an older heretix-cli)",
			pkg:  inventory.Package{Name: "glibc", Version: "2.34-83.el9.7", Ecosystem: "Rocky Linux:9", Source: "rpm"},
			want: "pkg:rpm/rocky/glibc@2.34-83.el9.7?distro=rockylinux-9",
		},
		{
			// Only RPM is changed: Trivy's Debian results were identical either way.
			name: "dpkg keeps its epoch in the version",
			pkg:  inventory.Package{Name: "bsdutils", Version: "1:2.38.1-5+deb12u3", Ecosystem: "Debian:12", Source: "dpkg", Arch: "amd64"},
			want: "pkg:deb/debian/bsdutils@1:2.38.1-5+deb12u3?distro=debian-12",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osID := "rocky"
			if tt.pkg.Source == "dpkg" {
				osID = "debian"
			}
			if got := PackagePURL(tt.pkg, osID); got != tt.want {
				t.Errorf("PackagePURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoundTripPreservesRPMArchAndEpoch(t *testing.T) {
	inv := &inventory.Inventory{
		OS: inventory.OSInfo{ID: "rocky", VersionID: "9.3"},
		Packages: []inventory.Package{
			{Name: "openssl-libs", Version: "1:3.0.7-24.el9", Ecosystem: "Rocky Linux:9", Source: "rpm", Arch: "x86_64"},
		},
	}
	bom := GenerateCycloneDX(inv, "test")
	pkgs := libraryComponents(bom)
	if len(pkgs) != 1 || pkgs[0].Version != "1:3.0.7-24.el9" {
		t.Fatalf("component version = %v, want the epoch kept as rpm displays it", pkgs)
	}
	got := FromCycloneDX(bom).Packages[0]
	if got.Version != "1:3.0.7-24.el9" || got.Arch != "x86_64" {
		t.Errorf("round trip: Version=%q Arch=%q, want 1:3.0.7-24.el9 x86_64", got.Version, got.Arch)
	}
}

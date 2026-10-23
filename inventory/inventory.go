package inventory

import (
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
	Scope      string   `json:"scope,omitempty"`     // ""=unknown/required, "excluded"=dev-only (unreachable in a prod build), mirrors CycloneDX component.scope
	// SourcePackage is the upstream source package this binary package was
	// built from (dpkg "Source:", rpm SourceRpm, apk "o:"). It is what lets
	// one CVE affecting one upstream project be reported once instead of once
	// per binary package it fans out into. Empty for non-OS ecosystems.
	SourcePackage string `json:"sourcePackage,omitempty"`
	// SourceVersion is the source package's version when it differs from the
	// binary's own (dpkg "Source: lvm2 (2.03.31-2)" on dmsetup 2:1.02.205-2),
	// empty when they are the same. Debian and Ubuntu advisories give source
	// versions, so heretix-api compares this one with them.
	SourceVersion string `json:"sourceVersion,omitempty"`
	// Category marks a package that is present in the image but is not part of
	// what it runs: "kernel" (kernel headers) or "build" (build toolchain) —
	// see collector.classifyNonRuntime — or a language package whose files an
	// OS package owns (CategoryOSManaged). "" means a normal runtime package.
	Category string `json:"category,omitempty"`
	// Arch is the package's CPU architecture as the package manager records
	// it ("x86_64", "noarch"). Collected for RPM only, where it is part of
	// the package identity: per-arch Rocky/Oracle Linux advisory data can
	// only be matched against a package whose PURL carries its exact arch.
	Arch string `json:"arch,omitempty"`
	// Features lists the optional features installed on a Windows Server
	// (DISM names, "DNS-Server-Full-Role"), on the package for the OS itself.
	// heretix-api names the features a role's CVEs need, so a consumer can set
	// aside the findings of roles the server does not run. nil means unknown,
	// as for every other package.
	Features []string `json:"features,omitempty"`

	// scopeRequired records, across a merge, that some copy came from a
	// scopeDecidingSources source that placed it in production — so that
	// copy outranks another's "excluded" whatever order the copies merge in.
	scopeRequired bool
}

// scopeDecidingSources are the Package.Source values whose collector tells
// dev/test-only packages from production ones, so their empty Scope means
// "required", not "unknown". Elsewhere (pnpm's virtual store, node_modules,
// site-packages, yarn.lock, ...) an empty Scope only means the source can't
// tell. Lockfile formats too old to classify (package-lock v1, pnpm-lock
// v5/v6) still count: their packages read as required, which can only keep a
// package checked, never hide one.
var scopeDecidingSources = map[string]bool{
	"package-lock.json": true,
	"pnpm-lock.yaml":    true,
	"Pipfile.lock":      true,
	"composer.lock":     true,
	"gradle.lockfile":   true,
	"pom.xml":           true, // test scope is dropped at collection, so what remains is required
	"build.gradle":      true, // likewise for test-only configurations
}

// scopeRequired reports whether p is known to be a production dependency.
func scopeRequired(p Package) bool {
	return p.scopeRequired || (p.Scope == "" && scopeDecidingSources[p.Source])
}

// CategoryOSManaged marks a language package (PyPI, npm, Go, Maven, ...) whose
// evidence file an rpm/deb/apk package installed — python3-urllib3's
// site-packages copy of urllib3, the npm bundled inside the nodejs rpm. Matched
// at its upstream version it ignores the fixes the distro backports into its
// own release, so its findings belong to that OS package; it is never sent for
// a vulnerability check. Set by collector.markOSManaged.
const CategoryOSManaged = "os-managed"

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

// Deduplicate removes duplicate packages (same name+version+ecosystem).
// When a duplicate is found, metadata fields are merged using priority rules:
//   - Direct: true > false > nil  (direct knowledge wins over indirect or unknown)
//   - Integrity, Location, Deps:  non-empty wins over empty
func Deduplicate(pkgs []Package) []Package {
	merged, _ := DeduplicateBy(pkgs, func(p Package) string {
		return p.Name + "\t" + p.Version + "\t" + p.Ecosystem
	})
	return merged
}

// DeduplicateBy merges packages that share a key, using the same field-priority
// rules as Deduplicate. It returns the merged list and the keys that actually
// had more than one package collapsed into them.
//
// The key function is a parameter because identity is not the same question in
// every context. Deduplicate answers "is this the same installed package?" and
// keys on name+version+ecosystem. SBOM generation answers "is this the same
// component?" and keys on the PURL — a stricter requirement, since CycloneDX
// requires every bom-ref to be unique within the BOM and this tool derives
// bom-ref from the PURL. Passing the key in keeps that PURL logic in the sbom
// package, which would otherwise be an import cycle.
func DeduplicateBy(pkgs []Package, key func(Package) string) (merged []Package, collapsed []string) {
	index := make(map[string]int) // key → index in result
	dupes := map[string]bool{}
	result := []Package{}
	for _, p := range pkgs {
		k := key(p)
		if i, exists := index[k]; exists {
			result[i] = mergePkg(result[i], p)
			if !dupes[k] {
				dupes[k] = true
				collapsed = append(collapsed, k)
			}
		} else {
			index[k] = len(result)
			result = append(result, p)
		}
	}
	return result, collapsed
}

// mergePkg merges metadata from b into a, preferring the richer value per field.
func mergePkg(a, b Package) Package {
	// Decided before the field-by-field merge below rewrites a.Category.
	if (a.Category == CategoryOSManaged) != (b.Category == CategoryOSManaged) {
		return mergeWithOSManaged(a, b)
	}
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
	// Scope: "excluded" fills an unknown scope, but loses to a copy a
	// dev/prod-aware source placed in production — e.g. a package one app's
	// lockfile resolves as a production dependency and another app's as
	// dev-only, found in one scan. heretix-management never checks excluded
	// packages, so letting "excluded" win there would hide its findings.
	required := scopeRequired(a) || scopeRequired(b)
	if a.Scope == "" {
		a.Scope = b.Scope
	}
	if required {
		a.Scope = ""
	}
	a.scopeRequired = required
	// SourcePackage / Category: prefer non-empty
	if a.SourcePackage == "" {
		a.SourcePackage = b.SourcePackage
	}
	if a.SourceVersion == "" {
		a.SourceVersion = b.SourceVersion
	}
	if a.Category == "" {
		a.Category = b.Category
	}
	return a
}

// mergeWithOSManaged merges two copies of a package where exactly one is
// os-managed. An OS-owned copy says nothing about another copy that something
// else put there (a requirements.txt pin, a venv, a binary the image's own
// build copied in) — that one still needs checking. So os-managed survives a
// merge only when every copy is os-managed; here the other copy's
// classification, scope and location win, and the rest merges as usual.
func mergeWithOSManaged(a, b Package) Package {
	owned, other := a, b
	if b.Category == CategoryOSManaged {
		owned, other = b, a
	}
	owned.Category, owned.Scope, owned.Location = "", "", ""
	return mergePkg(other, owned)
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

package collector

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// CargoCollector collects Rust crates from Cargo.lock files.
type CargoCollector struct{}

func (c *CargoCollector) Name() string { return "cargo" }

func (c *CargoCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "target" || d.Name() == ".git" || isCargoRegistryDir(path) || skipWalkDir(path, scanPath) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "Cargo.lock" {
			return nil
		}

		p, err := parseCargoLock(path, verbose)
		if err != nil {
			if verbose {
				log.Printf("[cargo] error parsing %s: %v", path, err)
			}
			return nil
		}
		pkgs = append(pkgs, p...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	enrichCargoLicensesFromCache(pkgs, verbose, scanPath, isContainer)

	if verbose {
		log.Printf("[cargo] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// isCargoRegistryDir reports whether path is Cargo's own "registry" cache
// directory (CARGO_HOME/registry, holding registry/src/<index>/<name>-
// <version>/ source extractions and registry/cache/<index>/*.crate
// archives), found empirically scanning a real built image: several
// downloaded crates (anyhow, proc-macro2, quote, serde, syn, unicode-ident,
// ...) ship their own Cargo.lock inside their source tarball -- their
// maintainers' own lockfile for building and testing that crate standalone,
// describing nothing about the image being scanned. Walking into it turned
// one real Cargo.lock (74 crates) into ten (455, nearly all unrelated) in
// that test. CARGO_HOME can be anywhere (the official Rust Docker images set
// it to /usr/local/cargo, not ~/.cargo), so this is matched structurally --
// a "registry" directory whose own parent is named "cargo" or ".cargo" --
// rather than against one hardcoded path, the same way skipWalkDir matches
// "testdata" by name rather than by a fixed location.
func isCargoRegistryDir(path string) bool {
	if filepath.Base(path) != "registry" {
		return false
	}
	parent := strings.ToLower(filepath.Base(filepath.Dir(path)))
	return parent == "cargo" || parent == ".cargo"
}

// cargoLockEntry is one [[package]] table read from a Cargo.lock.
type cargoLockEntry struct {
	Name         string
	Version      string
	Source       string
	Checksum     string
	Dependencies []string
}

func cargoPURL(name, version string) string {
	return "pkg:cargo/" + name + "@" + version
}

// isCratesIoSource reports whether a Cargo.lock [[package]] table's "source"
// value names the crates.io registry: "registry+https://github.com/rust-lang/
// crates.io-index" (the git-index form) or "registry+sparse+https://
// index.crates.io/" (the sparse-index form Cargo has defaulted to since
// 1.70). A package with no source field at all is a workspace member or a
// path dependency -- local code that was never published anywhere, the same
// reason golang.go drops the main module (Main: true) before returning
// packages. A "git+..." source was fetched from a repository at an arbitrary
// ref, whose Cargo.toml sets its own version field; that number need not mean
// what it means for the same name on crates.io, so matching it against
// crates.io advisory data risks the same kind of false positive as matching
// a renamed fork. Both are skipped here rather than guessed at.
func isCratesIoSource(source string) bool {
	return strings.HasPrefix(source, "registry+")
}

var (
	cargoPackageHeaderRe = regexp.MustCompile(`^\[\[package\]\]$`)
	cargoSectionHeaderRe = regexp.MustCompile(`^\[.*\]$`)
	cargoKeyValueRe      = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.*)$`)
	cargoQuotedStringRe  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

// scanCargoLockPackages reads the [[package]] tables of a Cargo.lock.
//
// Cargo.lock is TOML, but Cargo only ever writes it in this flat, generated
// shape -- one scalar per line, dependency arrays either inline or one quoted
// string per line -- never the full generality TOML allows (nested inline
// tables, multi-line basic strings, etc.). A small line-oriented scan is
// therefore enough, the same tradeoff parseGoMod makes for go.mod, rather
// than reaching for a general TOML library to parse a file whose shape is
// this constrained.
func scanCargoLockPackages(data string) []cargoLockEntry {
	var entries []cargoLockEntry
	var current *cargoLockEntry
	inDeps := false

	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if cargoPackageHeaderRe.MatchString(line) {
			entries = append(entries, cargoLockEntry{})
			current = &entries[len(entries)-1]
			inDeps = false
			continue
		}
		if cargoSectionHeaderRe.MatchString(line) {
			// Some other table: [metadata] (pre-v3 Cargo.lock), [[metadata]], etc.
			current = nil
			inDeps = false
			continue
		}
		if current == nil {
			continue
		}

		if inDeps {
			for _, m := range cargoQuotedStringRe.FindAllStringSubmatch(line, -1) {
				current.Dependencies = append(current.Dependencies, m[1])
			}
			if strings.Contains(line, "]") {
				inDeps = false
			}
			continue
		}

		m := cargoKeyValueRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, value := m[1], m[2]

		switch key {
		case "name":
			current.Name = firstQuoted(value)
		case "version":
			current.Version = firstQuoted(value)
		case "source":
			current.Source = firstQuoted(value)
		case "checksum":
			current.Checksum = firstQuoted(value)
		case "dependencies":
			for _, m2 := range cargoQuotedStringRe.FindAllStringSubmatch(value, -1) {
				current.Dependencies = append(current.Dependencies, m2[1])
			}
			if strings.Contains(value, "[") && !strings.Contains(value, "]") {
				inDeps = true
			}
		}
	}
	return entries
}

func firstQuoted(s string) string {
	m := cargoQuotedStringRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// resolveCargoDepRef turns one element of a [[package]]'s "dependencies"
// array into the name and version it refers to. Cargo writes the bare name
// ("foo") when exactly one version of that crate is in the lockfile, and
// "name version" when several are (so the reference is ambiguous without
// it). versionsByName is every entry's own (name, version) pairs, used to
// resolve the bare form.
func resolveCargoDepRef(ref string, versionsByName map[string][]string) (name, version string, ok bool) {
	fields := strings.Fields(ref)
	switch len(fields) {
	case 1:
		name = fields[0]
		versions := versionsByName[name]
		if len(versions) != 1 {
			return "", "", false
		}
		return name, versions[0], true
	case 2:
		return fields[0], fields[1], true
	default:
		return "", "", false
	}
}

var (
	cargoDepSectionRe = regexp.MustCompile(`^\[(?:target\.[^]]*\.)?(?:dependencies|dev-dependencies|build-dependencies)\]$`)
	cargoDepKeyRe     = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=`)
)

// cargoManifestInfo is what parseCargoLock needs from the Cargo.toml next to
// a Cargo.lock: enough to tell direct dependencies from transitive ones, and
// (via devOnly) prod-reachable crates from ones kept only for `cargo
// test`/`cargo bench`.
type cargoManifestInfo struct {
	// packageName is this manifest's own [package].name -- empty for a
	// workspace's virtual root manifest, which has [workspace] but no
	// [package] of its own.
	packageName string
	// direct is every crate name declared under [dependencies],
	// [dev-dependencies] or [build-dependencies] (plus their per-target
	// "[target.'cfg(...)'.*dependencies]" form).
	direct map[string]bool
	// devOnly is the subset of direct that appears under a
	// [dev-dependencies] table and no other -- a name in both, e.g. to pin
	// extra features for tests, is required regardless of the dev-deps copy.
	devOnly map[string]bool
}

// cargoDepSectionKind classifies a TOML table header already known to match
// cargoDepSectionRe as "dev" (a dev-dependencies table) or "normal"
// (dependencies or build-dependencies -- both ship in a production build).
func cargoDepSectionKind(header string) string {
	if strings.HasSuffix(header, "dev-dependencies]") {
		return "dev"
	}
	return "normal"
}

// loadCargoManifest reads Cargo.toml in the same directory as a Cargo.lock.
// Returns nil if Cargo.toml is absent or unreadable, so callers can tell
// "legitimately none" (a non-nil cargoManifestInfo with empty sets) from
// "unknown, don't filter" -- the way loadComposerDirectSet does for
// composer.json.
//
// A workspace root's Cargo.toml commonly declares no dependencies of its own
// (a virtual manifest listing only [workspace] members, each with their own
// Cargo.toml); scanning that file alone then marks every crate in the
// workspace's single Cargo.lock as non-direct, and leaves packageName empty
// so markCargoDevOnlyScope also skips scope detection rather than guessing.
// Reading every member's Cargo.toml too would fix this, but is left for
// later -- Direct is best-effort everywhere else in this package as well
// (see parseGoMod).
func loadCargoManifest(lockPath string) *cargoManifestInfo {
	cargoToml := filepath.Join(filepath.Dir(lockPath), "Cargo.toml")
	data, err := os.ReadFile(cargoToml)
	if err != nil {
		return nil
	}

	info := &cargoManifestInfo{direct: map[string]bool{}, devOnly: map[string]bool{}}
	normalOrBuild := map[string]bool{}
	devNames := map[string]bool{}

	inPackage := false
	section := "" // "" | "normal" | "dev"
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cargoSectionHeaderRe.MatchString(line) {
			inPackage = line == "[package]"
			section = ""
			if cargoDepSectionRe.MatchString(line) {
				section = cargoDepSectionKind(line)
			}
			continue
		}
		if inPackage {
			if m := cargoKeyValueRe.FindStringSubmatch(line); m != nil && m[1] == "name" {
				info.packageName = firstQuoted(m[2])
			}
			continue
		}
		if section == "" {
			continue
		}
		m := cargoDepKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		info.direct[name] = true
		if section == "dev" {
			devNames[name] = true
		} else {
			normalOrBuild[name] = true
		}
	}

	for name := range devNames {
		if !normalOrBuild[name] {
			info.devOnly[name] = true
		}
	}
	return info
}

func cargoKey(name, version string) string { return name + "@" + version }

// markCargoDevOnlyScope sets Scope "excluded" on every locked crate that is
// reachable from the root package only through a [dev-dependencies] edge:
// present in Cargo.lock because `cargo test`/`cargo bench` need it, but
// never linked into a production build (`cargo build --release`).
//
// Cargo.lock does not tag each dependency edge by kind, but it does fold a
// *root* package's dev-dependencies into the same "dependencies" array as
// its normal and build dependencies -- a crate pulled in merely as someone
// else's ordinary dependency never has its own [dev-dependencies] consulted,
// so this folding happens only at the root. The manifest is therefore the
// only place the normal/dev split survives; this walks the lockfile's own
// graph from the root's non-dev-only direct deps to find everything a
// production build actually reaches.
//
// Skips entirely (leaving Scope unset, as for any source that can't tell)
// when there is no usable root to start from: entries is empty, the
// manifest is a workspace's virtual root with no [package] of its own, it
// declares no dev-only direct dependency at all (nothing to find is dev-only
// then, so marking is a no-op anyway), or -- the npm/pnpm precedent for this
// same guard -- the root's own entry resolves to zero non-dev-only direct
// deps, which would otherwise make every other package look unreachable and
// mark the whole lockfile excluded.
func markCargoDevOnlyScope(pkgs []inventory.Package, entries []cargoLockEntry, manifest *cargoManifestInfo) {
	if manifest == nil || manifest.packageName == "" || len(manifest.devOnly) == 0 {
		return
	}

	byKey := make(map[string]cargoLockEntry, len(entries))
	versionsByName := make(map[string][]string, len(entries))
	for _, e := range entries {
		byKey[cargoKey(e.Name, e.Version)] = e
		versionsByName[e.Name] = append(versionsByName[e.Name], e.Version)
	}

	var root *cargoLockEntry
	for i := range entries {
		if entries[i].Name == manifest.packageName {
			root = &entries[i]
			break
		}
	}
	if root == nil {
		return
	}

	var frontier []string
	for _, ref := range root.Dependencies {
		name, version, ok := resolveCargoDepRef(ref, versionsByName)
		if ok && !manifest.devOnly[name] {
			frontier = append(frontier, cargoKey(name, version))
		}
	}
	if len(frontier) == 0 {
		return
	}

	required := make(map[string]bool, len(entries))
	for len(frontier) > 0 {
		key := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if required[key] {
			continue
		}
		required[key] = true
		e, ok := byKey[key]
		if !ok {
			continue
		}
		for _, ref := range e.Dependencies {
			if name, version, ok := resolveCargoDepRef(ref, versionsByName); ok {
				frontier = append(frontier, cargoKey(name, version))
			}
		}
	}

	for i := range pkgs {
		if !required[cargoKey(pkgs[i].Name, pkgs[i].Version)] {
			pkgs[i].Scope = "excluded"
		}
	}
}

// cargoHome returns Cargo's own data directory: $CARGO_HOME, or ~/.cargo
// when unset (Cargo's documented default) -- on a live scan, where that
// env var (if any) is this real process's own, naming a real path on this
// filesystem. For an image scan, CARGO_HOME instead comes from the scanned
// image's own declared ENV (collector.applyImageEnv, since no container
// ever ran to apply it any other way) if it set one at all; such a path
// names a location inside the image, not this host, so scanPath (the
// extracted rootfs) is prefixed onto it. An image that never declared
// CARGO_HOME has no cache this function could identify -- the live host's
// own default (~/.cargo) describes the scanning machine, not the image --
// so this returns "" rather than a path that merely looks plausible.
func cargoHome(scanPath string, isContainer bool) string {
	if v := os.Getenv("CARGO_HOME"); v != "" {
		if isContainer {
			return filepath.Join(scanPath, v)
		}
		return v
	}
	if isContainer {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cargo")
}

// findCargoCrateManifest locates a downloaded crate's own Cargo.toml in
// Cargo's registry source cache: registry/src/<registry-host-hash>/
// <name>-<version>/Cargo.toml. The middle component names the registry
// (crates.io's git index and its newer sparse index hash to different
// values, and a project could use another registry entirely), so it is
// globbed rather than computed. Returns "" if the crate was never
// downloaded, or when cargoHome itself returned "".
func findCargoCrateManifest(home, name, version string) string {
	matches, err := filepath.Glob(filepath.Join(home, "registry", "src", "*", name+"-"+version, "Cargo.toml"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// cargoPackageField reads one key's value from a Cargo.toml's [package]
// table.
func cargoPackageField(data []byte, key string) string {
	inPackage := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cargoSectionHeaderRe.MatchString(line) {
			inPackage = line == "[package]"
			continue
		}
		if !inPackage {
			continue
		}
		if m := cargoKeyValueRe.FindStringSubmatch(line); m != nil && m[1] == key {
			return firstQuoted(m[2])
		}
	}
	return ""
}

// enrichCargoLicensesFromCache fills in License for packages found in
// Cargo's local registry source cache (see cargoHome) -- on a live scan,
// this host's own cache; for an image scan, the image's own cache, read
// only when the image declared its own CARGO_HOME (there being no other
// way to know where it put one). crates.io requires every published crate
// to declare "license" (an SPDX expression, used as-is) or "license-file"
// in its own Cargo.toml, so this is more often able to find an answer than
// Go's equivalent (enrichGoLicensesFromCache, live-host-only since Go sets
// no such ENV convention to extend the same way), which falls back to
// guessing from a LICENSE file's text because Go modules carry no required
// license metadata at all.
func enrichCargoLicensesFromCache(pkgs []inventory.Package, verbose bool, scanPath string, isContainer bool) {
	home := cargoHome(scanPath, isContainer)
	if home == "" {
		return
	}

	found := 0
	for i := range pkgs {
		if pkgs[i].License != "" {
			continue
		}
		manifest := findCargoCrateManifest(home, pkgs[i].Name, pkgs[i].Version)
		if manifest == "" {
			continue
		}
		data, err := os.ReadFile(manifest)
		if err != nil {
			continue
		}
		if lic := cargoPackageField(data, "license"); lic != "" {
			pkgs[i].License = lic
			found++
			continue
		}
		licenseFile := cargoPackageField(data, "license-file")
		if licenseFile == "" {
			continue
		}
		licData, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), licenseFile))
		if err != nil {
			continue
		}
		if lic := classifyLicenseText(string(licData)); lic != "" {
			pkgs[i].License = lic
			found++
		}
	}

	if verbose {
		log.Printf("[cargo] enriched %d packages with license from cache (%s)", found, home)
	}
}

// parseCargoLock parses a Cargo.lock and returns the crates sourced from
// crates.io, with their dependency graph resolved to PURLs from the
// lockfile's own "dependencies" arrays.
func parseCargoLock(path string, verbose bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	entries := scanCargoLockPackages(string(data))

	// Build name -> versions, to resolve the bare dependency-reference form.
	versionsByName := make(map[string][]string, len(entries))
	for _, e := range entries {
		versionsByName[e.Name] = append(versionsByName[e.Name], e.Version)
	}

	manifest := loadCargoManifest(path)

	var pkgs []inventory.Package
	for _, e := range entries {
		if e.Name == "" || e.Version == "" || !isCratesIoSource(e.Source) {
			continue
		}

		var deps []string
		for _, ref := range e.Dependencies {
			depName, depVersion, ok := resolveCargoDepRef(ref, versionsByName)
			if ok {
				deps = append(deps, cargoPURL(depName, depVersion))
			}
		}

		var direct *bool
		if manifest != nil {
			direct = inventory.BoolPtr(manifest.direct[e.Name])
		}

		var integrity string
		if e.Checksum != "" {
			integrity = "sha256:" + e.Checksum
		}

		pkgs = append(pkgs, inventory.Package{
			Name:       e.Name,
			Version:    e.Version,
			RawVersion: e.Version,
			Ecosystem:  "crates.io",
			Source:     "Cargo.lock",
			Location:   path,
			Direct:     direct,
			Deps:       deps,
			Integrity:  integrity,
		})
	}

	markCargoDevOnlyScope(pkgs, entries, manifest)

	if verbose {
		log.Printf("[cargo] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

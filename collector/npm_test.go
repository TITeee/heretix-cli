package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const pnpmLockFixture = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      foo:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      devtool:
        specifier: ^2.0.0
        version: 2.0.0

packages:

  foo@1.0.0:
    resolution: {integrity: sha512-aaaa==}

  shared@1.0.0:
    resolution: {integrity: sha512-bbbb==}

  devtool@2.0.0:
    resolution: {integrity: sha512-cccc==}

  shared-dev-only@1.0.0:
    resolution: {integrity: sha512-dddd==}

snapshots:

  foo@1.0.0:
    dependencies:
      shared: 1.0.0

  shared@1.0.0: {}

  devtool@2.0.0:
    dependencies:
      shared-dev-only: 1.0.0

  shared-dev-only@1.0.0: {}
`

// pnpmLockFixtureNoImporters is the same package/snapshot graph but with no
// "importers:" section, simulating an older (pre-v7) pnpm-lock.yaml. Scope must
// not be computed in this case — there is no way to tell prod from dev roots.
const pnpmLockFixtureNoImporters = `lockfileVersion: '5.4'

packages:

  foo@1.0.0:
    resolution: {integrity: sha512-aaaa==}

  devtool@2.0.0:
    resolution: {integrity: sha512-cccc==}

snapshots:

  foo@1.0.0: {}

  devtool@2.0.0: {}
`

func writeLockfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pnpm-lock.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCollect_ContainerScanSkipsHostGlobalFallback guards against reporting this
// process's own host npm/pnpm global packages as belonging to a scanned
// container image. When no lockfile is found under scanPath and isContainer is
// true, Collect must return no packages rather than falling back to "npm list
// -g"/"pnpm list -g", which run against the host, not the extracted rootfs.
func TestNPMCollect_ContainerScanSkipsHostGlobalFallback(t *testing.T) {
	dir := t.TempDir() // no lockfiles, no node_modules — global fallback would otherwise trigger

	pkgs, err := (&NPMCollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("Collect with isContainer=true returned %d packages, want 0 (host global fallback must not run for a container scan): %+v", len(pkgs), pkgs)
	}
}

// TestNPMCollect_NonRootScanSkipsHostGlobalFallback guards against reporting
// this host's own globally-installed npm/pnpm packages as belonging to a
// project scan that isn't scoped to the whole live filesystem (e.g. `collect
// --scan-path .`). See the 2026-08-30 investigation: scanning heretix-cli's
// own source tree — a Go project with no npm dependencies — picked up an
// unrelated globally-installed pnpm and its CVEs, because isContainer alone
// doesn't distinguish "scan this one directory" from "scan the whole host".
func TestNPMCollect_NonRootScanSkipsHostGlobalFallback(t *testing.T) {
	dir := t.TempDir() // absolute but not a filesystem root — global fallback would otherwise trigger

	pkgs, err := (&NPMCollector{}).Collect(dir, false, false)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("Collect on a non-root scanPath returned %d packages, want 0 (host global fallback must not run outside a whole-system scan): %+v", len(pkgs), pkgs)
	}
}

func TestParsePnpmLock_ScopeReflectsProdReachability(t *testing.T) {
	path := writeLockfile(t, pnpmLockFixture)
	pkgs, err := parsePnpmLock(path, false)
	if err != nil {
		t.Fatal(err)
	}

	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}

	want := map[string]string{
		"foo":             "",         // direct prod dependency
		"shared":          "",         // only reachable via foo (prod)
		"devtool":         "excluded", // direct dev dependency
		"shared-dev-only": "excluded", // only reachable via devtool (dev)
	}
	for name, wantScope := range want {
		if got, ok := scopes[name]; !ok {
			t.Errorf("package %q not found in parsed output", name)
		} else if got != wantScope {
			t.Errorf("package %q: got scope %q, want %q", name, got, wantScope)
		}
	}
}

func TestParsePnpmLock_NoImportersSectionLeavesScopeUnknown(t *testing.T) {
	path := writeLockfile(t, pnpmLockFixtureNoImporters)
	pkgs, err := parsePnpmLock(path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Scope != "" {
			t.Errorf("package %q: got scope %q, want \"\" (no importers section means prod/dev is unknowable)", p.Name, p.Scope)
		}
	}
}

func TestPurlToSnapshotKey(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/foo@1.2.3":          "foo@1.2.3",
		"pkg:npm/%40scope/foo@1.2.3": "@scope/foo@1.2.3",
	}
	for purl, want := range cases {
		if got := purlToSnapshotKey(purl); got != want {
			t.Errorf("purlToSnapshotKey(%q) = %q, want %q", purl, got, want)
		}
	}
}

func TestParsePackageLock_ScopeReflectsDevField(t *testing.T) {
	content := `{
  "packages": {
    "": { "dependencies": { "foo": "1.0.0" }, "devDependencies": { "devtool": "2.0.0" } },
    "node_modules/foo": { "version": "1.0.0" },
    "node_modules/devtool": { "version": "2.0.0", "dev": true }
  }
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parsePackageLock(path, false)
	if err != nil {
		t.Fatal(err)
	}
	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}
	if scopes["foo"] != "" {
		t.Errorf("foo: got scope %q, want \"\"", scopes["foo"])
	}
	if scopes["devtool"] != "excluded" {
		t.Errorf("devtool: got scope %q, want \"excluded\"", scopes["devtool"])
	}
}

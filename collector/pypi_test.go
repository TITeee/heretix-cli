package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const pipfileLockFixture = `{
  "default": {
    "requests": { "version": "==2.31.0" }
  },
  "develop": {
    "pytest": { "version": "==7.4.0" }
  }
}`

// TestCollect_ContainerScanSkipsHostGlobalFallback guards against reporting this
// process's own host pip global packages as belonging to a scanned container
// image. When no lock/requirements file is found under scanPath and
// isContainer is true, Collect must return no packages rather than falling
// back to "pip list", which runs against the host, not the extracted rootfs.
func TestPyPICollect_ContainerScanSkipsHostGlobalFallback(t *testing.T) {
	dir := t.TempDir() // no requirements files — global fallback would otherwise trigger

	pkgs, err := (&PyPICollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("Collect with isContainer=true returned %d packages, want 0 (host global fallback must not run for a container scan): %+v", len(pkgs), pkgs)
	}
}

// TestPyPICollect_NonRootScanSkipsHostGlobalFallback guards against reporting
// this host's own globally-installed pip packages as belonging to a project
// scan that isn't scoped to the whole live filesystem (e.g. `collect
// --scan-path .`). See the 2026-08-30 investigation: isContainer alone
// doesn't distinguish "scan this one directory" from "scan the whole host".
func TestPyPICollect_NonRootScanSkipsHostGlobalFallback(t *testing.T) {
	dir := t.TempDir() // absolute but not a filesystem root — global fallback would otherwise trigger

	pkgs, err := (&PyPICollector{}).Collect(dir, false, false)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("Collect on a non-root scanPath returned %d packages, want 0 (host global fallback must not run outside a whole-system scan): %+v", len(pkgs), pkgs)
	}
}

// TestPyPICollect_SitePackagesBecomesPrimarySource guards the core fix for the
// mysql:oraclelinux9 gap investigation (2026-09-14): a container image with no
// lock files at all (RPM/pip-installed straight into site-packages) must still
// report its installed PyPI packages, since site-packages/dist-info is the
// ground truth for a built image. It also checks Requires-Dist is resolved
// into Deps against the sibling package actually installed alongside it, and
// that a dependency not present in site-packages (an extras-only requirement)
// is simply omitted rather than causing an error.
func TestPyPICollect_SitePackagesBecomesPrimarySource(t *testing.T) {
	dir := t.TempDir()
	sitePkgs := filepath.Join(dir, "usr", "lib64", "python3.9", "site-packages")

	writeDistInfo(t, sitePkgs, "cryptography-46.0.7.dist-info", `Metadata-Version: 2.1
Name: cryptography
Version: 46.0.7
License-Expression: Apache-2.0 OR BSD-3-Clause
Requires-Dist: cffi (>=1.12)
Requires-Dist: sphinx (>=1.6.5) ; extra == "docs"

`)
	writeDistInfo(t, sitePkgs, "cffi-1.15.1.dist-info", `Metadata-Version: 2.1
Name: cffi
Version: 1.15.1
License: MIT

`)

	pkgs, err := (&PyPICollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byName := make(map[string]inventoryPackageForTest, len(pkgs))
	for _, p := range pkgs {
		byName[p.Name] = inventoryPackageForTest{version: p.Version, license: p.License, deps: p.Deps, source: p.Source}
	}

	crypto, ok := byName["cryptography"]
	if !ok {
		t.Fatalf("cryptography not found in collected packages: %+v", pkgs)
	}
	if crypto.version != "46.0.7" {
		t.Errorf("cryptography version = %q, want 46.0.7", crypto.version)
	}
	if crypto.license != "Apache-2.0 OR BSD-3-Clause" {
		t.Errorf("cryptography license = %q, want Apache-2.0 OR BSD-3-Clause", crypto.license)
	}
	if crypto.source != "dist-info" {
		t.Errorf("cryptography source = %q, want dist-info", crypto.source)
	}
	wantDep := "pkg:pypi/cffi@1.15.1"
	if len(crypto.deps) != 1 || crypto.deps[0] != wantDep {
		t.Errorf("cryptography deps = %v, want [%s] (sphinx is docs-only and not installed, so it must be omitted)", crypto.deps, wantDep)
	}

	if _, ok := byName["cffi"]; !ok {
		t.Errorf("cffi not found in collected packages: %+v", pkgs)
	}
}

// inventoryPackageForTest narrows inventory.Package to the fields this test asserts on.
type inventoryPackageForTest struct {
	version string
	license string
	deps    []string
	source  string
}

// writeDistInfo creates <sitePackages>/<dirName>/METADATA with the given content.
func writeDistInfo(t *testing.T, sitePackages, dirName, metadata string) {
	t.Helper()
	dir := filepath.Join(sitePackages, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "METADATA"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParsePipfileLock_ScopeReflectsDevelopSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Pipfile.lock")
	if err := os.WriteFile(path, []byte(pipfileLockFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parsePipfileLock(path, false)
	if err != nil {
		t.Fatal(err)
	}

	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}

	if got := scopes["requests"]; got != "" {
		t.Errorf("requests: got scope %q, want \"\" (default/runtime package)", got)
	}
	if got := scopes["pytest"]; got != "excluded" {
		t.Errorf("pytest: got scope %q, want \"excluded\" (develop-only package)", got)
	}
}

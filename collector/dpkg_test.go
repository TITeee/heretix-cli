package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDPKGCollect_PreservesEpoch guards against stripping the epoch prefix
// from a Debian version string. See heretix-cli bug report 2026-08-30:
// heretix-api's affectedVersions/introducedVersion/fixedVersion columns store
// OSV data with the epoch intact, and its version-range comparison treats an
// omitted epoch as 0 — sending an epoch-less version for a package that
// really has one (e.g. "shadow" is "1:4.13+dfsg1-1+deb12u1" on Debian 12)
// made it look older than long-fixed advisories, producing false positives.
func TestDPKGCollect_PreservesEpoch(t *testing.T) {
	dir := t.TempDir()
	dpkgDir := filepath.Join(dir, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	status := "Package: shadow\n" +
		"Status: install ok installed\n" +
		"Version: 1:4.13+dfsg1-1+deb12u1\n\n"
	if err := os.WriteFile(filepath.Join(dpkgDir, "status"), []byte(status), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&DPKGCollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(pkgs), pkgs)
	}
	want := "1:4.13+dfsg1-1+deb12u1"
	if pkgs[0].Version != want {
		t.Errorf("Version = %q, want %q (epoch must be preserved)", pkgs[0].Version, want)
	}
	if pkgs[0].RawVersion != want {
		t.Errorf("RawVersion = %q, want %q", pkgs[0].RawVersion, want)
	}
}

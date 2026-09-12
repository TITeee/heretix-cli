package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
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

// TestDPKGCollect_SourcePackageAndCategory covers the two fields the status
// parser learned in order to tell non-runtime packages apart: "Source:" (which
// dpkg omits when it equals the binary name, and which carries a parenthesised
// version when the two version numbers differ) and "Section:".
func TestDPKGCollect_SourcePackageAndCategory(t *testing.T) {
	dir := t.TempDir()
	dpkgDir := filepath.Join(dir, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	status := strings.Join([]string{
		"Package: libbinutils",
		"Status: install ok installed",
		"Section: libs",
		"Source: binutils",
		"Version: 2.44-3",
		"",
		"Package: linux-libc-dev",
		"Status: install ok installed",
		"Section: devel",
		"Source: linux (6.12.43-1)",
		"Version: 6.12.43-1",
		"",
		"Package: libc6",
		"Status: install ok installed",
		"Section: libs",
		"Source: glibc",
		"Version: 2.41-12",
		"",
		"Package: curl",
		"Status: install ok installed",
		"Section: web",
		"Version: 8.14.1-2",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dpkgDir, "status"), []byte(status), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&DPKGCollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byName := map[string]inventory.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	tests := []struct {
		name         string
		wantSource   string
		wantCategory string
	}{
		// Section=libs, so only the source package reveals this is build tooling.
		{"libbinutils", "binutils", CategoryBuild},
		{"linux-libc-dev", "linux", CategoryKernel},
		{"libc6", "glibc", ""},
		// No "Source:" field: the source name equals the binary name.
		{"curl", "curl", ""},
	}
	for _, tc := range tests {
		p, ok := byName[tc.name]
		if !ok {
			t.Errorf("%s was not collected", tc.name)
			continue
		}
		if p.SourcePackage != tc.wantSource {
			t.Errorf("%s: SourcePackage = %q, want %q", tc.name, p.SourcePackage, tc.wantSource)
		}
		if p.Category != tc.wantCategory {
			t.Errorf("%s: Category = %q, want %q", tc.name, p.Category, tc.wantCategory)
		}
	}
}

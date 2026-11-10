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

// Debian and Ubuntu advisories give source versions, and a binary's version
// can differ from its source's in epoch (bsdutils), in scheme (dmsetup, from
// lvm2) or both (login, "+really"). dpkg writes the source version in
// parentheses exactly when it differs; that is what has to reach heretix-api.
func TestDPKGCollect_SourceVersion(t *testing.T) {
	dir := t.TempDir()
	dpkgDir := filepath.Join(dir, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	status := strings.Join([]string{
		"Package: bsdutils",
		"Status: install ok installed",
		"Source: util-linux (2.41-5)",
		"Version: 1:2.41-5",
		"",
		"Package: login",
		"Status: install ok installed",
		"Source: util-linux (2.41-5)",
		"Version: 1:4.16.0-2+really2.41-5",
		"",
		"Package: dmsetup",
		"Status: install ok installed",
		"Source: lvm2 (2.03.31-2)",
		"Version: 2:1.02.205-2",
		"",
		"Package: mount",
		"Status: install ok installed",
		"Source: util-linux",
		"Version: 2.41-5",
		"",
		"Package: curl",
		"Status: install ok installed",
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
	got := map[string][2]string{}
	for _, p := range pkgs {
		got[p.Name] = [2]string{p.SourcePackage, p.SourceVersion}
	}
	want := map[string][2]string{
		"bsdutils": {"util-linux", "2.41-5"},
		"login":    {"util-linux", "2.41-5"},
		"dmsetup":  {"lvm2", "2.03.31-2"},
		// No version in "Source:": the source version is the binary's own.
		"mount": {"util-linux", ""},
		"curl":  {"curl", ""},
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: source = %q, want %q", name, got[name], w)
		}
	}
}

func TestParseDpkgSourceVersion(t *testing.T) {
	for in, want := range map[string]string{
		"lvm2 (2.03.31-2)":  "2.03.31-2",
		"linux (6.12.43-1)": "6.12.43-1",
		"util-linux":        "",
		"glibc ( 2.41-12 )": "2.41-12",
		"broken (":          "",
		"":                  "",
	} {
		if got := parseDpkgSourceVersion(in); got != want {
			t.Errorf("parseDpkgSourceVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// Debian files its advisories against the unsigned source (linux), not against
// the template that signs its binary (linux-signed-amd64), which carries no code
// and names the real source in Built-Using.
func TestDPKGCollect_SignedTemplateSource(t *testing.T) {
	dir := t.TempDir()
	dpkgDir := filepath.Join(dir, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	status := strings.Join([]string{
		"Package: linux-image-6.12.74+deb13+1-cloud-amd64",
		"Status: install ok installed",
		"Section: kernel",
		"Source: linux-signed-amd64 (6.12.74+2)",
		"Version: 6.12.74-2",
		"Built-Using: linux (= 6.12.74-2)",
		"",
		"Package: shim-signed",
		"Status: install ok installed",
		"Section: admin",
		"Source: shim-signed (1.47)",
		"Version: 1.47+15.8-1",
		"Built-Using: shim (= 15.8-1)",
		"",
		// No "Source:" field: the template is the package itself.
		"Package: grub-efi-amd64-signed",
		"Status: install ok installed",
		"Section: admin",
		"Version: 1+2.12+9+deb13u1",
		"Built-Using: grub2 (= 2.12-9+deb13u1)",
		"",
		// Built-Using of an ordinary package is what it links in statically.
		"Package: libslang2",
		"Status: install ok installed",
		"Section: libs",
		"Source: slang2 (2.3.3-5)",
		"Version: 2.3.3-5+b2",
		"Built-Using: unicode-data (= 15.1.0-1)",
		"",
		// More than one entry: not a template for a single source.
		"Package: sqv",
		"Status: install ok installed",
		"Source: rust-sequoia-sqv (1.3.0-3)",
		"Version: 1.3.0-3+b2",
		"Built-Using: rust-buffered-reader (= 1.3.1-2), rust-nettle (= 7.3.0-1)",
		"",
		// A signed template without Built-Using keeps what it has.
		"Package: linux-image-cloud-amd64",
		"Status: install ok installed",
		"Section: kernel",
		"Source: linux-signed-amd64 (6.12.74+2)",
		"Version: 6.12.74-2",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dpkgDir, "status"), []byte(status), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&DPKGCollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]inventory.Package{}
	for _, p := range pkgs {
		got[p.Name] = p
	}
	want := map[string][2]string{
		"linux-image-6.12.74+deb13+1-cloud-amd64": {"linux", "6.12.74-2"},
		"shim-signed":             {"shim", "15.8-1"},
		"grub-efi-amd64-signed":   {"grub2", "2.12-9+deb13u1"},
		"libslang2":               {"slang2", "2.3.3-5"},
		"sqv":                     {"rust-sequoia-sqv", "1.3.0-3"},
		"linux-image-cloud-amd64": {"linux-signed-amd64", "6.12.74+2"},
	}
	for name, w := range want {
		if g := [2]string{got[name].SourcePackage, got[name].SourceVersion}; g != w {
			t.Errorf("%s: source = %v, want %v", name, g, w)
		}
	}
	// What a package is classified as still goes by the source dpkg names.
	if c := got["linux-image-6.12.74+deb13+1-cloud-amd64"].Category; c != CategoryKernel {
		t.Errorf("signed kernel image: Category = %q, want %q", c, CategoryKernel)
	}
}

func TestParseSingleBuiltUsing(t *testing.T) {
	for in, want := range map[string][2]string{
		"linux (= 6.12.74-2)":      {"linux", "6.12.74-2"},
		"shim (= 15.8-1)":          {"shim", "15.8-1"},
		"grub2 (= 2.12-9+deb13u1)": {"grub2", "2.12-9+deb13u1"},
		"a (= 1), b (= 2)":         {"", ""},
		"":                         {"", ""},
		"linux":                    {"", ""},
		"linux (= )":               {"", ""},
		" (= 1.0)":                 {"", ""},
	} {
		name, version, ok := parseSingleBuiltUsing(in)
		if got := [2]string{name, version}; got != want || ok != (want[0] != "") {
			t.Errorf("parseSingleBuiltUsing(%q) = %q, %q, %v; want %v", in, name, version, ok, want)
		}
	}
}

// TestParseDpkgCopyrightLicense covers how the License fields of a DEP-5 file
// combine: every one applies to some of the files, so the package is under all
// of them ("and"), and a field that offers a choice stays one group.
func TestParseDpkgCopyrightLicense(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr", "share", "doc", "curl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyright := `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
License: curl

Files: lib/md4.c
License: GPL-2+ or BSD-3-clause

Files: debian/*
License: curl

License: curl
 Permission to use ...
`
	if err := os.WriteFile(filepath.Join(dir, "copyright"), []byte(copyright), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, want := parseDpkgCopyrightLicense(root, "curl"), "curl and (GPL-2+ or BSD-3-clause)"; got != want {
		t.Errorf("license = %q, want %q", got, want)
	}
	if got := parseDpkgCopyrightLicense(root, "missing"); got != "" {
		t.Errorf("no copyright file: license = %q, want empty", got)
	}
}

// TestDPKGCollect_Dependencies: Depends and Pre-Depends are resolved to the
// installed packages, through Provides for a virtual name, taking the first
// installed alternative, dropping version constraints, architecture
// qualifiers and names nothing installed provides; a package that is only
// configured, not installed, provides nothing.
func TestDPKGCollect_Dependencies(t *testing.T) {
	dir := t.TempDir()
	dpkgDir := filepath.Join(dir, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=debian\nVERSION_ID=\"13\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	status := strings.Join([]string{
		"Package: curl",
		"Status: install ok installed",
		"Architecture: amd64",
		"Version: 8.14.1-2",
		"Depends: libc6 (>= 2.34), libcurl4t64 (= 8.14.1-2)",
		"",
		"Package: libcurl4t64",
		"Status: install ok installed",
		"Architecture: amd64",
		"Source: curl",
		"Version: 8.14.1-2",
		"Depends: libc6 (>= 2.34), libssl3t64 (>= 3.0.0)",
		"",
		"Package: libc6",
		"Status: install ok installed",
		"Architecture: amd64",
		"Source: glibc",
		"Version: 2.41-12",
		"Pre-Depends: libgcc-s1 [amd64]",
		"",
		"Package: libgcc-s1",
		"Status: install ok installed",
		"Architecture: amd64",
		"Source: gcc-14",
		"Version: 14.2.0-19",
		"Depends: gcc-14-base (= 14.2.0-19)",
		"",
		"Package: mailutils",
		"Status: install ok installed",
		"Architecture: amd64",
		"Version: 1:3.17-1",
		"Depends: default-mta | mail-transport-agent, python3:any",
		"",
		"Package: exim4-daemon-light",
		"Status: install ok installed",
		"Architecture: amd64",
		"Source: exim4",
		"Version: 4.98-3",
		"Provides: mail-transport-agent",
		"",
		"Package: postfix",
		"Status: deinstall ok config-files",
		"Architecture: amd64",
		"Version: 3.10.1-1",
		"Provides: default-mta, mail-transport-agent",
		"",
		"Package: python3",
		"Status: install ok installed",
		"Architecture: amd64",
		"Source: python3-defaults",
		"Version: 3.13.5-1",
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
	if _, ok := byName["postfix"]; ok {
		t.Fatal("postfix is not installed and should not be collected")
	}

	purl := func(name, version string) string {
		return "pkg:deb/debian/" + name + "@" + version + "?distro=debian-13"
	}
	tests := []struct {
		name       string
		wantDeps   []string
		wantDirect bool
	}{
		{"curl", []string{purl("libc6", "2.41-12"), purl("libcurl4t64", "8.14.1-2")}, true},
		// libssl3t64 is not installed: dropped.
		{"libcurl4t64", []string{purl("libc6", "2.41-12")}, false},
		// Pre-Depends, with an architecture list.
		{"libc6", []string{purl("libgcc-s1", "14.2.0-19")}, false},
		{"libgcc-s1", []string{}, false},
		// default-mta is provided only by the removed postfix; the installed
		// alternative is exim4 through its Provides. ":any" is not part of a name.
		{"mailutils", []string{purl("exim4-daemon-light", "4.98-3"), purl("python3", "3.13.5-1")}, true},
		{"exim4-daemon-light", []string{}, false},
		{"python3", []string{}, false},
	}
	for _, tc := range tests {
		p, ok := byName[tc.name]
		if !ok {
			t.Errorf("%s was not collected", tc.name)
			continue
		}
		if !p.DepsResolved {
			t.Errorf("%s: DepsResolved = false, want true", tc.name)
		}
		if strings.Join(p.Deps, " ") != strings.Join(tc.wantDeps, " ") {
			t.Errorf("%s: Deps = %q, want %q", tc.name, p.Deps, tc.wantDeps)
		}
		if p.Direct == nil || *p.Direct != tc.wantDirect {
			t.Errorf("%s: Direct = %v, want %v", tc.name, p.Direct, tc.wantDirect)
		}
	}
}

func TestDpkgDependencyName(t *testing.T) {
	tests := map[string]string{
		"libgmp10 (>= 2:6.2.1+dfsg1)": "libgmp10",
		" python3:any":                "python3",
		"libc6:amd64 (>= 2.34)":       "libc6",
		"foo [i386]":                  "foo",
		"bar <!nocheck>":              "bar",
		"":                            "",
	}
	for in, want := range tests {
		if got := dpkgDependencyName(in); got != want {
			t.Errorf("dpkgDependencyName(%q) = %q, want %q", in, got, want)
		}
	}
}

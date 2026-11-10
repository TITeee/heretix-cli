package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

// TestAPKCollect_OriginIsCollectedAsSourcePackage covers the "o:" field, which
// is how an Alpine package records the origin (source) package its subpackages
// were split out of. Without it, "-dev" subpackages look like unrelated
// top-level packages.
func TestAPKCollect_OriginIsCollectedAsSourcePackage(t *testing.T) {
	root := t.TempDir()
	dbDir := filepath.Join(root, "lib", "apk", "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"),
		[]byte("ID=alpine\nVERSION_ID=3.21.3\n"), 0644); err != nil {
		t.Fatal(err)
	}

	installed := strings.Join([]string{
		"P:musl",
		"V:1.2.5-r9",
		"L:MIT",
		"o:musl",
		"",
		"P:musl-dev",
		"V:1.2.5-r9",
		"L:MIT",
		"o:musl",
		"",
		"P:busybox",
		"V:1.37.0-r12",
		"L:GPL-2.0-only",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dbDir, "installed"), []byte(installed), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&APKCollector{}).Collect(root, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byName := map[string]inventory.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if got := byName["musl-dev"].SourcePackage; got != "musl" {
		t.Errorf("musl-dev SourcePackage = %q, want %q", got, "musl")
	}
	if got := byName["musl-dev"].Category; got != CategoryBuild {
		t.Errorf("musl-dev Category = %q, want %q", got, CategoryBuild)
	}
	if got := byName["musl"].Category; got != "" {
		t.Errorf("musl Category = %q, want \"\" (runtime)", got)
	}
	// No "o:" line at all: the package is its own source.
	if got := byName["busybox"].SourcePackage; got != "busybox" {
		t.Errorf("busybox SourcePackage = %q, want %q", got, "busybox")
	}
}

// TestAPKCollect_Dependencies: "D:" entries are resolved against package
// names, "p:" provides (shared objects, commands) and the files packages own
// ("F:" directory, "R:" file), with version constraints dropped and conflicts
// ("!name") ignored.
func TestAPKCollect_Dependencies(t *testing.T) {
	root := t.TempDir()
	dbDir := filepath.Join(root, "lib", "apk", "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"),
		[]byte("ID=alpine\nVERSION_ID=3.21.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	installed := strings.Join([]string{
		"P:musl",
		"V:1.2.5-r9",
		"p:so:libc.musl-x86_64.so.1=1",
		"",
		"P:busybox",
		"V:1.37.0-r12",
		"D:so:libc.musl-x86_64.so.1",
		"p:cmd:sh=1.37.0-r12",
		"F:bin",
		"R:busybox",
		"R:sh",
		"",
		"P:libcurl",
		"V:8.12.1-r0",
		"o:curl",
		"D:so:libc.musl-x86_64.so.1 so:libssl.so.3",
		"p:so:libcurl.so.4=4",
		"",
		"P:curl",
		"V:8.12.1-r0",
		"D:/bin/sh so:libc.musl-x86_64.so.1 so:libcurl.so.4 !uclibc musl>=1.2",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dbDir, "installed"), []byte(installed), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&APKCollector{}).Collect(root, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byName := map[string]inventory.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	purl := func(name, version string) string {
		return "pkg:apk/alpine/" + name + "@" + version + "?distro=alpine-3.21"
	}
	tests := []struct {
		name       string
		wantDeps   []string
		wantDirect bool
	}{
		{"curl", []string{purl("busybox", "1.37.0-r12"), purl("libcurl", "8.12.1-r0"), purl("musl", "1.2.5-r9")}, true},
		// libssl.so.3 is provided by nothing installed: dropped.
		{"libcurl", []string{purl("musl", "1.2.5-r9")}, false},
		{"busybox", []string{purl("musl", "1.2.5-r9")}, false},
		{"musl", []string{}, false},
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

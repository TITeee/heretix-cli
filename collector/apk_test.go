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

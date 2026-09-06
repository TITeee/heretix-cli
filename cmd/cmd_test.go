package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

// withCollectFlags temporarily sets the package-level collect* flag
// variables that resolveOutputPath/writeCollectOutput read, restoring the
// previous values afterward. These are Cobra flag targets (set by flag
// parsing in real usage), not function parameters, so tests must manage
// them directly rather than passing arguments.
func withCollectFlags(t *testing.T, output, name, scanPath string) {
	t.Helper()
	prevOutput, prevName, prevScanPath := collectOutput, collectName, collectScanPath
	collectOutput, collectName, collectScanPath = output, name, scanPath
	t.Cleanup(func() {
		collectOutput, collectName, collectScanPath = prevOutput, prevName, prevScanPath
	})
}

func TestResolveOutputPath(t *testing.T) {
	tests := map[string]struct {
		output, name, scanPath, format string
		want                           string
	}{
		"--output wins over everything else": {
			output: "custom.json", name: "myapp", scanPath: "/var/lib", format: "cyclonedx",
			want: "custom.json",
		},
		"--name is used when --output is not set": {
			name: "myapp", scanPath: "/var/lib", format: "cyclonedx",
			want: "myapp.json",
		},
		"scan-path basename is used when neither --output nor --name is set": {
			scanPath: "/var/lib", format: "cyclonedx",
			want: "lib.json",
		},
		"a root scan-path falls back to the format default (cyclonedx)": {
			scanPath: "/", format: "cyclonedx",
			want: "sbom.json",
		},
		"a root scan-path falls back to the format default (json)": {
			scanPath: "/", format: "json",
			want: "inventory.json",
		},
		"a Windows drive root is treated as a root path too": {
			scanPath: `C:\`, format: "cyclonedx",
			want: "sbom.json",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			withCollectFlags(t, tc.output, tc.name, tc.scanPath)
			got := resolveOutputPath(tc.format)
			if got != tc.want {
				t.Errorf("resolveOutputPath(%q) = %q, want %q", tc.format, got, tc.want)
			}
		})
	}
}

func TestWriteCollectOutput(t *testing.T) {
	inv := &inventory.Inventory{
		Hostname: "host1",
		Packages: []inventory.Package{{Name: "curl", Version: "8.5.0", Ecosystem: "apk"}},
	}

	t.Run("cyclonedx format writes a valid CycloneDX document", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.json")
		if err := writeCollectOutput(inv, path, "cyclonedx"); err != nil {
			t.Fatalf("writeCollectOutput returned an error: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("could not read output file: %v", err)
		}
		var probe struct {
			BOMFormat string `json:"bomFormat"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if probe.BOMFormat != "CycloneDX" {
			t.Errorf("bomFormat = %q, want %q", probe.BOMFormat, "CycloneDX")
		}
	})

	t.Run("json format writes the legacy inventory document", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.json")
		if err := writeCollectOutput(inv, path, "json"); err != nil {
			t.Fatalf("writeCollectOutput returned an error: %v", err)
		}
		got, err := inventory.ReadFromFile(path)
		if err != nil {
			t.Fatalf("could not read output file back as an inventory: %v", err)
		}
		if got.Hostname != "host1" || len(got.Packages) != 1 {
			t.Errorf("unexpected round-tripped inventory: %+v", got)
		}
	})
}

func TestLoadInventoryFile(t *testing.T) {
	t.Run("loads a legacy heretix inventory JSON file", func(t *testing.T) {
		original := &inventory.Inventory{
			Hostname: "host1",
			Packages: []inventory.Package{{Name: "curl", Version: "8.5.0", Ecosystem: "apk"}},
		}
		path := filepath.Join(t.TempDir(), "inventory.json")
		if err := original.WriteToFile(path); err != nil {
			t.Fatal(err)
		}

		got, err := loadInventoryFile(path)
		if err != nil {
			t.Fatalf("loadInventoryFile returned an error: %v", err)
		}
		if got.Hostname != "host1" || len(got.Packages) != 1 || got.Packages[0].Name != "curl" {
			t.Errorf("unexpected inventory: %+v", got)
		}
	})

	t.Run("loads a heretix-generated CycloneDX SBOM via the bomFormat probe", func(t *testing.T) {
		original := &inventory.Inventory{
			Hostname: "host1",
			OS:       inventory.OSInfo{ID: "alpine", VersionID: "3.19"},
			Packages: []inventory.Package{{Name: "curl", Version: "8.5.0", Ecosystem: "apk"}},
		}
		bom := sbom.GenerateCycloneDX(original, "0.0.0-test")
		path := filepath.Join(t.TempDir(), "sbom.json")
		if err := sbom.WriteToFile(bom, path); err != nil {
			t.Fatal(err)
		}

		got, err := loadInventoryFile(path)
		if err != nil {
			t.Fatalf("loadInventoryFile returned an error: %v", err)
		}
		found := false
		for _, p := range got.Packages {
			if p.Name == "curl" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected the curl package to survive the CycloneDX round trip, got %+v", got.Packages)
		}
	})

	t.Run("returns an error for a missing file", func(t *testing.T) {
		if _, err := loadInventoryFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
			t.Error("expected an error for a missing file")
		}
	})

	t.Run("returns an error for invalid JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadInventoryFile(path); err == nil {
			t.Error("expected an error for invalid JSON")
		}
	})
}

func TestIsAuthError(t *testing.T) {
	tests := map[string]struct {
		errs []string
		want bool
	}{
		"nil slice has no auth error":                  {nil, false},
		"unrelated error has no auth error":            {[]string{"batch request failed: timeout"}, false},
		"a 401 anywhere in the message counts":         {[]string{"API returned 401: unauthorized"}, true},
		"only one of several errors needs to be a 401": {[]string{"timeout", "API returned 401: unauthorized"}, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := isAuthError(tc.errs); got != tc.want {
				t.Errorf("isAuthError(%v) = %v, want %v", tc.errs, got, tc.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := map[string]struct {
		vals []string
		want string
	}{
		"first value wins when non-empty": {[]string{"a", "b"}, "a"},
		"skips empty leading values":      {[]string{"", "", "c"}, "c"},
		"all empty yields empty":          {[]string{"", ""}, ""},
		"no arguments yields empty":       {nil, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := firstNonEmpty(tc.vals...); got != tc.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", tc.vals, got, tc.want)
			}
		})
	}
}

func TestDefaultScanPath(t *testing.T) {
	// CI runs this on ubuntu-latest, local dev runs it on Windows -- assert
	// whichever behavior actually applies to runtime.GOOS on the machine
	// running the test, rather than assuming one platform.
	if runtime.GOOS != "windows" {
		t.Run("non-Windows always returns the filesystem root", func(t *testing.T) {
			if got := defaultScanPath(); got != "/" {
				t.Errorf("defaultScanPath() = %q, want %q", got, "/")
			}
		})
		return
	}

	t.Run("uses SystemDrive when set", func(t *testing.T) {
		t.Setenv("SystemDrive", "D:")
		if got := defaultScanPath(); got != `D:\` {
			t.Errorf("defaultScanPath() = %q, want %q", got, `D:\`)
		}
	})

	t.Run("falls back to C:\\ when SystemDrive is unset", func(t *testing.T) {
		t.Setenv("SystemDrive", "")
		if got := defaultScanPath(); got != `C:\` {
			t.Errorf("defaultScanPath() = %q, want %q", got, `C:\`)
		}
	})
}

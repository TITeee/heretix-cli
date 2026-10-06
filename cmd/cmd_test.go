package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
	"github.com/spf13/cobra"
)

// withCollectFlags temporarily sets the package-level collect* flag
// variables that resolveOutputPath reads, restoring the previous values
// afterward. These are Cobra flag targets (set by flag parsing in real
// usage), not function parameters, so tests must manage them directly
// rather than passing arguments.
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
		output, name, scanPath string
		want                   string
	}{
		"--output wins over everything else": {
			output: "custom.json", name: "myapp", scanPath: "/var/lib",
			want: "custom.json",
		},
		"--name is used when --output is not set": {
			name: "myapp", scanPath: "/var/lib",
			want: "myapp.json",
		},
		"scan-path basename is used when neither --output nor --name is set": {
			scanPath: "/var/lib",
			want:     "lib.json",
		},
		"a root scan-path falls back to sbom.json": {
			scanPath: "/",
			want:     "sbom.json",
		},
		"a Windows drive root is treated as a root path too": {
			scanPath: `C:\`,
			want:     "sbom.json",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			withCollectFlags(t, tc.output, tc.name, tc.scanPath)
			if got := resolveOutputPath(); got != tc.want {
				t.Errorf("resolveOutputPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteSBOM(t *testing.T) {
	inv := &inventory.Inventory{
		Hostname: "host1",
		Packages: []inventory.Package{{Name: "curl", Version: "8.5.0", Ecosystem: "apk"}},
	}
	path := filepath.Join(t.TempDir(), "out.json")
	if err := writeSBOM(inv, path); err != nil {
		t.Fatalf("writeSBOM returned an error: %v", err)
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
}

func TestLoadSBOM(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "in.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("loads a heretix-generated CycloneDX SBOM", func(t *testing.T) {
		original := &inventory.Inventory{
			Hostname: "host1",
			OS:       inventory.OSInfo{ID: "alpine", VersionID: "3.19"},
			Packages: []inventory.Package{{Name: "curl", Version: "8.5.0", Ecosystem: "apk"}},
		}
		path := filepath.Join(t.TempDir(), "sbom.json")
		if err := sbom.WriteToFile(sbom.GenerateCycloneDX(original, "0.0.0-test"), path); err != nil {
			t.Fatal(err)
		}

		got, err := loadSBOM(path)
		if err != nil {
			t.Fatalf("loadSBOM returned an error: %v", err)
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

	// The heretix inventory JSON older versions of collect wrote is no longer
	// read; it must be named as such, so the user knows to re-run collect.
	t.Run("rejects a heretix inventory JSON with a dedicated error", func(t *testing.T) {
		path := write(t, `{"version":"1.0","hostname":"host1","packages":[{"name":"curl","version":"8.5.0","ecosystem":"apk"}]}`)
		if _, err := loadSBOM(path); !errors.Is(err, errInventoryJSON) {
			t.Errorf("loadSBOM error = %v, want errInventoryJSON", err)
		}
	})

	t.Run("rejects JSON that is not a CycloneDX SBOM", func(t *testing.T) {
		path := write(t, `{"hello":"world"}`)
		if _, err := loadSBOM(path); err == nil || errors.Is(err, errInventoryJSON) {
			t.Errorf("loadSBOM error = %v, want a not-a-CycloneDX-SBOM error", err)
		}
	})

	t.Run("returns an error for a missing file", func(t *testing.T) {
		if _, err := loadSBOM(filepath.Join(t.TempDir(), "missing.json")); err == nil {
			t.Error("expected an error for a missing file")
		}
	})

	t.Run("returns an error for invalid JSON", func(t *testing.T) {
		if _, err := loadSBOM(write(t, "not json")); err == nil {
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

// TestScanPathDefaultsAgree guards scan against drifting from collect/detect:
// scan once hard-coded "/", which on Windows is not the system drive's root.
func TestScanPathDefaultsAgree(t *testing.T) {
	want := defaultScanPath()
	for name, c := range map[string]*cobra.Command{"collect": collectCmd, "detect": detectCmd, "scan": scanCmd} {
		if got := c.Flags().Lookup("scan-path").DefValue; got != want {
			t.Errorf("%s --scan-path default = %q, want %q", name, got, want)
		}
	}
}

func TestResolveAPIKey(t *testing.T) {
	t.Run("flag wins over the environment", func(t *testing.T) {
		t.Setenv("HERETIX_API_KEY", "from-env")
		if got, err := resolveAPIKey("from-flag"); err != nil || got != "from-flag" {
			t.Errorf("resolveAPIKey = %q, %v; want from-flag", got, err)
		}
	})
	t.Run("falls back to HERETIX_API_KEY", func(t *testing.T) {
		t.Setenv("HERETIX_API_KEY", "from-env")
		if got, err := resolveAPIKey(""); err != nil || got != "from-env" {
			t.Errorf("resolveAPIKey = %q, %v; want from-env", got, err)
		}
	})
	t.Run("neither set is an error", func(t *testing.T) {
		t.Setenv("HERETIX_API_KEY", "")
		if _, err := resolveAPIKey(""); err == nil {
			t.Error("resolveAPIKey with no flag and no env returned no error")
		}
	})
}

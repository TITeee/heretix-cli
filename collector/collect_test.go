package collector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestApplyImageEnv_LiveScanIsNoop guards against a live host scan ever
// having its real environment overwritten by this mechanism, which exists
// only to make an image's own declared ENV visible during an image scan.
func TestApplyImageEnv_LiveScanIsNoop(t *testing.T) {
	t.Setenv("BUNDLE_APP_CONFIG", "/host/real/value")

	restore := applyImageEnv(false, []string{"BUNDLE_APP_CONFIG=/from/image"})
	defer restore()

	if got := os.Getenv("BUNDLE_APP_CONFIG"); got != "/host/real/value" {
		t.Errorf("isContainer=false: BUNDLE_APP_CONFIG = %q, want the host's own value untouched", got)
	}
}

// TestApplyImageEnv_SetsAndRestores covers the three cases an image scan's
// declared ENV can leave a tracked key in: overridden from unset, overridden
// from a previous value, and untouched because the image never declared it
// at all (which must not leak the image's other, untracked ENV entries, nor
// carry over whatever the host process happened to have set).
func TestApplyImageEnv_SetsAndRestores(t *testing.T) {
	os.Unsetenv("BUNDLE_APP_CONFIG")
	t.Setenv("BUNDLE_WITHOUT", "host-value")
	os.Unsetenv("CARGO_HOME")

	restore := applyImageEnv(true, []string{
		"BUNDLE_APP_CONFIG=/usr/local/bundle",
		"PATH=/usr/local/bin:/usr/bin", // not a tracked key: must be ignored
	})

	if got := os.Getenv("BUNDLE_APP_CONFIG"); got != "/usr/local/bundle" {
		t.Errorf("BUNDLE_APP_CONFIG = %q, want /usr/local/bundle (from the image's declared ENV)", got)
	}
	if _, had := os.LookupEnv("BUNDLE_WITHOUT"); had {
		t.Error("BUNDLE_WITHOUT: got set, want unset (the image never declared it, so the host's own value must not leak in)")
	}
	if _, had := os.LookupEnv("CARGO_HOME"); had {
		t.Error("CARGO_HOME: got set, want unset (neither the image nor the host declared it)")
	}

	restore()

	if _, had := os.LookupEnv("BUNDLE_APP_CONFIG"); had {
		t.Error("after restore: BUNDLE_APP_CONFIG should be unset again")
	}
	if got := os.Getenv("BUNDLE_WITHOUT"); got != "host-value" {
		t.Errorf("after restore: BUNDLE_WITHOUT = %q, want host-value", got)
	}
}

// TestIsFilesystemRoot guards the root-detection used to gate the npm/pip
// global-package-manager fallbacks. "." must NOT count as a root — it looks
// like one under a naive filepath.Dir(clean)==clean check because Clean(".")
// is a fixed point, which is exactly what let an unrelated globally-installed
// package leak into a `collect --scan-path .` scan (2026-08-30 investigation).
func TestIsFilesystemRoot(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"current directory is not a root", ".", false},
		{"relative subdirectory is not a root", "sub", false},
		{"absolute non-root directory", dir, false},
		{"absolute subdirectory", sub, false},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name string
			path string
			want bool
		}{"unix root", "/", true})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFilesystemRoot(tt.path); got != tt.want {
				t.Errorf("isFilesystemRoot(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestIsFilesystemRoot_WindowsDriveRoot only makes sense with a real drive
// letter, which t.TempDir() gives us on Windows CI without hardcoding "C:\".
func TestIsFilesystemRoot_WindowsDriveRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific")
	}
	dir := t.TempDir()
	root := filepath.VolumeName(dir) + `\`
	if !isFilesystemRoot(root) {
		t.Errorf("isFilesystemRoot(%q) = false, want true", root)
	}
}

func TestSkipAllExcept(t *testing.T) {
	skip, err := SkipAllExcept([]string{"Windows"})
	if err != nil {
		t.Fatalf("SkipAllExcept: %v", err)
	}
	if len(skip) != len(CollectorNames)-1 {
		t.Fatalf("skip = %v, want every collector but windows", skip)
	}
	for _, s := range skip {
		if s == "windows" {
			t.Errorf("windows is in the skip list %v", skip)
		}
	}

	// Several names, in any case, with blanks and repeats ignored.
	skip, err = SkipAllExcept([]string{"npm", " PyPI ", "", "npm"})
	if err != nil {
		t.Fatalf("SkipAllExcept: %v", err)
	}
	if len(skip) != len(CollectorNames)-2 {
		t.Errorf("skip = %v, want every collector but npm and pypi", skip)
	}
}

// A mistyped --only would otherwise skip everything and write an empty SBOM.
func TestSkipAllExceptRejectsWhatCannotBeKept(t *testing.T) {
	for _, only := range [][]string{{"windoze"}, {"windows", "nope"}, {}, {" ", ""}} {
		if skip, err := SkipAllExcept(only); err == nil {
			t.Errorf("SkipAllExcept(%q) = %v, want an error", only, skip)
		}
	}
}

// CollectorNames is what --skip and --only accept, so it has to name every
// collector CollectAll can register, or --only could not keep it.
func TestCollectorNamesCoverEveryCollector(t *testing.T) {
	all := []Collector{
		&RPMCollector{}, &DPKGCollector{}, &APKCollector{}, &WindowsCollector{},
		&PyPICollector{}, &NPMCollector{}, &GoCollector{}, &GoBinaryCollector{},
		&ComposerCollector{}, &CargoCollector{}, &BundlerCollector{}, &MavenCollector{}, &GradleCollector{}, &JARCollector{},
	}
	if len(all) != len(CollectorNames) {
		t.Fatalf("%d collectors, %d names in CollectorNames", len(all), len(CollectorNames))
	}
	names := map[string]bool{}
	for _, n := range CollectorNames {
		names[n] = true
	}
	for _, c := range all {
		if !names[c.Name()] {
			t.Errorf("collector %q is not in CollectorNames", c.Name())
		}
	}
}

// Skipping every collector the system has is allowed, but the empty SBOM must
// not pass for a clean system: it logs a warning (and still succeeds).
func TestCollectAllWithNothingLeft(t *testing.T) {
	skip, err := SkipAllExcept([]string{"windows"})
	if runtime.GOOS == "windows" {
		t.Skip("windows is available here")
	}
	if err != nil {
		t.Fatal(err)
	}
	inv, err := CollectAll(t.TempDir(), skip, false, false, nil)
	if err != nil {
		t.Fatalf("CollectAll: %v", err)
	}
	if len(inv.Packages) != 0 {
		t.Errorf("got %d packages, want none", len(inv.Packages))
	}
}

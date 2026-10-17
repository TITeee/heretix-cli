package collector

import (
	"path/filepath"
	"runtime"
	"testing"
)

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
		&ComposerCollector{}, &MavenCollector{}, &GradleCollector{}, &JARCollector{},
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
	inv, err := CollectAll(t.TempDir(), skip, false, false)
	if err != nil {
		t.Fatalf("CollectAll: %v", err)
	}
	if len(inv.Packages) != 0 {
		t.Errorf("got %d packages, want none", len(inv.Packages))
	}
}

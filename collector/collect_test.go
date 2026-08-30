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

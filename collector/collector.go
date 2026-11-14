package collector

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// skipWalkDir reports whether a collector's directory walk should leave a
// directory out: a testdata directory, or Windows' own system directories on
// a whole-drive Windows scan.
func skipWalkDir(path, scanPath string) bool {
	return isTestdataDir(path, scanPath) || isWindowsSystemDir(runtime.GOOS, path, scanPath)
}

// windowsSystemDirs are the top-level directories of a Windows drive that
// hold the OS and its bookkeeping, not installed applications. C:\Windows
// alone is several hundred thousand entries (WinSxS keeps every component
// version), and every collector walks the drive on its own, so walking them
// made a default scan of a Windows server take tens of minutes. The OS itself
// is covered by the windows collector, which reads the registry.
var windowsSystemDirs = []string{"Windows", "$Recycle.Bin", "System Volume Information"}

// isWindowsSystemDir reports whether path is one of windowsSystemDirs directly
// under a drive root that is itself the scan path, on a Windows host. A scan
// path below the root (a project directory, an extracted image) is walked in
// full, as is a directory of the same name anywhere deeper.
func isWindowsSystemDir(goos, path, scanPath string) bool {
	if goos != "windows" {
		return false
	}
	name := filepath.Base(path)
	matched := false
	for _, d := range windowsSystemDirs {
		if strings.EqualFold(name, d) {
			matched = true
			break
		}
	}
	if !matched || !isFilesystemRoot(scanPath) {
		return false
	}
	return filepath.Clean(filepath.Dir(path)) == filepath.Clean(scanPath)
}

// isTestdataDir reports whether a directory is named "testdata". Its contents
// are test fixtures — the Go toolchain never builds or ships them, and every
// local security check skips them — so a manifest found there (a
// requirements.txt a test parses, say) describes no real dependency, and
// collecting it would only produce false findings. Every collector's
// directory walk skips it — except as the scan root itself, which the user
// asked for explicitly.
func isTestdataDir(path, scanPath string) bool {
	return filepath.Base(path) == "testdata" && filepath.Clean(path) != filepath.Clean(scanPath)
}

// Collector is the interface that each ecosystem scanner must implement.
type Collector interface {
	// Name returns the collector's identifier (e.g. "rpm", "pypi", "npm").
	Name() string
	// Collect scans the system and returns discovered packages.
	// scanPath is the filesystem root to search under.
	// verbose enables detailed logging.
	// isContainer is true when scanPath is an extracted container rootfs rather
	// than the live host filesystem — collectors must not fall back to querying
	// the host's own package managers in that case, since the result would
	// describe the host, not the image being scanned.
	Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error)
}

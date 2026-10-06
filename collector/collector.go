package collector

import (
	"path/filepath"

	"github.com/TITeee/heretix-cli/inventory"
)

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

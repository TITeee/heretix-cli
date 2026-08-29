package collector

import (
	"github.com/TITeee/heretix-cli/inventory"
)

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

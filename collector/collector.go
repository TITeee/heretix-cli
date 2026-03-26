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
	Collect(scanPath string, verbose bool) ([]inventory.Package, error)
}

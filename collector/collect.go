package collector

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// CollectAll runs all collectors (except those in skip) and returns a deduplicated inventory.
func CollectAll(scanPath string, skip []string, verbose bool) (*inventory.Inventory, error) {
	skipSet := make(map[string]bool)
	for _, s := range skip {
		skipSet[strings.ToLower(s)] = true
	}

	collectors := []Collector{
		&RPMCollector{},
		&DPKGCollector{},
		&APKCollector{},
		&PyPICollector{},
		&NPMCollector{},
	}

	hostname, _ := os.Hostname()
	osInfo := detectOSInfo(scanPath)
	inv := inventory.New(hostname, osInfo)

	var allPkgs []inventory.Package
	collectorErrors := 0

	for _, c := range collectors {
		if skipSet[c.Name()] {
			if verbose {
				log.Printf("[collect] skipping %s collector", c.Name())
			}
			continue
		}

		pkgs, err := c.Collect(scanPath, verbose)
		if err != nil {
			log.Printf("Warning: %s collector failed: %v", c.Name(), err)
			collectorErrors++
			continue
		}
		allPkgs = append(allPkgs, pkgs...)
	}

	activeCollectors := len(collectors) - len(skipSet)
	if collectorErrors >= activeCollectors {
		return nil, fmt.Errorf("all collectors failed")
	}

	inv.Packages = inventory.Deduplicate(allPkgs)
	return inv, nil
}

// detectOSInfo reads <scanPath>/etc/os-release (or /usr/lib/os-release as fallback)
// to populate OS metadata. Alpine Linux uses a symlink for /etc/os-release which
// may not be resolved correctly after tar extraction, so both paths are tried.
func detectOSInfo(scanPath string) inventory.OSInfo {
	info := inventory.OSInfo{
		ID:        "unknown",
		VersionID: "unknown",
		Name:      "Unknown",
	}

	candidates := []string{
		filepath.Join(scanPath, "etc", "os-release"),
		filepath.Join(scanPath, "usr", "lib", "os-release"),
	}

	var data []byte
	for _, p := range candidates {
		if d, err := os.ReadFile(p); err == nil {
			data = d
			break
		}
	}
	if data == nil {
		return info
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			info.ID = v
		case "VERSION_ID":
			info.VersionID = v
		case "PRETTY_NAME":
			info.Name = v
		}
	}
	return info
}

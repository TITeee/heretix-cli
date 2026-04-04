package collector

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// CollectAll runs all collectors (except those in skip) and returns a deduplicated inventory.
// isContainer should be true when scanning an extracted container rootfs — on Windows this
// re-enables the Linux OS package collectors (RPM, DPKG, APK) which are otherwise skipped.
func CollectAll(scanPath string, skip []string, verbose bool, isContainer bool) (*inventory.Inventory, error) {
	skipSet := make(map[string]bool)
	for _, s := range skip {
		skipSet[strings.ToLower(s)] = true
	}

	collectors := []Collector{}
	if runtime.GOOS != "windows" || isContainer {
		collectors = append(collectors, &RPMCollector{}, &DPKGCollector{}, &APKCollector{})
	}
	collectors = append(collectors, &PyPICollector{}, &NPMCollector{})

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
// On Windows hosts, it queries `cmd /c ver` instead of reading os-release.
func detectOSInfo(scanPath string) inventory.OSInfo {
	info := inventory.OSInfo{
		ID:        "unknown",
		VersionID: "unknown",
		Name:      "Unknown",
	}

	if runtime.GOOS == "windows" {
		return detectOSInfoWindows()
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

// detectOSInfoWindows queries `cmd /c ver` to populate OS metadata on Windows hosts.
// Example output: "Microsoft Windows [Version 10.0.19041.1234]"
func detectOSInfoWindows() inventory.OSInfo {
	fallback := inventory.OSInfo{ID: "windows", VersionID: "unknown", Name: "Microsoft Windows"}

	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return fallback
	}

	line := strings.TrimSpace(string(out))
	re := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	ver := re.FindString(line)
	if ver == "" {
		return fallback
	}
	return inventory.OSInfo{
		ID:        "windows",
		VersionID: ver,
		Name:      "Microsoft Windows " + ver,
	}
}

package collector

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// windowsVersionKey is the registry key the Windows release and build are
// read from, recorded as the package's Location.
const windowsVersionKey = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// windowsServerReleases maps the OS build of each Windows Server release that
// heretix-api imports from MSRC to its name. A release keeps its build for its
// whole life; the monthly cumulative updates raise only the UBR. Keep in line
// with heretix-api's WINDOWS_SERVER_BUILDS.
var windowsServerReleases = map[uint64]string{
	14393: "2016",
	17763: "2019",
	20348: "2022",
	26100: "2025",
}

// windowsVersion is what readWindowsVersion reads from windowsVersionKey.
type windowsVersion struct {
	ProductName      string // "Windows Server 2022 Standard", for messages only
	InstallationType string // "Client", "Server", "Server Core" or "Nano Server"
	Major, Minor     uint64 // 10, 0
	Build            uint64 // CurrentBuild: 20348
	UBR              uint64 // update build revision: 5761
	HasUBR           bool
}

// WindowsCollector reports the Windows Server release the host runs as one
// package, named as MSRC names the product ("Windows Server 2022", or
// "Windows Server 2022 (Server Core installation)") and versioned by its full
// OS build including the UBR ("10.0.20348.5761"). heretix-api matches it
// against the build of the update that fixes each CVE.
//
// It describes the live host, so it only runs for a scan of the filesystem
// root, like the global npm and pip fallbacks (see isFilesystemRoot).
type WindowsCollector struct{}

func (c *WindowsCollector) Name() string { return "windows" }

func (c *WindowsCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	if isContainer || !isFilesystemRoot(scanPath) {
		return nil, nil
	}
	v, err := readWindowsVersion()
	if err != nil {
		return nil, fmt.Errorf("read the Windows version from %s: %w", windowsVersionKey, err)
	}
	p, ok, warning := windowsServerPackage(v)
	if warning != "" {
		log.Printf("Warning: %s", warning)
	}
	if !ok {
		if verbose {
			log.Printf("[windows] %q (%s, build %d) is not a Windows Server release to check", v.ProductName, v.InstallationType, v.Build)
		}
		return nil, nil
	}
	if verbose {
		log.Printf("[windows] %s %s", p.Name, p.Version)
	}
	// Best effort: without them every finding is reported, as before.
	if features, err := readWindowsFeatures(); err != nil {
		if verbose {
			log.Printf("[windows] installed features not read, so role findings cannot be set aside: %v", err)
		}
	} else {
		p.Features = features
		if verbose {
			log.Printf("[windows] %d optional features installed", len(features))
		}
	}
	return []inventory.Package{p}, nil
}

// parseWindowsFeatures reads the feature names readWindowsFeatures' query
// prints, one per line, into a sorted, de-duplicated list. Never nil: a
// server with nothing optional installed is known to have none.
func parseWindowsFeatures(out string) []string {
	seen := map[string]bool{}
	features := []string{}
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		features = append(features, name)
	}
	sort.Strings(features)
	return features
}

// windowsServerPackage builds the package for a Windows Server host. ok is
// false for anything else: a client Windows, Nano Server (serviced as a
// container image), or a release heretix-api does not import. warning
// explains a Windows Server that is left out, so a scan does not look as if
// it had checked the OS.
func windowsServerPackage(v windowsVersion) (p inventory.Package, ok bool, warning string) {
	var suffix string
	switch v.InstallationType {
	case "Server":
	case "Server Core":
		suffix = " (Server Core installation)"
	default:
		return inventory.Package{}, false, ""
	}

	release, known := windowsServerReleases[v.Build]
	if !known {
		return inventory.Package{}, false, fmt.Sprintf(
			"%s (build %d) is not covered by the OS vulnerability check; only Windows Server 2016, 2019, 2022 and 2025 are",
			v.ProductName, v.Build)
	}
	// Without the UBR the version would read as the release's first build,
	// and every CVE fixed since would be reported.
	if !v.HasUBR {
		return inventory.Package{}, false, fmt.Sprintf(
			"%s: the update build revision (UBR) could not be read, so the OS is not checked", v.ProductName)
	}

	return inventory.Package{
		Name:      "Windows Server " + release + suffix,
		Version:   fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Build, v.UBR),
		Ecosystem: "advisory",
		Source:    "windows-registry",
		Location:  windowsVersionKey,
	}, true, ""
}

package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// RPMCollector collects packages from the RPM database.
type RPMCollector struct{}

func (c *RPMCollector) Name() string { return "rpm" }

func (c *RPMCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("rpm"); err != nil {
		return nil, nil
	}

	args := []string{"-qa", "--queryformat", `%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n`}
	if scanPath != "/" {
		// Use alternate root for container/image scanning
		args = append([]string{"--root", scanPath}, args...)
	}

	cmd := exec.Command("rpm", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm -qa failed: %w", err)
	}

	ecosystem := detectRPMEcosystem(scanPath)

	var pkgs []inventory.Package
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			if verbose {
				log.Printf("[rpm] skipping malformed line: %s", line)
			}
			continue
		}
		name := parts[0]
		rawVersion := parts[1]
		version := cleanRPMVersion(rawVersion)

		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    version,
			RawVersion: rawVersion,
			Ecosystem:  ecosystem,
			Source:     "rpm",
		})
	}

	if verbose {
		log.Printf("[rpm] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// cleanRPMVersion removes only the epoch from an RPM version string,
// preserving the release suffix required for distro exact-match in vuln-api.
// "1:7.88.1-4.el9" → "7.88.1-4.el9"
// "0:2.36.1-8.el9" → "2.36.1-8.el9"
// "7.88.1-4.el9"   → "7.88.1-4.el9"  (no epoch, unchanged)
func cleanRPMVersion(raw string) string {
	if idx := strings.Index(raw, ":"); idx != -1 {
		return raw[idx+1:]
	}
	return raw
}

// detectRPMEcosystem reads <scanPath>/etc/os-release to determine the ecosystem name
// in the format required by vuln-api: "<Distro>:<MajorVersion>" (e.g., "AlmaLinux:9").
func detectRPMEcosystem(scanPath string) string {
	id, versionID := parseOSRelease(scanPath)
	major := strings.SplitN(versionID, ".", 2)[0]

	switch id {
	case "almalinux":
		return "AlmaLinux:" + major
	case "rocky":
		return "Rocky:" + major
	case "rhel":
		return "Red Hat:" + major
	case "centos":
		return "CentOS:" + major
	default:
		return "AlmaLinux:" + major
	}
}

// parseOSRelease reads /etc/os-release from the given root and returns (ID, VERSION_ID).
func parseOSRelease(scanPath string) (id, versionID string) {
	osReleasePath := filepath.Join(scanPath, "etc", "os-release")
	data, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok {
			v = strings.Trim(v, `"`)
			switch k {
			case "ID":
				id = v
			case "VERSION_ID":
				versionID = v
			}
		}
	}
	return id, versionID
}

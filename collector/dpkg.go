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

// DPKGCollector collects packages from the dpkg database (Debian/Ubuntu).
type DPKGCollector struct{}

func (c *DPKGCollector) Name() string { return "dpkg" }

func (c *DPKGCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	statusPath := filepath.Join(scanPath, "var", "lib", "dpkg", "status")

	if _, err := os.Stat(statusPath); err != nil {
		if scanPath != "/" {
			// No dpkg database in this container image
			return nil, nil
		}
		// Live system without status file: fall back to dpkg-query
		return c.collectViaDpkgQuery(verbose)
	}

	return c.parseStatusFile(statusPath, scanPath, verbose)
}

// parseStatusFile parses <scanPath>/var/lib/dpkg/status directly.
// This works for both live systems and extracted container filesystems.
func (c *DPKGCollector) parseStatusFile(statusPath, scanPath string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("open dpkg status: %w", err)
	}
	defer f.Close()

	ecosystem := detectDPKGEcosystem(scanPath)

	var pkgs []inventory.Package
	var currentPkg, currentVersion, currentStatus string

	flush := func() {
		if currentPkg != "" && currentVersion != "" && strings.Contains(currentStatus, "install ok installed") {
			version := cleanDPKGVersion(currentVersion)
			pkgs = append(pkgs, inventory.Package{
				Name:       currentPkg,
				Version:    version,
				RawVersion: currentVersion,
				Ecosystem:  ecosystem,
				Source:     "dpkg",
			})
		}
		currentPkg, currentVersion, currentStatus = "", "", ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package: "):
			currentPkg = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			currentVersion = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Status: "):
			currentStatus = strings.TrimPrefix(line, "Status: ")
		}
	}
	flush() // handle final record

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if verbose {
		log.Printf("[dpkg] collected %d packages from %s", len(pkgs), statusPath)
	}
	return pkgs, nil
}

// collectViaDpkgQuery falls back to dpkg-query for live systems without a readable status file.
func (c *DPKGCollector) collectViaDpkgQuery(verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		return nil, fmt.Errorf("dpkg-query command not found: %w", err)
	}

	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query failed: %w", err)
	}

	ecosystem := detectDPKGEcosystem("/")

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
				log.Printf("[dpkg] skipping malformed line: %s", line)
			}
			continue
		}
		name := parts[0]
		rawVersion := parts[1]
		if rawVersion == "" {
			continue
		}
		version := cleanDPKGVersion(rawVersion)
		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    version,
			RawVersion: rawVersion,
			Ecosystem:  ecosystem,
			Source:     "dpkg",
		})
	}

	if verbose {
		log.Printf("[dpkg] collected %d packages via dpkg-query", len(pkgs))
	}
	return pkgs, nil
}

// cleanDPKGVersion removes the epoch prefix from a Debian version string.
// Unlike RPM, Debian versions retain the release suffix for OSV matching.
// "1:7.88.1-1"       → "7.88.1-1"
// "5.1-2+deb11u1"    → "5.1-2+deb11u1"  (no epoch, unchanged)
// "2:1.0.0-1ubuntu1" → "1.0.0-1ubuntu1"
func cleanDPKGVersion(raw string) string {
	if idx := strings.Index(raw, ":"); idx != -1 {
		return raw[idx+1:]
	}
	return raw
}

// detectDPKGEcosystem reads <scanPath>/etc/os-release to determine the ecosystem name
// in the format required by vuln-api: "<Distro>:<Version>" (e.g., "Ubuntu:22.04").
func detectDPKGEcosystem(scanPath string) string {
	id, versionID := parseOSRelease(scanPath)

	switch id {
	case "ubuntu":
		return "Ubuntu:" + versionID
	case "debian":
		return "Debian:" + versionID
	default:
		if versionID != "" {
			return "Debian:" + versionID
		}
		return "Debian:12"
	}
}

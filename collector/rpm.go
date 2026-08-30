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

func (c *RPMCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("rpm"); err != nil {
		return nil, nil
	}

	args := []string{"-qa", "--queryformat", `%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{LICENSE}\n`}
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
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			if verbose {
				log.Printf("[rpm] skipping malformed line: %s", line)
			}
			continue
		}
		name := parts[0]
		rawVersion := parts[1]
		version := cleanRPMVersion(rawVersion)
		var license string
		if len(parts) == 3 && parts[2] != "(none)" {
			license = parts[2]
		}

		pkgs = append(pkgs, inventory.Package{
			Name:       name,
			Version:    version,
			RawVersion: rawVersion,
			Ecosystem:  ecosystem,
			Source:     "rpm",
			License:    license,
		})
	}

	if verbose {
		log.Printf("[rpm] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// cleanRPMVersion drops an epoch of "(none)" or "0" from an RPM version
// string — both mean "no epoch", and heretix-api's version comparison
// already treats an omitted epoch as 0. Any other epoch is preserved: it is
// the highest-precedence field in RPM version comparison, so dropping a real
// one (e.g. "2:") makes an already-patched package with an epoch bump look
// older than an advisory's fixed version, which is exactly what happened
// before this handled "(none)"/"0" as special cases instead of stripping
// every epoch unconditionally.
//
// "(none):7.88.1-4.el9" → "7.88.1-4.el9"  (rpm's placeholder for an unset %{EPOCH} tag)
// "0:2.36.1-8.el9"      → "2.36.1-8.el9"  (explicit zero epoch, same meaning)
// "2:4.9-6.el9"         → "2:4.9-6.el9"   (real epoch — preserved)
// "7.88.1-4.el9"        → "7.88.1-4.el9"  (no colon at all, unchanged)
func cleanRPMVersion(raw string) string {
	if rest, ok := strings.CutPrefix(raw, "(none):"); ok {
		return rest
	}
	if rest, ok := strings.CutPrefix(raw, "0:"); ok {
		return rest
	}
	return raw
}

// detectRPMEcosystem reads <scanPath>/etc/os-release to determine the ecosystem name
// in the format required by vuln-api: "<Distro>:<MajorVersion>" (e.g., "AlmaLinux:9").
//
// Oracle Linux is the one exception: heretix-api's AdvisoryAffectedProduct rows for
// Oracle Linux aren't split by major version, so its search routing matches the bare
// value "oracle-linux" with no version suffix (see heretix-api's rpmAdvisoryVendor()).
// This used to be "Oracle Linux:" + major, changed in 750b4ee under the mistaken
// assumption that all RPM distros shared one prefix+version convention — heretix-api
// has carried an alias for that form since, but keep this the canonical value.
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
	case "ol":
		return "oracle-linux"
	default:
		return "AlmaLinux:" + major
	}
}

// parseOSRelease reads /etc/os-release (or /usr/lib/os-release as fallback) from the
// given root and returns (ID, VERSION_ID). The fallback handles cases where
// /etc/os-release is a symlink that cannot be resolved after tar extraction.
func parseOSRelease(scanPath string) (id, versionID string) {
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

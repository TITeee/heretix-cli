package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// APKCollector collects packages from the Alpine Linux APK database.
type APKCollector struct{}

func (c *APKCollector) Name() string { return "apk" }

func (c *APKCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	dbPath := filepath.Join(scanPath, "lib", "apk", "db", "installed")

	if _, err := os.Stat(dbPath); err != nil {
		// No APK database found
		return nil, nil
	}

	ecosystem := detectAlpineEcosystem(scanPath)
	if verbose {
		log.Printf("[apk] detected ecosystem: %q", ecosystem)
	}

	pkgs, err := parseAPKDatabase(dbPath, ecosystem, verbose)
	if err != nil {
		return nil, fmt.Errorf("parse apk database: %w", err)
	}

	if verbose {
		log.Printf("[apk] collected %d packages from %s", len(pkgs), dbPath)
	}
	return pkgs, nil
}

// detectAlpineEcosystem returns "Alpine:{VERSION_ID}" if the OS is Alpine.
// Tries /etc/os-release first, then /usr/lib/os-release as fallback
// (Alpine uses a symlink for /etc/os-release which may not resolve after tar extraction).
// Returns "" if the Alpine version cannot be determined.
func detectAlpineEcosystem(scanPath string) string {
	candidates := []string{
		filepath.Join(scanPath, "etc", "os-release"),
		filepath.Join(scanPath, "usr", "lib", "os-release"),
	}

	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}

		var id, versionID string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "ID":
				id = strings.ToLower(v)
			case "VERSION_ID":
				versionID = v
			}
		}

		if id == "alpine" && versionID != "" {
			// Normalize to "Alpine:vMAJOR.MINOR" (e.g. "3.21.3" → "v3.21")
			parts := strings.SplitN(versionID, ".", 3)
			if len(parts) >= 2 {
				return "Alpine:v" + parts[0] + "." + parts[1]
			}
			return "Alpine:v" + versionID
		}
	}

	return ""
}

// parseAPKDatabase parses /lib/apk/db/installed.
// The file consists of package entries separated by blank lines.
// Each entry contains key-value pairs: "P:" = name, "V:" = version.
func parseAPKDatabase(dbPath string, ecosystem string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	var name, version string

	flush := func() {
		if name != "" && version != "" {
			pkgs = append(pkgs, inventory.Package{
				Name:       name,
				Version:    version,
				RawVersion: version,
				Ecosystem:  ecosystem,
				Source:     "apk-db",
				Location:   dbPath,
			})
		}
		name = ""
		version = ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			flush()
			continue
		}

		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "P":
			name = v
		case "V":
			version = v
		}
	}
	flush() // last entry may not be followed by a blank line

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

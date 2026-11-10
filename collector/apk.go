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

func (c *APKCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	dbPath := filepath.Join(scanPath, "lib", "apk", "db", "installed")

	if _, err := os.Stat(dbPath); err != nil {
		// No APK database found
		return nil, nil
	}

	ecosystem := detectAlpineEcosystem(scanPath)
	if verbose {
		log.Printf("[apk] detected ecosystem: %q", ecosystem)
	}

	pkgs, err := parseAPKDatabase(dbPath, ecosystem, detectOSInfo(scanPath).ID, verbose)
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
// Returns "Alpine:" (without version) if the version cannot be determined so that
// packages are still sent to the API rather than silently dropped.
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

	return "Alpine:"
}

// parseAPKDatabase parses /lib/apk/db/installed.
// The file consists of package entries separated by blank lines.
// Each entry contains key-value pairs: "P:" = name, "V:" = version,
// "L:" = license, "o:" = origin (source) package, "D:" = dependencies,
// "p:" = provides, "F:" = a directory the package owns and "R:" = a file in it.
// osID is the os-release ID, for the PURLs the dependencies are written as.
func parseAPKDatabase(dbPath string, ecosystem string, osID string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	var records []osDepRecord
	var files [][]string
	var name, version, license, origin, dir string
	var rec osDepRecord
	var owned []string

	flush := func() {
		if name != "" && version != "" {
			pkgs = append(pkgs, applyCategory(inventory.Package{
				Name:       name,
				Version:    version,
				RawVersion: version,
				Ecosystem:  ecosystem,
				Source:     "apk-db",
				Location:   dbPath,
				License:    license,
			}, origin, ""))
			records = append(records, rec)
			files = append(files, owned)
		}
		name = ""
		version = ""
		license = ""
		origin = ""
		dir = ""
		rec = osDepRecord{}
		owned = nil
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
		case "L":
			license = v
		case "o":
			// origin: the source package a subpackage (-dev, -doc, -libs) was
			// split out of. Absent when the package is its own origin.
			origin = v
		case "D":
			// Space-separated: "scanelf musl=1.2.5-r9 so:libc.musl-x86_64.so.1
			// /bin/sh !uclibc". A "!" entry is a conflict, not a dependency.
			for _, d := range strings.Fields(v) {
				if strings.HasPrefix(d, "!") {
					continue
				}
				if n := apkDependencyName(d); n != "" {
					rec.Requires = append(rec.Requires, osDependency{n})
				}
			}
		case "p":
			// Space-separated: "so:libssl.so.3=3 cmd:openssl=3.3.2-r0".
			for _, p := range strings.Fields(v) {
				if n := apkDependencyName(p); n != "" {
					rec.Provides = append(rec.Provides, n)
				}
			}
		case "F":
			dir = v
		case "R":
			owned = append(owned, "/"+dir+"/"+v)
		}
	}
	flush() // last entry may not be followed by a blank line

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// A dependency may name a file ("/bin/sh"); the files a package owns count
	// as provided when some package requires them.
	requiredPaths := make(map[string]bool)
	for _, r := range records {
		for _, dep := range r.Requires {
			if strings.HasPrefix(dep[0], "/") {
				requiredPaths[dep[0]] = true
			}
		}
	}
	for i, owned := range files {
		for _, f := range owned {
			if requiredPaths[f] {
				records[i].Provides = append(records[i].Provides, f)
			}
		}
	}
	linkOSDependencies(pkgs, records, osID)
	return pkgs, nil
}

// apkDependencyName strips the version constraint from a dependency or a
// provides entry: "musl>=1.2" is "musl", "so:libssl.so.3=3" is "so:libssl.so.3".
func apkDependencyName(s string) string {
	if i := strings.IndexAny(s, "<>=~"); i != -1 {
		s = s[:i]
	}
	return s
}

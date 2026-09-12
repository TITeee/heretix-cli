package collector

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	// go-rpmdb's sqlite backend opens databases through database/sql by
	// driver name ("sqlite") without importing a driver itself — the caller
	// is expected to register one. glebarez/go-sqlite is pure Go (no cgo),
	// which keeps heretix-cli's CGO_ENABLED=0 cross-compilation working.
	_ "github.com/glebarez/go-sqlite"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/TITeee/heretix-cli/inventory"
)

// RPMCollector collects packages from the RPM database.
type RPMCollector struct{}

func (c *RPMCollector) Name() string { return "rpm" }

// rpmDBDirs lists the directories, relative to a root, that hold the RPM
// database — checked in this order since a distro uses exactly one. Most use
// "var/lib/rpm"; some newer ones (e.g. openSUSE/SLE) moved it under
// "usr/lib/sysimage/rpm" to make /var read-only-friendly.
var rpmDBDirs = []string{
	filepath.Join("usr", "lib", "sysimage", "rpm"),
	filepath.Join("var", "lib", "rpm"),
}

// rpmDBFileNames are the filenames a database directory may hold, one per
// on-disk format: SQLite (RHEL/Fedora 9+ generation), NDB, and the legacy
// Berkeley DB. go-rpmdb identifies the actual format from each file's
// contents, not its name, so this list only needs to match filenames real RPM
// installations actually use.
var rpmDBFileNames = []string{"rpmdb.sqlite", "Packages.db", "Packages"}

func (c *RPMCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	dbPath := findRPMDatabase(scanPath)
	if dbPath == "" {
		return nil, nil
	}

	db, err := rpmdb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open rpm database %s: %w", dbPath, err)
	}
	defer db.Close()

	entries, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("list packages from %s: %w", dbPath, err)
	}

	ecosystem := detectRPMEcosystem(scanPath)

	var pkgs []inventory.Package
	for _, e := range entries {
		// gpg-pubkey entries record an imported signing key, not an installed
		// package — they have no real version/release and never appear in any
		// vulnerability advisory.
		if e.Name == "gpg-pubkey" {
			continue
		}
		version := rpmEvr(e.Epoch, e.Version, e.Release)
		pkgs = append(pkgs, applyCategory(inventory.Package{
			Name:       e.Name,
			Version:    version,
			RawVersion: version,
			Ecosystem:  ecosystem,
			Source:     "rpm",
			License:    e.License,
		}, sourceNameFromSourceRPM(e.SourceRpm), ""))
	}

	if verbose {
		log.Printf("[rpm] collected %d packages from %s", len(pkgs), dbPath)
	}
	return pkgs, nil
}

// findRPMDatabase locates the RPM database under root, trying each
// (directory, filename) combination in priority order, and returns the first
// path that exists as a regular file. Returns "" when none exist — the normal
// outcome for a non-RPM-based image or host.
func findRPMDatabase(root string) string {
	for _, dir := range rpmDBDirs {
		for _, name := range rpmDBFileNames {
			path := filepath.Join(root, dir, name)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}
	return ""
}

// rpmEvr formats a package's epoch/version/release the way rpm itself
// displays it: the epoch prefix is present only when non-zero, since that is
// the one piece of an RPM version string every comparison — rpm's own, and
// heretix-api's — treats as equivalent to no epoch at all.
func rpmEvr(epoch *int, version, release string) string {
	if epoch != nil && *epoch != 0 {
		return fmt.Sprintf("%d:%s-%s", *epoch, version, release)
	}
	return fmt.Sprintf("%s-%s", version, release)
}

// sourceNameFromSourceRPM extracts the source package name from a SourceRpm
// tag such as "binutils-2.41-1.el9.src.rpm". The filename is always
// "{name}-{version}-{release}.src.rpm" and neither version nor release may
// contain a dash, so stripping the last two dash-separated fields is exact
// even when the name itself contains dashes ("device-mapper-multipath").
//
// This is the only per-package source signal an RPM database carries:
// go-rpmdb's PackageInfo does not decode RPMTAG_GROUP, which RHEL deprecated
// in any case.
func sourceNameFromSourceRPM(srcRPM string) string {
	const suffix = ".src.rpm"
	if !strings.HasSuffix(srcRPM, suffix) {
		return ""
	}
	base := strings.TrimSuffix(srcRPM, suffix)
	for i := 0; i < 2; i++ {
		dash := strings.LastIndexByte(base, '-')
		if dash <= 0 {
			return ""
		}
		base = base[:dash]
	}
	return base
}

// detectRPMEcosystem reads <scanPath>/etc/os-release to determine the ecosystem name
// in the format required by vuln-api: "<Distro>:<MajorVersion>" (e.g., "AlmaLinux:9").
//
// Rocky Linux is "Rocky Linux:" + major, not "Rocky:" + major: heretix-api's OSV data
// stores it under the ecosystem name OSV itself publishes, "Rocky Linux:N" — a bare
// "Rocky:" prefix never matches any row there (found 2026-09-01 investigating why
// heretix-cli returned zero results for Rocky Linux packages).
//
// Oracle Linux is "Oracle Linux:" + major again, not the bare "oracle-linux" this
// returned from 750b4ee (2026) until 2026-09-01: heretix-api's AdvisoryAffectedProduct
// rows are looked up by (product, vendor) with vendor carrying no version at all
// ("red-hat", "oracle-linux"), so a query against one major release's data was
// silently compared against every other release's fix versions too — an unrelated
// EL10 fix numerically higher than the installed EL9 version reads as "not yet
// fixed" even when the correct EL9 advisory is long satisfied. heretix-api is
// being changed to key vendor by version (matching how OSV's own ecosystem strings
// already carry version for AlmaLinux/Rocky Linux/Ubuntu/Debian/Alpine); this value
// must carry the major version for that fix to actually take effect. Confirmed via
// heretix-api's own historical alias for this exact form (RPM_ECOSYSTEM_VENDOR's
// "Oracle Linux" entry) that reverting it here is safe against the pre-fix API too.
func detectRPMEcosystem(scanPath string) string {
	id, versionID := parseOSRelease(scanPath)
	major := strings.SplitN(versionID, ".", 2)[0]

	switch id {
	case "almalinux":
		return "AlmaLinux:" + major
	case "rocky":
		return "Rocky Linux:" + major
	case "rhel":
		return "Red Hat:" + major
	case "centos":
		return "CentOS:" + major
	case "ol":
		return "Oracle Linux:" + major
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

package collector

import (
	"debug/buildinfo"
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// goBinaryExcludeDirs lists directory names to skip during the binary walk.
var goBinaryExcludeDirs = map[string]bool{
	".git": true,
}

// GoBinaryCollector finds Go modules statically linked into compiled binaries
// (e.g. a base image's /usr/local/bin/gosu) by reading the module build info
// Go embeds in every binary built in module mode — the same data `go version
// -m` prints. This is the only way to see these dependencies: the binary
// ships without its go.mod, so GoCollector's go.mod/go-list-based discovery
// never finds them.
//
// Runs for container/image scans only (isContainer). A live-host full-disk
// walk that opens every executable file it finds would be far noisier and
// slower than auditing a single extracted image layer, and isn't needed for
// the case this collector exists for (a base image's bundled binaries).
type GoBinaryCollector struct{}

func (c *GoBinaryCollector) Name() string { return "gobinary" }

func (c *GoBinaryCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	if !isContainer {
		return nil, nil
	}

	var pkgs []inventory.Package
	goVersions := map[string]bool{}

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if goBinaryExcludeDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks are skipped: the file they point to is visited on its own
		// when the walk reaches it, so following the link here would just
		// read (and report) the same binary a second time under an alias
		// (e.g. /usr/bin/python -> python3).
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		// Deliberately not pre-filtered by the executable permission bit: a
		// container rootfs extracted onto a Windows host reports no exec bits
		// at all regardless of what the image's tar headers said (NTFS has no
		// such concept, and os.Stat doesn't synthesize one from the
		// extension), which would silently skip every binary on that
		// platform. buildinfo.ReadFile itself sniffs the file's ELF/PE/Mach-O
		// magic bytes and returns quickly for anything else, so this stays
		// cheap without depending on platform-specific permission semantics.
		if !d.Type().IsRegular() {
			return nil
		}

		bi, err := buildinfo.ReadFile(path)
		if err != nil {
			return nil // not a Go binary, or unreadable
		}

		if bi.GoVersion != "" {
			goVersions[strings.TrimPrefix(bi.GoVersion, "go")] = true
		}
		for _, dep := range bi.Deps {
			effective := dep
			if dep.Replace != nil {
				effective = dep.Replace
			}
			if effective.Path == "" || effective.Version == "" {
				continue
			}
			pkgs = append(pkgs, inventory.Package{
				Name:       effective.Path,
				Version:    effective.Version,
				RawVersion: effective.Version,
				Ecosystem:  "Go",
				Source:     "gobinary",
				Location:   path,
				Integrity:  effective.Sum,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// The Go toolchain itself ships stdlib packages that carry their own CVEs
	// (e.g. net/http, crypto/tls); a binary links against the stdlib version
	// it was built with regardless of what's installed on the system, so
	// record it as its own package rather than relying on an "installed Go"
	// collector that wouldn't reflect what's actually compiled into a binary.
	for version := range goVersions {
		pkgs = append(pkgs, inventory.Package{
			Name:       "stdlib",
			Version:    version,
			RawVersion: version,
			Ecosystem:  "Go",
			Source:     "gobinary",
		})
	}

	if verbose {
		log.Printf("[gobinary] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

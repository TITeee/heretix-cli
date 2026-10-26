package collector

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// inventoryPackageRef is a collected package with the architecture dpkg
// records for it, which apt's lists key on but the package does not keep (its
// PURL carries no arch for deb).
type inventoryPackageRef struct {
	pkg  *inventory.Package
	arch string
}

// aptEntry is what apt's package lists say about one binary package file.
type aptEntry struct {
	// SHA256 is the digest of the .deb file itself, the artifact CISA's 2026
	// SBOM minimum elements ask a component hash to describe.
	SHA256 string
	// Origin is the Origin field of the repository's Release file ("Debian",
	// "Ubuntu", "Docker"): who publishes the package, which a dpkg status file
	// does not record. A package from a third-party repository on Ubuntu is
	// that repository's, not Ubuntu's, so the origin has to come from here.
	Origin string
}

func aptKey(name, version, arch string) string { return name + "\x00" + version + "\x00" + arch }

// readAptLists reads the Packages indexes apt keeps under var/lib/apt/lists
// and returns, for each wanted package name, the entries keyed by aptKey.
//
// The lists hold what the configured repositories offer now, not what was
// installed, so only an exact name, version and architecture match counts. An
// installed version no repository still offers (an old point release, a
// package installed from a file) has no entry and gets no hash or origin, rather
// than one guessed from a neighbouring version. Two lists disagreeing about the
// same file leave it out too. Uncompressed and gzip lists are read; apt's
// default is uncompressed, and lz4/xz lists (an Acquire::GzipIndexes-style
// setting) are skipped.
func readAptLists(scanPath string, want map[string]bool) map[string]aptEntry {
	dir := filepath.Join(scanPath, "var", "lib", "apt", "lists")
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	found := map[string]aptEntry{}
	conflict := map[string]bool{}
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || !(strings.HasSuffix(name, "_Packages") || strings.HasSuffix(name, "_Packages.gz")) {
			continue
		}
		origin := releaseOrigin(dir, name)
		readPackagesIndex(filepath.Join(dir, name), func(pkg, version, arch, sha256 string) {
			if !want[pkg] || sha256 == "" {
				return
			}
			k := aptKey(pkg, version, arch)
			prev, seen := found[k]
			switch {
			case !seen:
				found[k] = aptEntry{SHA256: sha256, Origin: origin}
			case prev.SHA256 != sha256:
				conflict[k] = true
			case prev.Origin != origin:
				prev.Origin = ""
				found[k] = prev
			}
		})
	}
	for k := range conflict {
		delete(found, k)
	}
	return found
}

// readPackagesIndex calls fn for every stanza of a Packages index.
func readPackagesIndex(path string, fn func(pkg, version, arch, sha256 string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer gz.Close()
		r = gz
	}
	var pkg, version, arch, sum string
	scanner := bufio.NewScanner(r)
	// Description fields can run long; a stanza line is never near this.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if pkg != "" {
				fn(pkg, version, arch, sum)
			}
			pkg, version, arch, sum = "", "", "", ""
		case strings.HasPrefix(line, "Package: "):
			pkg = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Architecture: "):
			arch = strings.TrimPrefix(line, "Architecture: ")
		case strings.HasPrefix(line, "SHA256: "):
			sum = strings.TrimPrefix(line, "SHA256: ")
		}
	}
	if pkg != "" {
		fn(pkg, version, arch, sum)
	}
}

// releaseOrigin returns the Origin of the Release file a Packages list belongs
// to: "deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages" comes
// from "deb.debian.org_debian_dists_trixie_InRelease" (or "_Release").
func releaseOrigin(dir, listName string) string {
	i := strings.Index(listName, "_dists_")
	if i < 0 {
		return ""
	}
	rest := listName[i+len("_dists_"):]
	j := strings.Index(rest, "_")
	if j < 0 {
		return ""
	}
	prefix := listName[:i+len("_dists_")+j]
	for _, suffix := range []string{"_InRelease", "_Release"} {
		f, err := os.Open(filepath.Join(dir, prefix+suffix))
		if err != nil {
			continue
		}
		origin := ""
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if v, ok := strings.CutPrefix(scanner.Text(), "Origin: "); ok {
				origin = strings.TrimSpace(v)
				break
			}
		}
		f.Close()
		return origin
	}
	return ""
}

// withArchs pairs each package with the architecture collected beside it.
func withArchs(pkgs []inventory.Package, archs []string) []inventoryPackageRef {
	refs := make([]inventoryPackageRef, len(pkgs))
	for i := range pkgs {
		refs[i] = inventoryPackageRef{pkg: &pkgs[i], arch: archs[i]}
	}
	return refs
}

// applyAptLists gives each package the .deb digest and the publisher apt's
// lists record for its exact version, where they record one.
func applyAptLists(pkgs []inventoryPackageRef, scanPath string) {
	want := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		want[p.pkg.Name] = true
	}
	index := readAptLists(scanPath, want)
	if len(index) == 0 {
		return
	}
	for _, p := range pkgs {
		if e, ok := index[aptKey(p.pkg.Name, p.pkg.Version, p.arch)]; ok {
			p.pkg.Integrity = "sha256:" + e.SHA256
			p.pkg.Supplier = e.Origin
		}
	}
}

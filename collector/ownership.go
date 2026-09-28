package collector

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/TITeee/heretix-cli/inventory"
)

// osPackageSources are the Package.Source values the OS package collectors
// write. Those packages are what own files; they are never marked themselves.
var osPackageSources = map[string]bool{"rpm": true, "dpkg": true, "apk-db": true}

// markOSManaged sets CategoryOSManaged (and scope=excluded) on every language
// package whose evidence file an OS package owns: the dist-info directory
// python3-urllib3 installed, a jar under /usr/share/java from a maven rpm, the
// /usr/bin/dlv the delve rpm ships. Ownership comes from the package
// databases' own file lists, not from where a path looks like it belongs, so
// a package pip or npm installed next to the distro's — same directory or not
// — is left alone.
//
// It is a no-op when scanPath has no OS package database (a project directory).
func markOSManaged(pkgs []inventory.Package, scanPath string, verbose bool) {
	owned := osOwnedFiles(scanPath, verbose)
	if len(owned) == 0 {
		return
	}
	marked := 0
	for i, p := range pkgs {
		if osPackageSources[p.Source] || p.Category != "" || p.Location == "" {
			continue
		}
		if owned[rootRelative(evidenceFile(p.Location), scanPath)] {
			pkgs[i].Category = inventory.CategoryOSManaged
			pkgs[i].Scope = "excluded"
			marked++
		}
	}
	if verbose {
		log.Printf("[ownership] %d language packages are owned by OS packages", marked)
	}
}

// evidenceFile is the file on disk a Location refers to. A package found in a
// nested archive is located as "outer.jar!/BOOT-INF/lib/inner.jar"; the outer
// archive is the file a package database would list.
func evidenceFile(location string) string {
	if i := strings.Index(location, "!/"); i >= 0 {
		return location[:i]
	}
	return location
}

// rootRelative turns a collected path into the absolute path a package
// database records ("/usr/lib/..."), by removing scanPath when it is an
// extracted rootfs rather than the live filesystem root.
func rootRelative(path, scanPath string) string {
	p := filepath.ToSlash(path)
	if !isFilesystemRoot(scanPath) {
		p = strings.TrimPrefix(p, filepath.ToSlash(filepath.Clean(scanPath)))
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// osOwnedFiles returns every path an installed rpm, dpkg or apk package owns,
// as recorded by its package database under scanPath.
func osOwnedFiles(scanPath string, verbose bool) map[string]bool {
	owned := map[string]bool{}
	add := func(p string) {
		if p == "" {
			return
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		owned[p] = true
		// On a merged-/usr system /lib, /bin, /sbin and /lib64 are symlinks
		// into /usr, and the filesystem walk only ever reaches the /usr side —
		// but a package built before the merge still lists the old path.
		for _, dir := range []string{"/lib/", "/lib64/", "/bin/", "/sbin/"} {
			if strings.HasPrefix(p, dir) {
				owned["/usr"+p] = true
			}
		}
	}
	addRPMFiles(scanPath, add, verbose)
	addDpkgFiles(scanPath, add, verbose)
	addAPKFiles(scanPath, add, verbose)
	return owned
}

func addRPMFiles(scanPath string, add func(string), verbose bool) {
	dbPath := findRPMDatabase(scanPath)
	if dbPath == "" {
		return
	}
	db, err := rpmdb.Open(dbPath)
	if err != nil {
		if verbose {
			log.Printf("[ownership] open rpm database %s: %v", dbPath, err)
		}
		return
	}
	defer db.Close()
	entries, err := db.ListPackages()
	if err != nil {
		if verbose {
			log.Printf("[ownership] list rpm packages: %v", err)
		}
		return
	}
	for _, e := range entries {
		files, err := e.InstalledFileNames()
		if err != nil {
			continue
		}
		for _, f := range files {
			add(f)
		}
	}
}

// addDpkgFiles reads /var/lib/dpkg/info/<package>[:<arch>].list, one path per
// line, which dpkg keeps for every installed package.
//
// An image extracted onto Windows loses the ":<arch>" lists (NTFS has no ":"
// in file names), so architecture-specific packages' files go unowned there.
// Language libraries are nearly all Architecture: all (python3-*, node-*,
// ruby-*, lib*-java), whose lists carry no suffix.
func addDpkgFiles(scanPath string, add func(string), verbose bool) {
	lists, _ := filepath.Glob(filepath.Join(scanPath, "var", "lib", "dpkg", "info", "*.list"))
	for _, list := range lists {
		f, err := os.Open(list)
		if err != nil {
			if verbose {
				log.Printf("[ownership] %s: %v", list, err)
			}
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			add(strings.TrimSpace(scanner.Text()))
		}
		f.Close()
	}
}

// addAPKFiles reads /lib/apk/db/installed, where each package lists its files
// as an "F:<dir>" line followed by one "R:<file>" line per file in it.
func addAPKFiles(scanPath string, add func(string), verbose bool) {
	f, err := os.Open(filepath.Join(scanPath, "lib", "apk", "db", "installed"))
	if err != nil {
		return
	}
	defer f.Close()
	dir := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			dir = ""
			continue
		}
		switch k {
		case "P":
			dir = ""
		case "F":
			dir = v
		case "R":
			add(dir + "/" + v)
		}
	}
	if err := scanner.Err(); err != nil && verbose {
		log.Printf("[ownership] read apk database: %v", err)
	}
}

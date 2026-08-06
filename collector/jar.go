package collector

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// jarExcludeDirs lists directory names to skip during filesystem walk.
// The Maven and Gradle caches are excluded because their contents are already
// covered by the pom.xml / gradle.lockfile collectors, and including them would
// add thousands of duplicate entries.
var jarExcludeDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	".m2":          true,
	".gradle":      true,
}

const (
	// maxArchiveDepth limits recursion into nested archives. Depth 2 covers the
	// real-world layouts: war → WEB-INF/lib/*.jar and fat jar → BOOT-INF/lib/*.jar.
	maxArchiveDepth = 2
	// maxNestedArchiveSize caps the in-memory buffer used for one nested archive.
	maxNestedArchiveSize = 64 << 20 // 64 MiB
	// maxMetadataSize caps the read of a single metadata entry (pom.properties,
	// pom.xml, MANIFEST.MF) — all of which are small in practice.
	maxMetadataSize = 4 << 20 // 4 MiB
	// maxArchiveEntries aborts traversal of archives with an implausible entry count.
	maxArchiveEntries = 20000
)

// JARCollector collects Java packages from built artifacts (JAR/WAR/EAR).
// Unlike the Maven and Gradle collectors it does not need build files, so it
// works on runtime container images that ship only compiled artifacts.
type JARCollector struct{}

func (c *JARCollector) Name() string { return "jar" }

func (c *JARCollector) Collect(scanPath string, verbose bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if jarExcludeDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !isJavaArchive(d.Name()) {
			return nil
		}

		found, err := parseJavaArchiveFile(p, verbose)
		if err != nil {
			if verbose {
				log.Printf("[jar] error parsing %s: %v", p, err)
			}
			return nil
		}
		pkgs = append(pkgs, found...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	if verbose {
		log.Printf("[jar] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// parseJavaArchiveFile opens an archive on disk and extracts its packages.
func parseJavaArchiveFile(archivePath string, verbose bool) ([]inventory.Package, error) {
	digest, err := fileSHA256(archivePath)
	if err != nil {
		return nil, err
	}

	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return parseJavaArchive(&zr.Reader, archivePath, digest, 0, verbose), nil
}

// mavenCoord is a groupId/artifactId/version triple read from an archive.
type mavenCoord struct {
	groupID    string
	artifactID string
	version    string
}

// parseJavaArchive extracts Java packages from an open archive, then recurses
// into any nested archives it contains.
//
// location is the display path of this archive. Nested archives are reported as
// "<outer>!/<inner entry>", the convention used by Syft and Trivy.
// digest is the SHA-256 of this archive's bytes.
func parseJavaArchive(zr *zip.Reader, location, digest string, depth int, verbose bool) []inventory.Package {
	// A shaded (uber) JAR embeds several META-INF/maven/{g}/{a}/ directories, so
	// coordinates and licenses are keyed by their directory to keep them paired.
	coordByDir := make(map[string]mavenCoord)
	licenseByDir := make(map[string]string)
	var manifest []byte
	var nested []*zip.File

	for i, f := range zr.File {
		if i >= maxArchiveEntries {
			if verbose {
				log.Printf("[jar] %s: entry limit (%d) reached, truncating", location, maxArchiveEntries)
			}
			break
		}

		name := f.Name
		switch {
		case strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties"):
			data, err := readZipEntry(f, maxMetadataSize)
			if err != nil {
				continue
			}
			if g, a, v := parsePomProperties(data); g != "" && a != "" && v != "" {
				coordByDir[path.Dir(name)] = mavenCoord{g, a, v}
			}

		case strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.xml"):
			data, err := readZipEntry(f, maxMetadataSize)
			if err != nil {
				continue
			}
			if lic := parseEmbeddedPomLicense(data); lic != "" {
				licenseByDir[path.Dir(name)] = lic
			}

		case name == "META-INF/MANIFEST.MF":
			manifest, _ = readZipEntry(f, maxMetadataSize)

		case depth < maxArchiveDepth && isJavaArchive(name):
			nested = append(nested, f)
		}
	}

	var pkgs []inventory.Package

	// META-INF/maven is authoritative — it is written by maven-archiver and
	// carries the real groupId.
	for dir, c := range coordByDir {
		pkgs = append(pkgs, newJARPackage(c, location, digest, licenseByDir[dir]))
	}

	// Fall back to MANIFEST.MF only when it yields a complete coordinate.
	// A name guessed from the filename would have no groupId, producing a PURL
	// that silently matches no advisory, so that path is deliberately omitted.
	if len(pkgs) == 0 && manifest != nil {
		if g, a, v := parseManifestMF(manifest); g != "" && a != "" && v != "" {
			pkgs = append(pkgs, newJARPackage(mavenCoord{g, a, v}, location, digest, ""))
		}
	}

	for _, f := range nested {
		data, err := readZipEntry(f, maxNestedArchiveSize)
		if err != nil {
			if verbose {
				log.Printf("[jar] %s: skipping nested %s: %v", location, f.Name, err)
			}
			continue
		}
		nr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			if verbose {
				log.Printf("[jar] %s: nested %s is not a valid archive: %v", location, f.Name, err)
			}
			continue
		}
		sum := sha256.Sum256(data)
		nestedPkgs := parseJavaArchive(nr, location+"!/"+f.Name, hex.EncodeToString(sum[:]), depth+1, verbose)
		pkgs = append(pkgs, nestedPkgs...)
	}

	if verbose && len(pkgs) > 0 {
		log.Printf("[jar] %s: extracted %d packages", location, len(pkgs))
	}
	return pkgs
}

// newJARPackage builds an inventory entry for one set of Maven coordinates.
// Direct is left nil: a compiled artifact carries no record of whether it was a
// declared dependency or pulled in transitively.
func newJARPackage(c mavenCoord, location, digest, license string) inventory.Package {
	return inventory.Package{
		Name:       c.groupID + ":" + c.artifactID,
		Version:    c.version,
		RawVersion: c.version,
		Ecosystem:  "Maven",
		Source:     "jar",
		Location:   location,
		Integrity:  "sha256:" + digest,
		License:    license,
	}
}

// parsePomProperties reads the coordinates that maven-archiver writes to
// META-INF/maven/{groupId}/{artifactId}/pom.properties.
func parsePomProperties(data []byte) (groupID, artifactID, version string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "groupId":
			groupID = strings.TrimSpace(v)
		case "artifactId":
			artifactID = strings.TrimSpace(v)
		case "version":
			version = strings.TrimSpace(v)
		}
	}
	return groupID, artifactID, version
}

// parseEmbeddedPomLicense extracts the <licenses> block from a pom.xml embedded
// under META-INF/maven. It mirrors parsePomXmlLicenses in maven.go but reads a
// byte slice, since this pom lives inside a zip rather than on disk.
func parseEmbeddedPomLicense(data []byte) string {
	var pom struct {
		Licenses struct {
			License []struct {
				Name string `xml:"name"`
			} `xml:"license"`
		} `xml:"licenses"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return ""
	}

	var names []string
	for _, l := range pom.Licenses.License {
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	return strings.Join(names, " OR ")
}

// parseManifestMF reads coordinates from META-INF/MANIFEST.MF.
//
// Only Implementation-Vendor-Id is accepted as a groupId. OSGi headers such as
// Bundle-SymbolicName look like a groupId but frequently disagree with the real
// one, so they are ignored rather than guessed at.
func parseManifestMF(data []byte) (groupID, artifactID, version string) {
	attrs := make(map[string]string)
	var key, val string

	flush := func() {
		if key != "" {
			attrs[key] = val
		}
		key, val = "", ""
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		// Manifests wrap at 72 bytes; a leading space continues the previous value.
		if strings.HasPrefix(line, " ") {
			val += line[1:]
			continue
		}
		flush()
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(k), strings.TrimSpace(v)
	}
	flush()

	return attrs["Implementation-Vendor-Id"], attrs["Implementation-Title"], attrs["Implementation-Version"]
}

// readZipEntry reads one entry into memory. Entries declaring a size over limit
// are refused outright, and the LimitReader caps the read in case the header
// understates the real size.
func readZipEntry(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("entry %s too large (%d bytes)", f.Name, f.UncompressedSize64)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
}

// isJavaArchive reports whether name has a Java archive extension. WAR and EAR
// files are zips too — their nested jars carry the actual coordinates.
func isJavaArchive(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jar", ".war", ".ear":
		return true
	}
	return false
}

// fileSHA256 streams a file through SHA-256 so that large fat JARs never have to
// be held in memory.
func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

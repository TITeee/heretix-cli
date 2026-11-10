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

func (c *DPKGCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
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
	var archs []string
	var records []osDepRecord
	var currentPkg, currentVersion, currentStatus, currentSource, currentSourceVersion, currentSection, currentBuiltUsing, currentArch string
	var currentDepends, currentPreDepends, currentProvides string

	flush := func() {
		if currentPkg != "" && currentVersion != "" && strings.Contains(currentStatus, "install ok installed") {
			p := applyCategory(inventory.Package{
				Name:       currentPkg,
				Version:    currentVersion,
				RawVersion: currentVersion,
				Ecosystem:  ecosystem,
				Source:     "dpkg",
				License:    parseDpkgCopyrightLicense(scanPath, currentPkg),
			}, currentSource, currentSection)
			p.SourceVersion = currentSourceVersion
			setSignedTemplateSource(&p, currentSource, currentBuiltUsing)
			pkgs = append(pkgs, p)
			archs = append(archs, currentArch)
			records = append(records, dpkgDepRecord(currentDepends, currentPreDepends, currentProvides))
		}
		currentPkg, currentVersion, currentStatus, currentArch = "", "", "", ""
		currentSource, currentSourceVersion, currentSection, currentBuiltUsing = "", "", "", ""
		currentDepends, currentPreDepends, currentProvides = "", "", ""
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
		case strings.HasPrefix(line, "Source: "):
			currentSource = parseDpkgSourceField(strings.TrimPrefix(line, "Source: "))
			currentSourceVersion = parseDpkgSourceVersion(strings.TrimPrefix(line, "Source: "))
		case strings.HasPrefix(line, "Section: "):
			currentSection = parseDpkgSectionField(strings.TrimPrefix(line, "Section: "))
		case strings.HasPrefix(line, "Built-Using: "):
			currentBuiltUsing = strings.TrimPrefix(line, "Built-Using: ")
		case strings.HasPrefix(line, "Architecture: "):
			currentArch = strings.TrimPrefix(line, "Architecture: ")
		case strings.HasPrefix(line, "Depends: "):
			currentDepends = strings.TrimPrefix(line, "Depends: ")
		case strings.HasPrefix(line, "Pre-Depends: "):
			currentPreDepends = strings.TrimPrefix(line, "Pre-Depends: ")
		case strings.HasPrefix(line, "Provides: "):
			currentProvides = strings.TrimPrefix(line, "Provides: ")
		}
	}
	flush() // handle final record

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	linkOSDependencies(pkgs, records, detectOSInfo(scanPath).ID)
	applyAptLists(withArchs(pkgs, archs), scanPath, verbose)

	if verbose {
		log.Printf("[dpkg] collected %d packages from %s", len(pkgs), statusPath)
	}
	return pkgs, nil
}

// collectViaDpkgQuery falls back to dpkg-query for live systems without a readable status file.
func (c *DPKGCollector) collectViaDpkgQuery(verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		// Not a Debian-based host — same as RPMCollector's LookPath check, this is
		// a normal "wrong OS" outcome, not a failure worth surfacing as a warning.
		if verbose {
			log.Printf("[dpkg] dpkg-query not found, skipping (not a Debian-based system)")
		}
		return nil, nil
	}

	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${Section}\t${source:Version}\t${Built-Using}\t${Architecture}\t${Depends}\t${Pre-Depends}\t${Provides}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query failed: %w", err)
	}

	ecosystem := detectDPKGEcosystem("/")

	var pkgs []inventory.Package
	var archs []string
	var records []osDepRecord
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 10)
		if len(parts) < 2 {
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
		// ${source:Package}, ${Section} and ${source:Version} are best-effort: an
		// old dpkg that does not know a field substitutes an empty string for it.
		var srcPkg, section, srcVersion string
		if len(parts) > 2 {
			srcPkg = parseDpkgSourceField(parts[2])
		}
		if len(parts) > 3 {
			section = parseDpkgSectionField(parts[3])
		}
		// ${source:Version} is always filled in; kept, like the status file's
		// "Source: name (version)", only when it differs from the binary's own.
		if len(parts) > 4 && strings.TrimSpace(parts[4]) != rawVersion {
			srcVersion = strings.TrimSpace(parts[4])
		}
		p := applyCategory(inventory.Package{
			Name:       name,
			Version:    rawVersion,
			RawVersion: rawVersion,
			Ecosystem:  ecosystem,
			Source:     "dpkg",
			License:    parseDpkgCopyrightLicense("/", name),
		}, srcPkg, section)
		p.SourceVersion = srcVersion
		if len(parts) > 5 {
			setSignedTemplateSource(&p, srcPkg, parts[5])
		}
		pkgs = append(pkgs, p)
		arch := ""
		if len(parts) > 6 {
			arch = strings.TrimSpace(parts[6])
		}
		archs = append(archs, arch)
		var depends, preDepends, provides string
		if len(parts) > 9 {
			depends, preDepends, provides = parts[7], parts[8], parts[9]
		}
		records = append(records, dpkgDepRecord(depends, preDepends, provides))
	}
	linkOSDependencies(pkgs, records, detectOSInfo("/").ID)
	applyAptLists(withArchs(pkgs, archs), "/", verbose)

	if verbose {
		log.Printf("[dpkg] collected %d packages via dpkg-query", len(pkgs))
	}
	return pkgs, nil
}

// dpkgDepRecord reads a package's Depends, Pre-Depends and Provides fields.
// Pre-Depends is a dependency like any other for this purpose: it only says
// the dependency had to be installed first.
func dpkgDepRecord(depends, preDepends, provides string) osDepRecord {
	return osDepRecord{
		Requires: append(parseDpkgDependencies(depends), parseDpkgDependencies(preDepends)...),
		Provides: parseDpkgNames(provides),
	}
}

// parseDpkgDependencies reads a Depends-style field, "libc6 (>= 2.34),
// python3:any, default-mta | mail-transport-agent": one dependency per comma,
// alternatives within it separated by "|".
func parseDpkgDependencies(v string) []osDependency {
	var deps []osDependency
	for _, group := range strings.Split(v, ",") {
		var dep osDependency
		for _, alt := range strings.Split(group, "|") {
			if name := dpkgDependencyName(alt); name != "" {
				dep = append(dep, name)
			}
		}
		if len(dep) > 0 {
			deps = append(deps, dep)
		}
	}
	return deps
}

// parseDpkgNames reads a comma-separated list of package names with optional
// versions, as in Provides: "mail-transport-agent, libfoo1 (= 1.2-3)".
func parseDpkgNames(v string) []string {
	var names []string
	for _, entry := range strings.Split(v, ",") {
		if name := dpkgDependencyName(entry); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// dpkgDependencyName strips what may follow a package name in a dependency:
// a version in parentheses, an architecture list in brackets, build profiles
// in angle brackets, and an architecture qualifier after a colon
// ("python3:any", "libc6:amd64").
func dpkgDependencyName(s string) string {
	if i := strings.IndexAny(s, "([<"); i != -1 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i != -1 {
		s = s[:i]
	}
	return s
}

// parseDpkgSourceField normalizes a "Source:" value. dpkg appends the source
// version in parentheses whenever it differs from the binary package's own
// version (e.g. "linux (6.12.43-1)"), which is common exactly for the packages
// this field is needed for.
func parseDpkgSourceField(v string) string {
	if i := strings.IndexByte(v, '('); i != -1 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// setSignedTemplateSource points a package built from a "-signed" template at
// the source package that holds its code.
//
// Debian builds the signed binaries of the kernel, the boot loaders and the
// firmware updater (linux-signed-amd64, shim-signed, grub-efi-amd64-signed,
// fwupd-amd64-signed, ...) from a template source that carries no code: it
// signs the binary an unsigned source already built, and names that source in
// Built-Using ("linux (= 6.12.74-2)"). Debian files its advisories against the
// unsigned source, so a signed kernel matched as "linux-signed-amd64" finds
// none. Only the one-entry Built-Using of a "-signed" source is taken: other
// packages use Built-Using for what they link in statically, which is not what
// the advisories name them by. The version is set whenever the source is, as
// it belongs to the source named.
func setSignedTemplateSource(p *inventory.Package, source, builtUsing string) {
	if source == "" {
		source = p.Name
	}
	if !strings.Contains(source, "-signed") {
		return
	}
	name, version, ok := parseSingleBuiltUsing(builtUsing)
	if !ok {
		return
	}
	p.SourcePackage = name
	p.SourceVersion = version
}

// parseSingleBuiltUsing reads a Built-Using value that names exactly one
// source package: "linux (= 6.12.74-2)".
func parseSingleBuiltUsing(v string) (name, version string, ok bool) {
	entries := strings.Split(v, ",")
	if len(entries) != 1 {
		return "", "", false
	}
	entry := strings.TrimSpace(entries[0])
	open := strings.IndexByte(entry, '(')
	end := strings.LastIndexByte(entry, ')')
	if open <= 0 || end <= open {
		return "", "", false
	}
	version = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(entry[open+1:end]), "="))
	name = strings.TrimSpace(entry[:open])
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// parseDpkgSourceVersion returns the source version a "Source:" value carries
// in parentheses ("lvm2 (2.03.31-2)" on dmsetup 2:1.02.205-2), or "" when it
// has none, which means the source version is the binary's own. Debian and
// Ubuntu advisories give source versions, and a binary's version can differ
// from its source's in epoch or altogether, so this is what heretix-api
// compares with them.
func parseDpkgSourceVersion(v string) string {
	open := strings.IndexByte(v, '(')
	end := strings.LastIndexByte(v, ')')
	if open == -1 || end <= open {
		return ""
	}
	return strings.TrimSpace(v[open+1 : end])
}

// parseDpkgSectionField normalizes a "Section:" value, which carries an
// archive area prefix outside main (e.g. "non-free/libs", "contrib/devel").
func parseDpkgSectionField(v string) string {
	if i := strings.LastIndexByte(v, '/'); i != -1 {
		v = v[i+1:]
	}
	return strings.TrimSpace(v)
}

// parseDpkgCopyrightLicense best-effort extracts license identifiers from a
// Debian package's copyright file (<scanPath>/usr/share/doc/{pkgName}/copyright).
// Most packages use the DEP-5 machine-readable format, which declares one or more
// "License:" fields; free-form copyright files without that field yield "".
// Duplicate values are collapsed and distinct ones joined with " and ".
//
// "and", not "or": a DEP-5 file gives each group of files its own License, so
// the package as a whole is under all of them at once, not a choice between
// them (composer.json's list is a choice, which is why composer.go uses OR).
// A field that is itself a choice ("GPL-2+ or Artistic") is kept whole and
// parenthesized. The sbom package converts the DEP-5 short names to SPDX IDs.
func parseDpkgCopyrightLicense(scanPath, pkgName string) string {
	path := filepath.Join(scanPath, "usr", "share", "doc", pkgName, "copyright")
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	seen := make(map[string]bool)
	var licenses []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "License:") {
			continue
		}
		lic := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		if lic == "" || seen[lic] {
			continue
		}
		seen[lic] = true
		licenses = append(licenses, lic)
	}
	if len(licenses) == 0 {
		return ""
	}
	if len(licenses) == 1 {
		return licenses[0]
	}
	for i, lic := range licenses {
		if strings.Contains(lic, " ") {
			licenses[i] = "(" + lic + ")"
		}
	}
	return strings.Join(licenses, " and ")
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

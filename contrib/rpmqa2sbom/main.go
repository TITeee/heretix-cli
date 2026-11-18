// rpmqa2sbom builds a heretix CycloneDX SBOM for an RPM-based Linux host from
// the output of a few commands, for hosts heretix-cli cannot run on.
//
// Run these on the host, in an empty directory, and copy the files here:
//
//	rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' > rpm-qa.tsv
//	cp /etc/os-release os-release.txt
//	hostname > hostname.txt
//	uname -r > uname.txt
//
// Then:
//
//	go run ./contrib/rpmqa2sbom [--compat] <dir> [output.json]
//
// The output defaults to <hostname>.json in the current directory. Packages
// are built the way heretix-cli's rpm collector builds them, so the SBOM
// matches what `heretix-cli collect` writes on the host (licenses aside).
// uname.txt is only printed: the SBOM has no field for the running kernel.
//
// --compat writes the SBOM the way other CycloneDX scanners read an RPM host,
// to <hostname>.compat.json by default. Those take the OS from the only
// operating-system component and the distro from each package's PURL, and
// name RHEL "redhat", AlmaLinux "alma" and Oracle Linux "oracle". So the
// scanned host becomes an application, the OS component and the PURLs use
// that name, and the PURL's distro is the name and the full VERSION_ID
// (redhat-9.8). Keep the default output for heretix-management.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TITeee/heretix-cli/collector"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

func main() {
	compat := false
	var args []string
	for _, a := range os.Args[1:] {
		if a == "--compat" {
			compat = true
			continue
		}
		args = append(args, a)
	}
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: rpmqa2sbom [--compat] <dir> [output.json]")
		os.Exit(2)
	}
	if err := run(args[0], args[1:], compat); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir string, rest []string, compat bool) error {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b)), err
	}
	hostname, err := read("hostname.txt")
	if err != nil {
		return err
	}
	osrelease, err := read("os-release.txt")
	if err != nil {
		return err
	}
	tsv, err := read("rpm-qa.tsv")
	if err != nil {
		return err
	}

	osInfo := parseOSRelease(osrelease)
	ecosystem := rpmEcosystem(osInfo)

	inv := inventory.New(hostname, osInfo)
	for n, line := range strings.Split(tsv, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			return fmt.Errorf("rpm-qa.tsv line %d: want 6 tab-separated fields, got %d", n+1, len(f))
		}
		name, epoch, version, release, arch, srpm := f[0], f[1], f[2], f[3], f[4], f[5]
		if name == "gpg-pubkey" { // an imported signing key, not a package
			continue
		}
		evr := version + "-" + release
		if epoch != "" && epoch != "0" {
			evr = epoch + ":" + evr
		}
		p := inventory.Package{
			Name:          name,
			Version:       evr,
			RawVersion:    evr,
			Ecosystem:     ecosystem,
			Source:        "rpm",
			Arch:          arch,
			SourcePackage: sourceName(srpm, name),
		}
		// What heretix-cli leaves out of a host scan (collector.relaxForHost).
		if name == "kernel-headers" || strings.HasPrefix(name, "kernel-devel") {
			p.Category, p.Scope = collector.CategoryKernel, "excluded"
		}
		inv.Packages = append(inv.Packages, p)
	}
	inv.Packages = inventory.Deduplicate(inv.Packages)

	out := hostname + ".json"
	if compat {
		out = hostname + ".compat.json"
	}
	if len(rest) == 1 {
		out = rest[0]
	}
	bom := sbom.GenerateCycloneDX(inv, sbom.Generator{Name: "rpmqa2sbom", Version: sbom.BuildRevision(), Lifecycle: cdx.LifecyclePhaseOperations})
	if compat {
		if note := applyCompat(bom, osInfo); note != "" {
			fmt.Fprintln(os.Stderr, note)
		}
	}
	if err := sbom.WriteToFile(bom, out); err != nil {
		return err
	}
	kernel, _ := read("uname.txt")
	fmt.Fprintf(os.Stderr, "%s (%s): %d packages -> %s; running kernel %s\n", hostname, ecosystem, len(inv.Packages), out, kernel)
	return nil
}

// compatNames maps os-release's ID to the name other CycloneDX scanners give the
// distro, in the OS component and in the PURL's namespace and distro.
var compatNames = map[string]string{
	"rhel":      "redhat",
	"almalinux": "alma",
	"rocky":     "rocky",
	"centos":    "centos",
	"ol":        "oracle",
}

// applyCompat rewrites bom in place for scanners that read the OS from the one
// operating-system component and each package's distro from its PURL (see the
// package comment). It returns a note for the user when it left the names alone.
//
// The bom-refs of packages are their PURLs, so they and the dependency entries
// that name them follow the PURL; nothing else changes, heretix's own
// properties included.
func applyCompat(bom *cdx.BOM, osInfo inventory.OSInfo) string {
	name, ok := compatNames[osInfo.ID]
	if !ok {
		return fmt.Sprintf("--compat: no common name known for os-release ID %q; names are left as they are", osInfo.ID)
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		bom.Metadata.Component.Type = cdx.ComponentTypeApplication
	}
	renamed := map[string]string{}
	if bom.Components != nil {
		for i := range *bom.Components {
			c := &(*bom.Components)[i]
			if c.Type == cdx.ComponentTypeOS {
				c.Name = name
				continue
			}
			purl := compatPURL(c.PackageURL, name, osInfo.VersionID)
			if purl == c.PackageURL {
				continue
			}
			if c.BOMRef == c.PackageURL {
				renamed[c.BOMRef] = purl
				c.BOMRef = purl
			}
			c.PackageURL = purl
		}
	}
	if bom.Dependencies != nil {
		for i := range *bom.Dependencies {
			d := &(*bom.Dependencies)[i]
			if to, ok := renamed[d.Ref]; ok {
				d.Ref = to
			}
			if d.Dependencies != nil {
				for j, ref := range *d.Dependencies {
					if to, ok := renamed[ref]; ok {
						(*d.Dependencies)[j] = to
					}
				}
			}
		}
	}
	return ""
}

// compatPURL gives an rpm PURL the namespace name and the distro name-VERSION_ID:
// pkg:rpm/rhel/bash@5.1?distro=redhat-9 becomes pkg:rpm/redhat/bash@5.1?distro=redhat-9.8.
// Any other PURL comes back as it was.
func compatPURL(purl, name, versionID string) string {
	base, query, hasQuery := strings.Cut(purl, "?")
	rest, ok := strings.CutPrefix(base, "pkg:rpm/")
	if !ok {
		return purl
	}
	_, tail, ok := strings.Cut(rest, "/")
	if !ok {
		return purl
	}
	base = "pkg:rpm/" + name + "/" + tail
	if !hasQuery {
		return base
	}
	qualifiers := strings.Split(query, "&")
	for i, q := range qualifiers {
		if strings.HasPrefix(q, "distro=") {
			qualifiers[i] = "distro=" + name + "-" + versionID
		}
	}
	return base + "?" + strings.Join(qualifiers, "&")
}

func parseOSRelease(s string) inventory.OSInfo {
	info := inventory.OSInfo{ID: "unknown", VersionID: "unknown", Name: "Unknown"}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			info.ID = v
		case "VERSION_ID":
			info.VersionID = v
		case "PRETTY_NAME":
			info.Name = v
		}
	}
	return info
}

// rpmEcosystem mirrors collector.detectRPMEcosystem.
func rpmEcosystem(os inventory.OSInfo) string {
	major := strings.SplitN(os.VersionID, ".", 2)[0]
	switch os.ID {
	case "rhel":
		return "Red Hat:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "rocky":
		return "Rocky Linux:" + major
	case "centos":
		return "CentOS:" + major
	case "ol":
		return "Oracle Linux:" + major
	}
	return "AlmaLinux:" + major
}

// sourceName mirrors collector.sourceNameFromSourceRPM: the source RPM file is
// "{name}-{version}-{release}.src.rpm", so dropping the last two dash fields
// leaves the name. A package with no source RPM is its own source.
func sourceName(srpm, name string) string {
	const suffix = ".src.rpm"
	if !strings.HasSuffix(srpm, suffix) {
		return name
	}
	base := strings.TrimSuffix(srpm, suffix)
	for i := 0; i < 2; i++ {
		dash := strings.LastIndexByte(base, '-')
		if dash <= 0 {
			return name
		}
		base = base[:dash]
	}
	return base
}

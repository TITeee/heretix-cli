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
//	go run ./contrib/rpmqa2sbom <dir> [output.json]
//
// The output defaults to <hostname>.json in the current directory. Packages
// are built the way heretix-cli's rpm collector builds them, so the SBOM
// matches what `heretix-cli collect` writes on the host (licenses aside).
// uname.txt is only printed: the SBOM has no field for the running kernel.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/collector"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: rpmqa2sbom <dir> [output.json]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir string, rest []string) error {
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
	if len(rest) == 1 {
		out = rest[0]
	}
	if err := sbom.WriteToFile(sbom.GenerateCycloneDX(inv, "rpmqa2sbom"), out); err != nil {
		return err
	}
	kernel, _ := read("uname.txt")
	fmt.Fprintf(os.Stderr, "%s (%s): %d packages -> %s; running kernel %s\n", hostname, ecosystem, len(inv.Packages), out, kernel)
	return nil
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

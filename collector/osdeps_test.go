package collector

import (
	"reflect"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

// TestLinkOSDependencies covers the resolution rules shared by the dpkg, rpm
// and apk collectors: a dependency is written as the PURL of the installed
// package that provides it, by name or by a virtual name; of alternatives the
// first installed one is taken; a name nothing provides is dropped; a package
// does not depend on itself; and direct means "nothing installed depends on it".
func TestLinkOSDependencies(t *testing.T) {
	pkgs := []inventory.Package{
		{Name: "mailutils", Version: "1:3.17-1", Ecosystem: "Debian:13", Source: "dpkg"},
		{Name: "exim4-daemon-light", Version: "4.98-3", Ecosystem: "Debian:13", Source: "dpkg"},
		{Name: "libc6", Version: "2.41-12", Ecosystem: "Debian:13", Source: "dpkg"},
		// A second architecture's copy: the same PURL, so not a dependency of itself.
		{Name: "libc6", Version: "2.41-12", Ecosystem: "Debian:13", Source: "dpkg"},
		{Name: "libgcc-s1", Version: "14.2.0-19", Ecosystem: "Debian:13", Source: "dpkg"},
	}
	records := []osDepRecord{
		{Requires: []osDependency{{"default-mta", "mail-transport-agent"}, {"libc6"}, {"libnotinstalled"}}},
		{Provides: []string{"mail-transport-agent"}, Requires: []osDependency{{"libc6"}}},
		{Requires: []osDependency{{"libgcc-s1"}, {"libc6"}}},
		{Requires: []osDependency{{"libgcc-s1"}, {"libc6"}}},
		{Requires: []osDependency{{"gcc-14-base"}}},
	}
	linkOSDependencies(pkgs, records, "debian")

	const (
		exim = "pkg:deb/debian/exim4-daemon-light@4.98-3?distro=debian-13"
		libc = "pkg:deb/debian/libc6@2.41-12?distro=debian-13"
		gcc  = "pkg:deb/debian/libgcc-s1@14.2.0-19?distro=debian-13"
	)
	wantDeps := map[string][]string{
		"mailutils":          {exim, libc},
		"exim4-daemon-light": {libc},
		"libc6":              {gcc},
		"libgcc-s1":          {},
	}
	wantDirect := map[string]bool{"mailutils": true, "exim4-daemon-light": false, "libc6": false, "libgcc-s1": false}
	for _, p := range pkgs {
		if !p.DepsResolved {
			t.Errorf("%s: DepsResolved = false, want true", p.Name)
		}
		if !reflect.DeepEqual(p.Deps, wantDeps[p.Name]) {
			t.Errorf("%s: Deps = %q, want %q", p.Name, p.Deps, wantDeps[p.Name])
		}
		if p.Direct == nil || *p.Direct != wantDirect[p.Name] {
			t.Errorf("%s: Direct = %v, want %v", p.Name, p.Direct, wantDirect[p.Name])
		}
	}
}

// TestLinkOSDependencies_RPMCapabilities: rpm dependencies are capabilities,
// and the PURL a dependency is written as carries the arch, distro and epoch
// qualifiers the component's own bom-ref has.
func TestLinkOSDependencies_RPMCapabilities(t *testing.T) {
	pkgs := []inventory.Package{
		{Name: "bash", Version: "5.1.8-9.el9", Ecosystem: "Rocky Linux:9", Source: "rpm", Arch: "x86_64"},
		{Name: "glibc", Version: "2.34-125.el9", Ecosystem: "Rocky Linux:9", Source: "rpm", Arch: "x86_64"},
		{Name: "openssl-libs", Version: "1:3.2.2-6.el9", Ecosystem: "Rocky Linux:9", Source: "rpm", Arch: "x86_64"},
	}
	records := []osDepRecord{
		{Requires: []osDependency{{"libc.so.6(GLIBC_2.34)(64bit)"}, {"/usr/bin/sh"}}, Provides: []string{"/usr/bin/sh"}},
		{Provides: []string{"libc.so.6(GLIBC_2.34)(64bit)", "glibc(x86-64)"}, Requires: []osDependency{{"libssl.so.3()(64bit)"}}},
		{Provides: []string{"libssl.so.3()(64bit)"}},
	}
	linkOSDependencies(pkgs, records, "rocky")

	want := map[string][]string{
		"bash":         {"pkg:rpm/rocky/glibc@2.34-125.el9?arch=x86_64&distro=rockylinux-9"},
		"glibc":        {"pkg:rpm/rocky/openssl-libs@3.2.2-6.el9?arch=x86_64&distro=rockylinux-9&epoch=1"},
		"openssl-libs": {},
	}
	for _, p := range pkgs {
		if !reflect.DeepEqual(p.Deps, want[p.Name]) {
			t.Errorf("%s: Deps = %q, want %q", p.Name, p.Deps, want[p.Name])
		}
	}
	if pkgs[0].Direct == nil || !*pkgs[0].Direct {
		t.Errorf("bash: Direct = %v, want true", pkgs[0].Direct)
	}
}

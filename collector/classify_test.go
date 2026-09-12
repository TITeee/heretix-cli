package collector

import (
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

func pkgFor(name string) inventory.Package {
	return inventory.Package{Name: name, Version: "1.0", Ecosystem: "Debian:13", Source: "dpkg"}
}

func TestClassifyNonRuntime(t *testing.T) {
	tests := []struct {
		desc    string
		name    string
		source  string
		section string
		want    string
	}{
		// Kernel: the source package is the signal, so every binary package
		// built from it is caught regardless of its own name or section.
		{"debian kernel headers", "linux-libc-dev", "linux", "devel", CategoryKernel},
		{"rpm kernel headers", "kernel-headers", "kernel", "", CategoryKernel},
		{"signed kernel flavour", "linux-image-amd64", "linux-signed-amd64", "kernel", CategoryKernel},
		{"kernel headers with no source recorded", "linux-headers-6.12.0-amd64", "", "", CategoryKernel},
		{"alpine kernel headers", "linux-headers", "linux-headers", "", CategoryKernel},

		// Build toolchain. libbinutils/libctf0 are the reason Section alone is
		// not enough: they are Section=libs but built from the binutils source.
		{"binutils itself", "binutils", "binutils", "devel", CategoryBuild},
		{"binutils library split out as Section=libs", "libbinutils", "binutils", "libs", CategoryBuild},
		{"binutils ctf library", "libctf0", "binutils", "libs", CategoryBuild},
		{"binutils sframe library", "libsframe1", "binutils", "libs", CategoryBuild},
		{"macro processor", "m4", "m4", "interpreters", CategoryBuild},
		{"patch utility", "patch", "patch", "vcs", CategoryBuild},

		// Build toolchain via the package name, where the source is a runtime one.
		{"glibc headers", "libc6-dev", "glibc", "libdevel", CategoryBuild},
		{"glibc dev helpers", "libc-dev-bin", "glibc", "libdevel", CategoryBuild},
		{"rpm devel subpackage", "openssl-devel", "openssl", "", CategoryBuild},
		{"alpine dev subpackage", "musl-dev", "musl", "", CategoryBuild},
		{"static archive subpackage", "glibc-static", "glibc", "", CategoryBuild},

		// Build toolchain via Section, for packages neither rule above names.
		{"section devel", "autoconf", "autoconf", "devel", CategoryBuild},
		{"section libdevel", "libssl-dev", "openssl", "libdevel", CategoryBuild},

		// Runtime. gcc's source produces genuine runtime libraries, which is
		// why compiler sources must not be classified by source name.
		{"gcc runtime library", "libstdc++6", "gcc-14", "libs", ""},
		{"gcc support library", "libgcc-s1", "gcc-14", "libs", ""},
		// libtool's own package is build tooling, but the library it ships is
		// loaded at runtime by ImageMagick and PHP.
		{"libtool itself", "libtool", "libtool", "devel", CategoryBuild},
		{"libtool runtime loader", "libltdl7", "libtool", "libs", ""},
		{"c library", "libc6", "glibc", "libs", ""},
		{"http client", "curl", "curl", "web", ""},
		{"interpreter", "perl", "perl", "perl", ""},
		{"image library", "libmagickcore-7.q16-10", "imagemagick", "libs", ""},
		{"package manager is not build tooling", "dpkg", "dpkg", "admin", ""},
		{"empty input", "", "", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := classifyNonRuntime(tc.name, tc.source, tc.section)
			if got != tc.want {
				t.Errorf("classifyNonRuntime(%q, %q, %q) = %q, want %q",
					tc.name, tc.source, tc.section, got, tc.want)
			}
		})
	}
}

func TestClassifyNonRuntime_EmptySourceFallsBackToPackageName(t *testing.T) {
	// dpkg omits "Source:" when the source and binary names are identical, and
	// apk/rpm may have no origin recorded at all.
	if got := classifyNonRuntime("binutils", "", ""); got != CategoryBuild {
		t.Errorf("classifyNonRuntime with no source = %q, want %q", got, CategoryBuild)
	}
}

func TestApplyCategory_SetsExcludedScope(t *testing.T) {
	p := applyCategory(pkgFor("libbinutils"), "binutils", "libs")
	if p.Category != CategoryBuild {
		t.Errorf("Category = %q, want %q", p.Category, CategoryBuild)
	}
	if p.Scope != "excluded" {
		t.Errorf("Scope = %q, want %q", p.Scope, "excluded")
	}
	if p.SourcePackage != "binutils" {
		t.Errorf("SourcePackage = %q, want %q", p.SourcePackage, "binutils")
	}

	r := applyCategory(pkgFor("libc6"), "glibc", "libs")
	if r.Category != "" {
		t.Errorf("Category = %q, want \"\" for a runtime package", r.Category)
	}
	if r.Scope != "" {
		t.Errorf("Scope = %q, want \"\" for a runtime package", r.Scope)
	}
	if r.SourcePackage != "glibc" {
		t.Errorf("SourcePackage = %q, want %q", r.SourcePackage, "glibc")
	}
}

func TestApplyCategory_DefaultsSourcePackageToName(t *testing.T) {
	p := applyCategory(pkgFor("curl"), "", "web")
	if p.SourcePackage != "curl" {
		t.Errorf("SourcePackage = %q, want the package's own name", p.SourcePackage)
	}
}

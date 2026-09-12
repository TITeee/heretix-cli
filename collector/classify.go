package collector

import (
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// Categories for packages that are present in an image but are not part of
// what it runs. They are reported, never dropped — see report.PrintTable.
const (
	// CategoryKernel is kernel headers and kernel packages. In a container
	// image the host kernel is what actually runs, so a kernel-header package
	// attracts every kernel CVE while none of that code is executed.
	CategoryKernel = "kernel"
	// CategoryBuild is compilers, linkers and header/static-library packages
	// left behind by a build stage.
	CategoryBuild = "build"
)

// kernelSources are source package names whose every binary package belongs to
// the kernel. "linux-signed-*" is Debian's per-architecture signed rebuild.
var kernelSources = map[string]bool{
	"linux":  true, // Debian/Ubuntu
	"kernel": true, // RHEL family
}

// buildSources are source package names whose every binary package is build
// tooling, including the libraries they are split into. binutils is the reason
// this map exists: libbinutils, libctf0, libsframe1 and libgprofng0 are all
// Section=libs, so nothing but the source name identifies them.
//
// Sources that also produce a genuine runtime library are deliberately absent,
// even though their other binary packages are pure build tooling: gcc and clang
// ship libgcc-s1/libstdc++6, which every C/C++ program in the image links
// against, and libtool ships libltdl7, which ImageMagick and PHP load modules
// through. Their own binary packages are caught by name suffix or Section
// instead, which does not sweep up the runtime libraries with them.
var buildSources = map[string]bool{
	"autoconf":  true,
	"automake":  true,
	"binutils":  true,
	"bison":     true,
	"cmake":     true,
	"flex":      true,
	"m4":        true,
	"make":      true,
	"make-dfsg": true,
	"patch":     true,
	"pkgconf":   true,
}

// buildSuffixes are package-name endings that mark a header/static-library or
// development subpackage across all three OS package managers: "-dev" (dpkg,
// apk), "-devel" (rpm), "-static" (rpm), "-headers" (rpm).
var buildSuffixes = []string{"-dev", "-devel", "-dev-bin", "-static", "-headers"}

// buildSections are dpkg Section values that mean development material. They
// are a supporting signal only — see buildSources for why they are not enough.
var buildSections = map[string]bool{
	"devel":    true,
	"libdevel": true,
}

// classifyNonRuntime returns CategoryKernel, CategoryBuild, or "" for a normal
// runtime package. section is a dpkg Section value and is empty for rpm and
// apk, which have no equivalent field.
//
// The source package is the primary signal because it is the only one all
// three package databases record (dpkg "Source:", rpm SourceRpm, apk "o:"),
// and because it survives the split of one upstream project into many binary
// packages, which package names do not.
func classifyNonRuntime(name, source, section string) string {
	if source == "" {
		source = name
	}
	if kernelSources[source] || strings.HasPrefix(source, "linux-signed") {
		return CategoryKernel
	}
	if isKernelHeaderName(name) {
		return CategoryKernel
	}
	if buildSources[source] {
		return CategoryBuild
	}
	for _, suffix := range buildSuffixes {
		if strings.HasSuffix(name, suffix) {
			return CategoryBuild
		}
	}
	if buildSections[section] {
		return CategoryBuild
	}
	return ""
}

// isKernelHeaderName catches kernel header packages whose source package is
// itself named after the headers rather than after the kernel — Alpine's
// "linux-headers", and Debian's per-version "linux-headers-6.12.0-amd64".
func isKernelHeaderName(name string) bool {
	switch name {
	case "linux-libc-dev", "linux-headers", "linux-kernel-headers", "kernel-headers":
		return true
	}
	return strings.HasPrefix(name, "linux-headers-") || strings.HasPrefix(name, "kernel-devel")
}

// applyCategory fills in SourcePackage and Category on a collected OS package,
// and mirrors a non-runtime classification into Scope so it reaches the
// CycloneDX component as scope=excluded.
func applyCategory(p inventory.Package, source, section string) inventory.Package {
	if source == "" {
		source = p.Name
	}
	p.SourcePackage = source
	p.Category = classifyNonRuntime(p.Name, source, section)
	if p.Category != "" {
		p.Scope = "excluded"
	}
	return p
}

package collector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

// classified builds an OS package the way a collector does.
func classified(name, source, section, collectorSource string) inventory.Package {
	return applyCategory(inventory.Package{Name: name, Source: collectorSource}, source, section)
}

func TestRelaxForHost(t *testing.T) {
	tests := map[string]struct {
		pkg          inventory.Package
		wantCategory string
		wantScope    string
	}{
		// What runs on a host. Classified as non-runtime in an image, and
		// then never scanned by heretix-management.
		"debian kernel image":   {classified("linux-image-6.1.0-18-amd64", "linux-signed-amd64", "kernel", "dpkg"), "", ""},
		"ubuntu kernel modules": {classified("linux-modules-5.15.0-91-generic", "linux", "kernel", "dpkg"), "", ""},
		"rhel kernel":           {classified("kernel", "kernel", "", "rpm"), "", ""},
		"rhel kernel-core":      {classified("kernel-core", "kernel", "", "rpm"), "", ""},
		"compiler":              {classified("gcc", "gcc-14", "devel", "dpkg"), "", ""},
		"binutils":              {classified("binutils", "binutils", "devel", "dpkg"), "", ""},
		"development headers":   {classified("libssl-dev", "openssl", "libdevel", "dpkg"), "", ""},
		"rpm -devel":            {classified("openssl-devel", "openssl", "", "rpm"), "", ""},

		// Header packages run no code anywhere, so they stay non-runtime.
		"debian kernel headers": {classified("linux-libc-dev", "linux", "devel", "dpkg"), CategoryKernel, "excluded"},
		"debian versioned":      {classified("linux-headers-6.1.0-18-amd64", "linux", "kernel", "dpkg"), CategoryKernel, "excluded"},
		"rhel kernel-headers":   {classified("kernel-headers", "kernel", "", "rpm"), CategoryKernel, "excluded"},
		"rhel kernel-devel":     {classified("kernel-devel", "kernel", "", "rpm"), CategoryKernel, "excluded"},
		"alpine linux-headers":  {classified("linux-headers", "linux-headers", "", "apk-db"), CategoryKernel, "excluded"},

		// Nothing to take back.
		"ordinary package": {classified("openssl", "openssl", "utils", "dpkg"), "", ""},
	}
	for name, tc := range tests {
		pkgs := []inventory.Package{tc.pkg}
		relaxForHost(pkgs)
		if pkgs[0].Category != tc.wantCategory || pkgs[0].Scope != tc.wantScope {
			t.Errorf("%s: category/scope = %q/%q, want %q/%q", name, pkgs[0].Category, pkgs[0].Scope, tc.wantCategory, tc.wantScope)
		}
	}
}

// Only OS packages carry the kernel and build categories; other packages that
// are excluded for their own reasons must not be touched.
func TestRelaxForHost_LeavesOtherExclusionsAlone(t *testing.T) {
	pkgs := []inventory.Package{
		{Name: "urllib3", Source: "dist-info", Category: inventory.CategoryOSManaged, Scope: "excluded"},
		{Name: "jest", Source: "package-lock.json", Scope: "excluded"},
	}
	relaxForHost(pkgs)
	if pkgs[0].Category != inventory.CategoryOSManaged || pkgs[0].Scope != "excluded" {
		t.Errorf("os-managed package changed: %+v", pkgs[0])
	}
	if pkgs[1].Scope != "excluded" {
		t.Errorf("dev-only npm package changed: %+v", pkgs[1])
	}
}

// TestCollectAll_HostAndImageClassifyDifferently runs the same dpkg database
// through a host scan and an image scan: the kernel image and compiler are
// non-runtime only in the image. The OS package collectors don't run for a
// host scan on Windows, so this is a Linux (CI) test.
func TestCollectAll_HostAndImageClassifyDifferently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OS package collectors run for a non-container scan on Linux only")
	}
	root := t.TempDir()
	dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := ""
	for _, p := range []struct{ name, source, section string }{
		{"linux-image-6.1.0-18-amd64", "linux-signed-amd64", "kernel"},
		{"linux-libc-dev", "linux", "devel"},
		{"gcc", "gcc-14", "devel"},
		{"openssl", "openssl", "utils"},
	} {
		status += "Package: " + p.name + "\nStatus: install ok installed\nSection: " + p.section +
			"\nSource: " + p.source + "\nVersion: 1.0\n\n"
	}
	if err := os.WriteFile(filepath.Join(dpkgDir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}

	categories := func(isContainer bool) map[string]string {
		inv, err := CollectAll(root, []string{"rpm", "apk", "pypi", "npm", "go", "gobinary", "composer", "maven", "gradle", "jar"}, false, isContainer)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, p := range inv.Packages {
			got[p.Name] = p.Category
		}
		return got
	}

	image, host := categories(true), categories(false)
	for name, want := range map[string]string{"linux-image-6.1.0-18-amd64": CategoryKernel, "linux-libc-dev": CategoryKernel, "gcc": CategoryBuild, "openssl": ""} {
		if image[name] != want {
			t.Errorf("image scan: %s category = %q, want %q", name, image[name], want)
		}
	}
	for name, want := range map[string]string{"linux-image-6.1.0-18-amd64": "", "linux-libc-dev": CategoryKernel, "gcc": "", "openssl": ""} {
		if host[name] != want {
			t.Errorf("host scan: %s category = %q, want %q", name, host[name], want)
		}
	}
}

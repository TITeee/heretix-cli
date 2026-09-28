package collector

import (
	"path/filepath"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

// dpkgRootfs builds a minimal Debian rootfs whose dpkg database says
// python3-urllib3 installed urllib3's dist-info directory.
func dpkgRootfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	info := filepath.Join(root, "var", "lib", "dpkg", "info")
	mustMkdirAll(t, info)
	mustWriteFile(t, filepath.Join(info, "python3-urllib3.list"),
		"/.\n/usr\n/usr/lib/python3/dist-packages\n/usr/lib/python3/dist-packages/urllib3-1.26.5.dist-info/METADATA\n")
	// Pre-/usr-merge path; the walk only reaches it through /usr/lib.
	// Named without dpkg's usual ":amd64" suffix, which NTFS can't hold.
	mustWriteFile(t, filepath.Join(info, "libfoo.list"), "/lib/x86_64-linux-gnu/foo/foo.jar\n")
	return root
}

func TestMarkOSManaged_MarksOnlyPackagesWhoseFileAnOSPackageOwns(t *testing.T) {
	root := dpkgRootfs(t)
	in := func(p string) string { return filepath.Join(root, filepath.FromSlash(p)) }
	pkgs := []inventory.Package{
		{Name: "urllib3", Version: "1.26.5", Ecosystem: "PyPI", Source: "dist-info",
			Location: in("/usr/lib/python3/dist-packages/urllib3-1.26.5.dist-info/METADATA")},
		// Same directory, but pip put it there: no package lists it.
		{Name: "requests", Version: "2.31.0", Ecosystem: "PyPI", Source: "dist-info",
			Location: in("/usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA")},
		{Name: "org.example:foo", Version: "1.0", Ecosystem: "Maven", Source: "jar",
			Location: in("/usr/lib/x86_64-linux-gnu/foo/foo.jar") + "!/lib/inner.jar"},
		{Name: "python3-urllib3", Version: "1.26.5-1", Ecosystem: "Debian:12", Source: "dpkg"},
		{Name: "stdlib", Version: "1.22.0", Ecosystem: "Go", Source: "gobinary"}, // no Location
	}

	markOSManaged(pkgs, root, false)

	want := map[string]string{
		"urllib3":         inventory.CategoryOSManaged,
		"requests":        "",
		"org.example:foo": inventory.CategoryOSManaged,
		"python3-urllib3": "",
		"stdlib":          "",
	}
	for _, p := range pkgs {
		if p.Category != want[p.Name] {
			t.Errorf("%s: Category = %q, want %q", p.Name, p.Category, want[p.Name])
		}
		if wantScope := map[bool]string{true: "excluded", false: ""}[want[p.Name] != ""]; p.Scope != wantScope {
			t.Errorf("%s: Scope = %q, want %q", p.Name, p.Scope, wantScope)
		}
	}
}

func TestMarkOSManaged_NoPackageDatabaseIsANoOp(t *testing.T) {
	root := t.TempDir()
	pkgs := []inventory.Package{{Name: "urllib3", Version: "1.26.5", Ecosystem: "PyPI", Source: "dist-info",
		Location: filepath.Join(root, "usr", "lib", "python3", "dist-packages", "urllib3-1.26.5.dist-info", "METADATA")}}
	markOSManaged(pkgs, root, false)
	if pkgs[0].Category != "" {
		t.Errorf("Category = %q, want empty for a scan path with no OS package database", pkgs[0].Category)
	}
}

func TestOSOwnedFiles_ReadsAPKDatabase(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "lib", "apk", "db")
	mustMkdirAll(t, db)
	mustWriteFile(t, filepath.Join(db, "installed"),
		"P:py3-urllib3\nV:1.26.18-r0\nF:usr\nF:usr/lib/python3.12/site-packages/urllib3-1.26.18.dist-info\nR:METADATA\nR:RECORD\n\n"+
			"P:musl\nV:1.2.5-r0\nF:lib\nR:ld-musl-x86_64.so.1\n")

	owned := osOwnedFiles(root, false)
	for _, p := range []string{
		"/usr/lib/python3.12/site-packages/urllib3-1.26.18.dist-info/METADATA",
		"/usr/lib/python3.12/site-packages/urllib3-1.26.18.dist-info/RECORD",
		"/lib/ld-musl-x86_64.so.1",
	} {
		if !owned[p] {
			t.Errorf("expected %s to be owned", p)
		}
	}
	if owned["/usr/lib/python3.12/site-packages/urllib3-1.26.18.dist-info"] {
		t.Error("a directory line (F:) is not itself a file an R: line lists")
	}
}

func TestRootRelative(t *testing.T) {
	root := t.TempDir()
	got := rootRelative(filepath.Join(root, "usr", "bin", "dlv"), root)
	if got != "/usr/bin/dlv" {
		t.Errorf("rootRelative = %q, want %q", got, "/usr/bin/dlv")
	}
}

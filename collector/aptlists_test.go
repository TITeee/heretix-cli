package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestApplyAptLists: a package gets the .deb digest and the repository's Origin
// only for its exact name, version and architecture; a version the lists no
// longer offer, or one two lists disagree about, gets neither.
func TestApplyAptLists(t *testing.T) {
	root := t.TempDir()
	lists := filepath.Join(root, "var", "lib", "apt", "lists")
	writeFile(t, filepath.Join(lists, "deb.debian.org_debian_dists_trixie_InRelease"),
		"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nLabel: Debian\nSuite: stable\n")
	writeFile(t, filepath.Join(lists, "deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages"), `Package: curl
Version: 8.14.1-2+deb13u2
Architecture: amd64
Description: command line tool for transferring data with URL syntax
SHA256: aaaa

Package: curl
Version: 8.14.1-2+deb13u3
Architecture: amd64
SHA256: bbbb

Package: tzdata
Version: 2026a-1
Architecture: all
SHA256: cccc

Package: libfoo
Version: 1.0
Architecture: amd64
SHA256: dddd
`)
	writeFile(t, filepath.Join(lists, "download.docker.com_linux_debian_dists_trixie_InRelease"), "Origin: Docker\n")
	writeFile(t, filepath.Join(lists, "download.docker.com_linux_debian_dists_trixie_stable_binary-amd64_Packages"), `Package: docker-ce
Version: 5:28.0.0-1~debian.13~trixie
Architecture: amd64
SHA256: eeee

Package: libfoo
Version: 1.0
Architecture: amd64
SHA256: ffff
`)

	pkgs := []inventory.Package{
		{Name: "curl", Version: "8.14.1-2+deb13u2"},
		{Name: "tzdata", Version: "2026a-1"},
		{Name: "docker-ce", Version: "5:28.0.0-1~debian.13~trixie"},
		{Name: "openssl", Version: "3.5.1-1"}, // in no list
		{Name: "libfoo", Version: "1.0"},      // two lists, two digests
		{Name: "curl-old", Version: "8.0-1"},  // not wanted by any list
	}
	applyAptLists(withArchs(pkgs, []string{"amd64", "all", "amd64", "amd64", "amd64", "amd64"}), root, false)

	want := []struct{ integrity, supplier string }{
		{"sha256:aaaa", "Debian"},
		{"sha256:cccc", "Debian"},
		{"sha256:eeee", "Docker"},
		{"", ""},
		{"", ""},
		{"", ""},
	}
	for i, w := range want {
		if pkgs[i].Integrity != w.integrity || pkgs[i].Supplier != w.supplier {
			t.Errorf("%s: integrity %q supplier %q, want %q %q", pkgs[i].Name, pkgs[i].Integrity, pkgs[i].Supplier, w.integrity, w.supplier)
		}
	}
}

func TestApplyAptListsWithoutLists(t *testing.T) {
	pkgs := []inventory.Package{{Name: "curl", Version: "8.14.1-2"}}
	applyAptLists(withArchs(pkgs, []string{"amd64"}), t.TempDir(), false)
	if pkgs[0].Integrity != "" || pkgs[0].Supplier != "" {
		t.Errorf("no lists: got %+v", pkgs[0])
	}
}

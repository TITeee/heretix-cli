package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const sampleTSV = "openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\n" +
	"bash\t0\t5.1.8\t6.el9\tx86_64\tbash-5.1.8-6.el9.src.rpm\n" +
	"gpg-pubkey\t0\t5a6340b3\t6229229e\t(none)\t(none)\n"

// writeHost writes the four files rpmqa2sbom reads and returns their directory.
func writeHost(t *testing.T, osRelease string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"rpm-qa.tsv":     sampleTSV,
		"os-release.txt": osRelease,
		"hostname.txt":   "web-01\n",
		"uname.txt":      "5.14.0-362.el9.x86_64\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readBOM(t *testing.T, path string) *cdx.BOM {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatal(err)
	}
	return bom
}

func component(t *testing.T, bom *cdx.BOM, name string) cdx.Component {
	t.Helper()
	for _, c := range *bom.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component %q", name)
	return cdx.Component{}
}

func TestCompatPURL(t *testing.T) {
	for _, tc := range []struct{ in, name, ver, want string }{
		{"pkg:rpm/rhel/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=redhat-9&epoch=1", "redhat", "9.8",
			"pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=redhat-9.8&epoch=1"},
		{"pkg:rpm/almalinux/bash@5.1.8-6.el9?arch=x86_64&distro=almalinux-9", "alma", "9.2",
			"pkg:rpm/alma/bash@5.1.8-6.el9?arch=x86_64&distro=alma-9.2"},
		{"pkg:rpm/oraclelinux/bash@5.1.8-6.el9?distro=oraclelinux-9", "oracle", "9.2",
			"pkg:rpm/oracle/bash@5.1.8-6.el9?distro=oracle-9.2"},
		// No qualifiers: only the namespace changes.
		{"pkg:rpm/rhel/bash@5.1.8-6.el9", "redhat", "9.8", "pkg:rpm/redhat/bash@5.1.8-6.el9"},
		// Not an rpm PURL: left alone.
		{"pkg:pypi/requests@2.31.0", "redhat", "9.8", "pkg:pypi/requests@2.31.0"},
		{"", "redhat", "9.8", ""},
	} {
		if got := compatPURL(tc.in, tc.name, tc.ver); got != tc.want {
			t.Errorf("compatPURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunDefaultKeepsHeretixNames(t *testing.T) {
	dir := writeHost(t, "ID=\"rhel\"\nVERSION_ID=\"9.8\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.8 (Plow)\"\n")
	out := filepath.Join(t.TempDir(), "out.json")
	if err := run(dir, []string{out}, false); err != nil {
		t.Fatal(err)
	}
	bom := readBOM(t, out)
	if got := bom.Metadata.Component.Type; got != cdx.ComponentTypeOS {
		t.Errorf("metadata.component type = %q, want operating-system", got)
	}
	if got := component(t, bom, "rhel").Type; got != cdx.ComponentTypeOS {
		t.Errorf("the OS component = %q", got)
	}
	if purl := component(t, bom, "openssl-libs").PackageURL; !strings.HasPrefix(purl, "pkg:rpm/rhel/") || !strings.Contains(purl, "distro=redhat-9&") {
		t.Errorf("default PURL = %q", purl)
	}
}

func TestRunCompat(t *testing.T) {
	for _, tc := range []struct {
		osRelease, name, ver, purlStart, distro string
	}{
		{"ID=\"rhel\"\nVERSION_ID=\"9.8\"\n", "redhat", "9.8", "pkg:rpm/redhat/", "distro=redhat-9.8"},
		{"ID=\"almalinux\"\nVERSION_ID=\"9.2\"\n", "alma", "9.2", "pkg:rpm/alma/", "distro=alma-9.2"},
		{"ID=\"rocky\"\nVERSION_ID=\"9.2\"\n", "rocky", "9.2", "pkg:rpm/rocky/", "distro=rocky-9.2"},
		{"ID=\"centos\"\nVERSION_ID=\"7\"\n", "centos", "7", "pkg:rpm/centos/", "distro=centos-7"},
		{"ID=\"ol\"\nVERSION_ID=\"9.2\"\n", "oracle", "9.2", "pkg:rpm/oracle/", "distro=oracle-9.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeHost(t, tc.osRelease)
			out := filepath.Join(t.TempDir(), "compat.json")
			if err := run(dir, []string{out}, true); err != nil {
				t.Fatal(err)
			}
			bom := readBOM(t, out)

			// The scanned host is an application; the one operating-system component is the distro.
			if got := bom.Metadata.Component.Type; got != cdx.ComponentTypeApplication {
				t.Errorf("metadata.component type = %q, want application", got)
			}
			var osComponents []cdx.Component
			for _, c := range *bom.Components {
				if c.Type == cdx.ComponentTypeOS {
					osComponents = append(osComponents, c)
				}
			}
			if len(osComponents) != 1 || osComponents[0].Name != tc.name || osComponents[0].Version != tc.ver {
				t.Errorf("OS components = %+v, want one named %s %s", osComponents, tc.name, tc.ver)
			}

			// Packages: namespace and distro follow, nothing else about the PURL changes.
			ssl := component(t, bom, "openssl-libs")
			if !strings.HasPrefix(ssl.PackageURL, tc.purlStart) || !strings.Contains(ssl.PackageURL, tc.distro) ||
				!strings.Contains(ssl.PackageURL, "@3.0.7-24.el9") || !strings.Contains(ssl.PackageURL, "epoch=1") {
				t.Errorf("PURL = %q", ssl.PackageURL)
			}
			if ssl.BOMRef != ssl.PackageURL {
				t.Errorf("bom-ref %q should follow the PURL %q", ssl.BOMRef, ssl.PackageURL)
			}
			// heretix's own properties stay.
			if ssl.Properties == nil || len(*ssl.Properties) == 0 {
				t.Error("heretix properties were dropped")
			}
			// Every dependency reference still names a component.
			refs := map[string]bool{bom.Metadata.Component.BOMRef: true}
			for _, c := range *bom.Components {
				refs[c.BOMRef] = true
			}
			for _, d := range *bom.Dependencies {
				if !refs[d.Ref] {
					t.Errorf("dependency ref %q names no component", d.Ref)
				}
				if d.Dependencies == nil {
					continue
				}
				for _, r := range *d.Dependencies {
					if !refs[r] {
						t.Errorf("dependency %q -> %q names no component", d.Ref, r)
					}
				}
			}
		})
	}
}

func TestCompatLeavesAnUnknownDistroAlone(t *testing.T) {
	dir := writeHost(t, "ID=\"fedora\"\nVERSION_ID=\"40\"\n")
	out := filepath.Join(t.TempDir(), "compat.json")
	if err := run(dir, []string{out}, true); err != nil {
		t.Fatal(err)
	}
	bom := readBOM(t, out)
	if got := bom.Metadata.Component.Type; got != cdx.ComponentTypeOS {
		t.Errorf("metadata.component type = %q: names must be left as they are", got)
	}
	bom = &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeOS}}}
	if note := applyCompat(bom, parseOSRelease("ID=\"fedora\"\nVERSION_ID=\"40\"\n")); !strings.Contains(note, `"fedora"`) {
		t.Errorf("note = %q, want it to name the ID", note)
	}
}

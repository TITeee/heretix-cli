package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGoBinaryCollect_SkipsHostScans guards the container-only scope decision:
// a live-host scan (isContainer=false) must never open and parse arbitrary
// executables on disk, since that's far noisier/slower than the single
// extracted image layer this collector exists to audit.
func TestGoBinaryCollect_SkipsHostScans(t *testing.T) {
	pkgs, err := (&GoBinaryCollector{}).Collect(t.TempDir(), false, false)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pkgs != nil {
		t.Errorf("Collect with isContainer=false returned %d packages, want none", len(pkgs))
	}
}

// TestGoBinaryCollect_ReadsEmbeddedModules is the regression test for the
// mysql:oraclelinux9 gap investigation (2026-09-14): a statically-linked Go
// binary with no go.mod anywhere in the image (like /usr/local/bin/gosu) must
// still surface its embedded module dependencies and Go stdlib version.
//
// It builds heretix-cli's own main binary (which pulls in real third-party
// modules like github.com/spf13/cobra) into a fake rootfs and scans that,
// exercising the actual debug/buildinfo parsing path against a real
// multi-dependency binary without needing network access for a fixture.
func TestGoBinaryCollect_ReadsEmbeddedModules(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not available")
	}

	rootfs := t.TempDir()
	binDir := filepath.Join(rootfs, "usr", "local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(binDir, "app")

	cmd := exec.Command("go", "build", "-o", dest, "..")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build heretix-cli fixture binary: %v\n%s", err, out)
	}

	pkgs, err := (&GoBinaryCollector{}).Collect(rootfs, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("Collect found no packages in a real Go test binary")
	}

	var sawDep, sawStdlib bool
	for _, p := range pkgs {
		if p.Ecosystem != "Go" {
			t.Errorf("package %q has ecosystem %q, want Go", p.Name, p.Ecosystem)
		}
		if p.Source != "gobinary" {
			t.Errorf("package %q has source %q, want gobinary", p.Name, p.Source)
		}
		if p.Name == "github.com/spf13/cobra" {
			sawDep = true
			if p.Version == "" {
				t.Error("github.com/spf13/cobra: version is empty")
			}
			if p.Location != dest {
				t.Errorf("github.com/spf13/cobra: location = %q, want %q", p.Location, dest)
			}
		}
		if p.Name == "stdlib" {
			sawStdlib = true
			if p.Version == "" || p.Version[0] == 'g' {
				t.Errorf("stdlib version = %q, want a bare semver with no \"go\" prefix", p.Version)
			}
		}
	}
	if !sawDep {
		t.Errorf("did not find github.com/spf13/cobra among embedded deps: %+v", pkgs)
	}
	if !sawStdlib {
		t.Errorf("did not find a synthetic \"stdlib\" package: %+v", pkgs)
	}
}

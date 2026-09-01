package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

// TestDetectRPMEcosystem_RockyUsesFullName guards against sending an
// ecosystem string that never matches anything: heretix-api's OSV data
// stores Rocky Linux advisories under the ecosystem name OSV itself
// publishes, "Rocky Linux:N", not a bare "Rocky:N" prefix. Found 2026-09-01
// investigating why heretix-cli returned zero results for every Rocky Linux
// package despite matching advisory data existing.
func TestDetectRPMEcosystem_RockyUsesFullName(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc"))
	mustWriteFile(t, filepath.Join(root, "etc", "os-release"), "ID=rocky\nVERSION_ID=9.3\n")

	want := "Rocky Linux:9"
	if got := detectRPMEcosystem(root); got != want {
		t.Errorf("detectRPMEcosystem = %q, want %q", got, want)
	}
}

// TestDetectRPMEcosystem_OracleLinuxUsesVersionedForm guards against Oracle
// Linux's ecosystem string reverting to the bare, version-less "oracle-linux"
// form it used from 2026 until 2026-09-01. That form made heretix-api's
// AdvisoryAffectedProduct lookup (keyed by product+vendor, with vendor
// carrying no OS major version) compare an installed package against every
// major release's fix versions at once — an EL10 fix numerically higher than
// the installed EL9 version read as "not yet fixed" even when the correct
// EL9 advisory was long satisfied. The version suffix is what lets
// heretix-api's fix (keying vendor by version) take effect.
func TestDetectRPMEcosystem_OracleLinuxUsesVersionedForm(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc"))
	mustWriteFile(t, filepath.Join(root, "etc", "os-release"), "ID=ol\nVERSION_ID=9.3\n")

	want := "Oracle Linux:9"
	if got := detectRPMEcosystem(root); got != want {
		t.Errorf("detectRPMEcosystem = %q, want %q", got, want)
	}
}

// TestRpmEvr guards against a real epoch being dropped: it is the
// highest-precedence field in RPM version comparison, so a query missing it
// makes an already-patched package with a nonzero epoch look older than a
// long-fixed advisory. See heretix-cli bug report 2026-08-30.
func TestRpmEvr(t *testing.T) {
	two := 2

	tests := []struct {
		name    string
		epoch   *int
		version string
		release string
		want    string
	}{
		{"no epoch", nil, "7.88.1", "4.el9", "7.88.1-4.el9"},
		{"zero epoch", intPtr(0), "2.36.1", "8.el9", "2.36.1-8.el9"},
		{"real epoch is kept", &two, "4.9", "6.el9", "2:4.9-6.el9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rpmEvr(tt.epoch, tt.version, tt.release); got != tt.want {
				t.Errorf("rpmEvr(%v, %q, %q) = %q, want %q", tt.epoch, tt.version, tt.release, got, tt.want)
			}
		})
	}
}

func intPtr(i int) *int { return &i }

// TestFindRPMDatabase checks the (directory, filename) probing order: the
// newer "usr/lib/sysimage/rpm" location wins over the traditional
// "var/lib/rpm" one, and within a directory, sqlite/ndb/bdb filenames are
// tried in that order. None of these files need to be valid databases here —
// findRPMDatabase only decides which path to hand to rpmdb.Open.
func TestFindRPMDatabase(t *testing.T) {
	t.Run("no database present", func(t *testing.T) {
		root := t.TempDir()
		if got := findRPMDatabase(root); got != "" {
			t.Errorf("findRPMDatabase = %q, want \"\"", got)
		}
	})

	t.Run("legacy Packages under var/lib/rpm", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "var", "lib", "rpm")
		mustMkdirAll(t, dir)
		mustWriteFile(t, filepath.Join(dir, "Packages"), "bdb")

		want := filepath.Join(dir, "Packages")
		if got := findRPMDatabase(root); got != want {
			t.Errorf("findRPMDatabase = %q, want %q", got, want)
		}
	})

	t.Run("sqlite preferred over legacy Packages in the same directory", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "var", "lib", "rpm")
		mustMkdirAll(t, dir)
		mustWriteFile(t, filepath.Join(dir, "Packages"), "bdb")
		mustWriteFile(t, filepath.Join(dir, "rpmdb.sqlite"), "sqlite")

		want := filepath.Join(dir, "rpmdb.sqlite")
		if got := findRPMDatabase(root); got != want {
			t.Errorf("findRPMDatabase = %q, want %q", got, want)
		}
	})

	t.Run("usr/lib/sysimage/rpm preferred over var/lib/rpm", func(t *testing.T) {
		root := t.TempDir()
		oldDir := filepath.Join(root, "var", "lib", "rpm")
		newDir := filepath.Join(root, "usr", "lib", "sysimage", "rpm")
		mustMkdirAll(t, oldDir)
		mustMkdirAll(t, newDir)
		mustWriteFile(t, filepath.Join(oldDir, "Packages"), "bdb")
		mustWriteFile(t, filepath.Join(newDir, "Packages"), "bdb")

		want := filepath.Join(newDir, "Packages")
		if got := findRPMDatabase(root); got != want {
			t.Errorf("findRPMDatabase = %q, want %q", got, want)
		}
	})
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRPMCollect_ParsesRealDatabase is an integration test against a real RPM
// database (SQLite format, AlmaLinux 9), trimmed down to three packages —
// see collector/testdata/rpmdb-sample.sqlite. It guards the two things unit
// tests on synthetic data can't: that go-rpmdb actually parses this format,
// and that a real package carrying a genuine nonzero epoch (dbus, epoch 1)
// comes out with that epoch intact.
func TestRPMCollect_ParsesRealDatabase(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "rpmdb-sample.sqlite"))
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	dbDir := filepath.Join(root, "var", "lib", "rpm")
	mustMkdirAll(t, dbDir)
	if err := os.WriteFile(filepath.Join(dbDir, "rpmdb.sqlite"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	mustMkdirAll(t, filepath.Join(root, "etc"))
	mustWriteFile(t, filepath.Join(root, "etc", "os-release"), "ID=almalinux\nVERSION_ID=9.3\n")

	pkgs, err := (&RPMCollector{}).Collect(root, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byName := map[string]inventory.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["gpg-pubkey"]; ok {
		t.Error("gpg-pubkey entry (an imported signing key, not a package) should be filtered out")
	}

	base, ok := byName["basesystem"]
	if !ok {
		t.Fatal("expected \"basesystem\" package in results")
	}
	if base.Version != "11-13.el9" {
		t.Errorf("basesystem Version = %q, want %q (no epoch)", base.Version, "11-13.el9")
	}
	if base.Ecosystem != "AlmaLinux:9" {
		t.Errorf("basesystem Ecosystem = %q, want %q", base.Ecosystem, "AlmaLinux:9")
	}

	dbus, ok := byName["dbus"]
	if !ok {
		t.Fatal("expected \"dbus\" package in results")
	}
	if dbus.Version != "1:1.12.20-8.el9" {
		t.Errorf("dbus Version = %q, want %q (real epoch preserved)", dbus.Version, "1:1.12.20-8.el9")
	}
}

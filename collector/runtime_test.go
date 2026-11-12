package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

// fakeProc writes one process under procRoot: its maps, exe link, cgroup and
// comm, the files readProcess reads.
func fakeProc(t *testing.T, procRoot, pid, maps, exe, cgroup, comm string) {
	dir := filepath.Join(procRoot, pid)
	mustMkdirAll(t, dir)
	mustWriteFile(t, filepath.Join(dir, "maps"), maps)
	if exe != "" {
		if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, filepath.Join(dir, "cgroup"), cgroup)
	mustWriteFile(t, filepath.Join(dir, "comm"), comm+"\n")
}

func TestReadProcesses(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, "100",
		strings.Join([]string{
			"aaaa-bbbb r-xp 00000000 fd:01 1234                       /usr/bin/sleep",
			// A library maps several segments; its code is the executable one.
			"cccc-cccd r--p 00000000 fd:01 5678                       /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)",
			"cccd-ccce r-xp 00028000 fd:01 5678                       /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)",
			"eeee-ffff rw-p 00000000 00:00 0                          [heap]",
			"1111-2222 rw-p 00000000 00:00 0 ",
			"3333-4444 r-xp 00000000 fd:01 9999                       /usr/lib/with space/libx.so",
			// Data files: mapped, but no code of theirs runs. Not counted, replaced or not.
			"5555-6666 r--p 00000000 fd:01 7777                       /usr/lib/locale/C.utf8/LC_CTYPE",
			"7777-8888 r--s 00000000 fd:01 8888                       /usr/lib/modules/6.12.43-1-amd64/modules.alias.bin (deleted)",
		}, "\n")+"\n",
		"/usr/bin/sleep", "0::/system.slice/cron.service\n", "sleep")
	// A static binary: maps name no library, exe names it.
	fakeProc(t, root, "200", "aaaa-bbbb r-xp 00000000 00:00 0 \n", "/opt/app/server", "0::/user.slice/user-1000.slice/session-3.scope\n", "server")
	// A kernel thread: nothing mapped, no exe.
	fakeProc(t, root, "300", "", "", "0::/\n", "kworker/0:1")
	// Not a process directory.
	mustMkdirAll(t, filepath.Join(root, "sys"))

	procs, err := readProcesses(root, 200000)
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 2 {
		t.Fatalf("got %d processes, want 2 (the kernel thread is skipped): %+v", len(procs), procs)
	}
	sleep, server := procs[0], procs[1]
	wantFiles := []string{"/usr/bin/sleep", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/with space/libx.so"}
	if !reflect.DeepEqual(sleep.files, wantFiles) {
		t.Errorf("files = %q, want %q", sleep.files, wantFiles)
	}
	if !sleep.deleted["/usr/lib/x86_64-linux-gnu/libc.so.6"] || sleep.deleted["/usr/bin/sleep"] || len(sleep.deleted) != 1 {
		t.Errorf("deleted = %v, want only libc (a replaced data file is not code left running)", sleep.deleted)
	}
	if sleep.unit != "cron.service" {
		t.Errorf("unit = %q, want cron.service", sleep.unit)
	}
	if !reflect.DeepEqual(server.files, []string{"/opt/app/server"}) || server.unit != "server" {
		t.Errorf("static binary: files %q unit %q, want its exe and its command name", server.files, server.unit)
	}

	if _, err := readProcesses(filepath.Join(root, "missing"), 1); err == nil {
		t.Error("an unreadable proc root should be an error, not an empty result")
	}
	// Only the caller's own process: nothing to read is an error too.
	if _, err := readProcesses(root, 100); err == nil {
		// pid 200 is still there, so this is fine; the empty case is below.
	}
	empty := t.TempDir()
	mustMkdirAll(t, filepath.Join(empty, "sys"))
	if _, err := readProcesses(empty, 1); err == nil {
		t.Error("no readable process should be an error")
	}
}

// TestApplyRuntimeFacts covers the three facts and their undetermined cases.
func TestApplyRuntimeFacts(t *testing.T) {
	pkgs := []inventory.Package{
		{Name: "coreutils", Version: "9.7-3", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "libc6", Version: "2.41-12", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "libssl3t64", Version: "3.5.1-1", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "tzdata", Version: "2025b-4", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "python3-six", Version: "1.17.0-1", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "linux-image-6.12.43-1-amd64", Version: "6.12.43-1", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "linux-image-6.12.38-1-amd64", Version: "6.12.38-1", Source: "dpkg", Ecosystem: "Debian:13"},
		{Name: "linux-image-amd64", Version: "6.12.43-1", Source: "dpkg", Ecosystem: "Debian:13"},
		// Not an OS package: never touched.
		{Name: "requests", Version: "2.32.0", Source: "dist-info", Ecosystem: "PyPI"},
	}
	owners := map[string]string{
		"/usr/bin/sleep":                           ownerKey("dpkg", "coreutils", ""),
		"/usr/bin/ls":                              ownerKey("dpkg", "coreutils", ""),
		"/lib/x86_64-linux-gnu/libc.so.6":          ownerKey("dpkg", "libc6", ""),
		"/usr/lib/x86_64-linux-gnu/libc.so.6":      ownerKey("dpkg", "libc6", ""),
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":    ownerKey("dpkg", "libssl3t64", ""),
		"/usr/share/zoneinfo/UTC":                  ownerKey("dpkg", "tzdata", ""),
		"/usr/lib/python3/dist-packages/six.py":    ownerKey("dpkg", "python3-six", ""),
		"/boot/vmlinuz-6.12.43-1-amd64":            ownerKey("dpkg", "linux-image-6.12.43-1-amd64", ""),
		"/lib/modules/6.12.43-1-amd64/kernel/a.ko": ownerKey("dpkg", "linux-image-6.12.43-1-amd64", ""),
	}
	procs := []process{
		{unit: "cron.service", files: []string{"/usr/bin/sleep", "/usr/lib/x86_64-linux-gnu/libc.so.6"}, deleted: map[string]bool{"/usr/lib/x86_64-linux-gnu/libc.so.6": true}},
		{unit: "bash", files: []string{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/bin/bash"}, deleted: map[string]bool{}},
	}
	n := applyRuntimeFacts(pkgs, owners, procs, "6.12.43-1-amd64")
	if n != 3 {
		t.Errorf("in use = %d, want 3 (coreutils, libc6, the running kernel)", n)
	}

	want := map[string]struct {
		inUse        *bool
		needsRestart bool
		usedBy       []string
	}{
		"coreutils":                   {inventory.BoolPtr(true), false, []string{"cron.service"}},
		"libc6":                       {inventory.BoolPtr(true), true, []string{"bash", "cron.service"}},
		"libssl3t64":                  {inventory.BoolPtr(false), false, nil}, // a library nobody mapped
		"tzdata":                      {nil, false, nil},                      // no code of its own
		"python3-six":                 {nil, false, nil},                      // an interpreted library
		"linux-image-6.12.43-1-amd64": {inventory.BoolPtr(true), false, nil},
		"linux-image-6.12.38-1-amd64": {inventory.BoolPtr(false), false, nil},
		"linux-image-amd64":           {nil, false, nil}, // the metapackage
		"requests":                    {nil, false, nil},
	}
	for _, p := range pkgs {
		w := want[p.Name]
		if (p.InUse == nil) != (w.inUse == nil) || (p.InUse != nil && *p.InUse != *w.inUse) {
			t.Errorf("%s: InUse = %v, want %v", p.Name, fmtBool(p.InUse), fmtBool(w.inUse))
		}
		if p.NeedsRestart != w.needsRestart {
			t.Errorf("%s: NeedsRestart = %v, want %v", p.Name, p.NeedsRestart, w.needsRestart)
		}
		if !reflect.DeepEqual(p.UsedBy, w.usedBy) {
			t.Errorf("%s: UsedBy = %q, want %q", p.Name, p.UsedBy, w.usedBy)
		}
	}
}

func fmtBool(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestKernelPackage_RPM(t *testing.T) {
	running := inventory.Package{Name: "kernel-core", Version: "5.14.0-570.17.1.el9_6", Arch: "x86_64", Source: "rpm"}
	older := inventory.Package{Name: "kernel-core", Version: "5.14.0-503.11.1.el9_5", Arch: "x86_64", Source: "rpm"}
	other := inventory.Package{Name: "kernel-tools", Version: "5.14.0-570.17.1.el9_6", Arch: "x86_64", Source: "rpm"}
	release := "5.14.0-570.17.1.el9_6.x86_64"
	if r, k := kernelPackage(running, release); !r || !k {
		t.Errorf("running kernel-core: (%v, %v), want (true, true)", r, k)
	}
	if r, k := kernelPackage(older, release); r || !k {
		t.Errorf("older kernel-core: (%v, %v), want (false, true)", r, k)
	}
	if _, k := kernelPackage(other, release); k {
		t.Error("kernel-tools is not a kernel")
	}
	// The modules ship in subpackages of the same version: the running kernel's
	// are in use, an older kernel's are not.
	for _, name := range []string{"kernel", "kernel-modules", "kernel-modules-core", "kernel-modules-extra"} {
		if r, k := kernelPackage(inventory.Package{Name: name, Version: running.Version, Arch: "x86_64", Source: "rpm"}, release); !r || !k {
			t.Errorf("running %s: (%v, %v), want (true, true)", name, r, k)
		}
		if r, k := kernelPackage(inventory.Package{Name: name, Version: older.Version, Arch: "x86_64", Source: "rpm"}, release); r || !k {
			t.Errorf("older %s: (%v, %v), want (false, true)", name, r, k)
		}
	}
}

func TestKernelPackage_Dpkg(t *testing.T) {
	release := "7.0.0-1014-aws"
	tests := []struct {
		name            string
		running, kernel bool
	}{
		{"linux-image-7.0.0-1014-aws", true, true},
		{"linux-image-unsigned-7.0.0-1014-aws", true, true},
		{"linux-modules-7.0.0-1014-aws", true, true},
		{"linux-modules-extra-7.0.0-1014-aws", true, true},
		{"linux-modules-6.8.0-147-generic", false, true},
		{"linux-image-6.8.0-147-generic", false, true},
		// Metapackages name no release.
		{"linux-image-aws", false, false},
		{"linux-modules-extra-aws", false, false},
		// Neither the image nor its modules.
		{"linux-headers-7.0.0-1014-aws", false, false},
		{"linux-tools-7.0.0-1014-aws", false, false},
		{"linux-base", false, false},
	}
	for _, tc := range tests {
		r, k := kernelPackage(inventory.Package{Name: tc.name, Source: "dpkg"}, release)
		if r != tc.running || k != tc.kernel {
			t.Errorf("%s: (%v, %v), want (%v, %v)", tc.name, r, k, tc.running, tc.kernel)
		}
	}
	// Debian has no modules packages; its image carries the release with a "+".
	if r, k := kernelPackage(inventory.Package{Name: "linux-image-6.12.43+deb13-amd64", Source: "dpkg"}, "6.12.43+deb13-amd64"); !r || !k {
		t.Errorf("Debian image: (%v, %v), want (true, true)", r, k)
	}
}

func TestIsCodePath(t *testing.T) {
	tests := map[string]bool{
		"/usr/bin/sleep":                             true,
		"/bin/sh":                                    true,
		"/usr/sbin/sshd":                             true,
		"/usr/libexec/openssh/sftp-server":           true,
		"/usr/lib/systemd/systemd-logind":            true,
		"/usr/lib/x86_64-linux-gnu/libc.so.6":        true,
		"/usr/lib64/libssl.so.3.2.2":                 true,
		"/usr/lib/python3/dist-packages/six.py":      false,
		"/usr/share/zoneinfo/UTC":                    false,
		"/lib/modules/6.12.43-1-amd64/kernel/fs.ko":  false,
		"/usr/bin/":                                  false,
		"/usr/lib/python3.13/lib-dynload/_ssl.so":    true,
		"/usr/share/doc/libc6/changelog.Debian.gz":   false,
		"/usr/lib/x86_64-linux-gnu/perl/5.40/auto/x": false,
	}
	for in, want := range tests {
		if got := isCodePath(in); got != want {
			t.Errorf("isCodePath(%q) = %v, want %v", in, got, want)
		}
	}
}

package collector

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// Runtime facts: what the running processes of a host were doing with its OS
// packages when collect ran, read from /proc.
//
//   - in-use: a process had one of the package's executables or shared
//     libraries mapped (/proc/<pid>/maps, /proc/<pid>/exe). A package with
//     code files none of which is mapped is not in use; a package with no
//     code of its own (data, configuration, scripts for an interpreter) is
//     left undetermined, since /proc cannot tell whether it is used.
//   - needs-restart: a mapped file has been replaced on disk since the process
//     opened it (the kernel marks it "(deleted)"): the package was upgraded,
//     and the process runs the old code until it is restarted.
//   - used-by: the systemd units of those processes, or the command names of
//     processes outside a unit.
//
// All three describe the moment collect ran. A program that runs now and then
// (a cron job) is not seen, so "not in use" is not "never used". The running
// kernel is in use by definition; another installed kernel is not.

// RuntimeApplies says whether the runtime facts can be read for a scan: only
// on a Linux host scanned at its root, where /proc describes the processes
// that run the packages found. An image or a directory has no processes.
func RuntimeApplies(scanPath string) bool {
	return runtime.GOOS == "linux" && isFilesystemRoot(scanPath)
}

// ApplyRuntime reads /proc and sets InUse, NeedsRestart and UsedBy on the OS
// packages of inv. It needs root: /proc/<pid>/maps of another user's process
// is not readable otherwise, and facts read from only some processes would be
// wrong for the rest.
func ApplyRuntime(inv *inventory.Inventory, scanPath string, verbose bool) error {
	if os.Geteuid() != 0 {
		return errors.New("the in-use and needs-restart facts come from /proc/<pid>/maps, which only root can read for every process: run as root, or pass --runtime=off to leave them out")
	}
	procs, err := readProcesses("/proc", os.Getpid())
	if err != nil {
		return err
	}
	owners := osFileOwners(scanPath, verbose)
	n := applyRuntimeFacts(inv.Packages, owners, procs, kernelRelease())
	if verbose {
		log.Printf("[runtime] %d processes read, %d packages in use", len(procs), n)
	}
	return nil
}

// process is what /proc says about one running process.
type process struct {
	unit    string          // systemd unit, or the command name outside one
	files   []string        // files mapped into it, its executable included
	deleted map[string]bool // those of them replaced on disk since
}

// readProcesses reads every process under procRoot but the caller's own.
// A process that disappears while being read is skipped; being unable to read
// any at all is an error, since the facts would then be silently empty.
func readProcesses(procRoot string, selfPid int) ([]process, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procRoot, err)
	}
	var procs []process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == selfPid {
			continue
		}
		p, ok := readProcess(filepath.Join(procRoot, e.Name()))
		if ok {
			procs = append(procs, p)
		}
	}
	if len(procs) == 0 {
		return nil, fmt.Errorf("no process could be read under %s", procRoot)
	}
	return procs, nil
}

func readProcess(dir string) (process, bool) {
	f, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return process{}, false
	}
	defer f.Close()
	p := process{deleted: map[string]bool{}}
	seen := map[string]bool{}
	add := func(file string) {
		file, deleted := strings.CutSuffix(file, " (deleted)")
		if !strings.HasPrefix(file, "/") {
			return
		}
		if !seen[file] {
			seen[file] = true
			p.files = append(p.files, file)
		}
		if deleted {
			p.deleted[file] = true
		}
	}
	// address perms offset dev inode [path]; the path may hold spaces.
	//
	// Only executable mappings count. A process also maps data files: locale
	// definitions (/usr/lib/locale/C.utf8/LC_CTYPE, locale-archive), the kernel
	// module indexes udevd reads (modules.alias.bin), caches. Their packages
	// (glibc-common, kernel-modules-core) run no code in the process, and taking
	// them for "in use" put the kernel's findings on systemd-udevd. Every program
	// and shared library has its code mapped executable, so nothing is missed.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), " ", 6)
		if len(fields) == 6 && strings.Contains(fields[1], "x") {
			add(strings.TrimSpace(fields[5]))
		}
	}
	if scanner.Err() != nil {
		return process{}, false
	}
	// A static binary maps no library, so its own path is read from exe.
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		add(exe)
	}
	if len(p.files) == 0 {
		// A kernel thread: nothing of a package runs in it.
		return process{}, false
	}
	p.unit = processUnit(dir)
	return p, true
}

// processUnit names the systemd unit a process runs in, from its cgroup path
// ("0::/system.slice/ssh.service" is ssh.service); a process outside a unit
// (a session, a container's entry point) is named by its command.
func processUnit(dir string) string {
	if data, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			// "<id>:<controllers>:<path>"; cgroup v2 has one line, "0::<path>".
			parts := strings.SplitN(line, ":", 3)
			if len(parts) != 3 {
				continue
			}
			for _, elem := range strings.Split(parts[2], "/") {
				if strings.HasSuffix(elem, ".service") {
					return elem
				}
			}
		}
	}
	if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		if c := strings.TrimSpace(string(comm)); c != "" {
			return c
		}
	}
	return path.Base(dir)
}

// applyRuntimeFacts sets the facts on pkgs from the processes read and the
// file ownership of the OS packages; kernel is the running kernel's release
// (uname -r), "" when unknown. Returns how many packages are in use.
func applyRuntimeFacts(pkgs []inventory.Package, owners map[string]string, procs []process, kernel string) int {
	byOwner := map[string][]int{}
	for i, p := range pkgs {
		if osPackageSources[p.Source] {
			k := ownerKey(p.Source, p.Name, p.Version)
			byOwner[k] = append(byOwner[k], i)
		}
	}
	hasCode := map[string]bool{}
	for file, owner := range owners {
		if isCodePath(file) {
			hasCode[owner] = true
		}
	}

	usedBy := map[int]map[string]bool{}
	for _, proc := range procs {
		for _, file := range proc.files {
			owner := fileOwner(owners, file)
			if owner == "" {
				continue
			}
			for _, i := range byOwner[owner] {
				pkgs[i].InUse = inventory.BoolPtr(true)
				if proc.deleted[file] {
					pkgs[i].NeedsRestart = true
				}
				if usedBy[i] == nil {
					usedBy[i] = map[string]bool{}
				}
				usedBy[i][proc.unit] = true
			}
		}
	}
	for i, units := range usedBy {
		list := make([]string, 0, len(units))
		for u := range units {
			list = append(list, u)
		}
		sort.Strings(list)
		pkgs[i].UsedBy = list
	}

	for i, p := range pkgs {
		if !osPackageSources[p.Source] || p.InUse != nil {
			continue
		}
		if hasCode[ownerKey(p.Source, p.Name, p.Version)] {
			pkgs[i].InUse = inventory.BoolPtr(false)
		}
	}

	if kernel != "" {
		for i, p := range pkgs {
			if running, isKernel := kernelPackage(p, kernel); isKernel {
				pkgs[i].InUse = inventory.BoolPtr(running)
			}
		}
	}

	n := 0
	for _, p := range pkgs {
		if p.InUse != nil && *p.InUse {
			n++
		}
	}
	return n
}

// fileOwner looks a mapped file up among the owned ones, on either side of a
// merged /usr: the kernel reports the path it opened, a package list may
// carry the other.
func fileOwner(owners map[string]string, file string) string {
	if o := owners[file]; o != "" {
		return o
	}
	if rest, ok := strings.CutPrefix(file, "/usr"); ok {
		return owners[rest]
	}
	return owners["/usr"+file]
}

// isCodePath says whether a file an OS package owns is an executable or a
// shared library, the kinds of file a process maps. Scripts in bin count too:
// their interpreter maps nothing of theirs, but a running script shows up as
// a process whose exe is the interpreter, so the heuristic errs the other way
// only for libraries written in an interpreted language, which are left
// undetermined by having no such file.
func isCodePath(file string) bool {
	rel, _ := strings.CutPrefix(file, "/usr")
	// Programs: directly in bin or sbin; anywhere under libexec, where helper
	// programs live in per-package directories; systemd's own daemons.
	for _, dir := range []string{"/bin/", "/sbin/"} {
		if rest, ok := strings.CutPrefix(rel, dir); ok && rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	for _, dir := range []string{"/libexec/", "/lib/systemd/"} {
		if rest, ok := strings.CutPrefix(rel, dir); ok && rest != "" && !strings.HasSuffix(rest, "/") {
			return true
		}
	}
	base := path.Base(rel)
	return strings.Contains(base, ".so") && !strings.HasSuffix(base, ".ko")
}

// kernelPackage reports whether p is a kernel package and, if so, whether it is
// the one running: dpkg names it linux-image-<release>, rpm's kernel-core
// (kernel on older releases) carries <version>-<release>.<arch>. Alpine's
// kernel version does not match uname -r by name, and is left undetermined.
func kernelPackage(p inventory.Package, release string) (running, isKernel bool) {
	switch p.Source {
	case "dpkg":
		// The kernel image and its modules are named after the release they
		// belong to: linux-image-6.12.43+deb13-amd64, linux-modules-7.0.0-1014-aws.
		// Longer prefixes first, so linux-modules-extra- is not read as
		// linux-modules- with "extra-..." as the release.
		for _, prefix := range []string{"linux-image-unsigned-", "linux-image-", "linux-modules-extra-", "linux-modules-"} {
			rest, ok := strings.CutPrefix(p.Name, prefix)
			if !ok {
				continue
			}
			if rest == "" || rest[0] < '0' || rest[0] > '9' {
				// linux-image-amd64, linux-modules-extra-aws and the like are metapackages.
				return false, false
			}
			return rest == release, true
		}
		return false, false
	case "rpm":
		// The kernel and its modules come in subpackages of one version,
		// uname -r being <version>-<release>.<arch>.
		switch p.Name {
		case "kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-modules-extra":
			return p.Version+"."+p.Arch == release, true
		}
		return false, false
	}
	return false, false
}

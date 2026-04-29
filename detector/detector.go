package detector

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Finding represents a single local security finding detected without API access.
type Finding struct {
	Type      string // "glassworm" | "dep-confusion"
	Severity  string // "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
	File      string // path to the affected file
	Line      int    // line number (0 = not applicable)
	Package   string // related package name (if applicable)
	Ecosystem string // related ecosystem (if applicable)
	Detail    string // human-readable description
}

// baseDetector holds path skip logic and shared options for all detectors.
type baseDetector struct {
	absSkipPaths    map[string]bool
	prefixSkipPaths []string
	checkRegistry   bool // query npmjs.org to classify unknown scopes
}

func (b *baseDetector) shouldSkipDir(path string) bool {
	if b.absSkipPaths[path] {
		return true
	}
	for _, prefix := range b.prefixSkipPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func buildBaseDetector(scanPath string, isContainer bool, checkRegistry bool) baseDetector {
	abs := map[string]bool{}
	var prefixes []string

	if isContainer {
		// Container rootfs: skip OS system directories that are irrelevant to app code.
		for _, rel := range []string{
			"usr/share", "usr/lib/locale",
			"var/cache", "var/lib/apt", "var/lib/dpkg",
			"proc", "sys", "dev", "boot", "run", "tmp",
		} {
			abs[filepath.Join(scanPath, rel)] = true
		}
		prefixes = []string{
			filepath.Join(scanPath, "usr/lib/python"),
			filepath.Join(scanPath, "usr/lib/node_modules"),
		}
	} else {
		// Host scan: skip OS virtual filesystems, container runtime storage,
		// system library trees, and build source archives.
		// These contain no application source code and would generate enormous noise.
		// Use --image to scan Docker/containerd images properly.
		for _, p := range []string{
			"/proc", "/sys", "/dev", "/boot", "/run", "/tmp",
			"/var/lib/docker",
			"/var/lib/containerd",
			"/var/lib/kubelet",
			"/usr/src", // kernel headers, language source tarballs (e.g. Python-3.x.y/)
		} {
			abs[p] = true
		}
		// Skip system Python installations (stdlib + system-installed packages).
		// Installed third-party packages are also caught by the site-packages/dist-packages
		// skipDirs in the GlassWorm detector; these prefix skips cover the stdlib itself.
		prefixes = []string{
			"/usr/local/lib/python",
			"/usr/lib/python",
		}
	}
	return baseDetector{absSkipPaths: abs, prefixSkipPaths: prefixes, checkRegistry: checkRegistry}
}

// Detector is the interface implemented by each local security check.
type Detector interface {
	Name() string
	Detect(scanPath string, verbose bool, progress *atomic.Int64) ([]Finding, error)
}

// RunAll runs all detectors against scanPath and returns the combined findings.
// Errors from individual detectors are logged as warnings and do not abort the run.
func RunAll(scanPath string, verbose bool, isContainer bool, checkRegistry bool) ([]Finding, error) {
	base := buildBaseDetector(scanPath, isContainer, checkRegistry)
	detectors := []Detector{
		&GlassWormDetector{baseDetector: base},
		&DepConfusionDetector{baseDetector: base},
		&MaliciousInstallDetector{baseDetector: base},
		&CICDPoisoningDetector{baseDetector: base},
		// &HardcodedSecretsDetector{baseDetector: base}, // temporarily disabled
		&LockFileIntegrityDetector{baseDetector: base},
	}

	type result struct {
		findings []Finding
		err      error
	}
	results := make([]result, len(detectors))

	var progress atomic.Int64
	states := make([]atomic.Int32, len(detectors)) // 0=running, 1=done

	stopProgress := make(chan struct{})
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		spinners := []string{"|", "/", "-", "\\"}
		tick := 0
		first := true
		render := func(final bool) {
			var sb strings.Builder
			for i, d := range detectors {
				if i > 0 {
					sb.WriteString("  ")
				}
				if states[i].Load() == 1 {
					sb.WriteString(d.Name() + ":done")
				} else {
					sb.WriteString(d.Name() + ":" + spinners[tick%len(spinners)])
				}
			}
			fileSuffix := "..."
			if final {
				fileSuffix = ""
			}
			if first {
				fmt.Fprintf(os.Stderr, "%s\nScanned: %d files%s", sb.String(), progress.Load(), fileSuffix)
				first = false
			} else {
				fmt.Fprintf(os.Stderr, "\033[1A\033[2K\r%s\n\033[2K\rScanned: %d files%s", sb.String(), progress.Load(), fileSuffix)
			}
			if final {
				fmt.Fprintf(os.Stderr, "\n")
			}
		}
		for {
			select {
			case <-ticker.C:
				render(false)
				tick++
			case <-stopProgress:
				render(true)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i, d := range detectors {
		wg.Add(1)
		go func(idx int, det Detector) {
			defer wg.Done()
			f, err := det.Detect(scanPath, verbose, &progress)
			results[idx] = result{findings: f, err: err}
			states[idx].Store(1)
		}(i, d)
	}
	wg.Wait()
	close(stopProgress)
	progressWg.Wait()

	var all []Finding
	for i, r := range results {
		if r.err != nil {
			log.Printf("Warning: %s detector failed: %v", detectors[i].Name(), r.err)
			continue
		}
		all = append(all, r.findings...)
	}
	return all, nil
}

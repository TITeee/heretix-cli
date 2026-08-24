package detector

import (
	"sync/atomic"
	"testing"
)

// The fixtures under testdata/ are the regression corpus for detector accuracy.
//
//	benign/    real-world-shaped configuration that must produce no findings
//	malicious/ inert reproductions of documented supply chain attacks
//
// Nothing in malicious/ is functional — each file carries only the structural
// signature a detector keys on, never a working payload.

// newTestDetectors builds every active detector with the host-scan skip rules,
// matching what RunAll does outside of container scans.
func newTestDetectors() []Detector {
	base := buildBaseDetector("testdata", false, false)
	return []Detector{
		&GlassWormDetector{baseDetector: base},
		&DepConfusionDetector{baseDetector: base},
		&MaliciousInstallDetector{baseDetector: base},
		&CICDPoisoningDetector{baseDetector: base},
		&LockFileIntegrityDetector{baseDetector: base},
	}
}

func detect(t *testing.T, d Detector, path string) []Finding {
	t.Helper()
	var progress atomic.Int64
	findings, err := d.Detect(path, false, &progress)
	if err != nil {
		t.Fatalf("%s.Detect(%s) returned error: %v", d.Name(), path, err)
	}
	return findings
}

// TestBenignCorpusIsClean is the false-positive guard. Every fixture under
// testdata/benign is ordinary, correct configuration, so nothing there should
// be reported as actionable.
//
// LOW is exempt: it carries hardening advice that is true but not a defect.
// Pinning a third-party action to a tag is the example — tags really can be
// force-pushed (tj-actions/changed-files, CVE-2025-30066), yet the vast
// majority of such pins are fine. Treating that as a failure would push the
// rule out of existence; treating it as MEDIUM would bury real findings. Any
// LOW findings are logged so a new one still shows up in test output.
func TestBenignCorpusIsClean(t *testing.T) {
	for _, d := range newTestDetectors() {
		t.Run(d.Name(), func(t *testing.T) {
			var actionable int
			for _, f := range detect(t, d, "testdata/benign") {
				if f.Severity == "LOW" {
					t.Logf("advisory (allowed): %s:%d %s", f.File, f.Line, f.Detail)
					continue
				}
				actionable++
				t.Errorf("false positive: [%s] %s:%d %s", f.Severity, f.File, f.Line, f.Detail)
			}
			if actionable > 0 {
				t.Errorf("expected no findings above LOW on the benign corpus, got %d", actionable)
			}
		})
	}
}

// TestMaliciousCorpusIsDetected is the coverage guard: each entry names an
// attack the detector is expected to catch, identified by the substring its
// finding detail must contain.
func TestMaliciousCorpusIsDetected(t *testing.T) {
	tests := []struct {
		attack       string // what this reproduces
		detector     string // which detector must catch it
		wantSeverity string
		wantDetail   string // substring the finding's Detail must contain
		wantFile     string // substring the finding's File must contain
	}{
		{
			attack:       "Trojan Source bidirectional override",
			detector:     "glassworm",
			wantSeverity: "CRITICAL",
			wantDetail:   "202E",
			wantFile:     "trojan-source.js",
		},
		{
			attack:       "remote script piped to shell from an install hook",
			detector:     "malicious-install",
			wantSeverity: "CRITICAL",
			wantDetail:   "piped to shell",
			wantFile:     "postinstall",
		},
		{
			attack:       "secret interpolated into a CI shell command",
			detector:     "cicd-poisoning",
			wantSeverity: "HIGH",
			wantDetail:   "secret",
			wantFile:     "injection.yml",
		},
		{
			attack:       "remote script piped to shell in a CI step",
			detector:     "cicd-poisoning",
			wantSeverity: "CRITICAL",
			wantDetail:   "piped to shell",
			wantFile:     "injection.yml",
		},
		{
			attack:       "unmapped private scope resolvable from the public registry",
			detector:     "dep-confusion",
			wantSeverity: "HIGH",
			wantDetail:   "@acme-internal",
			wantFile:     "npm-private",
		},
		{
			attack:       "extra index enabling package substitution",
			detector:     "dep-confusion",
			wantSeverity: "HIGH",
			wantDetail:   "extra-index-url",
			wantFile:     "requirements.txt",
		},
		// Shai-Hulud (ReversingLabs / Datadog Security Labs, 2025): the hook
		// command is just "node bundle.js" — matching the command string alone
		// never sees the payload, so the referenced script has to be followed.
		{
			attack:       "Shai-Hulud: obfuscated bundle executed from install hook",
			detector:     "malicious-install",
			wantSeverity: "HIGH",
			wantDetail:   "bundle.js",
			wantFile:     "shaihulud",
		},
		// Hades campaign (Orca Security, 2026): a .pth file in site-packages
		// executes any line starting with "import" every time Python starts.
		{
			attack:       "Hades: Python .pth startup hook",
			detector:     "malicious-install",
			wantSeverity: "HIGH",
			wantDetail:   ".pth",
			wantFile:     "evil.pth",
		},
		// Nx s1ngularity (Cycode / Wiz, 2025): pull_request_target runs with the
		// base repo's secrets, and this checks out the PR's own code.
		{
			attack:       "pull_request_target checking out PR head",
			detector:     "cicd-poisoning",
			wantSeverity: "CRITICAL",
			wantDetail:   "pull_request_target",
			wantFile:     "prtarget.yml",
		},
		// Self-hosted runners hold cached credentials and internal network
		// access; issue_comment fires for anyone who can comment.
		{
			attack:       "self-hosted runner on an untrusted trigger",
			detector:     "cicd-poisoning",
			wantSeverity: "HIGH",
			wantDetail:   "self-hosted",
			wantFile:     "rogue-runner.yml",
		},
		// RedC2 (TrendAI Security, 2026): no lifecycle hook is declared at all —
		// the payload is a top-level IIFE in the package's entry point, so
		// --ignore-scripts and a hook-only check both miss it. It makes a
		// bundled ELF binary executable, then spawns it detached from Node.
		{
			attack:       "RedC2: entry point spawns a detached child on import",
			detector:     "malicious-install",
			wantSeverity: "CRITICAL",
			wantDetail:   "detached",
			wantFile:     "redc2",
		},
	}

	byName := map[string]Detector{}
	for _, d := range newTestDetectors() {
		byName[d.Name()] = d
	}

	// Detect once per detector, then assert against the collected findings.
	found := map[string][]Finding{}
	for name, d := range byName {
		found[name] = detect(t, d, "testdata/malicious")
	}

	for _, tc := range tests {
		t.Run(tc.attack, func(t *testing.T) {
			for _, f := range found[tc.detector] {
				if containsAll(f.Detail, tc.wantDetail) &&
					containsAll(f.File, tc.wantFile) &&
					f.Severity == tc.wantSeverity {
					return
				}
			}
			t.Errorf("no %s finding matched severity=%s file~=%q detail~=%q; got %d findings: %v",
				tc.detector, tc.wantSeverity, tc.wantFile, tc.wantDetail,
				len(found[tc.detector]), summarize(found[tc.detector]))
		})
	}
}

func containsAll(haystack, needle string) bool {
	return needle == "" || indexOf(haystack, needle) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func summarize(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, "["+f.Severity+"] "+f.File+": "+f.Detail)
	}
	return out
}

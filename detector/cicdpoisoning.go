package detector

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

// CICDPoisoningDetector scans CI/CD configuration files for patterns commonly
// used in pipeline poisoning and supply chain attacks.
type CICDPoisoningDetector struct {
	baseDetector
}

func (d *CICDPoisoningDetector) Name() string { return "cicd-poisoning" }

// ciRule is a line-level rule. runOnly restricts it to lines inside a `run:`
// script block — the only place a CI expression is actually handed to a shell.
// Applying such rules everywhere flags correct configuration: a secret passed
// via `env:` or `with:` is the documented way to use one, not a leak.
type ciRule struct {
	re       *regexp.Regexp
	severity string
	label    string
	runOnly  bool
}

// generalCIRules apply to all CI/CD systems. All of them describe shell
// behaviour, so all are confined to run blocks.
var generalCIRules = []ciRule{
	{regexp.MustCompile(`(?i)(curl|wget)\s+\S+.*\|\s*(ba)?sh\b`), "CRITICAL", "remote code download piped to shell", true},
	{regexp.MustCompile(`(?i)base64\s+(--decode|-d).*\|\s*(ba)?sh\b`), "CRITICAL", "base64-decoded payload piped to shell", true},
	{regexp.MustCompile(`(?i)(curl|wget)\s+https?://`), "HIGH", "outbound network download in CI pipeline", true},
	{regexp.MustCompile(`node\s+-e\s+["']`), "MEDIUM", "inline Node.js execution via node -e", true},
	{regexp.MustCompile(`python[23]?\s+-c\s+["']`), "MEDIUM", "inline Python execution via python -c", true},
}

// githubActionsRules apply only to files under .github/workflows/.
// Action pinning is handled separately by checkUsesPinning, which needs to
// distinguish GitHub-owned actions from third-party ones.
var githubActionsRules = []ciRule{
	{
		regexp.MustCompile(`\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.(body|title|name)\s*\}\}`),
		"CRITICAL",
		"user-controlled GitHub event data interpolated into a run step (script injection risk)",
		true,
	},
	{
		regexp.MustCompile(`\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`),
		"HIGH",
		"GitHub secret interpolated directly into a shell command — pass it via env: instead so it is not exposed to the command line or logs",
		true,
	},
}

// gitlabCIRules apply only to .gitlab-ci.yml.
var gitlabCIRules = []ciRule{
	{
		regexp.MustCompile(`(?i)remote:\s+https?://`),
		"HIGH",
		"remote pipeline configuration included from external URL",
		false,
	},
}

// cicdSkipDirs are excluded from the filesystem walk.
var cicdSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"testdata":     true, // fixtures, never executed — see skipDirs in glassworm.go
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"vendor":       true,
}

func (d *CICDPoisoningDetector) Detect(scanPath string, verbose bool, progress *atomic.Int64) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(scanPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if cicdSkipDirs[entry.Name()] || d.shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		progress.Add(1)

		system := classifyCIFile(path)
		if system == "" {
			return nil
		}

		found, _ := scanCIFile(path, system)
		findings = append(findings, found...)
		return nil
	})

	return findings, err
}

// classifyCIFile returns the CI system name for the given path, or "" if not a CI file.
func classifyCIFile(path string) string {
	name := filepath.Base(path)
	slashed := filepath.ToSlash(path)
	ext := strings.ToLower(filepath.Ext(name))

	switch {
	case (ext == ".yml" || ext == ".yaml") && strings.Contains(slashed, ".github/workflows/"):
		return "github-actions"
	case name == "Jenkinsfile":
		return "jenkins"
	case name == ".gitlab-ci.yml":
		return "gitlab-ci"
	case name == "config.yml" && strings.Contains(slashed, ".circleci/"):
		return "circleci"
	case name == "azure-pipelines.yml" || name == "azure-pipelines.yaml":
		return "azure-pipelines"
	case name == "bitbucket-pipelines.yml":
		return "bitbucket-pipelines"
	default:
		return ""
	}
}

func rulesForSystem(system string) []ciRule {
	rules := make([]ciRule, len(generalCIRules))
	copy(rules, generalCIRules)
	switch system {
	case "github-actions":
		rules = append(rules, githubActionsRules...)
	case "gitlab-ci":
		rules = append(rules, gitlabCIRules...)
	}
	return rules
}

// runKeyRe matches the `run:` key that opens a shell script block.
var runKeyRe = regexp.MustCompile(`^\s*-?\s*run:`)

// runBlockTracker follows YAML indentation to tell whether the current line is
// part of a `run:` script block. This is a deliberately small approximation of
// a YAML parser: it only needs to answer "is this line shell script?", which
// indentation alone determines for the block-scalar form CI configs use.
type runBlockTracker struct {
	active    bool
	keyIndent int
}

// observe advances the tracker by one line and reports whether that line is
// shell script (either the `run:` line itself or a line within its block).
func (t *runBlockTracker) observe(line string) bool {
	if strings.TrimSpace(line) == "" {
		return t.active // blank lines do not terminate a block scalar
	}

	indent := len(line) - len(strings.TrimLeft(line, " \t"))
	if t.active && indent <= t.keyIndent {
		t.active = false
	}

	if runKeyRe.MatchString(line) {
		t.active = true
		t.keyIndent = strings.Index(line, "run:")
		return true // covers the inline form: `run: curl x | sh`
	}
	return t.active
}

func scanCIFile(path, system string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	var findings []Finding
	if system == "github-actions" {
		findings = append(findings, checkWorkflowTriggers(path, lines)...)
	}

	rules := rulesForSystem(system)
	var tracker runBlockTracker

	for i, line := range lines {
		inRun := tracker.observe(line)

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if system == "github-actions" {
			if f, ok := checkUsesPinning(path, i+1, line); ok {
				findings = append(findings, f)
			}
		}

		for _, rule := range rules {
			if rule.runOnly && !inRun {
				continue
			}
			if rule.re.MatchString(line) {
				findings = append(findings, Finding{
					Type:     "cicd-poisoning",
					Severity: rule.severity,
					File:     path,
					Line:     i + 1,
					Detail:   "[" + system + "] " + rule.label + " — " + truncateStr(trimmed, 80),
				})
				break
			}
		}
	}
	return findings, nil
}

// ── Action pinning ───────────────────────────────────────────────────────────

var (
	usesRefRe = regexp.MustCompile(`(?i)uses:\s*["']?([A-Za-z0-9_.-]+)/([A-Za-z0-9_./-]+)@([^\s"']+)`)
	// mutableBranchRefs are refs whose contents can change under the same name.
	mutableBranchRefs = map[string]bool{
		"main": true, "master": true, "HEAD": true, "latest": true, "develop": true,
	}
	semverTagRe = regexp.MustCompile(`^v\d`)
	// githubOwnedOwners publish the actions GitHub's own documentation tells you
	// to pin by major tag, so flagging those tags is advice against the vendor's.
	githubOwnedOwners = map[string]bool{"actions": true, "github": true}
)

// checkUsesPinning evaluates a `uses:` line for supply chain exposure.
//
// A mutable branch ref is reported regardless of owner: the ref can be
// repointed at any commit. A semver tag is only reported for third-party
// actions, and only at LOW — tags are the norm GitHub itself recommends, so
// reporting every one of them buries real findings under advice nobody acts on.
func checkUsesPinning(path string, line int, raw string) (Finding, bool) {
	m := usesRefRe.FindStringSubmatch(raw)
	if m == nil {
		return Finding{}, false
	}
	owner, name, ref := m[1], m[2], m[3]
	action := owner + "/" + name

	switch {
	case mutableBranchRefs[ref]:
		return Finding{
			Type:     "cicd-poisoning",
			Severity: "HIGH",
			File:     path,
			Line:     line,
			Detail: "[github-actions] action " + action + " pinned to mutable ref @" + ref +
				" — the ref can be repointed at any commit; pin to a full commit SHA",
		}, true

	case semverTagRe.MatchString(ref) && !githubOwnedOwners[owner]:
		return Finding{
			Type:     "cicd-poisoning",
			Severity: "LOW",
			File:     path,
			Line:     line,
			Detail: "[github-actions] third-party action " + action + " pinned to tag @" + ref +
				" — a tag can be force-pushed; a full commit SHA is immutable",
		}, true
	}
	return Finding{}, false
}

// ── Workflow-level trigger analysis ──────────────────────────────────────────

var (
	// prHeadRefRe matches the pull request's own head, i.e. attacker-controlled code.
	prHeadRefRe = regexp.MustCompile(`\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref)\s*\}\}`)
	// untrustedTriggers fire for anyone who can open a PR or comment, yet run
	// in the base repository's context with its secrets.
	untrustedTriggers = []string{"pull_request_target", "issue_comment"}
	selfHostedRe      = regexp.MustCompile(`(?i)runs-on:\s*\[?\s*["']?self-hosted`)
)

// checkWorkflowTriggers reports risks that only exist as a combination of
// workflow-level facts, which a per-line rule cannot express.
func checkWorkflowTriggers(path string, lines []string) []Finding {
	var findings []Finding

	triggers := map[string]bool{}
	checkoutPRHeadLine := 0
	selfHostedLine := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, tr := range untrustedTriggers {
			if strings.Contains(line, tr) {
				triggers[tr] = true
			}
		}
		// A `ref:` naming the PR head is what turns pull_request_target's
		// privileges into arbitrary code execution.
		if strings.Contains(trimmed, "ref:") && prHeadRefRe.MatchString(line) && checkoutPRHeadLine == 0 {
			checkoutPRHeadLine = i + 1
		}
		if selfHostedRe.MatchString(line) && selfHostedLine == 0 {
			selfHostedLine = i + 1
		}
	}

	// pull_request_target grants the base repo's secrets and a privileged token;
	// checking out the PR's own code then executes an outsider's changes with them.
	if triggers["pull_request_target"] && checkoutPRHeadLine > 0 {
		findings = append(findings, Finding{
			Type:     "cicd-poisoning",
			Severity: "CRITICAL",
			File:     path,
			Line:     checkoutPRHeadLine,
			Detail: "[github-actions] pull_request_target workflow checks out the pull request's own head — " +
				"anyone who opens a PR gets code execution with the base repository's secrets",
		})
	}

	// Self-hosted runners hold cached credentials and internal network reach.
	// On its own that is normal; reachable from an untrusted trigger it is not.
	if selfHostedLine > 0 {
		for _, tr := range untrustedTriggers {
			if !triggers[tr] {
				continue
			}
			findings = append(findings, Finding{
				Type:     "cicd-poisoning",
				Severity: "HIGH",
				File:     path,
				Line:     selfHostedLine,
				Detail: "[github-actions] self-hosted runner reachable from the untrusted trigger " + tr +
					" — untrusted input can reach a runner holding internal network access and cached credentials",
			})
			break
		}
	}

	return findings
}

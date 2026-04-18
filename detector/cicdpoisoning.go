package detector

import (
	"bufio"
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

// generalCIRules apply to all CI/CD systems.
var generalCIRules = []scriptRule{
	{regexp.MustCompile(`(?i)(curl|wget)\s+\S+.*\|\s*(ba)?sh\b`), "CRITICAL", "remote code download piped to shell"},
	{regexp.MustCompile(`(?i)base64\s+(--decode|-d).*\|\s*(ba)?sh\b`), "CRITICAL", "base64-decoded payload piped to shell"},
	{regexp.MustCompile(`(?i)(curl|wget)\s+https?://`), "HIGH", "outbound network download in CI pipeline"},
	{regexp.MustCompile(`node\s+-e\s+["']`), "MEDIUM", "inline Node.js execution via node -e"},
	{regexp.MustCompile(`python[23]?\s+-c\s+["']`), "MEDIUM", "inline Python execution via python -c"},
}

// githubActionsRules apply only to files under .github/workflows/.
var githubActionsRules = []scriptRule{
	// Script injection: user-controlled event data interpolated into a run: step
	{
		regexp.MustCompile(`\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.(body|title|name)\s*\}\}`),
		"CRITICAL",
		"user-controlled GitHub event data interpolated into step (script injection risk)",
	},
	// Secret value echoed directly to CI log
	{
		regexp.MustCompile(`\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`),
		"HIGH",
		"GitHub secret interpolated directly in step — may leak to public logs",
	},
	// Action pinned to mutable branch ref
	{
		regexp.MustCompile(`(?i)uses:\s+\S+@(main|master|HEAD|latest|develop)\s*$`),
		"HIGH",
		"action pinned to mutable branch ref — use full commit SHA to prevent supply chain attack",
	},
	// Action pinned to semver tag (still mutable if maintainer force-pushes)
	{
		regexp.MustCompile(`uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@v\d`),
		"MEDIUM",
		"action pinned to semver tag instead of immutable full commit SHA",
	},
}

// gitlabCIRules apply only to .gitlab-ci.yml.
var gitlabCIRules = []scriptRule{
	{
		regexp.MustCompile(`(?i)remote:\s+https?://`),
		"HIGH",
		"remote pipeline configuration included from external URL",
	},
}

// cicdSkipDirs are excluded from the filesystem walk.
var cicdSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
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

func rulesForSystem(system string) []scriptRule {
	rules := make([]scriptRule, len(generalCIRules))
	copy(rules, generalCIRules)
	switch system {
	case "github-actions":
		rules = append(rules, githubActionsRules...)
	case "gitlab-ci":
		rules = append(rules, gitlabCIRules...)
	}
	return rules
}

func scanCIFile(path, system string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rules := rulesForSystem(system)

	var findings []Finding
	lineNum := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, rule := range rules {
			if rule.re.MatchString(line) {
				findings = append(findings, Finding{
					Type:     "cicd-poisoning",
					Severity: rule.severity,
					File:     path,
					Line:     lineNum,
					Detail:   "[" + system + "] " + rule.label + " — " + truncateStr(trimmed, 80),
				})
				break
			}
		}
	}
	return findings, scanner.Err()
}

package detector

import (
	"bufio"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

// HardcodedSecretsDetector scans source and config files for hardcoded secrets
// using both known-format patterns and Shannon entropy analysis.
type HardcodedSecretsDetector struct {
	baseDetector
}

func (d *HardcodedSecretsDetector) Name() string { return "hardcoded-secrets" }

// knownSecretPattern matches a specific well-known secret format.
type knownSecretPattern struct {
	name       string
	re         *regexp.Regexp
	severity   string
	valueGroup int // capture group index for the actual secret value; 0 = whole match
}

// entropyPattern matches an assignment context and checks the captured value's entropy.
type entropyPattern struct {
	name       string
	re         *regexp.Regexp // group 1 must capture the value
	severity   string
	minEntropy float64
}

var knownSecretPatterns = []knownSecretPattern{
	{"AWS Access Key ID", regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`), "CRITICAL", 1},
	{"GitHub Personal Access Token", regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{36})\b`), "CRITICAL", 1},
	{"GitHub Actions/App Token", regexp.MustCompile(`\b(gh[soa]_[A-Za-z0-9]{36})\b`), "CRITICAL", 1},
	{"GitHub Fine-Grained PAT", regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{82})\b`), "CRITICAL", 1},
	{"npm Access Token", regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), "CRITICAL", 1},
	{"Slack Token", regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z]{10,48})\b`), "CRITICAL", 1},
	{"Stripe Live Secret Key", regexp.MustCompile(`\b(sk_live_[A-Za-z0-9]{24,})\b`), "CRITICAL", 1},
	{"Stripe Test Secret Key", regexp.MustCompile(`\b(sk_test_[A-Za-z0-9]{24,})\b`), "MEDIUM", 1},
	{"SendGrid API Key", regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`), "CRITICAL", 1},
	{"Google API Key", regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`), "CRITICAL", 1},
	{"Google OAuth Client Secret", regexp.MustCompile(`\b(GOCSPX-[A-Za-z0-9_-]{28})\b`), "CRITICAL", 1},
	{"PEM Private Key Header", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "CRITICAL", 0},
	{"JSON Web Token", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`), "HIGH", 1},
}

// entropyPatterns look for assignment context and validate by entropy.
// Pure-hex values (commit hashes, checksums) are excluded to avoid false positives.
var secretEntropyPatterns = []entropyPattern{
	{"API Key", regexp.MustCompile(`(?i)\bapi[_-]?key\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`), "HIGH", 4.5},
	{"Access Token", regexp.MustCompile(`(?i)\baccess[_-]?token\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`), "HIGH", 4.5},
	{"Auth Token", regexp.MustCompile(`(?i)\bauth[_-]?token\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`), "HIGH", 4.5},
	{"Secret Key", regexp.MustCompile(`(?i)\bsecret[_-]?key\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`), "HIGH", 4.5},
	{"Private Key", regexp.MustCompile(`(?i)\bprivate[_-]?key\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`), "HIGH", 4.5},
}

// secretSkipDirs are excluded from the filesystem walk.
var secretSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"vendor":       true,
	".tox":         true,
	"target":       true,
	".next":        true,
	".nuxt":        true,
}

// secretTargetExtensions are the file types scanned for secrets.
var secretTargetExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".rb": true,
	".php": true, ".java": true, ".cs": true, ".sh": true, ".bash": true,
	".env": true, ".yaml": true, ".yml": true, ".toml": true,
	".json": true, ".xml": true, ".ini": true, ".cfg": true, ".conf": true,
	".properties": true, ".tf": true,
}

// placeholderREs match values that are clearly placeholder/example text, not real secrets.
var placeholderREs = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^your[_-]`),
	regexp.MustCompile(`(?i)[_-]here$`),
	regexp.MustCompile(`^[<{].*[>}]$`),
	regexp.MustCompile(`(?i)^(example|sample|test|fake|mock|dummy|placeholder|changeme|fixme|todo|xxxx+|1234+|abcd+)$`),
	regexp.MustCompile(`(?i)\${?[A-Z_]+}?`), // environment variable reference like $MY_SECRET or ${MY_SECRET}
}

var hexOnlyRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func (d *HardcodedSecretsDetector) Detect(scanPath string, verbose bool, progress *atomic.Int64) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(scanPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if secretSkipDirs[entry.Name()] || d.shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		progress.Add(1)

		name := entry.Name()
		if isExampleOrTestFile(name) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(name))
		// .env files have no extension match via Ext; handle them by name prefix
		if !secretTargetExtensions[ext] && !strings.HasPrefix(name, ".env") {
			return nil
		}

		found, _ := scanForSecrets(path)
		findings = append(findings, found...)
		return nil
	})

	return findings, err
}

func scanForSecrets(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	lineNum := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if isCommentLine(trimmed) {
			continue
		}

		// Known-format patterns: match and report immediately.
		for _, p := range knownSecretPatterns {
			m := p.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			val := m[0]
			if p.valueGroup > 0 && p.valueGroup < len(m) {
				val = m[p.valueGroup]
			}
			if isPlaceholderValue(val) {
				continue
			}
			findings = append(findings, Finding{
				Type:     "hardcoded-secrets",
				Severity: p.severity,
				File:     path,
				Line:     lineNum,
				Detail:   p.name + " detected — " + redact(val),
			})
		}

		// Entropy-based patterns: match assignment context, then validate entropy.
		for _, p := range secretEntropyPatterns {
			m := p.re.FindStringSubmatch(line)
			if m == nil || len(m) < 2 {
				continue
			}
			val := m[1]
			if isPlaceholderValue(val) {
				continue
			}
			// Skip pure-hex values (commit hashes, checksums, etc.)
			if hexOnlyRE.MatchString(val) {
				continue
			}
			if shannonEntropy(val) >= p.minEntropy {
				findings = append(findings, Finding{
					Type:     "hardcoded-secrets",
					Severity: p.severity,
					File:     path,
					Line:     lineNum,
					Detail:   p.name + " assignment with high-entropy value — " + redact(val),
				})
			}
		}
	}
	return findings, scanner.Err()
}

// shannonEntropy calculates the Shannon entropy (bits/char) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	return h
}

// isPlaceholderValue returns true when the value looks like a placeholder, not a real secret.
func isPlaceholderValue(val string) bool {
	if len(val) == 0 {
		return true
	}
	lower := strings.ToLower(val)
	static := []string{
		"", "null", "none", "false", "true", "undefined",
		"changeme", "placeholder", "example", "sample", "fake",
		"mock", "dummy", "test", "todo", "fixme",
	}
	for _, s := range static {
		if lower == s {
			return true
		}
	}
	for _, re := range placeholderREs {
		if re.MatchString(val) {
			return true
		}
	}
	// All same character (e.g. aaaaaaa, xxxxxxxx)
	if len(val) > 3 {
		allSame := true
		for i := 1; i < len(val); i++ {
			if val[i] != val[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// isExampleOrTestFile returns true for files that typically contain non-real secrets.
func isExampleOrTestFile(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".tpl"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return strings.HasSuffix(lower, "_test.go") ||
		strings.HasSuffix(lower, ".test.js") ||
		strings.HasSuffix(lower, ".test.ts") ||
		strings.HasSuffix(lower, ".spec.js") ||
		strings.HasSuffix(lower, ".spec.ts") ||
		strings.HasPrefix(lower, "test_")
}

// isCommentLine returns true if the trimmed line is a code comment.
func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "--") ||
		strings.HasPrefix(trimmed, "*")
}

// redact returns the first 6 characters of a secret followed by "***" to avoid
// printing live credentials in finding output.
func redact(val string) string {
	if len(val) <= 6 {
		return "***"
	}
	return val[:6] + "***"
}

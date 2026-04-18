package detector

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

// MaliciousInstallDetector scans npm lifecycle scripts and Python setup.py
// for patterns commonly used in supply chain / install-time attacks.
type MaliciousInstallDetector struct {
	baseDetector
}

func (d *MaliciousInstallDetector) Name() string { return "malicious-install" }

type scriptRule struct {
	re       *regexp.Regexp
	severity string
	label    string
}

// npmLifecycleRules are matched against the command string of each lifecycle hook.
var npmLifecycleRules = []scriptRule{
	// CRITICAL — direct remote code execution
	{regexp.MustCompile(`(?i)(curl|wget)\s+\S+.*\|\s*(ba)?sh\b`), "CRITICAL", "remote code download piped to shell"},
	{regexp.MustCompile(`(?i)base64\s+(--decode|-d).*\|\s*(ba)?sh\b`), "CRITICAL", "base64-decoded payload piped to shell"},
	{regexp.MustCompile(`(?i)\beval\s*\(\s*(await\s+)?fetch\b`), "CRITICAL", "eval() of network-fetched content"},
	// HIGH — strong indicators of malicious behaviour
	{regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`), "HIGH", "child_process module loaded in install hook"},
	{regexp.MustCompile(`(?i)(curl|wget)\s+https?://`), "HIGH", "outbound network request in install hook"},
	{regexp.MustCompile(`node\s+-e\s+["']`), "HIGH", "inline Node.js execution via node -e"},
	// MEDIUM — suspicious but context-dependent
	{regexp.MustCompile(`Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)`), "MEDIUM", "base64 decoding in install hook"},
	{regexp.MustCompile(`(?i)\bfetch\s*\(\s*['"]https?://`), "MEDIUM", "outbound fetch() in install hook"},
}

// setupPyRules are matched line-by-line against setup.py.
var setupPyRules = []scriptRule{
	{regexp.MustCompile(`(?i)\beval\s*\(`), "CRITICAL", "eval() in setup.py"},
	{regexp.MustCompile(`(?i)os\.system\s*\(`), "HIGH", "os.system() in setup.py"},
	{regexp.MustCompile(`(?i)subprocess\.(call|run|Popen|check_output|check_call)\s*\(`), "HIGH", "subprocess execution in setup.py"},
	{regexp.MustCompile(`(?i)\bexec\s*\(\s*compile\s*\(`), "HIGH", "exec(compile(...)) obfuscation in setup.py"},
	{regexp.MustCompile(`(?i)(urllib\.request\.|urllib2\.|requests\.)(get|urlopen|post)\s*\(`), "MEDIUM", "outbound network request in setup.py"},
}

// lifecycleHooks are the npm script names that execute automatically during install.
var lifecycleHooks = map[string]bool{
	"preinstall":     true,
	"install":        true,
	"postinstall":    true,
	"prepare":        true,
	"prepublish":     true,
	"prepublishOnly": true,
	"prepack":        true,
	"postpack":       true,
}

// skipMaliciousInstallDirs are directories to skip during the walk.
// node_modules is intentionally NOT skipped — installed packages are the primary attack surface.
var skipMaliciousInstallDirs = map[string]bool{
	".git":        true,
	".venv":       true,
	"venv":        true,
	"__pycache__": true,
	".tox":        true,
	"vendor":      true,
}

func (d *MaliciousInstallDetector) Detect(scanPath string, verbose bool, progress *atomic.Int64) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(scanPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if skipMaliciousInstallDirs[entry.Name()] || d.shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		progress.Add(1)
		switch entry.Name() {
		case "package.json":
			found, _ := checkInstallScripts(path)
			findings = append(findings, found...)
		case "setup.py":
			found, _ := checkSetupPy(path)
			findings = append(findings, found...)
		}
		return nil
	})

	return findings, err
}

type pkgJSON struct {
	Name    string            `json:"name"`
	Scripts map[string]string `json:"scripts"`
}

func checkInstallScripts(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg pkgJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var findings []Finding
	for hook, cmd := range pkg.Scripts {
		if !lifecycleHooks[hook] {
			continue
		}
		for _, rule := range npmLifecycleRules {
			if rule.re.MatchString(cmd) {
				findings = append(findings, Finding{
					Type:      "malicious-install",
					Severity:  rule.severity,
					File:      path,
					Package:   pkg.Name,
					Ecosystem: "npm",
					Detail:    hook + ": " + rule.label + " — " + truncateStr(cmd, 80),
				})
			}
		}
	}
	return findings, nil
}

func checkSetupPy(path string) ([]Finding, error) {
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
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, rule := range setupPyRules {
			if rule.re.MatchString(line) {
				findings = append(findings, Finding{
					Type:      "malicious-install",
					Severity:  rule.severity,
					File:      path,
					Line:      lineNum,
					Ecosystem: "pypi",
					Detail:    rule.label + " — " + truncateStr(trimmed, 80),
				})
				break // one finding per line is enough
			}
		}
	}
	return findings, scanner.Err()
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

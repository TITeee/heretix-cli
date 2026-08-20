package detector

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// npmLifecycleRules are matched against the command string of each lifecycle
// hook, and against the contents of any local script that hook runs.
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

// setupPyExecRules cover code execution in setup.py.
//
// Shelling out during a build is ordinary packaging practice — compiling a C
// extension, or reading a version from git — so os.system and subprocess are
// only advisory on their own; reporting every such package as actionable would
// flag a large share of PyPI. They are raised to HIGH when the same file also
// reaches the network (see checkSetupPy), which is the shape of a staged
// payload rather than a build step. eval and exec(compile(...)) have no such
// benign explanation and stay actionable regardless.
var setupPyExecRules = []scriptRule{
	{regexp.MustCompile(`(?i)\beval\s*\(`), "CRITICAL", "eval() in setup.py"},
	{regexp.MustCompile(`(?i)\bexec\s*\(\s*compile\s*\(`), "HIGH", "exec(compile(...)) obfuscation in setup.py"},
	{regexp.MustCompile(`(?i)os\.system\s*\(`), "LOW", "os.system() in setup.py"},
	{regexp.MustCompile(`(?i)subprocess\.(call|run|Popen|check_output|check_call)\s*\(`), "LOW", "subprocess execution in setup.py"},
}

// setupPyNetworkRe marks a setup.py that reaches the network at build time.
// Combined with code execution this is the shape of a staged install-time
// payload rather than an ordinary build step.
var setupPyNetworkRe = regexp.MustCompile(`(?i)(urllib\.request\.|urllib2\.|requests\.)(get|urlopen|post)\s*\(`)

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
	"testdata":    true, // fixtures, never executed — see skipDirs in glassworm.go
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

		switch {
		case entry.Name() == "package.json":
			found, _ := checkInstallScripts(path)
			findings = append(findings, found...)
		case entry.Name() == "setup.py":
			found, _ := checkSetupPy(path)
			findings = append(findings, found...)
		case strings.EqualFold(filepath.Ext(entry.Name()), ".pth"):
			found, _ := checkPthFile(path)
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
		// The command itself is often unremarkable — Shai-Hulud's hook is just
		// "node bundle.js" — so follow it to whatever local file it runs.
		findings = append(findings, checkHookScript(path, pkg.Name, hook, cmd)...)
	}
	return findings, nil
}

// ── Install hook script following ────────────────────────────────────────────

// hookScriptRe extracts the local script an install hook hands to an interpreter.
// Only relative paths are considered: an absolute path or a bare command name
// refers to something outside the package, which is not ours to read.
var hookScriptRe = regexp.MustCompile(`(?:^|[;&|]\s*)(?:node|nodejs|python[23]?|sh|bash)\s+(?:\./)?([A-Za-z0-9_./-]+\.(?:js|cjs|mjs|py|sh))\b`)

const (
	// minifiedLineThreshold is the line length past which a file is machine-
	// generated rather than written by hand. Bundlers emit whole modules on a
	// single line; install scripts people write do not come close.
	minifiedLineThreshold = 5000
	// maxHookScriptSize caps how much of a followed script is read.
	maxHookScriptSize = 8 << 20 // 8 MiB
)

// checkHookScript follows a lifecycle hook to the local script it executes and
// applies the same rules to that file's contents.
//
// This closes the gap the Shai-Hulud worm ran through: its hook command is a
// plain "node bundle.js", so a detector matching only the command string sees
// nothing, while the payload sits in the referenced bundle.
func checkHookScript(pkgPath, pkgName, hook, cmd string) []Finding {
	m := hookScriptRe.FindStringSubmatch(cmd)
	if m == nil {
		return nil
	}
	rel := m[1]
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return nil
	}

	scriptPath := filepath.Join(filepath.Dir(pkgPath), filepath.FromSlash(rel))
	info, err := os.Stat(scriptPath)
	if err != nil || info.IsDir() || info.Size() > maxHookScriptSize {
		return nil
	}
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil
	}
	content := string(data)

	var findings []Finding
	for _, rule := range npmLifecycleRules {
		if rule.re.MatchString(content) {
			findings = append(findings, Finding{
				Type:      "malicious-install",
				Severity:  followedScriptSeverity(rule.severity),
				File:      scriptPath,
				Package:   pkgName,
				Ecosystem: "npm",
				Detail:    hook + " runs " + rel + ": " + rule.label,
			})
		}
	}

	// Obfuscation is what actually separates an attack from a package that
	// merely does work at install time. Measured against real code: esbuild's
	// install.js downloads and executes a native binary — the same operations
	// an attacker performs — but its longest line is 125 characters, so it can
	// be read and audited. Shai-Hulud's bundle.js runs to a single line of
	// several thousand. There is no benign reason for an install hook to
	// execute code nobody can read, so this is reported on its own even when no
	// content rule matched — obfuscation exists precisely to defeat those.
	if longest := longestLineLen(content); longest >= minifiedLineThreshold {
		findings = append(findings, Finding{
			Type:      "malicious-install",
			Severity:  "HIGH",
			File:      scriptPath,
			Package:   pkgName,
			Ecosystem: "npm",
			Detail: hook + " runs " + rel + ": minified/obfuscated bundle executed at install time (longest line " +
				strconv.Itoa(longest) + " chars) — install hooks should run readable code",
		})
	}
	return findings
}

// followedScriptSeverity adjusts a rule's severity for a match inside a script
// the hook runs, rather than in the hook command itself.
//
// Fetching and executing during install is how native-binary packages —
// esbuild, sharp, playwright and many more — legitimately work, so on its own
// it is worth surfacing but is not an incident; at HIGH it would fire on a
// large share of every node_modules and train people to ignore the detector.
// CRITICAL rules are left alone: piping a download into a shell has no such
// benign reading wherever it appears.
func followedScriptSeverity(ruleSeverity string) string {
	if ruleSeverity == "HIGH" {
		return "MEDIUM"
	}
	return ruleSeverity
}

func longestLineLen(s string) int {
	longest, cur := 0, 0
	for _, r := range s {
		if r == '\n' {
			if cur > longest {
				longest = cur
			}
			cur = 0
			continue
		}
		cur++
	}
	if cur > longest {
		longest = cur
	}
	return longest
}

// ── Python ───────────────────────────────────────────────────────────────────

func checkSetupPy(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Network access anywhere in the file changes how its exec calls read: a
	// build step that shells out is routine, one that also downloads is staged.
	fetchesNetwork := setupPyNetworkRe.Match(data)

	var findings []Finding
	lineNum := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if setupPyNetworkRe.MatchString(line) {
			findings = append(findings, Finding{
				Type:      "malicious-install",
				Severity:  "MEDIUM",
				File:      path,
				Line:      lineNum,
				Ecosystem: "pypi",
				Detail:    "outbound network request in setup.py — " + truncateStr(trimmed, 80),
			})
			continue
		}

		for _, rule := range setupPyExecRules {
			if !rule.re.MatchString(line) {
				continue
			}
			severity := rule.severity
			label := rule.label
			if fetchesNetwork && severity == "LOW" {
				severity = "HIGH"
				label += " combined with a network fetch elsewhere in the file"
			}
			findings = append(findings, Finding{
				Type:      "malicious-install",
				Severity:  severity,
				File:      path,
				Line:      lineNum,
				Ecosystem: "pypi",
				Detail:    label + " — " + truncateStr(trimmed, 80),
			})
			break // one finding per line is enough
		}
	}
	return findings, scanner.Err()
}

// checkPthFile reports .pth files that execute code.
//
// Python runs any line in a .pth starting with "import" every time the
// interpreter starts, with no import of the package required. Legitimate .pth
// files contain only paths, so this distinction is exact rather than heuristic.
// Used by the 2026 Hades campaign to gain persistence from a wheel install.
func checkPthFile(path string) ([]Finding, error) {
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
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "import ") && !strings.HasPrefix(line, "import\t") {
			continue
		}
		findings = append(findings, Finding{
			Type:      "malicious-install",
			Severity:  "HIGH",
			File:      path,
			Line:      lineNum,
			Ecosystem: "pypi",
			Detail: "executable .pth entry — Python runs this on every interpreter start, " +
				"without the package being imported: " + truncateStr(line, 80),
		})
	}
	return findings, scanner.Err()
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

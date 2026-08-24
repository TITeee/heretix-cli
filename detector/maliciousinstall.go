package detector

import (
	"bufio"
	"bytes"
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
	Main    string            `json:"main"`
	Module  string            `json:"module"`
	Exports json.RawMessage   `json:"exports"`
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

	// A lifecycle hook is not the only way code runs during install: RedC2
	// (2026) used no hook at all — the payload was a top-level IIFE in the
	// package's entry point, which runs on the first `import`/`require`
	// anywhere in the dependency graph. --ignore-scripts gives no protection
	// against this, since no script is ever declared.
	if entry := resolveEntrypoint(pkg); entry != "" {
		findings = append(findings, checkEntrypointScript(path, pkg.Name, entry)...)
	}

	return findings, nil
}

// resolveEntrypoint returns the package's main module, relative to the
// package.json that declares it — the file that runs on import/require.
//
// Only the simple, single-target forms are resolved (a bare "main"/"module"
// string, or "exports"."."'s "import"/"default" string). Multi-target or
// conditional exports maps exist to select between platforms or environments,
// not to hide code, so resolving every branch would add walk cost without
// adding coverage against the attack this defends against.
func resolveEntrypoint(pkg pkgJSON) string {
	if pkg.Main != "" {
		return pkg.Main
	}
	if pkg.Module != "" {
		return pkg.Module
	}
	if len(pkg.Exports) == 0 {
		return ""
	}

	var asString string
	if json.Unmarshal(pkg.Exports, &asString) == nil {
		return asString
	}

	var asObject map[string]json.RawMessage
	if json.Unmarshal(pkg.Exports, &asObject) != nil {
		return ""
	}
	target, ok := asObject["."]
	if !ok {
		return ""
	}
	if json.Unmarshal(target, &asString) == nil {
		return asString
	}
	var nested map[string]string
	if json.Unmarshal(target, &nested) == nil {
		if v, ok := nested["import"]; ok {
			return v
		}
		if v, ok := nested["default"]; ok {
			return v
		}
	}
	return ""
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

// ── Entry-point scanning (no lifecycle hook involved) ────────────────────────

// spawnCallRe matches a child_process call by method name, independent of
// which identifier the module was imported as (cp.spawn, child_process.exec, a
// destructured `spawn(...)`, etc.).
var spawnCallRe = regexp.MustCompile(`\.(spawn|exec|execFile|fork)\s*\(|(?:^|[^.\w])(?:spawn|execFile)\s*\(`)

// detachedTrueRe matches the child_process option that keeps a process running
// after its parent exits.
var detachedTrueRe = regexp.MustCompile(`detached\s*:\s*true`)

// entrypointBinaryRe extracts a local file path passed as a spawn/exec target,
// to check whether it is an ELF binary regardless of its extension. Mirrors
// spawnCallRe's two call shapes (property access and a destructured import).
// Go's RE2 engine has no backreferences, so the opening and closing quote are
// matched independently rather than required to be the same character — in
// practice a path string never contains a different quote character anyway.
var entrypointBinaryRe = regexp.MustCompile(`(?:\.(?:spawn|exec|execFile)|(?:^|[^.\w])(?:spawn|execFile))\s*\(\s*['"` + "`" + `]((?:\.\/|\.\.\/)?[A-Za-z0-9_./-]+)['"` + "`" + `]`)

// checkEntrypointScript scans a package's entry point — the file that runs on
// import/require, resolved by resolveEntrypoint — for the one pattern that
// distinguishes an install-time attack here: a detached spawn.
//
// This is where RedC2 was caught: its package declared no install/postinstall
// script at all, so --ignore-scripts and any hook-only check missed it. The
// payload ran because the entry point itself spawned a bundled ELF binary,
// detached from the Node process, from a top-level IIFE evaluated at import.
//
// Deliberately narrower than checkHookScript. An install *hook* is a small
// script with no reason to look like the rest of the package, so minification
// or a stray child_process call there is already unusual. An entry point is
// the opposite: it *is* the rest of the package. Measured against a real repo,
// applying checkHookScript's obfuscation check and npmLifecycleRules here
// flagged the ordinary minified dist/index.cjs bundlers produce, and packages
// that use child_process/base64 as part of normal functionality — 38 findings
// on one small project, nearly all noise. The one thing left is not: a
// detached spawn is not something a bundler produces or a normal dependency
// needs, on any build.
func checkEntrypointScript(pkgPath, pkgName, entrypointRel string) []Finding {
	if filepath.IsAbs(entrypointRel) || strings.Contains(entrypointRel, "..") {
		return nil
	}
	scriptPath := filepath.Join(filepath.Dir(pkgPath), filepath.FromSlash(entrypointRel))
	info, err := os.Stat(scriptPath)
	if err != nil || info.IsDir() || info.Size() > maxHookScriptSize {
		return nil
	}
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil
	}
	content := string(data)

	if !spawnCallRe.MatchString(content) || !detachedTrueRe.MatchString(content) {
		return nil
	}

	detail := "entry point " + entrypointRel + " spawns a child process detached from Node — " +
		"it keeps running after the process exits, which a build-time helper has no reason to do"
	if rel, format := findSpawnedBinary(scriptPath, content); format != "" {
		detail += " (spawned target " + rel + " is a " + format + " binary despite its extension)"
	}
	return []Finding{{
		Type:      "malicious-install",
		Severity:  "CRITICAL",
		File:      scriptPath,
		Package:   pkgName,
		Ecosystem: "npm",
		Detail:    detail,
	}}
}

// findSpawnedELF looks for a local file referenced in a spawn/exec call and
// reports its path if it is an ELF binary. Used only to enrich a finding
// already raised by checkEntrypointScript — ELF binaries are routinely bundled
// by legitimate native-addon packages, so their presence alone is not a signal.
//
// Checked across platforms rather than just ELF: RedC2 itself targeted Linux,
// but a detached-spawn payload is not a Linux-specific technique, and the
// spawned target's extension proves nothing regardless of platform.
func findSpawnedBinary(scriptPath, content string) (rel, format string) {
	m := entrypointBinaryRe.FindStringSubmatch(content)
	if m == nil {
		return "", ""
	}
	rel = m[1]
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", ""
	}
	binPath := filepath.Join(filepath.Dir(scriptPath), filepath.FromSlash(rel))
	format = detectExecutableFormat(binPath)
	if format == "" {
		return "", ""
	}
	return rel, format
}

// executableMagic maps a file's leading bytes to the executable format they
// identify. Longer magics are listed first so a shorter one (PE's 2-byte "MZ")
// can't shadow a match a more specific check would have made.
var executableMagic = []struct {
	format string
	magic  []byte
}{
	{"ELF", []byte{0x7f, 'E', 'L', 'F'}},                 // Linux
	{"Mach-O", []byte{0xFE, 0xED, 0xFA, 0xCE}},           // macOS, 32-bit
	{"Mach-O", []byte{0xFE, 0xED, 0xFA, 0xCF}},           // macOS, 64-bit
	{"Mach-O universal", []byte{0xCA, 0xFE, 0xBA, 0xBE}}, // macOS, fat binary
	{"PE", []byte{'M', 'Z'}},                             // Windows
}

// detectExecutableFormat reports the executable format path begins with, or
// "" if it matches none of them — independent of its extension, since a
// bundled binary is often named to look like data (.bin, .dat).
func detectExecutableFormat(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var header [4]byte
	n, err := f.Read(header[:])
	if err != nil {
		return ""
	}
	for _, m := range executableMagic {
		if n >= len(m.magic) && bytes.Equal(header[:len(m.magic)], m.magic) {
			return m.format
		}
	}
	return ""
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

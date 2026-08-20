package detector

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// GlassWormDetector scans source files for invisible/zero-width Unicode characters
// that can be used to inject hidden malicious code (GlassWorm attack).
type GlassWormDetector struct {
	baseDetector
}

func (d *GlassWormDetector) Name() string { return "glassworm" }

// invisibleChars maps suspicious Unicode runes to their human-readable names and severities.
var invisibleChars = []struct {
	r        rune
	name     string
	severity string
}{
	// BiDi control characters — CRITICAL: can reverse visual order of code
	{'\u202A', "LEFT-TO-RIGHT EMBEDDING", "CRITICAL"},
	{'\u202B', "RIGHT-TO-LEFT EMBEDDING", "CRITICAL"},
	{'\u202C', "POP DIRECTIONAL FORMATTING", "CRITICAL"},
	{'\u202D', "LEFT-TO-RIGHT OVERRIDE", "CRITICAL"},
	{'\u202E', "RIGHT-TO-LEFT OVERRIDE", "CRITICAL"},
	// Line/paragraph separators — HIGH
	{'\u2028', "LINE SEPARATOR", "HIGH"},
	{'\u2029', "PARAGRAPH SEPARATOR", "HIGH"},
	// BOM mid-file is handled separately in scanFile
	// Zero-width characters — MEDIUM
	{'\u200B', "ZERO WIDTH SPACE", "MEDIUM"},
	{'\u200C', "ZERO WIDTH NON-JOINER", "MEDIUM"},
	{'\u200D', "ZERO WIDTH JOINER", "MEDIUM"},
	{'\u2060', "WORD JOINER", "MEDIUM"},
	{'\u034F', "COMBINING GRAPHEME JOINER", "MEDIUM"},
	{'\uFEFF', "BYTE ORDER MARK (mid-file)", "HIGH"}, // handled with special first-byte logic
}

// targetExtensions lists file extensions to scan.
// .json is intentionally excluded: JSON is data, not executed code, so invisible
// characters in JSON values cannot be used for the GlassWorm attack.
var targetExtensions = map[string]bool{
	".py":   true,
	".js":   true,
	".ts":   true,
	".go":   true,
	".php":  true,
	".rb":   true,
	".lock": true,
	".cfg":  true,
	".toml": true,
}

// skipDirs lists directory names to skip during filesystem walk.
//
// testdata is skipped by the same reasoning the Go toolchain applies to it: the
// contents are fixtures, never built or executed. Security tooling in
// particular keeps deliberately malicious samples there — this repository does
// — and reporting a project's own detection corpus back to it is pure noise.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"testdata":     true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"vendor":       true,
	".tox":         true,
	"site-packages":  true, // installed Python packages (analogous to node_modules)
	"dist-packages":  true, // Debian/Ubuntu system Python packages
	"Trash":          true, // FreeDesktop trash (~/.local/share/Trash)
	".Trash":         true, // macOS trash
}

// buildArtifactRe matches webpack/vite chunk filenames that contain a content hash,
// e.g. "1219.b5630aa3a46050fddc27.js". These are not human-authored source files.
var buildArtifactRe = regexp.MustCompile(`\.[0-9a-f]{12,}\.[a-z]+$`)

// Detect walks scanPath and reports files containing invisible/zero-width characters.
func (d *GlassWormDetector) Detect(scanPath string, verbose bool, progress *atomic.Int64) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(scanPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] || d.shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		progress.Add(1)

		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if !targetExtensions[ext] {
			return nil
		}
		// Skip minified files and webpack/vite chunk files with content hashes.
		lower := strings.ToLower(name)
		if strings.Contains(lower, ".min.") || buildArtifactRe.MatchString(lower) {
			return nil
		}

		found, scanErr := scanFile(path)
		if scanErr != nil {
			return nil // skip unreadable files
		}
		findings = append(findings, found...)
		return nil
	})

	return findings, err
}

// charOccurrence records where an invisible character was first seen in a file
// and how many times it appeared.
type charOccurrence struct {
	firstLine int
	count     int
	severity  string
	name      string
}

// scanFile reports invisible/zero-width characters in a file, one finding per
// distinct character rather than per occurrence.
//
// The same character usually appears many times in an affected file \u2014 a
// stripped build artifact can carry hundreds \u2014 and each repeat adds nothing:
// the file and the character are what a reviewer acts on. Reporting every
// occurrence separately turned one problem into hundreds of findings.
func scanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[rune]*charOccurrence{}
	var order []rune // preserve first-seen order for stable output

	lineNum := 0
	isFirst := true

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		runes := []rune(line)

		for i, r := range runes {
			for _, ic := range invisibleChars {
				if r != ic.r {
					continue
				}

				// BOM at the very first position of the file is an acceptable encoding marker.
				if ic.r == '\uFEFF' && isFirst && i == 0 {
					continue
				}

				// U+200B/200C/200D are required by many non-Latin scripts:
				// ZWS (U+200B) for word-wrapping in Thai/Tibetan/CJK,
				// ZWNJ/ZWJ (U+200C/200D) for glyph shaping in Devanagari/Arabic/Hebrew.
				// Only flag them when neighbours are ASCII \u2014 a sign of code-context injection.
				if (ic.r == '\u200B' || ic.r == '\u200C' || ic.r == '\u200D') && adjacentHasNonASCII(runes, i) {
					continue
				}

				if occ, ok := seen[r]; ok {
					occ.count++
				} else {
					seen[r] = &charOccurrence{firstLine: lineNum, count: 1, severity: ic.severity, name: ic.name}
					order = append(order, r)
				}
			}
		}
		isFirst = false
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(order))
	for _, r := range order {
		occ := seen[r]
		detail := "invisible char U+" + runeHex(r) + " (" + occ.name + ") detected"
		if occ.count > 1 {
			detail += " \u2014 " + strconv.Itoa(occ.count) + " occurrences, first at line " + strconv.Itoa(occ.firstLine)
		}
		findings = append(findings, Finding{
			Type:     "glassworm",
			Severity: occ.severity,
			File:     path,
			Line:     occ.firstLine,
			Detail:   detail,
		})
	}
	return findings, nil
}

// adjacentHasNonASCII reports whether the rune at idx in runes has at least one
// neighbouring rune (left or right) outside the ASCII range (> U+007F).
// Used to distinguish legitimate ZWJ/ZWNJ usage in Indic/Arabic scripts from
// suspicious injection between ASCII identifier characters.
func adjacentHasNonASCII(runes []rune, idx int) bool {
	if idx > 0 && runes[idx-1] > 0x7F {
		return true
	}
	if idx < len(runes)-1 && runes[idx+1] > 0x7F {
		return true
	}
	return false
}

// runeHex returns the uppercase hex representation of a rune (e.g. "202E").
func runeHex(r rune) string {
	const hex = "0123456789ABCDEF"
	n := uint32(r)
	var buf [4]byte
	for i := 3; i >= 0; i-- {
		buf[i] = hex[n&0xF]
		n >>= 4
	}
	return string(buf[:])
}

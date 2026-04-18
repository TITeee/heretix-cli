package detector

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
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
var targetExtensions = map[string]bool{
	".py":   true,
	".js":   true,
	".ts":   true,
	".go":   true,
	".php":  true,
	".rb":   true,
	".json": true,
	".lock": true,
	".cfg":  true,
	".toml": true,
}

// skipDirs lists directory names to skip during filesystem walk.
var skipDirs = map[string]bool{
	".git":        true,
	"node_modules": true,
	".venv":       true,
	"venv":        true,
	"__pycache__": true,
	"vendor":      true,
	".tox":        true,
}

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

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !targetExtensions[ext] {
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

// scanFile reads a file line by line and reports any invisible/zero-width characters found.
func scanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	lineNum := 0
	isFirst := true

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, ic := range invisibleChars {
			// Skip BOM at the very first character of the first line (legitimate encoding marker)
			if ic.r == '\uFEFF' && isFirst && strings.HasPrefix(line, string('\uFEFF')) {
				// BOM at start of file is acceptable; skip first occurrence only
				rest := strings.Replace(line, string('\uFEFF'), "", 1)
				if strings.ContainsRune(rest, '\uFEFF') {
					findings = append(findings, Finding{
						Type:     "glassworm",
						Severity: ic.severity,
						File:     path,
						Line:     lineNum,
						Detail:   "invisible char U+FEFF (" + ic.name + ") detected (multiple occurrences)",
					})
				}
				continue
			}

			if strings.ContainsRune(line, ic.r) {
				findings = append(findings, Finding{
					Type:     "glassworm",
					Severity: ic.severity,
					File:     path,
					Line:     lineNum,
					Detail:   "invisible char U+" + runeHex(ic.r) + " (" + ic.name + ") detected",
				})
				// Report once per character type per line
			}
		}
		isFirst = false
	}

	return findings, scanner.Err()
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

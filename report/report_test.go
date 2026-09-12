package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/checker"
	"github.com/TITeee/heretix-cli/detector"
	"github.com/TITeee/heretix-cli/inventory"
)

func TestTruncate(t *testing.T) {
	tests := map[string]struct {
		s    string
		max  int
		want string
	}{
		"shorter than max is unchanged":                 {"abc", 10, "abc"},
		"exactly max is unchanged":                      {"abcde", 5, "abcde"},
		"longer than max is truncated with an ellipsis": {"abcdefghij", 5, "ab..."},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := truncate(tc.s, tc.max)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.s, tc.max, got, tc.want)
			}
			if len(got) > tc.max {
				t.Errorf("truncate(%q, %d) = %q, longer than max", tc.s, tc.max, got)
			}
		})
	}
}

func TestIsMalwareID(t *testing.T) {
	if !isMalwareID("MAL-2026-1234") {
		t.Error("expected a MAL- prefixed ID to be classified as malware")
	}
	if isMalwareID("CVE-2026-1234") {
		t.Error("expected a CVE ID not to be classified as malware")
	}
}

func emptyInventory() *inventory.Inventory {
	return &inventory.Inventory{Packages: []inventory.Package{{Name: "foo", Source: "npm"}}}
}

func TestPrintTable_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, emptyInventory(), &checker.CheckResult{Hostname: "host"}, "sbom.json")

	out := buf.String()
	if !strings.Contains(out, "No vulnerabilities or malware found.") {
		t.Errorf("expected the no-findings message, got:\n%s", out)
	}
	if strings.Contains(out, "ECOSYSTEM") {
		t.Error("expected no table header when there are no findings")
	}
}

func TestPrintTable_NoFindingsStillShowsErrors(t *testing.T) {
	var buf bytes.Buffer
	result := &checker.CheckResult{Errors: []string{"batch request failed: timeout"}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")

	out := buf.String()
	if !strings.Contains(out, "Errors:") || !strings.Contains(out, "batch request failed: timeout") {
		t.Errorf("expected the collected error to be printed even with no findings, got:\n%s", out)
	}
}

func TestPrintTable_DBColumnPrefersSourcesOverSourceOverOSVFallback(t *testing.T) {
	tests := map[string]struct {
		v    checker.Vulnerability
		want string
	}{
		"Sources (plural) wins when present": {
			checker.Vulnerability{ExternalID: "CVE-1", Source: "nvd", Sources: []string{"oracle-linux"}},
			"oracle-linux",
		},
		"Source (singular) is used when Sources is empty": {
			checker.Vulnerability{ExternalID: "CVE-1", Source: "nvd"},
			"nvd",
		},
		"falls back to osv when both are empty": {
			checker.Vulnerability{ExternalID: "CVE-1"},
			"osv",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			result := &checker.CheckResult{Results: []checker.PackageResult{
				{Package: "pkg", Version: "1.0", Vulnerabilities: []checker.Vulnerability{tc.v}},
			}}
			PrintTable(&buf, emptyInventory(), result, "sbom.json")
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("expected DB column to contain %q, got:\n%s", tc.want, buf.String())
			}
		})
	}
}

func TestPrintTable_SeverityBucketBoundaries(t *testing.T) {
	// switch's own thresholds: >=9.0 critical, >=7.0 high, >=4.0 medium, else low.
	tests := map[string]struct {
		vuln   checker.Vulnerability
		bucket string
	}{
		"exactly 9.0 is critical":                           {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 9.0}, "Critical (>=9.0): 1"},
		"just under 9.0 is high":                            {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 8.9}, "High (>=7.0):     1"},
		"exactly 7.0 is high":                               {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 7.0}, "High (>=7.0):     1"},
		"exactly 4.0 is medium":                             {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 4.0}, "Medium (>=4.0):   1"},
		"just under 4.0 is low":                             {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 3.9}, "Low (<4.0):       1"},
		"zero score falls back to Severity text (CRITICAL)": {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 0, Severity: "CRITICAL"}, "Critical (>=9.0): 1"},
		"zero score with no Severity text is low":           {checker.Vulnerability{ExternalID: "CVE-1", CvssScore: 0}, "Low (<4.0):       1"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			result := &checker.CheckResult{Results: []checker.PackageResult{
				{Package: "pkg", Version: "1.0", Vulnerabilities: []checker.Vulnerability{tc.vuln}},
			}}
			PrintTable(&buf, emptyInventory(), result, "sbom.json")
			if !strings.Contains(buf.String(), tc.bucket) {
				t.Errorf("expected summary to contain %q, got:\n%s", tc.bucket, buf.String())
			}
		})
	}
}

func TestPrintTable_MalwareEntriesAreExcludedFromSeverityCountsAndCountedSeparately(t *testing.T) {
	var buf bytes.Buffer
	result := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "pkg", Version: "1.0", Vulnerabilities: []checker.Vulnerability{
			{ExternalID: "MAL-2026-1", CvssScore: 0},
		}},
	}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")

	out := buf.String()
	if !strings.Contains(out, "# = malicious package") {
		t.Error("expected the malware legend line")
	}
	if !strings.Contains(out, "1 malware") {
		t.Error("expected the malware count in the summary line")
	}
	if strings.Contains(out, "Critical (>=9.0): 1") || strings.Contains(out, "Low (<4.0):       1") {
		t.Errorf("expected the malware entry not to be counted into any severity bucket, got:\n%s", out)
	}
}

func TestPrintTable_KevPrefixAndLegendOnlyAppearWithAKevEntry(t *testing.T) {
	var buf bytes.Buffer
	result := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "pkg", Version: "1.0", Vulnerabilities: []checker.Vulnerability{
			{ExternalID: "CVE-1", CvssScore: 5.0, IsKev: true},
		}},
	}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")

	out := buf.String()
	if !hasRowWithPrefix(out, "CVE-1", "!") {
		t.Errorf("expected the KEV row to start with '!', got:\n%s", out)
	}
	if !strings.Contains(out, "! = in CISA Known Exploited Vulnerabilities") {
		t.Error("expected the KEV legend line")
	}
}

func TestPrintTable_ApproximateMatchPrefixAndLegend(t *testing.T) {
	var buf bytes.Buffer
	result := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "pkg", Version: "1.0", ApproximateMatch: true, Vulnerabilities: []checker.Vulnerability{
			{ExternalID: "CVE-1", CvssScore: 5.0},
		}},
	}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")

	out := buf.String()
	if !hasRowWithPrefix(out, "CVE-1", "~") {
		t.Errorf("expected the approximate-match row to start with '~', got:\n%s", out)
	}
	if !strings.Contains(out, "~ = approximate match") {
		t.Error("expected the approximate-match legend line")
	}
}

// hasRowWithPrefix reports whether some line in out contains marker and
// starts with prefix -- table rows are fixed-width-formatted, so the marker
// (e.g. a vuln ID) never sits immediately next to the leading "! "/"~ "/"# "
// column.
func hasRowWithPrefix(out, marker, prefix string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, marker) && strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func TestPrintTable_SourceDisplayPrefersLocationOverSource(t *testing.T) {
	var buf bytes.Buffer
	result := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "pkg", Version: "1.0", Source: "npm", Location: "package.json",
			Vulnerabilities: []checker.Vulnerability{{ExternalID: "CVE-1", CvssScore: 5.0}}},
	}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")

	if !strings.Contains(buf.String(), "package.json") {
		t.Errorf("expected the Location to be shown in place of Source, got:\n%s", buf.String())
	}
}

func TestPrintTable_SummaryFieldIsNotTruncatedInDataButRenderedRow(t *testing.T) {
	// The summary column has no width format specifier (no truncate() call
	// beyond the 40-char slice), so this exercises that a long summary is
	// shortened with an ellipsis rather than blowing out the table width.
	long := strings.Repeat("x", 100)
	var buf bytes.Buffer
	result := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "pkg", Version: "1.0", Vulnerabilities: []checker.Vulnerability{
			{ExternalID: "CVE-1", CvssScore: 5.0, Summary: long},
		}},
	}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")

	if strings.Contains(buf.String(), long) {
		t.Error("expected a 100-char summary to be truncated, not printed in full")
	}
}

func TestPrintJSON(t *testing.T) {
	t.Run("includes the check result and local findings", func(t *testing.T) {
		var buf bytes.Buffer
		result := &checker.CheckResult{Hostname: "host"}
		findings := []detector.Finding{{Type: "glassworm", Severity: "CRITICAL", File: "index.js"}}
		if err := PrintJSON(&buf, result, findings); err != nil {
			t.Fatalf("PrintJSON returned an error: %v", err)
		}

		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if _, ok := decoded["hostname"]; !ok {
			t.Error("expected a top-level \"hostname\" field")
		}
		if _, ok := decoded["localFindings"]; !ok {
			t.Error("expected a top-level \"localFindings\" field when findings are present")
		}
	})

	t.Run("omits localFindings entirely when there are none", func(t *testing.T) {
		var buf bytes.Buffer
		if err := PrintJSON(&buf, &checker.CheckResult{}, nil); err != nil {
			t.Fatalf("PrintJSON returned an error: %v", err)
		}
		if strings.Contains(buf.String(), "localFindings") {
			t.Errorf("expected \"localFindings\" to be omitted via omitempty, got:\n%s", buf.String())
		}
	})
}

func TestPrintFindings_EmptyWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	PrintFindings(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output for an empty findings slice, got:\n%s", buf.String())
	}
}

func TestPrintFindings_UnknownTypeFallsBackToQuestionMarkPrefix(t *testing.T) {
	var buf bytes.Buffer
	PrintFindings(&buf, []detector.Finding{{Type: "some-future-detector", Severity: "LOW", File: "a.txt"}})

	if !strings.Contains(buf.String(), "? some-future-detector") {
		t.Errorf("expected the unknown-type fallback prefix '?', got:\n%s", buf.String())
	}
}

func TestPrintFindings_LineZeroRendersAsDash(t *testing.T) {
	var buf bytes.Buffer
	PrintFindings(&buf, []detector.Finding{{Type: "hardcoded-secrets", Severity: "HIGH", File: "a.txt", Line: 0}})

	var findingRow string
	for _, l := range strings.Split(buf.String(), "\n") {
		// The summary line also contains "hardcoded-secrets"; the actual
		// finding row is the one naming the file.
		if strings.Contains(l, "a.txt") {
			findingRow = l
			break
		}
	}
	if findingRow == "" {
		t.Fatal("did not find the finding row in output")
	}
	if !strings.Contains(findingRow, "-  HIGH") {
		t.Errorf("expected line number to render as '-', got: %q", findingRow)
	}
}

func TestPrintFindings_DetailIsTruncatedAt60Chars(t *testing.T) {
	long := strings.Repeat("y", 100)
	var buf bytes.Buffer
	PrintFindings(&buf, []detector.Finding{{Type: "glassworm", Severity: "CRITICAL", File: "a.txt", Detail: long}})

	if strings.Contains(buf.String(), long) {
		t.Error("expected a 100-char detail to be truncated, not printed in full")
	}
}

func TestPrintFindings_LegendOnlyListsTypesActuallyPresent(t *testing.T) {
	var buf bytes.Buffer
	PrintFindings(&buf, []detector.Finding{{Type: "glassworm", Severity: "CRITICAL", File: "a.txt"}})

	out := buf.String()
	if !strings.Contains(out, "G = GlassWorm") {
		t.Error("expected the glassworm legend line")
	}
	if strings.Contains(out, "D = Dependency Confusion") {
		t.Error("expected the dep-confusion legend line to be absent when no such finding exists")
	}
}

func TestPrintFindings_SummaryLineCountsPerType(t *testing.T) {
	var buf bytes.Buffer
	PrintFindings(&buf, []detector.Finding{
		{Type: "glassworm", Severity: "CRITICAL", File: "a.txt"},
		{Type: "glassworm", Severity: "CRITICAL", File: "b.txt"},
		{Type: "dep-confusion", Severity: "HIGH", File: "c.txt"},
	})

	out := buf.String()
	if !strings.Contains(out, "Local findings: 3") {
		t.Errorf("expected the total count of 3, got:\n%s", out)
	}
	if !strings.Contains(out, "2 glassworm") || !strings.Contains(out, "1 dep-confusion") {
		t.Errorf("expected per-type counts, got:\n%s", out)
	}
}

func TestPrintFindingsJSON(t *testing.T) {
	var buf bytes.Buffer
	findings := []detector.Finding{{Type: "glassworm", File: "a.txt"}}
	if err := PrintFindingsJSON(&buf, findings); err != nil {
		t.Fatalf("PrintFindingsJSON returned an error: %v", err)
	}

	var decoded struct {
		LocalFindings []detector.Finding `json:"localFindings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded.LocalFindings) != 1 || decoded.LocalFindings[0].Type != "glassworm" {
		t.Errorf("expected the finding to round-trip through JSON, got %+v", decoded.LocalFindings)
	}
}

// debianInventory mirrors a real Debian image: two binary packages built from
// the binutils source, one kernel-header package, and one genuine runtime
// library.
func debianInventory() *inventory.Inventory {
	return &inventory.Inventory{Packages: []inventory.Package{
		{Name: "binutils", Version: "2.44-3", Ecosystem: "Debian:13", Source: "dpkg",
			SourcePackage: "binutils", Category: "build", Scope: "excluded"},
		{Name: "libbinutils", Version: "2.44-3", Ecosystem: "Debian:13", Source: "dpkg",
			SourcePackage: "binutils", Category: "build", Scope: "excluded"},
		{Name: "linux-libc-dev", Version: "6.12.43-1", Ecosystem: "Debian:13", Source: "dpkg",
			SourcePackage: "linux", Category: "kernel", Scope: "excluded"},
		{Name: "libc6", Version: "2.41-12", Ecosystem: "Debian:13", Source: "dpkg",
			SourcePackage: "glibc"},
	}}
}

func debianResult() *checker.CheckResult {
	vuln := func(id string, score float64) []checker.Vulnerability {
		return []checker.Vulnerability{{ExternalID: id, CvssScore: score}}
	}
	return &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "binutils", Version: "2.44-3", Ecosystem: "Debian:13", Vulnerabilities: vuln("CVE-2026-1", 5.0)},
		{Package: "libbinutils", Version: "2.44-3", Ecosystem: "Debian:13", Vulnerabilities: vuln("CVE-2026-1", 5.0)},
		{Package: "linux-libc-dev", Version: "6.12.43-1", Ecosystem: "Debian:13", Vulnerabilities: vuln("CVE-2026-3", 5.0)},
		{Package: "libc6", Version: "2.41-12", Ecosystem: "Debian:13", Vulnerabilities: vuln("CVE-2026-2", 5.0)},
	}}
}

// TestPrintTable_CollapsesFindingsSharingASourcePackage covers the larger of
// the two count-inflation mechanisms: one source package fans out into several
// binary packages, and the same CVE is then reported once per binary package.
func TestPrintTable_CollapsesFindingsSharingASourcePackage(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, debianInventory(), debianResult(), "sbom.json")
	out := buf.String()

	if n := countRowsContaining(out, "CVE-2026-1"); n != 1 {
		t.Errorf("CVE-2026-1 appears on %d rows, want 1 (binutils and libbinutils share a source package)", n)
	}
	if !strings.Contains(out, "binutils(+1)") {
		t.Errorf("expected the collapsed row to note the extra binary package, got:\n%s", out)
	}
	if !strings.Contains(out, "Summary: 3 packages with 3 findings") {
		t.Errorf("expected the summary to count collapsed findings once, got:\n%s", out)
	}
}

// TestPrintTable_TagsNonRuntimeFindings checks that non-runtime findings are
// marked rather than hidden -- the default has to stay complete so nothing
// disappears without the reader being told.
func TestPrintTable_TagsNonRuntimeFindings(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, debianInventory(), debianResult(), "sbom.json")
	out := buf.String()

	if !hasRowWithPrefix(out, "CVE-2026-3", " K") {
		t.Errorf("expected the kernel-header row to carry the K marker, got:\n%s", out)
	}
	if !hasRowWithPrefix(out, "CVE-2026-1", " B") {
		t.Errorf("expected the build-tooling row to carry the B marker, got:\n%s", out)
	}
	if !hasRowWithPrefix(out, "CVE-2026-2", "  ") {
		t.Errorf("expected the runtime row to carry no category marker, got:\n%s", out)
	}
	if !strings.Contains(out, "K = kernel headers") {
		t.Error("expected the kernel legend line")
	}
	if !strings.Contains(out, "B = build toolchain") {
		t.Error("expected the build legend line")
	}
	if !strings.Contains(out, "Non-runtime:      2 (kernel 1, build 1)") {
		t.Errorf("expected the non-runtime breakdown in the summary, got:\n%s", out)
	}
}

func TestPrintTable_RuntimeOnlyDropsNonRuntimeFindings(t *testing.T) {
	var buf bytes.Buffer
	PrintTableWithOptions(&buf, debianInventory(), debianResult(), "sbom.json", Options{RuntimeOnly: true})
	out := buf.String()

	if strings.Contains(out, "CVE-2026-1") || strings.Contains(out, "CVE-2026-3") {
		t.Errorf("expected non-runtime findings to be dropped with RuntimeOnly, got:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2026-2") {
		t.Errorf("expected the runtime finding to remain, got:\n%s", out)
	}
	if !strings.Contains(out, "Summary: 1 packages with 1 findings") {
		t.Errorf("expected the summary to count only runtime findings, got:\n%s", out)
	}
	if strings.Contains(out, "Non-runtime:") {
		t.Error("expected no non-runtime breakdown when non-runtime findings are excluded")
	}
}

// TestPrintTable_UnclassifiedPackagesKeepTheirOwnIdentity guards the default
// path: an inventory without source-package metadata (an npm project, or an
// SBOM produced before this field existed) must report exactly as before.
func TestPrintTable_UnclassifiedPackagesKeepTheirOwnIdentity(t *testing.T) {
	var buf bytes.Buffer
	result := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "a", Version: "1.0", Vulnerabilities: []checker.Vulnerability{{ExternalID: "CVE-1", CvssScore: 5}}},
		{Package: "b", Version: "1.0", Vulnerabilities: []checker.Vulnerability{{ExternalID: "CVE-1", CvssScore: 5}}},
	}}
	PrintTable(&buf, emptyInventory(), result, "sbom.json")
	out := buf.String()

	if n := countRowsContaining(out, "CVE-1"); n != 2 {
		t.Errorf("CVE-1 appears on %d rows, want 2 (unrelated packages must not be collapsed)", n)
	}
}

func countRowsContaining(out, marker string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, marker) {
			n++
		}
	}
	return n
}

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/TITeee/heretix-cli/checker"
	"github.com/TITeee/heretix-cli/detector"
	"github.com/TITeee/heretix-cli/inventory"
)

func isMalwareID(externalID string) bool {
	return strings.HasPrefix(externalID, "MAL-")
}

// PrintTable writes a human-readable vulnerability report to w.
func PrintTable(w io.Writer, inv *inventory.Inventory, result *checker.CheckResult, source string) {
	fmt.Fprintln(w, "Vulnerability Check Report")
	fmt.Fprintln(w, "==========================")
	fmt.Fprintf(w, "Source:     %s\n", source)
	fmt.Fprintf(w, "Host:       %s\n", result.Hostname)

	// Count packages by source type
	sourceCounts := make(map[string]int)
	for _, p := range inv.Packages {
		sourceCounts[p.Source]++
	}
	countParts := []string{}
	for src, cnt := range sourceCounts {
		countParts = append(countParts, fmt.Sprintf("%s: %d", src, cnt))
	}
	fmt.Fprintf(w, "Packages:   %d checked (%s)\n", len(inv.Packages), strings.Join(countParts, ", "))
	fmt.Fprintln(w)

	// Count vulnerabilities
	totalVulnPkgs := 0
	totalVulns := 0
	malwareCount := 0
	kevCount := 0
	critical, high, medium, low := 0, 0, 0, 0

	for _, r := range result.Results {
		if len(r.Vulnerabilities) > 0 {
			totalVulnPkgs++
		}
		for _, v := range r.Vulnerabilities {
			if isMalwareID(v.ExternalID) {
				malwareCount++
				continue
			}
			totalVulns++
			if v.IsKev {
				kevCount++
			}
			switch {
			case v.CvssScore >= 9.0 || (v.CvssScore == 0 && strings.EqualFold(v.Severity, "CRITICAL")):
				critical++
			case v.CvssScore >= 7.0 || (v.CvssScore == 0 && strings.EqualFold(v.Severity, "HIGH")):
				high++
			case v.CvssScore >= 4.0 || (v.CvssScore == 0 && strings.EqualFold(v.Severity, "MEDIUM")):
				medium++
			default:
				low++
			}
		}
	}

	if totalVulns == 0 && malwareCount == 0 {
		if len(result.Errors) > 0 {
			fmt.Fprintln(w, "Errors:")
			for _, e := range result.Errors {
				fmt.Fprintf(w, "  - %s\n", e)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "No vulnerabilities or malware found.")
		return
	}

	// Print header
	fmt.Fprintf(w, "  %-11s %-16s %-10s %-20s %-4s  %-20s %5s  %5s  %s\n",
		"ECOSYSTEM", "PACKAGE", "VERSION", "SOURCE", "DB", "VULN ID", "CVSS", "EPSS", "SUMMARY")
	fmt.Fprintf(w, "  %-11s %-16s %-10s %-20s %-4s  %-20s %5s  %5s  %s\n",
		strings.Repeat("─", 10),
		strings.Repeat("─", 15),
		strings.Repeat("─", 9),
		strings.Repeat("─", 20),
		strings.Repeat("─", 3),
		strings.Repeat("─", 19),
		strings.Repeat("─", 4),
		strings.Repeat("─", 4),
		strings.Repeat("─", 14))

	hasApproximate := false
	hasKev := false
	hasMalware := false
	for _, r := range result.Results {
		sourceDisplay := r.Source
		if r.Location != "" {
			sourceDisplay = r.Location
		}
		if len(sourceDisplay) > 20 {
			sourceDisplay = sourceDisplay[:17] + "..."
		}

		prefix := "  "
		if r.ApproximateMatch {
			prefix = "~ "
			hasApproximate = true
		}

		for _, v := range r.Vulnerabilities {
			rowPrefix := prefix
			if isMalwareID(v.ExternalID) {
				rowPrefix = "# "
				hasMalware = true
			} else if v.IsKev {
				rowPrefix = "! "
				hasKev = true
			}
			vulnID := v.ExternalID
			if vulnID == "" {
				vulnID = v.ID
			}
			dbSource := v.Source
			if dbSource == "" {
				dbSource = "osv"
			}
			summary := v.Summary
			if len(summary) > 40 {
				summary = summary[:37] + "..."
			}
			cvssDisplay := "-"
			if v.CvssScore > 0 {
				cvssDisplay = fmt.Sprintf("%.1f", v.CvssScore)
			}
			epssDisplay := "-"
			if v.EpssScore > 0 {
				epssDisplay = fmt.Sprintf("%.3f", v.EpssScore)
			}
			fmt.Fprintf(w, "%s%-11s %-16s %-10s %-20s %-4s  %-20s %5s  %5s  %s\n",
				rowPrefix, r.Ecosystem, truncate(r.Package, 15), truncate(r.Version, 9),
				sourceDisplay, dbSource, truncate(vulnID, 19), cvssDisplay, epssDisplay, summary)
		}
	}

	if hasApproximate || hasKev || hasMalware {
		fmt.Fprintln(w)
		if hasMalware {
			fmt.Fprintln(w, "# = malicious package (OSSF Malicious Packages)")
		}
		if hasKev {
			fmt.Fprintln(w, "! = in CISA Known Exploited Vulnerabilities (KEV) catalog")
		}
		if hasApproximate {
			fmt.Fprintln(w, "~ = approximate match (version could not be normalized, showing all vulnerabilities for this package)")
		}
		fmt.Fprintln(w, "DB = data source (osv = Open Source Vulnerabilities, nvd = NIST NVD, advisory = Vendor Advisory)")
		fmt.Fprintln(w, "EPSS = Exploit Prediction Scoring System probability (0.000–1.000)")
	}

	fmt.Fprintln(w)
	totalFindings := totalVulns + malwareCount
	fmt.Fprintf(w, "Summary: %d packages with %d findings", totalVulnPkgs, totalFindings)
	extras := []string{}
	if malwareCount > 0 {
		extras = append(extras, fmt.Sprintf("%d malware", malwareCount))
	}
	if kevCount > 0 {
		extras = append(extras, fmt.Sprintf("%d KEV", kevCount))
	}
	if len(extras) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(extras, ", "))
	}
	fmt.Fprintln(w)
	if malwareCount > 0 {
		fmt.Fprintf(w, "  Malware:          %d\n", malwareCount)
	}
	fmt.Fprintf(w, "  Critical (>=9.0): %d\n", critical)
	fmt.Fprintf(w, "  High (>=7.0):     %d\n", high)
	fmt.Fprintf(w, "  Medium (>=4.0):   %d\n", medium)
	fmt.Fprintf(w, "  Low (<4.0):       %d\n", low)

	if len(result.Errors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Errors:")
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
}

// PrintJSON writes the check result and local findings as JSON to w.
func PrintJSON(w io.Writer, result *checker.CheckResult, findings []detector.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	out := struct {
		*checker.CheckResult
		LocalFindings []detector.Finding `json:"localFindings,omitempty"`
	}{
		CheckResult:   result,
		LocalFindings: findings,
	}
	return enc.Encode(out)
}

// PrintFindings writes local security findings (GlassWorm, Dependency Confusion)
// to w in a human-readable table format.
func PrintFindings(w io.Writer, findings []detector.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Local Security Findings")
	fmt.Fprintln(w, "=======================")
	fmt.Fprintf(w, "  %-14s %-35s %4s  %-8s  %s\n", "TYPE", "FILE", "LINE", "SEVERITY", "DETAIL")
	fmt.Fprintf(w, "  %-14s %-35s %4s  %-8s  %s\n",
		strings.Repeat("─", 13),
		strings.Repeat("─", 34),
		strings.Repeat("─", 4),
		strings.Repeat("─", 8),
		strings.Repeat("─", 20))

	glasswormCount := 0
	depConfusionCount := 0

	for _, f := range findings {
		prefix := "G "
		switch f.Type {
		case "glassworm":
			prefix = "G "
			glasswormCount++
		case "dep-confusion":
			prefix = "D "
			depConfusionCount++
		}

		lineStr := "-"
		if f.Line > 0 {
			lineStr = fmt.Sprintf("%d", f.Line)
		}

		fileDisplay := f.File
		if len(fileDisplay) > 34 {
			fileDisplay = "..." + fileDisplay[len(fileDisplay)-31:]
		}

		detail := f.Detail
		if len(detail) > 60 {
			detail = detail[:57] + "..."
		}

		fmt.Fprintf(w, "%s%-14s %-35s %4s  %-8s  %s\n",
			prefix, f.Type, fileDisplay, lineStr, f.Severity, detail)
	}

	fmt.Fprintln(w)
	if glasswormCount > 0 {
		fmt.Fprintln(w, "G = GlassWorm (invisible/zero-width character injection)")
	}
	if depConfusionCount > 0 {
		fmt.Fprintln(w, "D = Dependency Confusion (private package resolvable from public registry)")
	}
	fmt.Fprintf(w, "\nLocal findings: %d", len(findings))
	extras := []string{}
	if glasswormCount > 0 {
		extras = append(extras, fmt.Sprintf("%d glassworm", glasswormCount))
	}
	if depConfusionCount > 0 {
		extras = append(extras, fmt.Sprintf("%d dep-confusion", depConfusionCount))
	}
	if len(extras) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(extras, ", "))
	}
	fmt.Fprintln(w)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

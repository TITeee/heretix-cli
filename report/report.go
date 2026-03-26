package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/TITeee/heretix-cli/checker"
	"github.com/TITeee/heretix-cli/inventory"
)

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
	kevCount := 0
	critical, high, medium, low := 0, 0, 0, 0

	for _, r := range result.Results {
		if len(r.Vulnerabilities) > 0 {
			totalVulnPkgs++
		}
		for _, v := range r.Vulnerabilities {
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

	if totalVulns == 0 {
		if len(result.Errors) > 0 {
			fmt.Fprintln(w, "Errors:")
			for _, e := range result.Errors {
				fmt.Fprintf(w, "  - %s\n", e)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "No vulnerabilities found.")
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
			if v.IsKev {
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

	if hasApproximate || hasKev {
		fmt.Fprintln(w)
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
	fmt.Fprintf(w, "Summary: %d packages with %d vulnerabilities", totalVulnPkgs, totalVulns)
	if kevCount > 0 {
		fmt.Fprintf(w, " (%d KEV)", kevCount)
	}
	fmt.Fprintln(w)
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

// PrintJSON writes the check result as JSON to w.
func PrintJSON(w io.Writer, result *checker.CheckResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

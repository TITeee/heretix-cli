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

// osPackageSources are inventory.Package.Source values written by an OS
// package collector (collector/dpkg.go, rpm.go, apk.go) -- the only place
// SourcePackage carries a real "one upstream project split into many binary
// packages" relationship. Everywhere else (npm, pip, ...) the same package
// name can legitimately appear at different versions from different
// locations in a single scan, and those must never be folded together just
// because they share a name.
var osPackageSources = map[string]bool{"dpkg": true, "rpm": true, "apk-db": true}

// Options configures PrintTable.
type Options struct {
	// RuntimeOnly drops findings on packages classified as non-runtime
	// (kernel headers, build toolchain) instead of tagging them. The default
	// reports everything, so nothing disappears unless it was asked for.
	RuntimeOnly bool
}

// reportRow is one printed line: a single vulnerability in a single source
// package. Findings that several binary packages of one source package share
// collapse into one row, with extraPkgs counting the ones folded in.
type reportRow struct {
	ecosystem    string
	pkg          string
	sourcePkg    string
	version      string
	versionMixed bool
	sourceDisp   string
	dbSource     string
	vulnID       string
	summary      string
	cvss         float64
	epss         float64
	severity     string
	approximate  bool
	kev          bool
	malware      bool
	category     string
	extraPkgs    int
}

// buildRows flattens the per-package check results into printable rows,
// resolving each result back to its collected package so that the source
// package and non-runtime category are available.
//
// The same CVE reported against several binary packages built from one source
// package is one finding, not several: binutils alone ships as eight binary
// packages on Debian 13, so a single binutils CVE would otherwise be counted
// eight times.
func buildRows(inv *inventory.Inventory, result *checker.CheckResult, opts Options) []reportRow {
	meta := make(map[string]inventory.Package, len(inv.Packages))
	for _, p := range inv.Packages {
		meta[p.Name+"\t"+p.Version+"\t"+p.Ecosystem] = p
	}

	var rows []reportRow
	index := make(map[string]int)
	for _, r := range result.Results {
		m := meta[r.Package+"\t"+r.Version+"\t"+r.Ecosystem]
		if opts.RuntimeOnly && m.Category != "" {
			continue
		}
		sourcePkg := m.SourcePackage
		if sourcePkg == "" {
			sourcePkg = r.Package
		}

		sourceDisp := r.Source
		if r.Location != "" {
			sourceDisp = r.Location
		}
		if len(sourceDisp) > 20 {
			sourceDisp = sourceDisp[:17] + "..."
		}

		for _, v := range r.Vulnerabilities {
			vulnID := v.ExternalID
			if vulnID == "" {
				vulnID = v.ID
			}
			// Only collapse across a real OS source-package relationship.
			// Elsewhere, group by this exact installed package so that two
			// different versions of, say, npm's picomatch never fold together
			// just because SourcePackage falls back to the package's own name.
			groupKey := sourcePkg
			if !osPackageSources[m.Source] {
				groupKey = r.Package + "\x00" + r.Version + "\x00" + r.Location
			}
			key := r.Ecosystem + "\t" + groupKey + "\t" + vulnID
			if i, ok := index[key]; ok {
				rows[i].extraPkgs++
				rows[i].kev = rows[i].kev || v.IsKev
				rows[i].approximate = rows[i].approximate || r.ApproximateMatch
				// A source package can produce both runtime and non-runtime
				// binary packages (glibc: libc6 is runtime, libc6-dev is
				// build), and the same CVE is often reported against all of
				// them. If any member affected by this CVE is a runtime
				// package, the row must not carry a non-runtime tag -- doing
				// so would let --runtime-only silently drop a finding that
				// does affect something that runs.
				if m.Category == "" {
					rows[i].category = ""
				}
				if r.Version != rows[i].version {
					rows[i].versionMixed = true
				}
				continue
			}

			// Sources (plural) is the authoritative record of which search
			// path actually matched; Source (singular) is only a display
			// preference (e.g. always "nvd" when the CVE has NVD metadata,
			// even when a vendor advisory is what matched) -- see checker.go.
			dbSource := strings.Join(v.Sources, ",")
			if dbSource == "" {
				dbSource = v.Source
			}
			if dbSource == "" {
				dbSource = "osv"
			}

			index[key] = len(rows)
			rows = append(rows, reportRow{
				ecosystem:   r.Ecosystem,
				pkg:         r.Package,
				sourcePkg:   sourcePkg,
				version:     r.Version,
				sourceDisp:  sourceDisp,
				dbSource:    dbSource,
				vulnID:      vulnID,
				summary:     v.Summary,
				cvss:        v.CvssScore,
				epss:        v.EpssScore,
				severity:    v.Severity,
				approximate: r.ApproximateMatch,
				kev:         v.IsKev,
				malware:     isMalwareID(vulnID),
				category:    m.Category,
			})
		}
	}
	return rows
}

// PrintTable writes a human-readable vulnerability report to w.
func PrintTable(w io.Writer, inv *inventory.Inventory, result *checker.CheckResult, source string) {
	PrintTableWithOptions(w, inv, result, source, Options{})
}

// PrintTableWithOptions is PrintTable with reporting options applied.
func PrintTableWithOptions(w io.Writer, inv *inventory.Inventory, result *checker.CheckResult, source string, opts Options) {
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

	rows := buildRows(inv, result, opts)

	// Count vulnerabilities
	totalVulns := 0
	malwareCount := 0
	kevCount := 0
	kernelCount, buildCount := 0, 0
	critical, high, medium, low := 0, 0, 0, 0
	vulnPkgs := map[string]bool{}

	for _, r := range rows {
		vulnPkgs[r.ecosystem+"\t"+r.sourcePkg] = true
		switch r.category {
		case "kernel":
			kernelCount++
		case "build":
			buildCount++
		}
		if r.malware {
			malwareCount++
			continue
		}
		totalVulns++
		if r.kev {
			kevCount++
		}
		switch {
		case r.cvss >= 9.0 || (r.cvss == 0 && strings.EqualFold(r.severity, "CRITICAL")):
			critical++
		case r.cvss >= 7.0 || (r.cvss == 0 && strings.EqualFold(r.severity, "HIGH")):
			high++
		case r.cvss >= 4.0 || (r.cvss == 0 && strings.EqualFold(r.severity, "MEDIUM")):
			medium++
		default:
			low++
		}
	}
	totalVulnPkgs := len(vulnPkgs)

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

	// Print header. PACKAGE is wider than a bare package name needs (20, not
	// 15) because a collapsed row's "sourcepkg(N pkgs)" display runs longer
	// than any single binary package name it replaces.
	fmt.Fprintf(w, "   %-11s %-21s %-10s %-20s %-4s  %-20s %5s  %5s  %s\n",
		"ECOSYSTEM", "PACKAGE", "VERSION", "SOURCE", "DB", "VULN ID", "CVSS", "EPSS", "SUMMARY")
	fmt.Fprintf(w, "   %-11s %-21s %-10s %-20s %-4s  %-20s %5s  %5s  %s\n",
		strings.Repeat("─", 10),
		strings.Repeat("─", 20),
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
	hasCollapsed := false
	hasMixedVersion := false
	for _, r := range rows {
		// Column 1 is what makes a finding urgent, column 2 is what makes it
		// (ir)relevant to this image; they are independent, so each gets its
		// own character rather than competing for one.
		marker := ' '
		switch {
		case r.malware:
			marker = '#'
			hasMalware = true
		case r.kev:
			marker = '!'
			hasKev = true
		case r.approximate:
			marker = '~'
			hasApproximate = true
		}
		categoryMark := ' '
		switch r.category {
		case "kernel":
			categoryMark = 'K'
		case "build":
			categoryMark = 'B'
		}

		// A collapsed row names the source package, not an arbitrary one of its
		// binary packages: most multi-binary sources have no binary package
		// sharing the source's own name (glibc -> libc6/libc6-dev/..., no
		// package literally named "glibc"), so there is no principled way to
		// pick one binary name to stand for the group. The source package name
		// is always meaningful and always available, since it is the key this
		// row was collapsed on.
		pkgDisplay := r.pkg
		if r.extraPkgs > 0 {
			pkgDisplay = fmt.Sprintf("%s(%d pkgs)", r.sourcePkg, r.extraPkgs+1)
			hasCollapsed = true
		}
		summary := r.summary
		if len(summary) > 40 {
			summary = summary[:37] + "..."
		}
		cvssDisplay := "-"
		if r.cvss > 0 {
			cvssDisplay = fmt.Sprintf("%.1f", r.cvss)
		}
		epssDisplay := "-"
		if r.epss > 0 {
			epssDisplay = fmt.Sprintf("%.3f", r.epss)
		}
		// A collapsed group's binary packages usually share one version, since
		// they are built together -- but not always (util-linux's binary
		// packages carry different version strings across a Debian source
		// rename). Showing one of them as if it applied to the whole group
		// would misstate which version is actually affected.
		versionDisplay := r.version
		if r.versionMixed {
			versionDisplay = "multiple"
			hasMixedVersion = true
		}
		fmt.Fprintf(w, "%c%c %-11s %-21s %-10s %-20s %-4s  %-20s %5s  %5s  %s\n",
			marker, categoryMark, r.ecosystem, truncate(pkgDisplay, 20), truncate(versionDisplay, 9),
			r.sourceDisp, r.dbSource, truncate(r.vulnID, 19), cvssDisplay, epssDisplay, summary)
	}

	if hasApproximate || hasKev || hasMalware || kernelCount > 0 || buildCount > 0 || hasCollapsed || hasMixedVersion {
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
		if kernelCount > 0 {
			fmt.Fprintln(w, "K = kernel headers (the host kernel runs, not this package's code)")
		}
		if buildCount > 0 {
			fmt.Fprintln(w, "B = build toolchain (compiler, linker or development headers left from a build stage)")
		}
		if hasCollapsed {
			fmt.Fprintln(w, "(N pkgs) = the same vulnerability in N binary packages built from this source package (PACKAGE names the source package)")
		}
		if hasMixedVersion {
			fmt.Fprintln(w, "multiple = the binary packages in this row do not share one version")
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
	if kernelCount > 0 || buildCount > 0 {
		parts := []string{}
		if kernelCount > 0 {
			parts = append(parts, fmt.Sprintf("kernel %d", kernelCount))
		}
		if buildCount > 0 {
			parts = append(parts, fmt.Sprintf("build %d", buildCount))
		}
		fmt.Fprintf(w, "  Non-runtime:      %d (%s)\n", kernelCount+buildCount, strings.Join(parts, ", "))
		fmt.Fprintln(w, "  (counted above; re-run with --runtime-only to exclude them)")
	}

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

	typePrefixes := map[string]string{
		"glassworm":          "G",
		"dep-confusion":      "D",
		"malicious-install":  "M",
		"cicd-poisoning":     "C",
		"hardcoded-secrets":  "S",
		"lockfile-integrity": "L",
	}
	typeCounts := make(map[string]int)

	for _, f := range findings {
		typeCounts[f.Type]++
		prefix := typePrefixes[f.Type]
		if prefix == "" {
			prefix = "?"
		}

		lineStr := "-"
		if f.Line > 0 {
			lineStr = fmt.Sprintf("%d", f.Line)
		}

		fileDisplay := f.File

		detail := f.Detail
		if len(detail) > 60 {
			detail = detail[:57] + "..."
		}

		fmt.Fprintf(w, "%s %-14s %-35s %4s  %-8s  %s\n",
			prefix, f.Type, fileDisplay, lineStr, f.Severity, detail)
	}

	fmt.Fprintln(w)
	legends := []struct{ typ, label string }{
		{"glassworm", "G = GlassWorm (invisible/zero-width character injection)"},
		{"dep-confusion", "D = Dependency Confusion (private package resolvable from public registry)"},
		{"malicious-install", "M = Malicious Install (malicious lifecycle script or setup.py)"},
		{"cicd-poisoning", "C = CI/CD Poisoning (pipeline script injection or tampering)"},
		{"hardcoded-secrets", "S = Hardcoded Secrets (credentials or tokens in source code)"},
		{"lockfile-integrity", "L = Lock File Integrity (tampered or inconsistent lock file)"},
	}
	for _, l := range legends {
		if typeCounts[l.typ] > 0 {
			fmt.Fprintln(w, l.label)
		}
	}

	fmt.Fprintf(w, "\nLocal findings: %d", len(findings))
	extras := []string{}
	for _, l := range legends {
		if typeCounts[l.typ] > 0 {
			extras = append(extras, fmt.Sprintf("%d %s", typeCounts[l.typ], l.typ))
		}
	}
	if len(extras) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(extras, ", "))
	}
	fmt.Fprintln(w)
}

// PrintFindingsJSON writes only local findings as JSON to w.
func PrintFindingsJSON(w io.Writer, findings []detector.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	out := struct {
		LocalFindings []detector.Finding `json:"localFindings"`
	}{
		LocalFindings: findings,
	}
	return enc.Encode(out)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

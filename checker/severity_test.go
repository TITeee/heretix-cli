package checker

import "testing"

func TestSeverityTier(t *testing.T) {
	tests := []struct {
		severity string
		score    float64
		want     string
	}{
		{"CRITICAL", 0, TierCritical},
		{"HIGH", 10.0, TierHigh}, // CVSS v2 10.0: the rating wins over v3 thresholds
		{"moderate", 0, TierMedium},
		{"MEDIUM", 9.8, TierMedium},
		{"LOW", 0, TierLow},
		{"", 9.0, TierCritical},
		{"", 7.0, TierHigh},
		{"", 4.0, TierMedium},
		{"NONE", 0.1, TierLow}, // unrecognized word falls back to the score
		{"", 0, TierNA},
	}
	for _, tc := range tests {
		if got := SeverityTier(tc.severity, tc.score); got != tc.want {
			t.Errorf("SeverityTier(%q, %v) = %q, want %q", tc.severity, tc.score, got, tc.want)
		}
	}
}

// TestFilterAndSort_KeepsRatedUnscoredVulnsAboveThreshold guards against a
// --severity threshold silently dropping a vulnerability that has a rating
// but no CVSS score, as if it had scored 0.
func TestFilterAndSort_KeepsRatedUnscoredVulnsAboveThreshold(t *testing.T) {
	results := []PackageResult{{Package: "p", Version: "1", Vulnerabilities: []Vulnerability{
		{ExternalID: "CVE-HIGH-UNSCORED", Severity: "HIGH"},
		{ExternalID: "CVE-LOW-UNSCORED", Severity: "LOW"},
		{ExternalID: "CVE-UNRATED"},
		{ExternalID: "CVE-SCORED-6", CvssScore: 6.5, Severity: "HIGH"},
	}}}

	got := filterAndSort(results, 7.0)
	kept := map[string]bool{}
	for _, r := range got {
		for _, v := range r.Vulnerabilities {
			kept[v.ExternalID] = true
		}
	}

	if !kept["CVE-HIGH-UNSCORED"] {
		t.Error("unscored HIGH vulnerability was dropped by --severity 7.0")
	}
	for _, id := range []string{"CVE-LOW-UNSCORED", "CVE-UNRATED", "CVE-SCORED-6"} {
		if kept[id] {
			t.Errorf("%s should not pass --severity 7.0", id)
		}
	}
}

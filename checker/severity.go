package checker

import "strings"

// Severity tiers, matching heretix-management's getAlertSeverityTier.
const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierMedium   = "medium"
	TierLow      = "low"
	TierNA       = "na"
)

// SeverityTier is the one rule for bucketing a vulnerability, shared with
// heretix-management so a CLI report and the console never disagree about the
// same finding. The severity word wins: it is the rating on the score's own
// CVSS version, so a CVSS v2 10.0 is HIGH (v2 has no Critical), which
// re-bucketing the score against v3 thresholds would get wrong. The score is
// only a fallback for a vulnerability with no recognized rating.
func SeverityTier(severity string, score float64) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return TierCritical
	case "HIGH":
		return TierHigh
	case "MEDIUM", "MODERATE": // MODERATE is GHSA's word; older heretix-api data may still carry it
		return TierMedium
	case "LOW":
		return TierLow
	}
	switch {
	case score >= 9.0:
		return TierCritical
	case score >= 7.0:
		return TierHigh
	case score >= 4.0:
		return TierMedium
	case score > 0:
		return TierLow
	}
	return TierNA
}

// meetsThreshold reports whether v passes a --severity CVSS threshold. A
// scored vulnerability is compared by its score, as the flag documents. An
// unscored one is compared by the highest score its rating allows, so a
// rated-but-unscored HIGH is kept for any threshold up to 8.9 instead of
// being silently dropped as if it scored 0.
func meetsThreshold(v Vulnerability, minSeverity float64) bool {
	if v.CvssScore > 0 || minSeverity <= 0 {
		return v.CvssScore >= minSeverity
	}
	var ceiling float64
	switch SeverityTier(v.Severity, 0) {
	case TierCritical:
		ceiling = 10.0
	case TierHigh:
		ceiling = 8.9
	case TierMedium:
		ceiling = 6.9
	case TierLow:
		ceiling = 3.9
	}
	return ceiling >= minSeverity
}

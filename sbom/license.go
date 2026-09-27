package sbom

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// licenseChoiceFor classifies a raw license string collected from a package
// manager (npm's package.json, rpm's License: tag, a dpkg copyright file,
// PyPI metadata, ...) into the CycloneDX-correct field for it.
//
// The CycloneDX schema documents license.id and license.expression as "A
// valid SPDX license ID" / "A valid SPDX license expression" respectively;
// license.name exists specifically for text that isn't one. Most package
// managers don't use SPDX syntax at all — rpm's own conventions look similar
// ("GPLv2+ and MIT", lowercase "and", non-SPDX identifiers like "GPLv2+" or
// "Public Domain") but aren't valid SPDX, and would misuse the expression
// field if written there uninspected. Only npm's package.json and Composer
// (which already emits SPDX-shaped "MIT OR Apache-2.0" strings) reliably
// produce real SPDX syntax.
func licenseChoiceFor(license string) cdx.LicenseChoice {
	if _, ok := spdxLicenseIDs[license]; ok {
		return cdx.LicenseChoice{License: &cdx.License{ID: license}}
	}
	if isSPDXExpression(license) {
		return cdx.LicenseChoice{Expression: license}
	}
	return cdx.LicenseChoice{License: &cdx.License{Name: license}}
}

// isSPDXExpression reports whether s parses as a compound SPDX license
// expression: license IDs joined by the uppercase "AND"/"OR"/"WITH"
// operators and optional parentheses, e.g. "MIT AND (Apache-2.0 OR ISC)".
// Every identifier token must be a real SPDX license ID (spdxLicenseIDs); a
// lowercase "and"/"or", or any identifier not on that list, fails the parse
// and falls through to license.name in licenseChoiceFor. This intentionally
// doesn't implement the "WITH <exception-id>" or trailing "+" legacy
// operators — a real use of either is rare enough among the package
// managers heretix-cli reads that under-classifying it as free text (safe:
// still valid CycloneDX, just less specific) is preferable to a parser that
// risks accepting non-SPDX text as valid syntax.
func isSPDXExpression(s string) bool {
	if !strings.Contains(s, " AND ") && !strings.Contains(s, " OR ") {
		return false
	}
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return r == '(' || r == ')' || r == ' '
	})
	sawOperator := false
	for _, tok := range tokens {
		if tok == "AND" || tok == "OR" {
			sawOperator = true
			continue
		}
		if _, ok := spdxLicenseIDs[tok]; !ok {
			return false
		}
	}
	return sawOperator
}

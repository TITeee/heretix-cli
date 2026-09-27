package sbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestLicenseChoiceFor(t *testing.T) {
	tests := []struct {
		name    string
		license string
		want    cdx.LicenseChoice
	}{
		{"a single valid SPDX ID", "MIT", cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}},
		{"a dashed SPDX ID", "GPL-2.0-only", cdx.LicenseChoice{License: &cdx.License{ID: "GPL-2.0-only"}}},
		// The one shape npm's package.json and Composer reliably produce.
		{"a compound SPDX expression", "MIT AND GPL-2.0-or-later", cdx.LicenseChoice{Expression: "MIT AND GPL-2.0-or-later"}},
		{"a parenthesized SPDX expression", "Apache-2.0 AND (MIT OR ISC)", cdx.LicenseChoice{Expression: "Apache-2.0 AND (MIT OR ISC)"}},
		// rpm's License: tag — real values collected from a Rocky Linux 9 image
		// (see collector/rpm.go). None of these are valid SPDX: "GPLv2+"/"ASL 2.0"
		// aren't SPDX identifiers, "and"/"or" are lowercase, and "Public Domain"/
		// "with advertising" are free text — every one must land in license.name,
		// not license.expression, or the emitted document violates the CycloneDX
		// schema's "A valid SPDX license expression" requirement on that field.
		{"rpm-style lowercase 'and'", "GPLv2+ and MIT", cdx.LicenseChoice{License: &cdx.License{Name: "GPLv2+ and MIT"}}},
		{"a non-SPDX identifier with a trailing '+'", "GPLv2+", cdx.LicenseChoice{License: &cdx.License{Name: "GPLv2+"}}},
		{"a non-SPDX abbreviation", "ASL 2.0", cdx.LicenseChoice{License: &cdx.License{Name: "ASL 2.0"}}},
		{"free text, no SPDX identifier at all", "Public Domain", cdx.LicenseChoice{License: &cdx.License{Name: "Public Domain"}}},
		{"an SPDX id with non-SPDX free text appended", "BSD with advertising", cdx.LicenseChoice{License: &cdx.License{Name: "BSD with advertising"}}},
		{"a descriptive name, not an SPDX id", "MIT License", cdx.LicenseChoice{License: &cdx.License{Name: "MIT License"}}},
		// One real identifier plus one that isn't: the whole expression must be
		// rejected — a partially-valid compound string is not itself valid SPDX.
		{"mixed valid and invalid identifiers", "MIT AND GPLv2+", cdx.LicenseChoice{License: &cdx.License{Name: "MIT AND GPLv2+"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := licenseChoiceFor(tt.license)
			if got.Expression != tt.want.Expression {
				t.Errorf("Expression = %q, want %q", got.Expression, tt.want.Expression)
			}
			gotLicense, wantLicense := got.License, tt.want.License
			if (gotLicense == nil) != (wantLicense == nil) {
				t.Fatalf("License = %v, want %v", gotLicense, wantLicense)
			}
			if gotLicense != nil && (gotLicense.ID != wantLicense.ID || gotLicense.Name != wantLicense.Name) {
				t.Errorf("License = %+v, want %+v", gotLicense, wantLicense)
			}
		})
	}
}

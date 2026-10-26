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
		// Fedora's legacy names with a fixed meaning are converted (normalizeLicense).
		{"rpm-style lowercase 'and'", "GPLv2+ and MIT", cdx.LicenseChoice{Expression: "GPL-2.0-or-later AND MIT"}},
		{"a Fedora legacy identifier", "GPLv2+", cdx.LicenseChoice{License: &cdx.License{ID: "GPL-2.0-or-later"}}},
		{"a Fedora legacy abbreviation", "ASL 2.0", cdx.LicenseChoice{License: &cdx.License{ID: "Apache-2.0"}}},
		{"an ambiguous Fedora name stays free text", "LGPLv2+", cdx.LicenseChoice{License: &cdx.License{Name: "LGPLv2+"}}},
		{"free text, no SPDX identifier at all", "Public Domain", cdx.LicenseChoice{License: &cdx.License{Name: "Public Domain"}}},
		{"an SPDX id with non-SPDX free text appended", "BSD with advertising", cdx.LicenseChoice{License: &cdx.License{Name: "BSD with advertising"}}},
		{"a descriptive name, not an SPDX id", "MIT License", cdx.LicenseChoice{License: &cdx.License{Name: "MIT License"}}},
		// One real identifier plus one that isn't: the whole expression must be
		// rejected — a partially-valid compound string is not itself valid SPDX.
		{"mixed valid and invalid identifiers", "MIT AND Public Domain", cdx.LicenseChoice{License: &cdx.License{Name: "MIT AND Public Domain"}}},
		// DEP-5 short names from Debian copyright files.
		{"DEP-5 names joined by AND", "GPL-2+ and (BSD-3-clause or Expat)", cdx.LicenseChoice{Expression: "GPL-2.0-or-later AND (BSD-3-Clause OR MIT)"}},
		{"an SPDX ID in another case", "zlib", cdx.LicenseChoice{License: &cdx.License{ID: "Zlib"}}},
		// Deprecated SPDX IDs are still on the list; they become the current ones.
		{"a deprecated SPDX ID", "LGPL-2.1+", cdx.LicenseChoice{License: &cdx.License{ID: "LGPL-2.1-or-later"}}},
		{"a deprecated SPDX ID in an expression", "MIT AND GPL-2.0", cdx.LicenseChoice{Expression: "MIT AND GPL-2.0-only"}},
		{"a DEP-5 exception stays free text", "GPL-2+ with OpenSSL exception", cdx.LicenseChoice{License: &cdx.License{Name: "GPL-2+ with OpenSSL exception"}}},
		// IDs added to the SPDX list after 3.17; RHEL 10 writes them (glibc's license).
		{"an ID newer than SPDX 3.17", "SunPro", cdx.LicenseChoice{License: &cdx.License{ID: "SunPro"}}},
		{"newer IDs and an exception in an expression", "LGPL-2.1-or-later AND Unicode-3.0 AND GPL-3.0-or-later WITH Texinfo-exception", cdx.LicenseChoice{Expression: "LGPL-2.1-or-later AND Unicode-3.0 AND GPL-3.0-or-later WITH Texinfo-exception"}},
		// RHEL's kernel license is SPDX already, with exceptions.
		{"an SPDX exception", "GPL-2.0-only WITH Linux-syscall-note", cdx.LicenseChoice{Expression: "GPL-2.0-only WITH Linux-syscall-note"}},
		{"an exception inside an expression", "(GPL-2.0-only WITH Linux-syscall-note) OR MIT", cdx.LicenseChoice{Expression: "(GPL-2.0-only WITH Linux-syscall-note) OR MIT"}},
		{"a LicenseRef", "MIT AND LicenseRef-Fedora-Public-Domain", cdx.LicenseChoice{Expression: "MIT AND LicenseRef-Fedora-Public-Domain"}},
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

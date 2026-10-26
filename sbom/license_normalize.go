package sbom

import "strings"

// licenseAliases maps the license names package managers use to SPDX license IDs.
//
// Only names whose meaning is fixed are listed. Debian's copyright files use the
// short names DEP-5 defines (https://dep-team.pages.debian.net/deps/dep5/), and
// rpm's License tag the names Fedora used before it moved to SPDX (RHEL 9 and
// earlier). A name that could mean more than one license is left out on purpose
// and stays free text: Fedora's "LGPLv2" was used for both 2.0 and 2.1, "BSD"
// for any of several clause counts, and DEP-5's "Artistic" for both Perl's and
// the original Artistic License. A wrong SPDX ID would state a license the
// package is not under, which is worse than a name a reader has to look up.
var licenseAliases = map[string]string{
	// DEP-5
	"GPL-1": "GPL-1.0-only", "GPL-1+": "GPL-1.0-or-later",
	"GPL-2": "GPL-2.0-only", "GPL-2+": "GPL-2.0-or-later",
	"GPL-3": "GPL-3.0-only", "GPL-3+": "GPL-3.0-or-later",
	"LGPL-2": "LGPL-2.0-only", "LGPL-2+": "LGPL-2.0-or-later",
	"LGPL-2.1": "LGPL-2.1-only", "LGPL-2.1+": "LGPL-2.1-or-later",
	"LGPL-3": "LGPL-3.0-only", "LGPL-3+": "LGPL-3.0-or-later",
	"AGPL-3": "AGPL-3.0-only", "AGPL-3+": "AGPL-3.0-or-later",
	"GFDL-1.2": "GFDL-1.2-only", "GFDL-1.2+": "GFDL-1.2-or-later",
	"GFDL-1.3": "GFDL-1.3-only", "GFDL-1.3+": "GFDL-1.3-or-later",
	"Expat": "MIT",
	// Fedora's legacy names
	"GPL+":  "GPL-1.0-or-later",
	"GPLv2": "GPL-2.0-only", "GPLv2+": "GPL-2.0-or-later",
	"GPLv3": "GPL-3.0-only", "GPLv3+": "GPL-3.0-or-later",
	"LGPLv3": "LGPL-3.0-only", "LGPLv3+": "LGPL-3.0-or-later",
	"AGPLv3": "AGPL-3.0-only", "AGPLv3+": "AGPL-3.0-or-later",
	"ASL 2.0": "Apache-2.0", "ASL 1.1": "Apache-1.1",
	"MPLv1.1": "MPL-1.1", "MPLv2.0": "MPL-2.0",
	"Artistic 2.0": "Artistic-2.0",
	"Boost":        "BSL-1.0",
	"CC0":          "CC0-1.0",
}

// spdxIDsByLower finds an SPDX ID written in another case ("BSD-3-clause", "zlib").
var spdxIDsByLower = func() map[string]string {
	m := make(map[string]string, len(spdxLicenseIDs))
	for id := range spdxLicenseIDs {
		m[strings.ToLower(id)] = id
	}
	return m
}()

// spdxIDFor returns the SPDX ID a license name stands for, or "" when it has none.
func spdxIDFor(name string) string {
	if _, ok := spdxLicenseIDs[name]; ok {
		return name
	}
	if id, ok := licenseAliases[name]; ok {
		return id
	}
	return spdxIDsByLower[strings.ToLower(name)]
}

// normalizeLicense rewrites a license string as an SPDX expression when every
// license in it has a known SPDX ID: "GPL-2+ and BSD-3-clause" becomes
// "GPL-2.0-or-later AND BSD-3-Clause", "GPLv2+ or ASL 2.0" becomes
// "GPL-2.0-or-later OR Apache-2.0". Operators may be in either case, licenses
// may be several words ("ASL 2.0"), parentheses are kept, and "WITH" takes an
// SPDX exception ID ("GPL-2.0-only WITH Linux-syscall-note", as RHEL writes its
// kernel license). If any license or exception is unknown (DEP-5's "with OpenSSL
// exception"), or the string uses an operator this does not read (DEP-5's
// comma), the string is returned unchanged and ends up as free text: a partly
// converted string would claim more than is known.
func normalizeLicense(s string) string {
	var out []string
	var name []string
	inException := false
	flush := func() bool {
		if len(name) == 0 {
			return !inException
		}
		joined := strings.Join(name, " ")
		name = name[:0]
		if inException {
			inException = false
			id := spdxIDsByLower[strings.ToLower(joined)]
			if id == "" || len(out) == 0 {
				return false
			}
			out[len(out)-1] += " WITH " + id
			return true
		}
		id := spdxIDFor(joined)
		if id == "" && strings.HasPrefix(joined, "LicenseRef-") && !strings.Contains(joined, " ") {
			id = joined
		}
		if id == "" {
			return false
		}
		out = append(out, id)
		return true
	}
	fields := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s))
	for _, f := range fields {
		switch strings.ToLower(f) {
		case "and", "or":
			if !flush() || len(out) == 0 || out[len(out)-1] == "(" {
				return s
			}
			out = append(out, strings.ToUpper(f))
		case "(", ")":
			if !flush() {
				return s
			}
			out = append(out, f)
		case "with":
			if inException || !flush() || len(out) == 0 {
				return s
			}
			inException = true
		default:
			if strings.Contains(f, ",") {
				return s
			}
			name = append(name, f)
		}
	}
	if !flush() || len(out) == 0 {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(strings.Join(out, " "), "( ", "("), " )", ")")
}

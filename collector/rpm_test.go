package collector

import "testing"

// TestCleanRPMVersion guards against a real epoch being stripped alongside
// rpm's "(none)" placeholder for an unset epoch. See heretix-cli bug report
// 2026-08-30: sending epoch-less versions to heretix-api made already-patched
// packages with a nonzero epoch (e.g. shadow-utils) look older than ancient,
// already-fixed advisories, producing dozens of false-positive CVEs.
func TestCleanRPMVersion(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"unset epoch placeholder", "(none):7.88.1-4.el9", "7.88.1-4.el9"},
		{"explicit zero epoch", "0:2.36.1-8.el9", "2.36.1-8.el9"},
		{"real epoch is preserved", "2:4.9-6.el9", "2:4.9-6.el9"},
		{"no colon at all", "7.88.1-4.el9", "7.88.1-4.el9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanRPMVersion(tt.raw); got != tt.want {
				t.Errorf("cleanRPMVersion(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

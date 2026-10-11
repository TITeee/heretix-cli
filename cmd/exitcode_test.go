package cmd

import (
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/checker"
)

func TestCheckExitCode(t *testing.T) {
	complete := &checker.CheckResult{Queried: 10}
	partial := &checker.CheckResult{Queried: 10, Unchecked: 4, Errors: []string{"batch request failed: API returned 429: x"}}

	tests := map[string]struct {
		result                        *checker.CheckResult
		hasFindings, hasLocalFindings bool
		want                          int
	}{
		"complete, nothing found":                 {complete, false, false, 0},
		"complete, vulnerabilities found":         {complete, true, false, 1},
		"complete, only local findings":           {complete, false, true, 1},
		"incomplete, nothing found in the rest":   {partial, false, false, 2},
		"incomplete, vulnerabilities in the rest": {partial, true, false, 2},
		"incomplete, local findings":              {partial, false, true, 2},
	}
	for name, tc := range tests {
		if got := checkExitCode(tc.result, tc.hasFindings, tc.hasLocalFindings); got != tc.want {
			t.Errorf("%s: checkExitCode = %d, want %d", name, got, tc.want)
		}
	}
}

func TestIncompleteWarning(t *testing.T) {
	if got := incompleteWarning(&checker.CheckResult{Queried: 5}); got != "" {
		t.Errorf("a complete check got a warning: %q", got)
	}
	got := incompleteWarning(&checker.CheckResult{Queried: 2500, Unchecked: 1000, Errors: []string{"x"}})
	for _, want := range []string{"1000 of 2500 packages could not be checked", "exit code is 2"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q should mention %q", got, want)
		}
	}
}

func TestIsRateLimited(t *testing.T) {
	if !isRateLimited([]string{"batch request failed: API returned 429: {}"}) {
		t.Error("a 429 error was not recognized")
	}
	if isRateLimited([]string{"batch request failed: API returned 401: no"}) {
		t.Error("a 401 error was taken for a 429")
	}
}

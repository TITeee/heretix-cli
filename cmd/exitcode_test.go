package cmd

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/pflag"

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

func TestTruncatedWarnings(t *testing.T) {
	r := &checker.CheckResult{Results: []checker.PackageResult{
		{Package: "lodash", Version: "4.17.20"},
		{Package: "Windows Server 2019", Version: "10.0.17763.1", Truncated: true, Total: 5128},
	}}
	got := truncatedWarnings(r)
	if len(got) != 1 {
		t.Fatalf("got %d warnings %q, want one for the truncated package", len(got), got)
	}
	for _, want := range []string{"Windows Server 2019 10.0.17763.1", "matched 5128 vulnerabilities", "most severe"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("warning %q should mention %q", got[0], want)
		}
	}
	if got := truncatedWarnings(&checker.CheckResult{}); got != nil {
		t.Errorf("no truncation got warnings: %q", got)
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

func TestCollectorSkip(t *testing.T) {
	// --skip is passed through as given.
	if got, err := collectorSkip(nil, []string{"npm"}); err != nil || len(got) != 1 || got[0] != "npm" {
		t.Errorf("--skip: got %v, %v", got, err)
	}
	// --only becomes every other collector.
	got, err := collectorSkip([]string{"windows"}, nil)
	if err != nil || len(got) == 0 {
		t.Fatalf("--only: got %v, %v", got, err)
	}
	for _, s := range got {
		if s == "windows" {
			t.Errorf("--only windows still skips windows: %v", got)
		}
	}
	// An unknown name is an error, not an empty SBOM.
	if _, err := collectorSkip([]string{"windoze"}, nil); err == nil || !strings.Contains(err.Error(), "unknown collector") {
		t.Errorf("--only windoze: err = %v, want an unknown-collector error", err)
	}
}

// --only and --skip contradict each other, so cobra refuses both together,
// before anything is collected.
func TestOnlyAndSkipAreExclusive(t *testing.T) {
	for _, name := range []string{"collect", "scan"} {
		t.Run(name, func(t *testing.T) {
			c, _, err := rootCmd.Find([]string{name})
			if err != nil || c.Flags().Lookup("only") == nil {
				t.Fatalf("%s has no --only (%v)", name, err)
			}
			t.Cleanup(func() {
				for _, flag := range []string{"only", "skip"} {
					f := c.Flags().Lookup(flag)
					f.Changed = false
					if sv, ok := f.Value.(pflag.SliceValue); ok {
						_ = sv.Replace(nil)
					}
				}
			})
			rootCmd.SetOut(io.Discard)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs([]string{name, "--only", "windows", "--skip", "npm"})
			err = rootCmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "none of the others can be") {
				t.Errorf("--only with --skip: err = %v, want a mutually-exclusive error", err)
			}
		})
	}
}

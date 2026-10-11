package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/TITeee/heretix-cli/checker"
	"github.com/spf13/cobra"
)

// version is set via -ldflags "-X github.com/TITeee/heretix-cli/cmd.version=..."
// at build time (see .goreleaser.yaml); a local `go build`/`go run` leaves it
// at "dev" since no linker flag is passed.
var version = "dev"

var rootCmd = &cobra.Command{
	Use:     "heretix-cli",
	Version: version,
	Short:   "CLI vulnerability scanner for OS and OSS packages",
	Long: `heretix-cli scans installed software (RPM, PyPI, npm) on Linux servers,
exports a detection list as JSON, and queries a vulnerability API
to find known vulnerabilities.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// resolveAPIKey returns the API key from the flag, else HERETIX_API_KEY.
// heretix-api rejects every request without a key, so check/scan call this
// before any work: a missing key then fails at once instead of after a
// collection that can take minutes.
func resolveAPIKey(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if k := os.Getenv("HERETIX_API_KEY"); k != "" {
		return k, nil
	}
	return "", fmt.Errorf("no API key: set --api-key or HERETIX_API_KEY (heretix-api rejects requests without one)")
}

// incompleteWarning describes a check that lost batches even after retries,
// or "" when every package was checked.
func incompleteWarning(r *checker.CheckResult) string {
	if len(r.Errors) == 0 {
		return ""
	}
	return fmt.Sprintf("Warning: the results are incomplete. %d of %d packages could not be checked "+
		"because their batch searches failed even after retries (see Errors below); "+
		"any findings in them are missing, so the exit code is 2.", r.Unchecked, r.Queried)
}

// checkExitCode is the exit code of check and scan: 2 when part of the check
// failed (the results can't be trusted to be complete, whatever they show),
// else 1 when there is anything to report, else 0.
func checkExitCode(r *checker.CheckResult, hasFindings, hasLocalFindings bool) int {
	switch {
	case len(r.Errors) > 0:
		return 2
	case hasFindings || hasLocalFindings:
		return 1
	}
	return 0
}

// explainCheckFailure prints a check that produced no results and why, with
// the likeliest fix: a wrong key, a rate-limited API, a partial failure, or a
// wrong or stopped API.
func explainCheckFailure(r *checker.CheckResult, apiURL string) {
	for _, e := range r.Errors {
		fmt.Fprintf(os.Stderr, "Error: %s\n", e)
	}
	switch {
	case isAuthError(r.Errors):
		fmt.Fprintln(os.Stderr, "Authentication failed: please set --api-key or HERETIX_API_KEY.")
	case r.Unchecked < r.Queried:
		// Some batches got through, so the API is up and the URL is right.
		fmt.Fprintln(os.Stderr, incompleteWarning(r))
	case isRateLimited(r.Errors):
		fmt.Fprintln(os.Stderr, "heretix-api kept refusing the batch searches (429) even after retries: other clients may be using it. "+
			"Try again later, or raise BATCH_SEARCH_MAX_CONCURRENT / RATE_LIMIT_BATCH_MAX on heretix-api.")
	default:
		fmt.Fprintf(os.Stderr, "Please verify --api-url (%s) is correct and the API is running.\n", apiURL)
	}
}

// isRateLimited reports whether any error message indicates a 429 response.
func isRateLimited(errs []string) bool {
	for _, e := range errs {
		if strings.Contains(e, "API returned 429") {
			return true
		}
	}
	return false
}

// isAuthError reports whether any error message indicates a 401 response.
func isAuthError(errs []string) bool {
	for _, e := range errs {
		if strings.Contains(e, "401") {
			return true
		}
	}
	return false
}

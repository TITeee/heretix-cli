package cmd

import (
	"fmt"
	"os"
	"strings"

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

// isAuthError reports whether any error message indicates a 401 response.
func isAuthError(errs []string) bool {
	for _, e := range errs {
		if strings.Contains(e, "401") {
			return true
		}
	}
	return false
}

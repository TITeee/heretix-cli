package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"github.com/TITeee/heretix-cli/checker"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/report"
)

var checkCmd = &cobra.Command{
	Use:   "check <file.json>",
	Short: "Check inventory JSON against the vulnerability API",
	Long:  `Reads an inventory JSON file and queries the vulnerability API to find known vulnerabilities.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runCheck,
}

var (
	checkAPIURL      string
	checkAPIKey      string
	checkFormat      string
	checkSeverity    float64
	checkConcurrency int
	checkTimeout     string
	checkVerbose     bool
)

func init() {
	checkCmd.Flags().StringVar(&checkAPIURL, "api-url", "http://localhost:3001", "Vulnerability API URL")
	checkCmd.Flags().StringVar(&checkAPIKey, "api-key", "", "API key for authentication (or set HERETIX_API_KEY)")
	checkCmd.Flags().StringVar(&checkFormat, "format", "table", "Output format: table / json")
	checkCmd.Flags().Float64Var(&checkSeverity, "severity", 0.0, "Minimum CVSS score threshold")
	checkCmd.Flags().IntVar(&checkConcurrency, "concurrency", 10, "Concurrent API requests")
	checkCmd.Flags().StringVar(&checkTimeout, "timeout", "30s", "Per-request timeout")
	checkCmd.Flags().BoolVar(&checkVerbose, "verbose", false, "Enable verbose logging")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	if checkVerbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	}

	filePath := args[0]
	inv, err := inventory.ReadFromFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read %s: %v\n", filePath, err)
		os.Exit(2)
	}

	timeout, err := time.ParseDuration(checkTimeout)
	if err != nil {
		return fmt.Errorf("invalid timeout %q: %w", checkTimeout, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	fmt.Fprintf(os.Stderr, "Checking %d packages against %s...\n", len(inv.Packages), checkAPIURL)

	apiKey := checkAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("HERETIX_API_KEY")
	}

	opts := checker.Options{
		APIURL:      checkAPIURL,
		APIKey:      apiKey,
		Concurrency: checkConcurrency,
		Timeout:     timeout,
		Severity:    checkSeverity,
		Verbose:     checkVerbose,
	}

	result, err := checker.Check(ctx, inv, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: API check failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please verify --api-url (%s) is correct and the API is running.\n", checkAPIURL)
		os.Exit(2)
	}
	if len(result.Results) == 0 && len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		}
		if isAuthError(result.Errors) {
			fmt.Fprintln(os.Stderr, "Authentication failed: please set --api-key or HERETIX_API_KEY.")
		} else {
			fmt.Fprintf(os.Stderr, "Please verify --api-url (%s) is correct and the API is running.\n", checkAPIURL)
		}
		os.Exit(2)
	}

	switch checkFormat {
	case "json":
		if err := report.PrintJSON(os.Stdout, result, nil); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}
	default:
		report.PrintTable(os.Stdout, inv, result, filePath)
	}

	// Exit code 1 if vulnerabilities found (for CI/CD)
	if len(result.Results) > 0 {
		os.Exit(1)
	}
	return nil
}

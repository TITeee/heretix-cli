package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/TITeee/heretix-cli/checker"
	"github.com/TITeee/heretix-cli/collector"
	"github.com/TITeee/heretix-cli/container"
	"github.com/TITeee/heretix-cli/detector"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/report"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Collect packages and check vulnerabilities in one step",
	Long:  `Runs collect and check together without an intermediate file.`,
	RunE:  runScan,
}

var (
	scanScanPath    string
	scanSkip        []string
	scanSkipLocal   bool
	scanAPIURL      string
	scanAPIKey      string
	scanFormat      string
	scanSeverity    float64
	scanConcurrency int
	scanTimeout     string
	scanVerbose     bool
	scanImage       string
	scanDockerfile  string
)

func init() {
	// collect flags
	scanCmd.Flags().StringVar(&scanScanPath, "scan-path", "/", "Filesystem root path to scan")
	scanCmd.Flags().StringSliceVar(&scanSkip, "skip", nil, "Sources to skip (e.g. --skip npm,pypi)")
	scanCmd.Flags().BoolVar(&scanSkipLocal, "skip-local", false, "Skip local security checks (GlassWorm, Dependency Confusion)")
	// check flags
	scanCmd.Flags().StringVar(&scanAPIURL, "api-url", "http://localhost:3001", "Vulnerability API URL")
	scanCmd.Flags().StringVar(&scanAPIKey, "api-key", "", "API key for authentication (or set HERETIX_API_KEY)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "table", "Output format: table / json")
	scanCmd.Flags().Float64Var(&scanSeverity, "severity", 0.0, "Minimum CVSS score threshold")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 10, "Concurrent API requests")
	scanCmd.Flags().StringVar(&scanTimeout, "timeout", "30s", "Per-request timeout")
	scanCmd.Flags().BoolVar(&scanVerbose, "verbose", false, "Enable verbose logging")
	scanCmd.Flags().StringVar(&scanImage, "image", "", "Docker image to scan (e.g. nginx:latest, registry.example.com/app:v1)")
	scanCmd.Flags().StringVar(&scanDockerfile, "dockerfile", "", "Dockerfile path: also scan the base image from its FROM instruction")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if scanVerbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	}

	timeout, err := time.ParseDuration(scanTimeout)
	if err != nil {
		return fmt.Errorf("invalid timeout %q: %w", scanTimeout, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var inv *inventory.Inventory
	var localFindings []detector.Finding

	if scanImage != "" {
		inv, localFindings, err = collectFromImages(ctx)
	} else {
		inv, err = collectFromFilesystem()
		if err == nil && !scanSkipLocal {
			localFindings, _ = detector.RunAll(scanScanPath, scanVerbose)
		}
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Collected %d packages\n", len(inv.Packages))
	fmt.Fprintf(os.Stderr, "Checking against %s...\n", scanAPIURL)

	apiKey := scanAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("HERETIX_API_KEY")
	}

	opts := checker.Options{
		APIURL:      scanAPIURL,
		APIKey:      apiKey,
		Concurrency: scanConcurrency,
		Timeout:     timeout,
		Severity:    scanSeverity,
		Verbose:     scanVerbose,
	}

	result, err := checker.Check(ctx, inv, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: API check failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please verify --api-url (%s) is correct and the API is running.\n", scanAPIURL)
		os.Exit(2)
	}
	if len(result.Results) == 0 && len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		}
		if isAuthError(result.Errors) {
			fmt.Fprintln(os.Stderr, "Authentication failed: please set --api-key or HERETIX_API_KEY.")
		} else {
			fmt.Fprintf(os.Stderr, "Please verify --api-url (%s) is correct and the API is running.\n", scanAPIURL)
		}
		os.Exit(2)
	}

	scanLabel := scanScanPath
	if scanImage != "" {
		scanLabel = scanImage
	}

	switch scanFormat {
	case "json":
		if err := report.PrintJSON(os.Stdout, result, localFindings); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}
	default:
		report.PrintTable(os.Stdout, inv, result, scanLabel)
		if len(localFindings) > 0 {
			report.PrintFindings(os.Stdout, localFindings)
		}
	}

	if len(result.Results) > 0 || len(localFindings) > 0 {
		os.Exit(1)
	}
	return nil
}

func collectFromFilesystem() (*inventory.Inventory, error) {
	fmt.Fprintf(os.Stderr, "Scanning packages (scan-path: %s)...\n", scanScanPath)
	if len(scanSkip) > 0 {
		fmt.Fprintf(os.Stderr, "Skipping: %s\n", strings.Join(scanSkip, ", "))
	}
	return collector.CollectAll(scanScanPath, scanSkip, scanVerbose, false)
}

func collectFromImages(ctx context.Context) (*inventory.Inventory, []detector.Finding, error) {
	images := []string{scanImage}

	// Phase 3: also scan base image from Dockerfile
	if scanDockerfile != "" {
		baseRef, err := container.ParseFromDirective(scanDockerfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse FROM from %s: %v\n", scanDockerfile, err)
		} else if baseRef != "" {
			fmt.Fprintf(os.Stderr, "Dockerfile base image detected: %s\n", baseRef)
			images = append(images, baseRef)
		}
	}

	var allPkgs []inventory.Package
	var allFindings []detector.Finding
	var combinedInv *inventory.Inventory

	for _, imageRef := range images {
		fmt.Fprintf(os.Stderr, "Loading image %s...\n", imageRef)
		rootfs, cleanup, err := container.ExtractImage(ctx, imageRef, scanVerbose)
		if err != nil {
			return nil, nil, fmt.Errorf("extract image %s: %w", imageRef, err)
		}

		fmt.Fprintf(os.Stderr, "Scanning image %s...\n", imageRef)
		inv, err := collector.CollectAll(rootfs, scanSkip, scanVerbose, true)
		if err == nil && !scanSkipLocal {
			if findings, detErr := detector.RunAll(rootfs, scanVerbose); detErr == nil {
				allFindings = append(allFindings, findings...)
			}
		}
		cleanup()
		if err != nil {
			return nil, nil, fmt.Errorf("collection failed for %s: %w", imageRef, err)
		}

		if combinedInv == nil {
			combinedInv = inv
		}
		allPkgs = append(allPkgs, inv.Packages...)
	}

	combinedInv.Packages = inventory.Deduplicate(allPkgs)
	combinedInv.Type = "docker_image"
	combinedInv.Hostname = scanImage
	return combinedInv, allFindings, nil
}

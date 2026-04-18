package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"github.com/TITeee/heretix-cli/container"
	"github.com/TITeee/heretix-cli/detector"
	"github.com/TITeee/heretix-cli/report"
)

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Run local security checks without vulnerability API",
	Long:  `Runs local security detectors (GlassWorm, Dependency Confusion, Malicious Install, CI/CD Poisoning, Hardcoded Secrets, Lock File Integrity) without calling the vulnerability API.`,
	RunE:  runDetect,
}

var (
	detectScanPath   string
	detectImage      string
	detectDockerfile string
	detectFormat     string
	detectVerbose    bool
)

func init() {
	detectCmd.Flags().StringVar(&detectScanPath, "scan-path", defaultScanPath(), "Filesystem root path to scan")
	detectCmd.Flags().StringVar(&detectImage, "image", "", "Docker image to scan (e.g. nginx:latest)")
	detectCmd.Flags().StringVar(&detectDockerfile, "dockerfile", "", "Dockerfile path: also scan the base image from its FROM instruction")
	detectCmd.Flags().StringVar(&detectFormat, "format", "table", "Output format: table / json")
	detectCmd.Flags().BoolVar(&detectVerbose, "verbose", false, "Enable verbose logging")
	rootCmd.AddCommand(detectCmd)
}

func runDetect(cmd *cobra.Command, args []string) error {
	if detectVerbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	}

	var findings []detector.Finding

	if detectImage != "" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		images := []string{detectImage}
		if detectDockerfile != "" {
			baseRef, err := container.ParseFromDirective(detectDockerfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not parse FROM from %s: %v\n", detectDockerfile, err)
			} else if baseRef != "" {
				fmt.Fprintf(os.Stderr, "Dockerfile base image detected: %s\n", baseRef)
				images = append(images, baseRef)
			}
		}

		for _, imageRef := range images {
			fmt.Fprintf(os.Stderr, "Loading image %s...\n", imageRef)
			rootfs, cleanup, err := container.ExtractImage(ctx, imageRef, detectVerbose)
			if err != nil {
				return fmt.Errorf("extract image %s: %w", imageRef, err)
			}
			fmt.Fprintf(os.Stderr, "Scanning image %s...\n", imageRef)
			f, _ := detector.RunAll(rootfs, detectVerbose, true)
			cleanup()
			findings = append(findings, f...)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Running local security checks (scan-path: %s)...\n", detectScanPath)
		findings, _ = detector.RunAll(detectScanPath, detectVerbose, false)
	}

	switch detectFormat {
	case "json":
		if err := report.PrintFindingsJSON(os.Stdout, findings); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}
	default:
		if len(findings) == 0 {
			fmt.Fprintln(os.Stdout, "No local security findings.")
		} else {
			report.PrintFindings(os.Stdout, findings)
		}
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
	return nil
}

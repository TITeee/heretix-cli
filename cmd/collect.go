package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/TITeee/heretix-cli/collector"
	"github.com/TITeee/heretix-cli/container"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

func defaultScanPath() string {
	if runtime.GOOS == "windows" {
		if drive := os.Getenv("SystemDrive"); drive != "" {
			return drive + "\\"
		}
		return `C:\`
	}
	return "/"
}

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Scan and collect installed packages to JSON",
	Long:  `Scans the system for installed RPM, PyPI, and npm packages and writes the detection list to a JSON file.`,
	RunE:  runCollect,
}

var (
	collectOutput     string
	collectScanPath   string
	collectSkip       []string
	collectVerbose    bool
	collectImage      string
	collectDockerfile string
	collectFormat     string
	collectName       string
)

func init() {
	collectCmd.Flags().StringVar(&collectOutput, "output", "", "Output file path (default: {name}.json, {scan-path-basename}.json, or inventory.json)")
	collectCmd.Flags().StringVar(&collectScanPath, "scan-path", defaultScanPath(), "Filesystem root path to scan")
	collectCmd.Flags().StringSliceVar(&collectSkip, "skip", nil, "Sources to skip (e.g. --skip npm,pypi)")
	collectCmd.Flags().BoolVar(&collectVerbose, "verbose", false, "Enable verbose logging")
	collectCmd.Flags().StringVar(&collectImage, "image", "", "Docker image to scan (e.g. nginx:latest, registry.example.com/app:v1)")
	collectCmd.Flags().StringVar(&collectDockerfile, "dockerfile", "", "Dockerfile path: also scan the base image from its FROM instruction")
	collectCmd.Flags().StringVar(&collectFormat, "format", "json", "Output format: json or cyclonedx")
	collectCmd.Flags().StringVar(&collectName, "name", "", "Override hostname in output (useful to distinguish multiple projects on the same host)")
	rootCmd.AddCommand(collectCmd)
}

func runCollect(cmd *cobra.Command, args []string) error {
	if collectVerbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	}

	if collectImage != "" {
		return runCollectWithImage()
	}

	fmt.Fprintf(os.Stderr, "Scanning packages (scan-path: %s)...\n", collectScanPath)
	if len(collectSkip) > 0 {
		fmt.Fprintf(os.Stderr, "Skipping: %s\n", strings.Join(collectSkip, ", "))
	}

	inv, err := collector.CollectAll(collectScanPath, collectSkip, collectVerbose, false)
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	if collectName != "" {
		inv.Hostname = collectName
	}

	out := resolveOutputPath()
	if err := writeCollectOutput(inv, out, collectFormat); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Collected %d packages -> %s\n", len(inv.Packages), out)
	return nil
}

func runCollectWithImage() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	images := []string{collectImage}

	// Phase 3: also scan base image from Dockerfile
	if collectDockerfile != "" {
		baseRef, err := container.ParseFromDirective(collectDockerfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse FROM from %s: %v\n", collectDockerfile, err)
		} else if baseRef != "" {
			fmt.Fprintf(os.Stderr, "Dockerfile base image detected: %s\n", baseRef)
			images = append(images, baseRef)
		}
	}

	var allPkgs []inventory.Package
	var combinedInv *inventory.Inventory

	var primaryDigest string
	for _, imageRef := range images {
		fmt.Fprintf(os.Stderr, "Loading image %s...\n", imageRef)
		rootfs, digest, cleanup, err := container.ExtractImage(ctx, imageRef, collectVerbose)
		if err != nil {
			return fmt.Errorf("extract image %s: %w", imageRef, err)
		}

		fmt.Fprintf(os.Stderr, "Scanning image %s...\n", imageRef)
		inv, err := collector.CollectAll(rootfs, collectSkip, collectVerbose, true)
		cleanup()
		if err != nil {
			return fmt.Errorf("collection failed for %s: %w", imageRef, err)
		}

		if combinedInv == nil {
			combinedInv = inv
			primaryDigest = digest
		}
		allPkgs = append(allPkgs, inv.Packages...)
	}

	combinedInv.Packages = inventory.Deduplicate(allPkgs)
	combinedInv.Type = "docker_image"
	combinedInv.ImageDigest = primaryDigest
	if collectName != "" {
		combinedInv.Hostname = collectName
	} else {
		combinedInv.Hostname = collectImage
	}

	out := resolveOutputPath()
	if err := writeCollectOutput(combinedInv, out, collectFormat); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Collected %d packages -> %s\n", len(combinedInv.Packages), out)
	return nil
}

// resolveOutputPath determines the output file path using the following priority:
//  1. --output (explicitly set)
//  2. --name + ".json"
//  3. basename of --scan-path + ".json" (skipped for root paths like "/" or "C:\")
//  4. "inventory.json"
func resolveOutputPath() string {
	if collectOutput != "" {
		return collectOutput
	}
	if collectName != "" {
		return collectName + ".json"
	}
	base := filepath.Base(collectScanPath)
	// Exclude root-like basenames (e.g. "/", "\", "C:\")
	if base != "" && base != "." && base != "/" && base != "\\" && !strings.HasSuffix(base, ":\\") {
		return base + ".json"
	}
	return "inventory.json"
}

func writeCollectOutput(inv *inventory.Inventory, path string, format string) error {
	if format == "cyclonedx" {
		bom := sbom.GenerateCycloneDX(inv, rootCmd.Version)
		if err := sbom.WriteToFile(bom, path); err != nil {
			return fmt.Errorf("write cyclonedx output: %w", err)
		}
		return nil
	}
	if err := inv.WriteToFile(path); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/TITeee/heretix-cli/management"
	"github.com/spf13/cobra"
)

var uploadCmd = &cobra.Command{
	Use:   "upload <sbom.json>",
	Short: "Upload an SBOM to heretix-management",
	Long: `Uploads a CycloneDX SBOM written by collect to heretix-management, which
imports it into the asset its hostname names (creating the asset if new).
heretix-management scans it on its own schedule, or from the asset's page.

Needs an access token with the "import" scope, created in heretix-management
under Settings -> Access Tokens.

Environment variables (used when the corresponding flag is not set):
  HERETIX_MANAGEMENT_URL    heretix-management's URL
  HERETIX_MANAGEMENT_TOKEN  Access token`,
	Args: cobra.ExactArgs(1),
	Run:  runUpload,
}

var (
	uploadURL         string
	uploadToken       string
	uploadHostname    string
	uploadDisplayName string
	uploadDryRun      bool
	uploadTimeout     string
)

func init() {
	uploadCmd.Flags().StringVar(&uploadURL, "url", "", "heretix-management URL, e.g. https://heretix.example.com (default: $HERETIX_MANAGEMENT_URL)")
	uploadCmd.Flags().StringVar(&uploadToken, "token", "", "Access token with the import scope (default: $HERETIX_MANAGEMENT_TOKEN)")
	uploadCmd.Flags().StringVar(&uploadHostname, "hostname", "", "Asset to import into, overriding the SBOM's own hostname")
	uploadCmd.Flags().StringVar(&uploadDisplayName, "display-name", "", "Asset display name; without it a new asset is named after its hostname and an existing one keeps its name (older heretix-management versions reset it to the hostname)")
	uploadCmd.Flags().BoolVar(&uploadDryRun, "dry-run", false, "Show which asset the upload would create or update, and its package changes, without importing")
	uploadCmd.Flags().StringVar(&uploadTimeout, "timeout", "5m", "Request timeout")
	rootCmd.AddCommand(uploadCmd)
}

func runUpload(cmd *cobra.Command, args []string) {
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "Error: "+format+"\n", a...)
		os.Exit(2)
	}

	// Everything is checked before the upload, so a CI job fails on a
	// missing setting at once rather than after reading a large SBOM.
	baseURL := firstNonEmpty(uploadURL, os.Getenv("HERETIX_MANAGEMENT_URL"))
	if baseURL == "" {
		fail("no heretix-management URL: set --url or HERETIX_MANAGEMENT_URL")
	}
	token := firstNonEmpty(uploadToken, os.Getenv("HERETIX_MANAGEMENT_TOKEN"))
	if token == "" {
		fail("no access token: set --token or HERETIX_MANAGEMENT_TOKEN (Settings -> Access Tokens in heretix-management, import scope)")
	}
	if _, err := management.ImportURL(baseURL); err != nil {
		fail("%v", err)
	}
	timeout, err := time.ParseDuration(uploadTimeout)
	if err != nil {
		fail("invalid --timeout %q: %v", uploadTimeout, err)
	}

	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fail("cannot read %s: %v", path, err)
	}
	if err := requireCycloneDX(data); err != nil {
		fail("cannot upload %s: %v", path, err)
	}

	if u, _ := url.Parse(baseURL); u != nil && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		fmt.Fprintln(os.Stderr, "Warning: sending the access token over plain HTTP; use https:// outside a trusted network.")
	}
	target := "the SBOM's own hostname"
	if uploadHostname != "" {
		target = "hostname " + uploadHostname
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	client := &management.Client{
		HTTP:      &http.Client{Timeout: timeout},
		BaseURL:   baseURL,
		Token:     token,
		UserAgent: "heretix-cli/" + rootCmd.Version,
	}
	opts := management.ImportOptions{Hostname: uploadHostname, Name: uploadDisplayName}

	if uploadDryRun {
		fmt.Fprintf(os.Stderr, "Dry run: checking what uploading %s to %s would do (asset: %s)...\n", path, baseURL, target)
		preview, err := client.Preview(ctx, data, opts)
		if err != nil {
			fail("dry run failed: %v%s", err, uploadHint(err))
		}
		fmt.Fprint(os.Stderr, describePreview(preview))
		return
	}

	fmt.Fprintf(os.Stderr, "Uploading %s to %s (asset: %s)...\n", path, baseURL, target)
	asset, err := client.Upload(ctx, data, opts)
	if err != nil {
		fail("upload failed: %v%s", err, uploadHint(err))
	}

	action := "Created"
	if asset.Updated {
		action = "Updated"
	}
	fmt.Fprintf(os.Stderr, "%s asset %q (hostname: %s). heretix-management scans it on its next scheduled scan, or run a scan from the asset's page.\n",
		action, asset.Name, asset.Hostname)
}

// describePreview renders a dry-run answer, ending in a note that nothing
// was imported.
func describePreview(p *management.Preview) string {
	var b strings.Builder
	if p.Existing == nil {
		fmt.Fprintf(&b, "Would create a new asset with hostname %s.\n", p.Hostname)
	} else {
		fmt.Fprintf(&b, "Would update asset %q (hostname: %s", p.Existing.Name, p.Existing.Hostname)
		if p.Existing.ScannedAt != "" {
			fmt.Fprintf(&b, ", last scanned %s", p.Existing.ScannedAt)
		}
		b.WriteString(").\n")
		if p.Diff != nil {
			fmt.Fprintf(&b, "  Packages: %d added, %d removed (%d of them upgraded to a new version)\n",
				p.Diff.Added, p.Diff.Removed, p.Diff.Superseded)
		}
	}
	b.WriteString("Nothing was imported (dry run).\n")
	return b.String()
}

// uploadHint explains the failures a misconfigured CI job most often hits.
func uploadHint(err error) string {
	var apiErr *management.APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	switch {
	case apiErr.Location != "":
		return "\n  --url must be heretix-management's own URL (the console's address); it answered with a redirect, usually to its login page"
	case apiErr.Status == http.StatusNotFound:
		return "\n  No import endpoint at that URL: --url must be heretix-management's, not heretix-api's"
	case apiErr.Status == http.StatusUnauthorized:
		return "\n  The access token is invalid, expired or revoked: check --token / HERETIX_MANAGEMENT_TOKEN"
	case apiErr.Status == http.StatusForbidden:
		return "\n  Create a token with the import scope under Settings -> Access Tokens"
	case apiErr.Status == http.StatusTooManyRequests:
		return "\n  Too many failed token attempts from this address; wait before retrying"
	}
	return ""
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

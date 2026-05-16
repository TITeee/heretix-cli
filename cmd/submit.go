package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/TITeee/heretix-cli/depgraph"
	"github.com/TITeee/heretix-cli/inventory"
)

var submitCmd = &cobra.Command{
	Use:   "submit <inventory.json>",
	Short: "Submit a dependency snapshot to GitHub Dependency Graph",
	Long: `Reads an inventory JSON and submits it to the GitHub Dependency Submission API.
Once submitted, Dependabot can generate vulnerability alerts based on the detected packages.

Environment variables (used when the corresponding flag is not set):
  GITHUB_TOKEN       GitHub token with contents:write permission
  GITHUB_REPOSITORY  Repository in owner/repo format
  GITHUB_SHA         Commit SHA to associate the snapshot with
  GITHUB_REF         Git ref (e.g. refs/heads/main)
  GITHUB_RUN_ID      Unique ID for the current workflow run (used as job ID)`,
	Args: cobra.ExactArgs(1),
	RunE: runSubmit,
}

var (
	submitToken       string
	submitRepo        string
	submitSHA         string
	submitRef         string
	submitCorrelator  string
	submitJobID       string
)

func init() {
	submitCmd.Flags().StringVar(&submitToken, "token", "", "GitHub token (default: $GITHUB_TOKEN)")
	submitCmd.Flags().StringVar(&submitRepo, "repo", "", "Repository owner/repo (default: $GITHUB_REPOSITORY)")
	submitCmd.Flags().StringVar(&submitSHA, "sha", "", "Commit SHA (default: $GITHUB_SHA)")
	submitCmd.Flags().StringVar(&submitRef, "ref", "", "Git ref, e.g. refs/heads/main (default: $GITHUB_REF)")
	submitCmd.Flags().StringVar(&submitCorrelator, "correlator", "heretix-cli", "Unique string identifying this detector (same value overwrites previous snapshot)")
	submitCmd.Flags().StringVar(&submitJobID, "job-id", "", "Unique ID for this run (default: $GITHUB_RUN_ID, then correlator)")
	rootCmd.AddCommand(submitCmd)
}

func runSubmit(cmd *cobra.Command, args []string) error {
	token := firstNonEmpty(submitToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return fmt.Errorf("GitHub token required: use --token or set GITHUB_TOKEN")
	}

	repo := firstNonEmpty(submitRepo, os.Getenv("GITHUB_REPOSITORY"))
	if repo == "" {
		return fmt.Errorf("repository required: use --repo or set GITHUB_REPOSITORY (owner/repo)")
	}

	sha := firstNonEmpty(submitSHA, os.Getenv("GITHUB_SHA"))
	if sha == "" {
		return fmt.Errorf("commit SHA required: use --sha or set GITHUB_SHA")
	}

	ref := firstNonEmpty(submitRef, os.Getenv("GITHUB_REF"), "refs/heads/main")
	jobID := firstNonEmpty(submitJobID, os.Getenv("GITHUB_RUN_ID"), submitCorrelator)

	inv, err := inventory.ReadFromFile(args[0])
	if err != nil {
		return fmt.Errorf("read inventory: %w", err)
	}

	snapshot := depgraph.BuildSnapshot(inv, sha, ref, submitCorrelator, jobID, rootCmd.Version)

	fmt.Fprintf(os.Stderr, "Submitting %d packages (%d manifests) to %s...\n",
		len(inv.Packages), len(snapshot.Manifests), repo)

	if err := depgraph.Submit(snapshot, token, repo); err != nil {
		return fmt.Errorf("submit: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Dependency snapshot submitted successfully.\n")
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

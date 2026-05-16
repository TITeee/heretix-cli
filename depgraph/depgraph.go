package depgraph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

// Snapshot is the payload for the GitHub Dependency Submission API.
// https://docs.github.com/en/rest/dependency-graph/dependency-submission
type Snapshot struct {
	Version   int                  `json:"version"`
	Sha       string               `json:"sha"`
	Ref       string               `json:"ref"`
	Job       Job                  `json:"job"`
	Detector  Detector             `json:"detector"`
	Scanned   string               `json:"scanned"`
	Manifests map[string]*Manifest `json:"manifests"`
}

type Job struct {
	Correlator string `json:"correlator"`
	ID         string `json:"id"`
}

type Detector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

type Manifest struct {
	Name     string               `json:"name"`
	File     *ManifestFile        `json:"file,omitempty"`
	Resolved map[string]*Resolved `json:"resolved"`
}

type ManifestFile struct {
	SourceLocation string `json:"source_location"`
}

type Resolved struct {
	PackageURL   string   `json:"package_url"`
	Relationship string   `json:"relationship"`
	Scope        string   `json:"scope"`
	Dependencies []string `json:"dependencies"`
}

// BuildSnapshot converts an Inventory into a GitHub Dependency Submission snapshot.
//
// Packages are grouped into manifests by their source file path (Location).
// OS packages without a location are grouped under their source type (e.g. "rpm").
// All packages are recorded as "indirect" because the inventory does not carry
// direct/transitive distinction.
func BuildSnapshot(inv *inventory.Inventory, sha, ref, correlator, jobID, version string) *Snapshot {
	manifests := make(map[string]*Manifest)

	for _, p := range inv.Packages {
		key, file := manifestFor(p)
		if _, ok := manifests[key]; !ok {
			manifests[key] = &Manifest{
				Name:     key,
				File:     file,
				Resolved: make(map[string]*Resolved),
			}
		}
		purl := sbom.PackagePURL(p, inv.OS.ID)

		relationship := "indirect"
		if p.Direct != nil && *p.Direct {
			relationship = "direct"
		}

		deps := make([]string, 0, len(p.Deps))
		deps = append(deps, p.Deps...)

		manifests[key].Resolved[purl] = &Resolved{
			PackageURL:   purl,
			Relationship: relationship,
			Scope:        "runtime",
			Dependencies: deps,
		}
	}

	scanned := inv.ScannedAt
	if scanned == "" {
		scanned = time.Now().UTC().Format(time.RFC3339)
	}

	return &Snapshot{
		Version: 0,
		Sha:     sha,
		Ref:     ref,
		Job: Job{
			Correlator: correlator,
			ID:         jobID,
		},
		Detector: Detector{
			Name:    "heretix-cli",
			Version: version,
			URL:     "https://github.com/TITeee/heretix-cli",
		},
		Scanned:   scanned,
		Manifests: manifests,
	}
}

// manifestFor returns the manifest key and optional file metadata for a package.
// Packages with a known location are grouped by that file path.
// OS packages (rpm, dpkg, apk) without a location are grouped by source type.
func manifestFor(p inventory.Package) (key string, file *ManifestFile) {
	if p.Location != "" {
		// Use the basename as the human-readable manifest name; keep the full
		// path as source_location so GitHub can link to the file in the repo.
		name := filepath.Base(p.Location)
		return name, &ManifestFile{SourceLocation: p.Location}
	}
	return p.Source, nil
}

// Submit posts the snapshot to the GitHub Dependency Submission API.
// repo must be in "owner/repo" format.
// token must have the "contents: write" permission (or the classic "repo" scope).
func Submit(snapshot *Snapshot, token, repo string) error {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid repo format, expected owner/repo: %q", repo)
	}

	body, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/dependency-graph/snapshots",
		parts[0], parts[1])
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST to GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck
		return fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, errBody.Message)
	}
	return nil
}

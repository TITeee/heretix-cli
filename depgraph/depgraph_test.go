package depgraph

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

func TestManifestFor(t *testing.T) {
	t.Run("groups a package with a known location by that file, basename as the manifest name", func(t *testing.T) {
		key, file := manifestFor(inventory.Package{Location: "src/backend/package.json"})
		if key != "package.json" {
			t.Errorf("key = %q, want %q", key, "package.json")
		}
		if file == nil || file.SourceLocation != "src/backend/package.json" {
			t.Errorf("file = %+v, want SourceLocation to be the full path", file)
		}
	})

	t.Run("groups a location-less OS package by its source type", func(t *testing.T) {
		key, file := manifestFor(inventory.Package{Source: "rpm"})
		if key != "rpm" {
			t.Errorf("key = %q, want %q", key, "rpm")
		}
		if file != nil {
			t.Errorf("file = %+v, want nil for an OS package with no location", file)
		}
	})
}

func TestBuildSnapshot(t *testing.T) {
	inv := &inventory.Inventory{
		OS:        inventory.OSInfo{ID: "alpine"},
		ScannedAt: "2026-01-01T00:00:00Z",
		Packages: []inventory.Package{
			{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", Source: "package-lock.json", Location: "package.json", Direct: inventory.BoolPtr(true)},
			{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm", Source: "package-lock.json", Location: "package.json", Direct: inventory.BoolPtr(false), Deps: []string{"pkg:npm/other@1.0.0"}},
			{Name: "curl", Version: "8.5.0", Ecosystem: "apk", Source: "apk"},
		},
	}

	snap := BuildSnapshot(inv, "abc123", "refs/heads/main", "corr-1", "job-1", "1.2.3")

	if snap.Sha != "abc123" || snap.Ref != "refs/heads/main" {
		t.Errorf("unexpected Sha/Ref: %+v", snap)
	}
	if snap.Job.Correlator != "corr-1" || snap.Job.ID != "job-1" {
		t.Errorf("unexpected Job: %+v", snap.Job)
	}
	if snap.Detector.Version != "1.2.3" {
		t.Errorf("Detector.Version = %q, want %q", snap.Detector.Version, "1.2.3")
	}
	if snap.Scanned != "2026-01-01T00:00:00Z" {
		t.Errorf("Scanned = %q, want the inventory's own ScannedAt", snap.Scanned)
	}

	if len(snap.Manifests) != 2 {
		t.Fatalf("expected 2 manifests (package.json, apk), got %d: %+v", len(snap.Manifests), snap.Manifests)
	}
	pkgJSON := snap.Manifests["package.json"]
	if pkgJSON == nil || len(pkgJSON.Resolved) != 2 {
		t.Fatalf("expected 2 resolved packages under package.json, got %+v", pkgJSON)
	}

	lodashPURL := "pkg:npm/lodash@4.17.21"
	if r, ok := pkgJSON.Resolved[lodashPURL]; !ok || r.Relationship != "direct" {
		t.Errorf("expected lodash to be resolved as direct, got %+v", pkgJSON.Resolved[lodashPURL])
	}
	leftPadPURL := "pkg:npm/left-pad@1.3.0"
	if r, ok := pkgJSON.Resolved[leftPadPURL]; !ok || r.Relationship != "indirect" || len(r.Dependencies) != 1 {
		t.Errorf("expected left-pad to be resolved as indirect with its dependency, got %+v", pkgJSON.Resolved[leftPadPURL])
	}
}

func TestBuildSnapshot_FallsBackToNowWhenScannedAtIsEmpty(t *testing.T) {
	inv := &inventory.Inventory{}
	snap := BuildSnapshot(inv, "sha", "ref", "corr", "job", "1.0")
	if snap.Scanned == "" {
		t.Error("expected Scanned to fall back to the current time, got empty string")
	}
}

func TestSubmit(t *testing.T) {
	t.Run("posts to the expected path with the expected headers and body", func(t *testing.T) {
		var gotPath, gotAuth string
		var gotBody map[string]json.RawMessage
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()
		withAPIBaseURL(t, server.URL)

		snap := &Snapshot{Sha: "abc123"}
		if err := Submit(snap, "my-token", "owner/repo"); err != nil {
			t.Fatalf("Submit returned an error: %v", err)
		}

		if gotPath != "/repos/owner/repo/dependency-graph/snapshots" {
			t.Errorf("path = %q, want the dependency-graph snapshots endpoint", gotPath)
		}
		if gotAuth != "Bearer my-token" {
			t.Errorf("Authorization = %q, want a Bearer token", gotAuth)
		}
		if _, ok := gotBody["sha"]; !ok {
			t.Error("expected the snapshot body to be posted as JSON")
		}
	})

	t.Run("returns an error for an invalid repo format", func(t *testing.T) {
		if err := Submit(&Snapshot{}, "token", "not-owner-slash-repo"); err == nil {
			t.Error("expected an error for a repo string with no slash")
		}
	})

	t.Run("returns an error including the GitHub message on a non-201 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by integration"})
		}))
		defer server.Close()
		withAPIBaseURL(t, server.URL)

		err := Submit(&Snapshot{}, "token", "owner/repo")
		if err == nil {
			t.Fatal("expected an error for a 403 response")
		}
		if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "Resource not accessible by integration") {
			t.Errorf("error %q should mention the status and GitHub's message", err.Error())
		}
	})
}

// withAPIBaseURL points Submit at a test server for the duration of the
// calling test, restoring the real GitHub API URL afterward.
func withAPIBaseURL(t *testing.T, url string) {
	t.Helper()
	prev := apiBaseURL
	apiBaseURL = url
	t.Cleanup(func() { apiBaseURL = prev })
}

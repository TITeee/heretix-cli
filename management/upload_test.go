package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sbom = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`

func newClient(server *httptest.Server) *Client {
	return &Client{HTTP: server.Client(), BaseURL: server.URL, Token: "hx_secret", UserAgent: "heretix-cli/test"}
}

// importRequest is the body heretix-management's import route reads.
type importRequest struct {
	Inventory json.RawMessage `json:"inventory"`
	Hostname  string          `json:"hostname"`
	Name      string          `json:"name"`
	DryRun    bool            `json:"dryRun"`
}

func TestImportURL(t *testing.T) {
	tests := map[string]struct {
		base, want string
		wantErr    bool
	}{
		"plain host":                         {"https://heretix.example.com", "https://heretix.example.com/api/assets", false},
		"trailing slash is not doubled":      {"https://heretix.example.com/", "https://heretix.example.com/api/assets", false},
		"path prefix behind a reverse proxy": {"https://example.com/heretix/", "https://example.com/heretix/api/assets", false},
		"a query string is dropped":          {"http://localhost:3000/?x=1", "http://localhost:3000/api/assets", false},
		"no scheme is rejected":              {"heretix.example.com", "", true},
		"non-http scheme is rejected":        {"ftp://heretix.example.com", "", true},
	}
	for name, tc := range tests {
		got, err := ImportURL(tc.base)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", name, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: ImportURL = %q, want %q", name, got, tc.want)
		}
	}
}

// The SBOM must arrive wrapped as {"inventory": <SBOM>} — the only form in
// which heretix-management also reads the display name and dry-run flag —
// with the SBOM itself unchanged.
func TestUpload_SendsTheWrappedSBOMWithTheToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/assets" {
			t.Errorf("request = %s %s, want POST /api/assets", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer hx_secret" {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var req importRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("request body is not JSON: %v", err)
		}
		if string(req.Inventory) != sbom {
			t.Errorf("inventory = %s, want the SBOM verbatim", req.Inventory)
		}
		if req.Hostname != "myapp" || req.Name != "My App" || req.DryRun {
			t.Errorf("request = %+v, want hostname myapp, name My App, no dry run", req)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"a1","name":"My App","hostname":"myapp"}`))
	}))
	defer server.Close()

	asset, err := newClient(server).Upload(context.Background(), []byte(sbom), ImportOptions{Hostname: "myapp", Name: "My App"})
	if err != nil {
		t.Fatalf("Upload returned an error: %v", err)
	}
	if asset.ID != "a1" || asset.Hostname != "myapp" || asset.Updated {
		t.Errorf("asset = %+v, want a newly created asset a1", asset)
	}
}

// Without options, the body carries only the SBOM: an empty hostname or name
// would otherwise be sent, and the server treats them as given.
func TestUpload_OmitsUnsetOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		for _, key := range []string{"hostname", "name", "dryRun"} {
			if _, ok := raw[key]; ok {
				t.Errorf("body has %q although it wasn't set", key)
			}
		}
		_, _ = w.Write([]byte(`{"id":"a1","name":"myapp","hostname":"myapp","updated":true}`))
	}))
	defer server.Close()

	asset, err := newClient(server).Upload(context.Background(), []byte(sbom), ImportOptions{})
	if err != nil {
		t.Fatalf("Upload returned an error: %v", err)
	}
	if !asset.Updated {
		t.Error("asset.Updated = false for a 200 response with updated: true")
	}
}

func TestPreview(t *testing.T) {
	t.Run("an existing asset with its package changes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req importRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if !req.DryRun {
				t.Error("Preview didn't set dryRun")
			}
			_, _ = w.Write([]byte(`{"hostname":"myapp","existing":{"id":"a1","name":"My App","hostname":"myapp","scannedAt":"2026-10-06T00:00:00Z"},"diff":{"added":12,"removed":3,"superseded":2}}`))
		}))
		defer server.Close()

		p, err := newClient(server).Preview(context.Background(), []byte(sbom), ImportOptions{})
		if err != nil {
			t.Fatalf("Preview returned an error: %v", err)
		}
		if p.Existing == nil || p.Existing.ID != "a1" || p.Diff == nil || p.Diff.Added != 12 || p.Diff.Superseded != 2 {
			t.Errorf("preview = %+v, want existing asset a1 with its diff", p)
		}
	})

	t.Run("a new asset", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"hostname":"newapp","existing":null}`))
		}))
		defer server.Close()

		p, err := newClient(server).Preview(context.Background(), []byte(sbom), ImportOptions{})
		if err != nil {
			t.Fatalf("Preview returned an error: %v", err)
		}
		if p.Hostname != "newapp" || p.Existing != nil {
			t.Errorf("preview = %+v, want a new asset newapp", p)
		}
	})
}

func TestUpload_Errors(t *testing.T) {
	tests := map[string]struct {
		handler     http.HandlerFunc
		wantStatus  int
		wantInError string
	}{
		"invalid token": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"Invalid or expired API token"}`))
			},
			wantStatus: 401, wantInError: "Invalid or expired API token",
		},
		"missing scope": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"API token lacks the required scope: import"}`))
			},
			wantStatus: 403, wantInError: "lacks the required scope",
		},
		// heretix-management redirects a request it won't take a token on
		// (wrong URL or path) to its login page; that must surface as a
		// redirect, not be followed into an HTML page.
		"redirect to the login page": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			},
			wantStatus: 307, wantInError: "redirect to /login",
		},
	}
	for name, tc := range tests {
		server := httptest.NewServer(tc.handler)
		_, err := newClient(server).Upload(context.Background(), []byte(sbom), ImportOptions{})
		server.Close()

		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Errorf("%s: err = %v, want an *APIError", name, err)
			continue
		}
		if apiErr.Status != tc.wantStatus || !strings.Contains(err.Error(), tc.wantInError) {
			t.Errorf("%s: err = %v (status %d), want status %d containing %q", name, err, apiErr.Status, tc.wantStatus, tc.wantInError)
		}
	}
}

func TestUpload_RejectsAResponseThatIsNotAnAsset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>not heretix-management</html>`))
	}))
	defer server.Close()

	if _, err := newClient(server).Upload(context.Background(), []byte(sbom), ImportOptions{}); err == nil {
		t.Error("Upload accepted an HTML 200 response as a successful import")
	}
}

// Package management is a client for heretix-management's API.
package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Asset is the part of heretix-management's import response heretix-cli uses.
type Asset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	// Updated is true when the import updated an existing asset (HTTP 200)
	// rather than creating one (HTTP 201).
	Updated bool `json:"updated"`
}

// Preview is heretix-management's answer to a dry-run import: the asset an
// import would update (nil for a new asset) and how its packages would change.
type Preview struct {
	Hostname string `json:"hostname"`
	Existing *struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Hostname  string `json:"hostname"`
		ScannedAt string `json:"scannedAt"`
	} `json:"existing"`
	Diff *struct {
		Added      int `json:"added"`
		Removed    int `json:"removed"`
		Superseded int `json:"superseded"` // upgrades; a subset of Removed
	} `json:"diff"`
}

// ImportOptions are the import request's optional fields.
type ImportOptions struct {
	// Hostname names the asset to import into, instead of the SBOM's own
	// metadata.component.name. Assets are matched by hostname.
	Hostname string
	// Name is the asset's display name. heretix-management sets the display
	// name to the hostname on an import that doesn't give one.
	Name string
}

// APIError is a non-success response from heretix-management.
type APIError struct {
	Status   int
	Message  string // the response's "error" field, when it has one
	Location string // the redirect target, for a 3xx response
}

func (e *APIError) Error() string {
	switch {
	case e.Location != "":
		return fmt.Sprintf("HTTP %d redirect to %s", e.Status, e.Location)
	case e.Message != "":
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	default:
		return fmt.Sprintf("HTTP %d", e.Status)
	}
}

// ImportURL returns the import endpoint under baseURL — heretix-management's
// own URL, which may sit under a path prefix behind a reverse proxy. The
// path must be exactly /api/assets: heretix-management only lets an access
// token through on that exact path, and sends anything else to its login page.
func ImportURL(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", baseURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q: want http(s)://host[:port][/path]", baseURL)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/assets"
	u.RawQuery = ""
	return u.String(), nil
}

// Client sends imports to one heretix-management with one access token
// (which needs the "import" scope).
type Client struct {
	HTTP      *http.Client
	BaseURL   string
	Token     string
	UserAgent string
}

// Upload imports a CycloneDX SBOM into the asset its hostname (or
// opts.Hostname) names, creating the asset if there is none.
func (c *Client) Upload(ctx context.Context, sbom []byte, opts ImportOptions) (*Asset, error) {
	body, status, err := c.post(ctx, sbom, opts, false)
	if err != nil {
		return nil, err
	}
	var asset Asset
	if err := json.Unmarshal(body, &asset); err != nil || asset.ID == "" {
		return nil, fmt.Errorf("unexpected response (HTTP %d) — is the URL heretix-management's?", status)
	}
	asset.Updated = asset.Updated || status == http.StatusOK
	return &asset, nil
}

// Preview asks what Upload would do — which asset it would update, and the
// package changes — without importing anything.
func (c *Client) Preview(ctx context.Context, sbom []byte, opts ImportOptions) (*Preview, error) {
	body, status, err := c.post(ctx, sbom, opts, true)
	if err != nil {
		return nil, err
	}
	var p Preview
	if err := json.Unmarshal(body, &p); err != nil || p.Hostname == "" {
		return nil, fmt.Errorf("unexpected response (HTTP %d) — is the URL heretix-management's?", status)
	}
	return &p, nil
}

// post sends the import request. The SBOM goes wrapped as
// {"inventory": <SBOM>, ...} rather than as the bare body: heretix-management
// reads the display name and dry-run flag only from the JSON body, and
// converts a wrapped CycloneDX document exactly as it does a bare one.
//
// Redirects are not followed: heretix-management answers a request it doesn't
// accept a token on (a wrong path or URL) by redirecting to its login page,
// and following that would turn a configuration mistake into a confusing
// HTML response.
func (c *Client) post(ctx context.Context, sbom []byte, opts ImportOptions, dryRun bool) ([]byte, int, error) {
	endpoint, err := ImportURL(c.BaseURL)
	if err != nil {
		return nil, 0, err
	}
	payload := struct {
		Inventory json.RawMessage `json:"inventory"`
		Hostname  string          `json:"hostname,omitempty"`
		Name      string          `json:"name,omitempty"`
		DryRun    bool            `json:"dryRun,omitempty"`
	}{json.RawMessage(sbom), opts.Hostname, opts.Name, dryRun}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, 0, &APIError{Status: resp.StatusCode, Location: resp.Header.Get("Location")}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return nil, 0, &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	return body, resp.StatusCode, nil
}

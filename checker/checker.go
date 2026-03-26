package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/TITeee/heretix-cli/inventory"
)

// Vulnerability represents a single vulnerability from the API response.
type Vulnerability struct {
	ID               string  `json:"id"`
	ExternalID       string  `json:"externalId"`
	Source           string  `json:"source"`
	Severity         string  `json:"severity"`
	CvssScore        float64 `json:"cvssScore"`
	CvssVector       string  `json:"cvssVector"`
	Summary          string  `json:"summary"`
	PublishedAt      string  `json:"publishedAt"`
	ApproximateMatch bool    `json:"approximateMatch"`
	IsKev            bool    `json:"isKev"`
	EpssScore        float64 `json:"epssScore"`
	EpssPercentile   float64 `json:"epssPercentile"`
}

// PackageResult holds the vulnerability check result for one package.
type PackageResult struct {
	Package          string          `json:"package"`
	Version          string          `json:"version"`
	Ecosystem        string          `json:"ecosystem"`
	Source           string          `json:"source,omitempty"`
	Location         string          `json:"location,omitempty"`
	ApproximateMatch bool            `json:"approximateMatch,omitempty"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
}

// CheckResult holds the complete check output.
type CheckResult struct {
	Hostname string          `json:"hostname"`
	Results  []PackageResult `json:"results"`
	Errors   []string        `json:"errors,omitempty"`
}

// Options configures the vulnerability checker.
type Options struct {
	APIURL      string
	APIKey      string
	Concurrency int
	Timeout     time.Duration
	Severity    float64
	Verbose     bool
}

// batchRequest is the payload for POST /api/v1/vulnerabilities/search/batch.
type batchRequest struct {
	Packages []batchPackage `json:"packages"`
}

type batchPackage struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// batchResponse is the response from the batch endpoint.
type batchResponse struct {
	Results []struct {
		Package         string          `json:"package"`
		Version         string          `json:"version"`
		Ecosystem       string          `json:"ecosystem"`
		Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	} `json:"results"`
}

// Check queries the vulnerability API for the given inventory packages.
func Check(ctx context.Context, inv *inventory.Inventory, opts Options) (*CheckResult, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	client := &http.Client{Timeout: opts.Timeout}
	result := &CheckResult{Hostname: inv.Hostname}

	// Build source/location lookup
	pkgMeta := make(map[string]inventory.Package)
	for _, p := range inv.Packages {
		key := p.Name + "\t" + p.Version + "\t" + p.Ecosystem
		pkgMeta[key] = p
	}

	// Chunk packages into batches of 1000
	chunks := chunkPackages(inv.Packages, 1000)

	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, chunk := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(pkgs []inventory.Package) {
			defer wg.Done()
			defer func() { <-sem }()

			batchResults, err := sendBatch(ctx, client, opts.APIURL, opts.APIKey, pkgs)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("batch request failed: %v", err))
				if opts.Verbose {
					log.Printf("[check] batch error: %v", err)
				}
				return
			}

			for _, r := range batchResults {
				key := r.Package + "\t" + r.Version + "\t" + r.Ecosystem
				meta := pkgMeta[key]
				// Check if any vulnerability is an approximate match
				approx := false
				for _, v := range r.Vulnerabilities {
					if v.ApproximateMatch {
						approx = true
						break
					}
				}
				pr := PackageResult{
					Package:          r.Package,
					Version:          r.Version,
					Ecosystem:        r.Ecosystem,
					Source:           meta.Source,
					Location:         meta.Location,
					ApproximateMatch: approx,
					Vulnerabilities:  r.Vulnerabilities,
				}
				result.Results = append(result.Results, pr)
			}
		}(chunk)
	}
	wg.Wait()

	// Filter by severity threshold and sort by CVSS descending
	result.Results = filterAndSort(result.Results, opts.Severity)

	return result, nil
}

// sendBatch sends a single batch request to the API.
func sendBatch(ctx context.Context, client *http.Client, apiURL, apiKey string, pkgs []inventory.Package) ([]struct {
	Package         string          `json:"package"`
	Version         string          `json:"version"`
	Ecosystem       string          `json:"ecosystem"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}, error) {
	reqBody := batchRequest{}
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" || p.Ecosystem == "" {
			continue
		}
		reqBody.Packages = append(reqBody.Packages, batchPackage{
			Package:   p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
		})
	}
	if len(reqBody.Packages) == 0 {
		return nil, nil
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal batch request: %w", err)
	}

	url := apiURL + "/api/v1/vulnerabilities/search/batch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode API response: %w", err)
	}

	return batchResp.Results, nil
}

// chunkPackages splits packages into chunks of the given size.
func chunkPackages(pkgs []inventory.Package, size int) [][]inventory.Package {
	var chunks [][]inventory.Package
	for i := 0; i < len(pkgs); i += size {
		end := i + size
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunks = append(chunks, pkgs[i:end])
	}
	return chunks
}

// filterAndSort keeps only packages with vulns above the severity threshold
// and sorts results: KEV-containing packages first, then by max CVSS score descending.
func filterAndSort(results []PackageResult, minSeverity float64) []PackageResult {
	var filtered []PackageResult
	for _, r := range results {
		var vulns []Vulnerability
		for _, v := range r.Vulnerabilities {
			if v.CvssScore >= minSeverity {
				vulns = append(vulns, v)
			}
		}
		if len(vulns) > 0 {
			r.Vulnerabilities = vulns
			filtered = append(filtered, r)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		iKev := hasKev(filtered[i].Vulnerabilities)
		jKev := hasKev(filtered[j].Vulnerabilities)
		if iKev != jKev {
			return iKev
		}
		return maxCVSS(filtered[i].Vulnerabilities) > maxCVSS(filtered[j].Vulnerabilities)
	})

	return filtered
}

func hasKev(vulns []Vulnerability) bool {
	for _, v := range vulns {
		if v.IsKev {
			return true
		}
	}
	return false
}

func maxCVSS(vulns []Vulnerability) float64 {
	max := 0.0
	for _, v := range vulns {
		if v.CvssScore > max {
			max = v.CvssScore
		}
	}
	return max
}

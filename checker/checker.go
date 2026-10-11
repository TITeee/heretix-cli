package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TITeee/heretix-cli/inventory"
)

// Vulnerability represents a single vulnerability from the API response.
type Vulnerability struct {
	ID         string `json:"id"`
	ExternalID string `json:"externalId"`
	// Source is a display-preference label (cveId > osvId > advisoryId), not
	// an indicator of which search path actually matched -- Sources (plural)
	// is the authoritative record of that; a CVE with NVD metadata always
	// shows Source "nvd" here even when the hit itself came from a vendor
	// advisory. Kept for backward compatibility with existing JSON consumers.
	Source           string   `json:"source"`
	Sources          []string `json:"sources"`
	Severity         string   `json:"severity"`
	CvssScore        float64  `json:"cvssScore"`
	CvssVector       string   `json:"cvssVector"`
	Summary          string   `json:"summary"`
	PublishedAt      string   `json:"publishedAt"`
	ApproximateMatch bool     `json:"approximateMatch"`
	IsKev            bool     `json:"isKev"`
	EpssScore        float64  `json:"epssScore"`
	EpssPercentile   float64  `json:"epssPercentile"`
	// FixedVersion is the version that resolves this finding, when the
	// server knows one. Empty (not just unset) also means "no fix known" for
	// a confirmed-unfixed vendor-advisory finding -- see heretix-api's
	// RedHatVexFetcher.
	FixedVersion string `json:"fixedVersion"`
	// DistroPriority is the distro's own rating of this CVE for the matched
	// package (Ubuntu priority, Debian urgency, Red Hat impact), verbatim. It
	// can differ from the CVE-wide Severity and is never merged into it.
	DistroPriority string `json:"distroPriority"`
	// FixStatus says whether a fix will come for an unfixed package:
	// affected, deferred, will_not_fix, out_of_support, under_investigation.
	// heretix-api may add values; treat an unknown one like "affected".
	// FixStatusDetail is the source's own wording (e.g. "Will not fix").
	FixStatus       string   `json:"fixStatus"`
	FixStatusDetail string   `json:"fixStatusDetail"`
	Aliases         []string `json:"aliases"`
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

	// Queried is how many packages were sent to the API, and Unchecked how
	// many of those sit in a batch that failed even after retries — so
	// their findings are missing from Results.
	Queried   int `json:"-"`
	Unchecked int `json:"-"`
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
		opts.Concurrency = DefaultConcurrency
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

	// A language package an OS package installed is covered by that OS
	// package's own advisories; queried at its upstream version it only adds
	// duplicates and false positives (see inventory.CategoryOSManaged).
	var toCheck []inventory.Package
	for _, p := range inv.Packages {
		if p.Category != inventory.CategoryOSManaged {
			toCheck = append(toCheck, p)
		}
	}

	// Chunk packages into batches of 1000
	chunks := chunkPackages(toCheck, 1000)

	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, chunk := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(pkgs []inventory.Package) {
			defer wg.Done()
			defer func() { <-sem }()

			batchResults, err := sendBatchWithRetry(ctx, client, opts.APIURL, opts.APIKey, pkgs)
			mu.Lock()
			defer mu.Unlock()
			result.Queried += queryable(pkgs)
			if err != nil {
				result.Unchecked += queryable(pkgs)
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
		return nil, &statusError{Status: resp.StatusCode, Body: string(respBody), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}

	var batchResp batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode API response: %w", err)
	}

	return batchResp.Results, nil
}

// DefaultConcurrency is how many batch searches run at once when --concurrency
// isn't given: heretix-api runs at most two at once by default and refuses the
// rest with 429, so asking for more only makes the extra ones wait and retry.
const DefaultConcurrency = 2

const (
	maxBatchAttempts = 5 // the first try plus four retries
	defaultRetryWait = 5 * time.Second
	minRetryWait     = time.Second
	maxRetryWait     = time.Minute
)

// statusError is a non-200 answer from the API.
type statusError struct {
	Status     int
	Body       string
	RetryAfter time.Duration // from the Retry-After header; 0 when absent or unreadable
}

func (e *statusError) Error() string {
	return fmt.Sprintf("API returned %d: %s", e.Status, e.Body)
}

// retrySleep waits for d or until ctx is done. A variable so tests needn't wait.
var retrySleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// parseRetryAfter reads a Retry-After header: a number of seconds, or an HTTP
// date. It returns 0 when the header is absent or unreadable.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// retryWait is how long to wait before retrying after d was asked for: the
// header's value, bounded so a bad one can neither hammer the API nor stall
// a CI job; defaultRetryWait when there was none.
func retryWait(asked time.Duration) time.Duration {
	switch {
	case asked <= 0:
		return defaultRetryWait
	case asked < minRetryWait:
		return minRetryWait
	case asked > maxRetryWait:
		return maxRetryWait
	}
	return asked
}

// sendBatchWithRetry is sendBatch that waits and tries again when the API
// answers 429 — it refuses a batch search past its concurrency cap or a
// client's per-minute limit, and says when to come back. Any other failure
// is final: a 401 won't get better, and a 5xx may have done the work.
func sendBatchWithRetry(ctx context.Context, client *http.Client, apiURL, apiKey string, pkgs []inventory.Package) ([]struct {
	Package         string          `json:"package"`
	Version         string          `json:"version"`
	Ecosystem       string          `json:"ecosystem"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}, error) {
	for attempt := 1; ; attempt++ {
		results, err := sendBatch(ctx, client, apiURL, apiKey, pkgs)
		var se *statusError
		if err == nil || !errors.As(err, &se) || se.Status != http.StatusTooManyRequests || attempt == maxBatchAttempts {
			return results, err
		}
		wait := retryWait(se.RetryAfter)
		log.Printf("API refused a batch search (429); retrying in %s (attempt %d of %d)", wait, attempt+1, maxBatchAttempts)
		if err := retrySleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// queryable counts the packages sendBatch actually sends: it skips any
// without a name, version or ecosystem.
func queryable(pkgs []inventory.Package) int {
	n := 0
	for _, p := range pkgs {
		if p.Name != "" && p.Version != "" && p.Ecosystem != "" {
			n++
		}
	}
	return n
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
// and sorts results: KEV-containing packages first, then malware, then by max CVSS score descending.
func filterAndSort(results []PackageResult, minSeverity float64) []PackageResult {
	var filtered []PackageResult
	for _, r := range results {
		var vulns []Vulnerability
		for _, v := range r.Vulnerabilities {
			// Malware entries bypass the severity threshold since they typically lack CVSS scores.
			if meetsThreshold(v, minSeverity) || isMalware(v) {
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
		iMal := hasMalware(filtered[i].Vulnerabilities)
		jMal := hasMalware(filtered[j].Vulnerabilities)
		if iMal != jMal {
			return iMal
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

// isMalware reports whether v is a malicious-package entry (OSSF MAL-* ID).
func isMalware(v Vulnerability) bool {
	return strings.HasPrefix(v.ExternalID, "MAL-")
}

// hasMalware reports whether any vulnerability in the slice is a malware entry.
func hasMalware(vulns []Vulnerability) bool {
	for _, v := range vulns {
		if isMalware(v) {
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

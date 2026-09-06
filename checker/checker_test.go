package checker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

func TestChunkPackages(t *testing.T) {
	pkg := func(name string) inventory.Package { return inventory.Package{Name: name} }

	tests := map[string]struct {
		pkgs      []inventory.Package
		size      int
		wantSizes []int
	}{
		"empty input produces no chunks": {
			pkgs:      nil,
			size:      3,
			wantSizes: nil,
		},
		"exact multiple of size splits evenly": {
			pkgs:      []inventory.Package{pkg("a"), pkg("b"), pkg("c"), pkg("d")},
			size:      2,
			wantSizes: []int{2, 2},
		},
		"remainder goes into a smaller final chunk": {
			pkgs:      []inventory.Package{pkg("a"), pkg("b"), pkg("c")},
			size:      2,
			wantSizes: []int{2, 1},
		},
		"size larger than input yields a single chunk": {
			pkgs:      []inventory.Package{pkg("a"), pkg("b")},
			size:      1000,
			wantSizes: []int{2},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := chunkPackages(tc.pkgs, tc.size)
			if len(got) != len(tc.wantSizes) {
				t.Fatalf("got %d chunks, want %d", len(got), len(tc.wantSizes))
			}
			for i, wantSize := range tc.wantSizes {
				if len(got[i]) != wantSize {
					t.Errorf("chunk %d: got size %d, want %d", i, len(got[i]), wantSize)
				}
			}
		})
	}
}

func TestHasKev(t *testing.T) {
	if hasKev(nil) {
		t.Error("empty slice should not have KEV")
	}
	if hasKev([]Vulnerability{{IsKev: false}}) {
		t.Error("no KEV entries should not have KEV")
	}
	if !hasKev([]Vulnerability{{IsKev: false}, {IsKev: true}}) {
		t.Error("one KEV entry among others should have KEV")
	}
}

func TestIsMalware(t *testing.T) {
	tests := map[string]struct {
		externalID string
		want       bool
	}{
		"OSSF malware ID matches":     {"MAL-2026-1234", true},
		"CVE ID does not match":       {"CVE-2026-1234", false},
		"empty ID does not match":     {"", false},
		"prefix must be at the start": {"XMAL-2026-1234", false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := isMalware(Vulnerability{ExternalID: tc.externalID})
			if got != tc.want {
				t.Errorf("isMalware(%q) = %v, want %v", tc.externalID, got, tc.want)
			}
		})
	}
}

func TestHasMalware(t *testing.T) {
	if hasMalware(nil) {
		t.Error("empty slice should not have malware")
	}
	if hasMalware([]Vulnerability{{ExternalID: "CVE-2026-1"}}) {
		t.Error("CVE-only slice should not have malware")
	}
	if !hasMalware([]Vulnerability{{ExternalID: "CVE-2026-1"}, {ExternalID: "MAL-2026-1"}}) {
		t.Error("slice containing a MAL- entry should have malware")
	}
}

func TestMaxCVSS(t *testing.T) {
	tests := map[string]struct {
		vulns []Vulnerability
		want  float64
	}{
		"empty slice yields zero":        {nil, 0},
		"single score is returned as-is": {[]Vulnerability{{CvssScore: 7.5}}, 7.5},
		"highest of several is returned": {[]Vulnerability{{CvssScore: 4.0}, {CvssScore: 9.1}, {CvssScore: 2.0}}, 9.1},
		"all-zero scores yield zero":     {[]Vulnerability{{CvssScore: 0}, {CvssScore: 0}}, 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := maxCVSS(tc.vulns); got != tc.want {
				t.Errorf("maxCVSS() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterAndSort(t *testing.T) {
	t.Run("drops vulnerabilities below the severity threshold", func(t *testing.T) {
		results := []PackageResult{
			{Package: "p", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-1", CvssScore: 3.0}, {ExternalID: "CVE-2", CvssScore: 8.0}}},
		}
		got := filterAndSort(results, 5.0)
		if len(got) != 1 || len(got[0].Vulnerabilities) != 1 || got[0].Vulnerabilities[0].ExternalID != "CVE-2" {
			t.Fatalf("expected only CVE-2 to survive a 5.0 threshold, got %+v", got)
		}
	})

	t.Run("a package with nothing above threshold is dropped entirely", func(t *testing.T) {
		results := []PackageResult{
			{Package: "p", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-1", CvssScore: 1.0}}},
		}
		got := filterAndSort(results, 5.0)
		if len(got) != 0 {
			t.Fatalf("expected the package to be dropped, got %+v", got)
		}
	})

	t.Run("malware entries bypass the severity threshold even with a zero score", func(t *testing.T) {
		// Malware findings typically carry no CVSS score at all -- a naive
		// score-only filter would silently hide every one of them.
		results := []PackageResult{
			{Package: "p", Vulnerabilities: []Vulnerability{{ExternalID: "MAL-2026-1", CvssScore: 0}}},
		}
		got := filterAndSort(results, 5.0)
		if len(got) != 1 || len(got[0].Vulnerabilities) != 1 {
			t.Fatalf("expected the malware entry to survive despite CvssScore 0, got %+v", got)
		}
	})

	t.Run("sorts KEV packages before non-KEV packages regardless of CVSS", func(t *testing.T) {
		results := []PackageResult{
			{Package: "high-cvss", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-1", CvssScore: 9.8}}},
			{Package: "kev", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-2", CvssScore: 4.0, IsKev: true}}},
		}
		got := filterAndSort(results, 0)
		if len(got) != 2 || got[0].Package != "kev" {
			t.Fatalf("expected the KEV package first regardless of lower CVSS, got %+v", got)
		}
	})

	t.Run("sorts malware packages before ordinary packages when neither has KEV", func(t *testing.T) {
		results := []PackageResult{
			{Package: "high-cvss", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-1", CvssScore: 9.8}}},
			{Package: "malware", Vulnerabilities: []Vulnerability{{ExternalID: "MAL-2026-1", CvssScore: 0}}},
		}
		got := filterAndSort(results, 0)
		if len(got) != 2 || got[0].Package != "malware" {
			t.Fatalf("expected the malware package first, got %+v", got)
		}
	})

	t.Run("breaks ties by descending max CVSS", func(t *testing.T) {
		results := []PackageResult{
			{Package: "low", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-1", CvssScore: 3.0}}},
			{Package: "high", Vulnerabilities: []Vulnerability{{ExternalID: "CVE-2", CvssScore: 9.0}}},
		}
		got := filterAndSort(results, 0)
		if len(got) != 2 || got[0].Package != "high" || got[1].Package != "low" {
			t.Fatalf("expected descending CVSS order, got %+v", got)
		}
	})
}

// TestSendBatch_PreservesFullVulnerabilityShape is a regression test for a
// real bug: the Vulnerability struct was once missing fixedVersion, sources,
// and aliases entirely, so encoding/json silently dropped them from every
// decoded response even though the server sent them -- the CLI's own output
// (table and JSON) never showed a fix version or which source actually
// matched. This asserts every field the API is known to send survives the
// HTTP round-trip into the Vulnerability struct.
func TestSendBatch_PreservesFullVulnerabilityShape(t *testing.T) {
	const responseBody = `{
		"results": [
			{
				"package": "openssl-libs",
				"version": "1:3.5.5-6.0.1.el9_8",
				"ecosystem": "Oracle Linux:9",
				"vulnerabilities": [
					{
						"id": "cmmt00rs2csr4skkakee0tfaq",
						"externalId": "CVE-2025-69421",
						"source": "nvd",
						"sources": ["oracle-linux"],
						"severity": "HIGH",
						"cvssScore": 7.5,
						"cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						"summary": "Issue summary",
						"publishedAt": "2026-01-27T00:00:00.000Z",
						"approximateMatch": false,
						"isKev": false,
						"epssScore": 0.00877,
						"epssPercentile": 0.56507,
						"fixedVersion": "10:3.5.1-7.0.1.el9_7_fips",
						"aliases": ["CVE-2025-69421", "ELSA-2026-50075/CVE-2025-69421"]
					}
				]
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	pkgs := []inventory.Package{{Name: "openssl-libs", Version: "1:3.5.5-6.0.1.el9_8", Ecosystem: "Oracle Linux:9"}}
	results, err := sendBatch(context.Background(), server.Client(), server.URL, "", pkgs)
	if err != nil {
		t.Fatalf("sendBatch returned an error: %v", err)
	}
	if len(results) != 1 || len(results[0].Vulnerabilities) != 1 {
		t.Fatalf("expected exactly one package with one vulnerability, got %+v", results)
	}

	v := results[0].Vulnerabilities[0]
	if v.FixedVersion != "10:3.5.1-7.0.1.el9_7_fips" {
		t.Errorf("FixedVersion = %q, want the fips fix version from the response", v.FixedVersion)
	}
	if len(v.Sources) != 1 || v.Sources[0] != "oracle-linux" {
		t.Errorf("Sources = %v, want [\"oracle-linux\"]", v.Sources)
	}
	if len(v.Aliases) != 2 {
		t.Errorf("Aliases = %v, want 2 entries", v.Aliases)
	}
}

func TestSendBatch_SkipsRequestWhenEveryPackageIsIncomplete(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Missing Ecosystem on every package: sendBatch filters these out before
	// building the request body, and an empty request body would be a
	// wasted round trip against the real API.
	pkgs := []inventory.Package{{Name: "foo", Version: "1.0"}}
	results, err := sendBatch(context.Background(), server.Client(), server.URL, "", pkgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results, got %+v", results)
	}
	if called {
		t.Error("expected sendBatch to skip the HTTP request entirely, but the server was called")
	}
}

func TestSendBatch_NonOKStatusReturnsErrorWithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid API key"))
	}))
	defer server.Close()

	pkgs := []inventory.Package{{Name: "foo", Version: "1.0", Ecosystem: "npm"}}
	_, err := sendBatch(context.Background(), server.Client(), server.URL, "bad-key", pkgs)
	if err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "invalid API key") {
		t.Errorf("error %q should mention the status code and body", err.Error())
	}
}

func TestSendBatch_SendsAPIKeyHeader(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	pkgs := []inventory.Package{{Name: "foo", Version: "1.0", Ecosystem: "npm"}}
	if _, err := sendBatch(context.Background(), server.Client(), server.URL, "secret-key", pkgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotKey != "secret-key" {
		t.Errorf("x-api-key header = %q, want %q", gotKey, "secret-key")
	}
}

// TestCheck_AttachesInventoryMetadataAndApproximateMatch exercises Check
// end-to-end against a fake server: the batch response doesn't carry a
// package's Source/Location (only sendBatch's request does), so Check must
// look them back up from the original inventory by (name, version,
// ecosystem) and attach them to each PackageResult.
func TestCheck_AttachesInventoryMetadataAndApproximateMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if len(req.Packages) != 1 || req.Packages[0].Package != "lodash" {
			t.Errorf("unexpected request payload: %+v", req.Packages)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"results": [
				{
					"package": "lodash",
					"version": "4.17.20",
					"ecosystem": "npm",
					"vulnerabilities": [
						{"id": "1", "externalId": "CVE-2026-1", "severity": "HIGH", "cvssScore": 7.0, "approximateMatch": true}
					]
				}
			]
		}`))
	}))
	defer server.Close()

	inv := &inventory.Inventory{
		Hostname: "test-host",
		Packages: []inventory.Package{
			{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Source: "npm", Location: "package.json"},
		},
	}

	result, err := Check(context.Background(), inv, Options{APIURL: server.URL})
	if err != nil {
		t.Fatalf("Check returned an error: %v", err)
	}
	if result.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", result.Hostname, "test-host")
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected exactly one package result, got %+v", result.Results)
	}

	pr := result.Results[0]
	if pr.Source != "npm" || pr.Location != "package.json" {
		t.Errorf("expected inventory Source/Location to be attached, got Source=%q Location=%q", pr.Source, pr.Location)
	}
	if !pr.ApproximateMatch {
		t.Error("expected ApproximateMatch to propagate from the vulnerability to the package result")
	}
}

func TestCheck_CollectsBatchErrorsWithoutFailingTheWholeRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()

	inv := &inventory.Inventory{
		Packages: []inventory.Package{{Name: "foo", Version: "1.0", Ecosystem: "npm"}},
	}

	result, err := Check(context.Background(), inv, Options{APIURL: server.URL})
	if err != nil {
		t.Fatalf("Check itself should not return an error on a batch failure, got: %v", err)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected exactly one collected error, got %+v", result.Errors)
	}
	if len(result.Results) != 0 {
		t.Errorf("expected no results after a failed batch, got %+v", result.Results)
	}
}

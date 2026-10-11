package checker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TITeee/heretix-cli/inventory"
)

// noSleep replaces retrySleep for a test, recording each wait instead of
// making it.
func noSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	prev := retrySleep
	retrySleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}
	t.Cleanup(func() { retrySleep = prev })
	return &waits
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		value string
		want  time.Duration
	}{
		"absent":                   {"", 0},
		"seconds":                  {"5", 5 * time.Second},
		"padded seconds":           {" 12 ", 12 * time.Second},
		"negative":                 {"-3", 0},
		"unreadable":               {"soon", 0},
		"an HTTP date ahead":       {now.Add(20 * time.Second).Format(http.TimeFormat), 20 * time.Second},
		"an HTTP date in the past": {now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for name, tc := range tests {
		if got := parseRetryAfter(tc.value, now); got != tc.want {
			t.Errorf("%s: parseRetryAfter(%q) = %v, want %v", name, tc.value, got, tc.want)
		}
	}
}

func TestRetryWait(t *testing.T) {
	tests := map[string]struct{ asked, want time.Duration }{
		"none asked uses the default":  {0, defaultRetryWait},
		"the asked wait is used":       {7 * time.Second, 7 * time.Second},
		"a tiny wait is raised, not 0": {100 * time.Millisecond, minRetryWait},
		"a huge wait is capped":        {time.Hour, maxRetryWait},
	}
	for name, tc := range tests {
		if got := retryWait(tc.asked); got != tc.want {
			t.Errorf("%s: retryWait(%v) = %v, want %v", name, tc.asked, got, tc.want)
		}
	}
}

func onePackage() []inventory.Package {
	return []inventory.Package{{Name: "foo", Version: "1.0", Ecosystem: "npm"}}
}

const okBody = `{"results":[{"package":"foo","version":"1.0","ecosystem":"npm","vulnerabilities":[]}]}`

// heretix-api refuses a batch search past its concurrency cap with 429 and a
// Retry-After; the client must wait that long and ask again.
func TestSendBatchWithRetry_RetriesA429AfterRetryAfter(t *testing.T) {
	waits := noSleep(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Too many batch searches running; retry shortly"}`))
			return
		}
		_, _ = w.Write([]byte(okBody))
	}))
	defer server.Close()

	results, err := sendBatchWithRetry(context.Background(), server.Client(), server.URL, "k", onePackage())
	if err != nil {
		t.Fatalf("sendBatchWithRetry returned an error: %v", err)
	}
	if len(results) != 1 || calls.Load() != 3 {
		t.Errorf("got %d results after %d calls, want 1 result after 3", len(results), calls.Load())
	}
	if len(*waits) != 2 || (*waits)[0] != 7*time.Second || (*waits)[1] != 7*time.Second {
		t.Errorf("waits = %v, want two waits of the Retry-After 7s", *waits)
	}
}

func TestSendBatchWithRetry_GivesUpAfterTheAttemptLimit(t *testing.T) {
	waits := noSleep(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("slow down"))
	}))
	defer server.Close()

	_, err := sendBatchWithRetry(context.Background(), server.Client(), server.URL, "k", onePackage())
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want the final 429", err)
	}
	if int(calls.Load()) != maxBatchAttempts {
		t.Errorf("made %d calls, want %d", calls.Load(), maxBatchAttempts)
	}
	if len(*waits) != maxBatchAttempts-1 || (*waits)[0] != defaultRetryWait {
		t.Errorf("waits = %v, want %d of the default %v (no Retry-After was sent)", *waits, maxBatchAttempts-1, defaultRetryWait)
	}
}

// A 401 will not get better and a 5xx may have done the work: neither is retried.
func TestSendBatchWithRetry_OnlyRetries429(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		noSleep(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
		}))
		_, err := sendBatchWithRetry(context.Background(), server.Client(), server.URL, "k", onePackage())
		server.Close()
		if err == nil || calls.Load() != 1 {
			t.Errorf("status %d: err = %v after %d calls, want an error after exactly 1", status, err, calls.Load())
		}
	}
}

// Ctrl-C during the wait must stop at once, not after the wait.
func TestSendBatchWithRetry_StopsWhenCancelledDuringTheWait(t *testing.T) {
	prev := retrySleep
	t.Cleanup(func() { retrySleep = prev })
	ctx, cancel := context.WithCancel(context.Background())
	retrySleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	if _, err := sendBatchWithRetry(ctx, server.Client(), server.URL, "k", onePackage()); err == nil {
		t.Error("expected the cancellation as an error")
	}
	if calls.Load() != 1 {
		t.Errorf("made %d calls, want 1: no retry after cancel", calls.Load())
	}
}

// TestCheck_CountsPackagesInFailedBatches is the check behind the exit code
// and the "N of M packages could not be checked" warning: with three batches
// and the second refused for good, the other two's results are kept and the
// failed batch's 1000 packages are counted as unchecked.
func TestCheck_CountsPackagesInFailedBatches(t *testing.T) {
	noSleep(t)
	var refused atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The second batch, the one starting at pkg1000, is always refused.
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"pkg1000"`) {
			refused.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	inv := &inventory.Inventory{}
	for i := 0; i < 2500; i++ {
		inv.Packages = append(inv.Packages, inventory.Package{Name: "pkg" + strconv.Itoa(i), Version: "1.0.0", Ecosystem: "npm"})
	}
	result, err := Check(context.Background(), inv, Options{APIURL: server.URL, APIKey: "k", Concurrency: 1})
	if err != nil {
		t.Fatalf("Check returned an error: %v", err)
	}
	if result.Queried != 2500 || result.Unchecked != 1000 {
		t.Errorf("Queried/Unchecked = %d/%d, want 2500/1000", result.Queried, result.Unchecked)
	}
	if len(result.Errors) != 1 || int(refused.Load()) != maxBatchAttempts {
		t.Errorf("errors = %v after %d refused calls, want one error after %d", result.Errors, refused.Load(), maxBatchAttempts)
	}
}

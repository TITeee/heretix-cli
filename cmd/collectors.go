package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/TITeee/heretix-cli/collector"
)

// collectorSkip is the list of collectors collect and scan hand to
// collector.CollectAll: --skip as given, or, for --only, every collector but
// the ones named. (Cobra rejects the two flags together, so at most one is set.)
func collectorSkip(only, skip []string) ([]string, error) {
	if len(only) == 0 {
		return skip, nil
	}
	return collector.SkipAllExcept(only)
}

// describeCollectors tells the user which collectors were chosen, on stderr,
// as the "Skipping:" line always has.
func describeCollectors(only, skip []string) {
	switch {
	case len(only) > 0:
		fmt.Fprintf(os.Stderr, "Collecting only: %s\n", strings.ToLower(strings.Join(only, ", ")))
	case len(skip) > 0:
		fmt.Fprintf(os.Stderr, "Skipping: %s\n", strings.Join(skip, ", "))
	}
}

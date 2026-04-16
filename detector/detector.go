package detector

import (
	"log"
)

// Finding represents a single local security finding detected without API access.
type Finding struct {
	Type      string // "glassworm" | "dep-confusion"
	Severity  string // "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
	File      string // path to the affected file
	Line      int    // line number (0 = not applicable)
	Package   string // related package name (if applicable)
	Ecosystem string // related ecosystem (if applicable)
	Detail    string // human-readable description
}

// Detector is the interface implemented by each local security check.
type Detector interface {
	Name() string
	Detect(scanPath string, verbose bool) ([]Finding, error)
}

// RunAll runs all detectors against scanPath and returns the combined findings.
// Errors from individual detectors are logged as warnings and do not abort the run.
func RunAll(scanPath string, verbose bool) ([]Finding, error) {
	detectors := []Detector{
		&GlassWormDetector{},
		&DepConfusionDetector{},
	}

	var all []Finding
	for _, d := range detectors {
		findings, err := d.Detect(scanPath, verbose)
		if err != nil {
			log.Printf("Warning: %s detector failed: %v", d.Name(), err)
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

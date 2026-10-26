package cmd

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestInferLifecycle(t *testing.T) {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	cases := []struct {
		name     string
		scanPath string
		image    bool
		want     cdx.LifecyclePhase
	}{
		{"filesystem root is a running system", root, false, cdx.LifecyclePhaseOperations},
		{"a directory is taken for a project", t.TempDir(), false, cdx.LifecyclePhasePreBuild},
		{"an image is a built artifact", root, true, cdx.LifecyclePhasePostBuild},
	}
	for _, c := range cases {
		if got := inferLifecycle(c.scanPath, c.image); got != c.want {
			t.Errorf("%s: inferLifecycle(%q, %v) = %q, want %q", c.name, c.scanPath, c.image, got, c.want)
		}
	}
}

func TestValidLifecycle(t *testing.T) {
	for _, p := range []string{"operations", "pre-build", "post-build", "discovery"} {
		if !validLifecycle(p) {
			t.Errorf("%q rejected", p)
		}
	}
	for _, p := range []string{"", "decommission", "runtime", "Operations"} {
		if validLifecycle(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

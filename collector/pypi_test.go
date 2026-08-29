package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const pipfileLockFixture = `{
  "default": {
    "requests": { "version": "==2.31.0" }
  },
  "develop": {
    "pytest": { "version": "==7.4.0" }
  }
}`

// TestCollect_ContainerScanSkipsHostGlobalFallback guards against reporting this
// process's own host pip global packages as belonging to a scanned container
// image. When no lock/requirements file is found under scanPath and
// isContainer is true, Collect must return no packages rather than falling
// back to "pip list", which runs against the host, not the extracted rootfs.
func TestPyPICollect_ContainerScanSkipsHostGlobalFallback(t *testing.T) {
	dir := t.TempDir() // no requirements files — global fallback would otherwise trigger

	pkgs, err := (&PyPICollector{}).Collect(dir, false, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("Collect with isContainer=true returned %d packages, want 0 (host global fallback must not run for a container scan): %+v", len(pkgs), pkgs)
	}
}

func TestParsePipfileLock_ScopeReflectsDevelopSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Pipfile.lock")
	if err := os.WriteFile(path, []byte(pipfileLockFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parsePipfileLock(path, false)
	if err != nil {
		t.Fatal(err)
	}

	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}

	if got := scopes["requests"]; got != "" {
		t.Errorf("requests: got scope %q, want \"\" (default/runtime package)", got)
	}
	if got := scopes["pytest"]; got != "excluded" {
		t.Errorf("pytest: got scope %q, want \"excluded\" (develop-only package)", got)
	}
}

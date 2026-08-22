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

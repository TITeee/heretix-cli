package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const composerLockFixture = `{
  "packages": [
    { "name": "monolog/monolog", "version": "2.9.1", "license": ["MIT"] }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "9.6.0", "license": ["BSD-3-Clause"] }
  ]
}`

func TestParseComposerLock_ScopeReflectsPackagesDev(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "composer.lock")
	if err := os.WriteFile(path, []byte(composerLockFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parseComposerLock(path, false)
	if err != nil {
		t.Fatal(err)
	}

	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}

	if got := scopes["monolog/monolog"]; got != "" {
		t.Errorf("monolog/monolog: got scope %q, want \"\" (runtime package)", got)
	}
	if got := scopes["phpunit/phpunit"]; got != "excluded" {
		t.Errorf("phpunit/phpunit: got scope %q, want \"excluded\" (dev-only package)", got)
	}
}

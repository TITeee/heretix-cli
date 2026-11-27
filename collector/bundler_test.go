package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

const gemfileLockFixture = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
      rack (~> 2.0, >= 2.2.4)
    actionview (7.0.4)
      builder (~> 3.1)
    builder (3.2.4)
    rack (2.2.6.4)
    rspec (3.12.0)
      rspec-core (~> 3.12.0)
    rspec-core (3.12.0)

GIT
  remote: https://github.com/example/forked-pry.git
  revision: abcdef1234567890
  specs:
    pry (0.14.0)

PATH
  remote: .
  specs:
    myapp (0.1.0)
      actionpack

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  actionpack
  myapp!
  rspec

BUNDLED WITH
   2.3.26
`

func writeGemfileLockFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Gemfile.lock")
	if err := os.WriteFile(path, []byte(gemfileLockFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseGemfileLockFile_OnlyRubygemsSourced(t *testing.T) {
	path := writeGemfileLockFixture(t)

	pkgs, err := parseGemfileLockFile(path, false, filepath.Dir(path), false)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	sort.Strings(names)

	want := []string{"actionpack", "actionview", "builder", "rack", "rspec", "rspec-core"}
	if len(names) != len(want) {
		t.Fatalf("got packages %v, want %v (pry is git-sourced, myapp is path-sourced — neither should be included)", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("got %v, want %v", names, want)
			break
		}
	}
}

func TestParseGemfileLockFile_EcosystemAndPURL(t *testing.T) {
	path := writeGemfileLockFixture(t)

	pkgs, err := parseGemfileLockFile(path, false, filepath.Dir(path), false)
	if err != nil {
		t.Fatal(err)
	}

	byName := make(map[string]int, len(pkgs))
	for i, p := range pkgs {
		byName[p.Name] = i
	}

	actionpack := pkgs[byName["actionpack"]]
	if actionpack.Ecosystem != "RubyGems" {
		t.Errorf("ecosystem = %q, want RubyGems", actionpack.Ecosystem)
	}
	if actionpack.Source != "Gemfile.lock" {
		t.Errorf("source = %q, want Gemfile.lock", actionpack.Source)
	}

	rack := pkgs[byName["rack"]]
	wantDep := gemPURL("rack", "2.2.6.4")
	found := false
	for _, dep := range actionpack.Deps {
		if dep == wantDep {
			found = true
		}
	}
	if !found {
		t.Errorf("actionpack deps = %v, want to contain %s", actionpack.Deps, wantDep)
	}
	_ = rack
}

func TestParseGemfileLockFile_Direct(t *testing.T) {
	path := writeGemfileLockFixture(t)

	pkgs, err := parseGemfileLockFile(path, false, filepath.Dir(path), false)
	if err != nil {
		t.Fatal(err)
	}

	byName := make(map[string]int, len(pkgs))
	for i, p := range pkgs {
		byName[p.Name] = i
	}

	actionpack := pkgs[byName["actionpack"]]
	if actionpack.Direct == nil || !*actionpack.Direct {
		t.Errorf("actionpack: direct = %v, want true (declared in DEPENDENCIES)", actionpack.Direct)
	}

	actionview := pkgs[byName["actionview"]]
	if actionview.Direct == nil || *actionview.Direct {
		t.Errorf("actionview: direct = %v, want false (transitive only)", actionview.Direct)
	}

	rspec := pkgs[byName["rspec"]]
	if rspec.Direct == nil || !*rspec.Direct {
		t.Errorf("rspec: direct = %v, want true (declared in DEPENDENCIES)", rspec.Direct)
	}
}

func TestStripGemPlatformSuffix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.15.4-x86_64-linux", "1.15.4"},
		{"1.15.4-arm64-darwin", "1.15.4"},
		{"1.15.4-java", "1.15.4"},
		{"1.15.4", "1.15.4"},
		{"1.15.4-pre", "1.15.4-pre"}, // unrecognized suffix: left alone, not guessed at
	}
	for _, tt := range tests {
		if got := stripGemPlatformSuffix(tt.in); got != tt.want {
			t.Errorf("stripGemPlatformSuffix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsRubygemsRemote(t *testing.T) {
	tests := []struct {
		remote string
		want   bool
	}{
		{"https://rubygems.org/", true},
		{`"https://rubygems.org/"`, true},
		{"https://gems.example.com/", false},
		{".", false},
		{"https://github.com/example/forked-pry.git", false},
	}
	for _, tt := range tests {
		if got := isRubygemsRemote(tt.remote); got != tt.want {
			t.Errorf("isRubygemsRemote(%q) = %v, want %v", tt.remote, got, tt.want)
		}
	}
}

func TestIsBundlerVendorDir(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/app/vendor/bundle", true},
		{"/app/.bundle", true},
		{"/app/vendor/other", false},
		{"/app/bundle", false},
	}
	for _, tt := range tests {
		if got := isBundlerVendorDir(tt.path); got != tt.want {
			t.Errorf("isBundlerVendorDir(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestCollect_SkipsVendorBundle mirrors cargo.go's real-image regression test:
// a gem installed under vendor/bundle could ship its own Gemfile.lock (its
// repo's own, for its own test suite), which must not be picked up as if it
// belonged to the scanned app.
func TestBundlerCollect_SkipsVendorBundle(t *testing.T) {
	dir := t.TempDir()
	appLock := `GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.6.4)

DEPENDENCIES
  rack
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(appLock), 0o600); err != nil {
		t.Fatal(err)
	}

	vendorDir := filepath.Join(dir, "vendor", "bundle", "ruby", "3.2.0", "gems", "rack-2.2.6.4")
	if err := os.MkdirAll(vendorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	vendoredLock := `GEM
  remote: https://rubygems.org/
  specs:
    unrelated-dev-tool (9.9.9)

DEPENDENCIES
  unrelated-dev-tool
`
	if err := os.WriteFile(filepath.Join(vendorDir, "Gemfile.lock"), []byte(vendoredLock), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&BundlerCollector{}).Collect(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Name == "unrelated-dev-tool" {
			t.Fatalf("collected %q from inside vendor/bundle; that directory should have been skipped", p.Name)
		}
	}
	if len(pkgs) != 1 || pkgs[0].Name != "rack" {
		t.Errorf("got %v, want exactly [rack]", pkgs)
	}
}

// TestMarkBundlerDevOnlyScope_RequiresRubyAndBundleWithout exercises the full
// scope pipeline against a real `ruby` binary when available, skipping
// otherwise -- the Gemfile DSL evaluation this depends on cannot be faked
// with a fixture the way Cargo.toml's static format can.
func TestMarkBundlerDevOnlyScope_RequiresRubyAndBundleWithout(t *testing.T) {
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby not available")
	}

	dir := t.TempDir()
	gemfile := `source "https://rubygems.org"
gem "rack"
group :test do
  gem "rspec"
end
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte(gemfile), 0o600); err != nil {
		t.Fatal(err)
	}
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.6.4)
    rspec (3.12.0)
      rspec-core (~> 3.12.0)
    rspec-core (3.12.0)

DEPENDENCIES
  rack
  rspec
`
	lockPath := filepath.Join(dir, "Gemfile.lock")
	if err := os.WriteFile(lockPath, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUNDLE_WITHOUT", "test")

	pkgs, err := parseGemfileLockFile(lockPath, false, filepath.Dir(lockPath), false)
	if err != nil {
		t.Fatal(err)
	}

	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}
	if got := scopes["rack"]; got != "" {
		t.Errorf("rack: scope = %q, want \"\" (default group, not excluded)", got)
	}
	for _, name := range []string{"rspec", "rspec-core"} {
		if got := scopes[name]; got != "excluded" {
			t.Errorf("%s: scope = %q, want \"excluded\" (:test group, BUNDLE_WITHOUT=test)", name, got)
		}
	}
}

func TestBundleWithoutGroups(t *testing.T) {
	dir := t.TempDir()
	if got := bundleWithoutGroups(dir, "", false); got != nil {
		t.Errorf("no env var, no .bundle/config: got %v, want nil", got)
	}

	if err := os.MkdirAll(filepath.Join(dir, ".bundle"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "---\nBUNDLE_WITHOUT: \"development:test\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".bundle", "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	got := bundleWithoutGroups(dir, "", false)
	want := []string{"development", "test"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestBundleWithoutGroups_BundleAppConfig reproduces a bug found scanning a
// real image built from the official ruby Docker image: it sets
// BUNDLE_APP_CONFIG=/usr/local/bundle, so bundle's config lives there
// instead of <app>/.bundle/config, and reading only the latter silently
// found nothing.
func TestBundleWithoutGroups_BundleAppConfig(t *testing.T) {
	appDir := t.TempDir()
	configDir := t.TempDir()
	t.Setenv("BUNDLE_APP_CONFIG", configDir)

	config := "---\nBUNDLE_WITHOUT: \"test\"\n"
	if err := os.WriteFile(filepath.Join(configDir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	got := bundleWithoutGroups(appDir, "", false)
	if len(got) != 1 || got[0] != "test" {
		t.Errorf("got %v, want [test]", got)
	}
}

// TestBundleWithoutGroups_ContainerPrefixesAppConfig covers an image scan:
// BUNDLE_APP_CONFIG names a path inside the scanned image (e.g.
// /usr/local/bundle, the official Ruby Docker images' own default), which
// exists on this host only under the extracted rootfs -- not at that literal
// absolute path, which may not exist on the host at all, or (worse) could
// coincidentally exist and belong to something unrelated.
func TestBundleWithoutGroups_ContainerPrefixesAppConfig(t *testing.T) {
	rootfs := t.TempDir()
	configDir := filepath.Join(rootfs, "usr", "local", "bundle")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := "---\nBUNDLE_WITHOUT: \"test\"\n"
	if err := os.WriteFile(filepath.Join(configDir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUNDLE_APP_CONFIG", "/usr/local/bundle")

	got := bundleWithoutGroups(filepath.Join(rootfs, "app"), rootfs, true)
	if len(got) != 1 || got[0] != "test" {
		t.Errorf("got %v, want [test] (config read from <rootfs>/usr/local/bundle/config)", got)
	}
}

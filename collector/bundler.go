package collector

import (
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// BundlerCollector collects Ruby gems from Gemfile.lock files.
type BundlerCollector struct{}

func (c *BundlerCollector) Name() string { return "bundler" }

func (c *BundlerCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || isBundlerVendorDir(path) || skipWalkDir(path, scanPath) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "Gemfile.lock" {
			return nil
		}

		p, err := parseGemfileLockFile(path, verbose, scanPath, isContainer)
		if err != nil {
			if verbose {
				log.Printf("[bundler] error parsing %s: %v", path, err)
			}
			return nil
		}
		pkgs = append(pkgs, p...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	if verbose {
		log.Printf("[bundler] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// isBundlerVendorDir reports whether path is Bundler's own local install
// directory ("vendor/bundle", the standard way a containerized app installs
// gems without touching the system gem path) or its config/cache directory
// (".bundle"). The same risk that made cargo.go add isCargoRegistryDir
// applies here: a gem's published tarball is often just `git ls-files` from
// its own repo, which can include that repo's own committed Gemfile.lock
// (for its own test suite), so walking into installed gems risks parsing
// gems' own unrelated lockfiles as if they belonged to the scanned app.
func isBundlerVendorDir(path string) bool {
	if filepath.Base(path) == ".bundle" {
		return true
	}
	return filepath.Base(path) == "bundle" && filepath.Base(filepath.Dir(path)) == "vendor"
}

// gemSpec is one gem entry under a GEM/GIT/PATH section's "specs:" list.
type gemSpec struct {
	name         string
	version      string
	fromRubygems bool
	dependencies []string
}

func gemPURL(name, version string) string {
	return "pkg:gem/" + name + "@" + version
}

// isRubygemsRemote reports whether a GEM/GIT/PATH section's "remote:" value
// names the public RubyGems index. A GIT or PATH section is local/forked
// code never published anywhere, same reasoning as cargo.go's git/path
// exclusion; a GEM section can also point at a private gem server (Gemfury,
// a company's own gem-in-a-box), whose gems were never published to
// rubygems.org either and so can't be matched against RubyGems advisory
// data without risking the same kind of false match.
func isRubygemsRemote(remote string) bool {
	remote = strings.Trim(strings.TrimSpace(remote), `"'`)
	u, err := url.Parse(remote)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), "rubygems.org")
}

// gemKnownPlatforms are the platform suffixes Bundler appends to a locked
// gem's version when it holds a prebuilt native-extension variant --
// "nokogiri (1.15.4-x86_64-linux)" and "nokogiri (1.15.4-arm64-darwin)" can
// both be locked at once for different deployment targets. The suffix has
// to be recognized and stripped to compare against RubyGems advisory data,
// which is keyed on the plain version ("1.15.4"); this list is not
// exhaustive (Ruby platform strings are open-ended), so an unrecognized
// hyphenated suffix is left as part of the version rather than guessed at --
// it may genuinely be a prerelease version instead of a platform ("1.15.4-pre").
var gemKnownPlatforms = []string{
	"x86_64-linux", "x86_64-linux-gnu", "x86_64-linux-musl",
	"aarch64-linux", "aarch64-linux-gnu", "aarch64-linux-musl",
	"arm-linux", "arm64-darwin", "x86_64-darwin", "universal-darwin",
	"x86-mingw32", "x64-mingw32", "x64-mingw-ucrt", "universal-mingw32",
	"java", "jruby",
}

func stripGemPlatformSuffix(version string) string {
	for _, p := range gemKnownPlatforms {
		if strings.HasSuffix(version, "-"+p) {
			return strings.TrimSuffix(version, "-"+p)
		}
	}
	return version
}

var gemNameTokenRe = regexp.MustCompile(`^([^\s(!]+)`)

// gemNameToken extracts the leading name from a Gemfile.lock line like
// "rack (~> 2.0, >= 2.2.4)", "rack (2.2.6.4)", "myapp!" or plain "rack".
func gemNameToken(s string) string {
	m := gemNameTokenRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

var gemSpecLineRe = regexp.MustCompile(`^([^\s(]+)\s*\(([^)]+)\)$`)

// parseGemSpecLine parses a "specs:" entry line ("rack (2.2.6.4)") into its
// name and version, with any platform suffix stripped from the version.
func parseGemSpecLine(line string) (name, version string) {
	m := gemSpecLineRe.FindStringSubmatch(line)
	if m == nil {
		return "", ""
	}
	return m[1], stripGemPlatformSuffix(m[2])
}

// leadingSpaces counts a line's indentation. Gemfile.lock's own writer uses
// a fixed, consistent indent (0/2/4/6 spaces for section/remote-or-specs/
// spec/spec-dependency), so indentation depth -- not a line's TOML-like
// syntax, since this format has none -- is what tells these apart.
func leadingSpaces(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// parseGemfileLock reads every GEM/GIT/PATH section's specs (for the
// dependency graph and version lookup) and the DEPENDENCIES section (the
// Gemfile's own direct dependency names, bang-suffixed when sourced from a
// GIT/PATH section rather than the default GEM source).
func parseGemfileLock(data string) (specs []gemSpec, directDeps []string) {
	var section string
	var sectionIsRubygems bool
	var inSpecs bool
	var current *gemSpec

	for _, raw := range strings.Split(data, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := leadingSpaces(raw)
		trimmed := strings.TrimSpace(raw)

		if indent == 0 {
			section = trimmed
			sectionIsRubygems = false
			inSpecs = false
			current = nil
			continue
		}

		switch section {
		case "GEM", "GIT", "PATH":
			if indent == 2 {
				if rest, ok := strings.CutPrefix(trimmed, "remote:"); ok {
					sectionIsRubygems = isRubygemsRemote(rest)
				} else if trimmed == "specs:" {
					inSpecs = true
				}
				current = nil
				continue
			}
			if indent == 4 && inSpecs {
				name, version := parseGemSpecLine(trimmed)
				if name == "" {
					continue
				}
				specs = append(specs, gemSpec{name: name, version: version, fromRubygems: sectionIsRubygems})
				current = &specs[len(specs)-1]
				continue
			}
			if indent == 6 && inSpecs && current != nil {
				if dep := gemNameToken(trimmed); dep != "" {
					current.dependencies = append(current.dependencies, dep)
				}
			}
		case "DEPENDENCIES":
			if indent == 2 {
				if name := gemNameToken(trimmed); name != "" {
					directDeps = append(directDeps, name)
				}
			}
		}
	}
	return specs, directDeps
}

// bundleWithoutGroups returns the Bundler groups excluded from this
// install -- the names passed to "bundle install --without ..." or "bundle
// config set --local without ...", recorded as BUNDLE_WITHOUT (colon
// joined). Checked first as an environment variable (set directly, or by a
// live process inheriting it), then in the config file "--local" writes:
// normally .bundle/config next to Gemfile.lock, but at BUNDLE_APP_CONFIG
// instead when that's set -- the official Ruby Docker images set it to
// /usr/local/bundle precisely to keep bundle's own config and cache out of
// the app directory, found scanning a container built from one: its config
// ended up at /usr/local/bundle/config, not /app/.bundle/config. Returns
// nil, meaning "nothing known to be excluded", when none of these are
// present -- in Bundler's own default, every group installs, so that
// reading is also the correct one, not just a fallback.
//
// On a live scan, BUNDLE_WITHOUT/BUNDLE_APP_CONFIG are the real process
// environment and any BUNDLE_APP_CONFIG path is already correct as-is. For
// an image scan, both are instead the scanned image's own declared ENV
// (collector.applyImageEnv, since no container ever ran to apply them any
// other way), so a BUNDLE_APP_CONFIG path from there names a location
// inside the image, not this host -- scanPath (the extracted rootfs) is
// prefixed onto it when isContainer to read the real file.
func bundleWithoutGroups(lockDir, scanPath string, isContainer bool) []string {
	if v := os.Getenv("BUNDLE_WITHOUT"); v != "" {
		return strings.Split(v, ":")
	}

	configDir := filepath.Join(lockDir, ".bundle")
	if v := os.Getenv("BUNDLE_APP_CONFIG"); v != "" {
		configDir = v
		if isContainer {
			configDir = filepath.Join(scanPath, configDir)
		}
	}

	data, err := os.ReadFile(filepath.Join(configDir, "config"))
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "BUNDLE_WITHOUT:")
		if !ok {
			continue
		}
		v := strings.Trim(strings.TrimSpace(rest), `"'`)
		if v == "" {
			return nil
		}
		return strings.Split(v, ":")
	}
	return nil
}

// rubyDependencyGroups returns each of the Gemfile's own direct
// dependencies' declared Bundler groups, by having Ruby's own Bundler
// library evaluate the Gemfile DSL (Bundler::Dsl#eval_gemfile) -- the only
// way to resolve `group`/`platforms`/conditionals correctly, the same
// reason gradle.go runs `gradle dependencies` and maven.go runs `mvn
// dependency:tree` against those build tools' own DSLs rather than
// re-implementing them. This does not install, resolve or fetch anything;
// it only parses the Gemfile and records each `gem` call's declared groups.
// Returns ok=false when ruby isn't available, the bundler library can't be
// loaded, or the Gemfile is missing or fails to evaluate, so callers fall
// back to reporting no scope information rather than a wrong one.
func rubyDependencyGroups(gemfileDir string) (groups map[string][]string, ok bool) {
	gemfile := filepath.Join(gemfileDir, "Gemfile")
	if _, err := os.Stat(gemfile); err != nil {
		return nil, false
	}
	if _, err := exec.LookPath("ruby"); err != nil {
		return nil, false
	}

	const script = `
require "bundler"
begin
  dsl = Bundler::Dsl.new
  dsl.eval_gemfile(ARGV[0])
  dsl.dependencies.each { |d| puts "#{d.name}\t#{d.groups.join(",")}" }
rescue Exception
  exit 1
end
`
	cmd := exec.Command("ruby", "-e", script, gemfile)
	cmd.Dir = gemfileDir
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}

	groups = make(map[string][]string)
	for _, line := range strings.Split(string(out), "\n") {
		name, rest, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		var gs []string
		if rest = strings.TrimSpace(rest); rest != "" {
			gs = strings.Split(rest, ",")
		}
		groups[name] = gs
	}
	return groups, true
}

func gemKey(name, version string) string { return name + "@" + version }

// markBundlerDevOnlyScope sets Scope "excluded" on every locked gem reachable
// from the Gemfile's direct dependencies only through a group named in
// bundleWithoutGroups -- a group Bundler itself was told to skip installing,
// so authoritative rather than a guess. Needs both pieces of information
// (which groups each direct dependency belongs to, and which groups are
// actually excluded here); either missing means "can't tell", so Scope is
// left unset rather than assuming common names like :development/:test are
// excluded when this specific install never said so.
func markBundlerDevOnlyScope(pkgs []inventory.Package, specs []gemSpec, directDeps []string, lockDir, scanPath string, isContainer bool) {
	without := bundleWithoutGroups(lockDir, scanPath, isContainer)
	if len(without) == 0 {
		return
	}
	groups, ok := rubyDependencyGroups(lockDir)
	if !ok {
		return
	}

	excluded := make(map[string]bool, len(without))
	for _, g := range without {
		excluded[g] = true
	}

	byKey := make(map[string]*gemSpec, len(specs))
	versionsByName := make(map[string]string, len(specs))
	for i := range specs {
		byKey[gemKey(specs[i].name, specs[i].version)] = &specs[i]
		versionsByName[specs[i].name] = specs[i].version
	}

	var frontier []string
	for _, name := range directDeps {
		depGroups, known := groups[name]
		if !known {
			continue // the Gemfile DSL didn't declare this name; don't guess its groups
		}
		if allGroupsExcluded(depGroups, excluded) {
			continue
		}
		if v, ok := versionsByName[name]; ok {
			frontier = append(frontier, gemKey(name, v))
		}
	}
	if len(frontier) == 0 {
		return
	}

	required := make(map[string]bool, len(specs))
	for len(frontier) > 0 {
		key := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if required[key] {
			continue
		}
		required[key] = true
		spec, ok := byKey[key]
		if !ok {
			continue
		}
		for _, depName := range spec.dependencies {
			if v, ok := versionsByName[depName]; ok {
				frontier = append(frontier, gemKey(depName, v))
			}
		}
	}

	for i := range pkgs {
		if !required[gemKey(pkgs[i].Name, pkgs[i].Version)] {
			pkgs[i].Scope = "excluded"
		}
	}
}

// allGroupsExcluded reports whether every group in groups is in excluded --
// a dependency declared with no group at all defaults to Bundler's own
// :default group, which "bundle install --without" can never name, so an
// empty groups list is never considered excluded.
func allGroupsExcluded(groups []string, excluded map[string]bool) bool {
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !excluded[g] {
			return false
		}
	}
	return true
}

// parseGemfileLockFile parses one Gemfile.lock and returns the gems sourced
// from rubygems.org, with their dependency graph resolved to PURLs.
func parseGemfileLockFile(path string, verbose bool, scanPath string, isContainer bool) ([]inventory.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	specs, directDeps := parseGemfileLock(string(data))
	directSet := make(map[string]bool, len(directDeps))
	for _, d := range directDeps {
		directSet[d] = true
	}
	versionsByName := make(map[string]string, len(specs))
	for _, s := range specs {
		versionsByName[s.name] = s.version
	}

	var pkgs []inventory.Package
	for _, s := range specs {
		if s.name == "" || s.version == "" || !s.fromRubygems {
			continue
		}

		var deps []string
		for _, depName := range s.dependencies {
			if v, ok := versionsByName[depName]; ok {
				deps = append(deps, gemPURL(depName, v))
			}
		}

		pkgs = append(pkgs, inventory.Package{
			Name:       s.name,
			Version:    s.version,
			RawVersion: s.version,
			Ecosystem:  "RubyGems",
			Source:     "Gemfile.lock",
			Location:   path,
			Direct:     inventory.BoolPtr(directSet[s.name]),
			Deps:       deps,
		})
	}

	markBundlerDevOnlyScope(pkgs, specs, directDeps, filepath.Dir(path), scanPath, isContainer)

	if verbose {
		log.Printf("[bundler] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, nil
}

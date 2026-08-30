package collector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/TITeee/heretix-cli/inventory"
)

// goExcludeDirs lists directory names to skip during filesystem walk.
var goExcludeDirs = map[string]bool{
	"vendor":   true,
	".git":     true,
	"testdata": true,
}

// GoCollector collects Go module dependencies from go.mod files.
type GoCollector struct{}

func (c *GoCollector) Name() string { return "go" }

func (c *GoCollector) Collect(scanPath string, verbose bool, isContainer bool) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	found := false

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if goExcludeDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}

		p, err := goModulePackages(path, verbose)
		if err != nil {
			if verbose {
				log.Printf("[go] error collecting %s: %v", path, err)
			}
			return nil
		}
		pkgs = append(pkgs, p...)
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", scanPath, err)
	}

	if !found {
		p, err := goListAllInDir(scanPath, verbose)
		if err != nil {
			if verbose {
				log.Printf("[go] go list fallback failed: %v", err)
			}
		} else {
			pkgs = append(pkgs, p...)
		}
	}

	enrichGoLicensesFromCache(pkgs, verbose)

	if verbose {
		log.Printf("[go] collected %d packages", len(pkgs))
	}
	return pkgs, nil
}

// goModulePackages returns all modules in the dependency graph for the module
// rooted at goModPath. It prefers "go list -m -json all" (run in the module
// directory) because that includes every transitive dependency — the same set
// that govulncheck / Dependabot use. Falls back to parsing go.mod directly
// when the go binary is unavailable or the command fails.
func goModulePackages(goModPath string, verbose bool) ([]inventory.Package, error) {
	dir := filepath.Dir(goModPath)
	pkgs, err := goListAllInDir(dir, verbose)
	if err == nil && len(pkgs) > 0 {
		return pkgs, nil
	}
	if verbose && err != nil {
		log.Printf("[go] go list failed for %s, falling back to go.mod parse: %v", dir, err)
	}
	return parseGoMod(goModPath, verbose)
}

// goListAllInDir runs "go list -m -json all" in dir and returns all modules
// in the resolved dependency graph (direct + indirect + transitive).
// It also calls goModGraph to populate Deps and Direct on each package.
//
// The result is filtered against goModDeclaredModules: "go list -m all" (and
// "go mod graph", used below) walk the full historical module graph, which
// includes modules needed only by some *other* dependency's own test suite —
// never something this module's build or its own tests can reach. go.mod
// itself (Go 1.17+ module graph pruning) is already the authoritative
// "actually needed" list, so anything outside it is dropped. See the
// 2026-08-30 false-positive investigation: heretix-cli's own module graph
// reported google.golang.org/grpc and golang.org/x/mod even though `go mod
// why -m` shows this module doesn't need them at all, and reported
// gopkg.in/yaml.v3/go.opentelemetry.io/otel/sdk even though both are reachable
// only through a dependency's ".test" edge (e.g. cyclonedx-go's own test
// suite), not through any code heretix-cli actually imports.
func goListAllInDir(dir string, verbose bool) ([]inventory.Package, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return nil, fmt.Errorf("go not found in PATH")
	}

	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list in %s: %w", dir, err)
	}

	allowed, allowedOK := goModDeclaredModules(filepath.Join(dir, "go.mod"), verbose)

	var pkgs []inventory.Package
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	for decoder.More() {
		var mod struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Main    bool   `json:"Main"`
		}
		if err := decoder.Decode(&mod); err != nil {
			break
		}
		if mod.Main || mod.Path == "" || mod.Version == "" {
			continue
		}
		if allowedOK && !allowed[mod.Path] {
			continue
		}
		pkgs = append(pkgs, inventory.Package{
			Name:       mod.Path,
			Version:    mod.Version,
			RawVersion: mod.Version,
			Ecosystem:  "Go",
			Source:     "go.mod",
			Location:   filepath.Join(dir, "go.mod"),
		})
	}

	// Populate Deps and Direct from go mod graph (best-effort; skipped on failure)
	depsByKey, directKeys := goModGraph(dir, verbose, allowed, allowedOK)
	for i := range pkgs {
		key := pkgs[i].Name + "@" + pkgs[i].Version
		if deps, ok := depsByKey[key]; ok {
			pkgs[i].Deps = deps
		}
		if len(directKeys) > 0 {
			pkgs[i].Direct = inventory.BoolPtr(directKeys[key])
		}
	}

	if verbose {
		log.Printf("[go] go list collected %d packages from %s", len(pkgs), dir)
	}
	return pkgs, nil
}

// goModDeclaredModules returns the set of module paths go.mod itself declares
// (direct and indirect combined), by reusing parseGoMod's require-block
// parsing. ok is false when go.mod couldn't be read/parsed, so callers can
// tell "legitimately no dependencies" (empty set, ok=true) apart from
// "unknown, don't filter" (ok=false).
func goModDeclaredModules(goModPath string, verbose bool) (allowed map[string]bool, ok bool) {
	pkgs, err := parseGoMod(goModPath, verbose)
	if err != nil {
		return nil, false
	}
	allowed = make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		allowed[p.Name] = true
	}
	return allowed, true
}

// goModGraph runs "go mod graph" in dir and returns:
//   - depsByKey: map of "module@version" → []PURL of its direct dependencies
//   - directKeys: set of "module@version" strings that are direct deps of the main module
//
// allowed/allowedOK mirror goModDeclaredModules: when allowedOK is true, an
// edge is dropped whenever its target module isn't in allowed. "go mod graph"
// walks the same full historical module graph as "go list -m all" (see
// goListAllInDir), so without this filter a package that did survive that
// filter could still end up with a Deps entry pointing at a PURL for a module
// this build doesn't actually include — a dangling reference once that module
// itself is filtered out of the package list.
//
// Returns empty maps on any failure (go binary missing, network unavailable, etc.)
// so callers can treat it as best-effort enrichment.
func goModGraph(dir string, verbose bool, allowed map[string]bool, allowedOK bool) (depsByKey map[string][]string, directKeys map[string]bool) {
	depsByKey = make(map[string][]string)
	directKeys = make(map[string]bool)

	if _, err := exec.LookPath("go"); err != nil {
		return
	}

	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if verbose {
			log.Printf("[go] go mod graph failed in %s: %v", dir, err)
		}
		return
	}

	var mainModule string
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		lines = append(lines, line)
		// The main module appears on the left side without an "@version" suffix
		if !strings.Contains(parts[0], "@") {
			mainModule = parts[0]
		}
	}

	for _, line := range lines {
		parts := strings.Fields(line)
		left, right := parts[0], parts[1]
		if allowedOK && !allowed[modulePathOf(right)] {
			continue
		}
		depsByKey[left] = append(depsByKey[left], goModuleToPURL(right))
		if mainModule != "" && left == mainModule {
			directKeys[right] = true
		}
	}

	if verbose {
		log.Printf("[go] go mod graph: %d module edges from %s", len(lines), dir)
	}
	return
}

// modulePathOf strips the "@version" suffix from a "go mod graph" token,
// leaving just the module path.
func modulePathOf(moduleAtVersion string) string {
	if at := strings.LastIndex(moduleAtVersion, "@"); at >= 0 {
		return moduleAtVersion[:at]
	}
	return moduleAtVersion
}

// goModuleToPURL converts a "module@version" token from go mod graph output
// to a CycloneDX-compatible PURL (pkg:golang/MODULE@VERSION).
func goModuleToPURL(moduleAtVersion string) string {
	at := strings.LastIndex(moduleAtVersion, "@")
	if at < 0 {
		return "pkg:golang/" + moduleAtVersion
	}
	return fmt.Sprintf("pkg:golang/%s@%s", moduleAtVersion[:at], moduleAtVersion[at+1:])
}

// parseGoMod parses a go.mod file and returns the declared dependencies.
// It handles both block require directives (require (...)) and single-line
// require statements (require name version).
func parseGoMod(path string, verbose bool) ([]inventory.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []inventory.Package
	inRequireBlock := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		// Check for // indirect before stripping the comment
		isIndirect := strings.Contains(line, "// indirect")

		// Strip inline comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		// Start of a require block
		if line == "require (" || line == "require(" {
			inRequireBlock = true
			continue
		}

		// End of a require block
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock {
			pkg := parseRequireLine(line, path, isIndirect)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
			continue
		}

		// Single-line require: "require github.com/foo/bar v1.2.3"
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			rest = strings.TrimSpace(rest)
			// Could still be "require (" on the same line — skip
			if rest == "(" {
				inRequireBlock = true
				continue
			}
			pkg := parseRequireLine(rest, path, isIndirect)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
		}
	}

	if verbose {
		log.Printf("[go] parsed %d packages from %s", len(pkgs), path)
	}
	return pkgs, scanner.Err()
}

// parseRequireLine parses a single "name version" line from a require block.
// isIndirect should be true when the original line contained "// indirect".
func parseRequireLine(line, location string, isIndirect bool) *inventory.Package {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	name := fields[0]
	version := fields[1]

	// Skip retract, replace, and exclude directives that may appear in go.mod
	if name == "=>" || version == "=>" {
		return nil
	}

	direct := inventory.BoolPtr(!isIndirect)
	return &inventory.Package{
		Name:       name,
		Version:    version,
		RawVersion: version,
		Ecosystem:  "Go",
		Source:     "go.mod",
		Location:   location,
		Direct:     direct,
	}
}

// goLicenseFileNames are the conventional names Go modules use for their license
// file, tried in this order.
var goLicenseFileNames = []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "COPYING.md"}

// goModCache returns the module download cache directory via "go env GOMODCACHE".
// Returns "" if the go binary is unavailable or the command fails.
func goModCache() string {
	if _, err := exec.LookPath("go"); err != nil {
		return ""
	}
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// escapeGoModulePath applies Go's module cache escaping: each uppercase letter is
// replaced with '!' followed by its lowercase form, so cache directory names stay
// case-insensitive-filesystem-safe (mirrors golang.org/x/mod/module.EscapePath).
// "github.com/BurntSushi/toml" -> "github.com/!burnt!sushi/toml"
func escapeGoModulePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r - 'A' + 'a')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// findGoModuleLicenseFile locates a module's license file inside the module cache
// ({modCache}/{escaped-path}@{version}/). Returns "" if the module isn't cached
// locally or carries none of the conventional license filenames.
func findGoModuleLicenseFile(modCache, modPath, version string) string {
	dir := filepath.Join(modCache, escapeGoModulePath(modPath)+"@"+version)
	for _, name := range goLicenseFileNames {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// classifyLicenseText applies a best-effort match against known license title
// lines to derive an SPDX identifier. License files are free-form prose, not
// structured metadata, so only the first few lines are checked against common
// headers; anything else is left unclassified rather than guessed at.
func classifyLicenseText(text string) string {
	lines := strings.SplitN(text, "\n", 6)
	head := strings.ToLower(strings.Join(lines, " "))

	switch {
	case strings.Contains(head, "mit license"):
		return "MIT"
	case strings.Contains(head, "apache license") && strings.Contains(head, "2.0"):
		return "Apache-2.0"
	case strings.Contains(head, "bsd 3-clause"):
		return "BSD-3-Clause"
	case strings.Contains(head, "bsd 2-clause"):
		return "BSD-2-Clause"
	case strings.Contains(head, "mozilla public license") && strings.Contains(head, "2.0"):
		return "MPL-2.0"
	case strings.Contains(head, "gnu lesser general public license") && strings.Contains(head, "3"):
		return "LGPL-3.0"
	case strings.Contains(head, "gnu general public license") && strings.Contains(head, "3"):
		return "GPL-3.0"
	case strings.Contains(head, "isc license"):
		return "ISC"
	case strings.Contains(head, "unlicense"):
		return "Unlicense"
	}
	return ""
}

// enrichGoLicensesFromCache fills in License for packages whose module is present
// in the local Go module cache (GOMODCACHE). This only helps on a live host that
// has previously built against these modules — the cache isn't part of a
// container image, so this is a no-op there. Best-effort: missing cache, missing
// license file, or unrecognized license text all leave License as-is.
func enrichGoLicensesFromCache(pkgs []inventory.Package, verbose bool) {
	modCache := goModCache()
	if modCache == "" {
		return
	}

	found := 0
	for i := range pkgs {
		if pkgs[i].License != "" {
			continue
		}
		licPath := findGoModuleLicenseFile(modCache, pkgs[i].Name, pkgs[i].Version)
		if licPath == "" {
			continue
		}
		data, err := os.ReadFile(licPath)
		if err != nil {
			continue
		}
		if lic := classifyLicenseText(string(data)); lic != "" {
			pkgs[i].License = lic
			found++
		}
	}

	if verbose {
		log.Printf("[go] enriched %d packages with license from module cache (%s)", found, modCache)
	}
}

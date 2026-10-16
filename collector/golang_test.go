package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// TestGoModDeclaredModules checks the pure go.mod-parsing side of the
// module-graph filter: the returned set must contain every module the
// require block(s) declare, direct or indirect, and nothing else.
func TestGoModDeclaredModules(t *testing.T) {
	dir := t.TempDir()
	goModPath := filepath.Join(dir, "go.mod")
	content := `module example.com/app

go 1.21

require github.com/direct/pkg v1.0.0

require (
	github.com/indirect/pkg v2.0.0 // indirect
)
`
	if err := os.WriteFile(goModPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	allowed, ok := goModDeclaredModules(goModPath, false)
	if !ok {
		t.Fatal("goModDeclaredModules: ok = false, want true")
	}
	for _, want := range []string{"github.com/direct/pkg", "github.com/indirect/pkg"} {
		if !allowed[want] {
			t.Errorf("allowed set missing %q: %v", want, allowed)
		}
	}
	if allowed["github.com/not/declared"] {
		t.Error("allowed set contains a module go.mod never declared")
	}
}

func TestGoModDeclaredModules_MissingFile(t *testing.T) {
	_, ok := goModDeclaredModules(filepath.Join(t.TempDir(), "go.mod"), false)
	if ok {
		t.Error("goModDeclaredModules: ok = true for a nonexistent go.mod, want false")
	}
}

// TestGoListAllInDir_ExcludesTestOnlyTransitiveModules is an integration-style
// regression test for the 2026-08-30 investigation: run against heretix-cli's
// own real go.mod/go.sum, "go list -m all" plus "go mod graph" report modules
// this module's build does not need at all (google.golang.org/grpc,
// golang.org/x/mod — confirmed independently via `go mod why -m`) and modules
// reachable only through a dependency's own ".test" edge
// (gopkg.in/yaml.v3 via cyclonedx-go's test suite, go.opentelemetry.io/otel/sdk
// via otelhttp's test suite) — none of which end up in heretix-cli's compiled
// binary. Skipped when the go toolchain isn't available to run the scan.
func TestGoListAllInDir_ExcludesTestOnlyTransitiveModules(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not available")
	}

	// collector/ is the test's working directory; the module root is its parent.
	pkgs, err := goListAllInDir("..", false)
	if err != nil {
		t.Fatalf("goListAllInDir: %v", err)
	}

	excluded := map[string]bool{
		"google.golang.org/grpc":       true,
		"golang.org/x/mod":             true,
		"gopkg.in/yaml.v3":             true,
		"go.opentelemetry.io/otel/sdk": true,
	}
	for _, p := range pkgs {
		if excluded[p.Name] {
			t.Errorf("goListAllInDir reported %s, but heretix-cli's build does not need it (unreachable outside another module's own test suite)", p.Name)
		}
	}

	foundReal := false
	for _, p := range pkgs {
		if p.Name == "go.opentelemetry.io/otel" {
			foundReal = true
		}
	}
	if !foundReal {
		t.Error("expected go.opentelemetry.io/otel (a real go.mod dependency) to still be reported")
	}
}

// resolveModGraph must point every edge at the version the build selects:
// "go mod graph" names the version each module asked for, which is not a
// component of the SBOM unless it happens to be the selected one.
func TestResolveModGraph_PointsEdgesAtSelectedVersions(t *testing.T) {
	graph := `example.com/app golang.org/x/sys@v0.42.0
example.com/app github.com/a/lib@v1.2.0
github.com/a/lib@v1.2.0 golang.org/x/sys@v0.10.0
github.com/a/lib@v1.2.0 golang.org/x/sys@v0.13.0
github.com/a/lib@v1.2.0 github.com/b/testonly@v0.1.0
github.com/a/lib@v1.0.0 github.com/c/old@v0.1.0
golang.org/x/sys@v0.10.0 github.com/d/gone@v1.0.0
`
	selected := map[string]string{
		"golang.org/x/sys": "v0.42.0",
		"github.com/a/lib": "v1.2.0",
		"github.com/c/old": "v0.1.0",
	}
	depsByKey, directKeys, edges := resolveModGraph(graph, selected)

	if edges != 7 {
		t.Errorf("edges = %d, want 7", edges)
	}
	want := map[string][]string{
		"example.com/app": {"pkg:golang/golang.org/x/sys@v0.42.0", "pkg:golang/github.com/a/lib@v1.2.0"},
		// Both requested x/sys versions collapse into the selected one; the
		// module go.mod doesn't declare is dropped.
		"github.com/a/lib@v1.2.0": {"pkg:golang/golang.org/x/sys@v0.42.0"},
		// lib@v1.0.0 and x/sys@v0.10.0 are not what the build uses, so their
		// requirements are not edges of anything in the SBOM.
	}
	if !reflect.DeepEqual(depsByKey, want) {
		t.Errorf("depsByKey = %v, want %v", depsByKey, want)
	}
	if !reflect.DeepEqual(directKeys, map[string]bool{"golang.org/x/sys@v0.42.0": true, "github.com/a/lib@v1.2.0": true}) {
		t.Errorf("directKeys = %v", directKeys)
	}
}

// On heretix-cli's own module, every dependency edge must point at a package
// the scan reports, or the SBOM's dependsOn references dangle.
func TestGoListAllInDir_EdgesPointAtReportedPackages(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not available")
	}
	pkgs, err := goListAllInDir("..", false)
	if err != nil {
		t.Fatalf("goListAllInDir: %v", err)
	}
	reported := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		reported[goModuleToPURL(p.Name+"@"+p.Version)] = true
	}
	edges := 0
	for _, p := range pkgs {
		for _, d := range p.Deps {
			edges++
			if !reported[d] {
				t.Errorf("%s@%s depends on %s, which is not a reported package", p.Name, p.Version, d)
			}
		}
	}
	if edges == 0 {
		t.Error("expected some dependency edges")
	}
}

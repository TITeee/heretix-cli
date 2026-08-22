package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const gradleLockfileFixture = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.springframework:spring-core:5.3.20=compileClasspath,runtimeClasspath
com.fasterxml.jackson.core:jackson-databind:2.15.2=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
org.mockito:mockito-core:5.4.0=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor,testAnnotationProcessor
`

func TestParseGradleLockfile_ScopeReflectsConfigurations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gradle.lockfile")
	if err := os.WriteFile(path, []byte(gradleLockfileFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parseGradleLockfile(path, false)
	if err != nil {
		t.Fatal(err)
	}

	scopes := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		scopes[p.Name] = p.Scope
	}

	want := map[string]string{
		"org.springframework:spring-core":             "", // prod-only
		"com.fasterxml.jackson.core:jackson-databind": "", // prod AND test — still ships
		"junit:junit":              "excluded", // test-only
		"org.mockito:mockito-core": "excluded", // test-only
	}
	for name, wantScope := range want {
		if got, ok := scopes[name]; !ok {
			t.Errorf("package %q not found in parsed output", name)
		} else if got != wantScope {
			t.Errorf("package %q: got scope %q, want %q", name, got, wantScope)
		}
	}

	if _, ok := scopes["empty"]; ok {
		t.Error("the \"empty=\" summary line must not be parsed as a package")
	}
}

func TestGradleLockfileScope(t *testing.T) {
	cases := map[string]string{
		"compileClasspath,runtimeClasspath":         "",
		"testCompileClasspath,testRuntimeClasspath": "excluded",
		"compileClasspath,testRuntimeClasspath":     "",
		"annotationProcessor":                       "",
		"testAnnotationProcessor":                   "excluded",
		"":                                          "",
		"  ":                                        "",
		" testCompileClasspath , testRuntimeClasspath ": "excluded",
	}
	for input, want := range cases {
		if got := gradleLockfileScope(input); got != want {
			t.Errorf("gradleLockfileScope(%q) = %q, want %q", input, got, want)
		}
	}
}

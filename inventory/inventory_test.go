package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	inv := New("host1", OSInfo{ID: "ubuntu", VersionID: "22.04"})

	if inv.Version != "1.0" {
		t.Errorf("Version = %q, want %q", inv.Version, "1.0")
	}
	if inv.Hostname != "host1" {
		t.Errorf("Hostname = %q, want %q", inv.Hostname, "host1")
	}
	if inv.OS.ID != "ubuntu" {
		t.Errorf("OS.ID = %q, want %q", inv.OS.ID, "ubuntu")
	}
	if inv.Packages == nil {
		t.Error("Packages should be an empty slice, not nil, so it marshals as [] rather than null")
	}
	if _, err := time.Parse(time.RFC3339, inv.ScannedAt); err != nil {
		t.Errorf("ScannedAt = %q is not a valid RFC3339 timestamp: %v", inv.ScannedAt, err)
	}
}

func TestWriteToFileThenReadFromFile_RoundTrips(t *testing.T) {
	original := &Inventory{
		Version:  "1.0",
		Hostname: "host1",
		OS:       OSInfo{ID: "alpine", VersionID: "3.19"},
		Packages: []Package{
			{Name: "curl", Version: "8.5.0", Ecosystem: "apk", Source: "apk", Direct: BoolPtr(true)},
		},
	}

	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := original.WriteToFile(path); err != nil {
		t.Fatalf("WriteToFile returned an error: %v", err)
	}

	got, err := ReadFromFile(path)
	if err != nil {
		t.Fatalf("ReadFromFile returned an error: %v", err)
	}
	if !reflect.DeepEqual(original, got) {
		t.Errorf("round-tripped inventory differs:\ngot:  %+v\nwant: %+v", got, original)
	}
}

func TestReadFromFile_MissingFileReturnsError(t *testing.T) {
	_, err := ReadFromFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestReadFromFile_InvalidJSONReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFromFile(path); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestMergeDirectPtr(t *testing.T) {
	tru, fls := BoolPtr(true), BoolPtr(false)

	tests := map[string]struct {
		a, b, want *bool
	}{
		"nil, nil stays nil":       {nil, nil, nil},
		"nil, true becomes true":   {nil, tru, tru},
		"nil, false becomes false": {nil, fls, fls},
		"false, true becomes true": {fls, tru, tru},
		"true, false stays true":   {tru, fls, tru},
		"true, nil stays true":     {tru, nil, tru},
		"false, nil stays false (nil does not override a known false)": {fls, nil, fls},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := mergeDirectPtr(tc.a, tc.b)
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("mergeDirectPtr(%v, %v) = %v, want %v", derefStr(tc.a), derefStr(tc.b), derefStr(got), derefStr(tc.want))
			}
		})
	}
}

func derefStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestMergePkg_FirstNonEmptyWinsPerField(t *testing.T) {
	a := Package{Name: "p", Integrity: "sha256:aaa", Deps: []string{"dep-a"}}
	b := Package{Name: "p", Integrity: "sha256:bbb", License: "MIT", Location: "go.sum", Scope: "excluded", Deps: []string{"dep-b"}}

	got := mergePkg(a, b)

	if got.Integrity != "sha256:aaa" {
		t.Errorf("Integrity = %q, want a's existing value to be kept", got.Integrity)
	}
	if got.License != "MIT" {
		t.Errorf("License = %q, want b's value to fill the empty field", got.License)
	}
	if got.Location != "go.sum" {
		t.Errorf("Location = %q, want b's value to fill the empty field", got.Location)
	}
	if got.Scope != "excluded" {
		t.Errorf("Scope = %q, want b's value to fill the empty field", got.Scope)
	}
	if len(got.Deps) != 1 || got.Deps[0] != "dep-a" {
		t.Errorf("Deps = %v, want a's existing non-empty slice to be kept", got.Deps)
	}
}

func TestDeduplicate(t *testing.T) {
	t.Run("passes through packages with distinct name+version+ecosystem unchanged", func(t *testing.T) {
		pkgs := []Package{
			{Name: "a", Version: "1.0", Ecosystem: "npm"},
			{Name: "a", Version: "2.0", Ecosystem: "npm"},  // different version: not a duplicate
			{Name: "a", Version: "1.0", Ecosystem: "pypi"}, // different ecosystem: not a duplicate
		}
		got := Deduplicate(pkgs)
		if len(got) != 3 {
			t.Fatalf("expected all 3 packages to survive, got %+v", got)
		}
	})

	t.Run("merges a genuine duplicate (same name+version+ecosystem)", func(t *testing.T) {
		pkgs := []Package{
			{Name: "a", Version: "1.0", Ecosystem: "npm", Direct: BoolPtr(false)},
			{Name: "a", Version: "1.0", Ecosystem: "npm", Direct: BoolPtr(true), License: "MIT"},
		}
		got := Deduplicate(pkgs)
		if len(got) != 1 {
			t.Fatalf("expected the duplicates to collapse into one entry, got %+v", got)
		}
		if got[0].Direct == nil || !*got[0].Direct {
			t.Error("expected Direct=true to win when merging")
		}
		if got[0].License != "MIT" {
			t.Errorf("expected License to be merged in, got %q", got[0].License)
		}
	})

	t.Run("preserves first-occurrence order", func(t *testing.T) {
		pkgs := []Package{
			{Name: "z", Version: "1.0", Ecosystem: "npm"},
			{Name: "a", Version: "1.0", Ecosystem: "npm"},
		}
		got := Deduplicate(pkgs)
		if len(got) != 2 || got[0].Name != "z" || got[1].Name != "a" {
			t.Errorf("expected order z, a to be preserved, got %+v", got)
		}
	})
}

func TestDeduplicateBy(t *testing.T) {
	byPurlLikeName := func(p Package) string { return p.Name }

	pkgs := []Package{
		{Name: "a", Version: "1.0"},
		{Name: "b", Version: "1.0"},
		{Name: "a", Version: "2.0"}, // same key as the first despite a different version -- custom key wins
	}
	merged, collapsed := DeduplicateBy(pkgs, byPurlLikeName)

	if len(merged) != 2 {
		t.Fatalf("expected 2 merged entries, got %+v", merged)
	}
	if len(collapsed) != 1 || collapsed[0] != "a" {
		t.Errorf("expected exactly one collapsed key \"a\", got %v", collapsed)
	}

	t.Run("a key seen only once is not reported as collapsed", func(t *testing.T) {
		_, collapsed := DeduplicateBy([]Package{{Name: "solo"}}, byPurlLikeName)
		if len(collapsed) != 0 {
			t.Errorf("expected no collapsed keys, got %v", collapsed)
		}
	})
}

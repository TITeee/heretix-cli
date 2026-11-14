package collector

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsTestdataDir(t *testing.T) {
	root := filepath.Join("srv", "app")
	tests := map[string]struct {
		path string
		want bool
	}{
		"a nested testdata directory":         {filepath.Join(root, "detector", "testdata"), true},
		"the scan root itself, even if named": {filepath.Join("srv", "testdata"), false},
		"a directory merely containing it":    {filepath.Join(root, "testdata-tools"), false},
		"an ordinary directory":               {filepath.Join(root, "src"), false},
	}
	for name, tc := range tests {
		scanPath := root
		if name == "the scan root itself, even if named" {
			scanPath = tc.path
		}
		if got := isTestdataDir(tc.path, scanPath); got != tc.want {
			t.Errorf("%s: isTestdataDir(%q, %q) = %v, want %v", name, tc.path, scanPath, got, tc.want)
		}
	}
}

func TestIsWindowsSystemDir(t *testing.T) {
	// The drive root of this machine: "C:\" on Windows, "/" elsewhere.
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	project := filepath.Join(root, "srv", "app")
	tests := map[string]struct {
		goos, path, scanPath string
		want                 bool
	}{
		"Windows under the scanned drive root":     {"windows", filepath.Join(root, "Windows"), root, true},
		"matched without regard to case":           {"windows", filepath.Join(root, "WINDOWS"), root, true},
		"the recycle bin":                          {"windows", filepath.Join(root, "$Recycle.Bin"), root, true},
		"System Volume Information":                {"windows", filepath.Join(root, "System Volume Information"), root, true},
		"an application directory":                 {"windows", filepath.Join(root, "Program Files"), root, false},
		"a Windows directory deeper down":          {"windows", filepath.Join(root, "Users", "dev", "Windows"), root, false},
		"a scan path below the root (a project)":   {"windows", filepath.Join(project, "Windows"), project, false},
		"a scan path below the root (its own dir)": {"windows", project, project, false},
		"a host other than Windows":                {"linux", filepath.Join(root, "Windows"), root, false},
	}
	for name, tc := range tests {
		if got := isWindowsSystemDir(tc.goos, tc.path, tc.scanPath); got != tc.want {
			t.Errorf("%s: isWindowsSystemDir(%q, %q, %q) = %v, want %v", name, tc.goos, tc.path, tc.scanPath, got, tc.want)
		}
	}
}

// TestPyPICollect_SkipsTestdataUnlessItIsTheScanRoot is the regression test
// for a requirements.txt fixture under detector/testdata showing up as a real
// PyPI dependency (and alert) when heretix-cli scanned its own repository.
func TestPyPICollect_SkipsTestdataUnlessItIsTheScanRoot(t *testing.T) {
	root := t.TempDir()
	fixtures := filepath.Join(root, "detector", "testdata")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, "requirements.txt"), []byte("pydantic==2.9.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&PyPICollector{}).Collect(root, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("scanning the project collected %d packages from testdata, want 0: %+v", len(pkgs), pkgs)
	}

	pkgs, err = (&PyPICollector{}).Collect(fixtures, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("scanning the testdata directory itself collected %d packages, want 1", len(pkgs))
	}
}

// TestGoCollect_WarnsWhenGoIsMissing guards the warning that replaced a
// --verbose-only log line: without the go command, go.mod is parsed directly
// and the SBOM silently loses every Go dependency edge.
func TestGoCollect_WarnsWhenGoIsMissing(t *testing.T) {
	root := t.TempDir()
	goMod := "module example.com/app\n\ngo 1.21\n\nrequire github.com/direct/pkg v1.0.0\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")

	var logs bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	pkgs, err := (&GoCollector{}).Collect(root, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("collected %d packages from go.mod, want 1", len(pkgs))
	}
	if !strings.Contains(logs.String(), "the go command is not in PATH") {
		t.Errorf("no warning about the missing go command; log output:\n%s", logs.String())
	}
}

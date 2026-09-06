package container

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildTar writes a tar archive from the given entries and returns its bytes.
// entries with Linkname set and Typeflag tar.TypeSymlink or tar.TypeLink
// don't need a Size; regular files carry their content via the accompanying
// data map keyed by name.
func buildTar(t *testing.T, headers []*tar.Header, data map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range headers {
		if content, ok := data[h.Name]; ok {
			h.Size = int64(len(content))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("WriteHeader(%q): %v", h.Name, err)
		}
		if content, ok := data[h.Name]; ok {
			if _, err := tw.Write([]byte(content)); err != nil {
				t.Fatalf("Write(%q): %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractTar_RegularFileAndDirectory(t *testing.T) {
	destDir := t.TempDir()
	data := buildTar(t, []*tar.Header{
		{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "etc/hostname", Typeflag: tar.TypeReg, Mode: 0644},
	}, map[string]string{"etc/hostname": "myhost\n"})

	if err := extractTar(bytes.NewReader(data), destDir); err != nil {
		t.Fatalf("extractTar returned an error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(destDir, "etc", "hostname"))
	if err != nil {
		t.Fatalf("could not read extracted file: %v", err)
	}
	if string(content) != "myhost\n" {
		t.Errorf("content = %q, want %q", content, "myhost\n")
	}
}

// TestExtractTar_RejectsPathTraversal reproduces a classic tar-slip attack:
// a layer entry named "../../etc/passwd" that would otherwise write outside
// destDir if the leading ".." weren't rejected.
func TestExtractTar_RejectsPathTraversal(t *testing.T) {
	destDir := t.TempDir()
	parent := filepath.Dir(destDir)
	data := buildTar(t, []*tar.Header{
		{Name: "../escaped.txt", Typeflag: tar.TypeReg, Mode: 0644},
	}, map[string]string{"../escaped.txt": "pwned"})

	if err := extractTar(bytes.NewReader(data), destDir); err != nil {
		t.Fatalf("extractTar returned an error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); err == nil {
		t.Fatal("path traversal entry was written outside destDir")
	}
}

// TestExtractTar_RejectsHardLinkEscapingDestDir reproduces a hard-link
// variant of the same escape: TypeLink pointing its Linkname outside destDir.
func TestExtractTar_RejectsHardLinkEscapingDestDir(t *testing.T) {
	destDir := t.TempDir()
	outsideFile := filepath.Join(filepath.Dir(destDir), "outside-target.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outsideFile)

	data := buildTar(t, []*tar.Header{
		{Name: "link-to-outside", Typeflag: tar.TypeLink, Linkname: "../outside-target.txt"},
	}, nil)

	if err := extractTar(bytes.NewReader(data), destDir); err != nil {
		t.Fatalf("extractTar returned an error: %v", err)
	}

	if _, err := os.Lstat(filepath.Join(destDir, "link-to-outside")); err == nil {
		t.Error("expected the escaping hard link to be skipped, but it was created")
	}
}

func TestExtractTar_AllowsHardLinkWithinDestDir(t *testing.T) {
	destDir := t.TempDir()
	data := buildTar(t, []*tar.Header{
		{Name: "real.txt", Typeflag: tar.TypeReg, Mode: 0644},
		{Name: "link.txt", Typeflag: tar.TypeLink, Linkname: "real.txt"},
	}, map[string]string{"real.txt": "content"})

	if err := extractTar(bytes.NewReader(data), destDir); err != nil {
		t.Fatalf("extractTar returned an error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(destDir, "link.txt"))
	if err != nil {
		t.Fatalf("expected the in-bounds hard link to be created: %v", err)
	}
	if string(content) != "content" {
		t.Errorf("content = %q, want %q", content, "content")
	}
}

func TestParseFromDirective(t *testing.T) {
	tests := map[string]struct {
		dockerfile string
		wantRef    string
		wantErr    bool
	}{
		"simple FROM": {
			dockerfile: "FROM alpine:3.19\nRUN echo hi\n",
			wantRef:    "alpine:3.19",
		},
		"FROM with AS build-stage name": {
			dockerfile: "FROM golang:1.25 AS builder\nCOPY . .\n",
			wantRef:    "golang:1.25",
		},
		"FROM scratch returns empty ref and no error": {
			dockerfile: "FROM scratch\n",
			wantRef:    "",
		},
		"lowercase from is matched case-insensitively": {
			dockerfile: "from ubuntu:22.04\n",
			wantRef:    "ubuntu:22.04",
		},
		"no FROM instruction is an error": {
			dockerfile: "RUN echo hi\n",
			wantErr:    true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Dockerfile")
			if err := os.WriteFile(path, []byte(tc.dockerfile), 0644); err != nil {
				t.Fatal(err)
			}

			ref, err := ParseFromDirective(path)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref != tc.wantRef {
				t.Errorf("ref = %q, want %q", ref, tc.wantRef)
			}
		})
	}
}

func TestParseFromDirective_MissingFileReturnsError(t *testing.T) {
	_, err := ParseFromDirective(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Error("expected an error for a missing Dockerfile")
	}
}

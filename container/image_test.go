package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
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

func writeDockerContext(t *testing.T, home, name, host string) {
	t.Helper()
	sum := sha256.Sum256([]byte(name))
	dir := filepath.Join(home, ".docker", "contexts", "meta", hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"Name":"` + name + `","Endpoints":{"docker":{"Host":"` + host + `"}}}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeDockerConfig(t *testing.T, home, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Docker Desktop on a Mac listens on ~/.docker/run/docker.sock, not /var/run/docker.sock, and
// the docker command finds it through the active context. Without that, the daemon was never
// reached and the image was pulled from a registry instead.
func TestDockerContextHost(t *testing.T) {
	const sock = "unix:///Users/me/.docker/run/docker.sock"

	t.Run("the current context of config.json", func(t *testing.T) {
		home := t.TempDir()
		writeDockerConfig(t, home, `{"currentContext":"desktop-linux"}`)
		writeDockerContext(t, home, "desktop-linux", sock)
		if got := dockerContextHost(home, ""); got != sock {
			t.Errorf("dockerContextHost = %q, want %q", got, sock)
		}
	})

	t.Run("DOCKER_CONTEXT wins over config.json", func(t *testing.T) {
		home := t.TempDir()
		writeDockerConfig(t, home, `{"currentContext":"desktop-linux"}`)
		writeDockerContext(t, home, "desktop-linux", sock)
		writeDockerContext(t, home, "colima", "unix:///Users/me/.colima/default/docker.sock")
		if got := dockerContextHost(home, "colima"); got != "unix:///Users/me/.colima/default/docker.sock" {
			t.Errorf("dockerContextHost = %q, want the colima socket", got)
		}
	})

	t.Run("the default context, no config, or an unknown context leave it to the default socket", func(t *testing.T) {
		home := t.TempDir()
		if got := dockerContextHost(home, ""); got != "" {
			t.Errorf("no config: dockerContextHost = %q, want none", got)
		}
		writeDockerConfig(t, home, `{"currentContext":"default"}`)
		if got := dockerContextHost(home, ""); got != "" {
			t.Errorf("default context: dockerContextHost = %q, want none", got)
		}
		writeDockerConfig(t, home, `{"currentContext":"gone"}`)
		if got := dockerContextHost(home, ""); got != "" {
			t.Errorf("unknown context: dockerContextHost = %q, want none", got)
		}
		writeDockerConfig(t, home, `not json`)
		if got := dockerContextHost(home, ""); got != "" {
			t.Errorf("unreadable config: dockerContextHost = %q, want none", got)
		}
	})
}

func imageFor(t *testing.T, os, arch, variant string) v1.Image {
	t.Helper()
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: os, Architecture: arch, Variant: variant})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestPlatformOfAndMatches(t *testing.T) {
	arm := imageFor(t, "linux", "arm64", "v8")
	amd := imageFor(t, "linux", "amd64", "")

	if got := platformOf(arm); got != "linux/arm64/v8" {
		t.Errorf("platformOf(arm) = %q", got)
	}
	if got := platformOf(amd); got != "linux/amd64" {
		t.Errorf("platformOf(amd) = %q", got)
	}
	if got := platformOf(empty.Image); got != "" {
		t.Errorf("platformOf(an image that does not say) = %q, want empty", got)
	}

	tests := []struct {
		img  v1.Image
		want string
		ok   bool
	}{
		{arm, "linux/arm64", true}, // no variant asked for: any variant
		{arm, "linux/arm64/v8", true},
		{arm, "linux/arm64/v7", false},
		{arm, "linux/amd64", false},
		{amd, "linux/amd64", true},
		{amd, "linux/arm64", false},
	}
	for _, tt := range tests {
		want, err := v1.ParsePlatform(tt.want)
		if err != nil {
			t.Fatal(err)
		}
		if got := platformMatches(tt.img, want); got != tt.ok {
			t.Errorf("platformMatches(%s, %s) = %v, want %v", platformOf(tt.img), tt.want, got, tt.ok)
		}
	}
}

func TestExtractImageWithRejectsABadPlatform(t *testing.T) {
	// Each is refused before any image is looked for.
	for _, bad := range []string{"arm64", "linux/", "/arm64", "not a platform", "linux/arm64/v8/x"} {
		_, _, _, err := ExtractImageWith(context.Background(), "nginx:latest", Options{Platform: bad})
		if err == nil || !strings.Contains(err.Error(), "invalid platform") {
			t.Errorf("Platform %q: err = %v, want an invalid platform error", bad, err)
		}
	}
	for _, good := range []string{"linux/arm64", "linux/arm64/v8", "windows/amd64"} {
		if _, err := parsePlatform(good); err != nil {
			t.Errorf("parsePlatform(%q): %v", good, err)
		}
	}
}

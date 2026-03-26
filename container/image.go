package container

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ExtractImage loads a container image and extracts its merged filesystem to a temp directory.
// It tries the local Docker daemon first, then falls back to the remote registry.
// The caller must call the returned cleanup function when done.
func ExtractImage(ctx context.Context, imageRef string, verbose bool) (string, func(), error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", nil, fmt.Errorf("invalid image reference %q: %w", imageRef, err)
	}

	img, err := loadImage(ctx, ref, verbose)
	if err != nil {
		return "", nil, fmt.Errorf("load image %q: %w", imageRef, err)
	}

	dir, err := os.MkdirTemp("", "heretix-rootfs-")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	if verbose {
		fmt.Fprintf(os.Stderr, "[container] extracting layers to %s...\n", dir)
	}

	if err := extractLayers(img, dir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("extract layers: %w", err)
	}

	return dir, cleanup, nil
}

// loadImage tries the local Docker daemon first, then falls back to the remote registry.
func loadImage(ctx context.Context, ref name.Reference, verbose bool) (v1.Image, error) {
	img, err := daemon.Image(ref, daemon.WithContext(ctx))
	if err == nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[container] loaded %s from local Docker daemon\n", ref)
		}
		return img, nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[container] daemon unavailable (%v), pulling from registry...\n", err)
	}

	img, err = remote.Image(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return nil, fmt.Errorf("not found locally or in registry: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[container] pulled %s from registry\n", ref)
	}
	return img, nil
}

// extractLayers flattens all image layers into destDir.
// mutate.Extract handles layer ordering and whiteout file processing automatically.
func extractLayers(img v1.Image, destDir string) error {
	rc := mutate.Extract(img)
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Sanitize path to prevent traversal
		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") {
			continue
		}
		dest := filepath.Join(destDir, cleanName)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0755); err != nil {
				return err
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
			if err != nil {
				// Non-fatal: skip files we can't create (e.g. permission issues)
				continue
			}
			const maxFileSize = 500 * 1024 * 1024 // 500 MB per file
			if _, err := io.Copy(f, io.LimitReader(tr, maxFileSize)); err != nil {
				f.Close()
				return err
			}
			f.Close()

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				return err
			}
			os.Remove(dest)
			// Non-fatal: symlinks may fail (e.g. dangling or cross-device)
			_ = os.Symlink(hdr.Linkname, dest)

		case tar.TypeLink:
			linkTarget := filepath.Join(destDir, filepath.Clean(hdr.Linkname))
			// Reject hard link targets that escape the rootfs
			if !strings.HasPrefix(linkTarget+string(os.PathSeparator), destDir+string(os.PathSeparator)) {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				return err
			}
			os.Remove(dest)
			// Non-fatal: fall back to nothing if hard link fails
			_ = os.Link(linkTarget, dest)
		}
	}
	return nil
}

// ParseFromDirective parses a Dockerfile and returns the base image reference
// from the first FROM instruction. Returns ("", nil) if the base is "scratch".
func ParseFromDirective(dockerfilePath string) (string, error) {
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return "", fmt.Errorf("read dockerfile: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "FROM ") {
			// FROM <image> [AS <name>]
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ref := parts[1]
				if strings.ToLower(ref) == "scratch" {
					return "", nil
				}
				return ref, nil
			}
		}
	}
	return "", fmt.Errorf("no FROM instruction found in %s", dockerfilePath)
}

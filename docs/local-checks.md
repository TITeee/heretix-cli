# Local security checks

> **Beta**: Local security checks are currently in beta. Detection rules may produce false positives, and coverage will expand in future releases.

The `scan` and `detect` commands run five local checks that require no network access.

**Automatic skip paths** — irrelevant directories are skipped to avoid false positives and unnecessary I/O:

- **Host scan**: `/proc`, `/sys`, `/dev`, `/boot`, `/run`, `/tmp`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`, `/usr/src`, `/usr/local/lib/python*`, `/usr/lib/python*`
- **Docker image scan** (`--image`), a separate list: `/proc`, `/sys`, `/dev`, `/boot`, `/run`, `/tmp`, `/usr/share`, `/usr/lib/locale`, `/usr/lib/python*`, `/usr/lib/node_modules`, `/var/cache`, `/var/lib/apt`, `/var/lib/dpkg`. Unlike a host scan, `/usr/src` and `/usr/local/lib/python*` are scanned

## GlassWorm Detection

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

## Dependency Confusion Detection

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

## Malicious Install Scripts Detection (Shai-Hulud, RedC2)

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

## CI/CD Pipeline Poisoning Detection

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

## Hardcoded Secrets Detection

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

## Lock File Integrity Detection

Validates lockfiles for weak or missing integrity hashes, and detects drift between manifest files and their lockfiles — both of which can indicate tampering or a stale dependency snapshot.

| Check | File | Severity |
|---|---|---|
| Direct dependency uses SHA-1 integrity (cryptographically broken — collision attacks possible) | `package-lock.json` | HIGH |
| Dependency declared in `package.json` but absent from `package-lock.json` | `package-lock.json` | MEDIUM |
| Module required in `go.mod` has no entry in `go.sum` (never fetched/verified) | `go.sum` | MEDIUM |
| Package in `Pipfile.lock` has no hash entries (integrity cannot be verified at install) | `Pipfile.lock` | MEDIUM |


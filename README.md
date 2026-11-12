# heretix-cli

heretix-cli is the scanner of **[heretix](https://titeee.github.io/heretix-web/)**, a self-hosted suite that tracks CVEs across servers, containers and network appliances (firewalls, VPNs) in one inventory (Apache-2.0).

[日本語版 README](README.ja.md)

## What it does

Run it on a server, or point it at a container image or a directory. It lists every installed package and asks [heretix-api](https://github.com/TITeee/heretix-api) which of them are vulnerable:

```
$ heretix-cli scan --image myapp:latest
   ECOSYSTEM   PACKAGE               VERSION    SOURCE               DB    VULN ID               CVSS   EPSS  SUMMARY
!  AlmaLinux   curl                  7.88.1     rpm                  nvd   CVE-2024-1234          9.8  0.950  Remote code exec
   PyPI        requests              2.31.0     /srv/myapp/requir... osv   GHSA-xxxx-yyyy         6.1  0.045  SSRF via proxy
 B Debian      binutils(2 pkgs)      2.44-3     dpkg                 osv   CVE-2024-9999          5.5  0.002  Heap overflow in BFD
...
Summary: 14 packages with 21 findings (1 malware, 1 KEV)
```

![How heretix-cli fits in: it reads the packages installed on servers, container images and directories, checks them against heretix-api, uploads the SBOM to heretix-management, submits it to GitHub for Dependabot, and reports the findings in the terminal or CI](docs/overview.svg)

- **heretix-cli** (this repository) finds the packages and writes them as a CycloneDX SBOM, or checks them right away.
- **[heretix-api](https://github.com/TITeee/heretix-api)** answers whether each package version is vulnerable.
- **[heretix-management](https://github.com/TITeee/heretix-management)** imports the SBOMs and keeps the findings over time.

`collect` and `detect` need no API and run offline, so heretix-cli also works on its own as an SBOM generator and supply-chain checker.

## Features

- **Hosts, images and directories**, OS packages (RPM, DPKG, APK), language packages (PyPI, npm, Go, Composer, Maven, Gradle, Java archives) and Windows Server (beta); no Docker needed for an image
- **CycloneDX 1.6 SBOM** with PURLs, licenses, hashes and the dependency graph, for OS packages too
- **What the host runs**: which packages running processes have loaded, by which services, and which services need a restart after an upgrade
- **Less noise**: a vulnerability in one source package is reported once, and kernel headers and build tools are tagged as non-runtime
- **Offline supply-chain checks**: invisible characters (GlassWorm), dependency confusion, malicious install scripts, CI/CD poisoning, lockfile integrity
- **Made for CI**: exit code 1 on findings, JSON output, and Dependabot alerts through GitHub's dependency submission

Which files each ecosystem is read from: [docs/package-detection.md](docs/package-detection.md).

## Installation

Download the binary for your platform from the [latest release](https://github.com/TITeee/heretix-cli/releases/latest). On Linux x86-64:

```bash
curl -fsSLO https://github.com/TITeee/heretix-cli/releases/latest/download/heretix-cli_linux_amd64.tar.gz
tar xzf heretix-cli_linux_amd64.tar.gz heretix-cli
sudo install -m 0755 heretix-cli /usr/local/bin/
```

Linux ARM64 and Windows, checking the download and its signature, and building from source: [docs/installation.md](docs/installation.md).

## Quick start

`scan` and `check` need a running [heretix-api](https://github.com/TITeee/heretix-api#quick-start) and its API key. They connect to `http://localhost:5000` unless you pass `--api-url`.

```bash
export HERETIX_API_KEY=<your key>

sudo -E heretix-cli scan                   # this host
heretix-cli scan --image nginx:latest      # a container image
heretix-cli detect --scan-path /srv/myapp  # supply-chain checks only, offline
```

Scanning the whole host runs as root, because it also reads which packages the running processes have loaded (`--runtime=off` skips that and needs no root). Images and directories need no root. `sudo -E` keeps `HERETIX_API_KEY`.

To keep the findings over time, send the SBOM to heretix-management, with an access token it issues under **Settings → Access Tokens**:

```bash
export HERETIX_MANAGEMENT_URL=https://heretix.example.com
export HERETIX_MANAGEMENT_TOKEN=<access token>
heretix-cli collect --image myapp:1.0 --name myapp --output sbom.json
heretix-cli upload sbom.json
```

## Commands

| Command | Purpose | Needs heretix-api |
|---|---|---|
| `collect` | Write the packages of a host, image or directory as a CycloneDX SBOM | No |
| `check` | Check an SBOM against heretix-api | Yes |
| `scan` | `collect` + `check` + local checks in one command | Yes |
| `detect` | Local supply-chain checks only | No |
| `upload` | Send an SBOM to heretix-management | No |
| `submit` | Send an SBOM to GitHub for Dependabot | No |

In CI, `check`, `scan` and `detect` exit with `1` when they find something and `2` when the check failed or is incomplete, so a pipeline step fails on its own:

```bash
heretix-cli scan --image myapp:latest --api-url http://heretix-api:5000 --severity 7.0
```

Every flag, the output formats and more CI examples (GitHub Actions): [docs/commands.md](docs/commands.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/installation.md](docs/installation.md) | Downloads for each platform, verifying them, building from source |
| [docs/commands.md](docs/commands.md) | Every command and flag, output formats, exit codes, CI/CD examples |
| [docs/package-detection.md](docs/package-detection.md) | What each collector reads, non-runtime and OS-managed packages |
| [docs/sbom.md](docs/sbom.md) | What the SBOM contains, runtime facts, and which fields each source fills |
| [docs/local-checks.md](docs/local-checks.md) | Local supply-chain checks and their rules |
| [docs/development.md](docs/development.md) | Project structure, adding a collector or a check |

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

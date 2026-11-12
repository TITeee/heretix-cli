# Installation

heretix-cli is a single static binary with no runtime dependencies. Download a release, or build it yourself.

## Download a release

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

To install a specific version, replace `latest/download` with `download/v0.7.0` (the tag).

## Verify the signature

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

## Build from source

Go 1.25 or later:

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o heretix-cli .

# Windows
GOOS=windows GOARCH=amd64 go build -o heretix-cli.exe .
```

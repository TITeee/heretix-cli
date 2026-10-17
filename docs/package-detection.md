# Package detection

How `collect` finds packages in each ecosystem, and how it tags packages that are installed but are not part of what an image runs.

## Supported ecosystems

| Ecosystem | Scan Target | Platform |
|---|---|---|
| RHEL / AlmaLinux / Rocky Linux / Oracle Linux / CentOS (RPM) | Parses `var/lib/rpm` / `usr/lib/sysimage/rpm` directly (BDB, NDB, or SQLite) | Linux only (any OS for `--image` scans) |
| Debian / Ubuntu-based (DPKG) | Parses `var/lib/dpkg/status` directly | Linux only (any OS for `--image` scans) |
| Alpine (APK) | Parses `/lib/apk/db/installed` directly | Linux only (any OS for `--image` scans) |
| PyPI | `site-packages`/`dist-packages` (`*.dist-info/METADATA`) as the primary source, plus `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` / fallback: `pip list`* | Linux / Windows |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` / fallback: `npm list -g`, `pnpm list -g`* | Linux / Windows |
| Go (go modules) | `go.mod`, resolved with `go list -m all` and `go mod graph` when the `go` command is in PATH‡ | Linux / Windows |
| Go (binaries) | Modules statically linked into a compiled binary (e.g. a base image's bundled tools), read from the binary's embedded build info — same data as `go version -m`† | Image scans only |
| Composer (PHP) | `composer.lock` | Linux / Windows |
| Maven (Java) | `pom.xml` / fallback: `mvn dependency:tree` | Linux / Windows |
| Gradle (Java/Kotlin) | `gradle.lockfile` / `build.gradle` / `build.gradle.kts` | Linux / Windows |
| Java artifacts | `*.jar`, `*.war`, `*.ear` — reads `META-INF/maven/*/pom.properties`, recurses into `WEB-INF/lib` and `BOOT-INF/lib` | Linux / Windows |
| Windows Server (beta) | The registry: release, installation type and OS build including the UBR — see [Windows Server](#windows-server-beta)* | Windows only |

\* Only runs for a whole-system scan (`--scan-path` at the filesystem root, the default with no `--image`): skipped for `--image`/`--dockerfile` scans and for any `--scan-path` narrower than the root, since `pip`/`npm`/`pnpm` here always query this process's own host environment regardless of `--scan-path` — never the extracted image or the scanned subdirectory.

† Only runs for `--image`/`--dockerfile` scans, walking every regular file under the extracted rootfs and attempting to parse it as a Go binary. Skipped for host scans, where opening every executable on the live filesystem would be far noisier and slower than auditing one image layer.

‡ Without the `go` command, `go.mod` is parsed directly: you get the modules it declares and whether each is direct, but no transitive dependencies or dependency relationships, so a dependency graph built from the SBOM comes out empty. `collect` warns when it finds a `go.mod` but no `go` command.

Every collector skips directories named `testdata` below the scan path: they hold test fixtures (the Go toolchain never builds them, and the local security checks skip them too), so a manifest there is not a real dependency. A `testdata` directory given as `--scan-path` itself is still scanned.

## Windows Server (beta)

On a Windows Server host, the OS itself is reported as one package, read from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`:

| Field | Value |
|---|---|
| Name | The product as Microsoft's Security Update Guide names it, from `CurrentBuild`: `Windows Server 2016` (14393), `2019` (17763), `2022` (20348) or `2025` (26100). A Server Core installation (`InstallationType` = `Server Core`) is its own product: `Windows Server 2022 (Server Core installation)` |
| Version | The full OS build, including the update build revision (`UBR`) that each monthly cumulative update raises: `10.0.20348.5761` |
| Ecosystem / source | `advisory` / `windows-registry` |
| PURL | `pkg:generic/microsoft/Windows%20Server%202022@10.0.20348.5761` |
| Installed features | The optional features installed, by their language-neutral names (`DNS-Server-Full-Role`, `DHCPServer`, ...), from `Win32_OptionalFeature` (through PowerShell, about a second), as the SBOM property `heretix:windows-features` (comma-separated). Left out when they cannot be read |

heretix-api reports the CVEs whose fixing update has a higher build than this one, so a server one month behind gets that month's CVEs, and a server on the latest update gets none. Installed KBs are not read: cumulative updates replace each other, so the build alone says which fixes are in.

What is left out:

- A client Windows (`InstallationType` = `Client`) and Nano Server report nothing.
- A Windows Server release heretix-api has no data for (2012 R2 and older, the semi-annual channel releases) is left out with a warning, so that a clean report is not read as a checked OS. So is a server whose UBR cannot be read: without it, every CVE since the release would be reported.
- `check` and `scan` report every CVE fixed for the release, including those of server roles the server does not run (DNS Server, DHCP Server, ...): the fix is the same cumulative update, but such a CVE cannot be exploited without the role. heretix-api names the features each such CVE needs, and heretix-management uses the installed features above to set those findings aside as not affected. Only the roles heretix-api can recognise are judged this way: DNS Server, DHCP Server, Routing and Remote Access, AD FS, NPS, Message Queuing, Remote Desktop Gateway, WSUS, IIS, AD CS and Windows Deployment Services. A CVE in Hyper-V, AD DS, Failover Cluster, Print Spooler, SMB, Remote Desktop, WebDAV, iSCSI or the operating system itself always applies (see heretix-api's [data-sources.md](https://github.com/TITeee/heretix-api/blob/main/docs/data-sources.md#microsoft-windows-server) for the full table and the reasons).
- The limits of the matching itself (CVEs fixed before March 2021, hotpatch-track servers, .NET and other Microsoft products) are listed in heretix-api's known issues.

A server many months behind can match thousands of CVEs, more than heretix-api returns for one package. heretix-api then returns the most severe ones, and `check` and `scan` print a warning naming the package and how many it matched.

## Non-runtime packages

A container image usually carries packages that are installed but never run: **kernel headers** (the host kernel is what executes, not `linux-libc-dev`) and **build toolchain** left behind by a build stage (compilers, linkers, `-dev`/`-devel` header packages). On `wordpress:php8.5-fpm` these account for 454 of 721 findings, `linux-libc-dev` alone contributing 388.

`collect` classifies them from the **source package** each binary package was built from — `Source:` in the dpkg status file, `SourceRpm` in the RPM database, `o:` in the APK database. The source package is used rather than the package name because one upstream project is split into many binary packages whose names give nothing away: `libbinutils`, `libctf0`, `libsframe1` and `libgprofng0` are all `Section: libs`, and only their shared `binutils` source identifies them as build tooling.

Two things follow from that same source-package information:

- **Findings are counted per source package, not per binary package.** One `binutils` CVE affects all eight of its binary packages; it is now one row naming the source package, `binutils(8 pkgs)`, rather than eight rows. The source package is shown rather than picking one binary package's name, because most multi-binary sources have no binary package sharing the source's own name at all (`glibc` produces `libc6`/`libc6-dev`/..., never a package literally named `glibc`). If the group's binary packages do not all share one version, the VERSION column shows `multiple` rather than picking one of them.
- **Non-runtime findings are tagged, not hidden.** They are marked `K` (kernel) or `B` (build) in the report and summarised under `Non-runtime:`, so nothing silently disappears. Pass `--runtime-only` to leave them out. A source package can produce both runtime and non-runtime binary packages (`glibc` ships both `libc6` and `libc6-dev`); when the same CVE affects both, the row is never tagged non-runtime, so `--runtime-only` cannot silently drop a finding that does affect something that runs.

Measured on `wordpress:php8.5-fpm`: 1485 findings before, **721** after collapsing per source package, **267** with `--runtime-only`.

The SBOM is unaffected by all of this: every package stays a component (CycloneDX `scope: excluded` plus a `heretix:category` property), because dropping components would break the coverage a complete SBOM is supposed to provide.

`--runtime-only` also changes `check`/`scan`'s CI/CD exit code (1 when findings remain), not just the table -- a build does not fail over a kernel-header or build-toolchain CVE that `--runtime-only` was asked to ignore.

### On a host, only kernel headers count as non-runtime

The classification above is for container images, where the host's kernel is what runs and a compiler is a leftover. On a host the reverse holds: the installed kernel image and modules (`linux-image-*`, `kernel`, `kernel-core`, ...) are what runs, and a toolchain is there because someone installed it, on a build server, CI runner or developer machine, where its vulnerabilities matter. So for a scan that is not of an image (`collect`, `scan` and `check` without `--image`), only kernel **header** packages (`linux-libc-dev`, `linux-headers-*`, `kernel-headers`, `kernel-devel*`) are tagged non-runtime; the kernel itself, compilers and `-dev`/`-devel` packages are reported like any other package.

The two mistakes cost different amounts: a package wrongly tagged non-runtime gets `scope: excluded`, which heretix-management never scans, so its findings disappear without a trace, whereas one wrongly kept as runtime only adds findings that can be seen and ignored.

> Versions up to 0.3.1 applied the image rules to hosts too, so a host's kernel and build packages came out as `scope: excluded` and heretix-management never scanned them. Upload a new SBOM from 0.3.2 or later to bring them back; the next scan then reports their findings.

## OS-managed language packages

A distro ships many language libraries as its own packages: `python3-urllib3` installs urllib3's `site-packages` directory, the `nodejs` rpm bundles npm and its dependencies under `/usr/lib/node_modules`, `maven` rpms put jars in `/usr/share/java`, and `delve` installs a Go binary at `/usr/bin/dlv`. The PyPI, npm, Maven and Go-binary collectors find these files as well, and would report the library a second time at its upstream version (`urllib3 1.26.5` next to `python3-urllib3 1.26.5-8.el9_8`). That upstream version does not reflect the fixes the distro backports into its own release, so matching it returns findings the distro has already fixed or rates as not affected, or duplicates of what the OS package's own advisory reports.

`collect` reads the file lists the package databases keep (the RPM database, `/var/lib/dpkg/info/*.list`, the APK database). A language package whose evidence file (`dist-info/METADATA`, the `.jar`, the Go binary) one of them owns is tagged `os-managed` and set to `scope: excluded`. Ownership is recorded fact, not a guess from the path: a package that pip, npm or an image's own build put next to the distro's copy is owned by no package and is left alone.

- **Not checked, not tagged.** Unlike non-runtime packages, OS-managed packages are never sent to the vulnerability API: their findings belong to the OS package, which is checked as usual. They stay in the SBOM as components with `heretix:category: os-managed`.
- **Another copy wins.** If the same name and version is also found somewhere nothing owns it (a `requirements.txt` pin, a venv, a binary the image's build copied in), the merged package is not OS-managed and is checked. Go's `stdlib` is recorded per binary for this reason: a stdlib version stays OS-managed only if every binary built with it is.
- **Windows hosts:** an image extracted onto NTFS loses dpkg's architecture-qualified lists (`libc6:amd64.list`, since `:` can't appear in a file name). Language libraries are nearly always `Architecture: all` packages, whose lists are unaffected.

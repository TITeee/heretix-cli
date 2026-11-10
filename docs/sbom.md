# SBOM output

`collect` writes a CycloneDX 1.6 SBOM by default (`--format cyclonedx`). `check`, `scan`, `submit` and heretix-management read it back.

## What the SBOM contains

- **PURL with `?distro=` qualifier** for OS packages (apk/rpm/deb); RPM PURLs also carry **`arch=`** and, when non-zero, **`epoch=`** (the component `version` keeps the epoch, as rpm displays it):
  ```
  pkg:apk/alpine/curl@7.79.1-r0?distro=alpine-3.18
  pkg:rpm/almalinux/curl@7.76.1-26.el9?arch=x86_64&distro=almalinux-9
  pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rockylinux-9&epoch=1
  ```
  This is the form the PURL spec defines: per-arch vendor advisory data (Rocky/Oracle Linux, at least) can only be matched against a package's exact arch, and a consumer reading only the version would treat an epoch placed inside it as epoch 0.
- **`bom-ref`** on every component, matching its PURL for correct dependency resolution
- **`hashes`** per component from lockfile integrity fields (SHA-512 for npm/pnpm, SHA-256 for PyPI), archive digests (SHA-256 for JAR/WAR/EAR) and, for deb packages, the SHA-256 of the `.deb` file from apt's package lists (`/var/lib/apt/lists`) when they still offer the installed version, architecture and all. The lists hold only what the repositories offer now, so a deb gets no hash (and no supplier, below) when the lists are empty — usual on cloud images and in containers until `apt update` — or when the installed version has since been replaced by an update: on a Debian 13 host behind on updates, 237 of 337 packages got one after `apt update`, and the rest were older versions the archive no longer offers. `collect --verbose` says how many matched. A hash of another version's `.deb` would describe a file that is not installed, so none is written. RPM packages get none: the RPM database keeps digests of the header and payload, not of the `.rpm` file, and CycloneDX cannot say which a hash describes, so a reader would compare it with the file and find a mismatch
- **`supplier`** per component where the package manager records who publishes the package: rpm's `Vendor` tag ("Red Hat, Inc."), the `Origin` of the apt repository a deb came from ("Debian", "Ubuntu", "Docker"), "Microsoft Corporation" for Windows. Otherwise it is left out rather than guessed from the distribution, since a third-party package installed on a distribution is not the distribution's
- **`licenses`** per component from package databases, lockfiles and installed packages (RPM, DPKG, APK, Composer, npm node_modules, PyPI site-packages, Go/Gradle module caches, Maven/JAR POMs — see the `license` column below)
- **`properties[heretix:direct]`** marking direct vs. indirect dependencies, mirrored as standard **`bom.dependencies`** edges from `metadata.component` to each direct dependency (omitted when no collector determined directness). Named under heretix's own namespace, not `cdx:` — CycloneDX reserves that namespace for its own official properties ([cyclonedx-property-taxonomy](https://github.com/CycloneDX/cyclonedx-property-taxonomy)). **Breaking change (0.3.0):** heretix-cli 0.2.x and earlier wrote this as `cdx:direct`, and no root edges. This version no longer reads `cdx:direct` back, so for an SBOM written by those versions the direct/indirect distinction is lost and every package is unclassified (`submit` then sends them all as indirect). Re-run `collect` to regenerate it.
- **`scope: excluded`** marking dev/test-only packages that don't ship in a production build (see the `scope` column below), OS packages classified as non-runtime (see [Non-runtime packages](package-detection.md#non-runtime-packages)), and language packages an OS package installed (see [OS-managed language packages](package-detection.md#os-managed-language-packages))
- **`properties[heretix:source-package]`** naming the source package an OS binary package was built from, and **`properties[heretix:category]`** (`kernel` / `build` / `os-managed`) on non-runtime and OS-managed packages
- **`properties[heretix:in-use]`**, **`properties[heretix:used-by]`** and **`properties[heretix:needs-restart]`** on the OS packages of a host scan, from `/proc`: whether a running process had the package loaded, which services those were, and whether one of them runs a file the package has since replaced. See [Runtime facts](#runtime-facts)
- **`bom.dependencies`** section with full dependency graph (npm package-lock.json, pnpm-lock.yaml, uv.lock, poetry.lock, composer.lock, `go list`, PyPI site-packages, and the OS package databases of dpkg, rpm and apk). A package from a source that records no dependency graph (`requirements.txt`, `pom.xml`, an OS package list converted by a `contrib/` tool, ...) gets no entry, since an empty one reads as "depends on nothing"; it is listed instead in a **`compositions`** entry with `aggregate: unknown`. 0.5.3 and earlier wrote empty entries for them
- **`metadata.component`** with OCI PURL and image digest for container scans
- An **`operating-system` component** (os-release `ID` / `VERSION_ID`, pretty name as description) when an OS was detected
- A **`serialNumber`** (`urn:uuid:`, new on every run) and **`version: 1`**. Each run describes the system as it is then, so it is a new SBOM, not a revision of an earlier one; SBOMs of the same host are tied together by `metadata.component`
- **`metadata.tools.components`** naming the program that wrote the SBOM and its version (`heretix-cli` and its release, `dev (<commit>)` for a local build, `dev (<commit>, modified)` when it was built with uncommitted changes; `rpmqa2sbom` / `winserver2sbom` and their commit for the contrib tools). This is the CycloneDX 1.5+ form; 0.5.3 and earlier wrote the deprecated `metadata.tools` array
- **`metadata.lifecycles`**: the stage of the software's life the data comes from. `operations` for a filesystem root (a running system; the lockfiles found on it belong to deployed applications), `pre-build` for any other directory (taken for a project checkout), `post-build` for an image. `--lifecycle` overrides it, e.g. `--lifecycle operations` for a deployed application directory such as `/opt/app`. The contrib tools write `operations`

## Coverage by lockfile

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
| `go.mod` (parsed, no `go` binary) | △ declared only | ✓ | — | — | △ ¹¹ | — |
| `go.mod` via `go list` (`go` binary available) | ✓ incl. transitive | ✓ ² | ✓ ² | — | △ ¹¹ | — |
| Go binaries (image scans) | ✓ incl. transitive + `stdlib` | — | — | — ¹⁸ | — | △ ¹⁷ |
| PyPI `site-packages` (`*.dist-info`) | ✓ | — | ✓ ¹⁹ | — | ✓ | △ ¹⁷ |
| `composer.lock` | ✓ | △ ³ | ✓ | — | ✓ | ✓ ¹⁴ |
| `pom.xml` (mvn command) | ✓ incl. transitive | ✓ | — | — | △ ⁶ | ✓ ¹⁵ |
| `pom.xml` (direct parse) | △ declared only | △ | — | — | △ ⁶ | ✓ ¹⁵ |
| `gradle.lockfile` | ✓ incl. transitive | — ⁷ | — | — | △ ¹² | ✓ ¹⁴ |
| `build.gradle(.kts)` (direct parse) | △ declared only | △ | — | — | △ ¹² | ✓ ¹⁵ |
| `*.jar` / `*.war` / `*.ear` | ✓ ⁸ | — ⁹ | — | ✓ SHA-256 | △ ¹⁰ | — |
| RPM | ✓ | ✓ ²⁰ | ✓ ²⁰ | — | ✓ | ✓ ¹⁶ |
| DPKG | ✓ | ✓ ²⁰ | ✓ ²⁰ | — | △ ¹³ | ✓ ¹⁶ |
| APK | ✓ | ✓ ²⁰ | ✓ ²⁰ | — | ✓ | ✓ ¹⁶ |

¹ `direct` for poetry.lock requires reading `pyproject.toml` — not implemented.  
² When the `go` binary is available, `go list -m -json all` is preferred over parsing `go.mod`, giving transitive dependencies; `direct` and `deps` come from `go mod graph`. Both are filtered to the modules `go.mod` declares, since the full module graph also lists modules needed only by another dependency's own tests.  
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
¹³ `license` for DPKG is read from `/usr/share/doc/{package}/copyright` (the DEP-5 machine-readable format's `License:` field) — present for most packages, but not guaranteed since some upstreams ship free-form copyright text instead. The fields are joined with `and`: DEP-5 gives each group of files its own license, so the package is under all of them (0.5.3 and earlier joined them with `OR`, as if they were a choice).  
¹⁴ `scope: excluded` marks a package resolved only via devDependencies / `packages-dev` / `develop` / test-only Gradle configurations — present in the lockfile's dependency graph but not shipped in a production build (e.g. `pnpm prune --prod`). Where marked `—`, dev/test-only packages are reported the same as production ones with no distinguishing tag. When one scan finds the same package (name and version) in several places — two apps' lockfiles, or a lockfile and `node_modules` — it is `excluded` only if no lockfile places it in production; a source that can't tell dev from production (pnpm's virtual store, `node_modules`, `site-packages`) doesn't count either way.  
¹⁵ Maven and Gradle's build-file parsing paths exclude `scope=test` (Maven) / test-only Gradle configurations outright rather than tagging them, so no dev-only package reaches the output at all — filtering instead of tagging, but the same practical result.  
¹⁶ `scope: excluded` for OS packages marks kernel headers and build toolchain, derived from the source package each binary package was built from — see [Non-runtime packages](package-detection.md#non-runtime-packages).  
¹⁷ `scope: excluded` is set only for a package an OS package installed (`heretix:category: os-managed`) — see [OS-managed language packages](package-detection.md#os-managed-language-packages). This applies to every language collector, not just these rows.  
¹⁸ CycloneDX has no algorithm for Go's `go.sum`-style hash (`h1:...`), so it is not written to `components[].hashes`.  
¹⁹ Resolved from each package's `Requires-Dist` headers against the other packages installed in the same `site-packages` directory; a requirement not installed there (an extra, a platform-specific dependency) is omitted.  
²⁰ Resolved from what the package database declares — dpkg `Depends` and `Pre-Depends` against package names and `Provides`, rpm `Requires` against `Provides` and the files packages own, apk `D:` against `p:` and owned files — to the packages installed on the same system. Version constraints are not checked, since the package manager checked them when it installed the packages; a name nothing installed provides is dropped; of dpkg alternatives (`a | b`) the first installed one is taken. `Recommends` and `Suggests` are not dependencies and are not read. `direct` marks the packages no other installed package depends on, so a package that was only recommended (`ca-certificates` next to `curl`) is direct too. The package manager's own record of what was installed by hand (apt's `extended_states`, dnf's history) is not read: it is missing from images and counts a base install as manual. An SBOM built by a `contrib/` converter from a package list has neither, and states the dependencies as unknown.

`deps` PURLs, `integrity` hashes, and `license` information are carried through to the CycloneDX `bom.dependencies`, `components[].hashes`, and `components[].licenses` fields respectively. A `license` string that is a real SPDX license ID or expression (e.g. npm's and Composer's, which are already SPDX-shaped) is written to `license.id`/`license.expression`; Debian's DEP-5 short names (`GPL-2+`, `Expat`, `BSD-3-clause`) and the license names Fedora used before SPDX (`GPLv2+`, `ASL 2.0`, as on RHEL 9) are converted to SPDX IDs first, operators included (`GPLv2+ and MIT` becomes `GPL-2.0-or-later AND MIT`), but only when every license in the string has a fixed meaning: an ambiguous name (Fedora's `LGPLv2`, used for both 2.0 and 2.1; `BSD`), an exception (`with OpenSSL exception`) or any unknown name leaves the whole string as it was. Anything not converted goes to `license.name`, since only a real SPDX id/expression may occupy those two fields per the CycloneDX spec.

## Runtime facts

On a Linux host scanned at its root, `collect` (and `scan`) read `/proc/<pid>/maps` and `/proc/<pid>/exe` of every process and match the files against what the OS packages own. Three properties come out of it, on dpkg, rpm and apk packages:

| Property | Values | Meaning |
|---|---|---|
| `heretix:in-use` | `true` / `false` / absent | A running process had one of the package's executables or shared libraries loaded. `false` means the package has such files and none was loaded. Absent means not determined: a package with no executable or library of its own (data, configuration, a library for an interpreter such as `python3-six`), an image or directory scan, or `--runtime=off` |
| `heretix:used-by` | `ssh.service,nginx.service,bash` | The systemd units of the processes that had the package loaded (from `/proc/<pid>/cgroup`); a process outside a unit is named by its command. Sorted, comma-separated. Only with `in-use: true` |
| `heretix:needs-restart` | `true` / absent | A process still has a file of the package loaded that was replaced on disk after it opened it (the kernel marks the mapping `(deleted)`): the package was upgraded, and the process runs the old code until it is restarted. The package database already shows the new version, so a vulnerability check reports it fixed; this property says the fix is not yet in effect |

The running kernel's package (dpkg `linux-image-<uname -r>`, rpm `kernel-core`) is `in-use: true` and any other installed kernel `false`; Alpine's kernel package is not matched. A kernel that was upgraded without a reboot is not marked `needs-restart`.

What the facts describe is the moment `collect` ran. A program that runs now and then (a cron job, a one-off command) is not seen, so `in-use: false` means "nothing was running it then", not "never used". Reading `/proc/<pid>/maps` of every process needs root; `collect` stops with an error without it rather than write facts for the processes it happened to see. `--runtime=off` turns the reading off, and the properties are then absent.

heretix-management shows the facts on the asset's packages and offers them as an alert filter. They are facts about the system, not a verdict: whether a vulnerability in a package nothing runs matters is still the operator's call.

## SBOM author

`collect --author "Example Corp"` records the organization responsible for the SBOM as `metadata.authors`. The author is whoever ran the scan, not the tool, so heretix-cli writes none unless told.

## Signing an SBOM

heretix-cli does not sign SBOMs: a signature is only worth something when the key belongs to the SBOM's author and is managed by them. To let a recipient check who made an SBOM and that it has not been changed since, sign it next to the file, for example with [cosign](https://github.com/sigstore/cosign), which heretix-cli's own releases are signed with:

```bash
cosign generate-key-pair                                                    # once; keep cosign.key private, hand out cosign.pub
cosign sign-blob --key cosign.key --output-signature sbom.json.sig sbom.json
cosign verify-blob --key cosign.pub --signature sbom.json.sig sbom.json     # the recipient: prints "Verified OK"
```

Send `sbom.json.sig` with `sbom.json`. heretix-management does not verify signatures.

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
- **`hashes`** per component from lockfile integrity fields (SHA-512 for npm/pnpm, SHA-256 for PyPI) and archive digests (SHA-256 for JAR/WAR/EAR)
- **`licenses`** per component from package databases, lockfiles and installed packages (RPM, DPKG, APK, Composer, npm node_modules, PyPI site-packages, Go/Gradle module caches, Maven/JAR POMs — see the `license` column below)
- **`properties[heretix:direct]`** marking direct vs. indirect dependencies, mirrored as standard **`bom.dependencies`** edges from `metadata.component` to each direct dependency (omitted when no collector determined directness). Named under heretix's own namespace, not `cdx:` — CycloneDX reserves that namespace for its own official properties ([cyclonedx-property-taxonomy](https://github.com/CycloneDX/cyclonedx-property-taxonomy)). **Breaking change (2026-09):** earlier heretix-cli versions wrote this as `cdx:direct`; re-run `collect` to regenerate an old SBOM — this version no longer reads `cdx:direct` back, so `check`/`scan` against one falls back to the `bom.dependencies` root edges above (fully equivalent for a direct dependency; a lockfile-derived indirect one degrades to unclassified rather than misreported).
- **`scope: excluded`** marking dev/test-only packages that don't ship in a production build (see the `scope` column below), OS packages classified as non-runtime (see [Non-runtime packages](package-detection.md#non-runtime-packages)), and language packages an OS package installed (see [OS-managed language packages](package-detection.md#os-managed-language-packages))
- **`properties[heretix:source-package]`** naming the source package an OS binary package was built from, and **`properties[heretix:category]`** (`kernel` / `build` / `os-managed`) on non-runtime and OS-managed packages
- **`bom.dependencies`** section with full dependency graph (npm package-lock.json, pnpm-lock.yaml, uv.lock, poetry.lock, composer.lock, `go list`, PyPI site-packages)
- **`metadata.component`** with OCI PURL and image digest for container scans
- An **`operating-system` component** (os-release `ID` / `VERSION_ID`, pretty name as description) when an OS was detected

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
| Go binaries (image scans) | ✓ incl. transitive + `stdlib` | — | — | △ ¹⁸ | — | △ ¹⁷ |
| PyPI `site-packages` (`*.dist-info`) | ✓ | — | ✓ ¹⁹ | — | ✓ | △ ¹⁷ |
| `composer.lock` | ✓ | △ ³ | ✓ | — | ✓ | ✓ ¹⁴ |
| `pom.xml` (mvn command) | ✓ incl. transitive | ✓ | — | — | △ ⁶ | ✓ ¹⁵ |
| `pom.xml` (direct parse) | △ declared only | △ | — | — | △ ⁶ | ✓ ¹⁵ |
| `gradle.lockfile` | ✓ incl. transitive | — ⁷ | — | — | △ ¹² | ✓ ¹⁴ |
| `build.gradle(.kts)` (direct parse) | △ declared only | △ | — | — | △ ¹² | ✓ ¹⁵ |
| `*.jar` / `*.war` / `*.ear` | ✓ ⁸ | — ⁹ | — | ✓ SHA-256 | △ ¹⁰ | — |
| RPM | ✓ | — | — | — | ✓ | ✓ ¹⁶ |
| DPKG | ✓ | — | — | — | △ ¹³ | ✓ ¹⁶ |
| APK | ✓ | — | — | — | ✓ | ✓ ¹⁶ |

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
¹³ `license` for DPKG is read from `/usr/share/doc/{package}/copyright` (the DEP-5 machine-readable format's `License:` field) — present for most packages, but not guaranteed since some upstreams ship free-form copyright text instead.  
¹⁴ `scope: excluded` marks a package resolved only via devDependencies / `packages-dev` / `develop` / test-only Gradle configurations — present in the lockfile's dependency graph but not shipped in a production build (e.g. `pnpm prune --prod`). Where marked `—`, dev/test-only packages are reported the same as production ones with no distinguishing tag.  
¹⁵ Maven and Gradle's build-file parsing paths exclude `scope=test` (Maven) / test-only Gradle configurations outright rather than tagging them, so no dev-only package reaches the output at all — filtering instead of tagging, but the same practical result.  
¹⁶ `scope: excluded` for OS packages marks kernel headers and build toolchain, derived from the source package each binary package was built from — see [Non-runtime packages](package-detection.md#non-runtime-packages).  
¹⁷ `scope: excluded` is set only for a package an OS package installed (`heretix:category: os-managed`) — see [OS-managed language packages](package-detection.md#os-managed-language-packages). This applies to every language collector, not just these rows.  
¹⁸ Each module's `go.sum`-style hash (`h1:...`) is recorded in the heretix inventory JSON. CycloneDX has no algorithm for that format, so it is not written to `components[].hashes`.  
¹⁹ Resolved from each package's `Requires-Dist` headers against the other packages installed in the same `site-packages` directory; a requirement not installed there (an extra, a platform-specific dependency) is omitted.

`deps` PURLs, `integrity` hashes, and `license` information are carried through to the CycloneDX `bom.dependencies`, `components[].hashes`, and `components[].licenses` fields respectively. A `license` string that is a real SPDX license ID or expression (e.g. npm's and Composer's, which are already SPDX-shaped) is written to `license.id`/`license.expression`; anything else — rpm's own "GPLv2+ and MIT"-style syntax, dpkg copyright free text, and the like — goes to `license.name` instead, since only a real SPDX id/expression may occupy those two fields per the CycloneDX spec.

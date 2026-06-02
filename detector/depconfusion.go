package detector

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DepConfusionDetector scans project configuration and lockfiles for indicators
// of Dependency Confusion attack vectors.
type DepConfusionDetector struct {
	baseDetector
}

func (d *DepConfusionDetector) Name() string { return "dep-confusion" }

// scopeChecker determines whether an npm scope is publicly registered.
// wellKnownPublicScopes is checked first (no network); unknown scopes are
// optionally verified against the npm registry when checkRegistry is true.
type scopeChecker struct {
	checkRegistry bool
	mu            sync.Mutex
	cache         map[string]bool
}

func newScopeChecker(checkRegistry bool) *scopeChecker {
	return &scopeChecker{checkRegistry: checkRegistry, cache: map[string]bool{}}
}

// isPublic returns true when the scope is known or confirmed to be a public
// npm scope. Returns false when the scope is unknown and registry checks are
// disabled, or when the registry returns 404.
func (s *scopeChecker) isPublic(scope string) bool {
	if wellKnownPublicScopes[scope] {
		return true
	}
	if !s.checkRegistry {
		return false
	}
	s.mu.Lock()
	if v, ok := s.cache[scope]; ok {
		s.mu.Unlock()
		return v
	}
	s.mu.Unlock()

	public := queryNpmScope(scope)

	s.mu.Lock()
	s.cache[scope] = public
	s.mu.Unlock()
	return public
}

// queryNpmScope uses the npm search API to check whether any packages are
// published under the given scope (e.g. "@auth").
// The registry does not support GET /@scope directly (returns 405), so we use
// the search endpoint with the scope: qualifier instead.
// Returns false on network errors so that unknown scopes are still flagged.
func queryNpmScope(scope string) bool {
	name := strings.TrimPrefix(scope, "@")
	url := "https://registry.npmjs.org/-/v1/search?text=scope:" + name + "&size=1"

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	var result struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.Total > 0
}

// Detect walks scanPath looking for dependency confusion indicators across
// npm, Python, and Go ecosystems.
func (d *DepConfusionDetector) Detect(scanPath string, verbose bool, progress *atomic.Int64) ([]Finding, error) {
	var findings []Finding
	sc := newScopeChecker(d.checkRegistry)

	err := filepath.WalkDir(scanPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] || d.shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		progress.Add(1)

		name := entry.Name()
		switch name {
		case "package.json":
			findings = append(findings, checkPackageJSON(path, sc)...)
		case ".npmrc":
			// .npmrc is read together with package.json; handled there
		case "package-lock.json":
			findings = append(findings, checkPackageLock(path, sc)...)
		case "yarn.lock":
			findings = append(findings, checkYarnLock(path, sc)...)
		case "pnpm-lock.yaml":
			findings = append(findings, checkPnpmLock(path, sc)...)
		case "requirements.txt":
			findings = append(findings, checkRequirementsTxt(path)...)
		case "pip.conf", "pip.ini":
			findings = append(findings, checkPipConf(path)...)
		case "Pipfile":
			findings = append(findings, checkPipfile(path)...)
		case "pyproject.toml":
			findings = append(findings, checkPyprojectToml(path)...)
		case "go.env":
			findings = append(findings, checkGoEnv(path)...)
		}
		return nil
	})

	return findings, err
}

// ── npm ──────────────────────────────────────────────────────────────────────

// wellKnownPublicScopes lists npm scopes that are always resolved from the
// public registry by design. Dependency confusion only applies to private/internal
// scoped packages, so these scopes are excluded from the .npmrc check.
var wellKnownPublicScopes = map[string]bool{
	// ── Core toolchain ────────────────────────────────────────────────────────
	"@types":             true,
	"@babel":             true,
	"@jest":              true,
	"@testing-library":   true,
	"@vitest":            true,
	"@playwright":        true,
	"@wdio":              true, // WebdriverIO
	"@storybook":         true,
	"@rollup":            true,
	"@vitejs":            true,
	"@vite":              true,
	"@webpack":           true,
	"@swc":               true,
	"@esbuild":           true,
	"@biomejs":           true,
	"@eslint":            true,
	"@eslint-community":  true,
	"@typescript-eslint": true,
	"@oxc-project":       true, // OXC Rust-based JS toolchain
	"@rspack":            true, // Rspack (Rust webpack)
	"@turbo":             true, // Turborepo
	"@nx":                true, // Nx build system
	"@nrwl":              true, // Nrwl / Nx (legacy scope)
	"@changesets":        true, // Changesets monorepo versioning
	"@rushstack":         true, // Microsoft Rush Stack

	// ── Frameworks ────────────────────────────────────────────────────────────
	"@angular":      true,
	"@vue":          true,
	"@react":        true,
	"@next":         true, // Next.js (Vercel)
	"@nuxt":         true, // Nuxt.js
	"@sveltejs":     true, // SvelteKit / Svelte official
	"@solidjs":      true, // SolidJS
	"@astrojs":      true, // Astro integrations
	"@remix-run":    true, // Remix
	"@preact":       true, // Preact
	"@hono":         true, // Hono web framework
	"@lit":          true, // Lit web components
	"@open-wc":      true, // Open Web Components
	"@fastify":      true,
	"@nestjs":       true,
	"@hapi":         true,
	"@koa":          true,
	"@adonisjs":     true, // AdonisJS
	"@poppinss":     true, // AdonisJS utilities

	// ── Mobile / cross-platform ───────────────────────────────────────────────
	"@ionic":                  true, // Ionic Framework
	"@capacitor":              true, // Capacitor
	"@expo":                   true, // Expo (React Native)
	"@react-navigation":       true, // React Navigation
	"@react-native-community": true, // React Native community packages

	// ── UI component libraries ────────────────────────────────────────────────
	"@mui":          true, // Material UI
	"@base-ui":      true, // MUI Base UI
	"@chakra-ui":    true,
	"@radix-ui":     true,
	"@headlessui":   true, // Headless UI (Tailwind Labs)
	"@heroicons":    true, // Heroicons (Tailwind Labs)
	"@tailwindcss":  true,
	"@shadcn":       true, // shadcn/ui
	"@ant-design":   true, // Ant Design
	"@mantine":      true, // Mantine UI
	"@fluentui":     true, // Microsoft Fluent UI
	"@shopify":      true, // Shopify Polaris
	"@carbon":       true, // IBM Carbon Design
	"@patternfly":   true, // Red Hat PatternFly
	"@ark-ui":       true, // Ark UI (headless)
	"@zag-js":       true, // Zag.js state machines for UI
	"@kobalte":      true, // Kobalte UI (Solid)
	"@corvu":        true, // Corvu UI (Solid)
	"@saas-ui":      true, // SaaS UI
	"@dnd-kit":      true, // dnd kit drag-and-drop
	"@floating-ui":  true,
	"@emotion":      true,

	// ── CSS / styling ─────────────────────────────────────────────────────────
	"@unocss":           true, // UnoCSS
	"@vanilla-extract":  true, // Vanilla Extract CSS
	"@pandacss":         true, // Panda CSS
	"@griffel":          true, // Griffel CSS-in-JS (Microsoft)

	// ── Editors ───────────────────────────────────────────────────────────────
	"@codemirror":    true, // CodeMirror 6
	"@lezer":         true, // Lezer parser (CodeMirror 6 dependency)
	"@tiptap":        true, // Tiptap rich text editor
	"@lexical":       true, // Lexical editor (Meta)
	"@monaco-editor": true, // Monaco Editor (VS Code)
	"@uiw":           true, // CodeMirror React wrapper + UIW components

	// ── State management ──────────────────────────────────────────────────────
	"@reduxjs":    true, // Redux Toolkit
	"@xstate":     true, // XState state machines
	"@statelyai":  true, // Stately AI (XState ecosystem)
	"@legendapp":  true, // Legend State
	"@effect":     true, // Effect.ts
	"@vueuse":     true, // VueUse utilities
	"@pinia":      true, // Pinia (Vue store)

	// ── Data fetching / GraphQL ───────────────────────────────────────────────
	"@apollo":         true,
	"@graphql-tools":  true,
	"@urql":           true, // urql GraphQL client
	"@trpc":           true,

	// ── Database / ORM ────────────────────────────────────────────────────────
	"@prisma":     true,
	"@typeorm":    true,
	"@mikro-orm":  true, // MikroORM
	"@typegoose":  true, // Typegoose (Mongoose TypeScript)
	"@mongodb":    true, // MongoDB JS driver & tools
	"@mongodb-js": true, // MongoDB JS utilities
	"@redis":      true, // node-redis v4 sub-packages
	"@upstash":    true, // Upstash Redis / Kafka

	// ── BaaS / cloud services ─────────────────────────────────────────────────
	"@supabase":    true, // Supabase
	"@firebase":    true, // Firebase modular SDK (Google)
	"@aws-sdk":     true, // AWS SDK v3
	"@smithy":      true, // AWS Smithy (AWS SDK v3 internals)
	"@aws-amplify": true, // AWS Amplify
	"@google-cloud": true,
	"@azure":       true,
	"@cloudflare":  true, // Cloudflare Workers SDK
	"@netlify":     true, // Netlify Edge Functions
	"@vercel":      true, // Vercel platform packages

	// ── Auth ──────────────────────────────────────────────────────────────────
	"@auth":              true, // Auth.js
	"@auth0":             true, // Auth0
	"@clerk":             true, // Clerk authentication
	"@ory":               true, // Ory (Kratos / Hydra)
	"@panva":             true, // JOSE / openid-client
	"@simplewebauthn":    true, // SimpleWebAuthn

	// ── Payments / commerce ───────────────────────────────────────────────────
	"@stripe": true, // Stripe JS

	// ── Search / analytics ────────────────────────────────────────────────────
	"@algolia":        true, // Algolia search
	"@sentry":         true,
	"@opentelemetry":  true, // OpenTelemetry (CNCF)
	"@datadog":        true, // Datadog

	// ── Notifications / messaging ─────────────────────────────────────────────
	"@novu":       true, // Novu notification infrastructure
	"@resend":     true, // Resend email API
	"@socket.io":  true, // Socket.io

	// ── API / protocol ────────────────────────────────────────────────────────
	"@grpc":       true, // gRPC JS
	"@bufbuild":   true, // Buf (protobuf)
	"@connectrpc": true, // Connect RPC
	"@hey-api":    true, // Hey API OpenAPI client generator
	"@octokit":    true,

	// ── Map / geospatial ──────────────────────────────────────────────────────
	"@mapbox":      true, // Mapbox GL JS
	"@maplibre":    true, // MapLibre GL JS
	"@turf":        true, // Turf.js geospatial
	"@googlemaps":  true, // Google Maps JS API

	// ── Charts / visualization / 3D ───────────────────────────────────────────
	"@nivo":           true, // Nivo charts
	"@react-three":    true, // React Three Fiber
	"@pmndrs":         true, // Poimandres collective (R3F ecosystem)
	"@observablehq":   true, // Observable Plot
	"@xyflow":         true, // React Flow (node-based diagram editor)
	"@dagrejs":        true, // dagre directed-graph layout
	"@mermaid-js":     true,

	// ── CLI tooling ───────────────────────────────────────────────────────────
	"@clack":    true, // Clack CLI prompts
	"@inquirer": true, // Inquirer.js (rewritten under @inquirer scope)
	"@oclif":    true, // oclif CLI framework

	// ── Misc well-known OSS authors / infrastructure packages ─────────────────
	"@img":              true, // sharp image processing
	"@jridgewell":       true, // source map tooling
	"@humanwhocodes":    true, // ESLint ecosystem
	"@humanfs":          true,
	"@nodelib":          true,
	"@pinojs":           true,
	"@pkgjs":            true, // npm-owned packages
	"@isaacs":           true, // Isaac Schlueter (npm)
	"@sindresorhus":     true, // Sindre Sorhus utilities
	"@lukeed":           true, // Luke Edwards utilities
	"@antfu":            true, // Anthony Fu utilities
	"@nicolo-ribaudo":   true, // Babel team
	"@rtsao":            true,
	"@alloc":            true,
	"@emnapi":           true, // Node-API runtime emulation
	"@nolyfill":         true,
}

// checkPackageJSON checks for scoped packages without a corresponding .npmrc
// registry mapping, and for unpinned version specifiers.
func checkPackageJSON(path string, sc *scopeChecker) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	// Collect all scopes used
	scopes := map[string]bool{}
	allDeps := map[string]string{}
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for name := range allDeps {
		if strings.HasPrefix(name, "@") {
			parts := strings.SplitN(name, "/", 2)
			if len(parts) == 2 {
				scopes[parts[0]] = true
			}
		}
	}

	var findings []Finding

	// (1) Check .npmrc in the same directory for scope→registry mappings.
	// Well-known public scopes are excluded: they are meant to resolve from
	// the public registry and are not vulnerable to dependency confusion.
	if len(scopes) > 0 {
		npmrcPath := filepath.Join(filepath.Dir(path), ".npmrc")
		mappedScopes := readNpmrcScopeMappings(npmrcPath)
		for scope := range scopes {
			if sc.isPublic(scope) {
				continue
			}
			if !mappedScopes[scope] {
				findings = append(findings, Finding{
					Type:      "dep-confusion",
					Severity:  "HIGH",
					File:      path,
					Package:   scope,
					Ecosystem: "npm",
					Detail:    "scoped package " + scope + " has no registry mapping in .npmrc — if this is a private package, npm will resolve from public registry",
				})
			}
		}
	}

	// (2) Truly unpinned version specifiers only.
	// ^ and ~ are standard semver practice and excluded to reduce noise.
	// Only flag *, latest, next, and missing versions which are genuinely uncontrolled.
	trulyUnpinned := map[string]bool{"*": true, "latest": true, "next": true, "": true}
	for name, ver := range allDeps {
		if trulyUnpinned[strings.ToLower(strings.TrimSpace(ver))] {
			findings = append(findings, Finding{
				Type:      "dep-confusion",
				Severity:  "MEDIUM",
				File:      path,
				Package:   name,
				Ecosystem: "npm",
				Detail:    "package " + name + " uses unpinned version \"" + ver + "\" — attacker can publish any version to public registry",
			})
		}
	}

	return findings
}

// readNpmrcScopeMappings parses an .npmrc file and returns the set of scopes
// that have an explicit registry mapping (e.g. @myco:registry=https://...).
func readNpmrcScopeMappings(path string) map[string]bool {
	mapped := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return mapped
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "@") && strings.Contains(line, ":registry=") {
			scope := strings.SplitN(line, ":", 2)[0]
			mapped[scope] = true
		}
	}
	return mapped
}

// readNpmrcPrivateScopeMappings returns scopes explicitly mapped to a private
// (non-npmjs.org) registry in the .npmrc file. These are the only scopes for
// which a lockfile resolving from registry.npmjs.org is a dep-confusion signal.
func readNpmrcPrivateScopeMappings(path string) map[string]bool {
	private := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return private
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "@") && strings.Contains(line, ":registry=") {
			parts := strings.SplitN(line, ":registry=", 2)
			if len(parts) == 2 {
				scope := parts[0]
				registry := strings.TrimSpace(parts[1])
				if !strings.Contains(registry, "registry.npmjs.org") {
					private[scope] = true
				}
			}
		}
	}
	return private
}

// checkPackageLock checks package-lock.json for scoped packages that are
// mapped to a private registry in .npmrc but are resolved from the public
// npm registry — a definitive dep-confusion indicator.
// Packages with no .npmrc mapping are not flagged: without an explicit private
// registry declaration we cannot distinguish private from public packages, and
// doing so produces massive false-positive noise for transitive dependencies.
func checkPackageLock(path string, _ *scopeChecker) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var lock struct {
		Packages map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}

	npmrcPath := filepath.Join(filepath.Dir(path), ".npmrc")
	privateScopes := readNpmrcPrivateScopeMappings(npmrcPath)
	if len(privateScopes) == 0 {
		return nil
	}

	var findings []Finding
	check := func(name, resolved string) {
		if !strings.HasPrefix(name, "@") {
			return
		}
		scope := strings.SplitN(name, "/", 2)[0]
		if !privateScopes[scope] {
			return
		}
		if strings.Contains(resolved, "registry.npmjs.org") {
			findings = append(findings, Finding{
				Type:      "dep-confusion",
				Severity:  "HIGH",
				File:      path,
				Package:   name,
				Ecosystem: "npm",
				Detail:    "scoped package " + name + " resolved from public registry.npmjs.org — .npmrc maps " + scope + " to a private registry but lockfile shows public resolution",
			})
		}
	}

	for name, pkg := range lock.Packages {
		pkgName := strings.TrimPrefix(name, "node_modules/")
		check(pkgName, pkg.Resolved)
	}
	for name, dep := range lock.Dependencies {
		check(name, dep.Resolved)
	}

	return findings
}

// checkYarnLock checks yarn.lock for scoped packages that are mapped to a
// private registry in .npmrc but resolved from the public npm registry.
func checkYarnLock(path string, _ *scopeChecker) []Finding {
	npmrcPath := filepath.Join(filepath.Dir(path), ".npmrc")
	privateScopes := readNpmrcPrivateScopeMappings(npmrcPath)
	if len(privateScopes) == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []Finding
	var currentPkg string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			currentPkg = trimmed
		}

		if strings.HasPrefix(trimmed, "resolved ") && strings.HasPrefix(currentPkg, "@") {
			scope := strings.SplitN(currentPkg, "/", 2)[0]
			scope = strings.Trim(scope, `"`)
			if !privateScopes[scope] {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				url := strings.Trim(parts[1], `"`)
				if strings.Contains(url, "registry.npmjs.org") {
					pkgName := strings.Split(strings.Trim(currentPkg, `":`), "@")[0]
					if pkgName == "" && len(strings.SplitN(currentPkg, "@", 3)) >= 2 {
						pkgName = "@" + strings.SplitN(strings.Trim(currentPkg, `":`), "@", 3)[1]
					}
					findings = append(findings, Finding{
						Type:      "dep-confusion",
						Severity:  "HIGH",
						File:      path,
						Package:   pkgName,
						Ecosystem: "npm",
						Detail:    "scoped package " + scope + " resolved from public registry.npmjs.org — .npmrc maps " + scope + " to a private registry but yarn.lock shows public resolution",
					})
				}
			}
		}
	}
	return findings
}

// checkPnpmLock checks pnpm-lock.yaml for scoped packages that are mapped to a
// private registry in .npmrc but resolved from the public npm registry.
// Uses line-by-line parsing to avoid an external YAML dependency.
func checkPnpmLock(path string, _ *scopeChecker) []Finding {
	npmrcPath := filepath.Join(filepath.Dir(path), ".npmrc")
	privateScopes := readNpmrcPrivateScopeMappings(npmrcPath)
	if len(privateScopes) == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []Finding
	var currentPkg string
	reported := map[string]bool{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			key := strings.TrimSuffix(trimmed, ":")
			key = strings.TrimPrefix(key, "/") // v5/v6 prefix
			if strings.HasPrefix(key, "@") {
				currentPkg = key
			} else {
				currentPkg = ""
			}
		}

		if currentPkg != "" && strings.HasPrefix(trimmed, "tarball:") {
			scope := strings.SplitN(currentPkg, "/", 2)[0]
			if privateScopes[scope] {
				url := strings.TrimSpace(strings.TrimPrefix(trimmed, "tarball:"))
				if strings.Contains(url, "registry.npmjs.org") && !reported[currentPkg] {
					reported[currentPkg] = true
					findings = append(findings, Finding{
						Type:      "dep-confusion",
						Severity:  "HIGH",
						File:      path,
						Package:   currentPkg,
						Ecosystem: "npm",
						Detail:    "scoped package " + currentPkg + " tarball resolved from public registry.npmjs.org — .npmrc maps " + scope + " to a private registry but pnpm-lock.yaml shows public resolution",
					})
				}
			}
		}
	}
	return findings
}

// ── Python ───────────────────────────────────────────────────────────────────

// checkRequirementsTxt checks for --extra-index-url usage and unpinned versions.
func checkRequirementsTxt(path string) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []Finding
	lineNum := 0
	hasExtraIndex := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// (4) --extra-index-url — HIGH risk
		if strings.HasPrefix(line, "--extra-index-url") || strings.HasPrefix(line, "-e ") {
			if !hasExtraIndex {
				findings = append(findings, Finding{
					Type:      "dep-confusion",
					Severity:  "HIGH",
					File:      path,
					Line:      lineNum,
					Ecosystem: "PyPI",
					Detail:    "--extra-index-url found: pip selects highest version across all indexes — attacker can publish higher version to public PyPI",
				})
				hasExtraIndex = true
			}
			continue
		}

		// Skip other options
		if strings.HasPrefix(line, "-") {
			continue
		}

		// (5) Unpinned version specifiers
		if !strings.Contains(line, "==") {
			pkgName := line
			if idx := strings.IndexAny(line, "><!~@["); idx > 0 {
				pkgName = line[:idx]
			}
			pkgName = strings.TrimSpace(pkgName)
			severity := "MEDIUM"
			detail := "package " + pkgName + " is not pinned with == — use exact version to prevent substitution"
			if strings.Contains(line, ">=") || strings.Contains(line, "~=") {
				detail = "package " + pkgName + " uses range specifier — attacker can publish higher version to public PyPI"
			}
			findings = append(findings, Finding{
				Type:      "dep-confusion",
				Severity:  severity,
				File:      path,
				Line:      lineNum,
				Package:   pkgName,
				Ecosystem: "PyPI",
				Detail:    detail,
			})
			continue
		}

		// (6) Missing integrity hash
		if !strings.Contains(line, "--hash=") {
			pkgName := strings.SplitN(line, "==", 2)[0]
			findings = append(findings, Finding{
				Type:      "dep-confusion",
				Severity:  "LOW",
				File:      path,
				Line:      lineNum,
				Package:   strings.TrimSpace(pkgName),
				Ecosystem: "PyPI",
				Detail:    "package " + strings.TrimSpace(pkgName) + " has no --hash= integrity check",
			})
		}
	}

	return findings
}

// checkPipConf checks pip.conf / pip.ini for extra-index-url configuration.
func checkPipConf(path string) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []Finding
	lineNum := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "extra-index-url") || strings.HasPrefix(line, "extra_index_url") {
			findings = append(findings, Finding{
				Type:      "dep-confusion",
				Severity:  "HIGH",
				File:      path,
				Line:      lineNum,
				Ecosystem: "PyPI",
				Detail:    "extra-index-url in pip config: pip selects highest version across all indexes — attacker can publish higher version to public PyPI",
			})
		}
	}
	return findings
}

// checkPipfile checks Pipfile [[source]] entries for non-PyPI sources.
func checkPipfile(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	inSource := false
	hasNonPyPI := false

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[source]]" {
			inSource = true
			hasNonPyPI = false
			continue
		}
		if inSource && strings.HasPrefix(trimmed, "url") {
			url := strings.Trim(strings.SplitN(trimmed, "=", 2)[len(strings.SplitN(trimmed, "=", 2))-1], ` "`)
			if !strings.Contains(url, "pypi.org") {
				hasNonPyPI = true
			}
		}
		if inSource && (trimmed == "" || strings.HasPrefix(trimmed, "[")) {
			if hasNonPyPI {
				findings = append(findings, Finding{
					Type:      "dep-confusion",
					Severity:  "HIGH",
					File:      path,
					Ecosystem: "PyPI",
					Detail:    "Pipfile [[source]] with non-PyPI URL: if same package exists on PyPI with higher version, pip may prefer it",
				})
			}
			inSource = false
		}
	}
	return findings
}

// checkPyprojectToml checks pyproject.toml for non-standard Poetry/uv sources.
func checkPyprojectToml(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")
	inPoetrySource := false
	inUvIndex := false
	sourceURL := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Poetry: [[tool.poetry.source]]
		if trimmed == "[[tool.poetry.source]]" {
			inPoetrySource = true
			inUvIndex = false
			sourceURL = ""
			continue
		}
		// uv: [[tool.uv.index]]
		if trimmed == "[[tool.uv.index]]" {
			inUvIndex = true
			inPoetrySource = false
			sourceURL = ""
			continue
		}

		if (inPoetrySource || inUvIndex) && strings.HasPrefix(trimmed, "url") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				sourceURL = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		}

		// End of block
		isLastLine := i == len(lines)-1
		nextIsBlock := isLastLine || strings.HasPrefix(strings.TrimSpace(lines[i+1]), "[")
		if (inPoetrySource || inUvIndex) && (trimmed == "" && nextIsBlock || isLastLine) {
			if sourceURL != "" && !strings.Contains(sourceURL, "pypi.org") {
				ecosystem := "PyPI"
				tool := "Poetry"
				if inUvIndex {
					tool = "uv"
				}
				findings = append(findings, Finding{
					Type:      "dep-confusion",
					Severity:  "HIGH",
					File:      path,
					Ecosystem: ecosystem,
					Detail:    tool + " non-PyPI source configured (" + sourceURL + "): if same package exists on PyPI with higher version, it may be preferred",
				})
			}
			inPoetrySource = false
			inUvIndex = false
		}
	}
	return findings
}

// ── Go ───────────────────────────────────────────────────────────────────────

// checkGoEnv checks go.env for GOPROXY/GOPRIVATE misconfigurations.
// Instead of walking the entire tree for go.mod files, it reads only the sibling
// go.mod in the same directory as the go.env (the module that owns this config).
func checkGoEnv(path string) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	env := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = strings.Trim(v, `"`)
		}
	}

	goproxy := env["GOPROXY"]
	goprivate := env["GOPRIVATE"]

	usesPublicProxy := strings.Contains(goproxy, "proxy.golang.org") || strings.Contains(goproxy, "direct")
	if !usesPublicProxy && goproxy != "" {
		return nil
	}

	// Read only the sibling go.mod — the module that owns this go.env.
	siblingMod := filepath.Join(filepath.Dir(path), "go.mod")
	data, err := os.ReadFile(siblingMod)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			modPath := strings.TrimSpace(strings.TrimPrefix(line, "module "))
			if looksInternal(modPath) && !isCoveredByGOPRIVATE(modPath, goprivate) {
				findings = append(findings, Finding{
					Type:      "dep-confusion",
					Severity:  "HIGH",
					File:      path,
					Package:   modPath,
					Ecosystem: "go",
					Detail:    "module " + modPath + " may be resolved via public GOPROXY — set GOPRIVATE to exclude internal modules",
				})
			}
			break
		}
	}
	return findings
}

// looksInternal returns true if a Go module path looks like a private/internal module.
// Heuristics: non-dotted hostname, internal. prefix, or private TLDs.
func looksInternal(modPath string) bool {
	if modPath == "" {
		return false
	}
	host := strings.SplitN(modPath, "/", 2)[0]
	// Standard public hosts
	publicHosts := []string{"github.com", "golang.org", "google.golang.org", "gopkg.in", "k8s.io", "sigs.k8s.io"}
	for _, h := range publicHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return false
		}
	}
	// No dot in host → local/internal (e.g. "mycompany")
	if !strings.Contains(host, ".") {
		return true
	}
	// internal. subdomain
	if strings.HasPrefix(host, "internal.") || strings.Contains(host, ".internal") {
		return true
	}
	return false
}

// isCoveredByGOPRIVATE reports whether modPath matches any comma-separated
// glob pattern in goprivate (same semantics as Go's GOPRIVATE env var).
func isCoveredByGOPRIVATE(modPath, goprivate string) bool {
	if goprivate == "" {
		return false
	}
	for _, pattern := range strings.Split(goprivate, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// Simple prefix match (Go's GOPRIVATE uses path prefix, not full glob)
		if strings.HasPrefix(modPath, pattern) {
			return true
		}
		// Wildcard: *.example.com matches foo.example.com
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			host := strings.SplitN(modPath, "/", 2)[0]
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

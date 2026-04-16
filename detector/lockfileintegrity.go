package detector

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LockFileIntegrityDetector checks lockfiles for weak/missing integrity hashes,
// and drift between manifests and their corresponding lockfiles.
type LockFileIntegrityDetector struct{}

func (d *LockFileIntegrityDetector) Name() string { return "lockfile-integrity" }

var lockfileSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"vendor":       true,
}

func (d *LockFileIntegrityDetector) Detect(scanPath string, verbose bool) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(scanPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if lockfileSkipDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch entry.Name() {
		case "package-lock.json":
			found, _ := checkNpmLockIntegrity(path)
			findings = append(findings, found...)
		case "go.sum":
			found, _ := checkGoSumDrift(path)
			findings = append(findings, found...)
		case "Pipfile.lock":
			found, _ := checkPipfileLock(path)
			findings = append(findings, found...)
		}
		return nil
	})

	return findings, err
}

// ── npm ──────────────────────────────────────────────────────────────────────

type npmLockFile struct {
	LockfileVersion int `json:"lockfileVersion"`
	// v2/v3: packages map; root entry "" holds direct dep lists
	Packages map[string]npmLockPkg `json:"packages"`
	// v1: flat dependencies map
	Dependencies map[string]npmLockPkg `json:"dependencies"`
}

type npmLockPkg struct {
	Integrity       string            `json:"integrity"`
	Resolved        string            `json:"resolved"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type npmManifest struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// checkNpmLockIntegrity checks:
// 1. Direct dependencies using SHA-1 integrity (cryptographically weak).
// 2. Direct dependencies declared in package.json but absent in the lockfile (drift).
func checkNpmLockIntegrity(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)

	// Resolve the set of direct dependency names from package.json.
	directDeps := map[string]bool{}
	manifestData, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err == nil {
		var manifest npmManifest
		if json.Unmarshal(manifestData, &manifest) == nil {
			for name := range manifest.Dependencies {
				directDeps[name] = true
			}
			for name := range manifest.DevDependencies {
				directDeps[name] = true
			}
		}
	}

	var findings []Finding

	if lock.LockfileVersion >= 2 && len(lock.Packages) > 0 {
		// v2/v3 format
		for key, pkg := range lock.Packages {
			if key == "" {
				continue // root pseudo-entry
			}
			pkgName := strings.TrimPrefix(key, "node_modules/")
			// Only check direct deps for SHA-1 to avoid flooding transitive packages.
			if directDeps[pkgName] && strings.HasPrefix(pkg.Integrity, "sha1-") {
				findings = append(findings, Finding{
					Type:      "lockfile-integrity",
					Severity:  "HIGH",
					File:      path,
					Package:   pkgName,
					Ecosystem: "npm",
					Detail:    pkgName + ": integrity uses SHA-1 (broken) — regenerate lockfile with npm ≥ 5 to get SHA-512",
				})
			}
		}
		// Drift: direct dep missing from lockfile.
		for dep := range directDeps {
			if _, ok := lock.Packages["node_modules/"+dep]; !ok {
				findings = append(findings, Finding{
					Type:      "lockfile-integrity",
					Severity:  "MEDIUM",
					File:      path,
					Package:   dep,
					Ecosystem: "npm",
					Detail:    dep + ": declared in package.json but absent from package-lock.json — run `npm install` to sync",
				})
			}
		}
	} else if len(lock.Dependencies) > 0 {
		// v1 format
		for name, dep := range lock.Dependencies {
			if directDeps[name] && strings.HasPrefix(dep.Integrity, "sha1-") {
				findings = append(findings, Finding{
					Type:      "lockfile-integrity",
					Severity:  "HIGH",
					File:      path,
					Package:   name,
					Ecosystem: "npm",
					Detail:    name + ": integrity uses SHA-1 (broken) — regenerate lockfile with npm ≥ 5 to get SHA-512",
				})
			}
		}
		for dep := range directDeps {
			if _, ok := lock.Dependencies[dep]; !ok {
				findings = append(findings, Finding{
					Type:      "lockfile-integrity",
					Severity:  "MEDIUM",
					File:      path,
					Package:   dep,
					Ecosystem: "npm",
					Detail:    dep + ": declared in package.json but absent from package-lock.json — run `npm install` to sync",
				})
			}
		}
	}

	return findings, nil
}

// ── Go ───────────────────────────────────────────────────────────────────────

// checkGoSumDrift checks that every module required in go.mod has a
// corresponding hash entry in go.sum. A missing entry means the module
// was never fetched/verified, which can indicate tampering or a stale lockfile.
func checkGoSumDrift(sumPath string) ([]Finding, error) {
	dir := filepath.Dir(sumPath)
	modData, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, nil // no go.mod alongside go.sum, skip
	}

	// Parse go.sum: build a set of "module version" entries (excluding /go.mod lines).
	sumData, err := os.ReadFile(sumPath)
	if err != nil {
		return nil, err
	}
	inSum := map[string]bool{}
	for _, line := range strings.Split(string(sumData), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && !strings.HasSuffix(fields[1], "/go.mod") {
			inSum[fields[0]+" "+fields[1]] = true
		}
	}

	// Parse go.mod require blocks.
	var findings []Finding
	inRequire := false
	for _, raw := range strings.Split(string(modData), "\n") {
		line := strings.TrimSpace(raw)
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		var mod, ver string
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mod, ver = fields[0], fields[1]
			}
		} else if strings.HasPrefix(line, "require ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				mod, ver = fields[1], fields[2]
			}
		}

		if mod == "" {
			continue
		}
		// Strip inline comments and the // indirect marker.
		ver = strings.SplitN(ver, "//", 2)[0]
		ver = strings.TrimSpace(ver)

		if !inSum[mod+" "+ver] {
			findings = append(findings, Finding{
				Type:      "lockfile-integrity",
				Severity:  "MEDIUM",
				File:      sumPath,
				Package:   mod,
				Ecosystem: "go",
				Detail:    mod + "@" + ver + ": required in go.mod but has no entry in go.sum — run `go mod tidy` to verify",
			})
		}
	}

	return findings, nil
}

// ── Python ───────────────────────────────────────────────────────────────────

type pipfileLockFile struct {
	Default map[string]pipfilePkg `json:"default"`
	Develop map[string]pipfilePkg `json:"develop"`
}

type pipfilePkg struct {
	Hashes  []string `json:"hashes"`
	Version string   `json:"version"`
}

// checkPipfileLock flags packages in Pipfile.lock that have no hash entries,
// meaning their contents cannot be cryptographically verified at install time.
func checkPipfileLock(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pipfileLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var findings []Finding
	report := func(name string, pkg pipfilePkg) {
		if len(pkg.Hashes) == 0 {
			findings = append(findings, Finding{
				Type:      "lockfile-integrity",
				Severity:  "MEDIUM",
				File:      path,
				Package:   name,
				Ecosystem: "PyPI",
				Detail:    name + ": no hash entries in Pipfile.lock — package integrity cannot be verified at install time",
			})
		}
	}
	for name, pkg := range lock.Default {
		report(name, pkg)
	}
	for name, pkg := range lock.Develop {
		report(name, pkg)
	}

	return findings, nil
}

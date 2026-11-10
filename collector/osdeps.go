package collector

import (
	"sort"

	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

// osDependency is one dependency an OS package declares: the names any one of
// which satisfies it. dpkg writes alternatives ("default-mta |
// mail-transport-agent"); rpm and apk declare one capability per dependency.
type osDependency []string

// osDepRecord is what a package database says one package needs and offers,
// as plain names with the version constraints removed: package names, virtual
// names (a dpkg Provides, an rpm capability such as "libc.so.6()(64bit)", an
// apk "so:libssl.so.3") and file paths. The package's own name counts as
// provided without being listed.
type osDepRecord struct {
	Requires []osDependency
	Provides []string
}

// linkOSDependencies resolves each package's declared dependencies to the
// installed packages that satisfy them and writes them to Deps, as the PURLs
// the SBOM uses for bom-refs. records[i] belongs to pkgs[i].
//
// Version constraints are not checked: the package manager checked them when
// it installed the packages, so whatever is installed under a required name
// is what satisfies the dependency. A name nothing installed provides is
// dropped (a dependency the package manager let go unmet, a capability the
// base system offers without a package). Of dpkg's alternatives the first one
// that is installed is taken, as apt does. When several installed packages
// provide one virtual name, each of them is a dependency, since the
// declaration does not say which one is used.
//
// Direct is read off the graph: a package no other installed package depends
// on is direct (someone asked for it, or it is the top of a chain), the rest
// are indirect. The package manager's own record of what was installed by
// hand (apt's extended_states, dnf's history) is not read: it is missing from
// images and, on a host, counts everything a base install brought as manual.
func linkOSDependencies(pkgs []inventory.Package, records []osDepRecord, osID string) {
	purls := make([]string, len(pkgs))
	providers := make(map[string][]int)
	for i, p := range pkgs {
		purls[i] = sbom.PackagePURL(p, osID)
		providers[p.Name] = append(providers[p.Name], i)
		for _, name := range records[i].Provides {
			if name != "" && name != p.Name {
				providers[name] = append(providers[name], i)
			}
		}
	}

	dependedOn := make(map[string]bool)
	for i := range pkgs {
		deps := make(map[string]bool)
		for _, dep := range records[i].Requires {
			for _, name := range dep {
				found := false
				for _, j := range providers[name] {
					// Not itself, nor another architecture's copy of itself,
					// which has the same PURL.
					if purls[j] == purls[i] {
						continue
					}
					deps[purls[j]] = true
					found = true
				}
				if found {
					break
				}
			}
		}
		list := make([]string, 0, len(deps))
		for purl := range deps {
			list = append(list, purl)
			dependedOn[purl] = true
		}
		sort.Strings(list)
		pkgs[i].Deps = list
		pkgs[i].DepsResolved = true
	}
	for i := range pkgs {
		pkgs[i].Direct = inventory.BoolPtr(!dependedOn[purls[i]])
	}
}

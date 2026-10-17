package collector

import (
	"strings"
	"testing"

	"github.com/TITeee/heretix-cli/inventory"
)

func TestWindowsServerPackage(t *testing.T) {
	server2022 := windowsVersion{
		ProductName: "Windows Server 2022 Standard", InstallationType: "Server",
		Major: 10, Minor: 0, Build: 20348, UBR: 5761, HasUBR: true,
	}

	tests := []struct {
		name        string
		v           windowsVersion
		wantName    string
		wantVersion string
		wantWarning string
	}{
		{
			name:     "desktop experience",
			v:        server2022,
			wantName: "Windows Server 2022", wantVersion: "10.0.20348.5761",
		},
		{
			name: "Server Core is its own MSRC product",
			v: windowsVersion{
				ProductName: "Windows Server 2019 Datacenter", InstallationType: "Server Core",
				Major: 10, Minor: 0, Build: 17763, UBR: 9376, HasUBR: true,
			},
			wantName: "Windows Server 2019 (Server Core installation)", wantVersion: "10.0.17763.9376",
		},
		{
			name: "a UBR above 9999 is kept whole",
			v: windowsVersion{
				ProductName: "Windows Server 2025 Standard", InstallationType: "Server",
				Major: 10, Minor: 0, Build: 26100, UBR: 33650, HasUBR: true,
			},
			wantName: "Windows Server 2025", wantVersion: "10.0.26100.33650",
		},
		{
			// Same build as Server 2019, told apart by InstallationType.
			name: "client Windows is not checked, silently",
			v: windowsVersion{
				ProductName: "Windows 10 Enterprise LTSC 2019", InstallationType: "Client",
				Major: 10, Minor: 0, Build: 17763, UBR: 1, HasUBR: true,
			},
		},
		{
			name: "Nano Server is not checked",
			v:    windowsVersion{ProductName: "Windows Server 2016 Datacenter", InstallationType: "Nano Server", Build: 14393, HasUBR: true},
		},
		{
			name: "a release heretix-api does not import is left out, with a warning",
			v: windowsVersion{
				ProductName: "Windows Server 2012 R2 Standard", InstallationType: "Server",
				Major: 6, Minor: 3, Build: 9600, UBR: 22000, HasUBR: true,
			},
			wantWarning: "only Windows Server 2016, 2019, 2022 and 2025 are",
		},
		{
			name: "without a UBR every CVE since release would be reported, so it is left out",
			v: windowsVersion{
				ProductName: "Windows Server 2022 Standard", InstallationType: "Server",
				Major: 10, Minor: 0, Build: 20348,
			},
			wantWarning: "update build revision (UBR) could not be read",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok, warning := windowsServerPackage(tt.v)
			if tt.wantWarning == "" && warning != "" {
				t.Errorf("unexpected warning %q", warning)
			}
			if tt.wantWarning != "" && !strings.Contains(warning, tt.wantWarning) {
				t.Errorf("warning = %q, want it to mention %q", warning, tt.wantWarning)
			}
			if tt.wantName == "" {
				if ok {
					t.Errorf("got package %+v, want none", p)
				}
				return
			}
			want := inventory.Package{
				Name: tt.wantName, Version: tt.wantVersion, Ecosystem: "advisory",
				Source: "windows-registry", Location: windowsVersionKey,
			}
			if !ok || p.Name != want.Name || p.Version != want.Version || p.Ecosystem != want.Ecosystem ||
				p.Source != want.Source || p.Location != want.Location {
				t.Errorf("got %+v (ok=%v), want %+v", p, ok, want)
			}
		})
	}
}

// The OS package describes the live host, so a scan of a project directory or
// of a container rootfs must not report it.
func TestWindowsCollectorOnlyForTheHostRoot(t *testing.T) {
	c := &WindowsCollector{}
	if pkgs, err := c.Collect(t.TempDir(), false, false); err != nil || len(pkgs) != 0 {
		t.Errorf("project directory: got %v, %v; want nothing", pkgs, err)
	}
	if pkgs, err := c.Collect(t.TempDir(), false, true); err != nil || len(pkgs) != 0 {
		t.Errorf("container rootfs: got %v, %v; want nothing", pkgs, err)
	}
}

func TestParseWindowsFeatures(t *testing.T) {
	// PowerShell's output: one name per line, CRLF, unsorted.
	got := parseWindowsFeatures("NetFx4\r\nDNS-Server-Full-Role\r\n\r\nNetFx4\r\n")
	want := []string{"DNS-Server-Full-Role", "NetFx4"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parseWindowsFeatures = %#v, want %#v", got, want)
	}
	if got := parseWindowsFeatures(""); got == nil || len(got) != 0 {
		t.Errorf("no output = %#v, want an empty, non-nil list (known to be none)", got)
	}
}

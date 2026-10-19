// winserver2sbom builds a heretix CycloneDX SBOM for a Windows Server from
// the output of a few PowerShell commands, for servers heretix-cli cannot run
// on. Run these in an empty directory on the server (64-bit PowerShell, as
// administrator) and copy the files here:
//
//	Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | ConvertTo-Json | Out-File -Encoding utf8 version.json
//	Get-CimInstance -ClassName Win32_OptionalFeature -Filter 'InstallState=1' | ForEach-Object Name | Out-File -Encoding utf8 features.txt
//	hostname | Out-File -Encoding utf8 hostname.txt
//	cmd /c ver | Out-File -Encoding utf8 ver.txt
//
// Then:
//
//	go run ./contrib/winserver2sbom <dir> [output.json]
//
// The output defaults to <hostname>.json in the current directory. The OS
// package is built by the same code `heretix-cli collect` runs on the server,
// so the SBOM matches what collect writes there. features.txt is optional:
// without it every role finding is reported, as for a collect that could not
// read the features. version.json holds more than is read (it carries the
// encoded product key, among others): keep it out of any shared place.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/TITeee/heretix-cli/collector"
	"github.com/TITeee/heretix-cli/inventory"
	"github.com/TITeee/heretix-cli/sbom"
)

const registryKey = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: winserver2sbom <dir> [output.json]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// readText reads a file PowerShell wrote: UTF-8 with a BOM, or UTF-16.
func readText(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if len(b) >= 2 && (b[0] == 0xFF && b[1] == 0xFE || b[0] == 0xFE && b[1] == 0xFF) {
		return "", fmt.Errorf("%s is UTF-16; write it with Out-File -Encoding utf8", name)
	}
	return string(b), nil
}

func run(dir string, rest []string) error {
	hostText, err := readText(dir, "hostname.txt")
	if err != nil {
		return err
	}
	hostname := strings.TrimSpace(hostText)

	raw, err := readText(dir, "version.json")
	if err != nil {
		return err
	}
	// Only these values are read; the key holds many more.
	var v struct {
		ProductName      string  `json:"ProductName"`
		InstallationType string  `json:"InstallationType"`
		CurrentBuild     string  `json:"CurrentBuild"`
		Major            uint64  `json:"CurrentMajorVersionNumber"`
		Minor            uint64  `json:"CurrentMinorVersionNumber"`
		UBR              *uint64 `json:"UBR"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return fmt.Errorf("version.json: %w", err)
	}
	build, err := strconv.ParseUint(v.CurrentBuild, 10, 64)
	if err != nil {
		return fmt.Errorf("version.json: CurrentBuild is not a number: %q", v.CurrentBuild)
	}

	p, ok, warning := collector.WindowsServerPackageFromRegistry(v.ProductName, v.InstallationType, v.Major, v.Minor, build, v.UBR)
	if warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	if !ok {
		return fmt.Errorf("%q (%s, build %d) is not a Windows Server release to check", v.ProductName, v.InstallationType, build)
	}
	p.Location = registryKey

	if features, err := readText(dir, "features.txt"); err == nil {
		p.Features = collector.ParseWindowsFeatures(features)
	} else if !os.IsNotExist(err) {
		return err
	} else {
		fmt.Fprintln(os.Stderr, "warning: no features.txt, so role findings cannot be set aside")
	}

	inv := inventory.New(hostname, osInfo(dir))
	inv.Packages = append(inv.Packages, p)

	out := hostname + ".json"
	if len(rest) == 1 {
		out = rest[0]
	}
	if err := sbom.WriteToFile(sbom.GenerateCycloneDX(inv, "winserver2sbom"), out); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %s %s, %d features -> %s\n", hostname, p.Name, p.Version, len(p.Features), out)
	return nil
}

var fourPartVersion = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

// osInfo mirrors collector.detectOSInfoWindows, which reads `cmd /c ver`.
func osInfo(dir string) inventory.OSInfo {
	fallback := inventory.OSInfo{ID: "windows", VersionID: "unknown", Name: "Microsoft Windows"}
	ver, err := readText(dir, "ver.txt")
	if err != nil {
		return fallback
	}
	m := fourPartVersion.FindString(ver)
	if m == "" {
		return fallback
	}
	return inventory.OSInfo{ID: "windows", VersionID: m, Name: "Microsoft Windows " + m}
}

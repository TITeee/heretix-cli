//go:build windows

package collector

import (
	"errors"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// readWindowsVersion reads the release and build of the running Windows from
// the registry. The 64-bit view is asked for explicitly so that a 32-bit
// build of heretix reads the same key.
func readWindowsVersion() (windowsVersion, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return windowsVersion{}, err
	}
	defer k.Close()

	var v windowsVersion
	v.ProductName, _, _ = k.GetStringValue("ProductName")
	v.InstallationType, _, _ = k.GetStringValue("InstallationType")

	build, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		return windowsVersion{}, err
	}
	if v.Build, err = strconv.ParseUint(build, 10, 64); err != nil {
		return windowsVersion{}, errors.New("CurrentBuild is not a number: " + build)
	}

	// CurrentMajorVersionNumber exists from Windows 10 / Server 2016, the
	// oldest release checked; older ones are left out by their build anyway.
	v.Major, _, _ = k.GetIntegerValue("CurrentMajorVersionNumber")
	v.Minor, _, _ = k.GetIntegerValue("CurrentMinorVersionNumber")

	if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
		v.UBR, v.HasUBR = ubr, true
	}
	return v, nil
}

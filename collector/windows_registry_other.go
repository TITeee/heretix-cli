//go:build !windows

package collector

import "errors"

// readWindowsVersion is never reached off Windows: CollectAll registers the
// WindowsCollector only on a Windows host.
func readWindowsVersion() (windowsVersion, error) {
	return windowsVersion{}, errors.New("not running on Windows")
}

func readWindowsFeatures() ([]string, error) {
	return nil, errors.New("not running on Windows")
}

//go:build !linux

package collector

// kernelRelease is only read on Linux, the one place RuntimeApplies is true.
func kernelRelease() string { return "" }

package cmd

import (
	"fmt"

	"github.com/TITeee/heretix-cli/collector"
	"github.com/TITeee/heretix-cli/inventory"
)

const runtimeFlagHelp = "Read /proc for what running processes do with the OS packages (in-use, used-by, needs-restart): on or off. " +
	"A host scan needs root for it; off leaves these facts out of the SBOM. An image or a directory has no processes and is not read either way"

// validRuntimeMode checks a --runtime value before any work is done.
func validRuntimeMode(mode string) error {
	if mode != "on" && mode != "off" {
		return fmt.Errorf("--runtime %q: use on or off", mode)
	}
	return nil
}

// applyRuntimeFacts adds the runtime facts to a host scan's inventory when
// --runtime is on. It is an error to run one without root, rather than a
// warning: an SBOM that silently left them out would read as "nothing is in
// use" to anyone who did not notice.
func applyRuntimeFacts(inv *inventory.Inventory, scanPath, mode string, verbose bool) error {
	if mode == "off" || !collector.RuntimeApplies(scanPath) {
		return nil
	}
	return collector.ApplyRuntime(inv, scanPath, verbose)
}

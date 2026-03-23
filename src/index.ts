#!/usr/bin/env node

// Suppress noisy output from opentimestamps library
const originalLog = console.log;
const originalWarn = console.warn;
const originalError = console.error;
const otsNoise = ["Got ", "Calendar ", "Pending confirmation", "Lite-client verification", "Could not connect to local Bitcoin node", "DeprecationWarning"];
const isOtsNoise = (args: unknown[]) => { const msg = String(args[0] || ""); return otsNoise.some(n => msg.includes(n)); };
console.log = (...args: unknown[]) => { if (isOtsNoise(args)) return; originalLog.apply(console, args); };
console.warn = (...args: unknown[]) => { if (isOtsNoise(args)) return; originalWarn.apply(console, args); };
console.error = (...args: unknown[]) => { if (isOtsNoise(args)) return; originalError.apply(console, args); };
process.removeAllListeners("warning");
process.on("warning", (w) => { if (w.name === "DeprecationWarning") return; originalWarn(w); });

import { readFileSync } from "fs";
import { verify } from "./verify";
import { VerifyResult } from "./types";

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function pass(msg: string) { return `${GREEN}[PASS]${RESET} ${msg}`; }
function fail(msg: string) { return `${RED}[FAIL]${RESET} ${msg}`; }
function warn(msg: string) { return `${YELLOW}[WARN]${RESET} ${msg}`; }
function dim(msg: string) { return `${DIM}${msg}${RESET}`; }

function printResult(result: VerifyResult) {
  console.log("");
  console.log("ProofSnap Evidence Verifier v1.0.0");
  console.log("===================================");
  console.log("");
  console.log(`Evidence ID: ${result.evidenceId}`);
  console.log("");

  // Signature
  console.log(
    result.signature.valid
      ? pass(`Signature: ${result.signature.algorithm}`)
      : fail(`Signature: INVALID`)
  );

  // File hashes
  for (const file of result.files) {
    console.log(
      file.match
        ? pass(`${file.name}: SHA-256 match ${dim(`(${file.actual.substring(0, 12)}...)`)}`)
        : fail(`${file.name}: SHA-256 MISMATCH ${dim(`(expected ${file.expected.substring(0, 12)}..., got ${file.actual.substring(0, 12)}...)`)}`)
    );
  }

  // Hash chain
  if (result.hashChain) {
    if (result.hashChain.valid) {
      console.log(pass(`Hash chain: ${result.hashChain.entries} operations, chain intact`));
    } else {
      if (!result.hashChain.forensicLogHashMatch) console.log(fail("Hash chain: forensic log hash mismatch"));
      if (!result.hashChain.chainSelfValid) console.log(fail("Hash chain: chain integrity broken"));
      if (result.hashChain.finalHashMatch === false) console.log(fail("Hash chain: final hash mismatch"));
      if (!result.hashChain.evidenceIdConsistent) console.log(fail("Hash chain: evidence ID mismatch"));
    }
  } else {
    console.log(warn("Hash chain: not present (older evidence package)"));
  }

  // OTS
  if (result.ots) {
    if (result.ots.verified && !result.ots.pending) {
      console.log(pass(
        `OpenTimestamps: Bitcoin block #${result.ots.bitcoinHeight}, ${result.ots.timestamp}`
      ));
    } else if (result.ots.verified && result.ots.pending) {
      console.log(warn("OpenTimestamps: pending Bitcoin confirmation"));
    } else {
      console.log(fail(`OpenTimestamps: verification failed${result.ots.error ? ` (${result.ots.error})` : ""}`));
    }
  }

  // eIDAS
  if (result.eidas) {
    if (result.eidas.overallValid) {
      console.log(pass(`eIDAS LTV: all checks passed (${result.eidas.details.join(", ")})`));
    } else {
      for (const detail of result.eidas.details) {
        if (detail.includes("VALID") || detail.includes("MATCH") || detail.includes("GOOD")) {
          console.log(pass(`eIDAS: ${detail}`));
        } else {
          console.log(fail(`eIDAS: ${detail}`));
        }
      }
    }
  }

  // Overall
  console.log("");
  const totalChecks = 1 + result.files.length +
    (result.hashChain ? 1 : 0) +
    (result.ots ? 1 : 0) +
    (result.eidas ? 1 : 0);

  const passedChecks = (result.signature.valid ? 1 : 0) +
    result.files.filter((f) => f.match).length +
    (result.hashChain?.valid ? 1 : 0) +
    (result.ots?.verified ? 1 : 0) +
    (result.eidas?.overallValid ? 1 : 0);

  if (result.overallValid) {
    console.log(`${GREEN}Result: ALL CHECKS PASSED (${passedChecks}/${totalChecks})${RESET}`);
  } else {
    console.log(`${RED}Result: VERIFICATION FAILED (${passedChecks}/${totalChecks} passed)${RESET}`);
  }
  console.log("");
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log("Usage: proofsnap-verify <evidence.zip>");
    console.log("");
    console.log("Independently verify a ProofSnap evidence package.");
    console.log("Checks: RSA-4096 signature, SHA-256 hashes, hash chain,");
    console.log("        OpenTimestamps (Bitcoin), eIDAS qualified timestamps.");
    console.log("");
    console.log("Options:");
    console.log("  --json    Output results as JSON");
    console.log("  --help    Show this help");
    console.log("");
    console.log("https://github.com/proofsnap/proofsnap-verify");
    process.exit(0);
  }

  const jsonOutput = args.includes("--json");
  const filePath = args.find((a) => !a.startsWith("--"));

  if (!filePath) {
    console.error("Error: Please provide a path to a ProofSnap evidence ZIP file.");
    process.exit(1);
  }

  try {
    const fileBuffer = readFileSync(filePath);
    const result = await verify(fileBuffer.buffer.slice(
      fileBuffer.byteOffset,
      fileBuffer.byteOffset + fileBuffer.byteLength
    ));

    if (jsonOutput) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printResult(result);
    }

    process.exit(result.overallValid ? 0 : 1);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : "Unknown error"}`);
    process.exit(1);
  }
}

main();

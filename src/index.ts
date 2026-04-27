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
import { inspectTimestamp } from "./inspectTimestamp";
import { verifyFileWithTimestamp } from "./verifyFileWithTimestamp";
import {
  VerifyResult,
  TimestampInspectionResult,
  FileTimestampResult,
} from "./types";
import { overrideDefaultTrustedRoots } from "./trustedRoots";

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

function pass(msg: string) { return `${GREEN}[PASS]${RESET} ${msg}`; }
function fail(msg: string) { return `${RED}[FAIL]${RESET} ${msg}`; }
function warn(msg: string) { return `${YELLOW}[WARN]${RESET} ${msg}`; }
function dim(msg: string) { return `${DIM}${msg}${RESET}`; }

function printZipResult(result: VerifyResult) {
  console.log("");
  console.log("ProofSnap Evidence Verifier v1.5.0 — ZIP mode");
  console.log("==============================================");
  console.log("");
  console.log(`Evidence ID: ${result.evidenceId}`);
  console.log("");

  console.log(
    result.signature.valid
      ? pass(`Signature: ${result.signature.algorithm}`)
      : fail(`Signature: INVALID`)
  );

  for (const file of result.files) {
    console.log(
      file.match
        ? pass(`${file.name}: SHA-256 match ${dim(`(${file.actual.substring(0, 12)}...)`)}`)
        : fail(`${file.name}: SHA-256 MISMATCH ${dim(`(expected ${file.expected.substring(0, 12)}..., got ${file.actual.substring(0, 12)}...)`)}`)
    );
  }

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

function printInspection(insp: TimestampInspectionResult, header: string) {
  console.log("");
  console.log(header);
  console.log("=".repeat(header.length));
  console.log("");

  console.log(`${BOLD}Time-Stamp Authority${RESET}`);
  console.log(`  Common Name:  ${insp.tsa.commonName ?? dim("(unknown)")}`);
  console.log(`  Organization: ${insp.tsa.organization ?? dim("(unknown)")}`);
  console.log(`  Country:      ${insp.tsa.country ?? dim("(unknown)")}`);
  if (insp.tsa.validFrom || insp.tsa.validUntil) {
    console.log(`  Cert valid:   ${insp.tsa.validFrom ?? "?"} → ${insp.tsa.validUntil ?? "?"}`);
  }
  if (insp.tsa.serialNumberHex) {
    console.log(`  Cert serial:  ${dim(insp.tsa.serialNumberHex)}`);
  }
  console.log("");

  console.log(`${BOLD}Timestamp${RESET}`);
  console.log(`  Issued at:    ${insp.timestampedAt ?? dim("(unknown)")}`);
  console.log(`  Hash algo:    ${insp.hashAlgorithm}`);
  console.log(`  Hash value:   ${dim(insp.messageImprint || "(missing)")}`);
  if (insp.policyOid) console.log(`  Policy OID:   ${dim(insp.policyOid)}`);
  if (insp.serialNumber) console.log(`  Serial:       ${dim(insp.serialNumber)}`);
  console.log("");

  console.log(`${BOLD}Verification${RESET}`);
  console.log(insp.signatureValid ? pass("TSR signature valid") : fail("TSR signature invalid"));
  console.log(insp.certChainValid ? pass("Certificate chain consistent") : fail("Certificate chain invalid"));
  if (insp.trustsKnownEUTL && insp.trustedRootMatch) {
    console.log(pass(`Trusted root: ${insp.trustedRootMatch.commonName} (${insp.trustedRootMatch.country})`));
  } else {
    console.log(warn("Trusted root: not matched against EUTL bundle"));
  }
  if (insp.ocspValid === true) console.log(pass("OCSP: GOOD"));
  else if (insp.ocspValid === false) console.log(fail("OCSP: REVOKED or NOT_GOOD"));
  else console.log(warn("OCSP: not checked"));

  if (insp.warnings.length) {
    console.log("");
    for (const w of insp.warnings) console.log(warn(w));
  }
  if (insp.errors.length) {
    console.log("");
    for (const e of insp.errors) console.log(fail(e));
  }

  console.log("");
  if (insp.overallValid) {
    console.log(`${GREEN}Result: TIMESTAMP VALID${RESET}`);
  } else {
    console.log(`${RED}Result: TIMESTAMP INVALID${RESET}`);
  }
  console.log("");
}

function printFileTimestamp(result: FileTimestampResult) {
  console.log("");
  console.log("ProofSnap Verifier v1.5.0 — File + Timestamp mode");
  console.log("=================================================");
  console.log("");
  console.log(`File:        ${result.fileName ?? "(unnamed)"}`);
  console.log(`File size:   ${result.fileSize.toLocaleString()} bytes`);
  console.log(`File SHA-256: ${dim(result.fileHash)}`);
  console.log("");
  console.log(
    result.hashCoversFile
      ? pass("Timestamp covers this exact file (hashes match)")
      : fail("Hash MISMATCH — this timestamp does NOT cover this file")
  );

  printInspection(result.tsr, "Timestamp Details");

  if (result.overallValid) {
    console.log(`${GREEN}Result: FILE + TIMESTAMP VALID${RESET}`);
  } else {
    console.log(`${RED}Result: FILE + TIMESTAMP INVALID${RESET}`);
  }
  console.log("");
}

function printHelp() {
  console.log("ProofSnap Evidence Verifier v1.5.0");
  console.log("");
  console.log("Usage:");
  console.log("  proofsnap-verify <evidence.zip>                       # ZIP mode (default)");
  console.log("  proofsnap-verify --file <file> --tsr <stamp.tsr>      # File + Timestamp mode");
  console.log("  proofsnap-verify --inspect-tsr <stamp.tsr>            # Inspect TSR alone");
  console.log("  proofsnap-verify <stamp.tsr>                          # Inspect TSR (auto-detected)");
  console.log("");
  console.log("Options:");
  console.log("  --json              Output JSON instead of human-readable text");
  console.log("  --roots <file.pem>  Provide trusted roots PEM bundle (overrides bundled EUTL)");
  console.log("  --help              Show this help");
  console.log("");
  console.log("Environment:");
  console.log("  PROOFSNAP_TRUSTED_ROOTS=/path/to/roots.pem  same as --roots");
  console.log("");
  console.log("Exit code: 0 = all checks passed, 1 = any check failed");
  console.log("");
  console.log("https://github.com/proofsnap/proofsnap-verify");
}

function readBuffer(path: string): Buffer {
  return readFileSync(path);
}

function bufferToArrayBuffer(b: Buffer): ArrayBuffer {
  // Buffer.buffer can be ArrayBuffer | SharedArrayBuffer in Node 24+ types.
  // Always copy into a fresh ArrayBuffer so JSZip and crypto.subtle accept it.
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

interface ParsedArgs {
  json: boolean;
  help: boolean;
  rootsPath: string | null;
  filePath: string | null;
  tsrPath: string | null;
  inspectTsr: string | null;
  positional: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = {
    json: false,
    help: false,
    rootsPath: null,
    filePath: null,
    tsrPath: null,
    inspectTsr: null,
    positional: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") out.json = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--roots") out.rootsPath = argv[++i];
    else if (a === "--file") out.filePath = argv[++i];
    else if (a === "--tsr") out.tsrPath = argv[++i];
    else if (a === "--inspect-tsr") out.inspectTsr = argv[++i];
    else if (!a.startsWith("--")) out.positional.push(a);
  }
  return out;
}

function loadTrustedRoots(args: ParsedArgs): void {
  const path =
    args.rootsPath || process.env.PROOFSNAP_TRUSTED_ROOTS || null;
  if (!path) return;
  try {
    const pem = readFileSync(path, "utf-8");
    overrideDefaultTrustedRoots(pem);
  } catch (err) {
    console.error(`Error: cannot read trusted roots from ${path}: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || (args.positional.length === 0 && !args.filePath && !args.tsrPath && !args.inspectTsr)) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }

  loadTrustedRoots(args);

  // Mode resolution priority:
  //  1. --file + --tsr  → file+timestamp
  //  2. --inspect-tsr   → inspect TSR
  //  3. positional ends in .tsr → inspect TSR
  //  4. positional ends in .zip → ZIP
  try {
    if (args.filePath && args.tsrPath) {
      const fileBytes = readBuffer(args.filePath);
      const tsrBytes = readBuffer(args.tsrPath);
      const result = await verifyFileWithTimestamp(
        new Uint8Array(fileBytes),
        new Uint8Array(tsrBytes),
        { fileName: args.filePath }
      );
      if (args.json) console.log(JSON.stringify(result, null, 2));
      else printFileTimestamp(result);
      process.exit(result.overallValid ? 0 : 1);
    }

    if (args.filePath || args.tsrPath) {
      console.error("Error: --file and --tsr must be used together");
      process.exit(2);
    }

    const inspectPath = args.inspectTsr || (args.positional[0]?.toLowerCase().endsWith(".tsr") ? args.positional[0] : null);
    if (inspectPath) {
      const tsrBytes = readBuffer(inspectPath);
      const result = await inspectTimestamp(new Uint8Array(tsrBytes));
      if (args.json) console.log(JSON.stringify(result, null, 2));
      else printInspection(result, "ProofSnap Verifier v1.5.0 — Inspect TSR");
      process.exit(result.overallValid ? 0 : 1);
    }

    const zipPath = args.positional[0];
    if (!zipPath) {
      console.error("Error: please provide an input file (.zip or .tsr)");
      process.exit(2);
    }

    const fileBuffer = readBuffer(zipPath);
    const result = await verify(bufferToArrayBuffer(fileBuffer));
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else printZipResult(result);
    process.exit(result.overallValid ? 0 : 1);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : "Unknown error"}`);
    process.exit(1);
  }
}

main();

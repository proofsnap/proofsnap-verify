#!/usr/bin/env node
import { closeSync, fstatSync, openSync, readdirSync, readSync, statSync } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import {
  CannotVerifyError,
  Check,
  inspectTimestamp,
  OtsReport,
  PackageReport,
  SourceEntry,
  TimestampReport,
  VERIFIER_VERSION,
  verifyFiles,
  verifyFileWithOts,
  verifyFileWithTimestamp,
  verifyOts,
  verifyZip,
} from "./index";

const HELP = `ProofSnap Verifier ${VERIFIER_VERSION}

Checks a ProofSnap evidence package on your machine. Nothing is uploaded.

Usage:
  proofsnap-verify package.zip           a package, matter export or delivery ZIP
  proofsnap-verify package-folder/       the same package after unzipping
  proofsnap-verify file token.tsr        does this RFC 3161 timestamp cover the file?
  proofsnap-verify file proof.ots        does this OpenTimestamps proof cover the file?
  proofsnap-verify token.tsr | proof.ots inspect a timestamp on its own

  Add your own copy of a certified file after the ZIP to compare it, or a
  separately delivered .ots proof to use it.

Options:
  --offline        no network (the Bitcoin confirmation is skipped)
  --verbose, -v    every check and every file
  --json           machine-readable report
  --roots <pem>    extra trusted roots for RFC 3161 timestamps
  --no-color       plain output

Exit codes: 0 valid, 1 invalid or not a ProofSnap package,
            2 the check could not run, 3 valid with warnings`;

// ---------------------------------------------------------------- output
const useColor = process.stdout.isTTY && !process.argv.includes("--no-color") && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = c("32");
const red = c("31");
const yellow = c("33");
const dim = c("2");
const bold = c("1");
const TAG: Record<string, string> = {
  pass: green("[PASS]"),
  fail: red("[FAIL]"),
  warn: yellow("[WARN]"),
  info: dim("[INFO]"),
  skip: dim("[SKIP]"),
};
const GROUP_TITLES: Record<string, string> = {
  structure: "Archive",
  signature: "Seal",
  files: "Files",
  custody: "Chain of custody",
  content: "Content",
  bitcoin: "Bitcoin timestamp (OpenTimestamps)",
  eidas: "Qualified timestamp (eIDAS)",
  issuance: "Issued by ProofSnap",
  container: "Packages inside",
};
// A group that passed but carries a note (for example a Bitcoin proof still pending) shows the note.
const RANK = ["skip", "pass", "info", "warn", "fail"];
const worst = (xs: Check[]) => xs.reduce((w, x) => (RANK.indexOf(x.status) > RANK.indexOf(w) ? x.status : w), "skip" as Check["status"]);
const when = (iso: string | null) => (iso ? iso.replace("T", " ").replace(/\.\d+Z$|Z$/, " UTC") : null);

function verdictLine(v: PackageReport["verdict"]): string {
  if (v === "valid") return green(bold("VALID: every file is exactly as sealed, every check passed"));
  if (v === "valid_with_warnings") return yellow(bold("VALID WITH WARNINGS: the sealed files are unchanged, read the warnings"));
  if (v === "not_a_package") return red(bold("NOT A PROOFSNAP PACKAGE"));
  return red(bold("INVALID: at least one check failed"));
}

function wrap(s: string, n = 92): string[] {
  const out: string[] = [];
  let line = "";
  for (const w of s.split(/\s+/)) {
    if ((line + " " + w).trim().length > n) {
      out.push(line.trim());
      line = w;
    } else line += " " + w;
  }
  if (line.trim()) out.push(line.trim());
  return out;
}

const SHORT: Record<PackageReport["verdict"], string> = { valid: green("[VALID]"), valid_with_warnings: yellow("[WARNINGS]"), invalid: red("[INVALID]"), not_a_package: red("[NOT A PACKAGE]") };

function printPackage(r: PackageReport, verbose: boolean, indent = "") {
  const p = (s = "") => console.log(s ? indent + s : "");
  // Inside an archive, a package that passed everything gets one line; the others are shown in full.
  if (indent && r.verdict === "valid" && !verbose) {
    const by = r.timeAnchor.existedBy ? `, existed by ${when(r.timeAnchor.existedBy)} at the latest` : "";
    p(`${SHORT.valid} ${r.name}  ${dim(`${r.label}${by}`)}`);
    return;
  }
  const fact = (k: string, v: string | null | undefined) => v && p(`  ${dim(k.padEnd(12))} ${v}`);
  p(bold(r.name));
  fact("Type", r.label);
  fact("Evidence ID", r.id);
  fact("URL", r.url);
  fact("Captured", when(r.capturedAt));
  if (r.timeAnchor.existedBy) fact("Existed by", `${bold(when(r.timeAnchor.existedBy)!)} at the latest, ${dim(r.timeAnchor.existedBySource ?? "")}`);
  if (r.testMode) p(`  ${yellow("TEST PACKAGE, not issued for use as evidence")}`);
  p();
  const groups = new Map<string, Check[]>();
  for (const ch of r.checks) groups.set(ch.group, [...(groups.get(ch.group) ?? []), ch]);
  for (const [g, checks] of groups) {
    const top = worst(checks);
    if (top === "skip" && !verbose) continue;
    p(`  ${TAG[top]} ${GROUP_TITLES[g] ?? g}`);
    // By default only what needs reading: failures and warnings in full, notes by title (online steps in full).
    const shown = verbose ? checks : checks.filter((x) => x.status === "fail" || x.status === "warn" || x.status === "info");
    for (const ch of shown) {
      p(`         ${verbose ? TAG[ch.status] + " " : ""}${ch.title}`);
      const full = verbose || ch.status !== "info" || ["bitcoin", "issuance", "container"].includes(g);
      if (ch.detail && full) for (const line of wrap(ch.detail)) p(`           ${dim(line)}`);
    }
  }
  const files = r.files.filter((f) => verbose || ["mismatch", "missing", "unlisted"].includes(f.status));
  if (files.length) {
    p();
    p(bold("  Files"));
    for (const f of files) {
      const st = f.status === "verified" ? green("ok      ") : f.status === "mismatch" ? red("CHANGED ") : f.status === "missing" ? red("MISSING ") : f.status === "unlisted" ? yellow("UNSEALED") : dim(f.status.padEnd(8));
      p(`    ${st} ${f.name}${f.note ? dim(`  (${f.note})`) : ""}`);
    }
  }
  if (r.children.length) p();
  for (const child of r.children) {
    if (verbose || child.verdict !== "valid") p();
    printPackage(child, verbose, indent + "  ");
  }
  p();
  p(indent ? `${SHORT[r.verdict]} ${r.name}` : verdictLine(r.verdict));
}

function printTimestamp(t: TimestampReport, file?: { name: string; sha256: string }) {
  console.log(bold(file ? `${file.name} + RFC 3161 timestamp` : "RFC 3161 timestamp"));
  if (file) console.log(`  ${dim("File".padEnd(12))} SHA-256 ${file.sha256}`);
  console.log(`  ${dim("Authority".padEnd(12))} ${[t.tsa.name, t.tsa.organization].filter(Boolean).join(", ") || "(unknown)"}`);
  console.log(`  ${dim("Time".padEnd(12))} ${when(t.genTime) ?? "(unknown)"}`);
  console.log(`  ${dim("Covers".padEnd(12))} ${t.imprintAlgorithm} ${t.imprint}`);
  if (t.trustAnchor.label) console.log(`  ${dim("Trust".padEnd(12))} ${t.trustAnchor.label}`);
  console.log();
  for (const [k, v] of Object.entries(t.checks)) {
    console.log(`  ${TAG[v.state]} ${k.replace(/_/g, " ")}`);
    if (v.detail && v.state !== "pass") for (const line of wrap(v.detail)) console.log(`         ${dim(line)}`);
  }
  console.log();
  console.log(t.valid ? (t.fullyVerified ? green(bold(t.qualified ? "VALID QUALIFIED TIMESTAMP" : "VALID TIMESTAMP")) : yellow(bold("VALID TIMESTAMP, see warnings"))) : red(bold("INVALID TIMESTAMP")));
}

function printOts(o: OtsReport, file?: { name: string; sha256: string }) {
  console.log(bold(file ? `${file.name} + OpenTimestamps proof` : "OpenTimestamps proof"));
  if (file) console.log(`  ${dim("File".padEnd(12))} SHA-256 ${file.sha256}`);
  console.log(`  ${dim("Covers".padEnd(12))} ${o.fileHashOp} ${o.fileDigest}`);
  if (o.error) console.log(`  ${TAG.fail} ${o.error}`);
  for (const b of o.bitcoin) console.log(`  ${b.verified ? TAG.pass : TAG.info} Bitcoin block ${b.height}${b.blockTime ? ` (${when(b.blockTime)})` : ""}: ${b.detail}`);
  if (o.status === "pending") console.log(`  ${TAG.info} pending at ${o.pendingCalendars.join(", ")}`);
  for (const n of o.notes) console.log(`         ${dim(n)}`);
  console.log();
  const first = o.bitcoin.find((b) => b.verified);
  console.log(first ? green(bold(`VALID: existed no later than ${when(first.blockTime)}`)) : o.valid ? yellow(bold(`VALID PROOF, not yet confirmed in Bitcoin (${o.status})`)) : red(bold("INVALID PROOF")));
}

// ---------------------------------------------------------------- input
/** Reads a whole file, also above the 2 GB limit of readFileSync. */
function readAll(path: string): Uint8Array {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    const out = new Uint8Array(size);
    for (let o = 0; o < size; ) {
      const n = readSync(fd, out, o, Math.min(size - o, 1 << 30), o);
      if (!n) throw new Error(`${path} changed while it was being read`);
      o += n;
    }
    return out;
  } finally {
    closeSync(fd);
  }
}

function folderEntries(root: string): SourceEntry[] {
  const out: SourceEntry[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.push({ name: relative(root, p).split(sep).join("/"), size: statSync(p).size, read: async () => readAll(p) });
    }
  };
  walk(root);
  return out;
}

interface Args {
  paths: string[];
  json: boolean;
  verbose: boolean;
  offline: boolean;
  roots?: string;
}

function usage(err?: string): never {
  if (err) console.error(`Error: ${err}\n`);
  (err ? console.error : console.log)(HELP);
  process.exit(err ? 2 : 0);
}

function parseArgs(argv: string[]): Args {
  const a: Args = { paths: [], json: false, verbose: false, offline: false };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === "--json") a.json = true;
    else if (x === "--verbose" || x === "-v") a.verbose = true;
    else if (x === "--offline") a.offline = true;
    else if (x === "--no-color") continue;
    else if (x === "--roots") a.roots = argv[++i] ?? usage("--roots needs a file");
    else if (x === "--help" || x === "-h") usage();
    else if (x === "--version") {
      console.log(VERIFIER_VERSION);
      process.exit(0);
    } else if (x.startsWith("-")) usage(`unknown option ${x}`);
    else a.paths.push(x);
  }
  if (!a.paths.length) usage("give a ProofSnap ZIP, an unzipped package folder, or a file with its timestamp");
  return a;
}

const ZIP_MAGIC = (b: Uint8Array) => b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05);

async function main(): Promise<number> {
  const a = parseArgs(process.argv.slice(2));
  const roots = a.roots ? new TextDecoder().decode(readAll(a.roots)) : undefined;
  const fetch = a.offline ? undefined : globalThis.fetch;
  const out = (json: unknown, human: () => void) => (a.json ? console.log(JSON.stringify(json, null, 2)) : human());
  if (!a.json) console.log(dim(`ProofSnap Verifier ${VERIFIER_VERSION}\n`));

  const lower = (p: string) => p.toLowerCase();
  const tsr = a.paths.find((p) => /\.(tsr|tst)$/.test(lower(p)));
  const ots = a.paths.filter((p) => lower(p).endsWith(".ots"));
  const isDir = (p: string) => statSync(p).isDirectory();
  const target = a.paths.find((p) => p !== tsr && !ots.includes(p) && (isDir(p) || lower(p).endsWith(".zip") || ZIP_MAGIC(readHead(p))));

  if (target) {
    const others = a.paths.filter((p) => p !== target && !ots.includes(p));
    const opts = {
      online: !a.offline,
      extraRootsPem: roots,
      originals: others.map((p) => ({ name: basename(p), bytes: readAll(p) })),
      upgradedOts: ots.map(readAll),
      onProgress: a.json || !process.stderr.isTTY ? undefined : (m: string) => process.stderr.write(`\r\x1b[K${dim(m)}`),
    };
    const name = basename(target);
    const report = isDir(target) ? await verifyFiles(folderEntries(target), name, opts) : await verifyZip(readAll(target), name, opts);
    if (opts.onProgress) process.stderr.write("\r\x1b[K");
    out(report, () => printPackage(report, a.verbose));
    return report.verdict === "valid" ? 0 : report.verdict === "valid_with_warnings" ? 3 : 1;
  }

  const file = a.paths.find((p) => p !== tsr && !ots.includes(p));
  if (tsr && file) {
    const r = await verifyFileWithTimestamp(readAll(file), readAll(tsr), { fileName: basename(file), extraRootsPem: roots });
    out(r, () => printTimestamp(r.timestamp, { name: basename(file), sha256: r.fileSha256 }));
    return r.valid ? (r.timestamp.fullyVerified ? 0 : 3) : 1;
  }
  if (ots.length && file) {
    const r = await verifyFileWithOts(readAll(file), readAll(ots[0]), { fetch, fileName: basename(file) });
    out(r, () => printOts(r.ots, { name: basename(file), sha256: r.fileSha256 }));
    return !r.valid ? 1 : r.ots.status === "bitcoin_verified" ? 0 : 3;
  }
  if (tsr) {
    const t = await inspectTimestamp(readAll(tsr), { extraRootsPem: roots });
    out(t, () => printTimestamp(t));
    return t.valid ? (t.fullyVerified ? 0 : 3) : 1;
  }
  if (ots.length) {
    const o = await verifyOts(readAll(ots[0]), { fetch });
    out(o, () => printOts(o));
    return !o.valid ? 1 : o.status === "bitcoin_verified" ? 0 : 3;
  }
  console.error(`${file} is not a ZIP. ProofSnap evidence comes as a ZIP file; give that ZIP (or its unzipped folder).`);
  return 1;
}

function readHead(p: string): Uint8Array {
  const fd = openSync(p, "r");
  try {
    const b = new Uint8Array(4);
    readSync(fd, b, 0, 4, 0);
    return b;
  } finally {
    closeSync(fd);
  }
}

// Exit as soon as the report is written: a network connection that was cancelled but is still closing
// (an explorer that never answered) must not keep the command waiting.
const exit = (code: number) => process.stdout.write("", () => process.stderr.write("", () => process.exit(code)));
main().then(exit, (e) => {
  const err = e as NodeJS.ErrnoException;
  if (e instanceof CannotVerifyError) console.error(`Could not verify: ${e.message}`);
  else if (err?.code === "ENOENT") console.error(`File not found: ${err.path ?? ""}`);
  else console.error(`Error: ${e instanceof Error ? e.message : e}`);
  exit(2);
});

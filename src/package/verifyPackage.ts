import { fromBase64, fromHex, isHex, pemBlocks, toHex } from "../core/bytes";
import { parseSpki, sha256Hex, sha512Hex, verifyRsaSha256 } from "../core/crypto";
import { Fetcher, OtsReport, parseOts, verifyOts } from "../core/ots";
import { TimestampReport, verifyTimestamp, LtvData } from "../core/timestamp";
import { CannotVerifyError } from "../core/errors";
import { CANNOT_UNPACK, StrictZip, ZipError } from "../zip/strictZip";
import { DERIVED, Detection, detect, WEB_REQUIRED } from "./detect";
import {
  checkCustody,
  checkImageInventory,
  checkMatterCustody,
  matterMembers,
  checkRedaction,
  checkSessionTabs,
  parseJson,
} from "./custody";
import { CheckGroup, CheckStatus, computeVerdict, FileResult, KIND_LABELS, newReport, PackageReport } from "./report";
import { PackageSource, SourceEntry } from "./source";

export const VERIFIER_VERSION = "2.0.0";

export interface VerifyOptions {
  /** Allow network access: Bitcoin block headers, OTS calendar upgrades, ProofSnap issuance ledger. */
  online?: boolean;
  fetch?: Fetcher;
  /** Extra trust anchors for RFC 3161 tokens (PEM). */
  extraRootsPem?: string;
  /** Original files to compare with a hash-existence certificate (name -> bytes). */
  originals?: { name: string; bytes: Uint8Array }[];
  /** Separately delivered upgraded OTS proofs for the top-level package. */
  upgradedOts?: Uint8Array[];
  onProgress?: (message: string) => void;
}

/** Deepest nesting of ZIPs inside ZIPs that is opened (a ZIP quine or a nesting bomb would never end). */
const MAX_NESTING = 8;
const LEDGERS = ["https://api.getproofsnap.com/v1/ledger/", "https://dev-api.getproofsnap.com/v1/ledger/"];
/** Files operating systems add when a folder is zipped or browsed (Finder, Explorer). */
const OS_JUNK = (n: string) => {
  const segs = n.split("/");
  const base = segs[segs.length - 1];
  return base === ".DS_Store" || base === "Thumbs.db" || base === "desktop.ini" || base.startsWith("._") || segs.includes("__MACOSX");
};
const NESTED = (n: string) => !OS_JUNK(n) && /\.(zip|ots)$/i.test(n);

type Push = (id: string, status: CheckStatus, title: string, detail?: string) => void;

function pusher(r: PackageReport, group: CheckGroup): Push {
  return (id, status, title, detail) => r.checks.push({ id, group, status, title, detail });
}

// Online steps only ever add confirmation, so they must never stall the check: every request gets a timeout,
// a host that failed once is not asked again during the same check, all requests together get a time budget,
// and requests still running when the check ends (a slower explorer that was not needed) are cancelled.
const REQUEST_TIMEOUT_MS = 10_000;
const NETWORK_BUDGET_MS = 45_000;
const GUARDED = Symbol("guarded");

interface GuardedFetch extends Fetcher {
  [GUARDED]: true;
  cancelAll(): void;
}

function guardFetch(f: Fetcher): GuardedFetch {
  let deadline = 0;
  const down = new Set<string>();
  const running = new Set<{ ctl: AbortController; timer: ReturnType<typeof setTimeout> }>();
  const g = async (url: string, init?: RequestInit) => {
    if (!deadline) deadline = Date.now() + NETWORK_BUDGET_MS;
    const host = new URL(url).host;
    const left = deadline - Date.now();
    if (down.has(host)) throw new Error(`${host} did not answer earlier in this check`);
    if (left <= 0) throw new Error("the time allowed for online checks is used up");
    const ctl = new AbortController();
    // The timer also covers reading the body after the response headers arrived.
    const req = { ctl, timer: setTimeout(() => ctl.abort(new Error(`${host} did not answer in time`)), Math.min(REQUEST_TIMEOUT_MS, left)) };
    running.add(req);
    try {
      const res = await f(url, { ...init, signal: ctl.signal });
      if (res.status === 429 || res.status >= 500) down.add(host);
      return res;
    } catch (e) {
      down.add(host);
      throw e;
    }
  };
  const cancelAll = () => {
    for (const { ctl, timer } of running) {
      clearTimeout(timer);
      ctl.abort(new Error("check finished"));
    }
    running.clear();
  };
  return Object.assign(g, { [GUARDED]: true as const, cancelAll });
}

/** Turns anything thrown into either an "invalid archive" report or a CannotVerifyError. */
function failure(e: unknown, name: string): PackageReport {
  if (e instanceof CannotVerifyError) throw e;
  if (e instanceof ZipError && !CANNOT_UNPACK.has(e.code)) {
    const r = newReport(name, VERIFIER_VERSION);
    // Entries are decompressed and CRC-checked when read, so a corrupt entry surfaces here too.
    pusher(r, "structure")(`zip:${e.code}`, "fail", "ZIP archive is well formed and unambiguous", e.message);
    r.verdict = e.code === "not_zip" ? "not_a_package" : "invalid";
    return r;
  }
  const msg = e instanceof Error ? e.message : String(e);
  if (e instanceof ZipError) throw new CannotVerifyError(`${name}: ${msg}`);
  if (e instanceof RangeError) throw new CannotVerifyError(`${name} is too large to check here (${msg}); try the command line, npx proofsnap-verify`);
  throw new CannotVerifyError(`${name}: the verifier could not finish (${msg})`);
}

/**
 * Verifies a ZIP given as bytes. Never reports a package as invalid because of the environment: when the check
 * cannot run here (unsupported runtime, a ZIP feature or size it cannot unpack) it throws CannotVerifyError.
 */
export async function verifyZip(bytes: Uint8Array, name = "package.zip", opts: VerifyOptions = {}): Promise<PackageReport> {
  let src: PackageSource;
  try {
    src = PackageSource.fromZip(StrictZip.open(bytes));
  } catch (e) {
    return failure(e, name);
  }
  return verifySource(src, name, opts);
}

/** Verifies an extracted package folder given as a list of files. Same contract as verifyZip. */
export async function verifyFiles(entries: SourceEntry[], name: string, opts: VerifyOptions = {}): Promise<PackageReport> {
  let src: PackageSource;
  try {
    src = new PackageSource("folder", entries.filter((e) => e.name && !e.name.endsWith("/")));
  } catch (e) {
    return failure(e, name);
  }
  return verifySource(src, name, opts);
}

/** Verifies any package source (ZIP or extracted folder). Same contract as verifyZip. */
export async function verifySource(src: PackageSource, name: string, opts: VerifyOptions = {}, extra: { upgradedOts?: Uint8Array[]; depth?: number } = {}): Promise<PackageReport> {
  let own: GuardedFetch | null = null;
  let fetch: Fetcher | undefined;
  if (opts.online) {
    const f = opts.fetch ?? ((globalThis as { fetch?: Fetcher }).fetch?.bind(globalThis) as Fetcher | undefined);
    fetch = !f || (f as Partial<GuardedFetch>)[GUARDED] ? f : (own = guardFetch(f));
  }
  try {
    return await route(src, name, { ...opts, fetch }, extra);
  } catch (e) {
    return failure(e, name);
  } finally {
    own?.cancelAll();
  }
}

async function route(src: PackageSource, name: string, opts: VerifyOptions, extra: { upgradedOts?: Uint8Array[]; depth?: number }): Promise<PackageReport> {
  const files = src.files();
  const nested = files.some(NESTED);
  if (src.has("manifest.json")) {
    const r = await verifySealed(src, name, opts, extra);
    // A manifest.json that is not ProofSnap's next to evidence packages: check it as a container.
    if (r.verdict !== "not_a_package" || !nested) return r;
  }
  if (src.has("matter.json") && src.has("custody_log.json")) return verifyContainer(src, name, opts, "matter_export", extra.depth ?? 0);

  // A package or matter export re-zipped after extraction: everything sits in one folder (Finder adds __MACOSX).
  const real = files.filter((f) => !OS_JUNK(f));
  const tops = new Set(real.map((f) => f.split("/")[0]));
  if (tops.size === 1 && real.every((f) => f.includes("/"))) {
    const top = [...tops][0];
    const inner = src.sub(`${top}/`);
    if (inner.has("manifest.json") || inner.has("matter.json")) {
      const rep = await route(inner, name, opts, extra);
      rep.checks.unshift({ id: "rezipped", group: "structure", status: "info", title: "Package sits inside a folder", detail: `files are under ${top}/ (re-zipped after extraction); verified from there` });
      return rep;
    }
  }
  if (nested) return verifyContainer(src, name, opts, src.has("captures.csv") ? "capture_export" : "container", extra.depth ?? 0);
  const r = newReport(name, VERIFIER_VERSION);
  pusher(r, "structure")("no_manifest", "fail", "Archive contains a ProofSnap manifest.json", "no manifest.json and no evidence packages inside");
  r.verdict = "not_a_package";
  return r;
}

// ---------------------------------------------------------------------------
// Sealed package
// ---------------------------------------------------------------------------

async function verifySealed(src: PackageSource, name: string, opts: VerifyOptions, extra: { upgradedOts?: Uint8Array[] }): Promise<PackageReport> {
  const r = newReport(name, VERIFIER_VERSION);
  const progress = opts.onProgress ?? (() => {});
  const fetch = opts.fetch;
  const S = pusher(r, "structure");

  if (src.type === "zip") {
    S("zip", "pass", "ZIP archive is well formed and unambiguous", "single central directory, no duplicate or unsafe names, every entry CRC-checked on read");
  }
  for (const w of src.notes) S("zip_note", "info", "ZIP structure", w);

  // 1. manifest
  progress("Reading manifest");
  const manifestBytes = await src.read("manifest.json");
  r.manifestSha256 = await sha256Hex(manifestBytes);
  const mj = parseJson(manifestBytes);
  if (mj.error) {
    S("manifest", "fail", "manifest.json is readable", mj.error);
    return finish(r);
  }
  const metadata = src.has("metadata.json") ? parseJson(await src.read("metadata.json")).value ?? null : null;
  const d = detect(mj.value, metadata && typeof metadata === "object" ? metadata : null);
  if (d.kind === "unknown" && !d.expected.size && !src.has("manifest.sig")) {
    // e.g. a browser extension ZIP: its manifest.json is not an evidence manifest
    S("no_manifest", "fail", "Archive contains a ProofSnap manifest.json", "manifest.json is not a ProofSnap evidence manifest and there is no manifest.sig");
    r.verdict = "not_a_package";
    return r;
  }
  r.kind = d.kind;
  r.label = KIND_LABELS[d.kind];
  r.producer = d.producer;
  r.id = d.id;
  r.url = d.url ?? (typeof metadata?.url === "string" ? metadata.url : null);
  r.capturedAt = d.capturedAt ?? (typeof metadata?.timestamp === "string" ? metadata.timestamp : null);
  r.testMode = d.testMode;
  for (const p of d.problems) S("manifest", "fail", "Manifest structure", p);
  for (const n of d.notes) S("manifest_note", "info", "Manifest", n);
  if (!d.problems.length) S("manifest", "pass", "Manifest structure recognised", `${KIND_LABELS[d.kind]}, ${d.expected.size} entries, manifest SHA-256 ${r.manifestSha256}`);

  // 2. signature
  progress("Checking signature");
  await checkSignature(src, manifestBytes, pusher(r, "signature"));

  // 3. files
  progress("Hashing files");
  await checkFiles(src, d, r);

  // 4. custody and content
  progress("Checking chain of custody");
  const C = pusher(r, "custody");
  const hashes = new Map<string, string | null>([...d.expected].map(([k, v]) => [k, v.sha256]));
  await checkCustody(src, d.id, hashes, d.url, C);
  if (d.kind === "session") await checkSessionTabs(src, d.id, C);
  await checkImageInventory(src, pusher(r, "content"));
  if (d.kind === "api_redaction") await checkRedaction(src, pusher(r, "content"));
  await checkContent(src, d, mj.value, r, opts);

  // 5. timestamps
  const anchor = d.anchor === "file_sha256" ? d.fileSha256 ?? null : r.manifestSha256;
  r.anchorSha256 = anchor;
  r.anchorSource = d.anchor === "file_sha256" ? "certified file" : "manifest.json";
  if (anchor) {
    progress("Checking timestamps");
    await checkTimestamps(src, d, r, anchor, opts, extra.upgradedOts ?? [], fetch);
  }

  // 6. issuance ledger (API packages)
  if (fetch && d.producer === "ProofSnap API" && r.manifestSha256) {
    progress("Looking up the ProofSnap issuance ledger");
    await checkLedger(r, LEDGERS, fetch);
  }

  if (d.testMode) S("test_mode", "warn", "Production package", "this is a TEST package (test_mode / is_test), not issued for use as evidence");
  return finish(r);
}

async function checkSignature(src: PackageSource, manifestBytes: Uint8Array, push: Push) {
  const T = "Manifest signature";
  if (!src.has("manifest.sig") || !src.has("publickey.pem")) {
    push("signature", "fail", T, `missing ${!src.has("manifest.sig") ? "manifest.sig" : "publickey.pem"}`);
    return;
  }
  const pem = new TextDecoder().decode(await src.read("publickey.pem"));
  const keys = pemBlocks(pem, "PUBLIC KEY");
  if (!keys.length) {
    push("signature", "fail", T, "publickey.pem holds no PUBLIC KEY block");
    return;
  }
  let bits = 0;
  try {
    const spki = parseSpki(keys[0]);
    if (spki.keyType !== "RSA") {
      push("signature", "fail", T, `unexpected key type ${spki.keyType}`);
      return;
    }
    bits = spki.keyBits ?? 0;
  } catch {
    push("signature", "fail", T, "publickey.pem is not a valid public key");
    return;
  }
  if (bits < 2048) {
    push("signature", "fail", T, `RSA key of ${bits} bits is too weak`);
    return;
  }
  let sig = await src.read("manifest.sig");
  let note = "";
  if (sig.length !== bits / 8) {
    // A few early API packages stored the signature base64-encoded.
    const txt = new TextDecoder().decode(sig).trim();
    if (/^[A-Za-z0-9+/=\s]+$/.test(txt)) {
      try {
        const dec = fromBase64(txt);
        if (dec.length === bits / 8) {
          sig = dec;
          note = " (signature stored base64-encoded, early API format)";
        }
      } catch {
        /* fall through */
      }
    }
  }
  if (sig.length !== bits / 8) {
    push("signature", "fail", T, `signature is ${sig.length} bytes, an RSA-${bits} signature has ${bits / 8}`);
    return;
  }
  const res = await verifyRsaSha256(keys[0], sig, manifestBytes);
  if (res.valid) {
    push("signature", "pass", T, `RSA-${bits} PKCS#1 v1.5 SHA-256 over the exact manifest.json bytes${note}. The key pair was generated for this package alone, so the signature proves the files have not changed since sealing; the timestamps prove when sealing happened.`);
  } else {
    push("signature", "fail", T, "signature does not verify: manifest.json was changed after sealing, or manifest.sig / publickey.pem were replaced");
  }
}

async function checkFiles(src: PackageSource, d: Detection, r: PackageReport) {
  const push = pusher(r, "files");
  const files: FileResult[] = [];
  let verified = 0;
  const mismatched: string[] = [];
  const missing: string[] = [];
  const unlisted: string[] = [];

  for (const [name, exp] of d.expected) {
    if (!src.has(name)) {
      if (exp.sha256 === null) {
        // Presence-only entries of derived files; manifests of 2026-07-30 to 2026-08-21 listed .ots even when absent.
        if (name === "manifest.json.ots" && d.otsListedOnlyWhenPresent) {
          missing.push(name);
          files.push({ name, status: "missing", note: "listed by the manifest, which marks .ots as listed only when present" });
        } else if (name !== "manifest.json.ots") {
          missing.push(name);
          files.push({ name, status: "missing" });
        }
        continue;
      }
      missing.push(name);
      files.push({ name, status: "missing", expected: exp.sha256 });
      continue;
    }
    if (exp.sha256 === null) {
      files.push({ name, status: DERIVED.has(name) ? "derived" : "presence_only", bytes: src.size(name) });
      continue;
    }
    const bytes = await src.read(name);
    const actual = await sha256Hex(bytes);
    let ok = actual === exp.sha256;
    let note: string | undefined;
    if (ok && exp.sha512 && (await sha512Hex(bytes)) !== exp.sha512) {
      ok = false;
      note = "SHA-512 differs";
    }
    if (ok && exp.bytes !== undefined && bytes.length !== exp.bytes) {
      ok = false;
      note = `size ${bytes.length} differs from ${exp.bytes}`;
    }
    if (ok) verified++;
    else mismatched.push(name);
    files.push({ name, status: ok ? "verified" : "mismatch", sha256: actual, expected: exp.sha256, bytes: bytes.length, note });
  }

  for (const name of src.files()) {
    if (d.expected.has(name)) continue;
    if (DERIVED.has(name)) {
      files.push({ name, status: "derived", bytes: src.size(name) });
      continue;
    }
    if (OS_JUNK(name)) {
      files.push({ name, status: "ignored", note: "operating system file" });
      continue;
    }
    // Single-file certification before 2026-08-21: the original is not keyed by name, only by file_sha256.
    if (d.kind === "file_certification" && d.fileSha256 && ![...d.expected.values()].some((e) => e.sha256 === d.fileSha256)) {
      const h = await sha256Hex(await src.read(name));
      if (h === d.fileSha256) {
        verified++;
        files.push({ name, status: "verified", sha256: h, expected: d.fileSha256, bytes: src.size(name), note: "certified original, matched through file_sha256" });
        continue;
      }
    }
    unlisted.push(name);
    files.push({ name, status: "unlisted", bytes: src.size(name), sha256: await sha256Hex(await src.read(name)) });
  }
  r.files = files;

  const T = "Every sealed file is present and unchanged";
  if (mismatched.length) push("files", "fail", T, `${mismatched.length} file(s) changed after sealing: ${mismatched.slice(0, 15).join(", ")}`);
  if (missing.length) push("files_missing", "fail", "No sealed file is missing", missing.slice(0, 15).join(", "));
  if (!mismatched.length && !missing.length) {
    if (verified) push("files", "pass", T, `${verified} file(s) re-hashed and matching the manifest`);
    else push("files", "fail", T, "the manifest seals no files");
  }
  if (unlisted.length) {
    push(
      "files_unlisted",
      "warn",
      "No file outside the seal",
      `${unlisted.length} file(s) are in the archive but not in the manifest, so the seal does not cover them and they must not be relied on: ${unlisted.slice(0, 15).join(", ")}`,
    );
  }
  // Single-file certification: the certified original must be covered.
  if (d.kind === "file_certification" && d.fileSha256) {
    const orig = files.find((f) => f.status === "verified" && f.sha256 === d.fileSha256);
    if (orig) push("certified_file", "pass", "The certified original is in the package and matches file_sha256", `${orig.name}, SHA-256 ${d.fileSha256}`);
    else push("certified_file", "warn", "The certified original is in the package", `no file in the package has the certified SHA-256 ${d.fileSha256}; supply the original to compare`);
  }
  // Web captures must seal their core files.
  if (["web_capture", "web_capture_legacy", "session", "api_capture"].includes(d.kind)) {
    const notSealed = WEB_REQUIRED.filter((n) => !d.expected.get(n)?.sha256 && !(n === "evidence.pdf" && d.kind === "api_capture"));
    const shot = ["screenshot.jpeg", "screenshot.png"].some((n) => d.expected.get(n)?.sha256);
    if (!shot) notSealed.push("screenshot");
    if (notSealed.length) push("core_files", "fail", "Core capture files are sealed", `not sealed: ${notSealed.join(", ")}`);
  }
}

async function checkContent(src: PackageSource, d: Detection, manifest: any, r: PackageReport, opts: VerifyOptions) {
  const push = pusher(r, "content");
  // C2PA Content Credentials in the screenshot
  const shotName = ["screenshot.jpeg", "screenshot.png"].find((n) => src.has(n));
  if (shotName === "screenshot.jpeg") {
    const head = await src.read(shotName);
    const hasC2pa = jpegHasC2pa(head);
    const c2paJson = src.has("c2pa.json");
    if (hasC2pa) {
      push("c2pa", "info", "C2PA Content Credentials embedded in the screenshot", "the screenshot carries a C2PA manifest; its own signature can be inspected with any C2PA validator (for example contentcredentials.org/verify). Its bytes are already covered by the ProofSnap manifest seal.");
    }
    if (typeof manifest?.c2pa_included === "boolean" && manifest.c2pa_included !== c2paJson) {
      push("c2pa_consistency", "warn", "C2PA flag in the manifest matches the package", `manifest says c2pa_included=${manifest.c2pa_included}, c2pa.json ${c2paJson ? "present" : "absent"}`);
    }
  }
  // Hash-existence certificate (API): zero-knowledge, compare with supplied originals
  if (d.kind === "api_certify") {
    const certified: { name: string; sha256: string }[] = [];
    if (typeof manifest.hash_sha256 === "string") certified.push({ name: manifest.label ?? "certified file", sha256: manifest.hash_sha256.toLowerCase() });
    if (Array.isArray(manifest.certified_files)) {
      for (const f of manifest.certified_files) if (f && typeof f.sha256 === "string") certified.push({ name: String(f.name ?? "file"), sha256: f.sha256.toLowerCase() });
    }
    push("certified_hashes", "info", "Certified file hashes", certified.map((c) => `${c.name}: ${c.sha256}`).join("; ") + ". The files themselves are not in the package; compare your copy with these values.");
    await compareOriginals(certified, opts, push);
  }
  if (d.kind === "file_certification" || d.kind === "file_certification_combined") {
    // Let a user confirm their own copy too.
    const certified = r.files.filter((f) => f.status === "verified" && (f.name.startsWith("files/") || f.sha256 === d.fileSha256)).map((f) => ({ name: f.name, sha256: f.sha256! }));
    if (opts.originals?.length) await compareOriginals(certified, opts, push);
  }
  if (d.kind === "api_compare" && src.has("compare.json")) {
    const c = parseJson(await src.read("compare.json")).value;
    const sources = Array.isArray(c?.sources) ? c.sources : [];
    if (sources.length) {
      push("compare_sources", "info", "Compared captures", sources.map((s: any) => `${s.capture_id ?? s.id ?? "?"} (manifest SHA-256 ${s.manifest_sha256 ?? "?"})`).join("; "));
    }
  }
  if (src.has("rule_902_certification.pdf")) {
    push("rule902", "info", "FRE 902(13)/(14) declaration template", "rule_902_certification.pdf is a template; it becomes a declaration only once a qualified person fills it in and signs it");
  }
}

async function compareOriginals(certified: { name: string; sha256: string }[], opts: VerifyOptions, push: Push) {
  for (const o of opts.originals ?? []) {
    const h = await sha256Hex(o.bytes);
    const hit = certified.find((c) => c.sha256 === h);
    if (hit) push(`original:${o.name}`, "pass", `Your file ${o.name} is the certified file`, `SHA-256 ${h} = ${hit.name}`);
    else push(`original:${o.name}`, "fail", `Your file ${o.name} is the certified file`, `SHA-256 ${h} matches none of the certified hashes`);
  }
}

function jpegHasC2pa(b: Uint8Array): boolean {
  if (b[0] !== 0xff || b[1] !== 0xd8) return false;
  let p = 2;
  while (p + 4 < b.length) {
    if (b[p] !== 0xff) return false;
    const marker = b[p + 1];
    if (marker === 0xda) return false; // start of scan
    const len = (b[p + 2] << 8) | b[p + 3];
    if (marker === 0xeb) {
      const seg = b.subarray(p + 4, p + 2 + len);
      for (let i = 0; i + 4 < seg.length; i++) if (seg[i] === 0x63 && seg[i + 1] === 0x32 && seg[i + 2] === 0x70 && seg[i + 3] === 0x61) return true;
    }
    p += 2 + len;
  }
  return false;
}

async function checkTimestamps(
  src: PackageSource,
  d: Detection,
  r: PackageReport,
  anchor: string,
  opts: VerifyOptions,
  upgraded: Uint8Array[],
  fetch: Fetcher | undefined,
) {
  const B = pusher(r, "bitcoin");
  const E = pusher(r, "eidas");
  const anchorLabel = d.anchor === "file_sha256" ? "the certified file" : "manifest.json";

  // ---- OpenTimestamps
  const extraProofs = [...upgraded, ...(opts.upgradedOts ?? [])];
  if (src.has("manifest.json.upgraded.ots")) extraProofs.push(await src.read("manifest.json.upgraded.ots"));
  if (src.has("manifest.json.ots") || extraProofs.length) {
    const main = src.has("manifest.json.ots") ? await src.read("manifest.json.ots") : extraProofs.shift()!;
    const ots = await verifyOts(main, { expectedDigest: anchor, fetch, extraProofs });
    r.ots = ots;
    applyOts(r, ots, anchorLabel, B, !!fetch);
  } else {
    r.timeAnchor.otsStatus = "absent";
    if (d.otsListedOnlyWhenPresent && d.expected.has("manifest.json.ots")) B("ots", "fail", "OpenTimestamps proof present", "the manifest lists manifest.json.ots but the proof was removed");
    else if (src.has("manifest.json.tsr")) B("ots", "info", "OpenTimestamps (Bitcoin) proof", "not included in this package");
    else B("no_timestamp", "warn", "Time of sealing confirmed", "this package carries no timestamp (neither OpenTimestamps nor eIDAS), so when it was sealed cannot be confirmed independently; the seal still shows the files are unchanged since sealing");
  }

  // ---- eIDAS RFC 3161
  if (src.has("manifest.json.tsr")) {
    let ltv: LtvData | null = null;
    if (src.has("eidas_validation.json")) {
      const v = parseJson(await src.read("eidas_validation.json")).value;
      if (v && typeof v === "object") {
        const recorded = [v.manifestHashHex, v.fileHashHex, v.manifest_hash_sha256, v.summary?.manifest_hash_sha256].filter((x) => typeof x === "string").map((x: string) => x.toLowerCase());
        if (recorded.some((x) => x !== anchor)) E("eidas_ltv_binding", "fail", "eidas_validation.json belongs to this package", `it records hash ${recorded.find((x) => x !== anchor)}, the package anchor is ${anchor}`);
        ltv = { tsaCertChain: Array.isArray(v.tsaCertChain) ? v.tsaCertChain.filter((x: unknown) => typeof x === "string") : [], ocspResponse: typeof v.ocspResponse === "string" ? v.ocspResponse : null, crlResponse: typeof v.crlResponse === "string" ? v.crlResponse : null };
      } else {
        E("eidas_ltv", "warn", "eidas_validation.json is readable", "unreadable; the token is verified with its embedded certificates only");
      }
    }
    const ts = await verifyTimestamp(await src.read("manifest.json.tsr"), { expectedHash: anchor, ltv, extraRootsPem: opts.extraRootsPem });
    r.eidas = ts;
    applyEidas(r, ts, anchorLabel, E);
    // Time consistency
    if (ts.genTime) {
      const g = Date.parse(ts.genTime);
      const cap = r.capturedAt ? Date.parse(r.capturedAt) : NaN;
      if (!isNaN(cap) && g < cap - 5 * 60_000) E("eidas_time_order", "warn", "Qualified timestamp follows the capture", `genTime ${ts.genTime} is before the recorded capture time ${r.capturedAt}`);
      const sealed = d.sealedAt ? Date.parse(d.sealedAt) : NaN;
      if (!isNaN(sealed) && Math.abs(g - sealed) > 300_000) E("eidas_seal_time", "warn", "Qualified timestamp matches the sealing time", `genTime ${ts.genTime} differs from sealed_at ${d.sealedAt} by more than 5 minutes`);
    }
  } else if (d.eidasRequested) {
    E("eidas", "fail", "Qualified eIDAS timestamp present", "the manifest records that a qualified timestamp was obtained (eidas_requested), but manifest.json.tsr is missing");
  } else if (src.has("eidas_validation.json")) {
    E("eidas", "warn", "Qualified eIDAS timestamp present", "eidas_validation.json is present without manifest.json.tsr");
  }

  setExistedBy(r);
  if (r.capturedAt && r.ots?.bitcoin?.some((b) => b.verified && b.blockTime && Date.parse(b.blockTime) < Date.parse(r.capturedAt!) - 2 * 3600_000)) {
    B("bitcoin_time_order", "warn", "Bitcoin anchor follows the capture", "a verified Bitcoin block is more than two hours older than the recorded capture time");
  }
}

/** Earliest independently verified point in time by which the sealed content existed. */
function setExistedBy(r: PackageReport) {
  const cands: { t: string; s: string }[] = [];
  if (r.eidas?.valid && r.eidas.genTime) cands.push({ t: r.eidas.genTime, s: `qualified eIDAS timestamp (${r.eidas.tsa.name ?? "TSA"})` });
  for (const b of r.ots?.bitcoin ?? []) if (b.verified && b.blockTime) cands.push({ t: b.blockTime, s: `Bitcoin block ${b.height}` });
  cands.sort((a, b) => a.t.localeCompare(b.t));
  if (cands.length) {
    r.timeAnchor.existedBy = cands[0].t;
    r.timeAnchor.existedBySource = cands[0].s;
  }
}

function applyOts(r: PackageReport, ots: OtsReport, anchorLabel: string, B: Push, online: boolean) {
  r.timeAnchor.otsStatus = ots.status;
  r.timeAnchor.bitcoin = ots.bitcoin.map((b) => ({ height: b.height, blockTime: b.blockTime, verified: b.verified }));
  const T = "OpenTimestamps proof anchors the seal in Bitcoin";
  if (!ots.valid) {
    B("ots", "fail", T, ots.error ?? "proof invalid");
    return;
  }
  B("ots_digest", "pass", `OpenTimestamps proof covers ${anchorLabel}`, `SHA-256 ${ots.fileDigest}`);
  if (ots.status === "bitcoin_verified") {
    const first = ots.bitcoin.filter((b) => b.verified).sort((a, b) => a.height - b.height)[0];
    B("ots", "pass", T, `existed no later than ${first.blockTime} (block ${first.height}); ${first.detail}${ots.upgradedOnline ? ". The proof was completed from the calendar servers during this check" : ""}`);
  } else if (ots.status === "bitcoin_unconfirmed") {
    // Unconfirmed only means no explorer was asked or none answered: a missing confirmation, not a problem.
    const heights = ots.bitcoin.map((b) => b.height).join(", ");
    B("ots", "info", T, `Bitcoin attestation at block ${heights}, not confirmed against the blockchain: ${online ? "no block explorer could be reached, try again later" : "run with network access to confirm it"}`);
  } else if (online && !ots.networkFailed) {
    B("ots", "warn", T, `still pending at ${ots.pendingCalendars.join(", ")}; Bitcoin confirmation usually takes a few hours`);
  } else {
    B("ots", "info", T, `pending attestation from ${ots.pendingCalendars.join(", ")}; ${online ? "the calendars could not be reached to complete it, try again later" : "run with network access to complete it and confirm it against Bitcoin"}`);
  }
  for (const n of ots.notes.filter((x) => x.includes("upgraded proof"))) B("ots_note", "info", "OpenTimestamps", n);
}

function applyEidas(r: PackageReport, ts: TimestampReport, anchorLabel: string, E: Push) {
  r.timeAnchor.eidas = { genTime: ts.genTime, tsa: ts.tsa.name, qualified: ts.qualified, valid: ts.valid };
  const label: Record<string, string> = {
    structure: "Timestamp token is readable",
    response_status: "TSA granted the timestamp",
    message_imprint: `Timestamp covers ${anchorLabel}`,
    content_type: "Token content type is TSTInfo",
    message_digest: "Token content is exactly what the TSA signed",
    signature: "TSA signature is valid",
    signing_certificate: "Token names the TSA certificate that signed it",
    tsa_profile: "Signer is a time-stamping certificate valid at the time of stamping",
    chain: "Certificate chain is valid at the time of stamping",
    trust: "TSA is trusted (EU Trusted List / pinned root)",
    revocation: "TSA certificate was not revoked",
  };
  for (const [k, v] of Object.entries(ts.checks)) {
    const status: CheckStatus = v.state === "pass" ? "pass" : v.state === "fail" ? "fail" : v.state === "warn" ? "warn" : "skip";
    E(`eidas:${k}`, status, label[k] ?? k, v.detail);
  }
  if (ts.valid && ts.trustAnchor.kind === "none") {
    // Inside a ProofSnap package the token must come from a trusted authority; a self-made TSA proves nothing.
    E("eidas", "fail", "Timestamp comes from a trusted authority", "the token's certificate chain reaches neither the EU Trusted List nor a pinned root, so anyone could have produced it");
  } else if (ts.valid) {
    E(
      "eidas",
      ts.fullyVerified ? "pass" : "warn",
      ts.qualified ? "Qualified electronic timestamp (eIDAS)" : "RFC 3161 timestamp",
      `${ts.genTime} by ${ts.tsa.name ?? "TSA"}${ts.tsa.organization ? `, ${ts.tsa.organization}` : ""}${ts.qualified ? ", qualified at that time per the EU Trusted List" : ""}`,
    );
  }
}

async function lookupLedger(base: string, hash: string, fetch: Fetcher): Promise<{ issued?: boolean; issued_at?: string; type?: string } | null> {
  const res = await fetch(base + hash, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) return null;
  return (await res.json()) as { issued?: boolean; issued_at?: string; type?: string };
}

async function checkLedger(r: PackageReport, bases: string[], fetch: Fetcher) {
  const push = pusher(r, "issuance");
  const T = "ProofSnap issued this exact package";
  try {
    for (const [i, base] of bases.entries()) {
      const j = await lookupLedger(base, r.manifestSha256!, fetch);
      if (j?.issued) {
        const env = i === 0 ? "the issuance ledger" : "the ProofSnap development ledger (packages issued before the production launch on 2026-10-16 or for testing)";
        push("ledger", "pass", T, `${env} records manifest ${r.manifestSha256} (${j.type ?? "package"}) issued at ${j.issued_at}`);
        return;
      }
    }
    // Absence is not evidence of forgery: packages from earlier infrastructure predate the ledger.
    push("ledger", "info", "ProofSnap issuance ledger", "no ledger record for this manifest; packages issued before the ledger existed are not listed. The seal and timestamps above are what prove integrity.");
  } catch (e) {
    push("ledger", "info", "ProofSnap issuance ledger", `not reachable: ${e instanceof Error ? e.message : e}`);
  }
}

function finish(r: PackageReport): PackageReport {
  r.verdict = computeVerdict(r);
  return r;
}

// ---------------------------------------------------------------------------
// Containers: delivery ZIPs, matter exports, capture exports
// ---------------------------------------------------------------------------

async function verifyContainer(src: PackageSource, name: string, opts: VerifyOptions, kind: "matter_export" | "capture_export" | "container", depth: number): Promise<PackageReport> {
  const r = newReport(name, VERIFIER_VERSION);
  r.kind = kind;
  r.label = KIND_LABELS[kind];
  r.producer = kind === "container" ? null : "ProofSnap API";
  const push = pusher(r, "container");
  const fetch = opts.fetch;
  if (src.type === "zip") pusher(r, "structure")("zip", "pass", "ZIP archive is well formed and unambiguous", "single central directory, no duplicate or unsafe names");
  for (const w of src.notes) pusher(r, "structure")("zip_note", "info", "ZIP structure", w);

  const files = src.files();
  const zips = files.filter((f) => NESTED(f) && f.toLowerCase().endsWith(".zip"));
  const otsFiles = files.filter((f) => NESTED(f) && f.toLowerCase().endsWith(".ots"));
  const consumed = new Set<string>([...zips]);

  // Nested packages
  for (const z of zips) {
    opts.onProgress?.(`Verifying ${z}`);
    const base = z.slice(0, -4);
    const sidecar = otsFiles.find((o) => o === `${base}.upgraded.ots`);
    const upgraded: Uint8Array[] = [];
    if (sidecar) {
      upgraded.push(await src.read(sidecar));
      consumed.add(sidecar);
    }
    let child: PackageReport;
    try {
      if (depth + 1 > MAX_NESTING) throw new ZipError("nesting_too_deep", `ZIP archives nested more than ${MAX_NESTING} levels deep are not opened`);
      const inner = PackageSource.fromZip(StrictZip.open(await src.read(z)));
      child = await verifySource(inner, z, { ...opts, upgradedOts: undefined }, { upgradedOts: upgraded, depth: depth + 1 });
    } catch (e) {
      child = failure(e, z);
      if (child.verdict === "not_a_package") child.verdict = "invalid";
    }
    if (sidecar) child.checks.push({ id: "ots_sidecar", group: "bitcoin", status: "info", title: "Upgraded OpenTimestamps proof delivered next to the package", detail: sidecar });
    r.children.push(child);
  }

  // Loose .ots proofs: attach to the package whose anchor they cover
  for (const o of otsFiles) {
    if (consumed.has(o)) continue;
    consumed.add(o);
    const bytes = await src.read(o);
    let digestHex: string | null = null;
    try {
      digestHex = toHex(parseOts(bytes).fileDigest);
    } catch (e) {
      // Not part of any seal, so an unreadable extra proof is noted, not held against the packages.
      push(`ots:${o}`, "warn", `${o} is a readable OpenTimestamps proof`, `${e instanceof Error ? e.message : String(e)}; it was not used`);
      continue;
    }
    const target = r.children.find((c) => c.anchorSha256 === digestHex);
    const res = await verifyOts(bytes, { expectedDigest: digestHex, fetch });
    if (target) {
      const ok = res.valid && res.status === "bitcoin_verified";
      target.checks.push({
        id: `ots_extra:${o}`,
        group: "bitcoin",
        status: res.valid ? (ok ? "pass" : "info") : "fail",
        title: `Supplementary OpenTimestamps proof ${o}`,
        detail: ok ? `existed no later than ${res.bitcoin.find((b) => b.verified)?.blockTime}` : res.error ?? res.status,
      });
      if (ok) {
        const t = res.bitcoin.filter((b) => b.verified).sort((a, b) => a.height - b.height)[0];
        if (t.blockTime && (!target.timeAnchor.existedBy || t.blockTime < target.timeAnchor.existedBy)) {
          target.timeAnchor.existedBy = t.blockTime;
          target.timeAnchor.existedBySource = `Bitcoin block ${t.height} (${o})`;
        }
      }
      target.verdict = computeVerdict(target);
    } else {
      const v = res.bitcoin.find((b) => b.verified);
      push(
        `ots:${o}`,
        res.valid ? "info" : "fail",
        `Stand-alone OpenTimestamps proof ${o}`,
        res.valid
          ? `covers SHA-256 ${digestHex}, which matches no package in this archive (it anchors a package delivered separately)${v ? `; that content existed no later than ${v.blockTime} (Bitcoin block ${v.height})` : `; status ${res.status}`}`
          : res.error,
      );
    }
  }

  // Matter export
  if (kind === "matter_export") await checkMatter(src, r, opts, fetch, push);
  if (kind === "matter_export") for (const n of ["matter.json", "custody_log.json"]) consumed.add(n);

  // Loose files
  const loose = files.filter((f) => !consumed.has(f) && !OS_JUNK(f));
  for (const f of loose) r.files.push({ name: f, status: "ignored", bytes: src.size(f), note: "not inside a sealed package" });
  if (loose.length) {
    const derivative = kind === "matter_export" ? " Exhibits, load files and reports are derived copies; the sealed originals are the packages under captures/." : "";
    push("loose_files", "info", "Files outside any sealed package", `${loose.length} file(s) (${loose.slice(0, 8).join(", ")}${loose.length > 8 ? ", …" : ""}) are not covered by a ProofSnap seal.${derivative}`);
  }
  if (!r.children.length && kind !== "matter_export") push("children", "warn", "Container holds evidence packages", "no nested ZIP packages found");
  else if (r.children.length) {
    const bad = r.children.filter((c) => c.verdict === "invalid").length;
    push("children", bad ? "fail" : "pass", "Every evidence package inside verifies", `${r.children.length - bad} of ${r.children.length} packages valid`);
  }
  return finish(r);
}

/** Every package under captures/ must be recorded in the (verified) custody log as part of this matter. */
function checkMatterMembership(r: PackageReport, log: unknown, C: Push) {
  const members = matterMembers(log);
  const present = new Set<string>();
  for (const child of r.children) {
    const m = /^captures\/([^/]+)\.zip$/.exec(child.name);
    if (!m) continue;
    present.add(m[1]);
    if (members.has(m[1])) {
      child.checks.push({ id: "matter_member", group: "container", status: "pass", title: "Recorded as part of this matter", detail: `the matter's custody log adds ${m[1]} and does not remove it` });
    } else {
      child.checks.push({ id: "matter_member", group: "container", status: "warn", title: "Recorded as part of this matter", detail: `the matter's custody log does not list ${m[1]} as a current member; this package may have been added to the export afterwards` });
    }
    child.verdict = computeVerdict(child);
  }
  const absent = [...members].filter((id) => !present.has(id));
  if (absent.length) C("matter_members_absent", "info", "Every matter member is in the export", `${absent.length} capture(s) recorded in the custody log are not in captures/: ${absent.slice(0, 10).join(", ")}`);
}

async function checkMatter(src: PackageSource, r: PackageReport, opts: VerifyOptions, fetch: Fetcher | undefined, push: Push) {
  const matter = parseJson(await src.read("matter.json")).value;
  const log = parseJson(await src.read("custody_log.json")).value;
  if (matter?.matter_id) r.id = String(matter.matter_id);
  const C = pusher(r, "custody");
  const head = await checkMatterCustody(log, matter, C);
  if (head) checkMatterMembership(r, log, C);
  r.anchorSha256 = head;
  r.anchorSource = "custody head hash";
  const seal = matter?.seal;
  if (!seal || typeof seal !== "object" || !Object.keys(seal).length) {
    push("matter_seal", "info", "Matter seal", "the matter was exported without a seal (no timestamp over the custody head)");
    return;
  }
  const root = seal.root_hash === undefined || seal.root_hash === null ? null : String(seal.root_hash).replace(/^sha256:/, "").toLowerCase();
  if (root !== null && (typeof seal.root_hash !== "string" || !/^[0-9a-f]{64}$/.test(root))) {
    C("matter_seal_root", "fail", "Seal names the custody head it covers", `seal root_hash ${JSON.stringify(String(seal.root_hash).slice(0, 80))} is not a SHA-256`);
    return;
  }
  if (root && head && root !== head) C("matter_seal_root", "fail", "Seal covers the current custody head", `seal root ${root}, custody head ${head}`);
  const target = root ?? head;
  if (!target) {
    C("matter_seal_root", "fail", "Seal names the custody head it covers", "the matter carries a seal, but neither the seal nor the custody log gives the hash it covers");
    return;
  }
  // A seal that is present must be readable: an unusable proof is reported, not skipped.
  if (seal.ots !== undefined && seal.ots !== null) {
    if (typeof seal.ots === "string" && isHex(seal.ots)) {
      const res = await verifyOts(fromHex(seal.ots), { expectedDigest: target, fetch });
      r.ots = res;
      applyOts(r, res, "the custody head hash", pusher(r, "bitcoin"), !!fetch);
    } else {
      pusher(r, "bitcoin")("ots", "fail", "OpenTimestamps proof anchors the seal in Bitcoin", "seal.ots is not a hex-encoded OpenTimestamps proof");
    }
  }
  if (seal.eidas !== undefined && seal.eidas !== null) {
    const tsrB64 = seal.eidas?.tsr_base64;
    let tsr: Uint8Array | null = null;
    try {
      if (typeof tsrB64 === "string") tsr = fromBase64(tsrB64);
    } catch {
      tsr = null;
    }
    if (!tsr) {
      pusher(r, "eidas")("eidas", "fail", "Qualified eIDAS timestamp over the custody head", "seal.eidas carries no readable base64 timestamp token (tsr_base64)");
    } else {
      // LTV data sits in seal.eidas.validation (seal.eidas.ltv is only a flag); older seals put it in ltv.
      const ltvSrc = [seal.eidas.validation, seal.eidas.ltv].find((x) => x && typeof x === "object");
      const ltv = ltvSrc ? { tsaCertChain: Array.isArray(ltvSrc.tsaCertChain) ? ltvSrc.tsaCertChain.filter((x: unknown) => typeof x === "string") : [], ocspResponse: typeof ltvSrc.ocspResponse === "string" ? ltvSrc.ocspResponse : null, crlResponse: typeof ltvSrc.crlResponse === "string" ? ltvSrc.crlResponse : null } : null;
      const ts = await verifyTimestamp(tsr, { expectedHash: target, ltv, extraRootsPem: opts.extraRootsPem });
      r.eidas = ts;
      applyEidas(r, ts, "the custody head hash", pusher(r, "eidas"));
    }
  }
  setExistedBy(r);
}

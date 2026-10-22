// "Must not fail genuine packages": formats real tools produce, networks that misbehave,
// and environments that cannot run the check. Each case was a way a genuine package
// could end as invalid, as not a package, or with a crash.
import { test } from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyZip, verifyFiles, verifyOts, CannotVerifyError } from "../dist/index.js";
import { crc32 } from "../dist/zip/strictZip.js";
import { zip, extensionCapture, seal, combinedCertification, legacyCapture, sha256 } from "./helpers.mjs";

const offline = { online: false };
const failed = (r) => r.checks.filter((c) => c.status === "fail").map((c) => `${c.id}: ${c.detail}`);
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

/** ZIP writer with per-entry method (8 = deflate), raw name bytes and flags, as other tools write them. */
function anyZip(items, { comment = "" } = {}) {
  const locals = [];
  const central = [];
  let off = 0;
  for (const it of items) {
    const { name, data: d, method = 8, flags = 0x0800, nameBytes } = it;
    const data = Buffer.from(d);
    const nb = nameBytes ?? Buffer.from(name, "utf8");
    const body = it.body ?? (method === 8 ? deflateRawSync(data) : data);
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nb.length, 26);
    locals.push(lh, nb, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nb.length, 28);
    ch.writeUInt32LE(off, 42);
    central.push(ch, nb);
    off += 30 + nb.length + body.length;
  }
  const cd = Buffer.concat(central);
  const cb = Buffer.from(comment);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(items.length, 8);
  eocd.writeUInt16LE(items.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(off, 16);
  eocd.writeUInt16LE(cb.length, 20);
  return new Uint8Array(Buffer.concat([...locals, cd, eocd, cb]));
}
const capture = () => {
  const { payload, manifest } = extensionCapture();
  return seal(payload, manifest);
};
/** Combined certification of one original with an accented name, the manifest spelling it `manifestForm`. */
function accented(manifestForm) {
  const id = "FC-11111111-2222-3333-4444-555555555555";
  const name = "smlouva č. 1 Žluťoučký.pdf";
  const m = { evidence_id: id, schema: "proofsnap-file-manifest/2.0", files: { [name.normalize(manifestForm)]: sha256("PDF") } };
  return { name, ...seal([[`files/${name.normalize(manifestForm)}`, "PDF"]], m, { pretty: false }) };
}

// ------------------------------------------------------------ formats

test("macOS decomposed (NFD) file names match a manifest in composed form, and the other way round", async () => {
  for (const [manifestForm, zipForm] of [["NFC", "NFD"], ["NFD", "NFC"]]) {
    const p = accented(manifestForm);
    const entries = p.entries.map(([n, d]) => [n.normalize(zipForm), d]);
    const r = await verifyZip(zip(entries), "p.zip", offline);
    assert.equal(r.verdict, "valid", `${manifestForm} manifest, ${zipForm} zip: ${failed(r)}`);
  }
});

test("a package re-zipped by Finder (inside a folder, with __MACOSX and .DS_Store) verifies", async () => {
  const p = capture();
  const entries = [
    ...p.entries.map(([n, d]) => [`proofsnap_20261020/${n}`, d]),
    ["proofsnap_20261020/.DS_Store", "x"],
    ["__MACOSX/proofsnap_20261020/._manifest.json", "apple double"],
    ["__MACOSX/proofsnap_20261020/._page.html", "apple double"],
  ];
  const r = await verifyZip(zip(entries), "p.zip", offline);
  assert.equal(r.verdict, "valid", failed(r).join("; "));
  assert.ok(r.checks.some((c) => c.id === "rezipped"));
});

test("a package in a folder that also seals a .zip original is verified as that package", async () => {
  const id = "FC-11111111-2222-3333-4444-555555555555";
  const inner = zip([["a.txt", "A"]]);
  const m = { evidence_id: id, schema: "proofsnap-file-manifest/2.0", files: { "archive.zip": sha256(inner) } };
  const p = seal([["files/archive.zip", inner]], m, { pretty: false });
  const r = await verifyZip(zip(p.entries.map(([n, d]) => [`pkg/${n}`, d])), "p.zip", offline);
  assert.equal(r.kind, "file_certification_combined");
  assert.equal(r.verdict, "valid", failed(r).join("; "));
});

test("a delivery re-zipped by Finder: AppleDouble ._x.zip files are not taken for evidence packages", async () => {
  const outer = zip([
    ["delivery/a.zip", legacyCapture().bytes],
    ["__MACOSX/delivery/._a.zip", "apple double, not a zip"],
  ]);
  const r = await verifyZip(outer, "d.zip", offline);
  assert.equal(r.children.length, 1);
  assert.equal(r.verdict, "valid", JSON.stringify(r.children.map((c) => [c.name, c.verdict])));
});

test("deflate-compressed entries, a ZIP comment and a CP437 name (Windows tools) do not fail a package", async () => {
  const p = capture();
  const items = p.entries.map(([name, data]) => ({ name, data }));
  items.push({ name: "notes.txt", data: "added", flags: 0, nameBytes: Buffer.from([0x6e, 0x6f, 0x74, 0x82, 0x2e, 0x74, 0x78, 0x74]) });
  const r = await verifyZip(anyZip(items, { comment: "created by some tool" }), "p.zip", offline);
  assert.equal(r.verdict, "valid_with_warnings", failed(r).join("; "));
  assert.deepEqual(r.checks.filter((c) => c.status === "warn").map((c) => c.id), ["files_unlisted"]);
  assert.equal(r.checks.find((c) => c.id === "zip_note")?.status, "info");
});

test("damaged compressed data is an invalid archive, not an internal error", async () => {
  const p = capture();
  const items = p.entries.map(([name, data]) => ({ name, data }));
  const bad = items.findIndex((i) => i.name === "page.html");
  items[bad] = { ...items[bad], body: Buffer.from([0xff, 0xff, 0xff, 0xff]) };
  const r = await verifyZip(anyZip(items), "p.zip", offline);
  assert.equal(r.verdict, "invalid");
  assert.ok(failed(r).some((f) => f.startsWith("zip:corrupt")), failed(r).join("; "));
});

test("an extracted folder verifies, also with decomposed names and Finder files", async () => {
  const p = accented("NFC");
  const entries = [...p.entries, [".DS_Store", "x"]].map(([n, d]) => ({ name: n.normalize("NFD"), size: Buffer.from(d).length, read: async () => new Uint8Array(Buffer.from(d)) }));
  const r = await verifyFiles(entries, "folder", offline);
  assert.equal(r.verdict, "valid", failed(r).join("; "));
});

// ------------------------------------------------------------ the check cannot run here: never "invalid"

test("no DecompressionStream (old browser): CannotVerifyError, not an invalid package", async () => {
  const p = capture();
  const z = anyZip(p.entries.map(([name, data]) => ({ name, data })));
  const saved = globalThis.DecompressionStream;
  delete globalThis.DecompressionStream;
  try {
    await assert.rejects(verifyZip(z, "p.zip", offline), (e) => e instanceof CannotVerifyError && /browser/.test(e.message));
  } finally {
    globalThis.DecompressionStream = saved;
  }
});

test("Deflate64 (Windows Explorer for big files) and password-protected re-zips: CannotVerifyError", async () => {
  const p = capture();
  const d64 = anyZip(p.entries.map(([name, data]) => ({ name, data, method: name === "page.html" ? 9 : 0 })));
  await assert.rejects(verifyZip(d64, "p.zip", offline), (e) => e instanceof CannotVerifyError && /method 9/.test(e.message));
  const enc = anyZip(p.entries.map(([name, data]) => ({ name, data, method: 0, flags: 0x0801 })));
  await assert.rejects(verifyZip(enc, "p.zip", offline), (e) => e instanceof CannotVerifyError && /encrypted/.test(e.message));
});

test("a fetch that throws synchronously is absorbed like any network error", async () => {
  const p = capture();
  const r = await verifyZip(p.bytes, "p.zip", { online: true, fetch: () => { throw new RangeError("boom"); } });
  assert.equal(r.verdict, "valid");
});

// ------------------------------------------------------------ network

const varuint = (n) => { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); if (n) b |= 0x80; o.push(b); } while (n); return Buffer.from(o); };
const varbytes = (b) => Buffer.concat([varuint(b.length), b]);
const MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
const ALICE = "https://alice.btc.calendar.opentimestamps.org";
const attPending = (u) => Buffer.concat([Buffer.from([0x00]), Buffer.from("83dfe30d2ef90c8e", "hex"), varbytes(varbytes(Buffer.from(u)))]);
const attBitcoin = (h) => Buffer.concat([Buffer.from([0x00]), Buffer.from("0588960d73d71901", "hex"), varbytes(varuint(h))]);
/** digest -> append(nonce) -> sha256 -> attestation */
const proof = (hashHex, att) => new Uint8Array(Buffer.concat([MAGIC, varuint(1), Buffer.from([0x08]), Buffer.from(hashHex, "hex"), Buffer.from([0xf0]), varbytes(Buffer.alloc(16, 7)), Buffer.from([0x08]), att]));
function withOts(otsFor) {
  const { payload, manifest } = extensionCapture();
  const s = seal(payload, manifest, { ots: false });
  return zip([...s.entries, ["manifest.json.ots", otsFor(s.manifestSha256)]]);
}
/** Explorers that all report `root` as the Merkle root of block `height`. */
const explorers = (root, height = 900000) => (url) => {
  if (url.includes("blockchain.info")) return new Response(JSON.stringify({ blocks: [{ hash: "11".repeat(32), mrkl_root: root, time: 1760000000, height }] }));
  if (url.includes("/block-height/")) return new Response("11".repeat(32));
  if (url.includes("/block/")) return new Response(JSON.stringify({ merkle_root: root, timestamp: 1760000000, height }));
  return null;
};

test("offline browser or blocked network: online steps end as notes, the package stays valid", async () => {
  const z = withOts((h) => proof(h, attPending(ALICE)));
  const r = await verifyZip(z, "p.zip", { online: true, fetch: async () => { throw new TypeError("Failed to fetch"); } });
  assert.equal(r.verdict, "valid", JSON.stringify(r.checks.filter((c) => c.status !== "pass")));
  assert.equal(r.checks.find((c) => c.id === "ots").status, "info");
  const b = withOts((h) => proof(h, attBitcoin(900000)));
  const r2 = await verifyZip(b, "p.zip", { online: true, fetch: async () => { throw new TypeError("Failed to fetch"); } });
  assert.equal(r2.verdict, "valid");
});

test("a captive portal answering every request with an HTML page does not fail or warn", async () => {
  const z = withOts((h) => proof(h, attPending(ALICE)));
  const html = async () => new Response("<html>Sign in to Wi-Fi</html>", { status: 200, headers: { "content-type": "text/html" } });
  const r = await verifyZip(z, "p.zip", { online: true, fetch: html });
  assert.equal(r.verdict, "valid", JSON.stringify(r.checks.filter((c) => c.status !== "pass")));
});

test("a host that failed is not asked again within the same check (many packages, dead calendar)", async () => {
  const pkgs = [1, 2, 3].map(() => withOts((h) => proof(h, attPending(ALICE))));
  const outer = zip(pkgs.map((b, i) => [`p${i}.zip`, b]));
  const asked = [];
  const r = await verifyZip(outer, "c.zip", { online: true, fetch: async (url) => { asked.push(url); throw new TypeError("timeout"); } });
  assert.equal(r.verdict, "valid");
  assert.equal(asked.length, 1, asked.join("\n"));
});

test("every request carries a timeout, so a silent server cannot leave the check hanging", async () => {
  const z = withOts((h) => proof(h, attPending(ALICE)));
  let signal;
  const r = await verifyZip(z, "p.zip", { online: true, fetch: async (url, init) => { signal = init?.signal; throw new TypeError("x"); } });
  assert.ok(signal instanceof AbortSignal);
  assert.equal(r.verdict, "valid");
});

test("a calendar completion that Bitcoin contradicts, or that cannot be replayed, is ignored, not a failure", async () => {
  const hash = "cd".repeat(32);
  const pending = proof(hash, attPending(ALICE));
  const wrongRoot = explorers("00".repeat(32));
  const answers = [
    attBitcoin(900000), // the explorers disagree with this Merkle root
    Buffer.concat([Buffer.from([0x67]), attBitcoin(900000)]), // keccak256, not supported
  ];
  for (const answer of answers) {
    const fetch = async (url) => (url.startsWith(ALICE) ? new Response(answer) : wrongRoot(url));
    const r = await verifyOts(pending, { expectedDigest: hash, fetch });
    assert.equal(r.valid, true, r.error);
    assert.equal(r.status, "pending");
    assert.ok(r.notes.some((n) => /ignored/.test(n)), r.notes.join("; "));
  }
});

test("control: a Bitcoin attestation delivered in the proof that the explorers contradict still fails", async () => {
  const z = withOts((h) => proof(h, attBitcoin(900000)));
  const r = await verifyZip(z, "p.zip", { online: true, fetch: async (url) => explorers("00".repeat(32))(url) ?? new Response("", { status: 404 }) });
  assert.equal(r.verdict, "invalid");
  assert.equal(r.checks.find((c) => c.id === "ots").status, "fail");
});

test("an unreadable loose .ots next to packages in a delivery is a warning, not a failure", async () => {
  const outer = zip([["a.zip", legacyCapture().bytes], ["a-extra.ots", "not a proof"]]);
  const r = await verifyZip(outer, "d.zip", offline);
  assert.equal(r.verdict, "valid_with_warnings", failed(r).join("; "));
});

// ------------------------------------------------------------ CLI

const cli = (...args) => spawnSync(process.execPath, [CLI, "--no-color", ...args], { encoding: "utf8" });

test("CLI: no arguments shows help and exits 2; a missing file exits 2 with a plain message", () => {
  const none = cli();
  assert.equal(none.status, 2);
  assert.match(none.stderr, /Usage:/);
  const missing = cli("/nonexistent/package.zip");
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /File not found/);
});

test("CLI: a package, its extracted folder and a re-zipped copy all verify offline", () => {
  const dir = mkdtempSync(join(tmpdir(), "psv-"));
  try {
    const p = combinedCertification();
    writeFileSync(join(dir, "p.zip"), p.bytes);
    const folder = join(dir, "unzipped");
    for (const [n, d] of p.entries) {
      mkdirSync(join(folder, n, ".."), { recursive: true });
      writeFileSync(join(folder, n), d);
    }
    for (const target of [join(dir, "p.zip"), folder]) {
      const r = cli("--offline", target);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.match(r.stdout, /VALID: every file is exactly as sealed/);
    }
    const j = JSON.parse(cli("--offline", "--json", join(dir, "p.zip")).stdout);
    assert.equal(j.verdict, "valid");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

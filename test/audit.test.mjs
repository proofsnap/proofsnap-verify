// Regression tests for the findings of the 2026-10-22 audit.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { verifyTimestamp, verifyOts, verifyZip } from "../dist/index.js";
import { crc32 } from "../dist/zip/strictZip.js";
import { zip, extensionCapture, seal, sha256 } from "./helpers.mjs";

// ------------------------------------------------------------ revocation data recorded with a token

const rev = JSON.parse(readFileSync(new URL("./fixtures/revocation/cases.json", import.meta.url), "utf8"));
const revTsr = new Uint8Array(Buffer.from(rev.tsr, "base64"));
const withLtv = (name) => verifyTimestamp(revTsr, { expectedHash: rev.hash, ltv: rev.ltv[name], extraRootsPem: rev.root, noEutl: true });

test("revocation: a current OCSP good and a current complete CRL are accepted", async () => {
  for (const name of ["ocsp_good", "crl_good"]) {
    const t = await withLtv(name);
    assert.equal(t.valid, true, name);
    assert.equal(t.checks.revocation.state, "pass", `${name}: ${t.checks.revocation.detail}`);
  }
});

test("revocation: revoked after genTime for key compromise fails the token (OCSP reason and CRL entry reason)", async () => {
  for (const name of ["ocsp_revoked_after_key_compromise", "crl_revoked_after_key_compromise"]) {
    const t = await withLtv(name);
    assert.equal(t.valid, false, name);
    assert.equal(t.checks.revocation.state, "fail", `${name}: ${t.checks.revocation.detail}`);
  }
  const t = await withLtv("ocsp_revoked_after_no_reason");
  assert.equal(t.valid, true);
  assert.equal(t.checks.revocation.state, "warn");
});

test("revocation: a stale good status, a delta CRL, a scoped CRL and a CRL of another issuer do not count as good", async () => {
  for (const name of ["ocsp_good_stale", "crl_good_stale", "crl_delta", "crl_only_ca_certs", "crl_other_issuer", "crl_remove_from_crl"]) {
    const t = await withLtv(name);
    assert.equal(t.valid, true, name);
    assert.equal(t.fullyVerified, false, name);
    assert.equal(t.checks.revocation.state, "warn", `${name}: ${t.checks.revocation.detail}`);
    assert.equal(t.revocation.status, "unknown", name);
  }
});

// ------------------------------------------------------------ OpenTimestamps calendar requests

const varuint = (n) => { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); if (n) b |= 0x80; o.push(b); } while (n); return Buffer.from(o); };
const varbytes = (b) => Buffer.concat([varuint(b.length), b]);
const OTS_MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
/** A pending proof: file digest -> append(nonce) -> sha256 -> pending attestation of each calendar URI. */
function pendingOts(hashHex, uris) {
  const att = (u) => Buffer.concat([Buffer.from([0x00]), Buffer.from("83dfe30d2ef90c8e", "hex"), varbytes(varbytes(Buffer.from(u)))]);
  const leaves = uris.map((u, i) => (i < uris.length - 1 ? Buffer.concat([Buffer.from([0xff]), att(u)]) : att(u)));
  return new Uint8Array(Buffer.concat([OTS_MAGIC, varuint(1), Buffer.from([0x08]), Buffer.from(hashHex, "hex"), Buffer.from([0xf0]), varbytes(Buffer.alloc(16, 7)), Buffer.from([0x08]), ...leaves]));
}

test("OTS upgrade contacts only the public calendars, never a host named by a crafted proof", async () => {
  const hash = "ab".repeat(32);
  const asked = [];
  const fetch = async (url) => {
    asked.push(String(url));
    return new Response("", { status: 404 });
  };
  const r = await verifyOts(pendingOts(hash, ["http://127.0.0.1:8080/x", "https://evil.example", "https://calendar.opentimestamps.org.evil.example", "https://alice.btc.calendar.opentimestamps.org"]), { expectedDigest: hash, fetch });
  assert.equal(r.valid, true);
  assert.deepEqual(asked.map((u) => new URL(u).hostname), ["alice.btc.calendar.opentimestamps.org"]);
  assert.equal(r.notes.filter((n) => n.includes("not contacted")).length, 3);
});

// ------------------------------------------------------------ ZIP structures a streaming extractor reads differently

/** A genuine extension package as ZIP bytes. */
function genuine() {
  const { payload, manifest } = extensionCapture();
  return Buffer.from(seal(payload, manifest).bytes);
}
const refusal = async (bytes) => {
  const r = await verifyZip(new Uint8Array(bytes), "z.zip", { online: false });
  return { verdict: r.verdict, ids: r.checks.filter((c) => c.status === "fail").map((c) => c.id) };
};
/** Rebuilds a STORE archive from [name, data, opts] with optional raw bytes between entries. */
function rawZip(items, { prepend = Buffer.alloc(0) } = {}) {
  const locals = [prepend];
  const central = [];
  let off = prepend.length;
  for (const it of items) {
    if (Buffer.isBuffer(it)) {
      locals.push(it);
      off += it.length;
      continue;
    }
    const [name, d, o = {}] = it;
    const data = Buffer.from(d);
    const nb = Buffer.from(name);
    const crc = crc32(data);
    const flags = o.dd ? 0x0808 : 0x0800;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(o.localFlags ?? flags, 6);
    lh.writeUInt32LE(o.dd ? 0 : (o.localCrc ?? crc) >>> 0, 14);
    lh.writeUInt32LE(o.dd ? 0 : data.length, 18);
    lh.writeUInt32LE(o.dd ? 0 : (o.localSize ?? data.length), 22);
    lh.writeUInt16LE(nb.length, 26);
    // Data descriptor as macOS Archive Utility writes it: signature, CRC-32, sizes
    const dd = Buffer.alloc(o.dd ? 16 : 0);
    if (o.dd) {
      dd.writeUInt32LE(0x08074b50, 0);
      dd.writeUInt32LE(crc, 4);
      dd.writeUInt32LE(data.length, 8);
      dd.writeUInt32LE(data.length, 12);
    }
    locals.push(lh, nb, data, dd);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(o.madeBy ?? 0x0314, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nb.length, 28);
    ch.writeUInt32LE((o.extAttr ?? 0o100644 << 16) >>> 0, 38);
    ch.writeUInt32LE(off, 42);
    central.push(ch, nb);
    off += 30 + nb.length + data.length + dd.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  const n = items.filter((x) => !Buffer.isBuffer(x)).length;
  eocd.writeUInt16LE(n, 8);
  eocd.writeUInt16LE(n, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}
const pkgEntries = () => {
  const { payload, manifest } = extensionCapture();
  return seal(payload, manifest).entries;
};

test("zip: the genuine raw-built package verifies, also with data descriptors (control for the cases below)", async () => {
  assert.equal((await refusal(rawZip(pkgEntries()))).verdict, "valid");
  assert.equal((await refusal(rawZip(pkgEntries().map(([n, d]) => [n, d, { dd: true }])))).verdict, "valid");
});

test("zip: a local header hidden in a gap between entries, or data before the first entry, is refused", async () => {
  const e = pkgEntries();
  const hidden = rawZip([["page.html", "<p>evil</p>"]]).subarray(0, 30 + 9 + 11);
  for (const bytes of [rawZip([e[0], hidden, ...e.slice(1)]), rawZip(e, { prepend: hidden })]) {
    const r = await refusal(bytes);
    assert.equal(r.verdict, "invalid");
    assert.deepEqual(r.ids, ["zip:hidden_data"]);
  }
});

test("zip: a local header whose CRC, size or encryption flag differs from the central directory is refused", async () => {
  const e = pkgEntries();
  const at = e.findIndex(([n]) => n === "page.html");
  for (const o of [{ localCrc: 0xdeadbeef }, { localSize: 3 }, { localFlags: 0x0801 }]) {
    const items = e.map((x, i) => (i === at ? [x[0], x[1], o] : x));
    const r = await refusal(rawZip(items));
    assert.equal(r.verdict, "invalid");
    assert.deepEqual(r.ids, ["zip:bad_local_header"], JSON.stringify(o));
  }
});

test("zip: a symbolic link entry and a file used as a folder are refused", async () => {
  const e = pkgEntries();
  assert.deepEqual((await refusal(rawZip([...e, ["link", "/etc/passwd", { extAttr: 0o120777 << 16 }]]))).ids, ["zip:symlink"]);
  assert.deepEqual((await refusal(rawZip([...e, ["page.html/x.txt", "x"]]))).ids, ["zip:file_used_as_folder"]);
});

test("zip: a corrupt entry is reported as a ZIP failure, not an internal error", async () => {
  const bytes = genuine();
  const i = bytes.indexOf(Buffer.from("<html>hello</html>"));
  bytes[i + 1] ^= 0xff;
  const r = await refusal(bytes);
  assert.equal(r.verdict, "invalid");
  assert.ok(r.ids.includes("zip:crc_mismatch"), r.ids.join());
});

test("zip: archives nested deeper than the limit are not opened", async () => {
  let b = genuine();
  for (let i = 0; i < 12; i++) b = Buffer.from(zip([[`n${i}.zip`, b]]));
  const r = await verifyZip(new Uint8Array(b), "deep.zip", { online: false });
  assert.equal(r.verdict, "invalid");
  let x = r;
  let depth = 0;
  while (x.children.length) {
    x = x.children[0];
    depth++;
  }
  assert.ok(depth <= 9, `opened ${depth} levels`);
  assert.ok(x.checks.some((c) => c.status === "fail" && /nested more than/.test(c.detail ?? "")));
});

// ------------------------------------------------------------ matter export seal

const hex = (s) => createHash("sha256").update(s).digest("hex");
/** custody_log.json rows in the export's canonical form (shared/firestore.mjs canonicalCustodyPayload) and the head. */
function custodyLog(n = 3) {
  const rows = [];
  let prev = "";
  for (let seq = 0; seq < n; seq++) {
    const row = { seq, ts: `2026-10-0${seq + 1}T00:00:00.000Z`, actor_uid: "u1", actor_name: "A", actor_role: "owner", action: seq ? "capture.assigned" : "matter.created", target: `t${seq}`, prev_hash: prev };
    const canonical = JSON.stringify([row.seq, row.ts, row.actor_uid, row.action, row.target, { actor_name: "A", actor_role: "owner" }, prev]);
    prev = hex(canonical);
    rows.push({ ...row, entry_hash: prev, canonical });
  }
  return { rows, head: prev };
}
const matterZip = (seal, log = custodyLog()) =>
  zip([
    ["matter.json", JSON.stringify({ matter_id: "mat_x", status: "sealed", custody_head_hash: `sha256:${log.head}`, seal })],
    ["custody_log.json", JSON.stringify(log.rows)],
    ["README.txt", "readme"],
  ]);

test("matter seal: an OTS seal over the head verifies; an unreadable seal is reported, not skipped", async () => {
  const log = custodyLog();
  const good = await verifyZip(matterZip({ root_hash: `sha256:${log.head}`, ots: Buffer.from(pendingOts(log.head, ["https://alice.btc.calendar.opentimestamps.org"])).toString("hex") }, log), "m.zip", { online: false });
  assert.equal(good.kind, "matter_export");
  assert.equal(good.verdict, "valid", JSON.stringify(good.checks.filter((c) => c.status === "fail")));
  for (const [seal, id] of [
    [{ root_hash: `sha256:${log.head}`, ots: "not hex" }, "ots"],
    [{ root_hash: `sha256:${log.head}`, eidas: { tsr_base64: "@@@" } }, "eidas"],
    [{ root_hash: 5, ots: "00" }, "matter_seal_root"],
    [{ root_hash: "sha256:xyz" }, "matter_seal_root"],
  ]) {
    const r = await verifyZip(matterZip(seal, log), "m.zip", { online: false });
    assert.equal(r.verdict, "invalid", JSON.stringify(seal));
    assert.ok(r.checks.some((c) => c.status === "fail" && c.id === id), `${JSON.stringify(seal)}: ${r.checks.map((c) => c.id).join()}`);
    assert.ok(!r.checks.some((c) => c.id === "internal"));
  }
});

// ------------------------------------------------------------ manifest structure

test("API capture: an unhashed evidence.pdf (2026-08 packages) does not hide another manifest problem", async () => {
  const { payload, manifest } = extensionCapture();
  const m = { ...manifest, source: "ProofSnap API", capture_id: "cap_AbCdEfGhIjKlMn12" };
  delete m.test_mode;
  m.files = m.files.map((f) => (f.name === "evidence.pdf" ? { name: "evidence.pdf", sha256: null } : f));
  m.files.push({ name: "extra.txt", sha256: null });
  const r = await verifyZip(seal([...payload, ["extra.txt", "x"]], m).bytes, "p.zip", { online: false });
  assert.equal(r.kind, "api_capture");
  assert.ok(r.checks.some((c) => c.id === "manifest" && c.status === "fail" && /extra\.txt without a hash/.test(c.detail ?? "")), JSON.stringify(r.checks.filter((c) => c.group === "structure")));
  assert.ok(r.checks.some((c) => c.id === "manifest_note" && /evidence\.pdf is listed without a hash/.test(c.detail ?? "")));
});

test("combined certification: a file listed both at the root and under files/ is a manifest problem", async () => {
  const m = { evidence_id: "FC-11111111-2222-3333-4444-555555555555", schema: "proofsnap-file-manifest/2.0", "files/a.txt": sha256("other"), files: { "a.txt": sha256("A") } };
  const r = await verifyZip(seal([["files/a.txt", "A"]], m, { pretty: false }).bytes, "p.zip", { online: false });
  assert.ok(r.checks.some((c) => c.id === "manifest" && c.status === "fail" && /twice/.test(c.detail ?? "")));
  assert.equal(r.verdict, "invalid");
});

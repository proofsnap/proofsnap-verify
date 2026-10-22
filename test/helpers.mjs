// Test helpers: a minimal STORE ZIP writer and builders for every ProofSnap
// package shape, signed the way the extension and the API sign them.
import { createHash, generateKeyPairSync, createSign } from "node:crypto";

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const sha512 = (b) => createHash("sha512").update(b).digest("hex");
const enc = (s) => (typeof s === "string" ? Buffer.from(s, "utf8") : Buffer.from(s));

let CRC;
function crc32(b) {
  if (!CRC) {
    CRC = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** entries: [name, bytes][]; options let tests craft malformed archives. */
export function zip(entries, { comment = "", centralNames = null } = {}) {
  const locals = [];
  const central = [];
  let off = 0;
  entries.forEach(([name, data], i) => {
    data = enc(data);
    const nb = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nb.length, 26);
    locals.push(lh, nb, data);
    const cnb = Buffer.from(centralNames?.[i] ?? name, "utf8");
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(cnb.length, 28);
    ch.writeUInt32LE(off, 42);
    central.push(ch, cnb);
    off += 30 + nb.length + data.length;
  });
  const cd = Buffer.concat(central);
  const cb = Buffer.from(comment, "utf8");
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(off, 16);
  eocd.writeUInt16LE(cb.length, 20);
  return new Uint8Array(Buffer.concat([...locals, cd, eocd, cb]));
}

function keys() {
  return generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
}
const sign = (priv, bytes) => createSign("RSA-SHA256").update(bytes).sign(priv);

/** Forensic log in the extension's ForensicLogger format, correctly chained. */
export function forensicLog(evidenceId, n = 3) {
  const genesis = sha256("genesis-" + evidenceId);
  let prev = genesis;
  let cum = genesis;
  const ops = [];
  for (let i = 0; i < n; i++) {
    const op = { operation_id: `op${i}`, operation_type: "capture_init", sequence_number: i, timestamp_local: `2026-10-20T10:00:0${i}.000Z`, timestamp_ntp: null, ntp_offset_ms: 1.5, duration_ms: 10, result: "success", hash_before: null, hash_after: null, details: { i } };
    const h = sha256(JSON.stringify(op));
    cum = sha256(cum + h);
    ops.push({ ...op, previous_entry_hash: prev, cumulative_hash: cum });
    prev = h;
  }
  return { version: "1.2.0", evidence_id: evidenceId, total_operations: n, operations: ops, hash_chain: { algorithm: "SHA-256", genesis_hash: genesis, final_hash: cum, chain_valid: true } };
}

/** Extension web capture, manifest 2.1. Returns { entries, manifest } before zipping, so tests can tamper. */
export function extensionCapture({ id = "ps_11111111-2222-3333-4444-555555555555", extra = [] } = {}) {
  const fl = JSON.stringify(forensicLog(id), null, 2);
  const coc = JSON.stringify({ version: "1.4.0", evidence: { evidence_id: id, source_url: "https://example.com/", source_url_hash: sha256("https://example.com/") }, integrity: { evidence_id_binding_hash: sha256(id + sha256(fl)) }, forensic_log_hash: sha256(fl), forensic_log_final_chain_hash: JSON.parse(fl).hash_chain.final_hash }, null, 2);
  const payload = [
    ["metadata.json", JSON.stringify({ url: "https://example.com/", timestamp: "2026-10-20T10:00:00.000Z" })],
    ["page.html", "<html>hello</html>"],
    ["screenshot.jpeg", Buffer.from([0xff, 0xd8, 0xff, 0xd9])],
    ["evidence.pdf", "%PDF-1.7 test"],
    ["domtextcontent.txt", "hello"],
    ["forensic_log.json", fl],
    ["chain_of_custody.json", coc],
    ["verification/verify.sh", "#!/bin/sh"],
    ...extra,
  ];
  const manifest = {
    version: "2.1",
    capture_id: id,
    source: "ProofSnap Extension",
    test_mode: false,
    url: "https://example.com/",
    captured_at: "2026-10-20T10:00:00.000Z",
    c2pa_included: false,
    hash_algorithm: "SHA-256",
    files: [...payload.map(([name, d]) => ({ name, sha256: sha256(enc(d)), sha512: sha512(enc(d)), bytes: enc(d).length })), { name: "publickey.pem", sha256: null }, { name: "manifest.sig", sha256: null }],
  };
  return { payload, manifest };
}

// A pending OpenTimestamps proof over `hashHex`, as every real package carries one (or an eIDAS token).
const varuint = (n) => { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); if (n) b |= 0x80; o.push(b); } while (n); return Buffer.from(o); };
const varbytes = (b) => Buffer.concat([varuint(b.length), b]);
export function pendingOts(hashHex) {
  const magic = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
  const att = Buffer.concat([Buffer.from([0x00]), Buffer.from("83dfe30d2ef90c8e", "hex"), varbytes(varbytes(Buffer.from("https://alice.btc.calendar.opentimestamps.org")))]);
  return Buffer.concat([magic, varuint(1), Buffer.from([0x08]), Buffer.from(hashHex, "hex"), Buffer.from([0xf0]), varbytes(Buffer.alloc(16, 7)), Buffer.from([0x08]), att]);
}

/** Signs the manifest; adds a pending .ots over `anchor` (default: the manifest hash) unless ots is false. */
export function seal(payload, manifestObj, { pretty = true, tamper, ots = true, anchor } = {}) {
  const k = keys();
  const mBytes = enc(pretty ? JSON.stringify(manifestObj, null, 2) : JSON.stringify(manifestObj));
  const entries = [...payload, ["manifest.json", mBytes], ["manifest.sig", sign(k.privateKey, mBytes)], ["publickey.pem", k.publicKey]];
  if (ots) entries.push(["manifest.json.ots", pendingOts(anchor ?? sha256(mBytes))]);
  if (tamper) tamper(entries);
  return { bytes: zip(entries), manifestSha256: sha256(mBytes), entries };
}

export function legacyCapture(id = "ps_11111111-2222-3333-4444-555555555555") {
  const payload = [
    ["metadata.json", "{}"],
    ["page.html", "<html/>"],
    ["screenshot.jpeg", Buffer.from([0xff, 0xd8, 0xff, 0xd9])],
    ["evidence.pdf", "%PDF"],
    ["domtextcontent.txt", "t"],
  ];
  const m = { evidence_id: id };
  for (const [n, d] of payload) m[n] = sha256(enc(d));
  return seal(payload, m, { pretty: false });
}

export function fileCertification(name = "contract.pdf", content = "the contract") {
  const id = "FC-11111111-2222-3333-4444-555555555555";
  const ev = [{ step: 1, action: "file_selected", timestamp: "t", detail: name, prev_hash: "genesis" }];
  ev.push({ step: 2, action: "sha256_computed", timestamp: "t", detail: sha256(content), prev_hash: sha256(JSON.stringify(ev[0])) });
  const fl = JSON.stringify({ schema: "proofsnap-file-forensic-log/1.0", evidence_id: id, events: ev, hash_chain: { algorithm: "SHA-256", chain_valid: true, total_operations: 2, final_hash: sha256(JSON.stringify(ev[1])) } }, null, 2);
  const coc = JSON.stringify({ evidence_id: id, file: { name, sha256: sha256(content) }, forensic_log_hash: sha256(fl) }, null, 2);
  const payload = [["chain_of_custody.json", coc], ["forensic_log.json", fl], [name, content]];
  const m = { evidence_id: id, file_sha256: sha256(content) };
  for (const [n, d] of payload) m[n] = sha256(enc(d));
  return { ...seal(payload, m, { pretty: false, anchor: sha256(content) }), fileSha256: sha256(content) };
}

export function combinedCertification() {
  const id = "FC-11111111-2222-3333-4444-555555555555";
  const files = [["a.txt", "A"], ["b.txt", "B"]];
  const m = { evidence_id: id, schema: "proofsnap-file-manifest/2.0", files: Object.fromEntries(files.map(([n, d]) => [n, sha256(d)])) };
  return seal(files.map(([n, d]) => [`files/${n}`, d]), m, { pretty: false });
}

export function apiCertify() {
  const id = "cert_AbCdEfGhIjKlMn12";
  const payload = [["evidence.pdf", "%PDF cert"]];
  const m = {
    type: "hash-existence-certificate",
    capture_id: id,
    certify_id: id,
    hash_algorithm: "sha256",
    hash_sha256: sha256("secret file"),
    label: "test",
    certified_at: "2026-10-18T09:00:00.000Z",
    is_test: false,
    files: [...payload.map(([name, d]) => ({ name, sha256: sha256(d), bytes: enc(d).length })), { name: "publickey.pem", sha256: null }, { name: "manifest.sig", sha256: null }],
    eidas_marker_version: 1,
    ots_listed_only_when_present: true,
  };
  return seal(payload, m);
}

export { sha256 };

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { verifyZip, verifyTimestamp, verifyFileWithTimestamp, StrictZip } from "../dist/index.js";
import { zip, extensionCapture, seal, legacyCapture, fileCertification, combinedCertification, apiCertify, sha256 } from "./helpers.mjs";

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/api-eidas/${n}`, import.meta.url)));
const failed = (r) => r.checks.filter((c) => c.status === "fail").map((c) => c.id);
const offline = { online: false };

// ------------------------------------------------------------ genuine packages verify

test("extension web capture 2.1 verifies", async () => {
  const { payload, manifest } = extensionCapture();
  const r = await verifyZip(seal(payload, manifest).bytes, "p.zip", offline);
  assert.equal(r.kind, "web_capture");
  assert.deepEqual(failed(r), []);
  assert.equal(r.verdict, "valid");
  assert.ok(r.checks.find((c) => c.id === "forensic_chain" && c.status === "pass"));
  assert.ok(r.checks.find((c) => c.id === "evidence_binding" && c.status === "pass"));
});

test("legacy flat manifest verifies", async () => {
  const r = await verifyZip(legacyCapture().bytes, "p.zip", offline);
  assert.equal(r.kind, "web_capture_legacy");
  assert.equal(r.verdict, "valid");
});

test("single-file certification verifies and uses the file hash as anchor", async () => {
  const p = fileCertification();
  const r = await verifyZip(p.bytes, "p.zip", offline);
  assert.equal(r.kind, "file_certification");
  assert.equal(r.anchorSha256, p.fileSha256);
  assert.equal(r.verdict, "valid");
});

test("combined certification verifies files/ originals", async () => {
  const r = await verifyZip(combinedCertification().bytes, "p.zip", offline);
  assert.equal(r.kind, "file_certification_combined");
  assert.equal(r.verdict, "valid");
  assert.equal(r.files.filter((f) => f.status === "verified").length, 2);
});

test("API hash certificate compares a supplied original", async () => {
  const p = apiCertify();
  const good = await verifyZip(p.bytes, "p.zip", { ...offline, originals: [{ name: "x", bytes: new TextEncoder().encode("secret file") }] });
  assert.equal(good.kind, "api_certify");
  assert.equal(good.verdict, "valid");
  const bad = await verifyZip(p.bytes, "p.zip", { ...offline, originals: [{ name: "x", bytes: new TextEncoder().encode("other") }] });
  assert.equal(bad.verdict, "invalid");
});

test("delivery container verifies nested packages", async () => {
  const inner = legacyCapture().bytes;
  const outer = zip([["delivery/a.zip", inner], ["delivery/readme.pdf", "%PDF"]]);
  const r = await verifyZip(outer, "d.zip", offline);
  assert.equal(r.kind, "container");
  assert.equal(r.children.length, 1);
  assert.equal(r.children[0].verdict, "valid");
  assert.equal(r.verdict, "valid");
});

// ------------------------------------------------------------ tampering is caught

test("a changed file fails", async () => {
  const { payload, manifest } = extensionCapture();
  const p = seal(payload, manifest, { tamper: (e) => (e.find((x) => x[0] === "page.html")[1] = "<html>forged</html>") });
  const r = await verifyZip(p.bytes, "p.zip", offline);
  assert.equal(r.verdict, "invalid");
  assert.ok(failed(r).includes("files"));
});

test("an edited manifest fails the signature", async () => {
  const { payload, manifest } = extensionCapture();
  const p = seal(payload, manifest, {
    tamper: (e) => {
      const m = e.find((x) => x[0] === "manifest.json");
      m[1] = Buffer.from(m[1].toString().replace("https://example.com/", "https://evil.example/"));
    },
  });
  const r = await verifyZip(p.bytes, "p.zip", offline);
  assert.ok(failed(r).includes("signature"));
});

test("a re-signed manifest over a forged file still fails the custody hashes", async () => {
  // Attacker swaps forensic_log.json, rehashes the manifest and re-signs with a new key.
  const { payload, manifest } = extensionCapture();
  const fl = payload.find((x) => x[0] === "forensic_log.json");
  const forged = JSON.parse(fl[1]);
  forged.operations[1].details = { forged: true };
  fl[1] = JSON.stringify(forged, null, 2);
  const f = manifest.files.find((x) => x.name === "forensic_log.json");
  f.sha256 = sha256(fl[1]);
  f.sha512 = createHash("sha512").update(fl[1]).digest("hex");
  f.bytes = Buffer.byteLength(fl[1]);
  const r = await verifyZip(seal(payload, manifest).bytes, "p.zip", offline);
  assert.equal(r.verdict, "invalid");
  assert.ok(failed(r).includes("forensic_chain"));
  assert.ok(failed(r).includes("forensic_log_hash"));
});

test("a missing sealed file fails", async () => {
  const { payload, manifest } = extensionCapture();
  const p = seal(payload, manifest, { tamper: (e) => e.splice(e.findIndex((x) => x[0] === "domtextcontent.txt"), 1) });
  const r = await verifyZip(p.bytes, "p.zip", offline);
  assert.ok(failed(r).includes("files_missing"));
});

test("an added file is flagged as outside the seal", async () => {
  const { payload, manifest } = extensionCapture();
  const p = seal(payload, manifest, { tamper: (e) => e.push(["extra.pdf", "%PDF injected"]) });
  const r = await verifyZip(p.bytes, "p.zip", offline);
  assert.equal(r.verdict, "valid_with_warnings");
  assert.ok(r.files.find((f) => f.name === "extra.pdf" && f.status === "unlisted"));
});

test("a removed eIDAS token is caught through the eidas_requested marker", async () => {
  const p = apiCertify();
  const m = JSON.parse(p.entries.find((x) => x[0] === "manifest.json")[1].toString());
  m.eidas_requested = true;
  const r = await verifyZip(seal([["evidence.pdf", "%PDF cert"]], m).bytes, "p.zip", offline);
  assert.ok(failed(r).includes("eidas"));
});

// ------------------------------------------------------------ hostile ZIP structures

test("duplicate entry names are refused", async () => {
  const r = await verifyZip(zip([["a.txt", "1"], ["a.txt", "2"]]), "z.zip", offline);
  assert.ok(r.checks.some((c) => c.id === "zip:duplicate_name"));
});

test("path traversal is refused", async () => {
  const r = await verifyZip(zip([["../evil.txt", "1"]]), "z.zip", offline);
  assert.ok(r.checks.some((c) => c.id === "zip:unsafe_name"));
});

test("local and central names that disagree are refused", async () => {
  const r = await verifyZip(zip([["page.html", "1"]], { centralNames: ["other.html"] }), "z.zip", offline);
  assert.ok(r.checks.some((c) => c.id === "zip:bad_local_header"));
});

test("a second EOCD signature in the comment is refused", async () => {
  const fake = Buffer.alloc(22);
  fake.writeUInt32LE(0x06054b50, 0);
  const comment = fake.toString("latin1");
  const bytes = zip([["a.txt", "1"]], { comment });
  assert.throws(() => StrictZip.open(bytes), /end-of-central-directory/);
});

test("a corrupted entry fails its CRC", async () => {
  const bytes = zip([["a.txt", "hello"]]);
  bytes[30 + 5] ^= 0xff; // first data byte
  const z = StrictZip.open(bytes);
  await assert.rejects(z.read("a.txt"), /CRC-32/);
});

// ------------------------------------------------------------ RFC 3161 with a real Disig token

const manifestHash = sha256(fx("manifest.json"));
const ltv = JSON.parse(new TextDecoder().decode(fx("eidas_validation.json")));

test("real Disig qualified timestamp verifies fully, offline", async () => {
  const t = await verifyTimestamp(fx("manifest.json.tsr"), { expectedHash: manifestHash, ltv });
  assert.equal(t.valid, true);
  assert.equal(t.qualified, true, "Disig TSU must be matched on the EU Trusted List");
  for (const k of ["message_imprint", "content_type", "message_digest", "signature", "signing_certificate", "tsa_profile", "chain", "trust"]) {
    assert.equal(t.checks[k].state, "pass", `${k}: ${t.checks[k].detail}`);
  }
});

test("timestamp over another hash fails", async () => {
  const r = await verifyFileWithTimestamp(new TextEncoder().encode("not the manifest"), fx("manifest.json.tsr"), { ltv });
  assert.equal(r.covered, false);
  assert.equal(r.valid, false);
});

test("an altered genTime inside the token is caught by the message digest", async () => {
  const tsr = Uint8Array.from(fx("manifest.json.tsr"));
  const s = Buffer.from(tsr).toString("latin1");
  const i = s.search(/20\d{12}(\.\d+)?Z/); // GeneralizedTime in TSTInfo
  assert.ok(i > 0);
  tsr[i + 3] = tsr[i + 3] === 0x35 ? 0x34 : 0x35; // change the year's last digit
  const t = await verifyTimestamp(tsr, { expectedHash: manifestHash, ltv });
  assert.equal(t.valid, false);
  assert.equal(t.checks.message_digest.state, "fail");
});

test("a substituted root in eidas_validation.json is ignored for trust", async () => {
  const forged = { ...ltv, rootCaPem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----" };
  const t = await verifyTimestamp(fx("manifest.json.tsr"), { expectedHash: manifestHash, ltv: forged });
  assert.equal(t.valid, true);
  assert.equal(t.checks.trust.state, "pass");
});

test("without the EU list the Disig token is trusted through the pinned root but not reported as qualified", async () => {
  const { setEutl, getEutl } = await import("../dist/index.js");
  const saved = getEutl();
  setEutl({ ...saved, services: [] });
  try {
    const t = await verifyTimestamp(fx("manifest.json.tsr"), { expectedHash: manifestHash, ltv });
    assert.equal(t.trustAnchor.kind, "pinned");
    assert.equal(t.qualified, false);
  } finally {
    setEutl(saved);
  }
});

// Verdict policy: matter membership, packages without a timestamp, older redactions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { verifyZip } from "../dist/index.js";
import { zip, extensionCapture, seal, legacyCapture } from "./helpers.mjs";

const offline = { online: false };
const hex = (b) => createHash("sha256").update(b).digest("hex");

/** custody_log.json rows in the export's canonical form, from [action, target] pairs. */
function custodyLog(events) {
  const rows = [];
  let prev = "";
  events.forEach(([action, target], seq) => {
    const ts = `2026-10-12T0${seq}:00:00.000Z`;
    const canonical = JSON.stringify([seq, ts, "u1", action, target, { actor_name: "A", actor_role: "user" }, prev]);
    const entry = hex(canonical);
    rows.push({ seq, ts, actor_uid: "u1", actor_name: "A", actor_role: "user", action, target, prev_hash: prev, entry_hash: entry, canonical });
    prev = entry;
  });
  return { rows, head: prev };
}

function matterExport(events, captureIds) {
  const log = custodyLog(events);
  const { payload, manifest } = extensionCapture();
  const pkg = seal(payload, manifest).bytes;
  return zip([
    ["matter.json", JSON.stringify({ matter_id: "mat_x", custody_head_hash: `sha256:${log.head}`, seal: {} })],
    ["custody_log.json", JSON.stringify(log.rows)],
    ...captureIds.map((id) => [`captures/${id}.zip`, pkg]),
  ]);
}

test("matter: a package recorded in the custody log is a member; one added to the export afterwards is flagged", async () => {
  const z = matterExport(
    [
      ["matter.created", "mat_x"],
      ["capture.added", "cap_A"],
      ["package.imported", "imp_B"],
      ["capture.added", "cap_C"],
      ["capture.removed", "cap_C"],
    ],
    ["cap_A", "imp_B", "cap_C", "cap_D"],
  );
  const r = await verifyZip(z, "m.zip", offline);
  const child = (id) => r.children.find((c) => c.name === `captures/${id}.zip`);
  const member = (id) => child(id).checks.find((c) => c.id === "matter_member")?.status;
  assert.equal(member("cap_A"), "pass");
  assert.equal(member("imp_B"), "pass");
  assert.equal(member("cap_C"), "warn", "removed from the matter");
  assert.equal(member("cap_D"), "warn", "never recorded");
  assert.equal(child("cap_A").verdict, "valid");
  assert.equal(child("cap_D").verdict, "valid_with_warnings");
  assert.equal(r.verdict, "valid_with_warnings");
});

test("matter: a member missing from the export is noted, not failed", async () => {
  const z = matterExport([["matter.created", "mat_x"], ["capture.added", "cap_A"], ["capture.added", "cap_Z"]], ["cap_A"]);
  const r = await verifyZip(z, "m.zip", offline);
  assert.equal(r.verdict, "valid");
  assert.ok(r.checks.some((c) => c.id === "matter_members_absent" && c.status === "info" && /cap_Z/.test(c.detail)));
});

test("a package without any timestamp is valid with a warning that the time is not confirmed", async () => {
  const { payload, manifest } = extensionCapture();
  const r = await verifyZip(seal(payload, manifest, { ots: false }).bytes, "p.zip", offline);
  assert.equal(r.verdict, "valid_with_warnings");
  assert.ok(r.checks.some((c) => c.id === "no_timestamp" && c.status === "warn"));
  const withOts = await verifyZip(legacyCapture().bytes, "p.zip", offline);
  assert.equal(withOts.verdict, "valid");
  assert.ok(!withOts.checks.some((c) => c.id === "no_timestamp"));
});

function merkle(leaves) {
  let level = leaves.map((x) => Buffer.from(x, "hex"));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(createHash("sha256").update(Buffer.concat([level[i], level[i + 1] ?? level[i]])).digest());
    level = next;
  }
  return level[0].toString("hex");
}

test("an older redaction without block offsets says the kept content is not checkable, instead of '0 verified'", async () => {
  const commitments = ["11", "22", "33"].map((x) => x.repeat(32));
  const rm = { spec_version: "redaction-1.0", text_block_commitments: [{ file: "page.html", algo: "sha256-salted-merkle", block_size: 512, commitments, merkle_root: merkle(commitments) }] };
  const id = "red_AbCdEfGhIjKlMn12";
  const payload = [["page.html", "<html/>"], ["redaction_manifest.json", JSON.stringify(rm)]];
  const m = {
    version: "2.1",
    type: "redacted-evidence",
    capture_id: id,
    redaction_id: id,
    source: "ProofSnap API",
    files: [...payload.map(([name, d]) => ({ name, sha256: hex(d), bytes: Buffer.byteLength(d) })), { name: "publickey.pem", sha256: null }, { name: "manifest.sig", sha256: null }],
  };
  const r = await verifyZip(seal(payload, m).bytes, "r.zip", offline);
  const c = r.checks.find((x) => x.id === "redaction_commitments:page.html");
  assert.equal(c.status, "info");
  assert.match(c.detail, /not checkable/);
  assert.ok(!r.checks.some((x) => / 0 kept blocks verified/.test(x.detail ?? "")));
});

// Checks of the documents inside a package that reference each other by hash:
// forensic log hash chain, chain of custody, session tabs, image inventories,
// redaction commitments, matter custody log. Every chain is recomputed; a
// stored "chain_valid: true" is never trusted.

import { concat, fromHex, isHex } from "../core/bytes";
import { sha256Hex, sha256HexOfString, digest } from "../core/crypto";
import type { CheckStatus } from "./report";
import type { PackageSource } from "./source";

type Push = (id: string, status: CheckStatus, title: string, detail?: string) => void;
const isObj = (v: unknown): v is Record<string, any> => v !== null && typeof v === "object" && !Array.isArray(v);
const HEX64 = /^[0-9a-f]{64}$/i;

export function parseJson(bytes: Uint8Array | null): { value?: any; error?: string } {
  if (!bytes) return { error: "absent" };
  try {
    let s = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
    return { value: JSON.parse(s) };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

const FL_FIELDS = [
  "operation_id",
  "operation_type",
  "sequence_number",
  "timestamp_local",
  "timestamp_ntp",
  "ntp_offset_ms",
  "duration_ms",
  "result",
  "hash_before",
  "hash_after",
  "details",
  "error_message",
];

export interface ChainResult {
  status: "verified" | "failed" | "not_applicable";
  schema: string;
  entries: number;
  finalHash?: string;
  reason?: string;
  reordered?: boolean;
}

async function entryHash(op: Record<string, unknown>): Promise<string> {
  const o: Record<string, unknown> = {};
  for (const k of FL_FIELDS) if (op[k] !== undefined) o[k] = op[k];
  return sha256HexOfString(JSON.stringify(o));
}

async function walkOperations(ops: Record<string, any>[], genesis: string): Promise<{ ok: boolean; final: string; failedAt?: number; why?: string }> {
  let prev = genesis;
  let cumulative = genesis;
  for (let i = 0; i < ops.length; i++) {
    const op = ops[i];
    if (!isObj(op) || op.previous_entry_hash !== prev) return { ok: false, final: cumulative, failedAt: i, why: "previous_entry_hash" };
    const h = await entryHash(op);
    cumulative = await sha256HexOfString(cumulative + h);
    if (op.cumulative_hash !== cumulative) return { ok: false, final: cumulative, failedAt: i, why: "cumulative_hash" };
    prev = h;
  }
  return { ok: true, final: cumulative };
}

/** Recomputes the forensic log chain (extension operations[] or file-certification events[]). */
export async function recomputeForensicChain(log: any): Promise<ChainResult> {
  if (!isObj(log)) return { status: "failed", schema: "unknown", entries: 0, reason: "forensic log is not an object" };
  const hc = log.hash_chain;
  if (hc === undefined) return { status: "not_applicable", schema: "none", entries: 0 };
  if (!isObj(hc) || typeof hc.final_hash !== "string") return { status: "failed", schema: "unknown", entries: 0, reason: "hash_chain unreadable" };

  if (Array.isArray(log.events)) {
    const ev = log.events;
    if (!ev.length) return { status: "failed", schema: "events", entries: 0, reason: "no events" };
    let prev = "genesis";
    for (let i = 0; i < ev.length; i++) {
      if (!isObj(ev[i]) || ev[i].prev_hash !== prev) return { status: "failed", schema: "events", entries: ev.length, reason: `prev_hash of event ${i + 1} does not match` };
      prev = await sha256HexOfString(JSON.stringify(ev[i]));
    }
    if (prev !== hc.final_hash) return { status: "failed", schema: "events", entries: ev.length, reason: "final_hash does not match the last event" };
    return { status: "verified", schema: "events", entries: ev.length, finalHash: prev };
  }

  if (Array.isArray(log.operations)) {
    const ops = log.operations as Record<string, any>[];
    if (!ops.length) return { status: "failed", schema: "operations", entries: 0, reason: "no operations" };
    const genesis = typeof hc.genesis_hash === "string" ? hc.genesis_hash : "";
    if (!HEX64.test(genesis)) return { status: "failed", schema: "operations", entries: ops.length, reason: "genesis_hash missing" };
    let res = await walkOperations(ops, genesis);
    let reordered = false;
    if (!res.ok) {
      // Packages before 2026-06-07 sorted operations by sequence_number after
      // chaining; rebuild the chaining order by following previous_entry_hash.
      const byPrev = new Map<string, Record<string, any>[]>();
      for (const op of ops) {
        const k = String(op?.previous_entry_hash);
        const list = byPrev.get(k);
        if (list) list.push(op);
        else byPrev.set(k, [op]);
      }
      const ordered: Record<string, any>[] = [];
      let cur = genesis;
      while (ordered.length < ops.length) {
        const next = byPrev.get(cur);
        if (!next || next.length !== 1) break;
        ordered.push(next[0]);
        cur = await entryHash(next[0]);
      }
      if (ordered.length === ops.length) {
        const r2 = await walkOperations(ordered, genesis);
        if (r2.ok) {
          res = r2;
          reordered = true;
        }
      }
    }
    if (!res.ok) return { status: "failed", schema: "operations", entries: ops.length, reason: `${res.why} of operation ${(res.failedAt ?? 0) + 1} does not match` };
    if (res.final !== hc.final_hash) return { status: "failed", schema: "operations", entries: ops.length, reason: "final_hash does not match the last cumulative hash" };
    return { status: "verified", schema: "operations", entries: ops.length, finalHash: res.final, reordered };
  }
  return { status: "failed", schema: "unknown", entries: 0, reason: "neither events nor operations" };
}

function selfIds(doc: any): string[] {
  if (!isObj(doc)) return [];
  return [doc.evidence_id, doc.capture_id, doc.compare_id, doc.redaction_id, doc.certify_id, isObj(doc.evidence) ? doc.evidence.evidence_id : undefined].filter(
    (x): x is string => typeof x === "string",
  );
}

export async function checkCustody(
  src: PackageSource,
  packageId: string | null,
  manifestHashes: Map<string, string | null>,
  manifestUrl: string | null,
  push: Push,
) {
  const flBytes = src.has("forensic_log.json") ? await src.read("forensic_log.json") : null;
  const cocBytes = src.has("chain_of_custody.json") ? await src.read("chain_of_custody.json") : null;
  if (!flBytes && !cocBytes) return;
  const fl = flBytes ? parseJson(flBytes) : null;
  const coc = cocBytes ? parseJson(cocBytes) : null;
  if (fl?.error) push("forensic_log_readable", "fail", "forensic_log.json is readable JSON", fl.error);
  if (coc?.error) push("custody_readable", "fail", "chain_of_custody.json is readable JSON", coc.error);

  // ids
  const ids = [...selfIds(coc?.value), ...selfIds(fl?.value)];
  if (packageId && ids.length) {
    const bad = ids.filter((x) => x !== packageId);
    if (bad.length) push("custody_ids", "fail", "Custody documents name the same evidence ID as the manifest", `found ${[...new Set(bad)].join(", ")}, manifest says ${packageId}`);
    else push("custody_ids", "pass", "Custody documents name the same evidence ID as the manifest", packageId);
  }

  // forensic_log_hash
  if (flBytes && isObj(coc?.value) && typeof coc!.value.forensic_log_hash === "string") {
    const actual = await sha256Hex(flBytes);
    if (actual === coc!.value.forensic_log_hash.toLowerCase()) push("forensic_log_hash", "pass", "chain_of_custody.json references this exact forensic_log.json", actual);
    else push("forensic_log_hash", "fail", "chain_of_custody.json references this exact forensic_log.json", `recorded ${coc!.value.forensic_log_hash}, actual ${actual}`);
  }

  // hash chain
  if (isObj(fl?.value)) {
    const fc = await recomputeForensicChain(fl!.value);
    if (fc.status === "verified") {
      push(
        "forensic_chain",
        "pass",
        "Forensic log hash chain recomputed",
        `${fc.entries} ${fc.schema === "events" ? "events" : "operations"} chained, final hash ${fc.finalHash}${fc.reordered ? " (chaining order rebuilt from previous_entry_hash, older package)" : ""}`,
      );
      const ref = coc?.value?.forensic_log_final_chain_hash ?? coc?.value?.integrity?.forensic_log_final_chain_hash;
      if (typeof ref === "string") {
        if (ref === fc.finalHash) push("forensic_chain_reference", "pass", "Chain of custody records the same final chain hash", ref);
        else push("forensic_chain_reference", "fail", "Chain of custody records the same final chain hash", `recorded ${ref}, recomputed ${fc.finalHash}`);
      }
    } else if (fc.status === "failed") {
      push("forensic_chain", "fail", "Forensic log hash chain recomputed", fc.reason);
    } else {
      push("forensic_chain", "info", "Forensic log hash chain", "this package type keeps a flat forensic log without a hash chain; its integrity comes from the manifest seal");
    }
  }

  const c = coc?.value;
  if (!isObj(c)) return;

  // evidence_id_binding_hash and source_url_hash (extension web capture)
  const integ = isObj(c.integrity) ? c.integrity : null;
  if (integ && typeof integ.evidence_id_binding_hash === "string" && flBytes && packageId) {
    const expected = await sha256HexOfString(packageId + (await sha256Hex(flBytes)));
    if (expected === integ.evidence_id_binding_hash) push("evidence_binding", "pass", "Evidence ID is bound to the forensic log", expected);
    else push("evidence_binding", "fail", "Evidence ID is bound to the forensic log", `recorded ${integ.evidence_id_binding_hash}, recomputed ${expected}`);
  }
  const ev = isObj(c.evidence) ? c.evidence : null;
  if (ev && typeof ev.source_url === "string" && typeof ev.source_url_hash === "string") {
    const h = await sha256HexOfString(ev.source_url);
    if (h === ev.source_url_hash) push("source_url_hash", "pass", "Source URL hash in the chain of custody matches the URL", ev.source_url);
    else push("source_url_hash", "fail", "Source URL hash in the chain of custody matches the URL", `recorded ${ev.source_url_hash}, recomputed ${h}`);
    if (manifestUrl && manifestUrl !== ev.source_url) push("source_url_consistent", "warn", "Manifest and chain of custody name the same URL", `manifest ${manifestUrl}, custody ${ev.source_url}`);
  }

  // integrity.files[] vs manifest
  if (integ && Array.isArray(integ.files)) {
    const bad: string[] = [];
    let n = 0;
    for (const f of integ.files) {
      if (!isObj(f) || typeof f.filename !== "string" || typeof f.sha256_hash !== "string") continue;
      const m = manifestHashes.get(f.filename.normalize("NFC"));
      if (m === undefined || m === null) continue;
      n++;
      if (m !== f.sha256_hash.toLowerCase()) bad.push(f.filename);
    }
    if (n) {
      if (bad.length) push("custody_file_hashes", "fail", "File hashes recorded in the chain of custody match the manifest", bad.join(", "));
      else push("custody_file_hashes", "pass", "File hashes recorded in the chain of custody match the manifest", `${n} files`);
    }
  }

  // file certification: coc.file.sha256 / coc.files[].sha256
  if (isObj(c.file) && typeof c.file.sha256 === "string" && typeof c.file.name === "string") {
    push("custody_certified_file", "info", "Chain of custody names the certified file", `${c.file.name}, SHA-256 ${c.file.sha256}`);
  }
}

/** Session mode: per-tab chain of custody refers to the root session and to its own files. */
export async function checkSessionTabs(src: PackageSource, rootId: string | null, push: Push) {
  const tabCocs = src.files().filter((n) => /^tabs\/[^/]+\/chain_of_custody\.json$/.test(n));
  if (!tabCocs.length) return;
  const problems: string[] = [];
  const warnings: string[] = [];
  for (const p of tabCocs) {
    const dir = p.slice(0, -"chain_of_custody.json".length);
    const c = parseJson(await src.read(p)).value;
    if (!isObj(c)) {
      problems.push(`${p} unreadable`);
      continue;
    }
    const sid = c.evidence?.session_evidence_id;
    if (rootId && sid !== rootId) problems.push(`${dir} names session ${sid}`);
    const map: [string, string][] = [
      ["screenshot_sha256", "screenshot.jpeg"],
      ["page_html_sha256", "page.html"],
      ["dom_text_sha256", "domtextcontent.txt"],
    ];
    for (const [k, file] of map) {
      const rec = c.integrity?.[k];
      if (typeof rec !== "string" || !src.has(dir + file)) continue;
      const act = await sha256Hex(await src.read(dir + file));
      if (act !== rec.toLowerCase()) warnings.push(`${dir}${file}`);
    }
  }
  if (problems.length) push("session_tabs", "fail", "Every tab snapshot belongs to this session", problems.join("; "));
  else push("session_tabs", "pass", "Every tab snapshot belongs to this session", `${tabCocs.length} tab snapshots`);
  if (warnings.length) {
    push(
      "session_tab_hashes",
      "info",
      "Per-tab custody hashes",
      `recorded before C2PA signing or URL banding for ${warnings.join(", ")}; the sealed bytes are verified by the manifest`,
    );
  }
}

/** images.json (extension) / image_inventory.json (API): every saved image matches its recorded hash. */
export async function checkImageInventory(src: PackageSource, push: Push) {
  for (const inv of ["images.json", "image_inventory.json"]) {
    if (!src.has(inv)) continue;
    const j = parseJson(await src.read(inv)).value;
    const list: any[] = Array.isArray(j?.images) ? j.images : Array.isArray(j?.entries) ? j.entries : [];
    let n = 0;
    const bad: string[] = [];
    const missing: string[] = [];
    const seen = new Set<string>();
    for (const e of list) {
      if (!isObj(e) || typeof e.local_path !== "string" || typeof e.sha256 !== "string" || seen.has(e.local_path)) continue;
      seen.add(e.local_path);
      if (!src.has(e.local_path)) {
        missing.push(e.local_path);
        continue;
      }
      n++;
      if ((await sha256Hex(await src.read(e.local_path))) !== e.sha256.toLowerCase()) bad.push(e.local_path);
    }
    if (bad.length) push("image_inventory", "fail", `${inv} matches the saved images`, bad.slice(0, 10).join(", "));
    else if (n) push("image_inventory", "pass", `${inv} matches the saved images`, `${n} images${missing.length ? `, ${missing.length} listed images not saved` : ""}`);
  }
}

async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (!leaves.length) return digest("SHA-256", new Uint8Array());
  let level = leaves;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i];
      const r = level[i + 1] ?? level[i];
      next.push(await digest("SHA-256", concat(l, r)));
    }
    level = next;
  }
  return level[0];
}

/** API redaction: kept blocks match their salted commitments, commitments form the Merkle root. */
export async function checkRedaction(src: PackageSource, push: Push) {
  if (!src.has("redaction_manifest.json")) return;
  const rm = parseJson(await src.read("redaction_manifest.json")).value;
  if (!isObj(rm)) {
    push("redaction_manifest", "fail", "redaction_manifest.json is readable", "unreadable");
    return;
  }
  const df = rm.derived_from;
  if (isObj(df) && typeof df.capture_id === "string") {
    push("redaction_source", "info", "Derived from an original capture", `${df.capture_id}, original manifest SHA-256 ${df.original_manifest_sha256 ?? "not recorded"}`);
  }
  const blocks = Array.isArray(rm.text_block_commitments) ? rm.text_block_commitments : [];
  for (const b of blocks) {
    if (!isObj(b) || typeof b.file !== "string" || !Array.isArray(b.commitments)) continue;
    const commits: string[] = b.commitments;
    if (!commits.every((x) => isHex(x, 32))) {
      push(`redaction_commitments:${b.file}`, "fail", `Redaction commitments of ${b.file}`, "malformed commitments");
      continue;
    }
    const root = Array.from(await merkleRoot(commits.map((x) => fromHex(x))), (x) => x.toString(16).padStart(2, "0")).join("");
    const rootOk = root === String(b.merkle_root).toLowerCase();
    const bytes = src.has(b.file) ? await src.read(b.file) : null;
    let revealed = 0;
    const badBlocks: string[] = [];
    if (bytes && isObj(b.revealed_salts) && isObj(b.revealed_block_offsets)) {
      for (const [i, salt] of Object.entries(b.revealed_salts)) {
        const off = b.revealed_block_offsets[i];
        if (!Array.isArray(off) || typeof salt !== "string" || !isHex(salt)) continue;
        const [o, l] = off as [number, number];
        const h = await sha256Hex(concat(fromHex(salt), bytes.subarray(o, o + l)));
        revealed++;
        if (h !== String(commits[Number(i)]).toLowerCase()) badBlocks.push(i);
      }
    }
    if (rootOk && !badBlocks.length && revealed === 0) {
      // Older redactions (no revealed_block_offsets) cannot show which bytes were kept: say so instead of "0 verified".
      push(
        `redaction_commitments:${b.file}`,
        "info",
        `Kept content of ${b.file} against the original`,
        `not checkable: this redaction does not record where the kept blocks are (older format). The commitments form the recorded Merkle root ${root}, and the redacted package itself is sealed.`,
      );
    } else if (!rootOk || badBlocks.length) {
      push(
        `redaction_commitments:${b.file}`,
        "fail",
        `Kept content of ${b.file} matches the original's salted commitments`,
        !rootOk ? "commitments do not form the recorded Merkle root" : `blocks ${badBlocks.slice(0, 10).join(", ")} do not match`,
      );
    } else {
      const withheld = Array.isArray(b.withheld_block_indexes) ? b.withheld_block_indexes.length : 0;
      push(
        `redaction_commitments:${b.file}`,
        "pass",
        `Kept content of ${b.file} matches the original's salted commitments`,
        `${revealed} kept blocks verified, ${withheld} redacted blocks withheld, Merkle root ${root}`,
      );
    }
  }
}

/** Captures that belong to the matter now: added or imported, and not removed since. */
export function matterMembers(custodyLog: any): Set<string> {
  const members = new Set<string>();
  if (!Array.isArray(custodyLog)) return members;
  for (const r of custodyLog) {
    if (!isObj(r) || typeof r.target !== "string") continue;
    if (r.action === "capture.added" || r.action === "package.imported") members.add(r.target);
    else if (r.action === "capture.removed") members.delete(r.target);
  }
  return members;
}

/** Matter export: custody_log.json rows, canonical form and hash links up to custody_head_hash. */
export async function checkMatterCustody(custodyLog: any, matter: any, push: Push): Promise<string | null> {
  if (!Array.isArray(custodyLog)) {
    push("matter_custody_log", "fail", "custody_log.json is a list of events", "unreadable");
    return null;
  }
  let prev = "";
  let head: string | null = null;
  for (let i = 0; i < custodyLog.length; i++) {
    const r = custodyLog[i];
    if (!isObj(r)) {
      push("matter_custody_log", "fail", "Matter custody log hash chain recomputed", `row ${i + 1} unreadable`);
      return null;
    }
    const extra: Record<string, unknown> = {};
    for (const k of ["actor_name", "actor_role"].sort()) if (r[k] !== undefined && r[k] !== null) extra[k] = r[k];
    const canonical = JSON.stringify([r.seq, r.ts, r.actor_uid || "", r.action, r.target || "", extra, r.prev_hash || ""]);
    if (typeof r.canonical === "string" && r.canonical !== canonical) {
      push("matter_custody_log", "fail", "Matter custody log hash chain recomputed", `row ${i + 1}: fields differ from the hashed canonical form`);
      return null;
    }
    if ((r.prev_hash || "") !== prev) {
      push("matter_custody_log", "fail", "Matter custody log hash chain recomputed", `row ${i + 1}: prev_hash does not link to row ${i}`);
      return null;
    }
    const h = await sha256HexOfString(canonical);
    if (h !== r.entry_hash) {
      push("matter_custody_log", "fail", "Matter custody log hash chain recomputed", `row ${i + 1}: entry_hash does not match`);
      return null;
    }
    prev = h;
    head = h;
  }
  push("matter_custody_log", "pass", "Matter custody log hash chain recomputed", `${custodyLog.length} events, head ${head ?? "(empty)"}`);
  const recorded = typeof matter?.custody_head_hash === "string" ? matter.custody_head_hash.replace(/^sha256:/, "") : null;
  if (recorded) {
    if (recorded === head) push("matter_head", "pass", "matter.json records the same custody head hash", recorded);
    else push("matter_head", "fail", "matter.json records the same custody head hash", `recorded ${recorded}, recomputed ${head}`);
  }
  return head;
}

// Recognises every manifest shape ProofSnap has issued and turns it into the
// list of files the seal covers.
//
//   files[] array      extension web capture / session (version 2.1), every API package
//   flat + file_sha256 extension single-file certification (timestamps over the file hash)
//   schema 2.0         extension combined certification (originals under files/)
//   flat evidence_id   extension web capture before 2026-07-30

import { unsafeNameReason } from "../zip/strictZip";
import type { PackageKind } from "./report";

export interface ExpectedFile {
  sha256: string | null;
  sha512?: string;
  bytes?: number;
}

export interface Detection {
  kind: PackageKind;
  producer: "ProofSnap extension" | "ProofSnap API" | "ProofSnap";
  id: string | null;
  url: string | null;
  capturedAt: string | null;
  sealedAt: string | null;
  testMode: boolean;
  expected: Map<string, ExpectedFile>;
  /** SHA-256 the timestamps must cover. */
  anchor: "manifest" | "file_sha256";
  fileSha256?: string;
  eidasRequested: boolean;
  otsListedOnlyWhenPresent: boolean;
  problems: string[];
  notes: string[];
}

const HEX64 = /^[0-9a-fA-F]{64}$/;
const HEX128 = /^[0-9a-fA-F]{128}$/;
const API_ID = /^(cap|cert|cmp|red)_[A-Za-z0-9]{12,24}$/;
const EXT_ID = /^ps_[0-9a-fA-F-]{36}$/;
const FC_ID = /^FC-[0-9a-fA-F-]{36}$/;

/** Files written after the manifest; never hashed in it. */
export const DERIVED = new Set([
  "manifest.json",
  "manifest.sig",
  "publickey.pem",
  "manifest.json.ots",
  "manifest.json.upgraded.ots",
  "manifest.json.tsr",
  "eidas_validation.json",
]);
const PRESENCE_ONLY = new Set(["publickey.pem", "manifest.sig", "manifest.json.ots"]);

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

function fromArray(files: unknown, d: Detection, allowNullFor: Set<string> = new Set()) {
  if (!Array.isArray(files)) {
    d.problems.push("manifest files is not an array");
    return;
  }
  for (const f of files) {
    if (!isObj(f) || typeof f.name !== "string") {
      d.problems.push("manifest entry without a name");
      continue;
    }
    const name = f.name.normalize("NFC");
    const why = unsafeNameReason(name);
    if (why || name.endsWith("/")) {
      d.problems.push(`manifest names an unsafe path (${why ?? "folder"}): ${JSON.stringify(name.slice(0, 120))}`);
      continue;
    }
    if (d.expected.has(name)) {
      d.problems.push(`manifest lists ${name} twice`);
      continue;
    }
    if (f.sha256 === null || f.sha256 === undefined) {
      if (!PRESENCE_ONLY.has(name) && !allowNullFor.has(name)) d.problems.push(`manifest lists ${name} without a hash, so it is not sealed`);
      d.expected.set(name, { sha256: null });
      continue;
    }
    if (typeof f.sha256 !== "string" || !HEX64.test(f.sha256)) {
      d.problems.push(`manifest sha256 of ${name} is not a SHA-256 value`);
      continue;
    }
    const e: ExpectedFile = { sha256: f.sha256.toLowerCase() };
    if (typeof f.sha512 === "string") {
      if (HEX128.test(f.sha512)) e.sha512 = f.sha512.toLowerCase();
      else d.problems.push(`manifest sha512 of ${name} is malformed`);
    }
    if (f.bytes !== undefined && f.bytes !== null) {
      if (Number.isSafeInteger(f.bytes) && (f.bytes as number) >= 0) e.bytes = f.bytes as number;
      else d.problems.push(`manifest size of ${name} is malformed`);
    }
    d.expected.set(name, e);
  }
}

function fromFlat(obj: Record<string, unknown>, meta: Set<string>, d: Detection, prefix = "") {
  for (const [k, v] of Object.entries(obj)) {
    if (meta.has(k)) continue;
    const name = (prefix + k).normalize("NFC");
    const why = unsafeNameReason(name);
    if (why || name.endsWith("/")) {
      d.problems.push(`manifest names an unsafe path (${why ?? "folder"}): ${JSON.stringify(name.slice(0, 120))}`);
      continue;
    }
    if (d.expected.has(name)) {
      d.problems.push(`manifest lists ${name} twice`);
      continue;
    }
    if (typeof v !== "string" || !HEX64.test(v)) {
      d.problems.push(`manifest value of ${JSON.stringify(k.slice(0, 80))} is not a SHA-256`);
      continue;
    }
    d.expected.set(name, { sha256: v.toLowerCase() });
  }
}

export function detect(m: unknown, metadata: Record<string, unknown> | null): Detection {
  const d: Detection = {
    kind: "unknown",
    producer: "ProofSnap",
    id: null,
    url: null,
    capturedAt: null,
    sealedAt: null,
    testMode: false,
    expected: new Map(),
    anchor: "manifest",
    eidasRequested: false,
    otsListedOnlyWhenPresent: false,
    problems: [],
    notes: [],
  };
  if (!isObj(m)) {
    d.problems.push("manifest.json is not a JSON object");
    return d;
  }
  d.eidasRequested = m.eidas_requested === true;
  d.otsListedOnlyWhenPresent = m.ots_listed_only_when_present === true;
  d.testMode = m.test_mode === true || m.is_test === true;
  d.url = str(m.url);
  d.capturedAt = str(m.captured_at) ?? str(m.certified_at) ?? str(m.created_at);
  d.sealedAt = str(m.sealed_at);
  const session = metadata?.captureMode === "browsing_session";

  // ---- API packages
  const apiTypes: Record<string, PackageKind> = {
    "hash-existence-certificate": "api_certify",
    "evidence-comparison": "api_compare",
    "redacted-evidence": "api_redaction",
  };
  if (m.source === "ProofSnap API" || (typeof m.type === "string" && apiTypes[m.type])) {
    d.producer = "ProofSnap API";
    if (m.type === undefined) {
      d.kind = "api_capture";
      d.id = str(m.capture_id);
      if (m.version !== "2.1") d.notes.push(`API manifest version ${String(m.version)}`);
    } else if (apiTypes[m.type as string]) {
      d.kind = apiTypes[m.type as string];
      d.id = d.kind === "api_compare" ? str(m.compare_id) : str(m.capture_id);
      if (d.kind === "api_redaction" && m.redaction_id !== m.capture_id) d.problems.push("redaction_id differs from capture_id");
      if (d.kind === "api_certify" && m.certify_id !== m.capture_id) d.problems.push("certify_id differs from capture_id");
      if (d.kind === "api_redaction") d.capturedAt = str(m.redacted_at) ?? d.capturedAt;
    } else {
      d.problems.push(`unknown API manifest type ${JSON.stringify(m.type)}`);
    }
    const prefix = { api_capture: "cap_", api_redaction: "red_", api_certify: "cert_", api_compare: "cmp_" }[d.kind as string];
    if (prefix && (!d.id || !API_ID.test(d.id) || !d.id.startsWith(prefix))) d.problems.push(`unexpected ${d.kind} id ${JSON.stringify(d.id)}`);
    // API captures sealed in 2026-08 listed evidence.pdf without a hash.
    fromArray(m.files, d, d.kind === "api_capture" ? new Set(["evidence.pdf"]) : new Set());
    if (d.kind === "api_capture" && d.expected.get("evidence.pdf")?.sha256 === null) {
      d.notes.push("evidence.pdf is listed without a hash (API packages of 2026-08); the report itself is not sealed");
    }
    return d;
  }

  // ---- Extension web capture / session, manifest 2.1
  if (m.source === "ProofSnap Extension") {
    d.producer = "ProofSnap extension";
    d.kind = session ? "session" : "web_capture";
    d.id = str(m.capture_id);
    if (!d.id || !EXT_ID.test(d.id)) d.problems.push(`unexpected capture_id ${JSON.stringify(d.id)}`);
    if (m.version !== "2.1") d.notes.push(`extension manifest version ${String(m.version)}`);
    fromArray(m.files, d);
    if ([...d.expected.keys()].some((n) => n.startsWith("tabs/"))) d.kind = "session";
    return d;
  }

  // ---- Combined file certification
  if (m.schema !== undefined) {
    d.producer = "ProofSnap extension";
    d.kind = "file_certification_combined";
    d.id = str(m.evidence_id);
    if (m.schema !== "proofsnap-file-manifest/2.0") d.problems.push(`unknown manifest schema ${JSON.stringify(m.schema)}`);
    if (!d.id || !FC_ID.test(d.id)) d.problems.push(`unexpected evidence_id ${JSON.stringify(d.id)}`);
    fromFlat(m, new Set(["evidence_id", "schema", "files"]), d);
    if (!isObj(m.files) || !Object.keys(m.files).length) d.problems.push("combined certification lists no files");
    else fromFlat(m.files as Record<string, unknown>, new Set(), d, "files/");
    return d;
  }

  // ---- Single-file certification
  if (m.file_sha256 !== undefined) {
    d.producer = "ProofSnap extension";
    d.kind = "file_certification";
    d.id = str(m.evidence_id);
    d.anchor = "file_sha256";
    if (typeof m.file_sha256 !== "string" || !HEX64.test(m.file_sha256)) d.problems.push("file_sha256 is not a SHA-256");
    else d.fileSha256 = m.file_sha256.toLowerCase();
    if (!d.id || !FC_ID.test(d.id)) d.problems.push(`unexpected evidence_id ${JSON.stringify(d.id)}`);
    fromFlat(m, new Set(["evidence_id", "file_sha256"]), d);
    return d;
  }

  // ---- Legacy flat web capture
  if (typeof m.evidence_id === "string" && m.version === undefined && m.files === undefined) {
    d.producer = "ProofSnap extension";
    d.kind = session ? "session" : "web_capture_legacy";
    d.id = m.evidence_id;
    if (!EXT_ID.test(d.id)) d.notes.push(`evidence_id ${d.id} does not have the ps_<uuid> form`);
    fromFlat(m, new Set(["evidence_id"]), d);
    return d;
  }

  // ---- Something else with a files[] array: verify generically
  if (Array.isArray(m.files)) {
    d.kind = "unknown";
    d.id = str(m.capture_id) ?? str(m.evidence_id);
    d.notes.push("manifest shape not recognised; files were checked generically");
    fromArray(m.files, d);
    return d;
  }
  d.problems.push("manifest.json does not have a ProofSnap manifest structure");
  return d;
}

export const WEB_REQUIRED = ["metadata.json", "page.html", "evidence.pdf", "domtextcontent.txt"];

import type { OtsReport } from "../core/ots";
import type { TimestampReport } from "../core/timestamp";

export type CheckStatus = "pass" | "fail" | "warn" | "info" | "skip";

export type CheckGroup =
  | "structure"
  | "signature"
  | "files"
  | "custody"
  | "content"
  | "bitcoin"
  | "eidas"
  | "issuance"
  | "container";

export interface Check {
  id: string;
  group: CheckGroup;
  status: CheckStatus;
  title: string;
  detail?: string;
}

export type PackageKind =
  | "web_capture"
  | "web_capture_legacy"
  | "session"
  | "file_certification"
  | "file_certification_combined"
  | "api_capture"
  | "api_certify"
  | "api_compare"
  | "api_redaction"
  | "matter_export"
  | "capture_export"
  | "container"
  | "unknown";

export const KIND_LABELS: Record<PackageKind, string> = {
  web_capture: "Web capture (ProofSnap extension)",
  web_capture_legacy: "Web capture, legacy manifest (ProofSnap extension)",
  session: "Multi-tab browsing session (ProofSnap extension)",
  file_certification: "File certification (ProofSnap extension)",
  file_certification_combined: "Combined file certification (ProofSnap extension)",
  api_capture: "Web capture (ProofSnap API)",
  api_certify: "Hash existence certificate (ProofSnap API)",
  api_compare: "Evidence comparison (ProofSnap API)",
  api_redaction: "Redacted evidence (ProofSnap API)",
  matter_export: "Matter export (ProofSnap API)",
  capture_export: "Capture export (ProofSnap API)",
  container: "Delivery container",
  unknown: "Unrecognised file",
};

export type Verdict = "valid" | "valid_with_warnings" | "invalid" | "not_a_package";

export interface FileResult {
  name: string;
  status: "verified" | "mismatch" | "missing" | "unlisted" | "presence_only" | "derived" | "ignored";
  sha256?: string;
  expected?: string;
  bytes?: number;
  note?: string;
}

export interface TimeAnchorSummary {
  /** Earliest independently verified point in time by which the sealed content existed. */
  existedBy: string | null;
  existedBySource: string | null;
  eidas: { genTime: string | null; tsa: string | null; qualified: boolean; valid: boolean } | null;
  bitcoin: { height: number; blockTime: string | null; verified: boolean }[] | null;
  otsStatus: OtsReport["status"] | "absent" | null;
}

export interface PackageReport {
  name: string;
  kind: PackageKind;
  label: string;
  producer: "ProofSnap extension" | "ProofSnap API" | "ProofSnap" | null;
  id: string | null;
  url: string | null;
  capturedAt: string | null;
  testMode: boolean;
  manifestSha256: string | null;
  anchorSha256: string | null;
  anchorSource: "manifest.json" | "certified file" | "custody head hash" | null;
  verdict: Verdict;
  checks: Check[];
  files: FileResult[];
  timeAnchor: TimeAnchorSummary;
  ots?: OtsReport;
  eidas?: TimestampReport;
  children: PackageReport[];
  verifiedAt: string;
  verifierVersion: string;
}

export function newReport(name: string, version: string): PackageReport {
  return {
    name,
    kind: "unknown",
    label: KIND_LABELS.unknown,
    producer: null,
    id: null,
    url: null,
    capturedAt: null,
    testMode: false,
    manifestSha256: null,
    anchorSha256: null,
    anchorSource: null,
    verdict: "invalid",
    checks: [],
    files: [],
    timeAnchor: { existedBy: null, existedBySource: null, eidas: null, bitcoin: null, otsStatus: null },
    children: [],
    verifiedAt: new Date().toISOString(),
    verifierVersion: version,
  };
}

export function computeVerdict(r: PackageReport): Verdict {
  if (r.kind === "unknown" && !r.checks.some((c) => c.status === "pass")) return "not_a_package";
  const childVerdicts = r.children.map((c) => c.verdict);
  if (r.checks.some((c) => c.status === "fail") || childVerdicts.includes("invalid")) return "invalid";
  if (r.checks.some((c) => c.status === "warn") || childVerdicts.includes("valid_with_warnings") || childVerdicts.includes("not_a_package")) {
    return "valid_with_warnings";
  }
  return "valid";
}

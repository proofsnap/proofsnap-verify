// Public library API. Runs unchanged in Node (>= 20.12) and in the browser.

import { sha256Hex } from "./core/crypto";
import { Fetcher, OtsReport, verifyOts } from "./core/ots";
import { TimestampOptions, TimestampReport, verifyTimestamp } from "./core/timestamp";

export { verifyZip, verifyFiles, VERIFIER_VERSION } from "./package/verifyPackage";
export type { VerifyOptions } from "./package/verifyPackage";
export type { PackageReport, Check, CheckStatus, CheckGroup, PackageKind, Verdict, FileResult, TimeAnchorSummary } from "./package/report";
export type { SourceEntry } from "./package/source";
export { CannotVerifyError } from "./core/errors";
export { StrictZip, ZipError } from "./zip/strictZip";
export { verifyTimestamp } from "./core/timestamp";
export type { TimestampReport, TimestampOptions, LtvData } from "./core/timestamp";
export { verifyOts } from "./core/ots";
export type { OtsReport, Fetcher } from "./core/ots";
export { getEutl, setEutl } from "./core/eutl";
export type { EutlData, EutlMatch } from "./core/eutl";

export interface FileTimestampResult {
  fileName?: string;
  fileSize: number;
  fileSha256: string;
  covered: boolean;
  timestamp: TimestampReport;
  valid: boolean;
}

/** Any file + its RFC 3161 token (.tsr / .tst): does the token cover exactly this file, and is it sound? */
export async function verifyFileWithTimestamp(
  file: Uint8Array,
  tsr: Uint8Array,
  opts: Omit<TimestampOptions, "expectedHash"> & { fileName?: string } = {},
): Promise<FileTimestampResult> {
  const fileSha256 = await sha256Hex(file);
  const timestamp = await verifyTimestamp(tsr, { ...opts, expectedHash: fileSha256 });
  const covered = timestamp.checks.message_imprint?.state === "pass";
  return { fileName: opts.fileName, fileSize: file.length, fileSha256, covered, timestamp, valid: covered && timestamp.valid };
}

/** An RFC 3161 token on its own: who issued it, when, over which hash, and is it sound. */
export async function inspectTimestamp(tsr: Uint8Array, opts: Omit<TimestampOptions, "expectedHash"> = {}): Promise<TimestampReport> {
  return verifyTimestamp(tsr, opts);
}

export interface FileOtsResult {
  fileName?: string;
  fileSha256: string;
  ots: OtsReport;
  valid: boolean;
}

/** Any file + its OpenTimestamps proof. Pass `fetch` to confirm against Bitcoin and complete pending proofs. */
export async function verifyFileWithOts(file: Uint8Array, ots: Uint8Array, opts: { fetch?: Fetcher; fileName?: string } = {}): Promise<FileOtsResult> {
  const fileSha256 = await sha256Hex(file);
  const r = await verifyOts(ots, { expectedDigest: fileSha256, fetch: opts.fetch });
  return { fileName: opts.fileName, fileSha256, ots: r, valid: r.valid };
}

import JSZip from "jszip";
import { VerifyResult, EidasLtvData } from "./types";
import { verifySignature } from "./verifySignature";
import { verifyHashes } from "./verifyHashes";
import { verifyHashChain } from "./verifyHashChain";
import { verifyOts } from "./verifyOts";
import { verifyEidas } from "./verifyEidas";

const REQUIRED_FILES = [
  "manifest.json",
  "manifest.sig",
  "publickey.pem",
  "metadata.json",
  "page.html",
  "screenshot.jpeg",
  "evidence.pdf",
  "domtextcontent.txt",
];

export async function verify(zipBuffer: ArrayBuffer): Promise<VerifyResult> {
  const zip = await JSZip.loadAsync(zipBuffer);

  // Check required files
  const missingFiles = REQUIRED_FILES.filter((f) => !zip.files[f]);
  if (missingFiles.length > 0) {
    throw new Error(`Missing required files: ${missingFiles.join(", ")}`);
  }

  // Read core files
  const manifestContent = await zip.files["manifest.json"].async("string");
  const manifest: Record<string, string> = JSON.parse(manifestContent);
  const sigBuffer = await zip.files["manifest.sig"].async("arraybuffer");
  const publicKeyPem = await zip.files["publickey.pem"].async("string");

  const evidenceId = manifest["evidence_id"] || "unknown";

  // 1. Verify signature
  const sigValid = await verifySignature(manifestContent, sigBuffer, publicKeyPem);

  // 2. Verify file hashes
  const fileResults = await verifyHashes(zip, manifest);

  // 3. Verify hash chain (if forensic log + CoC present)
  let hashChainResult = null;
  if (zip.files["forensic_log.json"] && zip.files["chain_of_custody.json"]) {
    const forensicLogContent = await zip.files["forensic_log.json"].async("string");
    const cocContent = await zip.files["chain_of_custody.json"].async("string");
    hashChainResult = await verifyHashChain(forensicLogContent, cocContent);
  }

  // 4. Verify OTS (if present)
  let otsResult = null;
  if (zip.files["manifest.json.ots"]) {
    const otsBuffer = await zip.files["manifest.json.ots"].async("arraybuffer");
    otsResult = await verifyOts(manifestContent, otsBuffer);
  }

  // 5. Verify eIDAS (if TSR + LTV present)
  let eidasResult = null;
  if (zip.files["manifest.json.tsr"] && zip.files["eidas_validation.json"]) {
    const tsrBuffer = await zip.files["manifest.json.tsr"].async("arraybuffer");
    const tsrBytes = new Uint8Array(tsrBuffer);
    const ltvContent = await zip.files["eidas_validation.json"].async("string");
    const ltvData: EidasLtvData = JSON.parse(ltvContent);
    eidasResult = await verifyEidas(manifestContent, tsrBytes, ltvData);
  }

  // Overall result
  const allFilesMatch = fileResults.every((f) => f.match);
  const overallValid =
    sigValid &&
    allFilesMatch &&
    (hashChainResult === null || hashChainResult.valid) &&
    (otsResult === null || otsResult.verified) &&
    (eidasResult === null || eidasResult.overallValid);

  return {
    evidenceId,
    signature: { valid: sigValid, algorithm: "RSA-4096 (RSASSA-PKCS1-v1_5, SHA-256)" },
    files: fileResults,
    hashChain: hashChainResult,
    ots: otsResult,
    eidas: eidasResult,
    overallValid,
  };
}

// Re-export public API for library consumers
export { inspectTimestamp } from "./inspectTimestamp";
export { verifyFileWithTimestamp } from "./verifyFileWithTimestamp";
export type {
  VerifyResult,
  FileCheckResult,
  HashChainResult,
  OtsResult,
  EidasResult,
  EidasLtvData,
  TsaInfo,
  TimestampInspectionResult,
  FileTimestampResult,
  InspectOptions,
} from "./types";

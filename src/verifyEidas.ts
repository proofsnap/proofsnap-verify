import { sha256 } from "./crypto";
import { EidasResult, EidasLtvData } from "./types";
import { inspectTimestamp } from "./inspectTimestamp";

/**
 * ZIP-mode adapter: verifies a manifest.json + manifest.json.tsr pair using
 * the bundled LTV data from eidas_validation.json. Returns the legacy
 * EidasResult shape (4 booleans + details list) so verify.ts (ZIP flow) keeps
 * its existing contract.
 *
 * The actual cryptographic work happens in inspectTimestamp(). This file
 * only adapts the result.
 */
export async function verifyEidas(
  manifestContent: string,
  tsrBytes: Uint8Array,
  ltvData: EidasLtvData
): Promise<EidasResult> {
  const manifestBytes = new TextEncoder().encode(manifestContent);
  const manifestHash = await sha256(manifestBytes);

  const inspection = await inspectTimestamp(tsrBytes, {
    ltvData,
    expectedHash: manifestHash,
  });

  const hashMatch =
    inspection.messageImprint.toLowerCase() === manifestHash.toLowerCase();

  const details: string[] = [];
  details.push(hashMatch ? "HASH_MATCH" : "HASH_MISMATCH");
  details.push(
    inspection.signatureValid ? "SIGNATURE_VALID" : "SIGNATURE_INVALID"
  );
  details.push(
    inspection.certChainValid ? "CERT_CHAIN_VALID" : "CERT_CHAIN_INVALID"
  );
  if (inspection.ocspValid === true) details.push("OCSP_GOOD");
  else if (inspection.ocspValid === false) details.push("OCSP_NOT_GOOD");
  else details.push("OCSP_MISSING");

  const overallValid =
    hashMatch &&
    inspection.signatureValid &&
    inspection.certChainValid &&
    inspection.ocspValid !== false;

  return {
    hashMatch,
    signatureValid: inspection.signatureValid,
    certChainValid: inspection.certChainValid,
    ocspValid: inspection.ocspValid,
    overallValid,
    details,
  };
}

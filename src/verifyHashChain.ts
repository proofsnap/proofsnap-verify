import { sha256String } from "./crypto";
import { HashChainResult } from "./types";

export async function verifyHashChain(
  forensicLogContent: string,
  cocContent: string
): Promise<HashChainResult> {
  const forensicLog = JSON.parse(forensicLogContent);
  const chainOfCustody = JSON.parse(cocContent);

  // Verify forensic_log.json hash matches CoC reference
  const forensicLogHash = await sha256String(forensicLogContent);
  const forensicLogHashMatch = forensicLogHash === chainOfCustody.forensic_log_hash;

  // Verify hash chain integrity (v1.1.0+)
  let chainSelfValid = true;
  let finalHashMatch: boolean | null = null;

  if (forensicLog.hash_chain) {
    chainSelfValid = forensicLog.hash_chain.chain_valid === true;

    if (chainOfCustody.forensic_log_final_chain_hash) {
      finalHashMatch =
        forensicLog.hash_chain.final_hash === chainOfCustody.forensic_log_final_chain_hash;
    }
  }

  // Verify evidence_id consistency
  const evidenceIdConsistent =
    forensicLog.evidence_id === chainOfCustody.evidence.evidence_id;

  const valid =
    forensicLogHashMatch && chainSelfValid && (finalHashMatch !== false) && evidenceIdConsistent;

  return {
    valid,
    entries: forensicLog.total_operations || forensicLog.operations?.length || 0,
    chainSelfValid,
    finalHashMatch,
    forensicLogHashMatch,
    evidenceIdConsistent,
  };
}

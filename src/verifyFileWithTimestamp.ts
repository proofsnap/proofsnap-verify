import { sha256 } from "./crypto";
import { inspectTimestamp } from "./inspectTimestamp";
import {
  FileTimestampResult,
  InspectOptions,
} from "./types";

export async function verifyFileWithTimestamp(
  fileBytes: Uint8Array,
  tsrBytes: Uint8Array,
  options: InspectOptions & { fileName?: string } = {}
): Promise<FileTimestampResult> {
  const fileHash = await sha256(fileBytes);

  const inspection = await inspectTimestamp(tsrBytes, {
    ltvData: options.ltvData,
    trustedRootsPem: options.trustedRootsPem,
    expectedHash: fileHash,
  });

  const hashCoversFile =
    inspection.messageImprint.toLowerCase() === fileHash.toLowerCase();

  // overallValid for the file+timestamp pair requires the hash to actually
  // match (the inspectTimestamp result already encodes signature + chain).
  const overallValid = hashCoversFile && inspection.overallValid;

  return {
    fileName: options.fileName,
    fileSize: fileBytes.length,
    fileHash,
    hashAlgorithm: inspection.hashAlgorithm,
    hashCoversFile,
    tsr: inspection,
    overallValid,
  };
}

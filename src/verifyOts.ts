import { sha256 } from "./crypto";
import { OtsResult } from "./types";

export async function verifyOts(
  manifestContent: string,
  otsBuffer: ArrayBuffer
): Promise<OtsResult> {
  try {
    // Dynamic import — opentimestamps is a CommonJS module
    const OpenTimestamps = require("opentimestamps");

    const manifestBytes = new TextEncoder().encode(manifestContent);
    const manifestHash = await sha256(manifestBytes);
    const hashBytes = Buffer.from(manifestHash, "hex");

    // Create detached timestamp from the manifest hash
    const detached = OpenTimestamps.DetachedTimestampFile.fromHash(
      new OpenTimestamps.Ops.OpSHA256(),
      hashBytes
    );

    // Deserialize the OTS proof
    const otsBytes = new Uint8Array(otsBuffer);
    const ots = OpenTimestamps.DetachedTimestampFile.deserialize(otsBytes);

    // Verify against calendar servers
    const verifyResult = await OpenTimestamps.verify(ots, detached);

    if (!verifyResult || Object.keys(verifyResult).length === 0) {
      return { verified: true, pending: true };
    }

    // Extract Bitcoin attestation
    const bitcoin = verifyResult["bitcoin"] || verifyResult;
    if (bitcoin && typeof bitcoin === "object") {
      const height = bitcoin.height || bitcoin.block_height;
      const timestamp = bitcoin.timestamp;
      if (height && timestamp) {
        const date = new Date(timestamp * 1000);
        return {
          verified: true,
          pending: false,
          bitcoinHeight: height,
          timestamp: date.toISOString(),
        };
      }
    }

    return { verified: true, pending: false };
  } catch (err) {
    return {
      verified: false,
      pending: false,
      error: err instanceof Error ? err.message : "OTS verification failed",
    };
  }
}

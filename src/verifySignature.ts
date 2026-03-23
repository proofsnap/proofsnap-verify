import { importPublicKey, verifyRsaSignature } from "./crypto";

export async function verifySignature(
  manifestContent: string,
  signatureBuffer: ArrayBuffer,
  publicKeyPem: string
): Promise<boolean> {
  const publicKey = await importPublicKey(publicKeyPem);
  const manifestBytes = new TextEncoder().encode(manifestContent);
  return verifyRsaSignature(publicKey, signatureBuffer, manifestBytes as unknown as Uint8Array);
}

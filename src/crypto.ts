import { webcrypto } from "crypto";

const subtle = webcrypto.subtle;

export async function sha256(input: Uint8Array): Promise<string> {
  const buf = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
  const hashBuffer = await subtle.digest("SHA-256", buf);
  return Buffer.from(hashBuffer).toString("hex");
}

export async function sha256String(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  return sha256(bytes);
}

export async function importPublicKey(pem: string): Promise<webcrypto.CryptoKey> {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");
  const binaryDer = Buffer.from(b64, "base64");
  return subtle.importKey(
    "spki",
    binaryDer as unknown as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

export async function verifyRsaSignature(
  publicKey: webcrypto.CryptoKey,
  signature: ArrayBuffer,
  data: Uint8Array
): Promise<boolean> {
  return subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    publicKey,
    signature,
    data
  );
}

export async function importSpkiKey(
  spki: Uint8Array,
  hashAlg: string
): Promise<webcrypto.CryptoKey> {
  const buf = spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength) as ArrayBuffer;
  return subtle.importKey(
    "spki",
    buf,
    { name: "RSASSA-PKCS1-v1_5", hash: hashAlg },
    false,
    ["verify"]
  );
}

export async function verifySig(
  key: webcrypto.CryptoKey,
  sig: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  return subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
}

export { subtle };

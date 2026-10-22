// WebCrypto wrapper. Uses globalThis.crypto, present in Node >= 20 and in
// every current browser, so the same code runs in the CLI and the web page.

import { Asn1, TAG, bitStringBytes, integerBytes, oidOf, parseDer } from "./asn1";
import { toArrayBuffer, toHex } from "./bytes";
import { DIGEST_OIDS, OID, SIGNATURE_OIDS } from "./oids";

export type DigestName = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error("WebCrypto is not available (Node 20+ or a modern browser is required)");
  return c.subtle;
}

export async function digest(alg: DigestName, data: Uint8Array): Promise<Uint8Array> {
  // The view is hashed in place: copying it first would double the memory a large video needs.
  return new Uint8Array(await subtle().digest(alg, data as unknown as BufferSource));
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return toHex(await digest("SHA-256", data));
}

export async function sha512Hex(data: Uint8Array): Promise<string> {
  return toHex(await digest("SHA-512", data));
}

export async function sha256HexOfString(s: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(s));
}

export function digestNameFromOid(oid: string | null | undefined): DigestName | null {
  return (oid && DIGEST_OIDS[oid]) || null;
}

export interface AlgorithmIdentifier {
  oid: string;
  params?: Asn1;
}

export function parseAlgorithmIdentifier(node: Asn1): AlgorithmIdentifier {
  const oid = oidOf(node.children[0]);
  if (!oid) throw new Error("malformed AlgorithmIdentifier");
  const p = node.children[1];
  return { oid, params: p && p.tag !== TAG.NULL ? p : undefined };
}

export interface SpkiInfo {
  raw: Uint8Array;
  algorithm: AlgorithmIdentifier;
  publicKey: Uint8Array;
  keyType: "RSA" | "RSA-PSS" | "EC" | "Ed25519" | "unknown";
  curve?: "P-256" | "P-384" | "P-521";
  keyBits?: number;
}

export function parseSpki(spkiDer: Uint8Array): SpkiInfo {
  const node = parseDer(spkiDer);
  const algorithm = parseAlgorithmIdentifier(node.children[0]);
  const publicKey = bitStringBytes(node.children[1]);
  const info: SpkiInfo = { raw: spkiDer, algorithm, publicKey, keyType: "unknown" };
  if (algorithm.oid === OID.rsaEncryption || algorithm.oid === OID.rsassaPss) {
    info.keyType = algorithm.oid === OID.rsaEncryption ? "RSA" : "RSA-PSS";
    try {
      const rsa = parseDer(publicKey);
      info.keyBits = integerBytes(rsa.children[0]).length * 8;
    } catch {
      /* leave keyBits undefined */
    }
  } else if (algorithm.oid === OID.ecPublicKey) {
    info.keyType = "EC";
    const curveOid = algorithm.params ? oidOf(algorithm.params) : null;
    info.curve =
      curveOid === OID.p256 ? "P-256" : curveOid === OID.p384 ? "P-384" : curveOid === OID.p521 ? "P-521" : undefined;
    info.keyBits = info.curve ? parseInt(info.curve.slice(2), 10) : undefined;
  } else if (algorithm.oid === OID.ed25519) {
    info.keyType = "Ed25519";
    info.keyBits = 256;
  }
  return info;
}

/** Re-wraps an id-RSASSA-PSS SPKI as rsaEncryption, which WebCrypto requires. */
function spkiForWebCrypto(spki: SpkiInfo): Uint8Array {
  if (spki.keyType !== "RSA-PSS") return spki.raw;
  // SEQUENCE { SEQUENCE { rsaEncryption, NULL }, BIT STRING key }
  const algId = Uint8Array.of(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00);
  const bits = parseDer(spki.raw).children[1].raw;
  const body = new Uint8Array(algId.length + bits.length);
  body.set(algId, 0);
  body.set(bits, algId.length);
  return encodeSeq(body);
}

function encodeSeq(body: Uint8Array): Uint8Array {
  const len = body.length;
  const lenBytes: number[] = len < 0x80 ? [len] : [];
  if (len >= 0x80) {
    let l = len;
    const tmp: number[] = [];
    while (l > 0) {
      tmp.unshift(l & 0xff);
      l = Math.floor(l / 256);
    }
    lenBytes.push(0x80 | tmp.length, ...tmp);
  }
  const out = new Uint8Array(1 + lenBytes.length + len);
  out[0] = 0x30;
  out.set(lenBytes, 1);
  out.set(body, 1 + lenBytes.length);
  return out;
}

/** DER ECDSA-Sig-Value -> IEEE P1363 r||s, which WebCrypto expects. */
function ecdsaDerToRaw(sig: Uint8Array, curve: "P-256" | "P-384" | "P-521"): Uint8Array {
  const size = curve === "P-256" ? 32 : curve === "P-384" ? 48 : 66;
  const node = parseDer(sig);
  const out = new Uint8Array(size * 2);
  [0, 1].forEach((i) => {
    let v = integerBytes(node.children[i]);
    if (v.length > size) v = v.subarray(v.length - size);
    out.set(v, size * (i + 1) - v.length);
  });
  return out;
}

interface PssParams {
  hash: DigestName;
  saltLength: number;
}

function parsePssParams(params?: Asn1): PssParams {
  let hash: DigestName = "SHA-1";
  let saltLength = 20;
  for (const c of params?.children ?? []) {
    if (c.tagClass !== 2) continue;
    if (c.tagNumber === 0) hash = digestNameFromOid(oidOf(c.children[0]?.children[0])) ?? hash;
    if (c.tagNumber === 2) saltLength = c.children[0] ? Number(BigInt("0x" + (toHex(c.children[0].value) || "0"))) : saltLength;
  }
  return { hash, saltLength };
}

export interface SignatureCheck {
  valid: boolean;
  algorithm: string;
  weak?: boolean;
  error?: string;
}

/**
 * Verifies `signature` over `data` with the key in `spkiDer`.
 * `sigAlg` is the signatureAlgorithm of the signed structure; `digestHint`
 * supplies the digest when the algorithm OID does not carry one (CMS
 * SignerInfo commonly says plain rsaEncryption).
 */
export async function verifySignature(
  spkiDer: Uint8Array,
  sigAlg: AlgorithmIdentifier,
  signature: Uint8Array,
  data: Uint8Array,
  digestHint?: DigestName | null,
): Promise<SignatureCheck> {
  const meta = SIGNATURE_OIDS[sigAlg.oid];
  if (!meta) return { valid: false, algorithm: sigAlg.oid, error: `unsupported signature algorithm ${sigAlg.oid}` };
  let spki: SpkiInfo;
  try {
    spki = parseSpki(spkiDer);
  } catch (e) {
    return { valid: false, algorithm: meta.family, error: "malformed public key" };
  }
  const s = subtle();
  try {
    if (meta.family === "RSA") {
      const hash = (meta.hash as DigestName) ?? digestHint ?? "SHA-256";
      const key = await s.importKey("spki", toArrayBuffer(spkiForWebCrypto(spki)), { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
      const valid = await s.verify("RSASSA-PKCS1-v1_5", key, toArrayBuffer(signature), toArrayBuffer(data));
      return { valid, algorithm: `RSA-${spki.keyBits ?? "?"} PKCS#1 v1.5 ${hash}`, weak: hash === "SHA-1" || (spki.keyBits ?? 2048) < 2048 };
    }
    if (meta.family === "RSA-PSS") {
      const p = parsePssParams(sigAlg.params);
      const key = await s.importKey("spki", toArrayBuffer(spkiForWebCrypto(spki)), { name: "RSA-PSS", hash: p.hash }, false, ["verify"]);
      const valid = await s.verify({ name: "RSA-PSS", saltLength: p.saltLength }, key, toArrayBuffer(signature), toArrayBuffer(data));
      return { valid, algorithm: `RSA-${spki.keyBits ?? "?"} PSS ${p.hash}`, weak: p.hash === "SHA-1" };
    }
    if (meta.family === "ECDSA") {
      if (!spki.curve) return { valid: false, algorithm: "ECDSA", error: "unsupported EC curve" };
      const hash = (meta.hash as DigestName) ?? digestHint ?? "SHA-256";
      const key = await s.importKey("spki", toArrayBuffer(spki.raw), { name: "ECDSA", namedCurve: spki.curve }, false, ["verify"]);
      const valid = await s.verify({ name: "ECDSA", hash }, key, toArrayBuffer(ecdsaDerToRaw(signature, spki.curve)), toArrayBuffer(data));
      return { valid, algorithm: `ECDSA ${spki.curve} ${hash}`, weak: hash === "SHA-1" };
    }
    const key = await s.importKey("spki", toArrayBuffer(spki.raw), { name: "Ed25519" }, false, ["verify"]);
    const valid = await s.verify({ name: "Ed25519" }, key, toArrayBuffer(signature), toArrayBuffer(data));
    return { valid, algorithm: "Ed25519" };
  } catch (e) {
    return { valid: false, algorithm: meta.family, error: e instanceof Error ? e.message : String(e) };
  }
}

/** RSA PKCS#1 v1.5 SHA-256 over raw bytes with a PEM/SPKI key (ProofSnap manifest.sig). */
export async function verifyRsaSha256(spkiDer: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<SignatureCheck> {
  return verifySignature(spkiDer, { oid: "1.2.840.113549.1.1.11" }, signature, data);
}

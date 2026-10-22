// Byte helpers that work identically in Node and in the browser (no Buffer).

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) throw new Error("invalid hex string");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function isHex(s: unknown, bytes?: number): s is string {
  if (typeof s !== "string") return false;
  if (bytes !== undefined && s.length !== bytes * 2) return false;
  return s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP = (() => {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < B64.length; i++) t[B64.charCodeAt(i)] = i;
  t["-".charCodeAt(0)] = 62; // base64url
  t["_".charCodeAt(0)] = 63;
  return t;
})();

export function fromBase64(b64: string): Uint8Array {
  const clean = b64.replace(/[\s=]/g, "");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buf = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < clean.length; i++) {
    const v = B64_LOOKUP[clean.charCodeAt(i)];
    if (v < 0) throw new Error("invalid base64");
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buf >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Copies into a standalone ArrayBuffer, which WebCrypto and JSZip both accept. */
export function toArrayBuffer(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

/** Extracts every PEM block with the given label (default: any label). */
export function pemBlocks(pem: string, label?: string): Uint8Array[] {
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]+?)-----END \1-----/g;
  const out: Uint8Array[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem))) {
    if (label && m[1] !== label) continue;
    out.push(fromBase64(m[2]));
  }
  return out;
}

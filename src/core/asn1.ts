// Strict DER parser. Every node keeps a view of its original bytes (`raw`) so
// signed structures are verified over exactly the bytes that were signed,
// never over a re-encoding.

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  ENUMERATED: 0x0a,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  TELETEX_STRING: 0x14,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  UNIVERSAL_STRING: 0x1c,
  BMP_STRING: 0x1e,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

export interface Asn1 {
  /** First identifier octet (class + constructed bit + low tag number). */
  tag: number;
  tagClass: number; // 0 universal, 1 application, 2 context, 3 private
  tagNumber: number;
  constructed: boolean;
  /** Full TLV bytes. */
  raw: Uint8Array;
  /** Content bytes. */
  value: Uint8Array;
  children: Asn1[];
}

const MAX_DEPTH = 64;

export function parseDer(buf: Uint8Array): Asn1 {
  const node = parseAt(buf, 0, 0);
  if (node.raw.length !== buf.length) {
    throw new Error(`ASN.1: ${buf.length - node.raw.length} trailing bytes after DER object`);
  }
  return node;
}

function parseAt(buf: Uint8Array, offset: number, depth: number): Asn1 {
  if (depth > MAX_DEPTH) throw new Error("ASN.1: nesting too deep");
  if (offset + 2 > buf.length) throw new Error("ASN.1: unexpected end of data");
  const tag = buf[offset];
  const tagClass = tag >> 6;
  const constructed = (tag & 0x20) !== 0;
  let tagNumber = tag & 0x1f;
  let pos = offset + 1;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    for (;;) {
      if (pos >= buf.length) throw new Error("ASN.1: truncated tag");
      const b = buf[pos++];
      tagNumber = tagNumber * 128 + (b & 0x7f);
      if (!(b & 0x80)) break;
      if (tagNumber > 0xffffff) throw new Error("ASN.1: tag too large");
    }
  }
  if (pos >= buf.length) throw new Error("ASN.1: truncated length");
  const first = buf[pos++];
  let length: number;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    throw new Error("ASN.1: indefinite length is not DER");
  } else {
    const n = first & 0x7f;
    if (n > 4) throw new Error("ASN.1: length too large");
    if (pos + n > buf.length) throw new Error("ASN.1: truncated length");
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[pos + i];
    pos += n;
  }
  const end = pos + length;
  if (end > buf.length) throw new Error("ASN.1: length exceeds available data");

  const value = buf.subarray(pos, end);
  const children: Asn1[] = [];
  if (constructed) {
    let c = pos;
    while (c < end) {
      const child = parseAt(buf, c, depth + 1);
      children.push(child);
      c += child.raw.length;
    }
    if (c !== end) throw new Error("ASN.1: child overruns parent");
  }
  return {
    tag,
    tagClass,
    tagNumber,
    constructed,
    raw: buf.subarray(offset, end),
    value,
    children,
  };
}

/** Context-specific tag test, e.g. isContext(node, 0) for [0]. */
export function isContext(node: Asn1 | undefined, n: number): boolean {
  return !!node && node.tagClass === 2 && node.tagNumber === n;
}

export function decodeOid(node: Asn1 | Uint8Array): string {
  const d = node instanceof Uint8Array ? node : node.value;
  if (!d.length) throw new Error("ASN.1: empty OID");
  const parts: number[] = [];
  let v = 0;
  let firstDone = false;
  for (let i = 0; i < d.length; i++) {
    v = v * 128 + (d[i] & 0x7f);
    if (!(d[i] & 0x80)) {
      if (!firstDone) {
        const a = v < 80 ? Math.floor(v / 40) : 2;
        parts.push(a, v - a * 40);
        firstDone = true;
      } else {
        parts.push(v);
      }
      v = 0;
    }
  }
  return parts.join(".");
}

export function oidOf(node: Asn1 | undefined): string | null {
  if (!node || node.tag !== TAG.OID) return null;
  try {
    return decodeOid(node);
  } catch {
    return null;
  }
}

/** Unsigned big-endian integer bytes with the DER sign octet removed. */
export function integerBytes(node: Asn1): Uint8Array {
  const v = node.value;
  return v.length > 1 && v[0] === 0 ? v.subarray(1) : v;
}

export function integerNumber(node: Asn1): number {
  let n = 0;
  for (const b of node.value) n = n * 256 + b;
  return n;
}

export function decodeString(node: Asn1): string {
  const b = node.value;
  switch (node.tag) {
    case TAG.BMP_STRING: {
      let s = "";
      for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
      return s;
    }
    case TAG.UNIVERSAL_STRING: {
      let s = "";
      for (let i = 0; i + 3 < b.length; i += 4) {
        s += String.fromCodePoint(((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0);
      }
      return s;
    }
    case TAG.UTF8_STRING:
      return new TextDecoder("utf-8").decode(b);
    case TAG.TELETEX_STRING:
      return new TextDecoder("latin1").decode(b);
    default:
      return new TextDecoder("ascii").decode(b);
  }
}

/** Parses UTCTime / GeneralizedTime into a Date (UTC). */
export function decodeTime(node: Asn1): Date | null {
  const t = new TextDecoder("ascii").decode(node.value);
  let m: RegExpMatchArray | null;
  if (node.tag === TAG.UTC_TIME) {
    m = t.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
    if (!m) return null;
    const yy = parseInt(m[1], 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  if (node.tag === TAG.GENERALIZED_TIME) {
    m = t.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?Z$/);
    if (!m) return null;
    const ms = m[7] ? Math.floor(parseFloat("0." + m[7]) * 1000) : 0;
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0), ms));
  }
  return null;
}

/** Fractional-second precision of a GeneralizedTime, as written by the TSA. */
export function decodeTimeText(node: Asn1): string {
  return new TextDecoder("ascii").decode(node.value);
}

/** BIT STRING content without the unused-bits octet. */
export function bitStringBytes(node: Asn1): Uint8Array {
  return node.value.subarray(1);
}

/** Returns the raw SET OF bytes for a [0] IMPLICIT SET OF field (signedAttrs). */
export function retagAsSet(node: Asn1): Uint8Array {
  const out = new Uint8Array(node.raw);
  out[0] = TAG.SET;
  return out;
}

// --- tiny DER encoder, only what the verifier needs (OCSP / ESS lookups) ---

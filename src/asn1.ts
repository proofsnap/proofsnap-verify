/**
 * Lightweight ASN.1 DER parser for LTV verification.
 * Ported from ProofSnap extension (asn1-utils.ts).
 * No external dependencies.
 */

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;

const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

export interface Asn1Node {
  tag: number;
  constructed: boolean;
  data: Uint8Array;
  children: Asn1Node[];
  offset: number;
  totalLength: number;
}

export function parseAsn1(buf: Uint8Array, offset = 0): Asn1Node {
  if (offset >= buf.length) throw new Error("ASN.1: unexpected end of data");

  const tag = buf[offset];
  const constructed = (tag & 0x20) !== 0;
  let pos = offset + 1;

  let length: number;
  if (buf[pos] < 0x80) {
    length = buf[pos];
    pos += 1;
  } else {
    const numBytes = buf[pos] & 0x7f;
    if (numBytes > 4) throw new Error("ASN.1: length too large");
    length = 0;
    pos += 1;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[pos + i];
    }
    pos += numBytes;
  }

  const data = buf.slice(pos, pos + length);
  const totalLength = pos - offset + length;
  const children: Asn1Node[] = [];

  if (constructed) {
    let childOffset = 0;
    while (childOffset < data.length) {
      const child = parseAsn1(data, childOffset);
      children.push(child);
      childOffset += child.totalLength;
    }
  }

  return { tag, constructed, data, children, offset, totalLength };
}

export function decodeOid(data: Uint8Array): string {
  const parts: number[] = [];
  parts.push(Math.floor(data[0] / 40));
  parts.push(data[0] % 40);

  let value = 0;
  for (let i = 1; i < data.length; i++) {
    value = (value << 7) | (data[i] & 0x7f);
    if ((data[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  return Buffer.from(b64, "base64");
}

function findEncapContentInfo(signedData: Asn1Node): Asn1Node | null {
  for (const child of signedData.children) {
    if (child.tag === TAG_SEQUENCE && child.children.length >= 2) {
      const firstChild = child.children[0];
      if (firstChild.tag === TAG_OID) {
        const oid = decodeOid(firstChild.data);
        if (oid === OID_TST_INFO) return child;
      }
    }
  }
  return null;
}

export function extractTsrMessageImprint(tsrRoot: Asn1Node): string | null {
  try {
    const timeStampToken = tsrRoot.children[1];
    if (!timeStampToken) return null;
    const signedDataWrapper = timeStampToken.children[1];
    if (!signedDataWrapper) return null;
    const signedData = signedDataWrapper.children[0];
    if (!signedData) return null;

    const encapContentInfo = findEncapContentInfo(signedData);
    if (!encapContentInfo) return null;

    const eContent = encapContentInfo.children[1];
    if (!eContent) return null;
    const tstInfoOctetString = eContent.children[0];
    if (!tstInfoOctetString) return null;

    const tstInfo = parseAsn1(tstInfoOctetString.data);
    const messageImprint = tstInfo.children[2];
    if (!messageImprint) return null;
    const hashedMessage = messageImprint.children[1];
    if (!hashedMessage || hashedMessage.tag !== TAG_OCTET_STRING) return null;

    return bytesToHex(hashedMessage.data);
  } catch {
    return null;
  }
}

function encodeAsn1Length(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  let temp = length;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function buildTlvFromNode(node: Asn1Node): Uint8Array {
  const data = node.data;
  const lengthBytes = encodeAsn1Length(data.length);
  const result = new Uint8Array(1 + lengthBytes.length + data.length);
  result[0] = node.tag;
  result.set(lengthBytes, 1);
  result.set(data, 1 + lengthBytes.length);
  return result;
}

export function extractTsrSignatureData(tsrRoot: Asn1Node): {
  signedAttrsBytes: Uint8Array;
  signatureBytes: Uint8Array;
  digestAlgorithmOid: string;
} | null {
  try {
    const timeStampToken = tsrRoot.children[1];
    const signedDataWrapper = timeStampToken.children[1];
    const signedData = signedDataWrapper.children[0];

    const signerInfosSet = signedData.children[signedData.children.length - 1];
    if (signerInfosSet.tag !== TAG_SET) return null;

    const signerInfo = signerInfosSet.children[0];
    if (!signerInfo) return null;

    let digestAlgNode: Asn1Node | null = null;
    let signedAttrsNode: Asn1Node | null = null;
    let signatureNode: Asn1Node | null = null;

    for (const child of signerInfo.children) {
      if (child.tag === TAG_SEQUENCE && !digestAlgNode) {
        const firstChild = child.children[0];
        if (firstChild && firstChild.tag === TAG_OID) {
          digestAlgNode = child;
        }
      }
      if (child.tag === 0xa0) {
        signedAttrsNode = child;
      }
      if (child.tag === TAG_OCTET_STRING && signedAttrsNode) {
        signatureNode = child;
      }
    }

    if (!signedAttrsNode || !signatureNode || !digestAlgNode) return null;

    const fullSignedAttrs = new Uint8Array(signedAttrsNode.totalLength);
    const originalTlv = buildTlvFromNode(signedAttrsNode);
    fullSignedAttrs.set(originalTlv);
    fullSignedAttrs[0] = TAG_SET;

    const digestOid = digestAlgNode.children[0]
      ? decodeOid(digestAlgNode.children[0].data)
      : "";

    return {
      signedAttrsBytes: fullSignedAttrs,
      signatureBytes: signatureNode.data,
      digestAlgorithmOid: digestOid,
    };
  } catch {
    return null;
  }
}

export function extractCertTbsAndSignature(certDer: Uint8Array): {
  tbsBytes: Uint8Array;
  signatureBytes: Uint8Array;
  signatureAlgorithmOid: string;
} | null {
  try {
    const cert = parseAsn1(certDer);
    const tbsCert = cert.children[0];
    const sigAlg = cert.children[1];
    const sigValue = cert.children[2];

    if (!tbsCert || !sigAlg || !sigValue) return null;

    const tbsBytes = buildTlvFromNode(tbsCert);
    const sigBits = sigValue.data;
    const signatureBytes = sigBits.slice(1);

    const sigAlgOid = sigAlg.children[0]
      ? decodeOid(sigAlg.children[0].data)
      : "";

    return { tbsBytes, signatureBytes, signatureAlgorithmOid: sigAlgOid };
  } catch {
    return null;
  }
}

export function extractSpkiFromCert(certDer: Uint8Array): Uint8Array | null {
  try {
    const cert = parseAsn1(certDer);
    const tbsCert = cert.children[0];

    for (const child of tbsCert.children) {
      if (
        child.tag === TAG_SEQUENCE &&
        child.children.length >= 2 &&
        child.children[0].tag === TAG_SEQUENCE &&
        child.children[1].tag === TAG_BIT_STRING
      ) {
        return buildTlvFromNode(child);
      }
    }
    return null;
  } catch {
    return null;
  }
}

export function parseOcspCertStatus(ocspDer: Uint8Array): string | null {
  try {
    const root = parseAsn1(ocspDer);
    const responseBytes = root.children[1];
    if (!responseBytes) return null;
    const responseSeq = responseBytes.children[0];
    if (!responseSeq) return null;
    const responseOctetString = responseSeq.children[1];
    if (!responseOctetString) return null;

    const basicResp = parseAsn1(responseOctetString.data);
    const tbsResponseData = basicResp.children[0];

    let responsesSeq: Asn1Node | null = null;
    for (const child of tbsResponseData.children) {
      if (child.tag === TAG_SEQUENCE) {
        if (child.children.length > 0 && child.children[0].tag === TAG_SEQUENCE) {
          responsesSeq = child;
          break;
        }
      }
    }
    if (!responsesSeq) return null;

    const singleResponse = responsesSeq.children[0];
    if (!singleResponse) return null;

    const certStatus = singleResponse.children[1];
    if (!certStatus) return null;

    const statusTag = certStatus.tag & 0x1f;
    if (statusTag === 0) return "good";
    if (statusTag === 1) return "revoked";
    return "unknown";
  } catch {
    return null;
  }
}

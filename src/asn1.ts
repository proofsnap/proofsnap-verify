/**
 * Lightweight ASN.1 DER parser for LTV verification.
 * Ported from ProofSnap extension (asn1-utils.ts).
 * No external dependencies.
 */

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_UTF8_STRING = 0x0c;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_TELETEX_STRING = 0x14;
const TAG_IA5_STRING = 0x16;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_BMP_STRING = 0x1e;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_CONTEXT_0 = 0xa0;

const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_CN = "2.5.4.3";
const OID_O = "2.5.4.10";
const OID_OU = "2.5.4.11";
const OID_C = "2.5.4.6";

const HASH_OID_MAP: Record<string, string> = {
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
  "1.3.14.3.2.26": "SHA-1",
};

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

export function derToPem(der: Uint8Array, label = "CERTIFICATE"): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

function decodeAsString(node: Asn1Node): string {
  const bytes = node.data;
  switch (node.tag) {
    case TAG_BMP_STRING: {
      let result = "";
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        result += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
      }
      return result;
    }
    case TAG_UTF8_STRING:
      return new TextDecoder("utf-8").decode(bytes);
    default:
      return new TextDecoder("ascii").decode(bytes);
  }
}

export function hashAlgorithmName(oid: string): string {
  return HASH_OID_MAP[oid] || `unknown(${oid})`;
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

function getTstInfo(tsrRoot: Asn1Node): Asn1Node | null {
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

    return parseAsn1(tstInfoOctetString.data);
  } catch {
    return null;
  }
}

function getSignedData(tsrRoot: Asn1Node): Asn1Node | null {
  try {
    const timeStampToken = tsrRoot.children[1];
    const signedDataWrapper = timeStampToken.children[1];
    return signedDataWrapper.children[0];
  } catch {
    return null;
  }
}

export function extractTsrMessageImprint(tsrRoot: Asn1Node): string | null {
  try {
    const tstInfo = getTstInfo(tsrRoot);
    if (!tstInfo) return null;
    const messageImprint = tstInfo.children[2];
    if (!messageImprint) return null;
    const hashedMessage = messageImprint.children[1];
    if (!hashedMessage || hashedMessage.tag !== TAG_OCTET_STRING) return null;
    return bytesToHex(hashedMessage.data);
  } catch {
    return null;
  }
}

export function extractTsrHashAlgorithmOid(tsrRoot: Asn1Node): string | null {
  try {
    const tstInfo = getTstInfo(tsrRoot);
    if (!tstInfo) return null;
    const messageImprint = tstInfo.children[2];
    if (!messageImprint) return null;
    const hashAlgIdent = messageImprint.children[0];
    if (!hashAlgIdent) return null;
    const oidNode = hashAlgIdent.children[0];
    if (!oidNode || oidNode.tag !== TAG_OID) return null;
    return decodeOid(oidNode.data);
  } catch {
    return null;
  }
}

export function extractTsrPolicyOid(tsrRoot: Asn1Node): string | null {
  try {
    const tstInfo = getTstInfo(tsrRoot);
    if (!tstInfo) return null;
    const policy = tstInfo.children[1];
    if (!policy || policy.tag !== TAG_OID) return null;
    return decodeOid(policy.data);
  } catch {
    return null;
  }
}

export function extractTsrSerialNumber(tsrRoot: Asn1Node): string | null {
  try {
    const tstInfo = getTstInfo(tsrRoot);
    if (!tstInfo) return null;
    const serial = tstInfo.children[3];
    if (!serial || serial.tag !== TAG_INTEGER) return null;
    return bytesToHex(serial.data);
  } catch {
    return null;
  }
}

export function extractTsrGenTime(tsrRoot: Asn1Node): string | null {
  try {
    const tstInfo = getTstInfo(tsrRoot);
    if (!tstInfo) return null;
    const genTime = tstInfo.children[4];
    if (!genTime || genTime.tag !== TAG_GENERALIZED_TIME) return null;
    return parseGeneralizedTime(genTime.data);
  } catch {
    return null;
  }
}

export function parseGeneralizedTime(bytes: Uint8Array): string | null {
  // Format: YYYYMMDDHHMMSS[.fff]Z
  const text = new TextDecoder("ascii").decode(bytes);
  const m = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z?$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac] = m;
  const ms = frac ? frac.padEnd(3, "0").substring(0, 3) : "000";
  return `${y}-${mo}-${d}T${h}:${mi}:${s}.${ms}Z`;
}

function parseUtcTime(bytes: Uint8Array): string | null {
  // Format: YYMMDDHHMMSSZ
  const text = new TextDecoder("ascii").decode(bytes);
  const m = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/);
  if (!m) return null;
  let [, y, mo, d, h, mi, s] = m;
  const yyyy = parseInt(y, 10) >= 50 ? `19${y}` : `20${y}`;
  return `${yyyy}-${mo}-${d}T${h}:${mi}:${s}.000Z`;
}

export function extractEmbeddedCerts(tsrRoot: Asn1Node): Uint8Array[] {
  // CMS SignedData certificates are in [0] IMPLICIT (tag 0xa0)
  try {
    const signedData = getSignedData(tsrRoot);
    if (!signedData) return [];

    const certsContainer = signedData.children.find(
      (c) => c.tag === TAG_CONTEXT_0
    );
    if (!certsContainer) return [];

    const certs: Uint8Array[] = [];
    for (const certNode of certsContainer.children) {
      if (certNode.tag === TAG_SEQUENCE) {
        certs.push(rebuildTlv(certNode));
      }
    }
    return certs;
  } catch {
    return [];
  }
}

function rebuildTlv(node: Asn1Node): Uint8Array {
  const data = node.data;
  const lengthBytes = encodeAsn1Length(data.length);
  const result = new Uint8Array(1 + lengthBytes.length + data.length);
  result[0] = node.tag;
  result.set(lengthBytes, 1);
  result.set(data, 1 + lengthBytes.length);
  return result;
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
  return rebuildTlv(node);
}

export function extractTsrSignatureData(tsrRoot: Asn1Node): {
  signedAttrsBytes: Uint8Array;
  signatureBytes: Uint8Array;
  digestAlgorithmOid: string;
} | null {
  try {
    const signedData = getSignedData(tsrRoot);
    if (!signedData) return null;

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

export interface CertSubjectInfo {
  commonName: string | null;
  organization: string | null;
  organizationalUnit: string | null;
  country: string | null;
}

function parseDn(dn: Asn1Node): CertSubjectInfo {
  let commonName: string | null = null;
  let organization: string | null = null;
  let organizationalUnit: string | null = null;
  let country: string | null = null;

  for (const rdn of dn.children) {
    if (rdn.tag !== TAG_SET) continue;
    for (const atv of rdn.children) {
      if (atv.tag !== TAG_SEQUENCE || atv.children.length < 2) continue;
      const oidNode = atv.children[0];
      const valueNode = atv.children[1];
      if (oidNode.tag !== TAG_OID) continue;
      const oid = decodeOid(oidNode.data);
      const value = decodeAsString(valueNode);
      if (oid === OID_CN && !commonName) commonName = value;
      else if (oid === OID_O && !organization) organization = value;
      else if (oid === OID_OU && !organizationalUnit) organizationalUnit = value;
      else if (oid === OID_C && !country) country = value;
    }
  }

  return { commonName, organization, organizationalUnit, country };
}

export interface CertInfo {
  subject: CertSubjectInfo;
  issuer: CertSubjectInfo;
  serialNumberHex: string;
  validFrom: string | null;
  validUntil: string | null;
}

export function extractCertInfo(certDer: Uint8Array): CertInfo | null {
  try {
    const cert = parseAsn1(certDer);
    const tbs = cert.children[0];
    if (!tbs || tbs.tag !== TAG_SEQUENCE) return null;

    // tbsCert: [version?] serial sigAlg issuer validity subject ...
    let idx = 0;
    if (tbs.children[0]?.tag === TAG_CONTEXT_0) idx = 1; // skip explicit version

    const serial = tbs.children[idx];
    const issuerDn = tbs.children[idx + 2];
    const validity = tbs.children[idx + 3];
    const subjectDn = tbs.children[idx + 4];

    const serialNumberHex = serial ? bytesToHex(serial.data) : "";
    const issuer = issuerDn ? parseDn(issuerDn) : emptyDn();
    const subject = subjectDn ? parseDn(subjectDn) : emptyDn();

    let validFrom: string | null = null;
    let validUntil: string | null = null;
    if (validity && validity.children.length >= 2) {
      validFrom = parseTimeNode(validity.children[0]);
      validUntil = parseTimeNode(validity.children[1]);
    }

    return { subject, issuer, serialNumberHex, validFrom, validUntil };
  } catch {
    return null;
  }
}

function parseTimeNode(node: Asn1Node): string | null {
  if (node.tag === TAG_UTC_TIME) return parseUtcTime(node.data);
  if (node.tag === TAG_GENERALIZED_TIME) return parseGeneralizedTime(node.data);
  return null;
}

function emptyDn(): CertSubjectInfo {
  return {
    commonName: null,
    organization: null,
    organizationalUnit: null,
    country: null,
  };
}

export function isSelfSigned(certDer: Uint8Array): boolean {
  const info = extractCertInfo(certDer);
  if (!info) return false;
  return (
    info.subject.commonName === info.issuer.commonName &&
    info.subject.organization === info.issuer.organization &&
    info.subject.country === info.issuer.country
  );
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

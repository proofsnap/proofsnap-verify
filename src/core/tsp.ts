// RFC 3161 TimeStampResp / TimeStampToken parsing (CMS SignedData, RFC 5652)
// plus RFC 5035 / RFC 5816 ESS signing-certificate attributes.

import { Asn1, TAG, decodeTime, decodeTimeText, integerBytes, integerNumber, isContext, oidOf, parseDer, retagAsSet } from "./asn1";
import { toHex } from "./bytes";
import { AlgorithmIdentifier, DigestName, digestNameFromOid, parseAlgorithmIdentifier } from "./crypto";
import { OID } from "./oids";
import { DistinguishedName, parseName } from "./x509";

export interface EssCertId {
  hashAlg: DigestName;
  hash: Uint8Array;
  issuerSerial?: { issuerNames: Uint8Array[]; serial: Uint8Array };
}

export interface ParsedTimestamp {
  /** 0 = granted, 1 = grantedWithMods, null when the input was a bare token. */
  pkiStatus: number | null;
  pkiStatusText: string | null;
  tokenRaw: Uint8Array;
  eContentType: string;
  /** DER TSTInfo bytes (the eContent OCTET STRING content). */
  tstInfoRaw: Uint8Array;
  tstVersion: number;
  policyOid: string | null;
  imprintAlg: DigestName | null;
  imprintAlgOid: string | null;
  imprint: Uint8Array;
  serial: string;
  genTime: Date | null;
  genTimeText: string;
  accuracy: { seconds: number; millis: number; micros: number } | null;
  ordering: boolean;
  nonce: string | null;
  tsaName: string | null;
  embeddedCerts: Uint8Array[];
  embeddedCrls: Uint8Array[];
  signer: {
    sidIssuer?: DistinguishedName;
    sidSerial?: Uint8Array;
    sidKeyId?: Uint8Array;
    digestAlg: DigestName | null;
    digestAlgOid: string;
    signatureAlg: AlgorithmIdentifier;
    signature: Uint8Array;
    /** DER SET OF signedAttrs, i.e. the exact bytes the TSA signed. */
    signedAttrsDer: Uint8Array | null;
    contentTypeAttr: string | null;
    messageDigestAttr: Uint8Array | null;
    messageDigestCount: number;
    essCertIds: EssCertId[];
    essVersion: 1 | 2 | null;
    signingTime: Date | null;
  };
  signerInfoCount: number;
}

const PKI_STATUS = ["granted", "grantedWithMods", "rejection", "waiting", "revocationWarning", "revocationNotification"];

/** Accepts a TimeStampResp (RFC 3161 §2.4.2) or a bare TimeStampToken (ContentInfo). */
export function parseTimestamp(bytes: Uint8Array): ParsedTimestamp {
  const root = parseDer(bytes);
  let token: Asn1;
  let pkiStatus: number | null = null;
  let pkiStatusText: string | null = null;
  if (oidOf(root.children[0]) === OID.signedData) {
    token = root;
  } else {
    const statusInfo = root.children[0];
    if (!statusInfo || statusInfo.tag !== TAG.SEQUENCE) throw new Error("not a TimeStampResp or TimeStampToken");
    pkiStatus = integerNumber(statusInfo.children[0]);
    pkiStatusText = PKI_STATUS[pkiStatus] ?? `status ${pkiStatus}`;
    token = root.children[1];
    if (!token) throw new Error(`TSA did not return a token (PKIStatus ${pkiStatusText})`);
  }
  if (oidOf(token.children[0]) !== OID.signedData) throw new Error("token is not CMS SignedData");
  const sd = token.children[1]?.children[0];
  if (!sd || sd.tag !== TAG.SEQUENCE) throw new Error("malformed SignedData");

  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
  //   certificates [0] OPTIONAL, crls [1] OPTIONAL, signerInfos SET }
  const encap = sd.children[2];
  const eContentType = oidOf(encap?.children[0]) ?? "";
  const eContentWrapper = encap?.children[1];
  if (!isContext(eContentWrapper, 0) || eContentWrapper.children[0]?.tag !== TAG.OCTET_STRING) {
    throw new Error("token has no encapsulated TSTInfo");
  }
  const tstInfoRaw = eContentWrapper.children[0].value;
  const tst = parseDer(tstInfoRaw);

  const embeddedCerts: Uint8Array[] = [];
  const embeddedCrls: Uint8Array[] = [];
  for (const c of sd.children.slice(3)) {
    if (isContext(c, 0)) for (const cert of c.children) if (cert.tag === TAG.SEQUENCE) embeddedCerts.push(cert.raw);
    if (isContext(c, 1)) for (const crl of c.children) if (crl.tag === TAG.SEQUENCE) embeddedCrls.push(crl.raw);
  }
  const signerInfos = sd.children[sd.children.length - 1];
  if (signerInfos.tag !== TAG.SET || !signerInfos.children.length) throw new Error("token has no SignerInfo");

  // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
  //   genTime, accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL,
  //   tsa [0] OPTIONAL, extensions [1] OPTIONAL }
  const [verNode, policyNode, imprintNode, serialNode, genTimeNode, ...rest] = tst.children;
  const imprintAlgOid = oidOf(imprintNode?.children[0]?.children[0]);
  let accuracy: ParsedTimestamp["accuracy"] = null;
  let ordering = false;
  let nonce: string | null = null;
  let tsaName: string | null = null;
  for (const n of rest) {
    if (n.tag === TAG.SEQUENCE) {
      accuracy = { seconds: 0, millis: 0, micros: 0 };
      for (const a of n.children) {
        if (a.tag === TAG.INTEGER) accuracy.seconds = integerNumber(a);
        else if (a.tagClass === 2 && a.tagNumber === 0) accuracy.millis = integerNumber(a);
        else if (a.tagClass === 2 && a.tagNumber === 1) accuracy.micros = integerNumber(a);
      }
    } else if (n.tag === TAG.BOOLEAN) ordering = n.value[0] !== 0;
    else if (n.tag === TAG.INTEGER) nonce = toHex(integerBytes(n));
    else if (isContext(n, 0)) {
      try {
        const dn = n.children[0]?.children[0];
        tsaName = dn ? parseName(dn).text : null;
      } catch {
        tsaName = null;
      }
    }
  }

  return {
    pkiStatus,
    pkiStatusText,
    tokenRaw: token.raw,
    eContentType,
    tstInfoRaw,
    tstVersion: verNode ? integerNumber(verNode) : 0,
    policyOid: oidOf(policyNode),
    imprintAlg: digestNameFromOid(imprintAlgOid),
    imprintAlgOid,
    imprint: imprintNode?.children[1]?.value ?? new Uint8Array(),
    serial: serialNode ? toHex(integerBytes(serialNode)) : "",
    genTime: genTimeNode ? decodeTime(genTimeNode) : null,
    genTimeText: genTimeNode ? decodeTimeText(genTimeNode) : "",
    accuracy,
    ordering,
    nonce,
    tsaName,
    embeddedCerts,
    embeddedCrls,
    signer: parseSignerInfo(signerInfos.children[0]),
    signerInfoCount: signerInfos.children.length,
  };
}

function parseSignerInfo(si: Asn1): ParsedTimestamp["signer"] {
  // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, signedAttrs [0] IMPLICIT OPTIONAL,
  //   signatureAlgorithm, signature, unsignedAttrs [1] OPTIONAL }
  const [, sid, digestAlgNode, ...rest] = si.children;
  const out: ParsedTimestamp["signer"] = {
    digestAlg: null,
    digestAlgOid: "",
    signatureAlg: { oid: "" },
    signature: new Uint8Array(),
    signedAttrsDer: null,
    contentTypeAttr: null,
    messageDigestAttr: null,
    messageDigestCount: 0,
    essCertIds: [],
    essVersion: null,
    signingTime: null,
  };
  if (sid?.tag === TAG.SEQUENCE) {
    out.sidIssuer = parseName(sid.children[0]);
    out.sidSerial = integerBytes(sid.children[1]);
  } else if (isContext(sid, 0)) {
    out.sidKeyId = sid.value;
  }
  const dAlg = parseAlgorithmIdentifier(digestAlgNode);
  out.digestAlgOid = dAlg.oid;
  out.digestAlg = digestNameFromOid(dAlg.oid);

  let idx = 0;
  if (isContext(rest[0], 0)) {
    const attrsNode = rest[0];
    out.signedAttrsDer = retagAsSet(attrsNode);
    for (const attr of attrsNode.children) {
      const type = oidOf(attr.children[0]);
      const values = attr.children[1]?.children ?? [];
      if (type === OID.contentType) out.contentTypeAttr = oidOf(values[0]);
      else if (type === OID.messageDigest) {
        out.messageDigestCount += values.length;
        out.messageDigestAttr = values[0]?.value ?? null;
      } else if (type === OID.signingTime && values[0]) out.signingTime = decodeTime(values[0]);
      else if (type === OID.signingCertificate || type === OID.signingCertificateV2) {
        const v2 = type === OID.signingCertificateV2;
        out.essVersion = v2 ? 2 : 1;
        const certs = values[0]?.children[0]?.children ?? [];
        for (const essId of certs) out.essCertIds.push(parseEssCertId(essId, v2));
      }
    }
    idx = 1;
  }
  out.signatureAlg = parseAlgorithmIdentifier(rest[idx]);
  out.signature = rest[idx + 1]?.value ?? new Uint8Array();
  return out;
}

function parseEssCertId(node: Asn1, v2: boolean): EssCertId {
  // ESSCertID   ::= SEQUENCE { certHash OCTET STRING (SHA-1), issuerSerial OPTIONAL }
  // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash, issuerSerial OPTIONAL }
  let i = 0;
  let hashAlg: DigestName = v2 ? "SHA-256" : "SHA-1";
  if (v2 && node.children[0]?.tag === TAG.SEQUENCE) {
    hashAlg = digestNameFromOid(oidOf(node.children[0].children[0])) ?? "SHA-256";
    i = 1;
  }
  const hash = node.children[i]?.value ?? new Uint8Array();
  const is = node.children[i + 1];
  let issuerSerial: EssCertId["issuerSerial"];
  if (is?.tag === TAG.SEQUENCE) {
    const names = (is.children[0]?.children ?? []).filter((g) => isContext(g, 4)).map((g) => g.children[0]?.raw).filter(Boolean) as Uint8Array[];
    issuerSerial = { issuerNames: names, serial: is.children[1] ? integerBytes(is.children[1]) : new Uint8Array() };
  }
  return { hashAlg, hash, issuerSerial };
}

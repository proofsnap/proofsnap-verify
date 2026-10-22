// OCSP (RFC 6960) and CRL (RFC 5280) parsing and verification.

import { Asn1, TAG, bitStringBytes, decodeTime, integerBytes, isContext, oidOf, parseDer } from "./asn1";
import { equalBytes, toHex } from "./bytes";
import { AlgorithmIdentifier, DigestName, digest, digestNameFromOid, parseAlgorithmIdentifier, verifySignature } from "./crypto";
import { OID } from "./oids";
import { Certificate, parseName, tryParseCertificate } from "./x509";

export type CertStatus = "good" | "revoked" | "unknown";

export interface OcspSingle {
  hashAlg: DigestName | null;
  issuerNameHash: Uint8Array;
  issuerKeyHash: Uint8Array;
  serial: Uint8Array;
  status: CertStatus;
  revocationTime: Date | null;
  revocationReason: number | null;
  thisUpdate: Date | null;
  nextUpdate: Date | null;
}

export interface ParsedOcsp {
  responseStatus: number;
  tbsRaw: Uint8Array;
  responderName?: Uint8Array;
  responderKeyHash?: Uint8Array;
  producedAt: Date | null;
  responses: OcspSingle[];
  signatureAlg: AlgorithmIdentifier;
  signature: Uint8Array;
  certs: Uint8Array[];
}

/** Accepts a full OCSPResponse or a bare BasicOCSPResponse. */
export function parseOcsp(der: Uint8Array): ParsedOcsp {
  const root = parseDer(der);
  let basic: Asn1;
  let responseStatus = 0;
  if (root.children[0]?.tag === TAG.ENUMERATED) {
    responseStatus = root.children[0].value[0];
    if (responseStatus !== 0) throw new Error(`OCSP responseStatus ${responseStatus} (not successful)`);
    const rb = root.children[1]?.children[0];
    if (oidOf(rb?.children[0]) !== OID.ocspBasic) throw new Error("unsupported OCSP response type");
    basic = parseDer(rb!.children[1].value);
  } else {
    basic = root;
  }
  const [tbs, sigAlgNode, sigNode, certsWrapper] = basic.children;
  let i = 0;
  if (isContext(tbs.children[0], 0)) i = 1; // version
  const responderId = tbs.children[i];
  const producedAtNode = tbs.children[i + 1];
  const responsesNode = tbs.children[i + 2];
  const out: ParsedOcsp = {
    responseStatus,
    tbsRaw: tbs.raw,
    producedAt: producedAtNode ? decodeTime(producedAtNode) : null,
    responses: [],
    signatureAlg: parseAlgorithmIdentifier(sigAlgNode),
    signature: bitStringBytes(sigNode),
    certs: [],
  };
  if (isContext(responderId, 1)) out.responderName = responderId.children[0]?.raw;
  if (isContext(responderId, 2)) out.responderKeyHash = responderId.children[0]?.value;
  for (const single of responsesNode?.children ?? []) {
    const [certId, statusNode, ...more] = single.children;
    const hashAlg = digestNameFromOid(oidOf(certId.children[0]?.children[0]));
    let status: CertStatus = "unknown";
    let revocationTime: Date | null = null;
    let revocationReason: number | null = null;
    if (statusNode.tagClass === 2 && statusNode.tagNumber === 0) status = "good";
    else if (statusNode.tagClass === 2 && statusNode.tagNumber === 1) {
      status = "revoked";
      revocationTime = statusNode.children[0] ? decodeTime(statusNode.children[0]) : null;
      const r = statusNode.children[1]?.children[0];
      if (r) revocationReason = r.value[0];
    }
    let thisUpdate: Date | null = null;
    let nextUpdate: Date | null = null;
    for (const m of more) {
      if (m.tag === TAG.GENERALIZED_TIME) thisUpdate = decodeTime(m);
      else if (isContext(m, 0) && m.children[0]) nextUpdate = decodeTime(m.children[0]);
    }
    out.responses.push({
      hashAlg,
      issuerNameHash: certId.children[1].value,
      issuerKeyHash: certId.children[2].value,
      serial: integerBytes(certId.children[3]),
      status,
      revocationTime,
      revocationReason,
      thisUpdate,
      nextUpdate,
    });
  }
  if (isContext(certsWrapper, 0)) {
    for (const c of certsWrapper.children[0]?.children ?? []) out.certs.push(c.raw);
  }
  return out;
}

export interface OcspVerification {
  status: CertStatus | null;
  signatureValid: boolean;
  matchesCert: boolean;
  signer: string | null;
  producedAt: string | null;
  thisUpdate: string | null;
  nextUpdate: string | null;
  revocationTime: string | null;
  revocationReason: number | null;
  problems: string[];
}

/**
 * Verifies an OCSP response about `subject` (issued by `issuer`): signature by
 * the CA itself or by a delegated responder carrying id-kp-OCSPSigning issued
 * by that CA, CertID match, and the reported status.
 */
export async function verifyOcsp(der: Uint8Array, subject: Certificate, issuer: Certificate | null): Promise<OcspVerification> {
  const res: OcspVerification = {
    status: null,
    signatureValid: false,
    matchesCert: false,
    signer: null,
    producedAt: null,
    thisUpdate: null,
    nextUpdate: null,
    revocationTime: null,
    revocationReason: null,
    problems: [],
  };
  let ocsp: ParsedOcsp;
  try {
    ocsp = parseOcsp(der);
  } catch (e) {
    res.problems.push(`OCSP response unreadable: ${e instanceof Error ? e.message : e}`);
    return res;
  }
  res.producedAt = ocsp.producedAt?.toISOString() ?? null;

  // CertID match
  let single: OcspSingle | undefined;
  for (const s of ocsp.responses) {
    if (!equalBytes(s.serial, subject.serial)) continue;
    if (issuer && s.hashAlg) {
      const nameHash = await digest(s.hashAlg, subject.issuer.raw);
      const keyHash = await digest(s.hashAlg, issuer.publicKeyBits);
      if (!equalBytes(nameHash, s.issuerNameHash) || !equalBytes(keyHash, s.issuerKeyHash)) continue;
    }
    single = s;
    break;
  }
  if (!single) {
    res.problems.push("OCSP response does not cover the TSA certificate (CertID mismatch)");
    return res;
  }
  res.matchesCert = true;
  res.status = single.status;
  res.thisUpdate = single.thisUpdate?.toISOString() ?? null;
  res.nextUpdate = single.nextUpdate?.toISOString() ?? null;
  res.revocationTime = single.revocationTime?.toISOString() ?? null;
  res.revocationReason = single.revocationReason;

  // Find the responder certificate
  const candidates: Certificate[] = [];
  if (issuer) candidates.push(issuer);
  for (const c of ocsp.certs) {
    const p = tryParseCertificate(c);
    if (p) candidates.push(p);
  }
  for (const cand of candidates) {
    if (ocsp.responderName && !equalBytes(cand.subject.raw, ocsp.responderName)) continue;
    if (ocsp.responderKeyHash) {
      const kh = await digest("SHA-1", cand.publicKeyBits);
      if (!equalBytes(kh, ocsp.responderKeyHash)) continue;
    }
    const sig = await verifySignature(cand.raw && cand.spki.raw, ocsp.signatureAlg, ocsp.signature, ocsp.tbsRaw);
    if (!sig.valid) continue;
    const isIssuer = issuer && equalBytes(cand.raw, issuer.raw);
    if (!isIssuer) {
      // Delegated responder: must be issued by the same CA and carry id-kp-OCSPSigning
      if (!cand.extKeyUsage?.includes(OID.ekuOcspSigning)) {
        res.problems.push("OCSP responder certificate lacks id-kp-OCSPSigning");
        continue;
      }
      if (issuer) {
        const delegatedOk = equalBytes(cand.issuer.raw, issuer.subject.raw) &&
          (await verifySignature(issuer.spki.raw, cand.signatureAlgorithm, cand.signature, cand.tbsRaw)).valid;
        if (!delegatedOk) {
          res.problems.push("OCSP responder certificate is not issued by the TSA's CA");
          continue;
        }
      }
    }
    res.signatureValid = true;
    res.signer = cand.subject.cn ?? cand.subject.text;
    break;
  }
  if (!res.signatureValid) res.problems.push("OCSP response signature could not be verified");
  return res;
}

export interface ParsedCrl {
  tbsRaw: Uint8Array;
  issuer: Uint8Array;
  issuerText: string;
  thisUpdate: Date | null;
  nextUpdate: Date | null;
  revoked: { serial: Uint8Array; date: Date | null; reason: number | null; unknownCritical: boolean }[];
  signatureAlg: AlgorithmIdentifier;
  signature: Uint8Array;
  /** deltaCRLIndicator present: not a complete list. */
  delta: boolean;
  /** issuingDistributionPoint narrows the scope (partitioned, CA or attribute certificates only, some reasons, indirect). */
  scope: string | null;
  unknownCriticalExtension: boolean;
}

const CRL_EXT_REASON = "2.5.29.21";
const CRL_EXT_INVALIDITY_DATE = "2.5.29.24";
const CRL_EXT_DELTA = "2.5.29.27";
const CRL_EXT_IDP = "2.5.29.28";
// cRLNumber, authorityKeyIdentifier, issuingDistributionPoint, deltaCRLIndicator, freshestCRL, expiredCertsOnCRL, authorityInfoAccess
const KNOWN_CRL_EXTS = new Set(["2.5.29.20", "2.5.29.35", CRL_EXT_IDP, CRL_EXT_DELTA, "2.5.29.46", "2.5.29.60", "1.3.6.1.5.5.7.1.1"]);

/** Extensions ::= SEQUENCE OF Extension { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } */
function eachExtension(node: Asn1 | undefined, fn: (oid: string | null, critical: boolean, value: Uint8Array) => void) {
  for (const e of node?.children ?? []) {
    const critical = e.children.length === 3 && e.children[1].tag === TAG.BOOLEAN && e.children[1].value[0] !== 0;
    fn(oidOf(e.children[0]), critical, e.children[e.children.length - 1].value);
  }
}

export function parseCrl(der: Uint8Array): ParsedCrl {
  const root = parseDer(der);
  const [tbs, sigAlgNode, sigNode] = root.children;
  let i = 0;
  if (tbs.children[0]?.tag === TAG.INTEGER) i = 1; // version
  const issuerNode = tbs.children[i + 1];
  const thisUpdateNode = tbs.children[i + 2];
  let j = i + 3;
  let nextUpdate: Date | null = null;
  const maybeNext = tbs.children[j];
  if (maybeNext && (maybeNext.tag === TAG.UTC_TIME || maybeNext.tag === TAG.GENERALIZED_TIME)) {
    nextUpdate = decodeTime(maybeNext);
    j++;
  }
  const revoked: ParsedCrl["revoked"] = [];
  const list = tbs.children[j];
  if (list?.tag === TAG.SEQUENCE) {
    j++;
    for (const entry of list.children) {
      let reason: number | null = null;
      let unknownCritical = false;
      eachExtension(entry.children[2], (oid, critical, value) => {
        if (oid === CRL_EXT_REASON) reason = parseDer(value).value[0] ?? null;
        else if (critical && oid !== CRL_EXT_INVALIDITY_DATE) unknownCritical = true;
      });
      revoked.push({ serial: integerBytes(entry.children[0]), date: entry.children[1] ? decodeTime(entry.children[1]) : null, reason, unknownCritical });
    }
  }
  let delta = false;
  let scope: string | null = null;
  let unknownCriticalExtension = false;
  const extsNode = tbs.children[j];
  if (isContext(extsNode, 0)) {
    eachExtension(extsNode.children[0], (oid, critical, value) => {
      if (oid === CRL_EXT_DELTA) delta = true;
      else if (oid === CRL_EXT_IDP) {
        for (const n of parseDer(value).children) {
          if (isContext(n, 0)) scope ??= "partitioned scope";
          else if (isContext(n, 2) && n.value[0]) scope = "only CA certificates";
          else if (isContext(n, 3)) scope ??= "only some reasons";
          else if (isContext(n, 4) && n.value[0]) scope = "indirect CRL";
          else if (isContext(n, 5) && n.value[0]) scope = "only attribute certificates";
        }
      } else if (critical && !KNOWN_CRL_EXTS.has(oid ?? "")) unknownCriticalExtension = true;
    });
  }
  return {
    tbsRaw: tbs.raw,
    issuer: issuerNode.raw,
    issuerText: parseName(issuerNode).text,
    thisUpdate: thisUpdateNode ? decodeTime(thisUpdateNode) : null,
    nextUpdate,
    revoked,
    signatureAlg: parseAlgorithmIdentifier(sigAlgNode),
    signature: bitStringBytes(sigNode),
    delta,
    scope,
    unknownCriticalExtension,
  };
}

export interface CrlVerification {
  signatureValid: boolean;
  /** The CRL is a complete list for the TSA certificate's issuer, so "not listed" means not revoked. */
  complete: boolean;
  listed: boolean;
  revocationTime: string | null;
  revocationReason: number | null;
  thisUpdate: string | null;
  nextUpdate: string | null;
  problems: string[];
}

export async function verifyCrl(der: Uint8Array, subject: Certificate, issuer: Certificate | null): Promise<CrlVerification> {
  const out: CrlVerification = { signatureValid: false, complete: false, listed: false, revocationTime: null, revocationReason: null, thisUpdate: null, nextUpdate: null, problems: [] };
  let crl: ParsedCrl;
  try {
    crl = parseCrl(der);
  } catch (e) {
    out.problems.push(`CRL unreadable: ${e instanceof Error ? e.message : e}`);
    return out;
  }
  out.thisUpdate = crl.thisUpdate?.toISOString() ?? null;
  out.nextUpdate = crl.nextUpdate?.toISOString() ?? null;
  if (!equalBytes(crl.issuer, subject.issuer.raw)) {
    out.problems.push("CRL issuer does not match the TSA certificate issuer");
    return out;
  }
  if (issuer) {
    out.signatureValid = (await verifySignature(issuer.spki.raw, crl.signatureAlg, crl.signature, crl.tbsRaw)).valid;
    if (!out.signatureValid) out.problems.push("CRL signature invalid");
  } else {
    out.problems.push("CRL issuer certificate not available, CRL signature not verified");
  }
  if (crl.delta) out.problems.push("delta CRL, not a complete list");
  else if (crl.unknownCriticalExtension) out.problems.push("CRL carries an unknown critical extension");
  out.complete = out.signatureValid && !crl.delta && !crl.unknownCriticalExtension && !crl.scope;
  if (crl.scope && !crl.delta) out.problems.push(`CRL scope is limited (${crl.scope}), it cannot show that a certificate is not revoked`);
  const hit = crl.revoked.find((r) => toHex(r.serial) === toHex(subject.serial));
  if (hit && (hit.reason === 8 || hit.unknownCritical)) {
    out.complete = false;
    out.problems.push(hit.reason === 8 ? "CRL entry for the TSA certificate says removeFromCRL" : "CRL entry for the TSA certificate carries an unknown critical extension");
  }
  // A delta CRL, an indirect or attribute-only CRL, an entry with an unknown critical extension and removeFromCRL (8) are not used as "revoked".
  if (hit && !crl.delta && !crl.unknownCriticalExtension && crl.scope !== "indirect CRL" && crl.scope !== "only attribute certificates" && !hit.unknownCritical && hit.reason !== 8) {
    out.listed = true;
    out.revocationTime = hit.date?.toISOString() ?? null;
    out.revocationReason = hit.reason;
  }
  return out;
}

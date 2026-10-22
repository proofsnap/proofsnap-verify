// Full offline verification of an RFC 3161 time-stamp token.
//
// Named checks (each "pass" | "fail" | "warn" | "skip"):
//   response_status      PKIStatus granted / grantedWithMods (TimeStampResp only)
//   message_imprint      TSTInfo messageImprint equals the expected hash (when one is given)
//   content_type         eContentType and the content-type attribute are id-ct-TSTInfo
//   message_digest       messageDigest attribute == digest(TSTInfo)        (RFC 5652 §5.4, §11.2)
//   signature            SignerInfo signature over the DER signedAttrs, single SignerInfo
//   signing_certificate  ESSCertID / ESSCertIDv2 names the signer certificate (RFC 3161 §2.4.1, RFC 5816)
//   tsa_profile          critical EKU id-kp-timeStamping only, not a CA    (RFC 3161 §2.3)
//   chain                path to a trust anchor, every certificate valid at genTime
//   revocation           OCSP / CRL recorded with the token, signature verified, judged at genTime
//   trust                anchored in the EU Trusted List (qualified at genTime), a pinned root, or a user root
//
// Nothing here uses the network.

import { equalBytes, pemBlocks, toHex, fromBase64 } from "./bytes";
import { DigestName, digest, verifySignature } from "./crypto";
import { OID } from "./oids";
import { ParsedTimestamp, parseTimestamp } from "./tsp";
import { Certificate, certSha256, describeCert, tryParseCertificate, validAt } from "./x509";
import { buildChain, ChainResult } from "./chain";
import { verifyCrl, verifyOcsp } from "./revocation";
import { EutlMatch, getEutl, matchEutl } from "./eutl";
import { PINNED_ROOTS } from "./pinned";

export type CheckState = "pass" | "fail" | "warn" | "skip";

export interface LtvData {
  tsaCertChain?: string[];
  rootCaPem?: string | null;
  ocspResponse?: string | null;
  crlResponse?: string | null;
  ocspStatus?: string | null;
}

export interface TimestampOptions {
  /** Hex digest the token must cover. */
  expectedHash?: string;
  /** LTV data recorded at stamping time (eidas_validation.json). */
  ltv?: LtvData | null;
  /** Extra trust anchors (PEM). */
  extraRootsPem?: string;
  /** Skip the EU Trusted List lookup. */
  noEutl?: boolean;
}

export interface TimestampReport {
  valid: boolean;
  /** valid, and revocation status known good (or revoked after genTime for a non-compromise reason). */
  fullyVerified: boolean;
  qualified: boolean;
  checks: Record<string, { state: CheckState; detail: string }>;
  genTime: string | null;
  genTimeText: string;
  accuracy: string | null;
  policyOid: string | null;
  serial: string;
  imprintAlgorithm: string;
  imprint: string;
  nonce: string | null;
  tsa: {
    name: string | null;
    organization: string | null;
    country: string | null;
    serial: string | null;
    notBefore: string | null;
    notAfter: string | null;
    certSha256: string | null;
    qcStatements: string[];
  };
  chain: { subject: string; issuer: string; sha256: string; notBefore: string | null; notAfter: string | null; validAtGenTime: boolean }[];
  trustAnchor: { kind: "eutl" | "pinned" | "user" | "none"; label: string | null; eutl?: EutlMatch };
  revocation: { status: string; source: string | null; detail: string };
  signatureAlgorithm: string | null;
  problems: string[];
}

const COMPROMISE_REASONS = new Set([1, 2, 10]); // keyCompromise, cACompromise, aACompromise
const WEAK: Set<string> = new Set(["SHA-1"]);
const OCSP_WINDOW_SKEW_MS = 120_000;
const OCSP_PRODUCED_BEFORE_GEN_MS = 300_000;
// A "good" status says nothing about the time before its thisUpdate: older than this before genTime it is
// not accepted as the status at genTime, and a status whose nextUpdate passed before genTime is stale.
const MAX_STATUS_AGE_BEFORE_GEN_MS = 7 * 86_400_000;
const STATUS_STALE_SKEW_MS = 3_600_000;

function staleAtGenTime(gen: Date | null, thisUpdate: string | null, nextUpdate: string | null): string | null {
  if (!gen) return null;
  const tu = thisUpdate ? Date.parse(thisUpdate) : NaN;
  const nu = nextUpdate ? Date.parse(nextUpdate) : NaN;
  if (isNaN(tu)) return "no thisUpdate";
  if (tu < gen.getTime() - MAX_STATUS_AGE_BEFORE_GEN_MS) return `issued ${thisUpdate}, more than 7 days before genTime`;
  if (!isNaN(nu) && nu < gen.getTime() - STATUS_STALE_SKEW_MS) return `its nextUpdate ${nextUpdate} is before genTime`;
  return null;
}

function emptyReport(): TimestampReport {
  return {
    valid: false,
    fullyVerified: false,
    qualified: false,
    checks: {},
    genTime: null,
    genTimeText: "",
    accuracy: null,
    policyOid: null,
    serial: "",
    imprintAlgorithm: "unknown",
    imprint: "",
    nonce: null,
    tsa: { name: null, organization: null, country: null, serial: null, notBefore: null, notAfter: null, certSha256: null, qcStatements: [] },
    chain: [],
    trustAnchor: { kind: "none", label: null },
    revocation: { status: "unknown", source: null, detail: "" },
    signatureAlgorithm: null,
    problems: [],
  };
}

function certsFromPem(pem: string | undefined | null): Certificate[] {
  if (!pem) return [];
  return pemBlocks(pem, "CERTIFICATE").map(tryParseCertificate).filter(Boolean) as Certificate[];
}

export async function verifyTimestamp(tsrBytes: Uint8Array, opts: TimestampOptions = {}): Promise<TimestampReport> {
  const r = emptyReport();
  const set = (name: string, state: CheckState, detail = "") => {
    r.checks[name] = { state, detail };
    if (state === "fail") r.problems.push(`${name}: ${detail}`);
  };

  let ts: ParsedTimestamp;
  try {
    ts = parseTimestamp(tsrBytes);
  } catch (e) {
    set("structure", "fail", e instanceof Error ? e.message : String(e));
    return r;
  }
  r.genTime = ts.genTime?.toISOString() ?? null;
  r.genTimeText = ts.genTimeText;
  r.policyOid = ts.policyOid;
  r.serial = ts.serial;
  r.imprintAlgorithm = ts.imprintAlg ?? ts.imprintAlgOid ?? "unknown";
  r.imprint = toHex(ts.imprint);
  r.nonce = ts.nonce;
  if (ts.accuracy) {
    const a = ts.accuracy;
    r.accuracy = `±${a.seconds ? a.seconds + " s " : ""}${a.millis ? a.millis + " ms " : ""}${a.micros ? a.micros + " µs" : ""}`.trim();
  }

  // response_status
  if (ts.pkiStatus === null) set("response_status", "skip", "bare TimeStampToken (no TimeStampResp wrapper)");
  else if (ts.pkiStatus === 0 || ts.pkiStatus === 1) set("response_status", "pass", ts.pkiStatusText ?? "");
  else set("response_status", "fail", ts.pkiStatusText ?? "");

  // message_imprint
  if (opts.expectedHash !== undefined) {
    const expected = opts.expectedHash.toLowerCase();
    if (r.imprint !== expected) set("message_imprint", "fail", `token covers ${r.imprint}, expected ${expected}`);
    else if (!ts.imprintAlg || WEAK.has(ts.imprintAlg)) set("message_imprint", "fail", `imprint algorithm ${r.imprintAlgorithm} not accepted`);
    else set("message_imprint", "pass", `${r.imprintAlgorithm} ${r.imprint}`);
  } else {
    set("message_imprint", "skip", "no expected hash given, the token was inspected only");
  }

  // content_type
  if (ts.eContentType !== OID.tstInfo) set("content_type", "fail", `eContentType ${ts.eContentType}`);
  else if (ts.signer.signedAttrsDer && ts.signer.contentTypeAttr !== OID.tstInfo) set("content_type", "fail", `content-type attribute ${ts.signer.contentTypeAttr ?? "missing"}`);
  else set("content_type", "pass", "id-ct-TSTInfo");

  // message_digest
  const sDigest: DigestName | null = ts.signer.digestAlg;
  if (!ts.signer.signedAttrsDer) set("message_digest", "fail", "SignerInfo carries no signed attributes");
  else if (!sDigest) set("message_digest", "fail", `unsupported digest ${ts.signer.digestAlgOid}`);
  else if (ts.signer.messageDigestCount !== 1 || !ts.signer.messageDigestAttr) set("message_digest", "fail", "message-digest attribute missing or repeated");
  else {
    const d = await digest(sDigest, ts.tstInfoRaw);
    if (equalBytes(d, ts.signer.messageDigestAttr)) set("message_digest", WEAK.has(sDigest) ? "warn" : "pass", `${sDigest} of TSTInfo matches`);
    else set("message_digest", "fail", "message-digest attribute does not match the TSTInfo, the token content was altered");
  }

  // Candidate certificates
  const embedded = ts.embeddedCerts.map(tryParseCertificate).filter(Boolean) as Certificate[];
  const ltvCerts = (opts.ltv?.tsaCertChain ?? []).flatMap((p) => certsFromPem(p));
  const userRoots = certsFromPem(opts.extraRootsPem);
  const pinned = PINNED_ROOTS();
  const pool = dedupe([...embedded, ...ltvCerts, ...pinned.map((p) => p.cert), ...userRoots]);

  // Signer: the certificate named by the SignerInfo sid whose key verifies the signature.
  let signer: Certificate | null = null;
  let sigDetail = "no candidate certificate verifies the signature";
  if (ts.signerInfoCount !== 1) sigDetail = `${ts.signerInfoCount} SignerInfos, exactly one expected`;
  for (const cand of pool) {
    if (ts.signer.sidSerial && ts.signer.sidIssuer) {
      if (!equalBytes(cand.serial, ts.signer.sidSerial) || !equalBytes(cand.issuer.raw, ts.signer.sidIssuer.raw)) continue;
    } else if (ts.signer.sidKeyId) {
      if (cand.subjectKeyId !== toHex(ts.signer.sidKeyId)) continue;
    }
    if (!ts.signer.signedAttrsDer) break;
    const sig = await verifySignature(cand.spki.raw, ts.signer.signatureAlg, ts.signer.signature, ts.signer.signedAttrsDer, sDigest);
    if (sig.valid) {
      signer = cand;
      r.signatureAlgorithm = sig.algorithm;
      sigDetail = sig.algorithm + (sig.weak ? " (weak algorithm)" : "");
      break;
    }
  }
  if (!signer) {
    const anySid = pool.find((c) => ts.signer.sidSerial && equalBytes(c.serial, ts.signer.sidSerial));
    if (!anySid && !embedded.length && !ltvCerts.length) sigDetail = "the token carries no TSA certificate and none was supplied";
    set("signature", "fail", sigDetail);
  } else if (ts.signerInfoCount !== 1) {
    set("signature", "fail", sigDetail);
  } else {
    set("signature", r.signatureAlgorithm?.includes("SHA-1") ? "warn" : "pass", sigDetail);
  }

  // TSA identity: from the verified signer, or the sid-named certificate for diagnostics
  const shown = signer ?? pool.find((c) => ts.signer.sidSerial && equalBytes(c.serial, ts.signer.sidSerial)) ?? embedded[0] ?? null;
  if (shown) {
    r.tsa = {
      name: shown.subject.cn,
      organization: shown.subject.o,
      country: shown.subject.c,
      serial: shown.serialHex,
      notBefore: shown.notBefore?.toISOString() ?? null,
      notAfter: shown.notAfter?.toISOString() ?? null,
      certSha256: await certSha256(shown),
      qcStatements: shown.qcStatements,
    };
  }

  if (!signer) {
    set("signing_certificate", "skip", "signer certificate not identified");
    set("tsa_profile", "skip", "signer certificate not identified");
    set("chain", "skip", "signer certificate not identified");
    set("revocation", "skip", "signer certificate not identified");
    set("trust", "fail", "signer certificate not identified");
    return finish(r);
  }

  // signing_certificate (ESS)
  if (!ts.signer.essCertIds.length) {
    set("signing_certificate", "fail", "no SigningCertificate / SigningCertificateV2 attribute (required by RFC 3161 §2.4.1)");
  } else {
    const ess = ts.signer.essCertIds[0];
    const h = await digest(ess.hashAlg, signer.raw);
    let ok = equalBytes(h, ess.hash);
    let detail = ok ? `ESSCertID${ts.signer.essVersion === 2 ? "v2" : ""} ${ess.hashAlg} names the signer` : "ESS certificate hash does not match the signer certificate";
    if (ok && ess.issuerSerial) {
      const serialOk = equalBytes(ess.issuerSerial.serial, signer.serial);
      const nameOk = !ess.issuerSerial.issuerNames.length || ess.issuerSerial.issuerNames.some((n) => equalBytes(n, signer!.issuer.raw));
      if (!serialOk || !nameOk) {
        ok = false;
        detail = "ESS issuerSerial does not match the signer certificate";
      }
    }
    if (ok && ess.hashAlg === "SHA-1" && !ess.issuerSerial) set("signing_certificate", "warn", detail + " (SHA-1 ESSCertID without issuerSerial)");
    else set("signing_certificate", ok ? "pass" : "fail", detail);
  }

  // tsa_profile
  const prof: string[] = [];
  if (!signer.extKeyUsage) prof.push("no extendedKeyUsage");
  else {
    if (!signer.extKeyUsageCritical) prof.push("extendedKeyUsage is not critical");
    if (signer.extKeyUsage.length !== 1 || signer.extKeyUsage[0] !== OID.ekuTimeStamping) prof.push("extendedKeyUsage is not id-kp-timeStamping only");
  }
  if (signer.isCA) prof.push("signer certificate is a CA certificate");
  if (signer.keyUsage && (signer.keyUsage.includes("keyCertSign") || signer.keyUsage.includes("cRLSign"))) prof.push("keyUsage allows certificate or CRL signing");
  if (ts.genTime && !validAt(signer, ts.genTime)) prof.push(`signer certificate not valid at genTime ${r.genTime}`);
  set("tsa_profile", prof.length ? "fail" : "pass", prof.length ? prof.join("; ") : "critical EKU id-kp-timeStamping, valid at genTime");

  // chain
  const chain: ChainResult = await buildChain(signer, pool, ts.genTime);
  r.chain = chain.links.map((l) => ({
    subject: l.subject,
    issuer: l.issuer,
    sha256: l.sha256,
    notBefore: l.notBefore,
    notAfter: l.notAfter,
    validAtGenTime: l.validAtReference,
  }));
  const chainProblems = [...chain.problems];
  if (chain.links.some((l, i) => l.weakAlgorithm && i < chain.links.length - 1)) chainProblems.push("a certificate in the path is signed with SHA-1");
  if (!chain.signaturesValid || !chain.validAtReference || !chain.caConstraintsOk || chainProblems.length) {
    const hard = !chain.signaturesValid || !chain.validAtReference || !chain.caConstraintsOk;
    set("chain", hard ? "fail" : "warn", chainProblems.join("; ") || "chain incomplete");
  } else {
    set("chain", "pass", `${chain.links.length} certificate${chain.links.length > 1 ? "s" : ""}, all valid at genTime`);
  }

  // trust: EUTL (qualified at genTime) > pinned ProofSnap root > user root
  const linkCerts = chain.links.map((l) => l.cert);
  let eutl: EutlMatch | null = null;
  if (!opts.noEutl) {
    const data = getEutl();
    if (data) eutl = await matchEutl(linkCerts, ts.genTime, data);
  }
  const shas = chain.links.map((l) => l.sha256);
  const pinnedHit = pinned.find((p) => shas.includes(p.sha256));
  const userHit = await (async () => {
    for (const u of userRoots) if (shas.includes(await certSha256(u))) return u;
    return null;
  })();
  if (eutl) {
    r.trustAnchor = { kind: "eutl", label: `${eutl.tsp}, ${eutl.service}`, eutl };
    r.qualified = eutl.qualifiedAtGenTime;
    if (eutl.qualifiedAtGenTime) set("trust", "pass", `qualified time-stamping service on the EU Trusted List at genTime: ${eutl.tsp}`);
    else set("trust", "warn", `listed on the EU Trusted List but status at genTime was "${eutl.statusAtGenTime ?? "unknown"}"`);
  } else if (pinnedHit) {
    r.trustAnchor = { kind: "pinned", label: pinnedHit.label };
    set("trust", "pass", `chains to the pinned root ${pinnedHit.label}`);
  } else if (userHit) {
    r.trustAnchor = { kind: "user", label: describeCert(userHit) };
    set("trust", "pass", `chains to the supplied root ${describeCert(userHit)}`);
  } else {
    set("trust", "warn", chain.endsInSelfSigned ? "chains to a self-signed root that is neither on the EU Trusted List nor pinned" : "no trust anchor reached");
  }
  if (r.trustAnchor.kind !== "none" && !chain.signaturesValid) set("trust", "fail", "trust anchor reached but a signature in the path is invalid");

  // revocation
  const issuer = chain.links[1]?.cert ?? null;
  await checkRevocation(r, set, signer, issuer, ts, opts.ltv ?? null);

  return finish(r);
}

async function checkRevocation(
  r: TimestampReport,
  set: (n: string, s: CheckState, d?: string) => void,
  signer: Certificate,
  issuer: Certificate | null,
  ts: ParsedTimestamp,
  ltv: LtvData | null,
) {
  const gen = ts.genTime;
  const results: { source: string; status: "good" | "revoked" | "unknown"; revokedAt: Date | null; reason: number | null; detail: string }[] = [];
  if (ltv?.ocspResponse) {
    let der: Uint8Array | null = null;
    try {
      der = fromBase64(ltv.ocspResponse);
    } catch {
      results.push({ source: "OCSP", status: "unknown", revokedAt: null, reason: null, detail: "OCSP response is not base64" });
    }
    if (der) {
      const o = await verifyOcsp(der, signer, issuer);
      let status: "good" | "revoked" | "unknown" = "unknown";
      let detail = o.problems.join("; ");
      if (o.signatureValid && o.matchesCert && o.status) {
        status = o.status;
        detail = `signed by ${o.signer}, thisUpdate ${o.thisUpdate}`;
        const stale = status === "good" ? staleAtGenTime(gen, o.thisUpdate, o.nextUpdate) : null;
        if (stale) {
          status = "unknown";
          detail = `OCSP "good" is not current at genTime (${stale})`;
        } else if (status === "good" && gen) {
          const tu = o.thisUpdate ? Date.parse(o.thisUpdate) : NaN;
          const nu = o.nextUpdate ? Date.parse(o.nextUpdate) : NaN;
          const pa = o.producedAt ? Date.parse(o.producedAt) : NaN;
          const g = gen.getTime();
          const outside = g < tu - OCSP_WINDOW_SKEW_MS || (!isNaN(nu) && g > nu + OCSP_WINDOW_SKEW_MS) || (isNaN(nu) && pa < g - OCSP_PRODUCED_BEFORE_GEN_MS);
          if (outside) {
            status = "unknown";
            detail = `OCSP "good" but its validity window does not cover genTime (thisUpdate ${o.thisUpdate})`;
          }
        }
      }
      results.push({ source: "OCSP", status, revokedAt: o.revocationTime ? new Date(o.revocationTime) : null, reason: o.revocationReason, detail });
    }
  }
  if (ltv?.crlResponse) {
    try {
      const c = await verifyCrl(fromBase64(ltv.crlResponse), signer, issuer);
      const stale = c.listed ? null : staleAtGenTime(gen, c.thisUpdate, c.nextUpdate);
      if (c.signatureValid && c.listed) {
        results.push({ source: "CRL", status: "revoked", revokedAt: c.revocationTime ? new Date(c.revocationTime) : null, reason: c.revocationReason, detail: `listed as revoked at ${c.revocationTime}` });
      } else if (c.complete && stale) {
        results.push({ source: "CRL", status: "unknown", revokedAt: null, reason: null, detail: `CRL is not current at genTime (${stale})` });
      } else if (c.complete) {
        results.push({ source: "CRL", status: "good", revokedAt: null, reason: null, detail: `not listed (CRL of ${c.thisUpdate})` });
      } else {
        results.push({ source: "CRL", status: "unknown", revokedAt: null, reason: null, detail: c.problems.join("; ") });
      }
    } catch (e) {
      results.push({ source: "CRL", status: "unknown", revokedAt: null, reason: null, detail: "CRL unreadable" });
    }
  }
  if (!results.length) {
    r.revocation = { status: "unknown", source: null, detail: "no OCSP response or CRL recorded with the token" };
    set("revocation", "warn", r.revocation.detail);
    return;
  }
  const revoked = results.find((x) => x.status === "revoked");
  if (revoked) {
    r.revocation = { status: "revoked", source: revoked.source, detail: revoked.detail };
    if (!gen || !revoked.revokedAt || revoked.revokedAt.getTime() <= gen.getTime()) {
      set("revocation", "fail", `TSA certificate revoked at or before genTime (${revoked.source})`);
    } else if (revoked.reason !== null && COMPROMISE_REASONS.has(revoked.reason)) {
      set("revocation", "fail", `TSA certificate revoked after genTime for key compromise (${revoked.source})`);
    } else {
      r.revocation.status = "revoked_after_gen_time";
      set("revocation", "warn", `TSA certificate revoked after genTime (${revoked.revokedAt.toISOString()}), compromise cannot be excluded`);
    }
    return;
  }
  const ocsp = results.find((x) => x.source === "OCSP");
  const good = (ocsp?.status === "good" ? ocsp : null) ?? (!ocsp || ocsp.status === "good" || !ocsp.detail.includes("window") ? results.find((x) => x.status === "good") : null);
  if (good) {
    r.revocation = { status: "good", source: good.source, detail: good.detail };
    set("revocation", "pass", `${good.source}: good, ${good.detail}`);
    return;
  }
  r.revocation = { status: "unknown", source: results[0].source, detail: results.map((x) => `${x.source}: ${x.detail}`).join("; ") };
  set("revocation", "warn", r.revocation.detail);
}

function dedupe(certs: Certificate[]): Certificate[] {
  const out: Certificate[] = [];
  for (const c of certs) if (!out.some((o) => equalBytes(o.raw, c.raw))) out.push(c);
  return out;
}

function finish(r: TimestampReport): TimestampReport {
  const states = Object.values(r.checks).map((c) => c.state);
  r.valid = !states.includes("fail") && r.checks.signature?.state !== undefined && r.checks.signature.state !== "skip";
  r.fullyVerified = r.valid && r.checks.revocation?.state === "pass" && r.checks.trust?.state === "pass";
  return r;
}

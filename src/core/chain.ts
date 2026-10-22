// Certificate path building and validation at a reference time (the
// timestamp's genTime), not at "now": a TSA certificate that has expired
// since stamping does not invalidate tokens it issued while valid.

import { equalBytes } from "./bytes";
import { verifySignature } from "./crypto";
import { Certificate, certSha256, describeCert, validAt } from "./x509";

export interface ChainLink {
  cert: Certificate;
  sha256: string;
  subject: string;
  issuer: string;
  notBefore: string | null;
  notAfter: string | null;
  validAtReference: boolean;
  signatureValid: boolean | null; // null for the last element when its issuer is unknown
  weakAlgorithm: boolean;
}

export interface ChainResult {
  links: ChainLink[];
  /** Chain ends in a self-signed certificate whose signature verifies. */
  endsInSelfSigned: boolean;
  /** Every signature along the path verified. */
  signaturesValid: boolean;
  /** Every certificate was within its validity period at the reference time. */
  validAtReference: boolean;
  /** Intermediate certificates are CAs. */
  caConstraintsOk: boolean;
  problems: string[];
}

function issuerMatches(child: Certificate, cand: Certificate): boolean {
  if (!equalBytes(child.issuer.raw, cand.subject.raw)) return false;
  if (child.authorityKeyId && cand.subjectKeyId && child.authorityKeyId !== cand.subjectKeyId) return false;
  return true;
}

/**
 * Builds the path from `leaf` upward using certificates in `pool`.
 * Stops at a self-signed certificate or when no issuer is found.
 */
export async function buildChain(leaf: Certificate, pool: Certificate[], referenceTime: Date | null): Promise<ChainResult> {
  const problems: string[] = [];
  const links: ChainLink[] = [];
  const seen = new Set<string>();
  let current: Certificate | null = leaf;
  let endsInSelfSigned = false;
  let signaturesValid = true;
  let caConstraintsOk = true;

  while (current) {
    const sha = await certSha256(current);
    if (seen.has(sha)) break;
    seen.add(sha);
    const link: ChainLink = {
      cert: current,
      sha256: sha,
      subject: current.subject.text,
      issuer: current.issuer.text,
      notBefore: current.notBefore?.toISOString() ?? null,
      notAfter: current.notAfter?.toISOString() ?? null,
      validAtReference: referenceTime ? validAt(current, referenceTime) : true,
      signatureValid: null,
      weakAlgorithm: false,
    };
    links.push(link);
    if (links.length > 10) {
      problems.push("certificate chain longer than 10, aborted");
      break;
    }

    if (current.selfIssued) {
      const sig = await verifySignature(current.spki.raw, current.signatureAlgorithm, current.signature, current.tbsRaw);
      link.signatureValid = sig.valid;
      link.weakAlgorithm = !!sig.weak;
      if (sig.valid) {
        endsInSelfSigned = true;
        break;
      }
    }

    let next: Certificate | null = null;
    for (const cand of pool) {
      if (cand === current || !issuerMatches(current, cand)) continue;
      const sig = await verifySignature(cand.spki.raw, current.signatureAlgorithm, current.signature, current.tbsRaw);
      if (sig.valid) {
        link.signatureValid = true;
        // SHA-1 on a self-signed root is harmless (the root is trusted by
        // identity, not by its own signature); on other links it matters.
        link.weakAlgorithm = !!sig.weak && !cand.selfIssued;
        next = cand;
        break;
      }
    }
    if (!next) {
      if (!current.selfIssued) problems.push(`issuer of "${describeCert(current)}" not available in the token or LTV data`);
      else {
        link.signatureValid = false;
        signaturesValid = false;
        problems.push(`self-signed certificate "${describeCert(current)}" has an invalid signature`);
      }
      break;
    }
    if (!next.isCA && !next.selfIssued) {
      caConstraintsOk = false;
      problems.push(`"${describeCert(next)}" issues certificates but is not marked as a CA`);
    }
    current = next;
  }

  for (const l of links) {
    if (l.signatureValid === false) signaturesValid = false;
  }
  const validAtRef = links.every((l) => l.validAtReference);
  if (!validAtRef && referenceTime) {
    for (const l of links) {
      if (!l.validAtReference) problems.push(`"${describeCert(l.cert)}" was not valid at ${referenceTime.toISOString()}`);
    }
  }
  return { links, endsInSelfSigned, signaturesValid, validAtReference: validAtRef, caConstraintsOk, problems };
}

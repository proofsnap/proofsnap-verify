import { importSpkiKey, verifySig } from "./crypto";
import {
  parseAsn1,
  pemToDer,
  extractTsrMessageImprint,
  extractTsrSignatureData,
  extractTsrHashAlgorithmOid,
  extractTsrPolicyOid,
  extractTsrSerialNumber,
  extractTsrGenTime,
  extractEmbeddedCerts,
  extractCertTbsAndSignature,
  extractSpkiFromCert,
  extractCertInfo,
  parseOcspCertStatus,
  hashAlgorithmName,
} from "./asn1";
import {
  TimestampInspectionResult,
  TsaInfo,
  EidasLtvData,
  InspectOptions,
} from "./types";
import {
  loadDefaultTrustedRoots,
  matchTrustedRoot,
  TrustedRootMatch,
} from "./trustedRoots";

export async function inspectTimestamp(
  tsrBytes: Uint8Array,
  options: InspectOptions = {}
): Promise<TimestampInspectionResult> {
  const warnings: string[] = [];
  const errors: string[] = [];

  let tsrRoot;
  try {
    tsrRoot = parseAsn1(tsrBytes);
  } catch (err) {
    return badResult(
      "TSR_PARSE_ERROR",
      err instanceof Error ? err.message : "Failed to parse TSR"
    );
  }

  const messageImprint = extractTsrMessageImprint(tsrRoot);
  const hashOid = extractTsrHashAlgorithmOid(tsrRoot);
  const policyOid = extractTsrPolicyOid(tsrRoot);
  const serialNumber = extractTsrSerialNumber(tsrRoot);
  const timestampedAt = extractTsrGenTime(tsrRoot);

  if (!messageImprint || !hashOid) {
    errors.push("TSR_MISSING_MESSAGE_IMPRINT");
  }

  // Resolve cert chain candidates: prefer ltvData (caller-curated, ordered),
  // fall back to TSR-embedded certs (CMS [0] set, order not guaranteed).
  let certChainDer: Uint8Array[];
  if (options.ltvData?.tsaCertChain && options.ltvData.tsaCertChain.length > 0) {
    certChainDer = options.ltvData.tsaCertChain.map((pem) => pemToDer(pem));
    if (options.ltvData.rootCaPem) {
      certChainDer.push(pemToDer(options.ltvData.rootCaPem));
    }
  } else {
    certChainDer = extractEmbeddedCerts(tsrRoot);
    if (certChainDer.length > 0) {
      warnings.push(
        "Certificate chain extracted from TSR (no LTV data provided)"
      );
    } else {
      warnings.push(
        "No certificate chain available — signature cannot be verified"
      );
    }
  }

  // Find the TSA signer cert. RFC 5652 places certs in a SET (no order),
  // so we try every candidate and accept the one whose public key verifies
  // the TSR signature. With ltvData the [0] cert is conventionally the leaf
  // and the loop short-circuits on the first try.
  let leafCertDer: Uint8Array | null = null;
  let signatureValid = false;
  if (certChainDer.length > 0) {
    for (const candidate of certChainDer) {
      try {
        if (await verifyTsrSignature(tsrBytes, candidate)) {
          leafCertDer = candidate;
          signatureValid = true;
          break;
        }
      } catch (err) {
        errors.push(
          `SIGNATURE_ERROR: ${err instanceof Error ? err.message : "unknown"}`
        );
        // Keep trying other candidates — one bad cert shouldn't kill the whole
        // verification.
      }
    }
    if (!signatureValid && leafCertDer === null) {
      // No cert verified the signature; fall back to first candidate so the
      // user still sees TSA identity for diagnostics.
      leafCertDer = certChainDer[0];
    }
  }

  // Extract TSA info from the resolved leaf cert
  const tsa: TsaInfo = {
    commonName: null,
    organization: null,
    country: null,
    serialNumberHex: null,
    validFrom: null,
    validUntil: null,
  };
  if (leafCertDer) {
    const leafInfo = extractCertInfo(leafCertDer);
    if (leafInfo) {
      tsa.commonName = leafInfo.subject.commonName;
      tsa.organization = leafInfo.subject.organization;
      tsa.country = leafInfo.subject.country;
      tsa.serialNumberHex = leafInfo.serialNumberHex;
      tsa.validFrom = leafInfo.validFrom;
      tsa.validUntil = leafInfo.validUntil;
    }
  }

  // Cert chain consistency. Inherits a known limit from the legacy verifier:
  // assumes leaf→root ordering. Misordered embedded certs would fail this
  // check even when a valid chain exists. With ltvData the chain is curated
  // by the issuer (e.g. ProofSnap) and ordering holds.
  let certChainValid = false;
  if (certChainDer.length > 0) {
    try {
      certChainValid = await verifyCertChain(certChainDer);
    } catch (err) {
      errors.push(
        `CERT_CHAIN_ERROR: ${err instanceof Error ? err.message : "unknown"}`
      );
    }
  }

  // Match top of chain against trusted EUTL roots
  let trustedRootMatch: TrustedRootMatch | null = null;
  if (certChainDer.length > 0) {
    const trustedRoots =
      options.trustedRootsPem !== undefined
        ? options.trustedRootsPem
        : loadDefaultTrustedRoots();
    if (trustedRoots) {
      trustedRootMatch = await matchTrustedRoot(certChainDer, trustedRoots);
      if (!trustedRootMatch) {
        warnings.push(
          "Chain root not found in trusted EUTL list — TRUST UNVERIFIED. Use --roots to provide a bundle."
        );
      }
    } else {
      warnings.push(
        "No trusted roots bundle loaded — TRUST UNVERIFIED. Use --roots to provide one."
      );
    }
  }
  const trustsKnownEUTL = trustedRootMatch !== null;

  // OCSP: only verifiable from ltvData
  let ocspValid: boolean | null = null;
  if (options.ltvData?.ocspResponse) {
    try {
      ocspValid = verifyOcspStatus(options.ltvData);
    } catch {
      ocspValid = false;
      warnings.push("OCSP_PARSE_ERROR");
    }
  } else if (options.ltvData?.ocspStatus === "good") {
    ocspValid = true;
  } else {
    warnings.push(
      "OCSP not checked (no LTV data) — TSA revocation status unknown"
    );
  }

  // Hash match (if expected hash provided)
  if (options.expectedHash !== undefined) {
    const expectedLc = options.expectedHash.toLowerCase();
    const actualLc = (messageImprint || "").toLowerCase();
    if (actualLc !== expectedLc) {
      errors.push("HASH_MISMATCH");
    }
  }

  const overallValid =
    signatureValid &&
    certChainValid &&
    (ocspValid === null || ocspValid === true) &&
    errors.length === 0;

  return {
    tsa,
    timestampedAt,
    hashAlgorithm: hashOid ? hashAlgorithmName(hashOid) : "unknown",
    messageImprint: messageImprint || "",
    policyOid,
    serialNumber,
    signatureValid,
    certChainValid,
    trustsKnownEUTL,
    trustedRootMatch: trustedRootMatch
      ? {
          commonName: trustedRootMatch.commonName,
          country: trustedRootMatch.country,
        }
      : null,
    ocspValid,
    warnings,
    errors,
    overallValid,
  };
}

function badResult(code: string, msg: string): TimestampInspectionResult {
  return {
    tsa: {
      commonName: null,
      organization: null,
      country: null,
      serialNumberHex: null,
      validFrom: null,
      validUntil: null,
    },
    timestampedAt: null,
    hashAlgorithm: "unknown",
    messageImprint: "",
    policyOid: null,
    serialNumber: null,
    signatureValid: false,
    certChainValid: false,
    trustsKnownEUTL: false,
    trustedRootMatch: null,
    ocspValid: null,
    warnings: [],
    errors: [`${code}: ${msg}`],
    overallValid: false,
  };
}

async function verifyTsrSignature(
  tsrBytes: Uint8Array,
  tsaCertDer: Uint8Array
): Promise<boolean> {
  const tsrRoot = parseAsn1(tsrBytes);
  const sigData = extractTsrSignatureData(tsrRoot);
  if (!sigData) return false;

  const spki = extractSpkiFromCert(tsaCertDer);
  if (!spki) return false;

  const hashAlg =
    sigData.digestAlgorithmOid === "2.16.840.1.101.3.4.2.1"
      ? "SHA-256"
      : sigData.digestAlgorithmOid === "2.16.840.1.101.3.4.2.2"
        ? "SHA-384"
        : sigData.digestAlgorithmOid === "2.16.840.1.101.3.4.2.3"
          ? "SHA-512"
          : "SHA-256";

  try {
    const publicKey = await importSpkiKey(spki, hashAlg);
    return await verifySig(
      publicKey,
      sigData.signatureBytes,
      sigData.signedAttrsBytes
    );
  } catch {
    return false;
  }
}

async function verifyCertChain(certs: Uint8Array[]): Promise<boolean> {
  if (certs.length === 0) return false;
  // Single-cert "chain" cannot be cryptographically validated against an
  // anchor on its own. Returning true matches the legacy ProofSnap verifier
  // (chrome ext eidas-ltv-verifier.ts), which treats a one-element chain as
  // structurally OK and lets the trusted-root match decide overall trust.
  if (certs.length === 1) return true;

  for (let i = 0; i < certs.length - 1; i++) {
    const valid = await verifyCertSignedBy(certs[i], certs[i + 1]);
    if (!valid) return false;
  }

  // Topmost cert must be self-signed (i.e., a root).
  return await verifyCertSignedBy(
    certs[certs.length - 1],
    certs[certs.length - 1]
  );
}

async function verifyCertSignedBy(
  certDer: Uint8Array,
  issuerDer: Uint8Array
): Promise<boolean> {
  const certData = extractCertTbsAndSignature(certDer);
  if (!certData) return false;

  const issuerSpki = extractSpkiFromCert(issuerDer);
  if (!issuerSpki) return false;

  const hashAlg = getHashAlgFromSigOid(certData.signatureAlgorithmOid);

  try {
    const issuerKey = await importSpkiKey(issuerSpki, hashAlg);
    return await verifySig(
      issuerKey,
      certData.signatureBytes,
      certData.tbsBytes
    );
  } catch {
    return false;
  }
}

function getHashAlgFromSigOid(oid: string): string {
  const map: Record<string, string> = {
    "1.2.840.113549.1.1.11": "SHA-256",
    "1.2.840.113549.1.1.12": "SHA-384",
    "1.2.840.113549.1.1.13": "SHA-512",
    "1.2.840.113549.1.1.5": "SHA-1",
  };
  return map[oid] || "SHA-256";
}

function verifyOcspStatus(ltvData: EidasLtvData): boolean {
  if (ltvData.ocspStatus === "good") return true;

  if (ltvData.ocspResponse) {
    try {
      const ocspDer = Buffer.from(ltvData.ocspResponse, "base64");
      const status = parseOcspCertStatus(new Uint8Array(ocspDer));
      return status === "good";
    } catch {
      return false;
    }
  }

  return false;
}

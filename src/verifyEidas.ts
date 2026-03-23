import { sha256 } from "./crypto";
import { importSpkiKey, verifySig } from "./crypto";
import {
  parseAsn1,
  pemToDer,
  bytesToHex,
  extractTsrMessageImprint,
  extractTsrSignatureData,
  extractCertTbsAndSignature,
  extractSpkiFromCert,
  parseOcspCertStatus,
} from "./asn1";
import { EidasResult, EidasLtvData } from "./types";

export async function verifyEidas(
  manifestContent: string,
  tsrBytes: Uint8Array,
  ltvData: EidasLtvData
): Promise<EidasResult> {
  const details: string[] = [];
  let hashMatch = false;
  let signatureValid = false;
  let certChainValid = false;
  let ocspValid: boolean | null = null;

  // Step 1: Verify hash match
  try {
    const manifestBytes = new TextEncoder().encode(manifestContent);
    const manifestHash = await sha256(manifestBytes);
    const tsrRoot = parseAsn1(tsrBytes);
    const tsrHash = extractTsrMessageImprint(tsrRoot);

    hashMatch = tsrHash !== null && manifestHash === tsrHash;
    details.push(hashMatch ? "HASH_MATCH" : "HASH_MISMATCH");
  } catch {
    details.push("HASH_ERROR");
  }

  // Step 2: Verify TSR signature
  try {
    signatureValid = await verifyTsrSignature(tsrBytes, ltvData);
    details.push(signatureValid ? "SIGNATURE_VALID" : "SIGNATURE_INVALID");
  } catch {
    details.push("SIGNATURE_ERROR");
  }

  // Step 3: Verify certificate chain
  try {
    certChainValid = await verifyCertChain(ltvData);
    details.push(certChainValid ? "CERT_CHAIN_VALID" : "CERT_CHAIN_INVALID");
  } catch {
    details.push("CERT_CHAIN_ERROR");
  }

  // Step 4: Verify OCSP status
  try {
    if (ltvData.ocspResponse) {
      ocspValid = verifyOcspStatus(ltvData);
      details.push(ocspValid ? "OCSP_GOOD" : "OCSP_NOT_GOOD");
    } else {
      details.push("OCSP_MISSING");
    }
  } catch {
    details.push("OCSP_ERROR");
  }

  const overallValid =
    hashMatch && signatureValid && certChainValid && ocspValid !== false;

  return { hashMatch, signatureValid, certChainValid, ocspValid, overallValid, details };
}

async function verifyTsrSignature(
  tsrBytes: Uint8Array,
  ltvData: EidasLtvData
): Promise<boolean> {
  if (!ltvData.tsaCertChain || ltvData.tsaCertChain.length === 0) return false;

  const tsrRoot = parseAsn1(tsrBytes);
  const sigData = extractTsrSignatureData(tsrRoot);
  if (!sigData) return false;

  const tsaCertPem = ltvData.tsaCertChain[0];
  const tsaCertDer = pemToDer(tsaCertPem);
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
    return await verifySig(publicKey, sigData.signatureBytes, sigData.signedAttrsBytes);
  } catch {
    return false;
  }
}

async function verifyCertChain(ltvData: EidasLtvData): Promise<boolean> {
  if (!ltvData.tsaCertChain || ltvData.tsaCertChain.length === 0) return false;

  const certs: Uint8Array[] = ltvData.tsaCertChain.map((pem) => pemToDer(pem));
  if (ltvData.rootCaPem) {
    certs.push(pemToDer(ltvData.rootCaPem));
  }

  if (certs.length < 2) {
    return certs.length === 1;
  }

  for (let i = 0; i < certs.length - 1; i++) {
    const valid = await verifyCertSignedBy(certs[i], certs[i + 1]);
    if (!valid) return false;
  }

  return await verifyCertSignedBy(certs[certs.length - 1], certs[certs.length - 1]);
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
    return await verifySig(issuerKey, certData.signatureBytes, certData.tbsBytes);
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

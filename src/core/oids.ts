export const OID = {
  // CMS / TSP
  signedData: "1.2.840.113549.1.7.2",
  data: "1.2.840.113549.1.7.1",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",

  // X.509 extensions
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  crlDistributionPoints: "2.5.29.31",
  authorityKeyIdentifier: "2.5.29.35",
  extKeyUsage: "2.5.29.37",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  qcStatements: "1.3.6.1.5.5.7.1.3",
  ocspNoCheck: "1.3.6.1.5.5.7.48.1.5",
  ocspAccess: "1.3.6.1.5.5.7.48.1",
  caIssuers: "1.3.6.1.5.5.7.48.2",

  // EKU
  ekuTimeStamping: "1.3.6.1.5.5.7.3.8",
  ekuOcspSigning: "1.3.6.1.5.5.7.3.9",

  // OCSP
  ocspBasic: "1.3.6.1.5.5.7.48.1.1",

  // ETSI
  etsiQcCompliance: "0.4.0.1862.1.1",
  etsiQtstStatement: "0.4.0.19422.1.1",
  etsiBestPracticesTsPolicy: "0.4.0.2023.1.1",

  // Names
  cn: "2.5.4.3",
  serialNumber: "2.5.4.5",
  c: "2.5.4.6",
  l: "2.5.4.7",
  o: "2.5.4.10",
  ou: "2.5.4.11",
  organizationIdentifier: "2.5.4.97",

  // Keys
  rsaEncryption: "1.2.840.113549.1.1.1",
  rsassaPss: "1.2.840.113549.1.1.10",
  ecPublicKey: "1.2.840.10045.2.1",
  ed25519: "1.3.101.112",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  mgf1: "1.2.840.113549.1.1.8",
} as const;

export const DIGEST_OIDS: Record<string, "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"> = {
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};

/** Signature algorithm OID -> [key family, digest]. */
export const SIGNATURE_OIDS: Record<string, { family: "RSA" | "RSA-PSS" | "ECDSA" | "Ed25519"; hash?: string }> = {
  "1.2.840.113549.1.1.5": { family: "RSA", hash: "SHA-1" },
  "1.2.840.113549.1.1.11": { family: "RSA", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { family: "RSA", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { family: "RSA", hash: "SHA-512" },
  "1.2.840.113549.1.1.10": { family: "RSA-PSS" },
  "1.2.840.10045.4.1": { family: "ECDSA", hash: "SHA-1" },
  "1.2.840.10045.4.3.2": { family: "ECDSA", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { family: "ECDSA", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { family: "ECDSA", hash: "SHA-512" },
  "1.3.101.112": { family: "Ed25519" },
  // In CMS SignerInfo the signatureAlgorithm is often plain rsaEncryption and
  // the digest comes from digestAlgorithm.
  "1.2.840.113549.1.1.1": { family: "RSA" },
  "1.2.840.10045.2.1": { family: "ECDSA" },
};

export const NAME_LABELS: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.97": "organizationIdentifier",
  "1.2.840.113549.1.9.1": "emailAddress",
};

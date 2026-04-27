export interface FileCheckResult {
  name: string;
  expected: string;
  actual: string;
  match: boolean;
}

export interface HashChainResult {
  valid: boolean;
  entries: number;
  chainSelfValid: boolean;
  finalHashMatch: boolean | null;
  forensicLogHashMatch: boolean;
  evidenceIdConsistent: boolean;
}

export interface OtsResult {
  verified: boolean;
  pending: boolean;
  bitcoinHeight?: number;
  timestamp?: string;
  error?: string;
}

export interface EidasResult {
  hashMatch: boolean;
  signatureValid: boolean;
  certChainValid: boolean;
  ocspValid: boolean | null;
  overallValid: boolean;
  details: string[];
}

export interface VerifyResult {
  evidenceId: string;
  signature: { valid: boolean; algorithm: string };
  files: FileCheckResult[];
  hashChain: HashChainResult | null;
  ots: OtsResult | null;
  eidas: EidasResult | null;
  overallValid: boolean;
}

export interface EidasLtvData {
  tsaCertChain: string[];
  rootCaPem: string | null;
  ocspResponse: string | null;
  ocspUrl: string | null;
  ocspStatus: string | null;
  ocspFetchedAt: string | null;
  crlUrl: string | null;
  crlResponse: string | null;
}

export interface TsaInfo {
  commonName: string | null;
  organization: string | null;
  country: string | null;
  serialNumberHex: string | null;
  validFrom: string | null;
  validUntil: string | null;
}

export interface TimestampInspectionResult {
  tsa: TsaInfo;
  timestampedAt: string | null;
  hashAlgorithm: string;
  messageImprint: string;
  policyOid: string | null;
  serialNumber: string | null;
  signatureValid: boolean;
  certChainValid: boolean;
  trustsKnownEUTL: boolean;
  trustedRootMatch: { commonName: string; country: string } | null;
  ocspValid: boolean | null;
  warnings: string[];
  errors: string[];
  overallValid: boolean;
}

export interface FileTimestampResult {
  fileName?: string;
  fileSize: number;
  fileHash: string;
  hashAlgorithm: string;
  hashCoversFile: boolean;
  tsr: TimestampInspectionResult;
  overallValid: boolean;
}

export interface InspectOptions {
  ltvData?: EidasLtvData;
  trustedRootsPem?: string;
  expectedHash?: string;
}

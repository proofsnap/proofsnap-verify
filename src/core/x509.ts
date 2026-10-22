import {
  Asn1,
  TAG,
  bitStringBytes,
  decodeString,
  decodeTime,
  integerBytes,
  isContext,
  oidOf,
  parseDer,
} from "./asn1";
import { equalBytes, toHex } from "./bytes";
import { AlgorithmIdentifier, digest, parseAlgorithmIdentifier, parseSpki, SpkiInfo } from "./crypto";
import { NAME_LABELS, OID } from "./oids";

export interface DistinguishedName {
  raw: Uint8Array;
  attrs: { oid: string; label: string; value: string }[];
  text: string;
  cn: string | null;
  o: string | null;
  c: string | null;
  organizationIdentifier: string | null;
}

export interface Certificate {
  raw: Uint8Array;
  tbsRaw: Uint8Array;
  signatureAlgorithm: AlgorithmIdentifier;
  signature: Uint8Array;
  version: number;
  serial: Uint8Array;
  serialHex: string;
  issuer: DistinguishedName;
  subject: DistinguishedName;
  notBefore: Date | null;
  notAfter: Date | null;
  spki: SpkiInfo;
  /** BIT STRING content of subjectPublicKey (used for OCSP issuerKeyHash). */
  publicKeyBits: Uint8Array;
  extensions: Map<string, { critical: boolean; value: Uint8Array }>;
  isCA: boolean;
  pathLen: number | null;
  keyUsage: string[] | null;
  extKeyUsage: string[] | null;
  extKeyUsageCritical: boolean;
  subjectKeyId: string | null;
  authorityKeyId: string | null;
  ocspUrls: string[];
  caIssuerUrls: string[];
  crlUrls: string[];
  qcStatements: string[];
  ocspNoCheck: boolean;
  selfIssued: boolean;
}

export function parseName(node: Asn1): DistinguishedName {
  const attrs: DistinguishedName["attrs"] = [];
  for (const rdn of node.children) {
    for (const atv of rdn.children) {
      const oid = oidOf(atv.children[0]);
      if (!oid || !atv.children[1]) continue;
      attrs.push({ oid, label: NAME_LABELS[oid] ?? oid, value: decodeString(atv.children[1]) });
    }
  }
  const get = (oid: string) => attrs.find((a) => a.oid === oid)?.value ?? null;
  return {
    raw: node.raw,
    attrs,
    text: attrs.map((a) => `${a.label}=${a.value}`).join(", "),
    cn: get(OID.cn),
    o: get(OID.o),
    c: get(OID.c),
    organizationIdentifier: get(OID.organizationIdentifier),
  };
}

const KEY_USAGE_NAMES = [
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly",
];

function generalNameUris(seq: Asn1): string[] {
  // GeneralName uniformResourceIdentifier is [6] IMPLICIT IA5String
  const out: string[] = [];
  const walk = (n: Asn1) => {
    if (n.tagClass === 2 && n.tagNumber === 6 && !n.constructed) out.push(new TextDecoder("ascii").decode(n.value));
    n.children.forEach(walk);
  };
  walk(seq);
  return out;
}

export function parseCertificate(der: Uint8Array): Certificate {
  const cert = parseDer(der);
  const [tbs, sigAlgNode, sigNode] = cert.children;
  if (!tbs || !sigAlgNode || !sigNode) throw new Error("malformed certificate");
  let i = 0;
  let version = 1;
  if (isContext(tbs.children[0], 0)) {
    version = (tbs.children[0].children[0]?.value[0] ?? 0) + 1;
    i = 1;
  }
  const serialNode = tbs.children[i];
  const issuerNode = tbs.children[i + 2];
  const validity = tbs.children[i + 3];
  const subjectNode = tbs.children[i + 4];
  const spkiNode = tbs.children[i + 5];
  const spki = parseSpki(spkiNode.raw);

  const extensions = new Map<string, { critical: boolean; value: Uint8Array }>();
  const extWrapper = tbs.children.find((c) => isContext(c, 3));
  if (extWrapper?.children[0]) {
    for (const ext of extWrapper.children[0].children) {
      const oid = oidOf(ext.children[0]);
      if (!oid) continue;
      const critical = ext.children[1]?.tag === TAG.BOOLEAN ? ext.children[1].value[0] !== 0 : false;
      const valueNode = ext.children[ext.children.length - 1];
      extensions.set(oid, { critical, value: valueNode.value });
    }
  }

  const c: Certificate = {
    raw: der,
    tbsRaw: tbs.raw,
    signatureAlgorithm: parseAlgorithmIdentifier(sigAlgNode),
    signature: bitStringBytes(sigNode),
    version,
    serial: integerBytes(serialNode),
    serialHex: toHex(integerBytes(serialNode)),
    issuer: parseName(issuerNode),
    subject: parseName(subjectNode),
    notBefore: validity?.children[0] ? decodeTime(validity.children[0]) : null,
    notAfter: validity?.children[1] ? decodeTime(validity.children[1]) : null,
    spki,
    publicKeyBits: spki.publicKey,
    extensions,
    isCA: false,
    pathLen: null,
    keyUsage: null,
    extKeyUsage: null,
    extKeyUsageCritical: false,
    subjectKeyId: null,
    authorityKeyId: null,
    ocspUrls: [],
    caIssuerUrls: [],
    crlUrls: [],
    qcStatements: [],
    ocspNoCheck: extensions.has(OID.ocspNoCheck),
    selfIssued: false,
  };
  c.selfIssued = equalBytes(c.issuer.raw, c.subject.raw);

  const tryExt = (oid: string, fn: (n: Asn1) => void) => {
    const e = extensions.get(oid);
    if (!e) return;
    try {
      fn(parseDer(e.value));
    } catch {
      /* ignore malformed extension */
    }
  };
  tryExt(OID.basicConstraints, (n) => {
    c.isCA = n.children[0]?.tag === TAG.BOOLEAN && n.children[0].value[0] !== 0;
    const pl = n.children.find((x) => x.tag === TAG.INTEGER);
    if (pl) c.pathLen = pl.value[0];
  });
  tryExt(OID.keyUsage, (n) => {
    const bits = bitStringBytes(n);
    c.keyUsage = KEY_USAGE_NAMES.filter((_, idx) => (bits[idx >> 3] ?? 0) & (0x80 >> (idx & 7)));
  });
  tryExt(OID.extKeyUsage, (n) => {
    c.extKeyUsage = n.children.map((x) => oidOf(x) ?? "");
    c.extKeyUsageCritical = extensions.get(OID.extKeyUsage)!.critical;
  });
  tryExt(OID.subjectKeyIdentifier, (n) => (c.subjectKeyId = toHex(n.value)));
  tryExt(OID.authorityKeyIdentifier, (n) => {
    const kid = n.children.find((x) => isContext(x, 0));
    if (kid) c.authorityKeyId = toHex(kid.value);
  });
  tryExt(OID.authorityInfoAccess, (n) => {
    for (const ad of n.children) {
      const method = oidOf(ad.children[0]);
      const uris = ad.children[1] ? generalNameUris(ad.children[1]) : [];
      if (method === OID.ocspAccess) c.ocspUrls.push(...uris);
      if (method === OID.caIssuers) c.caIssuerUrls.push(...uris);
    }
  });
  tryExt(OID.crlDistributionPoints, (n) => c.crlUrls.push(...generalNameUris(n)));
  tryExt(OID.qcStatements, (n) => {
    for (const st of n.children) {
      const oid = oidOf(st.children[0]);
      if (oid) c.qcStatements.push(oid);
    }
  });
  return c;
}

export function tryParseCertificate(der: Uint8Array): Certificate | null {
  try {
    return parseCertificate(der);
  } catch {
    return null;
  }
}

export async function certSha256(cert: Certificate): Promise<string> {
  return toHex(await digest("SHA-256", cert.raw));
}

export async function spkiSha256(cert: Certificate): Promise<string> {
  return toHex(await digest("SHA-256", cert.spki.raw));
}

export function validAt(cert: Certificate, at: Date): boolean {
  return !!cert.notBefore && !!cert.notAfter && at >= cert.notBefore && at <= cert.notAfter;
}

export function describeCert(cert: Certificate): string {
  return cert.subject.cn ?? cert.subject.o ?? cert.subject.text;
}

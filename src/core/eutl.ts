// EU Trusted List lookup for qualified time-stamping services (TSA/QTST).
// A chain certificate matches a service when its SubjectPublicKeyInfo SHA-256
// equals one of the service digital identities; the service status in force
// at genTime decides whether the timestamp is qualified (ETSI TS 119 615).

import bundled from "../data/eutl-qtst.json";
import { Certificate, spkiSha256 } from "./x509";

export interface EutlData {
  source: string;
  lotlSequence: string;
  generatedAt: string;
  services: { c: string; tsp: string; svc: string; h: [string, string][]; k: string[] }[];
}

export interface EutlMatch {
  country: string;
  tsp: string;
  service: string;
  statusAtGenTime: string | null;
  qualifiedAtGenTime: boolean;
  currentStatus: string | null;
  matchedCertificate: string;
  listGeneratedAt: string;
}

let active: EutlData | null = bundled as unknown as EutlData;

export function getEutl(): EutlData | null {
  return active;
}

/** Replaces the bundled list (e.g. with a freshly built one), or disables it with null. */
export function setEutl(data: EutlData | null): void {
  active = data;
}

function statusAt(history: [string, string][], at: Date | null): string | null {
  if (!at) return history[history.length - 1]?.[0] ?? null;
  let s: string | null = null;
  for (const [status, from] of history) {
    if (Date.parse(from) <= at.getTime()) s = status;
  }
  return s;
}

export async function matchEutl(chain: Certificate[], genTime: Date | null, data: EutlData): Promise<EutlMatch | null> {
  let best: EutlMatch | null = null;
  for (const cert of chain) {
    const k = await spkiSha256(cert);
    for (const s of data.services) {
      if (!s.k.includes(k)) continue;
      const st = statusAt(s.h, genTime);
      const m: EutlMatch = {
        country: s.c,
        tsp: s.tsp,
        service: s.svc,
        statusAtGenTime: st,
        qualifiedAtGenTime: st === "granted" || st === "accredited",
        currentStatus: s.h[s.h.length - 1]?.[0] ?? null,
        matchedCertificate: cert.subject.text,
        listGeneratedAt: data.generatedAt,
      };
      if (m.qualifiedAtGenTime) return m;
      best = best ?? m;
    }
  }
  return best;
}

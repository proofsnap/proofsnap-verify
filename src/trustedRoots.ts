import { extractCertInfo, pemToDer, bytesToHex } from "./asn1";
import { sha256 } from "./crypto";

export interface TrustedRootMatch {
  commonName: string;
  country: string;
  matchedAtDepth: number;
}

let cachedDefault: string | null = null;
let cachedDefaultLoaded = false;

/**
 * Loads the bundled trusted roots PEM file. Returns empty string if no bundle is shipped.
 *
 * The bundle is intentionally pluggable — users can override via:
 *   - InspectOptions.trustedRootsPem (programmatic)
 *   - --roots flag (CLI)
 *   - PROOFSNAP_TRUSTED_ROOTS env var (CLI)
 *
 * To regenerate the bundle from EU LOTL, run: scripts/refresh-eutl.ts
 */
export function loadDefaultTrustedRoots(): string {
  if (cachedDefaultLoaded) return cachedDefault || "";
  cachedDefaultLoaded = true;

  // Browser builds do not ship the file. Node CLI loads it lazily.
  try {
    if (typeof process !== "undefined" && process.versions?.node) {
      const fs = require("fs");
      const path = require("path");
      const candidates = [
        path.join(__dirname, "..", "data", "eutl-tsa-roots.pem"),
        path.join(__dirname, "data", "eutl-tsa-roots.pem"),
      ];
      for (const p of candidates) {
        if (fs.existsSync(p)) {
          cachedDefault = fs.readFileSync(p, "utf-8");
          return cachedDefault || "";
        }
      }
    }
  } catch {
    /* ignore */
  }

  cachedDefault = "";
  return "";
}

/**
 * Override the bundled trusted roots in the module-level cache. Used by the
 * CLI to honour --roots / PROOFSNAP_TRUSTED_ROOTS, and by tests.
 *
 * Pass null to reset to the bundled default on next call.
 */
export function overrideDefaultTrustedRoots(pem: string | null): void {
  cachedDefault = pem;
  cachedDefaultLoaded = pem !== null;
}

/** @deprecated kept for backward compatibility — use overrideDefaultTrustedRoots */
export const setTrustedRootsForTesting = overrideDefaultTrustedRoots;

interface ParsedTrustedRoot {
  der: Uint8Array;
  hash: string;
  commonName: string;
  country: string;
}

let parsedRootsCache: { source: string; roots: ParsedTrustedRoot[] } | null =
  null;

async function parseTrustedRoots(pem: string): Promise<ParsedTrustedRoot[]> {
  if (parsedRootsCache && parsedRootsCache.source === pem) {
    return parsedRootsCache.roots;
  }

  const blocks = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g
  );
  if (!blocks) {
    parsedRootsCache = { source: pem, roots: [] };
    return [];
  }

  const roots: ParsedTrustedRoot[] = [];
  for (const block of blocks) {
    try {
      const der = pemToDer(block);
      const info = extractCertInfo(der);
      if (!info) continue;
      const hash = await sha256(der);
      roots.push({
        der,
        hash,
        commonName: info.subject.commonName || "(no CN)",
        country: info.subject.country || "(no C)",
      });
    } catch {
      /* skip malformed cert */
    }
  }

  parsedRootsCache = { source: pem, roots };
  return roots;
}

export async function matchTrustedRoot(
  certChainDer: Uint8Array[],
  trustedRootsPem: string
): Promise<TrustedRootMatch | null> {
  if (!trustedRootsPem || certChainDer.length === 0) return null;

  const roots = await parseTrustedRoots(trustedRootsPem);
  if (roots.length === 0) return null;

  // Walk from top of chain down — most likely match is the root
  for (let i = certChainDer.length - 1; i >= 0; i--) {
    const certHash = await sha256(certChainDer[i]);
    const match = roots.find((r) => r.hash === certHash);
    if (match) {
      return {
        commonName: match.commonName,
        country: match.country,
        matchedAtDepth: i,
      };
    }
  }

  return null;
}

export async function getBundledRootCount(pem?: string): Promise<number> {
  const source = pem !== undefined ? pem : loadDefaultTrustedRoots();
  if (!source) return 0;
  const roots = await parseTrustedRoots(source);
  return roots.length;
}

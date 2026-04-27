# proofsnap-verify

Open-source verification tool for [ProofSnap](https://getproofsnap.com) evidence packages, eIDAS qualified timestamps, and any RFC 3161 time-stamp token from any EU TSA.

> **Don't trust us. Trust the math.**
> Three independent verification modes, all client-side. No upload, no account.

## Three modes

| Mode | Input | What it verifies |
|---|---|---|
| **ZIP** | `evidence.zip` | RSA-4096 signature, every file SHA-256, hash chain, OpenTimestamps, eIDAS LTV |
| **File + Timestamp** | any file + `.tsr` | File SHA-256 == TSR message imprint, TSA signature, cert chain, TSA identity |
| **Inspect Timestamp** | `.tsr` alone | TSA identity, timestamp time, hash algorithm, policy OID, signature, chain |

## What it verifies (ZIP mode)

| Check | Description |
|---|---|
| **RSA-4096 Signature** | Verifies `manifest.sig` against `manifest.json` using `publickey.pem` |
| **SHA-256 Hashes** | Recomputes hash of every file and compares with `manifest.json` |
| **Hash Chain** | Verifies forensic log integrity and chain of custody cross-references |
| **OpenTimestamps** | Verifies `manifest.json.ots` against Bitcoin blockchain via calendar servers |
| **eIDAS Timestamp** | Offline LTV verification of `manifest.json.tsr` (TSA signature, cert chain, OCSP) |

The ZIP-mode crypto is byte-for-byte identical to the verifier built into the ProofSnap Chrome Extension. The standalone TSR modes additionally resolve the TSA signer certificate by trying every embedded certificate against the TSR signature, so they handle TSRs that the Chrome extension's blind `tsaCertChain[0]` lookup would miss.

## Quick Start

### Option 1: Web Verifier (no install)

1. Open `web/index.html` in any modern browser, or visit [getproofsnap.com/verify](https://getproofsnap.com/verify)
2. Pick a tab — **Evidence ZIP** / **File + Timestamp** / **Inspect Timestamp**
3. Drop your file(s). Results appear instantly. Nothing leaves your browser.

> Browser mode skips OCSP fetching (CORS) and EUTL trust matching. For full LTV, use the CLI.

### Option 2: CLI

**Prerequisites:** [Node.js 18+](https://nodejs.org/).

```bash
# ZIP mode (default — auto-detected from .zip extension)
npx proofsnap-verify evidence.zip

# File + Timestamp mode
npx proofsnap-verify --file myfile.pdf --tsr myfile.tsr

# Inspect a TSR alone (auto-detected from .tsr extension)
npx proofsnap-verify stamp.tsr
# or explicit:
npx proofsnap-verify --inspect-tsr stamp.tsr

# JSON output for scripting / CI
npx proofsnap-verify evidence.zip --json
npx proofsnap-verify stamp.tsr --json

# Provide custom trusted roots bundle
npx proofsnap-verify --inspect-tsr stamp.tsr --roots my-eutl-roots.pem

# Or via env var
PROOFSNAP_TRUSTED_ROOTS=/path/to/roots.pem npx proofsnap-verify stamp.tsr
```

Exit code: `0` = all checks passed, `1` = any check failed, `2` = bad arguments.

### Option 3: Use as a library

```bash
npm install proofsnap-verify
```

```typescript
import {
  verify,
  verifyFileWithTimestamp,
  inspectTimestamp,
} from "proofsnap-verify";
import { readFileSync } from "fs";

// 1. Verify a ProofSnap evidence ZIP
const zipBuf = readFileSync("evidence.zip");
const zipResult = await verify(zipBuf.buffer);
console.log(zipResult.overallValid);

// 2. Verify any file against a standalone .tsr token
const file = readFileSync("contract.pdf");
const tsr = readFileSync("contract.tsr");
const fileResult = await verifyFileWithTimestamp(
  new Uint8Array(file),
  new Uint8Array(tsr)
);
console.log(fileResult.hashCoversFile, fileResult.tsr.tsa);

// 3. Inspect a TSR alone — extract TSA identity, time, etc.
const tsrOnly = readFileSync("stamp.tsr");
const inspection = await inspectTimestamp(new Uint8Array(tsrOnly));
console.log(inspection.tsa.commonName);   // "Disig Time Stamping Authority"
console.log(inspection.timestampedAt);     // "2026-04-13T10:23:11.000Z"
console.log(inspection.signatureValid);    // true
```

## Trusted root resolution (EUTL)

The CLI ships a **stub** EUTL bundle in `data/eutl-tsa-roots.pem` — by default the file is empty and the verifier emits a warning that EUTL trust is unverified, but signature + chain consistency are still checked.

To enable full EUTL trust resolution:

1. Build a PEM bundle from the [EU LOTL XML](https://ec.europa.eu/tools/lotl/eu-lotl.xml) (extract every QTSP root that lists a Time Stamping service)
2. Inject the bundle via one of:
   - CLI flag: `--roots my-eutl.pem`
   - Env var: `PROOFSNAP_TRUSTED_ROOTS=/path/to/roots.pem`
   - Programmatic: `import { overrideDefaultTrustedRoots } from "proofsnap-verify/dist/trustedRoots"` and call it with the PEM string before invoking `inspectTimestamp` / `verifyFileWithTimestamp`

When no match is found against the bundle (including the empty-stub case), the verifier emits a `TRUST UNVERIFIED` warning but still reports signature and chain consistency results.

A `scripts/refresh-eutl.ts` helper for automated bundle regeneration is on the roadmap.

## Example output (ZIP mode)

```
ProofSnap Evidence Verifier v1.5.0 — ZIP mode
==============================================

Evidence ID: ps_a1b2c3d4-e5f6-7890

[PASS] Signature: RSA-4096 (RSASSA-PKCS1-v1_5, SHA-256)
[PASS] screenshot.jpeg: SHA-256 match (a1b2c3d4e5f6...)
[PASS] metadata.json: SHA-256 match (d4e5f67890ab...)
[PASS] page.html: SHA-256 match (g7h8i9j0k1l2...)
[PASS] domtextcontent.txt: SHA-256 match (m3n4o5p6q7r8...)
[PASS] evidence.pdf: SHA-256 match (s9t0u1v2w3x4...)
[PASS] forensic_log.json: SHA-256 match (y5z6a7b8c9d0...)
[PASS] chain_of_custody.json: SHA-256 match (e1f2g3h4i5j6...)
[PASS] Hash chain: 14 operations, chain intact
[PASS] OpenTimestamps: Bitcoin block #890123, 2026-03-23T14:15:22.000Z
[PASS] eIDAS LTV: all checks passed (HASH_MATCH, SIGNATURE_VALID, CERT_CHAIN_VALID, OCSP_GOOD)

Result: ALL CHECKS PASSED (11/11)
```

## Example output (Inspect Timestamp mode)

```
ProofSnap Verifier v1.5.0 — Inspect TSR
========================================

Time-Stamp Authority
  Common Name:  Disig Time Stamping Authority TSA-Q-A1
  Organization: Disig a.s.
  Country:      SK
  Cert valid:   2024-02-23T... → 2029-02-23T...
  Cert serial:  1060062ed9b25b048400000000000005e2

Timestamp
  Issued at:    2026-04-13T10:23:11.000Z
  Hash algo:    SHA-256
  Hash value:   a1b2c3d4e5f6...
  Policy OID:   1.3.158.36061701.0.0.2.4.0
  Serial:       7e1c8a...

Verification
[PASS] TSR signature valid
[PASS] Certificate chain consistent
[WARN] Trusted root: not matched against EUTL bundle
[WARN] OCSP: not checked

Result: TIMESTAMP VALID
```

## How it works

A ProofSnap evidence ZIP contains:

- `screenshot.jpeg` — full-page screenshot
- `page.html` — complete HTML source
- `metadata.json` — URL, TLS cert, HTTP headers, device info
- `domtextcontent.txt` — extracted DOM text
- `evidence.pdf` — forensic evidence report
- `forensic_log.json` — ISO/IEC 27037 operation log with hash chain
- `chain_of_custody.json` — who captured, when, from what device
- `manifest.json` — SHA-256 hash of every file
- `manifest.sig` — RSA-4096 signature of manifest
- `publickey.pem` — public key for signature verification
- `manifest.json.ots` — OpenTimestamps proof (Bitcoin blockchain)
- `manifest.json.tsr` — eIDAS qualified timestamp (RFC 3161)
- `eidas_validation.json` — LTV data for offline TSR verification

This tool recomputes every hash, verifies the signature, validates the hash chain, and checks both blockchain and eIDAS timestamps — all independently, without contacting ProofSnap servers.

For File + Timestamp and Inspect modes, the tool parses RFC 3161 TimeStampResponses directly: it iterates over every certificate embedded in the CMS SignedData `certificates` set and selects the one whose public key actually verifies the TSR signature (falling back to the leaf if none verifies, so the result is still inspectable), validates the signature over `signedAttrs`, and walks the certificate chain to a self-signed root (optionally matched against a bundled EUTL list). The chain itself is assumed to be in leaf-to-root order — scrambled embedded certificates are not currently reordered.

## Requirements

- Node.js 18+ (uses native `crypto.subtle`)

## License

MIT — use freely, modify freely, verify freely.

## Links

- [ProofSnap Chrome Extension](https://getproofsnap.com)
- [Chrome Web Store](https://chromewebstore.google.com/detail/proofsnap-digital-evidenc/mfbhmfinogdedlgaoihbnmbldpabdhao)
- [Report issues](https://github.com/proofsnap/proofsnap-verify/issues)

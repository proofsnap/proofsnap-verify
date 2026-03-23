# proofsnap-verify

Open-source verification tool for [ProofSnap](https://getproofsnap.com) evidence packages. Independently verify the integrity of forensic web captures — no trust in ProofSnap required.

## What it verifies

| Check | Description |
|---|---|
| **RSA-4096 Signature** | Verifies `manifest.sig` against `manifest.json` using `publickey.pem` |
| **SHA-256 Hashes** | Recomputes hash of every file and compares with `manifest.json` |
| **Hash Chain** | Verifies forensic log integrity and chain of custody cross-references |
| **OpenTimestamps** | Verifies `manifest.json.ots` against Bitcoin blockchain via calendar servers |
| **eIDAS Timestamp** | Offline LTV verification of `manifest.json.tsr` (TSA signature, cert chain, OCSP) |

## Quick Start

### Option 1: Web Verifier (no install needed)

1. Open `web/index.html` in any modern browser (Chrome, Firefox, Safari, Edge)
2. Drag and drop a ProofSnap evidence ZIP onto the page
3. Results appear instantly — everything runs in your browser, nothing is uploaded

### Option 2: CLI

**Prerequisites:** [Node.js 18+](https://nodejs.org/) installed on your machine.

**Run without installing (recommended):**

```bash
npx proofsnap-verify evidence.zip
```

**Or install globally:**

```bash
npm install -g proofsnap-verify
proofsnap-verify evidence.zip
```

**Or clone and build from source:**

```bash
git clone https://github.com/proofsnap/proofsnap-verify.git
cd proofsnap-verify
npm install
npm run build
node dist/index.js /path/to/evidence.zip
```

### Option 3: Use as a library in your own code

```bash
npm install proofsnap-verify
```

```typescript
import { verify } from "proofsnap-verify";
import { readFileSync } from "fs";

async function main() {
  const zipBuffer = readFileSync("evidence.zip");
  const result = await verify(zipBuffer.buffer);

  console.log(result.overallValid); // true/false
  console.log(result.signature);    // { valid: true, algorithm: "RSA-4096 ..." }
  console.log(result.files);        // [{ name, expected, actual, match }]
  console.log(result.ots);          // { verified, bitcoinHeight, timestamp }
  console.log(result.eidas);        // { hashMatch, signatureValid, certChainValid, ... }
}

main();
```

## CLI Options

```bash
# Human-readable output (default)
proofsnap-verify evidence.zip

# JSON output (for scripting / CI pipelines)
proofsnap-verify evidence.zip --json

# Show help
proofsnap-verify --help
```

Exit code: `0` = all checks passed, `1` = any check failed.

## Example output

```
ProofSnap Evidence Verifier v1.0.0
===================================

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

## Requirements

- Node.js 18+ (uses native `crypto.subtle`)

## License

MIT — use freely, modify freely, verify freely.

## Links

- [ProofSnap Chrome Extension](https://getproofsnap.com)
- [Chrome Web Store](https://chromewebstore.google.com/detail/proofsnap-digital-evidenc/mfbhmfinogdedlgaoihbnmbldpabdhao)
- [Report issues](https://github.com/proofsnap/proofsnap-verify/issues)

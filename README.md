# proofsnap-verify

Checks a [ProofSnap](https://getproofsnap.com) evidence package without trusting ProofSnap. Every check is recomputed from the bytes of the package, in your browser or on your machine. Nothing is uploaded.

## Use it

**In the browser:** open [getproofsnap.com/verify](https://getproofsnap.com/verify) and drop the ZIP you received, or its unzipped folder. To run the page from this repository: `cd web && python3 -m http.server 8000`, then open http://localhost:8000.

**On the command line** (Node.js 20.12 or newer):

```bash
npx proofsnap-verify package.zip
```

The answer is one of:

| Result | Meaning |
|---|---|
| **VALID** | Every file is exactly as it was sealed, and every check passed. |
| **VALID WITH WARNINGS** | The sealed files are unchanged. Read the warnings, for example a file added to the ZIP after sealing, a Bitcoin proof that is still pending, a package with no timestamp at all (the time of sealing cannot be confirmed), or a package in a matter export that the matter's custody log does not list. |
| **INVALID** | At least one check failed: a file was changed, removed or forged, or a signature or timestamp does not verify. |
| **NOT A PROOFSNAP PACKAGE** | There is no ProofSnap evidence in the file. |

What a valid result means: the files have not changed since they were sealed, and they existed no later than the time shown. It does not say who created the content or whether it is true.

If the check cannot run at all (a very old browser, a ZIP re-packed with a password or with an unusual compression method, a file too large for the browser), you get **could not be checked** with the reason, never INVALID. Network problems never fail a package either: the online steps are then skipped and noted.

Exit codes: `0` valid, `1` invalid or not a ProofSnap package, `2` the check could not run, `3` valid with warnings.

## More ways to use it

```bash
npx proofsnap-verify ./unzipped-package/            # the package after unzipping
npx proofsnap-verify cert.zip my-file.pdf           # is my copy the certified file?
npx proofsnap-verify package.zip later.ots          # use a separately delivered OpenTimestamps proof
npx proofsnap-verify contract.pdf contract.tsr      # does this RFC 3161 timestamp cover this file?
npx proofsnap-verify contract.pdf contract.ots      # does this OpenTimestamps proof cover this file?
npx proofsnap-verify token.tsr                      # who issued a timestamp, when, over which hash
```

Options: `--offline` (no network), `--verbose` (every check and every file), `--json` (machine-readable report), `--roots <file.pem>` (extra trusted roots for RFC 3161 timestamps from other providers).

It accepts everything ProofSnap issues, detected automatically: extension web captures (with or without video), browsing sessions, file certifications, API captures, hash existence certificates, comparisons, redactions, matter exports, capture exports and delivery ZIPs, including older formats and packages that were unzipped and zipped again.

## What is checked

**The archive.** ZIP files are read with a strict parser: one central directory, no duplicate, renamed or path-traversal names, no symbolic links, local headers that agree with the central directory, no hidden bytes, every entry's CRC checked. These are the tricks that make two programs show different contents for the same ZIP.

**The seal.** `manifest.sig` is verified over the exact bytes of `manifest.json` (RSA, SHA-256), then every file is re-hashed. Changed, missing and unsealed files are reported by name. The key pair is made for each package, so the signature proves the files are unchanged since sealing; the timestamps prove when sealing happened.

**The chain of custody.** The forensic log hash chain is recomputed entry by entry and compared with the chain of custody (log hash, final chain hash, evidence ID, URL hash, recorded file hashes). Session tabs, image inventories, redaction commitments and matter custody logs are checked the same way. In a matter export, every package under `captures/` must be recorded in the matter's custody log as a current member (added or imported, not removed).

**The qualified timestamp (eIDAS, RFC 3161),** fully offline: the token covers this package, its content is what the authority signed, the authority's certificate chain and revocation status were valid at the time of stamping, and the authority was a qualified time-stamping service on the EU Trusted List at that moment (a bundled snapshot of the official list; ProofSnap's provider, Disig a.s., qualified trust service provider on the EU Trusted List, is also pinned).

**The Bitcoin timestamp (OpenTimestamps).** The proof is replayed to its Bitcoin block and compared with block headers from independent explorers (blockstream.info, mempool.space, blockchain.info). A pending proof is completed from the public OpenTimestamps calendars. The result means the content existed no later than that block.

**Issuance (API packages).** The manifest hash is looked up in ProofSnap's public issuance ledger. A match confirms ProofSnap issued that exact package; no match is only a note, since older packages are not listed.

## Network use

Only for the Bitcoin and ledger steps, never with file content: block heights to the explorers, the proof's own commitments to the OpenTimestamps calendars, the manifest SHA-256 to the ledger. Each request has a time limit, a server that does not answer is not asked again, and all online steps together stop after 45 seconds. Use `--offline` (or untick the box on the web page) to skip them; the qualified timestamp is checked fully either way.

## As a library

Same API in Node and in the browser (`web/proofsnap-verify.js` exposes it as `window.ProofSnapVerify`), no runtime dependencies:

```js
import { verifyZip, CannotVerifyError } from "proofsnap-verify";

const report = await verifyZip(bytes, "package.zip", { online: true });
report.verdict;            // "valid" | "valid_with_warnings" | "invalid" | "not_a_package"
report.timeAnchor.existedBy;
report.checks;             // [{ id, group, status, title, detail }]
report.children;           // packages inside an archive
```

`verifyZip` and `verifyFiles` (an unzipped folder as `{ name, size, read() }` entries) throw only `CannotVerifyError`, and only when the check cannot run in this environment. `verifyFileWithTimestamp`, `verifyFileWithOts`, `inspectTimestamp` and `verifyOts` check stand-alone proofs.

## Develop

```bash
npm install
npm test               # builds the library and the browser bundle, then runs the tests
npm run refresh-eutl   # rebuilds src/data/eutl-qtst.json from the official EU List of Trusted Lists
```

The EU list snapshot holds every qualified time-stamping service with its status history. The refresh script reads the lists over HTTPS from their official locations; when a national server refuses the request, it uses the latest Internet Archive copy of that list and records this in the snapshot. It does not validate the lists' XML signatures.

## License

MIT

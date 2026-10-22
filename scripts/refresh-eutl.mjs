#!/usr/bin/env node
// Builds src/data/eutl-qtst.json from the EU List of Trusted Lists (LOTL):
// every qualified time-stamping service (TSA/QTST) of every member state,
// with its service digital identities and full status history, so the
// verifier can decide whether a TSA was qualified at the moment of stamping
// (ETSI TS 119 615).
//
// Usage: node scripts/refresh-eutl.mjs [--out src/data/eutl-qtst.json]
//
// The XML is fetched over HTTPS from the official locations. XAdES
// signatures of the lists are not validated by this script.

import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
const QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
const out = process.argv.includes("--out") ? process.argv[process.argv.indexOf("--out") + 1] : new URL("../src/data/eutl-qtst.json", import.meta.url).pathname;

const stripNs = (xml) => xml.replace(/<(\/?)[A-Za-z0-9_-]+:/g, "<$1");
const blocks = (xml, tag) => {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "g");
  const res = [];
  let m;
  while ((m = re.exec(xml))) res.push(m[1]);
  return res;
};
const first = (xml, tag) => blocks(xml, tag)[0] ?? null;
const text = (s) => (s ?? "").replace(/<[^>]+>/g, "").trim();
const preferredName = (xml) => {
  const names = [...(xml ?? "").matchAll(/<Name xml:lang="([a-zA-Z-]+)">([\s\S]*?)<\/Name>/g)];
  return text((names.find((n) => n[1].toLowerCase() === "en") ?? names[0])?.[2] ?? "");
};

async function fetchText(url) {
  const res = await fetch(url, { headers: { "User-Agent": "proofsnap-verify refresh-eutl" }, signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

function digitalIds(sdi) {
  return blocks(sdi ?? "", "X509Certificate").map((b) => text(b).replace(/\s+/g, ""));
}

function spkiSha256(b64) {
  try {
    const { X509Certificate } = globalThis.__x509 ?? {};
    const cert = new X509Certificate(Buffer.from(b64, "base64"));
    const spki = cert.publicKey.export({ type: "spki", format: "der" });
    return { spki: createHash("sha256").update(spki).digest("hex"), subject: cert.subject.replace(/\n/g, ", "), notAfter: new Date(cert.validTo).toISOString() };
  } catch {
    return null;
  }
}

async function main() {
  globalThis.__x509 = await import("node:crypto");
  const lotl = stripNs(await fetchText(LOTL_URL));
  const lotlSeq = text(first(lotl, "TSLSequenceNumber"));
  const pointers = blocks(lotl, "OtherTSLPointer")
    .map((p) => ({
      url: text(first(p, "TSLLocation")),
      country: text(first(p, "SchemeTerritory")),
      mime: text(first(p, "MimeType")),
    }))
    .filter((p) => p.url && /xml/i.test(p.mime || "xml") && p.country && p.country !== "EU");

  const services = [];
  const lists = [];
  for (const p of pointers) {
    // Some national servers block automated or foreign requests; fall back to the
    // latest Internet Archive copy of the same file and record that it was used.
    let xml;
    let via = "official";
    try {
      xml = stripNs(await fetchText(p.url));
    } catch (e) {
      try {
        const avail = await (await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(p.url)}`, { signal: AbortSignal.timeout(60000) })).json();
        const ts = avail?.archived_snapshots?.closest?.timestamp;
        if (!ts) throw new Error("no archived copy");
        xml = stripNs(await fetchText(`https://web.archive.org/web/${ts}id_/${p.url}`));
        via = `web.archive.org copy of ${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
        console.error(`${p.country}: official list unreachable (${e.message}), using the ${via}`);
      } catch (e2) {
        console.error(`skip ${p.country}: ${e.message}; archive: ${e2.message}`);
        lists.push({ country: p.country, url: p.url, error: e.message });
        continue;
      }
    }
    const seq = text(first(xml, "TSLSequenceNumber"));
    const issued = text(first(xml, "ListIssueDateTime"));
    let count = 0;
    for (const tsp of blocks(xml, "TrustServiceProvider")) {
      const tspName = preferredName(first(tsp, "TSPName"));
      for (const svc of blocks(tsp, "TSPService")) {
        const info = first(svc, "ServiceInformation");
        if (text(first(info, "ServiceTypeIdentifier")) !== QTST) continue;
        const history = [
          { status: text(first(info, "ServiceStatus")).split("/").pop(), from: text(first(info, "StatusStartingTime")) },
          ...blocks(svc, "ServiceHistoryInstance")
            .filter((h) => text(first(h, "ServiceTypeIdentifier")) === QTST)
            .map((h) => ({ status: text(first(h, "ServiceStatus")).split("/").pop(), from: text(first(h, "StatusStartingTime")) })),
        ].sort((a, b) => a.from.localeCompare(b.from));
        const certs = [...new Set([
          ...digitalIds(first(info, "ServiceDigitalIdentity")),
          ...blocks(svc, "ServiceHistoryInstance").flatMap((h) => digitalIds(first(h, "ServiceDigitalIdentity"))),
        ])];
        const ids = certs.map((b64) => ({ b64, ...spkiSha256(b64) })).filter((c) => c.spki);
        if (!ids.length) continue;
        services.push({
          country: p.country,
          tsp: tspName,
          service: preferredName(first(info, "ServiceName")),
          history,
          certs: ids.map((c) => ({ der: c.b64, spkiSha256: c.spki, subject: c.subject, notAfter: c.notAfter })),
        });
        count++;
      }
    }
    lists.push({ country: p.country, url: p.url, sequence: seq, issued, qtstServices: count, via });
    console.error(`${p.country}: ${count} QTST services (TL #${seq})`);
  }

  // Compact form: the verifier matches chain certificates by SPKI SHA-256
  // (the service digital identity is a key, ETSI TS 119 612 §5.5.3), so the
  // certificates themselves are not shipped.
  const compact = services.map((s) => ({
    c: s.country,
    tsp: s.tsp,
    svc: s.service,
    h: s.history.map((x) => [x.status, x.from]),
    k: [...new Set(s.certs.map((c) => c.spkiSha256))],
  }));
  const seen = new Set();
  const unique = compact.filter((s) => {
    const key = JSON.stringify([s.c, s.tsp, s.svc, s.h, s.k]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const data = {
    source: LOTL_URL,
    lotlSequence: lotlSeq,
    generatedAt: new Date().toISOString(),
    serviceType: QTST,
    lists: lists.map((l) => ({ c: l.country, seq: l.sequence ?? null, issued: l.issued ?? null, n: l.qtstServices ?? 0, via: l.via, error: l.error })),
    services: unique,
  };
  writeFileSync(out, JSON.stringify(data));
  console.error(`wrote ${data.services.length} services to ${out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

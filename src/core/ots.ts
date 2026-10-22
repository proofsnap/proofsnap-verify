// OpenTimestamps proof parsing, evaluation and Bitcoin verification.
//
// The proof is replayed operation by operation from the file digest to each
// attestation. A Bitcoin attestation yields a block height and a 32-byte
// Merkle root; that root is compared with the block header fetched from
// independent block explorers, so neither the calendar servers nor a single
// explorer has to be trusted. No dependency on the opentimestamps npm module.

import { concat, equalBytes, fromHex, toHex, utf8 } from "./bytes";
import { digest } from "./crypto";
import { ripemd160 } from "./ripemd160";

const MAGIC = fromHex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294");

const TAG_BITCOIN = "0588960d73d71901";
const TAG_PENDING = "83dfe30d2ef90c8e";
const TAG_LITECOIN = "06869a0d73d71b45";
const TAG_ETHEREUM = "30fe8087b5c7ead7";

type OpName = "sha256" | "sha1" | "ripemd160" | "keccak256" | "append" | "prepend" | "reverse" | "hexlify";
const UNARY: Record<number, OpName> = { 0x08: "sha256", 0x02: "sha1", 0x03: "ripemd160", 0x67: "keccak256", 0xf2: "reverse", 0xf3: "hexlify" };
const BINARY: Record<number, OpName> = { 0xf0: "append", 0xf1: "prepend" };

export interface OtsAttestation {
  kind: "bitcoin" | "pending" | "litecoin" | "ethereum" | "unknown";
  height?: number;
  uri?: string;
  tag: string;
}

export interface OtsNode {
  attestations: OtsAttestation[];
  ops: { op: OpName; arg?: Uint8Array; child: OtsNode }[];
}

export interface ParsedOts {
  version: number;
  fileHashOp: OpName;
  fileDigest: Uint8Array;
  tree: OtsNode;
}

class Reader {
  pos = 0;
  constructor(private b: Uint8Array) {}
  byte(): number {
    if (this.pos >= this.b.length) throw new Error("OTS: unexpected end of proof");
    return this.b[this.pos++];
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.b.length) throw new Error("OTS: unexpected end of proof");
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint(): number {
    let v = 0;
    let shift = 1;
    for (let i = 0; i < 9; i++) {
      const b = this.byte();
      v += (b & 0x7f) * shift;
      if (!(b & 0x80)) return v;
      shift *= 128;
    }
    throw new Error("OTS: varuint too long");
  }
  varbytes(max = 8192): Uint8Array {
    const n = this.varuint();
    if (n > max) throw new Error("OTS: field too long");
    return this.bytes(n);
  }
  get done() {
    return this.pos >= this.b.length;
  }
}

function readAttestation(r: Reader): OtsAttestation {
  const tag = toHex(r.bytes(8));
  const payload = r.varbytes();
  const pr = new Reader(payload);
  if (tag === TAG_BITCOIN) return { kind: "bitcoin", height: pr.varuint(), tag };
  if (tag === TAG_LITECOIN) return { kind: "litecoin", height: pr.varuint(), tag };
  if (tag === TAG_ETHEREUM) return { kind: "ethereum", height: pr.varuint(), tag };
  if (tag === TAG_PENDING) {
    const uri = new TextDecoder().decode(pr.varbytes(1000));
    if (!/^https?:\/\/[A-Za-z0-9.\-:/_]+$/.test(uri)) throw new Error("OTS: invalid calendar URI");
    return { kind: "pending", uri, tag };
  }
  return { kind: "unknown", tag };
}

function readTimestamp(r: Reader, depth: number): OtsNode {
  if (depth > 256) throw new Error("OTS: proof nested too deep");
  const node: OtsNode = { attestations: [], ops: [] };
  const handle = (tag: number) => {
    if (tag === 0x00) {
      node.attestations.push(readAttestation(r));
    } else if (UNARY[tag]) {
      node.ops.push({ op: UNARY[tag], child: readTimestamp(r, depth + 1) });
    } else if (BINARY[tag]) {
      const arg = r.varbytes(4096);
      node.ops.push({ op: BINARY[tag], arg, child: readTimestamp(r, depth + 1) });
    } else {
      throw new Error(`OTS: unknown operation 0x${tag.toString(16)}`);
    }
  };
  let tag = r.byte();
  while (tag === 0xff) {
    handle(r.byte());
    tag = r.byte();
  }
  handle(tag);
  return node;
}

export function parseOts(bytes: Uint8Array): ParsedOts {
  if (bytes.length < MAGIC.length + 2 || !equalBytes(bytes.subarray(0, MAGIC.length), MAGIC)) {
    throw new Error("not an OpenTimestamps proof (bad magic)");
  }
  const r = new Reader(bytes);
  r.bytes(MAGIC.length);
  const version = r.varuint();
  if (version !== 1) throw new Error(`unsupported OTS version ${version}`);
  const hashTag = r.byte();
  const fileHashOp = UNARY[hashTag];
  const len = fileHashOp === "sha1" || fileHashOp === "ripemd160" ? 20 : 32;
  if (!fileHashOp || fileHashOp === "reverse" || fileHashOp === "hexlify") throw new Error("OTS: invalid file hash operation");
  const fileDigest = r.bytes(len);
  const tree = readTimestamp(r, 0);
  if (!r.done) throw new Error("OTS: trailing bytes after proof");
  return { version, fileHashOp, fileDigest, tree };
}

/** Parses a bare serialized Timestamp (what a calendar returns for /timestamp/<commitment>). */
export function parseTimestampTree(bytes: Uint8Array): OtsNode {
  const r = new Reader(bytes);
  const t = readTimestamp(r, 0);
  if (!r.done) throw new Error("OTS: trailing bytes after timestamp");
  return t;
}

async function applyOp(op: OpName, msg: Uint8Array, arg?: Uint8Array): Promise<Uint8Array> {
  switch (op) {
    case "sha256":
      return digest("SHA-256", msg);
    case "sha1":
      return digest("SHA-1", msg);
    case "ripemd160":
      return ripemd160(msg);
    case "append":
      return concat(msg, arg!);
    case "prepend":
      return concat(arg!, msg);
    case "reverse":
      return Uint8Array.from(msg).reverse();
    case "hexlify":
      return utf8(toHex(msg));
    case "keccak256":
      throw new Error("keccak256 operation is not supported");
  }
}

export interface ReachedAttestation extends OtsAttestation {
  /** The message the attestation commits to (for Bitcoin: the Merkle root in internal byte order). */
  message: Uint8Array;
}

/** Replays every path of the proof and returns each attestation with its committed message. */
export async function evaluate(tree: OtsNode, start: Uint8Array): Promise<ReachedAttestation[]> {
  const out: ReachedAttestation[] = [];
  const walk = async (n: OtsNode, msg: Uint8Array, depth: number) => {
    if (msg.length > 4096) throw new Error("OTS: message grew beyond 4096 bytes");
    for (const a of n.attestations) out.push({ ...a, message: msg });
    for (const o of n.ops) await walk(o.child, await applyOp(o.op, msg, o.arg), depth + 1);
  };
  await walk(tree, start, 0);
  return out;
}

/** Merges a calendar-returned subtree into the node whose message equals `commitment`. */
export async function mergeAt(tree: OtsNode, start: Uint8Array, commitment: Uint8Array, sub: OtsNode): Promise<boolean> {
  let merged = false;
  const walk = async (n: OtsNode, msg: Uint8Array) => {
    if (!merged && equalBytes(msg, commitment)) {
      n.attestations.push(...sub.attestations);
      n.ops.push(...sub.ops);
      merged = true;
      return;
    }
    for (const o of n.ops) {
      if (merged) return;
      await walk(o.child, await applyOp(o.op, msg, o.arg));
    }
  };
  await walk(tree, start);
  return merged;
}

export interface BlockHeaderInfo {
  height: number;
  hash: string;
  merkleRoot: string; // display (big-endian) hex as explorers show it
  time: number;
  source: string;
}

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

const EXPLORERS: { name: string; get: (height: number, f: Fetcher) => Promise<BlockHeaderInfo> }[] = [
  { name: "blockstream.info", get: (h, f) => esploraHeader("https://blockstream.info/api", "blockstream.info", h, f) },
  { name: "mempool.space", get: (h, f) => esploraHeader("https://mempool.space/api", "mempool.space", h, f) },
  { name: "blockchain.info", get: blockchainInfoHeader },
];

async function esploraHeader(base: string, name: string, height: number, f: Fetcher): Promise<BlockHeaderInfo> {
  const hashRes = await f(`${base}/block-height/${height}`, { signal: AbortSignal.timeout(8000) });
  if (!hashRes.ok) throw new Error(`${name}: HTTP ${hashRes.status}`);
  const hash = (await hashRes.text()).trim();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}: bad block hash`);
  const blockRes = await f(`${base}/block/${hash}`, { signal: AbortSignal.timeout(8000) });
  if (!blockRes.ok) throw new Error(`${name}: HTTP ${blockRes.status}`);
  const b = (await blockRes.json()) as { merkle_root?: string; timestamp?: number; height?: number };
  if (!b.merkle_root || b.height !== height) throw new Error(`${name}: unexpected block data`);
  return { height, hash, merkleRoot: b.merkle_root, time: b.timestamp ?? 0, source: name };
}

// The header-only endpoint (about 500 bytes); /block-height?format=json returns the whole block, megabytes.
async function blockchainInfoHeader(height: number, f: Fetcher): Promise<BlockHeaderInfo> {
  const res = await f(`https://api.blockchain.info/haskoin-store/btc/block/height/${height}?notx=true`, { signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`blockchain.info: HTTP ${res.status}`);
  const j = (await res.json()) as unknown;
  const list = (Array.isArray(j) ? j : [j]) as { hash?: string; merkle?: string; time?: number; height?: number; mainchain?: boolean }[];
  const b = list.find((x) => x && x.height === height && x.mainchain !== false);
  if (!b || typeof b.merkle !== "string" || !/^[0-9a-f]{64}$/.test(b.merkle) || typeof b.hash !== "string") throw new Error("blockchain.info: unexpected block data");
  return { height, hash: b.hash, merkleRoot: b.merkle, time: b.time ?? 0, source: "blockchain.info" };
}

export interface OtsBitcoinResult {
  height: number;
  verified: boolean;
  blockTime: string | null;
  blockHash: string | null;
  sources: string[];
  detail: string;
}

/** Checks a Bitcoin attestation against block headers from every reachable explorer; all that answer must agree. */
// Block headers never change once buried; cache them for the whole session
// so a container with many packages does not refetch the same blocks.
const headerCache = new Map<string, Promise<BlockHeaderInfo>>();
function cachedHeader(e: (typeof EXPLORERS)[number], height: number, f: Fetcher): Promise<BlockHeaderInfo> {
  const key = `${e.name}:${height}`;
  let p = headerCache.get(key);
  if (!p) {
    p = e.get(height, f);
    p.catch(() => headerCache.delete(key));
    headerCache.set(key, p);
  }
  return p;
}

/** Resolves once `need` sources answered (or all settled), so one unreachable explorer does not stall the check. */
function firstAgreeing(ps: Promise<BlockHeaderInfo>[], need: number): Promise<BlockHeaderInfo[]> {
  return new Promise((resolve) => {
    const got: BlockHeaderInfo[] = [];
    let settled = 0;
    const done = () => resolve(got.slice());
    for (const p of ps) {
      p.then((v) => {
        got.push(v);
      })
        .catch(() => {})
        .finally(() => {
          settled++;
          if (got.length >= need || settled === ps.length) done();
        });
    }
  });
}

export async function verifyBitcoinAttestation(att: ReachedAttestation, f: Fetcher): Promise<OtsBitcoinResult> {
  const height = att.height!;
  if (att.message.length !== 32) {
    return { height, verified: false, blockTime: null, blockHash: null, sources: ["proof"], detail: "Bitcoin attestation does not commit to a 32-byte Merkle root" };
  }
  const rootDisplay = toHex(Uint8Array.from(att.message).reverse());
  const ok = await firstAgreeing(EXPLORERS.map((e) => cachedHeader(e, height, f)), 2);
  if (!ok.length) {
    return { height, verified: false, blockTime: null, blockHash: null, sources: [], detail: "no block explorer reachable, Bitcoin block not checked" };
  }
  const mismatch = ok.filter((h) => h.merkleRoot !== rootDisplay);
  if (mismatch.length) {
    return {
      height,
      verified: false,
      blockTime: null,
      blockHash: null,
      sources: ok.map((h) => h.source),
      detail: `Merkle root of block ${height} does not match the proof (${mismatch.map((m) => m.source).join(", ")})`,
    };
  }
  const time = Math.min(...ok.map((h) => h.time));
  return {
    height,
    verified: true,
    blockTime: new Date(time * 1000).toISOString(),
    blockHash: ok[0].hash,
    sources: ok.map((h) => h.source),
    detail: `Merkle root matches block ${height} (${ok.map((h) => h.source).join(", ")})`,
  };
}

// The calendar URI comes from the proof, which is not covered by any seal. Only the public calendars the
// OpenTimestamps client trusts by default are contacted, so a crafted proof cannot make the verifier send
// requests to a host of the attacker's choosing (or into the local network).
const CALENDAR_HOSTS = [/(^|\.)calendar\.opentimestamps\.org$/, /(^|\.)calendar\.eternitywall\.com$/, /(^|\.)calendar\.catallaxy\.com$/];
export function isAllowedCalendar(uri: string): boolean {
  try {
    const u = new URL(uri);
    return u.protocol === "https:" && !u.username && !u.password && (u.port === "" || u.port === "443") && CALENDAR_HOSTS.some((re) => re.test(u.hostname));
  } catch {
    return false;
  }
}

/** Asks each pending calendar for the completed timestamp and merges what it returns. */
export async function upgradeFromCalendars(parsed: ParsedOts, f: Fetcher): Promise<{ upgraded: boolean; answered: number; notes: string[] }> {
  const notes: string[] = [];
  let answered = 0;
  const reached = await evaluate(parsed.tree, parsed.fileDigest);
  let upgraded = false;
  const pending = reached.filter((x) => x.kind === "pending" && (isAllowedCalendar(x.uri!) || (notes.push(`${x.uri}: not a known public OpenTimestamps calendar, not contacted`), false)));
  const answers = await Promise.all(
    pending.map(async (a) => {
      try {
        const res = await f(`${a.uri!.replace(/\/$/, "")}/timestamp/${toHex(a.message)}`, {
          headers: { Accept: "application/vnd.opentimestamps.v1" },
          signal: AbortSignal.timeout(8000),
        });
        // Only a real calendar answer counts as reached (a captive portal's HTML page does not).
        if (res.status === 404) return answered++, { a, note: `${a.uri}: not yet anchored in Bitcoin` };
        if (!res.ok) return { a, note: `${a.uri}: HTTP ${res.status}` };
        const sub = parseTimestampTree(new Uint8Array(await res.arrayBuffer()));
        answered++;
        return { a, sub };
      } catch (e) {
        return { a, note: `${a.uri}: ${e instanceof Error ? e.message : e}` };
      }
    }),
  );
  for (const { a, sub, note } of answers as { a: ReachedAttestation; sub?: OtsNode; note?: string }[]) {
    if (note) notes.push(note);
    if (sub && (await mergeAt(parsed.tree, parsed.fileDigest, a.message, sub))) {
      upgraded = true;
      notes.push(`${a.uri}: completed proof received`);
    }
  }
  return { upgraded, answered: pending.length ? answered : -1, notes };
}

export interface OtsReport {
  valid: boolean; // structure ok and digest matches
  digestMatches: boolean | null;
  fileDigest: string;
  fileHashOp: string;
  status: "bitcoin_verified" | "bitcoin_unconfirmed" | "pending" | "invalid";
  bitcoin: OtsBitcoinResult[];
  pendingCalendars: string[];
  upgradedOnline: boolean;
  /** An online check was attempted but no block explorer (or no calendar, for a pending proof) answered. */
  networkFailed: boolean;
  notes: string[];
  error?: string;
}

export interface OtsOptions {
  expectedDigest?: string;
  /** Network access for explorer lookups and calendar upgrades. Omit to stay offline. */
  fetch?: Fetcher;
  /** Additional proofs for the same digest (e.g. an .upgraded.ots shipped separately). */
  extraProofs?: Uint8Array[];
}

export async function verifyOts(bytes: Uint8Array, opts: OtsOptions = {}): Promise<OtsReport> {
  const rep: OtsReport = {
    valid: false,
    digestMatches: null,
    fileDigest: "",
    fileHashOp: "",
    status: "invalid",
    bitcoin: [],
    pendingCalendars: [],
    upgradedOnline: false,
    networkFailed: false,
    notes: [],
  };
  let parsed: ParsedOts;
  try {
    parsed = parseOts(bytes);
  } catch (e) {
    rep.error = e instanceof Error ? e.message : String(e);
    return rep;
  }
  rep.fileDigest = toHex(parsed.fileDigest);
  rep.fileHashOp = parsed.fileHashOp;
  if (opts.expectedDigest !== undefined) {
    rep.digestMatches = parsed.fileHashOp === "sha256" && rep.fileDigest === opts.expectedDigest.toLowerCase();
    if (!rep.digestMatches) {
      rep.error = `proof covers ${parsed.fileHashOp} ${rep.fileDigest}, expected sha256 ${opts.expectedDigest}`;
      return rep;
    }
  }
  for (const extra of opts.extraProofs ?? []) {
    try {
      const p = parseOts(extra);
      if (equalBytes(p.fileDigest, parsed.fileDigest)) {
        parsed.tree.ops.push(...p.tree.ops);
        parsed.tree.attestations.push(...p.tree.attestations);
        rep.notes.push("merged a separately supplied upgraded proof");
      } else rep.notes.push("a supplied upgraded proof covers a different digest and was ignored");
    } catch (e) {
      rep.notes.push(`supplied upgraded proof unreadable: ${e instanceof Error ? e.message : e}`);
    }
  }
  let reached: ReachedAttestation[];
  try {
    reached = await evaluate(parsed.tree, parsed.fileDigest);
  } catch (e) {
    rep.error = e instanceof Error ? e.message : String(e);
    return rep;
  }
  if (opts.fetch && !reached.some((a) => a.kind === "bitcoin")) {
    try {
      const up = await upgradeFromCalendars(parsed, opts.fetch);
      rep.upgradedOnline = up.upgraded;
      rep.networkFailed = up.answered === 0;
      rep.notes.push(...up.notes);
      if (up.upgraded) reached = await evaluate(parsed.tree, parsed.fileDigest);
    } catch (e) {
      // A calendar answer that cannot be replayed is ignored; the proof is judged as delivered.
      const asDelivered = await verifyOts(bytes, { ...opts, fetch: undefined });
      asDelivered.notes.push(`a calendar answer could not be used and was ignored (${e instanceof Error ? e.message : e})`);
      return asDelivered;
    }
  }
  rep.valid = true;
  rep.pendingCalendars = [...new Set(reached.filter((a) => a.kind === "pending").map((a) => a.uri!))];
  const btc = reached.filter((a) => a.kind === "bitcoin");
  // One check per distinct height is enough.
  const byHeight = new Map<number, ReachedAttestation>();
  for (const a of btc) if (!byHeight.has(a.height!)) byHeight.set(a.height!, a);
  // The earliest block is what "existed no later than" rests on; one is enough.
  const heights = [...byHeight.values()].sort((a, b) => a.height! - b.height!).slice(0, 1);
  if (heights.length && opts.fetch) {
    for (const a of heights) rep.bitcoin.push(await verifyBitcoinAttestation(a, opts.fetch));
  } else if (heights.length) {
    for (const a of heights) {
      rep.bitcoin.push({ height: a.height!, verified: false, blockTime: null, blockHash: null, sources: [], detail: "offline mode, block header not fetched" });
    }
  }
  if (opts.fetch && rep.bitcoin.length && rep.bitcoin.every((b) => !b.sources.length)) rep.networkFailed = true;
  const failed = rep.bitcoin.find((b) => b.sources.length && !b.verified);
  if (failed && rep.upgradedOnline) {
    // The Bitcoin attestation came from a calendar during this check, not from the proof itself: a calendar
    // answer that does not hold up says nothing about the evidence, so the proof stays as it was delivered.
    const asDelivered = await verifyOts(bytes, { ...opts, fetch: undefined });
    asDelivered.notes.push(...rep.notes, `a calendar returned a completion that does not match Bitcoin (${failed.detail}); it was ignored`);
    return asDelivered;
  }
  if (failed) {
    rep.valid = false;
    rep.status = "invalid";
    rep.error = failed.detail;
  } else if (rep.bitcoin.some((b) => b.verified)) rep.status = "bitcoin_verified";
  else if (rep.bitcoin.length) rep.status = "bitcoin_unconfirmed";
  else rep.status = "pending";
  return rep;
}

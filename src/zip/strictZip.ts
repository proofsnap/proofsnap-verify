// Strict ZIP reader for evidence verification.
//
// General-purpose readers (JSZip included) take the last end-of-central-
// directory record they find, let a later duplicate name win, rename entries
// by the Info-ZIP Unicode Path field and skip CRC checks. Each of those lets
// a crafted archive show the verifier other bytes than the ones a person
// opening the ZIP sees. This reader refuses such archives: exactly one EOCD,
// the central directory immediately before it, no duplicate or unsafe names,
// local headers consistent with the central directory, no overlapping
// entries, and CRC-32 plus size checked on every read.

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_Z64_EOCD = 0x06064b50;
const SIG_Z64_LOCATOR = 0x07064b50;

export interface ZipEntry {
  name: string;
  dir: boolean;
  method: number;
  crc32: number;
  compressedSize: number;
  size: number;
  localOffset: number;
  dataOffset: number;
  /** First byte after the entry's data (and data descriptor). */
  endOffset: number;
}

export interface ZipLimits {
  maxEntries: number;
  maxEntryBytes: number;
  maxTotalBytes: number;
  maxRatio: number;
}

export const DEFAULT_LIMITS: ZipLimits = {
  maxEntries: 20000,
  maxEntryBytes: 2 * 1024 * 1024 * 1024 - 1,
  maxTotalBytes: 16 * 1024 * 1024 * 1024,
  maxRatio: 1000,
};

export class ZipError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = "ZipError";
  }
}

export function unsafeNameReason(name: string): string | null {
  if (!name) return "empty name";
  if (/[\u0000-\u001f\u007f]/.test(name)) return "control character in name";
  if (name.includes("\\")) return "backslash in name";
  if (name.startsWith("/") || /^[A-Za-z]:/.test(name)) return "absolute path";
  const segs = (name.endsWith("/") ? name.slice(0, -1) : name).split("/");
  if (segs.some((s) => s === "..")) return "path traversal (..)";
  if (segs.some((s) => s === "" || s === ".")) return "empty or dot path segment";
  return null;
}

let CRC_TABLE: Uint32Array | null = null;
export function crc32(data: Uint8Array): number {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

const CP437 =
  "\u0000☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~⌂ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";

function decodeName(bytes: Uint8Array, utf8Flag: boolean): string {
  const ascii = bytes.every((b) => b < 0x80);
  if (utf8Flag || ascii) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      if (utf8Flag) throw new ZipError("bad_name", "file name is not valid UTF-8 although the UTF-8 flag is set");
    }
  }
  // Many tools write UTF-8 without setting the flag; prefer that when it decodes cleanly.
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return Array.from(bytes, (b) => CP437[b]).join("");
  }
}

export class StrictZip {
  readonly entries: ZipEntry[] = [];
  readonly byName = new Map<string, ZipEntry>();
  readonly warnings: string[] = [];
  private dv: DataView;

  private constructor(private buf: Uint8Array, private limits: ZipLimits) {
    this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  static open(buf: Uint8Array, limits: Partial<ZipLimits> = {}): StrictZip {
    const z = new StrictZip(buf, { ...DEFAULT_LIMITS, ...limits });
    z.parse();
    return z;
  }

  private u16(o: number) {
    return this.dv.getUint16(o, true);
  }
  private u32(o: number) {
    return this.dv.getUint32(o, true);
  }
  private u64(o: number) {
    const lo = this.dv.getUint32(o, true);
    const hi = this.dv.getUint32(o + 4, true);
    if (hi > 0x1fffff) throw new ZipError("too_large", "ZIP64 value exceeds the safe integer range");
    return hi * 0x100000000 + lo;
  }

  private parse() {
    const b = this.buf;
    if (b.length < 22) throw new ZipError("not_zip", "file is too small to be a ZIP archive");
    // Candidates: EOCD signatures whose comment length ends exactly at EOF. Exactly one may exist.
    const minPos = Math.max(0, b.length - 22 - 0xffff);
    const sigs: number[] = [];
    for (let p = b.length - 22; p >= minPos; p--) {
      if (b[p] === 0x50 && b[p + 1] === 0x4b && b[p + 2] === 0x05 && b[p + 3] === 0x06) sigs.push(p);
    }
    const valid = sigs.filter((p) => p + 22 + this.u16(p + 20) === b.length);
    if (!valid.length) throw new ZipError("not_zip", "no end-of-central-directory record, not a ZIP archive or truncated");
    if (valid.length > 1) throw new ZipError("ambiguous_eocd", "more than one end-of-central-directory record, archive is ambiguous");
    const eocd = valid[0];
    const commentLen = this.u16(eocd + 20);
    if (commentLen) {
      this.warnings.push("the archive has a ZIP comment, which ProofSnap does not write; it is not part of the evidence");
    }
    if (this.u16(eocd + 4) !== 0 || this.u16(eocd + 6) !== 0) throw new ZipError("multi_disk", "multi-volume archives are not supported");

    let count = this.u16(eocd + 10);
    let cdSize = this.u32(eocd + 12);
    let cdOffset = this.u32(eocd + 16);
    let cdEnd = eocd;
    if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const loc = eocd - 20;
      if (loc < 0 || this.u32(loc) !== SIG_Z64_LOCATOR) throw new ZipError("bad_zip64", "ZIP64 locator missing");
      const z64 = this.u64(loc + 8);
      if (z64 + 56 > loc || this.u32(z64) !== SIG_Z64_EOCD) throw new ZipError("bad_zip64", "ZIP64 end record missing");
      count = this.u64(z64 + 32);
      cdSize = this.u64(z64 + 40);
      cdOffset = this.u64(z64 + 48);
      cdEnd = z64;
    }
    if (count > this.limits.maxEntries) throw new ZipError("too_many_entries", `${count} entries exceed the limit of ${this.limits.maxEntries}`);
    if (cdOffset + cdSize !== cdEnd) throw new ZipError("bad_central_directory", "central directory does not end at the end record (data appended or prepended)");
    // A second EOCD signature after the start of the central directory (in the directory or the comment)
    // is how two readers are made to see two different archives.
    if (sigs.some((p) => p !== eocd && p >= cdOffset)) throw new ZipError("ambiguous_eocd", "a second end-of-central-directory signature follows the central directory");

    const seen = new Set<string>();
    let p = cdOffset;
    let total = 0;
    for (let i = 0; i < count; i++) {
      if (p + 46 > cdEnd || this.u32(p) !== SIG_CENTRAL) throw new ZipError("bad_central_directory", `central directory entry ${i + 1} is malformed`);
      const madeBy = this.u16(p + 4);
      const flags = this.u16(p + 8);
      const method = this.u16(p + 10);
      const crc = this.u32(p + 16);
      let csize = this.u32(p + 20);
      let usize = this.u32(p + 24);
      const nameLen = this.u16(p + 28);
      const extraLen = this.u16(p + 30);
      const commentLenE = this.u16(p + 32);
      const extAttr = this.u32(p + 38);
      let localOffset = this.u32(p + 42);
      const nameBytes = b.subarray(p + 46, p + 46 + nameLen);
      const extra = b.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
      const name = decodeName(nameBytes, (flags & 0x0800) !== 0);

      // Extra fields: ZIP64 sizes, and the Unicode Path field which must not rename the entry.
      for (let e = 0; e + 4 <= extra.length; ) {
        const id = extra[e] | (extra[e + 1] << 8);
        const len = extra[e + 2] | (extra[e + 3] << 8);
        const body = extra.subarray(e + 4, e + 4 + len);
        const bdv = new DataView(body.buffer, body.byteOffset, body.byteLength);
        if (id === 0x0001) {
          let q = 0;
          const read64 = () => {
            const lo = bdv.getUint32(q, true);
            const hi = bdv.getUint32(q + 4, true);
            q += 8;
            return hi * 0x100000000 + lo;
          };
          if (usize === 0xffffffff) usize = read64();
          if (csize === 0xffffffff) csize = read64();
          if (localOffset === 0xffffffff) localOffset = read64();
        } else if (id === 0x7075) {
          const unicodeName = new TextDecoder().decode(body.subarray(5));
          if (body[0] !== 1 || unicodeName !== name) {
            throw new ZipError("unicode_path_rename", `entry "${name}" carries a Unicode Path field naming "${unicodeName}"; some ZIP tools would show a different file`);
          }
        } else if (id === 0x6375) {
          throw new ZipError("unicode_comment", `entry "${name}" carries a Unicode Comment field`);
        }
        e += 4 + len;
      }

      const why = unsafeNameReason(name);
      if (why) throw new ZipError("unsafe_name", `${why}: ${JSON.stringify(name.slice(0, 200))}`);
      const key = (name.endsWith("/") ? name.slice(0, -1) : name).normalize("NFC").toLowerCase();
      if (seen.has(key)) throw new ZipError("duplicate_name", `two entries named ${JSON.stringify(name)} (or differing only in case / Unicode form)`);
      seen.add(key);
      if (flags & 0x0041 || flags & 0x2000) throw new ZipError("encrypted", `entry "${name}" is encrypted`);
      if (madeBy >> 8 === 3 && ((extAttr >>> 16) & 0o170000) === 0o120000) throw new ZipError("symlink", `entry "${name}" is a symbolic link`);
      if (name.endsWith("/") && usize !== 0) throw new ZipError("bad_directory_entry", `folder entry "${name}" has content`);
      if (method === 0 && csize !== usize) throw new ZipError("size_mismatch", `stored entry "${name}" declares ${csize} compressed and ${usize} uncompressed bytes`);
      if (method !== 0 && method !== 8) throw new ZipError("unsupported_method", `entry "${name}" uses compression method ${method}`);
      if (usize > this.limits.maxEntryBytes) throw new ZipError("too_large", `entry "${name}" is ${usize} bytes, above the limit`);
      total += usize;
      if (total > this.limits.maxTotalBytes) throw new ZipError("too_large", "archive expands beyond the size limit");
      if (method === 8 && usize > 1024 * 1024 && usize / Math.max(csize, 1) > this.limits.maxRatio) {
        throw new ZipError("zip_bomb", `entry "${name}" has a compression ratio above ${this.limits.maxRatio}:1`);
      }

      // Local header must agree with the central directory.
      if (localOffset + 30 > cdOffset || this.u32(localOffset) !== SIG_LOCAL) throw new ZipError("bad_local_header", `local header of "${name}" missing`);
      const lNameLen = this.u16(localOffset + 26);
      const lExtraLen = this.u16(localOffset + 28);
      const lName = b.subarray(localOffset + 30, localOffset + 30 + lNameLen);
      if (lNameLen !== nameLen || !lName.every((x, k) => x === nameBytes[k])) throw new ZipError("bad_local_header", `local header name of "${name}" differs from the central directory`);
      if (this.u16(localOffset + 8) !== method) throw new ZipError("bad_local_header", `local header method of "${name}" differs`);
      // Streaming extractors read the local header only: its flags, CRC and sizes must say what the central
      // directory says (zero is allowed with a data descriptor, 0xffffffff with ZIP64).
      // Encryption (bits 0, 6, 13) and UTF-8 (bit 11) must agree; some writers set the data descriptor bit (3) in the
      // local header only.
      const lflags = this.u16(localOffset + 6);
      if ((lflags & 0x2841) !== (flags & 0x2841)) throw new ZipError("bad_local_header", `local header flags of "${name}" differ from the central directory`);
      const dd = ((flags | lflags) & 0x0008) !== 0;
      const agrees = (local: number, central: number) => local === central || (dd && local === 0) || local === 0xffffffff;
      if (!agrees(this.u32(localOffset + 14), crc) || !agrees(this.u32(localOffset + 18), csize) || !agrees(this.u32(localOffset + 22), usize)) {
        throw new ZipError("bad_local_header", `local header CRC or sizes of "${name}" differ from the central directory`);
      }
      const dataOffset = localOffset + 30 + lNameLen + lExtraLen;
      if (dataOffset + csize > cdOffset) throw new ZipError("bad_local_header", `data of "${name}" overruns the central directory`);
      let end = dataOffset + csize;
      if (dd) {
        // Data descriptor: optional signature, CRC-32, then 4 or 8 byte sizes (ZIP64)
        const sig = end + 4 <= cdOffset && this.u32(end) === 0x08074b50 ? 4 : 0;
        // 8-byte sizes when the local header carries a ZIP64 extra field (APPNOTE 4.3.9.2)
        let z64 = false;
        for (let x = localOffset + 30 + lNameLen; x + 4 <= dataOffset; x += 4 + this.u16(x + 2)) if (this.u16(x) === 0x0001) z64 = true;
        const len = sig + 4 + (z64 ? 16 : 8);
        if (end + len > cdOffset || this.u32(end + sig) !== crc) throw new ZipError("bad_local_header", `data descriptor of "${name}" does not match the central directory`);
        end += len;
      }

      const entry: ZipEntry = {
        name,
        dir: name.endsWith("/"),
        method,
        crc32: crc,
        compressedSize: csize,
        size: usize,
        localOffset,
        dataOffset,
        endOffset: end,
      };
      this.entries.push(entry);
      this.byName.set(name, entry);
      p += 46 + nameLen + extraLen + commentLenE;
    }
    if (p !== cdEnd) throw new ZipError("bad_central_directory", "central directory size does not match its entries");

    // Entries must tile the archive from offset 0 to the central directory: overlapping entries are a zip-bomb and
    // smuggling trick, and bytes before, between or after them can hold local headers that a streaming extractor
    // reads as further files although the central directory does not list them.
    const ranges = this.entries.map((e) => [e.localOffset, e.endOffset] as const).sort((a, c) => a[0] - c[0]);
    for (let i = 1; i < ranges.length; i++) {
      if (ranges[i][0] < ranges[i - 1][1]) throw new ZipError("overlapping_entries", "two entries share the same bytes");
    }
    const first = ranges.length ? ranges[0][0] : cdOffset;
    if (first !== 0) throw new ZipError("hidden_data", `${first} bytes before the first entry (prepended data)`);
    for (let i = 1; i < ranges.length; i++) {
      if (ranges[i][0] !== ranges[i - 1][1]) throw new ZipError("hidden_data", `${ranges[i][0] - ranges[i - 1][1]} unlisted bytes between two entries`);
    }
    if (ranges.length && ranges[ranges.length - 1][1] !== cdOffset) throw new ZipError("hidden_data", "unlisted bytes between the last entry and the central directory");
    // A file must not also be the folder of another entry ("a" and "a/b").
    const fileKeys = new Set(this.entries.filter((e) => !e.dir).map((e) => e.name.normalize("NFC").toLowerCase()));
    for (const e of this.entries) {
      const segs = (e.dir ? e.name.slice(0, -1) : e.name).normalize("NFC").toLowerCase().split("/");
      for (let i = 1; i < segs.length; i++) {
        const parent = segs.slice(0, i).join("/");
        if (fileKeys.has(parent)) {
          throw new ZipError("file_used_as_folder", `${JSON.stringify(parent)} is a file and also the folder of ${JSON.stringify(e.name)}`);
        }
      }
    }
  }

  has(name: string): boolean {
    const e = this.byName.get(name);
    return !!e && !e.dir;
  }

  files(): ZipEntry[] {
    return this.entries.filter((e) => !e.dir);
  }

  /** Decompresses an entry and checks its size and CRC-32. */
  async read(name: string): Promise<Uint8Array> {
    const e = this.byName.get(name);
    if (!e || e.dir) throw new ZipError("missing", `no file named ${name}`);
    const raw = this.buf.subarray(e.dataOffset, e.dataOffset + e.compressedSize);
    const data = e.method === 0 ? raw : await inflateRaw(raw, e.size);
    if (data.length !== e.size) throw new ZipError("size_mismatch", `"${name}" decompressed to ${data.length} bytes, header says ${e.size}`);
    if (crc32(data) !== e.crc32) throw new ZipError("crc_mismatch", `CRC-32 of "${name}" does not match, the archive is corrupt`);
    return data;
  }
}

/** ZipError codes that say "this verifier cannot unpack it", never "the evidence is wrong". */
export const CANNOT_UNPACK = new Set(["no_inflate", "too_large", "too_many_entries", "unsupported_method", "encrypted", "multi_disk"]);

async function inflateRaw(data: Uint8Array, expected: number): Promise<Uint8Array> {
  const DS = (globalThis as { DecompressionStream?: typeof DecompressionStream }).DecompressionStream;
  if (!DS) {
    throw new ZipError("no_inflate", "this browser cannot unpack ZIP files (it needs Chrome 103, Firefox 113, Safari 16.4 or newer); update it or use the command line");
  }
  const ds = new DS("deflate-raw" as CompressionFormat);
  // Fed in slices straight from the archive: no copy of the compressed data is made.
  const writer = ds.writable.getWriter();
  const feed = (async () => {
    for (let i = 0; i < data.length; i += 1 << 20) await writer.write(data.subarray(i, i + (1 << 20)) as unknown as BufferSource);
    await writer.close();
  })();
  feed.catch(() => {});
  const reader = ds.readable.getReader();
  const out = new Uint8Array(expected);
  let o = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (o + value.length > expected) {
        await reader.cancel().catch(() => {});
        throw new ZipError("size_mismatch", "entry decompresses to more bytes than its header declares");
      }
      out.set(value, o);
      o += value.length;
    }
    await feed;
  } catch (e) {
    if (e instanceof ZipError) throw e;
    throw new ZipError("corrupt", `compressed data is damaged (${e instanceof Error ? e.message : String(e)})`);
  }
  return o === expected ? out : out.subarray(0, o);
}

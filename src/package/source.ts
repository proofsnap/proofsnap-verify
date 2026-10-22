// A package is read through one interface, whether it is a ZIP (strict reader)
// or an extracted folder (CLI, or a folder dropped on the web page).
//
// Names are compared in Unicode NFC: macOS writes accented file names
// decomposed (NFD), while the manifest usually holds them composed, and both
// spell the same name. Two entries that only differ in that form are refused,
// so the lookup can never pick between two different files.

import { StrictZip, ZipError } from "../zip/strictZip";

export interface SourceEntry {
  /** Path relative to the package root, "/" separated. */
  name: string;
  size: number;
  read(): Promise<Uint8Array>;
}

export class PackageSource {
  private map = new Map<string, SourceEntry>();

  constructor(
    readonly type: "zip" | "folder",
    entries: SourceEntry[],
    /** Notes collected while opening (e.g. a ZIP comment). */
    readonly notes: string[] = [],
  ) {
    for (const e of entries) {
      const key = e.name.normalize("NFC");
      if (this.map.has(key)) throw new ZipError("duplicate_name", `two files named ${JSON.stringify(e.name)} (differing only in Unicode form)`);
      this.map.set(key, e);
    }
  }

  static fromZip(zip: StrictZip): PackageSource {
    const entries = zip.files().map((e) => ({ name: e.name, size: e.size, read: () => zip.read(e.name) }));
    return new PackageSource("zip", entries, [...zip.warnings]);
  }

  files(): string[] {
    return [...this.map.keys()];
  }
  has(name: string): boolean {
    return this.map.has(name.normalize("NFC"));
  }
  size(name: string): number {
    return this.map.get(name.normalize("NFC"))?.size ?? 0;
  }
  read(name: string): Promise<Uint8Array> {
    const e = this.map.get(name.normalize("NFC"));
    if (!e) throw new ZipError("missing", `no file named ${name}`);
    return e.read();
  }
  /** The same package seen from one of its folders. */
  sub(prefix: string): PackageSource {
    const entries = [...this.map].filter(([k]) => k.startsWith(prefix)).map(([k, e]) => ({ ...e, name: k.slice(prefix.length) }));
    return new PackageSource(this.type, entries, this.notes);
  }
}

import JSZip from "jszip";
import { sha256 } from "./crypto";
import { FileCheckResult } from "./types";

const CORE_FILES = [
  "metadata.json",
  "page.html",
  "screenshot.jpeg",
  "evidence.pdf",
  "domtextcontent.txt",
];

export async function verifyHashes(
  zip: JSZip,
  manifest: Record<string, string>
): Promise<FileCheckResult[]> {
  const results: FileCheckResult[] = [];

  const filesToValidate = [...CORE_FILES];

  for (const optionalFile of ["forensic_log.json", "chain_of_custody.json"]) {
    if (manifest[optionalFile] && zip.files[optionalFile]) {
      filesToValidate.push(optionalFile);
    }
  }

  for (const fileName of filesToValidate) {
    const file = zip.files[fileName];
    if (!file) {
      results.push({ name: fileName, expected: manifest[fileName] || "", actual: "MISSING", match: false });
      continue;
    }

    const fileBuffer = await file.async("arraybuffer");
    const actual = await sha256(new Uint8Array(fileBuffer));
    const expected = manifest[fileName] || "";

    results.push({ name: fileName, expected, actual, match: actual === expected });
  }

  return results;
}

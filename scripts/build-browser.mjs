// Bundles the library for the browser: web/proofsnap-verify.js exposes the
// same API as the npm package on window.ProofSnapVerify.
import { build } from "esbuild";

await build({
  entryPoints: [new URL("../src/index.ts", import.meta.url).pathname],
  outfile: new URL("../web/proofsnap-verify.js", import.meta.url).pathname,
  bundle: true,
  format: "iife",
  globalName: "ProofSnapVerify",
  platform: "browser",
  target: ["es2020"],
  minify: true,
  legalComments: "none",
  banner: { js: "/* proofsnap-verify, MIT License, https://github.com/proofsnap/proofsnap-verify */" },
});
console.log("web/proofsnap-verify.js written");

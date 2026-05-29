// Enforce the gzipped-bundle-size budget for the published client.
//
// Reads `dist/npm/**/*.js`, gzips, and asserts the total is at or under the
// configured ceiling. Exits non-zero on breach.
import fs from "node:fs/promises";
import path from "node:path";
import { gzipSize } from "gzip-size";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const DIST_DIR = path.join(ROOT, "dist", "npm");
// 64 KB gzipped budget. History: 25 KB (planned, pre-measurement) → 40 KB
// (cljs.core baseline ~32 KB + Web Crypto wrappers, IndexedDB persistence,
// 8-axis fingerprinting, envelope codec, multi-tab coord) → 64 KB (v0.4.0
// knowledge-factor recovery).
//
// The v0.4.0 jump (~32 → ~60 KB measured) is the one place the client links
// third-party crypto: Argon2id has no SubtleCrypto primitive, and an
// Ed25519 public key cannot be derived from a raw seed via WebCrypto. The
// added stack is paulmillr's pure-JS, dependency-free, audited libraries —
// @noble/hashes (Argon2id + blake2s), @noble/ed25519 (KF keypair + sign),
// @scure/bip39 (recovery-phrase encode/decode + the 2048-word English
// list, which is itself most of the weight). These are bundled, not
// CDN-loaded, so the supply-chain posture differs from the CDN scripts
// `client.crypto` deliberately avoids.
//
// Trade-off accepted in 0.4.0: this all lands in the single `core.js`, so
// even verify-only consumers download the KF stack. The KF path is COLD
// (set-verifier / recover only) — the documented future optimisation is to
// code-split it into a dynamically-imported chunk so the verify hot path
// returns to ~32 KB and only recovery flows pull the crypto stack. Until
// then, 64 KB is the measured ceiling (~60 KB + ~4 KB headroom). A further
// bump should trigger investigation (or the code-split), not reflexive
// re-papering.
const BUDGET_BYTES = 64 * 1024;

async function* walk(dir) {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else if (p.endsWith(".js")) yield p;
  }
}

let total = 0;
const breakdown = [];
try {
  for await (const file of walk(DIST_DIR)) {
    const buf = await fs.readFile(file);
    const sz = await gzipSize(buf);
    breakdown.push([path.relative(DIST_DIR, file), sz]);
    total += sz;
  }
} catch (err) {
  if (err.code === "ENOENT") {
    console.error(`bundle dir not found at ${DIST_DIR} — run \`npx shadow-cljs release npm-module\` first`);
    process.exit(2);
  }
  throw err;
}

breakdown.sort((a, b) => b[1] - a[1]);
console.log("bundle breakdown (gzipped):");
for (const [name, sz] of breakdown) {
  console.log(`  ${(sz / 1024).toFixed(2).padStart(8)} KB  ${name}`);
}
const pct = (total / BUDGET_BYTES * 100).toFixed(1);
console.log(`total: ${(total / 1024).toFixed(2)} KB  (budget ${BUDGET_BYTES / 1024} KB, ${pct}%)`);

if (total > BUDGET_BYTES) {
  console.error(`bundle exceeds ${BUDGET_BYTES} bytes gzipped`);
  process.exit(1);
}

// k6 load test for continuity-auth `/v1/verify`.
//
// Target (per plan §G "Resource budget"):
//   2000 req/s sustained on a 2 vCPU instance, P99 < 25 ms, P50 < 5 ms,
//   error rate < 0.1 %.
//
// Pre-conditions:
//   - k6 ≥ 0.51 (needs the `k6/experimental/webcrypto` module that ships
//     ECDSA P-256 generate/sign/import/export).
//   - A running continuity-auth server reachable at $K6_TARGET_URL
//     (defaults to http://localhost:8080).
//   - For developer laptops the 2000 rps target is not meaningful; run
//     this against a staging deployment that mirrors the prod resource
//     budget. See `docs/deployment.md` for the target topology.
//
// Identity pool:
//   setup() bootstraps $POOL identities (default 200) up-front. Each
//   identity has its own P-256 keypair. The PKCS#8-exported private key
//   bytes are returned as base64; default() re-imports them per-VU on
//   first iteration. This avoids hitting the per-identity rate limit
//   (sliding-window-counter tier limits) — 2000 rps spread across 200
//   identities is 10 rps per identity, well inside the :tracked tier
//   limit of 30/min once host-linked, or 1/min if anonymous. The bootstrap
//   step does not attach a host-link, so identities sit at the anonymous
//   tier; the verify endpoint accepts the signature and returns ok=true
//   but a low `tier` keyword. The load test is measuring the signature-
//   verification + replay-check path, not the rate-limit outcome, so this
//   is fine — the response status is 200 either way.
//
// Run:
//   K6_TARGET_URL=http://localhost:8080 k6 run test/load/verify.js
//
// Pass / fail:
//   The thresholds at the bottom of `options` are enforced by k6 — the
//   process exits non-zero if any breach.

import http from "k6/http";
import { check, fail } from "k6";
import encoding from "k6/encoding";
import { crypto } from "k6/experimental/webcrypto";

const TARGET = __ENV.K6_TARGET_URL || "http://localhost:8080";
const POOL = parseInt(__ENV.POOL || "200", 10);
const VUS = parseInt(__ENV.VUS || "50", 10);
const DURATION = __ENV.DURATION || "60s";
const RPS = parseInt(__ENV.RPS || "2000", 10);

export const options = {
  scenarios: {
    verify: {
      executor: "constant-arrival-rate",
      rate: RPS,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: VUS,
      maxVUs: VUS * 4,
    },
  },
  thresholds: {
    // P50 < 5 ms, P99 < 25 ms, error rate < 0.1 %.
    "http_req_duration{name:verify}": ["p(50)<5", "p(99)<25"],
    "http_req_failed{name:verify}": ["rate<0.001"],
  },
};

// -- byte helpers ----------------------------------------------------------

function utf8(s) {
  return new TextEncoder().encode(s);
}

function concat(...chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function u32be(n) {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function lengthPrefixed(bytes) {
  return concat(u32be(bytes.length), bytes);
}

function lengthPrefixedString(s) {
  return lengthPrefixed(utf8(s));
}

// base64url without padding.
function b64url(bytes) {
  const std = encoding.b64encode(bytes.buffer ? bytes.buffer : bytes);
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

// Mirrors `continuity-auth.envelope/canonical-bytes` in cljs / clj. Field
// order MUST match exactly:
//   "FPL1\n" || LEN(method) || method
//          || LEN(path) || path
//          || LEN(body-sha) || body-sha            (32 bytes raw)
//          || LEN(ts) || ts
//          || LEN(nonce) || nonce                  (16 bytes raw)
//          || LEN(fp-digest) || fp-digest          (32 bytes raw)
//          || LEN(host-user-id|"") || host-user-id
//          || LEN(key-id) || key-id                (32 bytes raw)
function canonicalBytes(env) {
  return concat(
    utf8("FPL1\n"),
    lengthPrefixedString(env.method),
    lengthPrefixedString(env.path),
    lengthPrefixed(env.bodySha256),
    lengthPrefixedString(env.ts),
    lengthPrefixed(env.nonce),
    lengthPrefixed(env.fpDigest),
    lengthPrefixedString(env.hostUserId || ""),
    lengthPrefixed(env.keyId),
  );
}

function envelopeToWire(env, signature, alg) {
  return {
    method: env.method,
    path: env.path,
    "body-sha256": b64url(env.bodySha256),
    ts: env.ts,
    nonce: b64url(env.nonce),
    "fp-digest": b64url(env.fpDigest),
    "host-user-id": env.hostUserId || "",
    "key-id": b64url(env.keyId),
    alg: alg,
    signature: b64url(signature),
  };
}

// -- crypto helpers --------------------------------------------------------

const P256_PARAMS = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_PARAMS = { name: "ECDSA", hash: { name: "SHA-256" } };

async function generateKeypair() {
  return crypto.subtle.generateKey(P256_PARAMS, true, ["sign", "verify"]);
}

async function exportPublic(publicKey) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
}

async function exportPrivate(privateKey) {
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
}

async function importPrivate(pkcs8Bytes) {
  return crypto.subtle.importKey("pkcs8", pkcs8Bytes, P256_PARAMS, false, [
    "sign",
  ]);
}

async function sign(privateKey, bytes) {
  return new Uint8Array(
    await crypto.subtle.sign(SIGN_PARAMS, privateKey, bytes),
  );
}

async function thumbprint(pubBytes) {
  return sha256(pubBytes);
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

// Constant fp-digest for the load test. The verify path treats this as an
// opaque 32-byte input; we don't need a real fingerprint to measure
// signature-verify throughput.
const STATIC_FP = new Uint8Array(32).fill(0x11);

// -- bootstrap (setup) -----------------------------------------------------

async function bootstrapOne(idx) {
  const kp = await generateKeypair();
  const pubBytes = await exportPublic(kp.publicKey);
  const privBytes = await exportPrivate(kp.privateKey);
  const keyId = await thumbprint(pubBytes);
  const nonce = randomBytes(16);
  const ts = new Date().toISOString();
  const bodySha = await sha256(utf8(""));
  const env = {
    method: "POST",
    path: "/v1/bootstrap",
    bodySha256: bodySha,
    ts: ts,
    nonce: nonce,
    fpDigest: STATIC_FP,
    hostUserId: "",
    keyId: keyId,
  };
  const sig = await sign(kp.privateKey, canonicalBytes(env));
  const wire = envelopeToWire(env, sig, "p256");
  const payload = {
    envelope: wire,
    pubkey: b64url(pubBytes),
    alg: "p256",
  };
  const resp = http.post(`${TARGET}/v1/bootstrap`, JSON.stringify(payload), {
    headers: { "Content-Type": "application/json" },
    tags: { name: "bootstrap" },
  });
  if (resp.status !== 200) {
    fail(`bootstrap[${idx}] failed: status=${resp.status} body=${resp.body}`);
  }
  return {
    privPkcs8B64: b64url(privBytes),
    keyIdB64: b64url(keyId),
    keyIdRaw: Array.from(keyId),
  };
}

export async function setup() {
  console.log(`Bootstrapping ${POOL} identities against ${TARGET}…`);
  const identities = [];
  for (let i = 0; i < POOL; i++) {
    identities.push(await bootstrapOne(i));
  }
  console.log(`Bootstrap OK: ${identities.length} identities`);
  return { identities };
}

// -- per-VU state ----------------------------------------------------------

// Re-import private keys on first iteration of each VU. setup() returns
// JSON-safe data; we can't pass CryptoKey objects through.
let vuKeys = null;

async function loadKeys(identities) {
  const out = [];
  for (const id of identities) {
    const pkcs8 = new Uint8Array(
      encoding
        .b64decode(
          id.privPkcs8B64.replace(/-/g, "+").replace(/_/g, "/"),
          "std",
        )
        .map((c) => (typeof c === "string" ? c.charCodeAt(0) : c)),
    );
    const key = await importPrivate(pkcs8);
    out.push({
      privateKey: key,
      keyId: new Uint8Array(id.keyIdRaw),
    });
  }
  return out;
}

// -- main exercise ---------------------------------------------------------

export default async function (data) {
  if (vuKeys === null) {
    vuKeys = await loadKeys(data.identities);
  }
  const idx = Math.floor(Math.random() * vuKeys.length);
  const { privateKey, keyId } = vuKeys[idx];

  const bodySha = await sha256(utf8(""));
  const nonce = randomBytes(16);
  const ts = new Date().toISOString();
  const env = {
    method: "POST",
    path: "/v1/verify",
    bodySha256: bodySha,
    ts: ts,
    nonce: nonce,
    fpDigest: STATIC_FP,
    hostUserId: "",
    keyId: keyId,
  };
  const sig = await sign(privateKey, canonicalBytes(env));
  const wire = envelopeToWire(env, sig, "p256");
  const resp = http.post(
    `${TARGET}/v1/verify`,
    JSON.stringify({ envelope: wire }),
    {
      headers: { "Content-Type": "application/json" },
      tags: { name: "verify" },
    },
  );
  check(resp, {
    "status 200": (r) => r.status === 200,
  });
}

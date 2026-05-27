# Client substrates (browser, CLI, daemon, …)

> Doc filename remains `non-browser-clients.md` for URL stability; the
> framing inside is substrate-neutral.

continuity-auth is a substrate-neutral mechanism. Any caller that holds
a private key persistently and can emit length-prefixed canonical bytes
participates as a first-class client of the same protocol — the browser
(non-extractable WebCrypto + IndexedDB) is one substrate, the CLI (PEM
on filesystem + openssl) is another, and hardware-anchored substrates
(TPM, Secure Enclave, Android Keystore, iOS Keychain — v1.1+) are
more. They differ in *threat model*, not in *protocol*.

This document covers the non-browser substrates: how they implement the
wire protocol byte-for-byte, what their threat model looks like, and how
they compare structurally with proof-of-work gates like Anubis.

## Why this matters

Pick a typical rate-limit / abuse-mitigation design and ask: *can a
non-browser caller participate as a first-class client?*

- **CAPTCHA (Turnstile, hCaptcha, reCAPTCHA):** No. The challenge is a
  vendor-rendered iframe; passing it requires running the vendor's JS.
- **Per-IP limits:** Yes, but with no identity granularity. A shared NAT
  punishes everyone behind it; a residential proxy bypasses it.
- **Per-cookie limits:** Yes, but the cookie has no cryptographic
  binding — anyone who replays the cookie is the cookie.
- **Anonymous tokens (Privacy Pass, Anubis):** Either depends on a
  trusted issuer (Privacy Pass) or requires a JS engine to mint the
  pass-token (Anubis, see below).
- **continuity-auth:** Yes. The proof is a signature over canonical
  bytes; any client holding the private key can produce it.

## Mechanism comparison vs Anubis

Anubis ([techaro/anubis](https://github.com/TecharoHQ/anubis)) is the
nearest comparable project — both target the "anti-scraper rate limit"
niche. The mechanisms differ structurally; understanding the difference
is the cleanest way to frame what continuity-auth is *not*.

| | Anubis | continuity-auth |
|---|---|---|
| Proof of what? | "I burned N CPU seconds" | "I hold the key behind identity X" |
| Identity? | Anonymous; no binding | Persistent device-continuity |
| JS-required? | Yes (SHA-256 PoW in SubtleCrypto) | No — any client with `openssl` |
| Issuer? | None (self-issued PoW) | None (self-issued key) |
| Bypass economics | $1/hr GPU at ~10 GH/s mints ~10⁵ valid challenges/sec at difficulty 4 (16 leading zero bits ≈ 2¹⁶ hashes/challenge) — ~20,000× faster than a browser's WebCrypto SHA-256 (~500 KH/s) | Key generation is one-time per identity; sustained observation determines tier |
| Trust shape | Cost-floor (economic) | Trust-gradient (cryptographic + behavioural) |
| Renewal | Per-request challenge | Per-request signature; tier accumulates |

Anubis is well-engineered for its design goal: raise the per-request
cost so that cost-free scrapers (no JS engine, no GPU) can't afford a
million-request scrape campaign. It works *now* because the population
of HTTP-only scrapers is large and rational. It is a cost-floor defence
— the structural shape is anonymous and economic.

continuity-auth has a different shape. The proof that a request passes
is "this signature came from the key behind identity X, and X has
earned tier T through Y observed events." Trust is persistent and
accumulative; the cost-per-request approaches zero for well-behaved
identities (Ed25519 sign is sub-millisecond) and rises arbitrarily for
new or anomalous ones (the score model fans out into tier
projections).

The structural consequence is that a curl client and a browser run the
*same protocol*. There is no "headless mode" or "API client" exception
— the bytes the server verifies are the bytes any caller can produce.

This isn't an argument that one shape is better than the other; the
two address different problems. PoW gates are useful when the operator
has *no enrolment surface* — the gate is the enrolment. continuity-auth
makes the enrolment trivial (zero-prompt key generation) and uses the
key as the persistent handle for trust accumulation.

## Two ways in

Pick whichever fits.

1. **The shell example** — `scripts/cauth-curl-example.sh` produces
   the bytes from scratch using only `openssl`, `curl`, `jq`, `base64`,
   `xxd`, and `printf`. Read this when you want to see the wire shape
   bytes-for-bytes, port the client to another language, or convince
   yourself nothing is up your sleeve.
2. **The unified CLI** — `continuity auth init` / `continuity auth
   curl` (the bb-based `continuity` binary, installed via `install.sh`
   or `brew install`). Read this when you want to *use* it.

Both speak the same wire protocol. The shell example is the
reference; the CLI is the ergonomic surface.

## Quick start (shell reference)

```bash
# Bootstrap an identity using the shell example.
CONTINUITY_AUTH_ENDPOINT=http://localhost:8080 ./scripts/cauth-curl-example.sh

# Optional: burn the per-tier budget to demonstrate identity binding.
CONTINUITY_AUTH_DEMO_LOOP=200 ./scripts/cauth-curl-example.sh
```

The script generates an Ed25519 keypair under `$CONTINUITY_AUTH_WORKDIR`
(default a fresh `mktemp -d`), constructs the FPL2 canonical bytes
field-by-field, signs with `openssl pkeyutl -sign -rawin`, base64url-
encodes the byte fields, POSTs `/v1/bootstrap`, then `/v1/verify`, and
prints the decision.

It is written for portability across BSD and GNU coreutils. No
Python, no Node, no Clojure required.

## Quick start (ergonomic CLI)

```bash
# Install (one of):
curl -fsSL https://raw.githubusercontent.com/The-Continuity-Project/continuity-auth/main/install.sh | sh
# or, on macOS — the Homebrew tap will be registered alongside the v0.1.0 tag:
#   brew tap The-Continuity-Project/tap && brew install continuity
# until then, install from the formula path:
#   brew install --HEAD --build-from-source ./Formula/continuity.rb

# Bootstrap an identity.
continuity auth init

# Show what you've got.
continuity auth show

# Wrap a request: continuity attaches X-Continuity-Envelope.
continuity auth curl -X POST -d '{"thing":"value"}' https://app.example.com/api/thing
```

The CLI is a babashka script (`bin/continuity`). It uses the same
`continuity-auth.envelope` namespace as the JVM server, so the bytes it
produces are guaranteed to match what the server reconstructs.

## Env-var contract

| Variable | Default | Purpose |
|---|---|---|
| `CONTINUITY_AUTH_ENDPOINT` | `http://localhost:8080` | continuity-auth server base URL |
| `CONTINUITY_AUTH_HOME` | `$XDG_CONFIG_HOME/continuity-auth` (`~/.config/continuity-auth`) | Key + identity state dir |
| `CONTINUITY_AUTH_HOST_ID` | empty | `host_user_id` envelope field |
| `CONTINUITY_AUTH_ADMIN_KEY_ID` | — | (admin) HMAC key identifier |
| `CONTINUITY_AUTH_ADMIN_SECRET_FILE` | — | (admin) Path to HMAC secret |

Same variables work for the shell example and the CLI. They mirror the
server's `CONTINUITY_AUTH_*` config namespace.

## Threat model — keys on disk

For browser clients, the keypair lives in IndexedDB as a non-extractable
Web Crypto handle; even XSS can use the key but cannot exfiltrate it.

For shell + CLI clients, the key lives on the filesystem at
`$CONTINUITY_AUTH_HOME/key.pem`. That is meaningfully different:

- **Threat: host compromise leaks the key.** Anyone with read access to
  `key.pem` can sign any envelope. continuity-auth's score model
  *already* treats "this key just appeared from N IPs in M seconds" as
  anomalous (driving the identity toward `penalized` and ultimately
  `banned`), so a leaked key cannot indefinitely impersonate the
  victim without producing observable behaviour. But the detection
  window is finite — a stolen key can do real damage for the minutes
  to hours before its anomalies trigger tier demotion.

- **Operator guidance:**
  - On personal machines, keep `$CONTINUITY_AUTH_HOME` mode `0700`.
  - On servers, store the key in a secrets manager and project it into
    a tmpfs-mounted `$CONTINUITY_AUTH_HOME` at process start. Don't commit it.
  - Rotate via `continuity auth init --rotate` (planned for v1.1; for
    v0.1 the path is: revoke via `continuity admin revoke-key`, then
    re-init).
  - Treat key compromise the same way you'd treat any long-lived API
    credential compromise: revoke, rotate, audit.

- **What this is NOT:** non-extractable hardware-anchored keys (TPM,
  Secure Enclave, Android Keystore, iOS Keychain). Wrappers around
  those are natural follow-on work but out of scope for v0.1.

## When NOT to use a non-browser client

- **You want a CAPTCHA-equivalent challenge for un-enrolled visitors.**
  continuity-auth's bootstrap is free for the caller — that's the
  point. If you want each new identity to *pay* (in attention or in
  CPU) before being trusted at all, layer a CAPTCHA or Anubis-style
  PoW in front of `/v1/bootstrap`.

- **The caller is a one-off cron run with no continuity expectation.**
  An ephemeral identity costs you a single bootstrap and earns no tier
  — there's no benefit over per-IP rate limiting. continuity-auth
  pays off when the identity *persists*, accumulating tier.

- **You can't trust the caller's filesystem.** A multi-tenant CI
  runner is a shared filesystem; storing a long-lived key there is the
  wrong shape. Use ephemeral per-job keys or per-tenant key files
  scoped via Unix permissions.

## See also

- [`docs/crypto-protocol.md`](crypto-protocol.md) — canonical-bytes
  layout (FPL2, length-prefixed fields).
- [`docs/api.md`](api.md) — `/v1/bootstrap`, `/v1/verify`,
  `/v1/admin/*` wire shapes.
- [`docs/threat-model.md`](threat-model.md) — T1–T19 coverage,
  including the IP/fingerprint advisory-only model and the
  filesystem-resident-key risks for non-browser callers.
- [`scripts/cauth-curl-example.sh`](../scripts/cauth-curl-example.sh)
  — the see-the-bytes reference.

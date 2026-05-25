# continuity-auth

A zero-auth trust service. Decides whether a request should be allowed, throttled, or denied based on a cryptographic vector of identity signals — not on credentials.

It is **not an authentication system**. It is a parallel rate-limit / trust advisor that layers on top of whatever auth a host application already has.

## What it is

For every request a host wants to rate-limit:

1. The host's frontend (running this library) signs the request envelope with a non-extractable Ed25519 private key generated on first visit.
2. The host's backend forwards the envelope to continuity-auth and gets back `{ok, tier, retry_after_ms, identity_ref}`.
3. The host enforces the decision.

The trust vector is a tuple `(ip, browser_fingerprint, ls_pubkey)`, optionally extended to `(ip, browser_fingerprint, ls_pubkey, host_user_id)` when the host server-to-server attests a logged-in user.

The merge rule: **any axis match** identifies the same user. **Any axis mismatch** within an established cluster lowers the trust score. The only cryptographically anchored merge signal is the LS pubkey — IP and fingerprint matches are advisory only, so an attacker cannot poison a cluster they have no key for.

See [`.plans/read-docs-seed-md-and-plan-reflective-catmull.md`](.plans/read-docs-seed-md-and-plan-reflective-catmull.md) for the full plan, [`docs/seed.md`](docs/seed.md) for the original spec, and [`docs/threat-model.md`](docs/threat-model.md) (once written) for the security analysis.

## Stack

- Server: Clojure 1.12 on JDK 21, Ring/Reitit, Jetty 11, Malli, Integrant.
- Storage: Datalevin (LMDB, server mode in prod).
- Crypto: BouncyCastle for Ed25519 on JVM; Web Crypto SubtleCrypto in the browser.
- Frontend: ClojureScript via shadow-cljs, target ≤ 25 KB gzipped.

## Layout

```
src/continuity_auth/         — Clojure + ClojureScript sources
test/                          — kaocha + cljs.test
docs/                          — design + ops docs
bin/                           — task scripts
resources/                     — aero config, logback
.plans/                        — implementation plan(s)
```

## Common tasks (via [`just`](https://github.com/casey/just))

```
just run-dev       # start the service against an embedded Datalevin
just test          # run backend tests
just cljs-dev      # frontend dev server with hot reload
just cljs-release  # produce the publishable bundle
just docker-up     # run the full stack in containers
just load          # run the k6 load test
```

## Status

Under construction — see the plan file for execution order. Production cutover criteria are in §"Verification" of the plan.

## License

MIT — see [LICENSE](LICENSE).

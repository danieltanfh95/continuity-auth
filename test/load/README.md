# Load tests

Run the k6 script against a deployed continuity-auth instance to validate
performance against the plan's pass criteria.

## Prerequisites

- k6 ≥ 0.51 (`brew install k6`)
- A running continuity-auth server. For meaningful numbers run against a
  staging deployment that mirrors the prod resource budget (2 vCPU / 512MB
  heap / Datalevin server mode). Laptop runs will not hit the 2000 rps
  target — they are useful for catching regressions in shape, not for
  certifying the SLO.

## Run

    # Default: 2000 rps for 60 s against http://localhost:8080
    k6 run test/load/verify.js

    # Against a staging deployment
    K6_TARGET_URL=https://fl-staging.example.com k6 run test/load/verify.js

    # Tune pool / vu / duration
    POOL=500 VUS=100 DURATION=5m RPS=2000 k6 run test/load/verify.js

## Pass criteria

The script's `options.thresholds` enforce:

| Metric                                  | Threshold       |
|-----------------------------------------|-----------------|
| `http_req_duration{name:verify}` P50    | < 5 ms          |
| `http_req_duration{name:verify}` P99    | < 25 ms         |
| `http_req_failed{name:verify}` rate     | < 0.1 %         |

k6 exits non-zero if any threshold is breached.

## Notes

- The script bootstraps `$POOL` independent identities up-front (each with
  its own P-256 keypair) and round-robins verify requests across them, so
  the per-identity rate-limit window isn't the bottleneck — we're measuring
  signature-verify + replay-cache throughput.
- The fingerprint digest is a static 32-byte fixture; the verify path
  treats it as opaque input.
- See `docs/deployment.md` for the assumed target topology.

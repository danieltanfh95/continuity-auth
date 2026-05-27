#!/usr/bin/env bash
#
# cauth-curl-example.sh — see-the-bytes reference for continuity-auth.
#
# Bootstraps an Ed25519 identity against a continuity-auth server using
# only `openssl`, `curl`, `jq`, `base64`, `printf`, `xxd`, and `od`. The
# script implements the wire protocol from first principles so the bytes
# on the wire are visible; the ergonomic equivalent is `continuity auth
# init` (the bb client).
#
# Requirements (all bsd/gnu-portable):
#   openssl >= 3.0 (Ed25519 + -rawin support)
#   curl
#   jq
#   GNU coreutils OR BSD equivalents (base64, head, tr, od)
#
# Env vars:
#   CONTINUITY_AUTH_ENDPOINT   default http://localhost:8080
#   CONTINUITY_AUTH_HOST_ID    default "" (the host_user_id envelope field)
#   CONTINUITY_AUTH_WORKDIR    default $(mktemp -d) (key/state lives here)
#   CONTINUITY_AUTH_DEMO_LOOP  default 0 (set non-zero to run the rate-limit burn demo)
#
# Exit codes:
#   0   bootstrap + verify both 2xx
#   1   bootstrap failed
#   2   verify failed
#   3   rate-limit demo failed (when CONTINUITY_AUTH_DEMO_LOOP set)

set -euo pipefail

ENDPOINT="${CONTINUITY_AUTH_ENDPOINT:-http://localhost:8080}"
HOST_ID="${CONTINUITY_AUTH_HOST_ID:-}"
WORKDIR="${CONTINUITY_AUTH_WORKDIR:-$(mktemp -d -t cauth-curl-XXXXXX)}"
DEMO_LOOP="${CONTINUITY_AUTH_DEMO_LOOP:-0}"

KEY_PEM="${WORKDIR}/key.pem"
PUB_DER="${WORKDIR}/pubkey.der"
PUB_RAW="${WORKDIR}/pubkey.raw"
SIGN_IN="${WORKDIR}/sign-in.bin"
SIGN_OUT="${WORKDIR}/sign-out.bin"

log() { printf '%s\n' "$*" >&2; }

# -- byte helpers ---------------------------------------------------------

# base64url-encode stdin (no padding).
b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# uint32-BE write: $1 = integer; outputs 4 raw bytes to stdout.
u32be() {
  printf '%08x' "$1" | xxd -r -p
}

# Length-prefix: read all stdin into a tempfile, emit u32be(len) || bytes.
prefixed() {
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  u32be "$(wc -c < "$tmp")"
  cat "$tmp"
  rm -f "$tmp"
}

# SHA-256 raw 32-byte digest of stdin.
sha256bin() {
  openssl dgst -sha256 -binary
}

# ISO-8601 UTC with ms precision; uses fixed ".000Z" since the server
# tolerance is ±60s and shell `date` doesn't give us sub-second across
# all platforms.
iso8601_now() {
  date -u '+%Y-%m-%dT%H:%M:%S.000Z'
}

# -- 1. genkey + extract raw pubkey ---------------------------------------

if [[ ! -f "$KEY_PEM" ]]; then
  log "[init] generating Ed25519 keypair → $KEY_PEM"
  openssl genpkey -algorithm ed25519 -out "$KEY_PEM" 2>/dev/null
fi

log "[init] extracting raw 32-byte pubkey"
openssl pkey -in "$KEY_PEM" -pubout -outform DER -out "$PUB_DER" 2>/dev/null
# Ed25519 SPKI DER is 44 bytes: 12-byte prefix + 32 raw bytes.
tail -c 32 "$PUB_DER" > "$PUB_RAW"

PUBKEY_B64U="$(b64url < "$PUB_RAW")"
KEY_ID_RAW="$(mktemp)"
sha256bin < "$PUB_RAW" > "$KEY_ID_RAW"
KEY_ID_B64U="$(b64url < "$KEY_ID_RAW")"

log "[init] pubkey (b64url): $PUBKEY_B64U"
log "[init] key-id (b64url): $KEY_ID_B64U"

# -- 2. build canonical bytes ---------------------------------------------

# Synthetic fp digest: 32 bytes of randomness, persisted so subsequent
# verify calls produce the same fp-digest (the server treats fp as
# advisory; we just need it stable per "device" — the script run).
FP_DIGEST="${WORKDIR}/fp.bin"
if [[ ! -f "$FP_DIGEST" ]]; then
  head -c 32 /dev/urandom > "$FP_DIGEST"
fi
FP_B64U="$(b64url < "$FP_DIGEST")"

# build_envelope METHOD PATH (BODY-FILE) -> writes wire-envelope JSON to stdout
# Side effect: writes canonical-bytes blob to $SIGN_IN.
build_envelope() {
  local method="$1"
  local path="$2"
  local body_file="${3:-/dev/null}"

  local ts; ts="$(iso8601_now)"
  local nonce_file body_sha_file canon_file
  nonce_file="$(mktemp)"
  body_sha_file="$(mktemp)"
  canon_file="$(mktemp)"
  head -c 16 /dev/urandom > "$nonce_file"
  sha256bin < "$body_file" > "$body_sha_file"

  # Concatenate canonical bytes: literal version tag + each length-prefixed field.
  {
    printf 'FPL2\n'
    printf '%s' "$method"        | prefixed
    printf '%s' "$path"          | prefixed
    cat "$body_sha_file"         | prefixed
    printf '%s' "$ts"            | prefixed
    cat "$nonce_file"            | prefixed
    cat "$FP_DIGEST"             | prefixed
    printf '%s' "$HOST_ID"       | prefixed
    cat "$KEY_ID_RAW"            | prefixed
  } > "$canon_file"

  cp "$canon_file" "$SIGN_IN"

  # Sign with Ed25519 (-rawin: openssl signs the bytes directly, no hash).
  openssl pkeyutl -sign -inkey "$KEY_PEM" -rawin \
    -in "$SIGN_IN" -out "$SIGN_OUT" 2>/dev/null

  local sig_b64u nonce_b64u body_sha_b64u
  sig_b64u="$(b64url < "$SIGN_OUT")"
  nonce_b64u="$(b64url < "$nonce_file")"
  body_sha_b64u="$(b64url < "$body_sha_file")"

  jq -nc \
    --arg v "FPL2
" \
    --arg method "$method" \
    --arg path "$path" \
    --arg body_sha "$body_sha_b64u" \
    --arg ts "$ts" \
    --arg nonce "$nonce_b64u" \
    --arg fp "$FP_B64U" \
    --arg key_id "$KEY_ID_B64U" \
    --arg host_user_id "$HOST_ID" \
    --arg alg "ed25519" \
    --arg sig "$sig_b64u" \
    '{v:$v, method:$method, path:$path, body_sha:$body_sha, ts:$ts, nonce:$nonce, fp:$fp, key_id:$key_id, host_user_id:$host_user_id, alg:$alg, sig:$sig}'

  rm -f "$nonce_file" "$body_sha_file" "$canon_file"
}

# -- 3. POST /v1/bootstrap ------------------------------------------------

log "[bootstrap] building envelope"
ENV_JSON="$(build_envelope POST /v1/bootstrap)"

BOOT_BODY="$(jq -nc \
  --argjson envelope "$ENV_JSON" \
  --arg pubkey "$PUBKEY_B64U" \
  --arg alg "ed25519" \
  '{envelope:$envelope, pubkey:$pubkey, alg:$alg}')"

log "[bootstrap] POST ${ENDPOINT}/v1/bootstrap"
BOOT_RESP="$(curl -sS -X POST "${ENDPOINT}/v1/bootstrap" \
  -H 'Content-Type: application/json' \
  -d "$BOOT_BODY" \
  -w '\n__HTTP_STATUS__%{http_code}')"
BOOT_STATUS="${BOOT_RESP##*__HTTP_STATUS__}"
BOOT_JSON="${BOOT_RESP%__HTTP_STATUS__*}"

log "[bootstrap] HTTP ${BOOT_STATUS}"
log "[bootstrap] body: ${BOOT_JSON}"

if [[ "$BOOT_STATUS" != "200" && "$BOOT_STATUS" != "201" ]]; then
  log "[bootstrap] FAILED"
  exit 1
fi

IDENTITY_REF="$(printf '%s' "$BOOT_JSON" | jq -r '.identity_ref // empty')"
log "[bootstrap] identity_ref: ${IDENTITY_REF}"

# -- 4. POST /v1/verify --------------------------------------------------

log "[verify] building envelope"
VERIFY_ENV="$(build_envelope POST /v1/verify)"
VERIFY_BODY="$(jq -nc --argjson envelope "$VERIFY_ENV" '{envelope:$envelope}')"

log "[verify] POST ${ENDPOINT}/v1/verify"
VERIFY_RESP="$(curl -sS -X POST "${ENDPOINT}/v1/verify" \
  -H 'Content-Type: application/json' \
  -d "$VERIFY_BODY" \
  -w '\n__HTTP_STATUS__%{http_code}')"
VERIFY_STATUS="${VERIFY_RESP##*__HTTP_STATUS__}"
VERIFY_JSON="${VERIFY_RESP%__HTTP_STATUS__*}"

log "[verify] HTTP ${VERIFY_STATUS}"
log "[verify] body: ${VERIFY_JSON}"

if [[ "$VERIFY_STATUS" != "200" ]]; then
  log "[verify] FAILED — bootstrap succeeded but the first verify did not"
  exit 2
fi

# -- 5. (optional) rate-limit burn demo ----------------------------------

if [[ "$DEMO_LOOP" != "0" ]]; then
  log ""
  log "[demo] burning the anonymous-tier budget (CONTINUITY_AUTH_DEMO_LOOP=${DEMO_LOOP})"
  i=0
  while (( i < DEMO_LOOP )); do
    i=$((i+1))
    ENV="$(build_envelope POST /v1/verify)"
    BODY="$(jq -nc --argjson envelope "$ENV" '{envelope:$envelope}')"
    RESP="$(curl -sS -X POST "${ENDPOINT}/v1/verify" \
      -H 'Content-Type: application/json' \
      -d "$BODY" \
      -w '\n__HTTP_STATUS__%{http_code}')"
    S="${RESP##*__HTTP_STATUS__}"
    BJ="${RESP%__HTTP_STATUS__*}"
    log "[demo ${i}/${DEMO_LOOP}] HTTP ${S} ${BJ}"
    if [[ "$S" == "429" ]]; then
      log "[demo] rate-limit triggered after $i verifies — identity binding holds"
      exit 0
    fi
  done
  log "[demo] completed ${DEMO_LOOP} verifies without hitting 429"
fi

log ""
log "OK — identity ${IDENTITY_REF} bootstrapped and verified via curl + openssl."
log "Workdir: ${WORKDIR}"

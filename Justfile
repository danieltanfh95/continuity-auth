# continuity-auth task runner.
#
# Install just: https://github.com/casey/just

set shell := ["bash", "-uc"]

default:
    @just --list

# --- backend ---

run-dev:
    clojure -M:run

repl:
    clojure -M:dev

test:
    clojure -M:test

test-watch:
    clojure -M:test --watch

lint:
    clojure -M:lint

lint-init:
    clojure -M:lint-init

migrate:
    clojure -M:migrate

uberjar:
    clojure -T:build uber

# --- client (cljs) ---

cljs-dev:
    node_modules/.bin/shadow-cljs watch client

cljs-release:
    node_modules/.bin/shadow-cljs release npm-module
    node scripts/check-bundle-size.mjs

cljs-test:
    node_modules/.bin/shadow-cljs compile client-test
    node_modules/.bin/karma start karma.conf.cjs --single-run

# --- docker ---

docker-build:
    docker build -t continuity-auth:dev .

docker-up:
    docker compose up --build

docker-down:
    docker compose down -v

# --- load ---

load:
    k6 run test/load/verify.js

# --- continuity bb client ---

continuity-init:
    CONTINUITY_AUTH_ENDPOINT=${CONTINUITY_AUTH_ENDPOINT:-http://localhost:8080} bin/continuity auth init

continuity-demo:
    CONTINUITY_AUTH_ENDPOINT=${CONTINUITY_AUTH_ENDPOINT:-http://localhost:8080} bin/continuity auth init
    CONTINUITY_AUTH_ENDPOINT=${CONTINUITY_AUTH_ENDPOINT:-http://localhost:8080} bin/continuity auth show
    CONTINUITY_AUTH_ENDPOINT=${CONTINUITY_AUTH_ENDPOINT:-http://localhost:8080} bin/continuity auth curl http://localhost:8080/healthz

# --- meta ---

all-tests: lint test cljs-test

# Local CI gate. Run this before pushing; the project does not use hosted
# runners. Single command, fails fast, no third-party trust.
ci: lint-init lint test uberjar cljs-release cljs-test

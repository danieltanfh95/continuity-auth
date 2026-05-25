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
    npx shadow-cljs watch client

cljs-release:
    npx shadow-cljs release npm-module
    @bin/check-bundle-size

cljs-test:
    npx shadow-cljs compile client-test
    npx karma start karma.conf.js --single-run

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

# --- meta ---

all-tests: lint test cljs-test

ci: lint-init lint test cljs-release cljs-test

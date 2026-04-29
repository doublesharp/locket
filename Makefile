SHELL := /bin/bash

CARGO ?= cargo
CARGO_DENY ?= cargo deny
CARGO_AUDIT ?= cargo audit
CARGO_LLVM_COV ?= cargo llvm-cov
CARGO_FUZZ ?= cargo +nightly fuzz
CARGO_JOBS ?= 12
OFFLINE ?= 1
STRICT ?= 0
FUZZ_TARGET ?=
FUZZ_ARTIFACT ?=
FUZZ_TIME ?= 60
FUZZ_MAX_LEN ?= 65536
FUZZ_TIMEOUT ?= 30
FUZZ_RSS_LIMIT_MB ?= 2048

ifeq ($(OFFLINE),1)
CARGO_OFFLINE_FLAG := --offline
else
CARGO_OFFLINE_FLAG :=
endif

.PHONY: ci ci-local ci-strict fmt fmt-check clippy test nextest coverage coverage-html coverage-branch mutation supply-chain supply-chain-local audit deny unsafe-inventory sbom bench bench-ci bench-report fuzz-list fuzz-smoke fuzz fuzz-nightly fuzz-minimize leak-canary docs-check clean

# Local default gate. It avoids network by default and skips missing optional tools
# with explicit warnings. Use `make ci-strict OFFLINE=0 STRICT=1` for release-style
# blocking checks.
ci: ci-local

ci-local: fmt-check clippy test leak-canary bench-ci supply-chain-local

ci-strict: fmt-check clippy test coverage coverage-branch mutation leak-canary docs-check bench-ci deny audit fuzz-smoke

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features $(CARGO_OFFLINE_FLAG) -j $(CARGO_JOBS) -- -D warnings

test:
	scripts/cargo-test.sh

nextest:
	scripts/cargo-test.sh nextest

coverage:
	scripts/coverage.sh line

coverage-html:
	scripts/coverage.sh html

coverage-branch:
	scripts/coverage.sh branch

mutation:
	scripts/mutation-smoke.sh

supply-chain: supply-chain-local

supply-chain-local:
	scripts/supply-chain.sh local

audit:
	scripts/supply-chain.sh audit

deny:
	scripts/supply-chain.sh deny

unsafe-inventory:
	scripts/supply-chain.sh unsafe

sbom:
	scripts/supply-chain.sh sbom

bench:
	scripts/bench-smoke.sh full

bench-ci:
	scripts/bench-smoke.sh ci

bench-report:
	scripts/bench-smoke.sh report

fuzz-list:
	CARGO_FUZZ="$(CARGO_FUZZ)" scripts/fuzz-smoke.sh list

fuzz-smoke:
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TIME="$(FUZZ_TIME)" FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" STRICT="$(STRICT)" scripts/fuzz-smoke.sh

fuzz:
	@test -n "$(FUZZ_TARGET)" || (echo "Set FUZZ_TARGET=<target>"; exit 2)
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TARGETS="$(FUZZ_TARGET)" FUZZ_TIME="$(FUZZ_TIME)" FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" STRICT="$(STRICT)" scripts/fuzz-smoke.sh run

fuzz-nightly:
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TIME=900 FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" STRICT=1 scripts/fuzz-smoke.sh nightly

fuzz-minimize:
	@test -n "$(FUZZ_TARGET)" || (echo "Set FUZZ_TARGET=<target>"; exit 2)
	@test -n "$(FUZZ_ARTIFACT)" || (echo "Set FUZZ_ARTIFACT=<path-to-crash>"; exit 2)
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TARGET="$(FUZZ_TARGET)" FUZZ_ARTIFACT="$(FUZZ_ARTIFACT)" FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" scripts/fuzz-minimize.sh

leak-canary:
	scripts/leak-canary.sh

docs-check:
	scripts/docs-check.pl

clean:
	$(CARGO) clean
	rm -rf coverage target/quality

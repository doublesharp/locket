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
FUZZ_TIME ?= 60

ifeq ($(OFFLINE),1)
CARGO_OFFLINE_FLAG := --offline
else
CARGO_OFFLINE_FLAG :=
endif

.PHONY: ci ci-local ci-strict fmt fmt-check clippy test nextest coverage coverage-html coverage-branch mutation supply-chain supply-chain-local audit deny unsafe-inventory sbom bench bench-ci bench-report fuzz-list fuzz-smoke fuzz fuzz-nightly leak-canary docs-check clean

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
	$(CARGO_FUZZ) list

fuzz-smoke:
	scripts/fuzz-smoke.sh

fuzz:
	@test -n "$(FUZZ_TARGET)" || (echo "Set FUZZ_TARGET=<target>"; exit 2)
	$(CARGO_FUZZ) run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_TIME)

fuzz-nightly:
	FUZZ_TIME=900 STRICT=1 scripts/fuzz-smoke.sh

leak-canary:
	scripts/leak-canary.sh

docs-check:
	scripts/docs-check.pl

clean:
	$(CARGO) clean
	rm -rf coverage target/quality

SHELL := /bin/bash

CARGO ?= cargo
CARGO_DENY ?= cargo deny
CARGO_AUDIT ?= cargo audit
CARGO_GEIGER ?= cargo geiger
CARGO_VET ?= cargo vet
CARGO_MACHETE ?= cargo machete
CARGO_UDEPS ?= cargo +nightly udeps
CARGO_LLVM_COV ?= cargo llvm-cov
CARGO_FUZZ ?= cargo +nightly fuzz
PNPM ?= $(shell command -v pnpm 2>/dev/null)
CARGO_JOBS ?= 12
OFFLINE ?= 1
STRICT ?= 0
FUZZ_TARGET ?=
FUZZ_ARTIFACT ?=
FUZZ_TIME ?= 60
FUZZ_MAX_LEN ?= 65536
FUZZ_TIMEOUT ?= 30
FUZZ_RSS_LIMIT_MB ?= 2048
BENCH_FIXTURE_PROFILE ?= smoke
BENCH_FIXTURE_OUT ?= target/bench-fixtures
SLSA_ARTIFACT ?=
SLSA_PROVENANCE ?=
SLSA_EXPECTED_REPOSITORY ?=
SLSA_EXPECTED_BUILDER ?=
SLSA_EXPECTED_BUILD_TYPE ?=
SLSA_EXPECTED_WORKFLOW ?=

ifeq ($(OFFLINE),1)
CARGO_OFFLINE_FLAG := --offline
else
CARGO_OFFLINE_FLAG :=
endif

.PHONY: ci ci-local ci-strict fmt fmt-check clippy test nextest coverage coverage-html coverage-branch mutation supply-chain supply-chain-local audit deny vet unsafe-inventory sbom supply-chain-exceptions dependency-hygiene machete udeps bench-fixtures bench bench-ci bench-report perf-agent-idle-memory perf-passphrase-unlock perf-recovery-envelope-unlock slsa-provenance fuzz-list fuzz-smoke fuzz fuzz-nightly fuzz-minimize leak-canary docs-check app-ui-install app-ui-check app-ui-build vscode-vsix-package clean

# Local default gate. It avoids network by default and skips missing optional tools
# with explicit warnings. Use `make ci-strict OFFLINE=0 STRICT=1` for release-style
# blocking checks.
ci: ci-local

ci-local: fmt-check clippy test leak-canary bench-ci supply-chain-local dependency-hygiene

ci-strict: fmt-check clippy test coverage coverage-branch mutation leak-canary docs-check bench-ci deny audit vet unsafe-inventory sbom dependency-hygiene slsa-provenance fuzz-smoke

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

vet:
	CARGO_VET="$(CARGO_VET)" STRICT="$(STRICT)" scripts/supply-chain.sh vet

unsafe-inventory:
	CARGO_GEIGER="$(CARGO_GEIGER)" scripts/supply-chain.sh unsafe

sbom:
	scripts/supply-chain.sh sbom

supply-chain-exceptions:
	scripts/supply-chain.sh exceptions

dependency-hygiene:
	CARGO_MACHETE="$(CARGO_MACHETE)" CARGO_UDEPS="$(CARGO_UDEPS)" STRICT="$(STRICT)" scripts/dependency-hygiene.sh local

machete:
	CARGO_MACHETE="$(CARGO_MACHETE)" STRICT="$(STRICT)" scripts/dependency-hygiene.sh machete

udeps:
	CARGO_UDEPS="$(CARGO_UDEPS)" STRICT="$(STRICT)" scripts/dependency-hygiene.sh udeps

bench-fixtures:
	scripts/bench-fixtures.pl --profile "$(BENCH_FIXTURE_PROFILE)" --out "$(BENCH_FIXTURE_OUT)"

bench: BENCH_FIXTURE_PROFILE = release
bench: bench-fixtures
	scripts/bench-smoke.sh full

bench-ci: BENCH_FIXTURE_PROFILE = smoke
bench-ci: bench-fixtures
	scripts/bench-smoke.sh ci

bench-report:
	scripts/bench-smoke.sh report

perf-agent-idle-memory:
	scripts/perf-agent-idle-memory.sh

perf-passphrase-unlock:
	scripts/perf-passphrase-unlock.sh

perf-recovery-envelope-unlock:
	scripts/perf-recovery-envelope-unlock.sh

slsa-provenance:
	@if [ -z "$(SLSA_ARTIFACT)" ] || [ -z "$(SLSA_PROVENANCE)" ] || [ -z "$(SLSA_EXPECTED_REPOSITORY)" ] || [ -z "$(SLSA_EXPECTED_BUILDER)" ] || [ -z "$(SLSA_EXPECTED_BUILD_TYPE)" ] || [ -z "$(SLSA_EXPECTED_WORKFLOW)" ]; then \
		echo "skip: set SLSA_ARTIFACT, SLSA_PROVENANCE, SLSA_EXPECTED_REPOSITORY, SLSA_EXPECTED_BUILDER, SLSA_EXPECTED_BUILD_TYPE, and SLSA_EXPECTED_WORKFLOW"; \
	else \
		scripts/slsa-provenance-policy.pl \
			--artifact "$(SLSA_ARTIFACT)" \
			--provenance "$(SLSA_PROVENANCE)" \
			--expected-repository "$(SLSA_EXPECTED_REPOSITORY)" \
			--expected-builder "$(SLSA_EXPECTED_BUILDER)" \
			--expected-build-type "$(SLSA_EXPECTED_BUILD_TYPE)" \
			--expected-workflow "$(SLSA_EXPECTED_WORKFLOW)"; \
	fi

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

app-ui-install:
	@if [ -z "$(PNPM)" ]; then \
		echo "skip: pnpm not on PATH"; \
	else \
		$(PNPM) --dir crates/locket-app/ui install --frozen-lockfile; \
	fi

app-ui-check: app-ui-install
	@if [ -z "$(PNPM)" ]; then \
		echo "skip: pnpm not on PATH"; \
	else \
		$(PNPM) --dir crates/locket-app/ui lint && \
		$(PNPM) --dir crates/locket-app/ui typecheck; \
	fi

app-ui-build: app-ui-install
	@if [ -z "$(PNPM)" ]; then \
		echo "skip: pnpm not on PATH"; \
	else \
		$(PNPM) --dir crates/locket-app/ui build; \
	fi

vscode-vsix-package:
	PNPM="$(PNPM)" scripts/package-vscode-extension.sh

clean:
	$(CARGO) clean
	rm -rf coverage target/quality

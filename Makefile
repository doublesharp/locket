CARGO ?= cargo
CARGO_DENY ?= cargo deny
CARGO_AUDIT ?= cargo audit
CARGO_LLVM_COV ?= cargo llvm-cov
CARGO_FUZZ ?= cargo +nightly fuzz
FUZZ_TARGET ?=
FUZZ_TIME ?= 60

.PHONY: ci fmt fmt-check clippy test coverage coverage-html audit deny fuzz-list fuzz clean

ci: fmt-check clippy test deny audit

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test:
	$(CARGO) test --workspace --all-targets --all-features

coverage:
	$(CARGO_LLVM_COV) --workspace --all-features --fail-under-lines 90 --lcov --output-path coverage/lcov.info

coverage-html:
	$(CARGO_LLVM_COV) --workspace --all-features --fail-under-lines 90 --html --output-dir coverage/html

audit:
	$(CARGO_AUDIT)

deny:
	$(CARGO_DENY) check

fuzz-list:
	$(CARGO_FUZZ) list

fuzz:
	@test -n "$(FUZZ_TARGET)" || (echo "Set FUZZ_TARGET=<target>"; exit 2)
	$(CARGO_FUZZ) run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_TIME)

clean:
	$(CARGO) clean
	rm -rf coverage

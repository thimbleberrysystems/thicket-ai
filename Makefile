# Thicket — build, test, and coverage. Run `make help` for the list.
.DEFAULT_GOAL := help
.PHONY: help install install-rust install-python test test-rust test-python \
        coverage coverage-rust coverage-python demo fmt clippy

PY := cd sdk/py && PYTHONPATH=. python3
COV_INCLUDE := "*/thicket/*,*/fibers/py/*,*/weaves/py/*,*/apps/py/*"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## ---- install all dependencies ----
install: install-rust install-python ## Install everything (Rust components + coverage tool + Python deps)

install-rust: ## Rust toolchain components + cargo-llvm-cov (needs rustup)
	rustup component add llvm-tools-preview rustfmt clippy
	cargo install cargo-llvm-cov --locked || true

install-python: ## Python SDK + test/coverage deps (use a virtualenv)
	python3 -m pip install -r sdk/py/requirements-dev.txt

## ---- test ----
test: test-rust test-python ## Run all tests (Rust + Python)

test-rust: ## cargo test --workspace
	cargo test --workspace

test-python: ## Python unittest suite
	$(PY) -m unittest discover -s tests

## ---- coverage ----
coverage: coverage-rust coverage-python ## Coverage for both languages

coverage-rust: ## Rust line coverage (cargo-llvm-cov)
	cargo llvm-cov --workspace --summary-only

coverage-python: ## Python branch coverage (coverage.py)
	$(PY) -m coverage run --branch -m unittest discover -s tests
	cd sdk/py && python3 -m coverage report -m --include=$(COV_INCLUDE)

## ---- misc ----
demo: ## Build the directory + run the end-to-end demo
	cargo build -p thicket-directory --example directory_server
	python3 apps/py/demo/run_demo.py

fmt: ## Check Rust formatting
	cargo fmt --all --check

clippy: ## Lint (deny warnings)
	cargo clippy --workspace --all-targets -- -D warnings

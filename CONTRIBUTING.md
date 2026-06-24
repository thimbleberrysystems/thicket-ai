# Developing Thicket

Everything builds, tests, and measures coverage from a clean clone. `make help`
lists every target.

## Prerequisites

- **Rust** (stable) via [rustup](https://rustup.rs) — the coverage tooling needs
  rustup's `llvm-tools-preview` component.
- **Python 3.11+**.
- *(optional)* [Ollama](https://ollama.com) for the one live-inference test — the
  suite skips it gracefully when Ollama isn't running.

## Install all dependencies

```bash
make install
```

which runs:

```bash
# Rust: toolchain components + the coverage tool
rustup component add llvm-tools-preview rustfmt clippy
cargo install cargo-llvm-cov --locked

# Python: SDK runtime + test/coverage deps (prefer a virtualenv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r sdk/py/requirements-dev.txt
```

> On Debian/Ubuntu/WSL, a system Python may refuse `pip install` (PEP 668). Use a
> virtualenv as shown, or add `--break-system-packages`.

The Python dependencies are pinned in
[`sdk/py/requirements.txt`](sdk/py/requirements.txt) (runtime) and
[`sdk/py/requirements-dev.txt`](sdk/py/requirements-dev.txt) (+ coverage).

*(optional)* For the Ollama test:

```bash
ollama serve &        # start the daemon
ollama pull qwen2.5:0.5b
```

## Test

```bash
make test          # Rust + Python
make test-rust     # cargo test --workspace
make test-python   # PYTHONPATH=. python -m unittest discover -s tests
```

## Coverage

```bash
make coverage          # both languages
make coverage-rust     # cargo llvm-cov --workspace
make coverage-python   # coverage.py, branch coverage
```

CI enforces a Python coverage floor (`--fail-under`) so coverage can't silently
regress. Standalone `__main__` launchers are excluded (see
[`sdk/py/.coveragerc`](sdk/py/.coveragerc)); they're covered structurally by the
launchability smoke test instead.

## Run the demo

```bash
make demo   # builds the directory, then runs apps/py/demo/run_demo.py end to end
```

## What CI runs

`cargo fmt --check` · `cargo clippy -D warnings` · `cargo test --workspace`, then
the Python suite under coverage with the floor. Match it locally with
`make fmt clippy test coverage`.

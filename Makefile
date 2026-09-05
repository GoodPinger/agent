# Release build targets for the gpr agent.
#
# Linux uses **musl** — a glibc-linked (-gnu) binary won't start on older
# distros, and a monitoring agent that won't start is worse than none (§2.5).
#
# Cross-compiling musl/Windows from macOS needs a cross toolchain; the simplest
# is cargo-zigbuild (`cargo install cargo-zigbuild` + `brew install zig`), or use
# `cross`. On native Linux/Windows the plain `cargo build --target` works.

TARGETS = \
	x86_64-unknown-linux-musl \
	aarch64-unknown-linux-musl \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-pc-windows-msvc

.PHONY: build-all install-targets fmt clippy test check

## Add every release target's std (run once).
install-targets:
	rustup target add $(TARGETS)

## Build an optimized binary for every target.
build-all: $(TARGETS)

.PHONY: $(TARGETS)
$(TARGETS):
	cargo build --release --target $@

## Local dev gates (mirror CI).
fmt:
	cargo fmt --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

## Everything CI runs for the agent.
check: fmt clippy test

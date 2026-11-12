PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: run build install test check lint fmt clean

run:
	cargo run

build:
	cargo build --release

install: build
	mkdir -p $(BINDIR)
	install -m 755 target/release/macpack $(BINDIR)/macpack

test:
	cargo test

check:
	cargo check

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

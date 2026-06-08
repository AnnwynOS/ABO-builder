.PHONY: build install clean test

build:
	cargo build --release

install: build
	@DEST=$${HOME}/.local/bin; \
	mkdir -p $$DEST; \
	cp target/release/ABO-builder $$DEST/; \
	echo "==> Installed to $$DEST/ABO-builder"

test: build
	@echo "==> Running self-tests..."
	@cargo test

clean:
	cargo clean
.PHONY: install build test help

HELP_WIDTH=12

help:
	@echo "ForgeDB"
	@echo "  install      Build and install binary to PATH"
	@echo "  build        Compile all workspace crates"
	@echo "  test         Run all unit and integration tests"

install:
	@cargo install --path crates/bin --force

build:
	@cargo build --workspace

test:
	@cargo test --workspace

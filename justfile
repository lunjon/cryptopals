install-cli:
    cargo install --path ./cli

build-all: (_build "challenges") (_build "cli") (_build "core")

_build dir:
    cd {{dir}} && cargo build

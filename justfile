challenges:
    cd challenges && cargo test

install:
    cargo install --path ./cli

fmt:(_fmt "challenges") (_fmt "cli") (_fmt "crypt")
_fmt dir:
    cd {{dir}} && cargo fmt

build-all: (_build "challenges") (_build "cli") (_build "crypt")
_build dir:
    cd {{dir}} && cargo build


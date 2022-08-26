build: build-challenges build-cli build-core

build-challenges: (_build "challenges")
build-cli: (_build "cli")
build-core: (_build "core")

_build dir:
    cd {{dir}} && cargo build

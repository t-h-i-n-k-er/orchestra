# Orchestra build automation.
#
# Install `just` from https://github.com/casey/just (or `cargo install just`).
# Recipes are intentionally small and composable so they map 1:1 onto CI steps.

# Default target triple of the host machine.
default_target := `rustc -vV | sed -n 's/host: //p'`

# Build the standalone agent binary for TARGET.
build-agent TARGET=default_target:
    cargo build --release -p agent --target {{TARGET}}

# Encrypt INPUT into dist/payload.enc using the base64 KEY.
encrypt-payload INPUT KEY:
    mkdir -p dist
    cargo run --release -p payload-packager -- \
        --input {{INPUT}} --output dist/payload.enc --key {{KEY}}

# Build the launcher binary for TARGET.
build-launcher TARGET=default_target:
    cargo build --release -p launcher --target {{TARGET}}

# Build the dev HTTP server (host triple only).
build-dev-server:
    cargo build --release -p dev-server

# Full pipeline: build agent, package it, build launcher; copy artefacts to dist/.
package-all TARGET=default_target KEY="":
    @if [ -z "{{KEY}}" ]; then echo "ERROR: KEY=<base64-32B> is required"; exit 1; fi
    just build-agent {{TARGET}}
    just build-launcher {{TARGET}}
    mkdir -p dist
    # Locate the built agent binary (extension differs per target).
    @cp target/{{TARGET}}/release/agent* dist/ 2>/dev/null || true
    @cp target/{{TARGET}}/release/launcher* dist/ 2>/dev/null || true
    just encrypt-payload $(ls dist/agent* | head -n1) {{KEY}}
    @echo "dist/ contents:" && ls -lh dist/

# Run the full workspace test suite (host platform).
test:
    cargo test --workspace --features agent/persistence

# Format + lint gate used by CI.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --features agent/persistence -- -D warnings

# moqtap development tasks

# Run all checks (what CI runs)
check: fmt-check clippy test doc-check

# Run tests
test:
    cargo test --workspace

# Run clippy lints
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --all --check

# Format code
fmt:
    cargo fmt --all

# Check documentation builds
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Build documentation and open in browser
doc:
    cargo doc --workspace --no-deps --open

# Run dependency audit
deny:
    cargo deny check

# Clean build artifacts
clean:
    cargo clean

# Check MSRV compatibility
msrv:
    cargo +1.75 check --workspace

# Publish a single crate (dry run)
publish-dry crate:
    cargo publish -p {{crate}} --dry-run

# Publish all crates (dry run, in dependency order)
publish-dry-all:
    cargo publish -p moqtap-codec --dry-run
    cargo publish -p moqtap-trace --dry-run
    cargo publish -p moqtap-client --dry-run
    cargo publish -p moqtap-proxy --dry-run

# Tag and release a crate: just release moqtap-codec 0.2.0
release crate version:
    #!/usr/bin/env bash
    set -euo pipefail
    # Verify crate exists
    if [ ! -f "crates/{{crate}}/Cargo.toml" ]; then
        echo "Error: crate '{{crate}}' not found in crates/"
        exit 1
    fi
    # Verify Cargo.toml version matches
    CARGO_VERSION=$(grep '^version' "crates/{{crate}}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
    if [ "$CARGO_VERSION" != "{{version}}" ]; then
        echo "Error: Cargo.toml version ($CARGO_VERSION) does not match requested version ({{version}})"
        echo "Update crates/{{crate}}/Cargo.toml first"
        exit 1
    fi
    # Dry-run publish to catch issues early
    echo "Running publish dry-run..."
    cargo publish -p {{crate}} --dry-run
    # Create and push tag
    TAG="{{crate}}/v{{version}}"
    echo "Creating tag: $TAG"
    git tag "$TAG"
    echo "Pushing tag..."
    git push origin "$TAG"
    echo "Done! CI will handle publishing to crates.io."

# Build docs for the site repo
docs-site output_dir="site/api":
    ./scripts/build-docs.sh {{output_dir}}

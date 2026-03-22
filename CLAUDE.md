# CLAUDE.md — Project conventions for moqtap

## What is this project?

moqtap is a Rust implementation of MoQT (Media over QUIC Transport) draft-14. It is structured as a Cargo workspace with 4 crates.

## Build and test

```sh
cargo test --workspace        # Run all tests
cargo clippy --workspace      # Lint
cargo fmt --all --check       # Check formatting
cargo doc --workspace --no-deps  # Build docs
```

Or use `just check` to run everything CI runs.

## Crate dependency order

```
moqtap-codec (no internal deps)
  -> moqtap-trace (depends on codec)
  -> moqtap-client (depends on codec)
  -> moqtap-proxy (depends on codec, client)
  -> moqtap-cli (depends on codec, trace, client, proxy)
```

When publishing to crates.io, publish in the order above.

## Code conventions

- **MSRV**: 1.75
- **Edition**: 2021
- **Max line width**: 100 characters (rustfmt.toml)
- **Error handling**: use `thiserror` for library error types
- **Async runtime**: tokio (full features)
- **QUIC**: quinn 0.11 with rustls 0.23
- **Serialization**: serde + serde_json for trace events only
- **CLI**: clap with derive macros

## Architecture principles

- `moqtap-codec` is a pure codec with zero I/O dependencies (only `bytes` and `thiserror`)
- State machines in `moqtap-client` (including the `session` submodule) are pure — no I/O, fully testable
- The `connection` module in `moqtap-client` is the only place with real network I/O

## Test patterns

- Tests are in `crates/*/tests/` (integration test style)
- Unit tests use `#[cfg(test)] mod tests` within source files
- All public APIs have test coverage
- No test requires network access — connection tests would need a mock server

## File format

`.moqtrace` files use: 8-byte magic (`MOQTRACE`) + 4-byte LE version (1) + JSON-lines events.

## Release process

Each crate has its own version and is released independently.

### Releasing a crate

1. Update `version` in `crates/<crate>/Cargo.toml`
2. If this crate is a dependency of others, update the version in `[workspace.dependencies]`
3. Update the crate's `CHANGELOG.md`
4. Commit and push to main
5. Tag: `git tag codec-v0.2.0` (format: `<crate-name-suffix>-v<version>`)
6. Push tag: `git push origin codec-v0.2.0`

CI handles:
- **Any crate tag** → publishes that crate to crates.io + rebuilds rustdoc
- **moqtap-cli tag** → additionally builds cross-platform binaries and creates a GitHub release

Shortcut: `just release moqtap-codec 0.2.0` (validates version, dry-run publishes, tags, and pushes)

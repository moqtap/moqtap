# moqtap development tasks

# `draft-matrix` is a standing CI gate: the fourteen
# single-draft/zero-draft rows for `moqtap-client` and `moqtap-proxy`, with the
# resolved feature list asserted rather than inferred from an exit code. It was
# held out of this list while the `framer.rs` / `session.rs` draft collapse was
# in flight; that landed, `just draft-matrix` reports failures=0, and it is a
# dependency again — so `check` is once more the whole of CI.
#
# `msrv`, `deny` and `versions` are deliberately separate: the first two need a
# pinned toolchain and `cargo-deny`, which a contributor may not have installed,
# and `versions` needs the network. CI runs all three as their own jobs.
# Everything else CI runs is reachable from here.
#
# `interop` is separate for a fourth reason: it needs Docker and a container
# pulled from the network, and the peer it tests against is somebody else's
# codebase on somebody else's release schedule. A red run there can mean the
# other implementation moved, which is a thing to read and act on rather than a
# gate to fail a commit on. See the recipe at the foot of this file.
#
# Run all checks (except msrv, deny and versions — see the comment above)
check: fmt-check clippy test test-features optional-features draft-matrix draft-targets doc-check determinism

# Run tests
test:
    cargo test --workspace

# The feature combinations `cargo test --workspace` does not compile. A feature
# that is off by default is built by nothing unless something names it, and each
# row below was, at one point, named by nothing at all:
#
#   * `quinn-socket` compiles the socket adapter, its suite, and the committed
#     adapter that reports every impairment and forwards the datagram untouched
#     — plus the test that runs the socket suite against that adapter and
#     requires it to fail. `--workspace` does reach this through the proxy's
#     dev-dependency, so the row is here for the direct clippy rather than for
#     coverage.
#   * `quinn-netem` with no features is the zero-dependency engine — also not
#     reachable from `--workspace`, which unifies `quinn-socket` on.
#   * `serde` on `quinn-netem` compiles the derives on the profile and
#     impairment types. It is the crate's other optional dependency, and
#     therefore the other axis on which an engine that depends on nothing can
#     stop being one; a build that never enables it cannot notice.
#   * `webtransport` gates the WebTransport arm of the proxy's listener.
#   * `cert-gen` gates a module, its documentation example and two whole-file
#     `#![cfg]` test files: eleven integration tests and one doctest that no
#     recipe and no CI job compiled until they were listed here.
#   * `impair` gates the proxy's ability to install an impairment profile on a
#     leg's socket. `--workspace` does compile `quinn-netem` — the proxy
#     dev-depends on it — but that says nothing about the feature-gated code in
#     the proxy, which is what this row is for.
#   * `serde` derives Serialize and Deserialize on the configuration types.
#     Both are rows because neither feature implies the other: a build with
#     serde in the tree cannot show that the impairment control plane still
#     compiles without it, which is the cheaper build and the one more callers
#     will ask for.
#   * `qlog` gates a whole module — the spec type, its refusals, and the
#     loopback test that runs a real QUIC connection and counts the bytes the
#     capture recorded. It also turns on `quinn/qlog`, so this row is the only
#     place the qlog-capable build of quinn is compiled at all; without it a
#     quinn upgrade that moved the sink API would be found by whoever enabled
#     the feature next rather than here.
#
# `clippy` as well as `test` on each row, and not because it is thorough: the
# workspace clippy recipe sees only the default feature set, so a lint firing in
# code behind one of these features is invisible to every other recipe here.
#
# Run clippy and the tests behind each non-default feature (matches CI)
optional-features:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== quinn-netem: engine only, no features ==="
    cargo clippy -p quinn-netem --all-targets -- -D warnings
    cargo test -p quinn-netem
    echo "=== quinn-netem: socket adapter + send-anyway shim ==="
    cargo clippy -p quinn-netem --features quinn-socket --all-targets -- -D warnings
    cargo test -p quinn-netem --features quinn-socket
    echo "=== quinn-netem: serde derives ==="
    cargo clippy -p quinn-netem --all-targets --features serde -- -D warnings
    cargo test -p quinn-netem --features serde
    echo "=== moqtap-client: webtransport ==="
    cargo clippy -p moqtap-client --features webtransport --all-targets -- -D warnings
    cargo test -p moqtap-client --features webtransport
    echo "=== moqtap-proxy: webtransport ==="
    cargo clippy -p moqtap-proxy --features webtransport --all-targets -- -D warnings
    cargo test -p moqtap-proxy --features webtransport
    echo "=== moqtap-proxy: cert-gen ==="
    cargo clippy -p moqtap-proxy --features cert-gen --all-targets -- -D warnings
    cargo test -p moqtap-proxy --features cert-gen
    echo "=== moqtap-proxy: impair ==="
    cargo clippy -p moqtap-proxy --all-targets --features impair -- -D warnings
    cargo test -p moqtap-proxy --features impair
    echo "=== moqtap-proxy: serde ==="
    cargo clippy -p moqtap-proxy --all-targets --features serde -- -D warnings
    cargo test -p moqtap-proxy --features serde
    echo "=== moqtap-proxy: qlog ==="
    cargo clippy -p moqtap-proxy --all-targets --features qlog -- -D warnings
    cargo test -p moqtap-proxy --features qlog

# `--release` for two reasons. The statistical tests iterate hundreds of
# thousands of times and there is no optimisation override for the test profile,
# so the debug build spends minutes where this spends seconds; and the optimised
# build is a second, independent set of codegen decisions over the same integer
# arithmetic, which is where an engine that quietly depends on something
# unspecified stops agreeing with itself.
#
# CI runs this on all three operating systems. No runner can compare itself with
# another, so what makes "the same seed decides the same sequence everywhere" a
# checkable claim is that all three assert against one committed fixture that was
# computed by hand rather than blessed from the implementation.
#
# Run the reproducibility gate in the release profile (matches CI)
determinism:
    cargo test -p quinn-netem --release

# Run the codec test suite against each individual draft feature (matches CI).
test-features:
    #!/usr/bin/env bash
    set -euo pipefail
    for d in draft07 draft08 draft09 draft10 draft11 draft12 draft13 draft14 draft15 draft16 draft17 draft18 draft19; do
        echo "=== $d ==="
        cargo test -p moqtap-codec --no-default-features --features "$d"
    done
    echo "=== no drafts ==="
    cargo check -p moqtap-codec --no-default-features
    echo "=== draft07 + draft19 ==="
    cargo test -p moqtap-codec --no-default-features --features draft07,draft19
    echo "=== draft13 + draft14 ==="
    cargo test -p moqtap-codec --no-default-features --features draft13,draft14

# An exit code cannot distinguish a real single-draft build from the all-drafts
# build: if `default-features = false` is dropped from the root manifest's
# `[workspace.dependencies]` entries, cargo silently resolves every draft and
# warns only at the manifest level, where `RUSTFLAGS` cannot reach it. Measured:
# in that state all fourteen rows compiled all thirteen drafts and exited 0.
# So assert the resolved feature LIST, and assert the whole list.
#
# `quinn-netem` is deliberately not a row here. It has no draft features —
# impairment happens below the message layer, on datagram bytes, so a draft axis
# would multiply the matrix without changing a decision — and every row asserts a
# resolved draft string, so a crate with no drafts to resolve would report a
# mismatch on all thirteen and mean nothing by it. Its feature axes are covered
# by `optional-features`.
#
# Client + proxy libs under each single draft and zero drafts
draft-matrix:
    #!/usr/bin/env bash
    set -uo pipefail
    export RUSTFLAGS="-D warnings"
    fail=0
    # `$4` is the exit code the row is supposed to produce, 0 everywhere but
    # one place. `moqtap-proxy` with no draft at all is *refused*, at
    # const-evaluation: `capability::DEFAULT_DRAFT` has nothing to be, because
    # a proxy that compiled no draft can parse nothing and a silent default
    # would name a draft the build does not have. Asserting the refusal beats
    # skipping the row — an exit 0 there would mean that constant had quietly
    # acquired a fallback.
    run_row() {   # $1 = crate, $2 = feature args, $3 = expected resolution, $4 = expected exit
        local crate="$1" feat="$2" want="$3" want_rc="${4:-0}" got rc
        got=$(cargo tree -p "$crate" --no-default-features $feat \
                --edges normal --depth 1 --prefix none -f '{lib}={f}' 2>/dev/null \
              | grep -E '^moqtap_(client|codec)=' \
              | LC_ALL=C sort | paste -sd' ' -) || true
        cargo check -q -p "$crate" --no-default-features $feat --lib >/dev/null 2>&1
        rc=$?
        printf '%-14s %-20s exit=%-4d %s\n' "$crate" "${feat:-<zero drafts>}" "$rc" "$got"
        if [ "$rc" -ne "$want_rc" ]; then
            printf '  EXIT MISMATCH: expected %s\n' "$want_rc"
            fail=$((fail + 1))
        fi
        if [ "$got" != "$want" ]; then
            printf '  RESOLUTION MISMATCH: expected %s\n' "$want"
            fail=$((fail + 1))
        fi
    }
    for crate in moqtap-client moqtap-proxy; do
        echo "=== $crate ==="
        for d in draft07 draft08 draft09 draft10 draft11 draft12 draft13 draft14 draft15 draft16 draft17 draft18 draft19; do
            run_row "$crate" "--features $d" "moqtap_client=$d moqtap_codec=$d"
        done
        # The proxy is the one crate that must refuse a zero-draft build.
        if [ "$crate" = "moqtap-proxy" ]; then
            run_row "$crate" "" "moqtap_client= moqtap_codec=" 101
        else
            run_row "$crate" "" "moqtap_client= moqtap_codec="
        fi
    done
    echo "failures=$fail"
    exit $(( fail == 0 ? 0 : 1 ))

# `--lib` above is the whole of what a reduced draft set is checked for, and
# the three-OS test matrix runs the tests only under the default all-drafts
# build. Between them, every test target and the example in `moqtap-proxy` are
# compiled by nothing under a single draft.
#
# `--all-targets` on its own would close that and could not fail. A test target
# carrying `required-features` this feature set does not satisfy is not built
# and not reported: cargo skips it and exits 0, and an empty result is
# indistinguishable from a clean one. So the recipe also asserts WHICH test
# targets were built, against the set `cargo metadata` declares — which lists
# every one in the manifest whatever its `required-features` say.
#
# Comparing the reduced build against the DEFAULT build is not enough on its
# own, and this was measured rather than reasoned about: `required-features` on
# a test target naming a feature that is off in BOTH builds removes it from
# both, so the two agree and only the set `cargo metadata` declares notices.
#
# Test targets and the example under one draft, and the count asserted
draft-targets draft="draft07":
    #!/usr/bin/env bash
    set -euo pipefail
    export RUSTFLAGS="-D warnings"
    SCRIPT=$(cat <<'PY'
    import json, sys
    names = set()
    if sys.argv[1] == "declared":
        meta = json.load(sys.stdin)
        pkg = next(p for p in meta["packages"] if p["name"] == "moqtap-proxy")
        names = {t["name"] for t in pkg["targets"] if t["kind"] == ["test"]}
    else:
        for line in sys.stdin:
            line = line.strip()
            if not line.startswith("{"):
                continue
            msg = json.loads(line)
            if msg.get("reason") != "compiler-artifact":
                continue
            target = msg.get("target", {})
            if target.get("kind") == ["test"] and "moqtap-proxy" in msg.get("package_id", ""):
                names.add(target["name"])
    print(" ".join(sorted(names)))
    PY
    )
    cargo clippy -p moqtap-proxy --no-default-features --features {{draft}} --all-targets -- -D warnings
    declared=$(cargo metadata --format-version 1 --no-deps | python3 -c "$SCRIPT" declared)
    reduced=$(cargo clippy -p moqtap-proxy --no-default-features --features {{draft}} \
                --all-targets --message-format=json -- -D warnings | python3 -c "$SCRIPT" built)
    full=$(cargo clippy -p moqtap-proxy --all-targets --message-format=json -- -D warnings \
            | python3 -c "$SCRIPT" built)
    echo "declared: $(echo "$declared" | wc -w) test target(s)"
    echo "{{draft}}: $(echo "$reduced" | wc -w) built"
    echo "default features: $(echo "$full" | wc -w) built"
    status=0
    if [ "$reduced" != "$declared" ]; then
        echo "MISMATCH: --features {{draft}} built '$reduced', the manifest declares '$declared'"
        status=1
    fi
    if [ "$full" != "$declared" ]; then
        echo "MISMATCH: default features built '$full', the manifest declares '$declared'"
        status=1
    fi
    exit $status

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

# Check MSRV compatibility (must match rust-version in Cargo.toml)
msrv:
    cargo +1.88 check --workspace --all-targets

# Publish a single crate (dry run)
publish-dry crate:
    cargo publish -p {{crate}} --dry-run

# `quinn-netem` has no workspace dependencies at all, so its position here is
# free; it sits with the other leaf crate rather than next to the proxy, whose
# dev-dependency on it is path-only and therefore stripped from the published
# manifest.
#
# Check release numbers against crates.io: that every `[workspace.dependencies]`
# pin equals its member's version, and that no crate sits at an already-published
# version while carrying unreleased changes. Neither is observable from a build,
# a test or a lint — they only surface when `cargo publish` runs, which is after
# the number is permanent. Needs the network and fails closed without it.
#
# Run this before `just release`, not after.
versions:
    python3 scripts/check-versions.py

# Publish all crates (dry run, in dependency order)
publish-dry-all:
    cargo publish -p moqtap-codec --dry-run
    cargo publish -p moqtap-trace --dry-run
    cargo publish -p quinn-netem --dry-run
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
    # Create and push tag.
    #
    # The prefix, not the crate name. `publish.yml` triggers on `codec-v*`,
    # `trace-v*`, `client-v*`, `proxy-v*` and `netem-v*`, so a tag shaped
    # `moqtap-codec/v0.4.1` matches nothing: the push succeeds, this recipe
    # prints that CI will publish, and no workflow ever starts. Every tag in the
    # repository is already the prefix form; only this recipe disagreed. Keep
    # the case below and `publish.yml`'s in step, and refuse an unmapped crate
    # here rather than pushing a tag that fires nothing.
    case "{{crate}}" in
        moqtap-codec)  PREFIX=codec  ;;
        moqtap-trace)  PREFIX=trace  ;;
        moqtap-client) PREFIX=client ;;
        moqtap-proxy)  PREFIX=proxy  ;;
        quinn-netem)   PREFIX=netem  ;;
        *)
            echo "Error: no tag prefix for '{{crate}}'. Add it here and to publish.yml — both, or the tag fires nothing."
            exit 1 ;;
    esac
    TAG="${PREFIX}-v{{version}}"
    echo "Creating tag: $TAG"
    git tag "$TAG"
    echo "Pushing tag..."
    git push origin "$TAG"
    echo "Done! CI will handle publishing to crates.io."

# Build docs for the site repo
docs-site output_dir="site/api":
    ./scripts/build-docs.sh {{output_dir}}

# Interop against a real third-party MoQT relay: `moq-relay-ietf` from
# github.com/cloudflare/moq-rs, built from source in a container and reached
# over raw QUIC. It is what the public Cloudflare relays run, so this is the
# same implementation the endpoint directory is measured against.
#
# What this buys that `just test` cannot. Every integration test in
# `moqtap-proxy` builds both of the proxy's peers from these crates — the client
# is `moqtap-client` and so is `common::FakeRelay` — so every byte on both sides
# of the proxy comes out of `moqtap-codec`. That arrangement cannot see a
# symmetric encode/decode defect, and it cannot answer whether a foreign
# implementation accepts what this proxy re-frames. Here the far peer shares no
# code with this workspace, so a green run is two implementations agreeing.
#
# Not part of `check`, and the test itself carries `#[ignore]` on top of the
# environment variable this recipe sets, so `cargo test --workspace` is
# unaffected whether or not a relay happens to be running.
#
# `--nocapture` is not decoration. The test writes two things to stderr that
# libtest would otherwise swallow: the skip notice when no relay is reachable,
# and the census of every setup and control message the proxy reported — which
# is what says which parser arms a run actually reached.
#
# Start the relay, run the interop test against it, stop the relay
interop:
    #!/usr/bin/env bash
    set -euo pipefail
    just interop-up
    # Bring the relay down however this exits, including the test failing under
    # `set -e`. A container left listening on 4443 with authentication disabled
    # is not something to leave behind on a failure.
    trap 'just interop-down' EXIT
    MOQTAP_INTEROP_RELAY=127.0.0.1:4443         cargo test -p moqtap-proxy --test interop_moq_rs -- --ignored --nocapture

# Start the interop relay and wait until it is actually listening.
#
# The wait polls the relay's own log rather than sleeping a fixed interval:
# `docker compose up -d` returns when the container is started, which is before
# the process has bound its socket, and a QUIC dial into a closed port fails as
# a timeout that reads like a protocol fault.
#
# Start the interop relay and block until it has bound its socket
interop-up:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="crates/moqtap-proxy/tests/interop"
    compose="$dir/docker-compose.yml"

    # The relay refuses to start without a key and has no self-signed mode of
    # its own, so the certificate is made here and mounted in. Regenerated only
    # when absent: it is a throwaway for a loopback listener the proxy does not
    # verify, and nothing pins it.
    #
    # `//CN=localhost` with two slashes, not one. Under Git Bash a leading
    # slash is rewritten as a Windows path, and `-subj /CN=localhost` reaches
    # openssl as `C:/Program Files/Git/CN=localhost` — which fails with a
    # message about subject format that says nothing about the real cause. The
    # doubled slash is the documented escape and is inert on other platforms.
    if [ ! -f "$dir/certs/localhost.key" ]; then
        mkdir -p "$dir/certs"
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -keyout "$dir/certs/localhost.key" -out "$dir/certs/localhost.crt" \
            -subj "//CN=localhost" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    fi

    # Built on every start, from the git URL as a build context — no clone. The
    # build prints the commit the ref resolved to, which is what a red run needs
    # in order to be re-run against the same source later: `main` moves, and
    # MOQ_RELAY_REF takes a SHA to pin it. Rebuilding every time is the point;
    # an image reused because it already exists is an interop suite that has
    # stopped noticing the other implementation, which is the only failure it
    # exists to catch. An unchanged upstream hits the layer cache.
    #
    # The first build of a given revision compiles the relay from source and
    # takes a few minutes.
    ref="${MOQ_RELAY_REF:-main}"
    docker build -t "moqtap-interop-relay:$ref" \
        "https://github.com/cloudflare/moq-rs.git#$ref"
    docker compose -f "$compose" up -d
    for _ in $(seq 1 120); do
        if docker compose -f "$compose" logs relay 2>/dev/null | grep -q listening; then
            echo "relay ref: $ref"
            exit 0
        fi
        sleep 0.5
    done
    echo "relay did not report 'listening' within 60s; logs follow" >&2
    docker compose -f "$compose" logs relay >&2
    exit 1

# Stop and remove the interop relay
interop-down:
    docker compose -f crates/moqtap-proxy/tests/interop/docker-compose.yml down --remove-orphans

# Tail the interop relay's log.
#
# The other half of the evidence when a run goes red: the test reports what the
# proxy parsed, this reports what a foreign decoder made of the same bytes.
#
# Follow the interop relay's log
interop-logs:
    docker compose -f crates/moqtap-proxy/tests/interop/docker-compose.yml logs -f relay

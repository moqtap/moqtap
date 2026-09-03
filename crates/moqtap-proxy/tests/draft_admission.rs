//! A session refuses to start on a draft this build did not compile.
//!
//! `DraftVersion` carries all fourteen variants under every feature set, so
//! the draft in a `ProxySessionConfig` is a value the type system is happy
//! with whatever the build compiled — and
//! `ProxySessionConfig::default().draft` is one particular such value. On a
//! reduced-draft build, a caller who takes the default, or who names a draft
//! that feature set left out, gets a configuration that looks entirely
//! ordinary.
//!
//! # What such a session used to do
//!
//! Run. The codec's dispatch enums fall through to their catch-all arm and
//! answer `CodecError::UnsupportedDraft`, which is not an incomplete-input
//! error, so the object framer takes its terminal arm, latches
//! `BypassReason::DecodeError` and pumps the stream through as bytes. No
//! object surfaces to a hook, no shaping class claims anything, no
//! `ProxyEvent::Object` is emitted, and the control parser skips every frame
//! it cannot decode without a word. The run then completes and reports
//! success. That artifact — zero objects, zero shaped bytes, a clean exit —
//! is byte for byte what a session nobody sent anything on produces.
//!
//! # How this file measures it
//!
//! One row, sweeping every draft the enum has, and each element is judged
//! against `capability::draft_is_compiled` for the build the row is running
//! in. A draft this build carries has to get **past** the admission check,
//! which is observable because the session then fails on the deliberately
//! unparseable upstream address instead. A draft it does not carry has to be
//! refused by name, with the relay never dialled.
//!
//! Both halves are live in every build, and which of them each draft lands in
//! is decided by the feature set rather than by a `#[cfg]` written here: an
//! all-drafts build runs fourteen admissions and no refusals, and a
//! `--no-default-features --features draftNN` build runs one admission and
//! thirteen refusals. Nothing is skipped either way, so the row cannot quietly
//! stop checking anything.

mod common;

use std::sync::Arc;

use moqtap_codec::version::DraftVersion;
use moqtap_proxy::capability::draft_is_compiled;
use moqtap_proxy::error::ProxyError;
use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::session::{ProxySession, ProxySessionConfig};
use tokio_util::sync::CancellationToken;

/// The ALPN the fixture's client and its front endpoint speak.
///
/// `moq-00`, deliberately: it is the one ALPN that resolves to no draft at
/// all, which is what leaves `ProxySessionConfig::draft` as the session's
/// answer. An ALPN of `moqt-17` would settle the draft in the handshake and
/// the configured field would never be read.
const ALPN: &[u8] = b"moq-00";

/// An upstream address no resolver is asked about.
///
/// The relay is never dialled in this file, and that is the point rather
/// than a convenience: the check under test sits above the dial, so a
/// session that reaches the address at all has been admitted. Making the
/// address unparseable means the admitted case is answered from memory —
/// nothing here can hang, time out, or depend on a network being present.
const UNROUTABLE: &str = "not an address";

/// Start one session for `draft` over a real client connection and hand back
/// however it ended.
///
/// A `ProxySession` takes a `quinn::Connection`, so there is a client and a
/// front endpoint even though nothing is forwarded: the admission check runs
/// inside the session's own run loop, and reaching it any other way would be
/// testing a function rather than the sequence a caller actually gets.
///
/// `client_alpn` is empty rather than `ALPN`, which is what the accept path
/// hands over when a listener could not report one. Either value resolves to
/// no draft, so the configured field decides; the empty slice says so
/// without inviting a reader to check the table.
async fn session_outcome(draft: DraftVersion) -> ProxyError {
    common::init_crypto();

    let (front, addr) = common::spawn_quic_server(&[ALPN]);
    let running = tokio::spawn(async move {
        let incoming = front.accept().await.expect("the client connected");
        let conn = incoming.await.expect("the front handshake completed");

        // Functional-update syntax, which `ProxySessionConfig` permits
        // because it carries no `#[non_exhaustive]`: the two fields this row
        // cares about, and every other one exactly as a caller who wrote
        // nothing would have got it.
        let config = ProxySessionConfig {
            draft,
            upstream_addr: UNROUTABLE.to_string(),
            ..Default::default()
        };

        let session = ProxySession::new(
            SessionId(1),
            config,
            Vec::new(),
            Arc::new(NoOpProxyObserver),
            Arc::new(NoOpHook),
            CancellationToken::new(),
        );
        session.run(conn).await.expect_err("no session here can reach a relay")
    });

    let client_ep = common::client_endpoint(&[ALPN]);
    let client = client_ep
        .connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("the client handshake completed");

    let outcome = tokio::time::timeout(common::TIMEOUT, running)
        .await
        .expect("the session ended without the relay")
        .expect("the session task");
    client.close(0u32.into(), b"done");
    outcome
}

/// Every draft in the enum, whether or not this build compiled it.
///
/// Written out rather than derived from the feature set, because the drafts
/// this build *left out* are exactly what the row below is about and a list
/// assembled from `#[cfg]`s would not contain them.
const EVERY_DRAFT: [DraftVersion; 14] = [
    DraftVersion::Draft07,
    DraftVersion::Draft08,
    DraftVersion::Draft09,
    DraftVersion::Draft10,
    DraftVersion::Draft11,
    DraftVersion::Draft12,
    DraftVersion::Draft13,
    DraftVersion::Draft14,
    DraftVersion::Draft15,
    DraftVersion::Draft16,
    DraftVersion::Draft17,
    DraftVersion::Draft18,
    DraftVersion::Draft19,
    DraftVersion::Draft20,
];

/// A session configured for a draft this build cannot frame refuses to
/// start; one configured for a draft it can gets past the check.
///
/// The second half is not decoration. Without it a check that refused
/// *every* draft would satisfy the first half on a reduced build and would
/// be caught by nothing at all on an all-drafts build, where the first half
/// has no draft to fire on.
///
/// # Ablations, run
///
/// Two mutations, because the row has two halves and each is reddened by a
/// different one.
///
/// Delete the `draft_is_compiled` guard from `run_with_transport` in
/// `src/session.rs`. Under `cargo test -p moqtap-proxy
/// --no-default-features --features draft07 --test draft_admission`, thirteen
/// of the fourteen drafts stop being refused and the row reddens with
///
/// ```text
/// thread 'a_session_is_admitted_exactly_when_this_build_carries_its_draft'
/// (21564) panicked at crates\moqtap-proxy\tests\draft_admission.rs:192:13:
/// Draft08 was never compiled into this build, so a session on it forwards
/// every stream uninterpreted and reports success: it must be refused by
/// name, got upstream connection failed: invalid socket address syntax
/// ```
///
/// That tail is the whole of the evidence for the failure this guard
/// prevents: with it gone, a draft-07 build takes a draft-08 session as far
/// as resolving its relay address.
///
/// Widen the guard to refuse every draft — `if true` in place of the
/// `!draft_is_compiled(draft)` test. Under `cargo test -p moqtap-proxy
/// --all-features --test draft_admission` every one of the fourteen is
/// compiled, so the other half reddens instead:
///
/// ```text
/// thread 'a_session_is_admitted_exactly_when_this_build_carries_its_draft'
/// (53496) panicked at crates\moqtap-proxy\tests\draft_admission.rs:196:13:
/// this build compiled Draft07, so a session on it must be admitted and fail
/// on the address instead, got this session is configured for Draft07, which
/// this build did not compile: it would forward every stream uninterpreted,
/// surface no object to any hook, claim nothing with any shaping class, and
/// report success. Build with the matching draftNN feature, or configure a
/// draft this build carries
/// ```
#[tokio::test]
async fn a_session_is_admitted_exactly_when_this_build_carries_its_draft() {
    for draft in EVERY_DRAFT {
        let outcome = session_outcome(draft).await;
        if draft_is_compiled(draft) {
            assert!(
                matches!(outcome, ProxyError::UpstreamConnect(_)),
                "this build compiled {draft:?}, so a session on it must be admitted and fail on \
                 the address instead, got {outcome}"
            );
        } else {
            assert!(
                matches!(outcome, ProxyError::DraftNotCompiled { draft: named } if named == draft),
                "{draft:?} was never compiled into this build, so a session on it forwards every \
                 stream uninterpreted and reports success: it must be refused by name, got \
                 {outcome}"
            );
        }
    }
}

//! A control frame the decoder refuses: forwarded anyway, and reported.
//!
//! The proxy frames a control stream by following each message's declared
//! length, then hands the body to `AnyControlMessage::decode`. The two steps
//! fail independently, and this file is about the case where the first
//! succeeds and the second does not — the parser knows exactly where the
//! frame ends and cannot read what is inside it. Nothing about that is
//! exotic or per-draft: a Message Type the configured draft does not assign,
//! a body that does not match its own length field, and anything an
//! extension adds all arrive this way on all the drafts.
//!
//! # Two things were owed and neither was paid
//!
//! **The frame was skipped in silence.** No event, no counter, no
//! impairment. A control message this proxy could not read was therefore
//! indistinguishable, to everything downstream, from a control message the
//! peer never sent — and those two call for opposite conclusions. The data
//! path had this covered: a stream the framer gives up on emits one
//! `ImpairmentKind::FramerBypass`, which is what lets a reader tell "nothing
//! matched" from "nothing was looked at". The control path emitted nothing
//! at all.
//!
//! **On the mutating pipe the frame left the session.** That pipe exists so
//! a hook can rewrite control messages, so the parser *is* the forwarding
//! path there: bytes reach the far side only by being written back out
//! per decoded frame. A frame that did not decode was consumed by the parser
//! and never written. The peer received a control stream with a message
//! missing from the middle of it — every Request ID and state transition it
//! carried gone with it — and neither endpoint had anything to attribute
//! that to. This is the more serious of the two, and it is invisible from
//! the observation-only pipe, where the bytes are forwarded before anything
//! is parsed at all.
//!
//! So both pipes are driven here, one test each. They share a fixture and
//! nothing else: `Interest::NONE` with an observer routes through
//! `pipe_control_passthrough`, and `Interest::CONTROL` routes through
//! `pipe_control_mutating`, and a single test could only ever have been
//! evidence about one of them.
//!
//! # What the fixture is
//!
//! A frame declaring Message Type `0x3A` with an honest length of zero.
//! `0x3A` is unassigned on every draft from 07 to 20, and it is below
//! `0x40`, so it is a single byte under RFC 9000's varint encoding and under
//! MoQT's alike — one fixture, no per-draft encoder, and nothing malformed
//! about it. The decoder has nowhere to send it and says so; the parser can
//! still say where it ends.
//!
//! Two of them, `0x3A` then `0x3B`, because the report is emitted once per
//! direction and the counter counts every occurrence. One frame cannot tell
//! those apart: it satisfies "one event" and "count of one" at the same
//! time, and a build that emitted per frame, or counted per report, would
//! pass. The second frame is what separates them, and its different type is
//! what makes "the *first* refusal names itself" a claim.
//!
//! # What is deliberately not claimed
//!
//! Not the behaviour of good frames around a refused one. That is a
//! byte-level and order-level property, and it is gated where the bytes are
//! cheap to build: `ControlStreamParser`'s own unit tests feed a real
//! SUBSCRIBE either side of a refusal and compare the whole sequence. What
//! is asserted here is the half those cannot reach — that a session forwards
//! the frame, counts it and reports it.
//!
//! Not the relay-to-client direction either. Both fixtures are written by
//! the client, so every `leg` here is the turn taken from
//! `ProxySide::ClientToProxy`.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::event::{ImpairmentKind, ProxyEvent};
use moqtap_proxy::hook::{FrameCtx, ProxyHook};
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::transport::Leg;

use common::{FakeRelay, RecordingObserver, TimedReceiver};

// ── which draft, and how the session is told ───────────────────────────

/// Every draft this build compiled, oldest first. Each element carries its
/// own `#[cfg]`, so the array is the enabled set; the file-level gate above
/// is what makes it non-empty.
const COMPILED_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
];

/// The draft both fixtures are built for: the newest compiled.
///
/// Derived rather than named, so a single-draft CI row runs this file
/// against the draft it compiled instead of going green by absence. Nothing
/// asserted here is draft-specific — the Message Type is unassigned on
/// every draft and the refusal is one code path shared by every draft.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the front-end advertises and the session is told the client
/// negotiated.
///
/// Load-bearing rather than cosmetic. `DraftVersion::from_alpn` resolves
/// `moqt-15` and later, which fixes the session's draft before a byte
/// arrives and builds the control parser immediately. `moq-00` does not, so
/// on drafts 07-14 the pipe first peeks for a SETUP; the fixture below is
/// not one, which settles the draft to the configured fallback and builds
/// the parser then. Both routes are exercised across the CI rows, and the
/// assertions are the same either way.
const fn alpn(draft: DraftVersion) -> &'static [u8] {
    match draft {
        DraftVersion::Draft15 => b"moqt-15",
        DraftVersion::Draft16 => b"moqt-16",
        DraftVersion::Draft17 => b"moqt-17",
        DraftVersion::Draft18 => b"moqt-18",
        DraftVersion::Draft19 => b"moqt-19",
        _ => b"moq-00",
    }
}

/// How long a poll waits for something a correct build has already done.
///
/// A ceiling and never a measurement: every wait below is for a state a
/// working session reaches without being prompted, so load can make these
/// slower and cannot make them wrong.
const PATIENCE: Duration = Duration::from_secs(10);

// ── the fixture ────────────────────────────────────────────────────────

/// A control frame carrying `type_id` and an honest length of zero.
///
/// Built by hand rather than through the codec, which could not produce it:
/// the whole point is a Message Type the codec has no arm for. The framing
/// is the only part that has to be right, and it is two facts — a Message
/// Type varint, then a length that from draft-11 is a 16-bit big-endian
/// field and before that a varint.
fn undecodable_frame(draft: DraftVersion, type_id: u8) -> Vec<u8> {
    assert!(type_id < 0x40, "one byte under RFC 9000's encoding and under MoQT's alike");
    let mut out = vec![type_id];
    if draft.uses_fixed_length_framing() {
        out.extend_from_slice(&0u16.to_be_bytes());
    } else {
        out.push(0x00);
    }
    out
}

/// The two frames the client writes, back to back, as one buffer.
fn the_frames(draft: DraftVersion) -> (Vec<u8>, Vec<u8>) {
    (undecodable_frame(draft, 0x3A), undecodable_frame(draft, 0x3B))
}

// ── the hooks ──────────────────────────────────────────────────────────

/// A hook that declares one interest and passes whatever it is shown.
///
/// The message counter is what makes "the hook was never offered a frame
/// that did not decode" a measurement rather than an assumption: a build
/// that handed one over would have to invent an `AnyControlMessage` to do
/// it, and this would count it.
struct CountingHook {
    interest: Interest,
    messages: AtomicU64,
}

impl CountingHook {
    fn new(interest: Interest) -> Arc<Self> {
        Arc::new(Self { interest, messages: AtomicU64::new(0) })
    }

    fn messages_seen(&self) -> u64 {
        self.messages.load(Ordering::Relaxed)
    }
}

impl ProxyHook for CountingHook {
    fn interest(&self) -> Interest {
        self.interest
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        self.messages.fetch_add(1, Ordering::Relaxed);
        Action::Pass
    }
}

/// Poll `probe` until it answers, or give up naming what was awaited.
async fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        if let Some(v) = probe() {
            return v;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Every `Impairment` the observer saw, as `(leg, kind)`.
fn impairments(observer: &RecordingObserver) -> Vec<(Option<Leg>, ImpairmentKind)> {
    observer
        .events()
        .into_iter()
        .filter_map(|e| match e {
            ProxyEvent::Impairment { leg, kind, .. } => Some((leg, kind)),
            _ => None,
        })
        .collect()
}

/// Drive one pipe with the two undecodable frames and assert what the
/// session owed for them.
///
/// Shared because the claim is the same on both pipes and the routing is
/// the only difference; each caller supplies the `Interest` that chooses
/// the route, and the two are separate `#[tokio::test]`s so a failure names
/// the pipe.
async fn both_frames_are_forwarded_counted_and_reported_once(interest: Interest) {
    common::init_crypto();

    let (first, second) = the_frames(DRAFT);
    let both: Vec<u8> = first.iter().copied().chain(second.iter().copied()).collect();

    let relay = Arc::new(FakeRelay::bind(alpn(DRAFT)));
    let observer = Arc::new(RecordingObserver::new());
    let hook = CountingHook::new(interest);

    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        alpn(DRAFT),
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn(DRAFT)).await;
    let (mut client_send, _client_recv) =
        client_conn.open_bi().await.expect("the client opens its control stream");

    // A bidirectional stream does not reach the peer until a byte is
    // written on it, so the relay's accept is spawned around the first
    // write rather than awaited before it.
    let accepting = {
        let relay = Arc::clone(&relay);
        tokio::spawn(async move { relay.accept_bi().await })
    };

    client_send.write_all(&first).await.expect("the client writes the first frame");

    let (_relay_send, relay_recv) = tokio::time::timeout(PATIENCE, accepting)
        .await
        // A bidirectional stream does not reach the peer until a byte is
        // written on it, so this times out exactly when the proxy forwarded
        // nothing — which is what dropping the only frame it was given
        // amounts to.
        .expect("the relay saw a control stream; one exists only once a byte is forwarded")
        .expect("join");
    let relay_rx = TimedReceiver::spawn(relay_recv);

    // The first frame, all the way through, before the second is written.
    // Sequencing them is what makes `total: 1` a fact about the code rather
    // than about how the two writes happened to coalesce: both frames in one
    // chunk would be one feed, one report, and a total of 2 — also correct,
    // and not the claim being made here.
    assert_eq!(
        relay_rx.wait_for_bytes(first.len()).await,
        first,
        "a frame the proxy could not decode still has a peer that may be able to; it must reach \
         the relay verbatim"
    );
    let after_first =
        wait_for("the first refusal to be reported", || match impairments(&observer)[..] {
            [] => None,
            _ => Some(impairments(&observer)),
        })
        .await;

    client_send.write_all(&second).await.expect("the client writes the second frame");

    assert_eq!(
        relay_rx.wait_for_bytes(both.len()).await,
        both,
        "both frames reach the relay, in the order they were written"
    );
    wait_for("the second refusal to be counted", || {
        (proxy.counters().control_frames_not_decodable >= 2).then_some(())
    })
    .await;

    // ── what was owed ──────────────────────────────────────────────────

    // One report, naming the first refusal, on the connection the bytes
    // arrived on. Compared as a whole vector: a second report of the same
    // kind would satisfy a `contains`, and it is exactly what a build that
    // reported per frame would produce.
    assert_eq!(
        after_first,
        vec![(
            Some(Leg::Client),
            ImpairmentKind::ControlFrameNotDecodable { type_id: 0x3A, total: 1 }
        )],
        "the first refused frame is reported once, naming its own Message Type"
    );
    assert_eq!(
        impairments(&observer),
        after_first,
        "the report is once per control stream direction; the second refusal adds no event"
    );

    // The counter is the half the report cannot carry, and the two must
    // disagree here or one of them is measuring the other.
    assert_eq!(
        proxy.counters().control_frames_not_decodable,
        2,
        "every refusal is counted, however many were reported"
    );

    assert_eq!(
        hook.messages_seen(),
        0,
        "no hook is offered a message that did not decode; there is nothing to offer it"
    );
    assert!(
        observer.parse_errors().is_empty(),
        "a refused control frame is an impairment, not a parse error: {:?}",
        observer.parse_errors()
    );

    proxy.shutdown().await;
}

/// The observation-only pipe: an observer, and a hook that asked for
/// nothing.
///
/// `Interest::NONE` plus an attached observer is what puts the session on
/// `pipe_control_passthrough` — bytes are written to the far side first and
/// parsed afterwards, so forwarding was never in question here and the
/// report is the whole of what was missing.
///
/// *Ablation (measured):* drop the `report_refused_frames` call from
/// `emit_parsed_frames`. The counter goes with it — one call carries both —
/// so the row stops at the wait for the report:
///
/// ```text
/// ---- the_passthrough_pipe_forwards_counts_and_reports_a_refused_frame stdout ----
/// panicked at crates\moqtap-proxy\tests\control_undecodable.rs:
/// timed out waiting for the first refusal to be reported
/// ```
///
/// The mutating row stays green under that cut, which is the point of
/// having two: the call sites are separate and one of them going silent
/// says nothing about the other.
#[tokio::test]
async fn the_passthrough_pipe_forwards_counts_and_reports_a_refused_frame() {
    both_frames_are_forwarded_counted_and_reported_once(Interest::NONE).await;
}

/// The mutating pipe: a hook that declared `Interest::CONTROL`.
///
/// The forwarding claim has teeth on this route and only on this route. The
/// parser owns the write path here, so a refused frame it did not hand back
/// was a frame nothing ever wrote.
///
/// *Ablation (measured):* drop the `ParsedItem::Refused` arm's
/// `send.write_all(&raw)` in `forward_mutated_frames`, leaving the bare
/// `continue` this code had before the round:
///
/// ```text
/// ---- the_mutating_pipe_forwards_counts_and_reports_a_refused_frame stdout ----
/// panicked at crates\moqtap-proxy\tests\control_undecodable.rs:
/// the relay saw a control stream; one exists only once a byte is forwarded: Elapsed(())
/// ```
///
/// It fails earlier than the byte comparison and says more than the byte
/// comparison would have. The refused frame is the only thing this fixture
/// writes, and a bidirectional stream does not reach the peer until a byte
/// is written on it — so with the frame dropped the relay never sees the
/// control stream at all. All of this on a session that reported the
/// refusal correctly and counted it correctly, which is why the report was
/// not on its own the fix.
///
/// *Ablation (measured):* drop the `report_refused_frames` call from
/// `forward_mutated_frames` instead, leaving the forwarding intact:
///
/// ```text
/// ---- the_mutating_pipe_forwards_counts_and_reports_a_refused_frame stdout ----
/// panicked at crates\moqtap-proxy\tests\control_undecodable.rs:
/// timed out waiting for the first refusal to be reported
/// ```
///
/// Cut once per call site, because one cut stops at the first assertion
/// that reads it: the passthrough row is green under this one.
#[tokio::test]
async fn the_mutating_pipe_forwards_counts_and_reports_a_refused_frame() {
    both_frames_are_forwarded_counted_and_reported_once(Interest::CONTROL).await;
}

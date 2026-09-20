//! The draft a session frames with reaches the data tasks, on a session
//! nothing is observing.
//!
//! # The configuration these rows run, and why no other one would do
//!
//! Drafts 07 to 14 all negotiate the ALPN `moq-00`, so a session in that
//! cohort starts on the draft its configuration named and learns the real
//! one from CLIENT_SETUP. Every row here configures **draft-14**, hands the
//! session the ALPN `moq-00`, and has the client open its control stream and
//! offer **draft-11** and nothing else. So the configured draft and the
//! wire's draft disagree, by a pair whose subgroup streams open with
//! different bytes — `0x0C` on draft-11 and `0x14` on draft-14 — which is
//! what makes the disagreement visible in the objects rather than only in a
//! label.
//!
//! And **nothing observes**: [`NoOpProxyObserver`] answers `false` to
//! `wants_events`, and the session carries a [`ShapeProfile`], which is what
//! arms framing. That combination is the whole point. The SETUP peek used to
//! sit behind the observer gate, so this session — the one whose profile
//! most needs the draft — performed no detection at all, and the shared cell
//! it published into would have been a cell nothing ever wrote. A row run
//! with an observer attached proves nothing about it: the observer would
//! have turned the detection on.
//!
//! # What each row observes
//!
//! * [`the_rule_elides_the_object_it_names_and_leaves_its_neighbour`] — a
//!   hook rule naming one object by ID. With the client's draft, that object
//!   and only that object is gone from the stream the relay receives. With
//!   the configured one the framer cannot read the header at all, latches a
//!   bypass, forwards the stream verbatim, and the rule fires on nothing.
//! * [`a_shaped_session_with_no_interests_charges_its_class_for_real_objects`]
//!   — the same session with `Interest::NONE`, where the profile is the only
//!   consumer of the draft there is. It observes the shaper's own count of
//!   the objects it saw, which is zero on a stream the framer bypassed.
//!
//! Neither row reads a configured value back. The first asserts on the bytes
//! that reached the far peer, re-framed by an independent framer; the second
//! on what the shaper charged.
//!
//! # Two mutations, both applied, run, observed and reverted
//!
//! **One — read the per-task draft instead of the shared cell.** In
//! `session.rs`, `pipe_data_framed` opens with `let draft = ctx.draft.initial;`
//! in place of `let draft = ctx.resolved_draft().await;`. `initial` is
//! exactly the draft each `ForwardCtx` was cloned with, so this is the
//! per-task copy this work replaced. Both rows go red:
//!
//! ```text
//! thread 'the_rule_elides_the_object_it_names_and_leaves_its_neighbour' (52012)
//! panicked at crates\moqtap-proxy\tests\draft_refinement.rs:
//! assertion `left == right` failed: the rule names object 1, so the relay must
//! receive 0 and 2 and nothing between them
//!   left: [0, 1, 2]
//!  right: [0, 2]
//! ```
//!
//! ```text
//! thread 'a_shaped_session_with_no_interests_charges_its_class_for_real_objects' (68468)
//! panicked at crates\moqtap-proxy\tests\draft_refinement.rs:
//! assertion `left == right` failed: the shaper saw the three objects the client sent
//!   left: 0
//!  right: 3
//! ```
//!
//! **Two — put the SETUP peek back behind the observer gate.** In
//! `pipe_control_passthrough`, `if !detecting` becomes
//! `if !detecting || !ctx.observer_enabled`, which is where the detection
//! stood before this work. The cell is then never written on a session with
//! no observer, so the wait in mutation one's place returns the starting
//! draft and both rows fail identically — same lines, same left and right
//! values, differing only in the thread ids (`61740` and `50116`). That
//! identity is the point of running both: a shared cell nothing writes and
//! no shared cell at all are the same session, and a fix that only added the
//! cell would have shipped this failure under a new name.

//! Both drafts are compiled in, because both are load-bearing: draft-14 is
//! the one configured and draft-11 the one the client names, and a build
//! missing either cannot tell the two apart.

#![cfg(all(feature = "draft11", feature = "draft14"))]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, DropMode, Interest};
use moqtap_proxy::framer::{FramerConfig, FramerOut, ObjectFramer};
use moqtap_proxy::hook::{NoOpHook, ObjectCtx, ProxyHook};
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::parser::data::DataStreamType;
use moqtap_proxy::session::ProxySessionConfig;
use moqtap_proxy::shape::{
    BucketConfig, ClassRule, Discipline, Matcher, QueueConfig, ShapeProfile,
};

use common::{Ending, FakeRelay, TimedReceiver};

/// The ALPN both legs negotiate.
///
/// `moq-00` is load-bearing twice over: it is what drafts 07 to 14 all use,
/// so `DraftVersion::from_alpn` answers `None` and the session's draft stays
/// open to being named; and it is what makes CLIENT_SETUP the only thing
/// that can name it.
const ALPN: &[u8] = b"moq-00";

/// The draft the session is **configured** for, and the wrong answer.
const CONFIGURED: DraftVersion = DraftVersion::Draft14;

/// The draft the client's CLIENT_SETUP names, and the right answer.
const NAMED: DraftVersion = DraftVersion::Draft11;

/// How many objects each fixture stream carries.
const OBJECTS: u64 = 3;

/// The object ID the eliding rule names.
///
/// Not `0`: eliding the first object of a stream whose subgroup ID is
/// defined as that object's ID would redefine the subgroup ID for the
/// receiver, and the capability table refuses it. Object 1 has a neighbour
/// on each side, which is what makes "not its neighbour" observable in both
/// directions.
const NAMED_OBJECT: u64 = 1;

/// Payload bytes per object.
const PAYLOAD: usize = 16;

/// How long a row waits for bytes it expects.
const PATIENCE: Duration = Duration::from_secs(5);

// ── an encoder that shares nothing with the peek under test ────────────

/// QUIC variable-length integer, RFC 9000 §16.
///
/// Written here rather than borrowed from the codec so the CLIENT_SETUP
/// below is a fixture and not a round trip through the same code the proxy
/// reads it with.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1_073_741_824 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// A CLIENT_SETUP offering exactly one draft, in drafts 11-14's framing.
///
/// Type `0x20` as a one-byte varint, then a 16-bit big-endian payload
/// length — the framing draft-11 introduced — then the version list and an
/// empty parameter list. The version is `0xff000000 + draft`, which is what
/// the `moq-00` cohort puts on the wire.
fn client_setup(draft: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    put_varint(&mut payload, 1);
    put_varint(&mut payload, 0xff00_0000 + u64::from(draft));
    put_varint(&mut payload, 0);

    let mut out = vec![0x20];
    let len = u16::try_from(payload.len()).expect("the fixture setup is a few bytes");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// The stream-type byte a subgroup stream carrying an explicit Subgroup ID
/// opens with, per draft.
///
/// The two values this file needs differ, and that difference is the whole
/// experiment: a draft-14 framer handed `0x0C` cannot read the header, so it
/// gives up on the stream rather than mis-reading it.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        DraftVersion::Draft11 => 0x0C,
        DraftVersion::Draft14 => 0x14,
        other => panic!("this file only encodes draft-11 and draft-14 streams, not {other}"),
    }
}

/// A whole subgroup stream on `draft`: header, then [`OBJECTS`] objects of
/// [`PAYLOAD`] bytes, object IDs `0..OBJECTS`.
fn subgroup_stream(draft: DraftVersion) -> Vec<u8> {
    // Track alias 1, group 0, subgroup 0, publisher priority 0x80.
    let head = vec![subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80];
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(draft, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut out = head;
    for object_id in 0..OBJECTS {
        let fill = u8::try_from(0xA0 + object_id).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; PAYLOAD],
        };
        writer.write_object(&obj, &mut out).expect("write object");
    }
    out
}

/// The object IDs a captured stream decodes to, under `draft`.
///
/// An independent [`ObjectFramer`], built here from the bytes that actually
/// reached the far peer. A stream the proxy bypassed re-frames perfectly
/// well under the draft it was written in — that is the point: the bytes are
/// intact, and what is missing is any decision taken about them.
fn object_ids(bytes: &[u8], draft: DraftVersion) -> Vec<u64> {
    let mut framer = ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
    framer.feed(bytes);
    let mut ids = Vec::new();
    loop {
        match framer.poll() {
            FramerOut::NeedMore => return ids,
            FramerOut::Object { meta, .. } => ids.push(meta.object_id),
            FramerOut::Header { .. } | FramerOut::Passthrough(_) => {}
            FramerOut::Bypassed { reason, .. } => {
                panic!("the captured stream did not re-frame under {draft}: {reason:?}")
            }
            FramerOut::Error(e) => panic!("the captured stream did not re-frame: {e}"),
            other => panic!("unhandled FramerOut variant: {other:?}"),
        }
    }
}

// ── the fixtures ───────────────────────────────────────────────────────

/// A hook whose one rule names an object by ID and elides it.
///
/// [`Interest::OBJECTS`] and nothing else: no `Interest::CONTROL`, which
/// would route the control stream through the mutating pipe and detect the
/// draft there for an unrelated reason, and no observer anywhere in the
/// session. This hook is the *rule*; the profile beside it is what arms the
/// framing.
struct ElideOne;

impl ProxyHook for ElideOne {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        if cx.meta.object_id == NAMED_OBJECT {
            Action::Drop(DropMode::Elide)
        } else {
            Action::Pass
        }
    }
}

/// A profile that arms framing and paces nothing.
///
/// One bucket at an unlimited rate and one class claiming every unit, so
/// every object is classified, charged and released at once. It is here to
/// arm the framing path on a session with no observer — the configuration
/// the module docs describe — not to shape anything, and a rate would make
/// the rows below assertions about timing instead of about objects.
fn arming_profile() -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = "all".to_string();
    bucket.rate_bps = None;

    let mut class = ClassRule::default();
    class.name = "everything".to_string();
    class.bucket = "all".to_string();
    class.matcher = Matcher::default();

    ShapeProfile::try_new(vec![bucket], vec![class], QueueConfig::default(), Discipline::Fifo)
        .expect("one class naming its own bucket is a valid profile")
}

/// A draft-14 session config carrying [`arming_profile`].
fn shaped_config(upstream: SocketAddr) -> ProxySessionConfig {
    let mut config = common::session_config(CONFIGURED, upstream);
    config.shape = Some(arming_profile());
    config
}

/// Everything a row needs after the client has named its draft.
///
/// The four control-stream halves are held here and not dropped, and that
/// is load-bearing rather than tidy: quinn finishes a `SendStream` on drop
/// and stops a `RecvStream` on drop, so a half let go of ends the proxy's
/// control stream — and the first forwarding task to finish ends the whole
/// session. A row that dropped one would be measuring a session that had
/// already gone.
struct Named {
    client: quinn::Connection,
    relay: Arc<FakeRelay>,
    proxy: common::SpawnedProxy,
    _control: (quinn::SendStream, quinn::RecvStream),
    _relay_control: (quinn::SendStream, quinn::RecvStream),
    _client_endpoint: quinn::Endpoint,
}

/// Stand a session up, have the client name [`NAMED`] on its control
/// stream, and wait until the proxy has forwarded that CLIENT_SETUP to the
/// relay.
///
/// The wait is the row's synchronisation and it is a real one rather than a
/// sleep: the peek that names the draft runs **before** the chunk carrying
/// it is written on, so a relay that has the SETUP bytes is a relay whose
/// proxy has already settled the draft. Everything the rows do afterwards
/// happens on a session that knows what it is framing.
async fn name_the_draft(hook: Arc<dyn ProxyHook>) -> Named {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let proxy = common::spawn_proxy_with(
        shaped_config(relay.addr),
        ALPN,
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        hook,
    );

    let (client_endpoint, client) = common::connect_client(proxy.addr, ALPN).await;

    let setup = client_setup(11);
    let (mut control, control_recv) = client.open_bi().await.expect("the client control stream");
    control.write_all(&setup).await.expect("write CLIENT_SETUP");

    let (relay_send, mut relay_recv) = tokio::time::timeout(PATIENCE, relay.accept_bi())
        .await
        .expect("the proxy opens a control stream to the relay");
    let mut seen = vec![0u8; setup.len()];
    tokio::time::timeout(PATIENCE, relay_recv.read_exact(&mut seen))
        .await
        .expect("the CLIENT_SETUP reaches the relay")
        .expect("read the forwarded CLIENT_SETUP");
    assert_eq!(seen, setup, "the control stream forwards the SETUP verbatim");

    Named {
        client,
        relay,
        proxy,
        _control: (control, control_recv),
        _relay_control: (relay_send, relay_recv),
        _client_endpoint: client_endpoint,
    }
}

// ── the rows ───────────────────────────────────────────────────────────

/// **The rule elides the object it names, and leaves its neighbour.**
///
/// The session is configured for draft-14 and the client's SETUP names
/// draft-11; the stream the client then sends is a draft-11 subgroup stream.
/// A proxy framing it as draft-14 cannot read its header at all — the
/// stream-type byte is `0x0C` and draft-14 opens with `0x14` — so the framer
/// latches a bypass and forwards every byte uninterpreted. The rule is never
/// consulted, nothing is elided, and the session ends green.
///
/// Framed as draft-11, the rule sees three objects and removes exactly the
/// one it names. Drafts 07-13 encode absolute object IDs, so the survivors
/// are forwarded verbatim and the far peer decodes `0, 2` — a gap, which is
/// what `DropMode::Elide` promises.
///
/// *Ablation, run and recorded:* see the module docs.
#[tokio::test]
async fn the_rule_elides_the_object_it_names_and_leaves_its_neighbour() {
    let rig = name_the_draft(Arc::new(ElideOne)).await;

    let mut send = rig.client.open_uni().await.expect("the client opens a data stream");
    send.write_all(&subgroup_stream(NAMED)).await.expect("write the subgroup stream");
    send.finish().expect("finish the data stream");

    let recv = tokio::time::timeout(PATIENCE, rig.relay.accept_uni())
        .await
        .expect("the data stream reaches the relay");
    let rx = TimedReceiver::spawn(recv);
    assert_eq!(
        tokio::time::timeout(PATIENCE, rx.wait_for_ending())
            .await
            .expect("the forwarded stream ends"),
        Ending::Fin,
        "the client FINed its stream, so the relay must see a clean end",
    );
    let forwarded = rx.bytes();

    assert_eq!(
        object_ids(&forwarded, NAMED),
        vec![0, 2],
        "the rule names object {NAMED_OBJECT}, so the relay must receive 0 and 2 and nothing \
         between them",
    );

    rig.proxy.shutdown().await;
}

/// **A shaped session with no interests charges its class for real
/// objects.**
///
/// The configuration problem this file exists for, with nothing else in it:
/// a [`ShapeProfile`], no observer, and [`NoOpHook`] — `Interest::NONE`. The
/// profile is the only consumer of the draft in the whole session, and
/// before the peek was lifted out from behind the observer gate it was
/// consuming a guess.
///
/// The consequence observed is the shaper's own count of what it saw. A
/// stream the framer bypassed produces no `ObjectMeta` at all, so the
/// classifier never runs and the count is zero however many bytes crossed —
/// which is precisely the "byte pump reporting success" this gate exists to
/// tell apart from a session that shaped something.
///
/// *Ablation, run and recorded:* see the module docs.
#[tokio::test]
async fn a_shaped_session_with_no_interests_charges_its_class_for_real_objects() {
    let rig = name_the_draft(Arc::new(NoOpHook)).await;

    let mut send = rig.client.open_uni().await.expect("the client opens a data stream");
    send.write_all(&subgroup_stream(NAMED)).await.expect("write the subgroup stream");
    send.finish().expect("finish the data stream");

    let recv = tokio::time::timeout(PATIENCE, rig.relay.accept_uni())
        .await
        .expect("the data stream reaches the relay");
    let rx = TimedReceiver::spawn(recv);
    assert_eq!(
        tokio::time::timeout(PATIENCE, rx.wait_for_ending())
            .await
            .expect("the forwarded stream ends"),
        Ending::Fin,
        "the client FINed its stream, so the relay must see a clean end",
    );
    let forwarded = rx.bytes();
    assert_eq!(
        object_ids(&forwarded, NAMED),
        vec![0, 1, 2],
        "no rule claims anything here, so every object crosses",
    );

    let stats = rig.proxy.shape_stats();
    assert_eq!(stats.objects_seen, OBJECTS, "the shaper saw the three objects the client sent");
    assert_eq!(
        stats.classes[0].objects_delivered, OBJECTS,
        "and charged them to the class that claimed them",
    );

    rig.proxy.shutdown().await;
}

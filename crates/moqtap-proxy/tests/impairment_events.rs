//! The impairment stream, asserted as a **sequence** rather than a set.
//!
//! Every other integration file in this crate reads impairments through a
//! filter — "exactly one `EgressQueueFull`", "no `SerializeTargetUnknown`",
//! "at least one `FramerBypass`". Each of those is a claim about one kind in
//! isolation, and none of them can see the two defects this file exists for:
//!
//! * **an event that reports something the run did not do.** A filtered
//!   count is satisfied by an extra report as long as it is of a different
//!   kind, and a `contains` assertion is satisfied by an extra report of the
//!   *same* kind. The specific way that happens is an impairment emitted on
//!   the way *into* an operation a guard then refuses — see
//!   [`ProxyEvent::Impairment`]'s own rustdoc, which states the
//!   after-not-before rule and says plainly that nothing retracts one of
//!   these once it is out.
//! * **an event attributed to the wrong connection.** `leg` is not `side`
//!   renamed: most of what an impairment reports is a failure to *write*, so
//!   it belongs to the connection opposite the one the bytes arrived on. A
//!   report on the wrong leg still arrives, still carries a plausible kind,
//!   and blames a connection that is behaving perfectly.
//!
//! So the assertion here is `assert_eq!` on a whole `Vec<(Option<Leg>,
//! ImpairmentKind)>`. Not a set, not a superset, not `contains`: an extra
//! event fails it, a missing event fails it, a reordering fails it, and a
//! correct kind on the wrong leg fails it.
//!
//! # The run, and why each step is in it
//!
//! One session, two client-to-relay unidirectional streams, driven in a
//! fixed order with a feedback edge at every step, so the sequence is a
//! property of the code and not of the scheduler:
//!
//! | # | What the run does | What it owes |
//! |---|---|---|
//! | 1 | `on_stream_open` serializes stream A behind a key that names no stream | `SerializeTargetUnknown`, **Upstream** |
//! | 2 | object 0: `Delay { by: 9 s }` against a 60 ms `max_hold` | `HoldClamped`, **Upstream** |
//! | 3 | object 1: the same `Delay`, wrapping a `ReplacePayload` of the wrong length | **nothing** |
//! | 4 | object 2: `Delay { by: 9 s }` again | `HoldClamped`, **Upstream** |
//! | 5 | stream B opens with a header byte no draft decodes | `FramerBypass`, **Client** |
//!
//! Row 3 is the point of the file. The delay is admitted, the composition
//! is legal, and the *inner* action is refused — so the engine queues
//! nothing, holds nothing and clamps nothing, and the honest event count for
//! that object is zero. Rows 2 and 4 bracket it with the identical action
//! succeeding, so "row 3 emitted nothing" cannot be satisfied by a build
//! that stopped clamping altogether.
//!
//! Row 5 is the only step that changes the leg. Rows 1, 2 and 4 are all
//! failures to place bytes on the far side, so all three name the connection
//! **opposite** the one the objects arrived on; row 5 is the parser giving
//! up on bytes that came *in*, so it names the arriving one. Every one of the
//! four arrives on `ProxySide::ClientToProxy`, so a mapping that answered the
//! side's own connection everywhere would say `Client` four times — uniform,
//! plausible in a log, and wrong in the three places that are about what
//! could not be written.
//!
//! # What this file does not cover
//!
//! * **Twelve of the fifteen `ImpairmentKind`s.** The three asserted here
//!   plus the refusal are what one session over two streams can produce
//!   deterministically. `EgressQueueFull` is reachable but needs a queue
//!   depth that races the release wheel; `ObjectNotAddressable` needs an
//!   object past the framer's 4 MiB cap, which `session.rs` hardcodes;
//!   `CoarseReleaseTimer` needs an environment override; the four shaping
//!   reports need a profile and live in `actions_shaping.rs`;
//!   `ControlFrameNotDecodable` needs a control stream and lives in
//!   `control_undecodable.rs`; `QueuedBytesAtTeardown`, `DatagramNotSent`,
//!   `ControlStreamTruncated` and `ElideFixupLost` each need their own
//!   fixture. Those files assert *counts of a kind*; the sequence claim is
//!   made here and only over these four rows.
//! * **The relay-to-client direction.** Both streams run client → relay, so
//!   every `leg` here is the turn taken from `ProxySide::ClientToProxy`. The
//!   opposite turn is gated in `exec.rs`'s own unit tests
//!   (`one_pipe_reports_the_near_leg_the_far_leg_and_neither_in_order`),
//!   not over real traffic.
//! * **`None`.** No kind reachable from this fixture maps to "neither leg",
//!   so the third arm of the mapping is unexercised here.
//!
//! # Preconditions the fixture depends on
//!
//! `MOQTAP_RELEASE_TIMER` must not force the coarse backend. It would add a
//! `CoarseReleaseTimer` with `leg: None` on the session's first deferred
//! release — a genuine report, correctly placed, that this file's fixed
//! expectation does not name. [`the_release_backend_is_the_default_one`]
//! checks it explicitly rather than leaving the main gate to fail with a
//! confusing diff.
//!
//! # Which draft this file speaks
//!
//! The newest one this build compiled, derived rather than named, for the
//! reason `actions_timing.rs` sets out at length: a hardcoded draft makes
//! every other single-draft CI row green by absence. Nothing asserted here
//! is draft-specific — the refusal is a length comparison, the clamp is
//! arithmetic, and the bypass byte was checked against all thirteen drafts
//! (`0x00` is not a legal leading byte for a subgroup stream header on any
//! of them). A build with no draft compiled has no framer to drive, so the
//! whole file is gated out.

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
    feature = "draft19"
))]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, EgressConfig, Interest, StreamAction};
use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{ImpairmentKind, ProxyEvent, ProxySide};
use moqtap_proxy::framer::BypassReason;
use moqtap_proxy::hook::{ObjectCtx, ProxyHook, StreamCtx};
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::shape::StreamKey;
use moqtap_proxy::transport::Leg;

use common::{Ending, FakeRelay, SpawnedProxy, TimedReceiver};

// ── the shape of the run ───────────────────────────────────────────────

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
];

/// The draft every fixture here is built for: the newest compiled.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the front-end endpoint advertises, and the one the session is
/// told the client negotiated. Nothing here opens a control stream, which is
/// the only thing `draft_is_fixed` affects.
const ALPN: &[u8] = b"moq-00";

/// The ceiling every `Delay` in this file is clamped to.
///
/// Short enough that three sequenced objects cost under a fifth of a second,
/// and two orders of magnitude below [`ASKED`] so the clamp is unambiguous.
const MAX_HOLD: Duration = Duration::from_millis(60);

/// What the hook asks for, and never gets.
const ASKED: Duration = Duration::from_secs(9);

/// Payload bytes per object in stream A.
const PAYLOAD_LEN: usize = 8;

// ── the source stream ──────────────────────────────────────────────────

/// The stream-type field [`DRAFT`] opens a subgroup stream with, for a
/// header carrying an explicit Subgroup ID.
///
/// Drafts 07-10 define a single subgroup type, `0x04`, ahead of the header
/// body; draft-11 numbered the types from `0x08` and put the explicit-ID one
/// at `0x0C`; drafts 12+ moved it to `0x14` and folded it into the header's
/// own first byte. Restated here rather than shared with the neighbouring
/// test files: each is a separate binary, and a fixture encoder must not be
/// reachable from the crate under test.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        DraftVersion::Draft11 => 0x0C,
        _ => 0x14,
    }
}

/// A subgroup stream header for [`DRAFT`]: track alias 1, group 0, subgroup
/// 0, publisher priority `0x80`. Five bytes on every draft 07-19.
fn subgroup_header_bytes() -> Vec<u8> {
    vec![subgroup_stream_type(DRAFT), 0x01, 0x00, 0x00, 0x80]
}

/// Stream A: the header, and `count` objects of [`PAYLOAD_LEN`] bytes each,
/// returned separately so the test can write them one at a time with a
/// feedback edge in between.
fn subgroup_stream(count: u64) -> (Vec<u8>, Vec<Vec<u8>>) {
    let head = subgroup_header_bytes();
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut objects = Vec::new();
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; PAYLOAD_LEN],
        };
        let mut buf = Vec::new();
        writer.write_object(&obj, &mut buf).expect("write object");
        objects.push(buf);
    }
    (head, objects)
}

/// Stream B: bytes whose first octet is a data stream type no draft 07-19
/// decodes as a subgroup header.
///
/// `0x00` was chosen by feeding it to `ObjectFramer` on each of the thirteen
/// drafts in turn, in an all-drafts build. Every one answers `data stream
/// header decode: invalid field value` — a hard decode failure rather than an
/// incomplete read, so the framer latches [`BypassReason::DecodeError`]
/// instead of waiting for more bytes.
/// `session.rs::detect_stream_type` reads the same first byte and routes
/// anything but `0x05` to the subgroup framer, so this stream is framed and
/// then abandoned rather than never framed at all.
///
/// The bytes after it are arbitrary: once the framer has bypassed, the whole
/// stream is forwarded uninterpreted, which is what the byte-equality check
/// on the relay side confirms.
fn undecodable_stream() -> Vec<u8> {
    vec![0x00, 0x01, 0x00, 0x00, 0x80, 0xDE, 0xAD, 0xBE, 0xEF]
}

// ── the observer ───────────────────────────────────────────────────────

/// What one run reported, in arrival order.
///
/// `common::RecordingObserver` keeps impairments as bare
/// [`ImpairmentKind`]s, which is the right shape for the files that count
/// one kind and is exactly what this file cannot use: the leg is half of
/// every claim here. So this is a local observer rather than an edit to the
/// shared harness, and it keeps the pair.
#[derive(Default)]
struct SequenceObserver {
    inner: Mutex<Recorded>,
}

/// The vectors [`SequenceObserver`] fills.
#[derive(Debug, Default, Clone)]
struct Recorded {
    /// `ProxyEvent::Impairment`, as `(leg, kind)` — the sequence under test.
    impairments: Vec<(Option<Leg>, ImpairmentKind)>,
    /// `ProxyEvent::ActionRefused`, destructured.
    refused: Vec<(Site, ActionKind, Refusal)>,
    /// `ProxyEvent::ActionFailed`, destructured.
    failed: Vec<(Site, ActionKind, String)>,
    /// `ProxyEvent::ParseError`'s messages.
    parse_errors: Vec<String>,
}

impl SequenceObserver {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The impairment sequence so far, leg included.
    fn impairments(&self) -> Vec<(Option<Leg>, ImpairmentKind)> {
        self.inner.lock().expect("recorded").impairments.clone()
    }

    fn refused(&self) -> Vec<(Site, ActionKind, Refusal)> {
        self.inner.lock().expect("recorded").refused.clone()
    }

    fn failed(&self) -> Vec<(Site, ActionKind, String)> {
        self.inner.lock().expect("recorded").failed.clone()
    }

    fn parse_errors(&self) -> Vec<String> {
        self.inner.lock().expect("recorded").parse_errors.clone()
    }
}

impl ProxyObserver for SequenceObserver {
    fn on_event(&self, event: &ProxyEvent) {
        let mut rec = self.inner.lock().expect("recorded");
        match event {
            ProxyEvent::Impairment { leg, kind, .. } => {
                rec.impairments.push((*leg, kind.clone()));
            }
            ProxyEvent::ActionRefused { site, action, refusal, .. } => {
                rec.refused.push((*site, *action, refusal.clone()));
            }
            ProxyEvent::ActionFailed { site, action, error, .. } => {
                rec.failed.push((*site, *action, error.clone()));
            }
            ProxyEvent::ParseError { error, .. } => rec.parse_errors.push(error.clone()),
            _ => {}
        }
    }
}

// ── the hook ───────────────────────────────────────────────────────────

/// The scripted decisions of the run, plus the identities the engine showed
/// it.
///
/// The identities are the reason this records anything at all. The expected
/// event vector names a `StreamKey` and two transport stream ids, and
/// hardcoding them would pin QUIC's client-initiated-unidirectional
/// numbering into an assertion about impairment ordering. Reading them off
/// the **stream sites** instead keeps the expectation derived from the
/// fixture: `on_stream_open` is a different surface from the event stream
/// under test, so this is not the observer checked against itself.
struct ScriptedHook {
    /// `(stream_id, key)` per `on_stream_open`, in accept order.
    opens: Mutex<Vec<(u64, StreamKey)>>,
    /// Every object the engine framed, as `(object_id, payload_len)`.
    objects: Mutex<Vec<(u64, u64)>>,
    /// The key stream A is told to wait behind — one that names no stream.
    ghost: StreamKey,
}

impl ScriptedHook {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            opens: Mutex::new(Vec::new()),
            objects: Mutex::new(Vec::new()),
            // Session-local keys are minted from zero, one per forwarded
            // stream, so nothing in a two-stream run reaches this.
            ghost: StreamKey { side: ProxySide::ClientToProxy, id: 9_999 },
        })
    }

    /// The `n`th accepted stream's `(stream_id, key)`.
    fn open(&self, n: usize) -> (u64, StreamKey) {
        let opens = self.opens.lock().expect("opens");
        *opens.get(n).unwrap_or_else(|| panic!("the hook saw {} stream(s), not {}", opens.len(), n))
    }

    fn opens_seen(&self) -> usize {
        self.opens.lock().expect("opens").len()
    }

    fn objects_seen(&self) -> Vec<(u64, u64)> {
        self.objects.lock().expect("objects").clone()
    }
}

impl ProxyHook for ScriptedHook {
    /// `STREAMS`, which structurally contains `OBJECTS`.
    ///
    /// Deliberately **not** `CONTROL`. This file's expectation is a whole
    /// `Vec`, so it has to name everything the session reports; asking for
    /// the control site would put the control pipes and their draft
    /// detection into a run that is about two data streams.
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    /// Stream A waits behind a key naming nothing; stream B is forwarded
    /// plainly.
    ///
    /// The two answers are what keeps `SerializeTargetUnknown` at exactly
    /// one: the report is once per stream that asks, so a hook that asked on
    /// both streams would emit two and the sequence would say so.
    fn on_stream_open(&self, cx: &StreamCtx<'_>) -> StreamAction {
        let mut opens = self.opens.lock().expect("opens");
        opens.push((cx.stream_id, cx.key()));
        if opens.len() == 1 {
            StreamAction::SerializeAfter(self.ghost)
        } else {
            StreamAction::Open
        }
    }

    /// Objects 0 and 2 are delayed far past `max_hold`; object 1 asks for
    /// the same delay around an inner action the object site refuses.
    ///
    /// `ReplacePayload` is refused with
    /// [`Refusal::LengthChanged`] when the replacement is not the declared
    /// payload length, and that refusal is produced **inside**
    /// `exec::prepare_content` — below `check_composition`, which is what
    /// makes it the right instrument here. A composition refusal (a `Delay`
    /// wrapping a `Truncate`, say) is taken before the delay arithmetic
    /// under either ordering, so it could not tell a correct build from a
    /// reversed one.
    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        self.objects.lock().expect("objects").push((cx.meta.object_id, cx.meta.payload_len));
        if cx.meta.object_id == 1 {
            // One byte too many, whatever the fixture's payload length is.
            let wrong = vec![0x5A; cx.meta.payload_len as usize + 1];
            Action::Delay { by: ASKED, then: Box::new(Action::ReplacePayload(Bytes::from(wrong))) }
        } else {
            Action::Delay { by: ASKED, then: Box::new(Action::Pass) }
        }
    }
}

// ── the rig ────────────────────────────────────────────────────────────

/// A client, a proxy session and a relay, with nothing written yet.
struct Rig {
    proxy: SpawnedProxy,
    /// Held as its concrete type, not as `Arc<dyn ProxyObserver>`, so the
    /// test can read the sequence back off it.
    observer: Arc<SequenceObserver>,
    hook: Arc<ScriptedHook>,
    relay: Arc<FakeRelay>,
    /// The endpoint must outlive the connection.
    _client_ep: quinn::Endpoint,
    client_conn: quinn::Connection,
}

impl Rig {
    async fn start() -> Self {
        common::init_crypto();

        let relay = Arc::new(FakeRelay::bind(ALPN));
        let observer = SequenceObserver::new();
        let hook = ScriptedHook::new();

        let mut config = common::session_config(DRAFT, relay.addr);
        // Field assignment, not a struct literal: both `EgressConfig` and
        // `ProxySessionConfig` are `#[non_exhaustive]`.
        let mut egress = EgressConfig::default();
        egress.max_hold = MAX_HOLD;
        // Left at its 1 MiB default on purpose. Three eight-byte objects
        // cannot approach it, so `EgressQueueFull` has no producer in this
        // run and its absence from the expected vector is a fact about the
        // fixture rather than a filter.
        config.egress = egress;

        let proxy = common::spawn_proxy_with(
            config,
            ALPN,
            Arc::clone(&observer) as Arc<dyn ProxyObserver>,
            Arc::clone(&hook) as Arc<dyn ProxyHook>,
        );

        let (client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

        Self { proxy, observer, hook, relay, _client_ep: client_ep, client_conn }
    }

    /// Poll `probe` until it holds, or fail naming what was seen instead.
    async fn wait_until(&self, what: &str, probe: impl Fn() -> bool) {
        let poll = async {
            loop {
                if probe() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        if tokio::time::timeout(common::TIMEOUT, poll).await.is_err() {
            panic!(
                "timed out waiting for {what}; impairments so far were {:?}, refusals {:?}",
                self.observer.impairments(),
                self.observer.refused(),
            );
        }
    }

    async fn shutdown(self) {
        self.client_conn.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

// ── the gate ───────────────────────────────────────────────────────────

/// The impairment stream equals, element for element, what the run did.
///
/// # What each of the four elements is worth
///
/// **Element 1**, `SerializeTargetUnknown`, is a decision taken before a byte
/// of the stream is read: `pipe_data` resolves a `SerializeAfter` ahead of
/// `pipe_data_framed`, so its position at the head of the sequence is a fact
/// about the pipeline's shape rather than about timing.
///
/// **Elements 2 and 3**, the two `HoldClamped`s, bracket the one that is
/// missing. They are the identical `Delay` on the identical fixture, one
/// object either side of the refused one; only the inner action differs. A
/// build that stopped reporting clamps loses both and fails here, so "object
/// 1 contributed nothing" cannot be satisfied by a clamp report that stopped
/// working at all.
///
/// **Element 4**, `FramerBypass`, turns the leg over. The three above it are
/// failures to place bytes on the relay leg and answer `Upstream`; this one
/// is the parser giving up on bytes that arrived from the client and answers
/// `Client`. Both streams arrive on `ProxySide::ClientToProxy`, so `side` is
/// the same value at all four sites and cannot be what produced the
/// difference.
///
/// And the **absence** at object 1 is the whole reason the file exists. The
/// engine took a decision there, refused it, and forwarded the object
/// verbatim; the wire is byte-identical either way, and the run's own
/// `ActionRefused` says the attempt happened. The only place a spurious
/// impairment shows up is this vector.
///
/// # Two ablations, both run, and this is what each of them said
///
/// **(a) The ordering — the one this file was written for.** In
/// `exec::plan_action`'s `Action::Delay` arm, hoist the clamp above the
/// inner action: move `let config = queue_config(engine); let deferral =
/// egress::defer_by(unit.arrived_at, by, &config); if deferral.was_clamped()
/// { report.impairment(..) }` to sit *before* `let content =
/// prepare_content(unit, &then, report)?;`. That is the ordering the
/// `Impairment` variant's rustdoc forbids, and it is invisible on the wire:
/// object 1 is still refused, still forwarded verbatim, and every byte of
/// both streams is unchanged. Only this vector moves.
///
/// ```text
/// assertion `left == right` failed: the impairment sequence is what the run did, in order, on the leg it did it to
///   left: [(Some(Upstream), SerializeTargetUnknown { key: StreamKey { side: ClientToProxy, id: 0 }, target: StreamKey { side: ClientToProxy, id: 9999 } }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Client), FramerBypass { stream_id: 1, draft: Draft19, reason: DecodeError })]
///  right: [(Some(Upstream), SerializeTargetUnknown { key: StreamKey { side: ClientToProxy, id: 0 }, target: StreamKey { side: ClientToProxy, id: 9999 } }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Client), FramerBypass { stream_id: 1, draft: Draft19, reason: DecodeError })]
/// ```
///
/// A third `HoldClamped`, identical to the two real ones, reporting a hold on
/// an object that was never held. Every count, every kind filter and every
/// `contains` assertion in the rest of the suite stays green through it, and
/// so does every byte assertion in this test.
///
/// **(b) The leg.** In `event::impairment_leg`, move
/// `ImpairmentKind::FramerBypass` out of the arrival arm into the departure
/// arm, so every report answers the far connection. The sequence keeps its
/// length, its order and every field of every element; one word changes.
///
/// ```text
/// assertion `left == right` failed: the impairment sequence is what the run did, in order, on the leg it did it to
///   left: [(Some(Upstream), SerializeTargetUnknown { key: StreamKey { side: ClientToProxy, id: 0 }, target: StreamKey { side: ClientToProxy, id: 9999 } }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Upstream), FramerBypass { stream_id: 1, draft: Draft19, reason: DecodeError })]
///  right: [(Some(Upstream), SerializeTargetUnknown { key: StreamKey { side: ClientToProxy, id: 0 }, target: StreamKey { side: ClientToProxy, id: 9999 } }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Upstream), HoldClamped { requested: Some(9s), applied: 60ms }),
///          (Some(Client), FramerBypass { stream_id: 1, draft: Draft19, reason: DecodeError })]
/// ```
///
/// A stream the proxy could not parse on the way *in*, blamed on the relay
/// connection it was writing out to — with the three rows above it still
/// correct, so the whole sequence reads plausibly. Nothing else in the suite
/// notices: every other reader of this report filters on the kind.
#[tokio::test]
async fn the_impairment_sequence_is_exactly_what_the_run_did() {
    let (head, objects) = subgroup_stream(3);
    let whole_a: Vec<u8> = head.iter().copied().chain(objects.iter().flatten().copied()).collect();

    let rig = Rig::start().await;

    // ── stream A ───────────────────────────────────────────────────────
    //
    // The header first and on its own: a QUIC uni stream does not exist for
    // the peer until a frame arrives on it, so the relay cannot accept
    // before the client writes.
    let relay_a = Arc::clone(&rig.relay);
    let accepting_a = tokio::spawn(async move { relay_a.timed_uni().await });
    let mut send_a = rig.client_conn.open_uni().await.expect("open_uni A");
    send_a.write_all(&head).await.expect("write header A");

    let rx_a: TimedReceiver = tokio::time::timeout(common::TIMEOUT, accepting_a)
        .await
        .expect("the relay saw stream A")
        .expect("join");
    assert_eq!(
        rx_a.wait_for_bytes(head.len()).await,
        head,
        "the stream header reaches the relay unchanged"
    );

    // The serialize was resolved before the first byte was read, so it is
    // already reported by the time the header lands.
    rig.wait_until("the serialize report", || !rig.observer.impairments().is_empty()).await;

    // One object at a time, each waited out to its arrival, so the queue is
    // empty before the next decision is taken and the read loop's event
    // order is the write order.
    let mut expect_bytes = head.len();
    for (i, object) in objects.iter().enumerate() {
        send_a.write_all(object).await.expect("write object");
        expect_bytes += object.len();
        let got = rx_a.wait_for_bytes(expect_bytes).await;
        assert_eq!(
            got.len(),
            expect_bytes,
            "object {i} did not reach the relay: {} of {expect_bytes} byte(s)",
            got.len(),
        );
    }
    assert_eq!(rx_a.bytes(), whole_a, "stream A is byte-identical on both sides");

    send_a.finish().expect("finish A");
    assert_eq!(rx_a.wait_for_ending().await, Ending::Fin, "stream A ends cleanly");

    // The engine framed all three objects and showed each to the hook, which
    // is what makes "object 1 contributed no impairment" a statement about a
    // decision that was taken rather than one that never happened.
    assert_eq!(
        rig.hook.objects_seen(),
        vec![(0, PAYLOAD_LEN as u64), (1, PAYLOAD_LEN as u64), (2, PAYLOAD_LEN as u64)],
        "the hook was shown every object in stream order",
    );

    // ── stream B ───────────────────────────────────────────────────────
    //
    // Opened only after stream A has ended, so the two pipes' reports cannot
    // interleave. Every event above comes from one task; this one comes from
    // a second, and the sequence claim across them is only meaningful
    // because the first is finished.
    let stream_b = undecodable_stream();
    let relay_b = Arc::clone(&rig.relay);
    let accepting_b = tokio::spawn(async move { relay_b.timed_uni().await });
    let mut send_b = rig.client_conn.open_uni().await.expect("open_uni B");
    send_b.write_all(&stream_b).await.expect("write B");
    send_b.finish().expect("finish B");

    let rx_b: TimedReceiver = tokio::time::timeout(common::TIMEOUT, accepting_b)
        .await
        .expect("the relay saw stream B")
        .expect("join");
    assert_eq!(
        rx_b.wait_for_bytes(stream_b.len()).await,
        stream_b,
        "a bypassed stream is forwarded uninterpreted, byte for byte",
    );
    assert_eq!(rx_b.wait_for_ending().await, Ending::Fin, "stream B ends cleanly");

    // Keyed on the bypass itself rather than on a length, so a build that
    // emits a *different* fourth event does not satisfy the wait and then
    // fail the comparison for the wrong reason.
    rig.wait_until("the bypass report", || {
        rig.observer
            .impairments()
            .iter()
            .any(|(_, kind)| matches!(kind, ImpairmentKind::FramerBypass { .. }))
    })
    .await;

    // ── the sequence ───────────────────────────────────────────────────

    let (stream_a_id, key_a) = rig.hook.open(0);
    let (stream_b_id, _key_b) = rig.hook.open(1);
    assert_eq!(rig.hook.opens_seen(), 2, "exactly two streams were accepted");
    assert_ne!(stream_a_id, stream_b_id, "the two streams are distinct on the wire");

    let expected = vec![
        // Decided in `pipe_data`, before the framer exists: the key names no
        // live stream, so nothing is waited for and the mistake is reported
        // instead of being silently waited out. About the stream the proxy
        // was going to write on, hence the relay leg.
        (
            Some(Leg::Upstream),
            ImpairmentKind::SerializeTargetUnknown { key: key_a, target: rig.hook.ghost },
        ),
        // Object 0: a 9 s hold reduced to the 60 ms ceiling.
        (
            Some(Leg::Upstream),
            ImpairmentKind::HoldClamped { requested: Some(ASKED), applied: MAX_HOLD },
        ),
        // Object 1 is *not* here. Its `ReplacePayload` was refused inside
        // `prepare_content`, so the delay arithmetic never ran and there was
        // no hold to report.
        //
        // Object 2: the same clamp as object 0, on the same fixture.
        (
            Some(Leg::Upstream),
            ImpairmentKind::HoldClamped { requested: Some(ASKED), applied: MAX_HOLD },
        ),
        // Stream B: bytes that arrived and could not be parsed. The only row
        // that names the client leg, and the only one that is about what came
        // in rather than about what was going out.
        (
            Some(Leg::Client),
            ImpairmentKind::FramerBypass {
                stream_id: stream_b_id,
                draft: DRAFT,
                reason: BypassReason::DecodeError,
            },
        ),
    ];

    assert_eq!(
        rig.observer.impairments(),
        expected,
        "the impairment sequence is what the run did, in order, on the leg it did it to",
    );

    // The corroborating half: the refusal that produced the gap really was
    // emitted, at the object site, naming both lengths. Without this, an
    // engine that never called the hook for object 1 at all would satisfy
    // the vector above.
    assert_eq!(
        rig.observer.refused(),
        vec![(
            Site::Object,
            ActionKind::ReplacePayload,
            Refusal::LengthChanged { from: PAYLOAD_LEN as u64, to: PAYLOAD_LEN as u64 + 1 },
        )],
        "one refusal, at the object site, and nothing else was refused",
    );
    assert!(
        rig.observer.failed().is_empty(),
        "no action reached the transport and failed there: {:?}",
        rig.observer.failed(),
    );

    // Stream B's bypass is a decode failure over the wire rather than a
    // framer that gave up for some other reason, and the run says so once.
    let parse_errors = rig.observer.parse_errors();
    assert_eq!(
        parse_errors.len(),
        1,
        "exactly one parse error, from stream B's header: {parse_errors:?}",
    );
    assert!(
        parse_errors[0].contains("data stream header decode"),
        "the parse error names the header decode: {parse_errors:?}",
    );

    rig.shutdown().await;
}

/// The fixture above assumes the default release backend, and this is where
/// that assumption is checked rather than left to fail as a confusing diff.
///
/// `MOQTAP_RELEASE_TIMER=condvar` forces the coarse wheel, and a session
/// running on it reports `CoarseReleaseTimer` once, on its first deferred
/// release, with `leg: None` — a correct report about a real degradation.
/// The main gate delays three objects, so it would land in the middle of the
/// sequence and the whole-vector `assert_eq!` would fail on an element that
/// is not a defect.
///
/// This is not a claim about the proxy; it is a claim about the environment
/// the claim above is made in.
#[test]
fn the_release_backend_is_the_default_one() {
    let forced = std::env::var("MOQTAP_RELEASE_TIMER").unwrap_or_default();
    assert!(
        forced.is_empty(),
        "MOQTAP_RELEASE_TIMER={forced:?} forces a release backend. \
         the_impairment_sequence_is_exactly_what_the_run_did names every impairment its run \
         produces, and a coarse backend adds a CoarseReleaseTimer this file does not expect. \
         Clear the variable to run this file.",
    );
}

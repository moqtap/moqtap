//! Egress shaping, end to end.
//!
//! This file carries the deferred-start stream actions (`SerializeAfter`,
//! `OpenAfter` and the topology gate below), the scheduler gates, and the
//! end-to-end acceptance row; the fixtures, the draft derivation and the
//! timing doctrine below are written once, for all of them.
//!
//! One of the rows here is not like the others.
//! [`starve_video_while_audio_flows_from_config_alone`] **is** the acceptance
//! criterion for shaping as a whole rather than a gate on one of its
//! mechanisms: `Interest::NONE`, no observer, a two-class [`ShapeProfile`],
//! and three assertions — the starved stream's wire, the flowing stream's
//! wire, and the report that names which was which. If exactly one test in
//! this file has to be understood before changing anything, it is that one,
//! and its rustdoc carries the argument for each of the three.
//!
//! # What the two deferred-start actions actually promise
//!
//! [`StreamAction::SerializeAfter`] says *open now, write nothing until the
//! named stream has ended*. [`StreamAction::OpenAfter`] says *do not open at
//! all until the delay has elapsed*. They are two different promises and
//! this file gates them separately, because the second is a change to the
//! forwarding topology and the first is not.
//!
//! ## Why the "held stream" assertions are `assert_no_uni_stream_for` and
//! not `assert_no_bytes_for`
//!
//! The obvious form of the claim — "stream B receives zero bytes for 300 ms",
//! written with `assert_no_bytes_for` — is **not observable**, and the reason
//! is a transport fact rather than a proxy fact: quinn does not surface a
//! locally-opened unidirectional stream to the peer until the first frame
//! referencing it — a STREAM frame or a RESET_STREAM — so a stream that has
//! been opened and never written cannot be accepted, and there is no
//! [`common::TimedReceiver`] to run `assert_no_bytes_for` against. Measured
//! directly against quinn 0.11.9 through this crate's own harness: a client
//! that calls `open_uni()` and writes nothing is not accepted by the peer
//! within 300 ms.
//!
//! So the negative half is asserted with
//! [`common::assert_no_uni_stream_for`] on the relay's *connection*, after
//! the target stream's own destination has already been accepted. That
//! claims strictly more than a zero-bytes assertion would — no stream **and**
//! no byte for the held stream — and it reddens under the same ablation,
//! which is the only property a gate owes.
//!
//! # Which assertions are load-independent, and why
//!
//! `actions_timing.rs:32-76` is binding here, and this section is the
//! inventory that makes it checkable rather than merely cited. **A future
//! contributor who is tempted to "fix" a red gate by widening a number
//! should read this section first**: every bound below is separated from the
//! defect it rejects by a stated factor, and the factor is the thing to
//! keep. Widening one past its factor does not make the gate more robust, it
//! makes it stop measuring.
//!
//! Nothing in this file is a **two-sided** claim about a duration or a rate.
//! Every assertion falls into one of four groups, and each group is safe for
//! a different reason:
//!
//! 1. **Counts, byte equalities and orderings.** The large majority. "The
//!    destination stream is byte-equal to its source", "`objects_dropped ==
//!    K - D`", "audio's object count is at least twice video's", "the high
//!    class's last object preceded the low class's first", "exactly one
//!    `ShapeRuleUnmatchable`, naming the class and the field". None of these
//!    contains a duration, so no amount of scheduling delay can move them.
//!    Where a ratio is wanted it is asserted as a ratio of two integers
//!    ([`weighted_round_robin_shares_by_weight`]) and never as a rate.
//! 2. **Negative claims over a window.** "Nothing arrived in 300 ms", "the
//!    queue admitted at most `depth` after 150 ms of settling". Load can only
//!    make a negative claim *more* true: a slower box delivers less, not
//!    more. Two windows of this shape exist here — [`SETTLE`], 150 ms, which
//!    bounds a count from above, and the 300 ms
//!    [`common::assert_no_uni_stream_for`] window in the `SerializeAfter`
//!    rows, which bounds an event count of zero.
//! 3. **One-sided bounds in the direction load cannot push.**
//!    [`a_bucket_never_delivers_above_its_ceiling`] asserts
//!    `delivered <= rate * elapsed + burst` against an `elapsed` it measures
//!    itself. A loaded box makes `elapsed` larger, which *loosens* the
//!    allowance; there is no scheduling outcome that makes the bucket appear
//!    to have granted more than it did.
//! 4. **Upper bounds with a stated margin against a pinned ceiling.** Four
//!    sites, and only four. Each rejects a *specific* defect — "this
//!    resolved at `max_hold` instead of when it should have" — which is why
//!    "it arrived at all" cannot replace them:
//!
//!    | site | bound | ceiling | factor |
//!    |---|---|---|---|
//!    | the three `SerializeAfter` accepts | [`RESUME_WINDOW`] 500 ms | [`MAX_HOLD`] 2 s (`EgressConfig`) | 4x |
//!    | [`a_starved_class_resumes_and_loses_nothing`] | [`RESUME_WINDOW`] | [`STARVED_HOLD`] 5 s (`QueueConfig`) | 10x |
//!    | [`teardown_bypasses_the_pacer`] | [`RESUME_WINDOW`] | the paced drain, measured at 2.3 s | 4.6x |
//!    | [`a_zero_rate_class_starves_and_the_other_flows`] and [`starve_video_while_audio_flows_from_config_alone`] | the sample instant, tens of ms | [`STARVED_HOLD`] 5 s | ~100x |
//!
//!    Each carries the mandated comment at its site: *widen this, do not
//!    delete it*.
//!
//! Everything that needs "by now the pipe has run" uses an **anchor, not a
//! sleep** — [`common::TimedReceiver::wait_for_bytes`] or [`wait_until`],
//! both of which poll a monotone quantity a correct implementation always
//! reaches. Load makes those slower and never wrong; their timeouts are
//! failure ceilings, so a broken build reports the claim it was waiting on
//! instead of hanging.
//!
//! ## What is deliberately not here
//!
//! Four claims a reader might expect are two-sided rate or duration
//! equalities. Each is replaced by a load-independent companion rather than
//! weakened; the two-sided form belongs in a calibration run on a quiet
//! machine, not in a gate:
//!
//! * a ±2 % band around a 500 kbps bucket → the one-sided ceiling in
//!   group 3 above, plus `shape::bucket`'s exact `charge` arithmetic, which
//!   has no clock in it at all.
//! * "the source read rate matches the bucket rate" → an ordering and a
//!   count ([`block_loses_nothing_and_stalls_the_reader`],
//!   [`block_admits_at_most_depth_objects`]).
//! * a blocked total and a hold total → their companion counts.
//!   [`ClassStats`] carries no `Duration` for either, and nothing here or
//!   anywhere else asserts one, which is what a load-dependent figure comes
//!   to: `blocked_episodes` and `tokens_exhausted_episodes` are what is
//!   asserted, and they are the whole of what the row offers for the
//!   question.
//! * how *long* the low class stays starved → [`a_zero_rate_class_starves_and_the_other_flows`]
//!   gates the zero, [`strict_priority_decides_who_gets_a_shared_bucket`] the
//!   discipline, [`the_high_class_is_served_first`] the ordering.
//!
//! A fifth omission is the odd one out: the 13-draft sweep behind
//! [`an_unmatchable_rule_says_so_on_both_sides_of_the_partition`] is not
//! load-dependent at all, it is *budget*-dependent — thirteen QUIC sessions
//! measure 4.7-5.0 s, eight times the per-gate budget. The gate runs the two
//! drafts that bracket the partition; a build that adds a draft re-derives
//! the partition by hand. Measured by hand as a stand-in: this whole
//! binary is 28/28 green under each of `--features draft07`, `draft14`,
//! `draft15` and `draft19` in 0.45-0.69 s, which is both ends of the
//! 07-14/15-19 split and both ends of the compiled range.
//!
//! **This file therefore ships zero `#[ignore]`d tests, and that is an audit
//! result rather than an omission.** Every row above was checked against the
//! four groups and none needed to become calibration. If a future row does,
//! it takes the verbatim ignore string from `actions_timing.rs:828-829`
//! ("calibration measurement: asserts timing accuracy, which is not
//! measurable on a loaded box — run with --ignored on a quiet machine"),
//! which is the same string `release_timer.rs` uses, so that
//! `-- --ignored calibration` selects the whole cluster across the crate.
//!
//! ## The gate budget
//!
//! ≤ 600 ms per gate. All 28 rows measured one process at a time,
//! worst first: [`serialize_after_holds_a_stream_until_its_target_ends`]
//! 0.36 s, [`open_after_delays_the_peer_stream`] 0.34 s,
//! [`shape_stats_are_zero_without_a_profile_and_move_with_one`] 0.33 s,
//! [`a_shape_profile_arms_without_a_hook`] 0.31 s, and the remaining 24 at
//! or under 0.28 s — the acceptance row itself is 0.03 s, and the fastest,
//! [`reset_stream_overflow_abandons_the_stream`], is 0.02 s. Every row is
//! inside the budget by at least a factor of 1.7 and most by more than ten.
//! The whole binary is ~0.47 s for all 28 in parallel.
//!
//! One green row exceeds the budget, and it is named rather than rounded
//! down: [`an_oversized_object_names_the_class_whose_rate_it_escaped`], 0.97
//! s. It has to move an object past
//! `FramerConfig::max_buffered_object_bytes` — 4 MiB, the shipped default —
//! through a real QUIC session, and that size is the thing under test rather
//! than a number the fixture picked, so there is nothing to trim without
//! testing something else. The whole binary is still under a second in
//! parallel, because this row is bounded by one stream's bytes and not by a
//! wait.
//!
//! The only *other* run that exceeds the budget is a broken one: ablation (a)
//! in [`starve_video_while_audio_flows_from_config_alone`] reddens at the
//! harness's 10 s accept ceiling. A failure path is allowed to be slow; a
//! green one is not.
//!
//! ## Where the ceilings are pinned
//!
//! `max_hold` is pinned rather than inherited everywhere, because it is the
//! ceiling every bound in group 4 is separated from: a hold nobody releases
//! still *resolves*, at `max_hold`, so a fixture that inherited the 30 s
//! default would be claiming a 30 s margin it never wrote down. There are
//! two such fields and both are pinned: `EgressConfig`'s
//! [`max_hold`](moqtap_proxy::action::EgressConfig::max_hold) in
//! [`shaping_config`], which is what `SerializeAfter` races, and
//! `QueueConfig`'s, which is what the scheduler races — under the default
//! `Expiry::Deliver` even a class that can never be granted delivers once
//! `max_hold` has elapsed.
//!
//! `QueueConfig` is built at five sites here and **every one of them assigns
//! `max_hold`**: [`starving_profile`] and [`paced_queue`] take it as a
//! parameter with no default, so a caller cannot omit it, and the three
//! inline `QueueConfig::default()` sites ([`admission_profile`],
//! [`a_datagram_rule_says_so_instead_of_matching_nothing`] and
//! [`bytes_are_conserved_across_classes`]) each set `Some(MAX_HOLD)` on the
//! next line. `grep -n QueueConfig` against this file is how that stays
//! checkable: five constructions, five assignments, no inherited 30 s.
//!
//! # Which draft this file speaks
//!
//! Derived, not named — the same shape and for the same measured reason as
//! `actions_timing.rs:130-149`: a hardcoded `DraftVersion::Draft19` gives
//! 0 passed / 13 failed on every single-draft row that is not draft-19,
//! because the fixture's header bytes decode against the draft the session
//! was configured with. Nothing here reads a draft — a subgroup stream is a
//! subgroup stream — so the newest compiled one is used and the fixture is
//! derived from it.
//!
//! **Known gap, written down rather than papered over**: `just
//! draft-matrix` runs `cargo check … --lib` and never compiles `tests/`, so
//! no standing gate compiles this file under a single draft. Until that row
//! exists, the derived fixture is the only thing standing between this file
//! and fourteen red rows.

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
    feature = "draft20"
))]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, EgressConfig, Gate, Interest, StreamAction};
use moqtap_proxy::capability::{ActionKind, Site};
use moqtap_proxy::event::{DataStreamHeaderKind, Effect, ImpairmentKind, ProxyEvent, ShapeOutcome};
use moqtap_proxy::framer::FramerConfig;
use moqtap_proxy::hook::{NoOpHook, ObjectCtx, ProxyHook, StreamCtx};
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::session::ProxySessionConfig;
use moqtap_proxy::shape::{
    BucketConfig, ClassRule, ClassStats, Discipline, Expiry, MatchKind, Matcher, MatcherField,
    Overflow, QueueConfig, RangeSet, ShapeProfile, ShapeStats, StreamKey,
};

use common::{Ending, FakeRelay, RecordingObserver, SpawnedProxy};

/// Every draft this build compiled, oldest first. Each element carries its
/// own `#[cfg]`, so the array is the enabled set; the file-level gate above
/// guarantees it is non-empty, which makes [`DRAFT`]'s index a compile-time
/// fact rather than a panic.
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
];

/// The draft every fixture here is built for: the **newest** one this build
/// compiled.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the front-end endpoint advertises. `moq-00` leaves
/// `draft_is_fixed` false, which only affects the control parser — no test
/// in this file opens a control stream.
const ALPN: &[u8] = b"moq-00";

/// The `max_hold` every fixture pins, and the ceiling every upper bound
/// below is separated from.
///
/// Two seconds rather than the 30 s default so the margin is a number this
/// file wrote, and small enough that a genuinely stalled gate fails the
/// suite in seconds rather than looking like a hang.
const MAX_HOLD: Duration = Duration::from_secs(2);

/// The bound every "it proceeded rather than waiting out `max_hold`" claim
/// uses: a **4x** separation from [`MAX_HOLD`], which is the defect it
/// rejects.
///
/// Widen this, do not delete it. It is an upper bound, so load pushes it in
/// the red direction; the margin is what absorbs that, and the factor is the
/// thing to keep, not the number.
const RESUME_WINDOW: Duration = Duration::from_millis(500);

/// Track alias of the stream that is serialized *behind* another.
const HELD_ALIAS: u64 = 2;
/// Track alias of the stream that is forwarded normally.
const LEAD_ALIAS: u64 = 1;

// ── fixtures ───────────────────────────────────────────────────────────

/// The stream-type field [`DRAFT`] opens a subgroup stream with, for a
/// header carrying an **explicit** Subgroup ID.
///
/// The same table `actions_timing.rs` and `actions_objects.rs` carry,
/// restated rather than shared: the three are separate test binaries, and
/// this encoder is deliberately kept out of any crate the proxy itself
/// uses — a shared encoder would leave these tests comparing the proxy
/// against its own output.
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

/// A subgroup stream header for `draft` carrying `track_alias`: group 0,
/// subgroup 0, publisher priority `0x80`. Five bytes on every draft 07-20.
fn subgroup_header_bytes(draft: DraftVersion, track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "single-byte varint only");
    vec![subgroup_stream_type(draft), track_alias as u8, 0x00, 0x00, 0x80]
}

/// A whole [`DRAFT`] datagram on `track_alias`: group 0, object 0, publisher
/// priority `0x80`, then `payload`.
///
/// Restated here rather than shared with `actions_datagrams.rs` for the
/// reason [`subgroup_stream_type`] gives: a shared encoder would leave these
/// tests comparing the proxy against its own output.
///
/// Three layouts cover the fourteen. Drafts 07 and 08 declare a payload
/// length — and hang the Object Status off it being zero, which is why
/// `payload` may not be empty on those two. Drafts 09 and 10 replace the
/// length with an extension-headers byte count. From draft-11 on the type
/// field alone says there are no extensions, so the header stops at the
/// priority octet. Every varint here is one byte, which is the same octet
/// under RFC 9000's encoding and MoQT's.
fn datagram_bytes(draft: DraftVersion, track_alias: u64, payload: &[u8]) -> Vec<u8> {
    assert!(track_alias < 64, "single-byte varint only");
    assert!(payload.len() < 64, "single-byte length only");
    let alias = track_alias as u8;
    let mut out = match draft {
        DraftVersion::Draft07 => {
            assert!(!payload.is_empty(), "a zero-length draft-07 datagram states a status");
            vec![0x01, alias, 0x00, 0x00, 0x80, payload.len() as u8]
        }
        DraftVersion::Draft08 => {
            assert!(!payload.is_empty(), "a zero-length draft-08 datagram states a status");
            vec![0x01, alias, 0x00, 0x00, 0x80, 0x00, payload.len() as u8]
        }
        DraftVersion::Draft09 | DraftVersion::Draft10 => {
            vec![0x01, alias, 0x00, 0x00, 0x80, 0x00]
        }
        _ => vec![0x00, alias, 0x00, 0x00, 0x80],
    };
    out.extend_from_slice(payload);
    out
}

/// A whole [`DRAFT`] subgroup stream on `track_alias`: the header and
/// `count` objects of `payload_len` bytes each, returned as one vector.
fn subgroup_stream(track_alias: u64, count: u64, payload_len: usize) -> Vec<u8> {
    subgroup_stream_from(DRAFT, subgroup_header_bytes(DRAFT, track_alias), count, payload_len)
}

/// The same, for a caller that has built its own header on its own draft.
///
/// Split out for [`an_unmatchable_rule_says_so_on_both_sides_of_the_partition`],
/// the one row here that runs **two** sessions on **two** drafts and needs a
/// header whose bytes it chose: the
/// default-priority form below is a different header on a different draft
/// from [`DRAFT`], and encoding its objects with [`DRAFT`]'s writer would
/// produce a stream no publisher could send.
fn subgroup_stream_from(
    draft: DraftVersion,
    head: Vec<u8>,
    count: u64,
    payload_len: usize,
) -> Vec<u8> {
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(draft, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut out = head;
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; payload_len],
        };
        writer.write_object(&obj, &mut out).expect("write object");
    }
    out
}

/// A session config for [`DRAFT`] with [`MAX_HOLD`] pinned.
fn shaping_config(upstream: SocketAddr) -> ProxySessionConfig {
    shaping_config_for(DRAFT, upstream)
}

/// The same, on a draft the caller names — the two sessions the
/// priority-partition row runs.
fn shaping_config_for(draft: DraftVersion, upstream: SocketAddr) -> ProxySessionConfig {
    // Field assignment, not a struct literal: `EgressConfig` is
    // `#[non_exhaustive]`, which forbids literal construction from a test
    // crate.
    let mut egress = EgressConfig::default();
    egress.max_hold = MAX_HOLD;
    let mut config = common::session_config(draft, upstream);
    config.egress = egress;
    config
}

// ── the hook ───────────────────────────────────────────────────────────

/// Returns a scripted [`StreamAction`] at `Site::StreamOpen`, chosen from
/// the *index* of the stream and the keys minted before it.
///
/// The keys are what makes `SerializeAfter` testable at all: a hook can only
/// name a stream it has been shown, so the second stream's action is written
/// as a function of the first stream's [`StreamKey`]. That is exactly the
/// dependency [`StreamCtx::key`] exists for.
struct StreamScript {
    #[allow(clippy::type_complexity)]
    at_open: Box<dyn Fn(usize, &[StreamKey]) -> StreamAction + Send + Sync>,
    #[allow(clippy::type_complexity)]
    at_header: Box<dyn Fn(usize) -> StreamAction + Send + Sync>,
    keys: Mutex<Vec<StreamKey>>,
    headers: Mutex<usize>,
}

impl StreamScript {
    fn at_open(
        plan: impl Fn(usize, &[StreamKey]) -> StreamAction + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            at_open: Box::new(plan),
            at_header: Box::new(|_| StreamAction::Open),
            keys: Mutex::new(Vec::new()),
            headers: Mutex::new(0),
        })
    }

    fn at_open_and_header(
        open: impl Fn(usize, &[StreamKey]) -> StreamAction + Send + Sync + 'static,
        header: impl Fn(usize) -> StreamAction + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            at_open: Box::new(open),
            at_header: Box::new(header),
            keys: Mutex::new(Vec::new()),
            headers: Mutex::new(0),
        })
    }

    /// The key minted for the `n`-th stream this hook was shown.
    fn key(&self, n: usize) -> StreamKey {
        self.keys.lock().expect("keys")[n]
    }

    fn header_calls(&self) -> usize {
        *self.headers.lock().expect("headers")
    }
}

impl ProxyHook for StreamScript {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_open(&self, cx: &StreamCtx<'_>) -> StreamAction {
        let mut keys = self.keys.lock().expect("keys");
        let action = (self.at_open)(keys.len(), &keys);
        keys.push(cx.key());
        action
    }

    fn on_stream_header(&self, _cx: &StreamCtx<'_>, _h: &DataStreamHeaderKind) -> StreamAction {
        let mut n = self.headers.lock().expect("headers");
        let at = *n;
        *n += 1;
        (self.at_header)(at)
    }
}

/// Spawn a proxy with [`MAX_HOLD`] pinned, and hand back the pieces every
/// test below drives: the proxy, the relay's accepted connection, and a live
/// client connection.
async fn rig(
    relay: &Arc<FakeRelay>,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
) -> (SpawnedProxy, quinn::Connection, quinn::Endpoint, quinn::Connection) {
    let proxy = common::spawn_proxy_with(shaping_config(relay.addr), ALPN, observer, hook);
    let (client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");
    (proxy, relay_conn, client_ep, client_conn)
}

/// Every `SerializeTargetUnknown` this observer recorded, as `(key, target)`.
fn serialize_unknowns(observer: &RecordingObserver) -> Vec<(StreamKey, StreamKey)> {
    observer
        .impairments()
        .into_iter()
        .filter_map(|k| match k {
            ImpairmentKind::SerializeTargetUnknown { key, target } => Some((key, target)),
            _ => None,
        })
        .collect()
}

// ── serialize behind a live stream ─────────────────────────────────────

/// A stream serialized behind another writes nothing — and is not even
/// opened towards the peer — until its target ends, and then delivers every
/// byte.
///
/// The lead stream is deliberately left **in flight**: it has forwarded its
/// bytes and has not FINed, so the only thing that ends it is the test
/// calling `finish()`. That makes the negative window a claim about the gate
/// and not about a race with the lead stream's own teardown.
///
/// *Ablation:* return `StreamAction::Open` for the second stream instead of
/// `SerializeAfter`. Recorded: the second destination stream is accepted
/// **inside** the 300 ms window and `assert_no_uni_stream_for` panics with
/// "a unidirectional stream was opened within 300ms".
#[tokio::test]
async fn serialize_after_holds_a_stream_until_its_target_ends() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = StreamScript::at_open(|n, keys| match n {
        0 => StreamAction::Open,
        _ => StreamAction::SerializeAfter(keys[0]),
    });
    let (proxy, relay_conn, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    // The lead stream, opened and written but never finished.
    let lead = subgroup_stream(LEAD_ALIAS, 3, 16);
    let mut lead_send = client_conn.open_uni().await.expect("open lead");
    lead_send.write_all(&lead).await.expect("write lead");

    let rx_lead = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the lead stream was forwarded");
    assert_eq!(rx_lead.wait_for_bytes(lead.len()).await, lead, "the lead stream is in flight");

    // The held stream, opened, written whole and finished. Nothing about it
    // may reach the relay while the lead stream is live.
    let held = subgroup_stream(HELD_ALIAS, 3, 16);
    let mut held_send = client_conn.open_uni().await.expect("open held");
    held_send.write_all(&held).await.expect("write held");
    held_send.finish().expect("finish held");

    common::assert_no_uni_stream_for(&relay_conn, Duration::from_millis(300)).await;

    // End the lead stream. That, and only that, releases the gate.
    lead_send.finish().expect("finish lead");

    let rx_held = tokio::time::timeout(RESUME_WINDOW, relay.timed_uni())
        .await
        .expect("the held stream resumed once its target ended, well inside MAX_HOLD");
    assert_eq!(
        rx_held.wait_for_bytes(held.len()).await,
        held,
        "a serialized stream loses nothing: it is byte-equal to its source"
    );
    assert_eq!(rx_held.wait_for_ending().await, Ending::Fin, "and it ends cleanly");

    assert!(
        serialize_unknowns(&observer).is_empty(),
        "the target was live, so nothing is unknown: {:?}",
        serialize_unknowns(&observer)
    );
    assert!(
        observer.applied().contains(&(
            Site::StreamOpen,
            ActionKind::SerializeAfter,
            Effect::ForwardedVerbatim
        )),
        "the serialize was applied at the open site: {:?}",
        observer.applied()
    );
    assert!(observer.refused().is_empty(), "nothing was refused: {:?}", observer.refused());

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── serialize behind an unknown stream ─────────────────────────────────

/// A serialize naming a stream that does not exist proceeds
/// immediately, and says so exactly once.
///
/// Both halves matter and neither implies the other: proceeding without the
/// report is a silent no-op, and the report without proceeding is a stall.
///
/// *Ablations, both recorded:* (a) drop the `report.impairment(..)` from
/// `await_serialize_target`'s `None` arm — the "exactly one" assertion goes
/// red with an empty vector; (b) make the `None` arm wait on `max_hold`
/// instead of returning — the stream arrives at 2 s and the
/// [`RESUME_WINDOW`] timeout goes red.
#[tokio::test]
async fn serialize_after_an_unknown_stream_proceeds_and_says_so() {
    common::init_crypto();

    // An id no session-local mint will ever reach in this test: keys are
    // minted from zero, one per forwarded stream.
    let ghost = StreamKey { side: moqtap_proxy::event::ProxySide::ClientToProxy, id: 9_999 };

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = StreamScript::at_open(move |_, _| StreamAction::SerializeAfter(ghost));
    let (proxy, _relay_conn, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    let stream = subgroup_stream(LEAD_ALIAS, 3, 16);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");
    send.finish().expect("finish");

    // Widen this, do not delete it: a 4x separation from MAX_HOLD, which is
    // where an unknown key treated as a never-released gate would land.
    let rx = tokio::time::timeout(RESUME_WINDOW, relay.timed_uni())
        .await
        .expect("an unknown target does not hold the stream");
    assert_eq!(rx.wait_for_bytes(stream.len()).await, stream);
    assert_eq!(rx.wait_for_ending().await, Ending::Fin);

    assert_eq!(
        serialize_unknowns(&observer),
        vec![(hook.key(0), ghost)],
        "exactly one SerializeTargetUnknown, naming both the asker and the ghost"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── serialize behind a reset stream ────────────────────────────────────

/// A serialize survives its target being **reset** rather than FINed.
///
/// This is the gate on the rule that a serialize is released on every
/// termination path *without exception*. A reset is the path an enumerated
/// list forgets, and forgetting
/// it does not fail loudly — it degrades to a `max_hold` stall on a
/// *different* stream than the one that broke.
///
/// The window is [`RESUME_WINDOW`] against [`MAX_HOLD`] pinned in
/// [`shaping_config`]: a 4x separation from the defect. Widen this, do not
/// delete it.
///
/// *Ablation:* release the gate only on a clean end — in `forward_uni_streams`'s
/// spawned task, `match pipe_data(..).await { Ok(()) => drop(guard), Err(e)
/// => { std::mem::forget(guard); … } }`. Recorded: the held stream is not
/// accepted within 500 ms and this test panics with "the held stream resumed
/// after its target was reset";
/// [`serialize_after_holds_a_stream_until_its_target_ends`], whose target
/// FINs, stays green — which is what makes this the *reset* path's own gate.
#[tokio::test]
async fn serialize_after_survives_its_targets_reset() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = StreamScript::at_open(|n, keys| match n {
        0 => StreamAction::Open,
        _ => StreamAction::SerializeAfter(keys[0]),
    });
    let (proxy, relay_conn, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    let lead = subgroup_stream(LEAD_ALIAS, 3, 16);
    let mut lead_send = client_conn.open_uni().await.expect("open lead");
    lead_send.write_all(&lead).await.expect("write lead");

    let rx_lead = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the lead stream was forwarded");
    assert_eq!(rx_lead.wait_for_bytes(lead.len()).await, lead);

    let held = subgroup_stream(HELD_ALIAS, 3, 16);
    let mut held_send = client_conn.open_uni().await.expect("open held");
    held_send.write_all(&held).await.expect("write held");
    held_send.finish().expect("finish held");

    // The held stream really is held before the reset, or "it resumed"
    // below would be a claim about nothing.
    common::assert_no_uni_stream_for(&relay_conn, Duration::from_millis(150)).await;

    lead_send.reset(quinn::VarInt::from_u32(0x2A)).expect("reset lead");

    let rx_held = tokio::time::timeout(RESUME_WINDOW, relay.timed_uni())
        .await
        .expect("the held stream resumed after its target was reset");
    assert_eq!(
        rx_held.wait_for_bytes(held.len()).await,
        held,
        "a target that was reset still releases what was waiting on it, intact"
    );

    assert!(
        serialize_unknowns(&observer).is_empty(),
        "the target existed when it was named: {:?}",
        serialize_unknowns(&observer)
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── deferred open ──────────────────────────────────────────────────────

/// The delay `OpenAfter` is driven with. Twice [`OPEN_AFTER_WINDOW`], which
/// is the 2x separation the file's upper-bound rule requires.
const OPEN_AFTER: Duration = Duration::from_millis(300);
/// The window in which no peer stream may appear. Widen the ratio, not this.
const OPEN_AFTER_WINDOW: Duration = Duration::from_millis(150);

/// `OpenAfter` does not open the peer stream at all until the delay has
/// elapsed, and then forwards everything.
///
/// This is the topology half of the deferred-start actions and the only
/// thing in this file that moves `dest.open_uni()`. The negative claim is on
/// the relay's connection —
/// no unidirectional stream at all — which is the same primitive
/// `reject_at_stream_open_never_opens_a_peer_stream` uses, and it is what
/// distinguishes `OpenAfter` from `SerializeAfter`: the latter opens
/// immediately and merely writes nothing, which over QUIC is unobservable
/// from the peer.
///
/// *Ablation:* return `StreamAction::Open`. Recorded: the peer stream is
/// accepted immediately and `assert_no_uni_stream_for` panics with "a
/// unidirectional stream was opened within 150ms".
#[tokio::test]
async fn open_after_delays_the_peer_stream() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = StreamScript::at_open(|_, _| StreamAction::OpenAfter(OPEN_AFTER));
    let (proxy, relay_conn, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    let stream = subgroup_stream(LEAD_ALIAS, 3, 16);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");
    send.finish().expect("finish");

    common::assert_no_uni_stream_for(&relay_conn, OPEN_AFTER_WINDOW).await;

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the peer stream opened after the delay");
    assert_eq!(
        rx.wait_for_bytes(stream.len()).await,
        stream,
        "a deferred open forwards the whole stream, byte-equal"
    );
    assert_eq!(rx.wait_for_ending().await, Ending::Fin);

    assert_eq!(
        observer
            .applied()
            .into_iter()
            .filter(|(site, ..)| *site == Site::StreamOpen)
            .collect::<Vec<_>>(),
        vec![(Site::StreamOpen, ActionKind::OpenAfter, Effect::ForwardedVerbatim)],
        "exactly one ActionApplied at the open site, and it is the deferred open: {:?}",
        observer.events()
    );
    assert!(observer.refused().is_empty(), "nothing was refused: {:?}", observer.refused());

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── the topology hazard the default-path rows do not cover ─────────────

/// The code the header site rejects a deferred-open stream with.
const HEADER_REJECT_CODE: u64 = 0x11;

/// Moving `open_uni()` out of the accept loop must not change what a reject
/// at `Site::StreamHeader` means.
///
/// The two reject rows in `actions_streams.rs` —
/// `reject_at_stream_open_never_opens_a_peer_stream` and
/// `reject_at_the_stream_header_forwards_no_header_bytes` — pin the
/// **default** topology, where `open_uni()` stays in the accept loop, so
/// neither of them exercises the deferred-open path.
/// The hazard is specific to it: if the deferred open were made *lazy*
/// (opened on the first byte, or on the first write) rather than merely
/// *late*, then by the time the header decision is taken there would be no
/// peer stream to reset, and `Site::StreamHeader`'s published behaviour
/// would silently become `Site::StreamOpen`'s. The two reject sites are a
/// documented behavioural difference, and collapsing them is exactly
/// the kind of change a green suite would not notice.
///
/// So: `OpenAfter` at the open site, `Reject` at the header site. The peer
/// stream **exists** and is reset having carried zero bytes, which is
/// `reject_at_the_stream_header_forwards_no_header_bytes`'s claim,
/// re-asserted on the topology that moved.
///
/// *Ablation:* open the deferred stream lazily — move `dest.open_uni()`
/// below `pipe_data`'s first read instead of above it. Recorded: the relay
/// never accepts a stream, `wait_for_ending` times out, and this test panics
/// at "the deferred peer stream exists by the header decision".
#[tokio::test]
async fn a_deferred_open_still_reaches_the_header_reject_site() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = StreamScript::at_open_and_header(
        |_, _| StreamAction::OpenAfter(OPEN_AFTER_WINDOW),
        |_| StreamAction::Reject { code: HEADER_REJECT_CODE },
    );
    let (proxy, _relay_conn, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    let stream = subgroup_stream(LEAD_ALIAS, 3, 16);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the deferred peer stream exists by the header decision");
    assert_eq!(
        rx.wait_for_ending().await,
        Ending::Reset(HEADER_REJECT_CODE),
        "the peer stream is reset with the hook's code, exactly as on the default topology"
    );
    assert_eq!(rx.len(), 0, "not one header byte may be forwarded before the reset");

    let stopped = tokio::time::timeout(common::TIMEOUT, send.stopped())
        .await
        .expect("the client's stream was stopped")
        .expect("stopped");
    assert_eq!(
        stopped.map(|c| c.into_inner()),
        Some(HEADER_REJECT_CODE),
        "the source is stopped with the same code"
    );
    assert_eq!(hook.header_calls(), 1, "the header site fired once on the deferred stream");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── arming ─────────────────────────────────────────────────────────────

/// The bucket name [`starving_profile`] uses. Spelled once: a class naming
/// a bucket that is not present is rejected by `ShapeProfile::try_new`,
/// and a typo here would be a rejected profile rather than a silent
/// no-op — but a constant makes even that impossible.
const STARVED_BUCKET: &str = "starved";
/// The one class name [`starving_profile`] uses, and the label its
/// statistics are reported under.
const STARVED_CLASS: &str = "video";

/// The `max_hold` the **arming** fixtures pin.
///
/// Short on purpose, and the reason is the release path: under the default
/// `Expiry::Deliver` a 0-bps class delivers at `max_hold`, so a fixture
/// that both starves a class *and* waits for its whole stream — which is
/// what [`one_stream_under`]'s anchor does — waits exactly this long. The
/// rows it serves ask "did the shaping path run at all", not "how long does
/// a starved class stay starved", so the ceiling they pin is the smallest
/// one that still lets the anchor mean something. The starvation *windows*
/// are [`STARVED_HOLD`]'s, four times longer and separated from a 600 ms
/// sample.
///
/// Widen this, do not delete it: it is a fixture's stated ceiling, not a
/// timing assertion. Nothing is compared against it.
const ARMING_HOLD: Duration = Duration::from_millis(250);

/// The `max_hold` every **starvation** fixture pins, and the ceiling every
/// "delivered zero bytes" claim below is separated from.
///
/// Under `Expiry::Deliver` a starved class still delivers at `max_hold`, so
/// "video delivered nothing" is a statement about a sampling window and the
/// window is meaningless unless the fixture wrote the ceiling down. Five
/// seconds against a 600 ms sample is an 8x separation, in the direction
/// load cannot cross: load delays a delivery, it does not hurry one.
const STARVED_HOLD: Duration = Duration::from_secs(5);

/// A profile whose single class can never be granted from tokens: a
/// `Some(0)` rate with a zero burst, claiming every unit.
///
/// `rate_bps: Some(0)` is legal and distinct from `None` (unlimited): the
/// bucket never refills, so once the burst is spent nothing is grantable.
/// `burst_bytes: 0` means it is spent before the first unit.
///
/// `queue.max_hold` is a **parameter with no default**, because it is the
/// number every starvation claim here is separated from: under the default
/// `Expiry::Deliver` a 0-bps class still *delivers* at `max_hold`
/// (`BucketConfig::rate_bps`), so "delivers zero bytes" is a statement
/// about a sampling window and the window is only meaningful against a
/// ceiling the caller wrote down. Passing it in is what stops a caller
/// inheriting one.
fn starving_profile(max_hold: Duration) -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = STARVED_BUCKET.to_string();
    bucket.rate_bps = Some(0);
    bucket.burst_bytes = 0;

    let mut class = ClassRule::default();
    class.name = STARVED_CLASS.to_string();
    class.bucket = STARVED_BUCKET.to_string();
    // `Matcher::default()` is all-`None`, which claims every unit. Spelled
    // out because "this class matches everything" is the load-bearing half
    // of the fixture, not an omission.
    class.matcher = Matcher::default();

    let mut queue = QueueConfig::default();
    queue.max_hold = Some(max_hold);

    ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("the profile names its own bucket and has one uniquely-named class")
}

/// The number of objects [`one_stream_under`] offers. Three, so that
/// `objects_seen` is a count with more than one bit in it: a producer that
/// fired once per *stream* rather than once per object would still be
/// non-zero, and would still be wrong.
const ONE_STREAM_OBJECTS: u64 = 3;
/// The payload bytes in each of those objects.
const ONE_STREAM_PAYLOAD: usize = 16;

/// What [`one_stream_under`] observed, sampled at the same instant.
///
/// The two readings are returned together rather than by two helpers
/// because a two-helper form would run the fixture twice and let the
/// framer count and the shaping count come from different sessions — at
/// which point "the profile armed framing *and* the shaper saw the same
/// objects" would be two claims about two runs.
struct OneStreamRun {
    /// `Counters::framers_created` for the session.
    framers: u64,
    /// `ProxySession::shape_stats()` for the session.
    shape: ShapeStats,
    /// The wire length of the stream that was offered, header included.
    stream_len: usize,
}

/// Drive exactly one subgroup stream through a session with **no hook
/// interest**, wait until the relay has every byte of it, and report what
/// that session counted.
///
/// The hook is always [`NoOpHook`] — `Interest::NONE`. The observer is a
/// parameter because it is the *other* thing that can arm framing, and the
/// two questions this helper answers need it on both settings:
///
/// - With [`NoOpProxyObserver`] (`wants_events() == false`), framing is
///   otherwise off — `interest_none.rs` proves that combination ends at
///   `Counters::default()` — so `framers_created` reads as a direct answer
///   to "did anything arm the framer, and was it the profile?"
/// - With an observer that *does* want events, framing is on for a reason
///   that is not a profile. That is the only posture in which "an observer
///   must not start recording shaping statistics" is a claim with a
///   producer to lose: with framing off, the shaping call site is never
///   reached and its gate cannot be measured at all.
///
/// The wait is the anchor that makes a **zero** meaningful. Reading the
/// counters straight after the write would race the forwarding task, and a
/// zero would mean "not yet" as often as "never". Waiting until the relay
/// holds the whole stream means the pipe has already run end to end: if a
/// framer were going to be built for that stream, it has been, and if the
/// shaper were going to see those objects, it has.
///
/// `moqtap_proxy::instrument::Counters::framers_created`
async fn one_stream_under(
    shape: Option<ShapeProfile>,
    observer: Arc<dyn ProxyObserver>,
) -> OneStreamRun {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let mut config = shaping_config(relay.addr);
    config.shape = shape;

    let proxy =
        common::spawn_proxy_with(config, ALPN, observer, Arc::new(NoOpHook) as Arc<dyn ProxyHook>);
    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let stream = subgroup_stream(LEAD_ALIAS, ONE_STREAM_OBJECTS, ONE_STREAM_PAYLOAD);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");
    send.finish().expect("finish");

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the stream was forwarded upstream");
    assert_eq!(
        rx.wait_for_bytes(stream.len()).await,
        stream,
        "the stream reached the relay whole, so the pipe has run: a framer either \
         was built for it or never will be"
    );

    let run = OneStreamRun {
        framers: proxy.counters().framers_created,
        shape: proxy.shape_stats(),
        stream_len: stream.len(),
    };
    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    run
}

/// A [`ShapeProfile`] arms the framer **on its own** — with
/// `Interest::NONE`, with no observer, and with no hook of any kind.
///
/// This is the arming gate, and it is asserted in both directions in one
/// body because neither half means anything alone. `framers_created > 0`
/// under a profile could be some *other* session-start effect; `== 0`
/// without one could be a broken fixture that never forwarded a stream.
/// Together — same posture, same stream, same counter, one field changed —
/// they say that the profile and only the profile armed framing.
///
/// Why the framer is the thing measured: classification needs
/// `ObjectMeta`, which only `pipe_data_framed` produces. A configured
/// profile that left the session on the pass-through pipe would be a user
/// asking for 500 kbps, getting a byte pump, and reading a successful run.
///
/// # What this row does **not** claim
///
/// It does not assert that the 0-bps class delivers **zero** bytes in the
/// window. This row measures arming and nothing else — whether a profile on
/// its own moves the session onto the framed pipe. The starvation claim is a
/// statement about the release path and is gated separately, by
/// [`a_zero_rate_class_starves_and_the_other_flows`], on the same fixture
/// shape: a 0-bps class with `queue.max_hold` pinned.
///
/// # Ablations, both recorded
///
/// **(a) Drop the `|| shaping_enabled` term** from `objects_enabled`
/// (`session.rs`, the gating expression), leaving everything else. The
/// shaped arm falls to the pass-through pipe and `pipe_data`'s
/// `debug_assert!` catches it *first*, inside the forwarding task:
///
/// ```text
/// panicked at crates\moqtap-proxy\src\session.rs, in pipe_data:
/// a session with a ShapeProfile must be framed: shaping cannot classify a byte pump
/// ```
///
/// That kills the stream's task, so the relay receives nothing and this
/// test's own anchor reddens next, with `left: []` against the whole
/// 57-byte fixture. The other five tests in the file stay green — which is
/// what makes it a claim about the term and not about the harness.
///
/// **(b) Drop the term *and* the `debug_assert!`**, which is what a
/// `--release` gate would see. The pass-through pipe forwards the bytes,
/// the anchor is satisfied, and the counter assertion is the one that
/// fires:
///
/// ```text
/// panicked at crates\moqtap-proxy\tests\actions_shaping.rs, in the body below:
/// a ShapeProfile is configuration, not a hook capability: it must arm the
/// framer with Interest::NONE and no observer, but framers_created was 0
/// ```
///
/// Both were measured; (b) is why the counter assertion is here rather
/// than left to the `debug_assert!` alone.
#[tokio::test]
async fn a_shape_profile_arms_without_a_hook() {
    let unshaped =
        one_stream_under(None, Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>).await.framers;
    assert_eq!(
        unshaped, 0,
        "Interest::NONE with no observer and no profile is a byte pump: it builds \
         no framer, so the shaped arm below has something to differ from"
    );

    let shaped = one_stream_under(
        Some(starving_profile(ARMING_HOLD)),
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
    )
    .await
    .framers;
    assert!(
        shaped > 0,
        "a ShapeProfile is configuration, not a hook capability: it must arm the \
         framer with Interest::NONE and no observer, but framers_created was {shaped}"
    );
}

// ── statistics ─────────────────────────────────────────────────────────

/// `ShapeStats` is zero on an unshaped session and moves on a shaped one —
/// the pair of claims that makes "this session shaped nothing" falsifiable.
///
/// # Why three arms in one body, and why the middle one exists
///
/// "An unshaped session's `shape_stats()` is `ShapeStats::default()`" is,
/// on its own, unfalsifiable: it is also what a `shape_stats()` that always
/// returned `default()` would report, and what a recorder with no writer
/// anywhere would report. A standalone row asserting that zero was deleted
/// for exactly this reason, as was the `shape_stats()` half of a row in
/// `interest_none.rs`, where
/// `shape: None` makes every ablation invisible. So the zero is asserted
/// **beside** a non-zero taken from the same fixture with one field
/// changed.
///
/// The middle arm — `shape: None` but **framing armed by an observer** —
/// is what makes the *gate* measurable rather than merely written down, and
/// it is the honest form of what that deleted row was reaching for. Under
/// `Interest::NONE` with no observer the framed pipe never runs, so the
/// recording call site is unreachable and removing its
/// `if ctx.shaping_enabled` guard changes nothing anyone can see. With an
/// observer, framing is on for a reason that is not a profile, the call
/// site *is* reached, and the guard is the only thing keeping the stats at
/// zero. Measured: without that arm, the guard-removal ablation below is
/// green across the whole suite.
///
/// That claim also stands on its own merits. It is the same asymmetry
/// `object_hook` has and for the same reason: attaching an event observer
/// must not start recording — later, pacing — production traffic.
///
/// # What is asserted exactly, and what is bounded
///
/// `objects_seen == 3` is exact and load-independent: the framer yields one
/// `FramerOut::Object` per object on the wire, the fixture writes three,
/// and the anchor in [`one_stream_under`] has already waited for all of
/// them to reach the relay. A producer that fired once per *stream* reports
/// 1 and reddens here.
///
/// `bytes_shaped` is an **equality**, not a bound: the subgroup *stream
/// header* is charged to the `unshapeable` row and the payload to the class
/// row, so `bytes_shaped == stream_len` exactly. That is the stronger claim
/// — a bound admits any implementation inside it, an equality admits one —
/// and it is exact without copying the codec's framing, because the fixture
/// already knows the wire length of what it wrote.
///
/// # The per-class row, and what it claims
///
/// Per-class attribution needs a classifier, and this fixture has one, so
/// the row is asserted rather than waived: since `bytes_shaped` counts the
/// header too, the claim is the full conservation identity over this
/// fixture's three rows.
/// [`bytes_are_conserved_across_classes`] gates
/// the general form on a fixture that has a wholly unshapeable *stream*;
/// what this row adds is that the identity is already exact on the simplest
/// possible traffic, one subgroup stream, where the only unshapeable unit
/// is the header every stream carries.
///
/// The header is asserted **by name and by size**: one unshapeable unit of
/// exactly [`header_len`] bytes. A producer that charged the header to the
/// class row instead would keep the identity true and redden here, which is
/// the whole reason the two rows are separate — "no rule claimed it" and
/// "no rule could have" are different answers.
///
/// # Ablations, both recorded
///
/// **(a) Ship the storage with no writer.** Remove the `note_object_seen`
/// call from the `FramerOut::Object` arm of `pipe_data_framed`
/// (`session.rs`), leaving the field, the accessor and the recorder in
/// place. Both zero arms still pass, which is the point — an all-zero
/// `ShapeStats` is exactly what a recorder with no producer reports. The
/// shaped arm fires:
///
/// ```text
/// panicked at crates\moqtap-proxy\tests\actions_shaping.rs, the objects_seen assertion:
/// assertion `left == right` failed: a shaped session must count the objects the
/// shaper saw: three objects went through and objects_seen was 0
///   left: 0
///  right: 3
/// ```
///
/// **(b) Lose the gate.** Hoist the call out from behind
/// `if ctx.shaping_enabled`, so anything framed is recorded. The shaped arm
/// still passes and so does the `Interest::NONE` arm — that one never
/// frames, so its call site is never reached. The **observer** arm fires,
/// on the whole-struct compare (`bytes_shaped: 54` is the three 16-byte
/// payloads plus their per-object framing, and is why that figure is
/// bounded rather than pinned in the assertions below):
///
/// ```text
/// panicked at crates\moqtap-proxy\tests\actions_shaping.rs, the observer arm:
/// assertion `left == right` failed: an event observer is not a ShapeProfile:
/// it may arm framing, but it must not start recording shaping statistics
///   left: ShapeStats { classes: [], .., objects_seen: 3, bytes_shaped: 54, .. }
///  right: ShapeStats { classes: [], .., objects_seen: 0, bytes_shaped: 0, .. }
/// ```
///
/// Measured under (b): `cargo test -p moqtap-proxy` reports **exactly one**
/// failing test — this one, at that assertion, 23 targets and 344 other
/// tests green. So the observer arm is not merely the first detector of a
/// lost gate, it is the only one in the crate.
///
/// **(c) Count only what a rule saw.** Empty the body of
/// `ShapeRecorder::note_unshapeable_seen`, so the header is charged on
/// release and never entered on the left. The equality against `stream_len`
/// is exactly what catches it, and the shortfall is the header:
///
/// ```text
/// assertion `left == right` failed: bytes_shaped accounts for every byte of
/// the stream: the objects on the class row and the header on the unshapeable one
///   left: 54
///  right: 59
/// ```
///
/// A bound would not: `54` passes `bytes_shaped < stream_len`, and passes it
/// with a `3 * ONE_STREAM_PAYLOAD` floor under it as well.
///
/// **(d) Merge the two unnamed rows.** In `ShapeRecorder::row`, send
/// `Class::Unshapeable` to `&self.default_class`. The identity still holds —
/// nothing was lost, it was misfiled — and the row separation is what
/// reddens:
///
/// ```text
/// assertion `left == right` failed: an all-None matcher claims everything: a
/// non-zero default row means the rule did not fire
///   left: ClassStats { name: "", bytes_delivered: 5, .., objects_delivered: 1, .. }
///  right: ClassStats { name: "", bytes_delivered: 0, .., objects_delivered: 0, .. }
/// ```
///
/// Which is the whole argument for two rows: with one, a header would read as
/// a rule that failed to claim its traffic, and that is the diagnosis an
/// author would act on.
#[tokio::test]
async fn shape_stats_are_zero_without_a_profile_and_move_with_one() {
    let unshaped = one_stream_under(None, Arc::new(NoOpProxyObserver)).await;
    assert_eq!(
        unshaped.shape,
        ShapeStats::default(),
        "a session with no ShapeProfile must touch no shaping counter, and real \
         traffic moved through it: a non-zero field names the path that ran"
    );

    // Framing armed by something that is not a profile. The recording call
    // site is reached here and must still do nothing.
    let observed = one_stream_under(None, Arc::new(RecordingObserver::new())).await;
    assert!(
        observed.framers > 0,
        "the observer arm is only worth anything if it framed: framers_created was {}",
        observed.framers
    );
    assert_eq!(
        observed.shape,
        ShapeStats::default(),
        "an event observer is not a ShapeProfile: it may arm framing, but it must \
         not start recording shaping statistics"
    );

    let shaped =
        one_stream_under(Some(starving_profile(ARMING_HOLD)), Arc::new(NoOpProxyObserver)).await;
    assert_eq!(
        shaped.shape.objects_seen, ONE_STREAM_OBJECTS,
        "a shaped session must count the objects the shaper saw: three objects \
         went through and objects_seen was {}",
        shaped.shape.objects_seen
    );
    assert_eq!(
        shaped.shape.bytes_shaped as usize, shaped.stream_len,
        "bytes_shaped accounts for every byte of the stream: the objects on the \
         class row and the header on the unshapeable one"
    );

    // The rows are pre-sized from the profile, in configured order, and
    // labelled — that much is wired. What fills them is not.
    assert_eq!(
        shaped.shape.classes.len(),
        1,
        "one configured class means one row, present whether or not it saw a unit"
    );
    assert_eq!(shaped.shape.classes[0].name, STARVED_CLASS);
    // The rule claims every unit, so every byte the shaper saw is this
    // class's — the conservation identity restricted to one class. A byte
    // that reached the wire without being charged to the rule that claimed
    // it is the failure this catches, and it is the same failure whichever
    // side of the equality moved.
    assert_eq!(
        shaped.shape.classes[0].bytes_delivered as usize,
        shaped.stream_len - header_len(),
        "the one configured class claims every object, so it must be charged \
         every object byte — and only those"
    );
    assert_eq!(
        shaped.shape.classes[0].objects_delivered, ONE_STREAM_OBJECTS,
        "and every object, so a byte total that happened to add up cannot pass \
         alone"
    );
    assert_eq!(
        shaped.shape.default_class,
        ClassStats::default(),
        "an all-None matcher claims everything: a non-zero default row means the \
         rule did not fire"
    );
    assert_eq!(
        shaped.shape.unshapeable.objects_delivered, 1,
        "a subgroup stream carries exactly one unit no rule can see: its header"
    );
    assert_eq!(
        shaped.shape.unshapeable.bytes_delivered as usize,
        header_len(),
        "and it is charged the header's bytes, not the stream's"
    );
    assert_eq!(
        shaped.shape.classes[0].bytes_delivered
            + shaped.shape.default_class.bytes_delivered
            + shaped.shape.unshapeable.bytes_delivered,
        shaped.shape.bytes_shaped,
        "the conservation identity, on the simplest traffic there is: {:?}",
        shaped.shape
    );
}

// ── admission ──────────────────────────────────────────────────────────

/// The bucket the admission fixtures charge against.
const ADMIT_BUCKET: &str = "media";
/// The class every admission fixture's rule claims everything into.
const ADMIT_CLASS: &str = "all";

/// Objects one stream's queue may hold in the admission fixtures.
///
/// Four rather than one so `depth_objects + 1` is a bound with room in it:
/// at a depth of one, an off-by-one and a correct implementation differ by
/// 100 % of the count and every accident looks like a pass.
const ADMIT_DEPTH: usize = 4;

/// The payload every admission fixture's objects carry.
///
/// **This number is load-bearing and the reason is arithmetic, not taste.
/// It was chosen by a failed ablation, not by eye.**
///
/// `Overflow::Block` stops the *read* branch, but `pipe_data_framed` drains
/// the framer of everything one read delivered before it consults
/// `can_read` again — so the queue overshoots its depth by however many
/// whole objects one 8 KiB read can carry. Let `S` be an object's wire size
/// and `B = 8192` the pipe's read buffer. The framer holds at most one
/// *partial* object between reads (it always drains to `NeedMore`), so one
/// read yields at most
///
/// ```text
/// floor((S - 1 + B) / S)  =  1 + floor((B - 1) / S)
/// ```
///
/// objects. A bound of `depth_objects + 1` allows that overshoot, and
/// **measured, such a bound cannot detect an off-by-one**: at `S = 5004`
/// the formula gives 2 objects per read, so a
/// correct queue and one built with `q.len() <= depth` are both `<= 5` and
/// the ablation "off-by-one the object test" ran green.
///
/// So `S` is chosen **above `B`**, where the formula gives exactly one
/// object per read and the overshoot is zero. The bound below is then
/// `depth_objects` exactly, and the off-by-one reddens. 9000 payload bytes
/// give `S = 9005 > 8192`.
///
/// Widen the payload, do not shrink it: below 8192 the gate silently stops
/// measuring the thing it names.
const ADMIT_PAYLOAD: usize = 9000;

/// Objects each admission fixture offers before the drain reopens. Three
/// times the depth, so the overflow is a majority of the stream rather than
/// a rounding error.
const ADMIT_OFFERED: u64 = 12;

/// Objects offered *after* the drain reopens, in the tail-drop fixture.
const ADMIT_TAIL: u64 = 3;

/// How long a "however long you wait" claim waits before sampling.
///
/// It bounds a count from above, so load can only push the count down — the
/// safe direction. Widen this, do not delete it.
const SETTLE: Duration = Duration::from_millis(150);

/// A profile whose single class claims every unit, with an unlimited bucket
/// and a per-stream depth of [`ADMIT_DEPTH`] objects.
///
/// `rate_bps: None` on purpose: these rows are about **admission**, and a
/// rate-limited bucket would be an unread field pretending to participate.
/// `depth_bytes` is left at the 1 MiB default so the object count is the
/// only limit that can trip — which is what
/// `block_reports_backpressure_once` needs, since a queue full by
/// `EgressConfig::max_pending_bytes` would have had a producer already.
fn admission_profile(overflow: Overflow) -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = ADMIT_BUCKET.to_string();
    bucket.rate_bps = None;

    let mut class = ClassRule::default();
    class.name = ADMIT_CLASS.to_string();
    class.bucket = ADMIT_BUCKET.to_string();
    class.matcher = Matcher::default();

    let mut queue = QueueConfig::default();
    queue.depth_objects = ADMIT_DEPTH;
    queue.max_hold = Some(MAX_HOLD);
    queue.overflow = overflow;

    ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("the admission profile names its own bucket and has one class")
}

/// Holds the **first** object of every stream on a [`Gate`] the test owns,
/// and passes the rest.
///
/// This is how a fixture shuts the drain without touching the engine: the
/// head unit gates everything behind it, so the queue fills at line rate
/// and admission is the only thing that can decide what happens next.
/// Nothing here is a timing claim — the gate is released by the test, not
/// by a clock — and [`MAX_HOLD`] is the fixture's stated ceiling if it never
/// is.
struct HoldingHook {
    gate: Gate,
    calls: Mutex<Vec<u64>>,
}

impl HoldingHook {
    fn new() -> Arc<Self> {
        Arc::new(Self { gate: Gate::new(), calls: Mutex::new(Vec::new()) })
    }

    /// The object IDs `on_object` has been shown, in order.
    fn calls(&self) -> Vec<u64> {
        self.calls.lock().expect("calls").clone()
    }
}

impl ProxyHook for HoldingHook {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let mut calls = self.calls.lock().expect("calls");
        calls.push(cx.meta.object_id);
        if calls.len() == 1 {
            Action::Hold { gate: self.gate.clone(), then: Box::new(Action::Pass) }
        } else {
            Action::Pass
        }
    }
}

/// Poll `ready` until it answers `true`, or fail naming what was awaited.
///
/// A *liveness* anchor, never a deadline: every caller below waits for a
/// monotone quantity to reach a value a correct implementation always
/// reaches, so load makes this slower and never wrong. The timeout is a
/// failure ceiling — it exists so a broken build reports the claim it was
/// waiting on rather than hanging for the harness's 10 s.
async fn wait_until(mut ready: impl FnMut() -> bool, what: &str) {
    let poll = async {
        loop {
            if ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), poll).await.is_err() {
        panic!("timed out waiting for {what}");
    }
}

/// The subgroup stream header's length, on every draft 07-20.
fn header_len() -> usize {
    subgroup_header_bytes(DRAFT, LEAD_ALIAS).len()
}

/// One admission fixture, spun up and driven to the point where the queue
/// is full and the drain is shut.
struct AdmissionRun {
    proxy: SpawnedProxy,
    client: quinn::Connection,
    _client_ep: quinn::Endpoint,
    /// The client's source stream, still open: the tail-drop fixture writes
    /// more objects on it after the gate is released.
    send: quinn::SendStream,
    /// The destination stream as the relay sees it.
    rx: common::TimedReceiver,
    hook: Arc<HoldingHook>,
    observer: Arc<RecordingObserver>,
    /// Every byte the fixture *can* offer, phase one and phase two.
    whole: Vec<u8>,
    /// The wire size of one object in [`Self::whole`].
    object_size: usize,
}

impl AdmissionRun {
    /// The prefix of [`Self::whole`] that phase one offered.
    fn offered(&self) -> Vec<u8> {
        self.whole[..header_len() + ADMIT_OFFERED as usize * self.object_size].to_vec()
    }

    fn shape(&self) -> ShapeStats {
        self.proxy.shape_stats()
    }

    /// This run's one configured class row.
    fn class(&self) -> ClassStats {
        self.shape().classes[0].clone()
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

/// Spawn a session under `overflow`, offer [`ADMIT_OFFERED`] objects on one
/// stream with the head held, and hand back everything the gates assert on.
///
/// The whole `ADMIT_OFFERED + ADMIT_TAIL` stream is encoded **once**, by one
/// `AnySubgroupObjectWriter`, and then split: object IDs are delta-encoded
/// on the wire on drafts 14-20, so a second stream started at object 12
/// would encode a delta against nothing and the tail-drop fixture would be
/// asserting on bytes no publisher could produce.
async fn admission_run(overflow: Overflow) -> AdmissionRun {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = HoldingHook::new();

    let mut config = shaping_config(relay.addr);
    config.shape = Some(admission_profile(overflow));
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );
    let (client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let total = ADMIT_OFFERED + ADMIT_TAIL;
    let whole = subgroup_stream(LEAD_ALIAS, total, ADMIT_PAYLOAD);
    let body = whole.len() - header_len();
    assert_eq!(
        body % total as usize,
        0,
        "every object in the fixture must be the same wire size, or the split below \
         lands mid-object: {body} bytes over {total} objects"
    );
    let object_size = body / total as usize;
    assert!(
        object_size >= 8192,
        "an object must be at least the pipe's 8 KiB read buffer, or one read carries \
         two of them, the queue overshoots its depth, and the bound stops being able \
         to see an off-by-one: {object_size}. See ADMIT_PAYLOAD."
    );

    let mut send = client.open_uni().await.expect("open_uni");
    let phase_one = header_len() + ADMIT_OFFERED as usize * object_size;
    send.write_all(&whole[..phase_one]).await.expect("write phase one");

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the destination stream was opened and its header forwarded");

    AdmissionRun {
        proxy,
        client,
        _client_ep: client_ep,
        send,
        rx,
        hook,
        observer,
        whole,
        object_size,
    }
}

// ── block: nothing lost, reader stalled ────────────────────────────────

/// `Overflow::Block` stalls the reader and loses nothing.
///
/// Three claims in one body because none of them is worth anything alone: a
/// reader that stalls and drops is not `Block`, a stream that arrives whole
/// having never stalled is not `Block` either, and a `blocked_episodes`
/// with no byte-equality beside it could be produced by a shaper that
/// blocked and then lost the queue.
///
/// # Why the count and not the per-object claim
///
/// This row was first drafted as "the hook is not shown `i + 1` until `i`'s
/// bytes reached the destination". That is not what the mechanism guarantees:
/// `can_read` false means `send.write_all(i)` **returned**, and between that
/// and the relay's `read()` sit a loopback round trip and the reader task's
/// scheduling. `delay_is_not_backpressure` records that exact hazard as
/// measured ("the test passes on a coin flip"). The count form is a hard
/// upper bound, and load can only shrink it.
///
/// The bound is `depth_objects` **exactly**, not `depth_objects + 1`.
/// The `+ 1` was slack for the framer's read buffer; [`ADMIT_PAYLOAD`]
/// removes the slack instead of asserting around it, and the recorded
/// ablation there is why.
///
/// *Ablation, recorded:* drop the `within_shape_depth` term from
/// `PendingQueue::accepts_more`. The read branch never closes, the hook
/// races through all twelve objects and the bound reddens:
///
/// ```text
/// assertion failed: Overflow::Block must stop the read branch: the hook was shown
/// 12 objects against a depth of 4
/// ```
///
/// `blocked_episodes` goes to 0 in the same run, which is the second half
/// of the same fault.
#[tokio::test]
async fn block_loses_nothing_and_stalls_the_reader() {
    let run = admission_run(Overflow::Block).await;

    // Liveness, not a deadline: a correct implementation always fills the
    // queue, so this wait ends on every machine.
    wait_until(|| run.hook.calls().len() >= ADMIT_DEPTH, "the queue to reach its depth").await;
    tokio::time::sleep(SETTLE).await;

    let shown = run.hook.calls().len();
    assert!(
        shown <= ADMIT_DEPTH,
        "Overflow::Block must stop the read branch: the hook was shown {shown} objects \
         against a depth of {ADMIT_DEPTH}"
    );
    assert!(
        run.class().blocked_episodes > 0,
        "a stalled read branch is a blocked episode, charged to the class of the unit \
         that filled the queue: {:?}",
        run.class()
    );
    assert_eq!(
        run.class().objects_dropped,
        0,
        "Block is non-destructive: it stops reading, it never discards"
    );

    // Release the head. Everything queued drains, the read branch reopens,
    // and the rest of phase one follows it.
    run.hook.gate.release();
    let offered = run.offered();
    assert_eq!(
        run.rx.wait_for_bytes(offered.len()).await,
        offered,
        "a blocked stream loses nothing: once the drain reopens it is byte-equal to \
         its source"
    );
    assert_eq!(run.shape().objects_seen, ADMIT_OFFERED, "every offered object was seen");
    assert_eq!(run.class().objects_dropped, 0, "and none of them was discarded");

    run.finish().await;
}

// ── block: at most depth objects ───────────────────────────────────────

/// `Overflow::Block` admits at most `depth_objects` units, however long
/// you wait.
///
/// The narrow companion to [`block_loses_nothing_and_stalls_the_reader`]:
/// that row's ablation is the depth term missing
/// from `accepts_more` altogether, and this one's is the depth term being
/// *wrong by one*. They are different defects and a suite carrying only the
/// first would ship the second.
///
/// The claim is a hard upper bound on a count, so load can only satisfy it
/// more easily — which is why the anchor above it waits for the count to
/// **reach** the depth first. Without that, a fixture that forwarded nothing
/// at all would pass.
///
/// **This test is why [`ADMIT_PAYLOAD`] is what it is.** With a
/// `depth_objects + 1` bound and a payload smaller than the read buffer,
/// the off-by-one ablation below ran **green** — a correct queue and one
/// admitting five units both fit under five. The fixture was changed until
/// the ablation reddened, rather than the ablation being written down as
/// though it had.
///
/// *Ablation, recorded:* off-by-one the object test in
/// `PendingQueue::accepts_more` — `self.q.len() <= depth.objects` instead of
/// `<`. The queue admits a fifth unit and the bound reddens:
///
/// ```text
/// assertion failed: Block admits depth_objects units and no more: 5 > 4
/// ```
#[tokio::test]
async fn block_admits_at_most_depth_objects() {
    let run = admission_run(Overflow::Block).await;

    wait_until(|| run.hook.calls().len() >= ADMIT_DEPTH, "the queue to reach its depth").await;
    tokio::time::sleep(SETTLE).await;

    let shown = run.hook.calls().len();
    assert!(
        shown <= ADMIT_DEPTH,
        "Block admits depth_objects units and no more: {shown} > {ADMIT_DEPTH}"
    );
    // The objects the hook *was* shown are the first ones offered, in
    // order — a bound that admitted the wrong units would satisfy the count
    // and still be wrong.
    assert_eq!(
        run.hook.calls(),
        (0..shown as u64).collect::<Vec<_>>(),
        "Block admits a prefix, not a sample"
    );

    run.hook.gate.release();
    run.finish().await;
}

// ── block: backpressure reported once ──────────────────────────────────

/// A queue made full by `QueueConfig::depth_objects` reports
/// `EgressQueueFull` exactly once.
///
/// This row exists because the report has **no producer at all** unless the
/// shape depth is plumbed *into* `PendingQueue::accepts_more`: the
/// once-per-stream latch is computed inside `PendingQueue::push` from
/// `!accepts_more() && !backpressure_reported`, so a depth checked beside it
/// would leave the event unemitted and this row asserting a report nobody
/// sends.
/// The fixture is deliberately far under `EgressConfig::max_pending_bytes` —
/// four 5 KB objects against 1 MiB — so the engine's own budget cannot be
/// what fires it.
///
/// # Ablations, both run, and one of them says something about this test
///
/// **(a) Make the latch level-triggered** — drop
/// `&& !self.backpressure_reported` from `PendingQueue::push`. This was
/// expected to redden here. **Measured: it does not, and it cannot.** Under
/// `Overflow::Block` the read branch closes the instant `accepts_more()`
/// turns false, so no *second* push can observe a full queue and there is
/// nothing for a level trigger to double-report. The ablation is real and
/// it does redden — `exec::tests::backpressure_is_reported_once_per_stream`
/// fails, which is where the latch is gated, on a fixture that keeps
/// pushing past the limit because it has no read branch to close. Recorded
/// here rather than quietly dropped: this row's "exactly one" is a claim
/// about the **producer**, not about the latch.
///
/// **(b) Compute the shape depth beside `accepts_more()` rather than inside
/// it** — the one this row exists for. `push` never sees a full queue, the
/// event is never emitted, and the assertion reddens with an empty vector:
///
/// ```text
/// assertion `left == right` failed: exactly one EgressQueueFull per stream, on the
/// push that closed the read branch: []
///   left: 0
///  right: 1
/// ```
#[tokio::test]
async fn block_reports_backpressure_once() {
    let run = admission_run(Overflow::Block).await;

    wait_until(|| run.hook.calls().len() >= ADMIT_DEPTH, "the queue to reach its depth").await;
    tokio::time::sleep(SETTLE).await;

    let full: Vec<ImpairmentKind> = run
        .observer
        .impairments()
        .into_iter()
        .filter(|k| matches!(k, ImpairmentKind::EgressQueueFull { .. }))
        .collect();
    assert_eq!(
        full.len(),
        1,
        "exactly one EgressQueueFull per stream, on the push that closed the read \
         branch: {full:?}"
    );

    run.hook.gate.release();
    run.finish().await;
}

// ── drop-tail ──────────────────────────────────────────────────────────

/// `Overflow::DropTail` discards exactly the overflow, and the
/// survivors keep their absolute object IDs.
///
/// # The assertions, and why each needs the others
///
/// `objects_dropped == K - D` alone would be satisfied by a shaper that
/// dropped the *right number* of the *wrong* units. The surviving IDs alone
/// would be satisfied by one that dropped nothing. And `actions_refused ==
/// 0` is not decoration: a unit whose elide an existing guard refuses is
/// **admitted anyway**, so the queue overshoots by one —
/// without this assertion, `K - D` is silently off by the number of refusals
/// and "no guard fired" is hoped rather than checked. The fixture runs the
/// newest compiled draft, which on a default build is draft-19, precisely
/// where `WouldRedefineSubgroupId` lives.
///
/// # Why two phases
///
/// A tail-drop fixture that stops after the drops proves nothing about
/// renumbering: every discarded unit is at the *end*, so no survivor follows
/// one and `note_elided` is unobservable. So the gate is released, the queue
/// drains, and three more objects are offered on the same stream. Those
/// three are the successors whose leading delta the framer owes a fix-up on.
///
/// The expected IDs are `[0..D) ++ [K, K + ADMIT_TAIL)` — a **gap**, not a
/// shift. That is what delta re-encoding does: `reemit_subgroup_object`
/// re-encodes `delta = object_id - last_forwarded - 1`, so an elided run
/// leaves absolute IDs correct on both sides of it.
///
/// # Where this discriminates
///
/// On drafts 14-20, where object IDs are delta-encoded. On 07-13 the IDs are
/// absolute and the assertion holds whether or not `note_elided` was called
/// — so on a build compiled for those drafts alone this row is a regression
/// check rather than a gate. `DRAFT` is the newest compiled draft, so the
/// standing suite runs it where it bites.
///
/// *Ablation, recorded:* skip `framer.note_elided(&meta)` on the drop. The
/// eight elided objects leave the framer owing nothing, object 12's delta
/// stays `0`, and every survivor after the gap decodes one-per-drop low:
///
/// ```text
/// assertion `left == right` failed: DropTail leaves a gap in absolute object IDs,
/// never a shift
///   left: [0, 1, 2, 3, 4, 5, 6]
///  right: [0, 1, 2, 3, 12, 13, 14]
/// ```
#[tokio::test]
async fn drop_tail_discards_exactly_the_overflow() {
    let mut run = admission_run(Overflow::DropTail).await;

    // Under DropTail the read branch stays enabled, so every offered unit
    // is classified. Waiting for that is what makes the drop count exact
    // rather than a race with the reader.
    wait_until(|| run.shape().objects_seen >= ADMIT_OFFERED, "every offered object to be seen")
        .await;

    let dropped = ADMIT_OFFERED - ADMIT_DEPTH as u64;
    assert_eq!(
        run.class().objects_dropped,
        dropped,
        "a queue of depth {ADMIT_DEPTH} offered {ADMIT_OFFERED} units discards the \
         overflow and nothing else"
    );
    assert!(run.class().bytes_dropped >= dropped * ADMIT_PAYLOAD as u64);
    assert_eq!(
        run.proxy.counters().actions_refused,
        0,
        "an elide guard that refused would have left the unit admitted, and the drop \
         count above would be short by exactly that many"
    );
    assert_eq!(
        run.class().blocked_episodes,
        0,
        "DropTail does not block: the read branch must stay enabled or nothing ever \
         arrives to be dropped"
    );
    assert_eq!(run.hook.calls().len(), ADMIT_DEPTH, "a dropped unit is never shown to the hook");

    // Phase two: reopen the drain and offer the successors of the gap.
    run.hook.gate.release();
    let tail_from = header_len() + ADMIT_OFFERED as usize * run.object_size;
    let tail = run.whole[tail_from..].to_vec();
    run.send.write_all(&tail).await.expect("write phase two");
    run.send.finish().expect("finish");

    assert_eq!(run.rx.wait_for_ending().await, Ending::Fin);
    let ids: Vec<u64> =
        run.rx.into_objects(DRAFT).into_iter().map(|(_, meta, _)| meta.object_id).collect();
    let want: Vec<u64> =
        (0..ADMIT_DEPTH as u64).chain(ADMIT_OFFERED..ADMIT_OFFERED + ADMIT_TAIL).collect();
    assert_eq!(ids, want, "DropTail leaves a gap in absolute object IDs, never a shift");

    run.finish().await;
}

// ── block versus drop-tail ─────────────────────────────────────────────

/// `Block` and `DropTail` have orthogonal signatures.
///
/// Pure counts, and it is the plain statement of why `Block` is the default:
/// one policy costs latency and no bytes, the other costs bytes and no
/// latency, and a caller picks between them by reading two numbers.
/// If both signatures could be produced by one policy, the choice would be
/// decoration.
///
/// *Ablation, recorded:* make `DropTail` also block — return the depth from
/// `Scheduler::blocking_depth` for every overflow. The DropTail row inverts
/// into the Block row and this test reddens on the first half of it:
///
/// ```text
/// DropTail discards: ClassStats { name: "all", .., objects_dropped: 0,
///                                 blocked_episodes: 1, .. }
/// ```
///
/// Both halves are wrong in that run — the read branch closed, so nothing
/// arrived to drop *and* the reader stalled — which is the point: the two
/// signatures are not independently settable, so a policy cannot have one
/// without the other. `drop_tail_discards_exactly_the_overflow`,
/// `reset_stream_overflow_abandons_the_stream` and
/// `a_datagram_rule_says_so_instead_of_matching_nothing` redden in the same
/// run, and `shape::scheduler::tests::only_block_installs_a_blocking_depth`
/// is the unit-level detector.
#[tokio::test]
async fn block_and_drop_tail_have_orthogonal_signatures() {
    let blocking = admission_run(Overflow::Block).await;
    wait_until(|| blocking.hook.calls().len() >= ADMIT_DEPTH, "the blocking queue to fill").await;
    tokio::time::sleep(SETTLE).await;
    let blocked = blocking.class();
    blocking.hook.gate.release();
    blocking.finish().await;

    let dropping = admission_run(Overflow::DropTail).await;
    wait_until(|| dropping.shape().objects_seen >= ADMIT_OFFERED, "every unit to be seen").await;
    let tailed = dropping.class();
    dropping.hook.gate.release();
    dropping.finish().await;

    assert_eq!(blocked.objects_dropped, 0, "Block discards nothing: {blocked:?}");
    assert!(blocked.blocked_episodes > 0, "Block stalls the reader: {blocked:?}");
    assert!(tailed.objects_dropped > 0, "DropTail discards: {tailed:?}");
    assert_eq!(tailed.blocked_episodes, 0, "DropTail never stalls the reader: {tailed:?}");
}

// ── reset-stream overflow ──────────────────────────────────────────────

/// The code `reset_stream_overflow_abandons_the_stream` configures.
const OVERFLOW_RESET_CODE: u64 = 0x37;

/// `Overflow::ResetStream` abandons the destination stream, counts it,
/// and says so once.
///
/// This is `ShapeStats::streams_reset_by_shaping`'s only producer under
/// test, and the only place `ProxyEvent::Shaped { StreamReset }` fires in
/// this file. All three claims are in one body: the peer's view
/// (`Ending::Reset`), the run's own accounting (the counter), and the
/// observer's (`Shaped`). A reset with no counter is unattributable, a
/// counter with no reset is a lie, and either without the event leaves an
/// observer unable to tell a configured abandonment from a transport
/// failure.
///
/// The byte bound is an **upper** one — header only. Nothing else is
/// promised: quinn discards the local send buffer on `reset()`, so "the
/// prefix still arrives" is false whenever the reset and the write land in
/// the same step.
///
/// *Ablations, both recorded:* (a) make `Overflow::ResetStream` answer
/// `Admission::Admit` — the stream never ends, `wait_for_ending` runs out
/// the harness timeout and the test panics at "stream terminated";
/// (b) drop the `note_stream_reset_by_shaping()` call — the stream is still
/// reset and the count assertion reddens, `left: 0, right: 1`.
#[tokio::test]
async fn reset_stream_overflow_abandons_the_stream() {
    let run = admission_run(Overflow::ResetStream { code: OVERFLOW_RESET_CODE }).await;

    assert_eq!(
        run.rx.wait_for_ending().await,
        Ending::Reset(OVERFLOW_RESET_CODE),
        "a queue that overflowed under ResetStream abandons the destination with the \
         configured code"
    );
    assert!(
        run.rx.len() <= header_len(),
        "the head unit was held, so nothing but the stream header can have reached the \
         peer: {} bytes",
        run.rx.len()
    );
    assert_eq!(
        run.shape().streams_reset_by_shaping,
        1,
        "the abandonment is counted once, on the stream it happened to"
    );

    let shaped: Vec<ShapeOutcome> = run
        .observer
        .events()
        .into_iter()
        .filter_map(|e| match e {
            ProxyEvent::Shaped { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect();
    assert_eq!(
        shaped,
        vec![ShapeOutcome::StreamReset { code: OVERFLOW_RESET_CODE }],
        "exactly one Shaped event, and it names the code the stream was reset with"
    );

    run.hook.gate.release();
    run.finish().await;
}

// ── the unmatchable report ─────────────────────────────────────────────

/// A rule aimed at datagrams claims **no framed object**, and says nothing
/// about the ones that go past it.
///
/// Both halves matter. A `MatchKind::Datagram` class is live — datagrams
/// are policed — so a subgroup object walking past one is an ordinary
/// non-match rather than an `ImpairmentKind::ShapeRuleUnmatchable`: the
/// units fall to the default row, and the silence is correct rather than
/// the defect.
///
/// The default-row assertion is what makes "the class claimed nothing" a
/// claim with a producer. Delivery counters are the release side's, so the
/// falsifiable form here is the *drop* row: under `DropTail` the overflow
/// has to be charged somewhere, and it is charged to `default_class`
/// because no rule claimed it. A datagram rule that silently matched
/// everything would charge `classes[0]` instead — which is exactly what a
/// `stream_kind` key that stopped being read would do.
///
/// [`a_datagram_class_polices_what_its_bucket_cannot_cover`] is the other
/// half and has to be read beside this one: without it, a class that
/// claimed *nothing at all* would satisfy every assertion here.
///
/// *Ablation (measured):* delete the `stream_kind` comparison from
/// `Matcher::claims`.
///
/// ```text
/// ---- a_datagram_class_does_not_claim_a_framed_object stdout ----
/// assertion `left == right` failed: a datagram-aimed rule claims no subgroup
/// object, so the overflow is charged to the default row: ShapeStats { classes:
/// [ClassStats { name: "all", bytes_dropped: 72024, objects_dropped: 8, .. }],
/// default_class: ClassStats { objects_dropped: 0, .. }, .. }
///   left: 0
///  right: 8
/// ```
///
/// The class row in that dump is the finding rather than decoration: the
/// eight overflowed objects went to the datagram class, which is what a
/// `stream_kind` key that stopped being read looks like from the accounting
/// side.
#[tokio::test]
async fn a_datagram_class_does_not_claim_a_framed_object() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = HoldingHook::new();

    let mut bucket = BucketConfig::default();
    bucket.name = ADMIT_BUCKET.to_string();
    bucket.rate_bps = None;
    let mut class = ClassRule::default();
    class.name = ADMIT_CLASS.to_string();
    class.bucket = ADMIT_BUCKET.to_string();
    // Field assignment, not a struct literal: `Matcher` is
    // `#[non_exhaustive]`, which forbids literal construction from a test
    // crate — the pairing with `Default` is what keeps it constructible at
    // all.
    let mut matcher = Matcher::default();
    matcher.stream_kind = Some(MatchKind::Datagram);
    class.matcher = matcher;
    let mut queue = QueueConfig::default();
    queue.depth_objects = ADMIT_DEPTH;
    queue.max_hold = Some(MAX_HOLD);
    queue.overflow = Overflow::DropTail;
    let profile = ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("a datagram-aimed rule is a valid profile: unmatchable, not invalid");

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let stream = subgroup_stream(LEAD_ALIAS, ADMIT_OFFERED, ADMIT_PAYLOAD);
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");

    wait_until(
        || proxy.shape_stats().objects_seen >= ADMIT_OFFERED,
        "every offered object to be classified",
    )
    .await;

    let stats = proxy.shape_stats();
    assert_eq!(
        stats.default_class.objects_dropped,
        ADMIT_OFFERED - ADMIT_DEPTH as u64,
        "a datagram-aimed rule claims no subgroup object, so the overflow is \
         charged to the default row: {stats:?}"
    );
    assert_eq!(
        stats.classes[0].objects_dropped, 0,
        "and never to the class aimed at another carrier"
    );

    let unmatchable: Vec<ImpairmentKind> = observer
        .impairments()
        .into_iter()
        .filter(|k| matches!(k, ImpairmentKind::ShapeRuleUnmatchable { .. }))
        .collect();
    assert_eq!(
        unmatchable,
        vec![],
        "a datagram-aimed class is live, so a subgroup object it did not claim \
         is an ordinary non-match and reports nothing"
    );

    hook.gate.release();
    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// **A datagram-aimed class discards what its bucket cannot cover.**
///
/// The whole of policing in one body: a class over a bucket that will never
/// hold a token, one datagram of a shape it claims, and the datagram does
/// not cross. Nothing here queues and nothing here waits — a datagram
/// refused by its bucket is dropped where it arrived, which is the only
/// sound answer for a carrier with no successor to renumber and no delivery
/// order to preserve.
///
/// # Why the bucket is dry rather than small
///
/// A rate that refills makes the outcome a race between the refill and the
/// test's own window, and a shaping gate that can pass on a slow machine
/// and fail on a fast one is not a gate. `rate_bps: Some(0)` with
/// `burst_bytes: 0` is the one configuration whose answer is the same at
/// every speed: the bucket is empty at the first datagram and stays empty.
///
/// # The four assertions, and why none of them is the others
///
/// The relay reading nothing is the *peer's* view and is the claim a user
/// would make. The drop row is the run's own accounting, and without it a
/// proxy that lost the datagram to a bug would pass the first. The empty
/// delivery row forbids the opposite bookkeeping error — charging one
/// datagram to both rows. And the event is what an observer sees: a
/// discard with no report is exactly the silent drop this crate exists to
/// prevent, and its `Policed` outcome is a different word from
/// `ShapeOutcome::Dropped` because it is a different decision — no queue
/// was involved and no overflow policy was read.
///
/// *Ablation (measured):* have `forward_datagrams` skip the `acquire` call
/// and admit unconditionally.
///
/// ```text
/// ---- a_datagram_class_polices_what_its_bucket_cannot_cover stdout ----
/// timed out waiting for the datagram to be policed
/// ```
#[tokio::test]
async fn a_datagram_class_polices_what_its_bucket_cannot_cover() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());

    let proxy = spawn_datagram_policing_proxy(&relay, Arc::clone(&observer));
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let sent = datagram_bytes(DRAFT, LEAD_ALIAS, b"policed");
    client.send_datagram(bytes::Bytes::from(sent)).expect("client send_datagram");

    wait_until(
        || proxy.shape_stats().classes[0].objects_dropped >= 1,
        "the datagram to be policed",
    )
    .await;

    // The peer's view: nothing arrived. A window rather than an instant,
    // because "it has not arrived yet" and "it never will" are the same
    // observation until enough time has passed.
    let crossed = tokio::time::timeout(RESUME_WINDOW, relay_conn.read_datagram()).await;
    assert!(crossed.is_err(), "a policed datagram must not reach the relay: {crossed:?}");

    let stats = proxy.shape_stats();
    assert_eq!(stats.classes[0].objects_dropped, 1, "charged to the class that claimed it");
    assert_eq!(
        stats.classes[0].objects_delivered, 0,
        "and to that row only: a policed datagram is not also a delivered one: {stats:?}"
    );

    let policed: Vec<ShapeOutcome> = observer
        .events()
        .into_iter()
        .filter_map(|e| match e {
            ProxyEvent::ShapedDatagram { class, outcome, .. } => {
                assert_eq!(class, ADMIT_CLASS, "the event names the class that claimed it");
                Some(outcome)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        policed,
        vec![ShapeOutcome::Policed],
        "exactly one report, and it says the bucket refused rather than that a \
         queue overflowed"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// **A datagram whose header did not decode is not policed**, and is not
/// charged to the class either.
///
/// The same profile as the row above and the same dry bucket — one input
/// differs, and it is the only thing that could: the bytes are not a MoQT
/// datagram, so nothing can say which class they belong to. A rule names
/// fields, and a datagram that has none has nothing for a rule to name.
///
/// So it takes [`Class::Unshapeable`]'s answer, which is the one an object
/// too large for the framer to buffer already takes: no bucket charges it,
/// no rate binds it, and it crosses whole. That is a hole in a configured
/// rate and it is a **named** hole — the `unshapeable` row exists to be
/// read, and is deliberately separate from `default_class` so that "no rule
/// claimed this" and "no rule could have" stay two answers.
///
/// This is what stops the row above from passing for the wrong reason. A
/// policer that discarded everything it could not classify would satisfy
/// every assertion there and would silently delete a peer's traffic here.
///
/// *Ablation (measured):* have the `None` arm of the classification answer
/// `Class::Default` instead of `Class::Unshapeable`. Both are unpaced, so
/// the datagram still crosses — and the accounting moves, which is what the
/// row after the equality catches.
///
/// ```text
/// ---- a_datagram_whose_header_did_not_decode_is_not_policed stdout ----
/// assertion `left == right` failed: an unclassifiable datagram is charged to
/// the row named for it, not to the row that means "no rule claimed it"
///   left: 0
///  right: 26
/// ```
#[tokio::test]
async fn a_datagram_whose_header_did_not_decode_is_not_policed() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());

    let proxy = spawn_datagram_policing_proxy(&relay, Arc::clone(&observer));
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let payload = bytes::Bytes::from_static(b"not a MoQT datagram at all");
    client.send_datagram(payload.clone()).expect("client send_datagram");
    let forwarded = tokio::time::timeout(common::TIMEOUT, relay_conn.read_datagram())
        .await
        .expect("the datagram reached the relay")
        .expect("the relay read it");
    assert_eq!(forwarded, payload, "an unclassifiable datagram crosses byte for byte");

    let stats = proxy.shape_stats();
    assert_eq!(
        stats.classes[0].objects_dropped, 0,
        "a class cannot police what it cannot name: {stats:?}"
    );
    assert_eq!(
        stats.objects_seen, 0,
        "and it is not counted as classified either — `objects_seen` is what the \
         classifier saw: {stats:?}"
    );
    assert_eq!(
        stats.unshapeable.bytes_delivered,
        payload.len() as u64,
        "an unclassifiable datagram is charged to the row named for it, not to \
         the row that means \"no rule claimed it\""
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A proxy whose only configuration is a datagram-aimed class over a bucket
/// that never refills.
///
/// Shared by the two rows above so the one input that differs between them
/// is the datagram itself. `Interest::NONE` for the hook: the profile is the
/// only thing separating this session from a byte pump, which is what makes
/// each assertion attributable to the shaper.
fn spawn_datagram_policing_proxy(
    relay: &Arc<FakeRelay>,
    observer: Arc<RecordingObserver>,
) -> SpawnedProxy {
    let mut class = ClassRule::default();
    class.name = ADMIT_CLASS.to_string();
    class.bucket = ADMIT_BUCKET.to_string();
    let mut matcher = Matcher::default();
    matcher.stream_kind = Some(MatchKind::Datagram);
    class.matcher = matcher;
    let profile = ShapeProfile::try_new(
        vec![named_bucket(ADMIT_BUCKET, Some(0), 0)],
        vec![class],
        paced_queue(MAX_HOLD, Expiry::Deliver),
        Discipline::Fifo,
    )
    .expect("a datagram-aimed class over a dry bucket is a valid profile");

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    common::spawn_proxy_with(
        config,
        ALPN,
        observer as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    )
}

/// **A datagram over a live rate is dropped, not deferred**, and this is the
/// row that says the absence of datagram pacing is a decision rather than a
/// missing feature.
///
/// The row above uses a bucket that never refills, so the scheduler has no
/// instant to offer and dropping is the only answer available. This one gives
/// it an instant. The bucket carries exactly one datagram's worth of burst at
/// a rate of one byte per second, so the first datagram is granted outright
/// and the second is refused with an instant roughly `unit_len` **seconds**
/// away — the same `Later` answer that puts a stream unit on the release
/// timer. `forward_datagrams` discards it.
///
/// Take the second datagram away and the first is a test of nothing: a single
/// datagram crossing is what the un-shaped path does too. The pair is the
/// claim — the bucket really is live and really did grant, and the very next
/// unit was refused by a rate rather than by a dead bucket.
///
/// # Why seconds, and why not a tighter rate
///
/// The window this waits out is [`RESUME_WINDOW`], and the separation has to
/// be large enough that *it has not arrived yet* cannot be confused with *it
/// is still on a timer*. One byte per second puts the release roughly 30x the
/// window away for a datagram of this size, so a machine slow enough to blur
/// the two would have failed every other timing row in this file first.
///
/// # What it is asserting that the neighbouring row is not
///
/// That the discard is of a *deferrable* unit. A queue built for datagrams
/// would honour the instant, and every assertion in the row above would go on
/// passing while this one broke — which is precisely why the decision needs a
/// gate of its own rather than a paragraph.
///
/// *Ablation (measured):* honour `Acquire::Later` on the datagram path —
/// sleep until the instant and send — which is the smallest form of the queue
/// this row rejects. Nothing is charged as dropped, so this never reaches its
/// assertions:
///
/// ```text
/// ---- a_datagram_over_a_live_rate_is_dropped_rather_than_deferred stdout ----
/// timed out waiting for the second datagram to be refused by the rate
/// ```
///
/// **It is the only thing in the workspace that catches it.** Run whole under
/// that ablation, the suite reports one failure out of 289 binaries and 5,764
/// other assertions pass — the row above among them, on the bucket that never
/// refills. A decision this cheap to reverse silently is a decision that needs
/// a gate rather than a paragraph.
#[tokio::test]
async fn a_datagram_over_a_live_rate_is_dropped_rather_than_deferred() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());

    // Sized from the datagram itself: a burst below the unit is
    // `LargerThanBurst`, which is a different refusal and would make the
    // first datagram fail to cross for the wrong reason.
    let first = datagram_bytes(DRAFT, LEAD_ALIAS, b"first");
    let second = datagram_bytes(DRAFT, LEAD_ALIAS, b"secnd");
    assert_eq!(first.len(), second.len(), "the two fixtures must cost the bucket the same");
    let burst = first.len() as u64;

    let proxy = spawn_datagram_paced_proxy(&relay, Arc::clone(&observer), burst);
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client.send_datagram(bytes::Bytes::from(first.clone())).expect("client send_datagram");
    let crossed = tokio::time::timeout(common::TIMEOUT, relay_conn.read_datagram())
        .await
        .expect("the first datagram fits the burst and crosses")
        .expect("relay read_datagram");
    assert_eq!(crossed.as_ref(), first.as_slice(), "the granted datagram crosses byte for byte");

    client.send_datagram(bytes::Bytes::from(second)).expect("client send_datagram");
    wait_until(
        || proxy.shape_stats().classes[0].objects_dropped >= 1,
        "the second datagram to be refused by the rate",
    )
    .await;

    // The whole claim: the bucket named an instant and nothing is waiting for
    // it. A window rather than a poll, because a deferral and a drop look the
    // same until enough time has passed.
    let after = tokio::time::timeout(RESUME_WINDOW, relay_conn.read_datagram()).await;
    assert!(
        after.is_err(),
        "a datagram refused by a live rate must be dropped, not held until the instant \
         the bucket named: {after:?}"
    );

    let stats = proxy.shape_stats();
    assert_eq!(stats.classes[0].objects_delivered, 1, "one granted: {stats:?}");
    assert_eq!(stats.classes[0].objects_dropped, 1, "one refused: {stats:?}");

    let outcomes: Vec<ShapeOutcome> = observer
        .events()
        .into_iter()
        .filter_map(|e| match e {
            ProxyEvent::ShapedDatagram { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect();
    assert_eq!(
        outcomes,
        vec![ShapeOutcome::Policed],
        "a rate refusal is reported as policing, the same word a dry bucket gets, \
         because the datagram path has one answer for every refusal"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A proxy whose datagram class sits over a bucket that **does** refill, one
/// byte per second, with `burst_bytes` the caller sizes to the unit.
///
/// Deliberately not a parameter added to [`spawn_datagram_policing_proxy`]:
/// that fixture's whole point is a bucket with no instant to offer, and a
/// rate argument on it would let a future edit turn its `Never` into a
/// `Later` without anything reading differently.
fn spawn_datagram_paced_proxy(
    relay: &Arc<FakeRelay>,
    observer: Arc<RecordingObserver>,
    burst_bytes: u64,
) -> SpawnedProxy {
    let mut class = ClassRule::default();
    class.name = ADMIT_CLASS.to_string();
    class.bucket = ADMIT_BUCKET.to_string();
    let mut matcher = Matcher::default();
    matcher.stream_kind = Some(MatchKind::Datagram);
    class.matcher = matcher;
    let profile = ShapeProfile::try_new(
        vec![named_bucket(ADMIT_BUCKET, Some(8), burst_bytes)],
        vec![class],
        paced_queue(MAX_HOLD, Expiry::Deliver),
        Discipline::Fifo,
    )
    .expect("a datagram-aimed class over a slow bucket is a valid profile");

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    common::spawn_proxy_with(
        config,
        ALPN,
        observer as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    )
}

// ── release ────────────────────────────────────────────────────────────
//
// Everything below drives the pacer. The shape every fixture takes, and why:
//
// * **Over-offer.** Each stream is written whole, in one call, before
//   anything is asserted. A shaped queue fills at line rate and drains at the
//   configured one, so an unpaced implementation breaches within
//   milliseconds and a short window discriminates harder than a long one at
//   1x offer.
// * **`queue.max_hold` is pinned in every fixture**, never inherited. Under
//   the default `Expiry::Deliver` a class that can never be granted still
//   *delivers* at `max_hold`, so every "delivered nothing" claim is a
//   claim about a sampling window and the window means nothing without a
//   ceiling the fixture wrote down.
// * **Anchors, not sleeps.** Where a test needs "by now the pipe has run" it
//   waits for a monotone quantity a correct implementation always reaches
//   (`wait_for_bytes`, `wait_until`), so load makes the test slower and never
//   wrong. The places that do bound a duration bound it from *above*, against
//   a `max_hold` at least four times larger, and say so.

/// Track alias of the class that is meant to flow.
const AUDIO_ALIAS: u64 = 3;
/// Track alias of the class that is meant to be held back.
const VIDEO_ALIAS: u64 = 4;
/// The name the flowing class reports under.
const AUDIO_CLASS: &str = "audio";
/// The name the held-back class reports under.
const VIDEO_CLASS: &str = "video";

/// Payload bytes per object in the release fixtures.
///
/// Small, so a stream is short enough to drain inside the gate budget at a
/// rate low enough to be worth calling a rate. The wire size is a little
/// larger — object id, extension count and payload length — and every
/// arithmetic claim below is written against the measured wire size rather
/// than against this number.
const PACED_PAYLOAD: usize = 200;

/// Bytes per second the paced fixtures run at.
///
/// About a hundred objects a second, so a stream of a few dozen takes a few
/// hundred milliseconds: long enough that the pacer is unmistakably the thing
/// sequencing them, short enough for the 600 ms budget.
const PACED_RATE: u64 = 20_000;

/// The burst every paced fixture allows: one object, near enough.
///
/// It cannot be zero. `charge` answers `Never` for any unit larger than the
/// burst — a unit that will never fit is not a unit with a refill instant —
/// so a bucket meant to *pace* rather than *starve* must be able to hold at
/// least one object. Keeping it to exactly one is what makes the ceiling in
/// `a_bucket_never_delivers_above_its_ceiling` tight.
const PACED_BURST: u64 = 256;

/// A class rule claiming one track alias, charged to `bucket`.
fn alias_class(name: &str, alias: u64, bucket: &str, priority: u8, weight: u16) -> ClassRule {
    let mut class = ClassRule::default();
    class.name = name.to_string();
    class.bucket = bucket.to_string();
    // Field assignment over `..Default::default()`: `Matcher` is
    // `#[non_exhaustive]`, which forbids struct-expression construction from
    // this crate.
    let mut matcher = Matcher::default();
    matcher.track_alias = Some(RangeSet::single(alias));
    class.matcher = matcher;
    class.priority = priority;
    class.weight = weight;
    class
}

/// A bucket by name.
fn named_bucket(name: &str, rate_bps: Option<u64>, burst_bytes: u64) -> BucketConfig {
    let mut bucket = BucketConfig::default();
    bucket.name = name.to_string();
    bucket.rate_bps = rate_bps;
    bucket.burst_bytes = burst_bytes;
    bucket
}

/// A queue policy with `max_hold` spelled out — the only way to build one
/// here, so no fixture below can inherit the 30 s default.
fn paced_queue(max_hold: Duration, on_expiry: Expiry) -> QueueConfig {
    let mut queue = QueueConfig::default();
    queue.max_hold = Some(max_hold);
    queue.on_expiry = on_expiry;
    queue
}

/// Audio and video on **one shared bucket**, arbitrated by `discipline`.
///
/// One bucket is what makes a discipline mean anything: with a bucket each,
/// neither class is competing for anything and every discipline answers the
/// same. `priority` and `weight` are per class so one fixture serves
/// `StrictPriority` and `WeightedRoundRobin` both.
fn shared_bucket_profile(
    discipline: Discipline,
    rate_bps: Option<u64>,
    audio: (u8, u16),
    video: (u8, u16),
) -> ShapeProfile {
    ShapeProfile::try_new(
        vec![named_bucket("shared", rate_bps, PACED_BURST)],
        vec![
            alias_class(AUDIO_CLASS, AUDIO_ALIAS, "shared", audio.0, audio.1),
            alias_class(VIDEO_CLASS, VIDEO_ALIAS, "shared", video.0, video.1),
        ],
        paced_queue(STARVED_HOLD, Expiry::Deliver),
        discipline,
    )
    .expect("two uniquely-named classes over one configured bucket")
}

/// Holds the **first object of every stream** on one gate the test owns.
///
/// The barrier the discipline gates need: it is what makes "both streams were
/// enqueued before either could be released" true by construction rather than
/// by hoping the two `open_uni` calls raced favourably. Without it, whichever
/// stream the proxy happened to read first could take the bucket before the
/// other class had declared any demand at all, and the ordering under test
/// would be the arrival order's.
///
/// A gate, not a sleep: nothing here is a timing claim, and the fixture's
/// `EgressConfig::max_hold` is the stated ceiling if a test never releases it.
struct BarrierHook {
    gate: Gate,
    started: Mutex<Vec<u64>>,
}

impl BarrierHook {
    fn new() -> Arc<Self> {
        Arc::new(Self { gate: Gate::new(), started: Mutex::new(Vec::new()) })
    }

    /// How many streams have reached the barrier.
    fn arrived(&self) -> usize {
        self.started.lock().expect("barrier").len()
    }
}

impl ProxyHook for BarrierHook {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let mut started = self.started.lock().expect("barrier");
        if started.contains(&cx.stream_id) {
            return Action::Pass;
        }
        started.push(cx.stream_id);
        Action::Hold { gate: self.gate.clone(), then: Box::new(Action::Pass) }
    }
}

/// A running two-stream fixture: audio and video, both offered whole, both
/// held at the barrier until the test releases it.
struct TwoClassRun {
    proxy: SpawnedProxy,
    client: quinn::Connection,
    _client_ep: quinn::Endpoint,
    hook: Arc<BarrierHook>,
    audio_rx: common::TimedReceiver,
    video_rx: common::TimedReceiver,
    audio: Vec<u8>,
    video: Vec<u8>,
    /// The client's two source streams, held open for the run's whole life.
    ///
    /// Never read, and that is the point: dropping a `quinn::SendStream`
    /// finishes it, which would FIN the source and let the proxy's FIN drain
    /// start behind the barrier. Every gate below is about what the *pacer*
    /// does to a live stream, so the sources stay open until the fixture is
    /// torn down.
    _audio_send: quinn::SendStream,
    _video_send: quinn::SendStream,
}

impl TwoClassRun {
    fn shape(&self) -> ShapeStats {
        self.proxy.shape_stats()
    }

    /// The row named `name`, **by name** rather than by index, so a fixture
    /// that reorders its classes cannot silently swap two assertions.
    fn class(&self, name: &str) -> ClassStats {
        self.shape()
            .classes
            .into_iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no class row named {name}"))
    }

    /// Object bytes on one offered stream — every byte a bucket can be
    /// charged for, which is the whole stream **less its header**: a subgroup
    /// stream header carries no `ObjectMeta`, so no rule ever sees it, no
    /// bucket ever charges it, and it is accounted on
    /// `ShapeStats::unshapeable` rather than on any class row.
    fn object_bytes(stream: &[u8]) -> u64 {
        (stream.len() - header_len()) as u64
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

/// Spawn a session under `profile`, offer `objects` objects on an audio
/// stream and on a video stream, and hand back everything the gates below
/// assert on — with **both streams already queued** and nothing released.
///
/// The video stream is written **first**, so every ordering claim below is
/// about the discipline and not about who arrived first: under `Fifo` the
/// order that falls out is the offer order, and the offer order is the one
/// the gates deny.
async fn two_class_run(profile: ShapeProfile, objects: u64) -> TwoClassRun {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let hook = BarrierHook::new();

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );
    let (client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let video = subgroup_stream(VIDEO_ALIAS, objects, PACED_PAYLOAD);
    let audio = subgroup_stream(AUDIO_ALIAS, objects, PACED_PAYLOAD);

    let mut video_send = client.open_uni().await.expect("open_uni video");
    video_send.write_all(&video).await.expect("write video");
    let mut audio_send = client.open_uni().await.expect("open_uni audio");
    audio_send.write_all(&audio).await.expect("write audio");

    let accepted = tokio::time::timeout(
        common::TIMEOUT,
        relay.timed_uni_by_alias(&[AUDIO_ALIAS, VIDEO_ALIAS], DRAFT),
    )
    .await
    .expect("both destination streams were opened and their headers forwarded");
    let mut accepted = accepted.into_iter();
    let audio_rx = accepted.next().expect("audio receiver");
    let video_rx = accepted.next().expect("video receiver");

    // Both streams have reached the hook, so both are queued behind the
    // barrier and both classes have declared demand. Only now is what
    // follows the discipline's doing.
    wait_until(|| hook.arrived() >= 2, "both streams to reach the barrier").await;

    TwoClassRun {
        proxy,
        client,
        _client_ep: client_ep,
        hook,
        audio_rx,
        video_rx,
        audio,
        video,
        _audio_send: audio_send,
        _video_send: video_send,
    }
}

// ── a dry bucket beside a flowing one ──────────────────────────────────

/// **A bucket test.** A `rate_bps: Some(0)` class delivers nothing
/// while the class beside it delivers everything.
///
/// Two buckets, not one: this row is about the *bucket*, so the two classes
/// must not be competing for anything. The discipline is left at its default
/// `Fifo`, which arbitrates nothing — if it did, this would be measuring the
/// discipline and a zero-rate bucket would pass it under any of the three.
///
/// # The window, and the ceiling it is separated from
///
/// Under the default `Expiry::Deliver` a 0-bps class *does* deliver, at
/// `max_hold`. So "video delivered nothing" is a statement about a
/// sampling window, and the fixture pins the ceiling it is separated from:
/// [`STARVED_HOLD`], five seconds, against a sample taken as soon as the
/// audio stream is whole — tens of milliseconds. Load can only delay the
/// sample, and delay is the direction that keeps the claim true, up to a
/// separation of about two orders of magnitude.
///
/// The video destination stream is asserted to hold **exactly its header**,
/// not zero bytes. A subgroup stream header carries no `ObjectMeta`, so no
/// rule can claim it and no bucket can charge it; it is forwarded for
/// ordering and is not media. Asserting `is_empty` would be asserting that
/// unshapeable bytes are paced, which they are not and which the code says
/// they are not.
///
/// *Ablation, recorded:* give the video bucket `rate_bps: None` instead of
/// `Some(0)` — one field, one line. Video's objects flow and the header-only
/// assertion reddens:
///
/// ```text
/// assertion failed: the video destination stream must hold its header and
/// nothing else while its bucket is dry, but it holds 6485 bytes
/// ```
///
/// The previous revision's ablation — "set `Discipline::Fifo`" — could not
/// redden this at all: a zero-rate bucket grants nothing under any
/// discipline. That is why
/// [`strict_priority_decides_who_gets_a_shared_bucket`] exists as a separate
/// row.
#[tokio::test]
async fn a_zero_rate_class_starves_and_the_other_flows() {
    const OBJECTS: u64 = 8;

    let profile = ShapeProfile::try_new(
        vec![named_bucket("flowing", None, 0), named_bucket("dry", Some(0), 0)],
        vec![
            alias_class(AUDIO_CLASS, AUDIO_ALIAS, "flowing", 0, 1),
            alias_class(VIDEO_CLASS, VIDEO_ALIAS, "dry", 0, 1),
        ],
        paced_queue(STARVED_HOLD, Expiry::Deliver),
        Discipline::Fifo,
    )
    .expect("two uniquely-named classes over two configured buckets");

    let run = two_class_run(profile, OBJECTS).await;
    run.hook.gate.release();

    // The anchor: the unlimited class's stream is whole, so the pipe has run
    // end to end and anything the dry class was going to deliver on its own
    // account, it has.
    assert_eq!(
        run.audio_rx.wait_for_bytes(run.audio.len()).await,
        run.audio,
        "an unlimited bucket must deliver every byte offered to it"
    );

    let video = run.video_rx.len();
    assert_eq!(
        video,
        header_len(),
        "the video destination stream must hold its header and nothing else \
         while its bucket is dry, but it holds {video} bytes"
    );
    assert_eq!(
        run.class(VIDEO_CLASS).bytes_delivered,
        0,
        "a zero-rate bucket grants nothing, so its class is charged nothing"
    );
    assert!(
        run.class(VIDEO_CLASS).tokens_exhausted_episodes > 0,
        "...and says why: a dry bucket is an episode, not a silence"
    );
    assert_eq!(
        run.class(AUDIO_CLASS).bytes_delivered,
        TwoClassRun::object_bytes(&run.audio),
        "the unlimited class is charged every object byte it carried"
    );

    run.finish().await;
}

// ── resuming from starvation ───────────────────────────────────────────

/// A class starved by a **discipline** resumes when its blocker drains,
/// and loses nothing.
///
/// # Why the bucket is rate-limited rather than unlimited
///
/// Measured, and it is the whole reason this fixture looks the way it does.
/// With an *unlimited* shared bucket the high class's queue drains in a
/// single release pass, so whether the low class ever observes the high
/// class's demand at all is a question about task interleaving: on a
/// current-thread runtime the high stream finished before the low stream's
/// task ran once, the low class was never parked, and
/// `starved_behind_other_class` came out **0**. A gate whose subject may or
/// may not happen is not a gate — and worse, its ablation could not redden,
/// because there was no park for a missing wake to strand.
///
/// A rate-limited bucket removes the question. The high class holds demand
/// for as long as it takes to pace 8 objects, the low class cannot escape
/// through the burst (which covers one object), so the park is structural.
///
/// # The bound, and why it is an upper one
///
/// The window is measured **from the instant the high class's stream is
/// whole**, not from the start, so what it bounds is the resume and not the
/// high class's own paced drain. `RESUME_WINDOW` (500 ms) against a
/// `queue.max_hold` of [`STARVED_HOLD`] (5 s) is a **10x** separation from
/// the defect, and the defect is specific: a gate nobody releases still
/// resolves, at the unit's `max_hold` clamp, and the stream arrives whole —
/// late. "It arrived" cannot distinguish a working release from a broken
/// one; only the window can. Load pushes this bound in the red direction and
/// the margin is what absorbs that. **Widen this, do not delete it.**
///
/// *Ablation, recorded:* delete the `wake_bucket` call from
/// `Scheduler::withdraw_demand`, so nothing releases a starved class's gate.
/// The video stream arrives at its `max_hold` clamp instead, and the window
/// assertion reddens:
///
/// ```text
/// assertion failed: the low class must resume when its blocker drains, not
/// at max_hold: 4.99s after the high class finished, against a 500ms window
/// ```
#[tokio::test]
async fn a_starved_class_resumes_and_loses_nothing() {
    const OBJECTS: u64 = 8;

    let run = two_class_run(
        shared_bucket_profile(Discipline::StrictPriority, Some(PACED_RATE), (9, 1), (1, 1)),
        OBJECTS,
    )
    .await;

    run.hook.gate.release();

    assert_eq!(
        run.audio_rx.wait_for_bytes(run.audio.len()).await,
        run.audio,
        "the high class goes first and goes whole"
    );
    let blocker_gone = std::time::Instant::now();
    assert_eq!(
        run.video_rx.wait_for_bytes(run.video.len()).await,
        run.video,
        "and the low class loses nothing while it waits"
    );
    let elapsed = blocker_gone.elapsed();
    assert!(
        elapsed < RESUME_WINDOW,
        "the low class must resume when its blocker drains, not at max_hold: \
         {elapsed:?} after the high class finished, against a {RESUME_WINDOW:?} window"
    );

    assert!(
        run.class(VIDEO_CLASS).starved_behind_other_class > 0,
        "and the run says the low class waited on another class rather than \
         on its own bucket — the two are separate counters because they are \
         separate problems"
    );

    run.finish().await;
}

// ── strict priority: ordering ──────────────────────────────────────────

/// Under `StrictPriority` the high class is served first — **entirely**
/// first.
///
/// Two in-process instants and a fixed order (doctrine group 3), taken from
/// the re-framed objects on each destination stream rather than from the
/// first byte: the first byte of both streams is its subgroup *header*, which
/// carries no `ObjectMeta`, charges no bucket and is forwarded immediately on
/// both. Comparing headers would compare `open_uni` ordering.
///
/// The claim is deliberately the stronger one — the high class's **last**
/// object precedes the low class's **first** — because that is what
/// `StrictPriority` actually promises over one bucket, and because "first
/// before first" is satisfiable by an interleave.
///
/// The fixture offers the **low** class first and holds both at a barrier, so
/// the order under test is the discipline's and not the arrival order's.
///
/// # Ablations
///
/// **(a) Recorded, deterministic: swap the two priorities** — give video the
/// 9 and audio the 1, one line in the fixture. Video drains first and the
/// ordering assertion reddens:
///
/// ```text
/// assertion failed: StrictPriority must drain the high class before the low
/// class starts, but the low class's first object preceded the high class's
/// last
/// ```
///
/// **(b) `Discipline::Fifo`**, the obvious ablation, also reddens — but as a
/// *race*, not a certainty: with `Fifo` the two streams interleave and the
/// low class's first object lands somewhere inside the high class's run.
/// That is why (a) is the recorded ablation. An ablation whose red is a coin
/// flip does not tell you what the gate measures.
#[tokio::test]
async fn the_high_class_is_served_first() {
    const OBJECTS: u64 = 8;

    let run = two_class_run(
        shared_bucket_profile(Discipline::StrictPriority, Some(PACED_RATE), (9, 1), (1, 1)),
        OBJECTS,
    )
    .await;
    run.hook.gate.release();

    assert_eq!(
        run.audio_rx.wait_for_bytes(run.audio.len()).await.len(),
        run.audio.len(),
        "the high class must complete, or there is no ordering to assert"
    );
    assert_eq!(
        run.video_rx.wait_for_bytes(run.video.len()).await.len(),
        run.video.len(),
        "and the low class must complete too, or the ordering below is about \
         a stream that never ran"
    );

    let audio = run.audio_rx.into_objects(DRAFT);
    let video = run.video_rx.into_objects(DRAFT);
    assert_eq!(audio.len(), OBJECTS as usize);
    assert_eq!(video.len(), OBJECTS as usize);

    let audio_last = audio.last().expect("the high class delivered objects").0;
    let video_first = video.first().expect("the low class delivered objects").0;
    assert!(
        audio_last <= video_first,
        "StrictPriority must drain the high class before the low class starts, \
         but the low class's first object preceded the high class's last"
    );

    run.finish().await;
}

// ── strict priority: one shared bucket ─────────────────────────────────

/// **The discipline gate [`a_zero_rate_class_starves_and_the_other_flows`]
/// could not be.** Both classes share **one**
/// bucket that is rate-limited but non-zero, so tokens exist and the only
/// thing deciding who gets them is the `Discipline`.
///
/// At the sampling point — the instant the high class's stream is whole —
/// the high class has been charged every byte it offered and the low class a
/// small fraction of one. The fraction is not zero by construction: the
/// bucket starts full at [`PACED_BURST`], one object's worth, and whichever
/// class asks first may spend it. Bounding the low class at a quarter of the
/// high class's total leaves room for that and still separates a starved
/// class from a shared one by a factor of four.
///
/// The `starved_behind_other_class` assertion beside it is not decoration: it
/// is the only half of this row that `Discipline::Fifo` can be told apart by.
/// See the second ablation.
///
/// # Ablations
///
/// **(a) Recorded, deterministic: swap the two priorities**, giving video the
/// 9 and audio the 1. `StrictPriority` is the only discipline that reads
/// `ClassRule::priority`, so this ablates exactly the mechanism under test.
/// Video takes the bucket, audio never completes, and the byte-equality
/// assertion reddens after the harness timeout.
///
/// **(b) `Discipline::Fifo`**, the obvious ablation for this row, on the
/// grounds that a non-zero shared bucket is grantable under both
/// disciplines. **Measured: it does not redden the byte ratio.** With a
/// burst of one object exactly one unit is grantable at each refill instant,
/// so the two streams race for it — and under `Fifo`, which arbitrates
/// nothing, the winner is decided by the runtime's wake order, which on a
/// current-thread runtime went the same way all eight times. `video * 4 <
/// audio` therefore held with `Fifo` configured, and the run was 0.10 s
/// rather than the ~0.16 s a genuine share would take.
///
/// That is why `starved_behind_other_class` is asserted here. `Fifo` never
/// parks a class — `Scheduler::discipline_holds` returns before it looks at
/// anything — so under `Fifo` the counter is **0** and the assertion reddens
/// deterministically, whichever way the token race happens to go. That
/// ablation is kept, with the measurement that made it insufficient
/// written down beside it rather than the claim quietly repeated.
#[tokio::test]
async fn strict_priority_decides_who_gets_a_shared_bucket() {
    const OBJECTS: u64 = 8;

    let run = two_class_run(
        shared_bucket_profile(Discipline::StrictPriority, Some(PACED_RATE), (9, 1), (1, 1)),
        OBJECTS,
    )
    .await;
    run.hook.gate.release();

    assert_eq!(
        run.audio_rx.wait_for_bytes(run.audio.len()).await,
        run.audio,
        "the high class must get the whole bucket, so it must arrive whole"
    );

    // One snapshot, so the two figures below cannot come from two instants.
    let shape = run.shape();
    let audio =
        shape.classes.iter().find(|c| c.name == AUDIO_CLASS).expect("audio row").bytes_delivered;
    let video =
        shape.classes.iter().find(|c| c.name == VIDEO_CLASS).expect("video row").bytes_delivered;

    assert_eq!(
        audio,
        TwoClassRun::object_bytes(&run.audio),
        "the high class is charged every object byte it carried"
    );
    assert!(
        video * 4 < audio,
        "StrictPriority must give the shared bucket to the high class: video \
         was charged {video} bytes against audio's {audio}"
    );
    // The half that tells `StrictPriority` from `Fifo`. `Fifo` arbitrates
    // nothing and parks nobody, so this counter is 0 under it however the
    // token race is decided — see ablation (b) above.
    assert!(
        run.class(VIDEO_CLASS).starved_behind_other_class > 0,
        "the low class must have been held back by the *discipline*, not merely \
         have lost a race for tokens"
    );

    run.finish().await;
}

// ── weighted round robin ───────────────────────────────────────────────

/// `WeightedRoundRobin` shares one bucket by weight, as a **count**.
///
/// A count and never a rate: a rate is a duration in disguise and load moves
/// it, while "of the objects released so far, the 3-weight class holds at
/// least twice as many as the 1-weight class" is a pure ratio of two integers
/// that no amount of scheduling delay can change.
///
/// # Why the sample is taken part-way through
///
/// The ratio is a property of a class **that has something to send**. Once
/// one stream runs out the other takes the whole bucket, so a sample at the
/// end would measure the offer and not the weights. Both streams are
/// therefore long enough that neither is finished at the sampling point, and
/// the sample is taken through a single snapshot the moment a fixed number of
/// objects have been released — a monotone quantity, so load delays the
/// sample and never changes what it says.
///
/// The bound is `>= 2x` rather than `== 3x` for the reason
/// `weighted_round_robin_grants_in_the_weight_ratio` gives in full: a round
/// hands out `weight` grants per class, so the totals are exact only on a
/// round boundary, and the burst hands one free object to whichever class
/// asks first. `2x` still separates 3:1 from 1:1 by a factor of three.
///
/// *Ablation, recorded:* give both classes weight 1 — the counts come out
/// within one of each other and the ratio assertion reddens:
///
/// ```text
/// assertion failed: weights 3:1 must give the heavy class at least twice the
/// count: audio 13, video 12
/// ```
#[tokio::test]
async fn weighted_round_robin_shares_by_weight() {
    const OBJECTS: u64 = 40;
    /// Objects released before the sample. Six full rounds' worth, so the
    /// partial round at the end moves the ratio by at most one grant each.
    const SAMPLE_AT: u64 = 24;

    let run = two_class_run(
        shared_bucket_profile(Discipline::WeightedRoundRobin, Some(PACED_RATE), (0, 3), (0, 1)),
        OBJECTS,
    )
    .await;
    run.hook.gate.release();

    // One snapshot serves as both the trigger and the evidence, so nothing
    // can be released between deciding to sample and reading the figures.
    let sampled: Arc<Mutex<Option<ShapeStats>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&sampled);
    wait_until(
        || {
            let shape = run.shape();
            let released: u64 = shape.classes.iter().map(|c| c.objects_delivered).sum();
            if released >= SAMPLE_AT {
                *sink.lock().expect("sample") = Some(shape);
                true
            } else {
                false
            }
        },
        "the shared bucket to release enough objects to weigh",
    )
    .await;

    let shape = sampled.lock().expect("sample").clone().expect("wait_until stored a snapshot");
    let audio =
        shape.classes.iter().find(|c| c.name == AUDIO_CLASS).expect("audio row").objects_delivered;
    let video =
        shape.classes.iter().find(|c| c.name == VIDEO_CLASS).expect("video row").objects_delivered;

    assert!(
        video > 0,
        "the light class must still be scheduled, not starved: a weight is a \
         share and not a priority"
    );
    assert!(
        audio >= 2 * video,
        "weights 3:1 must give the heavy class at least twice the count: \
         audio {audio}, video {video}"
    );
    assert!(
        audio < OBJECTS && video < OBJECTS,
        "neither stream may have finished at the sampling point, or the ratio \
         measures the offer instead of the weights: audio {audio}, video \
         {video} of {OBJECTS}"
    );

    run.finish().await;
}

// ── the single-stream paced fixture ────────────────────────────────────

/// A running one-stream fixture: one class claiming every unit, one bucket,
/// and the whole stream offered before anything is asserted.
///
/// No hook and no barrier: with one stream there is nothing to arbitrate, so
/// the only thing sequencing the bytes is the bucket, and adding a hook would
/// put a second mechanism between the offer and the wire.
struct PacedRun {
    proxy: SpawnedProxy,
    client: quinn::Connection,
    _client_ep: quinn::Endpoint,
    observer: Arc<RecordingObserver>,
    rx: common::TimedReceiver,
    /// The client's source stream, still open — a test that wants a FIN or a
    /// reset issues it itself.
    send: quinn::SendStream,
    stream: Vec<u8>,
}

impl PacedRun {
    /// Every `QueuedBytesAtTeardown` this run reported, as its byte count.
    fn stranded(&self) -> Vec<usize> {
        self.observer
            .impairments()
            .into_iter()
            .filter_map(|k| match k {
                ImpairmentKind::QueuedBytesAtTeardown { bytes, .. } => Some(bytes),
                _ => None,
            })
            .collect()
    }

    /// Every `HoldClamped` this run reported, as `(requested, applied)`.
    ///
    /// `requested` is `None` for every clamp a *shaper* decides, which is
    /// every clamp in this file: a bucket that will not release the head
    /// named no refill instant, so there is no duration to report. A hook's
    /// own `Delay { by }` is the arm that carries `Some`.
    fn clamps(&self) -> Vec<(Option<Duration>, Duration)> {
        self.observer
            .impairments()
            .into_iter()
            .filter_map(|k| match k {
                ImpairmentKind::HoldClamped { requested, applied } => Some((requested, applied)),
                _ => None,
            })
            .collect()
    }

    /// This session's shaping statistics, as they stand.
    fn shape(&self) -> ShapeStats {
        self.proxy.shape_stats()
    }

    /// The row named `name`, **by name** rather than by index, so a fixture
    /// that reorders its classes cannot silently swap two assertions.
    fn class(&self, name: &str) -> ClassStats {
        self.shape()
            .classes
            .into_iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no class row named {name}"))
    }

    /// Every `ProxyEvent::Shaped` outcome this run emitted.
    fn shaped(&self) -> Vec<ShapeOutcome> {
        self.observer
            .events()
            .into_iter()
            .filter_map(|e| match e {
                ProxyEvent::Shaped { outcome, .. } => Some(outcome),
                _ => None,
            })
            .collect()
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

/// A profile whose one class claims every unit, over one bucket.
fn one_class_profile(
    rate_bps: Option<u64>,
    burst_bytes: u64,
    max_hold: Duration,
    on_expiry: Expiry,
) -> ShapeProfile {
    let mut class = ClassRule::default();
    class.name = VIDEO_CLASS.to_string();
    class.bucket = "one".to_string();
    // All-`None`, which claims every unit. Spelled out because "this rule
    // matches everything" is load-bearing here, not an omission.
    class.matcher = Matcher::default();
    class.weight = 1;

    ShapeProfile::try_new(
        vec![named_bucket("one", rate_bps, burst_bytes)],
        vec![class],
        paced_queue(max_hold, on_expiry),
        Discipline::Fifo,
    )
    .expect("one class over the bucket it names")
}

/// Spawn a session under `profile` and offer `objects` objects on one stream.
///
/// # Why the write is in two phases
///
/// The subgroup **stream header** goes first, on its own, and the receiver is
/// spawned before a single object is offered. That ordering is what makes
/// [`common::TimedReceiver::started`] a sound zero point for a rate ceiling,
/// and it was arrived at by a measured failure rather than by taste.
///
/// Written in one call, the proxy grants the first object out of the burst
/// while the relay's `accept_uni` is still completing its loopback round
/// trip. Those bytes are counted in the cumulative total — their read returns
/// after `started()` — but the elapsed time they were granted in is not, so
/// the ceiling is breached by whatever accrued in the gap. Measured: **object
/// 1 at 406 bytes against an allowance of 397**, on an implementation that
/// paces correctly.
///
/// With the header alone written first, quinn surfaces the stream to the peer
/// (a locally-opened uni stream is invisible until its first frame), the
/// receiver starts, and only then can any object be granted. The bucket holds
/// at most `burst_bytes` at that instant — it cannot hold more however long it
/// idles — so `rate * (t - started) + burst` is exact rather than nearly
/// right.
async fn paced_run(profile: ShapeProfile, objects: u64) -> PacedRun {
    paced_run_of(profile, subgroup_stream(LEAD_ALIAS, objects, PACED_PAYLOAD)).await
}

/// [`paced_run`] over a stream the caller built, for the rows whose objects
/// are not all the same size.
///
/// The two-phase write above is this function's, so a caller supplying its
/// own bytes gets the same sound zero point without restating why.
async fn paced_run_of(profile: ShapeProfile, stream: Vec<u8>) -> PacedRun {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    );
    let (client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&stream[..header_len()]).await.expect("write header");

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the destination stream was opened and its header forwarded");
    // The header is a unit too, so wait for it to reach the peer rather than
    // merely for the stream to be accepted: only then is the receiver's clock
    // ahead of every object the bucket will ever be asked about.
    assert_eq!(
        rx.wait_for_bytes(header_len()).await,
        stream[..header_len()].to_vec(),
        "the stream header carries no ObjectMeta, charges no bucket, and must \
         be forwarded unpaced"
    );

    send.write_all(&stream[header_len()..]).await.expect("write objects");

    PacedRun { proxy, client, _client_ep: client_ep, observer, rx, send, stream }
}

// ── the bucket ceiling ─────────────────────────────────────────────────

/// **The ceiling.** At every object boundary, the bytes a bucket has
/// released never exceed `rate * elapsed + burst`.
///
/// # Where the clock starts, and why not at the first chunk
///
/// `t = 0` is [`common::TimedReceiver::started`] — the instant the receiver
/// began reading — and **not** the first chunk's instant. `chunks()`
/// timestamps when `read()` *returned*, so a reader descheduled for Δ lets
/// quinn buffer `rate * Δ + burst` and hand it all back at once; anchored at
/// the first chunk the `i = 0` check would degenerate to `B₀ <= burst` and
/// fail on a busy box, in the **red** direction. Anchored at `started()` the
/// bound is monotone under load: load can only push `tᵢ` later, and a later
/// `tᵢ` only grows the allowance.
///
/// The bucket is full at `burst` when the session is constructed and cannot
/// hold more than that however long it idles, so `started()` — which is
/// strictly later — is a sound zero point.
///
/// The measurement is per **object**, from `into_objects`, rather than per
/// chunk: an object's raw bytes are exactly what the bucket was charged for,
/// where a chunk is whatever quinn happened to coalesce. Same claim, no
/// framing noise, and the subgroup stream header — which carries no
/// `ObjectMeta`, charges no bucket and is not media — drops out of both sides.
///
/// *Ablation, recorded:* give the bucket `rate_bps: None`. The whole stream
/// is released at once and the breach is never at object 0 — the first
/// object is bounded by the writer, and it is the accumulated
/// over-delivery that crosses. **Re-measured, 5/5 runs:** the breach lands
/// at index **2 or 3**, at 609 or 812 bytes against an allowance of
/// 406-622. The index and the byte figures move with the box; the direction
/// of the claim — never index 0, always within the first handful — does
/// not, which is why the transcript below is quoted for its *shape* and the
/// two numbers in it are the ones a re-measurement will disagree with:
///
/// ```text
/// assertion failed: object 2 broke the bucket ceiling: 609 bytes released
/// 1.3ms after the reader started, against an allowance of rate*dt + burst = 419
/// ```
#[tokio::test]
async fn a_bucket_never_delivers_above_its_ceiling() {
    const OBJECTS: u64 = 24;

    let run = paced_run(
        one_class_profile(Some(PACED_RATE), PACED_BURST, STARVED_HOLD, Expiry::Deliver),
        OBJECTS,
    )
    .await;

    assert_eq!(
        run.rx.wait_for_bytes(run.stream.len()).await.len(),
        run.stream.len(),
        "the whole stream must arrive, or the ceiling below is a claim about a \
         stream that stopped early"
    );

    let started = run.rx.started();
    let objects = run.rx.into_objects(DRAFT);
    assert_eq!(objects.len(), OBJECTS as usize);

    let mut released: u128 = 0;
    for (index, (at, _meta, raw)) in objects.iter().enumerate() {
        released += raw.len() as u128;
        let elapsed = at.saturating_duration_since(started);
        let allowance =
            u128::from(PACED_RATE) * elapsed.as_nanos() / 1_000_000_000 + u128::from(PACED_BURST);
        assert!(
            released <= allowance,
            "object {index} broke the bucket ceiling: {released} bytes released \
             {elapsed:?} after the reader started, against an allowance of \
             rate*dt + burst = {allowance}"
        );
    }

    // ...and the run is not passing by delivering almost nothing: the bucket
    // owes its rate as well as obeying it, and the whole stream arrived above.
    assert!(
        released >= u128::from(TwoClassRun::object_bytes(&run.stream)),
        "every object byte offered must have been released: {released}"
    );

    run.finish().await;
}

// ── expiry: deliver ────────────────────────────────────────────────────

/// Under the default `Expiry::Deliver`, an over-long wait is **clamped
/// and delivered** — late, never lost — and the run says so.
///
/// The bucket is rate-limited so low that its own refill instant is more than
/// ten times `max_hold` away: the clamp is therefore what releases every
/// object after the first, and there is no reading under which the bucket
/// could have done it.
///
/// `objects_expired == 0` is the other half, and it is not decoration. It is
/// the difference between "the shaper gave up on this object" and "the shaper
/// ran out of time and sent it anyway", and only the second is what `Deliver`
/// means. The counter has a producer only on the `ResetStream` arm — see
/// `expiry_reset_gives_up_on_the_stream`, which is the same fixture with one
/// field changed.
///
/// # Ablations, both recorded
///
/// **(a) Make `Expiry::Deliver` refuse instead of delivering** — return
/// `false` from that arm of `PendingQueue::expire_head`. Nothing after the
/// first object ever reaches the wire and the byte-equality assertion
/// reddens with a 208-byte prefix against the 4877-byte stream.
///
/// **(b) Drop the `ShapeReport::Clamped` emission.** The stream still
/// arrives, so (a)'s assertion stays green; the clamp assertion is the one
/// that fires, with `left: []`. That is the "it worked but nothing says so"
/// failure, and it is why both halves are in one body.
#[tokio::test]
async fn expiry_delivers_by_default() {
    const OBJECTS: u64 = 6;
    /// Short enough to be reached inside the budget, and pinned rather than
    /// inherited: it is the ceiling the delivery below happens *at*.
    const HOLD: Duration = Duration::from_millis(150);
    /// About one object every two seconds — more than ten times `HOLD` — so
    /// the bucket's own refill instant cannot be what releases anything.
    const CRAWL: u64 = 100;

    let run =
        paced_run(one_class_profile(Some(CRAWL), PACED_BURST, HOLD, Expiry::Deliver), OBJECTS)
            .await;

    assert_eq!(
        run.rx.wait_for_bytes(run.stream.len()).await,
        run.stream,
        "Expiry::Deliver clamps and delivers: a starved class is late, never lossy"
    );
    assert_eq!(
        run.proxy.shape_stats().objects_expired,
        0,
        "Deliver never expires an object — that counter belongs to ResetStream"
    );

    let clamps = run.clamps();
    assert!(
        !clamps.is_empty(),
        "a release the bucket would not have made must be reported, or the run \
         claims a rate it did not apply"
    );
    for (requested, applied) in &clamps {
        assert_eq!(*applied, HOLD, "the clamp applied is the configured max_hold");
        assert_eq!(
            *requested, None,
            "this bucket's refill instant is more than ten times max_hold away and \
             by expiry time it is in the past, so the clamp cut short a wait with \
             no figure attached to it: {requested:?}"
        );
    }

    run.finish().await;
}

// ── expiry: reset the stream ───────────────────────────────────────────

/// `Expiry::ResetStream` gives up on the **stream**.
///
/// The same fixture as `expiry_delivers_by_default` with one field changed,
/// so the two rows differ by exactly the thing they are about.
///
/// # Why there is no lower bound on delivered bytes
///
/// quinn discards the local send buffer when `reset()` is called, so "the
/// bytes drained at teardown reach the peer" is false whenever the drain and
/// the reset land in the same step. The only sound claim is an **upper**
/// bound — no more than the stream header can have arrived, because no object
/// was ever granted — and that is the shape
/// `cancel_with_a_terminal_behind_the_hold` already uses.
///
/// # Ablations, both recorded
///
/// **(a) Drop the `ShapeReport::Expired` emission.** The stream is still
/// reset and `objects_expired` still moves, so the first two assertions stay
/// green; the event assertion fires with `left: []`.
///
/// **(b) Reset without setting `objects_expired`** — delete the
/// `note_expired` call. The reset happens, the event fires, and the counter
/// assertion reddens with `0`. Two independent halves, two independent
/// ablations, because a reset nobody counted and a count nobody caused are
/// different bugs.
#[tokio::test]
async fn expiry_reset_gives_up_on_the_stream() {
    const OBJECTS: u64 = 6;
    const HOLD: Duration = Duration::from_millis(150);
    const CODE: u64 = 0x2A;

    let run = paced_run(
        // A bucket that grants nothing at all, so the clamp is the only thing
        // that can ever decide this stream's fate.
        one_class_profile(Some(0), 0, HOLD, Expiry::ResetStream { code: CODE }),
        OBJECTS,
    )
    .await;

    assert_eq!(
        run.rx.wait_for_ending().await,
        Ending::Reset(CODE),
        "an expiry under ResetStream abandons the destination stream with its \
         configured code"
    );
    assert!(
        run.proxy.shape_stats().objects_expired > 0,
        "and counts the object whose clamp ran out"
    );
    assert_eq!(
        run.proxy.shape_stats().streams_reset_by_shaping,
        1,
        "exactly one stream was abandoned by a shaping policy"
    );
    assert_eq!(
        run.shaped(),
        vec![ShapeOutcome::Expired],
        "exactly one Shaped{{Expired}}, and nothing else"
    );
    assert!(
        run.rx.len() <= header_len(),
        "no object was ever granted, so at most the stream header can have \
         arrived — and quinn may have discarded even that: {} bytes",
        run.rx.len()
    );

    run.finish().await;
}

// ── the FIN path ───────────────────────────────────────────────────────

/// Objects offered by each leg of the two FIN-path gates.
///
/// Four rather than one: a single object cannot tell "the FIN drain reports"
/// from "the FIN drain reports the first one and swallows the rest", and the
/// drain's report slot holds exactly one `ShapeReport` at a time.
const FIN_OBJECTS: u64 = 4;

/// `max_hold` for the FIN-path gates.
///
/// Short, because both legs of both gates spend it and the gate budget is
/// 600 ms — and it appears in **no** assertion. Every claim below is a count
/// or an equality (group 1 of the load-independence inventory at the top of
/// this file), so this number can be moved freely without weakening
/// anything. All four objects are pushed within a millisecond of each other
/// and therefore share one expiry wake, so a leg costs one `FIN_HOLD` and
/// not four.
const FIN_HOLD: Duration = Duration::from_millis(60);

/// A bucket that grants **nothing, ever**, so the clamp is the only thing
/// that can release an object and every object is clamped exactly once.
///
/// `rate_bps: Some(0)` with `burst_bytes: 0` makes `charge` answer
/// `Grant::Never` for every unit — see `shape::bucket` — so there is no
/// refill instant, no accrual, and no way for a slow box to let one more
/// object slip through on tokens. That is what makes the counts below exact
/// two-sided equalities rather than one-sided bounds: there is no clock in
/// them.
fn fin_profile(on_expiry: Expiry) -> ShapeProfile {
    one_class_profile(Some(0), 0, FIN_HOLD, on_expiry)
}

/// One leg of a FIN-path gate.
///
/// **The `fin` bit is the only difference between the two legs**, and that
/// is the whole design of these gates: same profile, same offered bytes,
/// same fixture, one `send.finish()`. A run that FINs releases its queue
/// through `session::drain_pending` →
/// `egress::drain_honouring_release_times`; a run that stays open releases
/// it through `session::release_due_units`. The two paths must report the
/// same shaping, because the source's choice to end a stream cleanly is not
/// a shaping decision.
///
/// Note that [`paced_run`] deliberately leaves `send` open — which is why
/// every other shaping gate here exercises only the second path, and why a
/// FIN drain that reported nothing survived a green suite.
async fn fin_leg(profile: ShapeProfile, fin: bool) -> PacedRun {
    let mut run = paced_run(profile, FIN_OBJECTS).await;
    if fin {
        run.send.finish().expect("the source stream is open and unreset");
    }
    run
}

/// The class row every FIN-path leg shapes into.
fn fin_class(run: &PacedRun) -> ClassStats {
    run.proxy
        .shape_stats()
        .classes
        .into_iter()
        .find(|c| c.name == VIDEO_CLASS)
        .expect("the one class in fin_profile")
}

/// **The FIN path reports its clamps.** A source that FINs — the ordinary
/// MoQT subgroup shape, header then a few objects then FIN — has every one
/// of its objects clamped and delivered by `max_hold`, and says so, exactly
/// as a source that stays open does.
///
/// # What the one-bit difference buys
///
/// The two legs are the same fixture, the same profile and the same bytes.
/// The only thing that differs is `send.finish()`, and a `finish()` is not a
/// shaping decision — so any difference in the shaping *report* between them
/// is a defect by construction, with no timing, no rate and no threshold to
/// argue about. That is why this is a gate and not a calibration: the
/// assertion is `fin == open`, and both sides are measured in the same run
/// of the same test.
///
/// # Why the counters are asserted too
///
/// `objects_delivered == FIN_OBJECTS` on both legs is what makes the failure
/// this guards *silent-noop* rather than *broken*: the bucket is consulted,
/// the clamp applied and every byte held for `max_hold` and then released
/// — the shaping unambiguously happens — while the run's output says
/// nothing about it. A capability that can decline must say so in the run's
/// own output, or its absence is indistinguishable from its success.
///
/// # Ablation, recorded
///
/// Delete the `on_shape` call from the release loop in
/// `egress::drain_honouring_release_times` (leave the `pop_next_due` loop
/// otherwise untouched, so the report is the only thing removed). The
/// bytes still arrive, `objects_delivered` is still 4 on both legs, and the
/// open leg still reports its four clamps. Only the FIN leg goes quiet:
///
/// ```text
/// ---- shaping_reports_do_not_depend_on_a_fin stdout ----
/// thread 'shaping_reports_do_not_depend_on_a_fin' (9800) panicked at
/// crates\moqtap-proxy\tests\actions_shaping.rs:
/// a source that FINs is the ordinary MoQT subgroup shape: header, a few
/// objects, FIN. Every one of its 4 objects was held to max_hold and released
/// by the clamp, and the run reported no clamp at all
/// ```
///
/// The three assertions above it — the whole stream arrived,
/// `objects_delivered == 4`, and the open leg's four clamps — all stay green
/// under that ablation. That is the isolation: only the FIN leg's report
/// moves.
#[tokio::test]
async fn shaping_reports_do_not_depend_on_a_fin() {
    // Both legs concurrently: two independent proxies on two ports, so the
    // test costs one `FIN_HOLD` rather than two.
    let (open, finished) = tokio::join!(
        fin_leg(fin_profile(Expiry::Deliver), false),
        fin_leg(fin_profile(Expiry::Deliver), true)
    );

    // The shaping happened, identically, on both legs — this is the half
    // the ablation above leaves green.
    for (label, run) in [("source stays open", &open), ("source FINs", &finished)] {
        assert_eq!(
            run.rx.wait_for_bytes(run.stream.len()).await,
            run.stream,
            "Expiry::Deliver is late, never lossy: the whole stream must arrive \
             on both legs, or the two legs are not comparable ({label})"
        );
        assert_eq!(
            fin_class(run).objects_delivered,
            FIN_OBJECTS,
            "every object must have been released through the class's own \
             bucket, or the leg never exercised the shaper ({label})"
        );
    }

    let open_clamps = open.clamps();
    let fin_clamps = finished.clamps();

    assert_eq!(
        open_clamps.len(),
        FIN_OBJECTS as usize,
        "a bucket that grants nothing releases every object by the clamp, and \
         each is one HoldClamped: {open_clamps:?}"
    );
    assert!(
        !fin_clamps.is_empty(),
        "a source that FINs is the ordinary MoQT subgroup shape: header, a few \
         objects, FIN. Every one of its {FIN_OBJECTS} objects was held to \
         max_hold and released by the clamp, and the run reported no clamp at all"
    );
    assert_eq!(
        fin_clamps, open_clamps,
        "the two legs differ only by send.finish(), which is not a shaping \
         decision: FIN {fin_clamps:?} against open {open_clamps:?}"
    );
    for (requested, applied) in &fin_clamps {
        assert_eq!(*applied, FIN_HOLD, "the clamp applied is the configured max_hold");
        assert_eq!(
            *requested, None,
            "a bucket that grants nothing names no refill instant, so the wait \
             the clamp cut short has no figure attached to it: {requested:?}"
        );
    }

    open.finish().await;
    finished.finish().await;
}

/// **The FIN path reports its expiries.** The same one-bit design as
/// [`shaping_reports_do_not_depend_on_a_fin`], over the other arm of
/// [`Expiry`]: a stream the shaper gives up on emits
/// `ProxyEvent::Shaped { Expired }` whether or not its source FINed first.
///
/// Separate from the clamp gate because `ShapeReport::Clamped` and
/// `ShapeReport::Expired` leave `PendingQueue::expire_head` on different
/// arms and land on different reporting channels — an `ImpairmentKind` and a
/// `ProxyEvent` — so a fix that drained the report slot for one and not the
/// other would pass a merged test.
///
/// `objects_expired > 0` and the mirrored `Ending::Reset` on **both** legs
/// are again the "it happened" half: the stream really was abandoned by the
/// shaper on the FIN leg too, which is what made the missing event silent
/// rather than merely absent.
///
/// # Ablation, recorded
///
/// Same ablation as the clamp gate — delete the `on_shape` call from
/// `egress::drain_honouring_release_times`'s release loop. The destination
/// is still reset with `0x2A` on both legs and `objects_expired` still
/// moves, so every other assertion here stays green:
///
/// ```text
/// ---- expiry_reports_do_not_depend_on_a_fin stdout ----
/// thread 'expiry_reports_do_not_depend_on_a_fin' (12420) panicked at
/// crates\moqtap-proxy\tests\actions_shaping.rs:
/// assertion `left == right` failed: the shaper abandoned this stream and the
/// run must say so, on both legs (source FINs)
///   left: []
///  right: [Expired]
/// ```
///
/// The `Ending::Reset(0x2A)` and `objects_expired > 0` assertions on the same
/// leg stay green underneath it, which is the shape of the defect: the stream
/// was abandoned by the shaper and the run said nothing.
#[tokio::test]
async fn expiry_reports_do_not_depend_on_a_fin() {
    const CODE: u64 = 0x2A;
    let expiry = Expiry::ResetStream { code: CODE };

    let (open, finished) =
        tokio::join!(fin_leg(fin_profile(expiry), false), fin_leg(fin_profile(expiry), true));

    for (label, run) in [("source stays open", &open), ("source FINs", &finished)] {
        assert_eq!(
            run.rx.wait_for_ending().await,
            Ending::Reset(CODE),
            "an expiry under ResetStream abandons the destination stream with \
             its configured code, on both legs ({label})"
        );
        assert!(
            run.proxy.shape_stats().objects_expired > 0,
            "and counts the object whose clamp ran out ({label})"
        );
        assert_eq!(
            run.shaped(),
            vec![ShapeOutcome::Expired],
            "the shaper abandoned this stream and the run must say so, on both \
             legs ({label})"
        );
    }

    open.finish().await;
    finished.finish().await;
}

// ── teardown bypasses the pacer ────────────────────────────────────────

/// **Teardown bypasses the pacer.**
///
/// A rate-limited but non-zero class that has already put a prefix on the
/// wire, then an upstream reset. The code is mirrored, and it is mirrored
/// *promptly* — which is the whole claim, because a teardown drain routed
/// through the token bucket would still mirror the code, just seconds later.
///
/// # Why the 0-bps class is not the fixture
///
/// With a 0-bps class every byte stays in
/// `PendingQueue` and nothing is ever handed to quinn, so "the bytes already
/// written still arrive" is zero bytes by construction and the row is
/// unfalsifiable. A non-zero rate puts a real prefix on the wire first.
///
/// # The disjunction, and why it is honest
///
/// Which arm holds depends on whether the reset raced the flush, and **both
/// are correct**: quinn discards the local send buffer on `reset()`, so a
/// drain that completed into a dying transport delivers nothing it can vouch
/// for. So the assertion is "the prefix was delivered **or** exactly one
/// `QueuedBytesAtTeardown` accounts for it", never both-and.
///
/// **The disjunction above is gone, and this is why.** It read
/// `before > header_len() || stranded.len() == 1`, with `before` sampled on
/// the line *after* `wait_until(|| rx.len() > header_len(), ..)`. Since
/// `TimedReceiver::len()` only ever grows, the anchor three lines above
/// made the first arm true by construction and the second unreachable —
/// demonstrated, not argued: forcing `stranded.len() == 1` to `false` left
/// the row passing 3/3. The rustdoc's "which arm holds depends on whether
/// the reset raced the flush" described a race this fixture had already
/// decided, because bytes at the *relay* cannot be un-delivered.
///
/// What replaces it is the claim the row can actually make. The residue
/// assertion (`<= 1`) was live all along but said nothing unless there
/// **was** a residue, so the missing half is the non-vacuity anchor: the
/// source offers 24 objects at ten a second and is reset within
/// milliseconds, so most of the stream must still be unsent when the
/// teardown runs. That is a fixture fact worth asserting — if a future edit
/// made this run complete before the reset, every residue claim below it
/// would go quietly vacuous, which is the same failure in a different
/// place.
///
/// # The window
///
/// The residue is 23 objects at ~10 objects a second: pacing it would take
/// **2.3 s**, against a [`RESUME_WINDOW`] of 500 ms — a 4.6x separation, in a
/// direction load can only push red. Widen this, do not delete it.
///
/// *Ablation, recorded:* route `propagate_reset`'s drain through
/// `drain_honouring_release_times` instead of `drain_ignoring_release_times`,
/// so the teardown flush asks the bucket. Neither arm of the disjunction
/// holds — nothing is delivered *and* nothing is reported, because the drain
/// never completes inside the window — and the mirror assertion times out
/// first:
///
/// ```text
/// assertion failed: an upstream reset must reach the peer without waiting on
/// a token bucket: 2.31s against a 500ms window
/// ```
#[tokio::test]
async fn teardown_bypasses_the_pacer() {
    const OBJECTS: u64 = 24;
    const CODE: u64 = 0x11;
    /// About ten objects a second, so pacing the residue would take seconds.
    const SLOW: u64 = 2_000;

    let mut run = paced_run(
        one_class_profile(Some(SLOW), PACED_BURST, STARVED_HOLD, Expiry::Deliver),
        OBJECTS,
    )
    .await;

    // A prefix is on the wire before the reset — the burst covers one object,
    // so this is an anchor and not a wait.
    let rx = &run.rx;
    wait_until(|| rx.len() > header_len(), "the first object to reach the peer").await;

    let reset_at = std::time::Instant::now();
    run.send.reset(CODE.try_into().expect("code fits a varint")).expect("reset the source");

    assert_eq!(
        run.rx.wait_for_ending().await,
        Ending::Reset(CODE),
        "the upstream reset is mirrored with the same code"
    );
    let elapsed = reset_at.elapsed();
    assert!(
        elapsed < RESUME_WINDOW,
        "an upstream reset must reach the peer without waiting on a token \
         bucket: {elapsed:?} against a {RESUME_WINDOW:?} window"
    );

    let delivered = run.rx.len();
    assert!(
        delivered < run.stream.len(),
        "a run that delivered everything before the reset strands nothing, and \
         every residue claim below it would be vacuous: {delivered} of {} bytes \
         reached the peer",
        run.stream.len()
    );
    let stranded = run.stranded();
    assert!(stranded.len() <= 1, "residue is reported by one owner, once: {stranded:?}");

    run.finish().await;
}

// ── stranded bytes at teardown ─────────────────────────────────────────

/// A shaped session still reports the bytes a bucket was holding when
/// the session went down.
///
/// The failure this exists to prevent is bytes going **silently** missing.
/// A queue full of units no bucket
/// would grant is exactly the state a naive teardown loses, and it is a state
/// only shaping can produce.
///
/// The claim is a disjunction: either the bytes
/// reached the peer, or **exactly one** `QueuedBytesAtTeardown` accounts for
/// them. "Exactly one" applies to the report, not to the disjunction —
/// `propagate_stop` reports `queued_bytes()` while the other four teardown
/// paths report `unconfirmed_bytes()`, and a stream must not be counted by
/// two of them.
///
/// *Ablation, recorded:* report from two owners — add a `report_unconfirmed`
/// call to the cancel branch beside the one already there. The `<= 1`
/// assertion reddens with two entries for one stream, which is the
/// double-count that would make a residue figure useless.
#[tokio::test]
async fn a_shaped_session_still_reports_stranded_bytes() {
    const OBJECTS: u64 = 6;

    let run = paced_run(
        // Nothing is grantable, so everything offered is still in the queue
        // when the session goes down — and `STARVED_HOLD` is far enough away
        // that the clamp cannot release it first.
        one_class_profile(Some(0), 0, STARVED_HOLD, Expiry::Deliver),
        OBJECTS,
    )
    .await;

    // The header is through, so the stream exists and its objects are queued
    // behind a bucket that will not grant them.
    let rx = &run.rx;
    wait_until(|| rx.len() >= header_len(), "the destination stream's header").await;
    wait_until(
        || run.proxy.shape_stats().objects_seen >= OBJECTS,
        "the shaper to have seen every offered object",
    )
    .await;

    let delivered = run.proxy.shape_stats().classes[0].bytes_delivered;
    run.proxy.cancel.cancel();
    wait_until(|| !run.stranded().is_empty() || delivered > 0, "the teardown report").await;

    let stranded = run.stranded();
    assert!(
        delivered > 0 || stranded.len() == 1,
        "a bucket-held unit must either reach the peer or be reported exactly \
         once: {delivered} bytes delivered, {stranded:?} reported"
    );
    assert!(stranded.len() <= 1, "one stream, one owner, one report: {stranded:?}");

    run.finish().await;
}

// ── events and reports ─────────────────────────────────────────────────
//
// Everything below is about what a run *says* rather than about what it
// moves. Three claims, and each is the same claim in a different register:
// a shaped session must be readable from outside. Bytes must add up, a
// stream that carries two classes must say so, and a rule that cannot fire
// on this draft must say so instead of quietly dropping its traffic into
// the default row.
//
// The reason they are gates and not documentation is the headline
// failure: an author configures shaping, the profile silently does nothing,
// and the run reports success. Every row here is a producer for the number
// that would have told them.

/// The drafts that ship a `FetchHeader` and **no fetch object layout**, so
/// the framer decodes the header and then stops.
///
/// Every byte of such a stream is `ShapeStats::unshapeable`: the header
/// because no header carries `ObjectMeta`, and everything after it because
/// parsing has been abandoned. That is the only way to get a *wholly*
/// unshapeable stream out of a fixture, which is why
/// [`bytes_are_conserved_across_classes`] uses one.
///
/// Each element carries its own `#[cfg]`, so this is the compiled subset —
/// empty on a build with no draft in 18-20, which is exactly when that
/// row's fetch leg is skipped.
const UNADDRESSED_FETCH_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The drafts on which `publisher_priority` is **`Option`** and the header
/// may omit it — the `0x20` DEFAULT_PRIORITY bit.
///
/// Written out rather than aliased to [`UNADDRESSED_FETCH_DRAFTS`]: that
/// list is drafts 18 through 20 and this one starts at 15, and they are not
/// the same claim in any case — this one is about a bit in a *subgroup*
/// header.
const OPTIONAL_PRIORITY_DRAFTS: &[DraftVersion] = &[
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
];

/// The drafts on which `publisher_priority` is always on the wire, so a
/// rule keyed on it always has something to compare.
const ALWAYS_PRIORITY_DRAFTS: &[DraftVersion] = &[
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
];

/// A whole fetch stream for [`DRAFT`], or `None` on a draft that can frame
/// one.
///
/// Two bytes of header — stream type `0x05` and a request id — then bytes
/// nothing on these drafts can interpret. `actions_objects.rs` uses the
/// same shape, for the same reason: the payload is deliberately opaque,
/// because the claim is that the framer *stops*, and a well-formed body
/// would leave open the possibility that it parsed one.
fn unshapeable_fetch_stream() -> Option<Vec<u8>> {
    UNADDRESSED_FETCH_DRAFTS.contains(&DRAFT).then(|| {
        let mut out = vec![0x05, 0x09];
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        out
    })
}

// ── byte conservation across classes ───────────────────────────────────

/// Track alias of the conservation fixture's class-`a` stream — the one that
/// overflows.
const CONS_A_ALIAS: u64 = 21;
/// Track alias of the conservation fixture's class-`b` stream.
const CONS_B_ALIAS: u64 = 22;
/// Track alias of the conservation fixture's unclaimed stream, which lands in
/// the default row.
const CONS_DEFAULT_ALIAS: u64 = 23;
/// The class name claiming [`CONS_A_ALIAS`].
const CONS_A_CLASS: &str = "a";
/// The class name claiming [`CONS_B_ALIAS`].
const CONS_B_CLASS: &str = "b";
/// Objects the two small streams carry.
const CONS_SMALL_OBJECTS: u64 = 3;
/// Payload bytes in each of those objects — small, because those two
/// streams are here to load the `b` and `default` terms of the identity and
/// not to be paced.
const CONS_SMALL_PAYLOAD: usize = 64;

/// Objects the conservation fixture's queue may hold per stream.
///
/// Six rather than [`ADMIT_DEPTH`]'s four, and the difference is
/// load-bearing: this fixture's two *small* streams arrive whole inside a
/// single 8 KiB read, so their header and all [`CONS_SMALL_OBJECTS`] objects
/// are classified in one pass with nothing released in between — four queued
/// units. A depth of four would drop from those streams too, and the fixture
/// would be measuring its own read batching.
const CONS_DEPTH: usize = 6;

/// **Bytes are conserved across classes.**
///
/// `Σ classes(delivered + dropped) + default + unshapeable == bytes_shaped`,
/// on a fixture that loads **every** term of the sum at once:
///
/// | term | what loads it |
/// |---|---|
/// | `classes[a].delivered` | the admitted prefix of the overflowing stream |
/// | `classes[a].dropped` | its tail, discarded by `Overflow::DropTail` |
/// | `classes[b].delivered` | a second claimed stream, which never overflows |
/// | `default` | a stream on an alias no rule names |
/// | `unshapeable` | three subgroup stream headers **and a whole fetch stream** |
///
/// A conservation identity with a term that is identically zero is not an
/// identity, it is four-fifths of one — so each term is separately asserted
/// non-zero *before* the sum is taken. That ordering is deliberate: a failure
/// then names the term that went missing rather than reporting a mismatched
/// total and leaving the reader to find it.
///
/// # Why a fetch stream, and what happens without one
///
/// Every subgroup stream contributes its header to `unshapeable`, so the row
/// is non-zero on any fixture at all. What a fetch stream adds is a stream
/// that is unshapeable **all the way down**: on drafts 18, 19 and 20 a fetch
/// object's Group ID is a difference the fetch's Group Order gives a
/// direction to, nothing on the data stream states it, and this fixture
/// sends no FETCH for the session to have read it off — so the framer
/// decodes the header, latches `FetchGroupOrderUnknown` and forwards the
/// rest uninterpreted. That is the case where the shaper handling bytes no
/// rule ever saw is the whole stream rather than five bytes of it, and it
/// is the case a producer keyed on the object arm alone would miss entirely.
///
/// On a build whose newest compiled draft is 07-17 the leg is skipped —
/// those drafts resolve a fetch stream from its own bytes, so there is no
/// such thing there — and the identity is still gated over the other four
/// terms. Skipped, not faked: a fetch stream those drafts could parse would
/// land in a class row and prove the opposite of what this leg is for.
///
/// # The anchor, and why it is not the assertion
///
/// Waiting is on the **object** counts — every classified object has been
/// delivered or dropped — and the claim is about **bytes**. Two different
/// measurements, so the anchor cannot make the assertion true: an
/// implementation that resolved every object and mislaid its bytes reaches
/// the anchor and reddens the claim. The fetch stream has no objects at all,
/// so its leg anchors on the relay holding the whole stream, which is
/// strictly later than the counter — `note_delivered` runs before
/// `write_all`, so the statistics lead the wire and never trail it.
///
/// No timing claim anywhere: every wait is for a monotone quantity a correct
/// implementation always reaches, so load makes this slower and never wrong.
///
/// *Ablation, recorded:* empty the body of
/// `ShapeRecorder::note_unshapeable_seen`, so the `unshapeable` row is still
/// charged on release but its bytes never enter `bytes_shaped`. Every
/// non-zero assertion still passes — the row is still written, and the
/// header-count equality above is about *delivery*, which the ablation does
/// not touch — and only the identity reddens, which is the point: the defect
/// is not a missing counter, it is a counter with nothing on the other side
/// of the equals sign.
///
/// ```text
/// assertion `left == right` failed: every byte the shaper saw is charged to
/// exactly one row: ShapeStats { .., unshapeable: ClassStats { ..,
/// bytes_delivered: 25, .., objects_delivered: 5, .. }, .., bytes_shaped: 108438, .. }
///   left: 108463
///  right: 108438
/// ```
///
/// The 25-byte shortfall is the whole of it: three five-byte subgroup stream
/// headers, a two-byte fetch header and an eight-byte passthrough chunk —
/// five units, and every one of them a unit no rule could have claimed.
#[tokio::test]
async fn bytes_are_conserved_across_classes() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let hook = HoldingHook::new();

    let mut bucket = BucketConfig::default();
    bucket.name = ADMIT_BUCKET.to_string();
    bucket.rate_bps = None;
    let mut queue = QueueConfig::default();
    queue.depth_objects = CONS_DEPTH;
    queue.max_hold = Some(MAX_HOLD);
    queue.overflow = Overflow::DropTail;
    let profile = ShapeProfile::try_new(
        vec![bucket],
        vec![
            alias_class(CONS_A_CLASS, CONS_A_ALIAS, ADMIT_BUCKET, 0, 1),
            alias_class(CONS_B_CLASS, CONS_B_ALIAS, ADMIT_BUCKET, 0, 1),
        ],
        queue,
        Discipline::Fifo,
    )
    .expect("two uniquely-named classes over one configured bucket");

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    // The fetch leg first and alone, because `timed_uni` hands back the next
    // stream with no identity and a fetch stream has no Track Alias to demux
    // on. Opening it by itself is what makes the receiver unambiguous.
    let fetch = unshapeable_fetch_stream();
    let fetch_bytes = match &fetch {
        Some(stream) => {
            let mut send = client.open_uni().await.expect("open_uni fetch");
            send.write_all(stream).await.expect("write fetch");
            send.finish().expect("finish fetch");
            let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
                .await
                .expect("the fetch stream was forwarded upstream");
            assert_eq!(
                rx.wait_for_bytes(stream.len()).await,
                *stream,
                "a bypassed fetch stream is forwarded uninterpreted, whole"
            );
            stream.len() as u64
        }
        None => 0,
    };

    // The overflowing stream next, on its own, so the hook's single hold
    // lands on *its* head and not on whichever stream raced it.
    let a = subgroup_stream(CONS_A_ALIAS, ADMIT_OFFERED, ADMIT_PAYLOAD);
    let mut a_send = client.open_uni().await.expect("open_uni a");
    a_send.write_all(&a).await.expect("write a");
    wait_until(|| !hook.calls().is_empty(), "the head of stream a to reach the hook").await;
    wait_until(
        || proxy.shape_stats().objects_seen >= ADMIT_OFFERED,
        "every object of stream a to be classified",
    )
    .await;

    let b = subgroup_stream(CONS_B_ALIAS, CONS_SMALL_OBJECTS, CONS_SMALL_PAYLOAD);
    let d = subgroup_stream(CONS_DEFAULT_ALIAS, CONS_SMALL_OBJECTS, CONS_SMALL_PAYLOAD);
    let mut b_send = client.open_uni().await.expect("open_uni b");
    b_send.write_all(&b).await.expect("write b");
    let mut d_send = client.open_uni().await.expect("open_uni d");
    d_send.write_all(&d).await.expect("write d");

    hook.gate.release();

    let objects = ADMIT_OFFERED + 2 * CONS_SMALL_OBJECTS;
    wait_until(
        || {
            let s = proxy.shape_stats();
            s.objects_seen == objects && classed_objects_resolved(&s) == s.objects_seen
        },
        "every classified object to be delivered or dropped",
    )
    .await;

    let stats = proxy.shape_stats();
    let a_row = named_row(&stats, CONS_A_CLASS);
    let b_row = named_row(&stats, CONS_B_CLASS);

    // Term by term, before the sum: a failure here names what went missing.
    assert!(a_row.bytes_delivered > 0, "the admitted prefix of stream a: {stats:?}");
    assert!(a_row.bytes_dropped > 0, "the overflow of stream a: {stats:?}");
    assert_eq!(
        a_row.objects_delivered + a_row.objects_dropped,
        ADMIT_OFFERED,
        "every offered object of stream a is either delivered or dropped, never \
         both and never neither: {stats:?}"
    );
    assert_eq!(
        b_row.objects_delivered, CONS_SMALL_OBJECTS,
        "stream b never overflows, so its class holds all of it: {stats:?}"
    );
    assert_eq!(
        stats.default_class.objects_delivered, CONS_SMALL_OBJECTS,
        "an alias no rule names lands in the default row: {stats:?}"
    );
    assert_eq!(
        stats.default_class.bytes_dropped, 0,
        "and is not dropped on the way there: {stats:?}"
    );
    assert_eq!(
        stats.unshapeable.bytes_delivered,
        3 * header_len() as u64 + fetch_bytes,
        "the unshapeable row holds exactly the three subgroup stream headers and \
         every byte of the fetch stream: {stats:?}"
    );

    let charged: u64 = stats
        .classes
        .iter()
        .chain([&stats.default_class, &stats.unshapeable])
        .map(|c| c.bytes_delivered + c.bytes_dropped)
        .sum();
    assert_eq!(
        charged, stats.bytes_shaped,
        "every byte the shaper saw is charged to exactly one row: {stats:?}"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// Objects that have reached a terminal state on a row a **classifier**
/// wrote: the configured classes and the default row.
///
/// Deliberately excludes `unshapeable`, and that exclusion is what keeps the
/// conservation row's anchor independent of its claim: an unshapeable unit is
/// never
/// counted by `objects_seen` — it is not an object — so including it here
/// would make the anchor unreachable by construction rather than by defect.
fn classed_objects_resolved(stats: &ShapeStats) -> u64 {
    stats
        .classes
        .iter()
        .chain([&stats.default_class])
        .map(|c| c.objects_delivered + c.objects_dropped)
        .sum()
}

/// The row named `name`, by name rather than by index, so a profile that
/// reorders its classes cannot silently swap two assertions.
fn named_row(stats: &ShapeStats, name: &str) -> ClassStats {
    stats
        .classes
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no class row named {name}"))
        .clone()
}

// ── one stream, two classes ────────────────────────────────────────────

/// Track alias of the mixed-class stream. Two classes, one stream — the whole
/// point is that the split is *inside* it.
const MIXED_ALIAS: u64 = 31;
/// Track alias of the single-object stream that fixture opens **first**.
///
/// It exists to make the `StreamKey` assertion discriminating. Measured: with
/// the mixed stream alone, its key is the session's first and its id is `0`,
/// so an implementation that reported a fabricated
/// `StreamKey { side, id: 0 }` passed the equality — the ablation was run and
/// came back green. One stream ahead of it moves the id off the default and
/// the same ablation reddens. A key assertion on the first stream of a
/// session is not an assertion.
///
/// One object, so it resolves to one class and reports no disagreement of its
/// own: `mixed.len() == 1` below stays a claim about the mixed stream.
const MIXED_DECOY_ALIAS: u64 = 32;
/// Objects on that decoy stream. **One**, and it must stay one: a second
/// object would resolve to the other class and the decoy would report a
/// disagreement of its own.
const MIXED_DECOY_OBJECTS: u64 = 1;
/// The class claiming object 0 alone, on a bucket that never grants.
const MIXED_HEAD_CLASS: &str = "head";
/// The class claiming every object after it, on an unlimited bucket.
const MIXED_TAIL_CLASS: &str = "tail";
/// Objects the mixed-class stream carries. Twelve, so
/// `starved_behind_other_class`
/// is a count with several bits in it: a producer that charged once per
/// *stream* rather than once per unit would report 1 and still be non-zero.
const MIXED_OBJECTS: u64 = 12;
/// Payload bytes per object. Small — nothing here is paced except the one
/// object that is never granted at all.
const MIXED_PAYLOAD: usize = 32;

/// A hook that records the [`StreamKey`] of every stream it is shown and
/// holds the first object of **each** stream on a gate the test owns.
///
/// Both halves are needed and neither is decoration. The key is what
/// [`ImpairmentKind::ClassChangedMidStream`] is asserted to name, and a hook
/// is the only thing that is ever shown one. The hold is what makes the
/// starvation count deterministic: see the test.
///
/// Per *stream* and not per session, which is what lets the fixture open a
/// decoy stream ahead of the one under test without the decoy swallowing the
/// hold.
struct MixedClassHook {
    gate: Gate,
    keys: Mutex<Vec<StreamKey>>,
    /// One entry per object call, holding the stream it arrived on: both the
    /// call count and the "have I already held this stream" answer.
    calls: Mutex<Vec<u64>>,
}

impl MixedClassHook {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: Gate::new(),
            keys: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        })
    }

    /// The key minted for the `n`-th stream this hook was shown.
    fn key(&self, n: usize) -> StreamKey {
        self.keys.lock().expect("keys")[n]
    }

    fn calls(&self) -> usize {
        self.calls.lock().expect("calls").len()
    }
}

impl ProxyHook for MixedClassHook {
    fn interest(&self) -> Interest {
        Interest::STREAMS | Interest::OBJECTS
    }

    fn on_stream_open(&self, cx: &StreamCtx<'_>) -> StreamAction {
        self.keys.lock().expect("keys").push(cx.key());
        StreamAction::Open
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let mut calls = self.calls.lock().expect("calls");
        let first_on_this_stream = !calls.contains(&cx.stream_id);
        calls.push(cx.stream_id);
        if first_on_this_stream {
            Action::Hold { gate: self.gate.clone(), then: Box::new(Action::Pass) }
        } else {
            Action::Pass
        }
    }
}

/// **A stream that carries two classes says so — and says which kind of
/// waiting it caused.**
///
/// One subgroup stream, split by an `object_id` rule: object 0 belongs to a
/// class whose bucket never grants, objects 1-11 to a class whose bucket is
/// unlimited. The queue is a single FIFO and its head gates
/// everything behind it, so the eleven unlimited objects wait on a bucket
/// that is not theirs.
///
/// That is a real cost and it has to be **loud**, or a caller reads
/// head-of-line blocking as the shaping they configured. Three producers say
/// it, and this row gates all three together because any one alone is
/// ambiguous:
///
/// - `Impairment{ClassChangedMidStream}` — **once per stream**, naming the
///   [`StreamKey`] the hook was shown. Keyed on the key and not on the
///   transport id, or "once per stream" would read as "once per session" on
///   the WebTransport arm, where every transport stream id is `0`.
/// - `ShapeStats::streams_with_mixed_classes` — the running figure beside it.
/// - `ClassStats::starved_behind_other_class` on the **tail** class, which is
///   the number that distinguishes "somebody else was in front of me" from
///   "my own bucket was dry".
///
/// # The orthogonality assertion, and why it is the ablation target
///
/// The tail class is asserted to have `tokens_exhausted_episodes == 0` and
/// the head class `starved_behind_other_class == 0`. Two causes of waiting,
/// two counters, and neither may leak into the other — the same shape
/// [`block_and_drop_tail_have_orthogonal_signatures`]
/// gates for `Block` versus `DropTail`, one layer down. Conflating them is
/// not a cosmetic defect: an author whose tail class reports an exhausted
/// bucket will raise its rate, which changes nothing at all, because the
/// bucket that refused was never theirs.
///
/// # Why the head is held before the pacer ever sees it
///
/// `starved_behind_other_class` is charged by the queue when it **parks** its
/// head, over the units already behind it. A dry-bucket park arms the next
/// wake at `max_hold` — five seconds out — so the queue parks exactly once
/// and charges exactly the units queued at that instant. Without the hold,
/// that instant is whenever the reader happened to be, and the count is the
/// runner's read batching rather than the shaper's.
///
/// So the hook holds object 0 on a gate the test owns. Nothing is due, so
/// nothing parks; the whole stream is read and queued; then the gate is
/// released, the head becomes due, the bucket refuses it once, and every one
/// of the eleven units behind it is charged in that single sweep. The count
/// is then exact — `MIXED_OBJECTS - 1` — rather than a lower bound, and an
/// implementation that charged per *wake* instead of per *unit* reddens on
/// the equality.
///
/// No timing claim: the gate is released by the test, not by a clock, and
/// [`STARVED_HOLD`] is the stated ceiling if it never were.
///
/// *Ablations, both recorded.*
///
/// **(a) Attribute head-of-line waiting to the wrong counter.** In
/// `PendingQueue::note_starved_behind`, call `stats.note_tokens_exhausted`
/// instead of `stats.note_starved`. The first half of the row — the report
/// and its key — is untouched and still green. The second half inverts, in
/// 0.02 s rather than on a timeout, which is what the anchor above is for:
///
/// ```text
/// assertion `left == right` failed: eleven units waited behind a class that
/// was not theirs, and each is charged once: ShapeStats { classes: [
///   ClassStats { name: "head", .., tokens_exhausted_episodes: 1, starved_behind_other_class: 0, .. },
///   ClassStats { name: "tail", .., tokens_exhausted_episodes: 11, starved_behind_other_class: 0, .. }], .. }
///   left: 0
///  right: 11
/// ```
///
/// The `tail` row in that dump is the defect stated in one line: eleven
/// exhausted-bucket episodes on a class whose bucket is `rate_bps: None` and
/// was never asked a question.
///
/// **(b) Report a key that is not the stream's.** In `pipe_data_framed`,
/// emit `ClassChangedMidStream { key: StreamKey { side, id: 0 }, stream_id }`
/// — the shape a WebTransport-blind implementation degenerates to, where
/// every stream reports the same identity:
///
/// ```text
/// assertion `left == right` failed: the report names the stream the hook was
/// shown, which is the only identity that survives the WebTransport arm
///   left: StreamKey { side: ClientToProxy, id: 0 }
///  right: StreamKey { side: ClientToProxy, id: 1 }
/// ```
///
/// **Measured twice, and the first run is the reason the decoy stream
/// exists**: with the mixed stream alone this exact ablation ran **green**,
/// because the stream under test was the session's first and its id really
/// was `0`. A gate that cannot distinguish the right answer from a constant
/// is not a gate. See [`MIXED_DECOY_ALIAS`].
#[tokio::test]
async fn a_mixed_class_stream_says_so() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = MixedClassHook::new();

    let mut head = ClassRule::default();
    head.name = MIXED_HEAD_CLASS.to_string();
    head.bucket = "dry".to_string();
    let mut head_matcher = Matcher::default();
    head_matcher.object_id = Some(RangeSet::single(0));
    head.matcher = head_matcher;

    let mut tail = ClassRule::default();
    tail.name = MIXED_TAIL_CLASS.to_string();
    tail.bucket = "open".to_string();
    let mut tail_matcher = Matcher::default();
    tail_matcher.object_id = Some(RangeSet::new([1..=u64::MAX]));
    tail.matcher = tail_matcher;

    let profile = ShapeProfile::try_new(
        vec![named_bucket("dry", Some(0), 0), named_bucket("open", None, 0)],
        vec![head, tail],
        paced_queue(STARVED_HOLD, Expiry::Deliver),
        Discipline::Fifo,
    )
    .expect("two uniquely-named classes over two configured buckets");

    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    // A single-object stream first, so the stream under test is not the
    // session's first and its `StreamKey` id is not the default `0`. See
    // [`MIXED_DECOY_ALIAS`].
    let decoy = subgroup_stream(MIXED_DECOY_ALIAS, MIXED_DECOY_OBJECTS, MIXED_PAYLOAD);
    let mut decoy_send = client.open_uni().await.expect("open_uni decoy");
    decoy_send.write_all(&decoy).await.expect("write decoy");
    wait_until(|| hook.calls() >= 1, "the decoy stream to reach the hook").await;

    let stream = subgroup_stream(MIXED_ALIAS, MIXED_OBJECTS, MIXED_PAYLOAD);
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");

    // Every object is classified and queued while the head is held, so the
    // sweep below has the whole stream to charge.
    let offered = MIXED_OBJECTS + MIXED_DECOY_OBJECTS;
    wait_until(
        || proxy.shape_stats().objects_seen >= offered,
        "every offered object to be classified",
    )
    .await;
    assert_eq!(
        hook.calls() as u64,
        offered,
        "the hook saw every object, so nothing was dropped on the way in and the \
         queue really does hold all twelve"
    );

    // The report is taken *before* the gate is released: classification is
    // what produces it, and it must not need a release to be visible.
    let mixed: Vec<ImpairmentKind> = observer
        .impairments()
        .into_iter()
        .filter(|k| matches!(k, ImpairmentKind::ClassChangedMidStream { .. }))
        .collect();
    let ImpairmentKind::ClassChangedMidStream { key, .. } = mixed
        .first()
        .unwrap_or_else(|| panic!("a stream carrying two classes must say so: {mixed:?}"))
    else {
        unreachable!("filtered to this variant")
    };
    assert_eq!(
        mixed.len(),
        1,
        "once per stream, on the first disagreement — and the single-object decoy \
         stream reported nothing of its own: {mixed:?}"
    );
    assert_ne!(
        hook.key(1),
        hook.key(0),
        "the fixture's own premise: two streams, two keys, so the equality below \
         is discriminating rather than a comparison against a default"
    );
    assert_eq!(
        *key,
        hook.key(1),
        "the report names the stream the hook was shown, which is the only \
         identity that survives the WebTransport arm"
    );
    assert_eq!(
        proxy.shape_stats().streams_with_mixed_classes,
        1,
        "and the running figure beside it moves with it"
    );

    hook.gate.release();

    // The anchor is "the tail class was charged for its wait", **whichever
    // counter the implementation chose** — which is deliberately not the
    // counter under test. Anchoring on `starved_behind_other_class` alone
    // would turn ablation (a) into a five-second timeout on the wait instead
    // of a one-line inversion on the assertion, and a gate whose failure mode
    // is a timeout does not say what it measured.
    let tail_charged = || {
        let row = named_row(&proxy.shape_stats(), MIXED_TAIL_CLASS);
        row.starved_behind_other_class + row.tokens_exhausted_episodes > 0
    };
    wait_until(tail_charged, "the head to be parked and its queue charged").await;

    let stats = proxy.shape_stats();
    let head_row = named_row(&stats, MIXED_HEAD_CLASS);
    let tail_row = named_row(&stats, MIXED_TAIL_CLASS);

    assert_eq!(
        tail_row.starved_behind_other_class,
        MIXED_OBJECTS - 1,
        "eleven units waited behind a class that was not theirs, and each is \
         charged once: {stats:?}"
    );
    assert_eq!(
        tail_row.tokens_exhausted_episodes, 0,
        "the tail class has an unlimited bucket and was never asked about it: \
         waiting behind another class is not an exhausted bucket: {stats:?}"
    );
    assert!(
        head_row.tokens_exhausted_episodes > 0,
        "the head class was refused by its own bucket, which is the other kind \
         of waiting and the other counter: {stats:?}"
    );
    assert_eq!(
        head_row.starved_behind_other_class, 0,
        "and nothing was ever in front of it: {stats:?}"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── the publisher-priority partition ───────────────────────────────────

/// The header-type bit that omits the Publisher Priority field on drafts
/// 15-20 (`draft19/data_stream.rs`'s `SUBGROUP_DEFAULT_PRIORITY_BIT`, and
/// the same value on every other draft in that range).
///
/// This is a bit in the **stream type byte**, not a value of the priority
/// field, and the two are easy to confuse: a priority *byte* of `0x80`
/// decodes as `Some(128)` on every draft 07-20.
/// `None` is only reachable by setting this bit and omitting the byte, and
/// `None` is what the whole row is about.
const DEFAULT_PRIORITY_BIT: u8 = 0x20;

/// The class name the priority-keyed rule uses on both sides of the
/// partition.
const PRIORITY_CLASS: &str = "priority-keyed";
/// Objects each of the two priority-partition streams carries.
const PRIORITY_OBJECTS: u64 = 4;
/// Payload bytes per object. Small: nothing here is paced.
const PRIORITY_PAYLOAD: usize = 32;
/// The Publisher Priority every always-priority header below carries.
const PRIORITY_VALUE: u8 = 0x80;

/// A subgroup stream header for `draft` that **omits** the Publisher
/// Priority field: four bytes, not five.
///
/// Only meaningful on drafts 15-20 — on 07-14 the bit is not defined and
/// the field is unconditional.
fn default_priority_header_bytes(draft: DraftVersion, track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "single-byte varint only");
    vec![subgroup_stream_type(draft) | DEFAULT_PRIORITY_BIT, track_alias as u8, 0x00, 0x00]
}

/// What one leg of the priority partition observed.
struct PriorityRun {
    /// Every `ShapeRuleUnmatchable` the session reported.
    unmatchable: Vec<ImpairmentKind>,
    stats: ShapeStats,
}

/// Run one session on `draft` with a single class keyed on
/// `publisher_priority`, offering one subgroup stream built from `head`.
///
/// The bucket is unlimited and `max_hold` is pinned, so the stream runs to
/// completion and the delivery rows below are totals rather than samples.
/// The anchor is the relay holding every byte: nothing here is a duration.
async fn priority_class_run(
    draft: DraftVersion,
    head: Vec<u8>,
    priority: std::ops::RangeInclusive<u8>,
) -> PriorityRun {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());

    let mut class = ClassRule::default();
    class.name = PRIORITY_CLASS.to_string();
    class.bucket = ADMIT_BUCKET.to_string();
    let mut matcher = Matcher::default();
    matcher.priority = Some(priority);
    class.matcher = matcher;

    let profile = ShapeProfile::try_new(
        vec![named_bucket(ADMIT_BUCKET, None, 0)],
        vec![class],
        paced_queue(MAX_HOLD, Expiry::Deliver),
        Discipline::Fifo,
    )
    .expect("one class over one configured bucket");

    let mut config = shaping_config_for(draft, relay.addr);
    config.shape = Some(profile);
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let stream = subgroup_stream_from(draft, head, PRIORITY_OBJECTS, PRIORITY_PAYLOAD);
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");
    send.finish().expect("finish");

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the stream was forwarded upstream");
    assert_eq!(
        rx.wait_for_bytes(stream.len()).await,
        stream,
        "[{draft}] the stream reached the relay whole, so every object has been \
         classified and released"
    );
    let run = PriorityRun {
        unmatchable: observer
            .impairments()
            .into_iter()
            .filter(|k| matches!(k, ImpairmentKind::ShapeRuleUnmatchable { .. }))
            .collect(),
        stats: proxy.shape_stats(),
    };
    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
    run
}

/// **An unmatchable rule says so — on both sides of the partition.**
///
/// A `publisher_priority`-keyed class, run twice:
///
/// - on the newest compiled draft in **15-20**, against a header that set the
///   `0x20` DEFAULT_PRIORITY bit and omitted the field. The key is `None`, and
///   a rule keyed on a field the header does not carry never matches, so
///   the objects fall to the default row,
///   and **exactly one** `Impairment{ShapeRuleUnmatchable{Priority}}` says
///   why.
/// - on the newest compiled draft in **07-14**, against a header that carries
///   the field. The rule matches, the class holds everything, and the
///   impairment does **not** fire.
///
/// Both halves are needed and neither is redundant. The first alone would
/// pass against an implementation that reported `ShapeRuleUnmatchable` for
/// every rule that failed to match, which would make the report noise. The
/// second alone would pass against one that never reported at all.
///
/// # Where the partition is, and why it is not 17-20
///
/// `publisher_priority` is `Option<u8>` on Draft15 **through** Draft20 and
/// `Some(_)` on 07-14 (`dispatch.rs:381-394`). A revision that
/// drew the line at 17 would leave drafts 15 and 16 unexercised on both
/// sides — and 15 and 16 are exactly where the acceptance case
/// ("`StrictPriority` starves video while audio flows") first goes silently
/// wrong.
///
/// The `None` is reached through a bit in the **stream type byte** and not
/// through a value of the priority field: see [`DEFAULT_PRIORITY_BIT`]. A
/// priority byte of `0x80` decodes as `Some(128)` on all fourteen drafts, so
/// a fixture that tried to produce `None` by choosing a byte value would be
/// testing nothing at all and would pass.
///
/// # Two drafts, not fourteen
///
/// A 13-draft QUIC sweep measures 4.7-5.0 s, eight times the 600 ms
/// per-gate budget. The full sweep belongs in a calibration run on a quiet
/// machine; this row gates the two drafts
/// that bracket the partition, which is what a regression would have to
/// cross.
///
/// Each half is skipped when its side of the partition compiled empty, and
/// the test then asserts that **at least one** ran — a build that exercised
/// neither would otherwise report a green row for a claim it never made.
///
/// *Ablation, recorded:* treat an absent key as the encoder's default. In
/// `Matcher::matches`, replace the priority arm's `Some(p) if ...` /
/// `_ => return false` pair with
/// `if !range.contains(&meta.publisher_priority.unwrap_or(128))`. The 07-14
/// half is unaffected — its key is present — and the 15-20 half reddens
/// twice over: the class claims every object, so the default row is empty,
/// and the impairment never fires. It reports the second first, because the
/// report is what an author would have read:
///
/// ```text
/// assertion `left == right` failed: [draft-19] a rule keyed on a field this
/// header omitted reports exactly once per session per (class, field), naming both
///   left: []
///  right: [ShapeRuleUnmatchable { class: "priority-keyed", field: Priority, draft: Draft19 }]
/// ```
///
/// That empty vector is the failure mode in one line: the profile did
/// something other than what it said, and the run reported success.
#[tokio::test]
async fn an_unmatchable_rule_says_so_on_both_sides_of_the_partition() {
    let mut ran = 0;

    // The half where the key can be absent. The rule names the widest range
    // there is, so a failure to match cannot be a failure to match a *value*.
    if let Some(&draft) = OPTIONAL_PRIORITY_DRAFTS.last() {
        ran += 1;
        let run =
            priority_class_run(draft, default_priority_header_bytes(draft, LEAD_ALIAS), 0..=255)
                .await;

        assert_eq!(
            run.unmatchable,
            vec![ImpairmentKind::ShapeRuleUnmatchable {
                class: PRIORITY_CLASS.to_string(),
                field: MatcherField::Priority,
                draft,
            }],
            "[{draft}] a rule keyed on a field this header omitted reports exactly \
             once per session per (class, field), naming both"
        );
        assert_eq!(
            run.stats.default_class.objects_delivered, PRIORITY_OBJECTS,
            "[{draft}] and the objects it could not claim are in the default row, \
             which is the figure an author reads: {:?}",
            run.stats
        );
        assert_eq!(
            run.stats.classes[0].objects_delivered, 0,
            "[{draft}] an absent key never matches: {:?}",
            run.stats
        );
    }

    // The half where the key is always on the wire. Same class, same field,
    // a range that contains what the header carries.
    if let Some(&draft) = ALWAYS_PRIORITY_DRAFTS.last() {
        ran += 1;
        let run = priority_class_run(
            draft,
            subgroup_header_bytes(draft, LEAD_ALIAS),
            PRIORITY_VALUE..=PRIORITY_VALUE,
        )
        .await;

        assert_eq!(
            run.unmatchable,
            vec![],
            "[{draft}] the key is on the wire here, so there is nothing to report: \
             a rule that matched is a rule working"
        );
        assert_eq!(
            run.stats.classes[0].objects_delivered, PRIORITY_OBJECTS,
            "[{draft}] and the class claims every object: {:?}",
            run.stats
        );
        assert_eq!(
            run.stats.default_class.objects_delivered, 0,
            "[{draft}] so nothing falls through: {:?}",
            run.stats
        );
    }

    assert!(
        ran > 0,
        "neither side of the partition compiled, so this row asserted nothing: \
         enable at least one draft feature"
    );
}

// ── the acceptance ─────────────────────────────────────────────────────

/// Objects offered on each of the acceptance row's two streams.
///
/// Eight rather than one, so "video delivered nothing" is a claim about
/// eight separate denials rather than about a single unit that might merely
/// not have arrived yet; and eight rather than eighty so the audio stream,
/// whose bucket is unlimited, is whole in a few milliseconds and the sample
/// below is taken far from [`STARVED_HOLD`].
const ACCEPTANCE_OBJECTS: u64 = 8;

/// **This test is the shaping acceptance criterion**, in one body:
/// *"starve video while audio flows" is expressible in configuration alone,
/// with statistics proving which class was starved*.
///
/// Everything else in this file gates a mechanism. This one gates the
/// *claim* — that a user who writes a [`ShapeProfile`] and no code gets the
/// behaviour the profile describes, and can read back which class paid for
/// it. It is deliberately the only row here that asserts all three halves
/// against a single session, because the promise being made is the
/// conjunction: any two of them hold in postures where the third does not.
///
/// # The posture is half the claim
///
/// The hook is [`NoOpHook`] — `Interest::NONE` — and the observer is
/// [`NoOpProxyObserver`], whose `wants_events()` is `false`. Neither can
/// decide anything: there is no `on_object`, no [`Action`], no event sink,
/// no user code of any kind between the client's bytes and the relay's. The
/// only input that differs from a plain byte pump is `config.shape`.
///
/// That posture is what makes this row different from its neighbours, and
/// the difference is not cosmetic. `objects_enabled` is
/// `observer_enabled || interest.contains(Interest::OBJECTS) ||
/// shaping_enabled` (`session.rs:293-295`), and classification needs
/// `ObjectMeta`, which only the framed pipe produces. Any fixture carrying a
/// hook with `Interest::OBJECTS` — [`two_class_run`]'s barrier, for one —
/// arms that pipe through the **second** term and would keep shaping alive
/// with the third term deleted. [`a_zero_rate_class_starves_and_the_other_flows`]
/// shares this row's buckets and asserts the same zero, and it stays green
/// with `|| shaping_enabled` removed. This one does not, which is the whole
/// reason it exists.
///
/// That is measured, not argued: with the term deleted, **exactly three of
/// this file's 28 rows redden** — [`a_shape_profile_arms_without_a_hook`],
/// [`shape_stats_are_zero_without_a_profile_and_move_with_one`] and this
/// one. Every other shaping gate here, including the two that share this
/// row's profile shape, stays green, because every one of them carries a
/// hook that arms framing on its own account.
///
/// The profile is written out **inline** rather than behind a fixture
/// helper. "Expressible in config alone" is a claim about what a reader has
/// to write, so what a reader has to write is on the screen: two buckets,
/// two classes, one queue policy, one discipline.
///
/// # `queue.max_hold` is pinned, and what it is separated from
///
/// Under the default [`Expiry::Deliver`] a `rate_bps: Some(0)` class
/// **does** deliver — at `max_hold`. "Video received nothing" is therefore a
/// statement about a *sampling window*, and a fixture that inherited the
/// 30 s default would be hiding a 30 s duration inside a claim that never
/// mentions one. [`STARVED_HOLD`] — five seconds — is pinned through
/// [`paced_queue`], and the sample is taken the instant the audio stream is
/// whole, tens of milliseconds in. Load can only delay that sample, and
/// delay is the direction that keeps the claim true, across roughly two
/// orders of magnitude of separation. Nothing here compares two durations.
///
/// # Why "zero bytes" is asserted as "exactly its header"
///
/// The obvious form of this row says the video destination stream receives
/// *zero* bytes. What is
/// measured, and what the code says should be measured, is that it receives
/// **exactly its five-byte subgroup stream header and no media byte at
/// all**. A stream header carries no `ObjectMeta`, so no rule can claim it,
/// no bucket can charge it, and
/// [`ShapeStats::unshapeable`](moqtap_proxy::shape::ShapeStats::unshapeable)
/// exists precisely to account for it. Asserting `is_empty()` would be
/// asserting that unshapeable bytes are paced — which they are not, which
/// the code says they are not, and which
/// [`a_zero_rate_class_starves_and_the_other_flows`] records the same
/// measurement for. The narrowing costs nothing: this is an `assert_eq!` on
/// an exact length either way, so it rejects one delivered object just as
/// sharply as `== 0` would.
///
/// # What each of the three assertions would let through alone
///
/// * **(1) alone** — the video stream carries no media — is also what a
///   proxy that dropped the video stream on the floor produces.
/// * **(2) alone** — audio is byte-equal to its source — is what an
///   unshaped session produces.
/// * **(3) alone** — the stats name video with zero — is what a recorder
///   with no writer produces. `bytes_delivered == 0` is that field's default
///   value, and ablation (b) below is the measurement that says so: under it
///   the whole `video` row reads back all-zero and that one assertion stays
///   **green** while every other assertion in this test goes red.
///
/// Together, with the video row's `tokens_exhausted_episodes > 0` beside
/// them, they say: the video objects reached the shaper, the shaper refused
/// them *because its bucket was dry* and said so, the audio objects reached
/// the shaper and were passed whole, and the report names both.
///
/// # Ablations, both recorded
///
/// **(a) Drop `|| shaping_enabled` from
/// `objects_enabled`** (`session.rs:295`), leaving every other term. The
/// session falls to the pass-through pipe and `pipe_data`'s `debug_assert!`
/// (`session.rs:2202`) catches it first, in the forwarding task:
///
/// ```text
/// panicked at crates\moqtap-proxy\src\session.rs:
/// a session with a ShapeProfile must be framed: shaping cannot classify a byte pump
/// ```
///
/// Both stream tasks die, so no destination stream is ever opened and this
/// test reddens at its accept — after the harness's 10 s ceiling, which is
/// the one posture in this file that exceeds the 600 ms budget and does so
/// only while broken:
///
/// ```text
/// panicked at crates\moqtap-proxy\tests\actions_shaping.rs:
/// both destination streams were opened and their headers forwarded: Elapsed(())
/// ```
///
/// **(b) The same, with the `debug_assert!` also removed** — which is what a
/// `--release` build would see, and the form that shows the *behaviour*
/// rather than the guard. The pass-through pipe forwards both streams
/// verbatim, in 0.03 s, and the wire assertion goes first:
///
/// ```text
/// assertion `left == right` failed: a dry bucket must deliver no media at all:
/// the video destination holds 1629 bytes against a 5-byte header
///   left: 1629
///  right: 5
/// ```
///
/// Neutralising that one and re-running — because an ablation that stops at
/// the first panic has only measured the first assertion — the next red is
/// the video row's *reason*:
///
/// ```text
/// ...and say *why* it got nothing: a dry bucket is an episode, not a silence.
/// Without this a zero is indistinguishable from a class that was never offered
/// anything: ClassStats { name: "video", bytes_delivered: 0, bytes_dropped: 0,
/// objects_delivered: 0, objects_dropped: 0, tokens_exhausted_episodes: 0, ... }
/// ```
///
/// and neutralising *that* one, the audio row:
///
/// ```text
/// assertion `left == right` failed: and must account every object byte the
/// flowing class carried — the whole stream less its unshapeable header:
/// ClassStats { name: "audio", bytes_delivered: 0, ... }
///   left: 0
///  right: 1624
/// ```
///
/// Three of the four go red; `video_row.bytes_delivered == 0` is the one that
/// does **not**, because under (b) the shaper never ran and zero is the
/// field's default. That is the measured form of the "(3) alone" bullet
/// above, and it is why `tokens_exhausted_episodes` is asserted beside it: a
/// starved class and an absent shaper report the same zero, and only the
/// episode count tells them apart.
#[tokio::test]
async fn starve_video_while_audio_flows_from_config_alone() {
    common::init_crypto();

    // ── the configuration, and nothing else ────────────────────────────
    let profile = ShapeProfile::try_new(
        vec![
            named_bucket("audio-bucket", None, 0),
            // The starvation, in one field.
            named_bucket("video-bucket", Some(0), 0),
        ],
        vec![
            alias_class(AUDIO_CLASS, AUDIO_ALIAS, "audio-bucket", 0, 1),
            alias_class(VIDEO_CLASS, VIDEO_ALIAS, "video-bucket", 0, 1),
        ],
        // `max_hold` pinned, never inherited — the reason is in the
        // rustdoc above.
        paced_queue(STARVED_HOLD, Expiry::Deliver),
        // `Fifo` arbitrates nothing. A discipline that did would make this
        // a test of the discipline; the strict-priority and
        // weighted-round-robin rows are those.
        Discipline::Fifo,
    )
    .expect("two uniquely-named classes over two configured buckets");

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let mut config = shaping_config(relay.addr);
    config.shape = Some(profile);

    // `Interest::NONE` and an observer that wants nothing: no user code is
    // in a position to decide any of what follows.
    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    // Video is offered **first**, so "audio flowed" cannot be a restatement
    // of the arrival order.
    let video = subgroup_stream(VIDEO_ALIAS, ACCEPTANCE_OBJECTS, PACED_PAYLOAD);
    let audio = subgroup_stream(AUDIO_ALIAS, ACCEPTANCE_OBJECTS, PACED_PAYLOAD);

    // Both source streams stay open for the rest of the test. Dropping a
    // `quinn::SendStream` finishes it, and a FIN starts the drain — which
    // routes around the pacer, so a finished video source would deliver
    // exactly the bytes this row asserts are absent.
    let mut video_send = client.open_uni().await.expect("open_uni video");
    video_send.write_all(&video).await.expect("write video");
    let mut audio_send = client.open_uni().await.expect("open_uni audio");
    audio_send.write_all(&audio).await.expect("write audio");

    let accepted = tokio::time::timeout(
        common::TIMEOUT,
        relay.timed_uni_by_alias(&[AUDIO_ALIAS, VIDEO_ALIAS], DRAFT),
    )
    .await
    .expect("both destination streams were opened and their headers forwarded");
    let mut accepted = accepted.into_iter();
    let audio_rx = accepted.next().expect("audio receiver");
    let video_rx = accepted.next().expect("video receiver");

    // (2) — and the anchor for (1) and (3). The unstarved class's stream is
    // whole, so the pipe has run end to end and anything the starved class
    // was going to deliver on its own account, it has.
    assert_eq!(
        audio_rx.wait_for_bytes(audio.len()).await,
        audio,
        "the flowing class must not pay for the starved one: the audio \
         destination stream must be byte-equal to its source"
    );

    // (1) The wire.
    let on_the_wire = video_rx.len();
    assert_eq!(
        on_the_wire,
        header_len(),
        "a dry bucket must deliver no media at all: the video destination \
         holds {on_the_wire} bytes against a {}-byte header",
        header_len()
    );

    // (3) The report. One snapshot, so the two rows below cannot be read at
    // two different instants.
    let shape = proxy.shape_stats();
    let video_row = named_row(&shape, VIDEO_CLASS);
    let audio_row = named_row(&shape, AUDIO_CLASS);

    assert_eq!(
        video_row.bytes_delivered, 0,
        "the report must name the starved class and say it got nothing: \
         {video_row:?}"
    );
    assert!(
        video_row.tokens_exhausted_episodes > 0,
        "...and say *why* it got nothing: a dry bucket is an episode, not a \
         silence. Without this a zero is indistinguishable from a class that \
         was never offered anything: {video_row:?}"
    );
    assert_eq!(
        audio_row.bytes_delivered,
        (audio.len() - header_len()) as u64,
        "and must account every object byte the flowing class carried — the \
         whole stream less its unshapeable header: {audio_row:?}"
    );
    assert_eq!(
        audio_row.objects_delivered, ACCEPTANCE_OBJECTS,
        "as objects as well as bytes, so one oversized release cannot satisfy \
         the byte total on its own: {audio_row:?}"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── the source is observed however full the queue is ───────────────────
//
// One fixture, two rows, and they are opposites on purpose. A shaped stream
// whose queue is full has to do two contradictory-looking things at once:
// refuse to *read* its source (that is what `Overflow::Block` is) while
// still *observing* it (or a peer's `RESET_STREAM` is invisible for as long
// as the block lasts). Either half alone is trivially satisfiable by
// deleting the other — always read, and the mirror is prompt because
// backpressure is gone; never look, and backpressure is perfect because the
// stream is dead. Neither row is worth anything without the other, so they
// share [`blocked_run`] and differ only in what they do once the queue is
// full.

/// The application error code the source peer resets its stream with.
///
/// Non-zero and distinctive: `0x0` is what a *synthesized* reset carries
/// (`synthesized_reset_code`), so a mirror that lost the peer's code and one
/// that never had it would be indistinguishable at zero.
const PEER_RESET_CODE: u64 = 0x2A;

/// Objects [`blocked_run`] offers on its one stream.
///
/// Three times [`ADMIT_DEPTH`], for the reason [`ADMIT_OFFERED`] gives:
/// the surplus has to be a majority of the stream, not a rounding error, or
/// a queue that admitted everything and one that admitted its depth look
/// alike. At [`ADMIT_PAYLOAD`] the whole stream is ~108 KB, comfortably
/// inside quinn's 1.25 MB default stream receive window, so the client's
/// `write_all` returns and the fixture is not itself waiting on the
/// backpressure it is about to measure.
const BLOCKED_OFFERED: u64 = 12;

/// The `max_hold` [`blocked_run`] pins, and the only number in either row
/// that a clock can reach.
///
/// **30 s is the shipped default posture verbatim**: `QueueConfig::default()`
/// leaves `max_hold: None`, which inherits `EgressConfig::max_hold`'s 30 s.
/// It is written here as a *ceiling these fixtures must never touch*, not as
/// a wait. With the queue held at its depth by a dry bucket, the clamp is
/// the only thing that can reopen the drain and therefore the only thing
/// that can reopen the read — so a mirrored reset that has to wait for the
/// read arrives at 30 s, and one that does not arrives in microseconds.
/// Those two answers are 20× apart from [`BLOCKED_MIRROR_WINDOW`] in
/// opposite directions, which is the separation the load-independence rules
/// at the top of this file ask for.
///
/// Shrinking this towards the window is what would break the gate: at
/// `max_hold == BLOCKED_MIRROR_WINDOW` the defect passes by waiting.
const BLOCKED_HOLD: Duration = Duration::from_secs(30);

/// How long [`a_peer_reset_is_mirrored_while_the_queue_is_blocked`] gives
/// the mirror before it reports the claim it was waiting on.
///
/// A failure ceiling, not a deadline, and the run never spends it: measured
/// arrival is sub-millisecond under both overflow policies. Safe to widen
/// anywhere well below [`BLOCKED_HOLD`]; see that constant for the factor.
const BLOCKED_MIRROR_WINDOW: Duration = Duration::from_millis(1_500);

/// A profile whose one catch-all class is charged to a **dry** bucket, with
/// a per-stream depth of [`ADMIT_DEPTH`] objects under `overflow`.
///
/// The dry bucket is the whole difference from [`admission_profile`]. There
/// the drain is shut by a hook's `Hold` and the test reopens it by releasing
/// a gate it owns; here it is shut by `rate_bps: Some(0)` and **nothing the
/// test can do reopens it** short of [`BLOCKED_HOLD`]. That is the shipped
/// default configuration — `Overflow::Block` (the `QueueConfig` default)
/// plus a
/// bucket that never grants — and it is the state in which the source's read
/// branch stays shut indefinitely.
fn dry_bucket_profile(overflow: Overflow) -> ShapeProfile {
    let mut class = ClassRule::default();
    class.name = ADMIT_CLASS.to_string();
    class.bucket = ADMIT_BUCKET.to_string();
    class.matcher = Matcher::default();

    let mut queue = QueueConfig::default();
    queue.depth_objects = ADMIT_DEPTH;
    queue.max_hold = Some(BLOCKED_HOLD);
    queue.overflow = overflow;

    ShapeProfile::try_new(
        vec![named_bucket(ADMIT_BUCKET, Some(0), 0)],
        vec![class],
        queue,
        Discipline::Fifo,
    )
    .expect("one catch-all class over the one bucket it names")
}

/// One dry-bucket fixture, spun up and driven to the point where the queue
/// is at its depth and the drain cannot reopen.
struct BlockedRun {
    proxy: SpawnedProxy,
    client: quinn::Connection,
    _client_ep: quinn::Endpoint,
    /// The client's source stream, kept open so the fixture — not a drop —
    /// decides how it ends.
    send: quinn::SendStream,
    /// The destination stream as the relay sees it.
    rx: common::TimedReceiver,
    /// Every byte offered, for the prefix claim.
    stream: Vec<u8>,
    overflow: Overflow,
}

impl BlockedRun {
    fn shape(&self) -> ShapeStats {
        self.proxy.shape_stats()
    }

    /// This run's one configured class row.
    fn class(&self) -> ClassStats {
        self.shape().classes[0].clone()
    }

    /// Wait until the queue is full — which is the *precondition* of both
    /// rows, not an assertion of either.
    ///
    /// Each policy is waited on through the counter it is defined by, so
    /// neither leg is inferring the state from a proxy for it:
    ///
    /// - `Block` — `blocked_episodes`, incremented by `pipe_data_framed` on
    ///   exactly the `can_read == false` edge. It going above zero *is* the
    ///   read branch being shut.
    /// - `DropTail` — `objects_dropped`, which cannot move until admission
    ///   has seen a full queue. `DropTail` installs no blocking depth, so
    ///   `blocked_episodes` stays zero there by design and would be a wait
    ///   that never ends.
    ///
    /// Both are monotone, so this is a liveness anchor: load makes it
    /// slower, never wrong.
    async fn wait_until_the_queue_is_full(&self) {
        match self.overflow {
            Overflow::Block => {
                wait_until(
                    || self.class().blocked_episodes > 0,
                    "the read branch to shut on a full queue",
                )
                .await
            }
            _ => {
                wait_until(
                    || self.class().objects_dropped > 0,
                    "the queue to reach its depth and start discarding",
                )
                .await
            }
        }
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

/// Spawn a dry-bucket session under `overflow`, offer [`BLOCKED_OFFERED`]
/// objects on one stream, and hand back everything either row asserts on.
///
/// The posture is the shipped default: `Interest::NONE` and an observer that
/// wants nothing, so nothing below is a hook's idea of what should happen.
/// [`ADMIT_PAYLOAD`]'s rustdoc is binding here for the same reason it is
/// binding for [`admission_run`] — an object smaller than the pipe's 8 KiB
/// read buffer lets one read carry two of them and the depth bound stops
/// being able to see an off-by-one.
async fn blocked_run(overflow: Overflow) -> BlockedRun {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let mut config = shaping_config(relay.addr);
    config.shape = Some(dry_bucket_profile(overflow));

    let proxy = common::spawn_proxy_with(
        config,
        ALPN,
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    );
    let (client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let stream = subgroup_stream(LEAD_ALIAS, BLOCKED_OFFERED, ADMIT_PAYLOAD);
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write the whole stream");

    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the destination stream was opened and its header forwarded");

    BlockedRun { proxy, client, _client_ep: client_ep, send, rx, stream, overflow }
}

/// **A peer's `RESET_STREAM` is mirrored while the queue is blocked.**
///
/// The failure mode, exactly, and the ablation below reproduces it: let the
/// read branch be the only observer of the source. `pipe_data_framed`
/// computes `let can_read = pending.accepts_more()` and spends it as that
/// branch's precondition, `result = recv.read(&mut buf), if can_read`, and a
/// peer reset surfaces **only** as `Err` from that `recv.read` — so with the
/// branch shut the reset goes unobserved and `propagate_reset` is
/// unreachable. Under `Overflow::Block` — the `QueueConfig` default — a dry
/// bucket holds the queue at its depth until `max_hold`, so that posture
/// delays a mirrored reset by up to **30 s**: measured at
/// `QueueConfig::default()`, 29.80 s. Nothing else in the `select!` covers
/// it: `StopWatcher` watches the *destination's* `stopped()`, the release
/// branch watches this proxy's own clock, and `cancel` is session teardown.
///
/// # What is asserted, and what deliberately is not
///
/// **Not a duration.** The claim is the *presence* of the mirror, its code,
/// and the *order* it stands in relative to the bytes that preceded it. The
/// only clock in the body is [`BLOCKED_MIRROR_WINDOW`], and it is a failure
/// ceiling — the thing that turns "hangs for the harness's 10 s" into a
/// sentence naming what was awaited. What makes that ceiling
/// load-independent is [`BLOCKED_HOLD`]: a read-only observer cannot answer
/// inside 30 s, the reset observer answers in microseconds, and the ceiling
/// sits 20× from one and 20 000× from the other.
///
/// **Both overflow policies, one body.** `DropTail` installs no blocking
/// depth, so its read branch never shuts and it mirrors the reset whether
/// or not the reset observer is there — it is the control, and it is in the
/// same body so the claim is *"the queue policy does not get to decide
/// whether a peer reset is mirrored"* rather than two separate claims about
/// two fixtures that might have drifted apart. The rows are also ordered
/// `Block` first, so a failure reports the interesting leg.
///
/// **The order is asserted as a prefix, not as a byte count.** The fixture
/// waits for the destination stream's header to arrive *before* resetting
/// the source, so "at least the header, then the reset" holds by
/// construction and load can only add bytes to the front. It cannot assert
/// an exact count, and that is a transport fact rather than slack:
/// `propagate_reset` drains the queue ignoring release times and *then*
/// calls `send.reset(code)`, and quinn's `reset()` discards whatever of that
/// drain is still buffered locally. So the delivered prefix is legitimately
/// anywhere from the header to the whole queue, and a prefix claim is the
/// strongest true statement about it.
///
/// *Ablation, recorded:* restore the defect by deleting the
/// `received_reset()` observer — make `observe_source`'s `!can_read` path
/// `std::future::pending().await` unconditionally. Run: **29 passed, 1
/// failed, 0 ignored, 0 filtered out**. The `DropTail` leg stays green,
/// [`a_blocked_reader_still_refuses_to_read`] stays green (it is the other
/// half and this ablation does not touch it), and the `Block` leg reddens:
///
/// ```text
/// thread 'a_peer_reset_is_mirrored_while_the_queue_is_blocked' panicked at
/// crates\moqtap-proxy\tests\actions_shaping.rs:
/// a peer reset must be mirrored whatever the queue is doing, and under Block
/// it was not: nothing ended the destination stream within 1.5s, against a
/// 30s max_hold
/// ```
#[tokio::test]
async fn a_peer_reset_is_mirrored_while_the_queue_is_blocked() {
    for overflow in [Overflow::Block, Overflow::DropTail] {
        let mut run = blocked_run(overflow).await;

        // Liveness, and what makes the prefix claim below true by
        // construction rather than by timing.
        assert_eq!(
            run.rx.wait_for_bytes(header_len()).await.len(),
            header_len(),
            "{overflow:?}: the destination stream must carry its header before the \
             source is reset, or 'data, then reset' is a claim about nothing"
        );
        run.wait_until_the_queue_is_full().await;

        run.send
            .reset(quinn::VarInt::from_u64(PEER_RESET_CODE).expect("reset code"))
            .expect("the client resets its source stream");

        let ending = tokio::time::timeout(BLOCKED_MIRROR_WINDOW, run.rx.wait_for_ending())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "a peer reset must be mirrored whatever the queue is doing, and under \
                     {overflow:?} it was not: nothing ended the destination stream within \
                     {BLOCKED_MIRROR_WINDOW:?}, against a {BLOCKED_HOLD:?} max_hold"
                )
            });

        assert_eq!(
            ending,
            Ending::Reset(PEER_RESET_CODE),
            "{overflow:?}: the destination must end with the peer's own code, not a FIN \
             and not a synthesized code"
        );

        let delivered = run.rx.bytes();
        assert!(
            delivered.len() >= header_len(),
            "{overflow:?}: data, then reset — the header had already arrived, so the \
             mirror cannot have unsent it: {} bytes",
            delivered.len()
        );
        assert!(
            run.stream.starts_with(&delivered),
            "{overflow:?}: everything delivered before the mirror must be a prefix of \
             the source stream, in order: {} bytes delivered",
            delivered.len()
        );

        run.finish().await;
    }
}

/// **A blocked reader still refuses to read** — the other half of the pair.
///
/// [`a_peer_reset_is_mirrored_while_the_queue_is_blocked`] is satisfiable by
/// deleting `Overflow::Block` — poll `recv.read` unconditionally and every
/// reset is prompt because there is no longer any state in which the source
/// goes unread. This is the row that forbids that, and the two are only
/// meaningful together.
///
/// # Why the count, and why it is the peer's backpressure
///
/// The count is the mechanism, not a proxy for it. QUIC re-advertises
/// `MAX_STREAM_DATA` as the application *consumes* its receive buffer, so
/// "the shaper saw `n` objects" is the same statement as "`n` objects' worth
/// of credit was granted". A blocked stream parks on
/// `RecvStream::received_reset`, which reads no bytes and therefore grants
/// no credit — so the bound below is the bound a stream parked on nothing
/// sits under, and that is the point of asserting it: watching for a reset
/// does not move it.
///
/// `objects_seen` rather than a hook's call count, deliberately.
/// `note_object_seen` runs before admission, before the hook and before any
/// policy decides anything, so it counts what came off the wire and nothing
/// downstream can flatter it. It also lets this row keep [`blocked_run`]'s
/// `Interest::NONE` posture, so what it measures is the shipped default and
/// not a hook's.
///
/// The bound is `ADMIT_DEPTH` exactly rather than `depth_objects + 1`,
/// for the arithmetic reason [`ADMIT_PAYLOAD`] records: at a wire size above
/// the pipe's 8 KiB read buffer one read carries at most one object, so the
/// overshoot is zero. It is one-sided — load can only push the count down.
///
/// The second assertion is what makes the first mean "blocked" rather than
/// "drained promptly": a dry bucket delivers the unshapeable header and not
/// one object byte, so the queue that filled is still full.
///
/// *Ablation, recorded:* the naive fix — make `observe_source` call
/// `recv.read` unconditionally, ignoring `can_read`. Run: **27 passed, 3
/// failed, 0 ignored, 0 filtered out**;
/// [`a_peer_reset_is_mirrored_while_the_queue_is_blocked`] stays green,
/// which is exactly the point — it cannot tell a fix from a deletion. The
/// other two casualties are [`block_loses_nothing_and_stalls_the_reader`]
/// ("the hook was shown 12 objects against a depth of 4") and
/// [`block_admits_at_most_depth_objects`] ("Block admits depth_objects units
/// and no more: 12 > 4"), so the deletion is caught three times over:
///
/// ```text
/// thread 'a_blocked_reader_still_refuses_to_read' panicked at
/// crates\moqtap-proxy\tests\actions_shaping.rs:
/// a reset observer must not read the source: with the drain shut by a dry
/// bucket the shaper may see at most the 4 objects the queue has room for,
/// and it saw 12 of 12 offered
/// ```
#[tokio::test]
async fn a_blocked_reader_still_refuses_to_read() {
    let run = blocked_run(Overflow::Block).await;

    // The state itself: `blocked_episodes` moves on exactly the
    // `can_read == false` edge.
    run.wait_until_the_queue_is_full().await;
    // "However long you wait" — bounding a count from above, so load can
    // only push it down.
    tokio::time::sleep(SETTLE).await;

    let seen = run.shape().objects_seen;
    assert!(
        seen <= ADMIT_DEPTH as u64,
        "a reset observer must not read the source: with the drain shut by a dry \
         bucket the shaper may see at most the {ADMIT_DEPTH} objects the queue has \
         room for, and it saw {seen} of {BLOCKED_OFFERED} offered"
    );
    assert_eq!(
        run.rx.len(),
        header_len(),
        "...and the drain really was shut for all of it: a dry bucket forwards the \
         unshapeable header and no object byte at all"
    );
    assert_eq!(
        run.class().objects_dropped,
        0,
        "Block is non-destructive: it stops reading, it never discards"
    );

    run.finish().await;
}

// ── two silent ways to miss a configured rate ──────────────────────────
//
// Both rows below are about a rate that is written down and then not
// applied, and neither shows on the wire: it looks exactly like a class that
// is genuinely being held back, and the only signals — one `HoldClamped` per
// unit and a rising `tokens_exhausted_episodes` — are the ones a *working*
// rate limit produces. So each row drives the fault **and** the innocent case
// it is otherwise indistinguishable from, in one body, and asserts the
// difference rather than the presence of a report.

/// Every `ShapeBurstBelowUnit` a run reported, as `(class, burst, unit)`.
fn burst_reports(run: &PacedRun) -> Vec<(String, u64, u64)> {
    run.observer
        .impairments()
        .into_iter()
        .filter_map(|k| match k {
            ImpairmentKind::ShapeBurstBelowUnit { class, burst_bytes, unit_bytes } => {
                Some((class, burst_bytes, unit_bytes))
            }
            _ => None,
        })
        .collect()
}

/// A rate an author writes down and means: 1 MB/s.
const BURST_RATE: u64 = 1_000_000;
/// A burst below one object — what a `BucketConfig` left at or near its
/// default gives. The rate above can never be applied through it.
const TINY_BURST: u64 = 100;
/// A rate low enough that the second object's refill instant lands beyond
/// [`BURST_HOLD`], so the innocent leg clamps too and the two legs really do
/// produce the same `HoldClamped` stream.
const SLOW_RATE: u64 = 500;
/// Objects per stream in the burst fixture.
const BURST_OBJECTS: u64 = 4;
/// The clamp both legs of the burst row are released by.
///
/// Short, because every unit of both legs is expected to reach it and the
/// gate has a budget. Nothing is compared against it — it is the fixture's
/// stated ceiling, and the row asserts counts and equalities only.
const BURST_HOLD: Duration = Duration::from_millis(150);

/// **A burst smaller than one object is reported as itself, not as a rate
/// limit.**
///
/// A token bucket can never grant a unit larger than the whole bucket, so a
/// `burst_bytes` below one object means the configured `rate_bps` never
/// binds at all: every unit is refused, waits out `max_hold` and leaves at
/// the clamp, and the throughput that results is `queue depth / max_hold` —
/// a figure the configuration never mentions. Measured here at 1 MB/s with a
/// 100-byte burst: every object left at exactly the clamp.
///
/// It cannot be rejected when the profile is built. `ShapeProfile::try_new`
/// has the burst and not the object sizes, and it is the comparison of the
/// two that decides, so the answer only exists once traffic is running.
///
/// # Why both legs are in one body
///
/// The defect is an *indistinguishability*, and one leg cannot state one.
/// Leg (a) is the mis-sized burst. Leg (b) is a class that is genuinely
/// rate-limited — a real rate, a burst that does hold an object, and a
/// refill interval past the clamp — chosen so the two legs agree on
/// everything that was observable before: both deliver the whole stream,
/// both clamp, both charge `tokens_exhausted_episodes`. The report is the
/// only difference, which is the claim.
///
/// The shared signals are asserted **positive on both legs**, not merely
/// absent on one. An implementation that emitted nothing anywhere satisfies
/// a forbidding assertion; what rules it out is that both legs are shown to
/// have reached the state being reported on.
///
/// The report is asserted as a whole tuple under an equality — class name
/// and both figures — and the object's size is derived from the fixture's
/// own wire bytes rather than written down. A report naming the class but
/// quoting the wrong burst is unactionable, and one quoting a payload length
/// where a wire length belongs sends its reader looking for an object that
/// does not exist.
///
/// # What this row does **not** gate, stated rather than implied
///
/// The report's once-per-session-per-class deduplication. Measured: with the
/// dedup removed — `Scheduler::claim_burst_report` always answering `Some` —
/// this row stays green, because the whole stream is queued in one write and
/// so every unit behind the head is already past its clamp by the time the
/// head clears. Only the head is ever put to a bucket, so only one refusal
/// happens whatever the dedup does. `shape::scheduler`'s
/// `a_burst_below_one_unit_is_separable_from_a_stopped_or_a_slow_class` is
/// where the second call is asserted to answer `None`, and it reddens with
/// `left: Some("v") / right: None` under exactly that ablation.
///
/// *Ablation, recorded:* fold the two unreachable answers back together in
/// `shape::charge` — `if rate == 0 || need > cap { Grant::Never }`, which is
/// the behaviour this row closes. Leg (a)'s equality reddens with
/// `left: []` against `right: [("video", 100, 203)]`, and every other
/// assertion in the body stays green, so the failure is attributable to the
/// report and not to the fixture. Three unit rows go with it —
/// `shape::bucket`'s `a_unit_larger_than_the_burst_is_refused_as_a_burst_problem`,
/// `shape::scheduler`'s
/// `a_burst_below_one_unit_is_separable_from_a_stopped_or_a_slow_class`, and
/// `egress`'s `an_unbounded_shaping_wait_reports_no_request_at_all` — so the
/// collapse is caught four times over, at every layer it passes through.
#[tokio::test]
async fn a_burst_smaller_than_one_object_is_reported_distinctly() {
    let offered = subgroup_stream(LEAD_ALIAS, BURST_OBJECTS, PACED_PAYLOAD);
    let object_bytes = (offered.len() - header_len()) as u64;
    assert_eq!(
        object_bytes % BURST_OBJECTS,
        0,
        "the fixture's objects are the same size on the wire, so one object's wire \
         length below is exact and not an average"
    );
    let unit = object_bytes / BURST_OBJECTS;
    assert!(
        unit > TINY_BURST && unit <= PACED_BURST,
        "the fixture only means anything if one object is above leg (a)'s burst and \
         inside leg (b)'s: {unit} bytes against {TINY_BURST} and {PACED_BURST}"
    );

    // (a) The fault: a rate that was asked for, through a bucket that can
    // never hold one object's worth of tokens.
    let mis_sized = paced_run(
        one_class_profile(Some(BURST_RATE), TINY_BURST, BURST_HOLD, Expiry::Deliver),
        BURST_OBJECTS,
    )
    .await;
    assert_eq!(
        mis_sized.rx.wait_for_bytes(offered.len()).await,
        offered,
        "leg (a) still delivers every byte — at the clamp, which is the whole \
         reason the fault is quiet"
    );

    // (b) The innocent case it was indistinguishable from.
    let slow = paced_run(
        one_class_profile(Some(SLOW_RATE), PACED_BURST, BURST_HOLD, Expiry::Deliver),
        BURST_OBJECTS,
    )
    .await;
    assert_eq!(slow.rx.wait_for_bytes(offered.len()).await, offered, "and so does leg (b)");

    assert_eq!(
        burst_reports(&mis_sized),
        vec![(VIDEO_CLASS.to_string(), TINY_BURST, unit)],
        "a burst below one object means the configured rate is never applied: name \
         the class, quote both numbers, once per session"
    );
    assert_eq!(
        burst_reports(&slow),
        vec![],
        "a class whose burst holds an object is a rate limit doing its job, and \
         reporting it would turn the report into noise"
    );

    // What the two legs agree on — which is why the difference above had to
    // be manufactured at all. From outside, these are the same run.
    assert!(
        !mis_sized.clamps().is_empty() && !slow.clamps().is_empty(),
        "both legs must actually reach the clamp, or the report above is the only \
         thing either of them did: {} and {}",
        mis_sized.clamps().len(),
        slow.clamps().len()
    );
    assert!(
        mis_sized.class(VIDEO_CLASS).tokens_exhausted_episodes > 0
            && slow.class(VIDEO_CLASS).tokens_exhausted_episodes > 0,
        "...and both charge the same starvation counter, which is exactly why that \
         counter cannot be the thing an author reads"
    );

    mis_sized.finish().await;
    slow.finish().await;
}

/// The payload of the object the framer cannot measure.
///
/// Past `FramerConfig::max_buffered_object_bytes`, so the framer streams it
/// through instead of buffering it whole and no `ObjectMeta` ever exists for
/// it. Read from the config rather than written down, so a change to that
/// default cannot leave this fixture quietly measuring an ordinary object.
fn oversized_payload() -> usize {
    FramerConfig::default().max_buffered_object_bytes + 1024
}

/// A subgroup stream carrying one ordinary object and then one past the
/// framer's measuring reach.
///
/// The ordinary object comes **first**, and that is the fixture rather than
/// an arrangement: classification is what gives a stream a class, so a
/// stream whose very first unit is unmeasurable has no class for a report to
/// name. One object establishes it, and being small it is paced by the
/// bucket — which makes the second object's escape a contrast inside a
/// single stream rather than a claim about two.
fn stream_with_an_oversized_object() -> Vec<u8> {
    let head = subgroup_header_bytes(DRAFT, LEAD_ALIAS);
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut out = head;
    for (object_id, payload_len) in [(0u64, PACED_PAYLOAD), (1u64, oversized_payload())] {
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![0xA5; payload_len],
        };
        writer.write_object(&obj, &mut out).expect("write object");
    }
    out
}

/// Every `ShapeUnpacedObject` a run reported, as `(class, stream_id, bytes)`.
fn unpaced_reports(run: &PacedRun) -> Vec<(String, u64, u64)> {
    run.observer
        .impairments()
        .into_iter()
        .filter_map(|k| match k {
            ImpairmentKind::ShapeUnpacedObject { class, stream_id, bytes } => {
                Some((class, stream_id, bytes))
            }
            _ => None,
        })
        .collect()
}

/// Every `ObjectNotAddressable`'s stream id.
fn unaddressable_streams(run: &PacedRun) -> Vec<u64> {
    run.observer
        .impairments()
        .into_iter()
        .filter_map(|k| match k {
            ImpairmentKind::ObjectNotAddressable { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect()
}

/// **An object past the framer's measuring reach names the class whose rate
/// it escaped.**
///
/// Shaping is per unit, and a unit is classified from its `ObjectMeta`. An
/// object too large for the framer to buffer has none — the framer streams
/// it through rather than measuring it — so no rule claims it, no bucket
/// charges it, and the release seam grants it unconditionally. One object
/// therefore crosses a configured rate whole. Measured here against a class
/// holding a bucket configured at **zero bytes per second**, which is the
/// strongest possible statement of the breach: the bucket that should let
/// nothing through lets a whole 4 MiB object through, in around 800 ms.
///
/// # What is asserted, and why the report alone would not do
///
/// The breach is asserted as well as the report, because a report on its own
/// is satisfied by an implementation that has started *charging* the object
/// and reports anyway. The pair of exact counts is the fault stated
/// arithmetically: the class row shows **one** object delivered — the small
/// one, the only one a bucket ever saw — while the whole stream, oversized
/// object included, reaches the relay.
///
/// The reported class is asserted **equal to the configured name**, not
/// merely present; and the reported stream id equal to the one
/// `ObjectNotAddressable` carries for the same object, so an implementation
/// reporting a fixed class, or correlating against the wrong stream, fails
/// an equality rather than passing a `contains`.
///
/// The byte figure is bounded below by the framer's own reach rather than by
/// zero. The chunk that triggers the report is the framer's buffer at the
/// moment it gave up measuring, so it is at least the cap; how far above
/// depends on read sizes this test does not control. One-sided, in the
/// direction load cannot push.
///
/// The **control leg** is the same profile and the same class carrying
/// ordinary objects only. Without it a report emitted for every stream would
/// pass everything above, so the assertion that this run says *nothing*
/// carries as much of the row as the equality does.
///
/// *Ablation, recorded:* report a fixed class — `class: String::new()`, the
/// label the unnamed rows carry — and the equality reddens with
/// `left: "" / right: "video"`.
///
/// *Second ablation, recorded:* delete the report and leave
/// `ObjectNotAddressable` alone, which is the behaviour this row closes.
/// `reports.len()` reddens with `left: 0 / right: 1`, and every assertion
/// above it stays green — the breach itself is unchanged, which is the point:
/// nothing about the wire said whose rate had gone.
#[tokio::test]
async fn an_oversized_object_names_the_class_whose_rate_it_escaped() {
    let offered = stream_with_an_oversized_object();
    // A zero-rate bucket: nothing this class owns may be granted from
    // tokens, so every byte of the oversized object that arrives is a byte
    // that went round the bucket rather than through it.
    let run =
        paced_run_of(one_class_profile(Some(0), 0, BURST_HOLD, Expiry::Deliver), offered.clone())
            .await;

    assert_eq!(
        run.rx.wait_for_bytes(offered.len()).await,
        offered,
        "an object the framer cannot measure crosses a bucket configured at zero \
         bytes per second whole"
    );

    // The breach, arithmetically: one object was paced and one was not.
    assert_eq!(
        run.class(VIDEO_CLASS).objects_delivered,
        1,
        "only the measurable object ever reached a bucket; the oversized one is on \
         no class row at all, which is the hole this report exists to name"
    );
    assert!(
        run.shape().unshapeable.bytes_delivered >= oversized_payload() as u64,
        "the escaped bytes are accounted as unshapeable, and it is a whole object's \
         worth of them: {}",
        run.shape().unshapeable.bytes_delivered
    );

    // The report, and what it names.
    let reports = unpaced_reports(&run);
    let unaddressable = unaddressable_streams(&run);
    assert_eq!(unaddressable.len(), 1, "one oversized object, one framer report");
    assert_eq!(
        reports.len(),
        1,
        "once per stream, whatever the object was chunked into: {reports:?}"
    );
    let (class, stream_id, bytes) = reports[0].clone();
    assert_eq!(
        class, VIDEO_CLASS,
        "the report must name the class whose rate went, not merely that one did"
    );
    assert_eq!(
        stream_id, unaddressable[0],
        "and it must name the stream the framer gave up measuring on, so the two \
         reports about one object correlate"
    );
    assert!(
        bytes >= FramerConfig::default().max_buffered_object_bytes as u64,
        "the chunk that escaped is at least the framer's whole buffer: {bytes}"
    );
    run.finish().await;

    // The control: same profile, same class, objects the framer can measure.
    // A report emitted per stream would pass every assertion above and fail
    // this one.
    let ordinary =
        paced_run(one_class_profile(Some(0), 0, BURST_HOLD, Expiry::Deliver), BURST_OBJECTS).await;
    ordinary
        .rx
        .wait_for_bytes(subgroup_stream(LEAD_ALIAS, BURST_OBJECTS, PACED_PAYLOAD).len())
        .await;
    assert_eq!(
        unpaced_reports(&ordinary),
        vec![],
        "every object here was measured, classified and charged, so nothing escaped \
         and there is nothing to report"
    );
    ordinary.finish().await;
}

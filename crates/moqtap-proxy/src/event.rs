//! Proxy event types emitted by the inline parser.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnyObjectHeader, AnySubgroupHeader,
};
use moqtap_codec::version::DraftVersion;

use crate::capability::{ActionKind, Refusal, Site};
use crate::shape::StreamKey;
use crate::types::{Leg, ObjectMeta};

pub use crate::types::ProxySide;

/// Unique session identifier (monotonic counter assigned by the proxy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// The kind of data stream header parsed from a unidirectional stream.
#[derive(Debug, Clone)]
pub enum DataStreamHeaderKind {
    /// Subgroup stream header.
    Subgroup(AnySubgroupHeader),
    /// Fetch response stream header.
    Fetch(AnyFetchHeader),
}

/// Events emitted by the proxy during stream forwarding.
///
/// Marked `#[non_exhaustive]`: observers must carry a catch-all arm, so
/// that adding an event is not a breaking change.
///
/// # Asserting on events — destructure, do not compare
///
/// `ProxyEvent` derives **`Debug` and `Clone` only**. It carries decoded
/// codec types ([`AnyControlMessage`], [`AnyDatagramHeader`], …) that do
/// not implement `PartialEq`, so there is no `assert_eq!(event,
/// ProxyEvent::Something { .. })` to write and there will not be one:
/// deriving `PartialEq` here would require it on every draft's message
/// enum.
///
/// Every assertion in this workspace therefore has the same two-step
/// shape — **count with `matches!`, then destructure and compare the
/// payload**:
///
/// ```
/// use moqtap_proxy::event::{Effect, ProxyEvent};
///
/// fn exactly_one_replacement(events: &[ProxyEvent]) {
///     // 1. count the variant with `matches!`
///     let applied: Vec<&ProxyEvent> = events
///         .iter()
///         .filter(|e| matches!(e, ProxyEvent::ActionApplied { .. }))
///         .collect();
///     assert_eq!(applied.len(), 1);
///
///     // 2. destructure, then compare the payload with `assert_eq!`
///     let ProxyEvent::ActionApplied { effect, .. } = applied[0] else {
///         unreachable!("filtered above")
///     };
///     assert_eq!(*effect, Effect::Replaced { bytes: 4 });
/// }
/// # let _ = exactly_one_replacement;
/// ```
///
/// Step 2 works because the *payload* types added in 0.4.0 — [`Effect`],
/// [`ImpairmentKind`], [`Refusal`], [`Site`] and [`ActionKind`] — do
/// derive `PartialEq` and `Eq`. The boundary is exactly at the event: the
/// event is destructured, what comes out of it is compared.
///
/// `ProxyEvent` and every one of those payload enums is
/// `#[non_exhaustive]`, so a `match` over any of them from outside this
/// crate needs a catch-all arm; `matches!` supplies one for free, which
/// is the other reason it is the recommended spelling.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProxyEvent {
    /// A new client connected and a session was created.
    SessionStarted {
        /// The session identifier.
        session_id: SessionId,
        /// The client's remote address.
        client_addr: SocketAddr,
        /// The transport the client chose via ALPN — e.g. `"QUIC"` or
        /// `"WebTransport"`. Observers use this to label per-client
        /// sessions; the proxy itself accepts either simultaneously.
        client_transport: String,
    },

    /// A setup message (CLIENT_SETUP or SERVER_SETUP) was observed.
    SetupMessage {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the message.
        side: ProxySide,
        /// The decoded setup message.
        message: AnyControlMessage,
    },

    /// A control message was parsed from the forwarded byte stream.
    ControlMessage {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the message.
        side: ProxySide,
        /// The decoded control message.
        message: AnyControlMessage,
    },

    /// A data stream header was parsed from a unidirectional stream.
    DataStreamHeader {
        /// The session identifier.
        session_id: SessionId,
        /// Which side opened the stream.
        side: ProxySide,
        /// The parsed header.
        header: DataStreamHeaderKind,
    },

    /// An object header was parsed on a data stream.
    ///
    /// Never emitted: `AnyObjectHeader` has no variants past draft-13, so
    /// this could only ever report objects on the oldest drafts, and even
    /// there it reported a header without consuming the payload behind it.
    /// [`ProxyEvent::Object`] replaces it and covers drafts 07-19.
    #[deprecated(since = "0.3.0", note = "superseded by ProxyEvent::Object")]
    ObjectHeader {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the object.
        side: ProxySide,
        /// The parsed object header.
        header: AnyObjectHeader,
    },

    /// A complete object was framed on a data stream.
    ///
    /// Emitted once per object, in stream order, on every draft 07-19.
    /// Objects the framer could not address individually — one larger than
    /// its buffer cap, or a stream it stopped parsing — produce no event;
    /// their bytes are still forwarded unchanged.
    Object {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the object.
        side: ProxySide,
        /// The object's identity and framing, without its payload.
        meta: ObjectMeta,
    },

    /// A datagram arrived and its header was parsed.
    ///
    /// An **observation of what came in**, emitted where the decode happens
    /// — before any hook is consulted and before the datagram is handed to
    /// the far transport. It is deliberately not a delivery receipt, and it
    /// once said "was forwarded", which was wrong in two directions at
    /// once: a hook that drops or replaces the datagram still produces this
    /// event, and the forward itself can be refused, which is reported
    /// separately as [`ImpairmentKind::DatagramNotSent`] or, when somebody
    /// acted on it, as [`ProxyEvent::ActionFailed`].
    ///
    /// It sits with [`ProxyEvent::Object`] and
    /// [`ProxyEvent::ControlMessage`] rather than with the action events:
    /// all three say a unit was seen and understood, and none of them says
    /// where it ended up. Withholding it until after the send would make an
    /// undecodable-or-dropped datagram invisible, which is exactly the case
    /// a scenario is usually watching for.
    ///
    /// Emitted only when an observer is attached — the decode is skipped
    /// entirely otherwise — and only when the header actually decoded. A
    /// datagram whose header this crate cannot read produces no event and is
    /// still forwarded.
    Datagram {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the datagram.
        side: ProxySide,
        /// The parsed datagram header.
        header: AnyDatagramHeader,
        /// Size of the datagram payload in bytes.
        payload_len: usize,
    },

    /// A bidirectional stream was opened or accepted.
    BiStreamOpened {
        /// The session identifier.
        session_id: SessionId,
        /// Which side opened the stream.
        side: ProxySide,
    },

    /// A unidirectional stream was opened or accepted.
    UniStreamOpened {
        /// The session identifier.
        session_id: SessionId,
        /// Which side opened the stream.
        side: ProxySide,
    },

    /// Inline parse failed (non-fatal — bytes are still forwarded).
    ParseError {
        /// The session identifier.
        session_id: SessionId,
        /// Which side the error occurred on.
        side: ProxySide,
        /// Description of the parse error.
        error: String,
    },

    /// A stream direction ended cleanly — the peer sent a FIN and every
    /// byte it wrote was forwarded.
    ///
    /// An abnormal end is reported as [`ProxyEvent::StreamReset`]
    /// instead, never as this event.
    StreamClosed {
        /// The session identifier.
        session_id: SessionId,
        /// Which side closed.
        side: ProxySide,
    },

    /// A peer tore a stream down abnormally — either `RESET_STREAM` from
    /// the sender or `STOP_SENDING` from the receiver.
    ///
    /// This reports the *observation*. The proxy mirrors the teardown
    /// onto the opposite stream with the same application error code;
    /// when that stream has already gone away the mirror is a no-op, and
    /// the event is still emitted so the teardown is never invisible.
    ///
    /// Distinct from [`ProxyEvent::StreamClosed`], which reports an
    /// orderly FIN. An observer that sees this knows the stream was
    /// abandoned and any data on it may be truncated.
    ///
    /// Not emitted for streams the proxy itself tears down at session
    /// shutdown — those still end with a FIN, as they did before this
    /// event existed.
    StreamReset {
        /// The session identifier.
        session_id: SessionId,
        /// The side the teardown was observed on. For a `RESET_STREAM`
        /// this is the ingress side the bytes were arriving on; for a
        /// `STOP_SENDING` it is the egress side they were leaving on.
        side: ProxySide,
        /// The peer's application error code, forwarded verbatim.
        code: u64,
    },

    /// The session ended.
    SessionEnded {
        /// The session identifier.
        session_id: SessionId,
        /// Reason for session termination.
        reason: String,
    },

    // ── 0.4.0: the action engine ───────────────────────────────────────
    /// An action was executed and the wire changed.
    ///
    /// Emitted once the engine has **admitted** the action and produced the
    /// bytes or the plan for it: every guard has run, every refusal has
    /// already been taken, and nothing between here and the wire can decline
    /// it on this proxy's behalf. `effect` is what was decided, down to the
    /// byte count.
    ///
    /// # It is not a delivery receipt, and one case makes that visible
    ///
    /// The engine decides; the forwarding task then hands the result to the
    /// transport. That transport can still say no — a replacement datagram
    /// above the path MTU is the case that exists — and when it does, this
    /// event has already been emitted and is followed by
    /// [`ProxyEvent::ActionFailed`] naming the same site and action. **Both
    /// events are emitted for that attempt**, in that order, and the pair is
    /// the whole truth: the action was admitted, and it did not reach the
    /// peer.
    ///
    /// Folding the two into one report was rejected twice over. Withholding
    /// this event until the write returned would mean an action that was
    /// admitted, queued behind a `Delay`, and lost at teardown reported
    /// nothing at all — and it is precisely the admitted-then-lost case that
    /// [`ImpairmentKind::QueuedBytesAtTeardown`] is paired against. Reporting
    /// only the failure would lose which action was taken, since a refusal
    /// and a rejection name different things.
    ///
    /// So the reading is: this event means *the engine did it*. An observer
    /// that needs *the peer got it* must also watch for `ActionFailed`, and
    /// for the impairments that report queued bytes.
    ///
    /// A proxy-initiated reset appears here, **not** as
    /// [`ProxyEvent::StreamReset`], which continues to mean an observed
    /// peer teardown.
    ///
    /// # Cardinality under `Delay` and `Hold`
    ///
    /// A deferred action emits **two** `ActionApplied` events, not one,
    /// and they are distinguishable by `action`:
    ///
    /// 1. at the decision, `{ action: Delay | Hold, effect: Queued {
    ///    release_at } }` — the modifier was accepted and the unit is in
    ///    the queue;
    /// 2. at the release, `{ action: <the inner kind>, effect: <what the
    ///    inner action did> }` — e.g. `{ action: Replace, effect:
    ///    Replaced { bytes } }`.
    ///
    /// One event would force a choice between reporting the delay and reporting
    /// the effect, and a queued unit that is later lost at teardown would have
    /// reported a `Replaced` that never happened. Two events keep *the engine
    /// accepted this* and "the wire changed" separately falsifiable, which is
    /// what [`ImpairmentKind::QueuedBytesAtTeardown`] is paired against.
    ///
    /// So the count to assert is *exactly one `ActionApplied` per
    /// (attempt, phase)*: one for a non-deferred action, two for a
    /// deferred one.
    ActionApplied {
        /// The session identifier.
        session_id: SessionId,
        /// The side the unit arrived on.
        side: ProxySide,
        /// The source stream, when there is one.
        stream_id: Option<u64>,
        /// Where the decision was taken.
        site: Site,
        /// What was executed.
        action: ActionKind,
        /// What actually happened.
        effect: Effect,
    },

    /// An action could not be executed. Emitted **per attempt**, and the
    /// unit is forwarded unchanged.
    ///
    /// The engine declined *before* anything reached the transport: the
    /// wire carries exactly what it would have carried with no hook at
    /// all. This is the pre-admission half of the two failure reports —
    /// [`ProxyEvent::ActionFailed`] is the post-admission one, where the
    /// engine accepted the action and the transport rejected it.
    ActionRefused {
        /// The session identifier.
        session_id: SessionId,
        /// The side the unit arrived on.
        side: ProxySide,
        /// The source stream, when there is one.
        stream_id: Option<u64>,
        /// Where the decision was taken.
        site: Site,
        /// What was attempted.
        action: ActionKind,
        /// Why it was refused.
        refusal: Refusal,
    },

    /// An action was admitted but the transport rejected it. The session
    /// survives.
    ///
    /// Emitted **per failed attempt**. The unit is not forwarded — the
    /// transport already declined it — and forwarding continues on
    /// everything else.
    ///
    /// Reaching this means the capability table admitted the action and
    /// the path disagreed; a replacement datagram above the path MTU is
    /// the case that exists in 0.4.0. Neither
    /// [`ProxyEvent::ActionApplied`] nor [`ProxyEvent::ActionRefused`]
    /// can carry it on its own: the action was admitted, so refusing it
    /// after the fact would be a lie, and it did not reach the peer, so
    /// reporting only that it applied would be a bigger one.
    ///
    /// It is **paired with** `ActionApplied`, not exclusive of it. The
    /// engine admits, emits `ActionApplied`, and hands the bytes on; the
    /// transport then declines them and this follows. An attempt that
    /// reaches here therefore contributes two events, in that order. It is
    /// exclusive of [`ProxyEvent::ActionRefused`], which is the other
    /// half of the same split: a refused unit is forwarded unchanged and a
    /// transport failure on *those* bytes is
    /// [`ImpairmentKind::DatagramNotSent`], because nobody's action was in
    /// flight.
    ///
    /// Distinct from [`ImpairmentKind::DatagramNotSent`], which is the
    /// same transport failure on a unit **nobody acted on** — there is no
    /// `site` and no `action` to name there, and this variant requires
    /// both.
    ///
    /// Connection-level errors (`ConnectionLost`, `Connection(_)`) are
    /// **not** reported here: they still end the session.
    ActionFailed {
        /// The session identifier.
        session_id: SessionId,
        /// The side the unit arrived on.
        side: ProxySide,
        /// Where the decision was taken.
        site: Site,
        /// What was executed.
        action: ActionKind,
        /// The transport's error.
        error: String,
    },

    /// Something reduced what the proxy can do, with no action involved.
    ///
    /// Every [`ImpairmentKind`] states its own emission cardinality;
    /// read it there before asserting a count.
    ///
    /// # This is emitted after the thing it reports, never before
    ///
    /// Whatever the report describes has already happened by the time the
    /// observer is called: the reset has been handed to the transport, the
    /// datagram has been refused, the queue has been abandoned. Nothing in
    /// this crate emits one of these on the way *into* an operation that
    /// could still be declined.
    ///
    /// That ordering is what makes the event stream a record rather than an
    /// intention. Reversed, an impairment raised before a step that a guard
    /// then refuses is an observer told about a loss that did not occur —
    /// and there is no later event that retracts it, because this variant
    /// has no counterpart to [`ProxyEvent::ActionFailed`]. An observer may
    /// therefore treat every one of these as a fact about the past.
    ///
    /// The one place the rule is visibly *not* the same is
    /// [`ProxyEvent::ActionApplied`], which is emitted when the engine
    /// admits an action and before the caller hands the bytes to the
    /// transport; that pairing is covered in its own rustdoc and is why
    /// `ActionFailed` exists.
    Impairment {
        /// The session identifier.
        session_id: SessionId,
        /// The side the reporting task was forwarding *from* — the
        /// direction bytes were arriving on, not necessarily the direction
        /// the impairment was felt in. Read `leg` for that.
        side: ProxySide,
        /// Which of the proxy's two connections the report is about, or
        /// `None` when it is about neither.
        ///
        /// # Not derivable from `side`, which is why it is here
        /// `side` names the direction the reporting task reads from, so it
        /// answers *where did these bytes come from*. Most of what
        /// [`ImpairmentKind`] reports is a failure to *write*: a queue that
        /// could not be flushed, a datagram the far transport refused, a
        /// destination stream that had to be reset. Those belong to the
        /// **opposite** connection from the one the bytes arrived on, and a
        /// reader who mapped `side` to a connection would attribute every one
        /// of them to the wrong leg — silently, and in a way that looks
        /// entirely plausible in a log.
        ///
        /// So the two are split, exactly as
        /// [`ProxyStats`](crate::shape::ProxyStats) splits what a leg read
        /// from what it wrote:
        ///
        /// * **the arriving connection** for
        ///   [`ImpairmentKind::FramerBypass`],
        ///   [`ImpairmentKind::ObjectNotAddressable`] and
        ///   [`ImpairmentKind::ControlFrameNotDecodable`] — all three are a
        ///   parser giving up on bytes that came *in*, and none of them
        ///   says anything about what could be written;
        /// * **the departing connection** for
        ///   [`ImpairmentKind::EgressQueueFull`],
        ///   [`ImpairmentKind::HoldClamped`],
        ///   [`ImpairmentKind::QueuedBytesAtTeardown`],
        ///   [`ImpairmentKind::DatagramNotSent`],
        ///   [`ImpairmentKind::ControlStreamTruncated`],
        ///   [`ImpairmentKind::ElideFixupLost`],
        ///   [`ImpairmentKind::ShapeUnpacedObject`],
        ///   [`ImpairmentKind::ClassChangedMidStream`] and
        ///   [`ImpairmentKind::SerializeTargetUnknown`] — every one of them
        ///   is about bytes the proxy was trying to place on the far side;
        /// * **`None`** for
        ///   [`ImpairmentKind::CoarseReleaseTimer`],
        ///   [`ImpairmentKind::ShapeRuleUnmatchable`] and
        ///   [`ImpairmentKind::ShapeBurstBelowUnit`]. These three compare a
        ///   *profile* against the sizes it is asked to pace, or the
        ///   process against its host. None of them is a property of a
        ///   connection, and all three are equally true of both legs.
        ///   `None` says that in the type instead of picking whichever leg
        ///   the reporting task happened to be on.
        ///
        /// A caller that wants *which connection is unhealthy* reads this field
        /// and skips the `None`s. A caller that wants *which direction was
        /// being forwarded when this was noticed* reads `side`.
        leg: Option<Leg>,
        /// What happened.
        kind: ImpairmentKind,
    },

    /// The egress shaper acted on a unit **as configured**.
    ///
    /// This is the product working, not an impairment: a configured drop is
    /// the tool doing what it was told, where an
    /// [`ImpairmentKind`] is the tool declining to. It is also the only
    /// event that can carry a class label, because a class is a shaping
    /// concept and nothing else in this enum has one.
    ///
    /// **Cardinality: once per stream per distinct `outcome`.** Running
    /// totals live in [`ShapeStats`](crate::shape::ShapeStats) — a
    /// per-object event would drown an observer at line rate, which is the
    /// same reason [`ImpairmentKind::ObjectNotAddressable`] carries a total
    /// instead of firing per object.
    Shaped {
        /// The session identifier.
        session_id: SessionId,
        /// The side the unit arrived on.
        side: ProxySide,
        /// Session-local identity. Unique even on the WebTransport arm,
        /// where every transport stream id is the constant `0`.
        key: StreamKey,
        /// Transport stream id, for correlation with the other events in
        /// this enum. **`0` for every WebTransport stream**; `key` is what
        /// identifies.
        stream_id: u64,
        /// The class the unit resolved to, or an empty string for a unit
        /// that matched no rule and for an outcome that is about the stream
        /// rather than about a unit.
        class: String,
        /// What the shaper did.
        outcome: ShapeOutcome,
    },

    /// The egress shaper discarded a **datagram** as configured.
    ///
    /// [`Self::Shaped`]'s datagram sibling, and separate from it because a
    /// datagram belongs to no stream: `Shaped` carries a [`StreamKey`] and a
    /// transport stream id, and there is nothing honest to put in either.
    /// Merging the two by making those fields optional would put an
    /// `Option` on the far commoner event to describe the rarer one.
    ///
    /// **Cardinality: once per forwarding direction per distinct
    /// `outcome`**, which is the same rule [`Self::Shaped`] states per
    /// stream — the direction is a datagram's whole scope. Running totals
    /// live in [`ShapeStats`](crate::shape::ShapeStats).
    ShapedDatagram {
        /// The session identifier.
        session_id: SessionId,
        /// The side the datagram arrived on.
        side: ProxySide,
        /// The class the datagram resolved to, or an empty string for one
        /// that matched no rule.
        class: String,
        /// What the shaper did.
        outcome: ShapeOutcome,
    },
}

/// What [`ProxyEvent::Shaped`] reports the shaper did.
///
/// `#[non_exhaustive]`; derives `PartialEq`/`Eq` like [`Effect`] and
/// [`ImpairmentKind`], so a test destructures the event and compares this.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShapeOutcome {
    /// A unit was discarded by
    /// [`Overflow::DropTail`](crate::shape::Overflow::DropTail).
    ///
    /// The unit went through the framer's elide path, so absolute object
    /// IDs on drafts 14-19 stay correct; a unit an elide guard refused was
    /// admitted instead of dropped and is reported as a refusal, not here.
    Dropped,
    /// A queued unit outlived `max_hold` under
    /// [`Expiry::ResetStream`](crate::shape::Expiry::ResetStream).
    ///
    /// Decided at release time rather than at admission: the queue notices
    /// the overrun when it next looks at its head, replaces everything it
    /// was holding with the reset the policy asked for, and reports this.
    /// So the event says the whole destination stream was abandoned, not
    /// that one unit was — which is why it carries an empty `class` for the
    /// same reason [`Self::StreamReset`] does.
    ///
    /// **Emitted once per stream.** The queue is gone after the first one,
    /// so there is nothing left to expire.
    ///
    /// This variant read "no producer yet" for as long as expiry was decided
    /// nowhere; it now has one, and asserting on it is
    /// `actions_shaping.rs`'s business rather than a promise waiting to be
    /// kept.
    Expired,
    /// A datagram was discarded because its class's bucket had no tokens
    /// for it.
    ///
    /// **Policing rather than shaping**, and the difference is that there is
    /// no queue: a datagram arriving over its class's configured rate is
    /// dropped at admission rather than held until the tokens arrive. That
    /// is the only sound answer for this carrier — a queue would impose an
    /// order the protocol does not have, and a datagram has no successor
    /// whose framing depends on it, which is what makes discarding one
    /// harmless where discarding a queued stream unit is not.
    ///
    /// Carried only by [`ProxyEvent::ShapedDatagram`]. [`Self::Dropped`] is
    /// the stream carrier's answer and says something different: that an
    /// overflow policy discarded a unit the queue had no room for.
    Policed,
    /// The destination stream was abandoned by an overflow or expiry
    /// policy.
    StreamReset {
        /// The application error code it was reset with.
        code: u64,
    },
}

/// What an executed action actually did.
///
/// Unlike [`ProxyEvent`] this derives `PartialEq` and `Eq`: destructure
/// the event, then `assert_eq!` on what comes out. See
/// [`ProxyEvent`]'s own rustdoc for the shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effect {
    /// The original bytes were forwarded.
    ForwardedVerbatim,
    /// Replacement bytes were forwarded.
    Replaced {
        /// How many bytes were written.
        bytes: usize,
    },
    /// An object was removed. `renumbered_successor` is `true` when the next
    /// object on the stream has to be re-encoded against the one now in
    /// front of it: its leading ID varint rewritten on a subgroup stream of
    /// drafts 14-19, its whole framing re-encoded on a fetch stream of
    /// drafts 15-19.
    ///
    /// It says a fix-up is **owed**, not that the bytes moved. A survivor
    /// that already stated everything it needed comes through unchanged, and
    /// the debt is settled all the same.
    Elided {
        /// Whether a successor fix-up is now pending.
        renumbered_successor: bool,
    },
    /// The unit was queued for later release.
    Queued {
        /// When it is due.
        release_at: Instant,
    },
    /// A prefix was written and the stream reset.
    ///
    /// `forwarded` counts bytes **handed to the transport**, not bytes the
    /// peer observed. quinn clears the peer's receive assembler when the
    /// reset is processed, so the peer may observe fewer — never more.
    Truncated {
        /// Bytes of this unit written before the reset.
        forwarded: usize,
        /// The reset code, as the action stated it.
        code: u64,
        /// `false` when the draft defines no stream-reset code vocabulary
        /// (drafts 07-10), so `code` is a choice rather than a claim.
        code_defined: bool,
    },
    /// The destination stream was reset.
    StreamReset {
        /// The reset code.
        code: u64,
        /// `false` when the draft defines no stream-reset code vocabulary
        /// (drafts 07-10), so `code` is a choice rather than a claim.
        code_defined: bool,
    },
    /// The stream was never forwarded.
    StreamRejected {
        /// The code the source was stopped with.
        code: u64,
    },
    /// A session close was requested.
    SessionClosing {
        /// The session termination code.
        code: u32,
    },
    /// The unit was not forwarded.
    Dropped,
}

/// A reduction in what the proxy can do or observe.
///
/// **Every variant states its emission cardinality**, because the counts
/// differ by an order of magnitude between them — some fire once per
/// session, some once per stream, and some once per unit — and a test
/// that assumes "exactly one" against a per-unit variant is a test that
/// goes red for the wrong reason. Where a variant is capped below its
/// natural rate, a counter on
/// [`crate::instrument::Counters`] carries the running total instead.
///
/// Like [`Effect`], this derives `PartialEq` and `Eq`; the event that
/// carries it does not.
///
/// # Every variant here has a producer
///
/// None of these is reserved, aspirational or waiting for a call site: each
/// one is emitted by code in this crate, and the emission happens **after**
/// what it reports — see [`ProxyEvent::Impairment`] for why that ordering is
/// the whole value of the surface.
///
/// One is harder to reach than the rest and says so on itself:
/// [`Self::CoarseReleaseTimer`] needs `MOQTAP_RELEASE_TIMER=condvar`,
/// because every default release backend is high-resolution. That is a
/// diagnostic override rather than a fallback, and the variant exists so a
/// run made under it cannot quote delays it was unable to honour.
///
/// A variant added here is forced to answer one more question before it
/// compiles: which of the proxy's two connections it is about. The mapping
/// that answers it matches exhaustively with no catch-all, so a new report
/// stops the crate building rather than defaulting to a leg somebody else
/// chose.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImpairmentKind {
    /// The framer stopped parsing a stream, so no object on it is
    /// addressable. Emitted exactly once per stream.
    FramerBypass {
        /// The source stream.
        stream_id: u64,
        /// The draft it was parsed as.
        draft: DraftVersion,
        /// Why parsing stopped.
        reason: crate::types::BypassReason,
    },
    /// An object exceeded the framer's buffer cap and was streamed through
    /// without being addressable.
    ///
    /// Emitted **at most once per stream**, on the first such object, and
    /// carries the running count. Every other `ImpairmentKind` states its
    /// cardinality; this one did not, and it fires per object — a stream
    /// of large objects under a low `max_buffered_object_bytes` would
    /// otherwise emit one event per object and swamp an observer written
    /// against the once-per-stream cardinality every neighbouring variant
    /// documents. The count keeps the information: `total` is the number
    /// of unaddressable objects seen on this stream **at the moment of
    /// emission**, i.e. `1`, and
    /// [`crate::instrument::Counters::objects_not_addressable`] is the
    /// running total that stays accurate afterwards.
    ObjectNotAddressable {
        /// The source stream.
        stream_id: u64,
        /// Unaddressable objects on this stream so far.
        total: u64,
    },
    /// A control frame's body was refused by the decoder, so the proxy
    /// forwarded a message it could not read.
    ///
    /// The frame's declared length was intact — that is what let the parser
    /// find the frame behind it — and only the message inside it failed to
    /// decode. The bytes reach the peer regardless, in the position they
    /// held: on the observation-only control pipe they were forwarded
    /// before anything was parsed, and on the mutating pipe, where the
    /// parser owns the forwarding path, they are written verbatim without
    /// a hook being consulted. So what a refusal costs is this proxy's
    /// account of a message, never the message.
    ///
    /// That account is the whole product, which is why the loss is
    /// reported. Without this event a control message the proxy could not
    /// read is indistinguishable from one the peer never sent, and the two
    /// call for opposite conclusions. It is not a per-draft hazard: a
    /// Message Type the configured draft does not assign, a frame whose
    /// body does not match its declared length, and anything an extension
    /// adds all take the same path on all thirteen drafts.
    ///
    /// # Cardinality: at most once per control stream direction
    ///
    /// Emitted on the first refused frame, carrying the count as it stood
    /// when the report went out. A peer repeating an unassigned Message
    /// Type would otherwise emit one event per frame, against neighbouring
    /// variants an observer has been told fire once per stream — the same
    /// argument [`Self::ObjectNotAddressable`] makes for the same shape of
    /// hazard.
    ///
    /// The running figure that stays accurate afterwards is
    /// [`crate::instrument::Counters::control_frames_not_decodable`]. That
    /// counter and this event count different things on purpose: one frame
    /// refused and forty refused produce one event each and differ by
    /// thirty-nine there.
    ControlFrameNotDecodable {
        /// The Message Type varint the **first** refused frame declared.
        ///
        /// The type is read from the frame header, which decoded; nothing
        /// inside the frame did, so this is the whole of what the refused
        /// message can still say about itself. A later refusal of a
        /// different type is counted and not named — see the cardinality
        /// note above.
        type_id: u64,
        /// Frames refused on this direction when the report went out.
        total: u64,
    },
    /// A stream's pending queue reached
    /// [`crate::action::EgressConfig::max_pending_bytes`], so delay has
    /// become backpressure. Emitted once per stream, on the transition
    /// into backpressure — a queue that drains and fills again does not
    /// report twice.
    EgressQueueFull {
        /// The source stream.
        stream_id: u64,
    },
    /// A delay, or a shaped release, was clamped to
    /// [`crate::action::EgressConfig::max_hold`].
    ///
    /// Emitted **once per clamped unit**, not once per stream: a hook
    /// that returns an over-long `Delay` for every object emits one event
    /// per object. It is a property of the decision, and the decision is
    /// taken again for the next unit.
    ///
    /// # `requested: None` is an unbounded wait, not a missing figure
    ///
    /// A hook's own `Delay { by }` names a duration, so it reports
    /// `Some(by)`. A shaped release frequently names none: a class whose
    /// rate is zero, or whose burst is smaller than the unit at the head of
    /// its queue, has **no** refill instant, and the clamp is the only
    /// thing that will ever release that unit. `None` is that case, and it
    /// is the honest report — there is no duration to quote and inventing a
    /// finite one would be a fabrication.
    ///
    /// The unbounded case was once reported as `Duration::MAX`, which
    /// reaches a log as `18446744073709551615.999999999s`. Two things went
    /// wrong with that. A reader sees a 584-billion-year request beside a
    /// 2 s applied one and takes it for an encoding fault in whatever
    /// rendered it, filing against the wrong component; and the natural
    /// assertion that a clamp *reduced* the request — `requested > applied`
    /// — cannot tell that sentinel from a real thirty-second request, so it
    /// passes either way and certifies nothing.
    HoldClamped {
        /// What was asked for, or `None` when the wait was unbounded.
        requested: Option<Duration>,
        /// What was applied: the `max_hold` ceiling.
        applied: Duration,
    },
    /// A **control** stream's destination ended with a FIN part-way
    /// through a message. The proxy does not synthesize a reset there —
    /// that would be a session-level protocol violation — and it does not
    /// finish the message either, because completing it would mean
    /// inventing control-stream bytes neither peer wrote. On a data stream
    /// the equivalent failure synthesizes a reset, which is what makes the
    /// truncation visible to the peer; here only this report carries it.
    ///
    /// Two things produce it, and `error` says which:
    ///
    /// 1. a non-reset read failure on the source half, which is the last
    ///    read that stream will ever do;
    /// 2. the drain window of a requested session close expiring while a
    ///    message was part-written — see
    ///    [`ProxyControl::close_session`](crate::control::ProxyControl::close_session).
    ///
    /// Emitted **at most once per control stream direction**. The two
    /// producers cannot both fire on one direction: the first returns from
    /// the pipe, so the second is unreachable afterwards. A session with
    /// both control directions affected emits two, one per `side`.
    ///
    /// The second producer says nothing at all when the proxy cannot tell
    /// where the message boundaries are — a control stream whose framing
    /// could not be followed reports no truncation rather than a guessed
    /// one.
    ControlStreamTruncated {
        /// The failure that caused it.
        error: String,
    },
    /// Queued bytes were still pending when the session tore down. They
    /// were flushed best-effort; `bytes` may not have reached the peer.
    ///
    /// Emitted **at most once per stream**, at teardown, and only for a
    /// stream that still had something queued when teardown began — a
    /// stream that drained at its release times reports nothing.
    ///
    /// `bytes` counts everything the teardown flush could not vouch for:
    /// what it could not write **and** what it wrote into a transport the
    /// session was already closing. The second half is not pedantry — a
    /// `write_all` into quinn returns `Ok` as soon as the bytes are
    /// buffered, and `Connection::close` discards that buffer, so counting
    /// only the residue reports zero for precisely the case that loses
    /// data. A peer that did receive the bytes gets a spurious impairment;
    /// that is the safe side to err on.
    QueuedBytesAtTeardown {
        /// The source stream.
        stream_id: u64,
        /// How many bytes could not be confirmed delivered.
        bytes: usize,
    },
    /// A datagram could not be handed to the transport, and the session
    /// survived.
    ///
    /// Emitted **once per rejected datagram** — this is a per-unit
    /// variant, so a source steadily sending datagrams above the path MTU
    /// produces one event each. Nothing caps it, because unlike
    /// [`Self::ObjectNotAddressable`] there is no stream to attribute a
    /// running total to.
    ///
    /// Distinct from [`ProxyEvent::ActionFailed`], which requires a `site`
    /// and an `action`: this is the un-hooked path, where nobody acted
    /// and there is nothing to name. Both exist because
    /// `forward_datagrams` drops the `?` on **every** `send_datagram`
    /// call, not only the ones behind a hook.
    DatagramNotSent {
        /// The transport's error.
        error: String,
    },
    /// The release wheel is not high-resolution on this host, so
    /// [`crate::action::Action::Delay`] cannot resolve below the ~15.6 ms
    /// system tick and every delay shorter than it is really a tick.
    ///
    /// The default backend is high-resolution on every platform, so in
    /// 0.4.0 the only way to reach this is
    /// `MOQTAP_RELEASE_TIMER=condvar` on Windows — the diagnostic
    /// override, not a fallback. It is reported rather than assumed away
    /// because a forced backend is still a run whose delays were not
    /// honoured.
    ///
    /// Emitted **once per session**, on that session's first deferred
    /// release. The measured shortfall is in
    /// [`crate::instrument::Counters::release_errors`]; this event exists
    /// so a report cannot quote "5 ms delay applied" while silently
    /// having been unable to apply it.
    CoarseReleaseTimer {
        /// The backend the release thread resolved to.
        backend: crate::instrument::TimerBackend,
        /// Reserved for a future backend that can fail to initialise.
        /// **Always `None` in 0.4.0**: the only coarse backend is the one
        /// `MOQTAP_RELEASE_TIMER` forces, and nothing failed for it to
        /// describe.
        detail: Option<String>,
    },
    /// The framer stopped parsing a stream while an elide fix-up was
    /// still owed, so the remainder of the stream cannot be renumbered.
    ///
    /// The destination stream is **reset** rather than forwarded, because
    /// the alternative is delivering bytes that are known to decode to
    /// the wrong Object IDs. This is the residual case of the elide
    /// mechanism, and it is reachable: a mid-stream decode error or an
    /// unmeasurable oversized object can latch bypass at any point after
    /// an elide.
    ///
    /// Emitted **at most once per stream**, and it is that stream's last
    /// event: the reset has already been asked for by the time this
    /// arrives, and the forwarding task returns immediately afterwards.
    /// The order is that way round on purpose — `code` names the value the
    /// destination *was* reset with, so an event raised above the reset
    /// would describe a wire change that had not been made, and this arm
    /// has no later event to correct it with. It is the
    /// `fixup_owed == true` half of the one `FramerOut::Bypassed` a
    /// stream can produce — the half that reports [`Self::FramerBypass`]
    /// is the other.
    ElideFixupLost {
        /// The source stream.
        stream_id: u64,
        /// Why the framer gave up.
        reason: crate::types::BypassReason,
        /// The code the destination was reset with (`0x0`).
        code: u64,
    },
    /// A [`StreamAction::SerializeAfter`](crate::action::StreamAction::SerializeAfter)
    /// named a stream there is nothing to wait for, so the stream it was
    /// returned on proceeded immediately.
    ///
    /// Three cases reach it and they are deliberately one report: the target
    /// never existed, the target had already ended, or the target is this
    /// stream itself. All three are a hook naming a stream that cannot end
    /// later than now, and in all three the honest engine behaviour is to
    /// proceed — a serialize that silently held forever would be a
    /// `max_hold` stall attributed to the wrong thing.
    ///
    /// Emitted **once per stream**. A stream takes at most one serialize
    /// decision at each of the two stream sites, and a decision that names a
    /// live target reports nothing at all.
    ///
    /// Both fields are [`StreamKey`]s rather than transport ids, because
    /// attribution is the whole point of the report and the transport id is
    /// the constant `0` on every WebTransport stream.
    SerializeTargetUnknown {
        /// The stream that asked to be serialized.
        key: StreamKey,
        /// The target it named.
        target: StreamKey,
    },
    /// A [`ClassRule`](crate::shape::ClassRule) keys on a field the wire
    /// does not carry on this draft and stream kind, so it can never claim
    /// a unit and everything it was aimed at falls to the default class.
    /// This is the report that keeps the rule **a key the wire does not carry
    /// never matches** from being a silent no-op. `Discipline::StrictPriority`
    /// is specified on `publisher_priority`, which is `None` on drafts 15-19
    /// under the default-priority bit — so without this, *starve video while
    /// audio flows* is a silent no-op on the five newest drafts and the run
    /// reports success. A rule aimed at
    /// [`MatchKind::Datagram`](crate::shape::MatchKind::Datagram) reports
    /// through the same seam, from the datagram forwarder rather than from the
    /// framer, and reports the one key a datagram can be missing: its priority,
    /// which drafts 15 and later let a type byte leave off. The key no datagram
    /// *ever* carries is refused before the run instead — see
    /// `Capabilities::admit_class`.
    ///
    /// Emitted **once per session per `(class, field)`**, on the first unit
    /// that reaches the rule. Not once per stream and not once per unit: it
    /// is a statement about a *profile* against a *draft*, both of which are
    /// fixed for the session. The falsifiable companion an author reads is
    /// `ShapeStats::default_class`, which is where the units went.
    ///
    /// A rule whose key is *present but out of range* reports nothing —
    /// that is a rule working.
    ShapeRuleUnmatchable {
        /// The [`ClassRule::name`](crate::shape::ClassRule::name) that
        /// cannot fire.
        class: String,
        /// The key it named that the wire did not carry.
        field: crate::shape::MatcherField,
        /// The draft the session is running as, which is half of why the
        /// key is absent.
        draft: DraftVersion,
    },
    /// A class's [`BucketConfig::burst_bytes`](crate::shape::BucketConfig::burst_bytes)
    /// is smaller than the units it is being asked to pace, so its
    /// configured rate never binds and every unit leaves at its `max_hold`
    /// clamp instead.
    ///
    /// A token bucket can never grant a unit larger than the whole bucket —
    /// there is no amount of refilling that covers it — so a burst below one
    /// object turns a rate into a metronome running at
    /// `queue depth / max_hold`. Measured: `rate_bps` of 1 000 000 with
    /// `burst_bytes` of 100 delivered 1000-byte objects at exactly the
    /// clamp, a figure the configuration never mentions.
    ///
    /// **This is the report that makes that case distinguishable.** Without
    /// it the symptoms are `HoldClamped` on every unit and a rising
    /// `tokens_exhausted_episodes` — which is *also* precisely what a class
    /// that is genuinely rate-limited produces, so an author who wrote a rate
    /// and left the burst at its default read a plausible-looking starved
    /// class and no indication that their number had been ignored.
    ///
    /// A class whose `rate_bps` is `Some(0)` never reaches this report. That
    /// is a class configured to stop, doing what it was asked; only a rate
    /// that was asked for and cannot be applied is a fault.
    ///
    /// It cannot be rejected when the profile is built:
    /// [`ShapeProfile::try_new`](crate::shape::ShapeProfile::try_new) has the
    /// burst but not the object sizes, and the sizes are half the comparison.
    ///
    /// Emitted **once per session per class**. The burst is a property of the
    /// profile, so every stream carrying the class reproduces it and every
    /// unit of it re-triggers it; the running figures beside this report are
    /// the class's own `tokens_exhausted_episodes` and one `HoldClamped` per
    /// clamped unit.
    ShapeBurstBelowUnit {
        /// The [`ClassRule::name`](crate::shape::ClassRule::name) whose rate
        /// is not being applied.
        class: String,
        /// The bucket cap, as configured.
        burst_bytes: u64,
        /// The wire size of the unit it could not cover — the other half of
        /// the comparison, so the report is actionable without a second
        /// measurement.
        unit_bytes: u64,
    },
    /// An object too large for the framer to buffer was forwarded without
    /// passing any token bucket, so the named class's configured rate was
    /// exceeded by exactly that object.
    ///
    /// Shaping is per unit and a unit is classified from its `ObjectMeta`.
    /// An object beyond
    /// [`FramerConfig::max_buffered_object_bytes`](crate::framer::FramerConfig::max_buffered_object_bytes)
    /// has none — the framer streams it through rather than measuring it —
    /// so no rule can claim it, no bucket can charge it, and the release seam
    /// grants it unconditionally. Measured: a 4 MiB object crossed in 800 ms
    /// against a class holding a bucket configured at zero bytes per second.
    ///
    /// This report is what keeps that from being a silent breach. `class` is
    /// the class the stream's *classified* units are charged to, which is the
    /// rate the escaping object was nominally under — an empty string on a
    /// stream that has not classified anything yet, matching the unnamed rows
    /// on [`ShapeStats`](crate::shape::ShapeStats). The bytes themselves are
    /// accounted on
    /// [`ShapeStats::unshapeable`](crate::shape::ShapeStats::unshapeable), so
    /// the conservation identity still closes; what was missing was anything
    /// naming the class whose ceiling they went over.
    ///
    /// Paired with, and deliberately distinct from,
    /// [`ObjectNotAddressable`](Self::ObjectNotAddressable): that one says
    /// the *hook* cannot address the object, this one says the *shaper* did
    /// not pace it. A session with no
    /// [`ShapeProfile`](crate::shape::ShapeProfile) emits the first and never
    /// the second, because there is no rate to exceed.
    ///
    /// Emitted **at most once per stream**, on the first such object, for the
    /// reason `ObjectNotAddressable` is capped the same way: a stream of
    /// large objects would otherwise emit one event each.
    ShapeUnpacedObject {
        /// The [`ClassRule::name`](crate::shape::ClassRule::name) this
        /// stream's classified units are charged to, or an empty string when
        /// no rule has claimed one yet.
        class: String,
        /// The source stream.
        stream_id: u64,
        /// Wire bytes of the unpaced chunk that triggered the report.
        bytes: u64,
    },
    /// Two units on one destination stream resolved to **different** shaping
    /// classes, so that stream's throughput is decided by whichever class is
    /// at its head rather than by any one class's bucket.
    ///
    /// This is not a defect and not a refusal — it is what per-unit
    /// classification over a single per-stream FIFO *means*. Reordering the
    /// queue by class is forbidden outright: object IDs are delta-encoded on
    /// the wire on drafts 14-19, and the framer's only re-encoding primitive
    /// handles removal, not reordering. So the head gates everything behind
    /// it whatever class those units are, and this report is what keeps that
    /// from being mistaken for the shaping the author configured.
    ///
    /// Emitted **once per stream**, on the first disagreement. The running
    /// figures beside it are
    /// [`ShapeStats::streams_with_mixed_classes`](crate::shape::ShapeStats::streams_with_mixed_classes)
    /// and, per class,
    /// [`ClassStats::starved_behind_other_class`](crate::shape::ClassStats::starved_behind_other_class)
    /// — which is deliberately *not*
    /// [`ClassStats::tokens_exhausted_episodes`](crate::shape::ClassStats::tokens_exhausted_episodes):
    /// two causes of waiting, two counters.
    ///
    /// **This report's `leg` and the proxy-wide counter's cell disagree by
    /// exactly one leg, on purpose.** This event answers the departing
    /// connection, because the stream whose throughput is now shared is the
    /// one being written to; the same occurrence is charged to the *arrival*
    /// cell of
    /// [`ProxyStats::per_leg`](crate::shape::ProxyStats::per_leg), so it sits
    /// beside the `bytes_shaped` that explains it. Correlating an event with
    /// a cell means expecting the two labels to differ — see
    /// [`DirectionStats::streams_with_mixed_classes`](crate::shape::DirectionStats::streams_with_mixed_classes),
    /// which states it from the other side.
    ///
    /// Keyed on [`StreamKey`] and **not** on `stream_id`, for the reason
    /// [`SerializeTargetUnknown`](Self::SerializeTargetUnknown) is: on the
    /// WebTransport arm every transport stream id is the constant `0`, so a
    /// report identified by `stream_id` alone would make "once per stream"
    /// read as "once per session" — and a test asserting one event per mixed
    /// stream would pass on QUIC and be unwritable on WT. The transport id
    /// rides along because it is what correlates this report with every
    /// other event in this enum.
    ClassChangedMidStream {
        /// Session-local identity of the destination stream carrying both
        /// classes. Unique even on the WebTransport arm.
        key: StreamKey,
        /// Transport stream id, for correlation with the other events in
        /// this enum. **`0` for every WebTransport stream**; `key` is what
        /// identifies.
        stream_id: u64,
    },
}

/// The connection an [`ImpairmentKind`] is about, given the side the task
/// that raised it was forwarding from.
///
/// The whole mapping lives here, in one exhaustive `match`, rather than at
/// the twenty-odd sites that raise these reports. Two reasons, and the
/// second is the one that matters.
///
/// A raising site knows only the direction it reads from. Working out that
/// a queue it could not flush belongs to the *other* connection is a turn
/// each site would have to make for itself, and a site that got it wrong
/// would produce a number that is correct under a wrong label — the failure
/// this whole surface is written to avoid, and one no test at that site
/// would notice, because the event would still arrive and still carry a
/// plausible leg.
///
/// And the turn is a property of the **kind**, not of the site. Whether a
/// report is about what came in or about what could not go out is decided
/// by what the report *says*, so the decision belongs beside the enum that
/// says it. A variant added to [`ImpairmentKind`] stops this function
/// compiling — the `match` has no catch-all on purpose — which is the one
/// place a new report reliably gets asked which leg it means.
///
/// # `arrived_on` must be an ingress side
///
/// Every [`Reporter`](crate::exec::Reporter) in this crate is built with the
/// side its pipe *reads* from, so `arrived_on` is `ClientToProxy` or
/// `RelayToProxy` in practice. The function is still total over all four,
/// because `ProxySide` has four variants and a panicking forwarding path is
/// worse than a defensible answer: an egress side is read as naming its own
/// connection, which is what it does.
pub(crate) fn impairment_leg(kind: &ImpairmentKind, arrived_on: ProxySide) -> Option<Leg> {
    let here = connection_of(arrived_on);
    match kind {
        // The parser gave up on bytes that arrived. Nothing here is a claim
        // about what could be written, so the far leg is not implicated.
        ImpairmentKind::FramerBypass { .. }
        | ImpairmentKind::ObjectNotAddressable { .. }
        | ImpairmentKind::ControlFrameNotDecodable { .. } => Some(here),

        // Every one of these is a failure to place bytes on the far side —
        // a queue that filled in front of it, a release it clamped, bytes it
        // could not vouch for, a datagram it refused, a stream it had to
        // reset or could not renumber for, an object that crossed it
        // unpaced, a destination whose throughput two classes now share, a
        // first write that was held. The connection they are about is the
        // one being written to, which is the opposite of the one they
        // arrived on.
        ImpairmentKind::EgressQueueFull { .. }
        | ImpairmentKind::HoldClamped { .. }
        | ImpairmentKind::QueuedBytesAtTeardown { .. }
        | ImpairmentKind::DatagramNotSent { .. }
        | ImpairmentKind::ControlStreamTruncated { .. }
        | ImpairmentKind::ElideFixupLost { .. }
        | ImpairmentKind::ShapeUnpacedObject { .. }
        | ImpairmentKind::ClassChangedMidStream { .. }
        | ImpairmentKind::SerializeTargetUnknown { .. } => Some(other_connection(here)),

        // A profile compared against the sizes it was asked to pace, or the
        // process compared against its host. All three are equally true of
        // both connections and none of them stops being true if one leg goes
        // away, so naming a leg would be naming whichever pipe noticed first.
        ImpairmentKind::CoarseReleaseTimer { .. }
        | ImpairmentKind::ShapeRuleUnmatchable { .. }
        | ImpairmentKind::ShapeBurstBelowUnit { .. } => None,
    }
}

/// The connection a direction of travel belongs to.
fn connection_of(side: ProxySide) -> Leg {
    match side {
        ProxySide::ClientToProxy | ProxySide::ProxyToClient => Leg::Client,
        ProxySide::ProxyToRelay | ProxySide::RelayToProxy => Leg::Upstream,
    }
}

/// The proxy's other connection. There are exactly two.
fn other_connection(leg: Leg) -> Leg {
    match leg {
        Leg::Client => Leg::Upstream,
        Leg::Upstream => Leg::Client,
    }
}

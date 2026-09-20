//! What a hook asks the engine to do, and the vocabulary it asks in.

use std::time::Duration;

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::shape::StreamKey;

/// What machinery a hook wants armed.
///
/// Bitflags-style with no dependency. Read **once per session**, when the
/// session starts, and cached; a hook that returns a different value later
/// is not re-consulted. The byte-pump path is chosen *structurally* — which
/// function `pipe_data` calls — so re-reading per frame would require the
/// framer to be armed at all times in order to be able to *become*
/// interested, which is precisely the cost `Interest::NONE` exists to
/// avoid. Declare the union of everything the hook may ever want here, and
/// gate at runtime by returning [`Action::Pass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Interest(u8);

impl Interest {
    /// Pure byte pump: no parsing on any path. Today's fast path,
    /// bit-for-bit. The default.
    pub const NONE: Self = Interest(0);
    /// Parse control messages and honour actions on them. Routes the
    /// control stream through the slower parse-then-forward pipe, which
    /// costs per-frame latency.
    pub const CONTROL: Self = Interest(1 << 0);
    /// Frame subgroup and fetch objects and honour actions on them. Costs
    /// whole-object buffering: an object is not forwarded until it is
    /// buffered whole, or until the framer gives up on it.
    pub const OBJECTS: Self = Interest(1 << 1);
    /// Decode and gate datagrams. The hook fires even when the datagram's
    /// header does not decode.
    pub const DATAGRAMS: Self = Interest(1 << 2);
    /// Decide on unidirectional stream open, stream header, and stream end.
    ///
    /// **Includes [`Self::OBJECTS`]**, structurally — the bit pattern is
    /// `(1 << 3) | (1 << 1)`, so `STREAMS.contains(OBJECTS)` is `true` by
    /// construction rather than by documentation. The header decision only
    /// exists once the stream is framed, and framing is what `OBJECTS`
    /// turns on; a `STREAMS`-only hook that did not imply it would take
    /// `pipe_data_passthrough` and never see a header at all.
    ///
    /// A hook that wants stream decisions but no object decisions still
    /// declares `STREAMS` and simply returns [`Action::Pass`] from
    /// [`ProxyHook::on_object`](crate::hook::ProxyHook::on_object) — it
    /// pays for framing either way, because there is no header without it.
    ///
    /// ```
    /// use moqtap_proxy::action::Interest;
    /// assert!(Interest::STREAMS.contains(Interest::OBJECTS));
    /// ```
    pub const STREAMS: Self = Interest((1 << 3) | (1 << 1));

    /// Whether every flag in `other` is set here.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    /// The union of two interests.
    pub const fn union(self, other: Self) -> Self {
        Interest(self.0 | other.0)
    }
    /// Whether no flag is set.
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

// The implication `STREAMS ⊇ OBJECTS` is what makes `session.rs`'s
// `objects_enabled` true for a `STREAMS`-only hook. A revision that
// wrote `STREAMS` as a plain `1 << 3` would send that hook down
// `pipe_data_passthrough`, where `on_stream_header` can never fire — a
// silent no-op rather than a refusal. Fail the build instead.
const _: () = assert!(Interest::STREAMS.contains(Interest::OBJECTS));

impl std::ops::BitOr for Interest {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// A cheap, clonable release handle the engine awaits.
///
/// Level-triggered: releasing before anyone waits is observed by every
/// later waiter, so there is no lost-wakeup race. All clones share one
/// release, and the handle is eight bytes.
///
/// The engine never awaits a gate on its own — it always races the gate
/// against session cancellation and [`EgressConfig::max_hold`], so a hook
/// that never releases cannot make a stream unkillable.
///
/// Deliberately a newtype rather than an exposed `CancellationToken`:
/// handing the engine the session's own cancel token would conflate
/// teardown with object release.
#[derive(Debug, Clone, Default)]
pub struct Gate(CancellationToken);

impl Gate {
    /// A new, unreleased gate.
    pub fn new() -> Self {
        Self::default()
    }
    /// Release every holder. Idempotent.
    pub fn release(&self) {
        self.0.cancel();
    }
    /// Whether [`Self::release`] has been called.
    pub fn is_released(&self) -> bool {
        self.0.is_cancelled()
    }
    /// Resolve once the gate is released. Engine-internal: callers race it
    /// against session cancellation and [`EgressConfig::max_hold`].
    pub(crate) async fn wait(&self) {
        self.0.cancelled().await;
    }
}

/// What the engine should do with the unit of traffic the hook was shown.
///
/// [`Self::Delay`] and [`Self::Hold`] are *modifiers*: they carry the
/// action to perform once the unit is released. Their `then` must be a
/// content action — [`Self::Pass`], [`Self::Replace`],
/// [`Self::ReplacePayload`] or [`Self::Drop`]. Any other nesting is refused
/// with
/// [`Refusal::WrongComposition`](crate::capability::Refusal::WrongComposition)
/// rather than silently ignored, so `Delay { then: ResetStream { .. } }`
/// and `Delay { then: Truncate { .. } }` (terminals — positional by
/// construction, so the queue already orders them and a delay would only
/// move the end of the stream), `Delay { then: CloseSession { .. } }` (a
/// session-scoped decision, with no per-unit release to attach it to) and
/// `Delay { then: Delay { .. } }` (a nested modifier) are all loud. Those
/// four, and only those four, are the refused shapes; the three `detail`
/// strings in `exec.rs` enumerate them.
///
/// # `Delay { then: Drop(_) }` is admitted, and is not inert
///
/// A deferred drop is not unobservable: it takes an **ordering slot** in
/// the stream's pending queue for the whole of `by`, and the queue only
/// ever writes from its front — so nothing the hook decides after it can
/// reach the wire until it is released. So
/// `Action::Drop(DropMode::Elide).delayed(d)` deletes this object *and*
/// head-of-line-blocks everything after it on that stream for `d`: one
/// decision, two effects, both on the wire. That is a case worth
/// expressing — a relay that loses an object and stalls while it notices —
/// and refusing it would take it away. `Hold { then: Drop(_) }` is the
/// same impairment under a [`Gate`] instead of a clock.
///
/// It follows that this composition is **not** a way to write a
/// deliberately inert guard. `Drop` deletes the unit wherever it is
/// admitted, wrapped or not; a hook that wants the unit forwarded
/// untouched returns [`Self::Pass`], which is the only action that
/// promises that.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Action {
    /// Forward unchanged.
    ///
    /// On the object site this forwards the framer's own `Bytes` slice —
    /// never a re-encode, on any draft. That is what makes a no-action
    /// session byte-identical to the byte pump.
    Pass,
    /// Replace the whole unit's wire bytes.
    ///
    /// Valid at the control and datagram sites, where the unit is
    /// self-delimiting and the hook owns all of it. Refused at the object
    /// site with [`Refusal::WrongSite`](crate::capability::Refusal::WrongSite):
    /// replacing a whole wire object would require the hook to encode the
    /// draft's object framing, which is the knowledge this crate exists to
    /// hide. Use [`Self::ReplacePayload`].
    Replace(Bytes),
    /// Replace an object's or a datagram's payload, keeping its framing.
    ///
    /// **At the object site.** The replacement must be exactly
    /// [`ObjectMeta::payload_len`](crate::framer::ObjectMeta::payload_len)
    /// bytes; a different length is refused with
    /// [`Refusal::LengthChanged`](crate::capability::Refusal::LengthChanged)
    /// rather than mis-framed. The engine splices at
    /// `raw.len() - meta.payload_len`, which is the payload offset on every
    /// draft and both stream kinds.
    ///
    /// Refused when the object carries a status
    /// ([`ObjectMeta::status`](crate::framer::ObjectMeta::status) is
    /// `Some`), because a status object has no payload slot.
    ///
    /// **At the datagram site**, where it is gated on
    /// [`Precondition::DatagramPayloadDelimited`](crate::capability::Precondition::DatagramPayloadDelimited):
    /// the engine splices after the decoded header, at
    /// `data.len() - cursor.len()`. Refused with
    /// [`Refusal::PayloadNotDelimited`](crate::capability::Refusal::PayloadNotDelimited)
    /// in the three cases where no such offset exists — on **draft-14**,
    /// whose `AnyDatagramHeader` decode consumes the payload; on a **status
    /// datagram**, which has no payload slot; and when the **header did
    /// not decode**, where the hook still fires but there is nothing to
    /// splice after. See
    /// [`ProxyHook::on_datagram`](crate::hook::ProxyHook::on_datagram),
    /// whose rustdoc says the same thing from the caller's side.
    ///
    /// Refused with
    /// [`Refusal::WrongSite`](crate::capability::Refusal::WrongSite)
    /// everywhere else — the control site's unit has no payload/framing
    /// split the proxy may assume, and the stream sites take a
    /// [`StreamAction`].
    ReplacePayload(Bytes),
    /// Release `then` no earlier than `arrived_at + by`.
    ///
    /// A **deadline**, not a spacing: two objects that arrive together,
    /// each with `Delay { by: 100ms }`, are both released about 100 ms
    /// later — not at +100 ms and +200 ms. Release times are clamped
    /// monotonically against the queue's tail, so a later unit can never
    /// overtake an earlier one regardless of its delay.
    ///
    /// Reads continue while units wait, so this is a latency shift rather
    /// than a rate limit — until the stream's pending queue reaches
    /// [`EgressConfig::max_pending_bytes`], at which point reads stop and
    /// the delay becomes backpressure. That transition is reported once as
    /// `ProxyEvent::Impairment { kind: EgressQueueFull }`.
    ///
    /// `by` is clamped to [`EgressConfig::max_hold`]. A clamp is reported
    /// as `ProxyEvent::Impairment { kind: HoldClamped { .. } }`.
    ///
    /// # Resolution
    ///
    /// Release timing does **not** use `tokio::time::sleep`, which is
    /// bounded below by the ~15.6 ms Windows system tick — as is every
    /// other interruptible wait in `std`. Releases are driven by a
    /// process-wide release wheel on one dedicated OS thread, measured at
    /// **p50 0.11-0.17 ms, p95 0.52-0.57 ms end-to-end on Windows 11**
    /// against 11-15 ms for
    /// `tokio::time::sleep`. The measured lateness of every deferred
    /// release is reported in
    /// [`crate::instrument::Counters::release_errors`]; assert on it
    /// rather than assuming the delay was honoured.
    ///
    /// Three consequences worth knowing:
    ///
    /// * When `MOQTAP_RELEASE_TIMER` forces the coarse backend, the floor
    ///   returns to ~15.6 ms on Windows, and the session
    ///   says so exactly once with
    ///   `ProxyEvent::Impairment { kind: CoarseReleaseTimer { .. } }`.
    ///   A run that could not honour its own delays is never silent about
    ///   it. See [`crate::instrument::release_timer_backend`].
    /// * The wheel is on a real clock, not tokio's. A test using
    ///   `#[tokio::test(start_paused = true)]` and expecting a `Delay` to
    ///   complete will **wait out the real deadline**, not advance
    ///   virtual time. Do not pause time around `Delay` or `Hold`.
    /// * The wheel's thread is created on the first deferred release in
    ///   the process and is never joined (it lives in a `static
    ///   OnceLock`). Leak detectors and thread counters will see one live
    ///   thread and one leaked allocation after any delaying test. A
    ///   session that never delays never creates it —
    ///   [`crate::instrument::release_timer_started`] is the falsifiable
    ///   form of that claim.
    Delay {
        /// How long to hold the unit past its arrival.
        by: Duration,
        /// What to do once it is released.
        then: Box<Action>,
    },
    /// Release `then` when `gate` is released, at
    /// [`EgressConfig::max_hold`], or at session teardown — whichever comes
    /// first.
    Hold {
        /// The release handle.
        gate: Gate,
        /// What to do once it is released.
        then: Box<Action>,
    },
    /// Remove the unit from the wire. See [`DropMode`].
    Drop(DropMode),
    /// Write the first `bytes` bytes of this unit, then reset the stream.
    ///
    /// Positional: everything queued ahead of it is written first, then
    /// the truncated prefix, then `RESET_STREAM` with `code`.
    /// `code` is stated rather than defaulted, exactly as in
    /// [`Self::ResetStream`]. A truncation is a *simulated* publisher
    /// abandonment and the code is the whole of what it is
    /// simulating: `0x0` INTERNAL_ERROR reads as "the proxy did this", `0x2`
    /// DELIVERY_TIMEOUT reads as *a relay hit its delivery timeout*, and the
    /// two make a subscriber take different paths. There is no default that is
    /// right for both, so the type asks. The same range check as
    /// [`Self::ResetStream`] applies:
    /// [`Refusal::ErrorCodeOutOfRange`](crate::capability::Refusal::ErrorCodeOutOfRange)
    /// above 2^62 - 1, before anything is sent. On drafts 07-10, which define
    /// no stream-reset code vocabulary at all, the reset still executes and
    /// `Effect::Truncated` reports `code_defined: false`.
    /// The peer observes **at most** `bytes` further bytes, and may observe
    /// none. quinn clears the receive assembler the moment `RESET_STREAM` is
    /// processed (`quinn-proto/src/connection/streams/recv.rs`: **Nuke buffers
    /// so that future reads fail immediately**), so only bytes the peer
    /// application had already read out survive; `reset()` additionally
    /// discards anything still in the local send buffer. Assert an upper bound
    /// and a prefix, never an exact count.
    ///
    /// Refused on control streams on every draft, and on datagrams.
    Truncate {
        /// How many bytes of this unit to write before resetting.
        bytes: usize,
        /// The application error code for the reset that follows.
        code: u64,
    },
    /// Reset the destination stream with this application error code.
    ///
    /// Refused on control streams on every draft: resetting a control
    /// stream at the transport layer is a session-level `PROTOCOL_VIOLATION`
    /// in all of drafts 07-19. The documented escalation is
    /// [`Self::CloseSession`].
    ///
    /// Codes above the QUIC varint ceiling (2^62 - 1) are refused with
    /// [`Refusal::ErrorCodeOutOfRange`](crate::capability::Refusal::ErrorCodeOutOfRange)
    /// before anything is sent, rather than silently becoming a FIN.
    ResetStream {
        /// The application error code to send.
        code: u64,
    },
    /// Close both legs of the session with this code and reason.
    ///
    /// `code` is a *session termination* code, a different namespace from
    /// a stream reset code: `0x0` NO_ERROR, `0x1` INTERNAL_ERROR, `0x2`
    /// UNAUTHORIZED, `0x3` PROTOCOL_VIOLATION. Note that session
    /// INTERNAL_ERROR is `0x1` while stream-reset INTERNAL_ERROR is `0x0`.
    ///
    /// Honoured at **every** site that returns an [`Action`], including
    /// [`Site::StreamEnd`](crate::capability::Site::StreamEnd) on a data
    /// stream *and* on the control stream. A close is session-scoped, so
    /// no site can be the wrong one for it: unlike
    /// [`Self::ResetStream`], there is no per-stream object it needs and
    /// nothing left to forward that honouring it could corrupt. It is the
    /// documented escalation for the two sites where a stream reset is a
    /// protocol violation.
    ///
    /// The first close request wins; later ones are refused with
    /// [`Refusal::SessionAlreadyClosing`](crate::capability::Refusal::SessionAlreadyClosing).
    CloseSession {
        /// The session termination code.
        code: u32,
        /// The reason phrase.
        reason: Bytes,
    },
}

impl Action {
    /// Wrap this action in a [`Action::Delay`].
    pub fn delayed(self, by: Duration) -> Self {
        Action::Delay { by, then: Box::new(self) }
    }
    /// Wrap this action in a [`Action::Hold`].
    pub fn held(self, gate: Gate) -> Self {
        Action::Hold { gate, then: Box::new(self) }
    }
}

/// How [`Action::Drop`] removes an object.
///
/// `MarkMissing` — a zero-length object carrying status
/// `ObjectDoesNotExist`, the obvious default to reach for — is **not in
/// this enum**. That status was removed from the registry in
/// draft-17, and drafts 15-19 do not validate the status on write, so a
/// naive implementation emits a code point those drafts do not define, on a
/// stream that round-trips green against itself. Dropping an object
/// therefore always removes its bytes; nothing here can leave a tombstone
/// behind.
///
/// The absence is a compile-time fact, not a promise:
///
/// ```compile_fail
/// use moqtap_proxy::action::DropMode;
/// // drop_mark_missing_is_not_constructible: no such variant.
/// let _mode = DropMode::MarkMissing;
/// ```
///
/// The companion example below is what makes that `compile_fail` block
/// mean something: if the path or the import were wrong, the block would
/// still "pass" for the wrong reason, and this one would go red.
///
/// ```
/// use moqtap_proxy::action::{Action, DropMode};
/// let mode = DropMode::Elide;
/// assert!(matches!(mode, DropMode::Elide));
/// let _action = Action::Drop(mode);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropMode {
    /// Remove the object's bytes from the wire, preserving every survivor's
    /// **absolute** object ID.
    ///
    /// Drafts 07-13, and fetch streams on drafts 07-14, encode absolute
    /// IDs, so this is pure byte deletion: every survivor is forwarded
    /// verbatim, including any non-minimally-encoded varint it arrived
    /// with. Drafts 14-20 delta-encode, so the *one* object following an
    /// elided run has its leading ID varint rewritten and nothing else;
    /// every later object is again forwarded verbatim, because the wire
    /// cursor re-converges after that one fix-up.
    ///
    /// Eliding `2` from `0,1,2,3,4` yields a stream decoding to `0,1,3,4` —
    /// not `0,1,2,3`.
    ///
    /// Refused when the object is index 0 of a stream whose subgroup ID is
    /// defined as the first object's ID
    /// ([`ObjectMeta::subgroup_id`](crate::framer::ObjectMeta::subgroup_id)
    /// is `None`), because removing it silently redefines the subgroup ID
    /// for the receiver. Also refused when the object carries a status,
    /// which is conservatively treated as a boundary marker.
    Elide,
}

/// What to do with a unidirectional stream.
///
/// Returned from both
/// [`ProxyHook::on_stream_open`](crate::hook::ProxyHook::on_stream_open)
/// and
/// [`ProxyHook::on_stream_header`](crate::hook::ProxyHook::on_stream_header).
/// The observable effect of `Reject` differs between the two, and both are
/// honest:
///
/// * At open, no peer stream is created at all.
/// * At header, the peer stream already exists — it is opened before any
///   byte of the source is read, whether that is in the accept loop or, for
///   a stream whose open was deferred by [`Self::OpenAfter`], in the
///   stream's own task once the delay has elapsed — so it is reset with
///   `code` having carried zero payload bytes, and the source is stopped
///   with `code`.
///
/// The same asymmetry decides where [`Self::OpenAfter`] is legal: it is a
/// decision about *when the peer stream comes into existence*, so only the
/// open site can take it. [`Self::SerializeAfter`] is a decision about when
/// the first **byte** is written, which both sites can still take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamAction {
    /// Forward the stream normally.
    Open,
    /// Do not forward this stream. The source is stopped with `code`.
    Reject {
        /// The application error code.
        code: u64,
    },
    /// Forward the stream, but do not open the peer stream until `after`
    /// has elapsed.
    ///
    /// **Valid at
    /// [`ProxyHook::on_stream_open`](crate::hook::ProxyHook::on_stream_open)
    /// only.** By
    /// [`ProxyHook::on_stream_header`](crate::hook::ProxyHook::on_stream_header)
    /// the peer stream already exists — it is opened before the first
    /// source byte is read, which is what makes a header arrive at all — so
    /// there is nothing left to defer and the header site refuses it with
    /// [`Refusal::WrongSite`](crate::capability::Refusal::WrongSite),
    /// reported as `ProxyEvent::ActionRefused`. It is refused rather than
    /// quietly ignored: a hook that asks for a deferral this crate cannot
    /// perform is told so, and the stream is forwarded unchanged.
    /// Delaying a stream's *opening* on something only its header reveals
    /// — its track alias, say — would want the header site, and is
    /// therefore not expressible in this release: the open decision has to
    /// be taken before a byte is read.
    ///
    /// This models a relay that is slow to accept a subscription rather
    /// than one that is slow to send: the subscriber observes no stream at
    /// all for `after`, not an open-but-idle one. For the latter, see
    /// [`Self::SerializeAfter`], which *is* valid at both sites.
    ///
    /// The deferral is a wire-visible one, not a bookkeeping note: the peer
    /// stream is not opened and the source is not read until `after` has
    /// elapsed, so a stream opened later and not deferred reaches the peer
    /// first.
    OpenAfter(Duration),
    /// Open the peer stream now, but write nothing on it until the stream
    /// named by the key has ended.
    ///
    /// Head-of-line simulation: two streams that a relay would have
    /// interleaved are forced into sequence, so a caller can reproduce a
    /// subscriber that stalls behind an unrelated group.
    ///
    /// Valid at **both** stream sites — it defers the first write, not the
    /// stream's existence.
    ///
    /// One stream is exempt, and it is worth knowing before writing a
    /// hook against it: on the drafts whose control plane is a pair of
    /// unidirectional streams, a stream that turns out to *be* one of them
    /// is not held. Holding a control stream's first write would hold
    /// SETUP, and the session with it. The open site cannot tell in
    /// advance — which stream it is is decided by the first varint on it,
    /// read after the decision has been taken — so the decision is
    /// admitted and then does not apply to that one stream.
    ///
    /// The key comes from
    /// [`StreamCtx::key`](crate::hook::StreamCtx::key) on a stream the hook
    /// was shown earlier. A key naming a stream that has already ended, or
    /// that never existed in this session, **proceeds immediately** and
    /// reports `Impairment { SerializeTargetUnknown }` once — a caller
    /// cannot deadlock a stream by naming the wrong one, and the mistake is
    /// reported rather than silently waited out.
    SerializeAfter(StreamKey),
}

/// How a stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEnd {
    /// The source finished the stream cleanly.
    Fin,
    /// The source peer sent `RESET_STREAM`.
    Reset {
        /// The peer's application error code.
        code: u64,
    },
    /// The destination peer sent `STOP_SENDING`.
    Stopped {
        /// The peer's application error code.
        code: u64,
    },
    /// The session was cancelled while the stream was open.
    Cancelled,
}

/// Engine-side knobs for action execution. Carried on the session config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EgressConfig {
    /// Bytes a per-stream pending queue may hold before the read side is
    /// stalled. Past this point `Delay` and `Hold` are backpressure rather
    /// than latency, and the transition is reported once per stream.
    /// Default 1 MiB.
    pub max_pending_bytes: usize,
    /// Ceiling on any single [`Action::Hold`] and on any single
    /// [`Action::Delay`]. A clamped delay is reported. Default 30 s.
    ///
    /// The ceiling is an `Instant` deadline, and `Instant` does not
    /// behave the same way across a machine suspend on every platform: a
    /// 30 s hold armed before a laptop sleeps may fire immediately on
    /// resume (Windows `QueryPerformanceCounter`) or 30 s after resume
    /// (Linux `CLOCK_MONOTONIC`). Irrelevant on CI; surprising when
    /// debugging a run on a laptop.
    pub max_hold: Duration,
    /// How long a requested close gives this session's egress queues to
    /// flush before both legs are closed anyway. Default 100 ms.
    ///
    /// Only [`ProxyControl::close_session`](crate::control::ProxyControl::close_session)
    /// reads this. Every other way a session ends — a peer going away, a
    /// hook's [`Action::CloseSession`], the proxy being cancelled — tears
    /// down at once and has always done so. A requested close is different
    /// because somebody is waiting for it to mean something: closing the
    /// instant the request lands discards whatever a `Delay` or a `Hold`
    /// was still holding, and the caller cannot tell that from a session
    /// that had nothing queued.
    ///
    /// The bound is the point. An unbounded drain turns a close into a call
    /// that may never finish: a stream whose destination peer has stopped
    /// reading never empties its queue, and a shaped class whose bucket is
    /// dry empties it only at the configured rate. Whatever is still queued
    /// when this elapses is discarded and reported as
    /// [`ImpairmentKind::QueuedBytesAtTeardown`](crate::event::ImpairmentKind::QueuedBytesAtTeardown),
    /// so bytes that did not make it are named rather than lost quietly,
    /// and the close still carries the code that was asked for.
    ///
    /// # The default is a guess, and here is the measurement that replaces it
    ///
    /// 100 ms was chosen because it is long enough for a loopback flush and
    /// short enough that a caller closing sessions in a loop does not
    /// notice, not because anything was measured. To replace it: pin one
    /// queue state — a fixed object size, a fixed unit count, a fixed
    /// destination window, written down beside the figure — sweep this
    /// timeout across that state, and take the knee at which the **stranded
    /// byte count reaches zero**. Quote the queue state with the number; a
    /// knee measured against 4 KiB objects says nothing about 256 KiB ones.
    ///
    /// Measure stranded *bytes*, never elapsed time. Timing the drain
    /// measures the fixture that filled the queue — how fast the source
    /// wrote, how the destination's flow-control window happened to open —
    /// and a timeout tuned against it is tuned against the harness. The
    /// byte count is the thing that is either zero or not.
    pub drain_timeout: Duration,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            max_pending_bytes: 1024 * 1024,
            max_hold: Duration::from_secs(30),
            drain_timeout: Duration::from_millis(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_contains_objects_structurally() {
        assert!(Interest::STREAMS.contains(Interest::OBJECTS));
        assert!(!Interest::STREAMS.contains(Interest::CONTROL));
        assert!(!Interest::STREAMS.contains(Interest::DATAGRAMS));
    }

    #[test]
    fn none_is_the_default_and_contains_nothing() {
        assert_eq!(Interest::default(), Interest::NONE);
        assert!(Interest::NONE.is_none());
        assert!(!Interest::OBJECTS.is_none());
        assert!(Interest::NONE.contains(Interest::NONE));
        assert!(!Interest::NONE.contains(Interest::OBJECTS));
    }

    #[test]
    fn union_and_bitor_agree() {
        let a = Interest::CONTROL | Interest::DATAGRAMS;
        assert_eq!(a, Interest::CONTROL.union(Interest::DATAGRAMS));
        assert!(a.contains(Interest::CONTROL));
        assert!(a.contains(Interest::DATAGRAMS));
        assert!(!a.contains(Interest::OBJECTS));
    }

    #[test]
    fn a_gate_is_level_triggered() {
        let g = Gate::new();
        assert!(!g.is_released());
        let clone = g.clone();
        g.release();
        assert!(g.is_released());
        assert!(clone.is_released(), "clones share one release");
        g.release();
        assert!(g.is_released(), "release is idempotent");
    }

    #[tokio::test]
    async fn waiting_on_an_already_released_gate_returns_immediately() {
        let g = Gate::new();
        g.release();
        g.wait().await;
    }

    #[test]
    fn modifiers_wrap_the_action_they_are_given() {
        let a = Action::Pass.delayed(Duration::from_millis(5));
        match a {
            Action::Delay { by, then } => {
                assert_eq!(by, Duration::from_millis(5));
                assert!(matches!(*then, Action::Pass));
            }
            other => panic!("expected Delay, got {other:?}"),
        }
        let h = Action::Drop(DropMode::Elide).held(Gate::new());
        match h {
            Action::Hold { gate, then } => {
                assert!(!gate.is_released());
                assert!(matches!(*then, Action::Drop(DropMode::Elide)));
            }
            other => panic!("expected Hold, got {other:?}"),
        }
    }

    #[test]
    fn truncate_carries_its_own_reset_code() {
        let t = Action::Truncate { bytes: 7, code: 0x2 };
        match t {
            Action::Truncate { bytes, code } => {
                assert_eq!(bytes, 7);
                assert_eq!(code, 0x2);
            }
            other => panic!("expected Truncate, got {other:?}"),
        }
    }

    #[test]
    fn egress_defaults_are_one_mib_and_thirty_seconds() {
        let c = EgressConfig::default();
        assert_eq!(c.max_pending_bytes, 1024 * 1024);
        assert_eq!(c.max_hold, Duration::from_secs(30));
    }
}

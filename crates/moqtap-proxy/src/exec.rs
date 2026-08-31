//! The one place an [`Action`] becomes bytes on the wire, or a refusal.
//!
//! # Why this module exists at all
//!
//! Everything the engine can do is already published, by draft and by site,
//! in [`crate::capability`]. This module's whole job is to *not* re-derive
//! any of it: every admission decision here goes through
//! [`crate::capability::classify`], the same function
//! [`Capabilities::supports`](crate::capability::Capabilities::supports)
//! publishes, so the table a scenario author reads before a run and the code
//! that runs it are literally the same code. A cell that the table calls
//! `No(WrongSite { .. })` is refused here *with the refusal value classify
//! returned*, not with one this file rebuilt from the [`Action`] it was
//! handed.
//!
//! That last distinction is load-bearing and easy to lose. At
//! [`Site::Object`] both [`ActionKind::Replace`] and
//! [`ActionKind::ReplaceObject`] classify to the **same** value —
//! `No(WrongSite { site: Object, action: ActionKind::ReplaceObject })` —
//! because `Action::Replace(b)` is the one action value that attempts both
//! kinds at once. If this file synthesized `WrongSite { action:
//! Replace }` from the value it saw, the published `ReplaceObject` cell would
//! become unassertable by `tests/action_matrix.rs`, which compares
//! `refusal == r`. The [`ProxyEvent::ActionRefused`] event's separate
//! `action` field still reports what the value *was* — `Replace` — because
//! that is what the hook returned; only `refusal` is the table's.
//!
//! # Which refusals are this module's to produce
//!
//! Three, and they are the three that depend on the action's payload or on
//! session state rather than on the `(site, kind)` pair:
//!
//! * [`Refusal::WrongComposition`] — what a [`Action::Delay`] /
//!   [`Action::Hold`] wrapped;
//! * [`Refusal::ErrorCodeOutOfRange`] — a stream error code above the QUIC
//!   varint ceiling;
//! * [`Refusal::SessionAlreadyClosing`] — a second
//!   [`Action::CloseSession`].
//!
//! Everything else is propagated from `classify`. The **table-only**
//! refusal [`Refusal::StreamNotFramed`] is never emitted from here —
//! `every_refusal_this_module_emits_is_classifys_or_one_of_its_own_three`
//! below is the falsifiable form of that claim: it sweeps thirteen drafts ×
//! five sites × thirteen action shapes and asserts that neither variant ever
//! reaches an `ActionRefused`, and that all three executor-owned refusals do.
//!
//! # Event cardinality — what this module guarantees
//!
//! * Every **refusal** emits exactly one [`ProxyEvent::ActionRefused`] and
//!   bumps `Counters::actions_refused` exactly once. The two happen in one
//!   function ([`Reporter::refused`]) so they cannot drift, and the counter
//!   is bumped even when the observer is detached — a run with no observer
//!   still counts its refusals.
//! * Every **applied** action emits exactly one [`ProxyEvent::ActionApplied`]
//!   *per phase*.
//! * Every **transport failure on an admitted action** emits exactly one
//!   [`ProxyEvent::ActionFailed`], through [`Reporter::failed`]. This module
//!   does not own the transport, so the caller makes that call; it is the
//!   only shape of report this module publishes rather than performs.
//!
//! ## `Delay { then: Replace }` — two events, and this is the ruling
//!
//! Nothing about the action shape forces the choice, so it is written down
//! here. It is **two** [`ProxyEvent::ActionApplied`] events, distinguishable
//! by their `action` field:
//!
//! 1. at the decision: `{ action: Delay, effect: Queued { release_at } }` —
//!    the modifier was accepted and the unit is in the queue;
//! 2. at the release: `{ action: Replace, effect: Replaced { bytes } }` —
//!    the wire actually changed.
//!
//! One event would force a choice between reporting the deferral and reporting
//! the effect, and a queued unit lost at teardown would have reported a
//! `Replaced` that never happened. Two keep **the engine accepted this** and
//! *"the wire changed"* separately falsifiable, which is exactly what
//! [`ImpairmentKind::QueuedBytesAtTeardown`] is paired against. Stated as the
//! rule a test can count: *one `ActionApplied` for a direct action, two for a
//! `Delay`/`Hold`*.
//!
//! The second event is owed by this module and paid by the caller, because
//! the release happens in `session.rs`'s `select!` arm long after `execute`
//! returned. [`DeferredEffects`] is the ledger: `execute` pushes exactly one
//! entry per [`PendingQueue::push`] and the caller pops exactly one per
//! released unit, then hands it to [`Reporter::applied_deferred`]. Entries
//! are `Option` because a *direct* action queued merely for ordering (a
//! `Pass` behind a delayed unit) reports once at the decision and owes
//! nothing at release.
//!
//! **Units a drain could not flush report nothing further** — that absence
//! is the designed pairing with `QueuedBytesAtTeardown`, not a lost event.
//! See [`DeferredEffects`] for the three-call discipline.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;

use moqtap_codec::version::DraftVersion;

use crate::action::{Action, DropMode, StreamAction};
use crate::capability::{classify, ActionKind, CapCtx, Precondition, Refusal, Site, Support};
use crate::egress::{self, Deferral, Pending, PendingQueue, SessionCloser, Terminal};
use crate::event::{Effect, ImpairmentKind, ProxyEvent, SessionId};
use crate::instrument::Recorder;
use crate::observer::ProxyObserver;
use crate::shape::StreamKey;
use crate::types::{DataStreamType, ObjectMeta, ProxySide};

/// The QUIC varint ceiling, `2^62 - 1`.
///
/// A stream application error code above it cannot be encoded, and quinn
/// would panic or truncate rather than refuse. Checked here, before
/// anything is sent, so the stream stays usable
/// ([`Refusal::ErrorCodeOutOfRange`]).
pub(crate) const MAX_APPLICATION_ERROR_CODE: u64 = (1u64 << 62) - 1;

// ── What an action is being applied to ──────────────────────────────

/// The unit an [`Action`] was returned for, with every fact
/// [`crate::capability::classify`] needs to judge it.
///
/// An enum rather than a struct of `Option`s so that an under-populated
/// [`CapCtx`] is not expressible: each variant carries exactly the facts its
/// site's rules read, and [`Self::cap_ctx`] is the only place they are
/// assembled. That is what makes `Support::Conditional` unreachable at
/// execution time for the four *fact* preconditions — see
/// [`admit_conditional`].
///
/// The two [`StreamAction`] sites are deliberately **not** here: they take
/// [`execute_stream`], so `execute` cannot be called at a site whose hook
/// method returns the other type, and `Support::NotAttemptable` is
/// structurally unreachable from both entry points.
#[derive(Debug)]
pub(crate) enum Target<'a> {
    /// A whole control-stream frame, with its wire bytes.
    Control {
        /// The frame's complete wire bytes.
        raw: Bytes,
    },
    /// One framed object, with its wire bytes.
    Object {
        /// The object's framing, from the framer.
        meta: &'a ObjectMeta,
        /// The stream header's two subgroup-ID mode bits, on drafts 15-19.
        ///
        /// `None` on 07-14, whose header types carry no such pair. Supplying
        /// it on 15-19 is what separates [`Refusal::ReservedHeaderMode`] from
        /// [`Refusal::WouldRedefineSubgroupId`].
        subgroup_id_mode: Option<u8>,
        /// The object's complete wire bytes, framing and payload.
        raw: Bytes,
    },
    /// One datagram.
    Datagram {
        /// The datagram's complete wire bytes.
        raw: Bytes,
        /// `data.len() - cursor.len()` after a **successful**
        /// `AnyDatagramHeader::decode`, or `None` when the header did not
        /// decode.
        ///
        /// This is the raw offset, not the verdict:
        /// [`Self::payload_delimited`] applies draft-14's and the status
        /// datagram's exceptions on top of it.
        header_len: Option<usize>,
        /// Whether the datagram carries an Object Status.
        is_status: bool,
    },
    /// A stream ending. Carries no bytes.
    StreamEnd {
        /// `true` selects the control-stream rules for this site, `false`
        /// the data-stream rules; they differ, so the flag is not cosmetic.
        is_control_stream: bool,
    },
}

impl Target<'_> {
    /// Which published site this unit is at.
    pub(crate) fn site(&self) -> Site {
        match self {
            Target::Control { .. } => Site::Control,
            Target::Object { .. } => Site::Object,
            Target::Datagram { .. } => Site::Datagram,
            Target::StreamEnd { .. } => Site::StreamEnd,
        }
    }

    /// The unit's wire bytes, or `None` at a site that has no unit.
    fn raw(&self) -> Option<Bytes> {
        match self {
            Target::Control { raw } | Target::Object { raw, .. } | Target::Datagram { raw, .. } => {
                Some(raw.clone())
            }
            Target::StreamEnd { .. } => None,
        }
    }

    /// Whether a payload-preserving splice has a locatable boundary.
    ///
    /// At the object site, always: the payload is the trailing field in
    /// every layout on all thirteen drafts and both stream kinds.
    ///
    /// At the datagram site this is where the three exceptions live, and
    /// they live *here* rather than at the call site because getting one
    /// wrong is silent. `header_len` is `data.len() - cursor.len()`, which
    /// is a real boundary only when the decode both succeeded and left the
    /// payload behind:
    ///
    /// * **draft-14** — `AnyDatagramHeader` there is `DatagramObject`, whose
    ///   `decode` ends by reading all remaining bytes, so `header_len`
    ///   is the whole datagram and splicing would emit
    ///   `header ++ old ++ new`;
    /// * **a status datagram** — no payload slot exists at all;
    /// * **`header_len: None`** — the hook fires on an undecodable datagram,
    ///   and there is nothing to splice after.
    fn payload_delimited(&self, draft: DraftVersion) -> Option<bool> {
        match self {
            Target::Object { .. } => Some(true),
            Target::Datagram { header_len, is_status, .. } => {
                Some(header_len.is_some() && draft != DraftVersion::Draft14 && !*is_status)
            }
            Target::Control { .. } | Target::StreamEnd { .. } => None,
        }
    }

    /// Where the payload starts, when [`Self::payload_delimited`] is true.
    fn payload_offset(&self, draft: DraftVersion) -> Option<usize> {
        if self.payload_delimited(draft) != Some(true) {
            return None;
        }
        match self {
            Target::Object { meta, raw, .. } => {
                usize::try_from(meta.payload_len).ok().and_then(|n| raw.len().checked_sub(n))
            }
            Target::Datagram { header_len, .. } => *header_len,
            Target::Control { .. } | Target::StreamEnd { .. } => None,
        }
    }

    /// Assemble the facts [`crate::capability::classify`] reads.
    ///
    /// `replacement_len` is the only field that comes from the *action*
    /// rather than from the unit, which is why it is a parameter.
    fn cap_ctx(&self, draft: DraftVersion, replacement_len: Option<u64>) -> CapCtx {
        let mut cx = CapCtx { draft: Some(draft), replacement_len, ..CapCtx::default() };
        match self {
            Target::Control { .. } => {}
            Target::Object { meta, subgroup_id_mode, .. } => {
                cx.stream_kind = Some(meta.stream_kind);
                cx.index_in_stream = Some(meta.index_in_stream);
                cx.subgroup_id_resolved = Some(meta.subgroup_id.is_some());
                cx.is_status_object = Some(meta.status.is_some());
                cx.payload_len = Some(meta.payload_len);
                cx.payload_delimited = Some(true);
                cx.subgroup_id_mode = *subgroup_id_mode;
            }
            Target::Datagram { is_status, .. } => {
                cx.is_status_object = Some(*is_status);
                cx.payload_delimited = self.payload_delimited(draft);
            }
            Target::StreamEnd { is_control_stream } => {
                cx.is_control_stream = Some(*is_control_stream);
            }
        }
        cx
    }
}

/// Which of the two [`StreamAction`] sites a decision was taken at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamSite {
    /// Between `accept_uni()` and `open_uni()`: no peer stream exists yet.
    Open,
    /// In the `FramerOut::Header` arm: the peer stream exists and has
    /// carried no payload byte.
    Header,
}

impl StreamSite {
    /// The published site this maps to.
    pub(crate) fn site(self) -> Site {
        match self {
            StreamSite::Open => Site::StreamOpen,
            StreamSite::Header => Site::StreamHeader,
        }
    }
}

/// One unit of traffic, at one site, at one instant.
#[derive(Debug)]
pub(crate) struct Unit<'a> {
    /// What the action applies to.
    pub(crate) target: Target<'a>,
    /// The draft this session is running as.
    pub(crate) draft: DraftVersion,
    /// When the unit arrived. [`Action::Delay`] is a deadline measured from
    /// here, not from the moment the hook returned.
    pub(crate) arrived_at: Instant,
}

// ── The engine state `execute` mutates ──────────────────────────────

/// The per-stream deferral state.
///
/// The two halves travel together because [`DeferredEffects`] is only
/// correct if it is pushed in lockstep with [`PendingQueue`]; making them
/// one parameter is the cheapest way to keep a future edit from pushing to
/// one and not the other.
#[derive(Debug)]
pub(crate) struct Queue<'a> {
    /// The stream's pending deque.
    pub(crate) pending: &'a mut PendingQueue,
    /// The release-phase events owed against it.
    pub(crate) deferred: &'a mut DeferredEffects,
}

/// Everything [`execute`] may mutate.
#[derive(Debug)]
pub(crate) struct Engine<'a> {
    /// The stream's queue, or `None` at the datagram site.
    ///
    /// Datagrams are per-connection and unordered by definition, so they
    /// have no queue — and [`Action::Delay`] / [`Action::Hold`] are
    /// refused there, so nothing can need one. `None` is not a degraded
    /// mode; it is the datagram site's shape.
    pub(crate) queue: Option<Queue<'a>>,
    /// Where [`Action::CloseSession`] is recorded.
    pub(crate) closer: &'a SessionCloser,
}

impl Engine<'_> {
    /// Whether a unit written now would overtake something already waiting —
    /// **or** would escape the pacer.
    ///
    /// The second term is the whole of the release wiring's reach into this
    /// module. `Plan::WriteNow` hands bytes straight to the transport, which
    /// is correct and cheap on an unshaped stream and is exactly the path a
    /// token bucket cannot see: `PendingQueue::pop_next_due` is the release
    /// seam, and a unit that never enters the queue never reaches it. So a
    /// shaped queue is *always* busy, and every unit on a shaped stream is
    /// released rather than written.
    ///
    /// Nothing else in this module knows a class, a bucket or a discipline.
    /// The queue tags what it is handed from the class the pipe loop last
    /// resolved, so `push_unit` stays the one place a push and its ledger
    /// entry happen together.
    fn queue_is_busy(&self) -> bool {
        self.queue.as_ref().is_some_and(|q| !q.pending.is_empty() || q.pending.is_shaped())
    }
}

// ── The release-phase ledger ────────────────────────────────────────

/// What a released unit owes the observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Deferred {
    /// The **inner** action's kind — `Replace` for `Delay { then:
    /// Replace(b) }`, which is what distinguishes this event from the
    /// `Queued` one emitted at the decision.
    pub(crate) action: ActionKind,
    /// What the release did to the wire.
    pub(crate) effect: Effect,
}

/// The [`ProxyEvent::ActionApplied`] events owed at release, in queue order.
///
/// A sibling FIFO of [`PendingQueue`] rather than a field on `Pending`,
/// because `Pending` is `egress.rs`'s type and reporting is not its
/// concern — that module deliberately emits no events at all.
///
/// # The three-call discipline
///
/// Exactly one entry is pushed by [`execute`] on every
/// [`PendingQueue::push`], so `self.len() == pending.len()` at every point
/// the caller can observe. In `session.rs`:
///
/// * **release arm** — one [`Self::pop`] per [`PendingQueue::pop_next_due`],
///   and each `Some` goes to [`Reporter::applied_deferred`];
/// * **after a `DrainOutcome::Complete`** — [`Self::take_all`], and every
///   `Some` in it goes to `applied_deferred`: the drain wrote them, in
///   order, and they are owed;
/// * **after any other `DrainOutcome`** — [`Self::clear`], and *nothing* is
///   emitted. Whatever the fallback could not flush is reported once as
///   [`ImpairmentKind::QueuedBytesAtTeardown`] instead. The missing second
///   event is the point: a unit lost at teardown must not have reported a
///   `Replaced` that never reached the wire.
#[derive(Debug, Default)]
pub(crate) struct DeferredEffects {
    q: VecDeque<Option<Deferred>>,
}

impl DeferredEffects {
    /// An empty ledger. Allocates nothing until the first push.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many entries are owed. Equal to `PendingQueue::len()`.
    ///
    /// Read only by the tests below, which assert exactly that equality —
    /// the three-call discipline is what the pipe loops use, and none of
    /// them needs a count. Kept rather than `#[cfg(test)]`d because the
    /// equality is the ledger's whole invariant and a reader looking for it
    /// should find the accessor beside it.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.q.len()
    }

    /// Whether anything is owed. Tests only — see [`Self::len`].
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// The entry for the unit that was just released.
    pub(crate) fn pop(&mut self) -> Option<Deferred> {
        self.q.pop_front().flatten()
    }

    /// Every entry still owed, in order. For a drain that completed.
    pub(crate) fn take_all(&mut self) -> Vec<Deferred> {
        std::mem::take(&mut self.q).into_iter().flatten().collect()
    }

    /// Forget everything owed. For a drain that did not complete.
    pub(crate) fn clear(&mut self) {
        self.q.clear();
    }

    /// Record one entry against one [`PendingQueue::push`].
    fn push(&mut self, entry: Option<Deferred>) {
        self.q.push_back(entry);
    }
}

// ── Reporting ───────────────────────────────────────────────────────

/// Where this module's events and counters go.
///
/// Holds the session identity so no call site has to restate it, and holds
/// the [`Recorder`] so that a counter bump and its event are one function
/// call apart at most. Borrowed rather than owned: it is built per call from
/// `session.rs`'s `ForwardCtx`, which this module deliberately does not
/// name.
#[derive(Clone, Copy)]
pub(crate) struct Reporter<'a> {
    observer: &'a dyn ProxyObserver,
    /// Cached `observer.wants_events()`. Gates **events only** — counters
    /// are unconditional.
    enabled: bool,
    counters: &'a Recorder,
    session_id: SessionId,
    side: ProxySide,
    stream_id: Option<u64>,
}

impl std::fmt::Debug for Reporter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reporter")
            .field("enabled", &self.enabled)
            .field("session_id", &self.session_id)
            .field("side", &self.side)
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl<'a> Reporter<'a> {
    /// Build one for a stream direction, or for the datagram path
    /// (`stream_id: None`).
    pub(crate) fn new(
        observer: &'a dyn ProxyObserver,
        enabled: bool,
        counters: &'a Recorder,
        session_id: SessionId,
        side: ProxySide,
        stream_id: Option<u64>,
    ) -> Self {
        Self { observer, enabled, counters, session_id, side, stream_id }
    }

    /// One [`ProxyEvent::ActionApplied`], for one phase of one action — and
    /// the counter, for the two kinds that have one.
    ///
    /// The bumps sit **outside** the `enabled` gate, on exactly the terms
    /// [`Self::refused`] gives for its own: a session with nobody watching
    /// still counts what it did, and a counter that moved only when someone
    /// was looking would agree with its event by construction rather than by
    /// measurement.
    ///
    /// **Each kind reaches this method once per unit it was applied to**,
    /// which is what makes a match on the kind a count and not an
    /// over-count. `check_composition` refuses `Delay` and `Hold` as an
    /// inner action and refuses `Truncate` and `ResetStream` as a wrapped
    /// one, so a composition can hold neither of these two; and
    /// [`Self::applied_deferred`], which reports the **inner** kind when a
    /// deferred unit is released, can therefore never name either of them.
    /// A delayed unit is counted at its decision and reported again at its
    /// release under whatever it was wrapping, and only the first of those
    /// two is a `Delay`.
    pub(crate) fn applied(&self, site: Site, action: ActionKind, effect: Effect) {
        match action {
            ActionKind::Delay => self.counters.note_unit_delayed(),
            ActionKind::Truncate => self.counters.note_object_truncated(),
            _ => {}
        }
        self.emit(ProxyEvent::ActionApplied {
            session_id: self.session_id,
            side: self.side,
            stream_id: self.stream_id,
            site,
            action,
            effect,
        });
    }

    /// The release-phase half of a [`Action::Delay`] / [`Action::Hold`].
    ///
    /// Always at [`Site::Object`] or [`Site::Control`] — the two sites with
    /// a queue — and always with the **inner** action's kind, which is what
    /// tells it apart from the `Queued` event emitted at the decision.
    pub(crate) fn applied_deferred(&self, site: Site, deferred: Deferred) {
        self.applied(site, deferred.action, deferred.effect);
    }

    /// One [`ProxyEvent::ActionRefused`], and one `actions_refused`.
    ///
    /// The counter is bumped **outside** the `enabled` gate on purpose: a
    /// session with no observer attached still counts what it refused, and
    /// the counter and the event are asserted independently. Bumping it
    /// inside would make the two agree only when someone was watching.
    pub(crate) fn refused(&self, site: Site, action: ActionKind, refusal: Refusal) {
        self.counters.note_action_refused();
        self.emit(ProxyEvent::ActionRefused {
            session_id: self.session_id,
            side: self.side,
            stream_id: self.stream_id,
            site,
            action,
            refusal,
        });
    }

    /// One [`ProxyEvent::ActionFailed`]: the action was admitted and the
    /// transport rejected it.
    ///
    /// Called by `session.rs`, not from here — this module produces the
    /// bytes and the plan, and the caller hands them to the transport, so
    /// only the caller can see the rejection.
    /// It **follows** an `ActionApplied` for the same attempt rather than
    /// replacing one. [`execute`] emits the admission before it returns, and
    /// the caller cannot un-emit it once the transport declines; the two
    /// together say *the engine did it, and it did not arrive*, which is the
    /// whole truth and neither event carries it alone. What this is exclusive
    /// of is `ActionRefused`: a refused unit was never the engine's to place,
    /// so a transport failure on its bytes is
    /// [`ImpairmentKind::DatagramNotSent`] instead.
    ///
    /// Note the event carries no `stream_id`: it is the datagram path's, and
    /// a datagram has no stream to name.
    pub(crate) fn failed(&self, site: Site, action: ActionKind, error: String) {
        self.emit(ProxyEvent::ActionFailed {
            session_id: self.session_id,
            side: self.side,
            site,
            action,
            error,
        });
    }

    /// One [`ProxyEvent::Impairment`], carrying the connection it is about.
    ///
    /// The leg is worked out here, from the kind, rather than being a
    /// parameter each call site supplies. A site knows one thing — the
    /// direction it reads from — and most of what this enum reports is a
    /// failure to *write*, which belongs to the other connection. Asking
    /// twenty sites to make that turn is asking for the one to get it wrong
    /// that nothing downstream can catch: the event still arrives, still
    /// carries a leg, and names the wrong one.
    ///
    /// See [`crate::event::impairment_leg`] for the table and for why four
    /// kinds answer `None`.
    ///
    /// # Ordering
    ///
    /// Every caller of this is past the thing it is reporting: the reset has
    /// been handed to the transport, the datagram has come back refused, the
    /// queue has been abandoned. That is a rule about the call sites rather
    /// than something this function can enforce, and it is stated on
    /// [`ProxyEvent::Impairment`] because it is what an observer is entitled
    /// to rely on.
    pub(crate) fn impairment(&self, kind: ImpairmentKind) {
        let leg = crate::event::impairment_leg(&kind, self.side);
        self.emit(ProxyEvent::Impairment {
            session_id: self.session_id,
            side: self.side,
            leg,
            kind,
        });
    }

    fn emit(&self, event: ProxyEvent) {
        if self.enabled {
            self.observer.on_event(&event);
        }
    }
}

// ── What the caller must do next ────────────────────────────────────

/// The wire operation [`execute`] has decided on but not performed.
///
/// This module owns *what the bytes are*; `session.rs` owns the transport
/// handle and the `await`. Keeping the split here is what lets every rule
/// below be unit-tested with no QUIC, no runtime and no session — the same
/// argument `egress.rs` makes for its [`egress::EgressSink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Hand these bytes to the transport now: `send.write_all` on a stream
    /// site, `send_datagram` at the datagram site.
    ///
    /// A failure at the datagram site is a [`Reporter::failed`], not a
    /// session teardown: one undeliverable datagram must not take the
    /// session with it.
    WriteNow(Bytes),
    /// Nothing goes to the wire on this call. The unit was queued behind
    /// something already waiting, elided, or the site carries no bytes.
    Nothing,
    /// A positional terminal is now at the tail of the queue. Drain
    /// honouring release times; the drain returns
    /// `DrainOutcome::Terminated { forwarded, code }` and the stream is
    /// over — do not `finish()` it.
    Terminal,
    /// Do not forward this stream. Stop the source with `code`; at
    /// [`StreamSite::Header`] also reset the destination, which already
    /// exists and has carried nothing.
    RejectStream {
        /// The application error code.
        code: u64,
    },
    /// Forward this stream, but do not call `dest.open_uni()` until `after`
    /// has elapsed. Only [`StreamSite::Open`] can produce this — by the
    /// header site the peer stream exists, and that site refuses
    /// [`StreamAction::OpenAfter`] with
    /// [`Refusal::WrongSite`](crate::capability::Refusal::WrongSite) rather
    /// than accepting a deferral it cannot perform.
    ///
    /// `session.rs`'s unidirectional accept loop consumes it, and the
    /// deferral reaches the wire: the stream is spawned with **no**
    /// destination handle, and the per-stream task sleeps `after` — racing
    /// the session's cancellation — before it opens one. Nothing is read
    /// from the source in the meantime, so the peer sees no stream at all
    /// for `after` and then a whole one.
    ///
    /// The open happens inside the task but still *before* the first source
    /// byte is read, which is what keeps the two reject sites different on
    /// this topology too: by the time the header decision is taken the peer
    /// stream exists, so a rejection there still resets it.
    OpenStreamAfter {
        /// How long to wait before opening the peer stream.
        after: Duration,
    },
    /// Forward this stream, but write nothing on it until `target` has
    /// ended. An unknown or already-ended target proceeds immediately and
    /// reports `SerializeTargetUnknown` once.
    ///
    /// Consumed at both stream sites, because it defers the first *write*
    /// rather than the stream's existence: from the open site it is carried
    /// into the pipe, which waits before reading; at the header site the
    /// wait happens in the `FramerOut::Header` arm, ahead of the header's
    /// own bytes. Either way the peer stream is already open and silent.
    ///
    /// One stream never waits: the unidirectional control stream of a draft
    /// whose control plane is a pair of them. Holding its first write would
    /// hold SETUP, and the session with it.
    SerializeStreamAfter {
        /// The stream this one waits on.
        target: StreamKey,
    },
    /// A session close was recorded in the [`SessionCloser`], **and the
    /// session token is already cancelled** — `SessionCloser::request`
    /// cancels as it records, so the caller does not have to. Return from
    /// the forwarding task; `run_with_transport` reads the code and reason
    /// back out of the closer at `session.rs:255-256`.
    ///
    /// The unit itself is **not** forwarded: the hook returned a close
    /// *instead of* an action on it.
    CloseSession {
        /// The session termination code.
        code: u32,
        /// The reason phrase.
        reason: Bytes,
    },
}

/// Everything one [`execute`] call decided.
#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    /// What the caller must do with the wire.
    pub(crate) plan: Plan,
    /// The effect that was reported, or the refusal that
    /// was. **Both have already been emitted** — this is returned for the
    /// caller's own bookkeeping and for tests, not as an instruction to
    /// report again.
    pub(crate) result: Result<Effect, Refusal>,
    /// The caller must call `framer.note_elided(meta)` before polling the
    /// framer again.
    ///
    /// True for an admitted [`DropMode::Elide`] at [`Site::Object`],
    /// **including a deferred one**: the framer's cursor is positional and
    /// `note_elided` asserts it names the object most recently emitted, so
    /// it cannot be moved to the release.
    pub(crate) note_elided: bool,
    /// The [`Action::Delay`] arithmetic, on a `Delay` and only on a `Delay`.
    ///
    /// `Deferral::was_clamped()` says whether
    /// [`crate::action::EgressConfig::max_hold`] cut the request short; when
    /// it did, [`ImpairmentKind::HoldClamped`] has **already been emitted**.
    /// Returned so a test can assert the arithmetic without reading the
    /// observer. `None` for every other action, including [`Action::Hold`],
    /// which carries no requested duration to clamp.
    /// Read only by the tests below — the impairment it describes has already
    /// been emitted, so `session.rs` has nothing left to do with it. It stays
    /// on the returned value rather than being dropped because *the clamp is
    /// assertable without an observer* is what makes the arithmetic gateable at
    /// all.
    #[allow(dead_code)]
    pub(crate) clamped: Option<Deferral>,
    /// Set on the push after which the queue stops accepting reads.
    /// **Already reported** as [`ImpairmentKind::EgressQueueFull`], once per
    /// stream. Read only by the tests below, for the same reason
    /// [`Self::clamped`] is.
    #[allow(dead_code)]
    pub(crate) entered_backpressure: bool,
}

impl Outcome {
    /// Whether the action was admitted.
    pub(crate) fn is_applied(&self) -> bool {
        self.result.is_ok()
    }
}

// ── Entry points ────────────────────────────────────────────────────

/// Execute one [`Action`] at one site.
///
/// Emits exactly one [`ProxyEvent::ActionApplied`] or exactly one
/// [`ProxyEvent::ActionRefused`], plus any impairment the decision produced,
/// and returns the wire operation the caller must perform.
///
/// **A refused unit is forwarded unchanged**, through the same
/// queue-or-write-now fork an admitted `Pass` takes — a refusal must not let
/// a unit overtake one already waiting.
///
/// # Order of checks
///
/// 1. [`crate::capability::classify`] on the `(site, kind)` pair. The site's own
///    verdict comes first because it is the one the published table makes,
///    and the table must win: `Delay { then: ResetStream }` at the datagram
///    site is the datagram column's `WrongSite`, not a composition
///    complaint.
/// 2. Composition, for [`Action::Delay`] / [`Action::Hold`], which is
///    validated **before the unit is queued** so a bad composition never
///    reaches the deque and never bumps `egress_items_queued`.
/// 3. The inner action, classified in its own right — `Delay { then:
///    ReplacePayload(b) }` with the wrong length is
///    [`Refusal::LengthChanged`], reported against the *inner* kind, which
///    is the informative one.
/// 4. The numeric code range, then the session-closing latch.
pub(crate) fn execute(
    unit: &Unit<'_>,
    action: Action,
    engine: &mut Engine<'_>,
    report: &Reporter<'_>,
) -> Outcome {
    let site = unit.target.site();
    match plan_action(unit, action, engine, report) {
        Ok(applied) => {
            report.applied(site, applied.action, applied.effect.clone());
            Outcome {
                plan: applied.plan,
                result: Ok(applied.effect),
                note_elided: applied.note_elided,
                clamped: applied.clamped,
                entered_backpressure: applied.entered_backpressure,
            }
        }
        Err(Refused { action, refusal }) => {
            report.refused(site, action, refusal.clone());
            let (plan, entered_backpressure) = forward_unchanged(unit, engine, report);
            Outcome {
                plan,
                result: Err(refusal),
                note_elided: false,
                clamped: None,
                entered_backpressure,
            }
        }
    }
}

/// Execute one [`StreamAction`], at [`Site::StreamOpen`] or
/// [`Site::StreamHeader`].
///
/// A separate entry point rather than a variant of [`Target`], so that the
/// two sites whose hook methods return [`StreamAction`] cannot be handed an
/// [`Action`] and `Support::NotAttemptable` stays unreachable at runtime —
/// a claim made falsifiable by observing **zero** events at those 30-odd
/// site × action cells.
pub(crate) fn execute_stream(
    site: StreamSite,
    draft: DraftVersion,
    action: StreamAction,
    report: &Reporter<'_>,
) -> Outcome {
    let published = site.site();
    let cx = CapCtx { draft: Some(draft), ..CapCtx::default() };
    // Every arm reports `ForwardedVerbatim` except the rejection: the two
    // deferral decisions — `OpenAfter` and `SerializeAfter` — change *when*
    // the stream exists or *when* it first writes, never a byte of it. A
    // separate `Effect` would claim a content change that never happens.
    let (kind, effect) = match action {
        StreamAction::Open => (ActionKind::Open, Effect::ForwardedVerbatim),
        StreamAction::Reject { code } => (ActionKind::Reject, Effect::StreamRejected { code }),
        StreamAction::OpenAfter(_) => (ActionKind::OpenAfter, Effect::ForwardedVerbatim),
        StreamAction::SerializeAfter(_) => (ActionKind::SerializeAfter, Effect::ForwardedVerbatim),
    };

    let refuse = |refusal: Refusal| {
        report.refused(published, kind, refusal.clone());
        Outcome {
            plan: Plan::Nothing,
            result: Err(refusal),
            note_elided: false,
            clamped: None,
            entered_backpressure: false,
        }
    };

    if let Err(refusal) = admit(classify(published, kind, &cx)) {
        return refuse(refusal);
    }
    if let StreamAction::Reject { code } = action {
        if let Err(refusal) = check_error_code(code) {
            return refuse(refusal);
        }
    }

    report.applied(published, kind, effect.clone());
    Outcome {
        plan: match action {
            StreamAction::Open => Plan::Nothing,
            StreamAction::Reject { code } => Plan::RejectStream { code },
            StreamAction::OpenAfter(after) => Plan::OpenStreamAfter { after },
            StreamAction::SerializeAfter(target) => Plan::SerializeStreamAfter { target },
        },
        result: Ok(effect),
        note_elided: false,
        clamped: None,
        entered_backpressure: false,
    }
}

/// Run the elide guards for a **shaper's** tail-drop, and say whether the
/// unit may be discarded.
///
/// [`Overflow::DropTail`](crate::shape::Overflow::DropTail) is sound
/// precisely because it discards the *arriving* unit at admission time,
/// where `framer.note_elided` is still legal — the framer's positional
/// cursor has not moved past the object, so the successor's delta fix-up
/// can still be armed. That is the same place `Action::Drop(DropMode::Elide)`
/// is judged, so it is judged by the same code: this function asks
/// [`crate::capability::classify`] exactly what `prepare_content` asks it,
/// and the three elide guards — `WouldRedefineSubgroupId`,
/// `WouldDestroyStatusObject`, `ReservedHeaderMode` — apply unchanged.
///
/// # What a refusal means, and why it is reported
///
/// `false` means an elide guard refused, and the caller must **admit the
/// unit anyway** — the queue overshoots its depth by one. A shaper may not
/// corrupt a stream to honour a depth limit: eliding an object the framer
/// cannot renumber around does not lose one object, it makes every
/// successor decode with a wrong absolute ID on drafts 14-19.
///
/// The refusal is reported as an ordinary
/// [`ProxyEvent::ActionRefused`] and bumps `Counters::actions_refused`,
/// through the same [`Reporter::refused`] every other refusal takes. That
/// is why any test asserting an exact drop count must assert
/// `actions_refused == 0` in the same body: without it, the
/// arrivals-minus-drops arithmetic is off by the number of refusals and
/// "no guard fired" is hoped rather than checked.
///
/// # Why this is not `execute(.., Action::Drop(DropMode::Elide), ..)`
///
/// Because no hook returned one. Routing a configured drop through
/// `execute` would emit `ActionApplied { action: DropElide }` per dropped
/// unit — a per-object event claiming a hook decision that never happened,
/// on a path whose reporting is capped at once per stream per outcome. What
/// the shaper owes
/// the observer is [`ProxyEvent::Shaped`], which the caller emits; what it
/// owes on a *refusal* is the refusal, which is here.
pub(crate) fn shape_elide(unit: &Unit<'_>, report: &Reporter<'_>) -> bool {
    debug_assert!(
        matches!(unit.target, Target::Object { .. }),
        "only a framed object can be tail-dropped: the shaper never sees anything else",
    );
    match admit_kind(Site::Object, ActionKind::DropElide, unit, None) {
        Ok(()) => {
            report.counters.note_object_elided();
            true
        }
        Err(Refused { action, refusal }) => {
            report.refused(Site::Object, action, refusal);
            false
        }
    }
}

// ── Planning ────────────────────────────────────────────────────────

/// A refusal, and the kind to name in the event.
///
/// The two are separate because they disagree exactly once, and that
/// disagreement is the point of the module note: `Action::Replace(b)` at
/// `Site::Object` is refused with `WrongSite { action: ReplaceObject }` —
/// `classify`'s value, which the published `ReplaceObject` cell is compared
/// against — while the event says `action: Replace`, which is what the hook
/// returned.
#[derive(Debug, Clone)]
struct Refused {
    action: ActionKind,
    refusal: Refusal,
}

impl Refused {
    fn new(action: ActionKind, refusal: Refusal) -> Self {
        Self { action, refusal }
    }
}

/// An admitted action, before its event is emitted.
#[derive(Debug)]
struct AppliedPlan {
    action: ActionKind,
    effect: Effect,
    plan: Plan,
    note_elided: bool,
    clamped: Option<Deferral>,
    entered_backpressure: bool,
}

impl AppliedPlan {
    fn simple(action: ActionKind, effect: Effect, plan: Plan) -> Self {
        Self {
            action,
            effect,
            plan,
            note_elided: false,
            clamped: None,
            entered_backpressure: false,
        }
    }
}

/// What a *content* action makes of the unit — the four things a
/// [`Action::Delay`] / [`Action::Hold`] may wrap, and the same four when
/// they stand alone.
#[derive(Debug)]
struct Content {
    kind: ActionKind,
    payload: Payload,
    effect: Effect,
    note_elided: bool,
}

/// The bytes a content action produced, or their absence.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Payload {
    /// Write exactly these bytes.
    Write(Bytes),
    /// Write nothing. Still takes an ordering slot when the queue is busy:
    /// the drop was decided at a point in the stream, and letting it out of
    /// band would write a later unit before an earlier one.
    Elide,
    /// There is no unit. [`Site::StreamEnd`] only.
    ///
    /// Distinct from [`Self::Elide`] because a stream ending has no place in
    /// the deque at all — pushing an empty ordering slot behind a delayed
    /// object would owe a ledger entry for a unit that does not exist.
    Absent,
}

fn plan_action(
    unit: &Unit<'_>,
    action: Action,
    engine: &mut Engine<'_>,
    report: &Reporter<'_>,
) -> Result<AppliedPlan, Refused> {
    let site = unit.target.site();
    match action {
        Action::Delay { by, then } => {
            admit_kind(site, ActionKind::Delay, unit, None)?;
            check_composition(&then)?;
            // `prepare_content` first, and the clamp report strictly after
            // it. Every refusal a `Delay` can earn is taken above this line,
            // so an impairment emitted below it is reporting a hold that the
            // engine really did apply — see
            // `a_refused_action_reports_its_refusal_and_no_impairment`,
            // which is red the moment these two are swapped.
            let content = prepare_content(unit, &then, report)?;
            let config = queue_config(engine);
            let deferral = egress::defer_by(unit.arrived_at, by, &config);
            if deferral.was_clamped() {
                // `Some`, always: a `Delay` names its own duration, so this is
                // the arm of the report that has a figure to quote. The
                // absent case belongs to a shaped release whose bucket named
                // no refill instant at all.
                report.impairment(ImpairmentKind::HoldClamped {
                    requested: Some(deferral.requested),
                    applied: deferral.applied,
                });
            }
            let pending = pending_for(&content.payload, deferral.release_at);
            let push = push_unit(engine, report, pending, Some(content.deferred()));
            Ok(AppliedPlan {
                action: ActionKind::Delay,
                effect: Effect::Queued { release_at: push.release_at },
                plan: Plan::Nothing,
                note_elided: content.note_elided,
                clamped: Some(deferral),
                entered_backpressure: push.entered_backpressure,
            })
        }
        Action::Hold { gate, then } => {
            admit_kind(site, ActionKind::Hold, unit, None)?;
            check_composition(&then)?;
            let content = prepare_content(unit, &then, report)?;
            let config = queue_config(engine);
            let ceiling = egress::hold_ceiling(unit.arrived_at, &config);
            let pending = pending_for(&content.payload, ceiling).with_gate(gate);
            let push = push_unit(engine, report, pending, Some(content.deferred()));
            Ok(AppliedPlan {
                action: ActionKind::Hold,
                effect: Effect::Queued { release_at: push.release_at },
                plan: Plan::Nothing,
                note_elided: content.note_elided,
                clamped: None,
                entered_backpressure: push.entered_backpressure,
            })
        }
        Action::Truncate { bytes, code } => {
            admit_kind(site, ActionKind::Truncate, unit, None)?;
            check_error_code(code).map_err(|r| Refused::new(ActionKind::Truncate, r))?;
            let raw = unit.target.raw().unwrap_or_default();
            let prefix = raw.slice(..bytes.min(raw.len()));
            let forwarded = prefix.len();
            let push = push_unit(
                engine,
                report,
                Pending::terminal(Terminal::Truncate { prefix, code }),
                None,
            );
            Ok(AppliedPlan {
                action: ActionKind::Truncate,
                effect: Effect::Truncated {
                    forwarded,
                    code,
                    code_defined: stream_reset_code_defined(unit.draft),
                },
                plan: Plan::Terminal,
                note_elided: false,
                clamped: None,
                entered_backpressure: push.entered_backpressure,
            })
        }
        Action::ResetStream { code } => {
            admit_kind(site, ActionKind::ResetStream, unit, None)?;
            check_error_code(code).map_err(|r| Refused::new(ActionKind::ResetStream, r))?;
            let push = push_unit(engine, report, Pending::terminal(Terminal::Reset { code }), None);
            Ok(AppliedPlan {
                action: ActionKind::ResetStream,
                effect: Effect::StreamReset {
                    code,
                    code_defined: stream_reset_code_defined(unit.draft),
                },
                plan: Plan::Terminal,
                note_elided: false,
                clamped: None,
                entered_backpressure: push.entered_backpressure,
            })
        }
        Action::CloseSession { code, reason } => {
            admit_kind(site, ActionKind::CloseSession, unit, None)?;
            if !engine.closer.request(code, reason.clone()) {
                return Err(Refused::new(ActionKind::CloseSession, Refusal::SessionAlreadyClosing));
            }
            Ok(AppliedPlan::simple(
                ActionKind::CloseSession,
                Effect::SessionClosing { code },
                Plan::CloseSession { code, reason },
            ))
        }
        content_action => {
            let content = prepare_content(unit, &content_action, report)?;
            let (plan, entered_backpressure) = commit_now(&content.payload, engine, report);
            Ok(AppliedPlan {
                action: content.kind,
                effect: content.effect,
                plan,
                note_elided: content.note_elided,
                clamped: None,
                entered_backpressure,
            })
        }
    }
}

impl Content {
    /// The event this content owes when its unit is released.
    fn deferred(&self) -> Deferred {
        Deferred { action: self.kind, effect: self.effect.clone() }
    }
}

/// Classify and realise one content action.
///
/// The only place [`Action::Pass`], [`Action::Replace`],
/// [`Action::ReplacePayload`] and [`Action::Drop`] turn into bytes, reached
/// both directly and through a [`Action::Delay`] / [`Action::Hold`].
fn prepare_content(
    unit: &Unit<'_>,
    action: &Action,
    report: &Reporter<'_>,
) -> Result<Content, Refused> {
    let site = unit.target.site();
    match action {
        Action::Pass => {
            admit_kind(site, ActionKind::Pass, unit, None)?;
            Ok(Content {
                kind: ActionKind::Pass,
                payload: match unit.target.raw() {
                    Some(raw) => Payload::Write(raw),
                    // `Site::StreamEnd`: passing a stream ending is today's
                    // behaviour at all four FIN sites, and today's behaviour
                    // is to do nothing.
                    None => Payload::Absent,
                },
                effect: Effect::ForwardedVerbatim,
                note_elided: false,
            })
        }
        Action::Replace(replacement) => {
            admit_kind(site, ActionKind::Replace, unit, None)?;
            Ok(Content {
                kind: ActionKind::Replace,
                payload: Payload::Write(replacement.clone()),
                effect: Effect::Replaced { bytes: replacement.len() },
                note_elided: false,
            })
        }
        Action::ReplacePayload(replacement) => {
            let replacement_len = u64::try_from(replacement.len()).ok();
            admit_kind(site, ActionKind::ReplacePayload, unit, replacement_len)?;
            let raw = unit.target.raw().unwrap_or_default();
            // `admit_kind` returning `Ok` is what guarantees the offset
            // exists: `Precondition::DatagramPayloadDelimited` is the
            // datagram half and the object site is unconditionally
            // delimited. The `unwrap_or` is a total-function guard,
            // not a fallback with meaning.
            let offset = unit.target.payload_offset(unit.draft).unwrap_or(raw.len());
            let mut spliced = Vec::with_capacity(offset + replacement.len());
            spliced.extend_from_slice(&raw[..offset]);
            spliced.extend_from_slice(replacement);
            let spliced = Bytes::from(spliced);
            Ok(Content {
                kind: ActionKind::ReplacePayload,
                payload: Payload::Write(spliced.clone()),
                effect: Effect::Replaced { bytes: spliced.len() },
                note_elided: false,
            })
        }
        Action::Drop(DropMode::Elide) => {
            admit_kind(site, ActionKind::DropElide, unit, None)?;
            let at_object_site = matches!(unit.target, Target::Object { .. });
            let effect = if at_object_site {
                report.counters.note_object_elided();
                Effect::Elided { renumbered_successor: elide_renumbers_successor(unit) }
            } else {
                // A control frame or a datagram has no object slot to
                // renumber, so the mode is ignored rather than refused and
                // the honest report is that the unit is gone.
                Effect::Dropped
            };
            Ok(Content {
                kind: ActionKind::DropElide,
                payload: Payload::Elide,
                effect,
                note_elided: at_object_site,
            })
        }
        // Reachable only as a `Delay`/`Hold` inner action, and
        // `check_composition` rejects every one of these before we get
        // here. Kept total rather than panicking: a capability engine that
        // can panic is worse than one that repeats itself.
        Action::Delay { .. } | Action::Hold { .. } => {
            Err(Refused::new(kind_of(action), NESTED_MODIFIER))
        }
        Action::Truncate { .. } | Action::ResetStream { .. } => {
            Err(Refused::new(kind_of(action), WRAPPED_TERMINAL))
        }
        Action::CloseSession { .. } => Err(Refused::new(kind_of(action), WRAPPED_CLOSE)),
    }
}

// ── Admission ───────────────────────────────────────────────────────

/// Ask [`crate::capability::classify`], and turn its verdict into an admission.
fn admit_kind(
    site: Site,
    kind: ActionKind,
    unit: &Unit<'_>,
    replacement_len: Option<u64>,
) -> Result<(), Refused> {
    let cx = unit.target.cap_ctx(unit.draft, replacement_len);
    admit(classify(site, kind, &cx)).map_err(|refusal| Refused::new(kind, refusal))
}

/// The five verdicts, as an admission decision.
///
/// `NotAttemptable` and `Unreachable` are structurally unreachable from both
/// entry points — the first because the two `StreamAction` sites take
/// [`execute_stream`] and the four constructor-less kinds have no `Action`
/// value, the second because the hook is never invoked on a bypassed stream.
/// They are handled rather than `unreachable!()`d for the same reason
/// `capability.rs` has `filtered_earlier`: a total function beats a
/// panicking one on a forwarding task.
fn admit(support: Support) -> Result<(), Refusal> {
    match support {
        Support::Yes => Ok(()),
        Support::No(refusal) => Err(refusal),
        Support::Conditional(precondition) => admit_conditional(precondition),
        Support::NotAttemptable { refusal, .. } | Support::Unreachable { refusal, .. } => {
            Err(refusal)
        }
    }
}

/// What a surviving [`Support::Conditional`] means *at execution time*.
///
/// One of the five preconditions is environmental — it cannot be settled
/// from the unit, so the table publishes it as conditional forever and the
/// engine admits the action:
///
/// * [`Precondition::WithinMaxDatagramSize`] — no transport in the workspace
///   exposes a maximum datagram size, so the verdict arrives as
///   `send_datagram` failing, which is a [`Reporter::failed`], not a
///   refusal, and the session survives it.
///
/// The other four are *facts about the unit*, and [`Target`] supplies every
/// one of them, so reaching those arms means a `CapCtx` was assembled
/// somewhere other than [`Target::cap_ctx`].
/// `no_fact_precondition_survives_execution` sweeps every site × every
/// action with fully-populated targets and asserts they never arrive, which
/// is what makes the `debug_assert` a claim rather than a hope.
fn admit_conditional(precondition: Precondition) -> Result<(), Refusal> {
    match precondition {
        Precondition::WithinMaxDatagramSize => Ok(()),
        Precondition::ReplacementLengthEqualsPayload
        | Precondition::NotFirstObjectOfImplicitSubgroup
        | Precondition::NotAStatusObject
        | Precondition::DatagramPayloadDelimited => {
            debug_assert!(
                false,
                "exec supplies every per-unit fact; {precondition:?} means a CapCtx \
                 was built outside Target::cap_ctx",
            );
            Ok(())
        }
    }
}

/// *Composition*: a modifier accepts only a content action.
///
/// Checked **before the unit is queued**, so a bad composition never reaches
/// the deque and `egress_items_queued` does not move — which is what
/// `a_delay_wrapping_a_terminal_is_refused_before_it_is_queued` asserts.
///
/// The four legal inner actions are [`Action::Pass`],
/// [`Action::Replace`], [`Action::ReplacePayload`] and [`Action::Drop`].
/// [`Action::Drop`] belongs on it, and the fact that it does is worth one
/// sentence here because the `Action` rustdoc once said the opposite: a
/// deferred drop is **not** a no-op, because it holds an ordering slot for
/// the whole of its delay and [`PendingQueue::pop_next_due`] only ever
/// considers the front. The unit is deleted *and* the rest of the stream
/// is head-of-line-blocked, which is the impairment the composition exists
/// to express.
/// `a_delayed_drop_is_admitted_and_blocks_the_stream_behind_it` is the
/// falsifiable form of that claim — it asserts the successor's clamp, not
/// merely the admission, so a revision that queued the drop without an
/// ordering slot would still fail it.
fn check_composition(inner: &Action) -> Result<(), Refused> {
    let refusal = match inner {
        Action::Pass | Action::Replace(_) | Action::ReplacePayload(_) | Action::Drop(_) => {
            return Ok(())
        }
        Action::Delay { .. } | Action::Hold { .. } => NESTED_MODIFIER,
        Action::Truncate { .. } | Action::ResetStream { .. } => WRAPPED_TERMINAL,
        Action::CloseSession { .. } => WRAPPED_CLOSE,
    };
    Err(Refused::new(kind_of(inner), refusal))
}

/// A stream application error code must fit a QUIC varint.
fn check_error_code(code: u64) -> Result<(), Refusal> {
    if code > MAX_APPLICATION_ERROR_CODE {
        Err(Refusal::ErrorCodeOutOfRange { code })
    } else {
        Ok(())
    }
}

const NESTED_MODIFIER: Refusal =
    Refusal::WrongComposition { detail: "Delay or Hold wrapping another Delay or Hold" };
const WRAPPED_TERMINAL: Refusal =
    Refusal::WrongComposition { detail: "Delay or Hold wrapping Truncate or ResetStream" };
const WRAPPED_CLOSE: Refusal =
    Refusal::WrongComposition { detail: "Delay or Hold wrapping CloseSession" };

// ── Committing to the wire or to the queue ──────────────────────────

/// Write now, or take an ordering slot behind what is already waiting.
///
/// A unit that is due now on an **empty** queue is not pushed at all —
/// it is written inline in the read arm, which is today's code and today's
/// cost. On a **non-empty** queue it must be pushed, or it overtakes the
/// units ahead of it; the deque is what holds it back, and its own deadline
/// stays `now` (see [`PendingQueue::push`]) so that it goes out the instant
/// the units ahead of it have.
fn commit_now(payload: &Payload, engine: &mut Engine<'_>, report: &Reporter<'_>) -> (Plan, bool) {
    if matches!(payload, Payload::Absent) || !engine.queue_is_busy() {
        return (
            match payload {
                Payload::Write(raw) => Plan::WriteNow(raw.clone()),
                Payload::Elide | Payload::Absent => Plan::Nothing,
            },
            false,
        );
    }
    let push = push_unit(engine, report, pending_for(payload, Instant::now()), None);
    (Plan::Nothing, push.entered_backpressure)
}

/// The refusal path's write: the unit goes out unchanged, through the same
/// fork an admitted [`Action::Pass`] takes.
fn forward_unchanged(
    unit: &Unit<'_>,
    engine: &mut Engine<'_>,
    report: &Reporter<'_>,
) -> (Plan, bool) {
    match unit.target.raw() {
        Some(raw) => commit_now(&Payload::Write(raw), engine, report),
        // `Site::StreamEnd` carries no unit: refusing there leaves the FIN
        // exactly as it was, which is `Pass`'s behaviour and today's.
        None => (Plan::Nothing, false),
    }
}

fn pending_for(payload: &Payload, release_at: Instant) -> Pending {
    match payload {
        Payload::Write(raw) => Pending::bytes(raw.clone(), release_at),
        // `Absent` cannot be deferred: the only site that produces it,
        // `Site::StreamEnd`, refuses `Delay` and `Hold` outright, and
        // `commit_now` short-circuits it before it reaches here.
        Payload::Elide | Payload::Absent => Pending::elided(release_at),
    }
}

/// Push one unit and record exactly one ledger entry against it.
///
/// The single place both happen, so `DeferredEffects::len() ==
/// PendingQueue::len()` holds by construction rather than by review.
fn push_unit(
    engine: &mut Engine<'_>,
    report: &Reporter<'_>,
    unit: Pending,
    owed: Option<Deferred>,
) -> egress::Push {
    let Some(queue) = engine.queue.as_mut() else {
        debug_assert!(
            false,
            "the datagram site has no queue, and Delay/Hold/Truncate/ResetStream \
             are refused there — nothing may reach a push",
        );
        return egress::Push { release_at: Instant::now(), entered_backpressure: false };
    };
    let push = queue.pending.push(unit);
    queue.deferred.push(owed);
    if push.entered_backpressure {
        if let Some(stream_id) = report.stream_id {
            report.impairment(ImpairmentKind::EgressQueueFull { stream_id });
        }
    }
    push
}

/// Queue bytes the hook was never shown, on a **shaped** stream.
///
/// The counterpart of `session.rs`'s `write_in_order`, which drains and then
/// writes inline. That is right on an unshaped stream and wrong on a shaped
/// one twice over: it would let a stream header or an oversized object's
/// passthrough chunk escape the pacer, and — worse — the drain it runs first
/// honours release times, so on a paced queue it would block the read arm
/// for as long as the bucket took, inside a `select!` arm body that polls no
/// other branch.
///
/// Lives here rather than in `session.rs` for the reason `write_in_order`'s
/// own doc gives: `DeferredEffects`'s push is this module's, so the ledger
/// and the deque can only move together. The entry is `None` — these bytes
/// were never a hook decision, so nothing is owed at release.
///
/// The class is not a parameter: the queue carries the one the pipe loop
/// most recently resolved (`PendingQueue::tag_unit`), which for a header or
/// a passthrough chunk is `Class::Unshapeable`.
pub(crate) fn enqueue_unshown(
    pending: &mut PendingQueue,
    deferred: &mut DeferredEffects,
    raw: Bytes,
    report: &Reporter<'_>,
) {
    let push = pending.push(Pending::bytes(raw, Instant::now()));
    deferred.push(None);
    if push.entered_backpressure {
        if let Some(stream_id) = report.stream_id {
            report.impairment(ImpairmentKind::EgressQueueFull { stream_id });
        }
    }
}

/// The queue's knobs, or the defaults when there is no queue.
///
/// The `None` arm is the datagram site, where `Delay` and `Hold` are refused
/// before they can ask — it exists so this is an expression rather than a
/// panic.
fn queue_config(engine: &Engine<'_>) -> crate::action::EgressConfig {
    const FALLBACK: crate::action::EgressConfig = crate::action::EgressConfig {
        max_pending_bytes: 1024 * 1024,
        max_hold: std::time::Duration::from_secs(30),
        // Never read here: the drain window belongs to a session close and
        // this fallback exists for the datagram site, which has no queue.
        // Restated rather than elided because `EgressConfig::default()` is
        // not a `const fn`, so this literal has to name every field.
        drain_timeout: std::time::Duration::from_millis(100),
    };
    match engine.queue.as_ref() {
        Some(queue) => *queue.pending.config(),
        None => FALLBACK,
    }
}

// ── Per-draft facts this module needs ───────────────────────────────

/// Whether the draft defines a stream-reset error code vocabulary.
///
/// Drafts 07-10 do not, so the reset still executes with the code the
/// action named and [`Effect::StreamReset`] / [`Effect::Truncated`] report
/// `code_defined: false` — the code is a choice there, not a claim.
const fn stream_reset_code_defined(draft: DraftVersion) -> bool {
    !matches!(
        draft,
        DraftVersion::Draft07
            | DraftVersion::Draft08
            | DraftVersion::Draft09
            | DraftVersion::Draft10
    )
}

/// Whether eliding this object leaves the framer owing a successor fix-up.
///
/// Mirrors `ObjectFramer::elide_owes_a_fixup`, which is private to
/// `framer.rs`, and the two stream kinds owe it from different drafts. A
/// **subgroup** stream delta-encodes object IDs from draft-14, so the one
/// object following an elided run has its leading ID varint rewritten. A
/// **fetch** stream owes it from draft-15, where a Serialization Flags field
/// lets a frame take any of its Group ID, Subgroup ID, Object ID and
/// Priority from the frame before it, and the payment is a re-encode of the
/// survivor's whole framing rather than a rewrite of one varint. Drafts
/// 07-13 subgroup streams and 07-14 fetch streams state every field
/// outright and owe nothing.
///
/// Duplicated rather than borrowed because the value is needed *before*
/// `framer.note_elided(meta)` is called — the effect is reported at the
/// decision, and `note_elided` is what arms the fix-up.
/// `elide_renumbering_names_the_drafts_that_owe_a_fixup` restates the table
/// explicitly; see its comment for why it cannot ask the framer directly,
/// and what covers the gap.
fn elide_renumbers_successor(unit: &Unit<'_>) -> bool {
    let Target::Object { meta, .. } = &unit.target else {
        return false;
    };
    match meta.stream_kind {
        DataStreamType::Subgroup => matches!(
            unit.draft,
            DraftVersion::Draft14
                | DraftVersion::Draft15
                | DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
        ),
        DataStreamType::Fetch => matches!(
            unit.draft,
            DraftVersion::Draft15
                | DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
        ),
    }
}

/// The [`ActionKind`] an [`Action`] value attempts.
///
/// `Action::Replace(b)` maps to [`ActionKind::Replace`] here even at
/// [`Site::Object`], where it also carries [`ActionKind::ReplaceObject`].
/// That is deliberate: this function answers *what the hook returned*, which
/// is the `ActionRefused` event's `action` field. The *refusal* comes from
/// `classify`, which names `ReplaceObject`, and the two are compared against
/// different things: the event field against what the hook returned, the
/// refusal against the published table.
const fn kind_of(action: &Action) -> ActionKind {
    match action {
        Action::Pass => ActionKind::Pass,
        Action::Replace(_) => ActionKind::Replace,
        Action::ReplacePayload(_) => ActionKind::ReplacePayload,
        Action::Delay { .. } => ActionKind::Delay,
        Action::Hold { .. } => ActionKind::Hold,
        Action::Drop(DropMode::Elide) => ActionKind::DropElide,
        Action::Truncate { .. } => ActionKind::Truncate,
        Action::ResetStream { .. } => ActionKind::ResetStream,
        Action::CloseSession { .. } => ActionKind::CloseSession,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::action::{EgressConfig, Gate};
    use crate::egress::Item;
    use crate::types::Leg;
    use tokio_util::sync::CancellationToken;

    // ── harness ─────────────────────────────────────────────────────

    #[derive(Default)]
    struct Recording {
        events: Mutex<Vec<ProxyEvent>>,
    }

    impl ProxyObserver for Recording {
        fn on_event(&self, event: &ProxyEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    impl Recording {
        fn events(&self) -> Vec<ProxyEvent> {
            self.events.lock().unwrap().clone()
        }
        fn applied(&self) -> Vec<(Site, ActionKind, Effect)> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    ProxyEvent::ActionApplied { site, action, effect, .. } => {
                        Some((site, action, effect))
                    }
                    _ => None,
                })
                .collect()
        }
        fn refused(&self) -> Vec<(Site, ActionKind, Refusal)> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    ProxyEvent::ActionRefused { site, action, refusal, .. } => {
                        Some((site, action, refusal))
                    }
                    _ => None,
                })
                .collect()
        }
        fn impairments(&self) -> Vec<ImpairmentKind> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    ProxyEvent::Impairment { kind, .. } => Some(kind),
                    _ => None,
                })
                .collect()
        }

        /// Every impairment as the pair a reader actually needs — which
        /// connection it is about, and what it says — in emission order.
        ///
        /// A `Vec` rather than a set, and paired rather than two lists,
        /// because both halves of the claim are ordering claims: an
        /// impairment reports something that has already happened, so the
        /// order they arrive in is the order the proxy did things in, and a
        /// kind separated from its leg is a number without a label.
        fn attributed_impairments(&self) -> Vec<(Option<Leg>, ImpairmentKind)> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    ProxyEvent::Impairment { leg, kind, .. } => Some((leg, kind)),
                    _ => None,
                })
                .collect()
        }
    }

    /// Everything a call needs, owned, so a test is four lines.
    struct Harness {
        observer: Arc<Recording>,
        counters: Arc<Recorder>,
        pending: PendingQueue,
        deferred: DeferredEffects,
        closer: SessionCloser,
        cancel: CancellationToken,
        /// The side the pipe this harness stands in for reads from.
        ///
        /// `ClientToProxy` unless a test says otherwise, which is the shape
        /// every test here had before the leg attribution existed. It is a
        /// field rather than a per-call argument because a real pipe fixes
        /// its side once, at the top of the forwarding task, and a test that
        /// could vary it per call would be able to build an event sequence
        /// no session can produce.
        side: ProxySide,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_config(EgressConfig::default())
        }

        fn with_config(config: EgressConfig) -> Self {
            let counters = Arc::new(Recorder::new());
            let cancel = CancellationToken::new();
            Self {
                observer: Arc::new(Recording::default()),
                pending: PendingQueue::new(config, counters.clone()),
                deferred: DeferredEffects::new(),
                closer: SessionCloser::new(cancel.clone()),
                counters,
                cancel,
                side: ProxySide::ClientToProxy,
            }
        }

        /// The same harness, standing in for the pipe that reads from the
        /// relay instead of the one that reads from the client.
        fn reading_from(mut self, side: ProxySide) -> Self {
            self.side = side;
            self
        }

        fn report(&self) -> Reporter<'_> {
            Reporter::new(
                self.observer.as_ref(),
                true,
                self.counters.as_ref(),
                SessionId(1),
                self.side,
                Some(4),
            )
        }

        /// A reporter with no stream, as the datagram path builds one.
        fn datagram_report(&self) -> Reporter<'_> {
            Reporter::new(
                self.observer.as_ref(),
                true,
                self.counters.as_ref(),
                SessionId(1),
                self.side,
                None,
            )
        }

        /// The datagram site's shape: no queue at all.
        fn datagram_engine(&self) -> Engine<'_> {
            Engine { queue: None, closer: &self.closer }
        }

        /// The same call on a session **nobody attached an observer to**:
        /// `wants_events()` answered `false`, so not one event is emitted.
        ///
        /// The counters are asserted through it, which is the only way to
        /// tell a figure that was measured from one that agrees with its own
        /// event because the same `if` guarded both.
        fn run_unwatched(&mut self, unit: &Unit<'_>, action: Action) -> Outcome {
            let report = Reporter::new(
                self.observer.as_ref(),
                false,
                self.counters.as_ref(),
                SessionId(1),
                self.side,
                Some(4),
            );
            let mut engine = Engine {
                queue: Some(Queue { pending: &mut self.pending, deferred: &mut self.deferred }),
                closer: &self.closer,
            };
            execute(unit, action, &mut engine, &report)
        }

        fn run(&mut self, unit: &Unit<'_>, action: Action) -> Outcome {
            let report = Reporter::new(
                self.observer.as_ref(),
                true,
                self.counters.as_ref(),
                SessionId(1),
                self.side,
                Some(4),
            );
            let mut engine = Engine {
                queue: Some(Queue { pending: &mut self.pending, deferred: &mut self.deferred }),
                closer: &self.closer,
            };
            execute(unit, action, &mut engine, &report)
        }
    }

    fn meta(draft: DraftVersion) -> ObjectMeta {
        ObjectMeta {
            draft,
            stream_kind: DataStreamType::Subgroup,
            track_alias: Some(7),
            group_id: 1,
            subgroup_id: Some(0),
            object_id: 3,
            publisher_priority: Some(128),
            index_in_stream: 3,
            payload_len: 4,
            status: None,
            end_of_range: None,
        }
    }

    /// `[0xAA; 6]` framing followed by a four-byte payload.
    fn object_bytes() -> Bytes {
        Bytes::from_static(&[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, b'p', b'a', b'y', b'l'])
    }

    fn object_unit<'a>(m: &'a ObjectMeta, at: Instant) -> Unit<'a> {
        Unit {
            target: Target::Object { meta: m, subgroup_id_mode: None, raw: object_bytes() },
            draft: m.draft,
            arrived_at: at,
        }
    }

    fn control_unit<'a>(draft: DraftVersion, at: Instant) -> Unit<'a> {
        Unit {
            target: Target::Control { raw: Bytes::from_static(b"control-frame") },
            draft,
            arrived_at: at,
        }
    }

    fn datagram_unit<'a>(draft: DraftVersion, header_len: Option<usize>) -> Unit<'a> {
        Unit {
            target: Target::Datagram {
                raw: Bytes::from_static(&[0x01, 0x02, 0x03, b'p', b'a', b'y', b'l']),
                header_len,
                is_status: false,
            },
            draft,
            arrived_at: Instant::now(),
        }
    }

    fn stream_end_unit<'a>(draft: DraftVersion, is_control_stream: bool) -> Unit<'a> {
        Unit { target: Target::StreamEnd { is_control_stream }, draft, arrived_at: Instant::now() }
    }

    /// Every draft the vocabulary names, whether or not this build compiled
    /// a codec for it.
    ///
    /// The axis for the assertions that do not need one: the control site,
    /// the stream-end and datagram sites answer for a [`DraftVersion`]
    /// value, not for a decoder, and they answer the same way in every
    /// build — so restricting *those* sweeps to the compiled set would drop
    /// rows for nothing. Anything that reaches the **object** or **control**
    /// site sweeps [`COMPILED_DRAFTS`] instead: both are behind a decoder
    /// this build may not carry, and on a draft it does not carry the hook
    /// is never invoked at either.
    const ALL_DRAFTS: [DraftVersion; 13] = [
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
    ];

    /// The drafts this build actually compiled, in publication order.
    ///
    /// Each element carries its own `#[cfg]`, so the axis is the enabled set
    /// and not a hardcoded thirteen — the shape `tests/action_matrix.rs` and
    /// the test module of `framer.rs` already use. It is the **only** honest
    /// axis for the object site: with no decoder for a draft the framer
    /// never addresses its data streams, the hook is never invoked on an
    /// object there, and `classify` says so — `Support::Unreachable {
    /// refusal: StreamNotFramed { reason: DecodeError } }`, see
    /// [`crate::capability::draft_is_compiled`]. Sweeping the whole
    /// vocabulary through `execute` therefore measures that guard rather
    /// than this module's executor, which is what a `--features draft07`
    /// build used to turn twenty-seven of the tests below red.
    ///
    /// The **control** site joined it later, and for the same reason one
    /// decoder along: `AnyControlMessage::decode` has no arm for an
    /// uncompiled draft, so `ControlStreamParser::feed` refuses every frame
    /// and `ProxyHook::on_control_message` is never offered one.
    ///
    /// Under the default (all-drafts) build this is all thirteen and every
    /// object test below runs on all of them. Under `--no-default-features`
    /// it is empty: that build has no object site at all, so the object
    /// sweeps run zero times rather than asserting the framer's verdict is
    /// the executor's. The sites that survive there keep their own coverage
    /// through [`ALL_DRAFTS`].
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

    // ── how many events one action produces ─────────────────────────

    #[test]
    fn an_applied_action_emits_exactly_one_event() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(&object_unit(&m, Instant::now()), Action::Pass);
            assert_eq!(out.plan, Plan::WriteNow(object_bytes()), "draft {draft:?}");
            assert_eq!(out.result, Ok(Effect::ForwardedVerbatim), "draft {draft:?}");
            assert_eq!(h.observer.events().len(), 1, "draft {draft:?}");
            assert_eq!(
                h.observer.applied(),
                vec![(Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim)],
                "draft {draft:?}",
            );
            assert_eq!(h.counters.snapshot().actions_refused, 0, "draft {draft:?}");
        }
    }

    #[test]
    fn a_refusal_emits_exactly_one_event_and_bumps_exactly_one_counter() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::Replace(Bytes::from_static(b"nope")),
            );
            assert_eq!(h.observer.events().len(), 1, "draft {draft:?}");
            assert_eq!(h.counters.snapshot().actions_refused, 1, "draft {draft:?}");
            // The unit is forwarded unchanged.
            assert_eq!(out.plan, Plan::WriteNow(object_bytes()), "draft {draft:?}");
        }
    }

    #[test]
    fn the_counter_moves_even_with_no_observer_attached() {
        for &draft in COMPILED_DRAFTS {
            let counters = Arc::new(Recorder::new());
            let observer = Recording::default();
            let cancel = CancellationToken::new();
            let closer = SessionCloser::new(cancel);
            let mut pending = PendingQueue::new(EgressConfig::default(), counters.clone());
            let mut deferred = DeferredEffects::new();
            let report = Reporter::new(
                &observer,
                false, // observer.wants_events() == false
                counters.as_ref(),
                SessionId(1),
                ProxySide::ClientToProxy,
                Some(1),
            );
            let mut engine = Engine {
                queue: Some(Queue { pending: &mut pending, deferred: &mut deferred }),
                closer: &closer,
            };
            let m = meta(draft);
            let out = execute(
                &object_unit(&m, Instant::now()),
                Action::Replace(Bytes::from_static(b"x")),
                &mut engine,
                &report,
            );
            // `Replace` at the object site is `WrongSite { .. ReplaceObject }`
            // on every draft — the executor's refusal, not the framer's.
            assert_eq!(
                out.result,
                Err(Refusal::WrongSite { site: Site::Object, action: ActionKind::ReplaceObject }),
                "draft {draft:?}",
            );
            assert!(observer.events().is_empty(), "events are gated");
            assert_eq!(counters.snapshot().actions_refused, 1, "counters are not");
        }
    }

    /// The module note's cardinality contract, swept rather than argued:
    /// **exactly one** of `ActionApplied` / `ActionRefused` per `execute`,
    /// never both and never neither, and a refused unit's plan is its own
    /// bytes, unchanged.
    ///
    /// `every_refusal_this_module_emits_is_classifys_or_one_of_its_own_three`
    /// sweeps *which* refusals may appear; this sweeps *how many events*
    /// they arrive with, which is the half a partially-applied action would
    /// break. Impairments are excluded on purpose — a clamp or a
    /// backpressure transition is not a decision.
    ///
    /// *Ablation:* in `execute`'s `Err` arm, call
    /// `report.applied(site, action, Effect::ForwardedVerbatim)` beside
    /// `report.refused(..)`. Every refusing cell fails the one-decision
    /// assertion.
    #[test]
    fn exactly_one_decision_event_per_unit_and_refusals_forward_the_original() {
        let mut refused_cells = 0usize;
        let mut applied_cells = 0usize;
        for draft in ALL_DRAFTS {
            let m = meta(draft);
            // The control, stream-end and datagram cells answer for every
            // draft in the vocabulary; the object cell only for one this
            // build compiled (`COMPILED_DRAFTS`), because on the rest the
            // hook is never invoked there at all.
            let object_site_is_reachable = COMPILED_DRAFTS.contains(&draft);
            let actions = || {
                vec![
                    Action::Pass,
                    Action::Replace(Bytes::from_static(b"xxxx")),
                    Action::ReplacePayload(Bytes::from_static(b"abcd")),
                    Action::ReplacePayload(Bytes::from_static(b"toolong")),
                    Action::Drop(DropMode::Elide),
                    Action::Truncate { bytes: 2, code: 1 },
                    Action::ResetStream { code: u64::MAX },
                    Action::CloseSession { code: 1, reason: Bytes::new() },
                    Action::Pass.delayed(Duration::from_millis(1)),
                    Action::Pass.held(Gate::new()),
                    Action::Drop(DropMode::Elide).delayed(Duration::from_millis(1)),
                    Action::Drop(DropMode::Elide).held(Gate::new()),
                    Action::ResetStream { code: 1 }.delayed(Duration::from_millis(1)),
                    Action::CloseSession { code: 1, reason: Bytes::new() }.held(Gate::new()),
                ]
            };
            for action in actions() {
                // Each cell gets its own harness, so the queue is empty and
                // a refusal's forward is the inline write, not a slot.
                let mut cells: Vec<(Unit<'_>, Option<Bytes>)> = vec![
                    (
                        control_unit(draft, Instant::now()),
                        Some(Bytes::from_static(b"control-frame")),
                    ),
                    (stream_end_unit(draft, false), None),
                    (stream_end_unit(draft, true), None),
                ];
                if object_site_is_reachable {
                    cells.push((object_unit(&m, Instant::now()), Some(object_bytes())));
                }
                for (unit, original) in cells {
                    let mut h = Harness::new();
                    let out = h.run(&unit, action.clone());
                    let what = format!("{draft:?} / {:?} / {action:?}", unit.target.site());
                    let decisions = h
                        .observer
                        .events()
                        .iter()
                        .filter(|e| {
                            matches!(
                                e,
                                ProxyEvent::ActionApplied { .. } | ProxyEvent::ActionRefused { .. }
                            )
                        })
                        .count();
                    assert_eq!(decisions, 1, "[{what}] one decision event per unit");
                    match &out.result {
                        Ok(_) => {
                            applied_cells += 1;
                            assert!(h.observer.refused().is_empty(), "[{what}]");
                            assert_eq!(h.counters.snapshot().actions_refused, 0, "[{what}]");
                        }
                        Err(_) => {
                            refused_cells += 1;
                            assert!(
                                h.observer.applied().is_empty(),
                                "[{what}] a refused unit reports no ActionApplied",
                            );
                            assert_eq!(h.counters.snapshot().actions_refused, 1, "[{what}]");
                            let want = match &original {
                                Some(raw) => Plan::WriteNow(raw.clone()),
                                None => Plan::Nothing,
                            };
                            assert_eq!(
                                out.plan, want,
                                "[{what}] a refused unit is forwarded unchanged",
                            );
                            assert!(!out.note_elided, "[{what}]");
                            assert!(out.clamped.is_none(), "[{what}]");
                            assert!(
                                h.pending.is_empty(),
                                "[{what}] a refusal on an empty queue writes inline",
                            );
                            assert_eq!(h.counters.snapshot().egress_items_queued, 0, "[{what}]");
                        }
                    }
                }

                // The datagram site takes the same entry point with no queue.
                let h = Harness::new();
                let unit = datagram_unit(draft, Some(3));
                let raw = Bytes::from_static(&[0x01, 0x02, 0x03, b'p', b'a', b'y', b'l']);
                let report = h.datagram_report();
                let mut engine = h.datagram_engine();
                let out = execute(&unit, action.clone(), &mut engine, &report);
                let what = format!("{draft:?} / Datagram / {action:?}");
                let decisions = h
                    .observer
                    .events()
                    .iter()
                    .filter(|e| {
                        matches!(
                            e,
                            ProxyEvent::ActionApplied { .. } | ProxyEvent::ActionRefused { .. }
                        )
                    })
                    .count();
                assert_eq!(decisions, 1, "[{what}] one decision event per unit");
                if out.result.is_err() {
                    refused_cells += 1;
                    assert!(h.observer.applied().is_empty(), "[{what}]");
                    assert_eq!(out.plan, Plan::WriteNow(raw), "[{what}] forwarded unchanged");
                } else {
                    applied_cells += 1;
                    assert!(h.observer.refused().is_empty(), "[{what}]");
                }
            }
        }
        assert!(refused_cells > 0 && applied_cells > 0, "the sweep must reach both verdicts");
    }

    /// A refusal behind a delayed unit takes an ordering slot rather than
    /// overtaking it — `execute`'s "through the same queue-or-write-now
    /// fork an admitted `Pass` takes" clause, which the empty-queue sweep
    /// above cannot reach.
    ///
    /// *Ablation:* make `forward_unchanged` return `Plan::WriteNow(raw)`
    /// unconditionally. The refused object then jumps the delayed one and
    /// `pending.len()` stays at 1.
    #[test]
    fn a_refused_unit_queues_behind_a_delayed_one_rather_than_overtaking_it() {
        const DELAY: Duration = Duration::from_millis(60);
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            h.run(&object_unit(&m, at), Action::Pass.delayed(DELAY));
            // `Replace` at the object site is `WrongSite { .. ReplaceObject }`.
            let out = h.run(&object_unit(&m, at), Action::Replace(Bytes::from_static(b"no")));
            assert!(out.result.is_err(), "draft {draft:?}");
            assert_eq!(out.plan, Plan::Nothing, "not written inline: the queue is busy");
            assert_eq!(h.pending.len(), 2, "draft {draft:?}");
            assert_eq!(h.deferred.len(), 2, "one ledger entry per pushed unit, refusals included");

            assert!(
                h.pending.pop_next_due(Instant::now()).is_none(),
                "the delayed head still blocks the refused unit behind it",
            );
            let far = Instant::now() + Duration::from_secs(3600);
            let head = h.pending.pop_next_due(far).expect("the delayed Pass");
            let behind = h.pending.pop_next_due(far).expect("the refused unit, behind it");
            assert_eq!(*head.item(), Item::Write(object_bytes()));
            assert_eq!(
                *behind.item(),
                Item::Write(object_bytes()),
                "the refused unit's own bytes, not the replacement",
            );
            assert!(behind.expected_at() >= head.expected_at(), "and not expected ahead of it");
            assert_eq!(
                h.deferred.take_all(),
                vec![Deferred { action: ActionKind::Pass, effect: Effect::ForwardedVerbatim }],
                "the refused unit owes no release event",
            );
        }
    }

    // ── the ruling: Delay { then: Replace } is two events ────────────

    /// The ruling this module was asked to pin, at the one site where
    /// `Replace` is a legal inner action — the control site. (`Replace` at
    /// the object site is `WrongSite { .. ReplaceObject }` on every draft,
    /// so `Delay { then: Replace }` there is a *refusal*, which
    /// `a_delay_wrapping_a_refused_inner_action_is_refused` covers.)
    #[test]
    fn delay_then_replace_reports_queued_now_and_the_inner_effect_at_release() {
        let Some(draft) = a_compiled_draft() else { return };
        let mut h = Harness::new();
        let at = Instant::now();
        let out = h.run(
            &control_unit(draft, at),
            Action::Replace(Bytes::from_static(b"1234")).delayed(Duration::from_millis(50)),
        );

        // Step 1, at the decision.
        assert_eq!(out.plan, Plan::Nothing);
        let Ok(Effect::Queued { release_at }) = out.result else {
            panic!("expected Queued, got {:?}", out.result)
        };
        assert!(release_at >= at + Duration::from_millis(50));
        assert_eq!(h.observer.applied().len(), 1);
        assert_eq!(h.observer.applied()[0].1, ActionKind::Delay);

        // Step 2, at the release. One ledger entry, naming the inner kind.
        assert_eq!(h.deferred.len(), 1);
        assert_eq!(h.pending.len(), 1);
        let owed = h.deferred.pop().expect("the delay owes a release event");
        assert_eq!(
            owed,
            Deferred { action: ActionKind::Replace, effect: Effect::Replaced { bytes: 4 } },
        );
        h.report().applied_deferred(Site::Control, owed);

        let applied = h.observer.applied();
        assert_eq!(applied.len(), 2, "a deferred action reports twice");
        assert_eq!(applied[1].1, ActionKind::Replace);
        assert_eq!(applied[1].2, Effect::Replaced { bytes: 4 });
    }

    #[test]
    fn a_delay_wrapping_a_refused_inner_action_is_refused_with_the_inners_reason() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::Replace(Bytes::from_static(b"1234")).delayed(Duration::from_millis(50)),
            );
            assert_eq!(
                out.result,
                Err(Refusal::WrongSite { site: Site::Object, action: ActionKind::ReplaceObject }),
                "draft {draft:?}",
            );
            assert_eq!(
                h.observer.refused()[0].1,
                ActionKind::Replace,
                "the event names the inner action, which is the informative one",
            );
            assert!(h.pending.is_empty(), "the site check happens before the queue");
        }
    }

    #[test]
    fn a_direct_action_queued_only_for_ordering_owes_nothing_at_release() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            // Head of the queue: delayed, so the queue is busy.
            h.run(&object_unit(&m, at), Action::Pass.delayed(Duration::from_millis(80)));
            // A plain `Pass` behind it must not overtake it — and must report
            // once, now, not twice.
            let out = h.run(&object_unit(&m, at), Action::Pass);
            assert_eq!(out.plan, Plan::Nothing, "a busy queue swallows the write");
            assert_eq!(out.result, Ok(Effect::ForwardedVerbatim), "draft {draft:?}");
            assert_eq!(h.pending.len(), 2, "draft {draft:?}");
            assert_eq!(h.deferred.len(), 2, "one ledger entry per pushed unit");

            assert!(h.deferred.pop().is_some(), "the delayed unit owes one");
            assert!(h.deferred.pop().is_none(), "the ordering-only unit owes none");
            assert_eq!(h.observer.applied().len(), 2, "two decisions, two events");
        }
    }

    #[test]
    fn hold_reports_queued_at_the_ceiling_and_owes_the_inner_effect() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            let gate = Gate::new();
            let out = h.run(&object_unit(&m, at), Action::Pass.held(gate.clone()));
            let Ok(Effect::Queued { release_at }) = out.result else {
                panic!("[{draft:?}] expected Queued, got {:?}", out.result)
            };
            assert!(release_at >= at + Duration::from_secs(30) - Duration::from_millis(1));
            assert_eq!(out.clamped, None, "a Hold has no requested duration to clamp");
            assert_eq!(
                h.deferred.pop(),
                Some(Deferred { action: ActionKind::Pass, effect: Effect::ForwardedVerbatim }),
            );
            assert!(!gate.is_released());
        }
    }

    // ── composition ─────────────────────────────────────────────────

    #[test]
    fn a_delay_wrapping_a_terminal_is_refused_before_it_is_queued() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::ResetStream { code: 2 }.delayed(Duration::from_millis(10)),
            );
            assert_eq!(out.result, Err(WRAPPED_TERMINAL), "draft {draft:?}");
            assert_eq!(
                h.observer.refused(),
                vec![(Site::Object, ActionKind::ResetStream, WRAPPED_TERMINAL)],
            );
            assert!(h.pending.is_empty(), "nothing reached the deque");
            assert!(h.deferred.is_empty());
            assert_eq!(h.counters.snapshot().egress_items_queued, 0);
            // Refused units are still forwarded, unchanged.
            assert_eq!(out.plan, Plan::WriteNow(object_bytes()));
        }
    }

    #[test]
    fn every_illegal_composition_names_which_one_it_was() {
        let cases = [
            (Action::Pass.delayed(Duration::from_millis(1)), NESTED_MODIFIER),
            (Action::Pass.held(Gate::new()), NESTED_MODIFIER),
            (Action::Truncate { bytes: 1, code: 0 }, WRAPPED_TERMINAL),
            (Action::ResetStream { code: 0 }, WRAPPED_TERMINAL),
            (Action::CloseSession { code: 1, reason: Bytes::new() }, WRAPPED_CLOSE),
        ];
        for &draft in COMPILED_DRAFTS {
            for (inner, expected) in cases.clone() {
                let mut h = Harness::new();
                let m = meta(draft);
                let out = h.run(
                    &object_unit(&m, Instant::now()),
                    inner.clone().delayed(Duration::from_millis(1)),
                );
                assert_eq!(out.result, Err(expected.clone()), "draft {draft:?} / inner {inner:?}");
                assert!(h.pending.is_empty());
            }
        }
    }

    /// The list of legal inner actions, both directions, against the one
    /// function that decides it.
    ///
    /// A refusal on *other* grounds is not what this asserts — a wrapped
    /// `ReplacePayload` at the control site is `WrongSite`, and rightly.
    /// What must never happen is `WrongComposition` naming one of the four
    /// content actions.
    ///
    /// *Ablation:* move `Action::Drop(_)` out of `check_composition`'s `Ok`
    /// arm into any of the three refusing arms. The first loop fails on
    /// `Drop(Elide)`.
    #[test]
    fn the_composition_rule_admits_exactly_the_four_content_actions() {
        for inner in [
            Action::Pass,
            Action::Replace(Bytes::from_static(b"xxxx")),
            Action::ReplacePayload(Bytes::from_static(b"abcd")),
            Action::Drop(DropMode::Elide),
        ] {
            assert!(
                check_composition(&inner).is_ok(),
                "{inner:?} is a content action and must be legal inside Delay/Hold",
            );
        }
        for (inner, expected) in [
            (Action::Pass.delayed(Duration::ZERO), NESTED_MODIFIER),
            (Action::Pass.held(Gate::new()), NESTED_MODIFIER),
            (Action::Truncate { bytes: 1, code: 0 }, WRAPPED_TERMINAL),
            (Action::ResetStream { code: 0 }, WRAPPED_TERMINAL),
            (Action::CloseSession { code: 0, reason: Bytes::new() }, WRAPPED_CLOSE),
        ] {
            let Err(Refused { action, refusal }) = check_composition(&inner) else {
                panic!("{inner:?} is not a content action and must be refused")
            };
            assert_eq!(refusal, expected, "inner {inner:?}");
            assert_eq!(action, kind_of(&inner), "the event names what was wrapped");
        }
    }

    /// The composition ruling that the `Action` rustdoc used to state
    /// backwards, and the measurement behind it.
    ///
    /// `Drop` is one of the four legal inner actions, and so says the
    /// sentence directly above the one that used to call
    /// `Delay { then: Drop(_) }` "unobservable" and name it as refused. It
    /// is admitted, and it is not unobservable: the drop takes an ordering
    /// slot for the whole of its delay, so the undelayed `Pass` pushed
    /// behind it is clamped to the drop's release instead of going out
    /// inline. Deleting the unit and stalling the stream behind it is one
    /// impairment with two effects, both on the wire.
    ///
    /// *Ablation, both ways:*
    /// * refuse `Drop` in `check_composition` — the first assertion fails
    ///   with `Err(WrongComposition { .. })`, which is the defect this test
    ///   was written for;
    /// * keep the admission but let a `Payload::Elide` skip `push_unit` in
    ///   the `Delay` arm — the drop then holds no slot, the `Pass` behind it
    ///   comes back `Plan::WriteNow` and overtakes an object the hook had
    ///   already ordered ahead of it.
    #[test]
    fn a_delayed_drop_is_admitted_and_blocks_the_stream_behind_it() {
        const DELAY: Duration = Duration::from_millis(80);
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            // Whether the elide leaves a successor to renumber is the delta
            // drafts' business, not this test's; the table itself is pinned
            // by `elide_renumbering_names_the_delta_encoding_drafts`.
            let renumbered = elide_renumbers_successor(&object_unit(&m, at));

            let out = h.run(&object_unit(&m, at), Action::Drop(DropMode::Elide).delayed(DELAY));
            let Ok(Effect::Queued { release_at }) = out.result else {
                panic!("[{draft:?}] a delayed Drop is admitted, not refused; got {:?}", out.result)
            };
            assert!(release_at >= at + DELAY);
            assert!(out.note_elided, "the framer's cursor still moves at the decision");
            assert_eq!(h.counters.snapshot().actions_refused, 0);
            assert!(h.observer.refused().is_empty(), "nothing was refused");
            assert_eq!(
                h.observer.applied(),
                vec![(Site::Object, ActionKind::Delay, Effect::Queued { release_at })],
                "step 1 names the modifier",
            );

            // The observability claim: the next object cannot overtake it.
            let behind = h.run(&object_unit(&m, at), Action::Pass);
            assert_eq!(behind.plan, Plan::Nothing, "the drop's slot is still holding the queue");
            assert_eq!(behind.result, Ok(Effect::ForwardedVerbatim));
            assert_eq!(h.deferred.len(), h.pending.len());
            assert_eq!(
                h.deferred.take_all(),
                vec![Deferred {
                    action: ActionKind::DropElide,
                    effect: Effect::Elided { renumbered_successor: renumbered },
                }],
                "step 2 names the inner action; the ordering-only Pass owes nothing",
            );

            // The `Pass` is due on its own account the instant it is pushed,
            // and is still not writable: the elided drop is in front of it
            // and is not due. That is the head-of-line block, stated as
            // behaviour rather than as arithmetic.
            assert!(
                h.pending.pop_next_due(Instant::now()).is_none(),
                "a delayed drop head-of-line-blocks the undelayed unit behind it",
            );

            let far = Instant::now() + Duration::from_secs(3600);
            let dropped = h.pending.pop_next_due(far).expect("the drop holds a slot");
            let passed = h.pending.pop_next_due(far).expect("the Pass is queued behind it");
            assert_eq!(*dropped.item(), Item::Elided, "the drop writes nothing...");
            assert!(dropped.due_at() >= at + DELAY, "...and not until its delay is up");
            assert_eq!(*passed.item(), Item::Write(object_bytes()));
            assert!(
                passed.expected_at() >= at + DELAY,
                "the queue expects to write the unit behind the drop no earlier than the drop: \
                 {:?} is earlier than {:?}",
                passed.expected_at(),
                at + DELAY,
            );
        }
    }

    /// The same ruling under a [`Gate`]. The gate is the observable here:
    /// the unit is not due while the gate holds, and is the moment it is
    /// released.
    ///
    /// *Ablation:* refuse `Drop` in `check_composition`; the first
    /// assertion fails.
    #[test]
    fn a_held_drop_is_admitted_and_stays_undue_until_its_gate_is_released() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            let renumbered = elide_renumbers_successor(&object_unit(&m, at));
            let gate = Gate::new();
            let out = h.run(&object_unit(&m, at), Action::Drop(DropMode::Elide).held(gate.clone()));
            assert!(
                matches!(out.result, Ok(Effect::Queued { .. })),
                "[{draft:?}] a held Drop is admitted, not refused; got {:?}",
                out.result,
            );
            assert_eq!(h.counters.snapshot().actions_refused, 0);
            assert!(
                h.pending.pop_next_due(Instant::now()).is_none(),
                "nothing is due while the gate holds",
            );
            gate.release();
            let released =
                h.pending.pop_next_due(Instant::now()).expect("a released gate makes it due");
            assert_eq!(*released.item(), Item::Elided);
            assert_eq!(
                h.deferred.take_all(),
                vec![Deferred {
                    action: ActionKind::DropElide,
                    effect: Effect::Elided { renumbered_successor: renumbered },
                }],
            );
        }
    }

    #[test]
    fn the_site_verdict_wins_over_the_composition_verdict() {
        // `Delay` is refused at the datagram site. A bad composition
        // inside it must not shadow that site verdict.
        let h = Harness::new();
        let unit = datagram_unit(DraftVersion::Draft11, Some(3));
        let report = h.datagram_report();
        let mut engine = h.datagram_engine();
        let out = execute(
            &unit,
            Action::ResetStream { code: 1 }.delayed(Duration::from_millis(5)),
            &mut engine,
            &report,
        );
        assert_eq!(
            out.result,
            Err(Refusal::WrongSite { site: Site::Datagram, action: ActionKind::Delay }),
        );
    }

    // ── refusal propagation, verbatim from `classify` ────────────────

    #[test]
    fn replace_at_the_object_site_propagates_classifys_replaceobject_refusal() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out =
                h.run(&object_unit(&m, Instant::now()), Action::Replace(Bytes::from_static(b"x")));
            // The refusal is the table's — `ReplaceObject`, not `Replace`.
            assert_eq!(
                out.result,
                Err(Refusal::WrongSite { site: Site::Object, action: ActionKind::ReplaceObject }),
                "draft {draft:?}",
            );
            // The event's `action` is what the hook returned.
            assert_eq!(h.observer.refused()[0].1, ActionKind::Replace);
            // And it is byte-for-byte what the published table says.
            let published = crate::capability::Capabilities::for_draft(draft)
                .supports(Site::Object, ActionKind::ReplaceObject);
            assert_eq!(published, Support::No(out.result.unwrap_err()), "draft {draft:?}");
        }
    }

    #[test]
    fn every_refusal_this_module_emits_is_classifys_or_one_of_its_own_three() {
        // The exhaustive statement of the module note: sweep a wide set of
        // (site, action) pairs and assert every refusal that comes back is
        // either one `classify` produced for the same pair, or one of the
        // three the executor owns.
        let mut seen: Vec<Refusal> = Vec::new();
        for draft in ALL_DRAFTS {
            let m = meta(draft);
            let actions = || {
                vec![
                    Action::Pass,
                    Action::Replace(Bytes::from_static(b"xxxx")),
                    Action::ReplacePayload(Bytes::from_static(b"abcd")),
                    Action::ReplacePayload(Bytes::from_static(b"toolong")),
                    Action::Drop(DropMode::Elide),
                    Action::Truncate { bytes: 2, code: 1 },
                    Action::Truncate { bytes: 2, code: u64::MAX },
                    Action::ResetStream { code: 1 },
                    Action::ResetStream { code: u64::MAX },
                    Action::CloseSession { code: 1, reason: Bytes::new() },
                    Action::Pass.delayed(Duration::from_millis(1)),
                    Action::Pass.held(Gate::new()),
                    Action::ResetStream { code: 1 }.delayed(Duration::from_millis(1)),
                ]
            };
            for action in actions() {
                // As above: the object cell exists only where a decoder
                // does, so that the sweep collects the executor's refusals
                // and not the framer's `StreamNotFramed` on a draft this
                // build cannot address.
                let mut units = vec![
                    control_unit(draft, Instant::now()),
                    stream_end_unit(draft, false),
                    stream_end_unit(draft, true),
                ];
                if COMPILED_DRAFTS.contains(&draft) {
                    units.push(object_unit(&m, Instant::now()));
                }
                for unit in units {
                    let mut h = Harness::new();
                    let out = h.run(&unit, action.clone());
                    if let Err(refusal) = out.result {
                        assert_eq!(h.counters.snapshot().actions_refused, 1);
                        seen.push(refusal);
                    } else {
                        assert_eq!(h.counters.snapshot().actions_refused, 0);
                    }
                }
                let h = Harness::new();
                let unit = datagram_unit(draft, Some(3));
                let report = h.datagram_report();
                let mut engine = h.datagram_engine();
                let out = execute(&unit, action.clone(), &mut engine, &report);
                if let Err(refusal) = out.result {
                    seen.push(refusal);
                }
            }
        }
        assert!(!seen.is_empty(), "the sweep must actually refuse things");
        for refusal in &seen {
            assert!(
                !matches!(refusal, Refusal::StreamNotFramed { .. }),
                "table-only refusal {refusal:?} escaped into an ActionRefused",
            );
        }
        // All three executor-owned refusals are reachable from the sweep.
        assert!(seen.iter().any(|r| matches!(r, Refusal::WrongComposition { .. })));
        assert!(seen.iter().any(|r| matches!(r, Refusal::ErrorCodeOutOfRange { .. })));
    }

    #[test]
    fn a_second_close_is_refused_as_session_already_closing() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let first = h.run(
                &object_unit(&m, Instant::now()),
                Action::CloseSession { code: 3, reason: Bytes::from_static(b"bye") },
            );
            assert_eq!(first.result, Ok(Effect::SessionClosing { code: 3 }), "draft {draft:?}");
            assert_eq!(
                first.plan,
                Plan::CloseSession { code: 3, reason: Bytes::from_static(b"bye") },
            );
            let second = h.run(
                &object_unit(&m, Instant::now()),
                Action::CloseSession { code: 1, reason: Bytes::new() },
            );
            assert_eq!(second.result, Err(Refusal::SessionAlreadyClosing), "draft {draft:?}");
            assert_eq!(
                h.closer.close_args(),
                (3, Bytes::from_static(b"bye")),
                "the first request wins; the second does not overwrite the reason",
            );
            assert!(h.cancel.is_cancelled(), "SessionCloser::request cancels as it records");
            // The refused second close still forwarded its unit unchanged.
            assert_eq!(second.plan, Plan::WriteNow(object_bytes()));
        }
    }

    #[test]
    fn an_out_of_range_code_is_refused_before_anything_is_queued() {
        for &draft in COMPILED_DRAFTS {
            for action in [
                Action::ResetStream { code: 1 << 62 },
                Action::Truncate { bytes: 1, code: u64::MAX },
            ] {
                let mut h = Harness::new();
                let m = meta(draft);
                let out = h.run(&object_unit(&m, Instant::now()), action.clone());
                let Err(Refusal::ErrorCodeOutOfRange { code }) = out.result else {
                    panic!(
                        "[{draft:?}] expected ErrorCodeOutOfRange for {action:?}, got {:?}",
                        out.result,
                    )
                };
                assert!(code > MAX_APPLICATION_ERROR_CODE);
                assert!(h.pending.is_empty(), "nothing was queued");
            }
        }
        // And at the stream sites, which take the other entry point.
        let h = Harness::new();
        let out = execute_stream(
            StreamSite::Open,
            DraftVersion::Draft11,
            StreamAction::Reject { code: u64::MAX },
            &h.report(),
        );
        assert_eq!(out.result, Err(Refusal::ErrorCodeOutOfRange { code: u64::MAX }));
        assert_eq!(out.plan, Plan::Nothing);
    }

    // ── the object site ─────────────────────────────────────────────

    #[test]
    fn replace_payload_splices_at_the_trailing_field() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::ReplacePayload(Bytes::from_static(b"WXYZ")),
            );
            assert_eq!(out.result, Ok(Effect::Replaced { bytes: 10 }), "draft {draft:?}");
            let Plan::WriteNow(bytes) = out.plan else {
                panic!("[{draft:?}] expected an inline write")
            };
            assert_eq!(&bytes[..6], &object_bytes()[..6], "framing is untouched");
            assert_eq!(&bytes[6..], b"WXYZ");
        }
    }

    #[test]
    fn replace_payload_with_a_different_length_is_refused_with_the_lengths() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::ReplacePayload(Bytes::from_static(b"WXYZ!")),
            );
            assert_eq!(
                out.result,
                Err(Refusal::LengthChanged { from: 4, to: 5 }),
                "draft {draft:?}",
            );
            assert_eq!(out.plan, Plan::WriteNow(object_bytes()), "forwarded unchanged");
        }
    }

    /// Draft-11 by name and by `#[cfg]`: the refusal exists only on the drafts
    /// with a *subgroup ID is the first object's ID* stream type (11-14 and
    /// 16-19 — not 07-10, not 15), so the fixture picks one and the test
    /// compiles exactly where that one was compiled. `capability::tests` owns
    /// the sweep over the whole set.
    #[cfg(feature = "draft11")]
    #[test]
    fn eliding_the_first_object_of_an_implicit_subgroup_is_refused() {
        let mut h = Harness::new();
        let mut m = meta(DraftVersion::Draft11);
        m.index_in_stream = 0;
        m.subgroup_id = None;
        let out = h.run(&object_unit(&m, Instant::now()), Action::Drop(DropMode::Elide));
        assert_eq!(out.result, Err(Refusal::WouldRedefineSubgroupId));
        assert!(!out.note_elided, "a refused elide must not move the cursor");
        assert_eq!(h.counters.snapshot().objects_elided, 0);
    }

    /// The reserved mode is a draft-17-to-19 header field, and the fixture
    /// is a draft-19 header — so, like its neighbour, it compiles exactly
    /// where its draft did.
    #[cfg(feature = "draft19")]
    #[test]
    fn a_reserved_subgroup_id_mode_is_its_own_refusal() {
        let mut h = Harness::new();
        let mut m = meta(DraftVersion::Draft19);
        m.index_in_stream = 0;
        m.subgroup_id = None;
        let unit = Unit {
            target: Target::Object { meta: &m, subgroup_id_mode: Some(3), raw: object_bytes() },
            draft: DraftVersion::Draft19,
            arrived_at: Instant::now(),
        };
        let out = h.run(&unit, Action::Drop(DropMode::Elide));
        assert_eq!(out.result, Err(Refusal::ReservedHeaderMode { mode: 3 }));
    }

    /// A shaper's tail-drop takes the same guards a hook's elide takes, and
    /// reports the same refusal — but no `ActionApplied`, because no hook
    /// asked for anything.
    ///
    /// The two halves are the two obligations on `DropTail`:
    /// an admitted drop moves the cursor and counts one elide, and a
    /// refused one leaves the cursor alone so the caller can admit the unit
    /// anyway. The `applied()` assertion is what separates this from
    /// `execute(.., Drop(Elide), ..)`: routing a configured drop through
    /// the hook path would emit a per-object `ActionApplied` naming a
    /// decision nobody made.
    ///
    /// *Ablation, recorded:* have `shape_elide` return `true`
    /// unconditionally (skip `admit_kind`) — the refusal half reddens on
    /// `assert!(!exec::shape_elide(..))`, and, in the integration fixture,
    /// a status object would be silently destroyed.
    #[test]
    fn a_shaper_tail_drop_takes_the_elide_guards_and_reports_only_refusals() {
        for &draft in COMPILED_DRAFTS {
            // Admitted: an ordinary object.
            let h = Harness::new();
            let m = meta(draft);
            assert!(
                shape_elide(&object_unit(&m, Instant::now()), &h.report()),
                "draft {draft:?}: an ordinary object elides"
            );
            assert_eq!(h.counters.snapshot().objects_elided, 1, "draft {draft:?}");
            assert_eq!(h.counters.snapshot().actions_refused, 0, "draft {draft:?}");
            assert!(h.observer.applied().is_empty(), "no hook asked, so nothing was applied");

            // Refused: a status object, on every draft.
            let h = Harness::new();
            let mut m = meta(draft);
            m.status = Some(3);
            m.payload_len = 0;
            assert!(
                !shape_elide(&object_unit(&m, Instant::now()), &h.report()),
                "draft {draft:?}: a status object may not be elided, so the shaper \
                 must admit the unit instead"
            );
            assert_eq!(h.counters.snapshot().objects_elided, 0, "draft {draft:?}");
            assert_eq!(
                h.observer.refused(),
                vec![(Site::Object, ActionKind::DropElide, Refusal::WouldDestroyStatusObject)],
                "draft {draft:?}: the refusal is reported, once",
            );
            assert_eq!(h.counters.snapshot().actions_refused, 1, "draft {draft:?}");
        }
    }

    #[test]
    fn eliding_a_status_object_is_refused() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let mut m = meta(draft);
            m.status = Some(3);
            m.payload_len = 0;
            let out = h.run(&object_unit(&m, Instant::now()), Action::Drop(DropMode::Elide));
            assert_eq!(out.result, Err(Refusal::WouldDestroyStatusObject), "draft {draft:?}");
        }
    }

    #[test]
    fn an_admitted_elide_writes_nothing_counts_one_and_owes_a_cursor_move() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            let renumbered = elide_renumbers_successor(&object_unit(&m, at));
            let out = h.run(&object_unit(&m, at), Action::Drop(DropMode::Elide));
            assert_eq!(out.plan, Plan::Nothing, "draft {draft:?}");
            assert_eq!(
                out.result,
                Ok(Effect::Elided { renumbered_successor: renumbered }),
                "draft {draft:?}",
            );
            assert!(out.note_elided);
            assert_eq!(h.counters.snapshot().objects_elided, 1);
        }
    }

    /// A deferral is counted where it is decided, and a forwarded unit is
    /// not counted at all.
    ///
    /// The figure `Action::Delay` did not used to have. The one that was
    /// meant to answer for a deferral sat on the shaping statistics, where
    /// every figure is gated on a configured profile — so on the sessions a
    /// hook alone impairs, which need no profile whatever, it could only
    /// ever have read zero.
    ///
    /// *Ablation, run:* delete the `ActionKind::Delay` arm from
    /// `Reporter::applied`.
    ///
    /// ```text
    /// assertion `left == right` failed: draft Draft07: the engine took the unit
    /// off the wire and queued it for a later release, and the figure for what
    /// it deferred did not move
    ///   left: 0
    ///  right: 1
    /// ```
    ///
    /// Recorded without a `file:line` prefix: editing this paragraph moves
    /// the line it would name.
    #[test]
    fn a_deferred_unit_is_counted_and_a_forwarded_one_is_not() {
        for &draft in COMPILED_DRAFTS {
            let m = meta(draft);
            let mut h = Harness::new();
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::Delay { by: Duration::from_millis(5), then: Box::new(Action::Pass) },
            );
            assert!(matches!(out.result, Ok(Effect::Queued { .. })), "draft {draft:?}");
            let counted = h.counters.snapshot();
            assert_eq!(
                counted.units_delayed, 1,
                "draft {draft:?}: the engine took the unit off the wire and queued it \
                 for a later release, and the figure for what it deferred did not move",
            );
            assert_eq!(counted.actions_refused, 0, "draft {draft:?}");
            assert_eq!(
                counted.objects_truncated, 0,
                "draft {draft:?}: a deferral is not a truncation, and one figure \
                 answering for both would be indistinguishable from either",
            );

            let mut h = Harness::new();
            h.run(&object_unit(&m, Instant::now()), Action::Pass);
            assert_eq!(
                h.counters.snapshot().units_delayed,
                0,
                "draft {draft:?}: a unit that went straight out was never deferred",
            );
        }
    }

    /// The figure is `units_delayed` and not `objects_delayed`, and a
    /// deferred **control frame** is the whole reason.
    ///
    /// `classify_control` honours `Delay` on every compiled draft, so a
    /// SUBSCRIBE held back is a real deferral with no object anywhere in it.
    /// A counter named for objects would have had to either miss this or
    /// count it under a name that does not describe it. Its neighbour keeps
    /// the object name honestly: a truncation is refused on a control
    /// stream and can land nowhere but an object, which the gate below
    /// checks rather than assumes.
    #[test]
    fn a_deferred_control_frame_moves_the_same_figure() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let out = h.run(
                &control_unit(draft, Instant::now()),
                Action::Delay { by: Duration::from_millis(5), then: Box::new(Action::Pass) },
            );
            assert!(matches!(out.result, Ok(Effect::Queued { .. })), "draft {draft:?}");
            assert_eq!(
                h.counters.snapshot().units_delayed,
                1,
                "draft {draft:?}: a control frame is a unit, and it was deferred",
            );
        }
    }

    /// A truncation is counted when it is applied, and never when it is
    /// refused.
    ///
    /// Two refusals, because they are refused by different code and a
    /// counter placed at the attempt rather than the application would pass
    /// one of them and fail the other. The error code is checked inside the
    /// `Truncate` arm itself; the site is checked by `classify`, before the
    /// arm is reached at all.
    ///
    /// *Ablation, run:* delete the `ActionKind::Truncate` arm from
    /// `Reporter::applied`.
    ///
    /// ```text
    /// assertion `left == right` failed: draft Draft07: the object went out cut
    /// short to its first three bytes and nothing counted it
    ///   left: 0
    ///  right: 1
    /// ```
    #[test]
    fn a_truncation_counts_when_it_is_applied_and_never_when_it_is_refused() {
        for &draft in COMPILED_DRAFTS {
            let m = meta(draft);
            let mut h = Harness::new();
            let out =
                h.run(&object_unit(&m, Instant::now()), Action::Truncate { bytes: 3, code: 0x2 });
            assert!(matches!(out.result, Ok(Effect::Truncated { .. })), "draft {draft:?}");
            assert_eq!(
                h.counters.snapshot().objects_truncated,
                1,
                "draft {draft:?}: the object went out cut short to its first three \
                 bytes and nothing counted it",
            );

            let mut h = Harness::new();
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::Truncate { bytes: 3, code: MAX_APPLICATION_ERROR_CODE + 1 },
            );
            assert!(out.result.is_err(), "draft {draft:?}");
            let counted = h.counters.snapshot();
            assert_eq!(
                counted.objects_truncated, 0,
                "draft {draft:?}: an out-of-range code refuses the truncation, and \
                 a refused action cut nothing short",
            );
            assert_eq!(counted.actions_refused, 1, "draft {draft:?}");

            let mut h = Harness::new();
            let out = h.run(
                &control_unit(draft, Instant::now()),
                Action::Truncate { bytes: 3, code: 0x2 },
            );
            assert_eq!(out.result, Err(Refusal::ControlStreamResetIllegal), "draft {draft:?}");
            assert_eq!(
                h.counters.snapshot().objects_truncated,
                0,
                "draft {draft:?}: the object name holds because the control site \
                 refuses the action outright",
            );
        }
    }

    /// A session nobody is watching still counts what it did.
    ///
    /// `Reporter` caches `observer.wants_events()` and gates **events** on
    /// it; the counters are outside that gate, on the same terms
    /// `Reporter::refused` states for its own. The claim is worth a gate
    /// rather than a comment because the failure is silent in the direction
    /// that matters: a counter bumped inside the gate agrees with its event
    /// in every test that has an observer attached, which is all of them,
    /// and reads zero only in production.
    ///
    /// *Ablation, run:* move both bumps inside `Reporter::emit`'s `enabled`
    /// check by writing them as `if self.enabled { .. }`.
    ///
    /// ```text
    /// assertion `left == right` failed: draft Draft07: a deferral on a session
    /// nobody attached to is still a deferral, and this figure is the only
    /// thing that says so
    ///   left: 0
    ///  right: 1
    /// ```
    #[test]
    fn a_session_with_nobody_watching_still_counts_what_it_applied() {
        for &draft in COMPILED_DRAFTS {
            let m = meta(draft);
            let mut h = Harness::new();
            h.run_unwatched(
                &object_unit(&m, Instant::now()),
                Action::Delay { by: Duration::from_millis(5), then: Box::new(Action::Pass) },
            );
            let mut h2 = Harness::new();
            h2.run_unwatched(
                &object_unit(&m, Instant::now()),
                Action::Truncate { bytes: 3, code: 0x2 },
            );

            assert!(
                h.observer.events().is_empty() && h2.observer.events().is_empty(),
                "draft {draft:?}: nothing was emitted, which is what makes the \
                 counters below a measurement rather than a restatement",
            );
            assert_eq!(
                h.counters.snapshot().units_delayed,
                1,
                "draft {draft:?}: a deferral on a session nobody attached to is still \
                 a deferral, and this figure is the only thing that says so",
            );
            assert_eq!(
                h2.counters.snapshot().objects_truncated,
                1,
                "draft {draft:?}: and so is a truncation",
            );
        }
    }

    /// Draft-14 by name and by `#[cfg]`: `renumbered_successor: true` is
    /// asserted as a literal here rather than computed, so the fixture has
    /// to be a draft that delta-encodes Object IDs, and 14 is the first of
    /// them.
    #[cfg(feature = "draft14")]
    #[test]
    fn a_deferred_elide_still_moves_the_cursor_at_the_decision() {
        let mut h = Harness::new();
        let m = meta(DraftVersion::Draft14);
        let out = h.run(
            &object_unit(&m, Instant::now()),
            Action::Drop(DropMode::Elide).delayed(Duration::from_millis(20)),
        );
        assert!(
            out.note_elided,
            "the framer's cursor is positional; note_elided cannot wait for the release",
        );
        assert_eq!(
            h.deferred.pop(),
            Some(Deferred {
                action: ActionKind::DropElide,
                effect: Effect::Elided { renumbered_successor: true },
            }),
        );
    }

    /// The one predicate this module duplicates from `framer.rs`
    /// (`ObjectFramer::elide_owes_a_fixup`, private there).
    ///
    /// The two stream kinds are the two halves of the claim and the boundary
    /// moves between them — draft-14 for a subgroup stream, draft-15 for a
    /// fetch one. A single number restated for both would be a table that
    /// happened to agree with the code on twelve of the twenty-six rows.
    ///
    /// Asserted against an explicitly restated table rather than against the
    /// framer itself, and that is a limitation worth stating: `note_elided`
    /// `debug_assert`s that the object it is handed is the one the framer
    /// most recently emitted, so a standalone probe cannot ask the framer
    /// this question without driving thirteen drafts of real wire bytes
    /// through it. The compensating cover is
    /// `tests/actions_objects.rs`, which asserts the *bytes* of an elided
    /// run against an independent encoder — a wrong answer here shows up
    /// there as a wrong `renumbered_successor` on a stream whose bytes
    /// disagree.
    ///
    /// Swept over [`ALL_DRAFTS`] and not [`COMPILED_DRAFTS`] on purpose:
    /// `elide_renumbers_successor` reads the [`DraftVersion`] value and
    /// nothing else, so every row of the table is answerable in every
    /// build, and restating all thirteen is the whole point of the test.
    #[test]
    fn elide_renumbering_names_the_drafts_that_owe_a_fixup() {
        for draft in ALL_DRAFTS {
            for stream_kind in [DataStreamType::Subgroup, DataStreamType::Fetch] {
                let mut m = meta(draft);
                m.stream_kind = stream_kind;
                let unit = object_unit(&m, Instant::now());
                let expected = match stream_kind {
                    DataStreamType::Subgroup => draft.number() >= 14,
                    DataStreamType::Fetch => draft.number() >= 15,
                };
                assert_eq!(
                    elide_renumbers_successor(&unit),
                    expected,
                    "draft {draft:?} / {stream_kind:?}",
                );
            }
        }
        // A non-object site never renumbers anything.
        assert!(!elide_renumbers_successor(&control_unit(DraftVersion::Draft19, Instant::now())));
    }

    #[test]
    fn truncate_queues_a_prefix_then_a_reset_and_reports_the_prefix_length() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out =
                h.run(&object_unit(&m, Instant::now()), Action::Truncate { bytes: 3, code: 0x2 });
            assert_eq!(out.plan, Plan::Terminal, "draft {draft:?}");
            // `code_defined` is the reset vocabulary's business, not this
            // test's; `drafts_07_to_10_report_the_reset_code_as_undefined`
            // restates that table against the draft numbers themselves.
            assert_eq!(
                out.result,
                Ok(Effect::Truncated {
                    forwarded: 3,
                    code: 0x2,
                    code_defined: stream_reset_code_defined(draft),
                }),
                "draft {draft:?}",
            );
            assert_eq!(h.pending.len(), 1);
            assert!(h.pending.head_release().is_some());
        }
    }

    #[test]
    fn truncate_past_the_end_of_the_unit_forwards_the_whole_unit() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let out =
                h.run(&object_unit(&m, Instant::now()), Action::Truncate { bytes: 9_999, code: 0 });
            assert_eq!(
                out.result,
                Ok(Effect::Truncated {
                    forwarded: object_bytes().len(),
                    code: 0,
                    code_defined: stream_reset_code_defined(draft),
                }),
                "draft {draft:?}",
            );
        }
    }

    #[test]
    fn drafts_07_to_10_report_the_reset_code_as_undefined() {
        for &draft in COMPILED_DRAFTS {
            let expected = !matches!(
                draft,
                DraftVersion::Draft07
                    | DraftVersion::Draft08
                    | DraftVersion::Draft09
                    | DraftVersion::Draft10
            );
            let mut h = Harness::new();
            let m = meta(draft);
            let out = h.run(&object_unit(&m, Instant::now()), Action::ResetStream { code: 5 });
            assert_eq!(
                out.result,
                Ok(Effect::StreamReset { code: 5, code_defined: expected }),
                "draft {draft:?}",
            );
        }
    }

    // ── the control site ────────────────────────────────────────────

    /// The draft the single-row control fixtures use: the first this build
    /// compiled.
    ///
    /// `None` only in a build with no draft at all, where there is no
    /// control decoder and the rows below are not claims about this module.
    /// A hardcoded draft-11 was what a `--features draft07` build read as
    /// an executor failure when it was really the control site reporting
    /// that it has no decoder for draft 11.
    fn a_compiled_draft() -> Option<DraftVersion> {
        COMPILED_DRAFTS.first().copied()
    }

    #[test]
    fn the_control_site_replaces_the_whole_frame_and_drops_it_whole() {
        let Some(draft) = a_compiled_draft() else { return };
        let mut h = Harness::new();
        let unit = control_unit(draft, Instant::now());
        let out = h.run(&unit, Action::Replace(Bytes::from_static(b"other")));
        assert_eq!(out.plan, Plan::WriteNow(Bytes::from_static(b"other")));
        assert_eq!(out.result, Ok(Effect::Replaced { bytes: 5 }));

        let mut h = Harness::new();
        let out = h.run(&control_unit(draft, Instant::now()), Action::Drop(DropMode::Elide));
        assert_eq!(out.result, Ok(Effect::Dropped), "no object slot to renumber");
        assert!(!out.note_elided);
        assert_eq!(h.counters.snapshot().objects_elided, 0);
    }

    /// Sweeps [`COMPILED_DRAFTS`] rather than [`ALL_DRAFTS`]: a refusal is
    /// what the engine hands a hook, and on a draft with no decoder no hook
    /// is reached, so `classify` answers `Unreachable` there instead. The
    /// claim being made is about the executor's rule, not about the
    /// build's.
    #[test]
    fn resetting_a_control_stream_is_refused_on_every_draft() {
        for &draft in COMPILED_DRAFTS {
            for action in [Action::ResetStream { code: 1 }, Action::Truncate { bytes: 1, code: 1 }]
            {
                let mut h = Harness::new();
                let out = h.run(&control_unit(draft, Instant::now()), action.clone());
                assert_eq!(
                    out.result,
                    Err(Refusal::ControlStreamResetIllegal),
                    "draft {draft:?} / {action:?}",
                );
                assert!(h.pending.is_empty());
            }
        }
    }

    #[test]
    fn drafts_17_to_19_execute_a_control_action_like_every_other_draft() {
        // These three carry the control plane on a pair of unidirectional
        // streams and requests on bidirectional ones. Both shapes reach this
        // site, so the column is `Yes` here exactly as it is on 07-16 and a
        // draft-conditional refusal would be wrong.
        //
        // Filtered to the compiled set, like every other control row: a
        // build without one of the three has no decoder for it and no hook
        // is reached, which is a claim about the build rather than about
        // the control plane's shape.
        for draft in [DraftVersion::Draft17, DraftVersion::Draft18, DraftVersion::Draft19]
            .into_iter()
            .filter(|d| COMPILED_DRAFTS.contains(d))
        {
            let mut h = Harness::new();
            let out = h.run(
                &control_unit(draft, Instant::now()),
                Action::Replace(Bytes::from_static(b"z")),
            );
            assert_eq!(out.result, Ok(Effect::Replaced { bytes: 1 }), "draft {draft:?}");
        }
    }

    // ── the datagram site ───────────────────────────────────────────

    #[test]
    fn a_datagram_replace_is_admitted_and_its_failure_is_the_callers_to_report() {
        let h = Harness::new();
        let unit = datagram_unit(DraftVersion::Draft11, Some(3));
        let report = h.datagram_report();
        let mut engine = h.datagram_engine();
        let out =
            execute(&unit, Action::Replace(Bytes::from_static(b"bigger")), &mut engine, &report);
        assert_eq!(out.result, Ok(Effect::Replaced { bytes: 6 }));
        assert_eq!(out.plan, Plan::WriteNow(Bytes::from_static(b"bigger")));

        // The transport then rejects it: exactly one ActionFailed, and no
        // ActionApplied is retracted.
        report.failed(Site::Datagram, ActionKind::Replace, "too large".to_owned());
        let failed: Vec<_> = h
            .observer
            .events()
            .into_iter()
            .filter(|e| matches!(e, ProxyEvent::ActionFailed { .. }))
            .collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(h.counters.snapshot().actions_refused, 0);
    }

    #[test]
    fn a_datagram_payload_splice_needs_a_real_boundary() {
        // Delimited: spliced after the header.
        let h = Harness::new();
        let unit = datagram_unit(DraftVersion::Draft11, Some(3));
        let report = h.datagram_report();
        let mut engine = h.datagram_engine();
        let out = execute(
            &unit,
            Action::ReplacePayload(Bytes::from_static(b"NEWP")),
            &mut engine,
            &report,
        );
        let Plan::WriteNow(bytes) = out.plan else { panic!("expected a datagram write") };
        assert_eq!(&bytes[..3], &[0x01, 0x02, 0x03]);
        assert_eq!(&bytes[3..], b"NEWP");

        // The three cases where there is no boundary.
        let cases = [
            (DraftVersion::Draft14, Some(3), false, "draft-14 header decode consumes the payload"),
            (DraftVersion::Draft11, None, false, "datagram header did not decode"),
            (DraftVersion::Draft11, Some(3), true, "status datagram has no payload"),
        ];
        for (draft, header_len, is_status, detail) in cases {
            let h = Harness::new();
            let unit = Unit {
                target: Target::Datagram {
                    raw: Bytes::from_static(&[0x01, 0x02, 0x03, b'p']),
                    header_len,
                    is_status,
                },
                draft,
                arrived_at: Instant::now(),
            };
            let report = h.datagram_report();
            let mut engine = h.datagram_engine();
            let out = execute(
                &unit,
                Action::ReplacePayload(Bytes::from_static(b"N")),
                &mut engine,
                &report,
            );
            assert_eq!(
                out.result,
                Err(Refusal::PayloadNotDelimited { detail }),
                "draft {draft:?} / header_len {header_len:?} / status {is_status}",
            );
            assert_eq!(out.plan, Plan::WriteNow(Bytes::from_static(&[0x01, 0x02, 0x03, b'p'])),);
        }
    }

    #[test]
    fn timing_and_terminals_are_refused_at_the_datagram_site() {
        for action in [
            Action::Pass.delayed(Duration::from_millis(1)),
            Action::Pass.held(Gate::new()),
            Action::Truncate { bytes: 1, code: 1 },
            Action::ResetStream { code: 1 },
        ] {
            let h = Harness::new();
            let unit = datagram_unit(DraftVersion::Draft11, Some(3));
            let report = h.datagram_report();
            let mut engine = h.datagram_engine();
            let out = execute(&unit, action.clone(), &mut engine, &report);
            assert!(
                matches!(out.result, Err(Refusal::WrongSite { site: Site::Datagram, .. })),
                "{action:?} -> {:?}",
                out.result,
            );
        }
    }

    // ── the stream-end site ─────────────────────────────────────────

    #[test]
    fn close_session_is_honoured_at_both_stream_end_columns() {
        for is_control_stream in [false, true] {
            let mut h = Harness::new();
            let out = h.run(
                &stream_end_unit(DraftVersion::Draft11, is_control_stream),
                Action::CloseSession { code: 3, reason: Bytes::from_static(b"x") },
            );
            assert_eq!(
                out.result,
                Ok(Effect::SessionClosing { code: 3 }),
                "control={is_control_stream}",
            );
        }
    }

    #[test]
    fn reset_at_stream_end_is_a_data_stream_capability_only() {
        let mut h = Harness::new();
        let out =
            h.run(&stream_end_unit(DraftVersion::Draft11, false), Action::ResetStream { code: 4 });
        assert_eq!(out.plan, Plan::Terminal);
        assert_eq!(out.result, Ok(Effect::StreamReset { code: 4, code_defined: true }),);

        let mut h = Harness::new();
        let out =
            h.run(&stream_end_unit(DraftVersion::Draft11, true), Action::ResetStream { code: 4 });
        assert_eq!(out.result, Err(Refusal::ControlStreamResetIllegal));
        assert_eq!(out.plan, Plan::Nothing, "a stream end carries no unit to forward");
    }

    #[test]
    fn everything_else_at_stream_end_is_wrong_site_except_the_two_reset_shapes() {
        // Every unsupported action at the stream-end site is refused as
        // `WrongSite`, on both the control and the data stream — except
        // Truncate and ResetStream on a control stream, which have a
        // refusal of their own.
        for is_control_stream in [false, true] {
            for action in [
                Action::Replace(Bytes::from_static(b"x")),
                Action::ReplacePayload(Bytes::from_static(b"x")),
                Action::Pass.delayed(Duration::from_millis(1)),
                Action::Pass.held(Gate::new()),
                Action::Drop(DropMode::Elide),
            ] {
                let mut h = Harness::new();
                let out = h.run(
                    &stream_end_unit(DraftVersion::Draft11, is_control_stream),
                    action.clone(),
                );
                assert!(
                    matches!(out.result, Err(Refusal::WrongSite { site: Site::StreamEnd, .. })),
                    "control={is_control_stream} {action:?} -> {:?}",
                    out.result,
                );
            }
            let mut h = Harness::new();
            let out = h.run(
                &stream_end_unit(DraftVersion::Draft11, is_control_stream),
                Action::Truncate { bytes: 1, code: 1 },
            );
            let expected = if is_control_stream {
                Refusal::ControlStreamResetIllegal
            } else {
                Refusal::WrongSite { site: Site::StreamEnd, action: ActionKind::Truncate }
            };
            assert_eq!(out.result, Err(expected));
        }
    }

    #[test]
    fn pass_at_stream_end_changes_nothing() {
        let mut h = Harness::new();
        let out = h.run(&stream_end_unit(DraftVersion::Draft11, true), Action::Pass);
        assert_eq!(out.plan, Plan::Nothing);
        assert_eq!(out.result, Ok(Effect::ForwardedVerbatim));
        assert_eq!(h.observer.applied().len(), 1);
    }

    // ── the stream-decision sites ───────────────────────────────────

    #[test]
    fn stream_open_and_reject_each_report_once() {
        for site in [StreamSite::Open, StreamSite::Header] {
            let h = Harness::new();
            let out = execute_stream(site, DraftVersion::Draft11, StreamAction::Open, &h.report());
            assert_eq!(out.plan, Plan::Nothing);
            assert_eq!(out.result, Ok(Effect::ForwardedVerbatim));
            assert_eq!(h.observer.applied().len(), 1);
            assert_eq!(h.observer.applied()[0].0, site.site());

            let h = Harness::new();
            let out = execute_stream(
                site,
                DraftVersion::Draft11,
                StreamAction::Reject { code: 9 },
                &h.report(),
            );
            assert_eq!(out.plan, Plan::RejectStream { code: 9 });
            assert_eq!(out.result, Ok(Effect::StreamRejected { code: 9 }));
            assert_eq!(h.observer.applied().len(), 1);
        }
    }

    // ── invariants the rest of the file leans on ────────────────────

    #[test]
    fn no_fact_precondition_survives_execution() {
        // `admit_conditional`'s `debug_assert` is only a claim if this
        // passes: sweep every site with fully-populated targets and assert
        // `classify` never asks for a fact `Target` did not supply.
        let mut saw_conditional = 0usize;
        for draft in ALL_DRAFTS {
            for stream_kind in [DataStreamType::Subgroup, DataStreamType::Fetch] {
                for index_in_stream in [0u64, 3] {
                    for subgroup_id in [None, Some(0u64)] {
                        for status in [None, Some(3u64)] {
                            for mode in [None, Some(0u8), Some(1), Some(3)] {
                                let mut m = meta(draft);
                                m.stream_kind = stream_kind;
                                m.index_in_stream = index_in_stream;
                                m.subgroup_id = subgroup_id;
                                m.status = status;
                                let unit = Unit {
                                    target: Target::Object {
                                        meta: &m,
                                        subgroup_id_mode: mode,
                                        raw: object_bytes(),
                                    },
                                    draft,
                                    arrived_at: Instant::now(),
                                };
                                for kind in [
                                    ActionKind::Pass,
                                    ActionKind::ReplacePayload,
                                    ActionKind::DropElide,
                                    ActionKind::Truncate,
                                    ActionKind::ResetStream,
                                    ActionKind::CloseSession,
                                ] {
                                    let replacement_len =
                                        (kind == ActionKind::ReplacePayload).then_some(4);
                                    let cx = unit.target.cap_ctx(draft, replacement_len);
                                    if let Support::Conditional(p) =
                                        classify(Site::Object, kind, &cx)
                                    {
                                        saw_conditional += 1;
                                        assert!(
                                            matches!(p, Precondition::WithinMaxDatagramSize),
                                            "unsupplied fact {p:?} at Object/{kind:?} \
                                             draft {draft:?}",
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for is_status in [false, true] {
                for header_len in [None, Some(3usize)] {
                    let unit = Unit {
                        target: Target::Datagram {
                            raw: Bytes::from_static(&[1, 2, 3, 4]),
                            header_len,
                            is_status,
                        },
                        draft,
                        arrived_at: Instant::now(),
                    };
                    for kind in [
                        ActionKind::Pass,
                        ActionKind::Replace,
                        ActionKind::ReplacePayload,
                        ActionKind::DropElide,
                        ActionKind::CloseSession,
                    ] {
                        let cx = unit.target.cap_ctx(draft, Some(1));
                        if let Support::Conditional(p) = classify(Site::Datagram, kind, &cx) {
                            saw_conditional += 1;
                            assert!(
                                matches!(p, Precondition::WithinMaxDatagramSize),
                                "unsupplied fact {p:?} at Datagram/{kind:?} draft {draft:?}",
                            );
                        }
                    }
                }
            }
        }
        assert!(
            saw_conditional > 0,
            "the sweep must reach the environmental preconditions, or it proves nothing",
        );
    }

    #[test]
    fn the_ledger_stays_the_same_length_as_the_queue() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            let actions = [
                Action::Pass.delayed(Duration::from_millis(30)),
                Action::Pass,
                Action::Drop(DropMode::Elide),
                Action::ReplacePayload(Bytes::from_static(b"abcd")),
                Action::Replace(Bytes::from_static(b"refused")),
                Action::ResetStream { code: 1 },
            ];
            for action in actions {
                h.run(&object_unit(&m, at), action);
                assert_eq!(
                    h.deferred.len(),
                    h.pending.len(),
                    "[{draft:?}] one ledger entry per pushed unit, always",
                );
            }
            assert!(h.pending.len() >= 5, "draft {draft:?}");
        }
    }

    #[test]
    fn backpressure_is_reported_once_per_stream() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::with_config(EgressConfig {
                max_pending_bytes: 16,
                max_hold: Duration::from_secs(30),
                ..EgressConfig::default()
            });
            let m = meta(draft);
            let at = Instant::now();
            h.run(&object_unit(&m, at), Action::Pass.delayed(Duration::from_secs(5)));
            let mut transitions = 0;
            for _ in 0..6 {
                let out = h.run(&object_unit(&m, at), Action::Pass);
                if out.entered_backpressure {
                    transitions += 1;
                }
            }
            assert_eq!(transitions, 1, "[{draft:?}] the transition is reported once");
            assert_eq!(
                h.observer
                    .impairments()
                    .iter()
                    .filter(|k| matches!(k, ImpairmentKind::EgressQueueFull { .. }))
                    .count(),
                1,
            );
        }
    }

    #[test]
    fn a_delay_beyond_max_hold_is_clamped_and_reported_once() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::with_config(EgressConfig {
                max_pending_bytes: 1 << 20,
                max_hold: Duration::from_millis(50),
                ..EgressConfig::default()
            });
            let m = meta(draft);
            let at = Instant::now();
            let out = h.run(&object_unit(&m, at), Action::Pass.delayed(Duration::from_secs(9)));
            let clamped = out.clamped.expect("a clamp happened");
            assert!(clamped.was_clamped(), "draft {draft:?}");
            assert_eq!(clamped.requested, Duration::from_secs(9));
            assert_eq!(clamped.applied, Duration::from_millis(50));
            assert_eq!(
                h.observer.impairments(),
                vec![ImpairmentKind::HoldClamped {
                    requested: Some(Duration::from_secs(9)),
                    applied: Duration::from_millis(50),
                }],
            );

            // An unclamped delay reports nothing.
            let mut h = Harness::new();
            let out = h.run(&object_unit(&m, at), Action::Pass.delayed(Duration::from_millis(5)));
            assert_eq!(out.clamped.map(|d| d.was_clamped()), Some(false), "draft {draft:?}");
            assert!(h.observer.impairments().is_empty());
        }
    }

    #[test]
    fn the_ledger_forgets_what_a_failed_drain_could_not_write() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            h.run(
                &object_unit(&m, at),
                Action::ReplacePayload(Bytes::from_static(b"abcd"))
                    .delayed(Duration::from_millis(10)),
            );
            assert_eq!(h.deferred.len(), 1, "draft {draft:?}");
            h.deferred.clear();
            assert!(h.deferred.is_empty(), "no Replaced is reported for bytes never written");
            assert!(h.deferred.take_all().is_empty());
        }
    }

    #[test]
    fn take_all_yields_only_the_entries_that_owe_an_event() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::new();
            let m = meta(draft);
            let at = Instant::now();
            h.run(&object_unit(&m, at), Action::Pass.delayed(Duration::from_millis(30)));
            h.run(&object_unit(&m, at), Action::Pass);
            h.run(
                &object_unit(&m, at),
                Action::ReplacePayload(Bytes::from_static(b"wxyz"))
                    .delayed(Duration::from_millis(40)),
            );
            assert_eq!(h.deferred.len(), 3, "draft {draft:?}");
            let owed = h.deferred.take_all();
            assert_eq!(owed.len(), 2, "the ordering-only unit owes nothing");
            assert_eq!(owed[0].action, ActionKind::Pass);
            assert_eq!(owed[1].effect, Effect::Replaced { bytes: 10 });
            assert!(h.deferred.is_empty());
        }
    }

    #[test]
    fn kind_of_agrees_with_the_published_attempt_mapping() {
        assert_eq!(kind_of(&Action::Pass), ActionKind::Pass);
        assert_eq!(kind_of(&Action::Replace(Bytes::new())), ActionKind::Replace);
        assert_eq!(kind_of(&Action::ReplacePayload(Bytes::new())), ActionKind::ReplacePayload,);
        assert_eq!(kind_of(&Action::Pass.delayed(Duration::ZERO)), ActionKind::Delay);
        assert_eq!(kind_of(&Action::Pass.held(Gate::new())), ActionKind::Hold);
        assert_eq!(kind_of(&Action::Drop(DropMode::Elide)), ActionKind::DropElide);
        assert_eq!(kind_of(&Action::Truncate { bytes: 0, code: 0 }), ActionKind::Truncate,);
        assert_eq!(kind_of(&Action::ResetStream { code: 0 }), ActionKind::ResetStream);
        assert_eq!(
            kind_of(&Action::CloseSession { code: 0, reason: Bytes::new() }),
            ActionKind::CloseSession,
        );
    }

    // ── The impairment surface: ordering, and the leg ───────────────
    //
    // The three tests below are the gate for a single rule — an impairment
    // is emitted *after* what it reports, never before — and for the field
    // that says which of the proxy's two connections it is about. Both are
    // driven through `execute` and `Reporter`, the same two calls every
    // forwarding pipe makes, rather than by handing a `ProxyEvent` to an
    // observer directly: what is being checked is where the emission sits
    // relative to the work, which a hand-built event cannot show.

    /// An action that is refused emits **no impairment at all**, even when
    /// the refused action's own arithmetic would have produced one.
    ///
    /// This is the rule in its sharpest form. `Delay { by: 9s }` against a
    /// 50 ms `max_hold` is a clamp by any reading of the numbers, and the
    /// clamp arithmetic is cheap enough that computing it early would look
    /// harmless. But the inner `ReplacePayload` is refused — seven bytes
    /// where the object's payload is four — so nothing is queued, nothing is
    /// held, and no wait is shortened. An observer told otherwise would have
    /// recorded a hold that was never applied to a unit that was forwarded
    /// unchanged, and there is no later event that takes an impairment back.
    ///
    /// The `Pass` case beside it is the control: the identical delay, with
    /// an inner action that is admitted, does clamp and does report. Without
    /// it the assertion would also pass against an engine that had stopped
    /// reporting clamps altogether.
    ///
    /// *Ablation, recorded:* in `plan_action`'s `Action::Delay` arm, hoist
    /// the `egress::defer_by` call and the `if deferral.was_clamped()`
    /// report above `let content = prepare_content(...)?;`, so the clamp is
    /// computed and reported before the inner action is judged. This test
    /// goes red with the real message
    ///
    /// ```text
    /// assertion `left == right` failed: [Draft07] a refused action changed
    /// nothing, so it impaired nothing
    ///   left: [HoldClamped { requested: Some(9s), applied: 50ms }]
    ///  right: []
    /// ```
    ///
    /// which is exactly the failure the rule exists to prevent: a hold
    /// reported against a unit that was forwarded verbatim.
    #[test]
    fn a_refused_action_reports_its_refusal_and_no_impairment() {
        for &draft in COMPILED_DRAFTS {
            let clamping = EgressConfig {
                max_pending_bytes: 1 << 20,
                max_hold: Duration::from_millis(50),
                ..EgressConfig::default()
            };
            let m = meta(draft);
            let at = Instant::now();

            let mut h = Harness::with_config(clamping);
            let out = h.run(
                &object_unit(&m, at),
                // Seven bytes into a four-byte payload: `ReplacePayload` is
                // length-preserving at the object site, so the inner action
                // is refused before anything is queued.
                Action::ReplacePayload(Bytes::from_static(b"toolong"))
                    .delayed(Duration::from_secs(9)),
            );
            assert!(!out.is_applied(), "[{draft:?}] the inner action is refused");
            assert_eq!(
                h.observer.impairments(),
                vec![],
                "[{draft:?}] a refused action changed nothing, so it impaired nothing",
            );
            assert_eq!(
                h.observer.refused().len(),
                1,
                "[{draft:?}] and the refusal itself is still reported",
            );

            // The control: the same delay, admitted, does clamp and does say
            // so — so the emptiness above is the refusal and not silence.
            let mut h = Harness::with_config(clamping);
            let out = h.run(&object_unit(&m, at), Action::Pass.delayed(Duration::from_secs(9)));
            assert!(out.is_applied(), "[{draft:?}] a plain delay is admitted");
            assert_eq!(
                h.observer.impairments(),
                vec![ImpairmentKind::HoldClamped {
                    requested: Some(Duration::from_secs(9)),
                    applied: Duration::from_millis(50),
                }],
            );
        }
    }

    /// Two impairments from one admitted action arrive in the order the
    /// engine did the work, both attributed to the connection being written
    /// to.
    ///
    /// A `Delay` beyond `max_hold` onto a queue smaller than the unit does
    /// two separate things — it shortens the wait, then it fills the queue —
    /// and each owes its own report. Asserted as a `Vec` rather than as two
    /// counts because the order is a claim: the clamp is decided while the
    /// unit is still being planned, and backpressure is only knowable once
    /// the push has happened. Reversed, the pair would say the queue was
    /// already full before the unit that filled it went in.
    ///
    /// Both name [`Leg::Upstream`] on a pipe reading from the client,
    /// because both are about the queue in front of the *relay* connection.
    /// A reader who took the event's `side` for a connection would attribute
    /// them to the client leg — the one this proxy was reading from and the
    /// one that is behaving perfectly.
    ///
    /// *Ablation, recorded:* in `event::impairment_leg`, move
    /// `EgressQueueFull` and `HoldClamped` out of the departure arm into the
    /// arrival arm — `Some(here)`. This test goes red with the real message
    ///
    /// ```text
    /// assertion `left == right` failed: [Draft07] the clamp is decided
    /// before the push and both belong to the connection being written to
    ///   left: [(Some(Client), HoldClamped { requested: Some(9s), applied:
    ///          50ms }), (Some(Client), EgressQueueFull { stream_id: 4 })]
    ///  right: [(Some(Upstream), HoldClamped { requested: Some(9s),
    ///          applied: 50ms }), (Some(Upstream), EgressQueueFull {
    ///          stream_id: 4 })]
    /// ```
    #[test]
    fn one_action_owes_two_impairments_in_the_order_it_earned_them() {
        for &draft in COMPILED_DRAFTS {
            let mut h = Harness::with_config(EgressConfig {
                // Below the ten-byte unit, so the very first push crosses
                // the limit and the transition is reported on it.
                max_pending_bytes: 4,
                max_hold: Duration::from_millis(50),
                ..EgressConfig::default()
            });
            let m = meta(draft);
            let out = h.run(
                &object_unit(&m, Instant::now()),
                Action::Pass.delayed(Duration::from_secs(9)),
            );
            assert!(out.is_applied(), "[{draft:?}] the delay is admitted");
            assert_eq!(
                h.observer.attributed_impairments(),
                vec![
                    (
                        Some(Leg::Upstream),
                        ImpairmentKind::HoldClamped {
                            requested: Some(Duration::from_secs(9)),
                            applied: Duration::from_millis(50),
                        },
                    ),
                    (Some(Leg::Upstream), ImpairmentKind::EgressQueueFull { stream_id: 4 }),
                ],
                "[{draft:?}] the clamp is decided before the push and both belong to the \
                 connection being written to",
            );
        }
    }

    /// The same impairment names the other connection when it is raised by
    /// the other pipe, and a report that is about neither connection names
    /// neither.
    ///
    /// The first half is what makes the field worth carrying: `HoldClamped`
    /// is `Leg::Upstream` on the pipe reading from the client and
    /// `Leg::Client` on the pipe reading from the relay, because in both
    /// cases it is the far side that is being written to. The second half is
    /// [`ImpairmentKind::CoarseReleaseTimer`], which is a fact about the
    /// host's clock: it is equally true of both legs, stays true if one goes
    /// away, and so answers `None` rather than being pinned to whichever
    /// pipe noticed the coarse tick first.
    ///
    /// *Ablation, recorded:* in `event::impairment_leg`, move
    /// `CoarseReleaseTimer` from the `None` arm into the departure arm. This
    /// test goes red with the real message
    ///
    /// ```text
    /// assertion `left == right` failed: the release wheel belongs to the
    /// process, not to a connection, so the pipe reading from
    /// ClientToProxy must not name one either
    ///   left: Some(Upstream)
    ///  right: None
    /// ```
    ///
    /// — a host-clock fact attributed to the relay connection, and it would
    /// have been attributed to the client connection had the other pipe
    /// reported it first.
    #[test]
    fn the_leg_turns_with_the_pipe_and_is_absent_where_there_is_none() {
        let draft = COMPILED_DRAFTS[0];
        let m = meta(draft);
        let clamping = EgressConfig {
            max_pending_bytes: 1 << 20,
            max_hold: Duration::from_millis(50),
            ..EgressConfig::default()
        };

        for (side, expected) in
            [(ProxySide::ClientToProxy, Leg::Upstream), (ProxySide::RelayToProxy, Leg::Client)]
        {
            let mut h = Harness::with_config(clamping).reading_from(side);
            h.run(&object_unit(&m, Instant::now()), Action::Pass.delayed(Duration::from_secs(9)));
            assert_eq!(
                h.observer.attributed_impairments(),
                vec![(
                    Some(expected),
                    ImpairmentKind::HoldClamped {
                        requested: Some(Duration::from_secs(9)),
                        applied: Duration::from_millis(50),
                    },
                )],
                "a clamp on the pipe reading from {side:?} holds bytes off the {expected:?} leg",
            );
        }

        // Both pipes, because *equally true of both legs* is the claim. A
        // single side would pass against a mapping that answers whichever
        // connection the reporting pipe happens to be on — which is the guess
        // this arm exists to refuse.
        for side in [ProxySide::ClientToProxy, ProxySide::RelayToProxy] {
            let h = Harness::new().reading_from(side);
            h.report().impairment(ImpairmentKind::CoarseReleaseTimer {
                backend: crate::instrument::TimerBackend::Condvar,
                detail: None,
            });
            let attributed = h.observer.attributed_impairments();
            assert_eq!(attributed.len(), 1);
            assert_eq!(
                attributed[0].0, None,
                "the release wheel belongs to the process, not to a connection, so the pipe \
                 reading from {side:?} must not name one either",
            );
        }
    }

    /// One pipe, three reports, three different answers — as an exact
    /// sequence rather than a set.
    ///
    /// This is the shape the whole surface is for. A single forwarding task
    /// reading from the client raises a parser failure about the bytes that
    /// arrived, a queue failure about the bytes it is trying to place, and a
    /// host fact about neither, and the three have to come back attributed
    /// to `Client`, `Upstream` and nothing respectively. Compared as a `Vec`
    /// because the order is part of the claim: an impairment is emitted
    /// after what it reports, so the sequence is the order the proxy did
    /// things in, and a set would pass against a proxy that reported them
    /// backwards.
    ///
    /// *Ablation, recorded:* in `event::impairment_leg`, fold
    /// `FramerBypass` and `ObjectNotAddressable` into the departure arm, so
    /// every report answers the far connection. This test goes red with the
    /// real message
    ///
    /// ```text
    /// assertion `left == right` failed: one pipe, three answers: what
    /// arrived, what could not be written, and neither
    ///   left: [(Some(Upstream), FramerBypass { stream_id: 4, draft:
    ///          Draft07, reason: DecodeError }), (Some(Upstream),
    ///          EgressQueueFull { stream_id: 4 }), (None, CoarseReleaseTimer
    ///          { backend: Condvar, detail: None })]
    ///  right: [(Some(Client), FramerBypass { stream_id: 4, draft: Draft07,
    ///          reason: DecodeError }), (Some(Upstream), EgressQueueFull {
    ///          stream_id: 4 }), (None, CoarseReleaseTimer { backend:
    ///          Condvar, detail: None })]
    /// ```
    ///
    /// — a stream the proxy could not parse on the way *in*, blamed on the
    /// connection it was writing out to.
    #[test]
    fn one_pipe_reports_the_near_leg_the_far_leg_and_neither_in_order() {
        let draft = COMPILED_DRAFTS[0];
        let h = Harness::new();
        let report = h.report();

        report.impairment(ImpairmentKind::FramerBypass {
            stream_id: 4,
            draft,
            reason: crate::types::BypassReason::DecodeError,
        });
        report.impairment(ImpairmentKind::EgressQueueFull { stream_id: 4 });
        report.impairment(ImpairmentKind::CoarseReleaseTimer {
            backend: crate::instrument::TimerBackend::Condvar,
            detail: None,
        });

        assert_eq!(
            h.observer.attributed_impairments(),
            vec![
                (
                    Some(Leg::Client),
                    ImpairmentKind::FramerBypass {
                        stream_id: 4,
                        draft,
                        reason: crate::types::BypassReason::DecodeError,
                    },
                ),
                (Some(Leg::Upstream), ImpairmentKind::EgressQueueFull { stream_id: 4 }),
                (
                    None,
                    ImpairmentKind::CoarseReleaseTimer {
                        backend: crate::instrument::TimerBackend::Condvar,
                        detail: None,
                    },
                ),
            ],
            "one pipe, three answers: what arrived, what could not be written, and neither",
        );
    }
}

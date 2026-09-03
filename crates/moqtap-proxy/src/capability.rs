//! What is representable, per draft, per site, per stream — and why not.
//!
//! One function answers that question — [`classify`] — and it has exactly
//! two callers: [`Capabilities::supports`] / [`Capabilities::supports_on`],
//! which publish the table a caller reads before a run, and the
//! engine's executor, which decides what actually happens during one. That
//! is the whole of the design: the table and the engine are the same code,
//! so the table cannot become a documented lie about the engine.
//! `tests/action_matrix.rs` asserts it against observed behaviour on all
//! fourteen drafts.
//!
//! # Where each [`Refusal`] comes from
//!
//! Not every refusal is a `(site, kind)` fact, so not every refusal is
//! [`classify`]'s to produce:
//!
//! * **Classified here**, from `(site, kind)` plus [`CapCtx`]:
//!   [`Refusal::WrongSite`], [`Refusal::ControlStreamResetIllegal`],
//!   [`Refusal::LengthChanged`], [`Refusal::WouldRedefineSubgroupId`],
//!   [`Refusal::WouldDestroyStatusObject`], [`Refusal::ReservedHeaderMode`] and
//!   [`Refusal::PayloadNotDelimited`].
//! * **Produced by the executor**, because they depend on the action's payload
//!   or on session state rather than on the pair: [`Refusal::WrongComposition`]
//!   (what a `Delay` / `Hold` wrapped), [`Refusal::ErrorCodeOutOfRange`] (the
//!   numeric code) and [`Refusal::SessionAlreadyClosing`] (a close already in
//!   flight). They are reachable, and the sweep observes them; they are simply
//!   not decidable from a kind.
//! * **Table-only**: [`Refusal::StreamNotFramed`] and
//!   [`Refusal::ControlFrameNotDecodable`]. Both appear only inside
//!   [`Support::NotAttemptable`] and [`Support::Unreachable`], where nothing is
//!   ever attempted, so neither is ever emitted as a
//!   `ProxyEvent::ActionRefused`.
//!
//! `tests/action_matrix.rs::every_declared_refusal_is_reachable_or_declared_table_only`
//! asserts that split per *variant*, in both directions.
//!
//! # The table answers for a **build**, not only for a draft
//!
//! [`DraftVersion`] carries all fourteen variants under every feature set,
//! so [`Capabilities::for_draft`] answers for drafts this binary cannot
//! speak. A reduced-draft build — `--no-default-features --features
//! draft07`, a shipped configuration and one of CI's fourteen rows — cannot
//! frame a byte of the twelve drafts it left out, and
//! `ProxySessionConfig::default().draft` is `Draft14` with nothing
//! validating it against the compiled set. [`draft_is_compiled`] is
//! therefore a fact [`classify`] reads, exactly like the draft number, and
//! the object **and control** sites on an uncompiled draft are
//! [`Support::Unreachable`] rather than [`Support::Yes`]. The two fail in
//! different decoders and report different events, so they are two reads
//! of the same fact rather than one; see [`Instead`], which is where each
//! names what a run emits in its place. In the default all-drafts build
//! every row of the table is unchanged.

use moqtap_codec::version::DraftVersion;

use crate::shape::{ClassRule, MatchKind, Matcher, ShapeProfile};
use crate::types::BypassReason;
use crate::types::DataStreamType;

/// The fourth value of the two-bit subgroup-ID mode, which no draft assigns.
///
/// Drafts 16 through 20 reserve it by name and list the type bytes that carry
/// it; draft-15 arrives at the same eight bytes by leaving them out of its
/// table. Either way no header the decoder returns holds this value.
///
/// The codec stores a placeholder zero for **both** mode 1 (*subgroup ID is the
/// first object's ID*) and this one, which is why [`CapCtx::subgroup_id_mode`]
/// exists at all: without it a reserved-mode header is indistinguishable from a
/// first-object-mode header and the elide guard reports
/// [`Refusal::WouldRedefineSubgroupId`] for something that is not a subgroup ID
/// question.
const RESERVED_SUBGROUP_ID_MODE: u8 = 3;

/// Where a decision was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Site {
    /// [`ProxyHook::on_control_message`](crate::hook::ProxyHook::on_control_message).
    Control,
    /// [`ProxyHook::on_object`](crate::hook::ProxyHook::on_object).
    Object,
    /// [`ProxyHook::on_datagram`](crate::hook::ProxyHook::on_datagram).
    Datagram,
    /// [`ProxyHook::on_stream_open`](crate::hook::ProxyHook::on_stream_open).
    StreamOpen,
    /// [`ProxyHook::on_stream_header`](crate::hook::ProxyHook::on_stream_header).
    StreamHeader,
    /// [`ProxyHook::on_stream_end`](crate::hook::ProxyHook::on_stream_end).
    ///
    /// Honours [`Action::Pass`](crate::action::Action::Pass),
    /// [`Action::ResetStream`](crate::action::Action::ResetStream) on a
    /// **data** stream, and
    /// [`Action::CloseSession`](crate::action::Action::CloseSession) on
    /// either kind of stream — a session close is session-scoped, so no
    /// site can be the wrong one for it. Everything else is refused;
    /// delaying a stream's end is expressed by delaying its last object.
    /// [`CapCtx::is_control_stream`] is what splits the two published
    /// columns.
    StreamEnd,
}

/// A capability, named independently of whether
/// [`Action`](crate::action::Action) can express it.
///
/// Every kind here names a capability some value can express. A kind that
/// nothing could construct used to be published too, so the table could
/// document the gap — but a variant that no value can carry is a unit that
/// compiles and never runs, and a table row saying so is a row about this
/// crate's plans rather than about what it does. Two such kinds were
/// removed; the capabilities they named are simply absent, and absence is
/// what the table now says by not listing them.
///
/// [`Self::OpenAfter`] and [`Self::SerializeAfter`] were in that family
/// until 0.4.0, when that release shipped
/// [`StreamAction::OpenAfter`](crate::action::StreamAction::OpenAfter) and
/// [`StreamAction::SerializeAfter`](crate::action::StreamAction::SerializeAfter);
/// their rustdoc now carries ordinary doc-tests that *construct* them,
/// where it used to carry `compile_fail` blocks that could not.
///
/// [`Self::ReplaceObject`] is deliberately **not** in that family, and the
/// distinction is what keeps the table honest: a value that carries it to
/// [`Site::Object`] exists (`Action::Replace(b)`), so the engine really is
/// asked and really does refuse, with [`Refusal::WrongSite`]. The
/// deferred-capability id printed on the *variant* names the gap; it is
/// not the refusal a run emits. See the variant's own rustdoc.
///
/// **Attempt mapping** — how `tests/action_matrix.rs` turns a `(site,
/// kind)` pair into something to run. Every kind maps to exactly one
/// expression, and a kind whose mapping does not typecheck at a site is
/// precisely a `NotAttemptable` cell:
///
/// | Kind | The attempt |
/// |---|---|
/// | `Pass` | `Action::Pass` |
/// | `Replace` | `Action::Replace(b)` |
/// | `ReplacePayload` | `Action::ReplacePayload(b)`, `b.len() == payload_len` |
/// | `ReplaceObject` | `Action::Replace(b)` **at `Site::Object` only** — the same expression as `Replace`, so those two cells must agree, and `action_matrix.rs` asserts that they do. At every other site there is no attempt: the same expression there is `Replace`'s attempt, and this kind names a unit those sites do not carry (`NotAttemptable::KindNotDefinedAtThisSite`) |
/// | `Delay` | `Action::Pass.delayed(d)` |
/// | `Hold` | `Action::Pass.held(gate)` |
/// | `DropElide` | `Action::Drop(DropMode::Elide)` |
/// | `Truncate` | `Action::Truncate { bytes, code }` |
/// | `ResetStream` | `Action::ResetStream { code }` |
/// | `CloseSession` | `Action::CloseSession { code, reason }` |
/// | `Open` | `StreamAction::Open` |
/// | `Reject` | `StreamAction::Reject { code }` |
/// | `OpenAfter` | `StreamAction::OpenAfter(d)` |
/// | `SerializeAfter` | `StreamAction::SerializeAfter(key)` |
///
/// `Action::ReplacePayload` with a mismatched length **is** constructible,
/// and it is refused with [`Refusal::LengthChanged`] — the `ReplacePayload`
/// cell's `Conditional` failing. Re-framing an object around a new length
/// is a different capability, and it has no row here because it has no
/// value: there is nothing to attempt and therefore nothing to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionKind {
    /// [`Action::Pass`](crate::action::Action::Pass).
    Pass,
    /// [`Action::Replace`](crate::action::Action::Replace).
    Replace,
    /// [`Action::ReplacePayload`](crate::action::Action::ReplacePayload) at
    /// the original length.
    ReplacePayload,
    /// [`Action::Delay`](crate::action::Action::Delay).
    Delay,
    /// [`Action::Hold`](crate::action::Action::Hold).
    Hold,
    /// [`Action::Drop`](crate::action::Action::Drop) with
    /// [`DropMode::Elide`](crate::action::DropMode::Elide).
    DropElide,
    /// [`Action::Truncate`](crate::action::Action::Truncate).
    Truncate,
    /// [`Action::ResetStream`](crate::action::Action::ResetStream).
    ResetStream,
    /// [`Action::CloseSession`](crate::action::Action::CloseSession).
    CloseSession,
    /// [`StreamAction::Open`](crate::action::StreamAction::Open).
    Open,
    /// [`StreamAction::Reject`](crate::action::StreamAction::Reject).
    Reject,
    /// Replacing a whole wire object. **Attemptable and refused, not
    /// unconstructible** — `Action::Replace(b)` at [`Site::Object`] is
    /// exactly this attempt, so the engine is really asked and answers
    /// with [`Refusal::WrongSite`]. Whole-object replacement at the object
    /// site is a real attempt that really is refused, which is why this
    /// kind is published and why its refusal is one a run emits.
    ///
    /// At every non-object site it is
    /// `NotAttemptable { why: KindNotDefinedAtThisSite, refusal:
    /// WrongSite { site, action: ReplaceObject } }`: a control frame, a
    /// datagram and a stream are not objects, so no value carries this
    /// kind there and nothing is ever attempted.
    ReplaceObject,
    /// Opening the peer stream after a delay.
    /// [`StreamAction::OpenAfter`](crate::action::StreamAction::OpenAfter),
    /// shipped in 0.4.0; this kind is no longer in the constructor-less
    /// family.
    ///
    /// `open_after_and_serialize_after_are_constructible` — the pair of
    /// doc-tests that used to prove this capability's *absence* now proves
    /// its presence, and they remain the crate's only compile-time proof
    /// that the two variants exist with the shape they do. They are ordinary
    /// doc-tests rather than inverted `compile_fail` blocks on purpose: a
    /// `compile_fail` block that fails for the *wrong* reason reports `ok`
    /// exactly as loudly as one that fails for the right one, which is how
    /// the two blocks this replaces went on passing while asserting a
    /// **struct**-variant syntax (`OpenAfter { after: … }`) that never
    /// matched the tuple variants that actually exist. An ordinary
    /// doc-test can only pass by compiling *and* running.
    ///
    /// ```
    /// // open_after_and_serialize_after_are_constructible (1 of 2)
    /// use std::time::Duration;
    /// use moqtap_proxy::action::StreamAction;
    ///
    /// let a = StreamAction::OpenAfter(Duration::from_millis(1));
    /// assert!(matches!(a, StreamAction::OpenAfter(d) if d == Duration::from_millis(1)));
    /// ```
    ///
    /// ```
    /// // open_after_and_serialize_after_are_constructible (2 of 2)
    /// use moqtap_proxy::action::StreamAction;
    /// use moqtap_proxy::event::ProxySide;
    /// use moqtap_proxy::shape::StreamKey;
    ///
    /// // A session-local id plus the side it arrived on — never a
    /// // transport stream id, which is the constant 0 on WebTransport.
    /// let key = StreamKey { side: ProxySide::ClientToProxy, id: 7 };
    /// let b = StreamAction::SerializeAfter(key);
    /// assert!(matches!(b, StreamAction::SerializeAfter(k) if k == key));
    /// ```
    ///
    /// And the verdicts, which is the one place the two kinds disagree:
    /// `SerializeAfter` takes exactly the verdict
    /// [`Self::Open`] takes at every site, and `OpenAfter` takes the same
    /// except at [`Site::StreamHeader`], where the peer stream already
    /// exists and there is nothing left to defer.
    ///
    /// ```
    /// use moqtap_proxy::capability::{classify, ActionKind, CapCtx, Refusal, Site, Support};
    /// for site in [Site::StreamOpen, Site::StreamHeader] {
    ///     assert_eq!(
    ///         classify(site, ActionKind::SerializeAfter, &CapCtx::default()),
    ///         classify(site, ActionKind::Open, &CapCtx::default()),
    ///         "SerializeAfter tracks Open at every site",
    ///     );
    /// }
    /// assert_eq!(
    ///     classify(Site::StreamOpen, ActionKind::OpenAfter, &CapCtx::default()),
    ///     Support::Yes,
    /// );
    /// assert_eq!(
    ///     classify(Site::StreamHeader, ActionKind::OpenAfter, &CapCtx::default()),
    ///     Support::No(Refusal::WrongSite {
    ///         site: Site::StreamHeader,
    ///         action: ActionKind::OpenAfter,
    ///     }),
    /// );
    /// ```
    OpenAfter,
    /// Head-of-line simulation.
    /// [`StreamAction::SerializeAfter`](crate::action::StreamAction::SerializeAfter),
    /// shipped in 0.4.0; this kind is no longer in the constructor-less
    /// family either.
    ///
    /// Its constructor proof hangs on [`Self::OpenAfter`], with its pair,
    /// as its `compile_fail` block used to.
    SerializeAfter,
}

/// Whether a capability is available.
///
/// Five verdicts, not three. The earlier design had `Yes` / `No` /
/// `Conditional` only, and a large part of the published matrix fits none
/// of them: 30 site×kind pairs are ruled out by the *return type* (a site
/// that returns [`StreamAction`](crate::action::StreamAction) cannot be
/// handed an [`Action`](crate::action::Action), and four [`ActionKind`]s
/// have no constructor at all), and every cell on a draft this build did not
/// compile names a refusal the engine can never emit because the hook is
/// never invoked there. Both classes used to be written `—` or "unreachable" in prose,
/// which `tests/action_matrix.rs` cannot assert. They are now verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Support {
    /// The engine executes it and the wire changes.
    Yes,
    /// Attemptable, and the engine refuses it with this reason. Exactly
    /// one `ProxyEvent::ActionRefused` per attempt.
    No(Refusal),
    /// Executable, gated on a per-unit fact the table caller did not
    /// supply. The precondition is named so a caller can test for it.
    Conditional(Precondition),
    /// **No value of [`Action`](crate::action::Action) or
    /// [`StreamAction`](crate::action::StreamAction) can carry this kind to
    /// this site**, so the engine can never be asked and no
    /// `ActionRefused` can ever be emitted.
    ///
    /// Three families, and [`NotAttemptable`] names which:
    ///
    /// 1. a site whose return type is the other enum (`Pass` at
    ///    `StreamOpen`, `Reject` at `Object`, …) — two variants,
    ///    [`NotAttemptable::SiteReturnsAction`] and
    ///    [`NotAttemptable::SiteReturnsStreamAction`], so that the table
    ///    says which direction the mismatch runs in;
    /// 2. a kind whose unit does not exist at this site —
    ///    [`ActionKind::ReplaceObject`] anywhere but [`Site::Object`].
    ///
    /// `refusal` is what the published table reports and is never emitted
    /// as an event. For both families it is a variant that *is* reachable
    /// elsewhere in the matrix ([`Refusal::WrongSite`]). The split is per
    /// *variant*, not per cell: a variant is table-only when no cell
    /// anywhere emits it as a real `ActionRefused`.
    /// What the sweep observes is **zero action events** — no `ActionApplied`,
    /// no `ActionRefused`, no `ActionFailed` — and `actions_refused` unchanged.
    /// It is not *zero events of any kind*: per-stream impairments are a
    /// property of the stream, not of the kind swept, so a stream the framer
    /// gave up on still reports its one `Impairment { FramerBypass { .. } }`
    /// while every `NotAttemptable` cell on it stays silent.
    NotAttemptable {
        /// Which family, so a reader is not left to infer it.
        why: NotAttemptable,
        /// What the table reports. Never emitted as an event.
        refusal: Refusal,
    },
    /// Constructible and well-formed, but the hook is **never invoked**
    /// for this cell, so nothing is ever attempted and no `ActionRefused`
    /// is ever emitted.
    ///
    /// Two occupants, each reporting what the run does emit rather than
    /// the refusal it cannot. Both are a draft this build did not compile,
    /// one decoder apart — see `object_framing_bypass`:
    ///
    /// 1. **any** stream on such a draft, where the stream *header* decode
    ///    returns `UnsupportedDraft` first — see [`draft_is_compiled`], which
    ///    is why this verdict is a build fact and not only a draft fact.
    /// 2. the **control** site on such a draft, where
    ///    `AnyControlMessage::decode` has no arm and
    ///    `ControlStreamParser::feed` steps over every frame before the
    ///    hook is offered one. Same fact as case 1, a different decoder,
    ///    and a different report — which is what [`Instead`] is for.
    ///
    /// There was a third, and its going is worth a sentence because it is
    /// the shape of thing this enum is easiest to be wrong about. A fetch
    /// stream on drafts 18, 19 and 20 used to occupy this verdict, on the
    /// grounds that nothing on such a stream settles the Group Order its
    /// Group IDs are differences against. Nothing on the *stream* still
    /// does; the FETCH that opened it always did, and the session reads it
    /// now — see `fetch_group_order_is_needed`. The cell was answering a
    /// question about a draft with a fact about one component.
    ///
    /// A caller that reads the table by draft number alone will not see
    /// case 1 coming, which is why the table answers by build rather than by
    /// number. It is not a state a *session* can now reach —
    /// [`ProxySession::run`](crate::session::ProxySession::run) refuses an
    /// uncompiled draft with
    /// [`ProxyError::DraftNotCompiled`](crate::error::ProxyError::DraftNotCompiled)
    /// before it dials — but the table is answerable without a session, and a
    /// caller asking it about a draft this build does not carry has to be
    /// told the truth about that draft rather than about draft numbers in
    /// general.
    Unreachable {
        /// What the table reports. Never emitted as an event.
        refusal: Refusal,
        /// What the run emits instead, and how often.
        instead: Instead,
    },
}

/// What a run reports in place of the action event a
/// [`Support::Unreachable`] cell can never produce.
///
/// Every `Unreachable` cell owes one, and giving the field a type of its own is
/// what collects the debt: a cell whose only honest answer would be *nothing at
/// all is emitted* finds no variant here to reach for, so it cannot be
/// published until the report it needs exists. The control site on an
/// uncompiled draft sat outside this enum for exactly that reason, answering
/// [`Support::Yes`] for a cell no hook is ever offered, until
/// [`ImpairmentKind::ControlFrameNotDecodable`](crate::event::ImpairmentKind::ControlFrameNotDecodable)
/// gave it something true to point at.
///
/// The field is not a second copy of `refusal`. A refusal names what the
/// *table* would say; this names what an observer will actually see on the
/// wire-facing side, which is the only thing a run can be checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Instead {
    /// [`ProxyEvent::Impairment`](crate::event::ProxyEvent::Impairment)
    /// carrying
    /// [`ImpairmentKind::FramerBypass`](crate::event::ImpairmentKind::FramerBypass)
    /// with this reason, **once per such stream**.
    FramerBypass(BypassReason),
    /// [`ProxyEvent::Impairment`](crate::event::ProxyEvent::Impairment)
    /// carrying
    /// [`ImpairmentKind::ControlFrameNotDecodable`](crate::event::ImpairmentKind::ControlFrameNotDecodable),
    /// **once per control stream direction**, however many frames were
    /// refused; the running figure is
    /// [`Counters::control_frames_not_decodable`](crate::instrument::Counters::control_frames_not_decodable).
    ///
    /// Carries no reason, because on this cell there is only one: the
    /// build. A frame refused on a draft that *was* compiled produces the
    /// same event and no table cell, since it is a fact about one frame.
    ControlFrameNotDecodable,
}

/// Why a [`Support::NotAttemptable`] cell cannot be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotAttemptable {
    /// This site's hook method returns
    /// [`StreamAction`](crate::action::StreamAction), and `kind` names a
    /// content action.
    SiteReturnsStreamAction,
    /// This site's hook method returns [`Action`](crate::action::Action),
    /// and `kind` names a stream action.
    SiteReturnsAction,
    /// No value of [`Action`](crate::action::Action) or
    /// [`StreamAction`](crate::action::StreamAction) carries this kind to
    /// this site, so nothing here can be attempted.
    NoConstructor,
    /// The kind names a unit this site does not carry, so no value can
    /// bring it here even though the *expression* that would carry it is
    /// well-typed at this site under a different kind.
    ///
    /// The only occupant is [`ActionKind::ReplaceObject`] at any
    /// site but [`Site::Object`]: `Action::Replace(b)` typechecks at
    /// `Site::Control` and `Site::Datagram`, but there it *is* the
    /// [`ActionKind::Replace`] attempt — a control frame is not an
    /// object. The accompanying refusal is
    /// [`Refusal::WrongSite`], the same refusal the attemptable
    /// `ReplaceObject × Object` cell really emits, so a reader comparing
    /// the table against a run sees one consistent answer.
    KindNotDefinedAtThisSite,
}

// ── Table-only refusals ────────────────────────────────────────────────
//
// `Support::NotAttemptable` and `Support::Unreachable` both carry a
// `Refusal` the engine never emits, because in both cases nothing is ever
// attempted. Exactly one `Refusal` variant is table-only —
// `Refusal::StreamNotFramed` — and
// `tests/action_matrix.rs::every_declared_refusal_is_reachable_or_declared_table_only`
// asserts that split in both directions: every other variant must be
// observed as a real `ActionRefused` somewhere in the sweep, and this one
// must never be.

/// A runtime fact a [`Support::Conditional`] verdict depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Precondition {
    /// The replacement must be exactly `ObjectMeta::payload_len` bytes and
    /// the object must not carry a status.
    ReplacementLengthEqualsPayload,
    /// The object must not be index 0 of a stream whose subgroup ID is
    /// defined as the first object's ID.
    NotFirstObjectOfImplicitSubgroup,
    /// The object must not carry an Object Status.
    NotAStatusObject,
    /// The unit's payload must start at a known offset.
    ///
    /// True at the object site on every draft (`wire_len -
    /// payload_length`). At the **datagram** site it is true on
    /// twelve drafts and false on three counts:
    ///
    /// * **draft-14**, where `AnyDatagramHeader` is a `DatagramObject`
    ///   whose `decode` consumes the payload, so the only derivable
    ///   offset is the whole datagram;
    /// * a **status datagram**, which has no payload slot;
    /// * a datagram whose header **did not decode**, where the hook still
    ///   fires but no offset exists.
    ///
    /// Failing it is [`Refusal::PayloadNotDelimited`].
    DatagramPayloadDelimited,
    /// The replacement must fit the connection's maximum datagram size.
    ///
    /// **[`classify`] cannot evaluate this one.** Nothing in
    /// `moqtap-client`'s transport exposes a maximum datagram size, so
    /// [`CapCtx`] has no field for it and this verdict is always
    /// `Conditional`: the actual answer comes from `send_datagram`
    /// failing. That makes it the one precondition whose failure is a
    /// `ProxyEvent::ActionFailed` rather than an `ActionRefused` — the
    /// action was admitted and the transport rejected it. Stated here
    /// rather than left to be inferred.
    WithinMaxDatagramSize,
}

/// Why an action could not be executed.
///
/// Reported per attempt, never once per stream. A rule that would have
/// fired forty times and was refused forty times reports forty.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The action has no meaning at this site.
    WrongSite {
        /// Where it was attempted.
        site: Site,
        /// What was attempted.
        action: ActionKind,
    },
    /// A `Delay` or `Hold` wrapped an action the engine cannot schedule.
    WrongComposition {
        /// What the modifier wrapped.
        detail: &'static str,
    },
    /// Performing it would be a session-level protocol violation — a reset
    /// or truncation of a control stream, on any draft 07-20.
    ControlStreamResetIllegal,
    /// `ReplacePayload` whose length differs from the original.
    LengthChanged {
        /// The original payload length.
        from: u64,
        /// The replacement's length.
        to: u64,
    },
    /// Eliding index 0 of a stream whose subgroup ID is the first object's
    /// ID would silently redefine the subgroup ID downstream.
    WouldRedefineSubgroupId,
    /// Eliding an object that carries an Object Status would destroy what
    /// may be a boundary marker.
    WouldDestroyStatusObject,
    /// The stream header's subgroup-ID mode field holds a value this
    /// draft reserves, so the header is not interpretable and no object
    /// on the stream can be safely renumbered.
    /// Distinct from [`Self::WouldRedefineSubgroupId`] on purpose. On drafts
    /// 15 through 19 the codec stores a placeholder zero for **both** mode 1
    /// (*subgroup ID is the first object's ID*) and mode 3 (reserved), so an
    /// accessor returning `Option<u64>` cannot tell them apart and the earlier
    /// guard would have reported `WouldRedefineSubgroupId` for a reserved-mode
    /// header, where that reason is simply untrue.
    /// `AnySubgroupHeader::subgroup_id_mode()` is what makes the distinction
    /// available.
    ReservedHeaderMode {
        /// The mode value read from the header-type octet.
        mode: u8,
    },
    /// The unit's payload boundary is not derivable, so a
    /// payload-preserving splice cannot be located.
    ///
    /// Datagrams only. See [`Precondition::DatagramPayloadDelimited`] for
    /// the three cases.
    PayloadNotDelimited {
        /// Which case: `*draft-14 header decode consumes the payload*`,
        /// `*status datagram has no payload*`, or `*datagram header did not
        /// decode*`.
        detail: &'static str,
    },
    /// The framer stopped parsing this stream, so there is nothing
    /// addressable to act on.
    ///
    /// **Table-only** — see the module's note above [`Precondition`]. The
    /// engine never emits it, because when it is true the hook is never
    /// called.
    StreamNotFramed {
        /// Why the framer gave up.
        reason: BypassReason,
    },
    /// The decoder refused this control frame, so there is nothing decoded
    /// to act on.
    ///
    /// **Table-only** — see the module's note above [`Precondition`]. The
    /// engine never emits it, because when it is true
    /// [`ProxyHook::on_control_message`](crate::hook::ProxyHook::on_control_message)
    /// is never called: the message it would be handed is the thing that
    /// did not decode.
    ///
    /// Published for a draft this build did not compile, where
    /// `AnyControlMessage::decode` has no arm and refuses every frame the
    /// stream carries. One malformed frame on a draft that *is* compiled
    /// is refused for the same reason, but that is a fact about one frame
    /// rather than about the pair the table answers for, so no cell
    /// publishes it and the run reports it as
    /// [`ImpairmentKind::ControlFrameNotDecodable`](crate::event::ImpairmentKind::ControlFrameNotDecodable)
    /// instead.
    ControlFrameNotDecodable,
    /// The application error code exceeds the QUIC varint range
    /// (2^62 - 1). Nothing was sent and the stream stays usable.
    ErrorCodeOutOfRange {
        /// The code that was requested.
        code: u64,
    },
    /// A session close is already in flight.
    SessionAlreadyClosing,
}

/// The facts [`classify`] needs.
///
/// A caller building the published table leaves the per-unit fields `None`
/// and gets [`Support::Conditional`] where the answer depends on them; the
/// engine fills them in and gets [`Support::Yes`] or [`Support::No`].
///
/// The struct is `#[non_exhaustive]`, so build one with
/// [`CapCtx::default`] and assign the fields that are known.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapCtx {
    /// The draft the session is running as.
    pub draft: Option<DraftVersion>,
    /// Which stream kind, at the object site.
    pub stream_kind: Option<DataStreamType>,
    /// Whether the stream is a control stream.
    ///
    /// Read at [`Site::StreamEnd`], which publishes two columns: `Some(true)`
    /// selects the control column, and `Some(false)` or `None` the data one.
    pub is_control_stream: Option<bool>,
    /// Zero-based index of the object within its stream.
    pub index_in_stream: Option<u64>,
    /// Whether the stream header determines the subgroup ID.
    pub subgroup_id_resolved: Option<bool>,
    /// Whether the object carries an Object Status.
    pub is_status_object: Option<bool>,
    /// Declared payload length.
    pub payload_len: Option<u64>,
    /// Length of a proposed replacement payload.
    pub replacement_len: Option<u64>,
    /// Whether this unit's payload starts at a known offset.
    ///
    /// Always `Some(true)` at the object site. At the datagram site the
    /// engine sets it from `data.len() - cursor.len()` being a real
    /// boundary — false on draft-14, on a status datagram, and when the
    /// header did not decode. Drives
    /// [`Precondition::DatagramPayloadDelimited`].
    pub payload_delimited: Option<bool>,
    /// The two-bit subgroup-ID mode, on the drafts 15-20 whose header type
    /// carries one. `None` on drafts 07-14, which have no such pair of bits,
    /// and when the caller did not supply it. Mode 1 is *subgroup ID is the
    /// first object's ID*; mode 3 is the value no draft assigns. Drives the
    /// split between [`Refusal::WouldRedefineSubgroupId`] and
    /// [`Refusal::ReservedHeaderMode`].
    pub subgroup_id_mode: Option<u8>,
}

/// The single source of truth for what is executable.
///
/// [`Capabilities::supports`] and the engine's executor are its only two
/// callers, which is what keeps the published table and the engine from
/// disagreeing. `tests/action_matrix.rs` asserts the table against observed
/// behaviour on all fourteen drafts.
///
/// # How the verdict is reached
///
/// In order, because the order is what makes [`ActionKind::ReplaceObject`]
/// have exactly one reading:
///
/// 1. `ReplaceObject` off [`Site::Object`] is `NotAttemptable
///    { KindNotDefinedAtThisSite, WrongSite { .. } }`, and at `Site::Object`
///    it is the same `No(WrongSite { .. })` as `Replace` — one value for
///    both rows, since one expression carries both.
/// 3. A return-type mismatch is `NotAttemptable { SiteReturns.., WrongSite
///    { .. } }`.
/// 4. The object site behind a stream the framer cannot address is
///    [`Support::Unreachable`]: the hook is never invoked there, so no
///    refusal can be emitted and the run's reportable fact is the bypass.
///    One fact reaches this step: a draft this build did not compile
///    ([`draft_is_compiled`]). A fetch stream used to bring a second, and no
///    longer does — see `fetch_group_order_is_needed` for where that went.
/// 5. The control site on a draft this build did not compile is
///    [`Support::Unreachable`] too, for the same reason one decoder later:
///    every frame is stepped over before the hook is offered one.
/// 6. Otherwise the per-site rules apply.
///
/// # What an unsupplied fact means
///
/// A `None` field is *the caller did not say*, which yields
/// [`Support::Conditional`] naming the fact — never a guess. Two `None`s are
/// read structurally rather than conditionally, because a table caller supplies
/// neither and the published cell must still be the right one:
///
/// * `draft: None` reads as *no draft-specific restriction applies*, so the
///   elide guard is evaluated as though the draft had a first-object subgroup
///   mode — the conservative side, since it yields `Conditional` rather than
///   `Yes`.
/// * `stream_kind: None` reads as a **subgroup** stream, which is what
///   [`Capabilities::supports`] publishes; [`Capabilities::supports_on`] is how
///   a caller asks about fetch.
pub fn classify(site: Site, kind: ActionKind, cx: &CapCtx) -> Support {
    if let Some(answer) = not_attemptable(site, kind) {
        return answer;
    }

    // A stream the framer cannot address never reaches the object site, so
    // nothing can be attempted and nothing can be refused. One fact lands
    // here: *any* stream on a draft this build did not compile. A fetch
    // stream on drafts 18, 19 and 20 used to land here too, and does not now —
    // see `fetch_group_order_is_needed`.
    let framing_bypass = match (site, cx.draft) {
        (Site::Object, Some(draft)) => object_framing_bypass(draft, cx.stream_kind),
        _ => None,
    };
    if let Some(reason) = framing_bypass {
        return Support::Unreachable {
            refusal: Refusal::StreamNotFramed { reason },
            instead: Instead::FramerBypass(reason),
        };
    }

    // The same build fact one decoder later. On a draft this build did not
    // compile, `AnyControlMessage::decode` has no arm, so
    // `ControlStreamParser::feed` steps over every frame and the hook is
    // never offered one — nothing is attempted here and nothing can be
    // refused. It is a separate check rather than a wider `framing_bypass`
    // because the two report different events, and a cell that pointed at
    // the wrong one would send a reader looking for a `FramerBypass` that
    // no control stream emits.
    //
    // `draft: None` falls through to the per-site rules, as everywhere
    // else in this function: it means the caller did not say, and a build
    // fact cannot be read off a draft nobody named.
    if site == Site::Control && cx.draft.is_some_and(|draft| !draft_is_compiled(draft)) {
        return Support::Unreachable {
            refusal: Refusal::ControlFrameNotDecodable,
            instead: Instead::ControlFrameNotDecodable,
        };
    }

    match site {
        Site::Control => classify_control(kind),
        Site::Object => classify_object(kind, cx),
        Site::Datagram => classify_datagram(kind, cx),
        Site::StreamOpen | Site::StreamHeader => classify_stream_decision(site, kind),
        Site::StreamEnd => classify_stream_end(kind, cx),
    }
}

/// What a draft can express, queryable before a run.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    draft: DraftVersion,
}

impl Capabilities {
    /// The capability table for a draft.
    #[must_use]
    pub fn for_draft(draft: DraftVersion) -> Self {
        Self { draft }
    }

    /// Whether `kind` is available at `site`, with no per-unit facts.
    ///
    /// At [`Site::Object`] this is the **subgroup**-stream column;
    /// [`Self::supports_on`] answers for a named stream kind.
    #[must_use]
    pub fn supports(&self, site: Site, kind: ActionKind) -> Support {
        classify(site, kind, &CapCtx { draft: Some(self.draft), ..CapCtx::default() })
    }

    /// Whether `kind` is available at `site` for a given stream kind.
    #[must_use]
    pub fn supports_on(
        &self,
        site: Site,
        kind: ActionKind,
        stream_kind: DataStreamType,
    ) -> Support {
        classify(
            site,
            kind,
            &CapCtx {
                draft: Some(self.draft),
                stream_kind: Some(stream_kind),
                ..CapCtx::default()
            },
        )
    }

    /// Whether a shaping rule keyed on `field` can ever claim a unit
    /// arriving as `kind`. [`supports_matcher`], bound to this draft.
    #[must_use]
    pub fn supports_matcher(&self, kind: MatchKind, field: MatcherKey) -> bool {
        supports_matcher(self.draft, kind, field)
    }

    /// Admit one class rule, or refuse it naming the draft and the key.
    ///
    /// The first key the rule names that [`supports_matcher`] answers
    /// `false` for is the refusal, in the order the keys are declared on
    /// [`Matcher`] — the same first-match convention
    /// [`ShapeProfile::try_new`] uses for
    /// [`ShapeError::InertMatcher`](crate::shape::ShapeError::InertMatcher),
    /// so a rule with two dead keys reports the one an author reading their
    /// own configuration top to bottom reaches first.
    ///
    /// # A rule that names no stream kind is judged against both
    ///
    /// [`Matcher::stream_kind`] is optional, and a rule that omits it claims
    /// units of **any** kind. Such a rule is refused only when its key is
    /// carried by none of them, because refusing it for being dead on fetch
    /// alone would reject a rule that shapes subgroup traffic perfectly well
    /// — and a false rejection here is worse than the silence this exists to
    /// end, since it rejects a configuration that works.
    pub fn admit_class(&self, class: &ClassRule) -> Result<(), UnsupportedMatcherKey> {
        let aimed = class.matcher.stream_kind;
        for key in keys_named(&class.matcher).into_iter().flatten() {
            let carried = match aimed {
                Some(kind) => supports_matcher(self.draft, kind, key),
                None => ANY_KIND.iter().any(|&kind| supports_matcher(self.draft, kind, key)),
            };
            if !carried {
                return Err(UnsupportedMatcherKey {
                    class: class.name.clone(),
                    draft: self.draft,
                    kind: aimed,
                    key,
                });
            }
        }
        Ok(())
    }

    /// Admit every class in a profile, or refuse at the first dead key.
    ///
    /// The pre-run check [`ShapeProfile::try_new`] cannot make: that
    /// constructor validates the configuration alone and has no draft, so a
    /// rule keyed on something the negotiated draft does not carry is valid
    /// to it. This is the same question asked once a draft is known.
    ///
    /// # A session asks it twice, and the second time is not redundant
    ///
    /// Once before it dials, against the draft it is about to frame with,
    /// which is the only moment a profile can be refused with nothing yet
    /// forwarded. And once more when the peers name a draft, which drafts 07
    /// to 14 do in their SETUP rather than in the ALPN they share — so for
    /// that cohort the first answer was given about a configured guess and
    /// the second is given about the session actually running. The two
    /// differ only where a draft this build did not compile is involved, and
    /// that is exactly the case where every rule in the profile is dead.
    pub fn admit_profile(&self, profile: &ShapeProfile) -> Result<(), UnsupportedMatcherKey> {
        profile.classes().iter().try_for_each(|class| self.admit_class(class))
    }
}

// ── What a shaping rule may key on ─────────────────────────────────────

/// Every kind a rule that names none of them may claim.
///
/// All three, and the list is read only for a matcher whose
/// [`Matcher::stream_kind`] is `None`: such a rule is refused for a key only
/// when **no** kind carries it. Leaving [`MatchKind::Datagram`] out of the list
/// would refuse a rule keyed on something only a datagram carries, and
/// including a kind that carried nothing would admit a rule that claims nothing
/// — which is why the list is the answer to *what could this rule claim* rather
/// than a restatement of the enum.
const ANY_KIND: [MatchKind; 3] = [MatchKind::Subgroup, MatchKind::Fetch, MatchKind::Datagram];

/// One value key a [`Matcher`] can be built on.
///
/// Six variants, spelled as the [`Matcher`] fields are, so a refusal names
/// something an author can search their own configuration for — the same
/// contract
/// [`ShapeError::InertMatcher`](crate::shape::ShapeError::InertMatcher)'s
/// `key` field carries, and deliberately the same spelling, so the two
/// rejections read alike.
///
/// Two [`Matcher`] fields are **not** here, and their absence is a decision
/// rather than an omission:
///
/// * [`Matcher::side`] is the forwarding task's own direction label, not a
///   field any unit carries, so no draft can fail to carry it. The one side
///   value that names nothing a hook site sees is already rejected by
///   [`ShapeProfile::try_new`].
/// * [`Matcher::stream_kind`] names *which* units a rule claims rather than a
///   field those units carry. It is [`supports_matcher`]'s second argument, not
///   one of its answers.
///
/// Distinct from
/// [`MatcherField`](crate::shape::MatcherField), which is the *run's*
/// vocabulary and covers a different set: that enum names the four keys a
/// live session can report absent on a unit it actually saw, this one names
/// the six keys a configuration can be built on before any session exists.
/// They overlap on three names and neither is a superset of the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MatcherKey {
    /// [`Matcher::track_alias`].
    TrackAlias,
    /// [`Matcher::group_id`].
    GroupId,
    /// [`Matcher::subgroup_id`].
    SubgroupId,
    /// [`Matcher::object_id`].
    ObjectId,
    /// [`Matcher::priority`], MoQT's `publisher_priority`.
    Priority,
    /// [`Matcher::every_nth`].
    EveryNth,
}

impl MatcherKey {
    /// Every key, in the order the fields are declared on [`Matcher`].
    ///
    /// Published so a caller can sweep the whole axis without transcribing
    /// it; [`Capabilities::admit_class`] reports in this order too.
    pub const ALL: [MatcherKey; 6] = [
        MatcherKey::TrackAlias,
        MatcherKey::GroupId,
        MatcherKey::SubgroupId,
        MatcherKey::ObjectId,
        MatcherKey::Priority,
        MatcherKey::EveryNth,
    ];

    /// The key's name as the [`Matcher`] field is spelled.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            MatcherKey::TrackAlias => "track_alias",
            MatcherKey::GroupId => "group_id",
            MatcherKey::SubgroupId => "subgroup_id",
            MatcherKey::ObjectId => "object_id",
            MatcherKey::Priority => "priority",
            MatcherKey::EveryNth => "every_nth",
        }
    }
}

/// Whether a rule keyed on `field` can **ever** claim a unit arriving as
/// `kind`, on `draft`, in this build.
///
/// A shaping rule keyed on something the negotiated draft does not carry
/// arms, matches nothing, and reports success — the silent no-op this crate
/// exists to make loud. Before this predicate the only way to learn it was
/// to run the session and read `Impairment{ShapeRuleUnmatchable}` out of the
/// report, which requires a run, traffic of the right shape, and a reader.
/// The answer needs nothing but the draft and the compiled feature set, so
/// it is answerable before the run, and [`Capabilities::admit_profile`] turns
/// it into a refusal.
///
/// # Why the second argument is a [`MatchKind`] and not a [`Site`]
///
/// Shaping only ever sees framed objects. [`Site`] spans the control frame,
/// the two stream decisions and the stream end, none of which a [`Matcher`]
/// can be aimed at, and it does *not* distinguish the two things that decide
/// this question — a subgroup stream from a fetch one. [`MatchKind`] is the
/// axis the answer actually varies on, and it is the axis a rule is written
/// against.
///
/// # The three facts, in the order they are read
///
/// 1. **A draft this build did not compile frames nothing at all.** The
///    stream header decode returns `UnsupportedDraft`, the framer latches
///    [`BypassReason::DecodeError`] and forwards the stream uninterpreted,
///    so no [`ObjectMeta`](crate::framer::ObjectMeta) is ever built and *no*
///    key can match — see [`draft_is_compiled`], which is reachable by
///    default rather than only under exotic flags. This is why the predicate
///    answers for a build and not only for a draft, exactly as
///    [`classify`] does.
/// 2. **A fetch stream carries no track alias, and a datagram carries no
///    subgroup ID, on any draft.** A fetch header carries a request ID
///    where a subgroup header carries an alias, and no datagram of any
///    draft belongs to a subgroup. These are the two answers that vary by
///    *kind* rather than by draft, and they are why the predicate takes
///    the kind at all.
///
/// # What it deliberately does not refuse, and why
///
/// [`Matcher::subgroup_id`] and [`Matcher::priority`] are the two keys whose
/// absence can be a property of one **header** rather than of the draft — a
/// header in *subgroup ID is the first object's ID* mode (eight drafts) or
/// drafts 17-20's reserved mode 3 carries no subgroup ID, and drafts 15-20 omit
/// the publisher priority whenever the header sets the default-priority bit, on
/// a subgroup header and on a datagram alike. Neither is a *draft* fact. Every
/// one of the fourteen drafts also has header shapes that carry both — modes 0
/// and 2 on 17-20, an explicit subgroup ID field elsewhere, and a clear
/// default-priority bit — and every fetch object on the drafts that frame one
/// carries both unconditionally. So a rule keyed on either can match on every
/// draft, and this predicate answers `true`.
///
/// There is deliberately no fact about a stream *kind* that yields no unit
/// at all. There used to be one — a [`MatchKind::Fetch`] class on drafts 18
/// and 19, refused before the run because no fetch stream there could be
/// framed — and it went when those streams became readable; see
/// `fetch_group_order_is_needed`. A fetch stream the session cannot resolve
/// is now one stream rather than a draft, and it reports itself as
/// `Impairment { FramerBypass { FetchGroupOrderUnknown } }` while it happens.
///
/// The one place `subgroup_id` crosses the line is a rule aimed at
/// [`MatchKind::Datagram`], which fact 2 above refuses: there the absence is
/// not a header's but the carrier's, and no draft has a datagram shape that
/// carries one. A rule that names **no** kind and keys on `subgroup_id` is
/// still admitted, because it is a working subgroup rule that datagram
/// traffic simply walks past.
///
/// Refusing them would reject rules that work, which is a worse failure than
/// the one being fixed: a run that shapes nothing can at least be observed,
/// while a configuration rejected at startup cannot run at all. A key the
/// wire withheld from **one unit** stays what it already was —
/// `Impairment{ShapeRuleUnmatchable}`, reported per class per field, once
/// per session — because that answer depends on the traffic and nothing
/// before the run can know it.
#[must_use]
pub fn supports_matcher(draft: DraftVersion, kind: MatchKind, field: MatcherKey) -> bool {
    // Read in the same wire order `object_framing_bypass` reads them: the
    // stream header decodes first, so an uncompiled draft fails before the
    // fetch-object question is ever reached.
    if !draft_is_compiled(draft) {
        return false;
    }
    // A fetch header carries a request ID where a subgroup header carries a
    // track alias, so `ObjectFramer` builds every fetch object with
    // `track_alias: None` and an absent key never matches.
    if kind == MatchKind::Fetch && field == MatcherKey::TrackAlias {
        return false;
    }
    // A datagram carries one Object and belongs to no subgroup, on every one
    // of the fourteen drafts. There is no header shape anywhere in the family
    // that puts a Subgroup ID on one, which is what makes this a refusal here
    // rather than a `MatcherField::SubgroupId` report from a run: the answer
    // does not depend on a header the session has not seen yet.
    !(kind == MatchKind::Datagram && field == MatcherKey::SubgroupId)
}

/// The keys a matcher names, in [`Matcher`] field order.
///
/// A fixed-size array of `Option` rather than a `Vec`, matching
/// `Matcher::unmatchable_fields`: the shape reads as the struct does, so a
/// key added to [`Matcher`] and forgotten here is visible as a missing row
/// rather than as a shorter list.
fn keys_named(matcher: &Matcher) -> [Option<MatcherKey>; 6] {
    [
        matcher.track_alias.as_ref().map(|_| MatcherKey::TrackAlias),
        matcher.group_id.as_ref().map(|_| MatcherKey::GroupId),
        matcher.subgroup_id.as_ref().map(|_| MatcherKey::SubgroupId),
        matcher.object_id.as_ref().map(|_| MatcherKey::ObjectId),
        matcher.priority.as_ref().map(|_| MatcherKey::Priority),
        matcher.every_nth.map(|_| MatcherKey::EveryNth),
    ]
}

/// A class rule keyed on something no unit it could claim ever carries.
///
/// Returned by [`Capabilities::admit_class`] and
/// [`Capabilities::admit_profile`] **before** a session forwards anything,
/// so the rule never arms. The message names the draft and the key, because
/// either alone is unactionable: "keys on `track_alias`" does not say which
/// session it is dead in, and "draft-19" does not say what to change.
///
/// `#[non_exhaustive]` with public fields: nobody constructs an error, and a
/// later release naming a seventh key must not be a breaking change.
/// Reading the fields from outside the crate stays legal, which is what lets
/// a caller branch on the key rather than parse the message.
///
/// [`Display`](std::fmt::Display) is hand-written rather than a `thiserror`
/// attribute, unlike
/// [`ShapeError`](crate::shape::ShapeError): the message has two shapes,
/// because a rule that named no [`MatchKind`] was judged against both framed
/// kinds and naming one of them in the refusal would misreport what the rule
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedMatcherKey {
    /// The [`ClassRule::name`] holding the dead key.
    pub class: String,
    /// The draft the session would run as.
    pub draft: DraftVersion,
    /// The stream kind the rule was aimed at, or `None` when it named none
    /// and the key is carried by neither framed kind on this draft.
    pub kind: Option<MatchKind>,
    /// The key that can never match.
    pub key: MatcherKey,
}

impl std::fmt::Display for UnsupportedMatcherKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (class, key, draft) = (&self.class, self.key.field_name(), self.draft);
        match self.kind {
            Some(kind) => {
                write!(f, "class {class} keys on {key}, which no {kind:?} unit carries on {draft}")
            }
            None => {
                write!(f, "class {class} keys on {key}, which no framed unit carries on {draft}")
            }
        }
    }
}

impl std::error::Error for UnsupportedMatcherKey {}

// ── The three site-independent `NotAttemptable` families ───────────────

/// Whether this site's hook method returns
/// [`StreamAction`](crate::action::StreamAction) rather than
/// [`Action`](crate::action::Action).
const fn site_returns_stream_action(site: Site) -> bool {
    matches!(site, Site::StreamOpen | Site::StreamHeader)
}

/// Whether this kind is one of the four
/// [`StreamAction`](crate::action::StreamAction) decisions.
///
/// **The compiler does not check this list.** It is a `matches!`, not an
/// exhaustive `match`, so a `StreamAction` variant left out of it silently
/// becomes `NotAttemptable { SiteReturnsStreamAction }` at
/// [`Site::StreamOpen`] and [`Site::StreamHeader`] — the published table
/// then says a site's return type rules out a variant of that very return
/// type. `tests/action_matrix.rs::the_published_table_and_classify_agree`
/// is the gate that catches it, because its hand-transcribed twin of this
/// list is written independently.
const fn is_stream_decision(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::Open | ActionKind::Reject | ActionKind::OpenAfter | ActionKind::SerializeAfter
    )
}

/// Families 1-3 of [`Support::NotAttemptable`], in the order [`classify`]
/// documents: no constructor, then `ReplaceObject`'s single reading, then
/// the return-type mismatch.
fn not_attemptable(site: Site, kind: ActionKind) -> Option<Support> {
    if kind == ActionKind::ReplaceObject && site != Site::Object {
        return Some(Support::NotAttemptable {
            why: NotAttemptable::KindNotDefinedAtThisSite,
            refusal: Refusal::WrongSite { site, action: kind },
        });
    }

    let why = match (site_returns_stream_action(site), is_stream_decision(kind)) {
        (true, false) => NotAttemptable::SiteReturnsStreamAction,
        (false, true) => NotAttemptable::SiteReturnsAction,
        _ => return None,
    };
    Some(Support::NotAttemptable { why, refusal: Refusal::WrongSite { site, action: kind } })
}

/// The answer [`not_attemptable`] already gave, restated.
///
/// Every kind that reaches a site helper's "filtered earlier" arm was
/// answered before dispatch. Recomputing it keeps each helper a total
/// function instead of a panicking one — a capability table that can panic
/// is worse than one that repeats itself.
fn filtered_earlier(site: Site, kind: ActionKind) -> Support {
    not_attemptable(site, kind).unwrap_or(Support::NotAttemptable {
        why: NotAttemptable::KindNotDefinedAtThisSite,
        refusal: Refusal::WrongSite { site, action: kind },
    })
}

// ── Per-draft facts ────────────────────────────────────────────────────

/// Why [`ObjectFramer`](crate::framer::ObjectFramer) cannot address objects
/// on a stream of this shape, if it cannot.
///
/// One reason survives here, and it is the one the **wire** reaches first: a
/// draft this build did not compile fails at the stream header and reports
/// [`BypassReason::DecodeError`], so nothing after it is ever asked.
///
/// A fetch stream on drafts 18, 19 and 20 used to answer a second reason. It no
/// longer does, because whether such a stream can be addressed is no longer a
/// property of the draft: the session reads the Group Order off the FETCH and
/// the framer takes it from there — see [`fetch_group_order_is_needed`]. What
/// is left of that case belongs to one stream rather than to the table, and
/// is reported per stream as before.
///
/// `stream_kind: None` reads as a subgroup stream, matching
/// [`Capabilities::supports`]'s published column.
const fn object_framing_bypass(
    draft: DraftVersion,
    stream_kind: Option<DataStreamType>,
) -> Option<BypassReason> {
    let _ = stream_kind;
    if !draft_is_compiled(draft) {
        return Some(BypassReason::DecodeError);
    }
    None
}

/// Whether **this build** compiled a codec for `draft`.
///
/// [`DraftVersion`] carries all fourteen variants under every feature set,
/// so the table is *answerable* for a draft this binary cannot speak — and
/// that is exactly the case worth getting right. A build that did not
/// compile a draft cannot frame one byte of it, so a table that answers by
/// draft **number** alone publishes [`Support::Yes`] for work the binary
/// cannot do: the documented lie this module exists to prevent.
///
/// It is reachable **by default**, not only under exotic flags:
/// `ProxySessionConfig::default().draft` is [`DraftVersion::Draft14`], so a
/// `--no-default-features --features draft07` binary — a shipped
/// configuration and one of CI's fourteen rows — is configured for draft 14
/// unless its caller says otherwise.
///
/// # This is also the predicate a session is admitted on
///
/// [`ProxySession::run`](crate::session::ProxySession::run) asks this before
/// it dials and refuses with
/// [`ProxyError::DraftNotCompiled`](crate::error::ProxyError::DraftNotCompiled)
/// when the answer is `false`, so the run that the paragraph below describes
/// no longer happens to anybody. One predicate serves both, which is what
/// keeps the table's verdict and the session's admission from becoming two
/// lists that disagree — and the paragraph below stays because it is still
/// the reason the verdict is [`Support::Unreachable`] rather than
/// [`Support::Yes`].
///
/// # The mechanism, so the verdict is not taken on trust
///
/// `moqtap-proxy`'s `draftNN` features forward to **both** `moqtap-codec` and
/// `moqtap-client`, so a draft that is off here is off in the codec.
/// `AnySubgroupHeader::decode_stream` and `AnyFetchHeader::decode_stream` then
/// fall through to their catch-all arm and return
/// `CodecError::UnsupportedDraft(*draft DraftNN not enabled via feature
/// flag*)`. That is not an incomplete-input error
/// (`parser::data::is_incomplete_error` admits only `UnexpectedEnd`), so
/// [`ObjectFramer`](crate::framer::ObjectFramer)'s header poll takes its
/// terminal `Err` arm, latches [`BypassReason::DecodeError`] and forwards the
/// stream uninterpreted. No object on it ever reaches
/// [`ProxyHook::on_object`](crate::hook::ProxyHook::on_object), which is
/// precisely [`Support::Unreachable`].
///
/// # Why `cfg!` and not `#[cfg]`
///
/// A `cfg!` per arm keeps the function **total**. A `#[cfg]` per arm would
/// make the match non-exhaustive and force a catch-all, and the table would
/// stop being able to answer for the very drafts this exists to answer for.
///
/// # The control site reads it too, one decoder later
///
/// [`Site::Control`] on an uncompiled draft is never invoked either:
/// `ControlStreamParser::feed` steps over a frame whose
/// `AnyControlMessage::decode` fails, so the hook is offered nothing. That
/// cell published [`Support::Yes`] for a while, because the honest verdict
/// needs `instead` to name a report and this path emitted none. It emits
/// [`ImpairmentKind::ControlFrameNotDecodable`](crate::event::ImpairmentKind::ControlFrameNotDecodable)
/// now, so the cell is [`Support::Unreachable`] with
/// [`Instead::ControlFrameNotDecodable`] — see [`classify`], step 5.
///
/// # What it does *not* cover
///
/// [`Site::StreamOpen`], [`Site::StreamEnd`] and [`Site::Datagram`] need no
/// codec to fire and are unaffected; [`Site::StreamHeader`] fires only
/// behind a decoded header and shares the object site's fate.
#[must_use]
pub const fn draft_is_compiled(draft: DraftVersion) -> bool {
    match draft {
        DraftVersion::Draft07 => cfg!(feature = "draft07"),
        DraftVersion::Draft08 => cfg!(feature = "draft08"),
        DraftVersion::Draft09 => cfg!(feature = "draft09"),
        DraftVersion::Draft10 => cfg!(feature = "draft10"),
        DraftVersion::Draft11 => cfg!(feature = "draft11"),
        DraftVersion::Draft12 => cfg!(feature = "draft12"),
        DraftVersion::Draft13 => cfg!(feature = "draft13"),
        DraftVersion::Draft14 => cfg!(feature = "draft14"),
        DraftVersion::Draft15 => cfg!(feature = "draft15"),
        DraftVersion::Draft16 => cfg!(feature = "draft16"),
        DraftVersion::Draft17 => cfg!(feature = "draft17"),
        DraftVersion::Draft18 => cfg!(feature = "draft18"),
        DraftVersion::Draft19 => cfg!(feature = "draft19"),
        DraftVersion::Draft20 => cfg!(feature = "draft20"),
    }
}

/// Every draft this build could take as a default, in the order it would take
/// them.
///
/// Draft-14 first, because that is the value this had before the build's own
/// draft list was consulted and a full build should not change; then the newest
/// draft downwards, because a build that trimmed its drafts kept the ones it
/// means to speak and the newest of those is the likeliest thing meant by
/// naming none.
const DEFAULT_DRAFT_ORDER: [DraftVersion; 14] = [
    DraftVersion::Draft14,
    DraftVersion::Draft20,
    DraftVersion::Draft19,
    DraftVersion::Draft18,
    DraftVersion::Draft17,
    DraftVersion::Draft16,
    DraftVersion::Draft15,
    DraftVersion::Draft13,
    DraftVersion::Draft12,
    DraftVersion::Draft11,
    DraftVersion::Draft10,
    DraftVersion::Draft09,
    DraftVersion::Draft08,
    DraftVersion::Draft07,
];

/// The draft a session configuration takes when the caller names none.
///
/// Draft-14 wherever the build has it, which is every build that did not trim
/// its drafts, and the newest draft the build does have otherwise. The value is
/// what it always was on a full build; what changes is that a reduced-draft
/// build no longer starts out naming a draft it cannot speak.
///
/// # Why a default cannot simply refuse
///
/// [`Default`] returns a value, so it has no way to tell a caller that the
/// build left out the draft it would have chosen. Keeping draft-14 regardless
/// does not avoid the problem, it moves it: on a build without draft-14
/// [`draft_is_compiled`] answers `false`, [`supports_matcher`] refuses every
/// key on every stream kind, and a class rule that is perfectly well formed is
/// reported as naming a key the draft does not carry. That is a configuration
/// error raised against the author of a configuration that has nothing wrong
/// with it.
///
/// # The check below is a compile-time one, and it has to be
///
/// A test asserting the same thing would never run. The per-draft rows build
/// this crate fourteen times under `--no-default-features --features draftNN`
/// and stop at `clippy --all-targets`, so a reduced-draft build is *compiled*
/// fourteen times a round and its tests are run none — and a reduced-draft
/// build is the only kind that can have this defect. A const assertion fails
/// the compile, which is the one thing those rows do look at.
///
/// # Ablated, and the numbers are the account of why this survived
///
/// Putting the old value back — draft-14 chosen without consulting the build:
///
/// ```text
/// error[E0080]: evaluation panicked: the default draft is one this build did not compile
/// error: could not compile `moqtap-proxy` (lib) due to 1 previous error
/// ```
///
/// **Exit 101 under `--no-default-features --features draft07`, exit 101 under
/// the same with draft19, and exit 0 under `--all-features`.** The build every
/// round runs first cannot see this defect at all, and the fourteen that can
/// are compiled and never run.
pub const DEFAULT_DRAFT: DraftVersion = default_draft();

const fn default_draft() -> DraftVersion {
    let mut i = 0;
    while i < DEFAULT_DRAFT_ORDER.len() {
        if draft_is_compiled(DEFAULT_DRAFT_ORDER[i]) {
            return DEFAULT_DRAFT_ORDER[i];
        }
        i += 1;
    }
    panic!("this build compiled no draft at all, so there is no default to take")
}

const _: () = assert!(
    draft_is_compiled(DEFAULT_DRAFT),
    "the default draft is one this build did not compile"
);

/// Whether a fetch stream on this draft can be read only by an endpoint that
/// knows the Group Order the fetch was asked for.
///
/// A statement about the draft, not about the build and not about any one
/// session; whether the draft was compiled at all is [`draft_is_compiled`],
/// asked first by [`object_framing_bypass`] because the header decode happens
/// first.
///
/// **False on drafts 07-17.** Drafts 07-14 write each object's identity
/// outright, and drafts 15, 16 and 17 let an object leave a field off and
/// take the object before it — draft-16 Section 10.4.4.1: "Group ID is the
/// prior Object's Group ID" — which the reader carries the running state
/// for. Either way an absolute Location comes out of the stream and nothing
/// else, which is all addressing an object needs.
///
/// **True on drafts 18, 19 and 20**, where the Group ID is a difference and the
/// fetch's Group Order decides its sign. Nothing on the data stream states
/// the order, and the wrong choice decodes as willingly as the right one, so
/// a reader has to be told — see [`BypassReason::FetchGroupOrderUnknown`],
/// where the consequence of the wrong answer is written out.
///
/// # Where the answer comes from
///
/// One control message settles it. Draft-19 Section 10.12.3: "The publisher
/// responding to a FETCH is responsible for delivering all available Objects
/// in the requested range in the requested order (see Section 10.2.8)", and
/// draft-19 Section 10.2.8 states what a FETCH that carries no GROUP_ORDER
/// parameter has asked for: "If omitted from FETCH, the receiver uses
/// Ascending (0x1)." So a session that reads the FETCH knows the order for
/// that Request ID,
/// carrying it in a
/// [`FetchGroupOrders`](crate::framer::FetchGroupOrders) table the framer
/// takes it out of when the response stream opens.
///
/// That is why this is a draft fact and the bypass is not. The bypass now
/// belongs to one stream: a fetch stream naming a request this session never
/// saw asked for, which is a publisher answering something nobody requested.
///
/// The match is exhaustive on purpose. As a `matches!` this answered `false`
/// for a draft nobody had listed, which is the answer that reads a fetch
/// stream without knowing the order — the one reading this function exists to
/// prevent. A fifteenth draft must fail to compile here until someone has read
/// its FETCH section and said which side it is on.
pub(crate) const fn fetch_group_order_is_needed(draft: DraftVersion) -> bool {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10
        | DraftVersion::Draft11
        | DraftVersion::Draft12
        | DraftVersion::Draft13
        | DraftVersion::Draft14
        | DraftVersion::Draft15
        | DraftVersion::Draft16
        | DraftVersion::Draft17 => false,
        DraftVersion::Draft18 | DraftVersion::Draft19 | DraftVersion::Draft20 => true,
    }
}

/// Whether this draft defines a *subgroup ID is the first object's ID* stream
/// type.
///
/// Nine drafts do: every one from 11 on. Drafts 07-10 always carry the
/// subgroup ID explicitly, so eliding index 0 there redefines nothing.
///
/// The two wordings are worth telling apart, because reading only the later
/// one makes the earlier drafts look as though they lack the mode. Drafts 11
/// through 15 state it as a property of the type value — draft-15 Section
/// 10.4.2: "the Subgroup ID is either 0 (for Types 0x10-11 and 0x18-19) or the
/// Object ID of the first object transmitted in this subgroup (for Types
/// 0x12-13 and 0x1A-1B)" — while drafts 16 through 20 name a SUBGROUP_ID_MODE
/// field and give mode 1 the sentence "The Subgroup ID field is absent and the
/// Subgroup ID is the Object ID of the first Object transmitted in this
/// Subgroup". Different prose, one stream: `0x12` on both sides of the change.
///
/// Draft-15's absence here was not a narrower guard but a silent one. Skipping
/// the block admitted the elide instead of refusing it, so a hook removing
/// index 0 of a draft-15 first-object stream handed the receiver a stream
/// whose subgroup ID had become the second object's. The draft list the tests
/// sweep carried the same omission, so no run ever asked.
///
/// **Nothing that checks this list may read it.** Two places state the same
/// partition independently and are what a narrowing here contradicts: the
/// `a_first_object_carrier_exists` in this module's tests, which names every
/// draft in an exhaustive match, and the copy in `tests/action_matrix.rs`,
/// transcribed from the drafts and driving end-to-end probes. Both cuts have
/// been run — dropping draft-15, and narrowing to 17-19 — and each is caught
/// by both. A test that took the fact from *here* instead passed under both.
///
/// The restatement discipline above and the exhaustive match below answer two
/// different failures and neither substitutes for the other: restatement
/// catches this list saying the *wrong* thing about a draft it names, and
/// exhaustiveness catches it saying *nothing* about a draft that has just been
/// added. As a `matches!` a fifteenth draft would silently take the drafts
/// 07-10 answer.
const fn has_implicit_subgroup_id_mode(draft: DraftVersion) -> bool {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => false,
        DraftVersion::Draft11
        | DraftVersion::Draft12
        | DraftVersion::Draft13
        | DraftVersion::Draft14
        | DraftVersion::Draft15
        | DraftVersion::Draft16
        | DraftVersion::Draft17
        | DraftVersion::Draft18
        | DraftVersion::Draft19
        | DraftVersion::Draft20 => true,
    }
}

/// Whether a header's reserved subgroup-ID mode has to be told apart from
/// mode 1 before an object behind it can be judged. Drafts 15-20.
///
/// **Not the drafts that name a SUBGROUP_ID_MODE field**, which is neither a
/// superset nor a subset of this. Drafts 16 through 20 name one — draft-16:
/// "Type values with SUBGROUP_ID_MODE set to 0b11: 0x16, 0x17, 0x1E, 0x1F,
/// 0x36, 0x37, 0x3E, 0x3F. This mode is reserved for future use." Draft-15
/// names nothing and states the same three carriers as table columns, then
/// leaves the fourth combination out of the table. The wording is what
/// differs; the two bits and their four values are not.
///
/// What decides it is where `AnySubgroupHeader::subgroup_id` answers `None`
/// for more than one reason. On these five it answers `None` for both mode 1
/// and the fourth combination, so `None` alone cannot say whether the first
/// object defines the subgroup or the header is one no receiver should read,
/// and the mode has to be consulted. Drafts 11 through 14 give each carrier a
/// stream type of its own and assign every type they define, so their `None`
/// means the first object and nothing else; drafts 07-10 always put the ID on
/// the wire and never answer `None` at all.
///
/// Both were outside this set while the codec still resolved their fourth
/// combination to a subgroup ID — draft-15 to zero by falling through, draft-16
/// to whatever varint it went on to read — and being outside it was right then,
/// because a `None` from those two really did mean mode 1 and nothing else. The
/// codec now answers `None` for both readings, as it always did on 17-20, so
/// the sentence above is what picks the drafts rather than a list of the ones
/// that name a field.
///
/// Exhaustive rather than a `matches!`, because the question this asks is not
/// one a new draft can be assumed out of: the sentence above is about what
/// `AnySubgroupHeader::subgroup_id` answers `None` for on that draft, and only
/// reading the draft settles it.
const fn subgroup_id_mode_must_be_consulted(draft: DraftVersion) -> bool {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10
        | DraftVersion::Draft11
        | DraftVersion::Draft12
        | DraftVersion::Draft13
        | DraftVersion::Draft14 => false,
        DraftVersion::Draft15
        | DraftVersion::Draft16
        | DraftVersion::Draft17
        | DraftVersion::Draft18
        | DraftVersion::Draft19
        | DraftVersion::Draft20 => true,
    }
}

// ── Per-site rules ─────────────────────────────────────────────────────

/// The control site, which is honoured on every draft.
///
/// The site is shown every message the session's control plane carries,
/// whichever shape that plane has. On drafts 07-16 the plane is the one
/// client-initiated bidirectional stream. On 17-20 it is a pair of
/// unidirectional streams — each peer opens one and begins it with SETUP —
/// and bidirectional streams carry requests; `session.rs` identifies the
/// pair by its stream type and pipes both it and the request streams through
/// the control path, so SETUP reaches the hook there too.
///
/// Draft-16 is both at once and is the only draft that is: a bidirectional
/// control stream, and SUBSCRIBE_NAMESPACE on a bidirectional stream of its
/// own beside it. Its request streams take the same control path, so this
/// column reads the same for it as for every other draft.
///
/// This column carried a `Conditional` for 17-19 while the engine believed
/// the control plane was the first bidirectional stream on every draft.
/// `tests/control_plane_uni.rs` is the end-to-end reading that replaced it,
/// and `tests/draft16_request_streams.rs` is the one for the draft that
/// needs both answers.
fn classify_control(kind: ActionKind) -> Support {
    let honoured = Support::Yes;

    match kind {
        ActionKind::Pass
        | ActionKind::Replace
        | ActionKind::Delay
        | ActionKind::Hold
        | ActionKind::DropElide
        | ActionKind::CloseSession => honoured,
        // A control frame has no payload slot the proxy can locate.
        ActionKind::ReplacePayload => {
            Support::No(Refusal::WrongSite { site: Site::Control, action: kind })
        }
        // On every draft: a request stream is still a control-plane
        // stream, so 17-20 are refused for the same reason as 07-16.
        ActionKind::Truncate | ActionKind::ResetStream => {
            Support::No(Refusal::ControlStreamResetIllegal)
        }
        ActionKind::Open
        | ActionKind::Reject
        | ActionKind::ReplaceObject
        | ActionKind::OpenAfter
        | ActionKind::SerializeAfter => filtered_earlier(Site::Control, kind),
    }
}

/// The object site, on a stream the framer can address: subgroup streams
/// on every compiled draft, and fetch streams on the drafts whose objects
/// this codec can read.
fn classify_object(kind: ActionKind, cx: &CapCtx) -> Support {
    match kind {
        ActionKind::Pass
        | ActionKind::Delay
        | ActionKind::Hold
        | ActionKind::Truncate
        | ActionKind::ResetStream
        | ActionKind::CloseSession => Support::Yes,
        // One classification for both rows: `Action::Replace(b)` is the
        // attempt for each, so the cells are the same value, and the
        // refusal names the capability being refused.
        ActionKind::Replace | ActionKind::ReplaceObject => Support::No(Refusal::WrongSite {
            site: Site::Object,
            action: ActionKind::ReplaceObject,
        }),
        ActionKind::ReplacePayload => object_replace_payload(cx),
        ActionKind::DropElide => object_drop_elide(cx),
        ActionKind::Open
        | ActionKind::Reject
        | ActionKind::OpenAfter
        | ActionKind::SerializeAfter => filtered_earlier(Site::Object, kind),
    }
}

/// The object site's `ReplacePayload` rule: the replacement must be the
/// declared payload length, and the object must not carry a status.
///
/// The status guard is evaluated first: an object with a status has no
/// payload slot to splice into, so its length is not the interesting fact.
fn object_replace_payload(cx: &CapCtx) -> Support {
    if cx.is_status_object == Some(true) {
        return Support::No(Refusal::WouldDestroyStatusObject);
    }
    match (cx.payload_len, cx.replacement_len) {
        (Some(from), Some(to)) if from != to => Support::No(Refusal::LengthChanged { from, to }),
        (Some(_), Some(_)) if cx.is_status_object == Some(false) => Support::Yes,
        (Some(_), Some(_)) => Support::Conditional(Precondition::NotAStatusObject),
        _ => Support::Conditional(Precondition::ReplacementLengthEqualsPayload),
    }
}

/// The object site's `DropElide` rule, in guard order: facts about the
/// stream before facts about the object.
///
/// On a subgroup stream, the header's subgroup-ID mode first (a reserved
/// mode says something different about the wire than a first-object mode
/// does), then whether eliding this object would redefine the subgroup ID.
/// The status guard is last and applies on every draft and every stream
/// kind.
///
/// **A fetch stream reaches only the status guard**, on every draft. Nothing
/// about a fetch object's own bytes can stop a removal: the framer pays for one
/// by re-encoding the survivor's framing against the frame that is now in front
/// of it. The subgroup guards below are skipped rather than answered, because a
/// fetch object states its own Subgroup ID or states that it has none, so
/// *eliding this would redefine the subgroup ID* is not a sentence about it.
fn object_drop_elide(cx: &CapCtx) -> Support {
    let subgroup_stream = cx.stream_kind != Some(DataStreamType::Fetch);

    let implicit_mode = cx.draft.is_none_or(has_implicit_subgroup_id_mode);

    if subgroup_stream && implicit_mode {
        match cx.index_in_stream {
            // Not the first object: the subgroup ID is already pinned by
            // an object that is still on the wire, so eliding this one
            // redefines nothing.
            Some(index) if index != 0 => {}
            Some(_) => {
                if cx.draft.is_none_or(subgroup_id_mode_must_be_consulted)
                    && cx.subgroup_id_mode == Some(RESERVED_SUBGROUP_ID_MODE)
                {
                    return Support::No(Refusal::ReservedHeaderMode {
                        mode: RESERVED_SUBGROUP_ID_MODE,
                    });
                }
                match cx.subgroup_id_resolved {
                    Some(false) => return Support::No(Refusal::WouldRedefineSubgroupId),
                    None => {
                        return Support::Conditional(Precondition::NotFirstObjectOfImplicitSubgroup)
                    }
                    Some(true) => {}
                }
            }
            None => {
                return Support::Conditional(Precondition::NotFirstObjectOfImplicitSubgroup);
            }
        }
    }

    match cx.is_status_object {
        Some(true) => Support::No(Refusal::WouldDestroyStatusObject),
        Some(false) => Support::Yes,
        None => Support::Conditional(Precondition::NotAStatusObject),
    }
}

/// The datagram site.
///
/// # A datagram is policed and never paced, and that is a decision
///
/// `Truncate` and `ResetStream` name a stream and a datagram has none, so
/// those two are a type error wearing a refusal. `Delay` and `Hold` are
/// refused for a different reason, and an author who reaches that refusal is
/// owed the reason rather than the mechanism.
///
/// **A rate aimed at datagrams drops what it cannot cover, at the instant the
/// datagram arrived.** `forward_datagrams` asks the class's bucket and
/// discards every answer but *now* — including `Later`, where an instant does
/// exist and the datagram could have been held until it. So a datagram-mode
/// track can be held to a rate; what it cannot be is smoothed.
///
/// Smoothing would need a per-connection queue, and the argument against one
/// is not that it is hard:
///
/// - **It would model nothing.** A bottleneck queues by link, not by track: a
///   router does not know which track a datagram belongs to. Class-aware
///   *policing* is a real box — an operator rate-limiter drops over rate —
///   and class-aware *smoothing* is a scheduler inside a router, which is not
///   a condition a player is ever placed in.
/// - **It would impose an order the protocol does not have.** A datagram
///   belongs to no stream and has no successor to renumber. A FIFO would make
///   this proxy the one hop on the path that never reorders, which is a less
///   faithful network, not a more controlled one.
/// - **The capability already exists one layer down.** `quinn-netem` delays,
///   jitters and reorders at the socket, under the whole connection — which
///   is exactly the scope a link-level queue has. It is not class-aware, and
///   that is the correct scope for it rather than a gap in it.
///
/// So the answer for *smooth this traffic* is `quinn-netem`, and the answer
/// for *hold this track to a rate* is a class over a bucket, which is here.
/// The framed sites keep `Delay` and `Hold` because a stream **has** a
/// delivery order: holding object N and then N+1 preserves a guarantee the
/// protocol makes, where holding two datagrams would manufacture one.
///
/// `tests/actions_shaping.rs` pins both halves — that a dry bucket discards,
/// and that a *live* rate discards too rather than deferring to the instant
/// it names, which is the assertion a queue would break.
fn classify_datagram(kind: ActionKind, cx: &CapCtx) -> Support {
    match kind {
        ActionKind::Pass | ActionKind::DropElide | ActionKind::CloseSession => Support::Yes,
        // Always conditional: no transport in the workspace exposes a
        // maximum datagram size, so the verdict comes from
        // `send_datagram` failing, as `ActionFailed`.
        ActionKind::Replace => Support::Conditional(Precondition::WithinMaxDatagramSize),
        ActionKind::ReplacePayload => datagram_replace_payload(cx),
        // Two refusals with two reasons, both above: a stream action naming a
        // carrier that has no stream, and a deliberate absence of pacing.
        ActionKind::Delay | ActionKind::Hold | ActionKind::Truncate | ActionKind::ResetStream => {
            Support::No(Refusal::WrongSite { site: Site::Datagram, action: kind })
        }
        ActionKind::Open
        | ActionKind::Reject
        | ActionKind::ReplaceObject
        | ActionKind::OpenAfter
        | ActionKind::SerializeAfter => filtered_earlier(Site::Datagram, kind),
    }
}

/// The datagram site's `ReplacePayload` rule: the payload's start offset
/// must be derivable, or there is nowhere to splice the replacement in.
fn datagram_replace_payload(cx: &CapCtx) -> Support {
    match cx.payload_delimited {
        Some(true) => Support::Yes,
        Some(false) => {
            Support::No(Refusal::PayloadNotDelimited { detail: payload_not_delimited_detail(cx) })
        }
        None => Support::Conditional(Precondition::DatagramPayloadDelimited),
    }
}

/// Which of [`Precondition::DatagramPayloadDelimited`]'s three cases failed.
fn payload_not_delimited_detail(cx: &CapCtx) -> &'static str {
    if cx.draft == Some(DraftVersion::Draft14) {
        "draft-14 header decode consumes the payload"
    } else if cx.is_status_object == Some(true) {
        "status datagram has no payload"
    } else {
        "datagram header did not decode"
    }
}

/// The two stream-decision sites.
///
/// [`ActionKind::SerializeAfter`] takes exactly the verdict
/// [`ActionKind::Open`] takes at both sites: it defers the first *write*,
/// which either site can still decide. [`ActionKind::OpenAfter`] takes the
/// same at [`Site::StreamOpen`] and is refused at [`Site::StreamHeader`],
/// because the peer stream is opened before a byte of the source is read —
/// by the header site there is nothing left to defer, and moving `open_uni`
/// behind the header decision would erase the published difference between
/// the two reject sites.
///
/// The refusal is what keeps the header cell honest, and it is observable:
/// the engine reports `ProxyEvent::ActionRefused` naming
/// [`Refusal::WrongSite`], and the stream is forwarded unchanged. Admitting
/// it there instead would publish a delay nothing performs —
/// `tests/open_after_ordering.rs` runs exactly that mutation and records
/// what a caller would get.
fn classify_stream_decision(site: Site, kind: ActionKind) -> Support {
    match kind {
        ActionKind::Open | ActionKind::Reject | ActionKind::SerializeAfter => Support::Yes,
        ActionKind::OpenAfter => match site {
            Site::StreamOpen => Support::Yes,
            _ => Support::No(Refusal::WrongSite { site, action: kind }),
        },
        ActionKind::Pass
        | ActionKind::Replace
        | ActionKind::ReplacePayload
        | ActionKind::Delay
        | ActionKind::Hold
        | ActionKind::DropElide
        | ActionKind::Truncate
        | ActionKind::ResetStream
        | ActionKind::CloseSession
        | ActionKind::ReplaceObject => filtered_earlier(site, kind),
    }
}

/// The stream-end site's two columns: data streams and control streams.
///
/// `CloseSession` is honoured on both: a session close is session-scoped,
/// so no site can be the wrong one for it. `ResetStream` turns a clean FIN
/// into a reset on a **data** stream and is refused on a control stream,
/// where it would be a session-level protocol violation — as is
/// `Truncate`, which is the same violation with a prefix attached.
fn classify_stream_end(kind: ActionKind, cx: &CapCtx) -> Support {
    let control = cx.is_control_stream == Some(true);
    match kind {
        ActionKind::Pass | ActionKind::CloseSession => Support::Yes,
        ActionKind::ResetStream => {
            if control {
                Support::No(Refusal::ControlStreamResetIllegal)
            } else {
                Support::Yes
            }
        }
        ActionKind::Truncate => {
            if control {
                Support::No(Refusal::ControlStreamResetIllegal)
            } else {
                Support::No(Refusal::WrongSite { site: Site::StreamEnd, action: kind })
            }
        }
        // Delaying a stream's end is expressed by delaying its last object;
        // there is no unit here to replace or drop.
        ActionKind::Replace
        | ActionKind::ReplacePayload
        | ActionKind::Delay
        | ActionKind::Hold
        | ActionKind::DropElide => {
            Support::No(Refusal::WrongSite { site: Site::StreamEnd, action: kind })
        }
        ActionKind::Open
        | ActionKind::Reject
        | ActionKind::ReplaceObject
        | ActionKind::OpenAfter
        | ActionKind::SerializeAfter => filtered_earlier(Site::StreamEnd, kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every draft, in publication order. Not feature-gated:
    /// [`DraftVersion`] carries all fourteen variants under every draft
    /// feature set, so the table is answerable for a draft this build
    /// cannot speak.
    const DRAFTS: [DraftVersion; 14] = [
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

    /// All sixteen kinds — the axis every table test below sweeps.
    const KINDS: [ActionKind; 14] = [
        ActionKind::Pass,
        ActionKind::Replace,
        ActionKind::ReplacePayload,
        ActionKind::Delay,
        ActionKind::Hold,
        ActionKind::DropElide,
        ActionKind::Truncate,
        ActionKind::ResetStream,
        ActionKind::CloseSession,
        ActionKind::Open,
        ActionKind::Reject,
        ActionKind::ReplaceObject,
        ActionKind::OpenAfter,
        ActionKind::SerializeAfter,
    ];

    const SITES: [Site; 6] = [
        Site::Control,
        Site::Object,
        Site::Datagram,
        Site::StreamOpen,
        Site::StreamHeader,
        Site::StreamEnd,
    ];

    fn wrong_site(site: Site, action: ActionKind) -> Support {
        Support::No(Refusal::WrongSite { site, action })
    }

    fn returns_action(site: Site, action: ActionKind) -> Support {
        Support::NotAttemptable {
            why: NotAttemptable::SiteReturnsAction,
            refusal: Refusal::WrongSite { site, action },
        }
    }

    fn returns_stream_action(site: Site, action: ActionKind) -> Support {
        Support::NotAttemptable {
            why: NotAttemptable::SiteReturnsStreamAction,
            refusal: Refusal::WrongSite { site, action },
        }
    }

    fn kind_not_here(site: Site, action: ActionKind) -> Support {
        Support::NotAttemptable {
            why: NotAttemptable::KindNotDefinedAtThisSite,
            refusal: Refusal::WrongSite { site, action },
        }
    }

    fn unreachable_with(reason: BypassReason) -> Support {
        Support::Unreachable {
            refusal: Refusal::StreamNotFramed { reason },
            instead: Instead::FramerBypass(reason),
        }
    }

    /// The control site's verdict on a draft this build did not compile.
    fn unreachable_control() -> Support {
        Support::Unreachable {
            refusal: Refusal::ControlFrameNotDecodable,
            instead: Instead::ControlFrameNotDecodable,
        }
    }

    /// The object-site verdict the framing facts alone dictate, or `None`
    /// when the framer can address the stream and the per-kind rules decide.
    ///
    /// Built from [`object_framing_bypass`], which is the function under
    /// test — so it is used only to *select* which expectation applies, never
    /// as the expectation itself. The compiled-set rows are asserted against
    /// the feature flags directly in
    /// [`the_object_site_is_unreachable_on_a_draft_this_build_did_not_compile`].
    fn framing_verdict(draft: DraftVersion, stream_kind: DataStreamType) -> Option<Support> {
        object_framing_bypass(draft, Some(stream_kind)).map(unreachable_with)
    }

    /// A draft this build compiled, for the per-unit tests whose subject is
    /// a guard that does not depend on the draft.
    ///
    /// The `expect` is unreachable, not a skip: this helper and its two
    /// callers are compiled exactly when at least one draft feature is on,
    /// so `find` always succeeds. A `--no-default-features` build has no
    /// object site at all — it is not that those two facts go untested
    /// there, it is that there is no object site for them to be facts
    /// about, the same reason `exec.rs` compiles its object-site units only
    /// where their draft was compiled. What is *not* acceptable is the
    /// shape this replaced: a build that compiles clean under
    /// `-D warnings` and then panics at run time.
    #[cfg(any(
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
    fn some_compiled_draft() -> DraftVersion {
        DRAFTS
            .into_iter()
            .find(|d| draft_is_compiled(*d))
            .expect("gated on `any(draft07..draft20)`, so the compiled set is non-empty")
    }

    /// A configuration nobody edited can shape the traffic it will see.
    ///
    /// The consequence rather than the value. A class rule naming an ordinary
    /// key is put to the capability table at the draft a default configuration
    /// takes, and it is carried. Where the default names a draft the build did
    /// not compile, [`supports_matcher`] answers `false` for every key on every
    /// stream kind, and a rule with nothing wrong with it is refused as naming
    /// one the draft does not carry.
    ///
    /// **This cannot fail on a full build**, which is why the const assertion
    /// beside [`DEFAULT_DRAFT`] is what holds the invariant and this is the
    /// statement of what the invariant is for. A reduced-draft build is the
    /// only kind that can have the defect, and those are compiled rather than
    /// run.
    #[test]
    fn a_default_configuration_can_shape_the_draft_it_names() {
        let draft = crate::session::ProxySessionConfig::default().draft;
        assert!(
            supports_matcher(draft, MatchKind::Subgroup, MatcherKey::GroupId),
            "a default configuration names {draft:?}, which this build did not compile, so \
             every matcher key is refused on it"
        );
    }

    /// The compiled drafts for which `pred` holds, so a sweep that needs a
    /// draft-shape property still runs in a reduced-draft build and is
    /// simply empty where no such draft was compiled.
    ///
    /// **Do not pass a predicate the sweep is checking.** Narrowing such a
    /// predicate narrows this loop rather than failing a row in it: the drafts
    /// that drop out stop being asked, every draft left passes, and the sweep
    /// reports green over a smaller set than it covered before. Pass
    /// `|_| true` and let the body name each draft's answer, or pass a fact
    /// the code under test does not read.
    fn compiled_drafts_where(pred: fn(DraftVersion) -> bool) -> Vec<DraftVersion> {
        DRAFTS.into_iter().filter(|d| draft_is_compiled(*d) && pred(*d)).collect()
    }

    /// Whether a subgroup stream on this draft can take its Subgroup ID from
    /// the first object on it — stated here, per draft, and deliberately not
    /// read from [`has_implicit_subgroup_id_mode`].
    ///
    /// Two tests below turn on this fact and both used to take it from that
    /// predicate, which made each of them agree with whatever it said. Both
    /// narrowings were run. Removing draft-15 — the exact omission that once
    /// let the engine forward a stream whose Subgroup ID had silently become
    /// the second object's — left both passing, as did narrowing the predicate
    /// all the way to drafts 17-20.
    ///
    /// Eight other tests caught that second cut, so the fence was real; it was
    /// simply not here. `tests/action_matrix.rs` keeps its own copy of this
    /// fact, transcribed from the drafts rather than read off the engine, and
    /// the end-to-end probes it guards are what failed. This is the in-crate
    /// statement of the same fact, and the two are checked against each other
    /// by every verdict they both predict.
    ///
    /// The match is exhaustive on purpose: a fourteenth draft cannot join
    /// either side of the partition without an answer being written here.
    fn a_first_object_carrier_exists(draft: DraftVersion) -> bool {
        match draft {
            // Drafts 07-10 always put an explicit Subgroup ID in the header,
            // so index 0 defines nothing that outlives it.
            DraftVersion::Draft07
            | DraftVersion::Draft08
            | DraftVersion::Draft09
            | DraftVersion::Draft10 => false,
            DraftVersion::Draft11
            | DraftVersion::Draft12
            | DraftVersion::Draft13
            | DraftVersion::Draft14
            | DraftVersion::Draft15
            | DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20 => true,
        }
    }

    /// The object site on a subgroup stream: every cell, on every draft.
    #[test]
    fn object_site_on_subgroup_streams_matches_the_published_table() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            let cell = |kind| caps.supports_on(Site::Object, kind, DataStreamType::Subgroup);
            // A subgroup stream is addressable on every draft this build
            // compiled, and on none it did not — see `draft_is_compiled`.
            let bypassed = framing_verdict(draft, DataStreamType::Subgroup);

            for kind in [
                ActionKind::Pass,
                ActionKind::Delay,
                ActionKind::Hold,
                ActionKind::Truncate,
                ActionKind::ResetStream,
                ActionKind::CloseSession,
            ] {
                let want = bypassed.clone().unwrap_or(Support::Yes);
                assert_eq!(cell(kind), want, "{draft:?} {kind:?}");
            }

            let want = bypassed
                .clone()
                .unwrap_or(Support::Conditional(Precondition::ReplacementLengthEqualsPayload));
            assert_eq!(cell(ActionKind::ReplacePayload), want, "{draft:?}: ReplacePayload support");

            // Only the status guard on 07-10, the four drafts that always put
            // the subgroup ID on the wire and so have no first-object
            // carrier; the subgroup-ID guard leads on every other draft. The
            // fact comes from this module's tests rather than from the
            // predicate the table consults, so that narrowing that predicate
            // contradicts this row instead of moving it.
            let elide_headline = if a_first_object_carrier_exists(draft) {
                Precondition::NotFirstObjectOfImplicitSubgroup
            } else {
                Precondition::NotAStatusObject
            };
            let want = bypassed.clone().unwrap_or(Support::Conditional(elide_headline));
            assert_eq!(cell(ActionKind::DropElide), want, "{draft:?} elide");

            let whole_object =
                bypassed.clone().unwrap_or(wrong_site(Site::Object, ActionKind::ReplaceObject));
            assert_eq!(cell(ActionKind::Replace), whole_object, "{draft:?}");
            assert_eq!(cell(ActionKind::ReplaceObject), whole_object, "{draft:?}");

            for kind in [
                ActionKind::Open,
                ActionKind::Reject,
                ActionKind::OpenAfter,
                ActionKind::SerializeAfter,
            ] {
                assert_eq!(cell(kind), returns_action(Site::Object, kind), "{draft:?}");
            }
        }
    }

    /// The object site on a fetch stream: every cell, on every draft.
    ///
    /// One column now, where there were two. A fetch stream is addressable on
    /// every draft this build compiled, and the drafts that need the fetch's
    /// Group Order to read one get it from the session rather than from the
    /// table — see [`fetch_group_order_is_needed`].
    #[test]
    fn object_site_on_fetch_streams_matches_the_published_table() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            let cell = |kind| caps.supports_on(Site::Object, kind, DataStreamType::Fetch);
            // `DecodeError` on any draft this build left out, and nothing
            // on any it compiled: the header decode fails first there, so a
            // fetch stream's own reasons are never reached.
            let bypassed = framing_verdict(draft, DataStreamType::Fetch);
            if !draft_is_compiled(draft) {
                assert_eq!(
                    bypassed.clone(),
                    Some(unreachable_with(BypassReason::DecodeError)),
                    "{draft:?} is not compiled: the header decode is what fails"
                );
            } else {
                assert_eq!(
                    bypassed.clone(),
                    None,
                    "{draft:?} is compiled, so its fetch objects are the per-kind rules' to                      decide"
                );
            }

            for kind in [
                ActionKind::Pass,
                ActionKind::Delay,
                ActionKind::Hold,
                ActionKind::Truncate,
                ActionKind::ResetStream,
                ActionKind::CloseSession,
            ] {
                let want = bypassed.clone().unwrap_or(Support::Yes);
                assert_eq!(cell(kind), want, "{draft:?} {kind:?}");
            }

            let want = bypassed
                .clone()
                .unwrap_or(Support::Conditional(Precondition::ReplacementLengthEqualsPayload));
            assert_eq!(cell(ActionKind::ReplacePayload), want, "{draft:?}");

            // The status guard is the only one a fetch stream reaches, on
            // every draft: no subgroup-ID guard applies to an object that
            // states its own subgroup, and a removal that moves the survivors
            // is paid for by the framer rather than refused.
            let want =
                bypassed.clone().unwrap_or(Support::Conditional(Precondition::NotAStatusObject));
            assert_eq!(cell(ActionKind::DropElide), want, "{draft:?}");

            for kind in [ActionKind::Replace, ActionKind::ReplaceObject] {
                let want =
                    bypassed.clone().unwrap_or(wrong_site(Site::Object, ActionKind::ReplaceObject));
                assert_eq!(cell(kind), want, "{draft:?} {kind:?}");
            }

            // The unconstructible two and the four stream decisions stay
            // `NotAttemptable` even where the hook is never invoked — the
            // return-type family is decided before the framing bypass, so
            // a fetch cell on 18-19 is `NotAttemptable`, not `Unreachable`.
            for kind in [
                ActionKind::Open,
                ActionKind::Reject,
                ActionKind::OpenAfter,
                ActionKind::SerializeAfter,
            ] {
                assert_eq!(cell(kind), returns_action(Site::Object, kind), "{draft:?}");
            }
        }
    }

    /// The control site on every draft, which is one column and not two:
    /// the six honoured kinds are `Yes` on all fourteen this build carries.
    ///
    /// A draft it does not carry moves the **whole** classified column to
    /// [`Support::Unreachable`] together, refusals included. That is the
    /// object site's rule one decoder later and for the same reason: the
    /// hook is never offered a frame, so `ControlStreamResetIllegal` is a
    /// refusal nothing would ever be there to receive. Publishing it beside
    /// an unreachable `Pass` would say a reset was considered and declined
    /// where in fact nothing was considered at all.
    #[test]
    fn control_site_matches_the_published_table() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            let cell = |kind| caps.supports(Site::Control, kind);

            // The two `NotAttemptable` families below are decided ahead of
            // reachability — `classify` step 1 — so they keep their own
            // answers on every build, and this wrapper is deliberately not
            // applied to them.
            let unreachable = !draft_is_compiled(draft);
            let or_unreachable =
                |want: Support| if unreachable { unreachable_control() } else { want };

            for kind in [
                ActionKind::Pass,
                ActionKind::Replace,
                ActionKind::Delay,
                ActionKind::Hold,
                ActionKind::DropElide,
                ActionKind::CloseSession,
            ] {
                assert_eq!(cell(kind), or_unreachable(Support::Yes), "{draft:?} {kind:?}");
            }

            assert_eq!(
                cell(ActionKind::ReplacePayload),
                or_unreachable(wrong_site(Site::Control, ActionKind::ReplacePayload)),
                "{draft:?}"
            );
            for kind in [ActionKind::Truncate, ActionKind::ResetStream] {
                assert_eq!(
                    cell(kind),
                    or_unreachable(Support::No(Refusal::ControlStreamResetIllegal)),
                    "{draft:?} {kind:?}"
                );
            }
            for kind in [ActionKind::Open, ActionKind::Reject] {
                assert_eq!(cell(kind), returns_action(Site::Control, kind), "{draft:?}");
            }
            assert_eq!(
                cell(ActionKind::ReplaceObject),
                kind_not_here(Site::Control, ActionKind::ReplaceObject),
                "{draft:?}"
            );
        }
    }

    /// The datagram site on every draft.
    #[test]
    fn datagram_site_matches_the_published_table() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            let cell = |kind| caps.supports(Site::Datagram, kind);

            for kind in [ActionKind::Pass, ActionKind::DropElide, ActionKind::CloseSession] {
                assert_eq!(cell(kind), Support::Yes, "{draft:?} {kind:?}");
            }
            assert_eq!(
                cell(ActionKind::Replace),
                Support::Conditional(Precondition::WithinMaxDatagramSize),
                "{draft:?}"
            );
            assert_eq!(
                cell(ActionKind::ReplacePayload),
                Support::Conditional(Precondition::DatagramPayloadDelimited),
                "{draft:?}"
            );
            for kind in
                [ActionKind::Delay, ActionKind::Hold, ActionKind::Truncate, ActionKind::ResetStream]
            {
                assert_eq!(cell(kind), wrong_site(Site::Datagram, kind), "{draft:?} {kind:?}");
            }
        }
    }

    /// The two stream-decision sites on every draft.
    #[test]
    fn stream_decision_sites_match_the_published_table() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            for site in [Site::StreamOpen, Site::StreamHeader] {
                assert_eq!(caps.supports(site, ActionKind::Open), Support::Yes);
                assert_eq!(caps.supports(site, ActionKind::Reject), Support::Yes);
                // `SerializeAfter` tracks `Open` at both sites;
                // `OpenAfter` is refused at the header site, where the peer
                // stream already exists.
                assert_eq!(
                    caps.supports(site, ActionKind::SerializeAfter),
                    Support::Yes,
                    "{draft:?} {site:?}"
                );
                let open_after = if site == Site::StreamOpen {
                    Support::Yes
                } else {
                    wrong_site(site, ActionKind::OpenAfter)
                };
                assert_eq!(
                    caps.supports(site, ActionKind::OpenAfter),
                    open_after,
                    "{draft:?} {site:?}"
                );

                for kind in [
                    ActionKind::Pass,
                    ActionKind::Replace,
                    ActionKind::ReplacePayload,
                    ActionKind::Delay,
                    ActionKind::Hold,
                    ActionKind::DropElide,
                    ActionKind::Truncate,
                    ActionKind::ResetStream,
                    ActionKind::CloseSession,
                ] {
                    assert_eq!(
                        caps.supports(site, kind),
                        returns_stream_action(site, kind),
                        "{draft:?} {site:?} {kind:?}"
                    );
                }
                assert_eq!(
                    caps.supports(site, ActionKind::ReplaceObject),
                    kind_not_here(site, ActionKind::ReplaceObject)
                );
            }
        }
    }

    /// The stream-end site's two columns — the split
    /// `CapCtx::is_control_stream` exists to express, swept both ways.
    #[test]
    fn stream_end_is_answered_for_both_data_and_control_streams() {
        for draft in DRAFTS {
            for is_control in [false, true] {
                let cx = CapCtx {
                    draft: Some(draft),
                    is_control_stream: Some(is_control),
                    ..CapCtx::default()
                };
                let cell = |kind| classify(Site::StreamEnd, kind, &cx);

                // Honoured on both columns.
                assert_eq!(cell(ActionKind::Pass), Support::Yes, "{draft:?}");
                assert_eq!(cell(ActionKind::CloseSession), Support::Yes, "{draft:?}");

                let reset = cell(ActionKind::ResetStream);
                if is_control {
                    assert_eq!(reset, Support::No(Refusal::ControlStreamResetIllegal));
                } else {
                    assert_eq!(reset, Support::Yes);
                }

                let truncate = cell(ActionKind::Truncate);
                if is_control {
                    assert_eq!(truncate, Support::No(Refusal::ControlStreamResetIllegal));
                } else {
                    assert_eq!(truncate, wrong_site(Site::StreamEnd, ActionKind::Truncate));
                }

                for kind in [
                    ActionKind::Replace,
                    ActionKind::ReplacePayload,
                    ActionKind::Delay,
                    ActionKind::Hold,
                    ActionKind::DropElide,
                ] {
                    assert_eq!(
                        cell(kind),
                        wrong_site(Site::StreamEnd, kind),
                        "{draft:?} control={is_control} {kind:?}"
                    );
                }
            }
        }
    }

    /// The whole point of the module: one reading, not three.
    #[test]
    fn replace_object_has_exactly_one_reading() {
        for site in SITES {
            let verdict = classify(site, ActionKind::ReplaceObject, &CapCtx::default());
            if site == Site::Object {
                assert_eq!(
                    verdict,
                    wrong_site(Site::Object, ActionKind::ReplaceObject),
                    "the object site really is asked, and really refuses"
                );
            } else {
                assert_eq!(verdict, kind_not_here(site, ActionKind::ReplaceObject), "{site:?}");
            }
        }
    }

    /// At the object site the two rows are one expression, so they are one
    /// value.
    #[test]
    fn replace_and_replace_object_agree_at_the_object_site() {
        for draft in DRAFTS {
            for stream_kind in [DataStreamType::Subgroup, DataStreamType::Fetch] {
                let caps = Capabilities::for_draft(draft);
                assert_eq!(
                    caps.supports_on(Site::Object, ActionKind::Replace, stream_kind),
                    caps.supports_on(Site::Object, ActionKind::ReplaceObject, stream_kind),
                    "{draft:?} {stream_kind:?}"
                );
            }
        }
    }
    /// The table half of
    /// `every_declared_refusal_is_reachable_or_declared_table_only`: the
    /// table-only variant appears **only** inside `NotAttemptable` /
    /// `Unreachable`, never as a `No(..)` the engine would have to emit.
    #[test]
    fn table_only_refusals_never_appear_as_no() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            for site in SITES {
                for kind in KINDS {
                    for verdict in [
                        caps.supports(site, kind),
                        caps.supports_on(site, kind, DataStreamType::Subgroup),
                        caps.supports_on(site, kind, DataStreamType::Fetch),
                    ] {
                        let Support::No(refusal) = verdict else {
                            continue;
                        };
                        assert!(
                            !matches!(
                                refusal,
                                Refusal::StreamNotFramed { .. }
                            ),
                            "{draft:?} {site:?} {kind:?} declares a table-only refusal as No({refusal:?})"
                        );
                    }
                }
            }
        }
    }

    /// Every cell of the sweep axis has a verdict — no `(site, kind)` pair
    /// falls through a helper's filtered arm into a wrong answer.
    #[test]
    fn every_site_kind_pair_is_answered() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            for site in SITES {
                for kind in KINDS {
                    let verdict = caps.supports(site, kind);
                    // A filtered-arm leak would surface as a
                    // `KindNotDefinedAtThisSite` on a kind that is not
                    // `ReplaceObject`.
                    if let Support::NotAttemptable {
                        why: NotAttemptable::KindNotDefinedAtThisSite,
                        ..
                    } = verdict
                    {
                        assert_eq!(
                            kind,
                            ActionKind::ReplaceObject,
                            "{site:?} {kind:?} fell through to the filtered arm"
                        );
                    }
                }
            }
        }
    }

    // ── The per-unit facts: `Conditional` resolving both ways ───────────

    /// The length guard reads no draft field, so it is asserted on whatever
    /// draft this build compiled rather than on a hard-coded one — which is
    /// what keeps it running in a reduced-draft build, where a hard-coded
    /// draft-11 would be [`Support::Unreachable`] and measure nothing.
    ///
    /// Compiled where any draft was, because [`some_compiled_draft`] has an
    /// answer exactly there; a zero-draft build reaches no object site.
    #[cfg(any(
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
    #[test]
    fn replace_payload_length_mismatch_is_length_changed() {
        let cx = CapCtx {
            draft: Some(some_compiled_draft()),
            payload_len: Some(1200),
            replacement_len: Some(800),
            is_status_object: Some(false),
            ..CapCtx::default()
        };
        assert_eq!(
            classify(Site::Object, ActionKind::ReplacePayload, &cx),
            Support::No(Refusal::LengthChanged { from: 1200, to: 800 })
        );

        let ok = CapCtx { replacement_len: Some(1200), ..cx };
        assert_eq!(classify(Site::Object, ActionKind::ReplacePayload, &ok), Support::Yes);
    }

    /// Gated with its neighbour, and for the same reason.
    #[cfg(any(
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
    #[test]
    fn replace_payload_on_a_status_object_is_refused() {
        let cx = CapCtx {
            draft: Some(some_compiled_draft()),
            payload_len: Some(0),
            replacement_len: Some(0),
            is_status_object: Some(true),
            ..CapCtx::default()
        };
        assert_eq!(
            classify(Site::Object, ActionKind::ReplacePayload, &cx),
            Support::No(Refusal::WouldDestroyStatusObject)
        );
    }

    /// The reserved-mode split, on every draft whose two mode bits have to be
    /// consulted **and** was compiled. Empty in a build that left all five
    /// out, which is the honest answer there: those cells are `Unreachable`.
    #[test]
    fn elide_guards_follow_the_execution_order() {
        for draft in compiled_drafts_where(subgroup_id_mode_must_be_consulted) {
            let base = CapCtx {
                draft: Some(draft),
                stream_kind: Some(DataStreamType::Subgroup),
                index_in_stream: Some(0),
                subgroup_id_resolved: Some(false),
                is_status_object: Some(false),
                ..CapCtx::default()
            };

            // Mode 1: the first object defines the subgroup ID.
            assert_eq!(
                classify(Site::Object, ActionKind::DropElide, &base),
                Support::No(Refusal::WouldRedefineSubgroupId),
                "{draft:?}"
            );

            // Mode 3 is reserved, and says something different about the wire.
            let reserved = CapCtx { subgroup_id_mode: Some(3), ..base };
            assert_eq!(
                classify(Site::Object, ActionKind::DropElide, &reserved),
                Support::No(Refusal::ReservedHeaderMode { mode: 3 }),
                "{draft:?}"
            );

            // Later objects on the same stream redefine nothing.
            let later = CapCtx { index_in_stream: Some(1), ..base };
            assert_eq!(
                classify(Site::Object, ActionKind::DropElide, &later),
                Support::Yes,
                "{draft:?}"
            );

            // A status object is a boundary marker on every draft.
            let status = CapCtx { is_status_object: Some(true), ..later };
            assert_eq!(
                classify(Site::Object, ActionKind::DropElide, &status),
                Support::No(Refusal::WouldDestroyStatusObject),
                "{draft:?}"
            );
        }
    }

    /// What a reserved mode is answered with, on every compiled draft, from a
    /// list written out here rather than taken from
    /// [`subgroup_id_mode_must_be_consulted`].
    ///
    /// The test above sweeps that predicate, which makes it blind in one
    /// direction: narrowing the predicate narrows its loop, so coverage
    /// disappears without a failure and the drafts that dropped out are simply
    /// no longer asked. This match is exhaustive over [`DraftVersion`] and
    /// names every draft's answer, so narrowing the predicate contradicts a
    /// line here instead, and a fourteenth draft cannot be added without one.
    ///
    /// Three answers, and each is a different sentence about the wire:
    ///
    /// - Drafts 07-10 always put the Subgroup ID on the wire, so index 0 is
    ///   not special and there is nothing to refuse.
    /// - Drafts 11-14 name each carrier with a stream type of its own and
    ///   assign every type they define, so a header that determines no
    ///   Subgroup ID is a first-object header and nothing else — the mode
    ///   field is not theirs to read, and `WouldRedefineSubgroupId` is exactly
    ///   what is true of one.
    /// - Drafts 15-20 encode the carrier in two bits with a fourth
    ///   combination none of them assigns, so a header can determine no
    ///   Subgroup ID for either reason and the mode is what separates them.
    ///
    /// *Ablation (measured):* return to naming only drafts 17, 18 and 19 in
    /// `subgroup_id_mode_must_be_consulted`, which is the set it held while the
    /// codec still resolved the fourth combination on 15 and 16:
    ///
    /// ```text
    /// assertion `left == right` failed: Draft15
    ///   left: No(WouldRedefineSubgroupId)
    ///  right: No(ReservedHeaderMode { mode: 3 })
    /// ```
    ///
    /// The test above passes under that same ablation, which is why this one
    /// is here.
    #[test]
    fn a_reserved_mode_is_answered_as_itself_wherever_a_header_can_carry_one() {
        for draft in compiled_drafts_where(|_| true) {
            let cx = CapCtx {
                draft: Some(draft),
                stream_kind: Some(DataStreamType::Subgroup),
                index_in_stream: Some(0),
                subgroup_id_resolved: Some(false),
                is_status_object: Some(false),
                subgroup_id_mode: Some(RESERVED_SUBGROUP_ID_MODE),
                ..CapCtx::default()
            };
            let want = match draft {
                DraftVersion::Draft07
                | DraftVersion::Draft08
                | DraftVersion::Draft09
                | DraftVersion::Draft10 => Support::Yes,
                DraftVersion::Draft11
                | DraftVersion::Draft12
                | DraftVersion::Draft13
                | DraftVersion::Draft14 => Support::No(Refusal::WouldRedefineSubgroupId),
                DraftVersion::Draft15
                | DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
                | DraftVersion::Draft20 => {
                    Support::No(Refusal::ReservedHeaderMode { mode: RESERVED_SUBGROUP_ID_MODE })
                }
            };
            assert_eq!(classify(Site::Object, ActionKind::DropElide, &cx), want, "{draft:?}");
        }
    }

    /// A header that determines its own Subgroup ID frees index 0 on **every**
    /// draft, first-object carrier or not.
    ///
    /// This swept only the drafts with no such carrier, taken from the
    /// predicate under test, and asserted the one thing that is true of them —
    /// which made it two tests' worth of blind spot for one test's worth of
    /// claim. Narrowing the predicate narrowed the loop rather than failing a
    /// row, and the drafts it added to the loop answered `Yes` anyway, because
    /// a resolved Subgroup ID satisfies the guard on every draft that has one.
    ///
    /// That last sentence is the claim worth making, so the sweep is now all
    /// fourteen and the expected answer is one value. The contrast it used to
    /// gesture at — refused where the carrier exists, allowed where it does
    /// not — is
    /// [`the_first_object_subgroup_guard_turns_on_the_stream_kind`], which
    /// states it per draft.
    #[test]
    fn a_resolved_subgroup_id_frees_the_first_object_on_every_draft() {
        for draft in compiled_drafts_where(|_| true) {
            let cx = CapCtx {
                draft: Some(draft),
                stream_kind: Some(DataStreamType::Subgroup),
                index_in_stream: Some(0),
                subgroup_id_resolved: Some(true),
                is_status_object: Some(false),
                ..CapCtx::default()
            };
            assert_eq!(
                classify(Site::Object, ActionKind::DropElide, &cx),
                Support::Yes,
                "{draft:?}"
            );
        }
    }

    /// Index 0 with an unresolved subgroup ID — the exact shape the subgroup
    /// guard refuses — is refused on a subgroup stream and allowed on a fetch
    /// one, on every draft that addresses both.
    ///
    /// Both halves in one test because the claim is a contrast rather than
    /// two facts: the guard turns on the stream kind, and a fetch cell that
    /// happened to answer `Yes` for some other reason would be
    /// indistinguishable from one the guard never reached. A fetch object
    /// states its own Subgroup ID or states that it has none, so
    /// `WouldRedefineSubgroupId` is a sentence that is not true about it.
    ///
    /// The subgroup half takes which drafts have a first-object carrier from
    /// [`a_first_object_carrier_exists`] rather than from the predicate
    /// `classify` consults. Reading it from that predicate made this test
    /// agree with it whatever it said.
    ///
    /// *Ablation (measured):* narrow `has_implicit_subgroup_id_mode` to drafts
    /// 17, 18 and 19. With the fact taken independently, this now fails on the
    /// first draft that lost the guard:
    ///
    /// ```text
    /// assertion `left == right` failed: Draft11 subgroup
    ///   left: Yes
    ///  right: No(WouldRedefineSubgroupId)
    /// ```
    #[test]
    fn the_first_object_subgroup_guard_turns_on_the_stream_kind() {
        for draft in compiled_drafts_where(|_| true) {
            let cx = |stream_kind| CapCtx {
                draft: Some(draft),
                stream_kind: Some(stream_kind),
                index_in_stream: Some(0),
                subgroup_id_resolved: Some(false),
                is_status_object: Some(false),
                ..CapCtx::default()
            };
            assert_eq!(
                classify(Site::Object, ActionKind::DropElide, &cx(DataStreamType::Fetch)),
                Support::Yes,
                "{draft:?} fetch"
            );
            let subgroup =
                classify(Site::Object, ActionKind::DropElide, &cx(DataStreamType::Subgroup));
            if a_first_object_carrier_exists(draft) {
                assert_eq!(
                    subgroup,
                    Support::No(Refusal::WouldRedefineSubgroupId),
                    "{draft:?} subgroup"
                );
            } else {
                assert_eq!(subgroup, Support::Yes, "{draft:?} subgroup");
            }
        }
    }

    /// Eliding a fetch object turns on the object's status and on nothing
    /// else — not on its index, and not on the draft.
    /// The index half is the one worth stating: a fetch stream is the case
    /// where *the first object of the stream* carries no special meaning,
    /// because a fetch object's Subgroup ID is its own rather than the
    /// header's.
    ///
    /// Draft-15 is the only draft where the status half can be shown at all
    /// — 16 through 20 removed the Object Status field from fetch objects,
    /// so nothing there is ever `is_status_object: Some(true)` off the wire.
    /// It is swept on every addressable draft anyway, because the guard is
    /// draft-neutral and a context this crate cannot produce is still a
    /// context the published table answers.
    #[test]
    fn eliding_a_fetch_object_turns_only_on_its_status() {
        for draft in compiled_drafts_where(|_| true) {
            for index in [0u64, 1, 7] {
                for status in [Some(false), Some(true), None] {
                    let cx = CapCtx {
                        draft: Some(draft),
                        stream_kind: Some(DataStreamType::Fetch),
                        index_in_stream: Some(index),
                        is_status_object: status,
                        ..CapCtx::default()
                    };
                    let want = match status {
                        Some(true) => Support::No(Refusal::WouldDestroyStatusObject),
                        Some(false) => Support::Yes,
                        None => Support::Conditional(Precondition::NotAStatusObject),
                    };
                    assert_eq!(
                        classify(Site::Object, ActionKind::DropElide, &cx),
                        want,
                        "{draft:?} index {index} status {status:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn datagram_payload_not_delimited_names_its_case() {
        let undelimited = |draft, status| CapCtx {
            draft: Some(draft),
            payload_delimited: Some(false),
            is_status_object: status,
            ..CapCtx::default()
        };
        let detail = |cx: CapCtx| match classify(Site::Datagram, ActionKind::ReplacePayload, &cx) {
            Support::No(Refusal::PayloadNotDelimited { detail }) => detail,
            other => panic!("expected PayloadNotDelimited, got {other:?}"),
        };

        assert_eq!(
            detail(undelimited(DraftVersion::Draft14, Some(false))),
            "draft-14 header decode consumes the payload"
        );
        assert_eq!(
            detail(undelimited(DraftVersion::Draft19, Some(true))),
            "status datagram has no payload"
        );
        assert_eq!(
            detail(undelimited(DraftVersion::Draft19, None)),
            "datagram header did not decode"
        );

        let delimited = CapCtx {
            draft: Some(DraftVersion::Draft19),
            payload_delimited: Some(true),
            ..CapCtx::default()
        };
        assert_eq!(classify(Site::Datagram, ActionKind::ReplacePayload, &delimited), Support::Yes);
    }

    // ── The control column does not split on the draft ──────────────────

    /// The control site is honoured on all fourteen drafts, 17-20 included.
    ///
    /// Those three moved the control plane onto a pair of unidirectional
    /// streams, and while the engine still took the first bidirectional
    /// stream to be the control stream this column published
    /// `Conditional(SiteSeesTheControlStream)` there — the site was shown a
    /// request stream and SETUP never reached the hook. `session.rs` now
    /// identifies the pair by its stream type, so the whole control plane
    /// reaches the site and the split is gone.
    ///
    /// The draft rows are written out rather than derived, so the claim is
    /// made against the draft numbers and not against the function under
    /// test. *Ablation:* return anything but `Support::Yes` from
    /// `classify_control` for the three drafts named below and every one of
    /// their rows goes red.
    #[test]
    fn the_control_site_is_honoured_on_every_draft() {
        const UNI_CONTROL_PLANE: [DraftVersion; 4] = [
            DraftVersion::Draft17,
            DraftVersion::Draft18,
            DraftVersion::Draft19,
            DraftVersion::Draft20,
        ];

        // The kinds the control site honours — including the two whose
        // misreading is expensive.
        const HONOURED: [ActionKind; 6] = [
            ActionKind::Pass,
            ActionKind::Replace,
            ActionKind::Delay,
            ActionKind::Hold,
            ActionKind::DropElide,
            ActionKind::CloseSession,
        ];

        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            let uni_control_plane = UNI_CONTROL_PLANE.contains(&draft);

            // The one split this column does take is not a draft split at
            // all, and it is asserted next door rather than here: see
            // [`the_control_site_is_unreachable_on_a_draft_this_build_did_not_compile`].
            // Skipped rather than folded in, so this test stays a claim
            // about draft numbers and that one stays a claim about the
            // build.
            if !draft_is_compiled(draft) {
                continue;
            }

            for kind in HONOURED {
                let verdict = caps.supports(Site::Control, kind);
                assert_eq!(
                    verdict,
                    Support::Yes,
                    "{draft:?} {kind:?} (pair-of-unidirectional control plane: \
                     {uni_control_plane})"
                );

                // Restated structurally: `Unreachable` and `NotAttemptable` are
                // the module's two verdicts for *nothing is ever attempted
                // here*, and neither is what this site publishes.
                assert!(
                    !matches!(
                        verdict,
                        Support::Unreachable { .. } | Support::NotAttemptable { .. }
                    ),
                    "{draft:?} {kind:?}: the control site is attemptable on every draft"
                );
            }

            // The contrast, on the same draft, so "attemptable" is measured
            // against a cell that really is inert rather than asserted in
            // isolation: the object site is `Unreachable` on any draft this
            // build did not compile.
            if !draft_is_compiled(draft) {
                assert!(
                    matches!(
                        caps.supports_on(Site::Object, ActionKind::Pass, DataStreamType::Fetch),
                        Support::Unreachable { .. }
                    ),
                    "{draft:?}: the module does have a verdict for 'never invoked'"
                );
            }

            // The reset-and-truncate refusal is untouched by any of the
            // above, on every draft: a request stream is a control-plane
            // stream too, so resetting one is still refused.
            for kind in [ActionKind::Truncate, ActionKind::ResetStream] {
                assert_eq!(
                    caps.supports(Site::Control, kind),
                    Support::No(Refusal::ControlStreamResetIllegal),
                    "{draft:?} {kind:?}"
                );
            }
        }
    }

    // ── The compiled draft set is a fact the table reads ────────────────

    /// The **control** site is unreachable there too, one decoder later.
    ///
    /// Sibling of
    /// [`the_object_site_is_unreachable_on_a_draft_this_build_did_not_compile`]
    /// and separate from it on purpose: the two fail in different decoders
    /// and a run reports them with different events, so a single verdict
    /// covering both would send a reader looking for a `FramerBypass` that
    /// no control stream emits. `AnyControlMessage::decode` has no arm for
    /// an uncompiled draft, so `ControlStreamParser::feed` refuses every
    /// frame on the stream and `ProxyHook::on_control_message` is never
    /// offered one.
    ///
    /// This cell published [`Support::Yes`] until the run had something
    /// truthful to point at. It is the shape of documented lie this module
    /// exists to prevent, and the reason it survived is worth keeping: the
    /// honest verdict needs [`Support::Unreachable`]'s `instead`, and until
    /// [`ImpairmentKind::ControlFrameNotDecodable`](crate::event::ImpairmentKind::ControlFrameNotDecodable)
    /// existed there was nothing to put there.
    ///
    /// Vacuous under `--all-features` and load-bearing under a reduced
    /// build, exactly like its sibling: `cargo test -p moqtap-proxy
    /// --no-default-features --features draft07 --lib capability::` is
    /// where thirteen of the fourteen rows take the assertion.
    ///
    /// *Ablation (measured):* delete the `Site::Control` guard from
    /// [`classify`]. Green under `--all-features`, and under
    /// `--features draft07`:
    ///
    /// ```text
    /// ---- capability::tests::the_control_site_is_unreachable_on_a_draft_this_build_did_not_compile stdout ----
    /// assertion `left == right` failed: Draft08
    ///   left: Yes
    ///  right: Unreachable { refusal: ControlFrameNotDecodable, instead: ControlFrameNotDecodable }
    /// ```
    ///
    /// `Yes` for a site this build cannot reach, on the first of the twelve
    /// drafts it left out.
    #[test]
    fn the_control_site_is_unreachable_on_a_draft_this_build_did_not_compile() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            let want = if draft_is_compiled(draft) { Support::Yes } else { unreachable_control() };
            assert_eq!(caps.supports(Site::Control, ActionKind::Pass), want, "{draft:?}");

            // The reset kinds move with the column rather than keeping
            // their refusal. A refusal is what the engine would hand a
            // hook, and on this draft no hook is ever reached, so
            // publishing `ControlStreamResetIllegal` here would describe a
            // decision nothing takes. The object site answers the same way
            // for the same reason.
            assert_eq!(
                caps.supports(Site::Control, ActionKind::ResetStream),
                if draft_is_compiled(draft) {
                    Support::No(Refusal::ControlStreamResetIllegal)
                } else {
                    unreachable_control()
                },
                "{draft:?}: the reset refusal is published only where a hook could receive it"
            );

            // What does *not* move: the kinds no value can carry to this
            // site. They are decided before reachability is consulted, so
            // a reduced build must not turn them into `Unreachable` as
            // collateral.
            assert_eq!(
                caps.supports(Site::Control, ActionKind::ReplaceObject),
                kind_not_here(Site::Control, ActionKind::ReplaceObject),
                "{draft:?}: a control frame is not an object on any build"
            );
        }
    }

    /// The table must not publish [`Support::Yes`] for a draft this binary
    /// cannot frame.
    ///
    /// Runs in every feature configuration and has teeth in the reduced
    /// ones — `cargo test -p moqtap-proxy --no-default-features --features
    /// draft07 --lib capability::` is where thirteen of the fourteen rows take
    /// the `else` branch. It is deliberately not vacuous in the all-drafts
    /// build either: there it asserts that every row stayed `Yes`, which is
    /// the claim that this fix changed nothing in the shipped default.
    ///
    /// *Ablation:* drop the `draft_is_compiled` guard from
    /// [`object_framing_bypass`]. Green under `--all-features`, red under
    /// `--features draft07` on all twelve uncompiled drafts.
    ///
    /// `ProxySessionConfig::default().draft` is `Draft14` and nothing
    /// validates it against the compiled set, so the draft-14 row is the
    /// default configuration of a draft07-only binary, not a corner case.
    #[test]
    fn the_object_site_is_unreachable_on_a_draft_this_build_did_not_compile() {
        for draft in DRAFTS {
            let caps = Capabilities::for_draft(draft);
            for stream_kind in [DataStreamType::Subgroup, DataStreamType::Fetch] {
                let verdict = caps.supports_on(Site::Object, ActionKind::Pass, stream_kind);

                if draft_is_compiled(draft) {
                    assert_eq!(verdict, Support::Yes, "{draft:?} {stream_kind:?}");
                } else {
                    assert_eq!(
                        verdict,
                        unreachable_with(BypassReason::DecodeError),
                        "{draft:?} {stream_kind:?} is not compiled: the stream header decode \
                         returns UnsupportedDraft, the framer latches DecodeError, and no object \
                         reaches the hook"
                    );
                }
            }
        }
    }

    /// The sweep above chooses its own expectation with `draft_is_compiled`,
    /// so it is only meaningful if that function reports the build rather
    /// than a constant: answering `false` everywhere would make the whole
    /// object column `Unreachable` and pass, and answering `true` everywhere
    /// would make it all `Yes` and pass just as quietly.
    ///
    /// The invariant is therefore *agreement with the build*, not a
    /// non-empty set. "Non-empty" is simply false under
    /// `--no-default-features`, which is a supported configuration — the
    /// codec compiles with no draft, CI has a row for it, and a consumer
    /// vendoring one draft depends on that machinery — so a test asserting
    /// it was asserting a defect into a row that has none. Stated as
    /// agreement it runs, and bites, in all sixteen rows.
    ///
    /// *Ablation:* replace `draft_is_compiled`'s body with `false` — red in
    /// the fifteen rows that compile a draft. With `true` — red in the
    /// zero-draft row, which the previous wording could not reach at all.
    #[test]
    fn the_compiled_draft_set_agrees_with_the_enabled_features() {
        let compiled: Vec<DraftVersion> =
            DRAFTS.into_iter().filter(|d| draft_is_compiled(*d)).collect();
        let build_has_a_draft = cfg!(any(
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
        ));
        assert_eq!(
            !compiled.is_empty(),
            build_has_a_draft,
            "`draft_is_compiled` reports {compiled:?}, but this build has {} draft feature \
             enabled",
            if build_has_a_draft { "at least one" } else { "no" }
        );
    }

    /// And the shipped default really is all fourteen, so the fix above is
    /// inert in the configuration the acceptance suite runs under.
    #[cfg(feature = "all-drafts")]
    #[test]
    fn the_default_build_compiles_every_draft() {
        for draft in DRAFTS {
            assert!(draft_is_compiled(draft), "{draft:?} is missing from `all-drafts`");
        }
    }

    /// A default [`CapCtx`] answers the whole table without panicking, and
    /// without ever claiming `Yes` on a fact it was not given.
    #[test]
    fn a_default_context_is_answerable_at_every_cell() {
        for site in SITES {
            for kind in KINDS {
                let _ = classify(site, kind, &CapCtx::default());
            }
        }
    }
}

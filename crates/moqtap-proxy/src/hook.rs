//! Decide what happens to frames, objects, datagrams and streams.
//!
//! [`ProxyHook`] is the decision surface: every method is synchronous,
//! defaulted, and returns *data* describing what the engine should do —
//! never a future, never a mutation performed in place. Timing is
//! expressed as [`Action::Delay`] / [`Action::Hold`] and executed by the
//! egress engine, where it is precise, attributable and bounded, so a hook
//! can never stall a read loop.
//!
//! [`Interest`] is the other half. It is sampled **once**, at session
//! start, and decides which of the six methods are armed at all;
//! [`Interest::NONE`] keeps all three forwarding paths on the zero-parse
//! byte pump. The normative gating expression is mirrored in each method's
//! rustdoc below.
//!
//! [`LegacyProxyHook`] and [`LegacyHook`] carry the 0.3.x
//! `Option<Vec<u8>>` shape forward so existing implementations keep
//! working while they migrate.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;

use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
use moqtap_codec::version::DraftVersion;

use crate::action::{Action, Interest, StreamAction, StreamEnd};
use crate::capability::Capabilities;
use crate::event::{DataStreamHeaderKind, SessionId};
use crate::shape::StreamKey;
use crate::types::{ObjectMeta, ProxySide};

/// Context for a control message or datagram decision.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FrameCtx<'a> {
    /// The session identifier.
    pub session_id: SessionId,
    /// The side the unit arrived on.
    pub side: ProxySide,
    /// The draft this unit was parsed under.
    ///
    /// A session's draft is not necessarily the one it was configured with.
    /// The ALPN names a draft outright from draft-15 on, and such a session
    /// is settled before it dials, so this never moves. Drafts 07 to 14
    /// share the one ALPN `moq-00`: a session in that cohort starts on the
    /// draft its configuration named and the control stream refines it from
    /// the first SETUP it can read — CLIENT_SETUP's highest offered version,
    /// which SERVER_SETUP's selected version then outranks, because the
    /// second is what the peers agreed and the first is only what one of
    /// them proposed.
    ///
    /// Both sites this context is built for see the refined answer rather
    /// than the starting draft, by two different mechanisms.
    /// [`ProxyHook::on_datagram`]'s forwarding task waits for the control
    /// stream to answer before it reads its first datagram.
    /// [`ProxyHook::on_control_message`] needs no wait: a session that
    /// declared [`Interest::CONTROL`](crate::action::Interest::CONTROL)
    /// withholds the control stream's bytes until the leading SETUP has been
    /// peeked at, so even the frame that named the draft is reported under
    /// it.
    ///
    /// Two cases end the wait with the starting draft instead, and both are
    /// sessions no draft describes: a peer that sends no SETUP at all, and a
    /// peer whose first control message is something else. A SETUP arriving
    /// after either still refines what comes after it.
    pub draft: DraftVersion,
    /// The stream this frame belongs to. `None` for datagrams.
    pub stream_id: Option<u64>,
    /// When the proxy produced this unit for decision.
    pub arrived_at: Instant,
    /// What is executable on this draft at this site.
    pub caps: &'a Capabilities,
}

/// Context for a stream open, stream header, or stream end decision.
///
/// At [`ProxyHook::on_stream_open`] this is deliberately **track-blind**:
/// the peer stream is opened before the first byte of the source stream is
/// read, so no track alias, group or subgroup is known. To reject a stream
/// by track, return [`StreamAction::Open`] there and decide in
/// [`ProxyHook::on_stream_header`], which runs before the header's bytes
/// are forwarded.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct StreamCtx<'a> {
    /// The session identifier.
    pub session_id: SessionId,
    /// The side the stream arrived on.
    pub side: ProxySide,
    /// The source stream's transport-level identifier.
    ///
    /// **`0` for every WebTransport stream** — `SendStream::stream_id()` and
    /// `RecvStream::stream_id()` both return the constant on that arm. Use
    /// it to correlate with the transport-level events in
    /// [`crate::event`]; use [`Self::key`] to *identify* the stream.
    pub stream_id: u64,
    /// The draft this stream is being parsed under. See
    /// [`FrameCtx::draft`] for what settles it and when.
    ///
    /// [`ProxyHook::on_stream_header`] always carries the settled answer:
    /// its stream waits for one before it frames a byte, because the draft
    /// decides where an object ends. [`ProxyHook::on_stream_open`] and
    /// [`ProxyHook::on_stream_end`] read it without waiting — the first runs
    /// before the stream has been read at all, so there is nothing it could
    /// wait *for* that the session has not already asked of the control
    /// stream — so on the `moq-00` cohort a stream opened before any SETUP
    /// was readable is offered here under the draft the session started on.
    pub draft: DraftVersion,
    /// Whether the control stream's rules apply to this stream.
    /// It is the flag that selects those rules, not a claim about which QUIC
    /// stream this is, and on two of the three sites the difference is visible.
    /// Read it as *a reset here is a protocol violation*, which is what every
    /// site uses it for.
    ///
    /// **At [`ProxyHook::on_stream_end`] on drafts 17-19 it is `true` for a
    /// bidirectional *request* stream as well as for the control stream.**
    /// Those drafts carry the control plane on a pair of unidirectional
    /// streams and carry requests on bidirectional ones (draft-17 Section
    /// 3.3), and both are forwarded through the same control-message
    /// framing, so both run under the control stream's end-of-stream rules
    /// and [`Action::ResetStream`] is refused on both. Draft-17 Section
    /// 3.3.1 permits a *request* to be cancelled by resetting its stream, so
    /// refusing is stricter than the draft requires; it is the conservative
    /// direction, nothing is destroyed that the draft would have kept, and
    /// it is what [`crate::capability`] publishes. A hook that needs to tell
    /// the two apart on those drafts cannot do it from this flag.
    ///
    /// **At [`ProxyHook::on_stream_open`] on drafts 17-19 it is `false` for
    /// the unidirectional control stream.** That site runs before the
    /// stream's type varint has been read, which is the only thing that says
    /// what the stream is, so at that point nothing knows. One consequence
    /// is worth stating plainly: [`StreamAction::Reject`] returned there may
    /// land on a control stream, and no refusal reports it, because the site
    /// had nothing to refuse it on.
    ///
    /// On drafts 07-16 the control stream is the first client-initiated
    /// bidirectional stream, it never reaches `on_stream_open` at all, and
    /// this flag means exactly what its name says at every site.
    pub is_control_stream: bool,
    /// What is executable on this draft at this site.
    pub caps: &'a Capabilities,
    /// This stream's session-local identity.
    ///
    /// **Private, unlike every other field on the three context types**, and
    /// deliberately so: it is minted by the session, and a hook that could
    /// write one could hand
    /// [`StreamAction::SerializeAfter`](crate::action::StreamAction::SerializeAfter)
    /// a key naming a stream that never existed. That case is defined —
    /// it proceeds immediately and reports `SerializeTargetUnknown` — but it
    /// is a *mistake* the engine reports, not an API the struct should
    /// invite. [`Self::key`] is the read path and
    /// [`Self::new`] is the write path.
    key: StreamKey,
}

/// Context for an object decision.
///
/// Everything a hook matches on is on `meta`, without re-parsing.
/// `arrived_at` lives here and **not** on [`ObjectMeta`], which is
/// `Copy + PartialEq + Eq` and is compared by value across the test suite.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ObjectCtx<'a> {
    /// The session identifier.
    pub session_id: SessionId,
    /// The side the object arrived on.
    pub side: ProxySide,
    /// The source stream's transport-level identifier.
    pub stream_id: u64,
    /// Identity and framing: draft, stream kind, track alias, group,
    /// subgroup, object ID, publisher priority, index in stream, payload
    /// length and status.
    pub meta: &'a ObjectMeta,
    /// When the framer produced this object.
    pub arrived_at: Instant,
    /// What is executable on this draft and stream kind. Consult it before
    /// returning an action rather than discovering the refusal in a report.
    pub caps: &'a Capabilities,
}

// ── constructors for the three context types ───────────────────────────
//
// All three are `#[non_exhaustive]`, which forbids struct-literal
// construction outside this crate (E0639). Without constructors,
// `crates/moqtap-proxy/tests/` — a separate crate — could not build a
// `FrameCtx`, so `tests/hook_api.rs::the_hook_trait_is_dyn_compatible`
// could not be written, and that test is the *only* guard on this trait
// staying dyn-compatible — no `async fn`, no `async-trait`. The same
// restriction would stop every downstream user unit-testing their own
// hook, which is most of why these constructors exist at all.
//
// They are `pub`, not `#[doc(hidden)]`: unit-testing a hook is a
// supported use, not an internal one.

impl<'a> FrameCtx<'a> {
    /// Build a context. Field order matches the struct.
    ///
    /// `stream_id` is `None` for datagrams.
    pub fn new(
        session_id: SessionId,
        side: ProxySide,
        draft: DraftVersion,
        stream_id: Option<u64>,
        arrived_at: Instant,
        caps: &'a Capabilities,
    ) -> Self {
        Self { session_id, side, draft, stream_id, arrived_at, caps }
    }
}

impl<'a> StreamCtx<'a> {
    /// Build a context. Field order matches the struct.
    ///
    /// `key` is the stream's session-local identity; the session mints one
    /// per accepted stream and hands the *same* key to all three stream
    /// sites, which is what makes [`Self::key`] a name a later stream can
    /// serialize behind.
    pub fn new(
        session_id: SessionId,
        side: ProxySide,
        stream_id: u64,
        draft: DraftVersion,
        is_control_stream: bool,
        caps: &'a Capabilities,
        key: StreamKey,
    ) -> Self {
        Self { session_id, side, stream_id, draft, is_control_stream, caps, key }
    }

    /// This stream's session-local identity, for naming it later.
    ///
    /// The value to hand
    /// [`StreamAction::SerializeAfter`]
    /// so a *different* stream waits for this one. Stable across
    /// [`ProxyHook::on_stream_open`], [`ProxyHook::on_stream_header`] and
    /// [`ProxyHook::on_stream_end`] for one stream, unique for the
    /// session's lifetime, and never reused.
    ///
    /// **Not** [`Self::stream_id`]: that is the transport id, which is the
    /// constant `0` on every WebTransport stream, so keying on it would
    /// collapse every WT stream of a side onto one entry and make
    /// `SerializeAfter` attach a stream to an arbitrary sibling — or to
    /// itself, which is a self-deadlock that degrades to a `max_hold`
    /// stall. See [`StreamKey`].
    #[must_use]
    pub fn key(&self) -> StreamKey {
        self.key
    }
}

impl<'a> ObjectCtx<'a> {
    /// Build a context. Field order matches the struct.
    pub fn new(
        session_id: SessionId,
        side: ProxySide,
        stream_id: u64,
        meta: &'a ObjectMeta,
        arrived_at: Instant,
        caps: &'a Capabilities,
    ) -> Self {
        Self { session_id, side, stream_id, meta, arrived_at, caps }
    }
}

/// Decide what happens to frames, objects, datagrams and streams.
///
/// Every method is synchronous and defaulted, so `Arc<dyn ProxyHook>` stays
/// dyn-compatible and an observing-only implementation is
/// `impl ProxyHook for MyHook {}`. There is no `async fn` in the trait and
/// no `async-trait` dependency. Cases that genuinely need to await an
/// external signal use [`Action::Hold`], so a hook never stalls a read
/// loop: timing is expressed as data and executed by the engine, where it
/// is precise, attributable and bounded.
pub trait ProxyHook: Send + Sync {
    /// What this hook wants the proxy to parse.
    ///
    /// Sampled **once**, at session start, and cached. [`Interest::NONE`]
    /// keeps the zero-parse byte-pump path bit-for-bit on all three
    /// forwarding paths.
    fn interest(&self) -> Interest {
        Interest::NONE
    }

    /// Called before forwarding a control message.
    ///
    /// Fires only when [`Interest::CONTROL`] is set: without it the control
    /// stream takes the forward-first path, where the bytes are already in
    /// flight by the time they are parsed and a return value would be
    /// unexecutable.
    ///
    /// `raw` is the frame's original wire bytes — type, scope, length
    /// prefix and payload.
    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        Action::Pass
    }

    /// Called after a unidirectional stream is accepted and before the peer
    /// stream is opened. Stream identity only — see [`StreamCtx`].
    ///
    /// Fires only when [`Interest::STREAMS`] is set. Under any other
    /// interest the decision point between `accept_uni()` and
    /// `open_uni()` is not armed and the stream is forwarded. The gate is
    /// spelled out because otherwise it is undefined whether an
    /// `Interest::NONE` session calls a hook method at all: it does not,
    /// on this method or any other.
    fn on_stream_open(&self, _cx: &StreamCtx<'_>) -> StreamAction {
        StreamAction::Open
    }

    /// Called once the data stream's header has been framed and before its
    /// bytes are forwarded.
    ///
    /// This is where track-targeted decisions belong: `header` carries the
    /// track alias, group and publisher priority.
    ///
    /// Fires only when [`Interest::STREAMS`] is set. `STREAMS` includes
    /// [`Interest::OBJECTS`] structurally, so declaring `STREAMS` alone is
    /// sufficient and puts the stream on the framed path — which it must
    /// be, because there is no header without framing. Declaring
    /// `OBJECTS` alone frames the stream but does **not** call this
    /// method.
    fn on_stream_header(
        &self,
        _cx: &StreamCtx<'_>,
        _header: &DataStreamHeaderKind,
    ) -> StreamAction {
        StreamAction::Open
    }

    /// Called before forwarding one complete object.
    ///
    /// Fires only when [`Interest::OBJECTS`] is set (and therefore also
    /// under [`Interest::STREAMS`], which includes it). Attaching an
    /// event observer does **not** turn this on: an observer makes the
    /// proxy *frame* objects, so that
    /// [`ProxyEvent::Object`](crate::event::ProxyEvent::Object) can fire,
    /// but a hook that declared no object interest is never asked and
    /// never has a returned `Action` honoured. Framing and consulting the
    /// hook are separate decisions.
    ///
    /// `raw` is the object's exact wire bytes as they will be forwarded,
    /// framing and payload; `cx.meta.payload_len` bytes at the end of it
    /// are the payload. [`Action::ReplacePayload`] replaces that trailing
    /// region.
    /// *As they will be forwarded* is load-bearing after an elide: when a
    /// previous object on this stream was elided on a delta-encoding draft, the
    /// framer has already rewritten this object's leading Object ID varint, so
    /// `raw` is what goes on the wire and `raw.len() - cx.meta.payload_len` is
    /// still the payload offset. `cx.meta.object_id` is the absolute ID either
    /// way.
    ///
    /// Not called for objects the framer could not address: an object
    /// larger than
    /// [`FramerConfig::max_buffered_object_bytes`](crate::framer::FramerConfig::max_buffered_object_bytes),
    /// or any object on a stream the framer has stopped parsing. Those are
    /// reported as
    /// [`ProxyEvent::Impairment`](crate::event::ProxyEvent::Impairment)
    /// instead, so "nothing matched" and "never parsed" are
    /// distinguishable.
    fn on_object(&self, _cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        Action::Pass
    }

    /// Called before forwarding a datagram.
    ///
    /// Fires only when [`Interest::DATAGRAMS`] is set.
    ///
    /// `header` is `None` when the datagram's header did not decode. The
    /// hook is still called, so [`Action::Drop`] on malformed traffic is
    /// expressible. `raw` is the whole datagram.
    ///
    /// [`Action::ReplacePayload`] is available here only when the
    /// payload's start is derivable: not on draft-14, whose
    /// [`AnyDatagramHeader`] decode consumes the payload; not on a status
    /// datagram, which has no payload slot; and not when `header` is
    /// `None`. In those three cases it is refused with
    /// [`Refusal::PayloadNotDelimited`](crate::capability::Refusal::PayloadNotDelimited)
    /// and the datagram is forwarded unchanged. `cx.caps` answers this
    /// before you ask for it.
    fn on_datagram(
        &self,
        _cx: &FrameCtx<'_>,
        _header: Option<&AnyDatagramHeader>,
        _raw: &[u8],
    ) -> Action {
        Action::Pass
    }

    /// Called when a forwarded stream ends, for any reason.
    ///
    /// Fires when [`Interest::STREAMS`] is set, on data streams **and** on
    /// the control stream — `cx.is_control_stream` says which rules apply,
    /// and it must, because [`Action::ResetStream`] is illegal on a control
    /// stream on every draft and is refused there with
    /// [`Refusal::ControlStreamResetIllegal`](crate::capability::Refusal::ControlStreamResetIllegal).
    /// On drafts 17-19 that flag is also `true` for a bidirectional request
    /// stream, which runs under the same rules; see
    /// [`StreamCtx::is_control_stream`] for why and for what it costs.
    ///
    /// Three actions are honoured here: [`Action::Pass`],
    /// [`Action::ResetStream`] (data streams only) and
    /// [`Action::CloseSession`] (both, because a close is session-scoped
    /// and no site can be the wrong one for it — it is the documented
    /// escalation for a control stream, where a reset is a protocol
    /// violation). Everything else is refused with
    /// [`Refusal::WrongSite`](crate::capability::Refusal::WrongSite). To
    /// delay a stream's end, delay its last object.
    fn on_stream_end(&self, _cx: &StreamCtx<'_>, _end: StreamEnd) -> Action {
        Action::Pass
    }
}

/// A no-op hook that passes all frames through unchanged.
pub struct NoOpHook;

impl ProxyHook for NoOpHook {}

/// The 0.3.x hook shape, kept so existing implementations still compile.
///
/// Implement [`ProxyHook`] directly for new code; wrap an existing
/// implementation in [`LegacyHook`] to migrate without rewriting it.
#[deprecated(since = "0.4.0", note = "implement ProxyHook directly; wrap in LegacyHook to migrate")]
pub trait LegacyProxyHook: Send + Sync {
    /// Whether this hook may rewrite control messages.
    fn wants_control_mutation(&self) -> bool {
        false
    }
    /// Called before forwarding a control message.
    fn on_control_message(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _message: &AnyControlMessage,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        None
    }
    /// Called before forwarding a datagram.
    fn on_datagram(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _header: &AnyDatagramHeader,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        None
    }
}

/// Adapts a [`LegacyProxyHook`] to [`ProxyHook`], preserving 0.3.x
/// semantics exactly.
///
/// Three behaviours are preserved deliberately:
///
/// * [`Self::interest`] yields `DATAGRAMS`, plus `CONTROL` only when the
///   wrapped hook's `wants_control_mutation()` is `true`. `DATAGRAMS` is
///   unconditional because the 0.3.x datagram hook was the datagram hook,
///   and dropping the flag would stop datagram rewriting for anyone who had
///   it.
/// * A control `Some(bytes)` returned by a hook whose
///   `wants_control_mutation()` is `false` is **discarded**, as it was in
///   0.3.x. Mapping it to [`Action::Replace`] unconditionally would make an
///   observe-only hook that returns `Some(..)` out of sloppiness start
///   rewriting production traffic — source-compatible, compiling, and
///   semantically inverted.
/// * `on_datagram` returns [`Action::Pass`] when the header did not decode,
///   because 0.3.x never called the hook in that case.
///
/// One behaviour **changes**, and it is a change rather than a fix: in
/// 0.3.x `on_datagram` was unreachable unless an observer was attached. It
/// now fires regardless.
#[allow(deprecated)]
pub struct LegacyHook(pub Arc<dyn LegacyProxyHook>);

#[allow(deprecated)]
impl ProxyHook for LegacyHook {
    fn interest(&self) -> Interest {
        if self.0.wants_control_mutation() {
            Interest::DATAGRAMS | Interest::CONTROL
        } else {
            Interest::DATAGRAMS
        }
    }

    fn on_control_message(&self, cx: &FrameCtx<'_>, msg: &AnyControlMessage, raw: &[u8]) -> Action {
        // Called unconditionally, as 0.3.x did: the 0.3.x pass-through
        // control pipe invoked the hook for observation and threw the
        // return away. The `wants_control_mutation()` test is on the
        // *replacement*, not on the call.
        let replacement = self.0.on_control_message(cx.session_id, cx.side, msg, raw);
        match replacement {
            Some(bytes) if self.0.wants_control_mutation() => Action::Replace(Bytes::from(bytes)),
            _ => Action::Pass,
        }
    }

    fn on_datagram(
        &self,
        cx: &FrameCtx<'_>,
        header: Option<&AnyDatagramHeader>,
        raw: &[u8],
    ) -> Action {
        // 0.3.x sat inside `if let Ok(header) = AnyDatagramHeader::decode`
        // and was never reached for an undecodable datagram.
        let Some(header) = header else {
            return Action::Pass;
        };
        match self.0.on_datagram(cx.session_id, cx.side, header, raw) {
            Some(bytes) => Action::Replace(Bytes::from(bytes)),
            None => Action::Pass,
        }
    }
}

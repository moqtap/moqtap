//! Byte-exact object framing for MoQT data streams.
//!
//! [`ObjectFramer`] turns the raw bytes of one unidirectional data stream
//! into individually addressable objects without altering them: every item
//! it yields is a slice of the bytes that were fed in, and concatenating
//! those items reproduces the stream exactly.
//!
//! Framing is opt-in because it costs latency and memory — an object is
//! only emitted once it is buffered whole. The proxy pays that cost only
//! when something is observing; see `session::pipe_data`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes, BytesMut};

use moqtap_codec::dispatch::{
    reemit_subgroup_object, AnyFetchFrame, AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectMeta,
    AnyFetchObjectReader, AnyFetchObjectWriter, AnySubgroupHeader, AnySubgroupObjectMeta,
    AnySubgroupObjectReader, FetchReemit,
};
use moqtap_codec::version::DraftVersion;

use crate::capability::fetch_group_order_is_needed;
use crate::event::DataStreamHeaderKind;
use crate::instrument::Recorder;
use crate::parser::data::is_incomplete_error;
use crate::types::DataStreamType;

pub use crate::types::{BypassReason, ObjectMeta};

/// Every fetch this session has learned a Group Order for, keyed by the
/// Request ID that names it on both the control plane and the data stream.
///
/// # Why a fetch stream needs something from outside itself
///
/// Drafts 18 and 19 write a fetch Object's Group ID as a difference from the
/// Object before it, and the fetch's Group Order decides whether the
/// difference counts up or down — draft-19 Section 11.4.4.1. Nothing on the
/// data stream states the order, so a framer handed only the stream cannot
/// reach an absolute Group ID, and the wrong choice decodes every Object
/// without an error under Group IDs walking the wrong way.
///
/// The order is on the FETCH. Draft-19 Section 10.12.3: "The publisher
/// responding to a FETCH is responsible for delivering all available Objects
/// in the requested range in the requested order (see Section 10.2.8)." The
/// session's control pipes read it off each FETCH they carry and file it
/// here; [`ObjectFramer`] takes it out again when the response stream opens.
///
/// # Why an entry is taken rather than read
///
/// One FETCH opens one response stream, so an entry has exactly one reader
/// and is spent by it. Taking bounds the table to the fetches that have been
/// asked for and not yet answered, on a session that may run for hours, and
/// it needs no rule about when to forget: the reader is the rule.
///
/// What that leaves is a fetch the publisher answered with an error rather
/// than a stream, whose entry no reader ever comes for. A cap is the
/// bound on those, and it fails closed — past it nothing is recorded, so the
/// affected streams are bypassed and say so rather than being read against
/// somebody else's order.
#[derive(Debug, Default)]
pub struct FetchGroupOrders {
    known: Mutex<HashMap<u64, AnyFetchGroupOrder>>,
}

impl FetchGroupOrders {
    /// How many asked-for-but-unanswered fetches one session may hold.
    ///
    /// Reached only by a peer that sends FETCHes whose responses never open a
    /// stream, since every answered one takes its own entry away again.
    const CAP: usize = 1024;

    /// File the order a FETCH asked for, under the Request ID it asked under.
    ///
    /// Call with the order the *peer will act on*, which on a session whose
    /// control frames a hook may rewrite is the one leaving the proxy rather
    /// than the one that arrived.
    pub fn record(&self, request_id: u64, order: AnyFetchGroupOrder) {
        let mut known = self.known.lock().expect("no task holds the fetch orders across a panic");
        if known.len() >= Self::CAP && !known.contains_key(&request_id) {
            return;
        }
        known.insert(request_id, order);
    }

    /// Take the order filed for `request_id`, if one was.
    #[must_use]
    pub fn take(&self, request_id: u64) -> Option<AnyFetchGroupOrder> {
        self.known
            .lock()
            .expect("no task holds the fetch orders across a panic")
            .remove(&request_id)
    }
}

/// Padding width that puts every wire length a varint can express within
/// measuring reach.
///
/// Half of `usize::MAX`, so adding the buffered bytes cannot overflow
/// [`PaddedBuf::remaining`]; a varint tops out at `2^62 - 1`, well inside
/// it on a 64-bit target.
const UNBOUNDED_MEASURING_PAD: usize = usize::MAX / 2;

/// Configuration for [`ObjectFramer`].
///
/// Construct with [`FramerConfig::default`] and adjust fields, or with
/// [`FramerConfig::new`] and the builder setters. The struct is
/// `#[non_exhaustive]` so later releases can add knobs without a break;
/// that also means a struct literal no longer compiles from outside this
/// crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FramerConfig {
    /// Largest object the framer will buffer whole, in bytes. Objects
    /// larger than this are streamed through as
    /// [`FramerOut::Passthrough`] and are not individually addressable.
    /// Default 4 MiB.
    pub max_buffered_object_bytes: usize,
}

impl Default for FramerConfig {
    fn default() -> Self {
        Self { max_buffered_object_bytes: 4 * 1024 * 1024 }
    }
}

impl FramerConfig {
    /// A config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the largest object the framer will buffer whole.
    #[must_use]
    pub fn with_max_buffered_object_bytes(mut self, bytes: usize) -> Self {
        self.max_buffered_object_bytes = bytes;
        self
    }
}

/// One item produced by [`ObjectFramer::poll`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FramerOut {
    /// The stream's header, with its exact wire bytes (stream-type field
    /// included).
    Header {
        /// The decoded header.
        header: DataStreamHeaderKind,
        /// The header's wire bytes, including the stream-type field.
        raw: Bytes,
    },
    /// A complete object, with its exact wire bytes.
    Object {
        /// The object's framing, without its payload.
        meta: ObjectMeta,
        /// The object's complete wire bytes, framing and payload.
        raw: Bytes,
    },
    /// Bytes the framer is forwarding without interpreting them: an object
    /// larger than the buffer cap, a fetch stream on a draft whose fetch
    /// objects are not addressed, or any stream the framer has stopped
    /// parsing. These bytes are not individually addressable.
    Passthrough(Bytes),
    /// The framer has stopped parsing this stream.
    ///
    /// Carries **no bytes**, so [`ObjectFramer::poll`]'s concatenation
    /// invariant is untouched: this item contributes nothing to the
    /// reconstruction. Emitted exactly once per stream.
    ///
    /// **Ordering: immediately after the item the bypass was decided
    /// during, not in place of it.** Every one of `latch_bypass`'s call
    /// sites returns a *different* `FramerOut` from the same `poll()` —
    /// the two header sites fall through to [`Self::Header`], the
    /// measuring-reach sites return [`Self::Passthrough`], the decode and
    /// fix-up sites return [`Self::Error`] — and `poll()` returns one
    /// item. The variant is therefore **deferred**: `latch_bypass` stores
    /// a `pending_bypass: Option<BypassReason>`, and `poll()` drains it at
    /// the top of its next call, before anything else.
    Bypassed {
        /// Why parsing stopped.
        reason: BypassReason,
        /// Whether an elide fix-up was still owed when parsing stopped.
        ///
        /// `true` means the remainder of this stream cannot be renumbered
        /// and the destination must be reset rather than forwarded — the
        /// bytes still in flight decode to Object IDs one ahead of what
        /// was actually delivered.
        fixup_owed: bool,
    },
    /// Not enough buffered bytes to produce another item.
    NeedMore,
    /// The stream could not be parsed. The framer switches to
    /// [`Passthrough`](Self::Passthrough) for the remainder of the stream
    /// and never reports a second error.
    Error(String),
}

/// The state an elide leaves behind on a subgroup stream.
///
/// Read it with [`ObjectFramer::elide_cursor`]. The framer owns this state
/// rather than the caller because it forwards objects the caller never
/// sees an [`ObjectMeta`] for — an object one byte over
/// [`FramerConfig::max_buffered_object_bytes`] leaves as
/// [`FramerOut::Passthrough`], and a cursor kept outside the framer would
/// let its stale delta go out on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElideCursor {
    /// Absolute Object ID of the last object actually forwarded, or `None`
    /// when none has been.
    pub last_forwarded_id: Option<u64>,
    /// Whether the next object the framer emits will have its leading ID
    /// field rewritten. Always `false` on drafts 07-13, where IDs are
    /// absolute, and on fetch streams.
    pub fixup_pending: bool,
}

/// The object the framer emitted most recently, whose forward-or-elide
/// disposition has not been committed to the cursor yet.
#[derive(Debug, Clone, Copy)]
struct PendingObject {
    object_id: u64,
    index_in_stream: u64,
}

/// Identity fields the stream header contributes to every object on a
/// subgroup stream.
#[derive(Debug, Clone, Copy, Default)]
struct SubgroupContext {
    track_alias: u64,
    group_id: u64,
    subgroup_id: Option<u64>,
    publisher_priority: Option<u8>,
}

/// What the framer is currently decoding.
#[derive(Debug)]
enum Stage {
    /// Nothing decoded yet; the next bytes are the stream header.
    AwaitingHeader,
    /// Subgroup objects, with the per-stream delta state.
    Subgroup(AnySubgroupObjectReader),
    /// Fetch objects, with the state on both sides of the framer: what the
    /// stream said, and what has actually been forwarded from it.
    ///
    /// The two are the same value until something is elided, and every frame
    /// goes through the writer regardless. A frame it never saw would leave
    /// it a frame behind, and a survivor re-encoded against a stale
    /// predecessor is a renumbered stream rather than a decode error.
    Fetch { reader: AnyFetchObjectReader, writer: AnyFetchObjectWriter },
}

/// Frames a unidirectional MoQT data stream into individually addressable
/// objects while preserving the exact wire bytes.
///
/// Feed it the raw bytes of one stream, in order, from the stream's first
/// byte. Drain [`poll`](Self::poll) after each [`feed`](Self::feed) until
/// it returns [`FramerOut::NeedMore`]. The concatenation of every `raw`
/// and `Passthrough` payload it yields equals the concatenation of every
/// chunk fed to it, unless [`note_elided`](Self::note_elided) has been
/// called — see [`Self::poll`].
#[derive(Debug)]
pub struct ObjectFramer {
    stream_type: DataStreamType,
    draft: DraftVersion,
    config: FramerConfig,
    buf: BytesMut,
    stage: Stage,
    context: SubgroupContext,
    /// Bytes still owed to an oversized object that is being streamed
    /// through uninterpreted. Denominated in **source** bytes — see
    /// [`Self::poll_oversized`].
    passthrough_remaining: u64,
    /// Set once parsing has been abandoned for the rest of the stream.
    bypassed: bool,
    /// Why parsing was abandoned, waiting for [`Self::poll`] to drain it
    /// as a [`FramerOut::Bypassed`].
    ///
    /// `fixup_owed` is read off [`Self::fixup_pending`] at drain time
    /// rather than being captured here, and the two are the same value:
    /// once `bypassed` is set, `poll` never re-enters `poll_object`, which
    /// is the only thing that clears the flag, and no `Object` item can be
    /// emitted between the latch and the drain for `note_elided` to set it.
    pending_bypass: Option<BypassReason>,
    index_in_stream: u64,
    /// Absolute Object ID of the last object actually forwarded.
    last_forwarded_id: Option<u64>,
    /// Whether the next object emitted still owes a fix-up: on a subgroup
    /// stream the leading Object ID varint rewritten against
    /// [`Self::last_forwarded_id`], on a fetch stream a survivor re-encoded
    /// against the frame that is now in front of it.
    ///
    /// Both are settled by emitting one object, after which the writing
    /// cursor is level with the reading one again.
    fixup_pending: bool,
    /// The fetch writer as it stood before the object emitted most recently
    /// was re-emitted through it.
    ///
    /// Re-emitting advances the writer, and the caller's verdict on that
    /// object does not land until the next poll, so an elide has to put the
    /// writer back where it was — otherwise the survivor after it is encoded
    /// against an object nobody received.
    fetch_rollback: Option<AnyFetchObjectWriter>,
    /// The object emitted most recently, awaiting the caller's verdict.
    /// Committed lazily at the top of [`Self::poll_object`].
    pending_disposition: Option<PendingObject>,
    /// Slow-path counters for the session this framer belongs to.
    counters: Arc<Recorder>,
    /// The session's answered fetches, on the drafts where a fetch stream
    /// cannot be read without one. `None` for a framer built outside a
    /// session, and on every draft that needs no order.
    fetch_orders: Option<Arc<FetchGroupOrders>>,
}

impl ObjectFramer {
    /// A framer whose slow-path counters go to `counters`.
    ///
    /// **The only constructor `session.rs` may use.** The counters are
    /// session-scoped, and a framer that cannot reach its session's
    /// [`Recorder`] would leave `framers_created`, `framer_header_polls`,
    /// `framer_object_polls`, `objects_not_addressable` and
    /// `object_ids_rewritten` at zero for every real session — which is a
    /// *passing* `Interest::NONE` proof obtained by measuring nothing.
    ///
    /// [`Self::new`] is kept, unchanged, for tests and downstream callers
    /// that construct a framer to parse bytes rather than to forward them;
    /// it is equivalent to passing a fresh `Recorder` whose counts nobody
    /// reads. That is why this is an **addition** and not a signature
    /// change.
    pub fn with_recorder(
        stream_type: DataStreamType,
        draft: DraftVersion,
        config: FramerConfig,
        counters: Arc<Recorder>,
    ) -> Self {
        counters.note_framer_created();
        Self {
            stream_type,
            draft,
            config,
            buf: BytesMut::with_capacity(4096),
            stage: Stage::AwaitingHeader,
            context: SubgroupContext::default(),
            passthrough_remaining: 0,
            bypassed: false,
            pending_bypass: None,
            index_in_stream: 0,
            last_forwarded_id: None,
            fixup_pending: false,
            fetch_rollback: None,
            pending_disposition: None,
            counters,
            fetch_orders: None,
        }
    }

    /// Read this stream's fetch Objects against the order its FETCH asked for.
    ///
    /// Only drafts 18 and 19 need it — see [`FetchGroupOrders`] — and only a
    /// fetch stream consults it; a subgroup framer given one ignores it. A
    /// framer built without it on a draft that needs one reports
    /// [`BypassReason::FetchGroupOrderUnknown`] and forwards the stream
    /// uninterpreted, which is what every caller outside a session gets and
    /// what the session itself gets for a stream naming a request it never
    /// saw asked for.
    #[must_use]
    pub fn with_fetch_group_orders(mut self, orders: Arc<FetchGroupOrders>) -> Self {
        self.fetch_orders = Some(orders);
        self
    }

    /// Create a framer for a stream of the given kind on the given draft,
    /// discarding its counters.
    ///
    /// Increments go to a private [`Recorder`] nothing can read, so a
    /// caller that wants a session's counters to move must use
    /// [`Self::with_recorder`]. Retained for callers that parse bytes
    /// rather than forward them, where the counts are not the point.
    pub fn new(stream_type: DataStreamType, draft: DraftVersion, config: FramerConfig) -> Self {
        Self::with_recorder(stream_type, draft, config, Arc::new(Recorder::new()))
    }

    /// The state an elide has left behind on this stream.
    ///
    /// Read-only, and read-anytime: the framer applies the fix-up itself,
    /// so nothing outside has to act on this.
    #[must_use]
    pub fn elide_cursor(&self) -> ElideCursor {
        ElideCursor { last_forwarded_id: self.last_forwarded_id, fixup_pending: self.fixup_pending }
    }

    /// Record that the object the framer emitted **most recently** was not
    /// forwarded.
    ///
    /// Call exactly once, immediately after deciding to drop an object,
    /// and before the next [`Self::poll`]. `meta` must be the meta the
    /// framer handed out for that object; it is `debug_assert`ed against
    /// the framer's own record, because calling this out of order is the
    /// one way to corrupt a stream silently.
    ///
    /// On drafts 07-13 subgroup streams and on drafts 07-14 fetch streams
    /// this only suppresses the cursor advance — those Object IDs are
    /// absolute, so the bytes of every later object already say the truth.
    /// Elsewhere it also arms a fix-up: the leading Object ID varint on a
    /// drafts 14-19 subgroup stream, and the whole framing of the next frame
    /// on a drafts 15-19 fetch stream, where it additionally puts the fetch
    /// writer back to where the last forwarded frame left it.
    pub fn note_elided(&mut self, meta: &ObjectMeta) {
        let pending = self.pending_disposition.take();
        debug_assert!(
            matches!(
                pending,
                Some(p) if p.object_id == meta.object_id
                    && p.index_in_stream == meta.index_in_stream
            ),
            "note_elided must name the object the framer emitted most recently; \
             got object {} at index {}, framer holds {:?}",
            meta.object_id,
            meta.index_in_stream,
            pending.map(|p| (p.object_id, p.index_in_stream)),
        );
        // Taking `pending` is the elide: the cursor simply does not
        // advance to it. Arming the fix-up on a `None` would renumber an
        // object whose predecessor was already committed as forwarded.
        if pending.is_none() {
            return;
        }
        if self.elide_owes_a_fixup() {
            self.fixup_pending = true;
        }
        // The frame was re-emitted through the writer before the caller saw
        // it, so the writer is one frame ahead of what the destination
        // received. Nothing else can restore it: the per-draft state is what
        // the *forwarded* frames left behind, and this frame was not one.
        if let Some(rollback) = self.fetch_rollback.take() {
            if let Stage::Fetch { writer, .. } = &mut self.stage {
                *writer = rollback;
            }
        }
    }

    /// Buffer a chunk of stream bytes.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Bytes buffered but not yet emitted. Non-zero only mid-object.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// `true` once the framer has stopped parsing this stream and is
    /// forwarding bytes uninterpreted.
    pub fn is_bypassed(&self) -> bool {
        self.bypassed
    }

    /// Flush any buffered bytes at end of stream.
    ///
    /// Called when the source signals FIN. Returns whatever the framer
    /// still holds — a truncated final object, or bytes buffered behind an
    /// incomplete framing — so the caller can forward them before
    /// finishing the destination stream. Forgetting this call turns a
    /// clean FIN into silent truncation.
    pub fn finish(&mut self) -> Option<Bytes> {
        self.passthrough_remaining = 0;
        if self.buf.is_empty() {
            None
        } else {
            Some(self.buf.split().freeze())
        }
    }

    /// Produce the next item, or [`FramerOut::NeedMore`].
    ///
    /// # Invariant
    ///
    /// Concatenating the `raw` field of every [`Header`](FramerOut::Header)
    /// and [`Object`](FramerOut::Object) and the payload of every
    /// [`Passthrough`](FramerOut::Passthrough), in the order produced,
    /// reproduces the fed bytes exactly — on every draft, including
    /// streams that fall back to bypass — **unless**
    /// [`Self::note_elided`] has been called, which deliberately removes
    /// an object's bytes and may rewrite one leading varint.
    ///
    /// That exception is the *only* one, and it is opt-in per stream: a
    /// framer used as a pure observer never calls `note_elided`, so its
    /// output stays byte-identical to its input. When `note_elided` has
    /// been called on a drafts 14-19 subgroup stream, the next object the
    /// framer emits has its leading Object ID varint re-encoded against
    /// the last object actually forwarded — one field, in one object, and
    /// every byte after it copied verbatim. Everything else, on every
    /// other stream, still concatenates back to the source exactly.
    ///
    /// [`FramerOut::Bypassed`] and [`FramerOut::NeedMore`] carry no bytes
    /// and so contribute nothing to the reconstruction either way.
    pub fn poll(&mut self) -> FramerOut {
        // Drained before anything else. `latch_bypass` cannot return this
        // item itself — each of its call sites returns a different
        // `FramerOut` from the same `poll()` — so the bypass is reported
        // on the next call, immediately after the item it was decided
        // during. Zero bytes, so the invariant above is untouched.
        if let Some(reason) = self.pending_bypass.take() {
            return FramerOut::Bypassed { reason, fixup_owed: self.fixup_pending };
        }
        if self.passthrough_remaining > 0 {
            let owed = self.passthrough_remaining;
            return self.emit_passthrough(owed);
        }
        if self.bypassed {
            return self.emit_passthrough(u64::MAX);
        }
        match self.stage {
            Stage::AwaitingHeader => self.poll_header(),
            Stage::Subgroup(_) | Stage::Fetch { .. } => self.poll_object(),
        }
    }

    /// Hand out up to `limit` buffered bytes without interpreting them.
    fn emit_passthrough(&mut self, limit: u64) -> FramerOut {
        if self.buf.is_empty() {
            return FramerOut::NeedMore;
        }
        let take = usize::try_from(limit).unwrap_or(usize::MAX).min(self.buf.len());
        self.passthrough_remaining = self.passthrough_remaining.saturating_sub(take as u64);
        FramerOut::Passthrough(self.buf.split_to(take).freeze())
    }

    /// Stop parsing this stream for good, record why, and release
    /// everything buffered.
    ///
    /// Draining here is what keeps memory bounded: without it a stream the
    /// framer cannot parse grows the buffer for as long as the peer keeps
    /// writing.
    ///
    /// `reason` is stored rather than returned, because every call site
    /// returns a different [`FramerOut`] from the same
    /// [`poll`](Self::poll); the next `poll` drains it. Guarded on
    /// `bypassed` so a second latch — which today cannot happen, since
    /// `poll` short-circuits once the flag is set — could never overwrite
    /// the first reason or double-count
    /// `Counters::streams_not_shapeable`, whose whole job is to be one per
    /// stream.
    fn latch_bypass(&mut self, reason: BypassReason) {
        if !self.bypassed {
            self.bypassed = true;
            self.pending_bypass = Some(reason);
            self.counters.note_stream_not_shapeable();
        }
        self.passthrough_remaining = 0;
    }

    fn poll_header(&mut self) -> FramerOut {
        self.counters.note_framer_header_poll();
        if self.buf.is_empty() {
            return FramerOut::NeedMore;
        }

        let snapshot: &[u8] = &self.buf[..];
        let mut cursor: &[u8] = snapshot;
        let decoded = match self.stream_type {
            DataStreamType::Subgroup => AnySubgroupHeader::decode_stream(self.draft, &mut cursor)
                .map(DataStreamHeaderKind::Subgroup),
            DataStreamType::Fetch => AnyFetchHeader::decode_stream(self.draft, &mut cursor)
                .map(DataStreamHeaderKind::Fetch),
        };

        match decoded {
            Ok(header) => {
                let consumed = snapshot.len() - cursor.remaining();
                match &header {
                    DataStreamHeaderKind::Subgroup(h) => match AnySubgroupObjectReader::new(h) {
                        Ok(reader) => {
                            self.context = subgroup_context(h);
                            self.stage = Stage::Subgroup(reader);
                        }
                        // A subgroup stream type the object reader
                        // rejects. The header still decoded, so report it,
                        // then forward the rest uninterpreted.
                        Err(_) => self.latch_bypass(BypassReason::UnsupportedSubgroupStreamType),
                    },
                    // Whether this stream's Objects can be addressed is
                    // asked of `fetch_group_order_is_needed` and of the
                    // session's own record of what each FETCH asked for,
                    // rather than inferred from the reader refusing. A codec
                    // able to decode a layout is not on its own enough: on
                    // drafts 18 and 19 it decodes under a Group Order nothing
                    // on this stream states, and the wrong one decodes as
                    // willingly as the right one.
                    DataStreamHeaderKind::Fetch(h) => match self.fetch_stage(h) {
                        Ok(stage) => self.stage = stage,
                        Err(reason) => self.latch_bypass(reason),
                    },
                }
                let raw = self.buf.split_to(consumed).freeze();
                FramerOut::Header { header, raw }
            }
            Err(e) if is_incomplete_error(&e) => {
                if self.buf.len() >= self.config.max_buffered_object_bytes {
                    self.latch_bypass(BypassReason::ObjectBeyondMeasuringReach);
                    self.emit_passthrough(u64::MAX)
                } else {
                    FramerOut::NeedMore
                }
            }
            Err(e) => {
                self.latch_bypass(BypassReason::DecodeError);
                FramerOut::Error(format!("data stream header decode: {e}"))
            }
        }
    }

    /// The reader and writer a fetch stream is parsed with, or why it is not.
    ///
    /// Two drafts need an answer from off the stream and the other eleven do
    /// not, which is [`fetch_group_order_is_needed`]. Where one is needed it
    /// comes from the FETCH the session carried, filed under the Request ID
    /// this header names; a stream naming a request that was never asked for
    /// is bypassed rather than guessed at, because the guess would decode.
    ///
    /// The reader and writer are built with the same order. They are the two
    /// halves of one stream — the writer re-encodes a survivor after an elide
    /// against the frames now in front of it — so a pair built against
    /// different orders would renumber the stream it was meant to preserve.
    fn fetch_stage(&mut self, h: &AnyFetchHeader) -> Result<Stage, BypassReason> {
        let order = if fetch_group_order_is_needed(self.draft) {
            let orders = self.fetch_orders.as_ref().ok_or(BypassReason::FetchGroupOrderUnknown)?;
            Some(orders.take(h.request_id()).ok_or(BypassReason::FetchGroupOrderUnknown)?)
        } else {
            None
        };
        // Ascending where the draft needs no answer: the branch above supplies
        // one for every draft that does, so the fallback is only ever reached
        // where nothing on the stream is signed and the value cannot be wrong.
        let order = order.unwrap_or(AnyFetchGroupOrder::Ascending);
        let built = (AnyFetchObjectReader::new(h, order), AnyFetchObjectWriter::new(h, order));
        match built {
            (Ok(reader), Ok(writer)) => Ok(Stage::Fetch { reader, writer }),
            // A draft this build did not compile. Not an error — the stream
            // is simply not addressable. The header decode above would
            // already have failed on such a draft, so this is a second line
            // rather than the first.
            _ => Err(BypassReason::NoFetchObjectCodec),
        }
    }

    fn poll_object(&mut self) -> FramerOut {
        self.counters.note_framer_object_poll();

        // Lazy commit, once, here. The pipe loop is sequential — the
        // caller's verdict on object *N* always lands before `poll`
        // produces object *N+1* — so an object still pending at the top of
        // this call was forwarded. `poll_oversized` deliberately does
        // **not** repeat this: it is only ever reached from inside this
        // function, and a second commit would consume a disposition this
        // one already took. If it ever gains an entry path of its own,
        // make the commit idempotent rather than adding a second site.
        self.commit_disposition();

        if self.buf.is_empty() {
            return FramerOut::NeedMore;
        }

        let snapshot: &[u8] = &self.buf[..];
        let mut cursor: &[u8] = snapshot;

        // Probe against a clone: a reader mutated before the object is
        // known to be complete carries a corrupt delta state into every
        // later object on the stream.
        let probed = match &self.stage {
            Stage::Subgroup(reader) => {
                let mut probe = reader.clone();
                probe
                    .read_object_meta(&mut cursor)
                    .map(|m| (Probe::Subgroup(probe), Meta::Sub(m), None))
            }
            // `read_object_frame` rather than `read_object_meta`: it reports
            // the same framing and additionally keeps the shape the frame
            // arrived in, which is what re-encoding it against a different
            // predecessor takes.
            Stage::Fetch { reader, .. } => {
                let mut probe = reader.clone();
                probe
                    .read_object_frame(&mut cursor)
                    .map(|frame| (Probe::Fetch(probe), Meta::Fetch(frame.meta), Some(frame)))
            }
            Stage::AwaitingHeader => return FramerOut::NeedMore,
        };

        match probed {
            Ok((probe, meta, frame)) => {
                let consumed = snapshot.len() - cursor.remaining();
                let object_id = meta.object_id();
                // Before the source bytes are split off, so a failure
                // leaves them in the buffer for the bypassed poll that
                // follows to forward verbatim rather than dropping them.
                let rewritten = match self.apply_elide_fixup(consumed, object_id, frame.as_ref()) {
                    Ok(rewritten) => rewritten,
                    Err(e) => {
                        self.latch_bypass(BypassReason::DecodeError);
                        return FramerOut::Error(e);
                    }
                };
                let source = self.buf.split_to(consumed).freeze();
                let raw = rewritten.unwrap_or(source);
                self.commit(probe);
                // An object that arrives in one read completes before
                // buffering ever reaches the cap, so the incomplete-decode
                // path below never sees it. Judging it by its own wire
                // length too is what makes the cap a property of the object
                // rather than of the caller's read size. Judged on the
                // *source* length, so an elide fix-up that widens the ID
                // varint cannot move an object across the boundary.
                let out = if consumed > self.config.max_buffered_object_bytes {
                    // A `Passthrough` that is a whole object: the meta was
                    // decoded and is about to be discarded, so nothing
                    // outside the framer can address it.
                    self.counters.note_object_not_addressable();
                    FramerOut::Passthrough(raw)
                } else {
                    FramerOut::Object { meta: self.object_meta(meta), raw }
                };
                // Both branches emitted an object, so both arm the cursor:
                // the oversized one has no `ObjectMeta` for the caller to
                // name, which is exactly why the framer keeps the record.
                self.pending_disposition =
                    Some(PendingObject { object_id, index_in_stream: self.index_in_stream });
                self.index_in_stream += 1;
                out
            }
            Err(e) if is_incomplete_error(&e) => {
                if self.buf.len() < self.config.max_buffered_object_bytes {
                    FramerOut::NeedMore
                } else {
                    self.poll_oversized()
                }
            }
            Err(e) => {
                self.latch_bypass(BypassReason::DecodeError);
                FramerOut::Error(format!("object decode: {e}"))
            }
        }
    }

    /// The buffer hit its cap without completing an object. Decide whether
    /// the object's *framing* is understood — in which case its bytes can
    /// be streamed through and framing resumes afterwards — or whether the
    /// stream has to be abandoned.
    ///
    /// The framing is read against the buffered bytes followed by padding,
    /// so the decoder can advance past a payload that has not arrived. How
    /// wide that padding may be is [`Self::measuring_pad`]'s call.
    fn poll_oversized(&mut self) -> FramerOut {
        let pad = self.measuring_pad();
        let mut padded = PaddedBuf::new(&self.buf[..], pad);
        let probed = match &self.stage {
            Stage::Subgroup(reader) => {
                let mut probe = reader.clone();
                probe.read_object_meta(&mut padded).map(|m| {
                    (Probe::Subgroup(probe), m.object_id, m.wire_len, m.payload_length, None)
                })
            }
            Stage::Fetch { reader, .. } => {
                let mut probe = reader.clone();
                probe.read_object_frame(&mut padded).map(|frame| {
                    let meta = frame.meta;
                    (
                        Probe::Fetch(probe),
                        meta.object_id,
                        meta.wire_len,
                        meta.payload_length,
                        Some(frame),
                    )
                })
            }
            Stage::AwaitingHeader => return FramerOut::NeedMore,
        };

        let Ok((probe, object_id, wire_len, payload_length, frame)) = probed else {
            self.latch_bypass(BypassReason::ObjectBeyondMeasuringReach);
            return self.emit_passthrough(u64::MAX);
        };

        // Only trust the framing when every field ahead of the payload
        // came from real bytes rather than padding.
        let framing_len = wire_len - payload_length;
        let buffered = self.buf.len() as u64;
        if framing_len > buffered || wire_len <= buffered {
            self.latch_bypass(BypassReason::ObjectBeyondMeasuringReach);
            return self.emit_passthrough(u64::MAX);
        }

        // `framing_len <= buffered` is what makes the fix-up reachable
        // here: the whole framing, leading Object ID varint included, is
        // in the chunk about to be emitted. The chunk is a *prefix* of the
        // object, which `reemit_subgroup_object` accepts — it decodes the
        // ID field and copies the rest verbatim without validating any
        // length.
        let chunk = self.buf.len();
        let rewritten = match self.apply_elide_fixup(chunk, object_id, frame.as_ref()) {
            Ok(rewritten) => rewritten,
            Err(e) => {
                self.latch_bypass(BypassReason::DecodeError);
                return FramerOut::Error(e);
            }
        };

        self.commit(probe);
        // The second `Passthrough`-as-an-object path. Counted once here,
        // not once per emitted chunk: this function is entered once per
        // oversized object, and the chunks that follow come from `poll`'s
        // `passthrough_remaining` branch.
        self.counters.note_object_not_addressable();
        // Denominated in **source** bytes, and deliberately not adjusted
        // by the fix-up's `id_bytes_after - id_bytes_before`. Its job is
        // to say how many more bytes of the *incoming* stream belong to
        // this object; the emitted stream is a byte or two shorter or
        // longer for exactly one object, which is what an elide fix-up is.
        // Correcting it here would make the framer stop consuming this
        // object early or late and resynchronise mid-way through the next
        // one — a silent corruption that only fires when the new delta
        // needs a wider varint.
        self.passthrough_remaining = wire_len - buffered;
        self.pending_disposition =
            Some(PendingObject { object_id, index_in_stream: self.index_in_stream });
        self.index_in_stream += 1;
        let source = self.buf.split().freeze();
        FramerOut::Passthrough(rewritten.unwrap_or(source))
    }

    /// Commit the disposition of the object emitted most recently.
    ///
    /// An object still pending was forwarded; one the caller elided was
    /// taken out of `pending_disposition` by [`Self::note_elided`], so the
    /// cursor never advances to it.
    fn commit_disposition(&mut self) {
        if let Some(pending) = self.pending_disposition.take() {
            self.last_forwarded_id = Some(pending.object_id);
            // Forwarded, so the writer's advance stands and there is nothing
            // to put back. Cleared rather than left for the next re-emit to
            // overwrite, so that a rollback can only ever undo the frame it
            // was taken for.
            self.fetch_rollback = None;
        }
    }

    /// `true` when this stream's Object IDs are written as `id - prev - 1`
    /// rather than absolutely, so eliding one renumbers every later object.
    ///
    /// Subgroup streams on drafts 14-19, and no fetch stream on any draft:
    /// this is the predicate for the *varint rewrite*, and a fetch frame is
    /// paid for by [`Self::reemit_fetch_frame`] instead. Drafts 07-13 write
    /// subgroup Object IDs absolutely and need neither.
    fn delta_encodes_object_ids(&self) -> bool {
        matches!(self.stream_type, DataStreamType::Subgroup)
            && matches!(
                self.draft,
                DraftVersion::Draft14
                    | DraftVersion::Draft15
                    | DraftVersion::Draft16
                    | DraftVersion::Draft17
                    | DraftVersion::Draft18
                    | DraftVersion::Draft19
            )
    }

    /// `true` when eliding an object from this stream leaves the next one
    /// encoded against something that is no longer on the wire, so a fix-up
    /// is owed before another object may be forwarded.
    ///
    /// The two stream kinds owe it for different reasons and pay it in
    /// different ways, and the debt itself is the same: until one more object
    /// has been emitted, the bytes the destination would receive decode to
    /// Locations nobody sent. `fixup_owed` on a `Bypassed` is what a session
    /// resets its destination over, and it reads this.
    ///
    /// Fetch streams on drafts 15-19, where a Serialization Flags field lets
    /// a frame take any of its Group ID, Subgroup ID, Object ID and Priority
    /// from the frame before it — draft-17 Section 10.4.4.1, Table 7: "Object
    /// ID is the prior Object's ID plus one". Not drafts 07-14, whose fetch
    /// objects state all four outright.
    fn elide_owes_a_fixup(&self) -> bool {
        match self.stream_type {
            DataStreamType::Subgroup => self.delta_encodes_object_ids(),
            DataStreamType::Fetch => matches!(
                self.draft,
                DraftVersion::Draft15
                    | DraftVersion::Draft16
                    | DraftVersion::Draft17
                    | DraftVersion::Draft18
                    | DraftVersion::Draft19
            ),
        }
    }

    /// Rewrite the leading Object ID varint of `self.buf[..len]` when an
    /// elide has left the wire's delta chain one object ahead of what was
    /// actually forwarded.
    ///
    /// `len` may be a prefix of the object rather than the whole of it —
    /// the oversized path calls this with the first chunk. Returns
    /// `Ok(None)` when no fix-up was owed, in which case the caller emits
    /// the source bytes untouched; the borrow of `self.buf` ends before
    /// this returns, so the caller is free to split it afterwards.
    ///
    /// The error is unreachable in practice — Object IDs are strictly
    /// increasing within a stream and the caller has already established
    /// that the ID field is whole in the buffer — but it is reported
    /// rather than swallowed, because the alternative is emitting bytes
    /// known to decode to the wrong ID.
    fn apply_elide_fixup(
        &mut self,
        len: usize,
        object_id: u64,
        frame: Option<&AnyFetchFrame>,
    ) -> Result<Option<Bytes>, String> {
        // `frame` is `Some` exactly on a fetch stream, where the payment is a
        // re-encode of the whole framing rather than a rewrite of one varint,
        // and where it is the writer rather than a flag that decides whether
        // anything is owed.
        if let Some(frame) = frame {
            return self.reemit_fetch_frame(len, frame);
        }
        if !self.fixup_pending || !self.delta_encodes_object_ids() {
            return Ok(None);
        }
        let mut out = BytesMut::with_capacity(len + 8);
        let outcome = reemit_subgroup_object(
            self.draft,
            self.last_forwarded_id,
            object_id,
            &self.buf[..len],
            &mut out,
        );
        if let Err(e) = outcome {
            // Leaves `fixup_pending` set, so the cursor keeps reporting
            // that this stream still owes a fix-up.
            return Err(format!("elide fix-up: {e}"));
        }
        self.fixup_pending = false;
        self.counters.note_object_id_rewritten();
        Ok(Some(out.freeze()))
    }

    /// Re-emit one fetch frame through this stream's writer.
    ///
    /// Called for **every** fetch frame the framer emits, not only after an
    /// elide. The writer is what a survivor is re-encoded against, and it
    /// only moves when it is shown a frame, so skipping the frames nothing
    /// was owed for would leave it as many frames behind as were skipped.
    ///
    /// Answers `Ok(None)` when the frame's own bytes still say what the frame
    /// says, which is every frame on a stream nothing has been removed from.
    /// The writer is cloned first so that [`Self::note_elided`] can put it
    /// back: this runs before the caller's verdict on the frame, and a frame
    /// the caller drops must leave no trace on the writing side.
    ///
    /// `len` may be a prefix of the frame — the oversized path calls this
    /// with the first chunk — and the codec asks only that the whole framing
    /// be inside it, which is what the caller has already established.
    fn reemit_fetch_frame(
        &mut self,
        len: usize,
        frame: &AnyFetchFrame,
    ) -> Result<Option<Bytes>, String> {
        let mut out = BytesMut::with_capacity(len + 16);
        let (outcome, rollback) = {
            let Stage::Fetch { writer, .. } = &mut self.stage else {
                return Ok(None);
            };
            let rollback = writer.clone();
            (writer.reemit_object(frame, &self.buf[..len], &mut out), rollback)
        };
        self.fetch_rollback = Some(rollback);

        match outcome {
            Ok(FetchReemit::Unchanged) => {
                // The debt such as it was is settled either way. A removal
                // whose survivor happened to state every field it needed
                // costs nothing, and leaving the flag set would have the
                // stream report an unpaid fix-up at every later bypass.
                self.fixup_pending = false;
                Ok(None)
            }
            Ok(FetchReemit::Reframed { .. }) => {
                self.fixup_pending = false;
                self.counters.note_object_id_rewritten();
                Ok(Some(out.freeze()))
            }
            // Leaves `fixup_pending` set, as the subgroup path does, so the
            // stream keeps reporting that it still owes one.
            Err(e) => Err(format!("elide fix-up: {e}")),
        }
    }

    /// How much padding [`Self::poll_oversized`] may put behind the
    /// buffered bytes when measuring an object that has not arrived whole.
    ///
    /// The pad costs no memory by itself — it is never materialised — but
    /// every copying read in the codec checks `Buf::remaining()` before it
    /// allocates, so the pad is exactly the bound on the allocation a
    /// hostile length field can provoke. That makes the choice per layout
    /// rather than global:
    ///
    /// * Subgroup objects on drafts 14-19, and fetch objects on draft-14,
    ///   are measured without a single copy — their `read_object_meta`
    ///   advances past the extension block and the payload rather than
    ///   reading them. Nothing can be talked into allocating, so the pad is
    ///   effectively unbounded and an object of *any* declared size stays
    ///   measurable: it streams through and framing resumes after it.
    /// * Every older object layout decodes its extension block by copying
    ///   it out of the buffer. Those keep a pad of one cap, which bounds
    ///   the copy at the price of reach: an object whose wire length
    ///   exceeds `buffered + cap` cannot be measured and the stream falls
    ///   back to passthrough for its remainder.
    ///
    /// Widening the second case needs the codec to reject an extension
    /// length larger than the bytes actually present, which is not this
    /// crate's to change.
    fn measuring_pad(&self) -> usize {
        let copy_free = match self.stage {
            Stage::Subgroup(_) => matches!(
                self.draft,
                DraftVersion::Draft14
                    | DraftVersion::Draft15
                    | DraftVersion::Draft16
                    | DraftVersion::Draft17
                    | DraftVersion::Draft18
                    | DraftVersion::Draft19
            ),
            Stage::Fetch { .. } => matches!(self.draft, DraftVersion::Draft14),
            Stage::AwaitingHeader => false,
        };
        if copy_free {
            UNBOUNDED_MEASURING_PAD
        } else {
            self.config.max_buffered_object_bytes
        }
    }

    /// Adopt a probe reader whose decode succeeded.
    fn commit(&mut self, probe: Probe) {
        match (&mut self.stage, probe) {
            (Stage::Subgroup(reader), Probe::Subgroup(probe)) => *reader = probe,
            (Stage::Fetch { reader, .. }, Probe::Fetch(probe)) => *reader = probe,
            // `probe` was cloned from `stage` a few lines earlier, so the
            // pairing always matches.
            _ => {}
        }
    }

    fn object_meta(&self, meta: Meta) -> ObjectMeta {
        match meta {
            Meta::Sub(m) => ObjectMeta {
                draft: self.draft,
                stream_kind: DataStreamType::Subgroup,
                track_alias: Some(self.context.track_alias),
                group_id: self.context.group_id,
                subgroup_id: self.context.subgroup_id,
                object_id: m.object_id,
                publisher_priority: self.context.publisher_priority,
                index_in_stream: self.index_in_stream,
                payload_len: m.payload_length,
                status: m.status,
                end_of_range: None,
            },
            Meta::Fetch(m) => ObjectMeta {
                draft: self.draft,
                stream_kind: DataStreamType::Fetch,
                track_alias: None,
                group_id: m.group_id,
                // Not `Some(m.subgroup_id)`: from draft-15 a fetch frame
                // may carry no Subgroup ID at all — an object forwarded
                // over a datagram has no subgroup, and an End of Range
                // indicator names a Location rather than an object — and
                // the codec leaves a placeholder in the field when it says
                // so. Forwarding that placeholder would key a matcher on a
                // subgroup the publisher never named.
                subgroup_id: m.has_subgroup_id.then_some(m.subgroup_id),
                object_id: m.object_id,
                publisher_priority: Some(m.publisher_priority),
                index_in_stream: self.index_in_stream,
                payload_len: m.payload_length,
                status: m.status,
                end_of_range: m.end_of_range,
            },
        }
    }
}

/// A reader clone whose decode succeeded and is ready to be adopted.
enum Probe {
    Subgroup(AnySubgroupObjectReader),
    Fetch(AnyFetchObjectReader),
}

/// The codec-level framing of one object, either stream kind.
#[derive(Clone, Copy)]
enum Meta {
    Sub(AnySubgroupObjectMeta),
    Fetch(AnyFetchObjectMeta),
}

impl Meta {
    /// The object's absolute Object ID, delta encoding already resolved.
    fn object_id(self) -> u64 {
        match self {
            Meta::Sub(m) => m.object_id,
            Meta::Fetch(m) => m.object_id,
        }
    }
}

/// The identity fields a subgroup header contributes to its objects.
///
/// Every field comes from an [`AnySubgroupHeader`] accessor, so the
/// per-draft knowledge behind them — which stream types leave the subgroup
/// ID to the first object, which drafts fold a mode field into the
/// header-type octet, which drafts may omit the publisher priority — stays
/// in the codec beside the decoders that define it. This crate keeps no
/// copy of it, which is the point: the copy it used to keep (a mask
/// constant and a thirteen-arm match) had already drifted from draft-16's
/// own decoder.
///
/// Where a draft encodes the subgroup ID implicitly as the first object's
/// ID, the codec stores zero and [`AnySubgroupHeader::subgroup_id`]
/// reports `None` rather than that zero.
fn subgroup_context(header: &AnySubgroupHeader) -> SubgroupContext {
    SubgroupContext {
        track_alias: header.track_alias(),
        group_id: header.group_id(),
        subgroup_id: header.subgroup_id(),
        publisher_priority: header.publisher_priority(),
    }
}

/// A slice followed by a run of zero bytes.
///
/// Lets a decoder walk an object's framing and advance past a payload that
/// has not arrived yet, so the framer can learn an object's total wire
/// length without buffering it. Only fields decoded from the real prefix
/// are trustworthy; the caller checks that before using the result, and
/// picks the pad width from what the decode path may copy — see
/// `ObjectFramer::measuring_pad`.
struct PaddedBuf<'a> {
    real: &'a [u8],
    pad: usize,
}

/// Backing bytes for [`PaddedBuf`]'s padded region.
const ZEROS: [u8; 1024] = [0u8; 1024];

impl<'a> PaddedBuf<'a> {
    fn new(real: &'a [u8], pad: usize) -> Self {
        Self { real, pad }
    }
}

impl Buf for PaddedBuf<'_> {
    fn remaining(&self) -> usize {
        self.real.len() + self.pad
    }

    fn chunk(&self) -> &[u8] {
        if self.real.is_empty() {
            &ZEROS[..self.pad.min(ZEROS.len())]
        } else {
            self.real
        }
    }

    fn advance(&mut self, cnt: usize) {
        let from_real = cnt.min(self.real.len());
        self.real = &self.real[from_real..];
        self.pad = self.pad.saturating_sub(cnt - from_real);
    }
}

// Every test below builds its input with a codec writer and reads it back
// with a codec reader, so every one of them needs at least one draft
// compiled in. With none, `AnySubgroupHeader` and friends are uninhabited
// enums and the helpers stop type-checking — `-D warnings` reports the
// `decode_stream` call as an unreachable definition. Gating the module is
// the honest shape: with no draft there is no framing to test, so the
// module vanishes rather than being kept alive by `#[allow]`.
#[cfg(test)]
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
    feature = "draft19"
))]
mod tests {
    //! The elide cursor, on the wire.
    //! Everything here builds its input with the codec's *writer* and checks
    //! the framer's output by *decoding* it again — so the claim under test
    //! (*after eliding object N the stream still decodes to the IDs that
    //! survived*) is settled by the codec's readers rather than by the rewrite
    //! logic being tested. Byte identity in the absence of an elide stays the
    //! property `tests/framer_tests.rs` and
    //! `tests/object_framing_acceptance.rs` own; the fence here only pins that
    //! the new code does not fire when nothing asked it to.

    use super::*;

    use moqtap_codec::dispatch::{AnySubgroupObject, AnySubgroupObjectWriter};

    /// The drafts this build actually compiled.
    ///
    /// Each element carries its own `#[cfg]`, so the sweep is the enabled
    /// set rather than a hardcoded thirteen: a `--features draft14` build
    /// sweeps one draft and does not try to decode twelve headers whose
    /// decoders were not compiled.
    const DRAFTS: &[DraftVersion] = &[
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

    /// The drafts that write an Object ID as `id - prev - 1`, and so are
    /// the only ones where eliding an object corrupts its successors —
    /// intersected with the ones this build compiled.
    const DELTA_DRAFTS: &[DraftVersion] = &[
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

    /// The stream-type field opening a subgroup stream that carries an
    /// explicit subgroup ID and no extensions, per draft.
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

    /// Wire bytes of a subgroup header: track alias 1, group 0, subgroup 0,
    /// publisher priority 128, no extensions.
    fn header_bytes(draft: DraftVersion) -> Vec<u8> {
        vec![subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80]
    }

    fn object(object_id: u64, payload_len: usize) -> AnySubgroupObject {
        AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![0xAB; payload_len],
        }
    }

    /// Encode a whole subgroup stream: header plus `objects`, on `draft`.
    fn build_stream(draft: DraftVersion, objects: &[AnySubgroupObject]) -> Vec<u8> {
        let head = header_bytes(draft);
        let mut cursor: &[u8] = &head;
        let header = AnySubgroupHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] header decode: {e}"));
        let mut writer = AnySubgroupObjectWriter::new(&header)
            .unwrap_or_else(|e| panic!("[{draft}] writer: {e}"));

        let mut out = head;
        for obj in objects {
            writer
                .write_object(obj, &mut out)
                .unwrap_or_else(|e| panic!("[{draft}] write object {}: {e}", obj.object_id));
        }
        out
    }

    /// A subgroup framer on `draft`, reporting into `counters`.
    ///
    /// Every framer in this module goes through
    /// [`ObjectFramer::with_recorder`] rather than [`ObjectFramer::new`]:
    /// it keeps `src/` free of the string standing gate 7 greps for
    /// without the gate having to filter comments, and it gives the
    /// counter assertions below something to read.
    fn framer_for(
        draft: DraftVersion,
        config: FramerConfig,
        counters: &Arc<Recorder>,
    ) -> ObjectFramer {
        ObjectFramer::with_recorder(DataStreamType::Subgroup, draft, config, Arc::clone(counters))
    }

    /// What one run of the framer produced.
    struct Run {
        /// Every byte the framer emitted, in order.
        bytes: Vec<u8>,
        /// The Object IDs the framer itself resolved while producing them.
        ///
        /// Objects that left as `Passthrough` are absent — they were never
        /// addressable — so this is also the record of *where framing
        /// resumed* after one of them.
        framed_ids: Vec<u64>,
        /// The run's own counters.
        counters: Arc<Recorder>,
    }

    /// Feed `stream` to a framer in `chunk`-sized pieces, dropping every
    /// object whose ID is in `elide`, and return what the framer produced.
    ///
    /// A bypass is a panic rather than a recorded outcome: every test that
    /// uses this helper is about an elide surviving, and a stream that
    /// quietly stopped being parsed would satisfy the byte assertions
    /// while proving nothing.
    fn run_eliding(
        draft: DraftVersion,
        stream: &[u8],
        chunk: usize,
        config: FramerConfig,
        elide: &[u64],
    ) -> Run {
        let counters = Arc::new(Recorder::new());
        let mut framer = framer_for(draft, config, &counters);
        let mut run = Run { bytes: Vec::new(), framed_ids: Vec::new(), counters };
        for piece in stream.chunks(chunk.max(1)) {
            framer.feed(piece);
            loop {
                match framer.poll() {
                    FramerOut::NeedMore => break,
                    FramerOut::Header { raw, .. } => run.bytes.extend_from_slice(&raw),
                    FramerOut::Object { meta, raw } => {
                        run.framed_ids.push(meta.object_id);
                        if elide.contains(&meta.object_id) {
                            framer.note_elided(&meta);
                        } else {
                            run.bytes.extend_from_slice(&raw);
                        }
                    }
                    FramerOut::Passthrough(raw) => run.bytes.extend_from_slice(&raw),
                    FramerOut::Bypassed { reason, fixup_owed } => {
                        panic!("[{draft}] unexpected bypass: {reason:?}, fixup_owed {fixup_owed}")
                    }
                    FramerOut::Error(e) => panic!("[{draft}] framer error: {e}"),
                }
            }
        }
        if let Some(tail) = framer.finish() {
            run.bytes.extend_from_slice(&tail);
        }
        run
    }

    /// Decode `bytes` as a subgroup stream and report the Object IDs the
    /// codec's readers resolve from it.
    ///
    /// The framer used here has the default cap, so every object is framed
    /// individually no matter how the producing run chose to emit it.
    fn framed_object_ids(draft: DraftVersion, bytes: &[u8]) -> Vec<u64> {
        let counters = Arc::new(Recorder::new());
        let mut framer = framer_for(draft, FramerConfig::default(), &counters);
        framer.feed(bytes);
        let mut ids = Vec::new();
        loop {
            match framer.poll() {
                FramerOut::NeedMore => break,
                FramerOut::Header { .. } => {}
                FramerOut::Object { meta, .. } => ids.push(meta.object_id),
                FramerOut::Passthrough(raw) => {
                    panic!("[{draft}] re-decode fell back to passthrough after {} bytes", raw.len())
                }
                FramerOut::Bypassed { reason, .. } => {
                    panic!("[{draft}] re-decode bypassed: {reason:?}")
                }
                FramerOut::Error(e) => panic!("[{draft}] re-decode: {e}"),
            }
        }
        assert_eq!(framer.buffered(), 0, "[{draft}] re-decode left bytes buffered");
        ids
    }

    /// Eliding an object leaves a stream that still decodes to exactly the
    /// objects that survived, on every draft.
    ///
    /// On drafts 14-19 that is only true because the framer rewrites the
    /// next object's leading Object ID varint; on 07-13 the IDs are
    /// absolute and the surviving bytes already say the truth.
    ///
    /// *Ablation:* returning `Ok(None)` unconditionally from
    /// `apply_elide_fixup` (never rewriting) fails this on the six delta
    /// drafts, `[0, 2, 3]` decoding as `[0, 1, 2]` — the whole tail of the
    /// stream shifted by one — and leaves 07-13 passing, which is exactly
    /// the blast radius the fix-up is scoped to.
    #[test]
    fn eliding_an_object_renumbers_the_rest_of_the_stream() {
        for &draft in DRAFTS {
            let objects: Vec<_> = (0..4).map(|id| object(id, 16)).collect();
            let stream = build_stream(draft, &objects);

            let run = run_eliding(draft, &stream, stream.len(), FramerConfig::default(), &[1]);

            assert_eq!(
                framed_object_ids(draft, &run.bytes),
                vec![0, 2, 3],
                "[{draft}] elided stream must decode to the surviving IDs"
            );
        }
    }

    /// The elide survives an object the framer cannot address
    /// individually.
    ///
    /// Object 65 is over the buffer cap, so it leaves as `Passthrough` with
    /// no `ObjectMeta` for anyone outside the framer to name. A cursor
    /// owned by the caller could not renumber it, and its stale delta would
    /// shift every later object for the rest of the stream. The IDs are
    /// chosen so the correction changes the varint's *width*:
    /// `65 - 1 - 1 = 63` is one byte, `65 - 0 - 1 = 64` is two.
    ///
    /// *Ablation:* returning `Ok(None)` from `apply_elide_fixup` fails this
    /// on all six delta drafts, decoding `[0, 65, 66]` as `[0, 64, 65]`.
    #[test]
    fn an_oversized_object_after_an_elide_is_still_renumbered() {
        for &draft in DRAFTS {
            let objects = vec![object(0, 8), object(1, 8), object(65, 4096), object(66, 8)];
            let stream = build_stream(draft, &objects);
            let config = FramerConfig::new().with_max_buffered_object_bytes(64);

            // Whole stream in one feed: the oversized object decodes
            // completely and `poll_object` routes it by its own wire length.
            let run = run_eliding(draft, &stream, stream.len(), config, &[1]);
            assert_eq!(
                run.framed_ids,
                vec![0, 1, 66],
                "[{draft}] object 65 left as passthrough and framing resumed on 66"
            );
            assert_eq!(
                framed_object_ids(draft, &run.bytes),
                vec![0, 65, 66],
                "[{draft}] oversized successor of an elide, decoded whole"
            );
        }
    }

    /// The same, through `poll_oversized`: the object never arrives whole,
    /// so it is measured against padding and streamed out in chunks.
    ///
    /// This is the path where `passthrough_remaining` matters. It is
    /// computed from the *source* wire length while the emitted chunk is a
    /// byte longer, and the objects are picked so that gap is real.
    ///
    /// Restricted to the six delta drafts because they are the only ones
    /// whose object layout the codec can measure past an unarrived payload;
    /// on 07-13 a 4 KiB object with a 64-byte cap is out of measuring reach
    /// and the stream bypasses instead, which is a different property.
    ///
    /// *Ablation:* setting `passthrough_remaining = wire_len - emitted`
    /// instead of `wire_len - buffered` — the plausible-looking
    /// "correction" that redenominates the counter in emitted bytes when it
    /// has to stay in source bytes — fails this on all six drafts with
    /// `framed_ids == [0, 1]`: the
    /// framer leaves one payload byte of object 65 in the buffer, reads it
    /// as the head of the next object, and never frames object 66 at all.
    /// It fails **nothing else**, including this file's byte-level
    /// assertions, because the framer still emits every byte it was fed —
    /// just partitioned wrongly. That is why `Run` reports `framed_ids`:
    /// the first draft of this test asserted only on bytes and the
    /// ablation walked straight through it.
    ///
    /// Returning `Ok(None)` from `apply_elide_fixup` fails it earlier,
    /// with the re-decode reading `[0, 64, 65]`.
    #[test]
    fn an_elide_survives_an_object_streamed_through_in_chunks() {
        for &draft in DELTA_DRAFTS {
            let objects = vec![object(0, 8), object(1, 8), object(65, 4096), object(66, 8)];
            let stream = build_stream(draft, &objects);
            let config = FramerConfig::new().with_max_buffered_object_bytes(64);

            let run = run_eliding(draft, &stream, 32, config, &[1]);
            // The accounting claim: `passthrough_remaining` is denominated
            // in source bytes, so the framer consumes object 65 exactly and
            // resynchronises on object 66's first byte — even though what
            // it emitted for object 65 is a byte longer than what it read.
            assert_eq!(
                run.framed_ids,
                vec![0, 1, 66],
                "[{draft}] framing must resume exactly on object 66"
            );
            assert_eq!(
                framed_object_ids(draft, &run.bytes),
                vec![0, 65, 66],
                "[{draft}] oversized successor of an elide, streamed through"
            );
        }
    }

    /// A framer nobody elides on emits its input back, byte for byte.
    ///
    /// The regression fence for the fix-up code: it must be inert until
    /// [`ObjectFramer::note_elided`] is called. This is the property the
    /// acceptance suite rests on, restated where the code that could break
    /// it lives.
    ///
    /// *Ablation:* dropping the `self.fixup_pending` guard from
    /// `apply_elide_fixup` (rewriting every object unconditionally) still
    /// passes here, and passes `tests/framer_tests.rs` and
    /// `tests/object_framing_acceptance.rs` too — a minimally encoded delta
    /// re-encodes to itself, so the rewrite is invisible on any stream
    /// these build. `a_widened_object_id_field_is_not_re_encoded` below is
    /// the fence for that line; this test is a pin.
    #[test]
    fn a_stream_with_no_elide_is_emitted_byte_for_byte() {
        for &draft in DRAFTS {
            let objects: Vec<_> = (0..4).map(|id| object(id, 16)).collect();
            let stream = build_stream(draft, &objects);

            for chunk in [1usize, 7, stream.len()] {
                let run = run_eliding(draft, &stream, chunk, FramerConfig::default(), &[]);
                assert_eq!(run.bytes, stream, "[{draft}] chunk {chunk}: byte identity");
            }
        }
    }

    /// A non-minimally encoded Object ID field survives untouched when
    /// nothing was elided.
    ///
    /// QUIC varints may be written wider than they need to be, and a
    /// producer that does so is still emitting a legal stream. Re-encoding
    /// such a field would change bytes the proxy was asked to forward
    /// unchanged — so the fix-up must be reached only when an elide
    /// actually armed it, not merely when the draft delta-encodes.
    ///
    /// *Ablation:* dropping the `self.fixup_pending` guard from
    /// `apply_elide_fixup` fails this on all six delta drafts, and fails
    /// **nothing else** — not this file's other tests, not
    /// `tests/framer_tests.rs`, not `tests/object_framing_acceptance.rs` — because
    /// a minimally encoded field re-encodes to itself. This test is the
    /// only fence that line has.
    #[test]
    fn a_widened_object_id_field_is_not_re_encoded() {
        for &draft in DELTA_DRAFTS {
            let stream = build_stream(draft, &[object(0, 8), object(1, 8)]);

            // Object 0 starts right after the five header bytes, and its
            // leading field is the one-byte varint 0. The two-byte form of the
            // same value differs by draft: `0x40 0x00` under RFC 9000, and
            // `0x80 0x00` from draft-17, where `0x40` is the one-byte 64.
            let head = header_bytes(draft).len();
            assert_eq!(stream[head], 0x00, "[{draft}] object 0's ID field is not where expected");
            let two_byte_zero: [u8; 2] =
                if draft.uses_moqt_varint() { [0x80, 0x00] } else { [0x40, 0x00] };
            let mut widened = stream[..head].to_vec();
            widened.extend_from_slice(&two_byte_zero);
            widened.extend_from_slice(&stream[head + 1..]);

            let run = run_eliding(draft, &widened, widened.len(), FramerConfig::default(), &[]);
            assert_eq!(run.framed_ids, vec![0, 1], "[{draft}] widened field must still decode");
            assert_eq!(run.bytes, widened, "[{draft}] widened field must be forwarded verbatim");
        }
    }

    /// A draft-16 subgroup header cannot set both the explicit-subgroup-ID
    /// bit and the first-object bit, so the proxy never has to choose
    /// between them.
    ///
    /// This test used to pin the choice. Setting `0x04` (explicit subgroup
    /// ID) and `0x02` (subgroup ID is the first object's) together puts
    /// bits one and two at `0b11`, and draft-16 Section 10.4.2 reserves
    /// that Subgroup ID mode. The decoder now refuses all eight bytes that
    /// spell it, so a header asking the question can no longer be built.
    ///
    /// What the old test recorded is still worth keeping, because it
    /// explains why the proxy reads the field through the uniform
    /// accessor: the header's own `subgroup_id_from_first_object`
    /// predicate used to look only at `0x02`, so a match asking only that
    /// question reported `None` for a subgroup ID sitting on the wire.
    /// That predicate reads the whole two-bit mode now, and the accessor
    /// already let the explicit mode win, matching the decoder. That
    /// behaviour is unchanged and is exercised by every valid
    /// explicit-mode header; only the contradictory input is gone.
    ///
    /// The fence moved rather than vanished — this now sweeps the whole
    /// reserved mode instead of pinning one byte of it.
    ///
    /// *Ablation:* accepting the reserved mode again — dropping the
    /// Subgroup ID mode arm from the draft-16 `validate_subgroup_type` —
    /// lets all eight headers decode, and this fails on the first:
    ///
    /// ```text
    /// thread 'framer::tests::draft16_refuses_the_reserved_subgroup_id_mode'
    /// panicked at crates\moqtap-proxy\src\framer.rs:1436:13:
    /// type 0x16 sets the reserved Subgroup ID mode and must be refused
    /// ```
    #[test]
    #[cfg(feature = "draft16")]
    fn draft16_refuses_the_reserved_subgroup_id_mode() {
        let draft = DraftVersion::Draft16;
        // Bits one and two are the Subgroup ID mode; 0b11 is reserved.
        // These are the eight subgroup types that set it, with and without
        // the extensions and priority bits.
        for ty in [0x16u8, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F] {
            // Track alias 1, group 0, subgroup 42, publisher priority 128 —
            // a complete body, so a refusal is of the type and never of a
            // short buffer.
            let head = vec![ty, 0x01, 0x00, 0x2A, 0x80];
            let mut cursor: &[u8] = &head;
            assert!(
                AnySubgroupHeader::decode_stream(draft, &mut cursor).is_err(),
                "type {ty:#04x} sets the reserved Subgroup ID mode and must be refused",
            );
        }
    }

    /// The cursor advances lazily, one object behind the framer.
    ///
    /// An object's disposition is not known when it is emitted — the caller
    /// decides afterwards — so `last_forwarded_id` moves at the top of the
    /// *next* `poll_object`. The fix-up flag is the part that must be
    /// visible immediately, because it is what a bypass has to report as
    /// still owed.
    ///
    /// *Ablation:* committing eagerly (adding
    /// `self.last_forwarded_id = Some(object_id)` where
    /// `pending_disposition` is assigned) makes the elided object count as
    /// forwarded. This test fails at its first cursor assertion, on
    /// draft-07 — `Some(0)` where `None` is owed — and the three elide
    /// tests fail alongside it from draft-14 on, reading `[0, 1, 2]` and
    /// `[0, 64, 65]`.
    #[test]
    fn the_elide_cursor_tracks_the_last_object_actually_forwarded() {
        for &draft in DRAFTS {
            let delta = DELTA_DRAFTS.contains(&draft);
            let objects: Vec<_> = (0..3).map(|id| object(id, 8)).collect();
            let stream = build_stream(draft, &objects);

            let counters = Arc::new(Recorder::new());
            let mut framer = framer_for(draft, FramerConfig::default(), &counters);
            framer.feed(&stream);

            assert_eq!(
                framer.elide_cursor(),
                ElideCursor { last_forwarded_id: None, fixup_pending: false },
                "[{draft}] fresh framer"
            );

            assert!(matches!(framer.poll(), FramerOut::Header { .. }));

            // Object 0, forwarded.
            let FramerOut::Object { meta, .. } = framer.poll() else {
                panic!("[{draft}] expected object 0");
            };
            assert_eq!(meta.object_id, 0);
            assert_eq!(
                framer.elide_cursor().last_forwarded_id,
                None,
                "[{draft}] object 0's disposition is not known yet"
            );

            // Object 1, elided. Polling for it commits object 0 first.
            let FramerOut::Object { meta, .. } = framer.poll() else {
                panic!("[{draft}] expected object 1");
            };
            assert_eq!(meta.object_id, 1);
            assert_eq!(
                framer.elide_cursor().last_forwarded_id,
                Some(0),
                "[{draft}] object 0 committed as forwarded"
            );
            framer.note_elided(&meta);
            assert_eq!(
                framer.elide_cursor(),
                ElideCursor { last_forwarded_id: Some(0), fixup_pending: delta },
                "[{draft}] the elide is visible at once, and only delta drafts owe a fix-up"
            );

            // Object 2 clears the fix-up as it is emitted, and the cursor
            // still names object 0 until the object after it is asked for.
            let FramerOut::Object { meta, .. } = framer.poll() else {
                panic!("[{draft}] expected object 2");
            };
            assert_eq!(meta.object_id, 2);
            assert_eq!(
                framer.elide_cursor(),
                ElideCursor { last_forwarded_id: Some(0), fixup_pending: false },
                "[{draft}] the fix-up is spent on the object that carried it"
            );

            assert!(matches!(framer.poll(), FramerOut::NeedMore));
            assert_eq!(
                framer.elide_cursor().last_forwarded_id,
                Some(2),
                "[{draft}] object 2 committed as forwarded"
            );
        }
    }

    /// A bypass is reported once, as a zero-byte item, on the poll *after*
    /// the one that decided it.
    ///
    /// A draft-19 fetch stream is the cleanest case: the header decodes,
    /// so it is emitted, and only then is the stream found to be one whose
    /// objects are not addressed. `latch_bypass` cannot return the
    /// `Bypassed` item from that poll — the poll already owes a `Header` —
    /// so it is deferred.
    ///
    /// *Ablation:* dropping the `pending_bypass` drain from the top of
    /// `poll` fails this at the second poll with a `Passthrough`, and the
    /// stream's whole reason for not being addressable becomes
    /// unreportable — which is the state `BypassReason` was in before this
    /// unit: declared, and never constructed.
    #[test]
    #[cfg(feature = "draft19")]
    fn a_bypass_is_reported_once_on_the_poll_after_the_item_that_decided_it() {
        let draft = DraftVersion::Draft19;
        // Fetch stream type 0x05, request ID 42, then four bytes of
        // whatever the publisher was sending.
        let stream = vec![0x05u8, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF];

        let counters = Arc::new(Recorder::new());
        let mut framer = ObjectFramer::with_recorder(
            DataStreamType::Fetch,
            draft,
            FramerConfig::default(),
            Arc::clone(&counters),
        );
        framer.feed(&stream);

        let FramerOut::Header { raw, .. } = framer.poll() else {
            panic!("expected the fetch header");
        };
        assert_eq!(&raw[..], &stream[..2], "the header is still emitted in full");
        assert!(framer.is_bypassed(), "the bypass was decided before the header was handed out");

        assert!(
            matches!(
                framer.poll(),
                FramerOut::Bypassed {
                    reason: BypassReason::FetchGroupOrderUnknown,
                    fixup_owed: false
                }
            ),
            "the bypass follows the header rather than replacing it"
        );

        let FramerOut::Passthrough(rest) = framer.poll() else {
            panic!("expected the remainder to be forwarded uninterpreted");
        };
        assert_eq!(&rest[..], &stream[2..], "no byte is lost to the bypass");

        assert!(matches!(framer.poll(), FramerOut::NeedMore));
        assert!(matches!(framer.poll(), FramerOut::NeedMore), "reported exactly once");

        let c = counters.snapshot();
        assert_eq!(c.framers_created, 1);
        assert_eq!(c.framer_header_polls, 1);
        assert_eq!(c.framer_object_polls, 0, "a bypassed stream never enters the object path");
        assert_eq!(c.streams_not_shapeable, 1);
        assert_eq!(c.objects_not_addressable, 0, "no object was ever decoded");
    }

    /// A bypass while a fix-up is owed says so, because the bytes still in
    /// flight decode to Object IDs one ahead of what was delivered.
    ///
    /// Objects 0 and 1 are written normally and object 1 is elided, which
    /// arms the fix-up. The third object is a hand-written all-ones varint —
    /// `2^62 - 1` in eight bytes under RFC 9000, `2^64 - 1` in nine from
    /// draft-17. Either is legal and its delta resolves to an Object ID above
    /// the ceiling, so `read_object_meta` returns `InvalidField` rather than
    /// an incomplete-input error and the framer abandons the stream with the
    /// fix-up unspent.
    ///
    /// *Ablation:* reporting `fixup_owed: false` unconditionally passes
    /// every other test in this file — nothing else reads the flag — and
    /// leaves the session forwarding a tail that renumbers itself.
    #[test]
    fn a_bypass_that_strands_a_fix_up_reports_it_as_owed() {
        for &draft in DELTA_DRAFTS {
            let mut stream = build_stream(draft, &[object(0, 8), object(1, 8)]);
            // All-ones is the largest varint the draft's encoding can express:
            // eight bytes under RFC 9000, nine from draft-17.
            if draft.uses_moqt_varint() {
                stream.extend_from_slice(&[0xFFu8; 9]);
            } else {
                stream.extend_from_slice(&[0xFFu8; 8]);
            }

            let counters = Arc::new(Recorder::new());
            let mut framer = framer_for(draft, FramerConfig::default(), &counters);
            framer.feed(&stream);

            assert!(matches!(framer.poll(), FramerOut::Header { .. }));
            assert!(matches!(framer.poll(), FramerOut::Object { .. }), "[{draft}] object 0");
            let FramerOut::Object { meta, .. } = framer.poll() else {
                panic!("[{draft}] expected object 1");
            };
            framer.note_elided(&meta);
            assert!(framer.elide_cursor().fixup_pending, "[{draft}] the fix-up is armed");

            assert!(
                matches!(framer.poll(), FramerOut::Error(_)),
                "[{draft}] the third object must fail to decode outright"
            );
            assert!(
                matches!(
                    framer.poll(),
                    FramerOut::Bypassed { reason: BypassReason::DecodeError, fixup_owed: true }
                ),
                "[{draft}] the stranded fix-up must be reported"
            );

            assert_eq!(counters.snapshot().streams_not_shapeable, 1, "[{draft}] one latch");
            assert_eq!(
                counters.snapshot().object_ids_rewritten,
                0,
                "[{draft}] the fix-up never got the chance to be written"
            );
        }
    }

    /// The counters move where — and only where — the slow path ran.
    ///
    /// This is the falsifiable half of the `Interest::NONE` claim: the
    /// framer is the slow path, so a framer that counts nothing makes the
    /// proof pass by measuring nothing.
    ///
    /// *Ablation:* passing a throwaway `Recorder` from `with_recorder`
    /// instead of the caller's — the shape `ObjectFramer::new` has by
    /// design — leaves every assertion here reading 0.
    #[test]
    fn the_framer_counts_the_slow_path_work_it_did() {
        for &draft in DRAFTS {
            let delta = DELTA_DRAFTS.contains(&draft);
            let objects: Vec<_> = (0..4).map(|id| object(id, 16)).collect();
            let stream = build_stream(draft, &objects);

            let run = run_eliding(draft, &stream, stream.len(), FramerConfig::default(), &[1]);
            let c = run.counters.snapshot();

            assert_eq!(c.framers_created, 1, "[{draft}]");
            assert_eq!(c.framer_header_polls, 1, "[{draft}] one poll decoded the header");
            // Four objects plus the poll that returned `NeedMore`.
            assert_eq!(c.framer_object_polls, 5, "[{draft}]");
            assert_eq!(
                c.object_ids_rewritten,
                u64::from(delta),
                "[{draft}] one rewrite, and only where IDs are deltas"
            );
            assert_eq!(c.objects_not_addressable, 0, "[{draft}] every object was framed");
            assert_eq!(c.streams_not_shapeable, 0, "[{draft}] nothing was bypassed");
        }
    }

    /// An object too big to buffer is counted as unaddressable exactly
    /// once, on both of the paths that produce one.
    ///
    /// The whole-stream feed routes object 65 through `poll_object`'s
    /// oversized branch; the 32-byte feed routes it through
    /// `poll_oversized`, which emits it as several `Passthrough` chunks
    /// and must still count *one* object.
    ///
    /// *Ablation:* counting in `poll`'s `passthrough_remaining` branch
    /// instead — the obvious place, since that is where most of the bytes
    /// leave — reports 4 for the chunked run and 0 for the whole-stream
    /// one.
    #[test]
    fn an_unaddressable_object_is_counted_once_per_object_not_per_chunk() {
        for &draft in DELTA_DRAFTS {
            let objects = vec![object(0, 8), object(1, 8), object(65, 4096), object(66, 8)];
            let stream = build_stream(draft, &objects);
            let config = FramerConfig::new().with_max_buffered_object_bytes(64);

            for chunk in [stream.len(), 32] {
                let run = run_eliding(draft, &stream, chunk, config.clone(), &[1]);
                let c = run.counters.snapshot();
                assert_eq!(
                    c.objects_not_addressable, 1,
                    "[{draft}] chunk {chunk}: one object, however many chunks it left in"
                );
                assert_eq!(c.object_ids_rewritten, 1, "[{draft}] chunk {chunk}");
                assert_eq!(c.streams_not_shapeable, 0, "[{draft}] chunk {chunk}: no bypass");
            }
        }
    }
}

//! The words the rest of the crate keys on.
//!
//! Five leaf types, each a plain `Copy` value with no behaviour: which side of
//! the proxy a frame moves over, which of the two connections a call is about,
//! which kind of data stream is being read, what a framed object is, and why
//! the framer stopped framing one. Twenty-eight `use` edges from fourteen
//! modules reach for them.
//!
//! Before this module existed each lived wherever it was first needed, so those
//! edges ran upward: `framer` took a field of its own output type from
//! `parser::data`, and `event` took two fields of an event from `framer` and
//! `transport`. Nothing here imports anything from this crate, which is the
//! property that makes those edges disappear rather than reverse.
//!
//! **Every one of the five is still re-exported where it used to live**, so
//! `event::ProxySide`, `transport::Leg`, `framer::ObjectMeta`,
//! `framer::BypassReason` and `parser::data::DataStreamType` all still resolve.
//! A downstream match on `ProxySide` with no wildcard arm keeps compiling, and
//! nothing outside this crate has to move.

use moqtap_codec::dispatch::AnyFetchEndOfRange;
use moqtap_codec::version::DraftVersion;

/// Which side of the proxy a message originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySide {
    /// Client → Proxy (downstream ingress).
    ClientToProxy,
    /// Proxy → Relay (upstream egress).
    ProxyToRelay,
    /// Relay → Proxy (upstream ingress).
    RelayToProxy,
    /// Proxy → Client (downstream egress).
    ProxyToClient,
}

/// Which of the proxy's two connections a call is about.
///
/// **Not [`ProxySide`]**, which this crate also
/// has and which names something else entirely. A leg is a *connection*:
/// the proxy holds exactly two, one to the client and one to the upstream
/// relay, and each has its own endpoint, its own socket, its own
/// certificate and its own transport parameters. A side is a *direction of
/// travel* over a leg, which is why `ProxySide` has four variants where
/// this has two — `ClientToProxy` and `ProxyToClient` are the two
/// directions of the client leg, `ProxyToRelay` and `RelayToProxy` the two
/// of the upstream leg.
///
/// The two are worth keeping straight because the compiler will not: both are
/// small `Copy` enums that a reader skims as *which part of the proxy*. The
/// test is what the thing being described belongs to. Anything QUIC settles
/// once for a whole connection — a window, an MTU, a congestion controller, a
/// socket — is a leg. Anything a single frame can be observed in or acted on —
/// an event, a shaping rule, a hook site — is a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The connection between a client and this proxy.
    Client,
    /// The connection between this proxy and the upstream relay.
    Upstream,
}

/// The expected type of data stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStreamType {
    /// Subgroup data stream (most common).
    Subgroup,
    /// Fetch response data stream.
    Fetch,
}

/// A framed object's identity and framing, without its payload.
///
/// Every field is a primitive, so an observer never has to name a
/// per-draft codec type to key on an object. Produced by
/// [`ObjectFramer`](crate::framer::ObjectFramer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    /// The draft this stream was parsed as.
    pub draft: DraftVersion,
    /// Whether this object came from a subgroup or a fetch stream.
    pub stream_kind: DataStreamType,
    /// Track alias from the stream header. `None` on fetch streams, whose
    /// headers carry a request ID instead.
    pub track_alias: Option<u64>,
    /// Group ID: from the stream header on subgroup streams, from the
    /// object itself on fetch streams.
    pub group_id: u64,
    /// Subgroup ID. `None` when the frame has none to report, which
    /// happens two ways.
    /// On a subgroup stream, when the stream type encodes an implicit subgroup
    /// ID that this draft never resolves — eight drafts (11, 12, 13, 14, 16,
    /// 17, 18 and 19) define a *subgroup ID is the first object's ID* mode that
    /// the codec stores as zero, and reporting that zero would mis-key any
    /// matcher.
    ///
    /// On a fetch stream, when the frame carried no Subgroup ID at all:
    /// from draft-15 a fetch object may be marked as having been forwarded
    /// over a datagram, which has no subgroup, and an End of Range
    /// indicator names a Location rather than an object. Both cases reach
    /// this crate as `has_subgroup_id: false` on the codec's meta, behind
    /// a subgroup ID field that holds a placeholder — the same zero, and
    /// the same mis-keying if it were forwarded.
    pub subgroup_id: Option<u64>,
    /// Absolute Object ID, resolved from delta encoding on drafts 14-19.
    pub object_id: u64,
    /// Publisher priority. `None` when the header set a default-priority
    /// flag and omitted the field (drafts 15+).
    pub publisher_priority: Option<u8>,
    /// Zero-based index of this object within its stream.
    pub index_in_stream: u64,
    /// Declared payload length in bytes.
    pub payload_len: u64,
    /// Object Status wire code; `None` when a non-empty payload followed.
    pub status: Option<u64>,
    /// Which End of Range indicator this frame is, or `None` for an object.
    ///
    /// Drafts 16-19 let a fetch stream state that a run of Objects was not
    /// serialized instead of sending them, and those frames arrive through
    /// the same reader call as objects do. They are **not** objects: they
    /// carry no payload and no content, and one of them standing in a
    /// count of objects is a count that is wrong. An observer that means
    /// "objects" filters on this being `None`; one that means "frames"
    /// does not.
    ///
    /// Always `None` on a subgroup stream, and on every fetch stream of
    /// drafts 07-15, which have no such frame.
    pub end_of_range: Option<AnyFetchEndOfRange>,
}

/// Why [`ObjectFramer`](crate::framer::ObjectFramer) stopped parsing a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BypassReason {
    /// The header decoded but the object reader rejected this subgroup
    /// stream type.
    UnsupportedSubgroupStreamType,
    /// This build compiled no object reader for the fetch stream's draft,
    /// so the stream is forwarded intact from its header on.
    ///
    /// Defensive rather than routine. The stream *header* decodes first and
    /// fails first on a draft that was not compiled, reporting
    /// [`Self::DecodeError`], so a session reaches this only if the header
    /// dispatch and the object-reader dispatch ever disagree about which
    /// drafts this binary speaks.
    ///
    /// It used to mean something else and much more common: a fetch stream
    /// on any of drafts 15-19, none of which this crate would address. Three
    /// of those five are now framed, and the two that are not report
    /// [`Self::FetchGroupOrderUnknown`], which says why.
    NoFetchObjectCodec,
    /// A fetch stream on draft-18 or draft-19 naming a request this session
    /// never saw asked for.
    ///
    /// Those two drafts write an Object's Group ID as a difference from the
    /// previous Object's, and the fetch's Group Order decides which way the
    /// difference points — draft-19 Section 11.4.4.1: "If the Group Order is
    /// Ascending, the Group ID is the prior Object's Group ID plus the Group
    /// ID Delta + 1. If the Group Order is Descending, the Group ID is the
    /// prior Object's Group ID minus the (Group ID Delta + 1)."
    ///
    /// Nothing on the data stream states the order. It is on the FETCH the
    /// stream answers — draft-19 Section 10.2.8: "If omitted from FETCH, the
    /// receiver uses Ascending (0x1)" — so a session that carried the FETCH
    /// knows it, files it under that Request ID, and hands it to the framer
    /// when the response stream opens. See
    /// [`FetchGroupOrders`](crate::framer::FetchGroupOrders).
    ///
    /// What is left for this variant is the stream whose FETCH never came
    /// past: a publisher answering a request nobody made, a session whose
    /// control plane is a byte pump because nothing frames its data either,
    /// or a hook that rewrote a FETCH into bytes that no longer decode.
    ///
    /// Guessing would not fail loudly, which is why an unanswered stream is
    /// bypassed rather than read against the draft's default. A descending
    /// stream read as ascending decodes every Object and every field of it;
    /// only the Group IDs are wrong, walking up where the publisher sent them
    /// walking down. Every event reported off this stream and every shaping
    /// rule keyed on a group would then be wrong with nothing to say so. The
    /// bytes are forwarded untouched instead.
    FetchGroupOrderUnknown,
    /// An object could not be measured within the buffer cap's reach.
    ObjectBeyondMeasuringReach,
    /// A header or object failed to decode. Also reported as
    /// [`FramerOut::Error`](crate::framer::FramerOut::Error).
    DecodeError,
}

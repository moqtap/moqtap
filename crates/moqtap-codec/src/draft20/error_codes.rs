//! Error, status and stream-reset code registries defined by
//! draft-ietf-moq-transport-20.
//!
//! One enum per registry in the IANA Considerations section (Section 15.11). The
//! registry tables list only Name, Code and Specification; the per-code prose in
//! the variant docs is taken from the section each row cites.
//!
//! `from_u64` returns `None` for any value the draft does not assign. A peer may
//! legitimately send a code from a later draft or a private extension, and an
//! unrecognized code must not be a decode failure at this layer.
//!
//! Each of these four registries reserves `0x7f * N + 0x9D` for greasing
//! (Section 14). That is a range rather than an assignment, so it gets no
//! variant and `from_u64` reports it as unknown like any other unassigned value.
//!
//! Code points inside a registry are not contiguous; the gaps are the draft's.
//!
//! # What draft-20 took out
//!
//! Three code points that draft-19 assigned are unassigned here, and each is a
//! hole rather than a renumbering — nothing moved into the space:
//!
//! * `VERSION_NEGOTIATION_FAILED` (session termination `0x15`), draft-19: "The
//!   client didn't offer a version supported by the server." Version selection
//!   has happened in the ALPN since draft-15, so there is no in-band
//!   negotiation left to fail.
//! * `INVALID_JOINING_REQUEST_ID` (REQUEST_ERROR `0x32`), draft-19: "In response
//!   to a Joining FETCH, the referenced Request ID is not an Established
//!   Subscription." Joining fetches went with the FETCH rewrite (Section 10.13).
//! * `SUBSCRIPTION_ENDED` (PUBLISH_DONE `0x3`), draft-19: "The publisher reached
//!   the end of an associated location filter." Draft-20 Section 5.1.2 removed
//!   the behaviour with the code: "A publisher does not end a subscription
//!   solely because the Largest Object advances past the end of the current
//!   Location Filter."
//!
//! No code point was renumbered in any registry.

/// Session termination error codes (draft-20 Section 15.11.1).
///
/// Sent as the error code when closing the Transport Session: the QUIC `CONNECTION_CLOSE` frame
/// over native QUIC, or the `CLOSE_WEBTRANSPORT_SESSION` capsule over WebTransport. The per-code
/// definitions are in Section 3.5 of the draft. Note that this draft assigns no code point 0x7,
/// none in 0xA-0xF, and none at 0x15. 0x7 was last assigned by draft-17, as
/// `INVALID_REQUIRED_REQUEST_ID`; drafts 14 through 16 used it for `TOO_MANY_REQUESTS`. Draft-18
/// vacated it and draft-20 leaves it vacant. 0x15 is draft-20's own vacancy: draft-19 assigned it
/// to `VERSION_NEGOTIATION_FAILED` and draft-20 removed the row.
///
/// The registry also reserves the code points `0x7f * N + 0x9D` for greasing (draft-20 Section
/// 14). That is a range rather than an assignment, so it has no variant here and `from_u64`
/// reports it as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `NO_ERROR` — The session is being terminated without an error.
    NoError = 0x0,

    /// `INTERNAL_ERROR` — An implementation specific error occurred.
    InternalError = 0x1,

    /// `UNAUTHORIZED` — The client is not authorized to establish a session.
    Unauthorized = 0x2,

    /// `PROTOCOL_VIOLATION` — The remote endpoint performed an action that was disallowed by the
    /// specification.
    ProtocolViolation = 0x3,

    /// `INVALID_REQUEST_ID` — The endpoint received a Request ID with an incorrect least
    /// significant bit for the sender, or a duplicate Request ID. See Section 10.1.
    InvalidRequestId = 0x4,

    /// `DUPLICATE_TRACK_ALIAS` — The endpoint attempted to use a Track Alias that was already in
    /// use.
    DuplicateTrackAlias = 0x5,

    /// `KEY_VALUE_FORMATTING_ERROR` — The key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,

    /// `INVALID_PATH` — The PATH parameter was used by a server, on a WebTransport session, or
    /// the server does not support the path.
    InvalidPath = 0x8,

    /// `MALFORMED_PATH` — The PATH parameter does not conform to the rules in Section 10.3.1.2.
    MalformedPath = 0x9,

    /// `GOAWAY_TIMEOUT` — The session was closed because the peer took too long to close the
    /// session in response to a GOAWAY (Section 10.4) message. See session migration (Section
    /// 3.6).
    GoawayTimeout = 0x10,

    /// `CONTROL_MESSAGE_TIMEOUT` — The session was closed because the peer took too long to
    /// respond to a control message.
    ControlMessageTimeout = 0x11,

    /// `DATA_STREAM_TIMEOUT` — The session was closed because the peer took too long to send data
    /// expected on an open Data Stream (see Section 11). This includes fields of a stream header
    /// or an object header within a data stream. If an endpoint times out waiting for a new
    /// object header on an open subgroup stream, it MAY send a STOP_SENDING on that stream or
    /// terminate the subscription.
    DataStreamTimeout = 0x12,

    /// `AUTH_TOKEN_CACHE_OVERFLOW` — The Session limit Section 10.3.1.3 of the size of all
    /// registered Authorization tokens has been exceeded.
    AuthTokenCacheOverflow = 0x13,

    /// `DUPLICATE_AUTH_TOKEN_ALIAS` — Authorization Token attempted to register an Alias that was
    /// in use (see Section 10.2.2).
    DuplicateAuthTokenAlias = 0x14,

    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during registration (see Section
    /// 10.2.2).
    MalformedAuthToken = 0x16,

    /// `UNKNOWN_AUTH_TOKEN_ALIAS` — No registered token found for the provided Alias (see Section
    /// 10.2.2).
    UnknownAuthTokenAlias = 0x17,

    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 10.2.2).
    ExpiredAuthToken = 0x18,

    /// `INVALID_AUTHORITY` — The specified AUTHORITY does not correspond to this server or cannot
    /// be used in this context.
    InvalidAuthority = 0x19,

    /// `MALFORMED_AUTHORITY` — The AUTHORITY value is syntactically invalid.
    MalformedAuthority = 0x1A,

    /// `TOO_MANY_REQUEST_UPDATES` — The endpoint received a REQUEST_UPDATE that exceeded the
    /// per-stream limit communicated via the MAX_REQUEST_UPDATES Setup Option (Section 10.3.1.7).
    TooManyRequestUpdates = 0x1B,
}

/// REQUEST_ERROR codes (draft-20 Section 15.11.2).
///
/// 0x32 is unassigned. Draft-19 gave it to `INVALID_JOINING_REQUEST_ID`, which answered a Joining
/// FETCH; draft-20 deleted the joining mechanism along with the Fetch Type field it travelled in.
///
/// Section 10.6 states that REQUEST_ERROR is sent in response to any request: SUBSCRIBE, FETCH,
/// PUBLISH, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS, PUBLISH_NAMESPACE, TRACK_STATUS and
/// REQUEST_UPDATE. The per-code definitions are in Section 10.6.2, which the registry table cites
/// as Section 10.6.
///
/// Note that the shorter list naming only the first seven of those messages belongs to the
/// `REDIRECT` code specifically, not to the registry as a whole.
///
/// The registry also reserves the code points `0x7f * N + 0x9D` for greasing (draft-20 Section
/// 14). That is a range rather than an assignment, so it has no variant here and `from_u64`
/// reports it as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RequestErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,

    /// `UNAUTHORIZED` — The subscriber is not authorized to perform the requested action on the
    /// given track. This might be retryable if the authorization token is not yet valid.
    Unauthorized = 0x1,

    /// `TIMEOUT` — The subscription could not be completed before an implementation specific
    /// timeout. For example, a relay could not establish an upstream subscription within the
    /// timeout.
    Timeout = 0x2,

    /// `NOT_SUPPORTED` — The endpoint does not support the type of request.
    NotSupported = 0x3,

    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during registration (see Section
    /// 10.2.2).
    MalformedAuthToken = 0x4,

    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 10.2.2).
    ExpiredAuthToken = 0x5,

    /// `GOING_AWAY` — The endpoint has received a GOAWAY and MAY reject new requests.
    GoingAway = 0x6,

    /// `EXCESSIVE_LOAD` — The responder is overloaded and cannot process the request at this
    /// time. The sender SHOULD use the Retry Interval to indicate when the request can be
    /// retried.
    ExcessiveLoad = 0x9,

    /// `DOES_NOT_EXIST` — The track or namespace is not available at the publisher.
    DoesNotExist = 0x10,

    /// `INVALID_RANGE` — In response to SUBSCRIBE or FETCH, specified Filter or range of
    /// Locations cannot be satisfied.
    InvalidRange = 0x11,

    /// `MALFORMED_TRACK` — In response to a FETCH, a relay publisher detected the track was
    /// malformed (see Section 2.4.2).
    MalformedTrack = 0x12,

    /// `UNINTERESTED` — The subscriber is not interested in the track or namespace.
    Uninterested = 0x20,

    /// `PREFIX_OVERLAP` — In response to SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS, the namespace
    /// prefix shares a common prefix with another subscription of the same type in the same
    /// session. SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS have independent overlap spaces, so a
    /// SUBSCRIBE_NAMESPACE and a SUBSCRIBE_TRACKS may share the same prefix.
    PrefixOverlap = 0x30,

    /// `NAMESPACE_TOO_LARGE` — In response to SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS, the
    /// namespace prefix matches more publishers than the relay is willing to enumerate.
    NamespaceTooLarge = 0x31,

    /// `UNSUPPORTED_EXTENSION` — The track contains a Mandatory Track Property (see Section
    /// 2.5.1) that the endpoint does not understand.
    UnsupportedExtension = 0x33,

    /// `REDIRECT` — The request cannot be fulfilled by this endpoint, but could succeed at the
    /// location specified in the Redirect structure. The requester SHOULD establish a new session
    /// to the provided URI (if present) and retry the request using the Full Track Name from the
    /// Redirect (if present). This error code can appear in response to SUBSCRIBE, FETCH,
    /// TRACK_STATUS, PUBLISH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, and SUBSCRIBE_TRACKS.
    /// Relays are not required to follow redirects from upstream and MAY forward a REDIRECT
    /// response to matching downstream requests. A relay MAY cache a REDIRECT response for a Full
    /// Track Name for up to Retry Interval milliseconds and use it to respond to subsequent
    /// matching requests without forwarding them upstream.
    Redirect = 0x34,

    /// `CONFLICTING_FILTERS` — In response to SUBSCRIBE_TRACKS, the filter parameters conflict
    /// among too many subscribers to aggregate the subscription upstream or otherwise efficiently
    /// service it.
    ConflictingFilters = 0x35,

    /// `INVALID_FILTER` — A filter parameter is invalid.
    InvalidFilter = 0x36,
}

/// PUBLISH_DONE codes (draft-20 Section 15.11.3).
///
/// Carried in the Status Code field of PUBLISH_DONE. The per-code definitions are in Section
/// 10.12 of the draft, which is Section 10.11 renumbered — PUBLISH_STATE_NOTIFY took 10.10 and
/// pushed everything after it down by one.
///
/// 0x3 is unassigned. Draft-19 gave it to `SUBSCRIPTION_ENDED`; see this module's own
/// documentation for why the code and the behaviour went together.
///
/// The registry also reserves the code points `0x7f * N + 0x9D` for greasing (draft-20 Section
/// 14). That is a range rather than an assignment, so it has no variant here and `from_u64`
/// reports it as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishDoneStatusCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,

    /// `UNAUTHORIZED` — The subscriber is no longer authorized to subscribe to the given track.
    Unauthorized = 0x1,

    /// `TRACK_ENDED` — The track is no longer being published.
    TrackEnded = 0x2,

    /// `GOING_AWAY` — The subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,

    /// `TOO_FAR_BEHIND` — The publisher's queue of objects to be sent to the given subscriber
    /// exceeds its implementation defined limit.
    TooFarBehind = 0x5,

    /// `EXPIRED` — The publisher reached the timeout specified in SUBSCRIBE_OK.
    Expired = 0x6,

    /// `UPDATE_FAILED` — REQUEST_UPDATE failed on this subscription (see Section 10.9).
    UpdateFailed = 0x8,

    /// `EXCESSIVE_LOAD` — The publisher is overloaded and is terminating the subscription.
    ExcessiveLoad = 0x9,

    /// `MALFORMED_TRACK` — A relay publisher detected that the track was malformed (see Section
    /// 2.4.2).
    MalformedTrack = 0x12,
}

/// Stream reset error codes (draft-20 Section 15.11.4).
///
/// Section 3.3.4 says the application SHOULD use a relevant code from this registry when
/// resetting, or sending STOP_SENDING on, any stream — data streams and request streams alike.
/// The per-code definitions are in that same section.
///
/// Drafts 14 through 17, draft-17 Section 14.5.4 among them, titled this
/// registry "Data Stream Reset Error Codes" and this crate names those drafts'
/// enums `DataStreamResetErrorCode`. Draft-18 renamed it and widened it beyond
/// data streams; draft-20 keeps both the name and the wider scope, so this enum
/// takes that title.
///
/// The registry also reserves the code points `0x7f * N + 0x9D` for greasing (draft-20 Section
/// 14). That is a range rather than an assignment, so it has no variant here and `from_u64`
/// reports it as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamResetErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific error.
    InternalError = 0x0,

    /// `CANCELLED` — The stream was cancelled by either endpoint. For Subscriptions, PUBLISH_DONE
    /// (Section 10.12) may have a more detailed status code.
    Cancelled = 0x1,

    /// `DELIVERY_TIMEOUT` — A delivery timeout (Section 8) was exceeded for this stream.
    DeliveryTimeout = 0x2,

    /// `SESSION_CLOSED` — The session is being closed.
    SessionClosed = 0x3,

    /// `GOING_AWAY` — The endpoint is rejecting this request because it has sent or received a
    /// GOAWAY.
    GoingAway = 0x4,

    /// `TOO_FAR_BEHIND` — The corresponding subscription has exceeded the publisher's resource
    /// limits and is being terminated (see Section 8).
    TooFarBehind = 0x5,

    /// `UNKNOWN_OBJECT_STATUS` — In response to a FETCH, the publisher is unable to determine the
    /// status of the next Object in the requested range.
    UnknownObjectStatus = 0x6,

    /// `EXPIRED_AUTH_TOKEN` — The authorization token for the request has expired.
    ExpiredAuthToken = 0x7,

    /// `EXCESSIVE_LOAD` — The endpoint is overloaded and is resetting this stream.
    ExcessiveLoad = 0x9,

    /// `MALFORMED_TRACK` — A relay publisher detected that the track was malformed (see Section
    /// 2.4.2).
    MalformedTrack = 0x12,
}

impl SessionErrorCode {
    /// Every Session Error Code draft-20 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach — that this is the set `from_u64`
    /// answers to, and that none of it lands in the range the draft reserves
    /// for greasing.
    pub const ALL: &[SessionErrorCode] = &[
        SessionErrorCode::NoError,
        SessionErrorCode::InternalError,
        SessionErrorCode::Unauthorized,
        SessionErrorCode::ProtocolViolation,
        SessionErrorCode::InvalidRequestId,
        SessionErrorCode::DuplicateTrackAlias,
        SessionErrorCode::KeyValueFormattingError,
        SessionErrorCode::InvalidPath,
        SessionErrorCode::MalformedPath,
        SessionErrorCode::GoawayTimeout,
        SessionErrorCode::ControlMessageTimeout,
        SessionErrorCode::DataStreamTimeout,
        SessionErrorCode::AuthTokenCacheOverflow,
        SessionErrorCode::DuplicateAuthTokenAlias,
        SessionErrorCode::MalformedAuthToken,
        SessionErrorCode::UnknownAuthTokenAlias,
        SessionErrorCode::ExpiredAuthToken,
        SessionErrorCode::InvalidAuthority,
        SessionErrorCode::MalformedAuthority,
        SessionErrorCode::TooManyRequestUpdates,
    ];

    /// Convert a raw u64 to a `SessionErrorCode`, if the draft assigns that code point.
    ///
    /// Returns `None` for any unassigned value, including the greasing range, so
    /// that a peer sending a code this draft does not define cannot break decoding.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SessionErrorCode::NoError),
            0x1 => Some(SessionErrorCode::InternalError),
            0x2 => Some(SessionErrorCode::Unauthorized),
            0x3 => Some(SessionErrorCode::ProtocolViolation),
            0x4 => Some(SessionErrorCode::InvalidRequestId),
            0x5 => Some(SessionErrorCode::DuplicateTrackAlias),
            0x6 => Some(SessionErrorCode::KeyValueFormattingError),
            0x8 => Some(SessionErrorCode::InvalidPath),
            0x9 => Some(SessionErrorCode::MalformedPath),
            0x10 => Some(SessionErrorCode::GoawayTimeout),
            0x11 => Some(SessionErrorCode::ControlMessageTimeout),
            0x12 => Some(SessionErrorCode::DataStreamTimeout),
            0x13 => Some(SessionErrorCode::AuthTokenCacheOverflow),
            0x14 => Some(SessionErrorCode::DuplicateAuthTokenAlias),
            0x16 => Some(SessionErrorCode::MalformedAuthToken),
            0x17 => Some(SessionErrorCode::UnknownAuthTokenAlias),
            0x18 => Some(SessionErrorCode::ExpiredAuthToken),
            0x19 => Some(SessionErrorCode::InvalidAuthority),
            0x1A => Some(SessionErrorCode::MalformedAuthority),
            0x1B => Some(SessionErrorCode::TooManyRequestUpdates),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl RequestErrorCode {
    /// Every Request Error Code draft-20 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach — that this is the set `from_u64`
    /// answers to, and that none of it lands in the range the draft reserves
    /// for greasing.
    pub const ALL: &[RequestErrorCode] = &[
        RequestErrorCode::InternalError,
        RequestErrorCode::Unauthorized,
        RequestErrorCode::Timeout,
        RequestErrorCode::NotSupported,
        RequestErrorCode::MalformedAuthToken,
        RequestErrorCode::ExpiredAuthToken,
        RequestErrorCode::GoingAway,
        RequestErrorCode::ExcessiveLoad,
        RequestErrorCode::DoesNotExist,
        RequestErrorCode::InvalidRange,
        RequestErrorCode::MalformedTrack,
        RequestErrorCode::Uninterested,
        RequestErrorCode::PrefixOverlap,
        RequestErrorCode::NamespaceTooLarge,
        RequestErrorCode::UnsupportedExtension,
        RequestErrorCode::Redirect,
        RequestErrorCode::ConflictingFilters,
        RequestErrorCode::InvalidFilter,
    ];

    /// Convert a raw u64 to a `RequestErrorCode`, if the draft assigns that code point.
    ///
    /// Returns `None` for any unassigned value, including the greasing range, so
    /// that a peer sending a code this draft does not define cannot break decoding.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(RequestErrorCode::InternalError),
            0x1 => Some(RequestErrorCode::Unauthorized),
            0x2 => Some(RequestErrorCode::Timeout),
            0x3 => Some(RequestErrorCode::NotSupported),
            0x4 => Some(RequestErrorCode::MalformedAuthToken),
            0x5 => Some(RequestErrorCode::ExpiredAuthToken),
            0x6 => Some(RequestErrorCode::GoingAway),
            0x9 => Some(RequestErrorCode::ExcessiveLoad),
            0x10 => Some(RequestErrorCode::DoesNotExist),
            0x11 => Some(RequestErrorCode::InvalidRange),
            0x12 => Some(RequestErrorCode::MalformedTrack),
            0x20 => Some(RequestErrorCode::Uninterested),
            0x30 => Some(RequestErrorCode::PrefixOverlap),
            0x31 => Some(RequestErrorCode::NamespaceTooLarge),
            0x33 => Some(RequestErrorCode::UnsupportedExtension),
            0x34 => Some(RequestErrorCode::Redirect),
            0x35 => Some(RequestErrorCode::ConflictingFilters),
            0x36 => Some(RequestErrorCode::InvalidFilter),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishDoneStatusCode {
    /// Every PUBLISH_DONE Status Code draft-20 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach — that this is the set `from_u64`
    /// answers to, and that none of it lands in the range the draft reserves
    /// for greasing.
    pub const ALL: &[PublishDoneStatusCode] = &[
        PublishDoneStatusCode::InternalError,
        PublishDoneStatusCode::Unauthorized,
        PublishDoneStatusCode::TrackEnded,
        PublishDoneStatusCode::GoingAway,
        PublishDoneStatusCode::TooFarBehind,
        PublishDoneStatusCode::Expired,
        PublishDoneStatusCode::UpdateFailed,
        PublishDoneStatusCode::ExcessiveLoad,
        PublishDoneStatusCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `PublishDoneStatusCode`, if the draft assigns that code point.
    ///
    /// Returns `None` for any unassigned value, including the greasing range, so
    /// that a peer sending a code this draft does not define cannot break decoding.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(PublishDoneStatusCode::InternalError),
            0x1 => Some(PublishDoneStatusCode::Unauthorized),
            0x2 => Some(PublishDoneStatusCode::TrackEnded),
            0x4 => Some(PublishDoneStatusCode::GoingAway),
            0x5 => Some(PublishDoneStatusCode::TooFarBehind),
            0x6 => Some(PublishDoneStatusCode::Expired),
            0x8 => Some(PublishDoneStatusCode::UpdateFailed),
            0x9 => Some(PublishDoneStatusCode::ExcessiveLoad),
            0x12 => Some(PublishDoneStatusCode::MalformedTrack),
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl StreamResetErrorCode {
    /// Every Stream Reset Error Code draft-20 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach — that this is the set `from_u64`
    /// answers to, and that none of it lands in the range the draft reserves
    /// for greasing.
    pub const ALL: &[StreamResetErrorCode] = &[
        StreamResetErrorCode::InternalError,
        StreamResetErrorCode::Cancelled,
        StreamResetErrorCode::DeliveryTimeout,
        StreamResetErrorCode::SessionClosed,
        StreamResetErrorCode::GoingAway,
        StreamResetErrorCode::TooFarBehind,
        StreamResetErrorCode::UnknownObjectStatus,
        StreamResetErrorCode::ExpiredAuthToken,
        StreamResetErrorCode::ExcessiveLoad,
        StreamResetErrorCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `StreamResetErrorCode`, if the draft assigns that code point.
    ///
    /// Returns `None` for any unassigned value, including the greasing range, so
    /// that a peer sending a code this draft does not define cannot break decoding.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(StreamResetErrorCode::InternalError),
            0x1 => Some(StreamResetErrorCode::Cancelled),
            0x2 => Some(StreamResetErrorCode::DeliveryTimeout),
            0x3 => Some(StreamResetErrorCode::SessionClosed),
            0x4 => Some(StreamResetErrorCode::GoingAway),
            0x5 => Some(StreamResetErrorCode::TooFarBehind),
            0x6 => Some(StreamResetErrorCode::UnknownObjectStatus),
            0x7 => Some(StreamResetErrorCode::ExpiredAuthToken),
            0x9 => Some(StreamResetErrorCode::ExcessiveLoad),
            0x12 => Some(StreamResetErrorCode::MalformedTrack),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

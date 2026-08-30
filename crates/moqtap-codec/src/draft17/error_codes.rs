//! Error and status code registries defined by draft-17.
//!
//! One enum per IANA registry in Section 14.5 of the draft. Variant names are
//! the draft's own ALLCAPS names rewritten in Rust convention; each variant's
//! doc comment repeats the draft spelling so the mapping stays checkable.
//!
//! Codes are per-registry, not global, and the overlap is not benign: every
//! value from `0x0` to `0x5` is assigned in all four registries, with a
//! different meaning in nearly every cell.
//!
//! | code | session termination | REQUEST_ERROR | PUBLISH_DONE | data stream reset |
//! |------|---------------------|---------------|--------------|-------------------|
//! | 0x0  | `NO_ERROR` | `INTERNAL_ERROR` | `INTERNAL_ERROR` | `INTERNAL_ERROR` |
//! | 0x1  | `INTERNAL_ERROR` | `UNAUTHORIZED` | `UNAUTHORIZED` | `CANCELLED` |
//! | 0x2  | `UNAUTHORIZED` | `TIMEOUT` | `TRACK_ENDED` | `DELIVERY_TIMEOUT` |
//! | 0x3  | `PROTOCOL_VIOLATION` | `NOT_SUPPORTED` | `SUBSCRIPTION_ENDED` | `SESSION_CLOSED` |
//! | 0x4  | `INVALID_REQUEST_ID` | `MALFORMED_AUTH_TOKEN` | `GOING_AWAY` | `UNKNOWN_OBJECT_STATUS` |
//! | 0x5  | `DUPLICATE_TRACK_ALIAS` | `EXPIRED_AUTH_TOKEN` | `EXPIRED` | `TOO_FAR_BEHIND` |
//! | 0x9  | `MALFORMED_PATH` | `EXCESSIVE_LOAD` | `EXCESSIVE_LOAD` | `EXCESSIVE_LOAD` |
//! | 0x12 | `DATA_STREAM_TIMEOUT` | `MALFORMED_TRACK` | `MALFORMED_TRACK` | `MALFORMED_TRACK` |
//! | 0x19 | `INVALID_AUTHORITY` | `DUPLICATE_SUBSCRIPTION` | unassigned | unassigned |
//!
//! Carrying a value from one of these types to another is therefore always a
//! bug, even where the two happen to share a variant name. These type names
//! also recur in the sibling draft modules over different assignments, so an
//! import repointed at another draft still compiles while changing meaning.
//!
//! Every table's last row reserves `0x7f * N + 0x9D` for greasing (Section 13).
//! Those code points carry no semantics, get no variants here, and are rejected
//! by `from_u64` like any other unassigned value. Note that Section 13 of this
//! draft gives the formula as `0x7f * N + 0x9D` but illustrates it with the
//! sequence `0x9D, 0xBC, ...`, whose step is `0x1f` rather than `0x7f`; drafts
//! 18 and 19 keep the same formula and correct the illustration to
//! `0x9D, 0x11C, ...`. The formula is treated as normative. Either reading
//! leaves this module unchanged, since no greasing value gets a variant.

/// Session Termination Error Codes (draft-17, Section 14.5.1).
///
/// The registry table is in Section 14.5.1; the per-code descriptions carried on
/// the variants below are the ones given in Section 3.5 of the draft.
///
/// The table's last row reserves `0x7f * N + 0x9D` for greasing (Section 13).
/// Greasing code points are not a contiguous range and carry no semantics a
/// decoder can act on, so they get no variants and `from_u64` rejects them like
/// any other unassigned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `NO_ERROR` — The session is being terminated without an error.
    NoError = 0x0,
    /// `INTERNAL_ERROR` — An implementation specific error occurred.
    InternalError = 0x1,
    /// `UNAUTHORIZED` — The client is not authorized to establish a session.
    Unauthorized = 0x2,
    /// `PROTOCOL_VIOLATION` — The remote endpoint performed an action that was disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `INVALID_REQUEST_ID` — The endpoint received a Request ID with an incorrect least significant bit for the sender, or a duplicate Request ID. See Section 9.1.
    InvalidRequestId = 0x4,
    /// `DUPLICATE_TRACK_ALIAS` — The endpoint attempted to use a Track Alias that was already in use.
    DuplicateTrackAlias = 0x5,
    /// `KEY_VALUE_FORMATTING_ERROR` — The key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,
    /// `INVALID_REQUIRED_REQUEST_ID` — The endpoint received a Required Request ID Delta that results in an invalid Request ID. See Section 9.2.
    InvalidRequiredRequestId = 0x7,
    /// `INVALID_PATH` — The PATH parameter was used by a server, on a WebTransport session, or the server does not support the path.
    InvalidPath = 0x8,
    /// `MALFORMED_PATH` — The PATH parameter does not conform to the rules in Section 9.4.1.2.
    MalformedPath = 0x9,
    /// `GOAWAY_TIMEOUT` — The session was closed because the peer took too long to close the session in response to a GOAWAY (Section 9.5) message. See session migration (Section 3.6).
    GoawayTimeout = 0x10,
    /// `CONTROL_MESSAGE_TIMEOUT` — The session was closed because the peer took too long to respond to a control message.
    ControlMessageTimeout = 0x11,
    /// `DATA_STREAM_TIMEOUT` — The session was closed because the peer took too long to send data expected on an open Data Stream (see Section 10). This includes fields of a stream header or an object header within a data stream. If an endpoint times out waiting for a new object header on an open subgroup stream, it MAY send a STOP_SENDING on that stream or terminate the subscription.
    DataStreamTimeout = 0x12,
    /// `AUTH_TOKEN_CACHE_OVERFLOW` — The Session limit Section 9.4.1.3 of the size of all registered Authorization tokens has been exceeded.
    AuthTokenCacheOverflow = 0x13,
    /// `DUPLICATE_AUTH_TOKEN_ALIAS` — Authorization Token attempted to register an Alias that was in use (see Section 9.3.2).
    DuplicateAuthTokenAlias = 0x14,
    /// `VERSION_NEGOTIATION_FAILED` — The client didn't offer a version supported by the server.
    VersionNegotiationFailed = 0x15,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during registration (see Section 9.3.2).
    MalformedAuthToken = 0x16,
    /// `UNKNOWN_AUTH_TOKEN_ALIAS` — No registered token found for the provided Alias (see Section 9.3.2).
    UnknownAuthTokenAlias = 0x17,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 9.3.2).
    ExpiredAuthToken = 0x18,
    /// `INVALID_AUTHORITY` — The specified AUTHORITY does not correspond to this server or cannot be used in this context.
    InvalidAuthority = 0x19,
    /// `MALFORMED_AUTHORITY` — The AUTHORITY value is syntactically invalid.
    MalformedAuthority = 0x1A,
}

/// REQUEST_ERROR Codes (draft-17, Section 14.5.2).
///
/// The registry table is in Section 14.5.2; the per-code descriptions carried on
/// the variants below are the ones given in Section 9.7 of the draft.
///
/// The table's last row reserves `0x7f * N + 0x9D` for greasing (Section 13).
/// Greasing code points are not a contiguous range and carry no semantics a
/// decoder can act on, so they get no variants and `from_u64` rejects them like
/// any other unassigned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RequestErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is not authorized to perform the requested action on the given track. This might be retryable if the authorization token is not yet valid.
    Unauthorized = 0x1,
    /// `TIMEOUT` — The subscription could not be completed before an implementation specific timeout. For example, a relay could not establish an upstream subscription within the timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — The endpoint does not support the type of request.
    NotSupported = 0x3,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during registration (see Section 9.3.2).
    MalformedAuthToken = 0x4,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 9.3.2).
    ExpiredAuthToken = 0x5,
    /// `GOING_AWAY` — The endpoint has received a GOAWAY and MAY reject new requests.
    GoingAway = 0x6,
    /// `EXCESSIVE_LOAD` — The responder is overloaded and cannot process the request at this time. The sender SHOULD use the Retry Interval to indicate when the request can be retried.
    ExcessiveLoad = 0x9,
    /// `DOES_NOT_EXIST` — The track or namespace is not available at the publisher.
    DoesNotExist = 0x10,
    /// `INVALID_RANGE` — In response to SUBSCRIBE or FETCH, specified Filter or range of Locations cannot be satisfied.
    InvalidRange = 0x11,
    /// `MALFORMED_TRACK` — In response to a FETCH, a relay publisher detected the track was malformed (see Section 2.4.2).
    MalformedTrack = 0x12,
    /// `DUPLICATE_SUBSCRIPTION` — The PUBLISH or SUBSCRIBE request attempted to create a subscription to a Track with the same role as an existing subscription.
    DuplicateSubscription = 0x19,
    /// `UNINTERESTED` — The subscriber is not interested in the track or namespace.
    Uninterested = 0x20,
    /// `PREFIX_OVERLAP` — In response to SUBSCRIBE_NAMESPACE, the namespace prefix overlaps with another SUBSCRIBE_NAMESPACE in the same session.
    PrefixOverlap = 0x30,
    /// `NAMESPACE_TOO_LARGE` — In response to SUBSCRIBE_NAMESPACE, the namespace prefix matches more publishers than the relay is willing to enumerate.
    NamespaceTooLarge = 0x31,
    /// `INVALID_JOINING_REQUEST_ID` — In response to a Joining FETCH, the referenced Request ID is not an Established Subscription.
    InvalidJoiningRequestId = 0x32,
}

/// PUBLISH_DONE Codes (draft-17, Section 14.5.3).
///
/// The registry table is in Section 14.5.3; the per-code descriptions carried on
/// the variants below are the ones given in Section 9.13 of the draft.
///
/// The table's last row reserves `0x7f * N + 0x9D` for greasing (Section 13).
/// Greasing code points are not a contiguous range and carry no semantics a
/// decoder can act on, so they get no variants and `from_u64` rejects them like
/// any other unassigned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishDoneStatusCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is no longer authorized to subscribe to the given track.
    Unauthorized = 0x1,
    /// `TRACK_ENDED` — The track is no longer being published.
    TrackEnded = 0x2,
    /// `SUBSCRIPTION_ENDED` — The publisher reached the end of an associated subscription filter.
    SubscriptionEnded = 0x3,
    /// `GOING_AWAY` — The subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,
    /// `EXPIRED` — The publisher reached the timeout specified in SUBSCRIBE_OK.
    Expired = 0x5,
    /// `TOO_FAR_BEHIND` — The publisher's queue of objects to be sent to the given subscriber exceeds its implementation defined limit.
    TooFarBehind = 0x6,
    /// `UPDATE_FAILED` — REQUEST_UPDATE failed on this subscription (see Section 9.10).
    UpdateFailed = 0x8,
    /// `EXCESSIVE_LOAD` — The publisher is overloaded and is terminating the subscription.
    ExcessiveLoad = 0x9,
    /// `MALFORMED_TRACK` — A relay publisher detected that the track was malformed (see Section 2.4.2).
    MalformedTrack = 0x12,
}

/// Data Stream Reset Error Codes (draft-17, Section 14.5.4).
///
/// The registry table is in Section 14.5.4; the per-code descriptions carried on
/// the variants below are the ones given in Section 10.4.3 of the draft.
///
/// The table's last row reserves `0x7f * N + 0x9D` for greasing (Section 13).
/// Greasing code points are not a contiguous range and carry no semantics a
/// decoder can act on, so they get no variants and `from_u64` rejects them like
/// any other unassigned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DataStreamResetErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific error.
    InternalError = 0x0,
    /// `CANCELLED` — The subscriber or publisher cancelled the Request. For Subscriptions, PUBLISH_DONE (Section 9.13) will have a more detailed status code.
    Cancelled = 0x1,
    /// `DELIVERY_TIMEOUT` — The DELIVERY TIMEOUT Section 9.3.3 was exceeded for this stream.
    DeliveryTimeout = 0x2,
    /// `SESSION_CLOSED` — The publisher session is being closed.
    SessionClosed = 0x3,
    /// `UNKNOWN_OBJECT_STATUS` — In response to a FETCH, the publisher is unable to determine the Status of the next Object in the requested range.
    UnknownObjectStatus = 0x4,
    /// `TOO_FAR_BEHIND` — The corresponding subscription has exceeded the publisher's resource limits and is being terminated (see Section 9.3.3).
    TooFarBehind = 0x5,
    /// `EXCESSIVE_LOAD` — The publisher is overloaded and is resetting this stream.
    ExcessiveLoad = 0x9,
    /// `MALFORMED_TRACK` — A relay publisher detected that the track was malformed (see Section 2.4.2).
    MalformedTrack = 0x12,
}

impl SessionErrorCode {
    /// Every Session Error Code draft-17 assigns, in ascending wire order.
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
        SessionErrorCode::InvalidRequiredRequestId,
        SessionErrorCode::InvalidPath,
        SessionErrorCode::MalformedPath,
        SessionErrorCode::GoawayTimeout,
        SessionErrorCode::ControlMessageTimeout,
        SessionErrorCode::DataStreamTimeout,
        SessionErrorCode::AuthTokenCacheOverflow,
        SessionErrorCode::DuplicateAuthTokenAlias,
        SessionErrorCode::VersionNegotiationFailed,
        SessionErrorCode::MalformedAuthToken,
        SessionErrorCode::UnknownAuthTokenAlias,
        SessionErrorCode::ExpiredAuthToken,
        SessionErrorCode::InvalidAuthority,
        SessionErrorCode::MalformedAuthority,
    ];

    /// Convert a raw u64 to a `SessionErrorCode`, if valid.
    ///
    /// Returns `None` for any code draft-17 does not define, including the
    /// greasing range. Unknown codes arrive on the wire routinely and are not
    /// an error for the decoder.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SessionErrorCode::NoError),
            0x1 => Some(SessionErrorCode::InternalError),
            0x2 => Some(SessionErrorCode::Unauthorized),
            0x3 => Some(SessionErrorCode::ProtocolViolation),
            0x4 => Some(SessionErrorCode::InvalidRequestId),
            0x5 => Some(SessionErrorCode::DuplicateTrackAlias),
            0x6 => Some(SessionErrorCode::KeyValueFormattingError),
            0x7 => Some(SessionErrorCode::InvalidRequiredRequestId),
            0x8 => Some(SessionErrorCode::InvalidPath),
            0x9 => Some(SessionErrorCode::MalformedPath),
            0x10 => Some(SessionErrorCode::GoawayTimeout),
            0x11 => Some(SessionErrorCode::ControlMessageTimeout),
            0x12 => Some(SessionErrorCode::DataStreamTimeout),
            0x13 => Some(SessionErrorCode::AuthTokenCacheOverflow),
            0x14 => Some(SessionErrorCode::DuplicateAuthTokenAlias),
            0x15 => Some(SessionErrorCode::VersionNegotiationFailed),
            0x16 => Some(SessionErrorCode::MalformedAuthToken),
            0x17 => Some(SessionErrorCode::UnknownAuthTokenAlias),
            0x18 => Some(SessionErrorCode::ExpiredAuthToken),
            0x19 => Some(SessionErrorCode::InvalidAuthority),
            0x1A => Some(SessionErrorCode::MalformedAuthority),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl RequestErrorCode {
    /// Every Request Error Code draft-17 assigns, in ascending wire order.
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
        RequestErrorCode::DuplicateSubscription,
        RequestErrorCode::Uninterested,
        RequestErrorCode::PrefixOverlap,
        RequestErrorCode::NamespaceTooLarge,
        RequestErrorCode::InvalidJoiningRequestId,
    ];

    /// Convert a raw u64 to a `RequestErrorCode`, if valid.
    ///
    /// Returns `None` for any code draft-17 does not define, including the
    /// greasing range. Unknown codes arrive on the wire routinely and are not
    /// an error for the decoder.
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
            0x19 => Some(RequestErrorCode::DuplicateSubscription),
            0x20 => Some(RequestErrorCode::Uninterested),
            0x30 => Some(RequestErrorCode::PrefixOverlap),
            0x31 => Some(RequestErrorCode::NamespaceTooLarge),
            0x32 => Some(RequestErrorCode::InvalidJoiningRequestId),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishDoneStatusCode {
    /// Every PUBLISH_DONE Status Code draft-17 assigns, in ascending wire order.
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
        PublishDoneStatusCode::SubscriptionEnded,
        PublishDoneStatusCode::GoingAway,
        PublishDoneStatusCode::Expired,
        PublishDoneStatusCode::TooFarBehind,
        PublishDoneStatusCode::UpdateFailed,
        PublishDoneStatusCode::ExcessiveLoad,
        PublishDoneStatusCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `PublishDoneStatusCode`, if valid.
    ///
    /// Returns `None` for any code draft-17 does not define, including the
    /// greasing range. Unknown codes arrive on the wire routinely and are not
    /// an error for the decoder.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(PublishDoneStatusCode::InternalError),
            0x1 => Some(PublishDoneStatusCode::Unauthorized),
            0x2 => Some(PublishDoneStatusCode::TrackEnded),
            0x3 => Some(PublishDoneStatusCode::SubscriptionEnded),
            0x4 => Some(PublishDoneStatusCode::GoingAway),
            0x5 => Some(PublishDoneStatusCode::Expired),
            0x6 => Some(PublishDoneStatusCode::TooFarBehind),
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

impl DataStreamResetErrorCode {
    /// Every Data Stream Reset Error Code draft-17 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach — that this is the set `from_u64`
    /// answers to, and that none of it lands in the range the draft reserves
    /// for greasing.
    pub const ALL: &[DataStreamResetErrorCode] = &[
        DataStreamResetErrorCode::InternalError,
        DataStreamResetErrorCode::Cancelled,
        DataStreamResetErrorCode::DeliveryTimeout,
        DataStreamResetErrorCode::SessionClosed,
        DataStreamResetErrorCode::UnknownObjectStatus,
        DataStreamResetErrorCode::TooFarBehind,
        DataStreamResetErrorCode::ExcessiveLoad,
        DataStreamResetErrorCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `DataStreamResetErrorCode`, if valid.
    ///
    /// Returns `None` for any code draft-17 does not define, including the
    /// greasing range. Unknown codes arrive on the wire routinely and are not
    /// an error for the decoder.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(DataStreamResetErrorCode::InternalError),
            0x1 => Some(DataStreamResetErrorCode::Cancelled),
            0x2 => Some(DataStreamResetErrorCode::DeliveryTimeout),
            0x3 => Some(DataStreamResetErrorCode::SessionClosed),
            0x4 => Some(DataStreamResetErrorCode::UnknownObjectStatus),
            0x5 => Some(DataStreamResetErrorCode::TooFarBehind),
            0x9 => Some(DataStreamResetErrorCode::ExcessiveLoad),
            0x12 => Some(DataStreamResetErrorCode::MalformedTrack),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

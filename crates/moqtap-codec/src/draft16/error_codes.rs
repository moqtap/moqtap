//! Error and status code registries defined by MoQT draft-16.
//!
//! Each registry in Section 13.4 of the draft becomes one enum here. Variant names are
//! the draft's ALLCAPS names in UpperCamelCase; every variant's doc comment repeats the
//! draft spelling so the mapping stays checkable against the specification.
//!
//! `from_u64` returns `None` for a code this draft does not define. Peers legitimately
//! send codes from other draft versions or from private extensions, so an unknown code
//! is a decode result to handle, not a fault.

/// Session termination error codes.
///
/// Sent in the session-level close. Assigned in Section 13.4.1 of draft-16; the code definitions
/// are in Section 3.4.
///
/// Draft-16 assigns 0x0 through 0x9 and 0x10 through 0x1A. The gap at 0xA through 0xF is the
/// draft's own; this registry reserves no greasing range.
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
    /// `INVALID_REQUEST_ID` — The session was closed because the endpoint used a Request ID that
    /// was smaller than or equal to a previously received request ID, or the least-significant bit
    /// of the request ID was incorrect for the endpoint.
    InvalidRequestId = 0x4,
    /// `DUPLICATE_TRACK_ALIAS` — The endpoint attempted to use a Track Alias that was already in
    /// use.
    DuplicateTrackAlias = 0x5,
    /// `KEY_VALUE_FORMATTING_ERROR` — The key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,
    /// `TOO_MANY_REQUESTS` — The session was closed because the endpoint used a Request ID equal to
    /// or larger than the current Maximum Request ID.
    TooManyRequests = 0x7,
    /// `INVALID_PATH` — The PATH parameter was used by a server, on a WebTransport session, or the
    /// server does not support the path.
    InvalidPath = 0x8,
    /// `MALFORMED_PATH` — The PATH parameter does not conform to the rules in Section 9.3.1.2.
    MalformedPath = 0x9,
    /// `GOAWAY_TIMEOUT` — The session was closed because the peer took too long to close the
    /// session in response to a GOAWAY (Section 9.4) message. See session migration (Section 3.5).
    GoawayTimeout = 0x10,
    /// `CONTROL_MESSAGE_TIMEOUT` — The session was closed because the peer took too long to respond
    /// to a control message.
    ControlMessageTimeout = 0x11,
    /// `DATA_STREAM_TIMEOUT` — The session was closed because the peer took too long to send data
    /// expected on an open Data Stream (see Section 10). This includes fields of a stream header or
    /// an object header within a data stream. If an endpoint times out waiting for a new object
    /// header on an open subgroup stream, it MAY send a STOP_SENDING on that stream or terminate
    /// the subscription.
    DataStreamTimeout = 0x12,
    /// `AUTH_TOKEN_CACHE_OVERFLOW` — The Session limit Section 9.3.1.4 of the size of all
    /// registered Authorization tokens has been exceeded.
    AuthTokenCacheOverflow = 0x13,
    /// `DUPLICATE_AUTH_TOKEN_ALIAS` — Authorization Token attempted to register an Alias that was
    /// in use (see Section 9.2.2.1).
    DuplicateAuthTokenAlias = 0x14,
    /// `VERSION_NEGOTIATION_FAILED` — The client didn't offer a version supported by the server.
    VersionNegotiationFailed = 0x15,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during registration (see Section
    /// 9.2.2.1).
    MalformedAuthToken = 0x16,
    /// `UNKNOWN_AUTH_TOKEN_ALIAS` — No registered token found for the provided Alias (see Section
    /// 9.2.2.1).
    UnknownAuthTokenAlias = 0x17,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 9.2.2.1).
    ExpiredAuthToken = 0x18,
    /// `INVALID_AUTHORITY` — The specified AUTHORITY does not correspond to this server or cannot
    /// be used in this context.
    InvalidAuthority = 0x19,
    /// `MALFORMED_AUTHORITY` — The AUTHORITY value is syntactically invalid.
    MalformedAuthority = 0x1A,
}

/// Error codes carried in the REQUEST_ERROR control message.
///
/// REQUEST_ERROR answers any request (SUBSCRIBE, FETCH, PUBLISH, SUBSCRIBE_NAMESPACE,
/// PUBLISH_NAMESPACE, TRACK_STATUS). Most codes mean the same thing for every request type, but a
/// few are request-specific. Assigned in Section 13.4.2 of draft-16; the code definitions are in
/// Section 9.8.
///
/// PUBLISH_NAMESPACE_CANCEL carries a code from this registry as well: Section 9.24 states it uses
/// the same error codes as the REQUEST_ERROR that responds to PUBLISH_NAMESPACE.
///
/// Draft-16 assigns 0x0 through 0x5, 0x10 through 0x12, 0x19, 0x20, 0x30 and 0x32. The registry is
/// sparse by design and reserves no greasing range.
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
    /// 9.2.2.1).
    MalformedAuthToken = 0x4,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 9.2.2.1).
    ExpiredAuthToken = 0x5,
    /// `DOES_NOT_EXIST` — The track or namespace is not available at the publisher.
    DoesNotExist = 0x10,
    /// `INVALID_RANGE` — In response to SUBSCRIBE or FETCH, specified Filter or range of Locations
    /// cannot be satisfied.
    InvalidRange = 0x11,
    /// `MALFORMED_TRACK` — In response to a FETCH, a relay publisher detected the track was
    /// malformed (see Section 2.4.2).
    MalformedTrack = 0x12,
    /// `DUPLICATE_SUBSCRIPTION` — The PUBLISH or SUBSCRIBE request attempted to create a
    /// subscription to a Track with the same role as an existing subscription.
    DuplicateSubscription = 0x19,
    /// `UNINTERESTED` — The subscriber is not interested in the track or namespace.
    Uninterested = 0x20,
    /// `PREFIX_OVERLAP` — In response to SUBSCRIBE_NAMESPACE, the namespace prefix overlaps with
    /// another SUBSCRIBE_NAMESPACE in the same session.
    PrefixOverlap = 0x30,
    /// `INVALID_JOINING_REQUEST_ID` — In response to a Joining FETCH, the referenced Request ID is
    /// not an Established Subscription.
    InvalidJoiningRequestId = 0x32,
}

/// Status codes carried in the PUBLISH_DONE control message.
///
/// Indicates why a subscription ended, and whether ending it was an error. Assigned in Section
/// 13.4.3 of draft-16; the code definitions are in Section 9.15.
///
/// Draft-16 assigns 0x0 through 0x6, 0x8 and 0x12. The hole at 0x7 is real and deliberate:
/// draft-15 assigned 0x7 to MALFORMED_TRACK, and draft-16 moved that code to 0x12 without
/// reassigning 0x7. Section 9.15 also lists MALFORMED_TRACK ahead of UPDATE_FAILED in its prose
/// while the registry table lists both in numeric order; the two agree on names and values.
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
    /// `TOO_FAR_BEHIND` — The publisher's queue of objects to be sent to the given subscriber
    /// exceeds its implementation defined limit.
    TooFarBehind = 0x6,
    /// `UPDATE_FAILED` — REQUEST_UPDATE failed on this subscription (see Section 9.11).
    UpdateFailed = 0x8,
    /// `MALFORMED_TRACK` — A relay publisher detected that the track was malformed (see Section
    /// 2.4.2).
    MalformedTrack = 0x12,
}

/// Error codes carried in RESET_STREAM and RESET_STREAM_AT on a data stream.
///
/// Sent when a publisher closes a subgroup or fetch stream before delivering every object on it.
/// Assigned in Section 13.4.4 of draft-16; the code definitions are in Section 10.4.3. These are
/// application error codes carried on the stream, not session-level codes.
///
/// Draft-16 assigns 0x0 through 0x4 and 0x12, and reserves no greasing range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DataStreamResetErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific error.
    InternalError = 0x0,
    /// `CANCELLED` — The subscriber requested cancellation via UNSUBSCRIBE, FETCH_CANCEL or
    /// STOP_SENDING, or the publisher ended the subscription, in which case PUBLISH_DONE (Section
    /// 9.15) will have a more detailed status code.
    Cancelled = 0x1,
    /// `DELIVERY_TIMEOUT` — The DELIVERY TIMEOUT Section 9.2.2.2 was exceeded for this stream.
    DeliveryTimeout = 0x2,
    /// `SESSION_CLOSED` — The publisher session is being closed.
    SessionClosed = 0x3,
    /// `UNKNOWN_OBJECT_STATUS` — In response to a FETCH, the publisher is unable to determine the
    /// Status of the next Object in the requested range.
    UnknownObjectStatus = 0x4,
    /// `MALFORMED_TRACK` — A relay publisher detected that the track was malformed (see Section
    /// 2.4.2).
    MalformedTrack = 0x12,
}

impl SessionErrorCode {
    /// Every session termination code draft-16 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SessionErrorCode] = &[
        SessionErrorCode::NoError,
        SessionErrorCode::InternalError,
        SessionErrorCode::Unauthorized,
        SessionErrorCode::ProtocolViolation,
        SessionErrorCode::InvalidRequestId,
        SessionErrorCode::DuplicateTrackAlias,
        SessionErrorCode::KeyValueFormattingError,
        SessionErrorCode::TooManyRequests,
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

    /// Convert a raw u64 to a `SessionErrorCode`, if this draft defines that code.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SessionErrorCode::NoError),
            0x1 => Some(SessionErrorCode::InternalError),
            0x2 => Some(SessionErrorCode::Unauthorized),
            0x3 => Some(SessionErrorCode::ProtocolViolation),
            0x4 => Some(SessionErrorCode::InvalidRequestId),
            0x5 => Some(SessionErrorCode::DuplicateTrackAlias),
            0x6 => Some(SessionErrorCode::KeyValueFormattingError),
            0x7 => Some(SessionErrorCode::TooManyRequests),
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
    /// Every REQUEST_ERROR code draft-16 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[RequestErrorCode] = &[
        RequestErrorCode::InternalError,
        RequestErrorCode::Unauthorized,
        RequestErrorCode::Timeout,
        RequestErrorCode::NotSupported,
        RequestErrorCode::MalformedAuthToken,
        RequestErrorCode::ExpiredAuthToken,
        RequestErrorCode::DoesNotExist,
        RequestErrorCode::InvalidRange,
        RequestErrorCode::MalformedTrack,
        RequestErrorCode::DuplicateSubscription,
        RequestErrorCode::Uninterested,
        RequestErrorCode::PrefixOverlap,
        RequestErrorCode::InvalidJoiningRequestId,
    ];

    /// Convert a raw u64 to a `RequestErrorCode`, if this draft defines that code.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(RequestErrorCode::InternalError),
            0x1 => Some(RequestErrorCode::Unauthorized),
            0x2 => Some(RequestErrorCode::Timeout),
            0x3 => Some(RequestErrorCode::NotSupported),
            0x4 => Some(RequestErrorCode::MalformedAuthToken),
            0x5 => Some(RequestErrorCode::ExpiredAuthToken),
            0x10 => Some(RequestErrorCode::DoesNotExist),
            0x11 => Some(RequestErrorCode::InvalidRange),
            0x12 => Some(RequestErrorCode::MalformedTrack),
            0x19 => Some(RequestErrorCode::DuplicateSubscription),
            0x20 => Some(RequestErrorCode::Uninterested),
            0x30 => Some(RequestErrorCode::PrefixOverlap),
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
    /// Every PUBLISH_DONE status code draft-16 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[PublishDoneStatusCode] = &[
        PublishDoneStatusCode::InternalError,
        PublishDoneStatusCode::Unauthorized,
        PublishDoneStatusCode::TrackEnded,
        PublishDoneStatusCode::SubscriptionEnded,
        PublishDoneStatusCode::GoingAway,
        PublishDoneStatusCode::Expired,
        PublishDoneStatusCode::TooFarBehind,
        PublishDoneStatusCode::UpdateFailed,
        PublishDoneStatusCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `PublishDoneStatusCode`, if this draft defines that code.
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
    /// Every data stream reset code draft-16 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[DataStreamResetErrorCode] = &[
        DataStreamResetErrorCode::InternalError,
        DataStreamResetErrorCode::Cancelled,
        DataStreamResetErrorCode::DeliveryTimeout,
        DataStreamResetErrorCode::SessionClosed,
        DataStreamResetErrorCode::UnknownObjectStatus,
        DataStreamResetErrorCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `DataStreamResetErrorCode`, if this draft defines that code.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(DataStreamResetErrorCode::InternalError),
            0x1 => Some(DataStreamResetErrorCode::Cancelled),
            0x2 => Some(DataStreamResetErrorCode::DeliveryTimeout),
            0x3 => Some(DataStreamResetErrorCode::SessionClosed),
            0x4 => Some(DataStreamResetErrorCode::UnknownObjectStatus),
            0x12 => Some(DataStreamResetErrorCode::MalformedTrack),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

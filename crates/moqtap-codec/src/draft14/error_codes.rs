//! Error, status and stream-reset code registries defined by
//! draft-ietf-moq-transport-14.
//!
//! One enum per registry in the IANA Considerations section (Section 13.1). The
//! registry tables list only Name, Code and Specification; the per-code prose in
//! the variant docs is taken from the section each row cites.
//!
//! `from_u64` returns `None` for any value the draft does not assign. A peer may
//! legitimately send a code from a later draft or a private extension, and an
//! unrecognized code must not be a decode failure at this layer.
//!
//! draft-14 assigns no reserved-for-greasing ranges in these registries; every
//! row is a single code point.

/// Session termination error codes, from the "Session Termination Error Codes"
/// registry in draft-ietf-moq-transport-14 Section 13.1.1. Every row cites
/// Section 3.4 (Termination), the source of the descriptions below.
///
/// Carried in the QUIC CONNECTION_CLOSE frame or the WebTransport
/// CLOSE_WEBTRANSPORT_SESSION capsule. The draft assigns 0x0 through 0x9 and
/// 0x10 through 0x1A; 0xA through 0xF are unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `NO_ERROR` — The session is being terminated without an error.
    NoError = 0x0,
    /// `INTERNAL_ERROR` — An implementation specific error occurred.
    InternalError = 0x1,
    /// `UNAUTHORIZED` — The client is not authorized to establish a session.
    Unauthorized = 0x2,
    /// `PROTOCOL_VIOLATION` — The remote endpoint performed an action that was
    /// disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `INVALID_REQUEST_ID` — The session was closed because the endpoint used a
    /// Request ID that was smaller than or equal to a previously received
    /// request ID, or the least-significant bit of the request ID was incorrect
    /// for the endpoint.
    ///
    /// This is a monotonicity and parity rule, not a lookup failure: the code
    /// does not mean the Request ID was unknown.
    InvalidRequestId = 0x4,
    /// `DUPLICATE_TRACK_ALIAS` — The endpoint attempted to use a Track Alias
    /// that was already in use.
    DuplicateTrackAlias = 0x5,
    /// `KEY_VALUE_FORMATTING_ERROR` — The key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,
    /// `TOO_MANY_REQUESTS` — The session was closed because the endpoint used a
    /// Request ID equal to or larger than the current Maximum Request ID.
    ///
    /// This is a ceiling on the Request ID value, not a limit on how many
    /// requests are outstanding at once.
    TooManyRequests = 0x7,
    /// `INVALID_PATH` — The PATH parameter was used by a server, on a
    /// WebTransport session, or the server does not support the path.
    ///
    /// Two of those three conditions are about where PATH appeared rather than
    /// about the path value itself.
    InvalidPath = 0x8,
    /// `MALFORMED_PATH` — The PATH parameter does not conform to the rules in
    /// Section 9.3.2.2.
    MalformedPath = 0x9,
    /// `GOAWAY_TIMEOUT` — The session was closed because the peer took too long
    /// to close the session in response to a GOAWAY (Section 9.4) message. See
    /// session migration (Section 3.5).
    GoawayTimeout = 0x10,
    /// `CONTROL_MESSAGE_TIMEOUT` — The session was closed because the peer took
    /// too long to respond to a control message.
    ControlMessageTimeout = 0x11,
    /// `DATA_STREAM_TIMEOUT` — The session was closed because the peer took too
    /// long to send data expected on an open Data Stream (see Section 10). This
    /// includes fields of a stream header or an object header within a data
    /// stream. If an endpoint times out waiting for a new object header on an
    /// open subgroup stream, it MAY send a STOP_SENDING on that stream or
    /// terminate the subscription.
    DataStreamTimeout = 0x12,
    /// `AUTH_TOKEN_CACHE_OVERFLOW` — The Session limit Section 9.3.2.4 of the
    /// size of all registered Authorization tokens has been exceeded.
    ///
    /// The limit is on total serialized size, not on the number of tokens. The
    /// missing parentheses around the cross-reference are as printed in the
    /// draft.
    AuthTokenCacheOverflow = 0x13,
    /// `DUPLICATE_AUTH_TOKEN_ALIAS` — Authorization Token attempted to register
    /// an Alias that was in use (see Section 9.2.1.1).
    DuplicateAuthTokenAlias = 0x14,
    /// `VERSION_NEGOTIATION_FAILED` — The client didn't offer a version
    /// supported by the server.
    VersionNegotiationFailed = 0x15,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during
    /// registration (see Section 9.2.1.1).
    MalformedAuthToken = 0x16,
    /// `UNKNOWN_AUTH_TOKEN_ALIAS` — No registered token found for the provided
    /// Alias (see Section 9.2.1.1).
    UnknownAuthTokenAlias = 0x17,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired
    /// (Section 9.2.1.1).
    ExpiredAuthToken = 0x18,
    /// `INVALID_AUTHORITY` — The specified AUTHORITY does not correspond to this
    /// server or cannot be used in this context.
    InvalidAuthority = 0x19,
    /// `MALFORMED_AUTHORITY` — The AUTHORITY value is syntactically invalid.
    MalformedAuthority = 0x1A,
}

/// SUBSCRIBE_ERROR codes, from the "SUBSCRIBE_ERROR Codes" registry in
/// draft-ietf-moq-transport-14 Section 13.1.2. Every row cites Section 9.9
/// (SUBSCRIBE_ERROR), the source of the descriptions below.
///
/// This type decodes SUBSCRIBE_ERROR only. It is not a shared request-level
/// registry: draft-14 gives each request-scoped message its own registry, and
/// they disagree at 0x4. Decoding another message's error code with this type
/// silently produces the wrong variant.
///
/// | code | SUBSCRIBE_ERROR | PUBLISH_ERROR | FETCH_ERROR | ANNOUNCE_ERROR | SUBSCRIBE_NAMESPACE_ERROR |
/// |---|---|---|---|---|---|
/// | 0x4 | `TRACK_DOES_NOT_EXIST` | `UNINTERESTED` | `TRACK_DOES_NOT_EXIST` | `UNINTERESTED` | `NAMESPACE_PREFIX_UNKNOWN` |
///
/// Use [`PublishErrorCode`], [`FetchErrorCode`], [`AnnounceErrorCode`] and
/// [`SubscribeNamespaceErrorCode`] for those messages.
///
/// Draft-15 merges these five registries into one, carried there as
/// `RequestErrorCode`. Draft-14 has no REQUEST_ERROR message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is not authorized to subscribe to the
    /// given track.
    Unauthorized = 0x1,
    /// `TIMEOUT` — The subscription could not be completed before an
    /// implementation specific timeout. For example, a relay could not establish
    /// an upstream subscription within the timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — The endpoint does not support the SUBSCRIBE method.
    NotSupported = 0x3,
    /// `TRACK_DOES_NOT_EXIST` — The requested track is not available at the
    /// publisher.
    TrackDoesNotExist = 0x4,
    /// `INVALID_RANGE` — The end of the SUBSCRIBE range is earlier than the
    /// beginning, or the end of the range has already been published.
    InvalidRange = 0x5,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during
    /// registration (see Section 9.2.1.1).
    MalformedAuthToken = 0x10,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired
    /// (Section 9.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// PUBLISH_DONE status codes, from the "PUBLISH_DONE Codes" registry in
/// draft-ietf-moq-transport-14 Section 13.1.3. Every row cites Section 9.12
/// (PUBLISH_DONE), the source of the descriptions below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishDoneStatusCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is no longer authorized to subscribe to
    /// the given track.
    Unauthorized = 0x1,
    /// `TRACK_ENDED` — The track is no longer being published.
    TrackEnded = 0x2,
    /// `SUBSCRIPTION_ENDED` — The publisher reached the end of an associated
    /// Subscribe filter.
    SubscriptionEnded = 0x3,
    /// `GOING_AWAY` — The subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,
    /// `EXPIRED` — The publisher reached the timeout specified in SUBSCRIBE_OK.
    Expired = 0x5,
    /// `TOO_FAR_BEHIND` — The publisher's queue of objects to be sent to the
    /// given subscriber exceeds its implementation defined limit.
    TooFarBehind = 0x6,
    /// `MALFORMED_TRACK` — A relay publisher detected the track was malformed
    /// (see Section 2.5).
    MalformedTrack = 0x7,
}

/// PUBLISH_ERROR codes, from the "PUBLISH_ERROR Codes" registry in
/// draft-ietf-moq-transport-14 Section 13.1.4. Every row cites Section 9.15
/// (PUBLISH_ERROR), the source of the descriptions below.
///
/// Unlike the other request-scoped registries in this draft, PUBLISH_ERROR
/// assigns no `MALFORMED_AUTH_TOKEN` (0x10) or `EXPIRED_AUTH_TOKEN` (0x12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The publisher is not authorized to publish the given
    /// namespace or track.
    Unauthorized = 0x1,
    /// `TIMEOUT` — The subscription could not be established before an
    /// implementation specific timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — The endpoint does not support the PUBLISH method.
    NotSupported = 0x3,
    /// `UNINTERESTED` — The namespace or track is not of interest to the
    /// endpoint.
    Uninterested = 0x4,
}

/// FETCH_ERROR codes, from the "FETCH_ERROR Codes" registry in
/// draft-ietf-moq-transport-14 Section 13.1.5. Every row cites Section 9.18
/// (FETCH_ERROR), the source of the descriptions below.
///
/// The draft assigns 0x0 through 0x9, then 0x10 and 0x12; 0x11 is unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is not authorized to fetch from the
    /// given track.
    Unauthorized = 0x1,
    /// `TIMEOUT` — The fetch could not be completed before an implementation
    /// specific timeout. For example, a relay could not FETCH missing objects
    /// within the timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — The endpoint does not support the FETCH method.
    NotSupported = 0x3,
    /// `TRACK_DOES_NOT_EXIST` — The requested track is not available at the
    /// publisher.
    TrackDoesNotExist = 0x4,
    /// `INVALID_RANGE` — The end of the requested range is earlier than the
    /// beginning, the start of the requested range is beyond the Largest
    /// Location, or the track has not published any Objects yet.
    InvalidRange = 0x5,
    /// `NO_OBJECTS` — No Objects exist between the requested Start and End
    /// Locations.
    NoObjects = 0x6,
    /// `INVALID_JOINING_REQUEST_ID` — The joining Fetch referenced a Request ID
    /// that did not belong to an active Subscription.
    InvalidJoiningRequestId = 0x7,
    /// `UNKNOWN_STATUS_IN_RANGE` — The requested range contains objects with
    /// unknown status.
    UnknownStatusInRange = 0x8,
    /// `MALFORMED_TRACK` — A relay publisher detected the track was malformed
    /// (see Section 2.5).
    MalformedTrack = 0x9,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during
    /// registration (see Section 9.2.1.1).
    MalformedAuthToken = 0x10,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired
    /// (Section 9.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// ANNOUNCE_ERROR codes, from the "ANNOUNCE_ERROR Codes" registry in
/// draft-ietf-moq-transport-14 Section 13.1.6.
///
/// The registry is still titled ANNOUNCE_ERROR, but every row cites
/// Section 9.25, which defines PUBLISH_NAMESPACE_ERROR; draft-14 contains no
/// message named ANNOUNCE_ERROR. The name here follows the registry title, and
/// the descriptions below come from Section 9.25.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AnnounceErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is not authorized to announce the given
    /// namespace.
    Unauthorized = 0x1,
    /// `TIMEOUT` — The announce could not be completed before an implementation
    /// specific timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — The endpoint does not support the PUBLISH_NAMESPACE
    /// method.
    NotSupported = 0x3,
    /// `UNINTERESTED` — The namespace is not of interest to the endpoint.
    Uninterested = 0x4,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during
    /// registration (see Section 9.2.1.1).
    MalformedAuthToken = 0x10,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired
    /// (Section 9.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// SUBSCRIBE_NAMESPACE_ERROR codes, from the "SUBSCRIBE_NAMESPACE_ERROR Codes"
/// registry in draft-ietf-moq-transport-14 Section 13.1.7. Every row cites
/// Section 9.30 (SUBSCRIBE_NAMESPACE_ERROR), the source of the descriptions
/// below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeNamespaceErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — The subscriber is not authorized to subscribe to the
    /// given namespace prefix.
    Unauthorized = 0x1,
    /// `TIMEOUT` — The operation could not be completed before an
    /// implementation specific timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — The endpoint does not support the SUBSCRIBE_NAMESPACE
    /// method.
    NotSupported = 0x3,
    /// `NAMESPACE_PREFIX_UNKNOWN` — The namespace prefix is not available for
    /// subscription.
    NamespacePrefixUnknown = 0x4,
    /// `NAMESPACE_PREFIX_OVERLAP` — The namespace prefix overlaps with another
    /// SUBSCRIBE_NAMESPACE in the same session.
    NamespacePrefixOverlap = 0x5,
    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during
    /// registration (see Section 9.2.1.1).
    MalformedAuthToken = 0x10,
    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired
    /// (Section 9.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// Data stream reset error codes, from the "Data Stream Reset Error Codes"
/// registry in draft-ietf-moq-transport-14 Section 13.1.8. Every row cites
/// Section 10.4.3 (Closing Subgroup Streams), the source of the descriptions
/// below. These are the application error codes carried on RESET_STREAM and
/// RESET_STREAM_AT, not on the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DataStreamResetErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific error.
    InternalError = 0x0,
    /// `CANCELLED` — The subscriber requested cancellation via UNSUBSCRIBE,
    /// FETCH_CANCEL or STOP_SENDING, or the publisher ended the subscription,
    /// in which case PUBLISH_DONE (Section 9.12) will have a more detailed
    /// status code.
    Cancelled = 0x1,
    /// `DELIVERY_TIMEOUT` — The DELIVERY TIMEOUT Section 9.2.1.2 was exceeded
    /// for this stream.
    DeliveryTimeout = 0x2,
    /// `SESSION_CLOSED` — The publisher session is being closed.
    SessionClosed = 0x3,
}

impl SessionErrorCode {
    /// Every session termination code draft-14 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `SessionErrorCode`, if valid.
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

impl SubscribeErrorCode {
    /// Every SUBSCRIBE_ERROR code draft-14 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SubscribeErrorCode] = &[
        SubscribeErrorCode::InternalError,
        SubscribeErrorCode::Unauthorized,
        SubscribeErrorCode::Timeout,
        SubscribeErrorCode::NotSupported,
        SubscribeErrorCode::TrackDoesNotExist,
        SubscribeErrorCode::InvalidRange,
        SubscribeErrorCode::MalformedAuthToken,
        SubscribeErrorCode::ExpiredAuthToken,
    ];

    /// Convert a raw u64 to a `SubscribeErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeErrorCode::InternalError),
            0x1 => Some(SubscribeErrorCode::Unauthorized),
            0x2 => Some(SubscribeErrorCode::Timeout),
            0x3 => Some(SubscribeErrorCode::NotSupported),
            0x4 => Some(SubscribeErrorCode::TrackDoesNotExist),
            0x5 => Some(SubscribeErrorCode::InvalidRange),
            0x10 => Some(SubscribeErrorCode::MalformedAuthToken),
            0x12 => Some(SubscribeErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishDoneStatusCode {
    /// Every PUBLISH_DONE status code draft-14 assigns, in ascending wire order.
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
        PublishDoneStatusCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `PublishDoneStatusCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(PublishDoneStatusCode::InternalError),
            0x1 => Some(PublishDoneStatusCode::Unauthorized),
            0x2 => Some(PublishDoneStatusCode::TrackEnded),
            0x3 => Some(PublishDoneStatusCode::SubscriptionEnded),
            0x4 => Some(PublishDoneStatusCode::GoingAway),
            0x5 => Some(PublishDoneStatusCode::Expired),
            0x6 => Some(PublishDoneStatusCode::TooFarBehind),
            0x7 => Some(PublishDoneStatusCode::MalformedTrack),
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishErrorCode {
    /// Every PUBLISH_ERROR code draft-14 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[PublishErrorCode] = &[
        PublishErrorCode::InternalError,
        PublishErrorCode::Unauthorized,
        PublishErrorCode::Timeout,
        PublishErrorCode::NotSupported,
        PublishErrorCode::Uninterested,
    ];

    /// Convert a raw u64 to a `PublishErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(PublishErrorCode::InternalError),
            0x1 => Some(PublishErrorCode::Unauthorized),
            0x2 => Some(PublishErrorCode::Timeout),
            0x3 => Some(PublishErrorCode::NotSupported),
            0x4 => Some(PublishErrorCode::Uninterested),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl FetchErrorCode {
    /// Every FETCH_ERROR code draft-14 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[FetchErrorCode] = &[
        FetchErrorCode::InternalError,
        FetchErrorCode::Unauthorized,
        FetchErrorCode::Timeout,
        FetchErrorCode::NotSupported,
        FetchErrorCode::TrackDoesNotExist,
        FetchErrorCode::InvalidRange,
        FetchErrorCode::NoObjects,
        FetchErrorCode::InvalidJoiningRequestId,
        FetchErrorCode::UnknownStatusInRange,
        FetchErrorCode::MalformedTrack,
        FetchErrorCode::MalformedAuthToken,
        FetchErrorCode::ExpiredAuthToken,
    ];

    /// Convert a raw u64 to a `FetchErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(FetchErrorCode::InternalError),
            0x1 => Some(FetchErrorCode::Unauthorized),
            0x2 => Some(FetchErrorCode::Timeout),
            0x3 => Some(FetchErrorCode::NotSupported),
            0x4 => Some(FetchErrorCode::TrackDoesNotExist),
            0x5 => Some(FetchErrorCode::InvalidRange),
            0x6 => Some(FetchErrorCode::NoObjects),
            0x7 => Some(FetchErrorCode::InvalidJoiningRequestId),
            0x8 => Some(FetchErrorCode::UnknownStatusInRange),
            0x9 => Some(FetchErrorCode::MalformedTrack),
            0x10 => Some(FetchErrorCode::MalformedAuthToken),
            0x12 => Some(FetchErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl AnnounceErrorCode {
    /// Every ANNOUNCE_ERROR code draft-14 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[AnnounceErrorCode] = &[
        AnnounceErrorCode::InternalError,
        AnnounceErrorCode::Unauthorized,
        AnnounceErrorCode::Timeout,
        AnnounceErrorCode::NotSupported,
        AnnounceErrorCode::Uninterested,
        AnnounceErrorCode::MalformedAuthToken,
        AnnounceErrorCode::ExpiredAuthToken,
    ];

    /// Convert a raw u64 to an `AnnounceErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(AnnounceErrorCode::InternalError),
            0x1 => Some(AnnounceErrorCode::Unauthorized),
            0x2 => Some(AnnounceErrorCode::Timeout),
            0x3 => Some(AnnounceErrorCode::NotSupported),
            0x4 => Some(AnnounceErrorCode::Uninterested),
            0x10 => Some(AnnounceErrorCode::MalformedAuthToken),
            0x12 => Some(AnnounceErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeNamespaceErrorCode {
    /// Every SUBSCRIBE_NAMESPACE_ERROR code draft-14 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SubscribeNamespaceErrorCode] = &[
        SubscribeNamespaceErrorCode::InternalError,
        SubscribeNamespaceErrorCode::Unauthorized,
        SubscribeNamespaceErrorCode::Timeout,
        SubscribeNamespaceErrorCode::NotSupported,
        SubscribeNamespaceErrorCode::NamespacePrefixUnknown,
        SubscribeNamespaceErrorCode::NamespacePrefixOverlap,
        SubscribeNamespaceErrorCode::MalformedAuthToken,
        SubscribeNamespaceErrorCode::ExpiredAuthToken,
    ];

    /// Convert a raw u64 to a `SubscribeNamespaceErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeNamespaceErrorCode::InternalError),
            0x1 => Some(SubscribeNamespaceErrorCode::Unauthorized),
            0x2 => Some(SubscribeNamespaceErrorCode::Timeout),
            0x3 => Some(SubscribeNamespaceErrorCode::NotSupported),
            0x4 => Some(SubscribeNamespaceErrorCode::NamespacePrefixUnknown),
            0x5 => Some(SubscribeNamespaceErrorCode::NamespacePrefixOverlap),
            0x10 => Some(SubscribeNamespaceErrorCode::MalformedAuthToken),
            0x12 => Some(SubscribeNamespaceErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl DataStreamResetErrorCode {
    /// Every data stream reset code draft-14 assigns, in ascending wire order.
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
    ];

    /// Convert a raw u64 to a `DataStreamResetErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(DataStreamResetErrorCode::InternalError),
            0x1 => Some(DataStreamResetErrorCode::Cancelled),
            0x2 => Some(DataStreamResetErrorCode::DeliveryTimeout),
            0x3 => Some(DataStreamResetErrorCode::SessionClosed),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

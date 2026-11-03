//! Error, status and stream-reset code registries defined by
//! draft-ietf-moq-transport-23.
//!
//! One enum per registry in the IANA Considerations section (Section 16.12),
//! plus the Error Detail Types registry (Section 16.11). The per-code prose in
//! the variant docs is taken from the section each row cites.
//!
//! `from_u64` returns `None` for any value the draft does not assign. Section
//! 13: "Receipt of an unknown error code in any error context (Session
//! Termination, REQUEST_ERROR, PUBLISH_DONE, or Data Stream Reset) MUST be
//! treated as equivalent to INTERNAL_ERROR for that context."
//!
//! Each registry reserves `0x7f * N + 0x9D` for greasing (Section 13). That is
//! a range rather than an assignment, so it gets no variant and `from_u64`
//! reports it as unknown like any other unassigned value.
//!
//! Session termination codes do not fit a `u8`: 0x200 through 0x401 are
//! assigned.

/// Session termination error codes (draft-23 Section 16.12.1, Table 20).
///
/// Sent as the error code when closing the Transport Session. The per-code
/// definitions are in Section 12.2, which also groups 0x200-0x4FF: "Codes from
/// 0x200 to 0x4FF are organized into ranges by category". See
/// [`SessionErrorCategory`].
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
    /// disallowed by the specification and no more specific code applies.
    ProtocolViolation = 0x3,

    /// `INVALID_REQUEST_ID` — The endpoint received a Request ID with an
    /// incorrect least significant bit for the sender, or a duplicate Request
    /// ID. See Section 6.4.2.1.
    InvalidRequestId = 0x4,

    /// `DUPLICATE_TRACK_ALIAS` — The endpoint attempted to use a Track Alias
    /// that was already in use.
    DuplicateTrackAlias = 0x5,

    /// `MALFORMED_KEY_VALUE` — A Key-Value-Pair (Figure 4), such as a Setup
    /// Option or a Property, has a Value that does not match the definition of
    /// its Type.
    MalformedKeyValue = 0x6,

    /// `INVALID_PATH` — The PATH parameter was used by a server, on a
    /// WebTransport session, or the server does not support the path.
    InvalidPath = 0x8,

    /// `MALFORMED_PATH` — The PATH parameter does not conform to the rules in
    /// Section 9.1.2.
    MalformedPath = 0x9,

    /// `GOAWAY_TIMEOUT` — The session was closed because the peer took too
    /// long to close the session in response to a GOAWAY (Section 9.2)
    /// message. See session migration (Section 6.6.1).
    GoawayTimeout = 0x10,

    /// `CONTROL_MESSAGE_TIMEOUT` — The session was closed because the peer
    /// took too long to respond to a control message.
    ControlMessageTimeout = 0x11,

    /// `DATA_STREAM_TIMEOUT` — The session was closed because the peer took
    /// too long to send data expected on an open Data Stream (see Section 11).
    DataStreamTimeout = 0x12,

    /// `AUTH_TOKEN_CACHE_OVERFLOW` — The Session limit Section 9.1.3 of the
    /// size of all registered Authorization tokens has been exceeded.
    AuthTokenCacheOverflow = 0x13,

    /// `DUPLICATE_AUTH_TOKEN_ALIAS` — Authorization Token attempted to
    /// register an Alias that was in use (see Section 8.9).
    DuplicateAuthTokenAlias = 0x14,

    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization (see Section
    /// 8.9).
    MalformedAuthToken = 0x16,

    /// `UNKNOWN_AUTH_TOKEN_ALIAS` — No registered token found for the
    /// provided Alias (see Section 8.9).
    UnknownAuthTokenAlias = 0x17,

    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 8.9).
    ExpiredAuthToken = 0x18,

    /// `INVALID_AUTHORITY` — The specified AUTHORITY does not correspond to
    /// this server or cannot be used in this context.
    InvalidAuthority = 0x19,

    /// `MALFORMED_AUTHORITY` — The AUTHORITY value is syntactically invalid.
    MalformedAuthority = 0x1A,

    /// `TOO_MANY_REQUEST_UPDATES` — The endpoint received a REQUEST_UPDATE
    /// that exceeded the per-stream limit communicated via the
    /// MAX_REQUEST_UPDATES Setup Option (Section 9.1.7).
    TooManyRequestUpdates = 0x1B,

    /// `INVALID_STREAM_HEADER` — A data stream or datagram has an unknown type
    /// or invalid Type Flags.
    InvalidStreamHeader = 0x200,

    /// `MALFORMED_OBJECT` — The serialization of an Object on a data stream or
    /// in a datagram cannot be decoded, for example a flag references a prior
    /// Object that does not exist.
    MalformedObject = 0x201,

    /// `INVALID_OBJECT_STATUS` — An Object has an invalid Object Status, or
    /// has Properties when its status is not Normal.
    InvalidObjectStatus = 0x202,

    /// `TRUNCATED_OBJECT` — A data stream ended with a FIN in the middle of an
    /// Object.
    TruncatedObject = 0x203,

    /// `MALFORMED_MESSAGE` — A control message cannot be parsed or is missing
    /// a required element, for example its length does not match its
    /// contents.
    MalformedMessage = 0x300,

    /// `INVALID_FIELD` — A control message was parsed, but a field has a value
    /// that is not allowed.
    InvalidField = 0x301,

    /// `INVALID_TRACK_NAMESPACE` — A Track Namespace does not conform to
    /// Section 8.7.
    InvalidTrackNamespace = 0x302,

    /// `UNEXPECTED_MESSAGE` — A control message of an unknown type was
    /// received, or a message was received on the wrong stream, in the wrong
    /// order, or more times than allowed.
    UnexpectedMessage = 0x303,

    /// `ROLE_VIOLATION` — The peer sent a message or field that is not allowed
    /// for its role, for example a server receiving a non-empty New Session
    /// URI.
    RoleViolation = 0x304,

    /// `INVALID_PARAMETER` — A Message Parameter (Section 9.19) is unknown,
    /// duplicated, not allowed in the message, or has a value outside its
    /// allowed range.
    InvalidParameter = 0x305,

    /// `CLOSED_CONTROL_STREAM` — The peer closed the control stream (Section
    /// 6.3).
    ClosedControlStream = 0x306,

    /// `DELTA_ENCODING_OVERFLOW` — A value decoded from a delta encoding is
    /// less than 0 or greater than 2^64 - 1.
    DeltaEncodingOverflow = 0x400,

    /// `FIELD_LENGTH_EXCEEDED` — A field or structure is longer than its
    /// maximum allowed length.
    FieldLengthExceeded = 0x401,
}

/// The category Section 12.2 gives a session termination code in 0x200-0x4FF.
///
/// "0x200-0x2FF: Data stream and datagram errors", "0x300-0x3FF: Control
/// stream and control message errors", "0x400-0x4FF: Errors that can occur in
/// either". "The values reserved for greasing (Section 13) that fall within
/// these ranges are not assigned to a category."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorCategory {
    /// 0x200-0x2FF.
    DataStream,
    /// 0x300-0x3FF.
    ControlStream,
    /// 0x400-0x4FF.
    Either,
}

impl SessionErrorCategory {
    /// The category of `code`, assigned or not, or `None` outside 0x200-0x4FF
    /// and for a grease value.
    pub fn of(code: u64) -> Option<Self> {
        if code >= 0x9D && (code - 0x9D).is_multiple_of(0x7F) {
            return None;
        }
        match code {
            0x200..=0x2FF => Some(Self::DataStream),
            0x300..=0x3FF => Some(Self::ControlStream),
            0x400..=0x4FF => Some(Self::Either),
            _ => None,
        }
    }
}

/// REQUEST_ERROR codes (draft-23 Section 16.12.2, Table 21).
///
/// The per-code definitions are in Section 12.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RequestErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error
    /// occurred.
    InternalError = 0x0,

    /// `UNAUTHORIZED` — The subscriber is not authorized to perform the
    /// requested action on the given track.
    Unauthorized = 0x1,

    /// `TIMEOUT` — The subscription could not be completed before an
    /// implementation specific timeout.
    Timeout = 0x2,

    /// `NOT_SUPPORTED` — The endpoint does not support the type of request.
    NotSupported = 0x3,

    /// `MALFORMED_AUTH_TOKEN` — Invalid Auth Token serialization during
    /// registration (see Section 8.9).
    MalformedAuthToken = 0x4,

    /// `EXPIRED_AUTH_TOKEN` — Authorization token has expired (Section 8.9).
    ExpiredAuthToken = 0x5,

    /// `GOING_AWAY` — The endpoint has received a GOAWAY and MAY reject new
    /// requests.
    GoingAway = 0x6,

    /// `EXCESSIVE_LOAD` — The responder is overloaded and cannot process the
    /// request at this time.
    ExcessiveLoad = 0x9,

    /// `UNAVAILABLE` — The responder cannot fulfill this request at this
    /// time, but might be able to later; for example, a relay lacks stream
    /// credit to forward it upstream (see Section 7.4).
    Unavailable = 0xA,

    /// `DOES_NOT_EXIST` — The track or namespace is not available at the
    /// publisher.
    DoesNotExist = 0x10,

    /// `INVALID_RANGE` — In response to SUBSCRIBE or FETCH, specified Filter
    /// or range of Locations cannot be satisfied.
    InvalidRange = 0x11,

    /// `MALFORMED_TRACK` — In response to a FETCH, a relay publisher detected
    /// the track was malformed (see Section 12.1).
    MalformedTrack = 0x12,

    /// `UNINTERESTED` — The subscriber is not interested in the track or
    /// namespace.
    Uninterested = 0x20,

    /// `NAMESPACE_TOO_LARGE` — In response to SUBSCRIBE_NAMESPACE or
    /// SUBSCRIBE_TRACKS, the namespace prefix matches more publishers than the
    /// relay is willing to enumerate.
    NamespaceTooLarge = 0x31,

    /// `UNSUPPORTED_EXTENSION` — The track contains a Mandatory Track Property
    /// (see Section 3.7) that the endpoint does not understand. The
    /// UNSUPPORTED_PROPERTY Error Detail (Section 9.4.2.2) identifies which
    /// property.
    UnsupportedExtension = 0x33,

    /// `REDIRECT` — The request cannot be fulfilled by this endpoint, but
    /// could succeed at the location specified in the REDIRECT Error Detail
    /// (Section 9.4.2.1).
    Redirect = 0x34,

    /// `CONFLICTING_FILTERS` — In response to SUBSCRIBE_TRACKS, the filter
    /// parameters conflict among too many subscribers to aggregate the
    /// subscription upstream or otherwise efficiently service it.
    ConflictingFilters = 0x35,

    /// `INVALID_FILTER` — A filter parameter is invalid.
    InvalidFilter = 0x36,
}

/// PUBLISH_DONE codes (draft-23 Section 16.12.3, Table 22).
///
/// The per-code definitions are in Section 12.4. 0x3 is unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishDoneStatusCode {
    /// `INTERNAL_ERROR` — An implementation specific or generic error
    /// occurred.
    InternalError = 0x0,

    /// `UNAUTHORIZED` — The subscriber is no longer authorized to subscribe to
    /// the given track.
    Unauthorized = 0x1,

    /// `TRACK_ENDED` — The track is no longer being published.
    TrackEnded = 0x2,

    /// `GOING_AWAY` — The subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,

    /// `TOO_FAR_BEHIND` — The publisher's queue of objects to be sent to the
    /// given subscriber exceeds its implementation defined limit.
    TooFarBehind = 0x5,

    /// `EXPIRED` — The publisher reached the timeout specified in
    /// SUBSCRIBE_OK.
    Expired = 0x6,

    /// `EXPIRED_AUTH_TOKEN` — The authorization token that authorized the
    /// subscription has expired (see Section 9.9).
    ExpiredAuthToken = 0x7,

    /// `UPDATE_FAILED` — REQUEST_UPDATE failed on this subscription (see
    /// Section 9.5).
    UpdateFailed = 0x8,

    /// `EXCESSIVE_LOAD` — The publisher is overloaded and is terminating the
    /// subscription.
    ExcessiveLoad = 0x9,

    /// `MALFORMED_TRACK` — A relay publisher detected that the track was
    /// malformed (see Section 12.1).
    MalformedTrack = 0x12,
}

/// Stream reset error codes (draft-23 Section 16.12.4, Table 23).
///
/// Section 12.5: "The application SHOULD use a relevant error code when
/// resetting or sending STOP_SENDING on any stream." 0x6 is unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamResetErrorCode {
    /// `INTERNAL_ERROR` — An implementation specific error.
    InternalError = 0x0,

    /// `CANCELLED` — The stream was cancelled by either endpoint. For
    /// Subscriptions, PUBLISH_DONE (Section 9.9) may have a more detailed
    /// status code.
    Cancelled = 0x1,

    /// `DELIVERY_TIMEOUT` — A delivery timeout (Section 5.2) was exceeded for
    /// this stream.
    DeliveryTimeout = 0x2,

    /// `SESSION_CLOSED` — The session is being closed.
    SessionClosed = 0x3,

    /// `GOING_AWAY` — The endpoint is rejecting this request because it has
    /// sent or received a GOAWAY.
    GoingAway = 0x4,

    /// `TOO_FAR_BEHIND` — The corresponding subscription has exceeded the
    /// publisher's resource limits and is being terminated (see Section 5.2).
    TooFarBehind = 0x5,

    /// `EXPIRED_AUTH_TOKEN` — The authorization token for the request has
    /// expired.
    ExpiredAuthToken = 0x7,

    /// `EXCESSIVE_LOAD` — The endpoint is overloaded and is resetting this
    /// stream.
    ExcessiveLoad = 0x9,

    /// `MALFORMED_TRACK` — A relay publisher detected that the track was
    /// malformed (see Section 12.1).
    MalformedTrack = 0x12,
}

/// Error Detail types (draft-23 Section 16.11, Table 19).
///
/// Section 9.4.2: "Receivers MUST ignore unknown Error Detail types, and MUST
/// ignore a known Error Detail type that accompanies an Error Code it is not
/// defined for."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ErrorDetailType {
    /// `REDIRECT` — directs the requester to retry a request at a different
    /// URI and/or for a different Full Track Name (Section 9.4.2.1).
    Redirect = 0x01,

    /// `UNSUPPORTED_PROPERTY` — the Property Type of a Mandatory Track
    /// Property that the sender does not understand (Section 9.4.2.2).
    UnsupportedProperty = 0x02,
}

impl SessionErrorCode {
    /// Every Session Error Code draft-23 assigns, in ascending wire order:
    /// the set [`Self::from_u64`] accepts.
    pub const ALL: &[SessionErrorCode] = &[
        SessionErrorCode::NoError,
        SessionErrorCode::InternalError,
        SessionErrorCode::Unauthorized,
        SessionErrorCode::ProtocolViolation,
        SessionErrorCode::InvalidRequestId,
        SessionErrorCode::DuplicateTrackAlias,
        SessionErrorCode::MalformedKeyValue,
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
        SessionErrorCode::InvalidStreamHeader,
        SessionErrorCode::MalformedObject,
        SessionErrorCode::InvalidObjectStatus,
        SessionErrorCode::TruncatedObject,
        SessionErrorCode::MalformedMessage,
        SessionErrorCode::InvalidField,
        SessionErrorCode::InvalidTrackNamespace,
        SessionErrorCode::UnexpectedMessage,
        SessionErrorCode::RoleViolation,
        SessionErrorCode::InvalidParameter,
        SessionErrorCode::ClosedControlStream,
        SessionErrorCode::DeltaEncodingOverflow,
        SessionErrorCode::FieldLengthExceeded,
    ];

    /// Convert a raw u64 to a `SessionErrorCode`, if the draft assigns that
    /// code point. `None` for any unassigned value, including the greasing
    /// range.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SessionErrorCode::NoError),
            0x1 => Some(SessionErrorCode::InternalError),
            0x2 => Some(SessionErrorCode::Unauthorized),
            0x3 => Some(SessionErrorCode::ProtocolViolation),
            0x4 => Some(SessionErrorCode::InvalidRequestId),
            0x5 => Some(SessionErrorCode::DuplicateTrackAlias),
            0x6 => Some(SessionErrorCode::MalformedKeyValue),
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
            0x200 => Some(SessionErrorCode::InvalidStreamHeader),
            0x201 => Some(SessionErrorCode::MalformedObject),
            0x202 => Some(SessionErrorCode::InvalidObjectStatus),
            0x203 => Some(SessionErrorCode::TruncatedObject),
            0x300 => Some(SessionErrorCode::MalformedMessage),
            0x301 => Some(SessionErrorCode::InvalidField),
            0x302 => Some(SessionErrorCode::InvalidTrackNamespace),
            0x303 => Some(SessionErrorCode::UnexpectedMessage),
            0x304 => Some(SessionErrorCode::RoleViolation),
            0x305 => Some(SessionErrorCode::InvalidParameter),
            0x306 => Some(SessionErrorCode::ClosedControlStream),
            0x400 => Some(SessionErrorCode::DeltaEncodingOverflow),
            0x401 => Some(SessionErrorCode::FieldLengthExceeded),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    /// The Section 12.2 category of this code, `None` below 0x200.
    pub fn category(self) -> Option<SessionErrorCategory> {
        SessionErrorCategory::of(self.as_u64())
    }
}

impl RequestErrorCode {
    /// Every Request Error Code draft-23 assigns, in ascending wire order:
    /// the set [`Self::from_u64`] accepts.
    pub const ALL: &[RequestErrorCode] = &[
        RequestErrorCode::InternalError,
        RequestErrorCode::Unauthorized,
        RequestErrorCode::Timeout,
        RequestErrorCode::NotSupported,
        RequestErrorCode::MalformedAuthToken,
        RequestErrorCode::ExpiredAuthToken,
        RequestErrorCode::GoingAway,
        RequestErrorCode::ExcessiveLoad,
        RequestErrorCode::Unavailable,
        RequestErrorCode::DoesNotExist,
        RequestErrorCode::InvalidRange,
        RequestErrorCode::MalformedTrack,
        RequestErrorCode::Uninterested,
        RequestErrorCode::NamespaceTooLarge,
        RequestErrorCode::UnsupportedExtension,
        RequestErrorCode::Redirect,
        RequestErrorCode::ConflictingFilters,
        RequestErrorCode::InvalidFilter,
    ];

    /// Convert a raw u64 to a `RequestErrorCode`, if the draft assigns that
    /// code point. `None` for any unassigned value, including the greasing
    /// range.
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
            0xA => Some(RequestErrorCode::Unavailable),
            0x10 => Some(RequestErrorCode::DoesNotExist),
            0x11 => Some(RequestErrorCode::InvalidRange),
            0x12 => Some(RequestErrorCode::MalformedTrack),
            0x20 => Some(RequestErrorCode::Uninterested),
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
    /// Every PUBLISH_DONE Status Code draft-23 assigns, in ascending wire
    /// order: the set [`Self::from_u64`] accepts.
    pub const ALL: &[PublishDoneStatusCode] = &[
        PublishDoneStatusCode::InternalError,
        PublishDoneStatusCode::Unauthorized,
        PublishDoneStatusCode::TrackEnded,
        PublishDoneStatusCode::GoingAway,
        PublishDoneStatusCode::TooFarBehind,
        PublishDoneStatusCode::Expired,
        PublishDoneStatusCode::ExpiredAuthToken,
        PublishDoneStatusCode::UpdateFailed,
        PublishDoneStatusCode::ExcessiveLoad,
        PublishDoneStatusCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `PublishDoneStatusCode`, if the draft assigns
    /// that code point. `None` for any unassigned value, including the
    /// greasing range.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(PublishDoneStatusCode::InternalError),
            0x1 => Some(PublishDoneStatusCode::Unauthorized),
            0x2 => Some(PublishDoneStatusCode::TrackEnded),
            0x4 => Some(PublishDoneStatusCode::GoingAway),
            0x5 => Some(PublishDoneStatusCode::TooFarBehind),
            0x6 => Some(PublishDoneStatusCode::Expired),
            0x7 => Some(PublishDoneStatusCode::ExpiredAuthToken),
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
    /// Every Stream Reset Error Code draft-23 assigns, in ascending wire
    /// order: the set [`Self::from_u64`] accepts.
    pub const ALL: &[StreamResetErrorCode] = &[
        StreamResetErrorCode::InternalError,
        StreamResetErrorCode::Cancelled,
        StreamResetErrorCode::DeliveryTimeout,
        StreamResetErrorCode::SessionClosed,
        StreamResetErrorCode::GoingAway,
        StreamResetErrorCode::TooFarBehind,
        StreamResetErrorCode::ExpiredAuthToken,
        StreamResetErrorCode::ExcessiveLoad,
        StreamResetErrorCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `StreamResetErrorCode`, if the draft assigns
    /// that code point. `None` for any unassigned value, including the
    /// greasing range.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(StreamResetErrorCode::InternalError),
            0x1 => Some(StreamResetErrorCode::Cancelled),
            0x2 => Some(StreamResetErrorCode::DeliveryTimeout),
            0x3 => Some(StreamResetErrorCode::SessionClosed),
            0x4 => Some(StreamResetErrorCode::GoingAway),
            0x5 => Some(StreamResetErrorCode::TooFarBehind),
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

impl ErrorDetailType {
    /// Every Error Detail type draft-23 assigns, in ascending wire order.
    pub const ALL: &[ErrorDetailType] =
        &[ErrorDetailType::Redirect, ErrorDetailType::UnsupportedProperty];

    /// Convert a raw u64 to an `ErrorDetailType`, if the draft assigns it.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x01 => Some(ErrorDetailType::Redirect),
            0x02 => Some(ErrorDetailType::UnsupportedProperty),
            _ => None,
        }
    }

    /// Return the raw u64 value of this type.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

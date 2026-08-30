//! Error and status code registries defined by draft-15.
//!
//! Each of the four registries in Section 13.3 of the draft ("Error Codes") is
//! transcribed here as one enum. The IANA tables list only names, codes and a
//! pointer to the defining section; the per-variant prose below comes from those
//! defining sections (3.4, 9.8, 9.15 and 10.4.3).
//!
//! `from_u64` returns `None` for any code the draft does not define. Peers are
//! free to send codes from a newer draft or from a private range, so an unknown
//! code is a normal decode outcome and never an error on its own.

/// Session Termination Error Codes (draft-15 Section 13.3.1, defined in Section 3.4).
///
/// Sent when closing the session. Draft-15 assigns 0x0 through 0x9 and 0x10
/// through 0x1A; it reserves no greasing range in this registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `NO_ERROR` — the session is being terminated without an error.
    NoError = 0x0,
    /// `INTERNAL_ERROR` — an implementation specific error occurred.
    InternalError = 0x1,
    /// `UNAUTHORIZED` — the client is not authorized to establish a session.
    Unauthorized = 0x2,
    /// `PROTOCOL_VIOLATION` — the remote endpoint performed an action that was
    /// disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `INVALID_REQUEST_ID` — the session was closed because the endpoint used a
    /// Request ID that was smaller than or equal to a previously received request
    /// ID, or the least-significant bit of the request ID was incorrect for the
    /// endpoint.
    InvalidRequestId = 0x4,
    /// `DUPLICATE_TRACK_ALIAS` — the endpoint attempted to use a Track Alias that
    /// was already in use.
    DuplicateTrackAlias = 0x5,
    /// `KEY_VALUE_FORMATTING_ERROR` — the key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,
    /// `TOO_MANY_REQUESTS` — the session was closed because the endpoint used a
    /// Request ID equal to or larger than the current Maximum Request ID.
    TooManyRequests = 0x7,
    /// `INVALID_PATH` — the PATH parameter was used by a server, on a WebTransport
    /// session, or the server does not support the path.
    InvalidPath = 0x8,
    /// `MALFORMED_PATH` — the PATH parameter does not conform to the rules in
    /// Section 9.3.1.2.
    MalformedPath = 0x9,
    /// `GOAWAY_TIMEOUT` — the session was closed because the peer took too long to
    /// close the session in response to a GOAWAY (Section 9.4) message. See session
    /// migration (Section 3.5).
    GoawayTimeout = 0x10,
    /// `CONTROL_MESSAGE_TIMEOUT` — the session was closed because the peer took too
    /// long to respond to a control message.
    ControlMessageTimeout = 0x11,
    /// `DATA_STREAM_TIMEOUT` — the session was closed because the peer took too long
    /// to send data expected on an open Data Stream (see Section 10). This includes
    /// fields of a stream header or an object header within a data stream. If an
    /// endpoint times out waiting for a new object header on an open subgroup
    /// stream, it MAY send a STOP_SENDING on that stream or terminate the
    /// subscription.
    DataStreamTimeout = 0x12,
    /// `AUTH_TOKEN_CACHE_OVERFLOW` — the Session limit (Section 9.3.1.4) of the size
    /// of all registered Authorization tokens has been exceeded.
    AuthTokenCacheOverflow = 0x13,
    /// `DUPLICATE_AUTH_TOKEN_ALIAS` — Authorization Token attempted to register an
    /// Alias that was in use (see Section 9.2.1.1).
    DuplicateAuthTokenAlias = 0x14,
    /// `VERSION_NEGOTIATION_FAILED` — the client didn't offer a version supported by
    /// the server.
    VersionNegotiationFailed = 0x15,
    /// `MALFORMED_AUTH_TOKEN` — invalid Auth Token serialization during registration
    /// (see Section 9.2.1.1).
    MalformedAuthToken = 0x16,
    /// `UNKNOWN_AUTH_TOKEN_ALIAS` — no registered token found for the provided Alias
    /// (see Section 9.2.1.1).
    UnknownAuthTokenAlias = 0x17,
    /// `EXPIRED_AUTH_TOKEN` — authorization token has expired (Section 9.2.1.1).
    ExpiredAuthToken = 0x18,
    /// `INVALID_AUTHORITY` — the specified AUTHORITY does not correspond to this
    /// server or cannot be used in this context.
    InvalidAuthority = 0x19,
    /// `MALFORMED_AUTHORITY` — the AUTHORITY value is syntactically invalid.
    MalformedAuthority = 0x1A,
}

/// REQUEST_ERROR Codes (draft-15 Section 13.3.2, defined in Section 9.8).
///
/// Carried in the REQUEST_ERROR message, which draft-15 sends in response to any
/// request (SUBSCRIBE, FETCH, PUBLISH, SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE,
/// TRACK_STATUS). Most codepoints have identical meanings across request types,
/// but Section 9.8 lists the registry in four bands, separated by which side of
/// the session sends the code:
///
/// - 0x0 through 0x5 carry the same meaning whichever request they answer.
/// - 0x10 through 0x12 are for use by the publisher. They can appear in response
///   to SUBSCRIBE, FETCH, TRACK_STATUS and SUBSCRIBE_NAMESPACE, unless otherwise
///   noted.
/// - 0x20 is for use by the subscriber. It can appear in response to PUBLISH or
///   PUBLISH_NAMESPACE, unless otherwise noted.
/// - 0x30 and above can only be used in response to one message type.
///
/// The draft assigns no greasing range in this registry, and leaves 0x31
/// unassigned between PREFIX_OVERLAP and INVALID_JOINING_REQUEST_ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RequestErrorCode {
    /// `INTERNAL_ERROR` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — the subscriber is not authorized to perform the requested
    /// action on the given track.
    Unauthorized = 0x1,
    /// `TIMEOUT` — the subscription could not be completed before an implementation
    /// specific timeout. For example, a relay could not establish an upstream
    /// subscription within the timeout.
    Timeout = 0x2,
    /// `NOT_SUPPORTED` — the endpoint does not support the type of request.
    NotSupported = 0x3,
    /// `MALFORMED_AUTH_TOKEN` — invalid Auth Token serialization during registration
    /// (see Section 9.2.1.1).
    MalformedAuthToken = 0x4,
    /// `EXPIRED_AUTH_TOKEN` — authorization token has expired (Section 9.2.1.1).
    ExpiredAuthToken = 0x5,
    /// `DOES_NOT_EXIST` — the track or namespace is not available at the publisher.
    DoesNotExist = 0x10,
    /// `INVALID_RANGE` — in response to SUBSCRIBE or FETCH, specified Filter or range
    /// of Locations cannot be satisfied.
    InvalidRange = 0x11,
    /// `MALFORMED_TRACK` — in response to a FETCH, a relay publisher detected the
    /// track was malformed (see Section 2.4.2).
    MalformedTrack = 0x12,
    /// `UNINTERESTED` — the subscriber is not interested in the track or namespace.
    Uninterested = 0x20,
    /// `PREFIX_OVERLAP` — in response to SUBSCRIBE_NAMESPACE, the namespace prefix
    /// overlaps with another SUBSCRIBE_NAMESPACE in the same session.
    PrefixOverlap = 0x30,
    /// `INVALID_JOINING_REQUEST_ID` — in response to a Joining FETCH, the referenced
    /// Request ID is not an `Established` Subscription. `Established` is the
    /// subscription state named in Section 5.1.
    InvalidJoiningRequestId = 0x32,
    /// `UNKNOWN_STATUS_IN_RANGE` — in response to a FETCH, the requested range
    /// contains an object with unknown status.
    UnknownStatusInRange = 0x33,
}

/// PUBLISH_DONE Codes (draft-15 Section 13.3.3, defined in Section 9.15).
///
/// The status a publisher reports when a subscription ends. Draft-15 assigns 0x0
/// through 0x8 contiguously and reserves no greasing range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishDoneStatusCode {
    /// `INTERNAL_ERROR` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `UNAUTHORIZED` — the subscriber is no longer authorized to subscribe to the
    /// given track.
    Unauthorized = 0x1,
    /// `TRACK_ENDED` — the track is no longer being published.
    TrackEnded = 0x2,
    /// `SUBSCRIPTION_ENDED` — the publisher reached the end of an associated
    /// subscription filter.
    SubscriptionEnded = 0x3,
    /// `GOING_AWAY` — the subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,
    /// `EXPIRED` — the publisher reached the timeout specified in SUBSCRIBE_OK.
    Expired = 0x5,
    /// `TOO_FAR_BEHIND` — the publisher's queue of objects to be sent to the given
    /// subscriber exceeds its implementation defined limit.
    TooFarBehind = 0x6,
    /// `MALFORMED_TRACK` — a relay publisher detected the track was malformed (see
    /// Section 2.4.2).
    MalformedTrack = 0x7,
    /// `UPDATE_FAILED` — SUBSCRIBE_UPDATE failed on this subscription (see
    /// Section 9.11).
    UpdateFailed = 0x8,
}

/// Data Stream Reset Error Codes (draft-15 Section 13.3.4, defined in Section 10.4.3).
///
/// Sent as the application error code in the RESET_STREAM or RESET_STREAM_AT
/// frame when a publisher closes a data stream before delivering every object in
/// the subgroup. Draft-15 assigns 0x0 through 0x3 and reserves no greasing range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DataStreamResetErrorCode {
    /// `INTERNAL_ERROR` — an implementation specific error.
    InternalError = 0x0,
    /// `CANCELLED` — the subscriber requested cancellation via UNSUBSCRIBE,
    /// FETCH_CANCEL or STOP_SENDING, or the publisher ended the subscription, in
    /// which case PUBLISH_DONE (Section 9.15) will have a more detailed status code.
    Cancelled = 0x1,
    /// `DELIVERY_TIMEOUT` — the DELIVERY TIMEOUT (Section 9.2.1.2) was exceeded for
    /// this stream.
    DeliveryTimeout = 0x2,
    /// `SESSION_CLOSED` — the publisher session is being closed.
    SessionClosed = 0x3,
}

impl SessionErrorCode {
    /// Every session termination code draft-15 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `SessionErrorCode`, if draft-15 defines it.
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
    /// Every REQUEST_ERROR code draft-15 assigns, in ascending wire order.
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
        RequestErrorCode::Uninterested,
        RequestErrorCode::PrefixOverlap,
        RequestErrorCode::InvalidJoiningRequestId,
        RequestErrorCode::UnknownStatusInRange,
    ];

    /// Convert a raw u64 to a `RequestErrorCode`, if draft-15 defines it.
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
            0x20 => Some(RequestErrorCode::Uninterested),
            0x30 => Some(RequestErrorCode::PrefixOverlap),
            0x32 => Some(RequestErrorCode::InvalidJoiningRequestId),
            0x33 => Some(RequestErrorCode::UnknownStatusInRange),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishDoneStatusCode {
    /// Every PUBLISH_DONE status code draft-15 assigns, in ascending wire order.
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
        PublishDoneStatusCode::UpdateFailed,
    ];

    /// Convert a raw u64 to a `PublishDoneStatusCode`, if draft-15 defines it.
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
            0x8 => Some(PublishDoneStatusCode::UpdateFailed),
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl DataStreamResetErrorCode {
    /// Every data stream reset code draft-15 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `DataStreamResetErrorCode`, if draft-15 defines it.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_codes() {
        assert_eq!(SessionErrorCode::from_u64(0x1A), Some(SessionErrorCode::MalformedAuthority));
        assert_eq!(SessionErrorCode::MalformedAuthority.as_u64(), 0x1A);
        assert_eq!(RequestErrorCode::from_u64(0x33), Some(RequestErrorCode::UnknownStatusInRange));
        assert_eq!(RequestErrorCode::UnknownStatusInRange.as_u64(), 0x33);
        assert_eq!(PublishDoneStatusCode::from_u64(0x8), Some(PublishDoneStatusCode::UpdateFailed));
        assert_eq!(PublishDoneStatusCode::UpdateFailed.as_u64(), 0x8);
        assert_eq!(
            DataStreamResetErrorCode::from_u64(0x3),
            Some(DataStreamResetErrorCode::SessionClosed)
        );
        assert_eq!(DataStreamResetErrorCode::SessionClosed.as_u64(), 0x3);
    }

    #[test]
    fn unknown_codes_decode_to_none() {
        // 0xA..0xF and anything above 0x1A are unassigned in draft-15.
        assert_eq!(SessionErrorCode::from_u64(0xA), None);
        assert_eq!(SessionErrorCode::from_u64(0x1B), None);
        // 0x31 sits between PREFIX_OVERLAP and INVALID_JOINING_REQUEST_ID.
        assert_eq!(RequestErrorCode::from_u64(0x31), None);
        assert_eq!(PublishDoneStatusCode::from_u64(0x9), None);
        assert_eq!(DataStreamResetErrorCode::from_u64(0x4), None);
        assert_eq!(SessionErrorCode::from_u64(u64::MAX), None);
    }
}

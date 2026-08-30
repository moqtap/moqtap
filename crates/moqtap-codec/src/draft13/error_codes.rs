//! Error and status code registries defined by MoQ Transport draft-13.
//!
//! Draft-13 predates the IANA registries introduced in draft-14. Its code points are listed
//! inline in the sections that use them, in two-column `Code | Reason` tables that assign no
//! symbolic ALLCAPS name — the `Reason` cell is a human-readable phrase such as
//! `Key-Value Formatting Error`. Each variant name here is derived mechanically from that
//! phrase.
//!
//! Each table is followed in the draft by a bulleted description of every code it assigns.
//! Each variant below quotes its `Reason` cell verbatim, so a variant can be matched back to
//! its table row by eye, followed by that description, quoted from the draft unaltered. Where
//! the draft's own wording is ungrammatical or has an unbalanced parenthesis it is reproduced
//! as printed rather than corrected. Nothing beyond the draft's text is asserted about what a
//! code means.
//!
//! Every `from_u64` returns `None` for a code this draft does not assign. Peers do send codes
//! from other drafts and from private extensions, and an unrecognised code is a value to pass
//! through or report, not a decode failure.
//!
//! The eight registries transcribed here, with their draft-13 sections:
//!
//! - 3.4 Termination — [`SessionErrorCode`]
//! - 8.9 SUBSCRIBE_ERROR — [`SubscribeErrorCode`]
//! - 8.12 SUBSCRIBE_DONE — [`SubscribeDoneStatusCode`]
//! - 8.15 PUBLISH_ERROR — [`PublishErrorCode`]
//! - 8.18 FETCH_ERROR — [`FetchErrorCode`]
//! - 8.25 ANNOUNCE_ERROR — [`AnnounceErrorCode`]
//! - 8.30 SUBSCRIBE_NAMESPACE_ERROR — [`SubscribeNamespaceErrorCode`]
//! - 9.4.3 Closing Subgroup Streams — [`StreamResetErrorCode`]
//!
//! [`SessionErrorCode`]: crate::draft13::error_codes::SessionErrorCode
//! [`SubscribeErrorCode`]: crate::draft13::error_codes::SubscribeErrorCode
//! [`SubscribeDoneStatusCode`]: crate::draft13::error_codes::SubscribeDoneStatusCode
//! [`PublishErrorCode`]: crate::draft13::error_codes::PublishErrorCode
//! [`FetchErrorCode`]: crate::draft13::error_codes::FetchErrorCode
//! [`AnnounceErrorCode`]: crate::draft13::error_codes::AnnounceErrorCode
//! [`SubscribeNamespaceErrorCode`]: crate::draft13::error_codes::SubscribeNamespaceErrorCode
//! [`StreamResetErrorCode`]: crate::draft13::error_codes::StreamResetErrorCode
//!
//! Two further messages carry error codes without defining a registry: TRACK_STATUS_ERROR
//! (Section 8.22) reuses the SUBSCRIBE_ERROR codes and ANNOUNCE_CANCEL (Section 8.27) reuses
//! the ANNOUNCE_ERROR codes.
//!
//! Draft-13 reserves no code ranges for greasing in any of these tables; every row is a
//! single code point.

/// Session termination codes (draft-13 Section 3.4, Termination).
///
/// Sent in the QUIC `CONNECTION_CLOSE` frame or the WebTransport `CLOSE_WEBTRANSPORT_SESSION`
/// capsule. Draft-13: "When terminating the Session, the application MAY use any error message
/// and SHOULD use a relevant code, as defined below".
///
/// The table assigns 0x0 through 0x9 and 0x10 through 0x18. 0xA through 0xF are unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `No Error` — The session is being terminated without an error.
    NoError = 0x0,
    /// `Internal Error` — An implementation specific error occurred.
    InternalError = 0x1,
    /// `Unauthorized` — The client is not authorized to establish a session.
    Unauthorized = 0x2,
    /// `Protocol Violation` — The remote endpoint performed an action that was disallowed by
    /// the specification.
    ProtocolViolation = 0x3,
    /// `Invalid Request ID` — The session was closed because the endpoint used a Request ID
    /// that was smaller than or equal to a previously received request ID, or the
    /// least-significant bit of the request ID was incorrect for the endpoint.
    InvalidRequestId = 0x4,
    /// `Duplicate Track Alias` — The endpoint attempted to use a Track Alias that was already
    /// in use.
    DuplicateTrackAlias = 0x5,
    /// `Key-Value Formatting Error` — the key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,
    /// `Too Many Requests` — The session was closed because the endpoint used a Request ID
    /// equal to or larger than the current Maximum Request ID.
    TooManyRequests = 0x7,
    /// `Invalid Path` — The PATH parameter was used by a server, on a WebTransport session, or
    /// the server does not support the path.
    InvalidPath = 0x8,
    /// `Malformed Path` — The PATH parameter does not conform to the rules in Section 8.3.2.1.
    MalformedPath = 0x9,
    /// `GOAWAY Timeout` — The session was closed because the peer took too long to close the
    /// session in response to a GOAWAY (Section 8.4) message. See session migration (Section
    /// 3.5).
    GoawayTimeout = 0x10,
    /// `Control Message Timeout` — The session was closed because the peer took too long to
    /// respond to a control message.
    ControlMessageTimeout = 0x11,
    /// `Data Stream Timeout` — The session was closed because the peer took too long to send
    /// data expected on an open Data Stream (see Section 9). This includes fields of a stream
    /// header or an object header within a data stream. If an endpoint times out waiting for a
    /// new object header on an open subgroup stream, it MAY send a STOP_SENDING on that stream
    /// or terminate the subscription.
    DataStreamTimeout = 0x12,
    /// `Auth Token Cache Overflow` — the Session limit Section 8.3.2.3 of the size of all
    /// registered Authorization tokens has been exceeded.
    AuthTokenCacheOverflow = 0x13,
    /// `Duplicate Auth Token Alias` — Authorization Token attempted to register an Alias that
    /// was in use (see Section 8.2.1.1).
    DuplicateAuthTokenAlias = 0x14,
    /// `Version Negotiation Failed` — The client didn't offer a version supported by the
    /// server.
    VersionNegotiationFailed = 0x15,
    /// `Malformed Auth Token` — Invalid Auth Token serialization during registration (see
    /// Section 8.2.1.1).
    MalformedAuthToken = 0x16,
    /// `Unknown Auth Token Alias` — No registered token found for the provided Alias (see
    /// Section 8.2.1.1).
    UnknownAuthTokenAlias = 0x17,
    /// `Expired Auth Token` — Authorization token has expired Section 8.2.1.1).
    ExpiredAuthToken = 0x18,
}

/// SUBSCRIBE_ERROR codes (draft-13 Section 8.9).
///
/// Carried in the Error Code field of SUBSCRIBE_ERROR. TRACK_STATUS_ERROR (Section 8.22) has no
/// registry of its own: the draft states its message format is identical to SUBSCRIBE_ERROR and
/// that its fields are populated exactly as SUBSCRIBE_ERROR would be, so these codes apply
/// there too.
///
/// The table assigns 0x0 through 0x5, then 0x10 and 0x12. 0x6 through 0xF and 0x11 are
/// unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeErrorCode {
    /// `Internal Error` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — The subscriber is not authorized to subscribe to the given track.
    Unauthorized = 0x1,
    /// `Timeout` — The subscription could not be completed before an implementation specific
    /// timeout. For example, a relay could not establish an upstream subscription within the
    /// timeout.
    Timeout = 0x2,
    /// `Not Supported` — The endpoint does not support the SUBSCRIBE method.
    NotSupported = 0x3,
    /// `Track Does Not Exist` — The requested track is not available at the publisher.
    TrackDoesNotExist = 0x4,
    /// `Invalid Range` — The end of the SUBSCRIBE range is earlier than the beginning, or the
    /// end of the range has already been published.
    InvalidRange = 0x5,
    /// `Malformed Auth Token` — Invalid Auth Token serialization during registration (see
    /// Section 8.2.1.1).
    MalformedAuthToken = 0x10,
    /// `Expired Auth Token` — Authorization token has expired Section 8.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// SUBSCRIBE_DONE status codes (draft-13 Section 8.12).
///
/// Carried in the Status Code field of SUBSCRIBE_DONE, described by the draft as "an integer
/// status code indicating why the subscription ended". This is a status registry, not an error
/// registry: 0x0 is Internal Error rather than a success value, and every code describes a way
/// a subscription can end.
///
/// Draft-14 renamed the message to PUBLISH_DONE and moved these eight assignments into an IANA
/// registry (its Section 13.1.3) with the same codes in the same order, adding the ALLCAPS
/// names this draft lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeDoneStatusCode {
    /// `Internal Error` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — The subscriber is no longer authorized to subscribe to the given track.
    Unauthorized = 0x1,
    /// `Track Ended` — The track is no longer being published.
    TrackEnded = 0x2,
    /// `Subscription Ended` — The publisher reached the end of an associated Subscribe filter.
    SubscriptionEnded = 0x3,
    /// `Going Away` — The subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,
    /// `Expired` — The publisher reached the timeout specified in SUBSCRIBE_OK.
    Expired = 0x5,
    /// `Too Far Behind` — The publisher's queue of objects to be sent to the given subscriber
    /// exceeds its implementation defined limit.
    TooFarBehind = 0x6,
    /// `Malformed Track` — A relay publisher detected the track was malformed (see Section
    /// 2.5).
    MalformedTrack = 0x7,
}

/// PUBLISH_ERROR codes (draft-13 Section 8.15).
///
/// Carried in the Error Code field of PUBLISH_ERROR. The table stops at 0x4; unlike the four
/// other request-error tables in this draft it does not assign the 0x10 and 0x12 auth-token
/// codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishErrorCode {
    /// `Internal Error` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — The publisher is not authorized to publish the given namespace or
    /// track.
    Unauthorized = 0x1,
    /// `Timeout` — The subscription could not be established before an implementation specific
    /// timeout.
    Timeout = 0x2,
    /// `Not Supported` — The endpoint does not support the PUBLISH method.
    NotSupported = 0x3,
    /// `Uninterested` — The namespace or track is not of interest to the endpoint.
    Uninterested = 0x4,
}

/// FETCH_ERROR codes (draft-13 Section 8.18).
///
/// Carried in the Error Code field of FETCH_ERROR.
///
/// The table assigns 0x0 through 0x9, then 0x10 and 0x12. 0xA through 0xF and 0x11 are
/// unassigned.
///
/// Draft-13 names two of these codes inconsistently between its table and the prose immediately
/// below it. The table cell for 0x3 reads `Not Supported` while the prose reads `Not
/// supported`, and the table cell for 0x7 reads `Invalid Joining Request ID` while the prose
/// still reads `Invalid Joining Subscribe ID`. The table spelling is used for the variant names
/// here; the prose is quoted on the variants unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchErrorCode {
    /// `Internal Error` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — The subscriber is not authorized to fetch from the given track.
    Unauthorized = 0x1,
    /// `Timeout` — The fetch could not be completed before an implementation specific timeout.
    /// For example, a relay could not FETCH missing objects within the timeout.
    Timeout = 0x2,
    /// `Not Supported` — The endpoint does not support the FETCH method.
    NotSupported = 0x3,
    /// `Track Does Not Exist` — The requested track is not available at the publisher.
    TrackDoesNotExist = 0x4,
    /// `Invalid Range` — The end of the requested range is earlier than the beginning, the
    /// start of the requested range is beyond the Largest Location, or the track has not
    /// published any Objects yet.
    InvalidRange = 0x5,
    /// `No Objects` — No Objects exist between the requested Start and End Locations.
    NoObjects = 0x6,
    /// `Invalid Joining Request ID` — The joining Fetch referenced a Request ID that did not
    /// belong to an active Subscription.
    InvalidJoiningRequestId = 0x7,
    /// `Unknown Status in Range` — The requested range contains objects with unknown status.
    UnknownStatusInRange = 0x8,
    /// `Malformed Track` — A relay publisher detected the track was malformed (see Section
    /// 2.5).
    MalformedTrack = 0x9,
    /// `Malformed Auth Token` — Invalid Auth Token serialization during registration (see
    /// Section 8.2.1.1).
    MalformedAuthToken = 0x10,
    /// `Expired Auth Token` — Authorization token has expired Section 8.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// ANNOUNCE_ERROR codes (draft-13 Section 8.25).
///
/// Carried in the Error Code field of ANNOUNCE_ERROR, and also in the Error Code field of
/// ANNOUNCE_CANCEL: draft-13 Section 8.27 states that ANNOUNCE_CANCEL uses the same error codes
/// as ANNOUNCE_ERROR.
///
/// The table assigns 0x0 through 0x4, then 0x10 and 0x12. 0x5 through 0xF and 0x11 are
/// unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AnnounceErrorCode {
    /// `Internal Error` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — The subscriber is not authorized to announce the given namespace.
    Unauthorized = 0x1,
    /// `Timeout` — The announce could not be completed before an implementation specific
    /// timeout.
    Timeout = 0x2,
    /// `Not Supported` — The endpoint does not support the ANNOUNCE method.
    NotSupported = 0x3,
    /// `Uninterested` — The namespace is not of interest to the endpoint.
    Uninterested = 0x4,
    /// `Malformed Auth Token` — Invalid Auth Token serialization during registration (see
    /// Section 8.2.1.1).
    MalformedAuthToken = 0x10,
    /// `Expired Auth Token` — Authorization token has expired Section 8.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// SUBSCRIBE_NAMESPACE_ERROR codes (draft-13 Section 8.30).
///
/// Carried in the Error Code field of SUBSCRIBE_NAMESPACE_ERROR.
///
/// The table assigns 0x0 through 0x5, then 0x10 and 0x12. 0x6 through 0xF and 0x11 are
/// unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeNamespaceErrorCode {
    /// `Internal Error` — An implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — The subscriber is not authorized to subscribe to the given namespace
    /// prefix.
    Unauthorized = 0x1,
    /// `Timeout` — The operation could not be completed before an implementation specific
    /// timeout.
    Timeout = 0x2,
    /// `Not Supported` — The endpoint does not support the SUBSCRIBE_NAMESPACE method.
    NotSupported = 0x3,
    /// `Namespace Prefix Unknown` — The namespace prefix is not available for subscription.
    NamespacePrefixUnknown = 0x4,
    /// `Namespace Prefix Overlap` — The namespace prefix overlaps with another
    /// SUBSCRIBE_NAMESPACE in the same session.
    NamespacePrefixOverlap = 0x5,
    /// `Malformed Auth Token` — Invalid Auth Token serialization during registration (see
    /// Section 8.2.1.1).
    MalformedAuthToken = 0x10,
    /// `Expired Auth Token` — Authorization token has expired Section 8.2.1.1).
    ExpiredAuthToken = 0x12,
}

/// Data stream reset codes (draft-13 Section 9.4.3, Closing Subgroup Streams).
///
/// Sent in the QUIC `RESET_STREAM` or `RESET_STREAM_AT` frame that ends a subgroup stream
/// early. Draft-14 carries the same four assignments forward as its Data Stream Reset Error
/// Codes registry (its Section 13.1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamResetErrorCode {
    /// `Internal Error` — An implementation specific error
    InternalError = 0x0,
    /// `Cancelled` — The subscriber requested cancellation via UNSUBSCRIBE, FETCH_CANCEL or
    /// STOP_SENDING, or the publisher ended the subscription, in which case SUBSCRIBE_DONE
    /// (Section 8.12) will have a more detailed status code.
    Cancelled = 0x1,
    /// `Delivery Timeout` — The DELIVERY TIMEOUT Section 8.2.1.2 was exceeded for this stream
    DeliveryTimeout = 0x2,
    /// `Session Closed` — The publisher session is being closed
    SessionClosed = 0x3,
}

impl SessionErrorCode {
    /// Every session termination code draft-13 assigns, in ascending wire order.
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
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeErrorCode {
    /// Every SUBSCRIBE_ERROR code draft-13 assigns, in ascending wire order.
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

impl SubscribeDoneStatusCode {
    /// Every SUBSCRIBE_DONE status code draft-13 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SubscribeDoneStatusCode] = &[
        SubscribeDoneStatusCode::InternalError,
        SubscribeDoneStatusCode::Unauthorized,
        SubscribeDoneStatusCode::TrackEnded,
        SubscribeDoneStatusCode::SubscriptionEnded,
        SubscribeDoneStatusCode::GoingAway,
        SubscribeDoneStatusCode::Expired,
        SubscribeDoneStatusCode::TooFarBehind,
        SubscribeDoneStatusCode::MalformedTrack,
    ];

    /// Convert a raw u64 to a `SubscribeDoneStatusCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeDoneStatusCode::InternalError),
            0x1 => Some(SubscribeDoneStatusCode::Unauthorized),
            0x2 => Some(SubscribeDoneStatusCode::TrackEnded),
            0x3 => Some(SubscribeDoneStatusCode::SubscriptionEnded),
            0x4 => Some(SubscribeDoneStatusCode::GoingAway),
            0x5 => Some(SubscribeDoneStatusCode::Expired),
            0x6 => Some(SubscribeDoneStatusCode::TooFarBehind),
            0x7 => Some(SubscribeDoneStatusCode::MalformedTrack),
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishErrorCode {
    /// Every PUBLISH_ERROR code draft-13 assigns, in ascending wire order.
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
    /// Every FETCH_ERROR code draft-13 assigns, in ascending wire order.
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
    /// Every ANNOUNCE_ERROR code draft-13 assigns, in ascending wire order.
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
    /// Every SUBSCRIBE_NAMESPACE_ERROR code draft-13 assigns, in ascending wire order.
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

impl StreamResetErrorCode {
    /// Every subgroup stream reset code draft-13 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[StreamResetErrorCode] = &[
        StreamResetErrorCode::InternalError,
        StreamResetErrorCode::Cancelled,
        StreamResetErrorCode::DeliveryTimeout,
        StreamResetErrorCode::SessionClosed,
    ];

    /// Convert a raw u64 to a `StreamResetErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(StreamResetErrorCode::InternalError),
            0x1 => Some(StreamResetErrorCode::Cancelled),
            0x2 => Some(StreamResetErrorCode::DeliveryTimeout),
            0x3 => Some(StreamResetErrorCode::SessionClosed),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

//! Draft-11 error and status code registries.
//!
//! Draft-11 predates the IANA registries introduced in draft-14: every code
//! point here is defined by an inline `Code`/`Reason` table in the body of the
//! document, and each table is scoped to one control message rather than to a
//! shared registry. The tables carry no symbolic ALLCAPS names, so each variant
//! name below is derived from the reason text and the doc comment repeats the
//! draft's own wording verbatim, so the mapping stays checkable against the
//! document.
//!
//! Every `from_u64` returns `None` for a code this draft does not define. Peers
//! do send codes from other drafts and from private extensions, and a decoder
//! that panics on one is a decoder that dies on the wire.
//!
//! Not every draft-11 code registry is written as a table. `TrackStatusCode`
//! below comes from a prose list in the body of section 8.18, and the object
//! status values of section 9.1.1.1 are likewise prose; those live in
//! `super::types::ObjectStatus` rather than here.

/// Session termination codes, from the table in draft-11 section 3.4
/// (Termination). Carried in the session-level termination error code.
///
/// The draft assigns 0x0 through 0x9 and then 0x10 through 0x15; 0xA through
/// 0xF are not assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `No Error` — the session is being terminated without an error.
    NoError = 0x0,
    /// `Internal Error` — an implementation specific error occurred.
    InternalError = 0x1,
    /// `Unauthorized` — the endpoint breached an agreement, which MAY have been
    /// pre-negotiated by the application.
    Unauthorized = 0x2,
    /// `Protocol Violation` — the remote endpoint performed an action that was
    /// disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `Invalid Request ID` — the session was closed because the endpoint used a
    /// Request ID that was smaller than or equal to a previously received
    /// request ID, or the least-significant bit of the request ID was incorrect
    /// for the endpoint.
    InvalidRequestId = 0x4,
    /// `Duplicate Track Alias` — the endpoint attempted to use a Track Alias
    /// that was already in use.
    DuplicateTrackAlias = 0x5,
    /// `Key-Value Formatting Error` — the key-value pair has a formatting error.
    KeyValueFormattingError = 0x6,
    /// `Too Many Requests` — the session was closed because the endpoint used a
    /// Request ID equal or larger than the current Maximum Request ID.
    TooManyRequests = 0x7,
    /// `Invalid Path` — the PATH parameter was used by a server, on a
    /// WebTransport session, or the server does not support the path.
    InvalidPath = 0x8,
    /// `Malformed Path` — the PATH parameter does not conform to the rules in
    /// draft-11 section 8.3.2.1.
    MalformedPath = 0x9,
    /// `GOAWAY Timeout` — the session was closed because the peer took too long
    /// to close the session in response to a GOAWAY message. See session
    /// migration, draft-11 section 3.5.
    GoawayTimeout = 0x10,
    /// `Control Message Timeout` — the session was closed because the peer took
    /// too long to respond to a control message.
    ControlMessageTimeout = 0x11,
    /// `Data Stream Timeout` — the session was closed because the peer took too
    /// long to send data expected on an open data stream. This includes fields
    /// of a stream header or an object header within a data stream. An endpoint
    /// that times out waiting for a new object header on an open subgroup
    /// stream MAY instead send STOP_SENDING on that stream or terminate the
    /// subscription.
    DataStreamTimeout = 0x12,
    /// `Auth Token Cache Overflow` — the session limit on the total size of all
    /// registered authorization tokens has been exceeded. See draft-11
    /// section 8.3.2.3.
    AuthTokenCacheOverflow = 0x13,
    /// `Duplicate Auth Token Alias` — an Authorization Token attempted to
    /// register an alias that was in use. See draft-11 section 8.2.1.1.
    DuplicateAuthTokenAlias = 0x14,
    /// `Version Negotiation Failed` — the client didn't offer a version
    /// supported by the server.
    VersionNegotiationFailed = 0x15,
}

/// SUBSCRIBE_ERROR codes, from the table in draft-11 section 8.9.
///
/// The draft assigns 0x0 through 0x6 and then 0x10 through 0x12; 0x7 through
/// 0xF are not assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeErrorCode {
    /// `Internal Error` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — the subscriber is not authorized to subscribe to the
    /// given track.
    Unauthorized = 0x1,
    /// `Timeout` — the subscription could not be completed before an
    /// implementation specific timeout. For example, a relay could not
    /// establish an upstream subscription within the timeout.
    Timeout = 0x2,
    /// `Not Supported` — the endpoint does not support the SUBSCRIBE method.
    NotSupported = 0x3,
    /// `Track Does Not Exist` — the requested track is not available at the
    /// publisher.
    TrackDoesNotExist = 0x4,
    /// `Invalid Range` — the end of the SUBSCRIBE range is earlier than the
    /// beginning, or the end of the range has already been published.
    InvalidRange = 0x5,
    /// `Retry Track Alias` — the publisher requires the subscriber to use the
    /// given Track Alias when subscribing. The alias to retry with is carried
    /// in the Track Alias field of the SUBSCRIBE_ERROR message.
    RetryTrackAlias = 0x6,
    /// `Malformed Auth Token` — invalid Auth Token serialization during
    /// registration. See draft-11 section 8.2.1.1.
    MalformedAuthToken = 0x10,
    /// `Unknown Auth Token Alias` — the Authorization Token refers to an alias
    /// that is not registered. See draft-11 section 8.2.1.1.
    UnknownAuthTokenAlias = 0x11,
    /// `Expired Auth Token` — the authorization token has expired. See draft-11
    /// section 8.2.1.1.
    ExpiredAuthToken = 0x12,
}

/// SUBSCRIBE_DONE status codes, from the table in draft-11 section 8.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeDoneStatusCode {
    /// `Internal Error` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — the subscriber is no longer authorized to subscribe to
    /// the given track.
    Unauthorized = 0x1,
    /// `Track Ended` — the track is no longer being published.
    TrackEnded = 0x2,
    /// `Subscription Ended` — the publisher reached the end of an associated
    /// Subscribe filter.
    SubscriptionEnded = 0x3,
    /// `Going Away` — the subscriber or publisher issued a GOAWAY message.
    GoingAway = 0x4,
    /// `Expired` — the publisher reached the timeout specified in SUBSCRIBE_OK.
    Expired = 0x5,
    /// `Too Far Behind` — the publisher's queue of objects to be sent to the
    /// given subscriber exceeds its implementation defined limit.
    TooFarBehind = 0x6,
}

/// FETCH_ERROR codes, from the table in draft-11 section 8.15.
///
/// The draft assigns 0x0 through 0x7 and then 0x10 through 0x12; 0x8 through
/// 0xF are not assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchErrorCode {
    /// `Internal Error` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — the subscriber is not authorized to fetch from the given
    /// track.
    Unauthorized = 0x1,
    /// `Timeout` — the fetch could not be completed before an implementation
    /// specific timeout. For example, a relay could not FETCH missing objects
    /// within the timeout.
    Timeout = 0x2,
    /// `Not Supported` — the endpoint does not support the FETCH method.
    NotSupported = 0x3,
    /// `Track Does Not Exist` — the requested track is not available at the
    /// publisher.
    TrackDoesNotExist = 0x4,
    /// `Invalid Range` — the end of the requested range is earlier than the
    /// beginning, the start of the requested range is beyond the Largest
    /// Object, or the track has not published any Objects yet.
    InvalidRange = 0x5,
    /// `No Objects` — no Objects exist between the requested Start and End
    /// Locations.
    NoObjects = 0x6,
    /// `Invalid Joining Subscribe ID` — the joining Fetch referenced a Request
    /// ID that did not belong to an active Subscription.
    InvalidJoiningSubscribeId = 0x7,
    /// `Malformed Auth Token` — invalid Auth Token serialization during
    /// registration. See draft-11 section 8.2.1.1.
    MalformedAuthToken = 0x10,
    /// `Unknown Auth Token Alias` — the Authorization Token refers to an alias
    /// that is not registered. See draft-11 section 8.2.1.1.
    UnknownAuthTokenAlias = 0x11,
    /// `Expired Auth Token` — the authorization token has expired. See draft-11
    /// section 8.2.1.1.
    ExpiredAuthToken = 0x12,
}

/// ANNOUNCE_ERROR codes, from the table in draft-11 section 8.21.
///
/// The draft assigns 0x0 through 0x4 and then 0x10 through 0x12; 0x5 through
/// 0xF are not assigned.
///
/// These codes are also carried in the Error Code field of ANNOUNCE_CANCEL:
/// draft-11 section 8.23 states that ANNOUNCE_CANCEL uses the same error codes
/// as ANNOUNCE_ERROR, and defines no registry of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AnnounceErrorCode {
    /// `Internal Error` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — the subscriber is not authorized to announce the given
    /// namespace.
    Unauthorized = 0x1,
    /// `Timeout` — the announce could not be completed before an implementation
    /// specific timeout.
    Timeout = 0x2,
    /// `Not Supported` — the endpoint does not support the ANNOUNCE method.
    NotSupported = 0x3,
    /// `Uninterested` — the namespace is not of interest to the endpoint.
    Uninterested = 0x4,
    /// `Malformed Auth Token` — invalid Auth Token serialization during
    /// registration. See draft-11 section 8.2.1.1.
    MalformedAuthToken = 0x10,
    /// `Unknown Auth Token Alias` — the Authorization Token refers to an alias
    /// that is not registered. See draft-11 section 8.2.1.1.
    UnknownAuthTokenAlias = 0x11,
    /// `Expired Auth Token` — the authorization token has expired. See draft-11
    /// section 8.2.1.1.
    ExpiredAuthToken = 0x12,
}

/// SUBSCRIBE_ANNOUNCES_ERROR codes, from the table in draft-11 section 8.26.
///
/// The draft assigns 0x0 through 0x5 and then 0x10 through 0x12; 0x6 through
/// 0xF are not assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeAnnouncesErrorCode {
    /// `Internal Error` — an implementation specific or generic error occurred.
    InternalError = 0x0,
    /// `Unauthorized` — the subscriber is not authorized to subscribe to the
    /// given namespace prefix.
    Unauthorized = 0x1,
    /// `Timeout` — the operation could not be completed before an
    /// implementation specific timeout.
    Timeout = 0x2,
    /// `Not Supported` — the endpoint does not support the SUBSCRIBE_ANNOUNCES
    /// method.
    NotSupported = 0x3,
    /// `Namespace Prefix Unknown` — the namespace prefix is not available for
    /// subscription.
    NamespacePrefixUnknown = 0x4,
    /// `Namespace Prefix Overlap` — the namespace prefix overlaps with another
    /// SUBSCRIBE_ANNOUNCES in the same session.
    NamespacePrefixOverlap = 0x5,
    /// `Malformed Auth Token` — invalid Auth Token serialization during
    /// registration. See draft-11 section 8.2.1.1.
    MalformedAuthToken = 0x10,
    /// `Unknown Auth Token Alias` — the Authorization Token refers to an alias
    /// that is not registered. See draft-11 section 8.2.1.1.
    UnknownAuthTokenAlias = 0x11,
    /// `Expired Auth Token` — the authorization token has expired. See draft-11
    /// section 8.2.1.1.
    ExpiredAuthToken = 0x12,
}

/// TRACK_STATUS status codes, carried in the Status Code field of the
/// TRACK_STATUS message.
///
/// Draft-11 section 8.18 defines these as a prose list rather than as a
/// `Code`/`Reason` table, which is why they are named from the prose here. The
/// draft is stricter about this field than about the error registries above: it
/// says the Status Code MUST hold one of these values and that any other value
/// is a malformed message, so `from_u64` returning `None` is a decode failure
/// rather than a merely unrecognised code.
///
/// The draft also carries an unresolved editorial note about authorization
/// failures in this section, so a later draft may add codes here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TrackStatusCode {
    /// The track is in progress, and subsequent fields contain the highest
    /// group and object ID for that track.
    InProgress = 0x00,
    /// The track does not exist. Subsequent fields MUST be zero, and any other
    /// value is a malformed message.
    TrackDoesNotExist = 0x01,
    /// The track has not yet begun. Subsequent fields MUST be zero, and any
    /// other value is a malformed message.
    NotYetBegun = 0x02,
    /// The track has finished, so there is no live edge. Subsequent fields
    /// contain the highest group and object ID known.
    Finished = 0x03,
    /// The publisher is a relay that cannot obtain the current track status
    /// from upstream. Subsequent fields contain the largest group and object
    /// ID known.
    RelayStatusUnavailable = 0x04,
}

/// Data stream reset codes, from the table in draft-11 section 9.4.3 (Closing
/// Subgroup Streams). Carried in RESET_STREAM and RESET_STREAM_AT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamResetErrorCode {
    /// `Internal Error` — an implementation specific error.
    InternalError = 0x0,
    /// `Cancelled` — the subscriber requested cancellation via UNSUBSCRIBE,
    /// FETCH_CANCEL or STOP_SENDING, or the publisher ended the subscription,
    /// in which case SUBSCRIBE_DONE will have a more detailed status code.
    Cancelled = 0x1,
    /// `Delivery Timeout` — the DELIVERY TIMEOUT was exceeded for this stream.
    /// See draft-11 section 8.2.1.2.
    DeliveryTimeout = 0x2,
    /// `Session Closed` — the publisher session is being closed.
    SessionClosed = 0x3,
}

impl SessionErrorCode {
    /// Every session termination code draft-11 assigns, in ascending wire order.
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
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeErrorCode {
    /// Every SUBSCRIBE_ERROR code draft-11 assigns, in ascending wire order.
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
        SubscribeErrorCode::RetryTrackAlias,
        SubscribeErrorCode::MalformedAuthToken,
        SubscribeErrorCode::UnknownAuthTokenAlias,
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
            0x6 => Some(SubscribeErrorCode::RetryTrackAlias),
            0x10 => Some(SubscribeErrorCode::MalformedAuthToken),
            0x11 => Some(SubscribeErrorCode::UnknownAuthTokenAlias),
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
    /// Every SUBSCRIBE_DONE status code draft-11 assigns, in ascending wire order.
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
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl FetchErrorCode {
    /// Every FETCH_ERROR code draft-11 assigns, in ascending wire order.
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
        FetchErrorCode::InvalidJoiningSubscribeId,
        FetchErrorCode::MalformedAuthToken,
        FetchErrorCode::UnknownAuthTokenAlias,
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
            0x7 => Some(FetchErrorCode::InvalidJoiningSubscribeId),
            0x10 => Some(FetchErrorCode::MalformedAuthToken),
            0x11 => Some(FetchErrorCode::UnknownAuthTokenAlias),
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
    /// Every ANNOUNCE_ERROR code draft-11 assigns, in ascending wire order.
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
        AnnounceErrorCode::UnknownAuthTokenAlias,
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
            0x11 => Some(AnnounceErrorCode::UnknownAuthTokenAlias),
            0x12 => Some(AnnounceErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeAnnouncesErrorCode {
    /// Every SUBSCRIBE_ANNOUNCES_ERROR code draft-11 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SubscribeAnnouncesErrorCode] = &[
        SubscribeAnnouncesErrorCode::InternalError,
        SubscribeAnnouncesErrorCode::Unauthorized,
        SubscribeAnnouncesErrorCode::Timeout,
        SubscribeAnnouncesErrorCode::NotSupported,
        SubscribeAnnouncesErrorCode::NamespacePrefixUnknown,
        SubscribeAnnouncesErrorCode::NamespacePrefixOverlap,
        SubscribeAnnouncesErrorCode::MalformedAuthToken,
        SubscribeAnnouncesErrorCode::UnknownAuthTokenAlias,
        SubscribeAnnouncesErrorCode::ExpiredAuthToken,
    ];

    /// Convert a raw u64 to a `SubscribeAnnouncesErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeAnnouncesErrorCode::InternalError),
            0x1 => Some(SubscribeAnnouncesErrorCode::Unauthorized),
            0x2 => Some(SubscribeAnnouncesErrorCode::Timeout),
            0x3 => Some(SubscribeAnnouncesErrorCode::NotSupported),
            0x4 => Some(SubscribeAnnouncesErrorCode::NamespacePrefixUnknown),
            0x5 => Some(SubscribeAnnouncesErrorCode::NamespacePrefixOverlap),
            0x10 => Some(SubscribeAnnouncesErrorCode::MalformedAuthToken),
            0x11 => Some(SubscribeAnnouncesErrorCode::UnknownAuthTokenAlias),
            0x12 => Some(SubscribeAnnouncesErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl TrackStatusCode {
    /// Convert a raw u64 to a `TrackStatusCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x00 => Some(TrackStatusCode::InProgress),
            0x01 => Some(TrackStatusCode::TrackDoesNotExist),
            0x02 => Some(TrackStatusCode::NotYetBegun),
            0x03 => Some(TrackStatusCode::Finished),
            0x04 => Some(TrackStatusCode::RelayStatusUnavailable),
            _ => None,
        }
    }

    /// Whether this code requires the fields after it to be zero.
    ///
    /// Section 8.18 says of 0x01 "Subsequent fields MUST be zero, and any other
    /// value is a malformed message", and the same of 0x02. The other three
    /// codes describe those fields as carrying a real location, so they place
    /// no requirement on them.
    pub fn requires_zero_location(self) -> bool {
        matches!(self, TrackStatusCode::TrackDoesNotExist | TrackStatusCode::NotYetBegun)
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl StreamResetErrorCode {
    /// Every subgroup stream reset code draft-11 assigns, in ascending wire order.
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

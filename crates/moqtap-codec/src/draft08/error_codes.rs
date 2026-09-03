//! Error, status and termination code registries defined by
//! draft-ietf-moq-transport-08.
//!
//! One enum per registry. Draft-08 predates the IANA registry tables of the
//! later drafts: its tables carry only a code and a reason phrase, and assign no
//! symbolic ALLCAPS names. Each variant name below is therefore UpperCamelCase
//! derived from the reason phrase, not taken from the draft, and every variant's
//! doc comment quotes that phrase verbatim in backticks so the mapping back to
//! the draft stays checkable. Where the draft also defines a code in prose, that
//! prose follows the phrase.
//!
//! `from_u64` returns `None` for any value the draft does not assign. A peer may
//! legitimately send a code from a later draft or a private extension, and an
//! unrecognized code must not be a decode failure at this layer.
//!
//! Draft-08 assigns no reserved-for-greasing ranges in these registries; every
//! row is a single code point.
//!
//! Codes that share a spelling across registries do not always share a meaning,
//! and draft-08 spellings do not always carry over to later drafts.
//! `Unauthorized` is the clearest case: in
//! [`SessionErrorCode`] it
//! reports a breach of a pre-negotiated agreement, which is not what the
//! identically named code means in the request-scoped registries or in later
//! drafts.

/// Session termination codes (draft-08, section 3.5 "Termination").
///
/// Carried in the QUIC CONNECTION_CLOSE frame or the WebTransport
/// CLOSE_WEBTRANSPORT_SESSION capsule. The draft assigns 0x0 through 0x6 and
/// 0x10 through 0x12; 0x7 through 0xF are unassigned.
///
/// Section 3.5 defines every code in this registry in prose except
/// `Parameter Length Mismatch` (0x5), which the table assigns but the prose
/// list skips; that variant carries the reason phrase alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `No Error` — The session is being terminated without an error.
    NoError = 0x0,
    /// `Internal Error` — An implementation specific error occurred.
    InternalError = 0x1,
    /// `Unauthorized` — The endpoint breached an agreement, which MAY have been
    /// pre-negotiated by the application.
    ///
    /// This is a breach of agreement, not a failed authentication or a refused
    /// credential.
    Unauthorized = 0x2,
    /// `Protocol Violation` — The remote endpoint performed an action that was
    /// disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `Duplicate Track Alias` — The endpoint attempted to use a Track Alias
    /// that was already in use.
    DuplicateTrackAlias = 0x4,
    /// `Parameter Length Mismatch`
    ///
    /// Section 3.5 assigns this code in its table but does not define it in
    /// prose, so the reason phrase above is the whole of the draft's
    /// description.
    ParameterLengthMismatch = 0x5,
    /// `Too Many Subscribes` — The session was closed because the subscriber
    /// used a Subscribe ID equal or larger than the current Maximum Subscribe
    /// ID.
    ///
    /// This reports a Subscribe ID above the advertised maximum, not a count of
    /// concurrent subscriptions.
    TooManySubscribes = 0x6,
    /// `GOAWAY Timeout` — The session was closed because the peer took too long
    /// to close the session in response to a GOAWAY (Section 7.3) message. See
    /// session migration (Section 3.6).
    GoawayTimeout = 0x10,
    /// `Control Message Timeout` — The session was closed because the peer took
    /// too long to respond to a control message.
    ControlMessageTimeout = 0x11,
    /// `Data Stream Timeout` — The session was closed because the peer took too
    /// long to send data expected on an open Data Stream (Section 8). This
    /// includes fields of a stream header or an object header within a data
    /// stream.
    ///
    /// Closing the session is only one of the responses the draft permits here.
    /// Section 3.5: an endpoint that times out waiting for a new object header
    /// on an open subgroup stream MAY send STOP_SENDING on that stream,
    /// terminate the subscription, or close the session with an error.
    DataStreamTimeout = 0x12,
}

/// ANNOUNCE_ERROR codes (draft-08, section 7.10 "ANNOUNCE_ERROR").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AnnounceErrorCode {
    /// `Internal Error`
    InternalError = 0x0,
    /// `Unauthorized`
    Unauthorized = 0x1,
    /// `Timeout`
    Timeout = 0x2,
    /// `Not Supported`
    NotSupported = 0x3,
    /// `Uninterested`
    Uninterested = 0x4,
}

/// SUBSCRIBE_ERROR codes (draft-08, section 7.16 "SUBSCRIBE_ERROR").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeErrorCode {
    /// `Internal Error`
    InternalError = 0x0,
    /// `Unauthorized`
    Unauthorized = 0x1,
    /// `Timeout`
    Timeout = 0x2,
    /// `Not Supported`
    NotSupported = 0x3,
    /// `Track Does Not Exist`
    TrackDoesNotExist = 0x4,
    /// `Invalid Range`
    InvalidRange = 0x5,
    /// `Retry Track Alias`
    ///
    /// Not a plain failure. Section 7.16 states that when the Error Code is
    /// `Retry Track Alias`, the subscriber SHOULD re-issue the SUBSCRIBE using
    /// the Track Alias carried in the SUBSCRIBE_ERROR message instead of the one
    /// it chose; if that Track Alias is already in use, the subscriber MUST
    /// close the connection with `Duplicate Track Alias` (Section 3.5).
    RetryTrackAlias = 0x6,
}

/// FETCH_ERROR codes (draft-08, section 7.18 "FETCH_ERROR").
///
/// The same first six code points as [`SubscribeErrorCode`]; this registry has
/// no equivalent of `Retry Track Alias` (0x6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchErrorCode {
    /// `Internal Error`
    InternalError = 0x0,
    /// `Unauthorized`
    Unauthorized = 0x1,
    /// `Timeout`
    Timeout = 0x2,
    /// `Not Supported`
    NotSupported = 0x3,
    /// `Track Does Not Exist`
    TrackDoesNotExist = 0x4,
    /// `Invalid Range`
    InvalidRange = 0x5,
}

/// SUBSCRIBE_DONE status codes (draft-08, section 7.19 "SUBSCRIBE_DONE").
///
/// The draft calls these status codes rather than error codes. Section 7.19:
/// "The Status Code indicates why the subscription ended, and whether it was an
/// error." Both outcomes appear in the registry, so receiving one of these does
/// not by itself mean the subscription failed.
///
/// Note that 0x2 is `Track Ended` here, whereas the four request-scoped
/// registries in this draft assign `Timeout` to 0x2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeDoneStatusCode {
    /// `Internal Error`
    InternalError = 0x0,
    /// `Unauthorized`
    Unauthorized = 0x1,
    /// `Track Ended`
    TrackEnded = 0x2,
    /// `Subscription Ended`
    SubscriptionEnded = 0x3,
    /// `Going Away`
    GoingAway = 0x4,
    /// `Expired`
    Expired = 0x5,
    /// `Too Far Behind`
    TooFarBehind = 0x6,
}

/// SUBSCRIBE_ANNOUNCES_ERROR codes (draft-08, section 7.26
/// "SUBSCRIBE_ANNOUNCES_ERROR").
///
/// This registry agrees with [`AnnounceErrorCode`] on 0x0 through 0x3 and then
/// diverges: 0x4 is `Namespace Prefix Unknown` here and `Uninterested` there.
/// The request-scoped registries in this draft are kept as separate types
/// because 0x4 carries three different meanings across them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeAnnouncesErrorCode {
    /// `Internal Error`
    InternalError = 0x0,
    /// `Unauthorized`
    Unauthorized = 0x1,
    /// `Timeout`
    Timeout = 0x2,
    /// `Not Supported`
    NotSupported = 0x3,
    /// `Namespace Prefix Unknown`
    NamespacePrefixUnknown = 0x4,
}

impl SessionErrorCode {
    /// Every session termination code draft-08 assigns, in ascending wire order.
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
        SessionErrorCode::DuplicateTrackAlias,
        SessionErrorCode::ParameterLengthMismatch,
        SessionErrorCode::TooManySubscribes,
        SessionErrorCode::GoawayTimeout,
        SessionErrorCode::ControlMessageTimeout,
        SessionErrorCode::DataStreamTimeout,
    ];

    /// Convert a raw u64 to a `SessionErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SessionErrorCode::NoError),
            0x1 => Some(SessionErrorCode::InternalError),
            0x2 => Some(SessionErrorCode::Unauthorized),
            0x3 => Some(SessionErrorCode::ProtocolViolation),
            0x4 => Some(SessionErrorCode::DuplicateTrackAlias),
            0x5 => Some(SessionErrorCode::ParameterLengthMismatch),
            0x6 => Some(SessionErrorCode::TooManySubscribes),
            0x10 => Some(SessionErrorCode::GoawayTimeout),
            0x11 => Some(SessionErrorCode::ControlMessageTimeout),
            0x12 => Some(SessionErrorCode::DataStreamTimeout),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl AnnounceErrorCode {
    /// Every ANNOUNCE_ERROR code draft-08 assigns, in ascending wire order.
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
    ];

    /// Convert a raw u64 to an `AnnounceErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(AnnounceErrorCode::InternalError),
            0x1 => Some(AnnounceErrorCode::Unauthorized),
            0x2 => Some(AnnounceErrorCode::Timeout),
            0x3 => Some(AnnounceErrorCode::NotSupported),
            0x4 => Some(AnnounceErrorCode::Uninterested),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeErrorCode {
    /// Every SUBSCRIBE_ERROR code draft-08 assigns, in ascending wire order.
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
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl FetchErrorCode {
    /// Every FETCH_ERROR code draft-08 assigns, in ascending wire order.
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
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeDoneStatusCode {
    /// Every SUBSCRIBE_DONE status code draft-08 assigns, in ascending wire order.
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

impl SubscribeAnnouncesErrorCode {
    /// Every SUBSCRIBE_ANNOUNCES_ERROR code draft-08 assigns, in ascending wire order.
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
    ];

    /// Convert a raw u64 to a `SubscribeAnnouncesErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeAnnouncesErrorCode::InternalError),
            0x1 => Some(SubscribeAnnouncesErrorCode::Unauthorized),
            0x2 => Some(SubscribeAnnouncesErrorCode::Timeout),
            0x3 => Some(SubscribeAnnouncesErrorCode::NotSupported),
            0x4 => Some(SubscribeAnnouncesErrorCode::NamespacePrefixUnknown),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// TRACK_STATUS Status Code values (draft-08, Section 7.24).
///
/// The draft defines these as a prose list rather than as a `Code`/`Reason`
/// table, so they are named from the prose. It is stricter about this field
/// than about the error registries above: the Status Code "MUST hold one of the
/// following values" and "Any other value in the Status Code field is a
/// malformed message", so [`TrackStatusCode::from_u64`] answering `None` is a
/// decode failure rather than a merely unrecognised code.
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

impl TrackStatusCode {
    /// Convert a raw u64 to a `TrackStatusCode`, if this draft assigns it.
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
    /// Section 7.24 says of 0x01 "Subsequent fields MUST be zero, and any other
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

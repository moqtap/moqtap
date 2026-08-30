//! The error, status and termination code registries that MoQ Transport
//! draft-09 publishes as `Code`/`Reason` tables.
//!
//! Draft-09 predates the IANA registries introduced in later drafts. Every
//! registry here is an inline two-column table with a `Code` column and a
//! `Reason` column, and the draft assigns no ALLCAPS symbolic names to the code
//! points. Each variant's doc comment therefore quotes the draft's `Reason`
//! text verbatim so the mapping from the table to the Rust name is checkable by
//! eye; where the draft explains a code in prose, that explanation follows.
//!
//! # Scope
//!
//! Draft-09 has six such tables and all six are transcribed here: Section 3.5
//! (Termination), Section 7.10 (ANNOUNCE_ERROR), Section 7.16
//! (SUBSCRIBE_ERROR), Section 7.18 (FETCH_ERROR), Section 7.19 (SUBSCRIBE_DONE)
//! and Section 7.26 (SUBSCRIBE_ANNOUNCES_ERROR). Draft-09 assigns code points
//! in two further places, neither of which is a `Code`/`Reason` table and
//! neither of which belongs here:
//!
//! - Section 7.24 assigns TRACK_STATUS Status Codes 0x00 through 0x04 in a
//!   prose list. That registry is closed — the draft says the field "MUST hold
//!   one of the following values. Any other value is a malformed message" —
//!   which is the opposite of the open registries below, so folding it in would
//!   misrepresent it. [`super::message::TrackStatus`] carries the field as a
//!   raw `VarInt`.
//! - Section 8.1.1.1 assigns Object Status 0x0, 0x1, 0x3, 0x4 and 0x5 (0x2 is
//!   not assigned). That registry is [`super::types::ObjectStatus`], next to
//!   the data-stream code that reads it.
//!
//! ANNOUNCE_CANCEL carries an Error Code field with no table of its own, and
//! Section 7.11 says why: "ANNOUNCE_CANCEL uses the same error codes as
//! ANNOUNCE_ERROR". So its codes are [`AnnounceErrorCode`], and there is no
//! separate registry to transcribe.
//!
//! # Unrecognised codes
//!
//! All six registries here are open: the draft says only that an application
//! "SHOULD use a relevant error code", so a peer may send a code this draft
//! does not define. `from_u64` returns `None` for an unrecognised value rather
//! than failing or widening the enum.
//!
//! # These are six separate number spaces
//!
//! The registries are deliberately six distinct types because the same number
//! means different things in each, and the differences are not intuitive:
//!
//! - The termination registry is offset by one against the other five.
//!   `Internal Error` is 0x1 in Section 3.5 but 0x0 in all five message-scoped
//!   registries, and `Unauthorized` is 0x2 in Section 3.5 but 0x1 in all five.
//!   Reusing a session code as a message code therefore shifts its meaning by a
//!   whole row rather than producing an obviously wrong value.
//! - 0x2 is `Timeout` in ANNOUNCE_ERROR, SUBSCRIBE_ERROR, FETCH_ERROR and
//!   SUBSCRIBE_ANNOUNCES_ERROR, but `Track Ended` in SUBSCRIBE_DONE and
//!   `Unauthorized` in the termination registry.
//! - 0x4 carries five distinct meanings across the six registries:
//!   `Duplicate Track Alias`, `Uninterested`, `Track Does Not Exist` (in both
//!   SUBSCRIBE_ERROR and FETCH_ERROR), `Going Away` and
//!   `Namespace Prefix Unknown`.
//!
//! `Unauthorized` also differs in meaning as well as in number: in
//! [`SessionErrorCode`] it reports a breached agreement, which the
//! message-scoped registries do not say.

/// Session termination codes, from draft-09 Section 3.5 (Termination).
///
/// The draft introduces the table with "The application MAY use any error
/// message and SHOULD use a relevant code, as defined below". These codes
/// travel in the QUIC `CONNECTION_CLOSE` frame or the WebTransport
/// `CLOSE_WEBTRANSPORT_SESSION` capsule.
///
/// Section 3.5 assigns 0x0 through 0x6 and then jumps to 0x10 through 0x12 for
/// the three timeouts; 0x7 through 0xF are unassigned. The gap is the draft's
/// own, so `GOAWAY Timeout` is 0x10 and not 0x7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `No Error` — The session is being terminated without an error.
    NoError = 0x0,
    /// `Internal Error` — An implementation specific error occurred.
    InternalError = 0x1,
    /// `Unauthorized` — The endpoint breached an agreement, which MAY have been
    /// pre-negotiated by the application.
    Unauthorized = 0x2,
    /// `Protocol Violation` — The remote endpoint performed an action that was
    /// disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `Duplicate Track Alias` — The endpoint attempted to use a Track Alias
    /// that was already in use.
    DuplicateTrackAlias = 0x4,
    /// `Parameter Length Mismatch` — the Section 3.5 table assigns this code but
    /// the list of descriptions that follows the table skips it. Section 7.1
    /// supplies the meaning: if a receiver understands a parameter type, and the
    /// parameter length implied by that type does not match the Parameter Length
    /// field, the receiver MUST terminate the session with this code.
    ParameterLengthMismatch = 0x5,
    /// `Too Many Subscribes` — The session was closed because the subscriber
    /// used a Subscribe ID equal or larger than the current Maximum Subscribe
    /// ID.
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
    /// stream. If an endpoint times out waiting for a new object header on an
    /// open subgroup stream, it MAY send a STOP_SENDING on that stream,
    /// terminate the subscription, or close the session with an error.
    DataStreamTimeout = 0x12,
}

/// ANNOUNCE_ERROR codes, from draft-09 Section 7.10 (ANNOUNCE_ERROR).
///
/// The draft introduces the table with "The application SHOULD use a relevant
/// error code in ANNOUNCE_ERROR, as defined below" and gives no prose beyond the
/// `Reason` column for any of these codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AnnounceErrorCode {
    /// `Internal Error`.
    InternalError = 0x0,
    /// `Unauthorized`.
    Unauthorized = 0x1,
    /// `Timeout`.
    Timeout = 0x2,
    /// `Not Supported`.
    NotSupported = 0x3,
    /// `Uninterested`.
    Uninterested = 0x4,
}

/// SUBSCRIBE_ERROR codes, from draft-09 Section 7.16 (SUBSCRIBE_ERROR).
///
/// The draft introduces the table with "The application SHOULD use a relevant
/// error code in SUBSCRIBE_ERROR, as defined below".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeErrorCode {
    /// `Internal Error`.
    InternalError = 0x0,
    /// `Unauthorized`.
    Unauthorized = 0x1,
    /// `Timeout`.
    Timeout = 0x2,
    /// `Not Supported`.
    NotSupported = 0x3,
    /// `Track Does Not Exist`.
    TrackDoesNotExist = 0x4,
    /// `Invalid Range` — Section 7.4 adds that if a publisher cannot satisfy
    /// the requested start or end, or if the end has already been published, it
    /// SHOULD send a SUBSCRIBE_ERROR with this code.
    InvalidRange = 0x5,
    /// `Retry Track Alias` — Section 7.16 adds that the subscriber SHOULD
    /// re-issue the SUBSCRIBE with the Track Alias carried in the
    /// SUBSCRIBE_ERROR message instead. If that Track Alias is already in use,
    /// the subscriber MUST close the connection with a Duplicate Track Alias
    /// error (Section 3.5).
    RetryTrackAlias = 0x6,
}

/// FETCH_ERROR codes, from draft-09 Section 7.18 (FETCH_ERROR).
///
/// The draft introduces the table with "The application SHOULD use a relevant
/// error code in FETCH_ERROR, as defined below" and gives no prose beyond the
/// `Reason` column for any of these codes. The table stops at `Invalid Range`:
/// unlike SUBSCRIBE_ERROR, FETCH_ERROR has no `Retry Track Alias` code in this
/// draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchErrorCode {
    /// `Internal Error`.
    InternalError = 0x0,
    /// `Unauthorized`.
    Unauthorized = 0x1,
    /// `Timeout`.
    Timeout = 0x2,
    /// `Not Supported`.
    NotSupported = 0x3,
    /// `Track Does Not Exist`.
    TrackDoesNotExist = 0x4,
    /// `Invalid Range`.
    InvalidRange = 0x5,
}

/// SUBSCRIBE_DONE status codes, from draft-09 Section 7.19 (SUBSCRIBE_DONE).
///
/// The draft introduces the table with "The application SHOULD use a relevant
/// status code in SUBSCRIBE_DONE, as defined below"; the table's second column
/// is still headed `Reason`. The Status Code indicates why the subscription
/// ended, and whether it was an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeDoneStatusCode {
    /// `Internal Error`.
    InternalError = 0x0,
    /// `Unauthorized`.
    Unauthorized = 0x1,
    /// `Track Ended`.
    TrackEnded = 0x2,
    /// `Subscription Ended`.
    SubscriptionEnded = 0x3,
    /// `Going Away`.
    GoingAway = 0x4,
    /// `Expired`.
    Expired = 0x5,
    /// `Too Far Behind` — Section 7.1.1.2 adds that if a subscriber exceeds the
    /// publisher's resource limits by failing to consume objects at a sufficient
    /// rate, the publisher MAY terminate the subscription with this code.
    TooFarBehind = 0x6,
}

/// SUBSCRIBE_ANNOUNCES_ERROR codes, from draft-09 Section 7.26
/// (SUBSCRIBE_ANNOUNCES_ERROR).
///
/// The draft introduces the table with "The application SHOULD use a relevant
/// error code in SUBSCRIBE_ANNOUNCES_ERROR, as defined below" and gives no prose
/// beyond the `Reason` column for any of these codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeAnnouncesErrorCode {
    /// `Internal Error`.
    InternalError = 0x0,
    /// `Unauthorized`.
    Unauthorized = 0x1,
    /// `Timeout`.
    Timeout = 0x2,
    /// `Not Supported`.
    NotSupported = 0x3,
    /// `Namespace Prefix Unknown`.
    NamespacePrefixUnknown = 0x4,
}

impl SessionErrorCode {
    /// Every session termination code draft-09 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `SessionErrorCode`, if draft-09 defines it.
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
    /// Every ANNOUNCE_ERROR code draft-09 assigns, in ascending wire order.
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

    /// Convert a raw u64 to an `AnnounceErrorCode`, if draft-09 defines it.
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
    /// Every SUBSCRIBE_ERROR code draft-09 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `SubscribeErrorCode`, if draft-09 defines it.
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
    /// Every FETCH_ERROR code draft-09 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `FetchErrorCode`, if draft-09 defines it.
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
    /// Every SUBSCRIBE_DONE status code draft-09 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `SubscribeDoneStatusCode`, if draft-09 defines it.
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
    /// Every SUBSCRIBE_ANNOUNCES_ERROR code draft-09 assigns, in ascending wire order.
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

    /// Convert a raw u64 to a `SubscribeAnnouncesErrorCode`, if draft-09 defines
    /// it.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_error_code_roundtrip() {
        for code in [
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
        ] {
            assert_eq!(SessionErrorCode::from_u64(code.as_u64()), Some(code));
        }
    }

    #[test]
    fn unknown_codes_are_none() {
        // 0x7..=0xF are unassigned in draft-09's termination table, and the
        // table stops at 0x12. Assert over the whole gap rather than a sample.
        for code in 0x7..=0xF {
            assert_eq!(SessionErrorCode::from_u64(code), None, "0x{code:x}");
        }
        assert_eq!(SessionErrorCode::from_u64(0x13), None);
        assert_eq!(AnnounceErrorCode::from_u64(0x5), None);
        assert_eq!(SubscribeErrorCode::from_u64(0x7), None);
        assert_eq!(FetchErrorCode::from_u64(0x6), None);
        assert_eq!(SubscribeDoneStatusCode::from_u64(0x7), None);
        assert_eq!(SubscribeAnnouncesErrorCode::from_u64(0x5), None);
        assert_eq!(SessionErrorCode::from_u64(u64::MAX), None);
    }

    #[test]
    fn fetch_error_has_no_retry_track_alias() {
        // draft-09 gives SUBSCRIBE_ERROR 0x6 but stops FETCH_ERROR at 0x5.
        assert_eq!(SubscribeErrorCode::from_u64(0x6), Some(SubscribeErrorCode::RetryTrackAlias));
        assert_eq!(FetchErrorCode::from_u64(0x6), None);
    }
}

/// TRACK_STATUS Status Code values (draft-09, Section 7.24).
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

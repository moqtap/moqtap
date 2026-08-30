//! Error, status and termination code registries defined by MoQ Transport draft-07.
//!
//! Draft-07 predates the IANA registries introduced in draft-14. Its code points
//! live in inline two-column tables headed `Code | Reason`, and the draft assigns
//! no ALLCAPS symbolic names — the Reason cell is the only label a code has.
//! Variant names below are derived mechanically from that Reason text, and every
//! variant doc quotes the Reason text in backticks so the mapping from draft row
//! to Rust variant stays checkable by eye.
//!
//! Where the draft says more about a code than the Reason cell, the variant doc
//! carries that text and names the section it came from. How much exists differs
//! sharply by table: section 3.5 continues past its table with a list defining
//! seven of its eight codes, sections 6.1, 6.4, 6.16 and 6.20 state the rule for
//! four more, and the SUBSCRIBE_DONE table has no supporting prose anywhere —
//! each of its Reason strings occurs exactly once in the whole document, in the
//! table itself.
//!
//! `from_u64` returns `None` for any value the draft does not assign. A peer may
//! legitimately send a code from a later draft or a private extension, and an
//! unrecognized code must not be a decode failure at this layer.
//!
//! Draft-07 defines no reserved-for-greasing ranges; every row in all three tables
//! is a single assigned code point.

/// Session termination codes, from draft-07 section 3.5 "Termination" (Table 1).
///
/// The draft introduces the table with: "The application MAY use any error message
/// and SHOULD use a relevant code, as defined below". These are the codes carried
/// in the QUIC CONNECTION_CLOSE frame or the WebTransport
/// CLOSE_WEBTRANSPORT_SESSION capsule.
///
/// Section 3.5 continues past the table with a list defining the codes. That list
/// has seven entries for eight rows: it skips `Parameter Length Mismatch`, whose
/// rule appears in section 6.1 instead. Each variant below gives the Reason text
/// followed by that definition.
///
/// The jump from 0x6 to 0x10 is the draft's own; 0x7 through 0xF are unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// `No Error` — the session is being terminated without an error.
    NoError = 0x0,
    /// `Internal Error` — an implementation specific error occurred.
    InternalError = 0x1,
    /// `Unauthorized` — the endpoint breached an agreement, which may have been
    /// pre-negotiated by the application.
    Unauthorized = 0x2,
    /// `Protocol Violation` — the remote endpoint performed an action that was
    /// disallowed by the specification.
    ProtocolViolation = 0x3,
    /// `Duplicate Track Alias` — the endpoint attempted to use a Track Alias that
    /// was already in use.
    DuplicateTrackAlias = 0x4,
    /// `Parameter Length Mismatch` — the one code section 3.5 lists in its table
    /// but omits from the definitions that follow it. Section 6.1 supplies the
    /// rule: if a receiver understands a parameter type and the parameter length
    /// implied by that type does not match the Parameter Length field, the
    /// receiver must terminate the session with this code.
    ParameterLengthMismatch = 0x5,
    /// `Too Many Subscribes` — the session was closed because the subscriber used
    /// a Subscribe ID equal or larger than the current Maximum Subscribe ID.
    /// Section 6.20 states the same rule from the publisher's side, for any
    /// message carrying such a Subscribe ID rather than SUBSCRIBE alone.
    TooManySubscribes = 0x6,
    /// `GOAWAY Timeout` — the session was closed because the client took too long
    /// to close the session in response to a GOAWAY message (section 6.3). See
    /// session migration, section 3.6.
    GoawayTimeout = 0x10,
}

/// SUBSCRIBE_ERROR codes, from draft-07 section 5.1 "Subscriber Interactions" (Table 2).
///
/// The draft introduces the table with: "The application SHOULD use a relevant
/// error code in SUBSCRIBE_ERROR, as defined below". Draft-07 places this table
/// under a narrative section rather than under the SUBSCRIBE_ERROR message
/// definition in section 6.16.
///
/// No list of definitions follows this table. Two of the six codes have a stated
/// rule elsewhere in the draft and carry it below; for the other four the Reason
/// text is all there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeErrorCode {
    /// `Internal Error`
    InternalError = 0x0,
    /// `Invalid Range` — section 6.4 requires this code when the requested range
    /// cannot be served: for the AbsoluteStart and AbsoluteRange filters when
    /// StartGroup is prior to the current group, and when the publisher cannot
    /// satisfy the requested start or end, or the end has already been published.
    InvalidRange = 0x1,
    /// `Retry Track Alias` — section 6.16: the SUBSCRIBE_ERROR carries a Track
    /// Alias field, and the subscriber should re-issue the SUBSCRIBE with that
    /// alias instead. If that alias is itself already in use, the subscriber must
    /// close the session with `Duplicate Track Alias`
    /// ([`SessionErrorCode::DuplicateTrackAlias`]).
    RetryTrackAlias = 0x2,
    /// `Track Does Not Exist`
    TrackDoesNotExist = 0x3,
    /// `Unauthorized`
    Unauthorized = 0x4,
    /// `Timeout`
    Timeout = 0x5,
}

/// SUBSCRIBE_DONE status codes, from draft-07 section 5.1 "Subscriber Interactions" (Table 3).
///
/// The draft introduces the table with: "The application SHOULD use a relevant
/// status code in SUBSCRIBE_DONE, as defined below". These codes report why a
/// publisher ended a subscription; they are not all failures. Section 6.19
/// describes the field only as "an integer status code indicating why the
/// subscription ended".
///
/// The Reason text is the whole of what draft-07 says about these seven codes:
/// each of the strings below occurs exactly once in the document, in the table.
/// Reason-only docs here are the complete record, not a truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SubscribeDoneStatusCode {
    /// `Unsubscribed`
    Unsubscribed = 0x0,
    /// `Internal Error`
    InternalError = 0x1,
    /// `Unauthorized`
    Unauthorized = 0x2,
    /// `Track Ended`
    TrackEnded = 0x3,
    /// `Subscription Ended`
    SubscriptionEnded = 0x4,
    /// `Going Away`
    GoingAway = 0x5,
    /// `Expired`
    Expired = 0x6,
}

impl SessionErrorCode {
    /// Every session termination code draft-07 assigns, in ascending wire order.
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
    ];

    /// Convert a raw u64 to a `SessionErrorCode`, if draft-07 defines it.
    ///
    /// Returns `None` for any code the draft does not assign; peers are free to
    /// send codes from later drafts or from private extensions.
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
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeErrorCode {
    /// Every SUBSCRIBE_ERROR code draft-07 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SubscribeErrorCode] = &[
        SubscribeErrorCode::InternalError,
        SubscribeErrorCode::InvalidRange,
        SubscribeErrorCode::RetryTrackAlias,
        SubscribeErrorCode::TrackDoesNotExist,
        SubscribeErrorCode::Unauthorized,
        SubscribeErrorCode::Timeout,
    ];

    /// Convert a raw u64 to a `SubscribeErrorCode`, if draft-07 defines it.
    ///
    /// Returns `None` for any code the draft does not assign; peers are free to
    /// send codes from later drafts or from private extensions.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeErrorCode::InternalError),
            0x1 => Some(SubscribeErrorCode::InvalidRange),
            0x2 => Some(SubscribeErrorCode::RetryTrackAlias),
            0x3 => Some(SubscribeErrorCode::TrackDoesNotExist),
            0x4 => Some(SubscribeErrorCode::Unauthorized),
            0x5 => Some(SubscribeErrorCode::Timeout),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl SubscribeDoneStatusCode {
    /// Every SUBSCRIBE_DONE status code draft-07 assigns, in ascending wire order.
    ///
    /// This is the set [`Self::from_u64`] accepts, written out so that it can
    /// be enumerated: nothing can iterate an enum's variants, so a caller that
    /// wants the registry has to be handed it. Writing it down is also what
    /// lets a test state its claims about the registry itself rather than about
    /// the range some sweep happens to reach.
    pub const ALL: &[SubscribeDoneStatusCode] = &[
        SubscribeDoneStatusCode::Unsubscribed,
        SubscribeDoneStatusCode::InternalError,
        SubscribeDoneStatusCode::Unauthorized,
        SubscribeDoneStatusCode::TrackEnded,
        SubscribeDoneStatusCode::SubscriptionEnded,
        SubscribeDoneStatusCode::GoingAway,
        SubscribeDoneStatusCode::Expired,
    ];

    /// Convert a raw u64 to a `SubscribeDoneStatusCode`, if draft-07 defines it.
    ///
    /// Returns `None` for any code the draft does not assign; peers are free to
    /// send codes from later drafts or from private extensions.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SubscribeDoneStatusCode::Unsubscribed),
            0x1 => Some(SubscribeDoneStatusCode::InternalError),
            0x2 => Some(SubscribeDoneStatusCode::Unauthorized),
            0x3 => Some(SubscribeDoneStatusCode::TrackEnded),
            0x4 => Some(SubscribeDoneStatusCode::SubscriptionEnded),
            0x5 => Some(SubscribeDoneStatusCode::GoingAway),
            0x6 => Some(SubscribeDoneStatusCode::Expired),
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// TRACK_STATUS Status Code values (draft-07, Section 6.23).
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
    /// Section 6.23 says of 0x01 "Subsequent fields MUST be zero, and any other
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

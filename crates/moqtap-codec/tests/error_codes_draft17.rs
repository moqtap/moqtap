#![cfg(feature = "draft17")]
//! Round-trip and rejection tests for the draft-17 code registries.
//!
//! The four tables transcribed in `draft17::error_codes` are, in the draft:
//! Table 13 (Section 14.5.1, Session Termination Error Codes, 21 assignments),
//! Table 14 (Section 14.5.2, REQUEST_ERROR Codes, 16), Table 15 (Section
//! 14.5.3, PUBLISH_DONE Codes, 10) and Table 16 (Section 14.5.4, Data Stream
//! Reset Error Codes, 8). Each table also carries a final row reserving
//! `0x7f * N + 0x9D` for greasing, which is not an assignment and gets no
//! variant.
//!
//! The arrays below restate each table's code points independently of the enum
//! definitions, so a discriminant edited in one place and not the other fails
//! here rather than shipping. A test that only called `from_u64(as_u64(v))`
//! would pass even if a variant carried the wrong code point, so every row is
//! also pinned against a literal.

use moqtap_codec::draft17::error_codes::{
    DataStreamResetErrorCode, PublishDoneStatusCode, RequestErrorCode, SessionErrorCode,
};

/// Table 13. Codes run 0x0..=0x9 and 0x10..=0x1A; 0xA..=0xF are unassigned.
const SESSION: [(SessionErrorCode, u64); 21] = [
    (SessionErrorCode::NoError, 0x0),
    (SessionErrorCode::InternalError, 0x1),
    (SessionErrorCode::Unauthorized, 0x2),
    (SessionErrorCode::ProtocolViolation, 0x3),
    (SessionErrorCode::InvalidRequestId, 0x4),
    (SessionErrorCode::DuplicateTrackAlias, 0x5),
    (SessionErrorCode::KeyValueFormattingError, 0x6),
    (SessionErrorCode::InvalidRequiredRequestId, 0x7),
    (SessionErrorCode::InvalidPath, 0x8),
    (SessionErrorCode::MalformedPath, 0x9),
    (SessionErrorCode::GoawayTimeout, 0x10),
    (SessionErrorCode::ControlMessageTimeout, 0x11),
    (SessionErrorCode::DataStreamTimeout, 0x12),
    (SessionErrorCode::AuthTokenCacheOverflow, 0x13),
    (SessionErrorCode::DuplicateAuthTokenAlias, 0x14),
    (SessionErrorCode::VersionNegotiationFailed, 0x15),
    (SessionErrorCode::MalformedAuthToken, 0x16),
    (SessionErrorCode::UnknownAuthTokenAlias, 0x17),
    (SessionErrorCode::ExpiredAuthToken, 0x18),
    (SessionErrorCode::InvalidAuthority, 0x19),
    (SessionErrorCode::MalformedAuthority, 0x1A),
];

/// Table 14. The draft leaves 0x7 and 0x8 unassigned between `GOING_AWAY` and
/// `EXCESSIVE_LOAD`, and jumps again after 0x12.
const REQUEST: [(RequestErrorCode, u64); 16] = [
    (RequestErrorCode::InternalError, 0x0),
    (RequestErrorCode::Unauthorized, 0x1),
    (RequestErrorCode::Timeout, 0x2),
    (RequestErrorCode::NotSupported, 0x3),
    (RequestErrorCode::MalformedAuthToken, 0x4),
    (RequestErrorCode::ExpiredAuthToken, 0x5),
    (RequestErrorCode::GoingAway, 0x6),
    (RequestErrorCode::ExcessiveLoad, 0x9),
    (RequestErrorCode::DoesNotExist, 0x10),
    (RequestErrorCode::InvalidRange, 0x11),
    (RequestErrorCode::MalformedTrack, 0x12),
    (RequestErrorCode::DuplicateSubscription, 0x19),
    (RequestErrorCode::Uninterested, 0x20),
    (RequestErrorCode::PrefixOverlap, 0x30),
    (RequestErrorCode::NamespaceTooLarge, 0x31),
    (RequestErrorCode::InvalidJoiningRequestId, 0x32),
];

/// Table 15. 0x7 is unassigned; the table lists `MALFORMED_TRACK` at 0x12.
const PUBLISH_DONE: [(PublishDoneStatusCode, u64); 10] = [
    (PublishDoneStatusCode::InternalError, 0x0),
    (PublishDoneStatusCode::Unauthorized, 0x1),
    (PublishDoneStatusCode::TrackEnded, 0x2),
    (PublishDoneStatusCode::SubscriptionEnded, 0x3),
    (PublishDoneStatusCode::GoingAway, 0x4),
    (PublishDoneStatusCode::Expired, 0x5),
    (PublishDoneStatusCode::TooFarBehind, 0x6),
    (PublishDoneStatusCode::UpdateFailed, 0x8),
    (PublishDoneStatusCode::ExcessiveLoad, 0x9),
    (PublishDoneStatusCode::MalformedTrack, 0x12),
];

/// Table 16. 0x6, 0x7 and 0x8 are unassigned.
const STREAM_RESET: [(DataStreamResetErrorCode, u64); 8] = [
    (DataStreamResetErrorCode::InternalError, 0x0),
    (DataStreamResetErrorCode::Cancelled, 0x1),
    (DataStreamResetErrorCode::DeliveryTimeout, 0x2),
    (DataStreamResetErrorCode::SessionClosed, 0x3),
    (DataStreamResetErrorCode::UnknownObjectStatus, 0x4),
    (DataStreamResetErrorCode::TooFarBehind, 0x5),
    (DataStreamResetErrorCode::ExcessiveLoad, 0x9),
    (DataStreamResetErrorCode::MalformedTrack, 0x12),
];

/// Values reserved for greasing under either reading of Section 13: 0x9D is the
/// first greasing value, 0x11C follows it under the stated formula
/// `0x7f * N + 0x9D`, 0xBC follows it under the sequence the same section
/// prints, and 0x3ffffffffffffffe is the last value that section names. None of
/// them is assigned by any of the four tables.
const GREASE: [u64; 4] = [0x9D, 0xBC, 0x11C, 0x3ffffffffffffffe];

macro_rules! round_trip_test {
    ($name:ident, $ty:ty, $rows:expr) => {
        #[test]
        fn $name() {
            for (variant, code) in $rows {
                assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
                assert_eq!(
                    <$ty>::from_u64(variant.as_u64()),
                    Some(variant),
                    "from_u64(as_u64()) for {variant:?}"
                );
                assert_eq!(<$ty>::from_u64(code), Some(variant), "from_u64(0x{code:x})");
            }
        }
    };
}

round_trip_test!(session_error_code_round_trips, SessionErrorCode, SESSION);
round_trip_test!(request_error_code_round_trips, RequestErrorCode, REQUEST);
round_trip_test!(publish_done_status_code_round_trips, PublishDoneStatusCode, PUBLISH_DONE);
round_trip_test!(data_stream_reset_error_code_round_trips, DataStreamResetErrorCode, STREAM_RESET);

/// Sweeps every value a single-byte varint can carry plus the greasing values,
/// and requires `from_u64` to answer `Some` for exactly the pinned rows. A
/// stricter check than listing gaps by hand: an extra `match` arm anywhere in
/// the low code space fails here.
macro_rules! exhaustive_test {
    ($name:ident, $ty:ty, $rows:expr, $table:literal) => {
        #[test]
        fn $name() {
            for probe in (0..=0x3Fu64).chain(GREASE) {
                let expected = $rows.iter().find(|(_, c)| *c == probe).map(|(v, _)| *v);
                assert_eq!(
                    <$ty>::from_u64(probe),
                    expected,
                    "from_u64(0x{probe:x}) disagrees with draft-17 {}",
                    $table
                );
            }
        }
    };
}

exhaustive_test!(session_error_code_accepts_only_assigned, SessionErrorCode, SESSION, "Table 13");
exhaustive_test!(request_error_code_accepts_only_assigned, RequestErrorCode, REQUEST, "Table 14");
exhaustive_test!(
    publish_done_status_code_accepts_only_assigned,
    PublishDoneStatusCode,
    PUBLISH_DONE,
    "Table 15"
);
exhaustive_test!(
    data_stream_reset_error_code_accepts_only_assigned,
    DataStreamResetErrorCode,
    STREAM_RESET,
    "Table 16"
);

/// The specific gaps the draft's own tables leave, named so a regression report
/// points at the row rather than at a sweep.
#[test]
fn named_gaps_are_rejected() {
    for code in [0xA, 0xB, 0xC, 0xD, 0xE, 0xF] {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "0x{code:x} sits in the 0xA..=0xF gap of draft-17 Table 13"
        );
    }
    for code in [0x7, 0x8] {
        assert_eq!(
            RequestErrorCode::from_u64(code),
            None,
            "0x{code:x} is unassigned between GOING_AWAY and EXCESSIVE_LOAD in Table 14"
        );
    }
    assert_eq!(
        PublishDoneStatusCode::from_u64(0x7),
        None,
        "0x7 is unassigned in draft-17 Table 15"
    );
    for code in [0x6, 0x7, 0x8] {
        assert_eq!(
            DataStreamResetErrorCode::from_u64(code),
            None,
            "0x{code:x} is unassigned in draft-17 Table 16"
        );
    }
}

/// Nothing beyond the largest assigned code in each table is accepted, and the
/// varint maximum is rejected rather than wrapping onto a variant.
#[test]
fn out_of_range_codes_are_rejected() {
    for code in [0x1B, 0x20, 0x40, 0xFF, u64::MAX] {
        assert_eq!(SessionErrorCode::from_u64(code), None, "Table 13 0x{code:x}");
    }
    for code in [0x33, 0x40, 0xFF, u64::MAX] {
        assert_eq!(RequestErrorCode::from_u64(code), None, "Table 14 0x{code:x}");
    }
    for code in [0x13, 0x40, 0xFF, u64::MAX] {
        assert_eq!(PublishDoneStatusCode::from_u64(code), None, "Table 15 0x{code:x}");
    }
    for code in [0x13, 0x40, 0xFF, u64::MAX] {
        assert_eq!(DataStreamResetErrorCode::from_u64(code), None, "Table 16 0x{code:x}");
    }
}

/// Greasing rows are reservations, not assignments. Section 13 requires unknown
/// values from these registries to be handled gracefully, which at this layer
/// means decoding to `None` rather than to a variant.
#[test]
fn greasing_values_are_not_assignments() {
    for code in GREASE {
        assert_eq!(SessionErrorCode::from_u64(code), None, "0x{code:x}");
        assert_eq!(RequestErrorCode::from_u64(code), None, "0x{code:x}");
        assert_eq!(PublishDoneStatusCode::from_u64(code), None, "0x{code:x}");
        assert_eq!(DataStreamResetErrorCode::from_u64(code), None, "0x{code:x}");
    }
}

/// The four registries are separate number spaces. Every value from 0x0 to 0x5
/// is assigned in all four with a different meaning, which is the case most
/// likely to be collapsed by a future refactor into one shared enum.
#[test]
fn registries_are_distinct_number_spaces() {
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(RequestErrorCode::from_u64(0x2), Some(RequestErrorCode::Timeout));
    assert_eq!(PublishDoneStatusCode::from_u64(0x2), Some(PublishDoneStatusCode::TrackEnded));
    assert_eq!(
        DataStreamResetErrorCode::from_u64(0x2),
        Some(DataStreamResetErrorCode::DeliveryTimeout)
    );

    // 0x12 is the other high-traffic collision: a session-level timeout in one
    // registry, a malformed track in the other three.
    assert_eq!(SessionErrorCode::from_u64(0x12), Some(SessionErrorCode::DataStreamTimeout));
    assert_eq!(RequestErrorCode::from_u64(0x12), Some(RequestErrorCode::MalformedTrack));
    assert_eq!(PublishDoneStatusCode::from_u64(0x12), Some(PublishDoneStatusCode::MalformedTrack));
    assert_eq!(
        DataStreamResetErrorCode::from_u64(0x12),
        Some(DataStreamResetErrorCode::MalformedTrack)
    );

    // 0x19 is assigned in two registries only.
    assert_eq!(SessionErrorCode::from_u64(0x19), Some(SessionErrorCode::InvalidAuthority));
    assert_eq!(RequestErrorCode::from_u64(0x19), Some(RequestErrorCode::DuplicateSubscription));
    assert_eq!(PublishDoneStatusCode::from_u64(0x19), None);
    assert_eq!(DataStreamResetErrorCode::from_u64(0x19), None);
}

/// Two registries assign `MALFORMED_AUTH_TOKEN` and `EXPIRED_AUTH_TOKEN` under
/// different numbers. Copying either pair between the enums would compile.
#[test]
fn auth_token_codes_differ_between_registries() {
    assert_eq!(SessionErrorCode::MalformedAuthToken.as_u64(), 0x16);
    assert_eq!(SessionErrorCode::ExpiredAuthToken.as_u64(), 0x18);
    assert_eq!(RequestErrorCode::MalformedAuthToken.as_u64(), 0x4);
    assert_eq!(RequestErrorCode::ExpiredAuthToken.as_u64(), 0x5);
}

/// Row counts as transcribed, checked against the draft's tables. The greasing
/// row of each table is a reservation and is not counted as an assignment.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 21, "Section 14.5.1 Table 13");
    assert_eq!(REQUEST.len(), 16, "Section 14.5.2 Table 14");
    assert_eq!(PUBLISH_DONE.len(), 10, "Section 14.5.3 Table 15");
    assert_eq!(STREAM_RESET.len(), 8, "Section 14.5.4 Table 16");
    assert_eq!(SESSION.len() + REQUEST.len() + PUBLISH_DONE.len() + STREAM_RESET.len(), 55);
}

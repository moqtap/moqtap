#![cfg(feature = "draft16")]

//! Round-trip and rejection tests for the draft-16 code registries.
//!
//! Draft-16 collects every error and status registry under Section 13.4: Session
//! Termination Error Codes (13.4.1, 21 rows, defined in Section 3.4), REQUEST_ERROR
//! Codes (13.4.2, 13 rows, defined in Section 9.8), PUBLISH_DONE Codes (13.4.3, 9
//! rows, defined in Section 9.15) and Data Stream Reset Error Codes (13.4.4, 6 rows,
//! defined in Section 10.4.3).
//!
//! The arrays below restate each table's code points independently of the enum
//! definitions, so a discriminant edited in one place and not the other fails here
//! rather than shipping. Every registry is sparse, and the gaps carry meaning: a
//! value the draft leaves unassigned must decode to `None` rather than be folded
//! onto a neighbouring variant.

use moqtap_codec::draft16::error_codes::{
    DataStreamResetErrorCode, PublishDoneStatusCode, RequestErrorCode, SessionErrorCode,
};

/// Section 13.4.1, Table 10. Assigns 0x0..=0x9 and 0x10..=0x1A.
const SESSION: [(SessionErrorCode, u64); 21] = [
    (SessionErrorCode::NoError, 0x0),
    (SessionErrorCode::InternalError, 0x1),
    (SessionErrorCode::Unauthorized, 0x2),
    (SessionErrorCode::ProtocolViolation, 0x3),
    (SessionErrorCode::InvalidRequestId, 0x4),
    (SessionErrorCode::DuplicateTrackAlias, 0x5),
    (SessionErrorCode::KeyValueFormattingError, 0x6),
    (SessionErrorCode::TooManyRequests, 0x7),
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

/// Section 13.4.2, Table 11. Assigns 0x0..=0x5, 0x10..=0x12, 0x19, 0x20, 0x30, 0x32.
const REQUEST: [(RequestErrorCode, u64); 13] = [
    (RequestErrorCode::InternalError, 0x0),
    (RequestErrorCode::Unauthorized, 0x1),
    (RequestErrorCode::Timeout, 0x2),
    (RequestErrorCode::NotSupported, 0x3),
    (RequestErrorCode::MalformedAuthToken, 0x4),
    (RequestErrorCode::ExpiredAuthToken, 0x5),
    (RequestErrorCode::DoesNotExist, 0x10),
    (RequestErrorCode::InvalidRange, 0x11),
    (RequestErrorCode::MalformedTrack, 0x12),
    (RequestErrorCode::DuplicateSubscription, 0x19),
    (RequestErrorCode::Uninterested, 0x20),
    (RequestErrorCode::PrefixOverlap, 0x30),
    (RequestErrorCode::InvalidJoiningRequestId, 0x32),
];

/// Section 13.4.3, Table 12. Assigns 0x0..=0x6, 0x8 and 0x12.
const PUBLISH_DONE: [(PublishDoneStatusCode, u64); 9] = [
    (PublishDoneStatusCode::InternalError, 0x0),
    (PublishDoneStatusCode::Unauthorized, 0x1),
    (PublishDoneStatusCode::TrackEnded, 0x2),
    (PublishDoneStatusCode::SubscriptionEnded, 0x3),
    (PublishDoneStatusCode::GoingAway, 0x4),
    (PublishDoneStatusCode::Expired, 0x5),
    (PublishDoneStatusCode::TooFarBehind, 0x6),
    (PublishDoneStatusCode::UpdateFailed, 0x8),
    (PublishDoneStatusCode::MalformedTrack, 0x12),
];

/// Section 13.4.4, Table 13. Assigns 0x0..=0x4 and 0x12.
const STREAM_RESET: [(DataStreamResetErrorCode, u64); 6] = [
    (DataStreamResetErrorCode::InternalError, 0x0),
    (DataStreamResetErrorCode::Cancelled, 0x1),
    (DataStreamResetErrorCode::DeliveryTimeout, 0x2),
    (DataStreamResetErrorCode::SessionClosed, 0x3),
    (DataStreamResetErrorCode::UnknownObjectStatus, 0x4),
    (DataStreamResetErrorCode::MalformedTrack, 0x12),
];

/// Generate the round-trip and rejection tests for one registry.
///
/// The round trip is checked in both directions: `as_u64` must produce the code the
/// draft assigns, `from_u64(as_u64(v))` must return the same variant, and decoding
/// the literal code from the table must select that variant.
macro_rules! registry_tests {
    ($round:ident, $reject:ident, $ty:ty, $table:ident, $unassigned:expr, $where:literal) => {
        #[test]
        fn $round() {
            for (variant, code) in $table {
                assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
                assert_eq!(
                    <$ty>::from_u64(variant.as_u64()),
                    Some(variant),
                    "from_u64(as_u64()) for {variant:?}"
                );
                assert_eq!(<$ty>::from_u64(code), Some(variant), "from_u64(0x{code:x})");
            }
        }

        #[test]
        fn $reject() {
            let assigned: Vec<u64> = $table.iter().map(|(_, c)| *c).collect();
            for code in $unassigned {
                assert!(
                    !assigned.contains(&code),
                    "0x{code:x} is listed as both assigned and unassigned"
                );
                assert_eq!(
                    <$ty>::from_u64(code),
                    None,
                    "0x{code:x} is not assigned by draft-16 {}",
                    $where
                );
            }
        }
    };
}

registry_tests!(
    session_error_code_round_trips,
    session_error_code_rejects_unassigned,
    SessionErrorCode,
    SESSION,
    [0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1B, 0x1F, 0x20, 0xFF, u64::MAX],
    "Section 13.4.1"
);

registry_tests!(
    request_error_code_round_trips,
    request_error_code_rejects_unassigned,
    RequestErrorCode,
    REQUEST,
    [0x6, 0x7, 0x8, 0x9, 0xF, 0x13, 0x18, 0x1A, 0x1F, 0x21, 0x2F, 0x31, 0x33, 0xFF, u64::MAX],
    "Section 13.4.2"
);

registry_tests!(
    publish_done_status_code_round_trips,
    publish_done_status_code_rejects_unassigned,
    PublishDoneStatusCode,
    PUBLISH_DONE,
    [0x7, 0x9, 0xA, 0xF, 0x10, 0x11, 0x13, 0x20, 0xFF, u64::MAX],
    "Section 13.4.3"
);

registry_tests!(
    data_stream_reset_error_code_round_trips,
    data_stream_reset_error_code_rejects_unassigned,
    DataStreamResetErrorCode,
    STREAM_RESET,
    [0x5, 0x6, 0x7, 0x8, 0xF, 0x10, 0x11, 0x13, 0x20, 0xFF, u64::MAX],
    "Section 13.4.4"
);

/// PUBLISH_DONE skips 0x7, which draft-15 had assigned to MALFORMED_TRACK before
/// draft-16 moved that code to 0x12. Decoding 0x7 as anything would silently accept a
/// draft-15 peer's status code under a draft-16 meaning, so it is called out on its
/// own rather than left inside the bulk rejection list.
#[test]
fn publish_done_leaves_0x7_unassigned() {
    assert_eq!(PublishDoneStatusCode::from_u64(0x7), None);
    assert_eq!(PublishDoneStatusCode::from_u64(0x12), Some(PublishDoneStatusCode::MalformedTrack));
}

/// The four registries are separate number spaces. These codes carry a different
/// meaning in each, which is the case most likely to be broken by a future refactor
/// that collapses them into one shared enum.
#[test]
fn registries_are_distinct_number_spaces() {
    assert_eq!(SessionErrorCode::from_u64(0x4), Some(SessionErrorCode::InvalidRequestId));
    assert_eq!(RequestErrorCode::from_u64(0x4), Some(RequestErrorCode::MalformedAuthToken));
    assert_eq!(PublishDoneStatusCode::from_u64(0x4), Some(PublishDoneStatusCode::GoingAway));
    assert_eq!(
        DataStreamResetErrorCode::from_u64(0x4),
        Some(DataStreamResetErrorCode::UnknownObjectStatus)
    );

    // 0x12 is DATA_STREAM_TIMEOUT on the session but MALFORMED_TRACK in the other three.
    assert_eq!(SessionErrorCode::from_u64(0x12), Some(SessionErrorCode::DataStreamTimeout));
    assert_eq!(RequestErrorCode::from_u64(0x12), Some(RequestErrorCode::MalformedTrack));

    // 0x1 and 0x2 differ between the session registry and the request registry.
    assert_eq!(SessionErrorCode::from_u64(0x1), Some(SessionErrorCode::InternalError));
    assert_eq!(RequestErrorCode::from_u64(0x1), Some(RequestErrorCode::Unauthorized));
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(RequestErrorCode::from_u64(0x2), Some(RequestErrorCode::Timeout));
}

/// Row counts as transcribed, checked against the draft's tables.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 21, "Section 13.4.1 Table 10");
    assert_eq!(REQUEST.len(), 13, "Section 13.4.2 Table 11");
    assert_eq!(PUBLISH_DONE.len(), 9, "Section 13.4.3 Table 12");
    assert_eq!(STREAM_RESET.len(), 6, "Section 13.4.4 Table 13");
    assert_eq!(SESSION.len() + REQUEST.len() + PUBLISH_DONE.len() + STREAM_RESET.len(), 49);
}

/// Each registry's codes must be unique and listed in the draft's own order, which is
/// ascending by code point in all four tables.
#[test]
fn tables_are_ascending_and_free_of_duplicates() {
    fn check(codes: &[u64], label: &str) {
        for pair in codes.windows(2) {
            assert!(pair[0] < pair[1], "{label}: 0x{:x} does not precede 0x{:x}", pair[0], pair[1]);
        }
    }
    check(&SESSION.iter().map(|(_, c)| *c).collect::<Vec<_>>(), "Session Termination Error Codes");
    check(&REQUEST.iter().map(|(_, c)| *c).collect::<Vec<_>>(), "REQUEST_ERROR Codes");
    check(&PUBLISH_DONE.iter().map(|(_, c)| *c).collect::<Vec<_>>(), "PUBLISH_DONE Codes");
    check(
        &STREAM_RESET.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
        "Data Stream Reset Error Codes",
    );
}

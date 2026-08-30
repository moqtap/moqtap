#![cfg(feature = "draft09")]
//! Round-trip and rejection tests for the draft-09 code registries.
//!
//! The six tables transcribed in `draft09::error_codes` are, in the draft:
//! Table 1 (Section 3.5 Termination, 10 rows), Table 3 (Section 7.10
//! ANNOUNCE_ERROR, 5 rows), Table 4 (Section 7.16 SUBSCRIBE_ERROR, 7 rows),
//! Table 5 (Section 7.18 FETCH_ERROR, 6 rows), Table 6 (Section 7.19
//! SUBSCRIBE_DONE, 7 rows) and Table 7 (Section 7.26
//! SUBSCRIBE_ANNOUNCES_ERROR, 5 rows) — 40 code points in total.
//!
//! The arrays below restate each table's code points independently of the enum
//! definitions, so a discriminant edited in one place and not the other fails
//! here rather than shipping.
#![cfg(feature = "draft09")]

use moqtap_codec::draft09::error_codes::{
    AnnounceErrorCode, FetchErrorCode, SessionErrorCode, SubscribeAnnouncesErrorCode,
    SubscribeDoneStatusCode, SubscribeErrorCode,
};

/// Section 3.5, Table 1. Note the gap: 0x6 is followed by 0x10.
const SESSION: [(SessionErrorCode, u64); 10] = [
    (SessionErrorCode::NoError, 0x0),
    (SessionErrorCode::InternalError, 0x1),
    (SessionErrorCode::Unauthorized, 0x2),
    (SessionErrorCode::ProtocolViolation, 0x3),
    (SessionErrorCode::DuplicateTrackAlias, 0x4),
    (SessionErrorCode::ParameterLengthMismatch, 0x5),
    (SessionErrorCode::TooManySubscribes, 0x6),
    (SessionErrorCode::GoawayTimeout, 0x10),
    (SessionErrorCode::ControlMessageTimeout, 0x11),
    (SessionErrorCode::DataStreamTimeout, 0x12),
];

/// Section 7.10, Table 3.
const ANNOUNCE_ERROR: [(AnnounceErrorCode, u64); 5] = [
    (AnnounceErrorCode::InternalError, 0x0),
    (AnnounceErrorCode::Unauthorized, 0x1),
    (AnnounceErrorCode::Timeout, 0x2),
    (AnnounceErrorCode::NotSupported, 0x3),
    (AnnounceErrorCode::Uninterested, 0x4),
];

/// Section 7.16, Table 4.
const SUBSCRIBE_ERROR: [(SubscribeErrorCode, u64); 7] = [
    (SubscribeErrorCode::InternalError, 0x0),
    (SubscribeErrorCode::Unauthorized, 0x1),
    (SubscribeErrorCode::Timeout, 0x2),
    (SubscribeErrorCode::NotSupported, 0x3),
    (SubscribeErrorCode::TrackDoesNotExist, 0x4),
    (SubscribeErrorCode::InvalidRange, 0x5),
    (SubscribeErrorCode::RetryTrackAlias, 0x6),
];

/// Section 7.18, Table 5.
const FETCH_ERROR: [(FetchErrorCode, u64); 6] = [
    (FetchErrorCode::InternalError, 0x0),
    (FetchErrorCode::Unauthorized, 0x1),
    (FetchErrorCode::Timeout, 0x2),
    (FetchErrorCode::NotSupported, 0x3),
    (FetchErrorCode::TrackDoesNotExist, 0x4),
    (FetchErrorCode::InvalidRange, 0x5),
];

/// Section 7.19, Table 6.
const SUBSCRIBE_DONE: [(SubscribeDoneStatusCode, u64); 7] = [
    (SubscribeDoneStatusCode::InternalError, 0x0),
    (SubscribeDoneStatusCode::Unauthorized, 0x1),
    (SubscribeDoneStatusCode::TrackEnded, 0x2),
    (SubscribeDoneStatusCode::SubscriptionEnded, 0x3),
    (SubscribeDoneStatusCode::GoingAway, 0x4),
    (SubscribeDoneStatusCode::Expired, 0x5),
    (SubscribeDoneStatusCode::TooFarBehind, 0x6),
];

/// Section 7.26, Table 7.
const SUBSCRIBE_ANNOUNCES_ERROR: [(SubscribeAnnouncesErrorCode, u64); 5] = [
    (SubscribeAnnouncesErrorCode::InternalError, 0x0),
    (SubscribeAnnouncesErrorCode::Unauthorized, 0x1),
    (SubscribeAnnouncesErrorCode::Timeout, 0x2),
    (SubscribeAnnouncesErrorCode::NotSupported, 0x3),
    (SubscribeAnnouncesErrorCode::NamespacePrefixUnknown, 0x4),
];

/// Both directions for every row of every table: the discriminant is the code
/// the draft prints, and the code decodes back to the variant it came from.
macro_rules! round_trip {
    ($name:ident, $ty:ty, $rows:ident, $table:literal) => {
        #[test]
        fn $name() {
            for (variant, code) in $rows {
                assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?} ({})", $table);
                assert_eq!(
                    <$ty>::from_u64(variant.as_u64()),
                    Some(variant),
                    "from_u64(as_u64()) for {variant:?} ({})",
                    $table
                );
                assert_eq!(
                    <$ty>::from_u64(code),
                    Some(variant),
                    "from_u64(0x{code:x}) ({})",
                    $table
                );
            }
        }
    };
}

round_trip!(session_error_code_round_trips, SessionErrorCode, SESSION, "Section 3.5 Table 1");
round_trip!(
    announce_error_code_round_trips,
    AnnounceErrorCode,
    ANNOUNCE_ERROR,
    "Section 7.10 Table 3"
);
round_trip!(
    subscribe_error_code_round_trips,
    SubscribeErrorCode,
    SUBSCRIBE_ERROR,
    "Section 7.16 Table 4"
);
round_trip!(fetch_error_code_round_trips, FetchErrorCode, FETCH_ERROR, "Section 7.18 Table 5");
round_trip!(
    subscribe_done_status_code_round_trips,
    SubscribeDoneStatusCode,
    SUBSCRIBE_DONE,
    "Section 7.19 Table 6"
);
round_trip!(
    subscribe_announces_error_code_round_trips,
    SubscribeAnnouncesErrorCode,
    SUBSCRIBE_ANNOUNCES_ERROR,
    "Section 7.26 Table 7"
);

/// Section 3.5 assigns 0x0..=0x6 and 0x10..=0x12. Every value in the 0x7..=0xF
/// gap must be rejected rather than silently folded onto a neighbour, and the
/// three timeout codes must not be reachable at 0x7, 0x8 or 0x9.
#[test]
fn session_error_code_rejects_unassigned() {
    for code in [0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x13, 0x20, 0xFF, u64::MAX] {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-09 Section 3.5"
        );
    }
}

/// The five request-scoped tables each stop where the draft stops them.
#[test]
fn request_scoped_registries_reject_unassigned() {
    for code in [0x5, 0x6, 0x7, 0x10, 0xFF, u64::MAX] {
        assert_eq!(
            AnnounceErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-09 Table 3"
        );
        assert_eq!(
            SubscribeAnnouncesErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-09 Table 7"
        );
    }
    for code in [0x7, 0x8, 0x10, 0xFF, u64::MAX] {
        assert_eq!(
            SubscribeErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-09 Table 4"
        );
        assert_eq!(
            SubscribeDoneStatusCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-09 Table 6"
        );
    }
    for code in [0x6, 0x7, 0x10, 0xFF, u64::MAX] {
        assert_eq!(
            FetchErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-09 Table 5"
        );
    }
}

/// Table 4 assigns 0x6 to `Retry Track Alias`; Table 5 is otherwise identical
/// but stops at 0x5. Copying one registry from the other would produce a
/// FETCH_ERROR code the draft does not define.
#[test]
fn fetch_error_has_no_retry_track_alias() {
    assert_eq!(SubscribeErrorCode::from_u64(0x6), Some(SubscribeErrorCode::RetryTrackAlias));
    assert_eq!(FetchErrorCode::from_u64(0x6), None);
}

/// The six registries are separate number spaces. These are the collisions most
/// likely to be collapsed by a future refactor into one shared enum.
#[test]
fn registries_are_distinct_number_spaces() {
    // The termination registry is offset by one against the request-scoped
    // registries: `Internal Error` and `Unauthorized` sit one row lower there.
    assert_eq!(SessionErrorCode::from_u64(0x0), Some(SessionErrorCode::NoError));
    assert_eq!(AnnounceErrorCode::from_u64(0x0), Some(AnnounceErrorCode::InternalError));
    assert_eq!(SessionErrorCode::from_u64(0x1), Some(SessionErrorCode::InternalError));
    assert_eq!(AnnounceErrorCode::from_u64(0x1), Some(AnnounceErrorCode::Unauthorized));

    // 0x2 carries three meanings.
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(SubscribeErrorCode::from_u64(0x2), Some(SubscribeErrorCode::Timeout));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x2), Some(SubscribeDoneStatusCode::TrackEnded));

    // 0x4 carries five.
    assert_eq!(SessionErrorCode::from_u64(0x4), Some(SessionErrorCode::DuplicateTrackAlias));
    assert_eq!(AnnounceErrorCode::from_u64(0x4), Some(AnnounceErrorCode::Uninterested));
    assert_eq!(FetchErrorCode::from_u64(0x4), Some(FetchErrorCode::TrackDoesNotExist));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x4), Some(SubscribeDoneStatusCode::GoingAway));
    assert_eq!(
        SubscribeAnnouncesErrorCode::from_u64(0x4),
        Some(SubscribeAnnouncesErrorCode::NamespacePrefixUnknown)
    );
}

/// Row counts as transcribed, checked against the draft's tables.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 10, "Section 3.5 Table 1");
    assert_eq!(ANNOUNCE_ERROR.len(), 5, "Section 7.10 Table 3");
    assert_eq!(SUBSCRIBE_ERROR.len(), 7, "Section 7.16 Table 4");
    assert_eq!(FETCH_ERROR.len(), 6, "Section 7.18 Table 5");
    assert_eq!(SUBSCRIBE_DONE.len(), 7, "Section 7.19 Table 6");
    assert_eq!(SUBSCRIBE_ANNOUNCES_ERROR.len(), 5, "Section 7.26 Table 7");
    assert_eq!(
        SESSION.len()
            + ANNOUNCE_ERROR.len()
            + SUBSCRIBE_ERROR.len()
            + FETCH_ERROR.len()
            + SUBSCRIBE_DONE.len()
            + SUBSCRIBE_ANNOUNCES_ERROR.len(),
        40
    );
}

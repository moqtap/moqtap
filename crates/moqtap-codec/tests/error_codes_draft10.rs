#![cfg(feature = "draft10")]
//! Round-trip and rejection tests for the draft-10 code registries.
//!
//! Draft-10 defines six inline `Code | Reason` tables that assign code points:
//! Table 1 (Section 3.4 Termination, 10 rows), Table 3 (Section 8.8
//! SUBSCRIBE_ERROR, 7 rows), Table 4 (Section 8.11 SUBSCRIBE_DONE, 7 rows),
//! Table 5 (Section 8.14 FETCH_ERROR, 6 rows), Table 6 (Section 8.20
//! ANNOUNCE_ERROR, 5 rows) and Table 7 (Section 8.25 SUBSCRIBE_ANNOUNCES_ERROR,
//! 5 rows), for 40 rows in total.
//!
//! The arrays below restate each table's code points independently of the enum
//! definitions, so a discriminant edited in one place and not the other fails
//! here rather than shipping. The sweep in `registry_tests!` additionally
//! checks that `from_u64` accepts exactly the listed codes, so a variant added
//! without updating the array is caught too.

use moqtap_codec::draft10::error_codes::{
    AnnounceErrorCode, FetchErrorCode, SessionErrorCode, SubscribeAnnouncesErrorCode,
    SubscribeDoneStatusCode, SubscribeErrorCode,
};

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

const SUBSCRIBE_ERROR: [(SubscribeErrorCode, u64); 7] = [
    (SubscribeErrorCode::InternalError, 0x0),
    (SubscribeErrorCode::Unauthorized, 0x1),
    (SubscribeErrorCode::Timeout, 0x2),
    (SubscribeErrorCode::NotSupported, 0x3),
    (SubscribeErrorCode::TrackDoesNotExist, 0x4),
    (SubscribeErrorCode::InvalidRange, 0x5),
    (SubscribeErrorCode::RetryTrackAlias, 0x6),
];

const SUBSCRIBE_DONE: [(SubscribeDoneStatusCode, u64); 7] = [
    (SubscribeDoneStatusCode::InternalError, 0x0),
    (SubscribeDoneStatusCode::Unauthorized, 0x1),
    (SubscribeDoneStatusCode::TrackEnded, 0x2),
    (SubscribeDoneStatusCode::SubscriptionEnded, 0x3),
    (SubscribeDoneStatusCode::GoingAway, 0x4),
    (SubscribeDoneStatusCode::Expired, 0x5),
    (SubscribeDoneStatusCode::TooFarBehind, 0x6),
];

const FETCH_ERROR: [(FetchErrorCode, u64); 6] = [
    (FetchErrorCode::InternalError, 0x0),
    (FetchErrorCode::Unauthorized, 0x1),
    (FetchErrorCode::Timeout, 0x2),
    (FetchErrorCode::NotSupported, 0x3),
    (FetchErrorCode::TrackDoesNotExist, 0x4),
    (FetchErrorCode::InvalidRange, 0x5),
];

const ANNOUNCE_ERROR: [(AnnounceErrorCode, u64); 5] = [
    (AnnounceErrorCode::InternalError, 0x0),
    (AnnounceErrorCode::Unauthorized, 0x1),
    (AnnounceErrorCode::Timeout, 0x2),
    (AnnounceErrorCode::NotSupported, 0x3),
    (AnnounceErrorCode::Uninterested, 0x4),
];

const SUBSCRIBE_ANNOUNCES_ERROR: [(SubscribeAnnouncesErrorCode, u64); 5] = [
    (SubscribeAnnouncesErrorCode::InternalError, 0x0),
    (SubscribeAnnouncesErrorCode::Unauthorized, 0x1),
    (SubscribeAnnouncesErrorCode::Timeout, 0x2),
    (SubscribeAnnouncesErrorCode::NotSupported, 0x3),
    (SubscribeAnnouncesErrorCode::NamespacePrefixUnknown, 0x4),
];

/// Emits the checks every registry has to satisfy: `as_u64` returns the number
/// the draft assigns, `from_u64` inverts it, and the set of accepted values is
/// exactly the set the table lists.
macro_rules! registry_tests {
    ($name:ident, $ty:ty, $table:ident, $label:literal) => {
        #[test]
        fn $name() {
            for (variant, code) in $table {
                assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?} in {}", $label);
                assert_eq!(
                    <$ty>::from_u64(variant.as_u64()),
                    Some(variant),
                    "from_u64(as_u64()) for {variant:?} in {}",
                    $label
                );
                assert_eq!(
                    <$ty>::from_u64(code),
                    Some(variant),
                    "from_u64(0x{code:x}) in {}",
                    $label
                );
            }
            // Draft-10 assigns nothing above 0x12 in any of these registries, so
            // sweeping 0x0..=0x100 covers every assigned code with room to
            // spare. Accepting a value outside the table means either an
            // invented code point or a stale array.
            for code in (0..=0x100u64).chain([0xFFFF, 1 << 32, u64::MAX]) {
                let listed = $table.iter().any(|(_, c)| *c == code);
                assert_eq!(
                    <$ty>::from_u64(code).is_some(),
                    listed,
                    "from_u64(0x{code:x}) acceptance disagrees with {}",
                    $label
                );
            }
        }
    };
}

registry_tests!(session_error_code_round_trips, SessionErrorCode, SESSION, "Section 3.4 Table 1");
registry_tests!(
    subscribe_error_code_round_trips,
    SubscribeErrorCode,
    SUBSCRIBE_ERROR,
    "Section 8.8 Table 3"
);
registry_tests!(
    subscribe_done_status_code_round_trips,
    SubscribeDoneStatusCode,
    SUBSCRIBE_DONE,
    "Section 8.11 Table 4"
);
registry_tests!(fetch_error_code_round_trips, FetchErrorCode, FETCH_ERROR, "Section 8.14 Table 5");
registry_tests!(
    announce_error_code_round_trips,
    AnnounceErrorCode,
    ANNOUNCE_ERROR,
    "Section 8.20 Table 6"
);
registry_tests!(
    subscribe_announces_error_code_round_trips,
    SubscribeAnnouncesErrorCode,
    SUBSCRIBE_ANNOUNCES_ERROR,
    "Section 8.25 Table 7"
);

/// Table 1 assigns 0x0..=0x6 and then jumps to 0x10..=0x12. The gap is the
/// draft's own and carries no reserved-range statement, so every value in it
/// must be rejected rather than folded onto a neighbour.
#[test]
fn session_error_code_rejects_the_unassigned_gap() {
    for code in [0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF] {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "0x{code:x} falls in the 0x7..=0xF gap and draft-10 does not assign it"
        );
    }
    assert_eq!(SessionErrorCode::from_u64(0x13), None, "table stops at 0x12");
}

/// Table 5 stops at 0x5. Section 8.12 nonetheless requires a publisher to
/// answer an out-of-range fetch with a `No Objects` code that draft-10 never
/// numbers; draft-11 is the first to assign it, at 0x6. Draft-10 must not
/// anticipate that assignment, so 0x6 is rejected here even though the same
/// number is a valid `Retry Track Alias` in the SUBSCRIBE_ERROR table.
#[test]
fn fetch_error_code_does_not_anticipate_no_objects() {
    assert_eq!(FetchErrorCode::from_u64(0x6), None);
    assert_eq!(
        SubscribeErrorCode::from_u64(0x6),
        Some(SubscribeErrorCode::RetryTrackAlias),
        "0x6 is assigned in Table 3 but not in Table 5"
    );
}

/// The six registries are separate number spaces that happen to share their low
/// numbers. 0x4 is assigned in all six and means something different in four of
/// them, which is the case most likely to be lost in a refactor that collapses
/// them into one shared enum.
#[test]
fn registries_are_distinct_number_spaces() {
    assert_eq!(SessionErrorCode::from_u64(0x4), Some(SessionErrorCode::DuplicateTrackAlias));
    assert_eq!(SubscribeErrorCode::from_u64(0x4), Some(SubscribeErrorCode::TrackDoesNotExist));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x4), Some(SubscribeDoneStatusCode::GoingAway));
    assert_eq!(FetchErrorCode::from_u64(0x4), Some(FetchErrorCode::TrackDoesNotExist));
    assert_eq!(AnnounceErrorCode::from_u64(0x4), Some(AnnounceErrorCode::Uninterested));
    assert_eq!(
        SubscribeAnnouncesErrorCode::from_u64(0x4),
        Some(SubscribeAnnouncesErrorCode::NamespacePrefixUnknown)
    );
}

/// SUBSCRIBE_ERROR and FETCH_ERROR agree on 0x0..=0x5 and diverge above it.
/// They are transcribed as two enums for that reason.
#[test]
fn subscribe_and_fetch_error_share_a_prefix_only() {
    for code in 0..=0x5u64 {
        let s = SubscribeErrorCode::from_u64(code);
        let f = FetchErrorCode::from_u64(code);
        assert!(s.is_some() && f.is_some(), "0x{code:x} is assigned in both Table 3 and Table 5");
    }
    assert!(SubscribeErrorCode::from_u64(0x6).is_some());
    assert!(FetchErrorCode::from_u64(0x6).is_none());
}

/// Row counts as transcribed, checked against the draft's tables.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 10, "Section 3.4 Table 1");
    assert_eq!(SUBSCRIBE_ERROR.len(), 7, "Section 8.8 Table 3");
    assert_eq!(SUBSCRIBE_DONE.len(), 7, "Section 8.11 Table 4");
    assert_eq!(FETCH_ERROR.len(), 6, "Section 8.14 Table 5");
    assert_eq!(ANNOUNCE_ERROR.len(), 5, "Section 8.20 Table 6");
    assert_eq!(SUBSCRIBE_ANNOUNCES_ERROR.len(), 5, "Section 8.25 Table 7");
    assert_eq!(
        SESSION.len()
            + SUBSCRIBE_ERROR.len()
            + SUBSCRIBE_DONE.len()
            + FETCH_ERROR.len()
            + ANNOUNCE_ERROR.len()
            + SUBSCRIBE_ANNOUNCES_ERROR.len(),
        40
    );
}

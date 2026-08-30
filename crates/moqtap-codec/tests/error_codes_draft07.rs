#![cfg(feature = "draft07")]
//! Round-trip and rejection tests for the draft-07 code registries.
//!
//! The three tables transcribed in `draft07::error_codes` are, in the draft:
//! Table 1 (section 3.5 Termination, 8 rows), Table 2 (section 5.1
//! SUBSCRIBE_ERROR, 6 rows) and Table 3 (section 5.1 SUBSCRIBE_DONE, 7 rows).
//! The arrays below restate each table's code points independently of the enum
//! definitions, so a discriminant edited in one place and not the other fails
//! here rather than shipping.

use moqtap_codec::draft07::error_codes::{
    SessionErrorCode, SubscribeDoneStatusCode, SubscribeErrorCode,
};

const SESSION: [(SessionErrorCode, u64); 8] = [
    (SessionErrorCode::NoError, 0x0),
    (SessionErrorCode::InternalError, 0x1),
    (SessionErrorCode::Unauthorized, 0x2),
    (SessionErrorCode::ProtocolViolation, 0x3),
    (SessionErrorCode::DuplicateTrackAlias, 0x4),
    (SessionErrorCode::ParameterLengthMismatch, 0x5),
    (SessionErrorCode::TooManySubscribes, 0x6),
    (SessionErrorCode::GoawayTimeout, 0x10),
];

const SUBSCRIBE_ERROR: [(SubscribeErrorCode, u64); 6] = [
    (SubscribeErrorCode::InternalError, 0x0),
    (SubscribeErrorCode::InvalidRange, 0x1),
    (SubscribeErrorCode::RetryTrackAlias, 0x2),
    (SubscribeErrorCode::TrackDoesNotExist, 0x3),
    (SubscribeErrorCode::Unauthorized, 0x4),
    (SubscribeErrorCode::Timeout, 0x5),
];

const SUBSCRIBE_DONE: [(SubscribeDoneStatusCode, u64); 7] = [
    (SubscribeDoneStatusCode::Unsubscribed, 0x0),
    (SubscribeDoneStatusCode::InternalError, 0x1),
    (SubscribeDoneStatusCode::Unauthorized, 0x2),
    (SubscribeDoneStatusCode::TrackEnded, 0x3),
    (SubscribeDoneStatusCode::SubscriptionEnded, 0x4),
    (SubscribeDoneStatusCode::GoingAway, 0x5),
    (SubscribeDoneStatusCode::Expired, 0x6),
];

#[test]
fn session_error_code_round_trips() {
    for (variant, code) in SESSION {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            SessionErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(SessionErrorCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

#[test]
fn subscribe_error_code_round_trips() {
    for (variant, code) in SUBSCRIBE_ERROR {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            SubscribeErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(SubscribeErrorCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

#[test]
fn subscribe_done_status_code_round_trips() {
    for (variant, code) in SUBSCRIBE_DONE {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            SubscribeDoneStatusCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(SubscribeDoneStatusCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

/// Section 3.5 assigns 0x0..=0x6 and 0x10. The gap is the draft's own, and every
/// value in it must be rejected rather than silently folded onto a neighbour.
#[test]
fn session_error_code_rejects_unassigned() {
    for code in [0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x11, 0x12, 0xFF, u64::MAX] {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-07 section 3.5"
        );
    }
}

/// Table 2 stops at 0x5; draft-14 later reuses several of these numbers for a
/// different registry, so accepting anything above 0x5 here would be wrong.
#[test]
fn subscribe_error_code_rejects_unassigned() {
    for code in [0x6, 0x7, 0x10, 0xFF, u64::MAX] {
        assert_eq!(
            SubscribeErrorCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-07 Table 2"
        );
    }
}

/// Table 3 stops at 0x6.
#[test]
fn subscribe_done_status_code_rejects_unassigned() {
    for code in [0x7, 0x8, 0x10, 0xFF, u64::MAX] {
        assert_eq!(
            SubscribeDoneStatusCode::from_u64(code),
            None,
            "0x{code:x} is not assigned by draft-07 Table 3"
        );
    }
}

/// The three registries are separate number spaces. Draft-07 reuses 0x2 with
/// three different meanings, which is the case most likely to be collapsed by a
/// future refactor into one shared enum.
#[test]
fn registries_are_distinct_number_spaces() {
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(SubscribeErrorCode::from_u64(0x2), Some(SubscribeErrorCode::RetryTrackAlias));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x2), Some(SubscribeDoneStatusCode::Unauthorized));
}

/// Row counts as transcribed, checked against the draft's tables.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 8, "section 3.5 Table 1");
    assert_eq!(SUBSCRIBE_ERROR.len(), 6, "section 5.1 Table 2");
    assert_eq!(SUBSCRIBE_DONE.len(), 7, "section 5.1 Table 3");
    assert_eq!(SESSION.len() + SUBSCRIBE_ERROR.len() + SUBSCRIBE_DONE.len(), 21);
}

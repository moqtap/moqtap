#![cfg(feature = "draft08")]
//! Round-trip and rejection tests for the draft-08 code registries.
//!
//! The expected tables below are transcribed from draft-ietf-moq-transport-08
//! independently of `src/draft08/error_codes.rs`: code point and reason phrase
//! per row, in the order the draft's tables list them. A test that only called
//! `from_u64(as_u64(v))` would pass even if a variant carried the wrong code
//! point, so each registry is also pinned against those literals.

use moqtap_codec::draft08::error_codes::{
    AnnounceErrorCode, FetchErrorCode, SessionErrorCode, SubscribeAnnouncesErrorCode,
    SubscribeDoneStatusCode, SubscribeErrorCode,
};

/// Section 3.5 "Termination", Table 1.
const SESSION: &[(u64, SessionErrorCode)] = &[
    (0x0, SessionErrorCode::NoError),
    (0x1, SessionErrorCode::InternalError),
    (0x2, SessionErrorCode::Unauthorized),
    (0x3, SessionErrorCode::ProtocolViolation),
    (0x4, SessionErrorCode::DuplicateTrackAlias),
    (0x5, SessionErrorCode::ParameterLengthMismatch),
    (0x6, SessionErrorCode::TooManySubscribes),
    (0x10, SessionErrorCode::GoawayTimeout),
    (0x11, SessionErrorCode::ControlMessageTimeout),
    (0x12, SessionErrorCode::DataStreamTimeout),
];

/// Section 7.10 "ANNOUNCE_ERROR", Table 3.
const ANNOUNCE: &[(u64, AnnounceErrorCode)] = &[
    (0x0, AnnounceErrorCode::InternalError),
    (0x1, AnnounceErrorCode::Unauthorized),
    (0x2, AnnounceErrorCode::Timeout),
    (0x3, AnnounceErrorCode::NotSupported),
    (0x4, AnnounceErrorCode::Uninterested),
];

/// Section 7.16 "SUBSCRIBE_ERROR", Table 4.
const SUBSCRIBE: &[(u64, SubscribeErrorCode)] = &[
    (0x0, SubscribeErrorCode::InternalError),
    (0x1, SubscribeErrorCode::Unauthorized),
    (0x2, SubscribeErrorCode::Timeout),
    (0x3, SubscribeErrorCode::NotSupported),
    (0x4, SubscribeErrorCode::TrackDoesNotExist),
    (0x5, SubscribeErrorCode::InvalidRange),
    (0x6, SubscribeErrorCode::RetryTrackAlias),
];

/// Section 7.18 "FETCH_ERROR", Table 5.
const FETCH: &[(u64, FetchErrorCode)] = &[
    (0x0, FetchErrorCode::InternalError),
    (0x1, FetchErrorCode::Unauthorized),
    (0x2, FetchErrorCode::Timeout),
    (0x3, FetchErrorCode::NotSupported),
    (0x4, FetchErrorCode::TrackDoesNotExist),
    (0x5, FetchErrorCode::InvalidRange),
];

/// Section 7.19 "SUBSCRIBE_DONE", Table 6.
const SUBSCRIBE_DONE: &[(u64, SubscribeDoneStatusCode)] = &[
    (0x0, SubscribeDoneStatusCode::InternalError),
    (0x1, SubscribeDoneStatusCode::Unauthorized),
    (0x2, SubscribeDoneStatusCode::TrackEnded),
    (0x3, SubscribeDoneStatusCode::SubscriptionEnded),
    (0x4, SubscribeDoneStatusCode::GoingAway),
    (0x5, SubscribeDoneStatusCode::Expired),
    (0x6, SubscribeDoneStatusCode::TooFarBehind),
];

/// Section 7.26 "SUBSCRIBE_ANNOUNCES_ERROR", Table 7.
const SUBSCRIBE_ANNOUNCES: &[(u64, SubscribeAnnouncesErrorCode)] = &[
    (0x0, SubscribeAnnouncesErrorCode::InternalError),
    (0x1, SubscribeAnnouncesErrorCode::Unauthorized),
    (0x2, SubscribeAnnouncesErrorCode::Timeout),
    (0x3, SubscribeAnnouncesErrorCode::NotSupported),
    (0x4, SubscribeAnnouncesErrorCode::NamespacePrefixUnknown),
];

/// Assert the three properties that matter for one registry:
///
/// 1. every variant encodes to the code point the draft assigns it,
/// 2. every assigned code point decodes back to that same variant, so
///    `from_u64(as_u64(v)) == Some(v)` for all variants, and
/// 3. every code point in `0..=0xFF` that the draft does not assign decodes to
///    `None`, which catches both a stray extra variant and an over-broad
///    `from_u64` arm.
macro_rules! check_registry {
    ($table:expr, $from:path, $name:literal) => {{
        for &(code, variant) in $table {
            assert_eq!(
                variant.as_u64(),
                code,
                "{}: variant {:?} encodes to {:#x}, draft assigns {:#x}",
                $name,
                variant,
                variant.as_u64(),
                code
            );
            assert_eq!(
                $from(code),
                Some(variant),
                "{}: from_u64({:#x}) did not decode to {:?}",
                $name,
                code,
                variant
            );
            assert_eq!(
                $from(variant.as_u64()),
                Some(variant),
                "{}: round trip failed for {:?}",
                $name,
                variant
            );
        }
        for code in 0u64..=0xFF {
            let assigned = $table.iter().any(|&(c, _)| c == code);
            if !assigned {
                assert_eq!(
                    $from(code),
                    None,
                    "{}: from_u64({:#x}) returned a value, but the draft does not \
                     assign that code point",
                    $name,
                    code
                );
            }
        }
    }};
}

#[test]
fn session_error_code_round_trips() {
    check_registry!(SESSION, SessionErrorCode::from_u64, "Termination");
    assert_eq!(SESSION.len(), 10);
}

#[test]
fn announce_error_code_round_trips() {
    check_registry!(ANNOUNCE, AnnounceErrorCode::from_u64, "ANNOUNCE_ERROR");
    assert_eq!(ANNOUNCE.len(), 5);
}

#[test]
fn subscribe_error_code_round_trips() {
    check_registry!(SUBSCRIBE, SubscribeErrorCode::from_u64, "SUBSCRIBE_ERROR");
    assert_eq!(SUBSCRIBE.len(), 7);
}

#[test]
fn fetch_error_code_round_trips() {
    check_registry!(FETCH, FetchErrorCode::from_u64, "FETCH_ERROR");
    assert_eq!(FETCH.len(), 6);
}

#[test]
fn subscribe_done_status_code_round_trips() {
    check_registry!(SUBSCRIBE_DONE, SubscribeDoneStatusCode::from_u64, "SUBSCRIBE_DONE");
    assert_eq!(SUBSCRIBE_DONE.len(), 7);
}

#[test]
fn subscribe_announces_error_code_round_trips() {
    check_registry!(
        SUBSCRIBE_ANNOUNCES,
        SubscribeAnnouncesErrorCode::from_u64,
        "SUBSCRIBE_ANNOUNCES_ERROR"
    );
    assert_eq!(SUBSCRIBE_ANNOUNCES.len(), 5);
}

/// The six registries together hold 40 rows.
#[test]
fn registry_row_counts_match_the_draft() {
    let total = SESSION.len()
        + ANNOUNCE.len()
        + SUBSCRIBE.len()
        + FETCH.len()
        + SUBSCRIBE_DONE.len()
        + SUBSCRIBE_ANNOUNCES.len();
    assert_eq!(total, 40, "draft-08 defines 40 code points across 6 registries");
}

/// Section 3.5 assigns 0x0-0x6 and 0x10-0x12. The gap matters: an enum written
/// without explicit discriminants would renumber `GOAWAY Timeout` and its two
/// neighbours to 0x7-0x9 and still round trip cleanly.
#[test]
fn session_termination_gap_is_unassigned() {
    for code in 0x7u64..=0xF {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "{code:#x} lies in the 0x7-0xF gap and must not decode"
        );
    }
    assert_eq!(
        SessionErrorCode::GoawayTimeout.as_u64(),
        0x10,
        "GOAWAY Timeout must stay at 0x10, not shift into the gap"
    );
    assert_eq!(SessionErrorCode::ControlMessageTimeout.as_u64(), 0x11);
    assert_eq!(SessionErrorCode::DataStreamTimeout.as_u64(), 0x12);
}

/// Large and boundary values are rejected rather than wrapping or panicking.
#[test]
fn out_of_range_values_decode_to_none() {
    for &code in &[0x100u64, 0x1000, u64::from(u32::MAX), u64::MAX] {
        assert_eq!(SessionErrorCode::from_u64(code), None);
        assert_eq!(AnnounceErrorCode::from_u64(code), None);
        assert_eq!(SubscribeErrorCode::from_u64(code), None);
        assert_eq!(FetchErrorCode::from_u64(code), None);
        assert_eq!(SubscribeDoneStatusCode::from_u64(code), None);
        assert_eq!(SubscribeAnnouncesErrorCode::from_u64(code), None);
    }
}

/// The registries overlap on 0x0-0x3 but diverge above it, which is why each is
/// a distinct type. These are the specific rows that differ.
#[test]
fn registries_diverge_where_the_draft_says_they_do() {
    // 0x2 is Timeout in the request-scoped registries but Track Ended in
    // SUBSCRIBE_DONE.
    assert_eq!(SubscribeErrorCode::from_u64(0x2), Some(SubscribeErrorCode::Timeout));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x2), Some(SubscribeDoneStatusCode::TrackEnded));

    // 0x4 carries three different meanings across the request-scoped registries.
    assert_eq!(AnnounceErrorCode::from_u64(0x4), Some(AnnounceErrorCode::Uninterested));
    assert_eq!(
        SubscribeAnnouncesErrorCode::from_u64(0x4),
        Some(SubscribeAnnouncesErrorCode::NamespacePrefixUnknown)
    );
    assert_eq!(SubscribeErrorCode::from_u64(0x4), Some(SubscribeErrorCode::TrackDoesNotExist));

    // FETCH_ERROR matches SUBSCRIBE_ERROR through 0x5 and stops there.
    assert_eq!(FetchErrorCode::from_u64(0x5), Some(FetchErrorCode::InvalidRange));
    assert_eq!(FetchErrorCode::from_u64(0x6), None, "FETCH_ERROR has no Retry Track Alias");
    assert_eq!(SubscribeErrorCode::from_u64(0x6), Some(SubscribeErrorCode::RetryTrackAlias));

    // ANNOUNCE_ERROR and SUBSCRIBE_ANNOUNCES_ERROR both stop at 0x4.
    assert_eq!(AnnounceErrorCode::from_u64(0x5), None);
    assert_eq!(SubscribeAnnouncesErrorCode::from_u64(0x5), None);
}

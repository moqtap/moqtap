#![cfg(feature = "draft15")]
//! Round-trip and rejection tests for the draft-15 code registries.
//!
//! The expected tables below are transcribed from draft-ietf-moq-transport-15
//! independently of `src/draft15/error_codes.rs`: name and code point per row,
//! in the order the draft's IANA tables list them. A test that only called
//! `from_u64(as_u64(v))` would pass even if a variant carried the wrong code
//! point, so each registry is also pinned against those literals.
//!
//! Draft-15 states each of these registries twice — once as an IANA table in
//! Section 13.3 and once as a definition list in the section that table cites.
//! The two agree row for row, so the literals below can be checked against
//! either.

use moqtap_codec::draft15::error_codes::{
    DataStreamResetErrorCode, PublishDoneStatusCode, RequestErrorCode, SessionErrorCode,
};

/// Section 13.3.1 "Session Termination Error Codes", Table 11; defined in
/// Section 3.4 "Termination". Assigns 0x0-0x9 and 0x10-0x1A.
const SESSION: &[(u64, SessionErrorCode)] = &[
    (0x0, SessionErrorCode::NoError),
    (0x1, SessionErrorCode::InternalError),
    (0x2, SessionErrorCode::Unauthorized),
    (0x3, SessionErrorCode::ProtocolViolation),
    (0x4, SessionErrorCode::InvalidRequestId),
    (0x5, SessionErrorCode::DuplicateTrackAlias),
    (0x6, SessionErrorCode::KeyValueFormattingError),
    (0x7, SessionErrorCode::TooManyRequests),
    (0x8, SessionErrorCode::InvalidPath),
    (0x9, SessionErrorCode::MalformedPath),
    (0x10, SessionErrorCode::GoawayTimeout),
    (0x11, SessionErrorCode::ControlMessageTimeout),
    (0x12, SessionErrorCode::DataStreamTimeout),
    (0x13, SessionErrorCode::AuthTokenCacheOverflow),
    (0x14, SessionErrorCode::DuplicateAuthTokenAlias),
    (0x15, SessionErrorCode::VersionNegotiationFailed),
    (0x16, SessionErrorCode::MalformedAuthToken),
    (0x17, SessionErrorCode::UnknownAuthTokenAlias),
    (0x18, SessionErrorCode::ExpiredAuthToken),
    (0x19, SessionErrorCode::InvalidAuthority),
    (0x1A, SessionErrorCode::MalformedAuthority),
];

/// Section 13.3.2 "REQUEST_ERROR Codes", Table 12; defined in Section 9.8
/// "REQUEST_ERROR". Assigns 0x0-0x5, 0x10-0x12, 0x20, 0x30, 0x32 and 0x33.
const REQUEST: &[(u64, RequestErrorCode)] = &[
    (0x0, RequestErrorCode::InternalError),
    (0x1, RequestErrorCode::Unauthorized),
    (0x2, RequestErrorCode::Timeout),
    (0x3, RequestErrorCode::NotSupported),
    (0x4, RequestErrorCode::MalformedAuthToken),
    (0x5, RequestErrorCode::ExpiredAuthToken),
    (0x10, RequestErrorCode::DoesNotExist),
    (0x11, RequestErrorCode::InvalidRange),
    (0x12, RequestErrorCode::MalformedTrack),
    (0x20, RequestErrorCode::Uninterested),
    (0x30, RequestErrorCode::PrefixOverlap),
    (0x32, RequestErrorCode::InvalidJoiningRequestId),
    (0x33, RequestErrorCode::UnknownStatusInRange),
];

/// Section 13.3.3 "PUBLISH_DONE Codes", Table 13; defined in Section 9.15
/// "PUBLISH_DONE". Assigns 0x0-0x8 contiguously.
const PUBLISH_DONE: &[(u64, PublishDoneStatusCode)] = &[
    (0x0, PublishDoneStatusCode::InternalError),
    (0x1, PublishDoneStatusCode::Unauthorized),
    (0x2, PublishDoneStatusCode::TrackEnded),
    (0x3, PublishDoneStatusCode::SubscriptionEnded),
    (0x4, PublishDoneStatusCode::GoingAway),
    (0x5, PublishDoneStatusCode::Expired),
    (0x6, PublishDoneStatusCode::TooFarBehind),
    (0x7, PublishDoneStatusCode::MalformedTrack),
    (0x8, PublishDoneStatusCode::UpdateFailed),
];

/// Section 13.3.4 "Data Stream Reset Error Codes", Table 14; defined in
/// Section 10.4.3 "Closing Subgroup Streams". Assigns 0x0-0x3 contiguously.
const STREAM_RESET: &[(u64, DataStreamResetErrorCode)] = &[
    (0x0, DataStreamResetErrorCode::InternalError),
    (0x1, DataStreamResetErrorCode::Cancelled),
    (0x2, DataStreamResetErrorCode::DeliveryTimeout),
    (0x3, DataStreamResetErrorCode::SessionClosed),
];

/// Assert the three properties that matter for one registry:
///
/// 1. every variant encodes to the code point the draft assigns it,
/// 2. every assigned code point decodes back to that same variant, so
///    `from_u64(as_u64(v)) == Some(v)` holds for all variants, and
/// 3. every code point in `0..=0xFF` that the draft does not assign decodes to
///    `None`, which catches both a stray extra variant and an over-broad
///    `from_u64` arm.
macro_rules! check_registry {
    ($table:expr, $from:path, $name:literal) => {{
        for &(code, variant) in $table {
            assert_eq!(
                variant.as_u64(),
                code,
                "{}: variant {:?} encodes to {:#x}, draft-15 assigns {:#x}",
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
                "{}: round trip from_u64(as_u64(v)) failed for {:?}",
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
                    "{}: from_u64({:#x}) returned a value, but draft-15 does not \
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
    check_registry!(SESSION, SessionErrorCode::from_u64, "Session Termination Error Codes");
    assert_eq!(SESSION.len(), 21);
}

#[test]
fn request_error_code_round_trips() {
    check_registry!(REQUEST, RequestErrorCode::from_u64, "REQUEST_ERROR Codes");
    assert_eq!(REQUEST.len(), 13);
}

#[test]
fn publish_done_status_code_round_trips() {
    check_registry!(PUBLISH_DONE, PublishDoneStatusCode::from_u64, "PUBLISH_DONE Codes");
    assert_eq!(PUBLISH_DONE.len(), 9);
}

#[test]
fn data_stream_reset_error_code_round_trips() {
    check_registry!(
        STREAM_RESET,
        DataStreamResetErrorCode::from_u64,
        "Data Stream Reset Error Codes"
    );
    assert_eq!(STREAM_RESET.len(), 4);
}

/// The four registries together hold 47 rows.
#[test]
fn registry_row_counts_match_the_draft() {
    let total = SESSION.len() + REQUEST.len() + PUBLISH_DONE.len() + STREAM_RESET.len();
    assert_eq!(total, 47, "draft-15 defines 47 code points across 4 registries");
}

/// Section 3.4 assigns 0x0-0x9 and 0x10-0x1A. The gap matters: an enum written
/// without explicit discriminants would renumber GOAWAY_TIMEOUT and everything
/// after it down into 0xA onwards and still round trip cleanly.
#[test]
fn session_termination_gap_is_unassigned() {
    for code in 0xAu64..=0xF {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "{code:#x} lies in the 0xA-0xF gap and must not decode"
        );
    }
    assert_eq!(
        SessionErrorCode::GoawayTimeout.as_u64(),
        0x10,
        "GOAWAY_TIMEOUT must stay at 0x10, not shift into the gap"
    );
    assert_eq!(SessionErrorCode::MalformedAuthority.as_u64(), 0x1A);
    assert_eq!(SessionErrorCode::from_u64(0x1B), None);
}

/// REQUEST_ERROR is the sparsest registry in the draft: three interior gaps plus
/// the single hole at 0x31, which sits between PREFIX_OVERLAP (0x30) and
/// INVALID_JOINING_REQUEST_ID (0x32) in both Table 12 and Section 9.8.
#[test]
fn request_error_gaps_are_unassigned() {
    for code in (0x6u64..=0xF).chain(0x13..=0x1F).chain(0x21..=0x2F).chain(std::iter::once(0x31)) {
        assert_eq!(
            RequestErrorCode::from_u64(code),
            None,
            "{code:#x} is unassigned in draft-15 REQUEST_ERROR and must not decode"
        );
    }
    assert_eq!(RequestErrorCode::from_u64(0x30), Some(RequestErrorCode::PrefixOverlap));
    assert_eq!(RequestErrorCode::from_u64(0x32), Some(RequestErrorCode::InvalidJoiningRequestId));
}

/// Large and boundary values are rejected rather than wrapping or panicking.
#[test]
fn out_of_range_values_decode_to_none() {
    for &code in &[0x100u64, 0x1000, u64::from(u32::MAX), u64::MAX] {
        assert_eq!(SessionErrorCode::from_u64(code), None);
        assert_eq!(RequestErrorCode::from_u64(code), None);
        assert_eq!(PublishDoneStatusCode::from_u64(code), None);
        assert_eq!(DataStreamResetErrorCode::from_u64(code), None);
    }
}

/// The registries share code points but not meanings, which is why each is a
/// distinct type. These are rows where the same integer means different things,
/// so a cast between registries would silently mislabel an error.
#[test]
fn registries_diverge_where_the_draft_says_they_do() {
    // 0x2 is TIMEOUT for a request, TRACK_ENDED for a completed publication and
    // DELIVERY_TIMEOUT for a reset stream.
    assert_eq!(RequestErrorCode::from_u64(0x2), Some(RequestErrorCode::Timeout));
    assert_eq!(PublishDoneStatusCode::from_u64(0x2), Some(PublishDoneStatusCode::TrackEnded));
    assert_eq!(
        DataStreamResetErrorCode::from_u64(0x2),
        Some(DataStreamResetErrorCode::DeliveryTimeout)
    );

    // 0x4 is INVALID_REQUEST_ID at session scope, MALFORMED_AUTH_TOKEN at
    // request scope and GOING_AWAY in PUBLISH_DONE. The stream reset registry
    // stops at 0x3 and does not assign it at all.
    assert_eq!(SessionErrorCode::from_u64(0x4), Some(SessionErrorCode::InvalidRequestId));
    assert_eq!(RequestErrorCode::from_u64(0x4), Some(RequestErrorCode::MalformedAuthToken));
    assert_eq!(PublishDoneStatusCode::from_u64(0x4), Some(PublishDoneStatusCode::GoingAway));
    assert_eq!(DataStreamResetErrorCode::from_u64(0x4), None);

    // MALFORMED_AUTH_TOKEN and EXPIRED_AUTH_TOKEN exist in both the session and
    // request registries, at different code points.
    assert_eq!(SessionErrorCode::MalformedAuthToken.as_u64(), 0x16);
    assert_eq!(RequestErrorCode::MalformedAuthToken.as_u64(), 0x4);
    assert_eq!(SessionErrorCode::ExpiredAuthToken.as_u64(), 0x18);
    assert_eq!(RequestErrorCode::ExpiredAuthToken.as_u64(), 0x5);

    // MALFORMED_TRACK likewise appears in two registries at two code points.
    assert_eq!(RequestErrorCode::MalformedTrack.as_u64(), 0x12);
    assert_eq!(PublishDoneStatusCode::MalformedTrack.as_u64(), 0x7);

    // PUBLISH_DONE stops at UPDATE_FAILED (0x8); the session registry keeps
    // going, and 0x9 is MALFORMED_PATH there.
    assert_eq!(PublishDoneStatusCode::from_u64(0x9), None);
    assert_eq!(SessionErrorCode::from_u64(0x9), Some(SessionErrorCode::MalformedPath));
}

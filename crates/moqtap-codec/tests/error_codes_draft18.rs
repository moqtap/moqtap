#![cfg(feature = "draft18")]
//! Round-trip and rejection tests for the draft-18 code registries.
//!
//! The expected tables below were transcribed from the four registry tables in
//! Section 15.10 of draft-ietf-moq-transport-18 independently of
//! `src/draft18/error_codes.rs`: code point and draft name per row, in the order
//! the draft lists them. A test that only called `from_u64(as_u64(v))` would
//! pass even if a variant carried the wrong code point, so every registry is
//! also pinned against those literals.
//!
//! Each table also reserves `0x7f * N + 0x9D` for greasing (Section 14). That is
//! a range, not an assignment, so no variant may claim one of those values.

use moqtap_codec::draft18::error_codes::{
    PublishDoneStatusCode, RequestErrorCode, SessionErrorCode, StreamResetErrorCode,
};
use moqtap_codec::draft18::message::{publish_done_codes, request_error_codes};

/// Section 15.10.1 "Session Termination Error Codes", Table 17.
const SESSION: &[(u64, SessionErrorCode)] = &[
    (0x0, SessionErrorCode::NoError),
    (0x1, SessionErrorCode::InternalError),
    (0x2, SessionErrorCode::Unauthorized),
    (0x3, SessionErrorCode::ProtocolViolation),
    (0x4, SessionErrorCode::InvalidRequestId),
    (0x5, SessionErrorCode::DuplicateTrackAlias),
    (0x6, SessionErrorCode::KeyValueFormattingError),
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

/// Section 15.10.2 "REQUEST_ERROR Codes", Table 18.
const REQUEST: &[(u64, RequestErrorCode)] = &[
    (0x0, RequestErrorCode::InternalError),
    (0x1, RequestErrorCode::Unauthorized),
    (0x2, RequestErrorCode::Timeout),
    (0x3, RequestErrorCode::NotSupported),
    (0x4, RequestErrorCode::MalformedAuthToken),
    (0x5, RequestErrorCode::ExpiredAuthToken),
    (0x6, RequestErrorCode::GoingAway),
    (0x9, RequestErrorCode::ExcessiveLoad),
    (0x10, RequestErrorCode::DoesNotExist),
    (0x11, RequestErrorCode::InvalidRange),
    (0x12, RequestErrorCode::MalformedTrack),
    (0x19, RequestErrorCode::DuplicateSubscription),
    (0x20, RequestErrorCode::Uninterested),
    (0x30, RequestErrorCode::PrefixOverlap),
    (0x31, RequestErrorCode::NamespaceTooLarge),
    (0x32, RequestErrorCode::InvalidJoiningRequestId),
    (0x33, RequestErrorCode::UnsupportedExtension),
    (0x34, RequestErrorCode::Redirect),
];

/// Section 15.10.3 "PUBLISH_DONE Codes", Table 19.
const PUBLISH_DONE: &[(u64, PublishDoneStatusCode)] = &[
    (0x0, PublishDoneStatusCode::InternalError),
    (0x1, PublishDoneStatusCode::Unauthorized),
    (0x2, PublishDoneStatusCode::TrackEnded),
    (0x3, PublishDoneStatusCode::SubscriptionEnded),
    (0x4, PublishDoneStatusCode::GoingAway),
    (0x5, PublishDoneStatusCode::TooFarBehind),
    (0x6, PublishDoneStatusCode::Expired),
    (0x8, PublishDoneStatusCode::UpdateFailed),
    (0x9, PublishDoneStatusCode::ExcessiveLoad),
    (0x12, PublishDoneStatusCode::MalformedTrack),
];

/// Section 15.10.4 "Stream Reset Error Codes", Table 20.
const STREAM_RESET: &[(u64, StreamResetErrorCode)] = &[
    (0x0, StreamResetErrorCode::InternalError),
    (0x1, StreamResetErrorCode::Cancelled),
    (0x2, StreamResetErrorCode::DeliveryTimeout),
    (0x3, StreamResetErrorCode::SessionClosed),
    (0x4, StreamResetErrorCode::GoingAway),
    (0x5, StreamResetErrorCode::TooFarBehind),
    (0x6, StreamResetErrorCode::UnknownObjectStatus),
    (0x7, StreamResetErrorCode::ExpiredAuthToken),
    (0x9, StreamResetErrorCode::ExcessiveLoad),
    (0x12, StreamResetErrorCode::MalformedTrack),
];

/// The greasing range reserved by Section 14: `0x7f * N + 0x9D` for
/// non-negative N. The draft spells the sequence out as
/// "0x9D, 0x11C, ..., 0x3fffffffffffffde".
fn grease(n: u64) -> u64 {
    0x7f * n + 0x9D
}

/// Assert the four properties that matter for one registry:
///
/// 1. every variant encodes to the code point the draft assigns it,
/// 2. every assigned code point decodes back to that same variant, so
///    `from_u64(as_u64(v)) == Some(v)` holds for every variant,
/// 3. every code point in `0..=0xFF` that the draft does not assign decodes to
///    `None`, which catches both a stray extra variant and an over-broad
///    `from_u64` arm, and
/// 4. values past the byte range, including the varint maximum, decode to
///    `None` rather than wrapping or panicking.
macro_rules! check_registry {
    ($table:expr, $from:path, $name:literal) => {{
        for &(code, variant) in $table {
            assert_eq!(
                variant.as_u64(),
                code,
                "{}: variant {:?} encodes to {:#x}, the draft assigns {:#x}",
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
                    "{}: from_u64({:#x}) returned a value, but the draft does not \
                     assign that code point",
                    $name,
                    code
                );
            }
        }
        for &code in &[0x100u64, 0x1000, u64::from(u32::MAX), (1u64 << 62) - 1, u64::MAX] {
            assert_eq!($from(code), None, "{}: from_u64({:#x}) must be unrecognized", $name, code);
        }
    }};
}

#[test]
fn session_error_code_round_trips() {
    check_registry!(SESSION, SessionErrorCode::from_u64, "Session Termination");
    assert_eq!(SESSION.len(), 20);
}

#[test]
fn request_error_code_round_trips() {
    check_registry!(REQUEST, RequestErrorCode::from_u64, "REQUEST_ERROR");
    assert_eq!(REQUEST.len(), 18);
}

#[test]
fn publish_done_status_code_round_trips() {
    check_registry!(PUBLISH_DONE, PublishDoneStatusCode::from_u64, "PUBLISH_DONE");
    assert_eq!(PUBLISH_DONE.len(), 10);
}

#[test]
fn stream_reset_error_code_round_trips() {
    check_registry!(STREAM_RESET, StreamResetErrorCode::from_u64, "Stream Reset");
    assert_eq!(STREAM_RESET.len(), 10);
}

/// Section 15.10 holds four registries. Their tables list 62 rows, four of which
/// are the reserved greasing range rather than an assignment, leaving 58 code
/// points that need a variant.
#[test]
fn registry_row_counts_match_the_draft() {
    let assigned = SESSION.len() + REQUEST.len() + PUBLISH_DONE.len() + STREAM_RESET.len();
    assert_eq!(
        assigned, 58,
        "draft-18 assigns 58 code points across the four registries in Section 15.10"
    );
    assert_eq!(assigned + 4, 62, "the four tables hold 62 rows in total");
}

/// The greasing range is a range, not an assignment. No variant may claim one of
/// its values and no `from_u64` may recognize one, in any of the four
/// registries.
#[test]
fn greasing_range_is_never_recognized() {
    assert_eq!(grease(0), 0x9D, "the sequence starts at 0x9D");
    assert_eq!(grease(1), 0x11C, "the second grease value is 0x11C");
    assert_eq!(
        grease(36_312_488_334_073_919),
        0x3fff_ffff_ffff_ffde,
        "the last grease value inside the 62-bit varint range is 0x3fffffffffffffde"
    );

    let samples: Vec<u64> = (0..64).map(grease).chain([grease(36_312_488_334_073_919)]).collect();

    for code in samples {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "Session Termination: grease value {code:#x} must not decode"
        );
        assert_eq!(
            RequestErrorCode::from_u64(code),
            None,
            "REQUEST_ERROR: grease value {code:#x} must not decode"
        );
        assert_eq!(
            PublishDoneStatusCode::from_u64(code),
            None,
            "PUBLISH_DONE: grease value {code:#x} must not decode"
        );
        assert_eq!(
            StreamResetErrorCode::from_u64(code),
            None,
            "Stream Reset: grease value {code:#x} must not decode"
        );
    }

    for &(code, _) in SESSION {
        assert_ne!((code as i64 - 0x9D) % 0x7f, 0, "{code:#x} collides with grease");
    }
    for &(code, _) in REQUEST {
        assert_ne!((code as i64 - 0x9D) % 0x7f, 0, "{code:#x} collides with grease");
    }
}

/// Section 15.10.1 runs 0x6 then 0x8. The missing 0x7 is not a typo in the
/// table: draft-14 assigned TOO_MANY_REQUESTS there and draft-18 does not, so a
/// decoder that accepts 0x7 is accepting a code this draft never defined. The
/// registry then resumes at 0x8 and 0x9 before a second gap at 0xA-0xF.
#[test]
fn session_termination_gap_is_unassigned() {
    assert_eq!(
        SessionErrorCode::from_u64(0x7),
        None,
        "0x7 is unassigned in draft-18 and must not decode"
    );
    for code in 0xAu64..=0xF {
        assert_eq!(
            SessionErrorCode::from_u64(code),
            None,
            "{code:#x} lies in the unassigned 0xA-0xF gap and must not decode"
        );
    }
    assert_eq!(
        SessionErrorCode::MalformedPath.as_u64(),
        0x9,
        "0x9 is assigned, so the gap below 0x10 starts at 0xA"
    );
    assert_eq!(
        SessionErrorCode::KeyValueFormattingError.as_u64(),
        0x6,
        "the assignment below the gap must stay at 0x6"
    );
    assert_eq!(
        SessionErrorCode::InvalidPath.as_u64(),
        0x8,
        "INVALID_PATH must stay at 0x8, not slide down into the gap"
    );
    assert_eq!(SessionErrorCode::GoawayTimeout.as_u64(), 0x10);
    assert_eq!(SessionErrorCode::MalformedAuthority.as_u64(), 0x1A);
}

/// The four registries share low code points but assign them different
/// meanings, which is why each is a distinct type. These are rows that would
/// silently mean the wrong thing if a value were moved between the types.
#[test]
fn registries_diverge_where_the_draft_says_they_do() {
    // 0x0 is NO_ERROR only when terminating a session; the other three
    // registries assign it INTERNAL_ERROR.
    assert_eq!(SessionErrorCode::from_u64(0x0), Some(SessionErrorCode::NoError));
    assert_eq!(RequestErrorCode::from_u64(0x0), Some(RequestErrorCode::InternalError));
    assert_eq!(PublishDoneStatusCode::from_u64(0x0), Some(PublishDoneStatusCode::InternalError));
    assert_eq!(StreamResetErrorCode::from_u64(0x0), Some(StreamResetErrorCode::InternalError));

    // 0x2 carries three meanings.
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(RequestErrorCode::from_u64(0x2), Some(RequestErrorCode::Timeout));
    assert_eq!(PublishDoneStatusCode::from_u64(0x2), Some(PublishDoneStatusCode::TrackEnded));
    assert_eq!(StreamResetErrorCode::from_u64(0x2), Some(StreamResetErrorCode::DeliveryTimeout));

    // 0x5 and 0x6 differ between REQUEST_ERROR and PUBLISH_DONE, and 0x5/0x6
    // in PUBLISH_DONE are the pair draft-18 swapped relative to draft-17.
    assert_eq!(RequestErrorCode::from_u64(0x5), Some(RequestErrorCode::ExpiredAuthToken));
    assert_eq!(PublishDoneStatusCode::from_u64(0x5), Some(PublishDoneStatusCode::TooFarBehind));
    assert_eq!(PublishDoneStatusCode::from_u64(0x6), Some(PublishDoneStatusCode::Expired));

    // 0x7 is assigned only in the stream reset registry.
    assert_eq!(StreamResetErrorCode::from_u64(0x7), Some(StreamResetErrorCode::ExpiredAuthToken));
    assert_eq!(SessionErrorCode::from_u64(0x7), None);
    assert_eq!(RequestErrorCode::from_u64(0x7), None);
    assert_eq!(PublishDoneStatusCode::from_u64(0x7), None);

    // The high REQUEST_ERROR block exists in no other registry.
    for code in [0x20u64, 0x30, 0x31, 0x32, 0x33, 0x34] {
        assert!(RequestErrorCode::from_u64(code).is_some());
        assert_eq!(SessionErrorCode::from_u64(code), None);
        assert_eq!(PublishDoneStatusCode::from_u64(code), None);
        assert_eq!(StreamResetErrorCode::from_u64(code), None);
    }
}

/// `message.rs` decodes the trailing Redirect structure by comparing the wire
/// value against its own constants, so those constants and these variants are
/// two independent statements of the same code point. Pin them together: if one
/// side is edited alone, the decoder's framing decision and the enum's meaning
/// part company without any compile error.
#[test]
fn message_module_constants_agree_with_the_registry() {
    assert_eq!(
        RequestErrorCode::Redirect.as_u64(),
        request_error_codes::REDIRECT,
        "REDIRECT selects whether a REQUEST_ERROR carries a Redirect structure"
    );
    assert_eq!(
        RequestErrorCode::UnsupportedExtension.as_u64(),
        request_error_codes::UNSUPPORTED_EXTENSION
    );
    assert_eq!(PublishDoneStatusCode::TooFarBehind.as_u64(), publish_done_codes::TOO_FAR_BEHIND);
    assert_eq!(PublishDoneStatusCode::Expired.as_u64(), publish_done_codes::EXPIRED);
}

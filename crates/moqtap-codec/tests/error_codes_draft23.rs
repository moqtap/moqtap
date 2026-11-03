#![cfg(feature = "draft23")]
//! Draft-23 error and status code registries, checked against the draft.
//!
//! The code points asserted here are the `Name`/`Code`/`Specification` tables
//! in draft-23's IANA Considerations: Tables 20 through 23,
//! draft-23 Section 16.12.1 (Session Termination Error Codes),
//! draft-23 Section 16.12.2 (REQUEST_ERROR Codes), draft-23 Section 16.12.3
//! (PUBLISH_DONE Codes) and draft-23 Section 16.12.4 (Stream Reset Error
//! Codes), and Table 19, draft-23 Section 16.11 (Error Detail Types). Each
//! registry is pinned as a full list.
//!
//! Every table also carries a `0x7f * N + 0x9D` row reserved for greasing
//! (Section 13), which `from_u64` answers `None` for.

use moqtap_codec::draft23::error_codes::{
    ErrorDetailType, PublishDoneStatusCode, RequestErrorCode, SessionErrorCategory,
    SessionErrorCode, StreamResetErrorCode,
};

/// Members of the reserved greasing range `0x7f * N + 0x9D`, including the six
/// Section 12.2 places inside 0x200-0x4FF.
const GREASING: [u64; 9] =
    [0x9D, 0x7f + 0x9D, 2 * 0x7f + 0x9D, 0x21A, 0x299, 0x318, 0x397, 0x416, 0x495];

/// For one registry: assert the exact set of assigned code points, that
/// `from_u64` and `as_u64` invert each other, and that every unassigned code
/// point up to `ceiling` decodes to `None`.
macro_rules! check_registry {
    ($name:literal, $ty:ty, $ceiling:expr, [$($code:expr => $variant:expr),+ $(,)?]) => {{
        let assigned: &[(u64, $ty)] = &[$(($code, $variant)),+];
        for (code, variant) in assigned {
            assert_eq!(variant.as_u64(), *code, "{}: as_u64 of {:?}", $name, variant);
            assert_eq!(<$ty>::from_u64(*code), Some(*variant), "{}: {:#x}", $name, code);
        }
        let codes: Vec<u64> = assigned.iter().map(|(c, _)| *c).collect();
        assert_eq!(
            <$ty>::ALL.iter().map(|v| v.as_u64()).collect::<Vec<_>>(),
            codes,
            "{}: ALL is not the registry in wire order",
            $name
        );
        for c in 0u64..=$ceiling {
            if !codes.contains(&c) {
                assert!(<$ty>::from_u64(c).is_none(), "{}: {:#x} is unassigned", $name, c);
            }
        }
        for c in GREASING.into_iter().chain([u32::MAX as u64, u64::MAX]) {
            assert!(<$ty>::from_u64(c).is_none(), "{}: {:#x} decoded", $name, c);
        }
        assigned.len()
    }};
}

/// Section 16.12.1, Table 20. 0x6 is MALFORMED_KEY_VALUE; 0x200-0x203,
/// 0x300-0x306 and 0x400-0x401 are new.
#[test]
fn session_error_codes_match_draft23_section_16_12_1() {
    let n = check_registry!("SessionErrorCode", SessionErrorCode, 0x500, [
        0x0 => SessionErrorCode::NoError,
        0x1 => SessionErrorCode::InternalError,
        0x2 => SessionErrorCode::Unauthorized,
        0x3 => SessionErrorCode::ProtocolViolation,
        0x4 => SessionErrorCode::InvalidRequestId,
        0x5 => SessionErrorCode::DuplicateTrackAlias,
        0x6 => SessionErrorCode::MalformedKeyValue,
        0x8 => SessionErrorCode::InvalidPath,
        0x9 => SessionErrorCode::MalformedPath,
        0x10 => SessionErrorCode::GoawayTimeout,
        0x11 => SessionErrorCode::ControlMessageTimeout,
        0x12 => SessionErrorCode::DataStreamTimeout,
        0x13 => SessionErrorCode::AuthTokenCacheOverflow,
        0x14 => SessionErrorCode::DuplicateAuthTokenAlias,
        0x16 => SessionErrorCode::MalformedAuthToken,
        0x17 => SessionErrorCode::UnknownAuthTokenAlias,
        0x18 => SessionErrorCode::ExpiredAuthToken,
        0x19 => SessionErrorCode::InvalidAuthority,
        0x1A => SessionErrorCode::MalformedAuthority,
        0x1B => SessionErrorCode::TooManyRequestUpdates,
        0x200 => SessionErrorCode::InvalidStreamHeader,
        0x201 => SessionErrorCode::MalformedObject,
        0x202 => SessionErrorCode::InvalidObjectStatus,
        0x203 => SessionErrorCode::TruncatedObject,
        0x300 => SessionErrorCode::MalformedMessage,
        0x301 => SessionErrorCode::InvalidField,
        0x302 => SessionErrorCode::InvalidTrackNamespace,
        0x303 => SessionErrorCode::UnexpectedMessage,
        0x304 => SessionErrorCode::RoleViolation,
        0x305 => SessionErrorCode::InvalidParameter,
        0x306 => SessionErrorCode::ClosedControlStream,
        0x400 => SessionErrorCode::DeltaEncodingOverflow,
        0x401 => SessionErrorCode::FieldLengthExceeded,
    ]);
    assert_eq!(n, 33);
}

/// Section 12.2: "0x200-0x2FF: Data stream and datagram errors",
/// "0x300-0x3FF: Control stream and control message errors", "0x400-0x4FF:
/// Errors that can occur in either", and "The values reserved for greasing
/// (Section 13) that fall within these ranges are not assigned to a category."
#[test]
fn the_new_session_codes_carry_their_category() {
    assert_eq!(
        SessionErrorCode::TruncatedObject.category(),
        Some(SessionErrorCategory::DataStream)
    );
    assert_eq!(
        SessionErrorCode::ClosedControlStream.category(),
        Some(SessionErrorCategory::ControlStream)
    );
    assert_eq!(
        SessionErrorCode::FieldLengthExceeded.category(),
        Some(SessionErrorCategory::Either)
    );
    assert_eq!(SessionErrorCode::ProtocolViolation.category(), None);
    assert_eq!(SessionErrorCategory::of(0x2FF), Some(SessionErrorCategory::DataStream));
    assert_eq!(SessionErrorCategory::of(0x500), None);
    for grease in [0x21A, 0x299, 0x318, 0x397, 0x416, 0x495] {
        assert_eq!(SessionErrorCategory::of(grease), None, "{grease:#x}");
    }
}

/// Section 16.12.2, Table 21. UNAVAILABLE 0xA is new; 0x30 is unassigned.
#[test]
fn request_error_codes_match_draft23_section_16_12_2() {
    let n = check_registry!("RequestErrorCode", RequestErrorCode, 0x100, [
        0x0 => RequestErrorCode::InternalError,
        0x1 => RequestErrorCode::Unauthorized,
        0x2 => RequestErrorCode::Timeout,
        0x3 => RequestErrorCode::NotSupported,
        0x4 => RequestErrorCode::MalformedAuthToken,
        0x5 => RequestErrorCode::ExpiredAuthToken,
        0x6 => RequestErrorCode::GoingAway,
        0x9 => RequestErrorCode::ExcessiveLoad,
        0xA => RequestErrorCode::Unavailable,
        0x10 => RequestErrorCode::DoesNotExist,
        0x11 => RequestErrorCode::InvalidRange,
        0x12 => RequestErrorCode::MalformedTrack,
        0x20 => RequestErrorCode::Uninterested,
        0x31 => RequestErrorCode::NamespaceTooLarge,
        0x33 => RequestErrorCode::UnsupportedExtension,
        0x34 => RequestErrorCode::Redirect,
        0x35 => RequestErrorCode::ConflictingFilters,
        0x36 => RequestErrorCode::InvalidFilter,
    ]);
    assert_eq!(n, 18);
    assert!(RequestErrorCode::from_u64(0x30).is_none());
}

/// Section 16.12.3, Table 22. EXPIRED_AUTH_TOKEN 0x7 is new; 0x3 is
/// unassigned.
#[test]
fn publish_done_status_codes_match_draft23_section_16_12_3() {
    let n = check_registry!("PublishDoneStatusCode", PublishDoneStatusCode, 0x100, [
        0x0 => PublishDoneStatusCode::InternalError,
        0x1 => PublishDoneStatusCode::Unauthorized,
        0x2 => PublishDoneStatusCode::TrackEnded,
        0x4 => PublishDoneStatusCode::GoingAway,
        0x5 => PublishDoneStatusCode::TooFarBehind,
        0x6 => PublishDoneStatusCode::Expired,
        0x7 => PublishDoneStatusCode::ExpiredAuthToken,
        0x8 => PublishDoneStatusCode::UpdateFailed,
        0x9 => PublishDoneStatusCode::ExcessiveLoad,
        0x12 => PublishDoneStatusCode::MalformedTrack,
    ]);
    assert_eq!(n, 10);
    assert!(PublishDoneStatusCode::from_u64(0x3).is_none());
}

/// Section 16.12.4, Table 23. 0x6 is unassigned.
#[test]
fn stream_reset_error_codes_match_draft23_section_16_12_4() {
    let n = check_registry!("StreamResetErrorCode", StreamResetErrorCode, 0x100, [
        0x0 => StreamResetErrorCode::InternalError,
        0x1 => StreamResetErrorCode::Cancelled,
        0x2 => StreamResetErrorCode::DeliveryTimeout,
        0x3 => StreamResetErrorCode::SessionClosed,
        0x4 => StreamResetErrorCode::GoingAway,
        0x5 => StreamResetErrorCode::TooFarBehind,
        0x7 => StreamResetErrorCode::ExpiredAuthToken,
        0x9 => StreamResetErrorCode::ExcessiveLoad,
        0x12 => StreamResetErrorCode::MalformedTrack,
    ]);
    assert_eq!(n, 9);
    assert!(StreamResetErrorCode::from_u64(0x6).is_none());
}

/// Section 16.11, Table 19.
#[test]
fn error_detail_types_match_draft23_section_16_11() {
    let n = check_registry!("ErrorDetailType", ErrorDetailType, 0x100, [
        0x01 => ErrorDetailType::Redirect,
        0x02 => ErrorDetailType::UnsupportedProperty,
    ]);
    assert_eq!(n, 2);
}

/// The registries are separate code spaces: EXPIRED_AUTH_TOKEN is 0x18, 0x5,
/// 0x7 and 0x7 in the four.
#[test]
fn registries_are_independent_code_spaces() {
    assert_eq!(SessionErrorCode::ExpiredAuthToken.as_u64(), 0x18);
    assert_eq!(RequestErrorCode::ExpiredAuthToken.as_u64(), 0x5);
    assert_eq!(PublishDoneStatusCode::ExpiredAuthToken.as_u64(), 0x7);
    assert_eq!(StreamResetErrorCode::ExpiredAuthToken.as_u64(), 0x7);
    assert_eq!(SessionErrorCode::InvalidField.as_u64(), 0x301);
}

#![cfg(feature = "draft19")]
//! Draft-19 error and status code registries, checked against the draft.
//!
//! The code points asserted here were read out of the `Name`/`Code`/
//! `Specification` tables in the IANA Considerations of draft-19: tables 18
//! through 21, sections 15.11.1 (Session Termination Error Codes), 15.11.2
//! (REQUEST_ERROR Codes), 15.11.3 (PUBLISH_DONE Codes) and 15.11.4 (Stream
//! Reset Error Codes). Each registry is pinned as a full list rather than
//! spot-checked, so that a variant added, dropped or renumbered later fails
//! here instead of silently changing what the codec puts on the wire.
//!
//! Every one of the four tables also carries a `0x7f * N + 0x9D` row reserved
//! for greasing (Section 14). That is a range, not an assignment, so no variant
//! corresponds to it and `from_u64` must answer `None` for those values like it
//! does for any other code the draft leaves unassigned.

use moqtap_codec::draft19::error_codes::{
    PublishDoneStatusCode, RequestErrorCode, SessionErrorCode, StreamResetErrorCode,
};

/// The first few members of the reserved greasing range `0x7f * N + 0x9D`.
const GREASING: [u64; 6] = [
    0x9D,        // N = 0
    0x7f + 0x9D, // N = 1
    2 * 0x7f + 0x9D,
    3 * 0x7f + 0x9D,
    100 * 0x7f + 0x9D,
    1_000_000 * 0x7f + 0x9D,
];

/// For one registry: assert the exact set of assigned code points, that
/// `from_u64` and `as_u64` invert each other in both directions, and that every
/// unassigned code point below a generous ceiling decodes to `None`.
macro_rules! check_registry {
    ($name:literal, $ty:ty, [$($code:expr => $variant:expr),+ $(,)?]) => {{
        let assigned: &[(u64, $ty)] = &[$(($code, $variant)),+];

        // Declared discriminant matches the code point the draft assigns.
        for (code, variant) in assigned {
            assert_eq!(
                variant.as_u64(),
                *code,
                "{}: as_u64 of {:?} is not {:#x}",
                $name,
                variant,
                code
            );
        }

        // Round trip, value first: from_u64(as_u64(v)) == Some(v).
        for (_, variant) in assigned {
            assert_eq!(
                <$ty>::from_u64(variant.as_u64()),
                Some(*variant),
                "{}: {:?} did not survive the as_u64/from_u64 round trip",
                $name,
                variant
            );
        }

        // Round trip, code first: as_u64(from_u64(c)) == c.
        for (code, variant) in assigned {
            let decoded = <$ty>::from_u64(*code)
                .unwrap_or_else(|| panic!("{}: {:#x} should decode", $name, code));
            assert_eq!(decoded, *variant, "{}: {:#x} decoded to the wrong variant", $name, code);
            assert_eq!(decoded.as_u64(), *code, "{}: {:#x} re-encoded differently", $name, code);
        }

        // No two variants share a code point.
        let mut codes: Vec<u64> = assigned.iter().map(|(c, _)| *c).collect();
        codes.sort_unstable();
        let len_before = codes.len();
        codes.dedup();
        assert_eq!(len_before, codes.len(), "{}: duplicate code point", $name);

        // Everything the draft does not assign, up to 0x40, must be None. This
        // is what catches a variant quietly numbered into a gap. 0x40 clears the
        // highest code point any draft-19 registry uses (REQUEST_ERROR 0x36).
        for c in 0u64..=0x40 {
            if codes.binary_search(&c).is_ok() {
                continue;
            }
            assert!(
                <$ty>::from_u64(c).is_none(),
                "{}: {:#x} is unassigned in draft-19 but decoded to {:?}",
                $name,
                c,
                <$ty>::from_u64(c)
            );
        }

        // The reserved greasing range is not an assignment and must not decode.
        for c in GREASING {
            assert!(
                <$ty>::from_u64(c).is_none(),
                "{}: greasing code {:#x} decoded to {:?}, but the range is reserved",
                $name,
                c,
                <$ty>::from_u64(c)
            );
        }

        // Values a peer might plausibly send that this draft never defines,
        // including the varint ceiling. A decoder must answer None, not panic.
        for c in [0x41u64, 0xff, 0x1000, 0x3fff_ffff, u32::MAX as u64, u64::MAX] {
            assert!(
                <$ty>::from_u64(c).is_none(),
                "{}: out-of-registry code {:#x} decoded to {:?}",
                $name,
                c,
                <$ty>::from_u64(c)
            );
        }

        assigned.len()
    }};
}

/// Draft-19 section 15.11.1, table 18 (Session Termination Error Codes).
/// 21 assignments; definitions in section 3.5.
#[test]
fn session_error_codes_match_draft19_section_15_11_1() {
    let n = check_registry!("SessionErrorCode", SessionErrorCode, [
        0x0 => SessionErrorCode::NoError,
        0x1 => SessionErrorCode::InternalError,
        0x2 => SessionErrorCode::Unauthorized,
        0x3 => SessionErrorCode::ProtocolViolation,
        0x4 => SessionErrorCode::InvalidRequestId,
        0x5 => SessionErrorCode::DuplicateTrackAlias,
        0x6 => SessionErrorCode::KeyValueFormattingError,
        0x8 => SessionErrorCode::InvalidPath,
        0x9 => SessionErrorCode::MalformedPath,
        0x10 => SessionErrorCode::GoawayTimeout,
        0x11 => SessionErrorCode::ControlMessageTimeout,
        0x12 => SessionErrorCode::DataStreamTimeout,
        0x13 => SessionErrorCode::AuthTokenCacheOverflow,
        0x14 => SessionErrorCode::DuplicateAuthTokenAlias,
        0x15 => SessionErrorCode::VersionNegotiationFailed,
        0x16 => SessionErrorCode::MalformedAuthToken,
        0x17 => SessionErrorCode::UnknownAuthTokenAlias,
        0x18 => SessionErrorCode::ExpiredAuthToken,
        0x19 => SessionErrorCode::InvalidAuthority,
        0x1A => SessionErrorCode::MalformedAuthority,
        0x1B => SessionErrorCode::TooManyRequestUpdates,
    ]);
    assert_eq!(n, 21);

    // Draft-14 assigned TOO_MANY_REQUESTS at 0x7. Draft-19 does not assign 0x7
    // at all, and closing the hole up would renumber everything after it.
    assert!(SessionErrorCode::from_u64(0x7).is_none());

    // The 0xA..=0xF hole is the easiest place for a transcription slip to hide,
    // because 0x10 reads like "ten" if the hex prefix is dropped.
    for c in 0xA..=0xF {
        assert!(SessionErrorCode::from_u64(c).is_none(), "{c:#x}");
    }
    assert_eq!(SessionErrorCode::GoawayTimeout.as_u64(), 16);
    assert_eq!(SessionErrorCode::MalformedAuthority.as_u64(), 26);
    assert_eq!(SessionErrorCode::TooManyRequestUpdates.as_u64(), 27);
}

/// Draft-19 section 15.11.2, table 19 (REQUEST_ERROR Codes).
/// 19 assignments; definitions in section 10.6.2.
#[test]
fn request_error_codes_match_draft19_section_15_11_2() {
    let n = check_registry!("RequestErrorCode", RequestErrorCode, [
        0x0 => RequestErrorCode::InternalError,
        0x1 => RequestErrorCode::Unauthorized,
        0x2 => RequestErrorCode::Timeout,
        0x3 => RequestErrorCode::NotSupported,
        0x4 => RequestErrorCode::MalformedAuthToken,
        0x5 => RequestErrorCode::ExpiredAuthToken,
        0x6 => RequestErrorCode::GoingAway,
        0x9 => RequestErrorCode::ExcessiveLoad,
        0x10 => RequestErrorCode::DoesNotExist,
        0x11 => RequestErrorCode::InvalidRange,
        0x12 => RequestErrorCode::MalformedTrack,
        0x20 => RequestErrorCode::Uninterested,
        0x30 => RequestErrorCode::PrefixOverlap,
        0x31 => RequestErrorCode::NamespaceTooLarge,
        0x32 => RequestErrorCode::InvalidJoiningRequestId,
        0x33 => RequestErrorCode::UnsupportedExtension,
        0x34 => RequestErrorCode::Redirect,
        0x35 => RequestErrorCode::ConflictingFilters,
        0x36 => RequestErrorCode::InvalidFilter,
    ]);
    assert_eq!(n, 19);

    // Section 10.6.2 lists these codes in a different order from table 19 and
    // gives no numbers at all, so the table is the only binding of name to
    // value. Walking the prose list and numbering it positionally would put
    // UNSUPPORTED_EXTENSION at 0x10 and DOES_NOT_EXIST at 0x33; pin the pairs
    // the prose order would most easily corrupt.
    assert_eq!(RequestErrorCode::DoesNotExist.as_u64(), 0x10);
    assert_eq!(RequestErrorCode::UnsupportedExtension.as_u64(), 0x33);
    assert_eq!(RequestErrorCode::Redirect.as_u64(), 0x34);
    assert_eq!(RequestErrorCode::ConflictingFilters.as_u64(), 0x35);
    assert_eq!(RequestErrorCode::InvalidFilter.as_u64(), 0x36);

    // 0x7 and 0x8 are unassigned here, though PUBLISH_DONE assigns 0x8.
    assert!(RequestErrorCode::from_u64(0x7).is_none());
    assert!(RequestErrorCode::from_u64(0x8).is_none());
}

/// Draft-19 section 15.11.3, table 20 (PUBLISH_DONE Codes).
/// 10 assignments; definitions in section 10.11.
#[test]
fn publish_done_status_codes_match_draft19_section_15_11_3() {
    let n = check_registry!("PublishDoneStatusCode", PublishDoneStatusCode, [
        0x0 => PublishDoneStatusCode::InternalError,
        0x1 => PublishDoneStatusCode::Unauthorized,
        0x2 => PublishDoneStatusCode::TrackEnded,
        0x3 => PublishDoneStatusCode::SubscriptionEnded,
        0x4 => PublishDoneStatusCode::GoingAway,
        0x5 => PublishDoneStatusCode::TooFarBehind,
        0x6 => PublishDoneStatusCode::Expired,
        0x8 => PublishDoneStatusCode::UpdateFailed,
        0x9 => PublishDoneStatusCode::ExcessiveLoad,
        0x12 => PublishDoneStatusCode::MalformedTrack,
    ]);
    assert_eq!(n, 10);

    // Section 10.11 prints MALFORMED_TRACK (0x12) between EXPIRED (0x6) and
    // UPDATE_FAILED (0x8), out of code order. Table 20 is in code order and is
    // the one followed here.
    assert_eq!(PublishDoneStatusCode::MalformedTrack.as_u64(), 0x12);
    assert_eq!(PublishDoneStatusCode::UpdateFailed.as_u64(), 0x8);
    assert!(PublishDoneStatusCode::from_u64(0x7).is_none());
}

/// Draft-19 section 15.11.4, table 21 (Stream Reset Error Codes).
/// 10 assignments; definitions in section 3.3.4.
#[test]
fn stream_reset_error_codes_match_draft19_section_15_11_4() {
    let n = check_registry!("StreamResetErrorCode", StreamResetErrorCode, [
        0x0 => StreamResetErrorCode::InternalError,
        0x1 => StreamResetErrorCode::Cancelled,
        0x2 => StreamResetErrorCode::DeliveryTimeout,
        0x3 => StreamResetErrorCode::SessionClosed,
        0x4 => StreamResetErrorCode::GoingAway,
        0x5 => StreamResetErrorCode::TooFarBehind,
        0x6 => StreamResetErrorCode::UnknownObjectStatus,
        0x7 => StreamResetErrorCode::ExpiredAuthToken,
        0x9 => StreamResetErrorCode::ExcessiveLoad,
        0x12 => StreamResetErrorCode::MalformedTrack,
    ]);
    assert_eq!(n, 10);

    // This registry is the only one of the four that assigns 0x7, and the only
    // one that leaves 0x8 unassigned.
    assert_eq!(StreamResetErrorCode::from_u64(0x7), Some(StreamResetErrorCode::ExpiredAuthToken));
    assert!(StreamResetErrorCode::from_u64(0x8).is_none());
}

/// The four registries are separate code spaces. The same symbolic name takes
/// different values in different registries, and the same value means different
/// things, so nothing here may be collapsed into a shared enum or converted by
/// passing a raw `u64` from one registry's decoder to another's.
#[test]
fn registries_are_independent_code_spaces() {
    // EXPIRED_AUTH_TOKEN: three registries, three different code points.
    assert_eq!(SessionErrorCode::ExpiredAuthToken.as_u64(), 0x18);
    assert_eq!(RequestErrorCode::ExpiredAuthToken.as_u64(), 0x5);
    assert_eq!(StreamResetErrorCode::ExpiredAuthToken.as_u64(), 0x7);

    // MALFORMED_AUTH_TOKEN differs between the session and request registries.
    assert_eq!(SessionErrorCode::MalformedAuthToken.as_u64(), 0x16);
    assert_eq!(RequestErrorCode::MalformedAuthToken.as_u64(), 0x4);

    // 0x2 is UNAUTHORIZED in the session registry but TIMEOUT in the request
    // registry and TRACK_ENDED in PUBLISH_DONE.
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(RequestErrorCode::from_u64(0x2), Some(RequestErrorCode::Timeout));
    assert_eq!(PublishDoneStatusCode::from_u64(0x2), Some(PublishDoneStatusCode::TrackEnded));

    // Where the draft does agree, it should keep agreeing: MALFORMED_TRACK is
    // 0x12 in all three registries that define it, and EXCESSIVE_LOAD is 0x9.
    assert_eq!(RequestErrorCode::MalformedTrack.as_u64(), 0x12);
    assert_eq!(PublishDoneStatusCode::MalformedTrack.as_u64(), 0x12);
    assert_eq!(StreamResetErrorCode::MalformedTrack.as_u64(), 0x12);
    assert_eq!(RequestErrorCode::ExcessiveLoad.as_u64(), 0x9);
    assert_eq!(PublishDoneStatusCode::ExcessiveLoad.as_u64(), 0x9);
    assert_eq!(StreamResetErrorCode::ExcessiveLoad.as_u64(), 0x9);
}

/// No registry decodes a value the draft reserved for greasing, and none of
/// them panics on a code from outside the registry entirely.
#[test]
fn greasing_and_unknown_codes_decode_to_none() {
    for c in GREASING.into_iter().chain([0x37u64, 0x3f, 0x40, 0x100, u64::MAX]) {
        assert!(SessionErrorCode::from_u64(c).is_none(), "{c:#x}");
        assert!(RequestErrorCode::from_u64(c).is_none(), "{c:#x}");
        assert!(PublishDoneStatusCode::from_u64(c).is_none(), "{c:#x}");
        assert!(StreamResetErrorCode::from_u64(c).is_none(), "{c:#x}");
    }
}

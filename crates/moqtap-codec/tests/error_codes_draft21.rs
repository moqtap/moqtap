#![cfg(feature = "draft21")]
//! Draft-21 error and status code registries, checked against the draft.
//!
//! The code points asserted here were read out of the `Name`/`Code`/
//! `Specification` tables in the IANA Considerations of draft-21: tables 18
//! through 21, sections 16.11.1 (Session Termination Error Codes), 15.11.2
//! (REQUEST_ERROR Codes), 15.11.3 (PUBLISH_DONE Codes) and 15.11.4 (Stream
//! Reset Error Codes). Each registry is pinned as a full list rather than
//! spot-checked, so that a variant added, dropped or renumbered later fails
//! here instead of silently changing what the codec puts on the wire.
//!
//! Every one of the four tables also carries a `0x7f * N + 0x9D` row reserved
//! for greasing (Section 13). That is a range, not an assignment, so no variant
//! corresponds to it and `from_u64` must answer `None` for those values like it
//! does for any other code the draft leaves unassigned.
//!
//! # The three codes draft-20 took out
//!
//! Draft-19 assigned three code points that draft-21 does not, one in each of
//! three registries, and each is now a hole rather than a renumbering:
//!
//! * `VERSION_NEGOTIATION_FAILED`, Session Termination `0x15`;
//! * `INVALID_JOINING_REQUEST_ID`, REQUEST_ERROR `0x32`;
//! * `SUBSCRIPTION_ENDED`, PUBLISH_DONE `0x3`.
//!
//! [`the_three_codes_draft21_removed_are_unassigned`] states them together,
//! because the registry lists below can only say a code is absent by not
//! mentioning it — and a removal recorded that way is indistinguishable from a
//! transcription slip. Section 13 is what makes the removal a receiver's
//! problem rather than a decoder's: an unknown REQUEST_ERROR or PUBLISH_DONE
//! code "MUST be treated as equivalent to INTERNAL_ERROR for that context" and
//! MUST NOT close the session, so `from_u64` answering `None` is the whole of
//! what this crate does about it. Nothing in the message decoder refuses such a
//! frame.

use moqtap_codec::draft21::error_codes::{
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
        // highest code point any draft-21 registry uses (REQUEST_ERROR 0x36).
        for c in 0u64..=0x40 {
            if codes.binary_search(&c).is_ok() {
                continue;
            }
            assert!(
                <$ty>::from_u64(c).is_none(),
                "{}: {:#x} is unassigned in draft-21 but decoded to {:?}",
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

/// Draft-21 section 16.11.1, table 18 (Session Termination Error Codes).
/// 20 assignments; definitions in section 6.6. Draft-19 had 21: `0x15`
/// `VERSION_NEGOTIATION_FAILED` is gone.
#[test]
fn session_error_codes_match_draft21_section_15_11_1() {
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
        0x16 => SessionErrorCode::MalformedAuthToken,
        0x17 => SessionErrorCode::UnknownAuthTokenAlias,
        0x18 => SessionErrorCode::ExpiredAuthToken,
        0x19 => SessionErrorCode::InvalidAuthority,
        0x1A => SessionErrorCode::MalformedAuthority,
        0x1B => SessionErrorCode::TooManyRequestUpdates,
    ]);
    assert_eq!(n, 20);

    // Draft-14 assigned TOO_MANY_REQUESTS at 0x7. Draft-21 does not assign 0x7
    // at all, and closing the hole up would renumber everything after it.
    assert!(SessionErrorCode::from_u64(0x7).is_none());

    // 0x15 is draft-20's own hole, and it sits between two assignments rather
    // than at the end, so filling it in from a draft-19 list would be silent:
    // every neighbour still decodes.
    assert!(SessionErrorCode::from_u64(0x15).is_none());
    assert_eq!(SessionErrorCode::from_u64(0x14), Some(SessionErrorCode::DuplicateAuthTokenAlias));
    assert_eq!(SessionErrorCode::from_u64(0x16), Some(SessionErrorCode::MalformedAuthToken));

    // The 0xA..=0xF hole is the easiest place for a transcription slip to hide,
    // because 0x10 reads like "ten" if the hex prefix is dropped.
    for c in 0xA..=0xF {
        assert!(SessionErrorCode::from_u64(c).is_none(), "{c:#x}");
    }
    assert_eq!(SessionErrorCode::GoawayTimeout.as_u64(), 16);
    assert_eq!(SessionErrorCode::MalformedAuthority.as_u64(), 26);
    assert_eq!(SessionErrorCode::TooManyRequestUpdates.as_u64(), 27);
}

/// Draft-21 section 16.11.2, table 19 (REQUEST_ERROR Codes).
/// 18 assignments; definitions in section 9.4.2. Draft-19 had 19: `0x32`
/// `INVALID_JOINING_REQUEST_ID` went with the Joining Fetch.
#[test]
fn request_error_codes_match_draft21_section_15_11_2() {
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
        0x33 => RequestErrorCode::UnsupportedExtension,
        0x34 => RequestErrorCode::Redirect,
        0x35 => RequestErrorCode::ConflictingFilters,
        0x36 => RequestErrorCode::InvalidFilter,
    ]);
    assert_eq!(n, 18);

    // 0x32 is draft-21's hole here, and it sits between two assignments.
    assert!(RequestErrorCode::from_u64(0x32).is_none());
    assert_eq!(RequestErrorCode::from_u64(0x31), Some(RequestErrorCode::NamespaceTooLarge));
    assert_eq!(RequestErrorCode::from_u64(0x33), Some(RequestErrorCode::UnsupportedExtension));

    // Section 9.4.2 lists these codes in a different order from table 19 and
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

/// Draft-21 section 16.11.3, table 20 (PUBLISH_DONE Codes).
/// 9 assignments; definitions in section 9.9 — draft-19's 10.11, renumbered
/// because PUBLISH_STATE_NOTIFY took 10.10. Draft-19 had 10: `0x3`
/// `SUBSCRIPTION_ENDED` is gone, and the behaviour went with it (Section 3.3.1:
/// "A publisher does not end a subscription solely because the Largest Object
/// advances past the end of the current Location Filter").
#[test]
fn publish_done_status_codes_match_draft21_section_15_11_3() {
    let n = check_registry!("PublishDoneStatusCode", PublishDoneStatusCode, [
        0x0 => PublishDoneStatusCode::InternalError,
        0x1 => PublishDoneStatusCode::Unauthorized,
        0x2 => PublishDoneStatusCode::TrackEnded,
        0x4 => PublishDoneStatusCode::GoingAway,
        0x5 => PublishDoneStatusCode::TooFarBehind,
        0x6 => PublishDoneStatusCode::Expired,
        0x8 => PublishDoneStatusCode::UpdateFailed,
        0x9 => PublishDoneStatusCode::ExcessiveLoad,
        0x12 => PublishDoneStatusCode::MalformedTrack,
    ]);
    assert_eq!(n, 9);

    // Section 9.9 prints MALFORMED_TRACK (0x12) between EXPIRED (0x6) and
    // UPDATE_FAILED (0x8), out of code order. Table 20 is in code order and is
    // the one followed here.
    assert_eq!(PublishDoneStatusCode::MalformedTrack.as_u64(), 0x12);
    assert_eq!(PublishDoneStatusCode::UpdateFailed.as_u64(), 0x8);
    assert!(PublishDoneStatusCode::from_u64(0x7).is_none());

    // 0x3 is draft-21's hole, between TRACK_ENDED and GOING_AWAY.
    assert!(PublishDoneStatusCode::from_u64(0x3).is_none());
    assert_eq!(PublishDoneStatusCode::from_u64(0x2), Some(PublishDoneStatusCode::TrackEnded));
    assert_eq!(PublishDoneStatusCode::from_u64(0x4), Some(PublishDoneStatusCode::GoingAway));
}

/// Draft-21 section 16.11.4, table 21 (Stream Reset Error Codes).
/// 10 assignments; definitions in section 12.5. The one registry of the four
/// draft-21 left alone.
#[test]
fn stream_reset_error_codes_match_draft21_section_15_11_4() {
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

/// The three code points draft-19 assigned and draft-21 does not.
///
/// Written out together because the registry lists above can only record a
/// removal by omission, and an omission reads the same as a transcription slip.
/// Each is also a hole *between* two assignments rather than at the end of one
/// registry, so a list copied forward from draft-19 would keep decoding it with
/// every neighbour still correct.
///
/// # What the removals mean for a receiver
///
/// Nothing here refuses a frame carrying one. Draft-21 Section 13: "Receipt of
/// an unknown error code in any error context (Session Termination,
/// REQUEST_ERROR, PUBLISH_DONE, or Data Stream Reset) MUST be treated as
/// equivalent to INTERNAL_ERROR for that context. An endpoint MUST NOT close
/// the session because it received an unknown error code in a REQUEST_ERROR or
/// PUBLISH_DONE." So `from_u64` answering `None` is exactly the required
/// behaviour, and the message decoder carries the raw code up so a caller can
/// apply the INTERNAL_ERROR reading itself.
///
/// # Ablation
///
/// Restoring `SubscriptionEnded = 0x3` to `PublishDoneStatusCode`, in the enum
/// and in `from_u64` together:
///
/// ```text
/// PUBLISH_DONE 0x3 (draft-19 SUBSCRIPTION_ENDED) is unassigned in draft-21
/// and decoded to Some(SubscriptionEnded)
/// ```
#[test]
fn the_three_codes_draft21_removed_are_unassigned() {
    assert!(
        SessionErrorCode::from_u64(0x15).is_none(),
        "session 0x15 (draft-19 VERSION_NEGOTIATION_FAILED) is unassigned in draft-21 and \
         decoded to {:?}",
        SessionErrorCode::from_u64(0x15)
    );
    assert!(
        RequestErrorCode::from_u64(0x32).is_none(),
        "REQUEST_ERROR 0x32 (draft-19 INVALID_JOINING_REQUEST_ID) is unassigned in draft-21 \
         and decoded to {:?}",
        RequestErrorCode::from_u64(0x32)
    );
    assert!(
        PublishDoneStatusCode::from_u64(0x3).is_none(),
        "PUBLISH_DONE 0x3 (draft-19 SUBSCRIPTION_ENDED) is unassigned in draft-21 and \
         decoded to {:?}",
        PublishDoneStatusCode::from_u64(0x3)
    );

    // The removals are holes, not renumberings: every other code point in the
    // three registries kept its value, which is the half a bare "0x3 is gone"
    // assertion cannot state.
    assert_eq!(SessionErrorCode::ALL.len(), 20);
    assert_eq!(RequestErrorCode::ALL.len(), 18);
    assert_eq!(PublishDoneStatusCode::ALL.len(), 9);
    assert_eq!(StreamResetErrorCode::ALL.len(), 10);
}

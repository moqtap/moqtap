#![cfg(feature = "draft11")]
//! Draft-11 error and status code registries, checked against the draft.
//!
//! The code points asserted here were read out of the `Code`/`Reason` tables in
//! draft-11 sections 3.4, 8.9, 8.12, 8.15, 8.21, 8.26 and 9.4.3, and out of the
//! prose list in section 8.18. Each registry is pinned as a full list rather
//! than spot-checked, so that a variant added, dropped or renumbered later
//! fails here instead of silently changing what the codec puts on the wire.

use moqtap_codec::draft11::error_codes::{
    AnnounceErrorCode, FetchErrorCode, SessionErrorCode, StreamResetErrorCode,
    SubscribeAnnouncesErrorCode, SubscribeDoneStatusCode, SubscribeErrorCode, TrackStatusCode,
};

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
        // is what catches a variant quietly numbered into a gap.
        for c in 0u64..=0x40 {
            if codes.binary_search(&c).is_ok() {
                continue;
            }
            assert!(
                <$ty>::from_u64(c).is_none(),
                "{}: {:#x} is unassigned in draft-11 but decoded to {:?}",
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

/// Draft-11 section 3.4 (Termination). 16 rows; 0xA through 0xF unassigned.
#[test]
fn session_error_codes_match_draft11_section_3_4() {
    let n = check_registry!("SessionErrorCode", SessionErrorCode, [
        0x0 => SessionErrorCode::NoError,
        0x1 => SessionErrorCode::InternalError,
        0x2 => SessionErrorCode::Unauthorized,
        0x3 => SessionErrorCode::ProtocolViolation,
        0x4 => SessionErrorCode::InvalidRequestId,
        0x5 => SessionErrorCode::DuplicateTrackAlias,
        0x6 => SessionErrorCode::KeyValueFormattingError,
        0x7 => SessionErrorCode::TooManyRequests,
        0x8 => SessionErrorCode::InvalidPath,
        0x9 => SessionErrorCode::MalformedPath,
        0x10 => SessionErrorCode::GoawayTimeout,
        0x11 => SessionErrorCode::ControlMessageTimeout,
        0x12 => SessionErrorCode::DataStreamTimeout,
        0x13 => SessionErrorCode::AuthTokenCacheOverflow,
        0x14 => SessionErrorCode::DuplicateAuthTokenAlias,
        0x15 => SessionErrorCode::VersionNegotiationFailed,
    ]);
    assert_eq!(n, 16);
    // The 0xA..=0xF hole is the easiest place for a transcription slip to hide,
    // because 0x10 reads like "ten" if the hex prefix is dropped.
    for c in 0xA..=0xF {
        assert!(SessionErrorCode::from_u64(c).is_none());
    }
    assert_eq!(SessionErrorCode::GoawayTimeout.as_u64(), 16);
    assert_eq!(SessionErrorCode::VersionNegotiationFailed.as_u64(), 21);
}

/// Draft-11 section 8.9 (SUBSCRIBE_ERROR). 10 rows.
#[test]
fn subscribe_error_codes_match_draft11_section_8_9() {
    let n = check_registry!("SubscribeErrorCode", SubscribeErrorCode, [
        0x0 => SubscribeErrorCode::InternalError,
        0x1 => SubscribeErrorCode::Unauthorized,
        0x2 => SubscribeErrorCode::Timeout,
        0x3 => SubscribeErrorCode::NotSupported,
        0x4 => SubscribeErrorCode::TrackDoesNotExist,
        0x5 => SubscribeErrorCode::InvalidRange,
        0x6 => SubscribeErrorCode::RetryTrackAlias,
        0x10 => SubscribeErrorCode::MalformedAuthToken,
        0x11 => SubscribeErrorCode::UnknownAuthTokenAlias,
        0x12 => SubscribeErrorCode::ExpiredAuthToken,
    ]);
    assert_eq!(n, 10);
}

/// Draft-11 section 8.12 (SUBSCRIBE_DONE). 7 rows, contiguous from 0x0.
#[test]
fn subscribe_done_status_codes_match_draft11_section_8_12() {
    let n = check_registry!("SubscribeDoneStatusCode", SubscribeDoneStatusCode, [
        0x0 => SubscribeDoneStatusCode::InternalError,
        0x1 => SubscribeDoneStatusCode::Unauthorized,
        0x2 => SubscribeDoneStatusCode::TrackEnded,
        0x3 => SubscribeDoneStatusCode::SubscriptionEnded,
        0x4 => SubscribeDoneStatusCode::GoingAway,
        0x5 => SubscribeDoneStatusCode::Expired,
        0x6 => SubscribeDoneStatusCode::TooFarBehind,
    ]);
    assert_eq!(n, 7);
    // This registry stops at 0x6; it has no auth-token codes, unlike the
    // request-scoped error registries.
    assert!(SubscribeDoneStatusCode::from_u64(0x10).is_none());
}

/// Draft-11 section 8.15 (FETCH_ERROR). 11 rows.
#[test]
fn fetch_error_codes_match_draft11_section_8_15() {
    let n = check_registry!("FetchErrorCode", FetchErrorCode, [
        0x0 => FetchErrorCode::InternalError,
        0x1 => FetchErrorCode::Unauthorized,
        0x2 => FetchErrorCode::Timeout,
        0x3 => FetchErrorCode::NotSupported,
        0x4 => FetchErrorCode::TrackDoesNotExist,
        0x5 => FetchErrorCode::InvalidRange,
        0x6 => FetchErrorCode::NoObjects,
        0x7 => FetchErrorCode::InvalidJoiningSubscribeId,
        0x10 => FetchErrorCode::MalformedAuthToken,
        0x11 => FetchErrorCode::UnknownAuthTokenAlias,
        0x12 => FetchErrorCode::ExpiredAuthToken,
    ]);
    assert_eq!(n, 11);
}

/// Draft-11 section 8.21 (ANNOUNCE_ERROR). 8 rows. Section 8.23 reuses these
/// for the ANNOUNCE_CANCEL Error Code field.
#[test]
fn announce_error_codes_match_draft11_section_8_21() {
    let n = check_registry!("AnnounceErrorCode", AnnounceErrorCode, [
        0x0 => AnnounceErrorCode::InternalError,
        0x1 => AnnounceErrorCode::Unauthorized,
        0x2 => AnnounceErrorCode::Timeout,
        0x3 => AnnounceErrorCode::NotSupported,
        0x4 => AnnounceErrorCode::Uninterested,
        0x10 => AnnounceErrorCode::MalformedAuthToken,
        0x11 => AnnounceErrorCode::UnknownAuthTokenAlias,
        0x12 => AnnounceErrorCode::ExpiredAuthToken,
    ]);
    assert_eq!(n, 8);
    // ANNOUNCE_ERROR assigns no 0x5; SUBSCRIBE_ANNOUNCES_ERROR does. Confusing
    // the two registries is the failure this asserts against.
    assert!(AnnounceErrorCode::from_u64(0x5).is_none());
}

/// Draft-11 section 8.26 (SUBSCRIBE_ANNOUNCES_ERROR). 9 rows.
#[test]
fn subscribe_announces_error_codes_match_draft11_section_8_26() {
    let n = check_registry!(
        "SubscribeAnnouncesErrorCode",
        SubscribeAnnouncesErrorCode,
        [
            0x0 => SubscribeAnnouncesErrorCode::InternalError,
            0x1 => SubscribeAnnouncesErrorCode::Unauthorized,
            0x2 => SubscribeAnnouncesErrorCode::Timeout,
            0x3 => SubscribeAnnouncesErrorCode::NotSupported,
            0x4 => SubscribeAnnouncesErrorCode::NamespacePrefixUnknown,
            0x5 => SubscribeAnnouncesErrorCode::NamespacePrefixOverlap,
            0x10 => SubscribeAnnouncesErrorCode::MalformedAuthToken,
            0x11 => SubscribeAnnouncesErrorCode::UnknownAuthTokenAlias,
            0x12 => SubscribeAnnouncesErrorCode::ExpiredAuthToken,
        ]
    );
    assert_eq!(n, 9);
}

/// Draft-11 section 8.18 (TRACK_STATUS). 5 code points, defined in prose.
#[test]
fn track_status_codes_match_draft11_section_8_18() {
    let n = check_registry!("TrackStatusCode", TrackStatusCode, [
        0x00 => TrackStatusCode::InProgress,
        0x01 => TrackStatusCode::TrackDoesNotExist,
        0x02 => TrackStatusCode::NotYetBegun,
        0x03 => TrackStatusCode::Finished,
        0x04 => TrackStatusCode::RelayStatusUnavailable,
    ]);
    assert_eq!(n, 5);
    // The draft says any other Status Code value is a malformed message, so
    // 0x05 upward must not decode.
    assert!(TrackStatusCode::from_u64(0x05).is_none());
}

/// Draft-11 section 9.4.3 (Closing Subgroup Streams). 4 rows.
#[test]
fn stream_reset_error_codes_match_draft11_section_9_4_3() {
    let n = check_registry!("StreamResetErrorCode", StreamResetErrorCode, [
        0x0 => StreamResetErrorCode::InternalError,
        0x1 => StreamResetErrorCode::Cancelled,
        0x2 => StreamResetErrorCode::DeliveryTimeout,
        0x3 => StreamResetErrorCode::SessionClosed,
    ]);
    assert_eq!(n, 4);
}

/// The registries collide: the same code point means different things in
/// different messages. A decoder that picks the wrong registry produces a
/// plausible-looking wrong answer rather than an error, so the distinctness is
/// worth asserting directly.
#[test]
fn registries_are_not_interchangeable() {
    // 0x2
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(SubscribeErrorCode::from_u64(0x2), Some(SubscribeErrorCode::Timeout));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x2), Some(SubscribeDoneStatusCode::TrackEnded));
    assert_eq!(StreamResetErrorCode::from_u64(0x2), Some(StreamResetErrorCode::DeliveryTimeout));

    // 0x4 means five different things across five registries.
    assert_eq!(SessionErrorCode::from_u64(0x4), Some(SessionErrorCode::InvalidRequestId));
    assert_eq!(SubscribeErrorCode::from_u64(0x4), Some(SubscribeErrorCode::TrackDoesNotExist));
    assert_eq!(FetchErrorCode::from_u64(0x4), Some(FetchErrorCode::TrackDoesNotExist));
    assert_eq!(AnnounceErrorCode::from_u64(0x4), Some(AnnounceErrorCode::Uninterested));
    assert_eq!(
        SubscribeAnnouncesErrorCode::from_u64(0x4),
        Some(SubscribeAnnouncesErrorCode::NamespacePrefixUnknown)
    );

    // 0x6 likewise.
    assert_eq!(SessionErrorCode::from_u64(0x6), Some(SessionErrorCode::KeyValueFormattingError));
    assert_eq!(SubscribeErrorCode::from_u64(0x6), Some(SubscribeErrorCode::RetryTrackAlias));
    assert_eq!(FetchErrorCode::from_u64(0x6), Some(FetchErrorCode::NoObjects));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x6), Some(SubscribeDoneStatusCode::TooFarBehind));

    // FETCH_ERROR is the only request registry with 0x7.
    assert_eq!(FetchErrorCode::from_u64(0x7), Some(FetchErrorCode::InvalidJoiningSubscribeId));
    assert!(SubscribeErrorCode::from_u64(0x7).is_none());
    assert!(AnnounceErrorCode::from_u64(0x7).is_none());
    assert!(SubscribeAnnouncesErrorCode::from_u64(0x7).is_none());
}

/// The three auth-token codes are shared verbatim by the four request-scoped
/// error registries in draft-11, and by none of the others.
#[test]
fn auth_token_codes_are_shared_by_the_request_registries_only() {
    for c in [0x10u64, 0x11, 0x12] {
        assert!(SubscribeErrorCode::from_u64(c).is_some(), "{c:#x}");
        assert!(FetchErrorCode::from_u64(c).is_some(), "{c:#x}");
        assert!(AnnounceErrorCode::from_u64(c).is_some(), "{c:#x}");
        assert!(SubscribeAnnouncesErrorCode::from_u64(c).is_some(), "{c:#x}");

        assert!(SubscribeDoneStatusCode::from_u64(c).is_none(), "{c:#x}");
        assert!(StreamResetErrorCode::from_u64(c).is_none(), "{c:#x}");
        assert!(TrackStatusCode::from_u64(c).is_none(), "{c:#x}");
    }

    // 0x10..=0x12 are session codes too, but they mean something else there.
    assert_eq!(SessionErrorCode::from_u64(0x10), Some(SessionErrorCode::GoawayTimeout));
}

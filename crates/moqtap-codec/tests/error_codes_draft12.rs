#![cfg(feature = "draft12")]
//! Round-trip and rejection tests for the draft-12 code registries.
//!
//! The expected (code, variant) pairs below are written out independently of
//! `src/draft12/error_codes.rs`, transcribed from the eight `Code | Reason` tables of MoQ
//! Transport draft-12: section 3.4 Termination, 8.9 SUBSCRIBE_ERROR, 8.12 SUBSCRIBE_DONE,
//! 8.15 PUBLISH_ERROR, 8.18 FETCH_ERROR, 8.24 ANNOUNCE_ERROR, 8.29
//! SUBSCRIBE_ANNOUNCES_ERROR and 9.4.3 Closing Subgroup Streams. 19 + 8 + 8 + 5 + 12 + 7 +
//! 8 + 4 = 71 codes.
//!
//! Duplicating the table here is the point: a test that iterated a list exported by the
//! module under test would pass even if that list had a row missing. Each enum also gets an
//! exhaustive `match`, so adding a variant without adding it here fails to compile rather
//! than silently going untested.

use moqtap_codec::draft12::error_codes::{
    AnnounceErrorCode, FetchErrorCode, PublishErrorCode, SessionErrorCode, StreamResetErrorCode,
    SubscribeAnnouncesErrorCode, SubscribeDoneStatusCode, SubscribeErrorCode,
};

/// Body shared by every registry check: the listed codes map both ways, and nothing else
/// maps at all.
macro_rules! check_registry {
    ($name:literal, $ty:ty, [$(($code:expr, $variant:expr)),+ $(,)?]) => {{
        let expected: &[(u64, $ty)] = &[$(($code, $variant)),+];

        // forward: the draft's code produces the expected variant
        for &(code, variant) in expected {
            assert_eq!(
                <$ty>::from_u64(code),
                Some(variant),
                "{}: from_u64({:#x}) should be {:?}",
                $name,
                code,
                variant
            );
        }

        // backward: the variant produces the draft's code, checked separately so a
        // copy-paste in one direction cannot hide behind the other
        for &(code, variant) in expected {
            assert_eq!(
                variant.as_u64(),
                code,
                "{}: {:?}.as_u64() should be {:#x}",
                $name,
                variant,
                code
            );
        }

        // round trip, stated the way the registries are used
        for &(_, variant) in expected {
            assert_eq!(
                <$ty>::from_u64(variant.as_u64()),
                Some(variant),
                "{}: round trip failed for {:?}",
                $name,
                variant
            );
        }

        // no two variants share a code point
        for (i, &(code_a, variant_a)) in expected.iter().enumerate() {
            for &(code_b, variant_b) in &expected[i + 1..] {
                assert_ne!(
                    code_a, code_b,
                    "{}: {:?} and {:?} share code {:#x}",
                    $name, variant_a, variant_b, code_a
                );
            }
        }

        // every other code in a generous window is unassigned. 0x400 is far past the
        // largest code any of these tables assigns (0x18), so this sweeps the whole
        // assigned region plus the gaps inside it: 0xA..=0xF in the termination table and
        // 0x11 in the four request-error tables.
        for code in 0u64..=0x400 {
            let assigned = expected.iter().any(|&(c, _)| c == code);
            if !assigned {
                assert_eq!(
                    <$ty>::from_u64(code),
                    None,
                    "{}: {:#x} is not assigned by draft-12 but from_u64 accepted it",
                    $name,
                    code
                );
            }
        }

        // values a peer could plausibly send that no draft-12 table assigns
        for code in [
            0x0001_0000u64,
            0x3fff_ffff,
            0x4000_0000,
            u32::MAX as u64,
            (1u64 << 62) - 1,
            u64::MAX,
        ] {
            assert_eq!(
                <$ty>::from_u64(code),
                None,
                "{}: {:#x} should not decode",
                $name,
                code
            );
        }

        expected.len()
    }};
}

#[test]
fn session_error_code_matches_draft12_section_3_4() {
    let n = check_registry!(
        "SessionErrorCode",
        SessionErrorCode,
        [
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
        ]
    );
    assert_eq!(n, 19, "draft-12 section 3.4 assigns 19 codes");

    // the table skips 0xA through 0xF
    for code in 0xAu64..=0xF {
        assert_eq!(SessionErrorCode::from_u64(code), None);
    }
}

#[test]
fn subscribe_error_code_matches_draft12_section_8_9() {
    let n = check_registry!(
        "SubscribeErrorCode",
        SubscribeErrorCode,
        [
            (0x0, SubscribeErrorCode::InternalError),
            (0x1, SubscribeErrorCode::Unauthorized),
            (0x2, SubscribeErrorCode::Timeout),
            (0x3, SubscribeErrorCode::NotSupported),
            (0x4, SubscribeErrorCode::TrackDoesNotExist),
            (0x5, SubscribeErrorCode::InvalidRange),
            (0x10, SubscribeErrorCode::MalformedAuthToken),
            (0x12, SubscribeErrorCode::ExpiredAuthToken),
        ]
    );
    assert_eq!(n, 8, "draft-12 section 8.9 assigns 8 codes");
    assert_eq!(SubscribeErrorCode::from_u64(0x11), None, "0x11 is unassigned");
}

#[test]
fn subscribe_done_status_code_matches_draft12_section_8_12() {
    let n = check_registry!(
        "SubscribeDoneStatusCode",
        SubscribeDoneStatusCode,
        [
            (0x0, SubscribeDoneStatusCode::InternalError),
            (0x1, SubscribeDoneStatusCode::Unauthorized),
            (0x2, SubscribeDoneStatusCode::TrackEnded),
            (0x3, SubscribeDoneStatusCode::SubscriptionEnded),
            (0x4, SubscribeDoneStatusCode::GoingAway),
            (0x5, SubscribeDoneStatusCode::Expired),
            (0x6, SubscribeDoneStatusCode::TooFarBehind),
            (0x7, SubscribeDoneStatusCode::MalformedTrack),
        ]
    );
    assert_eq!(n, 8, "draft-12 section 8.12 assigns 8 codes");
}

#[test]
fn publish_error_code_matches_draft12_section_8_15() {
    let n = check_registry!(
        "PublishErrorCode",
        PublishErrorCode,
        [
            (0x0, PublishErrorCode::InternalError),
            (0x1, PublishErrorCode::Unauthorized),
            (0x2, PublishErrorCode::Timeout),
            (0x3, PublishErrorCode::NotSupported),
            (0x4, PublishErrorCode::Uninterested),
        ]
    );
    assert_eq!(n, 5, "draft-12 section 8.15 assigns 5 codes");

    // unlike the other request-error tables, PUBLISH_ERROR assigns no auth-token codes
    assert_eq!(PublishErrorCode::from_u64(0x10), None);
    assert_eq!(PublishErrorCode::from_u64(0x12), None);
}

#[test]
fn fetch_error_code_matches_draft12_section_8_18() {
    let n = check_registry!(
        "FetchErrorCode",
        FetchErrorCode,
        [
            (0x0, FetchErrorCode::InternalError),
            (0x1, FetchErrorCode::Unauthorized),
            (0x2, FetchErrorCode::Timeout),
            (0x3, FetchErrorCode::NotSupported),
            (0x4, FetchErrorCode::TrackDoesNotExist),
            (0x5, FetchErrorCode::InvalidRange),
            (0x6, FetchErrorCode::NoObjects),
            (0x7, FetchErrorCode::InvalidJoiningRequestId),
            (0x8, FetchErrorCode::UnknownStatusInRange),
            (0x9, FetchErrorCode::MalformedTrack),
            (0x10, FetchErrorCode::MalformedAuthToken),
            (0x12, FetchErrorCode::ExpiredAuthToken),
        ]
    );
    assert_eq!(n, 12, "draft-12 section 8.18 assigns 12 codes");
    assert_eq!(FetchErrorCode::from_u64(0x11), None, "0x11 is unassigned");
}

#[test]
fn announce_error_code_matches_draft12_section_8_24() {
    let n = check_registry!(
        "AnnounceErrorCode",
        AnnounceErrorCode,
        [
            (0x0, AnnounceErrorCode::InternalError),
            (0x1, AnnounceErrorCode::Unauthorized),
            (0x2, AnnounceErrorCode::Timeout),
            (0x3, AnnounceErrorCode::NotSupported),
            (0x4, AnnounceErrorCode::Uninterested),
            (0x10, AnnounceErrorCode::MalformedAuthToken),
            (0x12, AnnounceErrorCode::ExpiredAuthToken),
        ]
    );
    assert_eq!(n, 7, "draft-12 section 8.24 assigns 7 codes");
    assert_eq!(AnnounceErrorCode::from_u64(0x11), None, "0x11 is unassigned");
    assert_eq!(
        AnnounceErrorCode::from_u64(0x5),
        None,
        "ANNOUNCE_ERROR stops at 0x4; 0x5 belongs to other tables, not this one"
    );
}

#[test]
fn subscribe_announces_error_code_matches_draft12_section_8_29() {
    let n = check_registry!(
        "SubscribeAnnouncesErrorCode",
        SubscribeAnnouncesErrorCode,
        [
            (0x0, SubscribeAnnouncesErrorCode::InternalError),
            (0x1, SubscribeAnnouncesErrorCode::Unauthorized),
            (0x2, SubscribeAnnouncesErrorCode::Timeout),
            (0x3, SubscribeAnnouncesErrorCode::NotSupported),
            (0x4, SubscribeAnnouncesErrorCode::NamespacePrefixUnknown),
            (0x5, SubscribeAnnouncesErrorCode::NamespacePrefixOverlap),
            (0x10, SubscribeAnnouncesErrorCode::MalformedAuthToken),
            (0x12, SubscribeAnnouncesErrorCode::ExpiredAuthToken),
        ]
    );
    assert_eq!(n, 8, "draft-12 section 8.29 assigns 8 codes");
    assert_eq!(SubscribeAnnouncesErrorCode::from_u64(0x11), None, "0x11 is unassigned");
}

#[test]
fn stream_reset_error_code_matches_draft12_section_9_4_3() {
    let n = check_registry!(
        "StreamResetErrorCode",
        StreamResetErrorCode,
        [
            (0x0, StreamResetErrorCode::InternalError),
            (0x1, StreamResetErrorCode::Cancelled),
            (0x2, StreamResetErrorCode::DeliveryTimeout),
            (0x3, StreamResetErrorCode::SessionClosed),
        ]
    );
    assert_eq!(n, 4, "draft-12 section 9.4.3 assigns 4 codes");
    assert_eq!(StreamResetErrorCode::from_u64(0x4), None);
}

/// Exhaustive matches so that a variant added to any registry without a corresponding row
/// in the tables above is a compile error, not a silently untested variant.
///
/// The arm bodies return the code point the draft assigns, giving a third statement of the
/// mapping that is independent of both `from_u64` and `as_u64`.
#[test]
fn every_variant_is_covered_by_these_tests() {
    fn session(v: SessionErrorCode) -> u64 {
        match v {
            SessionErrorCode::NoError => 0x0,
            SessionErrorCode::InternalError => 0x1,
            SessionErrorCode::Unauthorized => 0x2,
            SessionErrorCode::ProtocolViolation => 0x3,
            SessionErrorCode::InvalidRequestId => 0x4,
            SessionErrorCode::DuplicateTrackAlias => 0x5,
            SessionErrorCode::KeyValueFormattingError => 0x6,
            SessionErrorCode::TooManyRequests => 0x7,
            SessionErrorCode::InvalidPath => 0x8,
            SessionErrorCode::MalformedPath => 0x9,
            SessionErrorCode::GoawayTimeout => 0x10,
            SessionErrorCode::ControlMessageTimeout => 0x11,
            SessionErrorCode::DataStreamTimeout => 0x12,
            SessionErrorCode::AuthTokenCacheOverflow => 0x13,
            SessionErrorCode::DuplicateAuthTokenAlias => 0x14,
            SessionErrorCode::VersionNegotiationFailed => 0x15,
            SessionErrorCode::MalformedAuthToken => 0x16,
            SessionErrorCode::UnknownAuthTokenAlias => 0x17,
            SessionErrorCode::ExpiredAuthToken => 0x18,
        }
    }
    fn subscribe(v: SubscribeErrorCode) -> u64 {
        match v {
            SubscribeErrorCode::InternalError => 0x0,
            SubscribeErrorCode::Unauthorized => 0x1,
            SubscribeErrorCode::Timeout => 0x2,
            SubscribeErrorCode::NotSupported => 0x3,
            SubscribeErrorCode::TrackDoesNotExist => 0x4,
            SubscribeErrorCode::InvalidRange => 0x5,
            SubscribeErrorCode::MalformedAuthToken => 0x10,
            SubscribeErrorCode::ExpiredAuthToken => 0x12,
        }
    }
    fn done(v: SubscribeDoneStatusCode) -> u64 {
        match v {
            SubscribeDoneStatusCode::InternalError => 0x0,
            SubscribeDoneStatusCode::Unauthorized => 0x1,
            SubscribeDoneStatusCode::TrackEnded => 0x2,
            SubscribeDoneStatusCode::SubscriptionEnded => 0x3,
            SubscribeDoneStatusCode::GoingAway => 0x4,
            SubscribeDoneStatusCode::Expired => 0x5,
            SubscribeDoneStatusCode::TooFarBehind => 0x6,
            SubscribeDoneStatusCode::MalformedTrack => 0x7,
        }
    }
    fn publish(v: PublishErrorCode) -> u64 {
        match v {
            PublishErrorCode::InternalError => 0x0,
            PublishErrorCode::Unauthorized => 0x1,
            PublishErrorCode::Timeout => 0x2,
            PublishErrorCode::NotSupported => 0x3,
            PublishErrorCode::Uninterested => 0x4,
        }
    }
    fn fetch(v: FetchErrorCode) -> u64 {
        match v {
            FetchErrorCode::InternalError => 0x0,
            FetchErrorCode::Unauthorized => 0x1,
            FetchErrorCode::Timeout => 0x2,
            FetchErrorCode::NotSupported => 0x3,
            FetchErrorCode::TrackDoesNotExist => 0x4,
            FetchErrorCode::InvalidRange => 0x5,
            FetchErrorCode::NoObjects => 0x6,
            FetchErrorCode::InvalidJoiningRequestId => 0x7,
            FetchErrorCode::UnknownStatusInRange => 0x8,
            FetchErrorCode::MalformedTrack => 0x9,
            FetchErrorCode::MalformedAuthToken => 0x10,
            FetchErrorCode::ExpiredAuthToken => 0x12,
        }
    }
    fn announce(v: AnnounceErrorCode) -> u64 {
        match v {
            AnnounceErrorCode::InternalError => 0x0,
            AnnounceErrorCode::Unauthorized => 0x1,
            AnnounceErrorCode::Timeout => 0x2,
            AnnounceErrorCode::NotSupported => 0x3,
            AnnounceErrorCode::Uninterested => 0x4,
            AnnounceErrorCode::MalformedAuthToken => 0x10,
            AnnounceErrorCode::ExpiredAuthToken => 0x12,
        }
    }
    fn subscribe_announces(v: SubscribeAnnouncesErrorCode) -> u64 {
        match v {
            SubscribeAnnouncesErrorCode::InternalError => 0x0,
            SubscribeAnnouncesErrorCode::Unauthorized => 0x1,
            SubscribeAnnouncesErrorCode::Timeout => 0x2,
            SubscribeAnnouncesErrorCode::NotSupported => 0x3,
            SubscribeAnnouncesErrorCode::NamespacePrefixUnknown => 0x4,
            SubscribeAnnouncesErrorCode::NamespacePrefixOverlap => 0x5,
            SubscribeAnnouncesErrorCode::MalformedAuthToken => 0x10,
            SubscribeAnnouncesErrorCode::ExpiredAuthToken => 0x12,
        }
    }
    fn reset(v: StreamResetErrorCode) -> u64 {
        match v {
            StreamResetErrorCode::InternalError => 0x0,
            StreamResetErrorCode::Cancelled => 0x1,
            StreamResetErrorCode::DeliveryTimeout => 0x2,
            StreamResetErrorCode::SessionClosed => 0x3,
        }
    }

    // walk every code point in range and confirm all three statements of the mapping
    // agree wherever from_u64 yields a variant
    let mut seen = 0usize;
    for code in 0u64..=0x400 {
        if let Some(v) = SessionErrorCode::from_u64(code) {
            assert_eq!(session(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = SubscribeErrorCode::from_u64(code) {
            assert_eq!(subscribe(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = SubscribeDoneStatusCode::from_u64(code) {
            assert_eq!(done(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = PublishErrorCode::from_u64(code) {
            assert_eq!(publish(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = FetchErrorCode::from_u64(code) {
            assert_eq!(fetch(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = AnnounceErrorCode::from_u64(code) {
            assert_eq!(announce(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = SubscribeAnnouncesErrorCode::from_u64(code) {
            assert_eq!(subscribe_announces(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
        if let Some(v) = StreamResetErrorCode::from_u64(code) {
            assert_eq!(reset(v), code);
            assert_eq!(v.as_u64(), code);
            seen += 1;
        }
    }

    assert_eq!(
        seen, 71,
        "the eight draft-12 tables assign 71 codes in total: 19 + 8 + 8 + 5 + 12 + 7 + 8 + 4"
    );
}

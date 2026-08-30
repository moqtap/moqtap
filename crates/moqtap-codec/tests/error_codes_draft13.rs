#![cfg(feature = "draft13")]
//! Round-trip and rejection tests for the draft-13 code registries.
//!
//! The eight tables transcribed in `draft13::error_codes` are, in the draft: Section 3.4
//! Termination (19 rows), 8.9 SUBSCRIBE_ERROR (8), 8.12 SUBSCRIBE_DONE (8), 8.15
//! PUBLISH_ERROR (5), 8.18 FETCH_ERROR (12), 8.25 ANNOUNCE_ERROR (7), 8.30
//! SUBSCRIBE_NAMESPACE_ERROR (8) and 9.4.3 Closing Subgroup Streams (4) — 71 code points.
//!
//! The arrays below restate each table's code points, read from the draft rather than from
//! the enum definitions, so a discriminant edited in one place and not the other fails here
//! rather than shipping.

use moqtap_codec::draft13::error_codes::{
    AnnounceErrorCode, FetchErrorCode, PublishErrorCode, SessionErrorCode, StreamResetErrorCode,
    SubscribeDoneStatusCode, SubscribeErrorCode, SubscribeNamespaceErrorCode,
};

/// Draft-13 Section 3.4 Termination.
const SESSION: [(SessionErrorCode, u64); 19] = [
    (SessionErrorCode::NoError, 0x0),
    (SessionErrorCode::InternalError, 0x1),
    (SessionErrorCode::Unauthorized, 0x2),
    (SessionErrorCode::ProtocolViolation, 0x3),
    (SessionErrorCode::InvalidRequestId, 0x4),
    (SessionErrorCode::DuplicateTrackAlias, 0x5),
    (SessionErrorCode::KeyValueFormattingError, 0x6),
    (SessionErrorCode::TooManyRequests, 0x7),
    (SessionErrorCode::InvalidPath, 0x8),
    (SessionErrorCode::MalformedPath, 0x9),
    (SessionErrorCode::GoawayTimeout, 0x10),
    (SessionErrorCode::ControlMessageTimeout, 0x11),
    (SessionErrorCode::DataStreamTimeout, 0x12),
    (SessionErrorCode::AuthTokenCacheOverflow, 0x13),
    (SessionErrorCode::DuplicateAuthTokenAlias, 0x14),
    (SessionErrorCode::VersionNegotiationFailed, 0x15),
    (SessionErrorCode::MalformedAuthToken, 0x16),
    (SessionErrorCode::UnknownAuthTokenAlias, 0x17),
    (SessionErrorCode::ExpiredAuthToken, 0x18),
];

/// Draft-13 Section 8.9 SUBSCRIBE_ERROR.
const SUBSCRIBE_ERROR: [(SubscribeErrorCode, u64); 8] = [
    (SubscribeErrorCode::InternalError, 0x0),
    (SubscribeErrorCode::Unauthorized, 0x1),
    (SubscribeErrorCode::Timeout, 0x2),
    (SubscribeErrorCode::NotSupported, 0x3),
    (SubscribeErrorCode::TrackDoesNotExist, 0x4),
    (SubscribeErrorCode::InvalidRange, 0x5),
    (SubscribeErrorCode::MalformedAuthToken, 0x10),
    (SubscribeErrorCode::ExpiredAuthToken, 0x12),
];

/// Draft-13 Section 8.12 SUBSCRIBE_DONE.
const SUBSCRIBE_DONE: [(SubscribeDoneStatusCode, u64); 8] = [
    (SubscribeDoneStatusCode::InternalError, 0x0),
    (SubscribeDoneStatusCode::Unauthorized, 0x1),
    (SubscribeDoneStatusCode::TrackEnded, 0x2),
    (SubscribeDoneStatusCode::SubscriptionEnded, 0x3),
    (SubscribeDoneStatusCode::GoingAway, 0x4),
    (SubscribeDoneStatusCode::Expired, 0x5),
    (SubscribeDoneStatusCode::TooFarBehind, 0x6),
    (SubscribeDoneStatusCode::MalformedTrack, 0x7),
];

/// Draft-13 Section 8.15 PUBLISH_ERROR.
const PUBLISH_ERROR: [(PublishErrorCode, u64); 5] = [
    (PublishErrorCode::InternalError, 0x0),
    (PublishErrorCode::Unauthorized, 0x1),
    (PublishErrorCode::Timeout, 0x2),
    (PublishErrorCode::NotSupported, 0x3),
    (PublishErrorCode::Uninterested, 0x4),
];

/// Draft-13 Section 8.18 FETCH_ERROR.
const FETCH_ERROR: [(FetchErrorCode, u64); 12] = [
    (FetchErrorCode::InternalError, 0x0),
    (FetchErrorCode::Unauthorized, 0x1),
    (FetchErrorCode::Timeout, 0x2),
    (FetchErrorCode::NotSupported, 0x3),
    (FetchErrorCode::TrackDoesNotExist, 0x4),
    (FetchErrorCode::InvalidRange, 0x5),
    (FetchErrorCode::NoObjects, 0x6),
    (FetchErrorCode::InvalidJoiningRequestId, 0x7),
    (FetchErrorCode::UnknownStatusInRange, 0x8),
    (FetchErrorCode::MalformedTrack, 0x9),
    (FetchErrorCode::MalformedAuthToken, 0x10),
    (FetchErrorCode::ExpiredAuthToken, 0x12),
];

/// Draft-13 Section 8.25 ANNOUNCE_ERROR.
const ANNOUNCE_ERROR: [(AnnounceErrorCode, u64); 7] = [
    (AnnounceErrorCode::InternalError, 0x0),
    (AnnounceErrorCode::Unauthorized, 0x1),
    (AnnounceErrorCode::Timeout, 0x2),
    (AnnounceErrorCode::NotSupported, 0x3),
    (AnnounceErrorCode::Uninterested, 0x4),
    (AnnounceErrorCode::MalformedAuthToken, 0x10),
    (AnnounceErrorCode::ExpiredAuthToken, 0x12),
];

/// Draft-13 Section 8.30 SUBSCRIBE_NAMESPACE_ERROR.
const SUBSCRIBE_NAMESPACE_ERROR: [(SubscribeNamespaceErrorCode, u64); 8] = [
    (SubscribeNamespaceErrorCode::InternalError, 0x0),
    (SubscribeNamespaceErrorCode::Unauthorized, 0x1),
    (SubscribeNamespaceErrorCode::Timeout, 0x2),
    (SubscribeNamespaceErrorCode::NotSupported, 0x3),
    (SubscribeNamespaceErrorCode::NamespacePrefixUnknown, 0x4),
    (SubscribeNamespaceErrorCode::NamespacePrefixOverlap, 0x5),
    (SubscribeNamespaceErrorCode::MalformedAuthToken, 0x10),
    (SubscribeNamespaceErrorCode::ExpiredAuthToken, 0x12),
];

/// Draft-13 Section 9.4.3 Closing Subgroup Streams.
const STREAM_RESET: [(StreamResetErrorCode, u64); 4] = [
    (StreamResetErrorCode::InternalError, 0x0),
    (StreamResetErrorCode::Cancelled, 0x1),
    (StreamResetErrorCode::DeliveryTimeout, 0x2),
    (StreamResetErrorCode::SessionClosed, 0x3),
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

#[test]
fn publish_error_code_round_trips() {
    for (variant, code) in PUBLISH_ERROR {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            PublishErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(PublishErrorCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

#[test]
fn fetch_error_code_round_trips() {
    for (variant, code) in FETCH_ERROR {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            FetchErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(FetchErrorCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

#[test]
fn announce_error_code_round_trips() {
    for (variant, code) in ANNOUNCE_ERROR {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            AnnounceErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(AnnounceErrorCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

#[test]
fn subscribe_namespace_error_code_round_trips() {
    for (variant, code) in SUBSCRIBE_NAMESPACE_ERROR {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            SubscribeNamespaceErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(
            SubscribeNamespaceErrorCode::from_u64(code),
            Some(variant),
            "from_u64(0x{code:x})"
        );
    }
}

#[test]
fn stream_reset_error_code_round_trips() {
    for (variant, code) in STREAM_RESET {
        assert_eq!(variant.as_u64(), code, "as_u64 for {variant:?}");
        assert_eq!(
            StreamResetErrorCode::from_u64(variant.as_u64()),
            Some(variant),
            "from_u64(as_u64()) for {variant:?}"
        );
        assert_eq!(StreamResetErrorCode::from_u64(code), Some(variant), "from_u64(0x{code:x})");
    }
}

/// Every value the draft does not assign must decode to `None`, in particular the gaps the
/// draft leaves inside its own numbering: 0xA through 0xF in the termination table, and 0x11
/// in the four request-error tables that jump from 0x10 to 0x12. Scanning the whole low range
/// rather than a hand-written gap list means a variant added at a wrong code point is caught
/// from both directions.
#[test]
fn unassigned_code_points_decode_to_none() {
    for code in 0u64..=0x400 {
        let assigned = SESSION.iter().find(|(_, c)| *c == code);
        match (assigned, SessionErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "SessionErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("SessionErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("SessionErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = SUBSCRIBE_ERROR.iter().find(|(_, c)| *c == code);
        match (assigned, SubscribeErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "SubscribeErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("SubscribeErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("SubscribeErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = SUBSCRIBE_DONE.iter().find(|(_, c)| *c == code);
        match (assigned, SubscribeDoneStatusCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "SubscribeDoneStatusCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("SubscribeDoneStatusCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("SubscribeDoneStatusCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = PUBLISH_ERROR.iter().find(|(_, c)| *c == code);
        match (assigned, PublishErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "PublishErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("PublishErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("PublishErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = FETCH_ERROR.iter().find(|(_, c)| *c == code);
        match (assigned, FetchErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "FetchErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!(
                    "FetchErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}"
                )
            }
            (None, Some(got)) => {
                panic!("FetchErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = ANNOUNCE_ERROR.iter().find(|(_, c)| *c == code);
        match (assigned, AnnounceErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "AnnounceErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("AnnounceErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("AnnounceErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = SUBSCRIBE_NAMESPACE_ERROR.iter().find(|(_, c)| *c == code);
        match (assigned, SubscribeNamespaceErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "SubscribeNamespaceErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("SubscribeNamespaceErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("SubscribeNamespaceErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in 0u64..=0x400 {
        let assigned = STREAM_RESET.iter().find(|(_, c)| *c == code);
        match (assigned, StreamResetErrorCode::from_u64(code)) {
            (Some((want, _)), Some(got)) => {
                assert_eq!(*want, got, "StreamResetErrorCode::from_u64(0x{code:x})")
            }
            (None, None) => {}
            (Some((want, _)), None) => {
                panic!("StreamResetErrorCode::from_u64(0x{code:x}) returned None, draft-13 assigns {want:?}")
            }
            (None, Some(got)) => {
                panic!("StreamResetErrorCode::from_u64(0x{code:x}) returned {got:?}, draft-13 assigns nothing there")
            }
        }
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(SessionErrorCode::from_u64(code), None, "SessionErrorCode 0x{code:x}");
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(SubscribeErrorCode::from_u64(code), None, "SubscribeErrorCode 0x{code:x}");
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(
            SubscribeDoneStatusCode::from_u64(code),
            None,
            "SubscribeDoneStatusCode 0x{code:x}"
        );
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(PublishErrorCode::from_u64(code), None, "PublishErrorCode 0x{code:x}");
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(FetchErrorCode::from_u64(code), None, "FetchErrorCode 0x{code:x}");
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(AnnounceErrorCode::from_u64(code), None, "AnnounceErrorCode 0x{code:x}");
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(
            SubscribeNamespaceErrorCode::from_u64(code),
            None,
            "SubscribeNamespaceErrorCode 0x{code:x}"
        );
    }
    for code in [0x4001u64, 0xFFFF, 1 << 32, u64::MAX] {
        assert_eq!(StreamResetErrorCode::from_u64(code), None, "StreamResetErrorCode 0x{code:x}");
    }
}

/// The eight registries are separate number spaces. 0x0 and 0x2 in particular carry a
/// different meaning in almost every table, which is the case most likely to be collapsed
/// by a future refactor into one shared enum.
#[test]
fn registries_are_distinct_number_spaces() {
    assert_eq!(SessionErrorCode::from_u64(0x0), Some(SessionErrorCode::NoError));
    assert_eq!(SubscribeErrorCode::from_u64(0x0), Some(SubscribeErrorCode::InternalError));
    assert_eq!(SessionErrorCode::from_u64(0x2), Some(SessionErrorCode::Unauthorized));
    assert_eq!(SubscribeErrorCode::from_u64(0x2), Some(SubscribeErrorCode::Timeout));
    assert_eq!(SubscribeDoneStatusCode::from_u64(0x2), Some(SubscribeDoneStatusCode::TrackEnded));
    assert_eq!(StreamResetErrorCode::from_u64(0x2), Some(StreamResetErrorCode::DeliveryTimeout));
}

/// PUBLISH_ERROR is the one request-error table in draft-13 that does not assign the 0x10 and
/// 0x12 auth-token codes. Its four sibling tables all do.
#[test]
fn publish_error_has_no_auth_token_codes() {
    assert_eq!(PublishErrorCode::from_u64(0x10), None);
    assert_eq!(PublishErrorCode::from_u64(0x12), None);
    for code in [0x10u64, 0x12] {
        assert!(SubscribeErrorCode::from_u64(code).is_some());
        assert!(FetchErrorCode::from_u64(code).is_some());
        assert!(AnnounceErrorCode::from_u64(code).is_some());
        assert!(SubscribeNamespaceErrorCode::from_u64(code).is_some());
    }
}

/// Discriminants inside one registry must be distinct; a duplicated code point would make
/// one variant unreachable through `from_u64` without any compiler complaint.
#[test]
fn code_points_are_unique_within_each_registry() {
    {
        let mut codes: Vec<u64> = SESSION.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in SessionErrorCode");
    }
    {
        let mut codes: Vec<u64> = SUBSCRIBE_ERROR.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in SubscribeErrorCode");
    }
    {
        let mut codes: Vec<u64> = SUBSCRIBE_DONE.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in SubscribeDoneStatusCode");
    }
    {
        let mut codes: Vec<u64> = PUBLISH_ERROR.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in PublishErrorCode");
    }
    {
        let mut codes: Vec<u64> = FETCH_ERROR.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in FetchErrorCode");
    }
    {
        let mut codes: Vec<u64> = ANNOUNCE_ERROR.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in AnnounceErrorCode");
    }
    {
        let mut codes: Vec<u64> = SUBSCRIBE_NAMESPACE_ERROR.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in SubscribeNamespaceErrorCode");
    }
    {
        let mut codes: Vec<u64> = STREAM_RESET.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate code point in StreamResetErrorCode");
    }
}

/// Row counts as transcribed, checked against the draft's tables.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 19, "draft-13 Section 3.4 Termination");
    assert_eq!(SUBSCRIBE_ERROR.len(), 8, "draft-13 Section 8.9 SUBSCRIBE_ERROR");
    assert_eq!(SUBSCRIBE_DONE.len(), 8, "draft-13 Section 8.12 SUBSCRIBE_DONE");
    assert_eq!(PUBLISH_ERROR.len(), 5, "draft-13 Section 8.15 PUBLISH_ERROR");
    assert_eq!(FETCH_ERROR.len(), 12, "draft-13 Section 8.18 FETCH_ERROR");
    assert_eq!(ANNOUNCE_ERROR.len(), 7, "draft-13 Section 8.25 ANNOUNCE_ERROR");
    assert_eq!(
        SUBSCRIBE_NAMESPACE_ERROR.len(),
        8,
        "draft-13 Section 8.30 SUBSCRIBE_NAMESPACE_ERROR"
    );
    assert_eq!(STREAM_RESET.len(), 4, "draft-13 Section 9.4.3 Closing Subgroup Streams");
    assert_eq!(
        SESSION.len()
            + SUBSCRIBE_ERROR.len()
            + SUBSCRIBE_DONE.len()
            + PUBLISH_ERROR.len()
            + FETCH_ERROR.len()
            + ANNOUNCE_ERROR.len()
            + SUBSCRIBE_NAMESPACE_ERROR.len()
            + STREAM_RESET.len(),
        71
    );
}

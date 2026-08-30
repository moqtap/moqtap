#![cfg(feature = "draft14")]
//! Round-trip and rejection tests for the draft-14 code registries.
//!
//! The eight tables transcribed in `draft14::error_codes` are the IANA registries in
//! Section 13.1: 13.1.1 Session Termination Error Codes (21 rows), 13.1.2 SUBSCRIBE_ERROR
//! Codes (8), 13.1.3 PUBLISH_DONE Codes (8), 13.1.4 PUBLISH_ERROR Codes (5), 13.1.5
//! FETCH_ERROR Codes (12), 13.1.6 ANNOUNCE_ERROR Codes (7), 13.1.7
//! SUBSCRIBE_NAMESPACE_ERROR Codes (8) and 13.1.8 Data Stream Reset Error Codes (4) —
//! 73 code points.
//!
//! The arrays below restate each table's code points, read from the draft rather than from
//! the enum definitions, so a discriminant edited in one place and not the other fails here
//! rather than shipping.

#![cfg(feature = "draft14")]

use moqtap_codec::draft14::error_codes::{
    AnnounceErrorCode, DataStreamResetErrorCode, FetchErrorCode, PublishDoneStatusCode,
    PublishErrorCode, RequestErrorCode, SessionErrorCode, SubscribeNamespaceErrorCode,
};

/// Draft-14 Section 13.1.1 Session Termination Error Codes.
const SESSION: [(SessionErrorCode, u64); 21] = [
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
    (SessionErrorCode::InvalidAuthority, 0x19),
    (SessionErrorCode::MalformedAuthority, 0x1A),
];

/// Draft-14 Section 13.1.2 SUBSCRIBE_ERROR Codes.
const SUBSCRIBE_ERROR: [(RequestErrorCode, u64); 8] = [
    (RequestErrorCode::InternalError, 0x0),
    (RequestErrorCode::Unauthorized, 0x1),
    (RequestErrorCode::Timeout, 0x2),
    (RequestErrorCode::NotSupported, 0x3),
    (RequestErrorCode::TrackDoesNotExist, 0x4),
    (RequestErrorCode::InvalidRange, 0x5),
    (RequestErrorCode::MalformedAuthToken, 0x10),
    (RequestErrorCode::ExpiredAuthToken, 0x12),
];

/// Draft-14 Section 13.1.3 PUBLISH_DONE Codes.
const PUBLISH_DONE: [(PublishDoneStatusCode, u64); 8] = [
    (PublishDoneStatusCode::InternalError, 0x0),
    (PublishDoneStatusCode::Unauthorized, 0x1),
    (PublishDoneStatusCode::TrackEnded, 0x2),
    (PublishDoneStatusCode::SubscriptionEnded, 0x3),
    (PublishDoneStatusCode::GoingAway, 0x4),
    (PublishDoneStatusCode::Expired, 0x5),
    (PublishDoneStatusCode::TooFarBehind, 0x6),
    (PublishDoneStatusCode::MalformedTrack, 0x7),
];

/// Draft-14 Section 13.1.4 PUBLISH_ERROR Codes.
const PUBLISH_ERROR: [(PublishErrorCode, u64); 5] = [
    (PublishErrorCode::InternalError, 0x0),
    (PublishErrorCode::Unauthorized, 0x1),
    (PublishErrorCode::Timeout, 0x2),
    (PublishErrorCode::NotSupported, 0x3),
    (PublishErrorCode::Uninterested, 0x4),
];

/// Draft-14 Section 13.1.5 FETCH_ERROR Codes.
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

/// Draft-14 Section 13.1.6 ANNOUNCE_ERROR Codes.
const ANNOUNCE_ERROR: [(AnnounceErrorCode, u64); 7] = [
    (AnnounceErrorCode::InternalError, 0x0),
    (AnnounceErrorCode::Unauthorized, 0x1),
    (AnnounceErrorCode::Timeout, 0x2),
    (AnnounceErrorCode::NotSupported, 0x3),
    (AnnounceErrorCode::Uninterested, 0x4),
    (AnnounceErrorCode::MalformedAuthToken, 0x10),
    (AnnounceErrorCode::ExpiredAuthToken, 0x12),
];

/// Draft-14 Section 13.1.7 SUBSCRIBE_NAMESPACE_ERROR Codes.
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

/// Draft-14 Section 13.1.8 Data Stream Reset Error Codes.
const STREAM_RESET: [(DataStreamResetErrorCode, u64); 4] = [
    (DataStreamResetErrorCode::InternalError, 0x0),
    (DataStreamResetErrorCode::Cancelled, 0x1),
    (DataStreamResetErrorCode::DeliveryTimeout, 0x2),
    (DataStreamResetErrorCode::SessionClosed, 0x3),
];

/// Runs the three per-registry invariants over one table.
///
/// 1. `as_u64` returns the code point the draft assigns.
/// 2. `from_u64` maps that code point back to the same variant, so
///    `from_u64(as_u64(v)) == Some(v)` for every variant.
/// 3. no two variants share a code point.
macro_rules! check_registry {
    ($table:expr, $ty:ty, $label:literal) => {{
        for (variant, code) in $table {
            assert_eq!(
                variant.as_u64(),
                code,
                "{}: {:?} should encode as {:#x}",
                $label,
                variant,
                code
            );
            assert_eq!(
                <$ty>::from_u64(code),
                Some(variant),
                "{}: {:#x} should decode to {:?}",
                $label,
                code,
                variant
            );
            assert_eq!(
                <$ty>::from_u64(variant.as_u64()),
                Some(variant),
                "{}: round trip failed for {:?}",
                $label,
                variant
            );
        }
        let mut codes: Vec<u64> = $table.iter().map(|(_, c)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "{}: duplicate code point", $label);
    }};
}

/// `from_u64(as_u64(v)) == Some(v)` for every variant of every registry.
#[test]
fn round_trip_every_variant() {
    check_registry!(SESSION, SessionErrorCode, "SessionErrorCode");
    check_registry!(SUBSCRIBE_ERROR, RequestErrorCode, "RequestErrorCode");
    check_registry!(PUBLISH_DONE, PublishDoneStatusCode, "PublishDoneStatusCode");
    check_registry!(PUBLISH_ERROR, PublishErrorCode, "PublishErrorCode");
    check_registry!(FETCH_ERROR, FetchErrorCode, "FetchErrorCode");
    check_registry!(ANNOUNCE_ERROR, AnnounceErrorCode, "AnnounceErrorCode");
    check_registry!(
        SUBSCRIBE_NAMESPACE_ERROR,
        SubscribeNamespaceErrorCode,
        "SubscribeNamespaceErrorCode"
    );
    check_registry!(STREAM_RESET, DataStreamResetErrorCode, "DataStreamResetErrorCode");
}

/// Every code point the draft leaves unassigned decodes to `None`.
///
/// The gaps are as much a part of each table as the rows: draft-14 numbers these registries
/// in hex and jumps from 0x9 to 0x10, so 0xA through 0xF are unassigned everywhere, and the
/// auth-token codes sit at 0x10 and 0x12 with 0x11 unassigned.
#[test]
fn unassigned_code_points_decode_to_none() {
    // Session: assigns 0x0-0x9 and 0x10-0x1A.
    for code in 0xA..=0xF {
        assert_eq!(SessionErrorCode::from_u64(code), None, "session {code:#x}");
    }
    for code in 0x1B..=0x30 {
        assert_eq!(SessionErrorCode::from_u64(code), None, "session {code:#x}");
    }

    // SUBSCRIBE_ERROR: assigns 0x0-0x5, 0x10, 0x12.
    for code in [0x6, 0x7, 0x8, 0x9, 0xA, 0xF, 0x11, 0x13, 0x14] {
        assert_eq!(RequestErrorCode::from_u64(code), None, "subscribe {code:#x}");
    }

    // PUBLISH_DONE: assigns 0x0-0x7 only.
    for code in 0x8..=0x20 {
        assert_eq!(PublishDoneStatusCode::from_u64(code), None, "publish_done {code:#x}");
    }

    // PUBLISH_ERROR: assigns 0x0-0x4 only, and notably not 0x10 or 0x12.
    for code in 0x5..=0x20 {
        assert_eq!(PublishErrorCode::from_u64(code), None, "publish_error {code:#x}");
    }

    // FETCH_ERROR: assigns 0x0-0x9, 0x10, 0x12.
    for code in [0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x11, 0x13, 0x14] {
        assert_eq!(FetchErrorCode::from_u64(code), None, "fetch {code:#x}");
    }

    // ANNOUNCE_ERROR: assigns 0x0-0x4, 0x10, 0x12.
    for code in [0x5, 0x6, 0x9, 0xA, 0xF, 0x11, 0x13, 0x14] {
        assert_eq!(AnnounceErrorCode::from_u64(code), None, "announce {code:#x}");
    }

    // SUBSCRIBE_NAMESPACE_ERROR: assigns 0x0-0x5, 0x10, 0x12.
    for code in [0x6, 0x7, 0x9, 0xA, 0xF, 0x11, 0x13, 0x14] {
        assert_eq!(
            SubscribeNamespaceErrorCode::from_u64(code),
            None,
            "subscribe_namespace {code:#x}"
        );
    }

    // Data stream reset: assigns 0x0-0x3 only.
    for code in 0x4..=0x20 {
        assert_eq!(DataStreamResetErrorCode::from_u64(code), None, "stream_reset {code:#x}");
    }
}

/// An unrecognized code is not a decode failure, so the largest varint decodes to `None`
/// rather than panicking, in every registry.
#[test]
fn out_of_range_codes_decode_to_none() {
    for code in [0xFFFF_u64, 0x7FFF_FFFF, u64::MAX] {
        assert_eq!(SessionErrorCode::from_u64(code), None);
        assert_eq!(RequestErrorCode::from_u64(code), None);
        assert_eq!(PublishDoneStatusCode::from_u64(code), None);
        assert_eq!(PublishErrorCode::from_u64(code), None);
        assert_eq!(FetchErrorCode::from_u64(code), None);
        assert_eq!(AnnounceErrorCode::from_u64(code), None);
        assert_eq!(SubscribeNamespaceErrorCode::from_u64(code), None);
        assert_eq!(DataStreamResetErrorCode::from_u64(code), None);
    }
}

/// The request-scoped registries disagree at 0x4, which is why they are separate types.
///
/// Decoding one message's error code with another's type would be silently wrong rather
/// than a decode failure, so the divergence is pinned here.
#[test]
fn request_scoped_registries_diverge_at_0x4() {
    assert_eq!(RequestErrorCode::from_u64(0x4), Some(RequestErrorCode::TrackDoesNotExist));
    assert_eq!(FetchErrorCode::from_u64(0x4), Some(FetchErrorCode::TrackDoesNotExist));
    assert_eq!(PublishErrorCode::from_u64(0x4), Some(PublishErrorCode::Uninterested));
    assert_eq!(AnnounceErrorCode::from_u64(0x4), Some(AnnounceErrorCode::Uninterested));
    assert_eq!(
        SubscribeNamespaceErrorCode::from_u64(0x4),
        Some(SubscribeNamespaceErrorCode::NamespacePrefixUnknown)
    );

    // PUBLISH_ERROR is the only request-scoped registry with no auth-token codes.
    assert_eq!(PublishErrorCode::from_u64(0x10), None);
    assert_eq!(PublishErrorCode::from_u64(0x12), None);
    assert!(RequestErrorCode::from_u64(0x10).is_some());
    assert!(FetchErrorCode::from_u64(0x10).is_some());
    assert!(AnnounceErrorCode::from_u64(0x10).is_some());
    assert!(SubscribeNamespaceErrorCode::from_u64(0x10).is_some());
}

/// Row counts as transcribed, checked against the draft's tables.
#[test]
fn row_counts_match_the_draft_tables() {
    assert_eq!(SESSION.len(), 21, "draft-14 Section 13.1.1 Session Termination Error Codes");
    assert_eq!(SUBSCRIBE_ERROR.len(), 8, "draft-14 Section 13.1.2 SUBSCRIBE_ERROR Codes");
    assert_eq!(PUBLISH_DONE.len(), 8, "draft-14 Section 13.1.3 PUBLISH_DONE Codes");
    assert_eq!(PUBLISH_ERROR.len(), 5, "draft-14 Section 13.1.4 PUBLISH_ERROR Codes");
    assert_eq!(FETCH_ERROR.len(), 12, "draft-14 Section 13.1.5 FETCH_ERROR Codes");
    assert_eq!(ANNOUNCE_ERROR.len(), 7, "draft-14 Section 13.1.6 ANNOUNCE_ERROR Codes");
    assert_eq!(
        SUBSCRIBE_NAMESPACE_ERROR.len(),
        8,
        "draft-14 Section 13.1.7 SUBSCRIBE_NAMESPACE_ERROR Codes"
    );
    assert_eq!(STREAM_RESET.len(), 4, "draft-14 Section 13.1.8 Data Stream Reset Error Codes");
    assert_eq!(
        SESSION.len()
            + SUBSCRIBE_ERROR.len()
            + PUBLISH_DONE.len()
            + PUBLISH_ERROR.len()
            + FETCH_ERROR.len()
            + ANNOUNCE_ERROR.len()
            + SUBSCRIBE_NAMESPACE_ERROR.len()
            + STREAM_RESET.len(),
        73
    );
}

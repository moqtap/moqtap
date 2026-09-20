//! The Full Track Name cap binds the writer too, on every message that carries one.
//!
//! Drafts 11 through 20 all state the same sentence: the maximum total length of
//! a Full Track Name is 4,096 bytes, computed as the sum of the Track Namespace
//! field lengths and the Track Name length, and an endpoint that receives one
//! longer MUST close the session. Drafts 07 through 10 state no such cap and are
//! deliberately absent.
//!
//! # Why the writer, when the rule is written for the reader
//!
//! Because a writer that emits one hands a conforming peer a reason to close the
//! session, and the sender learns of it only when the session goes. The codec
//! already refuses it on the way out — the point of this file is that it does so
//! on **every** message that carries a Full Track Name, not on the one that
//! happened to get a test.
//!
//! That is the gap this file closes. `full_track_name_cap.rs` drives the decode
//! side of SUBSCRIBE on drafts 11 through 20 and nothing else; without the cases
//! here, every other call site — the encode side of all of them, and both sides of
//! TRACK_STATUS, FETCH, PUBLISH, PUBLISH_BLOCKED, PUBLISH_SKIPPED and the
//! Redirect inside REQUEST_ERROR — could have its check deleted with the suite
//! still green.
//!
//! # The shape of each case
//!
//! One byte over the cap must be refused, and one byte under must be written.
//! The second half is what stops a check that refuses everything from passing:
//! a namespace of 4,000 bytes is unusual enough that an over-eager bound would
//! never be noticed by any other test here.
//!
//! Nothing is written on refusal. Every draft builds the payload into a scratch
//! buffer and copies it out once the whole message is known good, so a caller
//! whose message is refused still holds a buffer it can put something else in.
//! That is asserted rather than assumed, because it is a property of how the
//! encoders happen to be written rather than one the drafts require.

#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
use moqtap_codec::types::TrackNamespace;
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
use moqtap_codec::varint::VarInt;

/// A namespace of one field, `bytes` long.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn namespace(bytes: usize) -> TrackNamespace {
    TrackNamespace(vec![vec![b'n'; bytes]])
}

/// A track name of `bytes` bytes.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn name(bytes: usize) -> Vec<u8> {
    vec![b't'; bytes]
}

#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("fixture value fits a varint")
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{name, namespace, v};
    use moqtap_codec::draft11::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Subscribe, TrackStatusRequest,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;
    use moqtap_codec::types::{Forward, GroupOrder};

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_alias: v(1),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    forward: Forward::Forward,
                    filter_type: v(2),
                    start_group: None,
                    start_object: None,
                    end_group: None,
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS_REQUEST",
                ControlMessage::TrackStatusRequest(TrackStatusRequest {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{name, namespace, v};
    use moqtap_codec::draft12::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, Subscribe, TrackStatusRequest,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;
    use moqtap_codec::types::{ContentExists, Forward, GroupOrder};

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    forward: Forward::Forward,
                    filter_type: v(2),
                    start_group: None,
                    start_object: None,
                    end_group: None,
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS_REQUEST",
                ControlMessage::TrackStatusRequest(TrackStatusRequest {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    group_order: GroupOrder::Ascending,
                    content_exists: ContentExists::NoLargestLocation,
                    largest_location: None,
                    forward: Forward::Forward,
                    parameters: vec![],
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{name, namespace, v};
    use moqtap_codec::draft13::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, Subscribe, TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;
    use moqtap_codec::types::{ContentExists, FilterType, Forward, GroupOrder};

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    forward: Forward::Forward,
                    filter_type: FilterType::LargestObject,
                    start_group: None,
                    start_object: None,
                    end_group: None,
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    forward: Forward::Forward,
                    filter_type: FilterType::LargestObject,
                    start_group: None,
                    start_object: None,
                    end_group: None,
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    group_order: GroupOrder::Ascending,
                    content_exists: ContentExists::NoLargestLocation,
                    largest_location: None,
                    forward: Forward::Forward,
                    parameters: vec![],
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::{name, namespace, v};
    use moqtap_codec::draft14::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, Subscribe, TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;
    use moqtap_codec::types::{ContentExists, FilterType, Forward, GroupOrder};

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    forward: Forward::Forward,
                    filter_type: FilterType::LargestObject,
                    start_location: None,
                    end_group: None,
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    forward: Forward::Forward,
                    filter_type: FilterType::LargestObject,
                    start_location: None,
                    end_group: None,
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    subscriber_priority: 128,
                    group_order: GroupOrder::Ascending,
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    group_order: GroupOrder::Ascending,
                    content_exists: ContentExists::NoLargestLocation,
                    largest_location: None,
                    forward: Forward::Forward,
                    parameters: vec![],
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{name, namespace, v};
    use moqtap_codec::draft15::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, Subscribe, TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    parameters: vec![],
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{name, namespace, v};
    use moqtap_codec::draft16::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, Subscribe, TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    parameters: vec![],
                    track_extensions: vec![],
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::{name, namespace, v};
    use moqtap_codec::draft17::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, PublishBlocked, Subscribe,
        TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    required_request_id_delta: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    required_request_id_delta: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    required_request_id_delta: v(0),
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    required_request_id_delta: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    parameters: vec![],
                    track_properties: vec![],
                }),
            ),
            (
                "PUBLISH_BLOCKED",
                ControlMessage::PublishBlocked(PublishBlocked {
                    namespace_suffix: ns.clone(),
                    track_name: tn.clone(),
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use super::{name, namespace, v};
    use moqtap_codec::draft18::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, PublishBlocked, Redirect,
        RequestError, Subscribe, TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    parameters: vec![],
                    track_properties: vec![],
                }),
            ),
            (
                "PUBLISH_BLOCKED",
                ControlMessage::PublishBlocked(PublishBlocked {
                    namespace_suffix: ns.clone(),
                    track_name: tn.clone(),
                }),
            ),
            (
                "REQUEST_ERROR",
                ControlMessage::RequestError(RequestError {
                    // The Redirect body is written only under the code that defines it,
                    // so any other code would encode a message with no Full Track Name
                    // in it at all and the case would measure nothing.
                    error_code: v(0x34),
                    retry_interval: v(0),
                    reason_phrase: b"go elsewhere".to_vec(),
                    redirect: Some(Redirect {
                        connect_uri: Vec::new(),
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                    }),
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::{name, namespace, v};
    use moqtap_codec::draft19::message::{
        ControlMessage, Fetch, FetchPayload, FetchType, Publish, PublishSkipped, Redirect,
        RequestError, Subscribe, TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    fetch_type: FetchType::Standalone,
                    fetch_payload: FetchPayload::Standalone {
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    },
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    parameters: vec![],
                    track_properties: vec![],
                }),
            ),
            (
                "PUBLISH_SKIPPED",
                ControlMessage::PublishSkipped(PublishSkipped {
                    namespace_suffix: ns.clone(),
                    track_name: tn.clone(),
                }),
            ),
            (
                "REQUEST_ERROR",
                ControlMessage::RequestError(RequestError {
                    // The Redirect body is written only under the code that defines it,
                    // so any other code would encode a message with no Full Track Name
                    // in it at all and the case would measure nothing.
                    error_code: v(0x34),
                    retry_interval: v(0),
                    reason_phrase: b"go elsewhere".to_vec(),
                    redirect: Some(Redirect {
                        connect_uri: Vec::new(),
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                    }),
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

#[cfg(feature = "draft20")]
mod draft20 {
    use super::{name, namespace, v};
    use moqtap_codec::draft20::message::{
        ControlMessage, Fetch, Publish, PublishSkipped, Redirect, RequestError, Subscribe,
        TrackStatus,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::TrackNamespace;

    /// Every message this draft gives a Full Track Name, built around one.
    ///
    /// The namespace carries 4,000 bytes and the name carries the rest, so the
    /// two lengths together are what crosses the cap - which is what the drafts
    /// define, rather than a bound on either field alone.
    fn messages(ns: TrackNamespace, tn: Vec<u8>) -> Vec<(&'static str, ControlMessage)> {
        vec![
            (
                "SUBSCRIBE",
                ControlMessage::Subscribe(Subscribe {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "TRACK_STATUS",
                ControlMessage::TrackStatus(TrackStatus {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            // Draft-20's FETCH holds the namespace and the name inline rather
            // than inside a Standalone Fetch, and has no Fetch Type and no
            // inline range (Section 10.13). Same two fields, same cap, one
            // level shallower.
            (
                "FETCH",
                ControlMessage::Fetch(Fetch {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    parameters: vec![],
                }),
            ),
            (
                "PUBLISH",
                ControlMessage::Publish(Publish {
                    request_id: v(0),
                    track_namespace: ns.clone(),
                    track_name: tn.clone(),
                    track_alias: v(1),
                    parameters: vec![],
                    track_properties: vec![],
                }),
            ),
            (
                "PUBLISH_SKIPPED",
                ControlMessage::PublishSkipped(PublishSkipped {
                    namespace_suffix: ns.clone(),
                    track_name: tn.clone(),
                }),
            ),
            (
                "REQUEST_ERROR",
                ControlMessage::RequestError(RequestError {
                    // The Redirect body is written only under the code that defines it,
                    // so any other code would encode a message with no Full Track Name
                    // in it at all and the case would measure nothing.
                    error_code: v(0x34),
                    retry_interval: v(0),
                    reason_phrase: b"go elsewhere".to_vec(),
                    redirect: Some(Redirect {
                        connect_uri: Vec::new(),
                        track_namespace: ns.clone(),
                        track_name: tn.clone(),
                    }),
                }),
            ),
        ]
    }

    /// One byte over the cap is refused, on every message that carries a name.
    ///
    /// Ablation: removing the `check_full_track_name` call from any one arm of
    /// this draft's `encode_payload` fails with that arm's name, as
    ///
    /// ```text
    /// SUBSCRIBE: a 4,097-byte Full Track Name must be refused, got Ok(())
    /// ```
    #[test]
    fn a_full_track_name_one_byte_over_the_cap_is_refused() {
        for (label, msg) in messages(namespace(4000), name(97)) {
            let mut wire = Vec::new();
            let result = msg.encode(&mut wire);
            assert!(
                matches!(result, Err(CodecError::TrackNameTooLong)),
                "{label}: a 4,097-byte Full Track Name must be refused, got {result:?}",
            );
            assert!(
                wire.is_empty(),
                "{label}: a refused message must leave the caller's buffer alone, \
                 and it wrote {} bytes",
                wire.len(),
            );
        }
    }

    /// One byte under is written, on every one of them.
    ///
    /// Without this the gate above would pass against a codec that refused
    /// every namespace of any size, which is a different rule and a worse one.
    #[test]
    fn a_full_track_name_at_the_cap_is_written() {
        for (label, msg) in messages(namespace(4000), name(96)) {
            let mut wire = Vec::new();
            msg.encode(&mut wire)
                .unwrap_or_else(|e| panic!("{label}: 4,096 bytes is within the cap: {e:?}"));
            assert!(!wire.is_empty(), "{label}: an accepted message must write something");
        }
    }
}

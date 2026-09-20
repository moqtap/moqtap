//! An id a peer chose is held to the rules, on the path a peer's message takes.
//!
//! Two numbers are easy to confuse and this gate keeps them apart. The ceiling
//! a peer's ids are measured against is the one **this** endpoint advertised.
//! The ceiling this endpoint's own ids are measured against is the one the peer
//! granted it. They are different values, and either may be the larger.
//!
//! So each draft below has a gate that goes through `receive_message` - the
//! path a message off the wire actually takes - as well as gates on the
//! boundary itself. A rule that is implemented and reachable from nothing is
//! not enforced, and a boundary test alone cannot tell the two apart.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{ns, varint};
    use moqtap_client::draft07::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_client::draft07::session::subscribe_id::SubscribeIdError;
    use moqtap_codec::draft07::message::{ControlMessage, Fetch, MaxSubscribeId, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::types::*;

    /// The ROLE parameter draft-07 requires of both endpoints, in the shape
    /// this era gives a setup parameter value. Section 6.2.2.1.
    fn role() -> KeyValuePair {
        KeyValuePair { key: varint(0x00), value: KvpValue::Bytes(vec![0x03]) }
    }

    /// An endpoint that has finished setup and advertised `ceiling` to the
    /// peer.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000007)], vec![role()]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff000007),
                parameters: vec![role()],
            })
            .unwrap();
        endpoint.send_max_subscribe_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A standalone FETCH as a peer would send it, carrying `id`.
    fn peer_fetch(id: u64) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(1),
            end_object: varint(0),
            parameters: vec![],
        })
    }

    /// The ceiling is exclusive: Section 6.20 gives the Maximum Subscribe
    /// ID a default of 0 and reads that as "the peer MUST NOT create
    /// subscriptions", which holds only if a ceiling of 0 forbids the id 0.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_subscribe_id(8);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(8, 8)))),
            "a ceiling of 8 does not include 8: {result:?}",
        );
    }

    /// The boundary on the other side, without which the gate above would pass
    /// on an endpoint that refused every id a peer sent.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        assert!(endpoint.validate_peer_subscribe_id(3).is_ok(), "3 is below a ceiling of 8");
    }

    /// Section 6.4: the Subscribe ID "MUST be unique and
    /// monotonically increasing within a session". Strictly increasing answers
    /// both halves, so a repeat is caught by the same comparison.
    ///
    /// Dropping the high-water mark fails with:
    ///
    /// ```text
    /// 3 does not increase on 3: Ok(())
    /// ```
    #[test]
    fn a_peer_id_that_does_not_increase_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.validate_peer_subscribe_id(3).unwrap();
        for repeat in [3, 2] {
            let result = endpoint.validate_peer_subscribe_id(repeat);
            assert!(
                matches!(result, Err(EndpointError::PeerSubscribeIdNotIncreasing(_, 3))),
                "{repeat} does not increase on 3: {result:?}",
            );
        }
    }

    /// The two ceilings are different numbers. Here the peer grants a large
    /// budget and this endpoint advertises a small one; the peer is held to the
    /// small one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_subscribe_id(5);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring. A FETCH off the wire reaches the dispatcher, and the
    /// dispatcher has to apply the rule - the validator being correct is worth
    /// nothing if no arriving message ever meets it.
    ///
    /// Removing the dispatch arm fails with:
    ///
    /// ```text
    /// a FETCH whose Subscribe ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_fetch(9));
        assert!(
            result.is_err(),
            "a FETCH whose Subscribe ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_fetch(1)).is_ok(),
            "a FETCH within the ceiling is a request this endpoint invited",
        );
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{ns, varint};
    use moqtap_client::draft08::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_client::draft08::session::subscribe_id::SubscribeIdError;
    use moqtap_codec::draft08::message::FetchType;
    use moqtap_codec::draft08::message::{ControlMessage, Fetch, MaxSubscribeId, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::types::*;

    /// An endpoint that has finished setup and advertised `ceiling` to the
    /// peer.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000008)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff000008),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_subscribe_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A standalone FETCH as a peer would send it, carrying `id`.
    fn peer_fetch(id: u64) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(ns()),
            track_name: Some(b"video".to_vec()),
            start_group: Some(varint(0)),
            start_object: Some(varint(0)),
            end_group: Some(varint(1)),
            end_object: Some(varint(0)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        })
    }

    /// The ceiling is exclusive: Section 7.20 gives the Maximum Subscribe
    /// ID a default of 0 and reads that as "the peer MUST NOT create
    /// subscriptions", which holds only if a ceiling of 0 forbids the id 0.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_subscribe_id(8);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(8, 8)))),
            "a ceiling of 8 does not include 8: {result:?}",
        );
    }

    /// The boundary on the other side, without which the gate above would pass
    /// on an endpoint that refused every id a peer sent.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        assert!(endpoint.validate_peer_subscribe_id(3).is_ok(), "3 is below a ceiling of 8");
    }

    /// Section 7.4: the Subscribe ID "MUST be unique and
    /// monotonically increasing within a session". Strictly increasing answers
    /// both halves, so a repeat is caught by the same comparison.
    ///
    /// Dropping the high-water mark fails with:
    ///
    /// ```text
    /// 3 does not increase on 3: Ok(())
    /// ```
    #[test]
    fn a_peer_id_that_does_not_increase_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.validate_peer_subscribe_id(3).unwrap();
        for repeat in [3, 2] {
            let result = endpoint.validate_peer_subscribe_id(repeat);
            assert!(
                matches!(result, Err(EndpointError::PeerSubscribeIdNotIncreasing(_, 3))),
                "{repeat} does not increase on 3: {result:?}",
            );
        }
    }

    /// The two ceilings are different numbers. Here the peer grants a large
    /// budget and this endpoint advertises a small one; the peer is held to the
    /// small one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_subscribe_id(5);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring. A FETCH off the wire reaches the dispatcher, and the
    /// dispatcher has to apply the rule - the validator being correct is worth
    /// nothing if no arriving message ever meets it.
    ///
    /// Removing the dispatch arm fails with:
    ///
    /// ```text
    /// a FETCH whose Subscribe ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_fetch(9));
        assert!(
            result.is_err(),
            "a FETCH whose Subscribe ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_fetch(1)).is_ok(),
            "a FETCH within the ceiling is a request this endpoint invited",
        );
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{ns, varint};
    use moqtap_client::draft09::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_client::draft09::session::subscribe_id::SubscribeIdError;
    use moqtap_codec::draft09::message::FetchType;
    use moqtap_codec::draft09::message::{ControlMessage, Fetch, MaxSubscribeId, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::types::*;

    /// An endpoint that has finished setup and advertised `ceiling` to the
    /// peer.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000009)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff000009),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_subscribe_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A standalone FETCH as a peer would send it, carrying `id`.
    fn peer_fetch(id: u64) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(ns()),
            track_name: Some(b"video".to_vec()),
            start_group: Some(varint(0)),
            start_object: Some(varint(0)),
            end_group: Some(varint(1)),
            end_object: Some(varint(0)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        })
    }

    /// The ceiling is exclusive: Section 7.20 gives the Maximum Subscribe
    /// ID a default of 0 and reads that as "the peer MUST NOT create
    /// subscriptions", which holds only if a ceiling of 0 forbids the id 0.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_subscribe_id(8);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(8, 8)))),
            "a ceiling of 8 does not include 8: {result:?}",
        );
    }

    /// The boundary on the other side, without which the gate above would pass
    /// on an endpoint that refused every id a peer sent.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        assert!(endpoint.validate_peer_subscribe_id(3).is_ok(), "3 is below a ceiling of 8");
    }

    /// Section 7.4: the Subscribe ID "MUST be unique and
    /// monotonically increasing within a session". Strictly increasing answers
    /// both halves, so a repeat is caught by the same comparison.
    ///
    /// Dropping the high-water mark fails with:
    ///
    /// ```text
    /// 3 does not increase on 3: Ok(())
    /// ```
    #[test]
    fn a_peer_id_that_does_not_increase_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.validate_peer_subscribe_id(3).unwrap();
        for repeat in [3, 2] {
            let result = endpoint.validate_peer_subscribe_id(repeat);
            assert!(
                matches!(result, Err(EndpointError::PeerSubscribeIdNotIncreasing(_, 3))),
                "{repeat} does not increase on 3: {result:?}",
            );
        }
    }

    /// The two ceilings are different numbers. Here the peer grants a large
    /// budget and this endpoint advertises a small one; the peer is held to the
    /// small one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_subscribe_id(5);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring. A FETCH off the wire reaches the dispatcher, and the
    /// dispatcher has to apply the rule - the validator being correct is worth
    /// nothing if no arriving message ever meets it.
    ///
    /// Removing the dispatch arm fails with:
    ///
    /// ```text
    /// a FETCH whose Subscribe ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_fetch(9));
        assert!(
            result.is_err(),
            "a FETCH whose Subscribe ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_fetch(1)).is_ok(),
            "a FETCH within the ceiling is a request this endpoint invited",
        );
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{ns, varint};
    use moqtap_client::draft10::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_client::draft10::session::subscribe_id::SubscribeIdError;
    use moqtap_codec::draft10::message::FetchType;
    use moqtap_codec::draft10::message::{ControlMessage, Fetch, MaxSubscribeId, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::types::*;

    /// An endpoint that has finished setup and advertised `ceiling` to the
    /// peer.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000a)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000a),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_subscribe_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A standalone FETCH as a peer would send it, carrying `id`.
    fn peer_fetch(id: u64) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(ns()),
            track_name: Some(b"video".to_vec()),
            start_group: Some(varint(0)),
            start_object: Some(varint(0)),
            end_group: Some(varint(1)),
            end_object: Some(varint(0)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        })
    }

    /// The ceiling is exclusive: Section 8.4 gives the Maximum Subscribe
    /// ID a default of 0 and reads that as "the peer MUST NOT create
    /// subscriptions", which holds only if a ceiling of 0 forbids the id 0.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_subscribe_id(8);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(8, 8)))),
            "a ceiling of 8 does not include 8: {result:?}",
        );
    }

    /// The boundary on the other side, without which the gate above would pass
    /// on an endpoint that refused every id a peer sent.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        assert!(endpoint.validate_peer_subscribe_id(3).is_ok(), "3 is below a ceiling of 8");
    }

    /// Section 8.6: the Subscribe ID "MUST be unique and
    /// monotonically increasing within a session". Strictly increasing answers
    /// both halves, so a repeat is caught by the same comparison.
    ///
    /// Dropping the high-water mark fails with:
    ///
    /// ```text
    /// 3 does not increase on 3: Ok(())
    /// ```
    #[test]
    fn a_peer_id_that_does_not_increase_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.validate_peer_subscribe_id(3).unwrap();
        for repeat in [3, 2] {
            let result = endpoint.validate_peer_subscribe_id(repeat);
            assert!(
                matches!(result, Err(EndpointError::PeerSubscribeIdNotIncreasing(_, 3))),
                "{repeat} does not increase on 3: {result:?}",
            );
        }
    }

    /// The two ceilings are different numbers. Here the peer grants a large
    /// budget and this endpoint advertises a small one; the peer is held to the
    /// small one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_subscribe_id(5);
        assert!(
            matches!(result, Err(EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring. A FETCH off the wire reaches the dispatcher, and the
    /// dispatcher has to apply the rule - the validator being correct is worth
    /// nothing if no arriving message ever meets it.
    ///
    /// Removing the dispatch arm fails with:
    ///
    /// ```text
    /// a FETCH whose Subscribe ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_fetch(9));
        assert!(
            result.is_err(),
            "a FETCH whose Subscribe ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_fetch(1)).is_ok(),
            "a FETCH within the ceiling is a request this endpoint invited",
        );
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{ns, varint};
    use moqtap_client::draft11::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft11::session::request_id::{RequestIdError, Role};
    use moqtap_codec::draft11::message::{
        ControlMessage, MaxRequestId, ServerSetup, TrackStatusRequest,
    };
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A client endpoint that has finished setup and advertised `ceiling`.
    ///
    /// A client's own ids are even, so the peer's are odd - that is what makes
    /// the parity gate below meaningful.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000b)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000b),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_request_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A request as the peer would send it, carrying `id`.
    fn peer_request(id: u64) -> ControlMessage {
        ControlMessage::TrackStatusRequest(TrackStatusRequest {
            request_id: varint(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![],
        })
    }

    /// Section 8.1: a Request ID "equal to or larger than" the maximum in
    /// force closes the session, so the ceiling does not include itself.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(9);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(9, 8)))),
            "9 is past a ceiling of 8: {result:?}",
        );
    }

    /// The boundary on the other side, walked rather than sampled.
    ///
    /// A single id cannot show this any more: taking one advances the peer's
    /// sequence, so 7 on its own is now a skip and would be refused for a
    /// reason that has nothing to do with the ceiling. Every id the peer may
    /// spend under a ceiling of 8 is spent here, in the order the sequence
    /// fixes, which is the only way the boundary and the sequence can both be
    /// read off one run.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        for id in [1, 3, 5, 7] {
            let result = endpoint.validate_peer_request_id(id);
            assert!(result.is_ok(), "{id} is a server id below 8: {result:?}");
        }
    }

    /// Section 8.1: "The client's Request ID starts at 0 and are even and the
    /// server's Request ID starts at 1 and are odd." An even id from a server
    /// is one out of this endpoint's own half of the space.
    #[test]
    fn a_peer_id_from_this_endpoints_own_half_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(2);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::WrongParity(2, _)))),
            "an even id is a client's, and this endpoint is the client: {result:?}",
        );
    }

    /// The two ceilings are different numbers: the peer grants a large budget,
    /// this endpoint advertises a small one, and the peer is held to the small
    /// one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_request_id(5);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring, on the path a message off the wire takes.
    ///
    /// Removing the call from `receive_message` fails with:
    ///
    /// ```text
    /// a request whose Request ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_request(9));
        assert!(
            result.is_err(),
            "a request whose Request ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_request(1)).is_ok(),
            "a request within the ceiling is one this endpoint invited",
        );
    }

    /// A Request ID the peer has already spent is refused.
    ///
    /// Section 8.1 closes the session on "a new request with a Request ID that is not expected", and a repeat is the
    /// case the other two halves both miss: it has the parity of the peer's
    /// space, and it sat below the ceiling when it was accepted the first time,
    /// so it sits below it still. Only a record of what has been spent answers
    /// it, and until that record existed a peer could open a second request
    /// under the id of one already open and take its place in every map keyed
    /// by Request ID.
    ///
    /// Ablation: dropping the `record_peer_id` call from
    /// `validate_peer_request_id` fails with
    ///
    /// ```text
    /// an id the peer has already opened a request under must be refused: Ok(())
    /// ```
    #[test]
    fn an_id_the_peer_already_spent_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.receive_message(peer_request(1)).expect("the peer's first request is in sequence");

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "an id the peer has already opened a request under must be refused: {result:?}",
        );
    }

    /// A Request ID the peer skipped ahead to is refused on the same rule.
    ///
    /// The other direction, and the one that shows the check is about the
    /// sequence rather than about repeats. Section 8.1 starts the peer's
    /// half at 1 here and steps it by 2, so its first request has one legal id
    /// and 3 is not it.
    #[test]
    fn an_id_the_peer_skipped_ahead_to_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_request(3));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the peer's first request has one legal id and 3 is not it: {result:?}",
        );
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{ns, varint};
    use moqtap_client::draft12::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft12::session::request_id::{RequestIdError, Role};
    use moqtap_codec::draft12::message::{
        ControlMessage, MaxRequestId, ServerSetup, TrackStatusRequest,
    };
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A client endpoint that has finished setup and advertised `ceiling`.
    ///
    /// A client's own ids are even, so the peer's are odd - that is what makes
    /// the parity gate below meaningful.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000c)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000c),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_request_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A request as the peer would send it, carrying `id`.
    fn peer_request(id: u64) -> ControlMessage {
        ControlMessage::TrackStatusRequest(TrackStatusRequest {
            request_id: varint(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![],
        })
    }

    /// Section 8.1: a Request ID "equal to or larger than" the maximum in
    /// force closes the session, so the ceiling does not include itself.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(9);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(9, 8)))),
            "9 is past a ceiling of 8: {result:?}",
        );
    }

    /// The boundary on the other side, walked rather than sampled.
    ///
    /// A single id cannot show this any more: taking one advances the peer's
    /// sequence, so 7 on its own is now a skip and would be refused for a
    /// reason that has nothing to do with the ceiling. Every id the peer may
    /// spend under a ceiling of 8 is spent here, in the order the sequence
    /// fixes, which is the only way the boundary and the sequence can both be
    /// read off one run.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        for id in [1, 3, 5, 7] {
            let result = endpoint.validate_peer_request_id(id);
            assert!(result.is_ok(), "{id} is a server id below 8: {result:?}");
        }
    }

    /// Section 8.1: "The client's Request ID starts at 0 and are even and the
    /// server's Request ID starts at 1 and are odd." An even id from a server
    /// is one out of this endpoint's own half of the space.
    #[test]
    fn a_peer_id_from_this_endpoints_own_half_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(2);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::WrongParity(2, _)))),
            "an even id is a client's, and this endpoint is the client: {result:?}",
        );
    }

    /// The two ceilings are different numbers: the peer grants a large budget,
    /// this endpoint advertises a small one, and the peer is held to the small
    /// one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_request_id(5);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring, on the path a message off the wire takes.
    ///
    /// Removing the call from `receive_message` fails with:
    ///
    /// ```text
    /// a request whose Request ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_request(9));
        assert!(
            result.is_err(),
            "a request whose Request ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_request(1)).is_ok(),
            "a request within the ceiling is one this endpoint invited",
        );
    }

    /// A Request ID the peer has already spent is refused.
    ///
    /// Section 8.1 closes the session on "a new request with a Request ID that is not expected", and a repeat is the
    /// case the other two halves both miss: it has the parity of the peer's
    /// space, and it sat below the ceiling when it was accepted the first time,
    /// so it sits below it still. Only a record of what has been spent answers
    /// it, and until that record existed a peer could open a second request
    /// under the id of one already open and take its place in every map keyed
    /// by Request ID.
    ///
    /// Ablation: dropping the `record_peer_id` call from
    /// `validate_peer_request_id` fails with
    ///
    /// ```text
    /// an id the peer has already opened a request under must be refused: Ok(())
    /// ```
    #[test]
    fn an_id_the_peer_already_spent_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.receive_message(peer_request(1)).expect("the peer's first request is in sequence");

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "an id the peer has already opened a request under must be refused: {result:?}",
        );
    }

    /// A Request ID the peer skipped ahead to is refused on the same rule.
    ///
    /// The other direction, and the one that shows the check is about the
    /// sequence rather than about repeats. Section 8.1 starts the peer's
    /// half at 1 here and steps it by 2, so its first request has one legal id
    /// and 3 is not it.
    #[test]
    fn an_id_the_peer_skipped_ahead_to_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_request(3));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the peer's first request has one legal id and 3 is not it: {result:?}",
        );
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{ns, varint};
    use moqtap_client::draft13::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft13::session::request_id::{RequestIdError, Role};
    use moqtap_codec::draft13::message::{
        ControlMessage, MaxRequestId, ServerSetup, SubscribeNamespace,
    };
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A client endpoint that has finished setup and advertised `ceiling`.
    ///
    /// A client's own ids are even, so the peer's are odd - that is what makes
    /// the parity gate below meaningful.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000d)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000d),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_request_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A request as the peer would send it, carrying `id`.
    fn peer_request(id: u64) -> ControlMessage {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: varint(id),
            track_namespace_prefix: ns(),
            parameters: vec![],
        })
    }

    /// Section 8.1: a Request ID "equal to or larger than" the maximum in
    /// force closes the session, so the ceiling does not include itself.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(9);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(9, 8)))),
            "9 is past a ceiling of 8: {result:?}",
        );
    }

    /// The boundary on the other side, walked rather than sampled.
    ///
    /// A single id cannot show this any more: taking one advances the peer's
    /// sequence, so 7 on its own is now a skip and would be refused for a
    /// reason that has nothing to do with the ceiling. Every id the peer may
    /// spend under a ceiling of 8 is spent here, in the order the sequence
    /// fixes, which is the only way the boundary and the sequence can both be
    /// read off one run.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        for id in [1, 3, 5, 7] {
            let result = endpoint.validate_peer_request_id(id);
            assert!(result.is_ok(), "{id} is a server id below 8: {result:?}");
        }
    }

    /// Section 8.1: "The client's Request ID starts at 0 and are even and the
    /// server's Request ID starts at 1 and are odd." An even id from a server
    /// is one out of this endpoint's own half of the space.
    #[test]
    fn a_peer_id_from_this_endpoints_own_half_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(2);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::WrongParity(2, _)))),
            "an even id is a client's, and this endpoint is the client: {result:?}",
        );
    }

    /// The two ceilings are different numbers: the peer grants a large budget,
    /// this endpoint advertises a small one, and the peer is held to the small
    /// one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_request_id(5);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring, on the path a message off the wire takes.
    ///
    /// Removing the call from `receive_message` fails with:
    ///
    /// ```text
    /// a request whose Request ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_request(9));
        assert!(
            result.is_err(),
            "a request whose Request ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_request(1)).is_ok(),
            "a request within the ceiling is one this endpoint invited",
        );
    }

    /// A Request ID the peer has already spent is refused.
    ///
    /// Section 8.1 closes the session on "a new request with a Request ID that is not expected", and a repeat is the
    /// case the other two halves both miss: it has the parity of the peer's
    /// space, and it sat below the ceiling when it was accepted the first time,
    /// so it sits below it still. Only a record of what has been spent answers
    /// it, and until that record existed a peer could open a second request
    /// under the id of one already open and take its place in every map keyed
    /// by Request ID.
    ///
    /// Ablation: dropping the `record_peer_id` call from
    /// `validate_peer_request_id` fails with
    ///
    /// ```text
    /// an id the peer has already opened a request under must be refused: Ok(())
    /// ```
    #[test]
    fn an_id_the_peer_already_spent_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.receive_message(peer_request(1)).expect("the peer's first request is in sequence");

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "an id the peer has already opened a request under must be refused: {result:?}",
        );
    }

    /// A Request ID the peer skipped ahead to is refused on the same rule.
    ///
    /// The other direction, and the one that shows the check is about the
    /// sequence rather than about repeats. Section 8.1 starts the peer's
    /// half at 1 here and steps it by 2, so its first request has one legal id
    /// and 3 is not it.
    #[test]
    fn an_id_the_peer_skipped_ahead_to_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_request(3));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the peer's first request has one legal id and 3 is not it: {result:?}",
        );
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::{ns, varint};
    use moqtap_client::draft14::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft14::session::request_id::{RequestIdError, Role};
    use moqtap_codec::draft14::message::{
        ControlMessage, MaxRequestId, ServerSetup, SubscribeNamespace, SubscribeUpdate,
    };
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A client endpoint that has finished setup and advertised `ceiling`.
    ///
    /// A client's own ids are even, so the peer's are odd - that is what makes
    /// the parity gate below meaningful.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000e),
                parameters: vec![],
            })
            .unwrap();
        endpoint.send_max_request_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A request as the peer would send it, carrying `id`.
    fn peer_request(id: u64) -> ControlMessage {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: varint(id),
            track_namespace: ns(),
            parameters: vec![],
        })
    }

    /// Section 9.1: a Request ID "equal to or larger than" the maximum in
    /// force closes the session, so the ceiling does not include itself.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(9);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(9, 8)))),
            "9 is past a ceiling of 8: {result:?}",
        );
    }

    /// The boundary on the other side, walked rather than sampled.
    ///
    /// A single id cannot show this any more: taking one advances the peer's
    /// sequence, so 7 on its own is now a skip and would be refused for a
    /// reason that has nothing to do with the ceiling. Every id the peer may
    /// spend under a ceiling of 8 is spent here, in the order the sequence
    /// fixes, which is the only way the boundary and the sequence can both be
    /// read off one run.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        for id in [1, 3, 5, 7] {
            let result = endpoint.validate_peer_request_id(id);
            assert!(result.is_ok(), "{id} is a server id below 8: {result:?}");
        }
    }

    /// Section 9.1: "The client's Request ID starts at 0 and are even and the
    /// server's Request ID starts at 1 and are odd." An even id from a server
    /// is one out of this endpoint's own half of the space.
    #[test]
    fn a_peer_id_from_this_endpoints_own_half_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(2);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::WrongParity(2, _)))),
            "an even id is a client's, and this endpoint is the client: {result:?}",
        );
    }

    /// The two ceilings are different numbers: the peer grants a large budget,
    /// this endpoint advertises a small one, and the peer is held to the small
    /// one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_request_id(5);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring, on the path a message off the wire takes.
    ///
    /// Removing the call from `receive_message` fails with:
    ///
    /// ```text
    /// a request whose Request ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_request(9));
        assert!(
            result.is_err(),
            "a request whose Request ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_request(1)).is_ok(),
            "a request within the ceiling is one this endpoint invited",
        );
    }

    /// A SUBSCRIBE_UPDATE as the peer would send it: `id` is the update's own
    /// Request ID and `names` is the subscription it modifies.
    fn peer_update(id: u64, names: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: varint(id),
            subscription_request_id: varint(names),
            start_location: Location { group: varint(0), object: varint(0) },
            end_group: varint(10),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: vec![],
        })
    }

    /// A Request ID the peer has already spent is refused.
    ///
    /// Section 9.1 closes the session on "a new request with a Request ID that is not expected", and a repeat is the
    /// case the other two halves both miss: it has the parity of the peer's
    /// space, and it sat below the ceiling when it was accepted the first time,
    /// so it sits below it still. Only a record of what has been spent answers
    /// it, and until that record existed a peer could open a second request
    /// under the id of one already open and take its place in every map keyed
    /// by Request ID.
    ///
    /// Ablation: dropping the `record_peer_id` call from
    /// `validate_peer_request_id` fails with
    ///
    /// ```text
    /// an id the peer has already opened a request under must be refused: Ok(())
    /// ```
    #[test]
    fn an_id_the_peer_already_spent_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.receive_message(peer_request(1)).expect("the peer's first request is in sequence");

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "an id the peer has already opened a request under must be refused: {result:?}",
        );
    }

    /// A Request ID the peer skipped ahead to is refused on the same rule.
    ///
    /// The other direction, and the one that shows the check is about the
    /// sequence rather than about repeats. Section 9.1 starts the peer's
    /// half at 1 here and steps it by 2, so its first request has one legal id
    /// and 3 is not it.
    #[test]
    fn an_id_the_peer_skipped_ahead_to_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_request(3));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the peer's first request has one legal id and 3 is not it: {result:?}",
        );
    }

    /// SUBSCRIBE_UPDATE spends a Request ID of its own, so its own id is checked.
    ///
    /// Section 9.1 lists it among the messages that step the sequence, and
    /// its shape says the same thing: it carries a Request ID **and** a
    /// separate field naming the request it modifies. Leaving it out of the set
    /// left its own id unchecked for parity and for the ceiling as well.
    ///
    /// The update below names a request that does not exist, so it fails either
    /// way. What is measured is which rule it fails on.
    ///
    /// Ablation: removing the arm from `receive_request` fails with
    ///
    /// ```text
    /// the update's own Request ID must be held to the peer's sequence:
    /// Err(UnknownRequest(99))
    /// ```
    #[test]
    fn the_update_messages_own_id_is_checked() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_update(3, 99));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the update's own Request ID must be held to the peer's sequence: {result:?}",
        );
    }

    /// And spending it moves the sequence on for everything after.
    ///
    /// The consequence of the arm above, seen from the next request rather than
    /// from the update itself: an update that took id 1 leaves 3 as the next,
    /// and a request that reuses 1 is a repeat.
    #[test]
    fn the_update_message_advances_the_peers_sequence() {
        let mut endpoint = advertising(8);
        // This fails to find the request it names - a different rule, and not
        // the one under test. Its Request ID is spent before that is reached.
        let _ = endpoint.receive_message(peer_update(1, 99));

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "the update spent the peer's first id, so 1 is no longer available: {result:?}",
        );
    }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{ns, varint};
    use moqtap_client::draft15::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft15::session::request_id::{RequestIdError, Role};
    use moqtap_codec::draft15::message::{
        ControlMessage, MaxRequestId, ServerSetup, SubscribeUpdate, TrackStatus,
    };
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A client endpoint that has finished setup and advertised `ceiling`.
    ///
    /// A client's own ids are even, so the peer's are odd - that is what makes
    /// the parity gate below meaningful.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![]).unwrap();
        endpoint.receive_server_setup(&ServerSetup { parameters: vec![] }).unwrap();
        endpoint.send_max_request_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A request as the peer would send it, carrying `id`.
    fn peer_request(id: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: varint(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![],
        })
    }

    /// Section 9.1: a Request ID "equal to or larger than" the maximum in
    /// force closes the session, so the ceiling does not include itself.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(9);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(9, 8)))),
            "9 is past a ceiling of 8: {result:?}",
        );
    }

    /// The boundary on the other side, walked rather than sampled.
    ///
    /// A single id cannot show this any more: taking one advances the peer's
    /// sequence, so 7 on its own is now a skip and would be refused for a
    /// reason that has nothing to do with the ceiling. Every id the peer may
    /// spend under a ceiling of 8 is spent here, in the order the sequence
    /// fixes, which is the only way the boundary and the sequence can both be
    /// read off one run.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        for id in [1, 3, 5, 7] {
            let result = endpoint.validate_peer_request_id(id);
            assert!(result.is_ok(), "{id} is a server id below 8: {result:?}");
        }
    }

    /// Section 9.1: "The client's Request ID starts at 0 and are even and the
    /// server's Request ID starts at 1 and are odd." An even id from a server
    /// is one out of this endpoint's own half of the space.
    #[test]
    fn a_peer_id_from_this_endpoints_own_half_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(2);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::WrongParity(2, _)))),
            "an even id is a client's, and this endpoint is the client: {result:?}",
        );
    }

    /// The two ceilings are different numbers: the peer grants a large budget,
    /// this endpoint advertises a small one, and the peer is held to the small
    /// one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_request_id(5);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring, on the path a message off the wire takes.
    ///
    /// Removing the call from `receive_message` fails with:
    ///
    /// ```text
    /// a request whose Request ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_request(9));
        assert!(
            result.is_err(),
            "a request whose Request ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_request(1)).is_ok(),
            "a request within the ceiling is one this endpoint invited",
        );
    }

    /// A SUBSCRIBE_UPDATE as the peer would send it: `id` is the update's own
    /// Request ID and `names` is the subscription it modifies.
    fn peer_update(id: u64, names: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: varint(id),
            subscription_request_id: varint(names),
            parameters: vec![],
        })
    }

    /// A Request ID the peer has already spent is refused.
    ///
    /// Section 9.1 closes the session on "a new request with a Request ID that is not the next in sequence", and a repeat is the
    /// case the other two halves both miss: it has the parity of the peer's
    /// space, and it sat below the ceiling when it was accepted the first time,
    /// so it sits below it still. Only a record of what has been spent answers
    /// it, and until that record existed a peer could open a second request
    /// under the id of one already open and take its place in every map keyed
    /// by Request ID.
    ///
    /// Ablation: dropping the `record_peer_id` call from
    /// `validate_peer_request_id` fails with
    ///
    /// ```text
    /// an id the peer has already opened a request under must be refused: Ok(())
    /// ```
    #[test]
    fn an_id_the_peer_already_spent_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.receive_message(peer_request(1)).expect("the peer's first request is in sequence");

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "an id the peer has already opened a request under must be refused: {result:?}",
        );
    }

    /// A Request ID the peer skipped ahead to is refused on the same rule.
    ///
    /// The other direction, and the one that shows the check is about the
    /// sequence rather than about repeats. Section 9.1 starts the peer's
    /// half at 1 here and steps it by 2, so its first request has one legal id
    /// and 3 is not it.
    #[test]
    fn an_id_the_peer_skipped_ahead_to_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_request(3));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the peer's first request has one legal id and 3 is not it: {result:?}",
        );
    }

    /// SUBSCRIBE_UPDATE spends a Request ID of its own, so its own id is checked.
    ///
    /// Section 9.1 lists it among the messages that step the sequence, and
    /// its shape says the same thing: it carries a Request ID **and** a
    /// separate field naming the request it modifies. Leaving it out of the set
    /// left its own id unchecked for parity and for the ceiling as well.
    ///
    /// The update below names a request that does not exist, so it fails either
    /// way. What is measured is which rule it fails on.
    ///
    /// Ablation: removing the arm from `receive_request` fails with
    ///
    /// ```text
    /// the update's own Request ID must be held to the peer's sequence:
    /// Err(UnknownRequest(99))
    /// ```
    #[test]
    fn the_update_messages_own_id_is_checked() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_update(3, 99));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the update's own Request ID must be held to the peer's sequence: {result:?}",
        );
    }

    /// And spending it moves the sequence on for everything after.
    ///
    /// The consequence of the arm above, seen from the next request rather than
    /// from the update itself: an update that took id 1 leaves 3 as the next,
    /// and a request that reuses 1 is a repeat.
    #[test]
    fn the_update_message_advances_the_peers_sequence() {
        let mut endpoint = advertising(8);
        // This fails to find the request it names - a different rule, and not
        // the one under test. Its Request ID is spent before that is reached.
        let _ = endpoint.receive_message(peer_update(1, 99));

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "the update spent the peer's first id, so 1 is no longer available: {result:?}",
        );
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{ns, varint};
    use moqtap_client::draft16::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft16::session::request_id::{RequestIdError, Role};
    use moqtap_codec::draft16::message::{
        ControlMessage, MaxRequestId, RequestUpdate, ServerSetup, TrackStatus,
    };
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A client endpoint that has finished setup and advertised `ceiling`.
    ///
    /// A client's own ids are even, so the peer's are odd - that is what makes
    /// the parity gate below meaningful.
    fn advertising(ceiling: u64) -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![]).unwrap();
        endpoint.receive_server_setup(&ServerSetup { parameters: vec![] }).unwrap();
        endpoint.send_max_request_id(varint(ceiling)).unwrap();
        endpoint
    }

    /// A request as the peer would send it, carrying `id`.
    fn peer_request(id: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: varint(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![],
        })
    }

    /// Section 9.1: a Request ID "equal to or larger than" the maximum in
    /// force closes the session, so the ceiling does not include itself.
    #[test]
    fn a_peer_id_at_the_advertised_ceiling_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(9);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(9, 8)))),
            "9 is past a ceiling of 8: {result:?}",
        );
    }

    /// The boundary on the other side, walked rather than sampled.
    ///
    /// A single id cannot show this any more: taking one advances the peer's
    /// sequence, so 7 on its own is now a skip and would be refused for a
    /// reason that has nothing to do with the ceiling. Every id the peer may
    /// spend under a ceiling of 8 is spent here, in the order the sequence
    /// fixes, which is the only way the boundary and the sequence can both be
    /// read off one run.
    #[test]
    fn a_peer_id_below_the_advertised_ceiling_is_accepted() {
        let mut endpoint = advertising(8);
        for id in [1, 3, 5, 7] {
            let result = endpoint.validate_peer_request_id(id);
            assert!(result.is_ok(), "{id} is a server id below 8: {result:?}");
        }
    }

    /// Section 9.1: "The client's Request ID starts at 0 and are even and the
    /// server's Request ID starts at 1 and are odd." An even id from a server
    /// is one out of this endpoint's own half of the space.
    #[test]
    fn a_peer_id_from_this_endpoints_own_half_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.validate_peer_request_id(2);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::WrongParity(2, _)))),
            "an even id is a client's, and this endpoint is the client: {result:?}",
        );
    }

    /// The two ceilings are different numbers: the peer grants a large budget,
    /// this endpoint advertises a small one, and the peer is held to the small
    /// one.
    ///
    /// Measuring against the budget the peer granted fails with:
    ///
    /// ```text
    /// the peer's 64 is this endpoint's budget, not the peer's: Ok(())
    /// ```
    #[test]
    fn the_ceiling_a_peer_is_held_to_is_the_one_this_endpoint_advertised() {
        let mut endpoint = advertising(4);
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(64) }).unwrap();

        let result = endpoint.validate_peer_request_id(5);
        assert!(
            matches!(result, Err(EndpointError::RequestId(RequestIdError::ExceedsMax(5, 4)))),
            "the peer's 64 is this endpoint's budget, not the peer's: {result:?}",
        );
    }

    /// The wiring, on the path a message off the wire takes.
    ///
    /// Removing the call from `receive_message` fails with:
    ///
    /// ```text
    /// a request whose Request ID is past the advertised ceiling must be refused: Ok(())
    /// ```
    #[test]
    fn a_peer_request_off_the_wire_is_checked() {
        let mut endpoint = advertising(4);
        let result = endpoint.receive_message(peer_request(9));
        assert!(
            result.is_err(),
            "a request whose Request ID is past the advertised ceiling must be refused: \
             {result:?}",
        );

        let mut endpoint = advertising(4);
        assert!(
            endpoint.receive_message(peer_request(1)).is_ok(),
            "a request within the ceiling is one this endpoint invited",
        );
    }

    /// A REQUEST_UPDATE as the peer would send it: `id` is the update's own
    /// Request ID and `names` is the request it modifies.
    fn peer_update(id: u64, names: u64) -> ControlMessage {
        ControlMessage::RequestUpdate(RequestUpdate {
            request_id: varint(id),
            existing_request_id: varint(names),
            parameters: vec![],
        })
    }

    /// A Request ID the peer has already spent is refused.
    ///
    /// Section 9.1 closes the session on "a new request with a Request ID that is not the next in sequence", and a repeat is the
    /// case the other two halves both miss: it has the parity of the peer's
    /// space, and it sat below the ceiling when it was accepted the first time,
    /// so it sits below it still. Only a record of what has been spent answers
    /// it, and until that record existed a peer could open a second request
    /// under the id of one already open and take its place in every map keyed
    /// by Request ID.
    ///
    /// Ablation: dropping the `record_peer_id` call from
    /// `validate_peer_request_id` fails with
    ///
    /// ```text
    /// an id the peer has already opened a request under must be refused: Ok(())
    /// ```
    #[test]
    fn an_id_the_peer_already_spent_is_refused() {
        let mut endpoint = advertising(8);
        endpoint.receive_message(peer_request(1)).expect("the peer's first request is in sequence");

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "an id the peer has already opened a request under must be refused: {result:?}",
        );
    }

    /// A Request ID the peer skipped ahead to is refused on the same rule.
    ///
    /// The other direction, and the one that shows the check is about the
    /// sequence rather than about repeats. Section 9.1 starts the peer's
    /// half at 1 here and steps it by 2, so its first request has one legal id
    /// and 3 is not it.
    #[test]
    fn an_id_the_peer_skipped_ahead_to_is_refused() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_request(3));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the peer's first request has one legal id and 3 is not it: {result:?}",
        );
    }

    /// REQUEST_UPDATE spends a Request ID of its own, so its own id is checked.
    ///
    /// Section 9.1 lists it among the messages that step the sequence, and
    /// its shape says the same thing: it carries a Request ID **and** a
    /// separate field naming the request it modifies. Leaving it out of the set
    /// left its own id unchecked for parity and for the ceiling as well.
    ///
    /// The update below names a request that does not exist, so it fails either
    /// way. What is measured is which rule it fails on.
    ///
    /// Ablation: removing the arm from `receive_request` fails with
    ///
    /// ```text
    /// the update's own Request ID must be held to the peer's sequence:
    /// Err(UnknownRequest(99))
    /// ```
    #[test]
    fn the_update_messages_own_id_is_checked() {
        let mut endpoint = advertising(8);
        let result = endpoint.receive_message(peer_update(3, 99));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 3,
                    expected: 1
                }))
            ),
            "the update's own Request ID must be held to the peer's sequence: {result:?}",
        );
    }

    /// And spending it moves the sequence on for everything after.
    ///
    /// The consequence of the arm above, seen from the next request rather than
    /// from the update itself: an update that took id 1 leaves 3 as the next,
    /// and a request that reuses 1 is a repeat.
    #[test]
    fn the_update_message_advances_the_peers_sequence() {
        let mut endpoint = advertising(8);
        // This fails to find the request it names - a different rule, and not
        // the one under test. Its Request ID is spent before that is reached.
        let _ = endpoint.receive_message(peer_update(1, 99));

        let result = endpoint.receive_message(peer_request(1));
        assert!(
            matches!(
                result,
                Err(EndpointError::RequestId(RequestIdError::OutOfSequence {
                    got: 1,
                    expected: 3
                }))
            ),
            "the update spent the peer's first id, so 1 is no longer available: {result:?}",
        );
    }
}

#![cfg(feature = "draft14")]

use moqtap_client::draft14::endpoint::*;
use moqtap_client::draft14::session::request_id::Role;
use moqtap_client::draft14::session::state::SessionState;
use moqtap_codec::draft14::message::{self, *};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

// ============================================================
// Construction and initial state
// ============================================================

/// draft-14 Section 3.3: the control stream is the first thing a session opens,
/// so an endpoint that has opened nothing is outside the Setup exchange.
#[test]
fn endpoint_new_client_starts_in_connecting() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.session_state(), SessionState::Connecting);
}

/// draft-14 Section 3.3: the control stream is "client-initiated", so a server
/// waits in the same state the client starts in.
#[test]
fn endpoint_new_server_starts_in_connecting() {
    let ep = Endpoint::new(Role::Server);
    assert_eq!(ep.session_state(), SessionState::Connecting);
}

/// A new endpoint has no active subscriptions.
#[test]
fn endpoint_new_has_no_subscriptions() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.active_subscription_count(), 0);
}

/// A new endpoint has no active fetches.
#[test]
fn endpoint_new_has_no_fetches() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.active_fetch_count(), 0);
}

/// A new endpoint has no active namespace operations.
#[test]
fn endpoint_new_has_no_namespace_ops() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.active_subscribe_namespace_count(), 0);
    assert_eq!(ep.active_publish_namespace_count(), 0);
}

/// A new endpoint reports its role.
#[test]
fn endpoint_reports_role() {
    let client = Endpoint::new(Role::Client);
    assert_eq!(client.role(), Role::Client);

    let server = Endpoint::new(Role::Server);
    assert_eq!(server.role(), Role::Server);
}

// ============================================================
// Session lifecycle: connect and setup
// ============================================================

/// draft-14 Section 3.3: "The first stream opened is a client-initiated
/// bidirectional control stream where the endpoints exchange Setup messages",
/// and the sentence runs on into the messages that follow them on it.
#[test]
fn endpoint_connect_transitions_to_setup_exchange() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().expect("connect should succeed");
    assert_eq!(ep.session_state(), SessionState::SetupExchange);
}

/// draft-14 Section 3.3: "a peer MAY close the session as a PROTOCOL_VIOLATION
/// if it receives a second bidirectional stream."
#[test]
fn endpoint_connect_twice_fails() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    assert!(ep.connect().is_err());
}

/// draft-14 Section 9.3: CLIENT_SETUP and SERVER_SETUP "are the first messages
/// exchanged by the client and the server".
#[test]
fn endpoint_client_generates_setup_message() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()]; // draft-14
    let msg = ep.send_client_setup(versions.clone(), vec![]).expect("should generate setup");
    match msg {
        ControlMessage::ClientSetup(cs) => {
            assert_eq!(cs.supported_versions, versions);
        }
        _ => panic!("expected ClientSetup message"),
    }
}

/// draft-14 Section 3.2: "The server replies with a SERVER_SETUP message that
/// indicates the chosen version", and the sentence runs on into the parameters
/// that reply must carry as well. With a version chosen the session is in use.
#[test]
fn endpoint_client_receives_server_setup() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();

    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000014).unwrap(), parameters: vec![] };
    ep.receive_server_setup(&server_setup).expect("should accept server setup");
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// draft-14 Section 9.3.1: "If the server does not support any of the versions
/// offered by the client, or the client receives a server version that it did
/// not offer, the corresponding peer MUST close the session with
/// VERSION_NEGOTIATION_FAILED."
#[test]
fn endpoint_rejects_server_setup_version_mismatch() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();

    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000099).unwrap(), parameters: vec![] };
    assert!(ep.receive_server_setup(&server_setup).is_err());
}

// ============================================================
// MAX_REQUEST_ID
// ============================================================

/// draft-14 Section 9.5: "An endpoint sends a MAX_REQUEST_ID message to increase
/// the number of requests the peer can send within a session."
#[test]
fn endpoint_receive_max_request_id() {
    let mut ep = make_active_client();
    let msg = MaxRequestId { request_id: VarInt::from_u64(10).unwrap() };
    ep.receive_max_request_id(&msg).expect("should accept max request id");
}

/// draft-14 Section 9.5: "The Maximum Request ID MUST only increase within a
/// session, and receipt of a MAX_REQUEST_ID message with an equal or smaller
/// Request ID value is a PROTOCOL_VIOLATION."
#[test]
fn endpoint_max_request_id_cannot_decrease() {
    let mut ep = make_active_client();
    let msg1 = MaxRequestId { request_id: VarInt::from_u64(10).unwrap() };
    ep.receive_max_request_id(&msg1).unwrap();

    let msg2 = MaxRequestId { request_id: VarInt::from_u64(5).unwrap() };
    assert!(ep.receive_max_request_id(&msg2).is_err());
}

// ============================================================
// Subscribe flow
// ============================================================

/// draft-14 Section 9.1: "The client's Request ID starts at 0 and are even ...
/// The Request ID increments by 2 with each FETCH, SUBSCRIBE ... request."
#[test]
fn endpoint_subscribe_allocates_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, msg) = ep
        .subscribe(
            ns.clone(),
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .expect("subscribe should succeed");

    // Client uses even request IDs
    assert_eq!(req_id.into_inner() % 2, 0);
    assert_eq!(ep.active_subscription_count(), 1);

    match msg {
        ControlMessage::Subscribe(sub) => {
            assert_eq!(sub.request_id, req_id);
            assert_eq!(sub.track_namespace, ns);
            assert_eq!(sub.track_name, b"track1".to_vec());
        }
        _ => panic!("expected Subscribe message"),
    }
}

/// draft-14 Section 3.3: control messages follow the Setup exchange on the
/// control stream, so a SUBSCRIBE has nothing to travel on before it.
#[test]
fn endpoint_subscribe_requires_active_session() {
    let mut ep = Endpoint::new(Role::Client);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new()
        )
        .is_err());
}

/// draft-14 Section 9.3.2.3: "The default value is 0, so if not specified, the
/// peer MUST NOT send requests."
#[test]
fn endpoint_subscribe_fails_when_blocked() {
    let mut ep = make_active_client(); // max_id = 0, blocked
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new()
        )
        .is_err());
}

/// draft-14 Section 9.8: SUBSCRIBE_OK answers a SUBSCRIBE, and the subscription
/// it names is in force from then on.
#[test]
fn endpoint_receive_subscribe_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let ok = SubscribeOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    ep.receive_subscribe_ok(&ok).expect("should accept subscribe ok");
}

/// draft-14 Section 9.1: "If an endpoint receives a Request ID that is not valid
/// for the peer, or a new request with a Request ID that is not expected, it
/// MUST close the session with INVALID_REQUEST_ID."
#[test]
fn endpoint_receive_subscribe_ok_unknown_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ok = SubscribeOk {
        request_id: VarInt::from_u64(42).unwrap(),
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    assert!(ep.receive_subscribe_ok(&ok).is_err());
}

/// draft-14 Section 9.9: SUBSCRIBE_ERROR refuses a SUBSCRIBE, so the
/// subscription it names never begins.
#[test]
fn endpoint_receive_subscribe_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let err = SubscribeError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x04).unwrap(),
        reason_phrase: b"track not found".to_vec(),
    };
    ep.receive_subscribe_error(&err).expect("should accept subscribe error");
}

/// draft-14 Section 9.11: "A Subscriber issues an UNSUBSCRIBE message to a
/// Publisher indicating it is no longer interested in receiving the specified
/// Track, indicating that the Publisher stop sending Objects as soon as
/// possible."
#[test]
fn endpoint_unsubscribe() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    // First make subscription Active
    let ok = SubscribeOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    ep.receive_subscribe_ok(&ok).unwrap();

    let msg = ep.unsubscribe(req_id).expect("unsubscribe should succeed");
    match msg {
        ControlMessage::Unsubscribe(unsub) => {
            assert_eq!(unsub.request_id, req_id);
        }
        _ => panic!("expected Unsubscribe message"),
    }
}

/// draft-14 Section 9.11: UNSUBSCRIBE carries "the Request ID of the
/// subscription that is being terminated", and no subscription has that one.
#[test]
fn endpoint_unsubscribe_unknown_id() {
    let mut ep = make_active_client_with_max_id(10);
    assert!(ep.unsubscribe(VarInt::from_u64(42).unwrap()).is_err());
}

/// draft-14 Section 9.12: "A publisher sends a PUBLISH_DONE message to indicate
/// it is done publishing Objects for that subscription."
#[test]
fn endpoint_receive_publish_done() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let ok = SubscribeOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    ep.receive_subscribe_ok(&ok).unwrap();

    let done = PublishDone {
        request_id: req_id,
        status_code: VarInt::from_u64(0).unwrap(),
        stream_count: VarInt::from_u64(0).unwrap(),
        reason_phrase: b"normal".to_vec(),
    };
    ep.receive_publish_done(&done).expect("should accept publish done");
}

/// draft-14 Section 9.1: "The Request ID increments by 2 with each ... SUBSCRIBE
/// ... request", so two subscriptions in one session are two identifiers.
#[test]
fn endpoint_multiple_subscriptions() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);

    let (id1, _) = ep
        .subscribe(
            ns.clone(),
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();
    let (id2, _) = ep
        .subscribe(
            ns,
            b"track2".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    assert_ne!(id1, id2);
    assert_eq!(ep.active_subscription_count(), 2);
}

// ============================================================
// Fetch flow
// ============================================================

/// draft-14 Section 9.16: "A subscriber issues a FETCH to a publisher to request
/// a range of already published objects within a track."
#[test]
fn endpoint_fetch_allocates_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, msg) = ep
        .fetch(
            ns.clone(),
            b"segment1".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .expect("fetch should succeed");

    assert_eq!(req_id.into_inner() % 2, 0);
    assert_eq!(ep.active_fetch_count(), 1);

    match msg {
        ControlMessage::Fetch(f) => {
            assert_eq!(f.request_id, req_id);
            match &f.fetch_payload {
                message::FetchPayload::Standalone { track_namespace, track_name, .. } => {
                    assert_eq!(track_namespace, &ns);
                    assert_eq!(track_name, &b"segment1".to_vec());
                }
                _ => panic!("expected standalone fetch payload"),
            }
        }
        _ => panic!("expected Fetch message"),
    }
}

/// draft-14 Section 3.3: control messages follow the Setup exchange on the
/// control stream, so a FETCH has nothing to travel on before it.
#[test]
fn endpoint_fetch_requires_active_session() {
    let mut ep = Endpoint::new(Role::Client);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    assert!(ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .is_err());
}

/// draft-14 Section 9.17: "A publisher sends a FETCH_OK control message in
/// response to successful fetches."
#[test]
fn endpoint_receive_fetch_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    let ok = FetchOk {
        request_id: req_id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).expect("should accept fetch ok");
}

/// draft-14 Section 9.18: "A publisher sends a FETCH_ERROR control message in
/// response to a failed FETCH."
#[test]
fn endpoint_receive_fetch_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    let err = message::FetchError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x04).unwrap(),
        reason_phrase: b"not found".to_vec(),
    };
    ep.receive_fetch_error(&err).expect("should accept fetch error");
}

/// draft-14 Section 9.19: "A subscriber sends a FETCH_CANCEL message to a
/// publisher to indicate it is no longer interested in receiving objects for the
/// fetch identified by the 'Request ID'."
#[test]
fn endpoint_fetch_cancel() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    let msg = ep.fetch_cancel(req_id).expect("fetch cancel should succeed");
    match msg {
        ControlMessage::FetchCancel(fc) => {
            assert_eq!(fc.request_id, req_id);
        }
        _ => panic!("expected FetchCancel message"),
    }
}

/// draft-14 Section 9.19: FETCH_CANCEL carries "the Request ID of the FETCH ...
/// this message is cancelling", and no fetch has that one.
#[test]
fn endpoint_fetch_cancel_unknown_id() {
    let mut ep = make_active_client_with_max_id(10);
    assert!(ep.fetch_cancel(VarInt::from_u64(42).unwrap()).is_err());
}

/// draft-14 Section 9.16.3: "The Objects in the response are delivered on a
/// single unidirectional stream." The end of that stream is the end of the
/// response.
#[test]
fn endpoint_fetch_stream_fin() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    let ok = FetchOk {
        request_id: req_id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).unwrap();

    ep.on_fetch_stream_fin(req_id).expect("stream fin should succeed");
}

/// draft-14 Section 10.4.1: "Streams aside from the control stream MAY be
/// canceled due to congestion or other reasons by either the publisher or
/// subscriber."
#[test]
fn endpoint_fetch_stream_reset() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    let ok = FetchOk {
        request_id: req_id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).unwrap();

    ep.on_fetch_stream_reset(req_id).expect("stream reset should succeed");
}

/// draft-14 Section 9.17: "A publisher MAY send Objects in response to a FETCH
/// before the FETCH_OK message is sent, but the FETCH_OK MUST NOT be sent until
/// the End Location is known", and Section 9.16.3: "The FETCH_OK or FETCH_ERROR
/// can come at any time relative to object delivery." Driven at the endpoint
/// rather than at the state machine, because the endpoint is what a caller
/// holds and what returned an error for this sequence.
///
/// # Ablation, run
///
/// Deleting the `FetchState::Pending` arm of `on_stream_fin` in
/// `src/draft14/fetch.rs`:
///
/// ```text
/// a stream ending before the answer should succeed: Fetch(InvalidTransition {
/// from: Pending, event: "on_stream_fin" })
/// ```
#[test]
fn endpoint_fetch_stream_fin_before_the_answer() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    ep.on_fetch_stream_fin(req_id).expect("a stream ending before the answer should succeed");

    let ok = FetchOk {
        request_id: req_id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).expect("the answer describing a delivered response should land");
}

// ============================================================
// Subscribe Namespace flow
// ============================================================

/// draft-14 Section 9.28: "The subscriber sends the SUBSCRIBE_NAMESPACE control
/// message to a publisher to request the current set of matching published
/// namespaces and established subscriptions, as well as future updates to the
/// set."
#[test]
fn endpoint_subscribe_namespace() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, msg) =
        ep.subscribe_namespace(ns.clone(), vec![]).expect("subscribe namespace should succeed");

    assert_eq!(ep.active_subscribe_namespace_count(), 1);

    match msg {
        ControlMessage::SubscribeNamespace(sn) => {
            assert_eq!(sn.request_id, req_id);
            assert_eq!(sn.track_namespace, ns);
        }
        _ => panic!("expected SubscribeNamespace message"),
    }
}

/// draft-14 Section 6.1: "A publisher MUST send exactly one
/// SUBSCRIBE_NAMESPACE_OK or SUBSCRIBE_NAMESPACE_ERROR in response to a
/// SUBSCRIBE_NAMESPACE."
#[test]
fn endpoint_receive_subscribe_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns, vec![]).unwrap();

    let ok = SubscribeNamespaceOk { request_id: req_id };
    ep.receive_subscribe_namespace_ok(&ok).expect("should accept subscribe namespace ok");
}

/// draft-14 Section 9.30: "A publisher sends a SUBSCRIBE_NAMESPACE_ERROR control
/// message in response to a failed SUBSCRIBE_NAMESPACE."
#[test]
fn endpoint_receive_subscribe_namespace_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns, vec![]).unwrap();

    let err = SubscribeNamespaceError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"unauthorized".to_vec(),
    };
    ep.receive_subscribe_namespace_error(&err).expect("should accept subscribe namespace error");
}

/// draft-14 Section 6.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous
/// SUBSCRIBE_NAMESPACE."
#[test]
fn endpoint_unsubscribe_namespace() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns.clone(), vec![]).unwrap();

    let ok = SubscribeNamespaceOk { request_id: req_id };
    ep.receive_subscribe_namespace_ok(&ok).unwrap();

    let msg =
        ep.unsubscribe_namespace(req_id, ns.clone()).expect("unsubscribe namespace should succeed");
    match msg {
        ControlMessage::UnsubscribeNamespace(unsub) => {
            assert_eq!(unsub.track_namespace_prefix, ns);
            let _ = req_id;
        }
        _ => panic!("expected UnsubscribeNamespace message"),
    }
}

// ============================================================
// Publish Namespace flow
// ============================================================

/// draft-14 Section 9.23: "The publisher sends the PUBLISH_NAMESPACE control
/// message to advertise that it has tracks available within a Track Namespace."
#[test]
fn endpoint_publish_namespace() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, msg) =
        ep.publish_namespace(ns.clone(), vec![]).expect("publish namespace should succeed");

    assert_eq!(ep.active_publish_namespace_count(), 1);

    match msg {
        ControlMessage::PublishNamespace(pn) => {
            assert_eq!(pn.request_id, req_id);
            assert_eq!(pn.track_namespace, ns);
        }
        _ => panic!("expected PublishNamespace message"),
    }
}

/// draft-14 Section 9.24: PUBLISH_NAMESPACE_OK acknowledges "the successful
/// authorization and acceptance of a PUBLISH_NAMESPACE message".
#[test]
fn endpoint_receive_publish_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns, vec![]).unwrap();

    let ok = PublishNamespaceOk { request_id: req_id };
    ep.receive_publish_namespace_ok(&ok).expect("should accept publish namespace ok");
}

/// draft-14 Section 9.25: "The subscriber sends a PUBLISH_NAMESPACE_ERROR
/// control message for tracks that failed authorization."
#[test]
fn endpoint_receive_publish_namespace_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns, vec![]).unwrap();

    let err = PublishNamespaceError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"unauthorized".to_vec(),
    };
    ep.receive_publish_namespace_error(&err).expect("should accept publish namespace error");
}

/// draft-14 Section 9.26: PUBLISH_NAMESPACE_DONE indicates the publisher's
/// "intent to stop serving new subscriptions for tracks within the provided
/// Track Namespace". The publisher of an announcement that arrives here is the
/// peer, so what the withdrawal ends is the peer's announcement.
#[test]
fn endpoint_receive_publish_namespace_done() {
    let mut ep = make_active_client_with_max_id(10);
    let advert = PublishNamespace {
        request_id: VarInt::from_u64(1).unwrap(),
        track_namespace: TrackNamespace(vec![b"live".to_vec()]),
        parameters: vec![],
    };
    ep.receive_publish_namespace(&advert).expect("the peer may announce");
    ep.send_publish_namespace_ok(VarInt::from_u64(1).unwrap()).expect("accept it");

    let done = PublishNamespaceDone { track_namespace: TrackNamespace(vec![b"live".to_vec()]) };
    ep.receive_publish_namespace_done(&done).expect("should accept publish namespace done");
}

/// draft-14 Section 6.2 gives the cancellation to the subscriber, and
/// Section 8.4 says what it revokes: a namespace "it previously responded
/// PUBLISH_NAMESPACE_OK to". This endpoint is that subscriber here, so the
/// announcement it revokes is one the peer made.
#[test]
fn endpoint_publish_namespace_cancel() {
    let mut ep = make_active_client_with_max_id(10);
    let advert = PublishNamespace {
        request_id: VarInt::from_u64(1).unwrap(),
        track_namespace: TrackNamespace(vec![b"live".to_vec()]),
        parameters: vec![],
    };
    ep.receive_publish_namespace(&advert).expect("the peer may announce");
    ep.send_publish_namespace_ok(VarInt::from_u64(1).unwrap()).expect("accept it");

    let msg = ep
        .publish_namespace_cancel(
            TrackNamespace(vec![b"live".to_vec()]),
            VarInt::from_u64(0).unwrap(),
            b"cancelled".to_vec(),
        )
        .expect("cancel should succeed");
    match msg {
        ControlMessage::PublishNamespaceCancel(c) => {
            assert_eq!(c.reason_phrase, b"cancelled".to_vec());
            assert_eq!(c.track_namespace, TrackNamespace(vec![b"live".to_vec()]));
        }
        _ => panic!("expected PublishNamespaceCancel message"),
    }
}

// ============================================================
// GoAway and session draining
// ============================================================

/// draft-14 Section 9.4: "An endpoint sends a GOAWAY message to inform the peer
/// it intends to close the session soon."
#[test]
fn endpoint_receive_goaway() {
    let mut ep = make_active_client();
    let goaway = GoAway { new_session_uri: b"https://new.example.com".to_vec() };
    ep.receive_goaway(&goaway).expect("goaway should succeed");
    assert_eq!(ep.session_state(), SessionState::Draining);
}

/// draft-14 Section 3.3: the Setup exchange is "followed by other messages
/// defined in Section 9", and GOAWAY is one of them.
#[test]
fn endpoint_receive_goaway_not_active() {
    let mut ep = Endpoint::new(Role::Client);
    let goaway = GoAway { new_session_uri: b"https://new.example.com".to_vec() };
    assert!(ep.receive_goaway(&goaway).is_err());
}

/// draft-14 Section 9.4: "New Session URI: When received by a client, indicates
/// where the client can connect to continue this session. The client MUST use
/// this URI for the new session if provided."
#[test]
fn endpoint_goaway_stores_uri() {
    let mut ep = make_active_client();
    let goaway = GoAway { new_session_uri: b"https://new.example.com".to_vec() };
    ep.receive_goaway(&goaway).unwrap();
    assert_eq!(ep.goaway_uri(), Some(b"https://new.example.com".as_slice()));
}

// ============================================================
// Session close
// ============================================================

/// draft-14 Section 3.4: "The Transport Session can be terminated at any point."
#[test]
fn endpoint_close_from_active() {
    let mut ep = make_active_client();
    ep.close().expect("close should succeed");
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// draft-14 Section 3.5: after a GOAWAY "it's RECOMMENDED that the client waits
/// until there are no more active subscriptions before closing the session".
#[test]
fn endpoint_close_from_draining() {
    let mut ep = make_active_client();
    let goaway = GoAway { new_session_uri: vec![] };
    ep.receive_goaway(&goaway).unwrap();
    ep.close().expect("close from draining should succeed");
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// draft-14 Section 3.4: termination ends an established Transport Session, and
/// in Connecting no transport has been established to end. The Setup exchange
/// is a different matter and closes; see `close_during_setup.rs`.
#[test]
fn endpoint_close_from_connecting_fails() {
    let mut ep = Endpoint::new(Role::Client);
    assert!(ep.close().is_err());
}

// ============================================================
// Operations during draining
// ============================================================

/// draft-14 Section 9.4: "Upon receiving a GOAWAY, an endpoint SHOULD NOT
/// initiate new requests to the peer including SUBSCRIBE, PUBLISH, FETCH,
/// PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE and TRACK_SATUS."
#[test]
fn endpoint_subscribe_blocked_during_draining() {
    let mut ep = make_active_client_with_max_id(10);
    let goaway = GoAway { new_session_uri: vec![] };
    ep.receive_goaway(&goaway).unwrap();

    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new()
        )
        .is_err());
}

/// draft-14 Section 9.4: the same sentence names FETCH among the requests an
/// endpoint should not initiate after a GOAWAY.
#[test]
fn endpoint_fetch_blocked_during_draining() {
    let mut ep = make_active_client_with_max_id(10);
    let goaway = GoAway { new_session_uri: vec![] };
    ep.receive_goaway(&goaway).unwrap();

    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    assert!(ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .is_err());
}

// ============================================================
// Unified receive_message dispatch
// ============================================================

/// draft-14: receive_message dispatches SUBSCRIBE_OK correctly.
#[test]
fn endpoint_receive_message_dispatches_subscribe_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let ok_msg = ControlMessage::SubscribeOk(SubscribeOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

/// draft-14: receive_message dispatches GOAWAY correctly.
#[test]
fn endpoint_receive_message_dispatches_goaway() {
    let mut ep = make_active_client();
    let msg = ControlMessage::GoAway(GoAway {
        new_session_uri: b"https://redirect.example.com".to_vec(),
    });
    ep.receive_message(msg).expect("dispatch should succeed");
    assert_eq!(ep.session_state(), SessionState::Draining);
}

/// draft-14: receive_message dispatches MAX_REQUEST_ID correctly.
#[test]
fn endpoint_receive_message_dispatches_max_request_id() {
    let mut ep = make_active_client();
    let msg =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(20).unwrap() });
    ep.receive_message(msg).expect("dispatch should succeed");
}

/// draft-14: receive_message dispatches FETCH_OK correctly.
#[test]
fn endpoint_receive_message_dispatches_fetch_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(
            ns,
            b"seg".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    let ok_msg = ControlMessage::FetchOk(FetchOk {
        request_id: req_id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        parameters: vec![],
    });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

/// draft-14: receive_message dispatches SUBSCRIBE_NAMESPACE_OK correctly.
#[test]
fn endpoint_receive_message_dispatches_subscribe_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns, vec![]).unwrap();

    let ok_msg = ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id: req_id });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

/// draft-14: receive_message dispatches PUBLISH_NAMESPACE_OK correctly.
#[test]
fn endpoint_receive_message_dispatches_publish_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns, vec![]).unwrap();

    let ok_msg = ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id: req_id });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

// ============================================================
// Server-side endpoint
// ============================================================

/// draft-14 Section 3.2: "The server replies with a SERVER_SETUP message that
/// indicates the chosen version, includes all parameters required for a
/// handshake in that version, and parameters for every extension requested by
/// the client that it supports."
#[test]
fn endpoint_server_sends_setup() {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().unwrap();

    let client_setup = ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff000014).unwrap()],
        parameters: vec![],
    };
    let msg = ep
        .receive_client_setup_and_respond(&client_setup, VarInt::from_u64(0xff000014).unwrap())
        .expect("should generate server setup");

    match msg {
        ControlMessage::ServerSetup(ss) => {
            assert_eq!(ss.selected_version, VarInt::from_u64(0xff000014).unwrap());
        }
        _ => panic!("expected ServerSetup message"),
    }
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// draft-14 Section 9.5: the grant travels in either direction — "an endpoint"
/// sends it, not a role.
#[test]
fn endpoint_server_sends_max_request_id() {
    let mut ep = make_active_server();
    let msg = ep
        .send_max_request_id(VarInt::from_u64(20).unwrap())
        .expect("should generate max request id");
    match msg {
        ControlMessage::MaxRequestId(m) => {
            assert_eq!(m.request_id, VarInt::from_u64(20).unwrap());
        }
        _ => panic!("expected MaxRequestId message"),
    }
}

/// draft-14: Server uses odd request IDs.
#[test]
fn endpoint_server_allocates_odd_ids() {
    let mut ep = make_active_server_with_max_id(11);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(req_id.into_inner() % 2, 1);
}

// ============================================================
// Edge cases
// ============================================================

/// Operations on a closed session fail.
#[test]
fn endpoint_operations_fail_after_close() {
    let mut ep = make_active_client_with_max_id(10);
    ep.close().unwrap();

    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(
            ns,
            b"track".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new()
        )
        .is_err());
}

/// Negotiated version is accessible after setup.
#[test]
fn endpoint_negotiated_version() {
    let mut ep = Endpoint::new(Role::Client);
    assert_eq!(ep.negotiated_version(), None);

    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();

    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000014).unwrap(), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert_eq!(ep.negotiated_version(), Some(VarInt::from_u64(0xff000014).unwrap()));
}

/// Request IDs are allocated sequentially (client: 0, 2, 4, ...).
#[test]
fn endpoint_sequential_request_ids() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);

    let (id1, _) = ep
        .subscribe(
            ns.clone(),
            b"t1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();
    let (id2, _) = ep
        .subscribe(
            ns.clone(),
            b"t2".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();
    let (id3, _) = ep
        .fetch(
            ns,
            b"t3".to_vec(),
            128,
            GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
        .unwrap();

    assert_eq!(id1.into_inner(), 0);
    assert_eq!(id2.into_inner(), 2);
    assert_eq!(id3.into_inner(), 4);
}

/// is_blocked reports correctly.
#[test]
fn endpoint_is_blocked() {
    let mut ep = make_active_client();
    assert!(ep.is_blocked());

    let msg = MaxRequestId { request_id: VarInt::from_u64(10).unwrap() };
    ep.receive_max_request_id(&msg).unwrap();
    assert!(!ep.is_blocked());
}

// ============================================================
// SUBSCRIBE_UPDATE
// ============================================================

/// draft-14 Section 9.10: "A subscriber sends a SUBSCRIBE_UPDATE to a publisher
/// to modify an existing subscription." It changes the subscription's
/// parameters, not its lifecycle.
#[test]
fn endpoint_receive_subscribe_update_on_active_subscription() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let ok = SubscribeOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    ep.receive_subscribe_ok(&ok).unwrap();

    let update = SubscribeUpdate {
        request_id: req_id,
        subscription_request_id: req_id,
        start_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        end_group: VarInt::from_u64(0).unwrap(),
        subscriber_priority: 200,
        forward: Forward::Forward,
        parameters: vec![],
    };
    ep.receive_subscribe_update(&update).expect("subscribe update on active should succeed");
}

/// draft-14 Section 9.10: "A publisher MUST terminate the session with a
/// PROTOCOL_VIOLATION ... if the subscriber specifies a request ID that has not
/// existed within the Session."
#[test]
fn endpoint_receive_subscribe_update_unknown_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let update = SubscribeUpdate {
        request_id: VarInt::from_u64(42).unwrap(),
        subscription_request_id: VarInt::from_u64(42).unwrap(),
        start_location: Location {
            group: VarInt::from_u64(0).unwrap(),
            object: VarInt::from_u64(0).unwrap(),
        },
        end_group: VarInt::from_u64(0).unwrap(),
        subscriber_priority: 128,
        forward: Forward::Forward,
        parameters: vec![],
    };
    assert!(ep.receive_subscribe_update(&update).is_err());
}

/// draft-14 Section 9.10: an update may be sent and received before the
/// SUBSCRIBE has been answered.
///
/// "This MUST match an existing Request ID" is all the section asks of the
/// identifier, and a Request ID exists from the moment the SUBSCRIBE carrying it
/// is sent. Nothing in the draft orders an update against the SUBSCRIBE_OK.
///
/// Both directions are driven, because both consult the same subscription
/// state: this endpoint receives an update for a subscription still waiting for
/// its answer, and sends one. The SUBSCRIBE_OK at the end says neither moved it,
/// being the transition out of Subscribing.
#[test]
fn endpoint_subscribe_update_before_the_subscribe_is_answered() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let start =
        Location { group: VarInt::from_u64(0).unwrap(), object: VarInt::from_u64(0).unwrap() };
    let update = SubscribeUpdate {
        request_id: req_id,
        subscription_request_id: req_id,
        start_location: start,
        end_group: VarInt::from_u64(0).unwrap(),
        subscriber_priority: 200,
        forward: Forward::Forward,
        parameters: vec![],
    };
    ep.receive_subscribe_update(&update)
        .expect("an update may precede the subscription's own answer");

    ep.subscribe_update(req_id, start, VarInt::from_u64(0).unwrap(), 200, Forward::Forward, vec![])
        .expect("and may be sent before it too");

    let ok = SubscribeOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    ep.receive_subscribe_ok(&ok)
        .expect("the answer still reaches a subscription that is Subscribing");
}

// ============================================================
// Track Status flow
// ============================================================

/// Client sends TRACK_STATUS, gets request ID.
#[test]
fn endpoint_track_status_allocates_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, msg) = ep
        .track_status(
            ns.clone(),
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
        .expect("track_status should succeed");

    assert_eq!(req_id.into_inner() % 2, 0);
    assert_eq!(ep.active_track_status_count(), 1);

    match msg {
        ControlMessage::TrackStatus(ts) => {
            assert_eq!(ts.request_id, req_id);
            assert_eq!(ts.track_namespace, ns);
            assert_eq!(ts.track_name, b"track1".to_vec());
        }
        _ => panic!("expected TrackStatus message"),
    }
}

/// TRACK_STATUS_OK transitions to Done.
#[test]
fn endpoint_receive_track_status_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .track_status(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
        .unwrap();

    let ok = message::TrackStatusOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(0).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    ep.receive_track_status_ok(&ok).expect("should accept track status ok");
}

/// TRACK_STATUS_ERROR transitions to Done.
#[test]
fn endpoint_receive_track_status_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .track_status(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
        .unwrap();

    let err = message::TrackStatusError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"not found".to_vec(),
    };
    ep.receive_track_status_error(&err).expect("should accept track status error");
}

/// TRACK_STATUS_OK for unknown request ID fails.
#[test]
fn endpoint_receive_track_status_ok_unknown_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ok = message::TrackStatusOk {
        request_id: VarInt::from_u64(42).unwrap(),
        track_alias: VarInt::from_u64(0).unwrap(),
        expires: VarInt::from_u64(0).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    };
    assert!(ep.receive_track_status_ok(&ok).is_err());
}

/// active_track_status_count reflects state.
#[test]
fn endpoint_track_status_count() {
    let mut ep = make_active_client_with_max_id(10);
    assert_eq!(ep.active_track_status_count(), 0);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    ep.track_status(
        ns.clone(),
        b"t1".to_vec(),
        128,
        GroupOrder::Ascending,
        Forward::Forward,
        FilterType::LargestObject,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    ep.track_status(
        ns,
        b"t2".to_vec(),
        128,
        GroupOrder::Ascending,
        Forward::Forward,
        FilterType::LargestObject,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(ep.active_track_status_count(), 2);
}

// ============================================================
// Publish flow (publisher side)
// ============================================================

/// Client sends PUBLISH, gets request ID.
#[test]
fn endpoint_publish_allocates_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, msg) = ep
        .publish(
            ns.clone(),
            b"video".to_vec(),
            VarInt::from_u64(7).unwrap(),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .expect("publish should succeed");

    assert_eq!(req_id.into_inner() % 2, 0);
    assert_eq!(ep.active_publish_count(), 1);

    match msg {
        ControlMessage::Publish(p) => {
            assert_eq!(p.request_id, req_id);
            assert_eq!(p.track_namespace, ns);
            assert_eq!(p.track_name, b"video".to_vec());
        }
        _ => panic!("expected Publish message"),
    }
}

/// PUBLISH_OK transitions to Active.
#[test]
fn endpoint_receive_publish_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep
        .publish(
            ns,
            b"video".to_vec(),
            VarInt::from_u64(7).unwrap(),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();

    let ok = message::PublishOk {
        request_id: req_id,
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).expect("should accept publish ok");
}

/// send_publish_done transitions Active publish to Done.
#[test]
fn endpoint_send_publish_done_for_publish() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep
        .publish(
            ns,
            b"video".to_vec(),
            VarInt::from_u64(7).unwrap(),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();

    let ok = message::PublishOk {
        request_id: req_id,
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).unwrap();

    let msg = ep
        .send_publish_done(req_id, VarInt::from_u64(0).unwrap(), b"done".to_vec())
        .expect("should generate publish done");
    match msg {
        ControlMessage::PublishDone(pd) => {
            assert_eq!(pd.request_id, req_id);
        }
        _ => panic!("expected PublishDone message"),
    }
}

/// PUBLISH_ERROR on publisher-side publishes transitions to Done.
#[test]
fn endpoint_receive_publish_error_for_publish() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep
        .publish(
            ns,
            b"video".to_vec(),
            VarInt::from_u64(7).unwrap(),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();

    let err = message::PublishError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"rejected".to_vec(),
    };
    ep.receive_publish_error(&err).expect("should accept publish error");
}

/// A PUBLISH_ERROR does not refuse a SUBSCRIBE.
///
/// A SUBSCRIBE is refused with SUBSCRIBE_ERROR, which has a handler of its own
/// that reaches the same record. A PUBLISH_ERROR handler that fell through to
/// this endpoint's subscriptions would answer a message the peer had no reason
/// to send and hide one it should have been told about.
#[test]
fn endpoint_receive_publish_error_does_not_refuse_a_subscribe() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();

    let err = message::PublishError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"nope".to_vec(),
    };
    let refused = ep.receive_publish_error(&err);
    assert!(
        matches!(refused, Err(EndpointError::UnknownRequest(_))),
        "a PUBLISH_ERROR names an offer this endpoint made, and a SUBSCRIBE is not one; \
         instead: {refused:?}"
    );

    // The message that does refuse it still does, and reaches the same record.
    let subscribe_err = message::SubscribeError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"nope".to_vec(),
    };
    ep.receive_subscribe_error(&subscribe_err).expect("SUBSCRIBE_ERROR refuses a SUBSCRIBE");
}

/// A PUBLISH_ERROR naming nothing is refused, as its sibling answer is.
///
/// The two answers to one offer must agree about an unknown identifier:
/// `receive_publish_ok` returns `UnknownRequest` for one, and so does this,
/// which the second half of the gate checks.
#[test]
fn endpoint_receive_publish_error_unknown_id_is_refused() {
    let mut ep = make_active_client_with_max_id(10);
    let err = message::PublishError {
        request_id: VarInt::from_u64(99).unwrap(),
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"nope".to_vec(),
    };
    let refused = ep.receive_publish_error(&err);
    assert!(
        matches!(refused, Err(EndpointError::UnknownRequest(99))),
        "no offer was made under that identifier, and instead: {refused:?}"
    );

    let ok = message::PublishOk {
        request_id: VarInt::from_u64(99).unwrap(),
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: Vec::new(),
    };
    let other = ep.receive_publish_ok(&ok);
    assert!(
        matches!(other, Err(EndpointError::UnknownRequest(99))),
        "the two answers to one offer must agree about an unknown id, and instead: {other:?}"
    );
}

/// active_publish_count reflects state.
#[test]
fn endpoint_publish_count() {
    let mut ep = make_active_client_with_max_id(10);
    assert_eq!(ep.active_publish_count(), 0);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    ep.publish(
        ns.clone(),
        b"v1".to_vec(),
        VarInt::from_u64(1).unwrap(),
        GroupOrder::Ascending,
        None,
        Forward::Forward,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(ep.active_publish_count(), 1);
    ep.publish(
        ns,
        b"v2".to_vec(),
        VarInt::from_u64(2).unwrap(),
        GroupOrder::Ascending,
        None,
        Forward::Forward,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(ep.active_publish_count(), 2);
}

// ============================================================
// Helper functions
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();
    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000014).unwrap(), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    ep
}

fn make_active_client_with_max_id(max_id: u64) -> Endpoint {
    let mut ep = make_active_client();
    let msg = MaxRequestId { request_id: VarInt::from_u64(max_id).unwrap() };
    ep.receive_max_request_id(&msg).unwrap();
    ep
}

fn make_active_server() -> Endpoint {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().unwrap();
    let client_setup = ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff000014).unwrap()],
        parameters: vec![],
    };
    ep.receive_client_setup_and_respond(&client_setup, VarInt::from_u64(0xff000014).unwrap())
        .unwrap();
    ep
}

fn make_active_server_with_max_id(max_id: u64) -> Endpoint {
    let mut ep = make_active_server();
    let msg = MaxRequestId { request_id: VarInt::from_u64(max_id).unwrap() };
    ep.receive_max_request_id(&msg).unwrap();
    ep
}

// ============================================================
// REQUESTS_BLOCKED (draft-14 Section 9.6)
// ============================================================

/// draft-14 Section 9.6: "The REQUESTS_BLOCKED message is sent when an endpoint
/// would like to send a new request, but cannot because the Request ID would
/// exceed the Maximum Request ID value sent by the peer."
#[test]
fn endpoint_send_requests_blocked() {
    let ep = make_active_client();
    let msg = ep.send_requests_blocked().expect("should generate requests blocked");
    match msg {
        ControlMessage::RequestsBlocked(rb) => {
            assert_eq!(rb.maximum_request_id, VarInt::from_u64(0).unwrap());
        }
        _ => panic!("expected RequestsBlocked message"),
    }
}

/// Draft-14 Section 9.6: REQUESTS_BLOCKED reports the ceiling the peer set.
/// A ceiling of 10 is one past the largest usable ID, so a client gets the
/// five IDs 0, 2, 4, 6 and 8, and 10 itself is out of reach.
#[test]
fn endpoint_send_requests_blocked_after_max_update() {
    let mut ep = make_active_client_with_max_id(10);
    // Exhaust all IDs: 0, 2, 4, 6, 8
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    for i in 0..5 {
        let name = format!("t{i}");
        ep.subscribe(
            ns.clone(),
            name.into_bytes(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .unwrap();
    }
    assert!(ep.is_blocked());

    let msg = ep.send_requests_blocked().unwrap();
    match msg {
        ControlMessage::RequestsBlocked(rb) => {
            assert_eq!(rb.maximum_request_id, VarInt::from_u64(10).unwrap());
        }
        _ => panic!("expected RequestsBlocked message"),
    }
}

/// draft-14 Section 9.6: "An endpoint MAY send a MAX_REQUEST_ID upon receipt of
/// REQUESTS_BLOCKED", so receiving one is not itself an error.
#[test]
fn endpoint_receive_message_dispatches_requests_blocked() {
    let mut ep = make_active_server();
    let msg = ControlMessage::RequestsBlocked(RequestsBlocked {
        maximum_request_id: VarInt::from_u64(5).unwrap(),
    });
    ep.receive_message(msg).expect("dispatch should succeed");
}

// ============================================================
// send_max_request_id monotonic enforcement
// ============================================================

/// draft-14 Section 9.5: "The Maximum Request ID MUST only increase within a
/// session." The rule binds the sender as well as the receiver.
#[test]
fn endpoint_send_max_request_id_cannot_decrease() {
    let mut ep = make_active_server();
    ep.send_max_request_id(VarInt::from_u64(20).unwrap()).unwrap();
    assert!(ep.send_max_request_id(VarInt::from_u64(10).unwrap()).is_err());
}

/// draft-14 Section 9.5: "receipt of a MAX_REQUEST_ID message with an equal or
/// smaller Request ID value is a PROTOCOL_VIOLATION" — equal counts.
#[test]
fn endpoint_send_max_request_id_cannot_stay_same() {
    let mut ep = make_active_server();
    ep.send_max_request_id(VarInt::from_u64(20).unwrap()).unwrap();
    assert!(ep.send_max_request_id(VarInt::from_u64(20).unwrap()).is_err());
}

/// draft-14 Section 9.5: "An endpoint sends a MAX_REQUEST_ID message to increase
/// the number of requests the peer can send within a session."
#[test]
fn endpoint_send_max_request_id_can_increase() {
    let mut ep = make_active_server();
    ep.send_max_request_id(VarInt::from_u64(10).unwrap()).unwrap();
    ep.send_max_request_id(VarInt::from_u64(20).unwrap()).expect("increasing max should succeed");
}

// ============================================================
// SERVER_SETUP MAX_REQUEST_ID parameter extraction
// ============================================================

/// draft-14 Section 9.3.2.3: "The MAX_REQUEST_ID parameter (Parameter Type 0x02)
/// communicates an initial value for the Maximum Request ID to the receiving
/// endpoint." It
/// initializes the request ID allocator.
#[test]
fn endpoint_server_setup_with_max_request_id_param() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();

    let server_setup = ServerSetup {
        selected_version: VarInt::from_u64(0xff000014).unwrap(),
        parameters: vec![KeyValuePair {
            key: VarInt::from_u64(0x02).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(10).unwrap()),
        }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    assert_eq!(ep.session_state(), SessionState::Active);

    // Should be able to subscribe immediately (no separate MAX_REQUEST_ID needed)
    assert!(!ep.is_blocked());
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"track1".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .expect("subscribe should succeed with setup-granted max request id");
    assert_eq!(req_id.into_inner(), 0);
}

/// draft-14 Section 9.3.2.3: "The default value is 0, so if not specified, the
/// peer MUST NOT send requests." A SERVER_SETUP without the parameter
/// leaves endpoint blocked.
#[test]
fn endpoint_server_setup_without_max_request_id_stays_blocked() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();

    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000014).unwrap(), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

/// draft-14: Mid-session MAX_REQUEST_ID update after setup-granted initial max.
#[test]
fn endpoint_mid_session_max_request_id_update() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions, vec![]).unwrap();

    // Server grants an initial ceiling of 4 via the setup parameter, which is
    // one past the largest usable ID and so leaves the client 0 and 2.
    let server_setup = ServerSetup {
        selected_version: VarInt::from_u64(0xff000014).unwrap(),
        parameters: vec![KeyValuePair {
            key: VarInt::from_u64(0x02).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(4).unwrap()),
        }],
    };
    ep.receive_server_setup(&server_setup).unwrap();

    // Use up IDs 0 and 2
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    ep.subscribe(
        ns.clone(),
        b"t1".to_vec(),
        128,
        GroupOrder::Ascending,
        FilterType::NextGroupStart,
        Vec::new(),
    )
    .unwrap();
    ep.subscribe(
        ns.clone(),
        b"t2".to_vec(),
        128,
        GroupOrder::Ascending,
        FilterType::NextGroupStart,
        Vec::new(),
    )
    .unwrap();

    // Should now be blocked
    assert!(ep.is_blocked());

    // Mid-session update from server increases the limit
    let max_msg = MaxRequestId { request_id: VarInt::from_u64(10).unwrap() };
    ep.receive_max_request_id(&max_msg).unwrap();

    // Now unblocked, can allocate more
    assert!(!ep.is_blocked());
    let (req_id, _) = ep
        .subscribe(
            ns,
            b"t3".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
            Vec::new(),
        )
        .expect("subscribe should succeed after mid-session max increase");
    assert_eq!(req_id.into_inner(), 4);
}

// ============================================================
// PUBLISH_ERROR (draft-14 Section 9.15)
// ============================================================

/// draft-14 Section 9.15: "The subscriber sends a PUBLISH_ERROR control message
/// to reject a subscription initiated by PUBLISH."
///
/// The subscription has to have been initiated: this endpoint answers the
/// PUBLISH it received, and Section 5.1 gives it exactly one answer to give.
#[test]
fn endpoint_send_publish_error() {
    let mut ep = make_active_server();
    ep.receive_publish(&message::Publish {
        request_id: VarInt::from_u64(0).unwrap(),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"track".to_vec(),
        track_alias: VarInt::from_u64(1).unwrap(),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        forward: Forward::Forward,
        parameters: vec![],
    })
    .expect("the peer's PUBLISH");
    let msg = ep
        .send_publish_error(
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0x01).unwrap(),
            b"could not publish".to_vec(),
        )
        .expect("should generate publish error");
    match msg {
        ControlMessage::PublishError(pe) => {
            assert_eq!(pe.request_id, VarInt::from_u64(0).unwrap());
            assert_eq!(pe.error_code, VarInt::from_u64(0x01).unwrap());
            assert_eq!(pe.reason_phrase, b"could not publish".to_vec());
        }
        _ => panic!("expected PublishError message"),
    }
}

/// draft-14 Section 9.15: PUBLISH_ERROR carries "the Request ID of the PUBLISH
/// this message is replying to", and this endpoint sent no such PUBLISH.
#[test]
fn endpoint_receive_message_dispatches_publish_error() {
    let mut ep = make_active_client();
    let msg = ControlMessage::PublishError(message::PublishError {
        request_id: VarInt::from_u64(99).unwrap(),
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"rejected".to_vec(),
    });
    // Section 9.15 opens "The subscriber sends a PUBLISH_ERROR control message
    // to reject a subscription initiated by PUBLISH", and an identifier this
    // endpoint made no PUBLISH under names no such subscription. The doc above
    // said as much while this line asserted the opposite.
    let refused = ep.receive_message(msg);
    assert!(
        matches!(refused, Err(EndpointError::UnknownRequest(99))),
        "there is no subscription under that identifier to reject, and instead: {refused:?}"
    );
}

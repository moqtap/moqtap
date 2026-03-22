use moqtap_client::endpoint::*;
use moqtap_client::session::request_id::Role;
use moqtap_client::session::state::SessionState;
use moqtap_codec::draft14::message::{self, *};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

// ============================================================
// Construction and initial state
// ============================================================

/// draft-14 section 4: An endpoint starts in Connecting state.
#[test]
fn endpoint_new_client_starts_in_connecting() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.session_state(), SessionState::Connecting);
}

/// draft-14 section 4: Server endpoint starts in Connecting state.
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

/// draft-14 section 4: Connecting -> SetupExchange on connect.
#[test]
fn endpoint_connect_transitions_to_setup_exchange() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().expect("connect should succeed");
    assert_eq!(ep.session_state(), SessionState::SetupExchange);
}

/// draft-14 section 4: Double connect is an error.
#[test]
fn endpoint_connect_twice_fails() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    assert!(ep.connect().is_err());
}

/// draft-14 section 4.1: Client generates CLIENT_SETUP message.
#[test]
fn endpoint_client_generates_setup_message() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()]; // draft-14
    let msg = ep.send_client_setup(versions.clone()).expect("should generate setup");
    match msg {
        ControlMessage::ClientSetup(cs) => {
            assert_eq!(cs.supported_versions, versions);
        }
        _ => panic!("expected ClientSetup message"),
    }
}

/// draft-14 section 4.2: Client processes SERVER_SETUP, transitions to Active.
#[test]
fn endpoint_client_receives_server_setup() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions).unwrap();

    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000014).unwrap(), parameters: vec![] };
    ep.receive_server_setup(&server_setup).expect("should accept server setup");
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// draft-14 section 4.2: Server setup with unknown version is rejected.
#[test]
fn endpoint_rejects_server_setup_version_mismatch() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions).unwrap();

    let server_setup =
        ServerSetup { selected_version: VarInt::from_u64(0xff000099).unwrap(), parameters: vec![] };
    assert!(ep.receive_server_setup(&server_setup).is_err());
}

// ============================================================
// MAX_REQUEST_ID
// ============================================================

/// draft-14 section 5.1: Endpoint receives MAX_REQUEST_ID to allow requests.
#[test]
fn endpoint_receive_max_request_id() {
    let mut ep = make_active_client();
    let msg = MaxRequestId { request_id: VarInt::from_u64(10).unwrap() };
    ep.receive_max_request_id(&msg).expect("should accept max request id");
}

/// draft-14 section 5.1: MAX_REQUEST_ID can only increase.
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

/// draft-14 section 6.4: Client sends SUBSCRIBE, gets request ID.
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

/// draft-14 section 6.4: Subscribe fails when session is not active.
#[test]
fn endpoint_subscribe_requires_active_session() {
    let mut ep = Endpoint::new(Role::Client);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .is_err());
}

/// draft-14 section 6.4: Subscribe fails when blocked (no request IDs available).
#[test]
fn endpoint_subscribe_fails_when_blocked() {
    let mut ep = make_active_client(); // max_id = 0, blocked
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .is_err());
}

/// draft-14 section 6.4: SUBSCRIBE_OK transitions subscription to Active.
#[test]
fn endpoint_receive_subscribe_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
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

/// draft-14 section 6.4: SUBSCRIBE_OK for unknown request ID fails.
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

/// draft-14 section 6.4: SUBSCRIBE_ERROR transitions subscription to Done.
#[test]
fn endpoint_receive_subscribe_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .unwrap();

    let err = SubscribeError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x04).unwrap(),
        reason_phrase: b"track not found".to_vec(),
    };
    ep.receive_subscribe_error(&err).expect("should accept subscribe error");
}

/// draft-14 section 6.4: UNSUBSCRIBE transitions Active subscription to Done.
#[test]
fn endpoint_unsubscribe() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
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

/// draft-14 section 6.4: Unsubscribe for unknown request ID fails.
#[test]
fn endpoint_unsubscribe_unknown_id() {
    let mut ep = make_active_client_with_max_id(10);
    assert!(ep.unsubscribe(VarInt::from_u64(42).unwrap()).is_err());
}

/// draft-14 section 6.8: PUBLISH_DONE transitions Active subscription to Done.
#[test]
fn endpoint_receive_publish_done() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
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
        reason_phrase: b"normal".to_vec(),
    };
    ep.receive_publish_done(&done).expect("should accept publish done");
}

/// draft-14 section 6.4: Multiple concurrent subscriptions each get unique IDs.
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
        )
        .unwrap();
    let (id2, _) = ep
        .subscribe(ns, b"track2".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .unwrap();

    assert_ne!(id1, id2);
    assert_eq!(ep.active_subscription_count(), 2);
}

// ============================================================
// Fetch flow
// ============================================================

/// draft-14 section 6.9: Client sends FETCH, gets request ID.
#[test]
fn endpoint_fetch_allocates_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, msg) = ep
        .fetch(
            ns.clone(),
            b"segment1".to_vec(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
        )
        .expect("fetch should succeed");

    assert_eq!(req_id.into_inner() % 2, 0);
    assert_eq!(ep.active_fetch_count(), 1);

    match msg {
        ControlMessage::Fetch(f) => {
            assert_eq!(f.request_id, req_id);
            assert_eq!(f.track_namespace, ns);
            assert_eq!(f.track_name, b"segment1".to_vec());
        }
        _ => panic!("expected Fetch message"),
    }
}

/// draft-14 section 6.9: Fetch fails when session is not active.
#[test]
fn endpoint_fetch_requires_active_session() {
    let mut ep = Endpoint::new(Role::Client);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    assert!(ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .is_err());
}

/// draft-14 section 6.9: FETCH_OK transitions fetch to Receiving.
#[test]
fn endpoint_receive_fetch_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .unwrap();

    let ok = FetchOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        end_of_track: VarInt::from_u64(0).unwrap(),
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).expect("should accept fetch ok");
}

/// draft-14 section 6.9: FETCH_ERROR transitions fetch to Done.
#[test]
fn endpoint_receive_fetch_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .unwrap();

    let err = message::FetchError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x04).unwrap(),
        reason_phrase: b"not found".to_vec(),
    };
    ep.receive_fetch_error(&err).expect("should accept fetch error");
}

/// draft-14 section 6.9: FETCH_CANCEL transitions fetch to Done.
#[test]
fn endpoint_fetch_cancel() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .unwrap();

    let msg = ep.fetch_cancel(req_id).expect("fetch cancel should succeed");
    match msg {
        ControlMessage::FetchCancel(fc) => {
            assert_eq!(fc.request_id, req_id);
        }
        _ => panic!("expected FetchCancel message"),
    }
}

/// draft-14 section 6.9: Fetch cancel for unknown request ID fails.
#[test]
fn endpoint_fetch_cancel_unknown_id() {
    let mut ep = make_active_client_with_max_id(10);
    assert!(ep.fetch_cancel(VarInt::from_u64(42).unwrap()).is_err());
}

/// draft-14 section 6.9: Stream FIN transitions Receiving fetch to Done.
#[test]
fn endpoint_fetch_stream_fin() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .unwrap();

    let ok = FetchOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        end_of_track: VarInt::from_u64(0).unwrap(),
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).unwrap();

    ep.on_fetch_stream_fin(req_id).expect("stream fin should succeed");
}

/// draft-14 section 6.9: Stream RESET transitions Receiving fetch to Done.
#[test]
fn endpoint_fetch_stream_reset() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    let (req_id, _) = ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .unwrap();

    let ok = FetchOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        end_of_track: VarInt::from_u64(0).unwrap(),
        parameters: vec![],
    };
    ep.receive_fetch_ok(&ok).unwrap();

    ep.on_fetch_stream_reset(req_id).expect("stream reset should succeed");
}

// ============================================================
// Subscribe Namespace flow
// ============================================================

/// draft-14 section 6.11: Client sends SUBSCRIBE_NAMESPACE.
#[test]
fn endpoint_subscribe_namespace() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, msg) =
        ep.subscribe_namespace(ns.clone()).expect("subscribe namespace should succeed");

    assert_eq!(ep.active_subscribe_namespace_count(), 1);

    match msg {
        ControlMessage::SubscribeNamespace(sn) => {
            assert_eq!(sn.request_id, req_id);
            assert_eq!(sn.track_namespace, ns);
        }
        _ => panic!("expected SubscribeNamespace message"),
    }
}

/// draft-14 section 6.11: SUBSCRIBE_NAMESPACE_OK transitions to Active.
#[test]
fn endpoint_receive_subscribe_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns).unwrap();

    let ok = SubscribeNamespaceOk { request_id: req_id, parameters: vec![] };
    ep.receive_subscribe_namespace_ok(&ok).expect("should accept subscribe namespace ok");
}

/// draft-14 section 6.11: SUBSCRIBE_NAMESPACE_ERROR transitions to Done.
#[test]
fn endpoint_receive_subscribe_namespace_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns).unwrap();

    let err = SubscribeNamespaceError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"unauthorized".to_vec(),
    };
    ep.receive_subscribe_namespace_error(&err).expect("should accept subscribe namespace error");
}

/// draft-14 section 6.11: UNSUBSCRIBE_NAMESPACE transitions Active to Done.
#[test]
fn endpoint_unsubscribe_namespace() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns.clone()).unwrap();

    let ok = SubscribeNamespaceOk { request_id: req_id, parameters: vec![] };
    ep.receive_subscribe_namespace_ok(&ok).unwrap();

    let msg =
        ep.unsubscribe_namespace(req_id, ns.clone()).expect("unsubscribe namespace should succeed");
    match msg {
        ControlMessage::UnsubscribeNamespace(unsub) => {
            assert_eq!(unsub.request_id, req_id);
        }
        _ => panic!("expected UnsubscribeNamespace message"),
    }
}

// ============================================================
// Publish Namespace flow
// ============================================================

/// draft-14 section 6.12: Client sends PUBLISH_NAMESPACE.
#[test]
fn endpoint_publish_namespace() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, msg) = ep.publish_namespace(ns.clone()).expect("publish namespace should succeed");

    assert_eq!(ep.active_publish_namespace_count(), 1);

    match msg {
        ControlMessage::PublishNamespace(pn) => {
            assert_eq!(pn.request_id, req_id);
            assert_eq!(pn.track_namespace, ns);
        }
        _ => panic!("expected PublishNamespace message"),
    }
}

/// draft-14 section 6.12: PUBLISH_NAMESPACE_OK transitions to Active.
#[test]
fn endpoint_receive_publish_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns).unwrap();

    let ok = PublishNamespaceOk { request_id: req_id, parameters: vec![] };
    ep.receive_publish_namespace_ok(&ok).expect("should accept publish namespace ok");
}

/// draft-14 section 6.12: PUBLISH_NAMESPACE_ERROR transitions to Done.
#[test]
fn endpoint_receive_publish_namespace_error() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns).unwrap();

    let err = PublishNamespaceError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"unauthorized".to_vec(),
    };
    ep.receive_publish_namespace_error(&err).expect("should accept publish namespace error");
}

/// draft-14 section 6.12: PUBLISH_NAMESPACE_DONE transitions Active to Done.
#[test]
fn endpoint_receive_publish_namespace_done() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns).unwrap();

    let ok = PublishNamespaceOk { request_id: req_id, parameters: vec![] };
    ep.receive_publish_namespace_ok(&ok).unwrap();

    let done = PublishNamespaceDone {
        request_id: req_id,
        status_code: VarInt::from_u64(0).unwrap(),
        reason_phrase: b"done".to_vec(),
    };
    ep.receive_publish_namespace_done(&done).expect("should accept publish namespace done");
}

/// draft-14 section 6.12: PUBLISH_NAMESPACE_CANCEL transitions Active to Done.
#[test]
fn endpoint_publish_namespace_cancel() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns).unwrap();

    let ok = PublishNamespaceOk { request_id: req_id, parameters: vec![] };
    ep.receive_publish_namespace_ok(&ok).unwrap();

    let msg =
        ep.publish_namespace_cancel(req_id, b"cancelled".to_vec()).expect("cancel should succeed");
    match msg {
        ControlMessage::PublishNamespaceCancel(c) => {
            assert_eq!(c.request_id, req_id);
        }
        _ => panic!("expected PublishNamespaceCancel message"),
    }
}

// ============================================================
// GoAway and session draining
// ============================================================

/// draft-14 section 4.6: GOAWAY transitions Active session to Draining.
#[test]
fn endpoint_receive_goaway() {
    let mut ep = make_active_client();
    let goaway = GoAway { new_session_uri: b"https://new.example.com".to_vec() };
    ep.receive_goaway(&goaway).expect("goaway should succeed");
    assert_eq!(ep.session_state(), SessionState::Draining);
}

/// draft-14 section 4.6: GOAWAY when not active fails.
#[test]
fn endpoint_receive_goaway_not_active() {
    let mut ep = Endpoint::new(Role::Client);
    let goaway = GoAway { new_session_uri: b"https://new.example.com".to_vec() };
    assert!(ep.receive_goaway(&goaway).is_err());
}

/// draft-14 section 4.6: GoAway URI is stored for reconnection.
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

/// draft-14 section 4: Active session can be closed.
#[test]
fn endpoint_close_from_active() {
    let mut ep = make_active_client();
    ep.close().expect("close should succeed");
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// draft-14 section 4: Draining session can be closed.
#[test]
fn endpoint_close_from_draining() {
    let mut ep = make_active_client();
    let goaway = GoAway { new_session_uri: vec![] };
    ep.receive_goaway(&goaway).unwrap();
    ep.close().expect("close from draining should succeed");
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// draft-14 section 4: Connecting session cannot be closed directly.
#[test]
fn endpoint_close_from_connecting_fails() {
    let mut ep = Endpoint::new(Role::Client);
    assert!(ep.close().is_err());
}

// ============================================================
// Operations during draining
// ============================================================

/// draft-14 section 4.6: New subscriptions are blocked during draining.
#[test]
fn endpoint_subscribe_blocked_during_draining() {
    let mut ep = make_active_client_with_max_id(10);
    let goaway = GoAway { new_session_uri: vec![] };
    ep.receive_goaway(&goaway).unwrap();

    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    assert!(ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .is_err());
}

/// draft-14 section 4.6: New fetches are blocked during draining.
#[test]
fn endpoint_fetch_blocked_during_draining() {
    let mut ep = make_active_client_with_max_id(10);
    let goaway = GoAway { new_session_uri: vec![] };
    ep.receive_goaway(&goaway).unwrap();

    let ns = TrackNamespace(vec![b"vod".to_vec()]);
    assert!(ep
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
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
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
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
        .fetch(ns, b"seg".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
        .unwrap();

    let ok_msg = ControlMessage::FetchOk(FetchOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        end_of_track: VarInt::from_u64(0).unwrap(),
        parameters: vec![],
    });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

/// draft-14: receive_message dispatches SUBSCRIBE_NAMESPACE_OK correctly.
#[test]
fn endpoint_receive_message_dispatches_subscribe_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep.subscribe_namespace(ns).unwrap();

    let ok_msg = ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk {
        request_id: req_id,
        parameters: vec![],
    });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

/// draft-14: receive_message dispatches PUBLISH_NAMESPACE_OK correctly.
#[test]
fn endpoint_receive_message_dispatches_publish_namespace_ok() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish_namespace(ns).unwrap();

    let ok_msg = ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
        request_id: req_id,
        parameters: vec![],
    });
    ep.receive_message(ok_msg).expect("dispatch should succeed");
}

// ============================================================
// Server-side endpoint
// ============================================================

/// draft-14 section 4.2: Server generates SERVER_SETUP.
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

/// draft-14 section 5.1: Server sends MAX_REQUEST_ID.
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
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
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
        .subscribe(ns, b"track".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .is_err());
}

/// Negotiated version is accessible after setup.
#[test]
fn endpoint_negotiated_version() {
    let mut ep = Endpoint::new(Role::Client);
    assert_eq!(ep.negotiated_version(), None);

    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions).unwrap();

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
        )
        .unwrap();
    let (id2, _) = ep
        .subscribe(
            ns.clone(),
            b"t2".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
        )
        .unwrap();
    let (id3, _) = ep
        .fetch(ns, b"t3".to_vec(), VarInt::from_u64(0).unwrap(), VarInt::from_u64(0).unwrap())
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

/// draft-14 section 6.4: SUBSCRIBE_UPDATE on active subscription stays active.
#[test]
fn endpoint_receive_subscribe_update_on_active_subscription() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
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

/// draft-14 section 6.4: SUBSCRIBE_UPDATE for unknown request ID fails.
#[test]
fn endpoint_receive_subscribe_update_unknown_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let update = SubscribeUpdate {
        request_id: VarInt::from_u64(42).unwrap(),
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

// ============================================================
// Track Status flow
// ============================================================

/// Client sends TRACK_STATUS, gets request ID.
#[test]
fn endpoint_track_status_allocates_request_id() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, msg) =
        ep.track_status(ns.clone(), b"track1".to_vec()).expect("track_status should succeed");

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
    let (req_id, _) = ep.track_status(ns, b"track1".to_vec()).unwrap();

    let ok = message::TrackStatusOk {
        request_id: req_id,
        status_code: VarInt::from_u64(0).unwrap(),
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
    let (req_id, _) = ep.track_status(ns, b"track1".to_vec()).unwrap();

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
        status_code: VarInt::from_u64(0).unwrap(),
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
    ep.track_status(ns.clone(), b"t1".to_vec()).unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    ep.track_status(ns, b"t2".to_vec()).unwrap();
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
        .publish(ns.clone(), b"video".to_vec(), Forward::Forward)
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
    let (req_id, _) = ep.publish(ns, b"video".to_vec(), Forward::Forward).unwrap();

    let ok = message::PublishOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        forward: Forward::Forward,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).expect("should accept publish ok");
}

/// send_publish_done transitions Active publish to Done.
#[test]
fn endpoint_send_publish_done_for_publish() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    let (req_id, _) = ep.publish(ns, b"video".to_vec(), Forward::Forward).unwrap();

    let ok = message::PublishOk {
        request_id: req_id,
        track_alias: VarInt::from_u64(1).unwrap(),
        forward: Forward::Forward,
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
    let (req_id, _) = ep.publish(ns, b"video".to_vec(), Forward::Forward).unwrap();

    let err = message::PublishError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"rejected".to_vec(),
    };
    ep.receive_publish_error(&err).expect("should accept publish error");
}

/// PUBLISH_ERROR falls through to subscription if no publish found.
#[test]
fn endpoint_receive_publish_error_falls_through_to_subscription() {
    let mut ep = make_active_client_with_max_id(10);
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    let (req_id, _) = ep
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .unwrap();

    let err = message::PublishError {
        request_id: req_id,
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"nope".to_vec(),
    };
    ep.receive_publish_error(&err).expect("should fall through to subscription");
}

/// PUBLISH_ERROR for unknown ID is silently ignored.
#[test]
fn endpoint_receive_publish_error_unknown_id_graceful() {
    let mut ep = make_active_client_with_max_id(10);
    let err = message::PublishError {
        request_id: VarInt::from_u64(99).unwrap(),
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"nope".to_vec(),
    };
    ep.receive_publish_error(&err).expect("should silently ignore unknown id");
}

/// active_publish_count reflects state.
#[test]
fn endpoint_publish_count() {
    let mut ep = make_active_client_with_max_id(10);
    assert_eq!(ep.active_publish_count(), 0);
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    ep.publish(ns.clone(), b"v1".to_vec(), Forward::Forward).unwrap();
    assert_eq!(ep.active_publish_count(), 1);
    ep.publish(ns, b"v2".to_vec(), Forward::Forward).unwrap();
    assert_eq!(ep.active_publish_count(), 2);
}

// ============================================================
// Helper functions
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions).unwrap();
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
// REQUESTS_BLOCKED (draft-14 §6.3.2)
// ============================================================

/// draft-14 section 6.3.2: Endpoint generates REQUESTS_BLOCKED with current max.
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

/// draft-14 section 6.3.2: REQUESTS_BLOCKED reports the peer's current max after update.
#[test]
fn endpoint_send_requests_blocked_after_max_update() {
    let mut ep = make_active_client_with_max_id(10);
    // Exhaust all IDs: 0, 2, 4, 6, 8, 10
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    for i in 0..6 {
        let name = format!("t{i}");
        ep.subscribe(
            ns.clone(),
            name.into_bytes(),
            128,
            GroupOrder::Ascending,
            FilterType::NextGroupStart,
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

/// draft-14 section 6.3.2: receive_message dispatches REQUESTS_BLOCKED.
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

/// draft-14 section 6.3.1: Server cannot send MAX_REQUEST_ID with a decreased value.
#[test]
fn endpoint_send_max_request_id_cannot_decrease() {
    let mut ep = make_active_server();
    ep.send_max_request_id(VarInt::from_u64(20).unwrap()).unwrap();
    assert!(ep.send_max_request_id(VarInt::from_u64(10).unwrap()).is_err());
}

/// draft-14 section 6.3.1: Server cannot send MAX_REQUEST_ID with the same value.
#[test]
fn endpoint_send_max_request_id_cannot_stay_same() {
    let mut ep = make_active_server();
    ep.send_max_request_id(VarInt::from_u64(20).unwrap()).unwrap();
    assert!(ep.send_max_request_id(VarInt::from_u64(20).unwrap()).is_err());
}

/// draft-14 section 6.3.1: Server can increase MAX_REQUEST_ID monotonically.
#[test]
fn endpoint_send_max_request_id_can_increase() {
    let mut ep = make_active_server();
    ep.send_max_request_id(VarInt::from_u64(10).unwrap()).unwrap();
    ep.send_max_request_id(VarInt::from_u64(20).unwrap()).expect("increasing max should succeed");
}

// ============================================================
// SERVER_SETUP MAX_REQUEST_ID parameter extraction
// ============================================================

/// draft-14 section 6.1.2: SERVER_SETUP with MAX_REQUEST_ID parameter (key 0x02)
/// initializes the request ID allocator.
#[test]
fn endpoint_server_setup_with_max_request_id_param() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions).unwrap();

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
        .subscribe(ns, b"track1".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .expect("subscribe should succeed with setup-granted max request id");
    assert_eq!(req_id.into_inner(), 0);
}

/// draft-14 section 6.1.2: SERVER_SETUP without MAX_REQUEST_ID parameter
/// leaves endpoint blocked.
#[test]
fn endpoint_server_setup_without_max_request_id_stays_blocked() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![VarInt::from_u64(0xff000014).unwrap()];
    ep.send_client_setup(versions).unwrap();

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
    ep.send_client_setup(versions).unwrap();

    // Server grants initial MAX_REQUEST_ID of 2 via setup parameter
    let server_setup = ServerSetup {
        selected_version: VarInt::from_u64(0xff000014).unwrap(),
        parameters: vec![KeyValuePair {
            key: VarInt::from_u64(0x02).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(2).unwrap()),
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
    )
    .unwrap();
    ep.subscribe(
        ns.clone(),
        b"t2".to_vec(),
        128,
        GroupOrder::Ascending,
        FilterType::NextGroupStart,
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
        .subscribe(ns, b"t3".to_vec(), 128, GroupOrder::Ascending, FilterType::NextGroupStart)
        .expect("subscribe should succeed after mid-session max increase");
    assert_eq!(req_id.into_inner(), 4);
}

// ============================================================
// PUBLISH_ERROR (draft-14 §6.5.3)
// ============================================================

/// draft-14 section 6.5.3: Endpoint generates PUBLISH_ERROR message.
#[test]
fn endpoint_send_publish_error() {
    let ep = make_active_server();
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

/// draft-14 section 6.5.3: receive_message dispatches PUBLISH_ERROR.
#[test]
fn endpoint_receive_message_dispatches_publish_error() {
    let mut ep = make_active_client();
    let msg = ControlMessage::PublishError(message::PublishError {
        request_id: VarInt::from_u64(99).unwrap(),
        error_code: VarInt::from_u64(0x01).unwrap(),
        reason_phrase: b"rejected".to_vec(),
    });
    // Should not fail even for unknown request IDs (graceful handling)
    ep.receive_message(msg).expect("dispatch should succeed");
}

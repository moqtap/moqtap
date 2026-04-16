#![cfg(feature = "draft17")]

//! Draft-17 endpoint tests.
//!
//! Differences from earlier-draft tests:
//!   * Single SETUP message replaces CLIENT_SETUP / SERVER_SETUP.
//!   * Response messages (`SubscribeOk`, `PublishOk`, `FetchOk`,
//!     `PublishDone`, `RequestOk`, `RequestError`) do NOT carry a
//!     `request_id` — they arrive on the request's bidi stream and are
//!     delivered via `receive_response_on_stream(request_id, msg)`.
//!   * No UNSUBSCRIBE, FETCH_CANCEL, MAX_REQUEST_ID, REQUESTS_BLOCKED,
//!     PUBLISH_NAMESPACE_DONE, or PUBLISH_NAMESPACE_CANCEL.
//!   * Request-producing messages carry `required_request_id_delta`.

use moqtap_client::draft17::endpoint::{Endpoint, EndpointError};
use moqtap_client::draft17::session::request_id::Role;
use moqtap_client::draft17::session::state::SessionState;
use moqtap_codec::draft17::message::{
    ControlMessage, FetchOk, Namespace, NamespaceDone, PublishBlocked, PublishDone, PublishOk,
    RequestError, RequestOk, RequestUpdate, Setup, SubscribeOk,
};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|s| s.to_vec()).collect())
}

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_setup(vec![]).unwrap();
    ep.receive_setup(&Setup { options: vec![] }).unwrap();
    assert_eq!(ep.session_state(), SessionState::Active);
    ep
}

fn req_ok() -> ControlMessage {
    ControlMessage::RequestOk(RequestOk { parameters: vec![] })
}

fn req_err() -> ControlMessage {
    ControlMessage::RequestError(RequestError {
        error_code: varint(1),
        retry_interval: varint(0),
        reason_phrase: b"nope".to_vec(),
    })
}

fn sub_ok() -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        track_alias: varint(42),
        parameters: vec![],
        track_properties: vec![],
    })
}

// ============================================================
// Session lifecycle
// ============================================================

#[test]
fn endpoint_starts_in_connecting() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.session_state(), SessionState::Connecting);
}

#[test]
fn endpoint_setup_activates_session() {
    let ep = make_active_client();
    assert_eq!(ep.session_state(), SessionState::Active);
}

#[test]
fn endpoint_server_role() {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().unwrap();
    ep.receive_setup(&Setup { options: vec![] }).unwrap();
    let _ = ep.send_setup(vec![]).unwrap();
    assert_eq!(ep.session_state(), SessionState::Active);
}

#[test]
fn endpoint_goaway_transitions_to_draining() {
    let mut ep = make_active_client();
    ep.receive_message(ControlMessage::GoAway(moqtap_codec::draft17::message::GoAway {
        new_session_uri: b"bye".to_vec(),
        timeout: varint(0),
    }))
    .unwrap();
    assert_eq!(ep.session_state(), SessionState::Draining);
    assert_eq!(ep.goaway_uri(), Some(b"bye".as_slice()));
}

#[test]
fn endpoint_draining_rejects_new_subscribe() {
    let mut ep = make_active_client();
    ep.receive_message(ControlMessage::GoAway(moqtap_codec::draft17::message::GoAway {
        new_session_uri: b"bye".to_vec(),
        timeout: varint(0),
    }))
    .unwrap();
    let err = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap_err();
    assert!(matches!(err, EndpointError::Draining));
}

// ============================================================
// Request ID allocation
// ============================================================

#[test]
fn endpoint_client_even_request_ids() {
    let mut ep = make_active_client();
    let (id0, _) = ep.subscribe(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap();
    let (id1, _) = ep.subscribe(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap();
    assert_eq!(id0.into_inner() % 2, 0);
    assert_eq!(id1.into_inner() % 2, 0);
    assert!(id1.into_inner() > id0.into_inner());
}

// ============================================================
// Subscribe flow
// ============================================================

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    assert_eq!(ep.active_subscription_count(), 0);
    let (_id, msg) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    assert!(matches!(msg, ControlMessage::Subscribe(_)));
    assert_eq!(ep.active_subscription_count(), 1);
}

#[test]
fn endpoint_subscribe_ok_routes_by_request_id() {
    let mut ep = make_active_client();
    let (id, _) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, sub_ok()).unwrap();
}

#[test]
fn endpoint_subscribe_ok_for_unknown_stream_errors() {
    let mut ep = make_active_client();
    let err = ep.receive_response_on_stream(varint(999), sub_ok()).unwrap_err();
    assert!(matches!(err, EndpointError::UnknownRequest(999)));
}

#[test]
fn endpoint_response_on_control_stream_rejected() {
    let mut ep = make_active_client();
    let err = ep.receive_message(sub_ok()).unwrap_err();
    assert!(matches!(err, EndpointError::ResponseOnControlStream));
}

#[test]
fn endpoint_request_error_routes_to_subscribe() {
    let mut ep = make_active_client();
    let (id, _) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, req_err()).unwrap();
}

#[test]
fn endpoint_request_update_references_by_request_id() {
    let mut ep = make_active_client();
    let (id, _) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, sub_ok()).unwrap();
    let upd = ControlMessage::RequestUpdate(RequestUpdate {
        request_id: id,
        required_request_id_delta: varint(0),
        parameters: vec![],
    });
    ep.receive_message(upd).unwrap();
}

#[test]
fn endpoint_publish_done_ends_subscription() {
    let mut ep = make_active_client();
    let (id, _) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, sub_ok()).unwrap();
    let done = ControlMessage::PublishDone(PublishDone {
        status_code: varint(0),
        stream_count: varint(1),
        reason_phrase: b"ok".to_vec(),
    });
    ep.receive_response_on_stream(id, done).unwrap();
}

// ============================================================
// Fetch flow
// ============================================================

#[test]
fn endpoint_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (_id, msg) =
        ep.fetch(ns(&[b"a"]), b"t".to_vec(), varint(0), varint(0), varint(10), varint(5)).unwrap();
    assert!(matches!(msg, ControlMessage::Fetch(_)));
    assert_eq!(ep.active_fetch_count(), 1);
}

#[test]
fn endpoint_fetch_ok_routes_by_request_id() {
    let mut ep = make_active_client();
    let (id, _) =
        ep.fetch(ns(&[b"a"]), b"t".to_vec(), varint(0), varint(0), varint(10), varint(5)).unwrap();
    let ok = ControlMessage::FetchOk(FetchOk {
        end_of_track: 0,
        end_group: varint(10),
        end_object: varint(5),
        parameters: vec![],
        track_properties: vec![],
    });
    ep.receive_response_on_stream(id, ok).unwrap();
}

#[test]
fn endpoint_joining_fetch_allocates() {
    let mut ep = make_active_client();
    let (_id, msg) = ep.joining_fetch(varint(0), varint(0)).unwrap();
    assert!(matches!(msg, ControlMessage::Fetch(_)));
}

// ============================================================
// Out-of-order responses (d17 responses on independent bidi streams)
// ============================================================

#[test]
fn endpoint_out_of_order_responses_route_correctly() {
    let mut ep = make_active_client();
    let (sub_id, _) = ep.subscribe(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap();
    let (fetch_id, _) =
        ep.fetch(ns(&[b"a"]), b"t".to_vec(), varint(0), varint(0), varint(1), varint(1)).unwrap();

    // Fetch response first, then subscribe response — fine because each is
    // addressed by its own request_id.
    let fetch_ok = ControlMessage::FetchOk(FetchOk {
        end_of_track: 0,
        end_group: varint(1),
        end_object: varint(1),
        parameters: vec![],
        track_properties: vec![],
    });
    ep.receive_response_on_stream(fetch_id, fetch_ok).unwrap();
    ep.receive_response_on_stream(sub_id, sub_ok()).unwrap();
}

// ============================================================
// Publish flow
// ============================================================

#[test]
fn endpoint_publish_allocates() {
    let mut ep = make_active_client();
    let (_id, msg) = ep.publish(ns(&[b"a"]), b"t".to_vec(), varint(0), vec![], vec![]).unwrap();
    assert!(matches!(msg, ControlMessage::Publish(_)));
    assert_eq!(ep.active_publish_count(), 1);
}

#[test]
fn endpoint_publish_ok_activates() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"a"]), b"t".to_vec(), varint(0), vec![], vec![]).unwrap();
    ep.receive_response_on_stream(id, ControlMessage::PublishOk(PublishOk { parameters: vec![] }))
        .unwrap();
}

#[test]
fn endpoint_send_publish_done() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"a"]), b"t".to_vec(), varint(0), vec![], vec![]).unwrap();
    ep.receive_response_on_stream(id, ControlMessage::PublishOk(PublishOk { parameters: vec![] }))
        .unwrap();
    let msg = ep.send_publish_done(id, varint(0), varint(1), b"ok".to_vec()).unwrap();
    assert!(matches!(msg, ControlMessage::PublishDone(_)));
}

// ============================================================
// Namespace flows
// ============================================================

#[test]
fn endpoint_publish_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (id, msg) = ep.publish_namespace(ns(&[b"a"]), vec![]).unwrap();
    assert!(matches!(msg, ControlMessage::PublishNamespace(_)));
    ep.receive_response_on_stream(id, req_ok()).unwrap();
}

#[test]
fn endpoint_subscribe_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (id, msg) = ep.subscribe_namespace(ns(&[b"x"]), varint(2), vec![]).unwrap();
    match &msg {
        ControlMessage::SubscribeNamespace(sn) => {
            assert_eq!(sn.subscribe_options.into_inner(), 2);
        }
        _ => panic!("expected SubscribeNamespace"),
    }
    ep.receive_response_on_stream(id, req_ok()).unwrap();
}

#[test]
fn endpoint_request_ok_routes_to_correct_flow() {
    let mut ep = make_active_client();
    let (_sub, _) = ep.subscribe(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap();
    let (pn_id, _) = ep.publish_namespace(ns(&[b"a"]), vec![]).unwrap();
    // REQUEST_OK addressed to the publish_namespace request only affects it.
    ep.receive_response_on_stream(pn_id, req_ok()).unwrap();
}

#[test]
fn endpoint_namespace_announcement_is_informational() {
    let mut ep = make_active_client();
    ep.receive_message(ControlMessage::Namespace(Namespace { namespace_suffix: ns(&[b"x"]) }))
        .unwrap();
    ep.receive_message(ControlMessage::NamespaceDone(NamespaceDone {
        namespace_suffix: ns(&[b"x"]),
    }))
    .unwrap();
}

#[test]
fn endpoint_publish_blocked_is_informational() {
    let mut ep = make_active_client();
    ep.receive_message(ControlMessage::PublishBlocked(PublishBlocked {
        namespace_suffix: ns(&[b"x"]),
        track_name: b"t".to_vec(),
    }))
    .unwrap();
}

// ============================================================
// Track Status
// ============================================================

#[test]
fn endpoint_track_status_request_and_ok() {
    let mut ep = make_active_client();
    let (id, msg) = ep.track_status(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap();
    assert!(matches!(msg, ControlMessage::TrackStatus(_)));
    ep.receive_response_on_stream(id, req_ok()).unwrap();
}

// ============================================================
// Error path coverage
// ============================================================

#[test]
fn endpoint_subscribe_before_active_fails() {
    let mut ep = Endpoint::new(Role::Client);
    let err = ep.subscribe(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap_err();
    assert!(matches!(err, EndpointError::NotActive));
}

#[test]
fn endpoint_request_error_for_unknown_stream_fails() {
    let mut ep = make_active_client();
    let err = ep.receive_response_on_stream(varint(999), req_err()).unwrap_err();
    assert!(matches!(err, EndpointError::UnknownRequest(999)));
}

#[test]
fn endpoint_request_ok_for_unknown_stream_fails() {
    let mut ep = make_active_client();
    let err = ep.receive_response_on_stream(varint(999), req_ok()).unwrap_err();
    assert!(matches!(err, EndpointError::UnknownRequest(999)));
}

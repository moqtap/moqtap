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
//!   * `Namespace`, `NamespaceDone` and `PublishBlocked` arrive on the
//!     SUBSCRIBE_NAMESPACE request stream they report on, not on the
//!     control stream.

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

/// A REQUEST_UPDATE names its target by the stream it arrives on, not by the
/// Request ID in its own body.
///
/// Draft-17 Section 9.1 has REQUEST_UPDATE consume a Request ID of its own, and
/// Section 9.10 puts it "on the same bidi stream as the request to modify it".
/// The update below therefore carries an id (`update_id`) that names no request
/// at all, and still has to land on the subscription whose stream it came in on.
#[test]
fn endpoint_request_update_is_correlated_by_the_stream_not_by_its_own_id() {
    let mut ep = make_active_client();
    let (id, _) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, sub_ok()).unwrap();

    let update_id = varint(id.into_inner() + 100);
    let upd = ControlMessage::RequestUpdate(RequestUpdate {
        request_id: update_id,
        required_request_id_delta: varint(0),
        parameters: vec![],
    });
    ep.receive_response_on_stream(id, upd).unwrap();
}

/// The control stream is not where a REQUEST_UPDATE belongs, and receiving one
/// there is refused without ending the session.
///
/// Section 9.10 gives the stream the job of naming the request being modified,
/// so an update with no request stream around it identifies nothing.
///
/// # Why the refusal is not a close
///
/// Section 3.3's opener sentence does not reach this: it is about what a
/// bidirectional stream may *begin* with, and a message on the control stream
/// begins nothing. Draft-17 Section 9.10 says only where a conforming sender
/// puts a REQUEST_UPDATE — "The sender of a request (SUBSCRIBE, PUBLISH, FETCH,
/// PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE) can later send a REQUEST_UPDATE on
/// the same bidi stream as the request to modify it." — and attaches no
/// consequence to one that arrives elsewhere. Draft-19 is the first to add one.
/// So a close here would be this crate's model of the protocol rather than
/// draft-17's, and the refusal, which needs no sentence, is what is left.
#[test]
fn endpoint_request_update_on_the_control_stream_is_refused_without_closing() {
    use moqtap_client::draft17::endpoint::EndpointError;

    let mut ep = make_active_client();
    let (id, _) = ep.subscribe(ns(&[b"a"]), b"trk".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, sub_ok()).unwrap();

    let upd = ControlMessage::RequestUpdate(RequestUpdate {
        request_id: id,
        required_request_id_delta: varint(0),
        parameters: vec![],
    });
    let err = ep.receive_message(upd).unwrap_err();
    assert!(matches!(err, EndpointError::RequestUpdateOnControlStream), "got {err:?}");
    assert_eq!(err.session_error_code(), None, "draft-17 states no close for this");
    assert_eq!(ep.session_state(), moqtap_client::draft17::session::state::SessionState::Active);
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
    let (_id, msg) = ep
        .fetch(ns(&[b"a"]), b"t".to_vec(), varint(0), varint(0), varint(10), varint(5), Vec::new())
        .unwrap();
    assert!(matches!(msg, ControlMessage::Fetch(_)));
    assert_eq!(ep.active_fetch_count(), 1);
}

#[test]
fn endpoint_fetch_ok_routes_by_request_id() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .fetch(ns(&[b"a"]), b"t".to_vec(), varint(0), varint(0), varint(10), varint(5), Vec::new())
        .unwrap();
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
    let (_id, msg) = ep.joining_fetch(varint(0), varint(0), Vec::new()).unwrap();
    assert!(matches!(msg, ControlMessage::Fetch(_)));
}

// ============================================================
// Out-of-order responses (d17 responses on independent bidi streams)
// ============================================================

#[test]
fn endpoint_out_of_order_responses_route_correctly() {
    let mut ep = make_active_client();
    let (sub_id, _) = ep.subscribe(ns(&[b"a"]), b"t".to_vec(), vec![]).unwrap();
    let (fetch_id, _) = ep
        .fetch(ns(&[b"a"]), b"t".to_vec(), varint(0), varint(0), varint(1), varint(1), Vec::new())
        .unwrap();

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

/// A NAMESPACE and a NAMESPACE_DONE report namespaces on the
/// SUBSCRIBE_NAMESPACE stream that asked for them, and they only report: the
/// request the stream carries is left where it was.
///
/// Draft-17 Section 9.18 says NAMESPACE "is sent on the response stream of a
/// SUBSCRIBE_NAMESPACE request", and Section 9.19 that "All NAMESPACE_DONE
/// messages are in response to a SUBSCRIBE_NAMESPACE". Section 9.20 fixes what
/// they follow: "If the subscriber receives any frame other than a REQUEST_OK
/// or a REQUEST_ERROR as the first frame on the response half of the stream,
/// then it MUST close the session with a PROTOCOL_VIOLATION", so the
/// announcements come after the REQUEST_OK, which is how this drives them.
///
/// That REQUEST_OK is also what makes the flow's state readable: it leaves the
/// flow Active, and a second REQUEST_OK is then refused *from wherever the flow
/// now is*, naming that state in the error. So the last assertion reads back
/// the state the announcements left behind, which is the whole claim.
///
/// # What this catches, observed by making each change and running it
///
/// Dropping the NAMESPACE arm from `Endpoint::receive_response_on_stream`, so
/// the announcement falls through to the catch-all:
///
/// ```text
/// NAMESPACE belongs on the SUBSCRIBE_NAMESPACE stream: ResponseOnControlStream
/// ```
///
/// Giving that arm a state edge — ending the namespace subscription instead of
/// reporting on it — so the message is still accepted but no longer
/// informational:
///
/// ```text
/// the announcements moved the SUBSCRIBE_NAMESPACE flow: namespace error: invalid transition from Done on event on_subscribe_namespace_ok
/// ```
#[test]
fn endpoint_namespace_announcement_is_informational() {
    use moqtap_client::draft17::namespace::NamespaceError;

    let mut ep = make_active_client();
    let (id, _) = ep.subscribe_namespace(ns(&[b"x"]), varint(2), vec![]).unwrap();
    ep.receive_response_on_stream(id, req_ok()).unwrap();

    ep.receive_response_on_stream(
        id,
        ControlMessage::Namespace(Namespace { namespace_suffix: ns(&[b"y"]) }),
    )
    .expect("NAMESPACE belongs on the SUBSCRIBE_NAMESPACE stream");
    ep.receive_response_on_stream(
        id,
        ControlMessage::NamespaceDone(NamespaceDone { namespace_suffix: ns(&[b"y"]) }),
    )
    .expect("NAMESPACE_DONE belongs on the SUBSCRIBE_NAMESPACE stream");

    assert_eq!(ep.session_state(), SessionState::Active);
    assert_eq!(ep.active_subscribe_namespace_count(), 1);

    let err = ep.receive_response_on_stream(id, req_ok()).unwrap_err();
    assert!(
        matches!(
            &err,
            EndpointError::Namespace(NamespaceError::InvalidTransition { from, .. })
                if from == "Active"
        ),
        "the announcements moved the SUBSCRIBE_NAMESPACE flow: {err}"
    );
}

/// A PUBLISH_BLOCKED names a track on the same stream, and is informational in
/// the same sense.
///
/// Draft-17 Section 9.21: "All PUBLISH_BLOCKED messages are in response to a
/// SUBSCRIBE_NAMESPACE" — this draft has no SUBSCRIBE_TRACKS, the request
/// draft-18 moved it onto, so on draft-17 it shares the one stream with the two
/// announcements above. The state is read back the same way.
///
/// # What this catches, observed by making each change and running it
///
/// Dropping the PUBLISH_BLOCKED arm from
/// `Endpoint::receive_response_on_stream`:
///
/// ```text
/// PUBLISH_BLOCKED belongs on the SUBSCRIBE_NAMESPACE stream: ResponseOnControlStream
/// ```
///
/// Giving that arm a state edge, ending the namespace subscription the blocked
/// track was reported under:
///
/// ```text
/// PUBLISH_BLOCKED moved the SUBSCRIBE_NAMESPACE flow: namespace error: invalid transition from Done on event on_subscribe_namespace_ok
/// ```
#[test]
fn endpoint_publish_blocked_is_informational() {
    use moqtap_client::draft17::namespace::NamespaceError;

    let mut ep = make_active_client();
    let (id, _) = ep.subscribe_namespace(ns(&[b"x"]), varint(2), vec![]).unwrap();
    ep.receive_response_on_stream(id, req_ok()).unwrap();

    ep.receive_response_on_stream(
        id,
        ControlMessage::PublishBlocked(PublishBlocked {
            namespace_suffix: ns(&[b"y"]),
            track_name: b"t".to_vec(),
        }),
    )
    .expect("PUBLISH_BLOCKED belongs on the SUBSCRIBE_NAMESPACE stream");

    assert_eq!(ep.session_state(), SessionState::Active);
    assert_eq!(ep.active_subscribe_namespace_count(), 1);

    let err = ep.receive_response_on_stream(id, req_ok()).unwrap_err();
    assert!(
        matches!(
            &err,
            EndpointError::Namespace(NamespaceError::InvalidTransition { from, .. })
                if from == "Active"
        ),
        "PUBLISH_BLOCKED moved the SUBSCRIBE_NAMESPACE flow: {err}"
    );
}

/// None of the three belongs on the control stream, and one arriving there ends
/// the session.
///
/// The sections above give each of them one place, and it is a request stream;
/// a copy on the control stream names no request, so there is nothing it could
/// be reporting on. The live SUBSCRIBE_NAMESPACE is what rules out the weaker
/// reading of the refusal — it is not "no such request", because the request
/// exists and its stream is open.
///
/// A fresh endpoint per message because the first refusal closes the session.
///
/// # What this catches, observed by making the change and running it
///
/// Adding a control-stream arm that accepts a NAMESPACE there
/// (`ControlMessage::Namespace(ref m) => self.receive_namespace(m)`):
///
/// ```text
/// NAMESPACE must be refused on the control stream
/// ```
#[test]
fn endpoint_namespace_announcements_on_the_control_stream_are_refused() {
    // The name is the one the endpoint reports the refusal under, so each pair
    // also gates the message against the wrong name.
    let cases = [
        ("NAMESPACE", ControlMessage::Namespace(Namespace { namespace_suffix: ns(&[b"y"]) })),
        (
            "NAMESPACE_DONE",
            ControlMessage::NamespaceDone(NamespaceDone { namespace_suffix: ns(&[b"y"]) }),
        ),
        (
            "PUBLISH_BLOCKED",
            ControlMessage::PublishBlocked(PublishBlocked {
                namespace_suffix: ns(&[b"y"]),
                track_name: b"t".to_vec(),
            }),
        ),
    ];

    for (name, msg) in cases {
        let mut ep = make_active_client();
        let (id, _) = ep.subscribe_namespace(ns(&[b"x"]), varint(2), vec![]).unwrap();
        ep.receive_response_on_stream(id, req_ok()).unwrap();

        let err = match ep.receive_message(msg) {
            Err(e) => e,
            Ok(()) => panic!("{name} must be refused on the control stream"),
        };
        assert!(
            matches!(err, EndpointError::RequestMessageOnControlStream(m) if m == name),
            "{name} on the control stream gave {err}"
        );
        // Refused, and the session runs on: draft-17 states no close for a
        // message arriving on a stream it does not belong on, so a close here
        // would be this crate's reading rather than the draft's. See
        // `endpoint_request_update_on_the_control_stream_is_refused_without_closing`.
        assert_eq!(err.session_error_code(), None, "draft-17 states no close for this");
        assert_eq!(ep.session_state(), SessionState::Active);
    }
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

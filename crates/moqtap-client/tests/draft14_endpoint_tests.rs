#![cfg(feature = "draft14")]

use moqtap_client::draft14::endpoint::*;
use moqtap_client::draft14::session::request_id::Role;
use moqtap_client::draft14::session::state::SessionState;
use moqtap_codec::draft14::message::{self, *};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|p| p.to_vec()).collect())
}

// ============================================================
// Construction and initial state
// ============================================================

#[test]
fn endpoint_starts_in_connecting() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.role(), Role::Client);
    assert_eq!(ep.session_state(), SessionState::Connecting);
    assert_eq!(ep.active_subscription_count(), 0);
    assert_eq!(ep.active_fetch_count(), 0);
    assert_eq!(ep.active_subscribe_namespace_count(), 0);
    assert_eq!(ep.active_publish_namespace_count(), 0);
    assert_eq!(ep.active_track_status_count(), 0);
    assert_eq!(ep.active_publish_count(), 0);
}

#[test]
fn endpoint_server_role() {
    let ep = Endpoint::new(Role::Server);
    assert_eq!(ep.role(), Role::Server);
}

// ============================================================
// Session lifecycle
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
    let server_setup = ServerSetup {
        selected_version: varint(0xff00000e),
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    // A peer may not open a request until this endpoint has granted it a
    // budget: a peer's Request ID is measured against the maximum this
    // endpoint advertised, and that starts at 0.
    let _ = ep.send_max_request_id(varint(100)).unwrap();
    ep
}

fn make_active_server() -> Endpoint {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().unwrap();
    let client_setup =
        ClientSetup { supported_versions: vec![varint(0xff00000e)], parameters: vec![] };
    let _ = ep.receive_client_setup_and_respond(&client_setup, varint(0xff00000e)).unwrap();
    ep
}

#[test]
fn endpoint_connect_transitions_to_setup_exchange() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    assert_eq!(ep.session_state(), SessionState::SetupExchange);
}

#[test]
fn endpoint_receive_server_setup_activates_session() {
    let ep = make_active_client();
    assert_eq!(ep.session_state(), SessionState::Active);
    assert_eq!(ep.negotiated_version(), Some(varint(0xff00000e)));
    assert!(!ep.is_blocked());
}

#[test]
fn endpoint_server_setup_activates_session() {
    let ep = make_active_server();
    assert_eq!(ep.session_state(), SessionState::Active);
    assert_eq!(ep.negotiated_version(), Some(varint(0xff00000e)));
}

#[test]
fn endpoint_blocked_without_max_request_id() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff00000e), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

#[test]
fn endpoint_server_setup_wrong_version_fails() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff000099), parameters: vec![] };
    assert!(ep.receive_server_setup(&server_setup).is_err());
}

// ============================================================
// Subscribe flow
// ============================================================

fn default_subscribe(ep: &mut Endpoint, track: &[u8]) -> (VarInt, ControlMessage) {
    ep.subscribe(
        ns(&[b"ns"]),
        track.to_vec(),
        0,
        GroupOrder::Publisher,
        FilterType::LargestObject,
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_subscribe(&mut ep, b"trk");
    // Client uses even IDs, starts at 0
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_subscription_count(), 1);
    match &msg {
        ControlMessage::Subscribe(s) => {
            assert_eq!(s.request_id, id);
            assert_eq!(s.track_namespace.0, vec![b"ns".to_vec()]);
            assert_eq!(s.track_name, b"trk");
            assert_eq!(s.group_order, GroupOrder::Publisher);
            assert_eq!(s.filter_type, FilterType::LargestObject);
            assert_eq!(s.forward, Forward::Forward);
        }
        _ => panic!("expected Subscribe"),
    }
}

fn subscribe_ok_for(id: VarInt, alias: VarInt) -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        request_id: id,
        track_alias: alias,
        expires: varint(0),
        group_order: GroupOrder::Publisher,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    })
}

#[test]
fn endpoint_subscribe_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(42))).unwrap();
}

#[test]
fn endpoint_subscribe_error_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    let err = ControlMessage::SubscribeError(SubscribeError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"nope".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

/// Section 9.10 sends a SUBSCRIBE_UPDATE from the subscriber to the publisher,
/// so one that arrives names a subscription the peer opened. The peer opens
/// one here first, because an update naming a subscription this endpoint
/// opened itself is a message no peer following the draft sends.
#[test]
fn endpoint_subscribe_update_via_dispatch() {
    let mut ep = make_active_client();
    let peers = varint(1);
    ep.receive_message(ControlMessage::Subscribe(message::Subscribe {
        request_id: peers,
        track_namespace: ns(&[b"ns"]),
        track_name: b"trk".to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    }))
    .unwrap();
    let upd = ControlMessage::SubscribeUpdate(SubscribeUpdate {
        // The update spends a Request ID of its own, so this is the peer's
        // second, not a free-standing number.
        request_id: varint(3),
        subscription_request_id: peers,
        start_location: Location { group: varint(0), object: varint(0) },
        end_group: varint(10),
        subscriber_priority: 5,
        forward: Forward::Forward,
        parameters: vec![],
    });
    ep.receive_message(upd).unwrap();
}

#[test]
fn endpoint_unsubscribe_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();
    let msg = ep.unsubscribe(id).unwrap();
    assert!(matches!(msg, ControlMessage::Unsubscribe(_)));
}

#[test]
fn endpoint_receive_publish_done_ends_subscription() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();
    let done = ControlMessage::PublishDone(PublishDone {
        request_id: id,
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: vec![],
    });
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_client_even_request_ids() {
    let mut ep = make_active_client();
    let (id0, _) = default_subscribe(&mut ep, b"a");
    let (id1, _) = default_subscribe(&mut ep, b"b");
    let (id2, _) = default_subscribe(&mut ep, b"c");
    assert_eq!(id0.into_inner(), 0);
    assert_eq!(id1.into_inner(), 2);
    assert_eq!(id2.into_inner(), 4);
}

// ============================================================
// Fetch flow (simplified in draft-14)
// ============================================================

fn default_fetch(ep: &mut Endpoint) -> (VarInt, ControlMessage) {
    ep.fetch(
        ns(&[b"ns"]),
        b"trk".to_vec(),
        128,
        GroupOrder::Ascending,
        varint(0),
        varint(0),
        varint(0),
        varint(0),
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn endpoint_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_fetch(&mut ep);
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_fetch_count(), 1);
    match &msg {
        ControlMessage::Fetch(f) => {
            assert_eq!(f.request_id, id);
            match &f.fetch_payload {
                message::FetchPayload::Standalone {
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    ..
                } => {
                    assert_eq!(track_namespace.0, vec![b"ns".to_vec()]);
                    assert_eq!(track_name, &b"trk".to_vec());
                    assert_eq!(*start_group, varint(0));
                    assert_eq!(*start_object, varint(0));
                }
                _ => panic!("expected standalone fetch payload"),
            }
        }
        _ => panic!("expected Fetch"),
    }
}

#[test]
fn endpoint_fetch_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_fetch_error_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let err = ControlMessage::FetchError(message::FetchError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"not found".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_fetch_cancel_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let msg = ep.fetch_cancel(id).unwrap();
    assert!(matches!(msg, ControlMessage::FetchCancel(_)));
}

#[test]
fn endpoint_fetch_stream_fin() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    ep.on_fetch_stream_fin(id).unwrap();
}

#[test]
fn endpoint_fetch_stream_reset() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        end_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    ep.on_fetch_stream_reset(id).unwrap();
}

// ============================================================
// Joining fetch
// ============================================================

/// A subscription for a joining fetch to attach itself to.
fn joined_subscription(ep: &mut Endpoint) -> VarInt {
    let (parent_id, _) = default_subscribe(ep, b"trk");
    ep.receive_message(subscribe_ok_for(parent_id, varint(1))).unwrap();
    parent_id
}

/// A Relative Joining Fetch names the subscription it joins and how far back
/// from its live edge to start, and nothing else: Section 9.16.2 has the
/// publisher take the track from the subscription.
#[test]
fn endpoint_joining_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    let parent_id = joined_subscription(&mut ep);

    let (fetch_id, msg) =
        ep.joining_fetch(0, GroupOrder::Publisher, parent_id, varint(2), Vec::new()).unwrap();
    assert_ne!(fetch_id.into_inner(), parent_id.into_inner());
    assert_eq!(ep.active_fetch_count(), 1);
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::RelativeJoining as u64);
            assert_eq!(f.subscriber_priority, 0);
            assert_eq!(f.group_order, GroupOrder::Publisher);
            match &f.fetch_payload {
                message::FetchPayload::Joining { joining_request_id, joining_start } => {
                    assert_eq!(*joining_request_id, parent_id);
                    assert_eq!(*joining_start, varint(2));
                }
                _ => panic!("expected Joining payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

/// The absolute form is a different Fetch Type and the same payload, because
/// Section 9.16.2.1 reads the one field two ways: "For a Relative Joining
/// Fetch, the publisher sets the Start Location to {Subscribe Largest
/// Location.Group - Joining Start, 0}", where "For an Absolute Joining Fetch,
/// the publisher sets the Start Location to Joining Start."
#[test]
fn endpoint_absolute_joining_fetch_names_the_group_it_starts_at() {
    let mut ep = make_active_client();
    let parent_id = joined_subscription(&mut ep);

    let (_, msg) = ep
        .absolute_joining_fetch(128, GroupOrder::Ascending, parent_id, varint(9), Vec::new())
        .unwrap();
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::AbsoluteJoining as u64);
            match &f.fetch_payload {
                message::FetchPayload::Joining { joining_start, .. } => {
                    assert_eq!(*joining_start, varint(9));
                }
                _ => panic!("expected Joining payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

/// A joining fetch under a Request ID this session has no subscription for is
/// still built, because Section 9.16.2 puts that refusal at the other end:
/// "If a publisher receives a Joining Fetch with a Request ID that does not
/// correspond to an existing Subscribe in the same session, it MUST respond
/// with a Fetch Error with code Invalid Joining Request ID."
#[test]
fn endpoint_joining_fetch_does_not_judge_the_request_it_joins() {
    let mut ep = make_active_client();
    let (fetch_id, _) =
        ep.joining_fetch(0, GroupOrder::Publisher, varint(40), varint(1), Vec::new()).unwrap();
    assert_eq!(ep.active_fetch_count(), 1);
    // And the fetch is a fetch like any other: it can be cancelled.
    ep.fetch_cancel(fetch_id).unwrap();
}

// ============================================================
// Publish flow (publisher side — new in draft-14)
// ============================================================

#[test]
fn endpoint_publish_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = ep
        .publish(
            ns(&[b"pub", b"alice"]),
            b"trk".to_vec(),
            varint(7),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_publish_count(), 1);
    match &msg {
        ControlMessage::Publish(p) => {
            assert_eq!(p.request_id, id);
            assert_eq!(p.track_namespace.0, vec![b"pub".to_vec(), b"alice".to_vec()]);
            assert_eq!(p.track_name, b"trk");
            assert_eq!(p.track_alias, varint(7));
            assert_eq!(p.forward, Forward::Forward);
        }
        _ => panic!("expected Publish"),
    }
}

#[test]
fn endpoint_publish_ok_activates_publish() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .publish(
            ns(&[b"pub"]),
            b"trk".to_vec(),
            varint(7),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();
    let ok = PublishOk {
        request_id: id,
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).unwrap();
}

#[test]
fn endpoint_publish_done_lifecycle() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .publish(
            ns(&[b"pub"]),
            b"trk".to_vec(),
            varint(7),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();
    let ok = PublishOk {
        request_id: id,
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).unwrap();
    let done = ep.send_publish_done(id, varint(0), vec![]).unwrap();
    assert!(matches!(done, ControlMessage::PublishDone(_)));
}

/// draft-14 Section 5.1: "The subscriber either accepts or rejects the
/// subscription using PUBLISH_OK or PUBLISH_ERROR." The offer has to exist
/// before it can be rejected, and rejecting it is what ends it.
#[test]
fn endpoint_send_publish_error() {
    let mut ep = make_active_client();
    ep.receive_publish(&Publish {
        request_id: varint(7),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"track".to_vec(),
        track_alias: varint(1),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        forward: Forward::Forward,
        parameters: vec![],
    })
    .expect("the peer's PUBLISH");
    let resp = ep.send_publish_error(varint(7), varint(3), b"denied".to_vec()).unwrap();
    match &resp {
        ControlMessage::PublishError(e) => {
            assert_eq!(e.error_code, varint(3));
            assert_eq!(e.reason_phrase, b"denied");
        }
        _ => panic!("expected PublishError"),
    }
    assert!(
        ep.send_publish_error(varint(7), varint(3), b"again".to_vec()).is_err(),
        "Section 5.1 allows exactly one answer to a PUBLISH"
    );
}

#[test]
fn endpoint_receive_publish_error_on_publish() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .publish(
            ns(&[b"pub"]),
            b"trk".to_vec(),
            varint(7),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();
    let err = message::PublishError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"rejected".to_vec(),
    };
    ep.receive_publish_error(&err).unwrap();
}

// ============================================================
// Publish Namespace flow (replaces Announce in draft-14)
// ============================================================

#[test]
fn endpoint_publish_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.publish_namespace(ns(&[b"pub", b"alice"]), vec![]).unwrap();
    assert_eq!(ep.active_publish_namespace_count(), 1);
    assert!(matches!(msg, ControlMessage::PublishNamespace(_)));

    let ok = ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_publish_namespace_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.publish_namespace(ns(&[b"pub"]), Vec::new()).unwrap();
    let err = ControlMessage::PublishNamespaceError(PublishNamespaceError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

/// Section 9.26: "The publisher sends the PUBLISH_NAMESPACE_DONE control
/// message to indicate its intent to stop serving new subscriptions for tracks
/// within the provided Track Namespace." The publisher here is the peer, so
/// what arrives ends the announcement the peer made and not one of this
/// endpoint's own.
#[test]
fn endpoint_publish_namespace_done() {
    let mut ep = make_active_client();
    ep.receive_publish_namespace(&PublishNamespace {
        request_id: varint(1),
        track_namespace: ns(&[b"pub"]),
        parameters: vec![],
    })
    .unwrap();
    ep.send_publish_namespace_ok(varint(1)).unwrap();
    let done = ControlMessage::PublishNamespaceDone(PublishNamespaceDone {
        track_namespace: ns(&[b"pub"]),
    });
    ep.receive_message(done).unwrap();
}

/// Section 8.4 names what a cancellation revokes: a namespace "it previously
/// responded PUBLISH_NAMESPACE_OK to". This endpoint responded, so the
/// announcement it revokes is the peer's.
#[test]
fn endpoint_publish_namespace_cancel() {
    let mut ep = make_active_client();
    ep.receive_publish_namespace(&PublishNamespace {
        request_id: varint(1),
        track_namespace: ns(&[b"pub"]),
        parameters: vec![],
    })
    .unwrap();
    ep.send_publish_namespace_ok(varint(1)).unwrap();
    let msg = ep.publish_namespace_cancel(ns(&[b"pub"]), varint(0), b"done".to_vec()).unwrap();
    assert!(matches!(msg, ControlMessage::PublishNamespaceCancel(_)));
}

#[test]
fn endpoint_unknown_publish_namespace_ok_rejected() {
    let mut ep = make_active_client();
    let ok = ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id: varint(999) });
    assert!(ep.receive_message(ok).is_err());
}

// ============================================================
// Subscribe Namespace flow
// ============================================================

#[test]
fn endpoint_subscribe_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.subscribe_namespace(ns(&[b"prefix"]), vec![]).unwrap();
    assert_eq!(ep.active_subscribe_namespace_count(), 1);
    assert!(matches!(msg, ControlMessage::SubscribeNamespace(_)));

    let ok = ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();

    let unsub = ep.unsubscribe_namespace(req_id, ns(&[b"prefix"])).unwrap();
    assert!(matches!(unsub, ControlMessage::UnsubscribeNamespace(_)));
}

#[test]
fn endpoint_subscribe_namespace_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.subscribe_namespace(ns(&[b"prefix"]), vec![]).unwrap();
    let err = ControlMessage::SubscribeNamespaceError(SubscribeNamespaceError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

// ============================================================
// Track Status flow (simplified in draft-14)
// ============================================================

#[test]
fn endpoint_track_status_request_and_ok() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep
        .track_status(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    assert!(matches!(msg, ControlMessage::TrackStatus(_)));

    let reply = ControlMessage::TrackStatusOk(TrackStatusOk {
        request_id: req_id,
        track_alias: varint(0),
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_track_status_error_reply() {
    let mut ep = make_active_client();
    let (req_id, _) = ep
        .track_status(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
        .unwrap();
    let reply = ControlMessage::TrackStatusError(message::TrackStatusError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"not found".to_vec(),
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_unknown_track_status_ok_rejected() {
    let mut ep = make_active_client();
    let reply = ControlMessage::TrackStatusOk(TrackStatusOk {
        request_id: varint(999),
        track_alias: varint(0),
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    });
    assert!(ep.receive_message(reply).is_err());
}

// ============================================================
// GoAway
// ============================================================

#[test]
fn endpoint_goaway_transitions_to_draining() {
    let mut ep = make_active_client();
    let msg = GoAway { new_session_uri: b"https://new".to_vec() };
    ep.receive_goaway(&msg).unwrap();
    assert_eq!(ep.session_state(), SessionState::Draining);
    assert_eq!(ep.goaway_uri(), Some(b"https://new".as_slice()));
}

#[test]
fn endpoint_draining_rejects_new_subscribe() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.subscribe(
        ns(&[b"ns"]),
        b"trk".to_vec(),
        0,
        GroupOrder::Publisher,
        FilterType::LargestObject,
        Vec::new(),
    );
    assert!(matches!(result, Err(EndpointError::Draining)));
}

#[test]
fn endpoint_draining_rejects_new_publish() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.publish(
        ns(&[b"pub"]),
        b"trk".to_vec(),
        varint(7),
        GroupOrder::Ascending,
        None,
        Forward::Forward,
        Vec::new(),
    );
    assert!(matches!(result, Err(EndpointError::Draining)));
}

#[test]
fn endpoint_draining_rejects_new_fetch() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.fetch(
        ns(&[b"ns"]),
        b"trk".to_vec(),
        128,
        GroupOrder::Ascending,
        varint(0),
        varint(0),
        varint(0),
        varint(0),
        Vec::new(),
    );
    assert!(matches!(result, Err(EndpointError::Draining)));
}

// ============================================================
// MAX_REQUEST_ID
// ============================================================

#[test]
fn endpoint_max_request_id_monotonic_send() {
    let mut ep = make_active_client();
    let _ = ep.send_max_request_id(varint(200)).unwrap();
    let _ = ep.send_max_request_id(varint(300)).unwrap();
    assert!(ep.send_max_request_id(varint(200)).is_err());
}

#[test]
fn endpoint_receive_max_request_id_raises_limit() {
    let mut ep = make_active_client();
    ep.receive_max_request_id(&MaxRequestId { request_id: varint(1000) }).unwrap();
    assert!(!ep.is_blocked());
}

// ============================================================
// REQUESTS_BLOCKED
// ============================================================

#[test]
fn endpoint_send_requests_blocked() {
    let ep = make_active_client();
    let msg = ep.send_requests_blocked().unwrap();
    assert!(matches!(msg, ControlMessage::RequestsBlocked(_)));
}

#[test]
fn endpoint_receive_requests_blocked() {
    let ep = make_active_client();
    let msg = RequestsBlocked { maximum_request_id: varint(100) };
    ep.receive_requests_blocked(&msg).unwrap();
}

// ============================================================
// Close
// ============================================================

#[test]
fn endpoint_close_from_active() {
    let mut ep = make_active_client();
    ep.close().unwrap();
    assert_eq!(ep.session_state(), SessionState::Closed);
}

#[test]
fn endpoint_close_from_draining() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    ep.close().unwrap();
    assert_eq!(ep.session_state(), SessionState::Closed);
}

// ============================================================
// Mixed request ID allocation across flows
// ============================================================

#[test]
fn endpoint_mixed_flows_allocate_distinct_even_ids() {
    let mut ep = make_active_client();
    let (sub_id, _) = default_subscribe(&mut ep, b"trk");
    let (fetch_id, _) = default_fetch(&mut ep);
    let (pub_id, _) = ep
        .publish(
            ns(&[b"pub"]),
            b"trk".to_vec(),
            varint(7),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
        .unwrap();
    let (ns_id, _) = ep.publish_namespace(ns(&[b"pub"]), Vec::new()).unwrap();
    let (ts_id, _) = ep
        .track_status(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
        .unwrap();

    // Client uses even IDs: 0, 2, 4, 6, 8
    assert_eq!(sub_id.into_inner(), 0);
    assert_eq!(fetch_id.into_inner(), 2);
    assert_eq!(pub_id.into_inner(), 4);
    assert_eq!(ns_id.into_inner(), 6);
    assert_eq!(ts_id.into_inner(), 8);
}
/// A helper cannot hand back a SUBSCRIBE the encoder will not write.
///
/// `subscribe` carries no start location, so the two filters that name one are
/// refused there and served by `subscribe_range`, which derives the filter from
/// the range it was given. The gate drives the message all the way to bytes,
/// because the claim is not that the helper returned `Ok`, it is that a peer
/// can read what it returned.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping the guard from `Endpoint::subscribe`:
///
/// ```text
/// AbsoluteStart names a start location this call cannot carry: Ok((VarInt(0), Subscribe(Subscribe { request_id: VarInt(0), track_namespace: TrackNamespace([[110, 115]]), track_name: [116], subscriber_priority: 0, group_order: Publisher, forward: Forward, filter_type: AbsoluteStart, start_location: None, end_group: None, parameters: [] })))
/// ```
#[test]
fn endpoint_subscribe_refuses_a_filter_it_cannot_carry() {
    for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
        let mut ep = make_active_client();
        let got =
            ep.subscribe(ns(&[b"ns"]), b"t".to_vec(), 0, GroupOrder::Publisher, filter, Vec::new());
        assert!(
            matches!(got, Err(EndpointError::FilterNeedsRange)),
            "{filter:?} names a start location this call cannot carry: {got:?}"
        );
    }
}

/// And the range form builds one that encodes.
#[test]
fn endpoint_subscribe_range_builds_a_message_that_encodes() {
    for (end_group, expected) in
        [(None, FilterType::AbsoluteStart), (Some(varint(9)), FilterType::AbsoluteRange)]
    {
        let mut ep = make_active_client();
        let (_, msg) = ep
            .subscribe_range(
                ns(&[b"ns"]),
                b"t".to_vec(),
                0,
                GroupOrder::Publisher,
                Location { group: varint(3), object: varint(4) },
                end_group,
                Vec::new(),
            )
            .expect("the range form must build a message");
        match &msg {
            ControlMessage::Subscribe(s) => {
                assert_eq!(s.filter_type, expected, "the filter must follow the range");
            }
            other => panic!("expected SUBSCRIBE, got {other:?}"),
        }
        let mut out = Vec::new();
        msg.encode(&mut out).expect("and it must be one a peer can read");
    }
}

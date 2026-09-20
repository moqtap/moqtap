#![cfg(feature = "draft13")]

use moqtap_client::draft13::endpoint::*;
use moqtap_client::draft13::session::request_id::Role;
use moqtap_client::draft13::session::state::SessionState;
use moqtap_codec::draft13::message::{self, *};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|p| p.to_vec()).collect())
}

/// The Group Order a request sends when it has no preference.
fn group_order_original() -> GroupOrder {
    GroupOrder::Publisher
}

/// The Group Order a response sends. Every reply fixture here names a real
/// order rather than deferring, because a publisher that has settled on one is
/// what these tests are standing in for.
fn group_order_replied() -> GroupOrder {
    GroupOrder::Ascending
}

fn filter_largest_object() -> FilterType {
    FilterType::LargestObject
}

// ============================================================
// Construction and initial state
// ============================================================

#[test]
fn endpoint_starts_in_connecting() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.session_state(), SessionState::Connecting);
    assert_eq!(ep.active_subscription_count(), 0);
    assert_eq!(ep.active_fetch_count(), 0);
    assert_eq!(ep.active_subscribe_namespace_count(), 0);
    assert_eq!(ep.active_announce_count(), 0);
    assert_eq!(ep.active_track_status_count(), 0);
    assert_eq!(ep.pending_publish_count(), 0);
}

// ============================================================
// Session lifecycle
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![varint(0xff00000d)];
    let _ = ep.send_client_setup(versions, vec![]).unwrap();
    let server_setup = ServerSetup {
        selected_version: varint(0xff00000d),
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    // A peer may not open a request until this endpoint has granted it a
    // budget: a peer's Request ID is measured against the maximum this
    // endpoint advertised, and that starts at 0.
    let _ = ep.send_max_request_id(varint(100)).unwrap();
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
    assert_eq!(ep.negotiated_version(), Some(varint(0xff00000d)));
    assert!(!ep.is_blocked());
}

#[test]
fn endpoint_blocked_without_max_request_id() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000d)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff00000d), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

#[test]
fn endpoint_server_setup_wrong_version_fails() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000d)], vec![]).unwrap();
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
        group_order_original(),
        filter_largest_object(),
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_subscribe(&mut ep, b"trk");
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_subscription_count(), 1);
    assert!(matches!(msg, ControlMessage::Subscribe(_)));
}

fn subscribe_ok_for(id: VarInt, alias: VarInt) -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        request_id: id,
        track_alias: alias,
        expires: varint(0),
        group_order: group_order_replied(),
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    })
}

#[test]
fn endpoint_subscribe_ok_via_dispatch_records_alias() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(42))).unwrap();
    assert_eq!(ep.track_alias_for(id), Some(varint(42)));
}

#[test]
fn endpoint_subscribe_error_no_trailing_alias() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    let err = ControlMessage::SubscribeError(SubscribeError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"nope".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_subscribe_done_ends_subscription_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();

    let done = ControlMessage::SubscribeDone(SubscribeDone {
        request_id: id,
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: vec![],
    });
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_unsubscribe_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();
    let msg = ep.unsubscribe(id).unwrap();
    assert!(matches!(msg, ControlMessage::Unsubscribe(_)));
}

/// Section 8.1: a client's request IDs are the even ones and step by two,
/// so consecutive subscribes are 0, 2, 4 rather than 0, 1, 2.
#[test]
fn endpoint_monotonic_request_ids() {
    let mut ep = make_active_client();
    let (id0, _) = default_subscribe(&mut ep, b"a");
    let (id1, _) = default_subscribe(&mut ep, b"b");
    let (id2, _) = default_subscribe(&mut ep, b"c");
    assert_eq!(id0.into_inner(), 0);
    assert_eq!(id1.into_inner(), 2);
    assert_eq!(id2.into_inner(), 4);
}

// ============================================================
// Fetch flow
// ============================================================

fn default_fetch(ep: &mut Endpoint) -> (VarInt, ControlMessage) {
    ep.fetch(
        ns(&[b"ns"]),
        b"trk".to_vec(),
        0,
        group_order_original(),
        varint(0),
        varint(0),
        varint(10),
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
            assert_eq!(f.fetch_type as u64, FetchType::Standalone as u64);
            match &f.fetch_payload {
                FetchPayload::Standalone { track_namespace, track_name, .. } => {
                    assert_eq!(track_namespace.0, vec![b"ns".to_vec()]);
                    assert_eq!(track_name, b"trk");
                }
                _ => panic!("expected Standalone payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

#[test]
fn endpoint_fetch_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(message::FetchOk {
        request_id: id,
        group_order: group_order_replied(),
        end_of_track: 0,
        end_location: Location { group: varint(10), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_fetch_cancel_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let msg = ep.fetch_cancel(id).unwrap();
    assert!(matches!(msg, ControlMessage::FetchCancel(_)));
}

// ============================================================
// Announce flow
// ============================================================

#[test]
fn endpoint_announce_tracks_namespace() {
    let mut ep = make_active_client();
    let (_id, msg) = ep.announce(ns(&[b"pub", b"alice"]), vec![]).unwrap();
    assert_eq!(ep.active_announce_count(), 1);
    assert!(matches!(msg, ControlMessage::Announce(_)));
}

#[test]
fn endpoint_announce_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.announce(ns(&[b"pub", b"alice"]), vec![]).unwrap();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_unannounce_after_ok() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.announce(ns(&[b"pub", b"alice"]), vec![]).unwrap();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
    let msg = ep.unannounce(ns(&[b"pub", b"alice"])).unwrap();
    assert!(matches!(msg, ControlMessage::Unannounce(_)));
}

#[test]
fn endpoint_unknown_announce_request_id_rejected() {
    let mut ep = make_active_client();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { request_id: varint(999) });
    assert!(ep.receive_message(ok).is_err());
}

// ============================================================
// SubscribeNamespace flow (draft-12 spells the same request SUBSCRIBE_ANNOUNCES)
// ============================================================

#[test]
fn endpoint_subscribe_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.subscribe_namespace(ns(&[b"prefix"]), vec![]).unwrap();
    assert_eq!(ep.active_subscribe_namespace_count(), 1);
    let ok = ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
    let msg = ep.unsubscribe_namespace(ns(&[b"prefix"])).unwrap();
    assert!(matches!(msg, ControlMessage::UnsubscribeNamespace(_)));
}

// ============================================================
// Track status flow (restructured in draft-13)
// ============================================================

#[test]
fn endpoint_track_status_request_and_ok() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep
        .track_status(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            group_order_original(),
            Forward::Forward,
            filter_largest_object(),
            Vec::new(),
        )
        .unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    assert!(matches!(msg, ControlMessage::TrackStatus(_)));

    let reply = ControlMessage::TrackStatusOk(TrackStatusOk {
        request_id: req_id,
        track_alias: varint(10),
        expires: varint(0),
        group_order: group_order_replied(),
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
            0,
            group_order_original(),
            Forward::Forward,
            filter_largest_object(),
            Vec::new(),
        )
        .unwrap();
    let reply = ControlMessage::TrackStatusError(TrackStatusError {
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
        group_order: group_order_replied(),
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
        group_order_original(),
        filter_largest_object(),
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
fn endpoint_receive_requests_blocked_records_peer_max() {
    let mut ep = make_active_client();
    let msg = ControlMessage::RequestsBlocked(RequestsBlocked { maximum_request_id: varint(100) });
    ep.receive_message(msg).unwrap();
    assert_eq!(ep.peer_reported_max_request_id(), Some(varint(100)));
}

// ============================================================
// Joining fetch
// ============================================================

/// The relative form, at Fetch Type 0x2, is what a call named for it writes.
///
/// Cut and measured: the builder left reaching the absolute type gives
/// `left: 3` against `right: 2` here — the same mistake as the gate below in
/// the other direction, which is why both directions are gated rather than
/// one.
#[test]
fn endpoint_joining_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    // Open a parent subscription first
    let (parent_id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(parent_id, varint(1))).unwrap();

    // Issue a joining fetch against it
    let (fetch_id, msg) =
        ep.joining_fetch(0, group_order_original(), parent_id, varint(2), Vec::new()).unwrap();
    assert_ne!(fetch_id.into_inner(), parent_id.into_inner());
    assert_eq!(ep.active_fetch_count(), 1);
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::RelativeJoining as u64);
            match &f.fetch_payload {
                FetchPayload::Joining { joining_request_id, joining_start } => {
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
/// Section 8.16 reads the one field two ways: for a Relative Joining Fetch
/// "this value represents the group offset for the Fetch prior and relative to
/// the Current Group of the corresponding Subscribe", and "For an Absolute
/// Joining Fetch (0x3), this value represents the Starting Group ID."
///
/// Which of the two a call writes is settled by which call it is. There is no
/// Fetch Type to hand the endpoint, so this gate is what says the two calls
/// have not become one.
#[test]
fn endpoint_absolute_joining_fetch_names_the_group_it_starts_at() {
    let mut ep = make_active_client();
    let (parent_id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(parent_id, varint(1))).unwrap();

    let (_, msg) = ep
        .absolute_joining_fetch(128, GroupOrder::Ascending, parent_id, varint(9), Vec::new())
        .unwrap();
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::AbsoluteJoining as u64);
            match &f.fetch_payload {
                FetchPayload::Joining { joining_start, .. } => {
                    assert_eq!(*joining_start, varint(9));
                }
                _ => panic!("expected Joining payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

// ============================================================
// Publish flow
// ============================================================

fn make_publish(request_id: VarInt, alias: VarInt) -> Publish {
    Publish {
        request_id,
        track_namespace: ns(&[b"pub", b"alice"]),
        track_name: b"trk".to_vec(),
        track_alias: alias,
        group_order: group_order_replied(),
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        forward: Forward::Forward,
        parameters: vec![],
    }
}

#[test]
fn endpoint_receive_publish_records_pending() {
    let mut ep = make_active_client();
    let pub_msg = make_publish(varint(1), varint(42));
    ep.receive_message(ControlMessage::Publish(pub_msg.clone())).unwrap();
    assert_eq!(ep.pending_publish_count(), 1);
    let got = ep.pending_publish(varint(1)).expect("pending publish");
    assert_eq!(got.track_alias, varint(42));
    assert_eq!(got.track_name, b"trk");
}

#[test]
fn endpoint_send_publish_ok_consumes_pending() {
    let mut ep = make_active_client();
    let pub_msg = make_publish(varint(1), varint(42));
    ep.receive_message(ControlMessage::Publish(pub_msg)).unwrap();

    let resp = ep
        .send_publish_ok(
            varint(1),
            Forward::Forward,
            10,
            group_order_replied(),
            filter_largest_object(),
            None,
            None,
            None,
        )
        .unwrap();
    assert!(matches!(resp, ControlMessage::PublishOk(_)));
    assert_eq!(ep.pending_publish_count(), 0);
}

#[test]
fn endpoint_send_publish_error_consumes_pending() {
    let mut ep = make_active_client();
    let pub_msg = make_publish(varint(1), varint(42));
    ep.receive_message(ControlMessage::Publish(pub_msg)).unwrap();

    let resp = ep.send_publish_error(varint(1), varint(3), b"denied".to_vec()).unwrap();
    match resp {
        ControlMessage::PublishError(ref e) => {
            assert_eq!(e.error_code, varint(3));
            assert_eq!(e.reason_phrase, b"denied");
        }
        _ => panic!("expected PublishError"),
    }
    assert_eq!(ep.pending_publish_count(), 0);
}

#[test]
fn endpoint_publish_ok_for_unknown_request_fails() {
    let mut ep = make_active_client();
    let resp = ep.send_publish_ok(
        varint(99),
        Forward::Forward,
        0,
        group_order_replied(),
        filter_largest_object(),
        None,
        None,
        None,
    );
    assert!(matches!(resp, Err(EndpointError::UnknownRequest(_))));
}
/// A helper cannot hand back a SUBSCRIBE the encoder will not write.
///
/// `subscribe` carries no start location, so the two filters that name one are
/// refused there and served by `subscribe_range`, which derives the filter from
/// the range it was given. The gate drives the message all the way to bytes,
/// because the claim is not that the helper returned `Ok`, it is that a peer
/// can read what it returned.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Dropping the guard from `Endpoint::subscribe`:
///
/// ```text
/// AbsoluteStart names a start location this call cannot carry: Ok((VarInt(0), Subscribe(Subscribe { request_id: VarInt(0), track_namespace: TrackNamespace([[110, 115]]), track_name: [116], subscriber_priority: 0, group_order: Publisher, forward: Forward, filter_type: AbsoluteStart, start_group: None, start_object: None, end_group: None, parameters: [] })))
/// ```
#[test]
fn endpoint_subscribe_refuses_a_filter_it_cannot_carry() {
    for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
        let mut ep = make_active_client();
        let got = ep.subscribe(
            ns(&[b"ns"]),
            b"t".to_vec(),
            0,
            group_order_original(),
            filter,
            Vec::new(),
        );
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
                group_order_original(),
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

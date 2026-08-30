#![cfg(feature = "draft08")]

use moqtap_client::draft08::endpoint::*;
use moqtap_client::draft08::session::state::SessionState;
use moqtap_codec::draft08::message::{self, *};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|p| p.to_vec()).collect())
}

/// A setup parameter value in the shape this draft's wire format produces.
///
/// Drafts 07 through 10 frame every setup parameter as {Type, Length, Value},
/// so a value that came off the wire is always bytes. Building a
/// `KvpValue::Varint` here would be building a shape no peer can send, and a
/// test that does that is asserting on something it wrote itself.
fn setup_value(v: u64) -> KvpValue {
    let mut bytes = Vec::new();
    varint(v).encode(&mut bytes);
    KvpValue::Bytes(bytes)
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
    assert_eq!(ep.active_subscribe_announces_count(), 0);
    assert_eq!(ep.active_announce_count(), 0);
    assert_eq!(ep.active_track_status_count(), 0);
}

// ============================================================
// Session lifecycle
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let versions = vec![varint(0xff000008)];
    let _ = ep.send_client_setup(versions, vec![]).unwrap();
    let server_setup = ServerSetup {
        selected_version: varint(0xff000008),
        parameters: vec![KeyValuePair { key: varint(0x02), value: setup_value(100) }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    ep
}

#[test]
fn endpoint_connect_transitions_to_setup_exchange() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    assert_eq!(ep.session_state(), SessionState::SetupExchange);
}

/// A SERVER_SETUP activates the session, and the version it settled is
/// observed through what the endpoint will accept afterwards rather than by
/// reading it back: this module encodes one draft, and a SERVER_SETUP naming
/// another draft's version is refused whether or not the client offered it.
///
/// Dropping the version binding fails with:
///
/// ```text
/// this module speaks one draft, and 0xff000003 is not it
/// ```
#[test]
fn endpoint_receive_server_setup_activates_session() {
    let ep = make_active_client();
    assert_eq!(ep.session_state(), SessionState::Active);
    assert!(!ep.is_blocked());

    let mut other = Endpoint::new(Role::Client);
    other.connect().unwrap();
    let offered = vec![varint(0xff000008), varint(0xff000003)];
    let _ = other.send_client_setup(offered, vec![]).unwrap();
    let wrong_draft = ServerSetup { selected_version: varint(0xff000003), parameters: vec![] };
    assert!(
        other.receive_server_setup(&wrong_draft).is_err(),
        "this module speaks one draft, and 0xff000003 is not it",
    );
    assert_eq!(
        other.session_state(),
        SessionState::SetupExchange,
        "a refused SERVER_SETUP must not activate the session",
    );
}

#[test]
fn endpoint_blocked_without_max_subscribe_id() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff000008)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff000008), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

#[test]
fn endpoint_server_setup_wrong_version_fails() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff000008)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff000099), parameters: vec![] };
    assert!(ep.receive_server_setup(&server_setup).is_err());
}

// ============================================================
// Subscribe flow
// ============================================================

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = ep
        .subscribe(
            varint(1),
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_subscription_count(), 1);
    assert!(matches!(msg, ControlMessage::Subscribe(_)));
}

#[test]
fn endpoint_subscribe_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .subscribe(
            varint(1),
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    let ok = ControlMessage::SubscribeOk(SubscribeOk {
        subscribe_id: id,
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_group_id: None,
        largest_object_id: None,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_subscribe_done_ends_subscription_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .subscribe(
            varint(1),
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    let ok = ControlMessage::SubscribeOk(SubscribeOk {
        subscribe_id: id,
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_group_id: None,
        largest_object_id: None,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();

    let done = ControlMessage::SubscribeDone(SubscribeDone {
        subscribe_id: id,
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: vec![],
    });
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_unsubscribe_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .subscribe(
            varint(1),
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    // Must be Active first
    let ok = ControlMessage::SubscribeOk(SubscribeOk {
        subscribe_id: id,
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_group_id: None,
        largest_object_id: None,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    let msg = ep.unsubscribe(id).unwrap();
    assert!(matches!(msg, ControlMessage::Unsubscribe(_)));
}

#[test]
fn endpoint_monotonic_subscribe_ids() {
    let mut ep = make_active_client();
    let (id0, _) = ep
        .subscribe(
            varint(1),
            ns(&[b"ns"]),
            b"a".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    let (id1, _) = ep
        .subscribe(
            varint(2),
            ns(&[b"ns"]),
            b"b".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    let (id2, _) = ep
        .subscribe(
            varint(3),
            ns(&[b"ns"]),
            b"c".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    assert_eq!(id0.into_inner(), 0);
    assert_eq!(id1.into_inner(), 1);
    assert_eq!(id2.into_inner(), 2);
}

// ============================================================
// Fetch flow
// ============================================================

#[test]
fn endpoint_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = ep
        .fetch(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            varint(0),
            varint(0),
            varint(10),
            varint(0),
        )
        .unwrap();
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_fetch_count(), 1);
    assert!(matches!(msg, ControlMessage::Fetch(_)));
}

#[test]
fn endpoint_fetch_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .fetch(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            varint(0),
            varint(0),
            varint(10),
            varint(0),
        )
        .unwrap();
    let ok = ControlMessage::FetchOk(message::FetchOk {
        subscribe_id: id,
        group_order: GroupOrder::Ascending,
        end_of_track: 0,
        largest_group_id: varint(10),
        largest_object_id: varint(0),
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_fetch_cancel_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = ep
        .fetch(
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            varint(0),
            varint(0),
            varint(10),
            varint(0),
        )
        .unwrap();
    let msg = ep.fetch_cancel(id).unwrap();
    assert!(matches!(msg, ControlMessage::FetchCancel(_)));
}

// ============================================================
// Announce flow
// ============================================================

#[test]
fn endpoint_announce_tracks_namespace() {
    let mut ep = make_active_client();
    let msg = ep.announce(ns(&[b"pub", b"alice"])).unwrap();
    assert_eq!(ep.active_announce_count(), 1);
    assert!(matches!(msg, ControlMessage::Announce(_)));
}

#[test]
fn endpoint_announce_ok_via_dispatch() {
    let mut ep = make_active_client();
    let _ = ep.announce(ns(&[b"pub", b"alice"])).unwrap();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { track_namespace: ns(&[b"pub", b"alice"]) });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_unannounce_after_ok() {
    let mut ep = make_active_client();
    let _ = ep.announce(ns(&[b"pub", b"alice"])).unwrap();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { track_namespace: ns(&[b"pub", b"alice"]) });
    ep.receive_message(ok).unwrap();
    let msg = ep.unannounce(ns(&[b"pub", b"alice"])).unwrap();
    assert!(matches!(msg, ControlMessage::Unannounce(_)));
}

#[test]
fn endpoint_unknown_namespace_rejected() {
    let mut ep = make_active_client();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { track_namespace: ns(&[b"nope"]) });
    assert!(ep.receive_message(ok).is_err());
}

// ============================================================
// SubscribeAnnounces flow
// ============================================================

#[test]
fn endpoint_subscribe_announces_roundtrip() {
    let mut ep = make_active_client();
    let _ = ep.subscribe_announces(ns(&[b"prefix"])).unwrap();
    assert_eq!(ep.active_subscribe_announces_count(), 1);
    let ok = ControlMessage::SubscribeAnnouncesOk(SubscribeAnnouncesOk {
        track_namespace_prefix: ns(&[b"prefix"]),
    });
    ep.receive_message(ok).unwrap();
    let msg = ep.unsubscribe_announces(ns(&[b"prefix"])).unwrap();
    assert!(matches!(msg, ControlMessage::UnsubscribeAnnounces(_)));
}

// ============================================================
// Track status flow
// ============================================================

#[test]
fn endpoint_track_status_request_and_reply() {
    let mut ep = make_active_client();
    let _ = ep.track_status_request(ns(&[b"ns"]), b"trk".to_vec()).unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    let reply = ControlMessage::TrackStatus(TrackStatus {
        track_namespace: ns(&[b"ns"]),
        track_name: b"trk".to_vec(),
        status_code: varint(0),
        last_group_id: varint(5),
        last_object_id: varint(7),
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_unknown_track_status_rejected() {
    let mut ep = make_active_client();
    let reply = ControlMessage::TrackStatus(TrackStatus {
        track_namespace: ns(&[b"ns"]),
        track_name: b"trk".to_vec(),
        status_code: varint(0),
        last_group_id: varint(0),
        last_object_id: varint(0),
    });
    assert!(ep.receive_message(reply).is_err());
}

// ============================================================
// GoAway
// ============================================================

/// A GOAWAY drains the session. What that costs the peer is asserted rather
/// than the URI being read back: "The endpoint MUST terminate the session with
/// a Protocol Violation ... if it receives multiple GOAWAY messages", and a
/// second one has nowhere to go from Draining.
///
/// Letting a second GOAWAY through fails with:
///
/// ```text
/// a session can only be told to go away once
/// ```
#[test]
fn endpoint_goaway_transitions_to_draining() {
    let mut ep = make_active_client();
    let msg = GoAway { new_session_uri: b"https://new".to_vec() };
    ep.receive_goaway(&msg).unwrap();
    assert_eq!(ep.session_state(), SessionState::Draining);
    assert!(
        ep.receive_goaway(&GoAway { new_session_uri: Vec::new() }).is_err(),
        "a session can only be told to go away once",
    );
}

#[test]
fn endpoint_draining_rejects_new_subscribe() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.subscribe(
        varint(1),
        ns(&[b"ns"]),
        b"trk".to_vec(),
        0,
        GroupOrder::Ascending,
        FilterType::LargestObject,
    );
    assert!(matches!(result, Err(EndpointError::Draining)));
}

// ============================================================
// MAX_SUBSCRIBE_ID
// ============================================================

#[test]
fn endpoint_max_subscribe_id_monotonic_send() {
    let mut ep = make_active_client();
    let _ = ep.send_max_subscribe_id(varint(200)).unwrap();
    let _ = ep.send_max_subscribe_id(varint(300)).unwrap();
    assert!(ep.send_max_subscribe_id(varint(200)).is_err());
}

#[test]
fn endpoint_receive_max_subscribe_id_raises_limit() {
    let mut ep = make_active_client();
    ep.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(1000) }).unwrap();
    assert!(!ep.is_blocked());
}

// ============================================================
// SUBSCRIBES_BLOCKED (draft-08 new message)
// ============================================================

/// SUBSCRIBES_BLOCKED is the peer's account of where it stopped, not a grant.
///
/// The number in it is not read back. What is asserted is that it did not
/// become this endpoint's own advertised ceiling: if the handler had folded it
/// in, 100 would already be spent and advertising it would be refused for not
/// being an increase.
///
/// Folding it in fails with:
///
/// ```text
/// the peer's report is not a ceiling this endpoint has already advertised:
/// SubscribeId(Decreased(100, 100))
/// ```
#[test]
fn endpoint_receive_subscribes_blocked_is_not_a_grant() {
    let mut ep = make_active_client();
    let _ = ep.send_max_subscribe_id(varint(50)).unwrap();

    let msg =
        ControlMessage::SubscribesBlocked(SubscribesBlocked { maximum_subscribe_id: varint(100) });
    ep.receive_message(msg).unwrap();

    let _ = ep
        .send_max_subscribe_id(varint(100))
        .expect("the peer's report is not a ceiling this endpoint has already advertised");
}

// ============================================================
// Joining fetch (draft-08 new fetch mode)
// ============================================================

#[test]
fn endpoint_joining_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    // Open a parent subscription first
    let (parent_id, _) = ep
        .subscribe(
            varint(1),
            ns(&[b"ns"]),
            b"trk".to_vec(),
            0,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
        .unwrap();
    let ok = ControlMessage::SubscribeOk(SubscribeOk {
        subscribe_id: parent_id,
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_group_id: None,
        largest_object_id: None,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();

    // Issue a joining fetch against it
    let (fetch_id, msg) = ep.joining_fetch(0, GroupOrder::Ascending, parent_id, varint(2)).unwrap();
    assert_ne!(fetch_id.into_inner(), parent_id.into_inner());
    assert_eq!(ep.active_fetch_count(), 1);
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::Joining as u64);
            assert_eq!(f.joining_subscribe_id, Some(parent_id));
            assert_eq!(f.preceding_group_offset, Some(varint(2)));
            assert!(f.track_namespace.is_none());
        }
        _ => panic!("expected Fetch control message"),
    }
}

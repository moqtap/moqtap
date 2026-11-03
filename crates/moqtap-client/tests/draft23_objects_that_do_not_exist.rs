#![cfg(feature = "draft23")]

//! Draft-23 Section 12.1 makes a track malformed when "An Object is received
//! after it has been recorded as not existing, or is signalled as not existing
//! after it was received (see Section 2.1.2)." Section 10.8 states the Prior
//! Group ID Gap cases: "An endpoint receives an Object with a Prior Group ID Gap
//! covering an Object it previously received" and "An endpoint receives an
//! Object with a Group ID within a previously communicated gap."

use moqtap_client::draft23::endpoint::{Endpoint, EndpointError};
use moqtap_client::draft23::session::request_id::Role;
use moqtap_client::track_locations::{ObjectLocation, ObjectRole, TrackLocations};
use moqtap_codec::draft23::message::{Setup, SubscribeOk};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

const ALIAS: u64 = 9;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

fn at(group: u64, object: u64) -> ObjectLocation {
    ObjectLocation { group, object }
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A client with one established subscription, bound to [`ALIAS`].
fn subscribed() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().expect("connect");
    ep.send_setup(Vec::new()).expect("SETUP");
    ep.receive_setup(&Setup { options: Vec::new() }).expect("the peer's SETUP");
    let (id, _) = ep.subscribe(namespace(), b"video".to_vec(), Vec::new()).expect("SUBSCRIBE");
    ep.receive_subscribe_ok(
        id,
        &SubscribeOk { track_alias: v(ALIAS), parameters: vec![], track_properties: vec![] },
    )
    .expect("SUBSCRIBE_OK");
    ep
}

/// Prior Object ID Gap (0x3E) of `n`, as an Object Properties block.
fn object_gap(n: u8) -> Vec<u8> {
    vec![0x3E, n]
}

/// Prior Group ID Gap (0x3C) of `n`, as an Object Properties block.
fn group_gap(n: u8) -> Vec<u8> {
    vec![0x3C, n]
}

#[test]
fn a_gap_covering_a_received_object_makes_the_track_malformed() {
    let ep = subscribed();
    ep.note_received_object(ALIAS, at(5, 3), ObjectRole::Produced, &[]).expect("Object {5, 3}");
    let err = ep
        .note_received_object(ALIAS, at(5, 6), ObjectRole::Produced, &object_gap(3))
        .expect_err("Objects 3, 4 and 5 of Group 5 cannot all not exist");
    assert!(
        matches!(err, EndpointError::ObjectExistenceContradicted { group: 5, object: 3, .. }),
        "{err}"
    );
    assert_eq!(err.session_error_code(), None, "a Malformed Track costs the track");
}

#[test]
fn an_object_inside_a_communicated_group_gap_makes_the_track_malformed() {
    let ep = subscribed();
    ep.note_received_object(ALIAS, at(10, 0), ObjectRole::Produced, &group_gap(2))
        .expect("Groups 8 and 9 do not exist");
    let err = ep
        .note_received_object(ALIAS, at(9, 4), ObjectRole::Produced, &[])
        .expect_err("Group 9 was communicated as a gap");
    assert!(
        matches!(err, EndpointError::ObjectExistenceContradicted { group: 9, object: 4, .. }),
        "{err}"
    );
}

#[test]
fn objects_outside_every_gap_are_accepted() {
    let ep = subscribed();
    ep.note_received_object(ALIAS, at(10, 5), ObjectRole::Produced, &object_gap(2))
        .expect("Objects 3 and 4 of Group 10 do not exist");
    for object in [0, 1, 2, 6] {
        ep.note_received_object(ALIAS, at(10, object), ObjectRole::Produced, &[])
            .expect("outside the gap");
    }
}

#[test]
fn the_record_merges_runs_and_checks_ranges_across_groups() {
    let ns = namespace();
    let mut record = TrackLocations::new();
    for object in [0, 1, 2, 4, 3] {
        record.note_exists(&ns, b"t", at(2, object)).expect("received");
    }
    assert_eq!(record.note_absent(&ns, b"t", at(1, 7), at(2, 0)), Err(at(2, 0)));
    assert_eq!(record.note_absent(&ns, b"t", at(2, 5), at(3, 9)), Ok(()));
    assert_eq!(record.note_exists(&ns, b"t", at(3, 2)), Err(at(3, 2)));
    assert_eq!(record.note_exists(&ns, b"t", at(4, 0)), Ok(()));
}

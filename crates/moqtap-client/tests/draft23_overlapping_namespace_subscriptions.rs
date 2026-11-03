#![cfg(feature = "draft23")]

//! Draft-23 allows namespace subscriptions whose prefixes overlap.
//!
//! The PREFIX_OVERLAP sentences of earlier drafts are gone from draft-23
//! Sections 3.6, 4.2, 9.5.2 and 9.19.20, and so is the code itself (Section
//! 12.3). Section 3.6: "If a Track matches more than one SUBSCRIBE_TRACKS, the
//! publisher sends a PUBLISH for each." So an overlapping SUBSCRIBE_NAMESPACE
//! or SUBSCRIBE_TRACKS, and a REQUEST_UPDATE moving a prefix onto another
//! subscription's, is answered like any other.

use moqtap_client::draft23::endpoint::Endpoint;
use moqtap_client::draft23::session::request_id::Role;
use moqtap_codec::draft23::message::*;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::{Moqt18, VarInt};

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

fn root() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn under() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"alpha".to_vec()])
}

fn active() -> Endpoint {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().expect("an endpoint may open");
    ep.send_setup(Vec::new()).expect("SETUP");
    ep.receive_setup(&Setup { options: Vec::new() }).expect("the peer's SETUP");
    ep
}

fn accept(ep: &mut Endpoint, id: u64) {
    ep.send_response_on_stream(
        v(id),
        &ControlMessage::RequestOk(RequestOk {
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }),
    )
    .expect("an overlapping subscription is accepted like any other");
}

fn prefix_param(ns: &TrackNamespace) -> KeyValuePair {
    let mut bytes = Vec::new();
    ns.encode_moqt::<Moqt18>(&mut bytes);
    KeyValuePair { key: v(0x34), value: KvpValue::Bytes(bytes) }
}

#[test]
fn overlapping_namespace_subscriptions_are_both_accepted() {
    let mut ep = active();
    for (id, prefix) in [(0, root()), (2, under()), (4, root())] {
        ep.receive_request_on_stream(&ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: v(id),
            namespace_prefix: prefix,
            parameters: Vec::new(),
        }))
        .expect("the peer may open a namespace subscription");
        accept(&mut ep, id);
    }
}

#[test]
fn overlapping_track_subscriptions_are_both_accepted() {
    let mut ep = active();
    for (id, prefix) in [(0, root()), (2, under())] {
        ep.receive_request_on_stream(&ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: v(id),
            namespace_prefix: prefix,
            parameters: Vec::new(),
        }))
        .expect("the peer may subscribe to tracks under a prefix");
        accept(&mut ep, id);
    }
}

#[test]
fn a_prefix_may_move_onto_another_subscriptions_prefix() {
    let mut ep = active();
    for (id, prefix) in [(0, root()), (2, under())] {
        ep.receive_request_on_stream(&ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: v(id),
            namespace_prefix: prefix,
            parameters: Vec::new(),
        }))
        .expect("the peer may open a namespace subscription");
        accept(&mut ep, id);
    }
    ep.receive_on_peer_request_stream(
        v(2),
        ControlMessage::RequestUpdate(RequestUpdate {
            request_id: v(2),
            parameters: vec![prefix_param(&root())],
        }),
    )
    .expect("an update may name any prefix");
    accept(&mut ep, 2);
}

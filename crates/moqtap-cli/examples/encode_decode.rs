//! Example: Encode and decode MoQT control messages.
//!
//! Run with: cargo run --example encode_decode

use moqtap_codec::draft14::message::{ClientSetup, ControlMessage, ServerSetup, Subscribe};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

fn main() {
    // -- CLIENT_SETUP --
    let client_setup = ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff00000e).unwrap()], // draft-14
        parameters: vec![],
    });

    let mut buf = Vec::new();
    client_setup.encode(&mut buf).unwrap();
    println!("CLIENT_SETUP encoded: {} bytes -> {:02x?}", buf.len(), &buf);

    let mut cursor = &buf[..];
    let decoded = ControlMessage::decode(&mut cursor).unwrap();
    assert_eq!(client_setup, decoded);
    println!("CLIENT_SETUP roundtrip: OK\n");

    // -- SERVER_SETUP --
    let server_setup = ControlMessage::ServerSetup(ServerSetup {
        selected_version: VarInt::from_u64(0xff00000e).unwrap(),
        parameters: vec![],
    });

    buf.clear();
    server_setup.encode(&mut buf).unwrap();
    println!("SERVER_SETUP encoded: {} bytes", buf.len());

    let mut cursor = &buf[..];
    let decoded = ControlMessage::decode(&mut cursor).unwrap();
    assert_eq!(server_setup, decoded);
    println!("SERVER_SETUP roundtrip: OK\n");

    // -- SUBSCRIBE --
    let subscribe = ControlMessage::Subscribe(Subscribe {
        request_id: VarInt::from_u64(0).unwrap(),
        track_namespace: TrackNamespace(vec![b"live".to_vec(), b"stream".to_vec()]),
        track_name: b"video".to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::NextGroupStart,
        start_location: None,
        end_group: None,
        parameters: vec![],
    });

    buf.clear();
    subscribe.encode(&mut buf).unwrap();
    println!("SUBSCRIBE encoded: {} bytes", buf.len());

    let mut cursor = &buf[..];
    let decoded = ControlMessage::decode(&mut cursor).unwrap();
    assert_eq!(subscribe, decoded);
    println!("SUBSCRIBE roundtrip: OK");
}

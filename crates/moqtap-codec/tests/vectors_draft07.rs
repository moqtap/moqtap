#![cfg(feature = "draft07")]

mod test_vectors;

use bytes::BufMut;
use moqtap_codec::draft07::message::ControlMessage;
use test_vectors::{load_vectors, vectors_dir};

fn run_message_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected_decoded) = &vector.decoded {
            // Valid vector: decode hex and compare JSON
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let msg = ControlMessage::decode(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));
            let actual_json = test_vectors::draft07_json::message_to_json(&msg);
            assert_eq!(
                actual_json,
                *expected_decoded,
                "[{}] decoded JSON mismatch\nactual:   {}\nexpected: {}",
                vector.id,
                serde_json::to_string_pretty(&actual_json).unwrap(),
                serde_json::to_string_pretty(expected_decoded).unwrap()
            );

            // Re-encode canonical vectors
            if vector.is_canonical() {
                let mut buf = Vec::new();
                msg.encode(&mut buf)
                    .unwrap_or_else(|e| panic!("[{}] encode failed: {e}", vector.id));
                assert_eq!(
                    hex::encode(&buf),
                    vector.hex,
                    "[{}] re-encoded hex mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            // Error vector: decode should fail
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let result = ControlMessage::decode(&mut &bytes[..]);
            assert!(result.is_err(), "[{}] expected error but decoded successfully", vector.id);
        }
    }
}

macro_rules! d07_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft07/codec/messages/", $file));
        }
    };
}

d07_test!(d07_announce_cancel, "announce-cancel.json");
d07_test!(d07_announce_error, "announce-error.json");
d07_test!(d07_announce_ok, "announce-ok.json");
d07_test!(d07_announce, "announce.json");
d07_test!(d07_client_setup, "client-setup.json");
d07_test!(d07_server_setup, "server-setup.json");
d07_test!(d07_goaway, "goaway.json");
d07_test!(d07_max_subscribe_id, "max-subscribe-id.json");
d07_test!(d07_subscribe, "subscribe.json");
d07_test!(d07_subscribe_ok, "subscribe-ok.json");
d07_test!(d07_subscribe_error, "subscribe-error.json");
d07_test!(d07_subscribe_update, "subscribe-update.json");
d07_test!(d07_subscribe_done, "subscribe-done.json");
d07_test!(d07_unsubscribe, "unsubscribe.json");
d07_test!(d07_subscribe_announces, "subscribe-announces.json");
d07_test!(d07_subscribe_announces_ok, "subscribe-announces-ok.json");
d07_test!(d07_subscribe_announces_error, "subscribe-announces-error.json");
d07_test!(d07_unsubscribe_announces, "unsubscribe-announces.json");
d07_test!(d07_track_status_request, "track-status-request.json");
d07_test!(d07_track_status, "track-status.json");
d07_test!(d07_fetch, "fetch.json");
d07_test!(d07_fetch_ok, "fetch-ok.json");
d07_test!(d07_fetch_error, "fetch-error.json");
d07_test!(d07_fetch_cancel, "fetch-cancel.json");
d07_test!(d07_unannounce, "unannounce.json");
d07_test!(d07_unknown_type, "unknown-type.json");

#![cfg(feature = "draft14")]

mod test_vectors;

use moqtap_codec::draft14::message::ControlMessage;
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
            let actual_json = test_vectors::draft14_json::message_to_json(&msg);
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

macro_rules! d14_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft14/codec/messages/", $file));
        }
    };
}

d14_test!(d14_client_setup, "client-setup.json");
d14_test!(d14_server_setup, "server-setup.json");
d14_test!(d14_goaway, "goaway.json");
d14_test!(d14_max_request_id, "max-request-id.json");
d14_test!(d14_requests_blocked, "requests-blocked.json");
d14_test!(d14_subscribe, "subscribe.json");
d14_test!(d14_subscribe_ok, "subscribe-ok.json");
d14_test!(d14_subscribe_error, "subscribe-error.json");
d14_test!(d14_subscribe_update, "subscribe-update.json");
d14_test!(d14_unsubscribe, "unsubscribe.json");
d14_test!(d14_subscribe_namespace, "subscribe-namespace.json");
d14_test!(d14_subscribe_namespace_ok, "subscribe-namespace-ok.json");
d14_test!(d14_subscribe_namespace_error, "subscribe-namespace-error.json");
d14_test!(d14_unsubscribe_namespace, "unsubscribe-namespace.json");
d14_test!(d14_publish, "publish.json");
d14_test!(d14_publish_ok, "publish-ok.json");
d14_test!(d14_publish_error, "publish-error.json");
d14_test!(d14_publish_done, "publish-done.json");
d14_test!(d14_publish_namespace, "publish-namespace.json");
d14_test!(d14_publish_namespace_ok, "publish-namespace-ok.json");
d14_test!(d14_publish_namespace_error, "publish-namespace-error.json");
d14_test!(d14_publish_namespace_done, "publish-namespace-done.json");
d14_test!(d14_publish_namespace_cancel, "publish-namespace-cancel.json");
d14_test!(d14_track_status, "track-status.json");
d14_test!(d14_track_status_ok, "track-status-ok.json");
d14_test!(d14_track_status_error, "track-status-error.json");
d14_test!(d14_fetch, "fetch.json");
d14_test!(d14_fetch_ok, "fetch-ok.json");
d14_test!(d14_fetch_error, "fetch-error.json");
d14_test!(d14_fetch_cancel, "fetch-cancel.json");
d14_test!(d14_unknown_type, "unknown-type.json");

#![cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
))]

//! `AnyConnection::recv_inbound` refuses a peer request it has no entry point
//! for with REQUEST_ERROR NOT_SUPPORTED, retry interval 0, and a FIN, rather
//! than resetting the stream.
//!
//! "When an endpoint rejects a request without performing any application
//! processing, it SHOULD send a REQUEST_ERROR and FIN the stream." (draft-17
//! Section 3.3.1; Section 3.3.2 from draft-18.)

mod common;

use std::time::Duration;

use common::render;
use moqtap_client::dispatch::{AnyArrival, AnyClientConfig, AnyConnection, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::fields::FieldValue;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

const PATIENCE: Duration = Duration::from_secs(10);

/// Odd: the peer is the server.
const PEER_REQUEST_ID: u64 = 1;

/// NOT_SUPPORTED on every draft here.
const NOT_SUPPORTED: u64 = 0x3;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("fixture value fits a varint")
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

const TRACK: &[u8] = b"video";

/// `max_request_id`, so the peer's request is within budget.
fn granted_budget() -> KeyValuePair {
    KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }
}

fn client_config(draft: DraftVersion) -> AnyClientConfig {
    AnyClientConfig {
        draft,
        additional_versions: Vec::new(),
        transport: AnyTransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: vec![granted_budget()],
    }
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

fn uint(message: &AnyControlMessage, field: &str) -> String {
    match message.fields().get(field) {
        Some(FieldValue::Uint(n)) => n.to_string(),
        other => format!("{other:?}"),
    }
}

/// Reads whole control messages off one stream, then how the stream ended.
struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    async fn read_control(&mut self) -> Option<AnyControlMessage> {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(self.draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    let mut tmp = [0u8; 2048];
                    match self.recv.read(&mut tmp).await {
                        Ok(Some(n)) => self.buf.extend_from_slice(&tmp[..n]),
                        _ => return None,
                    }
                }
                Err(e) => panic!("the peer could not decode what the client wrote: {e}"),
            }
        }
    }

    /// "fin", or what ended the stream instead.
    async fn end(&mut self) -> String {
        let mut tmp = [0u8; 2048];
        loop {
            match self.recv.read(&mut tmp).await {
                Ok(Some(n)) => self.buf.extend_from_slice(&tmp[..n]),
                Ok(None) if self.buf.is_empty() => return "fin".into(),
                Ok(None) => return format!("fin after {} unread bytes", self.buf.len()),
                Err(e) => return format!("{e}"),
            }
        }
    }
}

/// One draft's gate. `$request` is a TRACK_STATUS, which the facade has no
/// entry point for.
macro_rules! refusal_gate {
    ($module:ident, $feat:literal, $version:ident, $request:expr) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;
            use moqtap_codec::$module::message::{ControlMessage, Setup};

            const DRAFT: DraftVersion = DraftVersion::$version;

            /// Handshake, open a request stream with the peer's request, and
            /// report the answer and how the stream ended.
            async fn serve(server: quinn::Endpoint) -> (String, String) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control = PeerStream {
                    recv: conn.accept_uni().await.expect("accept_uni"),
                    draft: DRAFT,
                    buf: Vec::new(),
                };
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                let setup = ControlMessage::Setup(Setup { options: vec![granted_budget()] });
                ours.write_all(&encoded(AnyControlMessage::$version(setup)))
                    .await
                    .expect("write the peer's SETUP");

                let (mut send, recv) = conn.open_bi().await.expect("open a request stream");
                let request = AnyControlMessage::$version(ControlMessage::TrackStatus($request));
                send.write_all(&encoded(request)).await.expect("write TRACK_STATUS");
                let mut stream = PeerStream { recv, draft: DRAFT, buf: Vec::new() };
                let answer = stream.read_control().await.expect("the client's answer");
                let answer = render(
                    answer.message_type_name(),
                    answer.message_type_id(),
                    &[
                        ("error_code", uint(&answer, "error_code")),
                        ("retry_interval", uint(&answer, "retry_interval")),
                    ],
                );
                (answer, stream.end().await)
            }

            #[tokio::test]
            async fn an_unanswerable_request_gets_request_error_and_fin() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound())
                    .await
                    .expect("nothing arrived")
                    .expect("accept the peer's request stream");
                match arrival {
                    AnyArrival::Other(message) => {
                        assert_eq!(message.message_type_name(), "track_status")
                    }
                    AnyArrival::Subscribe { .. } => panic!("a TRACK_STATUS came back as SUBSCRIBE"),
                }

                let (answer, end) = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    answer,
                    render(
                        "request_error",
                        0x05,
                        &[
                            ("error_code", NOT_SUPPORTED.to_string()),
                            ("retry_interval", "0".to_string()),
                        ],
                    ),
                    "{DRAFT:?} refuses with NOT_SUPPORTED and no retry"
                );
                assert_eq!(end, "fin", "{DRAFT:?} finishes the stream rather than resetting it");
                drop(conn);
            }
        }
    };
}

refusal_gate!(
    draft17,
    "draft17",
    Draft17,
    moqtap_codec::draft17::message::TrackStatus {
        request_id: v(PEER_REQUEST_ID),
        required_request_id_delta: v(0),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

refusal_gate!(
    draft18,
    "draft18",
    Draft18,
    moqtap_codec::draft18::message::TrackStatus {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

refusal_gate!(
    draft19,
    "draft19",
    Draft19,
    moqtap_codec::draft19::message::TrackStatus {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

refusal_gate!(
    draft20,
    "draft20",
    Draft20,
    moqtap_codec::draft20::message::TrackStatus {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

refusal_gate!(
    draft21,
    "draft21",
    Draft21,
    moqtap_codec::draft21::message::TrackStatus {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

refusal_gate!(
    draft22,
    "draft22",
    Draft22,
    moqtap_codec::draft22::message::TrackStatus {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

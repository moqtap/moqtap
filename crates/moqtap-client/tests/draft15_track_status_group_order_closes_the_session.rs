#![cfg(feature = "draft15")]
//! draft-15 Section 9.2.1.6: "The GROUP_ORDER parameter (Parameter Type 0x22)
//! MAY appear in a SUBSCRIBE, SUBSCRIBE_OK, TRACK_STATUS, REQUEST_OK (in
//! response to TRACK_STATUS), PUBLISH, PUBLISH_OK or FETCH." and "The allowed
//! values are Ascending (0x1) or Descending (0x2). If an endpoint receives a
//! value outside this range, it MUST close the session with
//! PROTOCOL_VIOLATION."
//!
//! Which request a REQUEST_OK answers is session state, so the codec carries
//! GROUP_ORDER in every REQUEST_OK and the connection checks it in one that
//! answers a TRACK_STATUS, received or sent. In a REQUEST_OK answering a
//! SUBSCRIBE_UPDATE it is out of scope, and draft-15 Section 9.2.1: "If it
//! appears in some other type of message, it MUST be ignored."

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_client::draft15::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_client::draft15::event::ClientEvent;
use moqtap_client::draft15::observer::ConnectionObserver;
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft15::message::{
    ControlMessage, MessageType, RequestOk, ServerSetup, SubscribeOk, TrackStatus,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-15 Section 13.3.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// GROUP_ORDER, draft-15 Section 9.2.1.6, Parameter Type 0x22.
const GROUP_ORDER: u64 = 0x22;

/// Neither Ascending (0x1) nor Descending (0x2).
const OUTSIDE_THE_RANGE: u64 = 7;

const PATIENCE: Duration = Duration::from_secs(10);

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft15,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn encode(message: ControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft15(message).encode(&mut out).expect("the message encodes");
    out
}

/// A SERVER_SETUP granting Request IDs, MAX_REQUEST_ID (0x02) in
/// draft-15 Section 9.3.1.3.
fn server_setup() -> Vec<u8> {
    encode(ControlMessage::ServerSetup(ServerSetup {
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    }))
}

fn request_ok_with_group_order(request_id: u64) -> Vec<u8> {
    encode(ControlMessage::RequestOk(RequestOk {
        request_id: varint(request_id),
        parameters: vec![KeyValuePair {
            key: varint(GROUP_ORDER),
            value: KvpValue::Varint(varint(OUTSIDE_THE_RANGE)),
        }],
    }))
}

/// The frames the connection reports refused.
struct Refusals(Arc<Mutex<Vec<Vec<u8>>>>);

impl ConnectionObserver for Refusals {
    fn on_event(&self, event: &ClientEvent) {
        if let ClientEvent::ControlMessageRefused { raw } = event {
            self.0.lock().expect("lock").push(raw.clone());
        }
    }
}

/// A REQUEST_OK answering this endpoint's TRACK_STATUS with a GROUP_ORDER
/// outside the range closes the session with PROTOCOL_VIOLATION.
#[tokio::test]
async fn a_track_status_answer_with_group_order_outside_its_range_closes_the_session() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft15.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft15);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        send.write_all(&server_setup()).await.expect("write SERVER_SETUP");

        let request_id = match framed_recv.read_control(false).await.expect("read TRACK_STATUS").0 {
            AnyControlMessage::Draft15(ControlMessage::TrackStatus(m)) => m.request_id,
            other => panic!("expected a TRACK_STATUS, got {other:?}"),
        };
        let offending = request_ok_with_group_order(request_id.into_inner());
        send.write_all(&offending).await.expect("write the offending REQUEST_OK");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");
        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => assert_eq!(
                u64::from(frame.error_code),
                PROTOCOL_VIOLATION,
                "draft-15 Section 9.2.1.6 answers a GROUP_ORDER outside its range \
                 with PROTOCOL_VIOLATION; the close carried {} instead",
                u64::from(frame.error_code)
            ),
            other => panic!("expected an application close, got {other:?}"),
        }
        offending
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");
    let refusals = Arc::new(Mutex::new(Vec::new()));
    conn.set_observer(Box::new(Refusals(refusals.clone())));
    conn.track_status(TrackNamespace(vec![b"ns".to_vec()]), b"t".to_vec(), Vec::new())
        .await
        .expect("send TRACK_STATUS");

    let err = conn.recv_control().await.expect_err("the GROUP_ORDER must be refused");
    assert!(
        matches!(
            err,
            ConnectionError::Codec(CodecError::ParameterValueOutOfRange {
                key: GROUP_ORDER,
                value: OUTSIDE_THE_RANGE,
                message_type,
            }) if message_type == MessageType::RequestOk.id()
        ),
        "expected a GROUP_ORDER range refusal naming REQUEST_OK, got {err:?}"
    );

    let offending = tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
    assert_eq!(
        *refusals.lock().expect("lock"),
        vec![offending],
        "the refused frame should reach the observer"
    );
}

/// A REQUEST_OK answering a SUBSCRIBE_UPDATE carries the same GROUP_ORDER.
#[tokio::test]
async fn a_subscribe_update_answer_carries_group_order_unchecked() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft15.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft15);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        send.write_all(&server_setup()).await.expect("write SERVER_SETUP");

        let subscribe_id = match framed_recv.read_control(false).await.expect("read SUBSCRIBE").0 {
            AnyControlMessage::Draft15(ControlMessage::Subscribe(m)) => m.request_id,
            other => panic!("expected a SUBSCRIBE, got {other:?}"),
        };
        send.write_all(&encode(ControlMessage::SubscribeOk(SubscribeOk {
            request_id: subscribe_id,
            track_alias: varint(4),
            parameters: Vec::new(),
        })))
        .await
        .expect("write SUBSCRIBE_OK");

        let update_id =
            match framed_recv.read_control(false).await.expect("read SUBSCRIBE_UPDATE").0 {
                AnyControlMessage::Draft15(ControlMessage::SubscribeUpdate(m)) => m.request_id,
                other => panic!("expected a SUBSCRIBE_UPDATE, got {other:?}"),
            };
        send.write_all(&request_ok_with_group_order(update_id.into_inner()))
            .await
            .expect("write the REQUEST_OK");

        // Held open until the client has read the REQUEST_OK and gone.
        let _ = tokio::time::timeout(PATIENCE, conn.closed()).await;
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");
    let subscription = conn
        .subscribe(TrackNamespace(vec![b"ns".to_vec()]), b"t".to_vec(), Vec::new())
        .await
        .expect("send SUBSCRIBE");
    match conn.recv_and_dispatch().await.expect("read SUBSCRIBE_OK") {
        ControlMessage::SubscribeOk(_) => {}
        other => panic!("expected a SUBSCRIBE_OK, got {other:?}"),
    }
    let update =
        conn.subscribe_update(subscription, Vec::new()).await.expect("send SUBSCRIBE_UPDATE");

    match conn.recv_control().await.expect("the REQUEST_OK is carried") {
        ControlMessage::RequestOk(ok) => {
            assert_eq!(ok.request_id, update);
            assert_eq!(
                ok.parameters,
                vec![KeyValuePair {
                    key: varint(GROUP_ORDER),
                    value: KvpValue::Varint(varint(OUTSIDE_THE_RANGE)),
                }]
            );
        }
        other => panic!("expected a REQUEST_OK, got {other:?}"),
    }

    conn.close(0, b"done");
    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

/// An answer to the peer's TRACK_STATUS with a GROUP_ORDER outside the range
/// is refused before anything is written, and the request stays unanswered.
#[tokio::test]
async fn an_answer_to_the_peers_track_status_with_group_order_outside_its_range_is_not_sent() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft15.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft15);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        send.write_all(&server_setup()).await.expect("write SERVER_SETUP");
        send.write_all(&encode(ControlMessage::TrackStatus(TrackStatus {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters: Vec::new(),
        })))
        .await
        .expect("write TRACK_STATUS");

        tokio::time::timeout(PATIENCE, framed_recv.read_control(false))
            .await
            .expect("the client never answered")
            .expect("read the answer")
            .0
    });

    let mut config = client_config();
    config.setup_parameters =
        vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }];
    let mut conn = Connection::connect(&addr.to_string(), config).await.expect("client connect");
    match conn.recv_and_dispatch().await.expect("read TRACK_STATUS") {
        ControlMessage::TrackStatus(_) => {}
        other => panic!("expected a TRACK_STATUS, got {other:?}"),
    }

    let refused = vec![KeyValuePair {
        key: varint(GROUP_ORDER),
        value: KvpValue::Varint(varint(OUTSIDE_THE_RANGE)),
    }];
    let err = conn.request_ok(varint(1), refused).await.expect_err("the GROUP_ORDER is refused");
    assert!(
        matches!(
            err,
            ConnectionError::Codec(CodecError::ParameterValueOutOfRange {
                key: GROUP_ORDER,
                value: OUTSIDE_THE_RANGE,
                message_type,
            }) if message_type == MessageType::RequestOk.id()
        ),
        "expected a GROUP_ORDER range refusal naming REQUEST_OK, got {err:?}"
    );

    let legal = vec![KeyValuePair { key: varint(GROUP_ORDER), value: KvpValue::Varint(varint(1)) }];
    conn.request_ok(varint(1), legal.clone()).await.expect("an Ascending answer is sent");

    let read = tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
    match read {
        AnyControlMessage::Draft15(ControlMessage::RequestOk(ok)) => {
            assert_eq!(ok.parameters, legal, "the refused answer must not reach the peer");
        }
        other => panic!("expected a REQUEST_OK, got {other:?}"),
    }
}

//! Loopback data-plane test — subgroup stream and datagram exchange
//! over a real quinn endpoint, with observer-event assertions on the
//! client side.

mod common;

use std::sync::{Arc, Mutex};

use moqtap_client::draft14::connection::{ClientConfig, Connection, TransportType};
use moqtap_client::draft14::event::{ClientEvent, Direction, StreamKind};
use moqtap_client::draft14::observer::ConnectionObserver;
use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
use moqtap_codec::draft14::data_stream::{
    DatagramObject, DatagramType, SubgroupHeader, SubgroupObject, SubgroupStreamType,
};
use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

#[derive(Clone)]
struct Recorder {
    events: Arc<Mutex<Vec<ClientEvent>>>,
}

impl ConnectionObserver for Recorder {
    fn on_event(&self, event: &ClientEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

impl Recorder {
    fn new() -> Self {
        Recorder { events: Arc::new(Mutex::new(Vec::new())) }
    }
    fn snapshot(&self) -> Vec<ClientEvent> {
        self.events.lock().unwrap().clone()
    }
}

/// Drive the handshake on the server side and return the live connection.
async fn server_handshake(endpoint: quinn::Endpoint) -> quinn::Connection {
    let incoming = endpoint.accept().await.expect("accept");
    let conn = incoming.await.expect("tls handshake");
    let (send, recv) = conn.accept_bi().await.expect("accept_bi");
    let (mut framed_send, mut framed_recv) = common::frame_bi(send, recv, DraftVersion::Draft14);

    let (msg, _) = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
    let selected = match msg {
        AnyControlMessage::Draft14(ControlMessage::ClientSetup(cs)) => cs.supported_versions[0],
        other => panic!("expected CLIENT_SETUP, got {other:?}"),
    };
    let server_setup = AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected,
        parameters: vec![],
    }));
    framed_send.write_control(&server_setup).await.expect("write SERVER_SETUP");
    conn
}

fn default_client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft14,
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

#[tokio::test]
async fn subgroup_stream_round_trip_emits_observer_events() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[b"moq-00"]);

    let (object_tx, object_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let quic = server_handshake(endpoint).await;
        let recv = quic.accept_uni().await.expect("accept_uni");
        let mut framed = common::frame_uni_recv(recv, DraftVersion::Draft14);
        let header = framed.read_subgroup_header().await.expect("read subgroup header");
        let object = framed.read_subgroup_object().await.expect("read subgroup object");
        let _ = object_tx.send((header, object));
        let _ = quic.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), default_client_config())
        .await
        .expect("client connect");

    let recorder = Recorder::new();
    conn.set_observer(Box::new(recorder.clone()));

    let header = AnySubgroupHeader::Draft14(SubgroupHeader {
        stream_type: SubgroupStreamType::from_flags(false, false, false, false),
        track_alias: VarInt::from_u64(42).unwrap(),
        group_id: VarInt::from_u64(7).unwrap(),
        subgroup_id: None,
        publisher_priority: 128,
    });

    let mut send = conn.open_subgroup_stream(&header).await.expect("open subgroup stream");
    let object = SubgroupObject {
        object_id: VarInt::from_u64(0).unwrap(),
        extension_headers: Vec::new(),
        status: None,
        payload: b"hello-subgroup".to_vec(),
    };
    send.write_subgroup_object(&object).await.expect("write object");
    send.finish().await.expect("finish send");

    let (got_header, got_object) =
        tokio::time::timeout(std::time::Duration::from_secs(5), object_rx)
            .await
            .expect("server response within timeout")
            .expect("server sent object");

    match got_header {
        AnySubgroupHeader::Draft14(h) => {
            assert_eq!(h.track_alias.into_inner(), 42);
            assert_eq!(h.group_id.into_inner(), 7);
            assert_eq!(h.publisher_priority, 128);
        }
        other => panic!("unexpected draft variant: {other:?}"),
    }
    assert_eq!(got_object.payload, b"hello-subgroup");
    assert_eq!(got_object.object_id.into_inner(), 0);

    let events = recorder.snapshot();
    assert!(
        events.iter().any(|e| matches!(
            e,
            ClientEvent::StreamOpened {
                direction: Direction::Send,
                stream_kind: StreamKind::Subgroup,
                ..
            }
        )),
        "missing StreamOpened event: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ClientEvent::DataStreamHeader { direction: Direction::Send, .. })),
        "missing DataStreamHeader event: {events:?}"
    );

    conn.close(0, b"done");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

#[tokio::test]
async fn datagram_send_delivers_to_server_and_emits_event() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[b"moq-00"]);

    let (dg_tx, dg_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let quic = server_handshake(endpoint).await;
        let bytes = quic.read_datagram().await.expect("read datagram");
        let mut cursor = &bytes[..];
        let decoded = DatagramObject::decode(&mut cursor).expect("decode datagram");
        let _ = dg_tx.send(decoded);
        let _ = quic.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), default_client_config())
        .await
        .expect("client connect");
    let recorder = Recorder::new();
    conn.set_observer(Box::new(recorder.clone()));

    let header = AnyDatagramHeader::Draft14(DatagramObject {
        datagram_type: DatagramType::payload(true, false, false),
        track_alias: VarInt::from_u64(99).unwrap(),
        group_id: VarInt::from_u64(3).unwrap(),
        object_id: VarInt::from_u64(11).unwrap(),
        publisher_priority: 64,
        extension_headers: Vec::new(),
        status: None,
        // Left empty here: Connection::send_datagram appends the payload
        // arg after encoding the header.
        payload: Vec::new(),
    });
    conn.send_datagram(&header, b"hello-datagram").expect("send datagram");

    let got = tokio::time::timeout(std::time::Duration::from_secs(5), dg_rx)
        .await
        .expect("server received datagram")
        .expect("channel");
    assert_eq!(got.track_alias.into_inner(), 99);
    assert_eq!(got.group_id.into_inner(), 3);
    assert_eq!(got.object_id.into_inner(), 11);
    assert_eq!(got.publisher_priority, 64);
    assert_eq!(got.payload, b"hello-datagram");

    let events = recorder.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ClientEvent::DatagramReceived { direction: Direction::Send, .. })),
        "missing DatagramReceived(Send) event: {events:?}"
    );

    conn.close(0, b"done");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

#![cfg(feature = "draft23")]
//! A fill fetch stream and a subgroup stream on one subscription each reach
//! the accept for their kind, whichever arrives first and whichever accept is
//! called first.
//!
//! draft-23 Section 3.4: a subscription carrying FILL_PARAMETERS has the
//! publisher open "a unidirectional stream beginning with a FETCH_HEADER", and
//! the subscription's own Objects arrive on subgroup streams beside it. The
//! leading stream type is all that tells the two apart:
//! draft-23 Section 6.4.1.

mod common;

use std::time::Duration;

use moqtap_client::draft23::connection::{ClientConfig, Connection, TransportType};
use moqtap_client::draft23::fill::FillParameters;
use moqtap_codec::dispatch::{AnyControlMessage, AnyFetchHeader, AnySubgroupHeader};
use moqtap_codec::draft23::data_stream::FetchHeader;
use moqtap_codec::draft23::message::{ControlMessage, Setup, SubscribeOk, FILL_PARAMETERS};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The Track Alias the peer's SUBSCRIBE_OK binds.
const ALIAS: u64 = 4;

/// The Group the subgroup stream carries.
const LIVE_GROUP: u64 = 9;

const PAYLOAD: [u8; 3] = [0xDE, 0xAD, 0xBE];

/// Which stream the peer opens first.
#[derive(Clone, Copy)]
enum First {
    Fill,
    Subgroup,
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("a fixture value fits a varint")
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft23,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn setup_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft23(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut out)
        .expect("encode SETUP");
    out
}

fn subscribe_ok_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft23(ControlMessage::SubscribeOk(SubscribeOk {
        track_alias: v(ALIAS),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    }))
    .encode(&mut out)
    .expect("encode SUBSCRIBE_OK");
    out
}

/// A FETCH_HEADER naming the subscription, then one Object: flags 0x1F state
/// Group 4, Subgroup 0, Object 0 and Priority 128 outright.
fn fill_stream_bytes(request_id: u64) -> Vec<u8> {
    let mut out = Vec::new();
    AnyFetchHeader::Draft23(FetchHeader { request_id: v(request_id) }).encode(&mut out);
    out.extend_from_slice(&[0x1F, 0x04, 0x00, 0x00, 0x80, PAYLOAD.len() as u8]);
    out.extend_from_slice(&PAYLOAD);
    out
}

/// A SUBGROUP_HEADER of Type 0x10: no Properties, Subgroup ID zero, and a
/// Publisher Priority byte.
fn subgroup_stream_bytes() -> Vec<u8> {
    vec![0x10, ALIAS as u8, LIVE_GROUP as u8, 0x80]
}

/// A reader that pulls whole control messages off one quinn stream.
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, buf: Vec::new() }
    }

    async fn read_control(&mut self) -> Option<AnyControlMessage> {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(DraftVersion::Draft23, &mut cursor) {
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
                Err(_) => return None,
            }
        }
    }
}

async fn write_stream(conn: &quinn::Connection, bytes: &[u8]) {
    let mut stream = conn.open_uni().await.expect("open a data stream");
    stream.write_all(bytes).await.expect("write the data stream");
    stream.finish().expect("finish the data stream");
}

/// The setup exchange and the SUBSCRIBE's answer, then the two data streams
/// in the order `first` names. Stays up until the client closes.
async fn serve(server: quinn::Endpoint, first: First) {
    let conn = server.accept().await.expect("accept").await.expect("tls handshake");

    let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"));
    control.read_control().await.expect("read the client's SETUP");
    let mut our_control = conn.open_uni().await.expect("open the peer's control stream");
    our_control.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

    let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
    let mut request = PeerStream::new(request);
    let subscribe = match request.read_control().await {
        Some(AnyControlMessage::Draft23(ControlMessage::Subscribe(m))) => m,
        other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
    };
    assert!(
        subscribe.parameters.iter().any(|p| p.key.into_inner() == FILL_PARAMETERS),
        "the SUBSCRIBE has to ask for a fill or no fill fetch stream is legal"
    );
    let request_id = subscribe.request_id.into_inner();
    answer.write_all(&subscribe_ok_bytes()).await.expect("write SUBSCRIBE_OK");

    let fill = fill_stream_bytes(request_id);
    let live = subgroup_stream_bytes();
    match first {
        First::Fill => {
            write_stream(&conn, &fill).await;
            write_stream(&conn, &live).await;
        }
        First::Subgroup => {
            write_stream(&conn, &live).await;
            write_stream(&conn, &fill).await;
        }
    }

    let _ = tokio::time::timeout(PATIENCE * 2, conn.closed()).await;
}

/// Connect, subscribe with a fill, and read the SUBSCRIBE_OK. Returns the
/// subscription's Request ID.
async fn subscribed(addr: std::net::SocketAddr) -> (Connection, u64) {
    let mut conn =
        tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), client_config()))
            .await
            .expect("connect did not finish")
            .expect("connect");
    let fill = FillParameters::inherited().parameter().expect("the fill block encodes");
    let mut request = tokio::time::timeout(
        PATIENCE,
        conn.subscribe(
            TrackNamespace(vec![b"conformance".to_vec()]),
            b"video".to_vec(),
            vec![fill],
        ),
    )
    .await
    .expect("subscribe did not finish")
    .expect("subscribe");
    let answer = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
        .await
        .expect("the answer never arrived")
        .expect("read SUBSCRIBE_OK");
    assert!(matches!(answer, ControlMessage::SubscribeOk(_)));
    let request_id = request.request_id().into_inner();
    (conn, request_id)
}

async fn accept_subgroup(conn: &Connection) {
    let (header, _stream) = tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
        .await
        .expect("the subgroup stream never reached accept_subgroup_stream")
        .expect("accept_subgroup_stream reads a SUBGROUP_HEADER");
    match header {
        AnySubgroupHeader::Draft23(h) => {
            assert_eq!(h.track_alias.into_inner(), ALIAS);
            assert_eq!(h.group_id.into_inner(), LIVE_GROUP, "the subgroup stream, not the fill");
        }
        #[allow(unreachable_patterns)]
        other => panic!("expected a draft-23 subgroup header, got {other:?}"),
    }
}

async fn accept_fill(conn: &mut Connection, request_id: u64) {
    let (header, mut stream) = tokio::time::timeout(PATIENCE, conn.accept_fill_stream())
        .await
        .expect("the fill fetch stream never reached accept_fill_stream")
        .expect("accept_fill_stream reads the fill's FETCH_HEADER");
    assert_eq!(header.request_id(), request_id, "the fill names the subscription");
    let (object, payload) = tokio::time::timeout(PATIENCE, stream.read_fetch_object())
        .await
        .expect("the fill's Object never arrived")
        .expect("the fill's Object decodes");
    assert_eq!((object.group_id, object.object_id), (4, 0));
    assert_eq!(payload, PAYLOAD);
}

#[tokio::test]
async fn a_subgroup_accept_leaves_a_fill_stream_that_arrived_first() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft23.quic_alpn()]);
    let peer = tokio::spawn(serve(endpoint, First::Fill));
    let (mut conn, request_id) = subscribed(addr).await;

    accept_subgroup(&conn).await;
    assert_eq!(conn.deferred_stream_count(), 1, "the fill stream is held for its accept");
    accept_fill(&mut conn, request_id).await;
    assert_eq!(conn.deferred_stream_count(), 0);

    conn.close(0, b"bye");
    tokio::time::timeout(PATIENCE * 3, peer).await.expect("the peer hung").expect("the peer task");
}

#[tokio::test]
async fn a_fill_accept_leaves_a_subgroup_stream_that_arrived_first() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft23.quic_alpn()]);
    let peer = tokio::spawn(serve(endpoint, First::Subgroup));
    let (mut conn, request_id) = subscribed(addr).await;

    accept_fill(&mut conn, request_id).await;
    assert_eq!(conn.deferred_stream_count(), 1, "the subgroup stream is held for its accept");
    accept_subgroup(&conn).await;
    assert_eq!(conn.deferred_stream_count(), 0);

    conn.close(0, b"bye");
    tokio::time::timeout(PATIENCE * 3, peer).await.expect("the peer hung").expect("the peer task");
}

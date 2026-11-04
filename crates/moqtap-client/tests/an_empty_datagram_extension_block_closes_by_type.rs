#![cfg(any(feature = "draft12", feature = "draft13"))]

//! Drafts 12 and 13: which datagram Types close the session over an Extension
//! Headers Length of 0.
//!
//! Types 0x01, 0x03 and 0x05 carry extensions and close it. Types 0x00, 0x02
//! and 0x04 carry no Extension Headers Length, so the same zero byte is payload
//! or Object Status, and the datagram is received. The ruling, with its quotes,
//! is on each draft's `ConnectionError::EmptyDatagramExtensions`.

mod common;

use std::time::Duration;

const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough that a message on its way would have arrived.
const BRIEF: Duration = Duration::from_millis(400);

/// `datagram_type`, Track Alias 7, Group 1, Object 0, Publisher Priority 128
/// and a zero byte, then what that Type has after its extension block: a
/// payload byte, Object Status 0 on 0x05, and nothing on 0x04, whose zero byte
/// is its Object Status.
fn datagram(datagram_type: u8) -> Vec<u8> {
    let mut bytes = vec![datagram_type, 0x07, 0x01, 0x00, 0x80, 0x00];
    match datagram_type {
        0x04 => {}
        0x05 => bytes.push(0x00),
        _ => bytes.push(0xAA),
    }
    bytes
}

macro_rules! type_gates {
    ($draft:ident, $feat:literal, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use super::{datagram, BRIEF, PATIENCE};
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, TransportType,
            };
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup};

            fn setup_parameters() -> Vec<KeyValuePair> {
                vec![KeyValuePair {
                    key: VarInt::from_u64(0x02).unwrap(),
                    value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
                }]
            }

            /// Send `bytes` as a datagram and report whether the session was
            /// closed.
            async fn peer(server: quinn::Endpoint, bytes: Vec<u8>) -> bool {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                let setup = ServerSetup {
                    selected_version: DraftVersion::$version.version_varint(),
                    parameters: setup_parameters(),
                };
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::ServerSetup(setup))
                    .encode(&mut out)
                    .expect("encode SERVER_SETUP");
                send.write_all(&out).await.expect("write SERVER_SETUP");
                conn.send_datagram(bytes.into()).expect("send the datagram");
                while let Ok(Ok(_)) = tokio::time::timeout(BRIEF, framed.read_control(false)).await
                {
                }
                conn.close_reason().is_some()
            }

            /// Receive `bytes`, hand any error to `close_for_data_stream`, and
            /// report the result and whether the peer saw a close.
            async fn received(bytes: Vec<u8>) -> (Result<(), ConnectionError>, bool) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let served = tokio::spawn(peer(endpoint, bytes));
                let config = ClientConfig {
                    additional_versions: Vec::new(),
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: setup_parameters(),
                };
                let conn =
                    tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), config))
                        .await
                        .expect("connect did not finish")
                        .expect("connect");
                let got = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the datagram never arrived")
                    .map(|_| ());
                if let Err(err) = &got {
                    conn.close_for_data_stream(err);
                }
                let closed =
                    tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap();
                (got, closed)
            }

            #[tokio::test]
            async fn types_with_extensions_close_the_session() {
                for datagram_type in [0x01, 0x03, 0x05] {
                    let (got, closed) = received(datagram(datagram_type)).await;
                    assert!(
                        matches!(
                            got,
                            Err(ConnectionError::EmptyDatagramExtensions { object_id: 0 })
                        ),
                        "Type {datagram_type:#04x}: expected an empty extension block, got {got:?}"
                    );
                    assert!(closed, "Type {datagram_type:#04x}: the session was not closed");
                }
            }

            #[tokio::test]
            async fn types_without_extensions_are_received() {
                for datagram_type in [0x00, 0x02, 0x04] {
                    let (got, closed) = received(datagram(datagram_type)).await;
                    assert!(got.is_ok(), "Type {datagram_type:#04x}: refused with {got:?}");
                    assert!(!closed, "Type {datagram_type:#04x}: the session was closed");
                }
            }
        }
    };
}

type_gates!(draft12, "draft12", Draft12);
type_gates!(draft13, "draft13", Draft13);

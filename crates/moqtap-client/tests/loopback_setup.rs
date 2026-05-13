//! Loopback handshake test — verifies `Connection::connect()` performs
//! CLIENT_SETUP/SERVER_SETUP against a real quinn endpoint.
//!
//! The server side is built on raw quinn + moqtap-codec so it acts as a
//! neutral peer. Nothing here proves interop with other MoQT
//! implementations, only that our wire framing and state transitions
//! survive a round-trip over real QUIC.

mod common;

use moqtap_client::draft14::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
use moqtap_codec::version::DraftVersion;

const DRAFT14_VERSION: u64 = 0xff000000 + 14;

#[tokio::test]
async fn handshake_succeeds_against_loopback_server() {
    common::init_crypto();
    let (server_endpoint, addr) = common::spawn_server(&[b"moq-00"]);

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.expect("accept");
        let conn = incoming.await.expect("tls handshake");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft14);

        let (msg, _raw) = framed_recv.read_control(false).await.expect("read client setup");
        let selected = match msg {
            AnyControlMessage::Draft14(ControlMessage::ClientSetup(cs)) => {
                assert!(!cs.supported_versions.is_empty());
                cs.supported_versions[0]
            }
            other => panic!("expected CLIENT_SETUP, got {other:?}"),
        };

        let server_setup = AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: vec![],
        }));
        framed_send.write_control(&server_setup).await.expect("write server setup");

        // Hold open until the client closes — otherwise it would see FIN
        // mid-assertion.
        let _ = conn.closed().await;
    });

    let config = ClientConfig {
        draft: DraftVersion::Draft14,
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    };
    let conn = Connection::connect(&addr.to_string(), config).await.expect("client connect");

    let negotiated = conn.negotiated_version().expect("negotiated version set");
    assert_eq!(negotiated.into_inner(), DRAFT14_VERSION);
    assert_eq!(conn.draft(), DraftVersion::Draft14);

    conn.close(0, b"bye");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

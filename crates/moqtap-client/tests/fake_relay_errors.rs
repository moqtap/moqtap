//! Error-injection tests. A minimal server built on raw quinn +
//! moqtap-codec plays the role of a misbehaving peer to drive the
//! client's handshake failure paths.
//!
//! This covers the failure modes a symmetric self-loop can't: our own
//! sender would never produce these byte sequences.

mod common;

use moqtap_client::draft14::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_client::draft14::endpoint::EndpointError;
use moqtap_client::draft14::session::setup::SetupError;
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ControlMessage, GoAway, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

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
async fn server_replies_with_goaway_returns_not_active() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[b"moq-00"]);

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("accept");
        let conn = incoming.await.expect("tls");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft14);
        let _ = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        // Write GOAWAY instead of SERVER_SETUP.
        let bad = AnyControlMessage::Draft14(ControlMessage::GoAway(GoAway {
            new_session_uri: b"somewhere-else".to_vec(),
        }));
        framed_send.write_control(&bad).await.expect("write GOAWAY");
        let _ = conn.closed().await;
    });

    let err = match Connection::connect(&addr.to_string(), default_client_config()).await {
        Ok(_) => panic!("connect should have failed"),
        Err(e) => e,
    };
    assert!(
        matches!(err, ConnectionError::Endpoint(EndpointError::NotActive)),
        "expected Endpoint(NotActive), got: {err:?}"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

#[tokio::test]
async fn server_selects_unknown_version_returns_no_common_version() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[b"moq-00"]);

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("accept");
        let conn = incoming.await.expect("tls");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft14);
        let _ = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        // Pick a version the client never offered.
        let bogus = VarInt::from_u64(0xff0000ff).unwrap();
        let reply = AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
            selected_version: bogus,
            parameters: vec![],
        }));
        framed_send.write_control(&reply).await.expect("write SERVER_SETUP");
        let _ = conn.closed().await;
    });

    let err = match Connection::connect(&addr.to_string(), default_client_config()).await {
        Ok(_) => panic!("connect should have failed"),
        Err(e) => e,
    };
    assert!(
        matches!(err, ConnectionError::Endpoint(EndpointError::Setup(SetupError::NoCommonVersion))),
        "expected Endpoint(Setup(NoCommonVersion)), got: {err:?}"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

#[tokio::test]
async fn server_closes_control_stream_without_replying_returns_unexpected_end() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[b"moq-00"]);

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("accept");
        let conn = incoming.await.expect("tls");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft14);
        // Read CLIENT_SETUP so the client's write completes cleanly, then
        // send FIN on the server's send stream without a reply.
        let _ = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        framed_send.finish().await.ok();
        let _ = conn.closed().await;
    });

    let err = match Connection::connect(&addr.to_string(), default_client_config()).await {
        Ok(_) => panic!("connect should have failed"),
        Err(e) => e,
    };
    assert!(matches!(err, ConnectionError::UnexpectedEnd), "expected UnexpectedEnd, got: {err:?}");

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

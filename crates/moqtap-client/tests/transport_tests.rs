use moqtap_client::transport::quic::QuicTransport;
use moqtap_client::transport::TransportError;

// ============================================================
// TransportError
// ============================================================

#[test]
fn transport_error_connection_display() {
    let err = TransportError::Connection("peer closed".to_string());
    assert!(err.to_string().contains("peer closed"));
}

#[test]
fn transport_error_write_display() {
    let err = TransportError::Write("broken pipe".to_string());
    assert!(err.to_string().contains("broken pipe"));
}

#[test]
fn transport_error_read_display() {
    let err = TransportError::Read("timeout".to_string());
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn transport_error_stream_closed_display() {
    let err = TransportError::StreamClosed;
    assert!(err.to_string().contains("stream closed"));
}

#[test]
fn transport_error_send_datagram_display() {
    let err = TransportError::SendDatagram("too large".to_string());
    assert!(err.to_string().contains("too large"));
}

#[test]
fn transport_error_connection_lost_display() {
    let err = TransportError::ConnectionLost;
    assert!(err.to_string().contains("connection lost"));
}

#[test]
fn transport_error_connect_display() {
    let err = TransportError::Connect("refused".to_string());
    assert!(err.to_string().contains("refused"));
}

// ============================================================
// QuicTransport type existence
// ============================================================

/// QuicTransport::new() is accessible (can't test I/O without a server).
#[test]
fn quic_transport_type_exists() {
    // This test verifies the type and constructor are public.
    // We can't construct a QuicTransport without a real quinn::Connection,
    // but we verify the type is accessible from tests.
    let _: fn(quinn::Connection) -> QuicTransport = QuicTransport::new;
}

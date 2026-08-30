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

#[test]
fn transport_error_stream_reset_display_carries_the_code() {
    assert!(TransportError::StreamReset(0x10).to_string().contains("16"));
}

#[test]
fn transport_error_stopped_display_carries_the_code() {
    assert!(TransportError::Stopped(0x05).to_string().contains('5'));
}

// ============================================================
// quinn error → TransportError mapping
//
// These pin the *conversion*, which is where the peer's application
// error code can be lost or attached to the wrong variant. Asserting on
// a hand-built `TransportError::StreamReset(n)` would only prove that a
// tuple variant remembers its own field.
// ============================================================

/// A read that failed because the peer sent `RESET_STREAM` must surface
/// as `StreamReset`, not as a `Read` message — otherwise a forwarder has
/// to re-parse the code out of text to mirror it.
#[test]
fn quinn_read_error_reset_maps_to_stream_reset() {
    let err: TransportError = quinn::ReadError::Reset(quinn::VarInt::from_u32(0x10)).into();
    match err {
        TransportError::StreamReset(code) => assert_eq!(code, 0x10),
        other => panic!("expected StreamReset(16), got {other:?}"),
    }
}

/// A write that failed because the peer sent `STOP_SENDING` must surface
/// as `Stopped` — the mirror-image mapping. Swapping the two would leave
/// a forwarder resetting when it should stop, and vice versa.
#[test]
fn quinn_write_error_stopped_maps_to_stopped() {
    let err: TransportError = quinn::WriteError::Stopped(quinn::VarInt::from_u32(0x05)).into();
    match err {
        TransportError::Stopped(code) => assert_eq!(code, 0x05),
        other => panic!("expected Stopped(5), got {other:?}"),
    }
}

/// Every other read cause keeps collapsing to a message, so the typed
/// variants stay a reliable "the peer abandoned this stream" signal.
#[test]
fn quinn_read_error_other_causes_stay_untyped() {
    let err: TransportError = quinn::ReadError::ClosedStream.into();
    assert!(matches!(err, TransportError::Read(_)), "got {err:?}");

    let err: TransportError = quinn::ReadError::ZeroRttRejected.into();
    assert!(matches!(err, TransportError::Read(_)), "got {err:?}");
}

/// Same for writes.
#[test]
fn quinn_write_error_other_causes_stay_untyped() {
    let err: TransportError = quinn::WriteError::ClosedStream.into();
    assert!(matches!(err, TransportError::Write(_)), "got {err:?}");

    let err: TransportError = quinn::WriteError::ZeroRttRejected.into();
    assert!(matches!(err, TransportError::Write(_)), "got {err:?}");
}

/// `read_exact` wraps `ReadError`, so the reset code has to survive one
/// extra layer of unwrapping to reach a caller of the framed helpers.
#[test]
fn quinn_read_exact_error_unwraps_to_stream_reset() {
    let err: TransportError =
        quinn::ReadExactError::ReadError(quinn::ReadError::Reset(quinn::VarInt::from_u32(0x10)))
            .into();
    match err {
        TransportError::StreamReset(code) => assert_eq!(code, 0x10),
        other => panic!("expected StreamReset(16), got {other:?}"),
    }
}

/// …but a stream that simply finished early is not a reset.
#[test]
fn quinn_read_exact_error_finished_early_is_not_a_reset() {
    let err: TransportError = quinn::ReadExactError::FinishedEarly(3).into();
    assert!(matches!(err, TransportError::Read(_)), "got {err:?}");
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

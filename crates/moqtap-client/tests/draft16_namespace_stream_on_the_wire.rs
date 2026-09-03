#![cfg(feature = "draft16")]
//! A draft-16 namespace subscription really does travel on a stream of its own.
//!
//! The endpoint gates in `draft16_namespace_has_a_stream_of_its_own.rs` prove
//! which messages the state machines take where. They cannot prove what a peer
//! sees, and the whole of Section 3.3 is a statement about the wire: "This
//! specification only specifies two uses of bidirectional streams, the control
//! stream, which begins with CLIENT_SETUP, and SUBSCRIBE_NAMESPACE."
//!
//! So the peer here is a real quinn endpoint speaking draft-16 framing. It
//! counts the streams the client opens, reads what arrives on each, and — for
//! the two rules the draft answers with a session close — waits on
//! `Connection::closed` and reads the code back off the wire.
//!
//! # The two ways a subscription ends
//!
//! Section 6.1: "A SUBSCRIBE_NAMESPACE can be cancelled by closing the stream
//! with either a FIN or RESET_STREAM." Both forms are driven from the peer side
//! below, and each is checked twice over — that the client observes it, and
//! that its endpoint stops accepting the answer the subscription was owed.

mod common;

use std::time::Duration;

use moqtap_client::draft16::connection::{ClientConfig, Connection, TransportType};
use moqtap_client::draft16::endpoint::EndpointError;
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::message::{
    self, ClientSetup, ControlMessage, GoAway, RequestOk, ServerSetup, SubscribeNamespace,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-16 Section 13.4.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// REQUEST_ERROR code PREFIX_OVERLAP, draft-16 Section 13.4.2.
const PREFIX_OVERLAP: u64 = 0x30;

const PATIENCE: Duration = Duration::from_secs(10);

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"example.com".to_vec()])
}

fn suffix() -> TrackNamespace {
    TrackNamespace(vec![b"meeting=123".to_vec()])
}

/// A prefix that extends [`ns`], so the two overlap and a session may not
/// carry namespace subscriptions under both.
fn under_ns() -> TrackNamespace {
    TrackNamespace(vec![b"example.com".to_vec(), b"meeting=123".to_vec()])
}

/// A client config that grants the peer a request budget, so a peer-opened
/// namespace subscription is not refused for having no room.
fn config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft16,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: vec![KeyValuePair {
            key: varint(0x02),
            value: KvpValue::Varint(varint(100)),
        }],
    }
}

/// The peer's half of the handshake: take the client's control stream, read its
/// CLIENT_SETUP, answer with a SERVER_SETUP, and hand both halves back.
///
/// Both halves come back because both have to stay alive. Dropping the reader
/// would send `STOP_SENDING` on the control stream, and Section 3.3 says the
/// control stream "MUST NOT be closed at the underlying transport layer during
/// the session's lifetime" — a test peer that did it would be committing a
/// violation of its own halfway through measuring one.
async fn handshake(
    conn: &quinn::Connection,
) -> (
    moqtap_client::draft16::connection::FramedSendStream,
    moqtap_client::draft16::connection::FramedRecvStream,
) {
    use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};

    let (send, recv) = conn.accept_bi().await.expect("the client's control stream");
    let mut send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
    let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
    let (msg, _) = recv.read_control(false).await.expect("read CLIENT_SETUP");
    assert!(
        matches!(msg, AnyControlMessage::Draft16(ControlMessage::ClientSetup(ClientSetup { .. }))),
        "the control stream opens with CLIENT_SETUP, got {msg:?}"
    );
    send.write_control(&AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup {
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    })))
    .await
    .expect("write SERVER_SETUP");
    (send, recv)
}

// -- The request goes on a stream of its own ---------------------------------

/// The SUBSCRIBE_NAMESPACE arrives on a second bidirectional stream, not on the
/// control stream.
///
/// Section 6.1: "The subscriber sends SUBSCRIBE_NAMESPACE on a new
/// bidirectional stream".
///
/// # What it catches
///
/// Reverting `Connection::subscribe_namespace` to `self.send_control(&msg)`
/// fails with
///
/// ```text
/// the client never opened a second bidirectional stream: Elapsed(())
/// ```
///
/// The client still allocates the Request ID and still writes a well-formed
/// SUBSCRIBE_NAMESPACE; it writes it in the one place this draft does not put
/// it, and no endpoint gate can see that.
#[tokio::test]
async fn the_request_opens_a_bidirectional_stream_of_its_own() {
    use moqtap_client::draft16::connection::FramedRecvStream;
    use moqtap_client::transport::RecvStream;

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (_send, recv) = tokio::time::timeout(PATIENCE, conn.accept_bi())
            .await
            .expect("the client never opened a second bidirectional stream")
            .expect("accept_bi");
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        let (msg, _) = recv.read_control(false).await.expect("read the request");
        match msg {
            AnyControlMessage::Draft16(ControlMessage::SubscribeNamespace(sn)) => {
                assert_eq!(sn.namespace_prefix, ns());
                sn.request_id
            }
            other => panic!("a namespace subscription's stream opens with it, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let stream =
        conn.subscribe_namespace(ns(), varint(0), vec![]).await.expect("subscribe_namespace");
    let seen = peer.await.expect("peer task");
    assert_eq!(seen, stream.request_id(), "the stream carries the id the endpoint allocated");
    // Held to the end on purpose: dropping it is a cancellation.
    drop(stream);
}

/// The answer and the namespaces that follow it are read off that same stream.
///
/// Section 9.25: "The publisher will respond with REQUEST_OK or REQUEST_ERROR
/// on the response half of the stream. If the SUBSCRIBE_NAMESPACE is
/// successful, the publisher will send matching NAMESPACE messages on the
/// response stream if they are requested."
#[tokio::test]
async fn the_answer_and_its_namespaces_come_back_on_that_stream() {
    use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (send, recv) =
            tokio::time::timeout(PATIENCE, conn.accept_bi()).await.expect("accept").expect("bi");
        let mut send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        let (msg, _) = recv.read_control(false).await.expect("read the request");
        let AnyControlMessage::Draft16(ControlMessage::SubscribeNamespace(sn)) = msg else {
            panic!("expected SUBSCRIBE_NAMESPACE");
        };
        for m in [
            ControlMessage::RequestOk(RequestOk { request_id: sn.request_id, parameters: vec![] }),
            ControlMessage::Namespace(message::Namespace { namespace_suffix: suffix() }),
            ControlMessage::NamespaceDone(message::NamespaceDone { namespace_suffix: suffix() }),
        ] {
            send.write_control(&AnyControlMessage::Draft16(m)).await.expect("write");
        }
        let _ = conn.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let mut stream =
        conn.subscribe_namespace(ns(), varint(0), vec![]).await.expect("subscribe_namespace");

    let answer = conn.recv_on_namespace_stream(&mut stream).await.expect("the answer");
    assert!(matches!(answer, Some(ControlMessage::RequestOk(_))), "got {answer:?}");
    let first = conn.recv_on_namespace_stream(&mut stream).await.expect("a namespace");
    assert!(matches!(first, Some(ControlMessage::Namespace(_))), "got {first:?}");
    let second = conn.recv_on_namespace_stream(&mut stream).await.expect("its withdrawal");
    assert!(matches!(second, Some(ControlMessage::NamespaceDone(_))), "got {second:?}");
    conn.close(0, b"done");
    let _ = peer.await;
}

// -- The two ways it is withdrawn --------------------------------------------

/// The peer's FIN withdraws the subscription, and the endpoint records it.
///
/// Section 6.1 names a FIN as one of the two forms of the cancellation, so a
/// clean end of stream is not an error here: it comes back as `Ok(None)`.
///
/// # What it catches
///
/// Dropping the `cancel_namespace_subscription` call from the `Ok(None)` arm of
/// `recv_on_namespace_stream` fails with
///
/// ```text
/// the answer owed to a withdrawn subscription must be refused, got Ok(())
/// ```
///
/// The client still sees the stream end; its endpoint goes on believing the
/// subscription is live and applies whatever arrives next to it.
#[tokio::test]
async fn the_peers_fin_withdraws_the_subscription() {
    use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (send, recv) =
            tokio::time::timeout(PATIENCE, conn.accept_bi()).await.expect("accept").expect("bi");
        let mut send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        let _ = recv.read_control(false).await.expect("read the request");
        // No answer at all: Section 6.1 lets a request be withdrawn before one.
        send.finish().await.expect("FIN");
        let _ = conn.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let mut stream =
        conn.subscribe_namespace(ns(), varint(0), vec![]).await.expect("subscribe_namespace");
    let id = stream.request_id();

    let end = tokio::time::timeout(PATIENCE, conn.recv_on_namespace_stream(&mut stream))
        .await
        .expect("the peer's FIN never arrived")
        .expect("a clean end is not an error");
    assert!(end.is_none(), "a FIN ends the stream rather than delivering a message, got {end:?}");

    let owed = conn.endpoint_mut().receive_on_namespace_stream(
        id,
        &ControlMessage::RequestOk(RequestOk { request_id: id, parameters: vec![] }),
    );
    assert!(
        owed.is_err(),
        "the answer owed to a withdrawn subscription must be refused, got {owed:?}"
    );
    conn.close(0, b"done");
    let _ = peer.await;
}

/// The peer's reset withdraws it too, by the other half of the same sentence.
///
/// # What it catches
///
/// Dropping the `cancel_namespace_subscription` call from the error arm of
/// `recv_on_namespace_stream` fails with
///
/// ```text
/// the answer owed to a reset subscription must be refused, got Ok(())
/// ```
#[tokio::test]
async fn the_peers_reset_withdraws_the_subscription() {
    use moqtap_client::draft16::connection::FramedRecvStream;
    use moqtap_client::transport::RecvStream;

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (mut send, recv) =
            tokio::time::timeout(PATIENCE, conn.accept_bi()).await.expect("accept").expect("bi");
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        let _ = recv.read_control(false).await.expect("read the request");
        send.reset(quinn::VarInt::from_u32(1)).expect("RESET_STREAM");
        let _ = conn.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let mut stream =
        conn.subscribe_namespace(ns(), varint(0), vec![]).await.expect("subscribe_namespace");
    let id = stream.request_id();

    let outcome = tokio::time::timeout(PATIENCE, conn.recv_on_namespace_stream(&mut stream))
        .await
        .expect("the peer's reset never arrived");
    assert!(outcome.is_err(), "a reset is an error to the reader, got {outcome:?}");

    let owed = conn.endpoint_mut().receive_on_namespace_stream(
        id,
        &ControlMessage::RequestOk(RequestOk { request_id: id, parameters: vec![] }),
    );
    assert!(owed.is_err(), "the answer owed to a reset subscription must be refused, got {owed:?}");
    conn.close(0, b"done");
    let _ = peer.await;
}

/// Dropping the handle ends the stream with a FIN, which on this draft is
/// exactly the cancellation — and leaves the endpoint's record standing.
///
/// This is the one place the two halves of the answer come apart, so it is
/// asserted rather than left implicit. Section 6.1 makes a FIN a cancellation,
/// so the default drop of a send stream performs the right wire act and
/// [`NamespaceStream`] needs no `Drop` of its own. What a drop cannot do is
/// reach the session, so the endpoint still holds the subscription — which is
/// why `Connection::finish_namespace_stream` exists.
///
/// # Why the peer says when it has the request
///
/// A reset discards unsent stream data, so a handle dropped the instant the
/// request was written could leave the peer with a stream that ended before
/// the request reached it — and the gate would then fail on the peer's *first*
/// read rather than on the one that measures the ending. Waiting for the peer
/// to say it has the request puts the failure where the claim is.
///
/// # What it catches
///
/// Giving `NamespaceStream` the `Drop` impl drafts 17 to 20 carry, resetting
/// both halves, fails with
///
/// ```text
/// a dropped handle finishes the stream cleanly, got Err(Transport(StreamReset(1)))
/// ```
#[tokio::test]
async fn dropping_the_handle_finishes_the_stream_and_leaves_the_record() {
    use moqtap_client::draft16::connection::FramedRecvStream;
    use moqtap_client::transport::RecvStream;

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);
    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel::<()>();

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (_send, recv) =
            tokio::time::timeout(PATIENCE, conn.accept_bi()).await.expect("accept").expect("bi");
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        let _ = recv.read_control(false).await.expect("read the request");
        arrived_tx.send(()).expect("the test is still waiting");
        // The next read is the observable: `Ok(None)` is a FIN, an error is a
        // reset. Section 6.1 permits both, so what is asserted is which one a
        // dropped handle performs.
        let after = tokio::time::timeout(PATIENCE, recv.read_control_or_end(false))
            .await
            .expect("the client neither finished nor reset the stream");
        assert!(
            matches!(after, Ok(None)),
            "a dropped handle finishes the stream cleanly, got {after:?}"
        );
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let stream =
        conn.subscribe_namespace(ns(), varint(0), vec![]).await.expect("subscribe_namespace");
    let id = stream.request_id();
    tokio::time::timeout(PATIENCE, arrived_rx).await.expect("the peer never got the request").ok();
    drop(stream);

    let still_there = conn.endpoint_mut().receive_on_namespace_stream(
        id,
        &ControlMessage::RequestOk(RequestOk { request_id: id, parameters: vec![] }),
    );
    assert!(
        still_there.is_ok(),
        "a drop holds the stream and not the session, so the record stands: {still_there:?}"
    );
    peer.await.expect("peer task");
    conn.close(0, b"done");
}

// -- Accepting the peer's namespace subscription -----------------------------

/// The peer opens a bidirectional stream with a SUBSCRIBE_NAMESPACE on it and
/// gets its answer back on that same stream.
///
/// Without this a draft-16 client can never be asked for its namespaces, and
/// the refusal below could not exist: an endpoint that took a bidirectional
/// stream only to refuse everything would close sessions over the one message
/// Section 3.3 permits.
#[tokio::test]
async fn the_peers_subscription_is_answered_on_its_own_stream() {
    use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (send, recv) = conn.open_bi().await.expect("open_bi");
        let mut send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        // A server's Request IDs are odd and start at 1.
        send.write_control(&AnyControlMessage::Draft16(ControlMessage::SubscribeNamespace(
            SubscribeNamespace {
                request_id: varint(1),
                namespace_prefix: ns(),
                subscribe_options: varint(0),
                parameters: vec![],
            },
        )))
        .await
        .expect("write the request");
        let (answer, _) = tokio::time::timeout(PATIENCE, recv.read_control(false))
            .await
            .expect("the client never answered on the stream")
            .expect("read the answer");
        match answer {
            AnyControlMessage::Draft16(ControlMessage::RequestOk(ok)) => {
                assert_eq!(ok.request_id, varint(1), "the answer names the request it answers");
            }
            other => panic!("the answer opens the response half, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let (request, mut stream) = tokio::time::timeout(PATIENCE, conn.accept_namespace_stream())
        .await
        .expect("the peer's stream never arrived")
        .expect("accept it");
    assert!(matches!(request, ControlMessage::SubscribeNamespace(_)), "got {request:?}");
    assert_eq!(stream.request_id(), varint(1));
    assert_eq!(
        conn.endpoint()
            .pending_subscribe_namespace(varint(1))
            .expect("the request the peer opened the stream with must be on record")
            .namespace_prefix,
        ns(),
        "the record should name the prefix that arrived on the wire"
    );
    conn.respond_ok_on_namespace_stream(&mut stream, vec![]).await.expect("answer it");
    assert!(stream.responded(), "the answer was written on this stream");
    peer.await.expect("peer task");
    conn.close(0, b"done");
}

/// A subscriber that withdraws before the answer is not answered.
///
/// Section 6.1 gives the cancellation to either endpoint and asks only for a
/// stream to close, so a subscriber may withdraw before the publisher has
/// replied. This is the direction the endpoint gates cannot reach: the
/// withdrawal arrives as a stream ending rather than as a message, and only a
/// real peer can end a stream.
///
/// # Why the FIN comes before the answer and not after
///
/// After the answer the subscription is `Active` and a second REQUEST_OK is
/// refused whether or not the withdrawal was recorded — the gate would pass
/// with the recording cut out, measuring the answered-once rule instead. Before
/// the answer the two states differ: `Pending` accepts the answer and `Done`
/// does not, so the assertion turns on the record and nothing else.
///
/// # What it catches
///
/// The same cut as `the_peers_fin_withdraws_the_subscription` — dropping the
/// `cancel_namespace_subscription` call from the `Ok(None)` arm of
/// `recv_on_namespace_stream` — fails here with
///
/// ```text
/// a subscription the peer withdrew must not be answered, got Ok(())
/// ```
#[tokio::test]
async fn a_subscription_withdrawn_before_the_answer_is_not_answered() {
    use moqtap_client::draft16::connection::FramedSendStream;
    use moqtap_client::transport::SendStream;

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (send, _recv) = conn.open_bi().await.expect("open_bi");
        let mut send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        send.write_control(&AnyControlMessage::Draft16(ControlMessage::SubscribeNamespace(
            SubscribeNamespace {
                request_id: varint(1),
                namespace_prefix: ns(),
                subscribe_options: varint(0),
                parameters: vec![],
            },
        )))
        .await
        .expect("write the request");
        // A FIN delivers what was written before it, so the request still
        // arrives; what does not arrive is anything after it.
        send.finish().await.expect("FIN");
        let _ = conn.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let (_request, mut stream) = tokio::time::timeout(PATIENCE, conn.accept_namespace_stream())
        .await
        .expect("the peer's stream never arrived")
        .expect("accept it");

    let end = tokio::time::timeout(PATIENCE, conn.recv_on_namespace_stream(&mut stream))
        .await
        .expect("the subscriber's FIN never arrived")
        .expect("a clean end is not an error");
    assert!(end.is_none(), "a FIN ends the stream rather than delivering a message, got {end:?}");

    let answer = conn.respond_ok_on_namespace_stream(&mut stream, vec![]).await;
    assert!(
        answer.is_err(),
        "a subscription the peer withdrew must not be answered, got {answer:?}"
    );
    conn.close(0, b"done");
    let _ = peer.await;
}

/// A subscription this endpoint made cannot be answered by this endpoint.
///
/// The answer is owed by whoever received the request, so the `respond_*`
/// helpers refuse a stream that came from `subscribe_namespace`. Without the
/// check the endpoint would drive the peer's side of its own state machine and
/// write a REQUEST_OK at a publisher that is waiting to send one.
#[tokio::test]
async fn a_subscription_this_endpoint_made_is_not_ours_to_answer() {
    use moqtap_client::draft16::connection::{ConnectionError, FramedRecvStream};
    use moqtap_client::transport::RecvStream;

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;
        let (_send, recv) =
            tokio::time::timeout(PATIENCE, conn.accept_bi()).await.expect("accept").expect("bi");
        let mut recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        let _ = recv.read_control(false).await.expect("read the request");
        let _ = conn.closed().await;
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let mut stream =
        conn.subscribe_namespace(ns(), varint(0), vec![]).await.expect("subscribe_namespace");
    let outcome = conn.respond_ok_on_namespace_stream(&mut stream, vec![]).await;
    assert!(
        matches!(outcome, Err(ConnectionError::NotOursToAnswer(_))),
        "a request this endpoint made is not ours to answer, got {outcome:?}"
    );
    conn.close(0, b"done");
    let _ = peer.await;
}

/// A bidirectional stream that begins with anything else closes the session on
/// the wire, with PROTOCOL_VIOLATION.
///
/// Section 3.3: "Bidirectional streams MUST NOT begin with any other message
/// type unless negotiated. If they do, the peer MUST close the Session with a
/// Protocol Violation." That close is a statement about the wire, so only the
/// peer can check it.
///
/// # What it catches
///
/// Dropping the `self.close_for(&err)` call from `accept_namespace_stream`
/// fails with
///
/// ```text
/// the client refused the stream but never closed the session: Elapsed(())
/// ```
#[tokio::test]
async fn a_bidi_stream_that_begins_with_the_wrong_message_closes_the_session() {
    use moqtap_client::draft16::connection::FramedSendStream;
    use moqtap_client::transport::SendStream;

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        let (send, _recv) = conn.open_bi().await.expect("open_bi");
        let mut send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        send.write_control(&AnyControlMessage::Draft16(ControlMessage::GoAway(GoAway {
            new_session_uri: vec![],
        })))
        .await
        .expect("write GOAWAY on a bidirectional stream");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the stream but never closed the session");
        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 3.3 names this code; the close carried {} instead",
                    u64::from(frame.error_code)
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let outcome = tokio::time::timeout(PATIENCE, conn.accept_namespace_stream())
        .await
        .expect("the peer's stream never arrived")
        .err();
    assert!(
        matches!(
            outcome,
            Some(moqtap_client::draft16::connection::ConnectionError::
                NonSubscribeNamespaceOnBidiStream(_))
        ),
        "a GOAWAY does not begin a namespace subscription: {outcome:?}"
    );
    peer.await.expect("peer task");
}

/// A NAMESPACE on the control stream closes the session on the wire too.
///
/// It belongs on a SUBSCRIBE_NAMESPACE response stream and carries no Request
/// ID, so on the control stream it names nothing. The client used to take it
/// there and do nothing with it.
///
/// # What it catches
///
/// Replacing the `Namespace` arm of `Endpoint::receive_message` with `Ok(())`
/// fails with
///
/// ```text
/// a NAMESPACE on the control stream is refused, got Ok(Namespace(Namespace {
/// namespace_suffix: TrackNamespace([[109, 101, 101, 116, 105, 110, 103, 61, 49, 50, 51]]) }))
/// ```
///
/// The client takes the message, hands it back as though it belonged there, and
/// the peer's `closed()` never resolves.
#[tokio::test]
async fn a_namespace_on_the_control_stream_closes_the_session() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (mut control_send, _control_recv) = handshake(&conn).await;
        control_send
            .write_control(&AnyControlMessage::Draft16(ControlMessage::Namespace(
                message::Namespace { namespace_suffix: suffix() },
            )))
            .await
            .expect("write NAMESPACE on the control stream");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client accepted a NAMESPACE on the control stream");
        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "a message on a stream it does not belong on closes with this code; the \
                     close carried {} instead",
                    u64::from(frame.error_code)
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let outcome = tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
        .await
        .expect("the NAMESPACE never arrived");
    assert!(
        matches!(
            outcome,
            Err(moqtap_client::draft16::connection::ConnectionError::Endpoint(
                EndpointError::NamespaceMessageOnControlStream(_)
            ))
        ),
        "a NAMESPACE on the control stream is refused, got {outcome:?}"
    );
    peer.await.expect("peer task");
}

/// The second of two overlapping namespace subscriptions is refused on its own
/// stream, under the code the draft names.
///
/// Section 9.25: "Within a session, if a publisher receives a
/// SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that shares a common
/// prefix with an established namespace subscription, it MUST respond with
/// REQUEST_ERROR with error code PREFIX_OVERLAP."
///
/// The endpoint gates prove the verdict is taken and the acceptance refused.
/// What they cannot prove is that the refusal reaches the peer, and on this
/// draft the two requests arrive on two streams, so only a real peer can put
/// the second one where the first has already been answered.
///
/// # What it catches
///
/// The same cuts as the endpoint gates: with the relation never holding, the
/// acceptance below succeeds and this fails on `expect_err`.
#[tokio::test]
async fn an_overlapping_namespace_subscription_is_refused_on_its_own_stream() {
    use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (_control_send, _control_recv) = handshake(&conn).await;

        // A server's Request IDs are odd and start at 1. The first request is
        // answered before the second is written, so the client sees them in
        // the order the rule is stated for.
        let (send, recv) = conn.open_bi().await.expect("open_bi");
        let mut first_send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        let mut first_recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        first_send
            .write_control(&AnyControlMessage::Draft16(ControlMessage::SubscribeNamespace(
                SubscribeNamespace {
                    request_id: varint(1),
                    namespace_prefix: ns(),
                    subscribe_options: varint(0),
                    parameters: vec![],
                },
            )))
            .await
            .expect("write the first request");
        let (answer, _) = tokio::time::timeout(PATIENCE, first_recv.read_control(false))
            .await
            .expect("the client never answered the first request")
            .expect("read the answer");
        assert!(
            matches!(answer, AnyControlMessage::Draft16(ControlMessage::RequestOk(_))),
            "the first namespace subscription overlaps nothing, got {answer:?}"
        );

        let (send, recv) = conn.open_bi().await.expect("open_bi");
        let mut second_send = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        let mut second_recv = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
        second_send
            .write_control(&AnyControlMessage::Draft16(ControlMessage::SubscribeNamespace(
                SubscribeNamespace {
                    request_id: varint(3),
                    namespace_prefix: under_ns(),
                    subscribe_options: varint(0),
                    parameters: vec![],
                },
            )))
            .await
            .expect("write the second request");
        let (answer, _) = tokio::time::timeout(PATIENCE, second_recv.read_control(false))
            .await
            .expect("the client never answered the second request")
            .expect("read the answer");
        match answer {
            AnyControlMessage::Draft16(ControlMessage::RequestError(err)) => {
                assert_eq!(err.request_id, varint(3), "the refusal names the request it refuses");
                assert_eq!(
                    err.error_code,
                    varint(PREFIX_OVERLAP),
                    "Section 9.25 names the code this refusal carries"
                );
            }
            other => panic!("an overlapping namespace subscription is refused, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(&addr.to_string(), config()).await.expect("client connect");
    let (_, mut first) = tokio::time::timeout(PATIENCE, conn.accept_namespace_stream())
        .await
        .expect("the peer's first stream never arrived")
        .expect("accept it");
    conn.respond_ok_on_namespace_stream(&mut first, vec![]).await.expect("answer the first");

    let (_, mut second) = tokio::time::timeout(PATIENCE, conn.accept_namespace_stream())
        .await
        .expect("the peer's second stream never arrived")
        .expect("accept it");
    let refused = conn
        .respond_ok_on_namespace_stream(&mut second, vec![])
        .await
        .expect_err("the second namespace subscription overlaps the first and may not be accepted");
    assert!(
        matches!(
            refused,
            moqtap_client::draft16::connection::ConnectionError::Endpoint(
                EndpointError::PeerPrefixOverlap { .. }
            )
        ),
        "the refusal should name the rule, and named {refused}"
    );
    conn.respond_error_on_namespace_stream(
        &mut second,
        varint(PREFIX_OVERLAP),
        varint(0),
        b"overlap".to_vec(),
    )
    .await
    .expect("and the refusal goes out under that code");
    peer.await.expect("peer task");
    conn.close(0, b"done");
}

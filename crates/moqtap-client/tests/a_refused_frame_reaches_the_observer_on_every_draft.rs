//! The frames a connection refuses reach its observer, on every draft this build
//! compiles: a SETUP refused during the handshake, a control message refused
//! after it, a frame refused on a request stream, and the SETUP this side sent
//! before a peer that never answers. A peer's close reaches the caller with its
//! code.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyClientEvent, AnyConnection, AnyConnectionError, AnyConnectionObserver,
    AnyTransportType, ErrorCause,
};
use moqtap_client::transport::{dial_quic, CodeSpace, QuicDialOptions, Transport};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The server's answer to each shape of client SETUP.
///
/// `selected` is drafts 08-14: SERVER_SETUP echoes a version from the client's
/// list. `role` is draft-07: draft-07 Section 6.2.2.1 requires both endpoints
/// to send a ROLE parameter, so the server answers with the one the client
/// sent. `server` is drafts 15 and 16: SERVER_SETUP with no version. `unified`
/// is draft-17 on: the same SETUP both ways, on a unidirectional stream.
macro_rules! answer {
    (role, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (selected, parameters) = match $client {
            AnyControlMessage::$variant(ControlMessage::ClientSetup(c)) => {
                (c.supported_versions[0], c.parameters.clone())
            }
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::$variant(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters,
        }))
    }};
    (selected, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let selected = match $client {
            AnyControlMessage::$variant(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::$variant(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: Vec::new(),
        }))
    }};
    (server, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        match $client {
            AnyControlMessage::$variant(ControlMessage::ClientSetup(_)) => {}
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        }
        // MAX_REQUEST_ID (0x02), so the client may make a request.
        AnyControlMessage::$variant(ControlMessage::ServerSetup(ServerSetup {
            parameters: vec![KeyValuePair {
                key: VarInt::from_u64(0x02).expect("a key is a varint"),
                value: KvpValue::Varint(VarInt::from_u64(100).expect("a varint")),
            }],
        }))
    }};
    (unified, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, Setup};
        match $client {
            AnyControlMessage::$variant(ControlMessage::Setup(_)) => {}
            other => panic!("expected a SETUP, got {other:?}"),
        }
        AnyControlMessage::$variant(ControlMessage::Setup(Setup { options: Vec::new() }))
    }};
}

/// One row per draft. `compiled` is an exhaustive match with no wildcard, so a
/// draft added to `DraftVersion` does not compile here until it has a row.
macro_rules! drafts {
    ($( $feat:literal => $variant:ident, $module:ident, $kind:ident; )+) => {
        /// Whether this build carries `draft`. Spelled out per feature rather
        /// than read from the facade, which is the thing under test.
        fn compiled(draft: DraftVersion) -> bool {
            match draft {
                $( DraftVersion::$variant => cfg!(feature = $feat), )+
            }
        }

        /// Whether `draft` runs its control plane on a pair of unidirectional
        /// streams rather than one bidirectional stream.
        fn unidirectional_control(draft: DraftVersion) -> bool {
            match draft {
                $( DraftVersion::$variant => stringify!($kind) == "unified", )+
            }
        }

        /// The framed bytes the peer answers `client` with.
        #[allow(unused_variables)]
        fn answer(draft: DraftVersion, client: &AnyControlMessage) -> Vec<u8> {
            let reply = match draft {
                $(
                    #[cfg(feature = $feat)]
                    DraftVersion::$variant => answer!($kind, $variant, $module, client),
                )+
                #[allow(unreachable_patterns)]
                other => panic!("{other:?} is not compiled, so no setup for it arrives"),
            };
            #[allow(unreachable_code)]
            {
                let mut out = Vec::new();
                reply.encode(&mut out).expect("a setup this test built encodes");
                out
            }
        }
    };
}

drafts! {
    "draft07" => Draft07, draft07, role;
    "draft08" => Draft08, draft08, selected;
    "draft09" => Draft09, draft09, selected;
    "draft10" => Draft10, draft10, selected;
    "draft11" => Draft11, draft11, selected;
    "draft12" => Draft12, draft12, selected;
    "draft13" => Draft13, draft13, selected;
    "draft14" => Draft14, draft14, selected;
    "draft15" => Draft15, draft15, server;
    "draft16" => Draft16, draft16, server;
    "draft17" => Draft17, draft17, unified;
    "draft18" => Draft18, draft18, unified;
    "draft19" => Draft19, draft19, unified;
    "draft20" => Draft20, draft20, unified;
    "draft21" => Draft21, draft21, unified;
    "draft22" => Draft22, draft22, unified;
    "draft23" => Draft23, draft23, unified;
}

/// A peer's view of one stream: bytes in, one decoded control message out.
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
                Ok(msg) => return Some(msg),
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
}

#[derive(Default)]
struct Collect(Mutex<Vec<AnyClientEvent>>);

impl AnyConnectionObserver for Collect {
    fn on_event(&self, event: &AnyClientEvent) {
        self.0.lock().expect("observer lock").push(event.clone());
    }
}

fn config(draft: DraftVersion) -> AnyClientConfig {
    // Draft-07 Section 6.2.2.1 requires ROLE of both endpoints, and the client
    // sends what it is given; PubSub (0x03). No later draft has the parameter.
    let setup_parameters = if draft == DraftVersion::Draft07 {
        vec![KeyValuePair {
            key: VarInt::from_u64(0x00).expect("a key is a varint"),
            value: KvpValue::Bytes(vec![0x03]),
        }]
    } else {
        Vec::new()
    };
    AnyClientConfig {
        draft,
        additional_versions: Vec::new(),
        transport: AnyTransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters,
    }
}

/// `frame` with one more byte in its body than its fields hold, so its
/// Length disagrees with them: a frame every draft's decoder refuses.
fn padded(draft: DraftVersion, frame: &[u8]) -> Vec<u8> {
    let type_len = draft.varint_len(frame[0]);
    let (length, field_len) = if draft.uses_fixed_length_framing() {
        (u64::from(u16::from_be_bytes([frame[type_len], frame[type_len + 1]])), 2)
    } else {
        let n = draft.varint_len(frame[type_len]);
        let mut cursor = &frame[type_len..type_len + n];
        (draft.decode_varint(&mut cursor).expect("a length").into_inner(), n)
    };
    let body = &frame[type_len + field_len..];
    assert_eq!(body.len() as u64, length, "{draft:?}: the frame is not one whole message");
    let mut out = frame[..type_len].to_vec();
    if draft.uses_fixed_length_framing() {
        out.extend_from_slice(&u16::try_from(length + 1).expect("short").to_be_bytes());
    } else {
        draft.encode_varint(VarInt::from_u64(length + 1).expect("short"), &mut out);
    }
    out.extend_from_slice(body);
    out.push(0x00);
    out
}

/// What the peer does once it has read the client's SETUP.
#[derive(Clone, Copy)]
enum Peer {
    /// Answer with a SETUP whose Length disagrees with its fields.
    RefuseSetup,
    /// Read the SETUP and say nothing.
    Silent,
    /// Answer properly, then send a padded SETUP on the control stream.
    RefuseLater,
    /// Answer properly, then close the connection with this code.
    Close(u32),
    /// Answer properly, then open a request stream and write on it the SETUP
    /// answered with, `padded` or as it was.
    OpenBi { padded: bool },
    /// Answer properly, then answer the client's first request stream with a
    /// padded SETUP.
    AnswerBi,
}

/// Play `script` against one client, handing back what the peer wrote last and
/// the application code the client closed the connection with.
async fn serve(
    endpoint: quinn::Endpoint,
    draft: DraftVersion,
    script: Peer,
) -> (Vec<u8>, Option<u64>) {
    let incoming = endpoint.accept().await.expect("a client");
    let conn = incoming.await.expect("tls handshake");
    let (mut send, setup) = if unidirectional_control(draft) {
        let recv = conn.accept_uni().await.expect("the client's control stream");
        let mut control = PeerStream { recv, draft, buf: Vec::new() };
        let setup = control.read_control().await.expect("the client's SETUP");
        (conn.open_uni().await.expect("open the peer's control stream"), setup)
    } else {
        let (send, recv) = conn.accept_bi().await.expect("the control stream");
        let mut control = PeerStream { recv, draft, buf: Vec::new() };
        (send, control.read_control().await.expect("the client's CLIENT_SETUP"))
    };
    let reply = answer(draft, &setup);
    let written = match script {
        Peer::RefuseSetup => {
            let bad = padded(draft, &reply);
            send.write_all(&bad).await.expect("write the padded SETUP");
            bad
        }
        Peer::Silent => Vec::new(),
        Peer::RefuseLater => {
            send.write_all(&reply).await.expect("write the SETUP");
            let bad = padded(draft, &reply);
            send.write_all(&bad).await.expect("write the padded frame");
            bad
        }
        Peer::Close(code) => {
            send.write_all(&reply).await.expect("write the SETUP");
            // Closed once the client has had time to read its SETUP, so the
            // close lands on an established session.
            tokio::time::sleep(Duration::from_millis(100)).await;
            conn.close(quinn::VarInt::from_u32(code), b"peer closed");
            Vec::new()
        }
        Peer::OpenBi { padded: pad } => {
            send.write_all(&reply).await.expect("write the SETUP");
            let (mut ours, theirs) = conn.open_bi().await.expect("open a request stream");
            let frame = if pad { padded(draft, &reply) } else { reply.clone() };
            ours.write_all(&frame).await.expect("write on the request stream");
            return finish(conn, frame, (send, ours, theirs)).await;
        }
        Peer::AnswerBi => {
            send.write_all(&reply).await.expect("write the SETUP");
            let (mut ours, mut theirs) = conn.accept_bi().await.expect("the client's request");
            let mut first = [0u8; 1];
            theirs.read_exact(&mut first).await.expect("the request");
            let frame = padded(draft, &reply);
            ours.write_all(&frame).await.expect("write the answer");
            return finish(conn, frame, (send, ours, theirs)).await;
        }
    };
    finish(conn, written, send).await
}

/// Wait for the client to close, holding `streams` open until it does.
async fn finish<T>(
    conn: quinn::Connection,
    written: Vec<u8>,
    streams: T,
) -> (Vec<u8>, Option<u64>) {
    let closed = tokio::time::timeout(PATIENCE, conn.closed()).await;
    drop(streams);
    let code = match closed {
        Ok(quinn::ConnectionError::ApplicationClosed(close)) => Some(close.error_code.into_inner()),
        _ => None,
    };
    (written, code)
}

/// Dial a fresh peer playing `script`.
async fn start(
    draft: DraftVersion,
    script: Peer,
) -> (Transport, tokio::task::JoinHandle<(Vec<u8>, Option<u64>)>) {
    let (endpoint, addr) = common::spawn_server(&[draft.quic_alpn()]);
    let peer = tokio::spawn(serve(endpoint, draft, script));
    let (transport, _) = tokio::time::timeout(
        PATIENCE,
        dial_quic(
            &addr.to_string(),
            &QuicDialOptions::new(vec![draft.quic_alpn().to_vec()]).insecure(true),
        ),
    )
    .await
    .expect("the dial completes within the timeout")
    .expect("dial");
    (transport, peer)
}

impl Collect {
    fn events(&self) -> Vec<AnyClientEvent> {
        self.0.lock().expect("observer lock").clone()
    }
}

fn compiled_drafts() -> impl Iterator<Item = DraftVersion> {
    DraftVersion::ALL.into_iter().filter(|draft| compiled(*draft))
}

/// A SETUP the client refuses reaches an observer attached before the
/// handshake, after the SETUP the client sent, with the bytes the peer wrote.
#[tokio::test]
async fn a_refused_setup_reaches_an_observer_attached_before_the_handshake() {
    common::init_crypto();
    for draft in compiled_drafts() {
        let (transport, peer) = start(draft, Peer::RefuseSetup).await;
        let events = Arc::new(Collect::default());
        let adopted = tokio::time::timeout(
            PATIENCE,
            AnyConnection::adopt_observed(transport, config(draft), events.clone()),
        )
        .await
        .unwrap_or_else(|_| panic!("{draft:?}: adopt did not finish"));
        let err = adopted.err().unwrap_or_else(|| panic!("{draft:?}: a padded SETUP was accepted"));
        assert!(matches!(err.cause(), ErrorCause::Codec { .. }), "{draft:?}: got {err}");
        let (written, _) = tokio::time::timeout(PATIENCE, peer).await.expect("peer").expect("peer");

        let events = events.events();
        let sent = events.first().and_then(AnyClientEvent::control_frame);
        assert!(sent.is_some_and(|f| f.outbound), "{draft:?}: the client's SETUP comes first");
        let refused: Vec<_> = events.iter().filter_map(AnyClientEvent::refused_frame).collect();
        assert_eq!(refused.len(), 1, "{draft:?}: one refusal, got {events:?}");
        assert_eq!(refused[0].draft, draft);
        assert_eq!(refused[0].stream_id, None, "{draft:?}: the control stream");
        assert_eq!(refused[0].raw, &written[..], "{draft:?}: the bytes the peer wrote");
    }
}

/// The SETUP this side sent reaches the observer even when the peer never
/// answers and the caller gives up on the handshake.
#[tokio::test]
async fn the_sent_setup_is_observed_before_a_silent_peer_times_out() {
    common::init_crypto();
    for draft in compiled_drafts() {
        let (transport, peer) = start(draft, Peer::Silent).await;
        let events = Arc::new(Collect::default());
        let adopted = tokio::time::timeout(
            Duration::from_millis(500),
            AnyConnection::adopt_observed(transport, config(draft), events.clone()),
        )
        .await;
        assert!(adopted.is_err(), "{draft:?}: a silent peer completed a handshake");
        peer.abort();

        let events = events.events();
        assert_eq!(events.len(), 1, "{draft:?}: only the SETUP sent, got {events:?}");
        let sent = events[0].control_frame().expect("a control frame");
        assert!(sent.outbound, "{draft:?}");
        assert!(sent.raw.is_some_and(|raw| !raw.is_empty()), "{draft:?}: with its bytes");
    }
}

/// A control message the decoder refuses after the handshake reaches the
/// observer with the bytes the peer wrote, before the read returns its error.
#[tokio::test]
async fn a_refused_control_message_reaches_the_observer() {
    common::init_crypto();
    for draft in compiled_drafts() {
        let (transport, peer) = start(draft, Peer::RefuseLater).await;
        let events = Arc::new(Collect::default());
        let mut conn = tokio::time::timeout(
            PATIENCE,
            AnyConnection::adopt_observed(transport, config(draft), events.clone()),
        )
        .await
        .unwrap_or_else(|_| panic!("{draft:?}: adopt did not finish"))
        .unwrap_or_else(|e| panic!("{draft:?}: adopt failed: {e}"));
        let err = tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
            .await
            .unwrap_or_else(|_| panic!("{draft:?}: the padded frame never arrived"))
            .expect_err("a padded frame was accepted");
        assert!(matches!(err.cause(), ErrorCause::Codec { .. }), "{draft:?}: got {err}");
        let refused: Vec<Vec<u8>> = events
            .events()
            .iter()
            .filter_map(|e| e.refused_frame().map(|f| f.raw.to_vec()))
            .collect();
        conn.close(0, b"");
        drop(conn);
        let (written, _) = tokio::time::timeout(PATIENCE, peer).await.expect("peer").expect("peer");
        assert_eq!(refused, vec![written], "{draft:?}: one refusal, with the bytes the peer wrote");
    }
}

/// A peer's application close reaches the caller as a code in the application
/// space, sent by the peer.
#[tokio::test]
async fn a_peer_close_is_read_with_its_code() {
    common::init_crypto();
    for draft in compiled_drafts() {
        let (transport, peer) = start(draft, Peer::Close(0x1234)).await;
        let mut conn =
            tokio::time::timeout(PATIENCE, AnyConnection::adopt(transport, config(draft)))
                .await
                .unwrap_or_else(|_| panic!("{draft:?}: adopt did not finish"))
                .unwrap_or_else(|e| panic!("{draft:?}: adopt failed: {e}"));
        assert_eq!(conn.transport_close(), None, "{draft:?}: still open");
        let _ = tokio::time::timeout(PATIENCE, conn.recv_and_dispatch()).await;
        let close = conn.transport_close().unwrap_or_else(|| panic!("{draft:?}: no close"));
        assert_eq!(close.code, 0x1234, "{draft:?}");
        assert_eq!(close.space, CodeSpace::Application, "{draft:?}");
        assert!(close.by_peer, "{draft:?}");
        assert_eq!(close.reason, b"peer closed", "{draft:?}");
        drop(conn);
        let _ = tokio::time::timeout(PATIENCE, peer).await;
    }
}

/// A handshake that fails because the peer closed the connection says how it
/// closed.
#[tokio::test]
async fn a_handshake_the_peer_closed_carries_the_close() {
    common::init_crypto();
    let draft = compiled_drafts().last().expect("a draft is compiled");
    let (endpoint, addr) = common::spawn_server(&[draft.quic_alpn()]);
    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("a client").await.expect("tls handshake");
        conn.close(quinn::VarInt::from_u32(0x15), b"no");
        let _ = tokio::time::timeout(PATIENCE, conn.closed()).await;
    });
    let (transport, _) = dial_quic(
        &addr.to_string(),
        &QuicDialOptions::new(vec![draft.quic_alpn().to_vec()]).insecure(true),
    )
    .await
    .expect("dial");
    let err = tokio::time::timeout(PATIENCE, AnyConnection::adopt(transport, config(draft)))
        .await
        .expect("adopt did not finish")
        .err()
        .expect("a closed connection completed a handshake");
    let close = err.transport_close().unwrap_or_else(|| panic!("no close on {err}"));
    assert_eq!((close.code, close.space, close.by_peer), (0x15, CodeSpace::Application, true));
    let _ = tokio::time::timeout(PATIENCE, peer).await;
}

/// The compiled drafts that carry a request on a bidirectional stream of its
/// own: SUBSCRIBE_NAMESPACE on draft-16, every request from draft-17.
fn request_stream_drafts() -> impl Iterator<Item = DraftVersion> {
    compiled_drafts().filter(|draft| {
        matches!(
            draft,
            DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
                | DraftVersion::Draft20
                | DraftVersion::Draft21
                | DraftVersion::Draft22
                | DraftVersion::Draft23
        )
    })
}

/// Accept the peer's request stream through the draft's own connection, which
/// the facade does not reach, and hand back the refusal.
async fn refused_accept(conn: &mut AnyConnection) -> AnyConnectionError {
    macro_rules! accept {
        ($( $feat:literal => $variant:ident, $method:ident; )+) => {
            match conn {
                $(
                    #[cfg(feature = $feat)]
                    AnyConnection::$variant(c) => match c.$method().await {
                        Ok(_) => panic!("{:?}: the request stream was accepted", DraftVersion::$variant),
                        Err(e) => AnyConnectionError::from(e),
                    },
                )+
                #[allow(unreachable_patterns)]
                other => panic!("{:?} has no request streams", other.draft()),
            }
        };
    }
    accept! {
        "draft16" => Draft16, accept_namespace_stream;
        "draft17" => Draft17, accept_request_stream;
        "draft18" => Draft18, accept_request_stream;
        "draft19" => Draft19, accept_request_stream;
        "draft20" => Draft20, accept_request_stream;
        "draft21" => Draft21, accept_request_stream;
        "draft22" => Draft22, accept_request_stream;
        "draft23" => Draft23, accept_request_stream;
    }
}

async fn adopted(
    draft: DraftVersion,
    transport: Transport,
    events: &Arc<Collect>,
) -> AnyConnection {
    tokio::time::timeout(
        PATIENCE,
        AnyConnection::adopt_observed(transport, config(draft), events.clone()),
    )
    .await
    .unwrap_or_else(|_| panic!("{draft:?}: adopt did not finish"))
    .unwrap_or_else(|e| panic!("{draft:?}: adopt failed: {e}"))
}

/// The bytes of every refused frame `events` holds, with the stream each
/// arrived on.
fn refusals(events: &Collect) -> Vec<(Option<u64>, Vec<u8>)> {
    events
        .events()
        .iter()
        .filter_map(|e| e.refused_frame().map(|f| (f.stream_id, f.raw.to_vec())))
        .collect()
}

/// A request stream whose first frame the decoder refuses is reported with its
/// stream, and the session is closed with the code the draft names.
#[tokio::test]
async fn a_refused_frame_opening_a_request_stream_closes_the_session() {
    common::init_crypto();
    for draft in request_stream_drafts() {
        let (transport, peer) = start(draft, Peer::OpenBi { padded: true }).await;
        let events = Arc::new(Collect::default());
        let mut conn = adopted(draft, transport, &events).await;
        let err = tokio::time::timeout(PATIENCE, refused_accept(&mut conn))
            .await
            .unwrap_or_else(|_| panic!("{draft:?}: the request stream never arrived"));
        let ErrorCause::Codec { close: Some(code), .. } = err.cause() else {
            panic!("{draft:?}: a decoder refusal the draft closes over, got {err:?}");
        };
        let code = *code;
        let (written, closed) =
            tokio::time::timeout(PATIENCE, peer).await.expect("peer").expect("peer");
        assert_eq!(closed, Some(code), "{draft:?}: the session is closed with the draft's code");
        let refused = refusals(&events);
        assert_eq!(refused.len(), 1, "{draft:?}: one refusal");
        assert!(refused[0].0.is_some(), "{draft:?}: named by its stream");
        assert_eq!(refused[0].1, written, "{draft:?}: the bytes the peer wrote");
    }
}

/// A frame that decodes and opens no request is reported first as the message
/// and then as refused, with the same bytes.
#[tokio::test]
async fn a_frame_that_opens_no_request_is_reported_as_refused() {
    common::init_crypto();
    for draft in request_stream_drafts() {
        let (transport, peer) = start(draft, Peer::OpenBi { padded: false }).await;
        let events = Arc::new(Collect::default());
        let mut conn = adopted(draft, transport, &events).await;
        let err = tokio::time::timeout(PATIENCE, refused_accept(&mut conn))
            .await
            .unwrap_or_else(|_| panic!("{draft:?}: the request stream never arrived"));
        assert!(matches!(err.cause(), ErrorCause::PeerViolation { .. }), "{draft:?}: {err:?}");
        let (written, _) = tokio::time::timeout(PATIENCE, peer).await.expect("peer").expect("peer");
        let events = events.events();
        let received = events
            .iter()
            .filter_map(AnyClientEvent::control_frame)
            .filter(|f| !f.outbound)
            .filter_map(|f| f.raw.map(<[u8]>::to_vec))
            .next_back();
        assert_eq!(received.as_deref(), Some(&written[..]), "{draft:?}: reported as received");
        let refused: Vec<_> = events.iter().filter_map(AnyClientEvent::refused_frame).collect();
        assert_eq!(refused.len(), 1, "{draft:?}: one refusal");
        assert_eq!(refused[0].raw, &written[..], "{draft:?}: the same bytes");
    }
}

/// An answer the decoder refuses on a request stream this side opened is
/// reported with its stream, and the session is closed with the code the
/// draft names.
#[tokio::test]
async fn a_refused_answer_on_a_request_stream_closes_the_session() {
    common::init_crypto();
    for draft in request_stream_drafts() {
        let (transport, peer) = start(draft, Peer::AnswerBi).await;
        let events = Arc::new(Collect::default());
        let mut conn = adopted(draft, transport, &events).await;
        let mut request = conn
            .subscribe_namespace(TrackNamespace(vec![b"refused".to_vec()]))
            .await
            .unwrap_or_else(|e| panic!("{draft:?}: subscribe_namespace: {e}"));
        let err = tokio::time::timeout(PATIENCE, conn.recv_response(&mut request))
            .await
            .unwrap_or_else(|_| panic!("{draft:?}: the answer never arrived"))
            .expect_err("a padded answer was accepted");
        let ErrorCause::Codec { close: Some(code), .. } = err.cause() else {
            panic!("{draft:?}: a decoder refusal the draft closes over, got {err:?}");
        };
        let code = *code;
        let (written, closed) =
            tokio::time::timeout(PATIENCE, peer).await.expect("peer").expect("peer");
        assert_eq!(closed, Some(code), "{draft:?}: the session is closed with the draft's code");
        let refused = refusals(&events);
        assert_eq!(refused.len(), 1, "{draft:?}: one refusal");
        assert!(refused[0].0.is_some(), "{draft:?}: named by its stream");
        assert_eq!(refused[0].1, written, "{draft:?}: the bytes the peer wrote");
    }
}

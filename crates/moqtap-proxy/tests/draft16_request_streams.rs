//! Draft-16: the control plane is one bidirectional stream **and** there are
//! request streams beside it.
//!
//! # What the draft says
//!
//! Draft-16 Section 3.3 (Session initialization) opens exactly as drafts 07
//! through 15 do: "The first stream opened is a client-initiated bidirectional
//! control stream where the endpoints exchange Setup messages (Section 9.3),
//! followed by other messages defined in Section 9." It then adds a sentence
//! none of them has:
//! "This specification only specifies two uses of bidirectional streams, the
//! control stream, which begins with CLIENT_SETUP, and SUBSCRIBE_NAMESPACE.
//! Bidirectional streams MUST NOT begin with any other message type unless
//! negotiated."
//!
//! Draft-16 Section 6.1 says who opens the second kind: "The subscriber sends
//! SUBSCRIBE_NAMESPACE on a new bidirectional stream and the publisher MUST
//! send a single REQUEST_OK or REQUEST_ERROR as the first message on the
//! bidirectional stream in response to a SUBSCRIBE_NAMESPACE." Either endpoint
//! of a session can be that subscriber, so the streams arrive in both
//! directions.
//!
//! Drafts 17 through 20 moved the control plane onto a pair of unidirectional
//! streams and every bidirectional stream became a request stream — that
//! topology is gated by `control_plane_uni.rs`. Draft-16 is the one draft
//! where the two answers differ, which is why it needs a gate of its own: a
//! proxy with a single predicate for whether the control plane is
//! bidirectional and whether bidirectional streams carry requests is right on
//! drafts and silently wrong here.
//!
//! # Why the claims are about decoded messages
//!
//! Because the failure this gates is a stream that is never accepted, and an
//! unaccepted stream produces no bytes to compare. Each claim runs a real
//! draft-16 control decoder at the peer that should receive the stream and
//! asserts an exact `Vec` equality over what it produced. A stream the proxy
//! never took off the transport shows up as the empty sequence, with the
//! assertion naming which direction was dropped.
//!
//! # The three cuts
//!
//! One per direction, and one for the predicate that feeds both:
//!
//! * the client-to-relay branch of `forward_control_stream`'s `select!`
//!   replaced by a pending future — the direction where the control stream
//!   and the request streams share one transport;
//! * the relay-to-client accept loop dropped from the session wiring — the
//!   direction nothing accepted at all before;
//! * `bidi_streams_carry_requests` narrowed back to the drafts whose control
//!   plane is unidirectional, which is the whole change reverted.
//!
//! The third loses both directions and is still not a substitute for the
//! first two: it fails on the earlier of the two claims and never reaches the
//! later one, so the direction it stops short of would be measured by
//! nothing. Each message is recorded on the gate below.

#![cfg(feature = "draft16")]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::message::{
    ClientSetup, ControlMessage, MaxRequestId, RequestOk, RequestsBlocked, ServerSetup,
    SubscribeNamespace,
};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::hook::{FrameCtx, ProxyHook};
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};

use tokio::task::JoinHandle;

const DRAFT: DraftVersion = DraftVersion::Draft16;

/// How long an anchored poll waits before it gives up and lets the assertion
/// after it report the shortfall.
///
/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

// ── the fixture messages ───────────────────────────────────────────────

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("a fixture varint")
}

fn any(msg: ControlMessage) -> AnyControlMessage {
    AnyControlMessage::Draft16(msg)
}

/// CLIENT_SETUP, the message draft-16 Section 3.3 says the control stream
/// begins with.
fn client_setup() -> AnyControlMessage {
    any(ControlMessage::ClientSetup(ClientSetup { parameters: Vec::new() }))
}

/// SERVER_SETUP, the answer on the other direction of the same stream.
fn server_setup() -> AnyControlMessage {
    any(ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }))
}

/// MAX_REQUEST_ID: a message that belongs on the control stream and nowhere
/// else, which is what makes it usable as a rewrite target. It is not one of
/// the two message types draft-16 Section 3.3 lets a bidirectional stream
/// begin with, so a rewrite that landed on a request stream would be a rewrite
/// in a place this message cannot be.
fn max_request_id(id: u64) -> AnyControlMessage {
    any(ControlMessage::MaxRequestId(MaxRequestId { request_id: varint(id) }))
}

/// REQUESTS_BLOCKED, what the hook turns the one MAX_REQUEST_ID into. Another
/// single-varint control message, so the two differ in their type and in
/// nothing else — a decoder that had lost the framing could not produce
/// either one by accident.
fn requests_blocked(id: u64) -> AnyControlMessage {
    any(ControlMessage::RequestsBlocked(RequestsBlocked { maximum_request_id: varint(id) }))
}

/// SUBSCRIBE_NAMESPACE, the one message besides CLIENT_SETUP that draft-16
/// Section 3.3 lets a bidirectional stream begin with.
fn subscribe_namespace(request_id: u64, prefix: &[u8]) -> AnyControlMessage {
    any(ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(request_id),
        namespace_prefix: TrackNamespace(vec![prefix.to_vec()]),
        subscribe_options: varint(0),
        parameters: Vec::new(),
    }))
}

/// REQUEST_OK, which draft-16 Section 6.1 requires as the first message back
/// on the same stream.
fn request_ok(request_id: u64) -> AnyControlMessage {
    any(ControlMessage::RequestOk(RequestOk { request_id: varint(request_id), parameters: vec![] }))
}

/// The Request ID the client's namespace subscription carries: even, which is
/// the client's half of the space on this draft.
const CLIENT_REQUEST: u64 = 0;

/// The relay's: odd, the server's half.
const RELAY_REQUEST: u64 = 1;

/// The ceiling value the hook rewrites on. Named once so the message the
/// client writes, the message the hook matches and the message the relay must
/// decode are the same value.
const REWRITTEN_CEILING: u64 = 64;

/// A second ceiling, written by the relay and left alone — so claim 2 shows
/// the rewrite was selective rather than applied to everything of that type.
const UNTOUCHED_CEILING: u64 = 128;

/// Frame `msg` as it goes on the wire: type varint, 16-bit length, payload.
///
/// The same encoder produces the bytes a peer writes and the bytes the hook
/// substitutes, so nothing here asserts against its own idea of the framing.
fn framed(msg: &AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("every fixture message encodes");
    out
}

/// One decoded message, rendered for comparison.
///
/// `AnyControlMessage` carries no `PartialEq`, so the sequences here are
/// compared through the derived `Debug`, which prints every field of every
/// message this file builds.
fn shown(msg: &AnyControlMessage) -> String {
    format!("{msg:?}")
}

/// [`shown`] over a whole expected sequence.
fn shown_all(msgs: &[AnyControlMessage]) -> Vec<String> {
    msgs.iter().map(shown).collect()
}

// ── what a peer decoded ────────────────────────────────────────────────

/// What one [`ControlLog`]'s reader has produced so far.
#[derive(Default)]
struct LogState {
    decoded: Vec<AnyControlMessage>,
    failure: Option<String>,
}

/// How many bytes the message at the head of `pending` occupies, or `None`
/// while too few bytes have arrived to say.
///
/// Buffering, not decoding: it exists so `AnyControlMessage::decode` is handed
/// a complete message and never a partial one, because a short read and a
/// desynchronized stream would otherwise both come back as "insufficient
/// bytes".
fn framed_len(pending: &[u8]) -> Option<usize> {
    let type_len = DRAFT.varint_len(*pending.first()?);
    let hi = *pending.get(type_len)? as usize;
    let lo = *pending.get(type_len + 1)? as usize;
    Some(type_len + 2 + ((hi << 8) | lo))
}

/// A live decoder over one stream of framed MoQT messages.
///
/// Spawned rather than drained at the end, because every claim here is about
/// what a peer had decoded *by* some point, and a fixture has to be able to
/// wait for one message before writing the next.
struct ControlLog {
    state: Arc<Mutex<LogState>>,
    task: JoinHandle<()>,
}

impl ControlLog {
    fn spawn(mut recv: quinn::RecvStream) -> Self {
        assert!(
            DRAFT.uses_fixed_length_framing(),
            "the length field this reader walks is the 16-bit big-endian one drafts 11 and \
             later use",
        );
        let state = Arc::new(Mutex::new(LogState::default()));
        let sink = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut pending: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => pending.extend_from_slice(&chunk[..n]),
                    // End of stream, or the connection went away. Whatever
                    // was decoded stands.
                    Ok(None) | Err(_) => return,
                }
                while let Some(len) = framed_len(&pending) {
                    if pending.len() < len {
                        break;
                    }
                    let mut cursor = &pending[..len];
                    match AnyControlMessage::decode(DRAFT, &mut cursor) {
                        Ok(message) => sink.lock().expect("control log").decoded.push(message),
                        Err(e) => {
                            sink.lock().expect("control log").failure = Some(e.to_string());
                            return;
                        }
                    }
                    pending.drain(..len);
                }
            }
        });
        Self { state, task }
    }

    fn decoded(&self) -> Vec<String> {
        self.state.lock().expect("control log").decoded.iter().map(shown).collect()
    }

    /// How the framing was lost, if it was. Folded into the assertion
    /// messages: it is the difference between reporting that the sequence is
    /// short and reporting that it is short because the stream stopped being
    /// control messages here.
    fn failure(&self) -> Option<String> {
        self.state.lock().expect("control log").failure.clone()
    }

    /// Wait until `n` messages have been decoded, and hand back whatever was
    /// decoded either way — so the caller's `assert_eq!` reports the sequence
    /// that was produced rather than a bare timeout.
    async fn wait_for(&self, n: usize) -> Vec<String> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let seen = self.decoded();
            if seen.len() >= n || Instant::now() >= deadline {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for ControlLog {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── the hook ───────────────────────────────────────────────────────────

/// Rewrites the one MAX_REQUEST_ID carrying [`REWRITTEN_CEILING`] into a
/// REQUESTS_BLOCKED, and records everything it was shown.
///
/// Selective on purpose. The proxy shows this hook the messages on the
/// control stream *and* the messages on every request stream — draft-16 Section 9
/// gives both the same framing, so both are decodable and both reach
/// `Site::Control`. A rewrite applied to everything would leave the two
/// indistinguishable in what each peer decodes.
#[derive(Default)]
struct RewriteOneCeiling {
    seen: Mutex<Vec<AnyControlMessage>>,
}

impl RewriteOneCeiling {
    fn seen(&self) -> Vec<AnyControlMessage> {
        self.seen.lock().expect("seen").clone()
    }
}

impl ProxyHook for RewriteOneCeiling {
    fn interest(&self) -> Interest {
        Interest::CONTROL
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        self.seen.lock().expect("seen").push(msg.clone());
        if shown(msg) == shown(&max_request_id(REWRITTEN_CEILING)) {
            return Action::Replace(Bytes::from(framed(&requests_blocked(REWRITTEN_CEILING))));
        }
        Action::Pass
    }
}

// ── harness ────────────────────────────────────────────────────────────

/// A proxy bound to an ephemeral loopback port, forwarding to `upstream`,
/// with a hook.
fn proxy_with_hook(upstream: SocketAddr, hook: Arc<dyn ProxyHook>) -> TransparentProxy {
    let (cert_chain, key_der) = common::self_signed_localhost();
    let config = ProxyConfig {
        listener: ListenerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("a literal address"),
            cert_chain,
            key_der,
            transport_config: None,
            transport_profile: None,
            installer: None,
            #[cfg(feature = "qlog")]
            qlog: None,
        },
        session: common::session_config(DRAFT, upstream),
    };
    TransparentProxy::with_hook(config, Arc::new(NoOpProxyObserver), hook)
}

/// Start `proxy`'s accept loop and hand back its bound address and the loop's
/// join handle.
async fn start(proxy: Arc<TransparentProxy>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let control = proxy.control();
    let running = Arc::clone(&proxy);
    let loop_task = tokio::spawn(async move {
        let _ = running.run().await;
    });
    let addr = wait_for("the proxy to bind", || control.local_addr().ok()).await;
    (addr, loop_task)
}

/// Poll `probe` until it answers, or give up naming what was awaited.
async fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(answer) = probe() {
            return answer;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── the gate ───────────────────────────────────────────────────────────

/// The first bidirectional stream is the control stream, and the ones after
/// it are request streams — in both directions.
///
/// Five exact `Vec` equalities over what real decoders at the two peers
/// produced:
///
/// 1. the relay's **first** bidirectional stream decodes to CLIENT_SETUP and
///    then the *rewritten* MAX_REQUEST_ID, so that is the stream the proxy
///    identified as the control plane and acted on;
/// 2. the client's half of the same stream decodes to what the relay wrote,
///    with its own MAX_REQUEST_ID untouched — the rewrite was one message,
///    not one type;
/// 3. a **second** client-initiated bidirectional stream reaches the relay
///    carrying its SUBSCRIBE_NAMESPACE, unrewritten;
/// 4. the answer draft-16 Section 6.1 requires comes back to the client on that same
///    stream, so the request stream is forwarded in both of its directions;
/// 5. a **relay-initiated** bidirectional stream reaches the client, which is
///    the direction nothing accepted at all before.
///
/// # What it catches, observed by making each change and running it
///
/// Dropping the client-to-relay loop — the
/// `request_streams_beside_the_control_stream` branch of
/// `forward_control_stream`'s `select!` replaced by a pending future — stops
/// the stream before claim 3 has anything to compare:
///
/// ```text
/// the client's second bidirectional stream never reached the relay: draft-16 Section 3.3
/// gives SUBSCRIBE_NAMESPACE a stream of its own, and a proxy that accepts only
/// the control stream never takes it off the transport
/// ```
///
/// Dropping the relay-to-client `forward_request_streams` spawn from the
/// session wiring leaves claims 1 to 4 green and stops at claim 5:
///
/// ```text
/// the relay's bidirectional stream never reached the client: draft-16 Section 6.1 lets
/// either endpoint be the subscriber, so a proxy that accepts bidirectional
/// streams from the client alone drops every subscription the relay makes
/// ```
///
/// # Why the coarse cut is not enough on its own
///
/// Narrowing `bidi_streams_carry_requests` back to the drafts whose control
/// plane is unidirectional reverts the whole change and loses both
/// directions — but it fails with the *first* of the two messages above and
/// stops there, so it never reaches the claim about the relay's direction. A
/// single predicate feeding two call sites needs one cut per call site, or
/// the second is measured by nothing.
#[tokio::test]
async fn the_first_bidi_is_the_control_stream_and_the_rest_are_requests() {
    common::init_crypto();
    let alpn = DRAFT.quic_alpn();

    let relay = common::FakeRelay::bind(alpn);
    let hook = Arc::new(RewriteOneCeiling::default());
    let proxy = Arc::new(proxy_with_hook(relay.addr, Arc::clone(&hook) as Arc<dyn ProxyHook>));
    let (addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, alpn).await;

    // ── the control stream ──
    //
    // The first client-initiated bidirectional stream, opening with
    // CLIENT_SETUP. Both halves are held to the end of this function: a
    // dropped `quinn::SendStream` sends a FIN, and a FIN on the control
    // stream ends the session.
    let (mut control_send, control_recv) =
        client.open_bi().await.expect("the client opens its control stream");
    control_send.write_all(&framed(&client_setup())).await.expect("the client writes CLIENT_SETUP");

    let (mut relay_control_send, relay_control_recv) = relay.accept_bi().await;
    let relay_control = ControlLog::spawn(relay_control_recv);
    let client_control = ControlLog::spawn(control_recv);

    // ── the relay's half ──
    relay_control_send
        .write_all(&framed(&server_setup()))
        .await
        .expect("the relay writes SERVER_SETUP");
    relay_control_send
        .write_all(&framed(&max_request_id(UNTOUCHED_CEILING)))
        .await
        .expect("the relay grants a ceiling");

    // ── the message the hook rewrites ──
    //
    // Written while the control stream is still the only bidirectional
    // stream in the session, so claim 1 is about that stream and nothing
    // else.
    control_send
        .write_all(&framed(&max_request_id(REWRITTEN_CEILING)))
        .await
        .expect("the client grants a ceiling");

    // ── claim 1 ──
    let want_at_relay = shown_all(&[client_setup(), requests_blocked(REWRITTEN_CEILING)]);
    assert_eq!(
        relay_control.wait_for(want_at_relay.len()).await,
        want_at_relay,
        "the relay's first bidirectional stream decoded CLIENT_SETUP and then the rewritten \
         message: this is the stream the proxy must treat as the control plane (decode \
         failure: {:?})",
        relay_control.failure(),
    );

    // ── claim 2 ──
    let want_at_client = shown_all(&[server_setup(), max_request_id(UNTOUCHED_CEILING)]);
    assert_eq!(
        client_control.wait_for(want_at_client.len()).await,
        want_at_client,
        "the other direction of the control stream reached the client, and the rewrite was one \
         message rather than every message of its type (decode failure: {:?})",
        client_control.failure(),
    );

    // ── the client's namespace subscription ──
    let clients = subscribe_namespace(CLIENT_REQUEST, b"studio");
    let (mut clients_send, clients_recv) =
        client.open_bi().await.expect("the client opens a namespace stream");
    clients_send.write_all(&framed(&clients)).await.expect("the client subscribes");
    let clients_answer = ControlLog::spawn(clients_recv);

    let (mut clients_at_relay_send, clients_at_relay_recv) =
        tokio::time::timeout(PATIENCE, relay.accept_bi()).await.unwrap_or_else(|_| {
            panic!(
                "the client's second bidirectional stream never reached the relay: \
                 draft-16 Section 3.3 gives SUBSCRIBE_NAMESPACE a stream of its own, and a \
                 proxy that accepts only the control stream never takes it off the transport"
            )
        });
    let clients_at_relay = ControlLog::spawn(clients_at_relay_recv);

    // ── claim 3 ──
    assert_eq!(
        clients_at_relay.wait_for(1).await,
        shown_all(&[clients]),
        "the client's second bidirectional stream reached the relay: draft-16 Section 3.3 \
         gives SUBSCRIBE_NAMESPACE a stream of its own, so a proxy that stops accepting after \
         the control stream drops every namespace subscription the client makes (decode \
         failure: {:?})",
        clients_at_relay.failure(),
    );

    // ── claim 4: draft-16 Section 6.1's answer, on the same stream ──
    clients_at_relay_send
        .write_all(&framed(&request_ok(CLIENT_REQUEST)))
        .await
        .expect("the relay answers the subscription");
    assert_eq!(
        clients_answer.wait_for(1).await,
        shown_all(&[request_ok(CLIENT_REQUEST)]),
        "Draft-16 Section 6.1 puts the REQUEST_OK on the same stream as the request, so the back \
         direction of a forwarded request stream carries it (decode failure: {:?})",
        clients_answer.failure(),
    );

    // ── the relay's own namespace subscription ──
    //
    // Draft-16 Section 6.1 gives the subscriber role to either endpoint, so this is
    // the same rule read from the other end — and it is the direction in
    // which nothing accepted a bidirectional stream at all.
    let relays = subscribe_namespace(RELAY_REQUEST, b"cdn-edge");
    let (mut relays_send, _relays_recv) = relay.open_bi().await;
    relays_send.write_all(&framed(&relays)).await.expect("the relay subscribes");

    let (_relays_at_client_send, relays_at_client_recv) =
        tokio::time::timeout(PATIENCE, client.accept_bi())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the relay's bidirectional stream never reached the client: draft-16 \
                     Section 6.1 lets either endpoint be the subscriber, so a proxy that \
                     accepts bidirectional streams from the client alone drops every \
                     subscription the relay makes"
                )
            })
            .expect("the client accepts the relay's stream");
    let relays_at_client = ControlLog::spawn(relays_at_client_recv);

    // ── claim 5 ──
    assert_eq!(
        relays_at_client.wait_for(1).await,
        shown_all(&[relays]),
        "the relay-initiated bidirectional stream reached the client (decode failure: {:?})",
        relays_at_client.failure(),
    );

    // ── and what the hook was shown ──
    //
    // Both stream kinds reach `Site::Control`, which is the pipe decision:
    // Draft-16 Section 9 gives a request stream the same framing the control stream
    // has, so its messages are decodable and a proxy that handed them to the
    // object framer instead would show the hook nothing.
    let seen = shown_all(&hook.seen());
    assert!(
        seen.contains(&shown(&client_setup())),
        "the hook was shown the CLIENT_SETUP that opened the control stream: {seen:?}",
    );
    assert!(
        seen.contains(&shown(&subscribe_namespace(CLIENT_REQUEST, b"studio"))),
        "the hook was shown the SUBSCRIBE_NAMESPACE that opened a request stream, so a request \
         stream travels the control path and not the object framer: {seen:?}",
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

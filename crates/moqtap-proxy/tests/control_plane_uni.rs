//! Drafts 17, 18 and 19: the control plane is a **pair of unidirectional
//! streams**, and a bidirectional stream is a request stream.
//!
//! # What the drafts say
//!
//! Draft-16 Section 3.3 (Session initialization): "The first stream opened is
//! a client-initiated bidirectional control stream where the endpoints
//! exchange Setup messages (Section 9.3), followed by other messages defined
//! in Section 9."
//!
//! Draft-17 Section 3.3, and word for word the same in draft-18 and draft-19:
//! "MOQT uses a pair of unidirectional streams for creating the session and
//! exchanging control messages. Each peer opens one control stream beginning
//! with a SETUP message. Using a pair of unidirectional streams rather than a
//! single bidirectional stream allows either peer to send data as soon as it
//! is able." And immediately after: "In addition to the control streams, this
//! specification uses bidirectional streams to carry requests. A request
//! stream begins with one of these six message types: TRACK_STATUS,
//! SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE, and SUBSCRIBE_NAMESPACE"
//! (seven from draft-18, which adds SUBSCRIBE_TRACKS).
//!
//! A control stream is told apart from a data stream by its first varint.
//! Draft-17 Section 3.4 (Unidirectional Stream Types): "All unidirectional
//! MOQT streams start with a variable-length integer indicating the type of
//! the stream", with 0x05 FETCH_HEADER, 0x10-0x1D SUBGROUP_HEADER and 0x2F00
//! SETUP. 0x2F00 is also the SETUP *message* type (draft-17 Section 9.4), so
//! the stream's type varint is the first field of its first message and a
//! control stream can be forwarded byte for byte.
//!
//! # Why both gates assert decoded messages and not bytes
//!
//! Because on this topology a byte assertion cannot fail. A proxy that
//! believes the first bidirectional stream is the control stream still
//! forwards a unidirectional control stream verbatim — it forwards it as an
//! opaque data stream, and the bytes arrive. Everything that distinguishes
//! the two beliefs is a *decision*: which stream a hook is shown, which
//! stream an injected message is written onto, and whether a second
//! bidirectional stream is forwarded at all. So each gate runs a real
//! per-draft control decoder at the peer and asserts an exact `Vec` equality
//! over what it produced, per stream — which is the only place those
//! decisions become visible.
//!
//! # The two gates
//!
//! * **the topology**, one row per draft — a hook that rewrites one control
//!   message rewrites it on the control stream, the request streams are
//!   untouched, and *both* request streams are forwarded.
//! * **injection**, one row per draft — the capability at risk.
//!   `ProxyControl::inject_control` places a message in the peer's
//!   control-message sequence, and nothing appears in the request stream's.
//!
//! Each runs once per compiled draft in 17-19, so a build with only one of
//! them still gates that one.

#![cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::control::ProxyControl;
use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::{FrameCtx, ProxyHook};
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};
use moqtap_proxy::transport::Leg;

use tokio::task::JoinHandle;

/// How long an anchored poll waits before it gives up and lets the assertion
/// after it report the shortfall.
///
/// A failure ceiling, never spent by a correct build: every poll here waits
/// on a monotone count a working proxy always reaches, so load makes this
/// slower and never wrong.
const PATIENCE: Duration = Duration::from_secs(10);

/// The window a negative claim is made over — that a stream stayed as short
/// as it was. Load can only make a negative claim more true.
const SETTLE: Duration = Duration::from_millis(300);

// ── the fixture messages, per draft ────────────────────────────────────
//
// Three drafts, three separate `ControlMessage` types, so every fixture is a
// match with one arm per compiled draft. NAMESPACE and NAMESPACE_DONE carry
// one field — a namespace, a list of length-prefixed byte strings — and have
// the same shape on all three, which is why they are the messages the gates
// count in: a decoder that had lost the framing by a byte cannot produce one
// by accident.

/// SETUP: the first message on a control stream, and the stream's type.
fn setup(draft: DraftVersion) -> AnyControlMessage {
    match draft {
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            use moqtap_codec::draft17::message::{ControlMessage, Setup};
            AnyControlMessage::Draft17(ControlMessage::Setup(Setup { options: Vec::new() }))
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            use moqtap_codec::draft18::message::{ControlMessage, Setup};
            AnyControlMessage::Draft18(ControlMessage::Setup(Setup { options: Vec::new() }))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            use moqtap_codec::draft19::message::{ControlMessage, Setup};
            AnyControlMessage::Draft19(ControlMessage::Setup(Setup { options: Vec::new() }))
        }
        other => panic!("{other} does not carry its control plane on unidirectional streams"),
    }
}

/// NAMESPACE, an advertisement that belongs on the control stream — it is
/// not one of the message types a request stream may begin with.
fn namespace(draft: DraftVersion, suffix: &[u8]) -> AnyControlMessage {
    let suffix = TrackNamespace(vec![suffix.to_vec()]);
    match draft {
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            use moqtap_codec::draft17::message::{ControlMessage, Namespace};
            AnyControlMessage::Draft17(ControlMessage::Namespace(Namespace {
                namespace_suffix: suffix,
            }))
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            use moqtap_codec::draft18::message::{ControlMessage, Namespace};
            AnyControlMessage::Draft18(ControlMessage::Namespace(Namespace {
                namespace_suffix: suffix,
            }))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            use moqtap_codec::draft19::message::{ControlMessage, Namespace};
            AnyControlMessage::Draft19(ControlMessage::Namespace(Namespace {
                namespace_suffix: suffix,
            }))
        }
        other => panic!("{other} does not carry its control plane on unidirectional streams"),
    }
}

/// NAMESPACE_DONE, the withdrawal of one — the same shape, a different type,
/// which is what makes it usable as a rewrite target.
fn namespace_done(draft: DraftVersion, suffix: &[u8]) -> AnyControlMessage {
    let suffix = TrackNamespace(vec![suffix.to_vec()]);
    match draft {
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            use moqtap_codec::draft17::message::{ControlMessage, NamespaceDone};
            AnyControlMessage::Draft17(ControlMessage::NamespaceDone(NamespaceDone {
                namespace_suffix: suffix,
            }))
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            use moqtap_codec::draft18::message::{ControlMessage, NamespaceDone};
            AnyControlMessage::Draft18(ControlMessage::NamespaceDone(NamespaceDone {
                namespace_suffix: suffix,
            }))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            use moqtap_codec::draft19::message::{ControlMessage, NamespaceDone};
            AnyControlMessage::Draft19(ControlMessage::NamespaceDone(NamespaceDone {
                namespace_suffix: suffix,
            }))
        }
        other => panic!("{other} does not carry its control plane on unidirectional streams"),
    }
}

/// SUBSCRIBE — one of the message types draft-17 Section 3.3 says a request
/// stream may begin with, so it is what the bidirectional streams here open
/// with.
fn subscribe(draft: DraftVersion, request_id: u64, track: &[u8]) -> AnyControlMessage {
    let id = VarInt::from_u64(request_id).expect("a request id");
    let ns = TrackNamespace(vec![b"live".to_vec()]);
    match draft {
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            use moqtap_codec::draft17::message::{ControlMessage, Subscribe};
            AnyControlMessage::Draft17(ControlMessage::Subscribe(Subscribe {
                request_id: id,
                required_request_id_delta: VarInt::from_u64(0).expect("a delta"),
                track_namespace: ns,
                track_name: track.to_vec(),
                parameters: Vec::new(),
            }))
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            use moqtap_codec::draft18::message::{ControlMessage, Subscribe};
            AnyControlMessage::Draft18(ControlMessage::Subscribe(Subscribe {
                request_id: id,
                track_namespace: ns,
                track_name: track.to_vec(),
                parameters: Vec::new(),
            }))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            use moqtap_codec::draft19::message::{ControlMessage, Subscribe};
            AnyControlMessage::Draft19(ControlMessage::Subscribe(Subscribe {
                request_id: id,
                track_namespace: ns,
                track_name: track.to_vec(),
                parameters: Vec::new(),
            }))
        }
        other => panic!("{other} does not carry its control plane on unidirectional streams"),
    }
}

/// GOAWAY — the message the second gate injects. A control-stream message
/// whose payload is a length-prefixed URI, so an injection that lost its
/// framing would leave the peer reading the URI's first bytes as a type and a
/// length.
fn goaway(draft: DraftVersion, uri: &[u8]) -> AnyControlMessage {
    let timeout = VarInt::from_u64(0).expect("a timeout");
    match draft {
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            use moqtap_codec::draft17::message::{ControlMessage, GoAway};
            AnyControlMessage::Draft17(ControlMessage::GoAway(GoAway {
                new_session_uri: uri.to_vec(),
                timeout,
            }))
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            use moqtap_codec::draft18::message::{ControlMessage, GoAway};
            AnyControlMessage::Draft18(ControlMessage::GoAway(GoAway {
                new_session_uri: uri.to_vec(),
                timeout,
                request_id: None,
            }))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            use moqtap_codec::draft19::message::{ControlMessage, GoAway};
            AnyControlMessage::Draft19(ControlMessage::GoAway(GoAway {
                new_session_uri: uri.to_vec(),
                timeout,
            }))
        }
        other => panic!("{other} does not carry its control plane on unidirectional streams"),
    }
}

/// Frame `msg` as it goes on the wire: type varint, 16-bit length, payload.
///
/// The same encoder produces the bytes a peer writes and the bytes the
/// control plane injects, so nothing here asserts against its own idea of the
/// framing.
fn framed(msg: &AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("every fixture message encodes");
    out
}

/// One decoded message, rendered for comparison.
///
/// `AnyControlMessage` carries no `PartialEq` — the dispatch enum derives
/// `Debug` and `Clone` and nothing else — so the sequences here are compared
/// through the derived `Debug`, which prints every field of every message
/// this file builds. Nothing is elided on the way: two renderings are equal
/// exactly when the two messages are, and a mismatch prints the whole message
/// rather than a discriminant.
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
    /// Every whole message decoded off the stream, in order.
    decoded: Vec<AnyControlMessage>,
    /// The first decode failure, if the stream stopped being a sequence of
    /// framed messages.
    failure: Option<String>,
}

/// How many bytes the message at the head of `pending` occupies, or `None`
/// while too few bytes have arrived to say.
///
/// Buffering, not decoding: it exists so `AnyControlMessage::decode` is
/// handed a complete message and never a partial one. Without the split, a
/// short read and a desynchronized stream both come back as "insufficient
/// bytes" and a reader that retried on every error could not tell them apart
/// — and telling them apart is the point.
///
/// The type field's width comes from the draft, because from draft-17 MoQT
/// counts leading ones where RFC 9000 read a two-bit prefix: SETUP's 0x2F00
/// is the two bytes `AF 00` here and would be four under the old rule.
fn framed_len(draft: DraftVersion, pending: &[u8]) -> Option<usize> {
    let type_len = draft.varint_len(*pending.first()?);
    let hi = *pending.get(type_len)? as usize;
    let lo = *pending.get(type_len + 1)? as usize;
    Some(type_len + 2 + ((hi << 8) | lo))
}

/// A live decoder over one stream of framed MoQT messages.
///
/// Spawned rather than drained at the end, because every claim here is about
/// what a peer had decoded *by* some point and a fixture has to be able to
/// wait for the third message before writing the fourth.
struct ControlLog {
    draft: DraftVersion,
    state: Arc<Mutex<LogState>>,
    task: JoinHandle<()>,
}

impl ControlLog {
    /// Start decoding `recv` in the background as `draft`.
    fn spawn(draft: DraftVersion, mut recv: quinn::RecvStream) -> Self {
        assert!(
            draft.uses_fixed_length_framing(),
            "the length field this reader walks is the 16-bit big-endian one drafts 11 and \
             later use; a draft that framed it as a varint would need a different walk",
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
                while let Some(len) = framed_len(draft, &pending) {
                    if pending.len() < len {
                        break;
                    }
                    let mut cursor = &pending[..len];
                    match AnyControlMessage::decode(draft, &mut cursor) {
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
        Self { draft, state, task }
    }

    /// Everything decoded so far, rendered by [`shown`].
    fn decoded(&self) -> Vec<String> {
        self.state.lock().expect("control log").decoded.iter().map(shown).collect()
    }

    /// How the framing was lost, if it was.
    ///
    /// Folded into the assertion messages rather than asserted on separately:
    /// it is the difference between "the sequence is short" and "the sequence
    /// is short because the stream stopped being control messages here".
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

    /// The draft this log decodes as — read back so a fixture that built one
    /// for the wrong draft says so rather than producing an empty sequence.
    fn draft(&self) -> DraftVersion {
        self.draft
    }
}

impl Drop for ControlLog {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── the hook the first gate watches with ───────────────────────────────

/// Rewrites every NAMESPACE it is shown into a NAMESPACE_DONE, and records
/// everything it was shown.
///
/// Selective on purpose. The proxy shows this hook the messages on the
/// control stream *and* the messages on every request stream — draft-17
/// Section 9 gives both the same framing, so both are decodable and both
/// reach `Site::Control`. Rewriting indiscriminately would leave the two
/// indistinguishable in what the peer decodes. NAMESPACE is not one of the
/// message types a request stream may begin with, so a rewrite that lands on
/// one is a rewrite that landed where it should not have.
#[derive(Default)]
struct RewriteNamespaces {
    draft: Mutex<Option<DraftVersion>>,
    seen: Mutex<Vec<AnyControlMessage>>,
}

impl RewriteNamespaces {
    fn new(draft: DraftVersion) -> Self {
        Self { draft: Mutex::new(Some(draft)), seen: Mutex::new(Vec::new()) }
    }

    fn seen(&self) -> Vec<AnyControlMessage> {
        self.seen.lock().expect("seen").clone()
    }
}

impl ProxyHook for RewriteNamespaces {
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
        let draft = self.draft.lock().expect("draft").expect("the hook was given a draft");
        if shown(msg) == shown(&namespace(draft, ADVERTISED)) {
            return Action::Replace(Bytes::from(framed(&namespace_done(draft, ADVERTISED))));
        }
        Action::Pass
    }
}

/// The namespace suffix the hook rewrites on. One value, used to build the
/// message the client writes, the message the hook matches, and the message
/// the relay must decode.
const ADVERTISED: &[u8] = b"studio-a";

// ── harness ────────────────────────────────────────────────────────────

/// A proxy bound to an ephemeral loopback port, forwarding to `upstream`.
///
/// A `TransparentProxy` rather than a directly constructed session, because
/// the second gate needs a control plane to call and a session built directly
/// belongs to none. The first gate uses the same shape so both run the same
/// code path.
fn proxy(draft: DraftVersion, upstream: SocketAddr) -> TransparentProxy {
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
        session: common::session_config(draft, upstream),
    };
    TransparentProxy::new(config, Arc::new(NoOpProxyObserver))
}

/// [`proxy`], with a hook.
fn proxy_with_hook(
    draft: DraftVersion,
    upstream: SocketAddr,
    hook: Arc<dyn ProxyHook>,
) -> TransparentProxy {
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
        session: common::session_config(draft, upstream),
    };
    TransparentProxy::with_hook(config, Arc::new(NoOpProxyObserver), hook)
}

/// Start `proxy`'s accept loop and hand back its handle, its bound address
/// and the loop's join handle.
async fn start(
    proxy: Arc<TransparentProxy>,
) -> (ProxyControl, SocketAddr, tokio::task::JoinHandle<()>) {
    let control = proxy.control();
    let running = Arc::clone(&proxy);
    let loop_task = tokio::spawn(async move {
        let _ = running.run().await;
    });
    let addr = wait_for("the proxy to bind", || control.local_addr().ok()).await;
    (control, addr, loop_task)
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

/// The id of this proxy's one live session.
async fn only_session(control: &ProxyControl) -> SessionId {
    wait_for("the session to register with the control plane", || {
        let live = control.sessions();
        (live.len() == 1).then(|| live[0])
    })
    .await
}

// ── gate one: the topology ─────────────────────────────────────────────

/// The control plane is the pair of unidirectional streams, and a
/// bidirectional stream is a request stream.
///
/// The session runs a hook that rewrites NAMESPACE into NAMESPACE_DONE, and
/// the claim is made in three exact `Vec` equalities over what real decoders
/// at the two peers produced:
///
/// 1. the relay's **unidirectional control stream** decodes to SETUP followed
///    by the *rewritten* message — so that is the stream the proxy identified
///    as the control plane, and the stream its control-plane machinery acted
///    on;
/// 2. the client's unidirectional control stream decodes to what the relay
///    wrote on its own control stream, so the second half of the pair is
///    carried too rather than the client's half alone;
/// 3. each of **two** bidirectional request streams decodes to the SUBSCRIBE
///    it carried, unrewritten — so bidirectional streams are requests, they
///    are all forwarded rather than only the first, and the control-plane
///    rewrite did not reach them.
///
/// # The mutation
///
/// `control_plane_is_unidirectional` in `session.rs` was made to return
/// `false` for every draft, which is precisely "treat the first bidirectional
/// stream as the control stream": the session then spawns
/// `forward_control_stream` on the first bidi and forwards the unidirectional
/// control streams as opaque data streams, which is what this crate did
/// before this topology was implemented.
///
/// Run as `cargo test -p moqtap-proxy --all-features --test
/// control_plane_uni`, all three rows failed on claim 1. Draft 17's, verbatim:
///
/// ```text
/// thread 'the_control_plane_is_the_uni_pair_and_a_bidi_is_a_request_stream_draft17'
/// (55988) panicked at crates\moqtap-proxy\tests\control_plane_uni.rs:668:5:
/// assertion `left == right` failed: [draft-17] the relay's control decoder
/// produced SETUP and then the rewritten NAMESPACE_DONE: this is the stream
/// the proxy must treat as the control plane (decode failure: None)
///   left: ["Draft17(Setup(Setup { options: [] }))",
///          "Draft17(Namespace(Namespace { namespace_suffix:
///          TrackNamespace([[115, 116, 117, 100, 105, 111, 45, 97]]) }))"]
///  right: ["Draft17(Setup(Setup { options: [] }))",
///          "Draft17(NamespaceDone(NamespaceDone { namespace_suffix:
///          TrackNamespace([[115, 116, 117, 100, 105, 111, 45, 97]]) }))"]
/// ```
///
/// Drafts 18 and 19 produced the same failure with their own variant names.
///
/// The NAMESPACE arrived unrewritten: the hook never saw it, because the
/// proxy was watching a bidirectional stream that on this draft is a request
/// stream. Every byte arrived and the sequence is the right length —
/// `decode failure: None` — which is exactly why a byte-level assertion could
/// not have caught it. Reverted, and the rows are green again.
#[cfg(feature = "draft17")]
#[tokio::test]
async fn the_control_plane_is_the_uni_pair_and_a_bidi_is_a_request_stream_draft17() {
    topology_gate(DraftVersion::Draft17).await;
}

/// [`the_control_plane_is_the_uni_pair_and_a_bidi_is_a_request_stream_draft17`],
/// on draft 18.
#[cfg(feature = "draft18")]
#[tokio::test]
async fn the_control_plane_is_the_uni_pair_and_a_bidi_is_a_request_stream_draft18() {
    topology_gate(DraftVersion::Draft18).await;
}

/// [`the_control_plane_is_the_uni_pair_and_a_bidi_is_a_request_stream_draft17`],
/// on draft 19.
#[cfg(feature = "draft19")]
#[tokio::test]
async fn the_control_plane_is_the_uni_pair_and_a_bidi_is_a_request_stream_draft19() {
    topology_gate(DraftVersion::Draft19).await;
}

/// The body of the three rows above.
async fn topology_gate(draft: DraftVersion) {
    common::init_crypto();
    let alpn = draft.quic_alpn();

    let relay = common::FakeRelay::bind(alpn);
    let hook = Arc::new(RewriteNamespaces::new(draft));
    let proxy =
        Arc::new(proxy_with_hook(draft, relay.addr, Arc::clone(&hook) as Arc<dyn ProxyHook>));
    let (_control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, alpn).await;

    // ── the client's half of the control plane ──
    //
    // One unidirectional stream, opening with SETUP — which is both the
    // message and the stream type, so nothing precedes it.
    let mut client_control = client.open_uni().await.expect("the client opens its control stream");
    let client_setup = setup(draft);
    client_control.write_all(&framed(&client_setup)).await.expect("the client writes SETUP");

    let relay_control = ControlLog::spawn(draft, relay.accept_uni().await);
    assert_eq!(relay_control.draft(), draft, "the relay decodes as the session's draft");

    // ── the relay's half ──
    let mut relay_control_send = relay.open_uni().await;
    let relay_setup = setup(draft);
    relay_control_send.write_all(&framed(&relay_setup)).await.expect("the relay writes SETUP");
    let relay_advert = namespace(draft, b"cdn-edge");
    relay_control_send.write_all(&framed(&relay_advert)).await.expect("the relay advertises");

    let client_control_log =
        ControlLog::spawn(draft, client.accept_uni().await.expect("the client accepts a stream"));

    // ── the control message the hook rewrites ──
    //
    // Written before any bidirectional stream exists, so claim 1 below is
    // about the unidirectional pair and nothing else: at this point in the
    // session there is no other stream the proxy could have mistaken for the
    // control plane.
    let advertised = namespace(draft, ADVERTISED);
    client_control.write_all(&framed(&advertised)).await.expect("the client advertises");

    // ── claim 1: the relay's control stream ──
    let want_control = shown_all(&[client_setup.clone(), namespace_done(draft, ADVERTISED)]);
    assert_eq!(
        relay_control.wait_for(want_control.len()).await,
        want_control,
        "[{draft}] the relay's control decoder produced SETUP and then the rewritten \
         NAMESPACE_DONE: this is the stream the proxy must treat as the control plane \
         (decode failure: {:?})",
        relay_control.failure(),
    );

    // ── claim 2: the other half of the pair ──
    let want_from_relay = shown_all(&[relay_setup, relay_advert]);
    assert_eq!(
        client_control_log.wait_for(want_from_relay.len()).await,
        want_from_relay,
        "[{draft}] the relay's own control stream reached the client: the control plane is a \
         pair, and a proxy that carried only the client's half would leave the session \
         half-established (decode failure: {:?})",
        client_control_log.failure(),
    );

    // ── two request streams ──
    //
    // Two, not one: a proxy that believes the first bidirectional stream is
    // the control stream accepts exactly one of them and never looks for
    // another, so the second is the half of this claim that no amount of
    // byte-for-byte forwarding satisfies.
    //
    // Every send half is held to the end of this function on both sides. A
    // dropped `quinn::SendStream` sends a FIN, and a FIN on a stream the
    // proxy believes is the control stream ends the session — which would
    // replace the assertions below with a closed connection and say nothing
    // about what anybody decoded.
    let first = subscribe(draft, 1, b"video");
    let (mut first_send, _first_recv) = client.open_bi().await.expect("the first request stream");
    first_send.write_all(&framed(&first)).await.expect("the client writes SUBSCRIBE(video)");
    let (_first_relay_send, first_relay_recv) = relay.accept_bi().await;
    let first_at_relay = ControlLog::spawn(draft, first_relay_recv);

    let second = subscribe(draft, 3, b"audio");
    let (mut second_send, _second_recv) =
        client.open_bi().await.expect("the second request stream");
    second_send.write_all(&framed(&second)).await.expect("the client writes SUBSCRIBE(audio)");
    let (_second_relay_send, second_relay_recv) =
        tokio::time::timeout(PATIENCE, relay.accept_bi()).await.unwrap_or_else(|_| {
            panic!(
                "[{draft}] the second request stream never reached the relay: on this draft \
                 every bidirectional stream is a request, so a proxy that forwards only the \
                 first one drops every request after it"
            )
        });
    let second_at_relay = ControlLog::spawn(draft, second_relay_recv);

    // ── claim 3: both request streams, untouched ──
    assert_eq!(
        first_at_relay.wait_for(1).await,
        shown_all(&[first]),
        "[{draft}] the first bidirectional stream is a request stream: its SUBSCRIBE reaches \
         the relay as written, and the control-plane rewrite did not reach it (decode failure: \
         {:?})",
        first_at_relay.failure(),
    );
    assert_eq!(
        second_at_relay.wait_for(1).await,
        shown_all(&[second]),
        "[{draft}] the second bidirectional stream is forwarded too (decode failure: {:?})",
        second_at_relay.failure(),
    );

    // ── and what the hook was shown ──
    //
    // The positive half of claim 1 read from the other end: the hook saw the
    // SETUP that opened the control stream, which is the message a proxy
    // watching a bidirectional stream can never be shown.
    let seen = shown_all(&hook.seen());
    assert!(
        seen.contains(&shown(&client_setup)),
        "[{draft}] the control hook was shown the SETUP that opened the control stream: {seen:?}",
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── gate two: injection ────────────────────────────────────────────────

/// `ProxyControl::inject_control` places its message in the peer's
/// **control-message** sequence, and nothing appears in the request stream's.
///
/// This is the capability the topology puts at risk, so it is gated on its
/// own. The session carries traffic on both at once: a control stream with a
/// message before the injection and one after it, and a request stream with a
/// SUBSCRIBE. Two exact `Vec` equalities:
///
/// * the relay's control decoder produced the injected GOAWAY **in sequence**,
///   between the messages written before and after it — the message after is
///   what makes this a claim about the peer's decoder rather than about one
///   successful write, since a decoder left mid-payload cannot produce it;
/// * the relay's request-stream decoder produced its SUBSCRIBE and nothing
///   else.
///
/// The hook is the default no-op one, which puts the control stream on the
/// forward-first pipe — the harder of the two paths for an injection, because
/// that pipe forwards raw read chunks and has to find the message boundaries
/// in the bytes it is forwarding.
///
/// # The mutation
///
/// The same one: `control_plane_is_unidirectional` made to return `false`, so
/// the first bidirectional stream is the control stream. All three rows
/// failed. Draft 17's, verbatim, with the `Namespace` and `NamespaceDone`
/// renderings elided where the real output spelled the namespace out as the
/// same byte list three times; nothing else is:
///
/// ```text
/// thread 'an_injection_lands_on_the_uni_control_stream_and_not_on_a_request_stream_draft17'
/// (46552) panicked at crates\moqtap-proxy\tests\control_plane_uni.rs:908:5:
/// assertion `left == right` failed: [draft-17] the relay's control decoder
/// produced the injected GOAWAY in sequence, between the messages written
/// before and after it (decode failure: None)
///   left: ["Draft17(Setup(Setup { options: [] }))",
///          "Draft17(Namespace(..))", "Draft17(NamespaceDone(..))"]
///  right: ["Draft17(Setup(Setup { options: [] }))",
///          "Draft17(Namespace(..))",
///          "Draft17(GoAway(GoAway { new_session_uri: [109, 111, 113, 116, 97,
///          112, 58, 47, 47, 101, 108, 115, 101, 119, 104, 101, 114, 101, 47],
///          timeout: VarInt(0) }))", "Draft17(NamespaceDone(..))"]
/// ```
///
/// Three messages instead of four, and the two around the hole decode
/// perfectly — nothing was written between them, which is what `decode
/// failure: None` says. The GOAWAY went onto the request stream instead,
/// where the relay's decoder read it as part of a subscription's message
/// sequence. Drafts 18 and 19 failed identically, draft 18's GOAWAY carrying
/// its extra `request_id: None`. Reverted, and the rows are green again.
#[cfg(feature = "draft17")]
#[tokio::test]
async fn an_injection_lands_on_the_uni_control_stream_and_not_on_a_request_stream_draft17() {
    injection_gate(DraftVersion::Draft17).await;
}

/// [`an_injection_lands_on_the_uni_control_stream_and_not_on_a_request_stream_draft17`],
/// on draft 18.
#[cfg(feature = "draft18")]
#[tokio::test]
async fn an_injection_lands_on_the_uni_control_stream_and_not_on_a_request_stream_draft18() {
    injection_gate(DraftVersion::Draft18).await;
}

/// [`an_injection_lands_on_the_uni_control_stream_and_not_on_a_request_stream_draft17`],
/// on draft 19.
#[cfg(feature = "draft19")]
#[tokio::test]
async fn an_injection_lands_on_the_uni_control_stream_and_not_on_a_request_stream_draft19() {
    injection_gate(DraftVersion::Draft19).await;
}

/// Where the injected message must appear in the relay's control sequence.
/// Two messages precede it and one follows.
const INJECTED_AT: usize = 2;

/// The body of the three rows above.
async fn injection_gate(draft: DraftVersion) {
    common::init_crypto();
    let alpn = draft.quic_alpn();

    let relay = common::FakeRelay::bind(alpn);
    let proxy = Arc::new(proxy(draft, relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, alpn).await;

    // ── the control plane, both halves ──
    let mut client_control = client.open_uni().await.expect("the client opens its control stream");
    let client_setup = setup(draft);
    client_control.write_all(&framed(&client_setup)).await.expect("the client writes SETUP");

    let relay_control = ControlLog::spawn(draft, relay.accept_uni().await);

    // The reverse half is written too, so the session is not a one-way pipe
    // with an obvious place to append to.
    let mut relay_control_send = relay.open_uni().await;
    let relay_setup = setup(draft);
    relay_control_send.write_all(&framed(&relay_setup)).await.expect("the relay writes SETUP");

    let id = only_session(&control).await;

    // ── a request stream, live at the same time ──
    let request = subscribe(draft, 1, b"video");
    let (mut request_send, _request_recv) = client.open_bi().await.expect("a request stream");
    request_send.write_all(&framed(&request)).await.expect("the client writes SUBSCRIBE");
    // Both halves held to the end, for the reason the topology gate gives:
    // a dropped send half FINs the stream, and a FIN on a stream this proxy
    // took for the control stream would end the session before the
    // injection had anywhere to go.
    let (_request_relay_send, request_relay_recv) = relay.accept_bi().await;
    let request_at_relay = ControlLog::spawn(draft, request_relay_recv);

    // ── one more control message, so the injection goes into a live flow ──
    let advert = namespace(draft, ADVERTISED);
    client_control.write_all(&framed(&advert)).await.expect("the client advertises");

    // Both through before the injection is asked for, which is what makes its
    // position in the decoded sequence a fact rather than a race.
    assert_eq!(
        relay_control.wait_for(2).await,
        shown_all(&[client_setup.clone(), advert.clone()]),
        "[{draft}] the two messages written before the injection reach the relay's control \
         decoder in order; without them there is no live flow to inject into (decode failure: \
         {:?})",
        relay_control.failure(),
    );
    assert_eq!(
        request_at_relay.wait_for(1).await,
        shown_all(std::slice::from_ref(&request)),
        "[{draft}] the request stream is carrying traffic too (decode failure: {:?})",
        request_at_relay.failure(),
    );

    // ── the injection ──
    let injected = goaway(draft, b"moqtap://elsewhere/");
    control
        .inject_control(id, Leg::Upstream, framed(&injected))
        .expect("a live session takes an injection for the leg its relay decodes");

    // A synchronisation point, not an assertion: the message below must be
    // written after the injection has been placed, or its position in the
    // decoded sequence is whichever branch of the pipe's select ran first. A
    // build that never places it spends the ceiling here and then fails at
    // the equality, which is the failure worth reading.
    let _ = relay_control.wait_for(INJECTED_AT + 1).await;

    // ── the flow, after the injection ──
    let closing = namespace_done(draft, ADVERTISED);
    client_control.write_all(&framed(&closing)).await.expect("the client withdraws");

    let mut expected = vec![client_setup, advert, closing];
    expected.insert(INJECTED_AT, injected.clone());
    let expected = shown_all(&expected);
    let seen = relay_control.wait_for(expected.len()).await;
    assert_eq!(
        seen,
        expected,
        "[{draft}] the relay's control decoder produced the injected GOAWAY in sequence, \
         between the messages written before and after it (decode failure: {:?})",
        relay_control.failure(),
    );
    assert_eq!(
        seen.get(INJECTED_AT),
        Some(&shown(&injected)),
        "[{draft}] the injected message is the one at index {INJECTED_AT}",
    );

    // ── and the request stream never saw it ──
    let request_seen = request_at_relay.wait_for(2).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        request_at_relay.decoded(),
        shown_all(&[request]),
        "[{draft}] the request stream carried exactly the SUBSCRIBE the client wrote: an \
         injection goes on the control stream, and a proxy that mistook a request stream for \
         one would have put a GOAWAY in front of a subscription's decoder (it had {} \
         message(s) when the control sequence completed, decode failure: {:?})",
        request_seen.len(),
        request_at_relay.failure(),
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

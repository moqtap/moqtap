//! Shared harness for proxy integration tests.
//!
//! Topology:
//!
//! ```text
//!   client (raw quinn + moqtap-client framed streams)
//!     ↓ QUIC, ALPN moq-00, self-signed cert
//!   proxy front-end endpoint (bound in the test)
//!     ↓ ProxySession::run() handed the accepted connection
//!   fake upstream (raw quinn + moqtap-client framed streams)
//! ```
//!
//! `ProxySession` is used directly rather than going through the full
//! `TransparentProxy` accept loop so tests can pick their own ephemeral
//! ports for both the proxy's front-end listener and the upstream —
//! avoiding the "how do I learn which port the proxy bound?" problem.
//!
//! # What a test can observe through this file
//!
//! This crate's test units need five things a raw quinn stream does not
//! give them, and each has one home here:
//!
//! | Question | Answer |
//! |---|---|
//! | What bytes did *this object* put on the wire? | [`TimedReceiver::into_objects`] / [`collect_objects`] |
//! | *When* did they arrive? | [`TimedReceiver::chunks`], and every object carries the `Instant` of the read that completed it |
//! | Did nothing arrive for a while? | [`assert_no_bytes_for`], [`assert_no_uni_stream_for`] |
//! | FIN or `RESET_STREAM`, and with what code? | [`Ending`], [`drain`], [`TimedReceiver::ending`] |
//! | What did the session's slow-path counters do? | [`SpawnedProxy::counters`] |
//! | Which of two concurrent destination streams is *this* one? | [`FakeRelay::timed_uni_by_alias`], [`TimedReceiver::track_alias`] |
//! | How many datagrams left the machine, below the impairment shim? | [`ImpairedSeam::wire`] / [`CountingUdpSocket::sends`] |
//!
//! Plus [`RecordingObserver`] for events and [`FakeRelay`] for a peer that
//! can *initiate* teardown in either direction rather than only observing
//! one.
//!
//! # `RecordingObserver` records destructured parts, not whole events
//!
//! [`ProxyEvent`] derives only `Debug` and `Clone` — it is deliberately
//! **not** `PartialEq`, because it carries per-draft codec types that are
//! not either. The payload enums ([`Effect`], [`Refusal`],
//! [`ImpairmentKind`], [`Site`], [`ActionKind`]) *are* `PartialEq + Eq`.
//! So the observer destructures on the way in and keeps parallel typed
//! vectors, and an assertion reads
//! `assert_eq!(obs.applied(), vec![(Site::Object, ActionKind::Drop, Effect::Elided { .. })])`
//! rather than trying to compare events. The raw `Vec<ProxyEvent>` is kept
//! too, for diagnostics and for the `matches!`-then-destructure shape
//! `ProxyEvent`'s own rustdoc teaches.
//!
//! # Framers built here use `ObjectFramer::new`, never `with_recorder`
//!
//! The framers in this file parse a *captured* byte stream in order to
//! assert on objects. Their counters are nobody's business — the counters
//! that matter belong to the session under test and are read through
//! [`SpawnedProxy::counters`]. Using `with_recorder` here would invite a
//! test to read the wrong `Recorder`.

#![allow(dead_code)]

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
#[cfg(feature = "draft14")]
use moqtap_client::draft14::connection::{FramedRecvStream, FramedSendStream};
#[cfg(feature = "draft14")]
use moqtap_client::transport::{RecvStream, SendStream};
use moqtap_codec::version::DraftVersion;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ClientConfig, Connection, Endpoint, ServerConfig, UdpPoller};
use quinn_netem::socket::ImpairedUdpSocket;
use quinn_netem::{ImpairHandle, ImpairProfile};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{
    DataStreamHeaderKind, Effect, ImpairmentKind, ProxyEvent, ProxySide, SessionId,
};
use moqtap_proxy::framer::{FramerConfig, FramerOut, ObjectFramer, ObjectMeta};
use moqtap_proxy::hook::ProxyHook;
use moqtap_proxy::instrument::Counters;
use moqtap_proxy::listener::{Listener, ListenerConfig};
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::parser::data::DataStreamType;
use moqtap_proxy::session::{ProxySession, ProxySessionConfig, UpstreamTransportType};
use moqtap_proxy::shape::ShapeStats;

/// How long a helper waits for something that should already have
/// happened before it declares the run broken.
pub const TIMEOUT: Duration = Duration::from_secs(10);

// ── crypto and endpoints ───────────────────────────────────────────────

/// Idempotent install of the ring crypto provider.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A fresh self-signed cert/key pair for `localhost`.
///
/// Exposed separately from [`spawn_quic_server`] so tests can build a
/// `moqtap_proxy::listener::ListenerConfig` without the `cert-gen`
/// feature.
pub fn self_signed_localhost() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
    let params = CertificateParams::new(vec!["localhost".into()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert_der], key_der)
}

/// A QUIC server endpoint bound to an ephemeral port on 127.0.0.1 with a
/// fresh self-signed cert for `localhost`.
pub fn spawn_quic_server(alpn: &[&[u8]]) -> (Endpoint, SocketAddr) {
    spawn_quic_server_windowed(alpn, None)
}

/// A [`quinn::TransportConfig`] whose only departure from the default is
/// `stream_receive_window`.
///
/// The knob exists for one reason, and it is worth stating so nobody
/// "tidies" it away: it is the **only** way a test can make a
/// `send.write_all` on the proxy still be in flight at a chosen instant.
/// quinn's defaults are a 1.25 MB per-stream window and no connection-level
/// limit at all, so a peer that never reads still absorbs megabytes and
/// every proxy write returns immediately. A test that needs a
/// `STOP_SENDING` to land *while the proxy is inside `write_all`* — which
/// is the only way to reach the deferred-release error path without racing
/// the stream-level stop watcher — has to shrink the window instead of
/// writing 1.25 MB of fixture.
fn windowed_transport(stream_receive_window: u32) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(stream_receive_window));
    Arc::new(transport)
}

/// [`spawn_quic_server`], optionally pinning the per-stream receive window
/// of everything this endpoint accepts. See [`windowed_transport`].
pub fn spawn_quic_server_windowed(
    alpn: &[&[u8]],
    stream_receive_window: Option<u32>,
) -> (Endpoint, SocketAddr) {
    let (cert_chain, key_der) = self_signed_localhost();
    let cert_der = cert_chain.into_iter().next().expect("one cert");

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    server_crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic crypto");
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    if let Some(window) = stream_receive_window {
        server_config.transport_config(windowed_transport(window));
    }
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind).expect("bind server");
    let addr = endpoint.local_addr().expect("local_addr");
    (endpoint, addr)
}

/// Build a QUIC client endpoint that skips certificate verification and
/// advertises the given ALPN list.
pub fn client_endpoint(alpn: &[&[u8]]) -> Endpoint {
    client_endpoint_windowed(alpn, None)
}

/// [`client_endpoint`], optionally pinning the per-stream receive window
/// this client advertises. See [`windowed_transport`].
pub fn client_endpoint_windowed(alpn: &[&[u8]], stream_receive_window: Option<u32>) -> Endpoint {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    client_crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("quic crypto");
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    if let Some(window) = stream_receive_window {
        client_config.transport_config(windowed_transport(window));
    }

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut ep = Endpoint::client(bind).expect("client endpoint");
    ep.set_default_client_config(client_config);
    ep
}

/// Connect to `addr` as a client speaking `alpn`, and hand back the
/// endpoint (which must outlive the connection) with the connection.
pub async fn connect_client(addr: SocketAddr, alpn: &[u8]) -> (Endpoint, Connection) {
    connect_client_windowed(addr, alpn, None).await
}

/// [`connect_client`], with the client's per-stream receive window pinned.
///
/// A small window is what lets a test hold the proxy inside `write_all`;
/// see [`windowed_transport`].
pub async fn connect_client_windowed(
    addr: SocketAddr,
    alpn: &[u8],
    stream_receive_window: Option<u32>,
) -> (Endpoint, Connection) {
    let ep = client_endpoint_windowed(&[alpn], stream_receive_window);
    let conn =
        ep.connect(addr, "localhost").expect("client connect").await.expect("client handshake");
    (ep, conn)
}

/// Wrap server-side quinn bi streams in moqtap framed helpers for the
/// given draft.
///
/// The `draft14::connection` path is hardcoded on purpose: both
/// constructors take a runtime [`DraftVersion`], so the module a type is
/// *named* through has no effect on what it parses. Until the client
/// exposes a draft-agnostic path to them, the *name* is what needs
/// `draft14` compiled, so this helper (and only this helper) is gated on
/// it. Its two callers, `proxy_forward.rs` and `proxy_hook_rewrite.rs`,
/// are whole-file `draft14` tests, so nothing else in the harness loses a
/// row to the gate.
#[cfg(feature = "draft14")]
pub fn frame_bi(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    draft: DraftVersion,
) -> (FramedSendStream, FramedRecvStream) {
    (
        FramedSendStream::new(SendStream::Quic(send), draft),
        FramedRecvStream::new(RecvStream::Quic(recv), draft),
    )
}

/// Rustls verifier that accepts every server cert. Tests only.
#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ── impaired sockets ───────────────────────────────────────────────────

/// A transparent `AsyncUdpSocket` decorator that counts the datagrams it
/// actually hands to the socket below it.
///
/// It exists so an assertion can span the seam between what a shim
/// *decided* and what left the machine. Counters kept by the shim itself
/// answer only the first half: a decorator that computes every
/// impairment, increments every counter, and then forwards the datagram
/// untouched reports a perfectly respectable drop count while delivering
/// 100% of the traffic. Placing this socket *underneath* the impairment
/// shim gives the other half — the number of datagrams that survived —
/// and the two together satisfy a conservation identity that neither can
/// fake alone.
///
/// Everything else is delegated verbatim, including the three capability
/// methods. Inheriting their trait defaults instead would be silent and
/// wrong: `may_fragment` defaults to `true`, and quinn reads it as
/// `let allow_mtud = !socket.may_fragment()`, so a decorator that forgets
/// it turns path-MTU discovery off for every endpoint built over it.
#[derive(Debug)]
pub struct CountingUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    sends: AtomicU64,
}

impl CountingUdpSocket {
    /// Wrap `inner`, counting from zero.
    pub fn wrap(inner: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        Arc::new(Self { inner, sends: AtomicU64::new(0) })
    }

    /// How many datagrams have been handed to the socket below.
    ///
    /// Datagrams, not transmits: a transmit that names a `segment_size`
    /// carries several, and counting it as one would understate exactly
    /// the traffic a GSO-capable platform sends.
    pub fn sends(&self) -> u64 {
        self.sends.load(Ordering::Relaxed)
    }
}

/// How many datagrams one transmit carries.
fn datagrams_in(transmit: &Transmit) -> u64 {
    match transmit.segment_size {
        Some(n) if n > 0 => transmit.contents.len().div_ceil(n) as u64,
        _ => 1,
    }
}

impl AsyncUdpSocket for CountingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    /// Counts only what the socket below accepted.
    ///
    /// A `WouldBlock` is not a send: quinn — or the impairment shim above
    /// — will offer the same datagram again, and counting the refusal
    /// would credit one datagram twice.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)?;
        self.sends.fetch_add(datagrams_in(transmit), Ordering::Relaxed);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// A bound UDP socket stack ready to hand to one of the proxy's two
/// socket arguments: `Listener::bind_with_socket` or
/// `ProxySessionConfig::upstream_socket`.
///
/// Three layers, top to bottom: the impairment shim quinn talks to, the
/// datagram counter, the real socket.
pub struct ImpairedSeam {
    /// The socket to hand to the proxy.
    pub socket: Arc<ImpairedUdpSocket>,
    /// Arms profiles and reads the shim's decision counters and log.
    pub handle: ImpairHandle,
    /// The datagrams that survived the shim, counted below it.
    pub wire: Arc<CountingUdpSocket>,
    /// The address the stack is bound to.
    pub addr: SocketAddr,
}

/// Bind an [`ImpairedSeam`] on an ephemeral loopback port, armed with
/// `profile` and recording every decision.
///
/// Must be called from inside a tokio runtime: the real socket is wrapped
/// by quinn's own runtime adapter, which is how it gets its readiness
/// notifications.
pub fn impaired_seam(profile: ImpairProfile) -> ImpairedSeam {
    init_crypto();

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("a literal address");
    let runtime = quinn::default_runtime().expect("a tokio runtime");
    let real = std::net::UdpSocket::bind(bind).expect("bind udp socket");
    let real = runtime.wrap_udp_socket(real).expect("wrap udp socket");

    let wire = CountingUdpSocket::wrap(real);
    let (socket, handle) = ImpairedUdpSocket::wrap(Arc::clone(&wire) as Arc<dyn AsyncUdpSocket>);

    // Recording is switched on before the profile is armed, so the log
    // covers the handshake as well as everything after it.
    handle.record_decisions(true);
    handle.arm(profile).expect("the profile is valid");

    let addr = socket.local_addr().expect("local_addr");
    ImpairedSeam { socket, handle, wire, addr }
}

/// A [`Listener`] whose whole client-facing leg runs over an
/// [`ImpairedSeam`].
pub struct ImpairedListener {
    /// The listener. Held behind an `Arc` because `accept` is usually
    /// spawned while the test keeps its own handle; dropping it tears the
    /// endpoint down.
    pub listener: Arc<Listener>,
    /// The address clients connect to — the seam's address, not
    /// [`ListenerConfig::bind_addr`].
    pub addr: SocketAddr,
    /// Arms profiles and reads the shim's decision counters and log.
    pub handle: ImpairHandle,
    /// The datagrams that survived the shim, counted below it.
    pub wire: Arc<CountingUdpSocket>,
}

/// Stand a listener up over an impaired socket armed with `profile`.
///
/// The certificate is a fresh self-signed `localhost` pair, and the
/// listener advertises every ALPN it normally does, so a client reaches
/// it exactly as it reaches a listener built by `Listener::bind`.
pub fn listener_over_impaired_socket(profile: ImpairProfile) -> ImpairedListener {
    let seam = impaired_seam(profile);
    let (cert_chain, key_der) = self_signed_localhost();

    let config = ListenerConfig {
        // Ignored by `bind_with_socket` — the supplied socket is already
        // bound and its address is what `local_addr()` reports. Kept
        // realistic so a regression that started honouring this field
        // would produce a listener on the wrong port rather than an
        // error.
        bind_addr: "127.0.0.1:0".parse().expect("a literal address"),
        cert_chain,
        key_der,
        transport_config: None,
        transport_profile: None,
        installer: None,
        // No capture on the client leg. A fixture that wants one builds its
        // own `ListenerConfig`: a spec owns a single-use writer, so there is
        // no version of it a shared harness could hand out.
        #[cfg(feature = "qlog")]
        qlog: None,
    };

    let listener = Arc::new(
        Listener::bind_with_socket(config, seam.socket).expect("bind the listener over the seam"),
    );
    let addr = listener.local_addr().expect("local_addr");

    ImpairedListener { listener, addr, handle: seam.handle, wire: seam.wire }
}

// ── the proxy under test ───────────────────────────────────────────────

/// A session config pointed at `upstream_addr`, parsing as `draft`.
///
/// `egress` is left at [`Default::default`] rather than spelled out, so a
/// later knob added to `EgressConfig` does not have to be threaded through
/// every test file.
///
/// `shape` is `None`, which is the posture every test in this crate but
/// `actions_shaping.rs` wants: no scheduler, no extra queueing, no armed
/// deadline. `interest_none.rs` depends on it being spelled out here — a
/// session that shaped by default would arm `objects_enabled`, run the
/// framer, and redden its whole-struct `Counters::default()` compare. A
/// test that wants shaping assigns the field after calling this.
pub fn session_config(draft: DraftVersion, upstream_addr: SocketAddr) -> ProxySessionConfig {
    ProxySessionConfig {
        draft,
        upstream_transport: UpstreamTransportType::Quic,
        upstream_addr: upstream_addr.to_string(),
        skip_upstream_cert_verify: true,
        upstream_ca_certs: Vec::new(),
        upstream_connect_timeout_secs: 5,
        upstream_transport_config: None,
        // The relay leg goes over a socket this session binds itself. A
        // test that wants to see or impair those datagrams assigns the
        // field after calling this.
        upstream_socket: None,
        egress: Default::default(),
        shape: None,
        upstream_transport_profile: None,
        upstream_installer: None,
        // No capture on the relay leg, for the same reason the listener
        // fixture above has none: a spec is a single-use writer, so a test
        // that wants one assigns the field after calling this — which is
        // what `qlog_artifact.rs` does.
        #[cfg(feature = "qlog")]
        upstream_qlog: None,
    }
}

/// A running proxy session, plus everything needed to talk to it, read its
/// counters and shut it down.
///
/// The [`ProxySession`] is built *before* the accept task is spawned and
/// held behind an `Arc`, which is what makes [`Self::counters`] readable
/// from the test thread while the session is still running. A session
/// constructed inside the task would be unreachable, and the only way to
/// prove `Interest::NONE` touched no slow path is to read its counters.
pub struct SpawnedProxy {
    /// The proxy's front-end address; the client connects here.
    pub addr: SocketAddr,
    /// Cancels the session.
    pub cancel: CancellationToken,
    /// The accept-then-run task.
    pub task: JoinHandle<()>,
    /// The session itself, live.
    pub session: Arc<ProxySession>,
}

impl SpawnedProxy {
    /// This session's slow-path counter snapshot.
    pub fn counters(&self) -> Counters {
        self.session.counters()
    }

    /// This session's shaping statistics.
    ///
    /// Sampled from the test thread **while the session runs**, which is
    /// the whole reason `session` is an `Arc` held out here rather than
    /// constructed inside the accept task. A shaping assertion is almost
    /// always about a window — what a class had delivered *by* some
    /// instant — so waiting for teardown would answer a different question
    /// than the one being asked.
    ///
    /// `ShapeStats::default()` on any session whose config left
    /// `shape` at `None`, which is every fixture but `actions_shaping.rs`'s.
    pub fn shape_stats(&self) -> ShapeStats {
        self.session.shape_stats()
    }

    /// Cancel the session and wait briefly for its task to finish.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.task).await;
    }
}

/// Spawn a draft-14 / `moq-00` proxy session in front of `upstream_addr`.
///
/// The shape lifted verbatim from `proxy_reset.rs`; use
/// [`spawn_proxy_with`] when the draft, the ALPN or the egress knobs
/// matter.
pub fn spawn_proxy(
    upstream_addr: SocketAddr,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
) -> SpawnedProxy {
    spawn_proxy_with(
        session_config(DraftVersion::Draft14, upstream_addr),
        b"moq-00",
        observer,
        hook,
    )
}

/// Spawn a proxy session with an explicit config and client ALPN.
///
/// `client_alpn` is what the session is *told* the client negotiated, and
/// it is load-bearing: `DraftVersion::from_alpn` derives `draft_is_fixed`
/// from it, and a session whose ALPN does not resolve builds no control
/// parser at all. Pass the ALPN the front-end endpoint actually
/// advertises.
pub fn spawn_proxy_with(
    config: ProxySessionConfig,
    client_alpn: &[u8],
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
) -> SpawnedProxy {
    let (front_ep, addr) = spawn_quic_server(&[client_alpn]);
    let cancel = CancellationToken::new();

    let session = Arc::new(ProxySession::new(
        SessionId(1),
        config,
        client_alpn.to_vec(),
        observer,
        hook,
        cancel.clone(),
    ));

    let run_session = Arc::clone(&session);
    let task = tokio::spawn(async move {
        let incoming = front_ep.accept().await.expect("proxy accept");
        let client_conn = incoming.await.expect("proxy tls");
        let _ = run_session.run(client_conn).await;
    });

    SpawnedProxy { addr, cancel, task, session }
}

// ── how a stream ended ─────────────────────────────────────────────────

/// How a forwarded stream ended, as the far peer saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// Clean FIN.
    Fin,
    /// `RESET_STREAM` with this application error code.
    Reset(u64),
}

impl Ending {
    /// The reset code, or `None` for a FIN.
    pub fn reset_code(&self) -> Option<u64> {
        match self {
            Ending::Fin => None,
            Ending::Reset(code) => Some(*code),
        }
    }
}

/// Read a uni stream to its end.
///
/// Returns the ending *and* the byte count delivered before it — a reset
/// that arrives having forwarded nothing is not the same fidelity claim
/// as "data, then reset", and quinn's `reset()` drops locally buffered
/// data, so the difference is reachable in practice.
pub async fn drain(recv: &mut quinn::RecvStream) -> (usize, Ending) {
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => total += n,
            Ok(None) => return (total, Ending::Fin),
            Err(quinn::ReadError::Reset(code)) => return (total, Ending::Reset(code.into_inner())),
            Err(e) => panic!("unexpected read error: {e:?}"),
        }
    }
}

// ── timing-aware capture ───────────────────────────────────────────────

#[derive(Default)]
struct TimedState {
    chunks: Vec<(Instant, Bytes)>,
    ending: Option<Ending>,
}

/// A live reader that timestamps every `read` return.
///
/// The timestamp is taken **when `read` returns**, not at end of stream:
/// a `Delay` that holds one object back for 40 ms is invisible in the
/// final byte vector and obvious in the chunk timeline. Spawned, so the
/// test thread can assert on what has arrived *so far* — which is what
/// [`assert_no_bytes_for`] needs.
pub struct TimedReceiver {
    state: Arc<Mutex<TimedState>>,
    task: JoinHandle<()>,
    started: Instant,
}

impl TimedReceiver {
    /// Start reading `recv` in the background.
    pub fn spawn(mut recv: quinn::RecvStream) -> Self {
        let state = Arc::new(Mutex::new(TimedState::default()));
        let sink = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        let at = Instant::now();
                        let bytes = Bytes::copy_from_slice(&buf[..n]);
                        sink.lock().expect("timed state").chunks.push((at, bytes));
                    }
                    Ok(None) => {
                        sink.lock().expect("timed state").ending = Some(Ending::Fin);
                        return;
                    }
                    Err(quinn::ReadError::Reset(code)) => {
                        sink.lock().expect("timed state").ending =
                            Some(Ending::Reset(code.into_inner()));
                        return;
                    }
                    Err(e) => panic!("unexpected read error: {e:?}"),
                }
            }
        });
        Self { state, task, started: Instant::now() }
    }

    /// When this receiver started reading. The zero point for a timeline.
    pub fn started(&self) -> Instant {
        self.started
    }

    /// Every chunk read so far, with the instant its `read` returned.
    pub fn chunks(&self) -> Vec<(Instant, Bytes)> {
        self.state.lock().expect("timed state").chunks.clone()
    }

    /// Every byte read so far, concatenated.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (_, chunk) in self.state.lock().expect("timed state").chunks.iter() {
            out.extend_from_slice(chunk);
        }
        out
    }

    /// How many bytes have arrived so far.
    pub fn len(&self) -> usize {
        self.state.lock().expect("timed state").chunks.iter().map(|(_, c)| c.len()).sum()
    }

    /// Whether nothing has arrived yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How the stream ended, or `None` while it is still open.
    pub fn ending(&self) -> Option<Ending> {
        self.state.lock().expect("timed state").ending.clone()
    }

    /// Wait until at least `want` bytes have arrived, or `TIMEOUT`
    /// elapses. Returns whatever arrived either way, so the caller's
    /// `assert_eq!` reports the shortfall rather than a bare timeout.
    pub async fn wait_for_bytes(&self, want: usize) -> Vec<u8> {
        let poll = async {
            loop {
                if self.len() >= want {
                    return self.bytes();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        match tokio::time::timeout(TIMEOUT, poll).await {
            Ok(bytes) => bytes,
            Err(_) => self.bytes(),
        }
    }

    /// The Track Alias in this stream's subgroup header, or `None` while
    /// too few bytes have arrived to decode one.
    ///
    /// This is the stream's *identity* on the wire, and the only thing
    /// that distinguishes two concurrent destination streams from each
    /// other — [`FakeRelay::timed_uni_by_alias`] is built on it.
    ///
    /// `None`, never a panic, for every "not yet": a header that has not
    /// arrived whole, or bytes that do not decode as a subgroup header on
    /// this draft. The framer behind it is a *subgroup* framer, which is
    /// the only stream kind that carries a Track Alias at all — a fetch
    /// stream's header carries a request ID instead, and
    /// `ObjectMeta::track_alias` is `None` on every one of them, so fetch
    /// streams are not demuxable this way.
    ///
    /// A caller that needs the alias waits for it with
    /// [`Self::wait_for_track_alias`], whose timeout reports the wait
    /// rather than leaving a decode failure to look like a hang here.
    pub fn track_alias(&self, draft: DraftVersion) -> Option<u64> {
        let mut framer =
            ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
        for (_, chunk) in self.chunks() {
            framer.feed(&chunk);
            loop {
                match framer.poll() {
                    FramerOut::Header { header: DataStreamHeaderKind::Subgroup(h), .. } => {
                        return Some(h.track_alias());
                    }
                    FramerOut::NeedMore => break,
                    FramerOut::Header { .. } | FramerOut::Error(_) => return None,
                    _ => {}
                }
            }
        }
        None
    }

    /// Wait until this stream's subgroup header has arrived, and report
    /// its Track Alias.
    ///
    /// Returns `None` on `TIMEOUT` rather than panicking, so the caller
    /// names the stream it was waiting for in the failure message.
    pub async fn wait_for_track_alias(&self, draft: DraftVersion) -> Option<u64> {
        let poll = async {
            loop {
                if let Some(alias) = self.track_alias(draft) {
                    return alias;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(TIMEOUT, poll).await.ok()
    }

    /// Wait for the stream to end, and report how it did.
    pub async fn wait_for_ending(&self) -> Ending {
        let poll = async {
            loop {
                if let Some(end) = self.ending() {
                    return end;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(TIMEOUT, poll).await.expect("stream terminated")
    }

    /// Re-frame what arrived into objects, keeping the arrival instant of
    /// the read that completed each one.
    ///
    /// Subgroup streams; [`Self::into_objects_of`] takes the stream kind.
    ///
    /// Borrows rather than consumes, despite the `into_` name: the
    /// receiver owns a live reader task, and a test routinely re-frames a
    /// stream that is still open and then keeps asserting on it.
    /// Consuming it here would abort that task. The lint is silenced
    /// deliberately rather than the name changed underneath the several
    /// test files that already call it.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_objects(&self, draft: DraftVersion) -> Vec<(Instant, ObjectMeta, Bytes)> {
        self.into_objects_of(DataStreamType::Subgroup, draft)
    }

    /// Re-frame what arrived into objects of a named stream kind.
    ///
    /// The framer is built with [`ObjectFramer::new`], not
    /// `with_recorder`: this parses a captured stream to assert on it, and
    /// its counters are nobody's business.
    ///
    /// A stream cut mid-object — what `Action::Truncate` leaves behind —
    /// simply yields the objects that completed; the partial tail is
    /// `NeedMore` and is dropped. A stream that fails to *decode* panics,
    /// because at that point the assertion the caller is about to make on
    /// the returned objects would be an assertion about nothing.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_objects_of(
        &self,
        kind: DataStreamType,
        draft: DraftVersion,
    ) -> Vec<(Instant, ObjectMeta, Bytes)> {
        let mut framer = ObjectFramer::new(kind, draft, FramerConfig::default());
        let mut out = Vec::new();
        for (at, chunk) in self.chunks() {
            framer.feed(&chunk);
            drain_framer(&mut framer, at, &mut out);
        }
        out
    }
}

impl Drop for TimedReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Pull every currently available object out of `framer`, stamping each
/// with `at` — the instant of the read that made it available.
fn drain_framer(
    framer: &mut ObjectFramer,
    at: Instant,
    out: &mut Vec<(Instant, ObjectMeta, Bytes)>,
) {
    loop {
        match framer.poll() {
            FramerOut::NeedMore => return,
            FramerOut::Object { meta, raw } => out.push((at, meta, raw)),
            FramerOut::Header { .. } | FramerOut::Passthrough(_) => {}
            FramerOut::Bypassed { .. } => {}
            FramerOut::Error(e) => panic!("captured stream did not re-frame: {e}"),
            other => panic!("unhandled FramerOut variant: {other:?}"),
        }
    }
}

/// Read `recv` to its end and report the objects on it, with the instant
/// each arrived.
pub async fn collect_objects(
    recv: quinn::RecvStream,
    draft: DraftVersion,
) -> Vec<(Instant, ObjectMeta, Bytes)> {
    let rx = TimedReceiver::spawn(recv);
    let _ = rx.wait_for_ending().await;
    rx.into_objects(draft)
}

/// Assert that no further byte arrives on `rx` for `window`.
///
/// The claim a `Delay` or a `Hold` makes is negative — *nothing* should be
/// on the wire yet — and a negative claim needs a window, not a poll.
pub async fn assert_no_bytes_for(rx: &TimedReceiver, window: Duration) {
    let before = rx.len();
    tokio::time::sleep(window).await;
    let after = rx.len();
    assert_eq!(
        after,
        before,
        "{} byte(s) arrived during a {window:?} window in which nothing should have",
        after - before
    );
}

/// Assert that `conn` accepts no unidirectional stream for `window`.
///
/// The proof that a stream was rejected at `Site::StreamOpen`: the peer
/// stream is never opened at all, so there is nothing to read and nothing
/// to reset.
pub async fn assert_no_uni_stream_for(conn: &Connection, window: Duration) {
    match tokio::time::timeout(window, conn.accept_uni()).await {
        // Timed out: nothing was opened, which is the claim.
        Err(_) => {}
        Ok(Ok(_)) => panic!("a unidirectional stream was opened within {window:?}"),
        Ok(Err(e)) => {
            panic!("the connection ended while waiting {window:?} for no stream to open: {e}")
        }
    }
}

// ── the far end, with teardown in both directions ──────────────────────

/// A stand-in relay that accepts one connection and can *initiate*
/// teardown as well as observe it.
///
/// Both directions matter: a proxy that mirrors a `RESET_STREAM` it
/// receives may still fail to mirror a `STOP_SENDING` it receives, and a
/// harness that can only make the client tear down cannot tell the two
/// apart. Every method resolves the accepted connection lazily through one
/// [`tokio::sync::OnceCell`], so the connection is accepted exactly once
/// however many helpers a test calls.
pub struct FakeRelay {
    /// The address to point a proxy's `upstream_addr` at.
    pub addr: SocketAddr,
    endpoint: Endpoint,
    conn: tokio::sync::OnceCell<Connection>,
}

impl FakeRelay {
    /// Bind a relay on an ephemeral port advertising `alpn`.
    pub fn bind(alpn: &[u8]) -> Self {
        let (endpoint, addr) = spawn_quic_server(&[alpn]);
        Self { addr, endpoint, conn: tokio::sync::OnceCell::new() }
    }

    /// [`Self::bind`], with the relay's per-stream receive window pinned —
    /// so a test can make the proxy's write towards this relay block. See
    /// [`windowed_transport`].
    pub fn bind_windowed(alpn: &[u8], stream_receive_window: u32) -> Self {
        let (endpoint, addr) = spawn_quic_server_windowed(&[alpn], Some(stream_receive_window));
        Self { addr, endpoint, conn: tokio::sync::OnceCell::new() }
    }

    /// The accepted connection, awaiting the handshake on first call.
    pub async fn connection(&self) -> Connection {
        self.conn
            .get_or_init(|| async {
                let incoming = self.endpoint.accept().await.expect("relay accept");
                incoming.await.expect("relay tls")
            })
            .await
            .clone()
    }

    /// Accept the next unidirectional stream the proxy forwards.
    pub async fn accept_uni(&self) -> quinn::RecvStream {
        self.connection().await.accept_uni().await.expect("relay accept_uni")
    }

    /// Accept the next unidirectional stream and start timestamping it.
    pub async fn timed_uni(&self) -> TimedReceiver {
        TimedReceiver::spawn(self.accept_uni().await)
    }

    /// Accept the next `n` unidirectional streams and start timestamping
    /// each one, in accept order.
    ///
    /// Each stream starts being read the moment it is accepted, so the
    /// `n` streams are captured *concurrently*: this returns as soon as
    /// the `n`th stream exists, not when any of them ends. A loop that
    /// read each stream to its end before accepting the next would
    /// serialize them and could not observe an interleaving at all.
    ///
    /// Accept order is the order the proxy opened the streams in, which is
    /// not an identity — use [`Self::timed_uni_by_alias`] when a test has
    /// to say *which* stream it is holding.
    pub async fn timed_uni_n(&self, n: usize) -> Vec<TimedReceiver> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.timed_uni().await);
        }
        out
    }

    /// Accept one unidirectional stream per entry of `aliases` and hand
    /// them back **in `aliases` order**, each matched to its subgroup
    /// header's Track Alias.
    ///
    /// [`Self::accept_uni`] and [`Self::timed_uni`] hand back the next
    /// stream with no identity, which is enough for a test that drives one
    /// destination stream and nothing more. A test that drives two at once
    /// — video and audio, one shaped and one not — has to be able to say
    /// *this receiver is the video stream* before it asserts anything
    /// about it, and accept order cannot say that: it is the order the
    /// proxy opened its destination streams in, which is a property of the
    /// proxy under test rather than of the fixture.
    ///
    /// So the demux keys on the one thing the fixture itself chose: the
    /// Track Alias in each stream's header. Deterministic and immediate —
    /// no sleep, and no assumption that the first stream to arrive is the
    /// first one the test wrote.
    ///
    /// Panics if a requested alias never arrives, naming what did arrive.
    /// Repeating an alias is likewise a panic on the second copy: each
    /// accepted stream is handed out at most once, so a fixture that
    /// writes one alias twice cannot silently be asserted on twice.
    pub async fn timed_uni_by_alias(
        &self,
        aliases: &[u64],
        draft: DraftVersion,
    ) -> Vec<TimedReceiver> {
        let mut pending = self.timed_uni_n(aliases.len()).await;

        let mut seen = Vec::with_capacity(pending.len());
        for rx in &pending {
            seen.push(rx.wait_for_track_alias(draft).await);
        }

        let mut out = Vec::with_capacity(aliases.len());
        for want in aliases {
            let at = seen.iter().position(|got| *got == Some(*want)).unwrap_or_else(|| {
                panic!(
                    "no forwarded stream carried track alias {want}; the {} unclaimed stream(s) \
                     carried {seen:?} (`None` = no subgroup header decoded within {TIMEOUT:?})",
                    seen.len()
                )
            });
            seen.remove(at);
            out.push(pending.remove(at));
        }
        out
    }

    /// Accept the control (bidirectional) stream.
    pub async fn accept_bi(&self) -> (quinn::SendStream, quinn::RecvStream) {
        self.connection().await.accept_bi().await.expect("relay accept_bi")
    }

    /// Open a unidirectional stream *towards* the proxy.
    pub async fn open_uni(&self) -> quinn::SendStream {
        self.connection().await.open_uni().await.expect("relay open_uni")
    }

    /// Open a bidirectional stream *towards* the proxy.
    ///
    /// The direction a relay opens one in is not symmetric with
    /// [`Self::accept_bi`] on every draft. On 07 through 15 a relay never
    /// opens a bidirectional stream at all; from draft-16 it does, because
    /// Draft-16 Section 6.1 lets either endpoint be the subscriber that "sends
    /// SUBSCRIBE_NAMESPACE on a new bidirectional stream", and from draft-17
    /// requests generally travel that way.
    pub async fn open_bi(&self) -> (quinn::SendStream, quinn::RecvStream) {
        self.connection().await.open_bi().await.expect("relay open_bi")
    }

    /// Relay-initiated teardown, sending direction: write `data`, wait
    /// `settle` so the bytes are forwarded first, then `RESET_STREAM`.
    ///
    /// The wait is what makes the resulting assertion "data, *then* a
    /// reset" rather than "a reset that raced the stream open", and it is a
    /// signal rather than a settle because the only thing that knows when
    /// the data has arrived is whoever is reading it. A dropped sender
    /// fires it too, so a caller that gives up cannot leave this parked.
    pub async fn push_then_reset(
        &self,
        data: &[u8],
        held: tokio::sync::oneshot::Receiver<()>,
        code: u64,
    ) {
        let mut send = self.open_uni().await;
        send.write_all(data).await.expect("relay write");
        let _ = held.await;
        send.reset(quinn::VarInt::from_u64(code).expect("reset code")).expect("relay reset");
    }

    /// Relay-initiated teardown, receiving direction: accept the next
    /// forwarded stream, read at least one chunk from it, then
    /// `STOP_SENDING(code)`.
    ///
    /// Returns the stream, kept alive so the stop is not immediately
    /// followed by the default-code stop that dropping a `RecvStream`
    /// sends.
    pub async fn accept_then_stop(&self, code: u64) -> quinn::RecvStream {
        let mut recv = self.accept_uni().await;
        let mut buf = [0u8; 4096];
        let _ = tokio::time::timeout(TIMEOUT, recv.read(&mut buf)).await.expect("relay first read");
        recv.stop(quinn::VarInt::from_u64(code).expect("stop code")).expect("relay stop");
        recv
    }

    /// Close the connection from the relay's side.
    pub fn close(&self, code: u32, reason: &[u8]) {
        if let Some(conn) = self.conn.get() {
            conn.close(code.into(), reason);
        }
    }
}

// ── event recording ────────────────────────────────────────────────────

/// Everything one [`RecordingObserver`] saw, destructured.
#[derive(Debug, Default, Clone)]
pub struct Recorded {
    /// Every event, in order, for diagnostics.
    pub events: Vec<ProxyEvent>,
    /// `ProxyEvent::ActionApplied`, destructured.
    pub applied: Vec<(Site, ActionKind, Effect)>,
    /// `ProxyEvent::ActionRefused`, destructured.
    pub refused: Vec<(Site, ActionKind, Refusal)>,
    /// `ProxyEvent::ActionFailed`, destructured.
    pub failed: Vec<(Site, ActionKind, String)>,
    /// `ProxyEvent::Impairment`, destructured.
    pub impairments: Vec<ImpairmentKind>,
    /// `ProxyEvent::Object`.
    pub objects: Vec<ObjectMeta>,
    /// `ProxyEvent::StreamReset`, as `(side, code)`.
    pub resets: Vec<(ProxySide, u64)>,
    /// `ProxyEvent::StreamClosed`.
    pub closes: Vec<ProxySide>,
    /// `ProxyEvent::ParseError`.
    pub parse_errors: Vec<String>,
}

/// Records everything the proxy reports, in the shape assertions want.
///
/// `wants_events()` is left at its `true` default: an observer that
/// answers `false` puts the session on the byte pump, and a test attached
/// to one would be measuring nothing. Use `NoOpProxyObserver` when that
/// *is* the point.
#[derive(Default)]
pub struct RecordingObserver {
    inner: Mutex<Recorded>,
}

impl RecordingObserver {
    /// A fresh recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of everything seen so far.
    pub fn recorded(&self) -> Recorded {
        self.inner.lock().expect("recorded").clone()
    }

    /// Every `ActionApplied`, as `(site, action, effect)`.
    pub fn applied(&self) -> Vec<(Site, ActionKind, Effect)> {
        self.inner.lock().expect("recorded").applied.clone()
    }

    /// Every `ActionRefused`, as `(site, action, refusal)`.
    pub fn refused(&self) -> Vec<(Site, ActionKind, Refusal)> {
        self.inner.lock().expect("recorded").refused.clone()
    }

    /// Every `ActionFailed`, as `(site, action, error)`.
    pub fn failed(&self) -> Vec<(Site, ActionKind, String)> {
        self.inner.lock().expect("recorded").failed.clone()
    }

    /// Every `Impairment`'s kind.
    pub fn impairments(&self) -> Vec<ImpairmentKind> {
        self.inner.lock().expect("recorded").impairments.clone()
    }

    /// Every framed object's meta.
    pub fn objects(&self) -> Vec<ObjectMeta> {
        self.inner.lock().expect("recorded").objects.clone()
    }

    /// Every observed stream teardown, as `(side, code)`.
    pub fn resets(&self) -> Vec<(ProxySide, u64)> {
        self.inner.lock().expect("recorded").resets.clone()
    }

    /// Every clean stream close.
    pub fn closes(&self) -> Vec<ProxySide> {
        self.inner.lock().expect("recorded").closes.clone()
    }

    /// Every inline parse error.
    pub fn parse_errors(&self) -> Vec<String> {
        self.inner.lock().expect("recorded").parse_errors.clone()
    }

    /// Every event, raw, for a failure message.
    pub fn events(&self) -> Vec<ProxyEvent> {
        self.inner.lock().expect("recorded").events.clone()
    }
}

impl ProxyObserver for RecordingObserver {
    fn on_event(&self, event: &ProxyEvent) {
        let mut rec = self.inner.lock().expect("recorded");
        rec.events.push(event.clone());
        match event {
            ProxyEvent::ActionApplied { site, action, effect, .. } => {
                rec.applied.push((*site, *action, effect.clone()));
            }
            ProxyEvent::ActionRefused { site, action, refusal, .. } => {
                rec.refused.push((*site, *action, refusal.clone()));
            }
            ProxyEvent::ActionFailed { site, action, error, .. } => {
                rec.failed.push((*site, *action, error.clone()));
            }
            ProxyEvent::Impairment { kind, .. } => rec.impairments.push(kind.clone()),
            ProxyEvent::Object { meta, .. } => rec.objects.push(*meta),
            ProxyEvent::StreamReset { side, code, .. } => rec.resets.push((*side, *code)),
            ProxyEvent::StreamClosed { side, .. } => rec.closes.push(*side),
            ProxyEvent::ParseError { error, .. } => rec.parse_errors.push(error.clone()),
            _ => {}
        }
    }
}

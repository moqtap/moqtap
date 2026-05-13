//! Per-connection proxy session — forwards streams between client and relay.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use moqtap_client::transport::quic::QuicTransport;
use moqtap_client::transport::{RecvStream, SendStream, Transport};
use moqtap_codec::dispatch::AnyDatagramHeader;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use crate::error::ProxyError;
use crate::event::{ProxyEvent, ProxySide, SessionId};
use crate::hook::ProxyHook;
use crate::observer::ProxyObserver;
use crate::parser::control::{ControlStreamParser, ParseResult};
use crate::parser::data::{DataStreamParser, DataStreamType};

/// The transport type for upstream relay connections.
#[derive(Debug, Clone)]
pub enum UpstreamTransportType {
    /// Raw QUIC — `upstream_addr` is `host:port`.
    Quic,
    /// WebTransport — `url` is the full WebTransport URL.
    WebTransport {
        /// The WebTransport endpoint URL (e.g., `https://host:port/path`).
        url: String,
    },
}

/// Configuration for a proxy session's upstream connection.
pub struct ProxySessionConfig {
    /// The MoQT draft version to use for parsing.
    pub draft: DraftVersion,
    /// The transport type to use for the upstream connection.
    pub upstream_transport: UpstreamTransportType,
    /// Upstream relay address (e.g., `"192.168.1.10:4443"` for QUIC).
    pub upstream_addr: String,
    /// Whether to skip TLS verification for the upstream connection.
    pub skip_upstream_cert_verify: bool,
    /// Custom CA certificates for the upstream connection (DER-encoded).
    pub upstream_ca_certs: Vec<Vec<u8>>,
    /// Timeout in seconds for the upstream connection attempt. 0 means no timeout.
    pub upstream_connect_timeout_secs: u64,
}

impl ProxySessionConfig {
    /// Returns the ALPN protocol identifiers for the upstream connection.
    ///
    /// For QUIC upstreams, mirrors the negotiated client ALPN so we connect
    /// to the relay with the same protocol the client is speaking. Falls
    /// back to `self.draft.quic_alpn()` if the client ALPN is empty
    /// (e.g., the listener didn't capture it).
    pub fn upstream_alpn(&self, client_alpn: &[u8]) -> Vec<Vec<u8>> {
        match &self.upstream_transport {
            UpstreamTransportType::Quic => {
                if client_alpn.is_empty() {
                    vec![self.draft.quic_alpn().to_vec()]
                } else {
                    vec![client_alpn.to_vec()]
                }
            }
            UpstreamTransportType::WebTransport { .. } => vec![b"h3".to_vec()],
        }
    }
}

impl Default for ProxySessionConfig {
    fn default() -> Self {
        Self {
            draft: DraftVersion::Draft14,
            upstream_transport: UpstreamTransportType::Quic,
            upstream_addr: String::new(),
            skip_upstream_cert_verify: false,
            upstream_ca_certs: Vec::new(),
            upstream_connect_timeout_secs: 0,
        }
    }
}

/// A proxy session that forwards traffic between a client and an upstream
/// relay. One session is created per accepted client connection.
pub struct ProxySession {
    session_id: SessionId,
    config: ProxySessionConfig,
    /// The ALPN the client negotiated with us (empty for WebTransport or
    /// when unavailable). Drives both upstream ALPN selection and initial
    /// draft detection for drafts 15+.
    client_alpn: Vec<u8>,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
}

impl ProxySession {
    /// Create a new proxy session.
    ///
    /// `client_alpn` should be the ALPN the listener negotiated with the
    /// client. Pass an empty slice if unavailable (e.g., WebTransport).
    pub fn new(
        session_id: SessionId,
        config: ProxySessionConfig,
        client_alpn: Vec<u8>,
        observer: Arc<dyn ProxyObserver>,
        hook: Arc<dyn ProxyHook>,
        cancel: CancellationToken,
    ) -> Self {
        Self { session_id, config, client_alpn, observer, hook, cancel }
    }

    /// Run the proxy session with a raw QUIC client connection.
    pub async fn run(self, client_conn: quinn::Connection) -> Result<(), ProxyError> {
        let client = Transport::Quic(QuicTransport::new(client_conn));
        self.run_with_transport(client).await
    }

    /// Run the proxy session with a WebTransport client connection.
    #[cfg(feature = "webtransport")]
    pub async fn run_webtransport(
        self,
        client_conn: wtransport::Connection,
    ) -> Result<(), ProxyError> {
        use moqtap_client::transport::webtransport::WebTransportTransport;
        let client = Transport::WebTransport(WebTransportTransport::new(client_conn));
        self.run_with_transport(client).await
    }

    /// The initial draft hint for this session. Drafts 15+ resolve
    /// unambiguously from the client ALPN (`moqt-15` / `moqt-16` /
    /// `moqt-17` / `moqt-18`); otherwise we fall back to `config.draft`,
    /// which the control-stream parser may refine once it peeks at
    /// CLIENT_SETUP / SERVER_SETUP for the moq-00 cohort (drafts 07–14).
    fn initial_draft(&self) -> DraftVersion {
        DraftVersion::from_alpn(&self.client_alpn).unwrap_or(self.config.draft)
    }

    /// Whether the initial draft is fixed (ALPN-derived) or should be
    /// refined from CLIENT_SETUP / SERVER_SETUP peek.
    fn draft_is_fixed(&self) -> bool {
        DraftVersion::from_alpn(&self.client_alpn).is_some()
    }

    /// Run the proxy session with an already-wrapped transport.
    ///
    /// Connects to the upstream relay, then forwards all streams and
    /// datagrams bidirectionally between the client and relay. Parses
    /// MoQT frames inline and emits events via the observer.
    async fn run_with_transport(self, client: Transport) -> Result<(), ProxyError> {
        // Connect to upstream relay
        let relay = self.connect_upstream().await?;

        let client = Arc::new(client);
        let relay = Arc::new(relay);

        let mut tasks: JoinSet<Result<(), ProxyError>> = JoinSet::new();

        let initial_draft = self.initial_draft();
        let draft_is_fixed = self.draft_is_fixed();

        let observer_enabled = self.observer.wants_events();
        let control_mutation = self.hook.wants_control_mutation();
        let base_ctx = ForwardCtx {
            session_id: self.session_id,
            draft: initial_draft,
            draft_is_fixed,
            observer: Arc::clone(&self.observer),
            hook: Arc::clone(&self.hook),
            cancel: self.cancel.clone(),
            observer_enabled,
            control_mutation,
        };

        // Control stream: accept bi from client, open bi to relay
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move { forward_control_stream(&client, &relay, &ctx).await });
        }

        // Client → Relay uni streams
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_uni_streams(&client, &relay, ProxySide::ClientToProxy, &ctx).await
            });
        }

        // Relay → Client uni streams
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_uni_streams(&relay, &client, ProxySide::RelayToProxy, &ctx).await
            });
        }

        // Datagram forwarding: client → relay
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_datagrams(&client, &relay, ProxySide::ClientToProxy, &ctx).await
            });
        }

        // Datagram forwarding: relay → client
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_datagrams(&relay, &client, ProxySide::RelayToProxy, &ctx).await
            });
        }

        // Wait for first task to finish (signals session is done)
        let first_result = tasks.join_next().await;

        // Cancel remaining tasks
        self.cancel.cancel();
        tasks.shutdown().await;

        // Determine reason from first result
        let reason = match &first_result {
            Some(Ok(Ok(()))) => "completed".to_string(),
            Some(Ok(Err(e))) => format!("{e}"),
            Some(Err(e)) => format!("task panic: {e}"),
            None => "no tasks".to_string(),
        };
        if self.observer.wants_events() {
            self.observer
                .on_event(&ProxyEvent::SessionEnded { session_id: self.session_id, reason });
        }

        // Close both sides
        client.close(0, b"proxy session ended");
        relay.close(0, b"proxy session ended");

        match first_result {
            Some(Ok(Ok(()))) | None => Ok(()),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(ProxyError::SessionClosed(format!("task panic: {e}"))),
        }
    }

    /// Connect to the upstream relay (with optional timeout).
    async fn connect_upstream(&self) -> Result<Transport, ProxyError> {
        let timeout_secs = self.config.upstream_connect_timeout_secs;
        if timeout_secs > 0 {
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                self.connect_upstream_inner(),
            )
            .await
            .map_err(|_| {
                ProxyError::UpstreamConnect(format!("connection timed out after {timeout_secs}s"))
            })?
        } else {
            self.connect_upstream_inner().await
        }
    }

    async fn connect_upstream_inner(&self) -> Result<Transport, ProxyError> {
        match &self.config.upstream_transport {
            UpstreamTransportType::Quic => self.connect_upstream_quic().await,
            #[cfg(feature = "webtransport")]
            UpstreamTransportType::WebTransport { url } => {
                let url = url.clone();
                self.connect_upstream_webtransport(&url).await
            }
            #[cfg(not(feature = "webtransport"))]
            UpstreamTransportType::WebTransport { .. } => {
                Err(ProxyError::UpstreamConnect("webtransport feature not enabled".to_string()))
            }
        }
    }

    /// Connect to the upstream relay via QUIC.
    async fn connect_upstream_quic(&self) -> Result<Transport, ProxyError> {
        let server_addr =
            self.config.upstream_addr.parse().map_err(|e: std::net::AddrParseError| {
                ProxyError::UpstreamConnect(e.to_string())
            })?;

        let mut tls_config = self.build_upstream_tls_config()?;
        tls_config.alpn_protocols = self.config.upstream_alpn(&self.client_alpn);

        let quic_config: quinn::crypto::rustls::QuicClientConfig =
            tls_config.try_into().map_err(|e| ProxyError::TlsConfig(format!("{e}")))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        let server_name =
            self.config.upstream_addr.split(':').next().unwrap_or("localhost").to_string();

        let conn = endpoint
            .connect(server_addr, &server_name)
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?
            .await
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

        Ok(Transport::Quic(QuicTransport::new(conn)))
    }

    /// Connect to the upstream relay via WebTransport.
    #[cfg(feature = "webtransport")]
    async fn connect_upstream_webtransport(&self, url: &str) -> Result<Transport, ProxyError> {
        use moqtap_client::transport::webtransport::WebTransportTransport;

        let wt_config = if self.config.skip_upstream_cert_verify {
            wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build()
        } else {
            wtransport::ClientConfig::builder().with_bind_default().with_native_certs().build()
        };

        let endpoint = wtransport::Endpoint::client(wt_config)
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

        let connection =
            endpoint.connect(url).await.map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

        Ok(Transport::WebTransport(WebTransportTransport::new(connection)))
    }

    /// Build a rustls `ClientConfig` for the upstream connection.
    fn build_upstream_tls_config(&self) -> Result<rustls::ClientConfig, ProxyError> {
        if self.config.skip_upstream_cert_verify {
            Ok(rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerification))
                .with_no_client_auth())
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for der in &self.config.upstream_ca_certs {
                roots
                    .add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|e| ProxyError::TlsConfig(format!("bad CA cert: {e}")))?;
            }
            Ok(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
        }
    }
}

// ── Forwarding helpers ──────────────────────────────────────────

/// Shared context for forwarding helpers, avoiding repeated parameter lists.
#[derive(Clone)]
struct ForwardCtx {
    session_id: SessionId,
    /// The current best draft guess for this session. For control streams
    /// this may be refined after observing CLIENT_SETUP / SERVER_SETUP when
    /// `draft_is_fixed` is false.
    draft: DraftVersion,
    /// Whether `draft` is fixed (from ALPN) and should not be refined by
    /// peeking at SETUP messages.
    draft_is_fixed: bool,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
    /// Cached `observer.wants_events()` — gates event construction and
    /// emission in the hot forwarding loop. When `false`, the proxy can
    /// skip parsing for observation purposes and run as a byte pump.
    observer_enabled: bool,
    /// Cached `hook.wants_control_mutation()` — when `true`, the control
    /// stream forwarder switches to a parse-then-forward mode that honors
    /// the hook's `Some(bytes)` return. Defaults to `false` (pure
    /// pass-through) to avoid per-frame parsing latency.
    control_mutation: bool,
}

impl ForwardCtx {
    /// Emit a proxy event only if the observer wants events.
    ///
    /// Takes a closure so the `ProxyEvent` is not constructed when
    /// observation is disabled — avoiding clones of message payloads in
    /// the hot path.
    fn emit(&self, event: impl FnOnce() -> ProxyEvent) {
        if self.observer_enabled {
            self.observer.on_event(&event());
        }
    }
}

/// Forward the control stream (first bidirectional stream).
async fn forward_control_stream(
    client: &Transport,
    relay: &Transport,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    // Accept bi from client
    let (client_send, client_recv) = client.accept_bi().await?;
    ctx.emit(|| ProxyEvent::BiStreamOpened {
        session_id: ctx.session_id,
        side: ProxySide::ClientToProxy,
    });

    // Open bi to relay
    let (relay_send, relay_recv) = relay.open_bi().await?;
    ctx.emit(|| ProxyEvent::BiStreamOpened {
        session_id: ctx.session_id,
        side: ProxySide::ProxyToRelay,
    });

    // Pipe client→relay and relay→client concurrently
    let ctx1 = ForwardCtx { ..ctx.clone() };
    let ctx2 = ForwardCtx { ..ctx.clone() };

    let client_to_relay = tokio::spawn(async move {
        pipe_control(client_recv, relay_send, ProxySide::ClientToProxy, &ctx1).await
    });

    let relay_to_client = tokio::spawn(async move {
        pipe_control(relay_recv, client_send, ProxySide::RelayToProxy, &ctx2).await
    });

    tokio::select! {
        r = client_to_relay => r.map_err(|e| ProxyError::SessionClosed(e.to_string()))?,
        r = relay_to_client => r.map_err(|e| ProxyError::SessionClosed(e.to_string()))?,
        _ = ctx.cancel.cancelled() => Ok(()),
    }
}

/// Pipe a control stream direction.
///
/// Bytes are forwarded to the peer immediately upon receipt — the parser
/// runs on a cloned copy purely to emit observer events. A stuck or
/// erroring parser can never block forwarding. This matches the
/// pass-through semantics of the data-stream and datagram paths.
///
/// If `ctx.draft_is_fixed` is false (moq-00 cohort, drafts 07–14), the
/// parser start is deferred until enough bytes arrive to peek the first
/// SETUP message and pick a concrete draft. Bytes observed during that
/// detection window are still forwarded immediately.
async fn pipe_control(
    recv: RecvStream,
    send: SendStream,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    if ctx.control_mutation {
        pipe_control_mutating(recv, send, side, ctx).await
    } else {
        pipe_control_passthrough(recv, send, side, ctx).await
    }
}

/// Forward-first control stream pipe.
///
/// Bytes are forwarded to the peer the instant they arrive; the parser
/// runs on a cloned copy purely to drive observer events. No hook can
/// rewrite frames on this path because the bytes are already in flight.
async fn pipe_control_passthrough(
    mut recv: RecvStream,
    mut send: SendStream,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let mut buf = [0u8; 8192];

    let mut parser: Option<ControlStreamParser> =
        if ctx.draft_is_fixed { Some(ControlStreamParser::new(ctx.draft)) } else { None };

    const DETECT_BUF_MAX: usize = 64 * 1024;
    let mut detect_buf = BytesMut::new();

    loop {
        tokio::select! {
            result = recv.read(&mut buf) => {
                match result? {
                    Some(n) => {
                        let data = &buf[..n];

                        // ── Forward immediately — no gating on parse ────
                        send.write_all(data).await?;

                        // ── Observer-only parse (side path) ─────────────
                        // Skip parsing when nobody is observing: the proxy
                        // becomes a pure byte pump on the control stream.
                        if ctx.observer_enabled {
                            if let Some(ref mut p) = parser {
                                emit_parsed_frames(p, data, side, ctx);
                            } else {
                                detect_buf.extend_from_slice(data);
                                if let Some(detected) = detect_draft_from_setup(
                                    &detect_buf,
                                    side,
                                    ctx.draft,
                                ) {
                                    let mut p = ControlStreamParser::new(detected);
                                    let buffered = detect_buf.split().freeze();
                                    emit_parsed_frames(&mut p, &buffered, side, ctx);
                                    parser = Some(p);
                                } else if detect_buf.len() >= DETECT_BUF_MAX {
                                    ctx.emit(|| ProxyEvent::ParseError {
                                        session_id: ctx.session_id,
                                        side,
                                        error: format!(
                                            "control draft detection gave up after {} bytes; \
                                             falling back to {}",
                                            detect_buf.len(),
                                            ctx.draft,
                                        ),
                                    });
                                    parser = Some(ControlStreamParser::new(ctx.draft));
                                    detect_buf = BytesMut::new();
                                }
                            }
                        }
                    }
                    None => {
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Parse-then-forward control stream pipe.
///
/// Bytes are withheld until a complete control message has been parsed,
/// at which point the hook's `on_control_message` is consulted and its
/// `Some(bytes)` return value (if any) is forwarded in place of the
/// original wire frame. This adds a per-frame latency cost — a hook that
/// only observes should leave `wants_control_mutation()` at its default
/// `false` and take the pass-through path instead.
async fn pipe_control_mutating(
    mut recv: RecvStream,
    mut send: SendStream,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let mut buf = [0u8; 8192];

    // Capturing parser — we need the original raw bytes so the hook can
    // choose to pass them through unchanged.
    let mut parser: Option<ControlStreamParser> =
        if ctx.draft_is_fixed { Some(ControlStreamParser::new_capturing(ctx.draft)) } else { None };

    const DETECT_BUF_MAX: usize = 64 * 1024;
    let mut detect_buf = BytesMut::new();

    loop {
        tokio::select! {
            result = recv.read(&mut buf) => {
                match result? {
                    Some(n) => {
                        let data = &buf[..n];

                        match parser.as_mut() {
                            Some(p) => {
                                forward_mutated_frames(p, data, &mut send, side, ctx).await?;
                            }
                            None => {
                                detect_buf.extend_from_slice(data);
                                let new_parser = if let Some(detected) = detect_draft_from_setup(
                                    &detect_buf,
                                    side,
                                    ctx.draft,
                                ) {
                                    Some(ControlStreamParser::new_capturing(detected))
                                } else if detect_buf.len() >= DETECT_BUF_MAX {
                                    ctx.emit(|| ProxyEvent::ParseError {
                                        session_id: ctx.session_id,
                                        side,
                                        error: format!(
                                            "control draft detection gave up after {} bytes; \
                                             falling back to {}",
                                            detect_buf.len(),
                                            ctx.draft,
                                        ),
                                    });
                                    Some(ControlStreamParser::new_capturing(ctx.draft))
                                } else {
                                    // Still detecting; nothing to forward yet.
                                    None
                                };

                                if let Some(mut p) = new_parser {
                                    let buffered = detect_buf.split().freeze();
                                    forward_mutated_frames(
                                        &mut p,
                                        &buffered,
                                        &mut send,
                                        side,
                                        ctx,
                                    )
                                    .await?;
                                    parser = Some(p);
                                }
                            }
                        }
                    }
                    None => {
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Feed bytes into the capturing control parser, then forward each
/// completed frame — giving the hook the chance to rewrite it.
async fn forward_mutated_frames(
    parser: &mut ControlStreamParser,
    data: &[u8],
    send: &mut SendStream,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let result = parser.feed(data);
    if let ParseResult::Messages(frames) = result {
        for frame in frames {
            let raw = frame.raw_bytes.as_deref().expect("capturing parser must populate raw_bytes");
            let replacement =
                ctx.hook.on_control_message(ctx.session_id, side, &frame.message, raw);
            let out: &[u8] = match replacement.as_deref() {
                Some(bytes) => bytes,
                None => raw,
            };
            send.write_all(out).await?;

            if ctx.observer_enabled {
                let event = if frame.message.is_setup() {
                    ProxyEvent::SetupMessage {
                        session_id: ctx.session_id,
                        side,
                        message: frame.message.clone(),
                    }
                } else {
                    ProxyEvent::ControlMessage {
                        session_id: ctx.session_id,
                        side,
                        message: frame.message.clone(),
                    }
                };
                ctx.observer.on_event(&event);
            }
        }
    }
    Ok(())
}

/// Feed bytes to the control parser and emit observer events for any
/// completed frames.
///
/// The hook is deliberately not invoked here — on the pass-through path
/// the bytes have already been forwarded, so a mutating `Some(bytes)`
/// return would be silently discarded. Hooks that need to see control
/// messages without rewriting them should be implemented as a
/// [`ProxyObserver`]; hooks that need to rewrite them should set
/// `wants_control_mutation()` to `true`, which routes traffic through
/// `pipe_control_mutating` instead.
fn emit_parsed_frames(
    parser: &mut ControlStreamParser,
    data: &[u8],
    side: ProxySide,
    ctx: &ForwardCtx,
) {
    if !ctx.observer_enabled {
        return;
    }
    match parser.feed(data) {
        ParseResult::Messages(frames) => {
            for frame in &frames {
                let event = if frame.message.is_setup() {
                    ProxyEvent::SetupMessage {
                        session_id: ctx.session_id,
                        side,
                        message: frame.message.clone(),
                    }
                } else {
                    ProxyEvent::ControlMessage {
                        session_id: ctx.session_id,
                        side,
                        message: frame.message.clone(),
                    }
                };
                ctx.observer.on_event(&event);
            }
        }
        ParseResult::NeedMore => {}
    }
}

/// Forward unidirectional streams from source to destination.
async fn forward_uni_streams(
    source: &Transport,
    dest: &Transport,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    loop {
        tokio::select! {
            result = source.accept_uni() => {
                let recv = result?;
                ctx.emit(|| ProxyEvent::UniStreamOpened {
                    session_id: ctx.session_id,
                    side,
                });

                let send = dest.open_uni().await?;
                let ctx = ctx.clone();

                tokio::spawn(async move {
                    if let Err(e) = pipe_data(
                        recv, send, side, &ctx,
                    )
                    .await
                    {
                        ctx.emit(|| ProxyEvent::ParseError {
                            session_id: ctx.session_id,
                            side,
                            error: format!("uni stream pipe: {e}"),
                        });
                    }
                });
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Determine the data stream type from the first varint on the stream.
///
/// MoQT data streams start with a stream type varint:
/// - 0x04 = Subgroup
/// - 0x05 = Fetch
///
/// Returns `(stream_type, bytes_consumed)` so the caller can account for
/// the type varint when setting up the parser.
fn detect_stream_type(first_byte: u8) -> DataStreamType {
    // The stream type varint is a single byte for values < 64.
    // Subgroup = 0x04, Fetch = 0x05.
    match first_byte {
        0x05 => DataStreamType::Fetch,
        // Default to Subgroup for 0x04 and anything else
        _ => DataStreamType::Subgroup,
    }
}

/// Pipe a unidirectional data stream with inline parsing.
async fn pipe_data(
    mut recv: RecvStream,
    mut send: SendStream,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let mut buf = [0u8; 8192];
    let mut parser: Option<DataStreamParser> = None;

    loop {
        tokio::select! {
            result = recv.read(&mut buf) => {
                match result? {
                    Some(n) => {
                        let data = &buf[..n];

                        // Skip parsing entirely when nobody is observing —
                        // the proxy then runs as a straight byte pump.
                        if ctx.observer_enabled {
                            // On first data, detect stream type from the
                            // leading varint and create the parser. Skip the
                            // stream type varint when feeding to the parser
                            // since SubgroupHeader/FetchHeader::decode()
                            // expects it to be already consumed.
                            let feed_data = if parser.is_none() && !data.is_empty() {
                                let stream_type = detect_stream_type(data[0]);
                                parser = Some(DataStreamParser::new(
                                    stream_type, ctx.draft,
                                ));
                                // The stream type varint is a single byte
                                // for values 0x00..0x3F. Skip it.
                                let skip = varint_len(data[0]);
                                &data[skip.min(data.len())..]
                            } else {
                                data
                            };

                            if let Some(ref mut p) = parser {
                                let results = p.feed(feed_data);
                                for result in &results {
                                    match result {
                                        crate::parser::data::DataParseResult::Header(header) => {
                                            ctx.observer.on_event(
                                                &ProxyEvent::DataStreamHeader {
                                                    session_id: ctx.session_id,
                                                    side,
                                                    header: header.clone(),
                                                },
                                            );
                                        }
                                        crate::parser::data::DataParseResult::Object(header) => {
                                            ctx.observer.on_event(
                                                &ProxyEvent::ObjectHeader {
                                                    session_id: ctx.session_id,
                                                    side,
                                                    header: header.clone(),
                                                },
                                            );
                                        }
                                        crate::parser::data::DataParseResult::Error(e) => {
                                            ctx.observer.on_event(
                                                &ProxyEvent::ParseError {
                                                    session_id: ctx.session_id,
                                                    side,
                                                    error: e.clone(),
                                                },
                                            );
                                        }
                                        crate::parser::data::DataParseResult::NeedMore => {}
                                    }
                                }
                            }
                        }

                        // Always forward the raw bytes (including
                        // stream type varint)
                        send.write_all(data).await?;
                    }
                    None => {
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Forward datagrams from source to destination.
async fn forward_datagrams(
    source: &Transport,
    dest: &Transport,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    loop {
        tokio::select! {
            result = source.recv_datagram() => {
                let data = result?;

                // Parse only when someone cares about events or the hook
                // may want to mutate the datagram.
                if ctx.observer_enabled {
                    let mut cursor = &data[..];
                    if let Ok(header) = AnyDatagramHeader::decode(ctx.draft, &mut cursor) {
                        let payload_len = cursor.len();
                        ctx.observer.on_event(&ProxyEvent::Datagram {
                            session_id: ctx.session_id,
                            side,
                            header: header.clone(),
                            payload_len,
                        });

                        if let Some(replacement) = ctx.hook.on_datagram(
                            ctx.session_id, side, &header, &data,
                        ) {
                            dest.send_datagram(Bytes::from(replacement))?;
                        } else {
                            dest.send_datagram(data)?;
                        }
                    } else {
                        dest.send_datagram(data)?;
                    }
                } else {
                    dest.send_datagram(data)?;
                }
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Determine the encoded length of a QUIC varint from its first byte.
fn varint_len(first_byte: u8) -> usize {
    1 << (first_byte >> 6)
}

/// Try to detect the concrete draft version by peeking at the first SETUP
/// message on a control stream.
///
/// - On the `ClientToProxy` direction, looks at CLIENT_SETUP's
///   `supported_versions` list and returns the highest draft in the 07–14
///   range we support.
/// - On the `RelayToProxy` direction, looks at SERVER_SETUP's
///   `selected_version` and returns the matching draft.
/// - For draft-15+ the SETUP carries no version, but those cases don't
///   reach this function because the caller only invokes it when the
///   draft isn't already fixed by ALPN.
///
/// Returns `None` if the buffer doesn't yet contain enough bytes for a
/// decision, or if the first message isn't a SETUP we recognize. The
/// caller keeps buffering and retries.
///
/// `fallback` is the session's configured default draft, used only to
/// reject impossible answers (e.g., SERVER_SETUP selected_version outside
/// the supported range).
fn detect_draft_from_setup(
    buf: &[u8],
    side: ProxySide,
    fallback: DraftVersion,
) -> Option<DraftVersion> {
    let _ = fallback;
    if buf.is_empty() {
        return None;
    }

    // Decode the message type varint. The first byte's top two bits give
    // the varint length. For drafts 07–10 the type is 0x40/0x41, encoded
    // as a 2-byte varint. For drafts 11+ it's 0x20/0x21, a 1-byte varint.
    let type_len = varint_len(buf[0]);
    if buf.len() < type_len {
        return None;
    }
    let mut cur = &buf[..type_len];
    let type_id = VarInt::decode(&mut cur).ok()?.into_inner();

    // Distinguish framing by the type id:
    //   0x40 = CLIENT_SETUP (drafts 07–10, varint length)
    //   0x41 = SERVER_SETUP (drafts 07–10, varint length)
    //   0x20 = CLIENT_SETUP (drafts 11+, u16-BE length)
    //   0x21 = SERVER_SETUP (drafts 11+, u16-BE length)
    let (is_client_setup, is_server_setup, uses_u16_length) = match type_id {
        0x40 => (true, false, false),
        0x41 => (false, true, false),
        0x20 => (true, false, true),
        0x21 => (false, true, true),
        _ => return None,
    };

    // The message we peek at is the one we'd expect to see first on this
    // direction. Anything else is probably out-of-order bytes we can't
    // disambiguate.
    match side {
        ProxySide::ClientToProxy | ProxySide::ProxyToRelay if !is_client_setup => return None,
        ProxySide::RelayToProxy | ProxySide::ProxyToClient if !is_server_setup => return None,
        _ => {}
    }

    let (payload_start, payload_len) = if uses_u16_length {
        if buf.len() < type_len + 2 {
            return None;
        }
        let len = ((buf[type_len] as usize) << 8) | (buf[type_len + 1] as usize);
        (type_len + 2, len)
    } else {
        if buf.len() <= type_len {
            return None;
        }
        let vl = varint_len(buf[type_len]);
        if buf.len() < type_len + vl {
            return None;
        }
        let mut cur = &buf[type_len..type_len + vl];
        let v = VarInt::decode(&mut cur).ok()?;
        (type_len + vl, v.into_inner() as usize)
    };

    if buf.len() < payload_start + payload_len {
        return None;
    }
    let payload = &buf[payload_start..payload_start + payload_len];

    if is_client_setup {
        // CLIENT_SETUP (draft 07–14): number_of_supported_versions (varint)
        // then that many version varints. Pick the highest draft we
        // support in the moq-00 cohort (07–14).
        let mut cur = payload;
        let count = VarInt::decode(&mut cur).ok()?.into_inner() as usize;
        let mut best: Option<DraftVersion> = None;
        for _ in 0..count {
            let v = VarInt::decode(&mut cur).ok()?.into_inner();
            if let Some(d) = version_varint_to_draft(v) {
                if (7..=14).contains(&d.number()) {
                    best = Some(match best {
                        Some(b) if b.number() >= d.number() => b,
                        _ => d,
                    });
                }
            }
        }
        best
    } else {
        // SERVER_SETUP (draft 07–14): selected_version (varint) then
        // parameters. We only need the first varint.
        let mut cur = payload;
        let v = VarInt::decode(&mut cur).ok()?.into_inner();
        let d = version_varint_to_draft(v)?;
        if (7..=14).contains(&d.number()) {
            Some(d)
        } else {
            None
        }
    }
}

/// Convert an on-wire MoQT version varint (`0xff000000 + draft`) to a
/// `DraftVersion`, or `None` if the value is malformed or unsupported.
fn version_varint_to_draft(v: u64) -> Option<DraftVersion> {
    const BASE: u64 = 0xff000000;
    if !(BASE..=BASE + 255).contains(&v) {
        return None;
    }
    DraftVersion::from_number((v - BASE) as u8)
}

/// TLS certificate verifier that skips all verification (testing only).
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a draft-07 CLIENT_SETUP on the wire with the given supported
    /// draft numbers.
    fn encode_client_setup_d07(drafts: &[u8]) -> Vec<u8> {
        use moqtap_codec::draft07::message::{ClientSetup, ControlMessage};
        let mut supported = Vec::new();
        for &n in drafts {
            supported.push(VarInt::from_usize(0xff000000 + n as usize));
        }
        let msg = ControlMessage::ClientSetup(ClientSetup {
            supported_versions: supported,
            parameters: Vec::new(),
        });
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        buf
    }

    /// Build a draft-14 CLIENT_SETUP on the wire (u16-BE framing).
    fn encode_client_setup_d14(drafts: &[u8]) -> Vec<u8> {
        use moqtap_codec::draft14::message::{ClientSetup, ControlMessage};
        let mut supported = Vec::new();
        for &n in drafts {
            supported.push(VarInt::from_usize(0xff000000 + n as usize));
        }
        let msg = ControlMessage::ClientSetup(ClientSetup {
            supported_versions: supported,
            parameters: Vec::new(),
        });
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        buf
    }

    /// Build a draft-07 SERVER_SETUP on the wire.
    fn encode_server_setup_d07(draft: u8) -> Vec<u8> {
        use moqtap_codec::draft07::message::{ControlMessage, ServerSetup};
        let msg = ControlMessage::ServerSetup(ServerSetup {
            selected_version: VarInt::from_usize(0xff000000 + draft as usize),
            parameters: Vec::new(),
        });
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        buf
    }

    /// Build a draft-14 SERVER_SETUP on the wire (u16-BE framing).
    fn encode_server_setup_d14(draft: u8) -> Vec<u8> {
        use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
        let msg = ControlMessage::ServerSetup(ServerSetup {
            selected_version: VarInt::from_usize(0xff000000 + draft as usize),
            parameters: Vec::new(),
        });
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn detect_picks_highest_draft_from_07_10_varint_framing() {
        // Drafts 07 and 09 offered; expect 09.
        let bytes = encode_client_setup_d07(&[7, 9]);
        let d = detect_draft_from_setup(&bytes, ProxySide::ClientToProxy, DraftVersion::Draft14);
        assert_eq!(d, Some(DraftVersion::Draft09));
    }

    #[test]
    fn detect_picks_highest_draft_from_11_14_u16_framing() {
        // Drafts 11, 13, 14 offered; expect 14.
        let bytes = encode_client_setup_d14(&[11, 13, 14]);
        let d = detect_draft_from_setup(&bytes, ProxySide::ClientToProxy, DraftVersion::Draft11);
        assert_eq!(d, Some(DraftVersion::Draft14));
    }

    #[test]
    fn detect_from_server_setup_varint_framing() {
        let bytes = encode_server_setup_d07(10);
        let d = detect_draft_from_setup(&bytes, ProxySide::RelayToProxy, DraftVersion::Draft07);
        assert_eq!(d, Some(DraftVersion::Draft10));
    }

    #[test]
    fn detect_from_server_setup_u16_framing() {
        let bytes = encode_server_setup_d14(14);
        let d = detect_draft_from_setup(&bytes, ProxySide::RelayToProxy, DraftVersion::Draft11);
        assert_eq!(d, Some(DraftVersion::Draft14));
    }

    #[test]
    fn detect_returns_none_on_partial_bytes() {
        let bytes = encode_client_setup_d14(&[14]);
        // Truncate to one byte — not enough to read length field.
        assert_eq!(
            detect_draft_from_setup(&bytes[..1], ProxySide::ClientToProxy, DraftVersion::Draft14),
            None
        );
    }

    #[test]
    fn detect_returns_none_for_unrelated_first_byte() {
        // First byte 0x10 is GOAWAY — not a SETUP we can detect from.
        let bytes = [0x10u8, 0x00, 0x00];
        assert_eq!(
            detect_draft_from_setup(&bytes, ProxySide::ClientToProxy, DraftVersion::Draft14),
            None
        );
    }

    #[test]
    fn detect_ignores_15_plus_versions_in_moq_00_setup() {
        // A malformed CLIENT_SETUP advertising only draft-15 over moq-00
        // (which shouldn't happen in practice). We refuse to pick 15 here
        // because 15+ uses ALPN, not CLIENT_SETUP.
        let bytes = encode_client_setup_d14(&[15]);
        assert_eq!(
            detect_draft_from_setup(&bytes, ProxySide::ClientToProxy, DraftVersion::Draft14),
            None
        );
    }

    #[test]
    fn detect_setup_wrong_direction_returns_none() {
        // CLIENT_SETUP peeked as SERVER_SETUP → None.
        let bytes = encode_client_setup_d14(&[14]);
        assert_eq!(
            detect_draft_from_setup(&bytes, ProxySide::RelayToProxy, DraftVersion::Draft14),
            None
        );
    }
}

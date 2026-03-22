//! Per-connection proxy session — forwards streams between client and relay.

use std::sync::Arc;

use bytes::Bytes;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use moqtap_client::transport::quic::QuicTransport;
use moqtap_client::transport::{RecvStream, SendStream, Transport};
use moqtap_codec::dispatch::AnyDatagramHeader;
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
}

impl ProxySessionConfig {
    /// Returns the ALPN protocol identifiers for the upstream connection.
    pub fn upstream_alpn(&self) -> Vec<Vec<u8>> {
        match &self.upstream_transport {
            UpstreamTransportType::Quic => vec![self.draft.quic_alpn().to_vec()],
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
        }
    }
}

/// A proxy session that forwards traffic between a client and an upstream
/// relay. One session is created per accepted client connection.
pub struct ProxySession {
    session_id: SessionId,
    config: ProxySessionConfig,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
}

impl ProxySession {
    /// Create a new proxy session.
    pub fn new(
        session_id: SessionId,
        config: ProxySessionConfig,
        observer: Arc<dyn ProxyObserver>,
        hook: Arc<dyn ProxyHook>,
        cancel: CancellationToken,
    ) -> Self {
        Self { session_id, config, observer, hook, cancel }
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

        let base_ctx = ForwardCtx {
            session_id: self.session_id,
            draft: self.config.draft,
            observer: Arc::clone(&self.observer),
            hook: Arc::clone(&self.hook),
            cancel: self.cancel.clone(),
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
        self.observer.on_event(&ProxyEvent::SessionEnded { session_id: self.session_id, reason });

        // Close both sides
        client.close(0, b"proxy session ended");
        relay.close(0, b"proxy session ended");

        match first_result {
            Some(Ok(Ok(()))) | None => Ok(()),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(ProxyError::SessionClosed(format!("task panic: {e}"))),
        }
    }

    /// Connect to the upstream relay.
    async fn connect_upstream(&self) -> Result<Transport, ProxyError> {
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
        tls_config.alpn_protocols = self.config.upstream_alpn();

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
    draft: DraftVersion,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
}

/// Forward the control stream (first bidirectional stream).
async fn forward_control_stream(
    client: &Transport,
    relay: &Transport,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    // Accept bi from client
    let (client_send, client_recv) = client.accept_bi().await?;
    ctx.observer.on_event(&ProxyEvent::BiStreamOpened {
        session_id: ctx.session_id,
        side: ProxySide::ClientToProxy,
    });

    // Open bi to relay
    let (relay_send, relay_recv) = relay.open_bi().await?;
    ctx.observer.on_event(&ProxyEvent::BiStreamOpened {
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

/// Pipe a control stream direction with inline parsing.
async fn pipe_control(
    mut recv: RecvStream,
    mut send: SendStream,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let mut parser = ControlStreamParser::new(ctx.draft);
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            result = recv.read(&mut buf) => {
                match result? {
                    Some(n) => {
                        let data = &buf[..n];

                        // Parse inline — the parser buffers bytes
                        // internally until a complete frame is available.
                        // We only forward bytes via frame.raw_bytes to
                        // avoid double-forwarding when a message spans
                        // multiple reads.
                        match parser.feed(data) {
                            ParseResult::Messages(frames) => {
                                for frame in &frames {
                                    // Emit event
                                    ctx.observer.on_event(
                                        &ProxyEvent::ControlMessage {
                                            session_id: ctx.session_id,
                                            side,
                                            message: frame
                                                .message
                                                .clone(),
                                        },
                                    );

                                    // Apply hook
                                    if let Some(replacement) =
                                        ctx.hook.on_control_message(
                                            ctx.session_id,
                                            side,
                                            &frame.message,
                                            &frame.raw_bytes,
                                        )
                                    {
                                        send.write_all(&replacement)
                                            .await?;
                                    } else {
                                        send.write_all(&frame.raw_bytes)
                                            .await?;
                                    }
                                }
                            }
                            ParseResult::NeedMore => {
                                // Bytes are buffered in the parser.
                                // They'll be forwarded as part of
                                // frame.raw_bytes when the message
                                // completes.
                            }
                        }
                    }
                    None => {
                        // Stream ended
                        ctx.observer.on_event(&ProxyEvent::StreamClosed {
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
                ctx.observer.on_event(&ProxyEvent::UniStreamOpened {
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
                        ctx.observer.on_event(&ProxyEvent::ParseError {
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

                        // Parse inline (best-effort)
                        if let Some(ref mut p) = parser {
                            let results = p.feed(feed_data);
                            for result in &results {
                                match result {
                                    crate::parser::data::DataParseResult::Header(
                                        header, _,
                                    ) => {
                                        ctx.observer.on_event(
                                            &ProxyEvent::DataStreamHeader {
                                                session_id: ctx.session_id,
                                                side,
                                                header: header.clone(),
                                            },
                                        );
                                    }
                                    crate::parser::data::DataParseResult::Object(
                                        header, _,
                                    ) => {
                                        ctx.observer.on_event(
                                            &ProxyEvent::ObjectHeader {
                                                session_id: ctx.session_id,
                                                side,
                                                header: header.clone(),
                                            },
                                        );
                                    }
                                    crate::parser::data::DataParseResult::Error(
                                        e,
                                    ) => {
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

                        // Always forward the raw bytes (including
                        // stream type varint)
                        send.write_all(data).await?;
                    }
                    None => {
                        ctx.observer.on_event(&ProxyEvent::StreamClosed {
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

                // Try to parse datagram header
                let mut cursor = &data[..];
                if let Ok(header) = AnyDatagramHeader::decode(ctx.draft, &mut cursor) {
                    let payload_len = cursor.len();
                    ctx.observer.on_event(&ProxyEvent::Datagram {
                        session_id: ctx.session_id,
                        side,
                        header: header.clone(),
                        payload_len,
                    });

                    // Apply hook
                    if let Some(replacement) = ctx.hook.on_datagram(
                        ctx.session_id, side, &header, &data,
                    ) {
                        dest.send_datagram(Bytes::from(replacement))?;
                    } else {
                        dest.send_datagram(data)?;
                    }
                } else {
                    // Forward even if parse fails
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

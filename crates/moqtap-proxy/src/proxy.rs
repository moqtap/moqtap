//! Transparent proxy orchestrator — accept loop and session management.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::error::ProxyError;
use crate::event::{ProxyEvent, SessionId};
use crate::hook::{NoOpHook, ProxyHook};
use crate::listener::{Listener, ListenerConfig};
use crate::observer::ProxyObserver;
use crate::session::{ProxySession, ProxySessionConfig};

/// The client-facing listener mode for the proxy.
#[derive(Debug, Clone)]
pub enum ListenerMode {
    /// Accept raw QUIC connections.
    Quic,
    /// Accept WebTransport sessions.
    WebTransport,
}

/// Configuration for the transparent proxy.
pub struct ProxyConfig {
    /// Listener configuration (bind address, certs, ALPN).
    pub listener: ListenerConfig,
    /// Per-session configuration (upstream address, TLS, transport).
    pub session: ProxySessionConfig,
    /// Client-facing listener mode.
    pub listener_mode: ListenerMode,
}

/// A transparent MoQT proxy that accepts client connections and forwards
/// traffic to an upstream relay.
///
/// Each accepted connection spawns a [`ProxySession`] that handles
/// bidirectional stream forwarding with inline MoQT frame parsing.
pub struct TransparentProxy {
    config: ProxyConfig,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
    next_session_id: AtomicU64,
}

impl TransparentProxy {
    /// Create a new proxy with the given configuration and observer.
    pub fn new(config: ProxyConfig, observer: Arc<dyn ProxyObserver>) -> Self {
        Self {
            config,
            observer,
            hook: Arc::new(NoOpHook),
            cancel: CancellationToken::new(),
            next_session_id: AtomicU64::new(1),
        }
    }

    /// Create a new proxy with a custom hook for frame mutation.
    pub fn with_hook(
        config: ProxyConfig,
        observer: Arc<dyn ProxyObserver>,
        hook: Arc<dyn ProxyHook>,
    ) -> Self {
        Self {
            config,
            observer,
            hook,
            cancel: CancellationToken::new(),
            next_session_id: AtomicU64::new(1),
        }
    }

    /// Returns a cancellation token that can be used to trigger shutdown.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Run the proxy accept loop. Blocks until cancelled or a fatal
    /// listener error occurs.
    pub async fn run(&self) -> Result<(), ProxyError> {
        match self.config.listener_mode {
            ListenerMode::Quic => self.run_quic().await,
            #[cfg(feature = "webtransport")]
            ListenerMode::WebTransport => self.run_webtransport().await,
            #[cfg(not(feature = "webtransport"))]
            ListenerMode::WebTransport => {
                Err(ProxyError::Listener("webtransport feature not enabled".to_string()))
            }
        }
    }

    /// Run the QUIC accept loop.
    async fn run_quic(&self) -> Result<(), ProxyError> {
        let listener = Listener::bind(ListenerConfig {
            bind_addr: self.config.listener.bind_addr,
            cert_chain: self.config.listener.cert_chain.clone(),
            key_der: self.config.listener.key_der.clone_key(),
            alpn: self.config.listener.alpn.clone(),
        })?;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (conn, alpn) = result?;
                    let session_id = self.next_session_id();
                    let client_addr = conn.remote_address();
                    self.emit_session_started(session_id, client_addr);

                    let session = self.new_session(session_id, alpn);
                    tokio::spawn(async move {
                        let _ = session.run(conn).await;
                    });
                }
                _ = self.cancel.cancelled() => {
                    listener.close();
                    return Ok(());
                }
            }
        }
    }

    /// Run the WebTransport accept loop.
    #[cfg(feature = "webtransport")]
    async fn run_webtransport(&self) -> Result<(), ProxyError> {
        use crate::listener::{WtListener, WtListenerConfig};

        let listener = WtListener::bind(WtListenerConfig {
            bind_addr: self.config.listener.bind_addr,
            cert_chain: self.config.listener.cert_chain.clone(),
            key_der: self.config.listener.key_der.clone_key(),
        })?;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let conn = result?;
                    let session_id = self.next_session_id();
                    let client_addr = conn.remote_address();
                    self.emit_session_started(session_id, client_addr);

                    // WebTransport carries no moqt-* ALPN (always h3) so the
                    // session falls back to config.draft and/or SETUP-peek.
                    let session = self.new_session(session_id, Vec::new());
                    tokio::spawn(async move {
                        let _ = session.run_webtransport(conn).await;
                    });
                }
                _ = self.cancel.cancelled() => {
                    listener.close();
                    return Ok(());
                }
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────

    fn next_session_id(&self) -> SessionId {
        SessionId(self.next_session_id.fetch_add(1, Ordering::Relaxed))
    }

    fn emit_session_started(&self, session_id: SessionId, client_addr: std::net::SocketAddr) {
        if self.observer.wants_events() {
            self.observer.on_event(&ProxyEvent::SessionStarted { session_id, client_addr });
        }
    }

    fn new_session(&self, session_id: SessionId, client_alpn: Vec<u8>) -> ProxySession {
        ProxySession::new(
            session_id,
            ProxySessionConfig {
                draft: self.config.session.draft,
                upstream_transport: self.config.session.upstream_transport.clone(),
                upstream_addr: self.config.session.upstream_addr.clone(),
                skip_upstream_cert_verify: self.config.session.skip_upstream_cert_verify,
                upstream_ca_certs: self.config.session.upstream_ca_certs.clone(),
                upstream_connect_timeout_secs: self.config.session.upstream_connect_timeout_secs,
            },
            client_alpn,
            Arc::clone(&self.observer),
            Arc::clone(&self.hook),
            self.cancel.child_token(),
        )
    }
}

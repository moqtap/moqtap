//! Unified listener — one UDP endpoint that accepts both raw-QUIC MoQT
//! and WebTransport clients, dispatching per connection based on the
//! ALPN the client negotiated during the TLS handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use moqtap_codec::version::DraftVersion;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::ProxyError;
use crate::transport::{self, TransportInstaller, TransportProfile};
use crate::types::Leg;

/// WebTransport ALPN identifier.
const H3_ALPN: &[u8] = b"h3";

/// Configuration for the proxy's listener.
pub struct ListenerConfig {
    /// Address to bind to (e.g., `"0.0.0.0:4443"`).
    pub bind_addr: SocketAddr,
    /// TLS certificate chain (DER-encoded).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// TLS private key (DER-encoded).
    pub key_der: PrivateKeyDer<'static>,
    /// Optional QUIC transport parameters — flow-control windows, MTU,
    /// keep-alive, congestion control — applied to every client
    /// connection this listener accepts.
    ///
    /// `None` installs no parameters of its own: the leg then takes
    /// [`ListenerConfig::transport_profile`] if it names one, and quinn's
    /// defaults otherwise.
    ///
    /// Setting this **and** [`ListenerConfig::transport_profile`] is
    /// refused by [`Listener::bind`] rather than merged, with
    /// [`ProxyError::TransportConfigAndProfile`] naming
    /// [`Leg::Client`] — see that variant for why no merge is possible.
    pub transport_config: Option<Arc<quinn::TransportConfig>>,
    /// The same parameters as [`ListenerConfig::transport_config`], as a
    /// value that can be written down, checked and stored.
    ///
    /// `Some(_)` builds the client leg's `quinn::TransportConfig` from this
    /// profile — through [`ListenerConfig::installer`], or through
    /// [`transport::DefaultInstaller`] when there is none — and installs it
    /// before the endpoint exists. A profile the installer refuses is
    /// [`ProxyError::TransportProfile`], and nothing is bound.
    ///
    /// `None` installs no profile: the leg then takes
    /// [`ListenerConfig::transport_config`] if it names one, and quinn's
    /// defaults otherwise. It is the *only* alternative to
    /// `transport_config`, never a companion to it: a leg naming both is
    /// refused at bind time.
    pub transport_profile: Option<TransportProfile>,
    /// How [`ListenerConfig::transport_profile`] becomes the config this
    /// leg installs.
    ///
    /// `None` uses [`transport::DefaultInstaller`], which applies the
    /// profile over a fresh `quinn::TransportConfig::default()`. Supply one
    /// to start from a base of your own instead — the trait exists because
    /// a `quinn::TransportConfig` cannot be cloned, so the only way to have
    /// a base *and* a profile is to build the base again for each leg.
    ///
    /// **Inert without a profile.** [`TransportInstaller::build`] takes a
    /// profile, so an installer set beside an empty
    /// [`ListenerConfig::transport_profile`] is never called and the leg
    /// installs nothing. It is said here because a setting that is quietly
    /// ignored is the failure this crate is least willing to hide.
    ///
    /// **It composes with a `qlog` spec** — named in plain code font
    /// because that field exists only under the `qlog` feature, so a link
    /// from this always-compiled one would not resolve. A leg carrying a
    /// profile, a spec and an installer builds its config here, once, and
    /// the capture sink is attached to what came back;
    /// [`TransportInstaller::build`] returns an owned
    /// `quinn::TransportConfig` precisely so that the two can stack.
    pub installer: Option<Arc<dyn TransportInstaller>>,
    /// Where this leg's QUIC-level capture is written, if it is captured at
    /// all.
    ///
    /// `Some(_)` builds the client leg's `quinn::TransportConfig`, installs
    /// the sink built from this spec on it, and hands that to the endpoint
    /// — all before the endpoint exists, because quinn accepts a sink in
    /// exactly one place and that place is a method which mutates a
    /// `quinn::TransportConfig`. It composes with
    /// [`ListenerConfig::transport_profile`], which is applied to the same
    /// config first, and **not** with
    /// [`ListenerConfig::transport_config`]: a leg naming a raw config and
    /// a spec is refused at bind time with
    /// [`ProxyError::TransportConfigAndQlog`] naming [`Leg::Client`], for
    /// the reason written out on that variant.
    ///
    /// A spec on its own, with neither of the other two fields set, is
    /// enough: the leg builds a `quinn::TransportConfig::default()` for the
    /// sink to go on and installs it, rather than installing nothing and
    /// leaving the capture attached to a config no connection uses.
    ///
    /// `None` is how a leg says it does not want a capture. A spec that
    /// names no writer is not that: it is refused with
    /// [`ProxyError::Qlog`], because a spec is how a caller *asks* for a
    /// capture.
    ///
    /// # Single-use, and therefore refused on a proxy template
    ///
    /// A [`QlogSpec`] owns its writer and is consumed when it becomes a
    /// sink, so it has no `Clone`. [`TransparentProxy`] copies its
    /// [`ListenerConfig`] template to build the listener it binds, and a
    /// copy has nothing it could hand over — so a spec set on a
    /// `ProxyConfig` could only be taken, counted as configured and
    /// delivered nowhere. `TransparentProxy::run` therefore **refuses** such
    /// a template with [`ProxyError::QlogOnProxyTemplate`], before it binds,
    /// rather than dropping the field and coming up: a proxy that ran anyway
    /// would report success and leave the caller's file uncreated, which
    /// reads as a run that produced no events.
    ///
    /// Capture a client leg by building the [`ListenerConfig`] here and
    /// calling [`Listener::bind`] yourself, which is also the only shape in
    /// which one capture per connection is expressible: one sink shared by
    /// an endpoint's connections writes all of them into one file, behind
    /// one preamble, with no record saying where one ends.
    ///
    /// [`ProxyError::TransportConfigAndQlog`]: crate::error::ProxyError::TransportConfigAndQlog
    /// [`ProxyError::Qlog`]: crate::error::ProxyError::Qlog
    /// [`ProxyError::QlogOnProxyTemplate`]: crate::error::ProxyError::QlogOnProxyTemplate
    /// [`QlogSpec`]: crate::qlog::QlogSpec
    /// [`TransparentProxy`]: crate::proxy::TransparentProxy
    #[cfg(feature = "qlog")]
    pub qlog: Option<crate::qlog::QlogSpec>,
}

/// A client connection that has completed its handshake and is ready
/// for MoQT session handling.
///
/// Produced by [`Listener::accept`]. Each variant corresponds to a
/// distinct client-facing transport that MoQT can run over.
pub enum AcceptedConn {
    /// Raw QUIC connection speaking MoQT directly. The negotiated ALPN
    /// (`moq-00`, `moqt-15`, `moqt-16`, `moqt-17`, …) is returned so
    /// callers can resolve the draft version.
    Quic {
        /// The accepted QUIC connection.
        conn: quinn::Connection,
        /// The ALPN negotiated with the client.
        alpn: Vec<u8>,
    },
    /// WebTransport session, with the H3 + extended-CONNECT dance
    /// already completed by the listener.
    #[cfg(feature = "webtransport")]
    WebTransport(wtransport::Connection),
}

/// Build the ALPN list the server advertises to clients — every MoQT
/// QUIC ALPN we support, plus `h3` when the WebTransport feature is on.
///
/// Each ALPN string comes from [`DraftVersion::quic_alpn`], but the set of
/// drafts is the hardcoded list below — `DraftVersion` exposes no iterator.
/// **A new draft must be added here by hand.** An earlier revision of this
/// comment claimed the list derived itself; draft-20 was consequently missing
/// for a while, and a draft-20 client failed the TLS handshake outright
/// ("peer doesn't support any known protocol") before sending a single MoQT
/// frame. `tests/control_plane_uni.rs` has a per-draft row that catches this.
fn advertised_alpns() -> Vec<Vec<u8>> {
    // Dedup: drafts 07–14 all map to `moq-00`, so iterate every draft
    // and keep unique ALPNs.
    let mut out: Vec<Vec<u8>> = Vec::new();
    for d in [
        DraftVersion::Draft07,
        DraftVersion::Draft08,
        DraftVersion::Draft09,
        DraftVersion::Draft10,
        DraftVersion::Draft11,
        DraftVersion::Draft12,
        DraftVersion::Draft13,
        DraftVersion::Draft14,
        DraftVersion::Draft15,
        DraftVersion::Draft16,
        DraftVersion::Draft17,
        DraftVersion::Draft18,
        DraftVersion::Draft19,
        DraftVersion::Draft20,
    ] {
        let alpn = d.quic_alpn().to_vec();
        if !out.iter().any(|existing| existing == &alpn) {
            out.push(alpn);
        }
    }
    #[cfg(feature = "webtransport")]
    out.push(H3_ALPN.to_vec());
    out
}

/// A transport-agnostic MoQT listener that accepts both raw-QUIC and
/// WebTransport clients on the same UDP port.
pub struct Listener {
    endpoint: quinn::Endpoint,
    /// The server configuration this endpoint was built with, kept so that
    /// [`Listener::set_transport`] can replace one field of it without
    /// rebuilding the rest.
    ///
    /// A clone of the value handed to quinn rather than a fresh build, and
    /// the difference is not an optimisation. Rebuilding would re-parse the
    /// certificate — which means retaining the private key here, and
    /// `PrivateKeyDer` is not `Clone` — and `quinn::ServerConfig::with_crypto`
    /// draws a fresh random handshake-token master key each time it is
    /// called, which would invalidate every retry token already outstanding.
    /// Keeping the built value costs one `Arc` per field and none of that.
    server_config: quinn::ServerConfig,
}

impl Listener {
    /// Bind to the configured address and start listening.
    ///
    /// The listener advertises every supported MoQT ALPN (`moq-00` and
    /// `moqt-<N>` for all known drafts) plus `h3` for WebTransport. The
    /// client picks which one to speak; the proxy forwards whatever
    /// arrives.
    ///
    /// This binds an ordinary UDP socket at [`ListenerConfig::bind_addr`],
    /// wraps it with quinn's default runtime adapter and hands it to
    /// [`Listener::bind_with_socket`]. Must therefore be called from
    /// inside a tokio runtime context — as it always had to be, because
    /// quinn reaches for the same runtime when it binds a socket itself.
    pub fn bind(config: ListenerConfig) -> Result<Self, ProxyError> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| ProxyError::Listener("no async runtime found".to_string()))?;
        let socket = std::net::UdpSocket::bind(config.bind_addr)
            .map_err(|e| ProxyError::Listener(e.to_string()))?;
        let socket =
            runtime.wrap_udp_socket(socket).map_err(|e| ProxyError::Listener(e.to_string()))?;

        Self::bind_with_socket(config, socket)
    }

    /// Bind the listener over a caller-supplied abstract socket.
    ///
    /// Every datagram this listener sends to, or receives from, a client
    /// passes through `socket`, so a caller that supplies a decorating
    /// implementation — a tap, a counter, a network-impairment shim —
    /// observes and can alter the whole client-facing leg. Ownership is
    /// shared, so the caller keeps its handle on the socket after the
    /// endpoint is running.
    ///
    /// [`ListenerConfig::bind_addr`] is ignored here: `socket` is already
    /// bound, and its address is the one [`Listener::local_addr`] reports.
    /// The rest of the configuration — the certificate, the advertised
    /// ALPN list, the transport parameters — applies exactly as it does to
    /// [`Listener::bind`], which is a thin wrapper around this function.
    ///
    /// # One socket covers WebTransport clients too
    ///
    /// This single seam reaches raw-QUIC and WebTransport clients alike,
    /// because on the client-facing side the proxy never builds a
    /// WebTransport endpoint of its own. It builds the QUIC endpoint here,
    /// reads the negotiated ALPN off the handshake, and for `h3` clients
    /// hands the still-connecting QUIC connection to the WebTransport
    /// library to finish. The library adopts a connection that already
    /// lives on this endpoint rather than binding a socket for it, so
    /// there is no second datagram path to intercept.
    ///
    /// The relay leg to the upstream relay is a separate endpoint and is
    /// not affected by this socket.
    pub fn bind_with_socket(
        config: ListenerConfig,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
    ) -> Result<Self, ProxyError> {
        // First, before the certificate is parsed and long before the
        // endpoint is built. Every refusal this can produce is a fault in
        // what the caller wrote rather than in the world, so a caller must
        // not have to get a working certificate before hearing about one,
        // and none of them must ever arrive attached to a live endpoint
        // that then has to be torn down. It is also where a capture's sink
        // is built, which writes the file's preamble — so a leg whose spec
        // was refused has written nothing anywhere.
        let transport = transport::resolve(
            Leg::Client,
            config.transport_config,
            config.transport_profile.as_ref(),
            config.installer.as_ref(),
            // Moved out of the config rather than borrowed: a spec owns its
            // writer and is consumed when it becomes a sink, so there is
            // nothing here a second bind could use.
            #[cfg(feature = "qlog")]
            config.qlog,
        )?;

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(config.cert_chain, config.key_der)
            .map_err(|e| ProxyError::TlsConfig(format!("server cert config: {e}")))?;

        server_tls.alpn_protocols = advertised_alpns();
        server_tls.max_early_data_size = u32::MAX;

        let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
            server_tls.try_into().map_err(|e| ProxyError::TlsConfig(format!("{e}")))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        if let Some(transport) = transport {
            server_config.transport_config(transport);
        }

        let runtime = quinn::default_runtime()
            .ok_or_else(|| ProxyError::Listener("no async runtime found".to_string()))?;

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config.clone()),
            socket,
            runtime,
        )
        .map_err(|e| ProxyError::Listener(e.to_string()))?;

        Ok(Self { endpoint, server_config })
    }

    /// Install `transport` as the QUIC transport parameters this listener
    /// gives to the connections it accepts **from now on**.
    ///
    /// # It cannot reach a connection that already exists
    ///
    /// A quinn connection takes its `TransportConfig` once, out of the
    /// server configuration in force when its handshake began, and keeps
    /// that `Arc` for as long as it lives. There is no way to hand a live
    /// connection a different one — quinn exposes four setters on an
    /// accepted connection (the two stream-count limits and the two
    /// windows) and nothing else. So this changes what the *next* accepted
    /// connection gets and leaves every connection already running exactly
    /// as it was.
    ///
    /// That is worth stating rather than glossing, because the failure it
    /// produces is silent: on a proxy nobody is connecting to any more,
    /// this call succeeds, changes the endpoint, and never reaches a single
    /// packet.
    ///
    /// Everything else about the endpoint — the certificate, the advertised
    /// ALPN list, the handshake token key — is carried over from the
    /// configuration the listener bound with, so a client's view of this
    /// server is unchanged apart from the transport parameters.
    pub(crate) fn set_transport(&self, transport: std::sync::Arc<quinn::TransportConfig>) {
        let mut config = self.server_config.clone();
        config.transport_config(transport);
        self.endpoint.set_server_config(Some(config));
    }

    /// Accept the next incoming connection and dispatch based on the
    /// ALPN negotiated during the TLS handshake.
    ///
    /// Raw-QUIC connections are returned immediately with the negotiated
    /// ALPN so the caller can pick the MoQT draft. For `h3` clients the
    /// listener drives the HTTP/3 + extended-CONNECT handshake to
    /// completion before returning a ready `wtransport::Connection`.
    pub async fn accept(&self) -> Result<AcceptedConn, ProxyError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ProxyError::Listener("endpoint closed".to_string()))?;

        let mut connecting = incoming.accept().map_err(|e| ProxyError::Listener(e.to_string()))?;

        // Peeking at handshake_data resolves as soon as the server has
        // processed the ClientHello, so the ALPN is known before the
        // full handshake completes — and the Connecting is still live.
        let hs_data = connecting
            .handshake_data()
            .await
            .map_err(|e| ProxyError::Listener(format!("handshake data: {e}")))?;

        let alpn = hs_data
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()
            .and_then(|hd| hd.protocol)
            .map(|p| p.to_vec())
            .unwrap_or_default();

        if alpn == H3_ALPN {
            #[cfg(feature = "webtransport")]
            {
                let session_fut =
                    wtransport::endpoint::IncomingSessionFuture::with_quic_connecting(connecting);
                let session_request = session_fut
                    .await
                    .map_err(|e| ProxyError::Listener(format!("webtransport handshake: {e}")))?;
                let conn = session_request
                    .accept()
                    .await
                    .map_err(|e| ProxyError::Listener(format!("webtransport accept: {e}")))?;
                Ok(AcceptedConn::WebTransport(conn))
            }
            #[cfg(not(feature = "webtransport"))]
            {
                drop(connecting);
                Err(ProxyError::Listener(
                    "client negotiated h3 but webtransport feature is not enabled".to_string(),
                ))
            }
        } else {
            let conn = connecting.await.map_err(|e| ProxyError::Listener(e.to_string()))?;
            Ok(AcceptedConn::Quic { conn, alpn })
        }
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.endpoint.local_addr().map_err(|e| ProxyError::Listener(e.to_string()))
    }

    /// Stop accepting new connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"proxy shutting down");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;
    use crate::transport::TransportProfileError;

    /// A certificate this listener will never get as far as parsing.
    ///
    /// Every refusal tested below has to be reported *before* the TLS
    /// build, so the tests hand over ten bytes of nothing. If one of them
    /// ever fails with a `TlsConfig` error, the check has drifted later
    /// than the certificate and a caller now has to hold a valid identity
    /// before they can be told their two transport fields contradict.
    fn unusable_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![CertificateDer::from(vec![0u8; 10])],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8; 10])),
        )
    }

    /// A real self-signed `localhost` pair, for the one test that has to
    /// bind successfully.
    fn usable_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("a key pair for a test certificate");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).expect("certificate params");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        (
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        )
    }

    fn config(identity: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)) -> ListenerConfig {
        let (cert_chain, key_der) = identity;
        ListenerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("a literal address"),
            cert_chain,
            key_der,
            transport_config: None,
            transport_profile: None,
            installer: None,
            #[cfg(feature = "qlog")]
            qlog: None,
        }
    }

    /// Counts the builds and returns a config built the default way.
    struct CountingInstaller(Arc<AtomicUsize>);

    impl TransportInstaller for CountingInstaller {
        fn build(
            &self,
            profile: &TransportProfile,
        ) -> Result<quinn::TransportConfig, TransportProfileError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            profile.into_config()
        }
    }

    #[tokio::test]
    async fn a_client_leg_naming_both_a_config_and_a_profile_is_refused_at_bind() {
        let mut config = config(unusable_identity());
        config.transport_config = Some(Arc::new(quinn::TransportConfig::default()));
        config.transport_profile = Some(TransportProfile::default());

        let err = Listener::bind(config).err().expect("a contradiction is not a listener");
        assert!(
            matches!(err, ProxyError::TransportConfigAndProfile { leg: Leg::Client }),
            "the client leg's contradiction has to be reported as the client leg's: {err}"
        );
    }

    /// The client leg's other contradiction, refused as its own thing and
    /// with nothing written anywhere.
    ///
    /// Two halves. The first is that the refusal is
    /// `TransportConfigAndQlog` and not `TransportConfigAndProfile`: the
    /// two pairs have different fixes, and a caller told the wrong one goes
    /// looking at the wrong half of their configuration. The second is what
    /// makes this more than a claim about a return value — the sink writes
    /// its preamble the instant it is built, so a writer that is still
    /// empty afterwards is proof that no sink was built and no capture was
    /// quietly begun on a leg that then refused to bind.
    #[cfg(feature = "qlog")]
    #[tokio::test]
    async fn a_client_leg_naming_both_a_config_and_a_spec_is_refused_as_that() {
        /// Everything written to it, readable while the writer is alive.
        #[derive(Clone)]
        struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("no test holds this across a panic").extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut config = config(unusable_identity());
        config.transport_config = Some(Arc::new(quinn::TransportConfig::default()));
        config.qlog = Some(crate::qlog::QlogSpec {
            writer: Some(Box::new(Captured(Arc::clone(&sink)))),
            title: Some("client leg".to_string()),
            description: None,
        });

        let err = Listener::bind(config).err().expect("a contradiction is not a listener");
        assert!(
            matches!(err, ProxyError::TransportConfigAndQlog { leg: Leg::Client }),
            "a raw config and a spec is a different fault from a raw config and a profile, with a \
             different fix, and one refusal covering both would send the caller to the wrong half \
             of their configuration: {err}"
        );
        assert!(
            sink.lock().expect("uncontended").is_empty(),
            "the preamble is written the moment a sink is built, so anything here means the \
             refused leg began a capture on its way to refusing"
        );
    }

    #[tokio::test]
    async fn a_client_leg_whose_profile_cannot_be_honoured_does_not_bind() {
        let mut config = config(unusable_identity());
        // quinn raises anything under 1200 to 1200 without a word, so a
        // listener that came up here would be running at an MTU nobody
        // asked for.
        config.transport_profile =
            Some(TransportProfile { initial_mtu: Some(900), ..Default::default() });

        let err = Listener::bind(config).err().expect("an unhonourable profile is not a listener");
        assert!(
            matches!(
                err,
                ProxyError::TransportProfile {
                    leg: Leg::Client,
                    source: TransportProfileError::MtuBelowFloor { .. },
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_profile_carrying_client_leg_installs_and_binds() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let builds = Arc::new(AtomicUsize::new(0));
        let mut config = config(usable_identity());
        config.transport_profile = Some(TransportProfile {
            initial_mtu: Some(1350),
            receive_window: Some(4 * 1024 * 1024),
            ..Default::default()
        });
        config.installer = Some(Arc::new(CountingInstaller(Arc::clone(&builds))));

        let listener = Listener::bind(config).expect("a valid profile binds a listener");
        assert!(listener.local_addr().is_ok(), "the endpoint is live");
        assert_eq!(
            builds.load(Ordering::Relaxed),
            1,
            "the leg has to build its config through the installer, once, before the endpoint \
             exists — a leg that bound without consulting it would be running on quinn's \
             defaults and reporting success"
        );
        listener.close();
    }
}

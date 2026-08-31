//! Transparent proxy orchestrator — accept loop and session management.
//!
//! The proxy binds a single listener that accepts raw-QUIC MoQT and
//! WebTransport clients simultaneously, negotiated via ALPN. Each
//! accepted connection is handed to a [`ProxySession`] that forwards
//! traffic to the configured upstream relay.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::control::{ControlPlane, LegSetup, ProxyControl};
use crate::error::ProxyError;
use crate::event::{ProxyEvent, SessionId};
use crate::hook::{NoOpHook, ProxyHook};
use crate::listener::{AcceptedConn, Listener, ListenerConfig};
use crate::observer::ProxyObserver;
use crate::session::{ProxySession, ProxySessionConfig, UpstreamTransportType};

/// Configuration for the transparent proxy.
pub struct ProxyConfig {
    /// Listener configuration (bind address, certs).
    pub listener: ListenerConfig,
    /// Per-session configuration (upstream address, TLS, transport).
    pub session: ProxySessionConfig,
}

/// A transparent MoQT proxy that accepts client connections and forwards
/// traffic to an upstream relay.
///
/// Each accepted connection spawns a [`ProxySession`] that handles
/// bidirectional stream forwarding with inline MoQT frame parsing. The
/// client-facing transport (raw QUIC vs WebTransport) is chosen by the
/// client via ALPN and dispatched automatically — no configuration
/// required.
pub struct TransparentProxy {
    config: ProxyConfig,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
    next_session_id: AtomicU64,
    /// What a [`ProxyControl`] reads and what every session registers with.
    ///
    /// Constructed with the proxy rather than with the listener, because
    /// [`TransparentProxy::control`] has to answer before `run()` is
    /// awaited: a caller that owns the proxy is usually the caller about to
    /// give up its thread of control to the accept loop, so a handle that
    /// could only be taken afterwards could not be taken at all.
    control: Arc<ControlPlane>,
    /// The socket the client-facing endpoint is bound over, when the caller
    /// supplied one.
    ///
    /// `None` — the ordinary case — makes `run()` bind its own socket at
    /// [`ListenerConfig::bind_addr`], which is what this proxy has always
    /// done. `Some(_)` is set only by
    /// `TransparentProxy::set_impaired_socket` — named in plain code font
    /// because it exists only under the `impair` feature, so a link to it
    /// from this always-compiled field would not resolve — which is also
    /// where the handle that arms it is recorded, so the socket and the
    /// thing that impairs it can only arrive together.
    client_socket: Option<Arc<dyn quinn::AsyncUdpSocket>>,
}

impl TransparentProxy {
    /// Create a new proxy with the given configuration and observer.
    pub fn new(config: ProxyConfig, observer: Arc<dyn ProxyObserver>) -> Self {
        let control = ControlPlane::new(LegSetup::from_config(&config));
        Self {
            config,
            observer,
            hook: Arc::new(NoOpHook),
            cancel: CancellationToken::new(),
            next_session_id: AtomicU64::new(1),
            control,
            client_socket: None,
        }
    }

    /// Create a new proxy with a custom hook for frame mutation.
    pub fn with_hook(
        config: ProxyConfig,
        observer: Arc<dyn ProxyObserver>,
        hook: Arc<dyn ProxyHook>,
    ) -> Self {
        let control = ControlPlane::new(LegSetup::from_config(&config));
        Self {
            config,
            observer,
            hook,
            cancel: CancellationToken::new(),
            next_session_id: AtomicU64::new(1),
            control,
            client_socket: None,
        }
    }

    /// Run one leg over `socket`, and let
    /// [`ProxyControl::set_impair`](crate::control::ProxyControl::set_impair)
    /// arm `handle` on it.
    ///
    /// Both halves at once, deliberately. `quinn`'s `AsyncUdpSocket` is a
    /// trait object with no downcast, and `quinn_netem` exposes no accessor
    /// from a wrapped socket back to its handle, so nothing anywhere can
    /// check that a handle belongs to the socket beside it. Taking them as
    /// two independent settings would make a mismatched pair expressible —
    /// and a mismatched pair arms an impairment that is reported as applied
    /// and crossed by nobody's traffic, which is the exact failure the whole
    /// impairment surface exists to make loud. Taking them together does not
    /// *prove* they match, but it removes every way of supplying them that
    /// does not.
    ///
    /// Call before [`TransparentProxy::run`]. The client leg's socket is
    /// consumed when the endpoint is bound and the relay leg's when a
    /// session dials, so a socket set afterwards reaches the client leg
    /// never and the relay leg only from the next session on.
    ///
    /// # What each leg does with it
    ///
    /// [`Leg::Client`](crate::transport::Leg::Client) binds the listener's
    /// endpoint over it, which covers raw-QUIC and WebTransport clients
    /// alike — the proxy builds one QUIC endpoint on that side and hands
    /// `h3` connections to the WebTransport library already connected, so
    /// there is no second datagram path.
    ///
    /// [`Leg::Upstream`](crate::transport::Leg::Upstream) sets
    /// [`ProxySessionConfig::upstream_socket`], which **every** session this
    /// proxy accepts then builds its relay endpoint over. Two endpoints
    /// reading one socket take each other's datagrams, so an upstream socket
    /// set here is only sound for a proxy handling one client at a time — a
    /// capture or impairment harness rather than a fan-out deployment. That
    /// is a property of the socket seam and not of this call; it is repeated
    /// here because this is now the easiest way to reach it.
    ///
    /// A WebTransport upstream refuses a socket outright when it dials, with
    /// [`ProxyError::UpstreamSocketUnsupported`], rather than connecting
    /// around it.
    #[cfg(feature = "impair")]
    pub fn set_impaired_socket(
        &mut self,
        leg: crate::types::Leg,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        handle: quinn_netem::ImpairHandle,
    ) {
        match leg {
            crate::types::Leg::Client => self.client_socket = Some(socket),
            crate::types::Leg::Upstream => self.config.session.upstream_socket = Some(socket),
        }
        self.control.set_impair_handle(leg, handle);
    }

    /// Returns a cancellation token that can be used to trigger shutdown.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// A handle onto this proxy — the address it bound, and the sessions it
    /// is running.
    ///
    /// Callable at any point after the proxy is constructed, and meant to be
    /// called **before** [`TransparentProxy::run`] is awaited: `run()` does
    /// not return until the proxy is finished, so a caller that waited for
    /// it would never get a handle to a proxy that was doing anything. Every
    /// question a handle answers is defined for a proxy that has not bound
    /// yet — see [`ProxyControl`].
    ///
    /// Cheap, and cheap to keep: the handle is one `Arc` onto state the
    /// proxy already holds, and clones of it share that state rather than
    /// copying it.
    pub fn control(&self) -> ProxyControl {
        ProxyControl::new(Arc::clone(&self.control))
    }

    /// Run the proxy accept loop. Blocks until cancelled or a fatal
    /// listener error occurs.
    pub async fn run(&self) -> Result<(), ProxyError> {
        // Behind an `Arc`, and published, because the bound endpoint is no
        // longer only this loop's business: it is the one place the port a
        // `bind_addr` of `:0` resolved to can be read, and a `ProxyControl`
        // taken before this function was even called has to be able to read
        // it. The guard un-publishes on every way out of this function —
        // cancellation below, the `?` on a fatal accept error, and this
        // whole future being dropped by whoever spawned it — so a handle
        // never reports an address for an endpoint that is gone.
        // Before the bind, because a template carrying a capture spec is a
        // contradiction in what the caller wrote rather than a fact about
        // the world, and because a proxy that came up anyway would be this
        // crate's cardinal failure with nothing to give it away: it would
        // bind, accept, forward, report success, and leave the file the
        // caller was watching uncreated. Both legs are checked here rather
        // than at the two copies below, so the answer arrives before a
        // socket exists and does not depend on a connection being accepted.
        #[cfg(feature = "qlog")]
        {
            if self.config.listener.qlog.is_some() {
                return Err(ProxyError::QlogOnProxyTemplate { leg: crate::types::Leg::Client });
            }
            if self.config.session.upstream_qlog.is_some() {
                return Err(ProxyError::QlogOnProxyTemplate { leg: crate::types::Leg::Upstream });
            }
        }

        let config = self.listener_config();
        let listener = Arc::new(match &self.client_socket {
            // A supplied socket replaces the bind and nothing else: the same
            // certificate, the same ALPN list and the same transport
            // parameters follow, and `bind_addr` is then ignored because the
            // socket is already bound.
            Some(socket) => Listener::bind_with_socket(config, Arc::clone(socket))?,
            None => Listener::bind(config)?,
        });
        let _bound = self.control.publish_listener(Arc::clone(&listener));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    self.dispatch(result?);
                }
                _ = self.cancel.cancelled() => {
                    listener.close();
                    return Ok(());
                }
            }
        }
    }

    /// Spawn a session for an accepted connection, picking the right
    /// entry point based on the negotiated transport.
    fn dispatch(&self, accepted: AcceptedConn) {
        match accepted {
            AcceptedConn::Quic { conn, alpn } => {
                let session_id = self.next_session_id();
                let client_addr = conn.remote_address();
                self.emit_session_started(session_id, client_addr, "QUIC");
                let session = self.new_session(session_id, alpn);
                tokio::spawn(async move {
                    let _ = session.run(conn).await;
                });
            }
            #[cfg(feature = "webtransport")]
            AcceptedConn::WebTransport(conn) => {
                let session_id = self.next_session_id();
                let client_addr = conn.remote_address();
                self.emit_session_started(session_id, client_addr, "WebTransport");
                // WebTransport carries no moqt-* ALPN (always h3) so the
                // session falls back to config.draft and/or SETUP-peek.
                let session = self.new_session(session_id, Vec::new());
                tokio::spawn(async move {
                    let _ = session.run_webtransport(conn).await;
                });
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────

    fn next_session_id(&self) -> SessionId {
        SessionId(self.next_session_id.fetch_add(1, Ordering::Relaxed))
    }

    fn emit_session_started(
        &self,
        session_id: SessionId,
        client_addr: std::net::SocketAddr,
        client_transport: &str,
    ) {
        if self.observer.wants_events() {
            self.observer.on_event(&ProxyEvent::SessionStarted {
                session_id,
                client_addr,
                client_transport: client_transport.to_string(),
            });
        }
    }

    fn new_session(&self, session_id: SessionId, client_alpn: Vec<u8>) -> ProxySession {
        let mut session = ProxySession::new(
            session_id,
            self.session_config(),
            client_alpn,
            Arc::clone(&self.observer),
            Arc::clone(&self.hook),
            self.cancel.child_token(),
        );
        // Attached here rather than taken as a seventh constructor argument:
        // a session built directly, which is how this crate's own tests
        // drive one, belongs to no proxy and therefore to no control plane,
        // and making the plane a parameter would force every such caller to
        // conjure one that lists a session nobody can reach.
        session.attach_control(Arc::clone(&self.control));
        session
    }

    // ── The two hand-written copies ────────────────────────────────
    //
    // This proxy holds one template per leg and copies it — once for the
    // listener it binds, once per connection it accepts — because neither
    // config is `Clone`: the listener owns a `PrivateKeyDer`, which is
    // cloned through `clone_key`, and the session config owns
    // `Arc<dyn>`s that are cheap to share but not derivable.
    // A hand-written copy is exactly where a field added later gets forgotten,
    // and this crate's cardinal failure is a setting that is accepted, reported
    // as applied, and silently reaches nothing: the caller sets a window, the
    // proxy comes up, and the run is believed. So both functions below start by
    // **destructuring the template with no `..`**. That is not decoration — a
    // field added to either config stops this file compiling with *pattern does
    // not mention field*, at the one place that has to learn about it, rather
    // than passing the build and dropping the value at run time. Do not add
    // `..` to either pattern; it would put the trap back.
    //
    // Two fields no longer come from the template unconditionally, and both
    // read the control plane first: the client leg's transport parameters
    // and the session's shape profile. A live request that set either of
    // them has to win over the value the proxy was built with, or the
    // request would apply to sessions already running and not to the ones
    // accepted after it — the reverse of what every caller expects.
    //
    // And one field per leg is deliberately *not* carried: the qlog spec,
    // which owns a writer, has no `Clone` and is consumed when it becomes a
    // sink. A template that is copied — once here, once per accepted
    // connection — has nothing it could hand over. The pattern still names
    // it, so the decision is visible where the copy is made rather than
    // inferred from its absence, and both fields say so in their own
    // documentation.
    //
    // Neither copy has to *report* that, because `run` has already refused a
    // template holding either spec before it binds. These two `None`s are
    // therefore what a template with no spec in it produces, and never a
    // value being dropped: if the refusal above is ever removed, these lines
    // become exactly the silent failure the paragraph above is about.

    /// A fresh [`ListenerConfig`] carrying every field of this proxy's
    /// template — every field but one, and the exception is stated at the
    /// pattern below rather than left to be noticed.
    fn listener_config(&self) -> ListenerConfig {
        let ListenerConfig {
            bind_addr,
            cert_chain,
            key_der,
            transport_config,
            transport_profile,
            installer,
            // Discarded rather than bound, because there is nothing a copy
            // could do with it. A `QlogSpec` owns a `Box<dyn Write>`, has
            // no `Clone`, and is consumed the moment it becomes a sink, so
            // a template cannot hand one to anything and this copy leaves
            // the field `None`. Naming it here is still what the pattern is
            // for: the next field added to `ListenerConfig` stops this file
            // compiling, and this one had to be *decided* rather than
            // forgotten.
            #[cfg(feature = "qlog")]
                qlog: _,
        } = &self.config.listener;

        // A profile installed through the control plane has already been
        // built — through this leg's own installer — so it arrives as a
        // finished config and displaces both of the template's transport
        // fields. Leaving `transport_profile` beside it would be the one
        // combination `Listener::bind` refuses outright, and this proxy
        // would stop binding.
        let live = self.control.client_transport();
        let (transport_config, transport_profile) = match live {
            Some(config) => (Some(config), None),
            None => (transport_config.clone(), transport_profile.clone()),
        };

        ListenerConfig {
            bind_addr: *bind_addr,
            cert_chain: cert_chain.clone(),
            key_der: key_der.clone_key(),
            transport_config,
            transport_profile,
            installer: installer.clone(),
            // The one field of either template that a copy cannot carry.
            // A spec set on a `ProxyConfig` therefore reaches no leg, which
            // is said on the field itself as well: capture a client leg by
            // building the `ListenerConfig` and calling `Listener::bind`
            // directly, which is also the only place one writer per
            // connection is expressible.
            #[cfg(feature = "qlog")]
            qlog: None,
        }
    }

    /// A fresh [`ProxySessionConfig`] carrying every field of this proxy's
    /// template, built once per accepted connection.
    fn session_config(&self) -> ProxySessionConfig {
        let ProxySessionConfig {
            draft,
            upstream_transport,
            upstream_addr,
            skip_upstream_cert_verify,
            upstream_ca_certs,
            upstream_connect_timeout_secs,
            upstream_transport_config,
            upstream_transport_profile,
            upstream_installer,
            // Discarded for the same reason the client leg's spec is, and
            // it bites harder here: this copy is made once per accepted
            // connection, and one spec — one writer, consumed when it
            // becomes a sink — cannot be divided between them. A relay leg
            // is captured by driving `ProxySession` directly, one spec per
            // session.
            #[cfg(feature = "qlog")]
                upstream_qlog: _,
            upstream_socket,
            egress,
            shape,
        } = &self.config.session;

        // As on the client leg, a live profile displaces both of the
        // template's transport fields rather than joining one of them: a leg
        // naming a raw config and a profile at once is refused when it
        // dials, so leaving the template's config in place would turn every
        // session accepted after the request into an upstream-connect
        // failure. Stored as a *profile* rather than as the config it built,
        // so each session still runs the installer once for its own
        // connection exactly as a configured profile does.
        let live_transport = self.control.upstream_transport();
        let (upstream_transport_config, upstream_transport_profile) = match live_transport {
            Some(profile) => (None, Some(profile)),
            None => (upstream_transport_config.clone(), upstream_transport_profile.clone()),
        };

        ProxySessionConfig {
            draft: *draft,
            upstream_transport: upstream_transport.clone(),
            upstream_addr: upstream_addr.clone(),
            skip_upstream_cert_verify: *skip_upstream_cert_verify,
            upstream_ca_certs: upstream_ca_certs.clone(),
            upstream_connect_timeout_secs: *upstream_connect_timeout_secs,
            upstream_transport_config,
            upstream_transport_profile,
            upstream_installer: upstream_installer.clone(),
            // Not carried, as on the listener above and for the same
            // reason. A spec set on a proxy template reaches no session.
            #[cfg(feature = "qlog")]
            upstream_qlog: None,
            // Every session this proxy accepts gets a clone of the *same*
            // socket, and each builds its own upstream endpoint over it.
            // Two endpoints reading one socket take each other's
            // datagrams, so a socket set here is only sound for a proxy
            // handling one client connection at a time — a capture or
            // impairment harness, not a fan-out deployment. A caller
            // wanting one socket per session drives `ProxySession`
            // directly, which is where the seam is.
            upstream_socket: upstream_socket.clone(),
            egress: *egress,
            // Cloned, not moved: this builds one config *per accepted
            // connection* from a template the proxy keeps. `ShapeProfile`
            // is not `Copy` either — it owns its bucket and class vectors
            // — so the clone is explicit here exactly as
            // `upstream_ca_certs`' is above.
            //
            // A profile installed through the control plane wins over the
            // template, and it wins for good: once set, every session
            // accepted afterwards shapes with it, including on a proxy whose
            // template had no profile at all. That is what makes
            // `set_shape` reach a proxy uniformly rather than only the
            // sessions that happened to be running when it was called.
            shape: self.control.shape().snapshot().1.or_else(|| shape.clone()),
        }
    }
}

impl LegSetup {
    /// What the control plane needs to know about the two legs, read off the
    /// configuration the proxy is being built with.
    ///
    /// The installers are shared rather than copied, so a live
    /// [`TransportProfile`](crate::transport::TransportProfile) is built by
    /// the same installer a configured one would have been.
    fn from_config(config: &ProxyConfig) -> Self {
        Self {
            client_installer: config.listener.installer.clone(),
            upstream_installer: config.session.upstream_installer.clone(),
            // Read once, here, because it cannot change: the upstream
            // transport is a field of the template and no request replaces
            // it. A WebTransport upstream builds its endpoint inside the
            // WebTransport library, which takes no `quinn::TransportConfig`
            // and returns no endpoint to install one on, so a transport
            // profile aimed at that leg has nowhere to go.
            upstream_webtransport: matches!(
                config.session.upstream_transport,
                UpstreamTransportType::WebTransport { .. }
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use moqtap_codec::version::DraftVersion;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::action::EgressConfig;
    use crate::observer::NoOpProxyObserver;
    use crate::session::UpstreamTransportType;
    use crate::shape::{BucketConfig, ClassRule, Discipline, QueueConfig, ShapeProfile};
    use crate::transport::{TransportInstaller, TransportProfile, TransportProfileError};

    /// An installer the copy tests only ever compare by address.
    struct MarkerInstaller;

    impl TransportInstaller for MarkerInstaller {
        fn build(
            &self,
            profile: &TransportProfile,
        ) -> Result<quinn::TransportConfig, TransportProfileError> {
            profile.into_config()
        }
    }

    fn marker_profile(initial_mtu: u16) -> TransportProfile {
        TransportProfile { initial_mtu: Some(initial_mtu), ..Default::default() }
    }

    /// A socket to hand the session template, so the field being carried is
    /// checkable by address rather than by "both are `None`".
    fn abstract_socket() -> Arc<dyn quinn::AsyncUdpSocket> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("an ephemeral port");
        quinn::default_runtime()
            .expect("these tests run under tokio")
            .wrap_udp_socket(socket)
            .expect("wrap the socket")
    }

    /// A template in which **no carryable field holds its default**.
    ///
    /// That is the whole design of these two tests. A copy that dropped a
    /// field would leave the copy holding a default, and a template built
    /// from defaults could not tell the two apart — every assertion would
    /// pass against a copy that carried nothing at all. So every field
    /// below is set to something the corresponding `Default` is not.
    ///
    /// The two qlog specs are the exception, and they are marked where they
    /// are set: a spec cannot be copied by anything, so there is no version
    /// of this fixture in which the copy carrying it is the correct
    /// behaviour to check for.
    fn distinctive_config(socket: Arc<dyn quinn::AsyncUdpSocket>) -> ProxyConfig {
        let egress = EgressConfig {
            max_pending_bytes: 12_345,
            max_hold: Duration::from_secs(7),
            ..Default::default()
        };

        ProxyConfig {
            listener: ListenerConfig {
                bind_addr: "127.0.0.1:4443".parse().expect("a literal address"),
                cert_chain: vec![CertificateDer::from(vec![1u8; 10])],
                key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![2u8; 10])),
                // Not both at once — the two are mutually exclusive on a
                // leg — so the raw config is the upstream template's and
                // the profile is this one's, and each is carried by only
                // one of the two copies.
                transport_config: None,
                transport_profile: Some(marker_profile(1350)),
                installer: Some(Arc::new(MarkerInstaller)),
                // The one field left at its default, because a spec cannot
                // be carried by a copy at all — it owns a writer, has no
                // `Clone`, and is consumed when it becomes a sink. Setting
                // one here would make the fixture describe a template whose
                // copy is *documented* to drop it, which is a fact about
                // the type rather than a copy worth checking.
                #[cfg(feature = "qlog")]
                qlog: None,
            },
            session: ProxySessionConfig {
                draft: DraftVersion::Draft19,
                upstream_transport: UpstreamTransportType::WebTransport {
                    url: "https://relay.invalid:4443/moq".to_string(),
                },
                upstream_addr: "relay.invalid:4443".to_string(),
                skip_upstream_cert_verify: true,
                upstream_ca_certs: vec![vec![3u8; 4]],
                upstream_connect_timeout_secs: 11,
                upstream_transport_config: Some(Arc::new(quinn::TransportConfig::default())),
                upstream_transport_profile: None,
                upstream_installer: Some(Arc::new(MarkerInstaller)),
                // Left at its default for the reason given on the listener
                // half above.
                #[cfg(feature = "qlog")]
                upstream_qlog: None,
                upstream_socket: Some(socket),
                egress,
                // One bucket and one class naming it, which is the smallest
                // profile there is: an empty one is `ShapeError::NoClasses`,
                // because a profile with no classes shapes nothing. The
                // names are distinctive for the same reason every other
                // field here is — a copy that dropped this would otherwise
                // be indistinguishable from one that carried it.
                shape: Some(
                    ShapeProfile::try_new(
                        vec![BucketConfig { name: "marker".to_string(), ..Default::default() }],
                        vec![ClassRule {
                            name: "marker class".to_string(),
                            bucket: "marker".to_string(),
                            ..Default::default()
                        }],
                        QueueConfig::default(),
                        Discipline::Fifo,
                    )
                    .expect("one class naming its own bucket is a valid profile"),
                ),
            },
        }
    }

    fn proxy(config: ProxyConfig) -> TransparentProxy {
        TransparentProxy::new(config, Arc::new(NoOpProxyObserver))
    }

    /// The listener template survives the copy `run` makes of it.
    ///
    /// A field this copy drops is not a compile error and not a test
    /// failure anywhere else in the crate: the caller sets it, the proxy
    /// binds, and the setting reaches nothing. The destructuring pattern in
    /// `listener_config` is the first line of defence and this is the
    /// second — it fails if a field is named in the pattern and then
    /// written from the wrong place, which the compiler cannot see.
    #[tokio::test]
    async fn the_listener_copy_carries_every_field() {
        let template = distinctive_config(abstract_socket());
        let expected_installer =
            Arc::clone(template.listener.installer.as_ref().expect("set above"));
        let proxy = proxy(template);
        let copy = proxy.listener_config();
        let template = &proxy.config.listener;

        assert_eq!(copy.bind_addr, template.bind_addr);
        assert_eq!(copy.cert_chain, template.cert_chain);
        assert_eq!(
            copy.key_der.secret_der(),
            template.key_der.secret_der(),
            "`clone_key` rather than `clone`: the key is the one field that cannot be derived"
        );
        assert!(copy.transport_config.is_none(), "the template names no raw config");
        assert_eq!(copy.transport_profile, template.transport_profile);
        assert!(
            Arc::ptr_eq(copy.installer.as_ref().expect("carried"), &expected_installer),
            "the copy shares the caller's installer rather than substituting the default one"
        );
    }

    /// The session template survives the copy made per accepted
    /// connection.
    #[tokio::test]
    async fn the_session_copy_carries_every_field() {
        let template = distinctive_config(abstract_socket());
        let expected_installer =
            Arc::clone(template.session.upstream_installer.as_ref().expect("set above"));
        let expected_raw =
            Arc::clone(template.session.upstream_transport_config.as_ref().expect("set above"));
        let expected_socket =
            Arc::clone(template.session.upstream_socket.as_ref().expect("set above"));
        let proxy = proxy(template);
        let copy = proxy.session_config();
        let template = &proxy.config.session;

        assert_eq!(copy.draft, template.draft);
        assert_eq!(
            format!("{:?}", copy.upstream_transport),
            format!("{:?}", template.upstream_transport),
            "`UpstreamTransportType` has no `PartialEq`, so the comparison is its `Debug`"
        );
        assert_eq!(copy.upstream_addr, template.upstream_addr);
        assert_eq!(copy.skip_upstream_cert_verify, template.skip_upstream_cert_verify);
        assert_eq!(copy.upstream_ca_certs, template.upstream_ca_certs);
        assert_eq!(copy.upstream_connect_timeout_secs, template.upstream_connect_timeout_secs);
        assert!(Arc::ptr_eq(
            copy.upstream_transport_config.as_ref().expect("carried"),
            &expected_raw
        ));
        assert!(copy.upstream_transport_profile.is_none(), "the template names no profile");
        assert!(
            Arc::ptr_eq(copy.upstream_installer.as_ref().expect("carried"), &expected_installer),
            "the copy shares the caller's installer rather than substituting the default one"
        );
        assert!(
            Arc::ptr_eq(copy.upstream_socket.as_ref().expect("carried"), &expected_socket),
            "a dropped socket is the loudest of these failures: every impairment armed on it \
             would be applied to nothing and the run would look clean"
        );
        assert_eq!(copy.egress, template.egress);
        assert_eq!(copy.shape, template.shape);
    }

    /// The mutually exclusive halves of the two templates, swapped.
    ///
    /// The pair above sets the profile on one leg and the raw config on the
    /// other, so between them every one of the four fields is checked —
    /// but only in one arrangement each. This runs the other arrangement,
    /// so neither copy can be carrying a field by reading it off the wrong
    /// leg.
    #[tokio::test]
    async fn the_copies_carry_the_other_arrangement_too() {
        let mut template = distinctive_config(abstract_socket());
        template.listener.transport_profile = None;
        template.listener.transport_config = Some(Arc::new(quinn::TransportConfig::default()));
        template.session.upstream_transport_config = None;
        template.session.upstream_transport_profile = Some(marker_profile(1400));

        let expected_raw =
            Arc::clone(template.listener.transport_config.as_ref().expect("set above"));
        let proxy = proxy(template);

        let listener = proxy.listener_config();
        assert!(
            Arc::ptr_eq(listener.transport_config.as_ref().expect("carried"), &expected_raw),
            "the client leg's raw config has to reach the listener unmodified"
        );
        assert!(listener.transport_profile.is_none());

        let session = proxy.session_config();
        assert_eq!(session.upstream_transport_profile, Some(marker_profile(1400)));
        assert!(session.upstream_transport_config.is_none());
    }
}

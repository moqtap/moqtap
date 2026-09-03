//! `quinn::TransportConfig` plumbing — the L1 seam.
//!
//! `ListenerConfig::transport_config` and
//! `ProxySessionConfig::upstream_transport_config` are `Option`s whose
//! `Some` branch is easy to drop on the floor: nothing about the code
//! stops compiling if the field is never read. These tests make the
//! setting *observable on the wire* so that dropping it fails.
//!
//! The observable used is datagram support. `TransportConfig::
//! datagram_receive_buffer_size(None)` stops the endpoint advertising
//! `max_datagram_frame_size`, and the peer then reports
//! `Connection::max_datagram_size() == None`. It is a transport
//! parameter, so it can only have come from the `TransportConfig` the
//! configuration under test carried through.
//!
//! # Why the file is gated on there being a draft at all
//!
//! Nothing here parses a MoQT frame — the session below is a byte pump that
//! never gets past its relay handshake — but a session refuses to start on a
//! draft this build did not compile, so a fixture has to name one the build
//! has. [`DRAFT`] is that draft and the gate is what guarantees there is one.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

mod common;

use std::sync::Arc;

use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::listener::{AcceptedConn, Listener, ListenerConfig};
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::session::{ProxySession, ProxySessionConfig, UpstreamTransportType};
use moqtap_proxy::transport::{TransportInstaller, TransportProfile, TransportProfileError};

use moqtap_codec::version::DraftVersion;
use tokio_util::sync::CancellationToken;

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The drafts this build compiled, draft-14 first.
///
/// Order rather than a plain list: the session below never frames anything,
/// so any compiled draft serves, and putting 14 first keeps the default
/// all-drafts build on the draft this file has always used. A reduced build
/// takes whichever one it has instead of failing on a draft it does not.
const CANDIDATE_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The draft the session fixture is configured for. The file-level gate is
/// what makes this index a compile-time fact rather than a panic.
const DRAFT: DraftVersion = CANDIDATE_DRAFTS[0];

/// A transport config that is distinguishable from quinn's defaults by
/// looking at the peer's connection.
fn datagrams_disabled() -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    cfg.datagram_receive_buffer_size(None);
    Arc::new(cfg)
}

fn listener_config(transport_config: Option<Arc<quinn::TransportConfig>>) -> ListenerConfig {
    let (cert_chain, key_der) = common::self_signed_localhost();
    ListenerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        cert_chain,
        key_der,
        transport_config,
        transport_profile: None,
        installer: None,
        #[cfg(feature = "qlog")]
        qlog: None,
    }
}

/// Bind a listener, connect one client to it, and report whether the
/// client sees the listener advertising datagram support.
async fn client_sees_datagrams(transport_config: Option<Arc<quinn::TransportConfig>>) -> bool {
    client_sees_datagrams_for(listener_config(transport_config)).await
}

/// The same question asked of a listener configured any other way.
///
/// Split out so a leg carrying a profile, an installer and a capture spec
/// can be measured with the observable this file already trusts, rather than
/// by reading a `quinn::TransportConfig` back — which cannot be done and
/// would prove only that a setter stored what it was given.
async fn client_sees_datagrams_for(config: ListenerConfig) -> bool {
    common::init_crypto();

    let listener = Listener::bind(config).expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accept = tokio::spawn(async move {
        match listener.accept().await.expect("accept") {
            AcceptedConn::Quic { conn, .. } => conn,
            #[cfg(feature = "webtransport")]
            _ => panic!("expected a raw-QUIC client"),
        }
    });

    let client_ep = common::client_endpoint(&[b"moq-00"]);
    let client_conn =
        client_ep.connect(addr, "localhost").expect("connect").await.expect("client handshake");

    let server_conn = tokio::time::timeout(TIMEOUT, accept).await.expect("accept task").unwrap();

    let seen = client_conn.max_datagram_size().is_some();
    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
    seen
}

#[tokio::test]
async fn listener_without_a_transport_config_keeps_quinn_defaults() {
    assert!(
        client_sees_datagrams(None).await,
        "quinn's default TransportConfig enables datagrams — this is the control for the next test"
    );
}

#[tokio::test]
async fn listener_applies_the_supplied_transport_config() {
    assert!(
        !client_sees_datagrams(Some(datagrams_disabled())).await,
        "ListenerConfig::transport_config was not applied: the client still sees the default \
         datagram support, so the Some branch in Listener::bind is being skipped"
    );
}

/// An installer that starts from a base of its own — one with datagrams
/// switched off — and applies the caller's profile over it.
///
/// The base is the whole reason the trait exists: a caller who has a
/// `quinn::TransportConfig` they built themselves and a `TransportProfile`
/// cannot have both any other way, because that type can be neither cloned
/// nor read back. Switching datagrams off in the base and leaving
/// `TransportProfile::datagram_receive_buffer` unset is what makes "the base
/// survived" answerable from the peer's side of a real connection.
struct DatagramlessInstaller;

impl TransportInstaller for DatagramlessInstaller {
    fn build(
        &self,
        profile: &TransportProfile,
    ) -> Result<quinn::TransportConfig, TransportProfileError> {
        let mut base = quinn::TransportConfig::default();
        base.datagram_receive_buffer_size(None);
        profile.apply_to(&mut base)?;
        Ok(base)
    }
}

/// A profile that says nothing about datagrams, so what the peer sees is
/// the installer's base rather than the profile's opinion.
fn mtu_only_profile() -> TransportProfile {
    let mut profile = TransportProfile::default();
    profile.initial_mtu = Some(1350);
    profile
}

#[tokio::test]
async fn listener_builds_a_profile_through_the_supplied_installer() {
    let mut config = listener_config(None);
    config.transport_profile = Some(mtu_only_profile());
    config.installer = Some(Arc::new(DatagramlessInstaller));

    assert!(
        !client_sees_datagrams_for(config).await,
        "ListenerConfig::installer was not consulted: the client still sees quinn's default \
         datagram support, so the leg is running on a base the caller never supplied"
    );
}

/// A leg carrying a profile, a capture spec **and** an installer runs on the
/// installer's base.
///
/// This is the combination in which the installer used to be skipped. The
/// reason was real — a sink is attached by mutating a
/// `quinn::TransportConfig`, and the trait used to hand back an `Arc` there
/// is no way to mutate — but the consequence was this crate's cardinal
/// failure: a caller sets an installer, sets a capture beside it, and the
/// installer is never called, with nothing anywhere saying so. `build` now
/// returns the config by value, so the base is the installer's and the sink
/// goes on top of it.
///
/// Both halves are asserted, because either alone would pass against the
/// wrong code. Datagram support is off, which is the installer's base
/// reaching the wire; and the capture holds bytes, which is the sink
/// reaching the same config. A run with the spec silently dropped would
/// satisfy the first and not the second.
///
/// *Ablation, run:* restore the old profile-and-spec arm of
/// `transport::resolve` — build the config with `profile.into_config()` and
/// ignore `installer`. This row reddens with
///
/// ```text
/// thread 'a_leg_with_a_profile_a_spec_and_an_installer_runs_on_the_installers_base'
/// (62076) panicked at crates\moqtap-proxy\tests\transport_config.rs:210:5:
/// the installer was skipped because a capture was asked for beside it: the leg
/// is running on quinn's defaults and reporting success
/// ```
#[cfg(feature = "qlog")]
#[tokio::test]
async fn a_leg_with_a_profile_a_spec_and_an_installer_runs_on_the_installers_base() {
    /// Everything written to it, readable while the sink is alive.
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
    let mut spec = moqtap_proxy::qlog::QlogSpec::default();
    spec.writer = Some(Box::new(Captured(Arc::clone(&sink))));
    spec.title = Some("client leg".to_string());

    let mut config = listener_config(None);
    config.transport_profile = Some(mtu_only_profile());
    config.installer = Some(Arc::new(DatagramlessInstaller));
    config.qlog = Some(spec);

    let seen = client_sees_datagrams_for(config).await;
    assert!(
        !seen,
        "the installer was skipped because a capture was asked for beside it: the leg is running \
         on quinn's defaults and reporting success"
    );
    assert!(
        !sink.lock().expect("uncontended").is_empty(),
        "and the sink has to be on the config the installer built — an empty writer means the \
         capture was attached to something else, or to nothing"
    );
}

/// Run one proxy session against a fake upstream and report whether the
/// upstream sees the proxy advertising datagram support. That is a
/// property of the *client* config the session builds, i.e. of
/// `upstream_transport_config`.
async fn upstream_sees_datagrams(
    upstream_transport_config: Option<Arc<quinn::TransportConfig>>,
) -> bool {
    common::init_crypto();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");
        let seen = conn.max_datagram_size().is_some();
        conn.close(0u32.into(), b"done");
        seen
    });

    let (proxy_front_ep, proxy_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let cancel = CancellationToken::new();
    let proxy_cancel = cancel.clone();
    let proxy_task = tokio::spawn(async move {
        let incoming = proxy_front_ep.accept().await.expect("proxy accept");
        let client_conn = incoming.await.expect("proxy tls");

        let session = ProxySession::new(
            SessionId(1),
            ProxySessionConfig {
                draft: DRAFT,
                upstream_transport: UpstreamTransportType::Quic,
                upstream_addr: upstream_addr.to_string(),
                skip_upstream_cert_verify: true,
                upstream_ca_certs: Vec::new(),
                upstream_connect_timeout_secs: 5,
                upstream_transport_config,
                upstream_socket: None,
                egress: Default::default(),
                shape: None,
                upstream_transport_profile: None,
                upstream_installer: None,
                #[cfg(feature = "qlog")]
                upstream_qlog: None,
            },
            b"moq-00".to_vec(),
            Arc::new(NoOpProxyObserver),
            Arc::new(NoOpHook),
            proxy_cancel,
        );
        let _ = session.run(client_conn).await;
    });

    let client_ep = common::client_endpoint(&[b"moq-00"]);
    let client_conn = client_ep
        .connect(proxy_addr, "localhost")
        .expect("client connect")
        .await
        .expect("client handshake");

    let seen = tokio::time::timeout(TIMEOUT, upstream_task)
        .await
        .expect("upstream connection established")
        .expect("upstream task");

    client_conn.close(0u32.into(), b"done");
    cancel.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_task).await;
    seen
}

#[tokio::test]
async fn upstream_without_a_transport_config_keeps_quinn_defaults() {
    assert!(
        upstream_sees_datagrams(None).await,
        "control: with no upstream_transport_config the relay sees quinn's defaults"
    );
}

#[tokio::test]
async fn session_applies_the_upstream_transport_config() {
    assert!(
        !upstream_sees_datagrams(Some(datagrams_disabled())).await,
        "ProxySessionConfig::upstream_transport_config was not applied to the relay connection, \
         so the Some branch in connect_upstream_quic is being skipped"
    );
}

//! `TransparentProxy` with a router: the WebTransport request is answered
//! only after the relay is dialled, protocols and certificate pins travel
//! with it, and both legs keep an idle session alive.

#![cfg(feature = "webtransport")]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_codec::version::DraftVersion;
use moqtap_proxy::listener::{ListenerConfig, Rejection};
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::proxy::{ProxyConfig, RouteClient, RouteRequest, TransparentProxy};
use moqtap_proxy::session::{ProxySessionConfig, UpstreamTransportType};
use moqtap_proxy::transport::TransportProfile;
use tokio::task::JoinHandle;

const TIMEOUT: Duration = Duration::from_secs(10);
const PAYLOAD: &[u8] = b"through the routed session";

// ── the relay ──────────────────────────────────────────────────────────

/// What the relay saw of the request it was sent.
#[derive(Debug, Clone, Default)]
struct Seen {
    path: String,
    offer: Option<String>,
}

/// A WebTransport relay that answers every request, optionally naming a
/// protocol, and hands over each session.
struct Relay {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    sessions: tokio::sync::mpsc::UnboundedReceiver<wtransport::Connection>,
    _task: JoinHandle<()>,
}

fn identity(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> wtransport::Identity {
    let cert = chain.into_iter().next().expect("one cert");
    wtransport::Identity::new(
        wtransport::tls::CertificateChain::single(
            wtransport::tls::Certificate::from_der(cert.to_vec()).expect("DER"),
        ),
        wtransport::tls::PrivateKey::from_der_pkcs8(key.secret_der().to_vec()),
    )
}

fn relay(
    identity: wtransport::Identity,
    answer: Option<&'static str>,
    idle: Option<Duration>,
) -> Relay {
    common::init_crypto();
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("literal");
    let mut builder =
        wtransport::ServerConfig::builder().with_bind_address(bind).with_identity(identity);
    if idle.is_some() {
        builder = builder.max_idle_timeout(idle).expect("a valid idle timeout");
    }
    let config = builder.build();
    let endpoint = wtransport::Endpoint::server(config).expect("bind the relay");
    let addr = endpoint.local_addr().expect("local_addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (tx, sessions) = tokio::sync::mpsc::unbounded_channel();
    let record = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        loop {
            let incoming = endpoint.accept().await;
            let Ok(request) = incoming.await else { continue };
            record.lock().expect("uncontended").push(Seen {
                path: request.path().to_string(),
                offer: request.headers().get("wt-available-protocols").cloned(),
            });
            let accepted = match answer {
                Some(p) => request.accept_with_headers([("wt-protocol", p)]).await,
                None => request.accept().await,
            };
            if let Ok(conn) = accepted {
                let _ = tx.send(conn);
            }
        }
    });
    Relay { addr, seen, sessions, _task: task }
}

// ── the proxy ──────────────────────────────────────────────────────────

/// Serves `/to/<port>` by routing to `https://127.0.0.1:<port>/moq`, and
/// refuses every other path.
fn route_by_path(
    request: &RouteRequest<'_>,
    mut config: ProxySessionConfig,
) -> Result<ProxySessionConfig, Rejection> {
    let RouteClient::WebTransport { path, .. } = request.client else {
        return Err(Rejection::Forbidden);
    };
    let port: u16 =
        path.strip_prefix("/to/").and_then(|p| p.parse().ok()).ok_or(Rejection::Forbidden)?;
    config.upstream_transport =
        UpstreamTransportType::WebTransport { url: format!("https://127.0.0.1:{port}/moq") };
    Ok(config)
}

struct Proxy {
    addr: SocketAddr,
    proxy: Arc<TransparentProxy>,
    _task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.proxy.cancel_token().cancel();
    }
}

async fn start_proxy(
    session: ProxySessionConfig,
    client_profile: Option<TransportProfile>,
    router: Arc<dyn moqtap_proxy::proxy::Router>,
    observer: Arc<dyn ProxyObserver>,
) -> Proxy {
    common::init_crypto();
    let (cert_chain, key_der) = common::self_signed_localhost();
    let config = ProxyConfig {
        listener: ListenerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("literal"),
            cert_chain,
            key_der,
            transport_config: None,
            transport_profile: client_profile,
            installer: None,
            #[cfg(feature = "qlog")]
            qlog: None,
        },
        session,
    };
    let mut proxy = TransparentProxy::new(config, observer);
    proxy.set_router(router);
    let proxy = Arc::new(proxy);
    let control = proxy.control();
    let running = Arc::clone(&proxy);
    let task = tokio::spawn(async move {
        let _ = running.run().await;
    });
    let start = tokio::time::Instant::now();
    let addr = loop {
        if let Ok(addr) = control.local_addr() {
            break addr;
        }
        assert!(start.elapsed() < TIMEOUT, "the proxy never bound");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    Proxy { addr, proxy, _task: task }
}

fn session_template() -> ProxySessionConfig {
    ProxySessionConfig {
        draft: DraftVersion::Draft14,
        upstream_transport: UpstreamTransportType::WebTransport {
            url: "https://127.0.0.1:1/unset".to_string(),
        },
        skip_upstream_cert_verify: true,
        upstream_connect_timeout_secs: 3,
        ..Default::default()
    }
}

// ── the client ─────────────────────────────────────────────────────────

fn client(
    idle: Option<Duration>,
) -> wtransport::Endpoint<wtransport::endpoint::endpoint_side::Client> {
    let mut builder =
        wtransport::ClientConfig::builder().with_bind_default().with_no_cert_validation();
    if idle.is_some() {
        builder = builder.max_idle_timeout(idle).expect("a valid idle timeout");
    }
    let config = builder.build();
    wtransport::Endpoint::client(config).expect("client endpoint")
}

async fn connect(
    endpoint: &wtransport::Endpoint<wtransport::endpoint::endpoint_side::Client>,
    url: String,
    offer: Option<&str>,
) -> Result<wtransport::Connection, wtransport::error::ConnectingError> {
    let request = wtransport::endpoint::ConnectOptions::builder(url);
    let request = match offer {
        Some(offer) => request.add_header("wt-available-protocols", offer),
        None => request,
    };
    tokio::time::timeout(TIMEOUT, endpoint.connect(request.build()))
        .await
        .expect("the client's connect finished")
}

fn rejected_with(
    result: Result<wtransport::Connection, wtransport::error::ConnectingError>,
) -> Option<u16> {
    match result {
        Err(wtransport::error::ConnectingError::SessionRejected { status, .. }) => status,
        Err(e) => panic!("refused some other way: {e}"),
        Ok(_) => panic!("the session was accepted"),
    }
}

async fn send_uni(conn: &wtransport::Connection, payload: &[u8]) {
    let mut send = conn.open_uni().await.expect("open_uni").await.expect("opened");
    send.write_all(payload).await.expect("write_all");
    send.finish().await.expect("finish");
}

async fn read_uni(conn: &wtransport::Connection) -> Vec<u8> {
    let mut recv = tokio::time::timeout(TIMEOUT, conn.accept_uni())
        .await
        .expect("a stream arrived")
        .expect("accept_uni");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Some(n) = recv.read(&mut buf).await.expect("read") {
        got.extend_from_slice(&buf[..n]);
    }
    got
}

async fn next_session(relay: &mut Relay) -> wtransport::Connection {
    tokio::time::timeout(TIMEOUT, relay.sessions.recv())
        .await
        .expect("the relay got a session")
        .expect("relay task alive")
}

// ── routing ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_router_picks_the_upstream_from_the_path_and_refuses_the_rest() {
    let (chain, key) = common::self_signed_localhost();
    let mut relay = relay(identity(chain, key), None, None);

    let asked: Arc<Mutex<Vec<(String, String, SocketAddr)>>> = Arc::default();
    let record = Arc::clone(&asked);
    let router = move |request: &RouteRequest<'_>, config: ProxySessionConfig| {
        if let RouteClient::WebTransport { authority, path, .. } = request.client {
            record.lock().expect("uncontended").push((
                authority.to_string(),
                path.to_string(),
                request.remote_address,
            ));
        }
        route_by_path(request, config)
    };
    let proxy =
        start_proxy(session_template(), None, Arc::new(router), Arc::new(NoOpProxyObserver)).await;
    let endpoint = client(None);

    let conn = connect(&endpoint, format!("https://{}/to/{}", proxy.addr, relay.addr.port()), None)
        .await
        .expect("a routed path is served");
    let upstream = next_session(&mut relay).await;
    send_uni(&conn, PAYLOAD).await;
    assert_eq!(read_uni(&upstream).await, PAYLOAD);
    assert_eq!(relay.seen.lock().expect("uncontended")[0].path, "/moq", "the router's URL");

    let refused = connect(&endpoint, format!("https://{}/elsewhere", proxy.addr), None).await;
    assert_eq!(rejected_with(refused), Some(403));

    let asked = asked.lock().expect("uncontended").clone();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[0].0, proxy.addr.to_string());
    assert_eq!(asked[0].1, format!("/to/{}", relay.addr.port()));
    assert_eq!(asked[1].1, "/elsewhere");
}

#[tokio::test]
async fn a_client_refused_at_its_first_packet_leaves_the_proxy_accepting() {
    let (chain, key) = common::self_signed_localhost();
    let mut relay = relay(identity(chain, key), None, None);
    let proxy =
        start_proxy(session_template(), None, Arc::new(route_by_path), Arc::new(NoOpProxyObserver))
            .await;

    let stray = common::client_endpoint(&[b"not-a-protocol"]);
    let refused = tokio::time::timeout(
        TIMEOUT,
        stray.connect(proxy.addr, "localhost").expect("connect starts"),
    )
    .await
    .expect("the stray client finished");
    assert!(refused.is_err(), "an unknown ALPN is refused");

    let conn =
        connect(&client(None), format!("https://{}/to/{}", proxy.addr, relay.addr.port()), None)
            .await
            .expect("the next client is served");
    let upstream = next_session(&mut relay).await;
    send_uni(&conn, PAYLOAD).await;
    assert_eq!(read_uni(&upstream).await, PAYLOAD);
}

#[tokio::test]
async fn an_unreachable_relay_refuses_the_client_with_404() {
    let closed = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = closed.local_addr().expect("addr").port();
    drop(closed);
    let proxy =
        start_proxy(session_template(), None, Arc::new(route_by_path), Arc::new(NoOpProxyObserver))
            .await;

    let refused = connect(&client(None), format!("https://{}/to/{port}", proxy.addr), None).await;
    assert_eq!(rejected_with(refused), Some(404));
}

// ── protocols ──────────────────────────────────────────────────────────

/// The client's offer reaches the relay byte for byte, the relay's answer
/// reaches the client, and the session frames with the draft it names.
#[cfg(feature = "wt-protocol")]
#[tokio::test]
async fn protocols_are_copied_both_ways_and_name_the_draft() {
    use moqtap_proxy::event::ImpairmentKind;

    let (chain, key) = common::self_signed_localhost();
    let mut relay = relay(identity(chain, key), Some("\"moqt-16\""), None);
    let observer = Arc::new(common::RecordingObserver::new());
    let proxy =
        start_proxy(session_template(), None, Arc::new(route_by_path), observer.clone()).await;

    let offer = "\"moqt-16\", \"moqt-15\"";
    let conn = connect(
        &client(None),
        format!("https://{}/to/{}", proxy.addr, relay.addr.port()),
        Some(offer),
    )
    .await
    .expect("accepted");
    let _upstream = next_session(&mut relay).await;

    assert_eq!(relay.seen.lock().expect("uncontended")[0].offer.as_deref(), Some(offer));
    let answer = conn.connect_response().and_then(|r| r.get("wt-protocol")).map(str::to_owned);
    assert_eq!(answer.as_deref(), Some("\"moqt-16\""));

    // A stream the framer cannot read is reported with the draft it was read
    // as: the relay's choice, not the template's draft-14.
    send_uni(&conn, &[0x3f, 0x3f, 0x3f, 0x3f]).await;
    let start = tokio::time::Instant::now();
    let draft = loop {
        let found = observer.impairments().into_iter().find_map(|k| match k {
            ImpairmentKind::FramerBypass { draft, .. } => Some(draft),
            _ => None,
        });
        if let Some(draft) = found {
            break draft;
        }
        assert!(start.elapsed() < TIMEOUT, "no bypass reported: {:?}", observer.events());
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(draft, DraftVersion::Draft16);
}

/// Without the protocol feature nothing is offered upstream and nothing is
/// answered.
#[cfg(not(feature = "wt-protocol"))]
#[tokio::test]
async fn without_the_protocol_feature_no_offer_is_passed_on() {
    let (chain, key) = common::self_signed_localhost();
    let mut relay = relay(identity(chain, key), None, None);
    let proxy =
        start_proxy(session_template(), None, Arc::new(route_by_path), Arc::new(NoOpProxyObserver))
            .await;
    let _conn = connect(
        &client(None),
        format!("https://{}/to/{}", proxy.addr, relay.addr.port()),
        Some("\"moqt-16\""),
    )
    .await
    .expect("accepted");
    let _upstream = next_session(&mut relay).await;
    assert_eq!(relay.seen.lock().expect("uncontended")[0].offer, None);
}

// ── certificate pins ───────────────────────────────────────────────────

/// A certificate a browser would accept by hash: ECDSA P-256, valid for
/// under two weeks.
fn short_lived() -> (wtransport::Identity, [u8; 32]) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(10);
    let cert = params.self_signed(&key).expect("self-sign");
    let der = cert.der().to_vec();
    let hash: [u8; 32] =
        ring::digest::digest(&ring::digest::SHA256, &der).as_ref().try_into().expect("32 bytes");
    let identity = identity(
        vec![rustls::pki_types::CertificateDer::from(der)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )),
    );
    (identity, hash)
}

#[tokio::test]
async fn a_pinned_relay_is_reached_with_verification_on() {
    let (identity, hash) = short_lived();
    let mut relay = relay(identity, None, None);
    let mut template = session_template();
    template.skip_upstream_cert_verify = false;
    template.upstream_server_certificate_hashes = vec![hash];
    let proxy =
        start_proxy(template, None, Arc::new(route_by_path), Arc::new(NoOpProxyObserver)).await;

    let conn =
        connect(&client(None), format!("https://{}/to/{}", proxy.addr, relay.addr.port()), None)
            .await
            .expect("the pin matches");
    let upstream = next_session(&mut relay).await;
    send_uni(&conn, PAYLOAD).await;
    assert_eq!(read_uni(&upstream).await, PAYLOAD);
}

#[tokio::test]
async fn a_relay_that_does_not_match_its_pin_is_refused() {
    let (identity, mut hash) = short_lived();
    hash[0] ^= 1;
    let relay = relay(identity, None, None);
    let mut template = session_template();
    template.skip_upstream_cert_verify = false;
    template.upstream_server_certificate_hashes = vec![hash];
    let proxy =
        start_proxy(template, None, Arc::new(route_by_path), Arc::new(NoOpProxyObserver)).await;

    let refused =
        connect(&client(None), format!("https://{}/to/{}", proxy.addr, relay.addr.port()), None)
            .await;
    assert_eq!(rejected_with(refused), Some(404));
    assert!(relay.seen.lock().expect("uncontended").is_empty(), "no request reached the relay");
}

// ── keep-alive ─────────────────────────────────────────────────────────

const IDLE: Duration = Duration::from_secs(2);

/// Whether a session left silent for `quiet` still carries a stream from the
/// relay to the client. Neither the client nor the relay sends keep-alives;
/// `relay_idle` and `client_idle` are their idle timeouts, and `profile` is
/// set on both proxy legs.
async fn survives_idle(
    relay_idle: Option<Duration>,
    client_idle: Option<Duration>,
    profile: Option<TransportProfile>,
    quiet: Duration,
) -> bool {
    let (chain, key) = common::self_signed_localhost();
    let mut relay = relay(identity(chain, key), None, relay_idle);
    let mut template = session_template();
    template.upstream_transport_profile = profile.clone();
    let proxy =
        start_proxy(template, profile, Arc::new(route_by_path), Arc::new(NoOpProxyObserver)).await;

    let conn = connect(
        &client(client_idle),
        format!("https://{}/to/{}", proxy.addr, relay.addr.port()),
        None,
    )
    .await
    .expect("accepted");
    let upstream = next_session(&mut relay).await;

    tokio::time::sleep(quiet).await;

    let Ok(send) = upstream.open_uni().await else { return false };
    let Ok(mut send) = send.await else { return false };
    if send.write_all(PAYLOAD).await.is_err() || send.finish().await.is_err() {
        return false;
    }
    let received = tokio::time::timeout(Duration::from_secs(3), conn.accept_uni()).await;
    let Ok(Ok(mut recv)) = received else { return false };
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    while let Ok(Some(n)) = recv.read(&mut buf).await {
        got.extend_from_slice(&buf[..n]);
    }
    got == PAYLOAD
}

/// Every endpoint times out after [`IDLE`]; the session stays up across three
/// idle timeouts. `keep_alive` overrides both proxy legs.
async fn idle_session(keep_alive: Option<Duration>) -> bool {
    let mut profile = TransportProfile::default();
    profile.max_idle_timeout = Some(IDLE);
    profile.keep_alive_interval = keep_alive;
    survives_idle(Some(IDLE), Some(IDLE), Some(profile), IDLE * 3).await
}

/// No transport profile on either leg, and a relay that times out after 8 s.
#[tokio::test]
async fn a_minute_long_silence_survives_on_unconfigured_legs() {
    let quiet = Duration::from_secs(60);
    assert!(
        survives_idle(Some(Duration::from_secs(8)), None, None, quiet).await,
        "the session died while idle"
    );
}

#[tokio::test]
async fn an_idle_session_survives_on_the_default_keep_alives() {
    assert!(idle_session(None).await, "the session died while idle");
}

#[tokio::test]
async fn without_keep_alives_the_same_idle_session_dies() {
    assert!(!idle_session(Some(Duration::ZERO)).await, "the control survived; it proves nothing");
}

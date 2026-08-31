//! The relay leg dialled as a **WebTransport** upstream, and the one
//! configuration that leg silently drops.
//!
//! `impair_e2e.rs::webtransport_ingress` covers the other direction: a real
//! `wtransport` client reaching this proxy's listener. Nothing in this
//! workspace stood a `wtransport::Endpoint::server` up, so nothing had ever
//! watched the proxy *dial* WebTransport — every WebTransport-upstream test
//! before this one pointed at a port that answered with raw QUIC or with
//! nothing at all, and asserted on the error that came back. This file
//! completes the session against a server that speaks the protocol, and
//! compares the forwarded payload byte for byte at the far end.
//!
//! # Why the fixture exists, which is not the handshake
//!
//! `ProxySessionConfig` carries two things a WebTransport upstream cannot
//! take, and the proxy treats them differently on purpose:
//!
//! * `upstream_socket` is **refused** — [`ProxyError::UpstreamSocketUnsupported`],
//!   and no connection is attempted. `impair_e2e.rs` asserts that refusal
//!   and its rendered message.
//! * `upstream_transport_config` is **dropped**, in silence, and the session
//!   connects anyway.
//!
//! The asymmetry was argued rather than overlooked: a dropped transport
//! config yields a working connection whose windows the caller did not pick,
//! while a dropped socket yields a relay leg that bypasses the caller's
//! decorator entirely — every impairment armed on it reported and applied to
//! nothing, and a run that looks clean because it *is* clean.
//!
//! Nothing observed the second half of that argument. A transport config
//! handed to a WebTransport upstream disappears between
//! `ProxySessionConfig` and `wtransport::ClientConfig`, and no counter, no
//! event and no error says so. This file is where that silence is written
//! down, so that the day it stops being silent is a red test with an
//! explanation in it rather than a behaviour change nobody noticed.
//!
//! # Three worlds, and this file asserts the one that exists
//!
//! [`a_transport_config_on_a_webtransport_upstream_is_dropped`] runs a
//! session whose profile could not possibly have been applied unseen, and
//! sorts the result into one of three outcomes:
//!
//! | What happened | What it means |
//! |---|---|
//! | the session connected and the payload arrived | the config was dropped — today |
//! | the session refused to run | the config became a refusal, as the socket already is |
//! | the session connected and nothing arrived | the config was honoured |
//!
//! Only the first is asserted, because only the first exists. The other two
//! each fail with a message naming which world the reader has landed in and
//! what to do about it, because "assertion failed: delivered.is_some()" on a
//! deliberate behaviour change is a morning wasted.
//!
//! # The profile, and why it is a zero send window
//!
//! A dropped configuration is invisible by construction: the run that
//! ignores it and the run that honours a harmless setting look identical. So
//! the profile here sets exactly one field, `send_window = 0`, which stops
//! every byte of stream data the leg would carry while leaving the handshake
//! — CRYPTO frames, not stream data — untouched. A leg that honours it
//! connects and delivers nothing. That is a difference no amount of
//! bookkeeping can hide, and it needs no clock: the payload cannot arrive at
//! any speed.
//!
//! [`the_same_profile_stops_a_quic_upstream_dead`] is the other half of that
//! claim and the reason it is worth making. It runs the identical profile
//! against a raw-QUIC upstream, where `connect_upstream_quic` does install
//! it, and asserts the payload never arrives. Without it, the WebTransport
//! test above is green against a profile that was applied and did nothing,
//! and would keep being green if `send_window` stopped meaning anything.
//!
//! It is not a second copy of `transport_config.rs`, which already covers
//! the QUIC upstream's transport-config seam and covers it better, through a
//! transport parameter the peer can read back. That observable says the
//! config reached the endpoint; it cannot say anything about *this* profile,
//! whose one field is a send-side limit with nothing on the wire to look at.
//! The claim here is narrower and local: the value handed to the
//! WebTransport leg is a value that bites.

#![cfg(feature = "webtransport")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::version::DraftVersion;
use moqtap_proxy::error::ProxyError;
use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::session::{ProxySession, ProxySessionConfig, UpstreamTransportType};
use moqtap_proxy::transport::TransportProfile;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Bounds the two handshakes — client to proxy, proxy to upstream — and the
/// upstream's accept. Generous on purpose: no assertion here measures how
/// long anything took.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How long a run waits for the forwarded payload before concluding none is
/// coming.
///
/// Both answers are reached through this one window, and it is sized for the
/// answer that has to be *waited out*: a leg that honours a zero send window
/// cannot deliver at any speed, so the cost of the window is paid in full by
/// [`the_same_profile_stops_a_quic_upstream_dead`] on every run. Five
/// seconds for a loopback stream on an already-established connection is not
/// a measurement — it is several orders of magnitude of headroom — so a slow
/// machine makes this file slower and never flakier.
const DELIVERY_WINDOW: Duration = Duration::from_secs(5);

/// The upstream connect timeout every session here runs with.
const CONNECT_TIMEOUT_SECS: u64 = 5;

/// What the client sends through the proxy, to be read at the upstream. Its
/// arrival is what proves the *forwarded payload* — not just a handshake —
/// crossed the relay leg.
const PAYLOAD: &[u8] = b"a client stream forwarded to a WebTransport upstream";

/// The ALPN the client-facing leg speaks.
///
/// `DraftVersion::Draft14` matches it, and is otherwise inert: a `NoOpHook`
/// declares `Interest::NONE` and `NoOpProxyObserver` wants no events, so the
/// session forwards bytes without parsing a frame and no draft-specific code
/// runs. The payload below is therefore compared as bytes, not as objects.
const CLIENT_ALPN: &[u8] = b"moq-00";

/// A profile whose one setting cannot be applied without being seen.
///
/// `send_window` is quinn's cap on unacknowledged outgoing data across the
/// whole connection, and zero admits none: a leg that installs this
/// completes its handshake, because CRYPTO frames are not stream data, and
/// then carries no stream byte at all. Everything else is left `None`, so
/// this profile has no opinion about the other fifteen knobs and a run that
/// drops it drops exactly one thing.
fn zero_send_window() -> TransportProfile {
    // `#[non_exhaustive]` outside the defining crate: `default()` then field
    // assignment is the only construction path, and it is the one the type's
    // own rustdoc teaches.
    let mut profile = TransportProfile::default();
    profile.send_window = Some(0);
    profile
}

/// The config field's value for an optional profile.
fn transport_config(profile: Option<TransportProfile>) -> Option<Arc<quinn::TransportConfig>> {
    profile.map(|p| Arc::new(p.into_config().expect("the profile is valid")))
}

// ── the far ends ───────────────────────────────────────────────────────

/// A `wtransport` server standing in for a WebTransport relay, with its
/// accept already in flight.
struct WtUpstream {
    /// The address to build the session's URL from.
    addr: SocketAddr,
    /// The accept, spawned before the proxy dials.
    accept: JoinHandle<wtransport::Connection>,
    /// Owns the endpoint for the length of the run. Dropping it tears the
    /// server down, and `wtransport::Endpoint` is not `Clone`, so the accept
    /// task holds a second `Arc` rather than a copy.
    _endpoint: Arc<wtransport::Endpoint<wtransport::endpoint::endpoint_side::Server>>,
}

/// Bind a `wtransport` server on an ephemeral loopback port and start
/// accepting.
///
/// The accept is spawned here rather than awaited by the caller because
/// quinn does not progress an incoming handshake until the application
/// accepts it. A server that only accepted once the test asked it to would
/// make "the session never connected" true whether or not the proxy dialled.
///
/// The identity is the same fresh self-signed `localhost` pair every other
/// fixture in this crate uses, converted into `wtransport`'s own types
/// rather than generated by `Identity::self_signed` — that constructor is
/// behind a `wtransport` feature this workspace does not enable, and the
/// certificate is never verified anyway: the session sets
/// `skip_upstream_cert_verify`, which puts the proxy's WebTransport client
/// on `with_no_cert_validation()`.
fn wt_upstream() -> WtUpstream {
    common::init_crypto();

    let (cert_chain, key_der) = common::self_signed_localhost();
    let cert = cert_chain.into_iter().next().expect("one cert");
    let identity = wtransport::Identity::new(
        wtransport::tls::CertificateChain::single(
            wtransport::tls::Certificate::from_der(cert.to_vec()).expect("the cert parses as DER"),
        ),
        wtransport::tls::PrivateKey::from_der_pkcs8(key_der.secret_der().to_vec()),
    );

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("a literal address");
    let config =
        wtransport::ServerConfig::builder().with_bind_address(bind).with_identity(identity).build();

    let endpoint =
        Arc::new(wtransport::Endpoint::server(config).expect("bind the wtransport server"));
    let addr = endpoint.local_addr().expect("local_addr");

    let accepting = Arc::clone(&endpoint);
    let accept = tokio::spawn(async move {
        let incoming = accepting.accept().await;
        let request = incoming.await.expect("the proxy's WebTransport handshake reached a request");
        request.accept().await.expect("the WebTransport session request was accepted")
    });

    WtUpstream { addr, accept, _endpoint: endpoint }
}

/// Read the next unidirectional stream at a WebTransport upstream to its
/// FIN.
async fn read_wt_uni(conn: &wtransport::Connection) -> Vec<u8> {
    let mut recv = conn.accept_uni().await.expect("the upstream accepted a forwarded stream");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Some(n) = recv.read(&mut buf).await.expect("read") {
        got.extend_from_slice(&buf[..n]);
    }
    got
}

/// Read the next unidirectional stream at a raw-QUIC upstream to its FIN.
async fn read_quic_uni(conn: &quinn::Connection) -> Vec<u8> {
    let mut recv = conn.accept_uni().await.expect("the upstream accepted a forwarded stream");
    recv.read_to_end(64 * 1024).await.expect("read_to_end")
}

// ── the proxy under test ───────────────────────────────────────────────

/// A live client -> proxy topology with the session running, and everything
/// that has to outlive it.
struct Leg {
    /// The session, still running, and what it eventually returned.
    session: JoinHandle<Result<(), ProxyError>>,
    /// The client the session is serving.
    client: quinn::Connection,
    cancel: CancellationToken,
    /// Owns the client's endpoint for the length of the run.
    _client_endpoint: quinn::Endpoint,
    /// The proxy's front end, and the proxy's own handle on the client
    /// connection.
    ///
    /// Both are held out here rather than left inside the session task,
    /// which matters on the runs where the session finishes early: a session
    /// that returns drops its transport, and a sole remaining handle to a
    /// quinn connection closes it on drop. The client would then see the
    /// close race its own handshake completing.
    _proxy_front: quinn::Endpoint,
    _server_side: quinn::Connection,
}

/// Stand a client up in front of `config`'s session and start it.
///
/// The upstream is the caller's — it must already be listening, for the
/// reason [`wt_upstream`] gives.
async fn spawn_leg(config: ProxySessionConfig) -> Leg {
    let (proxy_front, proxy_addr) = common::spawn_quic_server(&[CLIENT_ALPN]);

    let front = proxy_front.clone();
    let accepting = tokio::spawn(async move {
        front
            .accept()
            .await
            .expect("the proxy's front end accepted")
            .await
            .expect("the client's handshake with the proxy completed")
    });

    let (client_endpoint, client) = common::connect_client(proxy_addr, CLIENT_ALPN).await;
    let server_side = tokio::time::timeout(TIMEOUT, accepting)
        .await
        .expect("the proxy's front end accepted within the timeout")
        .expect("front-end accept task");

    let cancel = CancellationToken::new();
    let session_cancel = cancel.clone();
    let session_conn = server_side.clone();
    let session = tokio::spawn(async move {
        let session = ProxySession::new(
            SessionId(1),
            config,
            CLIENT_ALPN.to_vec(),
            Arc::new(NoOpProxyObserver),
            Arc::new(NoOpHook),
            session_cancel,
        );
        session.run(session_conn).await
    });

    Leg {
        session,
        client,
        cancel,
        _client_endpoint: client_endpoint,
        _proxy_front: proxy_front,
        _server_side: server_side,
    }
}

/// Open a unidirectional stream on `conn`, write [`PAYLOAD`], finish it.
async fn send_payload(conn: &quinn::Connection) {
    let mut send = conn.open_uni().await.expect("open_uni");
    send.write_all(PAYLOAD).await.expect("write_all");
    send.finish().expect("finish");
}

/// Everything one run of the fixture observed.
struct Run {
    /// `Some` when the session finished before the upstream ever saw it —
    /// which is what a *refusal* looks like from here, and the world this
    /// file does not assert.
    gave_up: Option<Result<(), ProxyError>>,
    /// What arrived at the upstream, or `None` when [`DELIVERY_WINDOW`]
    /// passed with nothing.
    delivered: Option<Vec<u8>>,
}

/// Wait for the upstream to finish accepting, or for the session to give up
/// first.
///
/// Both futures are raced rather than awaited in turn because either can
/// legitimately complete first, and awaiting the accept alone would turn a
/// session that refused its config into a ten-second hang with no
/// explanation.
async fn connected_or_gave_up<T: Send + 'static>(
    accept: JoinHandle<T>,
    session: &mut JoinHandle<Result<(), ProxyError>>,
) -> Result<T, Result<(), ProxyError>> {
    tokio::select! {
        connected = accept => Ok(connected.expect("the upstream's accept task")),
        ended = session => Err(ended.expect("session task")),
        _ = tokio::time::sleep(TIMEOUT) => panic!(
            "the session neither reached the upstream nor gave up within {TIMEOUT:?}"
        ),
    }
}

/// Run one session against a real WebTransport upstream, optionally with a
/// transport profile set, and report what the upstream saw.
async fn run_over_webtransport(profile: Option<TransportProfile>) -> Run {
    let upstream = wt_upstream();

    let mut config = common::session_config(DraftVersion::Draft14, upstream.addr);
    config.upstream_transport =
        UpstreamTransportType::WebTransport { url: format!("https://{}/moq", upstream.addr) };
    config.upstream_connect_timeout_secs = CONNECT_TIMEOUT_SECS;
    config.upstream_transport_config = transport_config(profile);

    let mut leg = spawn_leg(config).await;

    let conn = match connected_or_gave_up(upstream.accept, &mut leg.session).await {
        Ok(conn) => conn,
        Err(ended) => return Run { gave_up: Some(ended), delivered: None },
    };

    send_payload(&leg.client).await;
    let delivered = tokio::time::timeout(DELIVERY_WINDOW, read_wt_uni(&conn)).await.ok();

    leg.client.close(0u32.into(), b"done");
    leg.cancel.cancel();
    Run { gave_up: None, delivered }
}

/// The same, against a raw-QUIC upstream — the leg on which
/// `upstream_transport_config` *is* installed.
async fn run_over_quic(profile: Option<TransportProfile>) -> Run {
    let (upstream, upstream_addr) = common::spawn_quic_server(&[CLIENT_ALPN]);

    let accepting = upstream.clone();
    let accept = tokio::spawn(async move {
        accepting
            .accept()
            .await
            .expect("the upstream endpoint is live")
            .await
            .expect("the upstream's handshake with the proxy completed")
    });

    let mut config = common::session_config(DraftVersion::Draft14, upstream_addr);
    config.upstream_connect_timeout_secs = CONNECT_TIMEOUT_SECS;
    config.upstream_transport_config = transport_config(profile);

    let mut leg = spawn_leg(config).await;

    let conn = match connected_or_gave_up(accept, &mut leg.session).await {
        Ok(conn) => conn,
        Err(ended) => return Run { gave_up: Some(ended), delivered: None },
    };

    send_payload(&leg.client).await;
    let delivered = tokio::time::timeout(DELIVERY_WINDOW, read_quic_uni(&conn)).await.ok();

    leg.client.close(0u32.into(), b"done");
    leg.cancel.cancel();
    Run { gave_up: None, delivered }
}

// ── the fixture ────────────────────────────────────────────────────────

/// The proxy dials a WebTransport upstream, completes the session, and the
/// client's stream arrives there intact.
///
/// The control for everything below, and the leg this file exists to make
/// possible at all: the far end is a `wtransport::Endpoint::server`, so the
/// session went through `connect_upstream_webtransport` and the HTTP/3
/// SETTINGS and CONNECT exchange rather than through
/// `connect_upstream_quic`. A run that only opened a QUIC connection reaches
/// no `SessionRequest` and never resolves the accept this waits on.
///
/// The payload comparison is what makes it more than a handshake count: the
/// bytes the client wrote to the proxy are compared at the upstream, so the
/// forwarding path was exercised end to end and not merely constructed.
#[tokio::test]
async fn a_webtransport_upstream_is_dialled_and_carries_the_forwarded_payload() {
    let run = run_over_webtransport(None).await;

    assert!(
        run.gave_up.is_none(),
        "the session finished with {:?} instead of reaching the WebTransport upstream",
        run.gave_up
    );
    assert_eq!(
        run.delivered.as_deref(),
        Some(PAYLOAD),
        "the stream the proxy forwarded to the WebTransport upstream did not arrive intact"
    );
}

/// A transport config set on a WebTransport upstream is dropped, and the
/// session runs on.
///
/// This asserts today's behaviour and nothing else. `wtransport` builds its
/// own endpoint from a `wtransport::ClientConfig`, so a
/// `quinn::TransportConfig` on `ProxySessionConfig` has nowhere to go and is
/// discarded between the two — with no error, no event and no counter. The
/// session connects and forwards exactly as
/// [`a_webtransport_upstream_is_dialled_and_carries_the_forwarded_payload`]
/// does, which is the whole observation: the profile made no difference to a
/// run it could not have survived.
///
/// The profile is [`zero_send_window`], and
/// [`the_same_profile_stops_a_quic_upstream_dead`] is what keeps that
/// meaningful — it shows the same value does stop a leg that installs it. A
/// profile that was applied and harmless would pass here and fail there.
///
/// Both other outcomes fail loudly, because each of them is a real change
/// somebody made deliberately and the reader's next question is which one.
#[tokio::test]
async fn a_transport_config_on_a_webtransport_upstream_is_dropped() {
    let run = run_over_webtransport(Some(zero_send_window())).await;

    if let Some(ended) = run.gave_up {
        panic!(
            "the session finished with {ended:?} instead of connecting. A transport config on a \
             WebTransport upstream used to be dropped in silence, as this test asserts; if it is \
             now refused — as a supplied socket already is — then this is the intended new \
             behaviour and this test is the one that has to change: assert the refusal and its \
             rendered message, the way impair_e2e.rs asserts \
             ProxyError::UpstreamSocketUnsupported."
        );
    }

    match run.delivered.as_deref() {
        Some(PAYLOAD) => {}
        None => panic!(
            "the session connected to the WebTransport upstream and no byte of the forwarded \
             stream arrived within {DELIVERY_WINDOW:?}. That is what a send_window of 0 does to a \
             leg that installs it, so upstream_transport_config now reaches the WebTransport \
             upstream instead of being dropped. If that is intended, this test should assert the \
             config's effect rather than its absence."
        ),
        Some(other) => panic!(
            "the forwarded stream arrived at the WebTransport upstream altered: {} bytes against \
             an expected {}",
            other.len(),
            PAYLOAD.len()
        ),
    }
}

/// The ablation: the identical profile against a raw-QUIC upstream, where it
/// is installed, stops the forwarded payload dead.
///
/// This is not a test of quinn. It is what makes
/// [`a_transport_config_on_a_webtransport_upstream_is_dropped`] a claim
/// about the WebTransport leg rather than about a harmless setting. Same
/// profile, same client, same payload, same proxy — one field of
/// `ProxySessionConfig` different — and the outcome inverts.
///
/// The handshake is asserted separately from the delivery, and the order
/// matters: `send_window` bounds unacknowledged *stream* data, so a leg that
/// honours it still connects. A run that failed to connect would satisfy
/// "nothing arrived" for a reason that has nothing to do with the profile.
///
/// Ablation, recorded: dropping the profile from this run and leaving
/// everything else alone reddens it with
/// `the forwarded stream arrived at a QUIC upstream configured with a zero
/// send window`, and the payload was there in 0.02 s — against the
/// [`DELIVERY_WINDOW`] of five seconds that the profiled run waits out in
/// full. The window is not close to anything.
#[tokio::test]
async fn the_same_profile_stops_a_quic_upstream_dead() {
    let run = run_over_quic(Some(zero_send_window())).await;

    assert!(
        run.gave_up.is_none(),
        "the session finished with {:?} instead of connecting: a zero send window bounds stream \
         data, not the handshake, so the leg it is installed on still comes up",
        run.gave_up
    );
    assert_eq!(
        run.delivered, None,
        "the forwarded stream arrived at a QUIC upstream configured with a zero send window, so \
         the profile the WebTransport test hands over is one that changes nothing even where it \
         is installed, and that test proves nothing"
    );
}

//! Reconfiguring a proxy that is already running, and how far each change
//! reaches.
//!
//! Every gate here observes a **consequence** — a stream a peer could or
//! could not open, bytes that arrived or did not, a session that ended, a
//! request that was refused. Nothing reads a configuration value back
//! through a getter, because a getter would answer "yes, I stored it" for
//! precisely the defect these verbs are most likely to have: a setting
//! accepted, reported as applied, and reaching nothing.
//!
//! # The three reaches, and the negative half of each
//!
//! Each verb's claim has two sides, and the second is the one that is easy
//! to leave untested and easy to get wrong.
//!
//! * `set_transport` reaches a connection made **after** the call and never
//!   one that already exists. So the client-leg row connects a client
//!   before the call and another after it, and asserts that the new one is
//!   refused a stream while the old one is still granted them. A test that
//!   only checked the new client would pass equally for an implementation
//!   that reached into live connections, which quinn does not permit and
//!   which the documentation promises does not happen.
//! * `set_shape` reaches a running session at its **next stream**. So the
//!   row writes more objects on a stream that was already forwarding and
//!   watches them arrive, while a stream opened afterwards is held.
//! * `set_shaper_enabled` reaches the **next release decision each queue
//!   makes**, and keeps the profile. So the row switches it off, watches the
//!   queue drain, switches it back on and watches the next batch stop again.
//!
//! # Why the negative windows are safe under load
//!
//! Every negative claim here is either "nothing arrived in 300 ms" — on a
//! class configured at zero, which grants nothing at all — or "less than
//! half of what was offered arrived in 300 ms", on a class paced at 32 B/s,
//! which would need over a minute to reach half. Load can only make a
//! negative claim more true: a slower machine delivers less, never more.
//!
//! The positive companions are anchored polls with a failure ceiling rather
//! than sleeps, so a broken build reports the claim it was waiting on
//! instead of hanging.
//!
//! Two durations are real bounds. The starved profile's `max_hold` is pinned
//! at 30 s so that nothing observed in a 300 ms window can be the clamp
//! delivering — a factor of 100. The paced row's 10 s poll ceiling stands
//! against a paced delivery of at most 320 bytes in that time, an eighth of
//! what it asserts arrived. Widen either if it ever fails; do not delete
//! them.
//!
//! # The window rows, and the two fixture numbers they are obliged to pin
//!
//! The rows further down measure a transport profile through the only
//! observable a flow-control window has: the point at which a *source* stops
//! being able to write. That measurement is not a transport constant, and
//! writing it down as though it were is the mistake this file has to avoid
//! twice over.
//!
//! **The stall point is a function of the writer's chunk size.** A source
//! stalls a little short of its window, by however much of its final write
//! did not fit, so the same window reported against 1 KiB writes and against
//! 64 KiB writes gives two different numbers. Every window row here writes in
//! [`CHUNK`]-byte pieces and says so.
//!
//! **It is also a function of how much the reader consumed first.** QUIC
//! re-advertises `MAX_STREAM_DATA` as the receiving application reads, so a
//! source's total allowance is its initial window *plus* whatever the proxy
//! had already taken off the wire before it stopped reading. What the proxy
//! takes is capped by [`QUEUE_DEPTH`], the number of objects one stream's
//! egress queue may hold under `Overflow::Block` — a count, not a clock — and
//! that is pinned in [`dry_bucket_profile`] rather than inherited from the
//! 256 the type defaults to.
//!
//! Neither number is asserted directly. Every window claim below is one of
//! the two forms that survive a loaded machine, and an equality is assembled
//! from the pair rather than measured:
//!
//! * **the window's worth of bytes goes in** — a liveness anchor, which load
//!   can only delay; and
//! * **the bytes past it do not go in** within [`STALL_WINDOW`] — a negative
//!   claim over a window, which load can only make more true.
//!
//! There is no assertion of the form "the source pushed exactly N bytes",
//! because measuring N needs a stall detector and a stall detector is a clock
//! reading in the one direction load can push.
//!
//! # Why a window row needs the destination drained
//!
//! "The source stalled" is true of two quite different fixtures: one whose
//! proxy stopped reading because its shaper is holding, and one whose proxy
//! stopped reading because it is itself blocked writing to a destination
//! nobody is draining. They are indistinguishable at the source. So each
//! window row watches the far end as well — see [`assert_drained_and_holding`]
//! — and every one of them runs against [`DrainingRelay`], which reads what
//! is forwarded to it rather than merely accepting the connection.

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
    feature = "draft19"
))]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::control::{ControlError, ProxyControl};
use moqtap_proxy::event::SessionId;
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};
use moqtap_proxy::session::{ProxySessionConfig, UpstreamTransportType};
use moqtap_proxy::shape::{
    BucketConfig, ClassRule, Discipline, Matcher, Overflow, QueueConfig, ShapeProfile,
};
use moqtap_proxy::transport::{Leg, TransportProfile, TransportProfileError};

/// Every draft this build compiled, oldest first, so the fixture below has a
/// draft to encode for whichever single-draft build it is running under.
const COMPILED_DRAFTS: &[DraftVersion] = &[
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
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
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
];

/// The draft every media fixture here is built for: the newest one compiled.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the clients and the fake relays speak.
const ALPN: &[u8] = b"moq-00";

/// How long an anchored poll waits before declaring the run broken.
const PATIENCE: Duration = Duration::from_secs(10);

/// The window every negative claim is made over.
const SETTLE: Duration = Duration::from_millis(300);

/// The `max_hold` the starved profiles pin, and the ceiling the negative
/// windows above are separated from by a factor of 100.
///
/// A 0-bps class still *delivers*, at its clamp, under the default
/// `Expiry::Deliver` — so "nothing arrived" is a statement about a sampling
/// window and only means something against a ceiling the fixture wrote down.
/// Widen this if it ever fails; do not delete it.
const STARVED_HOLD: Duration = Duration::from_secs(30);

// ── the far end ────────────────────────────────────────────────────────

/// A relay that completes handshakes and then holds every connection.
///
/// `common::FakeRelay` accepts one connection; the transport rows here run
/// two sessions at once and need every one of them to stay up, because a
/// session that lost its relay would leave the census for a reason the test
/// did not cause.
struct HoldingRelay {
    addr: SocketAddr,
    /// Held, not used: dropping a quinn endpoint stops it accepting.
    _endpoint: quinn::Endpoint,
    /// Holds every accepted connection open for the life of the test.
    _accepting: tokio::task::JoinHandle<()>,
}

fn holding_relay() -> HoldingRelay {
    let (endpoint, addr) = common::spawn_quic_server(&[ALPN]);
    let acceptor = endpoint.clone();
    let accepting = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = acceptor.accept().await {
            if let Ok(conn) = incoming.await {
                held.push(conn);
            }
        }
    });
    HoldingRelay { addr, _endpoint: endpoint, _accepting: accepting }
}

// ── the proxy under test ───────────────────────────────────────────────

/// A proxy config bound to an ephemeral port and pointed at `upstream`.
///
/// Port 0 deliberately: the port is chosen inside `run()`, which is what
/// `local_addr()` exists for and what every row here connects to.
fn proxy_config(session: ProxySessionConfig) -> ProxyConfig {
    let (cert_chain, key_der) = common::self_signed_localhost();
    ProxyConfig {
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
        session,
    }
}

fn proxy(upstream: SocketAddr) -> TransparentProxy {
    TransparentProxy::new(
        proxy_config(common::session_config(DRAFT, upstream)),
        Arc::new(NoOpProxyObserver),
    )
}

/// Poll `probe` until it answers, or give up loudly.
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

/// The live list, once it holds exactly `n` ids.
fn live_count(control: &ProxyControl, n: usize) -> Option<Vec<SessionId>> {
    let live = control.sessions();
    (live.len() == n).then_some(live)
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

/// Whether `conn` is granted a unidirectional stream within `window`.
///
/// The consequence a `max_concurrent_uni_streams` of zero produces, and it
/// is a consequence rather than a reading: quinn does not resolve
/// `open_uni()` until the peer has granted stream credit, so a client that
/// negotiated a limit of zero waits here forever and one that negotiated
/// quinn's default is served immediately.
async fn can_open_uni(conn: &quinn::Connection, window: Duration) -> bool {
    matches!(tokio::time::timeout(window, conn.open_uni()).await, Ok(Ok(_)))
}

/// Whether `conn` is granted a bidirectional stream within `window`.
///
/// The same shape one line up, against the other ceiling. `open_bi()` waits
/// on its own credit, granted from its own transport parameter, so the two
/// helpers can disagree about the same connection — which is the whole of
/// what the row below asserts.
async fn can_open_bi(conn: &quinn::Connection, window: Duration) -> bool {
    matches!(tokio::time::timeout(window, conn.open_bi()).await, Ok(Ok(_)))
}

// ── set_transport, client leg ──────────────────────────────────────────

/// A client-leg profile reaches the next client to connect, and leaves the
/// one already connected exactly as it was.
///
/// The knob is `max_concurrent_uni_streams = 0`, chosen because its
/// consequence is immediate, binary and impossible to confuse with slowness:
/// a client that negotiated zero is never granted a stream, and a client
/// that negotiated quinn's default is granted one at once.
///
/// Both halves are asserted from the same call. The first — the new client
/// stalls — fails if the profile reached nothing. The second — the old
/// client is still served, *after* the call — fails if an implementation
/// somehow reached into a live connection, and is the assertion that makes
/// the documented "this never reaches a connection that already exists"
/// falsifiable rather than a claim about quinn nobody checked.
///
/// *Ablation, recorded:* replace the body of `Listener::set_transport` with
/// `let _ = transport;`, so the endpoint is never given the rebuilt server
/// configuration. This row fails with
///
/// ```text
/// a client that connected after the call negotiated the new limit, so it is
/// never granted a stream
/// ```
#[tokio::test]
async fn a_client_leg_profile_reaches_the_next_client_and_not_the_one_already_connected() {
    common::init_crypto();
    let relay = holding_relay();
    let proxy = Arc::new(proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_early_ep, early) = common::connect_client(addr, ALPN).await;
    wait_for("the first session", || live_count(&control, 1)).await;
    assert!(
        can_open_uni(&early, common::TIMEOUT).await,
        "before the call, a client is granted streams at quinn's default limit"
    );

    // `#[non_exhaustive]`, so `default()` then field assignment is the only
    // construction form available to a test crate.
    let mut profile = TransportProfile::default();
    profile.max_concurrent_uni_streams = Some(0);
    control.set_transport(Leg::Client, profile).expect("a valid profile is installed");

    let (_late_ep, late) = common::connect_client(addr, ALPN).await;
    assert!(
        !can_open_uni(&late, SETTLE).await,
        "a client that connected after the call negotiated the new limit, so it is never granted \
         a stream"
    );
    assert!(
        can_open_uni(&early, common::TIMEOUT).await,
        "the connection that already existed kept the limit it negotiated: a QUIC connection \
         takes its transport configuration once, and nothing here reaches back into one"
    );

    early.close(0u32.into(), b"done");
    late.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

/// The bidirectional ceiling is a ceiling of its own, and not the
/// unidirectional one under another name.
///
/// `max_concurrent_bidi_streams` is the only field in the profile whose
/// *meaning* moves across the drafts — the control stream on 07 through 15,
/// the control stream and SUBSCRIBE_NAMESPACE on 16, requests alone on 17
/// through 19 — and a profile is installed on a leg before any version has
/// been negotiated, so nothing here can know which. None of that is visible
/// from this row and none of it needs to be: a stream credit is the
/// consequence the setting has at the transport layer, whatever MoQT later
/// puts on the stream.
///
/// **Both halves come from one profile that sets the bidirectional ceiling
/// and nothing else**, which is what makes this a statement about this
/// field rather than about stream credit in general. The client is never
/// granted a bidirectional stream; it is granted a unidirectional one at
/// once, at quinn's untouched default.
///
/// *Ablations, recorded — three, and the first two are worth reading
/// together.* Deleting the `max_concurrent_bidi_streams` arm from
/// `TransportProfile::apply_to` fails the first half with
///
/// ```text
/// a client that negotiated a bidirectional ceiling of zero is never granted a bidirectional stream
/// ```
///
/// Pointing that same arm at `tc.max_concurrent_uni_streams` — the slip a
/// field added beside another is most likely to carry — fails it with the
/// **same message**. That was not the prediction and it is the more useful
/// answer: seen from the first half, a value written to the wrong setter and
/// a value written nowhere are one event, so this row catches the slip and
/// cannot tell a maintainer which of the two they made.
///
/// The second half is aimed at a different mistake, and it takes a third cut
/// to reach. Making the one arm set both ceilings — the shape a refactor to
/// a single stream-concurrency knob would take — leaves the first half green
/// and fails with
///
/// ```text
/// the unidirectional ceiling was left alone, so a unidirectional stream is still granted
/// ```
///
/// So the two assertions cover two mistakes rather than one of them twice.
#[tokio::test]
async fn a_bidirectional_ceiling_starves_only_bidirectional_streams() {
    common::init_crypto();
    let relay = holding_relay();
    let proxy = Arc::new(proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    // `#[non_exhaustive]`, so `default()` then field assignment is the only
    // construction form available to a test crate.
    let mut profile = TransportProfile::default();
    profile.max_concurrent_bidi_streams = Some(0);
    control.set_transport(Leg::Client, profile).expect("a valid profile is installed");

    let (_ep, client) = common::connect_client(addr, ALPN).await;
    wait_for("the session", || live_count(&control, 1)).await;
    assert!(
        !can_open_bi(&client, SETTLE).await,
        "a client that negotiated a bidirectional ceiling of zero is never granted a \
         bidirectional stream"
    );
    assert!(
        can_open_uni(&client, common::TIMEOUT).await,
        "the unidirectional ceiling was left alone, so a unidirectional stream is still granted"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

/// A client-leg profile set before the proxy has bound reaches the very
/// first client.
///
/// The handle is live before the endpoint is — that is the whole point of
/// taking one before `run()` is awaited — so a request that arrives in that
/// window has to be held and applied at the bind rather than dropped. The
/// consequence is the same one: the first client ever to connect is refused
/// a stream.
///
/// *Ablation, recorded, and it takes two:* the pre-bind path is carried
/// redundantly, on purpose. `listener_config()` reads the stored parameters
/// so the endpoint is *born* with them, and `ControlPlane::publish_listener`
/// installs them again under the lock so that a request landing between the
/// bind and the publish — the one window in which the first route has
/// already been taken and the second is not yet reachable — is not lost.
/// Removing either alone leaves this row green; that was measured, not
/// assumed. Removing **both** fails it with
///
/// ```text
/// the first client to connect negotiated a limit set before there was an
/// endpoint to set it on
/// ```
///
/// No gate reaches the window the second route exists for, because producing
/// it means winning a race against two adjacent statements. It is kept for
/// the same reason a `Drop` is preferred to a list of teardown calls: the
/// failure it prevents is a request accepted and silently dropped.
#[tokio::test]
async fn a_client_leg_profile_set_before_the_bind_reaches_the_first_client() {
    common::init_crypto();
    let relay = holding_relay();
    let proxy = Arc::new(proxy(relay.addr));
    let control = proxy.control();

    let mut profile = TransportProfile::default();
    profile.max_concurrent_uni_streams = Some(0);
    control.set_transport(Leg::Client, profile).expect("a handle answers before the proxy binds");

    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_ep, client) = common::connect_client(addr, ALPN).await;
    wait_for("the session", || live_count(&control, 1)).await;
    assert!(
        !can_open_uni(&client, SETTLE).await,
        "the first client to connect negotiated a limit set before there was an endpoint to set \
         it on"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── set_transport, relay leg ───────────────────────────────────────────

/// An upstream profile reaches the next session's relay connection, and
/// leaves the session already running alone.
///
/// The knob is a short `max_idle_timeout` with no keep-alive, chosen because
/// its consequence needs nothing of the relay: both legs of a session that
/// has exchanged its handshake and nothing else are idle, so a session that
/// dialled with the short timeout ends on its own and leaves the census,
/// while one that dialled before the call sits at quinn's 30 s default and
/// stays. Two sessions, one call, and the difference between them is the
/// dial that happened after it.
///
/// *Ablation, recorded:* make `session_config()` ignore
/// `ControlPlane::upstream_transport` and copy the template's fields
/// unconditionally. This row fails with
///
/// ```text
/// timed out waiting for the second session's relay leg to time out
/// ```
#[tokio::test]
async fn an_upstream_profile_reaches_the_next_session_and_not_the_one_already_dialled() {
    common::init_crypto();
    let relay = holding_relay();
    let proxy = Arc::new(proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_early_ep, early) = common::connect_client(addr, ALPN).await;
    assert_eq!(wait_for("the first session", || live_count(&control, 1)).await, vec![SessionId(1)]);

    let mut profile = TransportProfile::default();
    // Long enough that the session is comfortably observable in the census
    // before it dies, short enough that the row finishes in a second.
    profile.max_idle_timeout = Some(Duration::from_millis(1_500));
    control.set_transport(Leg::Upstream, profile).expect("a valid profile is installed");

    let (_late_ep, late) = common::connect_client(addr, ALPN).await;
    assert_eq!(
        wait_for("the second session", || live_count(&control, 2)).await,
        vec![SessionId(1), SessionId(2)],
        "the session that dialled after the call is running before its relay leg times out"
    );

    wait_for("the second session's relay leg to time out", || {
        (control.sessions() == vec![SessionId(1)]).then_some(())
    })
    .await;

    early.close(0u32.into(), b"done");
    late.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

/// A WebTransport upstream refuses a transport profile, and a QUIC upstream
/// takes the same one.
///
/// The pairing is what makes the refusal mean something: refused on one
/// transport and accepted on the other, from one profile, so the answer is
/// about where the endpoint is built and not about the profile being wrong.
/// A WebTransport endpoint is built inside the WebTransport library, which
/// takes no `quinn::TransportConfig` and hands back no endpoint to install
/// one on, so the only alternative to this refusal is storing the profile
/// and ignoring it.
#[tokio::test]
async fn a_webtransport_upstream_refuses_a_transport_profile_and_a_quic_one_takes_it() {
    common::init_crypto();
    let relay = holding_relay();

    let mut profile = TransportProfile::default();
    profile.initial_mtu = Some(1350);

    let mut wt = common::session_config(DRAFT, relay.addr);
    wt.upstream_transport =
        UpstreamTransportType::WebTransport { url: "https://relay.invalid:4443/moq".to_string() };
    let over_wt = TransparentProxy::new(proxy_config(wt), Arc::new(NoOpProxyObserver));
    assert_eq!(
        over_wt.control().set_transport(Leg::Upstream, profile.clone()),
        Err(ControlError::Unsupported {
            what: "transport profile",
            leg: Leg::Upstream,
            transport: "webtransport",
        }),
        "the refusal names the leg and the transport, so a caller knows it is the upstream's \
         transport and not the profile that is the problem"
    );

    let over_quic = proxy(relay.addr);
    assert_eq!(
        over_quic.control().set_transport(Leg::Upstream, profile),
        Ok(()),
        "the same profile on a QUIC upstream is installed, so the refusal above is about the \
         transport"
    );

    // The client leg is QUIC whatever the upstream is, so the WebTransport
    // proxy still takes a client-leg profile — the refusal is per leg and
    // not per proxy.
    let mut client_side = TransportProfile::default();
    client_side.initial_mtu = Some(1350);
    assert_eq!(over_wt.control().set_transport(Leg::Client, client_side), Ok(()));
}

/// A profile the leg would not have started with is refused at the call, and
/// the proxy carries on unchanged.
///
/// quinn raises an `initial_mtu` below 1200 to 1200 without a word, which is
/// why a profile naming 900 is refused rather than installed — a run at 900
/// would never have happened. The refusal has to arrive here rather than at
/// the next connect, or a caller would learn about it as a connection
/// failure minutes later with nothing linking the two.
///
/// The second half is the consequence: a client connects afterwards and is
/// granted a stream, so nothing was half-installed on the way to the
/// refusal.
#[tokio::test]
async fn a_profile_the_leg_would_not_have_started_with_is_refused_and_changes_nothing() {
    common::init_crypto();
    let relay = holding_relay();
    let proxy = Arc::new(proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let mut profile = TransportProfile::default();
    profile.initial_mtu = Some(900);

    for leg in [Leg::Client, Leg::Upstream] {
        assert_eq!(
            control.set_transport(leg, profile.clone()),
            Err(ControlError::Profile(TransportProfileError::MtuBelowFloor {
                field: "initial_mtu",
                value: 900,
                floor: 1200,
            })),
            "{leg:?} reports the same refusal a configured profile would have got"
        );
    }

    let (_ep, client) = common::connect_client(addr, ALPN).await;
    wait_for("a session after the refusal", || live_count(&control, 1)).await;
    assert!(
        can_open_uni(&client, common::TIMEOUT).await,
        "a refused profile leaves the leg exactly as it was, so a client that connects afterwards \
         is served"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── media fixtures for the shaping rows ────────────────────────────────

/// The stream type byte for a [`DRAFT`] subgroup header carrying an explicit
/// Subgroup ID.
///
/// Restated rather than shared with the proxy: an encoder taken from the
/// crate under test would leave these rows comparing the proxy against its
/// own output.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        DraftVersion::Draft11 => 0x0C,
        _ => 0x14,
    }
}

/// A subgroup stream header on `track_alias`: group 0, subgroup 0, publisher
/// priority `0x80`. Five bytes on every draft 07-19.
fn subgroup_header(track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "single-byte varint only");
    vec![subgroup_stream_type(DRAFT), track_alias as u8, 0x00, 0x00, 0x80]
}

/// A subgroup stream split into its header and one buffer per object.
///
/// Split rather than returned whole because these rows write a stream in two
/// batches with a control-plane call between them, and object IDs are
/// delta-encoded on drafts 14-19 — encoding the two batches separately would
/// encode the second batch's first delta against nothing. One writer, one
/// pass, and the pieces are handed back for the caller to send when it
/// likes.
fn subgroup_pieces(track_alias: u64, count: u64, payload_len: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let head = subgroup_header(track_alias);
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut objects = Vec::with_capacity(count as usize);
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; payload_len],
        };
        let mut buf = Vec::new();
        writer.write_object(&obj, &mut buf).expect("write object");
        objects.push(buf);
    }
    (head, objects)
}

/// A bucket burst that covers one object of this fixture's size and no more
/// than two.
///
/// Sized deliberately rather than generously: it is what makes a
/// rate-limited class deliver its first object at once and then wait a whole
/// object's worth of its rate for the second, so the pacing interval a row
/// waits on is a number the fixture chose.
const BURST: u64 = 128;

/// A one-class profile whose single bucket is named `class` and whose rate
/// is `rate_bps`.
///
/// `None` is an explicitly unshaped class — every unit granted, nothing
/// accounted — and `Some(0)` is a class that never grants from tokens at
/// all. The burst is zero beside a zero rate on purpose: `charge` asks about
/// the rate before the burst, so a deliberately stopped class answers "never"
/// rather than "your burst is too small", and the row is not competing with
/// a misconfiguration report it did not mean to produce.
fn one_class_profile(class: &str, rate_bps: Option<u64>) -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = class.to_string();
    bucket.rate_bps = rate_bps;
    bucket.burst_bytes = match rate_bps {
        Some(0) => 0,
        Some(_) => BURST,
        None => 1024 * 1024,
    };

    let mut rule = ClassRule::default();
    rule.name = class.to_string();
    rule.bucket = class.to_string();
    rule.weight = 1;

    let mut queue = QueueConfig::default();
    queue.max_hold = Some(STARVED_HOLD);
    // The arriving unit is never discarded, so "nothing arrived" is about
    // pacing and never about a drop policy quietly throwing the fixture
    // away.
    queue.overflow = Overflow::Block;

    ShapeProfile::try_new(vec![bucket], vec![rule], queue, Discipline::Fifo)
        .expect("the control profile must be valid or every row below is unattributable")
}

/// A shaped proxy in front of a one-connection relay, with its first client
/// connected and its relay connection accepted.
struct ShapedRun {
    proxy: Arc<TransparentProxy>,
    control: ProxyControl,
    relay: Arc<common::FakeRelay>,
    client: quinn::Connection,
    _client_ep: quinn::Endpoint,
    loop_task: tokio::task::JoinHandle<()>,
}

impl ShapedRun {
    async fn start(profile: ShapeProfile) -> Self {
        common::init_crypto();
        let relay = Arc::new(common::FakeRelay::bind(ALPN));
        let mut session = common::session_config(DRAFT, relay.addr);
        session.shape = Some(profile);
        let proxy =
            Arc::new(TransparentProxy::new(proxy_config(session), Arc::new(NoOpProxyObserver)));
        let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

        let (client_ep, client) = common::connect_client(addr, ALPN).await;
        let _ = tokio::time::timeout(common::TIMEOUT, relay.connection())
            .await
            .expect("the proxy connected upstream");
        Self { proxy, control, relay, client, _client_ep: client_ep, loop_task }
    }

    /// Open a source stream, write its header and `objects`, and hand back
    /// the destination the relay accepted for it.
    async fn offer(
        &self,
        head: &[u8],
        objects: &[Vec<u8>],
    ) -> (quinn::SendStream, common::TimedReceiver) {
        let mut send = self.client.open_uni().await.expect("open_uni");
        send.write_all(head).await.expect("write header");
        for object in objects {
            send.write_all(object).await.expect("write object");
        }
        let rx = tokio::time::timeout(common::TIMEOUT, self.relay.timed_uni())
            .await
            .expect("the proxy opened the destination stream");
        // The header carries no `ObjectMeta`, so no rule claims it and no
        // bucket charges it: it is through even on a stopped class, and
        // waiting for it here is what makes the object-byte assertions
        // below about the objects.
        rx.wait_for_bytes(head.len()).await;
        (send, rx)
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.cancel_token().cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.loop_task).await;
    }
}

// ── set_shaper_enabled ─────────────────────────────────────────────────

/// The rate the switch row paces at, in bytes per second.
///
/// Slow enough that the whole fixture would take over a minute to deliver
/// under pacing, which is what gives every bound below its separation, and
/// fast enough that one object's worth of it — the wait the switch is read
/// at — is about two seconds rather than a test-length hang.
const PACED_BPS: u64 = 32;

/// Switching the shaper off drains what a paced class was holding, and
/// switching it back on holds the next batch — with the same profile.
///
/// Three observations, in order, and each is a consequence rather than a
/// reading. Under a 32 B/s class the stream delivers its burst and stops.
/// Switching off drains the rest. Switching back on holds the next batch,
/// which is what makes "the profile is kept, not discarded" falsifiable: a
/// switch that threw the profile away would deliver the second batch too.
///
/// # Why the class is paced rather than stopped
///
/// The switch is read when a queue next asks its scheduler, and a queue that
/// has been refused asks again when the wait it was given expires. A class
/// configured at zero names no refill instant, so its wait is the `max_hold`
/// clamp and a row built on one would be asserting on a 30 s timer rather
/// than on the switch. A class with a real rate waits one object's worth of
/// it — about two seconds here — so this row observes the switch and says so
/// in the same terms the method's documentation does.
///
/// # The bounds, and the direction load can push them
///
/// Both negative claims are "less than half of what was offered", against a
/// rate that would need over a minute to deliver half. Load can only deliver
/// less, so neither can flake upward. The positive claim is an anchored poll
/// with a 10 s ceiling against a paced delivery of at most 320 bytes in that
/// time — a factor of eight below the total — so it cannot pass by pacing
/// having quietly finished.
///
/// *Ablation, recorded:* delete the `enabled` check at the top of
/// `Scheduler::acquire`, so the switch reaches nothing. This row fails with
///
/// ```text
/// assertion `left == right` failed: with pacing switched off the queue
/// drains
///   left: 401
///  right: 2645
/// ```
#[tokio::test]
async fn the_shaper_switch_stops_and_resumes_a_live_sessions_pacing() {
    let run = ShapedRun::start(one_class_profile("media", Some(PACED_BPS))).await;
    let (head, objects) = subgroup_pieces(1, 60, 64);
    let first: usize = objects[..40].iter().map(Vec::len).sum();
    let second: usize = objects[40..].iter().map(Vec::len).sum();

    let (mut send, rx) = run.offer(&head, &objects[..40]).await;
    // A settle rather than `assert_no_bytes_for`: a paced class is not a
    // stopped one, so the claim is "most of it is still queued" and the
    // burst is expected to have gone.
    tokio::time::sleep(SETTLE).await;
    assert!(
        rx.len() < head.len() + first / 2,
        "a class paced at {PACED_BPS} B/s has delivered its burst and stopped, not {} of {first} \
         object bytes",
        rx.len() - head.len()
    );

    run.control.set_shaper_enabled(false);
    assert_eq!(
        rx.wait_for_bytes(head.len() + first).await.len(),
        head.len() + first,
        "with pacing switched off the queue drains"
    );

    run.control.set_shaper_enabled(true);
    for object in &objects[40..] {
        send.write_all(object).await.expect("write object");
    }
    tokio::time::sleep(SETTLE).await;
    assert!(
        rx.len() < head.len() + first + second / 2,
        "switching the shaper back on resumes the same {PACED_BPS} B/s class rather than starting \
         from no profile at all, so most of the {second} bytes offered afterwards are still queued"
    );

    run.finish().await;
}

// ── set_shape ──────────────────────────────────────────────────────────

/// A new profile reaches the next stream a running session forwards, and
/// leaves the stream already forwarding alone.
///
/// The session starts on an unlimited class, so its first stream flows. The
/// call installs a stopped class with the same name. Then both halves are
/// asserted from the same session: more objects written on the stream that
/// was already forwarding still arrive, and a stream opened afterwards
/// delivers its header and nothing else.
///
/// The second half is the interesting one and it is why the granularity is
/// the stream rather than the object: a stream's egress queue holds the
/// scheduler its units were admitted under, so a unit classified against one
/// profile and released against another would charge a class that was not
/// the one matched.
///
/// *Ablation, recorded:* make `SessionShaper::current` return the cached
/// scheduler without consulting the plane's generation. This row fails with
///
/// ```text
/// assertion `left == right` failed: a stream opened after the call is paced
/// by the new profile, so its objects stay queued
///   left: 269
///  right: 5
/// ```
#[tokio::test]
async fn a_new_profile_reaches_the_next_stream_and_leaves_the_one_already_forwarding_alone() {
    let run = ShapedRun::start(one_class_profile("media", None)).await;
    let (head, objects) = subgroup_pieces(1, 8, 64);
    let first: usize = objects[..4].iter().map(Vec::len).sum();
    let second: usize = objects[4..].iter().map(Vec::len).sum();

    let (mut send, rx) = run.offer(&head, &objects[..4]).await;
    assert_eq!(
        rx.wait_for_bytes(head.len() + first).await.len(),
        head.len() + first,
        "an unlimited class delivers everything offered to it"
    );

    run.control
        .set_shape(one_class_profile("media", Some(0)))
        .expect("a profile built by try_new is one try_new accepts");

    for object in &objects[4..] {
        send.write_all(object).await.expect("write object");
    }
    assert_eq!(
        rx.wait_for_bytes(head.len() + first + second).await.len(),
        head.len() + first + second,
        "the stream that was already forwarding keeps the profile it started under, so the \
         objects written after the call still arrive"
    );

    let (later_head, later_objects) = subgroup_pieces(2, 4, 64);
    let (_later_send, later_rx) = run.offer(&later_head, &later_objects).await;
    common::assert_no_bytes_for(&later_rx, SETTLE).await;
    assert_eq!(
        later_rx.len(),
        later_head.len(),
        "a stream opened after the call is paced by the new profile, so its objects stay queued"
    );

    run.finish().await;
}

/// A profile whose class list differs is not taken up by a session already
/// running.
///
/// The statistics rows are pre-sized per session from the class list it
/// started with and charged by position, so a profile with a different list
/// would keep every number right and every label on it wrong. The session
/// therefore keeps its own profile until it ends — and the consequence is
/// visible on the wire: a stream opened after a call naming a *different*
/// class flows, where the row above showed the same call naming the *same*
/// class holding it.
///
/// The two rows together are the gate. Either alone would pass for an
/// implementation that ignored `set_shape` completely.
///
/// *Ablation, recorded:* make `same_classes` return `true` unconditionally.
/// This row fails with
///
/// ```text
/// assertion `left == right` failed: a session keeps its own profile when the
/// class list would change, so a stream opened afterwards still flows
///   left: 5
///  right: 269
/// ```
#[tokio::test]
async fn a_profile_with_a_different_class_list_is_not_taken_up_by_a_running_session() {
    let run = ShapedRun::start(one_class_profile("media", None)).await;

    run.control
        .set_shape(one_class_profile("something-else", Some(0)))
        .expect("the profile itself is valid; it is this session that declines it");

    let (head, objects) = subgroup_pieces(1, 4, 64);
    let want: usize = head.len() + objects.iter().map(Vec::len).sum::<usize>();
    let (_send, rx) = run.offer(&head, &objects).await;
    assert_eq!(
        rx.wait_for_bytes(want).await.len(),
        want,
        "a session keeps its own profile when the class list would change, so a stream opened \
         afterwards still flows"
    );

    run.finish().await;
}

// ── set_impair ─────────────────────────────────────────────────────────

/// A leg the proxy holds no impairment handle for is refused, loudly, with
/// the call that fixes it.
///
/// This is the refusal that must not be silent. A profile stored against a
/// leg whose datagrams never cross an impaired socket is armed, reported as
/// applied, and applied to nothing — and the run that follows looks clean
/// because it *is* clean, with no counter anywhere that would say so.
#[cfg(feature = "impair")]
#[tokio::test]
async fn impairing_a_leg_the_proxy_cannot_impair_is_refused_and_names_the_call_that_fixes_it() {
    common::init_crypto();
    let relay = holding_relay();
    let proxy = proxy(relay.addr);
    let control = proxy.control();

    for leg in [Leg::Client, Leg::Upstream] {
        let refusal = control
            .set_impair(leg, quinn_netem::ImpairProfile::default())
            .expect_err("a leg with no handle cannot be impaired and must not pretend otherwise");
        match refusal {
            ControlError::Unsupported { what, leg: named, transport } => {
                assert_eq!(what, "a datagram impairment");
                assert_eq!(named, leg);
                assert!(
                    transport.contains("set_impaired_socket"),
                    "the refusal has to name the call that supplies the missing half, or a \
                     caller cannot act on it: {transport}"
                );
            }
            other => panic!("expected an Unsupported refusal, got {other:?}"),
        }
    }

    // Idempotent, and silent: there is no impairment to remove and nothing
    // is owed. The refusal above is where a caller finds out.
    control.clear_impair(Leg::Client);
}

/// An impairment armed on the client leg stops the bytes, and clearing it
/// lets them through.
///
/// The only verb here that reaches traffic already flowing over a connection
/// that already exists, and the assertions say exactly that: the same
/// stream, the same session, bytes before, no bytes during, bytes again
/// after. Loss is `EveryNth { n: 1 }` rather than a probability so the
/// fixture consumes no random draws and cannot flake on a seed.
///
/// The recovery half is not decoration. Without it the row would pass for an
/// impairment that killed the connection outright, which is a different
/// thing from one that dropped its datagrams.
///
/// *Ablation, recorded:* make `ProxyControl::set_impair` return `Ok(())`
/// without arming the handle. This row fails with
///
/// ```text
/// assertion `left == right` failed: 256 byte(s) arrived during a 300ms
/// window in which nothing should have
///   left: 512
///  right: 256
/// ```
#[cfg(feature = "impair")]
#[tokio::test]
async fn an_impairment_armed_on_the_client_leg_stops_the_bytes_and_clearing_it_resumes_them() {
    use quinn_netem::{DirectionProfile, ImpairProfile, LossModel};

    common::init_crypto();
    let relay = Arc::new(common::FakeRelay::bind(ALPN));
    let seam = common::impaired_seam(ImpairProfile::default());

    let mut proxy = TransparentProxy::new(
        proxy_config(common::session_config(DRAFT, relay.addr)),
        Arc::new(NoOpProxyObserver),
    );
    proxy.set_impaired_socket(
        Leg::Client,
        Arc::clone(&seam.socket) as Arc<dyn quinn::AsyncUdpSocket>,
        seam.handle.clone(),
    );
    let proxy = Arc::new(proxy);
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;
    assert_eq!(addr, seam.addr, "the listener bound over the socket it was handed");

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    let _ = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&[0xAB; 256]).await.expect("write before");
    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the proxy opened the destination stream");
    assert_eq!(rx.wait_for_bytes(256).await.len(), 256, "the unimpaired leg carries the bytes");

    let every_datagram =
        DirectionProfile { loss: Some(LossModel::EveryNth { n: 1 }), ..Default::default() };
    let blackhole = ImpairProfile {
        downlink: every_datagram.clone(),
        uplink: every_datagram,
        ..Default::default()
    };
    control.set_impair(Leg::Client, blackhole).expect("a valid profile arms");

    send.write_all(&[0xCD; 256]).await.expect("write during");
    common::assert_no_bytes_for(&rx, SETTLE).await;

    control.clear_impair(Leg::Client);
    assert_eq!(
        rx.wait_for_bytes(512).await.len(),
        512,
        "clearing the impairment lets the client's retransmissions through, so the leg was \
         dropping datagrams rather than dead"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

/// A profile `quinn-netem` refuses comes back carrying *its* reason, and
/// leaves what was armed before exactly where it was.
///
/// Two claims, and they are the two halves of what the refusal is for.
///
/// The first is that the reasons are **told apart**. Both profiles below are
/// armed and do nothing, for different reasons and with different fixes:
/// `EveryNth { n: 0 }` is a loss model that can never fire, and
/// `PeerFilter::Only(vec![])` is a filter that matches no peer. They used to
/// arrive as one sentence naming the leg, with the caller directed to re-run
/// `ImpairProfile::validate` to find out which had happened — a workaround
/// for a type that could not hold the answer. Comparing the two refusals
/// against each other is what makes "the reason survived" checkable rather
/// than asserted: an error that carried no reason would make them equal.
///
/// The second is the consequence, and it is what a caller acts on: a refused
/// profile arms nothing and disturbs nothing. The blackout armed before the
/// two refusals is still in force after them — the bytes are still stopped —
/// and clearing it lets them through. A refusal that had half-armed
/// something, or had disarmed what was there, would show up as bytes
/// arriving in the middle window.
///
/// *Ablation, run:* return the old blanket refusal from
/// `ProxyControl::set_impair` —
/// `ControlError::Unsupported { what: "the impairment profile supplied",
/// leg, transport: … }` — for any profile `arm` rejects. This row reddens
/// with
///
/// ```text
/// thread 'a_profile_quinn_netem_refuses_is_reported_with_its_own_reason_and_arms_nothing'
/// (4568) panicked at crates\moqtap-proxy\tests\control_reconfigure.rs:1139:22:
/// a refused impairment profile has to carry quinn-netem's own reason: the
/// thirteen ways a profile arms and does nothing have thirteen different
/// fixes, got the impairment profile supplied is unsupported on the Client leg
/// over this leg's socket — quinn-netem refused the profile itself;
/// ImpairProfile::validate() returns the reason
/// ```
#[cfg(feature = "impair")]
#[tokio::test]
async fn a_profile_quinn_netem_refuses_is_reported_with_its_own_reason_and_arms_nothing() {
    use quinn_netem::{DirectionProfile, ImpairProfile, LossModel, PeerFilter, ProfileError};

    common::init_crypto();
    let relay = Arc::new(common::FakeRelay::bind(ALPN));
    let seam = common::impaired_seam(ImpairProfile::default());

    let mut proxy = TransparentProxy::new(
        proxy_config(common::session_config(DRAFT, relay.addr)),
        Arc::new(NoOpProxyObserver),
    );
    proxy.set_impaired_socket(
        Leg::Client,
        Arc::clone(&seam.socket) as Arc<dyn quinn::AsyncUdpSocket>,
        seam.handle.clone(),
    );
    let proxy = Arc::new(proxy);
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    let _ = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&[0xAB; 256]).await.expect("write before");
    let rx = tokio::time::timeout(common::TIMEOUT, relay.timed_uni())
        .await
        .expect("the proxy opened the destination stream");
    assert_eq!(rx.wait_for_bytes(256).await.len(), 256, "the unimpaired leg carries the bytes");

    // Armed first, so the rows below have something to fail to disturb.
    let every_datagram =
        DirectionProfile { loss: Some(LossModel::EveryNth { n: 1 }), ..Default::default() };
    let blackhole = ImpairProfile {
        downlink: every_datagram.clone(),
        uplink: every_datagram,
        ..Default::default()
    };
    control.set_impair(Leg::Client, blackhole).expect("a valid profile arms");

    // One row per unarmable profile, each with the reason quinn-netem gives
    // it. Two rows and not one: a single row passes against an error that
    // carries a fixed reason as easily as against one that carries the right
    // one.
    let never_fires =
        DirectionProfile { loss: Some(LossModel::EveryNth { n: 0 }), ..Default::default() };
    let rows: [(&str, ImpairProfile, ProfileError); 2] = [
        (
            "a loss model that can never fire",
            ImpairProfile { downlink: never_fires, ..Default::default() },
            ProfileError::EveryNthZero,
        ),
        (
            "a peer filter that matches no peer",
            ImpairProfile { peers: PeerFilter::Only(Vec::new()), ..Default::default() },
            ProfileError::PeerFilterMatchesNothing,
        ),
    ];

    let mut refusals = Vec::new();
    for (label, profile, reason) in rows {
        let refusal = control
            .set_impair(Leg::Client, profile)
            .expect_err("a profile that arms and does nothing is not armed");
        match &refusal {
            ControlError::Impairment { leg, source } => {
                assert_eq!(*leg, Leg::Client, "{label}: the refusal names the leg it was aimed at");
                assert_eq!(*source, reason, "{label}: and quinn-netem's own reason for it");
            }
            other => panic!(
                "a refused impairment profile has to carry quinn-netem's own reason: the thirteen \
                 ways a profile arms and does nothing have thirteen different fixes, got {other}"
            ),
        }
        refusals.push(refusal);
    }
    assert_ne!(
        refusals[0], refusals[1],
        "two profiles refused for two different reasons must not be indistinguishable to a caller \
         holding the answers: that is the whole of what the refusal carries"
    );

    // The consequence. A refused profile changed nothing, so the blackout
    // armed above is still the one in force.
    send.write_all(&[0xCD; 256]).await.expect("write during");
    common::assert_no_bytes_for(&rx, SETTLE).await;

    control.clear_impair(Leg::Client);
    assert_eq!(
        rx.wait_for_bytes(512).await.len(),
        512,
        "clearing lets the client's retransmissions through, so the two refusals left the armed \
         profile alone rather than replacing or disarming it"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── the window rows: the two windows, and the fixture numbers ──────────

/// The per-stream receive window every row below installs, in bytes.
///
/// 64 KiB, and the two properties that matter are that it is a round number a
/// reader can check the assertions against, and that it is **nineteen times
/// smaller** than [`DEFAULT_WINDOW`]. Every comparison here is separated by
/// that ratio; shrink it and the rows stop being able to tell a configured
/// window from an unconfigured one.
const SMALL_WINDOW: usize = 64 * 1024;

/// quinn's per-stream receive window when nothing sets one.
///
/// Restated rather than read out of quinn, because it is the value the rows
/// compare against and a constant read back from the library under test would
/// track it silently if it ever moved. If a quinn upgrade ever changes it,
/// this file should fail loudly and be corrected by hand.
const DEFAULT_WINDOW: usize = 1_250_000;

/// The size of every write a source makes below.
///
/// Pinned because the stall point is a function of it: a source stalls short
/// of its window by however much of its final write did not fit, so a stall
/// point quoted without the chunk size that produced it states a fixture
/// detail as a transport constant. It is also what makes the measurements
/// quoted on [`DRAIN_CEILING`] granular to 1024 bytes — they are "the last
/// whole write that completed", and the true pend point is somewhere in the
/// kilobyte above each.
const CHUNK: usize = 1024;

/// Objects one stream's egress queue may hold before the proxy stops reading
/// its source.
///
/// The other half of what decides a stall point, and pinned for the same
/// reason as [`CHUNK`]: a source's allowance is its initial window plus
/// whatever the proxy consumed before its read branch shut, and what the proxy
/// can consume first is capped by this count. Two, which is the smallest depth
/// that still distinguishes "queued and stalled" from "never started". The
/// type defaults to 256, which would let the proxy absorb the whole fixture.
const QUEUE_DEPTH: usize = 2;

/// Bytes one stream's egress queue may hold.
///
/// Restated at the type's own default rather than left unsaid. It is
/// deliberately **not** the binding limit — [`QUEUE_DEPTH`] objects of
/// [`OBJECT_PAYLOAD`] bytes is 16 KiB against this 1 MiB — because a byte
/// depth that bit first would make the stall point a function of the payload
/// size instead of a function of a count, and a count is the only one of the
/// two that load cannot move.
const QUEUE_BYTES: usize = 1024 * 1024;

/// The payload each fixture object carries.
///
/// 8192 rather than something smaller, and the reason is arithmetic rather
/// than taste: the forwarding pipe reads into an 8 KiB buffer, so an object
/// whose wire size is at or above that buffer cannot be completed twice by one
/// read. That is what keeps what the proxy consumes a small multiple of
/// [`QUEUE_DEPTH`] rather than of the whole stream.
const OBJECT_PAYLOAD: usize = 8192;

/// How far past its window a source may get before a row calls the fixture
/// broken.
///
/// The quantity being bounded is what the proxy read before its queue filled,
/// which is derived from a count, so load can only push it down.
///
/// Measured with these fixtures, writing [`CHUNK`]-byte pieces until one of
/// them fails to complete in 400 ms:
///
/// | window | last whole write that completed | past the window |
/// |---|---|---|
/// | 65 536 | **81 920** | 16 384 |
/// | 1 250 000 (quinn's default) | **1 249 280** | −720 |
///
/// The 16 KiB overshoot on the narrow arm is a five-byte stream header, two
/// whole objects and the partial read that filled the queue, re-advertised as
/// `MAX_STREAM_DATA` once the proxy had consumed a quarter of a 64 KiB window.
/// The default arm is *short* of its window rather than past it for the same
/// reason read the other way: 16 KiB out of 1.25 MB is not enough consumption
/// to buy another grant, so nothing is re-advertised and what is left is the
/// tail of the last write that did not fit.
///
/// 64 KiB is 4x the larger of the two overshoots, and the quantity is derived
/// from a count rather than from a clock, so load can only shrink it.
///
/// Widen this, do not delete it: it is the upper half of a bracket, and the
/// bracket is what turns "the source stalled somewhere" into "the source
/// stalled at its window".
const DRAIN_CEILING: usize = 64 * 1024;

/// The one length the two arms of
/// [`a_transport_profile_reaches_the_next_client_and_never_the_one_already_connected`]
/// are both measured at.
///
/// Above everything a 64 KiB source can reach — 131 072 against a measured
/// 81 920 — and far below everything a default-window source can reach. That
/// is what makes "this arm took it and that arm did not" a statement about the
/// two windows rather than about where either happened to stop.
const CROSS: usize = SMALL_WINDOW + DRAIN_CEILING;

/// The liveness anchor a default-window arm uses.
///
/// 1 MiB: strictly below both [`DEFAULT_WINDOW`] and the 1 249 280 bytes
/// [`CHUNK`]-byte writes actually reach under it, so "this completed" is a
/// claim about the window rather than about the fixture running out of bytes
/// to offer. The margin is not load-sensitive — flow-control credit is granted
/// by the transport parameters at the handshake, so a slow box delays the
/// write and cannot shrink the allowance.
const WIDE_PUSH: usize = 1024 * 1024;

/// Where a default-window arm's negative claim is made.
///
/// The same bracket [`DRAIN_CEILING`] gives the narrow arms, applied to the
/// default window: 1 315 536 bytes against a measured 1 249 280, a margin of
/// 66 KiB.
const DEFAULT_CEILING: usize = DEFAULT_WINDOW + DRAIN_CEILING;

/// Objects the fixture stream carries — enough that [`DEFAULT_CEILING`] bytes
/// of it exist to be offered, with room to spare.
const FIXTURE_OBJECTS: u64 = 200;

/// How long a write that must **not** complete is given to prove it.
///
/// A negative claim needs a window, not a poll. Load can only make the claim
/// more true, so the only thing this number costs is wall time.
const STALL_WINDOW: Duration = Duration::from_millis(500);

/// A profile whose single catch-all class is charged to a bucket that never
/// grants, over a queue of [`QUEUE_DEPTH`] objects under `Overflow::Block`.
///
/// `rate_bps: Some(0)` with a zero burst is legal and is not the same as
/// `None`: the bucket never refills and is spent before the first unit, so
/// nothing is ever grantable and nothing a row does reopens the drain. That is
/// the state every window row needs — the proxy's read branch shut and staying
/// shut — reached from configuration alone, with no hook and no observer.
///
/// `Overflow::Block` rather than a dropping policy, because a queue that
/// discarded would never stop the read and there would be no stall to measure
/// at all.
fn dry_bucket_profile() -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = "media".to_string();
    bucket.rate_bps = Some(0);
    bucket.burst_bytes = 0;

    let mut class = ClassRule::default();
    class.name = "all".to_string();
    class.bucket = "media".to_string();
    // All-`None`, which claims every unit. Spelled out because "this class
    // matches everything" is load-bearing here rather than an omission.
    class.matcher = Matcher::default();

    let mut queue = QueueConfig::default();
    queue.depth_objects = QUEUE_DEPTH;
    queue.depth_bytes = QUEUE_BYTES;
    // A queued object that outlives `max_hold` is delivered anyway under the
    // default `Expiry::Deliver`, which would reopen the drain and therefore
    // reopen the read. Thirty seconds against rows that finish in about two is
    // the separation, and it is written down rather than inherited so the
    // margin is a number this file chose.
    queue.max_hold = Some(STARVED_HOLD);
    queue.overflow = Overflow::Block;

    ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("one catch-all class over the one bucket it names")
}

/// A [`TransportProfile`] whose only departure from the default is the
/// per-stream receive window.
fn stream_window(bytes: usize) -> TransportProfile {
    // `#[non_exhaustive]`, so `default()` then field assignment is the only
    // construction form available to a test crate.
    let mut profile = TransportProfile::default();
    profile.stream_receive_window = Some(bytes as u64);
    profile
}

/// The whole fixture stream on `track_alias`: a subgroup header followed by
/// [`FIXTURE_OBJECTS`] objects of [`OBJECT_PAYLOAD`] bytes each, concatenated.
///
/// One writer over one pass, because object IDs are delta-encoded on the wire
/// from draft 14 on and a stream assembled from separately encoded pieces
/// would encode a delta against nothing.
fn window_fixture(track_alias: u64) -> Vec<u8> {
    let (head, objects) = subgroup_pieces(track_alias, FIXTURE_OBJECTS, OBJECT_PAYLOAD);
    let mut out = head;
    for object in &objects {
        out.extend_from_slice(object);
    }
    assert!(
        out.len() > DEFAULT_CEILING,
        "the fixture has to be able to offer more than a default window absorbs, or a \
         default-window row proves only that it ran out of bytes: {} against {DEFAULT_CEILING}",
        out.len()
    );
    out
}

/// The header length every window row waits for at its destination.
fn head_len() -> usize {
    subgroup_header(1).len()
}

/// Offer `data` to `send` in [`CHUNK`]-byte writes, and report whether the
/// whole of it went in within `window`.
///
/// The chunking is the point: see [`CHUNK`]. A `false` means the source was
/// still writing when the window closed, which is the only thing any negative
/// claim here asserts — how far it got is deliberately not measured, and the
/// partial final write is why no row writes on a stream again after a `false`.
async fn offer(send: &mut quinn::SendStream, data: &[u8], window: Duration) -> bool {
    let write = async {
        for chunk in data.chunks(CHUNK) {
            send.write_all(chunk)
                .await
                .expect("the source's write failed rather than pending: its leg went away");
        }
    };
    tokio::time::timeout(window, write).await.is_ok()
}

/// The destination leg is being read, and is carrying nothing but the stream
/// header.
///
/// Every window row's negative claim is "the source stalled", and on its own
/// that sentence is equally true of a fixture whose destination nobody is
/// draining: a proxy blocked on its own write stops reading its source in
/// exactly the way a shaper does, and the two are indistinguishable from the
/// source. So each row also watches the far end.
///
/// The header is the right thing to wait for because it carries no
/// `ObjectMeta` — no rule claims it and no bucket charges it — so it is
/// through even on a class that never grants, while every object behind it is
/// held. A destination that is being read, is open, and has nothing but its
/// header on it can only be a shaper holding.
async fn assert_drained_and_holding(rx: &common::TimedReceiver, leg: &str) {
    let head = head_len();
    assert_eq!(
        rx.wait_for_bytes(head).await.len(),
        head,
        "the {leg} destination stream never carried its header, so nothing below it is \
         attributable to the shaper"
    );
    common::assert_no_bytes_for(rx, SETTLE).await;
    assert_eq!(
        rx.len(),
        head,
        "the {leg} destination is drained and holds nothing but its header, so the source's \
         stall is the shaper's and not a proxy blocked on its own write"
    );
}

/// A relay that accepts every connection and **reads** every stream forwarded
/// to it.
///
/// [`holding_relay`] accepts connections and leaves their streams alone, which
/// is all the transport rows above need. A window row needs more than that:
/// the whole point of [`assert_drained_and_holding`] is that the destination
/// leg is being drained, and a relay that never accepted a forwarded stream
/// could not say so. `common::FakeRelay` cannot stand in either — it accepts
/// one connection and hands its streams out one at a time, and the
/// retro-application row below runs two sessions at once.
struct DrainingRelay {
    addr: SocketAddr,
    /// Every connection accepted, in accept order, so a row can push *towards*
    /// the proxy as well as watch what arrives.
    conns: Arc<Mutex<Vec<quinn::Connection>>>,
    /// Every stream forwarded here, in arrival order, each with a reader
    /// already running on it. Behind `Arc`s so a row can hold one while the
    /// list grows.
    forwarded: Arc<Mutex<Vec<Arc<common::TimedReceiver>>>>,
    /// Held, not used: dropping a quinn endpoint stops it accepting.
    _endpoint: quinn::Endpoint,
    _accepting: tokio::task::JoinHandle<()>,
}

impl DrainingRelay {
    fn bind() -> Self {
        common::init_crypto();
        let (endpoint, addr) = common::spawn_quic_server(&[ALPN]);
        let conns: Arc<Mutex<Vec<quinn::Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let forwarded: Arc<Mutex<Vec<Arc<common::TimedReceiver>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let acceptor = endpoint.clone();
        let conn_sink = Arc::clone(&conns);
        let stream_sink = Arc::clone(&forwarded);
        let accepting = tokio::spawn(async move {
            while let Some(incoming) = acceptor.accept().await {
                let Ok(conn) = incoming.await else { continue };
                conn_sink.lock().expect("relay connections").push(conn.clone());
                let stream_sink = Arc::clone(&stream_sink);
                // One reader task per connection, so several sessions are
                // drained at once. It holds its own clone of the connection,
                // which is what keeps that connection alive for the run.
                tokio::spawn(async move {
                    while let Ok(recv) = conn.accept_uni().await {
                        stream_sink
                            .lock()
                            .expect("forwarded streams")
                            .push(Arc::new(common::TimedReceiver::spawn(recv)));
                    }
                });
            }
        });

        Self { addr, conns, forwarded, _endpoint: endpoint, _accepting: accepting }
    }

    /// The `n`th connection this relay accepted, once it has one.
    async fn connection(&self, n: usize) -> quinn::Connection {
        let what = format!("relay connection {n}");
        wait_for(&what, || self.conns.lock().expect("relay connections").get(n).cloned()).await
    }

    /// The `n`th stream forwarded here, once it exists.
    async fn forwarded(&self, n: usize) -> Arc<common::TimedReceiver> {
        let what = format!("forwarded stream {n}");
        wait_for(&what, || self.forwarded.lock().expect("forwarded streams").get(n).cloned()).await
    }
}

/// A proxy in front of `relay` whose every session is shaped by
/// [`dry_bucket_profile`], so that its read branch shuts and stays shut.
fn windowed_proxy(relay: SocketAddr) -> TransparentProxy {
    let mut session = common::session_config(DRAFT, relay);
    session.shape = Some(dry_bucket_profile());
    TransparentProxy::new(proxy_config(session), Arc::new(NoOpProxyObserver))
}

// ── a transport profile does not reach backwards ────────────────────

/// A per-stream receive window set on the client leg reaches the next client
/// to connect, and leaves the connection that already exists on the window it
/// negotiated.
///
/// Both arms run the same proxy, the same dry-bucket profile, the same
/// [`QUEUE_DEPTH`]-object queue, the same [`CHUNK`]-byte writes and the same
/// fixture stream. One `set_transport` call sits between them, and it is the
/// only difference.
///
/// # What each arm asserts, and why neither is a stall detector
///
/// The arm connected **before** the call brackets its stall against the
/// default window: 1 MiB goes in, and [`DEFAULT_CEILING`] bytes do not go in
/// within [`STALL_WINDOW`]. The arm connected **after** it brackets its stall
/// against 64 KiB: [`SMALL_WINDOW`] bytes go in, and [`CROSS`] bytes do not.
/// Four claims, every one of them either a liveness anchor or a negative claim
/// over a window, and no number here is a measured stall point.
///
/// The cross-arm inequality is stated at one length, [`CROSS`]: the older
/// connection wrote it and the newer one could not. That is what makes the row
/// a statement about *when each connection was made* rather than two unrelated
/// brackets that happen to sit at different scales.
///
/// # Ablations, both run
///
/// **(a) Store the profile and never read it.** Delete the install from
/// `ControlPlane::set_client_transport`, keeping the store, so a request lands
/// in the plane and never on the endpoint. The late client then negotiates
/// quinn's default and writes straight past the ceiling:
///
/// ```text
/// a client that connected after the call negotiated the 65536-byte window, so
/// 131072 bytes must not go in — they did
/// ```
///
/// **(b) Retro-apply the profile to the connection that already exists.** This
/// one has no source-level form, and that is a fact about quinn rather than
/// about the proxy: a connection takes its `TransportConfig` once at setup,
/// the only per-connection window setter quinn exposes is the connection-level
/// `set_receive_window`, and a *shrink* there is booked as a debt worked off
/// against future grants because credit already advertised in
/// `MAX_STREAM_DATA` cannot be retracted. There is no edit to this crate that
/// makes a live connection feel a smaller per-stream window. So the ablation
/// was run against the fixture instead, which produces exactly the observable
/// a retro-applying implementation would: connect the first client *after* the
/// call rather than before it, changing nothing else. The cross-arm anchor
/// reddens at once:
///
/// ```text
/// a connection on quinn's default window takes 131072 bytes whatever the
/// shaper does
/// ```
#[tokio::test]
async fn a_transport_profile_reaches_the_next_client_and_never_the_one_already_connected() {
    common::init_crypto();
    let stream = window_fixture(1);
    let relay = DrainingRelay::bind();
    let proxy = Arc::new(windowed_proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    // ── the arm that connected first, on quinn's defaults ──
    let (_early_ep, early) = common::connect_client(addr, ALPN).await;
    wait_for("the first session", || live_count(&control, 1)).await;
    let mut early_send = early.open_uni().await.expect("open_uni");

    let early_took_cross = offer(&mut early_send, &stream[..CROSS], PATIENCE).await;
    assert!(
        early_took_cross,
        "a connection on quinn's default window takes {CROSS} bytes whatever the shaper does"
    );
    let early_dest = relay.forwarded(0).await;
    assert_drained_and_holding(&early_dest, "first session's").await;

    assert!(
        offer(&mut early_send, &stream[CROSS..WIDE_PUSH], PATIENCE).await,
        "the default window's worth goes in: {WIDE_PUSH} bytes against a {DEFAULT_WINDOW}-byte \
         window — if this ever stops being true the comparison below has nothing to compare"
    );
    assert!(
        !offer(&mut early_send, &stream[WIDE_PUSH..DEFAULT_CEILING], STALL_WINDOW).await,
        "and the bytes past it do not: {DEFAULT_CEILING} bytes went into a {DEFAULT_WINDOW}-byte \
         window plus a queue of {QUEUE_DEPTH} objects"
    );

    // ── one call, and nothing else changes ──
    control
        .set_transport(Leg::Client, stream_window(SMALL_WINDOW))
        .expect("a valid profile is installed");

    // ── the arm that connected afterwards ──
    let (_late_ep, late) = common::connect_client(addr, ALPN).await;
    wait_for("the second session", || live_count(&control, 2)).await;
    let mut late_send = late.open_uni().await.expect("open_uni");

    assert!(
        offer(&mut late_send, &stream[..SMALL_WINDOW], PATIENCE).await,
        "a source may always push its initial window, whatever the shaper does"
    );
    let late_dest = relay.forwarded(1).await;
    assert_drained_and_holding(&late_dest, "second session's").await;

    let late_took_cross = offer(&mut late_send, &stream[SMALL_WINDOW..CROSS], STALL_WINDOW).await;
    assert!(
        !late_took_cross,
        "a client that connected after the call negotiated the {SMALL_WINDOW}-byte window, so \
         {CROSS} bytes must not go in — they did"
    );

    // The cross-arm claim, spelled out at the one length both arms were
    // measured at rather than left to be inferred from two brackets.
    assert!(
        early_took_cross && !late_took_cross,
        "the connection made before the call still has the window it negotiated, so {CROSS} bytes \
         go into it (they did: {early_took_cross}) and not into the one made after it (they did: \
         {late_took_cross})"
    );

    early.close(0u32.into(), b"done");
    late.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── one leg only ───────────────────────────────────────────────────────

/// A window set on the client leg reaches the client leg and leaves the relay
/// leg on quinn's defaults.
///
/// One session, one shaper, one fixture, [`CHUNK`]-byte writes and a
/// [`QUEUE_DEPTH`]-object queue on both directions — and one call, naming
/// [`Leg::Client`]. The two legs are then measured the same way and answer
/// differently.
///
/// The client-leg half is the same bracket the row above makes of its late
/// arm:
/// [`SMALL_WINDOW`] goes in, [`CROSS`] does not. The relay-leg half is the
/// other side of the same length — the relay writes [`CROSS`] into the proxy
/// and it goes in — followed by its own bracket against the default window, so
/// that "pends strictly later" is a claim about *where* it stalls and not
/// merely that it had not stalled yet.
///
/// # Why the relay is the source on that leg
///
/// The upstream leg's transport parameters are what the proxy's relay-facing
/// endpoint advertises, so the source they bound is the relay writing
/// *towards* the proxy. Media on MoQT flows that way anyway; this row's client
/// is the source on one leg and its relay is the source on the other, and
/// neither direction is a special case in the forwarding path.
///
/// *Ablation, recorded:* make `set_transport`'s `Leg::Client` arm store the
/// profile as the upstream profile as well, so one call reaches both legs. The
/// relay-leg anchor reddens:
///
/// ```text
/// the relay leg was never named, so it keeps quinn's 1250000-byte window and
/// takes the 131072 bytes the client leg could not
/// ```
#[tokio::test]
async fn a_window_set_on_one_leg_leaves_the_other_leg_on_quinns_defaults() {
    common::init_crypto();
    let stream = window_fixture(1);
    let relay = DrainingRelay::bind();
    let proxy = Arc::new(windowed_proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    control
        .set_transport(Leg::Client, stream_window(SMALL_WINDOW))
        .expect("a valid profile is installed");

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    wait_for("the session", || live_count(&control, 1)).await;

    // ── the leg the profile named ──
    let mut from_client = client.open_uni().await.expect("open_uni");
    assert!(
        offer(&mut from_client, &stream[..SMALL_WINDOW], PATIENCE).await,
        "the configured window's worth goes into the leg it was set on"
    );
    let client_leg_dest = relay.forwarded(0).await;
    assert_drained_and_holding(&client_leg_dest, "client leg's").await;

    let client_leg_took_cross =
        offer(&mut from_client, &stream[SMALL_WINDOW..CROSS], STALL_WINDOW).await;
    assert!(
        !client_leg_took_cross,
        "and the bytes past it do not: {CROSS} bytes went into a {SMALL_WINDOW}-byte window plus \
         a queue of {QUEUE_DEPTH} objects"
    );

    // ── the leg it did not ──
    let relay_conn = relay.connection(0).await;
    let mut from_relay = relay_conn.open_uni().await.expect("relay open_uni");

    let relay_leg_took_cross = offer(&mut from_relay, &stream[..CROSS], PATIENCE).await;
    assert!(
        relay_leg_took_cross,
        "the relay leg was never named, so it keeps quinn's {DEFAULT_WINDOW}-byte window and \
         takes the {CROSS} bytes the client leg could not"
    );
    let to_client = common::TimedReceiver::spawn(
        tokio::time::timeout(common::TIMEOUT, client.accept_uni())
            .await
            .expect("the proxy opened a destination stream towards the client")
            .expect("accept_uni"),
    );
    assert_drained_and_holding(&to_client, "relay leg's").await;

    assert!(
        offer(&mut from_relay, &stream[CROSS..WIDE_PUSH], PATIENCE).await,
        "the default window's worth goes into the relay leg: {WIDE_PUSH} bytes"
    );
    assert!(
        !offer(&mut from_relay, &stream[WIDE_PUSH..DEFAULT_CEILING], STALL_WINDOW).await,
        "the relay leg pends at the default window rather than at no window at all: \
         {DEFAULT_CEILING} bytes went in"
    );

    // The cross-leg claim, at the one length both legs were measured at.
    assert!(
        !client_leg_took_cross && relay_leg_took_cross,
        "a profile naming one leg reaches that leg only: at {CROSS} bytes the client leg is not \
         still writing ({client_leg_took_cross}) and the relay leg is ({relay_leg_took_cross})"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── an impairment on the relay leg's socket ─────────────────────────

/// Objects the relay pushes before the impairment is armed.
#[cfg(feature = "impair")]
const FIRST_BATCH: usize = 4;

/// Objects it pushes afterwards, and which arrive once it is cleared.
#[cfg(feature = "impair")]
const SECOND_BATCH: usize = 4;

/// An impairment armed on the relay leg stops the objects reaching the client,
/// and clearing it lets them through.
///
/// The socket seam is the relay leg's, so what is blackholed is the leg between
/// the proxy and the relay — and what is observed is the far end of a
/// *different* leg, the objects arriving at the client. That is the whole
/// claim: an impairment on one leg's socket reaches the traffic crossing it,
/// and the consequence is visible where that traffic was going.
///
/// Loss is `EveryNth { n: 1 }` on both directions rather than a probability, so
/// the fixture consumes no random draws and cannot flake on a seed.
///
/// The recovery half is not decoration. Without it the row would pass equally
/// for an impairment that killed the connection outright, which is a different
/// thing from one that dropped its datagrams — a dead relay leg would also
/// deliver no objects, and would deliver none afterwards either.
///
/// # The window, and the direction load can push it
///
/// "Nothing arrived" is asserted over [`SETTLE`], and load can only make it
/// more true. The batches either side of it are waited for with anchored polls
/// against a [`PATIENCE`] ceiling, so a slow box makes this row slower and
/// never wrong. Nothing here measures how long a retransmission took.
///
/// *Ablation, recorded:* make `ProxyControl::set_impair` return `Ok(())`
/// without arming the handle, so the profile is stored and never installed on
/// the socket. The objects keep flowing and the row fails with
///
/// ```text
/// assertion `left == right` failed: with every datagram on the relay leg
/// dropped, no object written afterwards reaches the client
///   left: 8
///  right: 4
/// ```
#[cfg(feature = "impair")]
#[tokio::test]
async fn an_impairment_on_the_relay_leg_stops_the_objects_and_clearing_it_resumes_them() {
    use quinn_netem::{DirectionProfile, ImpairProfile, LossModel};

    common::init_crypto();
    let relay = Arc::new(common::FakeRelay::bind(ALPN));
    let seam = common::impaired_seam(ImpairProfile::default());

    let mut proxy = TransparentProxy::new(
        proxy_config(common::session_config(DRAFT, relay.addr)),
        Arc::new(NoOpProxyObserver),
    );
    proxy.set_impaired_socket(
        Leg::Upstream,
        Arc::clone(&seam.socket) as Arc<dyn quinn::AsyncUdpSocket>,
        seam.handle.clone(),
    );
    let proxy = Arc::new(proxy);
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy dialled the relay");
    assert_eq!(
        relay_conn.remote_address(),
        seam.addr,
        "the relay leg was made from {} instead of from the socket the proxy was handed, so \
         nothing armed on that socket could reach it",
        relay_conn.remote_address()
    );

    // The relay is the publisher here: objects flow relay -> proxy -> client,
    // which is the direction the seam sits in.
    let (head, objects) = subgroup_pieces(1, (FIRST_BATCH + SECOND_BATCH) as u64, 64);
    let mut push = relay.open_uni().await;
    push.write_all(&head).await.expect("write header");
    for object in &objects[..FIRST_BATCH] {
        push.write_all(object).await.expect("write object");
    }

    let rx = common::TimedReceiver::spawn(
        tokio::time::timeout(common::TIMEOUT, client.accept_uni())
            .await
            .expect("the proxy opened a destination stream towards the client")
            .expect("accept_uni"),
    );
    wait_for("the first batch to reach the client", || {
        (rx.into_objects(DRAFT).len() >= FIRST_BATCH).then_some(())
    })
    .await;

    let every_datagram =
        DirectionProfile { loss: Some(LossModel::EveryNth { n: 1 }), ..Default::default() };
    let blackhole = ImpairProfile {
        downlink: every_datagram.clone(),
        uplink: every_datagram,
        ..Default::default()
    };
    control.set_impair(Leg::Upstream, blackhole).expect("a valid profile arms");

    // Read after arming and after the first batch has fully landed, so nothing
    // is still in the proxy's pipeline to arrive and spoil the count.
    let before = rx.into_objects(DRAFT).len();
    assert_eq!(before, FIRST_BATCH, "the first batch crossed an unimpaired relay leg intact");

    for object in &objects[FIRST_BATCH..] {
        push.write_all(object).await.expect("write object");
    }
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        rx.into_objects(DRAFT).len(),
        before,
        "with every datagram on the relay leg dropped, no object written afterwards reaches the \
         client"
    );

    control.clear_impair(Leg::Upstream);
    wait_for("the second batch once the impairment is cleared", || {
        (rx.into_objects(DRAFT).len() == FIRST_BATCH + SECOND_BATCH).then_some(())
    })
    .await;

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

// ── the WebTransport refusal, against a server that speaks it ─────────

/// What the client sends through the WebTransport row's proxy, to be compared
/// at the upstream.
#[cfg(feature = "webtransport")]
const WT_PAYLOAD: &[u8] = b"a client stream forwarded to a WebTransport upstream";

/// A `wtransport` server standing in for a WebTransport relay, with its accept
/// already in flight.
///
/// The same fixture `webtransport_upstream.rs` stands up, restated here
/// because an integration test binary is its own crate and cannot import
/// another one's helpers. Keep the two in step: if that file's server ever
/// changes shape, this is the other place it lives.
#[cfg(feature = "webtransport")]
struct WtUpstream {
    /// The address to build the session's URL from.
    addr: SocketAddr,
    /// The accept, spawned before the proxy dials.
    accept: tokio::task::JoinHandle<wtransport::Connection>,
    /// Owns the endpoint for the length of the run. Dropping it tears the
    /// server down, and `wtransport::Endpoint` is not `Clone`, so the accept
    /// task holds a second `Arc` rather than a copy.
    _endpoint: Arc<wtransport::Endpoint<wtransport::endpoint::endpoint_side::Server>>,
}

/// Bind a `wtransport` server on an ephemeral loopback port and start
/// accepting.
///
/// The accept is spawned here rather than awaited by the caller because quinn
/// does not progress an incoming handshake until the application accepts it. A
/// server that only accepted once the test asked it to would make "the session
/// never connected" true whether or not the proxy dialled.
///
/// The identity is the same fresh self-signed `localhost` pair every other
/// fixture in this crate uses, converted into `wtransport`'s own types rather
/// than generated by `Identity::self_signed` — that constructor is behind a
/// `wtransport` feature this workspace does not enable, and the certificate is
/// never verified anyway: the session sets `skip_upstream_cert_verify`.
#[cfg(feature = "webtransport")]
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

/// Read the next unidirectional stream at a WebTransport upstream to its FIN.
#[cfg(feature = "webtransport")]
async fn read_wt_uni(conn: &wtransport::Connection) -> Vec<u8> {
    let mut recv = conn.accept_uni().await.expect("the upstream accepted a forwarded stream");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Some(n) = recv.read(&mut buf).await.expect("read") {
        got.extend_from_slice(&buf[..n]);
    }
    got
}

/// A proxy whose relay leg is a live WebTransport session refuses a transport
/// profile on that leg, takes the same one on its client leg, and keeps
/// forwarding.
///
/// The refusal is stated elsewhere in this file against a proxy configured for
/// a URL nobody answers. This row makes it against a relay leg that is **up**:
/// a real `wtransport::Endpoint::server` has completed the HTTP/3 SETTINGS and
/// extended-CONNECT exchange with this proxy before the call is made. The
/// difference matters because the alternative to refusing is storing the
/// profile and ignoring it, and a proxy with no upstream at all cannot tell
/// the two apart — there is no live leg for a stored profile to fail to reach.
///
/// Three observations, and the second and third are what stop the first being
/// a proxy that refuses everything:
///
/// * the relay leg refuses, naming the leg and the transport, so a caller
///   knows it is the upstream's transport and not the profile at fault;
/// * the client leg takes the identical profile, because it is QUIC whatever
///   the upstream is — the refusal is per leg, not per proxy;
/// * the client's stream still crosses the WebTransport leg and arrives byte
///   for byte, so the refusal left the session exactly as it was.
///
/// *Ablation, recorded:* replace the `Leg::Upstream` WebTransport arm of
/// `ProxyControl::set_transport` with `Ok(())`, which is the "store it and say
/// nothing" outcome this refusal exists to prevent. The row fails with
///
/// ```text
/// assertion `left == right` failed: a WebTransport relay leg has no endpoint
/// to install transport parameters on, so the request is refused rather than
/// accepted and dropped
///   left: Ok(())
///  right: Err(Unsupported { what: "transport profile", leg: Upstream, transport: "webtransport" })
/// ```
#[cfg(feature = "webtransport")]
#[tokio::test]
async fn a_live_webtransport_relay_leg_refuses_a_transport_profile_and_keeps_forwarding() {
    common::init_crypto();
    let upstream = wt_upstream();

    let mut session = common::session_config(DRAFT, upstream.addr);
    session.upstream_transport =
        UpstreamTransportType::WebTransport { url: format!("https://{}/moq", upstream.addr) };
    let proxy = Arc::new(TransparentProxy::new(proxy_config(session), Arc::new(NoOpProxyObserver)));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    let upstream_conn = tokio::time::timeout(PATIENCE, upstream.accept)
        .await
        .expect("the proxy completed a WebTransport handshake with the upstream")
        .expect("the upstream's accept task");

    let profile = stream_window(SMALL_WINDOW);
    assert_eq!(
        control.set_transport(Leg::Upstream, profile.clone()),
        Err(ControlError::Unsupported {
            what: "transport profile",
            leg: Leg::Upstream,
            transport: "webtransport",
        }),
        "a WebTransport relay leg has no endpoint to install transport parameters on, so the \
         request is refused rather than accepted and dropped"
    );
    assert_eq!(
        control.set_transport(Leg::Client, profile),
        Ok(()),
        "the client leg is QUIC whatever the upstream is, so the same profile is installed there \
         — the refusal above is about one leg's transport and not about this proxy"
    );

    // The consequence: the refused leg is the leg it always was.
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(WT_PAYLOAD).await.expect("write_all");
    send.finish().expect("finish");
    let delivered = tokio::time::timeout(PATIENCE, read_wt_uni(&upstream_conn))
        .await
        .expect("the forwarded stream reached the WebTransport upstream");
    assert_eq!(
        delivered, WT_PAYLOAD,
        "a refused profile leaves the leg exactly as it was, so the stream the client wrote after \
         it still crosses the WebTransport relay leg intact"
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

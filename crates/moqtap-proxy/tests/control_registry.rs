//! What a `ProxyControl` can be *seen* to report about a proxy that is
//! already running.
//!
//! Both claims here are only interesting because they are about a proxy
//! nobody can otherwise reach. `TransparentProxy::run` does not return while
//! the proxy is useful, so every question below is asked through a handle
//! taken **before** the accept loop was awaited, while that loop is running
//! and the caller's own thread of control is somewhere else entirely.
//!
//! # Neither claim is checked by reading a value back
//!
//! A handle that answered every question out of the configuration it was
//! built from would pass a test written as "ask, then compare with what you
//! configured", and it would be useless: the two facts worth having from a
//! running proxy are precisely the ones the configuration does not contain.
//! So each claim here is pinned to a consequence instead.
//!
//! The census is pinned to *which sessions are forwarding*. Two clients
//! connect and one goes away, and the four readings are compared as a whole
//! sequence — `[]`, `[1]`, `[1, 2]`, `[2]` — rather than as four independent
//! containment checks. That whole-sequence form is what separates the two
//! opposite ways to be wrong, because neither is visible from a single
//! reading: a list that keeps every id it has ever seen reads `[1, 2]` at
//! the end, and a list that forgets a session while it is still forwarding
//! reads `[]` or `[1]`. A `contains` assertion is satisfied by the first of
//! those and by any list that names the wrong survivor.
//!
//! The address is pinned to *a client connecting through it*. Nothing here
//! compares the reported address to anything at all — not to the configured
//! `bind_addr`, not to a loopback literal, not even to "some port that is
//! not zero". The proxy is configured with port 0 on purpose, so the only
//! address that could be assembled without asking the operating system is
//! the one address guaranteed not to work, and the way to say that is to
//! dial what came back and watch a session appear on the far side of it.
//!
//! # Wall time
//!
//! Both rows are sub-second on an idle machine: everything either happens
//! immediately or is polled for, and the one duration in the file
//! ([`PATIENCE`]) is a failure ceiling that a correct build never spends.
//!
//! # Why the file is gated on there being a draft at all
//!
//! Neither row parses a MoQT frame — the sessions here forward nothing but a
//! handshake — but a session refuses to start on a draft this build did not
//! compile, so the fixture has to name one the build has. [`DRAFT`] is that
//! draft and the gate is what guarantees there is one.

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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moqtap_codec::version::DraftVersion;
use moqtap_proxy::control::ProxyControl;
use moqtap_proxy::error::ProxyError;
use moqtap_proxy::event::SessionId;
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};

/// How long a poll waits for something a correct build has already done.
///
/// A ceiling and never a measurement: every wait below is for a state a
/// working proxy reaches without being prompted, so load can make these
/// slower and cannot make them wrong.
const PATIENCE: Duration = Duration::from_secs(10);

/// The ALPN both the clients and the fake relay speak. `moq-00` covers
/// drafts 07-14 and is what this crate's other fixtures use.
const ALPN: &[u8] = b"moq-00";

/// The drafts this build compiled, draft-14 first.
///
/// Order rather than a plain list: nothing here frames anything, so any
/// compiled draft serves, and putting 14 first pins the default all-drafts
/// build to draft-14. A reduced build takes whichever one it has instead of
/// configuring a session for a draft it cannot frame — which the session
/// refuses.
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

/// The draft the sessions here are configured for. The file-level gate is
/// what makes this index a compile-time fact rather than a panic.
const DRAFT: DraftVersion = CANDIDATE_DRAFTS[0];

/// A relay that completes handshakes and then does nothing.
///
/// A session registers when it starts running, which is after its upstream
/// connect has returned, so a proxy pointed at a dead address would produce
/// sessions that appeared and vanished in the same breath and a census that
/// was never wrong for long enough to read. This exists so that the sessions
/// under test stay up until their own clients take them down, and nothing
/// else — it never reads a byte.
///
/// It holds **every** connection it accepts rather than the first, which
/// [`common::FakeRelay`] does not: that one resolves a single connection
/// through a `OnceCell`, and the census row below needs two sessions alive
/// at once.
struct FakeRelay {
    /// Where to point the proxy's upstream address.
    addr: SocketAddr,
    /// Held, not used: dropping a quinn endpoint stops it accepting.
    _endpoint: quinn::Endpoint,
    /// Holds every accepted connection open for the life of the test.
    _accepting: tokio::task::JoinHandle<()>,
}

fn fake_relay() -> FakeRelay {
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
    FakeRelay { addr, _endpoint: endpoint, _accepting: accepting }
}

/// A proxy bound to an ephemeral loopback port, forwarding to `upstream`.
///
/// `bind_addr` names port 0 deliberately, in both rows. The port is then
/// chosen by the operating system inside `run()`, which is the situation
/// `local_addr()` exists for and the one that makes an address comparison
/// impossible to write from out here.
fn proxy(upstream: SocketAddr) -> Arc<TransparentProxy> {
    let (cert_chain, key_der) = common::self_signed_localhost();

    let config = ProxyConfig {
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
        session: common::session_config(DRAFT, upstream),
    };

    Arc::new(TransparentProxy::new(config, Arc::new(NoOpProxyObserver)))
}

/// Poll `probe` until it answers, or give up naming what was awaited.
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

/// The live list once it holds exactly `n` ids, whatever those ids are.
///
/// The count is the *settling* condition and never the assertion: the ids
/// themselves go into the recorded sequence, which is compared in one piece
/// at the end of the row. Waiting on a count is what makes the recording
/// deterministic — a bare read would sample a proxy mid-accept — and it is
/// safe to wait on because a census that settles at the wrong length never
/// settles at all, and says so at [`PATIENCE`].
fn census_of(control: &ProxyControl, n: usize) -> Option<Vec<SessionId>> {
    let live = control.sessions();
    (live.len() == n).then_some(live)
}

/// The census names the sessions that are forwarding right now, in full:
/// two connect, one leaves, and the whole sequence of readings is `[]`,
/// `[1]`, `[1, 2]`, `[2]`.
///
/// The four readings are asserted as one value rather than one at a time,
/// so the failure a reader gets is the shape of the whole run instead of
/// whichever step happened to be checked first. The last reading is the one
/// that carries the weight, and it carries it by naming the survivor: a
/// registry that removed *an* entry on any disconnect rather than the right
/// one would still be holding a single id at that point, and it would be
/// `SessionId(1)`.
///
/// # Ablation, run
///
/// Making the registry retain the sessions that have ended — the body of
/// `ControlPlane::end` in `src/control.rs` emptied to `let _ = id;`, so the
/// census hands back every id it has ever been given — leaves the first
/// three readings correct and the fourth permanently `[1, 2]`. The row never
/// reaches its whole-sequence comparison at all; it fails at the last wait,
/// ten seconds in:
///
/// ```text
/// thread 'the_census_names_the_sessions_that_are_forwarding_and_no_others'
/// panicked at crates\moqtap-proxy\tests\control_registry.rs:
/// timed out waiting for the census to drop the session whose client went away
/// ```
///
/// That is the never-removes failure exactly, and nothing else in the file
/// noticed: the address row below passed in that same mutated run. A census
/// read once, at one instant, would have passed too.
#[tokio::test]
async fn the_census_names_the_sessions_that_are_forwarding_and_no_others() {
    common::init_crypto();
    let relay = fake_relay();
    let proxy = proxy(relay.addr);
    let control = proxy.control();

    let running = Arc::clone(&proxy);
    let accept_loop = tokio::spawn(async move { running.run().await });
    let addr = wait_for("the proxy to bind", || control.local_addr().ok()).await;

    // Read straight away rather than polling: a proxy that has accepted
    // nothing is running nothing *now*, and there is no later state for a
    // poll to wait for.
    let mut census = vec![control.sessions()];

    let (first_ep, first) = common::connect_client(addr, ALPN).await;
    census.push(
        wait_for("the first client's session to start forwarding", || census_of(&control, 1)).await,
    );

    let (second_ep, second) = common::connect_client(addr, ALPN).await;
    census.push(
        wait_for("the second client's session to start forwarding", || census_of(&control, 2))
            .await,
    );

    first.close(0u32.into(), b"done");
    drop(first_ep);
    census.push(
        wait_for("the census to drop the session whose client went away", || {
            census_of(&control, 1)
        })
        .await,
    );

    assert_eq!(
        census,
        vec![vec![], vec![SessionId(1)], vec![SessionId(1), SessionId(2)], vec![SessionId(2)],],
        "the census is the set of sessions forwarding at the instant it is read: it starts \
         empty, grows by one per client, and loses exactly the id whose client went away"
    );

    second.close(0u32.into(), b"done");
    drop(second_ep);
    wait_for("the last session to end", || control.sessions().is_empty().then_some(())).await;

    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), accept_loop).await;
}

/// Before the proxy binds there is no address to report, and once it has
/// bound, the address it reports is one a client connects through.
///
/// The proxy is configured with port 0, so what the handle has to produce is
/// a fact that exists nowhere until the operating system supplies it. The
/// claim is therefore made by *use*: the returned address is dialled, the
/// handshake completes, and the session that connection created shows up in
/// the census. Nothing is compared. In particular there is deliberately no
/// `assert_ne!(addr.port(), 0)` — that would pass for an address on the
/// right port and the wrong interface, it would pass for the address of some
/// other endpoint in the process, and it invites the reader to believe a
/// port number is the thing being checked.
///
/// The census reading at the end is not decoration. A handshake alone proves
/// only that *something* was listening where the handle pointed; the session
/// appearing on this proxy's own handle is what makes it this proxy.
///
/// The `NotBound` reading afterwards closes the other end of the window: the
/// endpoint is gone once the accept loop has returned, and a handle that
/// kept reporting its address would be handing out somewhere nothing can be
/// reached.
///
/// # Ablation, run
///
/// Making the handle report the configured address instead of the resolved
/// one — the bound arm of `ProxyControl::local_addr` in `src/control.rs`
/// replaced with `Ok("127.0.0.1:0".parse().expect("literal"))`, which is
/// exactly the `bind_addr` this fixture supplies — leaves both `NotBound`
/// readings correct, because the mutation only speaks while there is a
/// listener to speak about. The dial is what fails:
///
/// ```text
/// thread 'the_reported_address_is_one_a_client_connects_through'
/// panicked at crates\moqtap-proxy\tests\control_registry.rs:
/// a client cannot dial the address the handle reported: invalid remote address: 127.0.0.1:0
/// ```
///
/// The refusal comes from quinn rather than from an assertion, and that is
/// the whole point of dialling rather than comparing: port 0 is not an
/// address a peer can be at, and it is precisely what a handle answering out
/// of its own configuration hands back. The census row above fails in the
/// same mutated run for the same reason, reported from inside the shared
/// harness instead — `crates\moqtap-proxy\tests\common\mod.rs:218:39: client
/// connect: InvalidRemoteAddress(127.0.0.1:0)`.
#[tokio::test]
async fn the_reported_address_is_one_a_client_connects_through() {
    common::init_crypto();
    let relay = fake_relay();
    let proxy = proxy(relay.addr);
    let control = proxy.control();

    assert!(
        matches!(control.local_addr(), Err(ProxyError::NotBound)),
        "a proxy whose accept loop has not been entered has no endpoint, so there is no \
         address to report and none is invented"
    );

    let running = Arc::clone(&proxy);
    let accept_loop = tokio::spawn(async move { running.run().await });

    let addr = wait_for("the proxy to bind", || control.local_addr().ok()).await;

    // Dialled by hand rather than through `common::connect_client`, which
    // reports a refused dial as its own `expect`. The refusal is the
    // observation this row is making, so it is worth the four lines to have
    // it come back saying what was being claimed.
    let client_ep = common::client_endpoint(&[ALPN]);
    let connecting = client_ep
        .connect(addr, "localhost")
        .unwrap_or_else(|e| panic!("a client cannot dial the address the handle reported: {e}"));
    let client = tokio::time::timeout(PATIENCE, connecting)
        .await
        .expect("a client's handshake against the reported address never completed")
        .expect("a client's handshake against the reported address failed");

    let live =
        wait_for("a session on the address the handle reported", || census_of(&control, 1)).await;
    assert_eq!(
        live,
        vec![SessionId(1)],
        "the connection reached *this* proxy — a handshake alone would only say something \
         was listening there"
    );

    client.close(0u32.into(), b"done");
    drop(client_ep);
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), accept_loop).await;

    assert!(
        matches!(control.local_addr(), Err(ProxyError::NotBound)),
        "the endpoint is gone once the accept loop has returned, and the handle says so \
         rather than reporting the address of a listener that no longer exists"
    );
}

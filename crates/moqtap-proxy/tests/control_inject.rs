//! A control message put on a live session by the control plane, seen by the
//! peer's decoder in sequence.
//!
//! `ProxyControl::inject_control` promises something narrower than "the bytes
//! arrive", and the difference is the whole point of this file. It promises
//! that the message lands on the session's **existing control stream**,
//! **between two whole messages**, so that the receiving peer decodes it as a
//! control message and keeps decoding everything that follows. Two
//! implementations that fail that promise both look like working code from the
//! writing side: the write returns `Ok`, the bytes reach the far host, and
//! nothing anywhere reports a problem.
//!
//! # Why the assertion is on decoded messages and not on bytes
//!
//! A byte-level assertion — "the relay's control stream contains these bytes
//! at this offset" — would pass for a proxy that spliced the injection into
//! the middle of another message's payload. The receiving peer would still
//! have received every byte; it would simply have read them as somebody
//! else's payload and then read the *next* message's type field out of the
//! middle of this one. That is the failure mode with the longest blast radius
//! in this crate, because it does not stop the connection: it silently
//! reinterprets every control message for the rest of the session.
//!
//! So the relay here runs a real draft-14 control decoder over its stream and
//! records what it produced, and the gate is an **exact `Vec` equality** over
//! that sequence. A spliced injection cannot satisfy it, because the messages
//! after the splice do not decode at all.
//!
//! # Why the session has to be exchanging messages, not idle
//!
//! An injection into a session where nothing else has ever been written is
//! satisfied by almost any implementation: the control stream is empty, so
//! every offset is a message boundary and there is nothing for the injection
//! to be spliced into. The session below therefore has messages flowing in
//! **both directions** before the call and more of them after it, and the
//! equality covers all of them. The two messages the client writes *after* the
//! injection are what make the claim about the peer's decoder rather than
//! about a single successful write — a decoder that was desynchronized by the
//! injection cannot produce them.
//!
//! # What is deliberately not claimed
//!
//! Not *when* the injection lands. The proxy holds an injection until the
//! stream it is writing is between messages, and how long that is depends on
//! how much of a message the peer had already written — a wait bounded by the
//! peer, not by the proxy. This file pins the *position* in the decoded
//! sequence and synchronises on delivery rather than timing it, so nothing
//! here can be moved by a loaded machine: every wait is an anchored poll that
//! a correct build always completes, and the single sleep is a settle window
//! over a negative claim, which load can only make more true.
//!
//! Not the draft-17-and-later behaviour either. Those drafts carry control
//! messages on unidirectional streams while this proxy forwards the first
//! bidirectional stream as the control stream, so an injection there lands on
//! a request stream and is reported as such. This file is draft 14 throughout
//! — the messages it builds are draft-14 messages and the decoder it asserts
//! with is the draft-14 decoder — so it compiles and runs exactly when that
//! draft does.

#![cfg(feature = "draft14")]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqtap_codec::draft14::message::{
    ClientSetup, ControlMessage, GoAway, MaxRequestId, ServerSetup, Subscribe, Unsubscribe,
};
use moqtap_codec::types::{FilterType, Forward, GroupOrder, TrackNamespace};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::control::ProxyControl;
use moqtap_proxy::event::SessionId;
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};
use moqtap_proxy::transport::Leg;

use tokio::task::JoinHandle;

/// The draft this file speaks, end to end: the messages it encodes, the
/// decoder it asserts with, and the draft the session is configured for.
const DRAFT: DraftVersion = DraftVersion::Draft14;

/// The MoQT version number draft 14 puts in a CLIENT_SETUP.
const DRAFT14_VERSION: u64 = 0xff00_0000 + 14;

/// The ALPN the client and the fake relay speak.
///
/// `moq-00` covers drafts 07-14 and does not resolve to one of them, so the
/// session's draft stays the configured [`DRAFT`] rather than becoming a fact
/// the ALPN settled. That is the posture the proxy tracks control-message
/// boundaries under — against the draft it was configured with — and it is
/// the one an injection has to be placed correctly in.
const ALPN: &[u8] = b"moq-00";

/// How long an anchored poll waits before it gives up and lets the assertion
/// that follows report the shortfall.
///
/// A failure ceiling, never spent by a correct build. Nothing is *timed*
/// against it: every poll here waits on a monotone count that a working proxy
/// always reaches, so load makes this slower and never wrong.
const PATIENCE: Duration = Duration::from_secs(10);

/// The window the one negative claim in this file is made over — that the
/// injection reached the leg it was addressed to and not the other one.
///
/// Load can only make a negative claim more true, so the cost of the number
/// is wall time and nothing else.
const SETTLE: Duration = Duration::from_millis(300);

/// Where the injected message must appear in the sequence the relay decodes.
///
/// Two client messages precede it and two follow it. The index is written
/// down here and used to build the expected sequence below, so the claim
/// "third message decoded, after two and before two more" is one value rather
/// than a position a reader has to count out of a literal.
const INJECTED_AT: usize = 2;

// ── the fixture messages ───────────────────────────────────────────────

/// Frame `msg` the way the control plane requires an injection to be framed:
/// type varint, length field, payload — exactly what
/// `ControlMessage::encode` produces.
///
/// Used for the client's own writes as well as for the injection, so the
/// bytes the proxy forwards and the bytes it injects are built by the same
/// encoder. A test that framed the injection by hand would be asserting
/// against its own idea of the framing rather than against the codec's.
fn framed(msg: &ControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("every fixture message below encodes");
    out
}

/// The first message the client writes; also what creates the control stream
/// on the wire, since quinn does not put a stream there until something is
/// written to it.
fn client_setup() -> ControlMessage {
    ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(DRAFT14_VERSION).expect("a draft-14 version")],
        parameters: Vec::new(),
    })
}

/// The relay's reply, which is what makes the session's control stream busy
/// in *both* directions while the injection is placed.
fn server_setup() -> ControlMessage {
    ControlMessage::ServerSetup(ServerSetup {
        selected_version: VarInt::from_u64(DRAFT14_VERSION).expect("a draft-14 version"),
        parameters: Vec::new(),
    })
}

/// A SUBSCRIBE for `track`, on request id `request_id`.
///
/// The messages on either side of the injection are subscribes because they
/// carry variable-length fields — a namespace, a track name — so a decoder
/// that had lost the framing by one byte would not accidentally produce a
/// well-formed one.
fn subscribe(request_id: u64, track: &[u8]) -> ControlMessage {
    ControlMessage::Subscribe(Subscribe {
        request_id: VarInt::from_u64(request_id).expect("a request id"),
        track_namespace: TrackNamespace(vec![b"live".to_vec()]),
        track_name: track.to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::NextGroupStart,
        start_location: None,
        end_group: None,
        parameters: Vec::new(),
    })
}

/// The message the control plane injects.
///
/// A GOAWAY, chosen because nothing else in this fixture is one and because
/// its payload is a length-prefixed byte string: if the framing were stripped
/// on the way out, the peer would read that length as a message type and the
/// URI's first bytes as a length, which is precisely the desynchronisation
/// this file exists to catch.
fn injected() -> ControlMessage {
    ControlMessage::GoAway(GoAway { new_session_uri: b"moqtap://elsewhere/".to_vec() })
}

/// The relay's second message, written after the injection has been placed.
fn max_request_id() -> ControlMessage {
    ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(64).expect("an id") })
}

/// The last message the client writes.
fn unsubscribe(request_id: u64) -> ControlMessage {
    ControlMessage::Unsubscribe(Unsubscribe {
        request_id: VarInt::from_u64(request_id).expect("a request id"),
    })
}

// ── what a peer decoded ────────────────────────────────────────────────

/// What one [`ControlLog`]'s reader has produced so far.
#[derive(Default)]
struct LogState {
    /// Every whole control message decoded off the stream, in order.
    decoded: Vec<ControlMessage>,
    /// The first decode failure, if the stream ever stopped being a sequence
    /// of framed control messages.
    failure: Option<String>,
}

/// How many bytes the message at the head of `pending` occupies, or `None`
/// while too few bytes have arrived to say.
///
/// This is buffering, not decoding: it exists only so that
/// `ControlMessage::decode` is handed a complete message and never a partial
/// one. That separation is what makes a decode error mean something —
/// `decode` reports "insufficient bytes" for a message that has not fully
/// arrived and for one whose framing is nonsense with the same error, so a
/// reader that simply retried on every error could not tell a slow stream
/// from a desynchronized one, and the failure this file is built to catch is
/// exactly the second.
fn framed_len(pending: &[u8]) -> Option<usize> {
    let type_len = DRAFT.varint_len(*pending.first()?);
    let hi = *pending.get(type_len)? as usize;
    let lo = *pending.get(type_len + 1)? as usize;
    Some(type_len + 2 + ((hi << 8) | lo))
}

/// A live decoder over one peer's half of the control stream.
///
/// Spawned rather than drained at the end, for the same reason
/// `common::TimedReceiver` is: every claim here is about what the peer had
/// decoded *by* some point, and the fixture has to be able to wait for the
/// third message before it writes the fourth. A reader that only ran after
/// the session ended could not order anything.
///
/// Whole messages are assembled by [`framed_len`] and then handed to
/// `ControlMessage::decode`, so "the peer accepted it" is the codec's answer
/// and not this file's. A message that decodes is recorded; anything else
/// stops the reader and is kept as [`ControlLog::failure`], because a decoder
/// that has lost the framing produces nothing further worth asserting on.
struct ControlLog {
    state: Arc<Mutex<LogState>>,
    task: JoinHandle<()>,
}

impl ControlLog {
    /// Start decoding `recv` in the background.
    fn spawn(mut recv: quinn::RecvStream) -> Self {
        assert!(
            DRAFT.uses_fixed_length_framing(),
            "the length field this reader walks is draft 14's 16-bit big-endian one; a draft \
             that frames it as a varint would need a different walk",
        );
        let state = Arc::new(Mutex::new(LogState::default()));
        let sink = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut pending: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => pending.extend_from_slice(&chunk[..n]),
                    // End of stream, or the connection went away. Either way
                    // there are no more messages; whatever was decoded stands.
                    Ok(None) | Err(_) => return,
                }
                while let Some(len) = framed_len(&pending) {
                    if pending.len() < len {
                        break;
                    }
                    let mut cursor = &pending[..len];
                    match ControlMessage::decode(&mut cursor) {
                        Ok(message) => sink.lock().expect("control log").decoded.push(message),
                        Err(e) => {
                            sink.lock().expect("control log").failure = Some(e.to_string());
                            return;
                        }
                    }
                    pending.drain(..len);
                }
            }
        });
        Self { state, task }
    }

    /// Everything decoded so far.
    fn decoded(&self) -> Vec<ControlMessage> {
        self.state.lock().expect("control log").decoded.clone()
    }

    /// How the framing was lost, if it was.
    ///
    /// Folded into the assertion messages below rather than asserted on
    /// separately: an injection written without its framing leaves the
    /// decoder reading a payload as a header, and naming that is the
    /// difference between "the sequence is short" and "the sequence is short
    /// because the stream stopped being control messages here".
    fn failure(&self) -> Option<String> {
        self.state.lock().expect("control log").failure.clone()
    }

    /// Wait until `n` messages have been decoded, and hand back whatever was
    /// decoded either way.
    ///
    /// Returning rather than panicking on the ceiling is deliberate and is
    /// the shape `common::TimedReceiver::wait_for_bytes` already uses: the
    /// caller's `assert_eq!` then reports the sequence that *was* produced
    /// against the one that should have been, which is a far more useful
    /// failure than a bare timeout.
    async fn wait_for(&self, n: usize) -> Vec<ControlMessage> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let seen = self.decoded();
            if seen.len() >= n || Instant::now() >= deadline {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for ControlLog {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── the proxy under test ───────────────────────────────────────────────

/// A proxy bound to an ephemeral loopback port, forwarding to `upstream`.
///
/// `TransparentProxy` rather than a directly constructed `ProxySession`,
/// because a session built directly belongs to no proxy and so to no control
/// plane: it is reachable by nothing this file calls. Port 0 is deliberate —
/// the port is chosen inside `run()`, and `local_addr()` is how the client
/// learns it.
fn proxy(upstream: SocketAddr) -> TransparentProxy {
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
    // `NoOpProxyObserver` and the default `NoOpHook`, which is what puts the
    // control stream on the pass-through pipe. That is the harder of the two
    // paths for an injection: the mutating pipe writes one whole message per
    // write, so its message boundaries come for free, while the pass-through
    // pipe forwards raw read chunks and has to track the framing itself.
    TransparentProxy::new(config, Arc::new(NoOpProxyObserver))
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

/// The id of this proxy's one live session.
async fn only_session(control: &ProxyControl) -> SessionId {
    wait_for("the session to register with the control plane", || {
        let live = control.sessions();
        (live.len() == 1).then(|| live[0])
    })
    .await
}

// ── the gate ───────────────────────────────────────────────────────────

/// An injected control message is decoded by the peer, in order, in the
/// middle of a control stream that is carrying traffic in both directions.
///
/// The relay decodes five messages and the equality names all five: the two
/// the client wrote before the call, the injected one at [`INJECTED_AT`], and
/// the two the client wrote after it. The last two are what turn this from a
/// claim about one write into a claim about the peer's decoder — a decoder
/// left mid-payload by a badly placed injection produces neither of them.
///
/// The companion claim is that the *other* leg is untouched: the client's own
/// decoded sequence is exactly the two messages the relay wrote, with no
/// injection in it. An implementation that wrote to both control directions,
/// or that mapped the leg the wrong way round, fails one of the two halves.
///
/// # Two mutations were run against this, separately
///
/// Both are ways to deliver the bytes and still deliver nothing, and both
/// leave the writing side reporting success. Message payloads are elided
/// below where the real output spelled them out; nothing else is.
///
/// **A fresh unidirectional stream.** In `forward_control_stream`, the
/// upstream request channel was diverted into a task that opened
/// `relay.open_uni()` and wrote each injection there instead of onto the
/// control stream — the simplest implementation that "works", and the one a
/// reader reaches for first, since a new stream needs no boundary tracking at
/// all. The bytes reach the relay host; the relay's control decoder never
/// sees them, because a new unidirectional stream in MoQT is a data stream.
/// This row failed after 20.08 s with
///
/// ```text
/// assertion `left == right` failed: the relay's control decoder produced the
/// injected message in sequence, between the messages written before and after
/// it (decode failure: None)
///   left: [ClientSetup(..), Subscribe(.. track_name "video" ..),
///          Subscribe(.. track_name "audio" ..), Unsubscribe(..)]
///  right: [ClientSetup(..), Subscribe(.. track_name "video" ..), GoAway(..),
///          Subscribe(.. track_name "audio" ..), Unsubscribe(..)]
/// ```
///
/// Four messages instead of five, everything else in place: the two after the
/// injection decode perfectly, because nothing was ever written between them.
/// A test that only counted messages, or only checked that the two later ones
/// arrived, would have passed.
///
/// **No framing.** In `ProxyControl::inject_control`, the message's type
/// varint and 16-bit length were stripped before the bytes were handed to the
/// session, leaving a bare payload — what an implementation that took a
/// payload and added no framing of its own would put on the wire. The write
/// succeeds and the bytes land in the right stream at the right offset; the
/// peer reads the payload's first byte as a message type and its next two as
/// a length, and waits for a message tens of kilobytes long that will never
/// come, swallowing everything the client writes afterwards. This row failed
/// after 20.09 s with
///
/// ```text
/// assertion `left == right` failed: the relay's control decoder produced the
/// injected message in sequence, between the messages written before and after
/// it (decode failure: None)
///   left: [ClientSetup(..), Subscribe(.. track_name "video" ..)]
///  right: [ClientSetup(..), Subscribe(.. track_name "video" ..), GoAway(..),
///          Subscribe(.. track_name "audio" ..), Unsubscribe(..)]
/// ```
///
/// Two messages instead of five. `decode failure: None` is not an oversight
/// in the fixture — the desynchronized decoder never *fails*, it waits, which
/// is precisely why this failure mode is so quiet in production and why the
/// gate is an equality over the whole sequence rather than a check that
/// nothing errored.
///
/// Both mutations were reverted, and the row is green again.
#[tokio::test]
async fn an_injected_control_message_is_decoded_by_the_peer_in_sequence() {
    common::init_crypto();

    let relay = common::FakeRelay::bind(ALPN);
    let proxy = Arc::new(proxy(relay.addr));
    let (control, addr, loop_task) = start(Arc::clone(&proxy)).await;

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    let (mut client_send, client_recv) = client.open_bi().await.expect("the client opens a bi");
    let client_log = ControlLog::spawn(client_recv);

    // ── the flow, before the injection ──
    let setup = client_setup();
    client_send.write_all(&framed(&setup)).await.expect("the client writes CLIENT_SETUP");

    let (mut relay_send, relay_recv) = tokio::time::timeout(PATIENCE, relay.accept_bi())
        .await
        .expect("the proxy opened a control stream toward the relay");
    let relay_log = ControlLog::spawn(relay_recv);

    let id = only_session(&control).await;

    // The relay answers, so the stream is busy in both directions rather than
    // being a one-way pipe with an obvious place to append to.
    let reply = server_setup();
    relay_send.write_all(&framed(&reply)).await.expect("the relay writes SERVER_SETUP");

    let video = subscribe(1, b"video");
    client_send.write_all(&framed(&video)).await.expect("the client writes SUBSCRIBE(video)");

    // Both messages are through before the injection is asked for, which is
    // what makes the position in the decoded sequence a fact rather than a
    // race: an injection requested while a message was still being forwarded
    // would land after it, and this fixture would be asserting on whichever
    // order the select happened to take.
    assert_eq!(
        relay_log.wait_for(2).await,
        vec![setup.clone(), video.clone()],
        "the two messages written before the injection reach the relay in order; without them \
         there is no live flow to inject into and the row below proves only that an empty \
         stream can be written to (decode failure: {:?})",
        relay_log.failure(),
    );
    assert_eq!(
        client_log.wait_for(1).await,
        vec![reply.clone()],
        "the reverse direction is carrying traffic too (decode failure: {:?})",
        client_log.failure(),
    );

    // ── the injection ──
    let goaway = injected();
    control
        .inject_control(id, Leg::Upstream, framed(&goaway))
        .expect("a live session takes an injection for the leg its relay decodes");

    // A synchronisation point, not an assertion: the two messages below must
    // be written after the injection has been placed, or their position in
    // the decoded sequence is whichever branch of the pipe's select ran
    // first. A build that never places it spends the ceiling here and then
    // fails at the equality, which is the failure worth reading.
    let _ = relay_log.wait_for(INJECTED_AT + 1).await;

    // ── the flow, after the injection ──
    let bump = max_request_id();
    relay_send.write_all(&framed(&bump)).await.expect("the relay writes MAX_REQUEST_ID");

    let audio = subscribe(2, b"audio");
    client_send.write_all(&framed(&audio)).await.expect("the client writes SUBSCRIBE(audio)");
    let done = unsubscribe(1);
    client_send.write_all(&framed(&done)).await.expect("the client writes UNSUBSCRIBE");

    // ── what the relay's decoder produced ──
    let mut expected = vec![setup, video, audio, done];
    expected.insert(INJECTED_AT, goaway.clone());

    let seen = relay_log.wait_for(expected.len()).await;
    assert_eq!(
        seen,
        expected,
        "the relay's control decoder produced the injected message in sequence, between the \
         messages written before and after it (decode failure: {:?})",
        relay_log.failure(),
    );
    assert_eq!(
        seen.get(INJECTED_AT),
        Some(&goaway),
        "the injected message is the one at index {INJECTED_AT}",
    );

    // ── and the leg it was not addressed to is untouched ──
    let client_seen = client_log.wait_for(2).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        client_log.decoded(),
        vec![reply, bump],
        "the client decoded exactly what the relay wrote: an injection names one leg, and \
         writing it toward both peers would put a message the relay never sent in front of \
         this decoder (it had {} message(s) when the relay's sequence completed, decode \
         failure: {:?})",
        client_seen.len(),
        client_log.failure(),
    );

    client.close(0u32.into(), b"done");
    proxy.cancel_token().cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
}

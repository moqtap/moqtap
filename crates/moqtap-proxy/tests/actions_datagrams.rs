//! The datagram site, end to end.
//!
//! `forward_datagrams` had **zero** end-to-end coverage before this file:
//! nothing in the repo had ever driven a datagram through a live
//! proxy session. This file starts from nothing, so it asserts the boring
//! things too — that a datagram is forwarded at all, that the hook fires,
//! that a transport refusal does not take the session down.
//!
//! # The independent encoder, and what it is independent *of*
//!
//! [`Action::ReplacePayload`] at this site splices at the offset the
//! engine derives as `data.len() - cursor.len()` after
//! `AnyDatagramHeader::decode`. The claim under test is therefore an
//! **offset**, and an offset cannot be checked by a round trip: a decoder
//! and an encoder that agree on a wrong header length agree on a wrong
//! splice, and the datagram still decodes.
//!
//! So the fixtures here are built by [`datagram_header`], a hand-written
//! per-draft field layout on top of a hand-written QUIC varint encoder
//! ([`varint`], RFC 9000 §16). It shares no code with the thing under
//! test. Because the test *constructs* the header, it knows its length by
//! construction, and `assert_eq!(forwarded, header ++ replacement)` is a
//! direct assertion on the engine's offset arithmetic.
//!
//! Every fixture here opens with the datagram's own type field, on all
//! thirteen drafts. That was not always true: drafts 07-13 model the type
//! separately from `DatagramHeader`, and for a while nothing between the
//! fixtures and the client wrote it, so the whole family put headerless
//! datagrams on the wire and read a peer's type octet as the first byte of
//! its Track Alias. The fixtures were built to match, which is why this
//! file went green over it. The splice offset moved when the codec grew
//! the field and the fixtures moved with it, exactly as the offsets here
//! are meant to.
//!
//! # Where `ReplacePayload` is refused, and why the three cases differ
//!
//! There are exactly three shapes with no derivable payload boundary, and
//! each gets its own `detail` string:
//!
//! | case | why | `detail` |
//! |---|---|---|
//! | **draft-14** | `AnyDatagramHeader` is `DatagramObject`, whose `decode` ends by reading every remaining byte, so `header_len == data.len()` | `"draft-14 header decode consumes the payload"` |
//! | status datagram | no payload slot exists at all | `"status datagram has no payload"` |
//! | undecodable header | the hook still fires, but there is nothing to splice after | `"datagram header did not decode"` |
//!
//! The draft-14 case is the one that would go wrong quietly: a splice at
//! `data.len() - cursor.len()` there is a splice at the *end*, producing
//! `header ++ old_payload ++ new_payload` — a datagram that decodes fine
//! and carries both payloads.
//!
//! # Which drafts this file covers
//!
//! [`DELIMITED`] is cfg-built, so the twelve-draft splice sweep is really
//! "every compiled draft whose datagram header delimits its payload".
//! [`STATUS_DRAFTS`] is the same idea for the five drafts that have a
//! status datagram. Draft-14's swallowing decode is the one probe gated on
//! a single draft, because draft-14 is the only draft it is about.
//!
//! Everything else here drives a live session, and a live session is
//! refused before it dials unless this build holds the codec for the draft
//! it is configured with — `ProxyError::DraftNotCompiled`, which reaches
//! the test as an upstream connection that never arrives. Those tests
//! therefore take their draft from [`a_compiled_draft`] rather than naming
//! one: none of them is about a draft, and a named one would make them
//! report on the feature set instead of on the datagram path.
//!
//! A build with **no** draft has no datagram decoder at all:
//! `AnyDatagramHeader` is uninhabited, `decode` cannot return `Ok`, and
//! every fixture assertion below becomes unreachable. Nothing here is
//! answerable in that build, so the file is gated out of it rather than
//! kept compiling by `#[allow]`.

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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use quinn::{Connection, Endpoint, ServerConfig};

use moqtap_codec::dispatch::AnyDatagramHeader;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Gate, Interest};
use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{Effect, ImpairmentKind};
use moqtap_proxy::hook::{FrameCtx, NoOpHook, ProxyHook};
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};

use common::{FakeRelay, RecordingObserver};

/// Every draft whose datagram header delimits its payload — all thirteen
/// except draft-14, whose header decode swallows it.
const DELIMITED: &[DraftVersion] = &[
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
];

/// Every draft this build compiled, delimited or not.
///
/// Separate from [`DELIMITED`] because the two answer different questions.
/// `DELIMITED` is about the wire; this one is about the build, and it is
/// what the single-session tests below pick their draft from. A session
/// configured for a draft the build holds no codec for is refused by
/// `ProxyError::DraftNotCompiled` before it dials, so a named draft turns
/// every one of those tests into an upstream connection that never
/// arrives. Guaranteed non-empty by the file-level gate.
const COMPILED: &[DraftVersion] = &[
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

/// Drafts 15-19, whose datagram type carries a status flag at bit 5 and,
/// when it is set, ends the header with a status field and no payload.
///
/// Draft-14 is left out although it has the same flag: its header decode
/// consumes the rest of the datagram either way, so a draft-14 status
/// datagram would be refused for the draft-14 reason rather than the
/// status one, and the case below would stop testing what it names.
const STATUS_DRAFTS: &[DraftVersion] = &[
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

/// The draft the single-session tests below run on: whichever this build
/// compiled first. None of them is about a draft — they are about the
/// hook firing, the header being decoded, a send failure not taking the
/// session down — so the draft is a fixture choice.
fn a_compiled_draft() -> DraftVersion {
    COMPILED[0]
}

const ORIGINAL: &[u8] = b"original-payload!";
const REPLACEMENT: &[u8] = b"REPLACED-PAYLOAD!";

/// One byte of a would-be eight-byte varint: no draft's header decoder can
/// get anything out of it.
const UNDECODABLE: &[u8] = &[0xC0];

// ── the independent encoder ────────────────────────────────────────────

/// A QUIC variable-length integer, RFC 9000 §16.
///
/// Hand-written, sharing nothing with `moqtap_codec::varint`: every
/// header-length claim in this file rests on it.
fn varint(v: u64, out: &mut Vec<u8>) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16_383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// Track alias carried by every fixture datagram.
const TRACK_ALIAS: u64 = 1;
/// Group ID carried by every fixture datagram.
const GROUP_ID: u64 = 7;
/// Object ID carried by every fixture datagram.
const OBJECT_ID: u64 = 3;
/// Publisher priority carried by every fixture datagram.
const PRIORITY: u8 = 128;

/// One draft's payload-bearing datagram header, field by field.
///
/// `payload_len` is only read by drafts 07 and 08, whose headers declare
/// it; it is passed for every draft so a caller cannot forget it where it
/// matters. Extension headers are absent everywhere (count `0` on 08,
/// byte-length `0` on 09/10, and the no-extensions datagram type
/// elsewhere), which is what keeps the layouts short enough to read.
///
/// Never `0` for `payload_len` on drafts 07-08: those two encode the
/// object status *instead of* a payload when the declared length is zero,
/// so a zero-length fixture would silently become a status datagram and
/// `ReplacePayload` would be refused for a reason the test did not intend.
fn datagram_header(draft: DraftVersion, payload_len: usize) -> Vec<u8> {
    let mut h = Vec::new();
    match draft {
        // 07: type, alias, group, object, priority, payload length.
        DraftVersion::Draft07 => {
            assert!(payload_len > 0, "a zero-length draft-07 datagram is a status datagram");
            varint(0x01, &mut h); // OBJECT_DATAGRAM
            varint(TRACK_ALIAS, &mut h);
            varint(GROUP_ID, &mut h);
            varint(OBJECT_ID, &mut h);
            h.push(PRIORITY);
            varint(payload_len as u64, &mut h);
        }
        // 08: 07 plus an extension *count* before the payload length.
        DraftVersion::Draft08 => {
            assert!(payload_len > 0, "a zero-length draft-08 datagram is a status datagram");
            varint(0x01, &mut h); // OBJECT_DATAGRAM
            varint(TRACK_ALIAS, &mut h);
            varint(GROUP_ID, &mut h);
            varint(OBJECT_ID, &mut h);
            h.push(PRIORITY);
            varint(0, &mut h); // extension count
            varint(payload_len as u64, &mut h);
        }
        // 09/10: the payload length field is gone; extensions are a byte
        // count followed by that many bytes.
        DraftVersion::Draft09 | DraftVersion::Draft10 => {
            varint(0x01, &mut h); // OBJECT_DATAGRAM
            varint(TRACK_ALIAS, &mut h);
            varint(GROUP_ID, &mut h);
            varint(OBJECT_ID, &mut h);
            h.push(PRIORITY);
            varint(0, &mut h); // extension headers length
        }
        // 11/12/13: type 0x00 carries no extensions at all, so the header
        // stops at the priority octet.
        DraftVersion::Draft11 | DraftVersion::Draft12 | DraftVersion::Draft13 => {
            varint(0x00, &mut h); // OBJECT_DATAGRAM, no extensions
            varint(TRACK_ALIAS, &mut h);
            varint(GROUP_ID, &mut h);
            varint(OBJECT_ID, &mut h);
            h.push(PRIORITY);
        }
        // 14-19: a leading datagram-type field. `0x00` clears every flag
        // — object ID present, priority present, no extensions or
        // properties, no status — so the layout is the same five fields on
        // all six. It is written as one octet, which is both a valid
        // one-byte varint (drafts 14-16 read it as a varint) and the raw
        // `u8` drafts 17-19 read.
        DraftVersion::Draft14
        | DraftVersion::Draft15
        | DraftVersion::Draft16
        | DraftVersion::Draft17
        | DraftVersion::Draft18
        | DraftVersion::Draft19 => {
            h.push(0x00);
            varint(TRACK_ALIAS, &mut h);
            varint(GROUP_ID, &mut h);
            varint(OBJECT_ID, &mut h);
            h.push(PRIORITY);
        }
    }
    h
}

/// A whole payload-bearing datagram: header, then payload.
fn datagram(draft: DraftVersion, payload: &[u8]) -> Vec<u8> {
    let mut out = datagram_header(draft, payload.len());
    out.extend_from_slice(payload);
    out
}

/// A **status** datagram on one of [`STATUS_DRAFTS`]: type `0x20` sets the
/// status flag, so the header ends with a status field and there is no
/// payload slot at all.
///
/// One byte-for-byte layout serves all five. The type is a single octet,
/// which drafts 15 and 16 read as a one-byte varint and 17-19 as a raw
/// `u8`; the status is `0x3`, which is one byte under both the RFC 9000
/// varint and MoQT's.
///
/// `0x3` is "End of Group" and it is the point of the choice. Drafts
/// 15-19 assign `0x0`, `0x3` and `0x4` (15 also assigns `0x1`), and the
/// codec refuses an unassigned code on decode — so an arbitrary octet
/// here would make the fixture undecodable and route every assertion
/// below down the undecodable-header path instead of the status path it
/// is for.
fn status_datagram(draft: DraftVersion) -> Vec<u8> {
    debug_assert!(STATUS_DRAFTS.contains(&draft), "[{draft}] has no status datagram in this shape");
    let mut out = vec![0x20];
    varint(TRACK_ALIAS, &mut out);
    varint(GROUP_ID, &mut out);
    varint(OBJECT_ID, &mut out);
    out.push(PRIORITY);
    out.push(0x03); // object status: end of group
    out
}

/// The fixtures decode, and decode to the fields they were built from.
///
/// Not a round trip — the encoder here is not the codec's — but a
/// cross-check in the one direction that matters: if a fixture did not
/// decode at all, every "refused because the header did not decode"
/// assertion below would pass for the wrong reason, and the twelve-draft
/// splice test would be asserting on datagrams the proxy never parsed.
#[test]
fn the_hand_built_fixtures_decode_on_every_draft() {
    for &draft in DELIMITED {
        let bytes = datagram(draft, ORIGINAL);
        let header = datagram_header(draft, ORIGINAL.len());
        let mut cursor = &bytes[..];
        AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] fixture header must decode: {e}"));
        assert_eq!(
            bytes.len() - cursor.len(),
            header.len(),
            "[{draft}] the decoder must consume exactly the header the fixture built"
        );
        assert_eq!(cursor, ORIGINAL, "[{draft}] the payload is what follows the header");
    }

    // draft-14 is the counter-example the refusal exists for: its decode
    // consumes the payload as well, so nothing is left for a splice to
    // land in front of. Only checkable where draft-14's decoder exists.
    #[cfg(feature = "draft14")]
    {
        let d14 = datagram(DraftVersion::Draft14, ORIGINAL);
        let mut cursor = &d14[..];
        AnyDatagramHeader::decode(DraftVersion::Draft14, &mut cursor)
            .expect("draft-14 fixture decodes");
        assert!(
            cursor.is_empty(),
            "draft-14's AnyDatagramHeader is a DatagramObject and swallows the payload — this is \
             the premise of the PayloadNotDelimited refusal"
        );
    }

    // And the status fixture really is a status datagram, on every draft
    // this build compiled that has one.
    for &draft in STATUS_DRAFTS {
        let status = status_datagram(draft);
        let mut cursor = &status[..];
        AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] the status fixture must decode: {e}"));
        assert!(cursor.is_empty(), "[{draft}] a status datagram has no payload after its header");
    }

    // The status *field* is read back on one draft, because reaching it
    // means naming a `DraftVersion`-specific header type and there is no
    // draft-neutral accessor for it.
    #[cfg(feature = "draft19")]
    {
        let status = status_datagram(DraftVersion::Draft19);
        let mut cursor = &status[..];
        let decoded =
            AnyDatagramHeader::decode(DraftVersion::Draft19, &mut cursor).expect("status decodes");
        assert!(cursor.is_empty(), "a status datagram has no payload after its header");
        match decoded {
            AnyDatagramHeader::Draft19(h) => {
                // The field is a typed `ObjectStatus`, not a raw code, so the
                // only thing that can be read back here is a status draft-19
                // assigns. 0x03 is End of Group.
                assert_eq!(
                    h.object_status,
                    Some(moqtap_codec::draft19::types::ObjectStatus::EndOfGroup),
                    "the status flag was set and read back"
                )
            }
            // Reachable only where some *other* draft's variant exists to
            // be mismatched. On a draft-19-only build `AnyDatagramHeader`
            // has exactly one variant and this arm is dead, which
            // `-D warnings` rightly rejects — so the arm is gated rather
            // than the lint silenced, which would have covered the arm
            // above it too.
            #[cfg(any(
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
                feature = "draft18"
            ))]
            other => panic!("expected a draft-19 header, got {other:?}"),
        }
    }

    // The undecodable fixture is undecodable everywhere.
    for &draft in DELIMITED {
        let mut cursor = UNDECODABLE;
        assert!(
            AnyDatagramHeader::decode(draft, &mut cursor).is_err(),
            "[{draft}] the undecodable fixture must not decode"
        );
    }
}

// ── hooks ──────────────────────────────────────────────────────────────

/// What one `on_datagram` call saw.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenDatagram {
    header_present: bool,
    raw: Vec<u8>,
}

/// Records every datagram it is shown and returns a caller-chosen action.
struct DatagramHook {
    seen: Mutex<Vec<SeenDatagram>>,
    decide: Box<dyn Fn(usize) -> Action + Send + Sync>,
}

impl DatagramHook {
    fn new(decide: impl Fn(usize) -> Action + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self { seen: Mutex::new(Vec::new()), decide: Box::new(decide) })
    }

    fn passing() -> Arc<Self> {
        Self::new(|_| Action::Pass)
    }

    fn seen(&self) -> Vec<SeenDatagram> {
        self.seen.lock().expect("seen").clone()
    }
}

impl ProxyHook for DatagramHook {
    fn interest(&self) -> Interest {
        Interest::DATAGRAMS
    }

    fn on_datagram(
        &self,
        _cx: &FrameCtx<'_>,
        header: Option<&AnyDatagramHeader>,
        raw: &[u8],
    ) -> Action {
        let index = {
            let mut seen = self.seen.lock().expect("seen");
            seen.push(SeenDatagram { header_present: header.is_some(), raw: raw.to_vec() });
            seen.len() - 1
        };
        (self.decide)(index)
    }
}

/// A hook that declares `Interest::NONE` and panics if the datagram site
/// is ever consulted.
///
/// A counter could not tell "not called" from "called and ignored".
struct NeverAskMeHook {
    calls: AtomicUsize,
}

impl ProxyHook for NeverAskMeHook {
    fn interest(&self) -> Interest {
        Interest::NONE
    }

    fn on_datagram(
        &self,
        _cx: &FrameCtx<'_>,
        _header: Option<&AnyDatagramHeader>,
        _raw: &[u8],
    ) -> Action {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("on_datagram fired on an Interest::NONE hook");
    }
}

// ── plumbing ───────────────────────────────────────────────────────────

/// A QUIC server endpoint that advertises a small `max_datagram_frame_size`.
///
/// The only way to make the proxy's *outbound* `send_datagram` fail
/// without touching the inbound one: a QUIC sender's datagram budget is
/// whatever its **peer** advertised, so shrinking it on the relay leaves
/// the client → proxy leg at quinn's default and squeezes only the proxy →
/// relay leg. That asymmetry is what
/// [`an_unhooked_send_failure_reports_an_impairment_and_does_not_kill_the_session`]
/// needs and what `common::spawn_quic_server` cannot express.
fn relay_with_datagram_cap(alpn: &[u8], cap: usize) -> (Endpoint, SocketAddr) {
    let (cert_chain, key_der) = common::self_signed_localhost();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .expect("server cert");
    server_crypto.alpn_protocols = vec![alpn.to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic crypto");
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    // quinn derives the advertised `max_datagram_frame_size` transport
    // parameter from this knob (`min(cap, u16::MAX)`), and a sender's
    // budget is that minus quinn's 17-byte `Datagram::SIZE_BOUND`. There
    // is no more direct setter.
    transport.datagram_receive_buffer_size(Some(cap));
    server_config.transport_config(Arc::new(transport));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind).expect("bind relay");
    let addr = endpoint.local_addr().expect("local_addr");
    (endpoint, addr)
}

/// Wait for one datagram on `conn`, or fail with a legible message.
async fn next_datagram(conn: &Connection, what: &str) -> Bytes {
    tokio::time::timeout(common::TIMEOUT, conn.read_datagram())
        .await
        .unwrap_or_else(|_| panic!("no datagram arrived: {what}"))
        .unwrap_or_else(|e| panic!("datagram read failed ({what}): {e}"))
}

/// Assert that no datagram arrives on `conn` within `window`.
async fn assert_no_datagram_for(conn: &Connection, window: Duration, what: &str) {
    match tokio::time::timeout(window, conn.read_datagram()).await {
        Err(_) => {}
        Ok(Ok(bytes)) => panic!("a datagram arrived when none should have ({what}): {bytes:?}"),
        Ok(Err(e)) => panic!("the connection ended while waiting for no datagram ({what}): {e}"),
    }
}

// ── the hook fires ─────────────────────────────────────────────────────

/// The datagram hook fires with **no observer attached**, and the header
/// is decoded for it.
///
/// In 0.3.x the datagram path sat entirely inside `if observer_enabled`,
/// so a hook could only ever see a datagram on a session that also had an
/// event observer — which is not a gate any hook asked for.
///
/// *Ablation:* narrow the decode-and-consult gate in `forward_datagrams`
/// back to `if ctx.observer_enabled`. Both the call count and
/// `datagram_headers_decoded` go to zero and this test goes red twice.
#[tokio::test]
async fn the_datagram_hook_fires_without_an_observer() {
    common::init_crypto();

    let draft = a_compiled_draft();
    let alpn = draft.quic_alpn();
    let bytes = datagram(draft, ORIGINAL);

    let relay = Arc::new(FakeRelay::bind(alpn));
    let hook = DatagramHook::passing();
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        // Not a RecordingObserver: `wants_events()` must be false, or the
        // gate under test is satisfied by the observer instead of by the
        // hook and the test measures nothing.
        Arc::new(NoOpProxyObserver),
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client_conn.send_datagram(Bytes::from(bytes.clone())).expect("client send_datagram");

    let got = next_datagram(&relay_conn, "forwarded datagram").await;
    assert_eq!(&got[..], &bytes[..], "Action::Pass forwards the datagram verbatim");

    assert_eq!(
        hook.seen(),
        vec![SeenDatagram { header_present: true, raw: bytes.clone() }],
        "on_datagram fired once, with a decoded header and the whole datagram"
    );
    assert_eq!(
        proxy.counters().datagram_headers_decoded,
        1,
        "the header was decoded for the hook's sake, with nobody observing"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// The hook fires on a datagram whose header did **not** decode, with
/// `header: None` — which is what makes `Action::Drop` on malformed
/// traffic expressible at all.
///
/// *Ablation:* restore the `if let Ok(header) = AnyDatagramHeader::decode`
/// gate around the hook call. The hook is never consulted and this test
/// goes red.
#[tokio::test]
async fn the_datagram_hook_fires_on_an_undecodable_datagram() {
    common::init_crypto();

    // `common::spawn_proxy` would do, but it names draft-14 outright and
    // a build without draft-14 refuses that session before it dials.
    let draft = a_compiled_draft();
    let alpn = draft.quic_alpn();
    let relay = Arc::new(FakeRelay::bind(alpn));
    let hook = DatagramHook::passing();
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::new(NoOpProxyObserver),
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client_conn.send_datagram(Bytes::from_static(UNDECODABLE)).expect("client send_datagram");

    let got = next_datagram(&relay_conn, "undecodable datagram").await;
    assert_eq!(&got[..], UNDECODABLE, "an undecodable datagram is still forwarded");

    assert_eq!(
        hook.seen(),
        vec![SeenDatagram { header_present: false, raw: UNDECODABLE.to_vec() }],
        "the hook is consulted with header: None"
    );
    assert_eq!(
        proxy.counters().datagram_headers_decoded,
        0,
        "nothing decoded, so nothing is counted"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── transport refusals do not end the session ──────────────────────────

/// A replacement the transport refuses is reported as `ActionFailed` and
/// the session keeps forwarding.
///
/// `ActionFailed`, not `ActionRefused`: the engine *admitted* the action —
/// `Precondition::WithinMaxDatagramSize` is not answerable from inside the
/// crate — and the transport then rejected it. Neither "applied" nor
/// "refused" would be true.
///
/// *Ablation:* restore the `?` on `dest.send_datagram(bytes)`. The
/// forwarding task returns an error, the first task to finish tears the
/// session down, and the second datagram never arrives.
#[tokio::test]
async fn an_oversized_replacement_does_not_kill_the_session() {
    common::init_crypto();

    let draft = a_compiled_draft();
    let alpn = draft.quic_alpn();
    let first = datagram(draft, b"first-datagram--!");
    let second = datagram(draft, b"second-datagram-!");
    // Comfortably past any path MTU: quinn answers `SendDatagramError::TooLarge`.
    let oversized = Bytes::from(vec![0xEE; 4096]);

    let relay = Arc::new(FakeRelay::bind(alpn));
    let observer = Arc::new(RecordingObserver::new());
    let huge = oversized.clone();
    let hook = DatagramHook::new(
        move |i| if i == 0 { Action::Replace(huge.clone()) } else { Action::Pass },
    );
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client_conn.send_datagram(Bytes::from(first.clone())).expect("send first");
    // The replacement cannot go out, so nothing should arrive for it.
    assert_no_datagram_for(&relay_conn, Duration::from_millis(200), "the oversized replacement")
        .await;

    client_conn.send_datagram(Bytes::from(second.clone())).expect("send second");
    let got = next_datagram(&relay_conn, "the datagram after the failure").await;
    assert_eq!(
        &got[..],
        &second[..],
        "the session must survive a refused datagram and keep forwarding"
    );

    let failed = observer.failed();
    assert_eq!(failed.len(), 1, "exactly one ActionFailed: {:?}", observer.events());
    assert_eq!(
        (failed[0].0, failed[0].1),
        (Site::Datagram, ActionKind::Replace),
        "the failure names the site and the action the hook returned"
    );
    assert!(
        !failed[0].2.is_empty(),
        "ActionFailed must carry the transport's own message, not an empty string"
    );
    assert!(
        observer.impairments().iter().all(|k| !matches!(k, ImpairmentKind::DatagramNotSent { .. })),
        "an *action* that failed is reported as ActionFailed, never as DatagramNotSent: {:?}",
        observer.impairments()
    );
    assert_eq!(hook.seen().len(), 2, "the hook was consulted for both datagrams");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A datagram the transport refuses on a session where **no hook took an
/// action** is reported as `Impairment { DatagramNotSent }`, and
/// forwarding continues.
///
/// This is the branch an `Interest::NONE` session takes, and the reason a
/// send failure has two reports rather than one: `ActionFailed` cannot be
/// used here, because nobody took an action to fail. The oversize is manufactured by capping the relay's
/// advertised `max_datagram_frame_size`, which squeezes the proxy → relay
/// leg while leaving client → proxy at quinn's default.
///
/// *Ablation:* restore the `?` on the un-hooked `dest.send_datagram(data)`.
/// The session dies and the small datagram never arrives.
#[tokio::test]
async fn an_unhooked_send_failure_reports_an_impairment_and_does_not_kill_the_session() {
    common::init_crypto();

    let draft = a_compiled_draft();
    let alpn = draft.quic_alpn();
    let small = datagram(draft, b"small");
    let oversized = vec![0x5Au8; 1000];

    let (relay_ep, relay_addr) = relay_with_datagram_cap(alpn, 256);
    let relay_task = tokio::spawn(async move {
        let incoming = relay_ep.accept().await.expect("relay accept");
        let conn = incoming.await.expect("relay tls");
        // Held for the duration; the endpoint must outlive the connection.
        let held = relay_ep;
        (conn, held)
    });

    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(NeverAskMeHook { calls: AtomicUsize::new(0) });
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay_addr),
        alpn,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let (relay_conn, _relay_ep) = tokio::time::timeout(common::TIMEOUT, relay_task)
        .await
        .expect("the proxy connected upstream")
        .expect("join");

    // The fixture's own premise: the client can send this, and the proxy
    // cannot forward it.
    assert!(
        client_conn.max_datagram_size().expect("client datagrams enabled") >= oversized.len(),
        "the client → proxy leg must be able to carry the oversized datagram"
    );

    client_conn.send_datagram(Bytes::from(oversized)).expect("client send oversized");
    assert_no_datagram_for(&relay_conn, Duration::from_millis(200), "the oversized datagram").await;

    client_conn.send_datagram(Bytes::from(small.clone())).expect("client send small");
    let got = next_datagram(&relay_conn, "the datagram after the drop").await;
    assert_eq!(&got[..], &small[..], "forwarding continues after a refused datagram");

    let not_sent: Vec<_> = observer
        .impairments()
        .into_iter()
        .filter(|k| matches!(k, ImpairmentKind::DatagramNotSent { .. }))
        .collect();
    assert_eq!(
        not_sent.len(),
        1,
        "exactly one Impairment {{ DatagramNotSent }}: {:?}",
        observer.impairments()
    );
    assert!(
        observer.failed().is_empty(),
        "nobody took an action, so nothing can have failed: {:?}",
        observer.failed()
    );
    assert_eq!(hook.calls.load(Ordering::SeqCst), 0, "an Interest::NONE hook is never consulted");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── the site's own refusals ────────────────────────────────────────────

/// `Delay` and `Hold` are refused on datagrams, and the datagram is
/// forwarded unchanged anyway.
///
/// Datagrams are per-connection and unordered by definition, so there is
/// no queue to defer into; a FIFO would impose ordering the protocol does
/// not have. The refusal is `WrongSite` — the datagram site rejects both
/// actions outright — rather than a composition complaint: the site's
/// verdict is decided before any composition rule is consulted.
#[tokio::test]
async fn delay_and_hold_are_refused_on_datagrams() {
    common::init_crypto();

    let draft = a_compiled_draft();
    let alpn = draft.quic_alpn();
    let first = datagram(draft, b"delayed-datagram!");
    let second = datagram(draft, b"held----datagram!");

    let relay = Arc::new(FakeRelay::bind(alpn));
    let observer = Arc::new(RecordingObserver::new());
    let hook = DatagramHook::new(|i| {
        if i == 0 {
            Action::Pass.delayed(Duration::from_millis(500))
        } else {
            Action::Pass.held(Gate::new())
        }
    });
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    // Sent and awaited one at a time: datagrams are unordered, and the
    // hook's decision is keyed on arrival order.
    client_conn.send_datagram(Bytes::from(first.clone())).expect("send first");
    let got = next_datagram(&relay_conn, "the delayed datagram").await;
    assert_eq!(&got[..], &first[..], "a refused Delay still forwards the datagram unchanged");

    client_conn.send_datagram(Bytes::from(second.clone())).expect("send second");
    let got = next_datagram(&relay_conn, "the held datagram").await;
    assert_eq!(&got[..], &second[..], "a refused Hold still forwards the datagram unchanged");

    assert_eq!(
        observer.refused(),
        vec![
            (
                Site::Datagram,
                ActionKind::Delay,
                Refusal::WrongSite { site: Site::Datagram, action: ActionKind::Delay }
            ),
            (
                Site::Datagram,
                ActionKind::Hold,
                Refusal::WrongSite { site: Site::Datagram, action: ActionKind::Hold }
            ),
        ],
        "both timing actions are refused at the datagram site: {:?}",
        observer.events()
    );
    assert_eq!(
        observer.applied(),
        vec![],
        "a refusal is not an application: {:?}",
        observer.events()
    );
    assert_eq!(proxy.counters().actions_refused, 2, "both refusals are counted");
    assert_eq!(
        proxy.counters().egress_items_queued,
        0,
        "a refused Delay must never reach the deque"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── ReplacePayload ─────────────────────────────────────────────────────

/// `ReplacePayload` splices immediately after the header, on all twelve
/// drafts whose datagram header delimits the payload.
///
/// The expected bytes are `header ++ replacement`, where `header` is the
/// fixture's own hand-built header — so this asserts the engine's splice
/// **offset**, not merely that a replacement happened. A splice at the
/// wrong offset yields a datagram of a different length, or one that
/// carries a slice of the original payload, and fails here.
#[tokio::test]
async fn replace_payload_splices_after_the_header_on_drafts_that_delimit_it() {
    common::init_crypto();

    for &draft in DELIMITED {
        let alpn = draft.quic_alpn();
        let header = datagram_header(draft, ORIGINAL.len());
        let sent = datagram(draft, ORIGINAL);
        let mut expected = header.clone();
        expected.extend_from_slice(REPLACEMENT);

        let relay = Arc::new(FakeRelay::bind(alpn));
        let observer = Arc::new(RecordingObserver::new());
        let hook = DatagramHook::new(|_| Action::ReplacePayload(Bytes::from_static(REPLACEMENT)));
        let proxy = common::spawn_proxy_with(
            common::session_config(draft, relay.addr),
            alpn,
            Arc::clone(&observer) as Arc<dyn ProxyObserver>,
            Arc::clone(&hook) as Arc<dyn ProxyHook>,
        );

        let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
        let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
            .await
            .unwrap_or_else(|_| panic!("[{draft}] the proxy connected upstream"));

        client_conn.send_datagram(Bytes::from(sent.clone())).expect("client send_datagram");
        let got = next_datagram(&relay_conn, "the spliced datagram").await;

        assert_eq!(
            &got[..],
            &expected[..],
            "[{draft}] the replacement must be spliced at offset {} — the header's own length",
            header.len()
        );
        assert_eq!(
            observer.applied(),
            vec![(
                Site::Datagram,
                ActionKind::ReplacePayload,
                Effect::Replaced { bytes: expected.len() }
            )],
            "[{draft}] one ActionApplied, reporting the spliced length: {:?}",
            observer.events()
        );
        assert!(
            observer.refused().is_empty(),
            "[{draft}] nothing refused: {:?}",
            observer.refused()
        );

        client_conn.close(0u32.into(), b"done");
        proxy.shutdown().await;
    }
}

/// One `ReplacePayload` refusal case, driven end to end.
///
/// `sent` goes in, the same bytes must come out, and exactly one
/// `ActionRefused { PayloadNotDelimited { detail } }` must be reported
/// with `detail` equal to `want_detail`.
async fn refusal_case(draft: DraftVersion, sent: Vec<u8>, want_detail: &'static str) {
    let alpn = draft.quic_alpn();
    let relay = Arc::new(FakeRelay::bind(alpn));
    let observer = Arc::new(RecordingObserver::new());
    let hook = DatagramHook::new(|_| Action::ReplacePayload(Bytes::from_static(REPLACEMENT)));
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .unwrap_or_else(|_| panic!("[{draft}/{want_detail}] the proxy connected upstream"));

    client_conn.send_datagram(Bytes::from(sent.clone())).expect("client send_datagram");
    let got = next_datagram(&relay_conn, want_detail).await;

    assert_eq!(
        &got[..],
        &sent[..],
        "[{draft}/{want_detail}] a refused ReplacePayload forwards the datagram byte-identically"
    );
    assert_eq!(
        observer.refused(),
        vec![(
            Site::Datagram,
            ActionKind::ReplacePayload,
            Refusal::PayloadNotDelimited { detail: want_detail }
        )],
        "[{draft}/{want_detail}] exactly one refusal, with the right detail: {:?}",
        observer.events()
    );
    assert!(
        observer.applied().is_empty(),
        "[{draft}/{want_detail}] nothing was applied: {:?}",
        observer.applied()
    );
    assert_eq!(
        proxy.counters().actions_refused,
        1,
        "[{draft}/{want_detail}] the refusal is counted"
    );
    assert_eq!(hook.seen().len(), 1, "[{draft}/{want_detail}] the hook was consulted exactly once");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// `ReplacePayload` is refused on all three shapes with no derivable
/// payload boundary, each with its own `detail`, and the datagram is
/// forwarded unchanged.
///
/// *Ablation for this test and its twelve-draft sibling:* derive the
/// offset as `data.len() - cursor.len()` unconditionally — that is, drop
/// the `draft != DraftVersion::Draft14 && !is_status` terms from
/// `Target::payload_delimited`. The draft-14 case then produces
/// `header ++ original ++ replacement`, a longer datagram with both
/// payloads in it, and no `ActionRefused` at all.
#[tokio::test]
async fn replace_payload_on_a_datagram_is_refused_where_the_payload_is_not_delimited() {
    common::init_crypto();

    // 1. draft-14: `AnyDatagramHeader` is `DatagramObject` and its decode
    //    reads to the end of the datagram, so there is no boundary. This
    //    is the case that would corrupt silently. Only draft-14 has it, so
    //    it is asked only where draft-14's decoder exists.
    #[cfg(feature = "draft14")]
    refusal_case(
        DraftVersion::Draft14,
        datagram(DraftVersion::Draft14, ORIGINAL),
        "draft-14 header decode consumes the payload",
    )
    .await;

    // 2. a status datagram: no payload slot exists at all. Asked on the
    //    first of the five drafts that have one, rather than on a named
    //    draft that a reduced build may not hold.
    if let Some(&draft) = STATUS_DRAFTS.first() {
        refusal_case(draft, status_datagram(draft), "status datagram has no payload").await;
    }

    // 3. an undecodable header: the hook still fires — that is the point
    //    of `header: None` — but there is nothing to splice after. No
    //    draft can decode the fixture, but the draft still has to be a
    //    delimited one: `Target::payload_delimited` tests the draft-14
    //    term before it looks at the header, so on draft-14 this datagram
    //    is refused with case 1's detail and this case has no way to
    //    arise at all.
    if let Some(&draft) = DELIMITED.first() {
        refusal_case(draft, UNDECODABLE.to_vec(), "datagram header did not decode").await;
    }
}

/// The datagram path is untouched by a `NoOpHook` on an `Interest::NONE`
/// session: the bytes are forwarded and no slow path runs.
///
/// The baseline the rest of this file is measured against — without it,
/// "the hook fired" and "the header was decoded" have nothing to be
/// contrasted with.
#[tokio::test]
async fn an_interest_none_session_forwards_datagrams_without_decoding_them() {
    common::init_crypto();

    let draft = a_compiled_draft();
    let alpn = draft.quic_alpn();
    let bytes = datagram(draft, ORIGINAL);

    let relay = Arc::new(FakeRelay::bind(alpn));
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::new(NoOpProxyObserver),
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client_conn.send_datagram(Bytes::from(bytes.clone())).expect("client send_datagram");
    let got = next_datagram(&relay_conn, "the forwarded datagram").await;
    assert_eq!(&got[..], &bytes[..], "the byte pump forwards the datagram unchanged");

    assert_eq!(
        proxy.counters(),
        moqtap_proxy::instrument::Counters::default(),
        "an Interest::NONE session with a non-event observer must not decode a datagram header"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

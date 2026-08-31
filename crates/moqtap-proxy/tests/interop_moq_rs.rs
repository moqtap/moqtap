//! Interop against a real third-party relay, rather than one built from
//! these crates.
//!
//! Topology:
//!
//! ```text
//!   client (raw quinn + moqtap-client framed streams)
//!     ↓ QUIC, ALPN moqt-16
//!   proxy front-end endpoint (bound by `common::spawn_proxy_with`)
//!     ↓ QUIC, ALPN moqt-16, upstream cert verification off
//!   moq-relay-ietf (github.com/cloudflare/moq-rs), in a container
//! ```
//!
//! # Why this file exists when forty other test files already drive the proxy
//!
//! Every other integration test in this crate builds *both* peers here: the
//! client is `moqtap-client` over quinn and the upstream is `common::FakeRelay`,
//! which is also `moqtap-client` over quinn. Every byte on both sides of the
//! proxy is therefore produced and consumed by `moqtap-codec`. Two consequences
//! follow, and neither is visible from inside that arrangement:
//!
//! * A symmetric encode/decode defect passes. If the encoder writes a field in
//!   the wrong order and the decoder reads it back in the same wrong order, a
//!   round-trip assertion is green and the wire format is wrong.
//! * "The proxy forwarded it" is only ever checked against a peer that shares
//!   the proxy's own parser. Whether a *foreign* implementation accepts what
//!   this proxy re-frames after parsing it is a question the suite cannot ask.
//!
//! This file asks it. The relay is a separate codebase with its own encoder,
//! its own decoder, and its own idea of what a conforming session looks like,
//! so a green run here is an agreement between two implementations rather than
//! one implementation agreeing with itself.
//!
//! # Draft-16, because that is the draft the relay's default branch speaks
//!
//! The relay's draft is a property of the branch it was built from, not a flag:
//! `main` is draft-16 and declares `pub const ALPN: &[u8] = b"moqt-16"` in
//! `moq-transport/src/setup/mod.rs`. `DraftVersion::Draft16::quic_alpn` in
//! `moqtap-codec` produces the same seven bytes, and that agreement is itself
//! an interop result — nothing in either tree was written against the other.
//! The relay offers `h3` alongside it, for WebTransport; a `moqt://` client
//! selects raw QUIC, which is the leg this proxy can carry a socket on.
//!
//! Draft-16 is also the ceiling of the shape `common`'s framed helpers and this
//! crate's control-stream parser are built around: draft-17 moves SETUP off the
//! bidirectional control stream onto a pair of unidirectional ones. Draft-14
//! would work too and is a smaller claim — the project keeps that branch in
//! maintenance — and draft-18 work happens on a branch of its own. Either is
//! reachable by pointing `MOQ_RELAY_REF` at it, but the draft this file speaks
//! would have to move with it.
//!
//! # Gating: `#[ignore]` *and* an environment variable, not either alone
//!
//! Both are load-bearing and each covers a case the other does not.
//!
//! `#[ignore]` is what keeps `cargo test --workspace` unaffected. It holds
//! whatever the environment says, so a developer who exported the endpoint
//! variable in their shell — or a CI job that inherits it — does not silently
//! start sending the default suite at a network service.
//!
//! The environment variable is what keeps `cargo test -- --ignored` honest.
//! With no relay running there is nothing to assert against, and the useful
//! outcome is a stated skip rather than a connect timeout dressed up as a
//! failure. The skip is written straight to the process's stderr handle rather
//! than through `eprintln!`, because libtest's capture intercepts the macro and
//! shows what it captured only when a test fails — a skip that prints through
//! the macro is a skip nobody ever reads.

#![cfg(feature = "draft16")]
// `AnyControlMessage` has one variant per compiled draft, so matching
// `Draft16` is refutable in the default build and irrefutable in a build that
// compiled draft-16 alone — where this file is the only reason the feature is
// on. The patterns below are written for the first case, because that is what
// the crate ships and what a reader is entitled to assume; narrowing them for
// the single-draft build would put a `cfg` around the body of a test whose
// subject is a relay rather than a draft set.
#![allow(irrefutable_let_patterns)]

mod common;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
use moqtap_client::transport::{RecvStream, SendStream};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::message::{ClientSetup, ControlMessage, PublishNamespace};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::event::ProxyEvent;
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::types::ProxySide;

/// Where the relay is listening, as a QUIC socket address — `127.0.0.1:4443`
/// for the container the justfile starts.
///
/// A socket address and not a URL: the upstream leg parses this string with
/// `SocketAddr::from_str` and derives the TLS server name by splitting it on
/// `:`, so a `https://` prefix or a bare hostname does not reach the dial.
const RELAY_ENV: &str = "MOQTAP_INTEROP_RELAY";

/// The relay's generated certificate is self-signed for `localhost` and its
/// key changes every restart, so there is nothing to pin. Verification is off
/// on the upstream leg, which is what `common::session_config` already sets.
const ALPN: &[u8] = b"moqt-16";

/// The first client-initiated request on a draft-16 session.
///
/// Zero rather than one: from draft-11 onward a client allocates even Request
/// IDs and a server odd ones, so a client's first request is 0 and a relay that
/// enforces the parity rule closes the session on anything else.
const FIRST_CLIENT_REQUEST_ID: u64 = 0;

/// The endpoint under test, or a stated skip.
///
/// Returns `None` after writing the reason to the real stderr — see the module
/// header for why this does not go through `eprintln!`.
fn relay_addr() -> Option<SocketAddr> {
    let raw = match std::env::var(RELAY_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            let _ = writeln!(
                std::io::stderr(),
                "SKIP interop: {RELAY_ENV} is unset. Start the relay with `just interop-up` \
                 and re-run, or use `just interop` to do both."
            );
            return None;
        }
    };
    match raw.trim().parse() {
        Ok(addr) => Some(addr),
        Err(e) => panic!("{RELAY_ENV}={raw:?} is not a socket address ({e}); expected host:port"),
    }
}

/// Every setup message the proxy reported, as `(side, is_client_setup)`.
///
/// Destructured on the way out rather than compared as events, for the reason
/// `common`'s `RecordingObserver` gives: `ProxyEvent` is deliberately not
/// `PartialEq`, because the per-draft codec types it carries are not either.
fn setups(events: &[ProxyEvent]) -> Vec<(ProxySide, bool)> {
    events
        .iter()
        .filter_map(|e| match e {
            ProxyEvent::SetupMessage { side, message, .. } => Some((
                *side,
                matches!(message, AnyControlMessage::Draft16(ControlMessage::ClientSetup(_))),
            )),
            _ => None,
        })
        .collect()
}

/// Every control message the proxy reported, as `(side, variant name)`.
///
/// The name rather than the message: it is what an assertion failure needs to
/// print, and it survives the codec types that cannot be compared.
fn controls(events: &[ProxyEvent]) -> Vec<(ProxySide, &'static str)> {
    events
        .iter()
        .filter_map(|e| match e {
            ProxyEvent::ControlMessage { side, message, .. } => {
                let AnyControlMessage::Draft16(inner) = message else {
                    return None;
                };
                Some((*side, variant_name(inner)))
            }
            _ => None,
        })
        .collect()
}

/// A stable name for the message kinds this test can reach.
///
/// Deliberately not exhaustive over `ControlMessage`: the point of the
/// catch-all is that an unexpected kind reaches the assertion as a printable
/// string rather than failing to compile when the enum grows.
fn variant_name(msg: &ControlMessage) -> &'static str {
    match msg {
        ControlMessage::PublishNamespace(_) => "PUBLISH_NAMESPACE",
        ControlMessage::RequestOk(_) => "REQUEST_OK",
        ControlMessage::RequestError(_) => "REQUEST_ERROR",
        ControlMessage::MaxRequestId(_) => "MAX_REQUEST_ID",
        ControlMessage::GoAway(_) => "GOAWAY",
        ControlMessage::SubscribeNamespace(_) => "SUBSCRIBE_NAMESPACE",
        ControlMessage::Namespace(_) => "NAMESPACE",
        _ => "other",
    }
}

/// Drive a draft-16 session through the proxy at a live moq-relay.
///
/// The assertions are on the *proxy's* observed events rather than on what the
/// client read back, because the claim is about what the proxy saw and
/// forwarded. A client that got a reply proves a byte moved; the event stream
/// proves the proxy parsed both directions of a foreign peer's control stream
/// and re-framed the client's messages into something that peer accepted.
#[tokio::test]
#[ignore = "needs a live moq-relay; run `just interop` (see MOQTAP_INTEROP_RELAY)"]
async fn draft16_setup_and_publish_namespace_reach_a_foreign_relay() {
    let Some(relay) = relay_addr() else { return };

    common::init_crypto();

    let observer = Arc::new(common::RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(DraftVersion::Draft16, relay),
        ALPN,
        observer.clone(),
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let (send, recv) = client_conn.open_bi().await.expect("open control stream");
    let mut tx = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
    let mut rx = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);

    // Draft-16 CLIENT_SETUP carries no supported-versions list — the draft was
    // settled by ALPN before a byte of MoQT was written — so the parameters are
    // the whole message.
    //
    // One parameter, PATH (key 1), carrying an empty value. It is not required:
    // the same run with `parameters: Vec::new()` was tried and the relay
    // completed the handshake, because the container grants anonymous access at
    // the empty prefix and an absent PATH resolves to the same root. It is here
    // for what it costs the *decoders*. An empty parameter list is one varint on
    // the wire and proves nothing about key-value coding; PATH is an odd key,
    // which in this draft means a length-prefixed byte string, so sending it
    // puts a real KVP through this crate's setup encoder, this crate's
    // control-stream parser, and the relay's decoder, none of which an empty
    // list reaches.
    let path_param =
        KeyValuePair { key: VarInt::from_u64(1).unwrap(), value: KvpValue::Bytes(Vec::new()) };
    let client_setup = AnyControlMessage::Draft16(ControlMessage::ClientSetup(ClientSetup {
        parameters: vec![path_param],
    }));
    tx.write_control(&client_setup).await.expect("write CLIENT_SETUP");

    // This read is where an unreachable relay surfaces, and it surfaces as a
    // lost *client* connection rather than as a dial error: the proxy fails its
    // own upstream connect after `upstream_connect_timeout_secs` and closes the
    // leg the client is holding, so what arrives here is the second-order
    // symptom. Naming the first-order cause in the message is the difference
    // between a five-second diagnosis and an hour spent reading the parser.
    let (server_setup, _) = tokio::time::timeout(common::TIMEOUT, rx.read_control(false))
        .await
        .expect("SERVER_SETUP within timeout")
        .unwrap_or_else(|e| {
            panic!("no SERVER_SETUP ({e}); is a relay listening on {relay}? try `just interop-up`")
        });
    assert!(
        matches!(&server_setup, AnyControlMessage::Draft16(ControlMessage::ServerSetup(_))),
        "relay answered CLIENT_SETUP with {server_setup:?}"
    );

    // PUBLISH_NAMESPACE rather than SUBSCRIBE: it is answered by the relay's
    // own state machine without any media having to exist, so the reply is
    // evidence about the control plane and not about whether a track happens to
    // be live in the container.
    let namespace = TrackNamespace(vec![b"moqtap-interop".to_vec()]);
    let announce = AnyControlMessage::Draft16(ControlMessage::PublishNamespace(PublishNamespace {
        request_id: VarInt::from_u64(FIRST_CLIENT_REQUEST_ID).unwrap(),
        track_namespace: namespace,
        parameters: Vec::new(),
    }));
    tx.write_control(&announce).await.expect("write PUBLISH_NAMESPACE");

    // The relay may send MAX_REQUEST_ID before it answers, so read until the
    // answer arrives rather than assuming it is the next message. Anything the
    // relay says here is still a parse the proxy had to get right, which is why
    // the loop asserts nothing and the event stream carries the verdict.
    let mut answered = None;
    for _ in 0..8 {
        let (msg, _) = tokio::time::timeout(common::TIMEOUT, rx.read_control(false))
            .await
            .expect("relay reply within timeout")
            .expect("read relay reply");
        if let AnyControlMessage::Draft16(inner) = &msg {
            match inner {
                ControlMessage::RequestOk(ok) => {
                    assert_eq!(
                        ok.request_id.into_inner(),
                        FIRST_CLIENT_REQUEST_ID,
                        "REQUEST_OK named a request this session never made"
                    );
                    answered = Some("REQUEST_OK");
                    break;
                }
                ControlMessage::RequestError(err) => {
                    panic!(
                        "relay refused PUBLISH_NAMESPACE: code={} reason={:?}",
                        err.error_code.into_inner(),
                        String::from_utf8_lossy(&err.reason_phrase)
                    );
                }
                _ => continue,
            }
        }
    }
    assert_eq!(answered, Some("REQUEST_OK"), "relay never answered PUBLISH_NAMESPACE");

    // The observer runs on the session's own task; give the last event a beat
    // to land before reading the vector, so the assertion is about what the
    // proxy reported rather than about scheduler order.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = observer.events();
    let seen = setups(&events);
    let control = controls(&events);

    // Written out on every run, and to the real stderr for the same reason the
    // skip is. It is not an assertion and should not become one: a relay build
    // is free to open with messages of its own, and this file must not fail
    // because the other implementation gained an opening move. What the census
    // gives a human is which of the proxy's parser arms a run actually reached,
    // and it is the first thing worth reading when a relay upgrade changes the
    // answer — the observed shape against this relay is two setups and two
    // control messages, PUBLISH_NAMESPACE out and REQUEST_OK back.
    let _ = writeln!(
        std::io::stderr(),
        "interop census: setups={seen:?}\ninterop census: control={control:?}"
    );

    // Both halves of the handshake, each attributed to the peer that sent it.
    // The side on a control event is the *ingress* side — the leg the bytes
    // arrived on — even though the event is emitted after the forwarding write
    // has completed. So the client's messages are `ClientToProxy` and the
    // relay's are `RelayToProxy`, and each one reported here is a message the
    // proxy parsed and then put on the far leg.
    assert!(
        seen.contains(&(ProxySide::ClientToProxy, true)),
        "proxy never reported forwarding CLIENT_SETUP; setups={seen:?}"
    );
    assert!(
        seen.contains(&(ProxySide::RelayToProxy, false)),
        "proxy never reported the relay's SERVER_SETUP; setups={seen:?}"
    );

    // The forwarding claim: a message this crate encoded reached a foreign
    // relay, and that relay's answer came back through the same parser.
    assert!(
        control.contains(&(ProxySide::ClientToProxy, "PUBLISH_NAMESPACE")),
        "proxy never reported PUBLISH_NAMESPACE toward the relay; control={control:?}"
    );
    assert!(
        control.contains(&(ProxySide::RelayToProxy, "REQUEST_OK")),
        "proxy never reported the relay's REQUEST_OK; control={control:?}"
    );

    // A parse error anywhere in the run means the proxy failed to read bytes a
    // conforming peer put on the wire, which is the defect this file exists to
    // find. Assert it last so the more specific failures above report first.
    assert!(
        observer.parse_errors().is_empty(),
        "proxy reported parse errors against a conforming peer: {:?}",
        observer.parse_errors()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

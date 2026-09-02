//! The Group Order a draft-19 fetch response is read against comes off the
//! FETCH that asked for it.
//!
//! Draft-19 Section 11.4.4.1 writes a fetch Object's Group ID as a difference
//! from the Object before it: "If the Group Order is Ascending, the Group ID is
//! the prior Object's Group ID plus the Group ID Delta + 1. If the Group Order
//! is Descending, the Group ID is the prior Object's Group ID minus the (Group
//! ID Delta + 1)." Nothing on the data stream says which, and the wrong choice
//! decodes every Object without an error under Group IDs walking the wrong way
//! — so a proxy that guessed would report a whole fetch response's Locations
//! backwards and have nothing to say about it.
//!
//! The order is one control message away. Draft-19 Section 10.12.3: "The
//! publisher responding to a FETCH is responsible for delivering all available
//! Objects in the requested range in the requested order (see Section 10.2.8)",
//! and draft-19 Section 10.2.8 states what the request means when it says
//! nothing: "If omitted from FETCH, the receiver uses Ascending (0x1)."
//!
//! So this file drives **the same response bytes** three times and changes only
//! what the session was told beforehand. Descending and Ascending are the two
//! halves of the claim — either alone would pass an implementation that had
//! hard-coded the other — and the third run sends no FETCH at all, which is the
//! only case left where the proxy gives a fetch stream up.
//!
//! Draft-19 puts requests on bidirectional streams and its control plane on a
//! pair of unidirectional ones, so the FETCH here travels on a client-initiated
//! bidirectional stream, which is where a subscriber would have sent it.

#![cfg(feature = "draft19")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft19::message as m;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;
use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::event::ImpairmentKind;
use moqtap_proxy::hook::{FrameCtx, ProxyHook};
use moqtap_proxy::types::BypassReason;

mod common;

/// The Request ID the FETCH is sent under and the response stream names.
const REQUEST: u64 = 4;
/// GROUP_ORDER, Parameter Type 0x22.
const GROUP_ORDER: u64 = 0x22;
/// The first Object's Group ID, which its Group ID Delta states outright.
///
/// Far enough above zero that a descending run has room to walk down and a
/// wrong reading walks somewhere visibly different rather than off the end.
const FIRST_GROUP: u64 = 20;
/// The three Group IDs the response resolves to under each order.
const DESCENDING: [u64; 3] = [20, 19, 18];
const ASCENDING: [u64; 3] = [20, 21, 22];

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("in range")
}

/// A FETCH under [`REQUEST`], asking for `order` when it is named.
///
/// Built through the codec rather than by hand, so what the proxy is asked to
/// read is a frame a conforming subscriber would have written.
fn fetch(order: Option<u64>) -> Vec<u8> {
    let parameters = order
        .map(|v| {
            vec![KeyValuePair { key: varint(GROUP_ORDER), value: KvpValue::Varint(varint(v)) }]
        })
        .unwrap_or_default();
    let msg = AnyControlMessage::Draft19(m::ControlMessage::Fetch(m::Fetch {
        request_id: varint(REQUEST),
        fetch_type: m::FetchType::Standalone,
        fetch_payload: m::FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(64),
            end_object: varint(0),
        },
        parameters,
    }));
    let mut out = Vec::new();
    msg.encode(&mut out).expect("the codec writes what it built");
    out
}

/// One varint, in the one width both varint encodings spell the same way.
///
/// Every value this file writes is below 64, where draft-19's encoding and
/// RFC 9000's agree on a single byte carrying the value outright. The
/// assertion is what keeps that true if a fixture value is ever raised.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    assert!(value < 64, "{value} needs a wider varint than this fixture writes");
    out.push(value as u8);
}

/// The fetch response: a header naming [`REQUEST`], then three Objects.
///
/// The first Object's Group ID Delta *is* its Group ID — draft-19 Section
/// 11.4.4.1: "The first Object MUST include a Group ID Delta and Object ID
/// Delta, and these values are the absolute Group ID and Object ID." The two
/// after it carry a delta of zero, which is one group along in whichever
/// direction the order points. That is what makes these bytes ambiguous on
/// their own and unambiguous once the FETCH has been read.
fn response() -> Vec<u8> {
    let mut out = vec![0x05];
    put_varint(&mut out, REQUEST);
    for (group_delta, object_id) in [(FIRST_GROUP, 0u64), (0, 0), (0, 0)] {
        // Serialization Flags: explicit Subgroup ID, Object ID Delta, Group
        // ID Delta and Publisher Priority all present.
        put_varint(&mut out, 0x03 | 0x04 | 0x08 | 0x10);
        put_varint(&mut out, group_delta);
        put_varint(&mut out, 0); // subgroup ID
        put_varint(&mut out, object_id);
        out.push(0x80); // publisher priority
        put_varint(&mut out, 4); // payload length
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    out
}

/// A hook that turns every FETCH it sees into a Descending one.
///
/// Standing in for the reason the proxy exists: a caller changing
/// what one peer asked for and watching what the other does about it. What
/// makes it a gate rather than a demonstration is that the *subscriber* asked
/// for Ascending, so a session filing the order it read on the way in would
/// read the response the wrong way round — and the publisher, which only ever
/// saw Descending, would be right.
struct RewriteToDescending;

impl ProxyHook for RewriteToDescending {
    fn interest(&self) -> Interest {
        Interest::CONTROL
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        message: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        let AnyControlMessage::Draft19(m::ControlMessage::Fetch(f)) = message else {
            return Action::Pass;
        };
        let mut rewritten = f.clone();
        rewritten.parameters =
            vec![KeyValuePair { key: varint(GROUP_ORDER), value: KvpValue::Varint(varint(0x2)) }];
        let mut buf = Vec::new();
        AnyControlMessage::Draft19(m::ControlMessage::Fetch(rewritten))
            .encode(&mut buf)
            .expect("re-encode the FETCH");
        Action::Replace(bytes::Bytes::from(buf))
    }
}

/// What the proxy made of one fetch response, given what it was told first.
struct Run {
    groups: Vec<u64>,
    bypasses: Vec<BypassReason>,
}

/// Drive one session. `asked` is the FETCH to send first, or `None` to send
/// none at all.
async fn run(asked: Option<Option<u64>>) -> Run {
    let at_relay = asked.map(fetch);
    run_with_hook(asked, Arc::new(moqtap_proxy::hook::NoOpHook), at_relay).await
}

/// [`run`], with a hook that may rewrite the FETCH on its way through.
///
/// `at_relay` is the frame the publisher must end up receiving, which is what
/// it will have answered — the same bytes on an unhooked run, and the
/// rewritten ones where a hook changed them.
async fn run_with_hook(
    asked: Option<Option<u64>>,
    hook: Arc<dyn ProxyHook>,
    at_relay: Option<Vec<u8>>,
) -> Run {
    common::init_crypto();
    let draft = DraftVersion::Draft19;
    let alpn = draft.quic_alpn();
    let relay = common::FakeRelay::bind(alpn);
    let obs = Arc::new(common::RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::clone(&obs) as Arc<dyn moqtap_proxy::observer::ProxyObserver>,
        hook,
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, alpn).await;
    let relay_conn = relay.connection().await;

    // The FETCH, and the wait that makes this a test rather than a race.
    //
    // A real publisher cannot open the response before receiving the request,
    // because the request is what tells it to. This harness plays both peers
    // over two streams the proxy reads on two tasks, so nothing orders them
    // for it — reading the FETCH back at the relay is the fixture supplying
    // the ordering the protocol supplies in the field.
    let _request = match asked {
        Some(order) => {
            let (mut send, recv) = client.open_bi().await.expect("request stream");
            send.write_all(&fetch(order)).await.expect("FETCH");
            let want = at_relay.clone().expect("an armed run says what the relay gets");
            let mut upstream = relay_conn.accept_bi().await.expect("relay accept_bi").1;
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while seen.len() < want.len() {
                let n = upstream
                    .read(&mut buf)
                    .await
                    .expect("relay read")
                    .expect("the FETCH must reach the relay");
                seen.extend_from_slice(&buf[..n]);
            }
            assert_eq!(seen, want, "the publisher answers the FETCH it received");
            Some((send, recv, upstream))
        }
        None => None,
    };

    // The response, from the publisher's side.
    let mut out = relay_conn.open_uni().await.expect("relay open_uni");
    out.write_all(&response()).await.expect("fetch response");
    let _ = out.finish();

    // Read it at the subscriber, so the proxy's forwarding completes.
    let mut inbound = client.accept_uni().await.expect("client accept_uni");
    let _ = common::drain(&mut inbound).await;

    // The proxy reports the objects it addressed, or the one bypass that says
    // it addressed none. Either way the count is settled, so the wait is for
    // three of one or one of the other rather than for a fixed pause.
    let deadline = Instant::now() + Duration::from_secs(10);
    let out = loop {
        let r = obs.recorded();
        let bypasses: Vec<_> = r
            .impairments
            .iter()
            .filter_map(|k| match k {
                ImpairmentKind::FramerBypass { reason, .. } => Some(*reason),
                _ => None,
            })
            .collect();
        if r.objects.len() == 3 || !bypasses.is_empty() {
            break Run { groups: r.objects.iter().map(|o| o.group_id).collect(), bypasses };
        }
        assert!(
            Instant::now() < deadline,
            "the session neither framed the response nor gave it up: {:#?}",
            r.events
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    proxy.shutdown().await;
    out
}

/// **The same response bytes resolve to different Locations under the two
/// orders, and the FETCH is what decides which.**
///
/// This is the whole row in one assertion pair. A proxy that assumed Ascending
/// passes the second half and fails the first; one that assumed Descending
/// does the reverse; one that read the FETCH passes both. Nothing about the
/// response stream differs between the two runs.
///
/// *Ablation, recorded:* have `note_fetch_orders` file
/// `AnyFetchGroupOrder::Ascending` whatever the FETCH asked for:
///
/// ```text
/// assertion `left == right` failed: a fetch answered Descending walks its
/// Group IDs down
///   left: [20, 21, 22]
///  right: [20, 19, 18]
/// ```
#[tokio::test]
async fn a_fetch_response_is_read_against_the_order_its_request_asked_for() {
    let descending = run(Some(Some(0x2))).await;
    assert_eq!(
        descending.groups, DESCENDING,
        "a fetch answered Descending walks its Group IDs down"
    );
    assert!(descending.bypasses.is_empty(), "and nothing was given up: {:?}", descending.bypasses);

    let ascending = run(Some(Some(0x1))).await;
    assert_eq!(
        ascending.groups, ASCENDING,
        "and the same bytes walk up when the request asked for Ascending"
    );
    assert!(ascending.bypasses.is_empty(), "and nothing was given up: {:?}", ascending.bypasses);
}

/// **A FETCH that names no order has still named one.**
///
/// Draft-19 Section 10.2.8: "If omitted from FETCH, the receiver uses Ascending
/// (0x1)." The absence is the answer, so a session that treated it as silence
/// would leave every conforming fetch that did not bother to write the
/// parameter unreadable — which is most of them.
///
/// *Ablation, recorded:* have `AnyControlMessage::fetch_group_order` answer
/// `None` for a FETCH carrying no GROUP_ORDER parameter:
///
/// ```text
/// assertion `left == right` failed: an omitted GROUP_ORDER is the draft's
/// Ascending, not a silence
///   left: []
///  right: [20, 21, 22]
/// ```
#[tokio::test]
async fn a_fetch_that_names_no_order_is_read_as_ascending() {
    let plain = run(Some(None)).await;
    assert_eq!(
        plain.groups, ASCENDING,
        "an omitted GROUP_ORDER is the draft's Ascending, not a silence"
    );
    assert!(plain.bypasses.is_empty(), "and nothing was given up: {:?}", plain.bypasses);
}

/// **A response to a request nobody made is forwarded and reported, not
/// guessed at.**
///
/// The one case the bypass still has. The publisher opened a fetch stream
/// naming a Request ID this session never carried a FETCH for, so the proxy
/// has no order for it and reading the stream would mean choosing one. It
/// forwards the bytes untouched and says why — which is the difference between
/// a gap the operator can see and a report that is quietly wrong.
///
/// *Ablation, recorded:* have `ObjectFramer::fetch_stage` fall back to
/// `AnyFetchGroupOrder::Ascending` when the table has no entry:
///
/// ```text
/// assertion `left == right` failed: a fetch stream nobody asked for is given
/// up rather than read against a guess
///   left: []
///  right: [FetchGroupOrderUnknown]
/// ```
#[tokio::test]
async fn a_response_to_a_request_that_was_never_made_is_given_up() {
    let unasked = run(None).await;
    assert_eq!(
        unasked.bypasses,
        vec![BypassReason::FetchGroupOrderUnknown],
        "a fetch stream nobody asked for is given up rather than read against a guess"
    );
    assert!(unasked.groups.is_empty(), "and no Location is reported off it: {:?}", unasked.groups);
}

/// **The order filed is the one the publisher will act on, not the one the
/// subscriber sent.**
///
/// A hook with `Interest::CONTROL` rewrites the FETCH on its way through, and
/// the two ends of the session then disagree about what was asked for: the
/// subscriber wrote Ascending, the publisher received Descending, and it is
/// the publisher that decides which way the response's Group IDs walk. So the
/// proxy has to read the frame it is about to write rather than the one it
/// just read — which is why the mutating pipe files its order after the hook's
/// verdict and from the outgoing bytes.
///
/// This is the case a proxy is for. Every other run in this file would pass a
/// session that filed what arrived.
///
/// *Ablation, recorded:* drop the `note_fetch_order` call from the mutating
/// pipe's `Plan::WriteNow` arm, so nothing is filed on a session whose control
/// frames a hook may rewrite:
///
/// ```text
/// assertion `left == right` failed: the response follows the FETCH the
/// publisher received
///   left: []
///  right: [20, 19, 18]
/// ```
#[tokio::test]
async fn a_rewritten_fetch_files_the_order_the_publisher_receives() {
    let rewritten =
        run_with_hook(Some(Some(0x1)), Arc::new(RewriteToDescending), Some(fetch(Some(0x2)))).await;
    assert_eq!(
        rewritten.groups, DESCENDING,
        "the response follows the FETCH the publisher received"
    );
    assert!(rewritten.bypasses.is_empty(), "and nothing was given up: {:?}", rewritten.bypasses);
}

//! Stream, object, close and control events carry the QUIC stream ID of the leg
//! named by their `side`, numbered as RFC 9000 Section 2.1 numbers them.

#![cfg(feature = "draft18")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::{
    AnyControlMessage, AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter,
};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::event::{ProxyEvent, ProxySide};
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::ProxyObserver;

const DRAFT: DraftVersion = DraftVersion::Draft18;

const PATIENCE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<ProxyEvent>>,
}

impl ProxyObserver for Recorder {
    fn on_event(&self, event: &ProxyEvent) {
        self.events.lock().expect("events").push(event.clone());
    }
}

impl Recorder {
    fn ids(&self, pick: impl Fn(&ProxyEvent) -> Option<u64>) -> Vec<u64> {
        let mut ids: Vec<u64> =
            self.events.lock().expect("events").iter().filter_map(pick).collect();
        ids.sort_unstable();
        ids
    }

    /// Polls until the picked IDs equal `want`, then returns them; returns what it has
    /// once `PATIENCE` runs out.
    async fn wait_for(&self, want: &[u64], pick: impl Fn(&ProxyEvent) -> Option<u64>) -> Vec<u64> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let got = self.ids(&pick);
            if got == want || Instant::now() >= deadline {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn framed(msg: &AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("every fixture message encodes");
    out
}

fn setup() -> Vec<u8> {
    use moqtap_codec::draft18::message::{ControlMessage, Setup};
    framed(&AnyControlMessage::Draft18(ControlMessage::Setup(Setup { options: Vec::new() })))
}

fn subscribe(request_id: u64, track: &[u8]) -> Vec<u8> {
    use moqtap_codec::draft18::message::{ControlMessage, Subscribe};
    framed(&AnyControlMessage::Draft18(ControlMessage::Subscribe(Subscribe {
        request_id: VarInt::from_u64(request_id).expect("a request id"),
        track_namespace: TrackNamespace(vec![b"live".to_vec()]),
        track_name: track.to_vec(),
        parameters: Vec::new(),
    })))
}

/// A subgroup stream on `alias` carrying two objects.
fn subgroup_stream(alias: u8) -> Vec<u8> {
    let head = vec![0x14, alias, 0x00, 0x00, 0x80];
    let header = AnySubgroupHeader::decode_stream(DRAFT, &mut &head[..]).expect("header decodes");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("writer");
    let mut out = head;
    for id in 0..2u64 {
        let obj = AnySubgroupObject {
            object_id: id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: b"payload".to_vec(),
        };
        writer.write_object(&obj, &mut out).expect("object encodes");
    }
    out
}

fn on(side: ProxySide, event_side: ProxySide, id: u64) -> Option<u64> {
    (side == event_side).then_some(id)
}

/// Two request streams and two data streams on a draft-18 session report four distinct IDs
/// each, of the stream type and initiator the IDs encode.
#[tokio::test]
async fn events_carry_the_quic_stream_id_of_their_leg() {
    common::init_crypto();
    let alpn = DRAFT.quic_alpn();

    let relay = common::FakeRelay::bind(alpn);
    let recorder = Arc::new(Recorder::default());
    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        alpn,
        Arc::clone(&recorder) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );
    let (_client_ep, client) = common::connect_client(proxy.addr, alpn).await;

    // Control plane: client uni 2, relay uni 3.
    let mut client_control = client.open_uni().await.expect("client control stream");
    client_control.write_all(&setup()).await.expect("client SETUP");
    let _relay_control_in = relay.accept_uni().await;
    let relay_conn = relay.connection().await;
    let mut relay_control = relay_conn.open_uni().await.expect("relay control stream");
    relay_control.write_all(&setup()).await.expect("relay SETUP");
    let _client_control_in = client.accept_uni().await.expect("client accepts control");

    // Request streams: client bidi 0 and 4 on both legs.
    let mut requests = Vec::new();
    for (request_id, track) in [(0u64, &b"video"[..]), (2, b"audio")] {
        let (mut send, recv) = client.open_bi().await.expect("request stream");
        send.write_all(&subscribe(request_id, track)).await.expect("SUBSCRIBE");
        let at_relay = tokio::time::timeout(PATIENCE, relay_conn.accept_bi())
            .await
            .expect("the request reaches the relay")
            .expect("relay accept_bi");
        requests.push((send, recv, at_relay));
    }

    // Data streams: relay uni 7 and 11 on both legs.
    for alias in [1u8, 2] {
        let mut send = relay_conn.open_uni().await.expect("data stream");
        send.write_all(&subgroup_stream(alias)).await.expect("subgroup bytes");
        send.finish().expect("finish");
    }
    for _ in 0..2 {
        let mut recv = tokio::time::timeout(PATIENCE, client.accept_uni())
            .await
            .expect("a data stream reaches the client")
            .expect("client accept_uni");
        recv.read_to_end(1 << 16).await.expect("data stream reads to its end");
    }

    let c2p = ProxySide::ClientToProxy;
    let r2p = ProxySide::RelayToProxy;

    let bidi_in = recorder
        .wait_for(&[0, 4], |e| match e {
            ProxyEvent::BiStreamOpened { side, stream_id, .. } => on(c2p, *side, *stream_id),
            _ => None,
        })
        .await;
    assert_eq!(bidi_in, vec![0, 4], "client-initiated bidirectional IDs are 0 mod 4");

    let bidi_out = recorder.ids(|e| match e {
        ProxyEvent::BiStreamOpened { side, stream_id, .. } => {
            on(ProxySide::ProxyToRelay, *side, *stream_id)
        }
        _ => None,
    });
    assert_eq!(bidi_out, vec![0, 4], "the proxy opens them upstream as a client");

    let subscribes = recorder
        .wait_for(&[0, 4], |e| match e {
            ProxyEvent::ControlMessage { side, stream_id, .. } if *side == c2p => *stream_id,
            _ => None,
        })
        .await;
    assert_eq!(subscribes, vec![0, 4], "each SUBSCRIBE names its own request stream");

    let setups = recorder.ids(|e| match e {
        ProxyEvent::SetupMessage { stream_id, .. } => *stream_id,
        _ => None,
    });
    assert_eq!(setups, vec![2, 3], "client uni is 2 mod 4, server uni is 3 mod 4");

    let headers = recorder
        .wait_for(&[7, 11], |e| match e {
            ProxyEvent::DataStreamHeader { side, stream_id, .. } => on(r2p, *side, *stream_id),
            _ => None,
        })
        .await;
    assert_eq!(headers, vec![7, 11], "the relay's data streams follow its control stream");

    let mut raws: Vec<Vec<u8>> = recorder
        .events
        .lock()
        .expect("events")
        .iter()
        .filter_map(|e| match e {
            ProxyEvent::DataStreamHeader { side, raw, .. } if *side == r2p => Some(raw.to_vec()),
            _ => None,
        })
        .collect();
    raws.sort();
    assert_eq!(
        raws,
        vec![vec![0x14, 1, 0, 0, 0x80], vec![0x14, 2, 0, 0, 0x80]],
        "each header event carries the header's bytes and nothing after them"
    );

    // Type 0x00, alias 1, group 2^32, object 3, priority 0x80, then the payload.
    let datagram_header = [0x00, 0x01, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80];
    let datagram = [&datagram_header[..], b"frame"].concat();
    relay_conn.send_datagram(datagram.into()).expect("relay send_datagram");
    let deadline = Instant::now() + PATIENCE;
    let seen = loop {
        let seen = recorder.events.lock().expect("events").iter().find_map(|e| match e {
            ProxyEvent::Datagram { side, header_raw, payload_len, .. } if *side == r2p => {
                Some((header_raw.to_vec(), *payload_len))
            }
            _ => None,
        });
        if seen.is_some() || Instant::now() >= deadline {
            break seen;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        seen,
        Some((datagram_header.to_vec(), 5)),
        "a datagram's header bytes stop at its payload"
    );

    let objects = recorder
        .wait_for(&[7, 7, 11, 11], |e| match e {
            ProxyEvent::Object { side, stream_id, .. } => on(r2p, *side, *stream_id),
            _ => None,
        })
        .await;
    assert_eq!(objects, vec![7, 7, 11, 11], "each object names the stream it arrived on");

    let uni_in = recorder.ids(|e| match e {
        ProxyEvent::UniStreamOpened { side, stream_id, .. } => on(r2p, *side, *stream_id),
        _ => None,
    });
    assert_eq!(uni_in, vec![3, 7, 11]);

    let closed = recorder
        .wait_for(&[7, 11], |e| match e {
            ProxyEvent::StreamClosed { side, stream_id, .. } => on(r2p, *side, *stream_id),
            _ => None,
        })
        .await;
    assert_eq!(closed, vec![7, 11], "a FIN names the stream it ended");

    drop(requests);
    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

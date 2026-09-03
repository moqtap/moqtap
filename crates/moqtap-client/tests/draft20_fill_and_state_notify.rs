#![cfg(feature = "draft20")]
//! The three things draft-20 added that a subscriber has to be able to do on
//! the wire: ask for a fill, read the stream that answers it, and take the
//! unilateral notice that a subscription's state moved.
//!
//! # What each gate is for
//!
//! **`FILL_PARAMETERS` goes out as the block draft-20 defines.** Section
//! 10.2.15 says the value is "a sequence of Parameters that apply to the fill
//! fetch stream" and is "encoded as if they were Parameters for a separate
//! message"
//! and stops there, so whether that block carries a `Number of Parameters`
//! count is a choice — recorded in this repository's `DECISIONS.md` as D1, made
//! in `draft20::fill`, and made again in the codec's decoder. The gate is the
//! bytes on the wire, read back by a peer that decodes them with the codec, so
//! the two halves of the choice have to agree for it to pass.
//!
//! **A fill fetch stream is attributable.** Section 5.1.3: "The FETCH_HEADER on
//! the fill fetch stream carries the Request ID of the message that initiated
//! it: the SUBSCRIBE Request ID for the initial fill". A client that knew only
//! about fetches would answer that header with "unknown request", so the gate
//! is that the subscription's own Request ID opens a stream the endpoint
//! accounts for — and that ending it leaves the subscription alone, which is
//! what Section 5.1.3.1 requires.
//!
//! **PUBLISH_STATE_NOTIFY is taken and answered with nothing.** Section 10.10
//! makes it unilateral: "the receiver does not respond with REQUEST_OK or
//! REQUEST_ERROR, and the message is not subject to the MAX_REQUEST_UPDATES
//! limit". Routing it through the REQUEST_UPDATE path instead would spend a
//! credit the peer never spent and leave this endpoint owing an answer the
//! section forbids it to send, so the gate reads the event *and* asserts that
//! nothing is owed.
//!
//! # Why a loopback and not three unit tests
//!
//! Each of the three crosses a seam the unit tests in `endpoint.rs` and
//! `fill.rs` do not: the parameter has to survive the encoder, the fill stream
//! has to come off `accept_uni` and be told apart from a subgroup, and the
//! notify has to reach the observer from `recv_on_request_stream`. The unit
//! tests hold the decisions; this holds the plumbing.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_client::draft20::connection::{ClientConfig, Connection, TransportType};
use moqtap_client::draft20::event::{ClientEvent, StreamKind};
use moqtap_client::draft20::fill::{FillParameters, LocationFilter};
use moqtap_client::draft20::observer::ConnectionObserver;
use moqtap_codec::dispatch::{AnyControlMessage, AnyFetchHeader};
use moqtap_codec::draft20::data_stream::FetchHeader;
use moqtap_codec::draft20::message::{
    decode_fill_parameters, decode_location_filter, ControlMessage, PublishStateNotify, Setup,
    SubscribeOk, FILL_PARAMETERS, LOCATION_FILTER,
};
use moqtap_codec::kvp::KvpValue;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The Track Alias the peer's SUBSCRIBE_OK binds.
const ALIAS: u64 = 4;

/// The track every gate here subscribes to.
const TRACK: &[u8] = b"video";

/// `LARGEST_OBJECT`, Parameter Type 0x09 — the parameter Section 10.10 says a
/// PUBLISH_STATE_NOTIFY MUST carry when the publisher knows it, so the fixture
/// carries one rather than being an empty message the rule would not recognise.
const LARGEST_OBJECT: u64 = 0x09;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("a fixture value fits a varint")
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft20,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

/// The fill this client asks for: everything from group 4 object 0 through
/// group 6 object 9, inclusive at both ends.
///
/// Written as a four-field filter so the inclusive end is on the wire and
/// visible to the assertion. Draft-19's encoder would have written 10 for the
/// last object of a range ending at 9; draft-20 Sections 5.1.2 and 10.13 make
/// the range inclusive and this writes 9.
fn fill_range() -> LocationFilter {
    LocationFilter::range_to(4, 0, 2, 9).expect("the end group is in range")
}

/// The peer's SETUP. Its message type is also its stream's type, so these bytes
/// go on a fresh unidirectional stream with nothing in front of them.
fn setup_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft20(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut out)
        .expect("encode SETUP");
    out
}

/// The answer that binds the alias. A draft-20 response carries no Request ID —
/// the stream it comes back on is the correlation — so this is the whole of it.
fn subscribe_ok_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft20(ControlMessage::SubscribeOk(SubscribeOk {
        track_alias: v(ALIAS),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    }))
    .encode(&mut out)
    .expect("encode SUBSCRIBE_OK");
    out
}

/// A PUBLISH_STATE_NOTIFY carrying the one parameter Section 10.10 requires.
fn state_notify_bytes() -> Vec<u8> {
    // A Location is two consecutive varints, with no length ahead of them
    // (Section 10.2.17). Both fit one byte, so these are the varints.
    let location = vec![6u8, 9];
    let mut out = Vec::new();
    AnyControlMessage::Draft20(ControlMessage::PublishStateNotify(PublishStateNotify {
        parameters: vec![moqtap_codec::kvp::KeyValuePair {
            key: v(LARGEST_OBJECT),
            value: KvpValue::Bytes(location),
        }],
    }))
    .encode(&mut out)
    .expect("encode PUBLISH_STATE_NOTIFY");
    out
}

/// The fill fetch stream's header: a FETCH_HEADER carrying the **subscription's**
/// Request ID, on a unidirectional stream of its own.
fn fill_stream_bytes(request_id: u64) -> Vec<u8> {
    let mut out = Vec::new();
    AnyFetchHeader::Draft20(FetchHeader { request_id: v(request_id) }).encode(&mut out);
    out
}

/// A reader that pulls whole control messages off one quinn stream.
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, buf: Vec::new() }
    }

    async fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 2048];
        match self.recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
            _ => false,
        }
    }

    async fn read_control(&mut self) -> Option<AnyControlMessage> {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(DraftVersion::Draft20, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    if !self.fill().await {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

/// Every event the client emitted, in order.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<ClientEvent>>,
}

impl ConnectionObserver for Recorder {
    fn on_event(&self, event: &ClientEvent) {
        self.events.lock().expect("not poisoned").push(event.clone());
    }
}

/// The connection takes a `Box<dyn ConnectionObserver>` and the assertions need
/// the recorder afterwards, so the handle is what implements the trait.
struct Shared(Arc<Recorder>);

impl ConnectionObserver for Shared {
    fn on_event(&self, event: &ClientEvent) {
        self.0.on_event(event);
    }
}

/// What the peer read off the client's SUBSCRIBE, so a gate can assert on it
/// after the session has run.
struct WhatThePeerSaw {
    /// The raw `FILL_PARAMETERS` value, exactly as it arrived.
    fill_value: Vec<u8>,
    /// The `LOCATION_FILTER` fields nested inside it.
    fill_range_fields: Vec<u64>,
}

/// Serve one connection: the setup exchange, the SUBSCRIBE and its answer, one
/// fill fetch stream, and one PUBLISH_STATE_NOTIFY.
async fn serve(server: quinn::Endpoint) -> WhatThePeerSaw {
    let conn = server.accept().await.expect("accept").await.expect("tls handshake");

    let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"));
    control.read_control().await.expect("read the client's SETUP");

    let mut our_control = conn.open_uni().await.expect("open the peer's control stream");
    our_control.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

    let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
    let mut request = PeerStream::new(request);
    let subscribe = match request.read_control().await {
        Some(AnyControlMessage::Draft20(ControlMessage::Subscribe(m))) => m,
        other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
    };
    let request_id = subscribe.request_id.into_inner();

    let fill = subscribe
        .parameters
        .iter()
        .find(|p| p.key.into_inner() == FILL_PARAMETERS)
        .expect("the SUBSCRIBE asks for a fill");
    let KvpValue::Bytes(fill_value) = &fill.value else {
        panic!("FILL_PARAMETERS uses length-prefixed encoding")
    };
    let nested = decode_fill_parameters(fill_value).expect("the nested block decodes");
    let inner_filter = nested
        .iter()
        .find(|p| p.key.into_inner() == LOCATION_FILTER)
        .expect("the fill names its range");
    let KvpValue::Bytes(filter_value) = &inner_filter.value else {
        panic!("LOCATION_FILTER is length-prefixed")
    };
    let fill_range_fields = decode_location_filter(filter_value).expect("the filter decodes");

    answer.write_all(&subscribe_ok_bytes()).await.expect("write SUBSCRIBE_OK");

    // The fill, opened and finished. Section 5.1.3.1: "The publisher signals
    // that the fill is complete by closing the stream with a FIN once all
    // objects in the fill range have been delivered." There are no objects in
    // this one, which is a fill of an empty range and still a well-formed
    // stream.
    let mut fill_stream = conn.open_uni().await.expect("open the fill fetch stream");
    fill_stream.write_all(&fill_stream_bytes(request_id)).await.expect("write FETCH_HEADER");
    fill_stream.finish().expect("finish the fill fetch stream");

    answer.write_all(&state_notify_bytes()).await.expect("write PUBLISH_STATE_NOTIFY");

    // Held until the client has read everything: dropping `answer` resets the
    // request stream, which on this draft is how a request is withdrawn.
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(answer);

    WhatThePeerSaw { fill_value: fill_value.clone(), fill_range_fields }
}

/// The whole exchange, once, with every assertion the three gates share.
///
/// One session rather than three, because the three facts are sequential on one
/// subscription and splitting them would mean three loopbacks proving the same
/// setup.
#[tokio::test]
async fn a_subscription_asks_for_a_fill_reads_its_stream_and_takes_a_state_notify() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft20.quic_alpn()]);
    let peer = tokio::spawn(serve(endpoint));

    let mut conn =
        tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), client_config()))
            .await
            .expect("connect did not finish")
            .expect("connect");

    let recorder = Arc::new(Recorder::default());
    conn.set_observer(Box::new(Shared(Arc::clone(&recorder))));

    // ── the SUBSCRIBE, carrying the fill ──
    let fill = FillParameters::inherited()
        .with_range(&fill_range())
        .expect("a LOCATION_FILTER may be nested")
        .parameter()
        .expect("the block encodes");
    let mut request =
        tokio::time::timeout(PATIENCE, conn.subscribe(namespace(), TRACK.to_vec(), vec![fill]))
            .await
            .expect("subscribe did not finish")
            .expect("subscribe");
    let request_id = request.request_id();
    assert!(
        conn.endpoint().fill_requested(request_id),
        "a SUBSCRIBE carrying FILL_PARAMETERS is a subscription that asked for a fill"
    );

    // ── its answer ──
    let answer = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
        .await
        .expect("the answer never arrived")
        .expect("read SUBSCRIBE_OK");
    match answer {
        ControlMessage::SubscribeOk(ok) => assert_eq!(ok.track_alias.into_inner(), ALIAS),
        other => panic!("expected a SUBSCRIBE_OK, got {other:?}"),
    }

    // ── the fill fetch stream ──
    let (header, _stream) = tokio::time::timeout(PATIENCE, conn.accept_fill_stream())
        .await
        .expect("the fill fetch stream never arrived")
        .expect("its FETCH_HEADER names a subscription that asked for a fill");
    assert_eq!(
        header.request_id(),
        request_id.into_inner(),
        "Section 5.1.3 puts the SUBSCRIBE's Request ID on the initial fill's header"
    );
    assert_eq!(conn.endpoint().open_fill_streams(request_id), 1);
    assert_eq!(conn.endpoint().fill_streams_opened(request_id), 1);

    conn.endpoint_mut().on_fill_stream_ended(request_id);
    assert_eq!(conn.endpoint().open_fill_streams(request_id), 0);
    assert_eq!(
        conn.endpoint().active_subscription_count(),
        1,
        "Section 5.1.3.1: ending a fill fetch stream does not affect the subscription"
    );

    // ── the notify ──
    let notify = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
        .await
        .expect("the notify never arrived")
        .expect("a PUBLISH_STATE_NOTIFY on a subscription's own stream is taken");
    match notify {
        ControlMessage::PublishStateNotify(m) => {
            assert_eq!(m.parameters.len(), 1);
            assert_eq!(m.parameters[0].key.into_inner(), LARGEST_OBJECT);
        }
        other => panic!("expected a PUBLISH_STATE_NOTIFY, got {other:?}"),
    }
    assert!(
        !conn.endpoint().has_unanswered_update(request_id),
        "Section 10.10 makes the notify unilateral: nothing is owed in reply"
    );

    // ── what the observer saw ──
    let events = recorder.events.lock().expect("not poisoned").clone();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ClientEvent::StreamOpened { stream_kind: StreamKind::Fill, .. })),
        "a fill fetch stream is reported as one, not as a fetch: {events:?}"
    );
    let notified = events
        .iter()
        .find_map(|e| match e {
            ClientEvent::PublishStateNotify { request_id, parameters, .. } => {
                Some((*request_id, parameters.clone()))
            }
            _ => None,
        })
        .expect("the notify reaches the observer as a decoded event");
    assert_eq!(notified.0, request_id.into_inner());
    assert_eq!(notified.1.len(), 1);

    // ── the bytes the peer read ──
    let saw = tokio::time::timeout(PATIENCE * 2, peer)
        .await
        .expect("the peer task hung")
        .expect("the peer task panicked");

    // Decision D1: the value opens with a `Number of Parameters` count, so a
    // block holding one nested LOCATION_FILTER is `01` and not the bare
    // parameter. The rest is the filter: type 0x21 written as a delta from 0
    // because the nested scope restarts the chain (D2), a length of 4, and the
    // four fields.
    assert_eq!(
        saw.fill_value,
        vec![0x01, 0x21, 0x04, 4, 0, 2, 9],
        "the FILL_PARAMETERS block on the wire"
    );
    // Inclusive at both ends, and nothing added one to the last object.
    assert_eq!(saw.fill_range_fields, vec![4, 0, 2, 9]);
}

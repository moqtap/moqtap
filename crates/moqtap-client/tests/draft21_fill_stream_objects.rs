#![cfg(feature = "draft21")]
//! Objects on a fill fetch stream: the Locations they resolve to, the streams
//! they arrive on, and what ending one does to the subscription.
//!
//! `draft21_fill_and_state_notify.rs` takes a fill fetch stream as far as its
//! FETCH_HEADER and finishes it. This file is what happens after the header,
//! which is where draft-21's numbering rules are and where a fill differs from
//! everything the earlier drafts had.
//!
//! # Why a fill stream is the place to test the delta rules
//!
//! A fill fetch stream is "delivered as a FETCH response" (Section 3.4), so
//! its Objects are framed by Section 11.4.1.1 — a Serialization Flags byte and
//! whichever of Group ID Delta, Subgroup ID, Object ID Delta, Priority and
//! Properties that byte says are present. **Every absent field is inherited
//! from the prior Object**, so a reader that resolves one of them wrongly does
//! not fail: it reports a different Object, with a well-formed Location, and
//! the stream stays in sync. There is no error to catch it, on either end.
//!
//! Two of the eight flag combinations are the ones a reader is most likely to
//! get wrong, and both are exercised below:
//!
//! * **`0x04`** — Object ID Delta present, Group ID Delta absent. Section
//!   11.4.1.1: "When the Group ID Delta field is not present, the Object ID is
//!   the prior Object's ID plus the Object ID Delta if present." The delta is
//!   *added*; it is not the Object ID.
//! * **`0x08`** — Group ID Delta present, Object ID Delta absent. The Group
//!   moves, and Section 11.4.1.1 still says "If Object ID Delta is not present,
//!   the Object ID is the prior Object's ID plus one, regardless of which group
//!   it belongs to". The numbering carries **across** the group boundary: it
//!   does not restart at 0, which is what a reader written from the shape of
//!   the format rather than from that sentence would do.
//!
//! # What else this holds
//!
//! * **A second fill fetch stream on one subscription.** Section 3.4: "a
//!   subscription can have multiple fill fetch streams open at once, each
//!   identified by its Request ID; opening a new fill fetch stream does not
//!   implicitly cancel any previously opened fill fetch streams."
//!   Each carries the subscription's Request ID, and each
//!   starts a delta chain of its own — the second stream's first Object states
//!   an absolute Location, and resolving it against the first stream's last
//!   Object would put it somewhere else entirely.
//! * **Both endings, and that neither disturbs the subscription.** A FIN means
//!   the fill range was delivered (Section 3.4.1) and is the only end signal
//!   a fill has — there is no FETCH_OK on a fill stream, so nothing states an
//!   End Location. A reset means the fill failed. After one of each, the
//!   subscription is still live and still carrying control messages.
//! * **Object Properties, and `INCLUDE_PROPERTIES`.** The SUBSCRIBE here
//!   carries `INCLUDE_PROPERTIES = 0` (0x35) and a fill Object still arrives
//!   with its Properties intact. That is not an accident of this
//!   implementation: Section 9.20.22 makes the parameter govern the **Track
//!   Properties** in an OK message, and a fill fetch stream has no OK message at
//!   all. Object Properties on a fill Object are governed by Serialization
//!   Flags bit 0x20 and by nothing else. The parameter is also absent from
//!   Table 6, so it cannot be nested inside `FILL_PARAMETERS`; `fill.rs` holds
//!   that half.
//! * **The Group Order a fill is read in.** Section 9.20.9: "When it appears
//!   inside FILL_PARAMETERS, it governs the fill fetch stream and its ordering
//!   relative to subscription-delivered Objects". The second gate asks for a
//!   Descending fill and never tells the reader — the client resolves it from
//!   the parameters it sent.
//!
//! # The bytes are written out, not built
//!
//! The peer writes each Object as a literal byte sequence rather than through
//! an encoder. A test whose expectation comes from the same code as its input
//! agrees with itself whatever either does; these bytes come from Figure 27 and
//! Table 9, and what is asserted is the Locations a draft-21 subscriber must
//! read out of them.

mod common;

use std::time::Duration;

use moqtap_client::draft21::connection::{ClientConfig, Connection, TransportType};
use moqtap_client::draft21::fill::{FillParameters, LocationFilter};
use moqtap_codec::dispatch::{AnyControlMessage, AnyFetchHeader};
use moqtap_codec::draft21::data_stream::{FetchHeader, GroupOrder};
use moqtap_codec::draft21::message::{
    ControlMessage, PublishStateNotify, Setup, SubscribeOk, FILL_PARAMETERS,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The Track Alias the peer's SUBSCRIBE_OK binds.
const ALIAS: u64 = 4;

/// The track both gates subscribe to.
const TRACK: &[u8] = b"video";

/// `INCLUDE_PROPERTIES`, Parameter Type 0x35 (Section 9.20.22).
const INCLUDE_PROPERTIES: u64 = 0x35;

/// `LARGEST_OBJECT`, Parameter Type 0x09 — the parameter Section 9.10 makes a
/// PUBLISH_STATE_NOTIFY carry when the publisher knows it.
const LARGEST_OBJECT: u64 = 0x09;

/// The payload every Object with one carries.
const PAYLOAD: [u8; 3] = [0xDE, 0xAD, 0xBE];

/// The Object Properties one fill Object carries: a `Properties Length` of 2
/// (written by the encoder, not held here) over one Key-Value-Pair — an even
/// Property Type `0x02`, whose value is the single `vi64` `0x2A`.
///
/// The codec keeps these bytes opaque, so what is asserted is that they come
/// back exactly as they went out.
const PROPERTIES: [u8; 2] = [0x02, 0x2A];

/// The application error code the peer resets the failed fill with. Any value;
/// what matters is that the same one comes back.
const FILL_FAILED: u64 = 0x1234;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("a fixture value fits a varint")
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft21,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn setup_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft21(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut out)
        .expect("encode SETUP");
    out
}

fn subscribe_ok_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft21(ControlMessage::SubscribeOk(SubscribeOk {
        track_alias: v(ALIAS),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    }))
    .encode(&mut out)
    .expect("encode SUBSCRIBE_OK");
    out
}

/// A PUBLISH_STATE_NOTIFY, used here only as proof that the subscription's own
/// stream still carries messages after a fill fetch stream has been reset.
fn state_notify_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    AnyControlMessage::Draft21(ControlMessage::PublishStateNotify(PublishStateNotify {
        parameters: vec![KeyValuePair {
            key: v(LARGEST_OBJECT),
            // A Location is two consecutive varints with no length ahead of
            // them (Section 9.20.18).
            value: KvpValue::Bytes(vec![9u8, 5]),
        }],
    }))
    .encode(&mut out)
    .expect("encode PUBLISH_STATE_NOTIFY");
    out
}

/// A fill fetch stream's FETCH_HEADER, carrying the subscription's Request ID.
fn fetch_header_bytes(request_id: u64) -> Vec<u8> {
    let mut out = Vec::new();
    AnyFetchHeader::Draft21(FetchHeader { request_id: v(request_id) }).encode(&mut out);
    out
}

/// The five Objects of the first fill fetch stream, written out field by field.
///
/// Read down the flags column: `0x1F` states everything, `0x05` moves the
/// Object ID by a delta inside one group, `0x01` states nothing at all, `0x09`
/// moves the Group and lets the Object ID run on across the boundary, and
/// `0x25` adds Properties.
fn first_fill_objects() -> Vec<u8> {
    let mut out = Vec::new();

    // 0x1F = 0b0001_1111: Subgroup ID mode 0b11 (explicit field), Object ID
    // Delta (0x04), Group ID Delta (0x08), Priority (0x10). Section 11.4.1.1
    // requires both deltas on the first Object, "and these values are the
    // absolute Group ID and Object ID". Group 4, Subgroup 7, Object 0,
    // Priority 128.
    out.extend_from_slice(&[0x1F, 0x04, 0x07, 0x00, 0x80, PAYLOAD.len() as u8]);
    out.extend_from_slice(&PAYLOAD);

    // 0x05 = 0b0000_0101: Subgroup ID mode 0b01 (the prior Object's), Object ID
    // Delta present, **no** Group ID Delta. The delta is added to the prior
    // Object's ID: 0 + 2 = 2, in the same Group 4.
    out.extend_from_slice(&[0x05, 0x02, PAYLOAD.len() as u8]);
    out.extend_from_slice(&PAYLOAD);

    // 0x01 = 0b0000_0001: mode 0b01 and nothing else. No Group ID Delta, no
    // Object ID Delta: Group 4 again, Object 2 + 1 = 3.
    out.extend_from_slice(&[0x01, PAYLOAD.len() as u8]);
    out.extend_from_slice(&PAYLOAD);

    // 0x09 = 0b0000_1001: mode 0b01, Group ID Delta present, Object ID Delta
    // absent. Ascending, so the Group is 4 + 0 + 1 = 5 — and the Object ID is
    // the prior one plus one, 3 + 1 = 4, *not* a restart at 0.
    out.extend_from_slice(&[0x09, 0x00, PAYLOAD.len() as u8]);
    out.extend_from_slice(&PAYLOAD);

    // 0x25 = 0b0010_0101: mode 0b01, Object ID Delta, Properties. Group 5
    // still, Object 4 + 1 = 5, and two bytes of Properties under their own
    // length prefix.
    out.extend_from_slice(&[0x25, 0x01, PROPERTIES.len() as u8]);
    out.extend_from_slice(&PROPERTIES);
    out.extend_from_slice(&[PAYLOAD.len() as u8]);
    out.extend_from_slice(&PAYLOAD);

    out
}

/// The two Objects of the second fill fetch stream.
///
/// Both payload-free, which on a fetch record is simply an Object with no
/// payload: Section 11.1.2 puts Object Status only on subscription-delivered
/// Objects, so there is no status field here to disagree with a zero length.
fn second_fill_objects() -> Vec<u8> {
    // 0x1F again: Group 9, Subgroup 1, Object 3, Priority 64. Absolute, because
    // it is the first Object of *this* stream.
    let mut out = vec![0x1F, 0x09, 0x01, 0x03, 0x40, 0x00];
    // 0x00: Subgroup ID mode 0b00, which Table 8 makes "Subgroup ID is zero"
    // rather than "the prior Object's" — so the Subgroup drops from 1 to 0 —
    // and no deltas, so Group 9, Object 3 + 1 = 4, Priority still 64.
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

/// The two Objects of a Descending fill fetch stream.
fn descending_fill_objects() -> Vec<u8> {
    // 0x1F: Group 10, Subgroup 0, Object 0, Priority 128.
    let mut out = vec![0x1F, 0x0A, 0x00, 0x00, 0x80, 0x00];
    // 0x0D = 0b0000_1101: mode 0b01, both deltas present. Section 11.4.1.1:
    // "If the Group Order is Descending, the Group ID is the prior Object's
    // Group ID minus the (Group ID Delta + 1)" — 10 - 1 = 9. Read Ascending the
    // same bytes say Group 11, which is what makes this a gate rather than a
    // restatement. The Object ID is the delta itself, because a Group ID Delta
    // restarts it.
    out.extend_from_slice(&[0x0D, 0x00, 0x05, 0x00]);
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
            match AnyControlMessage::decode(DraftVersion::Draft21, &mut cursor) {
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

/// The setup exchange, then the SUBSCRIBE and its answer. Leaves the peer
/// holding the request stream's send half and the Request ID it carried.
async fn accept_subscription(
    server: &quinn::Endpoint,
) -> (quinn::Connection, quinn::SendStream, u64) {
    let conn = server.accept().await.expect("accept").await.expect("tls handshake");

    let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"));
    control.read_control().await.expect("read the client's SETUP");
    let mut our_control = conn.open_uni().await.expect("open the peer's control stream");
    our_control.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

    let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
    let mut request = PeerStream::new(request);
    let subscribe = match request.read_control().await {
        Some(AnyControlMessage::Draft21(ControlMessage::Subscribe(m))) => m,
        other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
    };
    assert!(
        subscribe.parameters.iter().any(|p| p.key.into_inner() == FILL_PARAMETERS),
        "the SUBSCRIBE has to ask for a fill or no fill fetch stream is legal"
    );
    let request_id = subscribe.request_id.into_inner();
    answer.write_all(&subscribe_ok_bytes()).await.expect("write SUBSCRIBE_OK");
    (conn, answer, request_id)
}

/// Write one fill fetch stream and finish it.
async fn write_fill(conn: &quinn::Connection, request_id: u64, objects: &[u8]) {
    let mut stream = conn.open_uni().await.expect("open the fill fetch stream");
    stream.write_all(&fetch_header_bytes(request_id)).await.expect("write FETCH_HEADER");
    stream.write_all(objects).await.expect("write the objects");
    stream.finish().expect("FIN is what says the fill range was delivered");
}

/// Three fill fetch streams on one subscription — two finished, one reset —
/// followed by a control message on the subscription's own stream.
async fn serve_three_fills(server: quinn::Endpoint) {
    let (conn, mut answer, request_id) = accept_subscription(&server).await;

    write_fill(&conn, request_id, &first_fill_objects()).await;
    write_fill(&conn, request_id, &second_fill_objects()).await;

    // Section 3.4.1: "the publisher signals a fill failure by resetting the
    // stream; it MUST open a fill fetch stream and reset it immediately after
    // the FETCH_HEADER if necessary." The pause is so the header is on the wire
    // before the reset abandons what follows it.
    let mut failed = conn.open_uni().await.expect("open the failing fill fetch stream");
    failed.write_all(&fetch_header_bytes(request_id)).await.expect("write FETCH_HEADER");
    tokio::time::sleep(Duration::from_millis(300)).await;
    failed.reset(quinn::VarInt::from_u64(FILL_FAILED).expect("a code")).expect("reset");

    // The subscription is untouched by all three, which is what this proves:
    // its request stream still carries messages.
    answer.write_all(&state_notify_bytes()).await.expect("write PUBLISH_STATE_NOTIFY");

    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(answer);
}

/// One Descending fill fetch stream, and nothing else.
async fn serve_descending_fill(server: quinn::Endpoint) {
    let (conn, answer, request_id) = accept_subscription(&server).await;
    write_fill(&conn, request_id, &descending_fill_objects()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(answer);
}

/// One Object and its payload off a fill fetch stream, under the shared
/// timeout.
async fn read_one(
    stream: &mut moqtap_client::draft21::connection::FramedRecvStream,
) -> (moqtap_codec::draft21::data_stream::FetchObject, Vec<u8>) {
    tokio::time::timeout(PATIENCE, stream.read_fetch_object())
        .await
        .expect("an object never arrived")
        .expect("the object decodes")
}

/// The `FILL_PARAMETERS` a gate puts on its SUBSCRIBE, and the
/// `INCLUDE_PROPERTIES` beside it.
fn subscribe_parameters(fill: FillParameters) -> Vec<KeyValuePair> {
    vec![
        fill.parameter().expect("the fill block encodes"),
        // 0x35 > 0x23, so this is already in the ascending order by Parameter
        // Type that the wire requires. Section 9.20.22 gives the value 0 as
        // "do not send Properties" — the Track Properties in SUBSCRIBE_OK,
        // which is the only thing it governs.
        KeyValuePair { key: v(INCLUDE_PROPERTIES), value: KvpValue::Varint(v(0)) },
    ]
}

/// Five Objects on one fill fetch stream, a second stream on the same
/// subscription, a third that fails, and a subscription that notices none of it.
///
/// One session rather than four, because the four facts are sequential on one
/// subscription: the second stream's independence is only a claim if the first
/// one ran, and a subscription that survived is only a claim if something
/// happened to it first.
#[tokio::test]
async fn objects_on_a_fill_stream_resolve_where_the_deltas_put_them() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft21.quic_alpn()]);
    let peer = tokio::spawn(serve_three_fills(endpoint));

    let mut conn =
        tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), client_config()))
            .await
            .expect("connect did not finish")
            .expect("connect");

    // A fill over groups 4 through 9 inclusive, which is where the Objects
    // below live. Nothing adds one to the 9.
    let fill = FillParameters::inherited()
        .with_range(&LocationFilter::range(4, 0, 5).expect("the end group is in range"))
        .expect("a LOCATION_FILTER may be nested");
    let mut request = tokio::time::timeout(
        PATIENCE,
        conn.subscribe(namespace(), TRACK.to_vec(), subscribe_parameters(fill)),
    )
    .await
    .expect("subscribe did not finish")
    .expect("subscribe");
    let request_id = request.request_id();

    let answer = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
        .await
        .expect("the answer never arrived")
        .expect("read SUBSCRIBE_OK");
    assert!(matches!(answer, ControlMessage::SubscribeOk(_)));

    assert_eq!(
        conn.endpoint().fill_group_order(request_id),
        Some(GroupOrder::Ascending),
        "no GROUP_ORDER in either scope, so Section 9.20.9's FETCH default stands"
    );

    // ── the first fill fetch stream ──
    //
    // Nothing calls `begin_fetch_objects`: `accept_fill_stream` started the
    // reader with the order the endpoint resolved when the SUBSCRIBE went out.
    let (header, mut fill_stream) = tokio::time::timeout(PATIENCE, conn.accept_fill_stream())
        .await
        .expect("the fill fetch stream never arrived")
        .expect("its FETCH_HEADER names a subscription that asked for a fill");
    assert_eq!(header.request_id(), request_id.into_inner());

    let (first, payload) = read_one(&mut fill_stream).await;
    assert_eq!((first.group_id, first.object_id), (4, 0), "the first Object states its Location");
    assert_eq!(first.subgroup_id, Some(7));
    assert_eq!(first.publisher_priority, Some(128));
    assert_eq!(payload, PAYLOAD);

    let (second, _) = read_one(&mut fill_stream).await;
    assert_eq!(
        (second.group_id, second.object_id),
        (4, 2),
        "flags 0x04: the Object ID Delta is added to the prior Object's ID, not used as it"
    );
    assert_eq!(second.subgroup_id, Some(7), "Subgroup ID mode 0b01 is the prior Object's");
    assert_eq!(second.publisher_priority, Some(128), "no Priority field means the prior one");

    let (third, _) = read_one(&mut fill_stream).await;
    assert_eq!(
        (third.group_id, third.object_id),
        (4, 3),
        "no deltas at all: the same Group, and the prior Object's ID plus one"
    );

    let (fourth, _) = read_one(&mut fill_stream).await;
    assert_eq!(
        (fourth.group_id, fourth.object_id),
        (5, 4),
        "flags 0x08: the Group moves and the Object ID runs on across the boundary, \
         'regardless of which group it belongs to' — it does not restart at 0"
    );
    assert_eq!(fourth.subgroup_id, Some(7));
    assert_eq!(fourth.publisher_priority, Some(128));

    let (fifth, payload) = read_one(&mut fill_stream).await;
    assert_eq!((fifth.group_id, fifth.object_id), (5, 5));
    assert_eq!(
        fifth.header.properties.as_deref(),
        Some(&PROPERTIES[..]),
        "INCLUDE_PROPERTIES = 0 on the SUBSCRIBE governs Track Properties in the OK message \
         (Section 9.20.22); Object Properties on a fill Object answer to flag 0x20 alone"
    );
    assert_eq!(payload, PAYLOAD);

    // Section 3.4.1: "The publisher signals that the fill is complete by
    // closing the stream with a FIN once all objects in the fill range have
    // been delivered." That FIN is the whole of the signal — there is no
    // FETCH_OK on a fill stream and so no End Location to compare it against.
    let end = tokio::time::timeout(PATIENCE, fill_stream.read_fetch_object())
        .await
        .expect("the end of the stream never arrived");
    assert!(end.is_err(), "the FIN is the end of the fill and there is nothing after it");
    conn.endpoint_mut().on_fill_stream_ended(request_id);

    // ── the second fill fetch stream, on the same subscription ──
    let (header, mut second_fill) = tokio::time::timeout(PATIENCE, conn.accept_fill_stream())
        .await
        .expect("the second fill fetch stream never arrived")
        .expect("Section 3.4 allows several against one subscription");
    assert_eq!(
        header.request_id(),
        request_id.into_inner(),
        "each fill fetch stream carries the subscription's Request ID, so both carry this one"
    );
    assert_eq!(conn.endpoint().fill_streams_opened(request_id), 2);

    let (sixth, payload) = read_one(&mut second_fill).await;
    assert_eq!(
        (sixth.group_id, sixth.object_id),
        (9, 3),
        "a second fill stream starts a delta chain of its own; resolved against the first \
         stream's last Object this would be Group 15"
    );
    assert_eq!(sixth.subgroup_id, Some(1));
    assert_eq!(sixth.publisher_priority, Some(64));
    assert!(payload.is_empty(), "a zero Object Payload Length on a fetch record is no payload");

    let (seventh, _) = read_one(&mut second_fill).await;
    assert_eq!((seventh.group_id, seventh.object_id), (9, 4));
    assert_eq!(
        seventh.subgroup_id,
        Some(0),
        "Subgroup ID mode 0b00 is 'Subgroup ID is zero', not 'the prior Object's'"
    );
    assert_eq!(seventh.publisher_priority, Some(64));
    conn.endpoint_mut().on_fill_stream_ended(request_id);

    // ── the third, which fails ──
    let (_, mut failed) = tokio::time::timeout(PATIENCE, conn.accept_fill_stream())
        .await
        .expect("the failing fill fetch stream never arrived")
        .expect("a fill that will fail still opens with a FETCH_HEADER");
    let code = tokio::time::timeout(PATIENCE, failed.received_reset())
        .await
        .expect("the reset never arrived")
        .expect("a reset is observable");
    assert_eq!(
        code,
        Some(FILL_FAILED),
        "Section 3.4.1: 'the publisher signals a fill failure by resetting the stream'"
    );
    conn.endpoint_mut().on_fill_stream_ended(request_id);

    assert_eq!(conn.endpoint().fill_streams_opened(request_id), 3);
    assert_eq!(conn.endpoint().open_fill_streams(request_id), 0);

    // ── and the subscription noticed none of it ──
    let notify = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
        .await
        .expect("the subscription's stream went quiet after the fills")
        .expect("a message on a subscription whose fill was reset is still read");
    assert!(matches!(notify, ControlMessage::PublishStateNotify(_)));
    assert_eq!(
        conn.endpoint().active_subscription_count(),
        1,
        "Section 3.4.1: resetting a fill fetch stream 'does not affect the subscription'"
    );

    tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").expect("the peer task");
}

/// A `GROUP_ORDER` inside `FILL_PARAMETERS` is the order the fill is read in,
/// and the caller never has to say so twice.
///
/// The two Objects below decode to Group 10 and Group 9 under Descending and to
/// Group 10 and Group 11 under Ascending. Both readings parse; only one is the
/// one the subscription asked for. Nothing on the data stream distinguishes
/// them, which is why the parameter has to reach the reader.
///
/// Ablation: `Connection::accept_fill_stream` starts the reader with
/// `GroupOrder::Ascending` instead of the resolved order — `a Group ID Delta
/// counts downward under Descending`.
#[tokio::test]
async fn a_nested_group_order_is_the_order_the_fill_stream_is_read_in() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft21.quic_alpn()]);
    let peer = tokio::spawn(serve_descending_fill(endpoint));

    let mut conn =
        tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), client_config()))
            .await
            .expect("connect did not finish")
            .expect("connect");

    let fill = FillParameters::inherited()
        .with_group_order(GroupOrder::Descending)
        .expect("GROUP_ORDER is Table 6 row 0x22");
    let mut request = tokio::time::timeout(
        PATIENCE,
        conn.subscribe(namespace(), TRACK.to_vec(), subscribe_parameters(fill)),
    )
    .await
    .expect("subscribe did not finish")
    .expect("subscribe");
    let request_id = request.request_id();

    let answer = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
        .await
        .expect("the answer never arrived")
        .expect("read SUBSCRIBE_OK");
    assert!(matches!(answer, ControlMessage::SubscribeOk(_)));
    assert_eq!(
        conn.endpoint().fill_group_order(request_id),
        Some(GroupOrder::Descending),
        "the order was resolved from the parameters the SUBSCRIBE carried"
    );

    let (_, mut fill_stream) = tokio::time::timeout(PATIENCE, conn.accept_fill_stream())
        .await
        .expect("the fill fetch stream never arrived")
        .expect("its FETCH_HEADER names a subscription that asked for a fill");

    let (first, _) = tokio::time::timeout(PATIENCE, fill_stream.read_fetch_object())
        .await
        .expect("the first object never arrived")
        .expect("the first object decodes");
    assert_eq!((first.group_id, first.object_id), (10, 0));

    let (second, _) = tokio::time::timeout(PATIENCE, fill_stream.read_fetch_object())
        .await
        .expect("the second object never arrived")
        .expect("the second object decodes");
    assert_eq!(
        (second.group_id, second.object_id),
        (9, 5),
        "a Group ID Delta counts downward under Descending"
    );

    tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").expect("the peer task");
}

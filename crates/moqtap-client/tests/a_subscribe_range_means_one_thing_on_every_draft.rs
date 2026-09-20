//! `AnyConnection::subscribe_range` asks for the same range on every draft, and
//! each draft writes it the way that draft writes it.
//!
//! # The two filters nothing could ask for
//!
//! AbsoluteStart and AbsoluteRange are the filters that name a Start Location,
//! and they are the only two that ask a relay for anything it has **already
//! carried**. `AnyConnection::subscribe` takes a Filter Type beside the other
//! arguments and has no start location to give, so it refuses them — which left
//! the facade with no way to ask a relay for history at all, and so no way to
//! ask whether a relay holds a cache.
//!
//! `subscribe_range` takes a [`SubscribeRange`] and *derives* the Filter Type
//! from it. What has to be right is the conversion into four different wire
//! shapes, and that is what this file asserts.
//!
//! # Four shapes, and the number in an end field is not the same number twice
//!
//! * **draft-07** — Start Location and End **Location**, whose Object is "the
//!   end Object ID, plus 1. A value of 0 means the entire group is requested"
//!   (Section 6.4, in FETCH's own words).
//! * **drafts 08 through 14** — Start Location and an absolute End **Group**.
//!   Draft-08 deleted the End Object, so a range ending inside a group stopped
//!   being expressible.
//! * **drafts 15 through 19** — the same two fields, moved into the
//!   `SUBSCRIPTION_FILTER` parameter (`LOCATION_FILTER` from draft-19, same
//!   number). Drafts 15 and 16 write the End Group in full and use QUIC
//!   varints; drafts 17 and later write an End Group **Delta** and use MoQT
//!   varints.
//! * **draft-20** — `LOCATION_FILTER` with no Filter Type at all: Section 5.1.2
//!   selects the shape from how many fields the value holds, ranges are
//!   inclusive, and an End Object is back.
//!
//! # Why the loopbacks are drafts 15 through 20 and not all fourteen
//!
//! Deliberate, and it is about where a mistake survives compilation.
//!
//! On drafts 07 through 14 the range reaches the endpoint as *arguments* — a
//! `Location` and an `Option<VarInt>` — so an arm that put the start where the
//! end goes does not build, and an arm that reached for the wrong conversion
//! hands a `Location` to a parameter that wants a Group. What is left to get
//! wrong there is the draft-07 arithmetic, which is asserted below on its own,
//! and the pass-through, which
//! `a_request_helper_asks_for_what_it_was_told_on_the_earlier_drafts.rs` already
//! gates for each of those eight drafts at the layer underneath.
//!
//! From draft-15 the range is **a bag of bytes in a parameter**, and every way
//! of getting it wrong compiles and produces a well-formed SUBSCRIBE asking for
//! something else: a Filter Type that does not match the fields beside it, an
//! absolute Group where a delta belongs, the wrong varint profile, the value
//! attached under the wrong key. The codec's `SubscriptionFilter` refuses a
//! filter that disagrees with *itself*, which is a different claim — it cannot
//! know that a delta of 2 was the caller's `end_group` of 6 rather than of 5.
//! So those six drafts get a real session and the parameter is read off the
//! wire at a peer that decodes it with the codec.
//!
//! Every field asserted below is a value under 64, so its minimal varint
//! encoding is the single byte holding that number, on both encodings — the
//! value asserted and the byte on the wire are the same thing.

#![cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
))]

mod common;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyRequest, AnyTransportType, SubscribeEnd, SubscribeRange,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::KvpValue;
use moqtap_codec::types::{FilterType, GroupOrder, TrackNamespace};
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The track every subscription here names.
const TRACK: &[u8] = b"video";

/// The parameter every draft from 15 carries the filter in. Named
/// SUBSCRIPTION_FILTER through draft-18 and LOCATION_FILTER from draft-19; the
/// number did not move, and draft-20 kept it while rebuilding the value.
const FILTER_KEY: u64 = 0x21;

/// The two ranges every draft can express, in the order every gate asks for
/// them.
///
/// From Group 4 Object 0 with no end, and the same start through the whole of
/// Group 6. The third range — one that ends *inside* a group — is asked for
/// separately, because ten of the fourteen drafts cannot express it.
fn ranges() -> [SubscribeRange; 2] {
    [SubscribeRange::starting_at(4, 0), SubscribeRange::through_end_of_group(4, 0, 6)]
}

/// The range that ends inside a group, which draft-07 and draft-20 can express
/// and the twelve drafts between them cannot.
fn ends_inside_a_group() -> SubscribeRange {
    SubscribeRange::through_object(4, 0, 6, 9)
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn client_config(draft: DraftVersion) -> AnyClientConfig {
    AnyClientConfig {
        draft,
        additional_versions: Vec::new(),
        transport: AnyTransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

// ── The conversions, stated where a reader can see them at once ──

/// An end is an end Group and an open range has none, whichever way the range
/// was built.
#[test]
fn the_filter_type_comes_from_the_range_and_never_from_an_argument() {
    assert_eq!(SubscribeRange::starting_at(4, 0).filter_type(), FilterType::AbsoluteStart);
    assert_eq!(
        SubscribeRange::through_end_of_group(4, 0, 6).filter_type(),
        FilterType::AbsoluteRange
    );
    assert_eq!(ends_inside_a_group().filter_type(), FilterType::AbsoluteRange);

    assert_eq!(SubscribeRange::starting_at(4, 0).end_group(), None);
    assert_eq!(SubscribeRange::through_end_of_group(4, 0, 6).end_group(), Some(6));
    assert_eq!(ends_inside_a_group().end_group(), Some(6));
    assert_eq!(SubscribeRange::whole_group(6).end_group(), Some(6));
}

/// Draft-07's End Location is the last Object **plus one**, with `0` for the
/// whole Group — FETCH's convention, in a subscription.
///
/// The one place that arithmetic exists for SUBSCRIBE, so this is the whole of
/// what the draft-07 arm can get wrong that the type system does not catch: an
/// end of 9 must reach the wire as 10, and an end of "the whole group" as 0.
#[test]
fn draft07s_end_object_is_the_last_object_plus_one() {
    let open = SubscribeRange::starting_at(4, 0).inline_end_location().expect("no end to encode");
    assert!(open.is_none(), "an AbsoluteStart carries no End Location");

    let whole = SubscribeRange::through_end_of_group(4, 0, 6)
        .inline_end_location()
        .expect("a whole group encodes")
        .expect("an AbsoluteRange carries one");
    assert_eq!((whole.group.into_inner(), whole.object.into_inner()), (6, 0));

    let inside = ends_inside_a_group()
        .inline_end_location()
        .expect("an end inside a group encodes")
        .expect("an AbsoluteRange carries one");
    assert_eq!((inside.group.into_inner(), inside.object.into_inner()), (6, 10));
}

/// The one range draft-07 cannot express, refused rather than wrapped.
///
/// `u64::MAX + 1` leaves the number space, and wrapping it would write `0` —
/// which that draft reads as "the entire group". A different subscription, well
/// formed, and silent.
#[test]
fn an_end_object_at_the_top_of_the_number_space_has_no_draft07_encoding() {
    let err = SubscribeRange::through_object(0, 0, 0, u64::MAX)
        .inline_end_location()
        .expect_err("the plus one overflows");
    assert!(err.to_string().contains("plus 1"), "{err}");
}

/// Drafts 17 and later carry the end Group as a delta, and the range is given
/// as an absolute Group either way.
#[test]
fn the_end_group_travels_as_a_delta_from_the_start() {
    assert_eq!(SubscribeRange::starting_at(4, 0).end_group_delta().expect("no end"), None);
    assert_eq!(
        SubscribeRange::through_end_of_group(4, 0, 6).end_group_delta().expect("6 - 4"),
        Some(2)
    );
    assert_eq!(SubscribeRange::whole_group(6).end_group_delta().expect("6 - 6"), Some(0));

    let err = SubscribeRange::through_end_of_group(6, 0, 4)
        .end_group_delta()
        .expect_err("an unsigned delta cannot count down");
    assert!(err.to_string().contains("backwards"), "{err}");
}

/// Draft-20 reads `{0, 0}` as the live edge where every earlier draft reads it
/// as the beginning of the track, so the facade refuses it rather than sending
/// one draft the opposite of what the other thirteen were sent.
///
/// The refusal is that one value with no end beside it and nothing else: the
/// same start with an end is three fields and unambiguous, and any other start
/// is unambiguous either way.
#[cfg(feature = "draft20")]
#[test]
fn a_zero_start_with_no_end_has_no_draft20_filter() {
    let err = SubscribeRange::starting_at(0, 0)
        .location_filter()
        .expect_err("{0, 0} is Next Object on draft-20");
    assert!(err.to_string().contains("Next Object"), "{err}");

    assert_eq!(
        SubscribeRange::through_end_of_group(0, 0, 1)
            .location_filter()
            .expect("a range from {0,0} says what it means")
            .fields(),
        &[0, 0, 1]
    );
    assert_eq!(
        SubscribeRange::starting_at(0, 1)
            .location_filter()
            .expect("any other start is unambiguous")
            .fields(),
        &[0, 1]
    );
}

/// Ten drafts deleted the End Object and refuse a range that ends inside a
/// group, rather than widening it to the whole group behind the caller's back.
///
/// Asserted through the entry point, per draft, in the gates below; this states
/// the two ends of the span it applies to.
#[test]
fn a_range_ending_inside_a_group_is_two_drafts_and_not_fourteen() {
    assert!(matches!(ends_inside_a_group().end, SubscribeEnd::ThroughObject { .. }));
    // Draft-07 writes it as an End Location and draft-20 as a fourth field.
    ends_inside_a_group().inline_end_location().expect("draft-07 carries an End Object");
    #[cfg(feature = "draft20")]
    assert_eq!(
        ends_inside_a_group().location_filter().expect("draft-20 carries one too").fields(),
        &[4, 0, 2, 9]
    );
}

// ── The loopbacks ────────────────────────────────────────────────

/// A reader that pulls whole control messages off one quinn stream, framed for
/// whichever draft it was built with.
struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream, draft: DraftVersion) -> Self {
        Self { recv, draft, buf: Vec::new() }
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
            match AnyControlMessage::decode(self.draft, &mut cursor) {
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
                Err(e) => panic!("the peer could not decode what the client wrote: {e}"),
            }
        }
    }
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a setup message");
    out
}

/// The filter parameter's value, off a decoded SUBSCRIBE's parameter list.
///
/// Panics rather than returning an `Option`: a SUBSCRIBE built from a range and
/// carrying no filter is the failure this whole file exists to catch, and it
/// should say so where it happened.
fn filter_value(parameters: &[moqtap_codec::kvp::KeyValuePair]) -> Vec<u8> {
    let found = parameters
        .iter()
        .find(|p| p.key.into_inner() == FILTER_KEY)
        .expect("a range reaches the wire as the filter parameter and nowhere else");
    match &found.value {
        KvpValue::Bytes(bytes) => bytes.clone(),
        other => panic!("the filter parameter is length-prefixed, got {other:?}"),
    }
}

/// One gate on a draft that carries every request on the bidirectional control
/// stream: drafts 15 and 16.
macro_rules! control_stream_gate {
    ($mod_name:ident, $feat:literal, $version:ident, $expected:expr) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::varint::VarInt;

            const DRAFT: DraftVersion = DraftVersion::$version;

            /// MAX_REQUEST_ID, Setup Parameter 0x02, without which the client
            /// has no budget to allocate a Request ID from and nothing goes out.
            fn budget() -> KeyValuePair {
                KeyValuePair {
                    key: VarInt::from_u64(0x02).unwrap(),
                    value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
                }
            }

            fn server_setup_bytes() -> Vec<u8> {
                use moqtap_codec::$mod_name::message::{ControlMessage, ServerSetup};
                encoded(AnyControlMessage::$version(ControlMessage::ServerSetup(ServerSetup {
                    parameters: vec![budget()],
                })))
            }

            /// Complete the handshake, then read two SUBSCRIBEs off the control
            /// stream and report the filter parameter each one carried.
            async fn serve(server: quinn::Endpoint) -> Vec<Vec<u8>> {
                use moqtap_codec::$mod_name::message::ControlMessage;

                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = PeerStream::new(recv, DRAFT);
                control.read_control().await.expect("read the client's CLIENT_SETUP");
                send.write_all(&server_setup_bytes()).await.expect("write SERVER_SETUP");

                let mut seen = Vec::new();
                for _ in 0..2 {
                    match control.read_control().await {
                        Some(AnyControlMessage::$version(ControlMessage::Subscribe(s))) => {
                            seen.push(filter_value(&s.parameters))
                        }
                        other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                    }
                }
                seen
            }

            #[tokio::test]
            async fn a_subscribe_range_reaches_the_wire_as_this_draft_writes_it() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut held: Vec<AnyRequest> = Vec::new();
                for range in ranges() {
                    held.push(
                        tokio::time::timeout(
                            PATIENCE,
                            conn.subscribe_range(
                                namespace(),
                                TRACK.to_vec(),
                                128,
                                GroupOrder::Ascending,
                                range,
                            ),
                        )
                        .await
                        .expect("subscribe_range did not finish")
                        .expect("subscribe_range"),
                    );
                }

                // Refused before anything is written, which is why the peer
                // above reads two messages and not three.
                match conn
                    .subscribe_range(
                        namespace(),
                        TRACK.to_vec(),
                        128,
                        GroupOrder::Ascending,
                        ends_inside_a_group(),
                    )
                    .await
                {
                    Ok(_) => panic!("{DRAFT:?} deleted the End Object and cannot carry this"),
                    Err(e) => assert!(e.to_string().contains("End Object"), "{e}"),
                }

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    seen,
                    $expected.iter().map(|b: &&[u8]| b.to_vec()).collect::<Vec<_>>(),
                    "{DRAFT:?} writes the Filter Type, the Start Location, and an End Group in \
                     full"
                );
            }
        }
    };
}

/// Drafts 15 and 16: QUIC varints, and the End Group written out.
///
/// `0x03` is AbsoluteStart and `0x04` AbsoluteRange, then `{4, 0}`, then the
/// end Group `6` **absolute** — not the `2` the drafts after them write.
///
/// Gated on its own two readers, which are the two lines under it. A `cfg` and
/// not an `allow`: the condition is the pair of features the invocations below
/// name, it is two lines from both of them, and a third draft joining this
/// encoding would be added here and there in one edit. Without it the twelve
/// matrix rows that enable neither draft carry an unread constant and fail
/// under `RUSTFLAGS="-D warnings"`.
#[cfg(any(feature = "draft15", feature = "draft16"))]
const ABSOLUTE_END: [&[u8]; 2] = [&[0x03, 4, 0], &[0x04, 4, 0, 6]];

control_stream_gate!(draft15, "draft15", Draft15, ABSOLUTE_END);
control_stream_gate!(draft16, "draft16", Draft16, ABSOLUTE_END);

/// One gate on a draft whose every request owns a bidirectional stream of its
/// own: drafts 17 through 20.
macro_rules! request_stream_gate {
    ($mod_name:ident, $feat:literal, $version:ident, $extra:expr, $expected:expr, $claim:literal) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::$mod_name::message::{ControlMessage, Setup};

            const DRAFT: DraftVersion = DraftVersion::$version;

            /// Whether this draft can also express a range ending inside a
            /// group. Draft-20 can; drafts 17 through 19 cannot.
            const ENDS_INSIDE_A_GROUP: bool = $extra;

            fn setup_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
                    options: Vec::new(),
                })))
            }

            /// Complete the handshake, then read one SUBSCRIBE off each request
            /// stream and report the filter parameter it carried.
            async fn serve(server: quinn::Endpoint, count: usize) -> Vec<Vec<u8>> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let mut seen = Vec::new();
                for _ in 0..count {
                    let (_answer, request) = conn.accept_bi().await.expect("accept_bi");
                    let mut request = PeerStream::new(request, DRAFT);
                    match request.read_control().await {
                        Some(AnyControlMessage::$version(ControlMessage::Subscribe(s))) => {
                            seen.push(filter_value(&s.parameters))
                        }
                        other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                    }
                }
                seen
            }

            #[tokio::test]
            async fn a_subscribe_range_reaches_the_wire_as_this_draft_writes_it() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let count = if ENDS_INSIDE_A_GROUP { 3 } else { 2 };
                let peer = tokio::spawn(serve(endpoint, count));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                // Held: on these drafts an `AnyRequest` owns the request stream
                // and dropping it cancels the subscription before the peer has
                // read it.
                let mut held: Vec<AnyRequest> = Vec::new();
                for range in ranges() {
                    held.push(
                        tokio::time::timeout(
                            PATIENCE,
                            conn.subscribe_range(
                                namespace(),
                                TRACK.to_vec(),
                                128,
                                GroupOrder::Ascending,
                                range,
                            ),
                        )
                        .await
                        .expect("subscribe_range did not finish")
                        .expect("subscribe_range"),
                    );
                }

                let inside = tokio::time::timeout(
                    PATIENCE,
                    conn.subscribe_range(
                        namespace(),
                        TRACK.to_vec(),
                        128,
                        GroupOrder::Ascending,
                        ends_inside_a_group(),
                    ),
                )
                .await
                .expect("subscribe_range did not finish");
                match (ENDS_INSIDE_A_GROUP, inside) {
                    (true, Ok(request)) => held.push(request),
                    // Refused before a stream is opened, which is why the peer
                    // above accepts two and not three.
                    (false, Err(e)) => assert!(e.to_string().contains("End Object"), "{e}"),
                    (true, Err(e)) => panic!("{DRAFT:?} carries an End Object: {e}"),
                    (false, Ok(_)) => {
                        panic!("{DRAFT:?} deleted the End Object and cannot carry this")
                    }
                }

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    seen,
                    $expected.iter().map(|b: &&[u8]| b.to_vec()).collect::<Vec<_>>(),
                    $claim
                );
            }
        }
    };
}

/// Drafts 17 through 19: MoQT varints, and the End Group as a **delta**.
///
/// The `2` is `6 - 4`. A build that forwarded the absolute Group here would
/// subscribe through Group 10 and never be told.
///
/// [`ABSOLUTE_END`]'s reason, over the three drafts that read it — the
/// `request_stream_gate!` invocations below. Draft-20 is deliberately not in
/// the list: it dropped the Filter Type and reads [`FIELD_COUNT`] instead, so a
/// fourth feature here would gate this on a draft that never touches it.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const DELTA_END: [&[u8]; 2] = [&[0x03, 4, 0], &[0x04, 4, 0, 2]];

/// Draft-20: no Filter Type at all, and the shape from the field count.
///
/// Two fields for the open range, three for one through the end of a Group, and
/// four for one ending at Object 9 — which is written as `9` and not as `10`,
/// because Section 5.1.2's range is inclusive.
///
/// [`DELTA_END`]'s reason on one draft. Not caught by `just draft-pairs`, whose
/// `draft07,draft20` row enables the reader below: only the thirteen
/// single-draft matrix rows that are not draft-20 see this one unread, which is
/// why it is gated here rather than after a red build reported it.
#[cfg(feature = "draft20")]
const FIELD_COUNT: [&[u8]; 3] = [&[4, 0], &[4, 0, 2], &[4, 0, 2, 9]];

request_stream_gate!(
    draft17,
    "draft17",
    Draft17,
    false,
    DELTA_END,
    "drafts 17 and later encode the End Group as a delta from the Start Location's Group"
);
request_stream_gate!(
    draft18,
    "draft18",
    Draft18,
    false,
    DELTA_END,
    "drafts 17 and later encode the End Group as a delta from the Start Location's Group"
);
request_stream_gate!(
    draft19,
    "draft19",
    Draft19,
    false,
    DELTA_END,
    "drafts 17 and later encode the End Group as a delta from the Start Location's Group"
);
request_stream_gate!(
    draft20,
    "draft20",
    Draft20,
    true,
    FIELD_COUNT,
    "draft-20 Section 5.1.2 reads the shape off the field count and its ranges are inclusive: \
     no Filter Type, and an end Object of 9 rather than 10"
);

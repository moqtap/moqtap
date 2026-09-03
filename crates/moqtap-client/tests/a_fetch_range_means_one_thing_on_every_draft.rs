#![cfg(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
))]

//! `AnyConnection::fetch` asks for the same three ranges on every draft it is
//! wired for, and each draft writes them the way that draft writes them.
//!
//! # The number in an end field is not the same number twice
//!
//! Drafts 14 through 19 carry `Start Location` and `End Location` inline in
//! FETCH, and draft-19 Section 10.13 defines the end as "the last Object, plus
//! 1; or 0 to indicate the entire Group". Draft-20 Section 10.13 deleted both
//! fields, moved the range into the `LOCATION_FILTER` parameter, and Section
//! 5.1.2 calls that range **inclusive** — the plus one and the "0 means the
//! whole Group" convention are both gone, and **neither deletion appears in the
//! draft's own change log**. A `fetch` that took an `end_object: u64` would
//! therefore have meant one of two things, with nothing to say which, which is
//! why it takes a [`FetchRange`] instead.
//!
//! So the same call is asserted twice over, per draft:
//!
//! * `FetchRange::through_object(4, 0, 6, 9)` — objects up to and including
//!   Group 6 Object 9. Drafts 14-19 must write `end_object = 10`; draft-20 must
//!   write `9`. A translation that forwarded the number unchanged would ask one
//!   family for one object too few and the other for one too many, and both
//!   requests are well formed.
//! * `FetchRange::through_end_of_group(4, 0, 6)` — every Object of Group 6.
//!   Drafts 14-19 write `end_object = 0`; draft-20 writes a **three-field**
//!   filter, because on that draft a `0` in the fourth field is Object 0.
//! * `FetchRange::one_object(4, 7)` — exactly one Object. Drafts 14-19 write
//!   `{4,7}`-`{4,8}`; draft-20 writes `{4,7}`-`{4,7}`. The shape an off-by-one
//!   is loudest in: one reading asks for nothing and the other for two.
//!
//! # Why this is a loopback and not a call to the conversion
//!
//! The conversion being right is not the claim. The claim is that the entry
//! point applies it, to the right field, on the draft that is actually
//! negotiated — so every gate here runs a real session and reads the FETCH off
//! the wire at a peer that decodes it with the codec.
//!
//! The regression this pins is the drafts that were already wired: **drafts 14
//! through 19 send exactly the bytes they sent before `FetchRange` existed**.
//! Every field asserted below is a value under 64, so its minimal varint
//! encoding is the single byte holding that number — the value asserted and the
//! byte on the wire are the same thing.

mod common;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyRequest, AnyTransportType, FetchRange,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The track every fetch here names.
const TRACK: &[u8] = b"video";

/// The three ranges, in the order every gate asks for them.
///
/// Group 4 Object 0 through Group 6 Object 9; every Object of Group 6 from the
/// same start; and Group 4 Object 7 alone.
fn ranges() -> [FetchRange; 3] {
    [
        FetchRange::through_object(4, 0, 6, 9),
        FetchRange::through_end_of_group(4, 0, 6),
        FetchRange::one_object(4, 7),
    ]
}

/// What drafts 14 through 19 must put in `Start Location` and `End Location`
/// for [`ranges`], in the same order.
///
/// The `10` is the plus one draft-19 Section 10.13 asks for, the `0` is its
/// "entire Group", and the `8` is what makes a one-object range one object
/// rather than none.
///
/// Gated to the drafts that have an inline End Location: both readers of this
/// constant sit inside macros that only expand for drafts 14 through 19, so a
/// build without one of them — `draft07,draft20`, say — compiles a constant
/// nothing can reach and fails under `-D warnings`.
#[cfg(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
const INLINE_LOCATIONS: [(u64, u64, u64, u64); 3] = [(4, 0, 6, 10), (4, 0, 6, 0), (4, 7, 4, 8)];

/// What draft-20 must put in the `LOCATION_FILTER` value for [`ranges`], byte
/// for byte.
///
/// `StartGroup`, `StartObject`, `EndGroupDelta` — "delta encoded from
/// StartGroup" (Section 5.1.2), so `6 - 4 = 2` — and, on the two four-field
/// rows, the inclusive `EndObject`. The middle row has three fields and no
/// fourth: Section 5.1.2 makes a three-field filter cover every Object of the
/// end Group, where a fourth field of `0` would mean Object 0.
///
/// Gated for the same reason as [`INLINE_LOCATIONS`], in the other direction:
/// its readers only expand for draft-20, so a build without it — `draft14,draft19`,
/// say — compiles a constant nothing can reach and fails under `-D warnings`.
#[cfg(feature = "draft20")]
const FILTER_VALUES: [&[u8]; 3] = [&[4, 0, 2, 9], &[4, 0, 2], &[4, 7, 0, 7]];

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

/// The conversion drafts 14 through 19 apply, on its own.
///
/// The loopbacks below prove the entry point applies it; this states what it
/// is, in the one place a reader can see all three rows at once.
#[test]
fn the_inline_end_object_is_the_last_object_plus_one() {
    let seen: Vec<u64> =
        ranges().iter().map(|r| r.inline_end_object().expect("all three encode")).collect();
    assert_eq!(seen, vec![10, 0, 8]);
}

/// The one range drafts 14 through 19 cannot express, refused rather than
/// wrapped.
///
/// Their `End Location.Object` is the last Object plus one, and `u64::MAX + 1`
/// leaves the number space. Wrapping it would write `0`, which those drafts
/// read as "the entire Group" — a different request, well formed, and silent.
#[test]
fn an_end_object_at_the_top_of_the_number_space_has_no_inline_encoding() {
    let range = FetchRange::through_object(0, 0, 0, u64::MAX);
    let err = range.inline_end_object().expect_err("the plus one overflows");
    assert!(err.to_string().contains("drafts 14"), "{err}");
    #[cfg(feature = "draft20")]
    range.location_filter().expect("draft-20's end is the last Object, so this one is ordinary");
}

/// A range whose end Group is below its start has no draft-20 filter.
///
/// Section 5.1.2 encodes the end Group as `EndGroupDelta`, "delta encoded from
/// StartGroup", and a delta is unsigned. Drafts 14 through 19 carry two
/// absolute Groups and would put such a range on the wire for the publisher to
/// answer with INVALID_RANGE; the difference is where it is refused.
#[cfg(feature = "draft20")]
#[test]
fn a_range_that_runs_backwards_has_no_draft20_filter() {
    let range = FetchRange::through_object(6, 0, 4, 9);
    let err = range.location_filter().expect_err("an unsigned delta cannot count down");
    assert!(err.to_string().contains("backwards"), "{err}");
}

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

/// One gate on a draft that carries every request on the bidirectional control
/// stream: drafts 14, 15 and 16.
///
/// `$setup` builds the peer's SERVER_SETUP from the CLIENT_SETUP it read —
/// draft-14 has to echo a selected version and the other two have no such
/// field. All three need a MAX_REQUEST_ID, without which the client has no
/// budget to allocate a Request ID from and the first fetch never goes out.
macro_rules! control_stream_gate {
    ($mod_name:ident, $feat:literal, $version:ident, |$cs:ident| $setup:expr) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::varint::VarInt;

            const DRAFT: DraftVersion = DraftVersion::$version;

            /// MAX_REQUEST_ID, Setup Parameter 0x02 on all three drafts.
            fn budget() -> KeyValuePair {
                KeyValuePair {
                    key: VarInt::from_u64(0x02).unwrap(),
                    value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
                }
            }

            fn server_setup_bytes($cs: &AnyControlMessage) -> Vec<u8> {
                encoded($setup)
            }

            /// Complete the handshake, then read three FETCHes off the control
            /// stream and report each one's Start and End Location.
            async fn serve(server: quinn::Endpoint) -> Vec<(u64, u64, u64, u64)> {
                use moqtap_codec::$mod_name::message::{ControlMessage, FetchPayload};

                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = PeerStream::new(recv, DRAFT);
                let client_setup =
                    control.read_control().await.expect("read the client's CLIENT_SETUP");
                send.write_all(&server_setup_bytes(&client_setup))
                    .await
                    .expect("write SERVER_SETUP");

                let mut seen = Vec::new();
                for _ in 0..3 {
                    match control.read_control().await {
                        Some(AnyControlMessage::$version(ControlMessage::Fetch(f))) => {
                            match f.fetch_payload {
                                FetchPayload::Standalone {
                                    start_group,
                                    start_object,
                                    end_group,
                                    end_object,
                                    ..
                                } => seen.push((
                                    start_group.into_inner(),
                                    start_object.into_inner(),
                                    end_group.into_inner(),
                                    end_object.into_inner(),
                                )),
                                other => panic!("expected a standalone FETCH, got {other:?}"),
                            }
                        }
                        other => panic!("expected a FETCH from the client, got {other:?}"),
                    }
                }
                seen
            }

            #[tokio::test]
            async fn a_fetch_range_reaches_the_wire_as_this_draft_writes_it() {
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
                            conn.fetch(namespace(), TRACK.to_vec(), range),
                        )
                        .await
                        .expect("fetch did not finish")
                        .expect("fetch"),
                    );
                }

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    seen,
                    INLINE_LOCATIONS.to_vec(),
                    "{DRAFT:?} writes End Location as the last Object plus 1, or 0 for the \
                     entire Group"
                );
            }
        }
    };
}

control_stream_gate!(draft14, "draft14", Draft14, |cs| {
    use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
    let selected = match cs {
        AnyControlMessage::Draft14(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
        other => panic!("expected a CLIENT_SETUP, got {other:?}"),
    };
    AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected,
        parameters: vec![budget()],
    }))
});

control_stream_gate!(draft15, "draft15", Draft15, |cs| {
    use moqtap_codec::draft15::message::{ControlMessage, ServerSetup};
    let _ = cs;
    AnyControlMessage::Draft15(ControlMessage::ServerSetup(ServerSetup {
        parameters: vec![budget()],
    }))
});

control_stream_gate!(draft16, "draft16", Draft16, |cs| {
    use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
    let _ = cs;
    AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup {
        parameters: vec![budget()],
    }))
});

/// One gate on a draft whose control plane is a pair of unidirectional streams
/// and whose every request owns a bidirectional stream of its own: drafts 17
/// through 20.
///
/// `$read_range` turns the decoded FETCH into whatever this draft's range looks
/// like — four inline fields on drafts 17 to 19, and the `LOCATION_FILTER`
/// value on draft-20 — and `$expected` is what it must be.
macro_rules! request_stream_gate {
    (
        $mod_name:ident,
        $feat:literal,
        $version:ident,
        $seen:ty,
        |$fetch:ident| $read_range:expr,
        $expected:expr,
        $claim:literal
    ) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::$mod_name::message::{ControlMessage, Setup};

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn setup_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
                    options: Vec::new(),
                })))
            }

            /// Complete the handshake, then read one FETCH off each of three
            /// request streams and report the range each one carried.
            async fn serve(server: quinn::Endpoint) -> Vec<$seen> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let mut seen = Vec::new();
                for _ in 0..3 {
                    let (_answer, request) = conn.accept_bi().await.expect("accept_bi");
                    let mut request = PeerStream::new(request, DRAFT);
                    match request.read_control().await {
                        Some(AnyControlMessage::$version(ControlMessage::Fetch($fetch))) => {
                            seen.push($read_range)
                        }
                        other => panic!("expected a FETCH from the client, got {other:?}"),
                    }
                }
                seen
            }

            #[tokio::test]
            async fn a_fetch_range_reaches_the_wire_as_this_draft_writes_it() {
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

                // Held: on these drafts an `AnyRequest` owns the request stream
                // and dropping it resets the fetch before the peer has read it.
                let mut held: Vec<AnyRequest> = Vec::new();
                for range in ranges() {
                    held.push(
                        tokio::time::timeout(
                            PATIENCE,
                            conn.fetch(namespace(), TRACK.to_vec(), range),
                        )
                        .await
                        .expect("fetch did not finish")
                        .expect("fetch"),
                    );
                }

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(seen, $expected, $claim);
            }
        }
    };
}

/// The three drafts that still carry the range inline, and still carry it with
/// the plus one.
macro_rules! inline_request_stream_gate {
    ($mod_name:ident, $feat:literal, $version:ident) => {
        request_stream_gate!(
            $mod_name,
            $feat,
            $version,
            (u64, u64, u64, u64),
            |f| match f.fetch_payload {
                moqtap_codec::$mod_name::message::FetchPayload::Standalone {
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    ..
                } => (
                    start_group.into_inner(),
                    start_object.into_inner(),
                    end_group.into_inner(),
                    end_object.into_inner(),
                ),
                other => panic!("expected a standalone FETCH, got {other:?}"),
            },
            INLINE_LOCATIONS.to_vec(),
            "End Location is the last Object plus 1, or 0 for the entire Group"
        );
    };
}

inline_request_stream_gate!(draft17, "draft17", Draft17);
inline_request_stream_gate!(draft18, "draft18", Draft18);
inline_request_stream_gate!(draft19, "draft19", Draft19);

request_stream_gate!(
    draft20,
    "draft20",
    Draft20,
    Vec<u8>,
    |f| {
        let filter = f
            .parameters
            .iter()
            .find(|p| p.key.into_inner() == moqtap_codec::draft20::message::LOCATION_FILTER)
            .expect("draft-20 carries the range in a LOCATION_FILTER and nowhere else");
        match &filter.value {
            moqtap_codec::kvp::KvpValue::Bytes(bytes) => bytes.clone(),
            other => panic!("LOCATION_FILTER is length-prefixed, got {other:?}"),
        }
    },
    FILTER_VALUES.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
    "draft-20 Sections 5.1.2 and 10.13 make the filter's range inclusive: nothing adds one to \
     the end, and a range that covers a whole Group has three fields rather than a fourth of 0"
);

//! `AnyConnection::accept_fetch` reads a relay's fetch stream, on all
//! drafts.
//!
//! Putting the FETCH on the wire and reading the answer are two halves of the
//! facade that meet nowhere else. `AnyConnection::fetch` writes the request and
//! every draft's own `Connection` has an `accept_fetch_stream` that reads the
//! response stream; `accept_fetch` is the join, and without it a caller holding
//! an `AnyConnection` could ask a relay for a range of a track and have no way
//! to receive it. That is what these gates hold.
//!
//! # The peer writes bytes, not objects
//!
//! Every gate here hands the client a **checked-in wire vector** —
//! `test-vectors/transport/draftNN/codec/data-streams/fetch-header.json`, by the
//! vector's own id — and the peer writes those bytes verbatim on a
//! unidirectional stream. Nothing on the peer's side encodes anything.
//!
//! That is the whole design, and it is the opposite of an echo. An echo settles
//! very little on a fetch stream: from draft-15 an object may leave its Group
//! ID, Subgroup ID, Object ID and Priority off the wire entirely and inherit
//! each from the object before it, so a writer and a reader that both skipped
//! the inheritance would agree with each other perfectly and both be wrong. A
//! fixed transcript has no opinion. What the reader makes of `0x00` — a
//! Serialization Flags word that states nothing at all — is checked against what
//! the draft says that means, not against whatever produced the byte.
//!
//! # What the drafts make this reader absorb
//!
//! Four read shapes and five object shapes, and they do not line up.
//!
//! * Drafts **07 through 13** state every field on every object and model the
//!   Object Status as a field that is always there. The wire does not: it
//!   carries a status only where the declared payload length is zero. So
//!   `AnyFetchObject::status` is `None` on these gates, for objects whose own
//!   structs hold a `Normal` the peer never sent — the same normalisation
//!   `AnySubgroupReader::read_object` makes, for the same reason.
//! * Draft **14** returns a struct with the status already an `Option`, and is
//!   the only draft here whose two-object vector is three objects
//!   (`multi-object`) — the third crosses into a new Group.
//! * Draft **15** elides, and its own reader resolves: what comes back is a
//!   header whose every field is a value.
//! * Draft **16** elides and its reader does **not** resolve, though its codec
//!   offers a `FetchObjectReader` that does. `Draft16FetchStream` is where the
//!   facade keeps that state, and the second object of every draft-16 gate here
//!   is the proof it is doing something: flags `0x00`, nothing on the wire but a
//!   length and two payload bytes, and it comes back as group 0 object 1.
//! * Drafts **17 through 20** resolve on the stream and hand back the Location
//!   beside the header. From draft-16 the Object Status is gone from a fetch
//!   object altogether, replaced by the end-of-range markers below.
//!
//! # The Group Order is an argument because getting it wrong is silent
//!
//! Drafts 18, 19 and 20 encode a Group ID as a **delta**, and draft-18 Section
//! 11.4.4.1 makes that delta add under Ascending and subtract under Descending.
//! The order is on the FETCH_OK, which is a control message a data stream never
//! sees — so `accept_fetch` takes it, and on the other drafts it is
//! inert.
//!
//! `the_same_bytes_walk_the_other_way_under_descending` is that argument made
//! rather than asserted. One vector, `fetch-stream-cross-group-delta`, read
//! twice: Ascending gives groups **5 then 6**, Descending gives **5 then 4**.
//! Nothing fails to parse in either direction, which is exactly why the reader
//! has to be told — a caller that guessed would get a well-formed answer about
//! the wrong Groups.
//!
//! # An end-of-range marker is not an object and is not silence
//!
//! Drafts 16 through 20 end a fetch that cannot serve part of its range with a
//! marker: `0x8C` for a span known not to exist, `0x10C` for one whose status is
//! unknown, and draft-20 adds `0x20C` for one the publisher abandoned. It
//! occupies an object's position on the stream and carries a Location, and it is
//! the answer to "does this relay hold that range" stated outright rather than
//! inferred from nothing arriving.
//!
//! `AnyFetchObject::end_of_range` carries the marker's own wire code, so the
//! five gates below hold `0x8c` against the vector that wrote it. Drafts 07
//! through 15 have no such marker and report `none`; what they have instead is
//! the Object Status those drafts still carry, which is why the two fields are
//! documented as one question with two spellings.
//!
//! # What is *not* claimed
//!
//! That a relay serves a fetch. Nothing here dials one — the peer is a fixture
//! that writes fourteen fixed byte strings. What this settles is that the facade
//! can read the answer.
//!
//! # Ablations, measured
//!
//! Three cuts, each made, run and reverted. Every one of them splits the suite
//! along a boundary the drafts drew, which is what makes each normalisation
//! load-bearing rather than incidental.
//!
//! `accept_fetch` ignoring its Group Order and starting every reader Ascending.
//! **Three redden, twenty-two stay green** — exactly the drafts that delta-encode
//! a Group ID, and only on the gate that reads a stream twice:
//!
//! ```text
//! test result: FAILED. 22 passed; 3 failed
//!
//! under Descending the same delta subtracts, and the same bytes are a different answer
//!   left: "group=5 … | group=6 subgroup=0 object=0 payload=bb status=none eor=none"
//!  right: "group=5 … | group=4 subgroup=0 object=0 payload=bb status=none eor=none"
//! ```
//!
//! The draft-16 arm reading the header's own fields instead of resolving them
//! through `FetchObjectReader`. **Two redden, twenty-three stay green** — both of
//! draft-16's, and no other draft's, because draft-16 is the only stream the
//! facade resolves for:
//!
//! ```text
//! test result: FAILED. 23 passed; 2 failed
//!
//!   left: "group=0 subgroup=none object=0 … | group=0 subgroup=none object=0 payload=cafe …"
//!  right: "group=0 subgroup=0 object=0 … | group=0 subgroup=0 object=1 payload=cafe …"
//! ```
//!
//! Note what the elision cost there: not a parse failure, but a **second object
//! reported under the first one's Object ID**. A caller counting distinct objects
//! would have seen one.
//!
//! `read_object` reporting `Some(status)` for every object on drafts 07 through
//! 13 rather than only for the ones the wire carried a status for. **Seven
//! redden** — exactly the drafts whose fetch object holds a status
//! unconditionally, the same split the subgroup reader's own ablation produces:
//!
//! ```text
//! test result: FAILED. 18 passed; 7 failed
//!
//!   left: "group=0 subgroup=0 object=0 payload=deadbeef status=0x0 eor=none | …"
//!  right: "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | …"
//! ```

mod common;

use std::time::Duration;

// `fetch_group_order` is deliberately **not** imported here. Its only two
// callers are the pair of gates at the foot of this file, one gated on
// `draft20` and one on `draft14`, so a build that has neither — every one of
// the other twelve single-draft rows `just draft-matrix` compiles — would carry
// an import nothing reads and fail under `-D warnings`. Importing it inside
// each gate instead puts the `use` behind the same `#[cfg]` as the test that
// needs it, with no second feature list to keep level: the day one of those
// gates moves to another draft, its own `use` moves with it. That is the same
// shape the two gates already use for `ControlMessage` and `FetchOk`.
use moqtap_client::dispatch::{AnyClientConfig, AnyConnection, AnyFetchObject, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::GroupOrder;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

// A varint helper belongs in each of its three readers — the `with_role` arm of
// `draft_setup_parameters!` above and the two Group Order gates at the foot of
// the file — rather than here at file scope. Those three are gated on draft-07,
// draft-14 and draft-20 respectively, so at file scope one would be dead on the
// other eleven single-draft rows — and the `cfg` that would fix it in place is a
// three-feature list restating which gates happen to build a varint, which is a
// fact about the gates and not about this file.

/// A vector's `hex` field as bytes.
fn wire(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "a wire vector is whole bytes");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("a wire vector is hex"))
        .collect()
}

/// One object as the facade handed it back.
///
/// Every field of [`AnyFetchObject`], rendered so that the absences are visible:
/// a Subgroup ID the draft let an object omit reads `none` rather than `0`, and
/// so does a status the wire never carried. A reader that filled either in with
/// a default would read back as one that had been told.
fn describe(object: &AnyFetchObject) -> String {
    let or_none = |value: Option<u64>| match value {
        Some(n) => format!("0x{n:x}"),
        None => "none".to_string(),
    };
    format!(
        "group={} subgroup={} object={} payload={} status={} eor={}",
        object.group_id,
        match object.subgroup_id {
            Some(id) => id.to_string(),
            None => "none".to_string(),
        },
        object.object_id,
        if object.payload.is_empty() {
            "-".to_string()
        } else {
            object.payload.iter().map(|b| format!("{b:02x}")).collect::<String>()
        },
        or_none(object.status),
        or_none(object.end_of_range),
    )
}

/// Every object one fetch stream carried, in arrival order.
fn describe_all(objects: &[AnyFetchObject]) -> String {
    objects.iter().map(describe).collect::<Vec<_>>().join(" | ")
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
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

/// The setup exchange, in the three shapes the drafts give it.
///
/// The same three `an_object_written_through_the_facade_reads_back_through_it`
/// uses, and for the same reason: dropping the peer's half of the control
/// stream resets it, which ends the session before a byte of the fetch stream
/// could arrive.
macro_rules! peer_setup {
    (versioned, $conn:ident, $version:ident, $module:ident) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut control = PeerStream::new(recv, DRAFT);
        let client_setup = control.read_control().await.expect("read the client's CLIENT_SETUP");
        let selected = match &client_setup {
            AnyControlMessage::$version(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        send.write_all(&encoded(AnyControlMessage::$version(ControlMessage::ServerSetup(
            ServerSetup { selected_version: selected, parameters: setup_parameters() },
        ))))
        .await
        .expect("write SERVER_SETUP");
        (send, control)
    }};
    (plain, $conn:ident, $version:ident, $module:ident) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut control = PeerStream::new(recv, DRAFT);
        control.read_control().await.expect("read the client's CLIENT_SETUP");
        send.write_all(&encoded(AnyControlMessage::$version(ControlMessage::ServerSetup(
            ServerSetup { parameters: setup_parameters() },
        ))))
        .await
        .expect("write SERVER_SETUP");
        (send, control)
    }};
    (uni, $conn:ident, $version:ident, $module:ident) => {{
        use moqtap_codec::$module::message::{ControlMessage, Setup};
        let mut control = PeerStream::new($conn.accept_uni().await.expect("accept_uni"), DRAFT);
        control.read_control().await.expect("read the client's SETUP");
        let mut ours = $conn.open_uni().await.expect("open the peer's control stream");
        ours.write_all(&encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
            options: setup_parameters(),
        }))))
        .await
        .expect("write the peer's SETUP");
        (ours, control)
    }};
}

/// The setup parameters a draft insists on before a session is usable.
///
/// Draft-07 alone requires a ROLE — draft-08 withdrew it. No draft here needs a
/// request ceiling: the client sends no request in these gates. The FETCH that
/// would have opened a real fetch stream is not made, because what is under test
/// is the reader and a fixture peer has no track to fetch.
macro_rules! draft_setup_parameters {
    // `KvpValue`, `VarInt` and the varint helper are local to this arm, whose
    // only caller is the draft-07 gate — the one draft that
    // passes `with_role`. At file scope they were unread by the other thirteen
    // and `RUSTFLAGS="-D warnings"` makes that an error on every
    // `just draft-matrix` row but draft-07's. Here the condition is stated once,
    // by the invocation, so there is no `cfg` list and no `allow` to go stale.
    (with_role) => {
        fn setup_parameters() -> Vec<KeyValuePair> {
            use moqtap_codec::kvp::KvpValue;
            use moqtap_codec::varint::VarInt;

            let v = |n: u64| VarInt::from_u64(n).expect("fixture value fits a varint");
            let mut value = Vec::new();
            // PubSub: this endpoint both publishes and subscribes.
            v(3).encode(&mut value);
            vec![KeyValuePair { key: v(0x00), value: KvpValue::Bytes(value) }]
        }
    };
    (none) => {
        fn setup_parameters() -> Vec<KeyValuePair> {
            Vec::new()
        }
    };
}

/// Where the peer's first fetch stream falls among the unidirectional streams
/// the peer opened.
///
/// The same era split `stream_id` shows on a subgroup: drafts 07 through 16
/// carry control on a bidirectional stream, so the fetch stream is the peer's
/// first unidirectional one. From draft-17 the peer's control stream is
/// unidirectional and takes the ordinal ahead of it.
macro_rules! first_uni_index {
    (versioned) => {
        0
    };
    (plain) => {
        0
    };
    (uni) => {
        1
    };
}

/// One draft's fetch reader.
///
/// `$handshake` picks the setup exchange and `$params` whatever that draft needs
/// in it; `$wire` is the vector's hex and `$expected` what the facade must make
/// of it. `$extra` is whatever gates that draft has of its own — the markers
/// from draft-16 and the Group Order from draft-18.
macro_rules! fetch_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, $params:tt,
     $request:literal, $vector:literal, $wire:literal, $expected:literal
     $(, $extra:item)* $(,)?) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            draft_setup_parameters!($params);

            fn client_config() -> AnyClientConfig {
                AnyClientConfig {
                    draft: DRAFT,
                    additional_versions: Vec::new(),
                    transport: AnyTransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: setup_parameters(),
                }
            }

            /// Complete the handshake, write `bytes` on a unidirectional stream,
            /// and hold the connection open until the client is done reading.
            async fn serve(server: quinn::Endpoint, bytes: Vec<u8>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                // Held for the life of the session: dropping either half of the
                // control stream resets it, and the session with it.
                let _control = peer_setup!($handshake, conn, $version, $module);

                let mut send = conn.open_uni().await.expect("open a fetch stream");
                send.write_all(&bytes).await.expect("write the fetch stream");
                send.finish().expect("finish the fetch stream");

                // Returning here would drop the connection and tear the stream
                // down with it — a failure that reads as "the peer closed" and
                // is really "the peer finished first".
                conn.closed().await;
            }

            /// Read one wire vector back through the facade, in `order`.
            ///
            /// Objects are read until the stream ends, which arrives as an
            /// error on every draft — a fetch stream has no terminator record,
            /// so the read that fails is the loop's exit. The count is pinned by
            /// the expectation rather than by this function, which is what makes
            /// a decode that gave up early visible instead of merely shorter.
            async fn read_back(hex: &str, order: GroupOrder) -> String {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, wire(hex)));

                let conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let (header, mut reader) = tokio::time::timeout(PATIENCE, conn.accept_fetch(order))
                    .await
                    .expect("the fetch stream never arrived")
                    .expect("accept the fetch stream");
                assert_eq!(reader.draft(), DRAFT, "the reader reports the draft framing it");
                assert_eq!(
                    reader.stream_id(),
                    first_uni_index!($handshake),
                    "the number reported has to be the transport's own, and on this draft the \
                     peer's control stream has {} unidirectional streams ahead of the fetch",
                    first_uni_index!($handshake),
                );
                assert_eq!(
                    header.request_id(),
                    $request,
                    "the header names the request every object after it answers"
                );

                let mut objects = Vec::new();
                while let Ok(Ok(object)) =
                    tokio::time::timeout(PATIENCE, reader.read_object()).await
                {
                    objects.push(object);
                }

                // Releases the peer, which is holding its connection open until
                // this side is done reading.
                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").ok();

                describe_all(&objects)
            }

            /// The vector every draft has: two objects, the second of which
            /// states as little about itself as its draft allows.
            #[tokio::test]
            async fn a_fetch_stream_reads_back_as_the_objects_it_carried() {
                assert_eq!(
                    read_back($wire, GroupOrder::Ascending).await,
                    $expected,
                    "reading {} back through the facade",
                    $vector
                );
            }

            $($extra)*
        }
    };
}

// ── Drafts 07 through 13 ────────────────────────────────────────────────────
//
// Every field on every object, and a status the wire carries only where the
// payload length is zero — which none of these objects has, so every one of
// them reports `status=none` through the facade and `Normal` inside its own
// draft's struct.

fetch_gate!(
    draft07,
    "draft07",
    Draft07,
    versioned,
    with_role,
    4,
    "fetch-two-objects",
    "05040000008004deadbeef0000018002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft08,
    "draft08",
    Draft08,
    versioned,
    none,
    4,
    "fetch-two-objects",
    "0504000000800004deadbeef000001800002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft09,
    "draft09",
    Draft09,
    versioned,
    none,
    4,
    "fetch-two-objects",
    "0504000000800004deadbeef000001800002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft10,
    "draft10",
    Draft10,
    versioned,
    none,
    4,
    "fetch-two-objects",
    "0504000000800004deadbeef000001800002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft11,
    "draft11",
    Draft11,
    versioned,
    none,
    4,
    "fetch-two-objects",
    "0504000000800004deadbeef000001800002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft12,
    "draft12",
    Draft12,
    versioned,
    none,
    4,
    "fetch-two-objects",
    "0504000000800004deadbeef000001800002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft13,
    "draft13",
    Draft13,
    versioned,
    none,
    4,
    "fetch-two-objects",
    "0504000000800004deadbeef000001800002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);

// ── Draft-14 ────────────────────────────────────────────────────────────────
//
// The only draft whose vector for this is three objects rather than two, and
// the third is why it is used: it crosses into Group 1, which is the case a
// two-object stream inside one Group cannot reach.

fetch_gate!(
    draft14,
    "draft14",
    Draft14,
    versioned,
    none,
    2,
    "multi-object",
    "0502000000800004deadbeef000001800002cafe010000800004baadf00d",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none | \
     group=1 subgroup=0 object=0 payload=baadf00d status=none eor=none",
);

// ── Drafts 15 and 16 ────────────────────────────────────────────────────────
//
// The same bytes on both, and two different jobs behind them. The second object
// is Serialization Flags `0x00` and nothing else — no Group ID, no Object ID, no
// Priority — so `group=0 object=1` is inheritance resolved rather than read.
// Draft-15's own stream resolves it; draft-16's does not, and the facade holds
// the reader that does.

fetch_gate!(
    draft15,
    "draft15",
    Draft15,
    plain,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
);
fetch_gate!(
    draft16,
    "draft16",
    Draft16,
    plain,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
    /// The first draft with an end-of-range marker, and the first where a
    /// relay can say "that range is not here" rather than send nothing.
    #[tokio::test]
    async fn an_end_of_range_marker_is_a_record_and_not_an_object() {
        assert_eq!(
            read_back("0504408c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=0 object=10 payload=- status=none eor=0x8c",
            "reading fetch-end-of-non-existent-range back through the facade"
        );
    },
);

// ── Drafts 17 through 20 ────────────────────────────────────────────────────
//
// Control moved to a unidirectional stream each way at draft-17, which is why
// the fetch stream is the peer's *second*. The marker's varint widened from two
// bytes to two different bytes at the same draft — `408c` on draft-16, `808c`
// from draft-17 — which is visible in the vectors and invisible in the results,
// because a code is a code whatever width carried it.

fetch_gate!(
    draft17,
    "draft17",
    Draft17,
    uni,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
    #[tokio::test]
    async fn an_end_of_range_marker_is_a_record_and_not_an_object() {
        assert_eq!(
            read_back("0504808c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x8c",
            "reading fetch-end-of-non-existent-range back through the facade"
        );
    },
);
fetch_gate!(
    draft18,
    "draft18",
    Draft18,
    uni,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
    #[tokio::test]
    async fn an_end_of_range_marker_is_a_record_and_not_an_object() {
        assert_eq!(
            read_back("0504808c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x8c",
            "reading fetch-end-of-non-existent-range back through the facade"
        );
    },
    /// The first draft whose Group ID is a delta, and the argument for
    /// `accept_fetch` taking a Group Order at all.
    ///
    /// One vector, read twice. Neither direction fails to parse — that is the
    /// point: a reader told the wrong thing reports Groups that walk the wrong
    /// way, and nothing on the stream contradicts it.
    #[tokio::test]
    async fn the_same_bytes_walk_the_other_way_under_descending() {
        let wire = "05041c05008001aa0c000001bb";
        assert_eq!(
            read_back(wire, GroupOrder::Ascending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=6 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Ascending a Group ID Delta of 0 is the prior Group plus one"
        );
        assert_eq!(
            read_back(wire, GroupOrder::Descending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=4 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Descending the same delta subtracts, and the same bytes are a \
             different answer"
        );
    },
);
fetch_gate!(
    draft19,
    "draft19",
    Draft19,
    uni,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
    #[tokio::test]
    async fn an_end_of_range_marker_is_a_record_and_not_an_object() {
        assert_eq!(
            read_back("0504808c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x8c",
            "reading fetch-end-of-non-existent-range back through the facade"
        );
    },
    #[tokio::test]
    async fn the_same_bytes_walk_the_other_way_under_descending() {
        let wire = "05041c05008001aa0c000001bb";
        assert_eq!(
            read_back(wire, GroupOrder::Ascending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=6 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Ascending a Group ID Delta of 0 is the prior Group plus one"
        );
        assert_eq!(
            read_back(wire, GroupOrder::Descending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=4 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Descending the same delta subtracts, and the same bytes are a \
             different answer"
        );
    },
);
fetch_gate!(
    draft20,
    "draft20",
    Draft20,
    uni,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
    #[tokio::test]
    async fn an_end_of_range_marker_is_a_record_and_not_an_object() {
        assert_eq!(
            read_back("0504808c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x8c",
            "reading fetch-end-of-non-existent-range back through the facade"
        );
    },
    /// Draft-20's third marker, which no earlier draft has: a span the
    /// publisher gave up on rather than one it knows about.
    #[tokio::test]
    async fn the_third_marker_this_draft_added_comes_back_as_its_own_code() {
        assert_eq!(
            read_back("0504820c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x20c",
            "reading fetch-end-of-timed-out-range back through the facade"
        );
    },
    #[tokio::test]
    async fn the_same_bytes_walk_the_other_way_under_descending() {
        let wire = "05041c05008001aa0c000001bb";
        assert_eq!(
            read_back(wire, GroupOrder::Ascending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=6 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Ascending a Group ID Delta of 0 is the prior Group plus one"
        );
        assert_eq!(
            read_back(wire, GroupOrder::Descending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=4 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Descending the same delta subtracts, and the same bytes are a \
             different answer"
        );
    },
);
fetch_gate!(
    draft21,
    "draft21",
    Draft21,
    uni,
    none,
    4,
    "fetch-stream-two-objects",
    "05041c00008004deadbeef0002cafe",
    "group=0 subgroup=0 object=0 payload=deadbeef status=none eor=none | \
     group=0 subgroup=0 object=1 payload=cafe status=none eor=none",
    #[tokio::test]
    async fn an_end_of_range_marker_is_a_record_and_not_an_object() {
        assert_eq!(
            read_back("0504808c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x8c",
            "reading fetch-end-of-non-existent-range back through the facade"
        );
    },
    /// Draft-21's third marker, which no earlier draft has: a span the
    /// publisher gave up on rather than one it knows about.
    #[tokio::test]
    async fn the_third_marker_this_draft_added_comes_back_as_its_own_code() {
        assert_eq!(
            read_back("0504820c050a00", GroupOrder::Ascending).await,
            "group=5 subgroup=none object=10 payload=- status=none eor=0x20c",
            "reading fetch-end-of-timed-out-range back through the facade"
        );
    },
    #[tokio::test]
    async fn the_same_bytes_walk_the_other_way_under_descending() {
        let wire = "05041c05008001aa0c000001bb";
        assert_eq!(
            read_back(wire, GroupOrder::Ascending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=6 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Ascending a Group ID Delta of 0 is the prior Group plus one"
        );
        assert_eq!(
            read_back(wire, GroupOrder::Descending).await,
            "group=5 subgroup=0 object=0 payload=aa status=none eor=none | \
             group=4 subgroup=0 object=0 payload=bb status=none eor=none",
            "under Descending the same delta subtracts, and the same bytes are a \
             different answer"
        );
    },
);

// ── Where the Group Order comes from ────────────────────────────────────────

/// The three shapes `fetch_group_order` has to read, and the one it invents.
///
/// This is a pure conversion and needs no session: what it takes is a FETCH_OK,
/// and the point is that the field it wants has moved twice. Drafts 07 through
/// 14 carry Group Order on the message; drafts 15 and 16 deleted it; drafts 17
/// through 20 brought it back as an **optional** Track Property, on exactly the
/// three drafts where the answer decides how every Group ID after the first
/// resolves.
///
/// The absent case is the one worth pinning, because it is the common one: a
/// FETCH_OK with no `0x22` property is not an error and is not a missing answer.
/// Draft-20 Section 10.2.8 makes Ascending the default, so that is what comes
/// back — and a gate that only covered the present case would let a `None` here
/// turn into a reader pointed at nothing.
#[cfg(feature = "draft20")]
#[test]
fn the_group_order_is_read_off_the_property_that_carries_it_or_defaulted() {
    use moqtap_client::dispatch::fetch_group_order;
    use moqtap_codec::draft20::message::{ControlMessage, FetchOk};
    use moqtap_codec::kvp::KvpValue;
    use moqtap_codec::varint::VarInt;

    let v = |n: u64| VarInt::from_u64(n).expect("fixture value fits a varint");
    let fetch_ok = |properties: Vec<KeyValuePair>| {
        AnyControlMessage::Draft20(ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: v(0),
            end_object: v(0),
            parameters: Vec::new(),
            track_properties: properties,
        }))
    };
    let order = |code: u64| vec![KeyValuePair { key: v(0x22), value: KvpValue::Varint(v(code)) }];

    assert_eq!(
        fetch_group_order(&fetch_ok(order(0x2))),
        GroupOrder::Descending,
        "a FETCH_OK naming Descending is read as Descending"
    );
    assert_eq!(
        fetch_group_order(&fetch_ok(order(0x1))),
        GroupOrder::Ascending,
        "a FETCH_OK naming Ascending is read as Ascending"
    );
    assert_eq!(
        fetch_group_order(&fetch_ok(Vec::new())),
        GroupOrder::Ascending,
        "an omitted DEFAULT PUBLISHER GROUP ORDER is Ascending, which is the \
         draft's answer and not this function's guess"
    );
    assert_eq!(
        fetch_group_order(&fetch_ok(order(0x0))),
        GroupOrder::Ascending,
        "Publisher states no direction, and a delta reader needs one"
    );
}
/// The three shapes `fetch_group_order` has to read, and the one it invents.
///
/// This is a pure conversion and needs no session: what it takes is a FETCH_OK,
/// and the point is that the field it wants has moved twice. Drafts 07 through
/// 14 carry Group Order on the message; drafts 15 and 16 deleted it; drafts 17
/// through 20 brought it back as an **optional** Track Property, on exactly the
/// three drafts where the answer decides how every Group ID after the first
/// resolves.
///
/// The absent case is the one worth pinning, because it is the common one: a
/// FETCH_OK with no `0x22` property is not an error and is not a missing answer.
/// Draft-21 Section 9.20.9 makes Ascending the default, so that is what comes
/// back — and a gate that only covered the present case would let a `None` here
/// turn into a reader pointed at nothing.
#[cfg(feature = "draft21")]
#[test]
fn the_group_order_is_read_off_the_property_that_carries_it_or_defaulted_draft21() {
    use moqtap_client::dispatch::fetch_group_order;
    use moqtap_codec::draft21::message::{ControlMessage, FetchOk};
    use moqtap_codec::kvp::KvpValue;
    use moqtap_codec::varint::VarInt;

    let v = |n: u64| VarInt::from_u64(n).expect("fixture value fits a varint");
    let fetch_ok = |properties: Vec<KeyValuePair>| {
        AnyControlMessage::Draft21(ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: v(0),
            end_object: v(0),
            parameters: Vec::new(),
            track_properties: properties,
        }))
    };
    let order = |code: u64| vec![KeyValuePair { key: v(0x22), value: KvpValue::Varint(v(code)) }];

    assert_eq!(
        fetch_group_order(&fetch_ok(order(0x2))),
        GroupOrder::Descending,
        "a FETCH_OK naming Descending is read as Descending"
    );
    assert_eq!(
        fetch_group_order(&fetch_ok(order(0x1))),
        GroupOrder::Ascending,
        "a FETCH_OK naming Ascending is read as Ascending"
    );
    assert_eq!(
        fetch_group_order(&fetch_ok(Vec::new())),
        GroupOrder::Ascending,
        "an omitted DEFAULT PUBLISHER GROUP ORDER is Ascending, which is the \
         draft's answer and not this function's guess"
    );
    assert_eq!(
        fetch_group_order(&fetch_ok(order(0x0))),
        GroupOrder::Ascending,
        "Publisher states no direction, and a delta reader needs one"
    );
}

/// The same question on a draft that puts the answer on the message.
///
/// Drafts 07 through 14 have no Track Properties at all, so a lookup written
/// only against them would find nothing on the three drafts that need it — and
/// one written only against those three would find nothing here.
#[cfg(feature = "draft14")]
#[test]
fn the_group_order_is_read_off_the_message_on_the_drafts_that_put_it_there() {
    use moqtap_client::dispatch::fetch_group_order;
    use moqtap_codec::draft14::message::{ControlMessage, FetchOk};
    use moqtap_codec::types::{GroupOrder as WireOrder, Location};
    use moqtap_codec::varint::VarInt;

    let v = |n: u64| VarInt::from_u64(n).expect("fixture value fits a varint");
    let fetch_ok = |order: WireOrder| {
        AnyControlMessage::Draft14(ControlMessage::FetchOk(FetchOk {
            request_id: v(1),
            group_order: order,
            end_of_track: 0,
            end_location: Location { group: v(0), object: v(0) },
            parameters: Vec::new(),
        }))
    };

    assert_eq!(fetch_group_order(&fetch_ok(WireOrder::Descending)), GroupOrder::Descending);
    assert_eq!(fetch_group_order(&fetch_ok(WireOrder::Ascending)), GroupOrder::Ascending);
}

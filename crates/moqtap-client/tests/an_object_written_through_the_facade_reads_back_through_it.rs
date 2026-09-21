//! `AnyConnection::open_subgroup` puts an object on the wire and
//! `AnyConnection::accept_subgroup` reads one back, on all the drafts.
//!
//! This is the first thing the facade can ask a relay that is not a question
//! about control messages. Answering SUBSCRIBE is not delivering a track, and
//! from outside there is no way to tell the two apart until something puts an
//! object on the wire — which is what every gate here does.
//!
//! # The round trip, and what makes it one
//!
//! The client writes a subgroup stream through the facade. The peer reads it to
//! its end, decodes the header with `moqtap_codec`'s own parser, records every
//! byte, and writes the same bytes back on a stream of its own. The client then
//! reads them through the facade.
//!
//! The echo alone would settle very little: a writer and a reader wrong in the
//! same way agree with each other perfectly. What closes that is that the peer
//! is not the client. It parses the header with a parser the client never
//! touches, and it reports **the whole stream as a hex transcript**, which each
//! gate holds against a fixed string. So the header is checked by two
//! independent parsers, and the objects are checked against bytes rather than
//! against whatever produced them.
//!
//! That transcript is also the only thing here that can gate the Object ID
//! encoding. Drafts 14 and later send an ID as a delta from the object before
//! it, and a writer and a reader that both skipped the delta would round-trip
//! cleanly. The drafts 14-21 transcripts carry `02` and `03` where the objects
//! were written as 3 and 7; the drafts 07-13 ones carry `03` and `07`.
//!
//! # Five object shapes, four header shapes, one signature
//!
//! What the facade absorbs is two differences, and they do not move together.
//!
//! The header takes four shapes. Drafts 07 through 10 keep the stream type
//! outside it; drafts 11 through 13 name a `StreamType` variant per layout;
//! draft-14 folds the type in as a flag word and makes the Subgroup ID an
//! `Option` that must agree with it; drafts 15 through 20 replace the flags
//! with a type byte. The transcripts open `04`, `0c`, `14`, `14` — the type
//! moved twice inside that range without the struct moving with it.
//!
//! The object takes five. Draft-07 has no extension block at all. Draft-08
//! counts its extensions and draft-09 changed the count to a byte length, which
//! every draft through 13 kept. Draft-14 dropped the declared payload length
//! and derives it, and renamed the status field. Drafts 15 and later put the
//! length back and refuse an object whose field disagrees with the bytes beside
//! it.
//!
//! Seven of those nine boundaries fall in different places from each other.
//! That is the whole argument for a facade over a data plane: a caller has an
//! ID and some bytes, and not one of the nine is a choice it makes.
//!
//! # Drafts 08 through 10 cannot open a stream without an extension block
//!
//! Their subgroup header is four values and no type field, so nothing in it
//! could say whether the objects carry the block — and every object does. The
//! three gates for them assert `extensions=true` and a stream three bytes
//! longer, one length of zero per object. Draft-07 reports `false` for the
//! opposite reason: it has no such block to carry. Only from draft-11 is this a
//! question with two answers, and `open_subgroup` asks for the block-free one
//! wherever asking is possible.
//!
//! # Three objects, and why not one
//!
//! Object IDs `0`, `3` and `7`, deliberately not consecutive: on a stream
//! carrying one object a delta and an absolute value are the same number, and
//! consecutive IDs would make every delta `0`.
//!
//! The third object carries **no payload and a status**, which is the second of
//! the two forms the wire has for an object. Every draft writes the status
//! field only when the declared length is zero, because the status and the
//! payload occupy the same position — no sequence of bytes states both. So both
//! forms are here, and `AnyObject::status` is asserted `None` on the first two
//! and `Some(0)` on the third, on all the drafts, including the seven
//! whose own structs hold a status for every object whether the wire carried
//! one or not.
//!
//! # Where the era split shows up on the data plane
//!
//! `stream_id()` reports a stream's ordinal within its own (initiator,
//! directionality) class. Drafts 07 through 16 carry control on a bidirectional
//! stream, so the first subgroup either side opens is its first unidirectional
//! stream: ordinal `0`. From draft-17 control moved to one unidirectional
//! stream each way, which takes that ordinal, and the subgroup is `1`. Both
//! ends are asserted, which is what makes the number the transport's rather
//! than a counter of subgroups kept beside it.
//!
//! # A stream that arrives in pieces is the same stream
//!
//! Every gate here runs twice, and the second time the peer echoes the stream
//! in three writes rather than one: a single byte, then everything up to the
//! last, then the last byte on its own.
//!
//! This is not thoroughness for its own sake. A reader that decodes from a
//! buffer it fills itself has to tell *the field has not all arrived* from
//! *the field is wrong*, and running out of bytes has four spellings in
//! `CodecError` because a decode can run out inside a nested decoder that
//! reports in its own type. Only one of the four says `UnexpectedEnd` in its
//! own name. A framed reader that matched that one alone would treat the other
//! three as malformed input, and an object whose leading varint has not all
//! arrived would end the stream instead of waiting for it.
//!
//! A one-write echo cannot see that: the whole stream is in the buffer before
//! the first decode, so no field ever straddles a boundary. Against a relay it
//! is not a corner at all — moq-rs forwards a subgroup header as it arrives
//! and the objects after it, so the second read starts from an empty buffer
//! every time, and the fourteenth draft's delivery probe reported
//! `insufficient bytes for varint decoding` for an object that was merely
//! still in flight. The cuts here put the boundary where that relay puts it:
//! inside the header, and again immediately before the Object Status that ends
//! the last object on all the drafts.
//!
//! The condition has one answer, `CodecError::is_incomplete`, and the readers
//! this file drives ask it rather than keeping a list of spellings of their
//! own: `read_subgroup_header` and `read_subgroup_object` match on it on all
//! drafts, and `moqtap-proxy`'s `parser::data::is_incomplete_error`
//! delegates straight to it. A list copied per call site is one that can fall
//! behind the four spellings `is_incomplete` admits, and nothing here would
//! notice — `read_fetch_stream_header` keeps two of the four written out by
//! hand on drafts 15 and 17, and this file reads subgroups.
//!
//! # What is *not* claimed
//!
//! That a relay delivers objects. Nothing here dials one; the peer is a fixture
//! that echoes. What this settles is that the facade can express the question.
//!
//! # Ablations, measured
//!
//! Five cuts, each made, run and reverted.
//!
//! `CodecError::is_incomplete` narrowed to `UnexpectedEnd` alone, the one
//! spelling of running out that says so in its own name. **The
//! fourteen fragmented gates redden and the fourteen one-write gates stay
//! green** — a clean split, and the reason both halves are here: the one-write
//! gates cannot see this defect at all, and a suite that only reddens as a
//! whole would not have told which half was measuring it.
//!
//! ```text
//! test result: FAILED. 14 passed; 14 failed
//!
//! accept a subgroup header split across two reads:
//!     AnyConnectionError("codec error: varint error: insufficient bytes for varint decoding")
//! ```
//!
//! That string is quoted from the ablation, but it was first read off a relay:
//! it is what the delivery probe reported for moq-rs on draft-14, for an object
//! that had been forwarded correctly and was merely still arriving.
//!
//! `open_subgroup` ignoring its `subgroup_id` argument and writing zero. **All
//! fourteen redden**, which is the plainest form of the claim — the caller's
//! values reach the wire:
//!
//! ```text
//! assertion `left == right` failed: the header the facade's reader handed back is not the one that was asked for
//!   left: "subgroup alias=7 group=3 subgroup=0 priority=200 extensions=false"
//!  right: "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false"
//! ```
//!
//! The subgroup header type written as `0x15` rather than `0x14` on drafts 15
//! and later — the extension bit set, the objects untouched. **Six redden,
//! eight stay green**, which is the boundary: below draft-15 that bit is not in
//! a type byte at all.
//!
//! ```text
//! assertion `left == right` failed: the header the facade's reader handed back is not the one that was asked for
//!   left: "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=true"
//!  right: "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false"
//! ```
//!
//! `read_object` reporting `Some(status)` for every object on drafts 07 through
//! 13 rather than only for the ones the wire carried a status for. **Seven
//! redden and seven stay green** — exactly the drafts whose structs hold a
//! status unconditionally, which is that normalisation being load bearing
//! rather than incidental:
//!
//! ```text
//! assertion `left == right` failed: the objects that came back are not the ones written
//!   left: [AnyObject { object_id: 0, payload: [102, 105, 114, 115, 116], status: Some(0) }, ..]
//!  right: [AnyObject { object_id: 0, payload: [102, 105, 114, 115, 116], status: None }, ..]
//! ```
//!
//! `write_object` passing `None` for the empty object's status instead of
//! `Some(Normal)`. Worth recording for how it splits. On **drafts 15 through 20
//! nothing changes at all**: their writer reads `object_status.unwrap_or(Normal)`
//! beside a zero length, so the two spellings produce identical bytes and the
//! explicit one states the struct's contract at the call site rather than
//! putting anything on the wire. On **draft-14 the same cut reddens**, alone,
//! because its writer reads `None` as *not the status form* and writes a zero
//! length with nothing after it, leaving an object no reader can frame:
//!
//! ```text
//! read the object written as 7: codec error: varint error: insufficient bytes for varint decoding
//! ```

mod common;

use std::time::Duration;

use moqtap_client::dispatch::{AnyClientConfig, AnyConnection, AnyObject, AnyTransportType};
use moqtap_codec::dispatch::{AnyControlMessage, AnySubgroupHeader};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long the fragmenting peer waits between the pieces of one stream.
///
/// Long enough that the client has certainly consumed what it was given and is
/// blocked waiting for the rest — the work in between is three decodes against
/// a buffer already in memory. It buys the *boundary*, not the result: with a
/// reader that refills correctly any chunking passes, so no value here can
/// turn this gate red. Too small a one would only let the pieces coalesce and
/// quietly stop asking the question, which is why it is a named constant with
/// this paragraph attached rather than a number in the peer.
const SETTLE: Duration = Duration::from_millis(50);

/// The Track Alias the objects belong to.
///
/// Nothing subscribed to it, and nothing here needs to have: a subgroup stream
/// names its track by alias and the facade does not check the name against a
/// table, because a probe measuring a relay may well want to send objects for a
/// track it was never granted.
const ALIAS: u64 = 7;

/// The Group ID the stream carries, and the Subgroup ID within it.
///
/// Different numbers, and neither of them zero: a header that put the group
/// where the subgroup goes, or filled either in with a default, would read back
/// as the other and a gate using one value twice could not tell.
const GROUP: u64 = 3;
const SUBGROUP: u64 = 5;

/// The Publisher Priority. Not the midpoint 128, so a header that dropped the
/// field and let a default stand in is visible in the peer's report.
const PRIORITY: u8 = 200;

/// What each gate writes, in order.
///
/// The IDs skip, because drafts 14 and later delta-encode them; the payloads
/// differ in length, so an object framed against the wrong length is not merely
/// an object with the wrong bytes; and the last one is empty, which is what
/// puts a status on the wire.
const OBJECTS: [(u64, &[u8]); 3] = [(0, b"first"), (3, b"second object"), (7, b"")];

/// `Normal`, which is `0` on every draft — the drafts that assign any status at
/// all agree that a non-zero code forbids a payload, which fixes zero as the
/// one an object with a payload could have carried.
const NORMAL: u64 = 0;

/// What [`OBJECTS`] must read back as.
///
/// The status is `None` for the two objects with payloads and `Some(NORMAL)`
/// for the empty one, which is the wire's answer and not any one draft's.
fn expected_objects() -> Vec<AnyObject> {
    OBJECTS
        .iter()
        .map(|(id, payload)| AnyObject {
            object_id: *id,
            payload: payload.to_vec(),
            status: payload.is_empty().then_some(NORMAL),
        })
        .collect()
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

/// One subgroup header, rendered through [`AnySubgroupHeader`]'s uniform
/// accessors so the string means the same thing on all the drafts even
/// where the struct behind it does not.
///
/// Both sides render with this and each gate holds both against one literal:
/// the peer's, decoded by `moqtap_codec`'s own parser straight off the wire,
/// and the client's, handed back by the facade's reader. A writer and a reader
/// wrong in the same way agree with each other, and neither agrees with the
/// literal.
fn describe_header(header: &AnySubgroupHeader) -> String {
    let subgroup = match header.subgroup_id() {
        Some(id) => id.to_string(),
        None => "first-object".to_string(),
    };
    let priority = match header.publisher_priority() {
        Some(p) => p.to_string(),
        None => "inherited".to_string(),
    };
    format!(
        "subgroup alias={} group={} subgroup={} priority={} extensions={}",
        header.track_alias(),
        header.group_id(),
        subgroup,
        priority,
        header.carries_extension_block(),
    )
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
/// Drafts 07 through 14 answer CLIENT_SETUP with a SERVER_SETUP naming the
/// version they picked out of the list; drafts 15 and 16 settle the version by
/// ALPN and drop that field; drafts 17 and later replaced the pair with one
/// SETUP each way, on a unidirectional stream each way rather than on a shared
/// bidirectional one.
///
/// Expands to whatever must stay alive for the session to: dropping the peer's
/// half of the control stream resets it, which ends the session before a single
/// object could be written.
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
/// Draft-07 alone requires a ROLE of both endpoints in both directions —
/// draft-08 withdrew it — so a draft-07 session never reaches the point where a
/// data stream could be written without one. No draft here needs a request
/// ceiling, because no gate makes a request: a subgroup stream is not one, on
/// any draft.
macro_rules! draft_setup_parameters {
    // `KvpValue`, `VarInt` and the varint helper live in this arm rather than
    // at the top of the file because this arm has exactly one caller — the
    // draft-07 gate, the only draft that passes `with_role` — and
    // the `none` arm below needs none of them. At file scope they were unread
    // by the other thirteen, which `RUSTFLAGS="-D warnings"` makes an error on
    // every matrix row but draft-07's and on `just draft-pairs`'
    // `draft19,draft20`. Kept here they need no `cfg` and no `allow`: the
    // condition is already spelled, once, by which arm the invocation names.
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

/// Where the first subgroup stream falls among the unidirectional streams its
/// own side opened.
///
/// `stream_id()` reports quinn's `StreamId::index()` — the stream's ordinal
/// within its own (initiator, directionality) class, not the raw QUIC stream
/// number — and that ordinal is where the era split shows up on the data plane.
/// Drafts 07 through 16 carry control on a **bidirectional** stream, so the
/// first subgroup either side opens is the first unidirectional stream it has
/// opened at all. From draft-17 control moved to one unidirectional stream each
/// way, which takes the ordinal ahead of it.
///
/// So this is not a restatement of the handshake tag: it is the handshake being
/// visible from the data plane, which is the only place a number reported by
/// `stream_id()` could come from the transport rather than from a counter of
/// subgroups kept beside it.
macro_rules! first_subgroup_index {
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

/// One draft's round trip.
///
/// `$handshake` picks the setup exchange, `$params` whatever that draft needs
/// in it, `$header` is what both parsers must make of the header the client
/// wrote, `$bytes` is how long the whole stream came out, and `$wire` is every
/// byte of it.
macro_rules! subgroup_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, $params:tt,
     $header:literal, $bytes:literal, $wire:literal) => {
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

            /// Complete the handshake, read the client's subgroup stream whole,
            /// decode its header, and write the same bytes back.
            ///
            /// The echo is deliberately dumb. Re-encoding the stream from the
            /// decoded objects would put the *codec's* framing on the wire in
            /// place of the client's, and the client's is what is under test —
            /// a writer that framed its objects wrongly would have them
            /// silently corrected on the way back.
            async fn serve(server: quinn::Endpoint) -> String {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                // Held for the life of the session: dropping either half of the
                // control stream resets it, and the session with it.
                let _control = peer_setup!($handshake, conn, $version, $module);

                let mut recv =
                    conn.accept_uni().await.expect("accept the client's subgroup stream");
                let bytes =
                    recv.read_to_end(64 * 1024).await.expect("read the subgroup stream whole");

                let mut cursor = &bytes[..];
                let header = AnySubgroupHeader::decode_stream(DRAFT, &mut cursor)
                    .expect("the client wrote a subgroup header this draft's codec can read");
                // Everything past the header is the peer's alone. The client
                // reads the objects back off an echo of its own bytes, so a
                // writer and a reader wrong in the same way about the object
                // framing agree with each other; the only thing that does not
                // is a fixed transcript of what went out.
                let report = format!(
                    "{} bytes={} wire={}",
                    describe_header(&header),
                    bytes.len(),
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                );

                let mut send = conn.open_uni().await.expect("open a subgroup stream back");
                send.write_all(&bytes).await.expect("echo the subgroup stream");
                send.finish().expect("finish the echo");

                // Held open until the client has read the echo. Returning here
                // would drop the connection and tear the stream down with it —
                // a failure that reads as "the peer closed" and is really "the
                // peer finished first".
                conn.closed().await;
                report
            }

            #[tokio::test]
            async fn an_object_written_on_a_subgroup_stream_reads_back_as_what_was_written() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));

                let conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut writer = tokio::time::timeout(
                    PATIENCE,
                    conn.open_subgroup(ALIAS, GROUP, SUBGROUP, PRIORITY),
                )
                .await
                .expect("opening the subgroup did not finish")
                .expect("open a subgroup stream");
                assert_eq!(writer.draft(), DRAFT, "the writer reports the draft framing it");
                assert_eq!(
                    writer.stream_id(),
                    first_subgroup_index!($handshake),
                    "the number reported has to be the transport's own, and on this draft the \
                     control stream has {} unidirectional streams of this side's ahead of it",
                    first_subgroup_index!($handshake),
                );

                for (id, payload) in OBJECTS {
                    tokio::time::timeout(PATIENCE, writer.write_object(id, payload))
                        .await
                        .expect("writing an object did not finish")
                        .unwrap_or_else(|e| panic!("write object {id}: {e}"));
                }
                tokio::time::timeout(PATIENCE, writer.finish())
                    .await
                    .expect("finishing the subgroup did not finish")
                    .expect("finish the subgroup");

                let (header, mut reader) = tokio::time::timeout(PATIENCE, conn.accept_subgroup())
                    .await
                    .expect("the echoed subgroup never arrived")
                    .expect("accept the echoed subgroup");
                assert_eq!(reader.draft(), DRAFT, "the reader reports the draft framing it");
                assert_eq!(
                    reader.stream_id(),
                    first_subgroup_index!($handshake),
                    "the peer's control stream sits ahead of its subgroup on exactly the drafts \
                     where it is unidirectional, and the number reported must show it"
                );
                assert_eq!(
                    describe_header(&header),
                    $header,
                    "the header the facade's reader handed back is not the one that was asked for"
                );

                let mut read = Vec::new();
                for (id, _) in OBJECTS {
                    read.push(
                        tokio::time::timeout(PATIENCE, reader.read_object())
                            .await
                            .expect("an object never arrived")
                            .unwrap_or_else(|e| panic!("read the object written as {id}: {e}")),
                    );
                }
                assert_eq!(
                    read,
                    expected_objects(),
                    "the objects that came back are not the ones written"
                );

                // Releases the peer, which is holding its connection open until
                // this side is done reading.
                conn.close(0, b"gate complete");

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    seen,
                    concat!($header, " bytes=", $bytes, " wire=", $wire),
                    "the header the peer decoded off the wire is not the one that was asked for"
                );
            }

            /// The same round trip, echoed back in three pieces.
            ///
            /// The cuts are chosen so that both of the reader's refill paths
            /// are forced, and each one lands where a *varint* is the field
            /// that runs out:
            ///
            /// * one byte, then the rest. No draft's subgroup header fits in a
            ///   byte, so the header cannot be decoded from the first piece and
            ///   the reader has to go back for more.
            /// * everything but the final byte, then that byte. The last object
            ///   carries no payload, so on all the drafts the stream's
            ///   last byte is its Object Status — and the reader reaches it
            ///   having already consumed the two objects before it.
            async fn serve_fragmented(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!($handshake, conn, $version, $module);

                let mut recv =
                    conn.accept_uni().await.expect("accept the client's subgroup stream");
                let bytes =
                    recv.read_to_end(64 * 1024).await.expect("read the subgroup stream whole");
                assert!(
                    bytes.len() > 2,
                    "the three cuts below need a stream longer than the two of them"
                );

                let mut send = conn.open_uni().await.expect("open a subgroup stream back");
                let last = bytes.len() - 1;
                for piece in [&bytes[..1], &bytes[1..last], &bytes[last..]] {
                    send.write_all(piece).await.expect("echo a piece of the subgroup stream");
                    tokio::time::sleep(SETTLE).await;
                }
                send.finish().expect("finish the echo");

                conn.closed().await;
            }

            #[tokio::test]
            async fn an_object_split_across_reads_is_still_one_object() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve_fragmented(endpoint));

                let conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut writer = tokio::time::timeout(
                    PATIENCE,
                    conn.open_subgroup(ALIAS, GROUP, SUBGROUP, PRIORITY),
                )
                .await
                .expect("opening the subgroup did not finish")
                .expect("open a subgroup stream");
                for (id, payload) in OBJECTS {
                    tokio::time::timeout(PATIENCE, writer.write_object(id, payload))
                        .await
                        .expect("writing an object did not finish")
                        .unwrap_or_else(|e| panic!("write object {id}: {e}"));
                }
                tokio::time::timeout(PATIENCE, writer.finish())
                    .await
                    .expect("finishing the subgroup did not finish")
                    .expect("finish the subgroup");

                let (header, mut reader) = tokio::time::timeout(PATIENCE, conn.accept_subgroup())
                    .await
                    .expect("the echoed subgroup never arrived")
                    .expect("accept a subgroup header split across two reads");
                assert_eq!(
                    describe_header(&header),
                    $header,
                    "a header that arrived in two pieces is not the one that was written"
                );

                let mut read = Vec::new();
                for (id, _) in OBJECTS {
                    read.push(
                        tokio::time::timeout(PATIENCE, reader.read_object())
                            .await
                            .expect("an object never arrived")
                            .unwrap_or_else(|e| {
                                panic!("read the object written as {id}, arriving in pieces: {e}")
                            }),
                    );
                }
                assert_eq!(
                    read,
                    expected_objects(),
                    "the objects that came back in pieces are not the ones written"
                );

                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
            }
        }
    };
}

subgroup_gate!(
    draft07,
    "draft07",
    Draft07,
    versioned,
    with_role,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "04070305c800056669727374030d7365636f6e64206f626a656374070000"
);
subgroup_gate!(
    draft08,
    "draft08",
    Draft08,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=true",
    "33",
    "04070305c8000005666972737403000d7365636f6e64206f626a65637407000000"
);
subgroup_gate!(
    draft09,
    "draft09",
    Draft09,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=true",
    "33",
    "04070305c8000005666972737403000d7365636f6e64206f626a65637407000000"
);
subgroup_gate!(
    draft10,
    "draft10",
    Draft10,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=true",
    "33",
    "04070305c8000005666972737403000d7365636f6e64206f626a65637407000000"
);
subgroup_gate!(
    draft11,
    "draft11",
    Draft11,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "0c070305c800056669727374030d7365636f6e64206f626a656374070000"
);
subgroup_gate!(
    draft12,
    "draft12",
    Draft12,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374030d7365636f6e64206f626a656374070000"
);
subgroup_gate!(
    draft13,
    "draft13",
    Draft13,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374030d7365636f6e64206f626a656374070000"
);
subgroup_gate!(
    draft14,
    "draft14",
    Draft14,
    versioned,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft15,
    "draft15",
    Draft15,
    plain,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft16,
    "draft16",
    Draft16,
    plain,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft17,
    "draft17",
    Draft17,
    uni,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft18,
    "draft18",
    Draft18,
    uni,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft19,
    "draft19",
    Draft19,
    uni,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft20,
    "draft20",
    Draft20,
    uni,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);
subgroup_gate!(
    draft21,
    "draft21",
    Draft21,
    uni,
    none,
    "subgroup alias=7 group=3 subgroup=5 priority=200 extensions=false",
    "30",
    "14070305c800056669727374020d7365636f6e64206f626a656374030000"
);

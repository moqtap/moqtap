//! `AnyConnection::recv_inbound_serving_fetch` hands a peer's FETCH over, and
//! `answer_fetch`, `refuse_fetch` and `open_fetch_response` answer and serve it
//! the way its draft does. Plain `recv_inbound` refuses a FETCH with
//! NOT_SUPPORTED on drafts 08-23.
//!
//! draft-23 Section 3.2: "The publisher MUST send exactly one FETCH_OK or
//! FETCH_ERROR in response to a FETCH." draft-23 Section 1.5 uses those names
//! as shorthand for a REQUEST_OK and a REQUEST_ERROR sent in response to a
//! FETCH. The peer here is a raw subscriber that
//! reads every answer off the wire and compares its bytes with the message the
//! draft defines.
//!
//! # The End Location
//!
//! The track's Largest Object is {1, 1}. Draft-11 and drafts 20-22 name the
//! last Object the response covers; drafts 12-19 name it plus 1, or {Group, 0}
//! for a whole Group covered (draft-12 Section 8.17, draft-19 Section 10.13).
//! Draft-23 answers with REQUEST_OK, carrying LARGEST_OBJECT only when the
//! Largest Object is within the range (draft-23 Section 3.2).

// Shared fixtures and builders, each used by a subset of the per-draft gates.
#![allow(dead_code, unused_macros)]

mod common;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyArrival, AnyClientConfig, AnyConnection, AnyServedArrival, AnyTransportType, FetchAnswer,
    FetchAnswered, FetchEnd, FetchLocation, FetchRefusal, InboundFetchKind, JoiningStart,
    ServedFetchRange,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

const PATIENCE: Duration = Duration::from_secs(10);

const TRACK: &[u8] = b"video";

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("fixture value fits a varint")
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// `max_request_id` (`max_subscribe_id` on drafts 08-10), so the peer's
/// requests are within budget.
fn granted_budget() -> KeyValuePair {
    KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }
}

fn client_config(draft: DraftVersion) -> AnyClientConfig {
    AnyClientConfig {
        draft,
        additional_versions: Vec::new(),
        transport: AnyTransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: vec![granted_budget()],
    }
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `n`th request the peer makes. Odd: the peer is the server.
fn request_id(n: usize) -> u64 {
    1 + 2 * n as u64
}

/// The track as the publisher holds it.
const ANSWER: FetchAnswer = FetchAnswer {
    largest_object: FetchLocation { group: 1, object: 1 },
    end_of_track: true,
    end_group_last_object: Some(4),
};

/// The range one FETCH asks for.
#[derive(Debug, Clone, Copy)]
enum Ask {
    /// From `start` through `end`, inclusive.
    Through { start: (u64, u64), end: (u64, u64) },
    /// From `start` through every Object of `end_group`.
    WholeGroup { start: (u64, u64), end_group: u64 },
    /// A relative start, open-ended. Drafts 20-23 only.
    Relative(u64),
    /// The Next Object after the Largest Object, drafts 20-23.
    NextObject,
}

impl Ask {
    /// The inline fields of drafts 11-19, whose end Object is the last one
    /// plus 1, or 0 for the entire Group (draft-11 Section 8.13,
    /// draft-19 Section 10.12.1).
    fn inline(self) -> (u64, u64, u64, u64) {
        match self {
            Ask::Through { start, end } => (start.0, start.1, end.0, end.1 + 1),
            Ask::WholeGroup { start, end_group } => (start.0, start.1, end_group, 0),
            Ask::Relative(_) | Ask::NextObject => {
                panic!("drafts 11-19 have no relative FETCH start")
            }
        }
    }
}

/// What the client must send back.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// Served, with the expected inclusive End Location, plus-one End
    /// Location, draft-23 LARGEST_OBJECT presence, End Of Track, and the range
    /// `answer_fetch` reports.
    Served {
        inclusive: (u64, u64),
        plus_one: (u64, u64),
        largest_in_range: bool,
        end_of_track: u8,
        range: ServedFetchRange,
    },
    /// `answer_fetch` refuses with INVALID_RANGE on its own.
    InvalidRange,
    /// The caller refuses.
    Refused(FetchRefusal),
}

#[derive(Debug, Clone, Copy)]
struct Case {
    ask: Ask,
    expect: Expect,
    /// Serve two Objects on a fetch stream after the answer.
    stream: bool,
}

const fn served(start: (u64, u64), end_group: u64, end: FetchEnd) -> ServedFetchRange {
    ServedFetchRange { start: FetchLocation { group: start.0, object: start.1 }, end_group, end }
}

/// The cases every draft from 11 on runs.
fn cases() -> Vec<Case> {
    vec![
        // Within the published range: the End Location is the requested one.
        Case {
            ask: Ask::Through { start: (0, 0), end: (0, 1) },
            expect: Expect::Served {
                inclusive: (0, 1),
                plus_one: (0, 2),
                largest_in_range: false,
                end_of_track: 0,
                range: served((0, 0), 0, FetchEnd::Object(1)),
            },
            stream: true,
        },
        // Past the Largest Object: the response ends there, and reaches the
        // end of the track.
        Case {
            ask: Ask::Through { start: (0, 0), end: (5, 0) },
            expect: Expect::Served {
                inclusive: (1, 1),
                plus_one: (1, 2),
                largest_in_range: true,
                end_of_track: 1,
                range: served((0, 0), 1, FetchEnd::Object(1)),
            },
            stream: false,
        },
        // A whole Group before the Largest Object's, whose last Object is 4.
        Case {
            ask: Ask::WholeGroup { start: (0, 0), end_group: 0 },
            expect: Expect::Served {
                inclusive: (0, 4),
                plus_one: (0, 0),
                largest_in_range: false,
                end_of_track: 0,
                range: served((0, 0), 0, FetchEnd::EntireGroup),
            },
            stream: false,
        },
        // Start past the Largest Object.
        Case {
            ask: Ask::Through { start: (2, 0), end: (3, 0) },
            expect: Expect::InvalidRange,
            stream: false,
        },
        Case {
            ask: Ask::Through { start: (0, 0), end: (0, 1) },
            expect: Expect::Refused(FetchRefusal::DoesNotExist),
            stream: false,
        },
    ]
}

/// End before Start, within one Group. Drafts 20-23 only: on drafts 11-19 the
/// codec refuses such a FETCH as it decodes it, and nothing reaches the facade.
const END_BEFORE_START: Case = Case {
    ask: Ask::Through { start: (1, 1), end: (1, 0) },
    expect: Expect::InvalidRange,
    stream: false,
};

/// A relative StartGroup of 1 starts at "{Largest Object.Group + 1 -
/// StartGroup, 0}" (draft-22 Section 9.20.9, draft-20 Section 5.1.2), which is
/// {1, 0}, and runs to the Largest Object. Drafts 20-22.
const RELATIVE_START: Case = Case {
    ask: Ask::Relative(1),
    expect: Expect::Served {
        inclusive: (1, 1),
        plus_one: (1, 2),
        largest_in_range: true,
        end_of_track: 1,
        range: served((1, 0), 1, FetchEnd::Object(1)),
    },
    stream: false,
};

/// A Next Object start is past the Largest Object. Drafts 20-23.
const NEXT_OBJECT: Case =
    Case { ask: Ask::NextObject, expect: Expect::InvalidRange, stream: false };

/// The caller refuses a FETCH it cannot filter. Drafts 19-23.
const INVALID_FILTER: Case = Case {
    ask: Ask::Through { start: (0, 0), end: (0, 1) },
    expect: Expect::Refused(FetchRefusal::InvalidFilter),
    stream: false,
};

/// A Joining Fetch, answered against `answer`.
#[derive(Debug, Clone, Copy)]
struct JoiningCase {
    start: JoiningStart,
    answer: FetchAnswer,
    /// Drafts 11-13, whose Joining range ends just before the Largest
    /// Location.
    before_14: Expect,
    /// Drafts 14-19, whose Joining range ends at it.
    from_14: Expect,
}

impl JoiningCase {
    fn expect(&self, draft: DraftVersion) -> Expect {
        if draft.number() <= 13 {
            self.before_14
        } else {
            self.from_14
        }
    }
}

/// The Largest Object is the first of its Group.
const AT_GROUP_START: FetchAnswer = FetchAnswer {
    largest_object: FetchLocation { group: 1, object: 0 },
    end_of_track: true,
    end_group_last_object: Some(4),
};

/// The Joining cases drafts 11-19 run.
///
/// draft-11 Section 8.13.1 ends a Joining Fetch on "Fetch End Object:
/// Subscribe Largest Object", an end Object plus 1, and "1 is subtracted from
/// the Fetch End Group if Fetch End Object is 0"; draft-12 Section 8.16.1 does
/// the same with "Fetch End Location: Subscribe Largest Location".
/// draft-14 Section 9.16.2.1: "the last Object included in the Joining FETCH
/// response is Subscribe Largest Location".
fn joining_cases() -> Vec<JoiningCase> {
    vec![
        JoiningCase {
            start: JoiningStart::GroupsBefore(1),
            answer: ANSWER,
            before_14: Expect::Served {
                inclusive: (1, 0),
                plus_one: (1, 1),
                largest_in_range: false,
                end_of_track: 0,
                range: served((0, 0), 1, FetchEnd::Object(0)),
            },
            from_14: Expect::Served {
                inclusive: (1, 1),
                plus_one: (1, 2),
                largest_in_range: true,
                end_of_track: 1,
                range: served((0, 0), 1, FetchEnd::Object(1)),
            },
        },
        JoiningCase {
            start: JoiningStart::Group(1),
            answer: ANSWER,
            before_14: Expect::Served {
                inclusive: (1, 0),
                plus_one: (1, 1),
                largest_in_range: false,
                end_of_track: 0,
                range: served((1, 0), 1, FetchEnd::Object(0)),
            },
            from_14: Expect::Served {
                inclusive: (1, 1),
                plus_one: (1, 2),
                largest_in_range: true,
                end_of_track: 1,
                range: served((1, 0), 1, FetchEnd::Object(1)),
            },
        },
        // Before draft-14 the range ends with all of Group 0.
        JoiningCase {
            start: JoiningStart::GroupsBefore(1),
            answer: AT_GROUP_START,
            before_14: Expect::Served {
                inclusive: (0, 4),
                plus_one: (0, 0),
                largest_in_range: false,
                end_of_track: 0,
                range: served((0, 0), 0, FetchEnd::EntireGroup),
            },
            from_14: Expect::Served {
                inclusive: (1, 0),
                plus_one: (1, 1),
                largest_in_range: true,
                end_of_track: 1,
                range: served((0, 0), 1, FetchEnd::Object(0)),
            },
        },
        // Before draft-14 that end comes before the start.
        JoiningCase {
            start: JoiningStart::GroupsBefore(0),
            answer: AT_GROUP_START,
            before_14: Expect::InvalidRange,
            from_14: Expect::Served {
                inclusive: (1, 0),
                plus_one: (1, 1),
                largest_in_range: true,
                end_of_track: 1,
                range: served((1, 0), 1, FetchEnd::Object(0)),
            },
        },
    ]
}

/// A Request ID no subscription of the peer's has.
const UNJOINED: u64 = 51;

/// Which End Location convention a draft writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Inclusive,
    PlusOne,
    RequestOk,
}

/// Reads whole control messages off one stream, keeping the bytes each took.
struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream, draft: DraftVersion) -> Self {
        Self { recv, draft, buf: Vec::new() }
    }

    async fn read_raw(&mut self) -> Option<(AnyControlMessage, Vec<u8>)> {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(self.draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    let raw = self.buf.drain(..consumed).collect();
                    return Some((msg, raw));
                }
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    let mut tmp = [0u8; 2048];
                    match self.recv.read(&mut tmp).await {
                        Ok(Some(n)) => self.buf.extend_from_slice(&tmp[..n]),
                        _ => return None,
                    }
                }
                Err(e) => panic!("the peer could not decode what the client wrote: {e}"),
            }
        }
    }
}

/// The peer's side of the session.
enum Peer {
    /// Drafts 08-16: every request and answer on the one control stream.
    Control { send: quinn::SendStream, recv: PeerStream },
    /// Drafts 17-23: a request stream per request, held open to the end.
    Streams { held: Vec<quinn::SendStream>, kept: Vec<PeerStream> },
}

impl Peer {
    /// Send `fetch`, or any request, and read the answer's bytes.
    async fn ask(
        &mut self,
        conn: &quinn::Connection,
        draft: DraftVersion,
        fetch: Vec<u8>,
    ) -> String {
        match self {
            Peer::Control { send, recv } => {
                send.write_all(&fetch).await.expect("write FETCH");
                hex(&recv.read_raw().await.expect("the client's answer").1)
            }
            Peer::Streams { held, kept } => {
                let (mut send, recv) = conn.open_bi().await.expect("open a request stream");
                send.write_all(&fetch).await.expect("write FETCH");
                held.push(send);
                let mut stream = PeerStream::new(recv, draft);
                let answer = hex(&stream.read_raw().await.expect("the client's answer").1);
                kept.push(stream);
                answer
            }
        }
    }
}

/// Run the client's half of every case, then hand a last FETCH to plain
/// `recv_inbound`.
async fn client(conn: &mut AnyConnection, cases: &[Case]) {
    for (n, case) in cases.iter().enumerate() {
        let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound_serving_fetch())
            .await
            .expect("nothing arrived")
            .expect("read the peer's FETCH");
        let AnyServedArrival::Fetch { message, request: mut fetch } = arrival else {
            panic!("case {n}: a FETCH did not come back as one");
        };
        assert_eq!(message.message_type_name(), "fetch");
        assert_eq!(fetch.request_id().into_inner(), request_id(n), "case {n}: the peer's id");
        match case.expect {
            Expect::Refused(refusal) => {
                conn.refuse_fetch(&mut fetch, refusal, b"").await.expect("refuse the FETCH");
            }
            Expect::InvalidRange => {
                let answered = conn.answer_fetch(&mut fetch, ANSWER).await.expect("answer");
                assert_eq!(answered, FetchAnswered::RefusedInvalidRange, "case {n}");
            }
            Expect::Served { range, .. } => {
                let answered = conn.answer_fetch(&mut fetch, ANSWER).await.expect("answer");
                assert_eq!(answered, FetchAnswered::Served(range), "case {n}");
                if case.stream {
                    let mut writer =
                        conn.open_fetch_response(&fetch).await.expect("open the fetch stream");
                    writer.write_object(0, 0, 0, 128, b"a").await.expect("first object");
                    writer.write_object(0, 0, 1, 128, b"b").await.expect("second object");
                    writer.finish().await.expect("finish the fetch stream");
                }
                fetch.finish().await.expect("finish the request");
            }
        }
    }
    let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound())
        .await
        .expect("the last FETCH never arrived")
        .expect("read the last FETCH");
    match arrival {
        AnyArrival::Other(message) => assert_eq!(message.message_type_name(), "fetch"),
        AnyArrival::Subscribe { .. } => panic!("a FETCH came back as SUBSCRIBE"),
    }
}

/// Accept the peer's SUBSCRIBE, answer each Joining Fetch that joins it, then
/// hand one naming no subscription to plain `recv_inbound`.
async fn client_joining(conn: &mut AnyConnection, cases: &[JoiningCase]) {
    let draft = conn.draft();
    let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound_serving_fetch())
        .await
        .expect("nothing arrived")
        .expect("read the peer's SUBSCRIBE");
    let AnyServedArrival::Subscribe { request: mut subscription, .. } = arrival else {
        panic!("the SUBSCRIBE did not come back as one");
    };
    conn.accept_subscribe(&mut subscription, v(7)).await.expect("accept the SUBSCRIBE");
    for (n, case) in cases.iter().enumerate() {
        let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound_serving_fetch())
            .await
            .expect("nothing arrived")
            .expect("read the peer's FETCH");
        let AnyServedArrival::Fetch { request: mut fetch, .. } = arrival else {
            panic!("case {n}: a FETCH did not come back as one");
        };
        assert_eq!(
            fetch.kind(),
            &InboundFetchKind::Joining { subscription: request_id(0), start: case.start },
            "case {n}"
        );
        let answered = conn.answer_fetch(&mut fetch, case.answer).await.expect("answer");
        match case.expect(draft) {
            Expect::Served { range, .. } => {
                assert_eq!(answered, FetchAnswered::Served(range), "case {n}");
                fetch.finish().await.expect("finish the request");
            }
            Expect::InvalidRange => {
                assert_eq!(answered, FetchAnswered::RefusedInvalidRange, "case {n}");
            }
            Expect::Refused(_) => unreachable!("the caller refuses no Joining case"),
        }
    }
    let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound())
        .await
        .expect("the unjoinable FETCH never arrived")
        .expect("read the unjoinable FETCH");
    match arrival {
        AnyArrival::Other(message) => assert_eq!(message.message_type_name(), "fetch"),
        AnyArrival::Subscribe { .. } => panic!("a FETCH came back as SUBSCRIBE"),
    }
    drop(subscription);
}

/// What the peer saw: each answer's bytes, and the fetch stream's.
struct Seen {
    answers: Vec<String>,
    stream: String,
    refused: String,
}

/// One draft's gate.
///
/// `$handshake` is `control` (drafts 11-16) or `streams` (drafts 17-23);
/// `$setup` builds the peer's SETUP from the client's; `$fetch` builds the
/// FETCH for `(id, ask)`; `$ok` the expected FETCH_OK for `(id, end_of_track,
/// end, largest)`; `$err` the expected refusal for `(id, code)`.
macro_rules! serve_gate {
    (
        $module:ident, $feat:literal, $version:ident, $family:ident, $handshake:ident,
        setup: |$cs:ident| $setup:expr,
        fetch: |$fid:ident, $ask:ident| $fetch:expr,
        ok: |$oid:ident, $eot:ident, $end:ident, $largest:ident| $ok:expr,
        err: |$eid:ident, $code:ident| $err:expr,
        transcript: $transcript:expr
        $(, extra: [$($extra:expr),* $(,)?])?
        $(, joining: {
            subscribe: |$sid:ident| $subscribe:expr,
            fetch: |$jid:ident, $joined:ident, $jstart:ident| $jfetch:expr $(,)?
        })?
        $(,)?
    ) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;
            #[allow(unused_imports)]
            use moqtap_codec::$module::message::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            #[allow(unused_variables)]
            fn server_setup($cs: &AnyControlMessage) -> Vec<u8> {
                encoded(AnyControlMessage::$version($setup))
            }

            #[allow(unused_variables)]
            fn fetch($fid: u64, $ask: Ask) -> Vec<u8> {
                let $fid = v($fid);
                encoded(AnyControlMessage::$version(ControlMessage::Fetch($fetch)))
            }

            #[allow(unused_variables)]
            fn ok($oid: u64, $eot: u8, $end: (u64, u64), $largest: bool) -> Vec<u8> {
                let $oid = v($oid);
                encoded(AnyControlMessage::$version($ok))
            }

            #[allow(unused_variables)]
            fn err($eid: u64, $code: u64) -> Vec<u8> {
                let $eid = v($eid);
                let $code = v($code);
                encoded(AnyControlMessage::$version($err))
            }

            fn all_cases() -> Vec<Case> {
                #[allow(unused_mut)]
                let mut all = cases();
                $($(all.push($extra);)*)?
                all
            }

            fn expected(n: usize, case: &Case) -> String {
                let id = request_id(n);
                hex(&match case.expect {
                    Expect::Served { inclusive, plus_one, largest_in_range, end_of_track, .. } => {
                        match Family::$family {
                            Family::Inclusive => ok(id, end_of_track, inclusive, largest_in_range),
                            Family::PlusOne => ok(id, end_of_track, plus_one, largest_in_range),
                            Family::RequestOk => ok(id, end_of_track, (0, 0), largest_in_range),
                        }
                    }
                    Expect::InvalidRange => {
                        err(id, FetchRefusal::InvalidRange.code(DRAFT).expect("assigned"))
                    }
                    Expect::Refused(refusal) => err(id, refusal.code(DRAFT).expect("assigned")),
                })
            }

            async fn handshake(conn: &quinn::Connection) -> Peer {
                serve_gate!(@$handshake conn)
            }

            async fn serve(server: quinn::Endpoint, cases: Vec<Case>) -> Seen {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let mut peer = handshake(&conn).await;
                let mut answers = Vec::new();
                let mut stream = String::new();
                for (n, case) in cases.iter().enumerate() {
                    answers.push(peer.ask(&conn, DRAFT, fetch(request_id(n), case.ask)).await);
                    if case.stream {
                        let mut uni = conn.accept_uni().await.expect("the fetch stream");
                        let bytes = uni.read_to_end(1 << 16).await.expect("read to its FIN");
                        stream = hex(&bytes);
                    }
                }
                let last = Ask::Through { start: (0, 0), end: (0, 1) };
                let refused = peer.ask(&conn, DRAFT, fetch(request_id(cases.len()), last)).await;
                Seen { answers, stream, refused }
            }

            #[tokio::test]
            async fn a_peers_fetch_is_answered_and_served_as_its_draft_defines() {
                common::init_crypto();
                let cases = all_cases();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, cases.clone()));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");
                client(&mut conn, &cases).await;

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                for (n, case) in cases.iter().enumerate() {
                    assert_eq!(seen.answers[n], expected(n, case), "{DRAFT:?} case {n}: {case:?}");
                }
                assert_eq!(seen.stream, $transcript, "{DRAFT:?} fetch stream");
                let not_supported = FetchRefusal::NotSupported.code(DRAFT).expect("assigned");
                assert_eq!(
                    seen.refused,
                    hex(&err(request_id(cases.len()), not_supported)),
                    "{DRAFT:?}: plain recv_inbound refuses with NOT_SUPPORTED"
                );
                drop(conn);
            }

            $(
                #[allow(unused_variables)]
                fn subscribe($sid: u64) -> Vec<u8> {
                    let $sid = v($sid);
                    encoded(AnyControlMessage::$version(ControlMessage::Subscribe($subscribe)))
                }

                #[allow(unused_variables)]
                fn joining_fetch($jid: u64, $joined: u64, $jstart: JoiningStart) -> Vec<u8> {
                    let $jid = v($jid);
                    encoded(AnyControlMessage::$version(ControlMessage::Fetch($jfetch)))
                }

                fn expected_joining(n: usize, case: &JoiningCase) -> String {
                    let id = request_id(n + 1);
                    hex(&match case.expect(DRAFT) {
                        Expect::Served { inclusive, plus_one, end_of_track, .. } => {
                            match Family::$family {
                                Family::Inclusive => ok(id, end_of_track, inclusive, false),
                                _ => ok(id, end_of_track, plus_one, false),
                            }
                        }
                        Expect::InvalidRange => {
                            err(id, FetchRefusal::InvalidRange.code(DRAFT).expect("assigned"))
                        }
                        Expect::Refused(refusal) => err(id, refusal.code(DRAFT).expect("assigned")),
                    })
                }

                async fn serve_joining(
                    server: quinn::Endpoint,
                    cases: Vec<JoiningCase>,
                ) -> Vec<String> {
                    let conn =
                        server.accept().await.expect("accept").await.expect("tls handshake");
                    let mut peer = handshake(&conn).await;
                    let joined = request_id(0);
                    let mut answers = vec![peer.ask(&conn, DRAFT, subscribe(joined)).await];
                    for (n, case) in cases.iter().enumerate() {
                        let fetch = joining_fetch(request_id(n + 1), joined, case.start);
                        answers.push(peer.ask(&conn, DRAFT, fetch).await);
                    }
                    let last = request_id(cases.len() + 1);
                    let fetch = joining_fetch(last, UNJOINED, JoiningStart::GroupsBefore(1));
                    answers.push(peer.ask(&conn, DRAFT, fetch).await);
                    answers
                }

                #[tokio::test]
                async fn a_peers_joining_fetch_is_answered_as_its_draft_defines() {
                    common::init_crypto();
                    let cases = joining_cases();
                    let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                    let peer = tokio::spawn(serve_joining(endpoint, cases.clone()));

                    let mut conn = tokio::time::timeout(
                        PATIENCE,
                        AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                    )
                    .await
                    .expect("connect did not finish")
                    .expect("connect");
                    client_joining(&mut conn, &cases).await;

                    let seen = tokio::time::timeout(PATIENCE * 2, peer)
                        .await
                        .expect("the peer hung")
                        .expect("the peer task");
                    assert_eq!(seen.len(), cases.len() + 2);
                    for (n, case) in cases.iter().enumerate() {
                        assert_eq!(
                            seen[n + 1],
                            expected_joining(n, case),
                            "{DRAFT:?} joining case {n}: {case:?}"
                        );
                    }
                    let invalid_joining =
                        FetchRefusal::InvalidJoining.code(DRAFT).expect("assigned");
                    assert_eq!(
                        seen[cases.len() + 1],
                        hex(&err(request_id(cases.len() + 1), invalid_joining)),
                        "{DRAFT:?}: plain recv_inbound refuses an unjoinable FETCH"
                    );
                    drop(conn);
                }
            )?
        }
    };
    (@control $conn:ident) => {{
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut recv = PeerStream::new(recv, DRAFT);
        let (client_setup, _) = recv.read_raw().await.expect("read CLIENT_SETUP");
        send.write_all(&server_setup(&client_setup)).await.expect("write SERVER_SETUP");
        Peer::Control { send, recv }
    }};
    (@streams $conn:ident) => {{
        let mut control = PeerStream::new($conn.accept_uni().await.expect("accept_uni"), DRAFT);
        let (client_setup, _) = control.read_raw().await.expect("read SETUP");
        let mut ours = $conn.open_uni().await.expect("open the peer's control stream");
        ours.write_all(&server_setup(&client_setup)).await.expect("write SETUP");
        // Held for the session's life: dropping it would end the control
        // stream.
        Peer::Streams { held: vec![ours], kept: Vec::new() }
    }};
}

/// The selected version from a CLIENT_SETUP, drafts 11-14.
macro_rules! selected_version {
    ($cs:ident, $version:ident) => {
        match $cs {
            AnyControlMessage::$version(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        }
    };
}

/// A Standalone Fetch on drafts 11-14, with its fields inline.
macro_rules! inline_fetch_with_order {
    ($id:ident, $ask:ident) => {{
        let (sg, so, eg, eo) = $ask.inline();
        Fetch {
            request_id: $id,
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: namespace(),
                track_name: TRACK.to_vec(),
                start_group: v(sg),
                start_object: v(so),
                end_group: v(eg),
                end_object: v(eo),
            },
            parameters: Vec::new(),
        }
    }};
}

/// A Standalone Fetch on drafts 15-19, whose group order is a parameter.
macro_rules! inline_fetch {
    ($id:ident, $ask:ident $(, $extra:ident: $value:expr)*) => {{
        let (sg, so, eg, eo) = $ask.inline();
        Fetch {
            request_id: $id,
            $($extra: $value,)*
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: namespace(),
                track_name: TRACK.to_vec(),
                start_group: v(sg),
                start_object: v(so),
                end_group: v(eg),
                end_object: v(eo),
            },
            parameters: Vec::new(),
        }
    }};
}

/// A FETCH on drafts 20-23, whose range is its LOCATION_FILTER.
macro_rules! filter_fetch {
    ($id:ident, $ask:ident, $module:ident) => {{
        use moqtap_client::$module::fill::LocationFilter;
        let filter = match $ask {
            Ask::Through { start, end } => {
                LocationFilter::range_to(start.0, start.1, end.0 - start.0, end.1)
                    .expect("an absolute range")
            }
            Ask::WholeGroup { start, end_group } => {
                LocationFilter::range(start.0, start.1, end_group - start.0)
                    .expect("an absolute range")
            }
            Ask::Relative(groups) => LocationFilter::relative(groups),
            Ask::NextObject => LocationFilter::next_object(),
        };
        Fetch {
            request_id: $id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: vec![filter.parameter().expect("a LOCATION_FILTER parameter")],
        }
    }};
}

/// A Joining Fetch on drafts 11-19 joining request `$joined`, whose field
/// for it is `$field`.
macro_rules! joining_fetch {
    ($id:ident, $joined:ident, $start:ident, $field:ident $(, $extra:ident: $value:expr)*) => {{
        let (fetch_type, joining_start) = match $start {
            JoiningStart::GroupsBefore(groups) => (FetchType::RelativeJoining, groups),
            JoiningStart::Group(group) => (FetchType::AbsoluteJoining, group),
        };
        Fetch {
            request_id: $id,
            $($extra: $value,)*
            fetch_type,
            fetch_payload: FetchPayload::Joining {
                $field: v($joined),
                joining_start: v(joining_start),
            },
            parameters: Vec::new(),
        }
    }};
}

/// FETCH_OK on drafts 17-22, on the request's own stream.
macro_rules! stream_fetch_ok {
    ($eot:ident, $end:ident) => {
        ControlMessage::FetchOk(FetchOk {
            end_of_track: $eot,
            end_group: v($end.0),
            end_object: v($end.1),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        })
    };
}

/// Drafts 11-14 open with FETCH_HEADER 0x05 and Request ID 1, then state every
/// field of each Object: Group, Subgroup, Object, Priority 0x80, an Extension
/// Headers Length of 0, Payload Length 1, the payload.
const STATED: &str = "05010000008000016100000180000162";

/// Drafts 15-17: Serialization Flags 0x1F and every field stated.
const FLAGGED: &str = "05011f0000008001611f000001800162";

/// Drafts 18-23: the first Object states its Group and Object IDs, and the
/// second, the next Object of the same Group, carries neither: flags 0x13.
const DELTA: &str = "05011f0000008001611300800162";

serve_gate!(
    draft11, "draft11", Draft11, Inclusive, control,
    setup: |cs| ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected_version!(cs, Draft11),
        parameters: Vec::new(),
    }),
    fetch: |id, ask| inline_fetch_with_order!(id, ask),
    ok: |id, eot, end, largest| ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: moqtap_codec::types::GroupOrder::Ascending,
        end_of_track: eot,
        end_location: moqtap_codec::types::Location { group: v(end.0), object: v(end.1) },
        parameters: Vec::new(),
    }),
    err: |id, code| ControlMessage::FetchError(FetchError {
        request_id: id,
        error_code: code,
        reason_phrase: Vec::new(),
    }),
    transcript: STATED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_alias: v(7),
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            forward: moqtap_codec::types::Forward::Forward,
            filter_type: v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(
            id, joined, start, joining_subscribe_id,
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending
        ),
    },
);

serve_gate!(
    draft12, "draft12", Draft12, PlusOne, control,
    setup: |cs| ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected_version!(cs, Draft12),
        parameters: Vec::new(),
    }),
    fetch: |id, ask| inline_fetch_with_order!(id, ask),
    ok: |id, eot, end, largest| ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: moqtap_codec::types::GroupOrder::Ascending,
        end_of_track: eot,
        end_location: moqtap_codec::types::Location { group: v(end.0), object: v(end.1) },
        parameters: Vec::new(),
    }),
    err: |id, code| ControlMessage::FetchError(FetchError {
        request_id: id,
        error_code: code,
        reason_phrase: Vec::new(),
    }),
    transcript: STATED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            forward: moqtap_codec::types::Forward::Forward,
            filter_type: v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(
            id, joined, start, joining_request_id,
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending
        ),
    },
);

serve_gate!(
    draft13, "draft13", Draft13, PlusOne, control,
    setup: |cs| ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected_version!(cs, Draft13),
        parameters: Vec::new(),
    }),
    fetch: |id, ask| inline_fetch_with_order!(id, ask),
    ok: |id, eot, end, largest| ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: moqtap_codec::types::GroupOrder::Ascending,
        end_of_track: eot,
        end_location: moqtap_codec::types::Location { group: v(end.0), object: v(end.1) },
        parameters: Vec::new(),
    }),
    err: |id, code| ControlMessage::FetchError(FetchError {
        request_id: id,
        error_code: code,
        reason_phrase: Vec::new(),
    }),
    transcript: STATED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            forward: moqtap_codec::types::Forward::Forward,
            filter_type: moqtap_codec::types::FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(
            id, joined, start, joining_request_id,
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending
        ),
    },
);

serve_gate!(
    draft14, "draft14", Draft14, PlusOne, control,
    setup: |cs| ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected_version!(cs, Draft14),
        parameters: Vec::new(),
    }),
    fetch: |id, ask| inline_fetch_with_order!(id, ask),
    ok: |id, eot, end, largest| ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: moqtap_codec::types::GroupOrder::Ascending,
        end_of_track: eot,
        end_location: moqtap_codec::types::Location { group: v(end.0), object: v(end.1) },
        parameters: Vec::new(),
    }),
    err: |id, code| ControlMessage::FetchError(FetchError {
        request_id: id,
        error_code: code,
        reason_phrase: Vec::new(),
    }),
    transcript: STATED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            forward: moqtap_codec::types::Forward::Forward,
            filter_type: moqtap_codec::types::FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(
            id, joined, start, joining_request_id,
            subscriber_priority: 128,
            group_order: moqtap_codec::types::GroupOrder::Ascending
        ),
    },
);

serve_gate!(
    draft15, "draft15", Draft15, PlusOne, control,
    setup: |cs| ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }),
    fetch: |id, ask| inline_fetch!(id, ask),
    ok: |id, eot, end, largest| ControlMessage::FetchOk(FetchOk {
        request_id: id,
        end_of_track: eot,
        end_group: v(end.0),
        end_object: v(end.1),
        parameters: Vec::new(),
    }),
    err: |id, code| ControlMessage::RequestError(RequestError {
        request_id: id,
        error_code: code,
        reason_phrase: Vec::new(),
    }),
    transcript: FLAGGED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(id, joined, start, joining_request_id),
    },
);

serve_gate!(
    draft16, "draft16", Draft16, PlusOne, control,
    setup: |cs| ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }),
    fetch: |id, ask| inline_fetch!(id, ask),
    ok: |id, eot, end, largest| ControlMessage::FetchOk(FetchOk {
        request_id: id,
        end_of_track: eot,
        end_group: v(end.0),
        end_object: v(end.1),
        parameters: Vec::new(),
        track_extensions: Vec::new(),
    }),
    err: |id, code| ControlMessage::RequestError(RequestError {
        request_id: id,
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
    }),
    transcript: FLAGGED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(id, joined, start, joining_request_id),
    },
);

serve_gate!(
    draft17, "draft17", Draft17, PlusOne, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| inline_fetch!(id, ask, required_request_id_delta: v(0)),
    ok: |id, eot, end, largest| stream_fetch_ok!(eot, end),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
    }),
    transcript: FLAGGED,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            required_request_id_delta: v(0),
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(
            id, joined, start, joining_request_id, required_request_id_delta: v(0)
        ),
    },
);

serve_gate!(
    draft18, "draft18", Draft18, PlusOne, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| inline_fetch!(id, ask),
    ok: |id, eot, end, largest| stream_fetch_ok!(eot, end),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
        redirect: None,
    }),
    transcript: DELTA,
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(id, joined, start, joining_request_id),
    },
);

serve_gate!(
    draft19, "draft19", Draft19, PlusOne, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| inline_fetch!(id, ask),
    ok: |id, eot, end, largest| stream_fetch_ok!(eot, end),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
        redirect: None,
    }),
    transcript: DELTA,
    extra: [INVALID_FILTER],
    joining: {
        subscribe: |id| Subscribe {
            request_id: id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: Vec::new(),
        },
        fetch: |id, joined, start| joining_fetch!(id, joined, start, joining_request_id),
    },
);

serve_gate!(
    draft20, "draft20", Draft20, Inclusive, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| filter_fetch!(id, ask, draft20),
    ok: |id, eot, end, largest| stream_fetch_ok!(eot, end),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
        redirect: None,
    }),
    transcript: DELTA,
    extra: [END_BEFORE_START, RELATIVE_START, NEXT_OBJECT, INVALID_FILTER],
);

serve_gate!(
    draft21, "draft21", Draft21, Inclusive, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| filter_fetch!(id, ask, draft21),
    ok: |id, eot, end, largest| stream_fetch_ok!(eot, end),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
        redirect: None,
    }),
    transcript: DELTA,
    extra: [END_BEFORE_START, RELATIVE_START, NEXT_OBJECT, INVALID_FILTER],
);

serve_gate!(
    draft22, "draft22", Draft22, Inclusive, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| filter_fetch!(id, ask, draft22),
    ok: |id, eot, end, largest| stream_fetch_ok!(eot, end),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
        redirect: None,
    }),
    transcript: DELTA,
    extra: [END_BEFORE_START, RELATIVE_START, NEXT_OBJECT, INVALID_FILTER],
);

// draft-23 Section 9.19.17: LARGEST_OBJECT (0x09) "is a Location", two
// varints. draft-23 Section 3.2: "If the Location filter is relative (see
// Section 9.19.9), the publisher MUST return REQUEST_ERROR with error code
// INVALID_RANGE."
serve_gate!(
    draft23, "draft23", Draft23, RequestOk, streams,
    setup: |cs| ControlMessage::Setup(Setup { options: vec![granted_budget()] }),
    fetch: |id, ask| filter_fetch!(id, ask, draft23),
    ok: |id, eot, end, largest| ControlMessage::RequestOk(RequestOk {
        parameters: if largest {
            vec![KeyValuePair {
                key: VarInt::from_u64_moqt(0x09),
                value: KvpValue::Bytes(vec![0x01, 0x01]),
            }]
        } else {
            Vec::new()
        },
        track_properties: Vec::new(),
    }),
    err: |id, code| ControlMessage::RequestError(RequestError {
        error_code: code,
        retry_interval: v(0),
        reason_phrase: Vec::new(),
        error_details: Vec::new(),
    }),
    transcript: DELTA,
    extra: [
        END_BEFORE_START,
        Case { ask: Ask::Relative(1), expect: Expect::InvalidRange, stream: false },
        NEXT_OBJECT,
        INVALID_FILTER,
    ],
);

/// Drafts 08-10: plain `recv_inbound` refuses a FETCH with FETCH_ERROR Not
/// Supported. draft-08 Section 4.3: a publisher "MUST send exactly one
/// FETCH_OK or FETCH_ERROR in response to a FETCH".
macro_rules! subscribe_id_refusal_gate {
    ($module:ident, $feat:literal, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;
            use moqtap_codec::$module::message::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn fetch() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Fetch(Fetch {
                    subscribe_id: v(1),
                    subscriber_priority: 128,
                    group_order: moqtap_codec::types::GroupOrder::Ascending,
                    fetch_type: FetchType::Standalone,
                    track_namespace: Some(namespace()),
                    track_name: Some(TRACK.to_vec()),
                    start_group: Some(v(0)),
                    start_object: Some(v(0)),
                    end_group: Some(v(0)),
                    end_object: Some(v(2)),
                    joining_subscribe_id: None,
                    preceding_group_offset: None,
                    parameters: Vec::new(),
                })))
            }

            async fn serve(server: quinn::Endpoint) -> String {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut recv = PeerStream::new(recv, DRAFT);
                let (client_setup, _) = recv.read_raw().await.expect("read CLIENT_SETUP");
                let selected = match client_setup {
                    AnyControlMessage::$version(ControlMessage::ClientSetup(c)) => {
                        c.supported_versions[0]
                    }
                    other => panic!("expected a CLIENT_SETUP, got {other:?}"),
                };
                let setup = ControlMessage::ServerSetup(ServerSetup {
                    selected_version: selected,
                    parameters: Vec::new(),
                });
                send.write_all(&encoded(AnyControlMessage::$version(setup)))
                    .await
                    .expect("write SERVER_SETUP");
                send.write_all(&fetch()).await.expect("write FETCH");
                hex(&recv.read_raw().await.expect("the client's answer").1)
            }

            #[tokio::test]
            async fn plain_recv_inbound_refuses_a_fetch() {
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
                let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound())
                    .await
                    .expect("nothing arrived")
                    .expect("read the FETCH");
                match arrival {
                    AnyArrival::Other(message) => assert_eq!(message.message_type_name(), "fetch"),
                    AnyArrival::Subscribe { .. } => panic!("a FETCH came back as SUBSCRIBE"),
                }
                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                let refusal = ControlMessage::FetchError(FetchError {
                    subscribe_id: v(1),
                    error_code: v(0x3),
                    reason_phrase: Vec::new(),
                });
                assert_eq!(seen, hex(&encoded(AnyControlMessage::$version(refusal))));
                drop(conn);
            }
        }
    };
}

subscribe_id_refusal_gate!(draft08, "draft08", Draft08);
subscribe_id_refusal_gate!(draft09, "draft09", Draft09);
subscribe_id_refusal_gate!(draft10, "draft10", Draft10);

/// The codec's error code table for `$module`, in the order NotSupported,
/// DoesNotExist, InvalidRange, InvalidJoining, InvalidFilter; `-` where the
/// draft assigns none.
macro_rules! codec_codes {
    ($module:ident, $table:ident, $exists:ident, $joining:tt, $filter:tt) => {{
        use moqtap_codec::$module::error_codes::$table as C;
        [
            Some(C::NotSupported as u64),
            Some(C::$exists as u64),
            Some(C::InvalidRange as u64),
            codec_codes!(@C $joining),
            codec_codes!(@C $filter),
        ]
    }};
    (@$c:ident -) => {
        None
    };
    (@$c:ident $code:ident) => {
        Some($c::$code as u64)
    };
}

/// Each draft's codes as the codec's own table for that draft has them:
/// FETCH_ERROR on drafts 08-14 (draft-11 Section 8.15, draft-14 Section 9.18),
/// REQUEST_ERROR on drafts 15-23 (draft-15 Section 9.8,
/// draft-23 Section 16.12.2). `None` for a draft this build leaves out.
fn codec_codes(draft: DraftVersion) -> Option<[Option<u64>; 5]> {
    Some(match draft.number() {
        #[cfg(feature = "draft07")]
        7 => [None; 5],
        #[cfg(feature = "draft08")]
        8 => codec_codes!(draft08, FetchErrorCode, TrackDoesNotExist, -, -),
        #[cfg(feature = "draft09")]
        9 => codec_codes!(draft09, FetchErrorCode, TrackDoesNotExist, -, -),
        #[cfg(feature = "draft10")]
        10 => codec_codes!(draft10, FetchErrorCode, TrackDoesNotExist, -, -),
        #[cfg(feature = "draft11")]
        11 => codec_codes!(
            draft11, FetchErrorCode, TrackDoesNotExist, InvalidJoiningSubscribeId, -
        ),
        #[cfg(feature = "draft12")]
        12 => codec_codes!(draft12, FetchErrorCode, TrackDoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft13")]
        13 => codec_codes!(draft13, FetchErrorCode, TrackDoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft14")]
        14 => codec_codes!(draft14, FetchErrorCode, TrackDoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft15")]
        15 => codec_codes!(draft15, RequestErrorCode, DoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft16")]
        16 => codec_codes!(draft16, RequestErrorCode, DoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft17")]
        17 => codec_codes!(draft17, RequestErrorCode, DoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft18")]
        18 => codec_codes!(draft18, RequestErrorCode, DoesNotExist, InvalidJoiningRequestId, -),
        #[cfg(feature = "draft19")]
        19 => codec_codes!(
            draft19,
            RequestErrorCode,
            DoesNotExist,
            InvalidJoiningRequestId,
            InvalidFilter
        ),
        #[cfg(feature = "draft20")]
        20 => codec_codes!(draft20, RequestErrorCode, DoesNotExist, -, InvalidFilter),
        #[cfg(feature = "draft21")]
        21 => codec_codes!(draft21, RequestErrorCode, DoesNotExist, -, InvalidFilter),
        #[cfg(feature = "draft22")]
        22 => codec_codes!(draft22, RequestErrorCode, DoesNotExist, -, InvalidFilter),
        #[cfg(feature = "draft23")]
        23 => codec_codes!(draft23, RequestErrorCode, DoesNotExist, -, InvalidFilter),
        _ => return None,
    })
}

#[test]
fn every_refusal_carries_its_drafts_code() {
    use FetchRefusal::*;
    for draft in DraftVersion::ALL {
        let Some(table) = codec_codes(draft) else { continue };
        let refusals = [NotSupported, DoesNotExist, InvalidRange, InvalidJoining, InvalidFilter];
        for (refusal, want) in refusals.into_iter().zip(table) {
            assert_eq!(refusal.code(draft), want, "{draft:?} {refusal:?}");
        }
        assert_eq!(Code(0x9).code(draft), Some(0x9), "{draft:?}");
    }
}

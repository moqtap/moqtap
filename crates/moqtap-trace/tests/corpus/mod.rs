//! The shared `.moqtrace` corpus: where it lives, and the cases this crate
//! authors.
//!
//! `@moqtap/trace`'s `src/__tests__/corpus/cases.ts` builds the same cases
//! from the same values. That duplication is the point: the corpus test reads
//! both files and asserts they carry identical content, so a change made on
//! one side and not the other fails rather than drifts. Keep the two in step,
//! and keep the ordering identical — the assertion compares event lists
//! positionally.
//!
//! Values here are fixed rather than generated. A corpus whose bytes change
//! every time it is regenerated cannot be reviewed in a diff, and the whole
//! claim it backs is about bytes.

#![allow(dead_code)] // Each consumer uses a subset: the example writes, the test reads.

use std::path::{Path, PathBuf};

use moqtap_trace::event::{
    DerivationKind, Direction, EventData, PeerRole, Side, StreamType, SubscriptionRef, TraceEvent,
    TRACE_ID_LEN,
};
use moqtap_trace::header::{DetailLevel, Perspective, SegmentInfo, TraceHeader};
use moqtap_trace::Value;

/// 2026-01-01T00:00:00Z.
///
/// Deliberately past 2^32: an encoder that writes a number that large as a
/// float — which cbor-x does by default — hands a decoder that reads only
/// integers a header with no `startTime`. That was a real interop break and is
/// now a normative rule (SPEC.md, Interoperability), so every corpus header
/// exercises it.
pub const START_TIME: u64 = 1_767_225_600_000;

/// 16 bytes, the length the format fixes for a trace id.
pub fn trace_id() -> [u8; TRACE_ID_LEN] {
    let mut id = [0u8; TRACE_ID_LEN];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = i as u8;
    }
    id
}

/// One corpus case: a header and the events under it.
pub struct Case {
    pub header: TraceHeader,
    pub events: Vec<TraceEvent>,
}

/// Events legal in a version-1 file: types 0-7, no `"p"`, no `"segment"`, no
/// `"sampling"`, no `"relay-tap"`. Version 2 added everything else, so this
/// list is exactly what a pre-bump recorder could have written.
fn base_events() -> Vec<TraceEvent> {
    vec![
        TraceEvent::new(
            0,
            0,
            EventData::ControlMessage {
                direction: Direction::Send,
                message_type: 0x40,
                // snake_case, matching the shared codec vectors and the JS
                // codec. Key order matches the JS case so the two encodings
                // differ only where the encoders do.
                message: Value::Map(vec![
                    (Value::Text("request_id".into()), Value::Integer(1.into())),
                    (Value::Text("track_alias".into()), Value::Integer(2.into())),
                ]),
                stream_id: None,
                raw: Some(vec![0x40, 0x02, 0x01, 0x02]),
            },
        ),
        TraceEvent::new(
            1,
            1500,
            EventData::StreamOpened {
                stream_id: 4,
                direction: Direction::Receive,
                stream_type: StreamType::Subgroup,
                track_alias: None,
                subgroup_id: None,
                fetch_request_id: None,
                group_id: None,
            },
        ),
        TraceEvent::new(
            2,
            1600,
            EventData::ObjectHeader {
                stream_id: 4,
                group: 1,
                object: 0,
                publisher_priority: 128,
                object_status: 0,
            },
        ),
        TraceEvent::new(
            3,
            1700,
            EventData::ObjectPayload {
                stream_id: 4,
                group: 1,
                object: 0,
                size: 5,
                payload: Some(b"hello".to_vec()),
            },
        ),
        TraceEvent::new(4, 2000, EventData::StreamClosed { stream_id: 4, error_code: 0 }),
        TraceEvent::new(
            5,
            2100,
            EventData::StateChange { from: "connected".into(), to: "closing".into() },
        ),
        TraceEvent::new(
            6,
            2200,
            EventData::Error { error_code: 0, reason: "stream reset by peer".into() },
        ),
        TraceEvent::new(
            7,
            2300,
            EventData::Annotation { label: "note".into(), data: Value::Text("corpus".into()) },
        ),
    ]
}

/// Events version 2 added: peer lifecycle, subscription derivation.
fn v2_only_events() -> Vec<TraceEvent> {
    vec![
        TraceEvent::for_peer(
            8,
            2400,
            "peer-a",
            EventData::PeerConnected {
                endpoint: Some("127.0.0.1:50000".into()),
                transport: Some("raw-quic".into()),
                role: Some(PeerRole::Subscriber),
                side: Some(Side::Downstream),
            },
        ),
        TraceEvent::for_peer(
            9,
            2500,
            "peer-a",
            EventData::SubscriptionDerivation {
                upstream: SubscriptionRef { peer: "origin".into(), request_id: 1 },
                downstream: vec![
                    SubscriptionRef { peer: "peer-a".into(), request_id: 7 },
                    SubscriptionRef { peer: "peer-b".into(), request_id: 9 },
                ],
                kind: DerivationKind::Created,
                trace_id: Some(trace_id()),
                namespace: Some(vec![b"example".to_vec(), b"live".to_vec()]),
                track_name: Some(b"now".to_vec()),
                t_downstream_received: Some(2400),
                t_upstream_sent: Some(2410),
                t_upstream_ok_received: Some(2480),
                t_downstream_ok_sent: Some(2490),
            },
        ),
        TraceEvent::for_peer(
            10,
            2600,
            "peer-a",
            // Stream and group ids past 2^32, for the same reason START_TIME
            // is: an encoder that demotes them to a float loses the low bits
            // silently.
            EventData::ObjectHeader {
                stream_id: 4_294_967_300,
                group: 4_294_967_296,
                object: 1,
                publisher_priority: 0,
                object_status: 0,
            },
        ),
        TraceEvent::for_peer(
            11,
            2700,
            "peer-a",
            EventData::PeerDisconnected { error_code: 0, reason: Some("bye".into()) },
        ),
    ]
}

fn v1_header() -> TraceHeader {
    let mut header =
        TraceHeader::new("moq-transport-14", Perspective::Client, DetailLevel::Full, START_TIME);
    header.transport = Some("webtransport".into());
    header.source = Some("moqtap-corpus".into());
    header.endpoint = Some("https://relay.example:4443".into());
    header.session_id = Some("v1-basic".into());
    header
}

fn v2_header() -> TraceHeader {
    let mut header =
        TraceHeader::new("moq-transport-16", Perspective::RelayTap, DetailLevel::Full, START_TIME);
    header.end_time = Some(START_TIME + 5000);
    header.transport = Some("raw-quic".into());
    header.source = Some("moqtap-corpus".into());
    header.endpoint = Some("127.0.0.1:4443".into());
    header.session_id = Some("v2-basic".into());
    header
}

/// A version-1 file: only the keys and event types version 1 defined.
pub fn v1_basic() -> Case {
    Case { header: v1_header(), events: base_events() }
}

/// A non-segmented version-2 file, exercising every event type and both
/// normative encoding rules.
///
/// The perspective is `relay-tap`, which is why every version-2 event carries
/// `"p"`: the format requires it there.
pub fn v2_basic() -> Case {
    let mut events = base_events();
    events.extend(v2_only_events());
    Case { header: v2_header(), events }
}

/// Three segments of one stream.
///
/// This is the only thing version 2 exists for: a version-1 reader walking
/// this file decodes the `M` of the second segment's magic as a CBOR byte
/// string and desynchronizes. Sequence numbers and timestamps restart per
/// segment, which is what `"segment"` in the header announces.
pub fn v2_segmented() -> Vec<Case> {
    (0u64..3)
        .map(|sequence| {
            let mut header = TraceHeader::new(
                "moq-transport-16",
                Perspective::Observer,
                DetailLevel::Headers,
                START_TIME + sequence * 1000,
            );
            header.session_id = Some("v2-segmented".into());
            header.segment = Some(SegmentInfo {
                sequence,
                duration_ms: Some(1000),
                stream_id: Some("corpus-stream".into()),
                continues: Some(sequence > 0),
            });
            Case {
                header,
                events: vec![
                    TraceEvent::new(
                        0,
                        100,
                        EventData::ObjectHeader {
                            stream_id: 4,
                            group: sequence,
                            object: 0,
                            publisher_priority: 128,
                            object_status: 0,
                        },
                    ),
                    TraceEvent::new(
                        1,
                        200,
                        EventData::Annotation {
                            label: "segment".into(),
                            data: Value::Integer(sequence.into()),
                        },
                    ),
                ],
            }
        })
        .collect()
}

/// A file carrying an event type no reader knows.
///
/// New event types may be added without a version bump, so a reader must keep
/// this one — fields intact — rather than drop or relabel it. Dropping makes
/// one tool's ignorance permanent for everything downstream of it.
pub fn v2_unknown_event() -> Case {
    let mut header = TraceHeader::new(
        "moq-transport-16",
        Perspective::Observer,
        DetailLevel::Headers,
        START_TIME,
    );
    header.session_id = Some("v2-unknown-event".into());
    Case {
        header,
        events: vec![
            TraceEvent::new(
                0,
                100,
                EventData::StreamOpened {
                    stream_id: 4,
                    direction: Direction::Receive,
                    stream_type: StreamType::Subgroup,
                    track_alias: None,
                    subgroup_id: None,
                    fetch_request_id: None,
                    group_id: None,
                },
            ),
            TraceEvent::new(
                1,
                200,
                EventData::Unknown {
                    event_type: 99,
                    // A text value, an integer and a byte string, so a reader
                    // that keeps only one CBOR shape verbatim is caught.
                    fields: vec![
                        (Value::Text("note".into()), Value::Text("from the future".into())),
                        (Value::Text("count".into()), Value::Integer(3.into())),
                        (Value::Text("blob".into()), Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
                    ],
                },
            ),
            TraceEvent::new(2, 300, EventData::StreamClosed { stream_id: 4, error_code: 0 }),
        ],
    }
}

/// A file whose perspective is not one of the four this revision names.
///
/// New perspectives may be added without a bump, so this must read, keeping
/// the string verbatim. The protocol identifier is the RFC-phase spelling the
/// spec defines, which no draft-number regex matches.
pub fn v2_unknown_perspective() -> Case {
    let mut header = TraceHeader::new(
        "moq-transport-rfc9999",
        Perspective::Other("sidecar".into()),
        DetailLevel::Other("headers+sizes".into()),
        START_TIME,
    );
    header.session_id = Some("v2-unknown-perspective".into());
    Case {
        header,
        events: vec![
            TraceEvent::new(
                0,
                100,
                EventData::StateChange { from: "init".into(), to: "connected".into() },
            ),
            TraceEvent::new(
                1,
                200,
                EventData::Annotation {
                    label: "perspective".into(),
                    data: Value::Text("sidecar".into()),
                },
            ),
        ],
    }
}

/// Known event types carrying keys no reader knows, and no reader ever will.
///
/// Every key here begins `x-`, the prefix SPEC.md reserves for private use and
/// promises never to define. That reservation exists because of this case: it
/// was first built from the keys PROPOSAL-v3 §§1-3 propose, on the reasoning
/// that real proposals make better evidence than invented ones. §2 then landed
/// and claimed two of them. The dedicated assertions went red, which is the
/// mechanism working — but a red test whose *fixture* has gone stale invites
/// weakening the assertion rather than replacing the fixture, and that is what
/// happened before this rebuild. A fixture for a rule about unknown keys has to
/// be built from keys that cannot stop being unknown.
///
/// The failure it guards is quiet: a reader may ignore an unrecognised key, but
/// a reader that *drops* one turns any read-modify-write — a redaction pass, a
/// filter, an annotated download — into a file that looks like it never carried
/// the key at all.
pub fn v2_extra_keys() -> Case {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Observer, DetailLevel::Full, START_TIME);
    header.session_id = Some("v2-extra-keys".into());
    Case {
        header,
        events: vec![
            TraceEvent::new(
                0,
                100,
                EventData::StreamOpened {
                    stream_id: 4,
                    direction: Direction::Receive,
                    stream_type: StreamType::Subgroup,
                    track_alias: None,
                    subgroup_id: None,
                    fetch_request_id: None,
                    group_id: None,
                },
            )
            .with_extra(vec![
                (Value::Text("x-ta".into()), Value::Integer(7.into())),
                (Value::Text("x-sg".into()), Value::Integer(2.into())),
            ]),
            TraceEvent::new(
                1,
                200,
                EventData::ObjectHeader {
                    stream_id: 4,
                    group: 1,
                    object: 0,
                    publisher_priority: 128,
                    object_status: 0,
                },
            )
            .with_extra(vec![
                (Value::Text("x-ta".into()), Value::Integer(7.into())),
                // A nested value, because "the key survives" has to mean the
                // whole tree survives. A shallow copy passes every flat case
                // above and loses this one.
                (
                    Value::Text("x-nested".into()),
                    Value::Map(vec![
                        (Value::Text("blob".into()), Value::Bytes(vec![0x0f, 0xf0])),
                        (
                            Value::Text("inner".into()),
                            Value::Map(vec![(
                                Value::Text("depth".into()),
                                Value::Integer(3.into()),
                            )]),
                        ),
                        (
                            Value::Text("list".into()),
                            Value::Array(vec![Value::Integer(1.into()), Value::Text("two".into())]),
                        ),
                    ]),
                ),
            ]),
            TraceEvent::new(
                2,
                300,
                EventData::Error { error_code: 0, reason: "undecodable control bytes".into() },
            )
            .with_extra(vec![
                (Value::Text("x-ek".into()), Value::Text("decode".into())),
                (Value::Text("x-raw".into()), Value::Bytes(vec![0x99, 0x01])),
            ]),
        ],
    }
}

/// The three shapes a conforming `"msg"` takes.
///
/// `"msg"` is the one event-0 key whose contents no version of the spec fixes,
/// so its rules are about shape rather than content: a CBOR map, keyed in
/// snake_case, and an empty map rather than an omission when the recorder
/// decoded nothing. The empty-map event is the load-bearing one — omitting the
/// key instead was this crate's own cue to discard the event, and event 0 is a
/// type sampling MUST NOT drop.
///
/// The fourth shape, a `"msg"` that is not a map at all, needs no case of its
/// own: all four `capture-*` recordings carry a Rust `Debug` string there, so
/// the corpus already holds real files exercising the tolerance rule.
///
/// Key order matches the JS case, so the two encodings differ only where the
/// encoders do.
pub fn v2_control_msg_map() -> Case {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Full, START_TIME);
    header.session_id = Some("v2-control-msg-map".into());
    Case {
        header,
        events: vec![
            // Three value types in one map — integer, integer, byte string —
            // so an encoder that keeps only one CBOR shape verbatim is caught
            // here rather than in whichever field happened to be tested.
            TraceEvent::new(
                0,
                100,
                EventData::ControlMessage {
                    direction: Direction::Send,
                    message_type: 0x03,
                    message: Value::Map(vec![
                        (Value::Text("request_id".into()), Value::Integer(1.into())),
                        (Value::Text("track_alias".into()), Value::Integer(2.into())),
                        (Value::Text("track_name".into()), Value::Bytes(b"now".to_vec())),
                    ]),
                    stream_id: None,
                    raw: None,
                },
            ),
            // Nothing decoded, so an empty map. A writer that omits the key
            // instead produces a file this reader used to drop the event from.
            TraceEvent::new(
                1,
                200,
                EventData::ControlMessage {
                    direction: Direction::Receive,
                    message_type: 0x2F00,
                    message: Value::Map(Vec::new()),
                    stream_id: None,
                    raw: None,
                },
            ),
            // Nested structure, because "preserve the map" has to mean the
            // whole tree and not just its top level.
            TraceEvent::new(
                2,
                300,
                EventData::ControlMessage {
                    direction: Direction::Send,
                    message_type: 0x16,
                    message: Value::Map(vec![
                        (Value::Text("request_id".into()), Value::Integer(3.into())),
                        (
                            Value::Text("parameters".into()),
                            Value::Map(vec![(
                                Value::Text("location_filter".into()),
                                Value::Array(vec![
                                    Value::Integer(1.into()),
                                    Value::Integer(2.into()),
                                ]),
                            )]),
                        ),
                    ]),
                    stream_id: None,
                    raw: None,
                },
            ),
        ],
    }
}

/// A `headers`-level trace where the stream-header identifiers are the only way
/// to group anything.
///
/// This is what §2 exists for. At `"headers"` there are no payload bytes to
/// re-parse, so before the four keys below a recording could not answer which
/// track a stream belonged to — the level's whole purpose. One stream per type
/// covers all three scopes: `"sg"` on a subgroup, `"fri"` on a fetch, `"g"` on
/// a datagram, and `"ta"` on each.
///
/// The three streams deliberately share a track alias. That is legal and
/// ordinary — one track delivered over a subgroup stream, a fetch and a
/// datagram — and it is why `"ta"` alone cannot key a flow, which is §1's
/// argument sitting in a file rather than in prose.
///
/// Key order matches the JS case, so the two encodings differ only where the
/// encoders do.
pub fn v2_headers_level_flow() -> Case {
    let mut header = TraceHeader::new(
        "moq-transport-19",
        Perspective::Observer,
        DetailLevel::Headers,
        START_TIME,
    );
    header.session_id = Some("v2-headers-level-flow".into());
    Case {
        header,
        events: vec![
            TraceEvent::new(
                0,
                100,
                EventData::StreamOpened {
                    stream_id: 4,
                    direction: Direction::Receive,
                    stream_type: StreamType::Subgroup,
                    track_alias: Some(9),
                    subgroup_id: Some(2),
                    fetch_request_id: None,
                    group_id: None,
                },
            ),
            TraceEvent::new(
                1,
                150,
                EventData::ObjectHeader {
                    stream_id: 4,
                    group: 7,
                    object: 0,
                    publisher_priority: 128,
                    object_status: 0,
                },
            ),
            // `"fri"` is the only correlation between a fetch stream and the
            // FETCH that asked for it, which is why it is the one key a writer
            // MUST emit.
            TraceEvent::new(
                2,
                200,
                EventData::StreamOpened {
                    stream_id: 8,
                    direction: Direction::Receive,
                    stream_type: StreamType::Fetch,
                    track_alias: Some(9),
                    subgroup_id: None,
                    fetch_request_id: Some(42),
                    group_id: None,
                },
            ),
            // A datagram carries its group on the stream-opened event, because
            // there is no subgroup stream to hang it off. Note that `"sid"`
            // here names a stream a datagram never opened — §1's subject,
            // visible in this file.
            TraceEvent::new(
                3,
                300,
                EventData::StreamOpened {
                    stream_id: 12,
                    direction: Direction::Receive,
                    stream_type: StreamType::Datagram,
                    track_alias: Some(9),
                    subgroup_id: None,
                    fetch_request_id: None,
                    group_id: Some(4_294_967_296),
                },
            ),
        ],
    }
}

/// Every single-segment case both implementations author, by directory name.
pub fn authored_cases() -> Vec<(&'static str, Case)> {
    vec![
        ("v1-basic", v1_basic()),
        ("v2-basic", v2_basic()),
        ("v2-unknown-event", v2_unknown_event()),
        ("v2-unknown-perspective", v2_unknown_perspective()),
        ("v2-extra-keys", v2_extra_keys()),
        ("v2-control-msg-map", v2_control_msg_map()),
        ("v2-headers-level-flow", v2_headers_level_flow()),
    ]
}

/// Where the shared corpus lives.
///
/// It is `trace/` inside the `test-vectors` repository — the same one the
/// codec vectors come from — because the claim it backs is a cross-language
/// one: this crate reads it as a git submodule, `@moqtap/trace` reads it as a
/// dependency. One copy, two readers; a corpus each implementation kept its
/// own copy of would drift, and drift is the failure it exists to catch.
///
/// Two locations are tried, because the submodule sits under `moqtap-codec`
/// rather than at the workspace root, and a checkout of this repo alone does
/// not have the sibling clone that corpus development uses.
pub fn corpus_dir() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

    let submodule = manifest.join("../moqtap-codec/test-vectors/trace");
    if submodule.is_dir() {
        return Some(submodule);
    }

    // Bounded rather than unbounded: a search that walks to the filesystem
    // root on a machine that happens to have `test-vectors` somewhere above
    // the repo would read a corpus nobody meant to point it at.
    let mut dir = manifest;
    for _ in 0..8 {
        let candidate = dir.join("test-vectors/trace");
        if candidate.is_dir() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
    None
}

/// What to tell someone whose checkout has no corpus.
pub const CORPUS_MISSING_MESSAGE: &str = "No .moqtrace corpus found. It lives in the test-vectors \
     repository under trace/; run `git submodule update --init`, or clone \
     github.com/moqtap/test-vectors beside this repository.";

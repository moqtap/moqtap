#![cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
))]

//! `AnyConnection::recv_inbound` hands back a SUBSCRIBE the peer sent, and
//! `AnyConnection::accept_subscribe` answers it the way its draft answers one.
//!
//! This is the direction the facade did not have. Everything else on
//! `AnyConnection` asks a question and reads the answer; a relay that accepted
//! a namespace from `publish_namespace` sends a SUBSCRIBE *down* the connection
//! when somebody asks for a track under it, and that message answers nothing
//! this side asked for. Without a handle for it there is no round trip to
//! measure — a relay's routing table can only be observed from the publisher's
//! end.
//!
//! # Two waits, one question
//!
//! Drafts 11 through 16 carry the peer's requests on the shared control stream,
//! so `recv_inbound` reads that stream and every message arrives through it,
//! tagged. From draft-17 each request owns a bidirectional stream, so the same
//! call waits on a *new stream* and only the peer's own requests arrive. Both
//! gates below assert which of the two happened, through
//! [`AnyInboundRequest::stream_id`] — `None` on the control-stream drafts and
//! `Some` from draft-17, the one observable difference between the handles.
//!
//! # The Request ID is the peer's
//!
//! Section 9.1 splits the number space by parity: the client's IDs are even and
//! the server's odd. The peer here is the server, so its SUBSCRIBE carries `1`,
//! and a facade that reported an ID from *this* side's sequence would hand back
//! an even number that names a request the peer never made. Every gate asserts
//! the handle carries `1`, and the drafts that echo an ID in SUBSCRIBE_OK are
//! asserted to echo that one.
//!
//! # Where the Track Alias goes, and where it does not
//!
//! Drafts 11 and earlier put the alias on SUBSCRIBE and make it the
//! subscriber's, so their SUBSCRIBE_OK has no such field: the draft-11 gate
//! asserts the answer carries **no** `track_alias`, and that the value the
//! subscriber chose is on the message that arrived. Draft-12 moved the choice
//! to the publisher, and from there every gate asserts the answer carries the
//! alias this side passed in. That split is why `accept_subscribe` takes the
//! alias as an argument where `subscribe` reads it off the endpoint — see its
//! docs for why that is not an inconsistency.
//!
//! # A message that is not a request is still returned
//!
//! The control-stream gates end by having the peer send a GOAWAY, which is not
//! a request and has no handle. It must come back as [`AnyArrival::Other`]
//! rather than being skipped: on those drafts the same stream carries the
//! peer's requests and the answers to this side's own, so a `recv_inbound` that
//! silently dropped what it was not looking for would swallow a SUBSCRIBE_OK
//! somebody was waiting on.
//!
//! # Ablations, measured
//!
//! Two cuts, each run and reverted.
//!
//! * `accept_subscribe` made to answer with a constant alias instead of the one
//!   it was given. **Nine gates redden and draft-11 stays green** — which is
//!   the two-sided claim this file is for: the alias reaches the wire on drafts
//!   12 through 20, and draft-11 really does ignore the argument rather than
//!   happening to be asserted loosely.
//! * `recv_inbound`'s control-stream arm made to tag nothing, so every message
//!   comes back as [`AnyArrival::Other`]. The six control-stream gates redden
//!   on "a SUBSCRIBE came back untagged" and the four request-stream gates stay
//!   green, which is the two halves of that method being separately load
//!   bearing.
//!
//! # Why drafts 07 through 10 are absent, and why the arms for them stay
//!
//! Not because the facade cannot answer them — it can, and
//! `accept_subscribe` has an arm for each. Because a peer cannot *ask*. A
//! request is legal only below the ceiling its recipient granted, and those
//! four drafts grant it with the MAX_SUBSCRIBE_ID **message** (type 0x15) where
//! drafts 11 and later carry `max_request_id` as Setup Parameter `0x02`. This
//! crate's `Connection` has no entry point for sending that message, so a
//! peer's SUBSCRIBE on drafts 07 through 10 is refused for exceeding a ceiling
//! of zero before any of this is reached.
//!
//! That is a gap in *granting a budget*, not in answering a request, and the
//! arms here become reachable the day it is closed without being touched. No
//! relay in the fleet speaks below draft-11, so it costs nothing today.

mod common;

use std::time::Duration;

use common::render;
use moqtap_client::dispatch::{AnyArrival, AnyClientConfig, AnyConnection, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::fields::FieldValue;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The Request ID the peer's SUBSCRIBE carries.
///
/// Odd, because Section 9.1 gives the server the odd half of the number space.
/// An even one here would be refused by this side's own parity check before any
/// of the behaviour under test ran.
const PEER_REQUEST_ID: u64 = 1;

/// The alias this side answers with, on the drafts where that is its choice.
const OUR_ALIAS: u64 = 7;

/// The alias the *subscriber* chooses on draft-11, where the field is on
/// SUBSCRIBE rather than on the answer. Different from [`OUR_ALIAS`] so that a
/// gate cannot pass by reading the wrong one.
///
/// Draft-11 is the only draft that puts the alias there, so this has exactly
/// one reader — the `control_stream_gate!` invocation below — and it sits
/// inside a module the same feature gates. A `cfg` rather than an `allow`
/// because the condition is that one feature and it cannot drift from a single
/// use site; without it every matrix row but draft-11's carries an unread
/// constant and fails under `RUSTFLAGS="-D warnings"`.
#[cfg(feature = "draft11")]
const THEIR_ALIAS: u64 = 4;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("fixture value fits a varint")
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

const TRACK: &[u8] = b"video";

/// `max_request_id`, Setup Parameter `0x02` on every draft here.
///
/// Sent by *this* side, which is what makes the peer's SUBSCRIBE legal: a
/// request is bounded by the ceiling its recipient granted, and a ceiling
/// nobody granted is zero, which forbids every request.
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

/// One field of a decoded message, as a string a failure can be read from.
fn field_text(value: &FieldValue) -> String {
    match value {
        FieldValue::Uint(n) => n.to_string(),
        FieldValue::Bool(b) => b.to_string(),
        FieldValue::Text(s) => s.clone(),
        FieldValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        FieldValue::Array(items) => items.iter().map(field_text).collect::<Vec<_>>().join("/"),
        FieldValue::Map(_) => format!("{value:?}"),
    }
}

/// Render a decoded message: its name, its type number, and whichever of the
/// two fields this file asserts on it carries.
///
/// A field a draft does not have is rendered as absent rather than as empty,
/// which is the whole of the draft-11 claim: its SUBSCRIBE_OK has no
/// `track_alias`, and a rendering that printed one as `0` would make "the field
/// is not there" and "the field arrived zero" the same string.
fn describe(message: &AnyControlMessage) -> String {
    let fields = message.fields();
    let mut rendered = Vec::new();
    for name in ["request_id", "track_alias"] {
        if let Some(value) = fields.get(name) {
            rendered.push((name, field_text(value)));
        }
    }
    render(message.message_type_name(), message.message_type_id(), &rendered)
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
    msg.encode(&mut out).expect("encode a control message");
    out
}

/// One gate on a draft that carries every request on the bidirectional control
/// stream: drafts 11 through 16.
///
/// `$setup` builds the peer's SERVER_SETUP from the CLIENT_SETUP it read;
/// `$subscribe` is the SUBSCRIBE it then sends, whose shape moved in almost
/// every draft in this range; `$goaway` is the message that must come back as
/// [`AnyArrival::Other`]; and `$answer` is what the SUBSCRIBE_OK must render as.
macro_rules! control_stream_gate {
    (
        $mod_name:ident,
        $feat:literal,
        $version:ident,
        |$cs:ident| $setup:expr,
        $subscribe:expr,
        $answer:expr
    ) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn server_setup_bytes($cs: &AnyControlMessage) -> Vec<u8> {
                encoded($setup)
            }

            fn subscribe_bytes() -> Vec<u8> {
                use moqtap_codec::$mod_name::message::ControlMessage;
                encoded(AnyControlMessage::$version(ControlMessage::Subscribe($subscribe)))
            }

            fn goaway_bytes() -> Vec<u8> {
                use moqtap_codec::$mod_name::message::{ControlMessage, GoAway};
                encoded(AnyControlMessage::$version(ControlMessage::GoAway(GoAway {
                    new_session_uri: Vec::new(),
                })))
            }

            /// Complete the handshake, subscribe, read the answer, then send a
            /// message that is not a request at all.
            async fn serve(server: quinn::Endpoint) -> String {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = PeerStream::new(recv, DRAFT);
                let client_setup =
                    control.read_control().await.expect("read the client's CLIENT_SETUP");
                send.write_all(&server_setup_bytes(&client_setup))
                    .await
                    .expect("write SERVER_SETUP");

                send.write_all(&subscribe_bytes()).await.expect("write SUBSCRIBE");
                let answer = control.read_control().await.expect("read the client's answer");
                send.write_all(&goaway_bytes()).await.expect("write GOAWAY");
                // Held open until the client has gone. Returning here would
                // drop the connection, and the GOAWAY just written would be
                // torn down with it before the client could read it — the
                // failure looks like "the peer closed" and is really "the peer
                // finished first".
                conn.closed().await;
                describe(&answer)
            }

            #[tokio::test]
            async fn a_peers_subscribe_arrives_with_its_own_id_and_is_answered() {
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
                    .expect("read what the peer sent");
                let (message, mut request) = match arrival {
                    AnyArrival::Subscribe { message, request } => (message, request),
                    AnyArrival::Other(other) => {
                        panic!("a SUBSCRIBE came back untagged: {}", describe(&other))
                    }
                };
                assert_eq!(
                    message.message_type_name(),
                    "subscribe",
                    "the tagged message is the one that arrived"
                );
                assert_eq!(
                    request.request_id().into_inner(),
                    PEER_REQUEST_ID,
                    "{DRAFT:?} must report the id the peer allocated, not one of ours"
                );
                assert_eq!(
                    request.stream_id(),
                    None,
                    "{DRAFT:?} carries inbound requests on the shared control stream"
                );

                tokio::time::timeout(PATIENCE, conn.accept_subscribe(&mut request, v(OUR_ALIAS)))
                    .await
                    .expect("the answer did not finish")
                    .expect("answer the peer's SUBSCRIBE");

                // The GOAWAY the peer sends afterwards is not a request and has
                // no handle, and must still be handed back rather than skipped.
                let after = tokio::time::timeout(PATIENCE, conn.recv_inbound())
                    .await
                    .expect("the GOAWAY never arrived")
                    .expect("read the GOAWAY");
                match after {
                    AnyArrival::Other(message) => assert_eq!(
                        message.message_type_name(),
                        "goaway",
                        "a message with no handle comes back whole"
                    ),
                    AnyArrival::Subscribe { message, .. } => {
                        panic!("a GOAWAY was tagged as a request: {}", describe(&message))
                    }
                }

                // Releases the peer, which is holding its connection open until
                // this side is done reading.
                conn.close(0, b"gate complete");

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(seen, $answer, "{DRAFT:?} answers a SUBSCRIBE this way");
            }
        }
    };
}

control_stream_gate!(
    draft11,
    "draft11",
    Draft11,
    |cs| {
        use moqtap_codec::draft11::message::{ControlMessage, ServerSetup};
        let selected = match cs {
            AnyControlMessage::Draft11(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::Draft11(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: Vec::new(),
        }))
    },
    moqtap_codec::draft11::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        // The subscriber's, on this draft. The answer must not echo it and
        // must not carry one of its own.
        track_alias: v(THEIR_ALIAS),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        subscriber_priority: 128,
        group_order: moqtap_codec::types::GroupOrder::Ascending,
        forward: moqtap_codec::types::Forward::Forward,
        // Draft-11 carries the Filter Type as a bare varint; `LargestObject`
        // is 0x2 on every draft that names it.
        filter_type: v(0x2),
        start_group: None,
        start_object: None,
        end_group: None,
        parameters: Vec::new(),
    },
    // No `track_alias`: the field does not exist on this draft's answer.
    render("subscribe_ok", 0x04, &[("request_id", PEER_REQUEST_ID.to_string())])
);

control_stream_gate!(
    draft12,
    "draft12",
    Draft12,
    |cs| {
        use moqtap_codec::draft12::message::{ControlMessage, ServerSetup};
        let selected = match cs {
            AnyControlMessage::Draft12(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::Draft12(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: Vec::new(),
        }))
    },
    moqtap_codec::draft12::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
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
    // Draft-12 is where the alias moves onto the answer and becomes ours.
    render(
        "subscribe_ok",
        0x04,
        &[("request_id", PEER_REQUEST_ID.to_string()), ("track_alias", OUR_ALIAS.to_string()),]
    )
);

control_stream_gate!(
    draft13,
    "draft13",
    Draft13,
    |cs| {
        use moqtap_codec::draft13::message::{ControlMessage, ServerSetup};
        let selected = match cs {
            AnyControlMessage::Draft13(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::Draft13(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: Vec::new(),
        }))
    },
    moqtap_codec::draft13::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
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
    render(
        "subscribe_ok",
        0x04,
        &[("request_id", PEER_REQUEST_ID.to_string()), ("track_alias", OUR_ALIAS.to_string()),]
    )
);

control_stream_gate!(
    draft14,
    "draft14",
    Draft14,
    |cs| {
        use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
        let selected = match cs {
            AnyControlMessage::Draft14(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: Vec::new(),
        }))
    },
    moqtap_codec::draft14::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
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
    render(
        "subscribe_ok",
        0x04,
        &[("request_id", PEER_REQUEST_ID.to_string()), ("track_alias", OUR_ALIAS.to_string()),]
    )
);

control_stream_gate!(
    draft15,
    "draft15",
    Draft15,
    |cs| {
        use moqtap_codec::draft15::message::{ControlMessage, ServerSetup};
        let _ = cs;
        AnyControlMessage::Draft15(ControlMessage::ServerSetup(ServerSetup {
            parameters: Vec::new(),
        }))
    },
    // Draft-15 moved priority, order, forwarding and the filter into the
    // parameter block, which is why this literal is four fields where
    // draft-14's is ten.
    moqtap_codec::draft15::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    },
    render(
        "subscribe_ok",
        0x04,
        &[("request_id", PEER_REQUEST_ID.to_string()), ("track_alias", OUR_ALIAS.to_string()),]
    )
);

control_stream_gate!(
    draft16,
    "draft16",
    Draft16,
    |cs| {
        use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
        let _ = cs;
        AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup {
            parameters: Vec::new(),
        }))
    },
    moqtap_codec::draft16::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    },
    render(
        "subscribe_ok",
        0x04,
        &[("request_id", PEER_REQUEST_ID.to_string()), ("track_alias", OUR_ALIAS.to_string()),]
    )
);

/// One gate on a draft whose every request owns a bidirectional stream of its
/// own: drafts 17 through 20.
///
/// The peer opens the stream this time, which is the half of the transport this
/// facade had no reader for. The answer comes back on that same stream and
/// carries **no Request ID** — the stream is the correlation — so the render
/// asserted here is one field where the control-stream gates assert two.
macro_rules! request_stream_gate {
    ($mod_name:ident, $feat:literal, $version:ident, $subscribe:expr) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::$mod_name::message::{ControlMessage, Setup};

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn setup_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
                    options: vec![granted_budget()],
                })))
            }

            fn subscribe_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Subscribe($subscribe)))
            }

            /// Complete the handshake, open a request stream, subscribe on it,
            /// and read the answer off the same stream.
            async fn serve(server: quinn::Endpoint) -> String {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let (mut send, recv) = conn.open_bi().await.expect("open a request stream");
                send.write_all(&subscribe_bytes()).await.expect("write SUBSCRIBE");
                let mut request = PeerStream::new(recv, DRAFT);
                describe(&request.read_control().await.expect("read the client's answer"))
            }

            #[tokio::test]
            async fn a_peers_subscribe_arrives_on_its_own_stream_and_is_answered_there() {
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
                    .expect("accept the peer's request stream");
                let (message, mut request) = match arrival {
                    AnyArrival::Subscribe { message, request } => (message, request),
                    AnyArrival::Other(other) => {
                        panic!("a SUBSCRIBE came back untagged: {}", describe(&other))
                    }
                };
                assert_eq!(message.message_type_name(), "subscribe");
                assert_eq!(
                    request.request_id().into_inner(),
                    PEER_REQUEST_ID,
                    "{DRAFT:?} must report the id the peer allocated, not one of ours"
                );
                assert!(
                    request.stream_id().is_some(),
                    "{DRAFT:?} gives every request a stream of its own"
                );

                tokio::time::timeout(PATIENCE, conn.accept_subscribe(&mut request, v(OUR_ALIAS)))
                    .await
                    .expect("the answer did not finish")
                    .expect("answer the peer's SUBSCRIBE");

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    seen,
                    render("subscribe_ok", 0x04, &[("track_alias", OUR_ALIAS.to_string())]),
                    "{DRAFT:?} answers on the request's own stream, with no Request ID"
                );
            }
        }
    };
}

request_stream_gate!(
    draft17,
    "draft17",
    Draft17,
    moqtap_codec::draft17::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        // Draft-17 alone carries this field, and draft-18 deleted it again.
        required_request_id_delta: v(0),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

request_stream_gate!(
    draft18,
    "draft18",
    Draft18,
    moqtap_codec::draft18::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

request_stream_gate!(
    draft19,
    "draft19",
    Draft19,
    moqtap_codec::draft19::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

request_stream_gate!(
    draft20,
    "draft20",
    Draft20,
    moqtap_codec::draft20::message::Subscribe {
        request_id: v(PEER_REQUEST_ID),
        track_namespace: namespace(),
        track_name: TRACK.to_vec(),
        parameters: Vec::new(),
    }
);

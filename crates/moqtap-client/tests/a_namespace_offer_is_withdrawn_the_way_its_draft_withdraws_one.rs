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

//! `AnyConnection::publish_namespace` offers a namespace on every draft that
//! numbers the request, and `AnyConnection::publish_namespace_done` withdraws
//! it by whatever each draft keys a withdrawal on.
//!
//! # The type number never moved and everything else did
//!
//! The offer is message type `0x06` on all fourteen drafts and the withdrawal
//! is `0x09` on every draft that has one. Nothing else about the pair held
//! still:
//!
//! * **The name.** Drafts 07 through 13 call them ANNOUNCE and UNANNOUNCE;
//!   draft-14 renamed them PUBLISH_NAMESPACE and PUBLISH_NAMESPACE_DONE.
//! * **The acceptance.** Drafts 11 through 13 answer ANNOUNCE_OK and draft-14
//!   PUBLISH_NAMESPACE_OK; draft-15 replaced every per-request acceptance with
//!   one REQUEST_OK, which is why the peer below writes a different message on
//!   either side of that line to say the same thing.
//! * **What the withdrawal names.** Drafts 11 through 15 carry the namespace
//!   itself. **Draft-16 carries the Request ID instead** — the codec's own
//!   comment on the struct reads "Draft-16: just request_id (was namespace in
//!   d15)". Drafts 17 through 20 carry neither, because they have no such
//!   message at all: an announcement lives exactly as long as its bidirectional
//!   stream.
//!
//! A facade taking only the namespace would be wrong on draft-16 and one taking
//! only the handle would be wrong on the five drafts before it, so
//! [`AnyConnection::publish_namespace_done`] takes both and each draft spends
//! the one it needs. This file is what holds it to spending the right one.
//!
//! # Why two announcements and not one
//!
//! Because with one outstanding announcement, three different wrong
//! implementations of the draft-16 arm all pass: writing a constant `0`,
//! writing the connection's most recently allocated Request ID, and writing the
//! one the handle carries are the same number. So each gate announces two
//! namespaces, lets the peer accept both, and then withdraws them **in the
//! order they were made**. The first withdrawal kills the
//! most-recently-allocated reading and the second kills the constant, and
//! neither is visible with a single announcement in flight.
//!
//! The same pair also holds the drafts that key on the namespace: a withdrawal
//! naming the wrong one of two is a well-formed message that ends an
//! announcement the caller did not ask to end.
//!
//! # What the peer does
//!
//! Reads every control message the client writes, decodes it with the codec,
//! and renders it through [`common::render`] from the *draft's own* field
//! table — the message's name, its type number, and whichever of `request_id`
//! and `track_namespace` it carries. The gate renders what it asked for the
//! same way, from literals naming the draft. The two agree only if the facade
//! reached the right per-draft helper with the right key.
//!
//! Rendering from [`AnyControlMessage::fields`] rather than from a per-draft
//! `match` is what keeps the peer one function across six drafts whose message
//! *types* have six different names for the same two messages. The names
//! themselves are still pinned, because they arrive at the assertion from the
//! literals at each invocation.
//!
//! # Ablations, measured
//!
//! Two cuts, each run and reverted, each on the gate it reddens.
//!
//! * Draft-16's arm made to withdraw `request_id = 0` rather than the one the
//!   handle carries. The first withdrawal still passes — the first
//!   announcement's ID *is* zero — and the second fails inside the endpoint
//!   rather than at the assertion: "invalid transition from Done on event
//!   on_publish_namespace_done", because the constant had already ended the
//!   announcement it named. Which is the two-announcement design paying for
//!   itself; with one in flight the cut is invisible.
//! * The drafts 17 through 20 arm made to return `Ok(())` instead of refusing.
//!   All four request-stream gates redden, on the `expect_err`.
//!
//! # Drafts 07 through 10 are absent, and not for want of a gate
//!
//! Their ANNOUNCE carries no Request ID — the answer is matched by namespace —
//! so `Connection::announce` returns `()` there and the facade has no handle to
//! hand back. That is the same wall
//! [`AnyConnection::track_status`](moqtap_client::dispatch::AnyConnection::track_status)
//! stops at on those four drafts, for the same reason, and it is a fact about
//! the protocol rather than about how far this facade has been wired.

mod common;

use std::time::Duration;

use common::render;
use moqtap_client::dispatch::{AnyClientConfig, AnyConnection, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::fields::FieldValue;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The two namespaces every gate offers, in the order it offers them.
fn namespaces() -> [TrackNamespace; 2] {
    [
        TrackNamespace(vec![b"conformance".to_vec(), b"alpha".to_vec()]),
        TrackNamespace(vec![b"conformance".to_vec(), b"beta".to_vec()]),
    ]
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

/// One field of a decoded message, as a string a failure can be read from.
///
/// A namespace arrives as an [`FieldValue::Array`] of its tuple fields, and is
/// joined with slashes so that a message naming one field of the right
/// namespace does not render the same as one naming all of it — the same rule
/// [`common::namespace_text`] follows for the other end of the assertion.
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
/// two keys it carries.
///
/// Both keys where a message has both — every offer here does — because the
/// Request ID on the offer is the one the returned handle must be carrying, and
/// asserting it beside the namespace costs nothing.
fn describe(message: &AnyControlMessage) -> String {
    let fields = message.fields();
    let mut rendered = Vec::new();
    if let Some(id) = fields.get("request_id") {
        rendered.push(("request_id", field_text(id)));
    }
    if let Some(ns) = fields.get("track_namespace") {
        rendered.push(("namespace", field_text(ns)));
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
/// `$setup` builds the peer's SERVER_SETUP from the CLIENT_SETUP it read —
/// drafts 11 through 14 echo a selected version and drafts 15 and 16 have no
/// such field — and all six need a MAX_REQUEST_ID, without which the client has
/// no budget to allocate a Request ID from and the first offer never goes out.
///
/// `$accept` builds this draft's acceptance for a Request ID, which is
/// ANNOUNCE_OK, PUBLISH_NAMESPACE_OK or REQUEST_OK depending on where the draft
/// falls relative to the two renames. The announcement has to reach Active
/// before it can be withdrawn — `NamespaceStateMachine::on_unannounce` refuses
/// every other state — so this is not scene-setting: without it the withdrawal
/// is refused inside the endpoint and never reaches the wire for the peer to
/// read.
///
/// `$offer` and `$done` are what this draft calls the two messages, and
/// `$done_key` is which of the two keys its withdrawal carries.
macro_rules! control_stream_gate {
    (
        $mod_name:ident,
        $feat:literal,
        $version:ident,
        |$cs:ident| $setup:expr,
        |$id:ident| $accept:expr,
        $offer:literal,
        $done:literal,
        $done_key:literal
    ) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::varint::VarInt;

            const DRAFT: DraftVersion = DraftVersion::$version;

            /// MAX_REQUEST_ID, Setup Parameter 0x02 on all six drafts.
            fn budget() -> KeyValuePair {
                KeyValuePair {
                    key: VarInt::from_u64(0x02).unwrap(),
                    value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
                }
            }

            fn server_setup_bytes($cs: &AnyControlMessage) -> Vec<u8> {
                encoded($setup)
            }

            fn accept_bytes($id: VarInt) -> Vec<u8> {
                encoded($accept)
            }

            /// Complete the handshake, accept two announcements, then report all
            /// four messages the client wrote in the order it wrote them.
            async fn serve(server: quinn::Endpoint) -> Vec<String> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = PeerStream::new(recv, DRAFT);
                let client_setup =
                    control.read_control().await.expect("read the client's CLIENT_SETUP");
                send.write_all(&server_setup_bytes(&client_setup))
                    .await
                    .expect("write SERVER_SETUP");

                let mut seen = Vec::new();

                // The two offers, each accepted before the next goes out. The
                // Request ID answered is the one that arrived, so an acceptance
                // can never be the reason a withdrawal names the wrong request.
                for _ in 0..2 {
                    let offer = control.read_control().await.expect("read an offer");
                    let id = match offer.fields().get("request_id") {
                        Some(FieldValue::Uint(id)) => {
                            VarInt::from_u64(*id).expect("a Request ID the client allocated")
                        }
                        other => panic!("an offer with no Request ID: {other:?}"),
                    };
                    seen.push(describe(&offer));
                    send.write_all(&accept_bytes(id)).await.expect("write the acceptance");
                }

                // The two withdrawals, which need no answer.
                for _ in 0..2 {
                    seen.push(describe(&control.read_control().await.expect("read a withdrawal")));
                }
                seen
            }

            #[tokio::test]
            async fn a_withdrawal_names_what_this_draft_keys_one_on() {
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

                // Offer both, reading each acceptance before the next offer.
                // `recv_response` dispatches it, which is what moves the
                // announcement into the state a withdrawal is sent from.
                let mut handles = Vec::new();
                for namespace in namespaces() {
                    let mut handle =
                        tokio::time::timeout(PATIENCE, conn.publish_namespace(namespace))
                            .await
                            .expect("the offer did not finish")
                            .expect("offer the namespace");
                    tokio::time::timeout(PATIENCE, conn.recv_response(&mut handle))
                        .await
                        .expect("the acceptance did not arrive")
                        .expect("read the acceptance");
                    handles.push(handle);
                }

                // Withdrawn in the order they were offered. See the module docs
                // for why the order is the assertion and not an incidental.
                for (handle, namespace) in handles.iter().zip(namespaces()) {
                    tokio::time::timeout(PATIENCE, conn.publish_namespace_done(handle, namespace))
                        .await
                        .expect("the withdrawal did not finish")
                        .expect("withdraw the namespace");
                }

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");

                let ids: Vec<String> =
                    handles.iter().map(|h| h.request_id().into_inner().to_string()).collect();
                let names = ["conformance/alpha", "conformance/beta"];
                let mut want = Vec::new();
                for (id, name) in ids.iter().zip(names) {
                    want.push(render(
                        $offer,
                        0x06,
                        &[("request_id", id.clone()), ("namespace", name.to_string())],
                    ));
                }
                for (id, name) in ids.iter().zip(names) {
                    let value = match $done_key {
                        "request_id" => id.clone(),
                        _ => name.to_string(),
                    };
                    want.push(render($done, 0x09, &[($done_key, value)]));
                }

                assert_eq!(
                    seen, want,
                    "{DRAFT:?} offers {} and withdraws by {}",
                    $offer, $done_key
                );
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
            parameters: vec![budget()],
        }))
    },
    |id| {
        use moqtap_codec::draft11::message::{AnnounceOk, ControlMessage};
        AnyControlMessage::Draft11(ControlMessage::AnnounceOk(AnnounceOk { request_id: id }))
    },
    "announce",
    "unannounce",
    "namespace"
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
            parameters: vec![budget()],
        }))
    },
    |id| {
        use moqtap_codec::draft12::message::{AnnounceOk, ControlMessage};
        AnyControlMessage::Draft12(ControlMessage::AnnounceOk(AnnounceOk { request_id: id }))
    },
    "announce",
    "unannounce",
    "namespace"
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
            parameters: vec![budget()],
        }))
    },
    |id| {
        use moqtap_codec::draft13::message::{AnnounceOk, ControlMessage};
        AnyControlMessage::Draft13(ControlMessage::AnnounceOk(AnnounceOk { request_id: id }))
    },
    "announce",
    "unannounce",
    "namespace"
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
            parameters: vec![budget()],
        }))
    },
    |id| {
        use moqtap_codec::draft14::message::{ControlMessage, PublishNamespaceOk};
        AnyControlMessage::Draft14(ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
            request_id: id,
        }))
    },
    "publish_namespace",
    "publish_namespace_done",
    "namespace"
);

control_stream_gate!(
    draft15,
    "draft15",
    Draft15,
    |cs| {
        use moqtap_codec::draft15::message::{ControlMessage, ServerSetup};
        let _ = cs;
        AnyControlMessage::Draft15(ControlMessage::ServerSetup(ServerSetup {
            parameters: vec![budget()],
        }))
    },
    |id| {
        use moqtap_codec::draft15::message::{ControlMessage, RequestOk};
        AnyControlMessage::Draft15(ControlMessage::RequestOk(RequestOk {
            request_id: id,
            parameters: Vec::new(),
        }))
    },
    "publish_namespace",
    "publish_namespace_done",
    "namespace"
);

control_stream_gate!(
    draft16,
    "draft16",
    Draft16,
    |cs| {
        use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
        let _ = cs;
        AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup {
            parameters: vec![budget()],
        }))
    },
    |id| {
        use moqtap_codec::draft16::message::{ControlMessage, RequestOk};
        AnyControlMessage::Draft16(ControlMessage::RequestOk(RequestOk {
            request_id: id,
            parameters: Vec::new(),
        }))
    },
    "publish_namespace",
    "publish_namespace_done",
    // The swap this file exists for: draft-16 keys the withdrawal on the
    // Request ID where draft-15 keyed it on the namespace.
    "request_id"
);

/// One gate on a draft whose every request owns a bidirectional stream of its
/// own: drafts 17 through 20.
///
/// Two claims, and the second is the one worth having. The offer reaches the
/// wire on a stream of its own — so the facade opened one rather than writing
/// on the control plane — and the withdrawal is **refused**, naming the stream,
/// rather than silently doing nothing. There is no PUBLISH_NAMESPACE_DONE on
/// these four drafts to send, so a facade that returned `Ok(())` here would be
/// telling a caller it had withdrawn an announcement that is still standing.
macro_rules! request_stream_gate {
    ($mod_name:ident, $feat:literal, $version:ident) => {
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

            /// Complete the handshake, then read one message off the first
            /// request stream the client opens.
            async fn serve(server: quinn::Endpoint) -> String {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let (_answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request, DRAFT);
                describe(&request.read_control().await.expect("read the offer"))
            }

            #[tokio::test]
            async fn an_announcement_ends_with_its_stream_and_says_so() {
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

                let [first, _] = namespaces();
                let mut handle =
                    tokio::time::timeout(PATIENCE, conn.publish_namespace(first.clone()))
                        .await
                        .expect("the offer did not finish")
                        .expect("offer the namespace");
                assert!(
                    handle.stream_id().is_some(),
                    "{DRAFT:?} gives every request a stream of its own"
                );

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    seen,
                    render(
                        "publish_namespace",
                        0x06,
                        &[
                            ("request_id", handle.request_id().into_inner().to_string()),
                            ("namespace", "conformance/alpha".to_string()),
                        ],
                    ),
                    "{DRAFT:?} writes the offer on the request's own stream"
                );

                let refused = conn
                    .publish_namespace_done(&handle, first)
                    .await
                    .expect_err("there is no such message on this draft");
                assert!(
                    refused.to_string().contains("stream"),
                    "the refusal has to say where the announcement's lifetime lives: {refused}"
                );

                // The withdrawal these drafts do have, and the one the refusal
                // points at.
                handle.cancel(0).expect("resetting the stream withdraws the announcement");
            }
        }
    };
}

request_stream_gate!(draft17, "draft17", Draft17);
request_stream_gate!(draft18, "draft18", Draft18);
request_stream_gate!(draft19, "draft19", Draft19);
request_stream_gate!(draft20, "draft20", Draft20);

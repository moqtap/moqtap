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
    feature = "draft21",
    feature = "draft22",
))]

//! `AnyConnection::publish` offers a track on every draft that has PUBLISH,
//! and `AnyConnection::publish_done` ends an accepted offer the way its draft
//! ends one.
//!
//! # What held still and what did not
//!
//! PUBLISH is message type `0x1D` from draft-12, where it first appears,
//! through draft-22, and the message that ends it is `0x0B` throughout. The
//! rest moved:
//!
//! * **The end's name.** Drafts 12 and 13 end a PUBLISH-established
//!   subscription with SUBSCRIBE_DONE, like any other; draft-14 renamed the
//!   message PUBLISH_DONE.
//! * **The acceptance.** PUBLISH_OK (`0x1E`) through draft-17; from draft-18
//!   the acceptance is REQUEST_OK (`0x07`). The rejection is PUBLISH_ERROR on
//!   drafts 12 through 14 and REQUEST_ERROR from draft-15.
//! * **Forward.** A field of the message on drafts 12 through 14, and the
//!   FORWARD parameter (key 0x10) from draft-15. The peer below reads it from
//!   wherever its draft keeps it, so a facade that dropped it, or handed it to
//!   the wrong argument, reads as absent.
//! * **Where it travels.** The control stream through draft-16, its own
//!   bidirectional stream from draft-17 — and there the done is followed by a
//!   FIN, which the peer checks for: a stream left open would end with the
//!   handle's reset, which cancels a publication the caller had completed.
//!
//! # What the peer does
//!
//! Reads what the client writes, decodes it with the codec, and renders it
//! through [`common::render`] from the draft's own field table. The gate
//! renders what it asked for the same way from literals, so the two agree only
//! if the facade reached the right per-draft helper with the right arguments.

mod common;

use std::time::Duration;

use common::render;
use moqtap_client::dispatch::{AnyClientConfig, AnyConnection, AnyRequest, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::fields::FieldValue;
use moqtap_codec::types::{Forward, TrackNamespace};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The alias every offer here names.
const ALIAS: u64 = 5;

/// TRACK_ENDED, status code 0x2 on every draft from 12 to 22.
const TRACK_ENDED: u64 = 0x2;

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"offered".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
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

/// Forward, from wherever this draft keeps it: the message's own field on
/// drafts 12 through 14, the parameter of type 0x10 after that. `absent` when
/// neither holds it.
fn forward_text(message: &AnyControlMessage) -> String {
    let fields = message.fields();
    if let Some(forward) = fields.get("forward") {
        return field_text(forward);
    }
    if let Some(FieldValue::Array(params)) = fields.get("parameters") {
        for param in params {
            if let FieldValue::Map(entry) = param {
                if entry.get("type") == Some(&FieldValue::Text("0x10".to_string())) {
                    return entry.get("value").map(field_text).unwrap_or_default();
                }
            }
        }
    }
    "absent".to_string()
}

/// Render an offer or a done: its name and type, then whichever of the fields
/// below it carries, in this order.
fn describe(message: &AnyControlMessage) -> String {
    let fields = message.fields();
    let mut rendered = Vec::new();
    for key in [
        "request_id",
        "track_namespace",
        "track_name",
        "track_alias",
        "status_code",
        "stream_count",
    ] {
        if let Some(value) = fields.get(key) {
            rendered.push((key, field_text(value)));
        }
    }
    if fields.get("track_name").is_some() {
        rendered.push(("forward", forward_text(message)));
    }
    render(message.message_type_name(), message.message_type_id(), &rendered)
}

/// What the gate expects the offer to render as.
///
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn offer_rendering(request_id: VarInt) -> String {
    render(
        "publish",
        0x1D,
        &[
            ("request_id", request_id.into_inner().to_string()),
            ("track_namespace", "conformance/offered".to_string()),
            ("track_name", "probe".to_string()),
            ("track_alias", ALIAS.to_string()),
            ("forward", "0".to_string()),
        ],
    )
}

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

    /// Whether the client's direction ends with a FIN and nothing after the
    /// last message read: `true` for a FIN, `false` for a reset.
    ///
    /// Unread in a build that enables only drafts whose gates do not use it.
    #[allow(dead_code)]
    async fn ends_with_fin(&mut self) -> bool {
        assert!(self.buf.is_empty(), "bytes after the last message: {:?}", self.buf);
        let mut tmp = [0u8; 64];
        match self.recv.read(&mut tmp).await {
            Ok(None) => true,
            Ok(Some(n)) => panic!("more after the done: {:?}", &tmp[..n]),
            Err(_) => false,
        }
    }
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn request_id_of(message: &AnyControlMessage) -> VarInt {
    match message.fields().get("request_id") {
        Some(FieldValue::Uint(id)) => v(*id),
        other => panic!("a PUBLISH with no Request ID: {other:?}"),
    }
}

async fn connect(draft: DraftVersion, addr: std::net::SocketAddr) -> AnyConnection {
    tokio::time::timeout(PATIENCE, AnyConnection::connect(&addr.to_string(), client_config(draft)))
        .await
        .expect("connect did not finish")
        .expect("connect")
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
async fn offer(conn: &mut AnyConnection) -> AnyRequest {
    tokio::time::timeout(
        PATIENCE,
        conn.publish(namespace(), b"probe".to_vec(), v(ALIAS), Forward::DontForward),
    )
    .await
    .expect("the offer did not finish")
    .expect("offer the track")
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
async fn answer(conn: &mut AnyConnection, handle: &mut AnyRequest) -> String {
    let message = tokio::time::timeout(PATIENCE, conn.recv_response(handle))
        .await
        .expect("the answer did not arrive")
        .expect("read the answer")
        .expect("an answer, not a bare FIN");
    message.message_type_name().to_string()
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
async fn end(conn: &mut AnyConnection, handle: &mut AnyRequest) -> Result<(), String> {
    tokio::time::timeout(
        PATIENCE,
        conn.publish_done(handle, v(TRACK_ENDED), v(0), b"probe complete".to_vec()),
    )
    .await
    .expect("the done did not finish")
    .map_err(|e| {
        assert!(e.is_local(), "a done refused for want of an acceptance is this side's: {e}");
        e.to_string()
    })
}

/// One draft that carries every request on the control stream: drafts 12
/// through 16.
///
/// `$setup` builds the peer's SERVER_SETUP from the CLIENT_SETUP it read, with
/// a MAX_REQUEST_ID so the client has an identifier to spend. `$accept` and
/// `$reject` build this draft's answers for a Request ID; `$accepted` and
/// `$done` are the names the client should read the acceptance under and the
/// peer should read the end under.
macro_rules! control_stream_gates {
    (
        $mod_name:ident,
        $feat:literal,
        $version:ident,
        |$cs:ident| $setup:expr,
        |$id:ident| $accept:expr,
        |$rid:ident| $reject:expr,
        $accepted:literal,
        $done:literal
    ) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn budget() -> KeyValuePair {
                KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }
            }

            fn server_setup_bytes($cs: &AnyControlMessage) -> Vec<u8> {
                encoded($setup)
            }

            fn accept_bytes($id: VarInt) -> Vec<u8> {
                encoded($accept)
            }

            fn reject_bytes($rid: VarInt) -> Vec<u8> {
                encoded($reject)
            }

            /// Handshake, read the offer, answer it, and — when it was
            /// accepted — read the done. A rejecting peer holds the connection
            /// until the client closes it, so the client's read of the
            /// rejection never races a close.
            async fn serve(server: quinn::Endpoint, accept: bool) -> Vec<String> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = PeerStream::new(recv, DRAFT);
                let client_setup =
                    control.read_control().await.expect("read the client's CLIENT_SETUP");
                send.write_all(&server_setup_bytes(&client_setup))
                    .await
                    .expect("write SERVER_SETUP");

                let mut seen = Vec::new();
                let offer = control.read_control().await.expect("read the offer");
                let id = request_id_of(&offer);
                seen.push(describe(&offer));
                if accept {
                    send.write_all(&accept_bytes(id)).await.expect("write the acceptance");
                    seen.push(describe(&control.read_control().await.expect("read the done")));
                } else {
                    send.write_all(&reject_bytes(id)).await.expect("write the rejection");
                    conn.closed().await;
                }
                seen
            }

            #[tokio::test]
            async fn an_accepted_offer_is_ended_with_this_drafts_done() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, true));
                let mut conn = connect(DRAFT, addr).await;

                let mut handle = offer(&mut conn).await;
                assert_eq!(handle.stream_id(), None, "{DRAFT:?} offers on the control stream");
                assert_eq!(answer(&mut conn, &mut handle).await, $accepted);
                end(&mut conn, &mut handle).await.expect("end the accepted offer");

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                conn.close(0, b"");
                let id = handle.request_id();
                assert_eq!(
                    seen,
                    vec![
                        offer_rendering(id),
                        render(
                            $done,
                            0x0B,
                            &[
                                ("request_id", id.into_inner().to_string()),
                                ("status_code", TRACK_ENDED.to_string()),
                                ("stream_count", "0".to_string()),
                            ],
                        ),
                    ],
                    "{DRAFT:?} offers PUBLISH with Forward 0 and ends it with {}",
                    $done
                );
            }

            #[tokio::test]
            async fn a_rejected_offer_has_nothing_to_end() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, false));
                let mut conn = connect(DRAFT, addr).await;

                let mut handle = offer(&mut conn).await;
                answer(&mut conn, &mut handle).await;
                end(&mut conn, &mut handle).await.expect_err("a rejected offer was ended");
                conn.close(0, b"");

                let seen = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(seen, vec![offer_rendering(handle.request_id())]);
            }
        }
    };
}

control_stream_gates!(
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
        use moqtap_codec::draft12::message::{ControlMessage, PublishOk};
        use moqtap_codec::types::GroupOrder;
        AnyControlMessage::Draft12(ControlMessage::PublishOk(PublishOk {
            request_id: id,
            forward: Forward::DontForward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }))
    },
    |id| {
        use moqtap_codec::draft12::message::{ControlMessage, PublishError};
        AnyControlMessage::Draft12(ControlMessage::PublishError(PublishError {
            request_id: id,
            error_code: v(0x1),
            reason_phrase: b"unauthorized".to_vec(),
        }))
    },
    "publish_ok",
    "subscribe_done"
);

control_stream_gates!(
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
        use moqtap_codec::draft13::message::{ControlMessage, PublishOk};
        use moqtap_codec::types::{FilterType, GroupOrder};
        AnyControlMessage::Draft13(ControlMessage::PublishOk(PublishOk {
            request_id: id,
            forward: Forward::DontForward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }))
    },
    |id| {
        use moqtap_codec::draft13::message::{ControlMessage, PublishError};
        AnyControlMessage::Draft13(ControlMessage::PublishError(PublishError {
            request_id: id,
            error_code: v(0x1),
            reason_phrase: b"unauthorized".to_vec(),
        }))
    },
    "publish_ok",
    "subscribe_done"
);

control_stream_gates!(
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
        use moqtap_codec::draft14::message::{ControlMessage, PublishOk};
        use moqtap_codec::types::{FilterType, GroupOrder};
        AnyControlMessage::Draft14(ControlMessage::PublishOk(PublishOk {
            request_id: id,
            forward: Forward::DontForward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }))
    },
    |id| {
        use moqtap_codec::draft14::message::{ControlMessage, PublishError};
        AnyControlMessage::Draft14(ControlMessage::PublishError(PublishError {
            request_id: id,
            error_code: v(0x1),
            reason_phrase: b"unauthorized".to_vec(),
        }))
    },
    "publish_ok",
    // The rename this draft makes, for the same message number.
    "publish_done"
);

control_stream_gates!(
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
        use moqtap_codec::draft15::message::{ControlMessage, PublishOk};
        AnyControlMessage::Draft15(ControlMessage::PublishOk(PublishOk {
            request_id: id,
            parameters: Vec::new(),
        }))
    },
    |id| {
        use moqtap_codec::draft15::message::{ControlMessage, RequestError};
        AnyControlMessage::Draft15(ControlMessage::RequestError(RequestError {
            request_id: id,
            error_code: v(0x1),
            reason_phrase: b"unauthorized".to_vec(),
        }))
    },
    "publish_ok",
    "publish_done"
);

control_stream_gates!(
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
        use moqtap_codec::draft16::message::{ControlMessage, PublishOk};
        AnyControlMessage::Draft16(ControlMessage::PublishOk(PublishOk {
            request_id: id,
            parameters: Vec::new(),
        }))
    },
    |id| {
        use moqtap_codec::draft16::message::{ControlMessage, RequestError};
        AnyControlMessage::Draft16(ControlMessage::RequestError(RequestError {
            request_id: id,
            error_code: v(0x1),
            retry_interval: v(0),
            reason_phrase: b"unauthorized".to_vec(),
        }))
    },
    "publish_ok",
    "publish_done"
);

/// One draft whose every request owns a bidirectional stream: drafts 17
/// through 22.
///
/// `$accept` and `$reject` build this draft's answers, which carry no Request
/// ID — the stream is the correlation — and `$accepted` is the name the client
/// should read the acceptance under: PUBLISH_OK on draft-17, REQUEST_OK after
/// it.
macro_rules! request_stream_gates {
    (
        $mod_name:ident,
        $feat:literal,
        $version:ident,
        $accept:expr,
        $reject:expr,
        $accepted:literal
    ) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            #[allow(unused_imports)]
            use moqtap_codec::$mod_name::message::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn setup_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
                    options: Vec::new(),
                })))
            }

            fn accept_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version($accept))
            }

            fn reject_bytes() -> Vec<u8> {
                encoded(AnyControlMessage::$version($reject))
            }

            /// Handshake, read the offer on its own stream, answer it, and —
            /// when it was accepted — read the done and how the stream ended.
            /// A rejecting peer holds the connection until the client closes
            /// it.
            async fn serve(server: quinn::Endpoint, accept: bool) -> (Vec<String>, Option<bool>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request, DRAFT);
                let mut seen = vec![describe(&request.read_control().await.expect("the offer"))];
                let mut fin = None;
                if accept {
                    answer.write_all(&accept_bytes()).await.expect("write the acceptance");
                    seen.push(describe(&request.read_control().await.expect("read the done")));
                    fin = Some(request.ends_with_fin().await);
                } else {
                    answer.write_all(&reject_bytes()).await.expect("write the rejection");
                    conn.closed().await;
                }
                (seen, fin)
            }

            #[tokio::test]
            async fn an_accepted_offer_is_ended_and_its_stream_finished() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, true));
                let mut conn = connect(DRAFT, addr).await;

                let mut handle = offer(&mut conn).await;
                assert!(handle.stream_id().is_some(), "{DRAFT:?} gives the offer its own stream");
                assert_eq!(answer(&mut conn, &mut handle).await, $accepted);
                end(&mut conn, &mut handle).await.expect("end the accepted offer");
                let id = handle.request_id();
                // Dropped before the peer is awaited, so a send half left open
                // reaches the peer as the drop's reset rather than as a hang.
                drop(handle);

                let (seen, fin) = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                conn.close(0, b"");
                assert_eq!(
                    seen,
                    vec![
                        offer_rendering(id),
                        render(
                            "publish_done",
                            0x0B,
                            &[
                                ("status_code", TRACK_ENDED.to_string()),
                                ("stream_count", "0".to_string()),
                            ],
                        ),
                    ],
                    "{DRAFT:?} offers PUBLISH with FORWARD 0 and ends it with PUBLISH_DONE"
                );
                assert_eq!(
                    fin,
                    Some(true),
                    "draft-{:02} finishes the offer's stream after PUBLISH_DONE",
                    DRAFT.number()
                );
            }

            #[tokio::test]
            async fn a_rejected_offer_has_nothing_to_end() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, false));
                let mut conn = connect(DRAFT, addr).await;

                let mut handle = offer(&mut conn).await;
                assert_eq!(answer(&mut conn, &mut handle).await, "request_error");
                end(&mut conn, &mut handle).await.expect_err("a rejected offer was ended");
                let id = handle.request_id();
                drop(handle);
                conn.close(0, b"");

                let (seen, _) = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(seen, vec![offer_rendering(id)]);
            }
        }
    };
}

request_stream_gates!(
    draft17,
    "draft17",
    Draft17,
    ControlMessage::PublishOk(PublishOk { parameters: Vec::new() }),
    ControlMessage::RequestError(RequestError {
        error_code: v(0x1),
        retry_interval: v(0),
        reason_phrase: b"unauthorized".to_vec(),
    }),
    "publish_ok"
);
request_stream_gates!(
    draft18,
    "draft18",
    Draft18,
    ControlMessage::RequestOk(RequestOk { parameters: Vec::new(), track_properties: Vec::new() }),
    ControlMessage::RequestError(RequestError {
        error_code: v(0x1),
        retry_interval: v(0),
        reason_phrase: b"unauthorized".to_vec(),
        redirect: None,
    }),
    "request_ok"
);
request_stream_gates!(
    draft19,
    "draft19",
    Draft19,
    ControlMessage::RequestOk(RequestOk { parameters: Vec::new(), track_properties: Vec::new() }),
    ControlMessage::RequestError(RequestError {
        error_code: v(0x1),
        retry_interval: v(0),
        reason_phrase: b"unauthorized".to_vec(),
        redirect: None,
    }),
    "request_ok"
);
request_stream_gates!(
    draft20,
    "draft20",
    Draft20,
    ControlMessage::RequestOk(RequestOk { parameters: Vec::new(), track_properties: Vec::new() }),
    ControlMessage::RequestError(RequestError {
        error_code: v(0x1),
        retry_interval: v(0),
        reason_phrase: b"unauthorized".to_vec(),
        redirect: None,
    }),
    "request_ok"
);
request_stream_gates!(
    draft21,
    "draft21",
    Draft21,
    ControlMessage::RequestOk(RequestOk { parameters: Vec::new(), track_properties: Vec::new() }),
    ControlMessage::RequestError(RequestError {
        error_code: v(0x1),
        retry_interval: v(0),
        reason_phrase: b"unauthorized".to_vec(),
        redirect: None,
    }),
    "request_ok"
);
request_stream_gates!(
    draft22,
    "draft22",
    Draft22,
    ControlMessage::RequestOk(RequestOk { parameters: Vec::new(), track_properties: Vec::new() }),
    ControlMessage::RequestError(RequestError {
        error_code: v(0x1),
        retry_interval: v(0),
        reason_phrase: b"unauthorized".to_vec(),
        redirect: None,
    }),
    "request_ok"
);

/// Draft-11, the last draft without PUBLISH: the offer is refused before
/// anything reaches the wire, and so is a done for a handle no offer made.
#[cfg(feature = "draft11")]
mod draft11 {
    use super::*;
    use moqtap_codec::draft11::message::{ControlMessage, ServerSetup};
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    const DRAFT: DraftVersion = DraftVersion::Draft11;

    async fn serve(server: quinn::Endpoint) {
        let conn = server.accept().await.expect("accept").await.expect("tls handshake");
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut control = PeerStream::new(recv, DRAFT);
        let selected = match control.read_control().await.expect("read the CLIENT_SETUP") {
            AnyControlMessage::Draft11(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        send.write_all(&encoded(AnyControlMessage::Draft11(ControlMessage::ServerSetup(
            ServerSetup {
                selected_version: selected,
                parameters: vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }],
            },
        ))))
        .await
        .expect("write SERVER_SETUP");
        if let Some(message) = control.read_control().await {
            panic!("draft-11 has no PUBLISH, and the client wrote {}", describe(&message));
        }
    }

    #[tokio::test]
    async fn a_draft_without_publish_refuses_to_offer_or_end_one() {
        common::init_crypto();
        let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
        let peer = tokio::spawn(serve(endpoint));
        let mut conn = connect(DRAFT, addr).await;

        let refused = match conn
            .publish(namespace(), b"probe".to_vec(), v(ALIAS), Forward::DontForward)
            .await
        {
            Ok(_) => panic!("draft-11 has no PUBLISH, and the facade offered one"),
            Err(e) => e,
        };
        assert!(refused.to_string().contains("draft-12"), "say where PUBLISH starts: {refused}");

        let mut stray = AnyRequest::ControlPlane { request_id: v(0), draft: DRAFT };
        conn.publish_done(&mut stray, v(TRACK_ENDED), v(0), Vec::new())
            .await
            .expect_err("draft-11 has no publication to end");

        conn.close(0, b"");
        tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").expect("the peer");
    }
}

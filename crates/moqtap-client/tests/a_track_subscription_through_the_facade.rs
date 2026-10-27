#![cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
))]

//! `AnyConnection::subscribe_tracks` asks for every track under a prefix on
//! each draft that has SUBSCRIBE_TRACKS, and the handle it returns ends the
//! subscription by resetting its stream.
//!
//! SUBSCRIBE_TRACKS is message type `0x51` on drafts 18 through 22, always on a
//! bidirectional stream of its own, and answered with REQUEST_OK. The peer
//! below decodes it, renders the prefix and the FORWARD parameter through
//! [`common::render`], accepts it, and then reads how the client's direction
//! ends once the handle is dropped. A FIN would not do: on drafts 19 through
//! 22 it says only that the requester has nothing more to send (draft-22
//! Section 6.4.2.2), so a reset is how the handle cancels on every draft.
//!
//! Draft-17 is here for the refusal. It asks the same question through
//! SUBSCRIBE_NAMESPACE's Subscribe Options, so the facade has nothing to send
//! under this name and says so.

mod common;

use std::time::Duration;

use common::render;
use moqtap_client::dispatch::{AnyClientConfig, AnyConnection, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::fields::FieldValue;
use moqtap_codec::types::{Forward, TrackNamespace};
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

fn prefix() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"nobody-publishes-here".to_vec()])
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

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
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

/// The value of the parameter of type 0x10, FORWARD, or `absent`.
///
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn forward_text(message: &AnyControlMessage) -> String {
    if let Some(FieldValue::Array(params)) = message.fields().get("parameters") {
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

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn describe(message: &AnyControlMessage) -> String {
    let fields = message.fields();
    let mut rendered = Vec::new();
    for key in ["request_id", "namespace_prefix"] {
        if let Some(value) = fields.get(key) {
            rendered.push((key, field_text(value)));
        }
    }
    rendered.push(("forward", forward_text(message)));
    render(message.message_type_name(), message.message_type_id(), &rendered)
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

    /// How the client's direction ended: `Some(code)` for a reset, `None` for
    /// a FIN.
    ///
    /// Unread in a build that enables only drafts whose gates do not use it.
    #[allow(dead_code)]
    async fn reset_code(&mut self) -> Option<u64> {
        let mut tmp = [0u8; 64];
        match self.recv.read(&mut tmp).await {
            Ok(None) => None,
            Ok(Some(n)) => panic!("more after the request: {:?}", &tmp[..n]),
            Err(quinn::ReadError::Reset(code)) => Some(code.into_inner()),
            Err(e) => panic!("the stream ended neither way: {e}"),
        }
    }
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

async fn connect(draft: DraftVersion, addr: std::net::SocketAddr) -> AnyConnection {
    tokio::time::timeout(PATIENCE, AnyConnection::connect(&addr.to_string(), client_config(draft)))
        .await
        .expect("connect did not finish")
        .expect("connect")
}

/// One draft with SUBSCRIBE_TRACKS: drafts 18 through 22.
macro_rules! subscribe_tracks_gate {
    ($mod_name:ident, $feat:literal, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::*;
            use moqtap_codec::$mod_name::message::{ControlMessage, RequestOk, Setup};

            const DRAFT: DraftVersion = DraftVersion::$version;

            async fn serve(server: quinn::Endpoint) -> (String, Option<u64>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await.expect("read the client's SETUP");
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&encoded(AnyControlMessage::$version(ControlMessage::Setup(
                    Setup { options: Vec::new() },
                ))))
                .await
                .expect("write the peer's SETUP");

                let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request, DRAFT);
                let seen = describe(&request.read_control().await.expect("read the request"));
                answer
                    .write_all(&encoded(AnyControlMessage::$version(ControlMessage::RequestOk(
                        RequestOk { parameters: Vec::new(), track_properties: Vec::new() },
                    ))))
                    .await
                    .expect("write REQUEST_OK");
                (seen, request.reset_code().await)
            }

            #[tokio::test]
            async fn a_track_subscription_is_asked_and_cancelled_by_its_handle() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));
                let mut conn = connect(DRAFT, addr).await;

                let mut handle = tokio::time::timeout(
                    PATIENCE,
                    conn.subscribe_tracks(prefix(), Forward::DontForward),
                )
                .await
                .expect("the request did not finish")
                .expect("ask for the tracks");
                assert!(handle.stream_id().is_some(), "{DRAFT:?} gives the request its own stream");
                let answer = tokio::time::timeout(PATIENCE, conn.recv_response(&mut handle))
                    .await
                    .expect("the answer did not arrive")
                    .expect("read the answer")
                    .expect("an answer, not a bare FIN");
                assert_eq!(answer.message_type_name(), "request_ok");
                let id = handle.request_id();
                drop(handle);

                let (seen, reset) = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                conn.close(0, b"");
                assert_eq!(
                    seen,
                    render(
                        "subscribe_tracks",
                        0x51,
                        &[
                            ("request_id", id.into_inner().to_string()),
                            ("namespace_prefix", "conformance/nobody-publishes-here".to_string()),
                            ("forward", "0".to_string()),
                        ],
                    ),
                    "{DRAFT:?} asks SUBSCRIBE_TRACKS with FORWARD 0"
                );
                assert!(
                    reset.is_some(),
                    "dropping the handle cancels the subscription, which takes a reset, not a FIN"
                );
            }
        }
    };
}

subscribe_tracks_gate!(draft18, "draft18", Draft18);
subscribe_tracks_gate!(draft19, "draft19", Draft19);
subscribe_tracks_gate!(draft20, "draft20", Draft20);
subscribe_tracks_gate!(draft21, "draft21", Draft21);
subscribe_tracks_gate!(draft22, "draft22", Draft22);

/// Draft-17 has no SUBSCRIBE_TRACKS: the facade refuses before anything
/// reaches the wire, and points at the question's draft-17 spelling.
#[cfg(feature = "draft17")]
mod draft17 {
    use super::*;
    use moqtap_codec::draft17::message::{ControlMessage, Setup};

    const DRAFT: DraftVersion = DraftVersion::Draft17;

    async fn serve(server: quinn::Endpoint) {
        let conn = server.accept().await.expect("accept").await.expect("tls handshake");
        let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
        control.read_control().await.expect("read the client's SETUP");
        let mut ours = conn.open_uni().await.expect("open the peer's control stream");
        ours.write_all(&encoded(AnyControlMessage::Draft17(ControlMessage::Setup(Setup {
            options: Vec::new(),
        }))))
        .await
        .expect("write the peer's SETUP");
        if let Ok((_, recv)) = conn.accept_bi().await {
            let mut request = PeerStream::new(recv, DRAFT);
            if let Some(message) = request.read_control().await {
                panic!("draft-17 has no SUBSCRIBE_TRACKS, and the client wrote {message:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_draft_without_subscribe_tracks_refuses_and_names_the_alternative() {
        common::init_crypto();
        let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
        let peer = tokio::spawn(serve(endpoint));
        let mut conn = connect(DRAFT, addr).await;

        let refused = match conn.subscribe_tracks(prefix(), Forward::DontForward).await {
            Ok(_) => panic!("draft-17 has no SUBSCRIBE_TRACKS, and the facade sent one"),
            Err(e) => e,
        };
        let message = refused.to_string();
        assert!(message.contains("draft-18"), "say where SUBSCRIBE_TRACKS starts: {message}");
        assert!(
            message.contains("subscribe_namespace"),
            "name the entry point that asks this question on draft-17: {message}"
        );

        conn.close(0, b"");
        tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").expect("the peer");
    }
}

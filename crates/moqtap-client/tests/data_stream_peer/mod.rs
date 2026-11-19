//! The peer's half of setup, for the tests that drive `AnyConnection`'s data
//! stream accepts on every enabled draft.

#![allow(dead_code, unused_macros)]

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::version::DraftVersion;

pub fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

/// Whole control messages off one quinn stream, framed for one draft.
pub struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    pub fn new(recv: quinn::RecvStream, draft: DraftVersion) -> Self {
        Self { recv, draft, buf: Vec::new() }
    }

    pub async fn read_control(&mut self) -> Option<AnyControlMessage> {
        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(self.draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                Err(e) if e.is_incomplete() => {
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

/// The peer's half of setup. Expands to the control stream, which has to stay
/// alive for the session to stay open. Takes `DRAFT` and `setup_parameters`
/// from the module it expands in. On the drafts whose control plane is a pair
/// of unidirectional streams, `before` runs after the client's SETUP is read
/// and before the peer opens its own control stream.
macro_rules! peer_setup {
    (versioned, $conn:ident, $version:ident, $module:ident) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut control = $crate::data_stream_peer::PeerStream::new(recv, DRAFT);
        let client_setup = control.read_control().await.expect("read the client's CLIENT_SETUP");
        let selected = match &client_setup {
            AnyControlMessage::$version(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        send.write_all(&$crate::data_stream_peer::encoded(AnyControlMessage::$version(
            ControlMessage::ServerSetup(ServerSetup {
                selected_version: selected,
                parameters: setup_parameters(),
            }),
        )))
        .await
        .expect("write SERVER_SETUP");
        (send, control)
    }};
    (plain, $conn:ident, $version:ident, $module:ident) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut control = $crate::data_stream_peer::PeerStream::new(recv, DRAFT);
        control.read_control().await.expect("read the client's CLIENT_SETUP");
        send.write_all(&$crate::data_stream_peer::encoded(AnyControlMessage::$version(
            ControlMessage::ServerSetup(ServerSetup { parameters: setup_parameters() }),
        )))
        .await
        .expect("write SERVER_SETUP");
        (send, control)
    }};
    (uni, $conn:ident, $version:ident, $module:ident) => {
        peer_setup!(uni, $conn, $version, $module, before: {})
    };
    (uni, $conn:ident, $version:ident, $module:ident, before: $before:block) => {{
        use moqtap_codec::$module::message::{ControlMessage, Setup};
        let mut control = $crate::data_stream_peer::PeerStream::new(
            $conn.accept_uni().await.expect("accept_uni"),
            DRAFT,
        );
        control.read_control().await.expect("read the client's SETUP");
        $before
        let mut ours = $conn.open_uni().await.expect("open the peer's control stream");
        ours.write_all(&$crate::data_stream_peer::encoded(AnyControlMessage::$version(
            ControlMessage::Setup(Setup { options: setup_parameters() }),
        )))
        .await
        .expect("write the peer's SETUP");
        (ours, control)
    }};
}

/// Draft-07 alone needs a ROLE in setup.
macro_rules! draft_setup_parameters {
    (with_role) => {
        fn setup_parameters() -> Vec<moqtap_codec::kvp::KeyValuePair> {
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::varint::VarInt;

            let v = |n: u64| VarInt::from_u64(n).expect("fixture value fits a varint");
            let mut value = Vec::new();
            // PubSub: this endpoint both publishes and subscribes.
            v(3).encode(&mut value);
            vec![KeyValuePair { key: v(0x00), value: KvpValue::Bytes(value) }]
        }
    };
    (none) => {
        fn setup_parameters() -> Vec<moqtap_codec::kvp::KeyValuePair> {
            Vec::new()
        }
    };
}

/// Expands `$items` only on the drafts whose control plane is a pair of
/// unidirectional streams, the only ones whose peer can open a data stream
/// before its control stream.
macro_rules! on_uni_drafts {
    (uni, { $($items:item)* }) => { $($items)* };
    ($other:ident, { $($items:item)* }) => {};
}

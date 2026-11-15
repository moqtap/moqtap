//! A request this endpoint completed is let go of without STOP_SENDING.
//!
//! draft-22 Section 6.4.2.3: "An endpoint that has already sent a FIN on its
//! sending direction and subsequently wishes to cancel sends STOP_SENDING on
//! the receiving direction." So once the client has answered a FETCH and sent
//! its FIN, or ended a PUBLISH with PUBLISH_DONE and a FIN, dropping the handle
//! must not stop the peer's direction. The peer here keeps that direction open
//! past the drop, then finishes it.

#![cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23",
))]
// Each fetch builder is used only by the drafts it covers.
#![allow(unused_macros)]

mod common;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyServedArrival, AnyTransportType, FetchAnswer, FetchAnswered,
    FetchLocation, FetchRefusal,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::{Forward, TrackNamespace};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

const PATIENCE: Duration = Duration::from_secs(10);

/// How long `stopped()` must stay pending once the client has let go.
const PENDING_WINDOW: Duration = Duration::from_millis(500);

const TRACK: &[u8] = b"video";

const ANSWER: FetchAnswer = FetchAnswer {
    largest_object: FetchLocation { group: 1, object: 1 },
    end_of_track: false,
    end_group_last_object: Some(4),
};

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("fixture value fits a varint")
}

fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

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

/// Reads whole control messages off one stream.
struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream, draft: DraftVersion) -> Self {
        Self { recv, draft, buf: Vec::new() }
    }

    async fn read_control(&mut self) -> AnyControlMessage {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(self.draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return msg;
                }
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    let mut tmp = [0u8; 2048];
                    let n = self
                        .recv
                        .read(&mut tmp)
                        .await
                        .expect("read the client's direction")
                        .expect("a message before the FIN");
                    self.buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => panic!("the peer could not decode what the client wrote: {e}"),
            }
        }
    }

    /// Read the client's direction to its FIN, which must follow the last
    /// message with nothing in between.
    async fn ends_with_fin(&mut self) {
        assert!(self.buf.is_empty(), "bytes after the last message: {:?}", self.buf);
        let rest = self.recv.read_to_end(1 << 16).await.expect("a FIN, not a reset");
        assert!(rest.is_empty(), "bytes after the last message: {rest:?}");
    }
}

/// The peer's direction is still open after the client let go: it must not be
/// stopped, and it is acknowledged once the peer finishes it.
async fn not_stopped(mut send: quinn::SendStream, rule: &str, what: &str) {
    let early = tokio::time::timeout(PENDING_WINDOW, send.stopped()).await;
    assert!(
        early.is_err(),
        "{rule}: STOP_SENDING after the client's FIN cancels a request it completed ({what}): \
         {early:?}"
    );
    send.finish().expect("finish the peer's direction");
    let acked = tokio::time::timeout(PATIENCE, send.stopped()).await;
    assert!(
        matches!(acked, Ok(Ok(None))),
        "{rule}: the peer's FIN is read, not stopped ({what}): {acked:?}"
    );
}

/// One draft's gate. `$fetch` builds a FETCH for Request ID `id` asking for
/// {0, 0} through {0, 1}; `$accept` is the answer to a PUBLISH; `$rule` cites
/// the draft's request cancellation section.
macro_rules! gate {
    (
        $module:ident, $feat:literal, $version:ident, $rule:literal,
        fetch: |$id:ident| $fetch:expr,
        accept: $accept:expr $(,)?
    ) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;
            #[allow(unused_imports)]
            use moqtap_codec::$module::message::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn setup() -> Vec<u8> {
                encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
                    options: vec![granted_budget()],
                })))
            }

            fn fetch($id: u64) -> Vec<u8> {
                let $id = v($id);
                encoded(AnyControlMessage::$version(ControlMessage::Fetch($fetch)))
            }

            async fn handshake(conn: &quinn::Connection) -> quinn::SendStream {
                let mut control =
                    PeerStream::new(conn.accept_uni().await.expect("accept_uni"), DRAFT);
                control.read_control().await;
                let mut ours = conn.open_uni().await.expect("open the peer's control stream");
                ours.write_all(&setup()).await.expect("write SETUP");
                ours
            }

            /// Ask twice, once to be served and once to be refused, each time
            /// keeping this side's direction open past the client's drop.
            async fn ask(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = handshake(&conn).await;
                for (id, what) in [(1, "a served FETCH"), (3, "a refused FETCH")] {
                    let (mut send, recv) = conn.open_bi().await.expect("open a request stream");
                    send.write_all(&fetch(id)).await.expect("write FETCH");
                    let mut answer = PeerStream::new(recv, DRAFT);
                    answer.read_control().await;
                    answer.ends_with_fin().await;
                    not_stopped(send, $rule, what).await;
                }
            }

            #[tokio::test]
            async fn a_fetch_this_endpoint_answered_is_not_stopped_when_dropped() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(ask(endpoint));
                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                for refuse in [false, true] {
                    let arrival = tokio::time::timeout(PATIENCE, conn.recv_inbound_serving_fetch())
                        .await
                        .expect("nothing arrived")
                        .expect("read the peer's FETCH");
                    let AnyServedArrival::Fetch { request: mut fetch, .. } = arrival else {
                        panic!("a FETCH did not come back as one");
                    };
                    if refuse {
                        conn.refuse_fetch(&mut fetch, FetchRefusal::DoesNotExist, b"")
                            .await
                            .expect("refuse the FETCH");
                    } else {
                        let answered = conn.answer_fetch(&mut fetch, ANSWER).await.expect("answer");
                        assert!(matches!(answered, FetchAnswered::Served(_)), "{answered:?}");
                        fetch.finish().await.expect("finish the request");
                    }
                    drop(fetch);
                }

                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                drop(conn);
            }

            /// Accept the client's PUBLISH, read its PUBLISH_DONE and FIN, and
            /// keep this side's direction open past the client's drop.
            async fn accept(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = handshake(&conn).await;
                let (mut send, recv) = conn.accept_bi().await.expect("accept the PUBLISH");
                let mut request = PeerStream::new(recv, DRAFT);
                request.read_control().await;
                send.write_all(&encoded(AnyControlMessage::$version($accept)))
                    .await
                    .expect("write the acceptance");
                let done = request.read_control().await;
                assert_eq!(done.message_type_name(), "publish_done");
                request.ends_with_fin().await;
                not_stopped(send, $rule, "an ended PUBLISH").await;
            }

            #[tokio::test]
            async fn a_publish_this_endpoint_ended_is_not_stopped_when_dropped() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(accept(endpoint));
                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config(DRAFT)),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut handle = tokio::time::timeout(
                    PATIENCE,
                    conn.publish(namespace(), TRACK.to_vec(), v(5), Forward::DontForward),
                )
                .await
                .expect("the offer did not finish")
                .expect("offer the track");
                tokio::time::timeout(PATIENCE, conn.recv_response(&mut handle))
                    .await
                    .expect("the answer did not arrive")
                    .expect("read the answer")
                    .expect("an answer, not a bare FIN");
                conn.publish_done(&mut handle, v(0x2), v(0), Vec::new())
                    .await
                    .expect("end the offer");
                drop(handle);

                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                drop(conn);
            }
        }
    };
}

/// A Standalone Fetch on drafts 17-19, its range inline.
macro_rules! inline_fetch {
    ($id:ident $(, $extra:ident: $value:expr)*) => {
        Fetch {
            request_id: $id,
            $($extra: $value,)*
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: namespace(),
                track_name: TRACK.to_vec(),
                start_group: v(0),
                start_object: v(0),
                end_group: v(0),
                end_object: v(2),
            },
            parameters: Vec::new(),
        }
    };
}

/// A FETCH on drafts 20-23, its range a LOCATION_FILTER.
macro_rules! filter_fetch {
    ($id:ident, $module:ident) => {{
        use moqtap_client::$module::fill::LocationFilter;
        let filter = LocationFilter::range_to(0, 0, 0, 1).expect("an absolute range");
        Fetch {
            request_id: $id,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            parameters: vec![filter.parameter().expect("a LOCATION_FILTER parameter")],
        }
    }};
}

macro_rules! request_ok {
    () => {
        ControlMessage::RequestOk(RequestOk {
            parameters: Vec::new(),
            track_properties: Vec::new(),
        })
    };
}

gate!(
    draft17, "draft17", Draft17, "draft-17 Section 3.3.1",
    fetch: |id| inline_fetch!(id, required_request_id_delta: v(0)),
    accept: ControlMessage::PublishOk(PublishOk { parameters: Vec::new() }),
);
gate!(
    draft18, "draft18", Draft18, "draft-18 Section 3.3.2",
    fetch: |id| inline_fetch!(id),
    accept: request_ok!(),
);
gate!(
    draft19, "draft19", Draft19, "draft-19 Section 3.3.3",
    fetch: |id| inline_fetch!(id),
    accept: request_ok!(),
);
gate!(
    draft20, "draft20", Draft20, "draft-20 Section 3.3.3",
    fetch: |id| filter_fetch!(id, draft20),
    accept: request_ok!(),
);
gate!(
    draft21, "draft21", Draft21, "draft-21 Section 6.4.2.3",
    fetch: |id| filter_fetch!(id, draft21),
    accept: request_ok!(),
);
gate!(
    draft22, "draft22", Draft22, "draft-22 Section 6.4.2.3",
    fetch: |id| filter_fetch!(id, draft22),
    accept: request_ok!(),
);
gate!(
    draft23, "draft23", Draft23, "draft-23 Section 6.4.2.3",
    fetch: |id| filter_fetch!(id, draft23),
    accept: request_ok!(),
);

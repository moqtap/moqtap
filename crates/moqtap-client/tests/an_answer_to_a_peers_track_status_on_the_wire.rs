#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! The answer to a track status the peer asked for reaches the wire.
//!
//! The in-process half is in `a_track_status_the_peer_asks_for_is_answered.rs`,
//! which is where the rule and its draft range are written out. This file is
//! the other half: having an endpoint that will build the answer is not having
//! a route to the wire, and only a peer can see which bytes came out.
//!
//! Drafts 07 through 11 have no loopback harness here, so the ten `Connection`s
//! are covered by five gates. A cut in the write reaches all ten and is visible
//! on these five, which is what the recorded ablation measures.
//!
//! # Ablations, measured
//!
//! One cut was made, run and reverted, and it is this file's alone. In process
//! the endpoint's own record moves whether or not the message it built is
//! written, so a `Connection` method that built the answer and dropped it would
//! pass every gate in the other file.

mod common;

/// One draft's loopback gate.
macro_rules! track_status_answer_wire_gates {
    ($draft:ident, $feat:literal, $version:ident, $setup:tt, $cfg:tt, $request:tt,
     $answer:tt, $okmsg:ident) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The peer is the server here, so its Request IDs are the odd
            /// ones. Nothing reads it on the drafts whose request carries none.
            #[allow(dead_code)]
            const PEERS_ID: u64 = 1;

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            fn name() -> Vec<u8> {
                b"video".to_vec()
            }

            /// A ceiling large enough that no refusal here can be the
            /// ceiling's.
            fn setup_parameters() -> Vec<KeyValuePair> {
                vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }]
            }

            fn client_config() -> ClientConfig {
                crate::client_config!($cfg, $version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// Serve one connection: ask about a track, then report the next
            /// control message the client writes back.
            async fn one_exchange(server: quinn::Endpoint) -> AnyControlMessage {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(crate::server_setup!(
                    $setup,
                    $version,
                    setup_parameters()
                ))))
                .await
                .expect("write SERVER_SETUP");

                send.write_all(&encode(crate::wire_request!(
                    $request,
                    PEERS_ID,
                    namespace(),
                    name()
                )))
                .await
                .expect("write the request");

                tokio::time::timeout(PATIENCE, framed.read_control(false))
                    .await
                    .expect("the client was asked about a track and never answered")
                    .expect("read the answer")
                    .0
            }

            /// The answer to the peer's request reaches the peer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the client was asked about a track and never answered: Elapsed(())
            /// ```
            ///
            /// Made by building the answer and dropping it instead of writing it.
            /// The cut reaches all ten `Connection`s and reddens 5 tests, one on
            /// each draft with a loopback here: in process the endpoint's own
            /// record moves either way, so nothing but a peer can see the
            /// difference.
            #[tokio::test]
            async fn an_answer_reaches_the_peer() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(async move { one_exchange(server).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");
                conn.recv_and_dispatch().await.expect("the peer's request");
                crate::wire_answer!($answer, conn, PEERS_ID, namespace(), name())
                    .await
                    .expect("answer the peer's request");

                let read = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
                assert!(
                    matches!(read, AnyControlMessage::$version(ControlMessage::$okmsg(_))),
                    "the peer should read the answer; got {read:?}"
                );
            }
        }
    };
}

/// The client's configuration, which gained a draft field at draft-14 and lost
/// the extra offered versions at draft-15.
#[macro_export]
macro_rules! client_config {
    (versions, $version:ident, $params:expr) => {
        ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (draft_and_versions, $version:ident, $params:expr) => {
        ClientConfig {
            draft: DraftVersion::$version,
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (draft_only, $version:ident, $params:expr) => {
        ClientConfig {
            draft: DraftVersion::$version,
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
}

/// SERVER_SETUP, which carries a selected version up to draft-14 and leaves it
/// to the ALPN afterwards.
#[macro_export]
macro_rules! server_setup {
    (versioned, $version:ident, $params:expr) => {
        ServerSetup {
            selected_version: DraftVersion::$version.version_varint(),
            parameters: $params,
        }
    };
    (alpn, $version:ident, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// The request on the wire, which draft-13 renamed and reshaped.
#[macro_export]
macro_rules! wire_request {
    (ided, $id:expr, $ns:expr, $nm:expr) => {
        ControlMessage::TrackStatusRequest(TrackStatusRequest {
            request_id: v($id),
            track_namespace: $ns,
            track_name: $nm,
            parameters: Vec::new(),
        })
    };
    (subscribe13, $id:expr, $ns:expr, $nm:expr) => {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: v($id),
            track_namespace: $ns,
            track_name: $nm,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        })
    };
    (subscribe14, $id:expr, $ns:expr, $nm:expr) => {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: v($id),
            track_namespace: $ns,
            track_name: $nm,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        })
    };
    (simple, $id:expr, $ns:expr, $nm:expr) => {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: v($id),
            track_namespace: $ns,
            track_name: $nm,
            parameters: Vec::new(),
        })
    };
}

/// The connection method that answers one.
#[macro_export]
macro_rules! wire_answer {
    (by_id, $conn:expr, $id:expr, $ns:expr, $nm:expr) => {
        $conn.track_status(v($id), v(0), Location { group: v(0), object: v(0) }, Vec::new())
    };
    (named, $conn:expr, $id:expr, $ns:expr, $nm:expr) => {
        $conn.track_status_ok(v($id), v(0), GroupOrder::Ascending, Vec::new())
    };
    (request, $conn:expr, $id:expr, $ns:expr, $nm:expr) => {
        $conn.request_ok(v($id), Vec::new())
    };
}

track_status_answer_wire_gates!(
    draft12,
    "draft12",
    Draft12,
    versioned,
    versions,
    ided,
    by_id,
    TrackStatus
);
track_status_answer_wire_gates!(
    draft13,
    "draft13",
    Draft13,
    versioned,
    versions,
    subscribe13,
    named,
    TrackStatusOk
);
track_status_answer_wire_gates!(
    draft14,
    "draft14",
    Draft14,
    versioned,
    draft_and_versions,
    subscribe14,
    named,
    TrackStatusOk
);
track_status_answer_wire_gates!(
    draft15, "draft15", Draft15, alpn, draft_only, simple, request, RequestOk
);
track_status_answer_wire_gates!(
    draft16, "draft16", Draft16, alpn, draft_only, simple, request, RequestOk
);

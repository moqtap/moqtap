#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! The answer to a FETCH the peer sent reaches the wire, and the refusal of a
//! Joining Fetch reaches it carrying the code the section names.
//!
//! The in-process halves are in `a_fetch_the_peer_sends_is_answered.rs` and
//! `a_joining_fetch_names_a_live_subscription.rs`, which is where the rules
//! and their draft ranges are written out. This file is the other half:
//! having an endpoint that will build the message is not having a route to the
//! wire, and only a peer can see which bytes came out.
//!
//! # Why the refusal's code is read here
//!
//! The endpoint refuses to build the wrong one, which the in-process gates
//! measure. What they cannot see is whether the right one is written at all:
//! a `Connection` method that built the message and dropped it would pass
//! every one of them.
//!
//! # Ablations, measured
//!
//! Two cuts were made, run and reverted, and both are this file's alone. In
//! process the endpoint's own record moves whether or not the message it built
//! is written, so only a peer can tell a route to the wire from the absence of
//! one.

mod common;

/// One draft's two loopback gates.
macro_rules! fetch_answer_wire_gates {
    ($draft:ident, $feat:literal, $version:ident, $setup:tt, $cfg:tt, $fetchmsg:tt,
     $ok:tt, $refuse:tt, $code:literal, $sec:literal) => {
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
            use moqtap_codec::$draft::message::{
                ControlMessage, Fetch, FetchPayload, FetchType, ServerSetup,
            };

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The peer is the server here, so its Request IDs are the odd
            /// ones.
            const PEERS_FETCH: u64 = 1;

            /// An identifier no subscription of the peer's was ever opened
            /// under.
            const NEVER_USED: u64 = 3;

            /// The code the section names for a Joining Fetch that joins
            /// nothing.
            const NAMED: u64 = $code;

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
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

            /// Serve one connection: send `fetch`, then report the answer the
            /// client writes back.
            async fn one_exchange(
                server: quinn::Endpoint,
                fetch: ControlMessage,
            ) -> AnyControlMessage {
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

                send.write_all(&encode(fetch)).await.expect("write the FETCH");

                tokio::time::timeout(PATIENCE, framed.read_control(false))
                    .await
                    .expect("the client was sent a FETCH and never answered it")
                    .expect("read the answer")
                    .0
            }

            /// A standalone FETCH the peer sends, which needs no subscription.
            fn standalone() -> ControlMessage {
                ControlMessage::Fetch(crate::wire_fetch!(
                    $fetchmsg,
                    PEERS_FETCH,
                    FetchPayload::Standalone {
                        track_namespace: TrackNamespace(vec![b"conformance".to_vec()]),
                        track_name: b"alpha".to_vec(),
                        start_group: v(0),
                        start_object: v(0),
                        end_group: v(1),
                        end_object: v(0),
                    }
                ))
            }

            /// A Joining Fetch naming a subscription this session never had.
            fn joins_nothing() -> ControlMessage {
                ControlMessage::Fetch(crate::wire_fetch!(
                    $fetchmsg,
                    PEERS_FETCH,
                    FetchPayload::Joining {
                        joining_request_id: v(NEVER_USED),
                        joining_start: v(0),
                    }
                ))
            }

            /// The FETCH_OK answering the peer's FETCH reaches the peer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the client was sent a FETCH and never answered it: Elapsed(())
            /// ```
            ///
            /// Made by building the FETCH_OK and dropping it instead of writing it. It
            /// reddens five tests and only this gate: in process the endpoint's own
            /// record moves either way, so nothing but a peer can see the difference.
            #[tokio::test]
            async fn a_fetch_ok_reaches_the_peer() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(async move { one_exchange(server, standalone()).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");
                conn.recv_and_dispatch().await.expect("the peer's FETCH");
                crate::wire_ok!($ok, conn, PEERS_FETCH).await.expect("answer the peer's FETCH");

                let answer = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
                assert!(
                    matches!(answer, AnyControlMessage::$version(ControlMessage::FetchOk(_))),
                    "the peer should read a FETCH_OK; got {answer:?}"
                );
            }

            /// The refusal of a Joining Fetch that joins nothing reaches the
            /// peer, carrying the code the section names.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the client was sent a FETCH and never answered it: Elapsed(())
            /// ```
            ///
            /// The same cut on the refusal, which is a method of its own up to
            /// draft-14 and a branch of REQUEST_ERROR's on the two after it. It
            /// reddens five tests and only this gate.
            #[tokio::test]
            async fn a_joining_fetchs_refusal_reaches_the_peer() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(async move { one_exchange(server, joins_nothing()).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");
                conn.recv_and_dispatch().await.expect("the peer's Joining Fetch");
                crate::wire_refuse!($refuse, conn, PEERS_FETCH, NAMED)
                    .await
                    .expect("refuse the peer's Joining Fetch");

                let answer = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
                let code = crate::refusal_code!($refuse, $version, answer);
                assert_eq!(
                    code, NAMED,
                    "Section {} names one code for a Joining Fetch that joins nothing; \
                     the refusal carried {} instead",
                    $sec, code
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

/// The FETCH on the wire, which lost its priority and group order at draft-15.
#[macro_export]
macro_rules! wire_fetch {
    (priority, $id:expr, $payload:expr) => {
        Fetch {
            request_id: v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: match $payload {
                FetchPayload::Standalone { .. } => FetchType::Standalone,
                FetchPayload::Joining { .. } => FetchType::RelativeJoining,
            },
            fetch_payload: $payload,
            parameters: Vec::new(),
        }
    };
    (bare, $id:expr, $payload:expr) => {
        Fetch {
            request_id: v($id),
            fetch_type: match $payload {
                FetchPayload::Standalone { .. } => FetchType::Standalone,
                FetchPayload::Joining { .. } => FetchType::RelativeJoining,
            },
            fetch_payload: $payload,
            parameters: Vec::new(),
        }
    };
}

/// The connection method that answers a FETCH.
#[macro_export]
macro_rules! wire_ok {
    (location, $conn:expr, $id:expr) => {
        $conn.fetch_ok(
            v($id),
            GroupOrder::Ascending,
            0,
            Location { group: v(1), object: v(0) },
            Vec::new(),
        )
    };
    (split, $conn:expr, $id:expr) => {
        $conn.fetch_ok(v($id), 0, v(1), v(0), Vec::new())
    };
    (extensions, $conn:expr, $id:expr) => {
        $conn.fetch_ok(v($id), 0, v(1), v(0), Vec::new(), Vec::new())
    };
}

/// The connection method that refuses one.
#[macro_export]
macro_rules! wire_refuse {
    (fetch_error, $conn:expr, $id:expr, $code:expr) => {
        $conn.fetch_error(v($id), v($code), b"joins nothing".to_vec())
    };
    (request_error, $conn:expr, $id:expr, $code:expr) => {
        $conn.request_error(v($id), v($code), b"joins nothing".to_vec())
    };
    (retry, $conn:expr, $id:expr, $code:expr) => {
        $conn.request_error(v($id), v($code), v(0), b"joins nothing".to_vec())
    };
}

/// Reading the code back off whichever message the draft refuses with.
#[macro_export]
macro_rules! refusal_code {
    (fetch_error, $version:ident, $answer:expr) => {
        match $answer {
            AnyControlMessage::$version(ControlMessage::FetchError(ref e)) => {
                e.error_code.into_inner()
            }
            other => panic!("the peer should read a FETCH_ERROR; got {other:?}"),
        }
    };
    (request_error, $version:ident, $answer:expr) => {
        match $answer {
            AnyControlMessage::$version(ControlMessage::RequestError(ref e)) => {
                e.error_code.into_inner()
            }
            other => panic!("the peer should read a REQUEST_ERROR; got {other:?}"),
        }
    };
    (retry, $version:ident, $answer:expr) => {
        match $answer {
            AnyControlMessage::$version(ControlMessage::RequestError(ref e)) => {
                e.error_code.into_inner()
            }
            other => panic!("the peer should read a REQUEST_ERROR; got {other:?}"),
        }
    };
}

fetch_answer_wire_gates!(
    draft12,
    "draft12",
    Draft12,
    versioned,
    versions,
    priority,
    location,
    fetch_error,
    0x7,
    "8.16"
);
fetch_answer_wire_gates!(
    draft13,
    "draft13",
    Draft13,
    versioned,
    versions,
    priority,
    location,
    fetch_error,
    0x7,
    "8.16"
);
fetch_answer_wire_gates!(
    draft14,
    "draft14",
    Draft14,
    versioned,
    draft_and_versions,
    priority,
    location,
    fetch_error,
    0x7,
    "9.16.2"
);
fetch_answer_wire_gates!(
    draft15,
    "draft15",
    Draft15,
    alpn,
    draft_only,
    bare,
    split,
    request_error,
    0x32,
    "9.16.2"
);
fetch_answer_wire_gates!(
    draft16, "draft16", Draft16, alpn, draft_only, bare, extensions, retry, 0x32, "9.16.2"
);

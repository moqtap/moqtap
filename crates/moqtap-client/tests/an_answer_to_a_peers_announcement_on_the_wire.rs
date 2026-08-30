#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! The answer to an announcement the peer made reaches the wire, and so does
//! the cancellation that revokes it.
//!
//! The in-process halves are in `an_announcement_the_peer_makes_is_answered.rs`
//! and `a_cancellation_revokes_an_acceptance.rs`, which is where the rules and
//! their draft ranges are written out. This file is the other half: having an
//! endpoint that will build the message is not having a route to the wire, and
//! only a peer can see which bytes came out.
//!
//! # Why the cancellation is read here too
//!
//! It is the one message of the three that this crate could not send at all on
//! seven of the ten drafts and sent about the wrong announcement on the other
//! three. In process the endpoint's own record moves whether or not what it
//! built is written, so a `Connection` method that built the message and
//! dropped it would pass every gate in the other two files.
//!
//! # Ablations, measured
//!
//! Two cuts were made, run and reverted, and both are this file's alone. Each
//! reaches every one of the ten `Connection`s and is visible on the five drafts
//! that have a loopback here: in process the endpoint's own record moves
//! whether or not the message it built is written, so only a peer can tell a
//! route to the wire from the absence of one.

mod common;

/// One draft's two loopback gates.
macro_rules! announce_answer_wire_gates {
    ($draft:ident, $feat:literal, $version:ident, $setup:tt, $cfg:tt, $advert:tt,
     $accept:tt, $cancel:tt, $okmsg:ident, $cancelmsg:ident) => {
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
            /// ones.
            const PEERS_ID: u64 = 1;

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
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

            /// Serve one connection: announce, then report the next `wanted`
            /// control messages the client writes back.
            async fn one_exchange(
                server: quinn::Endpoint,
                wanted: usize,
            ) -> Vec<AnyControlMessage> {
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

                send.write_all(&encode(ControlMessage::$advert(crate::wire_advert!(
                    $advert,
                    PEERS_ID,
                    namespace()
                ))))
                .await
                .expect("write the announcement");

                let mut read = Vec::new();
                for _ in 0..wanted {
                    read.push(
                        tokio::time::timeout(PATIENCE, framed.read_control(false))
                            .await
                            .expect("the client was sent an announcement and never answered it")
                            .expect("read the answer")
                            .0,
                    );
                }
                read
            }

            /// The acceptance of the peer's announcement reaches the peer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the client was sent an announcement and never answered it: Elapsed(())
            /// ```
            ///
            /// Made by building the acceptance and dropping it instead of
            /// writing it. The cut reaches all ten `Connection`s and reddens 10
            /// tests, which is both gates on the five drafts that have a
            /// loopback here: in process the endpoint's own record moves either
            /// way, so nothing but a peer can see the difference.
            #[tokio::test]
            async fn an_acceptance_reaches_the_peer() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(async move { one_exchange(server, 1).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");
                conn.recv_and_dispatch().await.expect("the peer's announcement");
                crate::wire_accept!($accept, conn, PEERS_ID)
                    .await
                    .expect("answer the peer's announcement");

                let read = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
                assert!(
                    matches!(read[0], AnyControlMessage::$version(ControlMessage::$okmsg(_))),
                    "the peer should read the acceptance; got {:?}",
                    read[0]
                );
            }

            /// And so does the cancellation that revokes it afterwards.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the client was sent an announcement and never answered it: Elapsed(())
            /// ```
            ///
            /// The same cut on the cancellation, which seven of the ten drafts
            /// could not send at all before this crate built it. It reaches all ten
            /// `Connection`s and reddens 5 tests, this gate alone. The peer
            /// reads two messages here, so the acceptance ahead of it is not
            /// what the assertion sees.
            #[tokio::test]
            async fn a_cancellation_reaches_the_peer() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(async move { one_exchange(server, 2).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");
                conn.recv_and_dispatch().await.expect("the peer's announcement");
                crate::wire_accept!($accept, conn, PEERS_ID)
                    .await
                    .expect("answer the peer's announcement");
                crate::wire_cancel!($cancel, conn, PEERS_ID, namespace())
                    .await
                    .expect("revoke the acceptance");

                let read = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
                assert!(
                    matches!(read[1], AnyControlMessage::$version(ControlMessage::$cancelmsg(_))),
                    "the peer should read the cancellation; got {:?}",
                    read[1]
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

/// The advertisement on the wire, which draft-14 renamed.
#[macro_export]
macro_rules! wire_advert {
    (Announce, $id:expr, $ns:expr) => {
        Announce { request_id: v($id), track_namespace: $ns, parameters: Vec::new() }
    };
    (PublishNamespace, $id:expr, $ns:expr) => {
        PublishNamespace { request_id: v($id), track_namespace: $ns, parameters: Vec::new() }
    };
}

/// The connection method that accepts one.
#[macro_export]
macro_rules! wire_accept {
    (announce_ok, $conn:expr, $id:expr) => {
        $conn.announce_ok(v($id))
    };
    (publish_namespace_ok, $conn:expr, $id:expr) => {
        $conn.publish_namespace_ok(v($id))
    };
    (request_ok, $conn:expr, $id:expr) => {
        $conn.request_ok(v($id), Vec::new())
    };
}

/// The connection method that revokes the acceptance.
#[macro_export]
macro_rules! wire_cancel {
    (by_ns, $conn:expr, $id:expr, $ns:expr) => {
        $conn.announce_cancel($ns, v(1), b"expired".to_vec())
    };
    (renamed_ns, $conn:expr, $id:expr, $ns:expr) => {
        $conn.publish_namespace_cancel($ns, v(1), b"expired".to_vec())
    };
    (renamed_id, $conn:expr, $id:expr, $ns:expr) => {
        $conn.publish_namespace_cancel(v($id), v(1), b"expired".to_vec())
    };
}

announce_answer_wire_gates!(
    draft12,
    "draft12",
    Draft12,
    versioned,
    versions,
    Announce,
    announce_ok,
    by_ns,
    AnnounceOk,
    AnnounceCancel
);
announce_answer_wire_gates!(
    draft13,
    "draft13",
    Draft13,
    versioned,
    versions,
    Announce,
    announce_ok,
    by_ns,
    AnnounceOk,
    AnnounceCancel
);
announce_answer_wire_gates!(
    draft14,
    "draft14",
    Draft14,
    versioned,
    draft_and_versions,
    PublishNamespace,
    publish_namespace_ok,
    renamed_ns,
    PublishNamespaceOk,
    PublishNamespaceCancel
);
announce_answer_wire_gates!(
    draft15,
    "draft15",
    Draft15,
    alpn,
    draft_only,
    PublishNamespace,
    request_ok,
    renamed_ns,
    RequestOk,
    PublishNamespaceCancel
);
announce_answer_wire_gates!(
    draft16,
    "draft16",
    Draft16,
    alpn,
    draft_only,
    PublishNamespace,
    request_ok,
    renamed_id,
    RequestOk,
    PublishNamespaceCancel
);

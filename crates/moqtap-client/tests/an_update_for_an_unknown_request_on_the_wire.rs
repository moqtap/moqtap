#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! A peer that updates a request this session never carried is closed on, over
//! QUIC, with the code the section names.
//!
//! The in-process half is in
//! `an_update_for_an_unknown_request_ends_the_session.rs`, which is where the
//! rule and its draft range are written out. This file is the other half:
//! having the code in the close table is not having the route to the wire, and
//! only a peer can see which number the CONNECTION_CLOSE carries.
//!
//! # Why the code is read and not just the close
//!
//! Each of these drafts names PROTOCOL_VIOLATION for this rule and other codes
//! for its neighbours - Duplicate Track Alias for the Track Alias rules,
//! Invalid Request ID for the parity ones. A gate that observed only that the
//! connection ended would pass with any of them, and which rule was broken is
//! the whole of what the peer is being told.
//!
//! # Ablations, measured
//!
//! Two cuts were made, run and reverted, and both are this file's alone. From
//! inside the process the session ends whichever code the table names, so only
//! a peer can tell an arm that is missing from one that carries the wrong
//! number.

mod common;

/// One draft's loopback gate.
macro_rules! unknown_update_wire_gate {
    ($draft:ident, $feat:literal, $version:ident, $setup:tt, $cfg:tt, $updmsg:tt,
     $sec:literal) => {
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
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup};

            /// The session termination code this draft names for the rule.
            const PROTOCOL_VIOLATION: u64 = 0x3;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// An identifier this session never carries a request under. It
            /// has the peer's parity, so nothing else can refuse it first.
            const NEVER_USED: u64 = 9;

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

            /// Serve one connection: update a request that never existed, and
            /// report the close the client sends.
            async fn expect_close(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                #[allow(unused_mut)]
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(crate::server_setup!(
                    $setup,
                    $version,
                    setup_parameters()
                ))))
                .await
                .expect("write SERVER_SETUP");

                send.write_all(&encode(crate::update_message!($updmsg, NEVER_USED)))
                    .await
                    .expect("write the update");

                let reason = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the client was sent an update for nothing and never closed");
                match reason {
                    quinn::ConnectionError::ApplicationClosed(frame) => {
                        assert_eq!(
                            u64::from(frame.error_code),
                            PROTOCOL_VIOLATION,
                            "Section {} answers an update naming a request the session \
                             never carried with PROTOCOL_VIOLATION; the close carried \
                             {} instead",
                            $sec,
                            u64::from(frame.error_code)
                        );
                        let text = String::from_utf8_lossy(&frame.reason).to_string();
                        assert!(
                            text.contains("never carried"),
                            "the close reason should name the rule that was broken; \
                             got {text:?}"
                        );
                    }
                    other => panic!("expected an application close, got {other:?}"),
                }
            }

            /// An update for a request this session never carried ends the
            /// QUIC connection, with the code the section names.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the new arm from `EndpointError::session_error_code`
            /// leaves the endpoint refusing the update and ending its own
            /// session, and leaves the connection layer with no code to close
            /// with:
            ///
            /// ```text
            /// the client was sent an update for nothing and never closed: Elapsed(())
            /// ```
            ///
            /// It reddens ten tests: this gate on all five drafts and the in-process
            /// one on the same five, where the close code is read off the error rather
            /// than off the wire.
            ///
            /// Answering that arm with a different code leaves the close going
            /// out with the wrong number on it, which is the failure only a
            /// peer can see:
            ///
            /// ```text
            /// assertion `left == right` failed: Section 8.10 answers an update naming a request
            /// the session never carried with PROTOCOL_VIOLATION; the close carried 4 instead
            ///   left: 4
            ///  right: 3
            /// ```
            ///
            /// Made by answering the arm with INVALID_REQUEST_ID, which is the code the
            /// neighbouring rule about Request IDs uses. It reddens ten tests, and only
            /// the five here can tell the two codes apart: in process the session ends
            /// either way.
            #[tokio::test]
            async fn an_update_for_nothing_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move { expect_close(server).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("the peer updated a request that never existed");
                let text = err.to_string();
                assert!(
                    text.contains("never carried"),
                    "the error should name the rule; got {text:?}"
                );

                // Longer than the peer's own wait, so that when the close never
                // arrives it is the peer's message that fails the test.
                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
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

/// The update, in the three shapes these five drafts give it.
#[macro_export]
macro_rules! update_message {
    (reuses_id, $names:expr) => {
        ControlMessage::SubscribeUpdate(moqtap_codec::draft12::message::SubscribeUpdate {
            request_id: v($names),
            start_group: v(0),
            start_object: v(0),
            end_group: v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: Vec::new(),
        })
    };
    (reuses_id13, $names:expr) => {
        ControlMessage::SubscribeUpdate(moqtap_codec::draft13::message::SubscribeUpdate {
            request_id: v($names),
            start_group: v(0),
            start_object: v(0),
            end_group: v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: Vec::new(),
        })
    };
    (own_id, $names:expr) => {
        ControlMessage::SubscribeUpdate(moqtap_codec::draft14::message::SubscribeUpdate {
            request_id: v(1),
            subscription_request_id: v($names),
            start_location: Location { group: v(0), object: v(0) },
            end_group: v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: Vec::new(),
        })
    };
    (params, $names:expr) => {
        ControlMessage::SubscribeUpdate(moqtap_codec::draft15::message::SubscribeUpdate {
            request_id: v(1),
            subscription_request_id: v($names),
            parameters: Vec::new(),
        })
    };
    (renamed, $names:expr) => {
        ControlMessage::RequestUpdate(moqtap_codec::draft16::message::RequestUpdate {
            request_id: v(1),
            existing_request_id: v($names),
            parameters: Vec::new(),
        })
    };
}

unknown_update_wire_gate!(draft12, "draft12", Draft12, versioned, versions, reuses_id, "8.10");
unknown_update_wire_gate!(draft13, "draft13", Draft13, versioned, versions, reuses_id13, "8.10");
unknown_update_wire_gate!(
    draft14,
    "draft14",
    Draft14,
    versioned,
    draft_and_versions,
    own_id,
    "9.10"
);
unknown_update_wire_gate!(draft15, "draft15", Draft15, alpn, draft_only, params, "9.11");
unknown_update_wire_gate!(draft16, "draft16", Draft16, alpn, draft_only, renamed, "9.11");

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
))]

//! A subscriber that gives two tracks one Track Alias is closed on, over QUIC.
//!
//! The in-process half is in
//! `a_track_alias_names_one_track_at_the_publisher.rs`, which is where the
//! rule and its draft range are written out. This file is the other half:
//! having the code in the close table is not having the route to the wire, and
//! only a peer can see which number the CONNECTION_CLOSE carries.
//!
//! Two gates drive the rule from its two ends. In the first the peer sends two
//! SUBSCRIBEs with one alias, and this client is the publisher that must
//! close. In the second the peer answers one of this client's own SUBSCRIBEs
//! with a 'Retry Track Alias' error offering an alias another of them is
//! already using, and this client is the subscriber that must close. The two
//! are different sections and different code paths that end at the same close.
//!
//! # Why the code is read and not just the close
//!
//! Each of these drafts names Duplicate Track Alias for this rule and Protocol
//! Violation for most of its neighbours. A gate that observed only that the
//! connection ended would pass with either, and which rule was broken is the
//! whole of what the peer is being told.
//!
//! # Ablations, measured
//!
//! Three cuts are recorded below. Two are this file's alone — taking the code
//! out of the close table, and putting the wrong code in it — because from
//! inside the process the session ends either way and only a peer can see
//! which number the close carried. The third is one the in-process file
//! records too, seen here from the other side of a real connection.

mod common;

/// One draft's two loopback gates.
macro_rules! publisher_alias_wire_gate {
    ($draft:ident, $feat:literal, $version:ident, $submsg:tt, $errmsg:tt, $sub:tt,
     $role:tt, $peers_first:literal, $close_code:literal, $retry:literal,
     $sub_sec:literal, $err_sec:literal) => {
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
            use moqtap_codec::$draft::message::{
                ControlMessage, ServerSetup, Subscribe, SubscribeError,
            };

            /// The session termination code this draft names for the rule.
            const DUPLICATE_TRACK_ALIAS: u64 = $close_code;

            /// The SUBSCRIBE_ERROR code that makes the Track Alias field an
            /// offer to retry with.
            const RETRY_TRACK_ALIAS: u64 = $retry;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The alias the two tracks are both asked to answer to.
            const ALIAS: u64 = 7;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            /// The peer's first identifier. Draft-11 gave Request IDs a
            /// parity, and the peer here is the server.
            const PEERS_FIRST: u64 = $peers_first;

            /// A ceiling large enough that no refusal here can be the
            /// ceiling's. This endpoint advertises it, so it is what bounds
            /// the peer's own identifiers. Draft-07 also requires a ROLE of
            /// both endpoints, and is the only one of the five that does.
            fn setup_parameters() -> Vec<KeyValuePair> {
                #[allow(unused_mut)]
                let mut params =
                    vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }];
                crate::add_role!($role, params);
                params
            }

            fn client_config() -> ClientConfig {
                ClientConfig {
                    additional_versions: Vec::new(),
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: setup_parameters(),
                }
            }

            fn server_setup() -> ServerSetup {
                ServerSetup {
                    selected_version: DraftVersion::$version.version_varint(),
                    parameters: setup_parameters(),
                }
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// The identifier a SUBSCRIBE the client sent carries, or a panic
            /// naming what arrived instead.
            fn subscribe_id_of(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => {
                        crate::id_of!($submsg, s)
                    }
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// The close the client sent, or a panic saying what came instead.
            fn expect_duplicate_alias(reason: quinn::ConnectionError, section: &str, what: &str) {
                match reason {
                    quinn::ConnectionError::ApplicationClosed(frame) => {
                        assert_eq!(
                            u64::from(frame.error_code),
                            DUPLICATE_TRACK_ALIAS,
                            "{section} answers {what} with Duplicate Track Alias; the close \
                             carried {} instead",
                            u64::from(frame.error_code)
                        );
                        let text = String::from_utf8_lossy(&frame.reason).to_string();
                        assert!(
                            text.contains("track alias"),
                            "the close reason should name the rule that was broken; \
                             got {text:?}"
                        );
                    }
                    other => panic!("expected an application close, got {other:?}"),
                }
            }

            /// Serve one connection: subscribe to two tracks under one alias
            /// and report the close the client sends.
            async fn expect_close(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                #[allow(unused_mut)]
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                for (id, track) in [(PEERS_FIRST, ALPHA), (PEERS_FIRST + 2, BETA)] {
                    let request = crate::peer_subscribe!($submsg, id, ALIAS, track);
                    send.write_all(&encode(ControlMessage::Subscribe(request)))
                        .await
                        .expect("write SUBSCRIBE");
                }

                let reason = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the client was given one alias for two tracks and never closed");
                expect_duplicate_alias(reason, $sub_sec, "one alias naming two tracks");
            }

            /// Serve one connection: read this client's two SUBSCRIBEs and
            /// answer the second with a retry offering the first one's alias.
            async fn expect_close_after_retry(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                #[allow(unused_mut)]
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                framed.read_control(false).await.expect("read the first SUBSCRIBE");
                let (second, _) = framed.read_control(false).await.expect("read the second");
                let id = subscribe_id_of(&second);

                let refusal = crate::peer_rejects!($errmsg, id, RETRY_TRACK_ALIAS, ALIAS);
                send.write_all(&encode(ControlMessage::SubscribeError(refusal)))
                    .await
                    .expect("write SUBSCRIBE_ERROR");

                let reason = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the client was offered an alias it was using and never closed");
                expect_duplicate_alias(reason, $err_sec, "a retry alias that is already in use");
            }

            /// Two of the peer's subscriptions under one alias end the QUIC
            /// connection, with the code the section names.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the new arm from `EndpointError::session_error_code`
            /// leaves the endpoint refusing the SUBSCRIBE and ending its own
            /// session, and leaves the connection layer with no code to close
            /// with:
            ///
            /// ```text
            /// the client was given one alias for two tracks and never closed: Elapsed(())
            /// ```
            ///
            /// It reddens twenty-five tests across two files, because every
            /// gate that reads the code back off an error reads it out of that
            /// one arm.
            ///
            /// Answering that arm with `ProtocolViolation` instead leaves the
            /// close going out with the wrong number on it, which is the
            /// failure only a peer can see. It reddens the ten gates in this
            /// file and nothing in process, where the session ends either way:
            ///
            /// ```text
            /// assertion `left == right` failed: draft-08 Section 7.4 answers one alias
            /// naming two tracks with Duplicate Track Alias; the close carried 3 instead
            ///   left: 3
            ///  right: 4
            /// ```
            #[tokio::test]
            async fn one_alias_for_two_tracks_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move { expect_close(server).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                conn.recv_and_dispatch().await.expect("the peer's first SUBSCRIBE");
                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("the peer gave one alias to two tracks and was not refused");
                let text = err.to_string();
                assert!(
                    text.contains("track alias"),
                    "the error should name the rule; got {text:?}"
                );

                // Longer than the peer's own wait, so that when the close never
                // arrives it is the peer's message that fails the test.
                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// A retry offering an alias this client is already using ends the
            /// QUIC connection, with the same code.
            ///
            /// A different section, a different message and a different code
            /// path from the gate above, which is why it is a second gate
            /// rather than a second assertion.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `conflicting_retry_alias` call from
            /// `receive_subscribe_error` leaves the retry accepted and nothing
            /// closes:
            ///
            /// ```text
            /// the client was offered an alias it was using and never closed: Elapsed(())
            /// ```
            ///
            /// It reddens ten tests: this gate on all five drafts and the
            /// in-process one on the same five. The gate above stays green,
            /// which is what makes the retry a rule of its own.
            #[tokio::test]
            async fn a_retry_alias_in_use_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move { expect_close_after_retry(server).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                crate::subscribe_for!($sub, conn, ALIAS, namespace(), ALPHA)
                    .await
                    .expect("the ALPHA subscription");
                crate::subscribe_for!($sub, conn, ALIAS + 1, namespace(), BETA)
                    .await
                    .expect("the BETA subscription");

                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("the retry offered an alias another track was using");
                let text = err.to_string();
                assert!(
                    text.contains("track alias"),
                    "the error should name the rule; got {text:?}"
                );

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }
        }
    };
}

/// Draft-07 requires a ROLE parameter of both endpoints.
#[macro_export]
macro_rules! add_role {
    (role, $params:expr) => {
        $params.push(KeyValuePair { key: v(0x00), value: KvpValue::Varint(v(3)) })
    };
    (none, $params:expr) => {};
}

/// A SUBSCRIBE from the peer, in the three shapes it takes across the five
/// drafts.
#[macro_export]
macro_rules! peer_subscribe {
    (end_object, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            subscribe_id: v($id),
            track_alias: v($alias),
            track_namespace: namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            end_object: None,
            parameters: Vec::new(),
        }
    };
    (end_group, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            subscribe_id: v($id),
            track_alias: v($alias),
            track_namespace: namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (forward, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: v($id),
            track_alias: v($alias),
            track_namespace: namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
}

/// The identifier field, under the name each draft gives it.
#[macro_export]
macro_rules! id_of {
    (end_object, $msg:expr) => {
        $msg.subscribe_id
    };
    (end_group, $msg:expr) => {
        $msg.subscribe_id
    };
    (forward, $msg:expr) => {
        $msg.request_id
    };
}

/// A SUBSCRIBE_ERROR from the peer, offering `alias` under `code`.
#[macro_export]
macro_rules! peer_rejects {
    (subscribe_id, $id:expr, $code:expr, $alias:expr) => {
        SubscribeError {
            subscribe_id: $id,
            error_code: v($code),
            reason_phrase: b"no".to_vec(),
            track_alias: v($alias),
        }
    };
    (request_id, $id:expr, $code:expr, $alias:expr) => {
        SubscribeError {
            request_id: $id,
            error_code: v($code),
            reason_phrase: b"no".to_vec(),
            track_alias: v($alias),
        }
    };
}

/// A SUBSCRIBE this client sends. Draft-11 takes the Filter Type as a varint,
/// the four before it as a named type.
#[macro_export]
macro_rules! subscribe_for {
    (named, $conn:expr, $alias:expr, $ns:expr, $name:expr) => {
        $conn.subscribe(
            v($alias),
            $ns,
            $name.to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
    };
    (varint, $conn:expr, $alias:expr, $ns:expr, $name:expr) => {
        $conn.subscribe(v($alias), $ns, $name.to_vec(), 128, GroupOrder::Ascending, v(0x2))
    };
}

publisher_alias_wire_gate!(
    draft07,
    "draft07",
    Draft07,
    end_object,
    subscribe_id,
    named,
    role,
    0,
    0x4,
    0x2,
    "draft-07 Section 6.4",
    "draft-07 Section 6.16"
);
publisher_alias_wire_gate!(
    draft08,
    "draft08",
    Draft08,
    end_group,
    subscribe_id,
    named,
    none,
    0,
    0x4,
    0x6,
    "draft-08 Section 7.4",
    "draft-08 Section 7.16"
);
publisher_alias_wire_gate!(
    draft09,
    "draft09",
    Draft09,
    end_group,
    subscribe_id,
    named,
    none,
    0,
    0x4,
    0x6,
    "draft-09 Section 7.4",
    "draft-09 Section 7.16"
);
publisher_alias_wire_gate!(
    draft10,
    "draft10",
    Draft10,
    end_group,
    subscribe_id,
    named,
    none,
    0,
    0x4,
    0x6,
    "draft-10 Section 8.6",
    "draft-10 Section 8.8"
);
publisher_alias_wire_gate!(
    draft11,
    "draft11",
    Draft11,
    forward,
    request_id,
    varint,
    none,
    1,
    0x5,
    0x6,
    "draft-11 Section 8.7",
    "draft-11 Section 8.9"
);

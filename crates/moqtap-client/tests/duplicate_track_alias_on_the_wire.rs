#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! A publisher that gives two tracks one Track Alias is closed on, over QUIC.
//!
//! The in-process half is in `duplicate_track_alias_closes_the_session.rs`,
//! which is where the rule and its draft range are written out. This file is
//! the other half of the same rule: having the code in the close table is not
//! having the route to the wire, and only a peer can see which number the
//! CONNECTION_CLOSE carries.
//!
//! Two gates drive the rule from its two ends. In the first the peer answers
//! two SUBSCRIBEs with one alias; in the second it offers a track with PUBLISH,
//! waits for this client to accept it, and only then answers a SUBSCRIBE with
//! the alias that offer is holding. The second is the one that needs the
//! accepted offer to have been written down: a client that judged a PUBLISH
//! and kept nothing would pass the first and not the second.
//!
//! Five drafts are here — 12 through 16, the ones whose control plane is a
//! single bidirectional stream this peer can serve with raw quinn. Drafts 17,
//! 18 and 19 put control on a pair of unidirectional streams and every request
//! on a bidirectional stream of its own; their loopback gate lives beside the
//! peer that already enforces that topology, in `uni_control_plane.rs`.
//!
//! # Why the peer answers requests it has read
//!
//! A SUBSCRIBE_OK names the request it answers, and a gate whose peer guessed
//! the Request IDs would keep passing if the client stopped sending SUBSCRIBEs
//! altogether. The peer reads both requests off the wire and answers each with
//! the id it carried, so the second answer is an answer to the second
//! subscription by construction.
//!
//! # Why the code is read and not just the close
//!
//! Each of these drafts names DUPLICATE_TRACK_ALIAS for this rule and
//! PROTOCOL_VIOLATION for most of its neighbours. A gate that observed only
//! that the connection ended would pass with either, and which rule was broken
//! is the whole of what the peer is being told.
//!
//! # Ablations, measured
//!
//! Recorded on the gate below. A third, deleting the check in
//! `receive_subscribe_ok`, is recorded in the in-process file and reddens this
//! one too:
//!
//! ```text
//! the second answer reused a live track's alias and was accepted:
//! SubscribeOk(SubscribeOk { request_id: VarInt(2), track_alias: VarInt(7), parameters: [] })
//! ```

mod common;

/// One draft's loopback gate.
macro_rules! duplicate_alias_wire_gate {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt, $ok:tt,
     $pubmsg:tt, $accept:tt, $reject:tt, $refusal:pat, $code_name:literal,
     $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            #[allow(unused_imports)]
            use moqtap_codec::types::{ContentExists, GroupOrder};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{
                ControlMessage, Publish, ServerSetup, SubscribeOk,
            };

            /// The session termination code all five name for this rule.
            const DUPLICATE_TRACK_ALIAS: u64 = 0x5;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The alias the peer hands to both tracks.
            const ALIAS: u64 = 7;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            /// The peer's first Request ID: odd, because the peer is the
            /// server.
            const PEERS_FIRST: u64 = 1;

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
                crate::config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::server_setup_for!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// The Request ID a SUBSCRIBE the client sent carries, or a panic
            /// naming what arrived instead.
            fn request_id_of(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => s.request_id,
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// The close the client sent, or a panic saying what came
            /// instead of one.
            fn expect_duplicate_alias(reason: quinn::ConnectionError) {
                match reason {
                    quinn::ConnectionError::ApplicationClosed(frame) => {
                        assert_eq!(
                            u64::from(frame.error_code),
                            DUPLICATE_TRACK_ALIAS,
                            concat!(
                                "Section ",
                                $section,
                                " answers one alias naming two live tracks with ",
                                $code_name,
                                "; the close carried {} instead"
                            ),
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

            /// Serve one connection: complete the setup exchange, offer ALPHA
            /// and read the refusal this client answers with.
            async fn expect_refusal(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let offer = crate::publish_for!($pubmsg, v(PEERS_FIRST), v(ALIAS), ALPHA);
                send.write_all(&encode(ControlMessage::Publish(offer)))
                    .await
                    .expect("write PUBLISH");

                let (answer, _) = framed.read_control(false).await.expect("read the refusal");
                assert!(
                    matches!(answer, AnyControlMessage::$version($refusal)),
                    "the client rejected the offer and sent {answer:?}"
                );
            }

            /// Serve one connection: complete the setup exchange, offer ALPHA
            /// under `ALIAS` with a PUBLISH, wait for this client to accept it,
            /// then answer its SUBSCRIBE for BETA with the same alias.
            async fn expect_close_after_publish(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let offer = crate::publish_for!($pubmsg, v(PEERS_FIRST), v(ALIAS), ALPHA);
                send.write_all(&encode(ControlMessage::Publish(offer)))
                    .await
                    .expect("write PUBLISH");

                let (answer, _) = framed.read_control(false).await.expect("read PUBLISH_OK");
                assert!(
                    matches!(answer, AnyControlMessage::$version(ControlMessage::PublishOk(_))),
                    "the client was offered a track and answered {answer:?}"
                );

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                let id = request_id_of(&request);
                let reply = crate::subscribe_ok_for!($ok, id, v(ALIAS));
                send.write_all(&encode(ControlMessage::SubscribeOk(reply)))
                    .await
                    .expect("write SUBSCRIBE_OK");

                let reason = tokio::time::timeout(PATIENCE, conn.closed()).await.expect(
                    "the client took an alias its own accepted PUBLISH held and never closed",
                );
                expect_duplicate_alias(reason);
            }

            /// Serve one connection: complete the setup exchange, answer both
            /// SUBSCRIBEs with `ALIAS`, and report the close the client sends.
            async fn expect_close(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                for _ in 0..2 {
                    let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                    let id = request_id_of(&request);
                    let answer = crate::subscribe_ok_for!($ok, id, v(ALIAS));
                    send.write_all(&encode(ControlMessage::SubscribeOk(answer)))
                        .await
                        .expect("write SUBSCRIBE_OK");
                }

                let reason = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the client refused the second answer but never closed the connection");
                expect_duplicate_alias(reason);
            }

            /// A second track answered with a live track's alias ends the QUIC
            /// connection, with the code the section names.
            ///
            /// The first answer is accepted, which is what makes the second one
            /// the violation rather than the pair of them: a client that
            /// refused both would pass a gate built on the second alone.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the new arm from `EndpointError::session_error_code`
            /// leaves the endpoint refusing the answer and ending its own
            /// session, and leaves the connection layer with no code to close
            /// with:
            ///
            /// ```text
            /// the client refused the second answer but never closed the connection: Elapsed(())
            /// ```
            ///
            /// Answering that arm with `ProtocolViolation` instead leaves the
            /// close going out with the wrong number on it, which is the
            /// failure only a peer can see:
            ///
            /// ```text
            /// assertion `left == right` failed: Section 9.10 answers one alias naming
            /// two live tracks with DUPLICATE_TRACK_ALIAS; the close carried 3 instead
            ///   left: 3
            ///  right: 5
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

                crate::subscribe_for!($sub, conn, namespace(), ALPHA)
                    .await
                    .expect("the first SUBSCRIBE");
                crate::subscribe_for!($sub, conn, namespace(), BETA)
                    .await
                    .expect("the second SUBSCRIBE");

                conn.recv_and_dispatch().await.expect("the first SUBSCRIBE_OK");
                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("the second answer reused a live track's alias and was accepted");
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

            /// A SUBSCRIBE_OK taking the alias this client's own accepted
            /// PUBLISH holds ends the QUIC connection, with the code the
            /// section names.
            ///
            /// The peer waits for the PUBLISH_OK before it sends the clashing
            /// answer, so what is being measured is the alias an *established*
            /// offer holds and not merely one that arrived.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Recording nothing for an accepted PUBLISH - dropping the
            /// `track_bindings.insert` from the inbound PUBLISH path - leaves
            /// the alias free and the SUBSCRIBE_OK accepted. The client sees
            /// that before the peer's own wait runs out, so it is the client
            /// half of the gate that reports it:
            ///
            /// ```text
            /// the SUBSCRIBE_OK took the alias an accepted PUBLISH held and was accepted:
            /// SubscribeOk(SubscribeOk { request_id: VarInt(0), track_alias: VarInt(7), parameters: [] })
            /// ```
            ///
            /// Taking the `ControlMessage::Publish` arm out of
            /// `receive_message` stops the offer reaching the flow at all,
            /// and the peer never gets its answer:
            ///
            /// ```text
            /// accept the peer's offer: Endpoint(UnknownRequest(1))
            /// ```
            #[tokio::test]
            async fn an_accepted_publish_holds_its_alias_over_quic() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move { expect_close_after_publish(server).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                conn.recv_and_dispatch().await.expect("the peer's PUBLISH");
                assert_eq!(
                    conn.endpoint()
                        .pending_publish(v(PEERS_FIRST))
                        .expect("the offer that arrived over QUIC must be on record")
                        .track_alias,
                    v(ALIAS),
                    "the record should carry the alias that arrived on the wire"
                );
                crate::accept_publish_for!($accept, conn, v(PEERS_FIRST))
                    .await
                    .expect("accept the peer's offer");

                crate::subscribe_for!($sub, conn, namespace(), BETA)
                    .await
                    .expect("the SUBSCRIBE for a second track");
                let err = conn.recv_and_dispatch().await.expect_err(
                    "the SUBSCRIBE_OK took the alias an accepted PUBLISH held and was accepted",
                );
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

            /// A rejected offer is answered on the wire, with the message this
            /// draft rejects requests with.
            ///
            /// The accepting gate above cannot see this: a connection that
            /// could accept an offer and not refuse one would pass it, and the
            /// two answers are two methods writing two different messages.
            /// Drafts 15 and 16 answer with REQUEST_ERROR and the other three
            /// with PUBLISH_ERROR, which is the only thing that differs.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Taking the `ControlMessage::Publish` arm out of
            /// `receive_message`, so that the offer never reaches the record
            /// the refusal is built from:
            ///
            /// ```text
            /// reject the peer's offer: Endpoint(UnknownRequest(1))
            /// ```
            #[tokio::test]
            async fn a_rejected_offer_is_answered_over_quic() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move { expect_refusal(server).await });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                conn.recv_and_dispatch().await.expect("the peer's PUBLISH");
                assert_eq!(
                    conn.endpoint()
                        .pending_publish(v(PEERS_FIRST))
                        .expect("the offer that arrived over QUIC must be on record")
                        .track_alias,
                    v(ALIAS),
                    "the record should carry the alias that arrived on the wire"
                );
                crate::reject_publish_for!($reject, conn, v(PEERS_FIRST))
                    .await
                    .expect("reject the peer's offer");

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// The endpoint this file drives is the same one the in-process
            /// gates drive, and it starts out able to accept an answer.
            ///
            /// Without this, a client that had stopped subscribing altogether
            /// would still satisfy the gate above by never reaching the second
            /// answer.
            #[test]
            fn the_endpoint_builds_two_subscribes_for_two_tracks() {
                let mut ep =
                    Endpoint::new(moqtap_client::$draft::session::request_id::Role::Client);
                ep.connect().expect("a client may open");
                crate::endpoint_setup_for!($setup, ep, DraftVersion::$version);
                let (first, _) = crate::endpoint_subscribe_for!($sub, ep, namespace(), ALPHA)
                    .expect("the first SUBSCRIBE");
                let (second, _) = crate::endpoint_subscribe_for!($sub, ep, namespace(), BETA)
                    .expect("the second SUBSCRIBE");
                assert_ne!(
                    first, second,
                    "two subscriptions need two Request IDs, or the peer's second answer \
                     would be an answer to the first"
                );
            }
        }
    };
}

/// `ClientConfig`, in each of the three shapes it takes across the five drafts.
#[macro_export]
macro_rules! config_for {
    (early, $version:expr, $params:expr) => {
        ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (both, $version:expr, $params:expr) => {
        ClientConfig {
            draft: $version,
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (late, $version:expr, $params:expr) => {
        ClientConfig {
            draft: $version,
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
}

/// SERVER_SETUP, with and without the Selected Version drafts 15 and 16 dropped.
#[macro_export]
macro_rules! server_setup_for {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// The setup exchange, driven at an `Endpoint` rather than a `Connection`.
#[macro_export]
macro_rules! endpoint_setup_for {
    (versioned, $ep:expr, $version:expr) => {{
        let _ = $ep
            .send_client_setup(vec![$version.version_varint()], setup_parameters())
            .expect("CLIENT_SETUP");
        $ep.receive_server_setup(&server_setup()).expect("SERVER_SETUP");
    }};
    (plain, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup(setup_parameters()).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&server_setup()).expect("SERVER_SETUP");
    }};
}

/// SUBSCRIBE_OK, in the three shapes it takes across the five drafts.
#[macro_export]
macro_rules! subscribe_ok_for {
    (rich, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            expires: VarInt::from_u64(0).unwrap(),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $alias:expr) => {
        SubscribeOk { request_id: $id, track_alias: $alias, parameters: Vec::new() }
    };
    (ext, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// `Connection::subscribe`, in the three shapes it takes across the five
/// drafts, asking for a subscription to the largest object of `$name` and
/// nothing more.
#[macro_export]
macro_rules! subscribe_for {
    (varint, $conn:expr, $ns:expr, $name:expr) => {
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            Vec::new(),
        )
    };
    (filter, $conn:expr, $ns:expr, $name:expr) => {
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    };
    (params, $conn:expr, $ns:expr, $name:expr) => {
        $conn.subscribe($ns, $name.to_vec(), Vec::new())
    };
}

/// `Endpoint::subscribe`, which returns the message rather than sending it.
#[macro_export]
macro_rules! endpoint_subscribe_for {
    (varint, $ep:expr, $ns:expr, $name:expr) => {
        $ep.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            Vec::new(),
        )
    };
    (filter, $ep:expr, $ns:expr, $name:expr) => {
        $ep.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    };
    (params, $ep:expr, $ns:expr, $name:expr) => {
        $ep.subscribe($ns, $name.to_vec(), Vec::new())
    };
}

/// `Connection::publish_error`. Draft-16's REQUEST_ERROR carries a retry
/// interval the other four have no field for.
#[macro_export]
macro_rules! reject_publish_for {
    (plain, $conn:expr, $id:expr) => {
        $conn.publish_error($id, VarInt::from_u64(1).unwrap(), b"no".to_vec())
    };
    (retry, $conn:expr, $id:expr) => {
        $conn.publish_error(
            $id,
            VarInt::from_u64(1).unwrap(),
            VarInt::from_u64(0).unwrap(),
            b"no".to_vec(),
        )
    };
}

/// The PUBLISH the peer offers, in the three shapes it takes across the five
/// drafts.
#[macro_export]
macro_rules! publish_for {
    (rich, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $id,
            track_namespace: namespace(),
            track_name: $name.to_vec(),
            track_alias: $alias,
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            forward: moqtap_codec::types::Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $id,
            track_namespace: namespace(),
            track_name: $name.to_vec(),
            track_alias: $alias,
            parameters: Vec::new(),
        }
    };
    (ext, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $id,
            track_namespace: namespace(),
            track_name: $name.to_vec(),
            track_alias: $alias,
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// `Connection::publish_ok`, in the four shapes it takes across the five
/// drafts.
#[macro_export]
macro_rules! accept_publish_for {
    (varint, $conn:expr, $id:expr) => {
        $conn.publish_ok(
            $id,
            moqtap_codec::types::Forward::Forward,
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            None,
            None,
            None,
        )
    };
    (filter, $conn:expr, $id:expr) => {
        $conn.publish_ok(
            $id,
            moqtap_codec::types::Forward::Forward,
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            None,
            None,
            None,
        )
    };
    (location, $conn:expr, $id:expr) => {
        $conn.publish_ok(
            $id,
            moqtap_codec::types::Forward::Forward,
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            None,
            None,
        )
    };
    (params, $conn:expr, $id:expr) => {
        $conn.publish_ok($id, Vec::new())
    };
}

duplicate_alias_wire_gate!(
    draft12,
    "draft12",
    Draft12,
    early,
    versioned,
    varint,
    rich,
    rich,
    varint,
    plain,
    ControlMessage::PublishError(_),
    "'Duplicate Track Alias'",
    "8.8"
);
duplicate_alias_wire_gate!(
    draft13,
    "draft13",
    Draft13,
    early,
    versioned,
    filter,
    rich,
    rich,
    filter,
    plain,
    ControlMessage::PublishError(_),
    "'Duplicate Track Alias'",
    "8.8"
);
duplicate_alias_wire_gate!(
    draft14,
    "draft14",
    Draft14,
    both,
    versioned,
    filter,
    rich,
    rich,
    location,
    plain,
    ControlMessage::PublishError(_),
    "DUPLICATE_TRACK_ALIAS",
    "9.8"
);
duplicate_alias_wire_gate!(
    draft15,
    "draft15",
    Draft15,
    late,
    plain,
    params,
    plain,
    plain,
    params,
    plain,
    ControlMessage::RequestError(_),
    "DUPLICATE_TRACK_ALIAS",
    "9.10"
);
duplicate_alias_wire_gate!(
    draft16,
    "draft16",
    Draft16,
    late,
    plain,
    params,
    ext,
    ext,
    params,
    retry,
    ControlMessage::RequestError(_),
    "DUPLICATE_TRACK_ALIAS",
    "9.10"
);

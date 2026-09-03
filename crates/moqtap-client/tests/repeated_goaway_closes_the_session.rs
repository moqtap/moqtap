//! A GOAWAY that repeats one already received ends the session, on the wire.
//!
//! All fourteen drafts state it, each in its own GOAWAY section, and each with
//! the verb and the code in the same sentence. Draft-07 Section 6.3: "The
//! client MUST terminate the session with a Protocol Violation (Section 3.5) if
//! it receives multiple GOAWAY messages." Four things move under that sentence
//! and no two
//! of them move together. The verb is "terminate" through draft-15 and "close"
//! from draft-16. The code is spelled "Protocol Violation" through draft-13
//! and PROTOCOL_VIOLATION from draft-14. The subject is "The client" on
//! draft-07 alone and "The endpoint" from draft-08. And the scope changes
//! last: drafts 18 through 20 replace "multiple GOAWAY messages" with "more than
//! one GOAWAY on the control stream or on a single request stream".
//!
//! # Why draft-07 names the client where the others name the endpoint
//!
//! It is not a narrowing. The sentence beside it makes *any* GOAWAY at a
//! draft-07 server a session close, so a draft-07 server never reaches a
//! second one and between them the two sentences cover both roles. From
//! draft-08 the direction rule is about the URI a GOAWAY carries rather than
//! about the message, so an empty GOAWAY at a server is legal there and the
//! repeat rule has to name both roles to reach it.
//!
//! # Why the first GOAWAY is sent and not assumed
//!
//! An endpoint that refused every GOAWAY would satisfy a gate that sent only
//! the second one, and it would be wrong in the more damaging direction: a
//! GOAWAY is what a conforming peer sends to say it is going away. The peer
//! here sends one, has it accepted, and only then sends the second, so the
//! gate can tell a repeat that is refused from a message kind that is refused.
//!
//! # Why drafts 17 to 19 need a different peer
//!
//! Control travels on a client-opened bidirectional stream through draft-16
//! and on a pair of unidirectional streams from draft-17, so the peer that
//! delivers the two GOAWAYs is a different peer on either side of that line.
//! The rule is the same and both macros assert the same two things.
//!
//! # Why drafts 18 and 19 gate a third thing
//!
//! Those two count per stream. A gate that only sent two GOAWAYs on the
//! control stream would pass against an endpoint that counted per session and
//! closed on the second GOAWAY anywhere - which would end sessions over the
//! migration of two separate requests, something the same section permits in
//! the sentence above. So they also assert that one GOAWAY on each of two
//! request streams is accepted, and that the second on one of them is not.
//!
//! # Ablations, measured
//!
//! Four cuts, each made in every draft that carries the check, and each
//! recorded on the test that caught it. The first two are made in all thirteen
//! at once and fail in opposite directions: deleting the table arm leaves the
//! endpoint refusing the second GOAWAY and ending its own session with no code
//! for the connection layer to close with, so the thirteen wire gates fail and
//! the thirteen in-process gates pass; dropping the state move is the other way
//! round.
//!
//! The other two are drafts 18 and 19 only. Counting per session rather than
//! per stream fails at the *second request's first* GOAWAY, which is the
//! acceptance half rather than the refusal. Removing the GOAWAY arm from the
//! peer-opened dispatcher fails one draft's own shipped behaviour and one that
//! was already right, in the same place.

mod common;

/// One draft's two gates, drafts 07 through 16, where the control stream is a
/// bidirectional stream the client opens.
///
/// `$cfg` and `$setup` name the shapes the setup types take on this draft:
/// `ClientConfig` gained a `draft` field at 14 and lost `additional_versions`
/// at 15, `ServerSetup` dropped its Selected Version at 15, `send_client_setup`
/// lost its version list in the same place, and draft-07 alone requires a ROLE
/// parameter in both directions.
macro_rules! repeated_goaway_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $section:literal,
     $role:path) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::KeyValuePair;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, GoAway, ServerSetup};
            use $role as Role;

            /// Session termination code Protocol Violation, 0x3 in every
            /// draft's registry of them.
            const PROTOCOL_VIOLATION: u64 = 0x3;

            const PATIENCE: Duration = Duration::from_secs(10);

            fn setup_parameters() -> Vec<KeyValuePair> {
                crate::goaway_setup_params_for!($setup)
            }

            fn client_config() -> ClientConfig {
                crate::goaway_config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::goaway_server_setup_for!($setup, DraftVersion::$version, setup_parameters())
            }

            /// A GOAWAY a client may legally receive on this draft. The URI is
            /// what a server offers a client, so the direction rule stated in
            /// the same section is not what refuses the second one.
            fn goaway() -> GoAway {
                GoAway { new_session_uri: b"https://elsewhere.example/moq".to_vec() }
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            fn active_client() -> Endpoint {
                let mut endpoint = Endpoint::new(Role::Client);
                endpoint.connect().expect("connect");
                crate::goaway_send_client_setup_for!(
                    $setup,
                    endpoint,
                    DraftVersion::$version,
                    setup_parameters()
                );
                endpoint.receive_server_setup(&server_setup()).expect("SERVER_SETUP");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Active,
                    "the gate needs a running session to end"
                );
                endpoint
            }

            /// The peer says it is going away twice, and the client closes the
            /// QUIC connection.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `RepeatedGoAway` arm from `session_error_code`:
            ///
            /// ```text
            /// the client refused the second GOAWAY but never closed the connection: Elapsed(())
            /// ```
            #[tokio::test]
            async fn a_second_goaway_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");

                    let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                    let mut framed_recv =
                        crate::common::frame_uni_recv(recv, DraftVersion::$version);
                    framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

                    let mut out = Vec::new();
                    out.extend_from_slice(&encode(ControlMessage::ServerSetup(server_setup())));
                    out.extend_from_slice(&encode(ControlMessage::GoAway(goaway())));
                    out.extend_from_slice(&encode(ControlMessage::GoAway(goaway())));
                    send.write_all(&out).await.expect("write the setup and both GOAWAYs");

                    let reason = tokio::time::timeout(PATIENCE, conn.closed()).await.expect(
                        "the client refused the second GOAWAY but never closed the connection",
                    );

                    match reason {
                        quinn::ConnectionError::ApplicationClosed(frame) => {
                            assert_eq!(
                                u64::from(frame.error_code),
                                PROTOCOL_VIOLATION,
                                concat!(
                                    "Section ",
                                    $section,
                                    " answers a repeated GOAWAY with a Protocol Violation; the \
                                     close carried {} instead"
                                ),
                                u64::from(frame.error_code)
                            );
                            let text = String::from_utf8_lossy(&frame.reason).to_string();
                            assert!(
                                text.contains("second GOAWAY"),
                                "the close reason should name the rule that was broken; got \
                                 {text:?}"
                            );
                        }
                        other => panic!("expected an application close, got {other:?}"),
                    }
                });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                conn.recv_and_dispatch().await.expect("the first GOAWAY must be accepted");

                let err =
                    conn.recv_and_dispatch().await.expect_err("a second GOAWAY must be refused");
                let text = err.to_string();
                assert!(
                    text.contains("second GOAWAY"),
                    "the error should name the rule; got {text:?}"
                );

                // Longer than the peer's own wait, so that when the close never
                // arrives it is the peer's message that fails the test.
                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// The violation ends the endpoint's own session and not only the
            /// connection carrying it.
            ///
            /// The first GOAWAY leaves the session Draining, which is the
            /// state the rule is measured from, so `Closed` here can only have
            /// come from the second.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Dropping the `fail_session` call from `receive_goaway`:
            ///
            /// ```text
            /// assertion `left == right` failed: the violation was reported but
            /// the session was left running: Draining
            ///   left: Draining
            ///  right: Closed
            /// ```
            #[test]
            fn a_second_goaway_ends_the_endpoints_session() {
                let mut endpoint = active_client();

                endpoint
                    .receive_message(ControlMessage::GoAway(goaway()))
                    .expect("the first GOAWAY must be accepted");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Draining,
                    "a GOAWAY the endpoint accepted did not start the drain"
                );

                endpoint
                    .receive_message(ControlMessage::GoAway(goaway()))
                    .expect_err("a second GOAWAY must be refused");

                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Closed,
                    "the violation was reported but the session was left running: {:?}",
                    endpoint.session_state()
                );
            }
        }
    };
}

/// The setup parameters an endpoint sends. Draft-07 requires a ROLE from both
/// sides before a session is usable, and is the only draft in this range that
/// requires anything at all.
#[macro_export]
macro_rules! goaway_setup_params_for {
    (with_role) => {{
        let mut role = Vec::new();
        moqtap_codec::varint::VarInt::from_u64(3).unwrap().encode(&mut role); // PubSub
        vec![KeyValuePair {
            key: moqtap_codec::varint::VarInt::from_u64(0x00).unwrap(),
            value: moqtap_codec::kvp::KvpValue::Bytes(role),
        }]
    }};
    (versioned) => {
        Vec::new()
    };
    (plain) => {
        Vec::new()
    };
}

/// `ClientConfig`, in each of the three shapes it takes across the ten drafts.
#[macro_export]
macro_rules! goaway_config_for {
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
macro_rules! goaway_server_setup_for {
    (with_role, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// CLIENT_SETUP, which lost its Supported Versions list at draft-15.
#[macro_export]
macro_rules! goaway_send_client_setup_for {
    (with_role, $endpoint:expr, $version:expr, $params:expr) => {
        $endpoint.send_client_setup(vec![$version.version_varint()], $params).expect("CLIENT_SETUP")
    };
    (versioned, $endpoint:expr, $version:expr, $params:expr) => {
        $endpoint.send_client_setup(vec![$version.version_varint()], $params).expect("CLIENT_SETUP")
    };
    (plain, $endpoint:expr, $version:expr, $params:expr) => {
        $endpoint.send_client_setup($params).expect("CLIENT_SETUP")
    };
}

repeated_goaway_gates!(
    draft07,
    "draft07",
    Draft07,
    early,
    with_role,
    "6.3",
    moqtap_client::draft07::endpoint::Role
);
repeated_goaway_gates!(
    draft08,
    "draft08",
    Draft08,
    early,
    versioned,
    "7.3",
    moqtap_client::draft08::endpoint::Role
);
repeated_goaway_gates!(
    draft09,
    "draft09",
    Draft09,
    early,
    versioned,
    "7.3",
    moqtap_client::draft09::endpoint::Role
);
repeated_goaway_gates!(
    draft10,
    "draft10",
    Draft10,
    early,
    versioned,
    "8.3",
    moqtap_client::draft10::endpoint::Role
);
repeated_goaway_gates!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    "8.4",
    moqtap_client::draft11::session::request_id::Role
);
repeated_goaway_gates!(
    draft12,
    "draft12",
    Draft12,
    early,
    versioned,
    "8.4",
    moqtap_client::draft12::session::request_id::Role
);
repeated_goaway_gates!(
    draft13,
    "draft13",
    Draft13,
    early,
    versioned,
    "8.4",
    moqtap_client::draft13::session::request_id::Role
);
repeated_goaway_gates!(
    draft14,
    "draft14",
    Draft14,
    both,
    versioned,
    "9.4",
    moqtap_client::draft14::session::request_id::Role
);
repeated_goaway_gates!(
    draft15,
    "draft15",
    Draft15,
    late,
    plain,
    "9.4",
    moqtap_client::draft15::session::request_id::Role
);
repeated_goaway_gates!(
    draft16,
    "draft16",
    Draft16,
    late,
    plain,
    "9.4",
    moqtap_client::draft16::session::request_id::Role
);

/// One draft's two gates, drafts 17 through 19, where each peer opens a
/// unidirectional control stream of its own and SETUP is one message rather
/// than a client and a server half.
///
/// `$goaway` names which of the two GOAWAY shapes this draft has: draft-18
/// alone carries an optional Request ID, "present only when sent on the
/// control stream", which draft-19 removed again.
macro_rules! uni_repeated_goaway_gates {
    ($draft:ident, $feat:literal, $version:ident, $section:literal, $goaway:tt, $role:path) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, GoAway, Setup};
            use $role as Role;

            /// Session termination code PROTOCOL_VIOLATION, 0x3 in every
            /// draft's registry of them.
            const PROTOCOL_VIOLATION: u64 = 0x3;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// A GOAWAY a client may legally receive. The URI is what a server
            /// offers a client, so the direction rule stated in the same
            /// section is not what refuses the second one.
            pub(super) fn goaway() -> GoAway {
                crate::goaway_for!($goaway)
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            pub(super) fn active_client() -> Endpoint {
                let mut endpoint = Endpoint::new(Role::Client);
                endpoint.connect().expect("connect");
                let _ = endpoint.send_setup(Vec::new()).expect("SETUP");
                endpoint.receive_setup(&Setup { options: Vec::new() }).expect("peer SETUP");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Active,
                    "the gate needs a running session to end"
                );
                endpoint
            }

            /// The peer says it is going away twice on its control stream, and
            /// the client closes the QUIC connection.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `RepeatedGoAway` arm from `session_error_code`:
            ///
            /// ```text
            /// the client refused the second GOAWAY but never closed the connection: Elapsed(())
            /// ```
            #[tokio::test]
            async fn a_second_goaway_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");

                    // The client's own control stream carries its SETUP.
                    let mut client_control = conn.accept_uni().await.expect("accept_uni");
                    let mut seen = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while seen.len() < 3 {
                        match client_control.read(&mut chunk).await.expect("read SETUP") {
                            Some(n) => seen.extend_from_slice(&chunk[..n]),
                            None => break,
                        }
                    }
                    assert!(!seen.is_empty(), "the client sent no SETUP");

                    let mut our_control = conn.open_uni().await.expect("open_uni");
                    let mut out = Vec::new();
                    out.extend_from_slice(&encode(ControlMessage::Setup(Setup {
                        options: Vec::new(),
                    })));
                    out.extend_from_slice(&encode(ControlMessage::GoAway(goaway())));
                    out.extend_from_slice(&encode(ControlMessage::GoAway(goaway())));
                    our_control.write_all(&out).await.expect("write the SETUP and both GOAWAYs");

                    let reason = tokio::time::timeout(PATIENCE, conn.closed()).await.expect(
                        "the client refused the second GOAWAY but never closed the connection",
                    );

                    match reason {
                        quinn::ConnectionError::ApplicationClosed(frame) => {
                            assert_eq!(
                                u64::from(frame.error_code),
                                PROTOCOL_VIOLATION,
                                concat!(
                                    "Section ",
                                    $section,
                                    " answers a repeated GOAWAY with PROTOCOL_VIOLATION; the \
                                     close carried {} instead"
                                ),
                                u64::from(frame.error_code)
                            );
                            let text = String::from_utf8_lossy(&frame.reason).to_string();
                            assert!(
                                text.contains("second GOAWAY"),
                                "the close reason should name the rule that was broken; got \
                                 {text:?}"
                            );
                        }
                        other => panic!("expected an application close, got {other:?}"),
                    }
                });

                let config = ClientConfig {
                    draft: DraftVersion::$version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                };
                let mut conn =
                    Connection::connect(&addr.to_string(), config).await.expect("client connect");

                conn.recv_and_dispatch().await.expect("the first GOAWAY must be accepted");

                let err =
                    conn.recv_and_dispatch().await.expect_err("a second GOAWAY must be refused");
                let text = err.to_string();
                assert!(
                    text.contains("second GOAWAY"),
                    "the error should name the rule; got {text:?}"
                );

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// The violation ends the endpoint's own session and not only the
            /// connection carrying it.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Dropping the `fail_session` call from `receive_goaway`:
            ///
            /// ```text
            /// assertion `left == right` failed: the violation was reported but
            /// the session was left running: Draining
            ///   left: Draining
            ///  right: Closed
            /// ```
            #[test]
            fn a_second_goaway_ends_the_endpoints_session() {
                let mut endpoint = active_client();

                endpoint
                    .receive_message(ControlMessage::GoAway(goaway()))
                    .expect("the first GOAWAY must be accepted");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Draining,
                    "a GOAWAY the endpoint accepted did not start the drain"
                );

                endpoint
                    .receive_message(ControlMessage::GoAway(goaway()))
                    .expect_err("a second GOAWAY must be refused");

                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Closed,
                    "the violation was reported but the session was left running: {:?}",
                    endpoint.session_state()
                );
            }
        }
    };
}

/// The GOAWAY message, in the two shapes drafts 17 through 19 give it.
#[macro_export]
macro_rules! goaway_for {
    (plain) => {
        GoAway {
            new_session_uri: b"https://elsewhere.example/moq".to_vec(),
            timeout: VarInt::from_u64(0).unwrap(),
        }
    };
    (with_request_id) => {
        GoAway {
            new_session_uri: b"https://elsewhere.example/moq".to_vec(),
            timeout: VarInt::from_u64(0).unwrap(),
            request_id: None,
        }
    };
}

uni_repeated_goaway_gates!(
    draft17,
    "draft17",
    Draft17,
    "9.5",
    plain,
    moqtap_client::draft17::session::request_id::Role
);
uni_repeated_goaway_gates!(
    draft18,
    "draft18",
    Draft18,
    "10.4",
    with_request_id,
    moqtap_client::draft18::session::request_id::Role
);
uni_repeated_goaway_gates!(
    draft19,
    "draft19",
    Draft19,
    "10.4",
    plain,
    moqtap_client::draft19::session::request_id::Role
);
uni_repeated_goaway_gates!(
    draft20,
    "draft20",
    Draft20,
    "10.4",
    plain,
    moqtap_client::draft20::session::request_id::Role
);

/// The per-stream half of the rule, on the two drafts that state it.
///
/// Section 10.4 of both: "The endpoint MUST close the session with a
/// PROTOCOL_VIOLATION (Section 3.5) if it receives more than one GOAWAY on the
/// control stream or on a single request stream." The clause about the request
/// stream is the half these two drafts added. The sentence above it is what
/// makes the second half necessary - "A GOAWAY MAY also be sent on a request
/// stream to initiate migration of that individual request" - so a GOAWAY on
/// each of two request streams is two migrations and not a repeat.
macro_rules! request_stream_goaway_gates {
    ($draft:ident, $feat:literal, $mod:ident) => {
        #[cfg(feature = $feat)]
        mod $mod {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::$draft::message::{ControlMessage, Setup};

            use super::$draft::{active_client, goaway};

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            /// A SUBSCRIBE the peer would send, built by an endpoint in the
            /// peer's role so that the Request ID carries the peer's parity.
            ///
            /// Hand-numbering it would work until the parity rule moved, and
            /// then the gate would be failing on the id rather than on the
            /// GOAWAY.
            fn peer_subscribe() -> ControlMessage {
                let mut peer = Endpoint::new(Role::Server);
                peer.connect().expect("connect");
                let _ = peer.send_setup(Vec::new()).expect("SETUP");
                peer.receive_setup(&Setup { options: Vec::new() }).expect("peer SETUP");
                let (_, msg) = peer
                    .subscribe(namespace(), b"peer".to_vec(), Vec::new())
                    .expect("the peer's own endpoint builds the peer's SUBSCRIBE");
                msg
            }

            /// A GOAWAY on each of two request streams is accepted, and a
            /// second on one of them is not.
            ///
            /// The acceptance is the half that makes the refusal mean
            /// something: an endpoint that counted GOAWAYs per session rather
            /// than per stream would refuse the second request's migration
            /// too, and would be ending sessions over traffic the sentence
            /// above the rule permits.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Replacing the per-stream set with the session state - the shape
            /// the control-stream half uses:
            ///
            /// ```text
            /// a GOAWAY migrating a different request is not a repeat: RepeatedGoAwayOnRequestStream(2)
            /// ```
            #[test]
            fn the_count_is_per_stream() {
                let mut endpoint = active_client();
                let (first, _) = endpoint
                    .subscribe(namespace(), b"one".to_vec(), Vec::new())
                    .expect("a subscription to migrate");
                let (second, _) = endpoint
                    .subscribe(namespace(), b"two".to_vec(), Vec::new())
                    .expect("a second subscription to migrate");

                endpoint
                    .receive_response_on_stream(first, ControlMessage::GoAway(goaway()))
                    .expect("a GOAWAY migrating the first request must be accepted");
                endpoint
                    .receive_response_on_stream(second, ControlMessage::GoAway(goaway()))
                    .expect("a GOAWAY migrating a different request is not a repeat");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Active,
                    "two requests being migrated is not a session ending"
                );

                endpoint
                    .receive_response_on_stream(first, ControlMessage::GoAway(goaway()))
                    .expect_err("a second GOAWAY on one request's stream must be refused");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Closed,
                    "the violation was reported but the session was left running: {:?}",
                    endpoint.session_state()
                );
            }

            /// The same rule on a request stream the *peer* opened.
            ///
            /// Section 10.4 puts no direction on it - "A GOAWAY MAY also be
            /// sent on a request stream to initiate migration of that
            /// individual request" - and a request the peer opened is a
            /// request stream. Both halves are gated because they failed
            /// separately: draft-18 refused the first GOAWAY here outright,
            /// which dropped a conforming relay's migration on the floor, and
            /// neither draft counted the second.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Removing the GOAWAY arm from `receive_on_peer_request_stream`:
            ///
            /// ```text
            /// a GOAWAY migrating the peer's own request must be accepted: UnexpectedOnPeerRequestStream(GoAway)
            /// ```
            #[test]
            fn a_peer_opened_request_stream_counts_the_same_way() {
                let mut endpoint = active_client();
                let id = endpoint
                    .receive_request_on_stream(&peer_subscribe())
                    .expect("the peer's SUBSCRIBE opens a request stream");

                endpoint
                    .receive_on_peer_request_stream(id, ControlMessage::GoAway(goaway()))
                    .expect("a GOAWAY migrating the peer's own request must be accepted");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Active,
                    "migrating one request is not a session ending"
                );

                endpoint
                    .receive_on_peer_request_stream(id, ControlMessage::GoAway(goaway()))
                    .expect_err("a second GOAWAY on that stream must be refused");
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Closed,
                    "the violation was reported but the session was left running: {:?}",
                    endpoint.session_state()
                );
            }
        }
    };
}

request_stream_goaway_gates!(draft18, "draft18", draft18_request_streams);
request_stream_goaway_gates!(draft19, "draft19", draft19_request_streams);
request_stream_goaway_gates!(draft20, "draft20", draft20_request_streams);

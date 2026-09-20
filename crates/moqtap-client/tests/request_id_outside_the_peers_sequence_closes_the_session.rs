//! A Request ID that is not the peer's to spend ends the session, on the wire.
//!
//! Six drafts state the rule in one sentence and name one code for it.
//! Draft-11 Section 8.1: "If an endpoint receives a Request ID that is not
//! valid for the peer, or a new request with a Request ID that is not
//! expected, it MUST close the session with Invalid Request ID." Drafts 12 and
//! 13 repeat it word for word; draft-14 moves it to Section 9.1 and spells the
//! code INVALID_REQUEST_ID; drafts 15 and 16 rewrite the second half as "not
//! the next in sequence or exceeds the received MAX_REQUEST_ID".
//!
//! Drafts 07 through 10 have no gate because they have no rule: they have
//! Subscribe IDs rather than Request IDs, and the sentence enters at 11.
//! Drafts 17 through 20 have one already — they state the rule as an incorrect
//! least significant bit and a duplicate Request ID, and their close tables
//! carry both.
//!
//! # Two conditions, two gates
//!
//! The sentence names two things and they fail in different places. "Not valid
//! for the peer" is parity: an ID out of this endpoint's own half of the
//! space, which is refused on sight and needs no history. "Not expected" — the
//! same thing draft-15 renames "not the next in sequence" — is the sequence: an
//! ID of the peer's own parity, below the ceiling, that the peer has already
//! spent. One input cannot reach both, so there is one input for each.
//!
//! A third condition, which drafts 15 and 16 add to the same sentence, is an
//! ID past the received MAX_REQUEST_ID. It is answered with the code the
//! MAX_REQUEST_ID section names instead, for reasons written at each draft's
//! `validate_peer_request_id`, and it has gates of its own.
//!
//! # Why the code is read and not just the close
//!
//! Section 8.1 names a different code from the PROTOCOL_VIOLATION most of the
//! neighbouring rules use, and a different one again from the
//! TOO_MANY_REQUESTS the ceiling half uses. A gate that observed only that the
//! connection ended would pass with any of the three, and the peer's whole
//! reason for being told is which rule it broke. So the loopback gates read
//! the number off the close frame.
//!
//! # Why this crate builds the peer's SUBSCRIBE
//!
//! The refusal has to be about the Request ID and nothing else, and a SUBSCRIBE
//! assembled by hand is six different field layouts with six chances to be
//! refused for an unrelated reason. Each draft's own endpoint builds one
//! instead, so it conforms by construction, and only the ID field is
//! overwritten — from the same message each time, so two SUBSCRIBEs sent one
//! after the other differ in exactly the field under test.
//!
//! # Ablations, measured
//!
//! Each cut is made in all six drafts at once, because six copies of one rule
//! need six measurements and a single `--no-fail-fast` run produces all of
//! them. They fail in three different places.
//!
//! Deleting the `InvalidRequestId` arm from each
//! `EndpointError::session_error_code` leaves the endpoint refusing the
//! request and ending its own session, and leaves the connection layer with
//! no code to close with: all twelve loopback gates fail and all twelve
//! in-process gates pass. Changing that arm's code to
//! PROTOCOL_VIOLATION instead leaves the close going out with the wrong number
//! on it, which is the failure only a peer can see.
//!
//! Reducing either `fail_session` call in `validate_peer_request_id` to a
//! plain `?` is the other way round, and each cut reaches one
//! of the two conditions: the close still goes out, because the connection
//! layer reads the same table, and the endpoint's own session is left running.
//!
//! The messages all four cuts produce are recorded on the gates below.

mod common;

/// One draft's four gates.
///
/// `$cfg`, `$setup` and `$sub` name the shapes the setup types take on this
/// draft: `ClientConfig` gained a `draft` field at 14 and lost
/// `additional_versions` at 15, `ServerSetup` dropped its Selected Version at
/// 15, `send_client_setup` lost its version list in the same place, and
/// `Endpoint::subscribe` has four different signatures across the six.
macro_rules! wrong_request_id_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt,
     $code_name:literal, $section:literal, $role:path) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, Subscribe};
            use $role as Role;

            /// The session termination code every one of the six names for
            /// this rule.
            const INVALID_REQUEST_ID: u64 = 0x4;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The ceiling this endpoint grants the peer.
            ///
            /// Larger than either ID under test, so neither refusal can be the
            /// ceiling's. A gate that granted nothing would refuse every ID
            /// for a reason that has nothing to do with the sentence.
            const CEILING: u64 = 8;

            /// The peer's first Request ID: odd, because the peer is the
            /// server, and the first value of the sequence its role fixes.
            const PEERS_FIRST: u64 = 1;

            /// An ID out of this endpoint's own half of the space. Even, and
            /// this endpoint is the client, so the peer may not spend it.
            const OURS: u64 = 2;

            /// This endpoint's setup parameters, carrying the ceiling it
            /// grants the peer.
            fn setup_parameters() -> Vec<KeyValuePair> {
                vec![KeyValuePair {
                    key: VarInt::from_u64(0x02).unwrap(),
                    value: KvpValue::Varint(VarInt::from_u64(CEILING).unwrap()),
                }]
            }

            fn client_config() -> ClientConfig {
                crate::config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            /// The peer's SERVER_SETUP, which grants this endpoint the same
            /// budget so that it can build a SUBSCRIBE of its own.
            fn server_setup() -> ServerSetup {
                crate::server_setup_for!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// A client endpoint with its session established and a ceiling
            /// advertised to the peer.
            fn active_client() -> Endpoint {
                let mut endpoint = Endpoint::new(Role::Client);
                endpoint.connect().expect("connect");
                crate::send_client_setup_for!(
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

            /// A SUBSCRIBE this draft would accept in every respect but the
            /// Request ID, which is `id`.
            fn peer_subscribe(id: u64) -> Subscribe {
                let mut builder = active_client();
                let namespace = TrackNamespace(vec![b"conformance".to_vec()]);
                let (_, msg) = crate::subscribe_for!($sub, builder, namespace)
                    .expect("this draft's own endpoint builds its own SUBSCRIBE");
                let ControlMessage::Subscribe(mut subscribe) = msg else {
                    panic!("subscribe built something other than a SUBSCRIBE")
                };
                subscribe.request_id = VarInt::from_u64(id).unwrap();
                subscribe
            }

            /// Serve one connection: read CLIENT_SETUP, answer it, write the
            /// requests, and report the close the client sends back.
            ///
            /// The two loopback gates differ only in which requests they put
            /// on the wire and which words the close reason has to carry.
            async fn expect_close(
                server: quinn::Endpoint,
                requests: Vec<Subscribe>,
                rule: &'static str,
            ) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                // Control travels on a bidirectional stream the client opens,
                // on every draft in this range.
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed_recv = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

                let mut out = Vec::new();
                out.extend_from_slice(&encode(ControlMessage::ServerSetup(server_setup())));
                for request in requests {
                    out.extend_from_slice(&encode(ControlMessage::Subscribe(request)));
                }
                send.write_all(&out).await.expect("write the setup and the requests");

                let reason = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the client refused the request but never closed the connection");

                match reason {
                    quinn::ConnectionError::ApplicationClosed(frame) => {
                        assert_eq!(
                            u64::from(frame.error_code),
                            INVALID_REQUEST_ID,
                            concat!(
                                "Section ",
                                $section,
                                " answers a Request ID that is not the peer's to spend with ",
                                $code_name,
                                "; the close carried {} instead"
                            ),
                            u64::from(frame.error_code)
                        );
                        let text = String::from_utf8_lossy(&frame.reason).to_string();
                        assert!(
                            text.contains(rule),
                            "the close reason should name the rule that was broken; got {text:?}"
                        );
                    }
                    other => panic!("expected an application close, got {other:?}"),
                }
            }

            /// A request under an ID out of this endpoint's own half of the
            /// space closes the QUIC connection, with the code the section
            /// names.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `WrongParity | OutOfSequence` arm from
            /// `session_error_code`:
            ///
            /// ```text
            /// the client refused the request but never closed the connection: Elapsed(())
            /// ```
            ///
            /// Answering that arm with `ProtocolViolation` instead:
            ///
            /// ```text
            /// assertion `left == right` failed: Section 8.1 answers a Request ID
            /// that is not the peer's to spend with Invalid Request ID; the close
            /// carried 3 instead
            ///   left: 3
            ///  right: 4
            /// ```
            #[tokio::test]
            async fn an_id_from_this_endpoints_own_half_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let request = peer_subscribe(OURS);

                let peer = tokio::spawn(async move {
                    expect_close(server, vec![request], "wrong parity").await
                });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("a request under one of this endpoint's own IDs must be refused");
                let text = err.to_string();
                assert!(
                    text.contains("wrong parity"),
                    "the error should name the rule; got {text:?}"
                );

                // Longer than the peer's own wait, so that when the close never
                // arrives it is the peer's message that fails the test.
                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// The same violation ends the endpoint's own session and not only
            /// the connection carrying it.
            ///
            /// `Closed` is reachable from nowhere else here: the endpoint is
            /// asserted `Active` on the way out of `active_client`, and the
            /// only message it is given afterwards is the illegal one.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Reducing the parity check in `validate_peer_request_id` to a
            /// plain `?`:
            ///
            /// ```text
            /// assertion `left == right` failed: the violation was reported but
            /// the session was left running: Active
            ///   left: Active
            ///  right: Closed
            /// ```
            #[test]
            fn an_id_from_this_endpoints_own_half_ends_the_endpoints_session() {
                let mut endpoint = active_client();

                endpoint
                    .receive_message(ControlMessage::Subscribe(peer_subscribe(OURS)))
                    .expect_err("a request under one of this endpoint's own IDs must be refused");

                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Closed,
                    "the violation was reported but the session was left running: {:?}",
                    endpoint.session_state()
                );
            }

            /// A second request under an ID the peer has already spent closes
            /// the QUIC connection, with the same code.
            ///
            /// The first request is accepted, which is what makes the second
            /// one a repeat rather than a skip and what makes the refusal mean
            /// something: an endpoint that refused both would pass a gate built
            /// on the second alone.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `WrongParity | OutOfSequence` arm from
            /// `session_error_code`:
            ///
            /// ```text
            /// the client refused the request but never closed the connection: Elapsed(())
            /// ```
            #[tokio::test]
            async fn an_id_the_peer_already_spent_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (server, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let first = peer_subscribe(PEERS_FIRST);
                let repeat = peer_subscribe(PEERS_FIRST);

                let peer = tokio::spawn(async move {
                    expect_close(server, vec![first, repeat], "next in sequence").await
                });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                conn.recv_and_dispatch()
                    .await
                    .expect("the first ID of the peer's own sequence must be accepted");

                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("a second request under an ID already spent must be refused");
                let text = err.to_string();
                assert!(
                    text.contains("next in sequence"),
                    "the error should name the rule; got {text:?}"
                );

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// The repeat ends the endpoint's own session too.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Reducing the sequence check in `validate_peer_request_id` to
            /// a plain `?`:
            ///
            /// ```text
            /// assertion `left == right` failed: the violation was reported but
            /// the session was left running: Active
            ///   left: Active
            ///  right: Closed
            /// ```
            #[test]
            fn an_id_the_peer_already_spent_ends_the_endpoints_session() {
                let mut endpoint = active_client();

                endpoint
                    .receive_message(ControlMessage::Subscribe(peer_subscribe(PEERS_FIRST)))
                    .expect("the first ID of the peer's own sequence must be accepted");

                endpoint
                    .receive_message(ControlMessage::Subscribe(peer_subscribe(PEERS_FIRST)))
                    .expect_err("a second request under an ID already spent must be refused");

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

/// `ClientConfig`, in each of the three shapes it takes across the six drafts.
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

/// CLIENT_SETUP, which lost its Supported Versions list at draft-15.
#[macro_export]
macro_rules! send_client_setup_for {
    (versioned, $endpoint:expr, $version:expr, $params:expr) => {
        $endpoint.send_client_setup(vec![$version.version_varint()], $params).expect("CLIENT_SETUP")
    };
    (plain, $endpoint:expr, $version:expr, $params:expr) => {
        $endpoint.send_client_setup($params).expect("CLIENT_SETUP")
    };
}

/// `Endpoint::subscribe`, in the four shapes it takes across the six drafts.
///
/// The Track Alias left the message at 12, the Filter Type became a named type
/// again at 13, and at 15 the whole filter moved into the parameters. None of
/// that is what these gates are about, so each arm asks for whatever the draft
/// calls a subscription to the largest object and nothing more.
#[macro_export]
macro_rules! subscribe_for {
    (alias_varint, $ep:expr, $ns:expr) => {
        $ep.subscribe(
            VarInt::from_u64(1).unwrap(),
            $ns,
            b"track".to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
        )
    };
    (varint, $ep:expr, $ns:expr) => {
        $ep.subscribe(
            $ns,
            b"track".to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            Vec::new(),
        )
    };
    (filter, $ep:expr, $ns:expr) => {
        $ep.subscribe(
            $ns,
            b"track".to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    };
    (params, $ep:expr, $ns:expr) => {
        $ep.subscribe($ns, b"track".to_vec(), Vec::new())
    };
}

wrong_request_id_gates!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    alias_varint,
    "Invalid Request ID",
    "8.1",
    moqtap_client::draft11::session::request_id::Role
);
wrong_request_id_gates!(
    draft12,
    "draft12",
    Draft12,
    early,
    versioned,
    varint,
    "Invalid Request ID",
    "8.1",
    moqtap_client::draft12::session::request_id::Role
);
wrong_request_id_gates!(
    draft13,
    "draft13",
    Draft13,
    early,
    versioned,
    filter,
    "Invalid Request ID",
    "8.1",
    moqtap_client::draft13::session::request_id::Role
);
wrong_request_id_gates!(
    draft14,
    "draft14",
    Draft14,
    both,
    versioned,
    filter,
    "INVALID_REQUEST_ID",
    "9.1",
    moqtap_client::draft14::session::request_id::Role
);
wrong_request_id_gates!(
    draft15,
    "draft15",
    Draft15,
    late,
    plain,
    params,
    "INVALID_REQUEST_ID",
    "9.1",
    moqtap_client::draft15::session::request_id::Role
);
wrong_request_id_gates!(
    draft16,
    "draft16",
    Draft16,
    late,
    plain,
    params,
    "INVALID_REQUEST_ID",
    "9.1",
    moqtap_client::draft16::session::request_id::Role
);

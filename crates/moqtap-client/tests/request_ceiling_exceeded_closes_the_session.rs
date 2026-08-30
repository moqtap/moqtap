//! A request at the ceiling this endpoint advertised ends the session, on the
//! wire.
//!
//! Ten drafts state the rule, 07 through 16, each in the same MAX_* section
//! that carries the rule about the ceiling only increasing, and every one of
//! the ten supplies the verb. Draft-07 Section 6.20: "If a Subscribe ID equal
//! or larger than this is received in any message, including SUBSCRIBE, the
//! publisher MUST close the session with an error of 'Too Many Subscribes'."
//! Drafts 08 through 10 narrow the receiver to "the publisher that sent the
//! MAX_SUBSCRIBE_ID", which is the same endpoint by another name and is also
//! the reason the number a peer's ID is measured against is the one this
//! endpoint sent rather than the one it was granted. Draft-11 renames the
//! message, renames the code to 'Too Many Requests', and replaces "any
//! message" with a list of the request messages that spend an ID; the list
//! changes at 13, at 14 and at 16, and each draft's list is the one its
//! `receive_request` carries. Drafts 14 through 16 spell the code
//! TOO_MANY_REQUESTS.
//!
//! Drafts 17, 18 and 19 have no gate because they have no rule: they removed
//! MAX_REQUEST_ID, and with it the ceiling and the code. Neither name appears
//! anywhere in the three except in their own change logs.
//!
//! # The boundary is the interesting value
//!
//! Every one of the ten states the rule of an ID "equal or larger" than the
//! ceiling, so the ID at the ceiling is the one the rule turns on, and it is
//! the one the peer sends here. An implementation that read the bound as
//! inclusive would pass a test built on a much larger ID and fail this one.
//!
//! # Why a ceiling is granted first
//!
//! An endpoint that has advertised nothing has a ceiling of 0, which refuses
//! every ID a peer could pick, so a gate that grants nothing reaches the rule
//! without ever exercising it: it cannot tell a ceiling that is enforced from
//! one that is ignored in favour of refusing everything. The client here
//! grants 3 in its own CLIENT_SETUP, has a request at 1 accepted, and only
//! then sends one at 3. The accepted request is the half that makes the
//! refusal mean something.
//!
//! # Why this crate builds the peer's SUBSCRIBE
//!
//! The refusal has to be about the Request ID and nothing else, and a SUBSCRIBE
//! assembled by hand is ten different field layouts with ten chances to be
//! refused for an unrelated reason. Each draft's own endpoint builds one
//! instead, so it conforms by construction, and only the ID field is
//! overwritten - once with a legal value and once with the illegal one, from
//! the same message, so the two differ in exactly the field under test.
//!
//! # Ablations, measured
//!
//! Both cuts are made in all ten drafts at once, because ten copies of one
//! rule need ten measurements and a single `--no-fail-fast` run produces all
//! of them. They fail in opposite directions.
//!
//! Deleting the `ExceedsMax` arm from each `EndpointError::session_error_code`
//! leaves the endpoint refusing the request and ending its own session, and
//! leaves the connection layer with no code to close with: all ten loopback
//! gates fail and all ten in-process gates pass.
//!
//! Dropping the `fail_session` call from each `validate_peer_*` - the shape
//! all ten shipped with - is the other way round. The close still goes out,
//! because the connection layer reads the same table, and the endpoint's own
//! session is left running: all ten in-process gates fail and all ten loopback
//! gates pass.
//!
//! The messages both cuts produce are recorded on the two tests below.

mod common;

/// One draft's two gates.
///
/// `$cfg`, `$setup` and `$kvp` name the shapes the setup types take on this
/// draft: `ClientConfig` gained a `draft` field at 14 and lost
/// `additional_versions` at 15, `ServerSetup` dropped its Selected Version at
/// 15, `send_client_setup` lost its version list in the same place, draft-07
/// alone requires a ROLE parameter in both directions, and setup parameter
/// values are length-prefixed bytes through draft-10 and varints from 11.
/// `$sub` names which of the five shapes `Endpoint::subscribe` has here.
macro_rules! ceiling_exceeded_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $kvp:tt, $sub:tt,
     $field:ident, $code:literal, $code_name:literal, $section:literal, $role:path) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::KeyValuePair;
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, Subscribe};
            use $role as Role;

            /// The session termination code this draft names for the rule.
            const TOO_MANY: u64 = $code;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The ceiling the client grants the peer.
            const CEILING: u64 = 3;

            /// A Request ID below the ceiling, and of the peer's own parity on
            /// the drafts that give the two endpoints alternating halves of
            /// the space.
            const UNDER_THE_CEILING: u64 = 1;

            /// The ID the rule turns on: "equal or larger" makes the ceiling
            /// itself the first illegal value.
            const AT_THE_CEILING: u64 = CEILING;

            /// This endpoint's setup parameters, carrying the ceiling it
            /// grants the peer.
            fn setup_parameters() -> Vec<KeyValuePair> {
                let ceiling = KeyValuePair {
                    key: VarInt::from_u64(0x02).unwrap(),
                    value: crate::kvp_value_for!($kvp, CEILING),
                };
                crate::setup_params_for!($setup, ceiling)
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

            /// Two SUBSCRIBEs this draft would accept in every respect but the
            /// Request ID: one below the ceiling and one at it.
            fn peer_subscribes() -> (Subscribe, Subscribe) {
                let mut builder = active_client();
                let namespace = TrackNamespace(vec![b"conformance".to_vec()]);
                let (_, msg) = crate::subscribe_for!($sub, builder, namespace)
                    .expect("this draft's own endpoint builds its own SUBSCRIBE");
                let ControlMessage::Subscribe(first) = msg else {
                    panic!("subscribe built something other than a SUBSCRIBE")
                };
                let mut legal = first.clone();
                legal.$field = VarInt::from_u64(UNDER_THE_CEILING).unwrap();
                let mut illegal = first;
                illegal.$field = VarInt::from_u64(AT_THE_CEILING).unwrap();
                (legal, illegal)
            }

            /// The peer spends a granted ID, then one at the ceiling, and the
            /// client closes the QUIC connection.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `ExceedsMax` arm from `session_error_code`:
            ///
            /// ```text
            /// the client refused the request at the ceiling but never closed the connection: Elapsed(())
            /// ```
            #[tokio::test]
            async fn a_request_at_the_ceiling_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let (legal, illegal) = peer_subscribes();

                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");

                    // Control travels on a bidirectional stream the client
                    // opens, on every draft in this range.
                    let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                    let mut framed_recv =
                        crate::common::frame_uni_recv(recv, DraftVersion::$version);
                    framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

                    let mut out = Vec::new();
                    out.extend_from_slice(&encode(ControlMessage::ServerSetup(server_setup())));
                    out.extend_from_slice(&encode(ControlMessage::Subscribe(legal)));
                    out.extend_from_slice(&encode(ControlMessage::Subscribe(illegal)));
                    send.write_all(&out).await.expect("write the setup and both requests");

                    let reason = tokio::time::timeout(PATIENCE, conn.closed()).await.expect(
                        "the client refused the request at the ceiling but never closed the \
                         connection",
                    );

                    match reason {
                        quinn::ConnectionError::ApplicationClosed(frame) => {
                            assert_eq!(
                                u64::from(frame.error_code),
                                TOO_MANY,
                                concat!(
                                    "Section ",
                                    $section,
                                    " answers a request at the advertised ceiling with ",
                                    $code_name,
                                    "; the close carried {} instead"
                                ),
                                u64::from(frame.error_code)
                            );
                            let text = String::from_utf8_lossy(&frame.reason).to_string();
                            assert!(
                                text.contains("exceeds max"),
                                "the close reason should name the rule that was broken; \
                                 got {text:?}"
                            );
                        }
                        other => panic!("expected an application close, got {other:?}"),
                    }
                });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                conn.recv_and_dispatch()
                    .await
                    .expect("a request below the granted ceiling must be accepted");

                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("a request at the granted ceiling must be refused");
                let text = err.to_string();
                assert!(
                    text.contains("exceeds max"),
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
            /// `Closed` is reachable from nowhere else here: the endpoint is
            /// asserted `Active` before the first request, and the first
            /// request is legal.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Dropping the `fail_session` call from `validate_peer_*`:
            ///
            /// ```text
            /// assertion `left == right` failed: the violation was reported but
            /// the session was left running: Active
            ///   left: Active
            ///  right: Closed
            /// ```
            #[test]
            fn a_request_at_the_ceiling_ends_the_endpoints_session() {
                let mut endpoint = active_client();
                let (legal, illegal) = peer_subscribes();

                endpoint
                    .receive_message(ControlMessage::Subscribe(legal))
                    .expect("a request below the granted ceiling must be accepted");

                endpoint
                    .receive_message(ControlMessage::Subscribe(illegal))
                    .expect_err("a request at the granted ceiling must be refused");

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

/// The setup parameters an endpoint sends, around the ceiling it grants.
///
/// Draft-07 requires a ROLE from both sides before a session is usable, and is
/// the only one that requires anything else at all.
#[macro_export]
macro_rules! setup_params_for {
    (with_role, $ceiling:expr) => {{
        let mut role = Vec::new();
        VarInt::from_u64(3).unwrap().encode(&mut role); // PubSub
        vec![
            KeyValuePair {
                key: VarInt::from_u64(0x00).unwrap(),
                value: moqtap_codec::kvp::KvpValue::Bytes(role),
            },
            $ceiling,
        ]
    }};
    (versioned, $ceiling:expr) => {
        vec![$ceiling]
    };
    (plain, $ceiling:expr) => {
        vec![$ceiling]
    };
}

/// A setup parameter value, in the two shapes the range uses.
#[macro_export]
macro_rules! kvp_value_for {
    (bytes, $v:expr) => {{
        let mut bytes = Vec::new();
        VarInt::from_u64($v).unwrap().encode(&mut bytes);
        moqtap_codec::kvp::KvpValue::Bytes(bytes)
    }};
    (varint, $v:expr) => {
        moqtap_codec::kvp::KvpValue::Varint(VarInt::from_u64($v).unwrap())
    };
}

/// `ClientConfig`, in each of the three shapes it takes across the ten drafts.
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
macro_rules! send_client_setup_for {
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

/// `Endpoint::subscribe`, in the five shapes it takes across the ten drafts.
///
/// The Track Alias left the message at 12, the Filter Type became a plain
/// varint at 11 and a named type again at 13, and at 15 the whole filter moved
/// into the parameters. None of that is what these gates are about, so each
/// arm asks for whatever the draft calls a subscription to the largest object
/// and nothing more.
#[macro_export]
macro_rules! subscribe_for {
    (alias, $ep:expr, $ns:expr) => {
        $ep.subscribe(
            VarInt::from_u64(1).unwrap(),
            $ns,
            b"track".to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
        )
    };
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

ceiling_exceeded_gates!(
    draft07,
    "draft07",
    Draft07,
    early,
    with_role,
    bytes,
    alias,
    subscribe_id,
    0x6,
    "Too Many Subscribes",
    "6.20",
    moqtap_client::draft07::endpoint::Role
);
ceiling_exceeded_gates!(
    draft08,
    "draft08",
    Draft08,
    early,
    versioned,
    bytes,
    alias,
    subscribe_id,
    0x6,
    "Too Many Subscribes",
    "7.20",
    moqtap_client::draft08::endpoint::Role
);
ceiling_exceeded_gates!(
    draft09,
    "draft09",
    Draft09,
    early,
    versioned,
    bytes,
    alias,
    subscribe_id,
    0x6,
    "Too Many Subscribes",
    "7.20",
    moqtap_client::draft09::endpoint::Role
);
ceiling_exceeded_gates!(
    draft10,
    "draft10",
    Draft10,
    early,
    versioned,
    bytes,
    alias,
    subscribe_id,
    0x6,
    "Too Many Subscribes",
    "8.4",
    moqtap_client::draft10::endpoint::Role
);
ceiling_exceeded_gates!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    varint,
    alias_varint,
    request_id,
    0x7,
    "Too Many Requests",
    "8.5",
    moqtap_client::draft11::session::request_id::Role
);
ceiling_exceeded_gates!(
    draft12,
    "draft12",
    Draft12,
    early,
    versioned,
    varint,
    varint,
    request_id,
    0x7,
    "Too Many Requests",
    "8.5",
    moqtap_client::draft12::session::request_id::Role
);
ceiling_exceeded_gates!(
    draft13,
    "draft13",
    Draft13,
    early,
    versioned,
    varint,
    filter,
    request_id,
    0x7,
    "Too Many Requests",
    "8.5",
    moqtap_client::draft13::session::request_id::Role
);
ceiling_exceeded_gates!(
    draft14,
    "draft14",
    Draft14,
    both,
    versioned,
    varint,
    filter,
    request_id,
    0x7,
    "TOO_MANY_REQUESTS",
    "9.5",
    moqtap_client::draft14::session::request_id::Role
);
ceiling_exceeded_gates!(
    draft15,
    "draft15",
    Draft15,
    late,
    plain,
    varint,
    params,
    request_id,
    0x7,
    "TOO_MANY_REQUESTS",
    "9.5",
    moqtap_client::draft15::session::request_id::Role
);
ceiling_exceeded_gates!(
    draft16,
    "draft16",
    Draft16,
    late,
    plain,
    varint,
    params,
    request_id,
    0x7,
    "TOO_MANY_REQUESTS",
    "9.5",
    moqtap_client::draft16::session::request_id::Role
);

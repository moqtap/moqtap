//! A request ceiling that does not increase ends the session, on the wire.
//!
//! Every draft from 07 to 16 states the rule in its own MAX_* section and
//! nowhere else. Drafts 07 through 10 state it of MAX_SUBSCRIBE_ID: "The
//! Maximum Subscribe Id MUST only increase within a session, and receipt of a
//! MAX_SUBSCRIBE_ID message with an equal or smaller Subscribe ID value is a
//! 'Protocol Violation'." Draft-11 renamed the message and kept the sentence
//! word for word; drafts 14 and 15 spell the code as PROTOCOL_VIOLATION; and
//! draft-16 is the only one that supplies the verb — "If an endpoint receives
//! MAX_REQUEST_ID message with an equal or smaller Request ID it MUST close
//! the session with a PROTOCOL_VIOLATION."
//!
//! Drafts 17 through 20 have no gate here because they have no rule: they
//! removed the message. Their own change logs say so in one line — "Remove
//! MAX_REQUEST_ID/REQUESTS_BLOCKED" — and outside that change log the name
//! appears nowhere in any of the four.
//!
//! # Why one of these is a loopback test
//!
//! An endpoint can refuse the second ceiling and pass every in-process test of
//! that refusal while the refusal stops inside the process: the connection layer
//! returns the error to its caller and leaves the QUIC connection open, so the
//! peer — which is the one that broke the rule — sees a session that is still
//! running and can repeat the message forever. A rule whose consequence is a
//! session termination code is a statement about the wire, and only something
//! holding the other end can check it.
//!
//! The second gate is in-process because it observes the other half: the
//! endpoint's own session ends too. Without that, a caller that ignored the
//! returned error could go on issuing requests into a connection that is gone.
//!
//! # Why two ceilings and not one
//!
//! The ceiling starts at zero, so a single MAX_* carrying zero would already
//! break the rule — and would pass against an endpoint that refused every
//! ceiling, increase or not. The peer here raises the ceiling to 100 and has
//! that accepted, then repeats it. Only the second one is the violation, and
//! the first is what proves the refusal is about the rule.
//!
//! # Ablations, measured
//!
//! Both cuts are made in all ten drafts at once, because ten separate copies of
//! the same routing need ten separate measurements and one run with
//! `--no-fail-fast` produces all of them.
//!
//! Reducing each `Connection::recv_and_dispatch` to
//! `self.endpoint.receive_message(msg.clone())?`
//! leaves the endpoint refusing the frame and the connection open, and
//! fails the loopback gate on every one of the ten, each on its own draft's
//! line and none of the in-process ten.
//!
//! Reducing each `Endpoint::fail_session` to `err`, so the violation is
//! reported without the session ending, is the other way round: all ten
//! in-process gates fail and all ten loopback gates pass, because the close
//! still goes out. Two cuts, twenty failures, no overlap.
//!
//! The messages both cuts produce are recorded on the two tests below.

mod common;

/// One draft's two gates.
///
/// `$cfg` and `$setup` name the shapes the setup types take on this draft.
/// `ClientConfig` gained a `draft` field at 14 and lost `additional_versions`
/// at 15; `ServerSetup` dropped its Selected Version at 15, and
/// `send_client_setup` lost its version list in the same place; and draft-07
/// alone requires a ROLE parameter in both directions. Nothing else differs
/// across the ten.
macro_rules! ceiling_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt,
     $max:ident, $field:ident, $receive:ident, $section:literal, $role:path) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::KeyValuePair;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{$max, ControlMessage, ServerSetup};
            use $role as Role;

            /// Session termination code PROTOCOL_VIOLATION, from this draft's
            /// Termination section.
            const PROTOCOL_VIOLATION: u64 = 0x3;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// The ceiling the peer grants before it breaks its own promise.
            const CEILING: u64 = 100;

            fn setup_parameters() -> Vec<KeyValuePair> {
                crate::params_for!($setup)
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

            /// A ceiling of `value`, as this draft spells the message.
            fn ceiling(value: u64) -> $max {
                $max { $field: VarInt::from_u64(value).unwrap() }
            }

            /// A client endpoint with its session established.
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

            /// The peer raises the ceiling, then offers the same number again,
            /// and the client closes the QUIC connection.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Reducing the intake to `self.endpoint.receive_message(msg
            /// .clone())?`:
            ///
            /// ```text
            /// the client refused the repeated ceiling but never closed the connection: Elapsed(())
            /// ```
            #[tokio::test]
            async fn a_ceiling_that_does_not_increase_closes_the_quic_connection() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

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
                    out.extend_from_slice(&encode(ControlMessage::$max(ceiling(CEILING))));
                    out.extend_from_slice(&encode(ControlMessage::$max(ceiling(CEILING))));
                    send.write_all(&out).await.expect("write the setup and both ceilings");

                    let reason = tokio::time::timeout(PATIENCE, conn.closed()).await.expect(
                        "the client refused the repeated ceiling but never closed the connection",
                    );

                    match reason {
                        quinn::ConnectionError::ApplicationClosed(frame) => {
                            assert_eq!(
                                u64::from(frame.error_code),
                                PROTOCOL_VIOLATION,
                                concat!(
                                    "Section ",
                                    $section,
                                    " answers a ceiling that does not increase with \
                                     PROTOCOL_VIOLATION; the close carried {} instead"
                                ),
                                u64::from(frame.error_code)
                            );
                            let text = String::from_utf8_lossy(&frame.reason).to_string();
                            assert!(
                                text.contains("can only increase"),
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
                    .expect("the first ceiling is an increase and must be accepted");

                let err = conn
                    .recv_and_dispatch()
                    .await
                    .expect_err("a ceiling that repeats the last one must be refused");
                let text = err.to_string();
                assert!(
                    text.contains("can only increase"),
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
            /// asserted `Active` before the first ceiling, and the first
            /// ceiling is legal.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Reducing `fail_session` to `err`:
            ///
            /// ```text
            /// assertion `left == right` failed: the violation was reported but
            /// the session was left running: Active
            ///   left: Active
            ///  right: Closed
            /// ```
            #[test]
            fn a_ceiling_that_does_not_increase_ends_the_endpoints_session() {
                let mut endpoint = active_client();

                endpoint
                    .$receive(&ceiling(CEILING))
                    .expect("the first ceiling is an increase and must be accepted");

                endpoint
                    .$receive(&ceiling(CEILING))
                    .expect_err("a ceiling that repeats the last one must be refused");

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

/// The setup parameters this draft's endpoints exchange.
///
/// Draft-07 requires a ROLE from both sides before a session is usable, and is
/// the only one that requires anything.
#[macro_export]
macro_rules! params_for {
    (with_role) => {{
        let mut value = Vec::new();
        VarInt::from_u64(3).unwrap().encode(&mut value); // PubSub
        vec![KeyValuePair {
            key: VarInt::from_u64(0x00).unwrap(),
            value: moqtap_codec::kvp::KvpValue::Bytes(value),
        }]
    }};
    (versioned) => {
        Vec::<KeyValuePair>::new()
    };
    (plain) => {
        Vec::<KeyValuePair>::new()
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

ceiling_gates!(
    draft07,
    "draft07",
    Draft07,
    early,
    with_role,
    MaxSubscribeId,
    subscribe_id,
    receive_max_subscribe_id,
    "6.20",
    moqtap_client::draft07::endpoint::Role
);
ceiling_gates!(
    draft08,
    "draft08",
    Draft08,
    early,
    versioned,
    MaxSubscribeId,
    subscribe_id,
    receive_max_subscribe_id,
    "7.20",
    moqtap_client::draft08::endpoint::Role
);
ceiling_gates!(
    draft09,
    "draft09",
    Draft09,
    early,
    versioned,
    MaxSubscribeId,
    subscribe_id,
    receive_max_subscribe_id,
    "7.20",
    moqtap_client::draft09::endpoint::Role
);
ceiling_gates!(
    draft10,
    "draft10",
    Draft10,
    early,
    versioned,
    MaxSubscribeId,
    subscribe_id,
    receive_max_subscribe_id,
    "8.4",
    moqtap_client::draft10::endpoint::Role
);
ceiling_gates!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    MaxRequestId,
    request_id,
    receive_max_request_id,
    "8.5",
    moqtap_client::draft11::session::request_id::Role
);
ceiling_gates!(
    draft12,
    "draft12",
    Draft12,
    early,
    versioned,
    MaxRequestId,
    request_id,
    receive_max_request_id,
    "8.5",
    moqtap_client::draft12::session::request_id::Role
);
ceiling_gates!(
    draft13,
    "draft13",
    Draft13,
    early,
    versioned,
    MaxRequestId,
    request_id,
    receive_max_request_id,
    "8.5",
    moqtap_client::draft13::session::request_id::Role
);
ceiling_gates!(
    draft14,
    "draft14",
    Draft14,
    both,
    versioned,
    MaxRequestId,
    request_id,
    receive_max_request_id,
    "9.5",
    moqtap_client::draft14::session::request_id::Role
);
ceiling_gates!(
    draft15,
    "draft15",
    Draft15,
    late,
    plain,
    MaxRequestId,
    request_id,
    receive_max_request_id,
    "9.5",
    moqtap_client::draft15::session::request_id::Role
);
ceiling_gates!(
    draft16,
    "draft16",
    Draft16,
    late,
    plain,
    MaxRequestId,
    request_id,
    receive_max_request_id,
    "9.5",
    moqtap_client::draft16::session::request_id::Role
);

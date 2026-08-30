//! Only a server may offer a migration URI, and a server that is sent one ends
//! the session.
//!
//! "If a server receives a GOAWAY with a non-zero New Session URI Length it
//! MUST terminate the session with a Protocol Violation." Every draft from 08
//! on says it, once each, and two things move under it: the code is spelled
//! "Protocol Violation" through draft-13 and PROTOCOL_VIOLATION from draft-14,
//! and the verb is "terminate" through draft-15 and "close" from draft-16.
//! Drafts 18 and 19 keep this sentence and add the sender's half beside it - "A
//! client MUST send a zero-length New Session URI in any GOAWAY, as clients
//! cannot instruct servers to initiate connections" - so the receiver's rule is
//! stated by all twelve and not replaced on any of them.
//!
//! Draft-07 has no gate here because it states a **different and stricter**
//! rule, not because it states none. Its Section 6.3 reads "The server MUST
//! terminate the session with a Protocol Violation (Section 3.5) if it receives
//! a GOAWAY message" - about the message, not about the URI it carries - so an
//! empty
//! GOAWAY at a server is legal from draft-08 on and a session close on
//! draft-07. The two cannot share a gate, and draft-07's is
//! `goaway_at_a_draft07_server.rs`.
//!
//! Drafts 17 and 18 are gated in `draft17_18_session_rules.rs` and draft-19
//! beside its own implementation, all three with the same three assertions.
//!
//! # Why this rule is gated in process and not on the wire
//!
//! It is a rule a *server* applies, and this crate has no server to apply it
//! with: `Connection::connect` is the only way to build one and it always
//! builds a client, so no connection here can ever be the endpoint the sentence
//! is about. `Endpoint` is public and role-agnostic, and the close code is on
//! its public error type, so what a server built on it would put on the wire is
//! exactly what these gates read. Saying so is the point: the arm added to the
//! close table has no caller inside this crate, and an arm with no
//! caller is worth nothing until something reads it.
//!
//! # What each gate observes
//!
//! Three consequences, none of them a configured value read back. The session
//! state after the message, because a refusal that left the session running
//! would keep serving a peer just found in violation. The next request this
//! endpoint tries, because that is what an application would notice. And
//! whether the URI is retrievable afterwards, because an endpoint that stored
//! it would leave an application free to reconnect to somewhere a client chose.
//!
//! # Ablations, measured
//!
//! Two cuts, each made in all nine drafts at once and then reverted.
//!
//! Dropping `fail_session` from the guard, which leaves the behaviour drafts
//! 08 through 16 had without it:
//!
//! ```text
//! assertion `left == right` failed: the violation was reported and the
//! session was left running
//!   left: Active
//!  right: Closed
//! ```
//!
//! Deleting the close-table arm, leaving the state move in place:
//!
//! ```text
//! assertion `left == right` failed: a session this endpoint ended has no
//! code for the transport to close with
//!   left: None
//!  right: Some(ProtocolViolation)
//! ```

use moqtap_codec::types::TrackNamespace;

/// The URI a client would have no business offering.
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
const ELSEWHERE: &[u8] = b"https://elsewhere.example";

/// A namespace for the request each gate makes after the refusal. Nothing about
/// it matters except that the endpoint is asked to start something new.
#[allow(dead_code)]
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

/// One draft's three gates.
///
/// `$setup` names the shape the setup exchange takes on this draft: CLIENT_SETUP
/// carried a version list through draft-14 and stopped at 15, and the response
/// lost its Selected Version in the same place. `$next` names the request the
/// endpoint makes after the refusal - ANNOUNCE became PUBLISH_NAMESPACE at
/// draft-14 and grew a parameter list at 15 - and any request would do, because
/// every one of them is gated on the session being active.
macro_rules! goaway_uri_gates {
    ($draft:ident, $feat:literal, $section:literal, $setup:tt, $role:path,
     $next:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::$draft::error_codes::SessionErrorCode;
            use moqtap_codec::$draft::message::{ClientSetup, GoAway};
            use $role as Role;

            use super::ELSEWHERE;

            /// An endpoint of the given role with its session established.
            fn established(role: Role) -> Endpoint {
                let mut endpoint = Endpoint::new(role);
                endpoint.connect().expect("connect");
                crate::goaway_uri_setup_for!($setup, endpoint);
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Active,
                    "the gate needs a running session to end"
                );
                endpoint
            }

            /// Ask the endpoint to start something new. Which request it is does
            /// not matter: every one of them is refused once the session is over.
            fn next_request(endpoint: &mut Endpoint) -> Result<(), EndpointError> {
                crate::goaway_uri_next_for!($next, endpoint)
            }

            /// A migration URI arriving at a server ends the session.
            ///
            #[doc = $section]
            ///
            /// The sentence names the close and the code together, so the
            /// endpoint that raises this has already finished with the session
            /// and the transport has a code to close with.
            #[test]
            fn a_migration_uri_arriving_at_a_server_closes_the_session() {
                let mut endpoint = established(Role::Server);

                let err = endpoint
                    .receive_goaway(&GoAway { new_session_uri: ELSEWHERE.to_vec() })
                    .expect_err("a client may not tell a server where to go next");
                assert!(matches!(err, EndpointError::GoAwayUriAtServer), "got {err:?}");
                assert_eq!(
                    err.session_error_code(),
                    Some(SessionErrorCode::ProtocolViolation),
                    "a session this endpoint ended has no code for the transport to close with",
                );
                assert_eq!(
                    endpoint.session_state(),
                    SessionState::Closed,
                    "the violation was reported and the session was left running",
                );
                assert_eq!(endpoint.goaway_uri(), None, "the refused URI was stored anyway");
                assert!(
                    matches!(next_request(&mut endpoint), Err(EndpointError::NotActive)),
                    "the session was over and the endpoint started a new request anyway",
                );
            }

            /// A GOAWAY with no URI is the shape a client may send, and a server
            /// takes it. Without this the gate above would pass on an endpoint
            /// that refused every GOAWAY it received.
            #[test]
            fn a_goaway_with_no_uri_is_taken_at_a_server() {
                let mut endpoint = established(Role::Server);
                endpoint.receive_goaway(&GoAway { new_session_uri: Vec::new() }).unwrap();
                assert_eq!(endpoint.session_state(), SessionState::Draining);
            }

            /// And the same message at a client is the whole point of the field.
            #[test]
            fn a_migration_uri_arriving_at_a_client_is_taken() {
                let mut endpoint = established(Role::Client);
                endpoint.receive_goaway(&GoAway { new_session_uri: ELSEWHERE.to_vec() }).unwrap();
                assert_eq!(endpoint.session_state(), SessionState::Draining);
                assert_eq!(endpoint.goaway_uri(), Some(ELSEWHERE));
            }
        }
    };
}

/// CLIENT_SETUP carried a list of versions through draft-14 and the response
/// named the one chosen; draft-15 moved both onto the transport and left the
/// message with nothing but its parameters.
#[macro_export]
macro_rules! goaway_uri_setup_for {
    ((versioned $v:literal), $ep:ident) => {{
        let version = moqtap_codec::varint::VarInt::from_u64($v).unwrap();
        let client_setup = ClientSetup { supported_versions: vec![version], parameters: vec![] };
        $ep.receive_client_setup_and_respond(&client_setup, version).expect("CLIENT_SETUP");
    }};
    ((plain), $ep:ident) => {{
        let client_setup = ClientSetup { parameters: vec![] };
        $ep.receive_client_setup_and_respond(&client_setup).expect("CLIENT_SETUP");
    }};
}

/// The request each gate makes after the refusal. ANNOUNCE was renamed
/// PUBLISH_NAMESPACE at draft-14 and grew a parameter list at draft-15.
#[macro_export]
macro_rules! goaway_uri_next_for {
    (announce, $ep:ident) => {
        $ep.announce(super::ns()).map(|_| ())
    };
    (announce_params, $ep:ident) => {
        $ep.announce(super::ns(), vec![]).map(|_| ())
    };
    (publish_namespace, $ep:ident) => {
        $ep.publish_namespace(super::ns(), Vec::new()).map(|_| ())
    };
    (publish_namespace_with_parameters, $ep:ident) => {
        $ep.publish_namespace(super::ns(), vec![]).map(|_| ())
    };
}

goaway_uri_gates!(
    draft08,
    "draft08",
    "Draft-08 Section 7.3: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a Protocol Violation.\"",
    (versioned 0xff00_0008),
    moqtap_client::draft08::endpoint::Role,
    announce
);
goaway_uri_gates!(
    draft09,
    "draft09",
    "Draft-09 Section 7.3: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a Protocol Violation.\"",
    (versioned 0xff00_0009),
    moqtap_client::draft09::endpoint::Role,
    announce
);
goaway_uri_gates!(
    draft10,
    "draft10",
    "Draft-10 Section 8.3: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a Protocol Violation.\"",
    (versioned 0xff00_000a),
    moqtap_client::draft10::endpoint::Role,
    announce
);
goaway_uri_gates!(
    draft11,
    "draft11",
    "Draft-11 Section 8.4: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a Protocol Violation.\"",
    (versioned 0xff00_000b),
    moqtap_client::draft11::session::request_id::Role,
    announce
);
goaway_uri_gates!(
    draft12,
    "draft12",
    "Draft-12 Section 8.4: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a Protocol Violation.\"",
    (versioned 0xff00_000c),
    moqtap_client::draft12::session::request_id::Role,
    announce_params
);
goaway_uri_gates!(
    draft13,
    "draft13",
    "Draft-13 Section 8.4: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a Protocol Violation.\"",
    (versioned 0xff00_000d),
    moqtap_client::draft13::session::request_id::Role,
    announce_params
);
goaway_uri_gates!(
    draft14,
    "draft14",
    "Draft-14 Section 9.4: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a PROTOCOL_VIOLATION.\"",
    (versioned 0xff00_000e),
    moqtap_client::draft14::session::request_id::Role,
    publish_namespace
);
goaway_uri_gates!(
    draft15,
    "draft15",
    "Draft-15 Section 9.4: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST terminate the session with a PROTOCOL_VIOLATION.\"",
    (plain),
    moqtap_client::draft15::session::request_id::Role,
    publish_namespace_with_parameters
);
goaway_uri_gates!(
    draft16,
    "draft16",
    "Draft-16 Section 9.4: \"If a server receives a GOAWAY with a non-zero New Session URI Length it MUST close the session with a PROTOCOL_VIOLATION.\"",
    (plain),
    moqtap_client::draft16::session::request_id::Role,
    publish_namespace_with_parameters
);

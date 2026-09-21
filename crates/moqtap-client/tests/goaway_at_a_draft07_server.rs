//! On draft-07 a server refuses a GOAWAY outright, whatever it carries.
//!
//! Section 6.3 states the rule about the message rather than about its
//! contents: "The server MUST terminate the session with a Protocol Violation
//! (Section 3.5) if it receives a GOAWAY message. The client MUST terminate the
//! session with a Protocol Violation (Section 3.5) if it receives multiple
//! GOAWAY messages."
//!
//! Draft-08 replaced the first sentence with a narrower one - "If a server
//! receives a GOAWAY with a non-zero New Session URI Length it MUST terminate
//! the session with a Protocol Violation" - which every draft from 08 to 20
//! carries and which is gated in `goaway_uri_at_a_server.rs`. Enumerated over
//! the raw text of all the drafts, "if it receives a GOAWAY message"
//! appears once, on draft-07, and "non-zero New Session URI Length" appears
//! once on each of the other thirteen and not on draft-07.
//!
//! So the two rules are not the same rule differently worded, and they do not
//! agree about the same message: an empty GOAWAY arriving at a server is legal
//! from draft-08 on and a session close on draft-07. That is why this gate is a
//! file of its own rather than a draft-07 block in the other one, and why
//! `an_empty_goaway_is_refused_too` is the test that distinguishes the two.
//!
//! Each assertion observes a consequence rather than reading a value back:
//! the session state after the message, the code the transport would close
//! with, whether the next request this endpoint tries is refused, and whether
//! the URI is retrievable afterwards.
//!
//! # Why this rule is gated in process and not on the wire
//!
//! It is a rule a *server* applies, and this crate has no server to apply it
//! with: `Connection::connect` is the only way to build one and it always
//! builds a client, so no connection here can ever be the endpoint the sentence
//! is about. `Endpoint` is public and role-agnostic, and the close code is on
//! its public error type, so what a server built on it would put on the wire is
//! exactly what these gates read.
//!
//! # Recorded failures
//!
//! Each was produced by making the change and running the tests.
//!
//! Dropping the guard:
//!
//! ```text
//! a draft-07 server refuses a GOAWAY whatever it carries: ()
//! ```
//!
//! Narrowing the guard to draft-08's rule - refusing only a GOAWAY that carries
//! a URI:
//!
//! ```text
//! this draft states the rule about the message, not about the URI: ()
//! ```
//!
//! Widening the guard to both roles:
//!
//! ```text
//! called `Result::unwrap()` on an `Err` value: GoAwayAtServer
//! ```
//!
//! Refusing after the session has already been moved on rather than before:
//!
//! ```text
//! assertion `left == right` failed: the refused URI was stored anyway
//! ```
//!
//! Dropping `fail_session` from the guard - the state this draft shipped
//! before the close was routed:
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

#![cfg(feature = "draft07")]

use moqtap_client::draft07::endpoint::{Endpoint, EndpointError, Role};
use moqtap_client::draft07::session::state::SessionState;
use moqtap_codec::draft07::error_codes::SessionErrorCode;
use moqtap_codec::draft07::message::{ClientSetup, GoAway};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// The URI a client would have no business offering.
const ELSEWHERE: &[u8] = b"https://elsewhere.example";

/// A namespace for the request each gate makes after the refusal. Nothing about
/// it matters except that the endpoint is asked to start something new.
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

/// The ROLE parameter Section 6.2.2.1 requires of both endpoints, as PubSub.
/// Without it the setup exchange this gate needs would not complete.
fn role() -> KeyValuePair {
    KeyValuePair { key: varint(0x00), value: KvpValue::Bytes(vec![0x03]) }
}

fn established(role_of_this_endpoint: Role) -> Endpoint {
    let mut endpoint = Endpoint::new(role_of_this_endpoint);
    endpoint.connect().unwrap();
    let client_setup =
        ClientSetup { supported_versions: vec![varint(0xff000007)], parameters: vec![role()] };
    endpoint.receive_client_setup_and_respond(&client_setup, varint(0xff000007)).unwrap();
    assert_eq!(endpoint.session_state(), SessionState::Active);
    endpoint
}

/// A GOAWAY carrying a migration URI ends the session at a server, and the URI
/// is not kept: a refusal that stored it anyway would leave an application free
/// to reconnect to somewhere a client chose.
///
/// Section 6.3 names the close and the code in the same sentence, so the
/// endpoint that raises this has already finished with the session and the
/// transport has a code to close with. Draining is the wrong end state as well
/// as Active: this GOAWAY is refused, not obeyed.
#[test]
fn a_goaway_carrying_a_uri_is_refused_at_a_server() {
    let mut endpoint = established(Role::Server);

    let err = endpoint
        .receive_goaway(&GoAway { new_session_uri: ELSEWHERE.to_vec() })
        .expect_err("a draft-07 server refuses a GOAWAY whatever it carries");
    assert!(matches!(err, EndpointError::GoAwayAtServer), "got {err:?}");
    assert_eq!(
        err.session_error_code(),
        Some(SessionErrorCode::ProtocolViolation),
        "a session this endpoint ended has no code for the transport to close with",
    );
    assert_eq!(endpoint.goaway_uri(), None, "the refused URI was stored anyway");
    assert_eq!(
        endpoint.session_state(),
        SessionState::Closed,
        "the violation was reported and the session was left running",
    );
    assert!(
        matches!(endpoint.announce(ns()), Err(EndpointError::NotActive)),
        "the session was over and the endpoint started a new request anyway",
    );
}

/// And so is one carrying nothing at all. This is the assertion that separates
/// draft-07's rule from the one every later draft states: from draft-08 on this
/// exact message is legal and drains the session.
#[test]
fn an_empty_goaway_is_refused_too() {
    let mut endpoint = established(Role::Server);

    let err = endpoint
        .receive_goaway(&GoAway { new_session_uri: Vec::new() })
        .expect_err("this draft states the rule about the message, not about the URI");
    assert!(matches!(err, EndpointError::GoAwayAtServer), "got {err:?}");
    assert_eq!(
        endpoint.session_state(),
        SessionState::Closed,
        "the violation was reported and the session was left running",
    );
}

/// A client takes the same message, which is what the field is for. Without
/// this the two gates above would pass on an endpoint that refused every GOAWAY
/// it ever received.
#[test]
fn a_client_takes_the_migration_uri() {
    let mut endpoint = established(Role::Client);

    endpoint.receive_goaway(&GoAway { new_session_uri: ELSEWHERE.to_vec() }).unwrap();
    assert_eq!(endpoint.session_state(), SessionState::Draining);
    assert_eq!(endpoint.goaway_uri(), Some(ELSEWHERE));
}

/// The second half of Section 6.3 - "The client MUST terminate the session with
/// a Protocol Violation (Section 3.5) if it receives multiple GOAWAY
/// messages" - asserted here beside the first so the two halves of one
/// paragraph are held in one place.
///
/// The refusal is a rule of its own, `EndpointError::RepeatedGoAway`, rather
/// than a Draining-to-Draining transition - that generic error is what a dozen
/// unrelated illegal transitions produce, and no close code could be routed
/// from it. The code and the wire close this reaches are gated in
/// `repeated_goaway_closes_the_session.rs`.
#[test]
fn a_client_refuses_a_second_goaway() {
    let mut endpoint = established(Role::Client);

    endpoint.receive_goaway(&GoAway { new_session_uri: Vec::new() }).unwrap();
    let err = endpoint
        .receive_goaway(&GoAway { new_session_uri: Vec::new() })
        .expect_err("a session can only be told to go away once");
    assert!(matches!(err, EndpointError::RepeatedGoAway), "got {err:?}");
}

/// The refusal *is* the close, so there is nothing left to close afterwards.
///
/// Section 6.3 says the server terminates the session, so a second close is a
/// close of something already over, and a server that could still be shut down
/// cleanly is a server that never ended the session the way the sentence
/// requires.
#[test]
fn a_refused_goaway_is_itself_the_close() {
    let mut endpoint = established(Role::Server);
    assert!(endpoint.receive_goaway(&GoAway { new_session_uri: Vec::new() }).is_err());
    assert!(endpoint.close().is_err(), "the session was already over");

    // A server that was never sent one closes normally, so the refusal above is
    // what ended this session and not something structural about the role.
    let mut untouched = established(Role::Server);
    untouched.close().expect("an untouched session closes");
}

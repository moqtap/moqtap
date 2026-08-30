#![cfg(feature = "draft14")]

use moqtap_client::draft14::session::state::*;

// ============================================================
// Happy-path transitions
// ============================================================

/// draft-14 Section 3.3: before the control stream is opened nothing has been
/// exchanged, so a session begins outside the Setup exchange rather than in it.
#[test]
fn session_initial_state_is_connecting() {
    let sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);
}

/// draft-14 Section 3.3: "The first stream opened is a client-initiated
/// bidirectional control stream where the endpoints exchange Setup messages",
/// and the sentence runs on into the messages that follow them on it.
#[test]
fn session_connecting_to_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().expect("on_connect should succeed from Connecting");
    assert_eq!(sm.state(), SessionState::SetupExchange);
}

/// draft-14 Section 3.2: "Endpoints use the exchange of Setup messages to
/// negotiate the MOQT version and any extensions to use." The session is usable
/// once that exchange has settled both.
#[test]
fn session_setup_exchange_to_active() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().expect("on_setup_complete should succeed from SetupExchange");
    assert_eq!(sm.state(), SessionState::Active);
}

/// draft-14 Section 9.4: "An endpoint sends a GOAWAY message to inform the peer
/// it intends to close the session soon."
#[test]
fn session_active_to_draining() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().expect("on_goaway should succeed from Active");
    assert_eq!(sm.state(), SessionState::Draining);
}

/// draft-14 Section 3.5: after a GOAWAY "it's RECOMMENDED that the client waits
/// until there are no more active subscriptions before closing the session".
#[test]
fn session_draining_to_closed() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().unwrap();
    sm.on_close().expect("on_close should succeed from Draining");
    assert_eq!(sm.state(), SessionState::Closed);
}

/// draft-14 Section 3: the whole of a session, from the control stream through
/// the Setup exchange and a GOAWAY to the close.
#[test]
fn session_full_lifecycle() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    sm.on_connect().unwrap();
    assert_eq!(sm.state(), SessionState::SetupExchange);

    sm.on_setup_complete().unwrap();
    assert_eq!(sm.state(), SessionState::Active);

    sm.on_goaway().unwrap();
    assert_eq!(sm.state(), SessionState::Draining);

    sm.on_close().unwrap();
    assert_eq!(sm.state(), SessionState::Closed);
}

// ============================================================
// Invalid transitions
// ============================================================

/// draft-14 Section 3.3: the control stream carries the Setup exchange first, so
/// there is no version agreed and no session to use before it.
#[test]
fn session_cannot_skip_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    // Cannot go directly from Connecting to Active via on_setup_complete.
    let result = sm.on_setup_complete();
    assert!(result.is_err(), "on_setup_complete from Connecting should fail");
}

/// draft-14 Section 3.5: a peer that has closed migrates by "establishing a new
/// session in the background", not by reviving the one it terminated.
#[test]
fn session_cannot_go_from_closed_to_active() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().unwrap();
    sm.on_close().unwrap();
    assert_eq!(sm.state(), SessionState::Closed);

    let result = sm.on_setup_complete();
    assert!(result.is_err(), "on_setup_complete from Closed should fail");
}

/// draft-14 Section 3.5: GOAWAY exists to drain a session proactively, and a
/// draining session is carried to its close rather than back into service.
#[test]
fn session_cannot_go_from_draining_to_active() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().unwrap();
    assert_eq!(sm.state(), SessionState::Draining);

    let result = sm.on_setup_complete();
    assert!(result.is_err(), "on_setup_complete from Draining should fail");
}

/// draft-14 Section 3.2: the version is chosen by the Setup exchange, so a
/// session cannot be in use before one has been chosen.
#[test]
fn session_cannot_go_from_connecting_to_active() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    let result = sm.on_setup_complete();
    assert!(result.is_err(), "on_setup_complete from Connecting should fail");
}

/// draft-14 Section 3.3: "a peer MAY close the session as a PROTOCOL_VIOLATION
/// if it receives a second bidirectional stream". Connecting again would open
/// one.
#[test]
fn session_cannot_go_from_active_to_connecting() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    assert_eq!(sm.state(), SessionState::Active);

    let result = sm.on_connect();
    assert!(result.is_err(), "on_connect from Active should fail");
}

/// draft-14 Section 3.4: termination ends the Transport Session, and the control
/// stream ended with it.
#[test]
fn session_cannot_go_from_closed_to_connecting() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().unwrap();
    sm.on_close().unwrap();
    assert_eq!(sm.state(), SessionState::Closed);

    let result = sm.on_connect();
    assert!(result.is_err(), "on_connect from Closed should fail");
}

/// draft-14 Section 3.3: the Setup exchange is "followed by other messages
/// defined in Section 9", and GOAWAY is one of them. With no control stream
/// there is nothing to carry it.
#[test]
fn session_cannot_goaway_from_connecting() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    let result = sm.on_goaway();
    assert!(result.is_err(), "on_goaway from Connecting should fail");
}

/// draft-14 Section 3.3: the Setup exchange is "followed by other messages
/// defined in Section 9", so a GOAWAY follows it rather than interrupts it.
#[test]
fn session_cannot_goaway_from_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    assert_eq!(sm.state(), SessionState::SetupExchange);

    let result = sm.on_goaway();
    assert!(result.is_err(), "on_goaway from SetupExchange should fail");
}

/// draft-14 Section 3.4: "The Transport Session can be terminated at any point."
/// Draining is what a GOAWAY asks for, not a stage a close must pass through.
#[test]
fn session_active_to_closed_directly() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    assert_eq!(sm.state(), SessionState::Active);

    // Active reaches Closed without a GOAWAY first.
    sm.on_close().expect("on_close from Active should succeed");
    assert_eq!(sm.state(), SessionState::Closed);
}

/// draft-14 Section 9.4: "The endpoint MUST terminate the session with a
/// PROTOCOL_VIOLATION ... if it receives multiple GOAWAY messages."
#[test]
fn session_cannot_goaway_from_draining() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().unwrap();
    assert_eq!(sm.state(), SessionState::Draining);

    let result = sm.on_goaway();
    assert!(result.is_err(), "on_goaway from Draining should fail");
}

/// draft-14 Section 3.4: termination ends an established Transport Session, and
/// in Connecting no transport has been established to end.
#[test]
fn session_cannot_close_from_connecting() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    let result = sm.on_close();
    assert!(result.is_err(), "on_close from Connecting should fail");
}

/// draft-14 Section 3.4: "The Transport Session can be terminated at any point."
/// Section 9.3.1 obliges an endpoint to do so from here in particular: a version
/// mismatch is discoverable only during the Setup exchange, and "the
/// corresponding peer MUST close the session with VERSION_NEGOTIATION_FAILED".
///
/// The same close is asserted on the other twelve drafts in
/// `close_during_setup.rs`, which is where the ablation for it lives.
#[test]
fn session_closes_from_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    assert_eq!(sm.state(), SessionState::SetupExchange);

    sm.on_close().expect("a session may be terminated during the Setup exchange");
    assert_eq!(sm.state(), SessionState::Closed);
}

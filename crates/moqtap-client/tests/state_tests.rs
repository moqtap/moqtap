#![cfg(feature = "draft14")]

use moqtap_client::draft14::session::state::*;

// ============================================================
// Happy-path transitions
// ============================================================

/// draft-14 section 6.1: Session starts in Connecting state.
#[test]
fn session_initial_state_is_connecting() {
    let sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);
}

/// draft-14 section 6.1: Connecting -> SetupExchange when QUIC stream opened.
#[test]
fn session_connecting_to_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().expect("on_connect should succeed from Connecting");
    assert_eq!(sm.state(), SessionState::SetupExchange);
}

/// draft-14 section 6.1: SetupExchange -> Active after CLIENT_SETUP/SERVER_SETUP exchange.
#[test]
fn session_setup_exchange_to_active() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().expect("on_setup_complete should succeed from SetupExchange");
    assert_eq!(sm.state(), SessionState::Active);
}

/// draft-14 section 6.1: Active -> Draining on GOAWAY received.
#[test]
fn session_active_to_draining() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().expect("on_goaway should succeed from Active");
    assert_eq!(sm.state(), SessionState::Draining);
}

/// draft-14 section 6.1: Draining -> Closed.
#[test]
fn session_draining_to_closed() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    sm.on_goaway().unwrap();
    sm.on_close().expect("on_close should succeed from Draining");
    assert_eq!(sm.state(), SessionState::Closed);
}

/// draft-14 section 6.1: Full lifecycle Connecting -> SetupExchange -> Active -> Draining -> Closed.
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

/// draft-14 section 6.1: Cannot skip SetupExchange (Connecting -> Active not allowed).
#[test]
fn session_cannot_skip_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    // Cannot go directly from Connecting to Active via on_setup_complete.
    let result = sm.on_setup_complete();
    assert!(result.is_err(), "on_setup_complete from Connecting should fail");
}

/// draft-14 section 6.1: Closed is terminal; cannot transition to Active.
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

/// draft-14 section 6.1: Cannot go backward from Draining to Active.
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

/// draft-14 section 6.1: Cannot skip SetupExchange from Connecting.
#[test]
fn session_cannot_go_from_connecting_to_active() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    let result = sm.on_setup_complete();
    assert!(result.is_err(), "on_setup_complete from Connecting should fail");
}

/// draft-14 section 6.1: Cannot go backward from Active to Connecting.
#[test]
fn session_cannot_go_from_active_to_connecting() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    assert_eq!(sm.state(), SessionState::Active);

    let result = sm.on_connect();
    assert!(result.is_err(), "on_connect from Active should fail");
}

/// draft-14 section 6.1: Closed is terminal; cannot transition to Connecting.
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

/// draft-14 section 6.1: GOAWAY can only be sent/received in Active state.
#[test]
fn session_cannot_goaway_from_connecting() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    let result = sm.on_goaway();
    assert!(result.is_err(), "on_goaway from Connecting should fail");
}

/// draft-14 section 6.1: GOAWAY can only be sent/received in Active state.
#[test]
fn session_cannot_goaway_from_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    assert_eq!(sm.state(), SessionState::SetupExchange);

    let result = sm.on_goaway();
    assert!(result.is_err(), "on_goaway from SetupExchange should fail");
}

/// draft-14 section 6.1: Session can close from Active state (without going through Draining).
#[test]
fn session_active_to_closed_directly() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    sm.on_setup_complete().unwrap();
    assert_eq!(sm.state(), SessionState::Active);

    // on_close from Active should succeed (Active|Draining -> Closed).
    sm.on_close().expect("on_close from Active should succeed");
    assert_eq!(sm.state(), SessionState::Closed);
}

/// draft-14 section 6.1: GOAWAY cannot be sent from Draining (already draining).
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

/// draft-14 section 6.1: Cannot close from Connecting state (only Active|Draining -> Closed).
#[test]
fn session_cannot_close_from_connecting() {
    let mut sm = SessionStateMachine::new();
    assert_eq!(sm.state(), SessionState::Connecting);

    let result = sm.on_close();
    assert!(result.is_err(), "on_close from Connecting should fail");
}

/// draft-14 section 6.1: Cannot close from SetupExchange state (only Active|Draining -> Closed).
#[test]
fn session_cannot_close_from_setup_exchange() {
    let mut sm = SessionStateMachine::new();
    sm.on_connect().unwrap();
    assert_eq!(sm.state(), SessionState::SetupExchange);

    let result = sm.on_close();
    assert!(result.is_err(), "on_close from SetupExchange should fail");
}

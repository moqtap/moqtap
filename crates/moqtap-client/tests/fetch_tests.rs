use moqtap_client::fetch::*;

// ============================================================
// Happy path
// ============================================================

/// draft-14 section 6.9: Fetch starts in Idle state.
#[test]
fn fetch_initial_state_is_idle() {
    let sm = FetchStateMachine::new();
    assert_eq!(sm.state(), FetchState::Idle);
}

/// draft-14 section 6.9: Idle -> Pending on FETCH sent.
#[test]
fn fetch_idle_to_pending() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().expect("on_fetch_sent from Idle should succeed");
    assert_eq!(sm.state(), FetchState::Pending);
}

/// draft-14 section 6.9: Pending -> Receiving on FETCH_OK received.
#[test]
fn fetch_pending_to_receiving() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().expect("on_fetch_ok from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Receiving);
}

/// draft-14 section 6.9: Receiving -> Done on stream FIN.
#[test]
fn fetch_receiving_to_done_via_fin() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_stream_fin().expect("on_stream_fin from Receiving should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 section 6.9: Receiving -> Done on stream RESET.
#[test]
fn fetch_receiving_to_done_via_reset() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_stream_reset().expect("on_stream_reset from Receiving should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 section 6.9: Full lifecycle Idle -> Pending -> Receiving -> Done.
#[test]
fn fetch_full_lifecycle() {
    let mut sm = FetchStateMachine::new();
    assert_eq!(sm.state(), FetchState::Idle);

    sm.on_fetch_sent().unwrap();
    assert_eq!(sm.state(), FetchState::Pending);

    sm.on_fetch_ok().unwrap();
    assert_eq!(sm.state(), FetchState::Receiving);

    sm.on_stream_fin().unwrap();
    assert_eq!(sm.state(), FetchState::Done);
}

// ============================================================
// Cancel / error
// ============================================================

/// draft-14 section 6.9: Pending -> Done on FETCH_CANCEL.
#[test]
fn fetch_pending_to_done_via_cancel() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_cancel().expect("on_fetch_cancel from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 section 6.9: Receiving -> Done on FETCH_CANCEL.
#[test]
fn fetch_receiving_to_done_via_cancel() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_fetch_cancel().expect("on_fetch_cancel from Receiving should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 section 6.9: Pending -> Done on FETCH_ERROR received.
#[test]
fn fetch_pending_to_done_via_error() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_error().expect("on_fetch_error from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

// ============================================================
// Invalid transitions
// ============================================================

/// draft-14 section 6.9: Cannot receive FETCH_OK from Idle.
#[test]
fn fetch_cannot_fetch_ok_from_idle() {
    let mut sm = FetchStateMachine::new();
    let result = sm.on_fetch_ok();
    assert!(result.is_err(), "on_fetch_ok from Idle should fail");
}

/// draft-14 section 6.9: Cannot cancel from Idle.
#[test]
fn fetch_cannot_cancel_from_idle() {
    let mut sm = FetchStateMachine::new();
    let result = sm.on_fetch_cancel();
    assert!(result.is_err(), "on_fetch_cancel from Idle should fail");
}

/// draft-14 section 6.9: Cannot send FETCH from Receiving.
#[test]
fn fetch_cannot_send_from_receiving() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    assert_eq!(sm.state(), FetchState::Receiving);

    let result = sm.on_fetch_sent();
    assert!(result.is_err(), "on_fetch_sent from Receiving should fail");
}

/// draft-14 section 6.9: Cannot transition from Done to any other state (terminal).
#[test]
fn fetch_cannot_reuse_after_done() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_stream_fin().unwrap();
    assert_eq!(sm.state(), FetchState::Done);

    let result = sm.on_fetch_sent();
    assert!(result.is_err(), "on_fetch_sent from Done should fail");
}

/// draft-14 section 6.9: Cannot receive stream FIN from Idle.
#[test]
fn fetch_cannot_stream_fin_from_idle() {
    let mut sm = FetchStateMachine::new();
    let result = sm.on_stream_fin();
    assert!(result.is_err(), "on_stream_fin from Idle should fail");
}

/// draft-14 section 6.9: Cannot receive stream FIN from Pending (only from Receiving).
#[test]
fn fetch_cannot_stream_fin_from_pending() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    assert_eq!(sm.state(), FetchState::Pending);

    let result = sm.on_stream_fin();
    assert!(result.is_err(), "on_stream_fin from Pending should fail");
}

/// draft-14 section 6.9: Cannot receive FETCH_ERROR from Receiving (only from Pending).
#[test]
fn fetch_cannot_fetch_error_from_receiving() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    assert_eq!(sm.state(), FetchState::Receiving);

    let result = sm.on_fetch_error();
    assert!(result.is_err(), "on_fetch_error from Receiving should fail");
}

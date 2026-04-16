#![cfg(feature = "draft14")]

use moqtap_client::draft14::track_status::*;

// ============================================================
// Happy path
// ============================================================

/// TrackStatus starts in Idle state.
#[test]
fn track_status_initial_state_is_idle() {
    let sm = TrackStatusStateMachine::new();
    assert_eq!(sm.state(), TrackStatusState::Idle);
}

/// Idle -> Pending on TRACK_STATUS sent.
#[test]
fn track_status_idle_to_pending() {
    let mut sm = TrackStatusStateMachine::new();
    sm.on_track_status_sent().expect("on_track_status_sent from Idle should succeed");
    assert_eq!(sm.state(), TrackStatusState::Pending);
}

/// Pending -> Done on TRACK_STATUS_OK received.
#[test]
fn track_status_pending_to_done_via_ok() {
    let mut sm = TrackStatusStateMachine::new();
    sm.on_track_status_sent().unwrap();
    sm.on_track_status_ok().expect("on_track_status_ok from Pending should succeed");
    assert_eq!(sm.state(), TrackStatusState::Done);
}

/// Pending -> Done on TRACK_STATUS_ERROR received.
#[test]
fn track_status_pending_to_done_via_error() {
    let mut sm = TrackStatusStateMachine::new();
    sm.on_track_status_sent().unwrap();
    sm.on_track_status_error().expect("on_track_status_error from Pending should succeed");
    assert_eq!(sm.state(), TrackStatusState::Done);
}

/// Full lifecycle Idle -> Pending -> Done.
#[test]
fn track_status_full_lifecycle() {
    let mut sm = TrackStatusStateMachine::new();
    assert_eq!(sm.state(), TrackStatusState::Idle);

    sm.on_track_status_sent().unwrap();
    assert_eq!(sm.state(), TrackStatusState::Pending);

    sm.on_track_status_ok().unwrap();
    assert_eq!(sm.state(), TrackStatusState::Done);
}

/// Default impl creates Idle state.
#[test]
fn track_status_default_is_idle() {
    let sm = TrackStatusStateMachine::default();
    assert_eq!(sm.state(), TrackStatusState::Idle);
}

// ============================================================
// Invalid transitions
// ============================================================

/// Cannot receive TRACK_STATUS_OK from Idle.
#[test]
fn track_status_cannot_ok_from_idle() {
    let mut sm = TrackStatusStateMachine::new();
    assert!(sm.on_track_status_ok().is_err());
}

/// Cannot receive TRACK_STATUS_ERROR from Idle.
#[test]
fn track_status_cannot_error_from_idle() {
    let mut sm = TrackStatusStateMachine::new();
    assert!(sm.on_track_status_error().is_err());
}

/// Cannot send TRACK_STATUS from Done.
#[test]
fn track_status_cannot_send_from_done() {
    let mut sm = TrackStatusStateMachine::new();
    sm.on_track_status_sent().unwrap();
    sm.on_track_status_ok().unwrap();
    assert_eq!(sm.state(), TrackStatusState::Done);
    assert!(sm.on_track_status_sent().is_err());
}

use moqtap_client::publish::*;

// ============================================================
// Happy path
// ============================================================

/// Publish starts in Idle state.
#[test]
fn publish_initial_state_is_idle() {
    let sm = PublishStateMachine::new();
    assert_eq!(sm.state(), PublishState::Idle);
}

/// Idle -> Publishing on PUBLISH sent.
#[test]
fn publish_idle_to_publishing() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().expect("on_publish_sent from Idle should succeed");
    assert_eq!(sm.state(), PublishState::Publishing);
}

/// Publishing -> Active on PUBLISH_OK received.
#[test]
fn publish_publishing_to_active() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().unwrap();
    sm.on_publish_ok().expect("on_publish_ok from Publishing should succeed");
    assert_eq!(sm.state(), PublishState::Active);
}

/// Publishing -> Done on PUBLISH_ERROR received.
#[test]
fn publish_publishing_to_done_via_error() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().unwrap();
    sm.on_publish_error().expect("on_publish_error from Publishing should succeed");
    assert_eq!(sm.state(), PublishState::Done);
}

/// Active -> Done on PUBLISH_DONE sent.
#[test]
fn publish_active_to_done_via_publish_done() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().unwrap();
    sm.on_publish_ok().unwrap();
    sm.on_publish_done_sent().expect("on_publish_done_sent from Active should succeed");
    assert_eq!(sm.state(), PublishState::Done);
}

/// Full lifecycle Idle -> Publishing -> Active -> Done.
#[test]
fn publish_full_lifecycle() {
    let mut sm = PublishStateMachine::new();
    assert_eq!(sm.state(), PublishState::Idle);

    sm.on_publish_sent().unwrap();
    assert_eq!(sm.state(), PublishState::Publishing);

    sm.on_publish_ok().unwrap();
    assert_eq!(sm.state(), PublishState::Active);

    sm.on_publish_done_sent().unwrap();
    assert_eq!(sm.state(), PublishState::Done);
}

/// Default impl creates Idle state.
#[test]
fn publish_default_is_idle() {
    let sm = PublishStateMachine::default();
    assert_eq!(sm.state(), PublishState::Idle);
}

// ============================================================
// Invalid transitions
// ============================================================

/// Cannot receive PUBLISH_OK from Idle.
#[test]
fn publish_cannot_ok_from_idle() {
    let mut sm = PublishStateMachine::new();
    assert!(sm.on_publish_ok().is_err());
}

/// Cannot receive PUBLISH_ERROR from Idle.
#[test]
fn publish_cannot_error_from_idle() {
    let mut sm = PublishStateMachine::new();
    assert!(sm.on_publish_error().is_err());
}

/// Cannot send PUBLISH_DONE from Idle.
#[test]
fn publish_cannot_done_from_idle() {
    let mut sm = PublishStateMachine::new();
    assert!(sm.on_publish_done_sent().is_err());
}

/// Cannot send PUBLISH from Active.
#[test]
fn publish_cannot_send_from_active() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().unwrap();
    sm.on_publish_ok().unwrap();
    assert_eq!(sm.state(), PublishState::Active);
    assert!(sm.on_publish_sent().is_err());
}

/// Cannot send PUBLISH from Done (terminal).
#[test]
fn publish_cannot_reuse_after_done() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().unwrap();
    sm.on_publish_ok().unwrap();
    sm.on_publish_done_sent().unwrap();
    assert_eq!(sm.state(), PublishState::Done);
    assert!(sm.on_publish_sent().is_err());
}

/// Cannot receive PUBLISH_ERROR from Active.
#[test]
fn publish_cannot_error_from_active() {
    let mut sm = PublishStateMachine::new();
    sm.on_publish_sent().unwrap();
    sm.on_publish_ok().unwrap();
    assert_eq!(sm.state(), PublishState::Active);
    assert!(sm.on_publish_error().is_err());
}

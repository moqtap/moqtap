#![cfg(feature = "draft14")]

use moqtap_client::draft14::namespace::*;

// ============================================================
// SubscribeNamespace happy path
// ============================================================

/// draft-14 section 6.6: SubscribeNamespace starts in Idle state.
#[test]
fn sub_ns_initial_state_is_idle() {
    let sm = SubscribeNamespaceStateMachine::new();
    assert_eq!(sm.state(), SubscribeNamespaceState::Idle);
}

/// draft-14 section 6.6: Idle -> Pending on SUBSCRIBE_NAMESPACE sent.
#[test]
fn sub_ns_idle_to_pending() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().expect("on_subscribe_namespace_sent from Idle should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Pending);
}

/// draft-14 section 6.6: Pending -> Active on SUBSCRIBE_NAMESPACE_OK received.
#[test]
fn sub_ns_pending_to_active() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_ok().expect("on_subscribe_namespace_ok from Pending should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Active);
}

/// draft-14 section 6.6: Active -> Done on UNSUBSCRIBE_NAMESPACE sent.
#[test]
fn sub_ns_active_to_done_via_unsubscribe() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_ok().unwrap();
    sm.on_unsubscribe_namespace().expect("on_unsubscribe_namespace from Active should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Done);
}

/// draft-14 section 6.6: Pending -> Done on SUBSCRIBE_NAMESPACE_ERROR received.
#[test]
fn sub_ns_pending_to_done_via_error() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_error()
        .expect("on_subscribe_namespace_error from Pending should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Done);
}

/// draft-14 section 6.6: Full lifecycle Idle -> Pending -> Active -> Done.
#[test]
fn sub_ns_full_lifecycle() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    assert_eq!(sm.state(), SubscribeNamespaceState::Idle);

    sm.on_subscribe_namespace_sent().unwrap();
    assert_eq!(sm.state(), SubscribeNamespaceState::Pending);

    sm.on_subscribe_namespace_ok().unwrap();
    assert_eq!(sm.state(), SubscribeNamespaceState::Active);

    sm.on_unsubscribe_namespace().unwrap();
    assert_eq!(sm.state(), SubscribeNamespaceState::Done);
}

// ============================================================
// SubscribeNamespace invalid transitions
// ============================================================

/// draft-14 section 6.6: Cannot receive SUBSCRIBE_NAMESPACE_OK from Idle.
#[test]
fn sub_ns_cannot_ok_from_idle() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    let result = sm.on_subscribe_namespace_ok();
    assert!(result.is_err(), "on_subscribe_namespace_ok from Idle should fail");
}

/// draft-14 section 6.6: Cannot transition from Done to any other state.
#[test]
fn sub_ns_cannot_reuse_after_done() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_ok().unwrap();
    sm.on_unsubscribe_namespace().unwrap();
    assert_eq!(sm.state(), SubscribeNamespaceState::Done);

    let result = sm.on_subscribe_namespace_sent();
    assert!(result.is_err(), "on_subscribe_namespace_sent from Done should fail");
}

/// draft-14 section 6.6: Cannot UNSUBSCRIBE_NAMESPACE from Idle.
#[test]
fn sub_ns_cannot_unsubscribe_from_idle() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    let result = sm.on_unsubscribe_namespace();
    assert!(result.is_err(), "on_unsubscribe_namespace from Idle should fail");
}

// ============================================================
// PublishNamespace happy path
// ============================================================

/// draft-14 section 6.7: PublishNamespace starts in Idle state.
#[test]
fn pub_ns_initial_state_is_idle() {
    let sm = PublishNamespaceStateMachine::new();
    assert_eq!(sm.state(), PublishNamespaceState::Idle);
}

/// draft-14 section 6.7: Idle -> Pending on PUBLISH_NAMESPACE sent.
#[test]
fn pub_ns_idle_to_pending() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().expect("on_publish_namespace_sent from Idle should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Pending);
}

/// draft-14 section 6.7: Pending -> Active on PUBLISH_NAMESPACE_OK received.
#[test]
fn pub_ns_pending_to_active() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().expect("on_publish_namespace_ok from Pending should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Active);
}

/// draft-14 section 6.7: Active -> Done on PUBLISH_NAMESPACE_DONE sent (publisher withdrawing).
#[test]
fn pub_ns_active_to_done_via_done() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().unwrap();
    sm.on_publish_namespace_done().expect("on_publish_namespace_done from Active should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 section 6.7: Active -> Done on PUBLISH_NAMESPACE_CANCEL received (subscriber cancelling).
#[test]
fn pub_ns_active_to_done_via_cancel() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().unwrap();
    sm.on_publish_namespace_cancel()
        .expect("on_publish_namespace_cancel from Active should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 section 6.7: Pending -> Done on PUBLISH_NAMESPACE_ERROR received.
#[test]
fn pub_ns_pending_to_done_via_error() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_error()
        .expect("on_publish_namespace_error from Pending should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 section 6.7: Full lifecycle with PUBLISH_NAMESPACE_DONE.
#[test]
fn pub_ns_full_lifecycle_with_done() {
    let mut sm = PublishNamespaceStateMachine::new();
    assert_eq!(sm.state(), PublishNamespaceState::Idle);

    sm.on_publish_namespace_sent().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Pending);

    sm.on_publish_namespace_ok().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Active);

    sm.on_publish_namespace_done().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 section 6.7: Full lifecycle with PUBLISH_NAMESPACE_CANCEL.
#[test]
fn pub_ns_full_lifecycle_with_cancel() {
    let mut sm = PublishNamespaceStateMachine::new();
    assert_eq!(sm.state(), PublishNamespaceState::Idle);

    sm.on_publish_namespace_sent().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Pending);

    sm.on_publish_namespace_ok().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Active);

    sm.on_publish_namespace_cancel().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

// ============================================================
// PublishNamespace invalid transitions
// ============================================================

/// draft-14 section 6.7: Cannot receive PUBLISH_NAMESPACE_OK from Idle.
#[test]
fn pub_ns_cannot_ok_from_idle() {
    let mut sm = PublishNamespaceStateMachine::new();
    let result = sm.on_publish_namespace_ok();
    assert!(result.is_err(), "on_publish_namespace_ok from Idle should fail");
}

/// draft-14 section 6.7: Cannot send PUBLISH_NAMESPACE_DONE from Idle.
#[test]
fn pub_ns_cannot_done_from_idle() {
    let mut sm = PublishNamespaceStateMachine::new();
    let result = sm.on_publish_namespace_done();
    assert!(result.is_err(), "on_publish_namespace_done from Idle should fail");
}

/// draft-14 section 6.7: Cannot transition from Done to any other state (terminal).
#[test]
fn pub_ns_cannot_reuse_after_done() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().unwrap();
    sm.on_publish_namespace_done().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Done);

    let result = sm.on_publish_namespace_sent();
    assert!(result.is_err(), "on_publish_namespace_sent from Done should fail");
}

/// draft-14 section 6.7: Cannot receive PUBLISH_NAMESPACE_CANCEL from Idle.
#[test]
fn pub_ns_cannot_cancel_from_idle() {
    let mut sm = PublishNamespaceStateMachine::new();
    let result = sm.on_publish_namespace_cancel();
    assert!(result.is_err(), "on_publish_namespace_cancel from Idle should fail");
}

/// draft-14 section 6.7: Cannot receive PUBLISH_NAMESPACE_CANCEL from Pending.
#[test]
fn pub_ns_cannot_cancel_from_pending() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Pending);

    let result = sm.on_publish_namespace_cancel();
    assert!(result.is_err(), "on_publish_namespace_cancel from Pending should fail");
}

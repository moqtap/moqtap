#![cfg(feature = "draft14")]

use moqtap_client::draft14::subscription::*;

// ============================================================
// Happy path
// ============================================================

/// draft-14 section 6.4: Subscription starts in Idle state.
#[test]
fn subscription_initial_state_is_idle() {
    let sm = SubscriptionStateMachine::new();
    assert_eq!(sm.state(), SubscriptionState::Idle);
}

/// draft-14 section 6.4: Idle -> Subscribing on SUBSCRIBE sent.
#[test]
fn subscription_idle_to_subscribing() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().expect("on_subscribe_sent from Idle should succeed");
    assert_eq!(sm.state(), SubscriptionState::Subscribing);
}

/// draft-14 section 6.4: Subscribing -> Active on SUBSCRIBE_OK received.
#[test]
fn subscription_subscribing_to_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().expect("on_subscribe_ok from Subscribing should succeed");
    assert_eq!(sm.state(), SubscriptionState::Active);
}

/// draft-14 section 6.4: Active -> Done on UNSUBSCRIBE sent.
#[test]
fn subscription_active_to_done_via_unsubscribe() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    sm.on_unsubscribe().expect("on_unsubscribe from Active should succeed");
    assert_eq!(sm.state(), SubscriptionState::Done);
}

/// draft-14 section 6.4: Active -> Done on PUBLISH_DONE received.
#[test]
fn subscription_active_to_done_via_publish_done() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    sm.on_publish_done().expect("on_publish_done from Active should succeed");
    assert_eq!(sm.state(), SubscriptionState::Done);
}

/// draft-14 section 6.4: Subscribing -> Done on SUBSCRIBE_ERROR received.
#[test]
fn subscription_subscribing_to_done_via_error() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_error().expect("on_subscribe_error from Subscribing should succeed");
    assert_eq!(sm.state(), SubscriptionState::Done);
}

/// draft-14 section 6.4: Full lifecycle Idle -> Subscribing -> Active -> Done.
#[test]
fn subscription_full_lifecycle() {
    let mut sm = SubscriptionStateMachine::new();
    assert_eq!(sm.state(), SubscriptionState::Idle);

    sm.on_subscribe_sent().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Subscribing);

    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);

    sm.on_unsubscribe().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Done);
}

// ============================================================
// SUBSCRIBE_UPDATE (self-transition)
// ============================================================

/// draft-14 section 6.4: Active -> Active on SUBSCRIBE_UPDATE received.
#[test]
fn subscribe_update_from_active_stays_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);
    sm.on_subscribe_update().expect("on_subscribe_update from Active should succeed");
    assert_eq!(sm.state(), SubscriptionState::Active);
}

/// draft-14 section 6.4: Cannot receive SUBSCRIBE_UPDATE from Idle.
#[test]
fn subscribe_update_from_idle_fails() {
    let mut sm = SubscriptionStateMachine::new();
    assert!(sm.on_subscribe_update().is_err());
}

/// draft-14 section 6.4: Cannot receive SUBSCRIBE_UPDATE from Subscribing.
#[test]
fn subscribe_update_from_subscribing_fails() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Subscribing);
    assert!(sm.on_subscribe_update().is_err());
}

/// draft-14 section 6.4: Cannot receive SUBSCRIBE_UPDATE from Done.
#[test]
fn subscribe_update_from_done_fails() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_error().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Done);
    assert!(sm.on_subscribe_update().is_err());
}

// ============================================================
// Invalid transitions
// ============================================================

/// draft-14 section 6.4: Cannot send SUBSCRIBE_OK from Idle.
#[test]
fn subscription_cannot_subscribe_ok_from_idle() {
    let mut sm = SubscriptionStateMachine::new();
    let result = sm.on_subscribe_ok();
    assert!(result.is_err(), "on_subscribe_ok from Idle should fail");
}

/// draft-14 section 6.4: Cannot UNSUBSCRIBE from Idle.
#[test]
fn subscription_cannot_unsubscribe_from_idle() {
    let mut sm = SubscriptionStateMachine::new();
    let result = sm.on_unsubscribe();
    assert!(result.is_err(), "on_unsubscribe from Idle should fail");
}

/// draft-14 section 6.4: Cannot send SUBSCRIBE from Active.
#[test]
fn subscription_cannot_subscribe_from_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);

    let result = sm.on_subscribe_sent();
    assert!(result.is_err(), "on_subscribe_sent from Active should fail");
}

/// draft-14 section 6.4: Cannot transition from Done to any other state.
#[test]
fn subscription_cannot_subscribe_ok_from_done() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_error().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Done);

    let result = sm.on_subscribe_ok();
    assert!(result.is_err(), "on_subscribe_ok from Done should fail");
}

/// draft-14 section 6.4: Cannot receive PUBLISH_DONE from Idle.
#[test]
fn subscription_cannot_publish_done_from_idle() {
    let mut sm = SubscriptionStateMachine::new();
    let result = sm.on_publish_done();
    assert!(result.is_err(), "on_publish_done from Idle should fail");
}

/// draft-14 section 6.4: Cannot transition from Done to any other state (terminal).
#[test]
fn subscription_cannot_reuse_after_done() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    sm.on_unsubscribe().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Done);

    let result = sm.on_subscribe_sent();
    assert!(result.is_err(), "on_subscribe_sent from Done should fail");
}

/// draft-14 section 6.4: Cannot receive SUBSCRIBE_ERROR from Active (only from Subscribing).
#[test]
fn subscription_cannot_subscribe_error_from_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);

    let result = sm.on_subscribe_error();
    assert!(result.is_err(), "on_subscribe_error from Active should fail");
}

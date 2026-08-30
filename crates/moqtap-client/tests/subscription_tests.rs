#![cfg(feature = "draft14")]

use moqtap_client::draft14::subscription::*;

// ============================================================
// Happy path
// ============================================================

/// draft-14 Section 5.1: a subscription starts in Idle, before any SUBSCRIBE.
#[test]
fn subscription_initial_state_is_idle() {
    let sm = SubscriptionStateMachine::new();
    assert_eq!(sm.state(), SubscriptionState::Idle);
}

/// draft-14 Section 9.7: Idle -> Subscribing on SUBSCRIBE sent.
#[test]
fn subscription_idle_to_subscribing() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().expect("on_subscribe_sent from Idle should succeed");
    assert_eq!(sm.state(), SubscriptionState::Subscribing);
}

/// draft-14 Section 9.8: Subscribing -> Active on SUBSCRIBE_OK received.
#[test]
fn subscription_subscribing_to_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().expect("on_subscribe_ok from Subscribing should succeed");
    assert_eq!(sm.state(), SubscriptionState::Active);
}

/// draft-14 Section 9.11: Active -> Done on UNSUBSCRIBE sent.
#[test]
fn subscription_active_to_done_via_unsubscribe() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    sm.on_unsubscribe().expect("on_unsubscribe from Active should succeed");
    assert_eq!(sm.state(), SubscriptionState::Done);
}

/// draft-14 Section 9.12: Active -> Done on PUBLISH_DONE received.
#[test]
fn subscription_active_to_done_via_publish_done() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    sm.on_publish_done().expect("on_publish_done from Active should succeed");
    assert_eq!(sm.state(), SubscriptionState::Done);
}

/// draft-14 Section 9.9: Subscribing -> Done on SUBSCRIBE_ERROR received.
#[test]
fn subscription_subscribing_to_done_via_error() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_error().expect("on_subscribe_error from Subscribing should succeed");
    assert_eq!(sm.state(), SubscriptionState::Done);
}

/// draft-14 Section 5.1: the whole lifecycle, Idle -> Subscribing -> Active -> Done.
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

/// draft-14 Section 9.10: Active -> Active on SUBSCRIBE_UPDATE received.
#[test]
fn subscribe_update_from_active_stays_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);
    sm.on_subscribe_update().expect("on_subscribe_update from Active should succeed");
    assert_eq!(sm.state(), SubscriptionState::Active);
}

/// draft-14 Section 9.10: an update from Idle names a Request ID no SUBSCRIBE
/// has established.
#[test]
fn subscribe_update_from_idle_fails() {
    let mut sm = SubscriptionStateMachine::new();
    assert!(sm.on_subscribe_update().is_err());
}

/// draft-14 Section 9.10: a SUBSCRIBE_UPDATE may arrive before the SUBSCRIBE
/// has been answered.
///
/// The section asks only that the identifier already name something — "This
/// MUST match an existing Request ID" — and a Request ID exists from the moment
/// the SUBSCRIBE carrying it is sent. Nothing in the draft orders an update
/// against the SUBSCRIBE_OK, so a subscriber that sends both back to back is
/// conforming.
///
/// The SUBSCRIBE_OK afterwards is what says the update left the subscription
/// where it found it: it is the transition out of Subscribing, and it succeeds
/// only from there.
#[test]
fn subscribe_update_before_the_subscribe_is_answered_stays_subscribing() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_update().expect("an update may precede the subscription's own answer");
    sm.on_subscribe_ok().expect("the answer still arrives to a subscription that is Subscribing");
}

/// draft-14 Section 9.10: an update from Done names a subscription that has ended.
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

/// draft-14 Section 9.8: SUBSCRIBE_OK answers a SUBSCRIBE, so it has nothing to
/// answer from Idle.
#[test]
fn subscription_cannot_subscribe_ok_from_idle() {
    let mut sm = SubscriptionStateMachine::new();
    let result = sm.on_subscribe_ok();
    assert!(result.is_err(), "on_subscribe_ok from Idle should fail");
}

/// draft-14 Section 9.11: UNSUBSCRIBE ends a subscription, so it has none to end
/// from Idle.
#[test]
fn subscription_cannot_unsubscribe_from_idle() {
    let mut sm = SubscriptionStateMachine::new();
    let result = sm.on_unsubscribe();
    assert!(result.is_err(), "on_unsubscribe from Idle should fail");
}

/// draft-14 Section 9.7: a second SUBSCRIBE is a second subscription, not a
/// transition of this one.
#[test]
fn subscription_cannot_subscribe_from_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);

    let result = sm.on_subscribe_sent();
    assert!(result.is_err(), "on_subscribe_sent from Active should fail");
}

/// draft-14 Section 9.8: a refused subscription is not then accepted.
#[test]
fn subscription_cannot_subscribe_ok_from_done() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_error().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Done);

    let result = sm.on_subscribe_ok();
    assert!(result.is_err(), "on_subscribe_ok from Done should fail");
}

/// draft-14 Section 9.12: PUBLISH_DONE ends a subscription, so it has none to end
/// from Idle.
#[test]
fn subscription_cannot_publish_done_from_idle() {
    let mut sm = SubscriptionStateMachine::new();
    let result = sm.on_publish_done();
    assert!(result.is_err(), "on_publish_done from Idle should fail");
}

/// draft-14 Section 5.1: Done is terminal; nothing reopens a subscription.
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

/// draft-14 Section 9.9: SUBSCRIBE_ERROR refuses a SUBSCRIBE, so it cannot arrive
/// once one has been accepted.
#[test]
fn subscription_cannot_subscribe_error_from_active() {
    let mut sm = SubscriptionStateMachine::new();
    sm.on_subscribe_sent().unwrap();
    sm.on_subscribe_ok().unwrap();
    assert_eq!(sm.state(), SubscriptionState::Active);

    let result = sm.on_subscribe_error();
    assert!(result.is_err(), "on_subscribe_error from Active should fail");
}

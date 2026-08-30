#![cfg(feature = "draft14")]

use moqtap_client::draft14::namespace::*;

// ============================================================
// SubscribeNamespace happy path
// ============================================================

/// draft-14 Section 6.1: "If the subscriber is aware of a namespace of
/// interest, it can send SUBSCRIBE_NAMESPACE to publishers/relays it has
/// established a session with." Until it does, there is no interest registered.
#[test]
fn sub_ns_initial_state_is_idle() {
    let sm = SubscribeNamespaceStateMachine::new();
    assert_eq!(sm.state(), SubscribeNamespaceState::Idle);
}

/// draft-14 Section 9.28: "The subscriber sends the SUBSCRIBE_NAMESPACE control
/// message to a publisher to request the current set of matching published
/// namespaces and established subscriptions, as well as future updates to the
/// set."
#[test]
fn sub_ns_idle_to_pending() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().expect("on_subscribe_namespace_sent from Idle should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Pending);
}

/// draft-14 Section 6.1: "A publisher MUST send exactly one
/// SUBSCRIBE_NAMESPACE_OK or SUBSCRIBE_NAMESPACE_ERROR in response to a
/// SUBSCRIBE_NAMESPACE."
#[test]
fn sub_ns_pending_to_active() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_ok().expect("on_subscribe_namespace_ok from Pending should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Active);
}

/// draft-14 Section 6.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous
/// SUBSCRIBE_NAMESPACE."
#[test]
fn sub_ns_active_to_done_via_unsubscribe() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_ok().unwrap();
    sm.on_unsubscribe_namespace().expect("on_unsubscribe_namespace from Active should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Done);
}

/// draft-14 Section 9.30: "A publisher sends a SUBSCRIBE_NAMESPACE_ERROR
/// control message in response to a failed SUBSCRIBE_NAMESPACE."
#[test]
fn sub_ns_pending_to_done_via_error() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    sm.on_subscribe_namespace_sent().unwrap();
    sm.on_subscribe_namespace_error()
        .expect("on_subscribe_namespace_error from Pending should succeed");
    assert_eq!(sm.state(), SubscribeNamespaceState::Done);
}

/// draft-14 Section 6.1: the whole of a namespace subscription, from the request
/// through its single answer to the withdrawal.
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

/// draft-14 Section 9.29: the answer carries "the Request ID of the
/// SUBSCRIBE_NAMESPACE this message is replying to", and none has been sent.
#[test]
fn sub_ns_cannot_ok_from_idle() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    let result = sm.on_subscribe_namespace_ok();
    assert!(result.is_err(), "on_subscribe_namespace_ok from Idle should fail");
}

/// draft-14 Section 9.1: a Request ID is spent once, so a withdrawn namespace
/// subscription is not resumed under the identifier it ended with.
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

/// draft-14 Section 6.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous
/// SUBSCRIBE_NAMESPACE" — here there is no previous one to withdraw.
#[test]
fn sub_ns_cannot_unsubscribe_from_idle() {
    let mut sm = SubscribeNamespaceStateMachine::new();
    let result = sm.on_unsubscribe_namespace();
    assert!(result.is_err(), "on_unsubscribe_namespace from Idle should fail");
}

// ============================================================
// PublishNamespace happy path
// ============================================================

/// draft-14 Section 6.2: "A publisher MAY send PUBLISH_NAMESPACE messages to any
/// subscriber." Until it does, it has advertised nothing.
#[test]
fn pub_ns_initial_state_is_idle() {
    let sm = PublishNamespaceStateMachine::new();
    assert_eq!(sm.state(), PublishNamespaceState::Idle);
}

/// draft-14 Section 9.23: "The publisher sends the PUBLISH_NAMESPACE control
/// message to advertise that it has tracks available within a Track Namespace."
#[test]
fn pub_ns_idle_to_pending() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().expect("on_publish_namespace_sent from Idle should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Pending);
}

/// draft-14 Section 9.24: "The subscriber sends a PUBLISH_NAMESPACE_OK control
/// message to acknowledge the successful authorization and acceptance of a
/// PUBLISH_NAMESPACE message."
#[test]
fn pub_ns_pending_to_active() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().expect("on_publish_namespace_ok from Pending should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Active);
}

/// draft-14 Section 9.26: "The publisher sends the PUBLISH_NAMESPACE_DONE
/// control message to indicate its intent to stop serving new subscriptions for
/// tracks within the provided Track Namespace."
#[test]
fn pub_ns_active_to_done_via_done() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().unwrap();
    sm.on_publish_namespace_done().expect("on_publish_namespace_done from Active should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 Section 6.2: "A subscriber can send PUBLISH_NAMESPACE_CANCEL to
/// revoke acceptance of an PUBLISH_NAMESPACE ... After receiving an
/// PUBLISH_NAMESPACE_CANCEL, the publisher does not send
/// PUBLISH_NAMESPACE_DONE." The advertisement is over either way.
#[test]
fn pub_ns_active_to_done_via_cancel() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_ok().unwrap();
    sm.on_publish_namespace_cancel()
        .expect("on_publish_namespace_cancel from Active should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 Section 9.25: "The subscriber sends a PUBLISH_NAMESPACE_ERROR
/// control message for tracks that failed authorization."
#[test]
fn pub_ns_pending_to_done_via_error() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    sm.on_publish_namespace_error()
        .expect("on_publish_namespace_error from Pending should succeed");
    assert_eq!(sm.state(), PublishNamespaceState::Done);
}

/// draft-14 Section 6.2: "A PUBLISH_NAMESPACE_DONE message withdraws a previous
/// PUBLISH_NAMESPACE, although it is not a protocol error for the subscriber to
/// send a SUBSCRIBE or FETCH message for a track in a namespace after receiving
/// an PUBLISH_NAMESPACE_DONE." The publisher ends its own advertisement; the
/// subscriber is not obliged to stop asking.
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

/// draft-14 Section 6.2: the same advertisement ended by the subscriber instead,
/// revoking the acceptance it gave.
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

/// draft-14 Section 9.24: the answer carries "the Request ID of the
/// PUBLISH_NAMESPACE this message is replying to", and none has been sent.
#[test]
fn pub_ns_cannot_ok_from_idle() {
    let mut sm = PublishNamespaceStateMachine::new();
    let result = sm.on_publish_namespace_ok();
    assert!(result.is_err(), "on_publish_namespace_ok from Idle should fail");
}

/// draft-14 Section 6.2: "A PUBLISH_NAMESPACE_DONE message withdraws a previous
/// PUBLISH_NAMESPACE" — here there is no previous one to withdraw.
#[test]
fn pub_ns_cannot_done_from_idle() {
    let mut sm = PublishNamespaceStateMachine::new();
    let result = sm.on_publish_namespace_done();
    assert!(result.is_err(), "on_publish_namespace_done from Idle should fail");
}

/// draft-14 Section 9.1: a Request ID is spent once, so a withdrawn namespace is
/// advertised again as a new request rather than as this one.
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

/// draft-14 Section 6.2: a PUBLISH_NAMESPACE_CANCEL revokes "acceptance of an
/// PUBLISH_NAMESPACE", and nothing has been advertised to accept.
#[test]
fn pub_ns_cannot_cancel_from_idle() {
    let mut sm = PublishNamespaceStateMachine::new();
    let result = sm.on_publish_namespace_cancel();
    assert!(result.is_err(), "on_publish_namespace_cancel from Idle should fail");
}

/// draft-14 Section 6.2: a PUBLISH_NAMESPACE_CANCEL revokes "acceptance of an
/// PUBLISH_NAMESPACE", so it follows a PUBLISH_NAMESPACE_OK. While the answer is
/// still owed there is no acceptance to revoke.
#[test]
fn pub_ns_cannot_cancel_from_pending() {
    let mut sm = PublishNamespaceStateMachine::new();
    sm.on_publish_namespace_sent().unwrap();
    assert_eq!(sm.state(), PublishNamespaceState::Pending);

    let result = sm.on_publish_namespace_cancel();
    assert!(result.is_err(), "on_publish_namespace_cancel from Pending should fail");
}

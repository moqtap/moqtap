#![cfg(feature = "draft14")]

use moqtap_client::draft14::fetch::*;

// ============================================================
// Happy path
// ============================================================

/// draft-14 Section 9.16: a fetch exists once "a subscriber issues a FETCH to a
/// publisher", and not before.
#[test]
fn fetch_initial_state_is_idle() {
    let sm = FetchStateMachine::new();
    assert_eq!(sm.state(), FetchState::Idle);
}

/// draft-14 Section 9.16.3: "A publisher responds to a FETCH request with either
/// a FETCH_OK or a FETCH_ERROR message." Between the request and the answer the
/// fetch is outstanding.
#[test]
fn fetch_idle_to_pending() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().expect("on_fetch_sent from Idle should succeed");
    assert_eq!(sm.state(), FetchState::Pending);
}

/// draft-14 Section 9.17: "A publisher sends a FETCH_OK control message in
/// response to successful fetches."
#[test]
fn fetch_pending_to_receiving() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().expect("on_fetch_ok from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Receiving);
}

/// draft-14 Section 9.16.3: "The Objects in the response are delivered on a
/// single unidirectional stream." The end of that stream is the end of the
/// response.
#[test]
fn fetch_receiving_to_done_via_fin() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_stream_fin().expect("on_stream_fin from Receiving should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 10.4.1: "Streams aside from the control stream MAY be
/// canceled due to congestion or other reasons by either the publisher or
/// subscriber." A fetch delivered on a cancelled stream delivers no more.
#[test]
fn fetch_receiving_to_done_via_reset() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_stream_reset().expect("on_stream_reset from Receiving should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.16: the whole of a fetch, from the request through its
/// answer to the end of the stream carrying the response.
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

/// draft-14 Section 9.19: "A subscriber sends a FETCH_CANCEL message to a
/// publisher to indicate it is no longer interested in receiving objects for the
/// fetch identified by the 'Request ID'."
#[test]
fn fetch_pending_to_done_via_cancel() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_cancel().expect("on_fetch_cancel from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.19: "The publisher SHOULD promptly close the
/// unidirectional stream, even if it is in the middle of delivering an object."
#[test]
fn fetch_receiving_to_done_via_cancel() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_fetch_cancel().expect("on_fetch_cancel from Receiving should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.18: "A publisher sends a FETCH_ERROR control message in
/// response to a failed FETCH."
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

/// draft-14 Section 9.17: a FETCH_OK carries "the Request ID of the FETCH this
/// message is replying to", and no FETCH has established one.
#[test]
fn fetch_cannot_fetch_ok_from_idle() {
    let mut sm = FetchStateMachine::new();
    let result = sm.on_fetch_ok();
    assert!(result.is_err(), "on_fetch_ok from Idle should fail");
}

/// draft-14 Section 9.19: FETCH_CANCEL carries "the Request ID of the FETCH ...
/// this message is cancelling", and there is no fetch to cancel.
#[test]
fn fetch_cannot_cancel_from_idle() {
    let mut sm = FetchStateMachine::new();
    let result = sm.on_fetch_cancel();
    assert!(result.is_err(), "on_fetch_cancel from Idle should fail");
}

/// draft-14 Section 9.1: "The Request ID increments by 2 with each FETCH ...
/// request." A second FETCH is a second fetch, not a reissue of this one.
#[test]
fn fetch_cannot_send_from_receiving() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    assert_eq!(sm.state(), FetchState::Receiving);

    let result = sm.on_fetch_sent();
    assert!(result.is_err(), "on_fetch_sent from Receiving should fail");
}

/// draft-14 Section 9.1: a Request ID is spent once, so a fetch that has ended
/// is not restarted under the identifier it ended with.
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

/// draft-14 Section 9.16.3: "The publisher creates a new unidirectional stream
/// that is used to send the Objects" in response to the FETCH. With no FETCH
/// there is no such stream to finish.
#[test]
fn fetch_cannot_stream_fin_from_idle() {
    let mut sm = FetchStateMachine::new();
    let result = sm.on_stream_fin();
    assert!(result.is_err(), "on_stream_fin from Idle should fail");
}

/// draft-14 Section 9.16.3: a publisher answers a FETCH "with either a FETCH_OK
/// or a FETCH_ERROR message" — either, so an error after this fetch was accepted
/// would be a second answer to one request.
#[test]
fn fetch_cannot_fetch_error_from_receiving() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    assert_eq!(sm.state(), FetchState::Receiving);

    let result = sm.on_fetch_error();
    assert!(result.is_err(), "on_fetch_error from Receiving should fail");
}

// ============================================================
// The answer trailing the response stream
// ============================================================

/// draft-14 Section 9.17: "A publisher MAY send Objects in response to a FETCH
/// before the FETCH_OK message is sent, but the FETCH_OK MUST NOT be sent until
/// the End Location is known." A publisher that has the whole range to hand and
/// is still working out its End Location delivers the response first, so the
/// stream can finish while the answer is still owed.
///
/// # Ablation, run
///
/// Deleting the `FetchState::Pending` arm of `on_stream_fin`, which is
/// the graph this file used to pin as narrower than the draft:
///
/// ```text
/// on_stream_fin from Pending should succeed: InvalidTransition {
/// from: Pending, event: "on_stream_fin" }
/// ```
#[test]
fn fetch_pending_to_unanswered_via_fin() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    assert_eq!(sm.state(), FetchState::Pending);

    sm.on_stream_fin().expect("on_stream_fin from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Unanswered);
}

/// draft-14 Section 10.4.1: "Streams aside from the control stream MAY be
/// canceled due to congestion or other reasons by either the publisher or
/// subscriber." A stream reset settles the delivery half of a fetch the same way
/// a FIN does, and says nothing about the answer.
///
/// # Ablation, run
///
/// The same arm deleted from `on_stream_reset`, which is a second copy of
/// it and not the one above:
///
/// ```text
/// on_stream_reset from Pending should succeed: InvalidTransition {
/// from: Pending, event: "on_stream_reset" }
/// ```
#[test]
fn fetch_pending_to_unanswered_via_reset() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();

    sm.on_stream_reset().expect("on_stream_reset from Pending should succeed");
    assert_eq!(sm.state(), FetchState::Unanswered);
}

/// draft-14 Section 9.16.3: "The FETCH_OK or FETCH_ERROR can come at any time
/// relative to object delivery." After the delivery, then, and the FETCH_OK that
/// arrives once the objects are all through is the last thing the fetch was
/// waiting for.
///
/// # Ablation, run
///
/// Sending the trailing FETCH_OK to `Receiving` rather than `Done` — an
/// answer that arrives but does not end the fetch:
///
/// ```text
/// assertion `left == right` failed
///   left: Receiving
///  right: Done
/// ```
#[test]
fn fetch_unanswered_to_done_via_fetch_ok() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_stream_fin().unwrap();
    assert_eq!(sm.state(), FetchState::Unanswered);

    sm.on_fetch_ok().expect("on_fetch_ok from Unanswered should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.16.3: a relay whose upstream FETCH fails "sends a
/// FETCH_ERROR and can reset the unidirectional stream. It can choose to do so
/// immediately or wait until the cached objects have been delivered before
/// resetting the stream." Waiting is the order gated here: the stream ends and
/// the error follows it.
///
/// # Ablation, run
///
/// Dropping `Unanswered` from `on_fetch_error`'s pattern:
///
/// ```text
/// on_fetch_error from Unanswered should succeed: InvalidTransition {
/// from: Unanswered, event: "on_fetch_error" }
/// ```
#[test]
fn fetch_unanswered_to_done_via_error() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_stream_reset().unwrap();
    assert_eq!(sm.state(), FetchState::Unanswered);

    sm.on_fetch_error().expect("on_fetch_error from Unanswered should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.19: a FETCH_CANCEL says the subscriber "is no longer
/// interested in receiving objects for the fetch". A subscriber whose stream has
/// ended with no answer may stop waiting for one.
///
/// # Ablation, run
///
/// Dropping `Unanswered` from `on_fetch_cancel`'s pattern:
///
/// ```text
/// on_fetch_cancel from Unanswered should succeed: InvalidTransition {
/// from: Unanswered, event: "on_fetch_cancel" }
/// ```
#[test]
fn fetch_unanswered_to_done_via_cancel() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_stream_fin().unwrap();

    sm.on_fetch_cancel().expect("on_fetch_cancel from Unanswered should succeed");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.16: the whole of a fetch again, in the other of the two
/// orders Section 9.16.3 permits — the response delivered and finished before
/// the FETCH_OK describing it arrives.
#[test]
fn fetch_full_lifecycle_with_the_answer_last() {
    let mut sm = FetchStateMachine::new();
    assert_eq!(sm.state(), FetchState::Idle);

    sm.on_fetch_sent().unwrap();
    assert_eq!(sm.state(), FetchState::Pending);

    sm.on_stream_fin().unwrap();
    assert_eq!(sm.state(), FetchState::Unanswered);

    sm.on_fetch_ok().unwrap();
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.16.3: the relay that has already sent its FETCH_ERROR
/// "can reset the unidirectional stream", immediately or after the cached
/// objects. Either way the reset arrives at a fetch the error has already ended,
/// and it is expected rather than wrong.
///
/// # Ablation, run
///
/// Deleting the `FetchState::Done` arm from both stream events, so a fetch
/// that has ended treats its own stream closing as a violation:
///
/// ```text
/// a reset after the error should be tolerated: InvalidTransition {
/// from: Done, event: "on_stream_reset" }
/// ```
#[test]
fn fetch_done_ignores_the_close_that_follows_an_error() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_error().unwrap();
    assert_eq!(sm.state(), FetchState::Done);

    sm.on_stream_reset().expect("a reset after the error should be tolerated");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.19: "The publisher SHOULD promptly close the
/// unidirectional stream, even if it is in the middle of delivering an object."
/// So every cancel is followed by a close, and refusing it would make an error
/// out of the one thing the cancel was for.
///
/// # Ablation, run
///
/// The same deletion, reaching the other of the two events:
///
/// ```text
/// a FIN after the cancel should be tolerated: InvalidTransition {
/// from: Done, event: "on_stream_fin" }
/// ```
#[test]
fn fetch_done_ignores_the_close_that_follows_a_cancel() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_fetch_ok().unwrap();
    sm.on_fetch_cancel().unwrap();
    assert_eq!(sm.state(), FetchState::Done);

    sm.on_stream_fin().expect("a FIN after the cancel should be tolerated");
    assert_eq!(sm.state(), FetchState::Done);
}

/// draft-14 Section 9.16.3: "The Objects in the response are delivered on a
/// single unidirectional stream." One stream ends once, so a second ending for a
/// fetch still waiting on its answer is the driver's mistake and not the peer's.
///
/// # Ablation, run
///
/// Adding `FetchState::Unanswered => Ok(())` to `on_stream_fin`, which is
/// the tolerant answer given to a state that has not earned it:
///
/// ```text
/// on_stream_fin from Unanswered should fail
/// ```
#[test]
fn fetch_cannot_stream_fin_from_unanswered() {
    let mut sm = FetchStateMachine::new();
    sm.on_fetch_sent().unwrap();
    sm.on_stream_fin().unwrap();
    assert_eq!(sm.state(), FetchState::Unanswered);

    let result = sm.on_stream_fin();
    assert!(result.is_err(), "on_stream_fin from Unanswered should fail");
}

#![cfg(feature = "draft16")]
//! Draft-16 is the draft where one request gets a stream of its own.
//!
//! Section 3.3: "This specification only specifies two uses of bidirectional
//! streams, the control stream, which begins with CLIENT_SETUP, and
//! SUBSCRIBE_NAMESPACE. Bidirectional streams MUST NOT begin with any other
//! message type unless negotiated. If they do, the peer MUST close the Session
//! with a Protocol Violation."
//!
//! Section 6.1 says what happens on it — "The subscriber sends
//! SUBSCRIBE_NAMESPACE on a new bidirectional stream and the publisher MUST
//! send a single REQUEST_OK or REQUEST_ERROR as the first message on the
//! bidirectional stream in response" — and Section 9.21 puts the messages that
//! follow there too: NAMESPACE "is sent on the response stream of a
//! SUBSCRIBE_NAMESPACE request".
//!
//! These gates are the endpoint's half. What the connection does with a real
//! stream is in `draft16_namespace_stream_on_the_wire.rs`.
//!
//! # Why the placement is not a detail
//!
//! NAMESPACE and NAMESPACE_DONE carry no Request ID. Section 9.21: "All
//! NAMESPACE messages are in response to a SUBSCRIBE_NAMESPACE, so only the
//! namespace tuples after the 'Track Namespace Prefix' are included in the
//! 'Track Namespace Suffix'." A suffix is meaningless without the prefix the
//! subscription carries, so on the control stream those two messages name
//! nothing at all — which is why the control stream refuses them rather than
//! ignoring them.
//!
//! # Ablations
//!
//! Each is a single edit to `draft16/endpoint.rs` or `draft16/namespace.rs`,
//! run and reverted, with the message it produced recorded on the test that
//! caught it.

use moqtap_client::draft16::endpoint::{Endpoint, EndpointError};
use moqtap_client::draft16::namespace::SubscribeNamespaceState;
use moqtap_client::draft16::session::request_id::Role;
use moqtap_client::draft16::session::state::SessionState;
use moqtap_codec::draft16::error_codes::SessionErrorCode;
use moqtap_codec::draft16::message::{
    self, ControlMessage, GoAway, RequestError, RequestOk, ServerSetup, Subscribe,
    SubscribeNamespace,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"example.com".to_vec()])
}

fn suffix() -> TrackNamespace {
    TrackNamespace(vec![b"meeting=123".to_vec()])
}

/// An endpoint past setup, with a budget granted to the peer so it may open
/// requests of its own.
fn active(role: Role) -> Endpoint {
    let mut ep = Endpoint::new(role);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![]).unwrap();
    ep.receive_server_setup(&ServerSetup {
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    })
    .unwrap();
    let _ = ep.send_max_request_id(varint(100)).unwrap();
    ep
}

/// A client with one namespace subscription written and unanswered, and the
/// Request ID it was allocated.
fn subscribing() -> (Endpoint, VarInt) {
    let mut ep = active(Role::Client);
    let (id, _) = ep.subscribe_namespace(ns(), varint(0), vec![]).unwrap();
    (ep, id)
}

fn request_ok(id: VarInt) -> ControlMessage {
    ControlMessage::RequestOk(RequestOk { request_id: id, parameters: vec![] })
}

fn request_error(id: VarInt) -> ControlMessage {
    ControlMessage::RequestError(RequestError {
        request_id: id,
        error_code: varint(1),
        retry_interval: varint(0),
        reason_phrase: b"no".to_vec(),
    })
}

fn namespace() -> ControlMessage {
    ControlMessage::Namespace(message::Namespace { namespace_suffix: suffix() })
}

fn namespace_done() -> ControlMessage {
    ControlMessage::NamespaceDone(message::NamespaceDone { namespace_suffix: suffix() })
}

// -- The answer arrives on the stream, and only there ------------------------

/// The answer to a SUBSCRIBE_NAMESPACE is taken on the subscription's own
/// stream.
///
/// Section 9.25: "The publisher will respond with REQUEST_OK or REQUEST_ERROR
/// on the response half of the stream."
#[test]
fn the_answer_arrives_on_the_subscriptions_own_stream() {
    let (mut ep, id) = subscribing();
    ep.receive_on_namespace_stream(id, &request_ok(id)).expect("the answer on its own stream");
    assert_eq!(ep.active_subscribe_namespace_count(), 1);
}

/// The same REQUEST_OK on the control stream answers nothing.
///
/// It is the identical message; only the stream it arrived on differs, and on
/// this draft that is what says which request is being answered. An endpoint
/// that took it here would accept an answer in the one place Section 9.25 does
/// not put it.
///
/// Ablation: restoring the `subscribe_namespaces` arm at the top of
/// `receive_request_ok` fails with
///
/// ```text
/// a REQUEST_OK for a namespace subscription is not answered on the control
/// stream, got Ok(())
/// ```
#[test]
fn the_answer_on_the_control_stream_is_refused() {
    let (mut ep, id) = subscribing();
    let outcome = ep.receive_request_ok(&RequestOk { request_id: id, parameters: vec![] });
    assert!(
        matches!(outcome, Err(EndpointError::UnknownRequest(seen)) if seen == id.into_inner()),
        "a REQUEST_OK for a namespace subscription is not answered on the control stream, got \
         {outcome:?}"
    );
}

/// A REQUEST_OK naming a different request than the stream it came on is not
/// applied to either.
///
/// Draft-16 names the request twice over — the stream carries it and so does
/// the message's own Request ID field — and says nothing about the two
/// disagreeing. Neither is guessed at.
///
/// Ablation: making `require_same_request` return `Ok(())` unconditionally
/// fails with
///
/// ```text
/// a response naming another request must be refused, got Ok(())
/// ```
#[test]
fn a_response_naming_another_request_is_refused() {
    let (mut ep, id) = subscribing();
    let other = varint(id.into_inner() + 2);
    let outcome = ep.receive_on_namespace_stream(id, &request_ok(other));
    assert!(
        matches!(
            outcome,
            Err(EndpointError::ResponseIdMismatch { stream, message })
                if stream == id.into_inner() && message == other.into_inner()
        ),
        "a response naming another request must be refused, got {outcome:?}"
    );
    ep.receive_on_namespace_stream(id, &request_ok(id))
        .expect("the answer that does name this request is still taken");
}

// -- What the answer is followed by -----------------------------------------

/// NAMESPACE and NAMESPACE_DONE are taken on the subscription's stream.
///
/// Section 9.25: "If the SUBSCRIBE_NAMESPACE is successful, the publisher will
/// send matching NAMESPACE messages on the response stream if they are
/// requested."
#[test]
fn the_namespaces_it_asked_for_arrive_on_the_same_stream() {
    let (mut ep, id) = subscribing();
    ep.receive_on_namespace_stream(id, &request_ok(id)).unwrap();
    ep.receive_on_namespace_stream(id, &namespace()).expect("a namespace it asked for");
    ep.receive_on_namespace_stream(id, &namespace_done()).expect("and its withdrawal");
}

/// A NAMESPACE on the control stream closes the session.
///
/// It carries a suffix and no Request ID, so here it names nothing that could
/// be looked up. Section 3.3 answers a message on a stream it does not belong
/// on with a Protocol Violation.
///
/// Ablation: replacing the `Namespace` arm of `receive_message` with
/// `Ok(())` fails with
///
/// ```text
/// a NAMESPACE on the control stream must close the session, got Ok(())
/// ```
#[test]
fn a_namespace_on_the_control_stream_closes_the_session() {
    let mut ep = active(Role::Client);
    let outcome = ep.receive_message(namespace());
    let Err(e) = outcome else {
        panic!("a NAMESPACE on the control stream must close the session, got {outcome:?}");
    };
    assert_eq!(e.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// And so does a NAMESPACE_DONE, for the same reason.
///
/// Section 9.23: "All NAMESPACE_DONE messages are in response to a
/// SUBSCRIBE_NAMESPACE".
#[test]
fn a_namespace_done_on_the_control_stream_closes_the_session() {
    let mut ep = active(Role::Client);
    let outcome = ep.receive_message(namespace_done());
    let Err(e) = outcome else {
        panic!("a NAMESPACE_DONE on the control stream must close the session, got {outcome:?}");
    };
    assert_eq!(e.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// A NAMESPACE on a stream whose id no subscription carries is refused.
///
/// The stream is the correlation, so a stream that correlates to nothing has
/// no namespace to report on.
#[test]
fn a_namespace_needs_a_subscription_to_belong_to() {
    let mut ep = active(Role::Client);
    let outcome = ep.receive_on_namespace_stream(varint(40), &namespace());
    assert!(
        matches!(outcome, Err(EndpointError::UnknownRequest(40))),
        "a namespace report needs a subscription, got {outcome:?}"
    );
}

// -- What may begin a bidirectional stream ----------------------------------

/// A bidirectional stream that begins with anything else closes the session.
///
/// Section 3.3: "Bidirectional streams MUST NOT begin with any other message
/// type unless negotiated. If they do, the peer MUST close the Session with a
/// Protocol Violation." SUBSCRIBE is a request on this draft, and still not one
/// that may open a stream.
///
/// Ablation: making `receive_subscribe_namespace_on_stream` fall through to
/// `Ok(VarInt::from_u64(0).unwrap())` for a non-SUBSCRIBE_NAMESPACE fails with
///
/// ```text
/// a bidirectional stream may not begin with a SUBSCRIBE, got Ok(VarInt(0))
/// ```
#[test]
fn a_bidi_stream_may_not_begin_with_another_request() {
    let mut ep = active(Role::Client);
    let subscribe = ControlMessage::Subscribe(Subscribe {
        request_id: varint(1),
        track_namespace: ns(),
        track_name: b"video".to_vec(),
        parameters: vec![],
    });
    let outcome = ep.receive_subscribe_namespace_on_stream(&subscribe);
    assert!(
        matches!(outcome, Err(EndpointError::NotASubscribeNamespace(_))),
        "a bidirectional stream may not begin with a SUBSCRIBE, got {outcome:?}"
    );
    assert_eq!(
        outcome.unwrap_err().session_error_code(),
        Some(SessionErrorCode::ProtocolViolation)
    );
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// Nor with a message that is no request at all.
#[test]
fn a_bidi_stream_may_not_begin_with_a_session_message() {
    let mut ep = active(Role::Client);
    let goaway = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let outcome = ep.receive_subscribe_namespace_on_stream(&goaway);
    assert!(
        matches!(outcome, Err(EndpointError::NotASubscribeNamespace(_))),
        "a bidirectional stream may not begin with a GOAWAY, got {outcome:?}"
    );
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// The peer's SUBSCRIBE_NAMESPACE is registered, and this endpoint can answer
/// it.
///
/// The receive half is the reason the refusal above can exist: an endpoint that
/// accepted a bidirectional stream only to refuse everything on it would close
/// sessions over the one message Section 3.3 permits.
#[test]
fn the_peers_namespace_subscription_can_be_answered() {
    let mut ep = active(Role::Server);
    // A server's own ids are odd, so the client's first is 0.
    let request = ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(0),
        namespace_prefix: ns(),
        subscribe_options: varint(0),
        parameters: vec![],
    });
    let id = ep.receive_subscribe_namespace_on_stream(&request).expect("the peer's subscription");
    assert_eq!(id, varint(0));
    ep.respond_on_namespace_stream(id, None).expect("answering it");
    assert_eq!(ep.active_subscribe_namespace_count(), 1);
}

/// A peer's Request ID from this endpoint's own half of the space is refused,
/// and no subscription is registered under it.
///
/// Section 9.1: "The client's Request ID starts at 0 and are even and the
/// server's Request ID starts at 1 and are odd ... If an endpoint receives a
/// Request ID that is not valid for the peer, or a new request with a Request
/// ID that is not the next in sequence or exceeds the received MAX_REQUEST_ID,
/// it MUST close the session with INVALID_REQUEST_ID."
///
/// The refusal and the close are both asserted, because the sentence asks for
/// both and the intake path answers only the first. The code the close carries
/// is read off the wire by a gate of its own, on all six drafts that state
/// this sentence; here what matters is that a request arriving on a namespace
/// stream reaches the same rule a request arriving on the control stream does,
/// which is the half this stream could have lost.
///
/// Ablation: dropping the `validate_peer_request_id` call from
/// `receive_subscribe_namespace_on_stream` fails with
///
/// ```text
/// a Request ID from this endpoint's own half must be refused, got Ok(VarInt(1))
/// ```
#[test]
fn the_peers_request_id_is_held_to_its_own_half_of_the_space() {
    let mut ep = active(Role::Server);
    // 1 is a server id, and this endpoint is the server.
    let request = ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(1),
        namespace_prefix: ns(),
        subscribe_options: varint(0),
        parameters: vec![],
    });
    let outcome = ep.receive_subscribe_namespace_on_stream(&request);
    assert!(
        matches!(outcome, Err(EndpointError::RequestId(_))),
        "a Request ID from this endpoint's own half must be refused, got {outcome:?}"
    );
    assert_eq!(
        ep.active_subscribe_namespace_count(),
        0,
        "a refused request registers no subscription"
    );
    assert_eq!(
        ep.session_state(),
        SessionState::Closed,
        "Section 9.1 ends the session over it, not just the request: {:?}",
        ep.session_state()
    );
}

// -- Withdrawing it ---------------------------------------------------------

/// A namespace subscription is withdrawn by closing its stream, and the
/// endpoint records it.
///
/// Section 6.1: "A SUBSCRIBE_NAMESPACE can be cancelled by closing the stream
/// with either a FIN or RESET_STREAM." Draft-16 has no UNSUBSCRIBE_NAMESPACE,
/// so this is the whole of how one ends early.
///
/// Ablation: making `cancel_namespace_subscription` return `Ok(())` without
/// driving the state machine fails with
///
/// ```text
/// the answer owed to a withdrawn subscription must be refused, got Ok(())
/// ```
#[test]
fn a_withdrawn_subscription_refuses_its_answer() {
    let (mut ep, id) = subscribing();
    ep.cancel_namespace_subscription(id).expect("withdrawing it");
    let outcome = ep.receive_on_namespace_stream(id, &request_ok(id));
    assert!(
        outcome.is_err(),
        "the answer owed to a withdrawn subscription must be refused, got {outcome:?}"
    );
}

/// It can be withdrawn before it is ever answered.
///
/// The precondition Section 6.1 states is a stream to close, and the stream is
/// open from the SUBSCRIBE_NAMESPACE that opened it.
///
/// Ablation: narrowing `on_request_cancelled` to accept `Active` only fails
/// with
///
/// ```text
/// a subscription can be withdrawn before it is answered, got
/// Err(Namespace(InvalidTransition { from: "Pending", event: "on_request_cancelled" }))
/// ```
#[test]
fn it_can_be_withdrawn_before_it_is_answered() {
    let (mut ep, id) = subscribing();
    let outcome = ep.cancel_namespace_subscription(id);
    assert!(
        outcome.is_ok(),
        "a subscription can be withdrawn before it is answered, got {outcome:?}"
    );
}

/// Withdrawing one that has already ended is not an error.
///
/// A refused subscription is `Done` and its stream is still there to close; the
/// publisher FINs it itself, per Section 9.25. A caller that closes it too is
/// performing the ordinary end rather than a fault.
#[test]
fn withdrawing_one_that_already_ended_is_not_an_error() {
    let (mut ep, id) = subscribing();
    ep.receive_on_namespace_stream(id, &request_error(id)).unwrap();
    ep.cancel_namespace_subscription(id).expect("closing the stream of a refused subscription");
    ep.cancel_namespace_subscription(id).expect("and again");
}

/// One that was never written cannot be withdrawn: there is no stream to close.
///
/// This is the other half of Section 6.1's sentence, and the only state
/// `on_request_cancelled` refuses.
#[test]
fn one_that_was_never_written_cannot_be_withdrawn() {
    use moqtap_client::draft16::namespace::SubscribeNamespaceStateMachine;
    let mut sm = SubscribeNamespaceStateMachine::new();
    assert_eq!(sm.state(), SubscribeNamespaceState::Idle);
    assert!(
        sm.on_request_cancelled().is_err(),
        "nothing has been written, so there is no stream to close"
    );
}

/// Withdrawing a subscription nothing carries is refused.
#[test]
fn withdrawing_an_id_no_subscription_carries_is_refused() {
    let mut ep = active(Role::Client);
    let outcome = ep.cancel_namespace_subscription(varint(41));
    assert!(
        matches!(outcome, Err(EndpointError::UnknownRequest(41))),
        "there is no subscription 41 to withdraw, got {outcome:?}"
    );
}

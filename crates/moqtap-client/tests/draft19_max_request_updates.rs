//! The setup option that limits REQUEST_UPDATE concurrency, draft-19 only.
//!
//! Draft-19 Section 10.3.1.7 introduces MAX_REQUEST_UPDATES (Option Type 0x08):
//!
//! > The MAX_REQUEST_UPDATES option communicates the maximum number of
//! > unacknowledged REQUEST_UPDATE messages per request stream that the
//! > endpoint is willing to receive. A REQUEST_UPDATE is considered outstanding
//! > from when it is sent until the sender receives the corresponding
//! > REQUEST_OK or REQUEST_ERROR response. [...] If an endpoint receives a
//! > REQUEST_UPDATE on a stream that already has MAX_REQUEST_UPDATES
//! > outstanding REQUEST_UPDATEs, it MUST close the session with
//! > TOO_MANY_REQUEST_UPDATES.
//!
//! It came in with its own error code, TOO_MANY_REQUEST_UPDATES (0x1B), and the
//! draft's own change log lists both as new since draft-18. Nothing earlier has
//! either, so this file is draft-19 alone.
//!
//! # Two things the option is not
//!
//! It is not MAX_REQUEST_ID. A zero there means the peer may send no requests
//! at all; this one's zero means the endpoint is not limiting anything, and
//! zero is also the default when the option is absent. An implementation that
//! read them the same way would close the session on the first REQUEST_UPDATE
//! of every session that never sent the option, which is nearly all of them.
//!
//! It is not a total. The limit is on updates *outstanding*, so a peer that
//! waits for each answer may send any number. The running balance is what makes
//! that true, and a check written against a total would refuse a conforming
//! peer on its second update.

#![cfg(feature = "draft19")]

use moqtap_client::draft19::endpoint::{Endpoint, EndpointError};
use moqtap_client::draft19::session::request_id::Role;
use moqtap_client::draft19::session::state::SessionState;
use moqtap_codec::draft19::error_codes::SessionErrorCode;
use moqtap_codec::draft19::message::{
    ControlMessage, RequestOk, RequestUpdate, Setup, SubscribeNamespace,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// An endpoint whose own SETUP advertised `limit` updates per stream.
///
/// A server, because the peer has to be able to open a request stream and a
/// client's peer ids are the odd ones - which is what `peer_subscribe` below
/// sends.
fn advertising(limit: Option<u64>) -> Endpoint {
    let mut endpoint = Endpoint::new(Role::Server);
    endpoint.connect().unwrap();
    let options = match limit {
        Some(n) => vec![KeyValuePair { key: varint(0x08), value: KvpValue::Varint(varint(n)) }],
        None => vec![],
    };
    endpoint.send_setup(options).unwrap();
    endpoint.receive_setup(&Setup { options: vec![] }).unwrap();
    endpoint
}

/// The peer's SUBSCRIBE_NAMESPACE, which opens the request stream the updates
/// go on.
///
/// This request rather than a SUBSCRIBE because REQUEST_OK is its answer as
/// well as an update's, so one message restores a credit and the loop below can
/// observe it. Section 10.9 puts REQUEST_UPDATE on every request's stream, so
/// the choice is about what can be asserted and not about where the rule
/// applies.
fn peer_subscribe_namespace(endpoint: &mut Endpoint, request_id: u64, label: &[u8]) -> VarInt {
    let msg = ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(request_id),
        namespace_prefix: TrackNamespace(vec![label.to_vec()]),
        parameters: vec![],
    });
    endpoint.receive_request_on_stream(&msg).expect("the peer's request")
}

fn update(id: VarInt) -> ControlMessage {
    ControlMessage::RequestUpdate(RequestUpdate { request_id: id, parameters: vec![] })
}

fn request_ok() -> ControlMessage {
    ControlMessage::RequestOk(RequestOk { parameters: vec![], track_properties: vec![] })
}

/// One update past the limit closes the session, with its own code.
///
/// Ablation: dropping the `spend_update_credit` call from
/// `receive_request_update` fails with
///
/// ```text
/// a third REQUEST_UPDATE past a limit of 2 must close the session: Ok(())
/// ```
#[test]
fn an_update_past_the_advertised_limit_closes_the_session() {
    let mut endpoint = advertising(Some(2));
    let id = peer_subscribe_namespace(&mut endpoint, 0, b"live");

    endpoint.receive_on_peer_request_stream(id, update(id)).expect("first update is within 2");
    endpoint.receive_on_peer_request_stream(id, update(id)).expect("second update is within 2");

    let result = endpoint.receive_on_peer_request_stream(id, update(id));
    let err = match result {
        Err(e) => e,
        Ok(()) => panic!("a third REQUEST_UPDATE past a limit of 2 must close the session: Ok(())"),
    };
    assert!(
        matches!(err, EndpointError::TooManyRequestUpdates(got, 2) if got == id.into_inner()),
        "the error must name the stream and the limit it broke: {err:?}",
    );
    assert_eq!(
        err.session_error_code(),
        Some(SessionErrorCode::TooManyRequestUpdates),
        "the draft gives this its own code, not the general protocol violation",
    );
    assert_eq!(endpoint.session_state(), SessionState::Closed);
}

/// A peer that waits for the answer may send another.
///
/// The limit is on updates *outstanding*, and Section 10.3.1.7 says each
/// response "restores one credit on that stream". Under a limit of one, the
/// second update is refused if nothing came back in between and accepted if
/// something did, so the same pair of calls answers both halves of the rule.
#[test]
fn answering_an_update_restores_the_credit_it_spent() {
    // Without the answer, the second update is the one too many.
    let mut endpoint = advertising(Some(1));
    let id = peer_subscribe_namespace(&mut endpoint, 0, b"live");
    endpoint.receive_on_peer_request_stream(id, update(id)).expect("the one it was allowed");
    let unanswered = endpoint.receive_on_peer_request_stream(id, update(id));
    assert!(
        matches!(unanswered, Err(EndpointError::TooManyRequestUpdates(..))),
        "nothing was answered, so the credit was still spent: {unanswered:?}",
    );

    // With it, the same second update is within the limit.
    let mut endpoint = advertising(Some(1));
    let id = peer_subscribe_namespace(&mut endpoint, 0, b"live");
    endpoint.receive_on_peer_request_stream(id, update(id)).expect("the one it was allowed");
    endpoint.send_response_on_stream(id, &request_ok()).expect("answer it");
    endpoint
        .receive_on_peer_request_stream(id, update(id))
        .expect("the answer restored the credit the first update spent");
}

/// An endpoint that never sent the option limits nothing.
///
/// The half that would be easy to get backwards. Zero is the default and it
/// means no limit, so an endpoint with no MAX_REQUEST_UPDATES in its SETUP has
/// to accept updates it never answers.
#[test]
fn an_endpoint_that_never_sent_the_option_limits_nothing() {
    let mut endpoint = advertising(None);
    let id = peer_subscribe_namespace(&mut endpoint, 0, b"live");

    for round in 0..8 {
        endpoint
            .receive_on_peer_request_stream(id, update(id))
            .unwrap_or_else(|e| panic!("update {round} with no limit advertised: {e:?}"));
    }
    assert_eq!(endpoint.session_state(), SessionState::Active);
}

/// An explicit zero means the same as no option at all.
///
/// Stated separately because the two reach the check by different routes - one
/// through a parsed value and one through the default - and an implementation
/// that treated a present zero as a ceiling would pass the test above.
#[test]
fn an_explicit_zero_is_also_no_limit() {
    let mut endpoint = advertising(Some(0));
    let id = peer_subscribe_namespace(&mut endpoint, 0, b"live");

    for round in 0..8 {
        endpoint
            .receive_on_peer_request_stream(id, update(id))
            .unwrap_or_else(|e| panic!("update {round} under an explicit zero: {e:?}"));
    }
    assert_eq!(endpoint.session_state(), SessionState::Active);
}

/// The balance is per stream, not per session.
///
/// Two request streams, each allowed one outstanding update. Spending the
/// budget on the first leaves the second untouched, which is what "on any single
/// request stream" means.
#[test]
fn the_budget_is_kept_per_stream() {
    let mut endpoint = advertising(Some(1));
    let first = peer_subscribe_namespace(&mut endpoint, 0, b"live");
    let second = peer_subscribe_namespace(&mut endpoint, 2, b"recorded");

    endpoint.receive_on_peer_request_stream(first, update(first)).expect("first stream's one");
    endpoint
        .receive_on_peer_request_stream(second, update(second))
        .expect("the second stream has its own budget, untouched by the first");

    let result = endpoint.receive_on_peer_request_stream(first, update(first));
    assert!(
        matches!(result, Err(EndpointError::TooManyRequestUpdates(..))),
        "the first stream had already spent its one: {result:?}",
    );
}

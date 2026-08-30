#![cfg(feature = "draft16")]

//! A REQUEST_UPDATE's parameters are held to the kind of request it names, on
//! the one draft that says so.
//!
//! Draft-16 Section 9.11: "The receiver MUST close the session with
//! PROTOCOL_VIOLATION if the sender specifies an invalid Existing Request ID,
//! or if the parameters included in the REQUEST_UPDATE are invalid for the
//! type of request being modified."
//!
//! The first half was already answered. This file is the second, and it is
//! draft-16's alone: drafts 17, 18 and 19 keep the first half and drop the
//! second, and drafts 15 and earlier state neither, so the range here is one
//! draft wide.
//!
//! # What makes a parameter invalid for a kind
//!
//! Section 9.2.2 qualifies four of the parameters REQUEST_UPDATE may carry.
//! Draft-16 Section 9.2.2.3: the SUBSCRIBER_PRIORITY parameter "MAY appear in
//! a SUBSCRIBE, FETCH, REQUEST_UPDATE (for a subscription or FETCH),
//! PUBLISH_OK message". Draft-16 Section 9.2.2.5: SUBSCRIPTION_FILTER "MAY
//! appear in a SUBSCRIBE, PUBLISH_OK or REQUEST_UPDATE (for a subscription)
//! message", and Sections 9.2.2.8 and 9.2.2.9 say the same of FORWARD and
//! NEW_GROUP_REQUEST. AUTHORIZATION TOKEN and DELIVERY TIMEOUT name
//! REQUEST_UPDATE with no qualifier and are admitted whatever the kind.
//!
//! # The rule this file deliberately does not enforce
//!
//! A parameter that does not name REQUEST_UPDATE at all - GROUP_ORDER,
//! EXPIRES, LARGEST_OBJECT - is not a violation. Draft-16 Section 9.2.2 opens
//! by saying that each definition "indicates the message types in which it can
//! appear. If it appears in some other type of message, it MUST be ignored."
//! Closing the session over one of those would answer with a violation what
//! the draft answers by ignoring it, so the last gate here sends GROUP_ORDER
//! in an update to a namespace subscription and requires the session to
//! survive.
//!
//! # Ablations, measured
//!
//! Three cuts, each made against the two crates a change to `moqtap-client`
//! can reach and then reverted. They partition the five gates here: two, two
//! and one, with nothing outside this file reddened by any of them, and each
//! run left the other 166 binaries green.
//!
//! Removing the check, which leaves the behaviour draft-16 had without it:
//!
//! ```text
//! SUBSCRIPTION_FILTER is for a subscription and this is not one: ()
//! a namespace request is neither a subscription nor a FETCH: ()
//! ```
//!
//! Reading the qualifier table as a whitelist, so an unrecognised parameter is
//! refused instead of ignored:
//!
//! ```text
//! DELIVERY TIMEOUT names REQUEST_UPDATE with no qualifier:
//! UpdateParameterNotForKind { request_id: 0, key: 2 }
//! GROUP_ORDER does not name REQUEST_UPDATE, so it is ignored:
//! UpdateParameterNotForKind { request_id: 0, key: 34 }
//! ```
//!
//! Dropping the second half of SUBSCRIBER_PRIORITY's qualifier, so it reads
//! "for a subscription" rather than "for a subscription or FETCH":
//!
//! ```text
//! SUBSCRIBER_PRIORITY names a FETCH as well as a subscription:
//! UpdateParameterNotForKind { request_id: 0, key: 32 }
//! ```

use moqtap_client::draft16::endpoint::{Endpoint, EndpointError};
use moqtap_client::draft16::session::request_id::Role;
use moqtap_client::draft16::session::state::SessionState;
use moqtap_codec::draft16::error_codes::SessionErrorCode;
use moqtap_codec::draft16::message::*;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// An endpoint with its session running.
fn active() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().expect("a client may open");
    let _ = ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
    ep.receive_server_setup(&ServerSetup { parameters: vec![] }).expect("SERVER_SETUP");
    assert_eq!(ep.session_state(), SessionState::Active, "the gate needs a running session");
    // Room for the requests the gates open. Without a grant the allocator
    // refuses and every gate fails before reaching the rule it is about.
    ep.receive_max_request_id(&MaxRequestId { request_id: v(1000) }).expect("MAX_REQUEST_ID");
    ep
}

/// A parameter with an even key, so a varint value.
fn param(key: u64) -> KeyValuePair {
    KeyValuePair { key: v(key), value: KvpValue::Varint(v(1)) }
}

/// The update the peer sends, naming `existing` and carrying one parameter.
fn update(existing: u64, key: u64) -> RequestUpdate {
    RequestUpdate {
        request_id: v(100),
        existing_request_id: v(existing),
        parameters: vec![param(key)],
    }
}

/// A namespace subscription this endpoint opened, which is one of Section
/// 9.11's six updatable kinds and is not a subscription or a FETCH.
fn namespace_request(ep: &mut Endpoint) -> u64 {
    let (id, _) = ep
        .subscribe_namespace(ns(), v(0), Vec::new())
        .expect("this endpoint may subscribe to a namespace");
    id.into_inner()
}

/// A FETCH this endpoint opened.
fn fetch_request(ep: &mut Endpoint) -> u64 {
    let (id, _) = ep
        .fetch(ns(), b"track".to_vec(), v(0), v(0), v(1), v(0), Vec::new())
        .expect("this endpoint may fetch");
    id.into_inner()
}

/// SUBSCRIPTION_FILTER on a namespace subscription is refused, and the session
/// ends.
///
/// # What it catches
///
/// A REQUEST_UPDATE whose parameters are never judged, which is what this
/// draft shipped before the rule was read:
///
/// ```text
/// SUBSCRIPTION_FILTER is for a subscription and this is not one: ()
/// ```
#[test]
fn a_subscription_only_parameter_on_a_namespace_request_closes_the_session() {
    let mut ep = active();
    let id = namespace_request(&mut ep);

    let err = ep
        .receive_request_update(&update(id, 0x21))
        .expect_err("SUBSCRIPTION_FILTER is for a subscription and this is not one");
    assert!(
        matches!(err, EndpointError::UpdateParameterNotForKind { key: 0x21, .. }),
        "the refusal should name the parameter, and named {err:?}"
    );
    assert_eq!(
        err.session_error_code(),
        Some(SessionErrorCode::ProtocolViolation),
        "a session this endpoint ended has no code for the transport to close with",
    );
    assert_eq!(
        ep.session_state(),
        SessionState::Closed,
        "the violation was reported and the session was left running",
    );
}

/// SUBSCRIBER_PRIORITY is admitted on a FETCH, which is the half of its
/// qualifier a subscription-only rule would lose.
#[test]
fn subscriber_priority_is_admitted_on_a_fetch() {
    let mut ep = active();
    let id = fetch_request(&mut ep);

    ep.receive_request_update(&update(id, 0x20))
        .expect("SUBSCRIBER_PRIORITY names a FETCH as well as a subscription");
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// The same parameter on a namespace request is refused: the qualifier names
/// a subscription or a FETCH and this is neither.
#[test]
fn subscriber_priority_on_a_namespace_request_closes_the_session() {
    let mut ep = active();
    let id = namespace_request(&mut ep);

    let err = ep
        .receive_request_update(&update(id, 0x20))
        .expect_err("a namespace request is neither a subscription nor a FETCH");
    assert!(
        matches!(err, EndpointError::UpdateParameterNotForKind { key: 0x20, .. }),
        "got {err:?}"
    );
    assert_eq!(ep.session_state(), SessionState::Closed);
}

/// An unqualified parameter is admitted whatever the kind. Without this the
/// gates above would pass on an endpoint that refused every update to a
/// namespace request.
#[test]
fn an_unqualified_parameter_is_admitted_on_a_namespace_request() {
    let mut ep = active();
    let id = namespace_request(&mut ep);

    ep.receive_request_update(&update(id, 0x02))
        .expect("DELIVERY TIMEOUT names REQUEST_UPDATE with no qualifier");
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// A parameter REQUEST_UPDATE does not carry at all is ignored, not refused.
///
/// # What it catches
///
/// A check that answers every parameter it does not recognise with a close.
/// Section 9.2.2 says such a parameter "MUST be ignored", so this gate fails
/// on an implementation that reads the qualifier table as a whitelist.
#[test]
fn a_parameter_that_is_not_for_request_update_at_all_is_ignored() {
    let mut ep = active();
    let id = namespace_request(&mut ep);

    ep.receive_request_update(&update(id, 0x22))
        .expect("GROUP_ORDER does not name REQUEST_UPDATE, so it is ignored");
    assert_eq!(
        ep.session_state(),
        SessionState::Active,
        "ignoring is what the draft asks for, and this closed the session instead",
    );
}

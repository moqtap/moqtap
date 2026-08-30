//! The setup option that bounds Range Filters, draft-19 only.
//!
//! Draft-19 Section 10.3.1.6:
//!
//! > The MAX_FILTER_RANGES option (Type 0x06) limits the peer's total number of
//! > Ranges (Start/End pairs) allowed concurrently in all Range filter
//! > parameters for a given subscription or fetch. The default value is 0, so if
//! > not specified, the peer MUST NOT send any such filter parameters. If this
//! > limit is exceeded, an endpoint MUST reject this with REQUEST_ERROR with
//! > error code INVALID_FILTER.
//!
//! # The neighbour that reads its zero the other way
//!
//! The subsection after this one is MAX_REQUEST_UPDATES, whose zero means "no
//! limit" and whose breach is a session close. This option's zero means "none
//! allowed" and its breach is a reply. Two consecutive subsections, the same
//! shape, opposite answers on both counts — and nothing in either sentence
//! signals which way to read it, so both are driven here and in
//! `draft19_max_request_updates.rs` rather than left to one implementation of
//! "a setup ceiling".
//!
//! # Why the request is taken and then refused
//!
//! A REQUEST_ERROR names the Request ID of the request it answers. An endpoint
//! that refused a SUBSCRIBE carrying a filter it has no budget for would have
//! nothing to name, and the subscriber would wait for a reply about a request
//! the responder is pretending it never saw. So the request is recorded, the
//! rejection is recorded beside it, and what the endpoint is stopped from doing
//! is *accepting* it.

#![cfg(feature = "draft19")]

use moqtap_client::draft19::endpoint::{Endpoint, EndpointError, FilterRejection};
use moqtap_client::draft19::session::request_id::Role;
use moqtap_client::draft19::session::state::SessionState;
use moqtap_codec::draft19::error_codes::RequestErrorCode;
use moqtap_codec::draft19::message::{
    ControlMessage, RequestError, RequestOk, RequestUpdate, Setup, Subscribe, SubscribeOk,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::range_filter::*;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::{Moqt18, VarInt};

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// An endpoint whose own SETUP advertised `limit` ranges, or none at all.
///
/// A server, so the peer's Request IDs are the even ones the SUBSCRIBEs below
/// carry.
fn advertising(limit: Option<u64>) -> Endpoint {
    let mut endpoint = Endpoint::new(Role::Server);
    endpoint.connect().unwrap();
    let options = match limit {
        Some(n) => vec![KeyValuePair { key: varint(0x06), value: KvpValue::Varint(varint(n)) }],
        None => vec![],
    };
    endpoint.send_setup(options).unwrap();
    endpoint.receive_setup(&Setup { options: vec![] }).unwrap();
    endpoint
}

/// A Range Filter parameter carrying `ranges` inclusive ranges.
fn filter(parameter_type: u64, set_id: u8, ranges: &[(u64, u64)]) -> KeyValuePair {
    let filter = RangeFilter {
        parameter_type,
        set_id,
        property_type: None,
        ranges: ranges.iter().map(|&(start, end)| FilterRange { start, end: Some(end) }).collect(),
    };
    let mut value = Vec::new();
    filter.encode_moqt::<Moqt18>(&mut value).expect("the fixture filter is well formed");
    KeyValuePair { key: varint(parameter_type), value: KvpValue::Bytes(value) }
}

/// The peer's SUBSCRIBE, carrying `parameters`.
fn peer_subscribe(endpoint: &mut Endpoint, id: u64, parameters: Vec<KeyValuePair>) -> VarInt {
    let msg = ControlMessage::Subscribe(Subscribe {
        request_id: varint(id),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        parameters,
    });
    endpoint.receive_request_on_stream(&msg).expect("the request itself is taken")
}

/// Section 5.1.3's removal form: "Length can be 0 to remove a filter parameter".
fn removal(parameter_type: u64) -> KeyValuePair {
    KeyValuePair { key: varint(parameter_type), value: KvpValue::Bytes(Vec::new()) }
}

/// The peer's REQUEST_UPDATE on the stream `id` opened.
fn peer_update(endpoint: &mut Endpoint, id: VarInt, parameters: Vec<KeyValuePair>) {
    let msg = ControlMessage::RequestUpdate(RequestUpdate { request_id: id, parameters });
    endpoint.receive_on_peer_request_stream(id, msg).expect("the update itself is taken");
}

/// An accepted subscription carrying `filters`, on an endpoint advertising
/// `limit` ranges.
fn accepted_subscription(limit: u64, filters: Vec<KeyValuePair>) -> (Endpoint, VarInt) {
    let mut endpoint = advertising(Some(limit));
    let id = peer_subscribe(&mut endpoint, 0, filters);
    assert_eq!(endpoint.filter_rejection(id), None, "the fixture request is inside the budget");
    endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own answer");
    (endpoint, id)
}

fn request_ok() -> ControlMessage {
    ControlMessage::RequestOk(RequestOk { parameters: vec![], track_properties: vec![] })
}

fn subscribe_ok() -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        track_alias: varint(4),
        parameters: vec![],
        track_properties: vec![],
    })
}

fn request_error(code: RequestErrorCode) -> ControlMessage {
    ControlMessage::RequestError(RequestError {
        error_code: varint(code as u64),
        retry_interval: varint(0),
        reason_phrase: b"invalid filter".to_vec(),
        redirect: None,
    })
}

/// A Range Filter with no budget advertised cannot be accepted, and does not end
/// the session.
///
/// Both halves matter. "The default value is 0, so if not specified, the peer
/// MUST NOT send any such filter parameters" is the rule; "MUST reject this with
/// REQUEST_ERROR" is the answer, and it is not the answer the option next door
/// gives.
///
/// # What it catches
///
/// Ablation: dropping the guard from `send_response_on_stream` accepts the
/// subscription the endpoint had no budget to apply the filters of:
///
/// ```text
/// a request whose filters must be rejected cannot be accepted: Ok(())
/// ```
#[test]
fn a_range_filter_with_no_budget_advertised_cannot_be_accepted() {
    let mut endpoint = advertising(None);
    let id =
        peer_subscribe(&mut endpoint, 0, vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(3, 5)])]);

    assert_eq!(
        endpoint.filter_rejection(id),
        Some(&FilterRejection::NoBudgetAdvertised),
        "an absent MAX_FILTER_RANGES is a budget of zero, which allows no filter",
    );

    let result = endpoint.send_response_on_stream(id, &subscribe_ok());
    match result {
        Err(EndpointError::FilterMustBeRejected(got, FilterRejection::NoBudgetAdvertised)) => {
            assert_eq!(got, id.into_inner());
        }
        other => panic!("a request whose filters must be rejected cannot be accepted: {other:?}"),
    }

    assert_eq!(
        endpoint.session_state(),
        SessionState::Active,
        "this rule is answered with a reply, not with a close",
    );
}

/// The REQUEST_ERROR the draft requires goes through, and spends the rejection.
#[test]
fn the_request_error_the_draft_requires_is_the_way_out() {
    let mut endpoint = advertising(None);
    let id =
        peer_subscribe(&mut endpoint, 0, vec![filter(OBJECT_ID_FILTER_PARAMETER, 0, &[(1, 2)])]);

    let rejection = endpoint.filter_rejection(id).expect("there is a rejection to answer").clone();
    assert_eq!(
        rejection.request_error_code(),
        RequestErrorCode::InvalidFilter,
        "every Range Filter rule names the same code",
    );

    endpoint
        .send_response_on_stream(id, &request_error(rejection.request_error_code()))
        .expect("the answer the draft requires is the one that is allowed");
    assert_eq!(endpoint.filter_rejection(id), None, "answering it spends it");
}

/// A request inside the advertised budget is accepted.
#[test]
fn a_request_inside_the_budget_is_accepted() {
    let mut endpoint = advertising(Some(4));
    let id = peer_subscribe(
        &mut endpoint,
        0,
        vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(3, 5), (10, 15)])],
    );

    assert_eq!(endpoint.filter_rejection(id), None, "two ranges against a budget of four");
    endpoint.send_response_on_stream(id, &subscribe_ok()).expect("nothing is owed");
}

/// The budget is spent across every filter, not within one.
///
/// "the total number of Ranges allowed in all Range Filter parameters for a
/// given subscription or fetch". A count kept per parameter never reaches the
/// ceiling: three filters of two ranges each are two, two and two.
///
/// # What it catches
///
/// Ablation: counting the ranges of the largest filter instead of their sum:
///
/// ```text
/// assertion `left == right` failed: six ranges across three filters must exceed a budget of four
///   left: None
///  right: Some(TooManyRanges { ranges: 6, limit: 4 })
/// ```
#[test]
fn the_budget_is_spent_across_every_filter() {
    let mut endpoint = advertising(Some(4));
    let id = peer_subscribe(
        &mut endpoint,
        0,
        vec![
            filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)]),
            filter(OBJECT_ID_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)]),
            filter(PRIORITY_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)]),
        ],
    );

    assert_eq!(
        endpoint.filter_rejection(id),
        Some(&FilterRejection::TooManyRanges { ranges: 6, limit: 4 }),
        "six ranges across three filters must exceed a budget of four",
    );
}

/// Two filters sharing a key are rejected; two differing in one are not.
///
/// "If the same combination of Parameter Type, SetID, and Property Type ...
/// repeat in any message, an endpoint MUST reject this" sits two paragraphs
/// below "The Track Property filter parameter MAY appear multiple times", so the
/// type alone cannot be the key.
#[test]
fn the_repeat_rule_is_about_the_whole_key() {
    // The same type under two sets is two filters, not a repeat.
    let mut endpoint = advertising(Some(8));
    let id = peer_subscribe(
        &mut endpoint,
        0,
        vec![
            filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2)]),
            filter(SUBGROUP_FILTER_PARAMETER, 1, &[(5, 6)]),
        ],
    );
    assert_eq!(endpoint.filter_rejection(id), None, "two sets are two filters");

    // The same type under one set is the repeat.
    let mut endpoint = advertising(Some(8));
    let id = peer_subscribe(
        &mut endpoint,
        0,
        vec![
            filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2)]),
            filter(SUBGROUP_FILTER_PARAMETER, 0, &[(5, 6)]),
        ],
    );
    assert_eq!(
        endpoint.filter_rejection(id),
        Some(&FilterRejection::RepeatedFilter(SUBGROUP_FILTER_PARAMETER, 0, None)),
    );
}

/// A request with no Range Filter is untouched by a budget of zero.
///
/// The half that would be easy to break by reading "the peer MUST NOT send any
/// such filter parameters" as a rule about requests rather than about filters.
/// Draft-19 is the first draft with these parameters, so nearly every request an
/// endpoint sees carries none, and measuring those against the ceiling would
/// reject the whole of ordinary traffic.
#[test]
fn a_request_carrying_no_filter_is_untouched_by_a_budget_of_zero() {
    let mut endpoint = advertising(None);
    let id = peer_subscribe(&mut endpoint, 0, vec![]);

    assert_eq!(endpoint.filter_rejection(id), None);
    endpoint.send_response_on_stream(id, &subscribe_ok()).expect("an ordinary SUBSCRIBE");
}

/// A filter that does not read is a rejection and not a refusal.
///
/// The delta rules, the priority range and the property-type parity all reach
/// the endpoint the same way: the codec reports them out of the reader, and the
/// endpoint owes a REQUEST_ERROR rather than a closed session or a dropped
/// frame.
#[test]
fn a_filter_that_does_not_read_is_a_rejection_too() {
    let mut endpoint = advertising(Some(8));
    // A PRIORITY_FILTER whose End resolves to 300, which Section 10.2.12
    // answers with the same REQUEST_ERROR.
    let mut value = vec![0u8];
    for delta in [200u64, 100] {
        VarInt::from_u64_moqt(delta).encode_moqt::<Moqt18>(&mut value);
    }
    let id = peer_subscribe(
        &mut endpoint,
        0,
        vec![KeyValuePair {
            key: varint(PRIORITY_FILTER_PARAMETER),
            value: KvpValue::Bytes(value),
        }],
    );

    assert_eq!(
        endpoint.filter_rejection(id),
        Some(&FilterRejection::Unreadable(RangeFilterError::PriorityAboveTheField(300))),
    );
    assert_eq!(
        endpoint.session_state(),
        SessionState::Active,
        "none of these rules ends the session",
    );
}

// -- The ceiling after a REQUEST_UPDATE --------------------------------------
//
// Section 5.1.3: "In REQUEST_UPDATE, Length can be 0 to remove a filter
// parameter or non-zero to replace that entire filter parameter including all
// sets and Property Types. If a filter parameter is omitted from REQUEST_UPDATE,
// the value is unchanged."
//
// So an update rewrites the request's filters rather than adding a message's
// worth of them, and the ceiling is on what is in force afterwards. Section
// 5.1.3 states the same limit without the cross-reference Section 10.3.1.6
// carries inside the noun phrase: "the total number of Ranges allowed in all
// Range Filter parameters for a given subscription or fetch". Three readings
// are wrong in three different
// directions, and each has a gate below: measuring the update alone, appending
// it to what was already there, and dropping what it did not mention.

/// An update that takes the request past the budget is rejected.
///
/// # What it catches
///
/// Ablation: dropping the ceiling from `receive_request_update`, which is where
/// the endpoint stood before — the request was held to its budget and everything
/// it was later changed into was not:
///
/// ```text
/// assertion `left == right` failed: six ranges in force against a budget of four
///   left: None
///  right: Some(TooManyRanges { ranges: 6, limit: 4 })
/// ```
///
/// Measuring the update's parameters on their own does *not* fail this one, and
/// that is worth saying: six ranges arriving in one message are six however they
/// are counted. It takes the two gates below to tell the two readings apart.
#[test]
fn an_update_past_the_budget_is_rejected() {
    let (mut endpoint, id) =
        accepted_subscription(4, vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)])]);

    peer_update(
        &mut endpoint,
        id,
        vec![filter(
            SUBGROUP_FILTER_PARAMETER,
            0,
            &[(1, 2), (5, 6), (9, 10), (13, 14), (17, 18), (21, 22)],
        )],
    );

    assert_eq!(
        endpoint.filter_rejection(id),
        Some(&FilterRejection::TooManyRanges { ranges: 6, limit: 4 }),
        "six ranges in force against a budget of four",
    );

    // The answer an update takes is a REQUEST_OK, so that is what must be
    // refused here - the same guard the request's own acceptance meets.
    let result = endpoint.send_response_on_stream(id, &request_ok());
    assert!(
        matches!(result, Err(EndpointError::FilterMustBeRejected(..))),
        "an update whose filters must be rejected cannot be accepted either: {result:?}",
    );
    endpoint
        .send_response_on_stream(id, &request_error(RequestErrorCode::InvalidFilter))
        .expect("the answer the draft requires");
    assert_eq!(endpoint.filter_rejection(id), None, "answering it spends it");
}

/// A replacement replaces rather than adds.
///
/// Four ranges arriving under a type that already held three is four in force,
/// not seven: "non-zero to replace that entire filter parameter including all
/// sets and Property Types". An endpoint that appended would reject a request
/// that is inside its budget, and would do it on the peer's second update rather
/// than its first.
///
/// # What it catches
///
/// Ablation: extending the set in force instead of replacing by Parameter Type:
///
/// ```text
/// assertion `left == right` failed: the update replaced the three ranges with four, and four is the budget
///   left: Some(TooManyRanges { ranges: 7, limit: 4 })
///  right: None
/// ```
///
/// Three and four counted as seven, which is the request's whole history rather
/// than its current state.
#[test]
fn a_replacement_replaces_rather_than_adds() {
    let (mut endpoint, id) = accepted_subscription(
        4,
        vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6), (9, 10)])],
    );

    peer_update(
        &mut endpoint,
        id,
        vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6), (9, 10), (13, 14)])],
    );

    assert_eq!(
        endpoint.filter_rejection(id),
        None,
        "the update replaced the three ranges with four, and four is the budget",
    );
    endpoint.send_response_on_stream(id, &request_ok()).expect("nothing is owed");
}

/// A filter the update does not mention stays in force and keeps costing.
///
/// The other direction from the one above. "If a filter parameter is omitted
/// from REQUEST_UPDATE, the value is unchanged", so an endpoint that measured
/// only what the update named would let a subscription take up ranges one
/// parameter type at a time and never see a total.
///
/// # What it catches
///
/// Ablation: measuring the update's own parameters rather than the merged set:
///
/// ```text
/// assertion `left == right` failed: three ranges the update left alone plus the two it set
///   left: None
///  right: Some(TooManyRanges { ranges: 5, limit: 4 })
/// ```
#[test]
fn a_filter_the_update_does_not_mention_still_counts() {
    let (mut endpoint, id) = accepted_subscription(
        4,
        vec![
            filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6), (9, 10)]),
            filter(OBJECT_ID_FILTER_PARAMETER, 0, &[(1, 2)]),
        ],
    );

    // Only the Object ID filter is named, and it grows by one range. The three
    // Subgroup ranges are untouched and are what tips the total over.
    peer_update(&mut endpoint, id, vec![filter(OBJECT_ID_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)])]);

    assert_eq!(
        endpoint.filter_rejection(id),
        Some(&FilterRejection::TooManyRanges { ranges: 5, limit: 4 }),
        "three ranges the update left alone plus the two it set",
    );
}

/// A removal takes its filter's ranges out of the count.
///
/// The half that makes the ceiling usable: a subscriber at its limit can drop
/// one filter and take up another in the same update. An endpoint that treated
/// the zero-length parameter as a filter of its own would leave the old ranges
/// in force and refuse the exchange.
///
/// # What it catches
///
/// Ablation: taking the types an update mentions from its non-empty parameters
/// only, so that a removal names nothing and therefore removes nothing:
///
/// ```text
/// assertion `left == right` failed: the four Subgroup ranges were removed in the same message that took up two
///   left: Some(TooManyRanges { ranges: 6, limit: 4 })
///  right: None
/// ```
///
/// A subscriber that did everything the section asks of it would be refused,
/// which is the failure mode a ceiling has to avoid most.
#[test]
fn a_removal_gives_the_budget_back() {
    let (mut endpoint, id) = accepted_subscription(
        4,
        vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6), (9, 10), (13, 14)])],
    );

    // Without the removal the same update is two ranges too many.
    let (mut adding, other) = accepted_subscription(
        4,
        vec![filter(SUBGROUP_FILTER_PARAMETER, 0, &[(1, 2), (5, 6), (9, 10), (13, 14)])],
    );
    peer_update(&mut adding, other, vec![filter(OBJECT_ID_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)])]);
    assert_eq!(
        adding.filter_rejection(other),
        Some(&FilterRejection::TooManyRanges { ranges: 6, limit: 4 }),
    );

    // With it, the exchange is inside the budget.
    peer_update(
        &mut endpoint,
        id,
        vec![
            removal(SUBGROUP_FILTER_PARAMETER),
            filter(OBJECT_ID_FILTER_PARAMETER, 0, &[(1, 2), (5, 6)]),
        ],
    );
    assert_eq!(
        endpoint.filter_rejection(id),
        None,
        "the four Subgroup ranges were removed in the same message that took up two",
    );
    endpoint.send_response_on_stream(id, &request_ok()).expect("nothing is owed");
}

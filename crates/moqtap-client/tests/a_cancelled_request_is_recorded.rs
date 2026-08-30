//! A request withdrawn at its stream is a request the endpoint knows is over.
//!
//! Drafts 17, 18 and 19 carry no UNSUBSCRIBE, no FETCH_CANCEL, no
//! UNSUBSCRIBE_NAMESPACE and no PUBLISH_NAMESPACE_CANCEL. A request is
//! withdrawn by terminating the bidirectional stream it was made on — draft-17
//! Section 3.3.1, draft-18 Section 3.3.2 and draft-19 Section 3.3.3, in the
//! same words: "Once a request stream has been opened, the request MAY be
//! cancelled by either endpoint. Senders cancel requests if the response is no
//! longer of interest; Receivers cancel requests if they are unable to or
//! choose not to respond."
//!
//! `Endpoint::cancel_request` is where that act is recorded, and every request
//! kind each draft has needs its own arm in it. What each test below asserts is
//! the consequence rather than the record: a cancelled request refuses the
//! answer it would have taken a moment earlier.
//!
//! # Ablations, run
//!
//! Each arm is cut on its own, because a single cut stops at the first
//! assertion that reaches it.
//!
//! Removing the `subscriptions` arm from draft-17's `cancel_request`:
//!
//! ```text
//! a cancelled subscription must be recorded: UnknownRequest(0)
//! ```
//!
//! Removing the `subscribe_tracks` arm from draft-18's — the seventh request
//! kind, which draft-17 does not have:
//!
//! ```text
//! a cancelled track subscription must be recorded: UnknownRequest(0)
//! ```
//!
//! Narrowing `SubscriptionStateMachine::on_request_cancelled` on draft-19 back
//! to `Active` alone, so a subscription may only be withdrawn once it has been
//! answered:
//!
//! ```text
//! a cancelled subscription must be recorded: Subscription(InvalidTransition
//! { from: Subscribing, event: "on_request_cancelled" })
//! ```
//!
//! Making `TrackStatusStateMachine::on_request_cancelled` refuse `Done` on
//! draft-18:
//!
//! ```text
//! a request that has already ended still accepts the cancel that follows it:
//! TrackStatus(InvalidTransition { from: Done, event: "on_request_cancelled" })
//! ```
//!
//! Letting draft-17's subscription machine take a cancel from `Idle`:
//!
//! ```text
//! a request with no stream yet cannot be cancelled, and these accepted it:
//! ["subscription"]
//! ```
//!
//! And returning `Ok(())` from the end of draft-17's `cancel_request` instead
//! of naming the id nothing carries:
//!
//! ```text
//! `cancel_request` must refuse a request id nothing carries, got Ok(())
//! ```

#![cfg(all(feature = "draft17", feature = "draft18", feature = "draft19"))]

use moqtap_codec::types::TrackNamespace;

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

fn track() -> Vec<u8> {
    b"video".to_vec()
}

// -- draft-17 -------------------------------------------------------------

mod draft17 {
    use super::{ns, track};
    use moqtap_client::draft17::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft17::fetch::FetchStateMachine;
    use moqtap_client::draft17::namespace::{
        PublishNamespaceStateMachine, SubscribeNamespaceStateMachine,
    };
    use moqtap_client::draft17::publish::PublishStateMachine;
    use moqtap_client::draft17::session::request_id::Role;
    use moqtap_client::draft17::subscription::SubscriptionStateMachine;
    use moqtap_client::draft17::track_status::TrackStatusStateMachine;
    use moqtap_codec::draft17::message::{
        ControlMessage, RequestError, RequestOk, Setup, Subscribe, SubscribeOk,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).expect("a fixture value fits a varint")
    }

    /// A client with its session established, so requests may be made.
    fn active() -> Endpoint {
        let mut ep = Endpoint::new(Role::Client);
        ep.connect().expect("a client may open");
        ep.send_setup(vec![]).expect("its own SETUP");
        ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
        ep
    }

    /// A server, so the peer's Request IDs are the even ones.
    fn responder() -> Endpoint {
        let mut ep = Endpoint::new(Role::Server);
        ep.connect().expect("a server may open");
        ep.send_setup(vec![]).expect("its own SETUP");
        ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
        ep
    }

    /// The one answer every request kind on this draft can be given, which is
    /// what lets the cases below differ in nothing but the request.
    fn request_error() -> RequestError {
        RequestError { error_code: v(1), retry_interval: v(0), reason_phrase: Vec::new() }
    }

    fn request_ok() -> RequestOk {
        RequestOk { parameters: Vec::new() }
    }

    /// A cancelled subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe(ns(), track(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled fetch refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_fetch_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep
            .fetch(ns(), track(), v(0), v(0), v(1), v(0), Vec::new())
            .expect("the request is made");
        ep.cancel_request(id).expect("a cancelled fetch must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled fetch must be refused, got {refused:?}"
        );
    }

    /// A cancelled publication refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_publish_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.publish(ns(), track(), v(7), vec![], vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled publication must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled publication must be refused, got {refused:?}"
        );
    }

    /// A cancelled namespace subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_namespace_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe_namespace(ns(), v(2), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled namespace subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled namespace subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled namespace advertisement refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_namespace_advertisement_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.publish_namespace(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled namespace advertisement must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled namespace advertisement must be refused, got {refused:?}"
        );
    }

    /// A cancelled track status request refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_track_status_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.track_status(ns(), track(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled track status request must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled track status request must be refused, got {refused:?}"
        );
    }

    /// An answer to a request that was never cancelled is still taken.
    ///
    /// Without this the refusals above would hold just as well if
    /// `receive_request_error` refused everything.
    #[test]
    fn an_answer_to_a_live_request_is_still_accepted() {
        let mut ep = active();
        let (id, _) = ep.subscribe(ns(), track(), vec![]).expect("a subscription");
        ep.receive_request_error(id, &request_error())
            .expect("a REQUEST_ERROR answering a live subscription is taken");
    }

    /// A cancel after the request has already ended is not an error.
    ///
    /// Nothing finishes a request stream's send half on the ordinary path, so
    /// a caller that walks away from a request that ran its course still
    /// terminates the stream, and the endpoint hears about it afterwards.
    #[test]
    fn a_request_cancelled_after_it_ended_is_not_an_error() {
        let mut ep = active();
        let (id, _) = ep.track_status(ns(), track(), vec![]).expect("a track status request");
        ep.receive_request_ok(id, &request_ok()).expect("its answer");
        ep.cancel_request(id)
            .expect("a request that has already ended still accepts the cancel that follows it");
    }

    /// A request that was never written cannot be cancelled.
    ///
    /// The section's own precondition is a stream that has been opened, and
    /// every request kind states it separately, so every one of them is driven
    /// here. Each is reported rather than asserted one at a time: a machine
    /// that wrongly accepted would otherwise hide the ones after it.
    ///
    /// Unreachable through the endpoint, which moves a request out of `Idle`
    /// in the same call that creates it, so the machines are driven directly.
    #[test]
    fn a_request_that_was_never_written_cannot_be_cancelled() {
        let outcomes = [
            ("subscription", SubscriptionStateMachine::new().on_request_cancelled().is_err()),
            ("fetch", FetchStateMachine::new().on_request_cancelled().is_err()),
            ("publish", PublishStateMachine::new().on_request_cancelled().is_err()),
            (
                "namespace subscription",
                SubscribeNamespaceStateMachine::new().on_request_cancelled().is_err(),
            ),
            (
                "namespace advertisement",
                PublishNamespaceStateMachine::new().on_request_cancelled().is_err(),
            ),
            (
                "track status request",
                TrackStatusStateMachine::new().on_request_cancelled().is_err(),
            ),
        ];
        let accepted: Vec<&str> =
            outcomes.iter().filter(|(_, refused)| !refused).map(|(name, _)| *name).collect();
        assert!(
            accepted.is_empty(),
            "a request with no stream yet cannot be cancelled, and these accepted it: {accepted:?}"
        );
    }

    /// A request id no request carries is refused rather than ignored.
    #[test]
    fn cancel_request_refuses_an_id_no_request_carries() {
        let mut ep = active();
        let refused = ep.cancel_request(v(41));
        assert!(
            matches!(refused, Err(EndpointError::UnknownRequest(41))),
            "`cancel_request` must refuse a request id nothing carries, got {refused:?}"
        );
    }

    /// The other half of the sentence: a request the **peer** made, cancelled
    /// here because this endpoint chooses not to answer it.
    #[test]
    fn a_peers_request_cancelled_here_refuses_the_response_it_was_owed() {
        let mut ep = responder();
        let id = ep
            .receive_request_on_stream(&peer_subscribe())
            .expect("the peer's SUBSCRIBE opens a request stream");
        ep.cancel_request(id).expect("a request the peer made can be cancelled here");
        let refused = ep.send_response_on_stream(
            id,
            &ControlMessage::SubscribeOk(SubscribeOk {
                track_alias: v(1),
                parameters: Vec::new(),
                track_properties: Vec::new(),
            }),
        );
        assert!(
            refused.is_err(),
            "a SUBSCRIBE_OK owed on a cancelled request stream must be refused, got {refused:?}"
        );
    }

    fn peer_subscribe() -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: v(0),
            required_request_id_delta: v(0),
            track_namespace: ns(),
            track_name: track(),
            parameters: Vec::new(),
        })
    }
}

// -- draft-18 -------------------------------------------------------------

mod draft18 {
    use super::{ns, track};
    use moqtap_client::draft18::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft18::fetch::FetchStateMachine;
    use moqtap_client::draft18::namespace::{
        PublishNamespaceStateMachine, SubscribeNamespaceStateMachine,
    };
    use moqtap_client::draft18::publish::PublishStateMachine;
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::subscription::SubscriptionStateMachine;
    use moqtap_client::draft18::track_status::TrackStatusStateMachine;
    use moqtap_codec::draft18::message::{
        ControlMessage, RequestError, RequestOk, Setup, Subscribe, SubscribeOk,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).expect("a fixture value fits a varint")
    }

    /// A client with its session established, so requests may be made.
    fn active() -> Endpoint {
        let mut ep = Endpoint::new(Role::Client);
        ep.connect().expect("a client may open");
        ep.send_setup(vec![]).expect("its own SETUP");
        ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
        ep
    }

    /// A server, so the peer's Request IDs are the even ones.
    fn responder() -> Endpoint {
        let mut ep = Endpoint::new(Role::Server);
        ep.connect().expect("a server may open");
        ep.send_setup(vec![]).expect("its own SETUP");
        ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
        ep
    }

    /// The one answer every request kind on this draft can be given, which is
    /// what lets the cases below differ in nothing but the request.
    fn request_error() -> RequestError {
        RequestError {
            error_code: v(1),
            retry_interval: v(0),
            reason_phrase: Vec::new(),
            redirect: None,
        }
    }

    fn request_ok() -> RequestOk {
        RequestOk { parameters: Vec::new(), track_properties: Vec::new() }
    }

    /// A cancelled subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe(ns(), track(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled fetch refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_fetch_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep
            .fetch(ns(), track(), v(0), v(0), v(1), v(0), Vec::new())
            .expect("the request is made");
        ep.cancel_request(id).expect("a cancelled fetch must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled fetch must be refused, got {refused:?}"
        );
    }

    /// A cancelled publication refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_publish_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.publish(ns(), track(), v(7), vec![], vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled publication must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled publication must be refused, got {refused:?}"
        );
    }

    /// A cancelled namespace subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_namespace_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe_namespace(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled namespace subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled namespace subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled track subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_track_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe_tracks(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled track subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled track subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled namespace advertisement refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_namespace_advertisement_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.publish_namespace(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled namespace advertisement must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled namespace advertisement must be refused, got {refused:?}"
        );
    }

    /// A cancelled track status request refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_track_status_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.track_status(ns(), track(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled track status request must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled track status request must be refused, got {refused:?}"
        );
    }

    /// An answer to a request that was never cancelled is still taken.
    ///
    /// Without this the refusals above would hold just as well if
    /// `receive_request_error` refused everything.
    #[test]
    fn an_answer_to_a_live_request_is_still_accepted() {
        let mut ep = active();
        let (id, _) = ep.subscribe(ns(), track(), vec![]).expect("a subscription");
        ep.receive_request_error(id, &request_error())
            .expect("a REQUEST_ERROR answering a live subscription is taken");
    }

    /// A cancel after the request has already ended is not an error.
    ///
    /// Nothing finishes a request stream's send half on the ordinary path, so
    /// a caller that walks away from a request that ran its course still
    /// terminates the stream, and the endpoint hears about it afterwards.
    #[test]
    fn a_request_cancelled_after_it_ended_is_not_an_error() {
        let mut ep = active();
        let (id, _) = ep.track_status(ns(), track(), vec![]).expect("a track status request");
        ep.receive_request_ok(id, &request_ok()).expect("its answer");
        ep.cancel_request(id)
            .expect("a request that has already ended still accepts the cancel that follows it");
    }

    /// A request that was never written cannot be cancelled.
    ///
    /// The section's own precondition is a stream that has been opened, and
    /// every request kind states it separately, so every one of them is driven
    /// here. Each is reported rather than asserted one at a time: a machine
    /// that wrongly accepted would otherwise hide the ones after it.
    ///
    /// Unreachable through the endpoint, which moves a request out of `Idle`
    /// in the same call that creates it, so the machines are driven directly.
    #[test]
    fn a_request_that_was_never_written_cannot_be_cancelled() {
        let outcomes = [
            ("subscription", SubscriptionStateMachine::new().on_request_cancelled().is_err()),
            ("fetch", FetchStateMachine::new().on_request_cancelled().is_err()),
            ("publish", PublishStateMachine::new().on_request_cancelled().is_err()),
            (
                "namespace subscription",
                SubscribeNamespaceStateMachine::new().on_request_cancelled().is_err(),
            ),
            (
                "namespace advertisement",
                PublishNamespaceStateMachine::new().on_request_cancelled().is_err(),
            ),
            (
                "track status request",
                TrackStatusStateMachine::new().on_request_cancelled().is_err(),
            ),
        ];
        let accepted: Vec<&str> =
            outcomes.iter().filter(|(_, refused)| !refused).map(|(name, _)| *name).collect();
        assert!(
            accepted.is_empty(),
            "a request with no stream yet cannot be cancelled, and these accepted it: {accepted:?}"
        );
    }

    /// A request id no request carries is refused rather than ignored.
    #[test]
    fn cancel_request_refuses_an_id_no_request_carries() {
        let mut ep = active();
        let refused = ep.cancel_request(v(41));
        assert!(
            matches!(refused, Err(EndpointError::UnknownRequest(41))),
            "`cancel_request` must refuse a request id nothing carries, got {refused:?}"
        );
    }

    /// The other half of the sentence: a request the **peer** made, cancelled
    /// here because this endpoint chooses not to answer it.
    #[test]
    fn a_peers_request_cancelled_here_refuses_the_response_it_was_owed() {
        let mut ep = responder();
        let id = ep
            .receive_request_on_stream(&peer_subscribe())
            .expect("the peer's SUBSCRIBE opens a request stream");
        ep.cancel_request(id).expect("a request the peer made can be cancelled here");
        let refused = ep.send_response_on_stream(
            id,
            &ControlMessage::SubscribeOk(SubscribeOk {
                track_alias: v(1),
                parameters: Vec::new(),
                track_properties: Vec::new(),
            }),
        );
        assert!(
            refused.is_err(),
            "a SUBSCRIBE_OK owed on a cancelled request stream must be refused, got {refused:?}"
        );
    }

    fn peer_subscribe() -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: v(0),
            track_namespace: ns(),
            track_name: track(),
            parameters: Vec::new(),
        })
    }
}

// -- draft-19 -------------------------------------------------------------

mod draft19 {
    use super::{ns, track};
    use moqtap_client::draft19::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft19::fetch::FetchStateMachine;
    use moqtap_client::draft19::namespace::{
        PublishNamespaceStateMachine, SubscribeNamespaceStateMachine,
    };
    use moqtap_client::draft19::publish::PublishStateMachine;
    use moqtap_client::draft19::session::request_id::Role;
    use moqtap_client::draft19::subscription::SubscriptionStateMachine;
    use moqtap_client::draft19::track_status::TrackStatusStateMachine;
    use moqtap_codec::draft19::message::{
        ControlMessage, RequestError, RequestOk, Setup, Subscribe, SubscribeOk,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).expect("a fixture value fits a varint")
    }

    /// A client with its session established, so requests may be made.
    fn active() -> Endpoint {
        let mut ep = Endpoint::new(Role::Client);
        ep.connect().expect("a client may open");
        ep.send_setup(vec![]).expect("its own SETUP");
        ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
        ep
    }

    /// A server, so the peer's Request IDs are the even ones.
    fn responder() -> Endpoint {
        let mut ep = Endpoint::new(Role::Server);
        ep.connect().expect("a server may open");
        ep.send_setup(vec![]).expect("its own SETUP");
        ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
        ep
    }

    /// The one answer every request kind on this draft can be given, which is
    /// what lets the cases below differ in nothing but the request.
    fn request_error() -> RequestError {
        RequestError {
            error_code: v(1),
            retry_interval: v(0),
            reason_phrase: Vec::new(),
            redirect: None,
        }
    }

    fn request_ok() -> RequestOk {
        RequestOk { parameters: Vec::new(), track_properties: Vec::new() }
    }

    /// A cancelled subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe(ns(), track(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled fetch refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_fetch_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep
            .fetch(ns(), track(), v(0), v(0), v(1), v(0), Vec::new())
            .expect("the request is made");
        ep.cancel_request(id).expect("a cancelled fetch must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled fetch must be refused, got {refused:?}"
        );
    }

    /// A cancelled publication refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_publish_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.publish(ns(), track(), v(7), vec![], vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled publication must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled publication must be refused, got {refused:?}"
        );
    }

    /// A cancelled namespace subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_namespace_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe_namespace(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled namespace subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled namespace subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled track subscription refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_track_subscription_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.subscribe_tracks(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled track subscription must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled track subscription must be refused, got {refused:?}"
        );
    }

    /// A cancelled namespace advertisement refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_namespace_advertisement_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.publish_namespace(ns(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled namespace advertisement must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled namespace advertisement must be refused, got {refused:?}"
        );
    }

    /// A cancelled track status request refuses the answer it was waiting for.
    #[test]
    fn a_cancelled_track_status_refuses_its_answer() {
        let mut ep = active();
        let (id, _) = ep.track_status(ns(), track(), vec![]).expect("the request is made");
        ep.cancel_request(id).expect("a cancelled track status request must be recorded");
        let refused = ep.receive_request_error(id, &request_error());
        assert!(
            refused.is_err(),
            "an answer to a cancelled track status request must be refused, got {refused:?}"
        );
    }

    /// An answer to a request that was never cancelled is still taken.
    ///
    /// Without this the refusals above would hold just as well if
    /// `receive_request_error` refused everything.
    #[test]
    fn an_answer_to_a_live_request_is_still_accepted() {
        let mut ep = active();
        let (id, _) = ep.subscribe(ns(), track(), vec![]).expect("a subscription");
        ep.receive_request_error(id, &request_error())
            .expect("a REQUEST_ERROR answering a live subscription is taken");
    }

    /// A cancel after the request has already ended is not an error.
    ///
    /// Nothing finishes a request stream's send half on the ordinary path, so
    /// a caller that walks away from a request that ran its course still
    /// terminates the stream, and the endpoint hears about it afterwards.
    #[test]
    fn a_request_cancelled_after_it_ended_is_not_an_error() {
        let mut ep = active();
        let (id, _) = ep.track_status(ns(), track(), vec![]).expect("a track status request");
        ep.receive_request_ok(id, &request_ok()).expect("its answer");
        ep.cancel_request(id)
            .expect("a request that has already ended still accepts the cancel that follows it");
    }

    /// A request that was never written cannot be cancelled.
    ///
    /// The section's own precondition is a stream that has been opened, and
    /// every request kind states it separately, so every one of them is driven
    /// here. Each is reported rather than asserted one at a time: a machine
    /// that wrongly accepted would otherwise hide the ones after it.
    ///
    /// Unreachable through the endpoint, which moves a request out of `Idle`
    /// in the same call that creates it, so the machines are driven directly.
    #[test]
    fn a_request_that_was_never_written_cannot_be_cancelled() {
        let outcomes = [
            ("subscription", SubscriptionStateMachine::new().on_request_cancelled().is_err()),
            ("fetch", FetchStateMachine::new().on_request_cancelled().is_err()),
            ("publish", PublishStateMachine::new().on_request_cancelled().is_err()),
            (
                "namespace subscription",
                SubscribeNamespaceStateMachine::new().on_request_cancelled().is_err(),
            ),
            (
                "namespace advertisement",
                PublishNamespaceStateMachine::new().on_request_cancelled().is_err(),
            ),
            (
                "track status request",
                TrackStatusStateMachine::new().on_request_cancelled().is_err(),
            ),
        ];
        let accepted: Vec<&str> =
            outcomes.iter().filter(|(_, refused)| !refused).map(|(name, _)| *name).collect();
        assert!(
            accepted.is_empty(),
            "a request with no stream yet cannot be cancelled, and these accepted it: {accepted:?}"
        );
    }

    /// A request id no request carries is refused rather than ignored.
    #[test]
    fn cancel_request_refuses_an_id_no_request_carries() {
        let mut ep = active();
        let refused = ep.cancel_request(v(41));
        assert!(
            matches!(refused, Err(EndpointError::UnknownRequest(41))),
            "`cancel_request` must refuse a request id nothing carries, got {refused:?}"
        );
    }

    /// The other half of the sentence: a request the **peer** made, cancelled
    /// here because this endpoint chooses not to answer it.
    #[test]
    fn a_peers_request_cancelled_here_refuses_the_response_it_was_owed() {
        let mut ep = responder();
        let id = ep
            .receive_request_on_stream(&peer_subscribe())
            .expect("the peer's SUBSCRIBE opens a request stream");
        ep.cancel_request(id).expect("a request the peer made can be cancelled here");
        let refused = ep.send_response_on_stream(
            id,
            &ControlMessage::SubscribeOk(SubscribeOk {
                track_alias: v(1),
                parameters: Vec::new(),
                track_properties: Vec::new(),
            }),
        );
        assert!(
            refused.is_err(),
            "a SUBSCRIBE_OK owed on a cancelled request stream must be refused, got {refused:?}"
        );
    }

    fn peer_subscribe() -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: v(0),
            track_namespace: ns(),
            track_name: track(),
            parameters: Vec::new(),
        })
    }
}

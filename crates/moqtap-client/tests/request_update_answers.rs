//! The answer a REQUEST_UPDATE requires, on drafts 17, 18 and 19.
//!
//! Draft-17 Section 9.10 and drafts 18 and 19 Section 10.9, in the same words:
//!
//! > The sender of a request (SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
//! > SUBSCRIBE_NAMESPACE) can later send a REQUEST_UPDATE on the same bidi
//! > stream as the request to modify it. [...] The receiver of a REQUEST_UPDATE
//! > MUST respond with exactly one REQUEST_OK or REQUEST_ERROR message
//! > indicating if the update was successful.
//!
//! "On the same bidi stream as the request" is every request's stream, and the
//! answer is the same two messages whichever request the stream belongs to. So a
//! SUBSCRIBE's stream has to be able to carry a REQUEST_OK even though a
//! SUBSCRIBE is never answered with one.
//!
//! # What a refusal leaves behind
//!
//! Draft-18 Section 10.9, and draft-19 in the same words: "When a
//! REQUEST_UPDATE is unsuccessful, the publisher MUST also terminate the
//! subscription by sending a PUBLISH_DONE with error code UPDATE_FAILED."
//! Draft-17 Section 9.11 says it as "When a subscription update is
//! unsuccessful, the publisher MUST also terminate the subscription with
//! PUBLISH_DONE with error code UPDATE_FAILED" — the same obligation, one
//! wording earlier.
//!
//! So the REQUEST_ERROR is half an answer. The gates for the other half are at
//! the end of this file, and what they hold is the status of the ending rather
//! than its timing: a publisher with a second update still outstanding may
//! answer that first, because the sentence names a message and says nothing
//! about order. A first attempt at this refused every answer for the request
//! until the termination was written, and two of the gates above caught it.
//!
//! Drafts 15 and 16 state the same sentence and are not here, because neither
//! can refuse an update at all: their `receive_*_update` records the update
//! and returns, and the only refusal either offers is `send_request_error`,
//! which refuses the original request and moves that request's own lifecycle.
//!
//! # The ambiguity the drafts leave, and how both ends have to resolve it
//!
//! On a SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE or TRACK_STATUS stream, REQUEST_OK
//! is both the request's own answer and an update's. The two are the same message
//! and neither carries anything naming what it answers, so the only thing left to
//! tell them apart is order: the first response on a stream answers the request
//! that opened it and the ones after it answer updates. An endpoint that resolved
//! it any other way would disagree with a peer that resolved it this way, and
//! nothing on the wire would show which of them was wrong.
//!
//! On a SUBSCRIBE or FETCH stream no ordering is needed. Those are answered with
//! SUBSCRIBE_OK and FETCH_OK, so a REQUEST_OK there has nothing else it could be
//! answering — and that is the case this file exists for, because it is the one
//! the endpoint used to refuse outright.
//!
//! # What the drafts do not agree on
//!
//! Drafts 18 and 19 add Section 10.9.1: "The receiver MUST still send a
//! REQUEST_OK for each successful update, but it is not required to process
//! intermediate states individually. If the coalesced REQUEST_UPDATE results in
//! REQUEST_ERROR, only a single REQUEST_ERROR will be sent". So one REQUEST_ERROR
//! may stand for every update still waiting, while a REQUEST_OK stands for one.
//! Draft-17 has no such paragraph, and one message answers one update there
//! whichever message it is.

#[allow(unused_imports)]
use moqtap_codec::types::TrackNamespace;

/// Build the gates for one draft.
///
/// The message constructors come in as closures because the three drafts do not
/// build these messages alike: draft-17 puts a Required Request ID Delta in every
/// request and in REQUEST_UPDATE, its REQUEST_OK has no Track Properties, and its
/// REQUEST_ERROR has no Redirect. None of those differences is what is under
/// test, so they are supplied rather than worked around.
macro_rules! request_update_answer_gates {
    (
        $module:ident,
        $feat:literal,
        $draft:ident,
        subscribe = $subscribe:expr,
        fetch = $fetch:expr,
        subscribe_namespace = $subscribe_namespace:expr,
        subscribe_ok = $subscribe_ok:expr,
        fetch_ok = $fetch_ok:expr,
        publish_done = $publish_done:expr,
        request_ok = $request_ok:expr,
        request_error = $request_error:expr,
        update = $update:expr,
        one_error_answers_every_update = $coalesces:expr,
    ) => {
        #[cfg(feature = $feat)]
        mod $module {
            #[allow(unused_imports)]
            use super::*;
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_codec::$draft::message::{ControlMessage, Setup};
            use moqtap_codec::varint::VarInt;

            fn varint(v: u64) -> VarInt {
                VarInt::from_u64(v).expect("a fixture id fits a varint")
            }

            fn ns(label: &[u8]) -> TrackNamespace {
                TrackNamespace(vec![label.to_vec()])
            }

            /// A server, so the peer's Request IDs are the even ones below.
            fn responder() -> Endpoint {
                let mut endpoint = Endpoint::new(Role::Server);
                endpoint.connect().expect("a server may open");
                endpoint.send_setup(vec![]).expect("its own SETUP");
                endpoint.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
                endpoint
            }

            /// The peer's SUBSCRIBE, and the stream it opens.
            fn peer_subscribe(endpoint: &mut Endpoint, id: u64) -> VarInt {
                let build: fn(VarInt) -> ControlMessage = $subscribe;
                endpoint
                    .receive_request_on_stream(&build(varint(id)))
                    .expect("the peer's SUBSCRIBE")
            }

            fn peer_fetch(endpoint: &mut Endpoint, id: u64) -> VarInt {
                let build: fn(VarInt) -> ControlMessage = $fetch;
                endpoint.receive_request_on_stream(&build(varint(id))).expect("the peer's FETCH")
            }

            fn peer_subscribe_namespace(endpoint: &mut Endpoint, id: u64) -> VarInt {
                let build: fn(VarInt) -> ControlMessage = $subscribe_namespace;
                endpoint
                    .receive_request_on_stream(&build(varint(id)))
                    .expect("the peer's SUBSCRIBE_NAMESPACE")
            }

            fn peer_update(endpoint: &mut Endpoint, id: VarInt) {
                let build: fn(VarInt) -> ControlMessage = $update;
                endpoint
                    .receive_on_peer_request_stream(id, build(id))
                    .expect("a REQUEST_UPDATE on its own request's stream");
            }

            fn subscribe_ok() -> ControlMessage {
                let build: fn() -> ControlMessage = $subscribe_ok;
                build()
            }

            fn fetch_ok() -> ControlMessage {
                let build: fn() -> ControlMessage = $fetch_ok;
                build()
            }

            fn publish_done() -> ControlMessage {
                let build: fn() -> ControlMessage = $publish_done;
                build()
            }

            /// The termination a refused update requires, which is the same
            /// message under the status that says why it is ending.
            fn update_failed_done() -> ControlMessage {
                match publish_done() {
                    ControlMessage::PublishDone(mut done) => {
                        done.status_code = varint(0x8);
                        ControlMessage::PublishDone(done)
                    }
                    other => other,
                }
            }

            fn request_ok() -> ControlMessage {
                let build: fn() -> ControlMessage = $request_ok;
                build()
            }

            fn request_error() -> ControlMessage {
                let build: fn() -> ControlMessage = $request_error;
                build()
            }

            /// A REQUEST_OK answers an update on a subscription's stream, and the
            /// subscription is untouched by it.
            ///
            /// The whole of what was missing: a SUBSCRIBE is answered with
            /// SUBSCRIBE_OK, so nothing in the responder's response path had a
            /// place for a REQUEST_OK on that stream and the answer the draft
            /// requires could not be written at all.
            ///
            /// The PUBLISH_DONE at the end is the half that says the update did
            /// not move the subscription: it is the transition out of Active, so
            /// it succeeds only if answering the update left the subscription
            /// there.
            ///
            /// # What it catches
            ///
            /// Ablation: dropping the `answers_an_update` branch from
            /// `send_response_on_stream`, which is what the endpoint did before:
            ///
            /// ```text
            /// the REQUEST_OK a REQUEST_UPDATE requires: Err(UnknownRequest(0))
            /// ```
            #[test]
            fn a_request_ok_answers_an_update_on_a_subscriptions_stream() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");
                peer_update(&mut endpoint, id);

                if let Err(e) = endpoint.send_response_on_stream(id, &request_ok()) {
                    panic!("the REQUEST_OK a REQUEST_UPDATE requires: Err({e:?})");
                }

                endpoint
                    .send_response_on_stream(id, &publish_done())
                    .expect("an update changes a request's parameters and not its lifecycle");
            }

            /// The same on a fetch's stream, which is answered with FETCH_OK.
            #[test]
            fn a_request_ok_answers_an_update_on_a_fetchs_stream() {
                let mut endpoint = responder();
                let id = peer_fetch(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &fetch_ok()).expect("the FETCH's own");
                peer_update(&mut endpoint, id);

                if let Err(e) = endpoint.send_response_on_stream(id, &request_ok()) {
                    panic!("the REQUEST_OK a REQUEST_UPDATE requires: Err({e:?})");
                }
            }

            /// A REQUEST_OK with no update waiting is refused.
            ///
            /// "exactly one REQUEST_OK or REQUEST_ERROR" is a count as well as a
            /// requirement. A second answer names an update the peer never sent,
            /// and the peer has no way to tell it is a mistake — it will read it
            /// as the answer to whichever update it thinks is outstanding.
            #[test]
            fn a_request_ok_with_no_update_waiting_is_refused() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");

                let result = endpoint.send_response_on_stream(id, &request_ok());
                assert!(
                    matches!(result, Err(EndpointError::NoUpdateToAnswer(got)) if got == id.into_inner()),
                    "a REQUEST_OK with nothing to answer: {result:?}",
                );
            }

            /// An update that arrives before the request's own answer is still
            /// answered, and the request's answer still goes out after it.
            ///
            /// Nothing orders the two: the draft puts an update on the stream
            /// "later" than the request, not later than its response. The
            /// REQUEST_OK is recognised as the update's answer with the FETCH
            /// still unanswered, because FETCH_OK is the only thing that answers
            /// a FETCH and a REQUEST_OK there can be nothing else.
            ///
            /// # What it catches
            ///
            /// Ablation: dropping the two-map branch from `answers_an_update`, so
            /// that the ordering rule is the only rule:
            ///
            /// ```text
            /// a REQUEST_OK on a FETCH stream answers the update: UnknownRequest(0)
            /// ```
            ///
            /// which is the endpoint claiming not to know a request it opened a
            /// stream for two calls earlier.
            #[test]
            fn an_update_before_the_requests_own_answer_is_still_answered() {
                let mut endpoint = responder();
                let id = peer_fetch(&mut endpoint, 0);
                peer_update(&mut endpoint, id);

                endpoint
                    .send_response_on_stream(id, &request_ok())
                    .expect("a REQUEST_OK on a FETCH stream answers the update");
                endpoint
                    .send_response_on_stream(id, &fetch_ok())
                    .expect("the FETCH is still waiting for its own answer");
            }

            /// The same on a subscription's stream, which is the case that also
            /// needs the subscription's own state machine to allow it.
            ///
            /// A SUBSCRIBE stream has the same freedom from ordering a FETCH
            /// stream does — SUBSCRIBE_OK is the only thing that answers a
            /// SUBSCRIBE — but a subscription has a lifecycle where a fetch has
            /// only an answer, and the update used to be refused for arriving
            /// while that lifecycle was still at Subscribing. The PUBLISH_DONE
            /// at the end says the update moved nothing: it is the transition
            /// out of Active, so it succeeds only if the update left the
            /// subscription to be accepted normally.
            ///
            /// # What it catches
            ///
            /// Ablation: `on_subscribe_update` restricted to `Active`, which is
            /// what the subscription machine shipped:
            ///
            /// ```text
            /// thread 'draft19::an_update_before_a_subscribes_own_answer_is_still_answered'
            /// panicked at crates\moqtap-client\tests\request_update_answers.rs:549:1:
            /// a REQUEST_UPDATE on its own request's stream: Subscription(InvalidTransition { from: Subscribing, event: "on_subscribe_update" })
            /// ```
            ///
            /// It fails on the update rather than on the answer: the endpoint
            /// refused the REQUEST_UPDATE on the way in, so there was never an
            /// answer to write.
            #[test]
            fn an_update_before_a_subscribes_own_answer_is_still_answered() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                peer_update(&mut endpoint, id);

                endpoint
                    .send_response_on_stream(id, &request_ok())
                    .expect("a REQUEST_OK on a SUBSCRIBE stream answers the update");
                endpoint
                    .send_response_on_stream(id, &subscribe_ok())
                    .expect("the SUBSCRIBE is still waiting for its own answer");
                endpoint
                    .send_response_on_stream(id, &publish_done())
                    .expect("an update changes a request's parameters and not its lifecycle");
            }

            /// A REQUEST_ERROR answers the request until the request has been
            /// answered, and answers updates after that.
            ///
            /// The message that cannot be resolved by kind. Both halves are
            /// driven, because an endpoint that read every REQUEST_ERROR as an
            /// update's answer would leave a refused request open, and one that
            /// read every REQUEST_ERROR as the request's would refuse a
            /// subscription that had already been accepted.
            #[test]
            fn a_request_error_answers_the_request_until_the_request_is_answered() {
                // Before: with an update already waiting, the REQUEST_ERROR is
                // still the FETCH's own refusal, and the update's answer comes
                // after it.
                let mut endpoint = responder();
                let id = peer_fetch(&mut endpoint, 0);
                peer_update(&mut endpoint, id);
                endpoint
                    .send_response_on_stream(id, &request_error())
                    .expect("the FETCH's own refusal");
                assert!(
                    endpoint.send_response_on_stream(id, &fetch_ok()).is_err(),
                    "a fetch refused on the way in cannot then be accepted",
                );
                endpoint
                    .send_response_on_stream(id, &request_ok())
                    .expect("the update is still waiting for an answer of its own");

                // After: the same message answers the update and leaves the
                // subscription where it was.
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");
                peer_update(&mut endpoint, id);
                endpoint
                    .send_response_on_stream(id, &request_error())
                    .expect("a refused update is not a refused subscription");
                // The refusal above is what makes the status here
                // load-bearing: Section 10.9 says a publisher that refuses an
                // update terminates the subscription "by sending a
                // PUBLISH_DONE with error code UPDATE_FAILED", so that is the
                // ending available to it. What this gate is about is that
                // there is still a subscription to end at all.
                endpoint
                    .send_response_on_stream(id, &update_failed_done())
                    .expect("the subscription is still the one that was accepted");
            }

            /// On a stream REQUEST_OK answers, the first one is the request's and
            /// the ones after it are updates'.
            ///
            /// The ordering rule, driven where it is the only rule available.
            /// Three REQUEST_OKs against one request and one update: the first two
            /// have something to answer and the third does not.
            ///
            /// # What it catches
            ///
            /// Ablation: dropping the `answers_an_update` branch, so that every
            /// REQUEST_OK is read as the request's own answer:
            ///
            /// ```text
            /// the second answers the update:
            /// Namespace(InvalidTransition { from: "Active", event: "on_subscribe_namespace_ok_sent" })
            /// ```
            ///
            /// The namespace subscription was accepted once and is being accepted
            /// again, which is a state machine reporting a message it has already
            /// seen rather than one it was never given a place for.
            #[test]
            fn the_first_request_ok_on_a_namespace_stream_answers_the_request() {
                let mut endpoint = responder();
                let id = peer_subscribe_namespace(&mut endpoint, 0);
                endpoint
                    .send_response_on_stream(id, &request_ok())
                    .expect("the SUBSCRIBE_NAMESPACE's own answer");

                peer_update(&mut endpoint, id);
                endpoint
                    .send_response_on_stream(id, &request_ok())
                    .expect("the second answers the update");

                let result = endpoint.send_response_on_stream(id, &request_ok());
                assert!(
                    matches!(result, Err(EndpointError::NoUpdateToAnswer(_))),
                    "the third has nothing left to answer: {result:?}",
                );
            }

            /// How many updates one REQUEST_ERROR answers, which is where the
            /// drafts part company.
            ///
            /// Two updates outstanding and one REQUEST_ERROR. On drafts 18 and 19
            /// it stands for both, so a REQUEST_OK after it has nothing to answer;
            /// on draft-17 it stands for one, so the REQUEST_OK answers the other.
            ///
            /// # What it catches
            ///
            /// Ablation: dropping the `answers_an_update` branch, so that the
            /// REQUEST_ERROR answering an update is read as the subscription's own
            /// refusal:
            ///
            /// ```text
            /// one REQUEST_ERROR for the updates:
            /// Subscription(InvalidTransition { from: Active, event: "on_subscribe_error_sent" })
            /// ```
            ///
            /// An endpoint whose machine did admit that edge would have refused a
            /// subscription it had already accepted, on a message that was about
            /// one of its parameters.
            #[test]
            fn how_many_updates_one_request_error_answers() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");
                peer_update(&mut endpoint, id);
                peer_update(&mut endpoint, id);

                endpoint
                    .send_response_on_stream(id, &request_error())
                    .expect("one REQUEST_ERROR for the updates");

                let result = endpoint.send_response_on_stream(id, &request_ok());
                if $coalesces {
                    assert!(
                        matches!(result, Err(EndpointError::NoUpdateToAnswer(_))),
                        "a coalesced REQUEST_ERROR stood for both updates: {result:?}",
                    );
                } else {
                    result.expect("one message answers one update, so the second is still waiting");
                }
            }
            /// A refused update forces the status of the ending.
            ///
            /// Section 10.9 on drafts 18 and 19, Section 9.11 on draft-17: the
            /// publisher that refuses an update terminates the subscription
            /// with a PUBLISH_DONE carrying UPDATE_FAILED. The ending is
            /// therefore not free once a refusal has gone out.
            ///
            /// # What it catches
            ///
            /// Refusing an update and recording nothing, which is what all three
            /// drafts did:
            ///
            /// ```text
            /// the ending after a refused update carries UPDATE_FAILED and no other
            /// status, and instead: Ok(())
            /// ```
            ///
            /// It reddens three, this gate on all three drafts and nothing else.
            ///
            /// Taking whatever status the ending carries, so the obligation is
            /// remembered and then not enforced:
            ///
            /// ```text
            /// the ending after a refused update carries UPDATE_FAILED and no other
            /// status, and instead: Ok(())
            /// ```
            ///
            /// It reddens three, this gate on all three drafts and nothing else.
            /// The cut above leaves the obligation unrecorded and this one leaves
            /// it unenforced, and each fails at a different assertion in the same
            /// gate.
            #[test]
            fn a_refused_update_forces_the_status_of_the_ending() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");
                peer_update(&mut endpoint, id);
                endpoint
                    .send_response_on_stream(id, &request_error())
                    .expect("the update is refused");

                let wrong = endpoint.send_response_on_stream(id, &publish_done());
                assert!(
                    matches!(
                        wrong,
                        Err(EndpointError::WrongUpdateFailureStatus { required: 0x8, .. })
                    ),
                    "the ending after a refused update carries UPDATE_FAILED and no other \
                     status, and instead: {wrong:?}"
                );

                endpoint
                    .send_response_on_stream(id, &update_failed_done())
                    .expect("the ending the sentence names is the one that goes through");
            }

            /// The obligation is over once the ending is written.
            ///
            /// Without this the rule would hold a request to UPDATE_FAILED for
            /// the rest of the session, and a second ending would be refused
            /// for the wrong reason.
            ///
            /// # What it catches
            ///
            /// Never clearing the obligation, so a request whose update was refused
            /// is held to UPDATE_FAILED for the rest of the session:
            ///
            /// ```text
            /// the obligation was discharged and is not held open:
            /// Err(WrongUpdateFailureStatus { request: 0, required: 8 })
            /// ```
            ///
            /// It reddens three, this gate on all three drafts and nothing else.
            #[test]
            fn the_obligation_ends_when_the_ending_is_written() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");
                peer_update(&mut endpoint, id);
                endpoint
                    .send_response_on_stream(id, &request_error())
                    .expect("the update is refused");
                endpoint
                    .send_response_on_stream(id, &update_failed_done())
                    .expect("the ending the sentence names");

                let again = endpoint.send_response_on_stream(id, &publish_done());
                assert!(
                    !matches!(again, Err(EndpointError::WrongUpdateFailureStatus { .. })),
                    "the obligation was discharged and is not held open: {again:?}"
                );
            }

            /// An update this endpoint accepted leaves the ending alone.
            ///
            /// The sentence is about an *unsuccessful* update, and this is the
            /// half of it that says so.
            ///
            /// # What it catches
            ///
            /// Creating the obligation on an accepted update as well as a refused
            /// one, which is the sentence read without the word "unsuccessful":
            ///
            /// ```text
            /// an accepted update owes the peer no particular ending:
            /// WrongUpdateFailureStatus { request: 0, required: 8 }
            /// ```
            ///
            /// It reddens nine: this gate on all three drafts, and two gates about
            /// answering an update at all on the same three, which end their
            /// subscription afterwards and would now be held to a status they have
            /// no reason to carry.
            #[test]
            fn an_accepted_update_leaves_the_ending_alone() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");
                peer_update(&mut endpoint, id);
                endpoint
                    .send_response_on_stream(id, &request_ok())
                    .expect("the update is accepted");

                endpoint
                    .send_response_on_stream(id, &publish_done())
                    .expect("an accepted update owes the peer no particular ending");
            }

            /// A subscription no update was sent for ends however it likes.
            ///
            /// The control for the two above: a rule that fired on every
            /// REQUEST_ERROR rather than on an update's would pass both of
            /// them and fail here.
            ///
            /// # What it catches
            ///
            /// Nothing the four cuts reach, which is what a control is. Every
            /// one of the four cuts leaves it green, because none of them
            /// reaches a request no update was ever sent for. It is here
            /// so that a rule firing on every REQUEST_ERROR rather than on
            /// an update's would have somewhere to fail.
            #[test]
            fn a_subscription_with_no_update_ends_however_it_likes() {
                let mut endpoint = responder();
                let id = peer_subscribe(&mut endpoint, 0);
                endpoint.send_response_on_stream(id, &subscribe_ok()).expect("the SUBSCRIBE's own");

                endpoint
                    .send_response_on_stream(id, &publish_done())
                    .expect("nothing was refused, so nothing is owed");
            }
        }
    };
}

request_update_answer_gates!(
    draft17,
    "draft17",
    draft17,
    subscribe = |id| ControlMessage::Subscribe(moqtap_codec::draft17::message::Subscribe {
        request_id: id,
        required_request_id_delta: varint(0),
        track_namespace: ns(b"live"),
        track_name: b"video".to_vec(),
        parameters: vec![],
    }),
    fetch = |id| ControlMessage::Fetch(moqtap_codec::draft17::message::Fetch {
        request_id: id,
        required_request_id_delta: varint(0),
        fetch_type: moqtap_codec::draft17::message::FetchType::Standalone,
        fetch_payload: moqtap_codec::draft17::message::FetchPayload::Standalone {
            track_namespace: ns(b"live"),
            track_name: b"video".to_vec(),
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(1),
            end_object: varint(0),
        },
        parameters: vec![],
    }),
    subscribe_namespace = |id| ControlMessage::SubscribeNamespace(
        moqtap_codec::draft17::message::SubscribeNamespace {
            request_id: id,
            required_request_id_delta: varint(0),
            namespace_prefix: ns(b"live"),
            subscribe_options: varint(0),
            parameters: vec![],
        }
    ),
    subscribe_ok = || ControlMessage::SubscribeOk(moqtap_codec::draft17::message::SubscribeOk {
        track_alias: varint(4),
        parameters: vec![],
        track_properties: vec![],
    }),
    fetch_ok = || ControlMessage::FetchOk(moqtap_codec::draft17::message::FetchOk {
        end_of_track: 0,
        end_group: varint(1),
        end_object: varint(0),
        parameters: vec![],
        track_properties: vec![],
    }),
    publish_done = || ControlMessage::PublishDone(moqtap_codec::draft17::message::PublishDone {
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: b"done".to_vec(),
    }),
    request_ok = || ControlMessage::RequestOk(moqtap_codec::draft17::message::RequestOk {
        parameters: vec![]
    }),
    request_error = || ControlMessage::RequestError(moqtap_codec::draft17::message::RequestError {
        error_code: varint(0x1),
        retry_interval: varint(0),
        reason_phrase: b"no".to_vec(),
    }),
    update = |id| ControlMessage::RequestUpdate(moqtap_codec::draft17::message::RequestUpdate {
        request_id: id,
        required_request_id_delta: varint(0),
        parameters: vec![],
    }),
    one_error_answers_every_update = false,
);

request_update_answer_gates!(
    draft18,
    "draft18",
    draft18,
    subscribe = |id| ControlMessage::Subscribe(moqtap_codec::draft18::message::Subscribe {
        request_id: id,
        track_namespace: ns(b"live"),
        track_name: b"video".to_vec(),
        parameters: vec![],
    }),
    fetch = |id| ControlMessage::Fetch(moqtap_codec::draft18::message::Fetch {
        request_id: id,
        fetch_type: moqtap_codec::draft18::message::FetchType::Standalone,
        fetch_payload: moqtap_codec::draft18::message::FetchPayload::Standalone {
            track_namespace: ns(b"live"),
            track_name: b"video".to_vec(),
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(1),
            end_object: varint(0),
        },
        parameters: vec![],
    }),
    subscribe_namespace = |id| ControlMessage::SubscribeNamespace(
        moqtap_codec::draft18::message::SubscribeNamespace {
            request_id: id,
            namespace_prefix: ns(b"live"),
            parameters: vec![],
        }
    ),
    subscribe_ok = || ControlMessage::SubscribeOk(moqtap_codec::draft18::message::SubscribeOk {
        track_alias: varint(4),
        parameters: vec![],
        track_properties: vec![],
    }),
    fetch_ok = || ControlMessage::FetchOk(moqtap_codec::draft18::message::FetchOk {
        end_of_track: 0,
        end_group: varint(1),
        end_object: varint(0),
        parameters: vec![],
        track_properties: vec![],
    }),
    publish_done = || ControlMessage::PublishDone(moqtap_codec::draft18::message::PublishDone {
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: b"done".to_vec(),
    }),
    request_ok = || ControlMessage::RequestOk(moqtap_codec::draft18::message::RequestOk {
        parameters: vec![],
        track_properties: vec![],
    }),
    request_error = || ControlMessage::RequestError(moqtap_codec::draft18::message::RequestError {
        error_code: varint(0x1),
        retry_interval: varint(0),
        reason_phrase: b"no".to_vec(),
        redirect: None,
    }),
    update = |id| ControlMessage::RequestUpdate(moqtap_codec::draft18::message::RequestUpdate {
        request_id: id,
        parameters: vec![],
    }),
    one_error_answers_every_update = true,
);

request_update_answer_gates!(
    draft19,
    "draft19",
    draft19,
    subscribe = |id| ControlMessage::Subscribe(moqtap_codec::draft19::message::Subscribe {
        request_id: id,
        track_namespace: ns(b"live"),
        track_name: b"video".to_vec(),
        parameters: vec![],
    }),
    fetch = |id| ControlMessage::Fetch(moqtap_codec::draft19::message::Fetch {
        request_id: id,
        fetch_type: moqtap_codec::draft19::message::FetchType::Standalone,
        fetch_payload: moqtap_codec::draft19::message::FetchPayload::Standalone {
            track_namespace: ns(b"live"),
            track_name: b"video".to_vec(),
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(1),
            end_object: varint(0),
        },
        parameters: vec![],
    }),
    subscribe_namespace = |id| ControlMessage::SubscribeNamespace(
        moqtap_codec::draft19::message::SubscribeNamespace {
            request_id: id,
            namespace_prefix: ns(b"live"),
            parameters: vec![],
        }
    ),
    subscribe_ok = || ControlMessage::SubscribeOk(moqtap_codec::draft19::message::SubscribeOk {
        track_alias: varint(4),
        parameters: vec![],
        track_properties: vec![],
    }),
    fetch_ok = || ControlMessage::FetchOk(moqtap_codec::draft19::message::FetchOk {
        end_of_track: 0,
        end_group: varint(1),
        end_object: varint(0),
        parameters: vec![],
        track_properties: vec![],
    }),
    publish_done = || ControlMessage::PublishDone(moqtap_codec::draft19::message::PublishDone {
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: b"done".to_vec(),
    }),
    request_ok = || ControlMessage::RequestOk(moqtap_codec::draft19::message::RequestOk {
        parameters: vec![],
        track_properties: vec![],
    }),
    request_error = || ControlMessage::RequestError(moqtap_codec::draft19::message::RequestError {
        error_code: varint(0x1),
        retry_interval: varint(0),
        reason_phrase: b"no".to_vec(),
        redirect: None,
    }),
    update = |id| ControlMessage::RequestUpdate(moqtap_codec::draft19::message::RequestUpdate {
        request_id: id,
        parameters: vec![],
    }),
    one_error_answers_every_update = true,
);

/// A SUBSCRIBE_TRACKS may be updated on draft-18, which is the draft that added
/// it.
///
/// Section 10.9's list of the requests an update may modify grew by one between
/// draft-17 and draft-18: "SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
/// SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS". The endpoint probed every other kind
/// and not that one, so a conforming subscriber updating a SUBSCRIBE_TRACKS was
/// told the crate did not know the request — a refusal of traffic the draft
/// permits, which is the same shape as the gap this file's other gates close.
///
/// It sits outside the macro above because draft-17 has no such message and
/// draft-19, which does, already probed for it.
///
/// # What it catches
///
/// Ablation: dropping the `subscribe_tracks` probe from
/// `receive_request_update`:
///
/// ```text
/// a SUBSCRIBE_TRACKS is one of the requests Section 10.9 allows an update to:
/// UnknownRequest(0)
/// ```
#[cfg(feature = "draft18")]
#[test]
fn a_subscribe_tracks_may_be_updated_on_draft18() {
    use moqtap_client::draft18::endpoint::Endpoint;
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_codec::draft18::message::{
        ControlMessage, RequestOk, RequestUpdate, Setup, SubscribeTracks,
    };
    use moqtap_codec::varint::VarInt;

    let id = VarInt::from_u64(0).expect("a fixture id fits a varint");
    let mut endpoint = Endpoint::new(Role::Server);
    endpoint.connect().expect("a server may open");
    endpoint.send_setup(vec![]).expect("its own SETUP");
    endpoint.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");

    endpoint
        .receive_request_on_stream(&ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: id,
            namespace_prefix: TrackNamespace(vec![b"live".to_vec()]),
            parameters: vec![],
        }))
        .expect("the peer's SUBSCRIBE_TRACKS");

    let update =
        ControlMessage::RequestUpdate(RequestUpdate { request_id: id, parameters: vec![] });
    if let Err(e) = endpoint.receive_on_peer_request_stream(id, update) {
        panic!("a SUBSCRIBE_TRACKS is one of the requests Section 10.9 allows an update to: {e:?}");
    }

    // And the answer it requires goes out, which is the rule the rest of this
    // file is about: the first REQUEST_OK answers the request, the second the
    // update.
    let request_ok =
        || ControlMessage::RequestOk(RequestOk { parameters: vec![], track_properties: vec![] });
    endpoint.send_response_on_stream(id, &request_ok()).expect("the request's own answer");
    endpoint.send_response_on_stream(id, &request_ok()).expect("the update's answer");
}

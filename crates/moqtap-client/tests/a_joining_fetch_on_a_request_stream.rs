#![cfg(all(feature = "draft17", feature = "draft18", feature = "draft19"))]

//! A Joining Fetch names a subscription this session has, on the three drafts
//! that carry a request on a stream of its own.
//!
//! Draft-17 Section 9.14.2, draft-18 and draft-19 Section 10.12.2, in the same
//! words: "If a publisher receives a Joining Fetch with a Request ID that does
//! not correspond to a subscription in the same session in the Established or
//! Pending (subscriber) states, it MUST return a REQUEST_ERROR with error code
//! INVALID_JOINING_REQUEST_ID."
//!
//! These three already had the record: a FETCH arriving on a request stream
//! opens a fetch in the same map that holds this endpoint's own, because the
//! parity rule keeps the identifiers apart. What they had no check for is the
//! identifier the Joining Fetch names, so a fetch joining nothing was answered
//! FETCH_OK and the objects it asked for could not be found.
//!
//! The same rule on drafts 08 through 16 is in
//! `a_joining_fetch_names_a_live_subscription.rs`, which is where the range
//! and the wording changes across it are written out.
//!
//! # Either message can establish what is joined
//!
//! Section 5.1 on all three: the Largest Location a Joining FETCH works from
//! is the one saved "in PUBLISH or SUBSCRIBE_OK when establishing a
//! subscription". So a subscription this endpoint opened with PUBLISH is
//! joinable, and there is a gate for it below.
//!
//! # Why the verdict is taken when the FETCH arrives
//!
//! "If a publisher **receives** a Joining Fetch ..." names the moment. A
//! subscription that ends between the FETCH arriving and its answer going out
//! does not turn a fetch that could be joined into one that could not.
//!
//! # Ablations, measured
//!
//! Six cuts reach this file, each recorded on the gate it belongs to. They are
//! the same cuts `a_joining_fetch_names_a_live_subscription.rs` records,
//! because the rule is one rule. The fifth gate here is the exception and says
//! so: nothing on these three drafts can be cut to redden it.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn track() -> Vec<u8> {
    b"video".to_vec()
}

fn other_track() -> Vec<u8> {
    b"audio".to_vec()
}

/// The peer's FETCH, which draft-17 gives an extra field the others dropped.
#[macro_export]
macro_rules! peers_fetch {
    (delta, $id:expr, $payload:expr) => {
        Fetch {
            request_id: v($id),
            required_request_id_delta: v(0),
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: $payload,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $payload:expr) => {
        Fetch {
            request_id: v($id),
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: $payload,
            parameters: Vec::new(),
        }
    };
    (delta_standalone, $id:expr, $payload:expr) => {
        Fetch {
            request_id: v($id),
            required_request_id_delta: v(0),
            fetch_type: FetchType::Standalone,
            fetch_payload: $payload,
            parameters: Vec::new(),
        }
    };
    (plain_standalone, $id:expr, $payload:expr) => {
        Fetch {
            request_id: v($id),
            fetch_type: FetchType::Standalone,
            fetch_payload: $payload,
            parameters: Vec::new(),
        }
    };
}

/// The peer's SUBSCRIBE, which draft-17 gives the same extra field its FETCH
/// has.
#[macro_export]
macro_rules! peers_subscribe {
    (delta, $id:expr, $ns:expr, $track:expr) => {
        Subscribe {
            request_id: $id,
            required_request_id_delta: VarInt::from_u64(0).unwrap(),
            track_namespace: $ns,
            track_name: $track,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $ns:expr, $track:expr) => {
        Subscribe {
            request_id: $id,
            track_namespace: $ns,
            track_name: $track,
            parameters: Vec::new(),
        }
    };
}

/// The message the peer answers a PUBLISH with, which draft-18 folded into
/// REQUEST_OK.
#[macro_export]
macro_rules! peer_accepts_publish {
    (publish_ok) => {
        ControlMessage::PublishOk(PublishOk { parameters: Vec::new() })
    };
    (request_ok) => {
        ControlMessage::RequestOk(RequestOk {
            parameters: Vec::new(),
            track_properties: Vec::new(),
        })
    };
}

/// The refusal, which draft-18 gave a redirect to.
#[macro_export]
macro_rules! we_refuse {
    (plain, $code:expr) => {
        ControlMessage::RequestError(RequestError {
            error_code: v($code),
            retry_interval: v(0),
            reason_phrase: Vec::new(),
        })
    };
    (redirect, $code:expr) => {
        ControlMessage::RequestError(RequestError {
            error_code: v($code),
            retry_interval: v(0),
            reason_phrase: Vec::new(),
            redirect: None,
        })
    };
}

/// One draft's eight gates.
macro_rules! joining_stream_gates {
    ($draft:ident, $fetchmsg:tt, $alone:tt, $pubok:tt, $error:tt, $sec:literal) => {
        mod $draft {
            use super::{ns, other_track, track};
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::varint::VarInt;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::{
                ControlMessage, Fetch, FetchPayload, FetchType, PublishDone, RequestError,
                RequestOk, Setup, Subscribe, SubscribeOk,
            };

            /// The code the section names for this refusal.
            const NAMED: u64 = 0x32;

            /// A code the drafts use for other refusals of a fetch.
            const INTERNAL_ERROR: u64 = 0x0;

            /// An identifier no request of the peer's ever arrived under.
            const NEVER_USED: u64 = 8;

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).expect("a fixture value fits a varint")
            }

            /// A server, so the peer's Request IDs are the even ones and this
            /// endpoint's own are the odd ones.
            fn responder() -> Endpoint {
                let mut ep = Endpoint::new(Role::Server);
                ep.connect().expect("a server may open");
                ep.send_setup(vec![]).expect("its own SETUP");
                ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
                ep
            }

            fn peers_subscribe(id: u64) -> ControlMessage {
                ControlMessage::Subscribe(crate::peers_subscribe!($fetchmsg, v(id), ns(), track()))
            }

            fn subscribe_ok() -> ControlMessage {
                ControlMessage::SubscribeOk(SubscribeOk {
                    track_alias: v(1),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                })
            }

            fn fetch_ok() -> ControlMessage {
                ControlMessage::FetchOk(FetchOk {
                    end_of_track: 0,
                    end_group: v(1),
                    end_object: v(0),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                })
            }

            fn joins(id: u64) -> FetchPayload {
                FetchPayload::Joining { joining_request_id: v(id), joining_start: v(0) }
            }

            fn standalone() -> FetchPayload {
                FetchPayload::Standalone {
                    track_namespace: ns(),
                    track_name: other_track(),
                    start_group: v(0),
                    start_object: v(0),
                    end_group: v(1),
                    end_object: v(0),
                }
            }

            /// An endpoint publishing a track the peer subscribed to on a
            /// request stream of its own.
            fn publishing() -> (Endpoint, VarInt) {
                let mut ep = responder();
                let sub = ep
                    .receive_request_on_stream(&peers_subscribe(0))
                    .expect("the peer's SUBSCRIBE opens a request stream");
                ep.send_response_on_stream(sub, &subscribe_ok()).expect("accept the subscription");
                (ep, sub)
            }

            /// The peer's Joining Fetch, delivered on its own stream.
            fn joining(ep: &mut Endpoint, id: u64, names: u64) -> VarInt {
                ep.receive_request_on_stream(&ControlMessage::Fetch(crate::peers_fetch!(
                    $fetchmsg,
                    id,
                    joins(names)
                )))
                .expect("the peer's Joining Fetch opens a request stream")
            }

            /// The session is still running: this rule names a message to send
            /// back, not a session to end.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} answers this with a refusal, so the session goes on",
                    $sec
                );
            }

            /// A Joining Fetch naming a live subscription of the peer's is
            /// answered like any other.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a Joining Fetch naming a live subscription is answerable: UnjoinableSubscription { fetch: 2, joining: 0 }
            /// ```
            ///
            /// Made by judging every fetch unjoinable, standalone ones included, on
            /// every draft that states the rule.
            #[test]
            fn a_joining_fetch_naming_a_live_subscription_is_accepted() {
                let (mut ep, sub) = publishing();
                let id = joining(&mut ep, 2, sub.into_inner());
                ep.send_response_on_stream(id, &fetch_ok())
                    .expect("a Joining Fetch naming a live subscription is answerable");
            }

            /// A Joining Fetch naming nothing this session has cannot be
            /// accepted.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a Joining Fetch naming nothing was accepted: ()
            /// ```
            ///
            /// Made by taking the verdict and not acting on it. It reddens twenty-four
            /// tests: this gate and the ended-subscription one, on all twelve drafts
            /// that state the rule.
            #[test]
            fn a_joining_fetch_naming_nothing_is_refused() {
                let (mut ep, _) = publishing();
                let id = joining(&mut ep, 2, NEVER_USED);
                let err = ep
                    .send_response_on_stream(id, &fetch_ok())
                    .expect_err("a Joining Fetch naming nothing was accepted");
                assert!(
                    matches!(
                        err,
                        EndpointError::UnjoinableSubscription { fetch: 2, joining: NEVER_USED }
                    ),
                    "the refusal should name the fetch and what it asked to join; got {err:?}"
                );
                still_running(&ep);
            }

            /// A Joining Fetch naming a subscription that has already ended
            /// cannot be accepted either.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a Joining Fetch naming an ended subscription was accepted: ()
            /// ```
            ///
            /// Made by reading a subscription as live whenever its record exists. It
            /// reddens twelve tests and only this gate.
            #[test]
            fn a_joining_fetch_naming_an_ended_subscription_is_refused() {
                let (mut ep, sub) = publishing();
                ep.send_response_on_stream(
                    sub,
                    &ControlMessage::PublishDone(PublishDone {
                        status_code: v(0),
                        stream_count: v(0),
                        reason_phrase: Vec::new(),
                    }),
                )
                .expect("this endpoint ends the subscription");
                let id = joining(&mut ep, 2, sub.into_inner());
                let err = ep
                    .send_response_on_stream(id, &fetch_ok())
                    .expect_err("a Joining Fetch naming an ended subscription was accepted");
                assert!(
                    matches!(err, EndpointError::UnjoinableSubscription { fetch: 2, joining: 0 }),
                    "the refusal should name the fetch and what it asked to join; got {err:?}"
                );
                still_running(&ep);
            }

            /// A standalone FETCH joins nothing, so no subscription has to
            /// exist for it.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a standalone fetch names no subscription to join: UnjoinableSubscription { fetch: 0, joining: 0 }
            /// ```
            ///
            /// The same cut as the first gate, and this is the half of it that says
            /// the rule is about Joining Fetches and not about fetches.
            #[test]
            fn a_standalone_fetch_needs_no_subscription() {
                let mut ep = responder();
                let id = ep
                    .receive_request_on_stream(&ControlMessage::Fetch(crate::peers_fetch!(
                        $alone,
                        0,
                        standalone()
                    )))
                    .expect("the peer's standalone FETCH");
                ep.send_response_on_stream(id, &fetch_ok())
                    .expect("a standalone fetch names no subscription to join");
            }

            /// The verdict is taken when the FETCH arrives, not when it is
            /// answered.
            ///
            /// # What no cut here catches, and why
            ///
            /// Nothing on these three drafts can be cut to redden this gate.
            /// The verdict is taken as the FETCH arrives and there is no
            /// second place that could take it again: the message itself is
            /// not kept, so re-judging it at answer time is not a change that
            /// can be written. The sibling of this gate in
            /// `a_joining_fetch_names_a_live_subscription.rs` does have that
            /// cut, on the nine drafts that keep the FETCH, and carries the
            /// message it produced.
            #[test]
            fn a_subscription_that_ends_after_the_fetch_does_not_unmake_it() {
                let (mut ep, sub) = publishing();
                let id = joining(&mut ep, 2, sub.into_inner());
                ep.send_response_on_stream(
                    sub,
                    &ControlMessage::PublishDone(PublishDone {
                        status_code: v(0),
                        stream_count: v(0),
                        reason_phrase: Vec::new(),
                    }),
                )
                .expect("this endpoint ends the subscription the fetch joined");
                ep.send_response_on_stream(id, &fetch_ok()).expect(
                    "the subscription was live when the FETCH arrived, which is the moment \
                     the rule reads",
                );
            }

            /// The refusal the section names can be sent.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the code the section names should send the refusal: WrongJoiningRefusal { fetch: 2, required: 0 }
            /// ```
            ///
            /// Made by requiring the internal-error code instead of the one the
            /// section names.
            #[test]
            fn the_refusal_carries_the_code_the_section_names() {
                let (mut ep, _) = publishing();
                let id = joining(&mut ep, 2, NEVER_USED);
                ep.send_response_on_stream(id, &crate::we_refuse!($error, NAMED))
                    .expect("the code the section names should send the refusal");
                still_running(&ep);
            }

            /// It cannot be sent under any other code.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the refusal went out under a code the section does not name: ()
            /// ```
            ///
            /// Made by dropping the guard entirely. It reddens nine tests and only
            /// this gate, on the nine drafts that name a code.
            #[test]
            fn the_refusal_cannot_carry_another_code() {
                let (mut ep, _) = publishing();
                let id = joining(&mut ep, 2, NEVER_USED);
                let err = ep
                    .send_response_on_stream(id, &crate::we_refuse!($error, INTERNAL_ERROR))
                    .expect_err("the refusal went out under a code the section does not name");
                assert!(
                    matches!(err, EndpointError::WrongJoiningRefusal { fetch: 2, required: NAMED }),
                    "the refusal should name the code Section {} requires; got {err:?}",
                    $sec
                );
                still_running(&ep);
            }

            /// A subscription this endpoint established with PUBLISH can be
            /// joined.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// Section 5.1 saves the Largest Location from PUBLISH as well as SUBSCRIBE_OK, so a subscription a PUBLISH established can be joined: UnjoinableSubscription { fetch: 0, joining: 1 }
            /// ```
            ///
            /// Made by dropping the `publishes` half of the probe. It reddens five
            /// tests and only this gate.
            #[test]
            fn a_subscription_a_publish_established_can_be_joined() {
                let mut ep = responder();
                let (published, _) = ep
                    .publish(ns(), other_track(), v(11), Vec::new(), Vec::new())
                    .expect("this endpoint offers a track");
                ep.receive_response_on_stream(published, crate::peer_accepts_publish!($pubok))
                    .expect("the peer accepts the publication");
                let id = joining(&mut ep, 0, published.into_inner());
                ep.send_response_on_stream(id, &fetch_ok()).expect(
                    "Section 5.1 saves the Largest Location from PUBLISH as well as \
                     SUBSCRIBE_OK, so a subscription a PUBLISH established can be joined",
                );
            }
        }
    };
}

joining_stream_gates!(draft17, delta, delta_standalone, publish_ok, plain, "9.14.2");
joining_stream_gates!(draft18, plain, plain_standalone, request_ok, redirect, "10.12.2");
joining_stream_gates!(draft19, plain, plain_standalone, request_ok, redirect, "10.12.2");

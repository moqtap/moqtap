#![cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]

//! A REQUEST_UPDATE can move a namespace subscription's prefix, and the prefix
//! it moves to is judged before the move is allowed.
//!
//! Drafts 18 and 19 give a request one field it may change that no earlier
//! draft does. Draft-18 Section 10.2.14 and draft-19 Section 10.2.19 define the
//! parameter: "The TRACK_NAMESPACE_PREFIX parameter (Parameter Type 0x34) uses
//! the Track Namespace encoding described in Section 2.4.1. It MAY appear in
//! REQUEST_UPDATE for a SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS request. It
//! updates the Track Namespace Prefix for that subscription. If the new prefix
//! would share a common prefix with another active subscription of the same
//! type in the same session, the receiver MUST respond with REQUEST_ERROR with
//! error code PREFIX_OVERLAP."
//!
//! Section 10.9.2 says it a second time and adds three things the parameter's
//! own section leaves out. "A subscriber can update the Track Namespace
//! Prefix of an established SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS by
//! including the TRACK_NAMESPACE_PREFIX parameter", it says, naming the
//! section above, "in a REQUEST_UPDATE. The overlap restriction applies
//! independently per type: the new prefix MUST NOT share a common prefix with
//! any other active SUBSCRIBE_NAMESPACE (for a SUBSCRIBE_NAMESPACE update) or
//! SUBSCRIBE_TRACKS (for a SUBSCRIBE_TRACKS update) in the same session. If
//! the update is accepted, NAMESPACE and NAMESPACE_DONE messages following
//! the REQUEST_OK will contain Track Namespace suffixes relative to the
//! updated prefix. Updating the prefix of a SUBSCRIBE_TRACKS has no effect on
//! existing subscriptions."
//!
//! This is the third statement of the overlap rule on these two drafts. The
//! other two are about a request arriving and are gated in
//! `overlapping_namespace_subscriptions_are_refused.rs`; this file is the one
//! about a request that has already been accepted moving.
//!
//! # What the word "another" decides
//!
//! A subscription being moved is itself active, and its own prefix is still on
//! record while its update is unanswered. Weighing the new prefix against every
//! active subscription including itself would refuse every narrowing and every
//! widening -- moving from `conformance/alpha` to `conformance` overlaps
//! `conformance/alpha`, which is the subscription doing the moving. "Another"
//! is what takes it out of the comparison, and it is the only word in the
//! sentence that does.
//!
//! # When the prefix actually moves
//!
//! On the acceptance. "If the update is accepted, NAMESPACE and NAMESPACE_DONE
//! messages following the REQUEST_OK will contain Track Namespace suffixes
//! relative to the updated prefix" puts the effect after the REQUEST_OK, so an
//! unanswered update changes nothing: a request arriving while one is in flight
//! is weighed against the prefix the peer opened the subscription with, which
//! is the one still selecting namespaces. A REQUEST_ERROR drops the move.
//!
//! Nothing is recomputed when ground comes free. A subscription this endpoint
//! has already decided to refuse keeps that verdict even if the prefix that
//! blocked it moves away, because the sentence that refused it names the moment
//! it arrived and that moment has passed.
//!
//! # Why draft-17 is not here
//!
//! It has REQUEST_UPDATE and it has the overlap rule, and it does not have this
//! parameter: `TRACK_NAMESPACE_PREFIX` and `0x34` as a Parameter Type match
//! nothing in draft-17. Nothing before draft-18 lets a request change its
//! prefix at all, so on the other eleven drafts there is no third statement to
//! enforce.
//!
//! # What this endpoint cannot do
//!
//! Send one. Neither draft carries an outbound REQUEST_UPDATE builder, so the
//! only updates this crate sees are the peer's. That settles what would
//! otherwise be an open question -- whether an update to a request **this**
//! endpoint made needs the same judgement -- the same way drafts 18 and 19
//! settle the subscriber's half of the arrival rule, which is by not stating
//! it.
//!
//! # Ablations, measured
//!
//! Eleven cuts were made, run against the two crates a change to
//! `moqtap-client` can reach, and reverted. Each gate records the ones that
//! redden it under `# What it catches`, with the failure the run actually
//! produced.

#![allow(clippy::items_after_test_module)]

use bytes::BufMut;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::{Moqt18, VarInt};

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// The prefix a subscription is opened under.
fn under() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"alpha".to_vec()])
}

/// A second prefix beneath the same first element, which [`under`] neither
/// prefixes nor is prefixed by: the two select disjoint sets of namespaces.
fn sibling() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"beta".to_vec()])
}

/// The prefix both of the above sit under, so it overlaps each of them.
fn root() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A prefix sharing no element with any of the others.
fn elsewhere() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

/// A TRACK_NAMESPACE_PREFIX parameter carrying `ns`.
///
/// Encoded by the same code that decodes it, so a gate that fails fails for the
/// reason it is about rather than because a hand-written Track Namespace was
/// spelled wrongly.
fn prefix_param(ns: &TrackNamespace) -> KeyValuePair {
    let mut bytes = Vec::new();
    ns.encode_moqt::<Moqt18>(&mut bytes);
    KeyValuePair { key: v(0x34), value: KvpValue::Bytes(bytes) }
}

/// The same parameter with one byte too many, so its value is a whole Track
/// Namespace followed by a byte that is not part of one.
fn overlong_prefix_param(ns: &TrackNamespace) -> KeyValuePair {
    let KvpValue::Bytes(mut bytes) = prefix_param(ns).value else { unreachable!() };
    bytes.put_u8(0x01);
    KeyValuePair { key: v(0x34), value: KvpValue::Bytes(bytes) }
}

/// The code Section 10.6.2 registers for this refusal.
const PREFIX_OVERLAP: u64 = 0x30;

/// One draft's gates. Drafts 18 and 19 carry the parameter, the rule and every
/// message shape this file touches identically; only the section the parameter
/// is defined in moved.
macro_rules! gates {
    ($draft:ident, $feat:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_codec::kvp::KeyValuePair;
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::$draft::message::*;

            /// The Request IDs the peer opens its requests under. This endpoint
            /// is the server, so the peer's are the even ones.
            const FIRST: u64 = 0;
            const SECOND: u64 = 2;
            const THIRD: u64 = 4;

            /// An endpoint past setup, answering what the peer opens.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Server);
                ep.connect().expect("an endpoint may open");
                ep.send_setup(Vec::new()).expect("SETUP");
                ep.receive_setup(&Setup { options: Vec::new() }).expect("the peer's SETUP");
                ep
            }

            /// The peer's SUBSCRIBE_NAMESPACE arrives at `prefix` under `id`.
            fn namespace_arrives(ep: &mut Endpoint, id: u64, prefix: TrackNamespace) {
                ep.receive_request_on_stream(&ControlMessage::SubscribeNamespace(
                    SubscribeNamespace {
                        request_id: crate::v(id),
                        namespace_prefix: prefix,
                        parameters: Vec::new(),
                    },
                ))
                .expect("the peer may open a namespace subscription");
            }

            /// The peer's SUBSCRIBE_TRACKS arrives at `prefix` under `id`.
            fn tracks_arrives(ep: &mut Endpoint, id: u64, prefix: TrackNamespace) {
                ep.receive_request_on_stream(&ControlMessage::SubscribeTracks(SubscribeTracks {
                    request_id: crate::v(id),
                    namespace_prefix: prefix,
                    parameters: Vec::new(),
                }))
                .expect("the peer may subscribe to tracks under a prefix");
            }

            /// The same, accepted, so the subscription is established.
            fn namespace_open(ep: &mut Endpoint, id: u64, prefix: TrackNamespace) {
                namespace_arrives(ep, id, prefix);
                accept(ep, id).expect("a first namespace subscription is accepted");
            }

            fn tracks_open(ep: &mut Endpoint, id: u64, prefix: TrackNamespace) {
                tracks_arrives(ep, id, prefix);
                accept(ep, id).expect("a first track subscription is accepted");
            }

            /// The peer's REQUEST_UPDATE arrives on the stream `id` opened.
            fn update(
                ep: &mut Endpoint,
                id: u64,
                parameters: Vec<KeyValuePair>,
            ) -> Result<(), EndpointError> {
                ep.receive_on_peer_request_stream(
                    crate::v(id),
                    ControlMessage::RequestUpdate(RequestUpdate {
                        request_id: crate::v(id),
                        parameters,
                    }),
                )
            }

            /// The REQUEST_OK this endpoint is about to write on stream `id`,
            /// which answers the request itself the first time and an update
            /// after that.
            fn accept(ep: &mut Endpoint, id: u64) -> Result<(), EndpointError> {
                ep.send_response_on_stream(
                    crate::v(id),
                    &ControlMessage::RequestOk(RequestOk {
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    }),
                )
            }

            /// The REQUEST_ERROR this endpoint is about to write, under a code
            /// of the caller's choosing.
            fn refuse(ep: &mut Endpoint, id: u64, code: u64) -> Result<(), EndpointError> {
                ep.send_response_on_stream(
                    crate::v(id),
                    &ControlMessage::RequestError(RequestError {
                        error_code: crate::v(code),
                        retry_interval: crate::v(0),
                        reason_phrase: b"no".to_vec(),
                        redirect: None,
                    }),
                )
            }

            /// An update moving a subscription onto ground another one of its
            /// kind already holds may not be accepted.
            ///
            /// Sections 10.18 and 10.19 state the rule for the arriving
            /// request; Section 10.9.2 states it again for the update, and the
            /// answer it names is the same one.
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// Section 10.9.2 answers this update with REQUEST_ERROR, not Ok(())
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Taking the verdict on arrival and never reading it back when the
            /// answer is written, so the endpoint knows the update collides and
            /// lets it through anyway:
            ///
            /// ```text
            /// Section 10.9.2 answers this update with REQUEST_ERROR, not Ok(())
            /// ```
            ///
            /// It reddens six, the three gates whose subject is the answer, on both
            /// drafts. The four that watch where a prefix ended up stay green: the
            /// move still happens, it is only unpoliced.
            #[test]
            fn an_update_may_not_move_a_prefix_onto_an_established_one() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                namespace_open(&mut ep, SECOND, crate::elsewhere());

                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::under())])
                    .expect("an update may ask");

                match accept(&mut ep, SECOND) {
                    Err(EndpointError::PeerPrefixOverlap { request, established }) => {
                        assert_eq!(request, SECOND);
                        assert_eq!(established, FIRST);
                    }
                    other => panic!(
                        "Section 10.9.2 answers this update with REQUEST_ERROR, not {other:?}"
                    ),
                }
            }

            /// And the refusal it takes carries PREFIX_OVERLAP and no other
            /// code.
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// the code the sentence names is not optional: Ok(())
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Taking the verdict on arrival and never reading it back when the
            /// answer is written, so the endpoint knows the update collides and
            /// lets it through anyway:
            ///
            /// ```text
            /// the code the sentence names is not optional: Ok(())
            /// ```
            ///
            /// It reddens six, the three gates whose subject is the answer, on both
            /// drafts. The four that watch where a prefix ended up stay green: the
            /// move still happens, it is only unpoliced.
            #[test]
            fn an_overlapping_update_is_refused_under_prefix_overlap_and_no_other_code() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                namespace_open(&mut ep, SECOND, crate::elsewhere());
                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::under())])
                    .expect("an update may ask");

                match refuse(&mut ep, SECOND, 0x1) {
                    Err(EndpointError::WrongOverlapRefusal { request, required }) => {
                        assert_eq!(request, SECOND);
                        assert_eq!(required, crate::PREFIX_OVERLAP);
                    }
                    other => panic!("the code the sentence names is not optional: {other:?}"),
                }

                refuse(&mut ep, SECOND, crate::PREFIX_OVERLAP)
                    .expect("the refusal the sentence names goes out");
            }

            /// An accepted move frees the prefix the subscription leaves.
            ///
            /// This is the half the parameter's own sentence is about -- "It
            /// updates the Track Namespace Prefix for that subscription" -- and
            /// the only way to see it from outside is that ground the
            /// subscription used to hold stops refusing new requests.
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// the prefix the first subscription left is free for the second to
            /// take: PeerPrefixOverlap { request: 2, established: 0 }
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Judging the new prefix and never writing it into the record, so the
            /// subscription goes on selecting what the peer opened it with however
            /// many updates are accepted:
            ///
            /// ```text
            /// the prefix the first subscription left is free for the second to
            /// take: PeerPrefixOverlap { request: 2, established: 0 }
            /// ```
            ///
            /// It reddens eight, the four gates that observe a prefix having moved.
            /// The refusal gates stay green, because the verdict is still taken and
            /// still enforced.
            #[test]
            fn an_accepted_move_frees_the_prefix_it_leaves() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());

                update(&mut ep, FIRST, vec![crate::prefix_param(&crate::elsewhere())])
                    .expect("an update may ask");
                accept(&mut ep, FIRST).expect("nothing else holds that prefix");

                namespace_arrives(&mut ep, SECOND, crate::under());
                accept(&mut ep, SECOND).expect(
                    "the prefix the first subscription left is free for the second to take",
                );
            }

            /// And takes the one it arrives at.
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// the moved subscription holds that prefix now: Ok(())
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Judging the new prefix and never writing it into the record, so the
            /// subscription goes on selecting what the peer opened it with however
            /// many updates are accepted:
            ///
            /// ```text
            /// the moved subscription holds that prefix now: Ok(())
            /// ```
            ///
            /// It reddens eight, the four gates that observe a prefix having moved.
            /// The refusal gates stay green, because the verdict is still taken and
            /// still enforced.
            ///
            /// Dropping the verdict taken for an arriving request, which is the
            /// machinery this rule was built on top of and the only way most of
            /// these gates can see where a prefix ended up:
            ///
            /// ```text
            /// the moved subscription holds that prefix now: Ok(())
            /// ```
            ///
            /// It reddens twenty-four, evenly split: six gates here, every one that
            /// ends by watching a later request be taken in or turned away, and six
            /// in `overlapping_namespace_subscriptions_are_refused.rs`, which is
            /// the file that claim belongs to.
            #[test]
            fn an_accepted_move_takes_the_prefix_it_arrives_at() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());

                update(&mut ep, FIRST, vec![crate::prefix_param(&crate::elsewhere())])
                    .expect("an update may ask");
                accept(&mut ep, FIRST).expect("nothing else holds that prefix");

                namespace_arrives(&mut ep, SECOND, crate::elsewhere());
                match accept(&mut ep, SECOND) {
                    Err(EndpointError::PeerPrefixOverlap { request, established }) => {
                        assert_eq!(request, SECOND);
                        assert_eq!(established, FIRST);
                    }
                    other => panic!("the moved subscription holds that prefix now: {other:?}"),
                }
            }

            /// A refused move leaves the subscription selecting what it
            /// selected before.
            ///
            /// # What it catches
            ///
            /// Applying the move on a refusal as well as on an acceptance, which is
            /// the reading Section 10.9.2 rules out by putting the effect after the
            /// REQUEST_OK:
            ///
            /// ```text
            /// a refused update moves nothing: Ok(())
            /// ```
            ///
            /// It reddens two, this gate on both drafts and nothing else. The first
            /// run of it reported three; the third was the proxy's real-QUIC sweep
            /// failing to connect upstream on draft-09, which carries none of this
            /// code, and it did not recur.
            ///
            /// Dropping the verdict taken for an arriving request, which is the
            /// machinery this rule was built on top of and the only way most of
            /// these gates can see where a prefix ended up:
            ///
            /// ```text
            /// a refused update moves nothing: Ok(())
            /// ```
            ///
            /// It reddens twenty-four, evenly split: six gates here, every one that
            /// ends by watching a later request be taken in or turned away, and six
            /// in `overlapping_namespace_subscriptions_are_refused.rs`, which is
            /// the file that claim belongs to.
            #[test]
            fn a_refused_move_leaves_the_subscription_where_it_was() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                namespace_open(&mut ep, SECOND, crate::elsewhere());

                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::under())])
                    .expect("an update may ask");
                refuse(&mut ep, SECOND, crate::PREFIX_OVERLAP).expect("refused, as it must be");

                namespace_arrives(&mut ep, THIRD, crate::elsewhere());
                match accept(&mut ep, THIRD) {
                    Err(EndpointError::PeerPrefixOverlap { request, established }) => {
                        assert_eq!(request, THIRD);
                        assert_eq!(established, SECOND);
                    }
                    other => panic!("a refused update moves nothing: {other:?}"),
                }
            }

            /// A subscription is not weighed against itself.
            ///
            /// Moving from `conformance/alpha` to `conformance` overlaps
            /// `conformance/alpha`, and the only subscription holding that is
            /// the one being moved. "Another active subscription" is the word
            /// that lets this through.
            ///
            /// # What it catches
            ///
            /// Weighing the new prefix against every active subscription of its
            /// kind, the one being moved included. That is the sentence with the
            /// word "another" taken out of it, and it forbids every widening and
            /// every narrowing:
            ///
            /// ```text
            /// a subscription may be widened over the ground it already holds:
            /// PeerPrefixOverlap { request: 0, established: 0 }
            /// ```
            ///
            /// It reddens two, this gate on both drafts and nothing else. No other
            /// gate moves a subscription onto ground it already holds.
            #[test]
            fn a_subscription_is_not_weighed_against_itself() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());

                update(&mut ep, FIRST, vec![crate::prefix_param(&crate::root())])
                    .expect("an update may ask");
                accept(&mut ep, FIRST)
                    .expect("a subscription may be widened over the ground it already holds");
            }

            /// The two request kinds keep their own ground when a prefix moves.
            ///
            /// The module header carries the whole sentence; the half this gate
            /// is about reads "the new prefix MUST NOT share a common prefix with
            /// any other active SUBSCRIBE_NAMESPACE (for a SUBSCRIBE_NAMESPACE
            /// update) or SUBSCRIBE_TRACKS (for a SUBSCRIBE_TRACKS update) in the
            /// same session", which names the request kind on both sides of the
            /// comparison.
            ///
            /// # What it catches
            ///
            /// Merging the two overlap spaces, so a SUBSCRIBE_TRACKS moving its
            /// prefix is weighed against the peer's SUBSCRIBE_NAMESPACEs:
            ///
            /// ```text
            /// a SUBSCRIBE_TRACKS may move onto a prefix a SUBSCRIBE_NAMESPACE
            /// holds: PeerPrefixOverlap { request: 2, established: 0 }
            /// ```
            ///
            /// It reddens four: this gate, where the move should be allowed and is
            /// not, and the one where a SUBSCRIBE_TRACKS should collide with
            /// another SUBSCRIBE_TRACKS and instead finds a namespace subscription
            /// to blame.
            #[test]
            fn a_namespace_update_and_a_tracks_update_have_their_own_ground() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                tracks_open(&mut ep, SECOND, crate::elsewhere());

                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::under())])
                    .expect("an update may ask");
                accept(&mut ep, SECOND).expect(
                    "a SUBSCRIBE_TRACKS may move onto a prefix a SUBSCRIBE_NAMESPACE holds",
                );
            }

            /// And a tracks update is weighed against the other tracks
            /// subscriptions.
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// SUBSCRIBE_TRACKS has an overlap space of its own: Ok(())
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Taking the verdict on arrival and never reading it back when the
            /// answer is written, so the endpoint knows the update collides and
            /// lets it through anyway:
            ///
            /// ```text
            /// SUBSCRIBE_TRACKS has an overlap space of its own: Ok(())
            /// ```
            ///
            /// It reddens six, the three gates whose subject is the answer, on both
            /// drafts. The four that watch where a prefix ended up stay green: the
            /// move still happens, it is only unpoliced.
            ///
            /// Merging the two overlap spaces, so a SUBSCRIBE_TRACKS moving its
            /// prefix is weighed against the peer's SUBSCRIBE_NAMESPACEs:
            ///
            /// ```text
            /// SUBSCRIBE_TRACKS has an overlap space of its own: Ok(()) failures: d
            /// raft18::a_namespace_update_and_a_tracks_update_have_their_own_ground
            /// draft18::a_tracks_update_is_weighed_against_the_other_tracks_subscri
            /// ptions draft1
            /// ```
            ///
            /// It reddens four: this gate, where the move should be allowed and is
            /// not, and the one where a SUBSCRIBE_TRACKS should collide with
            /// another SUBSCRIBE_TRACKS and instead finds a namespace subscription
            /// to blame.
            #[test]
            fn a_tracks_update_is_weighed_against_the_other_tracks_subscriptions() {
                let mut ep = active();
                tracks_open(&mut ep, FIRST, crate::under());
                tracks_open(&mut ep, SECOND, crate::elsewhere());

                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::under())])
                    .expect("an update may ask");
                match accept(&mut ep, SECOND) {
                    Err(EndpointError::PeerPrefixOverlap { request, established }) => {
                        assert_eq!(request, SECOND);
                        assert_eq!(established, FIRST);
                    }
                    other => panic!("SUBSCRIBE_TRACKS has an overlap space of its own: {other:?}"),
                }
            }

            /// An update that names no prefix moves nothing, and does not undo
            /// a move an earlier one made.
            ///
            /// Section 10.9: "If a parameter previously set on the request is
            /// not present in REQUEST_UPDATE, its value remains unchanged."
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// the first subscription is still at the sibling: PeerPrefixOverlap {
            /// request: 2, established: 0 }
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Judging the new prefix and never writing it into the record, so the
            /// subscription goes on selecting what the peer opened it with however
            /// many updates are accepted:
            ///
            /// ```text
            /// the first subscription is still at the sibling: PeerPrefixOverlap {
            /// request: 2, established: 0 }
            /// ```
            ///
            /// It reddens eight, the four gates that observe a prefix having moved.
            /// The refusal gates stay green, because the verdict is still taken and
            /// still enforced.
            ///
            /// Dropping the verdict taken for an arriving request, which is the
            /// machinery this rule was built on top of and the only way most of
            /// these gates can see where a prefix ended up:
            ///
            /// ```text
            /// an empty update does not send it back: Ok(())
            /// ```
            ///
            /// It reddens twenty-four, evenly split: six gates here, every one that
            /// ends by watching a later request be taken in or turned away, and six
            /// in `overlapping_namespace_subscriptions_are_refused.rs`, which is
            /// the file that claim belongs to.
            #[test]
            fn an_update_that_names_no_prefix_moves_nothing() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());

                update(&mut ep, FIRST, vec![crate::prefix_param(&crate::sibling())])
                    .expect("an update may ask");
                accept(&mut ep, FIRST).expect("nothing holds that prefix");
                update(&mut ep, FIRST, Vec::new()).expect("an update may carry nothing");
                accept(&mut ep, FIRST).expect("and is answered like any other");

                namespace_arrives(&mut ep, SECOND, crate::under());
                accept(&mut ep, SECOND).expect("the first subscription is still at the sibling");

                namespace_arrives(&mut ep, THIRD, crate::sibling());
                match accept(&mut ep, THIRD) {
                    Err(EndpointError::PeerPrefixOverlap { established, .. }) => {
                        assert_eq!(established, FIRST);
                    }
                    other => panic!("an empty update does not send it back: {other:?}"),
                }
            }

            /// The last prefix an update names is the one that moves.
            ///
            /// Read from Section 10.9's rule for two messages -- "Parameter
            /// values from later REQUEST_UPDATE messages override values from
            /// earlier ones" -- applied inside one. Taking the first would
            /// refuse this update, because the first names ground the other
            /// subscription holds.
            ///
            /// # What it catches
            ///
            /// Reading nothing from an update's parameters:
            ///
            /// ```text
            /// the last prefix is where it went: Ok(())
            /// ```
            ///
            /// It reddens fourteen tests, the seven gates here that end in a move
            /// or a refusal, on both drafts.
            ///
            /// Judging the new prefix and never writing it into the record, so the
            /// subscription goes on selecting what the peer opened it with however
            /// many updates are accepted:
            ///
            /// ```text
            /// the last prefix is where it went: Ok(())
            /// ```
            ///
            /// It reddens eight, the four gates that observe a prefix having moved.
            /// The refusal gates stay green, because the verdict is still taken and
            /// still enforced.
            ///
            /// Taking the first TRACK_NAMESPACE_PREFIX a message carries rather
            /// than the last:
            ///
            /// ```text
            /// the last prefix names free ground: PeerPrefixOverlap { request: 2,
            /// established: 0 }
            /// ```
            ///
            /// It reddens two, this gate on both drafts and nothing else. Every
            /// other gate sends one prefix per message, where first and last are
            /// the same parameter.
            ///
            /// Dropping the verdict taken for an arriving request, which is the
            /// machinery this rule was built on top of and the only way most of
            /// these gates can see where a prefix ended up:
            ///
            /// ```text
            /// the last prefix is where it went: Ok(())
            /// ```
            ///
            /// It reddens twenty-four, evenly split: six gates here, every one that
            /// ends by watching a later request be taken in or turned away, and six
            /// in `overlapping_namespace_subscriptions_are_refused.rs`, which is
            /// the file that claim belongs to.
            #[test]
            fn the_last_prefix_an_update_names_is_the_one_that_moves() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                namespace_open(&mut ep, SECOND, crate::sibling());

                update(
                    &mut ep,
                    SECOND,
                    vec![
                        crate::prefix_param(&crate::root()),
                        crate::prefix_param(&crate::elsewhere()),
                    ],
                )
                .expect("an update may ask");
                accept(&mut ep, SECOND).expect("the last prefix names free ground");

                namespace_arrives(&mut ep, THIRD, crate::elsewhere());
                match accept(&mut ep, THIRD) {
                    Err(EndpointError::PeerPrefixOverlap { established, .. }) => {
                        assert_eq!(established, SECOND);
                    }
                    other => panic!("the last prefix is where it went: {other:?}"),
                }
            }

            /// Two updates are judged on their cumulative result.
            ///
            /// Section 10.9: "A receiver of multiple REQUEST_UPDATE messages on
            /// the same stream MAY coalesce their processing by applying only
            /// the cumulative result." The first names ground another
            /// subscription holds and the second moves off it again, so the
            /// cumulative result is legal and there is nothing to refuse.
            ///
            /// # What it catches
            ///
            /// Leaving an earlier update's verdict in place when a later update
            /// replaces the prefix that earned it, so a cumulative result
            /// overlapping nothing is refused anyway:
            ///
            /// ```text
            /// the cumulative result overlaps nothing: PeerPrefixOverlap { request:
            /// 2, established: 0 }
            /// ```
            ///
            /// It reddens two, this gate on both drafts and nothing else. It is the
            /// only one that sends a second update.
            #[test]
            fn two_updates_are_judged_on_their_cumulative_result() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                namespace_open(&mut ep, SECOND, crate::sibling());

                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::root())])
                    .expect("an update may ask");
                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::elsewhere())])
                    .expect("and a second may replace it");

                accept(&mut ep, SECOND).expect("the cumulative result overlaps nothing");
            }

            /// A value that is not a whole Track Namespace moves nothing.
            ///
            /// # What it catches
            ///
            /// Accepting a parameter value that begins with a Track Namespace and
            /// has bytes left over after it:
            ///
            /// ```text
            /// half a prefix is not a prefix: Ok(())
            /// ```
            ///
            /// It reddens two, this gate on both drafts and nothing else.
            ///
            /// Dropping the verdict taken for an arriving request, which is the
            /// machinery this rule was built on top of and the only way most of
            /// these gates can see where a prefix ended up:
            ///
            /// ```text
            /// half a prefix is not a prefix: Ok(())
            /// ```
            ///
            /// It reddens twenty-four, evenly split: six gates here, every one that
            /// ends by watching a later request be taken in or turned away, and six
            /// in `overlapping_namespace_subscriptions_are_refused.rs`, which is
            /// the file that claim belongs to.
            #[test]
            fn a_prefix_that_is_not_a_whole_namespace_moves_nothing() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());

                update(&mut ep, FIRST, vec![crate::overlong_prefix_param(&crate::elsewhere())])
                    .expect("an update may ask");
                accept(&mut ep, FIRST).expect("and is answered like any other");

                namespace_arrives(&mut ep, SECOND, crate::under());
                match accept(&mut ep, SECOND) {
                    Err(EndpointError::PeerPrefixOverlap { established, .. }) => {
                        assert_eq!(established, FIRST);
                    }
                    other => panic!("half a prefix is not a prefix: {other:?}"),
                }
            }

            /// An update to a request that has no namespace prefix is not
            /// judged against one.
            ///
            /// "It MAY appear in REQUEST_UPDATE for a SUBSCRIBE_NAMESPACE or
            /// SUBSCRIBE_TRACKS request" names the two kinds it belongs to. A
            /// SUBSCRIBE has no prefix for it to move, and weighing it against
            /// the namespace subscriptions would refuse an update this draft
            /// says nothing against.
            ///
            /// # What it catches
            ///
            /// Judging the update of every request kind rather than the two that
            /// carry a prefix at all:
            ///
            /// ```text
            /// a SUBSCRIBE has no namespace prefix to be judged against:
            /// PeerPrefixOverlap { request: 2, established: 0 }
            /// ```
            ///
            /// It reddens two, this gate on both drafts and nothing else. It is the
            /// only one that updates a request with no prefix of its own.
            #[test]
            fn an_update_to_a_request_that_has_no_prefix_is_not_judged() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());

                ep.receive_request_on_stream(&ControlMessage::Subscribe(Subscribe {
                    request_id: crate::v(SECOND),
                    track_namespace: crate::under(),
                    track_name: b"video".to_vec(),
                    parameters: Vec::new(),
                }))
                .expect("the peer may subscribe");
                ep.send_response_on_stream(
                    crate::v(SECOND),
                    &ControlMessage::SubscribeOk(SubscribeOk {
                        track_alias: crate::v(1),
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    }),
                )
                .expect("accept it");

                update(&mut ep, SECOND, vec![crate::prefix_param(&crate::under())])
                    .expect("an update may carry a parameter this request has no use for");
                accept(&mut ep, SECOND)
                    .expect("a SUBSCRIBE has no namespace prefix to be judged against");
            }

            /// A refusal already decided is not reopened when the prefix that
            /// caused it moves away.
            ///
            /// The arriving request was judged at the moment it arrived, which
            /// is the moment its own sentence names, and that moment does not
            /// come round again.
            ///
            /// # What it catches
            ///
            /// Dropping the verdict taken for an arriving request, which is the
            /// machinery this rule was built on top of and the only way most of
            /// these gates can see where a prefix ended up:
            ///
            /// ```text
            /// the verdict was taken on arrival: Ok(())
            /// ```
            ///
            /// It reddens twenty-four, evenly split: six gates here, every one that
            /// ends by watching a later request be taken in or turned away, and six
            /// in `overlapping_namespace_subscriptions_are_refused.rs`, which is
            /// the file that claim belongs to.
            #[test]
            fn a_refusal_already_decided_is_not_reopened_by_a_move() {
                let mut ep = active();
                namespace_open(&mut ep, FIRST, crate::under());
                namespace_arrives(&mut ep, SECOND, crate::root());

                update(&mut ep, FIRST, vec![crate::prefix_param(&crate::elsewhere())])
                    .expect("an update may ask");
                accept(&mut ep, FIRST).expect("nothing holds that prefix");

                match accept(&mut ep, SECOND) {
                    Err(EndpointError::PeerPrefixOverlap { request, established }) => {
                        assert_eq!(request, SECOND);
                        assert_eq!(established, FIRST);
                    }
                    other => panic!("the verdict was taken on arrival: {other:?}"),
                }
            }
        }
    };
}

gates!(draft18, "draft18");
gates!(draft19, "draft19");
gates!(draft20, "draft20");

#![cfg(any(
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! A Joining Fetch names a subscription of the peer's, and one that names none
//! this session has cannot be accepted.
//!
//! Drafts 08 through 10, in the FETCH message's own section: "If a publisher
//! receives a Joining Fetch with a Subscribe ID that does not correspond to an
//! existing Subscribe, it MUST respond with a Fetch Error." Draft-11 onwards
//! names the code that refusal carries, and drafts 15 and 16 name the message
//! REQUEST_ERROR. Drafts 16 through 19 say which states count - "in the
//! Established or Pending (subscriber) states" - and the drafts before them
//! say "existing", which is the same set.
//!
//! This endpoint is the publisher of a FETCH that arrives, so it is the one
//! the sentence addresses. Nothing here ends the session: the draft names a
//! message to send back, and a refusal to build the wrong answer is what the
//! crate can offer for it.
//!
//! Drafts 17 through 19 state the same rule over a request stream, and are
//! gated in `a_joining_fetch_on_a_request_stream.rs`. Draft-07 has no Joining
//! Fetch at all.
//!
//! # Which subscriptions can be joined
//!
//! Drafts 08 through 14 say "an existing Subscribe", so only a subscription a
//! SUBSCRIBE opened counts. From draft-15 the sentence says "a subscription",
//! and Section 5.1 there says the Largest Location a Joining FETCH works from
//! is the one saved "in PUBLISH or SUBSCRIBE_OK when establishing a
//! subscription" - so a subscription this endpoint established with PUBLISH
//! counts too. That is the last two drafts here, and it has a gate of its own.
//!
//! # Why the verdict is taken when the FETCH arrives
//!
//! "If a publisher **receives** a Joining Fetch with a Request ID that does
//! not correspond to ..." names the moment. A subscription that ends between
//! the FETCH arriving and its answer going out does not turn a fetch that
//! could be joined into one that could not, and the last gate below is the one
//! that says so.
//!
//! # Ablations, measured
//!
//! Seven cuts were made, run and reverted, each recorded on the gate it
//! belongs to. Every one of them also reaches
//! `a_joining_fetch_on_a_request_stream.rs`, because the rule is one rule
//! stated on twelve drafts and the two files split it only by how the request
//! arrives.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace both tracks live in.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A SUBSCRIBE from the peer, in the shapes these nine drafts give it.
#[macro_export]
macro_rules! peers_subscribe {
    (end_group, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            subscribe_id: $crate::v($id),
            track_alias: $crate::v($alias),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (forward, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_alias: $crate::v($alias),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: $crate::v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (filter_varint, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: $crate::v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (filter_type, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (location, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (bare, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            parameters: Vec::new(),
        }
    };
}

/// This endpoint's SUBSCRIBE_OK, which gained the Track Alias at draft-12 and
/// lost everything but it and the parameters at draft-15.
#[macro_export]
macro_rules! we_subscribe_ok {
    (expires_only, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok($crate::v($id), $crate::v(0), GroupOrder::Ascending, Vec::new())
    };
    (with_alias, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok(
            $crate::v($id),
            $crate::v($alias),
            $crate::v(0),
            GroupOrder::Ascending,
            Vec::new(),
        )
    };
    (params, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok($crate::v($id), $crate::v($alias), Vec::new())
    };
    (ext, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok($crate::v($id), $crate::v($alias), Vec::new(), Vec::new())
    };
}

/// The UNSUBSCRIBE the peer sends to end the subscription it opened.
#[macro_export]
macro_rules! peers_unsubscribe {
    (subscribe, $id:expr) => {
        Unsubscribe { subscribe_id: $crate::v($id) }
    };
    (request, $id:expr) => {
        Unsubscribe { request_id: $crate::v($id) }
    };
}

/// A Joining Fetch from the peer, naming `$joins`.
#[macro_export]
macro_rules! peers_joining_fetch {
    (optional, $id:expr, $joins:expr) => {
        Fetch {
            subscribe_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Joining,
            track_namespace: None,
            track_name: None,
            start_group: None,
            start_object: None,
            end_group: None,
            end_object: None,
            joining_subscribe_id: Some($crate::v($joins)),
            preceding_group_offset: Some($crate::v(0)),
            parameters: Vec::new(),
        }
    };
    (payload_subscribe, $id:expr, $joins:expr) => {
        Fetch {
            request_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: FetchPayload::Joining {
                joining_subscribe_id: $crate::v($joins),
                joining_start: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
    (payload_request, $id:expr, $joins:expr) => {
        Fetch {
            request_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: FetchPayload::Joining {
                joining_request_id: $crate::v($joins),
                joining_start: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
    (bare, $id:expr, $joins:expr) => {
        Fetch {
            request_id: $crate::v($id),
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: FetchPayload::Joining {
                joining_request_id: $crate::v($joins),
                joining_start: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
}

/// A standalone FETCH from the peer, for the gate that shows the rule reaches
/// only the joining ones.
#[macro_export]
macro_rules! peers_standalone_fetch {
    (optional, $id:expr, $track:expr) => {
        Fetch {
            subscribe_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some($crate::namespace()),
            track_name: Some($track.to_vec()),
            start_group: Some($crate::v(0)),
            start_object: Some($crate::v(0)),
            end_group: Some($crate::v(1)),
            end_object: Some($crate::v(0)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: Vec::new(),
        }
    };
    (payload_subscribe, $id:expr, $track:expr) => {
        $crate::peers_standalone_fetch!(@payload $id, $track)
    };
    (payload_request, $id:expr, $track:expr) => {
        $crate::peers_standalone_fetch!(@payload $id, $track)
    };
    (@payload $id:expr, $track:expr) => {
        Fetch {
            request_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: $crate::namespace(),
                track_name: $track.to_vec(),
                start_group: $crate::v(0),
                start_object: $crate::v(0),
                end_group: $crate::v(1),
                end_object: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
    (bare, $id:expr, $track:expr) => {
        Fetch {
            request_id: $crate::v($id),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: $crate::namespace(),
                track_name: $track.to_vec(),
                start_group: $crate::v(0),
                start_object: $crate::v(0),
                end_group: $crate::v(1),
                end_object: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
}

/// The FETCH_OK this endpoint builds, in the four shapes the answer takes.
#[macro_export]
macro_rules! we_accept_fetch {
    (largest, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok(
            $crate::v($id),
            GroupOrder::Ascending,
            0,
            $crate::v(1),
            $crate::v(0),
            Vec::new(),
        )
    };
    (location, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok(
            $crate::v($id),
            GroupOrder::Ascending,
            0,
            Location { group: $crate::v(1), object: $crate::v(0) },
            Vec::new(),
        )
    };
    (split, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok($crate::v($id), 0, $crate::v(1), $crate::v(0), Vec::new())
    };
    (extensions, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok($crate::v($id), 0, $crate::v(1), $crate::v(0), Vec::new(), Vec::new())
    };
}

/// The refusal this endpoint builds, which drafts 15 and 16 renamed and gave a
/// retry interval to.
#[macro_export]
macro_rules! we_refuse_fetch {
    (fetch_error, $ep:expr, $id:expr, $code:expr) => {
        $ep.send_fetch_error($crate::v($id), $crate::v($code), b"no".to_vec())
    };
    (request_error, $ep:expr, $id:expr, $code:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v($code), b"no".to_vec())
    };
    (retry, $ep:expr, $id:expr, $code:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v($code), $crate::v(0), b"no".to_vec())
    };
}

/// The setup parameters each draft requires, and the ceiling the peer must
/// grant before this endpoint may open a request of its own.
#[macro_export]
macro_rules! server_params {
    () => {
        vec![KeyValuePair { key: $crate::v(0x02), value: KvpValue::Varint($crate::v(100)) }]
    };
}

/// SERVER_SETUP, which carries a selected version up to draft-14 and leaves it
/// to the ALPN afterwards.
#[macro_export]
macro_rules! peers_setup {
    (versioned, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v($version)], Vec::new()).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($version),
            parameters: $crate::server_params!(),
        })
        .expect("SERVER_SETUP");
    }};
    (alpn, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup(Vec::new()).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup { parameters: $crate::server_params!() })
            .expect("SERVER_SETUP");
    }};
}

/// The five gates every one of these drafts carries.
macro_rules! joining_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $setup:tt,
     $submsg:tt, $subok:tt, $unsub:tt, $joinmsg:tt, $alone:tt, $accept:tt,
     $peers_first:literal, $step:literal, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            /// The peer's SUBSCRIBE takes its first identifier.
            pub(super) const PEERS_SUB: u64 = $peers_first;

            /// Its FETCH takes the next one it may use.
            pub(super) const PEERS_FETCH: u64 = $peers_first + $step;

            /// An identifier no request of the peer's ever arrived under.
            pub(super) const NEVER_USED: u64 = 9;

            const ALIAS: u64 = 7;
            const ALPHA: &[u8] = b"alpha";

            /// A client with its session established and a budget granted to
            /// the peer.
            pub(super) fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!($setup, ep, $version);
                let _ = ep.$grant($crate::v(100)).expect("a budget for the peer");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// An endpoint publishing a track the peer subscribed to.
            pub(super) fn publishing() -> Endpoint {
                let mut ep = active();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_SUB, ALIAS, ALPHA))
                    .expect("the peer's SUBSCRIBE");
                crate::we_subscribe_ok!($subok, ep, PEERS_SUB, ALIAS)
                    .expect("accept the subscription");
                ep
            }

            /// The same, with the subscription ended by the peer.
            pub(super) fn ended() -> Endpoint {
                let mut ep = publishing();
                ep.receive_unsubscribe(&crate::peers_unsubscribe!($unsub, PEERS_SUB))
                    .expect("the peer ends its subscription");
                ep
            }

            /// The session is still running: this rule names a message to send
            /// back, not a session to end.
            pub(super) fn still_running(ep: &Endpoint) {
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
            /// a Joining Fetch naming a live subscription is answerable: UnjoinableSubscription { fetch: 1, joining: 0 }
            /// ```
            ///
            /// Made by judging every fetch unjoinable, standalone ones included. It
            /// reddens a hundred and forty-two tests across all the drafts that
            /// state the rule: a fetch that can never be answered is one no later gate
            /// can reach.
            #[test]
            fn a_joining_fetch_naming_a_live_subscription_is_accepted() {
                let mut ep = publishing();
                ep.receive_fetch(&crate::peers_joining_fetch!($joinmsg, PEERS_FETCH, PEERS_SUB))
                    .expect("the peer's Joining Fetch");
                crate::we_accept_fetch!($accept, ep, PEERS_FETCH)
                    .expect("a Joining Fetch naming a live subscription is answerable");
            }

            /// A Joining Fetch naming nothing this session has cannot be
            /// accepted.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a Joining Fetch naming nothing was accepted: FetchOk(FetchOk { subscribe_id: VarInt(1), group_order: Ascending, end_of_track: 0, largest_group_id: VarInt(1), largest_object_id: VarInt(0), parameters: [] })
            /// ```
            ///
            /// Made by taking the verdict and not acting on it. It reddens twenty-four
            /// tests: this gate and the ended-subscription one, on all twelve.
            #[test]
            fn a_joining_fetch_naming_nothing_is_refused() {
                let mut ep = publishing();
                ep.receive_fetch(&crate::peers_joining_fetch!($joinmsg, PEERS_FETCH, NEVER_USED))
                    .expect("the peer's Joining Fetch");
                let err = crate::we_accept_fetch!($accept, ep, PEERS_FETCH)
                    .expect_err("a Joining Fetch naming nothing was accepted");
                assert!(
                    matches!(
                        err,
                        EndpointError::UnjoinableSubscription {
                            fetch: PEERS_FETCH,
                            joining: NEVER_USED
                        }
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
            /// a Joining Fetch naming an ended subscription was accepted: FetchOk(FetchOk { subscribe_id: VarInt(1), group_order: Ascending, end_of_track: 0, largest_group_id: VarInt(1), largest_object_id: VarInt(0), parameters: [] })
            /// ```
            ///
            /// Made by reading a subscription as live whenever its record exists. It
            /// reddens twelve tests and only this gate: every other joining fetch here
            /// names either a live subscription or nothing at all.
            #[test]
            fn a_joining_fetch_naming_an_ended_subscription_is_refused() {
                let mut ep = ended();
                ep.receive_fetch(&crate::peers_joining_fetch!($joinmsg, PEERS_FETCH, PEERS_SUB))
                    .expect("the peer's Joining Fetch");
                let err = crate::we_accept_fetch!($accept, ep, PEERS_FETCH)
                    .expect_err("a Joining Fetch naming an ended subscription was accepted");
                assert!(
                    matches!(
                        err,
                        EndpointError::UnjoinableSubscription {
                            fetch: PEERS_FETCH,
                            joining: PEERS_SUB
                        }
                    ),
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
            /// The same cut, and this is the half of it that says the rule is about
            /// Joining Fetches and not about fetches.
            #[test]
            fn a_standalone_fetch_needs_no_subscription() {
                let mut ep = active();
                ep.receive_fetch(&crate::peers_standalone_fetch!($alone, PEERS_SUB, ALPHA))
                    .expect("the peer's standalone FETCH");
                crate::we_accept_fetch!($accept, ep, PEERS_SUB)
                    .expect("a standalone fetch names no subscription to join");
            }

            /// The verdict is taken when the FETCH arrives, not when it is
            /// answered.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the subscription was live when the FETCH arrived, which is the moment the rule reads: UnjoinableSubscription { fetch: 1, joining: 0 }
            /// ```
            ///
            /// Made by judging the fetch again when it is answered instead of reading
            /// the verdict taken when it arrived. It reddens nine tests and only this
            /// gate, on the nine drafts here; the three in
            /// `a_joining_fetch_on_a_request_stream.rs` keep no copy of the FETCH to
            /// judge a second time, so there is nothing there to cut.
            #[test]
            fn a_subscription_that_ends_after_the_fetch_does_not_unmake_it() {
                let mut ep = publishing();
                ep.receive_fetch(&crate::peers_joining_fetch!($joinmsg, PEERS_FETCH, PEERS_SUB))
                    .expect("the peer's Joining Fetch");
                ep.receive_unsubscribe(&crate::peers_unsubscribe!($unsub, PEERS_SUB))
                    .expect("the peer ends the subscription it joined");
                crate::we_accept_fetch!($accept, ep, PEERS_FETCH).expect(
                    "the subscription was live when the FETCH arrived, which is the moment \
                     the rule reads",
                );
            }
        }
    };
}

/// The two gates the drafts that name a code for the refusal carry.
macro_rules! named_code_gates {
    ($mod:ident, $draft:ident, $feat:literal, $joinmsg:tt, $refuse:tt, $code:literal,
     $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $mod {
            use moqtap_client::$draft::endpoint::EndpointError;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            use super::$draft::{
                active, publishing, still_running, NEVER_USED, PEERS_FETCH, PEERS_SUB,
            };

            /// The code the section names for this refusal.
            const NAMED: u64 = $code;

            /// A code the drafts use for other refusals of a fetch.
            const INTERNAL_ERROR: u64 = 0x0;

            /// The refusal the section names can be built.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the code the section names should build the refusal: WrongJoiningRefusal { fetch: 3, required: 0 }
            /// ```
            ///
            /// Made by requiring the internal-error code instead of the one the
            /// section names. It reddens twenty-three tests across the nine drafts
            /// that name a code: this gate, its opposite below, and the wire gate that
            /// reads the number back off the refusal.
            #[test]
            fn the_refusal_carries_the_code_the_section_names() {
                let mut ep = publishing();
                ep.receive_fetch(&crate::peers_joining_fetch!($joinmsg, PEERS_FETCH, NEVER_USED))
                    .expect("the peer's Joining Fetch");
                crate::we_refuse_fetch!($refuse, ep, PEERS_FETCH, NAMED)
                    .expect("the code the section names should build the refusal");
                still_running(&ep);
            }

            /// It cannot be built under any other code.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the refusal went out under a code the section does not name: FetchError(FetchError { request_id: VarInt(3), error_code: VarInt(0), reason_phrase: [110, 111] })
            /// ```
            ///
            /// Made by dropping the guard entirely. It reddens nine tests and only
            /// this gate: a refusal under the right code is still built.
            #[test]
            fn the_refusal_cannot_carry_another_code() {
                let mut ep = publishing();
                ep.receive_fetch(&crate::peers_joining_fetch!($joinmsg, PEERS_FETCH, NEVER_USED))
                    .expect("the peer's Joining Fetch");
                let err = crate::we_refuse_fetch!($refuse, ep, PEERS_FETCH, INTERNAL_ERROR)
                    .expect_err("the refusal went out under a code the section does not name");
                assert!(
                    matches!(
                        err,
                        EndpointError::WrongJoiningRefusal { fetch: PEERS_FETCH, required: NAMED }
                    ),
                    "the refusal should name the code Section {} requires; got {err:?}",
                    $sec
                );
                still_running(&ep);
            }

            /// A fetch that joins nothing is refused under whatever code fits
            /// it, which is what makes the gate above a rule about Joining
            /// Fetches and not about refusals.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a standalone fetch's refusal carries the reason it was refused for: WrongJoiningRefusal { fetch: 1, required: 7 }
            /// ```
            ///
            /// The same cut as the first gate in this file, and this is the half of it
            /// that says the guard is about Joining Fetches: with every fetch judged
            /// unjoinable, a standalone one can be refused for nothing but that.
            #[test]
            fn a_fetch_that_joins_nothing_is_refused_under_any_code() {
                let mut ep = active();
                ep.receive_fetch(&crate::peers_standalone_fetch!($joinmsg, PEERS_SUB, b"alpha"))
                    .expect("the peer's standalone FETCH");
                crate::we_refuse_fetch!($refuse, ep, PEERS_SUB, INTERNAL_ERROR)
                    .expect("a standalone fetch's refusal carries the reason it was refused for");
            }
        }
    };
}

/// The gate the two drafts that let a PUBLISH establish a joinable
/// subscription carry.
macro_rules! published_join_gates {
    ($mod:ident, $draft:ident, $feat:literal, $publish:tt, $joinmsg:tt, $accept:tt) => {
        #[cfg(feature = $feat)]
        mod $mod {
            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            use super::$draft::{active, PEERS_FETCH};

            /// A subscription this endpoint established with PUBLISH can be
            /// joined.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// Section 5.1 saves the Largest Location from PUBLISH as well as SUBSCRIBE_OK, so a subscription a PUBLISH established can be joined: UnjoinableSubscription { fetch: 3, joining: 0 }
            /// ```
            ///
            /// Made by dropping the `publishes` half of the probe. It reddens five
            /// tests and only this gate, on the five drafts whose sentence says "a
            /// subscription" rather than "an existing Subscribe".
            #[test]
            fn a_subscription_a_publish_established_can_be_joined() {
                let mut ep = active();
                let (published, _) = crate::we_publish!($publish, ep, b"beta").expect("PUBLISH");
                ep.receive_publish_ok(&PublishOk { request_id: published, parameters: Vec::new() })
                    .expect("the peer accepts the publication");
                ep.receive_fetch(&crate::peers_joining_fetch!(
                    $joinmsg,
                    PEERS_FETCH,
                    published.into_inner()
                ))
                .expect("the peer's Joining Fetch");
                crate::we_accept_fetch!($accept, ep, PEERS_FETCH).expect(
                    "Section 5.1 saves the Largest Location from PUBLISH as well as \
                     SUBSCRIBE_OK, so a subscription a PUBLISH established can be joined",
                );
            }
        }
    };
}

/// This endpoint's PUBLISH, which gained track extensions at draft-16.
#[macro_export]
macro_rules! we_publish {
    (params, $ep:expr, $track:expr) => {
        $ep.publish($crate::namespace(), $track.to_vec(), $crate::v(11), Vec::new())
    };
    (ext, $ep:expr, $track:expr) => {
        $ep.publish($crate::namespace(), $track.to_vec(), $crate::v(11), Vec::new(), Vec::new())
    };
}

joining_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    send_max_subscribe_id,
    versioned,
    end_group,
    expires_only,
    subscribe,
    optional,
    optional,
    largest,
    0,
    1,
    "7.7"
);
joining_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    send_max_subscribe_id,
    versioned,
    end_group,
    expires_only,
    subscribe,
    optional,
    optional,
    largest,
    0,
    1,
    "7.7"
);
joining_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    send_max_subscribe_id,
    versioned,
    end_group,
    expires_only,
    subscribe,
    optional,
    optional,
    largest,
    0,
    1,
    "8.12"
);
joining_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    send_max_request_id,
    versioned,
    forward,
    expires_only,
    request,
    payload_subscribe,
    payload_subscribe,
    location,
    1,
    2,
    "8.13"
);
joining_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    moqtap_client::draft12::session::request_id::Role,
    send_max_request_id,
    versioned,
    filter_varint,
    with_alias,
    request,
    payload_request,
    payload_request,
    location,
    1,
    2,
    "8.16"
);
joining_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    send_max_request_id,
    versioned,
    filter_type,
    with_alias,
    request,
    payload_request,
    payload_request,
    location,
    1,
    2,
    "8.16"
);
joining_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    send_max_request_id,
    versioned,
    location,
    with_alias,
    request,
    payload_request,
    payload_request,
    location,
    1,
    2,
    "9.16.2"
);
joining_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    send_max_request_id,
    alpn,
    bare,
    params,
    request,
    bare,
    bare,
    split,
    1,
    2,
    "9.16.2"
);
joining_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    send_max_request_id,
    alpn,
    bare,
    ext,
    request,
    bare,
    bare,
    extensions,
    1,
    2,
    "9.16.2"
);

named_code_gates!(draft11_code, draft11, "draft11", payload_subscribe, fetch_error, 0x7, "8.13");
named_code_gates!(draft12_code, draft12, "draft12", payload_request, fetch_error, 0x7, "8.16");
named_code_gates!(draft13_code, draft13, "draft13", payload_request, fetch_error, 0x7, "8.16");
named_code_gates!(draft14_code, draft14, "draft14", payload_request, fetch_error, 0x7, "9.16.2");
named_code_gates!(draft15_code, draft15, "draft15", bare, request_error, 0x32, "9.16.2");
named_code_gates!(draft16_code, draft16, "draft16", bare, retry, 0x32, "9.16.2");

published_join_gates!(draft15_published, draft15, "draft15", params, bare, split);
published_join_gates!(draft16_published, draft16, "draft16", ext, bare, extensions);

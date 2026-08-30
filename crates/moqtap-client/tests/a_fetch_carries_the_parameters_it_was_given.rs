#![cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
))]

//! A FETCH carries the parameters the caller gave it, as every other request
//! this endpoint makes does.
//!
//! Draft-15 Section 9.2.1 and draft-19 Section 10.2 define what a request's
//! parameters are and what may go in them, and every request message on these
//! five drafts draws a Parameters field. That is the whole of the rule this
//! file holds: the field is the caller's, and a FETCH is a request.
//!
//! # What was here before
//!
//! `Endpoint::fetch` sent an empty list on all five drafts. Its four siblings
//! on the same drafts — `subscribe`, `track_status`, `publish_namespace` and
//! `publish` — all took the caller's, which made FETCH the one request an
//! application could not attach anything to.
//!
//! What it could not attach is the point. Draft-14's FETCH carried a
//! Subscriber Priority field of its own; drafts 15 and up dropped the field
//! and moved it into the parameters, where draft-17 Section 9.3.5 says it "MAY
//! appear in a SUBSCRIBE, FETCH, REQUEST_UPDATE (for a subscription or FETCH),
//! or PUBLISH_OK message". So a fetch on these five drafts had no way to say
//! what priority it wanted, and the field had not gone away — it had moved
//! somewhere the crate did not follow it. An authorization token, which
//! Section 9.3.2 puts in the same list, is the other thing no fetch could
//! carry.
//!
//! # Why the range starts at 15
//!
//! It used to stop there. Drafts 12, 13 and 14 filled in the parameters of
//! nearly every request they built, not only the fetch, so on those three the
//! FETCH was not the odd one out and fixing it alone would have made it so.
//! Their builders are being given the argument one at a time now, and the
//! fetch has had its turn; the gates for those three are in
//! `a_fetch_carries_the_parameters_it_was_given_on_the_earlier_drafts.rs`,
//! which needs its own call shape because a fetch draws a Subscriber Priority
//! and a Group Order of its own until draft-15 moves them into the
//! parameters.
//!
//! # Both kinds of FETCH
//!
//! A Joining Fetch is the same message under a different Fetch Type, with one
//! Parameters field and the same registered parameters to put in it. It sent
//! an empty list on all five of these drafts after the standalone form had
//! stopped, because the change that gave FETCH the caller's parameters
//! reached only the call it was looking at. So the third gate on each draft
//! is the joining one.
//!
//! # Ablations, measured
//!
//! One cut was made, run against the two crates a change to
//! `moqtap-client` can reach, and reverted. There is one claim here
//! and one way to break it, so there is one cut; the second gate is
//! the control that keeps the first from being satisfied by a field
//! that is always full.
//!
//! ## And one more when the claim reached the other kind of FETCH
//!
//! The joining call has a builder of its own on each draft, so emptying the
//! standalone one leaves the joining gate green and the other way round. The
//! cut recorded on the third gate is the joining builder's.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace every fetch here is for.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gate.
macro_rules! fetch_parameter_gates {
    ($draft:ident, $feat:literal, $setup:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::$draft::message::*;

            /// A client with its session established and a budget to spend.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::setup_for!($setup, ep);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gate needs a running session"
                );
                ep
            }

            /// The parameter the caller attaches, chosen so that an empty
            /// list cannot be mistaken for it.
            ///
            /// It is SUBSCRIBER PRIORITY (0x20), which is the parameter
            /// that makes this a fix rather than a tidy-up. Draft-14's FETCH
            /// carried a Subscriber Priority field; drafts 15 and up dropped
            /// the field and made it a parameter, and draft-17 Section 9.3.5
            /// says it "MAY appear in a SUBSCRIBE, FETCH, REQUEST_UPDATE (for
            /// a subscription or FETCH), or PUBLISH_OK message". With the
            /// parameter list filled in as empty, a fetch on these five drafts
            /// could not carry a priority at all.
            ///
            /// Three things the codec enforces had to line up for this to be a
            /// usable choice, and each would have failed the gate for its own
            /// reason: the key must be one the draft registers, its value's
            /// encoding follows the key's parity, and drafts 17 through 19
            /// check that the parameter is in scope for the message carrying
            /// it.
            fn token() -> KeyValuePair {
                KeyValuePair { key: crate::v(0x20), value: KvpValue::Varint(crate::v(42)) }
            }

            /// The parameters a fetch is given reach the peer.
            ///
            /// # What it catches
            ///
            /// Sending an empty parameter list whatever the caller passed, which is
            /// what all five drafts did:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameter the caller attached
            /// must reach the peer, and this call used to send an empty list
            /// whatever it was given left: 0 right: 1 failures:
            /// draft15::the_parameters_a_fetch_is_given_reach_the_peer
            /// ```
            ///
            /// It reddens five, this gate on every draft in the range and nothing
            /// else.
            #[test]
            fn the_parameters_a_fetch_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .fetch(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        crate::v(1),
                        crate::v(0),
                        crate::v(2),
                        crate::v(0),
                        vec![token()],
                    )
                    .expect("this endpoint may fetch with parameters");

                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the fetch encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Fetch(back) =
                    ControlMessage::decode(&mut cursor).expect("the fetch decodes")
                else {
                    panic!("what was encoded was a FETCH");
                };
                assert_eq!(
                    back.parameters.len(),
                    1,
                    "the parameter the caller attached must reach the peer, and this call \
                     used to send an empty list whatever it was given"
                );
                assert_eq!(
                    back.parameters[0].key.into_inner(),
                    0x20,
                    "and it must be the one the caller passed"
                );
            }

            /// A fetch with nothing attached still carries nothing.
            ///
            /// The other half, and the reason it is here: a change that made
            /// the field always non-empty would pass the gate above.
            ///
            /// # What it catches
            ///
            /// Nothing the cut reaches, and that is what it is for. The one
            /// cut sends an empty list whatever it is given, which is what
            /// this gate asserts, so the cut leaves it green. It is the
            /// control for the gate above: without it, a change that filled
            /// the field with something of its own would pass the only other
            /// assertion in this file.
            #[test]
            fn a_fetch_given_no_parameters_carries_none() {
                let mut ep = active();
                let (_, msg) = ep
                    .fetch(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        crate::v(1),
                        crate::v(0),
                        crate::v(2),
                        crate::v(0),
                        Vec::new(),
                    )
                    .expect("this endpoint may fetch without parameters");
                let ControlMessage::Fetch(built) = msg else {
                    panic!("what was built was a FETCH");
                };
                assert!(
                    built.parameters.is_empty(),
                    "an empty list is still what an empty list means"
                );
            }

            /// The other kind of FETCH carries them too.
            ///
            /// A Joining Fetch is a FETCH under a different Fetch Type: one
            /// Parameters field, the same registered parameters to put in it,
            /// and nothing about naming the range through a subscription
            /// rather than outright that changes what may be attached.
            ///
            /// The Request ID it joins names no subscription here, and the
            /// call does not mind: draft-15 Section 9.16.2 leaves that to the
            /// publisher, which "MUST return a REQUEST_ERROR with error code
            /// INVALID_JOINING_REQUEST_ID". What is being watched is the
            /// parameter list, and a fetch that never leaves the endpoint
            /// would not need one.
            ///
            /// # What it catches
            ///
            /// A joining fetch that sends an empty list whatever the caller
            /// passed, which is what all five drafts did:
            ///
            /// ```text
            /// assertion `left == right` failed: a Joining Fetch is a FETCH,
            /// and the parameter the caller attached must reach the peer
            ///   left: 0
            ///  right: 1
            /// ```
            ///
            /// It reddens one, this gate on the draft the cut was made in,
            /// because each draft builds its own message.
            #[test]
            fn the_parameters_a_joining_fetch_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .joining_fetch(crate::v(0), crate::v(2), vec![token()])
                    .expect("this endpoint may join a subscription with parameters");

                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the fetch encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Fetch(back) =
                    ControlMessage::decode(&mut cursor).expect("the fetch decodes")
                else {
                    panic!("what was encoded was a FETCH");
                };
                assert_eq!(
                    back.parameters.len(),
                    1,
                    "a Joining Fetch is a FETCH, and the parameter the caller attached must \
                     reach the peer"
                );
                assert_eq!(
                    back.parameters[0].key.into_inner(),
                    0x20,
                    "and it must be the one the caller passed"
                );
            }
        }
    };
}

/// SETUP, in the two shapes these five drafts take.
#[macro_export]
macro_rules! setup_for {
    (alpn, $ep:expr) => {{
        let _ = $ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
        let _ = $ep.send_max_request_id($crate::v(100)).expect("MAX_REQUEST_ID");
    }};
    (options, $ep:expr) => {{
        let _ = $ep.send_setup(vec![]).expect("SETUP");
        $ep.receive_setup(&Setup { options: vec![] }).expect("SETUP");
    }};
}

fetch_parameter_gates!(draft15, "draft15", alpn);
fetch_parameter_gates!(draft16, "draft16", alpn);
fetch_parameter_gates!(draft17, "draft17", options);
fetch_parameter_gates!(draft18, "draft18", options);
fetch_parameter_gates!(draft19, "draft19", options);

#![cfg(feature = "draft07")]

//! A subscription arriving for a namespace the peer has cancelled ends the
//! session, on the one draft that says so.
//!
//! Draft-07 Section 6.11: "If a publisher receives new subscriptions for that
//! namespace after receiving an ANNOUNCE_CANCEL, it SHOULD close the session
//! as a 'Protocol Violation'."
//!
//! Searched across all the drafts: draft-07 states it once and no other
//! draft states it at all, so the range here is one draft wide. It is a SHOULD
//! and this endpoint takes it — the sentence names both the action and the
//! code, so closing is conforming, and leaving the subscription open would go
//! on serving a namespace the peer has said it no longer wants announced.
//!
//! # Why a Done announcement is not the test
//!
//! An announcement reaches Done by two routes: this endpoint sending
//! UNANNOUNCE, and the peer sending ANNOUNCE_CANCEL. The sentence is about the
//! second only, so the endpoint records which namespaces were cancelled rather
//! than reading the state machine. The third gate here is what holds that
//! apart: it withdraws the announcement itself and requires the next SUBSCRIBE
//! to be taken.
//!
//! # And the record is retired, not accumulated
//!
//! Announcing the same namespace again clears it, because the peer's cancel
//! was of the announcement that is now over. Without that, a namespace
//! cancelled once could never be announced and subscribed to again in the same
//! session, which no draft asks for.
//!
//! # Ablations, measured
//!
//! Three cuts, each run against the two crates a change to `moqtap-client`
//! can reach and then reverted. They partition the five gates one apiece,
//! with nothing outside this file reddened and the other 167 binaries green.
//!
//! Removing the check, so a subscription for a cancelled namespace is taken:
//!
//! ```text
//! the peer cancelled this namespace and then subscribed to it: ()
//! ```
//!
//! Judging by the announcement's state machine instead of the record, so
//! this endpoint's own UNANNOUNCE refuses the next subscription too:
//!
//! ```text
//! Section 6.11 is about a cancel the peer sent, not a withdrawal this
//! endpoint made: SubscribeAfterAnnounceCancel
//! ```
//!
//! Never retiring the record, so a namespace announced again stays refused:
//!
//! ```text
//! the cancel was of the announcement that is now over:
//! SubscribeAfterAnnounceCancel
//! ```

use moqtap_client::draft07::endpoint::{Endpoint, EndpointError, Role};
use moqtap_client::draft07::session::state::SessionState;
use moqtap_codec::draft07::error_codes::SessionErrorCode;
use moqtap_codec::draft07::message::*;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::{FilterType, GroupOrder, TrackNamespace};
use moqtap_codec::varint::VarInt;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A namespace this endpoint never announced.
fn other_ns() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

/// An endpoint with a running session that has announced [`ns`] and had it
/// accepted.
fn announced() -> Endpoint {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().expect("a client may open");
    let version = v(0xff00_0007);
    // Draft-07 is the only draft that requires a ROLE parameter in
    // CLIENT_SETUP, and the setup is refused without it.
    let role = vec![KeyValuePair { key: v(0x00), value: KvpValue::Varint(v(3)) }];
    let setup = ClientSetup { supported_versions: vec![version], parameters: role };
    ep.receive_client_setup_and_respond(&setup, version).expect("CLIENT_SETUP");
    assert_eq!(ep.session_state(), SessionState::Active, "the gate needs a running session");
    // Room for the SUBSCRIBE the peer sends. Without a ceiling the allocator
    // refuses it and every gate fails before reaching the rule it is about.
    ep.send_max_subscribe_id(v(100)).expect("MAX_SUBSCRIBE_ID");
    ep.announce(ns()).expect("this endpoint may announce");
    ep.receive_announce_ok(&AnnounceOk { track_namespace: ns() }).expect("ANNOUNCE_OK");
    ep
}

/// The ANNOUNCE_CANCEL the peer sends for `namespace`. The code and the reason
/// are the peer's to choose and nothing here reads them.
fn cancel(namespace: TrackNamespace) -> AnnounceCancel {
    AnnounceCancel { track_namespace: namespace, error_code: v(0), reason_phrase: Vec::new() }
}

/// The SUBSCRIBE the peer sends for a track in `namespace`.
fn subscribe(id: u64, namespace: TrackNamespace) -> Subscribe {
    Subscribe {
        subscribe_id: v(id),
        track_alias: v(id),
        track_namespace: namespace,
        track_name: b"track".to_vec(),
        subscriber_priority: 0,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        end_object: None,
        parameters: vec![],
    }
}

/// A SUBSCRIBE for a cancelled namespace ends the session.
///
/// # What it catches
///
/// A SUBSCRIBE that is never judged against the cancel:
///
/// ```text
/// the peer cancelled this namespace and then subscribed to it: ()
/// ```
#[test]
fn a_subscribe_after_an_announce_cancel_closes_the_session() {
    let mut ep = announced();
    ep.receive_announce_cancel(&cancel(ns())).expect("the peer may cancel an announcement");

    let err = ep
        .receive_subscribe(&subscribe(0, ns()))
        .expect_err("the peer cancelled this namespace and then subscribed to it");
    assert!(matches!(err, EndpointError::SubscribeAfterAnnounceCancel), "got {err:?}");
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

/// Without the cancel the same SUBSCRIBE is taken. Otherwise the gate above
/// would pass on an endpoint that refused every subscription.
#[test]
fn a_subscribe_for_an_announced_namespace_is_taken() {
    let mut ep = announced();
    ep.receive_subscribe(&subscribe(0, ns())).expect("an announced namespace takes subscriptions");
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// This endpoint's own UNANNOUNCE is not the peer's cancel, and the rule is
/// about the peer's. Both leave the announcement in Done, so an endpoint that
/// judged by the state machine would fail here.
#[test]
fn a_subscribe_after_this_endpoints_own_unannounce_is_taken() {
    let mut ep = announced();
    ep.unannounce(ns()).expect("this endpoint may withdraw its announcement");

    ep.receive_subscribe(&subscribe(0, ns())).expect(
        "Section 6.11 is about a cancel the peer sent, not a withdrawal this endpoint made",
    );
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// A namespace announced again after a cancel takes subscriptions once more.
#[test]
fn announcing_again_retires_the_cancel() {
    let mut ep = announced();
    ep.receive_announce_cancel(&cancel(ns())).expect("the peer may cancel an announcement");
    ep.announce(ns()).expect("this endpoint may announce the namespace again");
    ep.receive_announce_ok(&AnnounceOk { track_namespace: ns() }).expect("ANNOUNCE_OK");

    ep.receive_subscribe(&subscribe(0, ns()))
        .expect("the cancel was of the announcement that is now over");
    assert_eq!(ep.session_state(), SessionState::Active);
}

/// The cancel reaches the namespace it names and no other.
#[test]
fn a_cancel_does_not_reach_another_namespace() {
    let mut ep = announced();
    ep.receive_announce_cancel(&cancel(ns())).expect("the peer may cancel an announcement");

    ep.receive_subscribe(&subscribe(0, other_ns()))
        .expect("a different namespace was never cancelled");
    assert_eq!(ep.session_state(), SessionState::Active);
}

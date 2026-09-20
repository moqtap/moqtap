#![allow(missing_docs)]
//! Draft-19 MoQT endpoint.
//!
//! Major changes from draft-18:
//!
//! * `GoAway` drops the `request_id` field entirely; the control-stream and
//!   request-stream forms are now identical on the wire.
//! * `PublishBlocked` renamed to `PublishSkipped` (still type 0x0F, wire
//!   identical).
//! * `GROUP_ORDER` (parameter 0x22) moves from PUBLISH_OK to SUBSCRIBE_TRACKS.
//! * New Range Filter parameters (SUBGROUP_FILTER 0x25, OBJECTID_FILTER 0x26,
//!   PRIORITY_FILTER 0x27, OBJECT_PROPERTY_FILTER 0x28, TRACK_PROPERTY_FILTER
//!   0x29) may appear on SUBSCRIBE / FETCH / SUBSCRIBE_TRACKS / REQUEST_UPDATE.
//! * `RequestError` adds CONFLICTING_FILTERS (0x35) and INVALID_FILTER (0x36);
//!   DUPLICATE_SUBSCRIPTION (0x19) is removed.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::draft19::fetch::{FetchError, FetchState, FetchStateMachine};
use crate::draft19::namespace::{
    NamespaceError, PublishNamespaceState, PublishNamespaceStateMachine, SubscribeNamespaceState,
    SubscribeNamespaceStateMachine,
};
use crate::draft19::publish::{
    PublishError as PublishFlowError, PublishState, PublishStateMachine,
};
use crate::draft19::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft19::session::setup::{self, SetupError};

use moqtap_codec::kvp::KvpValue;
use moqtap_codec::range_filter::{self, RangeFilterError};
use moqtap_codec::varint::Moqt18;

/// The MAX_REQUEST_UPDATES Setup Option, Section 10.3.1.7.
const MAX_REQUEST_UPDATES: u64 = 0x08;

/// The MAX_FILTER_RANGES Setup Option, Section 10.3.1.6.
const MAX_FILTER_RANGES: u64 = 0x06;

/// The Message Parameters a request carries, or nothing for a message that is
/// not a request.
///
/// Every one of the seven request kinds carries a parameter list, so the empty
/// arm is only reached by a caller that is not looking at a request. Section
/// 5.1.3 names five message types a Range Filter may appear in, and this does
/// not narrow to them: a filter parameter arriving where the section does not
/// list it is a scope question, and scope is answered by the parameter registry
/// rather than here. What matters for the ceiling is that a filter this endpoint
/// has no budget for is not accepted, wherever it turned up.
fn request_parameters(msg: &ControlMessage) -> &[KeyValuePair] {
    match msg {
        ControlMessage::Subscribe(m) => &m.parameters,
        ControlMessage::Publish(m) => &m.parameters,
        ControlMessage::Fetch(m) => &m.parameters,
        ControlMessage::PublishNamespace(m) => &m.parameters,
        ControlMessage::SubscribeNamespace(m) => &m.parameters,
        ControlMessage::SubscribeTracks(m) => &m.parameters,
        ControlMessage::TrackStatus(m) => &m.parameters,
        _ => &[],
    }
}

/// The Range Filter parameters in `parameters`, dropping the removals.
///
/// A Range Filter whose value is empty is Section 5.1.3's removal form — "Length
/// can be 0 to remove a filter parameter" — so it names a filter rather than
/// being one, and carrying it forward would leave a filter of no ranges in force
/// for the life of the request.
fn range_filter_parameters(parameters: &[KeyValuePair]) -> Vec<KeyValuePair> {
    parameters
        .iter()
        .filter(|p| range_filter::is_range_filter(p.key.into_inner()))
        .filter(|p| !matches!(&p.value, KvpValue::Bytes(bytes) if bytes.is_empty()))
        .cloned()
        .collect()
}

/// Apply a REQUEST_UPDATE's filter parameters to the set already in force.
///
/// Replacement is by Parameter Type and takes the whole type with it: "non-zero
/// to replace that entire filter parameter including all sets and Property
/// Types". A type the update does not mention is left alone, which is the other
/// half of the same sentence — "If a filter parameter is omitted from
/// REQUEST_UPDATE, the value is unchanged" — and is why this merges rather than
/// measuring the update on its own.
fn apply_filter_update(in_force: &mut Vec<KeyValuePair>, update: &[KeyValuePair]) {
    let mentioned: Vec<u64> = update
        .iter()
        .map(|p| p.key.into_inner())
        .filter(|key| range_filter::is_range_filter(*key))
        .collect();
    in_force.retain(|p| !mentioned.contains(&p.key.into_inner()));
    in_force.extend(range_filter_parameters(update));
}

/// Read a Setup Option's value as a variable-length integer, or 0 if it is
/// absent.
///
/// Zero is also the default every numeric option in Section 10.3.1 takes when
/// it is not sent, so an absent option and an explicit zero mean the same thing
/// and do not need to be told apart.
fn setup_varint(options: &[KeyValuePair], key: u64) -> u64 {
    let key = VarInt::from_u64(key).expect("option key fits a varint");
    options
        .iter()
        .find(|o| o.key == key)
        .and_then(|o| match &o.value {
            KvpValue::Varint(v) => Some(v.into_inner()),
            KvpValue::Bytes(bytes) => {
                let mut cursor = &bytes[..];
                let parsed = VarInt::decode_moqt::<Moqt18>(&mut cursor).ok()?;
                cursor.is_empty().then(|| parsed.into_inner())
            }
        })
        .unwrap_or(0)
}
use crate::draft19::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft19::subscription::{
    SubscriptionError, SubscriptionState, SubscriptionStateMachine,
};
use crate::draft19::track_status::{TrackStatusError, TrackStatusState, TrackStatusStateMachine};
use crate::malformed_tracks::{MalformedTrackCondition, MalformedTracks};
use crate::track_locations::{ObjectLocation, ObjectRole, TrackLocations, TrackObjects};
use moqtap_codec::draft19::error_codes::{
    PublishDoneStatusCode, RequestErrorCode, SessionErrorCode,
};
use moqtap_codec::draft19::message::{
    self, ControlMessage, Fetch, FetchPayload, FetchType, GoAway, MessageType, Publish,
    PublishDone, PublishNamespace, PublishSkipped, RequestError, RequestOk, RequestUpdate, Setup,
    Subscribe, SubscribeNamespace, SubscribeOk, SubscribeTracks,
};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Why a peer's request must be answered with REQUEST_ERROR and INVALID_FILTER.
///
/// Draft-19 gives the Range Filters four rules and answers every one of them
/// the same way — "MUST be rejected with REQUEST_ERROR with error code
/// INVALID_FILTER" — so this says which rule was broken rather than which code
/// to send. [`FilterRejection::request_error_code`] is the code, and it is the
/// same for all four.
///
/// None of these is a session close, which is the whole reason the type exists.
/// A rejection is a reply, and a reply names the Request ID of the request it
/// answers, so the endpoint has to have taken the request in order to refuse it.
/// The rejection is recorded against that id and spent by the REQUEST_ERROR that
/// answers it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterRejection {
    /// The peer sent a Range Filter and this endpoint advertised no budget.
    ///
    /// Section 10.3.1.6: "The default value is 0, so if not specified, the peer
    /// MUST NOT send any such filter parameters." Zero is the default and it
    /// means none allowed — the opposite of what zero means in the option
    /// beside it, MAX_REQUEST_UPDATES, where it means no limit. The two sit in
    /// consecutive subsections and read opposite ways.
    #[error("this endpoint advertised no MAX_FILTER_RANGES, so no range filter is allowed")]
    NoBudgetAdvertised,
    /// More Ranges than MAX_FILTER_RANGES allows, counted across every filter.
    #[error("{ranges} ranges across the request's filters, where {limit} were advertised")]
    TooManyRanges {
        /// The total the request carried.
        ranges: usize,
        /// The total this endpoint advertised.
        limit: u64,
    },
    /// Two filters with the same Parameter Type, SetID and Property Type.
    ///
    /// Repeats of a type are otherwise expected, so the key is the whole triple:
    /// "The Track Property filter parameter MAY appear multiple times in a
    /// SUBSCRIBE_TRACKS message"
    #[error("two filters share parameter type {0:#x}, set {1} and property type {2:?}")]
    RepeatedFilter(u64, u8, Option<u64>),
    /// A filter this codec could not read, or one that broke a rule of its own.
    #[error("a range filter is not usable: {0}")]
    Unreadable(#[from] RangeFilterError),
}

impl FilterRejection {
    /// The REQUEST_ERROR code every one of these is answered with.
    pub fn request_error_code(&self) -> RequestErrorCode {
        RequestErrorCode::InvalidFilter
    }
}

/// Errors that can occur during endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("request ID error: {0}")]
    RequestId(#[from] RequestIdError),
    #[error("subscription error: {0}")]
    Subscription(#[from] SubscriptionError),
    #[error("fetch error: {0}")]
    Fetch(#[from] FetchError),
    #[error("namespace error: {0}")]
    Namespace(#[from] NamespaceError),
    #[error("track status error: {0}")]
    TrackStatus(#[from] TrackStatusError),
    #[error("publish flow error: {0}")]
    PublishFlow(#[from] PublishFlowError),
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),
    #[error("unknown request ID: {0}")]
    UnknownRequest(u64),
    #[error(
        "response message received on control stream; draft-19 responses belong on bidi request streams"
    )]
    ResponseOnControlStream,
    /// A REQUEST_UPDATE arrived on the control stream.
    ///
    /// Draft-19 Table 5 gives REQUEST_UPDATE the Stream value "Request", and
    /// Section 10.9 requires it on the same bidi stream as the request it
    /// modifies. One on the control stream modifies nothing, which makes it a
    /// case Section 10.9 says MUST close the session.
    #[error(
        "REQUEST_UPDATE received on the control stream; it belongs on its request's own stream"
    )]
    RequestUpdateOnControlStream,
    /// A NAMESPACE, NAMESPACE_DONE or PUBLISH_SKIPPED arrived on the control
    /// stream.
    ///
    /// Draft-19 Table 5 gives all three the Stream value "Request": NAMESPACE
    /// (0x8, Section 10.16) and NAMESPACE_DONE (0xE, Section 10.17) belong on
    /// the SUBSCRIBE_NAMESPACE request stream whose namespace they report, and
    /// PUBLISH_SKIPPED (0xF, Section 10.20) on the SUBSCRIBE_TRACKS stream
    /// whose namespace it names a skipped track in — "All PUBLISH_SKIPPED
    /// messages are in response to a SUBSCRIBE_TRACKS". Only SETUP is
    /// "Control" alone; GOAWAY is the one message the
    /// table lists as "Control, Request". One of these three on the control
    /// stream names no request, so nothing can be done with it.
    #[error("{0} received on the control stream; draft-19 Table 5 places it on a request stream")]
    RequestMessageOnControlStream(&'static str),
    /// A REQUEST_UPDATE named a request that cannot be updated, or none.
    ///
    /// Draft-19 Section 10.9: "An endpoint that receives a REQUEST_UPDATE
    /// other than in the two cases above MUST close the session with a
    /// PROTOCOL_VIOLATION." TRACK_STATUS is called out in Section 10.14 as one
    /// such case: "the subscriber cannot send REQUEST_UPDATE."
    #[error("REQUEST_UPDATE for request {0}, which is not an updatable outstanding request")]
    UnexpectedRequestUpdate(u64),
    /// Track Properties on a REQUEST_OK answering something other than a
    /// TRACK_STATUS.
    ///
    /// Draft-19 Section 10.5: they "are empty in PUBLISH_OK,
    /// REQUEST_UPDATE_OK, SUBSCRIBE_NAMESPACE_OK and PUBLISH_NAMESPACE_OK. If
    /// an endpoint receives Track Properties in one of these messages it MUST
    /// close the session with a PROTOCOL_VIOLATION."
    #[error(
        "track properties on the REQUEST_OK answering request {0}, which is not a TRACK_STATUS"
    )]
    TrackPropertiesOnNonTrackStatus(u64),
    /// A server received a Redirect naming a Connect URI.
    ///
    /// Draft-19 Section 10.6.1: "If a server receives a Redirect with a
    /// non-zero Connect URI Length it MUST close the session with a
    /// PROTOCOL_VIOLATION." As with GOAWAY, only a client is redirected.
    #[error("Redirect carrying a Connect URI received at a server")]
    RedirectUriAtServer,
    /// A Redirect answering a namespace-scoped request carried a Track Name.
    ///
    /// Draft-19 Section 10.6.1: "Track Name is not meaningful for
    /// namespace-scoped requests (SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE,
    /// SUBSCRIBE_TRACKS) and MUST be empty; an endpoint that receives a
    /// non-empty Track Name in a Redirect for a namespace-scoped request MUST
    /// close the session with a PROTOCOL_VIOLATION." Draft-18 names the same
    /// rule with SUBSCRIBE_TRACKS left out of the list.
    #[error("Redirect for namespace-scoped request {0} carries a track name")]
    RedirectTrackNameOnNamespaceRequest(u64),
    /// A server received a GOAWAY carrying a New Session URI.
    ///
    /// Draft-19 Section 10.4: "If a server receives a GOAWAY with a non-zero
    /// New Session URI Length it MUST close the session with a
    /// PROTOCOL_VIOLATION." Only a client can be redirected.
    #[error("GOAWAY carrying a New Session URI received at a server")]
    GoAwayUriAtServer,
    /// The peer reused a Request ID it had already spent.
    ///
    /// Draft-19 Section 10.1: "If an endpoint receives a Request ID where the
    /// least significant bit is incorrect for the sender, or a duplicate
    /// Request ID, it MUST close the session with INVALID_REQUEST_ID."
    #[error("request {0} was already used by the peer")]
    DuplicateRequestId(u64),
    /// A bidirectional stream the peer opened began with a message that does
    /// not open a request stream.
    ///
    /// Draft-19 Section 3.3: "Bidirectional streams MUST NOT begin with any
    /// other message type unless negotiated. If they do, the peer MUST close
    /// the Session with a PROTOCOL_VIOLATION."
    #[error("{0:?} does not begin a request stream")]
    NotARequest(MessageType),
    /// A message that this endpoint may not write on a request stream the peer
    /// opened was handed to the responder path. Nothing was written and no
    /// state moved.
    #[error("{0:?} is not a message a responder writes on a peer's request stream")]
    NotAResponse(MessageType),
    /// A message arrived on a request stream the peer opened that may not
    /// follow a request there.
    ///
    /// This endpoint is the responder on such a stream, so a response arriving
    /// on it is the peer answering its own request.
    #[error("{0:?} may not follow a request on a stream the peer opened")]
    UnexpectedOnPeerRequestStream(MessageType),
    /// A namespace-scoped request's response half opened with something other
    /// than REQUEST_OK or REQUEST_ERROR.
    ///
    /// Draft-19 Sections 10.18 and 10.19, of SUBSCRIBE_NAMESPACE and
    /// SUBSCRIBE_TRACKS alike: "The publisher will respond with REQUEST_OK or
    /// REQUEST_ERROR on the response half of the stream. If the subscriber
    /// receives any message other than a REQUEST_OK or a REQUEST_ERROR as the
    /// first message on the response half of the stream, then it MUST close the
    /// session with a PROTOCOL_VIOLATION."
    #[error("request {0} answered with {1:?} before its REQUEST_OK or REQUEST_ERROR")]
    ResponseBeforeTheFirstResponse(u64, MessageType),
    /// Track Properties were put on a REQUEST_OK answering something other
    /// than a TRACK_STATUS, on the way out. Nothing was written.
    ///
    /// The send-side mirror of
    /// [`TrackPropertiesOnNonTrackStatus`](Self::TrackPropertiesOnNonTrackStatus):
    /// Section 10.5 answers receiving them with a session close, so writing
    /// them would hand a conforming peer a reason to close this session. This
    /// one is not fatal — nothing reached the wire, so there is nothing for the
    /// peer to object to.
    #[error("request {0} is not a TRACK_STATUS; only its response carries track properties")]
    TrackPropertiesOnOutgoingRequestOk(u64),
    /// A REQUEST_UPDATE arrived on a stream that had already used up the
    /// concurrency this endpoint advertised.
    ///
    /// Draft-19 Section 10.3.1.7: "If an endpoint receives a REQUEST_UPDATE on
    /// a stream that already has MAX_REQUEST_UPDATES outstanding
    /// REQUEST_UPDATEs, it MUST close the session with
    /// TOO_MANY_REQUEST_UPDATES."
    #[error("request {0} already has the {1} outstanding REQUEST_UPDATEs it was allowed")]
    TooManyRequestUpdates(u64, u64),
    /// A REQUEST_OK was offered for a request whose Range Filters this endpoint
    /// is required to reject.
    ///
    /// Not fatal, and deliberately not raised where the filter arrives. Every
    /// Range Filter rule in Section 5.1.3 is answered with a REQUEST_ERROR, and
    /// a REQUEST_ERROR names the Request ID of the request it answers — so the
    /// request has to be taken before it can be refused. What this stops is the
    /// other answer: accepting the request the draft says to reject leaves the
    /// subscriber with a subscription whose filters this endpoint never agreed
    /// to apply, and a publisher that then forwards by its own reading of them.
    #[error("request {0} must be answered with REQUEST_ERROR: {1}")]
    FilterMustBeRejected(u64, FilterRejection),
    /// A REQUEST_OK or REQUEST_ERROR was offered as the answer to a
    /// REQUEST_UPDATE on a stream with no update waiting for one.
    ///
    /// Section 10.9 requires "exactly one REQUEST_OK or REQUEST_ERROR message
    /// indicating if the update was successful", so an answer with nothing to
    /// answer is one the peer will read as belonging to an update it never
    /// sent. Not fatal: nothing was written.
    ///
    /// A SUBSCRIBE is answered with SUBSCRIBE_OK and a FETCH with FETCH_OK, so
    /// on those two streams a REQUEST_OK can be nothing but an update's answer
    /// and this is what a mistimed one produces. On the five kinds REQUEST_OK
    /// answers itself, the first one is the request's and only the ones after
    /// it can reach here.
    #[error("request {0} has no REQUEST_UPDATE waiting for an answer")]
    NoUpdateToAnswer(u64),
    /// An update was refused and the subscription it belongs to was then ended
    /// under some status other than the one that names why.
    ///
    /// Section 10.9.1: "When a REQUEST_UPDATE is unsuccessful, the publisher MUST
    /// also terminate the subscription by sending a PUBLISH_DONE with error
    /// code UPDATE_FAILED." The REQUEST_ERROR is half of what that sentence
    /// asks for and the termination is the other half, so this endpoint holds
    /// the request to it: whatever else the caller writes first, the
    /// termination it does write says so.
    #[error("request {request}'s update was refused, so its PUBLISH_DONE must carry {required}")]
    WrongUpdateFailureStatus {
        /// The request whose update was refused.
        request: u64,
        /// The status code the termination must carry.
        required: u64,
    },
    #[error("session not active")]
    NotActive,
    #[error("session is draining, no new requests allowed")]
    Draining,
    /// A second GOAWAY arrived on the control stream.
    ///
    /// The GOAWAY that says the peer is going away is one message, and the
    /// draft answers a repeat of it with a session close rather than with an
    /// error about the second message: there is no state a second one could
    /// move that the first has not already moved.
    #[error("a second GOAWAY arrived on the control stream")]
    RepeatedGoAway,
    /// A second GOAWAY arrived on one request's stream.
    ///
    /// The count is per stream rather than per session: this draft lets a
    /// GOAWAY migrate a single request, so one on each of two request streams
    /// is two first GOAWAYs and not a repeat.
    #[error("a second GOAWAY arrived on request {0}'s stream")]
    RepeatedGoAwayOnRequestStream(
        /// The Request ID of the stream that carried both.
        u64,
    ),
    /// The peer named a Track Alias it is already using for another track.
    ///
    /// Draft-19 Section 11.1: "The same Track Alias MUST NOT be used by a
    /// publisher to refer to two different Tracks simultaneously in the same
    /// session. If a subscriber receives a PUBLISH or SUBSCRIBE_OK that uses
    /// the same Track Alias as a different Track with an Established
    /// subscription, it MUST close the session with error
    /// DUPLICATE_TRACK_ALIAS."
    ///
    /// The session is over: this endpoint's own state has moved to Closed and
    /// the code the transport should close with is in
    /// [`EndpointError::session_error_code`].
    #[error("track alias {alias} already names request {established}'s track; request {offered} names a different one")]
    DuplicateTrackAlias {
        /// The alias both tracks are named by.
        alias: u64,
        /// The request whose Established subscription holds the alias.
        established: u64,
        /// The request whose message arrived naming it for another track.
        offered: u64,
    },
    /// This endpoint was asked to give a Track Alias to a second track.
    ///
    /// The same rule as [`EndpointError::DuplicateTrackAlias`] read at the end
    /// that chooses the alias. Section 11.1 states it as a prohibition on the
    /// publisher before it states what the subscriber does about one: "The
    /// same Track Alias MUST NOT be used by a publisher to refer to two different Tracks
    /// simultaneously in the same session."
    ///
    /// The message is refused instead of built, and nothing else moves: no
    /// Request ID is spent, no publish flow is created, and the session stays
    /// as it was. The alias never reaches the peer, so there is nothing for
    /// the peer to close over.
    #[error("track alias {alias} already names request {held}'s track")]
    TrackAliasInUse {
        /// The alias that is already spoken for.
        alias: u64,
        /// The request whose live flow holds it.
        held: u64,
    },
    /// An object arriving after the track's final object.
    ///
    /// Section 2.4.2 lists the condition: "An Object is received whose
    /// Group and Object ID are larger
    /// than the final Object in the Track.
    /// The final Object in a Track is the Object with Status END_OF_TRACK or
    /// the last Object sent in a FETCH whose response indicated End of Track."
    ///
    /// **Larger is Section 1.4.2's comparison and not a reading of the
    /// words.** That section puts one Location below another when "A.Group <
    /// B.Group || (A.Group == B.Group && A.Object < B.Object)", so an Object in
    /// a later group is past the end whatever its own Object ID is.
    ///
    /// **A Malformed Track and not a session error**, and on this draft not a
    /// message either. Section 2.4.2 answers its whole list at once with "it
    /// MUST cancel any corresponding subscription or fetches for that Track
    /// from that publisher", where cancelling a request is the transport
    /// operation Section 3.3.3 describes. This is the error half; the
    /// requests to cancel are named by
    /// [`Endpoint::requests_for_malformed_track`].
    #[error(
        "the object at group {group}, object {object} on track alias {alias} arrived \
         after the track's final object at group {final_group}, object {final_object}"
    )]
    ObjectPastFinalObject {
        /// The Track Alias the offending object named.
        alias: u64,
        /// The Group ID it named.
        group: u64,
        /// The Object ID it named.
        object: u64,
        /// The Group ID of the object the track ended at.
        final_group: u64,
        /// The Object ID of the object the track ended at.
        final_object: u64,
    },

    /// A Joining Fetch named a subscription this session cannot join.
    ///
    /// Section 10.12.2:
    /// "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to a subscription in the same session in the
    /// Established or Pending (subscriber) states, it MUST return a
    /// REQUEST_ERROR with error code INVALID_JOINING_REQUEST_ID."
    ///
    /// A refusal and not a session close, so the session runs on and the error
    /// names both identifiers: the fetch to refuse, and the subscription it
    /// asked to join.
    #[error("FETCH {fetch} joins request {joining}, which is no live subscription of the peer's")]
    UnjoinableSubscription {
        /// The fetch that named it.
        fetch: u64,
        /// The identifier it named.
        joining: u64,
    },

    /// A Joining Fetch was refused under a code other than the one the same
    /// sentence names for it.
    ///
    /// The reason travels with the refusal, so a subscriber told the wrong one
    /// retries the wrong thing: it can rebuild a fetch whose range was refused,
    /// and cannot rebuild one whose subscription is gone.
    #[error("refusing FETCH {fetch} for the subscription it joins takes error code {required}")]
    WrongJoiningRefusal {
        /// The fetch being refused.
        fetch: u64,
        /// The code the draft names for that refusal.
        required: u64,
    },
    /// The peer subscribed to a namespace prefix overlapping one it is
    /// already subscribed to.
    ///
    /// Section 10.18: "Within a session, if a publisher receives a
    /// SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that shares a common
    /// prefix with an established SUBSCRIBE_NAMESPACE, it MUST respond with
    /// REQUEST_ERROR with error code PREFIX_OVERLAP."
    ///
    /// Section 10.19: "Within a session, if a publisher receives a
    /// SUBSCRIBE_TRACKS with a Track Namespace Prefix that shares a common
    /// prefix with an established SUBSCRIBE_TRACKS, it MUST respond with
    /// REQUEST_ERROR with error code PREFIX_OVERLAP."
    ///
    /// Section 10.6.2: "SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS have
    /// independent overlap spaces, so a SUBSCRIBE_NAMESPACE and a
    /// SUBSCRIBE_TRACKS may share the same prefix."
    ///
    /// Taken when the message arrives, which is the moment the sentence
    /// names, and read again when an answer is built: a request this endpoint
    /// may not accept is one no later call can accept.
    ///
    /// The refusal itself is not this error. It is a message the peer is
    /// owed, so the request is recorded like any other and refused through
    /// the same call that refuses any other, under the code the sentence
    /// names.
    #[error(
        "request {request} subscribes to a namespace prefix overlapping request {established}"
    )]
    PeerPrefixOverlap {
        /// The request that arrived.
        request: u64,
        /// The namespace subscription it overlaps.
        established: u64,
    },
    /// A namespace subscription that overlaps another was refused under a
    /// code other than the one the sentence names.
    ///
    /// The same shape as [`EndpointError::WrongJoiningRefusal`]: a rule that
    /// names the code its refusal carries is not satisfied by a refusal under
    /// any other, because the peer reads the code to learn what went wrong.
    #[error("request {request} overlaps a namespace subscription and must be refused with code {required:#x}")]
    WrongOverlapRefusal {
        /// The request being refused.
        request: u64,
        /// The code the sentence names for it.
        required: u64,
    },
}

/// Whether two namespace prefixes overlap.
///
/// Section 10.18: "Within a session, if a publisher receives a
/// SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that shares a common
/// prefix with an established SUBSCRIBE_NAMESPACE, it MUST respond with
/// REQUEST_ERROR with error code PREFIX_OVERLAP."
///
/// Section 10.19: "Within a session, if a publisher receives a
/// SUBSCRIBE_TRACKS with a Track Namespace Prefix that shares a common prefix
/// with an established SUBSCRIBE_TRACKS, it MUST respond with REQUEST_ERROR
/// with error code PREFIX_OVERLAP."
///
/// Section 10.6.2: "SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS have independent
/// overlap spaces, so a SUBSCRIBE_NAMESPACE and a SUBSCRIBE_TRACKS may share
/// the same prefix."
///
/// A namespace matches a namespace subscription when the subscription's
/// prefix is a prefix of it, so two prefixes select overlapping sets of
/// namespaces exactly when one of them is a prefix of the other. Equal
/// prefixes are that case as well: every prefix is a prefix of itself, and
/// two equal ones select the same set.
///
/// "Shares a common prefix with" is read as the relation drafts 07 through 14
/// spell out at greater length. Taken at its word it would forbid every
/// second namespace subscription in a session, since any two prefixes share
/// the empty one, and nothing else in this draft supports that.
fn prefixes_overlap(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    let shared = a.len().min(b.len());
    a[..shared] == b[..shared]
}

/// Parameter Type of TRACK_NAMESPACE_PREFIX.
const TRACK_NAMESPACE_PREFIX: u64 = 0x34;

/// The Track Namespace Prefix a REQUEST_UPDATE asks a namespace subscription
/// to move to, and `None` when it asks for no such move.
///
/// Section 10.2.19: "The TRACK_NAMESPACE_PREFIX parameter (Parameter Type
/// 0x34) uses the Track Namespace encoding described in Section 2.4.1. It MAY
/// appear in REQUEST_UPDATE for a SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS
/// request. It updates the Track Namespace Prefix for that subscription."
///
/// A prefix of no fields is a value rather than a removal. Section 2.4.1 puts
/// a Track Namespace at "between 0 and 32 Track Namespace Fields", an empty
/// prefix selects every namespace, and Section 10.9 leaves no other reading
/// open: "There is no mechanism to remove a parameter from a request."
///
/// The last one wins when a message carries the parameter twice. That is the
/// rule Section 10.9 gives for two messages -- "Parameter values from later
/// REQUEST_UPDATE messages override values from earlier ones" -- applied
/// inside one, which is the only reading under which a repeat means anything.
///
/// A value that is not a whole Track Namespace answers `None`, so an update
/// carrying one leaves the prefix where it was. The decoder that built the
/// message has already refused a malformed one; this is the arm that keeps a
/// hand-built message from moving a subscription to half a prefix.
fn updated_prefix(parameters: &[KeyValuePair]) -> Option<TrackNamespace> {
    parameters.iter().rfind(|p| p.key.into_inner() == TRACK_NAMESPACE_PREFIX).and_then(|p| match &p
        .value
    {
        KvpValue::Bytes(bytes) => {
            let mut cursor = &bytes[..];
            let prefix = TrackNamespace::decode_allow_empty_moqt::<Moqt18>(&mut cursor).ok()?;
            cursor.is_empty().then_some(prefix)
        }
        KvpValue::Varint(_) => None,
    })
}

impl EndpointError {
    /// Whose doing this is — the peer's, or this endpoint's, or a variant that
    /// cannot say.
    ///
    /// The companion of [`EndpointError::session_error_code`], which answers
    /// *what the draft requires be done about it*. Neither answers the other's
    /// question and the pair is what a caller needs: a code without a side
    /// names nobody, and a side without a code is not grounds to publish
    /// anything.
    ///
    /// Exhaustive, with no wildcard arm, so a variant added to this draft's
    /// `EndpointError` is a compile error here rather than a silent arrival on
    /// the wrong side of the answer. See
    /// [`EndpointFault`](crate::above_codec_rules::EndpointFault) for the three
    /// answers and for the collision that made the third one necessary.
    pub fn fault(&self) -> crate::above_codec_rules::EndpointFault {
        use crate::above_codec_rules::{AboveCodecRule as Rule, EndpointFault as Fault};

        match self {
            // Raised on both a receive path and a send path, so the
            // variant cannot say which end is at fault. The state machines
            // render as `invalid transition from X on event Y` whichever end
            // asked for the transition, and the unknown-request errors name
            // an id that may be one the peer sent or one a caller here made
            // up.
            EndpointError::Session(..)
            | EndpointError::Subscription(..)
            | EndpointError::Fetch(..)
            | EndpointError::Namespace(..)
            | EndpointError::TrackStatus(..)
            | EndpointError::PublishFlow(..)
            | EndpointError::Setup(..)
            | EndpointError::UnknownRequest(..) => Fault::EitherEnd,

            // Raised on the way out. Nothing reached the wire, so none of
            // these is evidence about a peer — including the ones a peer
            // caused, where what failed is this side's attempt to accept
            // something the draft says to refuse.
            EndpointError::NotAResponse(..)
            | EndpointError::TrackPropertiesOnOutgoingRequestOk(..)
            | EndpointError::FilterMustBeRejected(..)
            | EndpointError::NoUpdateToAnswer(..)
            | EndpointError::WrongUpdateFailureStatus { .. }
            | EndpointError::NotActive
            | EndpointError::Draining
            | EndpointError::TrackAliasInUse { .. }
            | EndpointError::UnjoinableSubscription { .. }
            | EndpointError::WrongJoiningRefusal { .. }
            | EndpointError::PeerPrefixOverlap { .. }
            | EndpointError::WrongOverlapRefusal { .. } => Fault::ThisEndpoint,

            // Raised reading what the peer sent.
            EndpointError::NotARequest(..) => Fault::Peer(Rule::BidiStreamOpener),
            EndpointError::DuplicateTrackAlias { .. } => Fault::Peer(Rule::DuplicateTrackAlias),
            EndpointError::GoAwayUriAtServer => Fault::Peer(Rule::GoAwayAtServer),
            EndpointError::ResponseOnControlStream
            | EndpointError::RequestMessageOnControlStream(..)
            | EndpointError::UnexpectedOnPeerRequestStream(..) => {
                Fault::Peer(Rule::MessageOnTheWrongStream)
            }
            EndpointError::ObjectPastFinalObject { .. } => Fault::Peer(Rule::ObjectPastFinalObject),
            EndpointError::RedirectTrackNameOnNamespaceRequest(..) => {
                Fault::Peer(Rule::RedirectTrackNameOnNamespaceRequest)
            }
            EndpointError::RedirectUriAtServer => Fault::Peer(Rule::RedirectUriAtServer),
            EndpointError::RepeatedGoAway | EndpointError::RepeatedGoAwayOnRequestStream(..) => {
                Fault::Peer(Rule::RepeatedGoAway)
            }
            EndpointError::DuplicateRequestId(..) => Fault::Peer(Rule::RequestIdOutOfSequence),
            // A REQUEST_UPDATE on the control stream is this rule and not
            // `MessageOnTheWrongStream`. Section 10.9 states the rule as two
            // permitted cases and closes over everything else — "The sender of
            // a request (SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
            // SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) can later send a
            // REQUEST_UPDATE on the same bidi stream as the request to modify
            // it. A subscriber can also send REQUEST_UPDATE to modify
            // parameters of a subscription established with PUBLISH." — and
            // the first case is *on the same bidi stream as the request*. One
            // that arrives on the control stream is in neither case, so it is
            // squarely inside "other than in the two cases above", which is the
            // sentence this rule cites. Filed under the wrong-stream rule it
            // would carry a close no draft states; filed here, it carries the
            // one draft-19 and draft-20 do.
            EndpointError::RequestUpdateOnControlStream
            | EndpointError::UnexpectedRequestUpdate(..) => {
                Fault::Peer(Rule::RequestUpdateForTheWrongRequest)
            }
            EndpointError::ResponseBeforeTheFirstResponse(..) => {
                Fault::Peer(Rule::ResponseBeforeItsFirstResponse)
            }
            EndpointError::TooManyRequestUpdates(..) => Fault::Peer(Rule::TooManyRequestUpdates),
            EndpointError::TrackPropertiesOnNonTrackStatus(..) => {
                Fault::Peer(Rule::TrackPropertiesOnNonTrackStatus)
            }

            // The Request ID rules, which are the peer's: every one of them is
            // read off an id the peer put on the wire. This draft carries no
            // MAX_REQUEST_ID, so neither ceiling arm can fire — the allocator
            // opens at `u64::MAX` and nothing ever lowers it - and they are
            // answered rather than left out so that a draft restoring the
            // message does not restore a hole with it.
            EndpointError::RequestId(e) => match e {
                RequestIdError::Decreased(..) => Fault::Peer(Rule::MaxRequestIdDecreased),
                RequestIdError::ExceedsMax(..) => Fault::Peer(Rule::RequestIdCeiling),
                RequestIdError::WrongParity(..) => Fault::Peer(Rule::RequestIdParity),
                // This endpoint has spent the budget the peer granted it.
                RequestIdError::Blocked => Fault::ThisEndpoint,
            },
        }
    }

    /// The code to close the session with, when draft-19 says this error is
    /// fatal to the session rather than to one request.
    ///
    /// `None` means the error is recoverable: the caller may report it and
    /// keep the session running. `Some` means the draft requires a close, and
    /// the endpoint has already moved its own session state to
    /// [`SessionState::Closed`] — the code is what the transport should carry.
    ///
    /// The two codes are not interchangeable. Section 3.3 gives
    /// PROTOCOL_VIOLATION for a bidirectional stream that begins with the wrong
    /// message type; Section 10.1 gives INVALID_REQUEST_ID for a Request ID
    /// with the wrong least significant bit or a duplicate one. A peer checking
    /// close codes can tell the two apart, so this must too.
    pub fn session_error_code(&self) -> Option<SessionErrorCode> {
        match self {
            EndpointError::RequestUpdateOnControlStream
            | EndpointError::UnexpectedRequestUpdate(_)
            | EndpointError::TrackPropertiesOnNonTrackStatus(_)
            | EndpointError::RedirectUriAtServer
            | EndpointError::RedirectTrackNameOnNamespaceRequest(_)
            | EndpointError::ResponseBeforeTheFirstResponse(..)
            | EndpointError::NotARequest(_)
            | EndpointError::GoAwayUriAtServer
            | EndpointError::RepeatedGoAway
            | EndpointError::RepeatedGoAwayOnRequestStream(_) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            EndpointError::DuplicateRequestId(_)
            | EndpointError::RequestId(RequestIdError::WrongParity(..)) => {
                Some(SessionErrorCode::InvalidRequestId)
            }
            EndpointError::TooManyRequestUpdates(..) => {
                Some(SessionErrorCode::TooManyRequestUpdates)
            }
            // Section 11.1 names this code in the sentence that states the
            // rule, and names no other. A close carrying PROTOCOL_VIOLATION
            // would tell the peer a different thing went wrong.
            EndpointError::DuplicateTrackAlias { .. } => {
                Some(SessionErrorCode::DuplicateTrackAlias)
            }
            // Stated rather than left to the arm below, because the neighbour
            // above makes the opposite choice about a rule of the same shape.
            // MAX_REQUEST_UPDATES is a ceiling the draft answers with a session
            // close; MAX_FILTER_RANGES is a ceiling it answers with a
            // REQUEST_ERROR. Two consecutive subsections, two different answers,
            // and nothing about either sentence signals which.
            EndpointError::FilterMustBeRejected(..) => None,
            _ => None,
        }
    }
}

pub struct Endpoint {
    role: Role,
    session: SessionStateMachine,
    request_ids: RequestIdAllocator,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    fetches: HashMap<u64, FetchStateMachine>,
    /// Every Joining Fetch the peer sent naming a subscription this session
    /// had none live for, and the identifier each one named.
    ///
    /// Judged as the FETCH arrives, because that is the moment the rule about
    /// it names, and kept for as long as the fetch is: a subscription that
    /// ends between the FETCH and its answer does not turn a fetch that could
    /// be joined into one that could not.
    unjoinable_fetches: HashMap<u64, u64>,
    subscribe_namespaces: HashMap<u64, SubscribeNamespaceStateMachine>,
    subscribe_tracks: HashMap<u64, SubscribeNamespaceStateMachine>,
    publish_namespaces: HashMap<u64, PublishNamespaceStateMachine>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    publishes: HashMap<u64, PublishStateMachine>,
    goaway_uri: Option<Vec<u8>>,
    /// The peer's requests whose stream has already carried a GOAWAY.
    ///
    /// Section 10.4 makes the second GOAWAY on one request stream a session
    /// close while leaving a first one on every other stream legal, so the
    /// count cannot live on the session. Held apart from the per-kind request
    /// maps because a GOAWAY says nothing about which kind of request it
    /// migrates.
    goaway_request_streams: HashSet<u64>,
    /// Every Request ID the peer has spent, whether or not the request it
    /// opened is still live.
    ///
    /// Draft-19 Section 10.1 makes a duplicate Request ID a session close, and
    /// "duplicate" is about the id ever having been used, not about the
    /// request still being open. Deriving it from the per-kind maps instead
    /// would answer wrongly the moment those maps are ever pruned, so the rule
    /// is stated once, here, and this set is never pruned.
    peer_request_ids: HashSet<u64>,
    /// Every request the **peer** opened a stream with, as it arrived, keyed
    /// by the Request ID it carries.
    ///
    ///
    /// One map for all seven kinds, because one entry point takes all seven:
    /// [`receive_request_on_stream`](Self::receive_request_on_stream) is the
    /// only thing that writes here, so what is in here is a request, and it
    /// is the peer's, by construction. How far each one has got stays in the
    /// per-kind map beside this endpoint's own requests, which is where every
    /// later message on the stream reads it and where the parity of a Request
    /// ID keeps the two ends apart.
    ///
    /// What a map of state machines cannot hold is the request. Section 5.1 has
    /// the subscriber "either accepts or rejects the subscription", and what is
    /// being accepted or rejected -- the track, the namespace prefix, the
    /// parameters -- is named in the request and nowhere else once the message
    /// has been dropped.
    inbound_requests: HashMap<u64, ControlMessage>,
    /// The request each namespace subscription of the peer's overlapped when
    /// it arrived, keyed by the Request ID of the one that arrived.
    ///
    /// The prefix is judged where the sentence says it is judged, on receipt,
    /// and the verdict is read again when the answer is written. An entry
    /// means this endpoint owes that request a REQUEST_ERROR and may send it
    /// nothing else.
    overlapping_namespace_subscriptions: HashMap<u64, u64>,
    /// The Track Namespace Prefix a REQUEST_UPDATE asks one of the peer's
    /// namespace subscriptions to move to, held until that update is
    /// answered.
    ///
    /// Section 10.9.2 ties the move to the acceptance: "If the update is
    /// accepted, NAMESPACE and NAMESPACE_DONE messages following the
    /// REQUEST_OK will contain Track Namespace suffixes relative to the
    /// updated prefix." Until then the subscription still selects what the
    /// peer opened it with, so a later request is weighed against the prefix
    /// in `inbound_requests` and not against this one.
    updated_namespace_prefixes: HashMap<u64, TrackNamespace>,
    /// The subscription an unanswered prefix update would collide with, when
    /// it would, keyed by the Request ID of the one being moved.
    ///
    /// Separate from `overlapping_namespace_subscriptions` because one
    /// Request ID can be carrying both verdicts at once: the request that
    /// opened the stream has one and an update on it has another, and they
    /// are settled by different messages on that same stream.
    overlapping_prefix_updates: HashMap<u64, u64>,
    /// The MAX_REQUEST_UPDATES this endpoint put in its own SETUP.
    ///
    /// The peer's value is a different number and belongs to the sending side,
    /// which this type has no path for: draft-19 gives the endpoint no
    /// REQUEST_UPDATE builder, so there is nothing here to hold back.
    ///
    /// Zero means no limit rather than none allowed, which is the opposite of
    /// how MAX_REQUEST_ID reads. Section 10.3.1.7 says so outright - "A value
    /// of 0 means the endpoint does not limit REQUEST_UPDATE concurrency. If
    /// not present, the default value is 0" - so an endpoint that never sends
    /// the option is not limiting anything, and a check that read zero as a
    /// ceiling would refuse the first update of every session.
    advertised_max_request_updates: u64,
    /// Per request stream, how many REQUEST_UPDATEs the peer has sent that this
    /// endpoint has not yet answered.
    ///
    /// "Outstanding" is Section 10.3.1.7's word and it is per stream, not per
    /// session: "Each REQUEST_OK or REQUEST_ERROR response restores one credit
    /// on that stream."
    outstanding_peer_updates: HashMap<u64, u64>,
    /// Per request stream, how many REQUEST_UPDATEs are still waiting for the
    /// answer Section 10.9 requires.
    ///
    /// A second count rather than a reading of the one above, because the two
    /// sentences count different things and disagree on exactly one response.
    /// Section 10.3.1.7 says "Each REQUEST_OK or REQUEST_ERROR response
    /// restores one credit on that stream" — every response, including the
    /// REQUEST_OK that answers a SUBSCRIBE_NAMESPACE rather than an update. That
    /// is the sender's accounting rule as much as the receiver's, and an
    /// endpoint that credited more carefully than the peer does would close a
    /// conforming session, so the credit above stays literal.
    ///
    /// This one is about which response answers which message, and there the
    /// request's own REQUEST_OK answers the request. Keeping them apart is what
    /// lets a response be recognised as an update's answer without changing
    /// what the peer is allowed to send.
    unanswered_peer_updates: HashMap<u64, u64>,
    /// The requests whose refused update has not been followed by the
    /// PUBLISH_DONE that ends them.
    ///
    /// Emptied as each is written. A request is in here for exactly as long as
    /// this endpoint owes the peer the second half of a refusal.
    owed_update_failures: HashSet<u64>,
    /// The peer's requests whose own response has already been written.
    ///
    /// Section 10.9 gives an update the same two answers a request has, and on
    /// the five kinds REQUEST_OK answers, the message that answers the request
    /// and the message that answers an update are the same message. Nothing on
    /// the wire tells them apart, so both endpoints resolve it by order: the
    /// first response on a stream answers the request that opened it and the
    /// ones after it answer updates. This set is that order, recorded.
    answered_peer_requests: HashSet<u64>,
    /// The MAX_FILTER_RANGES this endpoint put in its own SETUP.
    ///
    /// Section 10.3.1.6: "The MAX_FILTER_RANGES option (Type 0x06) limits the
    /// peer's total number of Ranges (Start/End pairs) allowed concurrently in
    /// all Range filter parameters for a given subscription or fetch. The
    /// default value is 0, so if not specified, the peer MUST NOT send any such
    /// filter parameters."
    ///
    /// So zero is none allowed, and it is the default. The option in the
    /// subsection after this one, MAX_REQUEST_UPDATES, reads its zero the other
    /// way — no limit — and the two are otherwise the same shape. Reading either
    /// with the other's rule is a working implementation that is wrong in one
    /// direction or the other for every session.
    advertised_max_filter_ranges: u64,
    /// Requests whose Range Filters this endpoint owes the peer a REQUEST_ERROR
    /// about.
    ///
    /// Keyed by Request ID, because that is what the reply names. Entries are
    /// spent by the REQUEST_ERROR that answers them, and a REQUEST_OK offered
    /// for one is refused: taking the request in and then accepting it would
    /// leave the peer with a subscription whose filters were never agreed.
    peer_filter_rejections: HashMap<u64, FilterRejection>,
    /// The Range Filter parameters currently in force on each of the peer's
    /// requests.
    ///
    /// Section 5.1.3 makes the ceiling a property of the request rather than of
    /// the message that carried it — "the total number of Ranges allowed
    /// concurrently in all Range filter parameters for a given subscription or
    /// fetch" — and lets a REQUEST_UPDATE rewrite the set: "Length can be 0 to
    /// remove a filter parameter or non-zero to replace that entire filter
    /// parameter including all sets and Property Types. If a filter parameter is
    /// omitted from REQUEST_UPDATE, the value is unchanged."
    ///
    /// So the count that matters is of what is in force after the update, and
    /// the parameters an update leaves alone are part of it. Held as the
    /// parameters rather than as decoded filters because replacement is by
    /// Parameter Type, which is the key of the pair.
    peer_request_filters: HashMap<u64, Vec<KeyValuePair>>,
    /// What Full Track Name the peer has attached each Track Alias to, per
    /// Request ID.
    ///
    /// Section 11.1 forbids one alias naming two tracks at once, and the "at
    /// once" is what makes this a table rather than a set: an alias the peer
    /// used for a track whose subscription has ended is free again. The table
    /// therefore records the binding and reads liveness back off the request's
    /// own state machine, rather than keeping a second copy of it that every
    /// path ending a subscription would have to remember to prune.
    track_bindings: HashMap<u64, TrackBinding>,
    /// The track each fetch this endpoint made is for.
    ///
    /// Not in `track_bindings`, because that table exists to answer questions
    /// about Track Aliases and a fetch has none: its objects arrive on a stream
    /// that opens by naming the Request ID. A Joining Fetch names no track
    /// either and takes the joined subscription's, resolved as the fetch is
    /// made rather than at the withdrawal - one fills a buffer behind the live
    /// edge and outlives the subscription it joined, so a lookup through the
    /// join would come up empty exactly while there was still a fetch to
    /// cancel.
    fetch_tracks: HashMap<u64, FetchTrack>,
    /// Which tracks this endpoint has given up on, and what for.
    ///
    /// Behind a lock because the note is taken on the data plane, where this
    /// endpoint is reached through `&self`.
    malformed: Mutex<MalformedTracks>,
    /// How far each track's objects have reached, and where a track ended.
    ///
    /// An `Arc` because a subgroup stream measures its objects against one
    /// track for as long as it runs, and the handle it holds outlives any
    /// single call into this endpoint.
    locations: Arc<Mutex<TrackLocations>>,
}

/// The track one fetch is for, which the fetch's own state machine does not
/// hold.
#[derive(Debug, Clone)]
struct FetchTrack {
    namespace: TrackNamespace,
    name: Vec<u8>,
}

/// A Track Alias the peer has attached to a Full Track Name, and the request
/// whose lifetime the attachment follows.
#[derive(Debug, Clone)]
struct TrackBinding {
    namespace: TrackNamespace,
    name: Vec<u8>,
    /// The alias, once the peer has named one.
    ///
    /// A SUBSCRIBE this endpoint sends names a track and waits for its alias,
    /// so the binding exists with no alias in it from the moment the request
    /// is made until its SUBSCRIBE_OK arrives. A PUBLISH carries both at once
    /// and is never in that state.
    alias: Option<u64>,
    kind: BindingKind,
}

/// Which of the two sequences Section 5.1 names established the subscription
/// that owns a binding, and so which state machine says whether it still has
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    /// This endpoint's SUBSCRIBE, established by the peer's SUBSCRIBE_OK.
    Subscribe,
    /// A PUBLISH, established by the PUBLISH_OK answering it - whichever end
    /// sent which. Both are held in the same map, which Request ID parity
    /// keeps from colliding.
    Publish,
}

impl Endpoint {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(role),
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            unjoinable_fetches: HashMap::new(),
            subscribe_namespaces: HashMap::new(),
            subscribe_tracks: HashMap::new(),
            publish_namespaces: HashMap::new(),
            track_statuses: HashMap::new(),
            publishes: HashMap::new(),
            goaway_uri: None,
            goaway_request_streams: HashSet::new(),
            peer_request_ids: HashSet::new(),
            inbound_requests: HashMap::new(),
            overlapping_namespace_subscriptions: HashMap::new(),
            updated_namespace_prefixes: HashMap::new(),
            overlapping_prefix_updates: HashMap::new(),
            advertised_max_request_updates: 0,
            outstanding_peer_updates: HashMap::new(),
            unanswered_peer_updates: HashMap::new(),
            owed_update_failures: HashSet::new(),
            answered_peer_requests: HashSet::new(),
            advertised_max_filter_ranges: 0,
            peer_filter_rejections: HashMap::new(),
            peer_request_filters: HashMap::new(),
            track_bindings: HashMap::new(),
            fetch_tracks: HashMap::new(),
            malformed: Mutex::new(MalformedTracks::new()),
            locations: Arc::new(Mutex::new(TrackLocations::new())),
        }
    }

    /// The Track Alias the peer attached to `request_id`, once it has named
    /// one.
    ///
    /// Answers for a subscription this endpoint asked for from the moment its
    /// SUBSCRIBE_OK arrives, and for one the peer offered from the moment its
    /// PUBLISH does. `None` before that, and for a Request ID this session has
    /// no track for.
    pub fn track_alias_for(&self, request_id: VarInt) -> Option<VarInt> {
        let alias = self.track_bindings.get(&request_id.into_inner())?.alias?;
        VarInt::from_u64(alias).ok()
    }

    /// The refusal Section 11.1 requires when `alias` already names a
    /// different track that still has an Established subscription, or `None`
    /// when it is free.
    ///
    /// # Why the set is read rather than kept
    ///
    /// "Established" is a subscription state Section 5.1 defines, and both
    /// state machines here already hold it: a subscription reaches it on
    /// SUBSCRIBE_OK and a publish on PUBLISH_OK, and each leaves it on the
    /// message that ends the flow. Asking them is what makes an alias free
    /// again the moment its track's subscription ends, with nothing to prune
    /// on the way out - and a path that ended a subscription without telling
    /// this table would otherwise leave the alias held forever and refuse the
    /// peer's next, conforming, use of it.
    ///
    /// # Why the request's own binding is skipped
    ///
    /// A SUBSCRIBE_OK is judged before its own alias is written down, so the
    /// skip is not what keeps it from finding itself. A PUBLISH is not: a
    /// second PUBLISH under a Request ID already bound is refused by the
    /// duplicate-Request-ID rule before it reaches here, and comparing a
    /// request against its own binding would answer the wrong rule if that one
    /// ever moved.
    fn conflicting_track_alias(
        &self,
        request_id: u64,
        alias: u64,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<EndpointError> {
        for (&id, binding) in &self.track_bindings {
            if id == request_id || binding.alias != Some(alias) {
                continue;
            }
            if binding.namespace == *namespace && binding.name == name {
                continue;
            }
            if self.binding_is_established(id, binding.kind) {
                return Some(EndpointError::DuplicateTrackAlias {
                    alias,
                    established: id,
                    offered: request_id,
                });
            }
        }
        None
    }

    /// The request already using `alias` for a track other than (`namespace`,
    /// `name`), or `None` when this endpoint may give the alias to that track.
    ///
    /// Separate from [`Self::conflicting_track_alias`] because the two answer
    /// different questions about the same table. That one judges a message
    /// that has arrived and ends the session over it; this one judges one that
    /// has not been built and declines to build it.
    fn alias_held_elsewhere(
        &self,
        alias: u64,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<EndpointError> {
        self.track_bindings.iter().find_map(|(&id, binding)| {
            let other_track = binding.namespace != *namespace || binding.name != name;
            (binding.alias == Some(alias)
                && other_track
                && self.binding_is_in_use(id, binding.kind))
            .then_some(EndpointError::TrackAliasInUse { alias, held: id })
        })
    }

    /// Whether a binding's request has put its alias in play at all. Broader
    /// than [`Self::binding_is_established`], and the two sentences are why.
    /// What a subscriber must close over is qualified - "the same Track Alias
    /// as a different Track with an Established subscription" - and the
    /// prohibition on the publisher is not: "The same Track Alias MUST NOT be
    /// used by a publisher to refer to two different Tracks simultaneously in
    /// the same session." Once a PUBLISH carrying an alias has been sent,
    /// giving that alias to a second track is what that sentence forbids,
    /// answered or not.
    fn binding_is_in_use(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => {
                self.subscriptions.get(&id).is_some_and(|sm| sm.state() != SubscriptionState::Done)
            }
            BindingKind::Publish => {
                self.publishes.get(&id).is_some_and(|sm| sm.state() != PublishState::Done)
            }
        }
    }

    /// Whether the request that owns a binding still has an Established
    /// subscription.
    fn binding_is_established(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => self
                .subscriptions
                .get(&id)
                .is_some_and(|sm| sm.state() == SubscriptionState::Active),
            BindingKind::Publish => {
                self.publishes.get(&id).is_some_and(|sm| sm.state() == PublishState::Active)
            }
        }
    }

    /// The track a live binding has given `alias` to.
    ///
    /// Read rather than kept: a binding whose request has ended holds nothing,
    /// and an alias that is free again may name a different track next.
    fn track_for_alias(&self, alias: u64) -> Option<(&TrackNamespace, &[u8])> {
        self.track_bindings.iter().find_map(|(&id, binding)| {
            (binding.alias == Some(alias) && self.binding_is_in_use(id, binding.kind))
                .then_some((&binding.namespace, binding.name.as_slice()))
        })
    }

    /// Whether this endpoint *receives* the track a request names.
    ///
    /// The sentence to be answered is a subscriber's - "cancel any
    /// corresponding subscription or fetches for that Track from that
    /// publisher" - so a request that makes this endpoint the publisher is not
    /// one of them. A SUBSCRIBE in the table is always this endpoint's own,
    /// because a SUBSCRIBE the peer sends makes this endpoint the publisher and
    /// leaves no binding. A PUBLISH is in the table either way round, and
    /// Request ID parity is what separates them: the offer the peer made is the
    /// one this endpoint receives a track through.
    fn receives_through(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => true,
            BindingKind::Publish => self.request_ids.validate_peer_id(id).is_ok(),
        }
    }

    /// The record a stream carrying `alias`'s objects measures them against.
    ///
    /// `None` for an alias no live binding names: an object for one breaks a
    /// different rule, and measuring it against a track this endpoint never
    /// asked for would answer that one with the wrong sentence.
    pub fn track_objects(&self, alias: u64) -> Option<TrackObjects> {
        let (namespace, name) = self.track_for_alias(alias)?;
        Some(TrackObjects::new(
            Arc::clone(&self.locations),
            namespace.clone(),
            name.to_vec(),
            alias,
        ))
    }

    /// Record or judge one object that arrived outside a subgroup stream, and
    /// report Section 2.4.2's Malformed Track when it arrived after the place
    /// an end-of-track object put the end.
    ///
    /// One rule and not two. The placement rule drafts 08 through 13 state
    /// about an end-of-track object is not in this draft, so an object that
    /// ends a track here is judged against nothing and only settles where the
    /// track stopped.
    ///
    /// `&self`, because the call site is the data plane's.
    pub fn note_received_object(
        &self,
        alias: u64,
        at: ObjectLocation,
        role: ObjectRole,
    ) -> Result<(), EndpointError> {
        let Some(objects) = self.track_objects(alias) else { return Ok(()) };
        objects.note_past_final(at, role).map_err(|end| EndpointError::ObjectPastFinalObject {
            alias,
            group: at.group,
            object: at.object,
            final_group: end.group,
            final_object: end.object,
        })
    }

    /// The condition a track was withdrawn for, or `None` for a track this
    /// endpoint has found nothing wrong with.
    ///
    /// # Why this takes a track and not the alias the object carried
    ///
    /// An alias only means anything through a live binding, and the withdrawal
    /// ends the binding it would have been resolved through. An accessor taking
    /// an alias would therefore answer `None` from the instant it had something
    /// to say. The record is keyed on the track, and so is this.
    pub fn malformed_track(
        &self,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<MalformedTrackCondition> {
        self.malformed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .condition(namespace, name)
    }

    /// Note a track as malformed and name every request through which this
    /// endpoint is receiving it, so the caller can cancel them.
    ///
    /// **This is the whole of what this crate can do here, and the reason is
    /// structural rather than a shortfall.** Section 2.4.2 asks a subscriber
    /// that detects a Malformed Track to "cancel any corresponding subscription
    /// or fetches for that Track from that publisher", and on this draft
    /// cancelling a request means resetting the request's own bidirectional
    /// stream - Section 3.3.3. Every request lives at the front of a
    /// stream of its own, and `Connection::recv_on_request_stream` hands that
    /// stream to the caller as a `RequestStream`. So the stream this answer
    /// operates on is not the endpoint's to touch, and no amount of state here
    /// changes that. What the endpoint can do is say which requests they are.
    ///
    /// # Nothing here ends a request
    ///
    /// Deliberately, and it is what keeps the answer to one. The flows are read
    /// and not moved, so a caller that passes each id to
    /// `Connection::cancel_request_stream` ends the request there - and the
    /// binding stops being in use, so a second object past the end finds no
    /// track for the alias and names nothing. The request ending is still what
    /// closes the loop, exactly as it is on the drafts that answer with a
    /// message; what changed is which side ends it. A caller that ignores the
    /// list gets named the same requests again, which is honest: the condition
    /// really did fire again.
    ///
    /// # What is named, and what is not
    ///
    /// Requests through which this endpoint *receives* the track: a SUBSCRIBE
    /// this endpoint sent, a PUBLISH the peer sent, and a fetch this endpoint
    /// made. A request that makes this endpoint the publisher is not one of
    /// them. Empty for an alias no live binding names,
    /// and empty for a track whose only requests are ones this endpoint
    /// publishes.
    ///
    /// Sorted, because a `HashMap` iterates in no order and two requests for
    /// one track is a shape a peer can produce.
    pub fn requests_for_malformed_track(
        &self,
        alias: u64,
        condition: MalformedTrackCondition,
    ) -> Vec<VarInt> {
        let Some((namespace, name)) = self.track_for_alias(alias) else { return Vec::new() };
        let (namespace, name) = (namespace.clone(), name.to_vec());
        self.malformed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .note(&namespace, &name, condition);
        let mut ids: Vec<u64> = self
            .track_bindings
            .iter()
            .filter(|(&id, binding)| {
                binding.namespace == namespace
                    && binding.name == name
                    && self.binding_is_in_use(id, binding.kind)
                    && self.receives_through(id, binding.kind)
            })
            .map(|(&id, _)| id)
            .chain(self.fetch_tracks.iter().filter_map(|(&id, track)| {
                (track.namespace == namespace
                    && track.name == name
                    && self.fetches.get(&id).is_some_and(|sm| sm.state() != FetchState::Done))
                .then_some(id)
            }))
            .collect();
        ids.sort_unstable();
        ids.into_iter().filter_map(|id| VarInt::from_u64(id).ok()).collect()
    }

    /// The conflict a SUBSCRIBE_OK's alias has with the tracks already bound.
    ///
    /// Separate from [`Self::conflicting_track_alias`] because the track a
    /// SUBSCRIBE_OK is about is not in the SUBSCRIBE_OK: it is the one this
    /// endpoint's own SUBSCRIBE asked for, which is why the request has to be
    /// looked up before the alias can be judged.
    fn conflicting_alias_for_subscribe_ok(&self, id: u64, alias: u64) -> Option<EndpointError> {
        let binding = self.track_bindings.get(&id)?;
        self.conflicting_track_alias(id, alias, &binding.namespace, &binding.name)
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the role of the peer, which is the other one.
    pub fn peer_role(&self) -> Role {
        match self.role {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }

    /// Hold a refused update's ending to the status the draft names, and
    /// retire the obligation once that ending is written.
    ///
    /// Both routes to a PUBLISH_DONE come through here. A subscription this
    /// endpoint accepted is ended by a response on the peer's stream; a PUBLISH
    /// this endpoint sent is ended on its own, which does not go through the
    /// response path at all. The rule is the same either way, so it is stated
    /// once and called twice rather than written where each route happened to
    /// need it.
    fn require_update_failure_status(
        &mut self,
        id: u64,
        status_code: VarInt,
    ) -> Result<(), EndpointError> {
        if !self.owed_update_failures.contains(&id) {
            return Ok(());
        }
        let required = PublishDoneStatusCode::UpdateFailed as u64;
        if status_code.into_inner() != required {
            return Err(EndpointError::WrongUpdateFailureStatus { request: id, required });
        }
        self.owed_update_failures.remove(&id);
        Ok(())
    }

    /// Whether the peer has sent a REQUEST_UPDATE on this request that has not
    /// been answered yet.
    ///
    /// Draft-19 Section 10.9: "A subscriber can also send REQUEST_UPDATE to
    /// modify parameters of a subscription established with PUBLISH", and the
    /// receiver of one "MUST respond with exactly one REQUEST_OK or
    /// REQUEST_ERROR message indicating if the update was successful".
    ///
    /// Asked by the connection layer, which otherwise writes nothing on a
    /// stream this endpoint opened. An update the peer sent on a PUBLISH is
    /// the one thing on such a stream that this endpoint has to answer, and
    /// this is what tells it apart from a response to its own request.
    pub fn has_unanswered_update(&self, request_id: VarInt) -> bool {
        self.unanswered_peer_updates.get(&request_id.into_inner()).is_some_and(|&n| n > 0)
    }

    /// Whether the request `id` names a subscription this endpoint publishes.
    ///
    /// Draft-19 Section 10.9.1 gives a refused REQUEST_UPDATE three different
    /// consequences and picks between them by what was being updated: "When a
    /// REQUEST_UPDATE is unsuccessful, the publisher MUST also terminate the
    /// subscription by sending a PUBLISH_DONE with error code UPDATE_FAILED.
    /// When a REQUEST_UPDATE fails for a FETCH, the publisher MUST reset the
    /// FETCH data stream. When a REQUEST_UPDATE fails for a SUBSCRIBE_NAMESPACE,
    /// SUBSCRIBE_TRACKS or PUBLISH_NAMESPACE, the responder MUST close the bidi
    /// stream (see Section 3.3.2)."
    ///
    /// Only the first of the three is a message, and only the first is owed
    /// here. Recording it for the other two is what would hold their streams
    /// open past the close the third sentence requires.
    ///
    /// Two requests leave this endpoint publishing: a SUBSCRIBE the peer sent,
    /// and a PUBLISH this endpoint sent. Either can carry an update from the
    /// other side, and either is ended by a PUBLISH_DONE written from here. A
    /// peer's PUBLISH is neither, because the peer is the publisher on it, and
    /// it is told apart by having arrived rather than been sent.
    fn publishes_a_subscription(&self, id: u64) -> bool {
        matches!(self.inbound_requests.get(&id), Some(ControlMessage::Subscribe(_)))
            || (self.publishes.contains_key(&id) && !self.inbound_requests.contains_key(&id))
    }

    /// Whether this request's refused update still owes the peer the
    /// PUBLISH_DONE that ends it.
    ///
    /// Asked by the connection layer, which owns the stream that termination
    /// has to be written on and therefore has to know not to close it. A
    /// REQUEST_ERROR answering the request itself ends the exchange and takes
    /// the stream with it; one answering an update does not, and nothing in
    /// the message tells the two apart.
    pub fn owes_update_failure(&self, request_id: VarInt) -> bool {
        self.owed_update_failures.contains(&request_id.into_inner())
    }

    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    pub fn goaway_uri(&self) -> Option<&[u8]> {
        self.goaway_uri.as_deref()
    }

    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn active_fetch_count(&self) -> usize {
        self.fetches.len()
    }

    pub fn active_subscribe_namespace_count(&self) -> usize {
        self.subscribe_namespaces.len()
    }

    pub fn active_subscribe_tracks_count(&self) -> usize {
        self.subscribe_tracks.len()
    }

    pub fn active_publish_namespace_count(&self) -> usize {
        self.publish_namespaces.len()
    }

    pub fn active_track_status_count(&self) -> usize {
        self.track_statuses.len()
    }

    pub fn active_publish_count(&self) -> usize {
        self.publishes.len()
    }

    /// How many Request IDs the peer has spent on this session.
    ///
    /// Nothing here removes an entry, so this only grows. A responder that
    /// wants a ceiling on peer-created state has to impose one itself — see
    /// the note on [`receive_request_on_stream`](Self::receive_request_on_stream).
    pub fn peer_request_count(&self) -> usize {
        self.peer_request_ids.len()
    }

    // -- Session lifecycle ------------------------------------------

    pub fn connect(&mut self) -> Result<(), EndpointError> {
        self.session.on_connect()?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), EndpointError> {
        self.session.on_close()?;
        Ok(())
    }

    // -- Unified SETUP ----------------------------------------------

    /// Generate a SETUP message. Both client and server use the same message
    /// type; only the role (and the order of send/receive) distinguishes them.
    pub fn send_setup(
        &mut self,
        options: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let msg = Setup { options };
        setup::validate_setup(&msg, self.role)?;
        self.advertised_max_request_updates = setup_varint(&msg.options, MAX_REQUEST_UPDATES);
        self.advertised_max_filter_ranges = setup_varint(&msg.options, MAX_FILTER_RANGES);
        Ok(ControlMessage::Setup(msg))
    }

    /// Process an incoming SETUP message. Transitions the session to Active.
    pub fn receive_setup(&mut self, msg: &Setup) -> Result<(), EndpointError> {
        setup::validate_setup(msg, self.peer_role())?;
        self.session.on_setup_complete()?;
        Ok(())
    }

    // -- GoAway -----------------------------------------------------

    pub fn receive_goaway(&mut self, msg: &GoAway) -> Result<(), EndpointError> {
        // Draft-19 Section 10.4: "If a server receives a GOAWAY with a
        // non-zero New Session URI Length it MUST close the session with a
        // PROTOCOL_VIOLATION." Migration is something a server offers a
        // client, never the other way round, so the URI is refused here rather
        // than stored and later followed.
        if self.role == Role::Server && !msg.new_session_uri.is_empty() {
            return Err(self.fail_session(EndpointError::GoAwayUriAtServer));
        }
        // Draft-19 Section 10.4: "The endpoint MUST close the session with a
        // PROTOCOL_VIOLATION (Section 3.5) if it receives more than one GOAWAY on the
        // control stream or on a single request stream." Draining is reached
        // from nowhere else - `on_goaway` is its only entry and this method is
        // that method's only caller - so the session state is the record of
        // the first GOAWAY having arrived. This is the control-stream half;
        // the per-stream half is in `receive_goaway_on_request_stream`.
        if self.session.state() == SessionState::Draining {
            return Err(self.fail_session(EndpointError::RepeatedGoAway));
        }
        self.session.on_goaway()?;
        self.goaway_uri = Some(msg.new_session_uri.clone());
        Ok(())
    }

    /// Record that the session is over because the peer broke a rule the draft
    /// answers with a session close, and hand the error back unchanged.
    ///
    /// The state move is what makes the violation stick: every request entry
    /// point goes through [`require_active_or_err`](Self::require_active_or_err),
    /// so a caller that ignores the returned error still cannot start anything
    /// new. The close on the wire is the connection layer's job — see
    /// [`EndpointError::session_error_code`] for the code it should use.
    fn fail_session(&mut self, err: EndpointError) -> EndpointError {
        // `on_close` accepts SetupExchange, Active and Draining. A violation
        // seen in Connecting or Closed leaves the state machine alone: there
        // is no session to close, and the error itself is still the answer.
        //
        // SetupExchange is in that set because the Termination section says
        // "The Transport Session can be terminated at any point", and the
        // Setup exchange is a point. So a violation caught while the setup is
        // still in flight does close the session, and the discarded result is
        // safe because that is one of the states `on_close` accepts.
        let _ = self.session.on_close();
        err
    }

    fn require_active_or_err(&self) -> Result<(), EndpointError> {
        match self.session.state() {
            SessionState::Active => Ok(()),
            SessionState::Draining => Err(EndpointError::Draining),
            _ => Err(EndpointError::NotActive),
        }
    }

    // -- Subscribe flow ---------------------------------------------

    pub fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscriptionStateMachine::new();
        sm.on_subscribe_sent()?;
        self.subscriptions.insert(req_id.into_inner(), sm);
        // The track is recorded here because this is the only place it is
        // known: a SUBSCRIBE_OK names an alias and not the track it is for.
        self.track_bindings.insert(
            req_id.into_inner(),
            TrackBinding {
                namespace: track_namespace.clone(),
                name: track_name.clone(),
                alias: None,
                kind: BindingKind::Subscribe,
            },
        );

        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: req_id,
            track_namespace,
            track_name,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK. Draft-19: no request_id on wire; the
    /// caller supplies the `request_id` of the bidi stream on which the
    /// response arrived.
    pub fn receive_subscribe_ok(
        &mut self,
        request_id: VarInt,
        msg: &SubscribeOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if !self.subscriptions.contains_key(&id) {
            return Err(EndpointError::UnknownRequest(id));
        }
        let alias = msg.track_alias.into_inner();
        // Judged before the transition, so that the subscription this message
        // is about is not yet Established and cannot be found as its own
        // conflict, and so that a refused SUBSCRIBE_OK leaves no alias behind.
        if let Some(conflict) = self.conflicting_alias_for_subscribe_ok(id, alias) {
            return Err(self.fail_session(conflict));
        }
        let sm = self.subscriptions.get_mut(&id).expect("checked above");
        sm.on_subscribe_ok()?;
        if let Some(binding) = self.track_bindings.get_mut(&id) {
            binding.alias = Some(alias);
        }
        Ok(())
    }

    /// Take one of the REQUEST_UPDATE credits this endpoint advertised for
    /// `id`'s stream.
    ///
    /// Section 10.3.1.7 puts the limit on the number *outstanding*, so the
    /// count is a running balance rather than a total: it goes up on each
    /// REQUEST_UPDATE received and down on each REQUEST_OK or REQUEST_ERROR
    /// this endpoint writes back, and a peer that keeps pace never reaches the
    /// ceiling however many updates it sends.
    ///
    /// # Errors
    ///
    /// [`EndpointError::TooManyRequestUpdates`], which answers
    /// `Some(TooManyRequestUpdates)` - its own close code, not the general
    /// PROTOCOL_VIOLATION - and the session is failed before it returns.
    fn spend_update_credit(&mut self, id: u64) -> Result<(), EndpointError> {
        let limit = self.advertised_max_request_updates;
        if limit == 0 {
            return Ok(());
        }
        let outstanding = self.outstanding_peer_updates.entry(id).or_insert(0);
        if *outstanding >= limit {
            return Err(self.fail_session(EndpointError::TooManyRequestUpdates(id, limit)));
        }
        *outstanding += 1;
        Ok(())
    }

    /// Give back the credit a REQUEST_OK or REQUEST_ERROR restores.
    ///
    /// Called for every response this endpoint writes, whether or not the
    /// stream ever carried an update: a stream with no outstanding updates has
    /// nothing to restore and the saturating subtraction says so, which is
    /// cheaper than deciding first whether the response is answering an update
    /// or the original request.
    fn restore_update_credit(&mut self, id: u64) {
        if let Some(outstanding) = self.outstanding_peer_updates.get_mut(&id) {
            *outstanding = outstanding.saturating_sub(1);
        }
    }

    /// Process a REQUEST_UPDATE that arrived on the bidi request stream
    /// identified by `request_id`.
    ///
    /// Draft-19 Section 10.9: "The sender of a request (SUBSCRIBE, PUBLISH,
    /// FETCH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) can
    /// later send a REQUEST_UPDATE on the same bidi stream as the request to
    /// modify it. A subscriber can also send REQUEST_UPDATE to modify
    /// parameters of a subscription established with PUBLISH." Anything else
    /// "MUST close the session with a PROTOCOL_VIOLATION", which is what
    /// [`EndpointError::UnexpectedRequestUpdate`] carries — TRACK_STATUS most
    /// of all, since Section 10.14 says outright that "the subscriber cannot
    /// send REQUEST_UPDATE".
    ///
    /// The message carries a Request ID of its own and the stream carries one
    /// too. They name the same request when the peer is conforming; a
    /// disagreement means the update was sent on a stream that is not its
    /// request's, which is the same violation, so it is refused rather than
    /// silently resolved to one of the two.
    ///
    /// Only SUBSCRIBE-established subscriptions have a state-machine event for
    /// this. That is not an omission: an update changes a request's parameters
    /// and not its lifecycle, so for the other five kinds the update is a
    /// self-transition with nothing to record.
    pub fn receive_request_update(
        &mut self,
        request_id: VarInt,
        msg: &RequestUpdate,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if msg.request_id.into_inner() != id {
            return Err(self.fail_session(EndpointError::UnexpectedRequestUpdate(
                msg.request_id.into_inner(),
            )));
        }
        self.spend_update_credit(id)?;
        // The two cases are about who is sending, and only one of them is
        // about which request. Case one is the peer updating a request the
        // peer made, whatever its kind; case two is a subscriber updating a
        // subscription this endpoint established with PUBLISH. A SUBSCRIBE, a
        // FETCH or a namespace request this endpoint made is in neither, and
        // an update on one is a violation rather than a request to apply.
        //
        // They are not symmetrical about timing either. Case one allows an
        // update "later" and says nothing about the answer, so a request of
        // the peer's may be updated before this endpoint has answered it.
        // Case two rests on the subscription existing, and Section 5.1 says
        // when it does: "Once either of these sequences is successful, the
        // subscription moves to the Established state and can be updated by
        // the subscriber using REQUEST_UPDATE." A PUBLISH still waiting for
        // its answer is Pending, and an update on one is outside both cases.
        //
        // Checked before the state machine below moves, so a session that is
        // closing does not leave a subscription updated on the way out.
        let one_of_the_two_cases = self.inbound_requests.contains_key(&id)
            || self.binding_is_established(id, BindingKind::Publish);
        if !one_of_the_two_cases {
            return Err(self.fail_session(EndpointError::UnexpectedRequestUpdate(id)));
        }
        let updatable = if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_subscribe_update()?;
            true
        } else {
            self.publishes.contains_key(&id)
                || self.fetches.contains_key(&id)
                || self.subscribe_namespaces.contains_key(&id)
                || self.subscribe_tracks.contains_key(&id)
                || self.publish_namespaces.contains_key(&id)
        };
        if !updatable {
            return Err(self.fail_session(EndpointError::UnexpectedRequestUpdate(id)));
        }
        *self.unanswered_peer_updates.entry(id).or_insert(0) += 1;

        // The ceiling is on what the request carries after the update, so the
        // update is merged into the set in force and the whole set measured.
        // Recorded rather than refused for the reason the request itself is:
        // the answer is a REQUEST_ERROR, which names a Request ID.
        let mut in_force = self.peer_request_filters.remove(&id).unwrap_or_default();
        apply_filter_update(&mut in_force, &msg.parameters);
        if let Some(rejection) = self.filter_verdict(&in_force) {
            self.peer_filter_rejections.insert(id, rejection);
        }
        self.peer_request_filters.insert(id, in_force);

        // Section 10.9.2 gives an update one thing to move that no draft before
        // this one lets a request change: "A subscriber can update the Track
        // Namespace Prefix of an established SUBSCRIBE_NAMESPACE or
        // SUBSCRIBE_TRACKS by including the TRACK_NAMESPACE_PREFIX parameter
        // (Section 10.2.19) in a REQUEST_UPDATE."
        //
        // The two kinds keep their own ground -- "The overlap restriction
        // applies independently per type" -- so which set the new prefix is
        // weighed against is decided by what the peer opened the stream with.
        //
        // A request of any other kind has no prefix for the parameter to move,
        // and nothing in this draft says what to do with the parameter when it
        // turns up on one, so it is left alone rather than guessed at.
        if let Some(prefix) = updated_prefix(&msg.parameters) {
            let namespace = matches!(
                self.inbound_requests.get(&id),
                Some(ControlMessage::SubscribeNamespace(_))
            );
            let tracks =
                matches!(self.inbound_requests.get(&id), Some(ControlMessage::SubscribeTracks(_)));
            if namespace || tracks {
                let collides = if tracks {
                    self.peer_tracks_overlap(&prefix, Some(id))
                } else {
                    self.peer_namespace_overlap(&prefix, Some(id))
                };
                match collides {
                    Some(established) => {
                        self.overlapping_prefix_updates.insert(id, established);
                    }
                    // A later update clears an earlier one's verdict along with
                    // its prefix, which is what a receiver "applying only the
                    // cumulative result" is entitled to do.
                    None => {
                        self.overlapping_prefix_updates.remove(&id);
                    }
                }
                self.updated_namespace_prefixes.insert(id, prefix);
            }
        }
        Ok(())
    }

    pub fn receive_publish_done(
        &mut self,
        request_id: VarInt,
        _msg: &PublishDone,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done()?;
        Ok(())
    }

    // -- Fetch flow -------------------------------------------------

    /// `parameters` are the request's own, as they are on every other request
    /// this endpoint makes. FETCH carried an empty list on all five of these
    /// drafts while SUBSCRIBE, TRACK_STATUS, PUBLISH_NAMESPACE and PUBLISH
    /// took the caller's, which made it the only one an application could not
    /// attach an authorization token to.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        end_object: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);
        // Before the two of them are moved into the message below: a fetch
        // that has left no track behind is one no withdrawal can name.
        self.fetch_tracks.insert(
            req_id.into_inner(),
            FetchTrack { namespace: track_namespace.clone(), name: track_name.clone() },
        );

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace,
                track_name,
                start_group,
                start_object,
                end_group,
                end_object,
            },
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Send a Relative Joining Fetch (Fetch Type 0x2).
    ///
    /// `joining_start` counts groups back from the subscription's Largest
    /// Group. To name the group directly, use
    /// [`absolute_joining_fetch`](Self::absolute_joining_fetch).
    ///
    /// `parameters` are the request's own, as they are on every other request
    /// this endpoint makes.
    pub fn joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            FetchType::RelativeJoining,
            joining_request_id,
            joining_start,
            parameters,
        )
    }

    /// Send an Absolute Joining Fetch (Fetch Type 0x3).
    ///
    /// Draft-19 Section 10.12.2.1: "For an Absolute Joining Fetch, the
    /// publisher sets the Start Location to {Joining Start, 0}." So
    /// `joining_start` is the group to begin at, not an offset — which is what
    /// an application that knows the group it wants actually has. Expressing
    /// it as a relative fetch would need the Largest Group, which the
    /// subscriber may not know.
    pub fn absolute_joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            FetchType::AbsoluteJoining,
            joining_request_id,
            joining_start,
            parameters,
        )
    }

    fn joining_fetch_of_type(
        &mut self,
        fetch_type: FetchType,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);
        // Resolved through the join, once, here. A Joining Fetch names no
        // track; the publisher takes the Track Namespace and Track Name from
        // the subscription it names, so that is the track. A Request ID this
        // session holds no track for leaves the fetch out of the record
        // entirely rather than putting a guess in it.
        if let Some(binding) = self.track_bindings.get(&joining_request_id.into_inner()) {
            let track =
                FetchTrack { namespace: binding.namespace.clone(), name: binding.name.clone() };
            self.fetch_tracks.insert(req_id.into_inner(), track);
        }

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            fetch_type,
            fetch_payload: FetchPayload::Joining { joining_request_id, joining_start },
            parameters,
        });
        Ok((req_id, msg))
    }

    pub fn receive_fetch_ok(
        &mut self,
        request_id: VarInt,
        _msg: &message::FetchOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    pub fn on_fetch_stream_fin(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    pub fn on_fetch_stream_reset(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // -- Subscribe Namespace flow -----------------------------------

    pub fn subscribe_namespace(
        &mut self,
        namespace_prefix: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscribeNamespaceStateMachine::new();
        sm.on_subscribe_namespace_sent()?;
        self.subscribe_namespaces.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: req_id,
            namespace_prefix,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Subscribe Tracks flow (new in draft-18) --------------------

    pub fn subscribe_tracks(
        &mut self,
        namespace_prefix: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        // Reuse the SubscribeNamespace state machine — the lifecycle is the
        // same (request → ok/error → done) and adding a parallel state
        // machine purely to disambiguate would be churn.
        let mut sm = SubscribeNamespaceStateMachine::new();
        sm.on_subscribe_namespace_sent()?;
        self.subscribe_tracks.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: req_id,
            namespace_prefix,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Publish Namespace flow -------------------------------------

    pub fn publish_namespace(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = PublishNamespaceStateMachine::new();
        sm.on_publish_namespace_sent()?;
        self.publish_namespaces.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::PublishNamespace(PublishNamespace {
            request_id: req_id,
            track_namespace,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Track Status flow ------------------------------------------

    pub fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_sent()?;
        self.track_statuses.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::TrackStatus(message::TrackStatus {
            request_id: req_id,
            track_namespace,
            track_name,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Publish flow (publisher side) ------------------------------

    pub fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        parameters: Vec<KeyValuePair>,
        track_properties: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        // Section 11.1: "The same Track Alias MUST NOT be used by a publisher to refer to
        // two different Tracks simultaneously in the same session." Refused before the
        // Request ID is allocated, so a refusal spends nothing.
        let alias = track_alias.into_inner();
        if let Some(refusal) = self.alias_held_elsewhere(alias, &track_namespace, &track_name) {
            return Err(refusal);
        }
        let req_id = self.request_ids.allocate()?;
        let mut sm = PublishStateMachine::new();
        sm.on_publish_sent()?;
        self.publishes.insert(req_id.into_inner(), sm);
        // The alias and the track travel together in a PUBLISH, so the binding
        // is complete the moment the message is built.
        self.track_bindings.insert(
            req_id.into_inner(),
            TrackBinding {
                namespace: track_namespace.clone(),
                name: track_name.clone(),
                alias: Some(alias),
                kind: BindingKind::Publish,
            },
        );

        let msg = ControlMessage::Publish(Publish {
            request_id: req_id,
            track_namespace,
            track_name,
            track_alias,
            parameters,
            track_properties,
        });
        Ok((req_id, msg))
    }

    pub fn send_publish_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        stream_count: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        // Before the state machine moves, so an ending under the wrong status
        // leaves the publication where it was. A PUBLISH this endpoint sent is
        // ended here rather than through the response path, and a refused
        // update on it owes the same ending as one on a peer's SUBSCRIBE.
        self.require_update_failure_status(id, status_code)?;
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done_sent()?;
        Ok(ControlMessage::PublishDone(PublishDone { status_code, stream_count, reason_phrase }))
    }

    // -- Consolidated responses (per-bidi-stream routing) -----------

    /// Process an incoming REQUEST_OK on the bidi stream identified by
    /// `request_id`. Draft-19: PUBLISH_OK is a REQUEST_OK alias, so this
    /// handler also resolves outstanding PUBLISH requests.
    ///
    /// # Track Properties are refused except on TRACK_STATUS_OK
    ///
    /// Draft-19 Section 10.5: Track Properties "are populated in
    /// TRACK_STATUS_OK; they are empty in PUBLISH_OK, REQUEST_UPDATE_OK,
    /// SUBSCRIBE_NAMESPACE_OK and PUBLISH_NAMESPACE_OK. If an endpoint
    /// receives Track Properties in one of these messages it MUST close the
    /// session with a PROTOCOL_VIOLATION." The codec cannot make that check —
    /// REQUEST_OK is one wire form and only the request stream says which of
    /// the five shapes it is. This is the layer that knows, because finding
    /// the request id in one of the maps below is what names the shape.
    pub fn receive_request_ok(
        &mut self,
        request_id: VarInt,
        msg: &RequestOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if !msg.track_properties.is_empty() && !self.track_statuses.contains_key(&id) {
            return Err(self.fail_session(EndpointError::TrackPropertiesOnNonTrackStatus(id)));
        }
        if let Some(sm) = self.publishes.get_mut(&id) {
            sm.on_publish_ok()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_subscribe_namespace_ok()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_tracks.get_mut(&id) {
            sm.on_subscribe_namespace_ok()?;
            return Ok(());
        }
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_publish_namespace_ok()?;
            return Ok(());
        }
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_track_status_ok()?;
            return Ok(());
        }
        Err(EndpointError::UnknownRequest(id))
    }

    /// Process an incoming REQUEST_ERROR on the bidi stream identified by
    /// `request_id`.
    pub fn receive_request_error(
        &mut self,
        request_id: VarInt,
        msg: &RequestError,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if let Some(redirect) = &msg.redirect {
            // Draft-19 Section 10.6.1: "If a server receives a Redirect with a
            // non-zero Connect URI Length it MUST close the session with a
            // PROTOCOL_VIOLATION." Left unchecked, a Redirect sends a server
            // chasing a URI a client picked.
            if self.role == Role::Server && !redirect.connect_uri.is_empty() {
                return Err(self.fail_session(EndpointError::RedirectUriAtServer));
            }
            // Same section: "Track Name is not meaningful for namespace-scoped
            // requests (SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE,
            // SUBSCRIBE_TRACKS) and MUST be empty; an endpoint that receives a
            // non-empty Track Name in a Redirect for a namespace-scoped request
            // MUST close the session with a PROTOCOL_VIOLATION." Which request
            // this answers is known only here, from the map the stream's id is
            // in.
            let namespace_scoped = self.subscribe_namespaces.contains_key(&id)
                || self.subscribe_tracks.contains_key(&id)
                || self.publish_namespaces.contains_key(&id);
            if namespace_scoped && !redirect.track_name.is_empty() {
                return Err(
                    self.fail_session(EndpointError::RedirectTrackNameOnNamespaceRequest(id))
                );
            }
        }
        if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_subscribe_error()?;
            return Ok(());
        }
        if let Some(sm) = self.fetches.get_mut(&id) {
            sm.on_fetch_error()?;
            return Ok(());
        }
        if let Some(sm) = self.publishes.get_mut(&id) {
            sm.on_publish_error()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_subscribe_namespace_error()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_tracks.get_mut(&id) {
            sm.on_subscribe_namespace_error()?;
            return Ok(());
        }
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_publish_namespace_error()?;
            return Ok(());
        }
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_track_status_error()?;
            return Ok(());
        }
        Err(EndpointError::UnknownRequest(id))
    }

    /// Record that a request was cancelled at its stream.
    ///
    /// This draft withdraws a request by terminating the bidirectional stream
    /// it was made on rather than by sending a message. Section 3.3.3: "Once
    /// a request stream has been opened, the request MAY be cancelled by either
    /// endpoint. Senders cancel requests if the response is no longer of
    /// interest; Receivers cancel requests if they are unable to or choose not
    /// to respond."
    ///
    /// Both of those reach here. A request the peer opened and one this
    /// endpoint opened share a map and cannot collide, because their Request
    /// IDs have opposite least significant bits, so one method records a cancel
    /// from whichever side performed it.
    ///
    /// The request moves to its end state, which is what makes the record worth
    /// keeping: a response arriving afterwards is refused rather than applied to
    /// a request that is over. The Request ID is not released — nothing here
    /// reuses one — and the per-request bookkeeping keyed by it is left alone,
    /// since a cancelled request's stream carries nothing more.
    ///
    /// Nothing is written on the wire. The reset that goes with this is
    /// [`Connection::cancel_request_stream`], which calls this first and
    /// terminates the stream only if it returns `Ok`.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when no request of any kind carries
    /// that id, and the kind's own `InvalidTransition` when the request has not
    /// been written yet.
    ///
    /// [`Connection::cancel_request_stream`]: crate::draft19::connection::Connection::cancel_request_stream
    pub fn cancel_request(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        if let Some(sm) = self.fetches.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        if let Some(sm) = self.publishes.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_tracks.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_request_cancelled()?;
            return Ok(());
        }
        Err(EndpointError::UnknownRequest(id))
    }

    // -- PublishSkipped / Namespace announcements -------------------

    pub fn receive_namespace(&mut self, _msg: &message::Namespace) -> Result<(), EndpointError> {
        Ok(())
    }

    pub fn receive_namespace_done(
        &mut self,
        _msg: &message::NamespaceDone,
    ) -> Result<(), EndpointError> {
        Ok(())
    }

    pub fn receive_publish_skipped(&mut self, _msg: &PublishSkipped) -> Result<(), EndpointError> {
        Ok(())
    }

    // -- Unified message dispatch -----------------------------------

    /// Dispatch a message that arrived on the control stream.
    ///
    /// Draft-19 Table 5 gives every message a Stream value, and only two of
    /// them name the control stream: SETUP is "Control", GOAWAY is "Control,
    /// Request". Everything else is "Request", so this method's job is to take
    /// those two and refuse the messages that identify a request they have no
    /// stream to name.
    ///
    /// Four are refused for that reason. REQUEST_UPDATE modifies the request
    /// its stream carries (Section 10.9). NAMESPACE and NAMESPACE_DONE report
    /// namespaces on the SUBSCRIBE_NAMESPACE request stream that asked for them
    /// (Sections 10.16 and 10.17), and PUBLISH_SKIPPED names a track that will
    /// not be published on the SUBSCRIBE_TRACKS stream that asked for it
    /// (Section 10.20). All four route through
    /// [`receive_response_on_stream`](Self::receive_response_on_stream), which
    /// has the request ID they need.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::Setup(ref m) => self.receive_setup(m),
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::RequestUpdate(_) => {
                Err(self.fail_session(EndpointError::RequestUpdateOnControlStream))
            }
            // Refused, and the session left running. No draft states a close
            // for a message arriving on a stream it does not belong on — see
            // `session_error_code`, which answers `None` for them. A
            // control message carries its own length, so the next boundary is
            // known and a refused message costs the session nothing; that is
            // the answer `ResponseOnControlStream` below has always given.
            //
            // REQUEST_UPDATE above is the one that is not like these: Section
            // 10.9 does close over one that arrives outside the two cases it
            // names, so it keeps both the close and `fail_session`.
            ControlMessage::Namespace(_) => {
                Err(EndpointError::RequestMessageOnControlStream("NAMESPACE"))
            }
            ControlMessage::NamespaceDone(_) => {
                Err(EndpointError::RequestMessageOnControlStream("NAMESPACE_DONE"))
            }
            ControlMessage::PublishSkipped(_) => {
                Err(EndpointError::RequestMessageOnControlStream("PUBLISH_SKIPPED"))
            }
            ControlMessage::SubscribeOk(_)
            | ControlMessage::PublishDone(_)
            | ControlMessage::FetchOk(_)
            | ControlMessage::RequestOk(_)
            | ControlMessage::RequestError(_) => Err(EndpointError::ResponseOnControlStream),
            _ => Ok(()),
        }
    }

    /// Hold the response half of a namespace-scoped request to the rule that
    /// its first message answers the request.
    ///
    /// Sections 10.18 and 10.19 state it once each, for SUBSCRIBE_NAMESPACE
    /// and for SUBSCRIBE_TRACKS: "The publisher will respond with REQUEST_OK or
    /// REQUEST_ERROR on the response half of the stream. If the subscriber
    /// receives any message other than a REQUEST_OK or a REQUEST_ERROR as the
    /// first message on the response half of the stream, then it MUST close the
    /// session with a PROTOCOL_VIOLATION." Draft-18's own change log records it
    /// as new work rather than as a clarification, so drafts 17 and earlier are
    /// deliberately not held to it: they say nothing about which message comes
    /// first, and refusing one there would close a session over traffic those
    /// drafts permit.
    ///
    /// # Why only these two requests
    ///
    /// They are the two whose response half carries more than an answer.
    /// SUBSCRIBE_NAMESPACE goes on to carry NAMESPACE and NAMESPACE_DONE and
    /// SUBSCRIBE_TRACKS goes on to carry PUBLISH_SKIPPED, and those are exactly the
    /// messages that could arrive before the answer and be taken for it. A
    /// SUBSCRIBE has SUBSCRIBE_OK as its own first message and no such
    /// ambiguity, which is why the rule is written where it is.
    ///
    /// # What "first" is read from
    ///
    /// The request's own state machine. `Pending` means the request went out
    /// and nothing has come back, so it is the same question asked of the state
    /// rather than of a second counter that could disagree with it. A request
    /// this endpoint did not open, or one already answered, is not this rule's
    /// subject and passes through.
    ///
    /// # Errors
    ///
    /// [`EndpointError::ResponseBeforeTheFirstResponse`], which answers
    /// `Some(ProtocolViolation)`, and the session is failed before it returns.
    fn require_the_first_response_first(
        &mut self,
        id: u64,
        msg: &ControlMessage,
    ) -> Result<(), EndpointError> {
        let awaiting = [self.subscribe_namespaces.get(&id), self.subscribe_tracks.get(&id)]
            .into_iter()
            .flatten()
            .any(|sm| sm.state() == SubscribeNamespaceState::Pending);
        if !awaiting {
            return Ok(());
        }
        if matches!(msg, ControlMessage::RequestOk(_) | ControlMessage::RequestError(_)) {
            return Ok(());
        }
        let ty = msg.message_type();
        Err(self.fail_session(EndpointError::ResponseBeforeTheFirstResponse(id, ty)))
    }

    /// Dispatch a message that arrived on the bidi request stream identified
    /// by `request_id`.
    ///
    /// Beyond the five responses this also takes the messages draft-19 Table 5
    /// places on a request stream without their being answers to it.
    ///
    /// REQUEST_UPDATE modifies the request the stream carries (Section 10.9).
    /// GOAWAY is listed "Control, Request" because "A GOAWAY MAY also be sent
    /// on a request stream to initiate migration of that individual request"
    /// (Section 10.4); draft-19 is the draft where its receive path matters,
    /// since it removed GOAWAY's Request ID and left one wire form for both
    /// places.
    ///
    /// NAMESPACE (0x8) and NAMESPACE_DONE (0xE) arrive on the
    /// SUBSCRIBE_NAMESPACE request stream that asked for the namespaces they
    /// report, and PUBLISH_SKIPPED (0xF) on the SUBSCRIBE_TRACKS stream that
    /// asked for the track it says will not be published. Table 5 marks all
    /// three "Request", so this is where they land; the control stream refuses
    /// them.
    pub fn receive_response_on_stream(
        &mut self,
        request_id: VarInt,
        msg: ControlMessage,
    ) -> Result<(), EndpointError> {
        self.require_the_first_response_first(request_id.into_inner(), &msg)?;
        match msg {
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(request_id, m),
            ControlMessage::PublishDone(ref m) => self.receive_publish_done(request_id, m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(request_id, m),
            ControlMessage::RequestOk(ref m) => self.receive_request_ok(request_id, m),
            ControlMessage::RequestError(ref m) => self.receive_request_error(request_id, m),
            ControlMessage::RequestUpdate(ref m) => self.receive_request_update(request_id, m),
            ControlMessage::GoAway(ref m) => self.receive_goaway_on_request_stream(request_id, m),
            ControlMessage::Namespace(ref m) => self.receive_namespace(m),
            ControlMessage::NamespaceDone(ref m) => self.receive_namespace_done(m),
            ControlMessage::PublishSkipped(ref m) => self.receive_publish_skipped(m),
            _ => Err(EndpointError::ResponseOnControlStream),
        }
    }

    /// Process a GOAWAY that arrived on one request stream rather than on the
    /// control stream.
    ///
    /// Draft-19 Section 10.4: "A GOAWAY MAY also be sent on a request stream
    /// to initiate migration of that individual request. Upon receiving a
    /// GOAWAY on a request stream, the endpoint SHOULD re-issue that specific
    /// request on a session at the specified URI". The session keeps running —
    /// only this request is being moved — so the session state machine is not
    /// touched and no draining event follows. The server-side URI rule of the
    /// same section still applies.
    ///
    /// # Errors
    ///
    /// [`EndpointError::RepeatedGoAwayOnRequestStream`] if this request's
    /// stream has already carried one. The session is over: this endpoint's own
    /// state has moved to Closed and the code the transport should close with
    /// is in [`EndpointError::session_error_code`].
    pub fn receive_goaway_on_request_stream(
        &mut self,
        request_id: VarInt,
        msg: &GoAway,
    ) -> Result<(), EndpointError> {
        if self.role == Role::Server && !msg.new_session_uri.is_empty() {
            return Err(self.fail_session(EndpointError::GoAwayUriAtServer));
        }
        let id = request_id.into_inner();
        if self.subscriptions.contains_key(&id)
            || self.publishes.contains_key(&id)
            || self.fetches.contains_key(&id)
            || self.subscribe_namespaces.contains_key(&id)
            || self.subscribe_tracks.contains_key(&id)
            || self.publish_namespaces.contains_key(&id)
            || self.track_statuses.contains_key(&id)
        {
            // Section 10.4 counts per stream, so this is a separate first
            // GOAWAY on every request and a repeat only on the one that has
            // already carried one. The set is fed only by GOAWAYs accepted
            // here, and never pruned: a Request ID is spent once, so an entry
            // can never come to describe a different request.
            if self.goaway_request_streams.insert(id) {
                Ok(())
            } else {
                Err(self.fail_session(EndpointError::RepeatedGoAwayOnRequestStream(id)))
            }
        } else {
            Err(EndpointError::UnknownRequest(id))
        }
    }

    // -- Responder side: requests the peer opened a stream with -----

    /// Refuse a bidirectional stream the peer opened with a message type that
    /// does not begin a request, and end the session.
    ///
    /// Draft-19 Section 3.3: "Bidirectional streams MUST NOT begin with any
    /// other message type unless negotiated. If they do, the peer MUST close
    /// the Session with a PROTOCOL_VIOLATION." The returned error answers
    /// `Some(ProtocolViolation)` from
    /// [`EndpointError::session_error_code`], which is what tells the
    /// connection layer to put the close on the wire.
    pub fn refuse_non_request(&mut self, ty: MessageType) -> EndpointError {
        self.fail_session(EndpointError::NotARequest(ty))
    }

    /// Register a request the **peer** opened a bidirectional stream with, and
    /// hand back the Request ID it carries.
    ///
    /// The mirror of [`receive_response_on_stream`](Self::receive_response_on_stream):
    /// that one is fed what comes back on a stream this endpoint opened, this
    /// one is fed the first message on a stream the peer opened.
    ///
    /// # What it enforces, and with which code
    ///
    /// Draft-19 Section 10.1: "If an endpoint receives a Request ID where the
    /// least significant bit is incorrect for the sender, or a duplicate
    /// Request ID, it MUST close the session with INVALID_REQUEST_ID." Both
    /// halves are checked here and both are returned as errors that answer
    /// `Some(InvalidRequestId)` from
    /// [`EndpointError::session_error_code`]. A message that opens no request
    /// stream at all is a different rule with a different code — see
    /// [`refuse_non_request`](Self::refuse_non_request).
    ///
    /// # Why there are no separate inbound maps
    ///
    /// The peer's ids and this endpoint's ids have opposite least significant
    /// bits, so they cannot collide. A peer's request goes into the same
    /// `HashMap` its outbound twin would, keyed the same way, and only the
    /// transition names differ — `on_subscribe_received` where the outbound
    /// path calls `on_subscribe_sent`.
    ///
    /// # Peer-controlled growth
    ///
    /// Every accepted request adds an entry that nothing removes, and the peer
    /// chooses how many to open. [`peer_request_count`](Self::peer_request_count)
    /// is what a responder can watch to impose its own ceiling; this method
    /// imposes none.
    pub fn receive_request_on_stream(
        &mut self,
        msg: &ControlMessage,
    ) -> Result<VarInt, EndpointError> {
        let request_id = match msg {
            ControlMessage::Subscribe(m) => m.request_id,
            ControlMessage::Publish(m) => m.request_id,
            ControlMessage::Fetch(m) => m.request_id,
            ControlMessage::PublishNamespace(m) => m.request_id,
            ControlMessage::SubscribeNamespace(m) => m.request_id,
            ControlMessage::SubscribeTracks(m) => m.request_id,
            ControlMessage::TrackStatus(m) => m.request_id,
            other => return Err(self.refuse_non_request(other.message_type())),
        };
        self.require_active_or_err()?;

        let id = request_id.into_inner();
        if let Err(e) = self.request_ids.validate_peer_id(id) {
            return Err(self.fail_session(EndpointError::RequestId(e)));
        }
        // `insert` answers false when the id was already present, which is
        // exactly the duplicate the section names. Doing the check and the
        // record in one step means no path can record an id it did not check.
        if !self.peer_request_ids.insert(id) {
            return Err(self.fail_session(EndpointError::DuplicateRequestId(id)));
        }

        match msg {
            ControlMessage::Subscribe(_) => {
                let mut sm = SubscriptionStateMachine::new();
                sm.on_subscribe_received()?;
                self.subscriptions.insert(id, sm);
            }
            ControlMessage::Publish(m) => {
                let alias = m.track_alias.into_inner();
                if let Some(conflict) =
                    self.conflicting_track_alias(id, alias, &m.track_namespace, &m.track_name)
                {
                    return Err(self.fail_session(conflict));
                }
                let mut sm = PublishStateMachine::new();
                sm.on_publish_received()?;
                self.publishes.insert(id, sm);
                // A PUBLISH names its track and its alias in the one message,
                // so the binding is complete on arrival. It counts against the
                // next one only once this endpoint has answered PUBLISH_OK,
                // which is what moves its state machine to Active.
                self.track_bindings.insert(
                    id,
                    TrackBinding {
                        namespace: m.track_namespace.clone(),
                        name: m.track_name.clone(),
                        alias: Some(alias),
                        kind: BindingKind::Publish,
                    },
                );
            }
            ControlMessage::Fetch(m) => {
                if let Some(joining) = self.joining_subscription_missing(m) {
                    self.unjoinable_fetches.insert(id, joining);
                }
                let mut sm = FetchStateMachine::new();
                sm.on_fetch_received()?;
                self.fetches.insert(id, sm);
            }
            ControlMessage::PublishNamespace(_) => {
                let mut sm = PublishNamespaceStateMachine::new();
                sm.on_publish_namespace_received()?;
                self.publish_namespaces.insert(id, sm);
            }
            ControlMessage::SubscribeNamespace(m) => {
                if let Some(established) = self.peer_namespace_overlap(&m.namespace_prefix, None) {
                    self.overlapping_namespace_subscriptions.insert(id, established);
                }
                let mut sm = SubscribeNamespaceStateMachine::new();
                sm.on_subscribe_namespace_received()?;
                self.subscribe_namespaces.insert(id, sm);
            }
            // The seventh request kind, and the one draft-17 does not have.
            // It gets its own map for the same reason the outbound path gives
            // it one: Section 10.19 makes SUBSCRIBE_TRACKS and
            // SUBSCRIBE_NAMESPACE independent overlap spaces, so a responder
            // that merged them would answer the wrong request.
            ControlMessage::SubscribeTracks(m) => {
                // Its own space: a SUBSCRIBE_TRACKS is weighed against the
                // SUBSCRIBE_TRACKS the peer has open and against nothing else,
                // so one prefix may carry one of each.
                if let Some(established) = self.peer_tracks_overlap(&m.namespace_prefix, None) {
                    self.overlapping_namespace_subscriptions.insert(id, established);
                }
                let mut sm = SubscribeNamespaceStateMachine::new();
                sm.on_subscribe_namespace_received()?;
                self.subscribe_tracks.insert(id, sm);
            }
            ControlMessage::TrackStatus(_) => {
                let mut sm = TrackStatusStateMachine::new();
                sm.on_track_status_received()?;
                self.track_statuses.insert(id, sm);
            }
            // Unreachable: the match above returned for every other variant.
            other => return Err(self.refuse_non_request(other.message_type())),
        }

        // The request as it arrived, recorded last so that nothing above it
        // can leave one behind for a request it went on to refuse.
        self.inbound_requests.insert(id, msg.clone());

        // After the request is recorded, never before. The answer to every
        // Range Filter rule is a REQUEST_ERROR, which names the Request ID of
        // the request it answers, so refusing here would leave nothing to
        // answer with.
        let parameters = request_parameters(msg);
        if let Some(rejection) = self.filter_verdict(parameters) {
            self.peer_filter_rejections.insert(id, rejection);
        }
        self.peer_request_filters.insert(id, range_filter_parameters(parameters));
        Ok(request_id)
    }

    // -- What the peer asked for ------------------------------------

    /// The SUBSCRIBE the peer sent under `request_id` and this endpoint has
    /// not answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no SUBSCRIBE under, and for one this endpoint spent on a
    /// request of its own -- whose state is in the same map, but which never
    /// arrived here. The record itself lives on past the answer, because the
    /// subscription it opened runs on after it, for as long as the request
    /// stream does.
    pub fn pending_subscribe(&self, request_id: VarInt) -> Option<&Subscribe> {
        let id = request_id.into_inner();
        let unanswered = self
            .subscriptions
            .get(&id)
            .is_some_and(|sm| sm.state() == SubscriptionState::Subscribing);
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::Subscribe(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many SUBSCRIBEs the peer has sent that are still waiting for an
    /// answer.
    pub fn pending_subscribe_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::Subscribe(_))
                    && self
                        .subscriptions
                        .get(*id)
                        .is_some_and(|sm| sm.state() == SubscriptionState::Subscribing)
            })
            .count()
    }

    /// The PUBLISH the peer sent under `request_id` and this endpoint has not
    /// answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no PUBLISH under, and for one this endpoint spent on a request
    /// of its own -- whose state is in the same map, but which never arrived
    /// here. The record itself lives on past the answer, because the
    /// subscription the offer opened runs on after it, for as long as the
    /// request stream does.
    pub fn pending_publish(&self, request_id: VarInt) -> Option<&message::Publish> {
        let id = request_id.into_inner();
        let unanswered =
            self.publishes.get(&id).is_some_and(|sm| sm.state() == PublishState::Publishing);
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::Publish(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many offers the peer has sent that are still waiting for an
    /// answer.
    pub fn pending_publish_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::Publish(_))
                    && self
                        .publishes
                        .get(*id)
                        .is_some_and(|sm| sm.state() == PublishState::Publishing)
            })
            .count()
    }

    /// The FETCH the peer sent under `request_id` and this endpoint has not
    /// answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no FETCH under, and for one this endpoint spent on a request
    /// of its own -- whose state is in the same map, but which never arrived
    /// here. The record itself lives on past the answer, because the fetch is
    /// not over until its response stream is.
    pub fn pending_fetch(&self, request_id: VarInt) -> Option<&Fetch> {
        let id = request_id.into_inner();
        let unanswered = self
            .fetches
            .get(&id)
            .is_some_and(|sm| matches!(sm.state(), FetchState::Pending | FetchState::Unanswered));
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::Fetch(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many FETCHes the peer has sent that are still waiting for an
    /// answer.
    pub fn pending_fetch_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::Fetch(_))
                    && self.fetches.get(*id).is_some_and(|sm| {
                        matches!(sm.state(), FetchState::Pending | FetchState::Unanswered)
                    })
            })
            .count()
    }

    /// The PUBLISH_NAMESPACE the peer sent under `request_id` and this
    /// endpoint has not answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no PUBLISH_NAMESPACE under, and for one this endpoint spent on
    /// a request of its own -- whose state is in the same map, but which
    /// never arrived here. The record itself lives on past the answer,
    /// because an announcement that was accepted stands until it is
    /// withdrawn.
    pub fn pending_publish_namespace(&self, request_id: VarInt) -> Option<&PublishNamespace> {
        let id = request_id.into_inner();
        let unanswered = self
            .publish_namespaces
            .get(&id)
            .is_some_and(|sm| sm.state() == PublishNamespaceState::Pending);
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::PublishNamespace(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many announcements the peer has sent that are still waiting for an
    /// answer.
    pub fn pending_publish_namespace_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::PublishNamespace(_))
                    && self
                        .publish_namespaces
                        .get(*id)
                        .is_some_and(|sm| sm.state() == PublishNamespaceState::Pending)
            })
            .count()
    }

    /// The earliest namespace subscription the peer has made whose prefix
    /// overlaps `prefix`, and `None` when there is none.
    ///
    /// Only ones that have not ended count: the sentence weighs the arriving
    /// prefix against an "established" one, so one the peer has withdrawn and
    /// one this endpoint refused are both past. Drafts 07 through 11 say "an
    /// earlier" instead and count those too.
    ///
    /// One that has arrived and has not been answered does count. It is not
    /// established yet, but this endpoint is the one about to establish it,
    /// and accepting both would leave the session holding exactly the pair
    /// the sentence exists to prevent.
    ///
    /// The record of what the peer sent is what tells the two directions
    /// apart. The state machines live in one map per kind whichever end
    /// opened the request, so a prefix this endpoint asked about would be
    /// indistinguishable there; only requests that arrived are written into
    /// `inbound_requests`.
    ///
    /// The lowest Request ID wins when more than one overlaps, so the answer
    /// does not depend on the order a map happens to iterate in.
    ///
    /// `except` is the subscription a REQUEST_UPDATE is moving, which Section
    /// 10.2.19 weighs against "another active subscription of the same type"
    /// and therefore not against the prefix it is leaving behind.
    fn peer_namespace_overlap(&self, prefix: &TrackNamespace, except: Option<u64>) -> Option<u64> {
        self.inbound_requests
            .iter()
            .filter(|(&id, _)| Some(id) != except)
            .filter_map(|(&id, msg)| match msg {
                ControlMessage::SubscribeNamespace(m) => Some((id, &m.namespace_prefix)),
                _ => None,
            })
            .filter(|(id, _)| {
                self.subscribe_namespaces
                    .get(id)
                    .is_some_and(|sm| sm.state() != SubscribeNamespaceState::Done)
            })
            .filter_map(|(id, p)| prefixes_overlap(&p.0, &prefix.0).then_some(id))
            .min()
    }

    /// The earliest track subscription the peer has made whose prefix
    /// overlaps `prefix`, and `None` when there is none.
    ///
    /// Only ones that have not ended count: the sentence weighs the arriving
    /// prefix against an "established" one, so one the peer has withdrawn and
    /// one this endpoint refused are both past. Drafts 07 through 11 say "an
    /// earlier" instead and count those too.
    ///
    /// One that has arrived and has not been answered does count. It is not
    /// established yet, but this endpoint is the one about to establish it,
    /// and accepting both would leave the session holding exactly the pair
    /// the sentence exists to prevent.
    ///
    /// The record of what the peer sent is what tells the two directions
    /// apart. The state machines live in one map per kind whichever end
    /// opened the request, so a prefix this endpoint asked about would be
    /// indistinguishable there; only requests that arrived are written into
    /// `inbound_requests`.
    ///
    /// The lowest Request ID wins when more than one overlaps, so the answer
    /// does not depend on the order a map happens to iterate in.
    ///
    /// `except` is the subscription a REQUEST_UPDATE is moving, which Section
    /// 10.2.19 weighs against "another active subscription of the same type"
    /// and therefore not against the prefix it is leaving behind.
    fn peer_tracks_overlap(&self, prefix: &TrackNamespace, except: Option<u64>) -> Option<u64> {
        self.inbound_requests
            .iter()
            .filter(|(&id, _)| Some(id) != except)
            .filter_map(|(&id, msg)| match msg {
                ControlMessage::SubscribeTracks(m) => Some((id, &m.namespace_prefix)),
                _ => None,
            })
            .filter(|(id, _)| {
                self.subscribe_tracks
                    .get(id)
                    .is_some_and(|sm| sm.state() != SubscribeNamespaceState::Done)
            })
            .filter_map(|(id, p)| prefixes_overlap(&p.0, &prefix.0).then_some(id))
            .min()
    }

    /// The SUBSCRIBE_NAMESPACE the peer sent under `request_id` and this
    /// endpoint has not answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no SUBSCRIBE_NAMESPACE under, and for one this endpoint spent
    /// on a request of its own -- whose state is in the same map, but which
    /// never arrived here. The record itself lives on past the answer,
    /// because a namespace subscription lasts as long as its stream does.
    pub fn pending_subscribe_namespace(&self, request_id: VarInt) -> Option<&SubscribeNamespace> {
        let id = request_id.into_inner();
        let unanswered = self
            .subscribe_namespaces
            .get(&id)
            .is_some_and(|sm| sm.state() == SubscribeNamespaceState::Pending);
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::SubscribeNamespace(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many namespace subscriptions the peer has sent that are still
    /// waiting for an answer.
    pub fn pending_subscribe_namespace_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::SubscribeNamespace(_))
                    && self
                        .subscribe_namespaces
                        .get(*id)
                        .is_some_and(|sm| sm.state() == SubscribeNamespaceState::Pending)
            })
            .count()
    }

    /// The SUBSCRIBE_TRACKS the peer sent under `request_id` and this
    /// endpoint has not answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no SUBSCRIBE_TRACKS under, and for one this endpoint spent on
    /// a request of its own -- whose state is in the same map, but which
    /// never arrived here. The record itself lives on past the answer,
    /// because the subscription it opened lasts as long as its stream does.
    pub fn pending_subscribe_tracks(&self, request_id: VarInt) -> Option<&SubscribeTracks> {
        let id = request_id.into_inner();
        let unanswered = self
            .subscribe_tracks
            .get(&id)
            .is_some_and(|sm| sm.state() == SubscribeNamespaceState::Pending);
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::SubscribeTracks(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many track subscriptions the peer has sent that are still waiting
    /// for an answer.
    pub fn pending_subscribe_tracks_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::SubscribeTracks(_))
                    && self
                        .subscribe_tracks
                        .get(*id)
                        .is_some_and(|sm| sm.state() == SubscribeNamespaceState::Pending)
            })
            .count()
    }

    /// The TRACK_STATUS the peer sent under `request_id` and this endpoint
    /// has not answered yet.
    ///
    /// `None` once it has been answered, for an identifier this session has
    /// carried no TRACK_STATUS under, and for one this endpoint spent on a
    /// request of its own -- whose state is in the same map, but which never
    /// arrived here. The record itself lives on past the answer, because an
    /// update may still name it once it has been answered.
    pub fn pending_track_status(&self, request_id: VarInt) -> Option<&message::TrackStatus> {
        let id = request_id.into_inner();
        let unanswered =
            self.track_statuses.get(&id).is_some_and(|sm| sm.state() == TrackStatusState::Pending);
        match self.inbound_requests.get(&id) {
            Some(ControlMessage::TrackStatus(msg)) if unanswered => Some(msg),
            _ => None,
        }
    }

    /// How many track statuses the peer has sent that are still waiting for
    /// an answer.
    pub fn pending_track_status_count(&self) -> usize {
        self.inbound_requests
            .iter()
            .filter(|(id, msg)| {
                matches!(msg, ControlMessage::TrackStatus(_))
                    && self
                        .track_statuses
                        .get(*id)
                        .is_some_and(|sm| sm.state() == TrackStatusState::Pending)
            })
            .count()
    }

    /// Whether the Range Filters in `parameters` are ones this endpoint may
    /// accept.
    ///
    /// The three rules that need more than one parameter to see, in the order
    /// that reports the most specific fault: whether the filters read at all,
    /// then whether any budget was advertised, then whether the request stays
    /// inside it, then whether two filters share a key. A request with no Range
    /// Filter at all is not measured against the ceiling, so an endpoint that
    /// advertised nothing still takes ordinary requests — which is the whole of
    /// the traffic today, since draft-19 is the first draft with these
    /// parameters.
    fn filter_verdict(&self, parameters: &[KeyValuePair]) -> Option<FilterRejection> {
        let filters = match range_filter::decode_all_moqt::<Moqt18>(parameters) {
            Ok(filters) => filters,
            Err(e) => return Some(FilterRejection::Unreadable(e)),
        };
        if filters.is_empty() {
            return None;
        }
        if self.advertised_max_filter_ranges == 0 {
            return Some(FilterRejection::NoBudgetAdvertised);
        }
        let ranges = range_filter::total_ranges(&filters);
        if ranges as u64 > self.advertised_max_filter_ranges {
            return Some(FilterRejection::TooManyRanges {
                ranges,
                limit: self.advertised_max_filter_ranges,
            });
        }
        if let Some((parameter_type, set_id, property_type)) =
            range_filter::first_repeated_key(&filters)
        {
            return Some(FilterRejection::RepeatedFilter(parameter_type, set_id, property_type));
        }
        None
    }

    /// Why request `id` must be answered with a REQUEST_ERROR, if it must.
    ///
    /// The caller builds the message; [`FilterRejection::request_error_code`]
    /// gives the code and the variant gives the reason phrase. Answering it
    /// clears the record.
    pub fn filter_rejection(&self, id: VarInt) -> Option<&FilterRejection> {
        self.peer_filter_rejections.get(&id.into_inner())
    }

    /// Whether this response answers a REQUEST_UPDATE rather than the request
    /// that opened the stream. Section 10.9 gives an update the same two
    /// answers a request has: "The receiver of a REQUEST_UPDATE MUST respond
    /// with exactly one REQUEST_OK or REQUEST_ERROR message indicating if the
    /// update was successful, unless it is coalescing failed updates to produce
    /// just one REQUEST_ERROR for multiple REQUEST_UPDATE messages." Nothing in
    /// either message says which of the two it is answering, so the question is
    /// settled twice over.
    ///
    /// A SUBSCRIBE is answered with SUBSCRIBE_OK and a FETCH with FETCH_OK, so a
    /// REQUEST_OK on one of those streams has no other message it could be
    /// answering. That is the half that needs no ordering.
    ///
    /// Everywhere else it is ordering: the first REQUEST_OK or REQUEST_ERROR on
    /// a stream answers the request that opened it, and the ones after it answer
    /// updates. Both endpoints have to resolve it the same way and neither has
    /// anything else to resolve it with.
    fn answers_an_update(&self, id: u64, msg: &ControlMessage) -> bool {
        if !matches!(msg, ControlMessage::RequestOk(_) | ControlMessage::RequestError(_)) {
            return false;
        }
        // A request this endpoint made is answered by the peer, so a response
        // written here can only be answering an update the peer sent on it.
        // Section 10.9 names the one request that works that way: "A subscriber
        // can also send REQUEST_UPDATE to modify parameters of a subscription
        // established with PUBLISH."
        if self.publishes.contains_key(&id) && !self.inbound_requests.contains_key(&id) {
            return true;
        }
        if matches!(msg, ControlMessage::RequestOk(_))
            && (self.subscriptions.contains_key(&id) || self.fetches.contains_key(&id))
        {
            return true;
        }
        self.answered_peer_requests.contains(&id)
    }

    /// Record a response as the answer to one or more outstanding updates.
    ///
    /// A REQUEST_OK answers exactly one: "The receiver MUST still send a
    /// REQUEST_OK for each successful update". A REQUEST_ERROR may answer every
    /// update still waiting, because Section 10.9.1 permits the receiver to
    /// coalesce them — "If the coalesced REQUEST_UPDATE results in
    /// REQUEST_ERROR, only a single REQUEST_ERROR will be sent and the sender of
    /// the REQUEST_UPDATEs will not always be able to determine which caused an
    /// error." Draft-17 has no such paragraph, and its endpoint answers one
    /// update per message in both directions.
    ///
    /// The credit MAX_REQUEST_UPDATES counts is restored once whatever the
    /// answer covered, which is Section 10.3.1.7 read literally: "Each
    /// REQUEST_OK or REQUEST_ERROR response restores one credit on that stream."
    /// The peer restores by the same sentence, so an endpoint that gave back one
    /// per coalesced update would be crediting a peer that is not.
    ///
    /// No state machine moves. An update changes a request's parameters and not
    /// its lifecycle, so a subscription that was Active before its update was
    /// answered is Active after it, whichever answer went out.
    ///
    /// # Errors
    ///
    /// [`EndpointError::NoUpdateToAnswer`], and nothing is written or spent.
    ///
    /// [`EndpointError::PeerPrefixOverlap`] and
    /// [`EndpointError::WrongOverlapRefusal`] when the update asked to move a
    /// namespace subscription onto a prefix that overlaps another of its kind
    /// and the answer is not the REQUEST_ERROR the sentence names. The same
    /// two the request itself is refused with, because it is the same rule
    /// under the same code; which of the two moments raised it is told apart
    /// by which call returned.
    fn answer_an_update(&mut self, id: u64, msg: &ControlMessage) -> Result<(), EndpointError> {
        let unanswered = self.unanswered_peer_updates.get(&id).copied().unwrap_or(0);
        if unanswered == 0 {
            return Err(EndpointError::NoUpdateToAnswer(id));
        }
        // The update's half of the overlap rule, and the reason it needs a
        // verdict of its own: an update is answered by the same two messages
        // on the same stream as the request, so the moment one of them is
        // about to be written is the one place both the answer and the code
        // the sentence names are known. Section 10.2.19: "If the new prefix
        // would share a common prefix with another active subscription of the
        // same type in the same session, the receiver MUST respond with
        // REQUEST_ERROR with error code PREFIX_OVERLAP."
        if let Some(&established) = self.overlapping_prefix_updates.get(&id) {
            let ControlMessage::RequestError(err) = msg else {
                return Err(EndpointError::PeerPrefixOverlap { request: id, established });
            };
            let required = RequestErrorCode::PrefixOverlap as u64;
            if err.error_code.into_inner() != required {
                return Err(EndpointError::WrongOverlapRefusal { request: id, required });
            }
        }
        let answered = if matches!(msg, ControlMessage::RequestError(_)) { unanswered } else { 1 };
        self.unanswered_peer_updates.insert(id, unanswered - answered);
        self.restore_update_credit(id);
        // The same rule the request's own REQUEST_ERROR spends: a filter this
        // endpoint owes an error about has been answered.
        if matches!(msg, ControlMessage::RequestError(_)) {
            self.peer_filter_rejections.remove(&id);
        }
        // The prefix moves on the acceptance and not before: "If the update is
        // accepted, NAMESPACE and NAMESPACE_DONE messages following the
        // REQUEST_OK will contain Track Namespace suffixes relative to the
        // updated prefix." A REQUEST_ERROR drops it and the subscription goes
        // on selecting what it selected before the update was sent.
        //
        // Nothing else is recomputed. A subscription this endpoint has already
        // refused keeps that verdict when ground it wanted comes free, because
        // the sentence that refused it names the moment it arrived and that
        // moment has passed.
        let accepted = matches!(msg, ControlMessage::RequestOk(_));
        if let Some(prefix) = self.updated_namespace_prefixes.remove(&id) {
            if accepted {
                match self.inbound_requests.get_mut(&id) {
                    Some(ControlMessage::SubscribeNamespace(m)) => m.namespace_prefix = prefix,
                    Some(ControlMessage::SubscribeTracks(m)) => m.namespace_prefix = prefix,
                    // Unreachable: nothing else is ever written above.
                    _ => {}
                }
            }
        }
        if !accepted {
            self.overlapping_prefix_updates.remove(&id);
        }
        Ok(())
    }

    /// Drive the state machine for a message this endpoint is about to write
    /// on a request stream the peer opened.
    ///
    /// The mirror of [`receive_response_on_stream`](Self::receive_response_on_stream),
    /// and the reason the transitions are named `*_sent` rather than reusing
    /// the received-side ones: the state edges coincide, so a mis-dispatch
    /// would otherwise succeed silently instead of naming the wrong event in
    /// an `InvalidTransition`.
    ///
    /// Beyond the four responses this also takes the three messages draft-19
    /// Table 5 places on a request stream that a responder writes after its
    /// response: NAMESPACE and NAMESPACE_DONE on a SUBSCRIBE_NAMESPACE stream
    /// (Sections 10.16 and 10.17) and PUBLISH_SKIPPED on a SUBSCRIBE_TRACKS
    /// stream (Section 10.20). All three require the request to have been
    /// accepted first, because each machine only leaves Pending on its
    /// REQUEST_OK.
    ///
    /// The caller writes `msg` only after this returns `Ok`. What it cannot
    /// undo is the opposite order: a write that fails afterwards leaves the
    /// state machine one step ahead of the wire, the same asymmetry the
    /// outbound request path already carries.
    /// The identifier an arriving Joining Fetch names, when this session has
    /// no subscription it may join.
    ///
    /// Section 10.12.2:
    /// "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to a subscription in the same session in the
    /// Established or Pending (subscriber) states, it MUST return a
    /// REQUEST_ERROR with error code INVALID_JOINING_REQUEST_ID."
    /// A standalone fetch names none and answers `None`, and so does a joining
    /// one whose subscription is live. Either message can establish the one it
    /// joins: Section 5.1 says the Largest Location a Joining FETCH works from
    /// is the one saved "communicated in SUBSCRIBE_OK, PUBLISH or
    /// REQUEST_UPDATE_OK that changes the Forward State from 0 to 1".
    fn joining_subscription_missing(&self, msg: &Fetch) -> Option<u64> {
        let message::FetchPayload::Joining { joining_request_id: joined, .. } = &msg.fetch_payload
        else {
            return None;
        };
        let joined = joined.into_inner();
        let live =
            self.subscriptions.get(&joined).is_some_and(|s| s.state() != SubscriptionState::Done)
                || self.publishes.get(&joined).is_some_and(|p| p.state() != PublishState::Done);
        if live {
            None
        } else {
            Some(joined)
        }
    }

    /// Drive the state machines for a response this endpoint is about to write
    /// on a request stream the peer opened.
    ///
    /// The caller writes the message only after this returns `Ok`, so a
    /// response the endpoint refuses never reaches the wire.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when no request of the answering kind
    /// carries that identifier, [`EndpointError::NotAResponse`] when the
    /// message is not one, [`EndpointError::UnjoinableSubscription`] and
    /// [`EndpointError::WrongJoiningRefusal`] for a Joining Fetch that named no
    /// live subscription, [`EndpointError::PeerPrefixOverlap`] and
    /// [`EndpointError::WrongOverlapRefusal`] for a namespace subscription that
    /// overlapped one already open or that a REQUEST_UPDATE asked to move onto
    /// an overlapping prefix, [`EndpointError::FilterMustBeRejected`] for a request whose Range Filters this draft says to reject, and each flow's own
    /// `InvalidTransition` for a request already answered.
    pub fn send_response_on_stream(
        &mut self,
        request_id: VarInt,
        msg: &ControlMessage,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        // A request whose Range Filters the draft says to reject may be
        // answered with a REQUEST_ERROR and with nothing else. Checked across
        // every acceptance rather than inside the REQUEST_OK arm, because
        // SUBSCRIBE and FETCH — the two requests that most obviously carry these
        // filters — are accepted with SUBSCRIBE_OK and FETCH_OK instead.
        if matches!(
            msg,
            ControlMessage::SubscribeOk(_)
                | ControlMessage::FetchOk(_)
                | ControlMessage::RequestOk(_)
        ) {
            if let Some(rejection) = self.peer_filter_rejections.get(&id) {
                return Err(EndpointError::FilterMustBeRejected(id, rejection.clone()));
            }
        }
        // An answer to an update reaches none of the arms below: the request it
        // belongs to has its own lifecycle and an update does not move it.
        // A refused update leaves this endpoint owing the peer a termination,
        // and the draft names the status that termination must carry. So the
        // request's ending is what the debt governs: a PUBLISH_DONE under any
        // other status is refused, and everything else the caller may still
        // have to write for this request - the answer to a second update it
        // has not answered yet - is left alone, because the sentence orders
        // nothing.
        if let ControlMessage::PublishDone(done) = msg {
            self.require_update_failure_status(id, done.status_code)?;
        }
        if self.answers_an_update(id, msg) {
            self.answer_an_update(id, msg)?;
            // Refusing an update is half of what the draft asks for, and which
            // half it is depends on what was being updated. A subscription is
            // owed the PUBLISH_DONE that ends it, recorded here so that the
            // next ending written for this request has to be that one. A
            // namespace request, a fetch and a track status are owed no
            // message at all, and recording one for them would keep a stream
            // open that has nothing left to carry.
            if matches!(msg, ControlMessage::RequestError(_)) && self.publishes_a_subscription(id) {
                self.owed_update_failures.insert(id);
            }
            return Ok(());
        }
        // A namespace subscription that overlapped one already open when it
        // arrived has one answer available to it, and this is where both the
        // answer and its code are known. An update's answer returned above, so
        // nothing here judges one.
        if let Some(&established) = self.overlapping_namespace_subscriptions.get(&id) {
            let ControlMessage::RequestError(err) = msg else {
                return Err(EndpointError::PeerPrefixOverlap { request: id, established });
            };
            let required = RequestErrorCode::PrefixOverlap as u64;
            if err.error_code.into_inner() != required {
                return Err(EndpointError::WrongOverlapRefusal { request: id, required });
            }
        }
        match msg {
            ControlMessage::SubscribeOk(_) => {
                let sm =
                    self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_subscribe_ok_sent()?;
            }
            ControlMessage::FetchOk(_) => {
                if let Some(&joining) = self.unjoinable_fetches.get(&id) {
                    return Err(EndpointError::UnjoinableSubscription { fetch: id, joining });
                }
                let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_fetch_ok_sent()?;
            }
            ControlMessage::PublishDone(_) => {
                let sm =
                    self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_publish_done_sent()?;
            }
            // REQUEST_OK answers the kinds that have no response message of
            // their own, PUBLISH among them since draft-18 folded PUBLISH_OK
            // into it. The probe order does not matter: the maps are keyed by
            // Request ID and one id belongs to one request.
            ControlMessage::RequestOk(m) => {
                // Section 10.5 makes receiving Track Properties on anything but
                // a TRACK_STATUS response a session close, so putting them on
                // one of the others would be handing the peer a reason to close
                // this session. Refused before the write rather than after.
                if !m.track_properties.is_empty() && !self.track_statuses.contains_key(&id) {
                    return Err(EndpointError::TrackPropertiesOnOutgoingRequestOk(id));
                }
                if let Some(sm) = self.publishes.get_mut(&id) {
                    sm.on_publish_ok_sent()?;
                } else if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
                    sm.on_subscribe_namespace_ok_sent()?;
                } else if let Some(sm) = self.subscribe_tracks.get_mut(&id) {
                    sm.on_subscribe_namespace_ok_sent()?;
                } else if let Some(sm) = self.publish_namespaces.get_mut(&id) {
                    sm.on_publish_namespace_ok_sent()?;
                } else if let Some(sm) = self.track_statuses.get_mut(&id) {
                    sm.on_track_status_ok_sent()?;
                } else {
                    return Err(EndpointError::UnknownRequest(id));
                }
            }
            ControlMessage::RequestError(err) => {
                if let Some(sm) = self.subscriptions.get_mut(&id) {
                    sm.on_subscribe_error_sent()?;
                } else if self.fetches.contains_key(&id) {
                    if self.unjoinable_fetches.contains_key(&id) {
                        let required = RequestErrorCode::InvalidJoiningRequestId as u64;
                        if err.error_code.into_inner() != required {
                            return Err(EndpointError::WrongJoiningRefusal { fetch: id, required });
                        }
                    }
                    let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                    sm.on_fetch_error_sent()?;
                } else if let Some(sm) = self.publishes.get_mut(&id) {
                    sm.on_publish_error_sent()?;
                } else if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
                    sm.on_subscribe_namespace_error_sent()?;
                } else if let Some(sm) = self.subscribe_tracks.get_mut(&id) {
                    sm.on_subscribe_namespace_error_sent()?;
                } else if let Some(sm) = self.publish_namespaces.get_mut(&id) {
                    sm.on_publish_namespace_error_sent()?;
                } else if let Some(sm) = self.track_statuses.get_mut(&id) {
                    sm.on_track_status_error_sent()?;
                } else {
                    return Err(EndpointError::UnknownRequest(id));
                }
            }
            ControlMessage::Namespace(_) => {
                let sm = self
                    .subscribe_namespaces
                    .get_mut(&id)
                    .ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_namespace_sent()?;
            }
            ControlMessage::NamespaceDone(_) => {
                let sm = self
                    .subscribe_namespaces
                    .get_mut(&id)
                    .ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_namespace_done_sent()?;
            }
            ControlMessage::PublishSkipped(_) => {
                let sm =
                    self.subscribe_tracks.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_publish_skipped_sent()?;
            }
            other => return Err(EndpointError::NotAResponse(other.message_type())),
        }
        // After the match, not before it: the caller writes `msg` only once
        // this returns `Ok`, so a response that was refused restores nothing.
        if matches!(msg, ControlMessage::RequestOk(_) | ControlMessage::RequestError(_)) {
            self.restore_update_credit(id);
        }
        // Reached only by a response that answered the request itself, since an
        // update's answer returned above. From here on, a REQUEST_OK or
        // REQUEST_ERROR on this stream can only be answering an update.
        if matches!(
            msg,
            ControlMessage::SubscribeOk(_)
                | ControlMessage::FetchOk(_)
                | ControlMessage::RequestOk(_)
                | ControlMessage::RequestError(_)
        ) {
            self.answered_peer_requests.insert(id);
        }
        // For the same reason, and it matters more here: a rejection cleared by
        // a REQUEST_ERROR that was itself refused would leave the request
        // acceptable on the next attempt.
        if matches!(msg, ControlMessage::RequestError(_)) {
            self.peer_filter_rejections.remove(&id);
        }
        Ok(())
    }

    /// Dispatch a message that arrived on a request stream the **peer** opened,
    /// after the request that opened it.
    ///
    /// Nothing that arrives here is a response: this endpoint is the responder
    /// on such a stream, so a SUBSCRIBE_OK or REQUEST_ERROR turning up is the
    /// peer answering its own request, and it is refused with
    /// [`EndpointError::UnexpectedOnPeerRequestStream`].
    ///
    /// Three messages are expected instead.
    ///
    /// REQUEST_UPDATE, because draft-19 Section 10.9 puts it on the request's
    /// own stream: "The sender of a request (SUBSCRIBE, PUBLISH, FETCH,
    /// PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) can later send
    /// a REQUEST_UPDATE on the same bidi stream as the request to modify it."
    /// It goes through the same [`receive_request_update`](Self::receive_request_update)
    /// the requester side uses, so the peer's update is held to the same rule
    /// its own would be: the message's Request ID must name the stream's
    /// request, and a kind the section does not allow to be updated —
    /// TRACK_STATUS, by Section 10.14 — closes the session.
    ///
    /// GOAWAY, because Section 10.4 lets one arrive on a request stream to
    /// migrate that request alone, in either direction.
    ///
    /// PUBLISH_DONE, because a peer that sent PUBLISH is the publisher and ends
    /// the publication it opened.
    pub fn receive_on_peer_request_stream(
        &mut self,
        request_id: VarInt,
        msg: ControlMessage,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        match msg {
            ControlMessage::RequestUpdate(ref m) => self.receive_request_update(request_id, m),
            // Section 10.4 puts no direction on it: "A GOAWAY MAY also be
            // sent on a request stream to initiate migration of that individual
            // request." A request the peer opened is a request stream, so a
            // GOAWAY on one migrates it the same way.
            ControlMessage::GoAway(ref m) => self.receive_goaway_on_request_stream(request_id, m),
            ControlMessage::PublishDone(_) => {
                let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_publish_done_received()?;
                Ok(())
            }
            other => Err(EndpointError::UnexpectedOnPeerRequestStream(other.message_type())),
        }
    }
}

// -- Responder-side state machine transitions -----------------------
//
// Each one is the same edge as an existing requester-side transition — the
// graph does not change with the direction — but under a name that says which
// way the message went, so a mis-dispatch names the responder event in the
// `InvalidTransition` it produces instead of quietly succeeding.
//
// They are written against the public surface of the machines rather than
// against the state field, so the rejected-state error has to be rebuilt to
// carry the responder event name.

impl SubscriptionStateMachine {
    /// Idle -> Subscribing (SUBSCRIBE received from the peer).
    pub fn on_subscribe_received(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_sent().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_subscribe_received".to_string(),
        })
    }

    /// Subscribing -> Active (SUBSCRIBE_OK written on the peer's stream).
    pub fn on_subscribe_ok_sent(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_ok().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_subscribe_ok_sent".to_string(),
        })
    }

    /// Subscribing -> Done (REQUEST_ERROR written on the peer's stream).
    pub fn on_subscribe_error_sent(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_error().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_subscribe_error_sent".to_string(),
        })
    }

    /// Active -> Done (PUBLISH_DONE written on the peer's stream).
    pub fn on_publish_done_sent(&mut self) -> Result<(), SubscriptionError> {
        self.on_publish_done().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_publish_done_sent".to_string(),
        })
    }
}

impl FetchStateMachine {
    /// Idle -> Pending (FETCH received from the peer).
    pub fn on_fetch_received(&mut self) -> Result<(), FetchError> {
        self.on_fetch_sent().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_received".to_string(),
        })
    }

    /// Pending -> Receiving, Unanswered -> Done (FETCH_OK written on the
    /// peer's stream).
    ///
    /// The state is named for the requester's view; for a responder the same
    /// node means the objects are being served rather than received. It is the
    /// same node in the graph, with the same edges, so it keeps its name.
    pub fn on_fetch_ok_sent(&mut self) -> Result<(), FetchError> {
        self.on_fetch_ok().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_ok_sent".to_string(),
        })
    }

    /// Pending | Unanswered -> Done (REQUEST_ERROR written on the peer's
    /// stream).
    pub fn on_fetch_error_sent(&mut self) -> Result<(), FetchError> {
        self.on_fetch_error().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_error_sent".to_string(),
        })
    }

    /// Receiving -> Done, Pending -> Unanswered (this endpoint finished the
    /// fetch data stream).
    pub fn on_stream_fin_sent(&mut self) -> Result<(), FetchError> {
        self.on_stream_fin().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_stream_fin_sent".to_string(),
        })
    }
}

impl PublishStateMachine {
    /// Idle -> Publishing (PUBLISH received from the peer).
    pub fn on_publish_received(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_sent().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_received".to_string(),
        })
    }

    /// Publishing -> Active (REQUEST_OK written on the peer's stream).
    ///
    /// Draft-18 folded PUBLISH_OK into REQUEST_OK and draft-19 keeps it that
    /// way, so the message that walks this edge is a REQUEST_OK here where on
    /// draft-17 it was a PUBLISH_OK of its own.
    pub fn on_publish_ok_sent(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_ok().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_ok_sent".to_string(),
        })
    }

    /// Publishing -> Done (REQUEST_ERROR written on the peer's stream).
    pub fn on_publish_error_sent(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_error().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_error_sent".to_string(),
        })
    }

    /// Active -> Done (PUBLISH_DONE received from the publishing peer).
    pub fn on_publish_done_received(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_done_sent().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_done_received".to_string(),
        })
    }
}

impl PublishNamespaceStateMachine {
    /// Idle -> Pending (PUBLISH_NAMESPACE received from the peer).
    pub fn on_publish_namespace_received(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_sent().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_received".to_string(),
        })
    }

    /// Pending -> Active (REQUEST_OK written on the peer's stream).
    pub fn on_publish_namespace_ok_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_ok().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_ok_sent".to_string(),
        })
    }

    /// Pending -> Done (REQUEST_ERROR written on the peer's stream).
    pub fn on_publish_namespace_error_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_error().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_error_sent".to_string(),
        })
    }
}

impl SubscribeNamespaceStateMachine {
    /// Idle -> Pending (SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS received from
    /// the peer).
    pub fn on_subscribe_namespace_received(&mut self) -> Result<(), NamespaceError> {
        self.on_subscribe_namespace_sent().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_subscribe_namespace_received".to_string(),
        })
    }

    /// Pending -> Active (REQUEST_OK written on the peer's stream).
    pub fn on_subscribe_namespace_ok_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_subscribe_namespace_ok().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_subscribe_namespace_ok_sent".to_string(),
        })
    }

    /// Pending -> Done (REQUEST_ERROR written on the peer's stream).
    pub fn on_subscribe_namespace_error_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_subscribe_namespace_error().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_subscribe_namespace_error_sent".to_string(),
        })
    }

    /// Active -> Active (NAMESPACE written on the peer's SUBSCRIBE_NAMESPACE
    /// stream).
    ///
    /// Draft-19 Section 10.16 puts NAMESPACE "on the response stream of a
    /// SUBSCRIBE_NAMESPACE request", and Section 10.18 has the publisher send
    /// them only once the request has been accepted — "If the
    /// SUBSCRIBE_NAMESPACE is successful, the publisher will send matching
    /// NAMESPACE messages on the response stream." Requiring Active is what
    /// makes one written ahead of the REQUEST_OK an error rather than a frame
    /// on the wire.
    ///
    /// Draft-17 has no such edge: its message table has no Stream column and
    /// nothing there moves NAMESPACE off the control stream.
    pub fn on_namespace_sent(&mut self) -> Result<(), NamespaceError> {
        self.require_active("on_namespace_sent")
    }

    /// Active -> Active (NAMESPACE_DONE written on the peer's
    /// SUBSCRIBE_NAMESPACE stream).
    ///
    /// Section 10.17: "All NAMESPACE_DONE messages are in response to a
    /// SUBSCRIBE_NAMESPACE". The namespace subscription outlives it — Section
    /// 10.18 has the publisher go on sending NAMESPACE and NAMESPACE_DONE "when
    /// there are changes to the namespaces being published" — so this ends one
    /// namespace, not the request, and the state does not move.
    pub fn on_namespace_done_sent(&mut self) -> Result<(), NamespaceError> {
        self.require_active("on_namespace_done_sent")
    }

    /// Active -> Active (PUBLISH_SKIPPED written on the peer's
    /// SUBSCRIBE_TRACKS stream).
    ///
    /// Section 10.20: "All PUBLISH_SKIPPED messages are in response to a
    /// SUBSCRIBE_TRACKS". One skipped track says nothing about the rest, so
    /// like the two above this is a self-transition on an accepted request.
    pub fn on_publish_skipped_sent(&mut self) -> Result<(), NamespaceError> {
        self.require_active("on_publish_skipped_sent")
    }

    /// The shared body of the three self-transitions above: accept the event
    /// when the request has been answered with REQUEST_OK, and name the event
    /// that was refused otherwise.
    fn require_active(&self, event: &str) -> Result<(), NamespaceError> {
        if self.state() == SubscribeNamespaceState::Active {
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state()),
                event: event.to_string(),
            })
        }
    }
}

impl TrackStatusStateMachine {
    /// Idle -> Pending (TRACK_STATUS received from the peer).
    pub fn on_track_status_received(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_sent().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_received".to_string(),
        })
    }

    /// Pending -> Done (REQUEST_OK written on the peer's stream).
    pub fn on_track_status_ok_sent(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_ok().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_ok_sent".to_string(),
        })
    }

    /// Pending -> Done (REQUEST_ERROR written on the peer's stream).
    pub fn on_track_status_error_sent(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_error().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_error_sent".to_string(),
        })
    }
}

#[cfg(test)]
mod responder_tests {
    use super::*;
    use crate::draft19::namespace::SubscribeNamespaceState;
    use crate::draft19::publish::PublishState;
    use crate::draft19::subscription::SubscriptionState;
    use moqtap_codec::kvp::KvpValue;

    fn active_client() -> Endpoint {
        let mut ep = Endpoint::new(Role::Client);
        ep.connect().unwrap();
        let _ = ep.send_setup(vec![]).unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();
        ep
    }

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    fn ns() -> TrackNamespace {
        TrackNamespace(vec![b"live".to_vec()])
    }

    fn peer_subscribe(id: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: v(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![],
        })
    }

    fn peer_publish(id: u64) -> ControlMessage {
        ControlMessage::Publish(Publish {
            request_id: v(id),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            track_alias: v(7),
            parameters: vec![],
            track_properties: vec![],
        })
    }

    fn request_ok() -> ControlMessage {
        ControlMessage::RequestOk(RequestOk { parameters: vec![], track_properties: vec![] })
    }

    fn publish_done() -> ControlMessage {
        ControlMessage::PublishDone(PublishDone {
            status_code: v(0),
            stream_count: v(0),
            reason_phrase: Vec::new(),
        })
    }

    /// The peer's requests and this endpoint's share one map per kind, and the
    /// opposite Request ID parity is what keeps them apart. Both directions
    /// are registered here and both are still there afterwards, which is the
    /// consequence a collision would destroy.
    #[test]
    fn a_peers_request_lives_beside_our_own_in_the_same_map() {
        let mut ep = active_client();
        let (ours, _) = ep.subscribe(ns(), b"video".to_vec(), vec![]).unwrap();
        assert_eq!(ours.into_inner(), 0, "a client allocates even Request IDs");

        let theirs = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        assert_eq!(theirs.into_inner(), 1);
        assert_eq!(
            ep.active_subscription_count(),
            2,
            "the peer's subscription displaced ours in the map",
        );
        assert_eq!(ep.peer_request_count(), 1);
    }

    /// Draft-19 Section 10.1: a Request ID whose least significant bit is
    /// wrong for the sender MUST close the session with INVALID_REQUEST_ID.
    /// The close is observable twice over — the endpoint stops accepting
    /// requests, and the code the connection layer will put on the wire is the
    /// one the section names.
    #[test]
    fn a_peer_id_with_our_own_parity_closes_the_session() {
        let mut ep = active_client();
        // 2 is even, so it is an id this client allocates, not one the server
        // may send.
        let err = ep.receive_request_on_stream(&peer_subscribe(2)).unwrap_err();
        assert_eq!(err.session_error_code(), Some(SessionErrorCode::InvalidRequestId));
        assert_eq!(err.to_string(), "request ID error: request ID 2 has wrong parity for Server");
        assert_eq!(ep.session_state(), SessionState::Closed);
        assert_eq!(ep.active_subscription_count(), 0, "a refused request was registered anyway");
        assert!(matches!(
            ep.receive_request_on_stream(&peer_subscribe(1)),
            Err(EndpointError::NotActive),
        ));
    }

    /// The other half of the same sentence: a duplicate Request ID is also
    /// INVALID_REQUEST_ID. The id is remembered even though the first request
    /// is still open, which is why the second is caught.
    #[test]
    fn a_repeated_peer_request_id_closes_the_session() {
        let mut ep = active_client();
        ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        let err = ep.receive_request_on_stream(&peer_publish(1)).unwrap_err();
        assert_eq!(err.session_error_code(), Some(SessionErrorCode::InvalidRequestId));
        assert_eq!(err.to_string(), "request 1 was already used by the peer");
        assert_eq!(ep.session_state(), SessionState::Closed);
        assert_eq!(ep.active_publish_count(), 0, "the duplicate was registered anyway");
    }

    /// Draft-19 Section 3.3 gives a different code for a different rule: a
    /// bidirectional stream that begins with the wrong message type is a
    /// PROTOCOL_VIOLATION, not an INVALID_REQUEST_ID.
    #[test]
    fn a_stream_that_opens_no_request_closes_the_session_with_protocol_violation() {
        let mut ep = active_client();
        let not_a_request =
            ControlMessage::GoAway(GoAway { new_session_uri: Vec::new(), timeout: v(0) });
        let err = ep.receive_request_on_stream(&not_a_request).unwrap_err();
        assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
        assert_eq!(err.to_string(), "GoAway does not begin a request stream");
        assert_eq!(ep.session_state(), SessionState::Closed);
    }

    /// A peer's SUBSCRIBE runs the same graph our own does, in the other
    /// direction: received, then answered, then ended with PUBLISH_DONE by
    /// this endpoint rather than by the peer.
    #[test]
    fn answering_a_peers_subscribe_walks_the_subscription_to_done() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();

        let ok = ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: v(7),
            parameters: vec![],
            track_properties: vec![],
        });
        ep.send_response_on_stream(id, &ok).unwrap();
        assert_eq!(ep.subscriptions[&1].state(), SubscriptionState::Active);

        ep.send_response_on_stream(id, &publish_done()).unwrap();
        assert_eq!(ep.subscriptions[&1].state(), SubscriptionState::Done);
    }

    /// The responder transitions are separate from the requester ones so a
    /// mis-dispatch names the responder event rather than succeeding quietly.
    #[test]
    fn a_responder_transition_out_of_order_names_the_responder_event() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        // PUBLISH_DONE before SUBSCRIBE_OK: the subscription is not Active.
        let err = ep.send_response_on_stream(id, &publish_done()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "subscription error: invalid transition from Subscribing on event on_publish_done_sent",
        );
    }

    /// Draft-18 folded PUBLISH_OK into REQUEST_OK and draft-19 keeps the fold,
    /// so a peer's PUBLISH is accepted with REQUEST_OK here where draft-17
    /// answers with a PUBLISH_OK of its own. The peer is then the publisher,
    /// so PUBLISH_DONE comes back from it on the same stream — the one
    /// direction the requester path never has to handle, because there we are
    /// the publisher.
    #[test]
    fn a_peers_publish_is_accepted_with_request_ok_and_ended_by_the_peer() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_publish(1)).unwrap();
        ep.send_response_on_stream(id, &request_ok()).unwrap();
        assert_eq!(ep.publishes[&1].state(), PublishState::Active);

        ep.receive_on_peer_request_stream(id, publish_done()).unwrap();
        assert_eq!(ep.publishes[&1].state(), PublishState::Done);
        assert!(
            ep.receive_on_peer_request_stream(id, publish_done()).is_err(),
            "a second PUBLISH_DONE was accepted on a publication already Done",
        );
    }

    /// This endpoint is the responder on a stream the peer opened, so a
    /// response arriving there is the peer answering itself. Routing it to the
    /// response dispatcher would look up a request we never made; refusing it
    /// is what the origin marker buys.
    #[test]
    fn a_response_on_a_peer_opened_stream_is_refused() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        let ok = ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: v(7),
            parameters: vec![],
            track_properties: vec![],
        });
        let err = ep.receive_on_peer_request_stream(id, ok).unwrap_err();
        assert_eq!(
            err.to_string(),
            "SubscribeOk may not follow a request on a stream the peer opened",
        );
    }

    /// A peer's REQUEST_UPDATE is held to the same rule the requester side is:
    /// draft-19 Section 10.9 puts it on its request's own stream, and the
    /// audited receive path already refuses one whose Request ID names a
    /// different request. Routing the peer's updates through that same handler
    /// is what keeps the two directions from disagreeing.
    #[test]
    fn a_peers_request_update_is_held_to_its_own_stream() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        let ok = ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: v(7),
            parameters: vec![],
            track_properties: vec![],
        });
        ep.send_response_on_stream(id, &ok).unwrap();

        let update = |named: u64| {
            ControlMessage::RequestUpdate(RequestUpdate {
                request_id: v(named),
                parameters: vec![],
            })
        };
        ep.receive_on_peer_request_stream(id, update(1)).unwrap();
        assert_eq!(ep.subscriptions[&1].state(), SubscriptionState::Active);

        // An update naming a different request than its stream is the
        // violation the section answers with a close.
        let err = ep.receive_on_peer_request_stream(id, update(3)).unwrap_err();
        assert!(matches!(err, EndpointError::UnexpectedRequestUpdate(3)), "{err}");
        assert_eq!(ep.session_state(), SessionState::Closed);
    }

    /// SUBSCRIBE_TRACKS (0x51) is the seventh request kind, added in draft-18
    /// and absent from draft-17. A responder that carried draft-17's six over
    /// would refuse it as a non-request and close the session, so the
    /// consequence checked is that it is registered and answerable.
    ///
    /// Section 10.19 keeps its overlap space independent of
    /// SUBSCRIBE_NAMESPACE's, which is why it lands in its own map.
    #[test]
    fn a_peers_subscribe_tracks_is_a_request_of_its_own() {
        let mut ep = active_client();
        let tracks = ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: v(1),
            namespace_prefix: ns(),
            parameters: vec![],
        });
        let id = ep.receive_request_on_stream(&tracks).unwrap();
        assert_eq!(ep.active_subscribe_tracks_count(), 1);
        assert_eq!(
            ep.active_subscribe_namespace_count(),
            0,
            "SUBSCRIBE_TRACKS landed among the namespace subscriptions",
        );
        ep.send_response_on_stream(id, &request_ok()).unwrap();
        assert_eq!(ep.subscribe_tracks[&1].state(), SubscribeNamespaceState::Active);

        // Section 10.20 puts PUBLISH_SKIPPED on this stream, and only on this
        // stream: a SUBSCRIBE_NAMESPACE has no such message.
        let skipped = ControlMessage::PublishSkipped(PublishSkipped {
            namespace_suffix: ns(),
            track_name: b"video".to_vec(),
        });
        ep.send_response_on_stream(id, &skipped).unwrap();

        let mut other = active_client();
        let sub_ns = other
            .receive_request_on_stream(&ControlMessage::SubscribeNamespace(SubscribeNamespace {
                request_id: v(1),
                namespace_prefix: ns(),
                parameters: vec![],
            }))
            .unwrap();
        other.send_response_on_stream(sub_ns, &request_ok()).unwrap();
        assert!(
            other.send_response_on_stream(sub_ns, &skipped).is_err(),
            "PUBLISH_SKIPPED was accepted on a SUBSCRIBE_NAMESPACE stream",
        );
    }

    /// Draft-19 Table 5 gives NAMESPACE and NAMESPACE_DONE the Stream value
    /// "Request", and Section 10.18 has the publisher send them only once the
    /// SUBSCRIBE_NAMESPACE has been accepted: "If the SUBSCRIBE_NAMESPACE is
    /// successful, the publisher will send matching NAMESPACE messages on the
    /// response stream."
    ///
    /// Draft-17 has neither edge — its message table has no Stream column — so
    /// this is the half of the responder a port from draft-17 would leave out.
    #[test]
    fn namespaces_are_announced_on_the_peers_subscribe_namespace_stream() {
        let mut ep = active_client();
        let id = ep
            .receive_request_on_stream(&ControlMessage::SubscribeNamespace(SubscribeNamespace {
                request_id: v(1),
                namespace_prefix: ns(),
                parameters: vec![],
            }))
            .unwrap();

        let namespace = ControlMessage::Namespace(message::Namespace { namespace_suffix: ns() });
        let err = ep.send_response_on_stream(id, &namespace).unwrap_err();
        assert_eq!(
            err.to_string(),
            "namespace error: invalid transition from Pending on event on_namespace_sent",
            "a NAMESPACE was allowed ahead of the REQUEST_OK that accepts the request",
        );

        ep.send_response_on_stream(id, &request_ok()).unwrap();
        ep.send_response_on_stream(id, &namespace).unwrap();
        ep.send_response_on_stream(
            id,
            &ControlMessage::NamespaceDone(message::NamespaceDone { namespace_suffix: ns() }),
        )
        .unwrap();
        // One namespace ending does not end the subscription to the prefix.
        assert_eq!(ep.subscribe_namespaces[&1].state(), SubscribeNamespaceState::Active);
    }

    /// Draft-19 Section 10.5 answers Track Properties on a REQUEST_OK that is
    /// not a TRACK_STATUS response with a session close. The receive path
    /// already refuses them; a responder that writes them would be handing a
    /// conforming peer that reason, so the send path refuses them too — and
    /// without closing this session, because nothing reached the wire.
    #[test]
    fn track_properties_are_refused_on_the_way_out_too() {
        let properties = vec![KeyValuePair { key: v(0x04), value: KvpValue::Varint(v(1000)) }];
        let with_properties = ControlMessage::RequestOk(RequestOk {
            parameters: vec![],
            track_properties: properties.clone(),
        });

        let mut ep = active_client();
        let id = ep
            .receive_request_on_stream(&ControlMessage::SubscribeNamespace(SubscribeNamespace {
                request_id: v(1),
                namespace_prefix: ns(),
                parameters: vec![],
            }))
            .unwrap();
        let err = ep.send_response_on_stream(id, &with_properties).unwrap_err();
        assert!(matches!(err, EndpointError::TrackPropertiesOnOutgoingRequestOk(1)), "{err}");
        assert_eq!(err.session_error_code(), None, "refusing our own write closed the session");
        assert_eq!(
            ep.subscribe_namespaces[&1].state(),
            SubscribeNamespaceState::Pending,
            "the refused response moved the state machine anyway",
        );
        // The request is still answerable without them.
        ep.send_response_on_stream(id, &request_ok()).unwrap();

        // TRACK_STATUS_OK is the shape that carries them.
        let mut ep = active_client();
        let id = ep
            .receive_request_on_stream(&ControlMessage::TrackStatus(message::TrackStatus {
                request_id: v(1),
                track_namespace: ns(),
                track_name: b"video".to_vec(),
                parameters: vec![],
            }))
            .unwrap();
        ep.send_response_on_stream(id, &with_properties).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moqtap_codec::kvp::KvpValue;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64_moqt(n)
    }

    fn ns(label: &str) -> TrackNamespace {
        TrackNamespace(vec![label.as_bytes().to_vec()])
    }

    fn peer_subscribe(id: u64, label: &str) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: v(id),
            track_namespace: ns(label),
            track_name: b"video".to_vec(),
            parameters: vec![],
        })
    }

    fn peer_fetch(id: u64, label: &str) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: v(id),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: ns(label),
                track_name: b"video".to_vec(),
                start_group: v(0),
                start_object: v(0),
                end_group: v(1),
                end_object: v(0),
            },
            parameters: vec![],
        })
    }

    fn peer_subscribe_namespace(id: u64, label: &str) -> ControlMessage {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: v(id),
            namespace_prefix: ns(label),
            parameters: vec![],
        })
    }

    fn peer_subscribe_tracks(id: u64, label: &str) -> ControlMessage {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: v(id),
            namespace_prefix: ns(label),
            parameters: vec![],
        })
    }

    fn peer_publish_namespace(id: u64, label: &str) -> ControlMessage {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: v(id),
            track_namespace: ns(label),
            parameters: vec![],
        })
    }

    fn peer_publish(id: u64, label: &str) -> ControlMessage {
        ControlMessage::Publish(Publish {
            request_id: v(id),
            track_namespace: ns(label),
            track_name: b"video".to_vec(),
            track_alias: v(id + 100),
            parameters: vec![],
            track_properties: vec![],
        })
    }

    fn active(role: Role) -> Endpoint {
        let mut ep = Endpoint::new(role);
        ep.connect().unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();
        assert_eq!(ep.session_state(), SessionState::Active);
        ep
    }

    fn update(id: u64) -> RequestUpdate {
        RequestUpdate { request_id: v(id), parameters: vec![] }
    }

    /// A session-fatal error must leave the endpoint unable to carry on: the
    /// state machine is Closed and every new request is refused. Asserting the
    /// error alone would let a caller ignore it and keep the session running,
    /// which is the behaviour draft-19 Section 10.9 forbids.
    fn assert_session_failed(ep: &mut Endpoint, err: EndpointError) {
        assert_eq!(
            err.session_error_code(),
            Some(SessionErrorCode::ProtocolViolation),
            "{err} should be fatal to the session"
        );
        assert_eq!(ep.session_state(), SessionState::Closed);
        assert!(matches!(
            ep.subscribe(ns("a"), b"b".to_vec(), vec![]),
            Err(EndpointError::NotActive)
        ));
    }

    /// The other answer, and the one this file gives to a rule draft-19
    /// states no consequence for: the message is refused and the session runs
    /// on.
    ///
    /// The three request-stream messages below take this helper rather than
    /// [`Self::assert_session_failed`]. Section 3.3's opener sentence does not
    /// reach a message arriving on the control stream — it is about what a
    /// bidirectional stream may *begin* with — and no sentence in draft-19
    /// closes a session over a message being in the wrong place. Table 5's
    /// Stream column says where each message is sent and attaches no
    /// consequence to a peer that sends one elsewhere.
    ///
    /// REQUEST_UPDATE is the one exception and takes the helper above: Section
    /// 10.9 names two cases and closes over everything else, so a
    /// REQUEST_UPDATE on the control stream really is a close the draft asks
    /// for.
    ///
    /// Recovery is not an aspiration here. A control message carries its own
    /// length, so the next boundary on the stream is known however this one
    /// was refused, and the endpoint that follows really can carry on — which
    /// is what the third assertion checks rather than assumes.
    fn assert_refused_without_closing(ep: &mut Endpoint, err: &EndpointError) {
        assert_eq!(
            err.session_error_code(),
            None,
            "no sentence in draft-19 answers {err} with a close"
        );
        assert_eq!(ep.session_state(), SessionState::Active);
        ep.subscribe(ns("a"), b"b".to_vec(), vec![])
            .expect("the session survives a message it could not place");
    }

    /// Draft-19 Table 5 gives REQUEST_UPDATE the Stream value "Request", and
    /// Section 10.9 has it sent "on the same bidi stream as the request".
    ///
    /// Before the placement was corrected the control stream accepted it and
    /// the request stream refused it. Routing the request-stream case back
    /// through the catch-all arm produces, at the first call below:
    ///
    /// ```text
    /// called `Result::unwrap()` on an `Err` value: ResponseOnControlStream
    /// ```
    ///
    /// and leaving the control-stream arm in place produces, at the assertion
    /// after it:
    ///
    /// ```text
    /// assertion failed: matches!(err, EndpointError::RequestUpdateOnControlStream)
    /// ```
    #[test]
    fn a_request_update_belongs_on_its_request_stream_and_not_the_control_stream() {
        let mut ep = active(Role::Client);
        // A PUBLISH this endpoint made and the peer accepted. Section 10.9
        // allows an update on exactly that among the requests made here, so
        // this drives the routing question without also being a violation.
        let (id, _) = ep.publish(ns("live"), b"video".to_vec(), v(7), vec![], vec![]).unwrap();
        ep.receive_request_ok(id, &RequestOk { parameters: vec![], track_properties: vec![] })
            .unwrap();

        // The request stream is where it belongs, and the request-stream
        // dispatcher is the route that has to accept it.
        ep.receive_response_on_stream(id, ControlMessage::RequestUpdate(update(id.into_inner())))
            .unwrap();

        // The control stream is not, and the draft answers that with a close.
        let err =
            ep.receive_message(ControlMessage::RequestUpdate(update(id.into_inner()))).unwrap_err();
        assert!(matches!(err, EndpointError::RequestUpdateOnControlStream), "{err}");
        assert_session_failed(&mut ep, err);
    }

    /// The three messages draft-19 Table 5 places on a request stream that are
    /// not responses: NAMESPACE (0x8), NAMESPACE_DONE (0xE) and PUBLISH_SKIPPED
    /// (0xF).
    ///
    /// Table 5's Stream column reads "Request" for all three, the same value it
    /// gives REQUEST_UPDATE. Only SETUP is "Control" on its own; GOAWAY is
    /// "Control, Request". The placement had all three exactly inverted — the
    /// control stream accepted them and returned `Ok`, and the request stream
    /// fell through to the catch-all and refused them — so a conforming peer
    /// sending NAMESPACE on the SUBSCRIBE_NAMESPACE stream that asked for it
    /// had its announcement dropped.
    ///
    /// Restoring the control-stream arms (`Namespace(ref m) =>
    /// self.receive_namespace(m)` and its two siblings) fails this test at the
    /// second half with:
    ///
    /// ```text
    /// NAMESPACE must be refused on the control stream: Ok(())
    /// ```
    ///
    /// and removing the request-stream arms fails it at the first half with:
    ///
    /// ```text
    /// NAMESPACE belongs on a request stream: ResponseOnControlStream
    /// ```
    #[test]
    fn namespace_and_publish_skipped_belong_on_a_request_stream() {
        /// A message name paired with a way to build a fresh one, since each
        /// case needs two copies and `ControlMessage` is consumed by both
        /// dispatchers.
        type Case = (&'static str, fn() -> ControlMessage);

        let cases: [Case; 3] = [
            ("NAMESPACE", || {
                ControlMessage::Namespace(message::Namespace { namespace_suffix: ns("live") })
            }),
            ("NAMESPACE_DONE", || {
                ControlMessage::NamespaceDone(message::NamespaceDone {
                    namespace_suffix: ns("live"),
                })
            }),
            ("PUBLISH_SKIPPED", || {
                ControlMessage::PublishSkipped(PublishSkipped {
                    namespace_suffix: ns("live"),
                    track_name: b"video".to_vec(),
                })
            }),
        ];

        for (name, build) in cases {
            let mut ep = active(Role::Client);
            let id = ep.subscribe_namespace(ns("live"), vec![]).unwrap().0;

            // Sections 10.18 and 10.19 make REQUEST_OK or REQUEST_ERROR the
            // first message on this stream, so the answer comes before the
            // messages that follow it. Sending the NAMESPACE first is a
            // different rule's violation and would answer this test's question
            // with that rule's error.
            ep.receive_response_on_stream(
                id,
                ControlMessage::RequestOk(RequestOk {
                    parameters: vec![],
                    track_properties: vec![],
                }),
            )
            .expect("REQUEST_OK answers the namespace subscription");

            // Where Table 5 puts it.
            ep.receive_response_on_stream(id, build())
                .unwrap_or_else(|e| panic!("{name} belongs on a request stream: {e:?}"));

            // Where it does not. Refused, and the session left running.
            let err = match ep.receive_message(build()) {
                Err(e) => e,
                Ok(()) => panic!("{name} must be refused on the control stream: Ok(())"),
            };
            assert!(
                matches!(err, EndpointError::RequestMessageOnControlStream(m) if m == name),
                "{name} on the control stream gave {err}"
            );
            assert_refused_without_closing(&mut ep, &err);
        }
    }

    /// Draft-19 Section 10.9: "An endpoint that receives a REQUEST_UPDATE
    /// other than in the two cases above MUST close the session with a
    /// PROTOCOL_VIOLATION." Section 10.14 names TRACK_STATUS as one such case:
    /// "the subscriber cannot send REQUEST_UPDATE."
    ///
    /// A handler that consulted only `subscriptions`, answering both of these
    /// with a recoverable per-request error that leaves the session running,
    /// gives at the first assertion below:
    ///
    /// ```text
    /// unknown request ID: 40
    /// ```
    #[test]
    fn a_request_update_naming_a_non_updatable_request_closes_the_session() {
        // An id nothing was ever issued under.
        let mut ep = active(Role::Client);
        let err = ep.receive_request_update(v(40), &update(40)).unwrap_err();
        assert!(matches!(err, EndpointError::UnexpectedRequestUpdate(40)), "{err}");
        assert_session_failed(&mut ep, err);

        // TRACK_STATUS, which the draft rules out by name.
        let mut ep = active(Role::Client);
        let (id, _) = ep.track_status(ns("live"), b"video".to_vec(), vec![]).unwrap();
        let err = ep.receive_request_update(id, &update(id.into_inner())).unwrap_err();
        assert!(matches!(err, EndpointError::UnexpectedRequestUpdate(_)), "{err}");
        assert_session_failed(&mut ep, err);
    }

    /// Draft-19 Section 10.9's first case reaches every request kind: "The
    /// sender of a request (SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
    /// SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) can later send a REQUEST_UPDATE
    /// on the same bidi stream as the request to modify it."
    ///
    /// # What it catches
    ///
    /// Removing the five-map lookup, so that only a SUBSCRIBE resolves:
    ///
    /// ```text
    /// request 3 should be updatable: REQUEST_UPDATE for request 3, which is
    /// not an updatable outstanding request
    /// ```
    ///
    /// That cut is not evidence for this gate on its own. It reddens
    /// twenty-eight tests across the crate, because every update on a fetch or
    /// a namespace request comes through the same lookup — which makes it a
    /// poor ablation and a fair measure of how much rests on the line.
    #[test]
    fn an_update_from_the_requester_resolves_against_every_request_kind() {
        let mut ep = active(Role::Client);
        let mut ids = Vec::new();
        for msg in [
            peer_subscribe(1, "a"),
            peer_fetch(3, "b"),
            peer_subscribe_namespace(5, "c"),
            peer_subscribe_tracks(7, "d"),
            peer_publish_namespace(9, "e"),
            peer_publish(11, "f"),
        ] {
            ids.push(ep.receive_request_on_stream(&msg).unwrap());
        }
        for id in ids {
            ep.receive_request_update(id, &update(id.into_inner()))
                .unwrap_or_else(|e| panic!("request {} should be updatable: {e}", id.into_inner()));
        }
        assert_eq!(ep.session_state(), SessionState::Active);
    }

    /// Section 10.9's second case: "A subscriber can also send REQUEST_UPDATE
    /// to modify parameters of a subscription established with PUBLISH."
    ///
    /// The publication is this endpoint's, so this is the one request of its
    /// own that it may be sent an update on, and the one place the sender rule
    /// and the request-kind rule disagree.
    #[test]
    fn an_update_on_a_publish_this_endpoint_made_is_the_second_case() {
        let mut ep = active(Role::Client);
        let (id, _) = ep.publish(ns("live"), b"video".to_vec(), v(7), vec![], vec![]).unwrap();
        ep.receive_request_ok(id, &RequestOk { parameters: vec![], track_properties: vec![] })
            .unwrap();
        ep.receive_request_update(id, &update(id.into_inner())).unwrap();
        assert_eq!(ep.session_state(), SessionState::Active);
    }

    /// The second case needs the subscription to exist before it can be
    /// updated, and the first case does not.
    ///
    /// Section 5.1: "Once either of these sequences is successful, the
    /// subscription moves to the Established state and can be updated by the
    /// subscriber using REQUEST_UPDATE." A PUBLISH this endpoint has sent and
    /// the peer has not answered is Pending, so a subscriber updating it is
    /// updating a subscription that does not exist yet.
    ///
    /// The first case rests on something else and keeps its own timing:
    /// Section 10.9 lets the sender of a request update it "later" with
    /// nothing said about the answer, and five of the six kinds it names are
    /// not subscriptions at all. Both halves are here so that the asymmetry is
    /// the thing asserted rather than a side effect of one of them.
    ///
    /// # What it catches
    ///
    /// Asking only whether the request exists, which is all the map on its own
    /// can answer: it holds a PUBLISH from the moment it is sent, and the
    /// peer's answer is what makes it a subscription.
    ///
    /// ```text
    /// a PUBLISH still waiting for its answer is not an established one: ()
    /// ```
    ///
    /// It reddens this gate and nothing else in the client or the proxy, and
    /// the gate's second half stays green under it — which is what that
    /// half is for. A cut that tightened both cases would redden it too.
    #[test]
    fn only_an_established_publication_may_be_updated_by_its_subscriber() {
        // Case two, before the answer: the subscription is not established.
        let mut ep = active(Role::Client);
        let (id, _) = ep.publish(ns("live"), b"video".to_vec(), v(7), vec![], vec![]).unwrap();
        let err = ep
            .receive_request_update(id, &update(id.into_inner()))
            .expect_err("a PUBLISH still waiting for its answer is not an established one");
        assert!(matches!(err, EndpointError::UnexpectedRequestUpdate(_)), "{err}");
        assert_session_failed(&mut ep, err);

        // Case one, before the answer: allowed, and on the same beat.
        let mut ep = active(Role::Client);
        let peer = ep.receive_request_on_stream(&peer_subscribe(1, "live")).unwrap();
        ep.receive_request_update(peer, &update(peer.into_inner()))
            .expect("the sender of a request may update it before it is answered");
        assert_eq!(ep.session_state(), SessionState::Active);
    }

    /// Section 10.9: "An endpoint that receives a REQUEST_UPDATE other than in
    /// the two cases above MUST close the session with a PROTOCOL_VIOLATION."
    ///
    /// Neither case reaches a SUBSCRIBE, FETCH or namespace request this
    /// endpoint made. Those are modified by the endpoint that made them, which
    /// is this one, and an update arriving on one came from the side that has
    /// no say over it.
    ///
    /// # What it catches
    ///
    /// Reading the Request ID's map and not the direction the update came
    /// from, which is what this draft did: all five request kinds this
    /// endpoint can make were updatable by whoever asked.
    ///
    /// ```text
    /// an update on a request this endpoint made is neither case: ()
    /// ```
    ///
    /// It reddens this gate and nothing else in the client or the proxy. The
    /// `()` is the `Ok` the call returned, which is the whole defect: the
    /// update was applied and the session carried on.
    #[test]
    fn an_update_on_a_request_this_endpoint_made_closes_the_session() {
        for which in 0..5 {
            let mut ep = active(Role::Client);
            let (id, _) = match which {
                0 => ep.subscribe(ns("live"), b"video".to_vec(), vec![]).unwrap(),
                1 => {
                    ep.fetch(ns("live"), b"video".to_vec(), v(0), v(0), v(1), v(0), vec![]).unwrap()
                }
                2 => ep.subscribe_namespace(ns("live"), vec![]).unwrap(),
                3 => ep.subscribe_tracks(ns("live"), vec![]).unwrap(),
                _ => ep.publish_namespace(ns("live"), vec![]).unwrap(),
            };
            let err = ep
                .receive_request_update(id, &update(id.into_inner()))
                .expect_err("an update on a request this endpoint made is neither case");
            assert!(matches!(err, EndpointError::UnexpectedRequestUpdate(_)), "{which}: {err}");
            assert_session_failed(&mut ep, err);
        }
    }

    /// A REQUEST_UPDATE whose own Request ID names a different request than
    /// the stream it arrived on was sent on a stream that is not its
    /// request's, which is the same violation.
    #[test]
    fn a_request_update_whose_id_disagrees_with_its_stream_closes_the_session() {
        let mut ep = active(Role::Client);
        let (a, _) = ep.subscribe(ns("live"), b"video".to_vec(), vec![]).unwrap();
        let (b, _) = ep.subscribe(ns("live"), b"audio".to_vec(), vec![]).unwrap();
        let err = ep.receive_request_update(a, &update(b.into_inner())).unwrap_err();
        assert!(matches!(err, EndpointError::UnexpectedRequestUpdate(_)), "{err}");
        assert_session_failed(&mut ep, err);
    }

    /// Draft-19 Section 10.5: Track Properties "are populated in
    /// TRACK_STATUS_OK; they are empty in PUBLISH_OK, REQUEST_UPDATE_OK,
    /// SUBSCRIBE_NAMESPACE_OK and PUBLISH_NAMESPACE_OK. If an endpoint
    /// receives Track Properties in one of these messages it MUST close the
    /// session with a PROTOCOL_VIOLATION."
    ///
    /// Binding the message as `_msg` in `receive_request_ok`, so its Track
    /// Properties go unread, gives:
    ///
    /// ```text
    /// called `Result::unwrap_err()` on an `Ok` value: ()
    /// ```
    #[test]
    fn track_properties_on_a_request_ok_that_is_not_a_track_status_close_the_session() {
        let properties = vec![KeyValuePair { key: v(0x04), value: KvpValue::Varint(v(1000)) }];

        let mut ep = active(Role::Client);
        let (id, _) = ep.subscribe_namespace(ns("live"), vec![]).unwrap();
        let err = ep
            .receive_request_ok(
                id,
                &RequestOk { parameters: vec![], track_properties: properties.clone() },
            )
            .unwrap_err();
        assert!(matches!(err, EndpointError::TrackPropertiesOnNonTrackStatus(_)), "{err}");
        assert_session_failed(&mut ep, err);

        // TRACK_STATUS_OK is the shape that carries them, and still does.
        let mut ep = active(Role::Client);
        let (id, _) = ep.track_status(ns("live"), b"video".to_vec(), vec![]).unwrap();
        ep.receive_request_ok(id, &RequestOk { parameters: vec![], track_properties: properties })
            .unwrap();
        assert_eq!(ep.session_state(), SessionState::Active);
    }

    /// Draft-19 Section 10.4: "A GOAWAY MAY also be sent on a request stream
    /// to initiate migration of that individual request." Table 5 gives GOAWAY
    /// the Stream value "Control, Request".
    ///
    /// Without the `GoAway` arm in `receive_response_on_stream` the message
    /// falls through to the catch-all:
    ///
    /// ```text
    /// called `Result::unwrap()` on an `Err` value: ResponseOnControlStream
    /// ```
    ///
    /// The session must survive it — only the one request is being moved.
    #[test]
    fn a_goaway_on_a_request_stream_migrates_that_request_and_not_the_session() {
        let mut ep = active(Role::Client);
        let (id, _) = ep.subscribe(ns("live"), b"video".to_vec(), vec![]).unwrap();

        let goaway =
            GoAway { new_session_uri: b"https://elsewhere.example/moq".to_vec(), timeout: v(0) };
        ep.receive_response_on_stream(id, ControlMessage::GoAway(goaway)).unwrap();

        assert_eq!(ep.session_state(), SessionState::Active);
        // Per-request migration leaves the session-wide URI unset; the control
        // stream is what sets that.
        assert_eq!(ep.goaway_uri(), None);
        // And a new request is still allowed.
        ep.subscribe(ns("live"), b"audio".to_vec(), vec![]).unwrap();
    }

    /// Draft-19 Section 10.4: "If a server receives a GOAWAY with a non-zero
    /// New Session URI Length it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// Without the role check the URI is stored and a server-role endpoint
    /// will follow a redirect it should have refused:
    ///
    /// ```text
    /// called `Result::unwrap_err()` on an `Ok` value: ()
    /// ```
    #[test]
    fn a_server_refuses_a_goaway_carrying_a_new_session_uri() {
        let mut ep = active(Role::Server);
        let goaway =
            GoAway { new_session_uri: b"https://elsewhere.example/moq".to_vec(), timeout: v(0) };
        let err = ep.receive_goaway(&goaway).unwrap_err();
        assert!(matches!(err, EndpointError::GoAwayUriAtServer), "{err}");
        assert_eq!(ep.goaway_uri(), None);
        assert_session_failed(&mut ep, err);

        // An empty URI is the form a server may legitimately receive: it says
        // the peer is going away, not where to go.
        let mut ep = active(Role::Server);
        ep.receive_goaway(&GoAway { new_session_uri: vec![], timeout: v(0) }).unwrap();
        assert_eq!(ep.session_state(), SessionState::Draining);

        // A client is the side that may be redirected.
        let mut ep = active(Role::Client);
        ep.receive_goaway(&goaway).unwrap();
        assert_eq!(ep.goaway_uri(), Some(&b"https://elsewhere.example/moq"[..]));
    }

    /// Draft-19 Section 10.12, Table 6: Fetch Type 0x2 is a Relative Joining
    /// Fetch and 0x3 an Absolute Joining Fetch. The client could only build
    /// the relative form, so an application that knew the group it wanted had
    /// to express it as an offset from a Largest Group it may not know.
    #[test]
    fn both_joining_fetch_types_can_be_built() {
        let mut ep = active(Role::Client);
        let (_, relative) = ep.joining_fetch(v(0), v(2), Vec::new()).unwrap();
        let (_, absolute) = ep.absolute_joining_fetch(v(0), v(9), Vec::new()).unwrap();

        let types: Vec<FetchType> = [relative, absolute]
            .iter()
            .map(|m| match m {
                ControlMessage::Fetch(f) => f.fetch_type,
                other => panic!("expected a FETCH, got {other:?}"),
            })
            .collect();
        assert_eq!(types, vec![FetchType::RelativeJoining, FetchType::AbsoluteJoining]);

        // Both are tracked as fetches, so their responses resolve.
        assert_eq!(ep.active_fetch_count(), 2);
    }
}

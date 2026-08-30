use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::draft12::fetch::{FetchError, FetchState, FetchStateMachine};
use crate::draft12::namespace::{
    AnnounceState, AnnounceStateMachine, NamespaceError, SubscribeAnnouncesState,
    SubscribeAnnouncesStateMachine,
};
use crate::draft12::publish::{
    PublishError as PublishFlowError, PublishState, PublishStateMachine,
};
use crate::draft12::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft12::session::setup::{self, SetupError};
use crate::draft12::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft12::subscription::{
    SubscriptionError, SubscriptionState, SubscriptionStateMachine,
};
use crate::draft12::track_status::{TrackStatusError, TrackStatusState, TrackStatusStateMachine};
use crate::forwarding_preference::{ObjectForwardingPreference, TrackForwardingPreferences};
use crate::malformed_tracks::{MalformedTrackCondition, MalformedTracks};
use crate::track_locations::{
    EndOfTrackPlacement, ObjectLocation, ObjectRole, TrackFault, TrackLocations, TrackObjects,
};
use moqtap_codec::draft12::error_codes::{
    FetchErrorCode, SessionErrorCode, SubscribeAnnouncesErrorCode,
};
use moqtap_codec::draft12::message::{
    self, Announce, AnnounceCancel, AnnounceError, AnnounceOk, ClientSetup, ControlMessage, Fetch,
    FetchCancel, FetchPayload, FetchType, GoAway, MaxRequestId, Publish, PublishError, PublishOk,
    RequestsBlocked, ServerSetup, Subscribe, SubscribeAnnounces, SubscribeAnnouncesError,
    SubscribeAnnouncesOk, SubscribeDone, SubscribeError, SubscribeOk, SubscribeUpdate, TrackStatus,
    TrackStatusRequest, Unannounce, Unsubscribe, UnsubscribeAnnounces,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Key identifying a namespace (used for Announce maps).
type NamespaceKey = Vec<Vec<u8>>;

/// Errors that can occur during draft-12 endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A GOAWAY carrying a New Session URI arrived at a server.
    ///
    /// Section 8.4: "If a server receives a GOAWAY with a non-zero New
    /// Session URI Length it MUST terminate the session with a Protocol
    /// Violation." Migration is something a server offers a client, never the
    /// other way round.
    #[error("GOAWAY carrying a New Session URI received at a server")]
    GoAwayUriAtServer,
    /// A session-level state machine error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    /// A request ID allocation or validation error.
    #[error("request ID error: {0}")]
    RequestId(#[from] RequestIdError),
    /// A subscription state machine error.
    #[error("subscription error: {0}")]
    Subscription(#[from] SubscriptionError),
    /// A fetch state machine error.
    #[error("fetch error: {0}")]
    Fetch(#[from] FetchError),
    /// A namespace state machine error.
    #[error("namespace error: {0}")]
    Namespace(#[from] NamespaceError),
    /// A track status state machine error.
    #[error("track status error: {0}")]
    TrackStatus(#[from] TrackStatusError),
    /// A publish flow state machine error.
    #[error("publish flow error: {0}")]
    PublishFlow(#[from] PublishFlowError),
    /// A setup negotiation error.
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),
    /// The request ID does not match any known state machine.
    #[error("unknown request ID: {0}")]
    UnknownRequest(u64),
    /// The track namespace does not match any known state machine.
    #[error("unknown namespace")]
    UnknownNamespace,
    /// The session is not in the Active state.
    #[error("session not active")]
    NotActive,
    /// The session is draining and cannot accept new requests.
    #[error("session is draining, no new requests allowed")]
    Draining,
    /// A filter that names a start location was asked for through a helper
    /// that has no start location to give it.
    #[error("this filter type needs a start location; use the range form of this call")]
    FilterNeedsRange,
    /// A second GOAWAY arrived on the control stream.
    ///
    /// The GOAWAY that says the peer is going away is one message, and the
    /// draft answers a repeat of it with a session close rather than with an
    /// error about the second message: there is no state a second one could
    /// move that the first has not already moved.
    #[error("a second GOAWAY arrived on the control stream")]
    RepeatedGoAway,
    /// The peer named a Track Alias it is already using for another track.
    ///
    /// Draft-12 states it twice, once per message. Section 8.8: "The same
    /// Track Alias MUST NOT be used to refer to two different Tracks
    /// simultaneously. If a subscriber receives a SUBSCRIBE_OK that uses the
    /// same Track Alias as a different track with an active subscription, it
    /// MUST close the session with error 'Duplicate Track Alias'." Section 8.13 is the same
    /// sentence with PUBLISH in place of SUBSCRIBE_OK.
    ///
    /// The session is over: this endpoint's own state has moved to Closed and
    /// the code the transport should close with is in
    /// [`EndpointError::session_error_code`].
    #[error("track alias {alias} already names request {established}'s track; request {offered} names a different one")]
    DuplicateTrackAlias {
        /// The alias both tracks are named by.
        alias: u64,
        /// The request whose live subscription holds the alias.
        established: u64,
        /// The request whose message arrived naming it for another track.
        offered: u64,
    },
    /// This endpoint was asked to hand out a Track Alias that a live track of
    /// its own already holds.
    ///
    /// Section 8.8 states the rule as a prohibition before it states what the
    /// receiver does about one: "The same Track Alias MUST NOT be used to
    /// refer to two different Tracks simultaneously."
    ///
    /// The message is refused instead of built, and nothing else moves: the
    /// subscription the peer opened is still waiting for an answer, and the
    /// session stays as it was. The alias never reaches the peer, so there is
    /// nothing for the peer to close over.
    #[error("track alias {alias} already names request {held}'s track")]
    TrackAliasInUse {
        /// The alias that is already spoken for.
        alias: u64,
        /// The request whose live flow holds it.
        held: u64,
    },
    /// A track's objects were framed two different ways.
    ///
    /// Section 9: "Every Track has a single 'Object Forwarding Preference' and
    /// the Original Publisher MUST NOT mix different forwarding preferences
    /// within a single track (see Section 2.5)."
    ///
    /// The framing is the preference: an object on a subgroup stream has the
    /// Subgroup preference and an object in a datagram has the Datagram one,
    /// so the track's first object settles the property and this is every
    /// later object measured against it.
    ///
    /// # Why this one ends no session
    ///
    /// Drafts 07 through 11 finish that paragraph with a close and a code.
    /// This draft replaces the sentence with the cross-reference above, and
    /// what it points at is a different answer rather than the same one worded
    /// differently. Section 2.5 lists "An Object is received with a different
    /// Forwarding Preference than previously observed from the same Track"
    /// among the conditions that make a track malformed, and says of all of
    /// them: "When a subscriber detects a Malformed Track, it MUST UNSUBSCRIBE
    /// from the Track and SHOULD deliver an error to the application".
    ///
    /// So this error carries no code in [`EndpointError::session_error_code`],
    /// and the connection's `close_for_data_stream` declines it. Ending the
    /// session over it would be this crate inventing a consequence the draft
    /// withdrew.
    ///
    /// This is half of that answer and not all of it. "SHOULD deliver an error
    /// to the application" is what this error is. The unsubscribe the same
    /// sentence requires is not done: those are control messages, and a data
    /// path holding `&self` has no way to send one. It is also one condition
    /// of eight in that section rather than a rule of its own, so the answer
    /// belongs to the family and not to this arm. A caller that wants it has
    /// the error to act on.
    #[error(
        "track alias {alias} carries objects framed as {established}, and one is \
         framed as {offered}"
    )]
    MixedForwardingPreference {
        /// The Track Alias the offending object named.
        alias: u64,
        /// The framing the track's earlier objects settled on.
        established: ObjectForwardingPreference,
        /// The framing the offending object used.
        offered: ObjectForwardingPreference,
    },
    /// An object saying the track ended somewhere the track has already passed.
    ///
    /// Section 9.2.1.1 describes Object Status 0x4, end of Track, as one whose
    /// "GroupID is either the largest group produced in this track and the
    /// ObjectID is one greater than the largest object produced in that
    /// group, or GroupID is one greater than the largest group produced in
    /// this track and the ObjectID is zero", and states the consequence:
    /// "An object with this status that has a Group ID less than any other
    /// GroupID, or an ObjectID less than or equal to the largest in the
    /// specified group, is a protocol error, and the receiver MUST terminate
    /// the session."
    ///
    /// # What this draft merged
    ///
    /// Drafts 08 through 10 spell this against a status that means end of
    /// Track *and Group*, and carry a second status beside it for the end of
    /// the Track alone. This draft folded the two into 0x4 and kept the
    /// looser of the two conditions, which is why the Group ID may equal the
    /// largest group here and may not there.
    #[error(
        "the end-of-track object at group {group}, object {object} on track alias \
         {alias} is out of place: {placement}"
    )]
    EndOfTrackOutOfPlace {
        /// The Track Alias the offending object named.
        alias: u64,
        /// The Group ID it named.
        group: u64,
        /// The Object ID it named.
        object: u64,
        /// Which half of the condition it broke, and what it was measured
        /// against.
        placement: EndOfTrackPlacement,
    },
    /// An object arriving after the track's final object.
    ///
    /// Section 2.5 lists the condition: "An Object is received on a Track whose
    /// Group and Object ID are larger than the final Object in the Track. The
    /// final Object in a Track is the Object with Status END_OF_TRACK or the
    /// last Object sent in a FETCH whose response indicated End of Track."
    ///
    /// **Larger is Section 1.3.1's comparison and not a reading of the words.**
    /// That section puts one Location below another when "A.Group < B.Group ||
    /// (A.Group == B.Group && A.Object < B.Object)", so an Object in a later
    /// group is past the end whatever its own Object ID is.
    ///
    /// **A Malformed Track and not a session error**, which is the whole
    /// difference between this arm and the one above it. They are the same
    /// record's two answers about the same pair of numbers: that one asks
    /// whether an end-of-track object is behind what the track has carried and
    /// ends the session, this one asks whether an ordinary object is past where
    /// the track ended and gives up one track.
    ///
    /// This is the error half of the answer Section 2.5 states once for its
    /// whole list — "it MUST UNSUBSCRIBE from the Track and SHOULD deliver an
    /// error to the application". The UNSUBSCRIBE is the connection's, for the
    /// reason the mixed-framing arm gives.
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
    /// SUBSCRIBE_UPDATE named a Request ID this session has never carried a
    /// request under.
    ///
    /// Section 8.10: "A publisher MUST terminate the session with a 'Protocol
    /// Violation' if the SUBSCRIBE_UPDATE violates these rules or if the
    /// subscriber specifies a request ID that has not existed within the
    /// Session."
    ///
    /// A request that has **ended** is not this: it existed. That is why the
    /// record of an inbound SUBSCRIBE outlives the subscription, and why an
    /// update naming an ended one is refused by the flow rather than by the
    /// session.
    #[error("SUBSCRIBE_UPDATE names request {0}, which this session has never carried")]
    UpdateForUnknownRequest(u64),

    /// A Joining Fetch named a subscription this session cannot join.
    ///
    /// Section 8.16: "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to an existing Subscribe in the same session, it
    /// MUST respond with a Fetch Error with code Invalid Joining Request ID."
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
    /// A message about an announcement named a namespace the peer has not
    /// announced.
    ///
    /// Section 8.26 says what a cancellation is for: the subscriber "will stop
    /// sending new subscriptions for tracks within the provided Track
    /// Namespace". What a withdrawal ends and a cancellation revokes is an
    /// announcement the **peer** made, so the record they reach for is the one
    /// this endpoint keeps of the peer's announcements.
    ///
    /// Separate from [`EndpointError::UnknownNamespace`], which is the same
    /// miss on the announcements this endpoint made, so a caller can tell which
    /// of the two maps came up empty.
    #[error("the peer has made no live announcement for this namespace")]
    UnknownPeerNamespace,
    /// A message about a namespace subscription named a prefix the peer has
    /// not subscribed to.
    ///
    /// Section 5.1: "An UNSUBSCRIBE_ANNOUNCES withdraws a previous SUBSCRIBE_ANNOUNCES."
    ///
    /// What a withdrawal ends is a namespace subscription the **peer** made,
    /// so the record it reaches for is the one this endpoint keeps of the
    /// peer's. A namespace subscription this endpoint made is withdrawn by
    /// [`Endpoint::unsubscribe_announces`], which is the same message travelling the other
    /// way and answers with [`EndpointError::UnknownNamespace`].
    #[error("the peer has made no live namespace subscription for this prefix")]
    UnknownPeerNamespaceSubscription,
    /// The peer subscribed to a namespace prefix overlapping one it is
    /// already subscribed to.
    ///
    /// Section 8.27: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session. Within a session, if a publisher
    /// receives a SUBSCRIBE_ANNOUNCES with a Track Namespace Prefix that is a
    /// prefix of, suffix of, or equal to an active SUBSCRIBE_ANNOUNCES, it
    /// MUST respond with SUBSCRIBE_ANNOUNCES_ERROR, with error code Namespace
    /// Prefix Overlap."
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
    /// This endpoint was asked to subscribe to a namespace prefix overlapping
    /// one it is already subscribed to.
    ///
    /// The first half of the same sentence, which is addressed to the
    /// subscriber: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session."
    ///
    /// The message is refused instead of built, and nothing else moves: no
    /// Request ID is spent, no state machine is created and the session stays
    /// as it was. The request never reaches the peer, so there is nothing for
    /// the peer to refuse.
    #[error("the namespace prefix overlaps request {established}, which this endpoint made")]
    OwnPrefixOverlap {
        /// The namespace subscription this endpoint already has.
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
/// Section 8.27: "A subscriber cannot make overlapping namespace
/// subscriptions on a single session. Within a session, if a publisher
/// receives a SUBSCRIBE_ANNOUNCES with a Track Namespace Prefix that is a
/// prefix of, suffix of, or equal to an active SUBSCRIBE_ANNOUNCES, it MUST
/// respond with SUBSCRIBE_ANNOUNCES_ERROR, with error code Namespace Prefix
/// Overlap."
///
/// A namespace matches a namespace subscription when the subscription's
/// prefix is a prefix of it, so two prefixes select overlapping sets of
/// namespaces exactly when one of them is a prefix of the other. Equal
/// prefixes are that case as well, and this draft names them.
///
/// "Suffix of" is read as the "or vice versa" drafts 07 through 11 write in
/// the same place. Which suffix a prefix ends with decides nothing about the
/// namespaces it matches, so read at its word the term would forbid pairs
/// that overlap in nothing and permit pairs that overlap entirely.
fn prefixes_overlap(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    let shared = a.len().min(b.len());
    a[..shared] == b[..shared]
}

impl EndpointError {
    /// The code to close the session with, when draft-12 answers this error
    /// with a close rather than leaving it to the one request it concerns.
    ///
    /// `None` means the error is recoverable: the caller may report it, give
    /// up on the request it concerns, and keep the session running. `Some`
    /// means the draft ends the session, and the endpoint has already moved
    /// its own state to Closed - the code is what the transport should carry.
    ///
    /// The table grows one rule at a time, and a rule joins it with a gate
    /// that drives the bytes at a real connection and reads the close code
    /// back off the wire. An arm added without one asserts nothing: from
    /// inside the process the session ends either way, and only the peer can
    /// tell the difference.
    pub fn session_error_code(&self) -> Option<SessionErrorCode> {
        match self {
            // Section 8.5 answers a ceiling that does not increase with a
            // close, and names this code for it.
            EndpointError::RequestId(RequestIdError::Decreased(..)) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // The same section answers a Request ID that reaches the ceiling
            // this endpoint advertised, and names a different code for it.
            EndpointError::RequestId(RequestIdError::ExceedsMax(..)) => {
                Some(SessionErrorCode::TooManyRequests)
            }
            // Section 8.1 answers a Request ID that is not the peer's to
            // spend with a close, and names Invalid Request ID for it. Both
            // halves of that sentence arrive here: "not valid for the peer"
            // is an ID out of this endpoint's own half of the space, and "not
            // expected" is a new request carrying an ID other than the next
            // one the peer's sequence calls for.
            EndpointError::RequestId(
                RequestIdError::WrongParity(..) | RequestIdError::OutOfSequence { .. },
            ) => Some(SessionErrorCode::InvalidRequestId),
            // Section 8.4 answers a GOAWAY that repeats one already
            // received, and names this code in the same sentence.
            EndpointError::RepeatedGoAway => Some(SessionErrorCode::ProtocolViolation),
            // The same section answers a migration URI arriving at a server
            // with a close, and names this code for it. Only a server may
            // offer one, so a client that sends one is telling a server where
            // to reconnect, which it has no standing to do.
            EndpointError::GoAwayUriAtServer => Some(SessionErrorCode::ProtocolViolation),
            // Sections 8.8 and 8.13 name this code in the sentence that
            // states the rule, and name no other. A close carrying
            // PROTOCOL_VIOLATION would tell the peer a different thing went
            // wrong.
            EndpointError::DuplicateTrackAlias { .. } => {
                Some(SessionErrorCode::DuplicateTrackAlias)
            }
            // Section 8.10 answers an update naming a request the session has
            // never carried with a close, and names this code for it.
            EndpointError::UpdateForUnknownRequest(_) => Some(SessionErrorCode::ProtocolViolation),
            // Section 9.2.1.1 answers an end-of-track object in the wrong place
            // with "the receiver MUST terminate the session", and names no code
            // in that sentence. The paragraph it closes names one for the
            // status field's other failure — "Any other value SHOULD be treated
            // as a protocol error and terminate the session with a Protocol
            // Violation" — and it is the code this draft's decoder already
            // gives the half of the same rule it can settle from one header.
            EndpointError::EndOfTrackOutOfPlace { .. } => Some(SessionErrorCode::ProtocolViolation),
            _ => None,
        }
    }
}

impl EndpointError {
    /// The endpoint's report of a fault a track's record found.
    ///
    /// Written once because the two data paths reach it from different places:
    /// a datagram through [`Endpoint::note_received_object`], and a subgroup
    /// object through the stream that decoded it, which holds a record handle
    /// and no endpoint. Two translations would be two chances for the same
    /// fault to be reported as different rules.
    pub(crate) fn for_track_fault(alias: u64, at: ObjectLocation, fault: TrackFault) -> Self {
        match fault {
            TrackFault::EndOfTrackOutOfPlace(placement) => EndpointError::EndOfTrackOutOfPlace {
                alias,
                group: at.group,
                object: at.object,
                placement,
            },
            TrackFault::PastFinalObject(end) => EndpointError::ObjectPastFinalObject {
                alias,
                group: at.group,
                object: at.object,
                final_group: end.group,
                final_object: end.object,
            },
        }
    }
}

/// Unified draft-12 MoQT endpoint wrapping session lifecycle, request ID
/// allocation, and all per-flow state machines (subscriptions, fetches,
/// announces, subscribe-announces, track statuses).
pub struct Endpoint {
    /// Which end of the session this is, which fixes the parity of the
    /// request IDs it allocates.
    role: Role,
    session: SessionStateMachine,
    request_ids: RequestIdAllocator,
    /// Tracks the MAX_REQUEST_ID we have advertised to the peer.
    advertised_max_id: u64,
    subscriptions: HashMap<u64, Mutex<SubscriptionStateMachine>>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_announces: HashMap<u64, SubscribeAnnouncesStateMachine>,
    /// Namespace subscriptions the **peer** made, keyed by the Request ID it
    /// opened each under.
    ///
    /// Kept apart from `subscribe_announces`, which holds the ones this endpoint made:
    /// one Request ID names one request whichever end opened it, and the two
    /// ends answer opposite halves of the flow.
    inbound_subscribe_announces: HashMap<u64, InboundSubscribeAnnounces>,
    announces: HashMap<u64, AnnounceStateMachine>,
    /// Announcements the **peer** made, keyed by the Request ID it
    /// opened each under.
    inbound_announces: HashMap<u64, InboundAnnounce>,
    /// Maps namespace tuple -> request_id, so callers can UNANNOUNCE / cancel
    /// by namespace without threading the id through every API.
    announce_ids: HashMap<NamespaceKey, u64>,
    /// Maps namespace prefix tuple -> request_id for subscribe-announces.
    subscribe_announces_ids: HashMap<NamespaceKey, u64>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    /// Track statuses the **peer** asked about, keyed by the Request ID it
    /// asked under.
    ///
    /// Kept apart from `track_statuses`, which holds the ones this endpoint
    /// asked about: the two are answered by opposite ends, and one Request ID
    /// belongs to one request whichever end opened it.
    inbound_track_statuses: HashMap<u64, InboundTrackStatus>,
    /// The subscriptions the peer opened with PUBLISH, keyed by the request
    /// id it opened them under.
    ///
    /// The record outlives the answer. Section 4.1 makes a PUBLISH the start
    /// of a subscription rather than a question to be answered and forgotten:
    /// "Once either of these sequences is successful, the subscription can be
    /// updated by the subscriber using SUBSCRIBE_UPDATE, terminated by the
    /// subscriber using UNSUBSCRIBE, or terminated by the publisher using
    /// SUBSCRIBE_DONE." Everything after the answer needs the record - which
    /// Track Alias is spoken for, and whether a message naming this request is
    /// still about anything.
    ///
    /// The offers this endpoint makes itself are in `publishes` beside this,
    /// which holds their state and not their message: the two are answered by
    /// opposite ends.
    inbound_publishes: HashMap<u64, InboundPublish>,
    /// The subscriptions **this endpoint** opened with PUBLISH, keyed by the
    /// Request ID it allocated for each.
    ///
    /// The state and nothing else, because the offer was built here and the
    /// caller was handed it. That is the one asymmetry with `inbound_publishes`
    /// and it is the same one every other pair of records here has.
    publishes: HashMap<u64, PublishStateMachine>,
    /// Subscriptions the **peer** opened with SUBSCRIBE, by Request ID.
    ///
    /// Section 8.10 puts SUBSCRIBE_UPDATE in the subscriber's hands - "A
    /// subscriber sends a SUBSCRIBE_UPDATE to a publisher to modify an
    /// existing subscription" - so an update that arrives names a
    /// subscription in here and never one in `subscriptions`.
    ///
    /// The record holds the SUBSCRIBE itself and not only its state, because
    /// the answer is built out of the request: the track a SUBSCRIBE_OK is
    /// about is named nowhere else, and the alias it hands out has to be
    /// judged against that name.
    inbound_subscribes: HashMap<u64, InboundSubscribe>,
    /// Every FETCH the peer has sent, from arrival to the end of the fetch.
    ///
    /// Separate from `fetches`, which holds the ones this endpoint made. The
    /// record holds the FETCH itself and not only its state, because the
    /// answer is built out of the request: a Joining Fetch has to be judged
    /// against the subscription it names, and that name is nowhere else.
    inbound_fetches: HashMap<u64, InboundFetch>,
    negotiated_version: Option<VarInt>,
    offered_versions: Vec<VarInt>,
    goaway_uri: Option<Vec<u8>>,
    /// The most recent `maximum_request_id` reported by the peer via a
    /// `REQUESTS_BLOCKED` message.
    peer_reported_max_request_id: Option<VarInt>,
    /// What Full Track Name the peer has attached each Track Alias to, per
    /// Request ID.
    ///
    /// Sections 8.8 and 8.13 forbid one alias naming two tracks at once, and the
    /// "at once" is what makes this a table rather than a set: an alias the
    /// peer used for a track whose subscription has ended is free again. The
    /// table therefore records the binding and reads liveness back off the
    /// subscription's own state machine, rather than keeping a second copy of
    /// it that every path ending a subscription would have to remember to
    /// prune.
    /// What each track's objects have been framed as, so far.
    ///
    /// Behind a lock because this is the one endpoint fact a *data* stream
    /// settles, and the data plane reaches the endpoint through `&Connection`:
    /// a caller may hold one across tasks while it reads streams and datagrams,
    /// so there is no `&mut` to reach the rest of this struct with.
    forwarding_preferences: Mutex<TrackForwardingPreferences>,
    /// The tracks this endpoint has found malformed and withdrawn from.
    ///
    /// Behind a lock for the same reason the record above it is: it is
    /// written from the data plane, which holds a shared reference.
    malformed: Mutex<MalformedTracks>,
    /// How far each track's objects have reached, so far.
    ///
    /// Behind an `Arc` rather than beside the rest of this struct because the
    /// objects that settle it are read off stream handles the caller owns, one
    /// at a time, with no way back to the endpoint. Each such stream is handed a
    /// clone of the handle, and every clone measures against this one record.
    locations: Arc<Mutex<TrackLocations>>,
    track_bindings: HashMap<u64, TrackBinding>,
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

/// Which of the two sequences Section 4.1 names established the subscription
/// that owns a binding, and so which record says whether it still has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    /// This endpoint's SUBSCRIBE, established by the peer's SUBSCRIBE_OK.
    Subscribe,
    /// A PUBLISH, established by the PUBLISH_OK answering it - whichever end
    /// sent which. Both records are consulted for one of these, and only one
    /// of them can hold the id: Section 8.1 gives the two ends opposite halves
    /// of the Request ID space.
    Publish,
    /// The peer's SUBSCRIBE, established by this endpoint's SUBSCRIBE_OK.
    ///
    /// The alias is this endpoint's to choose on that one, because Section 8.8
    /// carries it in the answer rather than in the request.
    PeerSubscribe,
}

/// A subscription the peer opened with PUBLISH.
struct InboundPublish {
    /// The message as it arrived, which is what the application answers from.
    message: Publish,
    /// How far the subscription it opened has got.
    ///
    /// Behind a lock for the reason [`Endpoint::subscription`] gives: an
    /// offer the peer made is one of the two ways this endpoint receives a
    /// track, so a withdrawal from the data plane has to reach it.
    state: Mutex<PublishStateMachine>,
}

impl InboundPublish {
    /// The flow this offer opened, locked for a read or a transition.
    fn flow(&self) -> MutexGuard<'_, PublishStateMachine> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How far that flow has got.
    fn publish_state(&self) -> PublishState {
        self.flow().state()
    }
}

/// A subscription the peer opened with SUBSCRIBE.
struct InboundSubscribe {
    /// The message as it arrived, which is what the application answers from.
    message: Subscribe,
    /// How far the subscription it opened has got.
    state: SubscriptionStateMachine,
}
/// A fetch the peer opened with FETCH.
struct InboundFetch {
    /// The message as it arrived, which is what the application answers from.
    message: Fetch,
    /// How far the fetch it opened has got.
    state: FetchStateMachine,
    /// The subscription a Joining Fetch named and this session had none live
    /// for when the FETCH arrived, which is when the rule about it is read.
    unjoinable: Option<u64>,
}

/// An announcement the peer made with ANNOUNCE.
///
/// Kept apart from the announcements this endpoint made because the two are
/// answered by opposite ends: this one is waiting for an answer from here,
/// and the other for one from the peer.
struct InboundAnnounce {
    /// The message as it arrived, which is what the application answers from.
    message: Announce,
    /// How far the announcement it makes has got.
    state: AnnounceStateMachine,
}
/// A track status the peer asked for with TRACK_STATUS_REQUEST.
///
/// Kept apart from the ones this endpoint asked for because the two are
/// answered by opposite ends: this one is waiting for an answer from here,
/// and the other for one from the peer.
struct InboundTrackStatus {
    /// The message as it arrived, which is what the answer is built from.
    message: TrackStatusRequest,
    /// How far the request it opened has got.
    state: TrackStatusStateMachine,
}
/// A SUBSCRIBE_ANNOUNCES the peer sent, and how far the namespace subscription it opens
/// has got.
///
/// Kept apart from `subscribe_announces`, which holds the ones this endpoint made: the
/// two are answered by opposite ends, and this one is waiting for an answer
/// from here.
struct InboundSubscribeAnnounces {
    /// The message as it arrived, which is what the answer is built from.
    message: SubscribeAnnounces,
    /// How far the namespace subscription it opens has got.
    state: SubscribeAnnouncesStateMachine,
    /// The namespace subscription this one overlapped when it arrived,
    /// which is when the rule about it is read.
    overlaps: Option<u64>,
}
impl Endpoint {
    /// Create a new draft-12 endpoint for the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(role),
            advertised_max_id: 0,
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            subscribe_announces: HashMap::new(),
            inbound_subscribe_announces: HashMap::new(),
            announces: HashMap::new(),
            inbound_announces: HashMap::new(),
            announce_ids: HashMap::new(),
            subscribe_announces_ids: HashMap::new(),
            track_statuses: HashMap::new(),
            inbound_track_statuses: HashMap::new(),
            inbound_publishes: HashMap::new(),
            publishes: HashMap::new(),
            inbound_subscribes: HashMap::new(),
            inbound_fetches: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
            peer_reported_max_request_id: None,
            track_bindings: HashMap::new(),
            forwarding_preferences: Mutex::new(TrackForwardingPreferences::new()),
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

    /// The refusal Sections 8.8 and 8.13 require when `alias` already names a
    /// different track whose subscription is still live, or `None` when it is
    /// free.
    ///
    /// # Why the set is read rather than kept
    ///
    /// The draft says "an active subscription", and this endpoint's
    /// subscription state machine has exactly that state: a subscription
    /// reaches Active on SUBSCRIBE_OK and leaves it on the message that ends
    /// the flow. Asking it is what makes an alias free again the moment its track's
    /// subscription ends, with nothing to prune on the way out - and a path
    /// that ended a subscription without telling this table would otherwise
    /// leave the alias held forever and refuse the peer's next, conforming,
    /// use of it.
    ///
    /// # Why the request's own binding is skipped
    ///
    /// A SUBSCRIBE_OK is judged before its own alias is written down, so the
    /// skip is not what keeps it from finding itself. A PUBLISH is: it carries
    /// its alias and its track in the one message, and a second PUBLISH under
    /// a Request ID already bound is refused by the duplicate-Request-ID rule
    /// before it reaches here.
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

    /// Whether the request that owns a binding still has a live subscription.
    ///
    /// The two kinds are answered by two different records because the two
    /// sequences Section 4.1 names end in different places: a SUBSCRIBE this
    /// endpoint made is live once its SUBSCRIBE_OK arrives, a PUBLISH the peer
    /// made once this endpoint has answered PUBLISH_OK.
    fn binding_is_established(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => {
                self.subscription(id).is_some_and(|sm| sm.state() == SubscriptionState::Active)
            }
            BindingKind::Publish => {
                self.inbound_publishes
                    .get(&id)
                    .is_some_and(|p| p.publish_state() == PublishState::Active)
                    || self.publishes.get(&id).is_some_and(|sm| sm.state() == PublishState::Active)
            }
            BindingKind::PeerSubscribe => self
                .inbound_subscribes
                .get(&id)
                .is_some_and(|s| s.state.state() == SubscriptionState::Active),
        }
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

    /// The track a live binding has given `alias` to.
    ///
    /// Read rather than kept, for the reason the alias table beside it gives: a
    /// binding whose request has ended holds nothing, and an alias that is free
    /// again may name a different track next. That is exactly why the
    /// forwarding-preference record below is keyed on the track this returns
    /// and never on the alias itself.
    fn track_for_alias(&self, alias: u64) -> Option<(&TrackNamespace, &[u8])> {
        self.track_bindings.iter().find_map(|(&id, binding)| {
            (binding.alias == Some(alias) && self.binding_is_in_use(id, binding.kind))
                .then_some((&binding.namespace, binding.name.as_slice()))
        })
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
    /// report the two rules its track's record answers: Section 9.2.1.1's
    /// protocol error when an end-of-track object says the track ended
    /// somewhere the track has already passed, and Section 2.5's Malformed
    /// Track when an object arrives after the place an end-of-track object put
    /// the end.
    ///
    /// `&self`, because the call site is the data plane's.
    pub fn note_received_object(
        &self,
        alias: u64,
        at: ObjectLocation,
        role: ObjectRole,
    ) -> Result<(), EndpointError> {
        let Some(objects) = self.track_objects(alias) else { return Ok(()) };
        objects
            .note_with_final_object(at, role)
            .map_err(|fault| EndpointError::for_track_fault(alias, at, fault))
    }

    /// Record how a track's object was framed, and report Section 9's "MUST NOT
    /// mix" when it disagrees with what that track's earlier objects used.
    ///
    /// `&self`, because the call sites are the data plane's: a subgroup header
    /// arriving, a datagram arriving, and the two writers that produce them.
    ///
    /// An alias no live binding names records nothing and reports nothing. An
    /// object for such an alias breaks a different rule — the one about objects
    /// nobody asked for — and answering that one here would answer it with the
    /// wrong sentence.
    pub fn note_object_forwarding_preference(
        &self,
        alias: u64,
        seen: ObjectForwardingPreference,
    ) -> Result<(), EndpointError> {
        let Some((namespace, name)) = self.track_for_alias(alias) else { return Ok(()) };
        self.forwarding_preferences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(namespace, name, seen)
            .map_err(|established| EndpointError::MixedForwardingPreference {
                alias,
                established,
                offered: seen,
            })
    }

    /// The subscription `id` opened, locked for a read or a transition.
    ///
    /// `&self`, which is the whole point of the lock. Section 2.5's answer to
    /// a Malformed Track is "it MUST UNSUBSCRIBE from the Track", and the
    /// conditions that make a track malformed are detected on the data plane,
    /// where this endpoint is reached through a shared reference. A flow that
    /// could only be moved through `&mut self` would leave that sentence
    /// unanswerable from the only place it is ever read.
    ///
    /// Hold one guard at a time. Nothing here takes a second while a first is
    /// live, and [`Self::withdraw_malformed_track`] collects the requests it
    /// is going to move before it moves any of them for that reason.
    fn subscription(&self, id: u64) -> Option<MutexGuard<'_, SubscriptionStateMachine>> {
        self.subscriptions
            .get(&id)
            .map(|sm| sm.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    /// The condition a track was withdrawn for, or `None` for a track this
    /// endpoint has found nothing wrong with.
    ///
    /// The withdrawal happens without the application asking for it, so this
    /// is how an application that missed the error learns why a subscription
    /// it never ended has ended.
    ///
    /// # Why this takes a track and not the alias the object carried
    ///
    /// An alias only means anything through a live binding, and the
    /// withdrawal ends the binding it would have been resolved through. An
    /// accessor taking an alias would therefore answer `None` from the
    /// instant it had something to say, which is worse than not existing.
    /// The record is keyed on the track, and so is this.
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

    /// Withdraw from a track a condition has just shown to be malformed, and
    /// give back the UNSUBSCRIBEs Section 2.5 asks for.
    ///
    /// "When a subscriber detects a Malformed Track, it MUST UNSUBSCRIBE from
    /// the Track and SHOULD deliver an error to the application." This is the
    /// first half. The second is the error the detecting path returns, which
    /// is why nothing here reports anything: a caller that gets an empty list
    /// back is not being told the track was fine.
    ///
    /// `&self`, because the call site is the data plane's.
    ///
    /// # What comes back, and what does not
    ///
    /// One UNSUBSCRIBE for each request through which this endpoint is
    /// *receiving* the track — a SUBSCRIBE it sent, and a PUBLISH the peer
    /// sent that it accepted, which Section 4.1 ends with the same message.
    /// A request that names the track the other way round is not one of
    /// those: a peer subscribing to this endpoint makes it the publisher, and
    /// a publisher does not unsubscribe from what it is serving.
    ///
    /// Empty for an alias no live binding names — there is no track to
    /// withdraw from — and for a track whose only requests are in a state
    /// that has no UNSUBSCRIBE in it. A subscription still waiting for its
    /// SUBSCRIBE_OK is the case that reaches that last one, and it holds no
    /// alias for an object to have arrived under.
    ///
    /// # What makes the answer happen once
    ///
    /// Not the record. The requests this withdraws end here, and a request
    /// that has ended has no second UNSUBSCRIBE in it, so a publisher that
    /// goes on mixing a track's framing is answered once however many objects
    /// it sends. The record is read afterwards, by an application asking why
    /// a track it never gave up was given up.
    ///
    /// Which leaves the case the two answers differ on: an application that
    /// subscribes to the same track again. That request has never been
    /// withdrawn from, and a publisher mixing its framing again has broken
    /// the sentence again, so it is withdrawn from too.
    pub fn withdraw_malformed_track(
        &self,
        alias: u64,
        condition: MalformedTrackCondition,
    ) -> Vec<ControlMessage> {
        let Some((namespace, name)) = self.track_for_alias(alias) else { return Vec::new() };
        let (namespace, name) = (namespace.clone(), name.to_vec());
        self.malformed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .note(&namespace, &name, condition);
        // Collected before any of them is moved. `binding_is_in_use` takes a
        // subscription's own lock and the transitions below take it again, so
        // the scan finishes first and holds nothing while it runs.
        let mut ids: Vec<u64> = self
            .track_bindings
            .iter()
            .filter(|(&id, binding)| {
                binding.namespace == namespace
                    && binding.name == name
                    && self.binding_is_in_use(id, binding.kind)
            })
            .map(|(&id, _)| id)
            .collect();
        // A HashMap iterates in no order, and two subscriptions on one track
        // is a shape a peer can produce. Sorted so the wire is the same twice.
        ids.sort_unstable();
        ids.into_iter().filter_map(|id| self.withdraw_one(id)).collect()
    }

    /// The UNSUBSCRIBE ending one request, or `None` when that request is not
    /// one this endpoint receives a track through or is not in a state that
    /// can be unsubscribed from.
    fn withdraw_one(&self, id: u64) -> Option<ControlMessage> {
        let request_id = VarInt::from_u64(id).ok()?;
        if let Some(mut sm) = self.subscription(id) {
            sm.on_unsubscribe().ok()?;
            return Some(ControlMessage::Unsubscribe(Unsubscribe { request_id }));
        }
        let entry = self.inbound_publishes.get(&id)?;
        entry.flow().on_unsubscribe_sent().ok()?;
        Some(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Whether a binding's request has put its alias in play at all.
    ///
    /// Broader than [`Self::binding_is_established`], and the two sentences
    /// are why. What an endpoint must close over is qualified - "a different
    /// track with an active subscription" - and the prohibition Section 8.8
    /// opens with is not: "The same Track Alias MUST NOT be used to refer to
    /// two different Tracks simultaneously." Once an alias has been handed
    /// out, giving it to a second track is what that sentence forbids,
    /// answered or not.
    fn binding_is_in_use(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => {
                self.subscription(id).is_some_and(|sm| sm.state() != SubscriptionState::Done)
            }
            BindingKind::Publish => {
                self.inbound_publishes
                    .get(&id)
                    .is_some_and(|p| p.publish_state() != PublishState::Done)
                    || self.publishes.get(&id).is_some_and(|sm| sm.state() != PublishState::Done)
            }
            BindingKind::PeerSubscribe => self
                .inbound_subscribes
                .get(&id)
                .is_some_and(|s| s.state.state() != SubscriptionState::Done),
        }
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

    // ── Accessors ──────────────────────────────────────────────

    /// Returns the role (client or server) of this endpoint.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the current session state.
    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    /// Returns the negotiated MoQT version, if setup is complete.
    pub fn negotiated_version(&self) -> Option<VarInt> {
        self.negotiated_version
    }

    /// Returns the URI from a received GOAWAY message, if any.
    pub fn goaway_uri(&self) -> Option<&[u8]> {
        self.goaway_uri.as_deref()
    }

    /// Returns whether this endpoint is blocked on request ID allocation.
    pub fn is_blocked(&self) -> bool {
        self.request_ids.is_blocked()
    }

    /// Returns the number of active subscription state machines.
    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns the number of active fetch state machines.
    pub fn active_fetch_count(&self) -> usize {
        self.fetches.len()
    }

    /// Returns the number of active subscribe-announces state machines.
    pub fn active_subscribe_announces_count(&self) -> usize {
        self.subscribe_announces.len()
    }

    /// Returns the number of active announce state machines.
    pub fn active_announce_count(&self) -> usize {
        self.announces.len()
    }

    /// Returns the number of active track status state machines.
    pub fn active_track_status_count(&self) -> usize {
        self.track_statuses.len()
    }

    // ── Session lifecycle ──────────────────────────────────────

    /// Transition from Connecting to SetupExchange.
    pub fn connect(&mut self) -> Result<(), EndpointError> {
        self.session.on_connect()?;
        Ok(())
    }

    /// Close the session (SetupExchange, Active or Draining -> Closed).
    pub fn close(&mut self) -> Result<(), EndpointError> {
        self.session.on_close()?;
        Ok(())
    }

    // ── Client setup ───────────────────────────────────────────

    /// Generate a CLIENT_SETUP message (client-side).
    pub fn send_client_setup(
        &mut self,
        versions: Vec<VarInt>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        self.offered_versions = versions.clone();
        let msg = ClientSetup { supported_versions: versions, parameters };
        setup::validate_client_setup(&msg)?;
        // A MAX_REQUEST_ID parameter in our own CLIENT_SETUP is a grant to
        // the peer, so it is the first value of the ceiling we advertise.
        self.record_advertised_max(&msg.parameters);
        Ok(ControlMessage::ClientSetup(msg))
    }

    /// Process a SERVER_SETUP message (client-side). Transitions to Active.
    /// If the server includes a MAX_REQUEST_ID parameter (key 0x02), the
    /// request ID allocator is initialized with that value.
    pub fn receive_server_setup(&mut self, msg: &ServerSetup) -> Result<(), EndpointError> {
        setup::validate_server_setup(msg)?;
        let version = setup::negotiate_version(&self.offered_versions, msg.selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        // Extract MAX_REQUEST_ID (key 0x02) from setup parameters if present
        for param in &msg.parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                if let KvpValue::Varint(v) = &param.value {
                    self.request_ids.update_max(v.into_inner())?;
                }
            }
        }
        Ok(())
    }

    // ── Server setup ───────────────────────────────────────────

    /// Process CLIENT_SETUP and generate SERVER_SETUP (server-side).
    pub fn receive_client_setup_and_respond(
        &mut self,
        client_setup: &ClientSetup,
        selected_version: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        setup::validate_client_setup(client_setup)?;
        // Section 8.3.2.2 puts no role restriction on MAX_REQUEST_ID, so a
        // CLIENT_SETUP may carry it and it grants this endpoint its budget.
        for param in &client_setup.parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                if let KvpValue::Varint(v) = &param.value {
                    self.request_ids.update_max(v.into_inner())?;
                }
            }
        }
        let version = setup::negotiate_version(&client_setup.supported_versions, selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        let msg = ServerSetup { selected_version: version, parameters: vec![] };
        Ok(ControlMessage::ServerSetup(msg))
    }

    // ── MAX_REQUEST_ID ─────────────────────────────────────────

    /// Take a Request ID from a new request the peer sent, holding it to all
    /// three halves of the rule.
    ///
    /// Section 8.1 closes the session with Invalid Request ID on a request ID
    /// "that is not valid for the peer", and Section 8.5 closes it with
    /// 'Too Many Requests' on one at or above the ceiling this endpoint
    /// advertised. The parity half belongs to the allocator; the ceiling half
    /// needs `advertised_max_id`, which is this endpoint's grant to the peer
    /// and not the peer's grant to it, so the two numbers are different and
    /// only one of them answers this question.
    ///
    /// The third is the sequence. The same sentence closes the session on "a
    /// new request with a Request ID that is not expected", and what is
    /// expected is fixed by the two lines above it: each endpoint starts at 0
    /// or 1 by role and steps by 2 per request. So a repeat and a skip are both
    /// refused, and neither is caught by parity or by the ceiling - a repeat has
    /// the right parity and sits below the ceiling by construction, having been
    /// accepted once already.
    ///
    /// Taking the ID is what advances the sequence, so this is for a **new**
    /// request only. A response, a cancellation or an update that names the
    /// request it modifies all carry an ID that has already been spent, and
    /// passing one here would refuse it.
    ///
    /// # The ceiling is a session rule, not a request rule
    ///
    /// Section 8.5: a Request ID "equal to or larger than this" received by the
    /// endpoint that sent the MAX_REQUEST_ID in any request message - the list
    /// [`Self::receive_request`] carries - closes the session, and 'Too Many
    /// Requests' is the code. Which is also why the number measured against is
    /// the one **this** endpoint sent. An id that reaches the ceiling is not a
    /// request to refuse with an error message: the session is over, so this
    /// moves the endpoint's own state to Closed and leaves the code to
    /// [`EndpointError::session_error_code`].
    ///
    /// # Errors
    ///
    /// [`RequestIdError::WrongParity`] if the ID belongs to this endpoint's
    /// half of the space, [`RequestIdError::ExceedsMax`] if it is not
    /// below the advertised ceiling, or [`RequestIdError::OutOfSequence`] if it
    /// is not the one the peer's sequence called for. A ceiling that was never
    /// raised is 0, which refuses every ID, matching a default that reads "the
    /// peer MUST NOT send requests".
    ///
    /// All three end the session rather than the one request, so all three
    /// move this endpoint's own session to Closed on the way out and all three
    /// answer `Some` from [`EndpointError::session_error_code`]. Returning one
    /// of them without ending the session would leave a peer that broke the
    /// rule free to keep sending, and never told.
    pub fn validate_peer_request_id(&mut self, id: u64) -> Result<(), EndpointError> {
        if let Err(e) = self.request_ids.validate_peer_id(id) {
            return Err(self.fail_session(EndpointError::RequestId(e)));
        }
        if id >= self.advertised_max_id {
            return Err(self.fail_session(EndpointError::RequestId(RequestIdError::ExceedsMax(
                id,
                self.advertised_max_id,
            ))));
        }
        if let Err(e) = self.request_ids.record_peer_id(id) {
            return Err(self.fail_session(EndpointError::RequestId(e)));
        }
        Ok(())
    }

    /// Record a MAX_REQUEST_ID parameter this endpoint is about to send as
    /// the ceiling it has advertised to the peer.
    fn record_advertised_max(&mut self, parameters: &[KeyValuePair]) {
        for param in parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                if let KvpValue::Varint(v) = &param.value {
                    self.advertised_max_id = v.into_inner();
                }
            }
        }
    }

    /// Process an incoming MAX_REQUEST_ID message, ending the session if the
    /// ceiling it carries does not increase.
    /// Section 8.5: "The Maximum Request ID MUST only increase within a
    /// session, and receipt of a MAX_REQUEST_ID message with an equal or
    /// smaller Request ID value is a 'Protocol Violation'." Section 3.4 lists
    /// Protocol Violation among the codes for terminating the session - "The
    /// remote endpoint performed an action that was disallowed by the
    /// specification" - so naming it of a *receipt* is this draft saying the
    /// session ends, and with which code. Draft-16 Section 9.5 states the same
    /// rule with the verb in it: "it MUST close the session with a
    /// PROTOCOL_VIOLATION".
    ///
    /// # Errors
    ///
    /// [`RequestIdError::Decreased`] if the value does not increase, with the
    /// session already moved to Closed.
    pub fn receive_max_request_id(&mut self, msg: &MaxRequestId) -> Result<(), EndpointError> {
        if let Err(err) = self.request_ids.update_max(msg.request_id.into_inner()) {
            return Err(self.fail_session(err.into()));
        }
        Ok(())
    }

    /// Generate a MAX_REQUEST_ID message (typically server-side).
    ///
    /// Section 8.5: "The Maximum Request ID MUST only increase within a
    /// session", and a peer that receives an equal or smaller value closes
    /// the session. The ceiling starts at 0 and 0 is not greater than 0, so
    /// the first value that may go on the wire is 1 and there is no opening
    /// case where a repeat is allowed.
    ///
    /// # Errors
    ///
    /// The decrease error if the value does not strictly increase.
    pub fn send_max_request_id(&mut self, max_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let new_val = max_id.into_inner();
        if new_val <= self.advertised_max_id {
            return Err(EndpointError::RequestId(RequestIdError::Decreased(
                self.advertised_max_id,
                new_val,
            )));
        }
        self.advertised_max_id = new_val;
        Ok(ControlMessage::MaxRequestId(MaxRequestId { request_id: max_id }))
    }

    // ── GoAway ─────────────────────────────────────────────────

    /// Process an incoming GOAWAY message. Transitions to Draining.
    ///
    /// # Errors
    ///
    /// [`EndpointError::GoAwayUriAtServer`] if this endpoint is the server and
    /// the GOAWAY carries a New Session URI. The session is over: this
    /// endpoint's own state has moved to Closed and the code the transport
    /// should close with is in [`EndpointError::session_error_code`].
    ///
    /// [`EndpointError::RepeatedGoAway`] if a GOAWAY has already been
    /// received. The session is over: this endpoint's own state has moved to
    /// Closed and the code the transport should close with is in
    /// [`EndpointError::session_error_code`].
    pub fn receive_goaway(&mut self, msg: &GoAway) -> Result<(), EndpointError> {
        // Section 8.4: "If a server receives a GOAWAY with a non-zero New
        // Session URI Length it MUST terminate the session with a Protocol
        // Violation." Refused before the URI is stored rather than
        // after, so an application reading `goaway_uri` back can never be
        // handed somewhere a client chose to send it. The session ends with
        // it: the sentence names a close and a code, and an endpoint that
        // raised the error and carried on would keep serving a peer it had
        // just found in violation.
        if self.role == Role::Server && !msg.new_session_uri.is_empty() {
            return Err(self.fail_session(EndpointError::GoAwayUriAtServer));
        }
        // Section 8.4: "The endpoint MUST terminate the session with a
        // Protocol Violation (Section 3.4) if it receives multiple GOAWAY messages."
        // Draining is reached from nowhere else - `on_goaway` is its only
        // entry and this method is that method's only caller - so the session
        // state is the record of the first GOAWAY having arrived.
        if self.session.state() == SessionState::Draining {
            return Err(self.fail_session(EndpointError::RepeatedGoAway));
        }
        self.session.on_goaway()?;
        self.goaway_uri = Some(msg.new_session_uri.clone());
        Ok(())
    }

    // ── Subscribe flow ─────────────────────────────────────────

    fn require_active_or_err(&self) -> Result<(), EndpointError> {
        match self.session.state() {
            SessionState::Active => Ok(()),
            SessionState::Draining => Err(EndpointError::Draining),
            _ => Err(EndpointError::NotActive),
        }
    }

    /// Record that the session is over because the peer broke a rule this
    /// draft answers with a session close, and hand the error back unchanged.
    ///
    /// The state move is what makes the violation stick: every request entry
    /// point goes through
    /// [`require_active_or_err`](Self::require_active_or_err), so a caller
    /// that ignores the returned error still cannot start anything new.
    /// Closing on the wire is the connection layer's job - see
    /// [`EndpointError::session_error_code`] for the code it should use.
    fn fail_session(&mut self, err: EndpointError) -> EndpointError {
        // `on_close` accepts Active and Draining and nothing else. A
        // violation seen in any other state leaves the state machine
        // alone: there is no session to close, and the error itself is
        // still the answer.
        let _ = self.session.on_close();
        err
    }

    /// Send a SUBSCRIBE message. Allocates an ID and creates a subscription
    /// state machine.
    ///
    /// `AbsoluteStart` and `AbsoluteRange` name a start location, which this
    /// call has no way to supply, and are answered with
    /// [`EndpointError::FilterNeedsRange`] - use [`Self::subscribe_range`] for
    /// those. Without the refusal this call would hand back a message whose
    /// filter announces fields the message does not carry, and the frame that
    /// goes on the wire is short by exactly those fields.
    pub fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        if matches!(filter_type.into_inner(), 3 | 4) {
            return Err(EndpointError::FilterNeedsRange);
        }
        self.subscribe_inner(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            None,
            None,
            parameters,
        )
    }

    /// Send a SUBSCRIBE for a range of the track, starting at a given
    /// location.
    ///
    /// The Filter Type is derived from the arguments rather than taken beside
    /// them, so the message cannot name a filter whose fields it does not
    /// carry.
    #[allow(clippy::too_many_arguments)]
    pub fn subscribe_range(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        start_location: Location,
        end_group: Option<VarInt>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        // 0x3 is AbsoluteStart and 0x4 is AbsoluteRange. The Filter Type is a
        // bare varint on this draft, so there is no enum to name them by.
        let filter_type = VarInt::from_u64(if end_group.is_some() { 4 } else { 3 }).unwrap();
        self.subscribe_inner(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            Some(start_location),
            end_group,
            parameters,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn subscribe_inner(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: VarInt,
        start_location: Option<Location>,
        end_group: Option<VarInt>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscriptionStateMachine::new();
        sm.on_subscribe_sent()?;
        self.subscriptions.insert(req_id.into_inner(), Mutex::new(sm));
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

        let (start_group, start_object) = match start_location {
            Some(start) => (Some(start.group), Some(start.object)),
            None => (None, None),
        };
        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: req_id,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            forward: Forward::Forward,
            filter_type,
            start_group,
            start_object,
            end_group,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
    ///
    /// Draft-12 carries the publisher-assigned `track_alias` on SUBSCRIBE_OK,
    /// which is recorded here so callers can retrieve it via
    /// [`Endpoint::track_alias_for`].
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        if !self.subscriptions.contains_key(&id) {
            return Err(EndpointError::UnknownRequest(id));
        }
        let alias = msg.track_alias.into_inner();
        // Judged before the transition, so that the subscription this message
        // is about is not yet live and cannot be found as its own conflict,
        // and so that a refused SUBSCRIBE_OK leaves no alias behind.
        if let Some(conflict) = self.conflicting_alias_for_subscribe_ok(id, alias) {
            return Err(self.fail_session(conflict));
        }
        let mut sm = self.subscription(id).expect("checked above");
        sm.on_subscribe_ok()?;
        drop(sm);
        if let Some(binding) = self.track_bindings.get_mut(&id) {
            binding.alias = Some(alias);
        }
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ERROR.
    pub fn receive_subscribe_error(&mut self, msg: &SubscribeError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let mut sm = self.subscription(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE message for an active subscription.
    ///
    /// Section 4.1 gives the subscriber this for a subscription that came
    /// either way round, so a request the peer opened with PUBLISH ends here
    /// too. The two kinds cannot collide: a Request ID belongs to whichever
    /// endpoint allocated it, and the two halves of the space have opposite
    /// least significant bits.
    pub fn unsubscribe(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        if let Some(mut sm) = self.subscription(id) {
            sm.on_unsubscribe()?;
            return Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }));
        }
        let entry = self.inbound_publishes.get(&id).ok_or(EndpointError::UnknownRequest(id))?;
        entry.flow().on_unsubscribe_sent()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Send a SUBSCRIBE_UPDATE narrowing a subscription this endpoint opened.
    ///
    /// Section 8.10 gives the message to the subscriber, which is what this
    /// endpoint is for every subscription in `subscriptions`. No identifier is
    /// spent: this draft's SUBSCRIBE_UPDATE has one Request ID field and it
    /// names the subscription being modified, which is why Section 8.1 leaves
    /// the message out of the list that steps the peer's sequence.
    ///
    /// The narrowing rules the same section states are the caller's to keep.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when this endpoint opened no
    /// subscription under that identifier, and the subscription flow's own
    /// `InvalidTransition` when the one it names has already ended.
    #[allow(clippy::too_many_arguments)]
    pub fn subscribe_update(
        &mut self,
        request_id: VarInt,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        subscriber_priority: u8,
        forward: Forward,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let id = request_id.into_inner();
        let mut sm = self.subscription(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_update()?;
        drop(sm);
        Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id,
            start_group,
            start_object,
            end_group,
            subscriber_priority,
            forward,
            parameters,
        }))
    }

    /// Process an incoming SUBSCRIBE_UPDATE.
    ///
    /// Section 8.10: "A subscriber sends a SUBSCRIBE_UPDATE to a publisher to
    /// modify an existing subscription." One that arrives is therefore about a
    /// subscription the **peer** opened, which is why it is looked for among
    /// those and not among this endpoint's own.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UpdateForUnknownRequest`] when the Request ID names no
    /// subscription the peer has opened in this session, with the session
    /// already moved to Closed, and the subscription flow's own
    /// `InvalidTransition` when it names one that has already ended.
    pub fn receive_subscribe_update(&mut self, msg: &SubscribeUpdate) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        if let Some(sub) = self.inbound_subscribes.get_mut(&id) {
            sub.state.on_subscribe_update_received()?;
            return Ok(());
        }
        // The close is over an identifier "that has not existed within the
        // Session", which is wider than *no subscription the peer opened*:
        // every request this session has carried has existed. Only a
        // subscription the peer opened has a transition for an update, so for
        // the rest the message is accepted and the state left alone - which is
        // also what a PUBLISH-established subscription needs, since Section
        // 8.10 counts the parameters set in PUBLISH_OK among the ones an
        // update may change.
        let existed = self.subscriptions.contains_key(&id)
            || self.inbound_publishes.contains_key(&id)
            || self.fetches.contains_key(&id)
            || self.subscribe_announces.contains_key(&id)
            || self.announces.contains_key(&id)
            || self.track_statuses.contains_key(&id);
        if existed {
            return Ok(());
        }
        Err(self.fail_session(EndpointError::UpdateForUnknownRequest(id)))
    }

    /// Process an incoming SUBSCRIBE_DONE (subscriber side - publisher
    /// finished).
    ///
    /// Section 4.1 gives the publisher this for a subscription that came
    /// either way round, so one the peer opened with PUBLISH ends here too.
    pub fn receive_subscribe_done(&mut self, msg: &SubscribeDone) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        if let Some(mut sm) = self.subscription(id) {
            sm.on_subscribe_done()?;
            return Ok(());
        }
        let entry = self.inbound_publishes.get(&id).ok_or(EndpointError::UnknownRequest(id))?;
        entry.flow().on_subscribe_done_received()?;
        Ok(())
    }

    // ── Answering a SUBSCRIBE the peer sent ────────────────────

    /// Process an incoming SUBSCRIBE, recording the subscription it opens.
    ///
    /// The Request ID has already been checked by [`Self::receive_request`],
    /// which every request message passes through before its own handler.
    /// There is no Track Alias to judge here: Section 8.8 carries it in the
    /// SUBSCRIBE_OK, so this endpoint chooses it, and it is judged when the
    /// answer is built.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the
    /// subscription flow's own `InvalidTransition` for a second SUBSCRIBE
    /// under a Request ID already carrying one.
    pub fn receive_subscribe(&mut self, msg: &Subscribe) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let id = msg.request_id.into_inner();
        let mut state = SubscriptionStateMachine::new();
        state.on_subscribe_received()?;
        self.inbound_subscribes.insert(id, InboundSubscribe { message: msg.clone(), state });
        Ok(())
    }

    /// The SUBSCRIBE the peer sent under `request_id` and this endpoint has
    /// not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session
    /// has no inbound subscription for. The record itself lives on for as long
    /// as the session does, which is what lets an update say whether the
    /// request it names has ever existed.
    pub fn pending_subscribe(&self, request_id: VarInt) -> Option<&Subscribe> {
        self.inbound_subscribes
            .get(&request_id.into_inner())
            .filter(|s| s.state.state() == SubscriptionState::Subscribing)
            .map(|s| &s.message)
    }

    /// How many SUBSCRIBEs the peer has sent that are still waiting for an
    /// answer.
    pub fn pending_subscribe_count(&self) -> usize {
        self.inbound_subscribes
            .values()
            .filter(|s| s.state.state() == SubscriptionState::Subscribing)
            .count()
    }

    /// Build the SUBSCRIBE_OK accepting a subscription the peer opened, giving
    /// its track a Track Alias.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no subscription
    /// under that identifier, [`EndpointError::TrackAliasInUse`] if a live
    /// track of this endpoint's already holds the alias, and
    /// [`EndpointError::Subscription`] if the request has already been
    /// answered.
    pub fn send_subscribe_ok(
        &mut self,
        request_id: VarInt,
        track_alias: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let alias = track_alias.into_inner();
        let sub = self.inbound_subscribes.get(&id).ok_or(EndpointError::UnknownRequest(id))?;
        let namespace = sub.message.track_namespace.clone();
        let name = sub.message.track_name.clone();
        if let Some(refusal) = self.alias_held_elsewhere(alias, &namespace, &name) {
            return Err(refusal);
        }
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_subscribe_ok_sent()?;
        self.track_bindings.insert(
            id,
            TrackBinding { namespace, name, alias: Some(alias), kind: BindingKind::PeerSubscribe },
        );
        Ok(ControlMessage::SubscribeOk(SubscribeOk {
            request_id,
            track_alias,
            expires,
            group_order,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters,
        }))
    }

    /// Build the SUBSCRIBE_ERROR rejecting a subscription the peer opened.
    ///
    /// No Track Alias goes back with it. This draft moved the field out of
    /// SUBSCRIBE_ERROR along with the retry the earlier ones offered, so a
    /// refusal here says only that the request failed.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it has
    /// already been answered.
    pub fn send_subscribe_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_subscribe_error_sent()?;
        Ok(ControlMessage::SubscribeError(SubscribeError { request_id, error_code, reason_phrase }))
    }

    /// Build the SUBSCRIBE_DONE ending a subscription this endpoint publishes,
    /// whichever of the two sequences opened it.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if this session is carrying no such
    /// subscription under that identifier, [`EndpointError::Subscription`] if
    /// it is one the peer opened and this endpoint has not accepted or has
    /// already ended, and [`EndpointError::PublishFlow`] for the same of one
    /// this endpoint opened.
    pub fn send_subscribe_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        stream_count: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        // Section 4.1 gives this message to the publisher for a subscription
        // that came either way round - "Once either of these sequences is
        // successful, the subscription can be ... terminated by the publisher
        // using SUBSCRIBE_DONE" - so one this endpoint opened with PUBLISH
        // ends here too. Two records, one message.
        if let Some(state) = self.publishes.get_mut(&id) {
            state.on_subscribe_done_sent()?;
            return Ok(ControlMessage::SubscribeDone(SubscribeDone {
                request_id,
                status_code,
                stream_count,
                reason_phrase,
            }));
        }
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_subscribe_done_sent()?;
        Ok(ControlMessage::SubscribeDone(SubscribeDone {
            request_id,
            status_code,
            stream_count,
            reason_phrase,
        }))
    }

    /// Process an incoming UNSUBSCRIBE, ending a subscription this endpoint
    /// publishes and freeing the Track Alias it held.
    ///
    /// Section 8.11: "A subscriber issues a UNSUBSCRIBE message to a publisher
    /// indicating it is no longer interested in receiving media for the
    /// specified track and requesting that the publisher stop sending Objects
    /// as soon as possible." The message travels from subscriber to publisher,
    /// so what it can end is whatever this endpoint publishes - and Section
    /// 4.1 gives that two sources, not one: "A subscription can be initiated
    /// by either a publisher or a subscriber."
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if this endpoint publishes no
    /// subscription under that identifier, [`EndpointError::Subscription`] if
    /// it is one the peer opened that this endpoint never accepted or has
    /// already ended, and [`EndpointError::PublishFlow`] for the same of one
    /// this endpoint opened.
    pub fn receive_unsubscribe(&mut self, msg: &Unsubscribe) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // The offers this endpoint made itself. A PUBLISH the *peer* made is
        // not here and must not be: this endpoint is the subscriber of that
        // one, so an UNSUBSCRIBE naming it would be the publisher ending a
        // subscription the sentence above gives the subscriber, and the miss
        // below is the right answer for it.
        if let Some(state) = self.publishes.get_mut(&id) {
            state.on_unsubscribe_received()?;
            return Ok(());
        }
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_unsubscribe_received()?;
        Ok(())
    }

    // ── Fetch flow ─────────────────────────────────────────────

    /// Send a standalone FETCH message. Allocates a request ID and creates a
    /// fetch state machine.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
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

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority,
            group_order,
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

    /// Send a Relative Joining Fetch (Fetch Type 0x2), attaching a fetch to a
    /// subscription this session already holds. Allocates a Request ID.
    ///
    /// Section 8.16 calls it "A Fetch joined together with a Subscribe by
    /// specifying the Request ID of an active subscription and a relative
    /// starting offset", and has "A publisher receiving a Joining Fetch uses
    /// properties of the associated Subscribe to determine the Track
    /// Namespace, Track, Start Location, and End Location such that it is
    /// contiguous with the associated Subscribe." So a joining fetch names
    /// neither the namespace nor the name, and `joining_start` is read against
    /// the subscription rather than against the track: Section 8.16.1 has the
    /// publisher set "Fetch Start Location: {Subscribe Largest
    /// Location.Group - Joining Start, 0}", which makes it a count of groups
    /// back from the live edge.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the
    /// request-id error when this endpoint has no identifier left to spend. A
    /// Request ID naming no subscription is not refused here — Section 8.16
    /// answers that at the publisher, "it MUST respond with a Fetch Error with
    /// code Invalid Joining Request ID", and this endpoint is the subscriber.
    /// The code is 0x7 whichever of its two names is read: the FETCH_ERROR
    /// table in Section 8.18 lists it under the name above and then describes
    /// it one line down as Invalid Joining Subscribe ID.
    pub fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            FetchType::RelativeJoining,
            subscriber_priority,
            group_order,
            joining_request_id,
            joining_start,
            parameters,
        )
    }

    /// Send an Absolute Joining Fetch (Fetch Type 0x3).
    ///
    /// Section 8.16.2 is the whole of the difference: "Identical to the
    /// Relative Joining fetch except that Fetch Start Location.Group is the
    /// Joining Start value." So `joining_start` is the group to begin at
    /// rather than a count of groups back, which is what an application that
    /// knows the group it wants actually has. Asking for the same range
    /// relatively would need the Largest Location, and a subscriber that has
    /// not yet been told one cannot compute the offset.
    ///
    /// # Errors
    ///
    /// As [`Endpoint::joining_fetch`].
    pub fn absolute_joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            FetchType::AbsoluteJoining,
            subscriber_priority,
            group_order,
            joining_request_id,
            joining_start,
            parameters,
        )
    }

    /// What both calls above are, and why neither of them takes the type.
    ///
    /// Section 8.16 admits three Fetch Types and this payload carries two of
    /// them. A type taken as an argument here would leave a third value a
    /// caller could pass and this call would have to answer for; naming the
    /// two rules it out instead, so there is no answer left to get wrong.
    fn joining_fetch_of_type(
        &mut self,
        fetch_type: FetchType,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority,
            group_order,
            fetch_type,
            fetch_payload: FetchPayload::Joining { joining_request_id, joining_start },
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming FETCH_OK.
    pub fn receive_fetch_ok(&mut self, msg: &message::FetchOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    /// Process an incoming FETCH_ERROR.
    pub fn receive_fetch_error(&mut self, msg: &message::FetchError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_error()?;
        Ok(())
    }

    /// Send a FETCH_CANCEL message.
    pub fn fetch_cancel(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_cancel()?;
        Ok(ControlMessage::FetchCancel(FetchCancel { request_id }))
    }

    /// Notify that a fetch data stream received FIN.
    ///
    /// It may arrive before the FETCH_OK or FETCH_ERROR answering the
    /// request, which leaves the fetch in `FetchState::Unanswered` until the
    /// answer lands.
    pub fn on_fetch_stream_fin(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    /// Notify that a fetch data stream was reset.
    ///
    /// As with a FIN, it may arrive before the answer to the request.
    pub fn on_fetch_stream_reset(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // ── Answering a FETCH the peer sent ────────────────────────

    /// Process an incoming FETCH, recording the fetch it opens.
    ///
    /// The Request ID has already been checked by [`Self::receive_request`],
    /// which every request message passes through before its own handler.
    ///
    /// A Joining Fetch is recorded like any other. Section 8.16 answers one
    /// naming a subscription this session cannot join with a refusal and not
    /// a session close, and a refusal is a message this endpoint has to
    /// build, so the request it refuses has to be on record first.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the fetch
    /// flow's own `InvalidTransition` for a second FETCH under an identifier
    /// already carrying one.
    pub fn receive_fetch(&mut self, msg: &Fetch) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let id = msg.request_id.into_inner();
        let unjoinable = self.joining_subscription_missing(msg);
        let mut state = FetchStateMachine::new();
        state.on_fetch_received()?;
        self.inbound_fetches.insert(id, InboundFetch { message: msg.clone(), state, unjoinable });
        Ok(())
    }

    /// The FETCH the peer sent under `request_id` and this endpoint has not
    /// answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session
    /// has no inbound fetch for. The record itself lives on past the answer,
    /// because the fetch is not over until its data stream is.
    pub fn pending_fetch(&self, request_id: VarInt) -> Option<&Fetch> {
        self.inbound_fetches
            .get(&request_id.into_inner())
            .filter(|f| matches!(f.state.state(), FetchState::Pending | FetchState::Unanswered))
            .map(|f| &f.message)
    }

    /// How many FETCHes the peer has sent that are still waiting for an
    /// answer.
    pub fn pending_fetch_count(&self) -> usize {
        self.inbound_fetches
            .values()
            .filter(|f| matches!(f.state.state(), FetchState::Pending | FetchState::Unanswered))
            .count()
    }

    /// The identifier an arriving Joining Fetch names, when this session has
    /// no subscription it may join.
    ///
    /// Section 8.16:
    /// "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to an existing Subscribe in the same session, it
    /// MUST respond with a Fetch Error with code Invalid Joining Request ID."
    ///
    /// The verdict is taken as the FETCH arrives, because that is the moment
    /// the sentence names, and it is kept. A subscription that ends between
    /// the FETCH and its answer does not turn a fetch that could be joined
    /// into one that could not.
    ///
    /// A standalone fetch names none and answers `None`, and so does a joining
    /// one whose subscription is live. The subscription is one the peer opened,
    /// because the peer is the end that fetches and this endpoint is the one
    /// answering.
    /// "Existing" is read as "has not ended". Draft-16 Section 9.16.2 states
    /// the same rule with the states named - "in the Established or Pending
    /// (subscriber) states" - which is the same set read the same way.
    fn joining_subscription_missing(&self, msg: &Fetch) -> Option<u64> {
        let message::FetchPayload::Joining { joining_request_id: joined, .. } = &msg.fetch_payload
        else {
            return None;
        };
        let joined = joined.into_inner();
        let live = self
            .inbound_subscribes
            .get(&joined)
            .is_some_and(|s| s.state.state() != SubscriptionState::Done);
        if live {
            None
        } else {
            Some(joined)
        }
    }

    /// Build the FETCH_OK accepting a fetch the peer opened.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no fetch under
    /// that identifier, [`EndpointError::UnjoinableSubscription`] for a
    /// Joining Fetch naming a subscription this session cannot join, and the
    /// fetch flow's own `InvalidTransition` for a second answer: Section 4.1
    /// says the publisher "MUST send exactly one FETCH_OK or FETCH_ERROR in
    /// response to a FETCH".
    pub fn send_fetch_ok(
        &mut self,
        request_id: VarInt,
        group_order: GroupOrder,
        end_of_track: u8,
        end_location: Location,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let unjoinable =
            self.inbound_fetches.get(&id).ok_or(EndpointError::UnknownRequest(id))?.unjoinable;
        if let Some(joining) = unjoinable {
            return Err(EndpointError::UnjoinableSubscription { fetch: id, joining });
        }
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        fetch.state.on_fetch_ok_sent()?;
        Ok(ControlMessage::FetchOk(message::FetchOk {
            request_id,
            group_order,
            end_of_track,
            end_location,
            parameters,
        }))
    }

    /// Build the FETCH_ERROR refusing a fetch the peer opened.
    ///
    /// Section 8.16 names the code a Joining Fetch naming an unjoinable
    /// subscription is refused with, so that refusal cannot go out under any
    /// other: a subscriber told the wrong reason retries the wrong thing.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no fetch under
    /// that identifier, and the fetch flow's own `InvalidTransition` if it has
    /// already been answered.
    pub fn send_fetch_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        if fetch.unjoinable.is_some() {
            let required = FetchErrorCode::InvalidJoiningRequestId as u64;
            if error_code.into_inner() != required {
                return Err(EndpointError::WrongJoiningRefusal { fetch: id, required });
            }
        }
        fetch.state.on_fetch_error_sent()?;
        Ok(ControlMessage::FetchError(message::FetchError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming FETCH_CANCEL, ending the fetch the peer opened.
    ///
    /// Section 8.19: the subscriber sends it to stop a fetch it no longer
    /// wants, so the record this endpoint serves the fetch from is the one it
    /// ends.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no fetch under
    /// that identifier, and the fetch flow's own `InvalidTransition` for a fetch
    /// that has already ended.
    pub fn receive_fetch_cancel(&mut self, msg: &FetchCancel) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        fetch.state.on_fetch_cancel_received()?;
        Ok(())
    }

    /// Note that this endpoint finished the data stream serving a fetch the
    /// peer opened.
    ///
    /// A fetch is over when its answer and its data stream have both settled,
    /// and this is the second of those for the end that serves it.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no fetch under
    /// that identifier, and the fetch flow's own `InvalidTransition` from a state
    /// the stream cannot close from.
    pub fn on_peer_fetch_stream_fin(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        fetch.state.on_stream_fin_sent()?;
        Ok(())
    }

    // ── Subscribe Announces flow ───────────────────────────────

    /// Send a SUBSCRIBE_ANNOUNCES message. Returns the allocated request ID
    /// alongside the control message so the caller can correlate replies.
    ///
    /// Section 8.27 addresses the first half of the overlap rule to this end
    /// of the session: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session." So a prefix overlapping one this
    /// endpoint has already asked about is refused here rather than built and
    /// sent for the peer to refuse.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established,
    /// [`EndpointError::OwnPrefixOverlap`] when the prefix overlaps one this
    /// endpoint is already subscribed to, and the Request ID allocator's own
    /// error when the peer has granted no room for another request.
    pub fn subscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        // The subscriber's half of the rule, refused before the message
        // exists. A publisher that follows this draft answers it with a
        // refusal, so building it spends a Request ID on a namespace
        // subscription that is not going to open.
        if let Some(established) = self.own_prefix_overlap(&track_namespace_prefix) {
            return Err(EndpointError::OwnPrefixOverlap { established });
        }
        let req_id = self.request_ids.allocate()?;
        let key = track_namespace_prefix.0.clone();
        let mut sm = SubscribeAnnouncesStateMachine::new();
        sm.on_subscribe_announces_sent()?;
        self.subscribe_announces.insert(req_id.into_inner(), sm);
        self.subscribe_announces_ids.insert(key, req_id.into_inner());
        Ok((
            req_id,
            ControlMessage::SubscribeAnnounces(SubscribeAnnounces {
                request_id: req_id,
                track_namespace_prefix,
                parameters,
            }),
        ))
    }

    /// Process an incoming SUBSCRIBE_ANNOUNCES_OK.
    pub fn receive_subscribe_announces_ok(
        &mut self,
        msg: &SubscribeAnnouncesOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_announces_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ANNOUNCES_ERROR.
    pub fn receive_subscribe_announces_error(
        &mut self,
        msg: &SubscribeAnnouncesError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_announces_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE_ANNOUNCES message.
    pub fn unsubscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id = *self
            .subscribe_announces_ids
            .get(&track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.subscribe_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe_announces()?;
        Ok(ControlMessage::UnsubscribeAnnounces(UnsubscribeAnnounces { track_namespace_prefix }))
    }

    // ── Answering a SUBSCRIBE_ANNOUNCES the peer sent ──────────

    /// Process an incoming SUBSCRIBE_ANNOUNCES, recording the namespace
    /// subscription it opens.
    ///
    /// Section 8.27: "The subscriber sends the SUBSCRIBE_ANNOUNCES control
    /// message to a publisher to request the current set of matching
    /// announcements and established subscriptions, as well as future updates
    /// to the set."
    ///
    /// The set it asks for is this endpoint's to decide, and deciding needs
    /// both the request and somewhere to answer from. The record holds the
    /// message and not only its state, because every message that answers
    /// this request or ends it names the prefix the request carried, and
    /// nothing else here has it.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established.
    pub fn receive_subscribe_announces(
        &mut self,
        msg: &SubscribeAnnounces,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let overlaps = self.peer_prefix_overlap(&msg.track_namespace_prefix);
        let mut state = SubscribeAnnouncesStateMachine::new();
        state.on_subscribe_announces_received()?;
        self.inbound_subscribe_announces.insert(
            msg.request_id.into_inner(),
            InboundSubscribeAnnounces { message: msg.clone(), state, overlaps },
        );
        Ok(())
    }

    /// The earliest namespace subscription the peer has made whose prefix
    /// overlaps `prefix`, and `None` when there is none.
    ///
    /// Only ones that have not ended count: the sentence weighs the arriving
    /// prefix against "an active SUBSCRIBE_ANNOUNCES", so one the peer has
    /// withdrawn and one this endpoint refused are both past. Drafts 07
    /// through 11 say "an earlier" instead and count those too.
    ///
    /// One that has arrived and has not been answered does count. It is not
    /// active yet, but this endpoint is the one about to make it so, and
    /// accepting both would leave the session holding exactly the pair the
    /// sentence exists to prevent.
    ///
    /// Namespace subscriptions this endpoint made are a separate set and are
    /// not consulted. This endpoint is the subscriber for those, so a prefix
    /// it asked about says nothing about what the peer may ask about.
    ///
    /// The lowest Request ID wins when more than one overlaps, so the answer
    /// does not depend on the order a map happens to iterate in. Identifiers
    /// are handed out in increasing order, so the lowest of them is the
    /// earliest request.
    fn peer_prefix_overlap(&self, prefix: &TrackNamespace) -> Option<u64> {
        self.inbound_subscribe_announces
            .iter()
            .filter(|(_, s)| s.state.state() != SubscribeAnnouncesState::Done)
            .filter_map(|(&id, s)| {
                prefixes_overlap(&s.message.track_namespace_prefix.0, &prefix.0).then_some(id)
            })
            .min()
    }

    /// The earliest namespace subscription **this endpoint** has made whose
    /// prefix overlaps `prefix`, and `None` when there is none.
    ///
    /// The subscriber's half of the same sentence reads over this endpoint's
    /// own requests, and takes the same view of which of them are past as
    /// [`Self::peer_prefix_overlap`] takes of the peer's.
    fn own_prefix_overlap(&self, prefix: &TrackNamespace) -> Option<u64> {
        self.subscribe_announces_ids
            .iter()
            .filter_map(|(key, &id)| prefixes_overlap(key, &prefix.0).then_some(id))
            .filter(|id| {
                self.subscribe_announces
                    .get(id)
                    .is_some_and(|sm| sm.state() != SubscribeAnnouncesState::Done)
            })
            .min()
    }

    /// The SUBSCRIBE_ANNOUNCES the peer sent under `request_id` and this
    /// endpoint has not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier the peer has
    /// subscribed to nothing under. The record itself lives on past the
    /// answer, because a namespace subscription that was accepted is not over
    /// until it is withdrawn.
    pub fn pending_subscribe_announces(&self, request_id: VarInt) -> Option<&SubscribeAnnounces> {
        self.inbound_subscribe_announces
            .get(&request_id.into_inner())
            .filter(|s| s.state.state() == SubscribeAnnouncesState::Pending)
            .map(|s| &s.message)
    }

    /// How many namespace subscriptions the peer has made that are still
    /// waiting for an answer.
    pub fn pending_subscribe_announces_count(&self) -> usize {
        self.inbound_subscribe_announces
            .values()
            .filter(|s| s.state.state() == SubscribeAnnouncesState::Pending)
            .count()
    }

    /// The identifier of a live namespace subscription the peer made for
    /// `prefix`.
    ///
    /// Section 8.30 names a Track Namespace Prefix where the
    /// SUBSCRIBE_ANNOUNCES it ends named a Request ID, so one record has to
    /// be reachable both ways. It is stored under the identifier, which is
    /// unique, and found by prefix with a scan of the same map. A second map
    /// from prefix to identifier would be quicker and could fall out of step
    /// with the first; there is nothing here for it to disagree with.
    ///
    /// One that has ended is skipped, so a prefix subscribed again after
    /// being withdrawn finds the live one.
    fn inbound_subscribe_announces_id(&self, prefix: &TrackNamespace) -> Option<u64> {
        self.inbound_subscribe_announces
            .iter()
            .find(|(_, s)| {
                s.message.track_namespace_prefix == *prefix
                    && s.state.state() != SubscribeAnnouncesState::Done
            })
            .map(|(id, _)| *id)
    }

    /// Build the SUBSCRIBE_ANNOUNCES_OK accepting a namespace subscription
    /// the peer made.
    ///
    /// Section 5.1: "A publisher MUST send exactly one SUBSCRIBE_ANNOUNCES_OK
    /// or SUBSCRIBE_ANNOUNCES_ERROR in response to a SUBSCRIBE_ANNOUNCES."
    ///
    /// One answer and no second one: the flow moves on the first, and a
    /// second call finds a record that has left Pending.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has subscribed to
    /// nothing under that identifier, [`EndpointError::PeerPrefixOverlap`] if
    /// the prefix it asked about overlaps one the peer is already subscribed
    /// to, and the namespace flow's own `InvalidTransition` for a request
    /// already answered.
    pub fn send_subscribe_announces_ok(
        &mut self,
        request_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self
            .inbound_subscribe_announces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        // The MUST names one answer for this request, and it is not this one.
        if let Some(established) = sub.overlaps {
            return Err(EndpointError::PeerPrefixOverlap { request: id, established });
        }
        sub.state.on_subscribe_announces_ok_sent()?;
        Ok(ControlMessage::SubscribeAnnouncesOk(SubscribeAnnouncesOk { request_id }))
    }

    /// Build the SUBSCRIBE_ANNOUNCES_ERROR refusing a namespace subscription
    /// the peer made.
    ///
    /// The other half of the same sentence: one message back, whichever of
    /// the two it is.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has subscribed to
    /// nothing under that identifier, [`EndpointError::WrongOverlapRefusal`]
    /// if the request overlaps another and the code named is not the one the
    /// draft assigns to that refusal, and the namespace flow's own
    /// `InvalidTransition` for a request already answered.
    pub fn send_subscribe_announces_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self
            .inbound_subscribe_announces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        if sub.overlaps.is_some() {
            let required = SubscribeAnnouncesErrorCode::NamespacePrefixOverlap as u64;
            if error_code.into_inner() != required {
                return Err(EndpointError::WrongOverlapRefusal { request: id, required });
            }
        }
        sub.state.on_subscribe_announces_error_sent()?;
        Ok(ControlMessage::SubscribeAnnouncesError(SubscribeAnnouncesError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming UNSUBSCRIBE_ANNOUNCES, ending the namespace
    /// subscription the peer made.
    ///
    /// Section 5.1: "An UNSUBSCRIBE_ANNOUNCES withdraws a previous
    /// SUBSCRIBE_ANNOUNCES."
    ///
    /// The subscription it ends is the peer's, so the record it reads is the
    /// one this endpoint keeps of what the peer subscribed to. One this
    /// endpoint made is withdrawn by [`Endpoint::unsubscribe_announces`],
    /// which is the same message travelling the other way.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespaceSubscription`] if the peer has no
    /// live namespace subscription for that prefix, and the namespace flow's
    /// own `InvalidTransition` for one this endpoint never accepted.
    pub fn receive_unsubscribe_announces(
        &mut self,
        msg: &UnsubscribeAnnounces,
    ) -> Result<(), EndpointError> {
        let id = self
            .inbound_subscribe_announces_id(&msg.track_namespace_prefix)
            .ok_or(EndpointError::UnknownPeerNamespaceSubscription)?;
        let sub = self
            .inbound_subscribe_announces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_unsubscribe_announces_received()?;
        Ok(())
    }

    // ── Announce flow ──────────────────────────────────────────

    /// Send an ANNOUNCE message. Returns the allocated request ID alongside
    /// the control message.
    pub fn announce(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let key = track_namespace.0.clone();
        let mut sm = AnnounceStateMachine::new();
        sm.on_announce_sent()?;
        self.announces.insert(req_id.into_inner(), sm);
        self.announce_ids.insert(key, req_id.into_inner());
        Ok((
            req_id,
            ControlMessage::Announce(Announce { request_id: req_id, track_namespace, parameters }),
        ))
    }

    /// Process an incoming ANNOUNCE_OK.
    pub fn receive_announce_ok(&mut self, msg: &AnnounceOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_announce_ok()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_ERROR.
    pub fn receive_announce_error(&mut self, msg: &AnnounceError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_announce_error()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_CANCEL.
    pub fn receive_announce_cancel(&mut self, msg: &AnnounceCancel) -> Result<(), EndpointError> {
        let id = *self
            .announce_ids
            .get(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_announce_cancel()?;
        Ok(())
    }

    /// Send an UNANNOUNCE message (publisher withdrawing).
    pub fn unannounce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id =
            *self.announce_ids.get(&track_namespace.0).ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unannounce()?;
        Ok(ControlMessage::Unannounce(Unannounce { track_namespace }))
    }

    // ── Answering an ANNOUNCE the peer sent ────────────────────

    /// Process an incoming ANNOUNCE, recording the announcement it makes.
    ///
    /// Section 8.22: "The publisher sends the ANNOUNCE control message to
    /// advertise that it has tracks available within the announced Track
    /// Namespace. The receiver verifies the publisher is authorized to publish
    /// tracks under this namespace."
    ///
    /// Verifying is the application's to do, and it needs both the message to
    /// verify and somewhere to answer from. The Request ID has already been
    /// checked by [`Self::receive_request`], which every request message passes
    /// through before its own handler, so a repeat of one the peer has already
    /// spent never reaches here.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established.
    pub fn receive_announce(&mut self, msg: &Announce) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let id = msg.request_id.into_inner();
        let mut state = AnnounceStateMachine::new();
        state.on_announce_received()?;
        self.inbound_announces.insert(id, InboundAnnounce { message: msg.clone(), state });
        Ok(())
    }

    /// The ANNOUNCE the peer sent under `request_id` and this endpoint has not
    /// answered yet.
    ///
    /// `None` once it has been answered, and for an identifier the peer has
    /// announced nothing under. The record itself lives on past the answer,
    /// because an announcement that was accepted is not over until it is
    /// withdrawn or cancelled.
    pub fn pending_announce(&self, request_id: VarInt) -> Option<&Announce> {
        self.inbound_announces
            .get(&request_id.into_inner())
            .filter(|a| a.state.state() == AnnounceState::Pending)
            .map(|a| &a.message)
    }

    /// How many announcements the peer has made that are still waiting for an
    /// answer.
    pub fn pending_announce_count(&self) -> usize {
        self.inbound_announces
            .values()
            .filter(|a| a.state.state() == AnnounceState::Pending)
            .count()
    }

    /// The identifier of a live announcement the peer made for `namespace`.
    ///
    /// Section 8.25: "The publisher sends the UNANNOUNCE control message to
    /// indicate its intent to stop serving new subscriptions for tracks within
    /// the provided Track Namespace." and Section 8.26 says what a cancellation
    /// is for: the subscriber "will stop sending new subscriptions for tracks
    /// within the provided Track Namespace". Both name a namespace where the
    /// ANNOUNCE they are about named a Request ID, so one record has to be
    /// reachable both ways.
    ///
    /// It is stored under the identifier, which is unique, and found by
    /// namespace with a scan of the same map. A second map from namespace to
    /// identifier would be quicker and could fall out of step with the first;
    /// there is nothing here for it to disagree with.
    ///
    /// An announcement that has ended is skipped, so a namespace announced
    /// again after being withdrawn finds the live one. Which of two live
    /// announcements for the same namespace is found is not decided here,
    /// because no sentence in the draft makes a second one for a namespace
    /// already announced an error.
    fn inbound_announce_id(&self, namespace: &TrackNamespace) -> Option<u64> {
        self.inbound_announces
            .iter()
            .find(|(_, a)| {
                a.message.track_namespace == *namespace && a.state.state() != AnnounceState::Done
            })
            .map(|(id, _)| *id)
    }

    /// Build the ANNOUNCE_OK accepting an announcement the peer made.
    ///
    /// Section 5.2: "A subscriber MUST send exactly one ANNOUNCE_OK or
    /// ANNOUNCE_ERROR in response to an ANNOUNCE. The publisher SHOULD close
    /// the session with a protocol error if it receives more than one."
    ///
    /// One answer and no second one: the flow moves on the first, and a second
    /// call finds a record that has left Pending.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has announced nothing
    /// under that identifier, and the namespace flow's own `InvalidTransition`
    /// for an announcement already answered.
    pub fn send_announce_ok(
        &mut self,
        request_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let ann = self.inbound_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_announce_ok_sent()?;
        Ok(ControlMessage::AnnounceOk(AnnounceOk { request_id }))
    }

    /// Build the ANNOUNCE_ERROR refusing an announcement the peer made.
    ///
    /// The same sentence in Section 5.2 answers both ways: one message back and
    /// no second one, whichever of the two it is.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has announced nothing
    /// under that identifier, and the namespace flow's own `InvalidTransition`
    /// for an announcement already answered.
    pub fn send_announce_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let ann = self.inbound_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_announce_error_sent()?;
        Ok(ControlMessage::AnnounceError(AnnounceError { request_id, error_code, reason_phrase }))
    }

    /// Process an incoming UNANNOUNCE, ending the announcement the peer made.
    ///
    /// Section 8.25: "The publisher sends the UNANNOUNCE control message to
    /// indicate its intent to stop serving new subscriptions for tracks within
    /// the provided Track Namespace."
    ///
    /// The announcement it ends is the peer's, so the record it reads is the
    /// one this endpoint keeps of what the peer announced. An announcement this
    /// endpoint made is withdrawn by [`Self::unannounce`], which is the same
    /// message travelling the other way.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespace`] if the peer has no live
    /// announcement for that namespace, and the namespace flow's own
    /// `InvalidTransition` for one this endpoint never accepted.
    pub fn receive_unannounce(&mut self, msg: &Unannounce) -> Result<(), EndpointError> {
        let id = self
            .inbound_announce_id(&msg.track_namespace)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        let ann = self.inbound_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_unannounce_received()?;
        Ok(())
    }

    /// Build the ANNOUNCE_CANCEL revoking an acceptance.
    ///
    /// Section 7.3 names what a cancellation revokes: a namespace "it
    /// previously responded ANNOUNCE_OK to". Section 8.26 says what it does:
    /// the subscriber "will stop sending new subscriptions for tracks within
    /// the provided Track Namespace".
    ///
    /// Previously responded ANNOUNCE_OK to is a state, and it is Active: an
    /// announcement reaches it by being accepted and no other way. One still
    /// waiting for an answer, one refused and one already ended are all refused
    /// here rather than sent.
    ///
    /// The announcement is the peer's. An announcement this endpoint made is
    /// not cancelled by its own publisher; the peer cancels it, and that
    /// arrives at [`Self::receive_announce_cancel`].
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespace`] if the peer has no live
    /// announcement for that namespace, and the namespace flow's own
    /// `InvalidTransition` for one this endpoint never accepted.
    pub fn announce_cancel(
        &mut self,
        track_namespace: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = self
            .inbound_announce_id(&track_namespace)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        let ann = self.inbound_announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_announce_cancel_sent()?;
        Ok(ControlMessage::AnnounceCancel(AnnounceCancel {
            track_namespace,
            error_code,
            reason_phrase,
        }))
    }

    // ── Track Status flow ──────────────────────────────────────

    /// Send a TRACK_STATUS_REQUEST message. Returns the allocated request ID
    /// alongside the control message so the caller can correlate replies.
    pub fn track_status_request(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_request_sent()?;
        self.track_statuses.insert(req_id.into_inner(), sm);
        Ok((
            req_id,
            ControlMessage::TrackStatusRequest(TrackStatusRequest {
                request_id: req_id,
                track_namespace,
                track_name,
                parameters,
            }),
        ))
    }

    /// Process an incoming TRACK_STATUS reply.
    pub fn receive_track_status(&mut self, msg: &TrackStatus) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status()?;
        Ok(())
    }

    // ── Answering a TRACK_STATUS_REQUEST the peer sent ─────────

    /// Process an incoming TRACK_STATUS_REQUEST, recording what the peer asked
    /// about.
    ///
    /// Section 8.20: "A potential subscriber sends a 'TRACK_STATUS_REQUEST'
    /// message on the control stream to obtain information about the current
    /// status of a given track."
    ///
    /// Answering is the application's to do, and it needs both the request and
    /// somewhere to answer from. This draft gave the request a Request ID, so
    /// that is what the record is filed under and what the answer names.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established.
    pub fn receive_track_status_request(
        &mut self,
        msg: &TrackStatusRequest,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let id = msg.request_id.into_inner();
        let mut state = TrackStatusStateMachine::new();
        state.on_track_status_request_received()?;
        self.inbound_track_statuses.insert(id, InboundTrackStatus { message: msg.clone(), state });
        Ok(())
    }

    /// The TRACK_STATUS_REQUEST the peer sent under `request_id` and this
    /// endpoint has not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session has
    /// carried no track status request under.
    pub fn pending_track_status_request(&self, request_id: VarInt) -> Option<&TrackStatusRequest> {
        self.inbound_track_statuses
            .get(&request_id.into_inner())
            .filter(|t| t.state.state() == TrackStatusState::Pending)
            .map(|t| &t.message)
    }

    /// How many track statuses the peer has asked about that are still waiting
    /// for an answer.
    pub fn pending_track_status_request_count(&self) -> usize {
        self.inbound_track_statuses
            .values()
            .filter(|t| t.state.state() == TrackStatusState::Pending)
            .count()
    }

    /// Build the TRACK_STATUS answering a request the peer sent.
    ///
    /// Section 8.20 leaves the answering end no discretion about whether to
    /// answer: "A TRACK_STATUS message MUST be sent in response to each
    /// TRACK_STATUS_REQUEST." What it bounds is how many, and that half is what
    /// the record carries: the request leaves `Pending` on the first answer, so
    /// a second call finds nothing left to answer.
    ///
    /// Section 8.21 says the identifier this message carries is "The Request ID
    /// of the TRACK_STATUS_REQUEST this message is replying to", which is why
    /// the answer is asked for by the identifier the request arrived under and
    /// not by the track it named.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has asked nothing under
    /// that identifier, and the flow's own `InvalidTransition` for a request
    /// already answered.
    pub fn send_track_status(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        largest_location: Location,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let req =
            self.inbound_track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        req.state.on_track_status_sent()?;
        Ok(ControlMessage::TrackStatus(TrackStatus {
            request_id,
            status_code,
            largest_location,
            parameters,
        }))
    }

    // ── Requests blocked ───────────────────────────────────────

    /// Process an incoming REQUESTS_BLOCKED message.
    ///
    /// Draft-12 renames draft-12's SUBSCRIBES_BLOCKED to REQUESTS_BLOCKED so
    /// the peer can explicitly report that a new request id would exceed our
    /// advertised maximum. The endpoint records the peer's reported maximum;
    /// acting on it (issuing a new `MAX_REQUEST_ID`) is up to the caller.
    pub fn receive_requests_blocked(&mut self, msg: &RequestsBlocked) -> Result<(), EndpointError> {
        self.peer_reported_max_request_id = Some(msg.maximum_request_id);
        Ok(())
    }

    /// The maximum request id that the peer most recently reported in a
    /// `REQUESTS_BLOCKED` message, if any.
    pub fn peer_reported_max_request_id(&self) -> Option<VarInt> {
        self.peer_reported_max_request_id
    }

    // ── Publish flow (draft-12) ────────────────────────────────

    /// Offer the peer a subscription to a track this endpoint publishes.
    /// Allocates a Request ID.
    ///
    /// Section 4.1: "A subscription can be initiated by either a publisher or
    /// a subscriber. A publisher initiates a subscription to a track by
    /// sending the PUBLISH message. The subscriber either accepts or rejects
    /// the subscription using PUBLISH_OK or PUBLISH_ERROR."
    ///
    /// There is no `content_exists` parameter because it is not a choice.
    /// Section 8.13 makes it a flag for whether the field after it is there at
    /// all - "1 if an object has been published on this track, 0 if not. If 0,
    /// then the Largest Group ID and Largest Object ID fields will not be
    /// present" - so it is derived from `largest_location`, and the pair
    /// cannot be built disagreeing.
    ///
    /// `forward` is the subscription's initial Forward State, which Section
    /// 4.1 gives to whichever end opened it: "The initiator of the
    /// subscription sets the initial Forward State in either PUBLISH or
    /// SUBSCRIBE." Section 8.13 says what the peer may then assume of it: "1
    /// indicates the publisher will start transmitting objects immediately,
    /// even before PUBLISH_OK."
    ///
    /// # Errors
    ///
    /// [`EndpointError::TrackAliasInUse`] when some live request of this
    /// session already holds `track_alias` for a different track, which
    /// Section 8.13 forbids outright - "The same Track Alias MUST NOT be used
    /// to refer to two different Tracks simultaneously" - and which the
    /// subscriber answers by closing the session. Judged before the Request ID
    /// is allocated, so a refused offer spends nothing. Also the session error
    /// when the session is not established, and the request-id error when this
    /// endpoint has no identifier left to spend.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        group_order: GroupOrder,
        largest_location: Option<Location>,
        forward: Forward,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let alias = track_alias.into_inner();
        if let Some(refusal) = self.alias_held_elsewhere(alias, &track_namespace, &track_name) {
            return Err(refusal);
        }
        let req_id = self.request_ids.allocate()?;
        let id = req_id.into_inner();
        let mut state = PublishStateMachine::new();
        state.on_publish_sent()?;
        self.publishes.insert(id, state);
        // A PUBLISH names its track and its alias in the one message, so the
        // binding is complete the moment the offer is built, and the same
        // split applies as on the arriving side: it counts against the next
        // offer this endpoint builds from here on, because that sentence is
        // unqualified, and against an arriving PUBLISH or SUBSCRIBE_OK only
        // once the peer's PUBLISH_OK has made the subscription active.
        self.track_bindings.insert(
            id,
            TrackBinding {
                namespace: track_namespace.clone(),
                name: track_name.clone(),
                alias: Some(alias),
                kind: BindingKind::Publish,
            },
        );
        let content_exists = if largest_location.is_some() {
            ContentExists::HasLargestLocation
        } else {
            ContentExists::NoLargestLocation
        };
        let msg = ControlMessage::Publish(Publish {
            request_id: req_id,
            track_namespace,
            track_name,
            track_alias,
            group_order,
            content_exists,
            largest_location,
            forward,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH message, which opens a subscription this
    /// endpoint is the subscriber of.
    ///
    /// The message is kept so the application can answer it with
    /// [`Endpoint::send_publish_ok`] or [`Endpoint::send_publish_error`] under
    /// the same request id, and the record it is kept in outlives that answer:
    /// Section 4.1 gives the subscription that follows an UNSUBSCRIBE and a
    /// SUBSCRIBE_DONE, and both name this request.
    ///
    /// # Errors
    ///
    /// [`EndpointError::DuplicateTrackAlias`] when the Track Alias offered is
    /// one a different live track already holds, which ends the session, and
    /// the publish flow's own `InvalidTransition` for a second PUBLISH under a
    /// request id already carrying one.
    pub fn receive_publish(&mut self, msg: &Publish) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        // Section 8.13 answers a PUBLISH naming an alias another live track
        // already holds with a session close, in the same words Section 8.8
        // uses for a SUBSCRIBE_OK.
        let id = msg.request_id.into_inner();
        let alias = msg.track_alias.into_inner();
        if let Some(conflict) =
            self.conflicting_track_alias(id, alias, &msg.track_namespace, &msg.track_name)
        {
            return Err(self.fail_session(conflict));
        }
        let mut state = PublishStateMachine::new();
        state.on_publish_received()?;
        self.inbound_publishes
            .insert(id, InboundPublish { message: msg.clone(), state: Mutex::new(state) });
        // A PUBLISH names its track and its alias in the one message, so the
        // binding is complete on arrival. What it counts against from here
        // depends on which of the two comparisons is asking. An offer this
        // endpoint is about to build is refused now, because the prohibition
        // is not qualified; an arriving message closes the session only once
        // this endpoint has answered PUBLISH_OK, because the half that closes
        // is qualified by "a different track with an active subscription".
        self.track_bindings.insert(
            id,
            TrackBinding {
                namespace: msg.track_namespace.clone(),
                name: msg.track_name.clone(),
                alias: Some(alias),
                kind: BindingKind::Publish,
            },
        );
        Ok(())
    }

    /// The inbound PUBLISH for a request id that is still waiting to be
    /// answered.
    ///
    /// Stops answering once the PUBLISH has been answered, which is the whole
    /// of what "pending" means: the record itself lives on for as long as the
    /// subscription does.
    pub fn pending_publish(&self, request_id: VarInt) -> Option<&Publish> {
        self.inbound_publishes
            .get(&request_id.into_inner())
            .filter(|p| p.publish_state() == PublishState::Publishing)
            .map(|p| &p.message)
    }

    /// Number of PUBLISH requests received but not yet responded to.
    pub fn pending_publish_count(&self) -> usize {
        self.inbound_publishes
            .values()
            .filter(|p| p.publish_state() == PublishState::Publishing)
            .count()
    }

    /// Generate a PUBLISH_OK response for a previously received PUBLISH,
    /// which establishes the subscription it opened.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when no PUBLISH arrived under that
    /// id, and the publish flow's own `InvalidTransition` for a second answer:
    /// Section 4.1 says "A subscriber MUST send exactly one PUBLISH_OK or
    /// PUBLISH_ERROR in response to a PUBLISH."
    #[allow(clippy::too_many_arguments)]
    pub fn send_publish_ok(
        &mut self,
        request_id: VarInt,
        forward: Forward,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: VarInt,
        start_group: Option<VarInt>,
        start_object: Option<VarInt>,
        end_group: Option<VarInt>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let entry = self.inbound_publishes.get(&id).ok_or(EndpointError::UnknownRequest(id))?;
        entry.flow().on_publish_ok_sent()?;
        Ok(ControlMessage::PublishOk(PublishOk {
            request_id,
            forward,
            subscriber_priority,
            group_order,
            filter_type,
            start_group,
            start_object,
            end_group,
            parameters: vec![],
        }))
    }

    /// Generate a PUBLISH_ERROR response for a previously received PUBLISH,
    /// which ends the subscription it opened before it was established.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when no PUBLISH arrived under that
    /// id, and the publish flow's own `InvalidTransition` for a second answer:
    /// Section 4.1 says "A subscriber MUST send exactly one PUBLISH_OK or
    /// PUBLISH_ERROR in response to a PUBLISH."
    pub fn send_publish_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let entry = self.inbound_publishes.get(&id).ok_or(EndpointError::UnknownRequest(id))?;
        entry.flow().on_publish_error_sent()?;
        Ok(ControlMessage::PublishError(PublishError { request_id, error_code, reason_phrase }))
    }

    /// Process an incoming PUBLISH_OK, which establishes the subscription this
    /// endpoint offered under that Request ID.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when this endpoint has offered
    /// nothing under that identifier, and the publish flow's own
    /// `InvalidTransition` for an offer that has been answered already:
    /// Section 4.1 says "A subscriber MUST send exactly one PUBLISH_OK or
    /// PUBLISH_ERROR in response to a PUBLISH. The peer SHOULD close the
    /// session with a protocol error if it receives more than one." The verb
    /// there is SHOULD, so the second answer is reported rather than acted on,
    /// and the caller decides.
    pub fn receive_publish_ok(&mut self, msg: &PublishOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let state = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        state.on_publish_ok()?;
        Ok(())
    }

    /// Process an incoming PUBLISH_ERROR, which ends the subscription this
    /// endpoint offered under that Request ID before it was established.
    ///
    /// Section 4.1: "Objects MUST NOT be sent for requests that end with an
    /// error." The Track Alias the offer named is free again from here,
    /// because a binding reads liveness off this record rather than keeping a
    /// second copy of it.
    ///
    /// # Errors
    ///
    /// As [`Self::receive_publish_ok`].
    pub fn receive_publish_error(&mut self, msg: &PublishError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let state = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        state.on_publish_error()?;
        Ok(())
    }

    /// Hold a Request ID a peer allocated to the rules Section 8.1 states
    /// about it.
    ///
    /// "The client's Request ID starts at 0 and are even and the server's
    /// Request ID starts at 1 and are odd. The Request ID increments by 2 ...
    /// If an endpoint receives a Request ID that is not valid for the peer, it
    /// MUST close the session with Invalid Request ID." Parity says which end
    /// may have chosen it; the ceiling this endpoint advertised says how far
    /// the peer may go.
    ///
    /// This is the call site [`Self::validate_peer_request_id`] did not have.
    /// The rule was implemented and then applied to nothing, so a peer could
    /// open requests with ids from this endpoint's own half of the space, or
    /// past the ceiling it had advertised, and neither was noticed.
    ///
    /// A message that is a response rather than a request carries the id of a
    /// request this endpoint made, so it is not checked here - it is checked by
    /// finding the state machine it names. SUBSCRIBE_UPDATE is the same case on
    /// this draft: its one Request ID field names the subscription it modifies
    /// rather than opening a request of its own, which is why Section 8.1 does
    /// not list it among the messages that step the sequence.
    ///
    /// # The list below is the rule, not a convenience
    ///
    /// Every message named here spends one of the peer's Request IDs, and
    /// nothing else does. That makes the list load-bearing in a way it was not
    /// before the sequence was tracked: a request left out of it spends an ID
    /// this endpoint never counts, so the peer's **next** request looks like a
    /// skip and a conforming session is closed over it. PUBLISH is here and
    /// not in Section 8.1's enumeration, which predates the message; its own
    /// Request ID field refers the reader to that section like every other
    /// request's does.
    ///
    /// # Errors
    ///
    /// The request-id errors, for a wrong parity, an id at or above the
    /// advertised ceiling, or one that is not the next in the peer's sequence.
    pub fn receive_request(&mut self, msg: &ControlMessage) -> Result<(), EndpointError> {
        let request_id = match msg {
            ControlMessage::Subscribe(m) => m.request_id,
            ControlMessage::Fetch(m) => m.request_id,
            ControlMessage::Announce(m) => m.request_id,
            ControlMessage::SubscribeAnnounces(m) => m.request_id,
            ControlMessage::TrackStatusRequest(m) => m.request_id,
            ControlMessage::Publish(m) => m.request_id,
            _ => return Ok(()),
        };
        self.validate_peer_request_id(request_id.into_inner())
    }

    // ── Unified message dispatch ───────────────────────────────

    /// Dispatch an incoming control message to the appropriate handler.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        self.receive_request(&msg)?;
        match msg {
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::MaxRequestId(ref m) => self.receive_max_request_id(m),
            ControlMessage::RequestsBlocked(ref m) => self.receive_requests_blocked(m),
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(m),
            ControlMessage::SubscribeError(ref m) => self.receive_subscribe_error(m),
            ControlMessage::SubscribeUpdate(ref m) => self.receive_subscribe_update(m),
            ControlMessage::SubscribeDone(ref m) => self.receive_subscribe_done(m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(m),
            ControlMessage::FetchError(ref m) => self.receive_fetch_error(m),
            ControlMessage::SubscribeAnnouncesOk(ref m) => self.receive_subscribe_announces_ok(m),
            ControlMessage::SubscribeAnnouncesError(ref m) => {
                self.receive_subscribe_announces_error(m)
            }
            ControlMessage::AnnounceOk(ref m) => self.receive_announce_ok(m),
            ControlMessage::AnnounceError(ref m) => self.receive_announce_error(m),
            ControlMessage::AnnounceCancel(ref m) => self.receive_announce_cancel(m),
            ControlMessage::TrackStatus(ref m) => self.receive_track_status(m),
            ControlMessage::TrackStatusRequest(ref m) => self.receive_track_status_request(m),
            ControlMessage::Subscribe(ref m) => self.receive_subscribe(m),
            ControlMessage::Unsubscribe(ref m) => self.receive_unsubscribe(m),
            ControlMessage::Fetch(ref m) => self.receive_fetch(m),
            ControlMessage::FetchCancel(ref m) => self.receive_fetch_cancel(m),
            ControlMessage::Publish(ref m) => self.receive_publish(m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(m),
            ControlMessage::PublishError(ref m) => self.receive_publish_error(m),
            ControlMessage::Announce(ref m) => self.receive_announce(m),
            ControlMessage::Unannounce(ref m) => self.receive_unannounce(m),
            ControlMessage::SubscribeAnnounces(ref m) => self.receive_subscribe_announces(m),
            ControlMessage::UnsubscribeAnnounces(ref m) => self.receive_unsubscribe_announces(m),
            _ => Ok(()),
        }
    }
}

#![allow(missing_docs)]
//! Draft-17 MoQT endpoint.
//!
//! Major architectural differences from earlier drafts:
//!
//! * Unified `Setup` message (no separate CLIENT_SETUP / SERVER_SETUP).
//! * Response messages (`SubscribeOk`, `PublishOk`, `FetchOk`, `PublishDone`,
//!   `RequestOk`, `RequestError`) do NOT carry a `request_id`. Each request
//!   opens its own bidirectional stream and its response arrives as the
//!   first message on that stream, so the stream itself identifies the
//!   request. The transport
//!   layer knows which `request_id` each bidi stream belongs to; callers
//!   must supply that `request_id` via `Endpoint::receive_response_on_stream`.
//! * No `Unsubscribe`, `FetchCancel`, `MaxRequestId`, `RequestsBlocked`,
//!   `PublishNamespaceDone`, or `PublishNamespaceCancel` messages.
//! * Request-producing messages (`Subscribe`, `Publish`, `Fetch`,
//!   `PublishNamespace`, `SubscribeNamespace`, `TrackStatus`, `RequestUpdate`)
//!   gain a `required_request_id_delta` field.
//! * New `PublishBlocked` message notifies subscribers a publisher is blocked.
//! * `Namespace` and `NamespaceDone` are unsolicited announcements of
//!   namespace suffixes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::draft17::fetch::{FetchError, FetchState, FetchStateMachine};
use crate::draft17::namespace::{
    NamespaceError, PublishNamespaceState, PublishNamespaceStateMachine, SubscribeNamespaceState,
    SubscribeNamespaceStateMachine,
};
use crate::draft17::publish::{
    PublishError as PublishFlowError, PublishState, PublishStateMachine,
};
use crate::draft17::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft17::session::setup::{self, SetupError};
use crate::draft17::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft17::subscription::{
    SubscriptionError, SubscriptionState, SubscriptionStateMachine,
};
use crate::draft17::track_status::{TrackStatusError, TrackStatusState, TrackStatusStateMachine};
use crate::malformed_tracks::{MalformedTrackCondition, MalformedTracks};
use crate::track_locations::{ObjectLocation, ObjectRole, TrackLocations, TrackObjects};
use moqtap_codec::draft17::error_codes::{
    PublishDoneStatusCode, RequestErrorCode, SessionErrorCode,
};
use moqtap_codec::draft17::message::{
    self, ControlMessage, Fetch, FetchPayload, FetchType, GoAway, MessageType, Publish,
    PublishBlocked, PublishDone, PublishNamespace, RequestError, RequestOk, RequestUpdate, Setup,
    Subscribe, SubscribeNamespace, SubscribeOk,
};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

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
    /// A REQUEST_UPDATE named a track status.
    ///
    /// Section 9.16: "the subscriber cannot send REQUEST_UPDATE". A track status is
    /// the one request kind that sentence excludes, and Section 9.10's list of
    /// the requests an update may modify leaves it out for the same reason.
    ///
    /// Separate from [`EndpointError::UnknownRequest`], which says the
    /// identifier names nothing at all. This one says it names something, and
    /// that what it names cannot be updated.
    #[error("request {0} is a track status, which cannot be updated")]
    NotASubscription(u64),
    #[error(
        "response message received on control stream; d17 responses belong on bidi request streams"
    )]
    ResponseOnControlStream,
    /// A REQUEST_UPDATE arrived on the control stream.
    ///
    /// Draft-17 Section 9.10: "The sender of a request ... can later send a
    /// REQUEST_UPDATE on the same bidi stream as the request to modify it." The
    /// stream is what names the request being modified, so a REQUEST_UPDATE with
    /// no stream around it identifies nothing.
    #[error(
        "REQUEST_UPDATE received on the control stream; it belongs on the request's own stream"
    )]
    RequestUpdateOnControlStream,
    /// A NAMESPACE, NAMESPACE_DONE or PUBLISH_BLOCKED arrived on the control
    /// stream.
    ///
    /// Draft-17's message table has no Stream column — drafts 18 and 19 added
    /// one — so the placement is stated in the prose of each message's own
    /// section, and all three say the same thing. NAMESPACE (0x8) "is sent on
    /// the response stream of a SUBSCRIBE_NAMESPACE request" (Section 9.18).
    /// "All NAMESPACE_DONE messages are in response to a SUBSCRIBE_NAMESPACE"
    /// (Section 9.19), and "All PUBLISH_BLOCKED messages are in response to a
    /// SUBSCRIBE_NAMESPACE" (Section 9.21) — draft-17 has no SUBSCRIBE_TRACKS,
    /// so its PUBLISH_BLOCKED answers the same request the other two do.
    ///
    /// Section 9.20 makes the stream the correlation: the publisher "will send
    /// matching NAMESPACE messages on the response stream". One of these three
    /// on the control stream names no request, so there is nothing it could be
    /// reporting on.
    #[error(
        "{0} received on the control stream; draft-17 sends it on a SUBSCRIBE_NAMESPACE \
         response stream"
    )]
    RequestMessageOnControlStream(&'static str),
    /// A server received a GOAWAY carrying a New Session URI.
    ///
    /// Draft-17 Section 9.5: "If a server receives a GOAWAY with a non-zero
    /// New Session URI Length it MUST close the session with a
    /// PROTOCOL_VIOLATION." Only a client can be redirected.
    #[error("GOAWAY carrying a New Session URI received at a server")]
    GoAwayUriAtServer,
    /// The peer reused a Request ID it had already spent.
    ///
    /// Draft-17 Section 9.1: "If an endpoint receives a Request ID where the
    /// least significant bit is incorrect for the sender, or a duplicate
    /// Request ID, it MUST close the session with INVALID_REQUEST_ID."
    #[error("request {0} was already used by the peer")]
    DuplicateRequestId(u64),
    /// A bidirectional stream the peer opened began with a message that does
    /// not open a request stream.
    ///
    /// Draft-17 Section 3.3: "Bidirectional streams MUST NOT begin with any
    /// other message type unless negotiated. If they do, the peer MUST close
    /// the Session with a PROTOCOL_VIOLATION."
    #[error("{0:?} does not begin a request stream")]
    NotARequest(MessageType),
    /// A message that is not one of this draft's responses was handed to the
    /// responder path. Nothing was written and no state moved.
    #[error("{0:?} is not a response message")]
    NotAResponse(MessageType),
    /// A message arrived on a request stream the peer opened that may not
    /// follow a request there.
    ///
    /// This endpoint is the responder on such a stream, so a response arriving
    /// on it is the peer answering its own request.
    #[error("{0:?} may not follow a request on a stream the peer opened")]
    UnexpectedOnPeerRequestStream(MessageType),
    /// A REQUEST_OK or REQUEST_ERROR was offered as the answer to a
    /// REQUEST_UPDATE on a stream with no update waiting for one.
    ///
    /// Section 9.10 requires "exactly one REQUEST_OK or REQUEST_ERROR
    /// message indicating if the update was successful", so an answer with
    /// nothing to answer is one the peer will read as belonging to an update it
    /// never sent. Not fatal: nothing was written.
    #[error("request {0} has no REQUEST_UPDATE waiting for an answer")]
    NoUpdateToAnswer(u64),
    /// An update was refused and the subscription it belongs to was then ended
    /// under some status other than the one that names why.
    ///
    /// Section 9.10.1: "When a subscription update is unsuccessful, the
    /// publisher MUST also terminate the subscription with PUBLISH_DONE with
    /// error code UPDATE_FAILED." Drafts 18 and 19 reword it as "When a
    /// REQUEST_UPDATE is unsuccessful ... by sending a PUBLISH_DONE", which is
    /// the same obligation a wording later.
    ///
    /// The REQUEST_ERROR is half of what that sentence
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
    /// The peer named a Track Alias it is already using for another track.
    ///
    /// Draft-17 states it twice, once per message. Section 9.9: "The same
    /// Track Alias MUST NOT be used by a publisher to refer to two different
    /// Tracks simultaneously in the same session. If a subscriber receives a
    /// SUBSCRIBE_OK that uses the same Track Alias as a different track with
    /// an Established subscription, it MUST close the session with error
    /// DUPLICATE_TRACK_ALIAS." Section 9.11 is the same sentence with PUBLISH
    /// in place of SUBSCRIBE_OK.
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
    /// that chooses the alias. Section 9.11 states it as a prohibition on the
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
    /// Section 2.4.2 lists the condition: "An Object is received on a
    /// Track whose Group and Object ID are
    /// larger than the final Object in the Track.
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
    /// operation Section 3.3.1 describes. This is the error half; the
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
    /// Section 9.14.2:
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
    /// Section 9.20: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session. Within a session, if a publisher
    /// receives a SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that
    /// shares a common prefix with an established namespace subscription, it
    /// MUST respond with REQUEST_ERROR with error code PREFIX_OVERLAP."
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
    /// subscriptions on a single session." Drafts 18 and 19 drop it, and
    /// neither has this error.
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
/// Section 9.20: "A subscriber cannot make overlapping namespace
/// subscriptions on a single session. Within a session, if a publisher
/// receives a SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that shares a
/// common prefix with an established namespace subscription, it MUST respond
/// with REQUEST_ERROR with error code PREFIX_OVERLAP."
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

impl EndpointError {
    /// The code to close the session with, when draft-17 says this error is
    /// fatal to the session rather than to one request.
    ///
    /// `None` means the error is recoverable: the caller may report it, reset
    /// the one stream it concerns, and keep the session running. `Some` means
    /// the draft requires a close, and the endpoint has already moved its own
    /// session state to [`SessionState::Closed`] — the code is what the
    /// transport should carry.
    ///
    /// The two codes are not interchangeable. Section 3.3 gives
    /// PROTOCOL_VIOLATION for a bidirectional stream that begins with the
    /// wrong message type; Section 9.1 gives INVALID_REQUEST_ID for a Request
    /// ID with the wrong least significant bit or a duplicate one. A peer
    /// checking close codes can tell the two apart, so this must too.
    pub fn session_error_code(&self) -> Option<SessionErrorCode> {
        match self {
            EndpointError::NotARequest(_)
            | EndpointError::RequestUpdateOnControlStream
            | EndpointError::RequestMessageOnControlStream(_)
            | EndpointError::GoAwayUriAtServer
            | EndpointError::RepeatedGoAway => Some(SessionErrorCode::ProtocolViolation),
            EndpointError::DuplicateRequestId(_)
            | EndpointError::RequestId(RequestIdError::WrongParity(..)) => {
                Some(SessionErrorCode::InvalidRequestId)
            }
            // Sections 9.9 and 9.11 name this code in the sentence that states the
            // rule, and name no other. A close carrying PROTOCOL_VIOLATION
            // would tell the peer a different thing went wrong.
            EndpointError::DuplicateTrackAlias { .. } => {
                Some(SessionErrorCode::DuplicateTrackAlias)
            }
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
    /// The namespace prefix each SUBSCRIBE_NAMESPACE this endpoint sent asked
    /// about, which the state machine beside it does not hold.
    ///
    /// Read by [`Endpoint::own_prefix_overlap`] and by nothing else. The
    /// withdrawal names the Request ID here, so until the rule about
    /// overlapping prefixes was judged there was nothing to remember a prefix
    /// for.
    subscribe_namespace_prefixes: HashMap<u64, TrackNamespace>,
    subscribe_namespaces: HashMap<u64, SubscribeNamespaceStateMachine>,
    publish_namespaces: HashMap<u64, PublishNamespaceStateMachine>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    publishes: HashMap<u64, PublishStateMachine>,
    goaway_uri: Option<Vec<u8>>,
    /// Every Request ID the peer has spent, whether or not the request it
    /// opened is still live.
    ///
    /// Draft-17 Section 9.1 makes a duplicate Request ID a session close, and
    /// "duplicate" is about the id ever having been used, not about the
    /// request still being open. Deriving it from the per-kind maps instead
    /// would answer wrongly the moment those maps are ever pruned, so the rule
    /// is stated once, here, and this set is never pruned.
    peer_request_ids: HashSet<u64>,
    /// Every request the **peer** opened a stream with, as it arrived, keyed
    /// by the Request ID it carries.
    ///
    ///
    /// One map for all six kinds, because one entry point takes all six:
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
    /// Per request stream, how many REQUEST_UPDATEs are still waiting for the
    /// answer Section 9.10 requires.
    unanswered_peer_updates: HashMap<u64, u64>,
    /// The requests whose refused update has not been followed by the
    /// PUBLISH_DONE that ends them.
    ///
    /// Emptied as each is written. A request is in here for exactly as long as
    /// this endpoint owes the peer the second half of a refusal.
    owed_update_failures: HashSet<u64>,
    /// The peer's requests whose own response has already been written.
    ///
    /// Section 9.10 gives an update the same two answers a request has, and
    /// on the kinds REQUEST_OK answers, the message that answers the request and
    /// the message that answers an update are the same message. Nothing on the
    /// wire tells them apart, so both endpoints resolve it by order: the first
    /// response on a stream answers the request that opened it and the ones
    /// after it answer updates. This set is that order, recorded.
    answered_peer_requests: HashSet<u64>,
    /// What Full Track Name the peer has attached each Track Alias to, per
    /// Request ID.
    ///
    /// Sections 9.9 and 9.11 forbid one alias naming two tracks at once, and the "at
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
            subscribe_namespace_prefixes: HashMap::new(),
            publish_namespaces: HashMap::new(),
            track_statuses: HashMap::new(),
            publishes: HashMap::new(),
            goaway_uri: None,
            peer_request_ids: HashSet::new(),
            inbound_requests: HashMap::new(),
            overlapping_namespace_subscriptions: HashMap::new(),
            unanswered_peer_updates: HashMap::new(),
            owed_update_failures: HashSet::new(),
            answered_peer_requests: HashSet::new(),
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

    /// The refusal Sections 9.9 and 9.11 require when `alias` already names a
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
    /// as a different track with an Established subscription" - and the
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
    /// stream - Section 3.3.1. Every request lives at the front of a
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
    /// Draft-17 Section 9.10: "A subscriber can also send REQUEST_UPDATE to
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
    /// Draft-17 Section 9.10.1 makes a subscription the subject of the
    /// obligation a refusal creates: "When a subscription update is
    /// unsuccessful, the publisher MUST also terminate the subscription with
    /// PUBLISH_DONE with error code UPDATE_FAILED." A namespace subscription,
    /// a fetch and a track status have no subscription to terminate and no
    /// PUBLISH_DONE they could send, so a refused update on one owes nothing.
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

    // -- Unified SETUP (draft-17) -----------------------------------

    /// Generate a SETUP message. Both client and server use the same message
    /// type; only the role (and the order of send/receive) distinguishes them.
    pub fn send_setup(
        &mut self,
        options: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let msg = Setup { options };
        setup::validate_setup(&msg, self.role)?;
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
        // Draft-17 Section 9.5: "If a server receives a GOAWAY with a non-zero
        // New Session URI Length it MUST close the session with a
        // PROTOCOL_VIOLATION." Migration is something a server offers a client,
        // never the other way round, so the URI is refused here rather than
        // stored in `goaway_uri` and later followed — an application reading it
        // back would reconnect to somewhere a client chose.
        if self.role == Role::Server && !msg.new_session_uri.is_empty() {
            return Err(self.fail_session(EndpointError::GoAwayUriAtServer));
        }
        // Draft-17 Section 9.5: "The endpoint MUST close the session with a
        // PROTOCOL_VIOLATION (Section 3.5) if it receives multiple GOAWAY messages."
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

    // -- Request ID delta helper ------------------------------------

    /// `required_request_id_delta` is the distance between this request_id
    /// and the lowest still-pending one. For simplicity we always emit 0
    /// (tells the peer *no earlier requests need a response before this one*).
    fn delta() -> VarInt {
        VarInt::from_u64(0).unwrap()
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
        // still in flight does close the session rather than being recorded
        // and forgotten, which is what this discarded result used to mean.
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
            required_request_id_delta: Self::delta(),
            track_namespace,
            track_name,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK. Draft-17: no request_id on wire; the
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

    /// Process a REQUEST_UPDATE that arrived on the bidi request stream
    /// identified by `request_id`.
    ///
    /// The stream names the request being modified, not the message. Draft-17
    /// Section 9.10: "The sender of a request (SUBSCRIBE, PUBLISH, FETCH,
    /// PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE) can later send a REQUEST_UPDATE
    /// on the same bidi stream as the request to modify it." Section 9.1 lists
    /// REQUEST_UPDATE among the messages that consume a Request ID of their own,
    /// so the id in the message body is the update's, not the target's — reading
    /// it as the target means every conforming peer's update names a request
    /// that by construction does not exist.
    ///
    /// Every request kind in that list is accepted, not only subscriptions: the
    /// draft names five senders and only one of them is a SUBSCRIBE.
    /// `SubscriptionStateMachine` is the only one of the machines with an update
    /// edge, so a subscription walks it and the rest are acknowledged without a
    /// state move.
    pub fn receive_request_update(
        &mut self,
        request_id: VarInt,
        _msg: &RequestUpdate,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        // Section 9.16 takes the update away from this request kind outright:
        // "the subscriber cannot send REQUEST_UPDATE". Refused before the set below is
        // consulted, because an identifier naming a track status does name a
        // request, which is exactly what would otherwise let it through.
        if self.track_statuses.contains_key(&id) {
            return Err(EndpointError::NotASubscription(id));
        }
        let updatable = if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_subscribe_update()?;
            true
        } else {
            self.publishes.contains_key(&id)
                || self.fetches.contains_key(&id)
                || self.subscribe_namespaces.contains_key(&id)
                || self.publish_namespaces.contains_key(&id)
        };
        if !updatable {
            return Err(EndpointError::UnknownRequest(id));
        }
        *self.unanswered_peer_updates.entry(id).or_insert(0) += 1;
        Ok(())
    }

    /// Process an incoming PUBLISH_DONE (subscriber side). Draft-17: no
    /// request_id on wire; `request_id` identifies the subscription's
    /// bidi stream.
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
            required_request_id_delta: Self::delta(),
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

    /// Send a Relative Joining Fetch (Fetch Type 0x2). Allocates a request ID.
    ///
    /// `joining_start` is an offset rather than a group number: draft-17
    /// Section 9.14.2.1 has the publisher set the Start Location to
    /// "{Joining Location.Group - Joining Start, 0}". To name the starting group
    /// outright, use [`absolute_joining_fetch`](Self::absolute_joining_fetch).
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

    /// Send an Absolute Joining Fetch (Fetch Type 0x3). Allocates a request ID.
    ///
    /// Draft-17 Section 9.14.2.1: "For an Absolute Joining Fetch, the
    /// publisher sets the Start Location to {Joining Start, 0}." So
    /// `joining_start` is the group to begin at rather than a count back from
    /// one, and Section 9.14.2 leaves the choice with the subscriber: "The
    /// subscriber can set the Start Location to an absolute Location or a
    /// Location relative to the Largest group." Only the relative form could be sent
    /// before, so an application that knew which group it wanted had to
    /// express it as an offset from a largest group it may never have been
    /// told.
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

    /// The two above, which differ in the Fetch Type and in what the publisher
    /// then reads Joining Start as. Nothing else about the message changes.
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
            required_request_id_delta: Self::delta(),
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

    /// Send a SUBSCRIBE_NAMESPACE message, opening a request stream for it.
    ///
    /// Section 9.20 addresses the first half of the overlap rule to this end of
    /// the session: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session." So a prefix overlapping one this
    /// endpoint has already asked about is refused here rather than built and
    /// sent for the peer to refuse. Drafts 18 and 19 drop that sentence, and
    /// neither refuses a request of this endpoint's own.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established,
    /// [`EndpointError::OwnPrefixOverlap`] when the prefix overlaps one this
    /// endpoint is already subscribed to, and the Request ID allocator's own
    /// error when the peer has granted no room for another request.
    pub fn subscribe_namespace(
        &mut self,
        namespace_prefix: TrackNamespace,
        subscribe_options: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        // The subscriber's half of the rule, refused before the message
        // exists. A publisher that follows this draft answers it with a
        // refusal, so building it spends a Request ID on a namespace
        // subscription that is not going to open.
        if let Some(established) = self.own_prefix_overlap(&namespace_prefix) {
            return Err(EndpointError::OwnPrefixOverlap { established });
        }
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscribeNamespaceStateMachine::new();
        sm.on_subscribe_namespace_sent()?;
        self.subscribe_namespaces.insert(req_id.into_inner(), sm);
        self.subscribe_namespace_prefixes.insert(req_id.into_inner(), namespace_prefix.clone());

        let msg = ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: req_id,
            required_request_id_delta: Self::delta(),
            namespace_prefix,
            subscribe_options,
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
            required_request_id_delta: Self::delta(),
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
            required_request_id_delta: Self::delta(),
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
        // Section 9.11: "The same Track Alias MUST NOT be used by a publisher to refer to
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
            required_request_id_delta: Self::delta(),
            track_namespace,
            track_name,
            track_alias,
            parameters,
            track_properties,
        });
        Ok((req_id, msg))
    }

    pub fn receive_publish_ok(
        &mut self,
        request_id: VarInt,
        _msg: &message::PublishOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_ok()?;
        Ok(())
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

    // -- Consolidated responses (draft-17: per-bidi-stream routing) -

    /// Process an incoming REQUEST_OK on the bidi stream identified by
    /// `request_id`. Used by PublishNamespace, SubscribeNamespace, and
    /// TrackStatus flows.
    pub fn receive_request_ok(
        &mut self,
        request_id: VarInt,
        _msg: &RequestOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
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
        _msg: &RequestError,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
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
    /// it was made on rather than by sending a message. Section 3.3.1: "Once
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
    /// [`Connection::cancel_request_stream`]: crate::draft17::connection::Connection::cancel_request_stream
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

    // -- PublishBlocked / Namespace announcements -------------------

    /// Receive a NAMESPACE reporting one of the namespaces a
    /// SUBSCRIBE_NAMESPACE asked for. Informational — no state machine is
    /// involved.
    pub fn receive_namespace(&mut self, _msg: &message::Namespace) -> Result<(), EndpointError> {
        Ok(())
    }

    /// Receive a NAMESPACE_DONE withdrawing one of them.
    pub fn receive_namespace_done(
        &mut self,
        _msg: &message::NamespaceDone,
    ) -> Result<(), EndpointError> {
        Ok(())
    }

    /// Receive a PUBLISH_BLOCKED notification.
    pub fn receive_publish_blocked(&mut self, _msg: &PublishBlocked) -> Result<(), EndpointError> {
        Ok(())
    }

    // -- Unified message dispatch -----------------------------------

    /// Dispatch a message that arrived on the control stream.
    ///
    /// Only SETUP (Section 9.4) and GOAWAY (Section 9.5) belong to the session
    /// as a whole. Everything else names a request, and Section 3.3 gives every
    /// request a bidirectional stream of its own, so this method's job is to
    /// take those two and refuse the rest.
    ///
    /// Four are refused for that reason. REQUEST_UPDATE modifies the request
    /// its stream carries (Section 9.10). NAMESPACE and NAMESPACE_DONE report
    /// namespaces on the SUBSCRIBE_NAMESPACE request stream that asked for them
    /// (Sections 9.18 and 9.19), and PUBLISH_BLOCKED names a track that cannot
    /// be published on that same stream (Section 9.21 — draft-17 has no
    /// SUBSCRIBE_TRACKS to put it on). All four route through
    /// [`receive_response_on_stream`](Self::receive_response_on_stream), which
    /// has the request ID they need.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::Setup(ref m) => self.receive_setup(m),
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::RequestUpdate(_) => {
                Err(self.fail_session(EndpointError::RequestUpdateOnControlStream))
            }
            ControlMessage::Namespace(_) => {
                Err(self.fail_session(EndpointError::RequestMessageOnControlStream("NAMESPACE")))
            }
            ControlMessage::NamespaceDone(_) => {
                Err(self
                    .fail_session(EndpointError::RequestMessageOnControlStream("NAMESPACE_DONE")))
            }
            ControlMessage::PublishBlocked(_) => {
                Err(self
                    .fail_session(EndpointError::RequestMessageOnControlStream("PUBLISH_BLOCKED")))
            }
            ControlMessage::SubscribeOk(_)
            | ControlMessage::PublishDone(_)
            | ControlMessage::PublishOk(_)
            | ControlMessage::FetchOk(_)
            | ControlMessage::RequestOk(_)
            | ControlMessage::RequestError(_) => Err(EndpointError::ResponseOnControlStream),
            _ => Ok(()),
        }
    }

    /// Dispatch a message that arrived on the bidi request stream identified
    /// by `request_id`. Draft-17 responses carry no `request_id` of their own,
    /// so the caller must supply the one belonging to the stream the message
    /// arrived on.
    ///
    /// Beyond the six responses this also takes the three messages draft-17
    /// sends on a SUBSCRIBE_NAMESPACE response stream without their being
    /// answers to it.
    ///
    /// NAMESPACE (0x8) and NAMESPACE_DONE (0xE) report and withdraw the
    /// namespaces the subscription asked for — Section 9.18 says NAMESPACE "is
    /// sent on the response stream of a SUBSCRIBE_NAMESPACE request", and
    /// Section 9.20 restates it: the publisher "will send matching NAMESPACE
    /// messages on the response stream". PUBLISH_BLOCKED (0xF) names a track in
    /// that namespace the publisher cannot offer, and Section 9.21 puts it on
    /// the same stream: "All PUBLISH_BLOCKED messages are in response to a
    /// SUBSCRIBE_NAMESPACE". Draft-18 moved that one message to its new
    /// SUBSCRIBE_TRACKS stream; draft-17 has no such request.
    ///
    /// Without these three arms a peer that follows the draft renders
    /// SUBSCRIBE_NAMESPACE useless: every namespace it reports would fall
    /// through to [`EndpointError::ResponseOnControlStream`], on the one stream
    /// the draft says to report it on.
    pub fn receive_response_on_stream(
        &mut self,
        request_id: VarInt,
        msg: ControlMessage,
    ) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(request_id, m),
            ControlMessage::PublishDone(ref m) => self.receive_publish_done(request_id, m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(request_id, m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(request_id, m),
            ControlMessage::RequestOk(ref m) => self.receive_request_ok(request_id, m),
            ControlMessage::RequestError(ref m) => self.receive_request_error(request_id, m),
            // Section 9.10 puts a REQUEST_UPDATE on the stream of the request it
            // modifies, which is this one.
            ControlMessage::RequestUpdate(ref m) => self.receive_request_update(request_id, m),
            ControlMessage::Namespace(ref m) => self.receive_namespace(m),
            ControlMessage::NamespaceDone(ref m) => self.receive_namespace_done(m),
            ControlMessage::PublishBlocked(ref m) => self.receive_publish_blocked(m),
            _ => Err(EndpointError::ResponseOnControlStream),
        }
    }

    // -- Responder side: requests the peer opened a stream with -----

    /// Refuse a bidirectional stream the peer opened with a message type that
    /// does not begin a request, and end the session.
    ///
    /// Draft-17 Section 3.3: "Bidirectional streams MUST NOT begin with any
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
    /// Draft-17 Section 9.1: "If an endpoint receives a Request ID where the
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
                if let Some(established) = self.peer_namespace_overlap(&m.namespace_prefix) {
                    self.overlapping_namespace_subscriptions.insert(id, established);
                }
                let mut sm = SubscribeNamespaceStateMachine::new();
                sm.on_subscribe_namespace_received()?;
                self.subscribe_namespaces.insert(id, sm);
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
    fn peer_namespace_overlap(&self, prefix: &TrackNamespace) -> Option<u64> {
        self.inbound_requests
            .iter()
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

    /// The earliest namespace subscription **this endpoint** has made whose
    /// prefix overlaps `prefix`, and `None` when there is none.
    ///
    /// The subscriber's half of the same sentence reads over this endpoint's
    /// own requests, and takes the same view of which of them are past as
    /// [`Self::peer_namespace_overlap`] takes of the peer's. Drafts 18 and 19
    /// drop this half of the sentence, and there nothing refuses a request
    /// this endpoint makes.
    fn own_prefix_overlap(&self, prefix: &TrackNamespace) -> Option<u64> {
        self.subscribe_namespace_prefixes
            .iter()
            .filter_map(|(&id, key)| prefixes_overlap(&key.0, &prefix.0).then_some(id))
            .filter(|id| {
                self.subscribe_namespaces
                    .get(id)
                    .is_some_and(|sm| sm.state() != SubscribeNamespaceState::Done)
            })
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

    /// Drive the state machine for a response this endpoint is about to write
    /// on a request stream the peer opened.
    ///
    /// The mirror of [`receive_response_on_stream`](Self::receive_response_on_stream),
    /// and the reason the transitions are named `*_sent` rather than reusing
    /// the received-side ones: the state edges coincide, so a mis-dispatch
    /// would otherwise succeed silently instead of naming the wrong event in
    /// an `InvalidTransition`.
    ///
    /// The caller writes `msg` only after this returns `Ok`. What it cannot
    /// undo is the opposite order: a write that fails afterwards leaves the
    /// state machine one step ahead of the wire, the same asymmetry the
    /// outbound request path already carries.
    /// Whether this response answers a REQUEST_UPDATE rather than the request
    /// that opened the stream.
    ///
    /// Section 9.10 gives an update the same two answers a request has: "The
    /// receiver of a REQUEST_UPDATE MUST respond with exactly one REQUEST_OK or
    /// REQUEST_ERROR message indicating if the update was successful." Nothing
    /// in either message says which of the two it is answering, so the question
    /// is settled twice over.
    ///
    /// A SUBSCRIBE is answered with SUBSCRIBE_OK, a FETCH with FETCH_OK and a
    /// PUBLISH with PUBLISH_OK, so a REQUEST_OK on one of those three streams
    /// has no other message it could be answering. Draft-18 folded PUBLISH_OK
    /// into REQUEST_OK and left two.
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
        // Section 9.10 names the one request that works that way: "A subscriber
        // can also send REQUEST_UPDATE to modify parameters of a subscription
        // established with PUBLISH."
        if self.publishes.contains_key(&id) && !self.inbound_requests.contains_key(&id) {
            return true;
        }
        if matches!(msg, ControlMessage::RequestOk(_))
            && (self.subscriptions.contains_key(&id)
                || self.fetches.contains_key(&id)
                || self.publishes.contains_key(&id))
        {
            return true;
        }
        self.answered_peer_requests.contains(&id)
    }

    /// Record a response as the answer to an outstanding update.
    ///
    /// One update per answer, both ways round. Draft-17 has no coalescing
    /// paragraph — the one drafts 18 and 19 carry, which lets a single
    /// REQUEST_ERROR stand for several updates — so "exactly one REQUEST_OK or
    /// REQUEST_ERROR message" is the whole of the rule here.
    ///
    /// No state machine moves. An update changes a request's parameters and not
    /// its lifecycle, so a subscription that was Active before its update was
    /// answered is Active after it, whichever answer went out.
    ///
    /// # Errors
    ///
    /// [`EndpointError::NoUpdateToAnswer`], and nothing is written.
    fn answer_an_update(&mut self, id: u64) -> Result<(), EndpointError> {
        let unanswered = self.unanswered_peer_updates.get(&id).copied().unwrap_or(0);
        if unanswered == 0 {
            return Err(EndpointError::NoUpdateToAnswer(id));
        }
        self.unanswered_peer_updates.insert(id, unanswered - 1);
        Ok(())
    }

    /// The identifier an arriving Joining Fetch names, when this session has
    /// no subscription it may join.
    ///
    /// Section 9.14.2:
    /// "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to a subscription in the same session in the
    /// Established or Pending (subscriber) states, it MUST return a
    /// REQUEST_ERROR with error code INVALID_JOINING_REQUEST_ID."
    /// A standalone fetch names none and answers `None`, and so does a joining
    /// one whose subscription is live. Either message can establish the one it
    /// joins: Section 5.1 says the Largest Location a Joining FETCH works from
    /// is the one "communicated in SUBSCRIBE_OK, PUBLISH or REQUEST_OK (in
    /// response to a REQUEST_UPDATE) that changes the Forward State from 0 to
    /// 1".
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
    /// overlapped one already open, and each flow's own
    /// `InvalidTransition` for a request already answered.
    pub fn send_response_on_stream(
        &mut self,
        request_id: VarInt,
        msg: &ControlMessage,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
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
            self.answer_an_update(id)?;
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
            ControlMessage::PublishOk(_) => {
                let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_publish_ok_sent()?;
            }
            ControlMessage::PublishDone(_) => {
                let sm =
                    self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
                sm.on_publish_done_sent()?;
            }
            // REQUEST_OK answers the three kinds that have no response message
            // of their own. The probe order does not matter: the maps are
            // keyed by Request ID and one id belongs to one request.
            ControlMessage::RequestOk(_) => {
                if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
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
                } else if let Some(sm) = self.publish_namespaces.get_mut(&id) {
                    sm.on_publish_namespace_error_sent()?;
                } else if let Some(sm) = self.track_statuses.get_mut(&id) {
                    sm.on_track_status_error_sent()?;
                } else {
                    return Err(EndpointError::UnknownRequest(id));
                }
            }
            other => return Err(EndpointError::NotAResponse(other.message_type())),
        }
        // Reached only by a response that answered the request itself, since an
        // update's answer returned above. From here on, a REQUEST_OK or
        // REQUEST_ERROR on this stream can only be answering an update.
        if matches!(
            msg,
            ControlMessage::SubscribeOk(_)
                | ControlMessage::FetchOk(_)
                | ControlMessage::PublishOk(_)
                | ControlMessage::RequestOk(_)
                | ControlMessage::RequestError(_)
        ) {
            self.answered_peer_requests.insert(id);
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
    /// Two messages are expected instead.
    ///
    /// REQUEST_UPDATE, because draft-17 Section 9.10 puts it on the request's
    /// own stream: "The sender of a request (SUBSCRIBE, PUBLISH, FETCH,
    /// PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE) can later send a REQUEST_UPDATE
    /// on the same bidi stream as the request to modify it." The request it
    /// modifies is therefore the stream's, which is why `request_id` here comes
    /// from the stream and the message's own Request ID field is not consulted
    /// — Section 9.1 says REQUEST_UPDATE consumes a Request ID of its own, so
    /// that field does not name the request being updated. Only a subscription
    /// carries a transition for an update; for the other kinds draft-17 defines
    /// no state change, so the message is accepted and the state left alone.
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
            // Through the same method the requester side uses, so the rule
            // about which requests may be updated is stated once. An id the
            // peer never opened is in none of the maps that method probes,
            // which is the check this arm used to make for itself.
            ControlMessage::RequestUpdate(ref m) => self.receive_request_update(request_id, m),
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

    /// Publishing -> Active (PUBLISH_OK written on the peer's stream).
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
    /// Idle -> Pending (SUBSCRIBE_NAMESPACE received from the peer).
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
    use crate::draft17::publish::PublishState;
    use crate::draft17::subscription::SubscriptionState;

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
        TrackNamespace(vec![b"ns".to_vec()])
    }

    fn peer_subscribe(id: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: v(id),
            required_request_id_delta: v(0),
            track_namespace: ns(),
            track_name: b"t".to_vec(),
            parameters: vec![],
        })
    }

    fn peer_publish(id: u64) -> ControlMessage {
        ControlMessage::Publish(Publish {
            request_id: v(id),
            required_request_id_delta: v(0),
            track_namespace: ns(),
            track_name: b"t".to_vec(),
            track_alias: v(7),
            parameters: vec![],
            track_properties: vec![],
        })
    }

    /// The peer's requests and this endpoint's share one map per kind, and the
    /// opposite Request ID parity is what keeps them apart. Both directions
    /// are registered here and both are still there afterwards, which is the
    /// consequence a collision would destroy.
    #[test]
    fn a_peers_request_lives_beside_our_own_in_the_same_map() {
        let mut ep = active_client();
        let (ours, _) = ep.subscribe(ns(), b"t".to_vec(), vec![]).unwrap();
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

    /// Draft-17 Section 9.1: a Request ID whose least significant bit is wrong
    /// for the sender MUST close the session with INVALID_REQUEST_ID. The
    /// close is observable twice over — the endpoint stops accepting requests,
    /// and the code the connection layer will put on the wire is the one the
    /// section names.
    ///
    /// Deleting the `validate_peer_id` call from `receive_request_on_stream`
    /// fails with:
    ///
    /// ```text
    /// called `Result::unwrap_err()` on an `Ok` value: VarInt(2)
    /// ```
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

    /// Draft-17 Section 3.3 gives a different code for a different rule: a
    /// bidirectional stream that begins with the wrong message type is a
    /// PROTOCOL_VIOLATION, not an INVALID_REQUEST_ID.
    ///
    /// Mapping `NotARequest` to `InvalidRequestId` in `session_error_code`
    /// fails with:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: Some(InvalidRequestId)
    ///  right: Some(ProtocolViolation)
    /// ```
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

        let done = ControlMessage::PublishDone(PublishDone {
            status_code: v(0),
            stream_count: v(0),
            reason_phrase: Vec::new(),
        });
        ep.send_response_on_stream(id, &done).unwrap();
        assert_eq!(ep.subscriptions[&1].state(), SubscriptionState::Done);
    }

    /// The responder transitions are separate from the requester ones so a
    /// mis-dispatch names the responder event rather than succeeding quietly.
    #[test]
    fn a_responder_transition_out_of_order_names_the_responder_event() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        let done = ControlMessage::PublishDone(PublishDone {
            status_code: v(0),
            stream_count: v(0),
            reason_phrase: Vec::new(),
        });
        // PUBLISH_DONE before SUBSCRIBE_OK: the subscription is not Active.
        let err = ep.send_response_on_stream(id, &done).unwrap_err();
        assert_eq!(
            err.to_string(),
            "subscription error: invalid transition from Subscribing on event on_publish_done_sent",
        );
    }

    /// A peer that sends PUBLISH is the publisher, so PUBLISH_DONE comes back
    /// from it on the same stream. That is the one direction the requester
    /// path never has to handle, because there we are the publisher.
    #[test]
    fn a_peers_publish_is_ended_by_the_peer() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_publish(1)).unwrap();
        let ok = ControlMessage::PublishOk(message::PublishOk { parameters: vec![] });
        ep.send_response_on_stream(id, &ok).unwrap();
        assert_eq!(ep.publishes[&1].state(), PublishState::Active);

        let done = ControlMessage::PublishDone(PublishDone {
            status_code: v(0),
            stream_count: v(0),
            reason_phrase: Vec::new(),
        });
        ep.receive_on_peer_request_stream(id, done.clone()).unwrap();
        assert_eq!(ep.publishes[&1].state(), PublishState::Done);
        assert!(
            ep.receive_on_peer_request_stream(id, done).is_err(),
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

    /// Draft-17 Section 9.10 puts REQUEST_UPDATE on the request's own stream,
    /// so the request it modifies is the stream's and not whatever its own
    /// Request ID field says — that field names an id of its own, since
    /// Section 9.1 has REQUEST_UPDATE consume one.
    #[test]
    fn a_peers_request_update_is_correlated_by_the_stream() {
        let mut ep = active_client();
        let id = ep.receive_request_on_stream(&peer_subscribe(1)).unwrap();
        let ok = ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: v(7),
            parameters: vec![],
            track_properties: vec![],
        });
        ep.send_response_on_stream(id, &ok).unwrap();

        // The Request ID field carries 3, an id no request of ours or theirs
        // has opened. The update still lands on the stream's subscription.
        let update = ControlMessage::RequestUpdate(RequestUpdate {
            request_id: v(3),
            required_request_id_delta: v(0),
            parameters: vec![],
        });
        ep.receive_on_peer_request_stream(id, update).unwrap();
        assert_eq!(ep.subscriptions[&1].state(), SubscriptionState::Active);
    }

    /// The three messages draft-17 sends on a SUBSCRIBE_NAMESPACE response
    /// stream that are not answers to it: NAMESPACE (0x8), NAMESPACE_DONE (0xE)
    /// and PUBLISH_BLOCKED (0xF).
    ///
    /// Draft-17's message table has no Stream column, so each message's own
    /// section states its placement, and all three say the same thing.
    /// Section 9.18: NAMESPACE "is sent on the response stream of a
    /// SUBSCRIBE_NAMESPACE request". Section 9.19: "All NAMESPACE_DONE messages
    /// are in response to a SUBSCRIBE_NAMESPACE". Section 9.21: "All
    /// PUBLISH_BLOCKED messages are in response to a SUBSCRIBE_NAMESPACE" —
    /// draft-18 moved that one to its new SUBSCRIBE_TRACKS stream, but on this
    /// draft there is no such request and all three share the one stream.
    ///
    /// The placement had all three exactly inverted — the control stream
    /// accepted them and returned `Ok`, and the request stream fell through to
    /// the catch-all and refused them — so a conforming peer sending NAMESPACE
    /// on the SUBSCRIBE_NAMESPACE stream that asked for it had its announcement
    /// dropped, which is what made SUBSCRIBE_NAMESPACE unusable end to end on
    /// this draft.
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
    fn namespace_and_publish_blocked_arrive_on_a_request_stream() {
        /// A message name paired with a way to build a fresh one, since each
        /// case needs two copies and `ControlMessage` is consumed by both
        /// dispatchers.
        type Case = (&'static str, fn() -> ControlMessage);

        let cases: [Case; 3] = [
            ("NAMESPACE", || {
                ControlMessage::Namespace(message::Namespace { namespace_suffix: ns() })
            }),
            ("NAMESPACE_DONE", || {
                ControlMessage::NamespaceDone(message::NamespaceDone { namespace_suffix: ns() })
            }),
            ("PUBLISH_BLOCKED", || {
                ControlMessage::PublishBlocked(PublishBlocked {
                    namespace_suffix: ns(),
                    track_name: b"video".to_vec(),
                })
            }),
        ];

        for (name, build) in cases {
            let mut ep = active_client();
            let id = ep.subscribe_namespace(ns(), v(0), vec![]).unwrap().0;

            // Where the draft puts it.
            ep.receive_response_on_stream(id, build())
                .unwrap_or_else(|e| panic!("{name} belongs on a request stream: {e:?}"));

            // Where it does not, which the draft answers with a close.
            let err = match ep.receive_message(build()) {
                Err(e) => e,
                Ok(()) => panic!("{name} must be refused on the control stream: Ok(())"),
            };
            assert!(
                matches!(err, EndpointError::RequestMessageOnControlStream(m) if m == name),
                "{name} on the control stream gave {err}"
            );
            // The error alone would let a caller ignore it and carry on, which
            // is the opposite of the close the draft requires.
            assert_eq!(
                err.session_error_code(),
                Some(SessionErrorCode::ProtocolViolation),
                "{err} should be fatal to the session"
            );
            assert_eq!(ep.session_state(), SessionState::Closed);
            assert!(matches!(
                ep.subscribe(ns(), b"t".to_vec(), vec![]),
                Err(EndpointError::NotActive)
            ));
        }
    }
}

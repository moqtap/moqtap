use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::draft11::fetch::{FetchError, FetchState, FetchStateMachine};
use crate::draft11::namespace::{
    AnnounceState, AnnounceStateMachine, NamespaceError, SubscribeAnnouncesState,
    SubscribeAnnouncesStateMachine,
};
use crate::draft11::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft11::session::setup::{self, SetupError};
use crate::draft11::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft11::subscription::{
    SubscriptionError, SubscriptionState, SubscriptionStateMachine,
};
use crate::draft11::track_status::{TrackStatusError, TrackStatusState, TrackStatusStateMachine};
use crate::forwarding_preference::{ObjectForwardingPreference, TrackForwardingPreferences};
use crate::track_locations::{
    EndOfTrackPlacement, ObjectLocation, ObjectRole, TrackLocations, TrackObjects,
};
use moqtap_codec::draft11::error_codes::{
    FetchErrorCode, SessionErrorCode, SubscribeAnnouncesErrorCode, SubscribeErrorCode,
};
use moqtap_codec::draft11::message::{
    self, Announce, AnnounceCancel, AnnounceError, AnnounceOk, ClientSetup, ControlMessage, Fetch,
    FetchCancel, FetchPayload, FetchType, GoAway, MaxRequestId, RequestsBlocked, ServerSetup,
    Subscribe, SubscribeAnnounces, SubscribeAnnouncesError, SubscribeAnnouncesOk, SubscribeDone,
    SubscribeError, SubscribeOk, SubscribeUpdate, TrackStatus, TrackStatusRequest, Unannounce,
    Unsubscribe, UnsubscribeAnnounces,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Key identifying a namespace (used for Announce maps).
type NamespaceKey = Vec<Vec<u8>>;

/// Errors that can occur during draft-11 endpoint operations.
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
    /// This endpoint was asked to advertise a Maximum Request ID that does
    /// not increase, and refused. Nothing was written.
    ///
    /// The send-side mirror of the rule a peer breaks by sending one — Section 8.5:
    /// "The Maximum Request ID MUST only increase within a session". No closing
    /// mark, because the draft's sentence does not close there: it runs on
    /// into the receipt half, which is the peer's side of this rule and not
    /// this one's. Its own
    /// variant, and not the received one, because the two are opposite
    /// findings that would otherwise arrive as the same value: the received one
    /// is a peer in violation and this one is a caller of this library asking
    /// for a message that would put this endpoint in violation, and
    /// [`EndpointError::session_error_code`] answers `Some` for it either way.
    ///
    /// Not fatal. The message is refused instead of built, the ceiling stays
    /// where it was, and nothing reaches the peer to object to.
    #[error(
        "the Maximum Request ID already advertised is {advertised}, so {offered} would not increase it"
    )]
    MaxRequestIdWouldNotIncrease {
        /// The ceiling this endpoint has already advertised.
        advertised: u64,
        /// The value it was asked to advertise instead.
        offered: u64,
    },
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

    /// A Track Alias names two tracks at once.
    ///
    /// Section 8.7, on the Track Alias the subscriber chooses in SUBSCRIBE:
    /// "If the Track Alias is already being used for a different track, the
    /// publisher MUST close the session with a Duplicate Track Alias error".
    /// Section 8.9 states the other end of the same rule, on the alias a
    /// SUBSCRIBE_ERROR may offer to retry with: "If this Track Alias is
    /// already in use, the subscriber MUST close the connection with a
    /// Duplicate Track Alias error".
    ///
    /// This is the last draft that puts the alias in SUBSCRIBE and so the last
    /// that raises this at the publisher. From draft-12 the alias moves into
    /// SUBSCRIBE_OK and PUBLISH, and the endpoint that must close moves with
    /// it.
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
    /// This endpoint was asked to give a Track Alias to a second track.
    ///
    /// The same rule as [`EndpointError::DuplicateTrackAlias`] read at the end
    /// that chooses the alias. Section 3.4 describes the code as "The endpoint
    /// attempted to use a Track Alias that was already in use", and Section
    /// 8.7 says what the receiving publisher does about it, so a SUBSCRIBE
    /// built this way is one the peer must answer by ending the session.
    ///
    /// The message is refused instead, and nothing else moves: no Request ID
    /// is spent, no subscription is created, and the session stays as it was.
    /// The alias never reaches the peer, so there is nothing for the peer to
    /// close over.
    #[error("track alias {alias} already names request {held}'s track")]
    TrackAliasInUse {
        /// The alias that is already spoken for.
        alias: u64,
        /// The request whose live subscription holds it.
        held: u64,
    },
    /// A track's objects were framed two different ways.
    ///
    /// Section 9: "Every Track has a single 'Object Forwarding Preference' and
    /// the Original Publisher MUST NOT mix different forwarding preferences
    /// within a single track. If a subscriber receives Objects via both
    /// Subgroup streams and Datagrams in response to a SUBSCRIBE, it SHOULD
    /// close the session with an error of 'Protocol Violation'"
    ///
    /// The framing is the preference: an object on a subgroup stream has the
    /// Subgroup preference and an object in a datagram has the Datagram one,
    /// so the track's first object settles the property and this is every
    /// later object measured against it.
    ///
    /// # What this draft reworded
    ///
    /// The prohibition is the one drafts 07 through 10 state; the sentence
    /// after it is not. This draft names the two framings the rule is about
    /// rather than "different forwarding preferences", and scopes it to
    /// objects answering a SUBSCRIBE — which is where its Section 9.1.1 puts
    /// the definition as well: "When in response to a SUBSCRIBE, an Object
    /// MUST be sent according to its Object Forwarding Preference". A fetch
    /// stream is neither framing and settles nothing here either way.
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
    /// Section 9.1.1.1 describes Object Status 0x4, end of Track, as one whose
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
    /// A SUBSCRIBE_UPDATE named an identifier no subscription the peer opened
    /// has ever been given.
    ///
    /// Section 8.10: "A publisher SHOULD close the Session as a 'Protocol
    /// Violation' if the SUBSCRIBE_UPDATE violates either rule or if the
    /// subscriber specifies a Request ID that has not existed within the Session."
    ///
    /// **SHOULD**, so this is reported and the session is left running. From
    /// draft-12 the same sentence says MUST, and there the session ends. An
    /// endpoint that wants the close on these drafts has everything it needs
    /// to make it: the error names the identifier that was not found.
    ///
    /// A subscription that has **ended** is not this: it existed. That is why
    /// the record of an inbound SUBSCRIBE outlives the subscription, and why
    /// an update naming an ended one is refused by the flow rather than by
    /// this error.
    #[error("SUBSCRIBE_UPDATE names request {0}, which no subscription the peer opened has had")]
    UpdateForUnknownRequest(u64),

    /// A Joining Fetch named a subscription this session cannot join.
    ///
    /// Section 8.13: "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to an existing Subscribe in the same session, it
    /// MUST respond with a Fetch Error with code Invalid Joining Subscribe ID."
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
    /// Section 8.23 says what a cancellation is for: the subscriber "will stop
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
    /// Section 8.24: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session. Within a session, if a publisher
    /// receives a SUBSCRIBE_ANNOUNCES with a Track Namespace Prefix that is a
    /// prefix of an earlier SUBSCRIBE_ANNOUNCES or vice versa, it MUST
    /// respond with SUBSCRIBE_ANNOUNCES_ERROR, with error code Namespace
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
/// Section 8.24: "A subscriber cannot make overlapping namespace
/// subscriptions on a single session. Within a session, if a publisher
/// receives a SUBSCRIBE_ANNOUNCES with a Track Namespace Prefix that is a
/// prefix of an earlier SUBSCRIBE_ANNOUNCES or vice versa, it MUST respond
/// with SUBSCRIBE_ANNOUNCES_ERROR, with error code Namespace Prefix Overlap."
///
/// A namespace matches a namespace subscription when the subscription's
/// prefix is a prefix of it, so two prefixes select overlapping sets of
/// namespaces exactly when one of them is a prefix of the other. Equal
/// prefixes are that case as well: every prefix is a prefix of itself, and
/// two equal ones select the same set.
fn prefixes_overlap(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    let shared = a.len().min(b.len());
    a[..shared] == b[..shared]
}

/// A SUBSCRIBE the peer sent, and how far the subscription it opened has got.
struct InboundSubscribe {
    /// The message as it arrived, which is what the application answers from.
    message: Subscribe,
    /// The subscription's state, driven from the publisher's end.
    state: SubscriptionStateMachine,
}
/// A FETCH the peer sent, and how far the fetch it opened has got.
struct InboundFetch {
    /// The message as it arrived, which is what the application answers from.
    message: Fetch,
    /// The fetch's state, driven from the end that serves it.
    state: FetchStateMachine,
    /// The subscription a Joining Fetch named and this session had none live
    /// for when the FETCH arrived, which is when the rule about it is read.
    unjoinable: Option<u64>,
}

/// A Track Alias attached to a Full Track Name, and the request whose lifetime
/// the attachment follows.
///
/// SUBSCRIBE carries the alias and the track in the one message, whichever end
/// sends it, so a binding is complete from the moment it is made. That stops
/// being true at draft-12, where the alias arrives in the answer instead.
#[derive(Debug, Clone)]
struct TrackBinding {
    namespace: TrackNamespace,
    name: Vec<u8>,
    alias: u64,
    kind: BindingKind,
}

/// Which end sent the SUBSCRIBE a binding came from, and so which record says
/// whether its subscription is still standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    /// A SUBSCRIBE this endpoint sent, carrying the alias it chose.
    Ours,
    /// A SUBSCRIBE the peer sent, carrying the alias the peer chose.
    Peers,
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
            | EndpointError::Setup(..)
            | EndpointError::UnknownRequest(..)
            | EndpointError::UnknownNamespace
            | EndpointError::UnknownPeerNamespace
            | EndpointError::UnknownPeerNamespaceSubscription => Fault::EitherEnd,

            // Raised on the way out. Nothing reached the wire, so none of
            // these is evidence about a peer — including the ones a peer
            // caused, where what failed is this side's attempt to accept
            // something the draft says to refuse.
            EndpointError::MaxRequestIdWouldNotIncrease { .. }
            | EndpointError::NotActive
            | EndpointError::Draining
            | EndpointError::FilterNeedsRange
            | EndpointError::TrackAliasInUse { .. }
            | EndpointError::UnjoinableSubscription { .. }
            | EndpointError::WrongJoiningRefusal { .. }
            | EndpointError::PeerPrefixOverlap { .. }
            | EndpointError::OwnPrefixOverlap { .. }
            | EndpointError::WrongOverlapRefusal { .. } => Fault::ThisEndpoint,

            // Raised reading what the peer sent.
            EndpointError::DuplicateTrackAlias { .. } => Fault::Peer(Rule::DuplicateTrackAlias),
            EndpointError::EndOfTrackOutOfPlace { .. } => Fault::Peer(Rule::EndOfTrackOutOfPlace),
            EndpointError::GoAwayUriAtServer => Fault::Peer(Rule::GoAwayAtServer),
            EndpointError::MixedForwardingPreference { .. } => {
                Fault::Peer(Rule::MixedForwardingPreference)
            }
            EndpointError::RepeatedGoAway => Fault::Peer(Rule::RepeatedGoAway),
            EndpointError::UpdateForUnknownRequest(..) => {
                Fault::Peer(Rule::RequestUpdateForTheWrongRequest)
            }

            // The Request ID rules, which are the peer's whenever they are
            // read off the wire. The mirror — this endpoint asked to advertise
            // a ceiling that does not increase — is
            // `MaxRequestIdWouldNotIncrease` above, which is a variant of its
            // own so that the two never arrive as one value.
            EndpointError::RequestId(e) => match e {
                RequestIdError::Decreased(..) => Fault::Peer(Rule::MaxRequestIdDecreased),
                RequestIdError::ExceedsMax(..) => Fault::Peer(Rule::RequestIdCeiling),
                RequestIdError::WrongParity(..) => Fault::Peer(Rule::RequestIdParity),
                RequestIdError::OutOfSequence { .. } => Fault::Peer(Rule::RequestIdOutOfSequence),
                // This endpoint has spent the budget the peer granted it.
                RequestIdError::Blocked => Fault::ThisEndpoint,
            },
        }
    }

    /// The code to close the session with, when draft-11 answers this error
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
            // Section 8.7 answers a SUBSCRIBE whose Track Alias already
            // names a different track with a session close, and Section 8.9
            // answers the retry alias a SUBSCRIBE_ERROR offers the same way.
            // Section 3.4 names this code for both.
            EndpointError::DuplicateTrackAlias { .. } => {
                Some(SessionErrorCode::DuplicateTrackAlias)
            }
            // Section 9 answers a track whose objects mix forwarding
            // preferences, and names this code in the same sentence: "it SHOULD
            // close the session with an error of 'Protocol Violation'".
            //
            // SHOULD, so the close is the caller's to make. The code lives here
            // and `Connection::close_for_data_stream` is what carries it, the
            // same opt-in every other rule broken on a data stream takes.
            EndpointError::MixedForwardingPreference { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // Section 9.1.1.1 answers an end-of-track object in the wrong place
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

/// Unified draft-11 MoQT endpoint wrapping session lifecycle, request ID
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
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    /// Subscriptions the peer opened with SUBSCRIBE, each from the moment its
    /// message arrived to the end of the flow.
    ///
    /// Separate from `subscriptions`, which holds the ones this endpoint
    /// opened. The two never collide on an identifier - Request IDs carry the
    /// allocating end's parity - but a subscription's state is read from
    /// whichever end drives it, and the two ends drive different messages.
    inbound_subscribes: HashMap<u64, InboundSubscribe>,
    /// Every FETCH the peer has sent, from arrival to the end of the fetch.
    ///
    /// Separate from `fetches`, which holds the ones this endpoint made. The
    /// record holds the FETCH itself and not only its state, because the
    /// answer is built out of the request: a Joining Fetch has to be judged
    /// against the subscription it names, and that name is nowhere else.
    inbound_fetches: HashMap<u64, InboundFetch>,
    /// Every Track Alias in use in this session, and the track each one names.
    ///
    /// "Already being used" is what makes this a table rather than a set: an
    /// alias whose subscription has ended is free again. The table records the
    /// binding and reads liveness back off the subscription's own state
    /// machine, rather than keeping a second copy of it that every path ending
    /// a subscription would have to remember to prune.
    /// What each track's objects have been framed as, so far.
    ///
    /// Behind a lock because this is the one endpoint fact a *data* stream
    /// settles, and the data plane reaches the endpoint through `&Connection`:
    /// a caller may hold one across tasks while it reads streams and datagrams,
    /// so there is no `&mut` to reach the rest of this struct with.
    forwarding_preferences: Mutex<TrackForwardingPreferences>,
    /// How far each track's objects have reached, so far.
    ///
    /// Behind an `Arc` rather than beside the rest of this struct because the
    /// objects that settle it are read off stream handles the caller owns, one
    /// at a time, with no way back to the endpoint. Each such stream is handed a
    /// clone of the handle, and every clone measures against this one record.
    locations: Arc<Mutex<TrackLocations>>,
    track_bindings: HashMap<u64, TrackBinding>,
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
    negotiated_version: Option<VarInt>,
    offered_versions: Vec<VarInt>,
    goaway_uri: Option<Vec<u8>>,
    /// The most recent `maximum_request_id` reported by the peer via a
    /// `REQUESTS_BLOCKED` message.
    peer_reported_max_request_id: Option<VarInt>,
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
    /// Create a new draft-11 endpoint for the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(role),
            advertised_max_id: 0,
            subscriptions: HashMap::new(),
            inbound_subscribes: HashMap::new(),
            inbound_fetches: HashMap::new(),
            track_bindings: HashMap::new(),
            forwarding_preferences: Mutex::new(TrackForwardingPreferences::new()),
            locations: Arc::new(Mutex::new(TrackLocations::new())),
            fetches: HashMap::new(),
            subscribe_announces: HashMap::new(),
            inbound_subscribe_announces: HashMap::new(),
            announces: HashMap::new(),
            inbound_announces: HashMap::new(),
            announce_ids: HashMap::new(),
            subscribe_announces_ids: HashMap::new(),
            track_statuses: HashMap::new(),
            inbound_track_statuses: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
            peer_reported_max_request_id: None,
        }
    }

    // ── Track aliases ──────────────────────────────────────────

    /// The request already using `alias` for a track other than (`namespace`,
    /// `name`), or `None` when the alias is free for that track.
    ///
    /// # Why the set is read rather than kept
    ///
    /// Section 8.7 says "already being used", and a subscription that has
    /// ended is not using anything. Asking each binding's own state machine is
    /// what makes an alias free again the instant its track's subscription
    /// ends, with nothing to prune on the way out - and a path that ended a
    /// subscription without telling this table would otherwise hold the alias
    /// forever and refuse the peer's next, conforming, use of it.
    ///
    /// # Why a binding for the same track is not a conflict
    ///
    /// The rule is about a Track Alias naming two tracks, not about naming one
    /// track twice. A second subscription to the track an alias already names
    /// breaks nothing this section states.
    fn alias_holder(&self, alias: u64, namespace: &TrackNamespace, name: &[u8]) -> Option<u64> {
        self.track_bindings.iter().find_map(|(&id, binding)| {
            let other_track = binding.namespace != *namespace || binding.name != name;
            (binding.alias == alias && other_track && self.binding_is_live(id, binding.kind))
                .then_some(id)
        })
    }

    /// The lowest Track Alias no live binding has given to a track.
    ///
    /// Drafts 07 through 11 make the **subscriber** choose the Track Alias, and
    /// require it to name one track per session; draft-12 moved the field to
    /// SUBSCRIBE_OK and made the choice the publisher's. A client spanning both
    /// eras therefore has to supply a value on these drafts and cannot on the
    /// later ones, so the value is read off the endpoint rather than asked of
    /// the caller: that is what lets
    /// [`crate::dispatch::AnyConnection::subscribe`] carry one signature across
    /// all the drafts instead of an argument that does nothing on nine of
    /// them.
    ///
    /// Read rather than kept, for the same reason the alias table beside it
    /// gives: a binding whose request has ended holds nothing, so an alias
    /// falls free when its subscription does and may name a different track
    /// next. A caller that mixes this with aliases of its own choosing stays
    /// correct by construction, because both read this one table — and
    /// `subscribe` refuses a duplicate before the alias reaches the wire
    /// either way.
    pub fn next_free_track_alias(&self) -> VarInt {
        let taken: std::collections::BTreeSet<u64> = self
            .track_bindings
            .iter()
            .filter(|(&id, binding)| self.binding_is_live(id, binding.kind))
            .map(|(_, binding)| binding.alias)
            .collect();
        let mut candidate = 0;
        while taken.contains(&candidate) {
            candidate += 1;
        }
        VarInt::from_u64_moqt(candidate)
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
            (binding.alias == alias && self.binding_is_live(id, binding.kind))
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
    /// report Section 9.1.1.1's protocol error when it says the track ended
    /// somewhere the track has already passed.
    ///
    /// `&self`, because the call site is the data plane's.
    pub fn note_received_object(
        &self,
        alias: u64,
        at: ObjectLocation,
        role: ObjectRole,
    ) -> Result<(), EndpointError> {
        let Some(objects) = self.track_objects(alias) else { return Ok(()) };
        objects.note(at, role).map_err(|placement| EndpointError::EndOfTrackOutOfPlace {
            alias,
            group: at.group,
            object: at.object,
            placement,
        })
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

    /// Whether the subscription that owns a binding is still standing.
    /// Subscribing counts as well as Active, which is what separates this draft
    /// from the next one: draft-12 Section 8.8 reads "a different track with an
    /// active subscription" and the alias arrives in the answer, so only an
    /// answered request holds one. Here the alias is in the SUBSCRIBE itself,
    /// and the sentence puts no qualifier on "already being used" - so it is in
    /// use from the moment that message is sent or received, and stays in use
    /// until the subscription ends.
    fn binding_is_live(&self, id: u64, kind: BindingKind) -> bool {
        let state = match kind {
            BindingKind::Ours => self.subscriptions.get(&id).map(|sm| sm.state()),
            BindingKind::Peers => self.inbound_subscribes.get(&id).map(|s| s.state.state()),
        };
        matches!(state, Some(SubscriptionState::Subscribing | SubscriptionState::Active))
    }

    /// The close Section 8.7 requires of an arriving SUBSCRIBE whose Track
    /// Alias is spoken for, or `None` when it is free.
    fn conflicting_track_alias(
        &self,
        id: u64,
        alias: u64,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<EndpointError> {
        let established = self.alias_holder(alias, namespace, name)?;
        Some(EndpointError::DuplicateTrackAlias { alias, established, offered: id })
    }

    /// The close Section 8.9 requires of a SUBSCRIBE_ERROR offering a Track
    /// Alias to retry with, or `None` when the offer can be taken up.
    ///
    /// The track is not in the SUBSCRIBE_ERROR: it is the one this endpoint's
    /// own SUBSCRIBE asked for, so the request has to be looked up before the
    /// alias offered for it can be judged. An offer of an alias this endpoint
    /// already holds for that same track is the retry succeeding, not a
    /// conflict.
    fn conflicting_retry_alias(&self, id: u64, alias: u64) -> Option<EndpointError> {
        let binding = self.track_bindings.get(&id)?;
        let established = self.alias_holder(alias, &binding.namespace, &binding.name)?;
        Some(EndpointError::DuplicateTrackAlias { alias, established, offered: id })
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
    /// Section 8.5: a Request ID "equal or larger than this" received by the
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
    /// [`EndpointError::MaxRequestIdWouldNotIncrease`] if the value does not
    /// strictly increase. Its own variant rather than the one a *received*
    /// ceiling that did not increase raises, so that a refusal to write is
    /// never read back as a peer in violation.
    pub fn send_max_request_id(&mut self, max_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let new_val = max_id.into_inner();
        if new_val <= self.advertised_max_id {
            return Err(EndpointError::MaxRequestIdWouldNotIncrease {
                advertised: self.advertised_max_id,
                offered: new_val,
            });
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
        track_alias: VarInt,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        if matches!(filter_type.into_inner(), 3 | 4) {
            return Err(EndpointError::FilterNeedsRange);
        }
        self.subscribe_inner(
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            None,
            None,
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
        track_alias: VarInt,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        start_location: Location,
        end_group: Option<VarInt>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        // 0x3 is AbsoluteStart and 0x4 is AbsoluteRange. The Filter Type is a
        // bare varint on this draft, so there is no enum to name them by.
        let filter_type = VarInt::from_u64(if end_group.is_some() { 4 } else { 3 }).unwrap();
        self.subscribe_inner(
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            Some(start_location),
            end_group,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn subscribe_inner(
        &mut self,
        track_alias: VarInt,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: VarInt,
        start_location: Option<Location>,
        end_group: Option<VarInt>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        // The alias travels in the SUBSCRIBE, so this is the last point at
        // which giving it to a second track can still be taken back. Refused
        // before the Request ID is allocated, so a refusal spends nothing.
        let alias = track_alias.into_inner();
        if let Some(held) = self.alias_holder(alias, &track_namespace, &track_name) {
            return Err(EndpointError::TrackAliasInUse { alias, held });
        }
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscriptionStateMachine::new();
        sm.on_subscribe_sent()?;
        self.subscriptions.insert(req_id.into_inner(), sm);
        self.track_bindings.insert(
            req_id.into_inner(),
            TrackBinding {
                namespace: track_namespace.clone(),
                name: track_name.clone(),
                alias,
                kind: BindingKind::Ours,
            },
        );

        let (start_group, start_object) = match start_location {
            Some(start) => (Some(start.group), Some(start.object)),
            None => (None, None),
        };
        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: req_id,
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            forward: Forward::Forward,
            filter_type,
            start_group,
            start_object,
            end_group,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ERROR.
    pub fn receive_subscribe_error(&mut self, msg: &SubscribeError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // Section 8.9 gives SUBSCRIBE_ERROR a Track Alias field with one
        // meaning: an alias to retry the SUBSCRIBE with. Judged before the
        // subscription is ended, because the request it names is what says
        // which track the offered alias would be for.
        if SubscribeErrorCode::from_u64(msg.error_code.into_inner())
            == Some(SubscribeErrorCode::RetryTrackAlias)
        {
            if let Some(conflict) = self.conflicting_retry_alias(id, msg.track_alias.into_inner()) {
                return Err(self.fail_session(conflict));
            }
        }
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE message for an active subscription.
    pub fn unsubscribe(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Send a SUBSCRIBE_UPDATE narrowing a subscription this endpoint opened.
    ///
    /// Section 8.10 gives the message to the subscriber, which is what this
    /// endpoint is for every subscription in `subscriptions`. No identifier is
    /// spent: the update's one identifier field names the subscription being
    /// modified rather than opening a request of its own.
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
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_update()?;
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
    /// Section 8.10: "A subscriber issues a SUBSCRIBE_UPDATE to a publisher to
    /// request a change to an existing subscription." One that arrives is
    /// therefore about a subscription the **peer** opened, which is why it is
    /// looked for among those and not among this endpoint's own.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UpdateForUnknownRequest`] when the identifier names no
    /// subscription the peer has opened in this session, and the subscription
    /// flow's own `InvalidTransition` when it names one that has already
    /// ended. Neither ends the session: Section 8.10 says SHOULD.
    pub fn receive_subscribe_update(&mut self, msg: &SubscribeUpdate) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sub = self
            .inbound_subscribes
            .get_mut(&id)
            .ok_or(EndpointError::UpdateForUnknownRequest(id))?;
        sub.state.on_subscribe_update_received()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_DONE (subscriber side — publisher finished).
    pub fn receive_subscribe_done(&mut self, msg: &SubscribeDone) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_done()?;
        Ok(())
    }

    // ── Answering a SUBSCRIBE the peer sent ────────────────────

    /// Process an incoming SUBSCRIBE, judging the Track Alias it carries and
    /// recording the subscription it opens.
    ///
    /// Section 8.7: "If the Track Alias is already being used for a different
    /// track, the publisher MUST close the session with a Duplicate Track
    /// Alias error". This endpoint is the publisher of a SUBSCRIBE that
    /// arrives, so this is where that close is raised. Judged before anything
    /// is written down, so a refused SUBSCRIBE leaves no binding behind.
    ///
    /// The Request ID has already been checked by [`Self::receive_request`],
    /// which every request message passes through before its own handler.
    ///
    /// # Errors
    ///
    /// [`EndpointError::DuplicateTrackAlias`] when the alias names a second
    /// track, with the session already moved to Closed.
    pub fn receive_subscribe(&mut self, msg: &Subscribe) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let alias = msg.track_alias.into_inner();
        if let Some(conflict) =
            self.conflicting_track_alias(id, alias, &msg.track_namespace, &msg.track_name)
        {
            return Err(self.fail_session(conflict));
        }
        let mut state = SubscriptionStateMachine::new();
        state.on_subscribe_received()?;
        self.inbound_subscribes.insert(id, InboundSubscribe { message: msg.clone(), state });
        self.track_bindings.insert(
            id,
            TrackBinding {
                namespace: msg.track_namespace.clone(),
                name: msg.track_name.clone(),
                alias,
                kind: BindingKind::Peers,
            },
        );
        Ok(())
    }

    /// The SUBSCRIBE the peer sent under `request_id` and this endpoint has
    /// not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session
    /// has no inbound subscription for.
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

    /// Build the SUBSCRIBE_OK accepting a subscription the peer opened.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it has
    /// already been answered.
    pub fn send_subscribe_ok(
        &mut self,
        request_id: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_subscribe_ok_sent()?;
        Ok(ControlMessage::SubscribeOk(SubscribeOk {
            request_id,
            expires,
            group_order,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters,
        }))
    }

    /// Build the SUBSCRIBE_ERROR rejecting a subscription the peer opened.
    ///
    /// The Track Alias goes back out with the refusal because Section 8.9
    /// gives the field a use: an alias to retry with, when the code is 'Retry
    /// Track Alias'. Under any other code the peer reads nothing from it.
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
        track_alias: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_subscribe_error_sent()?;
        Ok(ControlMessage::SubscribeError(SubscribeError {
            request_id,
            error_code,
            reason_phrase,
            track_alias,
        }))
    }

    /// Build the SUBSCRIBE_DONE ending a subscription this endpoint accepted.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it is not
    /// one this endpoint accepted and has not already ended.
    pub fn send_subscribe_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_subscribe_done_sent()?;
        Ok(ControlMessage::SubscribeDone(SubscribeDone {
            request_id,
            status_code,
            stream_count: VarInt::from_u64(0).unwrap(),
            reason_phrase,
        }))
    }

    /// Process an incoming UNSUBSCRIBE, ending the subscription the peer
    /// opened and freeing the Track Alias it held.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it is not
    /// one this endpoint accepted and has not already ended.
    pub fn receive_unsubscribe(&mut self, msg: &Unsubscribe) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
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
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Send a Relative Joining Fetch (Fetch Type 0x2), attaching a fetch to a
    /// subscription this session already holds. Allocates a Request ID.
    ///
    /// Section 8.13 calls it "A Fetch joined together with a Subscribe by
    /// specifying the Request ID of an active subscription and a relative
    /// starting offset", and has "A publisher receiving a Joining Fetch uses
    /// properties of the associated Subscribe to determine the Track
    /// Namespace, Track, Start Group, Start Object, End Group, and End Object
    /// such that it is contiguous with the associated Subscribe." So a joining
    /// fetch names neither the namespace nor the name, and `joining_start` is
    /// read against the subscription rather than against the track: Section
    /// 8.13.1 has the publisher compute "Fetch Start Group: Subscribe Largest
    /// Group - Joining start", which makes it a count of groups back from the
    /// live edge.
    ///
    /// The subscription is named by `joining_subscribe_id`, which is what this
    /// draft's field list calls the field although the sentence under it
    /// already reads "The Request ID of the existing subscription to be
    /// joined".
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the
    /// request-id error when this endpoint has no identifier left to spend. A
    /// Request ID naming no subscription is not refused here — Section 8.13
    /// answers that at the publisher, "it MUST respond with a Fetch Error with
    /// code Invalid Joining Subscribe ID", and this endpoint is the
    /// subscriber.
    pub fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_subscribe_id: VarInt,
        joining_start: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            FetchType::RelativeJoining,
            subscriber_priority,
            group_order,
            joining_subscribe_id,
            joining_start,
        )
    }

    /// Send an Absolute Joining Fetch (Fetch Type 0x3).
    ///
    /// Section 8.13.2 is the whole of the difference: "Identical to the
    /// Relative Joining fetch except that Fetch Start Group is the Joining
    /// Start value." So `joining_start` is the group to begin at rather than a
    /// count of groups back, which is what an application that knows the group
    /// it wants actually has. Asking for the same range relatively would need
    /// the Largest Group, and a subscriber that has not yet been told one
    /// cannot compute the offset.
    ///
    /// # Errors
    ///
    /// As [`Endpoint::joining_fetch`].
    pub fn absolute_joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_subscribe_id: VarInt,
        joining_start: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            FetchType::AbsoluteJoining,
            subscriber_priority,
            group_order,
            joining_subscribe_id,
            joining_start,
        )
    }

    /// What both calls above are, and why neither of them takes the type.
    ///
    /// Section 8.13 admits three Fetch Types and this payload carries two of
    /// them. A type taken as an argument here would leave a third value a
    /// caller could pass and this call would have to answer for; naming the
    /// two rules it out instead, so there is no answer left to get wrong.
    fn joining_fetch_of_type(
        &mut self,
        fetch_type: FetchType,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_subscribe_id: VarInt,
        joining_start: VarInt,
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
            fetch_payload: FetchPayload::Joining { joining_subscribe_id, joining_start },
            parameters: vec![],
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
    /// A Joining Fetch is recorded like any other. Section 8.13 answers one
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
    /// Section 8.13:
    /// "If a publisher receives a Joining Fetch with a Request ID that
    /// does not correspond to an existing Subscribe in the same session, it
    /// MUST respond with a Fetch Error with code Invalid Joining Subscribe ID."
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
        let message::FetchPayload::Joining { joining_subscribe_id: joined, .. } =
            &msg.fetch_payload
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
    /// fetch flow's own `InvalidTransition` for a second answer: Section 4
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
    /// Section 8.13 names the code a Joining Fetch naming an unjoinable
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
            let required = FetchErrorCode::InvalidJoiningSubscribeId as u64;
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
    /// Section 8.16: the subscriber sends it to stop a fetch it no longer
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
    /// Section 8.24 addresses the first half of the overlap rule to this end
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
                parameters: vec![],
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
    /// Section 8.24: "The subscriber sends the SUBSCRIBE_ANNOUNCES control
    /// message to a publisher to request the current set of matching
    /// announcements, as well as future updates to the set."
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
    /// Every one the peer has made counts, including one it has since
    /// withdrawn and one this endpoint refused: the sentence weighs the
    /// arriving prefix against "an earlier SUBSCRIBE_ANNOUNCES", and one that
    /// has ended was still earlier. Draft-12 changes that word to "active",
    /// and there a subscription that has ended stops counting.
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
    /// Section 8.27 names a Track Namespace Prefix where the
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
            ControlMessage::Announce(Announce {
                request_id: req_id,
                track_namespace,
                parameters: vec![],
            }),
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
    /// Section 8.19: "The publisher sends the ANNOUNCE control message to
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
    /// Section 8.22: "The publisher sends the UNANNOUNCE control message to
    /// indicate its intent to stop serving new subscriptions for tracks within
    /// the provided Track Namespace." and Section 8.23 says what a cancellation
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
    /// Section 8.22: "The publisher sends the UNANNOUNCE control message to
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
    /// previously responded ANNOUNCE_OK to". Section 8.23 says what it does:
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
                parameters: vec![],
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
    /// Section 8.17: "A potential subscriber sends a 'TRACK_STATUS_REQUEST'
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
    /// Section 8.17 leaves the answering end no discretion about whether to
    /// answer: "A TRACK_STATUS message MUST be sent in response to each
    /// TRACK_STATUS_REQUEST." What it bounds is how many, and that half is what
    /// the record carries: the request leaves `Pending` on the first answer, so
    /// a second call finds nothing left to answer.
    ///
    /// Section 8.18 says the identifier this message carries is "The Request ID
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
    /// Draft-11 renames draft-10's SUBSCRIBES_BLOCKED to REQUESTS_BLOCKED so
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
    /// This is where [`Self::validate_peer_request_id`] is applied to arriving
    /// traffic, and the only place inside the endpoint that applies it. A
    /// request message the list below omits is one whose Request ID is checked
    /// for nothing: not its parity, not the ceiling this endpoint advertised,
    /// not its place in the peer's sequence.
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
    /// nothing else does. That is what makes the list load-bearing, because
    /// the sequence is tracked: a request left out of it spends an ID
    /// this endpoint never counts, so the peer's **next** request looks like a
    /// skip and a conforming session is closed over it.
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
            ControlMessage::Announce(ref m) => self.receive_announce(m),
            ControlMessage::Unannounce(ref m) => self.receive_unannounce(m),
            ControlMessage::SubscribeAnnounces(ref m) => self.receive_subscribe_announces(m),
            ControlMessage::UnsubscribeAnnounces(ref m) => self.receive_unsubscribe_announces(m),
            _ => Ok(()),
        }
    }
}

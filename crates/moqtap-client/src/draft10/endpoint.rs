use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::draft10::fetch::{FetchError, FetchState, FetchStateMachine};
use crate::draft10::namespace::{
    AnnounceState, AnnounceStateMachine, NamespaceError, SubscribeAnnouncesState,
    SubscribeAnnouncesStateMachine,
};
use crate::draft10::session::setup::{self, SetupError};
use crate::draft10::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft10::session::subscribe_id::{SubscribeIdAllocator, SubscribeIdError};
use crate::draft10::subscription::{
    SubscriptionError, SubscriptionState, SubscriptionStateMachine,
};
use crate::draft10::track_status::{TrackStatusError, TrackStatusState, TrackStatusStateMachine};
use crate::forwarding_preference::{ObjectForwardingPreference, TrackForwardingPreferences};
use crate::track_locations::{
    EndOfTrackPlacement, ObjectLocation, ObjectRole, TrackLocations, TrackObjects,
};
use moqtap_codec::draft10::error_codes::{SessionErrorCode, SubscribeErrorCode};
use moqtap_codec::draft10::message::{
    self, Announce, AnnounceCancel, AnnounceError, AnnounceOk, ClientSetup, ControlMessage, Fetch,
    FetchCancel, FetchType, GoAway, MaxSubscribeId, ServerSetup, Subscribe, SubscribeAnnounces,
    SubscribeAnnouncesError, SubscribeAnnouncesOk, SubscribeDone, SubscribeError, SubscribeOk,
    SubscribeUpdate, SubscribesBlocked, TrackStatus, TrackStatusRequest, Unannounce, Unsubscribe,
    UnsubscribeAnnounces,
};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Key identifying a namespace (used for Announce / SubscribeAnnounces maps).
type NamespaceKey = Vec<Vec<u8>>;

/// Key identifying a track (namespace + track name).
type TrackKey = (Vec<Vec<u8>>, Vec<u8>);

/// Which side of the session this endpoint is.
///
/// This draft has no Request ID parity and no ROLE parameter, so the only rule
/// that turns on the answer is the one in Section 8.3 about which side may
/// send a GOAWAY that carries a New Session URI. It lives here rather than
/// beside the Subscribe ID allocator for that reason: a Subscribe ID on this
/// draft is a session-wide counter and does not depend on who allocates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The endpoint that opened the session.
    Client,
    /// The endpoint that accepted it.
    Server,
}

/// Errors that can occur during draft-10 endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A GOAWAY carrying a New Session URI arrived at a server.
    ///
    /// Section 8.3: "If a server receives a GOAWAY with a non-zero New
    /// Session URI Length it MUST terminate the session with a Protocol
    /// Violation." Migration is something a server offers a client, never the
    /// other way round.
    #[error("GOAWAY carrying a New Session URI received at a server")]
    GoAwayUriAtServer,
    /// A session-level state machine error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    /// A subscribe ID allocation or validation error.
    #[error("subscribe ID error: {0}")]
    SubscribeId(#[from] SubscribeIdError),
    /// This endpoint was asked to advertise a Maximum Subscribe ID that does
    /// not increase, and refused. Nothing was written.
    ///
    /// The send-side mirror of the rule a peer breaks by sending one — Section 8.4:
    /// "The Maximum Subscribe Id MUST only increase within a session". No closing
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
        "the Maximum Subscribe ID already advertised is {advertised}, so {offered} would not increase it"
    )]
    MaxSubscribeIdWouldNotIncrease {
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
    /// The subscribe ID does not match any known state machine.
    #[error("unknown subscribe ID: {0}")]
    UnknownSubscribe(u64),
    /// The track namespace does not match any known state machine.
    #[error("unknown namespace")]
    UnknownNamespace,
    /// The (namespace, track) pair does not match any known track status request.
    #[error("unknown track status request")]
    UnknownTrackStatus,
    /// A message about a track status named a track the peer has not asked
    /// about.
    ///
    /// Section 8.16 makes the request the subscriber's: "A potential subscriber
    /// sends a 'TRACK_STATUS_REQUEST' message on the control stream to obtain
    /// information about the current status of a given track." What an answer
    /// answers is therefore a request the **peer** made, so the record it
    /// reaches for is the one this endpoint keeps of what the peer has asked
    /// about.
    ///
    /// Separate from [`EndpointError::UnknownTrackStatus`], which is the same
    /// miss on the requests this endpoint made, so a caller can tell which of
    /// the two maps came up empty.
    #[error("the peer has asked for no status of this track")]
    UnknownPeerTrackStatus,
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
    /// A setup parameter's value could not be read as the type its key implies.
    #[error("setup parameter {0:#x} has a malformed value")]
    MalformedSetupParameter(
        /// Key of the offending parameter.
        u64,
    ),
    /// A Subscribe ID the peer chose did not increase on the last one it used.
    #[error("peer subscribe ID {0} does not increase on {1}")]
    PeerSubscribeIdNotIncreasing(
        /// The Subscribe ID that arrived.
        u64,
        /// The highest Subscribe ID the peer had used before it.
        u64,
    ),
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
    /// Section 8.6, on the Track Alias the subscriber chooses in SUBSCRIBE:
    /// "If the Track Alias is already being used for a different track, the
    /// publisher MUST close the session with a Duplicate Track Alias error".
    /// Section 8.8 states the other end of the same rule, on the alias a
    /// SUBSCRIBE_ERROR may offer to retry with: "If this Track Alias is
    /// already in use, the subscriber MUST close the connection with a
    /// Duplicate Track Alias error".
    ///
    /// The session is over: this endpoint's own state has moved to Closed and
    /// the code the transport should close with is in
    /// [`EndpointError::session_error_code`].
    #[error(
        "track alias {alias} already names the track of {established_side} subscribe \
         {established}; {offered_side} subscribe {offered} names a different one"
    )]
    DuplicateTrackAlias {
        /// The alias both tracks are named by.
        alias: u64,
        /// Which end opened the subscription that holds the alias.
        established_side: SubscribeSide,
        /// That subscription's identifier, in its own end's sequence.
        established: u64,
        /// Which end opened the subscription naming it for another track.
        offered_side: SubscribeSide,
        /// That subscription's identifier, in its own end's sequence.
        offered: u64,
    },
    /// This endpoint was asked to give a Track Alias to a second track.
    ///
    /// The same rule as [`EndpointError::DuplicateTrackAlias`] read at the end
    /// that chooses the alias. Section 3.4 describes the code as "The
    /// endpoint attempted to use a Track Alias that was already in use", and
    /// Section 8.6 says what the receiving publisher does about it, so a
    /// SUBSCRIBE built this way is one the peer must answer by ending the
    /// session.
    ///
    /// The message is refused instead, and nothing else moves: no Subscribe ID
    /// is spent, no subscription is created, and the session stays as it was.
    /// The alias never reaches the peer, so there is nothing for the peer to
    /// close over.
    #[error("track alias {alias} already names the track of {side} subscribe {held}")]
    TrackAliasInUse {
        /// The alias that is already spoken for.
        alias: u64,
        /// Which end opened the subscription holding it.
        side: SubscribeSide,
        /// That subscription's identifier, in its own end's sequence.
        held: u64,
    },
    /// A track's objects were framed two different ways.
    ///
    /// Section 9: "Every Track has a single 'Object Forwarding Preference' and
    /// the Original Publisher MUST NOT mix different forwarding preferences
    /// within a single track. If a subscriber receives different forwarding
    /// preferences for a track, it SHOULD close the session with an error of
    /// 'Protocol Violation'."
    ///
    /// The framing is the preference: an object on a subgroup stream has the
    /// Subgroup preference and an object in a datagram has the Datagram one,
    /// so the track's first object settles the property and this is every
    /// later object measured against it.
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
    /// Section 9.1.1.1 describes Object Status 0x4, end of Track and
    /// Group, as one whose "GroupID is the largest group produced in this
    /// track and the ObjectId is one greater than the largest object
    /// produced in that group", and states the consequence: "An object with
    /// this status that has a Group ID less than any other Group ID, or an
    /// Object ID less than or equal to the largest in the group, is a
    /// protocol error, and the receiver MUST terminate the session."
    ///
    /// Status 0x5, end of Track, is one notch stricter in the same
    /// paragraph: "An object with this status that has a Group ID less than
    /// or equal to any other Group ID, or an Object ID other than zero, is a
    /// protocol error, and the receiver MUST terminate the session." Its
    /// Object-ID half needs no record and the codec refuses it on the header;
    /// its Group ID half is this.
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
    /// Section 8.9: "A publisher SHOULD close the Session as a 'Protocol
    /// Violation' if the SUBSCRIBE_UPDATE violates either rule or if the
    /// subscriber specifies a Subscribe ID that has not existed within the Session."
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
    #[error("SUBSCRIBE_UPDATE names subscribe {0}, which no subscription the peer opened has had")]
    UpdateForUnknownSubscribe(u64),

    /// A Joining Fetch named a subscription this session cannot join.
    ///
    /// Section 8.12: "If a publisher receives a Joining Fetch with a Subscribe ID
    /// that does not correspond to an existing Subscribe, it MUST respond with
    /// a Fetch Error."
    ///
    /// A refusal and not a session close, so the session runs on and the error
    /// names both identifiers: the fetch to refuse, and the subscription it
    /// asked to join.
    #[error(
        "FETCH {fetch} joins subscribe {joining}, which is no live subscription of the peer's"
    )]
    UnjoinableSubscription {
        /// The fetch that named it.
        fetch: u64,
        /// The identifier it named.
        joining: u64,
    },
    /// A message about an announcement named a namespace the peer has not
    /// announced.
    ///
    /// Section 8.22 says what a cancellation is for: the subscriber "will stop
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
    /// Section 8.23: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session. Within a session, if a publisher
    /// receives a SUBSCRIBE_ANNOUNCES with a Track Namespace Prefix that is a
    /// prefix of an earlier SUBSCRIBE_ANNOUNCES or vice versa, it MUST
    /// respond with SUBSCRIBE_ANNOUNCES_ERROR, with error code
    /// SUBSCRIBE_ANNOUNCES_OVERLAP."
    ///
    /// The request is refused where it arrives and nothing is written down for
    /// it, which is the only outcome this draft can express. SUBSCRIBE_ANNOUNCES
    /// carries no Request ID here, so the acceptance, the refusal and the
    /// withdrawal all name a Track Namespace Prefix and nothing else. Two
    /// namespace subscriptions under one prefix would therefore have answers
    /// that cannot be told apart, and an equal prefix is the first case the
    /// sentence above names.
    ///
    /// The code the sentence gives the refusal, SUBSCRIBE_ANNOUNCES_OVERLAP, is
    /// named in prose and appears in no registry this draft defines, so there
    /// is no number for this crate to put on the wire. A caller that wants to
    /// send the refusal builds it from the message it has just been handed.
    #[error("the namespace prefix the peer subscribed to overlaps one it already has")]
    PeerPrefixOverlap,
    /// This endpoint was asked to subscribe to a namespace prefix overlapping
    /// one it is already subscribed to.
    ///
    /// The first half of the same sentence, which is addressed to the
    /// subscriber: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session."
    ///
    /// The message is refused instead of built, and nothing else moves: no
    /// state machine is created and the session stays as it was. The request
    /// never reaches the peer, so there is nothing for the peer to refuse.
    ///
    /// A subscription that has been withdrawn still counts, because the
    /// publisher's half of the sentence weighs a new prefix against "an
    /// earlier SUBSCRIBE_ANNOUNCES" rather than against a live one. Drafts
    /// from 12 on say "active" instead, and there a withdrawn one stops
    /// counting.
    #[error("the namespace prefix overlaps one this endpoint is already subscribed to")]
    OwnPrefixOverlap,
}

/// Whether two namespace prefixes overlap.
///
/// Section 8.23: "A subscriber cannot make overlapping namespace
/// subscriptions on a single session. Within a session, if a publisher
/// receives a SUBSCRIBE_ANNOUNCES with a Track Namespace Prefix that is a
/// prefix of an earlier SUBSCRIBE_ANNOUNCES or vice versa, it MUST respond
/// with SUBSCRIBE_ANNOUNCES_ERROR, with error code
/// SUBSCRIBE_ANNOUNCES_OVERLAP."
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

/// Which end of the session opened a subscription.
///
/// It takes this and an identifier together to name one on this draft. Each
/// end allocates Subscribe IDs from zero, nothing in the draft separates the
/// two sequences, and this endpoint keeps the peer's apart from its own - so
/// the peer's subscribe 3 and this endpoint's subscribe 3 are two
/// subscriptions, not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscribeSide {
    /// A SUBSCRIBE this endpoint sent, carrying the alias it chose.
    Ours,
    /// A SUBSCRIBE the peer sent, carrying the alias the peer chose.
    Peers,
}

impl std::fmt::Display for SubscribeSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscribeSide::Ours => f.write_str("our"),
            SubscribeSide::Peers => f.write_str("the peer's"),
        }
    }
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

/// A Track Alias attached to a Full Track Name, and nothing else: the
/// subscription whose lifetime the attachment follows is the map's key.
///
/// SUBSCRIBE carries the alias and the track in the one message, whichever end
/// sends it, so a binding is complete from the moment it is made. That stops
/// being true at draft-12, where the alias arrives in the answer instead.
#[derive(Debug, Clone)]
struct TrackBinding {
    namespace: TrackNamespace,
    name: Vec<u8>,
    alias: u64,
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
            | EndpointError::UnknownSubscribe(..)
            | EndpointError::UnknownNamespace
            | EndpointError::UnknownPeerNamespace
            | EndpointError::UnknownPeerNamespaceSubscription => Fault::EitherEnd,

            // Raised on the way out. Nothing reached the wire, so none of
            // these is evidence about a peer — including the ones a peer
            // caused, where what failed is this side's attempt to accept
            // something the draft says to refuse.
            EndpointError::MaxSubscribeIdWouldNotIncrease { .. }
            | EndpointError::UnknownPeerTrackStatus
            | EndpointError::NotActive
            | EndpointError::Draining
            | EndpointError::FilterNeedsRange
            | EndpointError::TrackAliasInUse { .. }
            | EndpointError::UnjoinableSubscription { .. }
            | EndpointError::OwnPrefixOverlap => Fault::ThisEndpoint,

            // Raised reading what the peer sent.
            EndpointError::DuplicateTrackAlias { .. } => Fault::Peer(Rule::DuplicateTrackAlias),
            EndpointError::EndOfTrackOutOfPlace { .. } => Fault::Peer(Rule::EndOfTrackOutOfPlace),
            EndpointError::GoAwayUriAtServer => Fault::Peer(Rule::GoAwayAtServer),
            EndpointError::UnknownTrackStatus => Fault::Peer(Rule::MessageNamesAnUnknownRequest),
            EndpointError::MixedForwardingPreference { .. } => {
                Fault::Peer(Rule::MixedForwardingPreference)
            }
            EndpointError::PeerPrefixOverlap => Fault::Peer(Rule::NamespacePrefixOverlap),
            EndpointError::RepeatedGoAway => Fault::Peer(Rule::RepeatedGoAway),
            EndpointError::PeerSubscribeIdNotIncreasing(..) => {
                Fault::Peer(Rule::RequestIdOutOfSequence)
            }
            EndpointError::UpdateForUnknownSubscribe(..) => {
                Fault::Peer(Rule::RequestUpdateForTheWrongRequest)
            }
            EndpointError::MalformedSetupParameter(..) => Fault::Peer(Rule::SetupParameterValue),

            // The ceiling rules, which are the peer's whenever they are read
            // off the wire. The mirror — this endpoint asked to advertise a
            // ceiling that does not increase — is
            // `MaxSubscribeIdWouldNotIncrease` above, which is a variant of its
            // own so that the two never arrive as one value.
            EndpointError::SubscribeId(e) => match e {
                SubscribeIdError::Decreased(..) => Fault::Peer(Rule::MaxRequestIdDecreased),
                SubscribeIdError::ExceedsMax(..) => Fault::Peer(Rule::RequestIdCeiling),
                // This endpoint has spent the budget the peer granted it.
                SubscribeIdError::Blocked => Fault::ThisEndpoint,
            },
        }
    }

    /// The code to close the session with, when draft-10 answers this error
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
            // Section 8.4 answers a ceiling that does not increase with a
            // close, and names this code for it.
            EndpointError::SubscribeId(SubscribeIdError::Decreased(..)) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // The same section answers a Subscribe ID that reaches the ceiling
            // this endpoint advertised, and names a different code for it.
            EndpointError::SubscribeId(SubscribeIdError::ExceedsMax(..)) => {
                Some(SessionErrorCode::TooManySubscribes)
            }
            // Section 8.3 answers a GOAWAY that repeats one already
            // received, and names this code in the same sentence.
            EndpointError::RepeatedGoAway => Some(SessionErrorCode::ProtocolViolation),
            // The same section answers a migration URI arriving at a server
            // with a close, and names this code for it. Only a server may
            // offer one, so a client that sends one is telling a server where
            // to reconnect, which it has no standing to do.
            EndpointError::GoAwayUriAtServer => Some(SessionErrorCode::ProtocolViolation),
            // Section 8.6 answers a SUBSCRIBE whose Track Alias already
            // names a different track with a session close, and Section 8.8
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

/// Unified draft-10 MoQT endpoint wrapping session lifecycle, subscribe ID
/// allocation, and all per-flow state machines (subscriptions, fetches,
/// announces, subscribe-announces, track statuses).
pub struct Endpoint {
    /// Which side of the session this is. Read only by the GOAWAY rule.
    role: Role,
    session: SessionStateMachine,
    subscribe_ids: SubscribeIdAllocator,
    /// Tracks the MAX_SUBSCRIBE_ID we have advertised to the peer.
    advertised_max_id: u64,
    /// The highest Subscribe ID the peer has used, once it has used one.
    peer_highest_subscribe_id: Option<u64>,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    /// Subscriptions the peer opened with SUBSCRIBE, each from the moment its
    /// message arrived to the end of the flow.
    ///
    /// Separate from `subscriptions`, which holds the ones this endpoint
    /// opened, because the identifiers do not separate themselves: see
    /// [`SubscribeSide`].
    inbound_subscribes: HashMap<u64, InboundSubscribe>,
    /// Every FETCH the peer has sent, from arrival to the end of the fetch.
    ///
    /// Separate from `fetches`, which holds the ones this endpoint made,
    /// because the identifiers do not separate themselves: both ends allocate
    /// from zero, so one number can name a fetch at each end at once.
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
    track_bindings: HashMap<(SubscribeSide, u64), TrackBinding>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_announces: HashMap<NamespaceKey, SubscribeAnnouncesStateMachine>,
    /// Namespace subscriptions the **peer** made, keyed by the prefix each
    /// one names.
    ///
    /// The prefix is the whole of a request's name on this draft: the
    /// acceptance, the refusal and the withdrawal all carry a Track Namespace
    /// Prefix and nothing else, so one prefix has one record here. A second
    /// SUBSCRIBE_ANNOUNCES under a prefix already subscribed replaces it, which is
    /// a case Section 5.1 forbids rather than one this map decides.
    inbound_subscribe_announces: HashMap<NamespaceKey, InboundSubscribeAnnounces>,
    announces: HashMap<NamespaceKey, AnnounceStateMachine>,
    /// Announcements the **peer** made, keyed by the namespace each
    /// names, which is all this draft's ANNOUNCE carries to name it by.
    inbound_announces: HashMap<NamespaceKey, InboundAnnounce>,
    track_statuses: HashMap<TrackKey, TrackStatusStateMachine>,
    /// Track statuses the **peer** asked about, keyed by the track each names.
    ///
    /// Kept apart from `track_statuses`, which holds the ones this endpoint
    /// asked about: the two are answered by opposite ends. This draft's
    /// TRACK_STATUS_REQUEST carries no identifier of its own, so the track it
    /// names is the only thing an answer can be matched to, which is the key
    /// the outbound map is under for the same reason.
    inbound_track_statuses: HashMap<TrackKey, InboundTrackStatus>,
    negotiated_version: Option<VarInt>,
    offered_versions: Vec<VarInt>,
    goaway_uri: Option<Vec<u8>>,
    /// The most recent `maximum_subscribe_id` reported by the peer via a
    /// `SUBSCRIBES_BLOCKED` message.
    peer_reported_max_subscribe_id: Option<VarInt>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new(Role::Client)
    }
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
}
impl Endpoint {
    /// Create a new draft-10 endpoint for the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            subscribe_ids: SubscribeIdAllocator::new(),
            advertised_max_id: 0,
            peer_highest_subscribe_id: None,
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
            track_statuses: HashMap::new(),
            inbound_track_statuses: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
            peer_reported_max_subscribe_id: None,
        }
    }

    // ── Track aliases ──────────────────────────────────────────

    /// The subscription already using `alias` for a track other than
    /// (`namespace`, `name`), or `None` when the alias is free for that track.
    ///
    /// # Why the set is read rather than kept
    ///
    /// Section 8.6 says "already being used", and a subscription that has
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
    fn alias_holder(
        &self,
        alias: u64,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<(SubscribeSide, u64)> {
        self.track_bindings.iter().find_map(|(&key, binding)| {
            let other_track = binding.namespace != *namespace || binding.name != name;
            (binding.alias == alias && other_track && self.binding_is_live(key)).then_some(key)
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
            .filter(|(&key, _)| self.binding_is_live(key))
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
        self.track_bindings.iter().find_map(|(&key, binding)| {
            (binding.alias == alias && self.binding_is_live(key))
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
    /// from draft-12 Section 8.8 onwards: there the sentence is "a different
    /// track with an active subscription" and the alias arrives in the answer,
    /// so only an answered request holds one. Here the alias is in the
    /// SUBSCRIBE itself, and the sentence puts no qualifier on "already being
    /// used" - so it is in use from the moment that message is sent or
    /// received, and stays in use until the subscription ends.
    fn binding_is_live(&self, key: (SubscribeSide, u64)) -> bool {
        let state = match key.0 {
            SubscribeSide::Ours => self.subscriptions.get(&key.1).map(|sm| sm.state()),
            SubscribeSide::Peers => self.inbound_subscribes.get(&key.1).map(|s| s.state.state()),
        };
        matches!(state, Some(SubscriptionState::Subscribing | SubscriptionState::Active))
    }

    /// The close Section 8.6 requires of an arriving SUBSCRIBE whose Track
    /// Alias is spoken for, or `None` when it is free.
    fn conflicting_track_alias(
        &self,
        side: SubscribeSide,
        id: u64,
        alias: u64,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<EndpointError> {
        let (established_side, established) = self.alias_holder(alias, namespace, name)?;
        Some(EndpointError::DuplicateTrackAlias {
            alias,
            established_side,
            established,
            offered_side: side,
            offered: id,
        })
    }

    /// The close Section 8.8 requires of a SUBSCRIBE_ERROR offering a Track
    /// Alias to retry with, or `None` when the offer can be taken up.
    ///
    /// The track is not in the SUBSCRIBE_ERROR: it is the one this endpoint's
    /// own SUBSCRIBE asked for, so the request has to be looked up before the
    /// alias offered for it can be judged. An offer of an alias this endpoint
    /// already holds for that same track is the retry succeeding, not a
    /// conflict.
    fn conflicting_retry_alias(&self, id: u64, alias: u64) -> Option<EndpointError> {
        let binding = self.track_bindings.get(&(SubscribeSide::Ours, id))?;
        let (established_side, established) =
            self.alias_holder(alias, &binding.namespace, &binding.name)?;
        Some(EndpointError::DuplicateTrackAlias {
            alias,
            established_side,
            established,
            offered_side: SubscribeSide::Ours,
            offered: id,
        })
    }

    // ── Accessors ──────────────────────────────────────────────

    /// Returns which side of the session this endpoint is.
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

    /// Returns whether this endpoint is blocked on subscribe ID allocation.
    pub fn is_blocked(&self) -> bool {
        self.subscribe_ids.is_blocked()
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
        self.record_advertised_max(&msg.parameters);
        Ok(ControlMessage::ClientSetup(msg))
    }

    /// Process a SERVER_SETUP message (client-side). Transitions to Active.
    /// If the server includes a MAX_SUBSCRIBE_ID parameter (key 0x02), the
    /// subscribe ID allocator is initialized with that value.
    pub fn receive_server_setup(&mut self, msg: &ServerSetup) -> Result<(), EndpointError> {
        setup::validate_server_setup(msg)?;
        let version = setup::negotiate_version(&self.offered_versions, msg.selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        self.read_granted_max(&msg.parameters)?;
        Ok(())
    }

    // ── Server setup ───────────────────────────────────────────

    /// Process CLIENT_SETUP and generate SERVER_SETUP (server-side).
    pub fn receive_client_setup_and_respond(
        &mut self,
        client_setup: &ClientSetup,
        selected_version: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        self.receive_client_setup_and_respond_with(client_setup, selected_version, Vec::new())
    }

    /// Process CLIENT_SETUP and generate SERVER_SETUP carrying `parameters`.
    ///
    /// The form that can answer with a MAX_SUBSCRIBE_ID. Section 8.2.2.2
    /// describes the parameter as communicating "an initial value for the
    /// Maximum Subscribe ID to the receiving subscriber. The default value is
    /// 0, so if not specified, the peer MUST NOT create subscriptions" - so a
    /// server that never sends it has told the client it may not subscribe,
    /// and every SUBSCRIBE the client tries is answered Blocked until a
    /// MAX_SUBSCRIBE_ID message arrives.
    ///
    /// A MAX_SUBSCRIBE_ID among `parameters` is recorded as the ceiling this
    /// endpoint has advertised, which is the number a peer's Subscribe IDs are
    /// measured against.
    ///
    /// # Errors
    ///
    /// The setup errors, and a malformed MAX_SUBSCRIBE_ID in the CLIENT_SETUP.
    pub fn receive_client_setup_and_respond_with(
        &mut self,
        client_setup: &ClientSetup,
        selected_version: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        setup::validate_client_setup(client_setup)?;
        // Section 8.2.2.2 puts no role restriction on MAX_SUBSCRIBE_ID, so a
        // CLIENT_SETUP may carry it and it grants this endpoint its budget.
        self.read_granted_max(&client_setup.parameters)?;
        let version = setup::negotiate_version(&client_setup.supported_versions, selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        self.record_advertised_max(&parameters);
        let msg = ServerSetup { selected_version: version, parameters };
        Ok(ControlMessage::ServerSetup(msg))
    }

    /// Take the budget a peer's setup parameters grant this endpoint.
    ///
    /// An explicit 0 is the same as the parameter's absence - Section
    /// 8.2.2.2 gives it a default of 0 - so it is not put through the
    /// only-increase rule, which belongs to the MAX_SUBSCRIBE_ID message.
    fn read_granted_max(&mut self, parameters: &[KeyValuePair]) -> Result<(), EndpointError> {
        for param in parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                let max = setup::setup_varint(&param.value)
                    .ok_or(EndpointError::MalformedSetupParameter(0x02))?;
                if max > 0 {
                    self.subscribe_ids.update_max(max)?;
                }
            }
        }
        Ok(())
    }

    /// Record a MAX_SUBSCRIBE_ID parameter this endpoint is about to send as
    /// the ceiling it has advertised to the peer.
    ///
    /// The peer's Subscribe IDs are bound by this number, and this endpoint's
    /// own by the one the peer advertised. The two are different values and
    /// measuring against the wrong one accepts ids a conforming peer would
    /// never send and refuses ids it may.
    fn record_advertised_max(&mut self, parameters: &[KeyValuePair]) {
        for param in parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                if let Some(max) = setup::setup_varint(&param.value) {
                    self.advertised_max_id = max;
                }
            }
        }
    }

    /// Hold a Subscribe ID the peer chose to the rules Section 8.6
    /// states about it.
    ///
    /// "Subscribe ID is a variable length integer that MUST be unique and
    /// monotonically increasing within a session and MUST be less than the
    /// session's Maximum Subscribe ID", and Section 8.12 repeats the
    /// first half for FETCH - so the two share one sequence and are checked
    /// together here.
    ///
    /// The ceiling is the one **this** endpoint advertised, not the one the
    /// peer granted us: those are different numbers, and either may be the
    /// larger. Strictly increasing gives uniqueness as well, so one high-water
    /// mark answers both halves of the sentence.
    ///
    /// # The ceiling is a session rule, not a request rule
    ///
    /// Section 8.4: "If a Subscribe ID equal or larger than this is received
    /// by the publisher that sent the MAX_SUBSCRIBE_ID, the publisher MUST
    /// close the session with an error of 'Too Many Subscribes'." Which is
    /// also why the number measured against is the one **this** endpoint
    /// sent. An id that reaches the ceiling is not a SUBSCRIBE to refuse with
    /// a SUBSCRIBE_ERROR: the session is over, so this moves the endpoint's
    /// own state to Closed and leaves the code to
    /// [`EndpointError::session_error_code`].
    ///
    /// # Errors
    ///
    /// [`SubscribeIdError::ExceedsMax`] if the id reaches the advertised
    /// ceiling, and [`EndpointError::PeerSubscribeIdNotIncreasing`] if it does
    /// not increase on the last one the peer used.
    pub fn validate_peer_subscribe_id(&mut self, id: u64) -> Result<(), EndpointError> {
        if id >= self.advertised_max_id {
            return Err(self.fail_session(EndpointError::SubscribeId(
                SubscribeIdError::ExceedsMax(id, self.advertised_max_id),
            )));
        }
        if let Some(highest) = self.peer_highest_subscribe_id {
            if id <= highest {
                return Err(EndpointError::PeerSubscribeIdNotIncreasing(id, highest));
            }
        }
        self.peer_highest_subscribe_id = Some(id);
        Ok(())
    }

    /// Process an incoming SUBSCRIBE, checking the Subscribe ID the peer chose.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate_peer_subscribe_id`] answers.
    pub fn receive_subscribe(&mut self, msg: &Subscribe) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        self.validate_peer_subscribe_id(id)?;
        // Section 8.6: "If the Track Alias is already being used for a
        // different track, the publisher MUST close the session with a
        // Duplicate Track Alias error". This endpoint is the publisher of a
        // SUBSCRIBE that arrives, so this is where that close is raised.
        // Judged before anything is written down, so a refused SUBSCRIBE
        // leaves no binding behind.
        let alias = msg.track_alias.into_inner();
        if let Some(conflict) = self.conflicting_track_alias(
            SubscribeSide::Peers,
            id,
            alias,
            &msg.track_namespace,
            &msg.track_name,
        ) {
            return Err(self.fail_session(conflict));
        }
        let mut state = SubscriptionStateMachine::new();
        state.on_subscribe_received()?;
        self.inbound_subscribes.insert(id, InboundSubscribe { message: msg.clone(), state });
        self.track_bindings.insert(
            (SubscribeSide::Peers, id),
            TrackBinding {
                namespace: msg.track_namespace.clone(),
                name: msg.track_name.clone(),
                alias,
            },
        );
        Ok(())
    }

    // ── MAX_SUBSCRIBE_ID ───────────────────────────────────────

    /// Process an incoming MAX_SUBSCRIBE_ID message, ending the session if the
    /// ceiling it carries does not increase.
    /// Section 8.4: "The Maximum Subscribe Id MUST only increase within a
    /// session, and receipt of a MAX_SUBSCRIBE_ID message with an equal or
    /// smaller Subscribe ID value is a 'Protocol Violation'." Section 3.4 lists
    /// Protocol Violation among the codes for terminating the session - "The
    /// remote endpoint performed an action that was disallowed by the
    /// specification" - so naming it of a *receipt* is this draft saying the
    /// session ends, and with which code. Draft-16 Section 9.5 states the same
    /// rule with the verb in it: "it MUST close the session with a
    /// PROTOCOL_VIOLATION".
    ///
    /// # Errors
    ///
    /// [`SubscribeIdError::Decreased`] if the value does not increase, with
    /// the session already moved to Closed.
    pub fn receive_max_subscribe_id(&mut self, msg: &MaxSubscribeId) -> Result<(), EndpointError> {
        if let Err(err) = self.subscribe_ids.update_max(msg.subscribe_id.into_inner()) {
            return Err(self.fail_session(err.into()));
        }
        Ok(())
    }

    /// Generate a MAX_SUBSCRIBE_ID message (typically server-side).
    ///
    /// Section 8.4: "The Maximum Subscribe ID MUST only increase within a
    /// session", and a peer that receives an equal or smaller value closes
    /// the session. The ceiling starts at 0 and 0 is not greater than 0, so
    /// the first value that may go on the wire is 1 and there is no opening
    /// case where a repeat is allowed.
    ///
    /// # Errors
    ///
    /// [`EndpointError::MaxSubscribeIdWouldNotIncrease`] if the value does not
    /// strictly increase. Its own variant rather than the one a *received*
    /// ceiling that did not increase raises, so that a refusal to write is
    /// never read back as a peer in violation.
    pub fn send_max_subscribe_id(
        &mut self,
        max_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let new_val = max_id.into_inner();
        if new_val <= self.advertised_max_id {
            return Err(EndpointError::MaxSubscribeIdWouldNotIncrease {
                advertised: self.advertised_max_id,
                offered: new_val,
            });
        }
        self.advertised_max_id = new_val;
        Ok(ControlMessage::MaxSubscribeId(MaxSubscribeId { subscribe_id: max_id }))
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
        // Section 8.3: "If a server receives a GOAWAY with a non-zero New
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
        // Section 8.3: "The endpoint MUST terminate the session with a
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
        filter_type: FilterType,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        if matches!(filter_type, FilterType::AbsoluteStart | FilterType::AbsoluteRange) {
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
        let filter_type = match end_group {
            Some(_) => FilterType::AbsoluteRange,
            None => FilterType::AbsoluteStart,
        };
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
        filter_type: FilterType,
        start_location: Option<Location>,
        end_group: Option<VarInt>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        // The alias travels in the SUBSCRIBE, so this is the last point at
        // which giving it to a second track can still be taken back. Refused
        // before the Subscribe ID is allocated, so a refusal spends nothing.
        let alias = track_alias.into_inner();
        if let Some((side, held)) = self.alias_holder(alias, &track_namespace, &track_name) {
            return Err(EndpointError::TrackAliasInUse { alias, side, held });
        }
        let sub_id = self.subscribe_ids.allocate()?;

        let mut sm = SubscriptionStateMachine::new();
        sm.on_subscribe_sent()?;
        self.subscriptions.insert(sub_id.into_inner(), sm);
        self.track_bindings.insert(
            (SubscribeSide::Ours, sub_id.into_inner()),
            TrackBinding { namespace: track_namespace.clone(), name: track_name.clone(), alias },
        );

        let msg = ControlMessage::Subscribe(Subscribe {
            subscribe_id: sub_id,
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            start_location,
            end_group,
            parameters: vec![],
        });
        Ok((sub_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ERROR.
    pub fn receive_subscribe_error(&mut self, msg: &SubscribeError) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        // Section 8.8 gives SUBSCRIBE_ERROR a Track Alias field with one
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
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE message for an active subscription.
    pub fn unsubscribe(&mut self, subscribe_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_unsubscribe()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { subscribe_id }))
    }

    /// Send a SUBSCRIBE_UPDATE narrowing a subscription this endpoint opened.
    ///
    /// Section 8.9 gives the message to the subscriber, which is what this
    /// endpoint is for every subscription in `subscriptions`. No identifier is
    /// spent: the update's one identifier field names the subscription being
    /// modified rather than opening a request of its own.
    ///
    /// The narrowing rules the same section states are the caller's to keep.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownSubscribe`] when this endpoint opened no
    /// subscription under that identifier, and the subscription flow's own
    /// `InvalidTransition` when the one it names has already ended.
    pub fn subscribe_update(
        &mut self,
        subscribe_id: VarInt,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        subscriber_priority: u8,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let id = subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_update()?;
        Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
            subscribe_id,
            start_group,
            start_object,
            end_group,
            subscriber_priority,
            parameters,
        }))
    }

    /// Process an incoming SUBSCRIBE_UPDATE.
    ///
    /// Section 8.9: "A subscriber issues a SUBSCRIBE_UPDATE to a publisher to
    /// request a change to an existing subscription." One that arrives is
    /// therefore about a subscription the **peer** opened, which is why it is
    /// looked for among those and not among this endpoint's own.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UpdateForUnknownSubscribe`] when the identifier names no
    /// subscription the peer has opened in this session, and the subscription
    /// flow's own `InvalidTransition` when it names one that has already
    /// ended. Neither ends the session: Section 8.9 says SHOULD.
    pub fn receive_subscribe_update(&mut self, msg: &SubscribeUpdate) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sub = self
            .inbound_subscribes
            .get_mut(&id)
            .ok_or(EndpointError::UpdateForUnknownSubscribe(id))?;
        sub.state.on_subscribe_update_received()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_DONE (subscriber side — publisher finished).
    pub fn receive_subscribe_done(&mut self, msg: &SubscribeDone) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_done()?;
        Ok(())
    }

    // ── Answering a SUBSCRIBE the peer sent ────────────────────

    /// The SUBSCRIBE the peer sent under `subscribe_id` and this endpoint has
    /// not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session
    /// has no inbound subscription for.
    pub fn pending_subscribe(&self, subscribe_id: VarInt) -> Option<&Subscribe> {
        self.inbound_subscribes
            .get(&subscribe_id.into_inner())
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
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it has
    /// already been answered.
    pub fn send_subscribe_ok(
        &mut self,
        subscribe_id: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sub =
            self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sub.state.on_subscribe_ok_sent()?;
        Ok(ControlMessage::SubscribeOk(SubscribeOk {
            subscribe_id,
            expires,
            group_order,
            content_exists: ContentExists::NoLargestLocation,
            largest_group_id: None,
            largest_object_id: None,
            parameters,
        }))
    }

    /// Build the SUBSCRIBE_ERROR rejecting a subscription the peer opened.
    ///
    /// The Track Alias goes back out with the refusal because Section 8.8
    /// gives the field a use: an alias to retry with, when the code is 'Retry
    /// Track Alias'. Under any other code the peer reads nothing from it.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it has
    /// already been answered.
    pub fn send_subscribe_error(
        &mut self,
        subscribe_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
        track_alias: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sub =
            self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sub.state.on_subscribe_error_sent()?;
        Ok(ControlMessage::SubscribeError(SubscribeError {
            subscribe_id,
            error_code,
            reason_phrase,
            track_alias,
        }))
    }

    /// Build the SUBSCRIBE_DONE ending a subscription this endpoint accepted.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it is not
    /// one this endpoint accepted and has not already ended.
    pub fn send_subscribe_done(
        &mut self,
        subscribe_id: VarInt,
        status_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sub =
            self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sub.state.on_subscribe_done_sent()?;
        Ok(ControlMessage::SubscribeDone(SubscribeDone {
            subscribe_id,
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
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no subscription
    /// under that identifier, and [`EndpointError::Subscription`] if it is not
    /// one this endpoint accepted and has not already ended.
    pub fn receive_unsubscribe(&mut self, msg: &Unsubscribe) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sub =
            self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sub.state.on_unsubscribe_received()?;
        Ok(())
    }

    // ── Fetch flow ─────────────────────────────────────────────

    /// Send a FETCH message. Allocates a subscribe ID and creates a fetch state machine.
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
        let sub_id = self.subscribe_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(sub_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            subscribe_id: sub_id,
            subscriber_priority,
            group_order,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(track_namespace),
            track_name: Some(track_name),
            start_group: Some(start_group),
            start_object: Some(start_object),
            end_group: Some(end_group),
            end_object: Some(end_object),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        });
        Ok((sub_id, msg))
    }

    /// Send a joining FETCH message that attaches to an existing subscription.
    /// Allocates a new subscribe ID for the fetch and tracks it in its own
    /// fetch state machine.
    pub fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_subscribe_id: VarInt,
        preceding_group_offset: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let sub_id = self.subscribe_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(sub_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            subscribe_id: sub_id,
            subscriber_priority,
            group_order,
            fetch_type: FetchType::Joining,
            track_namespace: None,
            track_name: None,
            start_group: None,
            start_object: None,
            end_group: None,
            end_object: None,
            joining_subscribe_id: Some(joining_subscribe_id),
            preceding_group_offset: Some(preceding_group_offset),
            parameters: vec![],
        });
        Ok((sub_id, msg))
    }

    /// Process an incoming FETCH_OK.
    pub fn receive_fetch_ok(&mut self, msg: &message::FetchOk) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    /// Process an incoming FETCH_ERROR.
    pub fn receive_fetch_error(&mut self, msg: &message::FetchError) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_fetch_error()?;
        Ok(())
    }

    /// Send a FETCH_CANCEL message.
    pub fn fetch_cancel(&mut self, subscribe_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_fetch_cancel()?;
        Ok(ControlMessage::FetchCancel(FetchCancel { subscribe_id }))
    }

    /// Notify that a fetch data stream received FIN.
    ///
    /// It may arrive before the FETCH_OK or FETCH_ERROR answering the
    /// request, which leaves the fetch in `FetchState::Unanswered` until the
    /// answer lands.
    pub fn on_fetch_stream_fin(&mut self, subscribe_id: VarInt) -> Result<(), EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    /// Notify that a fetch data stream was reset.
    ///
    /// As with a FIN, it may arrive before the answer to the request.
    pub fn on_fetch_stream_reset(&mut self, subscribe_id: VarInt) -> Result<(), EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // ── Answering a FETCH the peer sent ────────────────────────

    /// Process an incoming FETCH, recording the fetch it opens.
    ///
    /// The Subscribe ID is checked here, in the same sequence a SUBSCRIBE
    /// draws from: Section 8.12 gives it the same "unique and monotonically
    /// increasing within a session" requirement.
    ///
    /// A Joining Fetch is recorded like any other. Section 8.12 answers one
    /// naming a subscription this session cannot join with a refusal and not
    /// a session close, and a refusal is a message this endpoint has to
    /// build, so the request it refuses has to be on record first.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate_peer_subscribe_id`] answers, and the fetch
    /// flow's own `InvalidTransition` for a second FETCH under an identifier
    /// already carrying one.
    pub fn receive_fetch(&mut self, msg: &Fetch) -> Result<(), EndpointError> {
        self.validate_peer_subscribe_id(msg.subscribe_id.into_inner())?;
        let id = msg.subscribe_id.into_inner();
        let unjoinable = self.joining_subscription_missing(msg);
        let mut state = FetchStateMachine::new();
        state.on_fetch_received()?;
        self.inbound_fetches.insert(id, InboundFetch { message: msg.clone(), state, unjoinable });
        Ok(())
    }

    /// The FETCH the peer sent under `subscribe_id` and this endpoint has not
    /// answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session
    /// has no inbound fetch for. The record itself lives on past the answer,
    /// because the fetch is not over until its data stream is.
    pub fn pending_fetch(&self, subscribe_id: VarInt) -> Option<&Fetch> {
        self.inbound_fetches
            .get(&subscribe_id.into_inner())
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
    /// Section 8.12:
    /// "If a publisher receives a Joining Fetch with a Subscribe ID
    /// that does not correspond to an existing Subscribe, it MUST respond with
    /// a Fetch Error."
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
        let joined = msg.joining_subscribe_id?.into_inner();
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
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no fetch under
    /// that identifier, [`EndpointError::UnjoinableSubscription`] for a
    /// Joining Fetch naming a subscription this session cannot join, and the
    /// fetch flow's own `InvalidTransition` for a second answer: Section 4
    /// says the publisher "MUST send exactly one FETCH_OK or FETCH_ERROR in
    /// response to a FETCH".
    pub fn send_fetch_ok(
        &mut self,
        subscribe_id: VarInt,
        group_order: GroupOrder,
        end_of_track: u8,
        largest_group_id: VarInt,
        largest_object_id: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let unjoinable =
            self.inbound_fetches.get(&id).ok_or(EndpointError::UnknownSubscribe(id))?.unjoinable;
        if let Some(joining) = unjoinable {
            return Err(EndpointError::UnjoinableSubscription { fetch: id, joining });
        }
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        fetch.state.on_fetch_ok_sent()?;
        Ok(ControlMessage::FetchOk(message::FetchOk {
            subscribe_id,
            group_order,
            end_of_track,
            largest_group_id,
            largest_object_id,
            parameters,
        }))
    }

    /// Build the FETCH_ERROR refusing a fetch the peer opened.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no fetch under
    /// that identifier, and the fetch flow's own `InvalidTransition` if it has
    /// already been answered.
    pub fn send_fetch_error(
        &mut self,
        subscribe_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        fetch.state.on_fetch_error_sent()?;
        Ok(ControlMessage::FetchError(message::FetchError {
            subscribe_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming FETCH_CANCEL, ending the fetch the peer opened.
    ///
    /// Section 8.15: the subscriber sends it to stop a fetch it no longer
    /// wants, so the record this endpoint serves the fetch from is the one it
    /// ends.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no fetch under
    /// that identifier, and the fetch flow's own `InvalidTransition` for a fetch
    /// that has already ended.
    pub fn receive_fetch_cancel(&mut self, msg: &FetchCancel) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
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
    /// [`EndpointError::UnknownSubscribe`] if the peer opened no fetch under
    /// that identifier, and the fetch flow's own `InvalidTransition` from a state
    /// the stream cannot close from.
    pub fn on_peer_fetch_stream_fin(&mut self, subscribe_id: VarInt) -> Result<(), EndpointError> {
        let id = subscribe_id.into_inner();
        let fetch = self.inbound_fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        fetch.state.on_stream_fin_sent()?;
        Ok(())
    }

    // ── Subscribe Announces flow ───────────────────────────────

    /// Send a SUBSCRIBE_ANNOUNCES message.
    ///
    /// Section 8.23: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session."
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and
    /// [`EndpointError::OwnPrefixOverlap`] when the prefix overlaps one this
    /// endpoint has already subscribed to.
    pub fn subscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let key = track_namespace_prefix.0.clone();
        // The subscriber's half of the rule, refused before the message
        // exists. A publisher that follows this draft would answer it with
        // SUBSCRIBE_ANNOUNCES_ERROR, so building it wastes a round trip and
        // leaves this endpoint holding a namespace subscription that is not
        // going to open.
        if self.subscribe_announces.keys().any(|k| prefixes_overlap(k, &key)) {
            return Err(EndpointError::OwnPrefixOverlap);
        }
        let mut sm = SubscribeAnnouncesStateMachine::new();
        sm.on_subscribe_announces_sent()?;
        self.subscribe_announces.insert(key, sm);
        Ok(ControlMessage::SubscribeAnnounces(SubscribeAnnounces {
            track_namespace_prefix,
            parameters: vec![],
        }))
    }

    /// Process an incoming SUBSCRIBE_ANNOUNCES_OK.
    pub fn receive_subscribe_announces_ok(
        &mut self,
        msg: &SubscribeAnnouncesOk,
    ) -> Result<(), EndpointError> {
        let sm = self
            .subscribe_announces
            .get_mut(&msg.track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_subscribe_announces_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ANNOUNCES_ERROR.
    pub fn receive_subscribe_announces_error(
        &mut self,
        msg: &SubscribeAnnouncesError,
    ) -> Result<(), EndpointError> {
        let sm = self
            .subscribe_announces
            .get_mut(&msg.track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_subscribe_announces_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE_ANNOUNCES message.
    pub fn unsubscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let sm = self
            .subscribe_announces
            .get_mut(&track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_unsubscribe_announces()?;
        Ok(ControlMessage::UnsubscribeAnnounces(UnsubscribeAnnounces { track_namespace_prefix }))
    }

    // ── Answering a SUBSCRIBE_ANNOUNCES the peer sent ──────────

    /// Process an incoming SUBSCRIBE_ANNOUNCES, recording the namespace
    /// subscription it opens.
    ///
    /// Section 8.23: "The subscriber sends the SUBSCRIBE_ANNOUNCES control
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
    /// The session error when the session is not established, and
    /// [`EndpointError::PeerPrefixOverlap`] when the prefix overlaps one the
    /// peer has already subscribed to.
    pub fn receive_subscribe_announces(
        &mut self,
        msg: &SubscribeAnnounces,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        // Judged on arrival, because that is the moment the sentence names:
        // "if a publisher receives a SUBSCRIBE_ANNOUNCES ... it MUST respond
        // with SUBSCRIBE_ANNOUNCES_ERROR". Nothing is recorded for a request
        // this endpoint may not accept, so no later call can accept it.
        if self.peer_prefix_overlap(&msg.track_namespace_prefix) {
            return Err(EndpointError::PeerPrefixOverlap);
        }
        let mut state = SubscribeAnnouncesStateMachine::new();
        state.on_subscribe_announces_received()?;
        self.inbound_subscribe_announces.insert(
            msg.track_namespace_prefix.0.clone(),
            InboundSubscribeAnnounces { message: msg.clone(), state },
        );
        Ok(())
    }

    /// Whether `prefix` overlaps a namespace subscription the peer has already
    /// made on this session.
    ///
    /// Every one of them counts, including a subscription the peer has since
    /// withdrawn: the sentence weighs the arriving prefix against "an earlier
    /// SUBSCRIBE_ANNOUNCES", and one that has ended was still earlier.
    ///
    /// Namespace subscriptions this endpoint made are a separate set and are
    /// not consulted. This endpoint is the subscriber for those, so a prefix
    /// it asked about says nothing about what the peer may ask about.
    fn peer_prefix_overlap(&self, prefix: &TrackNamespace) -> bool {
        self.inbound_subscribe_announces.keys().any(|k| prefixes_overlap(k, &prefix.0))
    }

    /// The SUBSCRIBE_ANNOUNCES the peer sent for `prefix` and this endpoint
    /// has not answered yet.
    ///
    /// `None` once it has been answered, and for a prefix the peer has
    /// subscribed to nothing under. The record itself lives on past the
    /// answer, because a namespace subscription that was accepted is not over
    /// until it is withdrawn.
    pub fn pending_subscribe_announces(
        &self,
        prefix: &TrackNamespace,
    ) -> Option<&SubscribeAnnounces> {
        self.inbound_subscribe_announces
            .get(&prefix.0)
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
    /// [`EndpointError::UnknownPeerNamespaceSubscription`] if the peer has
    /// subscribed to nothing under that prefix, and the namespace flow's own
    /// `InvalidTransition` for a request already answered.
    pub fn send_subscribe_announces_ok(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let sub = self
            .inbound_subscribe_announces
            .get_mut(&track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownPeerNamespaceSubscription)?;
        sub.state.on_subscribe_announces_ok_sent()?;
        Ok(ControlMessage::SubscribeAnnouncesOk(SubscribeAnnouncesOk { track_namespace_prefix }))
    }

    /// Build the SUBSCRIBE_ANNOUNCES_ERROR refusing a namespace subscription
    /// the peer made.
    ///
    /// The other half of the same sentence: one message back, whichever of
    /// the two it is.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespaceSubscription`] if the peer has
    /// subscribed to nothing under that prefix, and the namespace flow's own
    /// `InvalidTransition` for a request already answered.
    pub fn send_subscribe_announces_error(
        &mut self,
        track_namespace_prefix: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let sub = self
            .inbound_subscribe_announces
            .get_mut(&track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownPeerNamespaceSubscription)?;
        sub.state.on_subscribe_announces_error_sent()?;
        Ok(ControlMessage::SubscribeAnnouncesError(SubscribeAnnouncesError {
            track_namespace_prefix,
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
        let sub = self
            .inbound_subscribe_announces
            .get_mut(&msg.track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownPeerNamespaceSubscription)?;
        sub.state.on_unsubscribe_announces_received()?;
        Ok(())
    }

    // ── Announce flow ──────────────────────────────────────────

    /// Send an ANNOUNCE message.
    pub fn announce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let key = track_namespace.0.clone();
        let mut sm = AnnounceStateMachine::new();
        sm.on_announce_sent()?;
        self.announces.insert(key, sm);
        Ok(ControlMessage::Announce(Announce { track_namespace, parameters: vec![] }))
    }

    /// Process an incoming ANNOUNCE_OK.
    pub fn receive_announce_ok(&mut self, msg: &AnnounceOk) -> Result<(), EndpointError> {
        let sm = self
            .announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_announce_ok()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_ERROR.
    pub fn receive_announce_error(&mut self, msg: &AnnounceError) -> Result<(), EndpointError> {
        let sm = self
            .announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_announce_error()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_CANCEL.
    pub fn receive_announce_cancel(&mut self, msg: &AnnounceCancel) -> Result<(), EndpointError> {
        let sm = self
            .announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_announce_cancel()?;
        Ok(())
    }

    /// Send an UNANNOUNCE message (publisher withdrawing).
    pub fn unannounce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let sm =
            self.announces.get_mut(&track_namespace.0).ok_or(EndpointError::UnknownNamespace)?;
        sm.on_unannounce()?;
        Ok(ControlMessage::Unannounce(Unannounce { track_namespace }))
    }

    // ── Answering an ANNOUNCE the peer sent ────────────────────

    /// Process an incoming ANNOUNCE, recording the announcement it makes.
    ///
    /// Section 8.18: "The publisher sends the ANNOUNCE control message to
    /// advertise where the receiver can route SUBSCRIBEs for tracks within the
    /// announced Track Namespace. The receiver verifies the publisher is
    /// authorized to publish tracks under this namespace."
    ///
    /// Verifying is the application's to do, and it needs both the message to
    /// verify and somewhere to answer from. This draft's ANNOUNCE carries no
    /// Request ID, so the namespace it names is what the record is filed under,
    /// and a second one naming a namespace already held replaces it. No
    /// sentence makes a repeat an error, and the newest advertisement is the
    /// one an answer has to be built from.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established.
    pub fn receive_announce(&mut self, msg: &Announce) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let key = msg.track_namespace.0.clone();
        let mut state = AnnounceStateMachine::new();
        state.on_announce_received()?;
        self.inbound_announces.insert(key, InboundAnnounce { message: msg.clone(), state });
        Ok(())
    }

    /// The ANNOUNCE the peer sent for `track_namespace` and this endpoint has
    /// not answered yet.
    ///
    /// `None` once it has been answered, and for a namespace the peer has
    /// announced nothing under. The record itself lives on past the answer,
    /// because an announcement that was accepted is not over until it is
    /// withdrawn or cancelled.
    pub fn pending_announce(&self, track_namespace: &TrackNamespace) -> Option<&Announce> {
        self.inbound_announces
            .get(&track_namespace.0)
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
    /// [`EndpointError::UnknownPeerNamespace`] if the peer has announced
    /// nothing under that namespace, and the namespace flow's own
    /// `InvalidTransition` for an announcement already answered.
    pub fn send_announce_ok(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let ann = self
            .inbound_announces
            .get_mut(&track_namespace.0)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        ann.state.on_announce_ok_sent()?;
        Ok(ControlMessage::AnnounceOk(AnnounceOk { track_namespace }))
    }

    /// Build the ANNOUNCE_ERROR refusing an announcement the peer made.
    ///
    /// The same sentence in Section 5.2 answers both ways: one message back and
    /// no second one, whichever of the two it is.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespace`] if the peer has announced
    /// nothing under that namespace, and the namespace flow's own
    /// `InvalidTransition` for an announcement already answered.
    pub fn send_announce_error(
        &mut self,
        track_namespace: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let ann = self
            .inbound_announces
            .get_mut(&track_namespace.0)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        ann.state.on_announce_error_sent()?;
        Ok(ControlMessage::AnnounceError(AnnounceError {
            track_namespace,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming UNANNOUNCE, ending the announcement the peer made.
    ///
    /// Section 8.21: "The publisher sends the UNANNOUNCE control message to
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
        let ann = self
            .inbound_announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        ann.state.on_unannounce_received()?;
        Ok(())
    }

    /// Build the ANNOUNCE_CANCEL revoking an acceptance.
    ///
    /// Section 7.2 names what a cancellation revokes: a namespace "it
    /// previously responded ANNOUNCE_OK to". Section 8.22 says what it does:
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
        let ann = self
            .inbound_announces
            .get_mut(&track_namespace.0)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        ann.state.on_announce_cancel_sent()?;
        Ok(ControlMessage::AnnounceCancel(AnnounceCancel {
            track_namespace,
            error_code,
            reason_phrase,
        }))
    }

    // ── Track Status flow ──────────────────────────────────────

    /// Send a TRACK_STATUS_REQUEST message.
    pub fn track_status_request(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let key = (track_namespace.0.clone(), track_name.clone());
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_request_sent()?;
        self.track_statuses.insert(key, sm);
        Ok(ControlMessage::TrackStatusRequest(TrackStatusRequest { track_namespace, track_name }))
    }

    /// Process an incoming TRACK_STATUS reply.
    pub fn receive_track_status(&mut self, msg: &TrackStatus) -> Result<(), EndpointError> {
        let key = (msg.track_namespace.0.clone(), msg.track_name.clone());
        let sm = self.track_statuses.get_mut(&key).ok_or(EndpointError::UnknownTrackStatus)?;
        sm.on_track_status()?;
        Ok(())
    }

    // ── Answering a TRACK_STATUS_REQUEST the peer sent ─────────

    /// Process an incoming TRACK_STATUS_REQUEST, recording what the peer asked
    /// about.
    ///
    /// Section 8.16: "A potential subscriber sends a 'TRACK_STATUS_REQUEST'
    /// message on the control stream to obtain information about the current
    /// status of a given track."
    ///
    /// Answering is the application's to do, and it needs both the request and
    /// somewhere to answer from. This draft's request carries no Request ID, so
    /// the track it names is what the record is filed under, and a second
    /// request for a track already asked about replaces it. No sentence makes a
    /// repeat an error, and the newest request is the one an answer has to be
    /// built from.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established.
    pub fn receive_track_status_request(
        &mut self,
        msg: &TrackStatusRequest,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let key = (msg.track_namespace.0.clone(), msg.track_name.clone());
        let mut state = TrackStatusStateMachine::new();
        state.on_track_status_request_received()?;
        self.inbound_track_statuses.insert(key, InboundTrackStatus { message: msg.clone(), state });
        Ok(())
    }

    /// The TRACK_STATUS_REQUEST the peer sent about this track and this
    /// endpoint has not answered yet.
    ///
    /// `None` once it has been answered, and for a track the peer has asked
    /// nothing about.
    pub fn pending_track_status_request(
        &self,
        track_namespace: &TrackNamespace,
        track_name: &[u8],
    ) -> Option<&TrackStatusRequest> {
        self.inbound_track_statuses
            .get(&(track_namespace.0.clone(), track_name.to_vec()))
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
    /// Section 8.16 leaves the answering end no discretion about whether to
    /// answer: "A TRACK_STATUS message MUST be sent in response to each
    /// TRACK_STATUS_REQUEST." What it bounds is how many, and that half is what
    /// the record carries: the request leaves `Pending` on the first answer, so
    /// a second call finds nothing left to answer.
    ///
    /// Section 8.17 says which track the answer is about, and this draft has
    /// no identifier to say it with, so the caller names the track and the
    /// message repeats it.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerTrackStatus`] if the peer has asked nothing
    /// about that track, and the flow's own `InvalidTransition` for a request
    /// already answered.
    pub fn send_track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        status_code: VarInt,
        last_group_id: VarInt,
        last_object_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let key = (track_namespace.0.clone(), track_name.clone());
        let req = self
            .inbound_track_statuses
            .get_mut(&key)
            .ok_or(EndpointError::UnknownPeerTrackStatus)?;
        req.state.on_track_status_sent()?;
        Ok(ControlMessage::TrackStatus(TrackStatus {
            track_namespace,
            track_name,
            status_code,
            last_group_id,
            last_object_id,
        }))
    }

    // ── Subscribes blocked (draft-10 new) ──────────────────────

    /// Process an incoming SUBSCRIBES_BLOCKED.
    ///
    /// The peer sends this to report that a new subscribe id would exceed
    /// the maximum this endpoint advertised. The endpoint records the peer's
    /// reported maximum; acting on it - issuing a new `MAX_SUBSCRIBE_ID` - is
    /// up to the caller. The message arrived at draft-08, not here.
    pub fn receive_subscribes_blocked(
        &mut self,
        msg: &SubscribesBlocked,
    ) -> Result<(), EndpointError> {
        self.peer_reported_max_subscribe_id = Some(msg.maximum_subscribe_id);
        Ok(())
    }

    /// The maximum subscribe id that the peer most recently reported in a
    /// `SUBSCRIBES_BLOCKED` message, if any.
    pub fn peer_reported_max_subscribe_id(&self) -> Option<VarInt> {
        self.peer_reported_max_subscribe_id
    }

    // ── Unified message dispatch ───────────────────────────────

    /// Dispatch an incoming control message to the appropriate handler.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::MaxSubscribeId(ref m) => self.receive_max_subscribe_id(m),
            ControlMessage::SubscribesBlocked(ref m) => self.receive_subscribes_blocked(m),
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
            ControlMessage::Fetch(ref m) => self.receive_fetch(m),
            ControlMessage::FetchCancel(ref m) => self.receive_fetch_cancel(m),
            ControlMessage::Unsubscribe(ref m) => self.receive_unsubscribe(m),
            ControlMessage::Announce(ref m) => self.receive_announce(m),
            ControlMessage::Unannounce(ref m) => self.receive_unannounce(m),
            ControlMessage::SubscribeAnnounces(ref m) => self.receive_subscribe_announces(m),
            ControlMessage::UnsubscribeAnnounces(ref m) => self.receive_unsubscribe_announces(m),
            _ => Ok(()),
        }
    }
}

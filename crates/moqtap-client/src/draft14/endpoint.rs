use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::draft14::fetch::{FetchError, FetchState, FetchStateMachine};
use crate::draft14::namespace::{
    NamespaceError, PublishNamespaceState, PublishNamespaceStateMachine, SubscribeNamespaceState,
    SubscribeNamespaceStateMachine,
};
use crate::draft14::publish::{
    PublishError as PublishFlowError, PublishState, PublishStateMachine,
};
use crate::draft14::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft14::session::setup::{self, SetupError};
use crate::draft14::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft14::subscription::{
    SubscriptionError, SubscriptionState, SubscriptionStateMachine,
};
use crate::draft14::track_status::{TrackStatusError, TrackStatusState, TrackStatusStateMachine};
use crate::forwarding_preference::{ObjectForwardingPreference, TrackForwardingPreferences};
use crate::malformed_tracks::{MalformedTrackCondition, MalformedTracks};
use crate::track_locations::{ObjectLocation, ObjectRole, TrackLocations, TrackObjects};
use moqtap_codec::draft14::error_codes::{
    FetchErrorCode, SessionErrorCode, SubscribeNamespaceErrorCode,
};
use moqtap_codec::draft14::message::{
    self, ClientSetup, ControlMessage, Fetch, FetchCancel, GoAway, MaxRequestId, PublishDone,
    PublishNamespace, PublishNamespaceCancel, PublishNamespaceDone, PublishNamespaceError,
    PublishNamespaceOk, RequestsBlocked, ServerSetup, Subscribe, SubscribeError,
    SubscribeNamespace, SubscribeNamespaceError, SubscribeNamespaceOk, SubscribeOk,
    SubscribeUpdate, Unsubscribe, UnsubscribeNamespace,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Errors that can occur during endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A GOAWAY carrying a New Session URI arrived at a server.
    ///
    /// Section 9.4: "If a server receives a GOAWAY with a non-zero New
    /// Session URI Length it MUST terminate the session with a
    /// PROTOCOL_VIOLATION." Migration is something a server offers a client, never the
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
    /// The send-side mirror of the rule a peer breaks by sending one — Section 9.5:
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
    /// A publish flow state machine error.
    #[error("publish flow error: {0}")]
    PublishFlow(#[from] PublishFlowError),
    /// A setup negotiation error.
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),
    /// The request ID does not match any known state machine.
    #[error("unknown request ID: {0}")]
    UnknownRequest(u64),
    /// A message that only a subscription can carry named a track status.
    ///
    /// Section 9.20 treats a TRACK_STATUS as a SUBSCRIBE "except it does not
    /// create downstream subscription state", and says what follows from that
    /// in the same breath: "the subscriber cannot send SUBSCRIBE_UPDATE or
    /// UNSUBSCRIBE". Both messages are about a subscription, and this request
    /// opened none for them to name.
    ///
    /// Separate from [`EndpointError::UnknownRequest`], which says the
    /// identifier names nothing at all. This one says it names something, and
    /// that what it names is the one request kind neither message applies to.
    #[error("request {0} is a track status, which cannot be updated or unsubscribed")]
    NotASubscription(u64),
    /// The track namespace does not match any announcement this endpoint made.
    ///
    /// PUBLISH_NAMESPACE_DONE and PUBLISH_NAMESPACE_CANCEL name a namespace on
    /// this draft where the PUBLISH_NAMESPACE they are about named a Request
    /// ID, so a namespace that names nothing is a miss this endpoint has to be
    /// able to report on its own announcements as well as on the peer's.
    #[error("this endpoint has made no live announcement for this namespace")]
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
    /// Draft-14 states it twice, once per message. Section 9.8: "The same
    /// Track Alias MUST NOT be used to refer to two different Tracks
    /// simultaneously. If a subscriber receives a SUBSCRIBE_OK that uses the
    /// same Track Alias as a different track with an active subscription, it
    /// MUST close the session with error DUPLICATE_TRACK_ALIAS." Section 9.13 is the same
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
    /// This endpoint was asked to give a Track Alias to a second track.
    ///
    /// The same rule as [`EndpointError::DuplicateTrackAlias`] read at the end
    /// that chooses the alias. Section 9.13 states it as a prohibition on the
    /// publisher before it states what the subscriber does about one: "The
    /// same Track Alias MUST NOT be used to refer to two different Tracks
    /// simultaneously."
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
    /// A track's objects were framed two different ways.
    ///
    /// Section 10: "Every Track has a single 'Object Forwarding Preference'
    /// and the Original Publisher MUST NOT mix different forwarding
    /// preferences within a single track (see Section 2.5)."
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
    /// any subscription and FETCH_CANCEL any fetch for that Track from that
    /// publisher, and SHOULD deliver an error to the application".
    ///
    /// So this error carries no code in [`EndpointError::session_error_code`],
    /// and the connection's `close_for_data_stream` declines it. Ending the
    /// session over it would be this crate inventing a consequence the draft
    /// withdrew.
    ///
    /// This is half of that answer and not all of it. "SHOULD deliver an error
    /// to the application" is what this error is. The unsubscribe and cancel
    /// the same sentence requires is not done: those are control messages, and
    /// a data path holding `&self` has no way to send one. It is also one
    /// condition of eight in that section rather than a rule of its own, so
    /// the answer belongs to the family and not to this arm. A caller that
    /// wants it has the error to act on.
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
    /// An object arriving after the track's final object.
    ///
    /// Section 2.5 lists the condition: "An Object is received on a
    /// Track whose Group and Object ID are larger than the final Object in the
    /// Track. The final Object in a Track is the Object with Status
    /// END_OF_TRACK or the last Object sent in a FETCH whose response indicated
    /// End of Track."
    ///
    /// **Larger is Section 1.4.1's comparison and not a reading of the
    /// words.** That section puts one Location below another when "A.Group <
    /// B.Group || (A.Group == B.Group && A.Object < B.Object)", so an Object in
    /// a later group is past the end whatever its own Object ID is.
    ///
    /// **A Malformed Track and not a session error**, like the arm above it and
    /// for the same sentence: Section 2.5 answers its whole list at
    /// once, and on this draft that answer is "it MUST UNSUBSCRIBE any
    /// subscription and FETCH_CANCEL any fetch for that Track from that
    /// publisher". The messages are the connection's; this is the error half.
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
    /// Section 9.10: "A publisher MUST terminate the session with a
    /// PROTOCOL_VIOLATION if the SUBSCRIBE_UPDATE violates these rules or if
    /// the subscriber specifies a request ID that has not existed within the
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
    /// Section 9.16.2: "If a publisher receives a Joining Fetch with a Request ID that
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
    /// Section 9.27 says what a cancellation is for: the subscriber "will stop
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
    /// Section 6.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous SUBSCRIBE_NAMESPACE."
    ///
    /// What a withdrawal ends is a namespace subscription the **peer** made,
    /// so the record it reaches for is the one this endpoint keeps of the
    /// peer's. A namespace subscription this endpoint made is withdrawn by
    /// [`Endpoint::unsubscribe_namespace`], which is the same message travelling the other
    /// way and answers with [`EndpointError::UnknownNamespace`].
    #[error("the peer has made no live namespace subscription for this prefix")]
    UnknownPeerNamespaceSubscription,
    /// The peer subscribed to a namespace prefix overlapping one it is
    /// already subscribed to.
    ///
    /// Section 9.28: "A subscriber cannot make overlapping namespace
    /// subscriptions on a single session. Within a session, if a publisher
    /// receives a SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that is a
    /// prefix of, suffix of, or equal to an active SUBSCRIBE_NAMESPACE, it
    /// MUST respond with SUBSCRIBE_NAMESPACE_ERROR, with error code
    /// NAMESPACE_PREFIX_OVERLAP."
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
/// Section 9.28: "A subscriber cannot make overlapping namespace
/// subscriptions on a single session. Within a session, if a publisher
/// receives a SUBSCRIBE_NAMESPACE with a Track Namespace Prefix that is a
/// prefix of, suffix of, or equal to an active SUBSCRIBE_NAMESPACE, it MUST
/// respond with SUBSCRIBE_NAMESPACE_ERROR, with error code
/// NAMESPACE_PREFIX_OVERLAP."
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
            EndpointError::GoAwayUriAtServer => Fault::Peer(Rule::GoAwayAtServer),
            EndpointError::MixedForwardingPreference { .. } => {
                Fault::Peer(Rule::MixedForwardingPreference)
            }
            EndpointError::ObjectPastFinalObject { .. } => Fault::Peer(Rule::ObjectPastFinalObject),
            EndpointError::RepeatedGoAway => Fault::Peer(Rule::RepeatedGoAway),
            EndpointError::UpdateForUnknownRequest(..) => {
                Fault::Peer(Rule::RequestUpdateForTheWrongRequest)
            }
            EndpointError::NotASubscription(..) => Fault::Peer(Rule::TrackStatusIsNotASubscription),

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

    /// The code to close the session with, when draft-14 answers this error
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
            // Section 9.5 answers a ceiling that does not increase with a
            // close, and names this code for it.
            EndpointError::RequestId(RequestIdError::Decreased(..)) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // The same section answers a Request ID that reaches the ceiling
            // this endpoint advertised, and names a different code for it.
            EndpointError::RequestId(RequestIdError::ExceedsMax(..)) => {
                Some(SessionErrorCode::TooManyRequests)
            }
            // Section 9.1 answers a Request ID that is not the peer's to
            // spend with a close, and names INVALID_REQUEST_ID for it. Both
            // halves of that sentence arrive here: "not valid for the peer"
            // is an ID out of this endpoint's own half of the space, and "not
            // expected" is a new request carrying an ID other than the next
            // one the peer's sequence calls for.
            EndpointError::RequestId(
                RequestIdError::WrongParity(..) | RequestIdError::OutOfSequence { .. },
            ) => Some(SessionErrorCode::InvalidRequestId),
            // Section 9.4 answers a GOAWAY that repeats one already
            // received, and names this code in the same sentence.
            EndpointError::RepeatedGoAway => Some(SessionErrorCode::ProtocolViolation),
            // The same section answers a migration URI arriving at a server
            // with a close, and names this code for it. Only a server may
            // offer one, so a client that sends one is telling a server where
            // to reconnect, which it has no standing to do.
            EndpointError::GoAwayUriAtServer => Some(SessionErrorCode::ProtocolViolation),
            // Sections 9.8 and 9.13 name this code in the sentence that
            // states the rule, and name no other. A close carrying
            // PROTOCOL_VIOLATION would tell the peer a different thing went
            // wrong.
            EndpointError::DuplicateTrackAlias { .. } => {
                Some(SessionErrorCode::DuplicateTrackAlias)
            }
            // Section 9.10 answers an update naming a request the session has
            // never carried with a close, and names this code for it.
            EndpointError::UpdateForUnknownRequest(_) => Some(SessionErrorCode::ProtocolViolation),
            _ => None,
        }
    }
}

/// Unified MoQT endpoint wrapping session lifecycle, request ID allocation,
/// and all per-request state machines (subscriptions, fetches, namespaces).
pub struct Endpoint {
    role: Role,
    session: SessionStateMachine,
    request_ids: RequestIdAllocator,
    /// Tracks the MAX_REQUEST_ID we have advertised to the peer (for monotonic enforcement).
    advertised_max_id: u64,
    /// Each subscription this endpoint opened, behind a lock apiece.
    ///
    /// The lock is what lets the data plane end one. Section 2.5's answer to a
    /// Malformed Track is a message per request, the conditions that make a
    /// track malformed are detected where objects arrive, and objects arrive
    /// through a shared reference to the connection carrying them.
    subscriptions: HashMap<u64, Mutex<SubscriptionStateMachine>>,
    /// Each fetch this endpoint made, behind a lock apiece, for the reason the
    /// subscriptions above are: the same sentence ends a fetch for a malformed
    /// track and ends it from the same place.
    fetches: HashMap<u64, Mutex<FetchStateMachine>>,
    /// The track each fetch this endpoint made is for.
    ///
    /// # Why this is not in `track_bindings`
    ///
    /// That table exists to answer questions about Track Aliases, and a fetch
    /// has none: its objects arrive on a stream that opens by naming the
    /// Request ID, so no alias rule can ever be about a fetch. An entry that
    /// can never hold an alias would be one every reader of that table had to
    /// learn to skip.
    ///
    /// # Why a Joining Fetch is resolved here rather than when it is read
    ///
    /// A Joining Fetch names no track. It names the subscription it joins, and
    /// Section 9.16.2 takes the rest from there: "A publisher receiving a
    /// Joining Fetch uses properties of the associated Subscribe to determine
    /// the Track Namespace, Track Name and End Location such that it is
    /// contiguous with the associated Subscribe." So its track is the joined
    /// subscription's, and it is looked up once, as the fetch is made.
    ///
    /// The other place to look it up is the withdrawal, through the request the
    /// fetch joined, and that fails in the case a Joining Fetch exists for: one
    /// fills a buffer behind the live edge, so it outlives the subscription it
    /// joined, and the lookup would come up empty exactly while there was still
    /// a fetch to cancel.
    fetch_tracks: HashMap<u64, FetchTrack>,
    /// The namespace prefix each SUBSCRIBE_NAMESPACE this endpoint sent asked
    /// about, which the state machine beside it does not hold.
    ///
    /// Read by [`Endpoint::own_prefix_overlap`] and by nothing else. The
    /// withdrawal names the Request ID here, so until the rule about
    /// overlapping prefixes was judged there was nothing to remember a prefix
    /// for.
    subscribe_namespace_prefixes: HashMap<u64, TrackNamespace>,
    subscribe_namespaces: HashMap<u64, SubscribeNamespaceStateMachine>,
    /// Namespace subscriptions the **peer** made, keyed by the Request ID it
    /// opened each under.
    ///
    /// Kept apart from `subscribe_namespaces`, which holds the ones this endpoint made:
    /// one Request ID names one request whichever end opened it, and the two
    /// ends answer opposite halves of the flow.
    inbound_subscribe_namespaces: HashMap<u64, InboundSubscribeNamespace>,
    publish_namespaces: HashMap<u64, PublishNamespaceStateMachine>,
    /// The namespace each announcement this endpoint made names, so
    /// PUBLISH_NAMESPACE_DONE and PUBLISH_NAMESPACE_CANCEL, which carry
    /// a namespace and no Request ID, can find the one they are about.
    publish_namespace_namespaces: HashMap<u64, TrackNamespace>,
    /// Announcements the **peer** made, keyed by the Request ID it
    /// opened each under.
    inbound_publish_namespaces: HashMap<u64, InboundPublishNamespace>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    /// Track statuses the **peer** asked about, keyed by the Request ID it
    /// asked under.
    ///
    /// Kept apart from `track_statuses`, which holds the ones this endpoint
    /// asked about: the two are answered by opposite ends, and one Request ID
    /// belongs to one request whichever end opened it.
    inbound_track_statuses: HashMap<u64, InboundTrackStatus>,
    /// Both directions' publish flows, behind a lock apiece.
    ///
    /// A subscription the peer opened with PUBLISH is one of the two ways this
    /// endpoint receives a track, so the withdrawal a Malformed Track calls for
    /// has to reach these as well as the subscriptions above.
    publishes: HashMap<u64, Mutex<PublishStateMachine>>,
    /// The PUBLISH each offer the **peer** made arrived as, keyed by the
    /// Request ID it carries.
    ///
    ///
    /// The state of each one stays in `publishes` beside this endpoint's own
    /// offers, because every step after arrival names one Request ID and a
    /// Request ID the peer allocated can never be one this endpoint
    /// allocated. What a map of state machines cannot hold is the offer
    /// itself, and the offer is what the answer is decided from. Section 5.1:
    /// "A publisher initiates a subscription to a track by sending the
    /// PUBLISH message. The subscriber either accepts or rejects the
    /// subscription using PUBLISH_OK or PUBLISH_ERROR."
    ///
    ///
    /// `track_bindings` already keeps the Full Track Name and the Track
    /// Alias, because the rules about aliases read them. The delivery order,
    /// the largest location and the parameters are here and nowhere else.
    inbound_publishes: HashMap<u64, message::Publish>,
    /// Subscriptions the **peer** opened with SUBSCRIBE, by Request ID.
    ///
    /// Section 9.10 puts the update in the subscriber's hands, so one that
    /// arrives names a subscription in here and never one in `subscriptions`.
    ///
    /// The record holds the SUBSCRIBE itself and not only its state, because
    /// the answer is built out of the request: the track a SUBSCRIBE_OK is
    /// about is named nowhere else, and the alias it hands out has to be
    /// judged against that name. A PUBLISH needs no such record because it
    /// carries its track and its alias in the one message.
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
    /// What Full Track Name the peer has attached each Track Alias to, per
    /// Request ID.
    ///
    /// Sections 9.8 and 9.13 forbid one alias naming two tracks at once, and the
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
    /// Behind a lock for the same reason the record above it is: it is written
    /// from the data plane, which holds a shared reference.
    malformed: Mutex<MalformedTracks>,
    /// Where each track this endpoint receives has ended, once an end-of-track
    /// object has said so.
    ///
    /// Behind an `Arc` because the stream that reads a track's objects holds a
    /// handle onto it and the endpoint cannot be reached from there.
    locations: Arc<Mutex<TrackLocations>>,
    track_bindings: HashMap<u64, TrackBinding>,
}

/// The track a fetch this endpoint made asked for.
///
/// A standalone FETCH carries both fields and a Joining Fetch carries neither,
/// so what is kept is the answer rather than the question: whichever way the
/// fetch named its track, this is the track.
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
    /// The peer's SUBSCRIBE, established by this endpoint's SUBSCRIBE_OK.
    ///
    /// The alias is this endpoint's to choose on that one, because Section
    /// 9.8 carries it in the answer rather than in the request.
    PeerSubscribe,
}

/// A subscription the peer opened with SUBSCRIBE.
struct InboundSubscribe {
    /// The message as it arrived, which is what the application answers from.
    message: message::Subscribe,
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

/// An announcement the peer made with PUBLISH_NAMESPACE.
///
/// Kept apart from the announcements this endpoint made because the two are
/// answered by opposite ends: this one is waiting for an answer from here,
/// and the other for one from the peer.
struct InboundPublishNamespace {
    /// The message as it arrived, which is what the application answers from.
    message: PublishNamespace,
    /// How far the announcement it makes has got.
    state: PublishNamespaceStateMachine,
}
/// A track status the peer asked for with TRACK_STATUS.
///
/// Section 9.20 treats the request as a SUBSCRIBE "except it does not create
/// downstream subscription state", so it is recorded here and not among the
/// subscriptions the peer has opened. Nothing that names a subscription can
/// find it, which is the whole of what that exception asks for.
struct InboundTrackStatus {
    /// The message as it arrived, which is what the answer is built from.
    message: message::TrackStatus,
    /// How far the request it opened has got.
    state: TrackStatusStateMachine,
}
/// A SUBSCRIBE_NAMESPACE the peer sent, and how far the namespace subscription it opens
/// has got.
///
/// Kept apart from `subscribe_namespaces`, which holds the ones this endpoint made: the
/// two are answered by opposite ends, and this one is waiting for an answer
/// from here.
struct InboundSubscribeNamespace {
    /// The message as it arrived, which is what the answer is built from.
    message: SubscribeNamespace,
    /// How far the namespace subscription it opens has got.
    state: SubscribeNamespaceStateMachine,
    /// The namespace subscription this one overlapped when it arrived,
    /// which is when the rule about it is read.
    overlaps: Option<u64>,
}
impl Endpoint {
    /// Create a new endpoint with the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(role),
            advertised_max_id: 0,
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            fetch_tracks: HashMap::new(),
            subscribe_namespaces: HashMap::new(),
            subscribe_namespace_prefixes: HashMap::new(),
            inbound_subscribe_namespaces: HashMap::new(),
            publish_namespaces: HashMap::new(),
            publish_namespace_namespaces: HashMap::new(),
            inbound_publish_namespaces: HashMap::new(),
            track_statuses: HashMap::new(),
            inbound_track_statuses: HashMap::new(),
            publishes: HashMap::new(),
            inbound_publishes: HashMap::new(),
            inbound_subscribes: HashMap::new(),
            inbound_fetches: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
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

    /// The refusal Sections 9.8 and 9.13 require when `alias` already names a
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
    /// report Section 2.5's Malformed Track when it arrived after the
    /// place an end-of-track object put the end.
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

    /// Record how a track's object was framed, and report Section 10's "MUST NOT
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
    /// `&self`, which is the whole point of the lock. Section 2.5 answers a
    /// Malformed Track with a message per request, and the conditions that
    /// make a track malformed are detected on the data plane, where this
    /// endpoint is reached through a shared reference. A flow that could only
    /// be moved through `&mut self` would leave that sentence unanswerable
    /// from the only place it is ever read.
    ///
    /// Hold one guard at a time. Nothing here takes a second while a first is
    /// live, and [`Self::withdraw_malformed_track`] collects the requests it
    /// is going to move before it moves any of them for that reason.
    fn subscription(&self, id: u64) -> Option<MutexGuard<'_, SubscriptionStateMachine>> {
        self.subscriptions
            .get(&id)
            .map(|sm| sm.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    /// The publish flow `id` opened, locked for a read or a transition.
    ///
    /// One map for both directions, which is what makes this one accessor:
    /// the offer this endpoint made and the offer the peer made are the same
    /// flow read from opposite ends, and Request ID parity keeps them apart.
    fn publish_flow(&self, id: u64) -> Option<MutexGuard<'_, PublishStateMachine>> {
        self.publishes.get(&id).map(|sm| sm.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// The fetch `id` opened, locked for a read or a transition.
    fn fetch_flow(&self, id: u64) -> Option<MutexGuard<'_, FetchStateMachine>> {
        self.fetches.get(&id).map(|sm| sm.lock().unwrap_or_else(|p| p.into_inner()))
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
    /// give back the messages Section 2.5 asks for.
    ///
    /// "When a subscriber detects a Malformed Track, it MUST UNSUBSCRIBE any
    /// subscription and FETCH_CANCEL any fetch for that Track from that
    /// publisher, and SHOULD deliver an error to the application." This is the
    /// first half. The second is the error the detecting path returns, which
    /// is why nothing here reports anything: a caller that gets an empty list
    /// back is not being told the track was fine.
    ///
    /// `&self`, because the call site is the data plane's.
    ///
    /// # What comes back, and what does not
    ///
    /// One message for each request through which this endpoint is *receiving*
    /// the track: an UNSUBSCRIBE for a SUBSCRIBE it sent and for a PUBLISH the
    /// peer sent that it accepted, and a FETCH_CANCEL for each fetch it made
    /// for that track. A request that names the track the other way round is
    /// not one of those — a peer subscribing to this endpoint makes it the
    /// publisher, and a publisher does not unsubscribe from what it is
    /// serving.
    ///
    /// Empty for an alias no live binding names — there is no track to
    /// withdraw from — and for a track whose only requests are in a state that
    /// has no ending of that kind left in it.
    ///
    /// # Two records, one scan
    ///
    /// Subscriptions are found through the alias table and fetches through
    /// their own, because a fetch never holds an alias. Both are keyed by
    /// Request ID and a Request ID names one request, so the two lists cannot
    /// overlap and the withdrawal below can tell from the id alone which
    /// message a request takes.
    ///
    /// # What makes the answer happen once
    ///
    /// Not the record. The requests this withdraws end here, and a request
    /// that has ended has no second ending in it, so a publisher that goes on
    /// mixing a track's framing is answered once however many objects it
    /// sends. The record is read afterwards, by an application asking why a
    /// track it never gave up was given up.
    ///
    /// Which leaves the case the two answers differ on: an application that
    /// subscribes to the same track again. That request has never been
    /// withdrawn from, and a publisher mixing its framing again has broken the
    /// sentence again, so it is withdrawn from too.
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
        // Collected before any of them is moved. The liveness checks below
        // take each request's own lock and the transitions take it again, so
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
            .chain(self.fetch_tracks.iter().filter_map(|(&id, track)| {
                (track.namespace == namespace
                    && track.name == name
                    && self.fetch_flow(id).is_some_and(|sm| sm.state() != FetchState::Done))
                .then_some(id)
            }))
            .collect();
        // A HashMap iterates in no order, and two requests for one track is a
        // shape a peer can produce. Sorted so the wire is the same twice.
        ids.sort_unstable();
        ids.into_iter().filter_map(|id| self.withdraw_one(id)).collect()
    }

    /// The message ending one request, or `None` when that request is not one
    /// this endpoint receives a track through or is not in a state that can be
    /// ended that way.
    fn withdraw_one(&self, id: u64) -> Option<ControlMessage> {
        let request_id = VarInt::from_u64(id).ok()?;
        if let Some(mut sm) = self.subscription(id) {
            sm.on_unsubscribe().ok()?;
            return Some(ControlMessage::Unsubscribe(Unsubscribe { request_id }));
        }
        if let Some(mut sm) = self.fetch_flow(id) {
            sm.on_fetch_cancel().ok()?;
            return Some(ControlMessage::FetchCancel(FetchCancel { request_id }));
        }
        // `publishes` holds both directions and the offer's own message is
        // what tells them apart: only one the peer made is a track this
        // endpoint receives.
        self.inbound_publishes.get(&id)?;
        self.publish_flow(id)?.on_unsubscribe_sent().ok()?;
        Some(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Whether a binding's request has put its alias in play at all.
    ///
    /// Broader than [`Self::binding_is_established`], and the two sentences
    /// are why. What a subscriber must close over is qualified - "the same
    /// Track Alias as a different track with an active subscription" - and the
    /// prohibition on the publisher is not: "The same Track Alias MUST NOT be
    /// used to refer to two different Tracks simultaneously." Once a PUBLISH
    /// carrying an alias has been sent, giving that alias to a second track is
    /// what that sentence forbids, answered or not.
    fn binding_is_in_use(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => {
                self.subscription(id).is_some_and(|sm| sm.state() != SubscriptionState::Done)
            }
            BindingKind::Publish => {
                self.publish_flow(id).is_some_and(|sm| sm.state() != PublishState::Done)
            }
            BindingKind::PeerSubscribe => self
                .inbound_subscribes
                .get(&id)
                .is_some_and(|s| s.state.state() != SubscriptionState::Done),
        }
    }

    /// Whether the request that owns a binding still has a live subscription.
    ///
    /// The two kinds are answered by two different state machines because the
    /// two sequences Section 5.1 names end in different places: a SUBSCRIBE
    /// this endpoint made is live once its SUBSCRIBE_OK arrives, a PUBLISH the
    /// peer made once this endpoint has answered PUBLISH_OK.
    fn binding_is_established(&self, id: u64, kind: BindingKind) -> bool {
        match kind {
            BindingKind::Subscribe => {
                self.subscription(id).is_some_and(|sm| sm.state() == SubscriptionState::Active)
            }
            BindingKind::Publish => {
                self.publish_flow(id).is_some_and(|sm| sm.state() == PublishState::Active)
            }
            BindingKind::PeerSubscribe => self
                .inbound_subscribes
                .get(&id)
                .is_some_and(|s| s.state.state() == SubscriptionState::Active),
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

    /// Returns the number of active subscribe-namespace state machines.
    pub fn active_subscribe_namespace_count(&self) -> usize {
        self.subscribe_namespaces.len()
    }

    /// Returns the number of active publish-namespace state machines.
    pub fn active_publish_namespace_count(&self) -> usize {
        self.publish_namespaces.len()
    }

    /// Returns the number of active track status state machines.
    pub fn active_track_status_count(&self) -> usize {
        self.track_statuses.len()
    }

    /// Returns the number of active publish state machines.
    pub fn active_publish_count(&self) -> usize {
        self.publishes.len()
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
        // Section 9.3.2.3 puts no role restriction on MAX_REQUEST_ID, so a
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
    /// Section 9.1 closes the session with INVALID_REQUEST_ID on a request ID
    /// "that is not valid for the peer", and Section 9.5 closes it with
    /// TOO_MANY_REQUESTS on one at or above the ceiling this endpoint
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
    /// Section 9.5: a Request ID "equal to or larger than this" received by the
    /// endpoint that sent the MAX_REQUEST_ID in any request message - the list
    /// [`Self::receive_request`] carries - closes the session, and
    /// TOO_MANY_REQUESTS is the code. Which is also why the number measured
    /// against is the one **this** endpoint sent. An id that reaches the ceiling
    /// is not a request to refuse with an error message: the session is over, so
    /// this moves the endpoint's own state to Closed and leaves the code to
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
    ///
    /// Section 9.5: "The Maximum Request ID MUST only increase within a
    /// session, and receipt of a MAX_REQUEST_ID message with an equal or
    /// smaller Request ID value is a PROTOCOL_VIOLATION." Section 3.4 lists
    /// PROTOCOL_VIOLATION (0x3) among the codes for terminating the session -
    /// "The remote endpoint performed an action that was disallowed by the
    /// specification" - so naming it of a *receipt* is this draft saying the
    /// session ends, and with which code. Draft-16 states the same rule with
    /// the verb in it: "it MUST close the session with a PROTOCOL_VIOLATION".
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
    /// Section 9.5: "The Maximum Request ID MUST only increase within a
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

    /// Generate a REQUESTS_BLOCKED message indicating that this endpoint
    /// wants to create a new request but is blocked by the current
    /// MAX_REQUEST_ID.
    pub fn send_requests_blocked(&self) -> Result<ControlMessage, EndpointError> {
        let max_id = self.request_ids.max_id();
        Ok(ControlMessage::RequestsBlocked(RequestsBlocked {
            maximum_request_id: VarInt::from_u64(max_id).unwrap(),
        }))
    }

    /// Process an incoming REQUESTS_BLOCKED message from the peer.
    /// This signals that the peer wants to issue new requests but is
    /// limited by the MAX_REQUEST_ID we advertised.
    pub fn receive_requests_blocked(&self, _msg: &RequestsBlocked) -> Result<(), EndpointError> {
        // The peer is telling us they're blocked. This is informational;
        // the application layer should decide whether to increase MAX_REQUEST_ID.
        Ok(())
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
        // Section 9.4: "If a server receives a GOAWAY with a non-zero New
        // Session URI Length it MUST terminate the session with a
        // PROTOCOL_VIOLATION." Refused before the URI is stored rather than
        // after, so an application reading `goaway_uri` back can never be
        // handed somewhere a client chose to send it. The session ends with
        // it: the sentence names a close and a code, and an endpoint that
        // raised the error and carried on would keep serving a peer it had
        // just found in violation.
        if self.role == Role::Server && !msg.new_session_uri.is_empty() {
            return Err(self.fail_session(EndpointError::GoAwayUriAtServer));
        }
        // Section 9.4: "The endpoint MUST terminate the session with a
        // PROTOCOL_VIOLATION (Section 3.4) if it receives multiple GOAWAY messages."
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

    /// Send a SUBSCRIBE message. Allocates a request ID and creates a
    /// subscription state machine.
    ///
    /// `LargestObject` is a reasonable default. `AbsoluteStart` and
    /// `AbsoluteRange` name a start location, which this call has no way to
    /// supply, and are answered with [`EndpointError::FilterNeedsRange`] —
    /// use [`Self::subscribe_range`] for those. Without that refusal this
    /// call would hand back a message whose filter announces fields the
    /// message does not carry, which the encoder rejects.
    pub fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        if matches!(filter_type, FilterType::AbsoluteStart | FilterType::AbsoluteRange) {
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
    /// them: `end_group` present means AbsoluteRange and absent means
    /// AbsoluteStart. So the message cannot name a filter whose fields it does
    /// not carry.
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
        let filter_type = match end_group {
            Some(_) => FilterType::AbsoluteRange,
            None => FilterType::AbsoluteStart,
        };
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
        filter_type: FilterType,
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

        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: req_id,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            forward: Forward::Forward,
            filter_type,
            start_location,
            end_group,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
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
        self.subscription(id).expect("checked above").on_subscribe_ok()?;
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
    /// Section 5.1 gives the subscriber this for a subscription that came
    /// either way round, so a request the peer opened with PUBLISH ends here
    /// too. The two kinds share a map and cannot collide: a Request ID belongs
    /// to whichever endpoint allocated it, and the two halves of the space
    /// have opposite least significant bits.
    pub fn unsubscribe(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        if let Some(mut sm) = self.subscription(id) {
            sm.on_unsubscribe()?;
            return Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }));
        }
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe_sent()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Process an incoming SUBSCRIBE_UPDATE.
    ///
    /// Section 9.10 puts the message in the subscriber's hands, so one that
    /// arrives is about a subscription the **peer** opened, and is looked for
    /// among those and not among this endpoint's own.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UpdateForUnknownRequest`] when the Request ID names no
    /// request this session has carried, with the session already moved to
    /// Closed, and the subscription flow's own `InvalidTransition` when it
    /// names one that has already ended.
    pub fn receive_subscribe_update(&mut self, msg: &SubscribeUpdate) -> Result<(), EndpointError> {
        let id = msg.subscription_request_id.into_inner();
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
        // 9.10 counts the parameters set in PUBLISH_OK among the ones an
        // update may change.
        // Section 9.20 takes the update away from this request kind outright:
        // "the subscriber cannot send SUBSCRIBE_UPDATE or UNSUBSCRIBE". A track status
        // the peer asked for and one this endpoint asked for are the same kind
        // of request and neither is a subscription, so both are refused. The
        // check comes before the set below because an identifier naming a track
        // status has existed, and being told so is what would let it through.
        if self.track_statuses.contains_key(&id) || self.inbound_track_statuses.contains_key(&id) {
            return Err(EndpointError::NotASubscription(id));
        }
        let existed = self.subscriptions.contains_key(&id)
            || self.publishes.contains_key(&id)
            || self.fetches.contains_key(&id)
            || self.subscribe_namespaces.contains_key(&id)
            || self.publish_namespaces.contains_key(&id);
        if existed {
            return Ok(());
        }
        Err(self.fail_session(EndpointError::UpdateForUnknownRequest(id)))
    }

    /// Send a SUBSCRIBE_UPDATE for an active subscription. Allocates a fresh
    /// request ID for the update message and returns it alongside the message.
    pub fn subscribe_update(
        &mut self,
        subscription_request_id: VarInt,
        start_location: Location,
        end_group: VarInt,
        subscriber_priority: u8,
        forward: Forward,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let sub_id = subscription_request_id.into_inner();
        self.subscription(sub_id)
            .ok_or(EndpointError::UnknownRequest(sub_id))?
            .on_subscribe_update()?;
        let req_id = self.request_ids.allocate()?;
        let msg = ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: req_id,
            subscription_request_id,
            start_location,
            end_group,
            subscriber_priority,
            forward,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_DONE (subscriber side — publisher finished).
    ///
    /// Section 5.1 gives the publisher this for a subscription that came
    /// either way round, so one the peer opened with PUBLISH ends here too.
    pub fn receive_publish_done(&mut self, msg: &PublishDone) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        if let Some(mut sm) = self.subscription(id) {
            sm.on_publish_done()?;
            return Ok(());
        }
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done_received()?;
        Ok(())
    }

    // ── Answering a SUBSCRIBE the peer sent ────────────────────

    /// Process an incoming SUBSCRIBE, recording the subscription it opens.
    ///
    /// The Request ID has already been checked by [`Self::receive_request`],
    /// which every request message passes through before its own handler.
    /// There is no Track Alias to judge here: Section 9.8 carries it in the
    /// SUBSCRIBE_OK, so this endpoint chooses it, and it is judged when the
    /// answer is built.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the
    /// subscription flow's own `InvalidTransition` for a second SUBSCRIBE
    /// under a Request ID already carrying one.
    pub fn receive_subscribe(&mut self, msg: &message::Subscribe) -> Result<(), EndpointError> {
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
    pub fn pending_subscribe(&self, request_id: VarInt) -> Option<&message::Subscribe> {
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
    /// answered: Section 5.1 says "A publisher MUST send exactly one
    /// SUBSCRIBE_OK or SUBSCRIBE_ERROR in response to a SUBSCRIBE."
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
        Ok(ControlMessage::SubscribeOk(message::SubscribeOk {
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
        Ok(ControlMessage::SubscribeError(message::SubscribeError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming UNSUBSCRIBE, ending a subscription this endpoint
    /// publishes and freeing the Track Alias it held.
    ///
    /// Section 9.11: "A Subscriber issues an UNSUBSCRIBE message to a Publisher
    /// indicating it is no longer interested in receiving the specified Track,
    /// indicating that the Publisher stop sending Objects as soon as
    /// possible." The message travels from subscriber to publisher, so what it
    /// can end is whatever this endpoint publishes - and Section 5.1 gives
    /// that two sources, not one: "A subscription can be initiated by either a
    /// publisher or a subscriber."
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if this endpoint publishes no
    /// subscription under that identifier, [`EndpointError::NotASubscription`]
    /// for one that names a track status, [`EndpointError::Subscription`] if
    /// it is one the peer opened that this endpoint never accepted or has
    /// already ended, and [`EndpointError::PublishFlow`] for the same of one
    /// this endpoint opened.
    pub fn receive_unsubscribe(&mut self, msg: &message::Unsubscribe) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // The other half of the same sentence. Section 9.20: "the subscriber
        // cannot send SUBSCRIBE_UPDATE or UNSUBSCRIBE". Refused by name rather than left
        // to the miss below, which would say the identifier names nothing when
        // it names a request this session is carrying.
        if self.track_statuses.contains_key(&id) || self.inbound_track_statuses.contains_key(&id) {
            return Err(EndpointError::NotASubscription(id));
        }
        // The offers this endpoint made itself. `publishes` holds both
        // directions and the offer's own message is what tells them apart: one
        // the peer made was written down when it arrived and one of this
        // endpoint's never was. A peer sending UNSUBSCRIBE for its own PUBLISH
        // is the publisher ending a subscription the sentence above gives the
        // subscriber, so it falls to the miss below rather than being taken.
        if !self.inbound_publishes.contains_key(&id) {
            if let Some(mut sm) = self.publish_flow(id) {
                sm.on_unsubscribe_received()?;
                return Ok(());
            }
        }
        let sub = self.inbound_subscribes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_unsubscribe_received()?;
        Ok(())
    }

    // ── Fetch flow ─────────────────────────────────────────────

    /// Send a standalone FETCH, asking for a range of Objects independently of
    /// any subscription. Allocates a Request ID.
    ///
    /// Section 9.16.1 describes the range as two Locations: "Start Location:
    /// The start Location" and "End Location: The end Location, plus 1. A
    /// Location.Object value of 0 means the entire group is requested." The
    /// end is the caller's to name for the same reason the start is - a fetch
    /// that cannot say where it stops is a fetch for nothing - so all four
    /// bounds are parameters of this call rather than values it fills in.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the
    /// request-id error when this endpoint has no identifier left to spend.
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
        self.fetches.insert(req_id.into_inner(), Mutex::new(sm));
        // Recorded before the two of them are moved into the message: a fetch
        // that has left no track behind is one no withdrawal can find.
        self.fetch_tracks.insert(
            req_id.into_inner(),
            FetchTrack { namespace: track_namespace.clone(), name: track_name.clone() },
        );

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority,
            group_order,
            fetch_type: message::FetchType::Standalone,
            fetch_payload: message::FetchPayload::Standalone {
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
    /// Section 9.16.2: "A Joining Fetch is associated with a Subscribe request
    /// by specifying the Request ID of an active subscription. A publisher
    /// receiving a Joining Fetch uses properties of the associated Subscribe to
    /// determine the Track Namespace, Track Name and End Location such that it
    /// is contiguous with the associated Subscribe." So a joining fetch names
    /// neither the namespace nor the name, and `joining_start` is read against
    /// the subscription rather than against the track: Section 9.16.2.1 has the
    /// publisher set "the Start Location to {Subscribe Largest Location.Group -
    /// Joining Start, 0}", which makes it a count of groups back from the live
    /// edge.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established, and the
    /// request-id error when this endpoint has no identifier left to spend. A
    /// Request ID naming no subscription is not refused here — Section 9.16.2
    /// answers that at the publisher, "it MUST respond with a Fetch Error with
    /// code Invalid Joining Request ID", and this endpoint is the subscriber.
    pub fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.joining_fetch_of_type(
            message::FetchType::RelativeJoining,
            subscriber_priority,
            group_order,
            joining_request_id,
            joining_start,
            parameters,
        )
    }

    /// Send an Absolute Joining Fetch (Fetch Type 0x3).
    ///
    /// Section 9.16.2.1: "For an Absolute Joining Fetch, the publisher sets the
    /// Start Location to Joining Start." So `joining_start` is the group to
    /// begin at rather than a count of groups back, which is what an
    /// application that knows the group it wants actually has. Asking for the
    /// same range relatively would need the Largest Location, and a subscriber
    /// that has not yet been told one cannot compute the offset.
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
            message::FetchType::AbsoluteJoining,
            subscriber_priority,
            group_order,
            joining_request_id,
            joining_start,
            parameters,
        )
    }

    fn joining_fetch_of_type(
        &mut self,
        fetch_type: message::FetchType,
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
        self.fetches.insert(req_id.into_inner(), Mutex::new(sm));
        // Resolved through the join, once, here. Section 9.16.2 has the
        // publisher take the Track Namespace and Track Name from the
        // subscription this names, so that is the track, and a Request ID this
        // session holds no track for leaves the fetch out of the record
        // entirely rather than putting a guess in it.
        if let Some(binding) = self.track_bindings.get(&joining_request_id.into_inner()) {
            let track =
                FetchTrack { namespace: binding.namespace.clone(), name: binding.name.clone() };
            self.fetch_tracks.insert(req_id.into_inner(), track);
        }

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority,
            group_order,
            fetch_type,
            fetch_payload: message::FetchPayload::Joining { joining_request_id, joining_start },
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming FETCH_OK.
    pub fn receive_fetch_ok(&mut self, msg: &message::FetchOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let mut sm = self.fetch_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    /// Process an incoming FETCH_ERROR.
    pub fn receive_fetch_error(&mut self, msg: &message::FetchError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let mut sm = self.fetch_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_error()?;
        Ok(())
    }

    /// Send a FETCH_CANCEL message.
    pub fn fetch_cancel(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let mut sm = self.fetch_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
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
        let mut sm = self.fetch_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    /// Notify that a fetch data stream was reset.
    ///
    /// As with a FIN, it may arrive before the answer to the request.
    pub fn on_fetch_stream_reset(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let mut sm = self.fetch_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // ── Answering a FETCH the peer sent ────────────────────────

    /// Process an incoming FETCH, recording the fetch it opens.
    ///
    /// The Request ID has already been checked by [`Self::receive_request`],
    /// which every request message passes through before its own handler.
    ///
    /// A Joining Fetch is recorded like any other. Section 9.16.2 answers one
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
    /// Section 9.16.2:
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
    ///
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
    /// fetch flow's own `InvalidTransition` for a second answer: Section 5.1
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
    /// Section 9.16.2 names the code a Joining Fetch naming an unjoinable
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
    /// Section 9.19: the subscriber sends it to stop a fetch it no longer
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

    // ── Subscribe Namespace flow ───────────────────────────────

    /// Send a SUBSCRIBE_NAMESPACE message.
    ///
    /// Section 9.28 addresses the first half of the overlap rule to this end
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
    pub fn subscribe_namespace(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        // The subscriber's half of the rule, refused before the message
        // exists. A publisher that follows this draft answers it with a
        // refusal, so building it spends a Request ID on a namespace
        // subscription that is not going to open.
        if let Some(established) = self.own_prefix_overlap(&track_namespace) {
            return Err(EndpointError::OwnPrefixOverlap { established });
        }
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscribeNamespaceStateMachine::new();
        sm.on_subscribe_namespace_sent()?;
        self.subscribe_namespaces.insert(req_id.into_inner(), sm);
        self.subscribe_namespace_prefixes.insert(req_id.into_inner(), track_namespace.clone());

        let msg = ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: req_id,
            track_namespace,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_NAMESPACE_OK.
    pub fn receive_subscribe_namespace_ok(
        &mut self,
        msg: &SubscribeNamespaceOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_namespace_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_NAMESPACE_ERROR.
    pub fn receive_subscribe_namespace_error(
        &mut self,
        msg: &SubscribeNamespaceError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_namespace_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE_NAMESPACE message.
    pub fn unsubscribe_namespace(
        &mut self,
        request_id: VarInt,
        _track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe_namespace()?;
        let _ = request_id;
        Ok(ControlMessage::UnsubscribeNamespace(UnsubscribeNamespace {
            track_namespace_prefix: _track_namespace,
        }))
    }

    // ── Answering a SUBSCRIBE_NAMESPACE the peer sent ──────────

    /// Process an incoming SUBSCRIBE_NAMESPACE, recording the namespace
    /// subscription it opens.
    ///
    /// Section 9.28: "The subscriber sends the SUBSCRIBE_NAMESPACE control
    /// message to a publisher to request the current set of matching
    /// published namespaces and established subscriptions, as well as future
    /// updates to the set."
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
    pub fn receive_subscribe_namespace(
        &mut self,
        msg: &SubscribeNamespace,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let overlaps = self.peer_prefix_overlap(&msg.track_namespace);
        let mut state = SubscribeNamespaceStateMachine::new();
        state.on_subscribe_namespace_received()?;
        self.inbound_subscribe_namespaces.insert(
            msg.request_id.into_inner(),
            InboundSubscribeNamespace { message: msg.clone(), state, overlaps },
        );
        Ok(())
    }

    /// The earliest namespace subscription the peer has made whose prefix
    /// overlaps `prefix`, and `None` when there is none.
    ///
    /// Only ones that have not ended count: the sentence weighs the arriving
    /// prefix against "an active SUBSCRIBE_NAMESPACE", so one the peer has
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
        self.inbound_subscribe_namespaces
            .iter()
            .filter(|(_, s)| s.state.state() != SubscribeNamespaceState::Done)
            .filter_map(|(&id, s)| {
                prefixes_overlap(&s.message.track_namespace.0, &prefix.0).then_some(id)
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
    /// `None` once it has been answered, and for an identifier the peer has
    /// subscribed to nothing under. The record itself lives on past the
    /// answer, because a namespace subscription that was accepted is not over
    /// until it is withdrawn.
    pub fn pending_subscribe_namespace(&self, request_id: VarInt) -> Option<&SubscribeNamespace> {
        self.inbound_subscribe_namespaces
            .get(&request_id.into_inner())
            .filter(|s| s.state.state() == SubscribeNamespaceState::Pending)
            .map(|s| &s.message)
    }

    /// How many namespace subscriptions the peer has made that are still
    /// waiting for an answer.
    pub fn pending_subscribe_namespace_count(&self) -> usize {
        self.inbound_subscribe_namespaces
            .values()
            .filter(|s| s.state.state() == SubscribeNamespaceState::Pending)
            .count()
    }

    /// The identifier of a live namespace subscription the peer made for
    /// `prefix`.
    ///
    /// Section 9.31 names a Track Namespace Prefix where the
    /// SUBSCRIBE_NAMESPACE it ends named a Request ID, so one record has to
    /// be reachable both ways. It is stored under the identifier, which is
    /// unique, and found by prefix with a scan of the same map. A second map
    /// from prefix to identifier would be quicker and could fall out of step
    /// with the first; there is nothing here for it to disagree with.
    ///
    /// One that has ended is skipped, so a prefix subscribed again after
    /// being withdrawn finds the live one.
    fn inbound_subscribe_namespace_id(&self, prefix: &TrackNamespace) -> Option<u64> {
        self.inbound_subscribe_namespaces
            .iter()
            .find(|(_, s)| {
                s.message.track_namespace == *prefix
                    && s.state.state() != SubscribeNamespaceState::Done
            })
            .map(|(id, _)| *id)
    }

    /// Build the SUBSCRIBE_NAMESPACE_OK accepting a namespace subscription
    /// the peer made.
    ///
    /// Section 6.1: "A publisher MUST send exactly one SUBSCRIBE_NAMESPACE_OK
    /// or SUBSCRIBE_NAMESPACE_ERROR in response to a SUBSCRIBE_NAMESPACE."
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
    pub fn send_subscribe_namespace_ok(
        &mut self,
        request_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self
            .inbound_subscribe_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        // The MUST names one answer for this request, and it is not this one.
        if let Some(established) = sub.overlaps {
            return Err(EndpointError::PeerPrefixOverlap { request: id, established });
        }
        sub.state.on_subscribe_namespace_ok_sent()?;
        Ok(ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id }))
    }

    /// Build the SUBSCRIBE_NAMESPACE_ERROR refusing a namespace subscription
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
    pub fn send_subscribe_namespace_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sub = self
            .inbound_subscribe_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        if sub.overlaps.is_some() {
            let required = SubscribeNamespaceErrorCode::NamespacePrefixOverlap as u64;
            if error_code.into_inner() != required {
                return Err(EndpointError::WrongOverlapRefusal { request: id, required });
            }
        }
        sub.state.on_subscribe_namespace_error_sent()?;
        Ok(ControlMessage::SubscribeNamespaceError(SubscribeNamespaceError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming UNSUBSCRIBE_NAMESPACE, ending the namespace
    /// subscription the peer made.
    ///
    /// Section 6.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous
    /// SUBSCRIBE_NAMESPACE."
    ///
    /// The subscription it ends is the peer's, so the record it reads is the
    /// one this endpoint keeps of what the peer subscribed to. One this
    /// endpoint made is withdrawn by [`Endpoint::unsubscribe_namespace`],
    /// which is the same message travelling the other way.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespaceSubscription`] if the peer has no
    /// live namespace subscription for that prefix, and the namespace flow's
    /// own `InvalidTransition` for one this endpoint never accepted.
    pub fn receive_unsubscribe_namespace(
        &mut self,
        msg: &UnsubscribeNamespace,
    ) -> Result<(), EndpointError> {
        let id = self
            .inbound_subscribe_namespace_id(&msg.track_namespace_prefix)
            .ok_or(EndpointError::UnknownPeerNamespaceSubscription)?;
        let sub = self
            .inbound_subscribe_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        sub.state.on_unsubscribe_namespace_received()?;
        Ok(())
    }

    // ── Publish Namespace flow ─────────────────────────────────

    /// Send a PUBLISH_NAMESPACE message.
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
        self.publish_namespace_namespaces.insert(req_id.into_inner(), track_namespace.clone());

        let msg = ControlMessage::PublishNamespace(PublishNamespace {
            request_id: req_id,
            track_namespace,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_NAMESPACE_OK.
    pub fn receive_publish_namespace_ok(
        &mut self,
        msg: &PublishNamespaceOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_ok()?;
        Ok(())
    }

    /// Process an incoming PUBLISH_NAMESPACE_ERROR.
    pub fn receive_publish_namespace_error(
        &mut self,
        msg: &PublishNamespaceError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_error()?;
        Ok(())
    }

    // ── Answering a PUBLISH_NAMESPACE the peer sent ────────────

    /// Process an incoming PUBLISH_NAMESPACE, recording the announcement it
    /// makes.
    ///
    /// Section 9.23: "The publisher sends the PUBLISH_NAMESPACE control message
    /// to advertise that it has tracks available within a Track Namespace. The
    /// receiver verifies the publisher is authorized to publish tracks under
    /// this namespace."
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
    pub fn receive_publish_namespace(
        &mut self,
        msg: &PublishNamespace,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let id = msg.request_id.into_inner();
        let mut state = PublishNamespaceStateMachine::new();
        state.on_publish_namespace_received()?;
        self.inbound_publish_namespaces
            .insert(id, InboundPublishNamespace { message: msg.clone(), state });
        Ok(())
    }

    /// The PUBLISH_NAMESPACE the peer sent under `request_id` and this endpoint
    /// has not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier the peer has
    /// announced nothing under. The record itself lives on past the answer,
    /// because an announcement that was accepted is not over until it is
    /// withdrawn or cancelled.
    pub fn pending_publish_namespace(&self, request_id: VarInt) -> Option<&PublishNamespace> {
        self.inbound_publish_namespaces
            .get(&request_id.into_inner())
            .filter(|a| a.state.state() == PublishNamespaceState::Pending)
            .map(|a| &a.message)
    }

    /// How many announcements the peer has made that are still waiting for an
    /// answer.
    pub fn pending_publish_namespace_count(&self) -> usize {
        self.inbound_publish_namespaces
            .values()
            .filter(|a| a.state.state() == PublishNamespaceState::Pending)
            .count()
    }

    /// The identifier of a live announcement the peer made for `namespace`.
    ///
    /// Section 9.26: "The publisher sends the PUBLISH_NAMESPACE_DONE control
    /// message to indicate its intent to stop serving new subscriptions for
    /// tracks within the provided Track Namespace." and Section 9.27 says what
    /// a cancellation is for: the subscriber "will stop sending new
    /// subscriptions for tracks within the provided Track Namespace". Both name
    /// a namespace where the PUBLISH_NAMESPACE they are about named a Request
    /// ID, so one record has to be reachable both ways.
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
    fn inbound_publish_namespace_id(&self, namespace: &TrackNamespace) -> Option<u64> {
        self.inbound_publish_namespaces
            .iter()
            .find(|(_, a)| {
                a.message.track_namespace == *namespace
                    && a.state.state() != PublishNamespaceState::Done
            })
            .map(|(id, _)| *id)
    }

    /// Build the PUBLISH_NAMESPACE_OK accepting an announcement the peer made.
    ///
    /// Section 6.2: "A subscriber MUST send exactly one PUBLISH_NAMESPACE_OK or
    /// PUBLISH_NAMESPACE_ERROR in response to a PUBLISH_NAMESPACE. The
    /// publisher SHOULD close the session with a protocol error if it receives
    /// more than one."
    ///
    /// One answer and no second one: the flow moves on the first, and a second
    /// call finds a record that has left Pending.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has announced nothing
    /// under that identifier, and the namespace flow's own `InvalidTransition`
    /// for an announcement already answered.
    pub fn send_publish_namespace_ok(
        &mut self,
        request_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let ann = self
            .inbound_publish_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_publish_namespace_ok_sent()?;
        Ok(ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id }))
    }

    /// Build the PUBLISH_NAMESPACE_ERROR refusing an announcement the peer
    /// made.
    ///
    /// The same sentence in Section 6.2 answers both ways: one message back and
    /// no second one, whichever of the two it is.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has announced nothing
    /// under that identifier, and the namespace flow's own `InvalidTransition`
    /// for an announcement already answered.
    pub fn send_publish_namespace_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let ann = self
            .inbound_publish_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_publish_namespace_error_sent()?;
        Ok(ControlMessage::PublishNamespaceError(PublishNamespaceError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming PUBLISH_NAMESPACE_DONE, ending the announcement the
    /// peer made.
    ///
    /// Section 9.26: "The publisher sends the PUBLISH_NAMESPACE_DONE control
    /// message to indicate its intent to stop serving new subscriptions for
    /// tracks within the provided Track Namespace."
    ///
    /// The announcement it ends is the peer's, so the record it reads is the
    /// one this endpoint keeps of what the peer announced. An announcement this
    /// endpoint made is withdrawn by [`Self::publish_namespace_done`], which is
    /// the same message travelling the other way.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespace`] if the peer has no live
    /// announcement for that namespace, and the namespace flow's own
    /// `InvalidTransition` for one this endpoint never accepted.
    pub fn receive_publish_namespace_done(
        &mut self,
        msg: &PublishNamespaceDone,
    ) -> Result<(), EndpointError> {
        let id = self
            .inbound_publish_namespace_id(&msg.track_namespace)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        let ann = self
            .inbound_publish_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_publish_namespace_done_received()?;
        Ok(())
    }

    /// Build the PUBLISH_NAMESPACE_CANCEL revoking an acceptance.
    ///
    /// Section 8.4 names what a cancellation revokes: a namespace "it
    /// previously responded PUBLISH_NAMESPACE_OK to". Section 9.27 says what it
    /// does: the subscriber "will stop sending new subscriptions for tracks
    /// within the provided Track Namespace".
    ///
    /// Previously responded PUBLISH_NAMESPACE_OK to is a state, and it is
    /// Active: an announcement reaches it by being accepted and no other way.
    /// One still waiting for an answer, one refused and one already ended are
    /// all refused here rather than sent.
    ///
    /// The announcement is the peer's. An announcement this endpoint made is
    /// not cancelled by its own publisher; the peer cancels it, and that
    /// arrives at [`Self::receive_publish_namespace_cancel`].
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownPeerNamespace`] if the peer has no live
    /// announcement for that namespace, and the namespace flow's own
    /// `InvalidTransition` for one this endpoint never accepted.
    pub fn publish_namespace_cancel(
        &mut self,
        track_namespace: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = self
            .inbound_publish_namespace_id(&track_namespace)
            .ok_or(EndpointError::UnknownPeerNamespace)?;
        let ann = self
            .inbound_publish_namespaces
            .get_mut(&id)
            .ok_or(EndpointError::UnknownRequest(id))?;
        ann.state.on_publish_namespace_cancel_sent()?;
        Ok(ControlMessage::PublishNamespaceCancel(PublishNamespaceCancel {
            track_namespace,
            error_code,
            reason_phrase,
        }))
    }

    /// Send the PUBLISH_NAMESPACE_DONE withdrawing an announcement this
    /// endpoint made.
    ///
    /// Section 9.26: "The publisher sends the PUBLISH_NAMESPACE_DONE control
    /// message to indicate its intent to stop serving new subscriptions for
    /// tracks within the provided Track Namespace." This endpoint is that
    /// publisher, so the record it ends is one [`Self::publish_namespace`]
    /// opened.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownNamespace`] if this endpoint has announced
    /// nothing under that namespace, and the namespace flow's own
    /// `InvalidTransition` for an announcement the peer has not accepted, or
    /// has already cancelled.
    pub fn publish_namespace_done(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id = self
            .own_publish_namespace_id(&track_namespace)
            .ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_done()?;
        Ok(ControlMessage::PublishNamespaceDone(PublishNamespaceDone { track_namespace }))
    }

    /// Process an incoming PUBLISH_NAMESPACE_CANCEL, ending an announcement
    /// this endpoint made.
    ///
    /// Section 8.4 names what the peer is revoking: a namespace "it previously
    /// responded PUBLISH_NAMESPACE_OK to". What it responded to is an
    /// announcement this endpoint made, so the record this reads is the
    /// outbound one.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownNamespace`] if this endpoint has announced
    /// nothing under that namespace, and the namespace flow's own
    /// `InvalidTransition` for an announcement the peer never accepted.
    pub fn receive_publish_namespace_cancel(
        &mut self,
        msg: &PublishNamespaceCancel,
    ) -> Result<(), EndpointError> {
        let id = self
            .own_publish_namespace_id(&msg.track_namespace)
            .ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_cancel()?;
        Ok(())
    }

    /// The identifier of an announcement this endpoint made for `namespace`.
    ///
    /// The mirror of [`Self::inbound_publish_namespace_id`], over the other
    /// map: PUBLISH_NAMESPACE_DONE and PUBLISH_NAMESPACE_CANCEL name a
    /// namespace on this draft, and the announcements this endpoint made are
    /// filed under the Request IDs it allocated.
    fn own_publish_namespace_id(&self, namespace: &TrackNamespace) -> Option<u64> {
        self.publish_namespace_namespaces.iter().find(|(_, ns)| *ns == namespace).map(|(id, _)| *id)
    }

    // ── Track Status flow ────────────────────────────────────

    /// Send a TRACK_STATUS message, asking the publisher about a track.
    /// Allocates a Request ID.
    ///
    /// Section 9.20: "The TRACK_STATUS message format is identical to the
    /// SUBSCRIBE message", filter-dependent fields included, so the four the
    /// message names beyond the track - priority, group order, forward and
    /// filter type - are the caller's, as they are on draft-13, which words
    /// this message the same way.
    ///
    /// The filter types that need a range are refused rather than sent with an
    /// absent one, which is what [`Self::subscribe`] does with the same
    /// question one message over.
    ///
    /// # Errors
    ///
    /// [`EndpointError::FilterNeedsRange`] for `AbsoluteStart` or
    /// `AbsoluteRange`, the session error when the session is not established,
    /// and the request-id error when there is no identifier left to spend.
    #[allow(clippy::too_many_arguments)]
    pub fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        forward: Forward,
        filter_type: FilterType,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        if matches!(filter_type, FilterType::AbsoluteStart | FilterType::AbsoluteRange) {
            return Err(EndpointError::FilterNeedsRange);
        }
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_sent()?;
        self.track_statuses.insert(req_id.into_inner(), sm);
        let msg = ControlMessage::TrackStatus(message::TrackStatus {
            request_id: req_id,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            forward,
            filter_type,
            start_location: None,
            end_group: None,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming TRACK_STATUS_OK.
    pub fn receive_track_status_ok(
        &mut self,
        msg: &message::TrackStatusOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status_ok()?;
        Ok(())
    }

    /// Process an incoming TRACK_STATUS_ERROR.
    pub fn receive_track_status_error(
        &mut self,
        msg: &message::TrackStatusError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status_error()?;
        Ok(())
    }

    // ── Answering a TRACK_STATUS the peer sent ─────────────────

    /// Process an incoming TRACK_STATUS, recording what the peer asked about.
    ///
    /// Section 9.20: the receiver of one "treats it identically as if it had
    /// received a SUBSCRIBE message, except it does not create downstream
    /// subscription state or send any Objects". The exception is why this does
    /// not reach for the subscriptions the peer has opened: nothing that names
    /// a subscription is to find this request, and the surest way to hold to
    /// that is for it never to be one.
    ///
    /// # Errors
    ///
    /// The session error when the session is not established.
    pub fn receive_track_status(
        &mut self,
        msg: &message::TrackStatus,
    ) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        let id = msg.request_id.into_inner();
        let mut state = TrackStatusStateMachine::new();
        state.on_track_status_received()?;
        self.inbound_track_statuses.insert(id, InboundTrackStatus { message: msg.clone(), state });
        Ok(())
    }

    /// The TRACK_STATUS the peer sent under `request_id` and this endpoint has
    /// not answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session has
    /// carried no track status under.
    pub fn pending_track_status(&self, request_id: VarInt) -> Option<&message::TrackStatus> {
        self.inbound_track_statuses
            .get(&request_id.into_inner())
            .filter(|t| t.state.state() == TrackStatusState::Pending)
            .map(|t| &t.message)
    }

    /// How many track statuses the peer has asked about that are still waiting
    /// for an answer.
    pub fn pending_track_status_count(&self) -> usize {
        self.inbound_track_statuses
            .values()
            .filter(|t| t.state.state() == TrackStatusState::Pending)
            .count()
    }

    /// Build the TRACK_STATUS_OK accepting a track status the peer asked for.
    ///
    /// Section 9.21: "The publisher sends a TRACK_STATUS_OK control message in
    /// response to a successful TRACK_STATUS message", populating it "exactly
    /// as it would have populated a SUBSCRIBE_OK, setting Track Alias to 0".
    ///
    /// The alias is not a parameter for that reason: the one value the draft
    /// allows is the one this builds, so no caller can put another on the wire.
    /// The sentence after it is what keeps the alias out of the table this
    /// endpoint judges aliases against - "It is not considered an error if
    /// Track Alias 0 is already in use by an active subscription" - so nothing
    /// here consults that table and nothing here adds to it. An alias that
    /// names no track cannot collide with one that does.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has asked nothing under
    /// that identifier, and the flow's own `InvalidTransition` for a request
    /// already answered.
    pub fn send_track_status_ok(
        &mut self,
        request_id: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let req =
            self.inbound_track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        req.state.on_track_status_ok_sent()?;
        Ok(ControlMessage::TrackStatusOk(message::TrackStatusOk {
            request_id,
            track_alias: VarInt::from_u64(0).expect("0 fits in VarInt"),
            expires,
            group_order,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters,
        }))
    }

    /// Build the TRACK_STATUS_ERROR refusing a track status the peer asked for.
    ///
    /// Section 9.22: "The publisher sends a TRACK_STATUS_ERROR control message
    /// in response to a failed TRACK_STATUS message."
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] if the peer has asked nothing under
    /// that identifier, and the flow's own `InvalidTransition` for a request
    /// already answered.
    pub fn send_track_status_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let req =
            self.inbound_track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        req.state.on_track_status_error_sent()?;
        Ok(ControlMessage::TrackStatusError(message::TrackStatusError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    // ── Publish flow (publisher side) ─────────────────────────

    /// Offer the peer a subscription to a track this endpoint publishes.
    /// Allocates a Request ID.
    ///
    /// Section 5.1: "A subscription can be initiated by either a publisher or
    /// a subscriber. A publisher initiates a subscription to a track by
    /// sending the PUBLISH message. The subscriber either accepts or rejects
    /// the subscription using PUBLISH_OK or PUBLISH_ERROR."
    ///
    /// There is no `content_exists` parameter because it is not a choice.
    /// Section 9.13 makes it a flag for whether the field after it is there at
    /// all - "1 if an object has been published on this track, 0 if not. If 0,
    /// then the Largest Group ID and Largest Object ID fields will not be
    /// present" - so it is derived from `largest_location`, and the pair
    /// cannot be built disagreeing.
    ///
    /// `forward` is the subscription's initial Forward State, which Section
    /// 5.1 gives to whichever end opened it: "The initiator of the
    /// subscription sets the initial Forward State in either PUBLISH or
    /// SUBSCRIBE." Section 9.13 says what the peer may then assume of it: "1
    /// indicates the publisher will start transmitting objects immediately,
    /// even before PUBLISH_OK."
    ///
    /// # Errors
    ///
    /// [`EndpointError::TrackAliasInUse`] when some live request of this
    /// session already holds `track_alias` for a different track, which
    /// Section 9.13 forbids outright - "The same Track Alias MUST NOT be used
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
        let mut sm = PublishStateMachine::new();
        sm.on_publish_sent()?;
        self.publishes.insert(req_id.into_inner(), Mutex::new(sm));
        // The alias and the track travel together in a PUBLISH, so the binding
        // is complete the moment the message is built. What it counts against
        // from here depends on which comparison is asking: an offer this
        // endpoint is about to build is refused now, because the prohibition
        // is unqualified, and an arriving message closes the session only once
        // the peer's PUBLISH_OK has made the subscription active.
        self.track_bindings.insert(
            req_id.into_inner(),
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
        let msg = ControlMessage::Publish(message::Publish {
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

    /// Process an incoming PUBLISH_OK, which establishes the subscription this
    /// endpoint offered under that Request ID.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when this endpoint has offered
    /// nothing under that identifier, and the publish flow's own
    /// `InvalidTransition` for an offer that has been answered already:
    /// Section 5.1 says "A subscriber MUST send exactly one PUBLISH_OK or
    /// PUBLISH_ERROR in response to a PUBLISH. The peer SHOULD close the
    /// session with a protocol error if it receives more than one." The verb
    /// there is SHOULD, so the second answer is reported rather than acted on,
    /// and the caller decides.
    pub fn receive_publish_ok(&mut self, msg: &message::PublishOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // `publishes` holds both directions and this is what tells them apart:
        // an offer the peer made was written down when it arrived and one of
        // this endpoint's never was. The peer answering its own offer is not
        // something Section 5.1 allows - "The subscriber either accepts or
        // rejects the subscription using PUBLISH_OK or PUBLISH_ERROR", and the
        // subscriber of an offer the peer made is this endpoint - so the
        // identifier names a request and still names no offer of ours.
        if self.inbound_publishes.contains_key(&id) {
            return Err(EndpointError::UnknownRequest(id));
        }
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_ok()?;
        Ok(())
    }

    /// Send a PUBLISH_DONE message (publisher finishing).
    pub fn send_publish_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        // Section 9.12 gives the publisher this message for a subscription
        // that came either way round, so a subscription the peer opened with
        // SUBSCRIBE ends here too. Two records, one message.
        if let Some(sub) = self.inbound_subscribes.get_mut(&id) {
            sub.state.on_publish_done_sent()?;
            return Ok(ControlMessage::PublishDone(PublishDone {
                request_id,
                status_code,
                stream_count: VarInt::from_u64(0).unwrap(),
                reason_phrase,
            }));
        }
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done_sent()?;
        Ok(ControlMessage::PublishDone(PublishDone {
            request_id,
            status_code,
            stream_count: VarInt::from_u64(0).unwrap(),
            reason_phrase,
        }))
    }

    // ── Publish error ─────────────────────────────────────────

    /// Generate the PUBLISH_ERROR that rejects a PUBLISH the peer sent, which
    /// ends the subscription it opened before it was established.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when no PUBLISH arrived under that
    /// id, and the publish flow's own `InvalidTransition` for a second answer:
    /// Section 5.1 says "A subscriber MUST send exactly one PUBLISH_OK or
    /// PUBLISH_ERROR in response to a PUBLISH."
    pub fn send_publish_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_error_sent()?;
        Ok(ControlMessage::PublishError(message::PublishError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming PUBLISH_ERROR, which ends the subscription this
    /// endpoint offered under that Request ID before it was established.
    ///
    /// Section 5.1: "Objects MUST NOT be sent for requests that end with an
    /// error." The Track Alias the offer named is free again from here,
    /// because a binding reads liveness off this record rather than keeping a
    /// second copy of it.
    ///
    /// Neither a fall-through to the subscriptions this endpoint opened with
    /// SUBSCRIBE nor one to `Ok(())` would be right. A SUBSCRIBE is refused
    /// with SUBSCRIBE_ERROR, which arrives at
    /// [`Self::receive_subscribe_error`] and is answered there; and an
    /// identifier this session opened nothing under is one the peer had no
    /// reason to name, which the answer beside this one says as well.
    ///
    /// # Errors
    ///
    /// As [`Self::receive_publish_ok`].
    pub fn receive_publish_error(
        &mut self,
        msg: &message::PublishError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // `publishes` holds both directions and this is what tells them apart:
        // an offer the peer made was written down when it arrived and one of
        // this endpoint's never was. The peer answering its own offer is not
        // something Section 5.1 allows - "The subscriber either accepts or
        // rejects the subscription using PUBLISH_OK or PUBLISH_ERROR", and the
        // subscriber of an offer the peer made is this endpoint - so the
        // identifier names a request and still names no offer of ours.
        if self.inbound_publishes.contains_key(&id) {
            return Err(EndpointError::UnknownRequest(id));
        }
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_error()?;
        Ok(())
    }

    /// Process an incoming PUBLISH message, which opens a subscription this
    /// endpoint is the subscriber of.
    ///
    /// Section 5.1: "A publisher initiates a subscription to a track by
    /// sending the PUBLISH message. The subscriber either accepts or rejects
    /// the subscription using PUBLISH_OK or PUBLISH_ERROR." The record made here
    /// outlives that answer, because everything the section gives the
    /// subscription afterwards names this same request: an UNSUBSCRIBE from
    /// this endpoint, a PUBLISH_DONE from the peer, and the Track Alias the
    /// offer spends for as long as it lasts.
    ///
    /// # Errors
    ///
    /// [`EndpointError::DuplicateTrackAlias`] when the Track Alias offered is
    /// one a different live track already holds, which ends the session, and
    /// the publish flow's own `InvalidTransition` for a second PUBLISH under a
    /// request id already carrying one.
    pub fn receive_publish(&mut self, msg: &message::Publish) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        // Section 9.13 answers a PUBLISH naming an alias another live track
        // already holds with a session close, in the same words Section 9.8
        // uses for a SUBSCRIBE_OK. Judged before anything is written down, so
        // that a refused offer leaves no binding behind.
        let id = msg.request_id.into_inner();
        let alias = msg.track_alias.into_inner();
        if let Some(conflict) =
            self.conflicting_track_alias(id, alias, &msg.track_namespace, &msg.track_name)
        {
            return Err(self.fail_session(conflict));
        }
        let mut sm = PublishStateMachine::new();
        sm.on_publish_received()?;
        self.publishes.insert(id, Mutex::new(sm));
        // The offer as it arrived. The state machine above says how far it
        // has got and the binding says which track it is about; neither can
        // say what was offered, and that is what an answer is built from.
        self.inbound_publishes.insert(id, msg.clone());
        // A PUBLISH names its track and its alias in the one message, so the
        // binding is complete on arrival. It counts against the next one only
        // once this endpoint has answered PUBLISH_OK, which is what moves the
        // subscription to Active.
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

    /// The PUBLISH the peer sent under `request_id` and this endpoint has not
    /// answered yet.
    ///
    /// `None` once it has been answered, and for an identifier this session
    /// has carried no offer from the peer under -- an offer of this
    /// endpoint's own included, whose state is in the same map but whose
    /// message was never received. The record itself lives on past the
    /// answer, because the subscription the offer opened is not over until an
    /// UNSUBSCRIBE or a PUBLISH_DONE ends it.
    pub fn pending_publish(&self, request_id: VarInt) -> Option<&message::Publish> {
        let id = request_id.into_inner();
        let unanswered =
            self.publish_flow(id).is_some_and(|sm| sm.state() == PublishState::Publishing);
        self.inbound_publishes.get(&id).filter(|_| unanswered)
    }

    /// How many offers the peer has made that are still waiting for an answer.
    pub fn pending_publish_count(&self) -> usize {
        self.inbound_publishes
            .keys()
            .filter(|id| {
                self.publish_flow(**id).is_some_and(|sm| sm.state() == PublishState::Publishing)
            })
            .count()
    }
    /// Generate a PUBLISH_OK accepting a PUBLISH the peer sent, which
    /// establishes the subscription it opened.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnknownRequest`] when no PUBLISH arrived under that
    /// id, and the publish flow's own `InvalidTransition` for a second answer:
    /// Section 5.1 says "A subscriber MUST send exactly one PUBLISH_OK or
    /// PUBLISH_ERROR in response to a PUBLISH."
    #[allow(clippy::too_many_arguments)]
    pub fn send_publish_ok(
        &mut self,
        request_id: VarInt,
        forward: Forward,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
        start_location: Option<Location>,
        end_group: Option<VarInt>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let mut sm = self.publish_flow(id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_ok_sent()?;
        Ok(ControlMessage::PublishOk(message::PublishOk {
            request_id,
            forward,
            subscriber_priority,
            group_order,
            filter_type,
            start_location,
            end_group,
            parameters: vec![],
        }))
    }

    /// Hold a Request ID a peer allocated to the rules Section 9.1 states
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
    /// finding the state machine it names.
    ///
    /// # The list below is the rule, not a convenience
    ///
    /// Every message named here spends one of the peer's Request IDs, and
    /// nothing else does. That makes the list load-bearing in a way it was not
    /// before the sequence was tracked: a request left out of it spends an ID
    /// this endpoint never counts, so the peer's **next** request looks like a
    /// skip and a conforming session is closed over it. Section 9.1 names
    /// the set, and SUBSCRIBE_UPDATE is in it - it carries a Request ID of its own,
    /// alongside the separate field naming the request it modifies.
    ///
    /// # Errors
    ///
    /// The request-id errors, for a wrong parity, an id at or above the
    /// advertised ceiling, or one that is not the next in the peer's sequence.
    pub fn receive_request(&mut self, msg: &ControlMessage) -> Result<(), EndpointError> {
        let request_id = match msg {
            ControlMessage::Subscribe(m) => m.request_id,
            ControlMessage::Fetch(m) => m.request_id,
            ControlMessage::Publish(m) => m.request_id,
            ControlMessage::PublishNamespace(m) => m.request_id,
            ControlMessage::SubscribeNamespace(m) => m.request_id,
            ControlMessage::TrackStatus(m) => m.request_id,
            ControlMessage::SubscribeUpdate(m) => m.request_id,
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
            ControlMessage::Subscribe(ref m) => self.receive_subscribe(m),
            ControlMessage::Unsubscribe(ref m) => self.receive_unsubscribe(m),
            ControlMessage::Fetch(ref m) => self.receive_fetch(m),
            ControlMessage::FetchCancel(ref m) => self.receive_fetch_cancel(m),
            ControlMessage::Publish(ref m) => self.receive_publish(m),
            ControlMessage::PublishDone(ref m) => self.receive_publish_done(m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(m),
            ControlMessage::PublishError(ref m) => self.receive_publish_error(m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(m),
            ControlMessage::FetchError(ref m) => self.receive_fetch_error(m),
            ControlMessage::SubscribeNamespaceOk(ref m) => self.receive_subscribe_namespace_ok(m),
            ControlMessage::SubscribeNamespaceError(ref m) => {
                self.receive_subscribe_namespace_error(m)
            }
            ControlMessage::PublishNamespaceOk(ref m) => self.receive_publish_namespace_ok(m),
            ControlMessage::PublishNamespaceError(ref m) => self.receive_publish_namespace_error(m),
            ControlMessage::PublishNamespaceDone(ref m) => self.receive_publish_namespace_done(m),
            ControlMessage::TrackStatusOk(ref m) => self.receive_track_status_ok(m),
            ControlMessage::TrackStatusError(ref m) => self.receive_track_status_error(m),
            ControlMessage::TrackStatus(ref m) => self.receive_track_status(m),
            ControlMessage::PublishNamespace(ref m) => self.receive_publish_namespace(m),
            ControlMessage::PublishNamespaceCancel(ref m) => {
                self.receive_publish_namespace_cancel(m)
            }
            ControlMessage::SubscribeNamespace(ref m) => self.receive_subscribe_namespace(m),
            ControlMessage::UnsubscribeNamespace(ref m) => self.receive_unsubscribe_namespace(m),
            _ => Ok(()),
        }
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

    /// Publishing -> Active (PUBLISH_OK sent to the offering peer).
    pub fn on_publish_ok_sent(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_ok().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_ok_sent".to_string(),
        })
    }

    /// Publishing -> Done (PUBLISH_ERROR sent to the offering peer).
    pub fn on_publish_error_sent(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_error().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_error_sent".to_string(),
        })
    }

    /// Active -> Done (PUBLISH_DONE received from the offering peer).
    pub fn on_publish_done_received(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_done_sent().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_publish_done_received".to_string(),
        })
    }

    /// Active -> Done (UNSUBSCRIBE sent to the offering peer).
    ///
    /// The same transition as the one above and a separate name, because a
    /// refusal has to say which of the two events was refused.
    pub fn on_unsubscribe_sent(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_done_sent().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_unsubscribe_sent".to_string(),
        })
    }

    /// Active -> Done (UNSUBSCRIBE received from the subscribing peer).
    ///
    /// The mirror of the one above, on an offer this endpoint made rather than
    /// one it took. Both directions are held in this one map, so the event
    /// name is the only thing that says which of them was refused.
    pub fn on_unsubscribe_received(&mut self) -> Result<(), PublishFlowError> {
        self.on_publish_done_sent().map_err(|_| PublishFlowError::InvalidTransition {
            from: self.state(),
            event: "on_unsubscribe_received".to_string(),
        })
    }
}

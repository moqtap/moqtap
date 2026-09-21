//! The rules an endpoint enforces that its own decoder cannot see, named once
//! across the drafts that state them.
//!
//! # Why these do not live in the codec
//!
//! A decoder refuses a frame it cannot read. Every rule here is stated about a
//! frame that reads perfectly well — an Object whose properties are legal bytes
//! on a status that forbids properties, a GOAWAY that is a valid GOAWAY and is
//! the second one, a Request ID that is a valid varint and belongs to the other
//! endpoint's half of the number space. Being an *endpoint* rather than an
//! observer is what turns each of them into an error, so each is raised on a
//! receive path and never in the decoder.
//!
//! That placement is deliberate and it has a cost: a caller that reads
//! [`crate::dispatch::ErrorCause::Codec`] to find out which rule a peer broke
//! sees none of them, because the codec never raised anything.
//! [`AboveCodecRule`] is the other half of that answer.
//!
//! # Two groups, one enum
//!
//! **What one frame says about itself.** Three rules, across six drafts, each
//! comparing two fields of a single message: properties against a status, a
//! payload against a status, a stream's first message type against the set of
//! types that may open one. They reach here through
//! `Connection::draft_specific_cause`, which every draft implements over its own
//! `ConnectionError`.
//!
//! The drafts renamed two of the three and widened one, and none of the three
//! changes altered what is required:
//!
//! - **Properties on a non-Normal status.** Drafts 15 and 16 call the block
//!   *extension headers* and drafts 17 through 20 call it *properties*. Same
//!   sentence, same consequence, one rule.
//! - **A bidirectional stream's opening message.** Draft-16 permits exactly two
//!   openers and names SUBSCRIBE_NAMESPACE as the second; drafts 17 through 20
//!   permit any message that begins a request stream. The legal set grew, the
//!   requirement did not.
//! - **A payload on a status that permits none.** Drafts 17 through 20 only,
//!   and the one of the three the drafts state *without* a close — see
//!   [`AboveCodecRule::PayloadOnStatusDatagram`].
//!
//! **What a message says about the session it arrived in.** The rest, across
//! all the drafts, each comparing a message against state this endpoint
//! has been keeping: a Request ID against the sequence the peer's own ids
//! follow, a GOAWAY against whether one has already arrived, a Track Alias
//! against the track it already names, an Object's Location against the one the
//! track ended at. They reach here through `EndpointError::fault`, which every
//! draft implements over its own `EndpointError`.
//!
//! No frame carries the fact that decides any of them, so no decoder built for
//! any draft could refuse one — the same reason the first group is here, one
//! layer further out.
//!
//! # Which draft states which is not asked here
//!
//! It is answered per draft, beside the variant whose doc comment quotes that
//! draft's own sentence — the same division of labour
//! `Connection::codec_session_error_code` already has for the decoder's errors.
//! A rule named here on ten drafts and not on the other four is not a claim
//! that the other four permit it; it is a claim that this build enforces it
//! where the text says to.
//!
//! # And a second enum, for the rules the decoder *did* refuse
//!
//! [`CodecRule`] is at the foot of this file and is the other half of the same
//! job. Everything above is a rule no decoder could have caught; everything
//! there is one a decoder caught and nothing carried the draft's own sentence
//! for. The two are kept apart because they are two kinds of evidence — see
//! that enum's own doc — and they share this file for one reason:
//! `scripts/check-drafts.py` rule 8 reads [`RuleCitation`] rows out of **this
//! path**, so a citation written anywhere else is a citation nothing checks.

/// A rule a peer broke that no decoder could have caught.
///
/// Deliberately **not** `#[non_exhaustive]`. A consumer matching on this — a
/// conformance report deciding what it will name a relay for — should find out
/// about a new rule by failing to build, not by silently filing it under a
/// wildcard arm.
///
/// The `close` that travels beside it in
/// [`crate::dispatch::ErrorCause::PeerViolation`] is the negotiated draft's
/// own, and several of these are stated with a close on some drafts and without
/// one on others. The rule is the same rule either way; what the draft does
/// about it is the other field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AboveCodecRule {
    // ── What one frame says about itself ───────────────────────
    /// An Object arrived carrying properties on a status that is not Normal.
    ///
    /// Drafts 15 and 16 state it of *extension headers* and drafts 17 through
    /// 20 of *properties*; the block was renamed and the rule was not. Every
    /// draft that states it answers it with a close, so a caller reading
    /// [`crate::dispatch::ErrorCause::PeerViolation`] finds `close: Some` on
    /// all six.
    PropertiesOnNonNormalStatus,
    /// A datagram whose header declared a status permitting no payload arrived
    /// with bytes after the header.
    ///
    /// The one rule here the drafts state as a property of a conforming Object
    /// rather than as a "MUST close the session" case, so `close` is `None` on
    /// every draft that states it, and the datagram is refused with the session
    /// left running. A caller that gates on `close: Some` will therefore never
    /// see this one, which is the correct behaviour and not an oversight: a
    /// relay cannot be published for breaking a rule its draft attaches no
    /// consequence to.
    PayloadOnStatusDatagram,
    /// A bidirectional stream the peer opened began with a message type the
    /// draft does not permit one to begin with.
    ///
    /// The permitted set differs — draft-16 allows the control stream and
    /// SUBSCRIBE_NAMESPACE, drafts 17 through 20 allow any message that begins
    /// a request stream — and the sentence that forbids the rest is the same on
    /// all four. The offending stream is reset and the session closed before
    /// the error is returned.
    ///
    /// Reached from both halves of this module: a draft's own `ConnectionError`
    /// raises it where the connection owns the stream, and `EndpointError`
    /// where the endpoint does. One rule, so one name.
    BidiStreamOpener,

    // ── What a message says about the session ──────────────────
    /// A message arrived on a stream the draft does not place it on.
    ///
    /// The control stream carrying one the draft puts on a request stream, a
    /// request stream carrying one that may not follow a request there, a
    /// response arriving where no request is outstanding. Draft-16 states it of
    /// NAMESPACE and NAMESPACE_DONE; drafts 18 through 20 state it of every
    /// message their Table 5 gives a Stream value to.
    ///
    /// Distinct from [`Self::BidiStreamOpener`], which is about the *first*
    /// message on a stream and is what decides what that stream is. This is
    /// about a later one arriving somewhere it does not belong.
    ///
    /// # No draft states a close for it
    ///
    /// The rule is real — a NAMESPACE on the control stream names no request
    /// and there is nothing for a receiver to do with it — and the
    /// **consequence** would be ours to invent. The tempting one is
    /// `Some(PROTOCOL_VIOLATION)`, on the reading that Section 3.3's opener
    /// sentence covers a message on the wrong stream. It does not: that
    /// sentence is about what a bidirectional stream may *begin* with, and a
    /// message arriving on the control stream begins nothing.
    ///
    /// Read across all texts for a sentence that closes a session over
    /// a message being in the wrong place, there is none. The drafts state
    /// placement per message, mostly descriptively; drafts 18 through 20 add a
    /// Stream column to their message table, whose only MUST is that a message
    /// marked First is the first message on a new request stream — which is
    /// [`Self::BidiStreamOpener`]'s subject and names no code; and the only
    /// sentence in the range that closes a session over misplacement is drafts
    /// 19 and 20's REQUEST_UPDATE sentence, which is
    /// [`Self::RequestUpdateForTheWrongRequest`]'s.
    ///
    /// So a close here would be this build's model of the protocol rather than
    /// a draft's. `session_error_code` answers `None` for every variant that
    /// reaches this rule on every draft that raises it, and the receive paths
    /// that raise them do not fail the session: the message is refused, the
    /// caller is told, and the session runs on — which it can, because a
    /// control message carries its own length and the next boundary on the
    /// stream is known however this one was refused.
    ///
    /// One variant is covered by a draft sentence and is filed under the rule
    /// that carries it rather than here. A REQUEST_UPDATE on the control stream
    /// is, on drafts 19 and 20, squarely inside the sentence that closes over a
    /// REQUEST_UPDATE outside the two cases those drafts permit — the first of
    /// which is the request's own bidi stream — so it is
    /// [`Self::RequestUpdateForTheWrongRequest`] there, with the citation that
    /// rule already carries. On drafts 17 and 18 the same message answers
    /// `None`, because those drafts describe the placement and attach no
    /// consequence to it.
    ///
    /// The rule stays named. It is enforced, it is the peer's doing, and a
    /// draft that attaches a consequence to it should arrive here as a citation
    /// rather than as a rediscovery.
    MessageOnTheWrongStream,
    /// A response arrived on one request's stream naming a different request.
    ///
    /// Draft-16 only, and only because that draft has both halves at once: a
    /// stream per namespace subscription *and* a Request ID on the messages
    /// that travel it, so the two can disagree. Drafts 17 and later deleted the
    /// id from responses, which deletes the disagreement.
    ResponseNamesAnotherRequest,
    /// A request stream's response half opened with something other than the
    /// response the draft requires first.
    ///
    /// Drafts 18 through 20, of SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS: "If
    /// the subscriber receives any message other than a REQUEST_OK or a
    /// REQUEST_ERROR as the first message on the response half of the stream,
    /// then it MUST close the session with a PROTOCOL_VIOLATION."
    ResponseBeforeItsFirstResponse,
    /// A GOAWAY arrived at a server that had no standing to be sent one.
    ///
    /// Draft-07 states the rule about the message — a server may not be sent a
    /// GOAWAY at all — and drafts 08 through 20 about the migration URI it
    /// carries, since only a server may tell a client where to reconnect. The
    /// rename is the same shape as [`Self::PropertiesOnNonNormalStatus`]'s: the
    /// text moved the prohibition onto the field, and what a conforming client
    /// may send did not change.
    GoAwayAtServer,
    /// A second GOAWAY arrived where the draft allows one.
    ///
    /// Per session on every draft, and from draft-18 also per request stream —
    /// that draft lets a GOAWAY migrate a single request, so one on each of two
    /// request streams is two first GOAWAYs and not a repeat. Both are the same
    /// sentence read at two scopes.
    RepeatedGoAway,
    /// A server received a Redirect carrying a Connect URI.
    ///
    /// Drafts 18 through 20. The same standing [`Self::GoAwayAtServer`] is
    /// about, stated of the message that replaced GOAWAY's migration half.
    RedirectUriAtServer,
    /// A Redirect answering a namespace-scoped request carried a Track Name.
    ///
    /// Drafts 18 through 20: "an endpoint that receives a non-empty Track Name
    /// in a Redirect for a namespace-scoped request MUST close the session with
    /// a PROTOCOL_VIOLATION."
    ///
    /// Which requests are namespace-scoped is named in the first half of that
    /// same sentence, and is described here rather than quoted because the list
    /// is the half of it that moves: draft-18 names SUBSCRIBE_NAMESPACE and
    /// PUBLISH_NAMESPACE, and drafts 19 and 20 add SUBSCRIBE_TRACKS. An
    /// ellipsis across that list would join the clause before it to the clause
    /// after it and make a sentence none of the three drafts has — which a
    /// checker reports as *in no draft at all*, and which a reader cannot tell
    /// from a transcription.
    RedirectTrackNameOnNamespaceRequest,
    /// A Request ID arrived whose least significant bit belongs to this
    /// endpoint's half of the number space.
    ///
    /// Drafts 11 and later, which split the space by parity. Drafts 07 through
    /// 10 have one shared sequence and state no parity rule, so they cannot
    /// break this one.
    RequestIdParity,
    /// A new request carried a Request ID that is not the next one the peer's
    /// own sequence calls for.
    ///
    /// A repeat and a skip alike. Drafts 11 through 16 state it as "a new
    /// request with a Request ID that is not expected" and drafts 17 through 20
    /// as "a duplicate Request ID"; drafts 07 through 10 require the shared
    /// Subscribe ID to be "unique and monotonically increasing". Three
    /// phrasings of one requirement — that an id identifies exactly one request
    /// for the life of a session.
    RequestIdOutOfSequence,
    /// A request carried a Request ID at or above the ceiling this endpoint
    /// advertised.
    ///
    /// Drafts 07 through 16. The number measured against is the one **this**
    /// endpoint sent, not the one the peer sent it, and the two are different
    /// values. Draft-17 removed MAX_REQUEST_ID and the drafts after it have not
    /// brought it back, so there is no ceiling left to exceed.
    RequestIdCeiling,
    /// A ceiling the peer raised did not increase.
    ///
    /// Every draft from 07 to 16 states it, and no one sentence covers them.
    /// Drafts 11 through 13: "The Maximum Request ID MUST only increase within
    /// a session, and receipt of a MAX_REQUEST_ID message with an equal or
    /// smaller Request ID value is a 'Protocol Violation'."
    ///
    /// The other three eras say the same thing in different words. Drafts 07
    /// through 10 state it of the Maximum Subscribe Id and MAX_SUBSCRIBE_ID;
    /// drafts 14 and 15 carry draft-14's rename of the code, so the sentence
    /// ends `is a PROTOCOL_VIOLATION` with no quotation marks on it; and
    /// draft-16 splits it in two, keeping the first clause as a sentence of its
    /// own and answering the second with a close. Draft-17 removed
    /// MAX_REQUEST_ID and nothing after it restored one, so there is no ceiling
    /// left for a peer to lower. A setup parameter carrying the same field is
    /// held to the same sentence.
    ///
    /// The mirror — this endpoint asked to send a ceiling of its own that does
    /// not increase — is a separate `EndpointError` variant on every draft that
    /// has this one, so that the two never arrive as the same value. See
    /// [`EndpointFault`] for why one variant covering both would have been a
    /// silent wrong answer rather than an imprecise one.
    MaxRequestIdDecreased,
    /// A setup parameter arrived with a value of a kind the draft does not give
    /// that parameter.
    ///
    /// Drafts 07 through 10, where MAX_SUBSCRIBE_ID is read out of the setup
    /// block by hand. The frame decodes — a key-value pair holding bytes where
    /// a varint was meant is a well-formed key-value pair — so the decoder
    /// cannot see it and the endpoint reading the parameter is what does.
    SetupParameterValue,
    /// The peer used one Track Alias for two different tracks at once.
    ///
    /// Every draft states it, and every draft names a code of its own for it
    /// rather than the general one — which is why the code travels beside the
    /// rule instead of being assumed from it.
    DuplicateTrackAlias,
    /// Objects of one track arrived under more than one forwarding preference.
    ///
    /// Drafts 07 through 11: "it SHOULD close the session with an error of
    /// 'Protocol Violation'". SHOULD, so the close is the caller's to make and
    /// this build's is opt-in. The condition the drafts state it of narrows at
    /// draft-11, from any two differing preferences to Objects arriving on both
    /// Subgroup streams and datagrams for one SUBSCRIBE; the consequence is the
    /// same clause either way, which is why the clause and not the whole
    /// sentence is what is quoted.
    ///
    /// Drafts 12 through 15 raise it as well and answer it with nothing. That
    /// is where a differing Forwarding Preference became one entry in the
    /// Malformed Track list, and what those drafts require of a subscriber that
    /// detects one is an UNSUBSCRIBE and an error to the application — see
    /// [`Self::ObjectPastFinalObject`], which is another entry in the same
    /// list. The quotation is held to drafts 07 through 11 for that reason:
    /// ranging it across all nine would file four drafts' silence under a
    /// sentence they dropped.
    MixedForwardingPreference,
    /// An Object with status END_OF_TRACK arrived somewhere the draft does not
    /// allow one.
    ///
    /// Drafts 08 through 13: "the receiver MUST terminate the session".
    EndOfTrackOutOfPlace,
    /// An Object arrived past the Object the track had already ended at.
    ///
    /// Drafts 12 and later. A Malformed Track rather than a session error, and
    /// what the drafts require of a subscriber that detects one moves twice
    /// across that range. The words here are drafts 17 through 20's: "it MUST
    /// cancel any corresponding subscription or fetches for that Track from
    /// that publisher".
    ///
    /// Drafts 12 and 13 say UNSUBSCRIBE from the Track; drafts 14 through 16
    /// say UNSUBSCRIBE any subscription and FETCH_CANCEL any fetch for that
    /// Track from that publisher, which is the same operation named by the two
    /// messages that perform it. All three are transport operations on the
    /// requests and none of them is a close, so `close` is `None` wherever this
    /// appears — the reading the range shares, and the reason one quotation
    /// stands for the whole of it here.
    ///
    /// *Past* is the drafts' own Location comparison and not a reading of the
    /// word: an Object in a later group is past the end whatever its own Object
    /// ID is.
    ObjectPastFinalObject,
    /// An update arrived naming a request that cannot take one.
    ///
    /// A request the session has never carried, one that has already ended, one
    /// of a kind the draft does not let a subscriber update. Drafts 12 through
    /// 20 state some of these; drafts 19 and 20 gather them into one sentence —
    /// "An endpoint that receives a REQUEST_UPDATE other than in the two cases
    /// above MUST close the session with a PROTOCOL_VIOLATION."
    RequestUpdateForTheWrongRequest,
    /// More outstanding REQUEST_UPDATEs on one stream than this endpoint
    /// advertised room for.
    ///
    /// Drafts 19 and 20: "If an endpoint receives a REQUEST_UPDATE on a stream
    /// that already has MAX_REQUEST_UPDATES outstanding REQUEST_UPDATEs, it
    /// MUST close the session with TOO_MANY_REQUEST_UPDATES."
    ///
    /// The ceiling beside it in the same section, MAX_FILTER_RANGES, is
    /// answered with a REQUEST_ERROR instead, and nothing about either sentence
    /// signals which — see [`EndpointFault::ThisEndpoint`], which is where that
    /// one lands.
    TooManyRequestUpdates,
    /// Track Properties arrived on a REQUEST_OK answering something that is not
    /// a TRACK_STATUS.
    ///
    /// Drafts 18 through 20: they "are empty in PUBLISH_OK, REQUEST_UPDATE_OK,
    /// SUBSCRIBE_NAMESPACE_OK and PUBLISH_NAMESPACE_OK. If an endpoint receives
    /// Track Properties in one of these messages it MUST close the session with
    /// a PROTOCOL_VIOLATION."
    TrackPropertiesOnNonTrackStatus,
    /// A PUBLISH_STATE_NOTIFY arrived for something that is not a subscription,
    /// or from the end of one that may not send it.
    ///
    /// Draft-20, one sentence covering both: "PUBLISH_STATE_NOTIFY applies only
    /// to subscriptions, and is sent only by the publisher. An endpoint that
    /// receives a PUBLISH_STATE_NOTIFY for any other request type, or from the
    /// subscriber, MUST close the session with a PROTOCOL_VIOLATION."
    StateNotifyOnTheWrongRequest,
    /// A fill fetch stream opened against a request that asked for no fill.
    ///
    /// Draft-20, where `FILL_PARAMETERS` is the whole of the request: "Its
    /// presence is what requests a fill fetch stream; a subscription with no
    /// FILL_PARAMETERS opens none." Not a close — the draft states no
    /// consequence, and the honest handling is `STOP_SENDING` on that stream
    /// alone.
    UnrequestedFillStream,
    /// A SUBSCRIBE arrived for a namespace the peer had cancelled.
    ///
    /// Draft-07 alone: "it SHOULD close the session as a 'Protocol Violation'".
    /// The mechanism it is stated about, ANNOUNCE_CANCEL against a namespace
    /// the subscriber then subscribes under, survives the later drafts; the
    /// sentence does not.
    SubscribeAfterAnnounceCancel,
    /// An UNSUBSCRIBE or REQUEST_UPDATE arrived naming a TRACK_STATUS.
    ///
    /// Drafts 13 through 18: a track status request is answered once and is
    /// never a subscription, so there is nothing for either message to act on.
    /// The drafts state it without a code, so `close` is `None`.
    TrackStatusIsNotASubscription,
    /// A message arrived naming a request this session has no record of.
    ///
    /// Stated by every draft of the messages that carry an id, and answered by
    /// none of them with a code, so `close` is `None` throughout.
    ///
    /// This is narrower than it looks. Most of the variants that could carry it
    /// are raised on both a receive path and a send path and answer
    /// [`EndpointFault::EitherEnd`] instead; only the ones a draft raises on a
    /// receive path alone reach this rule.
    MessageNamesAnUnknownRequest,
    /// The peer subscribed to a namespace prefix overlapping one it already has.
    ///
    /// Drafts 07 through 10, which catch it as the message arrives. From
    /// draft-11 the same condition is caught where the answer is built, which
    /// makes it a refusal this endpoint owes rather than a fault it observed —
    /// see [`EndpointFault::ThisEndpoint`].
    ///
    /// Never a close on any draft: "it MUST respond with REQUEST_ERROR with
    /// error code PREFIX_OVERLAP" is a reply, and a reply needs the request it
    /// answers to have been taken.
    NamespacePrefixOverlap,
}

/// One draft's own words for one rule: the sentence, the section it sits in,
/// and what that draft calls the code it answers the rule with.
///
/// # A citation with no draft in it is a citation about no draft
///
/// [`AboveCodecRule`] names a rule across every draft that states it, and that
/// is what makes one rule one row in a conformance report rather than rows
/// that happen to rhyme. The *sentence* cannot be shared that way: one
/// quoted sentence per rule, printed beside whichever draft was negotiated,
/// publishes words the negotiated draft does not contain.
///
/// [`AboveCodecRule::DuplicateTrackAlias`] is the worked example. Draft-18
/// states it in Section 11.1 and spells the code DUPLICATE_TRACK_ALIAS;
/// draft-07 states it in Section 6.4, in different words, and spells the same
/// code Duplicate Track Alias. Publishing draft-18's row against a draft-07
/// session would be three wrong facts at once — sentence, section and name —
/// each dressed as evidence, and the row would read as checked.
///
/// The close *code* is a separate field and is not flattened with them. It
/// comes from each draft's own `EndpointError::session_error_code`, and those
/// fourteen tables answer 0x4 on drafts 07 through 10 and 0x5 from draft-11 on.
/// Draft-07 numbers 0x5 Parameter Length Mismatch, so a row that borrows a
/// neighbour's *name* for its own number names a different error entirely. The
/// sentence, the section and the name are the three things a reader uses to
/// check the number, which is why each is stored per run.
///
/// # Runs, and not a row per draft
///
/// Twenty-eight rules with a citation per draft is several hundred rows, and
/// most of them
/// would be one sentence written out again. A row here covers a **run**: every
/// draft over which one sentence sits under one section. The sentence itself is
/// a named constant, so a wording shared by three runs — or by two different
/// rules, which is what happens where one sentence states both the parity rule
/// and the sequence rule — is written once and pointed at from each.
///
/// Seventy-eight rows over fifty-five sentences cover every rule this build can
/// publish. The row count is a fact about the drafts rather than about the
/// representation: runs break where draft-14 renamed Protocol Violation to
/// PROTOCOL_VIOLATION, where draft-16 changed terminate to close, and — far
/// more often than either — where a section number moved under a sentence that
/// did not change at all. The Track Alias rule alone runs 6.4, 7.4, 8.6, 8.7,
/// 8.8, 9.8, 9.10, 9.9, 11.1 across the drafts, and only four of those eight
/// moves coincide with a change of wording.
///
/// # What checks it
///
/// `scripts/check-drafts.py` rule 8 reads this table out of this file and holds
/// every row against the drafts it names: that the sentence is in every draft
/// of the run, that it sits in the section the row gives, and that the code
/// name the row carries is a name the sentence itself uses. It is the only rule
/// in that script that reads a Rust value rather than a comment, and it is here
/// because a citation the gate cannot see is not a checked citation. A
/// catalogue of sentences kept outside this workspace is walked by no gate
/// here, so its rows are read by no machine at all.
///
/// # What is deliberately not here
///
/// Whether the negotiated draft answers the rule with a session close.
/// `session_error_code` answers that, per draft, quoting the sentence that
/// names it, and a second copy of that answer here could disagree with it. So a
/// row whose [`Self::code_name`] is `None` is a draft that states the rule and
/// names no code for it — **not** a draft that states no consequence. Two rules
/// here are in that position on some of their drafts and neither is a gap: the
/// end-of-Track rule says the receiver MUST terminate the session without
/// naming which code, and drafts 07 through 10 state the Subscribe ID
/// uniqueness requirement with no consequence at all, which is why those
/// drafts' `session_error_code` answers `None` for it and no row is ever
/// published there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCitation {
    /// The first and last draft this citation is claimed for, inclusive.
    pub drafts: (u8, u8),
    /// The section every draft in [`Self::drafts`] files the sentence under.
    ///
    /// One section for the whole run, because the run is cut wherever the
    /// number moves. That is why a rule can have more rows than it has
    /// wordings.
    pub section: &'static str,
    /// The sentence, in those drafts' own words.
    ///
    /// Verbatim, including what a transcriber would want to correct: the
    /// cross-references the renderings carry *inside* the sentence, draft-14's
    /// SUBSCRIBE_UDPATE, the stray backtick draft-15 renders before
    /// PROTOCOL_VIOLATION, and draft-11's missing full stop. Every one of those
    /// is load-bearing — the gate compares against the rendering, so a sentence
    /// tidied up is a sentence no draft has.
    pub sentence: &'static str,
    /// What these drafts call the session error code they answer the rule with,
    /// where the sentence names one.
    ///
    /// The name and not the number. The number is
    /// `EndpointError::session_error_code`'s answer and travels beside the rule
    /// already; what a reader cannot get from the number is that draft-07 calls
    /// 0x4 Duplicate Track Alias while draft-14 calls 0x5
    /// DUPLICATE_TRACK_ALIAS.
    pub code_name: Option<&'static str>,
}

impl RuleCitation {
    /// Whether this citation is claimed for `draft`.
    #[must_use]
    pub fn covers(&self, draft: u8) -> bool {
        self.drafts.0 <= draft && draft <= self.drafts.1
    }
}

// The sentences, one constant per wording. A wording shared by several
// runs -- or by two rules, which is what the Request ID sentence is -- is
// named here once and pointed at from each row that carries it. That is the
// claim `a_wording_shared_across_runs_is_written_once` holds.
//
// Transcribed from the renderings and not tidied. The cross-references the
// drafts put inside these sentences are part of them, draft-14's
// SUBSCRIBE_UDPATE is the drafts' typo, the backtick before draft-15's
// PROTOCOL_VIOLATION is in the rendering, and draft-11's forwarding
// preference sentence really does end without a full stop. `check-drafts.py`
// rule 8 compares each of these against the rendering it came from, so a
// correction of the drafts' spelling is a red gate.
const EXTENSION_HEADERS_ON_STATUS: &str = "If an endpoint receives extension headers on Objects \
                                           with status that is not Normal, it MUST close the \
                                           session with a PROTOCOL_VIOLATION.";
const PROPERTIES_ON_STATUS: &str = "If an endpoint receives properties on an Object with status \
                                    that is not Normal, it MUST close the session with a \
                                    PROTOCOL_VIOLATION.";
const BIDI_OPENER_16: &str = "Bidirectional streams MUST NOT begin with any other message type \
                              unless negotiated. If they do, the peer MUST close the Session with \
                              a Protocol Violation.";
const BIDI_OPENER_17: &str = "Bidirectional streams MUST NOT begin with any other message type \
                              unless negotiated. If they do, the peer MUST close the Session with \
                              a PROTOCOL_VIOLATION.";
const FIRST_RESPONSE: &str = "If the subscriber receives any message other than a REQUEST_OK or a \
                              REQUEST_ERROR as the first message on the response half of the \
                              stream, then it MUST close the session with a PROTOCOL_VIOLATION.";
const GOAWAY_AT_SERVER_07: &str =
    "The server MUST terminate the session with a Protocol Violation \
                                   (Section 3.5) if it receives a GOAWAY message.";
const GOAWAY_URI_TERMINATE: &str = "If a server receives a GOAWAY with a non-zero New Session URI \
                                    Length it MUST terminate the session with a Protocol \
                                    Violation.";
const GOAWAY_URI_TERMINATE_14: &str = "If a server receives a GOAWAY with a non-zero New Session \
                                       URI Length it MUST terminate the session with a \
                                       PROTOCOL_VIOLATION.";
const GOAWAY_URI_CLOSE: &str = "If a server receives a GOAWAY with a non-zero New Session URI \
                                Length it MUST close the session with a PROTOCOL_VIOLATION.";
const REPEATED_GOAWAY_07: &str = "The client MUST terminate the session with a Protocol Violation \
                                  (Section 3.5) if it receives multiple GOAWAY messages.";
const REPEATED_GOAWAY_08: &str = "The endpoint MUST terminate the session with a Protocol \
                                  Violation (Section 3.5) if it receives multiple GOAWAY messages.";
const REPEATED_GOAWAY_10: &str = "The endpoint MUST terminate the session with a Protocol \
                                  Violation (Section 3.4) if it receives multiple GOAWAY messages.";
const REPEATED_GOAWAY_14: &str = "The endpoint MUST terminate the session with a \
                                  PROTOCOL_VIOLATION (Section 3.4) if it receives multiple GOAWAY \
                                  messages.";
const REPEATED_GOAWAY_16: &str = "The endpoint MUST close the session with a PROTOCOL_VIOLATION \
                                  (Section 3.4) if it receives multiple GOAWAY messages.";
const REPEATED_GOAWAY_17: &str = "The endpoint MUST close the session with a PROTOCOL_VIOLATION \
                                  (Section 3.5) if it receives multiple GOAWAY messages.";
const REPEATED_GOAWAY_18: &str = "The endpoint MUST close the session with a PROTOCOL_VIOLATION \
                                  (Section 3.5) if it receives more than one GOAWAY on the control \
                                  stream or on a single request stream.";
const REPEATED_GOAWAY_21: &str = "The endpoint MUST close the session with a PROTOCOL_VIOLATION \
                                  (Section 12.2) if it receives more than one GOAWAY on the \
                                  control stream or on a single request stream.";
const REDIRECT_URI_AT_SERVER: &str = "If a server receives a Redirect with a non-zero Connect URI \
                                      Length it MUST close the session with a PROTOCOL_VIOLATION.";
const REDIRECT_TRACK_NAME: &str = "an endpoint that receives a non-empty Track Name in a Redirect \
                                   for a namespace-scoped request MUST close the session with a \
                                   PROTOCOL_VIOLATION.";
const REQUEST_ID_11: &str = "If an endpoint receives a Request ID that is not valid for the peer, \
                             or a new request with a Request ID that is not expected, it MUST \
                             close the session with Invalid Request ID.";
const REQUEST_ID_14: &str = "If an endpoint receives a Request ID that is not valid for the peer, \
                             or a new request with a Request ID that is not expected, it MUST \
                             close the session with INVALID_REQUEST_ID.";
const REQUEST_ID_15: &str = "If an endpoint receives a Request ID that is not valid for the peer, \
                             or a new request with a Request ID that is not the next in sequence \
                             or exceeds the received MAX_REQUEST_ID, it MUST close the session \
                             with INVALID_REQUEST_ID.";
const REQUEST_ID_17: &str = "If an endpoint receives a Request ID where the least significant bit \
                             is incorrect for the sender, or a duplicate Request ID, it MUST close \
                             the session with INVALID_REQUEST_ID.";
const SUBSCRIBE_ID_UNIQUE: &str = "Subscribe ID is a variable length integer that MUST be unique \
                                   and monotonically increasing within a session and MUST be less \
                                   than the session's Maximum Subscribe ID.";
const CEILING_07: &str = "If a Subscribe ID equal or larger than this is received in any message, \
                          including SUBSCRIBE, the publisher MUST close the session with an error \
                          of 'Too Many Subscribes'.";
const CEILING_08: &str = "If a Subscribe ID Section 7.4 equal or larger than this is received by \
                          the publisher that sent the MAX_SUBSCRIBE_ID, the publisher MUST close \
                          the session with an error of 'Too Many Subscribes'.";
const CEILING_10: &str = "If a Subscribe ID Section 8.6 equal or larger than this is received by \
                          the publisher that sent the MAX_SUBSCRIBE_ID, the publisher MUST close \
                          the session with an error of 'Too Many Subscribes'.";
const CEILING_11: &str = "If a Request ID equal or larger than this is received by the endpoint \
                          that sent the MAX_REQUEST_ID in any request message (ANNOUNCE, FETCH, \
                          SUBSCRIBE, SUBSCRIBE_ANNOUNCES or TRACK_STATUS_REQUEST), the endpoint \
                          MUST close the session with an error of 'Too Many Requests'.";
const CEILING_12: &str =
    "If a Request ID equal to or larger than this is received by the endpoint \
                          that sent the MAX_REQUEST_ID in any request message (ANNOUNCE, FETCH, \
                          SUBSCRIBE, SUBSCRIBE_ANNOUNCES or TRACK_STATUS_REQUEST), the endpoint \
                          MUST close the session with an error of 'Too Many Requests'.";
const CEILING_13: &str = "If a Request ID equal or larger than this is received by the endpoint \
                          that sent the MAX_REQUEST_ID in any request message (ANNOUNCE, FETCH, \
                          SUBSCRIBE, SUBSCRIBE_NAMESPACE or TRACK_STATUS), the endpoint MUST close \
                          the session with an error of 'Too Many Requests'.";
const CEILING_14: &str =
    "If a Request ID equal to or larger than this is received by the endpoint \
                          that sent the MAX_REQUEST_ID in any request message (PUBLISH_NAMESPACE, \
                          FETCH, SUBSCRIBE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_UDPATE or \
                          TRACK_STATUS), the endpoint MUST close the session with an error of \
                          TOO_MANY_REQUESTS.";
const CEILING_16: &str =
    "If a Request ID equal to or larger than this is received by the endpoint \
                          that sent the MAX_REQUEST_ID in any request message (PUBLISH_NAMESPACE, \
                          FETCH, SUBSCRIBE, SUBSCRIBE_NAMESPACE, REQUEST_UPDATE or TRACK_STATUS), \
                          the endpoint MUST close the session with an error of TOO_MANY_REQUESTS.";
const MAX_ID_07: &str =
    "The Maximum Subscribe Id MUST only increase within a session, and receipt \
                         of a MAX_SUBSCRIBE_ID message with an equal or smaller Subscribe ID value \
                         is a 'Protocol Violation'.";
const MAX_ID_11: &str = "The Maximum Request ID MUST only increase within a session, and receipt \
                         of a MAX_REQUEST_ID message with an equal or smaller Request ID value is \
                         a 'Protocol Violation'.";
const MAX_ID_14: &str = "The Maximum Request ID MUST only increase within a session, and receipt \
                         of a MAX_REQUEST_ID message with an equal or smaller Request ID value is \
                         a PROTOCOL_VIOLATION.";
const MAX_ID_16: &str = "The Maximum Request ID MUST only increase within a session. If an \
                         endpoint receives MAX_REQUEST_ID message with an equal or smaller Request \
                         ID it MUST close the session with a PROTOCOL_VIOLATION.";
const ALIAS_07: &str = "If the Track Alias is already being used for a different track, the \
                        publisher MUST close the session with a Duplicate Track Alias error \
                        (Section 3.5).";
const ALIAS_10: &str = "If the Track Alias is already being used for a different track, the \
                        publisher MUST close the session with a Duplicate Track Alias error \
                        (Section 3.4).";
const ALIAS_12: &str = "The same Track Alias MUST NOT be used to refer to two different Tracks \
                        simultaneously. If a subscriber receives a SUBSCRIBE_OK that uses the same \
                        Track Alias as a different track with an active subscription, it MUST \
                        close the session with error 'Duplicate Track Alias'.";
const ALIAS_14: &str = "The same Track Alias MUST NOT be used to refer to two different Tracks \
                        simultaneously. If a subscriber receives a SUBSCRIBE_OK that uses the same \
                        Track Alias as a different track with an active subscription, it MUST \
                        close the session with error DUPLICATE_TRACK_ALIAS.";
const ALIAS_15: &str = "The same Track Alias MUST NOT be used to refer to two different Tracks \
                        simultaneously. If a subscriber receives a SUBSCRIBE_OK that uses the same \
                        Track Alias as a different track with an Established subscription, it MUST \
                        close the session with error DUPLICATE_TRACK_ALIAS.";
const ALIAS_17: &str = "The same Track Alias MUST NOT be used by a publisher to refer to two \
                        different Tracks simultaneously in the same session. If a subscriber \
                        receives a SUBSCRIBE_OK that uses the same Track Alias as a different \
                        track with an Established subscription, it MUST close the session with \
                        error DUPLICATE_TRACK_ALIAS.";
const ALIAS_18: &str = "The same Track Alias MUST NOT be used by a publisher to refer to two \
                        different Tracks simultaneously in the same session. If a subscriber \
                        receives a PUBLISH or SUBSCRIBE_OK that uses the same Track Alias as a \
                        different Track with an Established subscription, it MUST close the \
                        session with error DUPLICATE_TRACK_ALIAS.";
const MIXED_PREFERENCE_07: &str =
    "Every Track has a single 'Object Forwarding Preference' and the \
                                   Original Publisher MUST NOT mix different forwarding \
                                   preferences within a single track. If a subscriber receives \
                                   different forwarding preferences for a track, it SHOULD close \
                                   the session with an error of 'Protocol Violation'.";
const MIXED_PREFERENCE_11: &str =
    "Every Track has a single 'Object Forwarding Preference' and the \
                                   Original Publisher MUST NOT mix different forwarding \
                                   preferences within a single track. If a subscriber receives \
                                   Objects via both Subgroup streams and Datagrams in response to \
                                   a SUBSCRIBE, it SHOULD close the session with an error of \
                                   'Protocol Violation'";
const END_OF_TRACK_08: &str = "An object with this status that has a Group ID less than any other \
                               Group ID, or an Object ID less than or equal to the largest in the \
                               group, is a protocol error, and the receiver MUST terminate the \
                               session.";
const END_OF_TRACK_11: &str = "An object with this status that has a Group ID less than any other \
                               GroupID, or an ObjectID less than or equal to the largest in the \
                               specified group, is a protocol error, and the receiver MUST \
                               terminate the session.";
const UPDATE_WRONG_12: &str = "A publisher MUST terminate the session with a 'Protocol Violation' \
                               if the SUBSCRIBE_UPDATE violates these rules or if the subscriber \
                               specifies a request ID that has not existed within the Session.";
const UPDATE_WRONG_14: &str =
    "A publisher MUST terminate the session with a PROTOCOL_VIOLATION if \
                               the SUBSCRIBE_UPDATE violates these rules or if the subscriber \
                               specifies a request ID that has not existed within the Session.";
const UPDATE_WRONG_15: &str = "This MUST match an existing Request ID. The publisher MUST close \
                               the session with ` PROTOCOL_VIOLATION if the subscriber specifies \
                               an invalid Subscription Request ID.";
const UPDATE_WRONG_16: &str =
    "This MUST match the Request ID of an existing request. The receiver \
                               MUST close the session with PROTOCOL_VIOLATION if the sender \
                               specifies an invalid Existing Request ID, or if the parameters \
                               included in the REQUEST_UPDATE are invalid for the type of request \
                               being modified.";
const UPDATE_WRONG_19: &str = "An endpoint that receives a REQUEST_UPDATE other than in the two \
                               cases above MUST close the session with a PROTOCOL_VIOLATION.";
const TOO_MANY_UPDATES: &str = "If an endpoint receives a REQUEST_UPDATE on a stream that already \
                                has MAX_REQUEST_UPDATES outstanding REQUEST_UPDATEs, it MUST close \
                                the session with TOO_MANY_REQUEST_UPDATES.";
const TRACK_PROPERTIES: &str = "Track Properties are populated in TRACK_STATUS_OK; they are empty \
                                in PUBLISH_OK, REQUEST_UPDATE_OK, SUBSCRIBE_NAMESPACE_OK and \
                                PUBLISH_NAMESPACE_OK. If an endpoint receives Track Properties in \
                                one of these messages it MUST close the session with a \
                                PROTOCOL_VIOLATION.";
const STATE_NOTIFY: &str = "PUBLISH_STATE_NOTIFY applies only to subscriptions, and is sent only \
                            by the publisher. An endpoint that receives a PUBLISH_STATE_NOTIFY for \
                            any other request type, or from the subscriber, MUST close the session \
                            with a PROTOCOL_VIOLATION.";
const SUBSCRIBE_AFTER_CANCEL: &str =
    "If a publisher receives new subscriptions for that namespace \
                                      after receiving an ANNOUNCE_CANCEL, it SHOULD close the \
                                      session as a 'Protocol Violation'.";

impl AboveCodecRule {
    /// Every draft run this rule has a checked citation for, oldest first.
    ///
    /// Exhaustive with no wildcard arm, for the reason the enum is not
    /// `#[non_exhaustive]`: a rule added to this file arrives here as an
    /// `E0004` and a decision about which drafts state it, rather than as an
    /// empty slice nobody chose.
    ///
    /// An empty slice is one of those decisions and not an oversight. Nine
    /// rules answer with one, in two groups.
    ///
    /// **Eight are rules no draft in range answers with a session close.** The
    /// datagram payload rule, a response naming another request, a setup
    /// parameter whose value is not of its type's kind, an Object past the one
    /// the track ended at, a fill stream nobody asked for, an UNSUBSCRIBE or
    /// REQUEST_UPDATE naming a TRACK_STATUS, a message naming a request the
    /// session has no record of, and a namespace prefix overlapping one the
    /// peer already has. Every one is a real rule this endpoint enforces, and
    /// `session_error_code` already answers `None` for all of them, so nothing
    /// downstream could publish one whatever this table said. They are written
    /// out so that a draft attaching a consequence to one arrives here as a
    /// build failure.
    ///
    /// **The ninth is [`Self::MessageOnTheWrongStream`].** It is enforced on
    /// drafts 16 through 20 and no draft in that range states it, so it is
    /// named, enforced and attributed to the peer while publishing nothing:
    /// there is no sentence to publish and `close` is `None` on every draft.
    /// The variant's own doc carries the reading across all texts that
    /// establishes it, and the one variant that really is covered by a draft
    /// sentence is filed under the rule whose sentence covers it. A draft that
    /// attaches a consequence to this one arrives as a citation rather than as
    /// a rediscovery.
    #[must_use]
    pub fn citations(self) -> &'static [RuleCitation] {
        match self {
            Self::PropertiesOnNonNormalStatus => &[
                RuleCitation {
                    drafts: (15, 16),
                    section: "10.2.1.2",
                    sentence: EXTENSION_HEADERS_ON_STATUS,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "10.2.1.2",
                    sentence: PROPERTIES_ON_STATUS,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "11.2.1.2",
                    sentence: PROPERTIES_ON_STATUS,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "11.1.3",
                    sentence: PROPERTIES_ON_STATUS,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::BidiStreamOpener => &[
                RuleCitation {
                    drafts: (16, 16),
                    section: "3.3",
                    sentence: BIDI_OPENER_16,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (17, 20),
                    section: "3.3",
                    sentence: BIDI_OPENER_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "6.3",
                    sentence: BIDI_OPENER_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::ResponseBeforeItsFirstResponse => &[
                RuleCitation {
                    drafts: (18, 19),
                    section: "10.18",
                    sentence: FIRST_RESPONSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (20, 20),
                    section: "10.19",
                    sentence: FIRST_RESPONSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.15",
                    sentence: FIRST_RESPONSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::GoAwayAtServer => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.3",
                    sentence: GOAWAY_AT_SERVER_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.3",
                    sentence: GOAWAY_URI_TERMINATE,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.3",
                    sentence: GOAWAY_URI_TERMINATE,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (11, 13),
                    section: "8.4",
                    sentence: GOAWAY_URI_TERMINATE,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 15),
                    section: "9.4",
                    sentence: GOAWAY_URI_TERMINATE_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.4",
                    sentence: GOAWAY_URI_CLOSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.5",
                    sentence: GOAWAY_URI_CLOSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.4",
                    sentence: GOAWAY_URI_CLOSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.2",
                    sentence: GOAWAY_URI_CLOSE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::RepeatedGoAway => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.3",
                    sentence: REPEATED_GOAWAY_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.3",
                    sentence: REPEATED_GOAWAY_08,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.3",
                    sentence: REPEATED_GOAWAY_10,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (11, 13),
                    section: "8.4",
                    sentence: REPEATED_GOAWAY_10,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 15),
                    section: "9.4",
                    sentence: REPEATED_GOAWAY_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.4",
                    sentence: REPEATED_GOAWAY_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.5",
                    sentence: REPEATED_GOAWAY_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.4",
                    sentence: REPEATED_GOAWAY_18,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.2",
                    sentence: REPEATED_GOAWAY_21,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::RedirectUriAtServer => &[
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.6.1",
                    sentence: REDIRECT_URI_AT_SERVER,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.4.1",
                    sentence: REDIRECT_URI_AT_SERVER,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::RedirectTrackNameOnNamespaceRequest => &[
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.6.1",
                    sentence: REDIRECT_TRACK_NAME,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.4.1",
                    sentence: REDIRECT_TRACK_NAME,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::RequestIdParity => &[
                RuleCitation {
                    drafts: (11, 13),
                    section: "8.1",
                    sentence: REQUEST_ID_11,
                    code_name: Some("Invalid Request ID"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "9.1",
                    sentence: REQUEST_ID_14,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (15, 16),
                    section: "9.1",
                    sentence: REQUEST_ID_15,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.1",
                    sentence: REQUEST_ID_17,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.1",
                    sentence: REQUEST_ID_17,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "6.4.2.1",
                    sentence: REQUEST_ID_17,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
            ],
            Self::RequestIdOutOfSequence => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.4",
                    sentence: SUBSCRIBE_ID_UNIQUE,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.4",
                    sentence: SUBSCRIBE_ID_UNIQUE,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.6",
                    sentence: SUBSCRIBE_ID_UNIQUE,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (11, 13),
                    section: "8.1",
                    sentence: REQUEST_ID_11,
                    code_name: Some("Invalid Request ID"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "9.1",
                    sentence: REQUEST_ID_14,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (15, 16),
                    section: "9.1",
                    sentence: REQUEST_ID_15,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.1",
                    sentence: REQUEST_ID_17,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.1",
                    sentence: REQUEST_ID_17,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "6.4.2.1",
                    sentence: REQUEST_ID_17,
                    code_name: Some("INVALID_REQUEST_ID"),
                },
            ],
            Self::RequestIdCeiling => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.20",
                    sentence: CEILING_07,
                    code_name: Some("Too Many Subscribes"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.20",
                    sentence: CEILING_08,
                    code_name: Some("Too Many Subscribes"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.4",
                    sentence: CEILING_10,
                    code_name: Some("Too Many Subscribes"),
                },
                RuleCitation {
                    drafts: (11, 11),
                    section: "8.5",
                    sentence: CEILING_11,
                    code_name: Some("Too Many Requests"),
                },
                RuleCitation {
                    drafts: (12, 12),
                    section: "8.5",
                    sentence: CEILING_12,
                    code_name: Some("Too Many Requests"),
                },
                RuleCitation {
                    drafts: (13, 13),
                    section: "8.5",
                    sentence: CEILING_13,
                    code_name: Some("Too Many Requests"),
                },
                RuleCitation {
                    drafts: (14, 15),
                    section: "9.5",
                    sentence: CEILING_14,
                    code_name: Some("TOO_MANY_REQUESTS"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.5",
                    sentence: CEILING_16,
                    code_name: Some("TOO_MANY_REQUESTS"),
                },
            ],
            Self::MaxRequestIdDecreased => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.20",
                    sentence: MAX_ID_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.20",
                    sentence: MAX_ID_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.4",
                    sentence: MAX_ID_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (11, 13),
                    section: "8.5",
                    sentence: MAX_ID_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 15),
                    section: "9.5",
                    sentence: MAX_ID_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.5",
                    sentence: MAX_ID_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::DuplicateTrackAlias => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.4",
                    sentence: ALIAS_07,
                    code_name: Some("Duplicate Track Alias"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.4",
                    sentence: ALIAS_07,
                    code_name: Some("Duplicate Track Alias"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.6",
                    sentence: ALIAS_10,
                    code_name: Some("Duplicate Track Alias"),
                },
                RuleCitation {
                    drafts: (11, 11),
                    section: "8.7",
                    sentence: ALIAS_10,
                    code_name: Some("Duplicate Track Alias"),
                },
                RuleCitation {
                    drafts: (12, 13),
                    section: "8.8",
                    sentence: ALIAS_12,
                    code_name: Some("Duplicate Track Alias"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "9.8",
                    sentence: ALIAS_14,
                    code_name: Some("DUPLICATE_TRACK_ALIAS"),
                },
                RuleCitation {
                    drafts: (15, 16),
                    section: "9.10",
                    sentence: ALIAS_15,
                    code_name: Some("DUPLICATE_TRACK_ALIAS"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.9",
                    sentence: ALIAS_17,
                    code_name: Some("DUPLICATE_TRACK_ALIAS"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "11.1",
                    sentence: ALIAS_18,
                    code_name: Some("DUPLICATE_TRACK_ALIAS"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "3.1.2",
                    sentence: ALIAS_18,
                    code_name: Some("DUPLICATE_TRACK_ALIAS"),
                },
            ],
            Self::MixedForwardingPreference => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "7",
                    sentence: MIXED_PREFERENCE_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "8",
                    sentence: MIXED_PREFERENCE_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "9",
                    sentence: MIXED_PREFERENCE_07,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (11, 11),
                    section: "9",
                    sentence: MIXED_PREFERENCE_11,
                    code_name: Some("Protocol Violation"),
                },
            ],
            Self::EndOfTrackOutOfPlace => &[
                RuleCitation {
                    drafts: (8, 9),
                    section: "8.1.1.1",
                    sentence: END_OF_TRACK_08,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "9.1.1.1",
                    sentence: END_OF_TRACK_08,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (11, 11),
                    section: "9.1.1.1",
                    sentence: END_OF_TRACK_11,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (12, 13),
                    section: "9.2.1.1",
                    sentence: END_OF_TRACK_11,
                    code_name: None,
                },
            ],
            Self::RequestUpdateForTheWrongRequest => &[
                RuleCitation {
                    drafts: (12, 13),
                    section: "8.10",
                    sentence: UPDATE_WRONG_12,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "9.10",
                    sentence: UPDATE_WRONG_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (15, 15),
                    section: "9.11",
                    sentence: UPDATE_WRONG_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.11",
                    sentence: UPDATE_WRONG_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (19, 20),
                    section: "10.9",
                    sentence: UPDATE_WRONG_19,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.5",
                    sentence: UPDATE_WRONG_19,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::TooManyRequestUpdates => &[
                RuleCitation {
                    drafts: (19, 20),
                    section: "10.3.1.7",
                    sentence: TOO_MANY_UPDATES,
                    code_name: Some("TOO_MANY_REQUEST_UPDATES"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.1.7",
                    sentence: TOO_MANY_UPDATES,
                    code_name: Some("TOO_MANY_REQUEST_UPDATES"),
                },
            ],
            Self::TrackPropertiesOnNonTrackStatus => &[
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.5",
                    sentence: TRACK_PROPERTIES,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.3",
                    sentence: TRACK_PROPERTIES,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::StateNotifyOnTheWrongRequest => &[
                RuleCitation {
                    drafts: (20, 20),
                    section: "10.10",
                    sentence: STATE_NOTIFY,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.10",
                    sentence: STATE_NOTIFY,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::SubscribeAfterAnnounceCancel => &[RuleCitation {
                drafts: (7, 7),
                section: "6.11",
                sentence: SUBSCRIBE_AFTER_CANCEL,
                code_name: Some("Protocol Violation"),
            }],
            // The eight with no consequence on any draft, and the one with no
            // sentence on any draft. See this function's own doc for which is
            // which and why they are written out rather than swallowed by a
            // wildcard.
            Self::PayloadOnStatusDatagram
            | Self::MessageOnTheWrongStream
            | Self::ResponseNamesAnotherRequest
            | Self::SetupParameterValue
            | Self::ObjectPastFinalObject
            | Self::UnrequestedFillStream
            | Self::TrackStatusIsNotASubscription
            | Self::MessageNamesAnUnknownRequest
            | Self::NamespacePrefixOverlap => &[],
        }
    }

    /// This rule as `draft` states it, or `None` where that draft does not.
    ///
    /// `None` has two readings and the caller does not need to tell them apart:
    /// the draft may not state the rule at all, or it may state it in words
    /// nobody has yet checked. Both mean the same thing downstream — there is
    /// no sentence to publish, so there is no accusation to make — and that is
    /// the whole of why this returns an `Option` rather than falling back on a
    /// neighbouring draft's wording. A fallback publishes a sentence the
    /// negotiated draft does not contain, which is the defect this table exists
    /// to prevent.
    #[must_use]
    pub fn citation(self, draft: u8) -> Option<&'static RuleCitation> {
        self.citations().iter().find(|c| c.covers(draft))
    }
}

/// A rule a peer broke that the negotiated draft's **decoder** did refuse,
/// named once across the drafts that state it.
///
/// # Why this is a second enum and not more variants of the first
///
/// [`AboveCodecRule`] is defined by what it is *not*: a rule stated about a
/// frame that reads perfectly well, which no decoder could refuse and which the
/// endpoint has to catch by comparing decoded fields against state it has been
/// keeping. Every rule here is the opposite. The frame did not read — a length
/// past its maximum, a discriminator the draft does not assign, a delta that
/// carries a number past the end of the varint space — and `CodecError` is what
/// says so. Folding the two into one enum would put *the decoder refused this*
/// and *the decoder could not have seen this* under one name, which is the
/// distinction [`crate::dispatch::ErrorCause`] exists to keep.
///
/// # Why it lives in this file rather than beside `CodecError`
///
/// Because of what reads it. `scripts/check-drafts.py` rule 8 walks **this
/// file** and holds every [`RuleCitation`] in it against the fourteen rendered
/// drafts: that the sentence is in every draft of the run, that it sits in the
/// section the row names, and that the code name is one the sentence itself
/// uses. A citation the gate cannot see is not a checked citation, and the
/// standard for adding one is deliberately steep: a sentence held against the
/// draft that will be cited, on each draft in the range claimed rather than on
/// a sample of it.
///
/// `moqtap-codec` is the other candidate and is the wrong one twice over: it is
/// where the *errors* live rather than where the drafts' answers to them do,
/// and nothing in `just drafts` reads a table there either.
///
/// # Where the quoted sentences are, and are not
///
/// In the constants below, one per wording, which is the only place the gate
/// looks. The variant docs here describe rather than quote, and use backticks
/// where they name a fragment of a draft's text. That is a departure from
/// [`AboveCodecRule`] above, and the reason is this group's ranges: nearly
/// every rule here says something different on the oldest drafts in its range
/// than on the newest, so a doc that quoted one wording beside a sentence
/// naming ten drafts would be claiming it for all ten. The checker has a rule
/// for exactly that and it would be right to fire.
///
/// # What is in this table
///
/// These are the rules a consumer's catalogue names as a list and does not
/// carry itself: a `rule_for` matching `CodecError` exhaustively has no
/// wildcard arm to file them under. Every one of them is a relay breaking a
/// rule the negotiated draft answers with a session close, and without a
/// citation here there is nothing to publish it as.
///
/// # Why the two Type-value rules are two
///
/// [`CodecRule::InvalidStreamTypeValue`] and
/// [`CodecRule::InvalidDatagramTypeValue`] are one condition as a reader thinks
/// of it — a Type inside its form holding a combination the draft rules out —
/// and two rules here, because drafts 16 through 21 state them as **two**
/// sentences in two sections, one about a datagram's Type and one about a
/// subgroup stream header's.
///
/// A [`RuleCitation`] is one sentence per draft: [`Self::citation`] takes the
/// first run that covers a draft and
/// `every_run_is_ordered_contiguous_and_in_range` forbids two runs claiming
/// one. So a single rule spanning both sentences could publish only one of
/// them, and would be right on half the frames it published and wrong on the
/// other half with nothing in the row to say which.
///
/// Splitting the rule here is only half of it, and the half that does not work
/// alone: the decoder has to hand over a value that says which sentence was
/// broken. `CodecError::InvalidStreamTypeValue` and
/// `CodecError::InvalidDatagramTypeValue` are that value. Deriving the
/// namespace from the raw number instead would be this build's reading rather
/// than the decoder's, because the two Type spaces overlap — which is the
/// reasoning `CodecError::InvalidField` already gets, arrived at from a
/// different direction.
///
/// # Two drafts where a close exists and no citation does
///
/// This table is not the inverse of `codec_session_error_code`, and two rows
/// are where the two come apart. Draft-20 answers both
/// [`Self::InvalidFilterType`] and [`Self::InvalidFetchType`] with
/// PROTOCOL_VIOLATION, and draft-20 states neither rule: it replaced the
/// subscription filter with a LOCATION_FILTER parameter whose optional fields
/// are found by length and carry no type discriminator, and it deleted the
/// Fetch Type field, both variant structures and the registry together.
///
/// Neither arm is reachable there. `moqtap-codec`'s draft-20 message reader
/// raises neither error and has nothing to raise it from, so the two closes are
/// inert rather than wrong, and both are kept for the reason draft-20's own
/// connection already gives: `CodecError` is shared across drafts and
/// is not `#[non_exhaustive]`, so every variant has to be answered on every
/// draft.
///
/// What the missing citation buys is that the inertness stops being
/// load-bearing. If a draft-20 decoder ever did raise one, a consumer would
/// find no sentence to publish and would name nobody — which is the right
/// answer for a rule draft-20 does not state, and it does not depend on an
/// unreachable arm staying unreachable.
///
/// Deliberately **not** `#[non_exhaustive]`, for the reason [`AboveCodecRule`]
/// is not: a consumer deciding what it will name a relay for should find out
/// about a new rule by failing to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecRule {
    // ── The four maxima ────────────────────────────────────────
    /// A Full Track Name longer than the drafts' maximum.
    ///
    /// Drafts 11 through 20, Section 2.4.1 throughout — the section never moves
    /// and the sentence changes three times, which is the opposite of the usual
    /// shape and why this rule has four runs where most have one wording per
    /// section.
    ///
    /// The maximum and its consequence are quoted together because the
    /// consequence alone is not evidence: through draft-15 it refers back to
    /// `exceeding this length`, and the length is in the sentence before it.
    ///
    /// One nuance the citation carries and this build's error message does not.
    /// On drafts 11 through 15 the sentence bounds the **Full Track Name**
    /// alone; draft-16 widens it to a Track Namespace or a Full Track Name.
    /// `CodecError::TrackNameTooLong` renders as *track namespace or full track
    /// name exceeds …* on all ten, which is the drafts' own scope only from 16
    /// on. A namespace over the maximum beside a short name is covered by no
    /// sentence on the older five, and their rows quote what those drafts do
    /// say rather than what this build measures.
    ///
    /// Drafts 07 through 10 state no maximum at all.
    TrackNameTooLong,
    /// A Reason Phrase longer than the drafts' maximum.
    ///
    /// Drafts 11 through 20. **The sentence has no full stop in any of them**:
    /// it runs straight into the next definition item, so every quotation here
    /// ends at the code name. Supplying the full stop a transcriber would want
    /// is exactly the truncation `check-drafts.py` rule 7 exists to catch, and
    /// it would file the row under a sentence no draft has.
    ///
    /// Four runs. The section moves twice — draft-14 inserts Section 1.3 Stream
    /// Management Terms and draft-17 inserts Section 1.4.1 Variable-Length
    /// Integers, pushing this down each time — and the wording changes twice,
    /// once for the code rename and once where the maximum stops being a
    /// `maximum length of 1024 bytes` and becomes a `maximum value of 1024
    /// bytes`.
    ReasonPhraseTooLong,
    /// A GOAWAY New Session URI longer than the drafts' maximum.
    ///
    /// Drafts 11 through 20, in the GOAWAY message's own section, which moves
    /// three times across the range.
    ///
    /// Drafts 11 through 16 spell it `The maxmimum length of the New Session
    /// URI is 8,192 bytes.` The typo is the drafts' and is reproduced in the
    /// constant, because the gate compares against the rendering: a sentence
    /// tidied up is a sentence no draft has. Draft-17 fixes it, which is one of
    /// the two wording breaks in this rule's four runs.
    GoAwayUriTooLong,
    /// A Key-Value-Pair whose value is longer than the drafts' maximum.
    ///
    /// Drafts 11 through 20, in the Key-Value-Pair structure's own section —
    /// 1.3.2 through draft-13, 1.4.2 on 14 through 16, 1.4.3 from draft-17,
    /// which is the same pair of insertions that moves the Reason Phrase rule.
    ///
    /// The sub-variant and not the arm. `CodecError::Kvp` also carries
    /// `MissingLength`, `UnexpectedEnd` and `VarInt`, which report how the bytes
    /// ran out rather than a rule an endpoint states, and all the drafts
    /// answer all three with no close. Only `ValueTooLong` reaches this rule,
    /// which is why the probe that consumes it matches the sub-variant.
    KvpValueTooLong,

    // ── The key-value pair rules ───────────────────────────────
    /// A key-value pair whose value is not the serialization its own Type
    /// defines.
    ///
    /// Drafts 11 through 20, and the one rule in this table whose code is
    /// KEY_VALUE_FORMATTING_ERROR on every draft that states it rather than
    /// PROTOCOL_VIOLATION.
    ///
    /// Four runs for three reasons at once. Drafts 11 through 13 spell the code
    /// in prose inside quotation marks and drafts 14 and later in capitals;
    /// draft-16 changes the verb from terminate to close; and the section moves
    /// twice under both. Only the first of those three is visible in the code
    /// name a row publishes, which is the argument for publishing the sentence
    /// beside it.
    KeyValueFormatting,
    /// A control message carrying a Message Parameter whose type its draft does
    /// not define.
    ///
    /// Drafts 16 through 20, and **the rule whose answer reverses** rather than
    /// arrives. Drafts 07 through 10 say a receiver ignores an unrecognized
    /// parameter, and drafts 11 through 15 add `Receivers MUST allow duplicates
    /// of unknown parameters`, which presumes unknown parameters arrive and are
    /// carried. Raising this on any of those nine would close a session over an
    /// extension those drafts leave room for, so the decoder does not, and the
    /// run starts where the sentence does.
    ///
    /// Draft-16 is a run of its own for one word: it has the parameter
    /// negotiated via `Setup Parameters` where drafts 17 and later say `Setup
    /// Options`, which is the rename draft-17 made. Publishing the later
    /// wording for draft-16 would be quoting a sentence draft-16 has not got —
    /// the exact defect this table was built to remove, one draft wide.
    ///
    /// One namespace only. Every draft in range says a receiver ignores an
    /// unrecognised Setup Option, so an unknown type in a SETUP is carried and
    /// this is never raised for one.
    UnknownMessageParameter,
    /// A Message Parameter appearing in a message type its own definition does
    /// not name.
    ///
    /// Drafts 17 through 20. The other reversal, and a wider one: drafts 07
    /// through 16 end the same sentence `it MUST be ignored`.
    ///
    /// The sentence says close the **connection**, not close the session, on
    /// all four drafts. Reproduced as it stands. The drafts use the two words
    /// interchangeably here, and correcting one to the other would be this file
    /// speaking inside a draft's own quotation marks — which is a defect this
    /// table has already been found holding five times.
    ParameterOutOfScope,
    /// A parameter whose value is not the shape its own type implies.
    ///
    /// **Drafts 07 through 10 alone**, which makes it the only rule in either
    /// table that exists on the oldest four drafts and nowhere else. The
    /// sentence goes with the Parameter framing it describes, and drafts 11 and
    /// later replaced that framing with Key-Value-Pairs — where the
    /// neighbouring rule is [`Self::KeyValueFormatting`], under a different
    /// code.
    ///
    /// It is also the only rule here answered with neither PROTOCOL_VIOLATION
    /// nor KEY_VALUE_FORMATTING_ERROR: each of those four drafts assigns
    /// Parameter Length Mismatch a number of its own in the session termination
    /// registry, and the sentence names it.
    ParameterLengthMismatch,

    // ── The discriminators a reader cannot get past ────────────
    /// A subscription filter naming a Filter Type the draft does not assign.
    ///
    /// Drafts 14 through 19, and two runs because **draft-14's sentence carries
    /// the draft's own missing word** — it has an endpoint `MUST be close the
    /// session`. Reproduced rather than corrected, for the reason
    /// [`RuleCitation::sentence`] gives.
    ///
    /// Drafts 07 through 13 state the rule and no consequence: a filter type
    /// other than the assigned ones `MUST be treated as error`, which names no
    /// code and no close. So the same value in the same place is a refused
    /// message on the first seven drafts and a dead session on the next six,
    /// and only the per-draft close table can tell them apart.
    ///
    /// Draft-20 states it nowhere. See this enum's own doc for why a close
    /// remains in draft-20's table and why the missing citation is what makes
    /// that safe.
    InvalidFilterType,
    /// A FETCH naming a Fetch Type the draft does not assign.
    ///
    /// The sentence next to the Filter Type one, moving the same way and
    /// carrying the same draft-14 missing word. Drafts 14 through 19; drafts 08
    /// through 13 say a Fetch Type outside the set `MUST be treated as an
    /// error` and state no consequence, and draft-07 has a FETCH with no Fetch
    /// Type field in it.
    ///
    /// Draft-20 deleted the field, both variant structures and the registry
    /// together, so it has nothing to state.
    ///
    /// Four runs for two wordings: the section moves three times across the
    /// range while the sentence stands still after draft-14.
    InvalidFetchType,
    /// A subscription filter parameter whose value is not a filter.
    ///
    /// Drafts 15 through 20, and the one rule here whose **code changes** within
    /// its own range rather than only being spelled differently. Drafts 15 and
    /// 16 state it of this parameter directly and answer PROTOCOL_VIOLATION;
    /// drafts 17 through 20 drop that sentence and leave the general key-value
    /// rule, which answers KEY_VALUE_FORMATTING_ERROR. A filter three bytes long
    /// inside a four-byte parameter ends a draft-16 session with one code and a
    /// draft-17 session with the other.
    ///
    /// The later run cites the same sentence [`Self::KeyValueFormatting`] does,
    /// which is what a shared constant is for. The reading that a malformed
    /// filter is a Value that does not match the serialization its Type defines
    /// is this build's, and it is the same reading `codec_session_error_code`
    /// already makes on those four drafts. Stated here rather than left to be
    /// noticed: the sentence is the drafts', and that this malformation is its
    /// case is a reading of it.
    ///
    /// A Filter Type outside the assigned set is not this rule. That is
    /// [`Self::InvalidFilterType`], whose own section names its own code.
    SubscriptionFilterMalformed,
    /// An AbsoluteRange filter whose End Group Delta carries the last Group ID
    /// past the end of the varint space.
    ///
    /// Drafts 18 through 20. Draft-17 introduced the delta and states the
    /// arithmetic with no consequence for overflowing it — that draft contains
    /// exactly one mention of the bound in the whole document and it is the
    /// Delta Type rule, not this one — so there an overflowing filter is a
    /// decode failure and nothing more.
    ///
    /// The draft-18 and draft-19 run keeps the clause before the consequence,
    /// because *the resulting Group ID* has no antecedent without it. The two
    /// are contiguous inside one paragraph, so it is a quotation and not a
    /// splice. Draft-20 rewrote the pair as one self-contained sentence naming
    /// its own operands, which is the second run.
    FilterEndGroupOverflow,

    // ── The data plane ─────────────────────────────────────────
    /// A delta-encoded Object ID that would exceed the varint space once the
    /// delta is added to the previous Object ID on the same stream.
    ///
    /// Drafts 18 through 20 in Section 11.4.2 and draft-21 in Section 11.3.1,
    /// two runs: the wording does not change and the section number does.
    ///
    /// Drafts 14 through 17 carry the identical arithmetic in Section 10.4.2
    /// and state no consequence for overflowing it — all four of them, not
    /// draft-17 alone — and drafts 07 through 13 have no Object ID Delta to
    /// overflow.
    ///
    /// The three sentences are quoted unbroken, and no ellipsis may stand
    /// between the first and the third: eliding there splices across the
    /// sentence about the first Object in the Subgroup stream and makes a
    /// sentence none of the three drafts has.
    ObjectIdOverflow,
    /// A subgroup stream header's Type holding a combination its draft names as
    /// invalid.
    ///
    /// Drafts 16 through 21, four runs: the section moves twice and the wording
    /// changes once, and the two moves do not coincide. Sections 10.4.2 on
    /// drafts 16 and 17, 11.4.2 on 18, 19 and 20, and 11.3.1 on draft-21;
    /// drafts 16 through 19 enumerate the code points after the sentence and
    /// drafts 20 and 21 state the bit pattern alone.
    ///
    /// The sentence is quoted as far as the colon it ends on, because what
    /// follows it is a bulleted list of values rather than more sentence. That
    /// is the whole quotation and not an elision, so no ellipsis stands in for
    /// the list.
    ///
    /// Paired with [`CodecRule::InvalidDatagramTypeValue`], which is the same
    /// rule stated for the other Type space in a different section of the same
    /// drafts. They are two rules here because they are two sentences there,
    /// and because a consumer holding one refusal has to be able to publish the
    /// sentence it actually broke.
    InvalidStreamTypeValue,
    /// A datagram's Type holding a combination its draft names as invalid.
    ///
    /// Drafts 16 through 21, four runs, cut where
    /// [`CodecRule::InvalidStreamTypeValue`]'s are cut and at different
    /// numbers: Sections 10.3.1 on drafts 16 and 17, 11.3.1 on 18, 19 and 20,
    /// and 11.2.1 on draft-21.
    ///
    /// Draft-21 is why the two rules cannot share a run. It splits the section
    /// that held both, so the datagram sentence lands at 11.2.1 and the stream
    /// sentence at 11.3.1 — the one number that had been the datagram's on the
    /// three drafts before it.
    InvalidDatagramTypeValue,
    /// An end-of-Track Object stating an Object ID other than zero.
    ///
    /// **Drafts 08 through 10 alone**, and the one rule in this table whose
    /// sentence names no code: it ends with the receiver having to terminate
    /// the session and nothing more, so [`RuleCitation::code_name`] is `None`
    /// and a row publishes the number without a name for it. The number comes
    /// from `codec_session_error_code`, which answers PROTOCOL_VIOLATION — what
    /// those drafts answer every rule they close over without naming a code.
    /// The name is absent because the draft does not supply it, which is not
    /// the same thing as the draft stating no consequence.
    ///
    /// There is a look-alike sentence in the same subsection of the same three
    /// drafts, about Object Status 0x4 rather than 0x5, and the two differ by
    /// four words in two places: the neighbour has a Group ID *less than* any
    /// other and an Object ID *less than or equal to the largest in the group*,
    /// where this one has a Group ID *less than or equal to* any other and an
    /// Object ID *other than zero*. The neighbour is
    /// [`AboveCodecRule::EndOfTrackOutOfPlace`]'s sentence and is already cited
    /// above; citing it here would have put two rules under one wording and
    /// looked right.
    ///
    /// Draft-07 assigns no 0x5. Drafts 11 and later merge end of Track into
    /// 0x4 and permit either shape, so there is no longer a rule to break.
    EndOfTrackObjectId,
    /// An Object with Object Status 'Object Does Not Exist' carrying extension
    /// headers.
    ///
    /// Drafts 11 through 14, three runs: the section moves twice and draft-14
    /// respells the code. The rule names one status and no others, so
    /// extensions beside End of Group or End of Track are legal on those four
    /// drafts and are not this.
    ///
    /// Drafts 15 and later replaced the narrow form with the general one —
    /// extensions, later properties, permitted only beside Normal — which is a
    /// different rule with a different subject and reaches a consumer as
    /// [`AboveCodecRule::PropertiesOnNonNormalStatus`]. Drafts 07 through 10
    /// state neither form.
    ExtensionsOnNonExistentObject,

    // ── And one that lived for exactly one draft ───────────────
    /// A request message's Required Request ID Delta naming a dependency below
    /// zero.
    ///
    /// **Draft-17 alone.** Draft-18 removed the field and mentions it only in
    /// its change log, so no other draft can state the rule.
    ///
    /// The only rule in this table answered with INVALID_REQUIRED_REQUEST_ID,
    /// and the only sentence in it carrying a character outside ASCII: the
    /// draft writes the comparison with a multiplication sign, and the gate
    /// compares against the rendering rather than against what a transcriber
    /// would have typed.
    InvalidRequiredRequestIdDelta,
}

// The sentences these rules are stated in, one constant per wording, on the
// same terms as the block above: transcribed from the renderings and not
// tidied. Three of them carry something a transcriber would want to correct and
// must not -- drafts 11 through 16 render the GOAWAY URI maximum with
// `maxmimum`, and draft-14 renders both the Filter Type and the Fetch Type
// sentences with `MUST be close the session`. `check-drafts.py` rule 8 compares
// each of these against the rendering it came from, so a correction of the
// drafts' spelling is a red gate.
//
// Two more shapes worth naming before a reader meets them. The Reason Phrase
// sentences end without a full stop, because the rendering runs them into the
// next definition item and a supplied mark is a sentence no draft has. And
// `KVP_FORMATTING_16` is named from one rule and carried by two: the general
// key-value sentence is what drafts 17 through 20 leave a malformed
// subscription filter to, having dropped the filter's own.
const TRACK_NAME_MAX_11: &str = "The maximum total length of a Full Track Name is 4,096 bytes, \
                                 computed as the sum of the lengths of each Track Namespace tuple \
                                 field and the Track Name length field. If an endpoint receives a \
                                 Full Track Name exceeding this length, it MUST close the session \
                                 with a Protocol Violation.";
const TRACK_NAME_MAX_14: &str = "The maximum total length of a Full Track Name is 4,096 bytes, \
                                 computed as the sum of the lengths of each Track Namespace tuple \
                                 field and the Track Name length field. If an endpoint receives a \
                                 Full Track Name exceeding this length, it MUST close the session \
                                 with a PROTOCOL_VIOLATION.";
const TRACK_NAME_MAX_15: &str =
    "The maximum total length of a Full Track Name is 4,096 bytes. The \
                                 length of a Full Track Name is computed as the sum of the Track \
                                 Namespace Field Length fields and the Track Name Length field. If \
                                 an endpoint receives a Full Track Name exceeding this length, it \
                                 MUST close the session with a PROTOCOL_VIOLATION.";
const TRACK_NAME_MAX_16: &str =
    "The maximum total length of a Full Track Name is 4,096 bytes. The \
                                 length of a Full Track Name is computed as the sum of the Track \
                                 Namespace Field Length fields and the Track Name Length field. \
                                 The length of a Track Namespace is the sum of the Track Namespace \
                                 Field Length fields. If an endpoint receives a Track Namespace or \
                                 a Full Track Name exceeding 4,096 bytes, it MUST close the \
                                 session with a PROTOCOL_VIOLATION.";
const REASON_PHRASE_MAX_11: &str = "The reason phrase length has a maximum length of 1024 bytes. \
                                    If an endpoint receives a length exceeding the maximum, it \
                                    MUST close the session with a Protocol Violation";
const REASON_PHRASE_MAX_14: &str = "The reason phrase length has a maximum length of 1024 bytes. \
                                    If an endpoint receives a length exceeding the maximum, it \
                                    MUST close the session with a PROTOCOL_VIOLATION";
const REASON_PHRASE_MAX_15: &str =
    "The reason phrase length has a maximum value of 1024 bytes. If \
                                    an endpoint receives a length exceeding the maximum, it MUST \
                                    close the session with a PROTOCOL_VIOLATION";
const GOAWAY_URI_MAX_11: &str = "The maxmimum length of the New Session URI is 8,192 bytes. If an \
                                 endpoint receives a length exceeding the maximum, it MUST close \
                                 the session with a Protocol Violation.";
const GOAWAY_URI_MAX_14: &str = "The maxmimum length of the New Session URI is 8,192 bytes. If an \
                                 endpoint receives a length exceeding the maximum, it MUST close \
                                 the session with a PROTOCOL_VIOLATION.";
const GOAWAY_URI_MAX_17: &str = "The maximum length of the New Session URI is 8,192 bytes. If an \
                                 endpoint receives a length exceeding the maximum, it MUST close \
                                 the session with a PROTOCOL_VIOLATION.";
const KVP_VALUE_MAX_11: &str = "The maximum length of a value is 2^16-1 bytes. If an endpoint \
                                receives a length larger than the maximum, it MUST close the \
                                session with a Protocol Violation.";
const KVP_VALUE_MAX_16: &str = "The maximum length of a value is 2^16-1 bytes. If an endpoint \
                                receives a length larger than the maximum, it MUST close the \
                                session with a PROTOCOL_VIOLATION.";
const KVP_FORMATTING_11: &str = "If a receiver understands a Type, and the following Value or \
                                 Length/Value does not match the serialization defined by that \
                                 Type, the receiver MUST terminate the session with error code \
                                 \"Key-Value Formatting Error\".";
const KVP_FORMATTING_14: &str = "If a receiver understands a Type, and the following Value or \
                                 Length/Value does not match the serialization defined by that \
                                 Type, the receiver MUST terminate the session with error code \
                                 KEY_VALUE_FORMATTING_ERROR.";
const KVP_FORMATTING_16: &str = "If a receiver understands a Type, and the following Value or \
                                 Length/Value does not match the serialization defined by that \
                                 Type, the receiver MUST close the session with error code \
                                 KEY_VALUE_FORMATTING_ERROR.";
const UNKNOWN_PARAMETER_16: &str = "All Message Parameters MUST be defined in the negotiated \
                                    version of MOQT or negotiated via Setup Parameters. An \
                                    endpoint that receives an unknown Message Parameter MUST close \
                                    the session with PROTOCOL_VIOLATION.";
const UNKNOWN_PARAMETER_17: &str = "All Message Parameters MUST be defined in the negotiated \
                                    version of MOQT or negotiated via Setup Options. An endpoint \
                                    that receives an unknown Message Parameter MUST close the \
                                    session with PROTOCOL_VIOLATION.";
const PARAMETER_SCOPE: &str = "Each Message Parameter definition indicates the message types in \
                               which it can appear. If it appears in some other type of message, \
                               the receiving endpoint MUST close the connection with a \
                               PROTOCOL_VIOLATION.";
const PARAMETER_LENGTH: &str = "If a receiver understands a parameter type, and the parameter \
                                length implied by that type does not match the Parameter Length \
                                field, the receiver MUST terminate the session with error code \
                                'Parameter Length Mismatch'.";
const FILTER_TYPE_14: &str =
    "An endpoint that receives a filter type other than the above MUST be \
                              close the session with PROTOCOL_VIOLATION.";
const FILTER_TYPE_15: &str = "An endpoint that receives a filter type other than the above MUST \
                              close the session with PROTOCOL_VIOLATION.";
const FETCH_TYPE_14: &str = "An endpoint that receives a Fetch Type other than 0x1, 0x2 or 0x3 \
                             MUST be close the session with a PROTOCOL_VIOLATION.";
const FETCH_TYPE_15: &str = "An endpoint that receives a Fetch Type other than 0x1, 0x2 or 0x3 \
                             MUST close the session with a PROTOCOL_VIOLATION.";
const FILTER_PARAMETER_15: &str = "If the length of the Subscription Filter does not match the \
                                   parameter length, the publisher MUST close the session with \
                                   PROTOCOL_VIOLATION.";
const END_GROUP_WRAP_18: &str =
    "Otherwise, the last Group ID to be delivered will be the Group ID \
                                 in Start Location plus the End Group Delta. If the resulting \
                                 Group ID would be greater than 2^64 - 1, the endpoint MUST close \
                                 the session with a PROTOCOL_VIOLATION.";
const END_GROUP_WRAP_20: &str =
    "If StartGroup + EndGroupDelta exceeds 2^64 - 1, the endpoint MUST \
                                 close the session with a PROTOCOL_VIOLATION.";
const OBJECT_ID_WRAP: &str = "The Object ID Delta + 1 is added to the previous Object ID in the \
                              Subgroup stream if there was one. The Object ID is the Object ID \
                              Delta if it's the first Object in the Subgroup stream. If the \
                              resulting Object ID would be greater than 2^64 - 1, the endpoint \
                              MUST close the session with a PROTOCOL_VIOLATION.";
// The two Type-value rules, four wordings between them. Each draft states both
// as a sentence introducing a bulleted list of the values it rules out, and
// what is quoted is the sentence: the list is bullets rather than prose, and a
// quotation reaching into it would be a quotation of a list.
//
// The wording changes once, at draft-20, which stopped enumerating the code
// points and states the bit pattern alone — so "these Type values" becomes
// "these values" and the drafts part into two groups on each rule. A needle
// carrying the word Type finds drafts 16 through 19 and silently misses 20 and
// 21; the invariant clause is "receives a stream header with any of these".
const INVALID_STREAM_TYPE_16: &str = "If an endpoint receives a stream header with any of these \
                                      Type values, it MUST close the session with a \
                                      PROTOCOL_VIOLATION:";
const INVALID_STREAM_TYPE_20: &str = "If an endpoint receives a stream header with any of these \
                                      values, it MUST close the session with a \
                                      PROTOCOL_VIOLATION:";
const INVALID_DATAGRAM_TYPE_16: &str = "If an endpoint receives a datagram with any of these Type \
                                        values, it MUST close the session with a \
                                        PROTOCOL_VIOLATION:";
const INVALID_DATAGRAM_TYPE_20: &str = "If an endpoint receives a datagram with any of these \
                                        values, it MUST close the session with a \
                                        PROTOCOL_VIOLATION:";
const END_OF_TRACK_OBJECT_ID: &str = "An object with this status that has a Group ID less than or \
                                      equal to any other Group ID, or an Object ID other than \
                                      zero, is a protocol error, and the receiver MUST terminate \
                                      the session.";
const EXTENSIONS_ON_NONEXISTENT_11: &str = "Any Object may have extension headers except those \
                                            with Object Status 'Object Does Not Exist'. If an \
                                            endpoint receives a non-existent Object containing \
                                            extension headers it MUST close the session with a \
                                            Protocol Violation.";
const EXTENSIONS_ON_NONEXISTENT_14: &str = "Any Object may have extension headers except those \
                                            with Object Status 'Object Does Not Exist'. If an \
                                            endpoint receives a non-existent Object containing \
                                            extension headers it MUST close the session with a \
                                            PROTOCOL_VIOLATION.";
const REQUIRED_REQUEST_ID_DELTA: &str = "An endpoint MUST close the session with \
                                         INVALID_REQUIRED_REQUEST_ID if it receives a delta where \
                                         2 × Required Request ID Delta exceeds the Request ID.";

impl CodecRule {
    /// Every draft run this rule has a checked citation for, oldest first.
    ///
    /// Exhaustive with no wildcard arm, for the reason the enum is not
    /// `#[non_exhaustive]`: a rule added to this file arrives here as an
    /// `E0004` and a decision about which drafts state it.
    ///
    /// No arm answers with an empty slice, which is the one structural
    /// difference from [`AboveCodecRule::citations`]. There, nine rules do, and
    /// eight of them are rules no draft answers with a close. Here a rule with
    /// nothing to cite would have no reason to exist: the whole set is chosen
    /// by reading the fourteen `codec_session_error_code` tables for variants
    /// answered `Some` on at least one draft, and a rule stated in no draft is
    /// left out rather than written down with an empty slice. One rule is left
    /// out on other grounds entirely, and the enum's doc names it and says
    /// which.
    ///
    /// The runs are **not** the drafts that answer with a close, and the enum's
    /// doc says which two rows differ and why. A draft with a close and no
    /// citation publishes nothing, which is the safe direction; a draft with a
    /// citation and no close is a row nothing can reach, and
    /// `a_cited_draft_is_a_draft_that_closes` below asserts there are none.
    #[must_use]
    pub fn citations(self) -> &'static [RuleCitation] {
        match self {
            Self::TrackNameTooLong => &[
                RuleCitation {
                    drafts: (11, 13),
                    section: "2.4.1",
                    sentence: TRACK_NAME_MAX_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "2.4.1",
                    sentence: TRACK_NAME_MAX_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (15, 15),
                    section: "2.4.1",
                    sentence: TRACK_NAME_MAX_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (16, 20),
                    section: "2.4.1",
                    sentence: TRACK_NAME_MAX_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "8.7",
                    sentence: TRACK_NAME_MAX_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::ReasonPhraseTooLong => &[
                RuleCitation {
                    drafts: (11, 13),
                    section: "1.3.3",
                    sentence: REASON_PHRASE_MAX_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "1.4.3",
                    sentence: REASON_PHRASE_MAX_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (15, 16),
                    section: "1.4.3",
                    sentence: REASON_PHRASE_MAX_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 20),
                    section: "1.4.4",
                    sentence: REASON_PHRASE_MAX_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "8.5",
                    sentence: REASON_PHRASE_MAX_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::GoAwayUriTooLong => &[
                RuleCitation {
                    drafts: (11, 13),
                    section: "8.4",
                    sentence: GOAWAY_URI_MAX_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 16),
                    section: "9.4",
                    sentence: GOAWAY_URI_MAX_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.5",
                    sentence: GOAWAY_URI_MAX_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.4",
                    sentence: GOAWAY_URI_MAX_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.2",
                    sentence: GOAWAY_URI_MAX_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::KvpValueTooLong => &[
                RuleCitation {
                    drafts: (11, 13),
                    section: "1.3.2",
                    sentence: KVP_VALUE_MAX_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 15),
                    section: "1.4.2",
                    sentence: KVP_VALUE_MAX_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "1.4.2",
                    sentence: KVP_VALUE_MAX_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 20),
                    section: "1.4.3",
                    sentence: KVP_VALUE_MAX_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "8.3",
                    sentence: KVP_VALUE_MAX_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::KeyValueFormatting => &[
                RuleCitation {
                    drafts: (11, 13),
                    section: "1.3.2",
                    sentence: KVP_FORMATTING_11,
                    code_name: Some("Key-Value Formatting Error"),
                },
                RuleCitation {
                    drafts: (14, 15),
                    section: "1.4.2",
                    sentence: KVP_FORMATTING_14,
                    code_name: Some("KEY_VALUE_FORMATTING_ERROR"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "1.4.2",
                    sentence: KVP_FORMATTING_16,
                    code_name: Some("KEY_VALUE_FORMATTING_ERROR"),
                },
                RuleCitation {
                    drafts: (17, 20),
                    section: "1.4.3",
                    sentence: KVP_FORMATTING_16,
                    code_name: Some("KEY_VALUE_FORMATTING_ERROR"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "8.3",
                    sentence: KVP_FORMATTING_16,
                    code_name: Some("KEY_VALUE_FORMATTING_ERROR"),
                },
            ],
            Self::UnknownMessageParameter => &[
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.2",
                    sentence: UNKNOWN_PARAMETER_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.3",
                    sentence: UNKNOWN_PARAMETER_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.2",
                    sentence: UNKNOWN_PARAMETER_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.20",
                    sentence: UNKNOWN_PARAMETER_17,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::ParameterOutOfScope => &[
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.3.1",
                    sentence: PARAMETER_SCOPE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 20),
                    section: "10.2.1",
                    sentence: PARAMETER_SCOPE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.20.1",
                    sentence: PARAMETER_SCOPE,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::ParameterLengthMismatch => &[
                RuleCitation {
                    drafts: (7, 7),
                    section: "6.1",
                    sentence: PARAMETER_LENGTH,
                    code_name: Some("Parameter Length Mismatch"),
                },
                RuleCitation {
                    drafts: (8, 9),
                    section: "7.1",
                    sentence: PARAMETER_LENGTH,
                    code_name: Some("Parameter Length Mismatch"),
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "8.1",
                    sentence: PARAMETER_LENGTH,
                    code_name: Some("Parameter Length Mismatch"),
                },
            ],
            Self::InvalidFilterType => &[
                RuleCitation {
                    drafts: (14, 14),
                    section: "9.7",
                    sentence: FILTER_TYPE_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (15, 19),
                    section: "5.1.2",
                    sentence: FILTER_TYPE_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::InvalidFetchType => &[
                RuleCitation {
                    drafts: (14, 14),
                    section: "9.16",
                    sentence: FETCH_TYPE_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (15, 16),
                    section: "9.16",
                    sentence: FETCH_TYPE_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 17),
                    section: "9.14",
                    sentence: FETCH_TYPE_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 19),
                    section: "10.12",
                    sentence: FETCH_TYPE_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::SubscriptionFilterMalformed => &[
                RuleCitation {
                    drafts: (15, 15),
                    section: "9.2.1.7",
                    sentence: FILTER_PARAMETER_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (16, 16),
                    section: "9.2.2.5",
                    sentence: FILTER_PARAMETER_15,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (17, 20),
                    section: "1.4.3",
                    sentence: KVP_FORMATTING_16,
                    code_name: Some("KEY_VALUE_FORMATTING_ERROR"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "8.3",
                    sentence: KVP_FORMATTING_16,
                    code_name: Some("KEY_VALUE_FORMATTING_ERROR"),
                },
            ],
            Self::FilterEndGroupOverflow => &[
                RuleCitation {
                    drafts: (18, 19),
                    section: "5.1.2",
                    sentence: END_GROUP_WRAP_18,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (20, 20),
                    section: "5.1.2",
                    sentence: END_GROUP_WRAP_20,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "9.20.10",
                    sentence: END_GROUP_WRAP_20,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::ObjectIdOverflow => &[
                RuleCitation {
                    drafts: (18, 20),
                    section: "11.4.2",
                    sentence: OBJECT_ID_WRAP,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "11.3.1",
                    sentence: OBJECT_ID_WRAP,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::InvalidStreamTypeValue => &[
                RuleCitation {
                    drafts: (16, 17),
                    section: "10.4.2",
                    sentence: INVALID_STREAM_TYPE_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 19),
                    section: "11.4.2",
                    sentence: INVALID_STREAM_TYPE_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (20, 20),
                    section: "11.4.2",
                    sentence: INVALID_STREAM_TYPE_20,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "11.3.1",
                    sentence: INVALID_STREAM_TYPE_20,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::InvalidDatagramTypeValue => &[
                RuleCitation {
                    drafts: (16, 17),
                    section: "10.3.1",
                    sentence: INVALID_DATAGRAM_TYPE_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (18, 19),
                    section: "11.3.1",
                    sentence: INVALID_DATAGRAM_TYPE_16,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (20, 20),
                    section: "11.3.1",
                    sentence: INVALID_DATAGRAM_TYPE_20,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
                RuleCitation {
                    drafts: (21, 21),
                    section: "11.2.1",
                    sentence: INVALID_DATAGRAM_TYPE_20,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::EndOfTrackObjectId => &[
                RuleCitation {
                    drafts: (8, 9),
                    section: "8.1.1.1",
                    sentence: END_OF_TRACK_OBJECT_ID,
                    code_name: None,
                },
                RuleCitation {
                    drafts: (10, 10),
                    section: "9.1.1.1",
                    sentence: END_OF_TRACK_OBJECT_ID,
                    code_name: None,
                },
            ],
            Self::ExtensionsOnNonExistentObject => &[
                RuleCitation {
                    drafts: (11, 11),
                    section: "9.1.1.2",
                    sentence: EXTENSIONS_ON_NONEXISTENT_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (12, 13),
                    section: "9.2.1.2",
                    sentence: EXTENSIONS_ON_NONEXISTENT_11,
                    code_name: Some("Protocol Violation"),
                },
                RuleCitation {
                    drafts: (14, 14),
                    section: "10.2.1.2",
                    sentence: EXTENSIONS_ON_NONEXISTENT_14,
                    code_name: Some("PROTOCOL_VIOLATION"),
                },
            ],
            Self::InvalidRequiredRequestIdDelta => &[RuleCitation {
                drafts: (17, 17),
                section: "9.2",
                sentence: REQUIRED_REQUEST_ID_DELTA,
                code_name: Some("INVALID_REQUIRED_REQUEST_ID"),
            }],
        }
    }

    /// This rule as `draft` states it, or `None` where that draft does not.
    ///
    /// The same contract as [`AboveCodecRule::citation`], including the part
    /// that matters most: there is no fallback to a neighbouring draft's
    /// wording. `None` means there is no sentence to publish, so there is no
    /// accusation to make.
    #[must_use]
    pub fn citation(self, draft: u8) -> Option<&'static RuleCitation> {
        self.citations().iter().find(|c| c.covers(draft))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rule this build enforces, so a sweep cannot silently narrow.
    ///
    /// Written out rather than derived, because there is nothing to derive it
    /// from: the enum is not iterable and adding a variant has to be a decision
    /// here as well as in `citations`. A rule added and not listed fails
    /// `every_variant_is_swept` below.
    const ALL: &[AboveCodecRule] = &[
        AboveCodecRule::PropertiesOnNonNormalStatus,
        AboveCodecRule::PayloadOnStatusDatagram,
        AboveCodecRule::BidiStreamOpener,
        AboveCodecRule::MessageOnTheWrongStream,
        AboveCodecRule::ResponseNamesAnotherRequest,
        AboveCodecRule::ResponseBeforeItsFirstResponse,
        AboveCodecRule::GoAwayAtServer,
        AboveCodecRule::RepeatedGoAway,
        AboveCodecRule::RedirectUriAtServer,
        AboveCodecRule::RedirectTrackNameOnNamespaceRequest,
        AboveCodecRule::RequestIdParity,
        AboveCodecRule::RequestIdOutOfSequence,
        AboveCodecRule::RequestIdCeiling,
        AboveCodecRule::MaxRequestIdDecreased,
        AboveCodecRule::SetupParameterValue,
        AboveCodecRule::DuplicateTrackAlias,
        AboveCodecRule::MixedForwardingPreference,
        AboveCodecRule::EndOfTrackOutOfPlace,
        AboveCodecRule::ObjectPastFinalObject,
        AboveCodecRule::RequestUpdateForTheWrongRequest,
        AboveCodecRule::TooManyRequestUpdates,
        AboveCodecRule::TrackPropertiesOnNonTrackStatus,
        AboveCodecRule::StateNotifyOnTheWrongRequest,
        AboveCodecRule::UnrequestedFillStream,
        AboveCodecRule::SubscribeAfterAnnounceCancel,
        AboveCodecRule::TrackStatusIsNotASubscription,
        AboveCodecRule::MessageNamesAnUnknownRequest,
        AboveCodecRule::NamespacePrefixOverlap,
    ];

    /// Every rule the *decoder* raises that a draft answers with a close.
    ///
    /// The same shape as `ALL` and for the same reason. The two lists are kept
    /// apart rather than merged because the sweeps below ask both the same
    /// structural questions and nothing else: the two enums are two kinds of
    /// evidence and a test that could not say which one it had found would be
    /// the wrong test to fix a mix-up with.
    const ALL_CODEC: &[CodecRule] = &[
        CodecRule::TrackNameTooLong,
        CodecRule::ReasonPhraseTooLong,
        CodecRule::GoAwayUriTooLong,
        CodecRule::KvpValueTooLong,
        CodecRule::KeyValueFormatting,
        CodecRule::UnknownMessageParameter,
        CodecRule::ParameterOutOfScope,
        CodecRule::ParameterLengthMismatch,
        CodecRule::InvalidFilterType,
        CodecRule::InvalidFetchType,
        CodecRule::SubscriptionFilterMalformed,
        CodecRule::FilterEndGroupOverflow,
        CodecRule::ObjectIdOverflow,
        CodecRule::InvalidStreamTypeValue,
        CodecRule::InvalidDatagramTypeValue,
        CodecRule::EndOfTrackObjectId,
        CodecRule::ExtensionsOnNonExistentObject,
        CodecRule::InvalidRequiredRequestIdDelta,
    ];

    /// Every run in both tables, so a sweep cannot be written for one of them
    /// and quietly answer for neither.
    ///
    /// The two enums do not share a trait and giving them one would be giving
    /// the library a shape it needs for nothing but this, so what is shared is
    /// the slice of runs rather than the rule that owns it. Where a test needs
    /// to name the rule it failed on, it asks its own list.
    fn every_run() -> Vec<&'static RuleCitation> {
        ALL.iter()
            .flat_map(|r| r.citations().iter())
            .chain(ALL_CODEC.iter().flat_map(|r| r.citations().iter()))
            .collect()
    }

    /// The list above names every variant, so the sweeps below really are
    /// sweeps.
    ///
    /// `citations` is exhaustive, so a new variant is a build failure there;
    /// this list is not, so a new variant would silently drop out of every test
    /// in this module. Counting is the cheapest link between the two that does
    /// not need the enum to be iterable.
    #[test]
    fn every_variant_is_swept() {
        assert_eq!(ALL.len(), 28, "a rule was added or removed without updating ALL");
    }

    /// And the same for the decoder's half.
    #[test]
    fn every_codec_rule_is_swept() {
        assert_eq!(ALL_CODEC.len(), 18, "a rule was added or removed without updating ALL_CODEC");
    }

    /// A cited rule is a rule this build can actually raise on that draft.
    ///
    /// Not a claim about the drafts, and deliberately weaker than the one a
    /// reader might expect. What it rules out is a run written for a draft
    /// **outside** the range the enum's own doc claims for it — the failure
    /// that would put a sentence in front of a reader with no path to it. The
    /// stronger claim, that a cited draft is one whose
    /// `codec_session_error_code` answers `Some`, needs every draft's
    /// connection at once, and so belongs in a consumer that builds every
    /// draft rather than here.
    #[test]
    fn a_cited_draft_is_a_draft_that_closes() {
        for rule in ALL_CODEC {
            let runs = rule.citations();
            assert!(!runs.is_empty(), "{rule:?} is named with nothing to cite");
            for cite in runs {
                assert!(
                    moqtap_codec::version::DraftVersion::from_number(cite.drafts.0).is_some()
                        && moqtap_codec::version::DraftVersion::from_number(cite.drafts.1)
                            .is_some(),
                    "{rule:?} cites a draft outside the range this build implements"
                );
            }
        }
    }

    /// A rule's runs are ordered, do not overlap, and name only drafts this
    /// build implements.
    ///
    /// Overlap is the failure that would be invisible otherwise: `citation`
    /// takes the first run that covers a draft, so two runs claiming draft-14
    /// would publish one of them and never say which.
    #[test]
    fn every_run_is_ordered_contiguous_and_in_range() {
        let runs: Vec<(String, &'static [RuleCitation])> = ALL
            .iter()
            .map(|r| (format!("{r:?}"), r.citations()))
            .chain(ALL_CODEC.iter().map(|r| (format!("{r:?}"), r.citations())))
            .collect();
        for (rule, citations) in runs {
            let mut last: Option<u8> = None;
            for cite in citations {
                let (lo, hi) = cite.drafts;
                assert!(lo <= hi, "{rule:?}: run ({lo}, {hi}) runs backwards");
                assert!(
                    moqtap_codec::version::DraftVersion::from_number(lo).is_some()
                        && moqtap_codec::version::DraftVersion::from_number(hi).is_some(),
                    "{rule:?}: out of range"
                );
                if let Some(prev) = last {
                    assert!(
                        prev < lo,
                        "{rule:?}: run at {lo} overlaps or repeats the one at {prev}"
                    );
                }
                last = Some(hi);
            }
        }
    }

    /// One wording is written once.
    ///
    /// The claim the run representation rests on. Two rows carrying the same
    /// sentence must be pointing at the same constant, not at two copies of it
    /// — because two copies is how a correction reaches one of them and not the
    /// other, and the second copy then reads as a second draft's wording that
    /// happens to be identical.
    ///
    /// Compared by pointer as well as by value, which is what makes this a test
    /// about the representation rather than about the text.
    #[test]
    fn a_wording_shared_across_runs_is_written_once() {
        let mut seen: Vec<&'static str> = Vec::new();
        for cite in every_run() {
            match seen.iter().find(|s| **s == cite.sentence) {
                Some(first) => assert!(
                    std::ptr::eq(*first, cite.sentence),
                    "a sentence is repeated instead of naming the constant: {}",
                    &cite.sentence[..40.min(cite.sentence.len())]
                ),
                None => seen.push(cite.sentence),
            }
        }
        assert_eq!(seen.len(), 91, "the sentence count moved; re-run the draft sweep");
    }

    /// The code name a row carries is a name its own sentence uses.
    ///
    /// The one claim in a row that the draft text cannot be searched for on its
    /// own: a section number resolves, a sentence resolves, and a code name is
    /// a word. Tying it to the sentence is what keeps it from drifting into
    /// this build's spelling of the code — which is exactly the direction it
    /// would drift, since `SessionErrorCode` spells every one of them in Rust.
    ///
    /// Underscores are folded to spaces because the drafts spell the same code
    /// both ways across the range, and this test is about the name being the
    /// sentence's rather than about which era it belongs to.
    #[test]
    fn the_code_name_is_a_name_the_sentence_uses() {
        for cite in every_run() {
            let Some(name) = cite.code_name else { continue };
            let sentence = cite.sentence.replace('_', " ").to_lowercase();
            let name = name.replace('_', " ").to_lowercase();
            assert!(sentence.contains(&name), "a run names a code its sentence does not: {name}");
        }
    }

    /// The rule that made this table necessary, read at both ends of the range.
    ///
    /// One quoted sentence per rule published draft-18's words on every draft.
    /// This is the same rule asked twice, and every field of the answer differs
    /// — which is the whole claim, stated as an assertion rather than as a
    /// paragraph.
    #[test]
    fn the_track_alias_rule_is_a_different_citation_on_draft_07_and_draft_20() {
        let old = AboveCodecRule::DuplicateTrackAlias.citation(7).expect("draft-07 states it");
        let new = AboveCodecRule::DuplicateTrackAlias.citation(20).expect("draft-20 states it");
        assert_eq!(old.section, "6.4");
        assert_eq!(new.section, "11.1");
        assert_eq!(old.code_name, Some("Duplicate Track Alias"));
        assert_eq!(new.code_name, Some("DUPLICATE_TRACK_ALIAS"));
        assert_ne!(old.sentence, new.sentence);
        assert!(old.sentence.contains("already being used for a different track"));
        assert!(new.sentence.contains("PUBLISH or SUBSCRIBE_OK"));
    }

    /// A draft that states a rule in no words this build has checked has no
    /// citation, and the gap is not filled from a neighbour.
    ///
    /// Drafts 17 and 18 are the concrete case. REQUEST_UPDATE moved onto the
    /// request's own stream and the field naming the request it modifies was
    /// deleted from the message, so there is nothing in either draft to name a
    /// request that cannot take an update — and neither draft closes a session
    /// over one. Draft-19 reintroduces the rule. A table that interpolated
    /// would answer draft-17 with draft-16's sentence about a field draft-17
    /// does not have.
    #[test]
    fn a_draft_that_does_not_state_a_rule_gets_no_citation_from_its_neighbours() {
        let rule = AboveCodecRule::RequestUpdateForTheWrongRequest;
        assert!(rule.citation(16).is_some());
        assert!(rule.citation(17).is_none(), "draft-17 deleted the field the rule is about");
        assert!(rule.citation(18).is_none(), "and draft-18 had not brought it back");
        assert!(rule.citation(19).is_some(), "draft-19 states it again, in new words");
    }

    /// Rules the newest draft genuinely stopped stating.
    ///
    /// Empty is the normal state and the interesting one. A draft really can
    /// drop a rule - `RequestUpdateForTheWrongRequest` above is the worked
    /// case, deleted in drafts 17 and 18 along with the field it is about -
    /// so the sweep below cannot simply demand every rule on every draft. An
    /// entry here is the evidence for one of those, written down instead of
    /// absorbed; `RequestUpdateForTheWrongRequest` is not in it because
    /// draft-19 brought the rule back.
    const DROPPED_BY_THE_NEWEST_DRAFT: &[&str] = &[];

    /// The newest draft is not quietly the first one to stop citing a rule.
    ///
    /// `check-draft-parity.py` rule 2 asks this of every draft list in the
    /// tree - a list naming draft N-1 and not draft N is the shape of one
    /// nobody brought forward - and it cannot ask it here: `citations`
    /// publishes runs as `(first, last)` tuples, and a tuple of integers is
    /// not a draft list. `check-drafts.py` rule 8 cannot ask it either. Rule 8
    /// holds every citation this table *makes* against that draft's rendered
    /// text, which is a strong check on the rows that exist and silent about
    /// the row that was never written. A rule left behind therefore publishes
    /// a finding with no sentence under it, on a green build.
    ///
    /// A run cannot be widened to cover the new draft, which is why this keeps
    /// happening: the drafts renumber, so a draft that keeps a sentence
    /// verbatim still files it under a different section and needs its own
    /// `RuleCitation`. Draft-21 moved every one of them.
    #[test]
    fn a_rule_the_previous_draft_states_is_cited_by_the_newest() {
        let newest = (7u8..=255)
            .take_while(|n| moqtap_codec::version::DraftVersion::from_number(*n).is_some())
            .last()
            .expect("this build implements at least one draft");
        let previous = newest - 1;
        assert!(
            moqtap_codec::version::DraftVersion::from_number(previous).is_some(),
            "the implemented drafts are contiguous, so the newest has a predecessor"
        );

        let mut left_behind = Vec::new();
        for rule in ALL {
            if rule.citation(previous).is_some() && rule.citation(newest).is_none() {
                left_behind.push(format!("{rule:?}"));
            }
        }
        for rule in ALL_CODEC {
            if rule.citation(previous).is_some() && rule.citation(newest).is_none() {
                left_behind.push(format!("{rule:?}"));
            }
        }
        left_behind.retain(|name| !DROPPED_BY_THE_NEWEST_DRAFT.contains(&name.as_str()));

        assert!(
            left_behind.is_empty(),
            "draft-{previous:02} states these rules and draft-{newest:02} cites none of \
             them: {left_behind:?}. Either that draft dropped the rule, in which case name \
             it in DROPPED_BY_THE_NEWEST_DRAFT beside the sentence that went away, or the \
             run was not brought forward - add a RuleCitation at the section the new draft \
             files the sentence under."
        );
    }

    /// A rule with no sentence anywhere answers `None` on every draft.
    #[test]
    fn an_uncited_rule_names_no_draft() {
        for draft in 7..=21 {
            assert!(
                AboveCodecRule::MessageOnTheWrongStream.citation(draft).is_none(),
                "draft-{draft:02} acquired a citation for a rule no draft states"
            );
        }
    }
}

/// What one of a draft's *own* `ConnectionError` variants is — the ones outside
/// the ten every draft shares.
///
/// Returned by `Connection::draft_specific_cause`, which every draft
/// implements exhaustively over its own error type. `None` from that function
/// means the variant is one of the shared ten, which
/// [`crate::dispatch::AnyConnectionError`] classifies itself and never asks a
/// draft about.
///
/// The split is the whole point: the two are opposite findings, one this build
/// declining to do something and the other a relay having done something the
/// draft forbids. Without it both reach a consumer as prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftSpecificCause {
    /// This endpoint refused the call. Nothing was written and no state moved.
    ///
    /// A message handed to the control stream that belongs on a request stream,
    /// a `respond_*` helper pointed at a request this endpoint opened, a FIN
    /// asked for before the response the draft requires first, an object asked
    /// for before the header it is framed against. Every one of them is this
    /// side being told to do something it will not do, and every one of them
    /// reaches [`crate::dispatch::ErrorCause::Facade`].
    ///
    /// # And one that is not a call at all
    ///
    /// `ConnectionError::ControlMessageNarrowing` is the odd member, and it is
    /// here for the reason the rest are rather than because it looks like them.
    /// Every draft's `recv_control` decodes into `AnyControlMessage` and then
    /// narrows the result to its own draft, and the arm that catches a
    /// narrowing that did not work is unreachable: the decoder was this draft's,
    /// so the variant can only be this draft's. Nothing pins that.
    ///
    /// Spelled as `CodecError::UnknownMessageType(0)` the placeholder would not
    /// stay inert. Every draft's `codec_session_error_code` answers that
    /// variant `Some(PROTOCOL_VIOLATION)`, so an unreachable arm being reached
    /// would reach a caller as *the peer sent a control message type this
    /// draft does not assign, and the session must be closed with a Protocol
    /// Violation* — with `0x00` riding along as the codepoint that proved it.
    /// A conformance report reading that publishes a named accusation against a
    /// relay, carrying a piece of evidence, for a defect in this build. Better
    /// dressed than any accusation it makes on real grounds, and false.
    ///
    /// So it is a variant of its own and it answers here. That does not make
    /// the arm reachable; it makes reaching it say *this build declined* rather
    /// than *the peer violated*, with no rule and no close code for anything
    /// downstream to read out of it.
    LocalRefusal,
    /// The peer broke a rule this endpoint enforces above its decoder.
    PeerViolation {
        /// Which rule, named the same way on every draft that states it.
        rule: AboveCodecRule,
        /// The session error code **this draft's own text** requires be sent
        /// for it, where it names one.
        ///
        /// Exactly the contract [`crate::dispatch::ErrorCause::Codec`] gives
        /// `close`, and for the same reason: a rule a draft attaches no
        /// consequence to is not grounds to name a peer.
        close: Option<u64>,
    },
}

/// Whose doing one of a draft's `EndpointError` variants is.
///
/// Returned by `EndpointError::fault`, which every draft implements
/// exhaustively over its own error type — no wildcard arm, so a variant added
/// to a draft is a compile error beside the sentence it enforces rather than a
/// silent arrival on the wrong side of this answer.
///
/// # The question it answers, and the one it does not
///
/// The endpoint's error type mixes two opposite findings under one name, and
/// they read alike as prose. Some of its variants are raised while **reading**
/// what the peer sent, and they are the peer's doing. The rest are raised while
/// this endpoint is **writing**, or refusing to, and they are this side's — the
/// call failed, nothing reached the wire, and there is nothing to say about the
/// relay.
///
/// The code the draft requires be sent is deliberately not carried here.
/// `EndpointError::session_error_code` already answers it, per draft, quoting
/// the sentence that names it, and a second copy of that table beside this one
/// could disagree with it. [`crate::dispatch::AnyConnectionError`] reads both
/// and pairs them.
///
/// # Why `Some(code)` is not the test
///
/// It looks like one: a variant the draft answers with a session close is a
/// variant a peer broke a rule to reach. It is not, and the counterexample is
/// concrete. On every draft from 07 to 16, the send path refusing to advertise
/// a ceiling that does not increase — `send_max_subscribe_id` on drafts 07
/// through 10, `send_max_request_id` on 11 through 16 — and a peer sending a
/// ceiling of its own that does not increase are one variant apart: under a
/// single variant `session_error_code` answers both `Some(PROTOCOL_VIOLATION)`,
/// so a local refusal to write a message publishes as a relay breaking the
/// ceiling rule. That rule is stated of MAX_SUBSCRIBE_ID on drafts 07 through
/// 10 and of MAX_REQUEST_ID on 11 through 16, and the section moves under it
/// four times across the ten: 6.20, 7.20, 8.4, 8.5 and 9.5 — see
/// [`AboveCodecRule::MaxRequestIdDecreased`]'s citations for which drafts each
/// of those covers. Each side has a variant of its own for that reason, and
/// this enum is what makes the collision visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointFault {
    /// This endpoint's own doing: a call it refused, or state of its own that
    /// would not take one.
    ///
    /// Nothing reached the wire. A response offered for a request the draft
    /// requires be refused, a message handed to the wrong writer, an alias this
    /// endpoint was asked to give to a second track, a session that is closed
    /// or draining. Every one of them is evidence about this build and none of
    /// them is evidence about a peer, so all of them reach
    /// [`crate::dispatch::ErrorCause::Endpoint`], which
    /// [`crate::dispatch::AnyConnectionError::is_local`] counts.
    ///
    /// A peer can *cause* one of these without having broken anything this
    /// endpoint may name it for. A request whose filters the draft says to
    /// reject is refused here when a REQUEST_OK is offered for it, because the
    /// refusal is a reply and a reply needs the request to have been taken
    /// first; what failed is this side's attempt to accept it.
    ThisEndpoint,
    /// The peer did what the draft forbids, and this endpoint caught it
    /// reading.
    Peer(AboveCodecRule),
    /// Both are reachable through this variant and the variant cannot say
    /// which.
    ///
    /// Answered like [`Self::ThisEndpoint`] — reaching
    /// [`crate::dispatch::ErrorCause::Endpoint`], counted by
    /// [`crate::dispatch::AnyConnectionError::is_local`] — because that is the
    /// safe direction and the one this facade already took: a failure that has
    /// not been told apart is not evidence against a relay.
    ///
    /// Kept as its own answer rather than folded into `ThisEndpoint` so that
    /// the ones still to be told apart are a list the compiler can produce.
    /// There are two kinds:
    ///
    /// - **The state machines.** `Session`, `Subscription`, `Fetch`,
    ///   `Namespace`, `TrackStatus`, `PublishFlow`, `Setup` all render as
    ///   *invalid transition from X on event Y*, and the same sentence covers
    ///   this endpoint declining to send a message in a state that forbids it
    ///   and a peer having sent one. Telling those apart is a pass of its own.
    /// - **The unknown-request errors.** `UnknownRequest` and its earlier name
    ///   `UnknownSubscribe` are raised on more than sixty call sites per draft,
    ///   about half of them reading a response that names an id this session
    ///   never issued — the peer's doing — and about half of them a caller
    ///   naming one of its own that does not exist.
    ///
    /// Neither is published as anything: both answer `is_local` true. What this
    /// enum adds is that they are countable.
    EitherEnd,
}

impl EndpointFault {
    /// The rule this fault names, or `None` where it names none.
    ///
    /// `None` for both of the non-peer answers, which is the same collapse
    /// [`crate::dispatch::ErrorCause`] performs: neither is grounds to name a
    /// relay, and a caller that needs to tell them apart has the variant.
    pub fn rule(self) -> Option<AboveCodecRule> {
        match self {
            Self::Peer(rule) => Some(rule),
            Self::ThisEndpoint | Self::EitherEnd => None,
        }
    }
}

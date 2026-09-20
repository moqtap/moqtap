/// Maximum control message payload length: 2^16 - 1 bytes.
pub const MAX_MESSAGE_LENGTH: usize = 65535;
/// Maximum reason phrase length: 1024 bytes.
pub const MAX_REASON_PHRASE_LENGTH: usize = 1024;
/// Maximum GOAWAY new session URI length: 8192 bytes.
pub const MAX_GOAWAY_URI_LENGTH: usize = 8192;
/// Maximum full track name length: 4096 bytes.
pub const MAX_FULL_TRACK_NAME_LENGTH: usize = 4096;
/// Maximum track namespace tuple size: 32 elements.
pub const MAX_NAMESPACE_TUPLE_SIZE: usize = 32;

/// Errors produced during MoQT message encoding and decoding.
///
/// # Adding a variant
///
/// This enum is deliberately **not** `#[non_exhaustive]`, so that a session-close
/// table matching it exhaustively fails to compile until a new variant has been
/// placed on each of the fourteen drafts — either among the rules that draft
/// answers with a close or among the ones it names and does not. A wildcard arm
/// would make those fourteen decisions silently, all in the direction of "no
/// rule", and a missing arm and a deliberate exclusion look identical from
/// inside such a table.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CodecError {
    /// Unknown or unsupported message type identifier.
    #[error("unknown message type: 0x{0:x}")]
    UnknownMessageType(u64),
    /// Not enough bytes in the buffer to complete decoding.
    #[error("insufficient bytes")]
    UnexpectedEnd,
    /// Control message payload exceeds [`MAX_MESSAGE_LENGTH`].
    #[error("message too long: {0} bytes (max {MAX_MESSAGE_LENGTH})")]
    MessageTooLong(usize),
    /// Variable-length integer encoding/decoding error.
    #[error("varint error: {0}")]
    VarInt(#[from] crate::varint::VarIntError),
    /// Key-value pair encoding/decoding error.
    #[error("kvp error: {0}")]
    Kvp(#[from] crate::kvp::KvpError),
    /// A decoded field value is not valid for its type.
    #[error("invalid field value")]
    InvalidField,
    /// Namespace tuple element count is outside the range the caller allows.
    ///
    /// The upper bound is [`MAX_NAMESPACE_TUPLE_SIZE`] everywhere. The lower
    /// bound is per-draft, and three wordings carry two rules. Drafts 07
    /// through 14 define a Track Namespace as "an ordered N-tuple of bytes
    /// where N can be between 1 and 32"; drafts 15 and 16 rename the elements
    /// to Track Namespace Fields and keep the 1; drafts 17 and later lower it
    /// to 0. So an empty tuple is refused only through draft-16.
    #[error("namespace tuple size {0} is not allowed here (max {MAX_NAMESPACE_TUPLE_SIZE})")]
    InvalidNamespaceTupleSize(usize),
    /// A Track Namespace Field was declared with a length of zero.
    ///
    /// Drafts 16 through 19 all carry the same sentence in Section 2.4.1: "Each
    /// Track Namespace Field Value MUST contain at least one byte. If an
    /// endpoint receives a Track Namespace Field with a Track Namespace Field
    /// Length of 0, it MUST close the session with a PROTOCOL_VIOLATION."
    #[error("track namespace field is empty; each field must contain at least one byte")]
    EmptyNamespaceField,
    /// Full track name exceeds [`MAX_FULL_TRACK_NAME_LENGTH`].
    #[error("track namespace or full track name exceeds {MAX_FULL_TRACK_NAME_LENGTH} bytes")]
    TrackNameTooLong,
    /// A requested range ends before it starts.
    ///
    /// Every draft states it, in the wording its fields have at the time.
    /// Draft-07 Section 6.4 and Section 6.7: "EndGroup and EndObject MUST
    /// specify the same or a later object than StartGroup and StartObject".
    /// Draft-08 Section 7.4 through draft-14 Section 9.7, for the AbsoluteRange
    /// filter: "End Group MUST specify the same or a larger Group than
    /// specified in Start". Draft-12 Section 8.16 onwards, for FETCH: "End
    /// Location MUST specify the same or a larger Location than Start
    /// Location", which drafts 14 and later qualify with "for Standalone and
    /// Absolute Joining Fetches".
    ///
    /// The two ends are reported as they appear on the wire, before the
    /// draft's plus-one adjustments are undone, so the numbers here are the
    /// ones a peer would read out of the frame.
    #[error("range from group {0} object {1} ends at group {2} object {3}, which is earlier")]
    InvalidRange(u64, u64, u64, u64),
    /// A parameter's value is not the shape the parameter's own type implies.
    ///
    /// Drafts 07 through 10 state it once each, in the section that gives the
    /// Parameter format: "If a receiver understands a parameter type, and the
    /// parameter length implied by that type does not match the Parameter Length
    /// field, the receiver MUST terminate the session with error code 'Parameter
    /// Length Mismatch'." Each of those drafts assigns that code its own number
    /// in the session termination registry. Drafts 11 and later drop the
    /// sentence along with the Parameter framing it describes.
    ///
    /// The parameter reported is the one whose value disagreed with its type.
    /// Which namespace the type is read in matters: a setup 0x02 is a
    /// MAX_SUBSCRIBE_ID integer and a version-specific 0x02 is an
    /// AUTHORIZATION INFO string.
    #[error("parameter type {0} carries a value of the wrong length for its type")]
    ParameterLengthMismatch(u64),
    /// A key-value pair's value is not the serialization its own Type defines.
    ///
    /// Drafts 11 through 19 state it once each, in the section that gives the
    /// Key-Value-Pair format. Drafts 14 and 15 word it: "If a receiver
    /// understands a Type, and the following Value or Length/Value does not
    /// match the serialization defined by that Type, the receiver MUST
    /// terminate the session with error code KEY_VALUE_FORMATTING_ERROR".
    /// Drafts 16 through 19 say close where those two say terminate, and
    /// drafts 11 through 13 spell the code 'Key-Value Formatting Error'. Every
    /// one of the nine assigns it a number in the session termination
    /// registry.
    ///
    /// This is the successor to [`CodecError::ParameterLengthMismatch`], which
    /// drafts 07 through 10 state about the Parameter framing they had instead.
    /// The two never overlap: no draft states both, and the earlier rule is
    /// about a declared length disagreeing with a type while this one is about
    /// the bytes themselves.
    ///
    /// The rule is conditional on understanding the Type, so it reaches only the
    /// types a draft defines a serialization for. A parameter this codec cannot
    /// name carries bytes no rule here describes, and refusing it would close
    /// sessions over extensions the drafts leave room for.
    ///
    /// `key` is the parameter type as the frame spelled it, in the namespace it
    /// was read in — AUTHORIZATION TOKEN is 0x01 on draft-11 and 0x03 on drafts
    /// 12 through 19, and a setup 0x01 is a PATH on draft-11 rather than a token
    /// at all. `detail` says which way the value failed to match, because the
    /// serialization is a structure rather than a length and "malformed" alone
    /// leaves the reader to re-derive it.
    #[error(
        "key-value pair of type {key} does not match the serialization that type defines: {detail}"
    )]
    KeyValueFormatting {
        /// The parameter type whose value did not match, as the frame spelled
        /// it.
        key: u64,
        /// How the value failed to match the serialization.
        detail: &'static str,
    },
    /// A control message carried a Message Parameter whose type its draft does
    /// not define.
    ///
    /// Drafts 16, 17, 18 and 19 state it in the paragraph that introduces
    /// parameters: "All Message Parameters MUST be defined in the negotiated
    /// version of MOQT or negotiated via Setup Options. An endpoint that
    /// receives an unknown Message Parameter MUST close the session with
    /// PROTOCOL_VIOLATION." Drafts 17 and later add the reasoning — "Because the
    /// receiver has to understand every Message Parameter, there is no need for
    /// a mechanism to skip unknown parameters" — and draft-19 draws the
    /// consequence for the framing: "Because unknown parameters cannot be
    /// skipped, the block is bounded by a parameter count rather than a length."
    /// Drafts 07 through 15 are the other way round and this must not reach
    /// them. They say "Receivers MUST allow duplicates of unknown parameters",
    /// which presumes unknown parameters arrive and are carried; refusing one
    /// there would close a session over an extension those drafts leave room
    /// for. Draft-16 is where the sentence narrows to *unknown **Setup**
    /// Parameters*, in the same paragraph that adds the close — one edit, both
    /// halves.
    ///
    /// Setup Parameters keep the older behaviour on every draft, which is why
    /// this is about one namespace and not both. Drafts 16 through 19 all say a
    /// receiver ignores an unrecognised Setup Option or Setup Parameter, so a
    /// type unknown in that namespace is carried and only a type unknown in the
    /// message namespace ends the session.
    #[error("message parameter type {0} is not one this draft defines")]
    UnknownMessageParameter(u64),
    /// A Message Parameter appeared in a message type its own definition does
    /// not name.
    ///
    /// Drafts 17, 18 and 19 only, and the split is the whole reason this is a
    /// variant rather than a shared rule. All fourteen drafts state the first
    /// half the same way and ten of them state the opposite consequence.
    /// Draft-19 Section 10.2.1, draft-18 Section 10.2.1 and draft-17 Section
    /// 9.3.1: "Each Message Parameter definition indicates the message types in
    /// which it can appear. If it appears in some other type of message, the
    /// receiving endpoint MUST close the connection with a PROTOCOL_VIOLATION."
    /// Draft-16 Section 9.2.2 and, under the older name Version Specific
    /// Parameters, drafts 07 through 15, end the same sentence "it MUST be
    /// ignored". Raising this on any of those ten would close a session over
    /// traffic they oblige an endpoint to tolerate, so the decoder never does.
    ///
    /// What each draft's own text settles, and what it leaves open:
    ///
    /// * A parameter's scope is the set of message types named as the
    ///   destination of its "MAY appear in" sentence, with trailing and
    ///   parenthesised qualifiers read as describing one of those destinations
    ///   rather than adding another. Draft-17's LARGEST_OBJECT "MAY appear in
    ///   SUBSCRIBE_OK, PUBLISH or in REQUEST_OK (in response to REQUEST_UPDATE
    ///   or TRACK_STATUS)" scopes three message types, not five, which is how
    ///   drafts 18 and 19 write the same rule once the responses have names of
    ///   their own.
    /// * Half the response names are one wire type. Draft-19 Section 10.5:
    ///   "This document uses the shorthand PUBLISH_OK, REQUEST_UPDATE_OK,
    ///   TRACK_STATUS_OK, SUBSCRIBE_NAMESPACE_OK, and PUBLISH_NAMESPACE_OK to
    ///   refer to a REQUEST_OK sent in response to the corresponding request
    ///   type." Which one a given REQUEST_OK is depends on the request its
    ///   Request ID answers, which is session state and not in the frame, so
    ///   every name that resolves to REQUEST_OK widens the same set and a
    ///   REQUEST_OK is held only to their union.
    ///
    /// Both readings err toward carrying the parameter, which is the direction
    /// a rule that ends sessions should be wrong in.
    ///
    /// `key` is the absolute parameter type after any delta encoding is
    /// resolved, and `message_type` is the type id off the wire, so a log names
    /// the pair the sender actually wrote.
    #[error("message parameter type {key} may not appear in message type {message_type}")]
    ParameterOutOfScope {
        /// The parameter type that was out of scope, absolute.
        key: u64,
        /// The message type it arrived in, as its id on the wire.
        message_type: u64,
    },
    /// A Message Parameter carried a value outside the range its type allows.
    ///
    /// Drafts 15 through 19 give several parameters a range and answer anything
    /// outside it with a close. GROUP_ORDER: "The allowed values are Ascending
    /// (0x1) or Descending (0x2). If an endpoint receives a value outside this
    /// range, it MUST close the session with PROTOCOL_VIOLATION." FORWARD says
    /// the same of 0 and 1. Drafts 15 and 16 add SUBSCRIBER_PRIORITY — "The
    /// range is restricted to 0-255" — which drafts 17 and later do not need,
    /// having made the parameter a uint8 so that nothing outside the range can
    /// be spelled. Draft-15 alone carries DYNAMIC_GROUPS as a Message Parameter,
    /// where "Values larger than 1 are a Protocol Violation"; draft-16 moved it
    /// into the extension header namespace, which this codec carries as opaque
    /// bytes.
    ///
    /// Not draft-15's PUBLISHER_PRIORITY. It says "Priorities above 255 are
    /// invalid" and stops there, naming no consequence, where every parameter
    /// above states one in the next clause. The contrast is within one section,
    /// so the omission is the draft's and not an oversight to be read past.
    ///
    /// Nor the Group Order and Forward *fields* of drafts 07 through 14, which
    /// are a different serialization and are answered separately — Forward by
    /// [`CodecError::InvalidForward`], Group Order by nothing, for the reason
    /// given there.
    ///
    /// `key` is the absolute parameter type, after any delta encoding is
    /// resolved, so a log names the type the sender meant rather than the
    /// increment it wrote.
    #[error(
        "message parameter type {key} carries value {value}, which is outside the range it allows"
    )]
    ParameterValueOutOfRange {
        /// The parameter type whose value was out of range, absolute.
        key: u64,
        /// The value as it arrived.
        value: u64,
    },
    /// A Track Extension or Track Property carried a value outside the range its
    /// type allows.
    ///
    /// A separate namespace from [`CodecError::ParameterValueOutOfRange`], and
    /// separate for a reason rather than for tidiness: the two registries assign
    /// the same numbers to different things. Type 0x22 is the GROUP_ORDER
    /// Message Parameter and it is also DEFAULT_PUBLISHER_GROUP_ORDER, which is
    /// a property of the track rather than a preference expressed by one
    /// subscriber. Type 0x30 is DYNAMIC_GROUPS in the second namespace and is
    /// unassigned in the first from draft-16 on. A single variant covering both
    /// would name a type without saying which table to read it in.
    ///
    /// Draft-16 states the rules of the extension header namespace and drafts
    /// 17, 18 and 19 restate them of the Track Property namespace that replaced
    /// it. Two types restrict their range and answer anything outside it with a
    /// close. DEFAULT_PUBLISHER_GROUP_ORDER: "The allowed values are Ascending
    /// (0x1) or Descending (0x2). If an endpoint receives a value outside this
    /// range, it MUST close the session with PROTOCOL_VIOLATION." DYNAMIC_GROUPS:
    /// "The allowed values are 0 or 1... If an endpoint receives a value larger
    /// than 1, it MUST close the session with PROTOCOL_VIOLATION."
    ///
    /// Draft-16 adds a third, and only draft-16: "DELIVERY_TIMEOUT, if present,
    /// MUST contain a value greater than 0. If an endpoint receives a
    /// DELIVERY_TIMEOUT equal to 0 it MUST close the session with
    /// PROTOCOL_VIOLATION." Draft-17 renamed the type to
    /// OBJECT_DELIVERY_TIMEOUT and states no range for it, so the rule ends
    /// where the name does.
    ///
    /// Not DEFAULT_PUBLISHER_PRIORITY, on any of the four. "Priorities above 255
    /// are invalid" names no consequence, in a section where its neighbours
    /// name one in the next clause. The same contrast excludes draft-15's
    /// PUBLISHER_PRIORITY from [`CodecError::ParameterValueOutOfRange`], and it
    /// is the draft's distinction both times.
    ///
    /// `key` is the absolute type, after any delta encoding is resolved.
    #[error(
        "track property type {key} carries value {value}, which is outside the range it allows"
    )]
    TrackPropertyValueOutOfRange {
        /// The extension or property type whose value was out of range,
        /// absolute.
        key: u64,
        /// The value as it arrived.
        value: u64,
    },
    /// A Forward field carried a value other than zero or one.
    ///
    /// Drafts 11 through 14 carry the field, and state the rule in two wordings.
    /// SUBSCRIBE and SUBSCRIBE_UPDATE, on all four: "Forward: If 1, Objects
    /// matching the subscription are forwarded to the subscriber. If 0, Objects
    /// are not forwarded to the subscriber. Any other value is a protocol error
    /// and MUST terminate the session with a Protocol Violation". PUBLISH, added
    /// in draft-12: "Any value other than 0 or 1 is a Protocol Violation."
    /// Draft-14 spells both codes PROTOCOL_VIOLATION and is otherwise unchanged.
    ///
    /// PUBLISH_OK, also from draft-12, is the one site that names no
    /// consequence: "Forward: The Forward State for this subscription, either 0
    /// (don't forward) or 1 (forward)." It is reported here all the same. The
    /// field carries the same two values in every message that has one, three of
    /// the four sites state the close outright, and the sentence enumerates 0
    /// and 1 without giving a third value any meaning — so this is the same rule
    /// stated shorter, not a permission. Reading an omission the other way is
    /// how a wrong claim gets in: on Group Order, drafts 12 through 14 do state
    /// the 0x0 rule for SUBSCRIBE_OK, PUBLISH and FETCH_OK, so a reading that has
    /// them silent about it is wrong about all three.
    ///
    /// Drafts 07 through 10 have no such field. Drafts 15 and later carry
    /// forwarding as the FORWARD parameter instead, under the same rule but a
    /// different serialization; that form is
    /// [`CodecError::ParameterValueOutOfRange`].
    #[error("forward field carries {0}, which is neither zero nor one")]
    InvalidForward(u8),
    /// A subscription filter names a Filter Type no draft in its range assigns.
    ///
    /// All fourteen drafts state the rule and they do not state the same
    /// consequence. Drafts 07 through 13: "A filter type other than the above
    /// MUST be treated as error", which names no code and no close. Draft-14:
    /// "An endpoint that receives a filter type other than the above MUST be
    /// close the session with PROTOCOL_VIOLATION", the typo being the draft's.
    /// Drafts 15 through 19 say the same without the typo. So the same value in
    /// the same place is a refused message on the first seven drafts and a
    /// session close on the last six, and only the per-draft session table can
    /// tell them apart.
    ///
    /// The assigned set is not constant either. Drafts 07 and 08 assign 0x1 as
    /// Latest Group, drafts 09 and 10 withdraw it and list three types, and
    /// drafts 11 and later reinstate 0x1 as Next Group Start — a different
    /// meaning at the same number. A decoder that accepts the union would read a
    /// draft-09 SUBSCRIBE the draft requires it to reject.
    ///
    /// The serialization moves as well. Drafts 07 through 14 carry the Filter
    /// Type as a field of SUBSCRIBE and its relatives; drafts 15 and later carry
    /// it as the first field inside the length-prefixed filter parameter, which
    /// is a place a reader of the field has to know to look.
    #[error("filter type {0} is not one this draft assigns")]
    InvalidFilterType(u64),
    /// A FETCH names a Fetch Type no draft in its range assigns.
    ///
    /// The sentence next to the Filter Type one, and it moves the same way.
    /// Drafts 08 through 13: "A Fetch Type other than 0x1, 0x2 or 0x3 MUST be
    /// treated as an error", naming no code and no close — 0x3 being absent from
    /// the sentence on drafts 08, 09 and 10, which assign only two types.
    /// Draft-14: "An endpoint that receives a Fetch Type other than 0x1, 0x2 or
    /// 0x3 MUST be close the session with a PROTOCOL_VIOLATION", carrying the
    /// same missing word as its Filter Type sentence. Drafts 15 through 19 say it
    /// without the typo. Draft-07 has no FETCH at all.
    ///
    /// Like the Filter Type, the value decides which fields follow it: a
    /// Standalone fetch carries a Track Namespace, a Track Name and a range, and
    /// a joining fetch carries a Request ID and an offset. A reader that cannot
    /// name the type cannot find the end of the message, which is why the later
    /// drafts answer it with a close rather than by ignoring the field.
    #[error("fetch type {0} is not one this draft assigns")]
    InvalidFetchType(u64),
    /// A subscription filter parameter's value is not a filter.
    ///
    /// Drafts 15 and 16 state it of this parameter directly: "If the length of
    /// the Subscription Filter does not match the parameter length, the publisher
    /// MUST close the session with PROTOCOL_VIOLATION." Drafts 17 through 19
    /// drop that sentence and leave the general one, which every draft from 15
    /// on also carries: "If a receiver understands a Type, and the following
    /// Value or Length/Value does not match the serialization defined by that
    /// Type, the receiver MUST close the session with error code
    /// KEY_VALUE_FORMATTING_ERROR."
    ///
    /// Two sentences, two codes, one malformation — which is why this is a
    /// variant of its own rather than reported as
    /// [`CodecError::KeyValueFormatting`]. A filter three bytes long inside a
    /// four-byte parameter ends a draft-16 session with PROTOCOL_VIOLATION and a
    /// draft-17 session with KEY_VALUE_FORMATTING_ERROR, and the session tables
    /// are where that difference belongs.
    ///
    /// A Filter Type outside the assigned set is not this: the filter's own
    /// section names PROTOCOL_VIOLATION for that on all five drafts, and it is
    /// [`CodecError::InvalidFilterType`].
    ///
    /// `detail` says which way the value failed, because "malformed" alone
    /// leaves the reader to work out whether the filter ran short or the
    /// parameter ran long.
    #[error("subscription filter parameter is not a filter: {detail}")]
    SubscriptionFilterMalformed {
        /// How the value failed to be a filter.
        detail: &'static str,
    },
    /// An AbsoluteRange filter's End Group Delta carries the range past the end
    /// of the number space.
    ///
    /// Drafts 17 and later replaced the absolute End Group with a delta measured
    /// from the Start Location's Group, which makes the last group in range a
    /// sum rather than a field. Drafts 18 and 19 answer the sum leaving the
    /// range: "Otherwise, the last Group ID to be delivered will be the Group ID
    /// in Start Location plus the End Group Delta. If the resulting Group ID
    /// would be greater than 2^64 - 1, the endpoint MUST close the session with
    /// a PROTOCOL_VIOLATION."
    ///
    /// Draft-17 introduced the delta and states no such sentence, so it is
    /// absent from that draft's session table. Drafts 15 and 16 write the End
    /// Group out in full and can express nothing to overflow.
    #[error(
        "filter start group {start_group} plus end group delta {delta} leaves the 64-bit range"
    )]
    FilterEndGroupOverflow {
        /// The Group ID of the filter's Start Location.
        start_group: u64,
        /// The End Group Delta as the filter carried it.
        delta: u64,
    },
    /// An end-of-track object states an Object ID other than zero.
    ///
    /// Drafts 08, 09 and 10 describe Object Status 0x5 as "end of Track. GroupID
    /// is one greater than the largest group produced in this track and the
    /// ObjectId is zero", and continue: "An object with this status that has a
    /// Group ID less than or equal to any other Group ID, or an Object ID other
    /// than zero, is a protocol error, and the receiver MUST terminate the
    /// session." The Group ID half needs the largest group seen on the track and
    /// is not settleable from one header; the Object ID half is, and is what this
    /// reports. Draft-07 assigns no 0x5 and drafts 11 and later drop the
    /// sentence.
    #[error("end-of-track object states object id {0}; an end of track ends at object zero")]
    EndOfTrackObjectId(u64),
    /// A delta-encoded key would exceed 2^64 - 1 once the delta is added to the
    /// previous key.
    ///
    /// Drafts 16, 17, 18 and 19 all say, in Section 1.4.3: "The previous Type
    /// value plus the Delta Type MUST NOT be greater than 2^64 - 1. If a Delta
    /// Type is received that would be too large, the Session MUST be closed
    /// with a PROTOCOL_VIOLATION." Delta encoding arrives with draft-16;
    /// drafts 15 and earlier write absolute types and cannot reach this.
    #[error("delta-encoded key {0} + {1} exceeds 2^64 - 1")]
    KeyDeltaOverflow(u64, u64),
    /// A caller asked to encode a parameter list that is not in ascending order
    /// by type.
    ///
    /// Drafts 17, 18 and 19 require it in as many words: "Parameters MUST be
    /// serialized in ascending order by Type." Draft-16 delta-encodes types
    /// without stating that sentence, but the constraint is the same there and
    /// is structural rather than stated: the delta is an unsigned difference
    /// from the previous type, so a descending pair has no representation at
    /// all. Encoding one anyway wraps the subtraction and emits a nine-byte
    /// delta the peer resolves to an unrelated key, which is why draft-16
    /// reports this too.
    #[error("parameter type {1} follows {0}; parameters must be in ascending order by type")]
    ParametersOutOfOrder(u64, u64),
    /// The same parameter type appears twice in one message, and its definition
    /// does not allow that.
    ///
    /// Every draft from 07 to 20 states the sender's half: "Senders MUST NOT
    /// repeat the same Parameter Type in a message" — drafts 11 and later
    /// adding "unless the parameter definition explicitly allows multiple
    /// instances of that type to be sent in a single message." The receiver's
    /// half is a SHOULD, and from draft-11 it carries a limit that makes the
    /// rule asymmetric: "Receivers MUST allow duplicates of unknown
    /// parameters." A receiver may therefore refuse a repeat only of a type its
    /// own draft names, while a sender may repeat nothing it is not granted.
    ///
    /// One type is granted repeats, from draft-11 onward: AUTHORIZATION TOKEN,
    /// numbered 0x01 on draft-11 and 0x03 on drafts 12 through 19. It is not
    /// reported here. Drafts 07 through 10 state neither the exemption clause
    /// nor the unknown-duplicates sentence, so on those four the rule is
    /// symmetric and every repeat is refused in both directions.
    ///
    /// Setup Parameters and Version Specific Parameters are separate
    /// namespaces that assign different meanings to the same number, so the
    /// exemption is per namespace: on draft-11, 0x01 is the repeatable
    /// AUTHORIZATION TOKEN in a SUBSCRIBE and the non-repeatable PATH in a
    /// CLIENT_SETUP.
    #[error("parameter type {0} appears more than once")]
    DuplicateParameter(u64),
    /// A delta-encoded Object ID would exceed 2^64 - 1 once the delta is added
    /// to the previous Object ID on the same stream.
    ///
    /// Draft-18 Section 11.4.2 and draft-19 Section 11.4.2: "The Object ID
    /// Delta + 1 is added to the previous Object ID in the Subgroup stream if
    /// there was one... If the resulting Object ID would be greater than
    /// 2^64 - 1, the endpoint MUST close the session with a
    /// PROTOCOL_VIOLATION." Draft-17
    /// Section 10.4.2 describes the same arithmetic and states no consequence,
    /// so on that draft this is a decode failure and nothing more.
    ///
    /// Distinct from [`CodecError::InvalidField`], which is too coarse for this
    /// rule: a caller could not tell the wrap from a dozen unrelated
    /// malformations, and so could not act on the rule.
    #[error("object id {0} + {1} + 1 exceeds 2^64 - 1")]
    ObjectIdOverflow(u64, u64),
    /// An Object with Object Status 'Object Does Not Exist' carries extension
    /// headers.
    ///
    /// Drafts 11 through 14 state it once each — draft-11 Section 9.1.1.2,
    /// drafts 12 and 13 Section 9.2.1.2, draft-14 Section 10.2.1.2 — and the
    /// first three word it: "Any Object may have extension headers except those
    /// with Object Status 'Object Does Not Exist'. If an endpoint receives a
    /// non-existent Object containing extension headers it MUST close the
    /// session with a Protocol Violation." Draft-14 states the same sentence
    /// with the code spelled PROTOCOL_VIOLATION.
    ///
    /// The rule names one status and no others, so extensions beside End of
    /// Group or End of Track are legal on those four drafts and are not
    /// reported here. Drafts 15 and later replaced this narrow form with the
    /// general one — extensions, later properties, are permitted only beside
    /// Normal — which is a different rule with a different subject and is
    /// reported by the carriers' own `extensions_permitted` predicates.
    ///
    /// Drafts 07 through 10 state neither form.
    ///
    /// All three carriers that announce a status reach this, in both
    /// directions: an object on a subgroup stream, an object on a fetch stream,
    /// and a status datagram. A plain datagram has no status field and is the
    /// one carrier that cannot break the rule.
    ///
    /// Distinct from [`CodecError::InvalidField`], which is too coarse for this
    /// rule: a caller could not tell it from a dozen unrelated malformations, so
    /// a session could not be closed over it without closing sessions the drafts
    /// do not ask to be closed.
    #[error("object with status 'object does not exist' carries {0} bytes of extension headers")]
    ExtensionsOnNonExistentObject(usize),
    /// An object arrived carrying a payload the draft gives it no room for.
    ///
    /// All fourteen drafts state the rule, in two phrasings. Drafts 07 through
    /// 18 say it of the status code — draft-07 Section 7.1.1.1, drafts 08 and
    /// 09 Section 8.1.1.1, drafts 10 and 11 Section 9.1.1.1, drafts 12 and 13
    /// Section 9.2.1.1, drafts 14 through 17 Section 10.2.1.1, draft-18 Section
    /// 11.2.1.1: "Any object with a status code other than zero MUST have an
    /// empty payload." Drafts 19 and 20 state it of a registry instead, both in
    /// their Section 11.2.1.1: "An Object MUST have an empty payload unless its
    /// Object Status value is registered as permitting a payload in the Object
    /// Status registry (Section 15.9). Of the values defined in this document,
    /// only Normal (0x0) permits a payload." The two agree on every status those
    /// documents define and differ in what a later one may add.
    ///
    /// `detail` separates the two ways an object can break it, because they are
    /// different mistakes and the second is the one a decoder can be fooled by:
    ///
    /// * The framing already said there would be no payload. A datagram whose
    ///   Type sets the STATUS bit carries a status in the payload's place, so
    ///   bytes after it are not a short payload or an odd one — they are bytes
    ///   the frame does not define. This bites hardest at status Normal, whose
    ///   status alone would report a payload as permitted, and a caller that
    ///   treats what is left as the payload hands the application content the
    ///   publisher never framed as content.
    /// * The status forbids one. The registry rule above, reached where a
    ///   caller holds a status and a payload together and the framing has not
    ///   already ruled one of them out.
    ///
    /// **No draft turns this into a close.** The sentence is a MUST on the
    /// sender with no receiver action named, and the "SHOULD be treated as a
    /// protocol error" beside it belongs to the neighbouring rule about
    /// unassigned status values. So all fourteen session-close tables place it
    /// among the rules they state and do not end a session over — which is a
    /// decision this variant makes visible, and one
    /// [`CodecError::InvalidField`] was making by accident.
    ///
    /// Distinct from that variant for the reason
    /// [`CodecError::ExtensionsOnNonExistentObject`] is: an error a caller
    /// cannot name is one no test can assert and no log can explain.
    #[error("object with status {status} carries {len} bytes of payload; {detail}")]
    PayloadNotPermitted {
        /// The object's status as it arrived on the wire.
        status: u64,
        /// How many bytes followed it.
        len: usize,
        /// Which of the two rules the bytes broke.
        detail: &'static str,
    },
    /// A request message's Required Request ID Delta names a dependency below
    /// zero.
    ///
    /// Draft-17 Section 9.2: "An endpoint MUST close the session with
    /// INVALID_REQUIRED_REQUEST_ID if it receives a delta where 2 × Required
    /// Request ID Delta exceeds the Request ID." Draft-18 removed the field.
    #[error("required request id delta {1} is too large for request id {0}")]
    InvalidRequiredRequestIdDelta(u64, u64),
    /// A unidirectional stream announced a type its draft's stream table does
    /// not assign.
    ///
    /// Every draft from 07 to 20 requires the session to end for this, in one
    /// of two phrasings. Draft-07 and drafts 17 through 19 say "An endpoint
    /// that receives an unknown stream type MUST close the session"; drafts 08
    /// through 16 fold the streams and the datagrams into one sentence, "an
    /// unknown stream or datagram type", whose second half is
    /// [`CodecError::UnknownDatagramType`]. No draft in the range is silent,
    /// and neither phrasing is a hint that the other draft's rule is weaker.
    ///
    /// What the tables assign moves across the range, so the set this reports
    /// on is per-draft rather than shared. Draft-07 has a single table covering
    /// streams and datagrams together, which is why an OBJECT_DATAGRAM type at
    /// the head of a draft-07 stream is *not* unknown; drafts 08 onward split
    /// them into two tables with independent numbering; drafts 17 through 19
    /// add SETUP, and drafts 18 and 19 add PADDING, both of which are assigned
    /// stream types that a subgroup reader must refuse without reporting this.
    ///
    /// A stream announcing an assigned type this reader cannot read is not this
    /// error: the value is one the draft defines, and the disagreement is with
    /// the caller rather than with the draft. Those stay
    /// [`CodecError::InvalidField`]. The distinction is the whole point of the
    /// variant — reporting an assigned type as unknown closes sessions over
    /// streams the draft permits, which is the more costly way to be wrong.
    #[error("stream type {0} is not one this draft assigns")]
    UnknownStreamType(u64),
    /// A datagram announced a type its draft's datagram table does not assign.
    ///
    /// The datagram half of the rule above, and stated by all fourteen drafts
    /// for the same reason: drafts 08 through 16 name streams and datagrams in
    /// one sentence, and drafts 17, 18 and 19 give the datagrams their own —
    /// "An endpoint that receives an unknown datagram type MUST close the
    /// session." Draft-07 alone numbers its datagrams in the stream table, so
    /// its datagram types are reported by [`CodecError::UnknownStreamType`] and
    /// this variant is never produced there.
    ///
    /// Separate from the stream variant because the two number spaces are
    /// separate from draft-08 on: 0x05 is FETCH_HEADER on a stream and an
    /// assigned OBJECT_DATAGRAM form in several drafts' datagram tables, so a
    /// single variant could not say which table had been consulted.
    #[error("datagram type {0} is not one this draft assigns")]
    UnknownDatagramType(u64),
    /// A Type value inside the form its draft defines, but one the draft
    /// separately names as invalid.
    ///
    /// Distinct from the two variants above, which report a value no table
    /// assigns. Drafts 16 through 19 describe their subgroup and datagram Types
    /// as bit fields rather than as a list of code points, and then rule out
    /// particular bit combinations *within* the form — a subgroup Type whose
    /// SUBGROUP_ID_MODE holds the reserved value, or a datagram Type asking to
    /// be both an object status and an end-of-group marker. The enclosing form
    /// is assigned, so calling these unknown would misname them; the drafts
    /// call them invalid and require a close with PROTOCOL_VIOLATION.
    ///
    /// `detail` names which combination was seen, because the rule is a list
    /// rather than a single condition and a log that says only "invalid" leaves
    /// the reader to re-derive the bits.
    #[error("type {raw:#x} is one this draft names as invalid: {detail}")]
    InvalidTypeValue {
        /// The Type value as it arrived, before any narrowing to a byte.
        raw: u64,
        /// Which of the draft's lists it fell into.
        detail: &'static str,
    },
    /// A ContentExists field carried a value other than zero or one.
    ///
    /// Drafts 07 through 13 all state it in the same words: "Content Exists: 1
    /// if an object has been published on this track, 0 if not. If 0, then the
    /// Largest Group ID and Largest Object ID fields will not be present. Any
    /// other value is a protocol error and MUST terminate the session with a
    /// Protocol Violation". Draft-14 states the same sentence with the code
    /// spelled PROTOCOL_VIOLATION. Draft-07 states it for SUBSCRIBE_OK
    /// in Section 6.15 and SUBSCRIBE_DONE in Section 6.19; drafts 08 through 11
    /// keep the SUBSCRIBE_OK site alone; drafts 12, 13 and 14 add PUBLISH.
    /// Draft-15 removed the field, replacing it with the presence or absence of
    /// a LARGEST_OBJECT parameter, so no draft from 15 on has one.
    ///
    /// The field is a single byte and it decides whether two more follow, so a
    /// value that is neither leaves a reader with no way to know where the
    /// message ends.
    #[error("content exists field carries {0}, which is neither zero nor one")]
    InvalidContentExists(u8),
    /// A control message's declared Length disagrees with the fields it
    /// carries.
    ///
    /// All fourteen drafts state it in the same paragraph that gives the
    /// message type registry, and only the code changes: drafts 07 through 10
    /// say "If the length does not match the length of the message content, the
    /// receiver MUST close the session", naming no code; drafts 11 through 18
    /// name the Message Payload and answer with PROTOCOL_VIOLATION; draft-19
    /// renames the field to Message Body and keeps the code.
    ///
    /// Both directions are the same rule and both are reported here. Fields that
    /// stop short leave bytes unread — a trailing field the sender wrote and
    /// this reader does not know about, or one it read at the wrong width.
    /// Fields that run past the end wanted more bytes than the Length allowed,
    /// which is the same disagreement seen from the other side.
    /// The second case is why this cannot be left as
    /// [`CodecError::UnexpectedEnd`]. That variant means *the message is still
    /// arriving* everywhere else, and a reader loops on it rather than closing;
    /// inside a buffer already bounded by the declared Length there is nothing
    /// left to arrive, so running out there means something else entirely.
    ///
    /// Distinct from [`CodecError::InvalidField`], which is too coarse for the
    /// leftover-bytes case: a caller could not tell it from a dozen unrelated
    /// malformations, so a session could not be closed over it.
    #[error("control message declares {declared} bytes of payload; {detail}")]
    ControlMessageLengthMismatch {
        /// The Length field the sender wrote.
        declared: usize,
        /// Which way the two disagreed, in words, because the useful number is
        /// different in each direction and neither is knowable in the other.
        detail: &'static str,
    },
    /// Reason phrase exceeds [`MAX_REASON_PHRASE_LENGTH`].
    #[error("reason phrase exceeds {MAX_REASON_PHRASE_LENGTH} bytes")]
    ReasonPhraseTooLong,
    /// GOAWAY URI exceeds [`MAX_GOAWAY_URI_LENGTH`].
    #[error("GOAWAY URI exceeds {MAX_GOAWAY_URI_LENGTH} bytes")]
    GoAwayUriTooLong,
    /// Draft not implemented or not enabled via feature flag.
    #[error("unsupported draft: {0}")]
    UnsupportedDraft(String),
}

impl CodecError {
    /// Whether more bytes might complete this decode.
    ///
    /// A reader that owns a growing buffer asks this to tell *the input has
    /// not all arrived* from *the input is wrong*: `true` means fill the
    /// buffer and decode again, `false` means the bytes are what they are and
    /// no amount of waiting improves them.
    ///
    /// # Why this is a predicate and not a variant test
    ///
    /// Running out of bytes has four spellings here, because a decode can run
    /// out inside a nested decoder that reports in its own error type and each
    /// one names the condition after itself:
    ///
    /// * [`CodecError::UnexpectedEnd`], from a field this module read;
    /// * [`CodecError::VarInt`] carrying [`VarIntError::UnexpectedEnd`], from a
    ///   varint whose length prefix promised bytes the buffer did not hold;
    /// * [`CodecError::Kvp`] carrying [`KvpError::UnexpectedEnd`], and
    /// * the same wrapped one level deeper as
    ///   [`KvpError::VarInt`]`(`[`VarIntError::UnexpectedEnd`]`)`, from a
    ///   key-value pair that ran out in its length or in its value.
    ///
    /// All four mean the same thing to a caller and only the first announces
    /// it in the variant name. That is not a hypothetical: a reader matching
    /// the first alone treated a subgroup object whose leading varint had not
    /// arrived yet as a malformed stream, and reported `insufficient bytes for
    /// varint decoding` for an object that was merely still in flight. The
    /// condition is one fact about a buffer, so it is answered in one place
    /// rather than re-derived by every reader that has to know it.
    ///
    /// # What is deliberately not here
    ///
    /// [`CodecError::ControlMessageLengthMismatch`] is the case that looks
    /// like this one and is its opposite, and its own documentation says why:
    /// inside a buffer already bounded by a declared Length there is nothing
    /// left to arrive, so running out there is a malformation and waiting for
    /// more would be waiting forever.
    ///
    /// [`VarIntError::UnexpectedEnd`]: crate::varint::VarIntError::UnexpectedEnd
    /// [`KvpError::UnexpectedEnd`]: crate::kvp::KvpError::UnexpectedEnd
    /// [`KvpError::VarInt`]: crate::kvp::KvpError::VarInt
    pub fn is_incomplete(&self) -> bool {
        use crate::kvp::KvpError;
        use crate::varint::VarIntError;
        matches!(
            self,
            CodecError::UnexpectedEnd
                | CodecError::VarInt(VarIntError::UnexpectedEnd)
                | CodecError::Kvp(KvpError::UnexpectedEnd)
                | CodecError::Kvp(KvpError::VarInt(VarIntError::UnexpectedEnd))
        )
    }
}

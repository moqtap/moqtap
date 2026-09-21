use crate::varint::{MoqtProfile, VarInt};
use bytes::{Buf, BufMut};

/// Reserve space for `count` items without trusting `count`.
///
/// A count-prefixed list declares how many items follow, and the declaration
/// arrives before any of them. Passing it straight to [`Vec::with_capacity`]
/// hands an unauthenticated peer control of one allocation: a varint holds
/// values up to 2^62-1, and asking for that many elements aborts the process
/// with `capacity overflow` before a single item has been read. On a control
/// stream the first message is a peer's SETUP, so this is reachable before
/// anything has been negotiated or authenticated.
///
/// Every item in these lists occupies at least one byte on the wire, so the
/// bytes still in `buf` are a true upper bound on how many can really follow.
/// A well-formed message is unaffected — its count is far below its length —
/// and a malformed one allocates no more than it actually sent.
///
/// This bounds the allocation only. The decode loop still fails on the first
/// item that is not there, which is what turns an over-long count into an
/// error rather than a short read.
#[inline]
pub fn reserve_bounded<T>(count: usize, buf: &impl Buf) -> Vec<T> {
    Vec::with_capacity(count.min(buf.remaining()))
}

/// Read exactly `len` bytes from `buf`, returning them as a `Vec<u8>`.
#[inline]
#[allow(clippy::uninit_vec)]
pub fn read_bytes(buf: &mut impl Buf, len: usize) -> Result<Vec<u8>, crate::error::CodecError> {
    if buf.remaining() < len {
        return Err(crate::error::CodecError::UnexpectedEnd);
    }
    let mut v = Vec::with_capacity(len);
    // Safety: `set_len(len)` with capacity `len` exposes `len` uninitialized
    // `u8`s. `copy_to_slice` immediately overwrites all of them before any
    // read. `u8` has no drop, so no leaks on panic beyond the `Vec` itself.
    unsafe {
        v.set_len(len);
    }
    buf.copy_to_slice(&mut v);
    Ok(v)
}

/// Refuse a range whose end is earlier than its start, where the End Group is
/// the last Group ID and the End Object is the last Object ID plus one.
///
/// This is the shape FETCH carries on every draft: the End Group field is "the
/// end Group ID" and the End Object field is "The end Object ID, plus 1. A
/// value of 0 means the entire group is requested." A zero End Object therefore
/// places no upper bound inside the end group and cannot make the range empty,
/// so it is exempt.
///
/// Draft-07 Section 6.4 gives the SUBSCRIBE AbsoluteRange filter the same two
/// fields with the same conventions, and states the rule in the same words, so
/// that filter is checked here too.
///
/// # Errors
///
/// [`crate::error::CodecError::InvalidRange`] if the end is earlier than the
/// start, reporting both ends as they appear on the wire.
pub fn check_location_range(
    start_group: u64,
    start_object: u64,
    end_group: u64,
    end_object: u64,
) -> Result<(), crate::error::CodecError> {
    let ends_early = end_group < start_group
        || (end_group == start_group && end_object != 0 && end_object <= start_object);
    if ends_early {
        return Err(crate::error::CodecError::InvalidRange(
            start_group,
            start_object,
            end_group,
            end_object,
        ));
    }
    Ok(())
}

/// Refuse a subscription whose End Group is earlier than its start group, where
/// the End Group is inclusive and always present.
///
/// Drafts 08 through 14 describe the SUBSCRIBE AbsoluteRange field as "the end
/// Group ID, inclusive. Only present for the 'AbsoluteRange' filter type", so
/// there is no value that means "no end" and nothing to exempt. The rule is
/// Section 7.4 through Section 9.7: "End Group MUST specify the same or a
/// larger Group than specified in Start."
///
/// Only the groups are compared. Those drafts have no End Object on SUBSCRIBE,
/// so an end group equal to the start group is the whole of that group and is
/// what the draft calls out as legal: "If the specified End Group is the same
/// group specified in Start, the remainder of that Group passes the filter."
///
/// # Errors
///
/// [`crate::error::CodecError::InvalidRange`] if the end group is smaller than
/// the start group.
pub fn check_group_range(start_group: u64, end_group: u64) -> Result<(), crate::error::CodecError> {
    if end_group < start_group {
        return Err(crate::error::CodecError::InvalidRange(start_group, 0, end_group, 0));
    }
    Ok(())
}

/// Refuse a SUBSCRIBE_UPDATE whose End Group is earlier than its start group.
///
/// SUBSCRIBE_UPDATE spells the field differently from SUBSCRIBE on every draft
/// that has both: "End Group: The end Group ID, plus 1. A value of 0 means the
/// subscription is open-ended." A zero is an open end and places no bound at
/// all, so it is exempt.
///
/// The comparison is deliberately the literal one the draft states - "Like
/// SUBSCRIBE, End Group MUST be greater than or equal to the Group specified in
/// Start" - against the field as it arrives, without first undoing the plus
/// one. Undoing it would make an End Group equal to the start group a refusal,
/// and the draft's sentence does not say that, so a frame the draft may permit
/// would be refused on a reading rather than on a rule.
///
/// # Errors
///
/// [`crate::error::CodecError::InvalidRange`] if a non-zero end group is
/// smaller than the start group.
pub fn check_open_ended_group_range(
    start_group: u64,
    end_group: u64,
) -> Result<(), crate::error::CodecError> {
    if end_group != 0 && end_group < start_group {
        return Err(crate::error::CodecError::InvalidRange(start_group, 0, end_group, 0));
    }
    Ok(())
}

/// Track Namespace: an ordered set of Track Namespace Fields.
///
/// The permitted field count is not the same on every draft, so this type does
/// not carry one. Section 2.4.1 "Track Naming" calls a Track Namespace "an
/// ordered N-tuple of bytes where N can be between 1 and 32" on drafts 07
/// through 14, "an ordered set of between 1 and 32 Track Namespace Fields" on
/// drafts 15 and 16, and "an ordered set of between 0 and 32 Track Namespace
/// Fields" from draft-17 on. [`TrackNamespaceRules`] carries that answer per
/// draft, along with the two rules Section 2.4.1 later adds about what a single
/// field may contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackNamespace(pub Vec<Vec<u8>>);

/// What a MoQ Transport draft states about a Track Namespace in Section 2.4.1
/// "Track Naming".
///
/// The rules arrive at different drafts and one of them is later withdrawn, so
/// any single rule applied to all the drafts is wrong somewhere:
///
/// - *At most 32 Track Namespace Fields.* Stated by every draft from 07 on, and
///   the only field-count rule drafts 17 and later state at all. It has never
///   moved, so it is not carried here; [`MAX_NAMESPACE_TUPLE_SIZE`] holds it and
///   every reader applies it.
///
/// - *At least one Track Namespace Field.* Drafts 07 through 16 define a Track
///   Namespace as "between 1 and 32", and drafts 08 through 16 add "If an
///   endpoint receives a Track Namespace tuple with an N of 0 or more than 32,
///   it MUST close the session with a Protocol Violation" (draft-15 and later
///   word it as "consisting of 0 or greater than 32 Track Namespace Fields").
///   Draft-17 redefines the type as "between 0 and 32" and drops that half of
///   the sentence.
///
///   An individual message may lower the minimum below what Section 2.4.1 says.
///   Draft-16 is the first to describe the SUBSCRIBE_NAMESPACE Track Namespace
///   Prefix as "a Track Namespace structure as described in Section 2.4.1 with
///   between 0 and 32 Track Namespace Fields", and it drops the sentence that
///   drafts 08 through 15 carry about a prefix of 0 fields closing the session.
///   [`min_fields`](Self::min_fields) is therefore a value a call site can
///   lower, not a function of the draft alone.
///
/// - *Each field at least one byte.* Draft-16 is the first to say "Each Track
///   Namespace Field Value MUST contain at least one byte. If an endpoint
///   receives a Track Namespace Field with a Track Namespace Field Length of 0,
///   it MUST close the session with a PROTOCOL_VIOLATION." Drafts 07 through 15
///   say nothing about it, and refusing an empty field there would reject
///   traffic those drafts permit.
///
/// - *A Track Namespace of at most 4,096 bytes.* Draft-16 is the first to say
///   "The length of a Track Namespace is the sum of the Track Namespace Field
///   Length fields... If an endpoint receives a Track Namespace or a Full Track
///   Name exceeding 4,096 bytes, it MUST close the session with a
///   PROTOCOL_VIOLATION." Drafts 11 through 15 cap only the Full Track Name, so
///   on those a namespace is bounded only through the Track Name beside it and
///   this reader cannot settle it alone. Drafts 07 through 10 state no cap.
///
/// [`MAX_NAMESPACE_TUPLE_SIZE`]: crate::error::MAX_NAMESPACE_TUPLE_SIZE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackNamespaceRules {
    /// Fewest Track Namespace Fields this position accepts.
    pub min_fields: usize,
    /// Whether a Track Namespace Field Length of 0 must be refused.
    pub reject_empty_field: bool,
    /// Cap on the sum of the Track Namespace Field Length fields, for the drafts
    /// that bound a Track Namespace on its own.
    ///
    /// `None` where the draft bounds only the Full Track Name, which no reader
    /// of the namespace alone can settle: the Track Name arrives beside it in
    /// the message, and the two lengths are summed there.
    pub max_namespace_bytes: Option<usize>,
}

impl TrackNamespaceRules {
    /// The rules MoQ Transport draft `draft` states for a Track Namespace.
    ///
    /// `draft` is the draft number, 7 through 19. A larger number is answered
    /// with the newest rules, which have not moved since draft-17.
    ///
    /// This is the Section 2.4.1 answer, which is what a position accepts unless
    /// the message that carries it says otherwise. A message that is looser
    /// about the count — draft-16's SUBSCRIBE_NAMESPACE prefix is — overrides
    /// [`min_fields`](Self::min_fields) on the value returned here, so that the
    /// content rules it does not restate still come from its own draft.
    pub const fn for_draft(draft: u8) -> Self {
        TrackNamespaceRules {
            min_fields: if draft >= 17 { 0 } else { 1 },
            reject_empty_field: draft >= 16,
            max_namespace_bytes: if draft >= 16 {
                Some(crate::error::MAX_FULL_TRACK_NAME_LENGTH)
            } else {
                None
            },
        }
    }
}

/// Full Track Name: a Track Namespace and the Track Name within it.
///
/// Drafts 11 and later cap the pair: "The maximum total length of a Full Track
/// Name is 4,096 bytes... computed as the sum of the Track Namespace Field
/// Length fields and the Track Name Length field." Drafts 07 through 10 state no
/// cap. That sum spans two fields that arrive separately, so it is settled where
/// a message decodes both, with [`TrackNamespace::field_bytes_len`] supplying
/// the namespace half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTrackName {
    /// The track namespace tuple.
    pub namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
}

/// Location within a track: (Group, Object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    /// Group identifier.
    pub group: VarInt,
    /// Object identifier within the group.
    pub object: VarInt,
}

/// Object status values, from MoQ Transport draft-14 Section 10.2.1.1
/// "Object Status".
///
/// The draft assigns 0x0, 0x1, 0x3 and 0x4; 0x2 is unassigned and
/// [`ObjectStatus::from_u8`] answers `None` for it. Each `draftNN` module
/// carries its own `ObjectStatus`, because the assigned set moves between
/// drafts: drafts 08 through 10 also assign 0x5, and drafts 16 onward drop 0x1
/// and assign only 0x0, 0x3 and 0x4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Object payload follows normally.
    Normal = 0x0,
    /// The referenced object does not exist at any publisher and will not be
    /// published in the future.
    DoesNotExist = 0x1,
    /// Last object in the group.
    EndOfGroup = 0x3,
    /// Last object in the track.
    EndOfTrack = 0x4,
}

/// Group ordering preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupOrder {
    /// Publisher determines the order.
    Publisher = 0x0,
    /// Groups delivered in ascending order.
    Ascending = 0x1,
    /// Groups delivered in descending order.
    Descending = 0x2,
}

/// Forwarding preference for objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ForwardingPreference {
    /// Object forwarding (sent on a subgroup stream).
    Object = 0x0,
    /// Datagram forwarding (sent as a QUIC datagram).
    Datagram = 0x1,
}

/// Whether content exists (used in SUBSCRIBE_OK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentExists {
    /// No largest location is provided.
    NoLargestLocation = 0,
    /// A largest location follows.
    HasLargestLocation = 1,
}

/// Forward state (0 = don't forward, 1 = forward).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Forward {
    /// Do not forward.
    DontForward = 0,
    /// Forward enabled.
    Forward = 1,
}

/// Subscription filter types, named as draft-14 names them.
///
/// Every draft that has this field assigns the same four numbers, but 0x1 does
/// not mean the same thing on all of them, and the variant here carries the
/// later meaning. Drafts 07 and 08 call 0x1 "Latest Group": an open-ended
/// subscription starting at the beginning of the *current* group. Drafts 09 and
/// 10 withdraw the value, and their decoders refuse it. Drafts 11 and later
/// call it "Next Group Start", which begins one group later. A caller reading
/// [`FilterType::NextGroupStart`] off a draft-07 or draft-08 SUBSCRIBE has the
/// right number and the wrong name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FilterType {
    /// Start from the next group on drafts 11 and later; the beginning of the
    /// current group on drafts 07 and 08, which call the same value "Latest
    /// Group". Not assigned on drafts 09 and 10.
    NextGroupStart = 0x1,
    /// Start from the largest available object.
    LargestObject = 0x2,
    /// Start from an absolute location.
    AbsoluteStart = 0x3,
    /// Absolute range with start and end locations.
    AbsoluteRange = 0x4,
}

/// Authorization token alias types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenAliasType {
    /// Delete a previously registered alias.
    Delete = 0x0,
    /// Register a new alias.
    Register = 0x1,
    /// Use an existing alias.
    UseAlias = 0x2,
    /// Use a literal token value.
    UseValue = 0x3,
}

impl TrackNamespace {
    /// Encode the namespace tuple into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.0.len()).encode(buf);
        for elem in &self.0 {
            VarInt::from_usize(elem.len()).encode(buf);
            buf.put_slice(elem);
        }
    }

    /// Decode a namespace tuple under the rules every draft from 07 through 16
    /// shares.
    ///
    /// All ten of those drafts define a Track Namespace as "between 1 and 32"
    /// fields, so the count is held to that and nothing else is. This one reader
    /// serves all of them and cannot tell them apart, while the empty-field rule
    /// and the 4,096-byte namespace cap both arrive in draft-16: applying either
    /// here would refuse namespaces drafts 07 through 15 permit. A call site that
    /// knows which draft it is decoding reaches those rules through
    /// [`decode_rules`](Self::decode_rules) with
    /// [`TrackNamespaceRules::for_draft`].
    ///
    /// Drafts 17 and later read namespaces through
    /// [`decode_moqt`](Self::decode_moqt), which uses the other varint encoding.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        Self::decode_rules(
            buf,
            TrackNamespaceRules {
                min_fields: 1,
                reject_empty_field: false,
                max_namespace_bytes: None,
            },
        )
    }

    /// Decode a draft-16 Track Namespace that may have zero fields.
    ///
    /// Draft-16 is the only draft before 17 with a namespace position that
    /// permits the empty set. Its NAMESPACE and NAMESPACE_DONE carry "only the
    /// namespace tuples after the 'Track Namespace Prefix'", which is nothing at
    /// all once the prefix names the whole namespace, and its
    /// SUBSCRIBE_NAMESPACE describes the prefix as "between 0 and 32 Track
    /// Namespace Fields". Drafts 07 through 15 put the minimum at one field
    /// everywhere, drafts 08 through 15 spelling out that zero closes the
    /// session, so none of them has any use for this reader.
    ///
    /// Because draft-16 is its only draft, the fields are held to both rules
    /// draft-16 Section 2.4.1 states about their contents: no field of length
    /// zero, and at most 4,096 bytes summed across the fields. A namespace being
    /// read for an earlier draft belongs in [`decode`](Self::decode), which
    /// states neither.
    pub fn decode_allow_empty(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        Self::decode_rules(
            buf,
            TrackNamespaceRules { min_fields: 0, ..TrackNamespaceRules::for_draft(16) },
        )
    }

    /// Decode a namespace tuple, holding it to `rules`.
    ///
    /// The reader for drafts 07 through 16, which write both the field count and
    /// every field length as a QUIC variable-length integer (RFC 9000 Section
    /// 16). Drafts 17 and later changed that encoding and read namespaces
    /// through [`decode_moqt`](Self::decode_moqt) instead.
    ///
    /// The upper bound on the field count is not part of `rules`: every draft
    /// from 07 on puts it at 32 and none has moved it, so it is applied here
    /// unconditionally. The byte cap is applied to the running sum as the field
    /// lengths are read, so a namespace that overruns is refused before its
    /// remaining fields are allocated.
    pub fn decode_rules(
        buf: &mut impl Buf,
        rules: TrackNamespaceRules,
    ) -> Result<Self, crate::error::CodecError> {
        let n = VarInt::decode(buf)?.into_inner() as usize;
        if n < rules.min_fields || n > crate::error::MAX_NAMESPACE_TUPLE_SIZE {
            return Err(crate::error::CodecError::InvalidNamespaceTupleSize(n));
        }
        let mut elements = Vec::with_capacity(n);
        let mut total = 0usize;
        for _ in 0..n {
            let len = VarInt::decode(buf)?.into_inner() as usize;
            if len == 0 && rules.reject_empty_field {
                return Err(crate::error::CodecError::EmptyNamespaceField);
            }
            total = total.saturating_add(len);
            if let Some(max) = rules.max_namespace_bytes {
                if total > max {
                    return Err(crate::error::CodecError::TrackNameTooLong);
                }
            }
            elements.push(read_bytes(buf, len)?);
        }
        Ok(TrackNamespace(elements))
    }

    /// Encode the namespace tuple using the MoQT varint (drafts 17 and later).
    pub fn encode_moqt<P: MoqtProfile>(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.0.len()).encode_moqt::<P>(buf);
        for elem in &self.0 {
            VarInt::from_usize(elem.len()).encode_moqt::<P>(buf);
            buf.put_slice(elem);
        }
    }

    /// Decode a namespace tuple using the MoQT varint (drafts 17 and later).
    ///
    /// A field count of zero is accepted. Drafts 17, 18 and 19 all define a
    /// Track Namespace as "an ordered set of between 0 and 32 Track Namespace
    /// Fields", and state only one field-count violation: "If an endpoint
    /// receives a Track Namespace consisting of greater than 32 Track Namespace
    /// Fields, it MUST close the session with a PROTOCOL_VIOLATION." Draft-16
    /// Section 2.4.1 says "between 1 and 32" instead, which is why the pre-17
    /// [`decode`](Self::decode) still refuses an empty tuple and this does not.
    ///
    /// Refusing the empty tuple here would also have made the codec emit frames
    /// it will not read: [`encode_moqt`](Self::encode_moqt) writes a zero field
    /// count without complaint, so the two directions disagreed about a shape
    /// the draft permits.
    ///
    /// This leaves [`decode_moqt`](Self::decode_moqt) and
    /// [`decode_allow_empty_moqt`](Self::decode_allow_empty_moqt) accepting the
    /// same field counts on drafts 17 and later. Both are kept because the
    /// distinction is still real one draft earlier, where [`decode`](Self::decode)
    /// and [`decode_allow_empty`](Self::decode_allow_empty) part company over it,
    /// and because a call site naming the one it means says which rule it is
    /// relying on.
    pub fn decode_moqt<P: MoqtProfile>(
        buf: &mut impl Buf,
    ) -> Result<Self, crate::error::CodecError> {
        Self::decode_allow_empty_moqt::<P>(buf)
    }

    /// Decode a MoQT namespace tuple that may have zero elements (suffix types).
    pub fn decode_allow_empty_moqt<P: MoqtProfile>(
        buf: &mut impl Buf,
    ) -> Result<Self, crate::error::CodecError> {
        let n = VarInt::decode_moqt::<P>(buf)?.into_inner() as usize;
        if n > crate::error::MAX_NAMESPACE_TUPLE_SIZE {
            return Err(crate::error::CodecError::InvalidNamespaceTupleSize(n));
        }
        Self::decode_elements_moqt::<P>(buf, n)
    }

    /// Read `n` Track Namespace Fields, holding them to the two rules Section
    /// 2.4.1 states about their contents.
    ///
    /// "Each Track Namespace Field Value MUST contain at least one byte. If an
    /// endpoint receives a Track Namespace Field with a Track Namespace Field
    /// Length of 0, it MUST close the session with a PROTOCOL_VIOLATION." An
    /// empty field is not the same namespace as no field, but the two render
    /// identically and an empty field makes two distinct namespaces compare
    /// equal under the prefix-matching rules, which is a routing hazard at a
    /// relay.
    ///
    /// "The length of a Track Namespace is the sum of the Track Namespace Field
    /// Length fields... If an endpoint receives a Track Namespace or a Full
    /// Track Name exceeding 4,096 bytes, it MUST close the session with a
    /// PROTOCOL_VIOLATION." The sum is kept as the fields are read, so a
    /// namespace that overruns is refused before its remaining fields are
    /// allocated. The Full Track Name half of that sentence needs the Track
    /// Name, which lives in the message rather than here, and is checked where
    /// the two are decoded together.
    ///
    /// Drafts 07 through 16 read their fields through
    /// [`decode_rules`](Self::decode_rules), which applies whichever of these two
    /// rules the caller's draft states: draft-16 states both, and no draft before
    /// it states either.
    fn decode_elements_moqt<P: MoqtProfile>(
        buf: &mut impl Buf,
        n: usize,
    ) -> Result<Self, crate::error::CodecError> {
        let mut elements = Vec::with_capacity(n);
        let mut total = 0usize;
        for _ in 0..n {
            let len = VarInt::decode_moqt::<P>(buf)?.into_inner() as usize;
            if len == 0 {
                return Err(crate::error::CodecError::EmptyNamespaceField);
            }
            total = total.saturating_add(len);
            if total > crate::error::MAX_FULL_TRACK_NAME_LENGTH {
                return Err(crate::error::CodecError::TrackNameTooLong);
            }
            elements.push(read_bytes(buf, len)?);
        }
        Ok(TrackNamespace(elements))
    }

    /// The sum of this namespace's Track Namespace Field Length fields.
    ///
    /// Section 2.4.1 defines both caps in terms of this sum: a Track Namespace
    /// is capped at 4,096 bytes on its own, and a Full Track Name is capped at
    /// this plus the Track Name Length.
    pub fn field_bytes_len(&self) -> usize {
        self.0.iter().map(|field| field.len()).sum()
    }

    /// Hold this namespace to the rules drafts 17 and later state in Section
    /// 2.4.1, before it goes on the wire.
    ///
    /// The encode-side mirror of
    /// [`decode_allow_empty_moqt`](Self::decode_allow_empty_moqt): at most 32 fields,
    /// no empty field, and at most 4,096 bytes of field content. Without it the
    /// codec would emit namespaces its own decoder refuses, and hand a
    /// conforming peer a reason to close the session.
    pub fn validate_moqt(&self) -> Result<(), crate::error::CodecError> {
        self.validate(TrackNamespaceRules::for_draft(17))
    }

    /// Hold this namespace to `rules` before it goes on the wire.
    ///
    /// The encode-side mirror of [`decode_rules`](Self::decode_rules), taking
    /// the same description of what a draft permits so that the two directions
    /// cannot drift apart. A codec that writes what it will not read hands a
    /// conforming peer a reason to close the session, and finds out only when
    /// the peer does.
    ///
    /// The upper bound on the field count is not part of `rules` here either:
    /// every draft from 07 on puts it at 32.
    pub fn validate(&self, rules: TrackNamespaceRules) -> Result<(), crate::error::CodecError> {
        if self.0.len() < rules.min_fields || self.0.len() > crate::error::MAX_NAMESPACE_TUPLE_SIZE
        {
            return Err(crate::error::CodecError::InvalidNamespaceTupleSize(self.0.len()));
        }
        if rules.reject_empty_field && self.0.iter().any(|field| field.is_empty()) {
            return Err(crate::error::CodecError::EmptyNamespaceField);
        }
        if let Some(max) = rules.max_namespace_bytes {
            if self.field_bytes_len() > max {
                return Err(crate::error::CodecError::TrackNameTooLong);
            }
        }
        Ok(())
    }
}

impl Location {
    /// Encode the location (group, object) into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group.encode(buf);
        self.object.encode(buf);
    }

    /// Decode a location from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        let group = VarInt::decode(buf)?;
        let object = VarInt::decode(buf)?;
        Ok(Location { group, object })
    }

    /// Encode the location using the MoQT varint (drafts 17 and later).
    pub fn encode_moqt<P: MoqtProfile>(&self, buf: &mut impl BufMut) {
        self.group.encode_moqt::<P>(buf);
        self.object.encode_moqt::<P>(buf);
    }

    /// Decode a location using the MoQT varint (drafts 17 and later).
    pub fn decode_moqt<P: MoqtProfile>(
        buf: &mut impl Buf,
    ) -> Result<Self, crate::error::CodecError> {
        let group = VarInt::decode_moqt::<P>(buf)?;
        let object = VarInt::decode_moqt::<P>(buf)?;
        Ok(Location { group, object })
    }
}

impl ObjectStatus {
    /// Every status draft-14 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`ObjectStatus::from_u8`] accepts. Any other
    /// value is one the draft does not assign.
    pub const ALL: &[ObjectStatus] = &[
        ObjectStatus::Normal,
        ObjectStatus::DoesNotExist,
        ObjectStatus::EndOfGroup,
        ObjectStatus::EndOfTrack,
    ];

    /// Convert a raw byte to an `ObjectStatus`, or `None` if draft-14 does not
    /// assign that value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(ObjectStatus::Normal),
            0x1 => Some(ObjectStatus::DoesNotExist),
            0x3 => Some(ObjectStatus::EndOfGroup),
            0x4 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl GroupOrder {
    /// Convert a raw byte to a `GroupOrder`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(GroupOrder::Publisher),
            0x1 => Some(GroupOrder::Ascending),
            0x2 => Some(GroupOrder::Descending),
            _ => None,
        }
    }
}

impl ForwardingPreference {
    /// Convert a raw byte to a `ForwardingPreference`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(ForwardingPreference::Object),
            0x1 => Some(ForwardingPreference::Datagram),
            _ => None,
        }
    }
}

impl FilterType {
    /// Convert a raw byte to a `FilterType`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::from_u64(v as u64)
    }

    /// Convert a raw u64 to a `FilterType`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x1 => Some(FilterType::NextGroupStart),
            0x2 => Some(FilterType::LargestObject),
            0x3 => Some(FilterType::AbsoluteStart),
            0x4 => Some(FilterType::AbsoluteRange),
            _ => None,
        }
    }
}

//! Location filters and fill fetch streams, the two things draft-21 asks a
//! subscriber to build that no earlier draft has.
//!
//! Draft-20 moved the range of a FETCH out of the message and into the
//! `LOCATION_FILTER` message parameter (Section 9.20.10), and added
//! `FILL_PARAMETERS` (Section 9.20.16) — a parameter whose *presence* on a
//! SUBSCRIBE or a REQUEST_UPDATE asks the publisher to open a fill fetch
//! stream, and whose value is a nested parameter block that overrides the
//! subscription's own settings for that fill alone.
//!
//! Both are parameter values a caller has to construct byte by byte, which is
//! why they are here rather than left to the caller: the two encodings are the
//! places draft-21 is least explicit, and getting either wrong desynchronises
//! the whole parameter list rather than producing a recognisable error.
//!
//! # What this module decides, and where the draft is silent
//!
//! * A `LOCATION_FILTER`'s shape comes from **how many** `vi64` fields its
//!   value holds, not from the byte length. See [`LocationFilter`].
//! * A `FILL_PARAMETERS` value **begins with a `Number of Parameters`
//!   count**, and its `Type Delta` chain restarts at 0. See
//!   [`FillParameters`].
//! * A fill fetch stream with no `GROUP_ORDER` anywhere is read **Ascending**.
//!   See [`group_order`].
//!
//! Every value this module builds is handed to the codec's own decoder before
//! it is returned, so a disagreement between the two is an error here rather
//! than a frame on the wire.
//!
//! # Ranges are inclusive
//!
//! Draft-19's fetch end was "the last Object, plus 1; or 0 to indicate the
//! entire Group". Draft-21 Sections 3.3.1 and 9.11 both say the Location
//! filter "specifies an inclusive range of Locations", and both draft-19
//! conventions are gone. **Nothing in this module adds or subtracts one from
//! an end location**, and a caller porting draft-19 arithmetic forward fetches
//! one object too many.

use moqtap_codec::draft21::data_stream::GroupOrder;
use moqtap_codec::draft21::message::{
    decode_fill_parameters, decode_location_filter, FILL_PARAMETERS, LOCATION_FILTER,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::{Moqt18 as Wire, VarInt};

/// `GROUP_ORDER`, Parameter Type 0x22 (Section 9.20.9).
///
/// Spelled here rather than imported because the codec's draft-21 message
/// module does not export it, and because this module needs the same number in
/// three places: Table 6's allow-list, the uint8 shape test, and [`group_order`].
pub const GROUP_ORDER: u64 = 0x22;

/// The `GROUP_ORDER` value Section 9.20.9 assigns to Ascending.
const GROUP_ORDER_ASCENDING: u64 = 0x1;

/// The `GROUP_ORDER` value Section 9.20.9 assigns to Descending.
const GROUP_ORDER_DESCENDING: u64 = 0x2;

/// Errors from building a `LOCATION_FILTER` or a `FILL_PARAMETERS` value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FillError {
    /// `StartGroup + EndGroupDelta` left the number space.
    ///
    /// Section 9.20.10: "If StartGroup + EndGroupDelta exceeds 2^64 - 1, the
    /// endpoint MUST close the session with a PROTOCOL_VIOLATION." A value the
    /// peer must close the session over is not a value this endpoint has a way
    /// of sending, so it is refused here instead.
    #[error("start group {start_group} plus end group delta {delta} exceeds 2^64 - 1")]
    EndGroupOverflow {
        /// The start group the filter named.
        start_group: u64,
        /// The delta added to it.
        delta: u64,
    },
    /// A parameter type Table 6 does not list was put inside `FILL_PARAMETERS`.
    ///
    /// Section 9.20.16: "An endpoint that receives a parameter inside
    /// FILL_PARAMETERS that is not listed above MUST close the session with
    /// PROTOCOL_VIOLATION."
    #[error("parameter type {0:#x} may not appear inside FILL_PARAMETERS")]
    NotAFillParameter(u64),
    /// The same parameter type was put inside `FILL_PARAMETERS` twice where its
    /// own definition does not allow repeats.
    #[error("parameter type {0:#x} appears twice inside FILL_PARAMETERS")]
    RepeatedFillParameter(u64),
    /// A value whose shape does not match the type it was filed under.
    #[error(
        "the value under parameter type {key:#x} is not the shape that type defines: {detail}"
    )]
    MalformedValue {
        /// The parameter type.
        key: u64,
        /// What is wrong with the value.
        detail: &'static str,
    },
    /// The value this module built is one the codec's own decoder refuses.
    ///
    /// Unreachable unless the encoder here and the decoder in
    /// `moqtap-codec` have drifted apart, which is what the check exists to
    /// catch: a value that goes out and comes back as a session close is worse
    /// than one that never goes out.
    #[error("the encoded value does not decode: {0}")]
    NotRoundTrippable(String),
}

/// The parameter types draft-21 Section 9.20.16, Table 6 permits inside a
/// `FILL_PARAMETERS` value, in ascending order.
///
/// `TRACK_PROPERTY_FILTER` (0x29) is deliberately absent: it selects tracks,
/// and a fill applies to one already-selected track. The same list is enforced
/// on the decode side by `moqtap_codec::draft21::message::decode_fill_parameters`,
/// which is what the round-trip check at the end of
/// [`FillParameters::parameter`] leans on.
const FILL_PARAMETERS_ALLOWED: &[u64] = &[0x0A, 0x20, 0x21, 0x22, 0x25, 0x26, 0x27, 0x28];

/// The five Range Filters, of which four may be nested. Only these may repeat.
///
/// Section 3.3.2 lets the Range Filters "appear multiple times", and Section
/// 9.20 forbids a repeat of anything else. A repeat is encoded as a `Type
/// Delta` of 0, which is the only encoding a second instance of an ascending
/// chain has.
fn may_repeat(key: u64) -> bool {
    (0x25..=0x29).contains(&key)
}

/// Whether a Table 6 parameter's value is a single raw byte rather than a
/// varint or a length-prefixed block.
///
/// `SUBSCRIBER_PRIORITY` (0x20, Section 9.20.8) and `GROUP_ORDER` (0x22,
/// Section 9.20.9) are the two uint8s that may be nested.
fn is_uint8(key: u64) -> bool {
    key == 0x20 || key == GROUP_ORDER
}

/// Whether a Table 6 parameter's value carries its own length prefix.
///
/// `LOCATION_FILTER` (0x21) and the four nestable Range Filters (0x25 through
/// 0x28). `FILL_TIMEOUT` (0x0A) is the only bare varint in the table.
fn is_length_prefixed(key: u64) -> bool {
    key == LOCATION_FILTER || (0x25..=0x28).contains(&key)
}

/// A draft-21 `LOCATION_FILTER` (Parameter Type 0x21), Section 9.20.10.
///
/// ```text
/// LOCATION_FILTER Parameter {
///   Parameter Type (vi64) = 0x21,
///   Length (vi64),
///   [StartGroup (vi64),]
///   [StartObject (vi64),]
///   [EndGroupDelta (vi64),]
///   [EndObject (vi64),]
/// }
/// ```
///
/// # The shape is the field count
///
/// Draft-19's filter opened with a `Filter Type` enum — Next Group Start,
/// Largest Object, AbsoluteStart, AbsoluteRange — and draft-20 deleted it. What
/// selects the shape now is how many `vi64` fields the value holds, and the
/// draft phrases that as "Length (in bytes) determines how many optional vi64
/// fields are present". That is not implementable as written: MoQT varints are
/// one to nine bytes and Section 8.1 permits non-minimal encodings, so a
/// `Length` of 2 fits two one-byte fields as readily as one two-byte field.
/// **This module always emits minimal varints, so the byte length and the field
/// count agree for everything it produces**, and the codec's decoder counts
/// fields rather than bytes. The two agree on every value built here; they part
/// only on a non-minimally-encoded value from a peer, which is the decoder's
/// problem and not this one's.
///
/// Each constructor names one row of the Section 9.20.10 table, so a caller
/// cannot build a shape the draft does not define, and cannot build a
/// three-field filter by leaving a field out of a four-field one.
///
/// # Migrating a draft-19 filter
///
/// Filter Type 0x1 (Next Group Start) becomes [`LocationFilter::relative`]
/// with `0`. Filter Type 0x2 (Largest Object) becomes
/// [`LocationFilter::next_object`]. Filter Types 0x3 and 0x4 become
/// [`LocationFilter::absolute_start`] and [`LocationFilter::range`]. The
/// one-field relative form has no draft-19 analogue outside the deleted
/// Relative Joining Fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationFilter {
    fields: Vec<u64>,
}

impl LocationFilter {
    /// No filter at all: `Length = 0`, no fields.
    ///
    /// Section 9.20.10 gives this one job beyond meaning "unfiltered": in a
    /// REQUEST_UPDATE it *removes* a filter already in force. It is the one
    /// shape whose meaning depends on the message carrying it.
    pub fn none() -> Self {
        Self { fields: Vec::new() }
    }

    /// One field: a start relative to the live edge.
    ///
    /// Section 9.20.10: Start is `{Largest Object.Group + 1 - StartGroup, 0}`, so
    /// `0` is the next group, `1` the current group, and `N` is `N - 1` groups
    /// before the current one. Clamped at both ends of the number space by the
    /// publisher rather than here, because resolving it needs Largest Object.
    /// Open-ended: there is no end.
    pub fn relative(start_group: u64) -> Self {
        Self { fields: vec![start_group] }
    }

    /// Two fields: an absolute start, open-ended.
    ///
    /// `{0, 0}` is **not** the beginning of the track — Section 9.20.10 makes it
    /// the Next Object, `{Largest Object.Group, Largest Object.Object + 1}`, or
    /// `{0,0}` when nothing has been delivered. [`LocationFilter::next_object`]
    /// is that case spelled out; this constructor accepts it too, and means the
    /// same thing.
    pub fn absolute_start(start_group: u64, start_object: u64) -> Self {
        Self { fields: vec![start_group, start_object] }
    }

    /// The two-field `{0, 0}` special case: start at the Next Object.
    ///
    /// Section 3.4 names this filter as half of the recipe for
    /// exactly-once delivery on a subscription with a fill: a Next Object
    /// subscription filter paired with an open-ended fill range, which the
    /// publisher ends at Largest Object.
    pub fn next_object() -> Self {
        Self::absolute_start(0, 0)
    }

    /// Three fields: an absolute start and an end group, covering **all**
    /// objects in the end group.
    ///
    /// Section 9.20.10: "EndGroupDelta is delta encoded from StartGroup, but both
    /// the start and end groups are absolute, not relative to Largest Object."
    /// So the end group is `start_group + end_group_delta`, and a delta of 0
    /// ends in the group it started in.
    ///
    /// # Errors
    ///
    /// [`FillError::EndGroupOverflow`] when the sum leaves the number space,
    /// which Section 9.20.10 makes a PROTOCOL_VIOLATION at the receiver.
    pub fn range(
        start_group: u64,
        start_object: u64,
        end_group_delta: u64,
    ) -> Result<Self, FillError> {
        check_end_group(start_group, end_group_delta)?;
        Ok(Self { fields: vec![start_group, start_object, end_group_delta] })
    }

    /// Four fields: a fully specified **inclusive** range,
    /// `{start_group, start_object}` through
    /// `{start_group + end_group_delta, end_object}`.
    ///
    /// `end_object` is the Object ID of the last object the range covers. It is
    /// not that Object ID plus one, and an `end_object` of 0 means object 0
    /// rather than the whole group — both draft-19 conventions were deleted
    /// without a note in the change log, and this is the constructor where a
    /// ported `+ 1` does its damage.
    ///
    /// # Errors
    ///
    /// [`FillError::EndGroupOverflow`], as [`LocationFilter::range`].
    pub fn range_to(
        start_group: u64,
        start_object: u64,
        end_group_delta: u64,
        end_object: u64,
    ) -> Result<Self, FillError> {
        check_end_group(start_group, end_group_delta)?;
        Ok(Self { fields: vec![start_group, start_object, end_group_delta, end_object] })
    }

    /// The `vi64` fields, in wire order.
    pub fn fields(&self) -> &[u64] {
        &self.fields
    }

    /// The encoded value, without the parameter type or the length ahead of it.
    pub fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.fields.len() * 2);
        for field in &self.fields {
            VarInt::from_u64_moqt(*field).encode_moqt::<Wire>(&mut out);
        }
        out
    }

    /// This filter as the Message Parameter that carries it.
    ///
    /// # Errors
    ///
    /// [`FillError::NotRoundTrippable`] if the codec's own
    /// `decode_location_filter` does not read back the fields that went in.
    pub fn parameter(&self) -> Result<KeyValuePair, FillError> {
        let value = self.encode_value();
        let read = decode_location_filter(&value)
            .map_err(|e| FillError::NotRoundTrippable(e.to_string()))?;
        if read != self.fields {
            return Err(FillError::NotRoundTrippable(
                "the codec read back a different field list".to_string(),
            ));
        }
        Ok(KeyValuePair {
            key: VarInt::from_u64_moqt(LOCATION_FILTER),
            value: KvpValue::Bytes(value),
        })
    }
}

fn check_end_group(start_group: u64, delta: u64) -> Result<(), FillError> {
    start_group
        .checked_add(delta)
        .map(|_| ())
        .ok_or(FillError::EndGroupOverflow { start_group, delta })
}

/// A draft-21 `FILL_PARAMETERS` (Parameter Type 0x23), Section 9.20.16.
///
/// Putting one of these on a SUBSCRIBE or on a REQUEST_UPDATE for a
/// subscription is what asks the publisher to open a **fill fetch stream**: a
/// unidirectional stream beginning with a FETCH_HEADER, delivered exactly as a
/// FETCH response, carrying the Objects behind the live edge that the
/// subscription itself will not deliver. Its mere presence is the request;
/// [`FillParameters::inherited`] asks for a fill with every setting taken from
/// the subscription.
///
/// The nested parameters override the subscription's for the fill alone. A
/// `LOCATION_FILTER` nested here selects the **fill range** and is evaluated
/// with Fetch rules, so it never reaches past Largest Object; it is independent
/// of the subscription's own filter.
///
/// # This value begins with a `Number of Parameters` count
///
/// Section 9.20.16 says the value is "a sequence of Parameters that apply to
/// the fill fetch stream" and is "encoded as if they were Parameters for a
/// separate message", and stops there. **This crate reads that as the
/// whole block, count included.** The draft does not state it either way. The
/// grounds are Section 9.20's own definition of what a parameter block is —
/// "Because unknown parameters cannot be skipped, the block is bounded by a
/// parameter count rather than a length" — and the fact that every message
/// figure in Section 9 pairs `Number of Parameters` with `Parameters`. The
/// outer length prefix is the generic length-prefixed value encoding, and says
/// nothing about the value's internal structure.
///
/// So an empty `FILL_PARAMETERS` is `Length = 1` carrying the single byte
/// `0x00`, **not** `Length = 0`. Getting this wrong desynchronises the whole
/// enclosing parameter list rather than producing a recognisable error, which
/// is why it is named here as well as at the decoder.
///
/// # The `Type Delta` chain restarts here
///
/// Section 9.20.16: "The value of FILL_PARAMETERS is a separate parameter
/// scope. Parameters inside it are not considered to appear in the enclosing
/// message for the purposes of Section 9.20, so a Parameter Type MAY appear
/// both in the message and inside FILL_PARAMETERS." Section 9.20 defines `Type
/// Delta` against "the previous Parameter Type in the message", and a
/// separate scope is not the message — so the inner chain starts from 0, and
/// the outer parameter after `FILL_PARAMETERS` deltas from `0x23` rather than
/// from the last inner type. **The draft states neither half**; both are
/// decided here and in the codec's decoder, together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FillParameters {
    inner: Vec<KeyValuePair>,
}

impl FillParameters {
    /// A fill with every setting inherited from the subscription.
    ///
    /// The common case, and the one whose encoding is worth knowing: one byte,
    /// `0x00`, under a `Length` of 1.
    pub fn inherited() -> Self {
        Self::default()
    }

    /// Add a nested parameter. Types must be added in ascending order.
    ///
    /// # Errors
    ///
    /// [`FillError::NotAFillParameter`] for a type outside Table 6, and
    /// [`FillError::RepeatedFillParameter`] for a second instance of a type
    /// whose own definition does not allow repeats. Ordering is not checked
    /// here — [`FillParameters::parameter`] sorts before encoding, because
    /// Section 9.20 requires ascending order on the wire and a caller should
    /// not have to know Table 6's numbering to satisfy it.
    pub fn with(mut self, parameter: KeyValuePair) -> Result<Self, FillError> {
        let key = parameter.key.into_inner();
        if !FILL_PARAMETERS_ALLOWED.contains(&key) {
            return Err(FillError::NotAFillParameter(key));
        }
        if !may_repeat(key) && self.inner.iter().any(|p| p.key.into_inner() == key) {
            return Err(FillError::RepeatedFillParameter(key));
        }
        self.inner.push(parameter);
        Ok(self)
    }

    /// Add the `LOCATION_FILTER` that selects the fill range.
    ///
    /// Shorthand for `with(filter.parameter()?)`, and the parameter most fills
    /// carry: the fill range is what a fill is for.
    pub fn with_range(self, filter: &LocationFilter) -> Result<Self, FillError> {
        let parameter = filter.parameter()?;
        self.with(parameter)
    }

    /// Add the `GROUP_ORDER` (0x22) that the fill fetch stream's Groups arrive
    /// in.
    ///
    /// Section 9.20.9: "When it appears inside FILL_PARAMETERS, it governs the
    /// fill fetch stream and its ordering relative to subscription-delivered
    /// Objects". It is the one nested parameter a **reader** cannot ignore:
    /// Section 11.4.1.1 makes a Group ID Delta count upward under Ascending and
    /// downward under Descending, nothing on the data stream says which, and a
    /// reader started in the wrong order decodes every Object after the first
    /// into a Group that walks the wrong way — without failing to parse.
    ///
    /// A shorthand rather than a raw [`KeyValuePair`] because the value is a
    /// uint8 on the wire while the crate's `KvpValue` has no uint8 arm: it
    /// travels as a `Varint` whose value must fit one byte, and
    /// `encode_nested_value` writes the byte. Getting that pair wrong is a
    /// `MalformedValue` at best and a desynchronised block at worst.
    ///
    /// # Errors
    ///
    /// As [`FillParameters::with`]: [`FillError::RepeatedFillParameter`] for a
    /// second `GROUP_ORDER`, which Section 9.20 does not allow.
    pub fn with_group_order(self, order: GroupOrder) -> Result<Self, FillError> {
        self.with(KeyValuePair {
            key: VarInt::from_u64_moqt(GROUP_ORDER),
            value: KvpValue::Varint(VarInt::from_u64_moqt(encode_group_order(order))),
        })
    }

    /// The nested parameters, in the order they were added.
    pub fn inner(&self) -> &[KeyValuePair] {
        &self.inner
    }

    /// This block as the Message Parameter that carries it.
    ///
    /// The value is the count, then the parameters in ascending type order with
    /// their types delta-encoded from 0, each value in the shape its own type
    /// names. It is decoded back through the codec before it is returned.
    ///
    /// # Errors
    ///
    /// [`FillError::MalformedValue`] for a value whose shape does not match its
    /// type, and [`FillError::NotRoundTrippable`] if the codec's
    /// `decode_fill_parameters` refuses what this built or reads it back
    /// differently.
    pub fn parameter(&self) -> Result<KeyValuePair, FillError> {
        let mut sorted = self.inner.clone();
        // Section 9.20: "Parameters MUST be serialized in ascending order by
        // Type." A stable sort keeps two instances of a repeatable filter in
        // the order the caller added them, which is the order their SetIDs are
        // meant to be read in.
        sorted.sort_by_key(|p| p.key.into_inner());

        let mut value = Vec::new();
        VarInt::from_usize(sorted.len()).encode_moqt::<Wire>(&mut value);
        let mut prev_key: u64 = 0;
        for pair in &sorted {
            let key = pair.key.into_inner();
            // The chain starts at 0 because this is a separate scope, not
            // because the block is at the start of a message.
            let delta = key - prev_key;
            prev_key = key;
            VarInt::from_u64_moqt(delta).encode_moqt::<Wire>(&mut value);
            encode_nested_value(key, &pair.value, &mut value)?;
        }

        let read = decode_fill_parameters(&value)
            .map_err(|e| FillError::NotRoundTrippable(e.to_string()))?;
        if read.len() != sorted.len() {
            return Err(FillError::NotRoundTrippable(
                "the codec read back a different number of parameters".to_string(),
            ));
        }
        Ok(KeyValuePair {
            key: VarInt::from_u64_moqt(FILL_PARAMETERS),
            value: KvpValue::Bytes(value),
        })
    }
}

/// Write one nested parameter's value in the shape its type names.
///
/// The shapes are Table 6's eight types only, which is the whole of what may be
/// nested; anything else was refused by [`FillParameters::with`] before it got
/// here.
fn encode_nested_value(key: u64, value: &KvpValue, out: &mut Vec<u8>) -> Result<(), FillError> {
    match value {
        KvpValue::Varint(v) if is_uint8(key) => {
            let raw = v.into_inner();
            let byte = u8::try_from(raw).map_err(|_| FillError::MalformedValue {
                key,
                detail: "a uint8 parameter's value does not fit one byte",
            })?;
            out.push(byte);
            Ok(())
        }
        KvpValue::Varint(v) if !is_length_prefixed(key) => {
            v.encode_moqt::<Wire>(out);
            Ok(())
        }
        KvpValue::Bytes(bytes) if is_length_prefixed(key) => {
            VarInt::from_usize(bytes.len()).encode_moqt::<Wire>(out);
            out.extend_from_slice(bytes);
            Ok(())
        }
        KvpValue::Varint(_) => Err(FillError::MalformedValue {
            key,
            detail: "a bare varint where the type defines a length-prefixed structure",
        }),
        KvpValue::Bytes(_) => Err(FillError::MalformedValue {
            key,
            detail: "bytes where the type defines a bare varint or a uint8",
        }),
    }
}

/// The Section 9.20.9 value for a Group Order.
fn encode_group_order(order: GroupOrder) -> u64 {
    match order {
        GroupOrder::Ascending => GROUP_ORDER_ASCENDING,
        GroupOrder::Descending => GROUP_ORDER_DESCENDING,
    }
}

/// The `GROUP_ORDER` in one parameter list, or `None` if it holds none.
///
/// One list, one level: the caller decides which scope this is being asked
/// about, because the two scopes answer the question in a fixed order and only
/// [`group_order`] knows that order.
fn read_group_order(parameters: &[KeyValuePair]) -> Result<Option<GroupOrder>, FillError> {
    let Some(parameter) = parameters.iter().find(|p| p.key.into_inner() == GROUP_ORDER) else {
        return Ok(None);
    };
    let KvpValue::Varint(value) = &parameter.value else {
        return Err(FillError::MalformedValue {
            key: GROUP_ORDER,
            detail: "bytes where Section 9.20.9 defines a uint8",
        });
    };
    match value.into_inner() {
        GROUP_ORDER_ASCENDING => Ok(Some(GroupOrder::Ascending)),
        GROUP_ORDER_DESCENDING => Ok(Some(GroupOrder::Descending)),
        // The codec's decoder holds a received 0x22 to this same range before
        // it ever reaches here (`uint8_value_in_range`), so this arm is for a
        // pair a caller built in memory. Section 9.20.9: "If an endpoint
        // receives a value outside this range, it MUST close the session with
        // PROTOCOL_VIOLATION", so it is refused rather than rounded.
        _ => Err(FillError::MalformedValue {
            key: GROUP_ORDER,
            detail: "Section 9.20.9 allows only Ascending (0x1) and Descending (0x2)",
        }),
    }
}

/// The Group Order a fill fetch stream's Objects arrive in, given the
/// parameters of the SUBSCRIBE (or REQUEST_UPDATE) that asked for the fill.
///
/// A fill fetch stream is "delivered as a FETCH response" (Section 3.4), and
/// a FETCH response's Group ID Deltas are read against a Group Order that is
/// nowhere on the data stream — Section 11.4.1.1 makes a delta count upward
/// under Ascending and downward under Descending. So a subscriber has to
/// resolve the order from the control exchange before it reads the first
/// Object, and this is that resolution. Hand the answer to
/// [`begin_fetch_objects`](crate::draft21::connection::FramedRecvStream::begin_fetch_objects);
/// [`accept_fill_stream`](crate::draft21::connection::Connection::accept_fill_stream)
/// already does.
///
/// Three steps, in the order the two sections put them:
///
/// 1. A `GROUP_ORDER` **inside** `FILL_PARAMETERS`. Section 9.20.9: "When it
///    appears inside FILL_PARAMETERS, it governs the fill fetch stream and its
///    ordering relative to subscription-delivered Objects".
/// 2. Otherwise the `GROUP_ORDER` on the request itself. Section 3.4: "The
///    fill fetch stream inherits the subscription's parameters" and
///    "parameters carried inside FILL_PARAMETERS override them for the fill
///    fetch stream".
/// 3. Otherwise **Ascending**.
///
/// # Step 3 is a choice the draft does not make
///
/// Section 9.20.9 gives two different defaults and a fill sits between them:
/// "If omitted from SUBSCRIBE or SUBSCRIBE_TRACKS, the publisher's preference
/// from the Track is used. If omitted from FETCH, the receiver uses Ascending
/// (0x1)." A fill is asked for by a SUBSCRIBE and delivered as a FETCH
/// response, so both sentences reach it. **This crate takes the FETCH
/// default**, because the publisher's preference is not a thing a subscriber
/// holds when the first Object arrives — it is a Track Property that arrives in
/// SUBSCRIBE_OK at the earliest, and on this path may not arrive at all — while
/// Ascending is a value the reader can be started with before the stream opens.
/// A subscriber that does learn the publisher's preference and finds it
/// Descending can restart the reader with `begin_fetch_objects` before reading
/// the first Object.
///
/// # Errors
///
/// [`FillError::MalformedValue`] for a `GROUP_ORDER` whose value is not a uint8
/// in `{1, 2}` or whose shape is not a bare number, and
/// [`FillError::NotRoundTrippable`] for a `FILL_PARAMETERS` value the codec's
/// own decoder refuses. Neither is reachable from a block this module built.
pub fn group_order(parameters: &[KeyValuePair]) -> Result<GroupOrder, FillError> {
    if let Some(fill) = parameters.iter().find(|p| p.key.into_inner() == FILL_PARAMETERS) {
        let KvpValue::Bytes(value) = &fill.value else {
            return Err(FillError::MalformedValue {
                key: FILL_PARAMETERS,
                detail: "a bare varint where Section 9.20.16 defines a parameter block",
            });
        };
        let nested = decode_fill_parameters(value)
            .map_err(|e| FillError::NotRoundTrippable(e.to_string()))?;
        if let Some(order) = read_group_order(&nested)? {
            return Ok(order);
        }
    }
    if let Some(order) = read_group_order(parameters)? {
        return Ok(order);
    }
    Ok(GroupOrder::Ascending)
}

/// Put `parameter` into `parameters` at the position ascending type order
/// requires.
///
/// Section 9.20 makes the order a wire rule — "Parameters MUST be serialized in
/// ascending order by Type" — and the codec's encoder refuses a descending
/// pair rather than emitting one, so a caller appending a `LOCATION_FILTER` to
/// a list that already holds a higher type would otherwise get an error from
/// the encoder instead of a message.
///
/// A parameter of a type already present is inserted after the ones already
/// there, which is the only placement that keeps a repeatable filter's
/// instances in the order they were added.
pub fn insert_parameter(parameters: &mut Vec<KeyValuePair>, parameter: KeyValuePair) {
    let key = parameter.key.into_inner();
    let at = parameters.iter().position(|p| p.key.into_inner() > key).unwrap_or(parameters.len());
    parameters.insert(at, parameter);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty fill is one byte, and that byte is the count: `Length = 1`
    /// carrying `0x00`, not `Length = 0`.
    ///
    /// Encoding it as `Length = 0` instead fails with a decode error from the
    /// codec, because a block with no count is a block whose first parameter
    /// count is missing.
    #[test]
    fn an_empty_fill_is_a_single_zero_byte() {
        let p = FillParameters::inherited().parameter().unwrap();
        assert_eq!(p.key.into_inner(), FILL_PARAMETERS);
        match p.value {
            KvpValue::Bytes(bytes) => assert_eq!(bytes, vec![0x00]),
            KvpValue::Varint(_) => panic!("FILL_PARAMETERS is length-prefixed"),
        }
    }

    /// The inner chain starts at 0, so the first nested type is written as its
    /// own number and not as a delta from the enclosing `0x23`. Decision D2.
    #[test]
    fn the_nested_type_delta_chain_restarts_at_zero() {
        let fill = FillParameters::inherited()
            .with_range(&LocationFilter::range_to(4, 0, 2, 7).unwrap())
            .unwrap();
        let p = fill.parameter().unwrap();
        let KvpValue::Bytes(bytes) = p.value else { panic!("length-prefixed") };
        // count = 1, then Type Delta = 0x21 (not 0x21 - 0x23, which would wrap),
        // then Length = 4, then the four minimal one-byte fields.
        assert_eq!(bytes, vec![0x01, 0x21, 0x04, 0x04, 0x00, 0x02, 0x07]);
    }

    /// Every shape Section 9.20.10 defines, and no others. The field count is
    /// what the decoder switches on, so the count is what is asserted.
    #[test]
    fn each_filter_shape_has_the_field_count_its_row_names() {
        assert_eq!(LocationFilter::none().fields().len(), 0);
        assert_eq!(LocationFilter::relative(3).fields().len(), 1);
        assert_eq!(LocationFilter::absolute_start(1, 2).fields().len(), 2);
        assert_eq!(LocationFilter::next_object().fields(), &[0, 0]);
        assert_eq!(LocationFilter::range(1, 2, 3).unwrap().fields().len(), 3);
        assert_eq!(LocationFilter::range_to(1, 2, 3, 4).unwrap().fields().len(), 4);
    }

    /// The end is the last object, and nothing here adds one to it. Draft-19's
    /// encoder wrote `last + 1`; a port that kept the arithmetic fetches one
    /// object too many, and nothing on the wire distinguishes the two.
    #[test]
    fn an_end_object_is_the_last_object_and_not_one_past_it() {
        let filter = LocationFilter::range_to(10, 0, 0, 5).unwrap();
        assert_eq!(filter.fields(), &[10, 0, 0, 5]);
        let KvpValue::Bytes(bytes) = filter.parameter().unwrap().value else { panic!() };
        assert_eq!(bytes, vec![10, 0, 0, 5]);
    }

    /// Section 9.20.10 answers the overflow with a session close, so it is
    /// refused rather than emitted.
    #[test]
    fn an_end_group_past_the_number_space_is_refused() {
        assert_eq!(
            LocationFilter::range(u64::MAX, 0, 1),
            Err(FillError::EndGroupOverflow { start_group: u64::MAX, delta: 1 })
        );
        assert!(LocationFilter::range_to(u64::MAX - 1, 0, 1, 0).is_ok());
    }

    /// Table 6 is a closed list, and the one Range Filter it leaves out is the
    /// one that selects tracks rather than objects.
    #[test]
    fn a_type_outside_table_6_may_not_be_nested() {
        let track_property_filter =
            KeyValuePair { key: VarInt::from_u64_moqt(0x29), value: KvpValue::Bytes(vec![]) };
        assert_eq!(
            FillParameters::inherited().with(track_property_filter).unwrap_err(),
            FillError::NotAFillParameter(0x29)
        );
        let expires = KeyValuePair {
            key: VarInt::from_u64_moqt(0x08),
            value: KvpValue::Varint(VarInt::from_u64_moqt(1)),
        };
        assert_eq!(
            FillParameters::inherited().with(expires).unwrap_err(),
            FillError::NotAFillParameter(0x08)
        );
    }

    /// The order on the wire is ascending whatever order the caller used, so a
    /// caller does not have to know Table 6's numbering.
    #[test]
    fn nested_parameters_go_out_in_ascending_type_order() {
        let group_order = KeyValuePair {
            key: VarInt::from_u64_moqt(0x22),
            value: KvpValue::Varint(VarInt::from_u64_moqt(1)),
        };
        let priority = KeyValuePair {
            key: VarInt::from_u64_moqt(0x20),
            value: KvpValue::Varint(VarInt::from_u64_moqt(128)),
        };
        let fill = FillParameters::inherited()
            .with(group_order)
            .unwrap()
            .with(priority)
            .unwrap()
            .parameter()
            .unwrap();
        let KvpValue::Bytes(bytes) = fill.value else { panic!() };
        // count = 2, then 0x20 with value 128, then a delta of 2 to 0x22 with
        // value 1 (Ascending).
        assert_eq!(bytes, vec![0x02, 0x20, 128, 0x02, 0x01]);
    }

    /// A repeat of a type whose definition does not allow one is the frame the
    /// codec refuses, so it is refused here first.
    #[test]
    fn a_non_repeatable_nested_type_may_not_appear_twice() {
        let filter = LocationFilter::relative(0);
        let err = FillParameters::inherited()
            .with_range(&filter)
            .unwrap()
            .with_range(&filter)
            .unwrap_err();
        assert_eq!(err, FillError::RepeatedFillParameter(LOCATION_FILTER));
    }

    /// `INCLUDE_PROPERTIES` (0x35) is not a fill parameter, and the reason is
    /// worth having on the record: Section 9.20.22 makes it govern the **Track
    /// Properties** in an OK message, and a fill fetch stream has no OK message
    /// at all (Section 3.4.1 — no FETCH_OK, no REQUEST_ERROR). It is absent
    /// from Table 6, so nesting it is refused.
    ///
    /// The consequence for the data stream is the one to hold on to: the Object
    /// Properties on a fill fetch object are governed by Serialization Flags bit
    /// 0x20 (Section 11.4.1.1) and by nothing else. `INCLUDE_PROPERTIES` does
    /// not gate them, on a fill or anywhere else.
    #[test]
    fn include_properties_is_not_a_fill_parameter() {
        let include_properties = KeyValuePair {
            key: VarInt::from_u64_moqt(0x35),
            value: KvpValue::Varint(VarInt::from_u64_moqt(0)),
        };
        assert_eq!(
            FillParameters::inherited().with(include_properties).unwrap_err(),
            FillError::NotAFillParameter(0x35)
        );
    }

    /// A `GROUP_ORDER` inside `FILL_PARAMETERS` is one byte under a `Type
    /// Delta` counted from 0, and it is what the fill stream is read in.
    #[test]
    fn a_nested_group_order_is_the_order_the_fill_is_read_in() {
        let fill = FillParameters::inherited()
            .with_group_order(GroupOrder::Descending)
            .unwrap()
            .parameter()
            .unwrap();
        let KvpValue::Bytes(bytes) = &fill.value else { panic!("length-prefixed") };
        // count = 1, Type Delta = 0x22 from the restarted chain, value = 0x02.
        assert_eq!(bytes, &vec![0x01, 0x22, 0x02]);
        assert_eq!(group_order(&[fill]).unwrap(), GroupOrder::Descending);
    }

    /// The nested order overrides the subscription's, which is what Section
    /// 3.4 means by "parameters carried inside FILL_PARAMETERS override them
    /// for the fill fetch stream".
    #[test]
    fn the_nested_group_order_beats_the_subscriptions_own() {
        let subscription_order = KeyValuePair {
            key: VarInt::from_u64_moqt(GROUP_ORDER),
            value: KvpValue::Varint(VarInt::from_u64_moqt(1)),
        };
        let fill = FillParameters::inherited()
            .with_group_order(GroupOrder::Descending)
            .unwrap()
            .parameter()
            .unwrap();
        let mut parameters = vec![fill];
        insert_parameter(&mut parameters, subscription_order);
        assert_eq!(group_order(&parameters).unwrap(), GroupOrder::Descending);
    }

    /// With nothing nested, the subscription's own `GROUP_ORDER` is inherited.
    #[test]
    fn a_fill_with_no_order_of_its_own_inherits_the_subscriptions() {
        let mut parameters = vec![FillParameters::inherited().parameter().unwrap()];
        insert_parameter(
            &mut parameters,
            KeyValuePair {
                key: VarInt::from_u64_moqt(GROUP_ORDER),
                value: KvpValue::Varint(VarInt::from_u64_moqt(2)),
            },
        );
        assert_eq!(group_order(&parameters).unwrap(), GroupOrder::Descending);
    }

    /// With no `GROUP_ORDER` in either scope, Ascending. Section 9.20.9 gives a
    /// fill two candidate defaults and this crate takes the FETCH one; see
    /// [`group_order`].
    #[test]
    fn a_fill_that_names_no_order_anywhere_is_ascending() {
        let parameters = vec![FillParameters::inherited().parameter().unwrap()];
        assert_eq!(group_order(&parameters).unwrap(), GroupOrder::Ascending);
        assert_eq!(group_order(&[]).unwrap(), GroupOrder::Ascending);
    }

    /// A `GROUP_ORDER` outside `{1, 2}` is refused rather than rounded to a
    /// direction, because reading a stream in the wrong direction does not fail
    /// to parse — it mis-locates every Object after the first.
    #[test]
    fn a_group_order_outside_the_two_values_is_refused() {
        let parameters = vec![KeyValuePair {
            key: VarInt::from_u64_moqt(GROUP_ORDER),
            value: KvpValue::Varint(VarInt::from_u64_moqt(3)),
        }];
        assert!(matches!(
            group_order(&parameters),
            Err(FillError::MalformedValue { key: GROUP_ORDER, .. })
        ));
    }

    /// Ascending order is a wire rule the codec's encoder enforces, so the
    /// helper that puts a parameter in a list has to respect it.
    #[test]
    fn insert_parameter_keeps_the_list_ascending() {
        let mut params = vec![
            KeyValuePair { key: VarInt::from_u64_moqt(0x03), value: KvpValue::Bytes(vec![]) },
            KeyValuePair {
                key: VarInt::from_u64_moqt(0x35),
                value: KvpValue::Varint(VarInt::from_u64_moqt(1)),
            },
        ];
        insert_parameter(&mut params, LocationFilter::relative(0).parameter().unwrap());
        let keys: Vec<u64> = params.iter().map(|p| p.key.into_inner()).collect();
        assert_eq!(keys, vec![0x03, 0x21, 0x35]);
    }
}

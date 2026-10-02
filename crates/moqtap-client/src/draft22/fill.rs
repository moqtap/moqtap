//! Location filters and fill fetch streams, the two things draft-22 asks a
//! subscriber to build byte by byte.
//!
//! The range of a FETCH travels in the `LOCATION_FILTER` message parameter
//! (Section 9.20.9), and `FILL_PARAMETERS` (Section 9.20.15) is a parameter
//! whose *presence* on a SUBSCRIBE or a REQUEST_UPDATE asks the publisher to
//! open a fill fetch stream, and whose value is a nested parameter block that
//! overrides the subscription's own settings for that fill alone.
//!
//! Both are parameter values a caller would otherwise have to construct by
//! hand, which is why they are here: neither carries anything a receiver could
//! resynchronise on, so getting either wrong desynchronises the whole parameter
//! list rather than producing a recognisable error. A `LOCATION_FILTER` has no
//! length at all — its `Location Filter Type` is the only thing that says
//! where it ends — and `FILL_PARAMETERS` is the place draft-22 is least
//! explicit.
//!
//! # What this module decides, and where the draft is silent
//!
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
//! entire Group". Draft-22 Section 3.3.1 says a Location filter "specifies an
//! inclusive range of Locations", Section 3.2 that a FETCH requests Objects
//! "between a Start Location and an End Location, inclusive", and neither
//! draft-19 convention survives. **Nothing in this module adds or subtracts one from
//! an end location**, and a caller porting draft-19 arithmetic forward fetches
//! one object too many.

use moqtap_codec::draft22::data_stream::GroupOrder;
use moqtap_codec::draft22::message::{
    decode_fill_parameters, decode_location_filter, location_filter_types, FILL_PARAMETERS,
    LOCATION_FILTER,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::{Moqt18 as Wire, VarInt};

/// `GROUP_ORDER`, Parameter Type 0x22 (Section 9.20.8).
///
/// Spelled here rather than imported because the codec's draft-22 message
/// module does not export it, and because this module needs the same number in
/// three places: Table 7's allow-list, the uint8 shape test, and [`group_order`].
pub const GROUP_ORDER: u64 = 0x22;

/// The `GROUP_ORDER` value Section 9.20.8 assigns to Ascending.
const GROUP_ORDER_ASCENDING: u64 = 0x1;

/// The `GROUP_ORDER` value Section 9.20.8 assigns to Descending.
const GROUP_ORDER_DESCENDING: u64 = 0x2;

/// Errors from building a `LOCATION_FILTER` or a `FILL_PARAMETERS` value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FillError {
    /// `StartGroup + EndGroupDelta` left the number space.
    ///
    /// Section 9.20.9: "If StartGroup + EndGroupDelta exceeds 2^64 - 1, the
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
    /// A parameter type Table 7 does not list was put inside `FILL_PARAMETERS`.
    ///
    /// Section 9.20.15: "An endpoint that receives a parameter inside
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

/// The parameter types draft-22 Section 9.20.15, Table 7 permits inside a
/// `FILL_PARAMETERS` value, in ascending order.
///
/// `TRACK_PROPERTY_FILTER` (0x29) is deliberately absent: it selects tracks,
/// and a fill applies to one already-selected track. The same list is enforced
/// on the decode side by `moqtap_codec::draft22::message::decode_fill_parameters`,
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

/// Whether a Table 7 parameter's value is a single raw byte rather than a
/// varint or a length-prefixed block.
///
/// `SUBSCRIBER_PRIORITY` (0x20, Section 9.20.7) and `GROUP_ORDER` (0x22,
/// Section 9.20.8) are the two uint8s that may be nested.
fn is_uint8(key: u64) -> bool {
    key == 0x20 || key == GROUP_ORDER
}

/// Whether a Table 7 parameter's value is a bare varint.
///
/// `FILL_TIMEOUT` (0x0A, Section 9.20.5) is the only one. `LOCATION_FILTER`
/// (0x21) also opens with a varint, but a varint alone is only its type, and
/// accepting one here would write a bare `0x05` as Next Object and a bare `0x00`
/// as no filter: the codec's own encoder refuses that value, so this one does
/// too.
fn is_bare_varint(key: u64) -> bool {
    key == 0x0A
}

/// Whether a Table 7 parameter's value carries its own length prefix.
///
/// The four nestable Range Filters (0x25 through 0x28). `FILL_TIMEOUT` (0x0A)
/// is the only bare varint in the table, and `LOCATION_FILTER` (0x21) is
/// neither: its value is a `Location Filter Type` and the fields that type
/// names, with no length ahead of them, nested or not.
fn is_length_prefixed(key: u64) -> bool {
    (0x25..=0x28).contains(&key)
}

/// A draft-22 `LOCATION_FILTER` (Parameter Type 0x21), Section 9.20.9.
///
/// ```text
/// LOCATION_FILTER Parameter {
///   Parameter Type (vi64) = 0x21,
///   Location Filter Type (vi64),
///   [StartGroup (vi64),]
///   [StartObject (vi64),]
///   [EndGroupDelta (vi64),]
///   [EndObject (vi64),]
/// }
/// ```
///
/// # The shape is the type
///
/// Section 9.20.9: "The Location Filter Type dictates which optional
/// variable-length integer fields follow, and how they are interpreted." Each
/// constructor here is one of the six types Table 6 lists, and the type is
/// written first, so a caller cannot build a type the draft does not define,
/// cannot build a three-field filter by leaving a field out of a four-field
/// one, and cannot confuse the two types that carry no fields at all — None
/// and Next Object, which mean opposite things.
///
/// There is no length. The type is the only thing that says where the value
/// ends, so a receiver that reads the type wrong reads every parameter after
/// it wrong too; this is why the value is built here and handed back through
/// the codec's own decoder before it is returned.
///
/// # Migrating a draft-19 filter
///
/// Draft-19's filter also opened with a type, and its numbers are **not**
/// these. Draft-19's Filter Type 0x1 (Next Group Start) is
/// [`LocationFilter::relative`] with `0`, type 0x01 here. Its 0x2 (Largest
/// Object) is [`LocationFilter::next_object`], type 0x05 here — not 0x02,
/// which is an absolute start. Its 0x3 and 0x4 (AbsoluteStart and
/// AbsoluteRange) are [`LocationFilter::absolute_start`] and
/// [`LocationFilter::range`], types 0x02 and 0x03 here. A draft-19 type number
/// copied across as a number asks a different question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationFilter {
    filter_type: u64,
    fields: Vec<u64>,
}

impl LocationFilter {
    /// Type 0x00: no filter at all, and no fields.
    ///
    /// Section 9.20.9: "If Location Filter Type is 0x00, no fields follow and
    /// there is no Location Filter." In a REQUEST_UPDATE this is how a filter
    /// already in force is taken away: Section 9.5 has "no generic mechanism to
    /// remove a parameter from a request", and omitting `LOCATION_FILTER` from
    /// a REQUEST_UPDATE leaves the value unchanged rather than clearing it.
    pub fn none() -> Self {
        Self { filter_type: location_filter_types::NONE, fields: Vec::new() }
    }

    /// Type 0x01: a start relative to the live edge, open-ended.
    ///
    /// Section 9.20.9: the start Location is `{Largest Object.Group + 1 -
    /// StartGroup, 0}`, so `0` is the next group, `1` the current group, and
    /// `N` is `N - 1` groups before the current one. Clamped at both ends of
    /// the number space by the publisher rather than here, because resolving it
    /// needs Largest Object.
    pub fn relative(start_group: u64) -> Self {
        Self { filter_type: location_filter_types::RELATIVE_START, fields: vec![start_group] }
    }

    /// Type 0x02: an absolute start, open-ended.
    ///
    /// Every start is absolute here, `{0, 0}` included: it is the first
    /// Location of the track. The live edge is a type of its own,
    /// [`LocationFilter::next_object`].
    pub fn absolute_start(start_group: u64, start_object: u64) -> Self {
        Self {
            filter_type: location_filter_types::ABSOLUTE_START,
            fields: vec![start_group, start_object],
        }
    }

    /// Type 0x05: start at the Next Object, open-ended, with no fields.
    ///
    /// Section 9.20.9: "If Location Filter Type is 0x05, no fields follow and
    /// it specifies the Next Object." Section 3.4 names this filter as half of
    /// the recipe for exactly-once delivery on a subscription with a fill: a
    /// Next Object subscription filter paired with an open-ended fill range,
    /// which the publisher ends at Largest Object.
    pub fn next_object() -> Self {
        Self { filter_type: location_filter_types::NEXT_OBJECT, fields: Vec::new() }
    }

    /// Type 0x03: an absolute start and an end group, covering **all** objects
    /// in the end group.
    ///
    /// Section 9.20.9: "EndGroupDelta is delta encoded from StartGroup, but both
    /// the start and end groups are absolute, not relative to Largest Object."
    /// So the end group is `start_group + end_group_delta`, and a delta of 0
    /// ends in the group it started in.
    ///
    /// # Errors
    ///
    /// [`FillError::EndGroupOverflow`] when the sum leaves the number space,
    /// which Section 9.20.9 makes a PROTOCOL_VIOLATION at the receiver.
    pub fn range(
        start_group: u64,
        start_object: u64,
        end_group_delta: u64,
    ) -> Result<Self, FillError> {
        check_end_group(start_group, end_group_delta)?;
        Ok(Self {
            filter_type: location_filter_types::ABSOLUTE_START_GROUP_END,
            fields: vec![start_group, start_object, end_group_delta],
        })
    }

    /// Type 0x04: a fully specified **inclusive** range,
    /// `{start_group, start_object}` through
    /// `{start_group + end_group_delta, end_object}`.
    ///
    /// `end_object` is the Object ID of the last object the range covers. It is
    /// not that Object ID plus one, and an `end_object` of 0 means object 0
    /// rather than the whole group — both draft-19 conventions are absent from
    /// this draft, and this is the constructor where a ported `+ 1` does its
    /// damage.
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
        Ok(Self {
            filter_type: location_filter_types::ABSOLUTE_RANGE,
            fields: vec![start_group, start_object, end_group_delta, end_object],
        })
    }

    /// The `Location Filter Type`, one of
    /// [`location_filter_types`].
    pub fn filter_type(&self) -> u64 {
        self.filter_type
    }

    /// The `vi64` fields that follow the type, in wire order. Empty for both
    /// None and Next Object, which only [`LocationFilter::filter_type`] tells
    /// apart.
    pub fn fields(&self) -> &[u64] {
        &self.fields
    }

    /// The encoded value, without the parameter type ahead of it: the
    /// `Location Filter Type`, then the fields it names.
    pub fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.fields.len() * 2);
        VarInt::from_u64_moqt(self.filter_type).encode_moqt::<Wire>(&mut out);
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
    /// `decode_location_filter` does not read back the type and fields that
    /// went in.
    pub fn parameter(&self) -> Result<KeyValuePair, FillError> {
        let value = self.encode_value();
        let (filter_type, fields) = decode_location_filter(&value)
            .map_err(|e| FillError::NotRoundTrippable(e.to_string()))?;
        if filter_type != self.filter_type || fields != self.fields {
            return Err(FillError::NotRoundTrippable(
                "the codec read back a different Location Filter Type or field list".to_string(),
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

/// A draft-22 `FILL_PARAMETERS` (Parameter Type 0x23), Section 9.20.15.
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
/// Section 9.20.15 says the value is "a sequence of Parameters that apply to
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
/// Section 9.20.15: "The value of FILL_PARAMETERS is a separate parameter
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
    /// [`FillError::NotAFillParameter`] for a type outside Table 7, and
    /// [`FillError::RepeatedFillParameter`] for a second instance of a type
    /// whose own definition does not allow repeats. Ordering is not checked
    /// here — [`FillParameters::parameter`] sorts before encoding, because
    /// Section 9.20 requires ascending order on the wire and a caller should
    /// not have to know Table 7's numbering to satisfy it.
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
    /// Section 9.20.8: "When it appears inside FILL_PARAMETERS, it governs the
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
/// The shapes are Table 7's eight types only, which is the whole of what may be
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
        KvpValue::Varint(v) if is_bare_varint(key) => {
            v.encode_moqt::<Wire>(out);
            Ok(())
        }
        KvpValue::Bytes(bytes) if is_length_prefixed(key) => {
            VarInt::from_usize(bytes.len()).encode_moqt::<Wire>(out);
            out.extend_from_slice(bytes);
            Ok(())
        }
        // Written as it stands: the reader finds the end of these bytes by
        // reading the type, so a value whose fields disagree with its type is
        // refused here rather than shifting every nested parameter after it.
        KvpValue::Bytes(bytes) if key == LOCATION_FILTER => {
            decode_location_filter(bytes).map_err(|_| FillError::MalformedValue {
                key,
                detail: "bytes that are not a Location Filter Type and the fields it names",
            })?;
            out.extend_from_slice(bytes);
            Ok(())
        }
        KvpValue::Varint(_) => Err(FillError::MalformedValue {
            key,
            detail: "a bare varint where the type defines a structure",
        }),
        KvpValue::Bytes(_) => Err(FillError::MalformedValue {
            key,
            detail: "bytes where the type defines a bare varint or a uint8",
        }),
    }
}

/// The Section 9.20.8 value for a Group Order.
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
            detail: "bytes where Section 9.20.8 defines a uint8",
        });
    };
    match value.into_inner() {
        GROUP_ORDER_ASCENDING => Ok(Some(GroupOrder::Ascending)),
        GROUP_ORDER_DESCENDING => Ok(Some(GroupOrder::Descending)),
        // The codec's decoder holds a received 0x22 to this same range before
        // it ever reaches here (`uint8_value_in_range`), so this arm is for a
        // pair a caller built in memory. Section 9.20.8: "If an endpoint
        // receives a value outside this range, it MUST close the session with
        // PROTOCOL_VIOLATION", so it is refused rather than rounded.
        _ => Err(FillError::MalformedValue {
            key: GROUP_ORDER,
            detail: "Section 9.20.8 allows only Ascending (0x1) and Descending (0x2)",
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
/// [`begin_fetch_objects`](crate::draft22::connection::FramedRecvStream::begin_fetch_objects);
/// [`accept_fill_stream`](crate::draft22::connection::Connection::accept_fill_stream)
/// already does.
///
/// Three steps, in the order the two sections put them:
///
/// 1. A `GROUP_ORDER` **inside** `FILL_PARAMETERS`. Section 9.20.8: "When it
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
/// Section 9.20.8 gives two different defaults and a fill sits between them:
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
                detail: "a bare varint where Section 9.20.15 defines a parameter block",
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
        // then Location Filter Type 0x04, then the four minimal one-byte
        // fields. No length: the type says where the value ends.
        assert_eq!(bytes, vec![0x01, 0x21, 0x04, 0x04, 0x00, 0x02, 0x07]);
    }

    /// A nested filter carries no length, which only a filter whose type and
    /// field count differ can show: Next Object is the type alone, and a
    /// parameter after it starts on the very next byte.
    #[test]
    fn a_nested_filter_is_written_without_a_length() {
        let fill = FillParameters::inherited()
            .with_range(&LocationFilter::next_object())
            .unwrap()
            .with_group_order(GroupOrder::Descending)
            .unwrap()
            .parameter()
            .unwrap();
        let KvpValue::Bytes(bytes) = fill.value else { panic!("length-prefixed") };
        // count = 2; Type Delta 0x21, type 0x05; Type Delta 1 to 0x22, value 2.
        assert_eq!(bytes, vec![0x02, 0x21, 0x05, 0x01, 0x02]);
        let nested = decode_fill_parameters(&bytes).unwrap();
        assert_eq!(nested.len(), 2);
    }

    /// Every type Section 9.20.9 defines, each with the fields its sentence
    /// names. The type is what the decoder switches on, so the type is
    /// asserted alongside the fields.
    #[test]
    fn each_constructor_is_one_location_filter_type() {
        use location_filter_types as T;
        let cases = [
            (LocationFilter::none(), T::NONE, vec![]),
            (LocationFilter::relative(3), T::RELATIVE_START, vec![3]),
            (LocationFilter::absolute_start(1, 2), T::ABSOLUTE_START, vec![1, 2]),
            (LocationFilter::range(1, 2, 3).unwrap(), T::ABSOLUTE_START_GROUP_END, vec![1, 2, 3]),
            (LocationFilter::range_to(1, 2, 3, 4).unwrap(), T::ABSOLUTE_RANGE, vec![1, 2, 3, 4]),
            (LocationFilter::next_object(), T::NEXT_OBJECT, vec![]),
        ];
        for (filter, filter_type, fields) in cases {
            assert_eq!(filter.filter_type(), filter_type);
            assert_eq!(filter.fields(), fields.as_slice());
            let mut expected = vec![filter_type as u8];
            expected.extend(fields.iter().map(|f| *f as u8));
            assert_eq!(filter.encode_value(), expected);
            assert!(filter.parameter().is_ok());
        }
    }

    /// `{0, 0}` is the beginning of the track and Next Object is a type of its
    /// own, so the two are different bytes. Section 9.20.9: "If Location
    /// Filter Type is 0x05, no fields follow and it specifies the Next Object."
    #[test]
    fn an_absolute_start_at_zero_is_not_the_next_object() {
        assert_eq!(LocationFilter::absolute_start(0, 0).encode_value(), vec![0x02, 0x00, 0x00]);
        assert_eq!(LocationFilter::next_object().encode_value(), vec![0x05]);
        assert_ne!(LocationFilter::absolute_start(0, 0), LocationFilter::next_object());
    }

    /// A field too large for one byte is where a type-led value and a
    /// length-led one part company: the type stays 0x02 for two fields however
    /// many bytes they take.
    #[test]
    fn the_type_counts_fields_not_bytes() {
        let filter = LocationFilter::absolute_start(1000, 3);
        let value = filter.encode_value();
        assert_eq!(value[0], 0x02);
        assert_eq!(value.len(), 4);
        assert_eq!(decode_location_filter(&value).unwrap(), (0x02, vec![1000, 3]));
    }

    /// None and Next Object both carry no fields and mean opposite things, so
    /// they are told apart by the type and never by the field list.
    #[test]
    fn none_and_next_object_differ_only_in_their_type() {
        assert_eq!(LocationFilter::none().fields(), LocationFilter::next_object().fields());
        assert_ne!(
            LocationFilter::none().filter_type(),
            LocationFilter::next_object().filter_type()
        );
        assert_eq!(LocationFilter::none().encode_value(), vec![0x00]);
    }

    /// The end is the last object, and nothing here adds one to it. Draft-19's
    /// encoder wrote `last + 1`; a port that kept the arithmetic fetches one
    /// object too many, and nothing on the wire distinguishes the two.
    #[test]
    fn an_end_object_is_the_last_object_and_not_one_past_it() {
        let filter = LocationFilter::range_to(10, 0, 0, 5).unwrap();
        assert_eq!(filter.fields(), &[10, 0, 0, 5]);
        let KvpValue::Bytes(bytes) = filter.parameter().unwrap().value else { panic!() };
        assert_eq!(bytes, vec![0x04, 10, 0, 0, 5]);
    }

    /// Section 9.20.9 answers the overflow with a session close, so it is
    /// refused rather than emitted.
    #[test]
    fn an_end_group_past_the_number_space_is_refused() {
        assert_eq!(
            LocationFilter::range(u64::MAX, 0, 1),
            Err(FillError::EndGroupOverflow { start_group: u64::MAX, delta: 1 })
        );
        assert!(LocationFilter::range_to(u64::MAX - 1, 0, 1, 0).is_ok());
    }

    /// Table 7 is a closed list, and the one Range Filter it leaves out is the
    /// one that selects tracks rather than objects.
    #[test]
    fn a_type_outside_table_7_may_not_be_nested() {
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
    /// caller does not have to know Table 7's numbering.
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
    /// worth having on the record: Section 9.20.21 makes it govern the **Track
    /// Properties** in an OK message, and a fill fetch stream has no OK message
    /// at all (Section 3.4.1 — no FETCH_OK, no REQUEST_ERROR). It is absent
    /// from Table 7, so nesting it is refused.
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

    /// With no `GROUP_ORDER` in either scope, Ascending. Section 9.20.8 gives a
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

    /// A bare varint under `LOCATION_FILTER` is refused rather than written as
    /// a Location Filter Type with no fields after it, which is what the codec's
    /// encoder does with the same value outside a fill.
    #[test]
    fn a_bare_varint_location_filter_is_refused() {
        for v in [0, 5] {
            let result = FillParameters::inherited()
                .with(KeyValuePair {
                    key: VarInt::from_u64_moqt(LOCATION_FILTER),
                    value: KvpValue::Varint(VarInt::from_u64_moqt(v)),
                })
                .and_then(|fill| fill.parameter());
            assert!(
                matches!(result, Err(FillError::MalformedValue { key: LOCATION_FILTER, .. })),
                "a bare varint {v} under 0x21 gave {result:?}"
            );
        }
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

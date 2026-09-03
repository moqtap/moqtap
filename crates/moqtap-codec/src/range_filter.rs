//! The Range Filters drafts 19 and 20 carry in five parameters.
//!
//! Section 5.1.3: "Range Filters are parameters in SUBSCRIBE, FETCH, or
//! SUBSCRIBE_TRACKS that tell a publisher to filter tracks (via TRACK PROPERTY
//! FILTER) and objects according to subscriber-provided criteria. Range filters
//! are specified as ranges of integer values in Track and Object Properties and
//! other Object header fields (Subgroup ID, Object ID, and Publisher Priority).
//! There are five Range Filter parameter types, 0x25-0x29, as shown below."
//!
//! Drafts 19 and 20 are the only drafts with them, and the five share one
//! value shape:
//!
//! ```text
//! SUBGROUP_FILTER        { Type=0x25, Length, [SetID], Range... }
//! OBJECTID_FILTER        { Type=0x26, Length, [SetID], Range... }
//! PRIORITY_FILTER        { Type=0x27, Length, [SetID], Range... }
//! OBJECT_PROPERTY_FILTER { Type=0x28, Length, [SetID], [Property Type], Range... }
//! TRACK_PROPERTY_FILTER  { Type=0x29, Length, [SetID], [Property Type], Range... }
//! Range                  { Start, [End] }
//! ```
//!
//! # Why this is a reader and not a check
//!
//! Every consequence Section 5.1.3 states is a **reply**, not a session close:
//! "MUST be rejected with REQUEST_ERROR with error code INVALID_FILTER" for a
//! delta that overruns, for a repeated filter key, and for more Ranges than
//! MAX_FILTER_RANGES allows. A reply is something an endpoint sends, and sending
//! it needs the request decoded — including the Request ID the reply names.
//!
//! So nothing here is wired into `decode_parameters`, and [`RangeFilterError`]
//! deliberately does not convert into [`CodecError`](crate::error::CodecError).
//! A refusal at decode time would turn a frame the endpoint owes an answer to
//! into a frame it never saw, and the subscriber would wait for a REQUEST_ERROR
//! that no longer has anything to be about. The five types are registered in
//! draft-19's parameter table as length-prefixed values, which is what keeps
//! them carried rather than refused; this module is what makes the bytes mean
//! something.
//!
//! # The delta encoding, which is not the one used elsewhere
//!
//! "Start is delta encoded from the prior Range's End or from 0 for the first
//! Range, and End is delta encoded from the current Range's Start." So the
//! baseline alternates: a Start counts from the previous End, and an End counts
//! from the Start beside it. The draft's own example is ranges 3-5 and 10-15,
//! written as 3, 2, 5, 5 — and reading it with one running baseline instead of
//! two produces 3-5 and 8-13, a range that is wrong and well formed.
//!
//! "The final End in a sequence of Ranges can be omitted to indicate no end", so
//! a value holding an odd number of integers ends in an unbounded range. Only
//! the last one may be omitted, which is what makes the pairing unambiguous.

use bytes::{Buf, BufMut};

use crate::kvp::{KeyValuePair, KvpValue};
use crate::varint::{MoqtProfile, VarInt};

/// SUBGROUP_FILTER, matching an Object's Subgroup ID.
pub const SUBGROUP_FILTER_PARAMETER: u64 = 0x25;
/// OBJECTID_FILTER, matching an Object's Object ID.
pub const OBJECT_ID_FILTER_PARAMETER: u64 = 0x26;
/// PRIORITY_FILTER, matching an Object's Publisher Priority.
pub const PRIORITY_FILTER_PARAMETER: u64 = 0x27;
/// OBJECT_PROPERTY_FILTER, matching the value of one Object Property.
pub const OBJECT_PROPERTY_FILTER_PARAMETER: u64 = 0x28;
/// TRACK_PROPERTY_FILTER, matching the value of one Track Property.
pub const TRACK_PROPERTY_FILTER_PARAMETER: u64 = 0x29;

/// Whether `parameter_type` is one of the five Range Filters.
pub fn is_range_filter(parameter_type: u64) -> bool {
    (SUBGROUP_FILTER_PARAMETER..=TRACK_PROPERTY_FILTER_PARAMETER).contains(&parameter_type)
}

/// Whether a Range Filter of this type carries a Property Type after its SetID.
///
/// The two property filters do and the three header-field filters do not: a
/// filter on Subgroup ID, Object ID or Publisher Priority already knows which
/// field it is about from its own parameter type, and a filter on a property has
/// to name which property. Reading the prefix for the wrong three shifts every
/// Range in the value by one integer.
pub fn carries_a_property_type(parameter_type: u64) -> bool {
    parameter_type == OBJECT_PROPERTY_FILTER_PARAMETER
        || parameter_type == TRACK_PROPERTY_FILTER_PARAMETER
}

/// One inclusive range of values, with the deltas already resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterRange {
    /// The first value the range admits.
    pub start: u64,
    /// The last value the range admits, or `None` for a range with no end.
    ///
    /// Only the final Range in a filter may be unbounded, because the omission
    /// is what the reader uses to tell a trailing Start from the next Range's.
    pub end: Option<u64>,
}

impl FilterRange {
    /// Whether `value` falls inside this range.
    ///
    /// Both ends are inclusive: Section 5.1.3 calls them "Start/End (vi64)
    /// inclusive Range pairs", and the example spells 3-5 as a Start of 3 and an
    /// End of 5 rather than as a half-open interval.
    pub fn contains(&self, value: u64) -> bool {
        value >= self.start && self.end.is_none_or(|end| value <= end)
    }
}

/// A decoded Range Filter parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeFilter {
    /// Which of the five filters this is.
    pub parameter_type: u64,
    /// The set this filter belongs to.
    /// "All filter parameters with the same SetID value are combined using
    /// logical 'AND' operations, then all the resulting sets are combined using
    /// logical 'OR' operations." So the SetID is not decoration: two filters
    /// under one SetID both have to pass, and two filters under different
    /// SetIDs each pass on their own.
    pub set_id: u8,
    /// The property this filter is about, on the two property filters.
    ///
    /// `None` on SUBGROUP_FILTER, OBJECTID_FILTER and PRIORITY_FILTER, whose
    /// subject is fixed by the parameter type.
    pub property_type: Option<u64>,
    /// The ranges, with every delta resolved to an absolute value.
    pub ranges: Vec<FilterRange>,
}

/// What the key of a Range Filter is, for the rule about repeats.
///
/// "If the same combination of Parameter Type, SetID, and Property Type (only in
/// the Track and Object Property Filters) repeat in any message, an endpoint
/// MUST reject this with REQUEST_ERROR with error code INVALID_FILTER."
pub type RangeFilterKey = (u64, u8, Option<u64>);

/// A Range Filter value this codec could not turn into ranges.
///
/// Kept out of [`CodecError`](crate::error::CodecError) on purpose, and the
/// absence of a `From` impl is the mechanism: draft-19 answers every one of
/// these with a REQUEST_ERROR carrying INVALID_FILTER, which is a message the
/// endpoint sends after decoding the request, so none of them may become a
/// decoder refusal. See this module's header.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RangeFilterError {
    /// A parameter type outside 0x25 through 0x29 was handed to the reader.
    #[error("parameter type {0} is not a Range Filter")]
    NotARangeFilter(u64),
    /// The value ran out before a field the shape requires.
    #[error("range filter value is malformed: {detail}")]
    Malformed {
        /// Which field was missing, for a log that says what was short.
        detail: &'static str,
    },
    /// A delta resolved past the end of the 64-bit space.
    ///
    /// "Any delta encoding that results in a value that exceeds 2^64-1 MUST be
    /// rejected with REQUEST_ERROR with error code INVALID_FILTER." The sum is
    /// checked rather than allowed to wrap: a wrapped Start is a small number,
    /// and a filter that reads as 0-5 when its sender wrote something above the
    /// end of the space passes Objects it was written to exclude.
    #[error("range filter delta {delta} past {base} runs off the end of the 64-bit space")]
    DeltaOverflow {
        /// The value the delta was counted from.
        base: u64,
        /// The delta as it arrived.
        delta: u64,
    },
    /// A PRIORITY_FILTER range names a value the field cannot hold.
    ///
    /// Section 10.2.12: "If a decoded value exceeds 255, the endpoint MUST
    /// reject this with REQUEST_ERROR with error code INVALID_FILTER since
    /// Publisher Priority is an 8-bit field."
    ///
    /// "A decoded value", so the resolved Start or End rather than the delta
    /// that spelled it — a filter of 200 to 300 has both deltas well inside the
    /// byte and one endpoint outside it.
    #[error("priority filter names {0}, which a Publisher Priority cannot hold")]
    PriorityAboveTheField(u64),
    /// A property filter names a Property Type that is not an integer-valued one.
    ///
    /// Sections 10.2.13 and 10.2.14 say the same of both: the filter selects a
    /// range "for a required Object Property Type which MUST be even, i.e. a
    /// single integer value (see Figure 2), otherwise the endpoint MUST reject
    /// this with REQUEST_ERROR with error code INVALID_FILTER".
    ///
    /// The parity is the Key-Value-Pair convention doing the work: an even Type
    /// carries a bare varint and an odd one carries length-prefixed bytes, so an
    /// odd Property Type is a property whose value is not a number and a range
    /// over it has nothing to compare.
    #[error("property filter names property type {0}, which is not an integer-valued one")]
    PropertyTypeIsNotAnInteger(u64),
}

/// The value ran out before `detail`.
const NO_SET_ID: &str = "it ends before the SetID";
const NO_PROPERTY_TYPE: &str = "it ends before the Property Type this filter type carries";

impl RangeFilter {
    /// Read a Range Filter from the bytes of its parameter value.
    ///
    /// `bytes` is the value after the Key-Value-Pair's Length has been consumed,
    /// which is what a decoded parameter holds — the Length in Section 5.1.3's
    /// figure is that same prefix and not a second one inside the value.
    /// An empty value decodes to a filter with no ranges rather than an error:
    /// "In REQUEST_UPDATE, Length can be 0 to remove a filter parameter or
    /// non-zero to replace that entire filter parameter including all sets and
    /// Property Types." The three-field filters can express that in zero bytes
    /// only if the SetID is also absent, so an empty value is taken as the
    /// removal and anything shorter than its own prefix is not.
    pub fn decode_moqt<P: MoqtProfile>(
        parameter_type: u64,
        bytes: &[u8],
    ) -> Result<Self, RangeFilterError> {
        let filter = Self::decode_moqt_structure::<P>(parameter_type, bytes)?;
        filter.check_its_own_types()?;
        Ok(filter)
    }

    /// Read a Range Filter without holding it to the two rules about its own
    /// contents that [`check_its_own_types`](Self::check_its_own_types) states.
    ///
    /// The bytes still have to be a Range Filter and still have to parse: a
    /// truncated value, a missing SetID and a delta that overflows are all
    /// refused here exactly as they are by [`decode_moqt`](Self::decode_moqt).
    /// What is not refused is a filter that decoded cleanly and then names a
    /// Publisher Priority above 255 or an odd Property Type.
    ///
    /// # When to reach for this instead
    ///
    /// A decoder must refuse those two, because they are answered with
    /// REQUEST_ERROR and passing them on would let an application act on a
    /// range the peer is not allowed to have asked for. A **renderer** must
    /// not: it is describing a message that has already been decoded, and a
    /// filter that broke a content rule is exactly the one whose fields a
    /// reader most needs to see. Refusing there degrades the rendering to
    /// opaque bytes and hides the offending value inside them.
    ///
    /// So the split is by what the caller does with the answer, not by how
    /// much checking it wants: decode with [`decode_moqt`](Self::decode_moqt),
    /// render with this and then call
    /// [`check_its_own_types`](Self::check_its_own_types) to say what is wrong
    /// alongside the fields rather than instead of them.
    pub fn decode_moqt_structure<P: MoqtProfile>(
        parameter_type: u64,
        bytes: &[u8],
    ) -> Result<Self, RangeFilterError> {
        if !is_range_filter(parameter_type) {
            return Err(RangeFilterError::NotARangeFilter(parameter_type));
        }
        if bytes.is_empty() {
            return Ok(RangeFilter {
                parameter_type,
                set_id: 0,
                property_type: None,
                ranges: Vec::new(),
            });
        }

        let mut buf = bytes;
        if buf.remaining() < 1 {
            return Err(RangeFilterError::Malformed { detail: NO_SET_ID });
        }
        let set_id = buf.get_u8();

        let property_type = if carries_a_property_type(parameter_type) {
            Some(
                VarInt::decode_moqt::<P>(&mut buf)
                    .map_err(|_| RangeFilterError::Malformed { detail: NO_PROPERTY_TYPE })?
                    .into_inner(),
            )
        } else {
            None
        };

        // Two baselines, alternating. A Start counts from the previous Range's
        // End and an End counts from the Start beside it, so the running value
        // is reset by each field rather than carried across the pair.
        let mut ranges = Vec::new();
        let mut previous_end: u64 = 0;
        while buf.has_remaining() {
            let delta = VarInt::decode_moqt::<P>(&mut buf)
                .map_err(|_| RangeFilterError::Malformed { detail: "a Range's Start is short" })?
                .into_inner();
            let start = previous_end
                .checked_add(delta)
                .ok_or(RangeFilterError::DeltaOverflow { base: previous_end, delta })?;

            if !buf.has_remaining() {
                // The final End is the only one that may be left off, and
                // leaving it off means the range has no end.
                ranges.push(FilterRange { start, end: None });
                break;
            }

            let delta = VarInt::decode_moqt::<P>(&mut buf)
                .map_err(|_| RangeFilterError::Malformed { detail: "a Range's End is short" })?
                .into_inner();
            let end = start
                .checked_add(delta)
                .ok_or(RangeFilterError::DeltaOverflow { base: start, delta })?;
            ranges.push(FilterRange { start, end: Some(end) });
            previous_end = end;
        }

        Ok(RangeFilter { parameter_type, set_id, property_type, ranges })
    }

    /// The two rules a Range Filter can break once it has decoded cleanly.
    ///
    /// Both are answered with the same REQUEST_ERROR as the delta rule, so
    /// [`decode_moqt`](Self::decode_moqt) applies them for you and a filter
    /// that reaches an application through it has already been held to
    /// everything Section 5.1.3 and Sections 10.2.12 through 10.2.14 state
    /// about its own contents. What is left for the session to decide is the
    /// ceiling and the repeats, which need more than one parameter to see.
    ///
    /// It is public so that a caller which decoded with
    /// [`decode_moqt_structure`](Self::decode_moqt_structure) can still ask the
    /// question — and, having the filter in hand, report the answer beside the
    /// fields rather than in place of them.
    pub fn check_its_own_types(&self) -> Result<(), RangeFilterError> {
        if let Some(property_type) = self.property_type {
            if !property_type.is_multiple_of(2) {
                return Err(RangeFilterError::PropertyTypeIsNotAnInteger(property_type));
            }
        }
        if self.parameter_type == PRIORITY_FILTER_PARAMETER {
            for range in &self.ranges {
                for value in [Some(range.start), range.end].into_iter().flatten() {
                    if value > 255 {
                        return Err(RangeFilterError::PriorityAboveTheField(value));
                    }
                }
            }
        }
        Ok(())
    }

    /// Write this filter as a parameter value.
    ///
    /// Refuses what the decoder refuses, and one thing more: a range whose End is
    /// below its Start, and an unbounded range anywhere but last. Both encode
    /// perfectly well and neither reads back as what was written — a backwards
    /// End wraps its delta into a nine-byte integer that resolves to an
    /// unrelated value, and an unbounded range in the middle silently pairs its
    /// successor's Start as its own End.
    pub fn encode_moqt<P: MoqtProfile>(
        &self,
        buf: &mut impl BufMut,
    ) -> Result<(), RangeFilterError> {
        if !is_range_filter(self.parameter_type) {
            return Err(RangeFilterError::NotARangeFilter(self.parameter_type));
        }
        match (carries_a_property_type(self.parameter_type), self.property_type) {
            (true, None) => {
                return Err(RangeFilterError::Malformed {
                    detail: "this filter type carries a Property Type and none was given",
                })
            }
            (false, Some(_)) => {
                return Err(RangeFilterError::Malformed {
                    detail: "this filter type carries no Property Type and one was given",
                })
            }
            _ => {}
        }
        self.check_its_own_types()?;

        let mut out = Vec::new();
        out.push(self.set_id);
        if let Some(property_type) = self.property_type {
            VarInt::from_u64_moqt(property_type).encode_moqt::<P>(&mut out);
        }

        let mut previous_end: u64 = 0;
        for (index, range) in self.ranges.iter().enumerate() {
            let start_delta =
                range.start.checked_sub(previous_end).ok_or(RangeFilterError::Malformed {
                    detail: "the Ranges are not in ascending order",
                })?;
            VarInt::from_u64_moqt(start_delta).encode_moqt::<P>(&mut out);

            match range.end {
                Some(end) => {
                    let end_delta =
                        end.checked_sub(range.start).ok_or(RangeFilterError::Malformed {
                            detail: "a Range ends before it starts",
                        })?;
                    VarInt::from_u64_moqt(end_delta).encode_moqt::<P>(&mut out);
                    previous_end = end;
                }
                None if index + 1 == self.ranges.len() => {}
                None => {
                    return Err(RangeFilterError::Malformed {
                        detail: "only the final Range may be left open",
                    })
                }
            }
        }

        buf.put_slice(&out);
        Ok(())
    }

    /// Whether `value` passes this filter.
    ///
    /// A filter with no ranges passes nothing, which is what a filter that lists
    /// no acceptable values says. The removal form of a REQUEST_UPDATE is the
    /// same shape on the wire and is not the same statement, so a caller acting
    /// on an update reads the removal from the parameter's zero Length before it
    /// asks anything to pass.
    pub fn passes(&self, value: u64) -> bool {
        self.ranges.iter().any(|range| range.contains(value))
    }

    /// This filter's key for the rule about repeats.
    pub fn key(&self) -> RangeFilterKey {
        (self.parameter_type, self.set_id, self.property_type)
    }
}

/// Read every Range Filter in a decoded parameter list, in the order they arrive.
///
/// Parameters that are not Range Filters are skipped, so this can be handed the
/// whole list a message carries.
pub fn decode_all_moqt<P: MoqtProfile>(
    parameters: &[KeyValuePair],
) -> Result<Vec<RangeFilter>, RangeFilterError> {
    let mut filters = Vec::new();
    for parameter in parameters {
        let parameter_type = parameter.key.into_inner();
        if !is_range_filter(parameter_type) {
            continue;
        }
        let bytes = match &parameter.value {
            KvpValue::Bytes(bytes) => bytes.as_slice(),
            // Unreachable from draft-19's decoder, which picks the shape from
            // the parameter table and finds all five length-prefixed. A caller
            // that built the pair in memory can still get here.
            KvpValue::Varint(_) => {
                return Err(RangeFilterError::Malformed {
                    detail: "its value is a bare varint where the type defines a filter",
                })
            }
        };
        filters.push(RangeFilter::decode_moqt::<P>(parameter_type, bytes)?);
    }
    Ok(filters)
}

/// The total number of Ranges across `filters`.
///
/// This is the count MAX_FILTER_RANGES bounds: "Range Filters are only allowed
/// if the setup option MAX_FILTER_RANGES is non-zero, which limits the total
/// number of Ranges allowed in all Range Filter parameters for a given
/// subscription or fetch." Across all of them, so a peer cannot spend the budget
/// a parameter at a time.
///
/// The ceiling itself is not applied here. It comes from a Setup Option, it is
/// per subscription rather than per message, and exceeding it is answered with a
/// REQUEST_ERROR — three reasons it belongs to whatever holds the session.
pub fn total_ranges(filters: &[RangeFilter]) -> usize {
    filters.iter().map(|filter| filter.ranges.len()).sum()
}

/// The first key that appears twice, if any.
///
/// "If the same combination of Parameter Type, SetID, and Property Type (only in
/// the Track and Object Property Filters) repeat in any message, an endpoint
/// MUST reject this with REQUEST_ERROR with error code INVALID_FILTER."
///
/// Repeats of a Range Filter type are otherwise expected — "The Track Property
/// filter parameter MAY appear multiple times in a SUBSCRIBE_TRACKS message" —
/// so the type alone is not the key and a check written against it would refuse
/// what the same section permits two paragraphs earlier.
pub fn first_repeated_key(filters: &[RangeFilter]) -> Option<RangeFilterKey> {
    let mut seen: Vec<RangeFilterKey> = Vec::with_capacity(filters.len());
    for filter in filters {
        let key = filter.key();
        if seen.contains(&key) {
            return Some(key);
        }
        seen.push(key);
    }
    None
}

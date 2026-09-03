//! The subscription filter drafts 15 through 19 carry inside a parameter.
//!
//! Through draft-14 a subscription's filter is a group of fields on SUBSCRIBE
//! and its relatives: a Filter Type, and the Start Location and End Group that
//! type promises. Draft-15 moved the whole group into one length-prefixed
//! parameter, and draft-19 renamed that parameter from SUBSCRIPTION_FILTER to
//! LOCATION_FILTER while leaving both its type number, 0x21, and its contents
//! alone.
//!
//! Draft-20 rebuilt that value — the Filter Type enum is gone and the shape
//! comes from the field count — so it reads its own filters through
//! `draft20::message::decode_location_filter` and does not use this module.
//! That name is spelled rather than linked because the module it names is
//! behind a feature flag, and a link would be broken in any build that leaves
//! draft-20 out.
//!
//! The move is why this module exists. A parameter value is a run of bytes, and
//! a codec that carries it as bytes carries the Filter Type with it — including
//! the values the drafts require a receiver to close the session over, and
//! including the Start Location a relay needs in order to know which Objects it
//! was asked for.

use bytes::{Buf, BufMut};

use crate::error::CodecError;
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::{FilterType, Location};
use crate::varint::{MoqtProfile, VarInt, VarIntError};

/// The parameter type carrying a subscription filter on drafts 15 and later.
///
/// Named SUBSCRIPTION_FILTER on drafts 15 through 18 and LOCATION_FILTER on
/// draft-19, which introduced a second family of filter parameters and renamed
/// this one to say which kind it is. The number did not move.
pub const SUBSCRIPTION_FILTER_PARAMETER: u64 = 0x21;

/// The end of an AbsoluteRange filter, in whichever of the two forms the draft
/// that carried it writes.
///
/// Drafts 15 and 16 write the End Group out: "AbsoluteRange (0x4): The filter
/// Start Location and End Group are specified explicitly... End Group MUST
/// specify the same or a larger Group than specified in Start Location."
///
/// Drafts 17 and later write a delta instead: "If the specified End Group Delta
/// is zero, the remainder of that Group passes the filter. Otherwise, the last
/// Group ID to be delivered will be the Group ID in Start Location plus the End
/// Group Delta."
///
/// The two spell the same intent and do not spell it the same way. A delta of
/// zero bounds the range to the starting group; an absolute End Group of zero
/// bounds it to group zero, which is a range that usually excludes its own start.
/// Resolving one into the other is [`SubscriptionFilter::last_group`], and it is
/// the only place the two forms meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterEnd {
    /// The End Group as drafts 15 and 16 put it on the wire: the last Group ID
    /// that passes the filter, in full.
    Group(u64),
    /// The End Group Delta as drafts 17 and later put it on the wire, measured
    /// from the Start Location's Group.
    GroupDelta(u64),
}

/// A decoded subscription filter.
///
/// The fields after the Filter Type are the ones that type promises, which is
/// why they are optional here and why both directions check them against it: an
/// AbsoluteStart filter puts a Start Location on the wire and no End Group, and
/// the two open-ended types put neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFilter {
    /// Which of the fields below the filter carries, and where the subscription
    /// starts when it carries none.
    pub filter_type: FilterType,
    /// Present on AbsoluteStart and AbsoluteRange.
    pub start_location: Option<Location>,
    /// Present on AbsoluteRange alone.
    pub end_group: Option<FilterEnd>,
}

/// Report a parameter value that is not a filter.
///
/// Drafts 15 and 16 answer this with PROTOCOL_VIOLATION and drafts 17 through 19
/// with KEY_VALUE_FORMATTING_ERROR, so the variant carries the malformation and
/// each draft's session table carries the code.
fn malformed(detail: &'static str) -> CodecError {
    CodecError::SubscriptionFilterMalformed { detail }
}

const NO_FILTER_TYPE: &str = "it carries no Filter Type";
const NO_START: &str = "its Filter Type promises a Start Location and the value ends first";
const NO_END: &str = "its Filter Type promises an End Group and the value ends first";
const TRAILING: &str = "bytes follow the filter inside the parameter";
const START_MISSING: &str = "its Filter Type promises a Start Location and none is set";
const START_SURPLUS: &str = "its Filter Type promises no Start Location and one is set";
const END_MISSING: &str = "its Filter Type promises an End Group and none is set";
const END_SURPLUS: &str = "its Filter Type promises no End Group and one is set";
const END_IS_DELTA: &str = "its End Group is a delta where this draft writes the group in full";
const END_IS_ABSOLUTE: &str = "its End Group is written in full where this draft writes a delta";

impl SubscriptionFilter {
    /// Whether this Filter Type puts a Start Location on the wire.
    fn wants_start(filter_type: FilterType) -> bool {
        matches!(filter_type, FilterType::AbsoluteStart | FilterType::AbsoluteRange)
    }

    /// Whether this Filter Type puts an End Group on the wire.
    fn wants_end(filter_type: FilterType) -> bool {
        matches!(filter_type, FilterType::AbsoluteRange)
    }

    /// Decode a filter from a draft-15 or draft-16 parameter value: QUIC
    /// variable-length integers, and an End Group written out in full.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_with(bytes, FilterEnd::Group, |buf: &mut &[u8]| VarInt::decode(buf))
    }

    /// Decode a filter from a draft-17, draft-18 or draft-19 parameter value:
    /// MoQT variable-length integers, and an End Group Delta.
    pub fn decode_moqt<P: MoqtProfile>(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_with(bytes, FilterEnd::GroupDelta, |buf: &mut &[u8]| {
            VarInt::decode_moqt::<P>(buf)
        })
    }

    /// The body both readers share, taking the integer encoding and the End
    /// Group spelling as parameters.
    ///
    /// A read that runs out of bytes is not [`CodecError::UnexpectedEnd`] here.
    /// The frame is intact and the parameter's declared length was satisfied;
    /// what ran out is the filter inside it, which is the rule drafts 15 and 16
    /// state in as many words — "If the length of the Subscription Filter does
    /// not match the parameter length" — and which the general key-value rule
    /// covers on the drafts after them. Reporting a truncated frame instead
    /// would send it to a table arm that answers with no close at all.
    ///
    /// Only running out is treated that way. An integer that is present and not
    /// a legal integer — a seven-byte length on a draft-17 session, which that
    /// draft calls an invalid code point and answers with PROTOCOL_VIOLATION —
    /// is a rule of its own, and it is reported as itself so that each draft's
    /// table can answer it as its own draft does rather than as a filter that
    /// did not match its type.
    fn decode_with<F>(
        bytes: &[u8],
        end: fn(u64) -> FilterEnd,
        mut read: F,
    ) -> Result<Self, CodecError>
    where
        F: FnMut(&mut &[u8]) -> Result<VarInt, VarIntError>,
    {
        /// Map only *the value ended here* onto the filter's own rule.
        fn ran_out(err: VarIntError, detail: &'static str) -> CodecError {
            match err {
                VarIntError::UnexpectedEnd => malformed(detail),
                other => CodecError::VarInt(other),
            }
        }

        let mut buf = bytes;
        let raw = read(&mut buf).map_err(|e| ran_out(e, NO_FILTER_TYPE))?.into_inner();
        let filter_type = FilterType::from_u64(raw).ok_or(CodecError::InvalidFilterType(raw))?;

        let start_location = if Self::wants_start(filter_type) {
            let group = read(&mut buf).map_err(|e| ran_out(e, NO_START))?;
            let object = read(&mut buf).map_err(|e| ran_out(e, NO_START))?;
            Some(Location { group, object })
        } else {
            None
        };

        let end_group = if Self::wants_end(filter_type) {
            Some(end(read(&mut buf).map_err(|e| ran_out(e, NO_END))?.into_inner()))
        } else {
            None
        };

        if buf.has_remaining() {
            return Err(malformed(TRAILING));
        }

        Ok(SubscriptionFilter { filter_type, start_location, end_group })
    }

    /// Write this filter as a draft-15 or draft-16 parameter value.
    ///
    /// Refuses a filter whose fields disagree with its own Filter Type, for the
    /// reason the decoder derives presence from that type: a filter with a
    /// surplus field is written out and read back short, and one with a missing
    /// field is written short and read back out of whatever follows it in the
    /// parameter block.
    /// Also refuses a value the QUIC integer encoding cannot spell. That
    /// encoding stops at 2^62 - 1 and the fields here are 64-bit, so a Start
    /// Location group above the limit would otherwise go out as an unrelated
    /// number with the length bits folded into it.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        self.encode_with(false, buf, |v, out| {
            VarInt::from_u64(v)?.encode(out);
            Ok(())
        })
    }

    /// Write this filter as a draft-17, draft-18 or draft-19 parameter value.
    ///
    /// The same field checks, and no range check: the MoQT integer encoding
    /// reaches the whole 64-bit range, so every value these fields can hold has
    /// a representation.
    pub fn encode_moqt<P: MoqtProfile>(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        self.encode_with(true, buf, |v, out| {
            VarInt::from_u64_moqt(v).encode_moqt::<P>(out);
            Ok(())
        })
    }

    fn encode_with<W>(
        &self,
        end_is_delta: bool,
        buf: &mut impl BufMut,
        write: W,
    ) -> Result<(), CodecError>
    where
        W: Fn(u64, &mut Vec<u8>) -> Result<(), CodecError>,
    {
        let wants_start = Self::wants_start(self.filter_type);
        if wants_start && self.start_location.is_none() {
            return Err(malformed(START_MISSING));
        }
        if !wants_start && self.start_location.is_some() {
            return Err(malformed(START_SURPLUS));
        }

        let wants_end = Self::wants_end(self.filter_type);
        let end = match (wants_end, self.end_group) {
            (true, None) => return Err(malformed(END_MISSING)),
            (false, Some(_)) => return Err(malformed(END_SURPLUS)),
            (_, value) => value,
        };
        match end {
            Some(FilterEnd::GroupDelta(_)) if !end_is_delta => {
                return Err(malformed(END_IS_DELTA));
            }
            Some(FilterEnd::Group(_)) if end_is_delta => {
                return Err(malformed(END_IS_ABSOLUTE));
            }
            _ => {}
        }

        let mut out = Vec::new();
        write(self.filter_type as u64, &mut out)?;
        if let Some(start) = self.start_location {
            write(start.group.into_inner(), &mut out)?;
            write(start.object.into_inner(), &mut out)?;
        }
        if let Some(FilterEnd::Group(v) | FilterEnd::GroupDelta(v)) = end {
            write(v, &mut out)?;
        }
        buf.put_slice(&out);
        Ok(())
    }

    /// This filter as the parameter a draft-15 or draft-16 message carries it
    /// in.
    ///
    /// The reason to have it: from draft-15 a client asking for a range hands
    /// its endpoint a parameter list, and the filter inside it is a run of bytes
    /// the caller has to assemble. Assembled by hand it is assembled wrong — the
    /// fields present depend on the Filter Type, and a frame short by the ones
    /// it promised is one the peer reads off the end of.
    pub fn parameter(&self) -> Result<KeyValuePair, CodecError> {
        let mut value = Vec::new();
        self.encode(&mut value)?;
        Ok(KeyValuePair {
            key: VarInt::from_u64_moqt(SUBSCRIPTION_FILTER_PARAMETER),
            value: KvpValue::Bytes(value),
        })
    }

    /// This filter as the parameter a draft-17, draft-18 or draft-19 message
    /// carries it in.
    pub fn parameter_moqt<P: MoqtProfile>(&self) -> Result<KeyValuePair, CodecError> {
        let mut value = Vec::new();
        self.encode_moqt::<P>(&mut value)?;
        Ok(KeyValuePair {
            key: VarInt::from_u64_moqt(SUBSCRIPTION_FILTER_PARAMETER),
            value: KvpValue::Bytes(value),
        })
    }

    /// The filter carried by a message's parameter list, if it carries one.
    ///
    /// `None` when no filter parameter is present, which every draft from 15 on
    /// defines as an unfiltered subscription rather than as an omission.
    pub fn from_parameters(parameters: &[KeyValuePair]) -> Option<Result<Self, CodecError>> {
        Self::from_parameters_with(parameters, Self::decode)
    }

    /// The same, reading the MoQT integer encoding of drafts 17 and later.
    pub fn from_parameters_moqt<P: MoqtProfile>(
        parameters: &[KeyValuePair],
    ) -> Option<Result<Self, CodecError>> {
        Self::from_parameters_with(parameters, Self::decode_moqt::<P>)
    }

    fn from_parameters_with(
        parameters: &[KeyValuePair],
        decode: fn(&[u8]) -> Result<Self, CodecError>,
    ) -> Option<Result<Self, CodecError>> {
        let parameter =
            parameters.iter().find(|p| p.key.into_inner() == SUBSCRIPTION_FILTER_PARAMETER)?;
        match &parameter.value {
            KvpValue::Bytes(value) => Some(decode(value)),
            KvpValue::Varint(_) => {
                Some(Err(malformed("its value is a bare varint where the type defines a filter")))
            }
        }
    }

    /// The last Group ID that passes this filter, or `None` when the filter is
    /// open ended.
    ///
    /// Errors when the sum leaves the number space, which is a rule drafts 18
    /// and 19 state and draft-17, which introduced the delta, does not. The
    /// caller decides whether its draft answers that with a close; every draft
    /// needs the addition itself, because a subscription bounded by a delta is
    /// bounded by nothing a comparison can use until the delta is resolved.
    pub fn last_group(&self) -> Result<Option<u64>, CodecError> {
        match self.end_group {
            None => Ok(None),
            Some(FilterEnd::Group(group)) => Ok(Some(group)),
            Some(FilterEnd::GroupDelta(delta)) => {
                let start_group =
                    self.start_location.map(|l| l.group.into_inner()).unwrap_or_default();
                start_group
                    .checked_add(delta)
                    .map(Some)
                    .ok_or(CodecError::FilterEndGroupOverflow { start_group, delta })
            }
        }
    }
}

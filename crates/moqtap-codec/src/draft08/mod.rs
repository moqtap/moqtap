//! MoQT wire codec for draft-08.
//!
//! Changes from draft-07:
//! - The ROLE setup parameter is gone. Draft-07 requires it of both endpoints;
//!   draft-08 does not mention it, and no later draft brings it back.
//! - Object Extension Headers arrive, as `Extension Count` — a number of
//!   headers, not a byte length. Draft-09 changes the field to a byte length,
//!   so this is the only draft where the two can disagree.
//! - SUBSCRIBES_BLOCKED (0x1A) arrives, beside the MAX_SUBSCRIBE_ID message
//!   draft-07 already had.
//! - OBJECT_DATAGRAM_STATUS (0x2) arrives beside OBJECT_DATAGRAM.
//! - FETCH gains a Fetch Type, and with it the Joining Fetch.
//! - SUBSCRIBE's AbsoluteRange filter loses EndObject and ends at a group.
//! - `Track Does Not Exist` enters the SUBSCRIBE_ERROR and FETCH_ERROR
//!   registries at 0x4, moving `Invalid Range` to 0x5.
//! - A server receiving a GOAWAY that carries a New Session URI must close the
//!   session; draft-07 states no such rule.
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
/// Session termination, error and status code registries.
pub mod error_codes;
/// Control message types with encode/decode.
pub mod message;
/// Draft-08 specific types.
pub mod types;

//! MoQT wire codec for draft-19.
//!
//! Key changes from draft-18:
//! - `Request ID` field removed from GOAWAY entirely; control-stream and
//!   request-stream GOAWAY now share one format
//! - New Range Filter parameters (length-prefixed): SUBGROUP_FILTER (0x25),
//!   OBJECTID_FILTER (0x26), PRIORITY_FILTER (0x27), OBJECT_PROPERTY_FILTER
//!   (0x28) and TRACK_PROPERTY_FILTER (0x29)
//! - New Setup Options MAX_FILTER_RANGES (0x06) and MAX_REQUEST_UPDATES (0x08)
//!   (even KVP types, varint values)
//! - GROUP_ORDER (0x22) moves from PUBLISH_OK to SUBSCRIBE_TRACKS
//! - PUBLISH_BLOCKED renamed to PUBLISH_SKIPPED (still type 0x0F, wire
//!   identical)
//! - SUBSCRIPTION_FILTER renamed to LOCATION_FILTER (still parameter 0x21)
//! - REQUEST_ERROR adds CONFLICTING_FILTERS (0x35) and INVALID_FILTER (0x36);
//!   DUPLICATE_SUBSCRIPTION (0x19) removed as multiple concurrent
//!   subscriptions per Track are now allowed
//! - Session error TOO_MANY_REQUEST_UPDATES (0x1B) added
//! - Data stream headers (subgroup, datagram, fetch) are byte-for-byte
//!   identical to draft-18

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Object status values for draft-19.
pub mod types;

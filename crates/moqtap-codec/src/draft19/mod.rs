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
//! - Object Status gets its own IANA registry (Section 15.9, Table 16) with a
//!   `Payload` column, and Section 11.2.1.1 defers to it: an Object has an
//!   empty payload "unless its Object Status value is registered as permitting
//!   a payload". Draft-18 stated one blanket rule for every status instead —
//!   any non-zero status means an empty payload — so the answer used to be
//!   arithmetic on the code point and is now registry data, which every future
//!   registration must supply. The three assigned code points are unchanged
//!   (0x0 Normal, 0x3 End of Group, 0x4 End of Track) and the two rules happen
//!   to agree on all three. Modelled as `types::PayloadPermission`
//! - The control-message framing field after Message Length is renamed from
//!   Message Payload to Message Body (Section 10, Figure 3). Editorial: the
//!   bytes are unchanged
//! - OBJECT_DELIVERY_TIMEOUT (Property Type 0x02) and
//!   SUBGROUP_DELIVERY_TIMEOUT (0x06) become Track *and* Object Properties
//!   (Section 15.8, Table 14; they were Track-only in draft-18). Section 8
//!   gives the new scope its meaning: set as an Object Property on the first
//!   object in a subgroup either value overrides the Track-level value for
//!   that subgroup, and on any other object in the subgroup it is ignored.
//!   This codec carries Object Properties as an opaque blob, so the change is
//!   recorded here rather than modelled
//! - The 1-byte Property Type range reserved for application-specific use
//!   moves from 0x38-0x3F to 0x78-0x7F (Section 2.5). The 2-byte range
//!   0x3800-0x3FFF is unchanged. Draft-18 had assigned PRIOR_GROUP_ID_GAP
//!   (0x3C) and PRIOR_OBJECT_ID_GAP (0x3E) inside its own reserved range;
//!   draft-19 resolves that by moving the range and leaving the two
//!   assignments where they are

#[allow(missing_docs)]
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod types;

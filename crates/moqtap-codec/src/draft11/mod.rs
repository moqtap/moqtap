//! MoQT wire codec for draft-11.
//!
//! Key changes from draft-09/10:
//! - Setup IDs 0x20/0x21; `request_id` replaces `subscribe_id`
//! - Even/odd KVP encoding; VarInt group_order/forward/filter_type
//! - Announce/SubscribeAnnounces restructured with request_id
//! - Fetch gains 3 types (Standalone, RelativeJoining, AbsoluteJoining)
//! - Framing: type_id(vi) + payload_length(16) + payload

/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
/// Control message types with encode/decode.
pub mod message;
/// Draft-11 types.
pub mod types;

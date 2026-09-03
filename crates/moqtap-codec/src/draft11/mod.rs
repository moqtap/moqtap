//! MoQT wire codec for draft-11.
//!
//! Key changes from draft-09/10:
//! - Setup IDs 0x20/0x21; `request_id` replaces `subscribe_id`
//! - Even/odd KVP encoding; VarInt group_order/forward/filter_type
//! - Announce/SubscribeAnnounces restructured with request_id
//! - Fetch gains 3 types (Standalone, RelativeJoining, AbsoluteJoining)
//! - Framing: type_id(vi) + payload_length(16) + payload

pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
pub mod message;
pub mod types;

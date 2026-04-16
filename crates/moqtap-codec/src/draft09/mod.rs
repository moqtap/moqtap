//! MoQT wire codec for draft-09.
//!
//! Changes from draft-08:
//! - `extension_count` → `extension_headers_length` in data stream object headers
//! - Datagrams no longer have `payload_length` or `object_status` — payload is remaining bytes
//! - DatagramStatus gains `extension_headers_length` field
//! - `filter_type=1` (LatestGroup/NextGroupStart) removed from SUBSCRIBE
pub mod data_stream;
pub mod message;
pub mod types;

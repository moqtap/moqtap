//! MoQT wire codec for draft-13.
//!
//! Key changes from draft-12:
//! - `subscribe_announces` → `subscribe_namespace` (0x11–0x14)
//! - TrackStatusRequest (0x0D) → TrackStatus with subscribe-like fields
//! - TrackStatus (0x0E) → TrackStatusOk with subscribe_ok-like fields
//! - New TrackStatusError (0x0F)

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Draft-13 types.
pub mod types;

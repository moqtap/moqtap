//! MoQT wire codec for draft-12.
//!
//! Key changes from draft-11:
//! - `track_alias` moves from Subscribe to SubscribeOk
//! - SubscribeError no longer has trailing `track_alias`
//! - New messages: Publish (0x1D), PublishOk (0x1E), PublishError (0x1F)
//! - Subgroup stream type IDs shift from 0x08-0x0D to 0x10-0x15

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Draft-12 types.
pub mod types;

//! MoQT wire codec for draft-12.
//!
//! Key changes from draft-11:
//! - `track_alias` moves from Subscribe to SubscribeOk
//! - SubscribeError no longer has trailing `track_alias`
//! - New messages: Publish (0x1D), PublishOk (0x1E), PublishError (0x1F)
//! - Subgroup stream type IDs shift from 0x08-0x0D to 0x10-0x15

#[allow(missing_docs)]
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod types;

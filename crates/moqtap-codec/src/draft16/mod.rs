//! MoQT wire codec for draft-16.
//!
//! Key changes from draft-15:
//! - SubscribeUpdate → RequestUpdate (0x02), field renamed to existing_request_id
//! - New: Namespace (0x08), NamespaceDone (0x0e) — namespace_suffix only
//! - Removed: UnsubscribeNamespace (0x14)
//! - RequestError gains retry_interval field
//! - SubscribeNamespace gains subscribe_options varint
//! - PublishNamespaceDone simplifies to just request_id

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Draft-16 types.
pub mod types;

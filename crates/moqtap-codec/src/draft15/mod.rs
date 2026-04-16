//! MoQT wire codec for draft-15.
//!
//! Key changes from draft-14:
//! - Version negotiation moves to ALPN (no versions in ClientSetup/ServerSetup)
//! - Consolidated RequestOk (0x07) and RequestError (0x05) replace per-type ok/error
//! - Subscribe/SubscribeOk/Publish/PublishOk simplified — fields moved to parameters
//! - New: PublishNamespace (0x06), PublishNamespaceDone (0x09), PublishNamespaceCancel (0x0C)
//! - PublishDone (0x0B) replaces SubscribeDone
//! - FetchOk: end_group/end_object inline instead of Location struct
//! - SubscribeUpdate: request_id + subscription_request_id + params
//! - Framing: type_id(vi) + payload_length(16) + payload
//! - Data streams: delta-encoded object IDs, priority bit flag, serialization flags

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Draft-15 types.
pub mod types;

//! MoQT wire codec for draft-17.
//!
//! Key changes from draft-16:
//! - Unified SETUP (0x2F00) replaces ClientSetup/ServerSetup
//! - Control message framing: Type (varint) + Length (16-bit) + Payload
//! - Parameters use delta-encoded types with type-specific value encoding
//! - RequestOk/RequestError/PublishOk/PublishDone/FetchOk: no request_id
//! - Request messages gain required_request_id_delta field
//! - New PublishBlocked (0x0F)
//! - FetchType gains AbsoluteJoining (0x03)
//! - SubscribeOk/Publish/FetchOk gain track_properties
//! - GoAway gains timeout field
//! - Removed: MaxRequestId, RequestsBlocked, Unsubscribe, PublishNamespaceDone,
//!   PublishNamespaceCancel, FetchCancel, ClientSetup, ServerSetup

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Object status values for draft-17.
pub mod types;

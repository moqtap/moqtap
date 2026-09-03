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
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod types;

//! MoQT wire codec for draft-18.
//!
//! Key changes from draft-17:
//! - `Required Request ID Delta` field removed from every request message
//! - SUBSCRIBE_NAMESPACE renumbered to 0x50 and `subscribe_options` removed;
//!   FORWARD parameter moves to the new SUBSCRIBE_TRACKS (0x51) message
//! - PUBLISH_OK collapsed into REQUEST_OK (0x07); REQUEST_OK gains a trailing
//!   Track Properties block
//! - GOAWAY gains an optional `request_id` (present only on the control stream);
//!   may also be sent on individual request streams
//! - REQUEST_ERROR adds REDIRECT (0x34) with a Redirect structure and
//!   UNSUPPORTED_EXTENSION (0x33)
//! - DELIVERY_TIMEOUT renamed to OBJECT_DELIVERY_TIMEOUT (still type 0x02);
//!   new SUBGROUP_DELIVERY_TIMEOUT (0x06) and FILL_TIMEOUT (0x0A) parameters
//! - New TRACK_NAMESPACE_PREFIX parameter (0x34) for REQUEST_UPDATE
//! - PUBLISH_DONE status codes 0x5/0x6 swapped: 0x5 = TOO_FAR_BEHIND,
//!   0x6 = EXPIRED
//! - SUBGROUP_HEADER gains FIRST_OBJECT bit (0x40); type ranges expand to
//!   0x10..0x1F, 0x30..0x3F, 0x50..0x5F, 0x70..0x7F
//! - FETCH stream objects use delta-encoded Group ID and Object ID

#[allow(missing_docs)]
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
#[allow(missing_docs)]
/// Control message types with encode/decode.
pub mod message;
#[allow(missing_docs)]
/// Object status values for draft-18.
pub mod types;

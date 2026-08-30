//! MoQT wire codec for draft-14.
//!
//! Changes from draft-13:
//! - Object IDs are delta encoded within a subgroup. Draft-13 and everything
//!   before it wrote them absolutely, so nothing on the wire stopped a
//!   publisher writing them out of order; from here on a repeat or a decrease
//!   has no encoding at all.
//! - A bit in the Datagram Type carries Object ID = 0, so the field is absent
//!   on the datagrams that would have spent a byte saying zero.
//! - ANNOUNCE becomes PUBLISH_NAMESPACE and SUBSCRIBE_DONE becomes
//!   PUBLISH_DONE, with the surrounding OK/ERROR/CANCEL messages renamed to
//!   match.
//! - SUBSCRIBE_UPDATE gains a Request ID.
//! - FETCH is reorganised, and the range rule it states is narrowed to
//!   "Standalone and Absolute Joining Fetches".
//! - The AUTHORITY setup parameter arrives, as does a free-form parameter
//!   naming the sender's implementation.
//! - Two extension headers arrive: Prior Object ID Gap, and one carrying
//!   immutable extensions.
//! - TRACK_STATUS joins the request types a GOAWAY affects.

/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
/// Error, status and stream-reset code registries.
pub mod error_codes;
/// Control message types with encode/decode.
pub mod message;
/// Draft-14 specific types (object status, etc.).
pub mod types;

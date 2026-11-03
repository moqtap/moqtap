//! MoQT wire codec for draft-23.
//!
//! The ALPN is `moqt-23`. The draft-23 wire format:
//!
//! - **The control message Length is a `vi64`** (Section 9, Figure 6) and is
//!   bounded by the receiver's MAX_CONTROL_MESSAGE_SIZE, Setup Option 0x09
//!   (Section 9.1.8), 65535 unless advertised higher. 0x09 is odd, so its
//!   value is a Length and one `vi64`.
//! - **FETCH is answered by REQUEST_OK.** Type 0x18 is "RESERVED (FETCH_OK in
//!   <= 22)" (Table 5). A FETCH_OK may carry EXPIRES and LARGEST_OBJECT and
//!   Track Properties (Section 9.3).
//! - **REQUEST_ERROR ends in Error Details**, Key-Value-Pairs (Section
//!   9.4.1): REDIRECT 0x01, which MUST accompany Error Code REDIRECT, and
//!   UNSUPPORTED_PROPERTY 0x02 (Section 9.4.2.1, Section 9.4.2.2).
//! - **NAMESPACE carries a parameter block** (Section 9.15, Figure 20).
//! - **`FILL_PARAMETERS` (0x23) is a count, not a length** (Section 9.19.15),
//!   and may appear in PUBLISH and SUBSCRIBE_TRACKS.
//! - **`PAUSED` (0x11)**, default 0 (Section 9.19.18), and
//!   **`SUBSCRIBE_TRACKS_ID` (0x36)** (Section 9.19.21).
//! - **A Track Name MUST NOT be empty** (Section 2.4.1).
//! - **Fetch streams**: an Object ID Delta in the same Group adds `delta + 2`
//!   (Section 11.4.1.1); End of Range indicators are delta encoded (Section
//!   11.4.2.1); Table 8 adds End of Gone Range `0x40C`, End of Group `0x80`
//!   and End of Track `0x81`.
//! - **Session termination codes 0x200-0x203, 0x300-0x306 and 0x400-0x401**,
//!   and 0x6 MALFORMED_KEY_VALUE (Section 12.2). REQUEST_ERROR has
//!   UNAVAILABLE 0xA and PUBLISH_DONE has EXPIRED_AUTH_TOKEN 0x7 (Section 12.3
//!   and Section 12.4); neither REQUEST_ERROR 0x30 nor stream reset 0x6 is
//!   assigned.
//!
//! # Where this codec had to choose
//!
//! Each decision is recorded at the site that makes it:
//!
//! - MAX_CONTROL_MESSAGE_SIZE is read as Length plus exactly one `vi64`, and
//!   a value below 65535 is decoded as it arrived and refused on encode —
//!   [`message::decode_max_control_message_size`]
//! - the limit applies to the Message Length field, the body alone —
//!   [`message::ControlMessage::decode_with_limit`]
//! - a REDIRECT Error Detail's Track Name may be empty, and a repeated REDIRECT
//!   detail is decoded and refused on encode — [`message::Redirect`]
//! - any parameter in NAMESPACE is out of scope, because no parameter
//!   definition names NAMESPACE — [`message::Namespace`]
//! - `Object Payload Length` is present on an End of Range indicator, encoded
//!   as 0, and absent on End of Group and End of Track —
//!   [`data_stream::FetchObjectHeader`]
//! - after End of Group or End of Track the prior Object ID is 2^64-1 for
//!   every later entry, indicators included, and either one as the first
//!   entry is refused — [`data_stream::FetchObjectReader`]
//!
//! # What this codec does not enforce
//!
//! REQUEST_UPDATE (Section 9.5) and REQUEST_OK (Section 9.3) list their
//! parameters per kind of request. Which list applies depends on the request
//! the frame answers or updates, which is session state, so
//! [`message::parameter_in_scope`] holds each to the union of its lists.
//! [`message::RequestOk::check_answers`] applies one REQUEST_OK list and the
//! Track Properties rule when the caller knows the request.

#[allow(missing_docs)]
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod types;

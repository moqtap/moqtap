//! MoQT wire codec for draft-22.
//!
//! **Draft-22 is draft-21 with one wire change, to `LOCATION_FILTER` (0x21).**
//! Every message keeps its code point, every field its width and its place,
//! every registry its rows, and the ALPN follows the draft's number:
//! `moqt-22`.
//!
//! The filter's value opens with a `Location Filter Type`, and the type names
//! which of `StartGroup`, `StartObject`, `EndGroupDelta` and `EndObject`
//! follow (Section 9.20.9, Table 6):
//!
//! | Type | Fields | Meaning |
//! |---|---|---|
//! | 0x00 | none | no filter |
//! | 0x01 | `StartGroup` | relative start, open-ended |
//! | 0x02 | `StartGroup`, `StartObject` | absolute start, open-ended |
//! | 0x03 | the above and `EndGroupDelta` | absolute start, ends with a group |
//! | 0x04 | all four | absolute range |
//! | 0x05 | none | Next Object, open-ended |
//!
//! "Any other Location Filter Type is a PROTOCOL_VIOLATION." No length
//! precedes the type, so the parameter is self-delimiting the way a Location
//! is, and a reader that cannot name the type cannot find the end of it.
//!
//! **Small values encode to the same bytes in draft-21 and draft-22, and some
//! of them mean different things.** With every field a one-byte `vi64`,
//! draft-21's `Length` equals the field count, and so equals the draft-22 type
//! that names that many fields: `21 01 03` is a three-groups-back relative
//! start in both. They part company elsewhere: `21 02 00 00` is the Next Object
//! in draft-21 and the absolute start of the track, `{0, 0}`, here, where Next
//! Object is `21 05`; and a two-byte field turns a draft-21 `Length` into a
//! type that names more fields than are present. A test built only from small
//! values cannot tell the two decoders apart.
//!
//! The rest of draft-22 is editorial, and it moved enough that **every
//! section, table and figure reference in this module is draft-22's own.**
//! Message Parameter definitions sit one section lower than in draft-21,
//! every figure one number higher, and every table from 6 on one higher. Some
//! rules left their section for a new one — the FETCH behaviours for Section
//! 3.2, the SUBSCRIBE_TRACKS parameter rule for Section 3.6.2 — and several
//! normative sentences were reworded, most of them to name a response by its
//! request (FETCH_ERROR rather than REQUEST_ERROR, Section 1.5). The sites
//! that quote them quote draft-22's wording.
//!
//! PUBLISH_NAMESPACE's field is named `Track Namespace Prefix` here (Section
//! 9.14, Figure 18). The bytes are the ones draft-21 calls `Track Namespace`,
//! and the Rust field keeps that name, so a consumer keyed on it reads every
//! draft the same way.
//!
//! The rest of this list is what a reader coming from draft-19 needs:
//!
//! - **FETCH (0x16) has no `Fetch Type`.** Track Namespace and Track Name are
//!   inline fields of FETCH itself, in the positions they occupied inside
//!   draft-19's Standalone Fetch, and the range travels in the
//!   `LOCATION_FILTER` message parameter. The codepoint is draft-19's, so a
//!   draft-19 decoder reads the Number of Track Namespace Fields count as a
//!   Fetch Type and mis-parses in silence; there is no in-band version signal
//!   to catch it (Section 9.11)
//! - **PUBLISH_STATE_NOTIFY (0x22)** is a publisher-only, unilateral report
//!   that a subscription's state changed for a reason other than a
//!   subscriber-sent REQUEST_UPDATE. It has no Request ID field — the message
//!   is identified by the bidirectional request stream it arrives on, like
//!   SUBSCRIBE_OK, PUBLISH_DONE and FETCH_OK (Section 9.10)
//! - **Ranges are inclusive at both ends**, on subscriptions and on fetches.
//!   Draft-19's fetch end was "the last Object, plus 1; or 0 to indicate the
//!   entire Group"; neither convention exists here, and a draft-19 encoder
//!   ported forward with its end-location arithmetic intact fetches one object
//!   too many (Sections 3.3.1, 9.12)
//! - **`FILL_PARAMETERS` (0x23)** is a length-prefixed parameter whose value is
//!   a nested parameter block, and whose mere presence on a SUBSCRIBE or a
//!   REQUEST_UPDATE asks the publisher to open a fill fetch stream
//!   (Section 9.20.15). A `LOCATION_FILTER` nested inside it is the
//!   type-led form, with no length of its own
//! - **`INCLUDE_PROPERTIES` (0x35)** is a uint8 opt-out from Track Properties
//!   on the responding OK, default 1 (Section 9.20.21)
//! - `SUBSCRIPTION_ENDED` (PUBLISH_DONE 0x3), `VERSION_NEGOTIATION_FAILED`
//!   (session 0x15) and `INVALID_JOINING_REQUEST_ID` (REQUEST_ERROR 0x32) are
//!   unassigned, and there is no Fetch Type registry
//! - `PUBLISH_DONE.Stream Count`'s "unknown" sentinel is `2^64 - 1`, and the
//!   count includes fill fetch streams (Section 9.9)
//! - `EXPIRES` (0x08) is the only parameter whose definition names
//!   `PUBLISH_OK`; a subscriber changes anything else with a REQUEST_UPDATE
//!   after it (Section 9.20)
//! - The data-plane headers call their leading field `Type Flags` and state
//!   the validity rules in prose after the figure. Sections 11.2.1 and 11.3.1
//!   give **different** rule sets — subgroup's reserved bit 4 must be 1,
//!   datagram's must be 0, and subgroup has no "unspecified bit" clause
//!   because bits 0-6 are all specified for it
//! - A fetch stream has a third End of Range marker, `End of Timed-Out Range`
//!   (Serialization Flags `0x20C`), for the Objects a relay abandoned when its
//!   `FILL_TIMEOUT` budget ran out (Section 11.4.1, Table 8)
//!
//! # Where this codec had to choose
//!
//! Draft-22 leaves several wire questions open. Each decision is recorded at
//! the encode or decode site that makes it, and each says that the draft does
//! not state it. They are, with the site that carries the comment:
//!
//! - `FILL_PARAMETERS`'s value begins with a `Number of Parameters` count —
//!   [`message::decode_fill_parameters`]
//! - the `Type Delta` chain restarts inside `FILL_PARAMETERS` and the outer
//!   chain is unaffected — [`message::decode_fill_parameters`]
//! - SUBSCRIBE_TRACKS admits every parameter SUBSCRIBE does, as Section 3.6.2
//!   says and Section 9.18's own list does not — [`message::parameter_in_scope`]
//! - a non-minimally encoded `Type Flags` is accepted on receive and never
//!   emitted — [`data_stream::SubgroupHeader::decode`](crate::draft22::data_stream::SubgroupHeader::decode) and
//!   [`data_stream::DatagramHeader::decode`](crate::draft22::data_stream::DatagramHeader::decode)
//! - `PUBLISH_DONE.Stream Count`'s `2^64 - 1` sentinel is indistinguishable
//!   from a well-formed exact count —
//!   [`message::publish_done_codes::STREAM_COUNT_UNKNOWN`]
//! - `Object Payload Length` is present on an End-of-Range marker record,
//!   encoded as 0, and the ordinary delta arithmetic applies to the marker's
//!   two fields — [`data_stream::FetchObjectHeader`]
//!
//! # What this codec does not enforce
//!
//! REQUEST_UPDATE (Section 9.5) and REQUEST_OK (Section 9.3) list their
//! parameters per kind of request: an update to a FETCH may carry only
//! `AUTHORIZATION_TOKEN` and `SUBSCRIBER_PRIORITY`, a PUBLISH_OK only
//! `EXPIRES`, and so on. Which list applies depends on the request the frame
//! answers or updates, which is session state and not in the frame, so
//! [`message::parameter_in_scope`] holds each of the two messages to the
//! union of its lists. A parameter inside the union and outside the list for
//! its own request passes this codec; refusing it is the session's job, and
//! nothing in this crate does it.

#[allow(missing_docs)]
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod types;

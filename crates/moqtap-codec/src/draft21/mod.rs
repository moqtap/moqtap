//! MoQT wire codec for draft-21.
//!
//! **Draft-21 is draft-20 restructured, and nothing a decoder can observe
//! changed.** Every message keeps its code point, every field its width and
//! its place, every registry its rows. The one wire-visible consequence is the
//! ALPN, which the draft derives from its own number: `moqt-21`.
//!
//! What did change is where the rules are written down. Two hundred numbered
//! sections became two hundred and fourteen and only eleven keep both their
//! title and their number, so **every section, table and figure reference in
//! this module is draft-21's own**. A draft-20 number carried over would
//! mostly still resolve — to a section that exists and states something else.
//!
//! Two normative sentences were reworded on the way, so *a restructure moves
//! text without touching it* is very nearly true and not quite. The
//! AUTHORIZATION TOKEN repetition rule takes a different subject here than it
//! took in draft-20, and LOCATION_FILTER's definition lost the opening
//! sentence that named its encoding — with the `Length` field still in the
//! structure, so the wire is as it was. Neither changes what either requires,
//! and both are quoted at the sites that read them.
//!
//! The rest of this list is what a reader coming from draft-19 needs; draft-20
//! made these changes and draft-21 keeps every one of them.
//!
//! - **FETCH (0x16) is rewritten.** The `Fetch Type` field, the Standalone
//!   Fetch and Joining Fetch structures and the Fetch Type registry are all
//!   gone. Track Namespace and Track Name are inline fields of FETCH itself, in
//!   the positions they occupied inside the old Standalone Fetch, and the range
//!   travels in the `LOCATION_FILTER` message parameter. The codepoint did not
//!   change, so a draft-19 decoder reads the Number of Track Namespace Fields
//!   count as a Fetch Type and mis-parses in silence; there is no in-band
//!   version signal to catch it (Section 9.11)
//! - **PUBLISH_STATE_NOTIFY (0x22) is new.** A publisher-only, unilateral
//!   report that a subscription's state changed for a reason other than a
//!   subscriber-sent REQUEST_UPDATE. It has no Request ID field — the message
//!   is identified by the bidirectional request stream it arrives on, like
//!   SUBSCRIBE_OK, PUBLISH_DONE and FETCH_OK (Section 9.10)
//! - **`LOCATION_FILTER` (0x21) is restructured.** The Filter Type enum
//!   (draft-19's 0x1 Next Group Start / 0x2 Largest Object / 0x3 AbsoluteStart
//!   / 0x4 AbsoluteRange) is gone; the filter's shape now comes from how many
//!   `vi64` fields its value holds (Section 9.20.10)
//! - **Ranges are inclusive at both ends**, on subscriptions and on fetches.
//!   Draft-19's fetch end was "the last Object, plus 1; or 0 to indicate the
//!   entire Group"; both conventions are deleted. This change is absent from
//!   the draft's own change log, and a draft-19 encoder ported forward with its
//!   end-location arithmetic intact fetches one object too many
//!   (Sections 3.3.1, 9.11, 9.12)
//! - **`FILL_PARAMETERS` (0x23) is new**: a length-prefixed parameter whose
//!   value is a nested parameter block, and whose mere presence on a SUBSCRIBE
//!   or a REQUEST_UPDATE asks the publisher to open a fill fetch stream
//!   (Section 9.20.16)
//! - **`INCLUDE_PROPERTIES` (0x35) is new**: a uint8 opt-out from Track
//!   Properties on the responding OK, default 1 (Section 9.20.22)
//! - Three code points are removed: `SUBSCRIPTION_ENDED` (PUBLISH_DONE 0x3),
//!   `VERSION_NEGOTIATION_FAILED` (session 0x15) and
//!   `INVALID_JOINING_REQUEST_ID` (REQUEST_ERROR 0x32). Two whole enumerations
//!   go with them: the Fetch Type registry and the Location Filter Type enum
//! - `PUBLISH_DONE.Stream Count`'s "unknown" sentinel moves from `2^62 - 1` to
//!   `2^64 - 1`, and the count now includes fill fetch streams (Section 9.9)
//! - Subscription parameters moved off `PUBLISH_OK`. Six parameter definitions
//!   dropped it from their "MAY appear in" list and several gained `PUBLISH`;
//!   `EXPIRES` (0x08) is the only one that still names it (Section 9.20)
//! - The data-plane headers rename their leading field `Type` to `Type Flags`
//!   and move the validity rules out of the figure into prose. The field list,
//!   order, widths and the set of valid values are all unchanged; what changed
//!   is the receive path. Sections 11.2.1 and 11.3.1 give **different** rule
//!   sets — subgroup's reserved bit 4 must be 1, datagram's must be 0, and
//!   subgroup has no "unspecified bit" clause because bits 0-6 are all
//!   specified for it
//! - A fetch stream gains a third End of Range marker, `End of Timed-Out
//!   Range` (Serialization Flags `0x20C`), for the Objects a relay abandoned
//!   when its `FILL_TIMEOUT` budget ran out. Draft-19 reported those as Unknown
//!   gaps (Section 11.4.1, Table 7)
//! - Draft-20 renumbered too, inserting PUBLISH_STATE_NOTIFY and shifting
//!   everything after it; draft-21 renumbered again and far more widely. Both
//!   are behind us: the numbers below are draft-21's
//!
//! # Where this codec had to choose
//!
//! Draft-21 leaves several wire questions open. Each decision is recorded at
//! the encode or decode site that makes it, and each says that the draft does
//! not state it. They are, with the site that carries the comment:
//!
//! - `FILL_PARAMETERS`'s value begins with a `Number of Parameters` count —
//!   [`message::decode_fill_parameters`]
//! - the `Type Delta` chain restarts inside `FILL_PARAMETERS` and the outer
//!   chain is unaffected — [`message::decode_fill_parameters`]
//! - a `LOCATION_FILTER`'s field count comes from parsing, never from the byte
//!   length — [`message::decode_location_filter`]
//! - a non-minimally encoded `Type Flags` is accepted on receive and never
//!   emitted — [`data_stream::SubgroupHeader::decode`](crate::draft21::data_stream::SubgroupHeader::decode) and
//!   [`data_stream::DatagramHeader::decode`](crate::draft21::data_stream::DatagramHeader::decode)
//! - `PUBLISH_DONE.Stream Count`'s `2^64 - 1` sentinel is indistinguishable
//!   from a well-formed exact count —
//!   [`message::publish_done_codes::STREAM_COUNT_UNKNOWN`]
//! - `PUBLISH_STATE_NOTIFY`'s parameter allow-list is treated as closed —
//!   [`message::parameter_in_scope`]
//! - `Object Payload Length` is present on an End-of-Range marker record,
//!   encoded as 0, and the ordinary delta arithmetic applies to the marker's
//!   two fields — [`data_stream::FetchObjectHeader`]

#[allow(missing_docs)]
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod types;

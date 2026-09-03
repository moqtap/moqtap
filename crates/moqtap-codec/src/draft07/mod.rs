//! MoQT wire codec for draft-07.
//!
//! The earliest draft this codec speaks, so there is no delta to record. What
//! follows is the other half of that: the places where draft-07 differs from
//! every draft after it, each of which has been mistaken for a later draft's
//! behaviour at some point in this tree.
//!
//! - **ROLE is required.** Section 6.2.2.1: "Both endpoints MUST send a ROLE
//!   parameter with one of the three values specified above. Both endpoints
//!   MUST close the session if the ROLE parameter is missing or is not one of
//!   the three above-specified values." Draft-08 removes the parameter and no
//!   later draft brings it back, so this is the only draft where a setup
//!   message can be refused for the parameter it is missing.
//! - **A server refuses a GOAWAY outright.** Section 6.3: "The server MUST
//!   terminate the session with a Protocol Violation (Section 3.5) if it
//!   receives a GOAWAY
//!   message." Every draft from 08 on narrows this to a GOAWAY carrying a New
//!   Session URI, so an empty GOAWAY at a server is legal there and a session
//!   close here.
//! - **Object Status 0x5 is End of Subgroup**, whose "Object ID is one greater
//!   than the largest normal object ID in the Subgroup". Drafts 08, 09 and 10
//!   assign 0x5 to End of Track and require the opposite - an Object ID of
//!   zero - and drafts 11 and later assign 0x5 nothing at all.
//! - **Filter Type 0x1 is Latest Group**, which begins at the current group.
//!   Drafts 09 and 10 withdraw the value; drafts 11 and later reuse the number
//!   for Next Group Start, one group later.
//! - **There are no extension headers.** The phrase does not appear in this
//!   draft. Draft-08 introduces them as a count of headers and draft-09 changes
//!   that to a byte length.
//! - **SUBSCRIBE's AbsoluteRange carries an EndObject** beside its EndGroup.
//!   Draft-08 drops it and the filter ends at a group.
//! - The FETCH message has no Fetch Type, so there is no Joining Fetch.
/// Data stream headers (subgroup, datagram, fetch, object).
pub mod data_stream;
pub mod error_codes;
/// This draft's field names for a decoded control message.
pub mod fields;
/// Control message types with encode/decode.
pub mod message;
/// Draft-07 specific types (Role, ObjectStatus).
pub mod types;

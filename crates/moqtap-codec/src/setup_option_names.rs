//! The name a draft gives a setup parameter.
//!
//! The sibling of [`crate::message_names`], and per draft for the same reason:
//! the codepoints are reused and retired rather than reserved. `0x02` is
//! `max_subscribe_id` through draft-10, `max_request_id` from draft-11 to
//! draft-16, and nothing at all from draft-17, which removed it and left the
//! number unassigned. A table keyed on the number alone cannot say that.
//!
//! # Why this takes a whole parameter and not a key
//!
//! Drafts 11 through 13 name a setup parameter from its key *and the shape of
//! its value*: `0x01` carrying bytes is `path`, and `0x01` carrying a varint is
//! nothing those drafts define. A `fn(u64) -> Option<&str>` would have to
//! guess, so the whole [`KeyValuePair`] goes in and the draft's own renderer
//! answers.
//!
//! That renderer is the same one [`crate::dispatch::AnyControlMessage::fields`]
//! uses, which is the property worth having: a parameter this reports as named
//! is a parameter that draft would have named in a decoded message, because it
//! is the same code answering.
//!
//! # What it is for
//!
//! Asking a *second* draft about a parameter that arrived under a first. A
//! relay that sends a setup parameter the draft it negotiated does not define
//! is sending something — an extension, or code left over from the draft it
//! used to speak — and which of those it is depends on whether some other draft
//! names it. That is an upgrade-hygiene signal: it is a fingerprint and also a
//! line an operator can act on.
//!
//! Receivers must ignore setup parameters they do not recognise, so a leftover
//! is never a protocol violation. It is still a fact about the sender.
//!
//! # The dispatch is shared; the answer is not
//!
//! The fourteen-armed, catch-all-free `match` this dispatch needs is
//! `crate::draft_table::by_draft` — private, so not a link — and
//! [`crate::message_names`] spells the
//! same one. Only the dispatch is shared: this table takes a whole parameter,
//! answers a `String` out of the draft's own renderer, and has its own reasons
//! for both. See `draft_table` for the argument the two share.

use crate::kvp::KeyValuePair;

/// The name draft `draft` gives `param` in a setup message, or `None` if that
/// draft defines nothing for it.
///
/// `draft` is the draft number as the IETF writes it — 7 through 20 — matching
/// [`crate::version::DraftVersion::number`]. A number outside the range this
/// crate implements answers `None`, as does a draft whose feature flag is off in
/// this build.
///
/// This is the *setup* parameter namespace, which is not the one non-setup
/// messages use: `0x02` is `max_request_id` in a draft-14 SERVER_SETUP and
/// `delivery_timeout` in a draft-14 SUBSCRIBE. Asking this about a parameter
/// that arrived on a request would name the wrong thing.
///
/// ```
/// use moqtap_codec::kvp::{KeyValuePair, KvpValue};
/// use moqtap_codec::setup_option_name;
/// use moqtap_codec::varint::VarInt;
///
/// # #[cfg(all(feature = "draft10", feature = "draft14", feature = "draft18"))]
/// # {
/// let max = KeyValuePair {
///     key: VarInt::from_u64(0x02).unwrap(),
///     value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
/// };
/// // The same codepoint, renamed once and then retired.
/// assert_eq!(setup_option_name(10, &max).as_deref(), Some("max_subscribe_id"));
/// assert_eq!(setup_option_name(14, &max).as_deref(), Some("max_request_id"));
/// assert_eq!(setup_option_name(18, &max), None);
/// # }
/// ```
// Both allows are the same fact about the same build, and it is the zero-draft
// one: `--no-default-features` with no `draftNN` named, which
// `just test-features` compiles as its own row and `just draft-matrix` compiles
// twice more. There every arm takes its `#[cfg(not(feature = ...))]` form, so
// nothing reads `one` and every arm diverges — which makes the whole `match` `!`
// and the call after it unreachable.
//
// An `allow` rather than a `cfg`, and the choice is forced rather than
// preferred. Spelling the condition would mean writing
// `any(feature = "draft07", ..., feature = "draft20")` — all fourteen — beside a
// list of the same fourteen, with nothing holding the two level. That is the
// drift `scripts/check-draft-parity.py` exists to catch and would not catch
// here: a fifteenth draft added to the table and forgotten in the `cfg` compiles
// clean and silently stops naming anything.
//
// Neither allow can hide a defect in a build that has a draft. With one draft
// enabled that draft's arm is the renderer, so `one` is read and the match
// returns a value; the allows are inert everywhere except the build that
// compiled no draft at all, where there is nothing left for them to conceal.
#[allow(unused_variables)]
#[allow(unreachable_code)]
pub fn setup_option_name(draft: u8, param: &KeyValuePair) -> Option<String> {
    let one = std::slice::from_ref(param);
    // `return None` rather than `None` as the absent answer: the arms produce a
    // `FieldValue` to be read by `name_in` below, and "this build has no table
    // for that draft" is not a rendering of anything. See
    // `crate::draft_table::by_draft`.
    let rendered = crate::draft_table::by_draft! { draft, return None,
        // Drafts 08 through 10 share draft-08's table, which is the same two
        // parameters draft-07 has minus ROLE.
        ("draft07", Draft07) => crate::fields::params::kvp_to_json_d07_setup(one),
        ("draft08", Draft08) => crate::fields::params::kvp_to_json_d08_setup(one),
        ("draft09", Draft09) => crate::fields::params::kvp_to_json_d08_setup(one),
        ("draft10", Draft10) => crate::fields::params::kvp_to_json_d08_setup(one),
        ("draft11", Draft11) => crate::draft11::fields::kvp_to_json_setup(one),
        ("draft12", Draft12) => crate::draft12::fields::kvp_to_json_setup(one),
        ("draft13", Draft13) => crate::draft13::fields::kvp_to_json_setup(one),
        ("draft14", Draft14) => crate::draft14::fields::kvp_to_json_d14_setup(one),
        ("draft15", Draft15) => crate::draft15::fields::kvp_to_json_d15_setup(one),
        ("draft16", Draft16) => crate::draft16::fields::kvp_to_json_d16_setup(one),
        // Draft-17 renamed the block to Setup Options and unified the message;
        // the renderer's name follows the draft's word for it.
        ("draft17", Draft17) => crate::draft17::fields::options_to_json(one),
        ("draft18", Draft18) => crate::draft18::fields::options_to_json(one),
        ("draft19", Draft19) => crate::draft19::fields::options_to_json(one),
        ("draft20", Draft20) => crate::draft20::fields::options_to_json(one),
    };
    name_in(&rendered)
}

/// The `name` of the single entry a one-parameter render produced.
///
/// `kvp_entries` writes `name` only for a parameter the draft defines, which is
/// the whole question — so an entry without one is the `None` this returns.
fn name_in(rendered: &crate::fields::FieldValue) -> Option<String> {
    use crate::fields::FieldValue;
    let FieldValue::Array(entries) = rendered else {
        return None;
    };
    let FieldValue::Map(entry) = entries.first()? else {
        return None;
    };
    match entry.get("name") {
        Some(FieldValue::Text(name)) => Some(name.clone()),
        _ => None,
    }
}

#[cfg(test)]
/// Every positive claim here is gated on the draft that makes it.
///
/// [`setup_option_name`] answers `None` for a draft this build did not compile,
/// by design and stated in its own rustdoc — so an ungated
/// `assert_eq!(setup_option_name(11, ..), Some("path"))` is not a claim about
/// the naming table at all under `--no-default-features --features draft07`. It
/// is a claim that draft-11 was compiled, failing in a build that never
/// promised to have it. `just test-features` runs this suite fourteen times,
/// once per draft alone, plus `draft07,draft20` and `draft13,draft14`, so
/// thirteen of those runs meet exactly that.
///
/// The gates are per **draft asserted**, not per test, wherever one test spans
/// several: `a_retired_codepoint_is_named_by_the_drafts_that_had_it_and_no_others`
/// is a statement about four drafts and keeps whichever of them this build has,
/// rather than being switched off whole because one is missing.
///
/// The two negative claims — a codepoint nobody assigned, and a draft number
/// outside 7..=20 — are left ungated because they are true under every feature
/// set and no build can make them false. They are *vacuous* for a draft that
/// was left out, since it answers `None` for every parameter; that is a
/// weakening the all-drafts `cargo test --workspace` run in `just test` covers,
/// and it is the reason those two are not the whole of this module's coverage.
mod tests {
    use super::*;
    use crate::kvp::KvpValue;
    use crate::varint::VarInt;

    fn varint(key: u64, value: u64) -> KeyValuePair {
        KeyValuePair {
            key: VarInt::from_u64(key).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(value).unwrap()),
        }
    }

    fn bytes(key: u64, value: &[u8]) -> KeyValuePair {
        KeyValuePair { key: VarInt::from_u64(key).unwrap(), value: KvpValue::Bytes(value.to_vec()) }
    }

    /// The case this exists for: a codepoint one draft removed.
    ///
    /// moxygen sends `0x02` on draft-18, which draft-17 deleted. Reading it as
    /// unknown is right about draft-18 and says nothing useful; asking the
    /// earlier drafts is what turns it into "MAX_REQUEST_ID, left behind".
    ///
    /// Three positive claims, one per draft, each kept only in a build that has
    /// that draft — see the note on this module. The retirement loop stays
    /// ungated: `None` is the right answer for 17 through 20 whether they were
    /// compiled or not, so no feature set can make it wrong, and the build that
    /// makes it *mean* something is any one with a draft in that range.
    #[test]
    fn a_retired_codepoint_is_named_by_the_drafts_that_had_it_and_no_others() {
        let max = varint(0x02, 100);
        #[cfg(feature = "draft10")]
        assert_eq!(setup_option_name(10, &max).as_deref(), Some("max_subscribe_id"));
        #[cfg(feature = "draft11")]
        assert_eq!(setup_option_name(11, &max).as_deref(), Some("max_request_id"));
        #[cfg(feature = "draft16")]
        assert_eq!(setup_option_name(16, &max).as_deref(), Some("max_request_id"));
        for draft in 17..=20 {
            assert_eq!(setup_option_name(draft, &max), None, "draft-{draft} still names 0x02");
        }
    }

    /// A codepoint no draft in the range has ever assigned.
    #[test]
    fn an_unassigned_codepoint_is_named_by_nobody() {
        let odd = bytes(0x21, b"\x01\xff");
        for draft in 7..=20 {
            assert_eq!(setup_option_name(draft, &odd), None, "draft-{draft} names 0x21");
        }
    }

    /// Drafts 11-13 name from the value's shape as well as the key, which is
    /// why this takes a parameter rather than a number.
    ///
    /// Wholly a draft-11 claim — both halves, including the negative one: a
    /// build without draft-11 answers `None` to the varint case for the reason
    /// this test is *not* about, so keeping that half alone would read as
    /// evidence for a rule the build cannot state. Gated whole rather than
    /// per-assertion, which is what tells the two apart.
    #[cfg(feature = "draft11")]
    #[test]
    fn a_name_can_depend_on_the_shape_of_the_value() {
        assert_eq!(setup_option_name(11, &bytes(0x01, b"/moq")).as_deref(), Some("path"));
        assert_eq!(
            setup_option_name(11, &varint(0x01, 4)),
            None,
            "draft-11 defines PATH as bytes and nothing as a varint"
        );
    }

    /// The setup namespace, and not the one requests use. `0x02` is
    /// `max_request_id` in a draft-14 setup and `delivery_timeout` in a
    /// draft-14 SUBSCRIBE, and answering the second here would be wrong in a
    /// way nothing downstream could catch.
    ///
    /// One draft's claim, so one draft's gate. The two namespaces it separates
    /// are both draft-14's, and a build without draft-14 has neither of them to
    /// confuse.
    #[cfg(feature = "draft14")]
    #[test]
    fn the_answer_is_the_setup_namespaces_and_not_the_message_ones() {
        assert_eq!(setup_option_name(14, &varint(0x02, 100)).as_deref(), Some("max_request_id"));
    }

    /// A draft number outside the range answers `None` rather than panicking.
    #[test]
    fn a_draft_this_crate_does_not_implement_names_nothing() {
        let max = varint(0x02, 100);
        assert_eq!(setup_option_name(6, &max), None);
        assert_eq!(setup_option_name(21, &max), None);
    }
}

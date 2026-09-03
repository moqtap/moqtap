//! The corpus's error categories and this crate's answers, checked against
//! each other.
//!
//! A negative vector says what kind of complaint a conforming decoder must
//! make. `test_vectors::error_category` is the translation from this crate's
//! [`CodecError`] to that vocabulary, and every negative vector in the corpus
//! is compared through it — so a category that translates wrongly, or that
//! nothing can produce, is a category no vector can use.
//!
//! Nothing else checks that. The corpus comparison only ever sees the
//! categories vectors happen to claim, which is why three of the schema's names
//! went years without a single one: a category is reachable or it is not, and
//! the corpus cannot tell you which until someone writes the vector that finds
//! out. This file finds out first, from bytes rather than from constructed
//! error values, because an arm that maps a variant no decoder returns is
//! indistinguishable from one that works.
//!
//! # What this catches, observed by making each change and running it
//!
//! Deleting the parameter-scope arm, so the rule falls through to the
//! catch-all it sat in until the corpus had a name for it:
//!
//! ```text
//! thread 'a_parameter_outside_its_scope_is_its_own_category' panicked at
//! crates\moqtap-codec\tests\vector_error_taxonomy.rs:135:5:
//! assertion `left == right` failed: draft-19 FETCH_OK carrying EXPIRES
//!   left: "invalid_value"
//!  right: "parameter_out_of_scope"
//! ```
//!
//! Reporting the reserved SUBGROUP_ID_MODE as an unassigned code point, by
//! removing that branch from draft-19's `stream_type_error`:
//!
//! ```text
//! thread 'a_type_the_draft_names_as_invalid_is_not_an_unknown_one' panicked at
//! crates\moqtap-codec\tests\vector_error_taxonomy.rs:155:5:
//! assertion `left == right` failed: draft-19 subgroup Type 0x16
//!   left: "unknown_message"
//!  right: "invalid_type"
//! ```
//!
//! Misspelling one vector's category by a letter, which is the failure the
//! corpus comparison cannot report on its own — it would say the decoder
//! refused the bytes for the wrong reason, and name a reason that does not
//! exist:
//!
//! ```text
//! thread 'every_category_the_corpus_claims_is_one_the_schema_names' panicked at
//! crates\moqtap-codec\tests\vector_error_taxonomy.rs:217:13:
//! transport/draft19/codec/messages/fetch-ok.json [with-params-and-properties]
//! claims error category "parameter_out_of_scop", which the schema does not
//! name. Nothing can answer to it, so the vector fails whatever the decoder
//! does.
//! ```
//!
//! And the one name in the schema that no decoder answers to, by emptying
//! [`UNREACHABLE`]:
//!
//! ```text
//! thread 'every_category_the_schema_names_is_either_reachable_or_recorded'
//! panicked at crates\moqtap-codec\tests\vector_error_taxonomy.rs:273:9:
//! the schema names "missing_parameter" and nothing in this file produces it.
//! Either drive a decoder to it, or add it to UNREACHABLE with the reason.
//! ```
//!
//! And the other direction — a name taken out of the shipped schema while this
//! file still drives a decoder to it, which is the shape a tidy-up takes when
//! two of the nine names have no vector claiming them:
//!
//! ```text
//! thread 'every_category_this_file_accounts_for_is_one_the_schema_names'
//! panicked at crates\moqtap-codec\tests\vector_error_taxonomy.rs:300:9:
//! this file drives a decoder to "payload_not_permitted" and the schema no
//! longer names it, so no vector can claim what the decoder demonstrably
//! produces. Restore the name, or delete the case above that reaches it.
//! ```
//!
//! That last one was measured against the whole crate before the check existed.
//! Deleting the name left 101 binaries and 1,942 assertions green — this file's
//! other five among them, and the corpus comparison too, because a category no
//! vector claims is one no corpus sweep can miss.

mod test_vectors;

use test_vectors::{vector_files, vectors_dir};

#[cfg(any(feature = "draft19", feature = "draft20"))]
use test_vectors::error_category;

#[cfg(any(feature = "draft19", feature = "draft20"))]
fn hex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).expect("test hex")
}

/// Drive `bytes` through a decoder and return the category of the refusal.
///
/// Panics if the bytes decode, because a case that stopped failing is a case
/// that stopped testing anything.
#[cfg(any(feature = "draft19", feature = "draft20"))]
fn category_of(
    what: &str,
    decode: impl FnOnce() -> Result<(), moqtap_codec::error::CodecError>,
) -> String {
    match decode() {
        Ok(()) => panic!("{what} decoded; this case tests nothing until it does not"),
        Err(err) => error_category(&err).to_string(),
    }
}

/// A Message Parameter in a message its own definition does not name.
///
/// The bytes are the corpus's `draft19/codec/messages/fetch-ok.json
/// [with-params-and-properties]`: a FETCH_OK carrying EXPIRES (0x8), whose
/// definition lists SUBSCRIBE_OK, PUBLISH, PUBLISH_OK, SUBSCRIBE_NAMESPACE_OK,
/// SUBSCRIBE_TRACKS_OK, PUBLISH_NAMESPACE_OK and REQUEST_UPDATE_OK and stops
/// there.
///
/// Its own category rather than a shade of `invalid_parameter`, because the
/// parameter is well formed and what is wrong is the message around it — and
/// because the rule exists on three drafts only. Draft-19 Section 10.2.1: "Each
/// Message Parameter definition indicates the message types in which it can
/// appear. If it appears in some other type of message, the receiving endpoint
/// MUST close the connection with a PROTOCOL_VIOLATION." Every draft before 17
/// ends that sentence "it MUST be ignored", so on those the same bytes decode
/// and there is no category to claim.
#[cfg(feature = "draft19")]
#[test]
fn a_parameter_outside_its_scope_is_its_own_category() {
    use moqtap_codec::draft19::message::ControlMessage;

    let bytes = hex("18000a000a0301081e04c07530");
    let category = category_of("draft-19 FETCH_OK carrying EXPIRES", || {
        ControlMessage::decode(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "parameter_out_of_scope", "draft-19 FETCH_OK carrying EXPIRES");
}

/// A Type inside the form its draft defines, which the draft separately names
/// as invalid.
///
/// Draft-19 Section 11.4.2 excludes the subgroup Types whose SUBGROUP_ID_MODE
/// is the reserved 0b11 — 0x16, 0x17, 0x1E, 0x1F and the same four offsets in
/// each higher range. 0x16 is inside the assigned form, so reporting it as an
/// unknown stream type would be the wrong complaint: the draft assigns the
/// range and rules out this value within it.
#[cfg(feature = "draft19")]
#[test]
fn a_type_the_draft_names_as_invalid_is_not_an_unknown_one() {
    use moqtap_codec::draft19::data_stream::SubgroupHeader;

    let bytes = hex("16");
    let category = category_of("draft-19 subgroup Type 0x16", || {
        SubgroupHeader::decode(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "invalid_type", "draft-19 subgroup Type 0x16");

    // A Type the draft assigns to nothing at all is the other complaint, and
    // this is what keeps the two apart rather than merely reaching one of them.
    let bytes = hex("60");
    let category = category_of("draft-19 subgroup Type 0x60", || {
        SubgroupHeader::decode(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "unknown_message", "draft-19 subgroup Type 0x60");
}

/// Draft-20 moved the boundary between those two complaints, and this is where
/// the move is visible.
///
/// Draft-19's figure enumerated the valid subgroup Types and left everything
/// else to Section 3.4's unknown-stream-type rule, so 0x60 — bit 4 clear, which
/// puts it outside the 0b0XX1XXXX pattern — was `unknown_message`. Draft-20
/// states three conditions instead, and "values where bit 4 is not set" is one
/// of them, so the draft now *names* 0x60 as invalid and the complaint is
/// `invalid_type`. The set of accepted values did not change; only what a
/// refusal is called did.
///
/// `unknown_message` is still reachable on draft-20, and only above the byte
/// space: Section 11.4.2's conditions are about a one-byte flags field, so a
/// stream type too wide to be one is Section 3.4's business again.
#[cfg(feature = "draft20")]
#[test]
fn draft20_names_every_invalid_type_inside_the_byte_space() {
    use moqtap_codec::draft20::data_stream::SubgroupHeader;

    for (label, bytes) in
        [("the reserved SUBGROUP_ID_MODE", "16"), ("bit 4 clear", "60"), ("128 or greater", "8090")]
    {
        let bytes = hex(bytes);
        let category = category_of(&format!("draft-20 subgroup Type, {label}"), || {
            SubgroupHeader::decode(&mut &bytes[..]).map(|_| ())
        });
        assert_eq!(category, "invalid_type", "draft-20 subgroup Type, {label}");
    }

    // Above the byte space, Section 3.4's rule is the one that answers.
    let bytes = hex("810007090380");
    let category = category_of("draft-20 subgroup Type 0x0100", || {
        SubgroupHeader::decode(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "unknown_message", "draft-20 subgroup Type 0x0100");
}

/// Draft-20's new LOCATION_FILTER value shape is the first thing in the corpus
/// to claim `invalid_parameter` for a malformed filter.
///
/// The two variants behind it — `SubscriptionFilterMalformed` and
/// `FilterEndGroupOverflow` — existed before and fell through to
/// `invalid_value`, because no vector on any draft reached either. Draft-20
/// Section 5.1.2 rebuilt the value, and its negative vectors are the first to
/// say what kind of complaint a malformed one is.
#[cfg(feature = "draft20")]
#[test]
fn a_malformed_location_filter_is_an_invalid_parameter() {
    use moqtap_codec::draft20::message::ControlMessage;

    // `messages/fetch.json [location-filter-five-fields]`: a LOCATION_FILTER
    // value holding five vi64 fields, where Section 5.1.2 defines shapes for
    // zero through four.
    let bytes = hex("1600150201046c69766505766964656f0121050102030405");
    let category = category_of("draft-20 LOCATION_FILTER with five fields", || {
        ControlMessage::decode(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "invalid_parameter", "draft-20 LOCATION_FILTER with five fields");

    // `messages/fetch.json [location-filter-end-group-overflow]`: StartGroup
    // 2^64 - 1 with an EndGroupDelta of 1.
    let bytes = hex("16001b0201046c69766505766964656f01210bffffffffffffffffff0001");
    let category = category_of("draft-20 LOCATION_FILTER end group overflow", || {
        ControlMessage::decode(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "invalid_parameter", "draft-20 LOCATION_FILTER end group overflow");
}

/// An object carrying a payload where its framing leaves no room for one.
///
/// A datagram whose Type sets the STATUS bit carries a status in the payload's
/// place — draft-19 Section 11.3.1: "When set to 1, the Object Status field is
/// present and there is no Object Payload" — so the bytes after it are not a
/// short payload, they are bytes the frame does not define.
///
/// Status 0x0 is the case worth driving. It is the one status the registry
/// marks as permitting a payload, so a reading that consults the status alone
/// hands those four bytes to the application as the object's content.
#[cfg(feature = "draft19")]
#[test]
fn a_payload_the_framing_forbids_is_its_own_category() {
    use moqtap_codec::draft19::data_stream::DatagramHeader;

    let bytes = hex("20 01 00 05 80 00 deadbeef");
    let category = category_of("draft-19 status datagram with a tail", || {
        DatagramHeader::decode_object(&mut &bytes[..]).map(|_| ())
    });
    assert_eq!(category, "payload_not_permitted", "draft-19 status datagram with a tail");

    // The same datagram without the tail is well formed, so the category is
    // about the four bytes and not about the status field.
    let bytes = hex("20 01 00 05 80 00");
    DatagramHeader::decode_object(&mut &bytes[..]).expect("a bare status datagram is lawful");
}

/// Every category the corpus claims is one the schema names.
///
/// The comparison in `TestVector::assert_error` is between a vector's category
/// and this crate's answer, so a category misspelled in the corpus fails
/// against every answer and reads as a decoder that refused the bytes for the
/// wrong reason — a real-looking failure with a made-up cause. The schema is
/// the authority on the names, and this is the only thing in the repository
/// that holds the corpus to it.
#[test]
fn every_category_the_corpus_claims_is_one_the_schema_names() {
    let named = schema_categories();
    let mut seen: Vec<String> = Vec::new();

    for relative in vector_files() {
        let path = vectors_dir().join(&relative);
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let file: serde_json::Value = serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()));
        let vectors = file["vectors"].as_array().unwrap_or_else(|| {
            panic!("{relative}: no vectors array — an empty file cannot be told from a clean one")
        });
        for vector in vectors {
            let Some(category) = vector["error"].as_str() else { continue };
            assert!(
                named.iter().any(|n| n == category),
                "{relative} [{}] claims error category {category:?}, which the schema does not \
                 name. Nothing can answer to it, so the vector fails whatever the decoder does.",
                vector["id"].as_str().unwrap_or("?")
            );
            if !seen.iter().any(|s| s == category) {
                seen.push(category.to_string());
            }
        }
    }

    assert!(
        seen.len() > 3,
        "the whole corpus claims only {seen:?}, which is a sweep that stopped reading rather than \
         a corpus that stopped asserting"
    );
}

/// The categories this crate produces, each demonstrated from bytes rather
/// than from a constructed error value.
///
/// The three cases above drive the three that nothing had produced before; the
/// other five this crate raises in rule suites of its own.
const REACHABLE: &[&str] = &[
    "incomplete",
    "unknown_message",
    "invalid_type",
    "invalid_value",
    "invalid_parameter",
    "parameter_out_of_scope",
    "duplicate_parameter",
    "payload_not_permitted",
];

/// The categories the schema names that nothing in this crate produces, and
/// why.
///
/// `missing_parameter` is the whole list. Absence is not something this decoder
/// detects, because nothing in it knows which parameters a message requires, so
/// a vector claiming it fails rather than passing quietly — which is the honest
/// outcome for a category the crate does not implement, and the reason to write
/// the row rather than to delete the category.
const UNREACHABLE: &[&str] = &["missing_parameter"];

/// Every category name in the shipped schema is one this file accounts for.
///
/// Read from `schema/codec-vector.schema.json` rather than restated here, so
/// the schema stays the authority and a category added upstream arrives as a
/// failure with a name in it instead of as silence.
#[test]
fn every_category_the_schema_names_is_either_reachable_or_recorded() {
    let names = schema_categories();

    for name in &names {
        let name = name.as_str();
        assert!(
            REACHABLE.contains(&name) || UNREACHABLE.contains(&name),
            "the schema names {name:?} and nothing in this file produces it. Either drive a \
             decoder to it, or add it to UNREACHABLE with the reason."
        );
    }
}

/// Every category name this file accounts for is one the shipped schema still
/// names.
///
/// The other direction, and it holds the half the test above cannot see. A
/// category no vector claims looks dead from inside the corpus: nothing reads
/// it, nothing fails without it, and taking it out of the schema leaves every
/// suite here green. Two of the nine sit in exactly that position today —
/// reachable, driven from bytes a few lines up, and claimed by no vector at
/// all.
///
/// A category is the vocabulary a vector is written in, so a name the schema
/// drops is a rule that can no longer be written down: not by anyone, not in
/// any corpus, not at any later date. That is worth a failure now rather than a
/// discovery then.
#[test]
fn every_category_this_file_accounts_for_is_one_the_schema_names() {
    let names = schema_categories();

    for name in REACHABLE {
        assert!(
            names.iter().any(|n| n == name),
            "this file drives a decoder to {name:?} and the schema no longer names it, so no \
             vector can claim what the decoder demonstrably produces. Restore the name, or \
             delete the case above that reaches it."
        );
    }

    for name in UNREACHABLE {
        assert!(
            names.iter().any(|n| n == name),
            "UNREACHABLE records {name:?}, which the schema no longer names — delete the row"
        );
    }
}

/// The error categories the shipped schema names, in the order it names them.
///
/// Read from `schema/codec-vector.schema.json` rather than restated in Rust, so
/// the schema stays the authority: a category added upstream arrives here as a
/// failure with a name in it instead of as silence.
fn schema_categories() -> Vec<String> {
    let path = vectors_dir().join("schema").join("codec-vector.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("cannot read {}: {e} — did you init the submodule?", path.display())
    });
    let schema: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()));

    let names: Vec<String> = schema["$defs"]["vector"]["properties"]["error"]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: no error enum where the schema keeps one", path.display()))
        .iter()
        .map(|n| n.as_str().expect("a category name is a string").to_string())
        .collect();
    assert!(
        names.len() >= 6,
        "{}: {} categories is fewer than the schema has ever had, so this is reading the wrong node",
        path.display(),
        names.len()
    );
    names
}

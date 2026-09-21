#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
//! Every code point this crate assigns, on every draft it implements, is
//! checked against the registries extracted from the rendered Internet-Drafts.
//!
//! The expected values are not written here. They are read out of
//! `tools/registries/draft-NN.json`, the committed output of
//! `tools/extract-registries.py`, which parses the rendered draft and emits one
//! row per code point the draft's registries assign. Each file carries
//! `source_sha256`, the hash of the rendered draft it was produced from, so the
//! assertions below are tied to one exact document rather than to a reading of
//! it. Re-run the tool against a new draft and every disagreement between the
//! document and this crate surfaces here.
//!
//! # Both directions, or it is not a conformance check
//!
//! A registry can drift two ways and only one of them is caught by "every code
//! in the spec is implemented". A code point that exists in this crate and not
//! in the draft is the more dangerous of the two: it puts a number on the wire
//! that the peer's registry does not define, and it survives any test that
//! iterates the spec and looks the code up. So each registry is compared as a
//! set: the spec's assignments and the crate's accepted code points must be
//! equal, and the two ways they can fail to be equal are reported separately.
//!
//! The set of registries is compared too. Each draft's list below is required
//! to name every registry its extraction carries, so a revision that adds one
//! cannot arrive with nothing comparing it — which is the shape this gate was
//! in for drafts 07 through 16, whose extractions existed and were read by
//! nothing.
//!
//! # Names are compared too, and the drafts do not spell them the same way
//!
//! A row whose code is right and whose name belongs to a different row is
//! exactly what a copy between two adjacent drafts produces, and the numbers
//! alone cannot see it. Draft-17 assigns PUBLISH_DONE 0x5 to `EXPIRED` and 0x6
//! to `TOO_FAR_BEHIND`; draft-18 swaps them. Both drafts have both codes and
//! both names, so only the pairing distinguishes them.
//!
//! What a name is, though, changes partway through the range. Drafts 14 and
//! later define their error codes in a list that gives each one a symbolic
//! name — `INTERNAL_ERROR`, `TOO_MANY_REQUESTS` — and the extraction records it
//! verbatim. Drafts 07 through 13 register the same codes in a table whose only
//! per-row label is a Reason, and write nothing beside it that names them, so
//! there is nothing to record: the extraction leaves `name` null and derives
//! `name_normalized` from the reason text, `Too Many Subscribes` becoming
//! `TOO_MANY_SUBSCRIBES`. Those drafts do reach for a symbolic spelling in
//! prose now and again — draft-13 says an Object with Status END_OF_GROUP, and
//! every draft from 07 on says to close with NO_ERROR — but never as the
//! registry's own label, which is the only place the extraction reads. The
//! Object Status registry crosses the same line four drafts later, at
//! draft-19's IANA table with its Name column.
//!
//! Every comparison below is against `name_normalized`, so it is against the
//! draft's own symbol where the draft has one and against a normalization of
//! its prose label where it does not. Which drafts supply which is asserted
//! rather than assumed, in
//! [`symbolic_names_appear_in_the_drafts_that_print_them`] — otherwise an
//! extraction that quietly stopped taking the names would leave every
//! comparison here still passing on the numbers.
//!
//! The crate's side needs a transform either way: the draft spells its names in
//! `UPPER_SNAKE_CASE` and this crate spells its variants in `UpperCamelCase`.
//! [`upper_snake`] is the mechanical transform between the two, applied to the
//! variant's `Debug` name.
//!
//! # Every draft, not a sample
//!
//! A gate that only ever sees one draft cannot tell that draft's registry from
//! its neighbour's, and a row copied forward from the previous draft is the
//! most likely way a wrong value gets in. Checking each draft against its
//! own extraction makes every one of them answer for itself.
//!
//! That argument needs the extractions to differ, so it is checked in
//! [`the_extracted_drafts_are_distinguishable_from_each_other`], which states
//! for every pair of drafts whether their assignments coincide. Three of them
//! do: drafts 08, 09 and 10 assign exactly the same error codes under the same
//! names, and their Object Status registries hold still for five drafts at a
//! time. Those runs are written down rather than excluded, so a draft leaving
//! one is as visible as a draft joining it.
//!
//! # What is deliberately not asserted
//!
//! From draft-17 on, each error registry ends with a row reserving
//! `0x7f * N + 0x9D` for greasing. It is a range written as an arithmetic
//! expression, not an assignment, so it gets no variant; the extraction marks
//! such rows `kind: "reserved"` and they are excluded from the expected set and
//! then required to decode as unassigned. That requirement is the arithmetic
//! itself and not a handful of its members: every code point a registry
//! declares is tested against the expression, so the range is covered whole
//! rather than sampled at the values someone thought to write down.
//!
//! Drafts 07 through 16 reserve nothing — they mention GREASE only as an open
//! TODO about setup parameters — so for those the check is that the reserved
//! row is absent, and no code point of theirs is held to a range their draft
//! does not set aside. [`greasing_era`] is where that boundary is stated.
//!
//! The per-code descriptions the extraction carries are not compared against
//! the crate's rustdoc. They are prose, and the draft rewords them between
//! revisions without changing what goes on the wire.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

#[cfg(feature = "draft07")]
use moqtap_codec::draft07;
#[cfg(feature = "draft08")]
use moqtap_codec::draft08;
#[cfg(feature = "draft09")]
use moqtap_codec::draft09;
#[cfg(feature = "draft10")]
use moqtap_codec::draft10;
#[cfg(feature = "draft11")]
use moqtap_codec::draft11;
#[cfg(feature = "draft12")]
use moqtap_codec::draft12;
#[cfg(feature = "draft13")]
use moqtap_codec::draft13;
#[cfg(feature = "draft14")]
use moqtap_codec::draft14;
#[cfg(feature = "draft15")]
use moqtap_codec::draft15;
#[cfg(feature = "draft16")]
use moqtap_codec::draft16;
#[cfg(feature = "draft17")]
use moqtap_codec::draft17;
#[cfg(feature = "draft18")]
use moqtap_codec::draft18;
#[cfg(feature = "draft19")]
use moqtap_codec::draft19;
#[cfg(feature = "draft20")]
use moqtap_codec::draft20;
#[cfg(feature = "draft21")]
use moqtap_codec::draft21;

/// Every draft with a committed extraction, which is every draft this crate
/// implements.
const DRAFTS: [u64; 14] = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

/// Highest code point swept when reading a registry back out of the crate.
///
/// The registries are sparse and their assignments are all below `0x40`, so the
/// ceiling exists to catch a code point this crate accepts that the draft does
/// not assign — it has to be well above the assigned range or an accidental
/// variant just past the end would go unseen.
///
/// It bounds the sweep and nothing else. Each registry also declares its own
/// set as an `ALL` const, and the two claims that could once only be sampled
/// are made against that: a declaration above the ceiling stops the test rather
/// than being swept past, and the greasing range is answered by arithmetic over
/// every declared code point rather than by looking a few members up. What is
/// left outside is one shape — a `from_u64` arm above the ceiling that no `ALL`
/// declares, undeclared and out of the sweep's reach at once.
const CEILING: u64 = 0xFFFF;

// ── The extracted draft ───────────────────────────────────────

/// Parse `tools/registries/draft-NN.json`.
fn extracted(draft: u64) -> Value {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tools/registries")
        // Zero-padded: the files are named after the draft as the IETF spells
        // it, `draft-07` through `draft-20`.
        .join(format!("draft-{draft:02}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));

    // The file names the draft it was extracted from. Reading it back guards
    // against a file being compared under the wrong draft number, which would
    // make every assertion below check the wrong document.
    assert_eq!(
        doc["draft"].as_u64(),
        Some(draft),
        "draft-{draft}.json reports draft {:?}",
        doc["draft"]
    );

    // The hash of the rendered draft is what ties these numbers to one
    // document. It is not recomputed here — the rendered drafts are not part of
    // this repository — but a file that lost it would silently become a set of
    // values with no stated origin.
    let sha = doc["source_sha256"].as_str().unwrap_or_else(|| {
        panic!("draft-{draft}.json carries no source_sha256; it is not tied to a rendered draft")
    });
    assert!(
        sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit()),
        "draft-{draft}.json source_sha256 is not a SHA-256 digest: {sha:?}"
    );

    doc
}

/// The registry the extraction filed under `registry_id`.
fn registry<'a>(doc: &'a Value, registry_id: &str) -> &'a Value {
    doc["registries"]
        .as_array()
        .unwrap_or_else(|| panic!("draft-{} has no registries array", doc["draft"]))
        .iter()
        .find(|r| r["registry_id"] == registry_id)
        .unwrap_or_else(|| panic!("draft-{} has no registry {registry_id}", doc["draft"]))
}

/// The code points a registry assigns, as code to name.
///
/// Rows the extraction marks `reserved` are ranges rather than assignments and
/// are excluded; [`reserved_greasing_row`] takes them instead.
fn assignments(reg: &Value) -> BTreeMap<u64, String> {
    let rows = reg["rows"].as_array().expect("registry has no rows array");
    let mut out = BTreeMap::new();
    for row in rows {
        if row["kind"] != "assignment" {
            continue;
        }
        let code = row["code_value"]
            .as_u64()
            .unwrap_or_else(|| panic!("assignment row without a code_value: {row}"));
        let name = row["name_normalized"]
            .as_str()
            .unwrap_or_else(|| panic!("assignment row without a name_normalized: {row}"))
            .to_string();
        if let Some(previous) = out.insert(code, name) {
            panic!("registry assigns {code:#x} twice; the first was {previous}");
        }
    }
    assert!(!out.is_empty(), "registry {} extracted no assignments", reg["registry"]);
    out
}

// ── The greasing range ────────────────────────────────────────

/// Whether a draft's error registries set the greasing range aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GreasingRange {
    /// The registry ends with a row reserving `0x7f * N + 0x9D`.
    Reserved,
    /// The draft sets no range aside, and this registry has no reserved row.
    NotYet,
}

/// Which of the two a draft is.
///
/// Draft-17 is the first with a Grease section — Section 13, "Grease" — and the
/// first whose registries carry a reservation. Before it the drafts mention
/// GREASE only in open TODOs, one to describe it for setup parameters and one
/// to grease the extension types, and reserve nothing; searching drafts 07
/// through 16 for the pattern finds no occurrence of it.
///
/// The boundary is stated once, here, rather than at each call: it is a
/// property of the document, not of the individual registry, and every registry
/// of a given draft is on the same side of it. Both eras are then asserted —
/// a draft on the `Reserved` side must have the row and be held to the range,
/// a draft on the `NotYet` side must have no reserved row at all — so moving
/// this boundary fails against whichever draft it is moved across.
///
/// # Ablation
///
/// Moving it down one draft puts draft-16 on the side that requires the row,
/// and draft-16 has none to find:
///
/// ```text
/// thread 'draft16_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// assertion `left == right` failed: registry "Session Termination Error Codes"
/// has 0 reserved rows, expected the one greasing range
///   left: 0
///  right: 1
/// ```
///
/// Moving it up one draft is the other side of the same claim, and is what
/// [`no_reserved_rows`] is for: draft-17 then has to have no reservation, and
/// it has one.
///
/// ```text
/// thread 'draft17_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-17 "Session Termination Error Codes": the extraction reserves
/// 0x7f * N + 0x9D, but no draft before 17 sets a range aside
/// ```
fn greasing_era(draft: u64) -> GreasingRange {
    if draft >= 17 {
        GreasingRange::Reserved
    } else {
        GreasingRange::NotYet
    }
}

/// Whether `code` is in the range the later registries reserve for greasing.
///
/// The reserved row writes the range as `0x7f * N + 0x9D`, so membership is
/// that arithmetic read backwards: a code point is greased when subtracting
/// `0x9D` from it leaves a multiple of `0x7f`. As a predicate the range is
/// answered for every `N` at once, where expanding it for chosen `N` and
/// looking each result up only ever asked about the members that were chosen.
///
/// The expression is what this follows, not the examples beside it. Draft-17's
/// Grease section illustrates the pattern with `0x9D, 0xBC, ...,
/// 0x3ffffffffffffffe`, and neither `0xBC` nor that last value is a member of
/// the range the same sentence defines — `0x7f * 1 + 0x9D` is `0x11C`, and the
/// largest member a varint can carry is `0x3fffffffffffffde`. Drafts 18 and 19
/// print both corrected values.
///
/// # Ablation
///
/// Moving `InvalidFilter` onto the first member of the range — `0x36` becoming
/// `0x9D` in `draft19::error_codes`, in the variant and in its `from_u64` arm
/// together, so that the crate really accepts it — is caught before the
/// comparison with the draft has a chance to call it an unassigned code point:
///
/// ```text
/// thread 'draft19_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-19 REQUEST_ERROR Codes: RequestErrorCode accepts 0x9d, which the
/// draft reserves for greasing rather than assigning
/// ```
///
/// The same move made in `tools/registries/draft-19.json` instead — the
/// extraction reporting `0x9D` as an assignment — is the other side, and is
/// named as the extraction's defect rather than the crate's:
///
/// ```text
/// thread 'draft19_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-19 REQUEST_ERROR Codes: the extraction reports 0x9d as assigned,
/// inside the range this same registry reserves for greasing
/// ```
fn is_greased(code: u64) -> bool {
    code >= 0x9D && (code - 0x9D).is_multiple_of(0x7f)
}

/// Require the registry's reserved row to still be the range [`is_greased`]
/// answers for.
///
/// The row's code is the expression `0x7f * N + 0x9D` rather than a number, and
/// this test can read only that one form. An extraction that spelled the range
/// some other way stops the test rather than leaving [`is_greased`] quietly
/// answering about a range the draft no longer reserves.
fn reserved_greasing_row(reg: &Value) {
    let rows = reg["rows"].as_array().expect("registry has no rows array");
    let reserved: Vec<&Value> = rows.iter().filter(|r| r["kind"] == "reserved").collect();
    assert_eq!(
        reserved.len(),
        1,
        "registry {} has {} reserved rows, expected the one greasing range",
        reg["registry"],
        reserved.len()
    );

    let code = reserved[0]["code"].as_str().unwrap_or_else(|| panic!("reserved row has no code"));
    let normalized: String = code.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    assert_eq!(
        normalized, "0x7f * n + 0x9d",
        "registry {} reserves {code:?}, which this test cannot expand",
        reg["registry"]
    );
}

/// Require the registry to reserve nothing.
///
/// An absence is worth asserting here because it is what the drafts before 17
/// actually say, and because the alternative — saying nothing about the earlier
/// drafts' reserved rows — would let a reservation appear in an extraction with
/// no test either enforcing it or refusing it.
///
/// Its ablation is [`greasing_era`]'s second one: moving the boundary up sends
/// a draft that does reserve the range down this path.
fn no_reserved_rows(draft: u64, reg: &Value) {
    let rows = reg["rows"].as_array().expect("registry has no rows array");
    let reserved: Vec<String> = rows
        .iter()
        .filter(|r| r["kind"] == "reserved")
        .map(|r| r["code"].as_str().unwrap_or("<no code>").to_string())
        .collect();
    assert!(
        reserved.is_empty(),
        "draft-{draft} {}: the extraction reserves {}, but no draft before 17 sets a range aside",
        reg["registry"],
        reserved.join(", ")
    );
}

// ── This crate ────────────────────────────────────────────────

/// `NoError` -> `NO_ERROR`.
///
/// The draft names a code `NO_ERROR` and this crate names the variant
/// `NoError`; comparing the two needs one of them transformed, and the
/// transform runs on the crate's side because the draft's spelling is the
/// authority. Every variant in these registries is `UpperCamelCase` with no
/// digits and no runs of capitals, so inserting a separator before each
/// interior capital is exact rather than a heuristic — `InvalidRequestId`
/// becomes `INVALID_REQUEST_ID`, which is what draft-19 Table 18 calls it.
fn upper_snake(camel: &str) -> String {
    let mut out = String::new();
    for (i, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// One registry as this crate has it, as code to name.
///
/// The set is taken twice, from two places that cannot be edited by the same
/// slip, and the two are required to agree. `ALL` is what the type declares,
/// and it is the half that can be enumerated — nothing can iterate an enum's
/// variants, so without it the registry has no stated end and every claim about
/// the whole of it has to be sampled. The sweep is the half that cannot fall
/// out of date: every code point up to [`CEILING`] is offered to `from_u64` and
/// the ones that come back are what the decoder really accepts.
///
/// Each catches what the other cannot. A code point left out of `ALL` but still
/// decoded is one no caller enumerating the registry will consider; a code point
/// in `ALL` that `from_u64` refuses is a registry entry that cannot arrive off
/// the wire. Only once they agree is either compared with the draft.
///
/// # Ablation
///
/// Dropping `RequestErrorCode::InvalidFilter` from `ALL` and leaving its
/// `from_u64` arm alone — the shape a hand-written list decays into — is the
/// disagreement, reported as the two sets:
///
/// ```text
/// thread 'draft19_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// assertion `left == right` failed: RequestErrorCode::ALL and
/// RequestErrorCode::from_u64 describe different sets
///   left: {..., 52: "REDIRECT", 53: "CONFLICTING_FILTERS"}
///  right: {..., 52: "REDIRECT", 53: "CONFLICTING_FILTERS", 54: "INVALID_FILTER"}
/// ```
///
/// All three of these are reported against the `registries!` line of the draft
/// whose registry it is, because that is where this macro is expanded.
///
/// Naming it twice instead is a list that reads as one entry longer than the
/// registry it describes:
///
/// ```text
/// assertion `left == right` failed: RequestErrorCode::ALL names one code
/// point twice: [..., ConflictingFilters, InvalidFilter, InvalidFilter]
///   left: 19
///  right: 20
/// ```
///
/// And renumbering `InvalidFilter` to `0x10000`, in the variant and its
/// `from_u64` arm together, is the one case the sweep alone could not see — it
/// is out of range, so without `ALL` it would simply not be swept:
///
/// ```text
/// RequestErrorCode::ALL declares 0x10000, which is above the 0xffff this
/// sweep reaches; raise CEILING
/// ```
macro_rules! codec_registry {
    ($ty:ty, $name:expr) => {{
        // Spelled out by the caller rather than taken from `stringify!` here:
        // this macro is reached through another one, and a type reassembled
        // from a substituted fragment prints with spaces around its `::`.
        let ty = $name;

        let declared: BTreeMap<u64, String> =
            <$ty>::ALL.iter().map(|v| (v.as_u64(), upper_snake(&format!("{v:?}")))).collect();
        assert_eq!(
            declared.len(),
            <$ty>::ALL.len(),
            "{ty}::ALL names one code point twice: {:?}",
            <$ty>::ALL
        );

        // The sweep has to reach everything `ALL` declares, or the two are
        // compared over a range that excludes the disagreement.
        let highest = declared.keys().copied().max().expect("a registry with no code points");
        assert!(
            highest <= CEILING,
            "{ty}::ALL declares {highest:#x}, which is above the {CEILING:#x} this sweep \
             reaches; raise CEILING"
        );

        let mut swept: BTreeMap<u64, String> = BTreeMap::new();
        for code in 0..=CEILING {
            if let Some(variant) = <$ty>::from_u64(code) {
                assert_eq!(
                    variant.as_u64(),
                    code,
                    "{ty}: from_u64({code:#x}) answered {variant:?}, whose as_u64 is {:#x}",
                    variant.as_u64()
                );
                swept.insert(code, upper_snake(&format!("{variant:?}")));
            }
        }

        assert_eq!(declared, swept, "{ty}::ALL and {ty}::from_u64 describe different sets");
        declared
    }};
}

// ── The comparison ────────────────────────────────────────────

/// Require the crate's registry and the draft's to be the same set of
/// code points with the same names.
fn same_registry(
    draft: u64,
    registry_id: &str,
    rust_type: &str,
    doc: &Value,
    codec: &BTreeMap<u64, String>,
) {
    let reg = registry(doc, registry_id);
    let title = reg["registry"].as_str().unwrap_or(registry_id);
    let spec = assignments(reg);

    // Both sides are held to the reserved range before they are compared with
    // each other. The comparison alone cannot see this: it makes the two sets
    // equal, so a greased code point in both would pass it and leave the crate
    // decoding a number the registry it was checked against says is not for
    // assigning. Each side is named separately because the fix is different —
    // one is a wrong extraction, the other a wrong variant.
    match greasing_era(draft) {
        GreasingRange::Reserved => {
            reserved_greasing_row(reg);
            let greased_by_draft: Vec<String> = spec
                .keys()
                .copied()
                .filter(|c| is_greased(*c))
                .map(|c| format!("{c:#x}"))
                .collect();
            assert!(
                greased_by_draft.is_empty(),
                "draft-{draft} {title}: the extraction reports {} as assigned, inside the range \
                 this same registry reserves for greasing",
                greased_by_draft.join(", ")
            );
            let greased_by_codec: Vec<String> = codec
                .keys()
                .copied()
                .filter(|c| is_greased(*c))
                .map(|c| format!("{c:#x}"))
                .collect();
            assert!(
                greased_by_codec.is_empty(),
                "draft-{draft} {title}: {rust_type} accepts {}, which the draft reserves for \
                 greasing rather than assigning",
                greased_by_codec.join(", ")
            );
        }
        // Nothing is held to the range on these drafts, because their registries
        // do not set it aside. A code point of theirs landing on `0x9D` would be
        // an ordinary assignment.
        GreasingRange::NotYet => no_reserved_rows(draft, reg),
    }

    let spec_codes: BTreeSet<u64> = spec.keys().copied().collect();
    let codec_codes: BTreeSet<u64> = codec.keys().copied().collect();

    let missing: Vec<String> =
        spec_codes.difference(&codec_codes).map(|c| format!("{c:#x} {}", spec[c])).collect();
    assert!(
        missing.is_empty(),
        "draft-{draft} {title}: assigned by the draft, not accepted by {rust_type}: {}",
        missing.join(", ")
    );

    let extra: Vec<String> =
        codec_codes.difference(&spec_codes).map(|c| format!("{c:#x} {}", codec[c])).collect();
    assert!(
        extra.is_empty(),
        "draft-{draft} {title}: accepted by {rust_type}, not assigned by the draft: {}",
        extra.join(", ")
    );

    for (code, spec_name) in &spec {
        assert_eq!(
            &codec[code], spec_name,
            "draft-{draft} {title}: {code:#x} is {spec_name} in the draft, {} in {rust_type}",
            codec[code]
        );
    }
}

/// One draft's error registries, each named with the type that transcribes it.
///
/// The list is the mapping, and it is not the same shape twice: the registries
/// split and merge across the range — draft-07 has three, draft-14 has eight,
/// draft-15 has four again — and one registry is renamed under the same id,
/// `stream_reset` carrying `StreamResetErrorCode` on drafts 11 through 13,
/// `DataStreamResetErrorCode` on 14 through 17, and `StreamResetErrorCode`
/// again from 18. So there is nothing to derive and the pairing is written out
/// per draft.
///
/// What is derived is that the list is complete. Every registry the extraction
/// carries has to appear, which is what stops a draft from being called gated
/// on the strength of the registries someone remembered to list.
///
/// # Ablation
///
/// Dropping the `publish_error` line from the draft-13 list leaves that
/// registry compared against nothing, and the list says so:
///
/// ```text
/// thread 'draft13_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-13: the extraction carries publish_error, which this test compares
/// against nothing
/// ```
macro_rules! registries {
    ($draft:expr, { $($id:literal => $ty:ident),+ $(,)? }) => {{
        let doc = extracted($draft);
        let mut compared: BTreeSet<&str> = BTreeSet::new();
        $(
            assert!(compared.insert($id), "draft-{}: {} is listed twice", $draft, $id);
            let codec = codec_registry!(ec::$ty, stringify!($ty));
            same_registry($draft, $id, stringify!($ty), &doc, &codec);
        )+

        // The other direction — a name in the list that the extraction does not
        // carry — is already a panic inside `registry`, which cannot go on
        // without it.
        let carried: BTreeSet<&str> = doc["registries"]
            .as_array()
            .expect("registries array")
            .iter()
            .map(|r| r["registry_id"].as_str().expect("registry_id"))
            .collect();
        let ungated: Vec<&str> = carried.difference(&compared).copied().collect();
        assert!(
            ungated.is_empty(),
            "draft-{}: the extraction carries {}, which this test compares against nothing",
            $draft,
            ungated.join(", ")
        );
    }};
}

// ── Error, status and termination code registries ─────────────

#[cfg(feature = "draft07")]
#[test]
fn draft07_error_registries_match_the_extracted_draft() {
    use draft07::error_codes as ec;

    registries!(7, {
        "session_termination" => SessionErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
    });
}

#[cfg(feature = "draft08")]
#[test]
fn draft08_error_registries_match_the_extracted_draft() {
    use draft08::error_codes as ec;

    registries!(8, {
        "session_termination" => SessionErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "fetch_error" => FetchErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
        "subscribe_announces_error" => SubscribeAnnouncesErrorCode,
    });
}

#[cfg(feature = "draft09")]
#[test]
fn draft09_error_registries_match_the_extracted_draft() {
    use draft09::error_codes as ec;

    registries!(9, {
        "session_termination" => SessionErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "fetch_error" => FetchErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
        "subscribe_announces_error" => SubscribeAnnouncesErrorCode,
    });
}

#[cfg(feature = "draft10")]
#[test]
fn draft10_error_registries_match_the_extracted_draft() {
    use draft10::error_codes as ec;

    registries!(10, {
        "session_termination" => SessionErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
        "fetch_error" => FetchErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_announces_error" => SubscribeAnnouncesErrorCode,
    });
}

#[cfg(feature = "draft11")]
#[test]
fn draft11_error_registries_match_the_extracted_draft() {
    use draft11::error_codes as ec;

    registries!(11, {
        "session_termination" => SessionErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
        "fetch_error" => FetchErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_announces_error" => SubscribeAnnouncesErrorCode,
        "stream_reset" => StreamResetErrorCode,
    });
}

#[cfg(feature = "draft12")]
#[test]
fn draft12_error_registries_match_the_extracted_draft() {
    use draft12::error_codes as ec;

    registries!(12, {
        "session_termination" => SessionErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
        "publish_error" => PublishErrorCode,
        "fetch_error" => FetchErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_announces_error" => SubscribeAnnouncesErrorCode,
        "stream_reset" => StreamResetErrorCode,
    });
}

#[cfg(feature = "draft13")]
#[test]
fn draft13_error_registries_match_the_extracted_draft() {
    use draft13::error_codes as ec;

    registries!(13, {
        "session_termination" => SessionErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "subscribe_done" => SubscribeDoneStatusCode,
        "publish_error" => PublishErrorCode,
        "fetch_error" => FetchErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_namespace_error" => SubscribeNamespaceErrorCode,
        "stream_reset" => StreamResetErrorCode,
    });
}

/// Draft-14 is where the registries are at their most divided: five of them
/// answer five different messages, and they disagree at `0x4`. It is also the
/// first draft to give its codes symbolic names.
#[cfg(feature = "draft14")]
#[test]
fn draft14_error_registries_match_the_extracted_draft() {
    use draft14::error_codes as ec;

    registries!(14, {
        "session_termination" => SessionErrorCode,
        "subscribe_error" => SubscribeErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "publish_error" => PublishErrorCode,
        "fetch_error" => FetchErrorCode,
        "announce_error" => AnnounceErrorCode,
        "subscribe_namespace_error" => SubscribeNamespaceErrorCode,
        "stream_reset" => DataStreamResetErrorCode,
    });
}

#[cfg(feature = "draft15")]
#[test]
fn draft15_error_registries_match_the_extracted_draft() {
    use draft15::error_codes as ec;

    registries!(15, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "stream_reset" => DataStreamResetErrorCode,
    });
}

#[cfg(feature = "draft16")]
#[test]
fn draft16_error_registries_match_the_extracted_draft() {
    use draft16::error_codes as ec;

    registries!(16, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "stream_reset" => DataStreamResetErrorCode,
    });
}

#[cfg(feature = "draft17")]
#[test]
fn draft17_error_registries_match_the_extracted_draft() {
    use draft17::error_codes as ec;

    registries!(17, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        // Drafts 14 through 17 title this registry "Data Stream Reset Error
        // Codes" and this crate names the draft-17 type to match; draft-18
        // renamed it and widened it beyond data streams.
        "stream_reset" => DataStreamResetErrorCode,
    });
}

/// # Ablation
///
/// Draft-17 assigns PUBLISH_DONE `0x5` to `EXPIRED` and `0x6` to
/// `TOO_FAR_BEHIND`; draft-18 swaps them. Copying draft-17's pairing into
/// `draft18::error_codes` — both names still present, both code points still
/// accepted, only the pairing wrong — is caught by name and not by count:
///
/// ```text
/// thread 'draft18_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// assertion `left == right` failed: draft-18 PUBLISH_DONE Codes: 0x5 is
/// TOO_FAR_BEHIND in the draft, EXPIRED in PublishDoneStatusCode
///   left: "EXPIRED"
///  right: "TOO_FAR_BEHIND"
/// ```
#[cfg(feature = "draft18")]
#[test]
fn draft18_error_registries_match_the_extracted_draft() {
    use draft18::error_codes as ec;

    registries!(18, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "stream_reset" => StreamResetErrorCode,
    });
}

/// # Ablation
///
/// Both of these take a coordinated edit, and that is the point of the `ALL`
/// cross-check standing in front of them: dropping the `from_u64` arm alone, or
/// adding one alone, is caught earlier as the crate disagreeing with itself,
/// and only a change made in both places gets as far as the draft.
///
/// Dropping one of the draft's assignments — `InvalidFilter` out of
/// `RequestErrorCode::ALL` and its `0x36` arm out of `from_u64` — is reported
/// against the draft that assigns it:
///
/// ```text
/// thread 'draft19_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-19 REQUEST_ERROR Codes: assigned by the draft, not accepted by
/// RequestErrorCode: 0x36 INVALID_FILTER
/// ```
///
/// Accepting a code point the draft does not assign — a plausible
/// `InvalidPriority = 0x37` added to the enum, to `ALL` and to `from_u64` — is
/// the direction a spec-driven iteration cannot see, and is reported the other
/// way round:
///
/// ```text
/// thread 'draft19_error_registries_match_the_extracted_draft' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-19 REQUEST_ERROR Codes: accepted by RequestErrorCode, not assigned by
/// the draft: 0x37 INVALID_PRIORITY
/// ```
#[cfg(feature = "draft19")]
#[test]
fn draft19_error_registries_match_the_extracted_draft() {
    use draft19::error_codes as ec;

    registries!(19, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "stream_reset" => StreamResetErrorCode,
    });
}

/// Draft-20 keeps all four registries and takes one row out of three of them.
///
/// The removals are what this comparison is for, and they are the direction a
/// spec-driven iteration cannot see: `VERSION_NEGOTIATION_FAILED` (session
/// `0x15`), `INVALID_JOINING_REQUEST_ID` (REQUEST_ERROR `0x32`) and
/// `SUBSCRIPTION_ENDED` (PUBLISH_DONE `0x3`) are each still assigned by
/// draft-19, so a registry copied forward keeps decoding them and every
/// "implement what the draft assigns" test still passes. Only comparing as a
/// set in both directions reports it.
///
/// # Ablation
///
/// Copying draft-19's `PublishDoneStatusCode` forward whole — the row and its
/// `from_u64` arm together, which is what a `cp -r draft19 draft20` produces:
///
/// ```text
/// draft-20 PUBLISH_DONE Codes: accepted by PublishDoneStatusCode, not assigned
/// by the draft: 0x3 SUBSCRIPTION_ENDED
/// ```
#[cfg(feature = "draft20")]
#[test]
fn draft20_error_registries_match_the_extracted_draft() {
    use draft20::error_codes as ec;

    registries!(20, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "stream_reset" => StreamResetErrorCode,
    });
}
/// Draft-21 keeps all four registries and takes one row out of three of them.
///
/// The removals are what this comparison is for, and they are the direction a
/// spec-driven iteration cannot see: `VERSION_NEGOTIATION_FAILED` (session
/// `0x15`), `INVALID_JOINING_REQUEST_ID` (REQUEST_ERROR `0x32`) and
/// `SUBSCRIPTION_ENDED` (PUBLISH_DONE `0x3`) are each still assigned by
/// draft-19, so a registry copied forward keeps decoding them and every
/// "implement what the draft assigns" test still passes. Only comparing as a
/// set in both directions reports it.
///
/// # Ablation
///
/// Copying draft-19's `PublishDoneStatusCode` forward whole — the row and its
/// `from_u64` arm together, which is what a `cp -r draft19 draft21` produces:
///
/// ```text
/// draft-21 PUBLISH_DONE Codes: accepted by PublishDoneStatusCode, not assigned
/// by the draft: 0x3 SUBSCRIPTION_ENDED
/// ```
#[cfg(feature = "draft21")]
#[test]
fn draft21_error_registries_match_the_extracted_draft() {
    use draft21::error_codes as ec;

    registries!(20, {
        "session_termination" => SessionErrorCode,
        "request_error" => RequestErrorCode,
        "publish_done" => PublishDoneStatusCode,
        "stream_reset" => StreamResetErrorCode,
    });
}

// ── Object Status registry ────────────────────────────────────

/// Compare one draft's Object Status set with the extraction's.
///
/// The extraction reports this registry separately from the error code
/// registries, because it is a different population counted under its own
/// definition: draft-19 prints it as an IANA table (Section 15.9, Table 16)
/// while drafts 07 through 18 assign the same code points as a bullet list in
/// the section defining the field. Both forms give a code and a name per row,
/// which is what is compared here; the difference between them is the subject
/// of `object_status_payload_rule.rs`.
///
/// It also reserves nothing on any draft: this is the one registry of the five
/// with no greasing row even on draft-19, so it is compared without the check
/// [`same_registry`] makes and [`reserved_greasing_row`] would stop the test
/// over an absent row.
fn same_object_status(draft: u64, doc: &Value, codec: &BTreeMap<u64, String>) {
    let reg = &doc["object_status"];
    assert_eq!(
        reg["present"],
        Value::Bool(true),
        "draft-{draft} extraction reports no Object Status registry"
    );
    let spec = assignments(reg);
    assert_eq!(
        &spec, codec,
        "draft-{draft} Object Status: the draft assigns {spec:?}, this crate accepts {codec:?}"
    );
}

/// # Ablation
///
/// Renumbering a status — `EndOfTrack` moved from `0x4` to `0x5` in
/// `draft19::types`, the code point drafts 07-10 used for a status of their
/// own — fails against Table 16:
///
/// ```text
/// thread 'object_status_registries_match_the_extracted_drafts' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// assertion `left == right` failed: draft-19 Object Status: the draft assigns
/// {0: "NORMAL", 3: "END_OF_GROUP", 4: "END_OF_TRACK"}, this crate accepts
/// {0: "NORMAL", 3: "END_OF_GROUP", 5: "END_OF_TRACK"}
///   left: {0: "NORMAL", 3: "END_OF_GROUP", 4: "END_OF_TRACK"}
///  right: {0: "NORMAL", 3: "END_OF_GROUP", 5: "END_OF_TRACK"}
/// ```
#[test]
fn object_status_registries_match_the_extracted_drafts() {
    #[cfg(feature = "draft07")]
    same_object_status(
        7,
        &extracted(7),
        &codec_registry!(draft07::types::ObjectStatus, "draft07 ObjectStatus"),
    );
    #[cfg(feature = "draft08")]
    same_object_status(
        8,
        &extracted(8),
        &codec_registry!(draft08::types::ObjectStatus, "draft08 ObjectStatus"),
    );
    #[cfg(feature = "draft09")]
    same_object_status(
        9,
        &extracted(9),
        &codec_registry!(draft09::types::ObjectStatus, "draft09 ObjectStatus"),
    );
    #[cfg(feature = "draft10")]
    same_object_status(
        10,
        &extracted(10),
        &codec_registry!(draft10::types::ObjectStatus, "draft10 ObjectStatus"),
    );
    #[cfg(feature = "draft11")]
    same_object_status(
        11,
        &extracted(11),
        &codec_registry!(draft11::types::ObjectStatus, "draft11 ObjectStatus"),
    );
    #[cfg(feature = "draft12")]
    same_object_status(
        12,
        &extracted(12),
        &codec_registry!(draft12::types::ObjectStatus, "draft12 ObjectStatus"),
    );
    #[cfg(feature = "draft13")]
    same_object_status(
        13,
        &extracted(13),
        &codec_registry!(draft13::types::ObjectStatus, "draft13 ObjectStatus"),
    );
    #[cfg(feature = "draft14")]
    same_object_status(
        14,
        &extracted(14),
        &codec_registry!(draft14::types::ObjectStatus, "draft14 ObjectStatus"),
    );
    #[cfg(feature = "draft15")]
    same_object_status(
        15,
        &extracted(15),
        &codec_registry!(draft15::types::ObjectStatus, "draft15 ObjectStatus"),
    );
    #[cfg(feature = "draft16")]
    same_object_status(
        16,
        &extracted(16),
        &codec_registry!(draft16::types::ObjectStatus, "draft16 ObjectStatus"),
    );
    #[cfg(feature = "draft17")]
    same_object_status(
        17,
        &extracted(17),
        &codec_registry!(draft17::types::ObjectStatus, "draft17 ObjectStatus"),
    );
    #[cfg(feature = "draft18")]
    same_object_status(
        18,
        &extracted(18),
        &codec_registry!(draft18::types::ObjectStatus, "draft18 ObjectStatus"),
    );
    #[cfg(feature = "draft19")]
    same_object_status(
        19,
        &extracted(19),
        &codec_registry!(draft19::types::ObjectStatus, "draft19 ObjectStatus"),
    );
    #[cfg(feature = "draft20")]
    same_object_status(
        20,
        &extracted(20),
        &codec_registry!(draft20::types::ObjectStatus, "draft20 ObjectStatus"),
    );
    #[cfg(feature = "draft21")]
    same_object_status(
        20,
        &extracted(20),
        &codec_registry!(draft21::types::ObjectStatus, "draft21 ObjectStatus"),
    );
}

// ── The extractions have to be able to disagree ───────────────

/// Runs of drafts whose error-code assignments are the same set of codes under
/// the same names.
///
/// Drafts 08, 09 and 10 changed nothing in any of their six registries; every
/// other draft in the range changed something. The runs are a partition of
/// [`DRAFTS`], so every one of the ninety-one pairs is claimed one way or
/// the other rather than merely not being claimed to differ.
const ERROR_REGISTRY_ERAS: &[&[u64]] =
    &[&[7], &[8, 9, 10], &[11], &[12], &[13], &[14], &[15], &[16], &[17], &[18], &[19], &[20]];

/// The same, for Object Status.
///
/// This registry moves three times in drafts and then holds: draft-08
/// renamed `0x5` from END_OF_SUBGROUP to END_OF_TRACK, draft-11 dropped `0x5`
/// and renamed `0x4` from END_OF_TRACK_AND_GROUP to END_OF_TRACK, and draft-16
/// dropped OBJECT_DOES_NOT_EXIST. Draft-19 changed how the registry is printed,
/// not what it assigns, and draft-20 changed nothing at all, which is why both
/// share a run with 16.
const OBJECT_STATUS_ERAS: &[&[u64]] =
    &[&[7], &[8, 9, 10], &[11, 12, 13, 14, 15], &[16, 17, 18, 19, 20]];

/// Every draft checked against its own file only proves something if the
/// files differ.
///
/// If an extraction were re-run in a way that gave every draft the same rows,
/// every assertion above would still pass and would have stopped
/// distinguishing the drafts — the exact failure the per-draft spread exists to
/// catch. So each pair of drafts is required to agree or disagree exactly as
/// the two era lists say.
///
/// The claim runs both ways on purpose. A pair the lists put in different runs
/// must differ, which is what catches an extraction collapsing onto its
/// neighbour; a pair inside one run must be identical, which is what catches
/// one drifting away from a draft it is supposed to match.
///
/// # Ablation
///
/// Moving draft-10 into its own run — the shape this test would have if the
/// coincidence between 08, 09 and 10 had been excluded rather than stated:
///
/// ```text
/// thread 'the_extracted_drafts_are_distinguishable_from_each_other' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// drafts 8 and 10 assign identical error code points, but this test has them
/// in different runs
/// ```
///
/// And putting draft-11 into the run its Object Status registry left is the
/// other direction, which is the one an exclusion could not have caught:
///
/// ```text
/// thread 'the_extracted_drafts_are_distinguishable_from_each_other' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// drafts 8 and 11 are in one run, but their Object Status assignments differ
/// ```
#[test]
fn the_extracted_drafts_are_distinguishable_from_each_other() {
    fn partitions(eras: &[&[u64]], what: &str) -> BTreeMap<u64, usize> {
        let mut out = BTreeMap::new();
        for (index, era) in eras.iter().enumerate() {
            for draft in *era {
                assert!(
                    out.insert(*draft, index).is_none(),
                    "the {what} runs name draft-{draft} twice"
                );
            }
        }
        assert_eq!(
            out.keys().copied().collect::<Vec<u64>>(),
            DRAFTS.to_vec(),
            "the {what} runs are not a partition of the drafts with an extraction"
        );
        out
    }

    fn error_codes(draft: u64) -> BTreeSet<(String, u64, String)> {
        let doc = extracted(draft);
        let mut out = BTreeSet::new();
        for reg in doc["registries"].as_array().expect("registries array") {
            let id = reg["registry_id"].as_str().expect("registry_id").to_string();
            for (code, name) in assignments(reg) {
                out.insert((id.clone(), code, name));
            }
        }
        out
    }

    fn object_status(draft: u64) -> BTreeSet<(String, u64, String)> {
        let doc = extracted(draft);
        assignments(&doc["object_status"])
            .into_iter()
            .map(|(code, name)| (String::from("object_status"), code, name))
            .collect()
    }

    for (eras, what, fingerprint) in [
        (ERROR_REGISTRY_ERAS, "error code", error_codes as fn(u64) -> BTreeSet<_>),
        (OBJECT_STATUS_ERAS, "Object Status", object_status as fn(u64) -> BTreeSet<_>),
    ] {
        let run = partitions(eras, what);
        let taken: BTreeMap<u64, BTreeSet<(String, u64, String)>> =
            DRAFTS.iter().map(|d| (*d, fingerprint(*d))).collect();

        for (i, a) in DRAFTS.iter().enumerate() {
            for b in &DRAFTS[i + 1..] {
                let together = run[a] == run[b];
                let identical = taken[a] == taken[b];
                if identical && !together {
                    panic!(
                        "drafts {a} and {b} assign identical {what} points, but this test has \
                         them in different runs"
                    );
                }
                if !identical && together {
                    panic!(
                        "drafts {a} and {b} are in one run, but their {what} assignments differ"
                    );
                }
            }
        }
    }
}

/// The drafts that print a symbolic name are the ones the comparison takes one
/// from.
///
/// Every name compared above is `name_normalized`, and that field has two
/// sources. Where the draft defines its codes in a list that names them, the
/// extraction records the name verbatim in `name` and normalizes that; where
/// the draft prints only a table with a Reason column, `name` stays null and
/// the normalization is of the reason text. Both are compared the same way, so
/// nothing above can tell which it got.
///
/// That is worth pinning, because the degradation it protects against is
/// silent: an extraction that stopped taking the names from draft-19's
/// definition list would fall back to normalizing prose, and the two agree
/// today on every row — `INTERNAL_ERROR` the symbol and `Internal Error` the
/// reason normalize alike. It would keep passing until a draft named a code
/// something its prose does not say.
///
/// The two boundaries are four drafts apart, because they are different
/// documents' decisions: draft-14 is the first to name its error codes, and
/// draft-19 is the first to give Object Status an IANA table with a Name
/// column. Both are thresholds rather than equalities — draft-20 prints the
/// same Object Status table draft-19 does, so a `draft == 19` test would have
/// failed against a draft that agrees with it completely.
///
/// # Ablation
///
/// Deleting the `name` from one draft-19 REQUEST_ERROR row in
/// `tools/registries/draft-19.json` — the row-level form of that fallback —
/// leaves every comparison above passing and fails here:
///
/// ```text
/// thread 'symbolic_names_appear_in_the_drafts_that_print_them' panicked at
/// crates\moqtap-codec\tests\registry_conformance.rs:
/// draft-19 request_error 0x36: draft-14 and later name their error codes, so
/// this row should carry a name and it carries none
/// ```
#[test]
fn symbolic_names_appear_in_the_drafts_that_print_them() {
    for draft in DRAFTS {
        let doc = extracted(draft);

        for reg in doc["registries"].as_array().expect("registries array") {
            let id = reg["registry_id"].as_str().expect("registry_id");
            for row in reg["rows"].as_array().expect("rows array") {
                if row["kind"] != "assignment" {
                    continue;
                }
                let code = row["code"].as_str().unwrap_or("<no code>");
                let named = row["name"].is_string();
                let source = row["description_source"].as_str().unwrap_or("<none>");
                if draft >= 14 {
                    assert!(
                        named,
                        "draft-{draft} {id} {code}: draft-14 and later name their error codes, \
                         so this row should carry a name and it carries none"
                    );
                    assert!(
                        source.starts_with("section "),
                        "draft-{draft} {id} {code}: a named row should have come from the \
                         definition list that names it, not from {source:?}"
                    );
                } else {
                    assert!(
                        !named,
                        "draft-{draft} {id} {code}: no draft before 14 labels a registry row \
                         with a symbolic name, so this one was read from somewhere that is not \
                         the registry"
                    );
                    assert_eq!(
                        source, "reason-column",
                        "draft-{draft} {id} {code}: an unnamed row's name is normalized from \
                         the Reason column, so that is where it has to have come from"
                    );
                }
                assert!(
                    row["name_normalized"].is_string(),
                    "draft-{draft} {id} {code}: no name_normalized, so there is nothing to \
                     compare the crate's variant against"
                );
            }
        }

        for row in doc["object_status"]["rows"].as_array().expect("rows array") {
            if row["kind"] != "assignment" {
                continue;
            }
            let code = row["code"].as_str().unwrap_or("<no code>");
            assert_eq!(
                row["name"].is_string(),
                draft >= 19,
                "draft-{draft} Object Status {code}: draft-19 is the first to print this \
                 registry as a table with a Name column, and draft-20 keeps it"
            );
            assert!(
                row["name_normalized"].is_string(),
                "draft-{draft} Object Status {code}: no name_normalized, so there is nothing \
                 to compare the crate's variant against"
            );
        }
    }
}

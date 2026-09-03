//! The committed registry extractions must be clean, and their two registry
//! definitions must have stayed apart.
//!
//! The other registry gates read values out of `tools/registries/draft-NN.json`
//! and compare them with this crate. That catches the crate drifting from the
//! extraction. It does not catch the extraction itself quietly degrading — and
//! a degraded extraction can go on producing the same row counts, so every
//! count-based check keeps passing while the rows lose a column.
//!
//! Nothing here can re-derive the JSON from the rendered draft; those documents
//! are not part of this repository, which is why each file carries
//! `source_sha256` instead. They are published Internet-Drafts and the tool
//! will fetch them — `extract-registries.py --all --fetch --check` re-derives
//! all fourteen from the IETF archive and fails if any row moved. What these tests do is make the extraction's own
//! self-reporting binding: the tool records a warning whenever it passes over
//! something it believes it should have taken, and counts the one overlap that
//! would mean its two definitions had collided. Neither was read by anything
//! until now, so both could be non-empty and non-zero in a committed file with
//! no test to say so.

use std::path::PathBuf;

use serde_json::Value;

/// The drafts with a committed extraction.
const DRAFTS: [u64; 14] = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

fn extraction(draft: u64) -> Value {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tools/registries")
        // Zero-padded: the files are named after the draft as the IETF spells
        // it, `draft-07` through `draft-20`.
        .join(format!("draft-{draft:02}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

/// No committed extraction may carry a warning.
///
/// The tool warns when it takes a table that matched a registry layout but
/// failed the semantic guard, when it merges line-wrap rows, and — the case
/// this test exists for — when it finds a table of code points under a heading
/// naming Object Status that it did not extract as the Object Status registry.
///
/// That last one is the failure mode of anchoring the Object Status extraction
/// on an exact heading. Retitling Section 15.9 to "Object Status Codes", which
/// is how every error registry in Section 15.11 is already spelled, makes the
/// heading match fail; the extraction falls back to the prose bullets in the
/// definition section, still reports three rows, and drops the Payload column
/// that is the whole reason draft-19 has that registry. The summary line is
/// unchanged apart from one word. Only the warning distinguishes it, and a
/// warning nothing reads is a warning that has not been raised.
///
/// Re-extracting draft-19 from a copy of the rendered draft with that heading
/// retitled fails this test with:
///
/// ```text
/// draft-19.json was committed with 1 warning(s): [
///     String("table-16: a code point table under '15.9. Object Status Codes' was
///     not extracted as the Object Status registry, and no Object Status registry
///     table was found anywhere in this draft. The section heading no longer reads
///     exactly 'Object Status', so the extraction fell back to the prose bullets
///     and any Payload column in this table has been dropped"),
/// ]
/// ```
#[test]
fn no_committed_extraction_carries_a_warning() {
    for draft in DRAFTS {
        let doc = extraction(draft);
        let warnings = doc["warnings"].as_array().unwrap_or_else(|| {
            panic!("draft-{draft}.json has no warnings array; it was not produced by the tool")
        });
        assert!(
            warnings.is_empty(),
            "draft-{draft}.json was committed with {} warning(s): {:#?}",
            warnings.len(),
            warnings
        );
    }
}

/// The Object Status registry and the outcome-code registries must not have
/// been read out of the same table.
///
/// The extraction counts two populations under two different definitions and
/// reports them separately, on the stated understanding that they never
/// overlap. `object_status_rows_also_counted_in_rows` is the tool's own measure
/// of that: the number of outcome-registry rows taken from the table the Object
/// Status registry came from.
///
/// It is reachable. Draft-19's Object Status table escapes the outcome-registry
/// filter only because its header reads `Code | Name | Payload | Specification`
/// — four columns, matching neither registry layout. A revision that dropped
/// the Payload column would leave `Name | Code | Specification`, which is the
/// IANA registry shape, and the semantic guard admits a table on the word
/// "status". The same three rows would then be counted once as outcome codes
/// and once as Object Status, and `totals.rows` would absorb them without any
/// other number moving.
#[test]
fn the_two_registry_definitions_do_not_share_a_source_table() {
    for draft in DRAFTS {
        let doc = extraction(draft);
        let totals = &doc["totals"];
        let overlap =
            totals["object_status_rows_also_counted_in_rows"].as_u64().unwrap_or_else(|| {
                panic!("draft-{draft}.json totals carry no object_status_rows_also_counted_in_rows")
            });
        assert_eq!(
            overlap, 0,
            "draft-{draft}: {overlap} outcome-registry row(s) came from the Object Status \
             table, so the same table was counted under both definitions"
        );

        // And the separation the overlap measures is only meaningful if the
        // two populations are actually reported apart: totals.rows must be the
        // sum of the registry row counts alone, with the Object Status rows
        // outside it.
        let sum: u64 = doc["registries"]
            .as_array()
            .unwrap_or_else(|| panic!("draft-{draft}.json has no registries array"))
            .iter()
            .map(|r| r["row_count"].as_u64().expect("registry without a row_count"))
            .sum();
        assert_eq!(
            totals["rows"].as_u64(),
            Some(sum),
            "draft-{draft}: totals.rows disagrees with the sum of the registry row counts"
        );
    }
}

/// Every Object Status row the extraction reports as an assignment carries a
/// payload permission.
///
/// This is the observable that the heading-anchored degradation actually
/// destroys. Falling back to the prose bullets leaves `payload` null on every
/// row, because the prose branch derives a permission only from the blanket
/// sentence of drafts 07-18 and draft-19 replaced that sentence with a deferral
/// to the registry. Row counts survive; this does not.
///
/// Re-extracting draft-19 from a retitled copy of the rendered draft fails this
/// test with:
///
/// ```text
/// draft-19 Object Status 0x0 has payload None; every assignment must record
/// whether it permits a payload
/// ```
#[test]
fn every_object_status_assignment_has_a_payload_permission() {
    for draft in DRAFTS {
        let doc = extraction(draft);
        let reg = &doc["object_status"];
        assert_eq!(
            reg["present"],
            Value::Bool(true),
            "draft-{draft} extracted no Object Status registry at all"
        );
        let rows = reg["rows"]
            .as_array()
            .unwrap_or_else(|| panic!("draft-{draft} Object Status registry has no rows array"));

        let mut assignments = 0;
        for row in rows {
            if row["kind"] != "assignment" {
                continue;
            }
            assignments += 1;
            let code = row["code"].as_str().unwrap_or("<no code>");
            let payload = row["payload"].as_str();
            assert!(
                matches!(payload, Some("yes") | Some("no")),
                "draft-{draft} Object Status {code} has payload {payload:?}; every assignment \
                 must record whether it permits a payload"
            );
            let source = row["payload_source"].as_str();
            assert!(
                source.is_some(),
                "draft-{draft} Object Status {code} records a payload permission with no \
                 payload_source, so there is no way to tell a registered answer from an \
                 inferred one"
            );
        }
        assert!(assignments > 0, "draft-{draft} Object Status registry assigns nothing");
    }
}

/// The first draft to give Object Status an IANA registry is 19, and every
/// draft from there on reads its permissions out of a Payload column.
///
/// The distinction the extraction records between a permission the draft
/// registered and one the tool derived from an older blanket sentence is what
/// separates draft-19 and later from their predecessors — the three rows are
/// otherwise identical in code, name and answer. A degraded draft-19 or
/// draft-20 extraction reports `form: prose-list` and looks exactly like a
/// draft-18 one, so pinning the form is what makes that visible from inside
/// this repository.
///
/// The boundary is stated as a threshold rather than as `draft == 19`, which is
/// what it was until draft-20 arrived. Draft-20 Section 15.9 prints the same
/// table with the same Payload column and changes no row, so an equality test
/// would have failed against a draft that agrees with 19 completely — and the
/// obvious fix, deleting the test, is what would have lost the claim.
#[test]
fn object_status_permissions_come_from_a_column_from_draft19_on() {
    for draft in DRAFTS {
        let doc = extraction(draft);
        let reg = &doc["object_status"];
        let expected_iana = draft >= 19;

        assert_eq!(
            reg["iana_registry"].as_bool(),
            Some(expected_iana),
            "draft-{draft} iana_registry should be {expected_iana}"
        );
        assert_eq!(
            reg["form"].as_str(),
            Some(if expected_iana { "iana-table" } else { "prose-list" }),
            "draft-{draft} Object Status form"
        );

        let expected_source = if expected_iana { "payload-column" } else { "blanket-rule" };
        for row in reg["rows"].as_array().expect("rows array") {
            if row["kind"] != "assignment" {
                continue;
            }
            let code = row["code"].as_str().unwrap_or("<no code>");
            let source = row["payload_source"].as_str().unwrap_or("<none>");
            if expected_iana {
                assert_eq!(
                    source, expected_source,
                    "draft-{draft} Object Status {code}: draft-19 and later register a \
                     Payload column, so every row's permission must come from it"
                );
            } else {
                // Drafts 07-18 have no column; 0x0 is the complement of their
                // blanket sentence rather than a value it states.
                assert!(
                    source.starts_with("blanket-rule"),
                    "draft-{draft} Object Status {code}: no draft before 19 has a Payload \
                     column, so its permission cannot have come from one ({source})"
                );
            }
        }
    }
}

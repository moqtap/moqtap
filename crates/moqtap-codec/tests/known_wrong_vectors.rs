//! The committed corpus and this codec must agree about every Object Status,
//! and this file is the standing check that they do.
//!
//! Every draft's whole data-stream corpus is swept against that draft's own
//! `ObjectStatus::ALL`, and the set of disagreements must be exactly what
//! [`KNOWN_WRONG`] records. That table is empty, so all fourteen sweeps assert
//! the same thing: no committed vector claims a status its draft does not
//! assign.
//!
//! # What the empty table means
//!
//! The trap a row would record is a vector seeded from the draft-08 numbering,
//! in which 0x4 is End of Track and Group and 0x5 is End of Track. Draft-11
//! Section 9.1.1.1 and draft-12 Section 9.2.1.1 merge those two into one: they
//! assign 0x0, 0x1, 0x3 and 0x4 only, name 0x4 "End of Track", and say any
//! other value SHOULD be treated as a protocol error that terminates the
//! session with a Protocol Violation. A `datagram-status-end-of-track`,
//! `fetch-end-of-track` or `subgroup-end-of-track` vector carrying 0x5 on
//! either draft is that trap; the corpus encodes 0x4, so no row is needed.
//!
//! An empty table is not a weaker check than a populated one — it is the
//! stronger claim. The sweep is the invariant; the table only ever named the
//! exceptions to it. With no exceptions left, every draft asserts that its
//! corpus agrees with it completely, and a bad vector on any draft fails
//! outright rather than being excused by a row. A row is added only to record a
//! disagreement this repository has decided to keep, and never to quiet one.
//!
//! # Why an empty result is not trusted on its own
//!
//! The sweep expects an empty row set everywhere, which is also what a sweep
//! that read nothing produces. Three ways of reading nothing are therefore
//! refused rather than returned as a clean answer: a directory with no vector
//! files, a file with no vectors, and — the one this corpus can actually
//! produce — a draft whose whole corpus yields no status field at all.
//!
//! That last one is why [`test_vectors::statuses_in`] names two JSON keys. The
//! corpus spells the field `object_status` in drafts 07-14 and on drafts 15-21's
//! datagram headers, but `status` inside drafts 15-21's subgroup objects. A walk
//! that knew only the first name read none of those six drafts' subgroup
//! objects and reported a clean sweep over vectors it had never opened.
//!
//! # What these tests catch, observed by making each change and running them
//!
//! A disagreement on a draft that has none. Deleting `ObjectStatus::EndOfGroup`
//! from draft-13's `ObjectStatus::ALL` turns every draft-13 vector carrying
//! `0x3` into a status the draft no longer assigns, and
//! `draft13_corpus_object_statuses` fails with:
//!
//! ```text
//! assertion `left == right` failed: draft13: the corpus disagrees with the draft
//! somewhere this repository has no record of. Every row must be listed in
//! KNOWN_WRONG with why, or the corpus must be fixed.
//!   left: [("datagram.json", "datagram-status-end-of-group", 3), ("datagram.json",
//!   "datagram-status-with-extensions", 3), ("fetch-header.json",
//!   "fetch-zero-payload-status", 3), ("subgroup.json", "subgroup-end-of-group", 3)]
//!  right: []
//! ```
//!
//! A disagreement the walk cannot see. Deleting `ObjectStatus::Normal` from
//! draft-17's `ObjectStatus::ALL` — 0x0 appears in draft-17's corpus only under
//! `status` — fails `draft17_corpus_object_statuses` with:
//!
//! ```text
//! left: [("subgroup.json", "subgroup-explicit-subgroup-id", 0)]
//! right: []
//! ```
//!
//! With `object_status` as the only key the walk knows, the same deletion
//! passes: 1 passed, 0 failed. That is what the second key is worth.
//!
//! The key names going stale again. Renaming both of them in `statuses_in` to
//! spellings the corpus does not use fails every sweep here:
//!
//! ```text
//! draft19: swept 34 vectors and found no object status in any of them. Every draft's
//! data-stream corpus carries statuses, so this is the walk having lost the corpus, not
//! the corpus having lost its statuses — check the JSON key names in `statuses_in`.
//! ```

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

mod test_vectors;

use test_vectors::{
    load_vectors, statuses_in, unassigned_statuses, vectors_dir, KNOWN_WRONG_MESSAGE_VECTORS,
};

/// Every disagreement between the committed corpus and the draft it claims to
/// encode: `(draft directory, file, vector id, the status the draft does not
/// assign)`.
///
/// Empty, and that is the assertion: no data-stream vector on any draft carries
/// an Object Status its own draft leaves unassigned. The sweeps below fail if
/// the corpus grows a disagreement that is not listed here, and fail if a
/// listed one goes away — so a row is a deliberate, documented record that the
/// vector is wrong and this codec is right, never a way to quiet a failure.
const KNOWN_WRONG: &[(&str, &str, &str, u64)] = &[];

/// One row of the sweep: the file it came from, the vector id, and the code.
type Row = (String, String, u64);

/// The `data-streams` directory for one draft.
fn data_streams_dir(draft: &str) -> std::path::PathBuf {
    vectors_dir().join("transport").join(draft).join("codec").join("data-streams")
}

/// Every vector file in a draft's `data-streams` directory, by name.
///
/// Read from the directory rather than from a list, so a file added upstream is
/// swept rather than silently ignored.
fn data_stream_files(draft: &str) -> Vec<String> {
    let dir = data_streams_dir(draft);
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("cannot read {}: {e} — did you init the submodule?", dir.display())
    });
    let mut names: Vec<String> = entries
        .map(|entry| entry.expect("directory entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    assert!(
        !names.is_empty(),
        "{}: no vector files — an empty sweep proves nothing",
        dir.display()
    );
    names
}

/// Every `(file, vector id, code)` in this draft's data-stream corpus whose
/// expected decode carries a status the draft does not assign.
///
/// Three ways of proving nothing are refused rather than returned as an empty
/// answer: a directory with no files, a file with no vectors, and — the one
/// this corpus can actually produce — a draft whose whole corpus yields no
/// status field, which is what a walk looking for a key the corpus does not use
/// looks like from here. All three read as "clean" in the row set alone, and
/// with every draft's expected set empty, "clean" is the answer every sweep is
/// hoping for.
fn sweep(draft: &str, assigned: &[u64]) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut vectors_seen = 0usize;
    let mut statuses_seen = 0usize;

    for file in data_stream_files(draft) {
        let parsed = load_vectors(&data_streams_dir(draft).join(&file));
        for vector in &parsed.vectors {
            vectors_seen += 1;
            statuses_seen += statuses_in(vector).len();
            for code in unassigned_statuses(vector, assigned) {
                rows.push((file.clone(), vector.id.clone(), code));
            }
        }
        assert!(
            !parsed.vectors.is_empty(),
            "{draft}/{file}: no vectors — an empty file cannot be distinguished from a clean one"
        );
    }

    assert!(vectors_seen > 0, "{draft}: swept no vectors at all");
    assert!(
        statuses_seen > 0,
        "{draft}: swept {vectors_seen} vectors and found no object status in any of them. \
         Every draft's data-stream corpus carries statuses, so this is the walk having lost \
         the corpus, not the corpus having lost its statuses — check the JSON key names in \
         `statuses_in`."
    );
    rows
}

/// The rows [`KNOWN_WRONG`] claims for one draft.
fn expected(draft: &str) -> Vec<Row> {
    let mut rows: Vec<Row> = KNOWN_WRONG
        .iter()
        .filter(|(dir, ..)| *dir == draft)
        .map(|(_, file, id, code)| (file.to_string(), id.to_string(), *code))
        .collect();
    rows.sort();
    rows
}

/// Generates one draft's corpus sweep. Every draft gets one, and every one of
/// them now expects an empty row set — that is the assertion that no
/// disagreement survives anywhere in the corpus.
macro_rules! corpus_sweep {
    ($name:ident, $feat:literal, $module:ident, $dir:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$module::types::ObjectStatus;
            let assigned: Vec<u64> = ObjectStatus::ALL.iter().map(|s| s.as_u64()).collect();

            let mut found = sweep($dir, &assigned);
            found.sort();

            assert_eq!(
                found,
                expected($dir),
                "{}: the corpus disagrees with the draft somewhere this repository has no \
                 record of. Every row must be listed in KNOWN_WRONG with why, or the corpus \
                 must be fixed.",
                $dir
            );
        }
    };
}

corpus_sweep!(draft07_corpus_object_statuses, "draft07", draft07, "draft07");
corpus_sweep!(draft08_corpus_object_statuses, "draft08", draft08, "draft08");
corpus_sweep!(draft09_corpus_object_statuses, "draft09", draft09, "draft09");
corpus_sweep!(draft10_corpus_object_statuses, "draft10", draft10, "draft10");
corpus_sweep!(draft11_corpus_object_statuses, "draft11", draft11, "draft11");
corpus_sweep!(draft12_corpus_object_statuses, "draft12", draft12, "draft12");
corpus_sweep!(draft13_corpus_object_statuses, "draft13", draft13, "draft13");
corpus_sweep!(draft14_corpus_object_statuses, "draft14", draft14, "draft14");
corpus_sweep!(draft15_corpus_object_statuses, "draft15", draft15, "draft15");
corpus_sweep!(draft16_corpus_object_statuses, "draft16", draft16, "draft16");
corpus_sweep!(draft17_corpus_object_statuses, "draft17", draft17, "draft17");
corpus_sweep!(draft18_corpus_object_statuses, "draft18", draft18, "draft18");
corpus_sweep!(draft19_corpus_object_statuses, "draft19", draft19, "draft19");
corpus_sweep!(draft20_corpus_object_statuses, "draft20", draft20, "draft20");
corpus_sweep!(draft21_corpus_object_statuses, "draft21", draft21, "draft21");

// ─────────────────────────────────────────────────────────────
// Message vectors carrying a parameter their draft does not admit there
// ─────────────────────────────────────────────────────────────
//
// The same shape as the data-stream sweep above, one layer up: a list of
// vectors this repository refuses on purpose, pinned so the skips in
// `vectors_draft17.rs`, `vectors_draft18.rs` and `vectors_draft19.rs` cannot be
// silent.
//
// `test_vectors::KNOWN_WRONG_MESSAGE_VECTORS` carries the list and the reason.
// The sweep below is the other half: for each of drafts 17 through 20 it
// decodes every committed message vector that claims a successful decode, and
// the set that fails must be exactly the rows recorded for that draft.
//
// Both shapes that could populate it have an answer that is not a row.
//
// One is a parameter written with an outer length its own definition does not
// give it. Draft-17 Section 9.3 defines a Location as "Two consecutive varints
// (Group, Object)", so it carries no outer length, and a vector that wraps one
// in a length is simply wrong bytes; the answer is to correct them. Drafts 18,
// 19 and 20 spell `request-ok.json [with-largest-object]` byte for byte as
// draft-17 does, and draft-17 is the control that makes the shorter framing
// readable as correct rather than as a disagreement about the draft.
//
// The other is where the bytes are right and the message is wrong: a parameter
// in a message type its own definition does not name, which draft-17 Section
// 9.3.1 and drafts 18 through 20 Section 10.2.1 require the receiver to close
// the connection over. Those are recorded as negative vectors asserting
// `parameter_out_of_scope` rather than as rows here, which is the difference
// between a rule being tested and a rule being tolerated.
//
// A corrected vector is read, not skipped, and that is measured rather than
// assumed. Splicing the length back into draft-18 `request-ok.json
// [with-largest-object]` — `07000401090a03` becoming `0700050109020a03`, which
// is what it shipped as — fails in both places at once. Here:
//
// ```text
// assertion `left == right` failed: draft18: the set of message vectors this
// codec refuses is not the set KNOWN_WRONG_MESSAGE_VECTORS records. ...
//   left: [("fetch-ok.json", "with-params-and-properties"), ("request-ok.json", "with-largest-object")]
//  right: [("fetch-ok.json", "with-params-and-properties")]
// ```
//
// and in the runner that would otherwise have skipped it:
//
// ```text
// thread 'd18_request_ok' panicked at crates\moqtap-codec\tests\vectors_draft18.rs:
// [with-largest-object] decode failed: control message declares 5 bytes of payload; its fields ran past the end
// ```

/// The `messages` directory for one draft.
fn messages_dir(draft: &str) -> std::path::PathBuf {
    vectors_dir().join("transport").join(draft).join("codec").join("messages")
}

/// Every `.json` file in a draft's `messages` directory, by name.
///
/// Read from the directory rather than from a list, so a file added upstream is
/// swept rather than silently ignored.
#[allow(dead_code)]
fn message_files(draft: &str) -> Vec<String> {
    let dir = messages_dir(draft);
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("cannot read {}: {e} — did you init the submodule?", dir.display())
    });
    let mut names: Vec<String> = entries
        .map(|entry| entry.expect("directory entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    assert!(
        !names.is_empty(),
        "{}: no vector files — an empty sweep proves nothing",
        dir.display()
    );
    names
}

/// The `(file, vector id)` rows [`KNOWN_WRONG_MESSAGE_VECTORS`] claims for one
/// draft.
#[allow(dead_code)]
fn expected_messages(draft: &str) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = KNOWN_WRONG_MESSAGE_VECTORS
        .iter()
        .filter(|(dir, ..)| *dir == draft)
        .map(|(_, file, id)| (file.to_string(), id.to_string()))
        .collect();
    rows.sort();
    rows
}

/// Generates one draft's message-vector sweep.
///
/// Only vectors that claim a successful decode are tried: a vector carrying an
/// `error` is *meant* to fail, and counting it would make the record a list of
/// the corpus's negative tests instead of a list of its mistakes.
macro_rules! message_sweep {
    ($name:ident, $feat:literal, $module:ident, $dir:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$module::message::ControlMessage;

            let mut refused: Vec<(String, String)> = Vec::new();
            let mut decoded_ok = 0usize;

            for file in message_files($dir) {
                let parsed = load_vectors(&messages_dir($dir).join(&file));
                assert!(
                    !parsed.vectors.is_empty(),
                    "{}/{file}: no vectors — an empty file cannot be distinguished from a clean one",
                    $dir
                );
                for vector in &parsed.vectors {
                    if vector.decoded.is_none() {
                        continue;
                    }
                    let bytes = hex::decode(&vector.hex)
                        .unwrap_or_else(|e| panic!("{}/{file} [{}]: bad hex: {e}", $dir, vector.id));
                    match ControlMessage::decode(&mut &bytes[..]) {
                        Ok(_) => decoded_ok += 1,
                        Err(_) => refused.push((file.clone(), vector.id.clone())),
                    }
                }
            }

            // A sweep that decoded nothing would report an empty refusal set
            // and read exactly like a clean corpus.
            assert!(
                decoded_ok > 0,
                "{}: swept the whole messages directory and decoded nothing — that is the walk \
                 having lost the corpus, not the corpus being empty",
                $dir
            );

            refused.sort();
            assert_eq!(
                refused,
                expected_messages($dir),
                "{}: the set of message vectors this codec refuses is not the set \
                 KNOWN_WRONG_MESSAGE_VECTORS records. A row on the left and not the right is a \
                 vector newly refused with no record of why; a row on the right and not the left \
                 is a vector corrected upstream, so delete its row and the runner's skip.",
                $dir
            );
        }
    };
}

message_sweep!(draft17_message_vectors_decode, "draft17", draft17, "draft17");
message_sweep!(draft18_message_vectors_decode, "draft18", draft18, "draft18");
message_sweep!(draft19_message_vectors_decode, "draft19", draft19, "draft19");
message_sweep!(draft20_message_vectors_decode, "draft20", draft20, "draft20");
message_sweep!(draft21_message_vectors_decode, "draft21", draft21, "draft21");

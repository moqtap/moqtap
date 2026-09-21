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
//! Every control message name this crate answers with, on every draft it
//! implements, is checked against the shared vector corpus.
//!
//! The names are not written here. They are read out of
//! `test-vectors/transport/draftNN/codec/messages/*.json`, whose every file
//! carries the pair this is about: `message_type_id`, the number on the wire,
//! and `message_type`, the `snake_case` name for it on that draft. The same
//! corpus is what the JavaScript codec's `MESSAGE_TYPE_MAP` is written from, so
//! holding this crate to it is what keeps the two implementations naming a
//! recorded trace the same way. Neither table is checked against the other
//! directly — they are each checked against the corpus, which is the only
//! arrangement in which a drift between them cannot be split fifty-fifty and
//! argued about.
//!
//! # Both directions, per draft
//!
//! A name table drifts two ways. An id the corpus assigns and this crate cannot
//! name reads as `UNKNOWN` in a dump, which is visible. An id this crate names
//! and the corpus does not assign is the dangerous one: it puts a confident,
//! wrong label on a message, and it survives any check that walks the corpus and
//! looks each id up. So the two id sets are compared as sets and the two
//! failures are reported separately.
//!
//! The comparison is per draft rather than over the union, because the ids are
//! reused. 0x07 is `announce_ok` through draft-13, `publish_namespace_ok` on
//! draft-14 and `request_ok` from draft-15 on; 0x08, 0x0E and 0x11 move the same
//! way. A table checked against the union of all fourteen corpora would accept
//! every one of those spellings on every draft, which is the draft-blind lookup
//! this replaced.
//!
//! # What an empty answer would mean
//!
//! Every assertion below is of the form *these two sets are equal*, and two
//! empty sets are equal. A walk that lost the corpus therefore reports a clean
//! sweep, so the shapes that produce one are refused rather than returned: a
//! draft directory with no message files, and a draft whose files named no ids
//! at all.
//!
//! # Ablation, each of these run
//!
//! Pointing the draft-18 arm of `message_type_name` at `draft17::message`, which
//! is the mistake per-draft dispatch exists to make impossible and which no
//! amount of checking against the union would see:
//!
//! ```text
//! thread 'draft18_names_agree_with_the_corpus' panicked at
//! crates\moqtap-codec\tests\message_type_names.rs:
//! draft18: assigned by the corpus, not named by this crate: 0x50
//! subscribe_namespace, 0x51 subscribe_tracks
//! ```
//!
//! Spelling draft-19's `PublishSkipped` arm `"publish_blocked"`, which is what
//! draft-18 calls the same wire value:
//!
//! ```text
//! thread 'draft19_names_agree_with_the_corpus' panicked at
//! crates\moqtap-codec\tests\message_type_names.rs:
//! draft19: 0xf is publish_skipped in the corpus, publish_blocked in this crate
//! ```
//!
//! And dropping the draft-18 row from [`ALIASES`], which is what a second name
//! on one id looks like before someone has said why it is there:
//!
//! ```text
//! thread 'draft18_names_agree_with_the_corpus' panicked at
//! crates\moqtap-codec\tests\message_type_names.rs:
//! draft18/publish-ok.json: 0x7 is also filed as publish_ok, and this crate
//! answers request_ok. Either the corpus assigns one id to two messages, or
//! publish_ok is an alias that needs a row in ALIASES saying so.
//! ```

mod test_vectors;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use moqtap_codec::message_type_name;
use test_vectors::{load_vectors, vectors_dir};

/// Every draft this crate implements, with the corpus directory that holds its
/// vectors.
const DRAFTS: [(u8, &str); 15] = [
    (7, "draft07"),
    (8, "draft08"),
    (9, "draft09"),
    (10, "draft10"),
    (11, "draft11"),
    (12, "draft12"),
    (13, "draft13"),
    (14, "draft14"),
    (15, "draft15"),
    (16, "draft16"),
    (17, "draft17"),
    (18, "draft18"),
    (19, "draft19"),
    (20, "draft20"),
    (21, "draft21"),
];

/// Highest id swept when reading a draft's names back out of this crate.
///
/// It has to clear the highest id any draft assigns — draft-17's unified SETUP
/// at 0x2F00 — by enough that a variant numbered just past the end is seen
/// rather than swept past. Nothing declares the assigned set as a list, so this
/// sweep is the only way to ask this crate what it names, and an id above the
/// ceiling would be a name the comparison never reaches.
const CEILING: u64 = 0xFFFF;

/// The corpus's name for a type code no draft assigns.
///
/// Each draft's `unknown-type.json` is a negative vector wearing the same header
/// as the positive ones: it puts 0x3F on the wire and expects a decoder to
/// refuse it. It names no message, so it is excluded from the corpus's table and
/// then held to what it claims — this crate must answer `None` for that id on
/// that draft.
const UNASSIGNED: &str = "unknown";

/// A second corpus file for an id that already has a name: `(draft directory,
/// the alias, the name this crate answers with)`.
///
/// Draft-18 collapsed PUBLISH_OK into REQUEST_OK, and the corpus kept a
/// `publish-ok.json` on drafts 18, 19 and 20 whose vectors are REQUEST_OK bytes
/// at 0x07 — `PUBLISH_OK (REQUEST_OK alias, Type 0x07)`, as the file's own
/// description puts it. There is one message type at 0x07 on those drafts and it
/// is `request_ok`, which is also the only name the JavaScript codec's
/// `MESSAGE_TYPE_MAP` files there. The alias is a second file name for one
/// assignment, not a second assignment.
///
/// A row here is the only way two names on one id pass. Anything else is the
/// corpus assigning an id twice, which is a finding rather than a fact — and a
/// row that stops being used fails as loudly as one that is missing, so the list
/// cannot outlive what it excuses.
const ALIASES: &[(&str, &str, &str)] = &[
    ("draft18", "publish_ok", "request_ok"),
    ("draft19", "publish_ok", "request_ok"),
    ("draft20", "publish_ok", "request_ok"),
    ("draft21", "publish_ok", "request_ok"),
];

/// The `codec/messages` directory for one draft.
fn messages_dir(draft: &str) -> PathBuf {
    vectors_dir().join("transport").join(draft).join("codec").join("messages")
}

/// Every vector file in a draft's `codec/messages` directory, by name.
///
/// Read from the directory rather than from a list, so a message added upstream
/// is compared rather than silently ignored — which is the whole point of
/// checking against a corpus instead of against a second copy of the table.
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

/// The wire id a vector file declares, as the corpus writes it: `0x` and hex.
fn declared_id(draft: &str, file: &str, raw: Option<&str>) -> u64 {
    let text = raw.unwrap_or_else(|| panic!("{draft}/{file}: no message_type_id"));
    let digits = text
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("{draft}/{file}: message_type_id {text:?} is not 0x-prefixed"));
    u64::from_str_radix(digits, 16)
        .unwrap_or_else(|e| panic!("{draft}/{file}: message_type_id {text:?} is not hex: {e}"))
}

/// What one draft's corpus names each control message id, and which file said
/// so.
///
/// Keyed by id, which is the direction a trace reader looks it up in, and
/// carrying every name filed under that id — one name for all but the two rows
/// [`ALIASES`] records.
fn corpus_names(draft: &str) -> BTreeMap<u64, BTreeMap<String, String>> {
    let mut named: BTreeMap<u64, BTreeMap<String, String>> = BTreeMap::new();
    let mut unassigned = 0usize;

    for file in message_files(draft) {
        let parsed = load_vectors(&messages_dir(draft).join(&file));
        let id = declared_id(draft, &file, parsed.message_type_id.as_deref());

        if parsed.message_type == UNASSIGNED {
            unassigned += 1;
            assert_eq!(
                message_type_name(draft_number(draft), id),
                None,
                "{draft}/{file} says {id:#x} is a type code the draft does not assign, and this \
                 crate names it"
            );
            continue;
        }

        let previous =
            named.entry(id).or_default().insert(parsed.message_type.clone(), file.clone());
        assert!(
            previous.is_none(),
            "{draft}: {} is declared at {id:#x} by two files, {file} and {}",
            parsed.message_type,
            previous.unwrap_or_default()
        );
    }

    assert_eq!(
        unassigned, 1,
        "{draft}: expected exactly one file declaring the unassigned type code, found \
         {unassigned} — every draft's corpus carries one, so this is the walk having lost it"
    );
    assert!(!named.is_empty(), "{draft}: the message corpus named no ids at all");
    named
}

/// The draft number for a corpus directory name.
fn draft_number(draft: &str) -> u8 {
    DRAFTS
        .iter()
        .find(|(_, dir)| *dir == draft)
        .unwrap_or_else(|| panic!("{draft} is not a draft this crate implements"))
        .0
}

/// Every id this crate names on one draft, read back by sweeping the lookup.
fn codec_names(draft: u8) -> BTreeMap<u64, &'static str> {
    (0..=CEILING).filter_map(|id| message_type_name(draft, id).map(|name| (id, name))).collect()
}

/// Require this crate's names for one draft and the corpus's to be the same set
/// of ids with the same name on each.
fn names_agree_with_the_corpus(draft: u8, dir: &str) {
    let corpus = corpus_names(dir);
    let codec = codec_names(draft);

    let corpus_ids: BTreeSet<u64> = corpus.keys().copied().collect();
    let codec_ids: BTreeSet<u64> = codec.keys().copied().collect();

    let missing: Vec<String> = corpus_ids
        .difference(&codec_ids)
        .map(|id| format!("{id:#x} {}", corpus[id].keys().cloned().collect::<Vec<_>>().join("/")))
        .collect();
    assert!(
        missing.is_empty(),
        "{dir}: assigned by the corpus, not named by this crate: {}",
        missing.join(", ")
    );

    let extra: Vec<String> =
        codec_ids.difference(&corpus_ids).map(|id| format!("{id:#x} {}", codec[id])).collect();
    assert!(
        extra.is_empty(),
        "{dir}: named by this crate, not assigned by the corpus: {}",
        extra.join(", ")
    );

    let mut aliases_used: BTreeSet<&str> = BTreeSet::new();
    for (id, spellings) in &corpus {
        let ours = codec[id];
        assert!(
            spellings.contains_key(ours),
            "{dir}: {id:#x} is {} in the corpus, {ours} in this crate",
            spellings.keys().cloned().collect::<Vec<_>>().join("/")
        );

        // Any other spelling the corpus files under this id has to be a
        // recorded alias for the one this crate answers with. Two unexplained
        // names on one id is the corpus assigning it twice.
        for (name, file) in spellings {
            if name == ours {
                continue;
            }
            let recorded = ALIASES
                .iter()
                .any(|(d, alias, canonical)| *d == dir && alias == name && canonical == &ours);
            assert!(
                recorded,
                "{dir}/{file}: {id:#x} is also filed as {name}, and this crate answers {ours}. \
                 Either the corpus assigns one id to two messages, or {name} is an alias that \
                 needs a row in ALIASES saying so."
            );
            aliases_used.insert(name.as_str());
        }
    }

    let stale: Vec<&str> = ALIASES
        .iter()
        .filter(|(d, alias, _)| *d == dir && !aliases_used.contains(alias))
        .map(|(_, alias, _)| *alias)
        .collect();
    assert!(
        stale.is_empty(),
        "{dir}: ALIASES records {} as a second name the corpus files, and the corpus no longer \
         does. The row excuses nothing and must go.",
        stale.join(", ")
    );
}

/// Generates one draft's comparison against its own corpus.
macro_rules! corpus_names_agree {
    ($name:ident, $feat:literal, $draft:literal, $dir:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            names_agree_with_the_corpus($draft, $dir);
        }
    };
}

corpus_names_agree!(draft07_names_agree_with_the_corpus, "draft07", 7, "draft07");
corpus_names_agree!(draft08_names_agree_with_the_corpus, "draft08", 8, "draft08");
corpus_names_agree!(draft09_names_agree_with_the_corpus, "draft09", 9, "draft09");
corpus_names_agree!(draft10_names_agree_with_the_corpus, "draft10", 10, "draft10");
corpus_names_agree!(draft11_names_agree_with_the_corpus, "draft11", 11, "draft11");
corpus_names_agree!(draft12_names_agree_with_the_corpus, "draft12", 12, "draft12");
corpus_names_agree!(draft13_names_agree_with_the_corpus, "draft13", 13, "draft13");
corpus_names_agree!(draft14_names_agree_with_the_corpus, "draft14", 14, "draft14");
corpus_names_agree!(draft15_names_agree_with_the_corpus, "draft15", 15, "draft15");
corpus_names_agree!(draft16_names_agree_with_the_corpus, "draft16", 16, "draft16");
corpus_names_agree!(draft17_names_agree_with_the_corpus, "draft17", 17, "draft17");
corpus_names_agree!(draft18_names_agree_with_the_corpus, "draft18", 18, "draft18");
corpus_names_agree!(draft19_names_agree_with_the_corpus, "draft19", 19, "draft19");
corpus_names_agree!(draft20_names_agree_with_the_corpus, "draft20", 20, "draft20");
corpus_names_agree!(draft21_names_agree_with_the_corpus, "draft21", 21, "draft21");

/// The draft pairs whose whole name table coincides.
///
/// A per-draft comparison catches an arm wired to the wrong draft only where the
/// two drafts disagree about something, so which drafts agree completely is the
/// measure of what the tests above cannot see. Drafts 08, 09 and 10 assign
/// exactly the same ids to exactly the same names, so those three arms are
/// interchangeable as far as any corpus check can tell.
///
/// Drafts 20 and 21 are the second such group, and they are here for a
/// different reason: draft-21 is draft-20 restructured, so the tables coincide
/// because the drafts do. That pair is the claim, not a coincidence to be
/// explained away — if it ever left this list, one of the two modules would
/// have acquired a code point the other has not.
///
/// Written down rather than derived, so a draft joining or leaving the run is a
/// change to this list.
///
/// Gated with the test that reads it: a build enabling some of the drafts can
/// say nothing about which of them coincide.
#[cfg(all(
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
    feature = "draft20"
))]
const IDENTICAL_TABLES: [(u8, u8); 4] = [(8, 9), (8, 10), (9, 10), (20, 21)];

#[cfg(all(
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
    feature = "draft20"
))]
#[test]
fn the_drafts_are_distinguishable_from_each_other() {
    let tables: Vec<(u8, BTreeMap<u64, &'static str>)> =
        DRAFTS.iter().map(|(draft, _)| (*draft, codec_names(*draft))).collect();

    let mut coinciding: Vec<(u8, u8)> = Vec::new();
    for (i, (a, table_a)) in tables.iter().enumerate() {
        for (b, table_b) in &tables[i + 1..] {
            if table_a == table_b {
                coinciding.push((*a, *b));
            }
        }
    }

    assert_eq!(
        coinciding,
        IDENTICAL_TABLES.to_vec(),
        "which drafts name every id the same way has changed. A pair that has joined this list \
         is a pair the per-draft tests can no longer tell apart; a pair that has left it is a \
         draft whose table moved."
    );
}

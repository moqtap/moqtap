//! One datagram's identity, read the same way on all the drafts.
//!
//! `AnyDatagramHeader::meta` is the draft-neutral answer to "what does this
//! datagram say it is". The per-draft shapes behind it disagree about more
//! than field order: drafts 07 through 13 carry a payload datagram and a
//! status datagram as two different structs behind one enum, draft-14 merges
//! them behind an optional field, and drafts 15 through 20 hang both the
//! status and the priority off bits in a type byte. A caller that wants a
//! track alias off a datagram had otherwise to know which of those it was
//! holding.
//!
//! # Why these run on the corpus
//!
//! The claim is that **one** call answers on every draft's shape, and a fixture
//! built here once per draft is one chance per draft to build it in the shape the
//! code already has. The corpus's datagrams are bytes nothing in this crate
//! produced, and each states its own decoded fields, so the comparison is
//! against something written independently of this function.
//!
//! # How the corpus says a datagram states a status
//!
//! Not from a single key, because the drafts do not frame it a single way.
//! Drafts 07 and 08 declare a payload length and put the status field on the
//! wire exactly when that length is zero, so a vector of theirs carries both
//! `payload_length` and `object_status` and the length is what decides.
//! Drafts 09 through 20 split the two, and there the corpus writes
//! `payload_hex` on a datagram that carries a payload and leaves the key out
//! of one that states a status. Both rules are read below and neither is
//! per-draft: a vector states a status when it names an `object_status` and
//! either declares no payload bytes or declares a payload length of zero.

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
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

mod test_vectors;

use moqtap_codec::dispatch::{AnyDatagramHeader, AnyDatagramMeta};
use moqtap_codec::version::DraftVersion;
use test_vectors::{load_vectors, vectors_dir};

/// Every draft this build compiled, oldest first. Each element carries its
/// own `#[cfg]`, so the array is the enabled set.
const COMPILED_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
    #[cfg(feature = "draft22")]
    DraftVersion::Draft22,
    #[cfg(feature = "draft23")]
    DraftVersion::Draft23,
];

/// The drafts whose datagram may leave the Publisher Priority off the wire.
///
/// Drafts 15 and later put a default-priority bit in the datagram's type byte;
/// an Object that sets it takes the priority the control message that
/// established the subscription specified, which is not on the datagram.
/// Drafts 07 through 14 always carry the field. By draft **number**, so it
/// answers for drafts this build did not compile.
fn priority_may_be_omitted(draft: DraftVersion) -> bool {
    draft.number() >= 15
}

/// A case a cohort gate below needs and one draft's vectors do not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingCase {
    /// No positive vector states an Object Status.
    StatusDatagram,
    /// No positive vector leaves the Publisher Priority off the wire, on a
    /// draft whose type byte lets one.
    DefaultPriorityDatagram,
}

/// Every such case, named. **The table is empty**, and
/// [`the_named_corpus_gaps_are_exactly_the_real_ones`] is what makes that a
/// claim rather than an absence: every compiled draft carries both cases.
///
/// The two cohort gates below count across `COMPILED_DRAFTS` and assert the
/// total is not zero. In the all-drafts build that is a coverage guard and a
/// good one — a corpus that quietly stopped carrying the interesting case
/// would turn the body above it into a vacuous pass. Under
/// `--no-default-features --features draftNN` the total is **one draft's
/// slice**, so a slice without the case fires the guard as though the codec
/// were wrong. CI runs exactly that command in every cell, which is
/// where a thin slice shows up as a red cell rather than as a question nobody
/// asked.
///
/// Conditioning the skip on the count instead of on this table would withdraw
/// the fence in the configuration where a thin corpus is likeliest, and say
/// nothing about which draft or which case. Naming them costs the table and
/// buys two things: the gate below says *why* it is not asking, and
/// [`the_named_corpus_gaps_are_exactly_the_real_ones`] fails the day a vector
/// arrives or a draft loses one.
///
/// # What an entry here has to clear
///
/// **A gap is closed with bytes this crate's own encoder did not produce.**
/// These gates compare against bytes the crate did not write, so a vector
/// generated from the decoder under test would leave every gate green while
/// making the premise false.
///
/// **A gap is the corpus's and not the loader's.** Drafts 09 and 10 hold no
/// datagram that states an Object Status in `datagram.json`: neither draft's
/// payload datagram carries a status field, so every status datagram of theirs
/// is the 0x02 form and all of them sit in `datagram-status.json`. A loader
/// that reads only `datagram.json` sees two gaps the corpus does not have. So:
/// **before a gap is recorded here, check that the reader reaches everywhere
/// the corpus keeps the case**, because an entry that blames the corpus for
/// the reader's reach is a gate switched off and a request for work nobody
/// needs to do.
///
/// **A real gap is a decode path no vector reaches.** Draft-15 is where the
/// default-priority bit arrives, and its default-priority decode path is
/// reached by exactly one vector: without a `datagram-default-priority`
/// derived from the draft rather than from this crate, the per-draft half of
/// [`the_priority_is_absent_only_where_a_draft_lets_a_datagram_omit_it`] is
/// never made for draft-15 at all. The bytes come from draft-15 Section 10.3.1:
/// Table 5 gives type `0x08` as no end of group, no extensions, Object ID
/// present, Priority Present "No", payload; Figure 26 orders the fields Type,
/// Track Alias, Group ID, Object ID, Publisher Priority, Extensions, Object
/// Status, Object Payload. Between them the vector is this file's own
/// `datagram-4byte-payload` with the type byte changed and the one byte that
/// column names removed, and nothing else moved.
const CORPUS_GAPS: &[(DraftVersion, MissingCase)] = &[];

/// Whether [`CORPUS_GAPS`] names this draft for this case.
fn corpus_lacks(draft: DraftVersion, what: MissingCase) -> bool {
    CORPUS_GAPS.contains(&(draft, what))
}

/// The corpus directory one draft's vectors live in.
fn corpus_dir(draft: DraftVersion) -> &'static str {
    match draft {
        DraftVersion::Draft07 => "draft07",
        DraftVersion::Draft08 => "draft08",
        DraftVersion::Draft09 => "draft09",
        DraftVersion::Draft10 => "draft10",
        DraftVersion::Draft11 => "draft11",
        DraftVersion::Draft12 => "draft12",
        DraftVersion::Draft13 => "draft13",
        DraftVersion::Draft14 => "draft14",
        DraftVersion::Draft15 => "draft15",
        DraftVersion::Draft16 => "draft16",
        DraftVersion::Draft17 => "draft17",
        DraftVersion::Draft18 => "draft18",
        DraftVersion::Draft19 => "draft19",
        DraftVersion::Draft20 => "draft20",
        DraftVersion::Draft21 => "draft21",
        DraftVersion::Draft22 => "draft22",
        DraftVersion::Draft23 => "draft23",
    }
}

/// One datagram from the corpus: what the file says it holds, and what this
/// crate made of its bytes.
struct Case {
    id: String,
    meta: AnyDatagramMeta,
    /// The fields the vector itself declares, as it declares them.
    track_alias: u64,
    group_id: u64,
    object_id: u64,
    priority: Option<u8>,
    /// The status this vector says the datagram *states*, resolved by the two
    /// framing rules described in the file header. `None` means it carries a
    /// payload instead.
    stated_status: Option<u64>,
}

/// Read a decoded field the corpus writes as a decimal string.
fn field(decoded: &serde_json::Value, key: &str) -> Option<u64> {
    decoded.get(key)?.as_str()?.parse().ok()
}

/// The two files a draft's positive datagram vectors can live in.
///
/// `datagram.json` holds the payload form on every draft. The status form is a
/// separate message type on drafts 07 through 13, and drafts 08, 09 and 10
/// give it a file of its own. Drafts 09 and 10 dropped the status field from
/// the payload datagram, so the 0x02 form is the only way either can state a
/// status and every vector that does sits in `datagram-status.json`. Draft-08
/// keeps the field on both forms.
const DATAGRAM_FILES: [&str; 2] = ["datagram.json", "datagram-status.json"];

/// Every positive datagram vector the corpus has for `draft`, decoded.
///
/// Negative vectors are left out: a datagram that does not decode has no
/// identity to report, and what it proves belongs to the per-draft runners.
///
/// Both files in [`DATAGRAM_FILES`] are read, because a draft that splits its
/// datagrams across two files has not thereby said less about them.
fn cases(draft: DraftVersion) -> Vec<Case> {
    let dir =
        vectors_dir().join("transport").join(corpus_dir(draft)).join("codec").join("data-streams");

    let mut out = Vec::new();
    for name in DATAGRAM_FILES {
        let path = dir.join(name);
        // The second file is not every draft's, and a draft that does not have
        // one is not thereby short of vectors. Missing is the ordinary case.
        if !path.exists() {
            continue;
        }
        let file = load_vectors(&path);
        for vector in &file.vectors {
            if vector.error.is_some() {
                continue;
            }
            let Some(decoded) = vector.decoded.as_ref() else {
                continue;
            };
            let wire = hex::decode(&vector.hex)
                .unwrap_or_else(|e| panic!("[{draft:?} {}] bad hex: {e}", vector.id));

            let mut cursor: &[u8] = &wire;
            let header = AnyDatagramHeader::decode(draft, &mut cursor)
                .unwrap_or_else(|e| panic!("[{draft:?} {}] datagram header: {e}", vector.id));

            let declares_payload_bytes = decoded.get("payload_hex").is_some();
            let declares_zero_length = field(decoded, "payload_length") == Some(0);
            let states_status = field(decoded, "object_status")
                .filter(|_| !declares_payload_bytes || declares_zero_length);

            out.push(Case {
                id: vector.id.clone(),
                meta: header.meta(),
                track_alias: field(decoded, "track_alias")
                    .unwrap_or_else(|| panic!("[{draft:?} {}] no track_alias", vector.id)),
                group_id: field(decoded, "group_id")
                    .unwrap_or_else(|| panic!("[{draft:?} {}] no group_id", vector.id)),
                object_id: field(decoded, "object_id")
                    .unwrap_or_else(|| panic!("[{draft:?} {}] no object_id", vector.id)),
                priority: field(decoded, "publisher_priority").map(|v| v as u8),
                stated_status: states_status,
            });
        }
    }
    out
}

/// Every field the draft-neutral meta reports is the one the corpus says the
/// datagram carries, on every draft this build compiled.
///
/// The Location fields are the load-bearing half. A datagram's Group ID and
/// Object ID are what a relay keys a rule on, and reading either off the wrong
/// arm of a two-struct enum produces a number rather than an error — drafts 08
/// through 13 carry the status form's fields in a different struct at a
/// different offset, and every one of them is a plausible `u64`.
///
/// Fails if the drafts 08-13 macro arm reads `object_id` off `group_id`.
#[test]
fn every_datagram_field_matches_the_corpus() {
    let mut seen = 0usize;
    for &draft in COMPILED_DRAFTS {
        let cases = cases(draft);
        assert!(!cases.is_empty(), "{draft:?}: the corpus has no datagram vectors to read");
        for case in &cases {
            let at = format!("[{draft:?} {}]", case.id);
            assert_eq!(case.meta.track_alias, case.track_alias, "{at} track_alias");
            assert_eq!(case.meta.group_id, case.group_id, "{at} group_id");
            assert_eq!(case.meta.object_id, case.object_id, "{at} object_id");
            assert_eq!(case.meta.publisher_priority, case.priority, "{at} publisher_priority");
            assert_eq!(case.meta.status, case.stated_status, "{at} status");
            seen += 1;
        }
    }
    assert!(seen >= COMPILED_DRAFTS.len(), "only {seen} datagrams were read");
}

/// A datagram reports no priority exactly on the drafts that let it omit one,
/// and the claim is made **per draft**.
///
/// The per-draft shape is the whole of the gate. Counting how many drafts
/// from 15 on show an omission and asserting the count is non-zero passes
/// while any one of the five still reports correctly. A cohort claim asserted
/// as a total is a claim about the cohort's best member.
///
/// Two-sided as well: a draft below 15 must report `Some` for every datagram
/// it has, or an `Option` that is simply always empty would pass the first
/// half.
///
/// Fails if any one draft of the five reports a priority on every datagram.
///
/// A draft with no such vector is named in [`CORPUS_GAPS`] rather than skipped
/// by the count. An `if corpus_omits > 0` guard reads as protection against a
/// thin corpus and is really a hole in this claim: a draft with no such vector
/// never has the per-draft assertion made for it at all, while the cohort
/// count below is satisfied by its neighbours. The table is empty, so the
/// assertion is made for every draft in the cohort.
///
/// [`every_datagram_field_matches_the_corpus`] makes the same check per object
/// rather than per count, so between them a draft's omissions are counted and
/// there is an object they were counted from.
#[test]
fn the_priority_is_absent_only_where_a_draft_lets_a_datagram_omit_it() {
    let mut drafts_with_an_omission = 0usize;
    for &draft in COMPILED_DRAFTS {
        let cases = cases(draft);
        let corpus_omits = cases.iter().filter(|c| c.priority.is_none()).count();
        let meta_omits = cases.iter().filter(|c| c.meta.publisher_priority.is_none()).count();
        if priority_may_be_omitted(draft) {
            if corpus_lacks(draft, MissingCase::DefaultPriorityDatagram) {
                continue;
            }
            drafts_with_an_omission += 1;
            assert!(
                corpus_omits > 0,
                "the corpus has no {draft:?} datagram that omits its priority, and \
                 CORPUS_GAPS does not say so"
            );
            assert_eq!(
                meta_omits, corpus_omits,
                "{draft:?} reported a priority on every datagram it has, though the \
                 corpus carries one that omits the field"
            );
        } else {
            assert_eq!(
                corpus_omits, 0,
                "the corpus has a {draft:?} datagram with no priority, though every datagram \
                 of this draft carries the field"
            );
            assert_eq!(
                meta_omits, 0,
                "{draft:?} reported a datagram with no priority, though every datagram of \
                 this draft carries the field"
            );
        }
    }
    let askable = COMPILED_DRAFTS.iter().any(|&d| {
        priority_may_be_omitted(d) && !corpus_lacks(d, MissingCase::DefaultPriorityDatagram)
    });
    if askable {
        assert!(
            drafts_with_an_omission > 0,
            "no draft from 15 on has a datagram in the corpus that omits its priority"
        );
    }
}

/// A datagram that states a status reports its code; one that carries a
/// payload reports none.
///
/// Asserted as a pair per draft rather than one at a time, because either
/// alone is satisfied by a constant: `status: None` for everything passes the
/// payload half, and `Some(0)` for everything passes nothing but would pass a
/// gate that only ever looked at status datagrams. The cohort count below
/// reads [`CORPUS_GAPS`] to decide whether it can be asked at all, rather than
/// exempting itself by its own count — a skip that said nothing about which
/// draft was thin, and that in an all-drafts build could not be reached to say
/// anything.
///
/// Fails if drafts 07 and 08's payload form takes its status from the enum
/// alone: those drafts put the status field on a payload datagram whose
/// length is zero.
///
/// Drafts 15 and 16 fill the status field exactly when the type byte's status
/// bit is set, so no decoded vector tells the field from the bit. The bit's
/// authority over values built in memory is held by
/// `draft15_data_stream_rules.rs`.
#[test]
fn a_stated_status_and_a_carried_payload_are_told_apart() {
    let mut with_status = 0usize;
    let mut with_payload = 0usize;
    for &draft in COMPILED_DRAFTS {
        for case in cases(draft) {
            let at = format!("[{draft:?} {}]", case.id);
            assert_eq!(case.meta.status, case.stated_status, "{at} status");
            if case.stated_status.is_some() {
                with_status += 1;
            } else {
                with_payload += 1;
            }
        }
    }
    let askable = COMPILED_DRAFTS.iter().any(|&d| !corpus_lacks(d, MissingCase::StatusDatagram));
    if askable {
        assert!(with_status > 0, "no draft in this build has a status datagram in the corpus");
    }
    // Every draft has payload datagrams, so this half needs no exemption and
    // is asserted unconditionally — one of the two counts staying
    // unconditional is what keeps `cases` from being allowed to return
    // nothing at all.
    assert!(with_payload > 0, "no draft in this build has a payload datagram in the corpus");
}

/// [`CORPUS_GAPS`] names exactly the drafts whose vectors really are missing
/// the case, in both directions.
///
/// This is what keeps the table from rotting into a licence. An entry that is
/// no longer true fails here the day the vector lands, and must be deleted
/// rather than left to exempt a draft that no longer needs exempting; a draft
/// that loses its vector fails here rather than quietly falling out of a
/// cohort count.
///
/// Only the compiled drafts are checked, so a reduced build asks about its own
/// slice and says nothing about the rest — an entry for a draft this build
/// left out is neither confirmed nor contradicted here, and the all-drafts
/// build is what settles the whole table.
///
/// The failure reports a count, which says what moved: the table, the loader,
/// or the corpus. This test refuses to let the table name a draft that does
/// not need it, and
/// [`the_priority_is_absent_only_where_a_draft_lets_a_datagram_omit_it`]
/// refuses to skip a draft the table does not name, so a removed vector fails
/// on both sides.
#[test]
fn the_named_corpus_gaps_are_exactly_the_real_ones() {
    for &draft in COMPILED_DRAFTS {
        let cases = cases(draft);

        let has_status = cases.iter().any(|c| c.stated_status.is_some());
        assert_eq!(
            has_status,
            !corpus_lacks(draft, MissingCase::StatusDatagram),
            "CORPUS_GAPS and the corpus disagree about whether {draft:?} has a status \
             datagram: the corpus has {} of them",
            cases.iter().filter(|c| c.stated_status.is_some()).count()
        );

        if !priority_may_be_omitted(draft) {
            assert!(
                !corpus_lacks(draft, MissingCase::DefaultPriorityDatagram),
                "CORPUS_GAPS exempts {draft:?} from a case its type byte cannot express, \
                 so the entry names nothing"
            );
            continue;
        }
        let omits = cases.iter().filter(|c| c.priority.is_none()).count();
        assert_eq!(
            omits > 0,
            !corpus_lacks(draft, MissingCase::DefaultPriorityDatagram),
            "CORPUS_GAPS and the corpus disagree about whether {draft:?} has a datagram \
             omitting its priority: the corpus has {omits} of them"
        );
    }
}

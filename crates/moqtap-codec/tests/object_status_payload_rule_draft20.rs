#![cfg(feature = "draft20")]
//! Draft-20's Object Status registry decides, per status, whether an Object may
//! carry a payload — and this crate's draft-20 encoders answer from that
//! registry rather than from a payload length.
//!
//! Draft-20 Section 11.2.1.1 states the rule as a deferral: an Object has an
//! empty payload unless its Object Status is registered as permitting one. The
//! registry it defers to is Section 15.9, Table 16, whose rows carry a
//! "Payload" column — `Normal` is "Yes", `End of Group` and `End of Track` are
//! "No". Draft-18 had no such column and said instead that any Object whose
//! status is other than zero has an empty payload, which is a statement about
//! the number rather than about the row.
//!
//! # Where the expected values come from
//!
//! Every status checked here, and every answer expected of it, is read out of
//! `tools/registries/draft-NN.json` — the committed extraction of the rendered
//! draft, which records each row's Payload column and, per row, whether the
//! value came from that column or from the older blanket sentence. No status
//! and no permission is written into this file. Add a row to Table 16 and
//! re-extract, and the sweep below picks it up and demands the encoders honour
//! it; change this crate's answer for an existing row and the sweep fails
//! against the draft.
//!
//! # Why the contrast with draft-18 is part of the gate
//!
//! The three rows assigned today make draft-20's registry rule and draft-18's
//! blanket rule agree on every input: the only status that permits a payload is
//! `0x0`, so "registered as permitting" and "equal to zero" pick out the same
//! set. Nothing on the wire distinguishes the two drafts, and a gate that only
//! exercised draft-20 would pass just as happily against an implementation that
//! had never heard of Table 16.
//!
//! What does distinguish them is what each encoder does with an Object that
//! states a forbidden status and holds a payload — a pair the wire cannot
//! express, since the status field appears only where the payload does not.
//! Draft-20 refuses it, because the registry rules on the pair. Draft-18 writes
//! it as an ordinary payload object and the status disappears, because there
//! the payload length alone chooses which of the two fields gets written. Both
//! halves are asserted here, so the gate says the drafts differ rather than
//! merely that draft-20 works.
//!
//! That makes this file the place a change to draft-18 has to argue with. The
//! conversion helpers this crate shares across drafts 07-20 make it easy to
//! give every draft one rule; doing so would move draft-20's registry into
//! drafts that have no registry, and would fail here.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

/// One draft's Object Status registry as extracted from the rendered draft:
/// wire code to "may this status carry a payload".
type PayloadColumn = BTreeMap<u64, bool>;

/// Read the Object Status rows out of `tools/registries/draft-NN.json`.
fn object_status_registry(draft: u64) -> Value {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tools/registries")
        .join(format!("draft-{draft}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
    assert_eq!(doc["draft"].as_u64(), Some(draft), "draft-{draft}.json reports another draft");
    let reg = doc["object_status"].clone();
    assert_eq!(
        reg["present"],
        Value::Bool(true),
        "draft-{draft} extraction reports no Object Status registry"
    );
    reg
}

/// The registry's Payload column, keyed by wire code.
///
/// The extraction spells the column `"yes"`/`"no"`; anything else stops the
/// test rather than being read as a permission.
///
/// Only rows the extraction tagged `kind: "assignment"` are read, the same
/// filter the registry conformance gate applies. The other tag is `"reserved"`,
/// the row a registry ends with to fence off the greasing code space, printed
/// with a code range or an arithmetic expression instead of a code point. Such
/// a row registers no status, so it has nothing to say about payloads and its
/// Payload cell is empty — and an unfiltered read would turn that emptiness
/// into a panic reading `status 0x… has payload None`, which is also what a
/// genuine extraction failure says. Draft-20's Object Status registry has no
/// such row today; the filter is here so that a revision adding one is a
/// registry that grew a row rather than a gate that broke.
fn payload_column(reg: &Value, draft: u64) -> PayloadColumn {
    let rows = reg["rows"].as_array().expect("Object Status registry has no rows array");
    let mut out = BTreeMap::new();
    for row in rows {
        if row["kind"] != "assignment" {
            continue;
        }
        let code =
            row["code_value"].as_u64().unwrap_or_else(|| panic!("row without a code: {row}"));
        let permits = match row["payload"].as_str() {
            Some("yes") => true,
            Some("no") => false,
            other => panic!("draft-{draft} status {code:#x} has payload {other:?}"),
        };
        out.insert(code, permits);
    }
    assert!(!out.is_empty(), "draft-{draft} Object Status registry extracted no assignments");
    out
}

/// Every row's `payload_source`, keyed by wire code.
///
/// The extraction distinguishes a value the draft registered in a Payload
/// column from one it computed by applying an older blanket sentence, and that
/// distinction is the whole difference between draft-18 and draft-20 for these
/// three rows.
fn payload_sources(reg: &Value) -> BTreeMap<u64, String> {
    reg["rows"]
        .as_array()
        .expect("Object Status registry has no rows array")
        .iter()
        .map(|row| {
            let code = row["code_value"].as_u64().expect("row without a code");
            let source =
                row["payload_source"].as_str().expect("row without a payload_source").to_string();
            (code, source)
        })
        .collect()
}

// ── Draft-20 ──────────────────────────────────────────────────

mod d20 {
    pub use moqtap_codec::draft20::data_stream::{
        DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectReader,
    };
    pub use moqtap_codec::draft20::types::ObjectStatus;
}

/// A subgroup header with no properties block and an explicit priority byte,
/// so that each object below is its framing and nothing else.
fn subgroup_header_19() -> d20::SubgroupHeader {
    d20::SubgroupHeader {
        header_type: 0x10,
        track_alias: VarInt::from_u64_moqt(1),
        group_id: VarInt::from_u64_moqt(7),
        subgroup_id: VarInt::from_u64_moqt(0),
        publisher_priority: Some(128),
    }
}

fn object_19(status: d20::ObjectStatus, payload: &[u8]) -> d20::SubgroupObject {
    d20::SubgroupObject {
        object_id: VarInt::from_u64_moqt(0),
        extension_headers: Vec::new(),
        payload_length: VarInt::from_u64_moqt(payload.len() as u64),
        object_status: Some(status),
        payload: payload.to_vec(),
    }
}

/// Encode one object onto a fresh subgroup stream.
fn write_19(object: &d20::SubgroupObject) -> Result<Vec<u8>, (CodecError, Vec<u8>)> {
    let header = subgroup_header_19();
    let mut writer = d20::SubgroupObjectReader::new(&header);
    let mut buf = Vec::new();
    match writer.write_object(object, &mut buf) {
        Ok(()) => Ok(buf),
        Err(e) => Err((e, buf)),
    }
}

/// Decode one object from a fresh subgroup stream, requiring the bytes to be
/// consumed exactly.
fn read_19(bytes: &[u8]) -> d20::SubgroupObject {
    let header = subgroup_header_19();
    let mut reader = d20::SubgroupObjectReader::new(&header);
    let mut cursor = bytes;
    let object = reader
        .read_object(&mut cursor)
        .unwrap_or_else(|e| panic!("read_object refused {bytes:02x?}: {e}"));
    assert!(cursor.is_empty(), "read_object left {} bytes of {bytes:02x?}", cursor.len());
    object
}

/// The registry, not a payload length, decides which draft-20 statuses may
/// carry a payload — and the encoder refuses the ones it forbids.
///
/// Each row of the extracted Table 16 is driven both ways: as a zero-length
/// Object, which every status may be, and as an Object holding three bytes,
/// which only a row marked "Yes" may be. A row marked "No" must be refused with
/// nothing written, and a row marked "Yes" must survive the round trip with its
/// bytes.
///
/// # Ablation
///
/// Reverting `SubgroupObjectReader::write_object` to draft-18's inference —
/// dropping the `declared != 0 && !object.permits_payload()` refusal so the
/// payload length alone decides which field is written — makes an End of Group
/// object holding a payload encode as an ordinary payload object with its
/// status silently gone:
///
/// ```text
/// thread 'the_registry_decides_which_draft20_statuses_may_carry_a_payload'
/// panicked at crates\moqtap-codec\tests\object_status_payload_rule.rs:297:30:
/// draft-20 status 0x3 is registered "Payload: No", so write_object must refuse
/// it a payload; it wrote [00, 03, 61, 62, 63]
/// ```
///
/// Moving a row instead of removing the check — `payload_permission` answering
/// `Permitted` for End of Group, as a status registered later with
/// "Payload: Yes" would — fails against the extracted column rather than
/// agreeing with itself:
///
/// ```text
/// thread 'the_registry_decides_which_draft20_statuses_may_carry_a_payload'
/// panicked at crates\moqtap-codec\tests\object_status_payload_rule.rs:248:9:
/// assertion `left == right` failed: draft-20 Table 16 marks 0x3 "Payload: no",
/// ObjectStatus::permits_payload disagrees
///   left: true
///  right: false
/// ```
#[test]
fn the_registry_decides_which_draft20_statuses_may_carry_a_payload() {
    let reg = object_status_registry(19);
    let column = payload_column(&reg, 19);

    // Draft-20 states this rule per row, in a column of its own. The rest of
    // this test reads that column, so a re-extraction that lost it would leave
    // the sweep asserting draft-18's rule under draft-20's name.
    assert_eq!(
        reg["payload_column"],
        Value::Bool(true),
        "draft-20 Object Status was extracted without a Payload column"
    );
    for (code, source) in payload_sources(&reg) {
        assert_eq!(
            source, "payload-column",
            "draft-20 status {code:#x} takes its payload rule from {source}, not the registry"
        );
    }

    // The status set is the crate's, checked against the draft's, so that a
    // status assigned by one and not the other is caught before any behaviour
    // is exercised — and so that nothing below is a status written into this
    // file.
    let codec_codes: Vec<u64> = d20::ObjectStatus::ALL.iter().map(|s| s.as_u64()).collect();
    let spec_codes: Vec<u64> = column.keys().copied().collect();
    assert_eq!(
        codec_codes, spec_codes,
        "draft-20 assigns {spec_codes:?}, this crate {codec_codes:?}"
    );

    for (&code, &permits) in &column {
        let status = d20::ObjectStatus::from_u64(code)
            .unwrap_or_else(|| panic!("draft-20 assigns {code:#x}, this crate does not decode it"));

        // The crate's own answer for this row.
        assert_eq!(
            status.permits_payload(),
            permits,
            "draft-20 Table 16 marks {code:#x} \"Payload: {}\", \
             ObjectStatus::permits_payload disagrees",
            if permits { "yes" } else { "no" }
        );

        // Every status, permitting or not, may be an Object with no payload,
        // and that Object states its status on the wire.
        let empty = write_19(&object_19(status, b""))
            .unwrap_or_else(|(e, _)| panic!("write_object refused a zero-length {status:?}: {e}"));
        let decoded = read_19(&empty);
        assert_eq!(
            decoded.status(),
            status,
            "a zero-length {status:?} came back as {:?}",
            decoded.status()
        );
        assert!(decoded.payload.is_empty(), "a zero-length {status:?} came back carrying bytes");
        assert_eq!(
            decoded.permits_payload(),
            permits,
            "a decoded {status:?} reports the wrong payload permission"
        );

        // And the registry decides whether it may be an Object that carries
        // one.
        let carrying = write_19(&object_19(status, b"abc"));
        if permits {
            let bytes = carrying.unwrap_or_else(|(e, _)| {
                panic!("draft-20 status {code:#x} is registered \"Payload: Yes\", {e} anyway")
            });
            let decoded = read_19(&bytes);
            assert_eq!(decoded.payload, b"abc", "a payload-carrying {status:?} lost its bytes");
            // A payload-carrying Object states no status: the field is only
            // there when the payload is not. So a status that permits a payload
            // has to be the one the encoding elides, or the round trip cannot
            // name it. A second "Payload: Yes" row would fail here, and the
            // encoding — not this test — is what would need deciding.
            assert_eq!(
                decoded.status(),
                status,
                "a payload-carrying {status:?} came back as {:?}; the encoding cannot \
                 express two statuses that permit a payload",
                decoded.status()
            );
        } else {
            let (err, written) = match carrying {
                Ok(bytes) => panic!(
                    "draft-20 status {code:#x} is registered \"Payload: No\", so write_object \
                     must refuse it a payload; it wrote {bytes:02x?}"
                ),
                Err(pair) => pair,
            };
            assert!(
                matches!(err, CodecError::PayloadNotPermitted { .. }),
                "draft-20 status {code:#x} with a payload was refused as {err}, \
                 not as an object the registry forbids one"
            );
            assert!(
                written.is_empty(),
                "a refused {status:?} left {written:02x?} on the stream for the next read"
            );
        }
    }
}

/// A decoded datagram keeps the framing question and the registry question
/// apart.
///
/// The two are genuinely distinct, and a caller holding the bytes after a
/// header needs both:
///
/// - The framing. Draft-20 Section 11.3.1 puts the Object Status field exactly
///   where the payload would otherwise sit, so a datagram whose type sets the
///   STATUS bit has no payload field at all — whichever code it carries,
///   including the Normal code the registry marks payload-permitting.
///   `permits_payload` answers this one, and it is `false` for every status a
///   STATUS-framed datagram can state.
/// - The registry. Section 15.9, Table 16 says whether an Object at this
///   status was allowed to carry payload bytes anywhere, on any carrier.
///   `status().permits_payload()` answers this one, and it is read here
///   straight from the extracted Payload column.
///
/// The Normal row is where the two visibly part company: the registry permits
/// it a payload, and this framing gives it nowhere to put one.
///
/// # What this catches
///
/// Dropping the `has_status()` arm from `DatagramHeader::permits_payload`, so
/// that it answers `self.status().permits_payload()` alone, collapses the
/// framing question into a second copy of the registry one. The loop below
/// asserts a STATUS-framed datagram permits no payload, and a registry-only
/// answer reports that one carrying the code 0x0 does.
///
/// The Normal row is also the only row that can catch it. End of Group and End
/// of Track are refused a payload by both rules at once, so either rule read
/// alone gives the same answer for them, and a sweep restricted to those two
/// could not tell the two questions apart at all. The disagreement assertion
/// after the loop is what keeps a row that separates them in the sweep, so a
/// registry that one day marked every status "Payload: No" would fail here
/// rather than quietly making the test vacuous.
#[test]
fn a_draft20_datagram_keeps_the_framing_and_the_registry_apart() {
    let column = payload_column(&object_status_registry(19), 19);
    let mut framing_and_registry_disagreed = false;

    for (&code, &permits) in &column {
        let status = d20::ObjectStatus::from_u64(code).expect("draft-20 decodes its own status");

        // Type 0x28: STATUS bit (0x20) set, DEFAULT_PRIORITY (0x08) set, so the
        // datagram is a header and a status byte with nothing after it.
        let header = d20::DatagramHeader {
            datagram_type: 0x28,
            track_alias: VarInt::from_u64_moqt(1),
            group_id: VarInt::from_u64_moqt(7),
            object_id: VarInt::from_u64_moqt(3),
            publisher_priority: None,
            properties: Vec::new(),
            object_status: Some(status),
        };
        let mut bytes = Vec::new();
        header.encode(&mut bytes);
        let decoded = d20::DatagramHeader::decode(&mut &bytes[..])
            .unwrap_or_else(|e| panic!("a datagram carrying {status:?} did not decode: {e}"));

        assert_eq!(decoded.status(), status, "a datagram carrying {status:?} came back otherwise");
        assert!(
            decoded.has_status(),
            "type 0x28 sets the STATUS bit, so a datagram carrying {status:?} must report a \
             status field; this fixture no longer exercises the framing it claims to"
        );
        assert!(
            !decoded.permits_payload(),
            "a datagram framed as carrying {status:?} reports that a payload is permitted, \
             but its status field sits where the payload would be"
        );
        assert_eq!(
            decoded.status().permits_payload(),
            permits,
            "the registry answer for {status:?} was read off the framing instead of off \
             Table 16's Payload column"
        );

        framing_and_registry_disagreed |= decoded.permits_payload() != permits;
    }

    assert!(
        framing_and_registry_disagreed,
        "no registered status told the framing rule from the registry rule, so this sweep \
         would pass on a codec that had only one of them"
    );

    // The same type byte without the STATUS bit carries a payload and no status
    // field. Its status is the one the encoding elides, and the registry has to
    // permit that status a payload or the datagram could not exist.
    let header = d20::DatagramHeader {
        datagram_type: 0x08,
        track_alias: VarInt::from_u64_moqt(1),
        group_id: VarInt::from_u64_moqt(7),
        object_id: VarInt::from_u64_moqt(3),
        publisher_priority: None,
        properties: Vec::new(),
        object_status: None,
    };
    let mut bytes = Vec::new();
    header.encode(&mut bytes);
    let decoded =
        d20::DatagramHeader::decode(&mut &bytes[..]).expect("a payload datagram did not decode");
    assert!(!decoded.has_status(), "a datagram without the STATUS bit reported a status field");
    assert!(
        decoded.permits_payload(),
        "a payload-carrying datagram reports a status that forbids the payload it carries"
    );
    assert!(
        column[&decoded.status().as_u64()],
        "the status a payload datagram elides is not registered as permitting a payload"
    );
}

// ── The neighbouring draft ────────────────────────────────────

#[cfg(feature = "draft18")]
mod d18 {
    pub use moqtap_codec::draft18::data_stream::{
        SubgroupHeader, SubgroupObject, SubgroupObjectReader,
    };
    pub use moqtap_codec::draft18::types::ObjectStatus;
}

/// Draft-18 takes the same three statuses from a blanket sentence about
/// non-zero codes, and its encoder lets the payload length decide; draft-20
/// takes them from a registry column, and its encoder refuses what the column
/// forbids.
///
/// Both drafts are driven from their own extraction. The extractions agree on
/// every code point's answer — the three rows assigned today make "registered
/// as permitting" and "equal to zero" the same set — and disagree on where the
/// answer came from, which is the fact this checks and then demonstrates as a
/// difference in behaviour: draft-20 refuses the Object that states a forbidden
/// status and holds a payload, draft-18 writes it and drops the status.
///
/// A failure here is not necessarily a bug in draft-18. Draft-18's own blanket
/// sentence forbids that Object too, so hardening its encoder is a defensible
/// change — but it is a change made against draft-18's rule, not by extending
/// draft-20's registry backwards over a draft that has none, and it has to be
/// argued here rather than arrived at by sharing one conversion across every
/// draft.
///
/// # Ablation
///
/// Giving draft-18's `write_object` draft-20's refusal — the shared-helper
/// mistake this exists to catch — erases the difference:
///
/// ```text
/// thread 'draft18_reads_the_same_rule_off_the_payload_length_and_draft20_off_the_registry'
/// panicked at crates\moqtap-codec\tests\object_status_payload_rule.rs:501:17:
/// draft-18 has no per-status Payload column, so its encoder cannot be refusing
/// status 0x3 a payload on the registry's authority: invalid field value
/// ```
#[cfg(feature = "draft18")]
#[test]
fn draft18_reads_the_same_rule_off_the_payload_length_and_draft20_off_the_registry() {
    let reg18 = object_status_registry(18);
    let column18 = payload_column(&reg18, 18);
    let column19 = payload_column(&object_status_registry(19), 19);

    // Same answers, different authority. The first is why no wire bytes differ
    // between the two drafts today; the second is why they are not the same
    // rule.
    assert_eq!(
        column18, column19,
        "the two drafts' Payload columns disagree, so the rest of this test is comparing \
         two different sets of statuses rather than two ways of ruling on one set"
    );
    assert_eq!(
        reg18["payload_column"],
        Value::Bool(false),
        "draft-18 Object Status was extracted with a Payload column of its own"
    );
    assert_eq!(
        reg18["payload_rule_kind"], "nonzero-must-be-empty",
        "draft-18's payload rule is not the blanket one this contrast rests on"
    );
    for (code, source) in payload_sources(&reg18) {
        assert!(
            source.starts_with("blanket-rule"),
            "draft-18 status {code:#x} takes its payload rule from {source}, \
             which is a registered answer rather than the blanket sentence"
        );
    }

    for (&code, &permits) in &column18 {
        if permits {
            continue;
        }
        let status18 = d18::ObjectStatus::from_u64(code).expect("draft-18 decodes its own status");
        let status19 = d20::ObjectStatus::from_u64(code).expect("draft-20 decodes the same status");

        // Draft-20: the registry rules on the pair, and refuses it.
        let refused = write_19(&object_19(status19, b"abc"));
        assert!(
            refused.is_err(),
            "draft-20 accepted a payload under {status19:?}, which its registry forbids one"
        );

        // Draft-18: no registry to consult, so the length picks the framing and
        // the status is written out of existence.
        let header = d18::SubgroupHeader {
            header_type: 0x10,
            track_alias: VarInt::from_u64_moqt(1),
            group_id: VarInt::from_u64_moqt(7),
            subgroup_id: VarInt::from_u64_moqt(0),
            publisher_priority: Some(128),
        };
        let object = d18::SubgroupObject {
            object_id: VarInt::from_u64_moqt(0),
            extension_headers: Vec::new(),
            payload_length: VarInt::from_u64_moqt(3),
            object_status: Some(status18),
            payload: b"abc".to_vec(),
        };
        let mut buf = Vec::new();
        d18::SubgroupObjectReader::new(&header).write_object(&object, &mut buf).unwrap_or_else(
            |e| {
                panic!(
                    "draft-18 has no per-status Payload column, so its encoder cannot be \
                     refusing status {code:#x} a payload on the registry's authority: {e}"
                )
            },
        );

        let mut cursor = &buf[..];
        let decoded = d18::SubgroupObjectReader::new(&header)
            .read_object(&mut cursor)
            .expect("draft-18 wrote bytes its own reader cannot parse");
        assert_eq!(decoded.payload, b"abc", "draft-18 lost the payload it chose to write");
        assert_eq!(
            decoded.object_status, None,
            "draft-18 found a status field on an object it framed as carrying a payload"
        );
    }
}

// ── The draft-neutral writer answers the same way ─────────────
//
// That half of the rule is not repeated here.
// `object_status_payload_rule.rs` drives `AnySubgroupObjectWriter` across every
// compiled draft in one test, draft-20 among them, because the dispatch layer
// is one piece of code answering for all of them. Repeating it under a
// per-draft gate would run the same arm twice and say nothing new.

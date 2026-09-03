//! Parameter *values* a peer may send that no decoder gated the shape of.
//!
//! `tests/hostile_input.rs` is about a length or a count taken from the wire
//! and trusted. This file is about the other half of the same root cause, and
//! it has a shape of its own:
//!
//! > A `draftNN/message.rs` decoder gates the parameter **type** — is it known,
//! > is it a duplicate, is it in scope for this message — but does not gate the
//! > parameter **value's** shape. A `draftNN/fields.rs` extractor then parses
//! > that value structurally, with `unwrap` and bare `+`, relying on a gate
//! > that was never written.
//!
//! Every test here drives the **public decode entry point** with bytes a peer
//! could put on a control stream, and then calls `message_fields` on what comes
//! back. That order is the point: a test that called the private extractor
//! directly would prove the extractor total and prove nothing about whether the
//! bytes reach it. The whole defect was that they do.
//!
//! The chain they close, in the shipped binary, is:
//!
//! ```text
//! peer bytes on a QUIC control stream
//!   -> ControlMessage::decode
//!   -> ProxyEvent::ControlMessage
//!   -> CliObserver::on_event, when a trace is being written
//!   -> AnyControlMessage::fields()
//!   -> draftNN::fields::message_fields    <- the panic was here
//! ```
//!
//! # A malformed value is not an error to report
//!
//! `message_fields` answers for a message that has **already decoded**. The
//! frame is valid, the peer is owed whatever reply the draft says, and one
//! parameter's value is not the shape its type names. There is no error channel
//! and there should not be one: the right answer is to render what arrived, as
//! `fields::params` does since the `params.rs` fix, which is the raw bytes.
//!
//! # Release mode is a separate claim
//!
//! Two of the defects below were an integer overflow on a bare `+`, which
//! panics in debug and **silently wraps** in release. A trace recording
//! `start = 18446744073709551615, end = 0` is worse than a crash: it is a wrong
//! answer that looks like data. Every overflow test here asserts the rendered
//! value rather than merely surviving, so it fails in both profiles. Run the
//! suite with `--release` as well; that is the configuration the wrap is silent
//! in.

use moqtap_codec::fields::FieldValue;

/// The parameters of a rendered message, collapsed to a map keyed by name.
///
/// The rendering is a list of entries in wire order, because a parameter block
/// is a list on the wire and two of its types may repeat. Every message in this
/// file carries one parameter, so a map is the convenient shape *here* — the
/// collapse is this file's business and not the renderer's, which is the point
/// of the list living in the corpus instead.
///
/// An entry the draft does not name is keyed by its type, so a test asserting
/// that a draft gives a type no name can still find what arrived.
///
/// Every test here is gated to the drafts its parameter exists on, so under a
/// single-draft build most of this file compiles away and its helpers go
/// unused. `allow` rather than a `cfg` listing the callers' drafts: that list
/// is an invariant nothing checks, and it silently stops being right the next
/// time a draft is added.
#[allow(dead_code)]
fn parameters(fields: &moqtap_codec::fields::FieldMap) -> moqtap_codec::fields::FieldMap {
    entries_by_name(fields.get("parameters"))
}

/// Collapse a rendered Key-Value-Pair list the same way, for a nested block.
#[allow(dead_code)]
fn entries_by_name(block: Option<&FieldValue>) -> moqtap_codec::fields::FieldMap {
    let Some(FieldValue::Array(entries)) = block else {
        panic!("no Key-Value-Pair list in the rendered message: {block:?}");
    };
    let mut out = moqtap_codec::fields::FieldMap::new();
    for entry in entries {
        let FieldValue::Map(entry) = entry else {
            panic!("an entry renders as a map: {entry:?}");
        };
        let key = match (entry.get("name"), entry.get("type")) {
            (Some(FieldValue::Text(name)), _) => name.clone(),
            (None, Some(FieldValue::Text(ty))) => ty.clone(),
            other => panic!("an entry carries a type and may carry a name: {other:?}"),
        };
        if let Some(value) = entry.get("value").or_else(|| entry.get("raw_hex")) {
            out.insert(key, value.clone());
        }
    }
    out
}

// ============================================================
// 1. LARGEST_OBJECT (0x09) on drafts 15 and 16
// ============================================================

/// A SUBSCRIBE_OK carrying one LARGEST_OBJECT parameter with `value`.
///
/// Drafts 15 and 16 lay SUBSCRIBE_OK out as Request ID, Track Alias, then a
/// count-prefixed Key-Value-Pair list. 0x09 is an odd Type, so its value is
/// length-prefixed and `KeyValuePair::decode` stores whatever bytes arrive.
#[allow(dead_code)]
fn subscribe_ok_with_largest_object(value: &[u8]) -> Vec<u8> {
    let mut body = vec![
        0x01, // Request ID
        0x01, // Track Alias
        0x01, // one parameter
        0x09, // LARGEST_OBJECT
    ];
    body.push(u8::try_from(value.len()).expect("fixture values are short"));
    body.extend_from_slice(value);

    let mut wire = vec![0x04]; // SUBSCRIBE_OK
    wire.extend_from_slice(
        &u16::try_from(body.len()).expect("fixture bodies are short").to_be_bytes(),
    );
    wire.extend_from_slice(&body);
    wire
}

/// Draft-15: a LARGEST_OBJECT whose value is not two varints must render, not
/// panic.
///
/// Drafts 17 and later give 0x09 a Location encoding — the decoder reads two
/// varints and re-serialises them, so the extractor is handed two varints by
/// construction. Draft-15 has no such table, and none of `decode_parameters`'
/// four checks looks at 0x09. `decode_largest_object` unwrapped both reads.
///
/// The whole attack is **eight bytes**, and they are the ones the sweep
/// recorded: `04 00 05 01 01 01 09 00`.
///
/// *Ablation:* restore `VarInt::decode(&mut buf).unwrap()` in
/// `draft15/fields.rs::decode_largest_object` and this does not fail — it
/// panics inside the function under test:
///
/// ```text
/// thread 'a_draft_15_largest_object_that_is_not_two_varints_renders' panicked at
/// crates\moqtap-codec\src\draft15\fields.rs:103:42:
/// called `Result::unwrap()` on an `Err` value: UnexpectedEnd
/// ```
#[cfg(feature = "draft15")]
#[test]
fn a_draft_15_largest_object_that_is_not_two_varints_renders() {
    use moqtap_codec::draft15::message::ControlMessage;

    let empty = subscribe_ok_with_largest_object(&[]);
    assert_eq!(
        empty,
        vec![0x04, 0x00, 0x05, 0x01, 0x01, 0x01, 0x09, 0x00],
        "the whole message is the eight bytes the sweep recorded"
    );

    // `[]` fails the first read; `[0x00]` fails the *second*, which is the
    // nastier of the two — the value looks well formed right up to the point
    // where it is not, and that is the `params.rs` shape exactly.
    for value in [vec![], vec![0x00]] {
        let wire = subscribe_ok_with_largest_object(&value);
        let decoded = ControlMessage::decode(&mut &wire[..])
            .expect("draft-15 gates 0x09's type and not its value, so this frame decodes");

        let fields = moqtap_codec::draft15::fields::message_fields(&decoded);
        assert_eq!(
            parameters(&fields).get("largest_object"),
            Some(&FieldValue::Bytes(value.clone())),
            "the value a peer sent, not a judgement on it (value {value:?})"
        );
    }
}

/// Draft-16, which repeats draft-15's table and therefore repeats its gap.
///
/// `KNOWN_MESSAGE_PARAMETERS` admits 0x09 and `decode_parameters_in` checks
/// duplicates, tokens, varint ranges and subscription filters — none of which
/// is about 0x09.
///
/// *Ablation:* as above, in `draft16/fields.rs::decode_largest_object`.
#[cfg(feature = "draft16")]
#[test]
fn a_draft_16_largest_object_that_is_not_two_varints_renders() {
    use moqtap_codec::draft16::message::ControlMessage;

    for value in [vec![], vec![0x00]] {
        let wire = subscribe_ok_with_largest_object(&value);
        let decoded = ControlMessage::decode(&mut &wire[..])
            .expect("draft-16 gates 0x09's type and not its value, so this frame decodes");

        let fields = moqtap_codec::draft16::fields::message_fields(&decoded);
        assert_eq!(
            parameters(&fields).get("largest_object"),
            Some(&FieldValue::Bytes(value.clone())),
            "the value a peer sent, not a judgement on it (value {value:?})"
        );
    }
}

/// The positive control for the two above: a well-formed LARGEST_OBJECT still
/// renders as a Group and an Object.
///
/// A fallback that swallowed everything would pass both tests above and destroy
/// the extractor. This is what says it did not.
#[cfg(feature = "draft15")]
#[test]
fn a_well_formed_draft_15_largest_object_still_renders_its_two_fields() {
    use moqtap_codec::draft15::message::ControlMessage;

    let wire = subscribe_ok_with_largest_object(&[0x0a, 0x03]);
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("two varints are the shape");
    let fields = moqtap_codec::draft15::fields::message_fields(&decoded);

    let params = parameters(&fields);
    let Some(FieldValue::Map(largest)) = params.get("largest_object") else {
        panic!("a well-formed value must still render as fields: {params:?}");
    };
    assert_eq!(largest.get("group"), Some(&FieldValue::Uint(10)));
    assert_eq!(largest.get("object"), Some(&FieldValue::Uint(3)));
}

// ============================================================
// 2. Range Filters (0x25-0x29) on drafts 19 and 20
// ============================================================

/// A SUBSCRIBE carrying one parameter of `parameter_type` with `value`.
///
/// Drafts 19 and 20 lay SUBSCRIBE out identically — Request ID, Track
/// Namespace, Track Name, then a count-prefixed parameter block with
/// delta-encoded types — and give 0x25 through 0x29 the length-prefixed
/// encoding, which stores the value verbatim.
#[cfg(any(feature = "draft19", feature = "draft20"))]
fn subscribe_with_parameter(parameter_type: u64, value: &[u8]) -> Vec<u8> {
    use moqtap_codec::varint::{Moqt18, VarInt};

    let mut body = vec![
        0x01, // Request ID
        0x01, // Track Namespace: one field
        0x01, b'n', // that field
        0x01, b't', // Track Name
        0x01, // one parameter
    ];
    // The type is a delta from zero, so it is the type itself.
    VarInt::from_u64_moqt(parameter_type).encode_moqt::<Moqt18>(&mut body);
    VarInt::from_usize(value.len()).encode_moqt::<Moqt18>(&mut body);
    body.extend_from_slice(value);

    let mut wire = vec![0x03]; // SUBSCRIBE
    wire.extend_from_slice(
        &u16::try_from(body.len()).expect("fixture bodies are short").to_be_bytes(),
    );
    wire.extend_from_slice(&body);
    wire
}

/// The two Range Filter values that ran out mid-field.
///
/// Returned as data rather than written out per draft, because drafts 19 and 20
/// gave these five parameters the same codepoints, the same field order and the
/// same delta arithmetic — draft-20 only replaced the prose of Section 5.1.3
/// with the figures of Section 5.1.4. A rule that did not change is one the new
/// draft still has to be held to.
///
/// The third trigger, the delta overflow, is deliberately **not** here: it is
/// the one whose ablation fails as an assertion rather than as a panic, and
/// putting it in the same loop as a panicking case would let the panic mask it.
#[cfg(any(feature = "draft19", feature = "draft20"))]
fn the_truncating_triggers() -> Vec<(&'static str, u64, Vec<u8>)> {
    vec![
        // OBJECT_PROPERTY_FILTER carries a Property Type after its SetID, and a
        // one-byte value holds the SetID and nothing else. `has_remaining` was
        // never asked.
        ("a property filter with no property type", 0x28, vec![0x00]),
        // 0xC0 opens a three-byte varint with one byte behind it.
        ("a value ending mid-varint", 0x25, vec![0x00, 0xc0]),
    ]
}

/// A SUBGROUP_FILTER whose Start delta is `u64::MAX` and whose End delta is 1.
///
/// A nine-byte MoQT varint is `0xFF` followed by the full 64-bit value, so this
/// is the largest Start the encoding can name, and one more than that has
/// nowhere to go.
#[cfg(any(feature = "draft19", feature = "draft20"))]
fn a_value_whose_delta_runs_off_the_end() -> Vec<u8> {
    let mut value = vec![0x00]; // SetID
    value.push(0xff);
    value.extend_from_slice(&u64::MAX.to_be_bytes());
    value.push(0x01); // End delta of 1, past a Start of u64::MAX
    assert_eq!(value.len(), 11, "SetID, a nine-byte varint, and a one-byte one");
    value
}

/// The name a parameter type renders under, for a failure that says which
/// filter it was about.
#[cfg(any(feature = "draft19", feature = "draft20"))]
fn filter_name(parameter_type: u64) -> &'static str {
    match parameter_type {
        0x25 => "subgroup_filter",
        0x28 => "object_property_filter",
        other => panic!("unexpected fixture type {other:#x}"),
    }
}

/// Draft-20: a Range Filter value that runs out mid-field renders, and does not
/// panic.
///
/// `param_encoding` gives 0x25-0x29 the length-prefixed encoding and
/// `check_location_filters` covers 0x21 and 0x23 and skips these five
/// entirely, so the bytes reaching `decode_range_filter` are arbitrary. It read
/// three varints with `unwrap`, on a value where `has_remaining` promises one
/// byte and a MoQT varint may need nine.
///
/// *Ablation:* restore the hand-written parse in
/// `draft20/fields.rs::decode_range_filter` and this does not fail — it panics
/// inside the function under test, in debug and in release alike:
///
/// ```text
/// thread 'a_truncated_draft_20_range_filter_renders' panicked at
/// crates\moqtap-codec\src\draft20\fields.rs:114:56:
/// called `Result::unwrap()` on an `Err` value: UnexpectedEnd
/// ```
#[cfg(feature = "draft20")]
#[test]
fn a_truncated_draft_20_range_filter_renders() {
    use moqtap_codec::draft20::message::ControlMessage;

    assert_eq!(
        subscribe_with_parameter(0x28, &[0x00]),
        vec![0x03, 0x00, 0x0a, 0x01, 0x01, 0x01, 0x6e, 0x01, 0x74, 0x01, 0x28, 0x01, 0x00],
        "the property-filter trigger is the thirteen bytes the sweep recorded"
    );
    assert_eq!(
        subscribe_with_parameter(0x25, &[0x00, 0xc0]),
        vec![0x03, 0x00, 0x0b, 0x01, 0x01, 0x01, 0x6e, 0x01, 0x74, 0x01, 0x25, 0x02, 0x00, 0xc0],
        "the mid-varint trigger is the fourteen bytes the sweep recorded"
    );

    for (what, parameter_type, value) in the_truncating_triggers() {
        let wire = subscribe_with_parameter(parameter_type, &value);
        let decoded = ControlMessage::decode(&mut &wire[..]).unwrap_or_else(|e| {
            panic!("draft-20 gates these types and not their values, so {what} decodes: {e:?}")
        });

        let fields = moqtap_codec::draft20::fields::message_fields(&decoded);
        assert_eq!(
            parameters(&fields).get(filter_name(parameter_type)),
            Some(&FieldValue::Bytes(value.clone())),
            "{what}: the bytes a peer sent, not a structure invented from them"
        );
    }
}

/// Draft-19, where the same two parse the same way.
///
/// *Ablation:* as above, in `draft19/fields.rs::decode_range_filter`.
#[cfg(feature = "draft19")]
#[test]
fn a_truncated_draft_19_range_filter_renders() {
    use moqtap_codec::draft19::message::ControlMessage;

    for (what, parameter_type, value) in the_truncating_triggers() {
        let wire = subscribe_with_parameter(parameter_type, &value);
        let decoded = ControlMessage::decode(&mut &wire[..]).unwrap_or_else(|e| {
            panic!("draft-19 gates these types and not their values, so {what} decodes: {e:?}")
        });

        let fields = moqtap_codec::draft19::fields::message_fields(&decoded);
        assert_eq!(
            parameters(&fields).get(filter_name(parameter_type)),
            Some(&FieldValue::Bytes(value.clone())),
            "{what}: the bytes a peer sent, not a structure invented from them"
        );
    }
}

/// The delta that runs off the end of the 64-bit space, on draft-20.
///
/// **This is the test that needs `--release` to be worth anything.** The parse
/// resolved its two delta baselines with a bare `+`. In debug that is a panic
/// and this test would report one. In release it *wraps*, and nothing crashes:
/// the extractor renders `start: 18446744073709551615, end: 0` and the trace
/// writer records it as though a peer had asked for it. A wrong answer that
/// looks like data is the worse of the two failures, and only an assertion on
/// the rendered value catches it.
///
/// `range_filter.rs` has used `checked_add` on both baselines since it was
/// written, and `tests/range_filters_draft20.rs` has covered
/// `DeltaOverflow { base: u64::MAX, delta: 2 }` for as long. Neither was
/// reached from here.
///
/// *Ablation:* restore the bare `+` in
/// `draft20/fields.rs::decode_range_filter`. In debug it panics with
/// `attempt to add with overflow`; in release it fails as an assertion:
///
/// ```text
/// assertion `left == right` failed: an overflowing delta is not a range
///   left: Some(Map(FieldMap { entries: [("set_id", Uint(0)),
///         ("ranges", Array([Map(FieldMap { entries: [("start",
///         Uint(18446744073709551615)), ("end", Uint(0))] })]))] }))
///  right: Some(Bytes([0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1]))
/// ```
#[cfg(feature = "draft20")]
#[test]
fn a_draft_20_range_filter_delta_off_the_end_of_the_space_does_not_wrap() {
    use moqtap_codec::draft20::message::ControlMessage;

    let value = a_value_whose_delta_runs_off_the_end();
    let wire = subscribe_with_parameter(0x25, &value);
    let decoded = ControlMessage::decode(&mut &wire[..])
        .expect("the frame is well formed; it is the parameter value that is not");

    let fields = moqtap_codec::draft20::fields::message_fields(&decoded);
    assert_eq!(
        parameters(&fields).get("subgroup_filter"),
        Some(&FieldValue::Bytes(value)),
        "an overflowing delta is not a range"
    );
}

/// The same, on draft-19.
///
/// *Ablation:* as above, in `draft19/fields.rs::decode_range_filter`.
#[cfg(feature = "draft19")]
#[test]
fn a_draft_19_range_filter_delta_off_the_end_of_the_space_does_not_wrap() {
    use moqtap_codec::draft19::message::ControlMessage;

    let value = a_value_whose_delta_runs_off_the_end();
    let wire = subscribe_with_parameter(0x25, &value);
    let decoded = ControlMessage::decode(&mut &wire[..])
        .expect("the frame is well formed; it is the parameter value that is not");

    let fields = moqtap_codec::draft19::fields::message_fields(&decoded);
    assert_eq!(
        parameters(&fields).get("subgroup_filter"),
        Some(&FieldValue::Bytes(value)),
        "an overflowing delta is not a range"
    );
}

/// All three triggers, one level down inside FILL_PARAMETERS.
///
/// Draft-20's `FILL_PARAMETERS_ALLOWED` lists 0x25 through 0x28, and
/// `draft20/fields.rs` recurses into `params_to_json` for a 0x23 value — so
/// every trigger above has a second route to the same extractor, through a
/// parameter the decoder does check the structure of. `decode_fill_parameters`
/// validates the nested block's framing and its nested LOCATION_FILTERs; it
/// says nothing about a nested Range Filter's value.
///
/// *Ablation:* as above. This one is worth keeping separate because a fix
/// applied to the top-level call site alone would leave it panicking.
#[cfg(feature = "draft20")]
#[test]
fn a_malformed_range_filter_nested_in_fill_parameters_renders() {
    use moqtap_codec::draft20::message::ControlMessage;
    use moqtap_codec::varint::{Moqt18, VarInt};

    let mut triggers = the_truncating_triggers();
    triggers.push((
        "a delta off the end of the 64-bit space",
        0x25,
        a_value_whose_delta_runs_off_the_end(),
    ));

    for (what, parameter_type, value) in triggers {
        // The FILL_PARAMETERS value is a parameter block of its own: a count,
        // then one delta-encoded type and its length-prefixed value.
        let mut nested = vec![0x01];
        VarInt::from_u64_moqt(parameter_type).encode_moqt::<Moqt18>(&mut nested);
        VarInt::from_usize(value.len()).encode_moqt::<Moqt18>(&mut nested);
        nested.extend_from_slice(&value);

        let wire = subscribe_with_parameter(0x23, &nested);
        let decoded = ControlMessage::decode(&mut &wire[..]).unwrap_or_else(|e| {
            panic!("a fill block carrying {what} is well formed as a block: {e:?}")
        });

        let fields = moqtap_codec::draft20::fields::message_fields(&decoded);
        let params = parameters(&fields);
        // A nested block is a Key-Value-Pair list like the outer one, so it
        // collapses the same way. The nesting is the whole point of the test:
        // a value the outer block would have rendered as bytes must not become
        // a structure one level down.
        let fill = entries_by_name(params.get("fill_parameters"));
        assert_eq!(
            fill.get(filter_name(parameter_type)),
            Some(&FieldValue::Bytes(value.clone())),
            "{what}, nested: the bytes a peer sent, not a structure invented from them"
        );
    }
}

/// The positive control for the Range Filters: a well-formed one still renders
/// as ranges, and renders them with the draft's own two baselines.
///
/// Section 5.1.3's worked example: ranges 3-5 and 10-15 are written `3, 2, 5,
/// 5`, because a Start counts from the prior Range's **End** and an End counts
/// from the Start beside it. A fallback that swallowed everything, or a reader
/// with one running baseline, would decode the same four integers as 3-5 and
/// 8-13 — well formed, in range, and wrong.
#[cfg(feature = "draft20")]
#[test]
fn a_well_formed_draft_20_range_filter_still_renders_its_ranges() {
    use moqtap_codec::draft20::message::ControlMessage;

    let wire = subscribe_with_parameter(0x25, &[0x00, 0x03, 0x02, 0x05, 0x05]);
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("a well-formed filter");
    let fields = moqtap_codec::draft20::fields::message_fields(&decoded);

    let params = parameters(&fields);
    let Some(FieldValue::Map(filter)) = params.get("subgroup_filter") else {
        panic!("a well-formed filter must render as fields: {params:?}");
    };
    assert_eq!(filter.get("set_id"), Some(&FieldValue::Uint(0)));

    let mut range = moqtap_codec::fields::FieldMap::new();
    range.insert("start".into(), FieldValue::Uint(3));
    range.insert("end".into(), FieldValue::Uint(5));
    let mut second = moqtap_codec::fields::FieldMap::new();
    second.insert("start".into(), FieldValue::Uint(10));
    second.insert("end".into(), FieldValue::Uint(15));
    assert_eq!(
        filter.get("ranges"),
        Some(&FieldValue::Array(vec![FieldValue::Map(range), FieldValue::Map(second)])),
        "a Start counts from the prior Range's End, not from its Start"
    );
}

/// A Range Filter whose final End is left off is a range with no end, and the
/// rendering says so by omitting the field rather than by inventing a number.
///
/// The omission is what makes the pairing unambiguous, so this also pins that
/// an odd number of integers is not treated as a truncated value.
#[cfg(feature = "draft20")]
#[test]
fn a_range_filter_with_no_final_end_renders_a_start_and_no_end() {
    use moqtap_codec::draft20::message::ControlMessage;

    let wire = subscribe_with_parameter(0x25, &[0x00, 0x07]);
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("a well-formed open filter");
    let fields = moqtap_codec::draft20::fields::message_fields(&decoded);

    let params = parameters(&fields);
    let Some(FieldValue::Map(filter)) = params.get("subgroup_filter") else {
        panic!("a well-formed filter must render as fields: {params:?}");
    };
    let mut range = moqtap_codec::fields::FieldMap::new();
    range.insert("start".into(), FieldValue::Uint(7));
    assert_eq!(
        filter.get("ranges"),
        Some(&FieldValue::Array(vec![FieldValue::Map(range)])),
        "an omitted End is an unbounded range, not a zero"
    );
}

/// A filter that parses but breaks a content rule renders its fields, and says
/// which rule.
///
/// `RangeFilter` enforces two rules past the value's shape: a `PRIORITY_FILTER`
/// range naming a value above 255 (Publisher Priority is an 8-bit field), and a
/// property filter over an odd Property Type (odd Types carry length-prefixed
/// bytes, so a range over one has nothing to compare). Both are answered with
/// REQUEST_ERROR rather than a session close, so both are values a peer really
/// sends and a reader really has to look at.
///
/// This is why the renderer parses with `decode_moqt_structure` and checks
/// with `check_its_own_types` rather than calling `decode_moqt`, which does
/// both: a reader that refuses the value falls back to a hex dump, hiding the
/// offending number inside the bytes at exactly the moment someone is looking
/// for it. Split, the field rendering and the rule report are both available.
///
/// *Ablation:* call `decode_moqt` from `draft20/fields.rs` instead and this
/// fails with `got Bytes([0, 129, 44])` — the value, unrendered.
#[cfg(feature = "draft20")]
#[test]
fn a_priority_filter_above_the_field_renders_its_fields_and_names_the_rule() {
    use moqtap_codec::draft20::message::ControlMessage;

    // set_id 0, one open range starting at 300. 300 is two MoQT varint bytes
    // (`0x8000 | 300`), and is the whole point: a Publisher Priority cannot
    // hold it.
    let wire = subscribe_with_parameter(0x27, &[0x00, 0x81, 0x2c]);
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("the frame itself is well-formed");
    let fields = moqtap_codec::draft20::fields::message_fields(&decoded);

    let params = parameters(&fields);
    let Some(FieldValue::Map(filter)) = params.get("priority_filter") else {
        panic!(
            "a rule-breaking filter must still render its fields, got {:?}",
            parameters(&fields).get("priority_filter")
        );
    };

    let mut range = moqtap_codec::fields::FieldMap::new();
    range.insert("start".into(), FieldValue::Uint(300));
    assert_eq!(
        filter.get("ranges"),
        Some(&FieldValue::Array(vec![FieldValue::Map(range)])),
        "the value that breaks the rule is the one a reader needs to see"
    );

    let Some(FieldValue::Text(violates)) = filter.get("violates") else {
        panic!("the broken rule must be named, got {filter:?}");
    };
    assert!(violates.contains("300"), "the report must name the offending value, got {violates:?}");
}

/// The same, for the other rule: a property filter over an odd Property Type.
#[cfg(feature = "draft20")]
#[test]
fn a_property_filter_over_an_odd_property_type_renders_and_names_the_rule() {
    use moqtap_codec::draft20::message::ControlMessage;

    // set_id 0, Property Type 3 (odd), one open range starting at 5.
    let wire = subscribe_with_parameter(0x28, &[0x00, 0x03, 0x05]);
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("the frame itself is well-formed");
    let fields = moqtap_codec::draft20::fields::message_fields(&decoded);

    let params = parameters(&fields);
    let Some(FieldValue::Map(filter)) = params.get(filter_name(0x28)) else {
        panic!("a rule-breaking filter must still render its fields: {params:?}");
    };
    assert_eq!(
        filter.get("property_type"),
        Some(&FieldValue::Uint(3)),
        "the odd Property Type is what the reader is looking for"
    );
    let Some(FieldValue::Text(violates)) = filter.get("violates") else {
        panic!("the broken rule must be named, got {filter:?}");
    };
    assert!(
        violates.contains('3'),
        "the report must name the offending Property Type, got {violates:?}"
    );
}

/// The negative control: a filter breaking no rule carries no `violates` key.
///
/// Without this, a bug that reported every filter as violating something would
/// pass both tests above.
#[cfg(feature = "draft20")]
#[test]
fn a_well_formed_filter_is_not_reported_as_violating_anything() {
    use moqtap_codec::draft20::message::ControlMessage;

    // A priority filter whose range is 1..=4 — inside the 8-bit field.
    let wire = subscribe_with_parameter(0x27, &[0x00, 0x01, 0x03]);
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("a well-formed priority filter");
    let fields = moqtap_codec::draft20::fields::message_fields(&decoded);

    let params = parameters(&fields);
    let Some(FieldValue::Map(filter)) = params.get("priority_filter") else {
        panic!("a well-formed filter must render as fields: {params:?}");
    };
    assert_eq!(filter.get("violates"), None, "nothing is broken here: {filter:?}");
}

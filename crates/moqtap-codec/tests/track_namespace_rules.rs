//! The Track Namespace rules of Section 2.4.1, on the drafts that read a
//! namespace with the QUIC variable-length integer — 07 through 16.
//!
//! Every rule here moves at some point in the draft series, and none of them
//! moves at the same point, so this file is organised by the rule rather than by
//! the draft: a rule that arrives in draft-16 gets one test with the draft
//! before it and the draft that states it side by side. That is the shape a
//! blanket rule fails, and a blanket rule is what this code had.
//!
//! Every gate is a consequence: bytes in and an answer out, or a frame in and
//! the message it becomes. None of them reads a rule value back.
//!
//! Drafts 17 and later state the same rules over a different varint and are
//! covered in `parameter_and_namespace_rules.rs`.
//!
//! # What breaking each fix does, observed by making the change and running
//!
//! The output quoted in each docstring came from making that edit and running
//! the test; none of it is a prediction.

#![cfg(all(feature = "draft15", feature = "draft16"))]

use moqtap_codec::error::{CodecError, MAX_FULL_TRACK_NAME_LENGTH};
use moqtap_codec::types::{TrackNamespace, TrackNamespaceRules};
use moqtap_codec::varint::VarInt;

/// `v` as QUIC varint bytes (RFC 9000 Section 16).
///
/// Written through the codec's own writer, so a frame these tests build is
/// framed the way the decoder under test expects.
fn vb(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(v).expect("value fits a QUIC varint").encode(&mut out);
    out
}

/// A draft-07 through draft-16 control frame: type, 16-bit length, body.
fn frame(msg_type: u64, body: &[u8]) -> Vec<u8> {
    let mut out = vb(msg_type);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A Track Namespace on the wire: field count, then each field length-prefixed.
fn namespace(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = vb(fields.len() as u64);
    for field in fields {
        out.extend_from_slice(&vb(field.len() as u64));
        out.extend_from_slice(field);
    }
    out
}

/// A Track Namespace whose fields carry the given lengths, filled with padding.
///
/// Separate from [`namespace`] so a four-kilobyte case does not have to
/// materialise its own filler at every call site.
fn namespace_of_lengths(lengths: &[usize]) -> Vec<u8> {
    let fields: Vec<Vec<u8>> = lengths.iter().map(|n| vec![b'n'; *n]).collect();
    let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
    namespace(&refs)
}

/// A draft-16 decode outcome in one readable line.
///
/// The oversize cases here carry thousands of identical bytes, and `{:?}` on the
/// message spells every one of them out. A failure report nobody can read
/// through is a failure nobody acts on, so a namespace that got through is
/// reported by its shape instead of its contents.
fn outcome(got: &Result<moqtap_codec::draft16::message::ControlMessage, CodecError>) -> String {
    use moqtap_codec::draft16::message::ControlMessage;
    let suffix = match got {
        Err(e) => return format!("Err({e:?})"),
        Ok(ControlMessage::Namespace(m)) => &m.namespace_suffix,
        Ok(ControlMessage::NamespaceDone(m)) => &m.namespace_suffix,
        Ok(ControlMessage::SubscribeNamespace(m)) => &m.namespace_prefix,
        Ok(other) => return format!("Ok({other:?})"),
    };
    format!("Ok({} fields, {} bytes)", suffix.0.len(), suffix.field_bytes_len())
}

/// A bare namespace decode outcome in one readable line, for the same reason as
/// [`outcome`].
fn ns_outcome(got: &Result<TrackNamespace, CodecError>) -> String {
    match got {
        Err(e) => format!("Err({e:?})"),
        Ok(ns) => format!("Ok({} fields, {} bytes)", ns.0.len(), ns.field_bytes_len()),
    }
}

// ─────────────────────────────────────────────────────────────
// Section 2.4.1 — a Track Namespace Field Value of zero bytes
// ─────────────────────────────────────────────────────────────

/// Draft-16 closes the session over a zero-length Track Namespace Field.
///
/// Draft-16 Section 2.4.1: "Each Track Namespace Field Value MUST contain at
/// least one byte. If an endpoint receives a Track Namespace Field with a Track
/// Namespace Field Length of 0, it MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// An empty field is not the same namespace as no field, but the two render
/// identically, and an empty field makes two distinct namespaces compare equal
/// under the prefix matching a relay routes on.
///
/// # Observed with the fix reverted
///
/// Removing the `len == 0` arm from `TrackNamespace::decode_rules`:
///
/// ```text
/// ---- draft_16_refuses_a_zero_length_namespace_field stdout ----
///
/// thread 'draft_16_refuses_a_zero_length_namespace_field' (56344) panicked at crates\moqtap-codec\tests\track_namespace_rules.rs:124:5:
/// draft-16 NAMESPACE accepted a zero-length field: Ok(Namespace(Namespace { namespace_suffix: TrackNamespace([[]]) }))
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
#[test]
fn draft_16_refuses_a_zero_length_namespace_field() {
    use moqtap_codec::draft16::message::ControlMessage;

    // NAMESPACE (0x08): one Track Namespace Field, declared length 0.
    let wire = frame(0x08, &namespace(&[b""]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-16 NAMESPACE accepted a zero-length field: {got:?}"
    );

    // NAMESPACE_DONE (0x0E) reads its suffix through the same path, and a rule
    // that reaches only one of the two is not the rule the draft states.
    let wire = frame(0x0E, &namespace(&[b"live", b""]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-16 NAMESPACE_DONE accepted a zero-length field: {got:?}"
    );
}

/// Drafts before 16 accept a zero-length Track Namespace Field, because none of
/// them says otherwise.
///
/// The "at least one byte" sentence first appears in draft-16. Draft-15
/// describes a Track Namespace Field Value only as "a sequence of bytes that
/// forms a Track Namespace Field" and stops there; drafts 07 through 14 have no
/// such field to describe, carrying the namespace as tuple fields their own
/// wording says carry a sequence of bytes. A decoder that refuses an empty one
/// on any of the nine closes sessions over traffic those drafts permit. Ten
/// drafts share one reader, so tightening it is the easy mistake and this is
/// the gate against it.
///
/// # Observed with the fix reverted
///
/// Setting `reject_empty_field: true` in `TrackNamespace::decode`:
///
/// ```text
/// ---- drafts_before_16_accept_a_zero_length_namespace_field stdout ----
///
/// thread 'drafts_before_16_accept_a_zero_length_namespace_field' (12696) panicked at crates\moqtap-codec\tests\track_namespace_rules.rs:172:18:
/// draft-15 PUBLISH_NAMESPACE refused a zero-length field: Err(EmptyNamespaceField)
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
#[test]
fn drafts_before_16_accept_a_zero_length_namespace_field() {
    use moqtap_codec::draft15::message::ControlMessage;

    // PUBLISH_NAMESPACE (0x06): request id, namespace, parameter count.
    let mut body = vb(1);
    body.extend_from_slice(&namespace(&[b""]));
    body.push(0x00);
    let wire = frame(0x06, &body);

    let got = ControlMessage::decode(&mut &wire[..]);
    let msg = match got {
        Ok(m) => m,
        other => panic!("draft-15 PUBLISH_NAMESPACE refused a zero-length field: {other:?}"),
    };
    let mut out = Vec::new();
    msg.encode(&mut out).expect("re-encode");
    assert_eq!(out, wire, "a zero-length namespace field did not round-trip");
}

// ─────────────────────────────────────────────────────────────
// Section 2.4.1 — a Track Namespace of at most 4,096 bytes
// ─────────────────────────────────────────────────────────────

/// Draft-16 closes the session over a Track Namespace above 4,096 bytes.
///
/// Draft-16 Section 2.4.1: "The length of a Track Namespace is the sum of the
/// Track Namespace Field Length fields. If an endpoint receives a Track
/// Namespace or a Full Track Name exceeding 4,096 bytes, it MUST close the
/// session with a PROTOCOL_VIOLATION."
///
/// A control message may be 65,535 bytes, so unenforced a peer spends sixteen
/// times the permitted budget on one namespace, and two relays that disagree
/// about whether it was legal disagree about cache identity.
///
/// The sum is what the draft caps, not any one field: two fields of 2,500 bytes
/// are each legal alone and together are not.
///
/// # Observed with the fix reverted
///
/// Removing the `max_namespace_bytes` arm from `TrackNamespace::decode_rules`:
///
/// ```text
/// ---- draft_16_refuses_a_namespace_over_4096_bytes stdout ----
///
/// thread 'draft_16_refuses_a_namespace_over_4096_bytes' (65036) panicked at crates\moqtap-codec\tests\track_namespace_rules.rs:214:5:
/// draft-16 accepted a 4097-byte namespace: Ok(1 fields, 4097 bytes)
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
#[test]
fn draft_16_refuses_a_namespace_over_4096_bytes() {
    use moqtap_codec::draft16::message::ControlMessage;

    let wire = frame(0x08, &namespace_of_lengths(&[MAX_FULL_TRACK_NAME_LENGTH + 1]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::TrackNameTooLong)),
        "draft-16 accepted a {}-byte namespace: {}",
        MAX_FULL_TRACK_NAME_LENGTH + 1,
        outcome(&got)
    );

    let wire = frame(0x08, &namespace_of_lengths(&[2500, 2500]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::TrackNameTooLong)),
        "draft-16 accepted two fields summing to 5000 bytes: {}",
        outcome(&got)
    );

    // The cap is inclusive: 4,096 bytes is the maximum, not the first refusal.
    let wire = frame(0x08, &namespace_of_lengths(&[2048, 2048]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        got.is_ok(),
        "draft-16 refused a namespace of exactly {MAX_FULL_TRACK_NAME_LENGTH} bytes: {}",
        outcome(&got)
    );
}

// ─────────────────────────────────────────────────────────────
// Section 2.4.1 — how few Track Namespace Fields a position accepts
// ─────────────────────────────────────────────────────────────

/// Draft-16's NAMESPACE and NAMESPACE_DONE still carry a suffix of no fields.
///
/// Both messages are answers to a SUBSCRIBE_NAMESPACE and carry "only the
/// namespace tuples after the 'Track Namespace Prefix'", which is nothing at all
/// when the prefix already names the whole namespace. Tightening the field
/// content rules is the change that would take this with it, since the two are
/// applied by the same reader, so it is gated beside them.
///
/// # Observed with the fix reverted
///
/// Setting `min_fields: 1` in `TrackNamespace::decode_allow_empty`:
///
/// ```text
/// ---- draft_16_accepts_a_namespace_suffix_of_no_fields stdout ----
///
/// thread 'draft_16_accepts_a_namespace_suffix_of_no_fields' (12500) panicked at crates\moqtap-codec\tests\track_namespace_rules.rs:270:18:
/// draft-16 refused an empty namespace suffix: Err(InvalidNamespaceTupleSize(0))
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
#[test]
fn draft_16_accepts_a_namespace_suffix_of_no_fields() {
    use moqtap_codec::draft16::message::ControlMessage;

    let wire = frame(0x08, &namespace(&[]));
    let got = ControlMessage::decode(&mut &wire[..]);
    let msg = match got {
        Ok(m) => m,
        other => panic!("draft-16 refused an empty namespace suffix: {other:?}"),
    };
    let mut out = Vec::new();
    msg.encode(&mut out).expect("re-encode");
    assert_eq!(out, wire, "an empty namespace suffix did not round-trip");
}

/// The per-draft rules answer each draft with what that draft states.
///
/// One reader serves drafts 07 through 16, so the only way it can be right on
/// all of them is to be told which one it is reading. Each pair below is the
/// draft that states a rule and the draft before it:
///
/// - Fields of zero bytes: draft-16 states "Each Track Namespace Field Value
///   MUST contain at least one byte"; draft-15 does not.
/// - A 4,096-byte cap on the namespace alone: draft-16 states "If an endpoint
///   receives a Track Namespace or a Full Track Name exceeding 4,096 bytes, it
///   MUST close the session with a PROTOCOL_VIOLATION"; draft-15 caps only the
///   Full Track Name, which no reader of the namespace alone can settle, and
///   draft-10 states no cap at all.
/// - No fields at all: drafts 07 through 16 define a Track Namespace as "between
///   1 and 32 Track Namespace Fields"; draft-17 redefines it as "between 0 and
///   32" and drops the sentence that made zero a session-closing error.
///
/// # Observed with the fix reverted
///
/// Changing `reject_empty_field` in `TrackNamespaceRules::for_draft` from
/// `draft >= 16` to `draft >= 15`:
///
/// ```text
/// ---- each_draft_gets_the_rules_that_draft_states stdout ----
///
/// thread 'each_draft_gets_the_rules_that_draft_states' (10648) panicked at crates\moqtap-codec\tests\track_namespace_rules.rs:316:5:
/// draft-15 refused a zero-length field: Err(EmptyNamespaceField)
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
#[test]
fn each_draft_gets_the_rules_that_draft_states() {
    let empty_field = namespace(&[b""]);
    let over_cap = namespace_of_lengths(&[5000]);
    let no_fields = namespace(&[]);

    let d15 = TrackNamespaceRules::for_draft(15);
    let d16 = TrackNamespaceRules::for_draft(16);

    let got = TrackNamespace::decode_rules(&mut &empty_field[..], d15);
    assert!(got.is_ok(), "draft-15 refused a zero-length field: {}", ns_outcome(&got));
    let got = TrackNamespace::decode_rules(&mut &empty_field[..], d16);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-16 accepted a zero-length field: {}",
        ns_outcome(&got)
    );

    let got = TrackNamespace::decode_rules(&mut &over_cap[..], TrackNamespaceRules::for_draft(10));
    assert!(got.is_ok(), "draft-10 applied a cap it does not state: {}", ns_outcome(&got));
    let got = TrackNamespace::decode_rules(&mut &over_cap[..], d15);
    assert!(got.is_ok(), "draft-15 capped the namespace on its own: {}", ns_outcome(&got));
    let got = TrackNamespace::decode_rules(&mut &over_cap[..], d16);
    assert!(
        matches!(got, Err(CodecError::TrackNameTooLong)),
        "draft-16 accepted a 5000-byte namespace: {}",
        ns_outcome(&got)
    );

    let got = TrackNamespace::decode_rules(&mut &no_fields[..], d16);
    assert!(
        matches!(got, Err(CodecError::InvalidNamespaceTupleSize(0))),
        "draft-16 accepted a namespace of no fields: {}",
        ns_outcome(&got)
    );
    let got = TrackNamespace::decode_rules(&mut &no_fields[..], TrackNamespaceRules::for_draft(17));
    assert!(got.is_ok(), "draft-17 refused a namespace of no fields: {}", ns_outcome(&got));
}

/// Every draft-16 namespace position reads under draft-16's rules, not just the
/// two that permit an empty tuple.
///
/// Draft-16 states its content rules about a Track Namespace, without regard to
/// which message carries one. The codec had them on only the positions that
/// also permit a zero-field tuple — NAMESPACE and NAMESPACE_DONE — because
/// those were the ones that needed a reader of their own. The other six read
/// through the shared pre-16 path, which states neither rule, so the same
/// namespace was legal or illegal in draft-16 depending on the message it
/// arrived in.
///
/// SUBSCRIBE_NAMESPACE is the vehicle because its prefix is one of the six and
/// carries no Track Name, which separates this cap from the Full Track Name cap
/// that applies where a name sits beside the namespace.
///
/// # Observed with the fix reverted
///
/// Restoring `TrackNamespace::decode(buf)?` at the SUBSCRIBE_NAMESPACE prefix:
///
/// ```text
/// draft-16 SUBSCRIBE_NAMESPACE accepted a 5000-byte namespace: Ok(2 fields, 5000 bytes)
/// ```
#[test]
fn draft_16_applies_its_namespace_rules_at_every_position() {
    use moqtap_codec::draft16::message::ControlMessage;

    // SUBSCRIBE_NAMESPACE (0x11): request id, namespace prefix, options, params.
    let subscribe_namespace = |ns: Vec<u8>| {
        let mut body = vb(1);
        body.extend_from_slice(&ns);
        body.push(0x00); // Subscribe Options
        body.push(0x00); // no parameters
        frame(0x11, &body)
    };

    let wire = subscribe_namespace(namespace_of_lengths(&[2500, 2500]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::TrackNameTooLong)),
        "draft-16 SUBSCRIBE_NAMESPACE accepted a 5000-byte namespace: {}",
        outcome(&got)
    );

    // The empty-field rule reaches the same position.
    let wire = subscribe_namespace(namespace(&[b"live", b""]));
    let got = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-16 SUBSCRIBE_NAMESPACE accepted a zero-length field: {}",
        outcome(&got)
    );

    // A namespace inside both rules still decodes, so what the two gates above
    // observe is the rules and not the position.
    let wire = subscribe_namespace(namespace(&[b"live", b"sports"]));
    ControlMessage::decode(&mut &wire[..]).expect("a lawful namespace prefix decodes");
}

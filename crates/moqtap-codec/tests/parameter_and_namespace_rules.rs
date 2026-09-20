//! The bounds drafts 17, 18 and 19 put on parameters, key-value pairs and
//! track names, checked in both directions.
//!
//! Every gate here is a consequence: bytes in and an answer out, or a message in
//! and the bytes it becomes. None of them reads a constant back.
//!
//! Two of these rules are the reason the file exists rather than a test module
//! beside each draft. They are worded identically in all three drafts, and the
//! defect they cover was present in all three at once — a decoder that panicked
//! on a delta-encoded key and an encoder that truncated a uint8 parameter. A
//! single file makes a draft that drifts out of line visible as a missing row
//! rather than as a test nobody wrote.
//!
//! # What breaking each fix does, observed by making the change and running
//!
//! The observed output for each is in the docstring of the test that catches
//! it; they are not predictions.

#![cfg(all(feature = "draft17", feature = "draft18", feature = "draft19", feature = "draft20"))]

use moqtap_codec::error::{
    CodecError, MAX_FULL_TRACK_NAME_LENGTH, MAX_GOAWAY_URI_LENGTH, MAX_REASON_PHRASE_LENGTH,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// A MoQT varint, in the form drafts 17+ use.
fn vi(v: u64) -> VarInt {
    VarInt::from_u64_moqt(v)
}

/// `v` as MoQT varint bytes.
///
/// Encoded through the codec's own writer rather than by hand, so a frame these
/// tests build is framed the way the decoder under test expects. The two
/// profiles differ only over the seven-byte length, which nothing here uses; the
/// assertion says so rather than leaving it to be assumed.
fn vb(v: u64) -> Vec<u8> {
    use moqtap_codec::varint::{Moqt17, Moqt18};
    let mut a = Vec::new();
    VarInt::from_u64_moqt(v).encode_moqt::<Moqt17>(&mut a);
    let mut b = Vec::new();
    VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(&mut b);
    assert_eq!(a, b, "{v} is encoded differently by the two varint profiles");
    a
}

/// A draft-17 or later control-message frame: type, 16-bit length, body.
fn frame(msg_type: u64, body: &[u8]) -> Vec<u8> {
    let mut out = vb(msg_type);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

// ─────────────────────────────────────────────────────────────
// Section 1.4.3 — the delta-encoded type may not pass 2^64 - 1
// ─────────────────────────────────────────────────────────────

/// A SETUP whose Setup Options step past the end of the 64-bit range is refused
/// rather than crashing the process.
///
/// Drafts 17, 18 and 19 all say, in Section 1.4.3: "The previous Type value plus
/// the Delta Type MUST NOT be greater than 2^64 - 1. If a Delta Type is received
/// that would be too large, the Session MUST be closed with a
/// PROTOCOL_VIOLATION."
///
/// The first option's delta is u64::MAX and the second's is 1, so the sum passes
/// the end. Twelve bytes of control message; nothing about it needs a session.
///
/// # Observed with the fix reverted
///
/// Restoring `let abs_key = prev_key + delta;` in `decode_kvp_delta` on all three
/// drafts and running `cargo test -p moqtap-codec --all-features --test
/// parameter_and_namespace_rules setup_option_key`:
///
/// ```text
/// ---- setup_option_key_may_not_wrap_past_the_end_of_the_range stdout ----
///
/// thread 'setup_option_key_may_not_wrap_past_the_end_of_the_range' (7244) panicked at crates\moqtap-codec\src\draft17\message.rs:
/// attempt to add with overflow
/// ```
///
/// A remote peer reaches that line with a control message it chooses, so the
/// panic is the finding rather than a test artefact.
#[test]
fn setup_option_key_may_not_wrap_past_the_end_of_the_range() {
    // Setup option type u64::MAX is odd, so its value is length-prefixed.
    let mut body = vb(u64::MAX);
    body.push(0x00); // zero-length value
    body.push(0x01); // delta 1 -> the sum wraps
    body.push(0x00);
    let wire = frame(0x2f00, &body);

    let d17 = moqtap_codec::draft17::message::ControlMessage::decode(&mut &wire[..]).err();
    let d18 = moqtap_codec::draft18::message::ControlMessage::decode(&mut &wire[..]).err();
    let d19 = moqtap_codec::draft19::message::ControlMessage::decode(&mut &wire[..]).err();
    let d20 = moqtap_codec::draft20::message::ControlMessage::decode(&mut &wire[..]).err();

    for (draft, got) in [("17", d17), ("18", d18), ("19", d19), ("20", d20)] {
        assert!(
            matches!(got, Some(CodecError::KeyDeltaOverflow(..))),
            "draft-{draft} accepted a wrapping setup option key: {got:?}"
        );
    }
}

/// The same rule, one layer along: a SUBSCRIBE's parameter block.
///
/// Message Parameters are delta-encoded by the same rule, and draft-18 and
/// draft-19 Section 10.2 restate it: "If the resulting Type would be greater
/// than 2^64 - 1, the endpoint MUST close the session with a
/// PROTOCOL_VIOLATION."
#[test]
fn parameter_key_may_not_wrap_past_the_end_of_the_range() {
    // draft-18/19 SUBSCRIBE body: request id, namespace, name, parameters.
    // Request ID 1, a one-field namespace, a one-byte track name.
    let mut body = vec![0x01];
    body.extend_from_slice(&[0x01, 0x02, b'n', b's']);
    body.extend_from_slice(&[0x01, b't']);
    // Two parameters. The first is GROUP_ORDER (0x22) with a legal value, so it
    // is a type the decoder knows and the block survives to the second.
    body.push(0x02);
    body.extend_from_slice(&[0x22, 0x01]);
    // Then a delta of u64::MAX, which 0x22 cannot absorb.
    body.extend_from_slice(&vb(u64::MAX));
    body.push(0x00);
    let wire = frame(0x03, &body);

    let d18 = moqtap_codec::draft18::message::ControlMessage::decode(&mut &wire[..]).err();
    let d19 = moqtap_codec::draft19::message::ControlMessage::decode(&mut &wire[..]).err();
    let d20 = moqtap_codec::draft20::message::ControlMessage::decode(&mut &wire[..]).err();
    for (draft, got) in [("18", d18), ("19", d19), ("20", d20)] {
        assert!(
            matches!(got, Some(CodecError::KeyDeltaOverflow(..))),
            "draft-{draft} accepted a wrapping parameter key: {got:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// Section 10.2 / 9.3 — ascending order, and no repeats
// ─────────────────────────────────────────────────────────────

/// Encoding a parameter list that descends is refused rather than wrapped.
///
/// Drafts 17, 18 and 19: "Parameters MUST be serialized in ascending order by
/// Type." The delta is a difference, so `[0x22, 0x02]` has no representation.
///
/// # Observed with the fix reverted
///
/// Restoring `let delta = abs_key - prev_key;` in draft-17's
/// `encode_parameters`:
///
/// ```text
/// ---- descending_parameters_are_refused_rather_than_wrapped stdout ----
///
/// thread 'descending_parameters_are_refused_rather_than_wrapped' (21352) panicked at crates\moqtap-codec\src\draft17\message.rs:
/// attempt to subtract with overflow
/// ```
///
/// The panic is the debug-build symptom. A release build has no overflow check
/// there, so the same input writes the wrapped difference as a nine-byte delta
/// and the peer resolves it to an unrelated key — which is why refusing beats
/// emitting.
#[test]
fn descending_parameters_are_refused_rather_than_wrapped() {
    use moqtap_codec::draft17::message as d17;

    let msg = d17::ControlMessage::Subscribe(d17::Subscribe {
        request_id: vi(1),
        required_request_id_delta: vi(0),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        parameters: vec![
            // GROUP_ORDER (0x22) then DELIVERY_TIMEOUT (0x02): descending.
            KeyValuePair { key: vi(0x22), value: KvpValue::Varint(vi(1)) },
            KeyValuePair { key: vi(0x02), value: KvpValue::Varint(vi(5)) },
        ],
    });

    let mut buf = Vec::new();
    let got = msg.encode(&mut buf);
    assert!(
        matches!(got, Err(CodecError::ParametersOutOfOrder(0x22, 0x02))),
        "descending parameters encoded: {got:?}"
    );
}

/// A repeated parameter type is refused on decode, and AUTHORIZATION_TOKEN is
/// the exception the drafts carve out.
///
/// Drafts 17, 18 and 19: "Senders MUST NOT repeat the same Parameter Type in a
/// message unless the parameter definition explicitly allows multiple instances
/// of that type to be sent in a single message. Receivers SHOULD check that
/// there are no unexpected duplicate parameters and close the session with
/// PROTOCOL_VIOLATION if found." Section 9.3.2 / 10.2.2 names the exception:
/// "The AUTHORIZATION TOKEN parameter MAY be repeated within a message."
///
/// The consequence of not checking is that downstream code scanning the list
/// for a key takes whichever copy it meets first, so two implementations reading
/// one frame pick opposite values.
#[test]
fn a_repeated_parameter_type_is_refused_unless_it_is_the_authorization_token() {
    // GROUP_ORDER twice: delta 0x22 then delta 0.
    let mut body = vec![0x01, 0x01, 0x02, b'n', b's', 0x01, b't'];
    body.extend_from_slice(&[0x02, 0x22, 0x01, 0x00, 0x02]);
    let repeated = frame(0x03, &body);

    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &repeated[..]);
    assert!(
        matches!(got, Err(CodecError::DuplicateParameter(0x22))),
        "a repeated GROUP_ORDER decoded: {got:?}"
    );

    // AUTHORIZATION_TOKEN (0x03) twice. Each value is a Token structure:
    // Alias Type 0x3 (USE_VALUE), then a Token Type, and no Token Value. The
    // two Token Types differ so the pair is two distinct tokens rather than one
    // sent twice, which is what Section 10.2.2's carve-out permits.
    let mut body = vec![0x01, 0x01, 0x02, b'n', b's', 0x01, b't'];
    body.extend_from_slice(&[0x02, 0x03, 0x02, 0x03, 0x00, 0x00, 0x02, 0x03, 0x01]);
    let allowed = frame(0x03, &body);

    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &allowed[..]);
    assert!(got.is_ok(), "a repeated AUTHORIZATION_TOKEN was refused: {got:?}");
}

// ─────────────────────────────────────────────────────────────
// Sections 9.3.6 / 9.3.10 and 10.2.8 / 10.2.12 — uint8 ranges
// ─────────────────────────────────────────────────────────────

/// FORWARD and GROUP_ORDER are refused outside the values their definitions
/// assign, on drafts 17 and 18 as well as 19.
///
/// "The allowed values are Ascending (0x1) or Descending (0x2). If an endpoint
/// receives a value outside this range, it MUST close the session with
/// PROTOCOL_VIOLATION" (GROUP_ORDER), and the same shape for FORWARD's 0 and 1.
///
/// An application that branches on `== 1` for ascending and `== 2` for
/// descending silently takes neither arm on 7 and falls through to its default,
/// which is the divergence the MUST exists to prevent.
#[test]
fn out_of_range_uint8_parameters_are_refused_on_every_draft_that_defines_them() {
    fn subscribe_with_param_d18(key: u8, value: u8) -> Vec<u8> {
        let mut body = vec![0x01, 0x01, 0x02, b'n', b's', 0x01, b't'];
        body.extend_from_slice(&[0x01, key, value]);
        frame(0x03, &body)
    }
    fn subscribe_with_param_d17(key: u8, value: u8) -> Vec<u8> {
        // draft-17 SUBSCRIBE has required_request_id_delta after request id.
        let mut body = vec![0x01, 0x00, 0x01, 0x02, b'n', b's', 0x01, b't'];
        body.extend_from_slice(&[0x01, key, value]);
        frame(0x03, &body)
    }

    for (key, bad, good) in [(0x22u8, 7u8, 2u8), (0x10u8, 9u8, 1u8)] {
        let d17_bad = subscribe_with_param_d17(key, bad);
        let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &d17_bad[..]);
        assert!(got.is_err(), "draft-17 accepted parameter {key:#x} = {bad}: {got:?}");

        let d17_good = subscribe_with_param_d17(key, good);
        let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &d17_good[..]);
        assert!(got.is_ok(), "draft-17 refused the legal parameter {key:#x} = {good}: {got:?}");

        let d18_bad = subscribe_with_param_d18(key, bad);
        let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &d18_bad[..]);
        assert!(got.is_err(), "draft-18 accepted parameter {key:#x} = {bad}: {got:?}");

        let d18_good = subscribe_with_param_d18(key, good);
        let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &d18_good[..]);
        assert!(got.is_ok(), "draft-18 refused the legal parameter {key:#x} = {good}: {got:?}");

        // Drafts 19 and 20 frame a SUBSCRIBE exactly as draft-18 does, so the
        // same bytes serve all three.
        let got = moqtap_codec::draft19::message::ControlMessage::decode(&mut &d18_bad[..]);
        assert!(got.is_err(), "draft-19 accepted parameter {key:#x} = {bad}: {got:?}");
        let got = moqtap_codec::draft19::message::ControlMessage::decode(&mut &d18_good[..]);
        assert!(got.is_ok(), "draft-19 refused the legal parameter {key:#x} = {good}: {got:?}");

        let got = moqtap_codec::draft20::message::ControlMessage::decode(&mut &d18_bad[..]);
        assert!(got.is_err(), "draft-20 accepted parameter {key:#x} = {bad}: {got:?}");
        let got = moqtap_codec::draft20::message::ControlMessage::decode(&mut &d18_good[..]);
        assert!(got.is_ok(), "draft-20 refused the legal parameter {key:#x} = {good}: {got:?}");
    }

    // Draft-20 adds a third uint8 with a restricted range. Section 10.2.21:
    // "The allowed values are 0 (do not send Properties) or 1 (send
    // Properties), and the default is 1. If an endpoint receives a value
    // outside this range, it MUST close the session with PROTOCOL_VIOLATION."
    for (bad, good) in [(2u8, 0u8), (0xFF, 1)] {
        let wire = subscribe_with_param_d18(0x35, bad);
        let got = moqtap_codec::draft20::message::ControlMessage::decode(&mut &wire[..]);
        assert!(got.is_err(), "draft-20 accepted INCLUDE_PROPERTIES = {bad}: {got:?}");

        let wire = subscribe_with_param_d18(0x35, good);
        let got = moqtap_codec::draft20::message::ControlMessage::decode(&mut &wire[..]);
        assert!(got.is_ok(), "draft-20 refused the legal INCLUDE_PROPERTIES = {good}: {got:?}");
    }
}

/// A uint8 parameter whose value does not fit an octet is refused on encode
/// rather than truncated to its low byte.
///
/// GROUP_ORDER 258 would otherwise go out as the byte 0x02 — a well-formed
/// Descending, indistinguishable on the wire from one the caller meant, and one
/// no receiver could question.
///
/// # Observed with the fix reverted
///
/// Restoring `buf.put_u8(v.into_inner() as u8);` in draft-17's
/// `encode_parameters`:
///
/// ```text
/// ---- an_oversized_uint8_parameter_is_refused_not_truncated stdout ----
///
/// thread 'an_oversized_uint8_parameter_is_refused_not_truncated' (59216) panicked at crates\moqtap-codec\tests\parameter_and_namespace_rules.rs:
/// draft-17 truncated GROUP_ORDER 258 instead of refusing it: Ok(())
/// ```
#[test]
fn an_oversized_uint8_parameter_is_refused_not_truncated() {
    use moqtap_codec::draft17::message as d17;

    let msg = d17::ControlMessage::Subscribe(d17::Subscribe {
        request_id: vi(1),
        required_request_id_delta: vi(0),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        parameters: vec![KeyValuePair { key: vi(0x22), value: KvpValue::Varint(vi(258)) }],
    });
    let mut buf = Vec::new();
    let got = msg.encode(&mut buf);
    assert!(got.is_err(), "draft-17 truncated GROUP_ORDER 258 instead of refusing it: {got:?}");

    use moqtap_codec::draft18::message as d18;
    let msg = d18::ControlMessage::Subscribe(d18::Subscribe {
        request_id: vi(1),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        parameters: vec![KeyValuePair { key: vi(0x22), value: KvpValue::Varint(vi(258)) }],
    });
    let mut buf = Vec::new();
    assert!(msg.encode(&mut buf).is_err(), "draft-18 truncated GROUP_ORDER 258");
}

// ─────────────────────────────────────────────────────────────
// Sections 9.5 / 10.4 and 1.4.4 — GOAWAY URI and reason phrase
// ─────────────────────────────────────────────────────────────

/// A GOAWAY declaring a New Session URI over the maximum is refused on decode,
/// and the maximum itself still decodes.
///
/// Draft-17 Section 9.5 and draft-18 Section 10.4, identical: "The maximum
/// length of the New Session URI is 8,192 bytes. If an endpoint receives a
/// length exceeding the maximum, it MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// Section 3.6 makes a client migrate to this URI, so an unbounded one is handed
/// straight to connection setup. The encoder already refused to write one; only
/// the direction we trust was unbounded.
#[test]
fn an_oversized_goaway_uri_is_refused_and_the_maximum_is_not() {
    fn goaway(uri_len: usize) -> Vec<u8> {
        let mut body = Vec::new();
        // The lengths used here need the four-byte varint form.
        body.extend_from_slice(&vb(uri_len as u64));
        body.extend(std::iter::repeat_n(b'x', uri_len));
        body.push(0x00); // timeout
        frame(0x10, &body)
    }

    let over = goaway(MAX_GOAWAY_URI_LENGTH + 1);
    let at = goaway(MAX_GOAWAY_URI_LENGTH);

    let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &over[..]);
    assert!(matches!(got, Err(CodecError::GoAwayUriTooLong)), "draft-17: {got:?}");
    assert!(moqtap_codec::draft17::message::ControlMessage::decode(&mut &at[..]).is_ok());

    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &over[..]);
    assert!(matches!(got, Err(CodecError::GoAwayUriTooLong)), "draft-18: {got:?}");
    assert!(moqtap_codec::draft18::message::ControlMessage::decode(&mut &at[..]).is_ok());
}

/// A REQUEST_ERROR or PUBLISH_DONE declaring a reason phrase over the maximum is
/// refused on decode, and the maximum itself still decodes.
///
/// Draft-17 Section 1.4.4 and draft-18 Section 1.4.4, identical: "The reason
/// phrase length has a maximum value of 1024 bytes. If an endpoint receives a
/// length exceeding the maximum, it MUST close the session with a
/// PROTOCOL_VIOLATION".
///
/// A reason phrase is diagnostic text implementations log and surface, so an
/// unbounded one is a peer-controlled amplification into whatever consumes it.
#[test]
fn an_oversized_reason_phrase_is_refused_and_the_maximum_is_not() {
    /// REQUEST_ERROR: error code, retry interval, reason length, reason.
    fn request_error(len: usize) -> Vec<u8> {
        let mut body = vec![0x01, 0x00];
        body.extend_from_slice(&vb(len as u64));
        body.extend(std::iter::repeat_n(b'x', len));
        frame(0x05, &body)
    }
    /// PUBLISH_DONE: status code, stream count, reason length, reason.
    fn publish_done(len: usize) -> Vec<u8> {
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&vb(len as u64));
        body.extend(std::iter::repeat_n(b'x', len));
        frame(0x0b, &body)
    }

    for build in [request_error as fn(usize) -> Vec<u8>, publish_done] {
        let over = build(MAX_REASON_PHRASE_LENGTH + 1);
        let at = build(MAX_REASON_PHRASE_LENGTH);

        let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &over[..]);
        assert!(matches!(got, Err(CodecError::ReasonPhraseTooLong)), "draft-17: {got:?}");
        assert!(moqtap_codec::draft17::message::ControlMessage::decode(&mut &at[..]).is_ok());

        let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &over[..]);
        assert!(matches!(got, Err(CodecError::ReasonPhraseTooLong)), "draft-18: {got:?}");
        assert!(moqtap_codec::draft18::message::ControlMessage::decode(&mut &at[..]).is_ok());
    }
}

// ─────────────────────────────────────────────────────────────
// Section 2.4.1 — Track Namespace fields, count and total length
// ─────────────────────────────────────────────────────────────

/// A Track Namespace Field declared with a length of zero is refused, on every
/// draft that reads its namespaces through the draft-17-and-later decoder.
///
/// Drafts 17, 18 and 19, identically: "Each Track Namespace Field Value MUST
/// contain at least one byte. If an endpoint receives a Track Namespace Field
/// with a Track Namespace Field Length of 0, it MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// An empty field is not the same namespace as no field, but the two render
/// identically and an empty field makes two distinct namespaces compare equal
/// under the prefix-matching rules, which is a routing hazard at a relay.
///
/// # Observed with the fix reverted
///
/// Removing the `len == 0` arm from `TrackNamespace::decode_elements_moqt`:
///
/// ```text
/// ---- a_zero_length_namespace_field_is_refused stdout ----
///
/// thread 'a_zero_length_namespace_field_is_refused' (59212) panicked at crates\moqtap-codec\tests\parameter_and_namespace_rules.rs:
/// draft-17 accepted a zero-length namespace field: Ok(Subscribe(Subscribe { request_id: VarInt(1), required_request_id_delta: VarInt(0), track_namespace: TrackNamespace([[]]), track_name: [116], parameters: [] }))
/// ```
#[test]
fn a_zero_length_namespace_field_is_refused() {
    // One field, length 0.
    let d17 = frame(0x03, &[0x01, 0x00, 0x01, 0x00, 0x01, b't', 0x00]);
    let d18 = frame(0x03, &[0x01, 0x01, 0x00, 0x01, b't', 0x00]);

    let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &d17[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-17 accepted a zero-length namespace field: {got:?}"
    );
    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &d18[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-18 accepted a zero-length namespace field: {got:?}"
    );
    let got = moqtap_codec::draft19::message::ControlMessage::decode(&mut &d18[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-19 accepted a zero-length namespace field: {got:?}"
    );
    let got = moqtap_codec::draft20::message::ControlMessage::decode(&mut &d18[..]);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "draft-20 accepted a zero-length namespace field: {got:?}"
    );
}

/// The encoder refuses a namespace its own decoder would refuse.
///
/// Without this the codec emits frames it will not read back, and hands a
/// conforming peer a reason to close the session over a message this client
/// built.
#[test]
fn the_encoder_refuses_a_namespace_the_decoder_would_refuse() {
    use moqtap_codec::draft18::message as d18;

    let msg = d18::ControlMessage::Subscribe(d18::Subscribe {
        request_id: vi(1),
        track_namespace: TrackNamespace(vec![b"live".to_vec(), Vec::new()]),
        track_name: b"t".to_vec(),
        parameters: vec![],
    });
    let mut buf = Vec::new();
    let got = msg.encode(&mut buf);
    assert!(
        matches!(got, Err(CodecError::EmptyNamespaceField)),
        "an empty namespace field was written: {got:?}"
    );
}

/// A Track Namespace of zero fields is accepted, because all three drafts define
/// one that way.
///
/// Drafts 17, 18 and 19: "Track Namespace is an ordered set of between 0 and 32
/// Track Namespace Fields", where the sentence runs on into the field layout.
/// The only field-count violation any of them states is the upper bound.
/// Draft-16 says "between 1 and 32" instead, which is where the old lower
/// bound came from and why the pre-17 decoder still applies it.
///
/// Refusing it was also an encode/decode disagreement: `encode_moqt` writes a
/// zero field count without complaint, so the codec emitted a namespace it would
/// not read.
#[test]
fn a_namespace_of_zero_fields_is_accepted_on_drafts_17_and_later() {
    // draft-18 SUBSCRIBE with a zero-field namespace.
    let wire = frame(0x03, &[0x01, 0x00, 0x01, b't', 0x00]);
    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &wire[..]);
    let msg = match got {
        Ok(m) => m,
        other => panic!("draft-18 refused a zero-field namespace: {other:?}"),
    };
    let mut out = Vec::new();
    msg.encode(&mut out).expect("re-encode");
    assert_eq!(out, wire, "a zero-field namespace did not round-trip");

    // Drafts 07-16 read namespaces through the other decoder, where draft-16
    // Section 2.4.1's "between 1 and 32" still applies.
    let mut empty = &[0x00u8][..];
    assert!(
        TrackNamespace::decode(&mut empty).is_err(),
        "the pre-17 decoder stopped applying draft-16's 1..32 rule"
    );
}

/// A Full Track Name over 4,096 bytes is refused in both directions.
///
/// Drafts 17, 18 and 19, identically: "The maximum total length of a Full Track
/// Name is 4,096 bytes. The length of a Full Track Name is computed as the sum
/// of the Track Namespace Field Length fields and the Track Name Length field...
/// If an endpoint receives a Track Namespace or a Full Track Name exceeding
/// 4,096 bytes, it MUST close the session with a PROTOCOL_VIOLATION."
///
/// The sum matters: a namespace of 4,000 bytes and a name of 500 are each legal
/// alone. A control message may be 65,535 bytes, so unchecked a peer hands the
/// application a name sixteen times the permitted size, and two relays that
/// disagree about whether it was legal disagree about cache identity.
#[test]
fn an_oversized_full_track_name_is_refused_in_both_directions() {
    let ns_len = MAX_FULL_TRACK_NAME_LENGTH - 100;
    let name_len = 200; // sum is 4,096 + 4

    let mut body = vec![0x01, 0x01];
    body.extend_from_slice(&vb(ns_len as u64));
    body.extend(std::iter::repeat_n(b'n', ns_len));
    body.extend_from_slice(&vb(name_len as u64));
    body.extend(std::iter::repeat_n(b't', name_len));
    body.push(0x00);
    let wire = frame(0x03, &body);

    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::TrackNameTooLong)),
        "an oversized full track name decoded: {got:?}"
    );

    use moqtap_codec::draft18::message as d18;
    let msg = d18::ControlMessage::Subscribe(d18::Subscribe {
        request_id: vi(1),
        track_namespace: TrackNamespace(vec![vec![b'n'; ns_len]]),
        track_name: vec![b't'; name_len],
        parameters: vec![],
    });
    let mut out = Vec::new();
    assert!(
        matches!(msg.encode(&mut out), Err(CodecError::TrackNameTooLong)),
        "an oversized full track name was written"
    );

    // The namespace half of the rule is enforced on its own, without a name
    // beside it: PUBLISH_NAMESPACE carries only a namespace.
    let mut body = vec![0x01, 0x01];
    let long = MAX_FULL_TRACK_NAME_LENGTH + 1;
    body.extend_from_slice(&vb(long as u64));
    body.extend(std::iter::repeat_n(b'n', long));
    body.push(0x00);
    let wire = frame(0x06, &body);
    let got = moqtap_codec::draft18::message::ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::TrackNameTooLong)),
        "an oversized namespace decoded on its own: {got:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// Draft-17 Section 9.2 — Required Request ID Delta
// ─────────────────────────────────────────────────────────────

/// A Required Request ID Delta that names a dependency below zero is refused,
/// and the largest legal one is not.
///
/// Draft-17 Section 9.2: "Required Request ID = Request ID - (2 x Required
/// Request ID Delta)... An endpoint MUST close the session with
/// INVALID_REQUIRED_REQUEST_ID if it receives a delta where 2 x Required Request
/// ID Delta exceeds the Request ID."
///
/// Both operands travel in the same message, so this is the one Required Request
/// ID rule the codec can settle with no session state. Left unchecked the
/// subtraction underflows and a consumer computing the dependency gets a wrapped
/// id. Draft-18 removed the field, so this is draft-17 only.
#[test]
fn a_required_request_id_delta_past_its_own_request_id_is_refused() {
    fn subscribe(request_id: u8, delta: u8) -> Vec<u8> {
        frame(0x03, &[request_id, delta, 0x01, 0x02, b'n', b's', 0x01, b't', 0x00])
    }

    // Request ID 4, delta 3: 2 x 3 = 6, past 4.
    let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &subscribe(4, 3)[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidRequiredRequestIdDelta(4, 3))),
        "an out-of-range required request id delta decoded: {got:?}"
    );

    // Request ID 4, delta 2: 2 x 2 = 4, exactly the Request ID, so the
    // dependency is request 0 and the frame is legal.
    let got = moqtap_codec::draft17::message::ControlMessage::decode(&mut &subscribe(4, 2)[..]);
    assert!(got.is_ok(), "the boundary delta was refused: {got:?}");
}

#![cfg(feature = "draft23")]
//! The session close code `Connection::codec_session_error_code` gives each
//! draft-23 decoder refusal, for the corpus's negative vectors.
//!
//! Each row names the corpus vector its bytes come from, and the code is the
//! one draft-23 Section 12.2 defines for the sentence that states the rule.

use moqtap_client::draft23::connection::Connection;
use moqtap_codec::draft23::data_stream::{
    FetchHeader, FetchObjectReader, GroupOrder, SubgroupHeader, SubgroupObjectReader,
};
use moqtap_codec::draft23::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::{Moqt18, VarInt};

const PROTOCOL_VIOLATION: u64 = 0x3;
const MALFORMED_KEY_VALUE: u64 = 0x6;
const MALFORMED_AUTH_TOKEN: u64 = 0x16;
const UNKNOWN_AUTH_TOKEN_ALIAS: u64 = 0x17;
const INVALID_STREAM_HEADER: u64 = 0x200;
const MALFORMED_OBJECT: u64 = 0x201;
const INVALID_OBJECT_STATUS: u64 = 0x202;
const MALFORMED_MESSAGE: u64 = 0x300;
const INVALID_TRACK_NAMESPACE: u64 = 0x302;
const UNEXPECTED_MESSAGE: u64 = 0x303;
const DELTA_ENCODING_OVERFLOW: u64 = 0x400;
const FIELD_LENGTH_EXCEEDED: u64 = 0x401;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn close(err: &CodecError) -> Option<u64> {
    Connection::codec_session_error_code(err).map(|code| code.as_u64())
}

/// A control message framed as type, vi64 Length, body.
fn framed(message_type: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    VarInt::from_u64_moqt(message_type).encode_moqt::<Moqt18>(&mut bytes);
    VarInt::from_usize(body.len()).encode_moqt::<Moqt18>(&mut bytes);
    bytes.extend_from_slice(body);
    bytes
}

fn message_refusal(bytes: &[u8]) -> CodecError {
    ControlMessage::decode(&mut &bytes[..]).expect_err("the vector is a refusal")
}

/// Read a FETCH stream to its first refusal.
fn fetch_refusal(bytes: &[u8]) -> CodecError {
    let mut buf = bytes;
    FetchHeader::decode(&mut buf).expect("the FETCH_HEADER");
    let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
    loop {
        match reader.read_object_header(&mut buf) {
            Ok(entry) => buf = &buf[entry.header.payload_length.into_inner() as usize..],
            Err(err) => return err,
        }
    }
}

#[test]
fn control_message_refusals_close_with_the_code_their_rule_names() {
    let over_limit = vec![0u8; 65_536];
    let mut namespace_33 = vec![0x00, 33];
    for _ in 0..33 {
        namespace_33.extend_from_slice(&[0x01, b'a']);
    }
    namespace_33.extend_from_slice(&[0x01, b'v', 0x00]);

    let rows: Vec<(&str, Vec<u8>, u64)> = vec![
        // Section 9: "An endpoint that receives an unknown message type MUST
        // close the session with UNEXPECTED_MESSAGE."
        ("unknown-type.json fetch-ok-reserved", hex("1804000a0300"), UNEXPECTED_MESSAGE),
        // Section 9: "If an endpoint receives a control message with a length
        // larger than its MAX_CONTROL_MESSAGE_SIZE, it MUST close the session
        // with FIELD_LENGTH_EXCEEDED."
        (
            "setup.json length-over-max-control-message-size",
            framed(0x2F00, &over_limit),
            FIELD_LENGTH_EXCEEDED,
        ),
        // Section 8.9: "The receiver of a message referencing an Alias that is
        // not currently registered MUST reject the message with
        // UNKNOWN_AUTH_TOKEN_ALIAS." A `Connection` is the client.
        ("setup.json with-auth-token-delete", hex("af000403020000"), UNKNOWN_AUTH_TOKEN_ALIAS),
        // Section 2.4.1: "If an endpoint receives a Track Name with a length
        // of 0, it MUST close the session with a PROTOCOL_VIOLATION."
        ("subscribe.json empty-track-name", hex("0306020101610000"), PROTOCOL_VIOLATION),
        (
            "subscribe.json namespace-33-fields",
            framed(0x03, &namespace_33),
            INVALID_TRACK_NAMESPACE,
        ),
        (
            "subscribe.json empty-namespace-field",
            hex("030c010201610005766964656f00"),
            INVALID_TRACK_NAMESPACE,
        ),
        // Section 8.9: "If the Token structure cannot be decoded, including an
        // unknown Alias Type, the receiver MUST close the Session with
        // MALFORMED_AUTH_TOKEN."
        (
            "subscribe.json auth-token-unknown-alias-type",
            hex("03110101046c69766505766964656f01030104"),
            MALFORMED_AUTH_TOKEN,
        ),
        // Section 9.4.2.1: "An endpoint that receives a REQUEST_ERROR with
        // Error Code REDIRECT and no REDIRECT Error Detail MUST close the
        // session with MALFORMED_MESSAGE."
        ("request-error.json redirect-without-detail", hex("0503340000"), MALFORMED_MESSAGE),
        // Section 8.3: a Value that does not match its Type's serialization is
        // MALFORMED_KEY_VALUE.
        (
            "request-error.json redirect-detail-trailing-bytes",
            hex("050c340000010700010161016200"),
            MALFORMED_KEY_VALUE,
        ),
    ];
    for (vector, bytes, code) in rows {
        let err = message_refusal(&bytes);
        assert_eq!(close(&err), Some(code), "{vector}: refused with {err:?}");
    }
}

#[test]
fn data_stream_refusals_close_with_the_code_their_rule_names() {
    // Section 11.4.1: "If an endpoint receives any other value greater than
    // 127, it MUST close the session with MALFORMED_OBJECT."
    let err = fetch_refusal(&hex("05048082"));
    assert_eq!(close(&err), Some(MALFORMED_OBJECT), "invalid-serialization-flags-0x82: {err:?}");

    // Section 11.4.1.1: "If the computed Object ID would be greater than
    // 2^64-1, the Subscriber MUST close the Session with
    // DELTA_ENCODING_OVERFLOW."
    let err = fetch_refusal(&hex("05041c05028001aa808018008001bb"));
    assert_eq!(
        close(&err),
        Some(DELTA_ENCODING_OVERFLOW),
        "end-of-group-then-object-id-overflow: {err:?}"
    );

    // Section 11.3.1: Type values "where bit 4 is not set" are invalid, and
    // the receiver "MUST close the session with INVALID_STREAM_HEADER".
    let err = SubgroupHeader::decode(&mut &hex("200100800004deadbeef")[..])
        .expect_err("subgroup.json bit-4-not-set");
    assert_eq!(close(&err), Some(INVALID_STREAM_HEADER), "bit-4-not-set: {err:?}");

    // Section 11.1.1: "If an endpoint receives any other value, it SHOULD
    // close the session with INVALID_OBJECT_STATUS (Section 12.2)." The
    // `subgroup-single-object` header, then an Object with no payload and
    // status 0x1.
    let bytes = hex("10010080000001");
    let mut buf = &bytes[..];
    let header = SubgroupHeader::decode(&mut buf).expect("the SUBGROUP_HEADER");
    let err = SubgroupObjectReader::new(&header).read_object(&mut buf).expect_err("status 0x1");
    assert_eq!(close(&err), Some(INVALID_OBJECT_STATUS), "status 0x1: {err:?}");
}

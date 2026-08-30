#![cfg(feature = "draft14")]

use moqtap_client::draft14::session::setup::*;
use moqtap_codec::draft14::message::{ClientSetup, ServerSetup};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// Draft-14 Section 9.3: a CLIENT_SETUP offering draft-14 (0xff00000e).
#[test]
fn validate_client_setup_valid() {
    let setup = ClientSetup { supported_versions: vec![varint(0xff00000e)], parameters: vec![] };
    let result = validate_client_setup(&setup);
    assert!(result.is_ok(), "valid client setup should pass: {result:?}");
}

/// Draft-14 Section 9.3.1: a CLIENT_SETUP offering no versions is refused.
#[test]
fn validate_client_setup_no_versions_rejected() {
    let setup = ClientSetup { supported_versions: vec![], parameters: vec![] };
    let result = validate_client_setup(&setup);
    assert!(result.is_err(), "empty version list should be rejected");
    assert_eq!(result.unwrap_err(), SetupError::EmptyVersionList);
}

/// Draft-14 Section 9.3: a SERVER_SETUP selecting draft-14 (0xff00000e).
#[test]
fn validate_server_setup_valid() {
    let setup = ServerSetup { selected_version: varint(0xff00000e), parameters: vec![] };
    let result = validate_server_setup(&setup);
    assert!(result.is_ok(), "valid server setup should pass: {result:?}");
}

/// Draft-14 Section 9.3.1: negotiation succeeds when the server's selected
/// version is one the client offered.
#[test]
fn version_negotiation_common_version_found() {
    let client_versions = vec![varint(0xff00000e)];
    let server_version = varint(0xff00000e);
    let result = negotiate_version(&client_versions, server_version);
    assert!(result.is_ok(), "common version should be found: {result:?}");
    assert_eq!(result.unwrap(), varint(0xff00000e));
}

/// Draft-14 Section 9.3.1: no common version is VERSION_NEGOTIATION_FAILED.
#[test]
fn version_negotiation_no_common_version() {
    // 0xff000010 = draft-16, not offered by client
    let client_versions = vec![varint(0xff00000e)];
    let server_version = varint(0xff000010);
    let result = negotiate_version(&client_versions, server_version);
    assert!(result.is_err(), "no common version should fail");
    assert_eq!(result.unwrap_err(), SetupError::NoCommonVersion);
}

/// Draft-14 Section 9.3.2.3 describes MAX_REQUEST_ID as communicating "an
/// initial value for the Maximum Request ID to the receiving endpoint" and
/// puts no restriction on which endpoint may send it. A client granting the
/// server a request budget during setup is doing exactly what the parameter is
/// for.
///
/// The message is decoded from the corpus rather than built here, because the
/// corpus and the validator disagreed about this exact byte string: the
/// draft-14 `client-setup.json` vector `max-request-id-param` is a canonical
/// CLIENT_SETUP that the client would neither send nor accept.
///
/// Refusing key 0x02 in `validate_client_setup` again fails with:
///
/// ```text
/// a CLIENT_SETUP carrying MAX_REQUEST_ID must be accepted: Err(WrongParameterRole(2))
/// ```
#[test]
fn client_setup_may_carry_max_request_id() {
    // client-setup.json / max-request-id-param: 20000c01c0000000ff00000e010200
    const VECTOR: &[u8] =
        &[0x20, 0x00, 0x0c, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0e, 0x01, 0x02, 0x00];

    let msg = moqtap_codec::draft14::message::ControlMessage::decode(&mut &VECTOR[..])
        .expect("the corpus vector must decode");
    let moqtap_codec::draft14::message::ControlMessage::ClientSetup(setup) = msg else {
        panic!("the vector is a CLIENT_SETUP");
    };
    assert!(
        setup.parameters.iter().any(|p| p.key == varint(0x02)),
        "the vector must still be the one that carries MAX_REQUEST_ID",
    );

    let result = validate_client_setup(&setup);
    assert!(result.is_ok(), "a CLIENT_SETUP carrying MAX_REQUEST_ID must be accepted: {result:?}");
}

/// Draft-14 Section 9.3.2.2 on PATH: "It MUST NOT be used by the server, or
/// when WebTransport is used." This is the parameter whose sender the draft
/// restricts, and the restriction is on the server, so it is a SERVER_SETUP
/// that has to refuse it.
///
/// Dropping the check from `validate_server_setup` fails with:
///
/// ```text
/// assertion `left == right` failed: a SERVER_SETUP carrying PATH must be refused
///   left: Ok(())
///  right: Err(WrongParameterRole(1))
/// ```
#[test]
fn server_setup_may_not_carry_path() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    let setup = ServerSetup {
        selected_version: varint(0xff00000e),
        parameters: vec![KeyValuePair {
            key: varint(0x01),
            value: KvpValue::Bytes(b"/live".to_vec()),
        }],
    };
    let result = validate_server_setup(&setup);
    assert_eq!(
        result,
        Err(SetupError::WrongParameterRole(0x01)),
        "a SERVER_SETUP carrying PATH must be refused",
    );
}

/// The same sentence in Section 9.3.2.2 forbids PATH "when WebTransport is
/// used", which is a fact about the transport rather than about the message,
/// so it is checked where the transport is known.
///
/// Removing the `over_webtransport` arm fails with:
///
/// ```text
/// assertion `left == right` failed: PATH over WebTransport must be refused
///   left: Ok(())
///  right: Err(PathOverWebTransport)
/// ```
#[test]
fn path_is_refused_over_webtransport_and_allowed_over_quic() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    let path = vec![KeyValuePair { key: varint(0x01), value: KvpValue::Bytes(b"/live".to_vec()) }];

    assert_eq!(
        validate_client_path_transport(&path, true),
        Err(SetupError::PathOverWebTransport),
        "PATH over WebTransport must be refused",
    );
    assert_eq!(
        validate_client_path_transport(&path, false),
        Ok(()),
        "PATH over native QUIC is what the parameter is for",
    );
}

/// Draft-14 Section 9.3.1: the version number is 0xff0000XX, XX the draft
/// number, so draft-14 is 0xff00000e.
#[test]
fn version_number_format_draft_14() {
    let draft_14_version: u64 = 0xff00000e;
    // Verify the draft number extraction: low byte should be 14
    assert_eq!(draft_14_version & 0xff, 14);
    // Verify the prefix
    assert_eq!(draft_14_version >> 8, 0xff0000);
}

/// Draft-14 Section 9.3.1: negotiation picks the one offered version that
/// matches the server's selection.
#[test]
fn version_negotiation_multiple_client_versions() {
    let client_versions = vec![varint(0xff00000d), varint(0xff00000e), varint(0xff00000f)];
    let server_version = varint(0xff00000e);
    let result = negotiate_version(&client_versions, server_version);
    assert!(result.is_ok(), "should find common version among multiple: {result:?}");
    assert_eq!(result.unwrap(), varint(0xff00000e));
}

#![cfg(feature = "draft14")]

use moqtap_client::draft14::session::setup::*;
use moqtap_codec::draft14::message::{ClientSetup, ServerSetup};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// draft-14 section 6.1.1: Valid CLIENT_SETUP with draft-14 version (0xff00000e).
#[test]
fn validate_client_setup_valid() {
    let setup = ClientSetup { supported_versions: vec![varint(0xff00000e)], parameters: vec![] };
    let result = validate_client_setup(&setup);
    assert!(result.is_ok(), "valid client setup should pass: {result:?}");
}

/// draft-14 section 6.1.1: CLIENT_SETUP with empty version list is rejected.
#[test]
fn validate_client_setup_no_versions_rejected() {
    let setup = ClientSetup { supported_versions: vec![], parameters: vec![] };
    let result = validate_client_setup(&setup);
    assert!(result.is_err(), "empty version list should be rejected");
    assert_eq!(result.unwrap_err(), SetupError::EmptyVersionList);
}

/// draft-14 section 6.1.2: Valid SERVER_SETUP with draft-14 version (0xff00000e).
#[test]
fn validate_server_setup_valid() {
    let setup = ServerSetup { selected_version: varint(0xff00000e), parameters: vec![] };
    let result = validate_server_setup(&setup);
    assert!(result.is_ok(), "valid server setup should pass: {result:?}");
}

/// draft-14 section 6.1.1/6.1.2: Version negotiation succeeds when server's
/// selected version is in the client's offered list.
#[test]
fn version_negotiation_common_version_found() {
    let client_versions = vec![varint(0xff00000e)];
    let server_version = varint(0xff00000e);
    let result = negotiate_version(&client_versions, server_version);
    assert!(result.is_ok(), "common version should be found: {result:?}");
    assert_eq!(result.unwrap(), varint(0xff00000e));
}

/// draft-14 section 6.1.1/6.1.2: No common version results in
/// VERSION_NEGOTIATION_FAILED (session error 0x15).
#[test]
fn version_negotiation_no_common_version() {
    // 0xff000010 = draft-16, not offered by client
    let client_versions = vec![varint(0xff00000e)];
    let server_version = varint(0xff000010);
    let result = negotiate_version(&client_versions, server_version);
    assert!(result.is_err(), "no common version should fail");
    assert_eq!(result.unwrap_err(), SetupError::NoCommonVersion);
}

/// draft-14 section 6.1.1: CLIENT_SETUP with a server-only parameter is rejected.
#[test]
fn validate_client_setup_server_only_param_rejected() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    // Key 0x02 is a server-only parameter.
    let setup = ClientSetup {
        supported_versions: vec![varint(0xff00000e)],
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(1)) }],
    };
    let result = validate_client_setup(&setup);
    assert!(result.is_err(), "client setup with server-only parameter should be rejected");
    assert_eq!(result.unwrap_err(), SetupError::WrongParameterRole);
}

/// draft-14 section 6.1.1: Version number format is 0xff0000XX where XX = draft number.
/// Draft-14 = 0xff00000e (14 = 0x0e).
#[test]
fn version_number_format_draft_14() {
    let draft_14_version: u64 = 0xff00000e;
    // Verify the draft number extraction: low byte should be 14
    assert_eq!(draft_14_version & 0xff, 14);
    // Verify the prefix
    assert_eq!(draft_14_version >> 8, 0xff0000);
}

/// draft-14 section 6.1.1/6.1.2: Version negotiation with multiple client versions
/// succeeds when one matches the server's selection.
#[test]
fn version_negotiation_multiple_client_versions() {
    let client_versions = vec![varint(0xff00000d), varint(0xff00000e), varint(0xff00000f)];
    let server_version = varint(0xff00000e);
    let result = negotiate_version(&client_versions, server_version);
    assert!(result.is_ok(), "should find common version among multiple: {result:?}");
    assert_eq!(result.unwrap(), varint(0xff00000e));
}

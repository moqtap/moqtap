use moqtap_codec::draft13::message::{ClientSetup, ServerSetup};
use moqtap_codec::varint::VarInt;

/// Errors from setup message validation or version negotiation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SetupError {
    /// Client and server share no supported protocol version.
    #[error("no common version between client and server")]
    NoCommonVersion,
    /// A required setup parameter is missing.
    #[error("missing required parameter: {0}")]
    MissingParameter(
        /// Name of the missing parameter.
        &'static str,
    ),
    /// Client included a parameter reserved for SERVER_SETUP.
    #[error("client sent SERVER_SETUP-only parameter")]
    WrongParameterRole,
    /// The supported versions list is empty.
    #[error("no versions offered")]
    EmptyVersionList,
}

/// Validate a CLIENT_SETUP message.
///
/// Draft-12 places `MAX_REQUEST_ID` (key 0x02) in SERVER_SETUP only;
/// a client that includes it is invalid.
pub fn validate_client_setup(msg: &ClientSetup) -> Result<(), SetupError> {
    if msg.supported_versions.is_empty() {
        return Err(SetupError::EmptyVersionList);
    }
    for param in &msg.parameters {
        if param.key == VarInt::from_u64(0x02).unwrap() {
            return Err(SetupError::WrongParameterRole);
        }
    }
    Ok(())
}

/// Validate a SERVER_SETUP message.
pub fn validate_server_setup(_msg: &ServerSetup) -> Result<(), SetupError> {
    Ok(())
}

/// Negotiate a version from the client's offered list and the server's selected version.
pub fn negotiate_version(
    client_versions: &[VarInt],
    server_version: VarInt,
) -> Result<VarInt, SetupError> {
    if client_versions.contains(&server_version) {
        Ok(server_version)
    } else {
        Err(SetupError::NoCommonVersion)
    }
}

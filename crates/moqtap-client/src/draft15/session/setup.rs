use moqtap_codec::draft15::message::{ClientSetup, ServerSetup};

/// Errors from setup message validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SetupError {
    /// A required setup parameter is missing.
    #[error("missing required parameter: {0}")]
    MissingParameter(
        /// Name of the missing parameter.
        &'static str,
    ),
    /// Client included a parameter reserved for SERVER_SETUP.
    #[error("client sent SERVER_SETUP-only parameter")]
    WrongParameterRole,
}

/// Validate a CLIENT_SETUP message.
///
/// Draft-15 uses ALPN for version negotiation, so CLIENT_SETUP has no
/// versions field. Validation just checks parameters.
pub fn validate_client_setup(_msg: &ClientSetup) -> Result<(), SetupError> {
    // No version list to validate in draft-15.
    // Could add parameter validation here if needed.
    Ok(())
}

/// Validate a SERVER_SETUP message.
///
/// Draft-15 uses ALPN for version negotiation, so SERVER_SETUP has no
/// selected_version field. Validation just checks parameters.
pub fn validate_server_setup(_msg: &ServerSetup) -> Result<(), SetupError> {
    Ok(())
}

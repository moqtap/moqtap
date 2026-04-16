#![allow(missing_docs)]
use moqtap_codec::draft17::message::Setup;

/// Errors from setup message validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("missing required parameter: {0}")]
    MissingParameter(&'static str),
    #[error("setup option rejected")]
    RejectedOption,
}

/// Validate a unified SETUP message. Draft-17 merges CLIENT_SETUP and
/// SERVER_SETUP into a single message and uses ALPN for version negotiation,
/// so there are no versions to validate.
pub fn validate_setup(_msg: &Setup) -> Result<(), SetupError> {
    Ok(())
}

use crate::draft17::session::request_id::Role;
use moqtap_codec::draft17::message::Setup;
use moqtap_codec::varint::VarInt;

/// The PATH setup parameter. It is the one setup parameter whose sender is
/// restricted, and the restriction runs one way: PATH is the client's.
const PATH: u64 = 0x01;

/// Errors from setup message validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SetupError {
    /// A required setup parameter is missing.
    #[error("missing required parameter: {0}")]
    MissingParameter(
        /// Name of the missing parameter.
        &'static str,
    ),
    /// A setup parameter was sent by the endpoint that may not send it.
    #[error("setup option {0:#x} may not be sent by a {1:?}")]
    WrongOptionRole(
        /// Key of the offending parameter.
        u64,
        /// The endpoint that sent it.
        Role,
    ),
    /// A PATH parameter was offered on a session that is not native QUIC.
    #[error("PATH may not be used when WebTransport is used")]
    PathOverWebTransport,
}

/// Validate a unified SETUP message from the endpoint named by `sender`.
///
/// Draft-17 merges the two setup messages into one and uses ALPN for version
/// negotiation, so there are no versions to check and nothing in the message
/// itself says which end sent it. That makes the sender an argument: Section
/// 9.4.1.2 says the PATH parameter "MUST NOT be used by the server", and with
/// one message type for both directions the caller is the only thing that
/// knows which direction this is.
///
/// # Errors
///
/// [`SetupError::WrongOptionRole`] if a server sent a PATH.
pub fn validate_setup(msg: &Setup, sender: Role) -> Result<(), SetupError> {
    if sender == Role::Server && has_path(&msg.options) {
        return Err(SetupError::WrongOptionRole(PATH, sender));
    }
    Ok(())
}

/// Refuse a PATH parameter on a session that is not native QUIC.
///
/// The same sentence in Section 9.4.1.2 forbids PATH "when WebTransport is
/// used". Which transport carries the session is known to the connection and
/// not to the endpoint, so this is a separate call.
///
/// # Errors
///
/// [`SetupError::PathOverWebTransport`] if a PATH is offered over
/// WebTransport.
pub fn validate_client_path_transport(
    options: &[moqtap_codec::kvp::KeyValuePair],
    over_webtransport: bool,
) -> Result<(), SetupError> {
    if over_webtransport && has_path(options) {
        return Err(SetupError::PathOverWebTransport);
    }
    Ok(())
}

fn has_path(options: &[moqtap_codec::kvp::KeyValuePair]) -> bool {
    let path = VarInt::from_u64(PATH).unwrap();
    options.iter().any(|o| o.key == path)
}

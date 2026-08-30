use moqtap_codec::draft16::message::{ClientSetup, ServerSetup};
use moqtap_codec::kvp::KeyValuePair;
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
    #[error("setup parameter {0:#x} may not be sent by this endpoint")]
    WrongParameterRole(
        /// Key of the offending parameter.
        u64,
    ),
    /// A PATH parameter was offered on a session that is not native QUIC.
    #[error("PATH may not be used when WebTransport is used")]
    PathOverWebTransport,
}

/// Validate a CLIENT_SETUP message.
///
/// Section 9.3.1.3 puts no role restriction on MAX_REQUEST_ID: it
/// "communicates an initial value for the Maximum Request ID to the receiving
/// endpoint", which is something either endpoint may do, and a client that
/// grants the server a request budget during setup is doing exactly that. PATH
/// is the restricted parameter, and it belongs to the client, so a
/// CLIENT_SETUP is where it is legal.
pub fn validate_client_setup(_msg: &ClientSetup) -> Result<(), SetupError> {
    Ok(())
}

/// Validate a SERVER_SETUP message.
///
/// Section 9.3.1.2 on PATH: "It MUST NOT be used by the server, or when
/// WebTransport is used", and a PATH received from the server closes the
/// session with INVALID_PATH. Nothing else in a SERVER_SETUP is restricted by
/// sender.
///
/// # Errors
///
/// [`SetupError::WrongParameterRole`] if the server sent a PATH.
pub fn validate_server_setup(msg: &ServerSetup) -> Result<(), SetupError> {
    if has_path(&msg.parameters) {
        return Err(SetupError::WrongParameterRole(PATH));
    }
    Ok(())
}

/// Refuse a PATH parameter on a session that is not native QUIC.
///
/// The same sentence in Section 9.3.1.2 forbids PATH "when WebTransport is
/// used" and closes the session with INVALID_PATH on one received there. Which
/// transport carries the session is known to the connection and not to the
/// endpoint, so this is a separate call rather than part of
/// `validate_client_setup`.
///
/// # Errors
///
/// [`SetupError::PathOverWebTransport`] if a PATH is offered over
/// WebTransport.
pub fn validate_client_path_transport(
    parameters: &[KeyValuePair],
    over_webtransport: bool,
) -> Result<(), SetupError> {
    if over_webtransport && has_path(parameters) {
        return Err(SetupError::PathOverWebTransport);
    }
    Ok(())
}

fn has_path(parameters: &[KeyValuePair]) -> bool {
    let path = VarInt::from_u64(PATH).unwrap();
    parameters.iter().any(|p| p.key == path)
}

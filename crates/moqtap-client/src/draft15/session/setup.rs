use moqtap_codec::draft15::error_codes::SessionErrorCode;
use moqtap_codec::draft15::message::{ClientSetup, ServerSetup};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::varint::VarInt;

/// The PATH setup parameter. PATH and AUTHORITY are the setup parameters whose
/// sender is restricted, and the restriction runs one way: both are the
/// client's.
const PATH: u64 = 0x01;

/// The AUTHORITY setup parameter.
const AUTHORITY: u64 = 0x05;

/// Errors from setup message validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
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
    /// An AUTHORITY parameter was offered on a session that is not native QUIC.
    #[error("AUTHORITY may not be used when WebTransport is used")]
    AuthorityOverWebTransport,
}

impl SetupError {
    /// The code a client closes the session with when it refuses the server's
    /// SETUP for this error: INVALID_PATH for a PATH (Section 9.3.1.2) and
    /// INVALID_AUTHORITY for an AUTHORITY (Section 9.3.1.1).
    pub(crate) fn close_code(&self) -> Option<SessionErrorCode> {
        match self {
            SetupError::WrongParameterRole(PATH) => Some(SessionErrorCode::InvalidPath),
            SetupError::WrongParameterRole(AUTHORITY) => Some(SessionErrorCode::InvalidAuthority),
            _ => None,
        }
    }
}

/// Validate a CLIENT_SETUP message.
///
/// Section 9.3.1.3 puts no role restriction on MAX_REQUEST_ID: it
/// "communicates an initial value for the Maximum Request ID to the receiving
/// endpoint", which is something either endpoint may do, and a client that
/// grants the server a request budget during setup is doing exactly that. PATH
/// and AUTHORITY are the restricted parameters, and they belong to the client,
/// so a CLIENT_SETUP is where they are legal.
pub fn validate_client_setup(_msg: &ClientSetup) -> Result<(), SetupError> {
    Ok(())
}

/// Validate a SERVER_SETUP message.
///
/// Section 9.3.1.2 on PATH: "It MUST NOT be used by the server, or when
/// WebTransport is used", and a PATH received from the server closes the
/// session with INVALID_PATH. Section 9.3.1.1 says the same of AUTHORITY, and
/// an AUTHORITY from the server closes the session with INVALID_AUTHORITY.
/// Nothing else in a SERVER_SETUP is restricted by sender.
///
/// # Errors
///
/// [`SetupError::WrongParameterRole`] if the server sent a PATH or an
/// AUTHORITY.
pub fn validate_server_setup(msg: &ServerSetup) -> Result<(), SetupError> {
    for key in [PATH, AUTHORITY] {
        if has_parameter(&msg.parameters, key) {
            return Err(SetupError::WrongParameterRole(key));
        }
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
    if over_webtransport && has_parameter(parameters, PATH) {
        return Err(SetupError::PathOverWebTransport);
    }
    Ok(())
}

/// Refuse an AUTHORITY parameter on a session that is not native QUIC.
///
/// Section 9.3.1.1 forbids AUTHORITY "when WebTransport is used" and closes
/// the session with INVALID_AUTHORITY on one received there.
///
/// # Errors
///
/// [`SetupError::AuthorityOverWebTransport`] if an AUTHORITY is offered over
/// WebTransport.
pub fn validate_client_authority_transport(
    parameters: &[KeyValuePair],
    over_webtransport: bool,
) -> Result<(), SetupError> {
    if over_webtransport && has_parameter(parameters, AUTHORITY) {
        return Err(SetupError::AuthorityOverWebTransport);
    }
    Ok(())
}

fn has_parameter(parameters: &[KeyValuePair], key: u64) -> bool {
    let key = VarInt::from_u64(key).unwrap();
    parameters.iter().any(|p| p.key == key)
}

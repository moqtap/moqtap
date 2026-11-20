use moqtap_codec::draft14::error_codes::SessionErrorCode;
use moqtap_codec::draft14::message::{ClientSetup, ServerSetup};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::varint::VarInt;

/// The PATH setup parameter. PATH and AUTHORITY are the setup parameters whose
/// sender is restricted, and the restriction runs one way: both are the
/// client's.
const PATH: u64 = 0x01;

/// The AUTHORITY setup parameter.
const AUTHORITY: u64 = 0x05;

/// Errors from setup message validation or version negotiation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The supported versions list is empty.
    #[error("no versions offered")]
    EmptyVersionList,
}

impl SetupError {
    /// The code a client closes the session with when it refuses the server's
    /// SETUP for this error: INVALID_PATH for a PATH (Section 9.3.2.2).
    pub(crate) fn close_code(&self) -> Option<SessionErrorCode> {
        match self {
            SetupError::WrongParameterRole(PATH) => Some(SessionErrorCode::InvalidPath),
            _ => None,
        }
    }
}

/// Validate a CLIENT_SETUP message.
///
/// Section 9.3.2.3 puts no role restriction on MAX_REQUEST_ID: it
/// "communicates an initial value for the Maximum Request ID to the receiving
/// endpoint", which is something either endpoint may do, and a client that
/// grants the server a request budget during setup is doing exactly that. PATH
/// and AUTHORITY are the restricted parameters, and they belong to the client,
/// so a CLIENT_SETUP is where they are legal.
pub fn validate_client_setup(msg: &ClientSetup) -> Result<(), SetupError> {
    if msg.supported_versions.is_empty() {
        return Err(SetupError::EmptyVersionList);
    }
    Ok(())
}

/// Validate a SERVER_SETUP message.
///
/// Section 9.3.2.2 on PATH: "It MUST NOT be used by the server, or when
/// WebTransport is used", and a PATH received from the server closes the
/// session with Invalid Path.
///
/// Section 9.3.2.1 says the same of AUTHORITY (Parameter Type 0x05), but a
/// server's 0x05 is not refused here: draft-14 Section 9.3.2.6 also assigns
/// 0x05 to MOQT_IMPLEMENTATION, which "identifies the name and version of the
/// sender's MOQT implementation" and is not restricted by sender, so a 0x05
/// from the server may be either parameter.
///
/// # Errors
///
/// [`SetupError::WrongParameterRole`] if the server sent a PATH.
pub fn validate_server_setup(msg: &ServerSetup) -> Result<(), SetupError> {
    if has_parameter(&msg.parameters, PATH) {
        return Err(SetupError::WrongParameterRole(PATH));
    }
    Ok(())
}

/// Refuse a PATH parameter on a session that is not native QUIC.
///
/// The same sentence in Section 9.3.2.2 forbids PATH "when WebTransport is
/// used" and closes the session with Invalid Path on one received there. Which
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
/// Section 9.3.2.1 forbids AUTHORITY "when WebTransport is used" and closes
/// the session with Invalid Authority on one received there. Every 0x05 is
/// refused over WebTransport, including one meant as MOQT_IMPLEMENTATION
/// (draft-14 Section 9.3.2.6, the same Parameter Type), because the server
/// cannot tell the two apart.
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

/// Negotiate a version from the client's offered list and the server's
/// selected version.
///
/// # Errors
///
/// [`SetupError::NoCommonVersion`] if the server selected a version the
/// client did not offer.
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

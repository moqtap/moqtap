use crate::draft19::session::request_id::Role;
use moqtap_codec::draft19::error_codes::SessionErrorCode;
use moqtap_codec::draft19::message::Setup;
use moqtap_codec::varint::VarInt;

/// The PATH setup option. PATH and AUTHORITY are the setup options whose
/// sender is restricted, and the restriction runs one way: both are the
/// client's.
const PATH: u64 = 0x01;

/// The AUTHORITY setup option.
const AUTHORITY: u64 = 0x05;

/// Errors from setup message validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupError {
    /// A required setup option is missing.
    #[error("missing required parameter: {0}")]
    MissingParameter(
        /// Name of the missing option.
        &'static str,
    ),
    /// A setup option was sent by the endpoint that may not send it.
    #[error("setup option {0:#x} may not be sent by a {1:?}")]
    WrongOptionRole(
        /// Key of the offending option.
        u64,
        /// The endpoint that sent it.
        Role,
    ),
    /// A PATH option was offered on a session that is not native QUIC.
    #[error("PATH may not be used when WebTransport is used")]
    PathOverWebTransport,
    /// An AUTHORITY option was offered on a session that is not native QUIC.
    #[error("AUTHORITY may not be used when WebTransport is used")]
    AuthorityOverWebTransport,
}

impl SetupError {
    /// The code a client closes the session with when it refuses the server's
    /// SETUP for this error: INVALID_PATH for a PATH (Section 10.3.1.2) and
    /// INVALID_AUTHORITY for an AUTHORITY (Section 10.3.1.1).
    pub(crate) fn close_code(&self) -> Option<SessionErrorCode> {
        match self {
            SetupError::WrongOptionRole(PATH, Role::Server) => Some(SessionErrorCode::InvalidPath),
            SetupError::WrongOptionRole(AUTHORITY, Role::Server) => {
                Some(SessionErrorCode::InvalidAuthority)
            }
            _ => None,
        }
    }
}

/// Validate a unified SETUP message from the endpoint named by `sender`.
///
/// Draft-19 merges the two setup messages into one and uses ALPN for version
/// negotiation, so there are no versions to check and nothing in the message
/// itself says which end sent it. That makes the sender an argument:
/// Section 10.3.1.2 says the PATH option "MUST NOT be used by the server",
/// Section 10.3.1.1 says the same of AUTHORITY, and with one message type for
/// both directions the caller is the only thing that knows which direction
/// this is.
///
/// # Errors
///
/// [`SetupError::WrongOptionRole`] if a server sent a PATH or an AUTHORITY.
pub fn validate_setup(msg: &Setup, sender: Role) -> Result<(), SetupError> {
    if sender == Role::Server {
        for key in [PATH, AUTHORITY] {
            if has_option(&msg.options, key) {
                return Err(SetupError::WrongOptionRole(key, sender));
            }
        }
    }
    Ok(())
}

/// Refuse a PATH option on a session that is not native QUIC.
///
/// The same sentence in Section 10.3.1.2 forbids PATH "when WebTransport is
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
    if over_webtransport && has_option(options, PATH) {
        return Err(SetupError::PathOverWebTransport);
    }
    Ok(())
}

/// Refuse an AUTHORITY option on a session that is not native QUIC.
///
/// Section 10.3.1.1 forbids AUTHORITY "when WebTransport is used", in the
/// sentence that forbids it to the server.
///
/// # Errors
///
/// [`SetupError::AuthorityOverWebTransport`] if an AUTHORITY is offered over
/// WebTransport.
pub fn validate_client_authority_transport(
    options: &[moqtap_codec::kvp::KeyValuePair],
    over_webtransport: bool,
) -> Result<(), SetupError> {
    if over_webtransport && has_option(options, AUTHORITY) {
        return Err(SetupError::AuthorityOverWebTransport);
    }
    Ok(())
}

fn has_option(options: &[moqtap_codec::kvp::KeyValuePair], key: u64) -> bool {
    let key = VarInt::from_u64(key).unwrap();
    options.iter().any(|o| o.key == key)
}

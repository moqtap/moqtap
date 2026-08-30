use moqtap_codec::draft07::message::{ClientSetup, ServerSetup};
use moqtap_codec::draft07::types::Role;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

/// The PATH setup parameter. It is the one setup parameter whose sender this
/// draft restricts, and the restriction runs one way: PATH is the client's.
const PATH: u64 = 0x01;

/// The version number this module speaks, and the only one it can.
///
/// Version numbers for IETF drafts are the draft number added to 0xff000000.
const DRAFT_VERSION: u64 = 0xff000007;

/// The ROLE setup parameter, which this draft requires of both endpoints and
/// which draft-08 removes.
const ROLE: u64 = 0x00;

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
    /// A setup parameter was sent by the endpoint that may not send it.
    #[error("setup parameter {0:#x} may not be sent by this endpoint")]
    WrongParameterRole(
        /// Key of the offending parameter.
        u64,
    ),
    /// A PATH parameter was offered on a session that is not native QUIC.
    #[error("PATH may not be used when WebTransport is used")]
    PathOverWebTransport,
    /// The supported versions list is empty.
    #[error("no versions offered")]
    EmptyVersionList,
    /// The selected version is not the one this module implements.
    #[error("selected version {0:#x} is not this draft's")]
    WrongDraftVersion(
        /// The version the server selected.
        u64,
    ),
    /// The ROLE parameter is absent or carries a value the draft does not
    /// assign.
    #[error("ROLE must be one of the three values this draft assigns")]
    InvalidRole,
}

/// Read a varint out of a setup parameter value, whichever shape it arrived in.
///
/// This draft frames every setup parameter as {Type, Length, Value}, and the
/// decoder has no per-key table telling it which values are numbers, so a
/// parameter that came off the wire always arrives as bytes. A caller that
/// matches on [`KvpValue::Varint`] alone therefore never sees anything a peer
/// sent - only something this process built itself. Both shapes are read here,
/// and a value with bytes left over after the varint is refused rather than
/// truncated.
pub fn setup_varint(value: &KvpValue) -> Option<u64> {
    match value {
        KvpValue::Varint(v) => Some(v.into_inner()),
        KvpValue::Bytes(bytes) => {
            let mut cursor = &bytes[..];
            let parsed = VarInt::decode(&mut cursor).ok()?;
            cursor.is_empty().then(|| parsed.into_inner())
        }
    }
}

/// Validate a CLIENT_SETUP message.
///
/// Section 6.2.2.3 puts no role restriction on MAX_SUBSCRIBE_ID: it
/// "communicates an initial value for the Maximum Subscribe ID to the receiving
/// subscriber", which is something either endpoint may do, and a client that
/// grants the server a subscribe budget during setup is doing exactly that.
/// PATH is the restricted parameter, and it belongs to the client, so a
/// CLIENT_SETUP is where it is legal.
///
/// ROLE is a different matter: Section 6.2.2.1 requires it of both
/// endpoints, so its absence is refused here rather than defaulted.
///
/// # Errors
///
/// [`SetupError::EmptyVersionList`] if no version is offered.
///
/// [`SetupError::MissingParameter`] if no ROLE is present, and
/// [`SetupError::InvalidRole`] if its value is not one the draft assigns.
pub fn validate_client_setup(msg: &ClientSetup) -> Result<(), SetupError> {
    if msg.supported_versions.is_empty() {
        return Err(SetupError::EmptyVersionList);
    }
    check_role(&msg.parameters)?;
    Ok(())
}

/// Validate a SERVER_SETUP message.
///
/// Section 6.2.2.2 on PATH: "It MUST NOT be used by the server, or when
/// WebTransport is used. If the peer receives a PATH parameter from the server,
/// or when WebTransport is used, it MUST close the connection." Nothing else in
/// a SERVER_SETUP is restricted by sender.
///
/// ROLE is required of the server too, by the same sentence in
/// Section 6.2.2.1 that requires it of the client.
///
/// # Errors
///
/// [`SetupError::WrongParameterRole`] if the server sent a PATH.
///
/// [`SetupError::MissingParameter`] if no ROLE is present, and
/// [`SetupError::InvalidRole`] if its value is not one the draft assigns.
pub fn validate_server_setup(msg: &ServerSetup) -> Result<(), SetupError> {
    if has_path(&msg.parameters) {
        return Err(SetupError::WrongParameterRole(PATH));
    }
    check_role(&msg.parameters)?;
    Ok(())
}

/// Refuse a PATH parameter on a session that is not native QUIC.
///
/// The same sentence in Section 6.2.2.2 forbids PATH "when WebTransport is
/// used" and closes the connection on one seen there. Which transport carries
/// the session is known to the connection and not to the endpoint, so this is a
/// separate call rather than part of [`validate_client_setup`].
///
/// # Errors
///
/// [`SetupError::PathOverWebTransport`] if a PATH is offered over WebTransport.
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

/// Hold a setup message to the ROLE rule.
///
/// Section 6.2.2.1: "Both endpoints MUST send a ROLE parameter with one of the
/// three values specified above. Both endpoints MUST close the session if the
/// ROLE parameter is missing or is not one of the three above-specified
/// values." The three values are the ones [`Role`] names, and this is the only
/// draft that states the rule at all - draft-08 removed the parameter, so no
/// later draft has a ROLE to check.
fn check_role(parameters: &[KeyValuePair]) -> Result<(), SetupError> {
    let key = VarInt::from_u64(ROLE).unwrap();
    let param =
        parameters.iter().find(|p| p.key == key).ok_or(SetupError::MissingParameter("ROLE"))?;
    let value = setup_varint(&param.value).ok_or(SetupError::InvalidRole)?;
    match u8::try_from(value).ok().and_then(Role::from_u8) {
        Some(_) => Ok(()),
        None => Err(SetupError::InvalidRole),
    }
}

/// Negotiate a version from the client's offered list and the server's selected
/// version.
///
/// A client may offer other drafts' versions beside this one, but this module
/// encodes exactly one draft: a session that settled on another version would
/// have every frame after the handshake written in the wrong format, and the
/// first symptom would be the peer closing it. So a selected version that is
/// not this draft's is refused here rather than carried.
///
/// # Errors
///
/// [`SetupError::WrongDraftVersion`] if the server selected a version this
/// module does not implement, and [`SetupError::NoCommonVersion`] if it
/// selected one the client did not offer.
pub fn negotiate_version(
    client_versions: &[VarInt],
    server_version: VarInt,
) -> Result<VarInt, SetupError> {
    if server_version.into_inner() != DRAFT_VERSION {
        return Err(SetupError::WrongDraftVersion(server_version.into_inner()));
    }
    if client_versions.contains(&server_version) {
        Ok(server_version)
    } else {
        Err(SetupError::NoCommonVersion)
    }
}

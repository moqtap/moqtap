/// Session termination error codes (draft-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SessionErrorCode {
    /// No error occurred.
    NoError = 0x0,
    /// Implementation-specific internal error.
    InternalError = 0x1,
    /// Authorization failed.
    Unauthorized = 0x2,
    /// Protocol rule violation detected.
    ProtocolViolation = 0x3,
    /// Request ID is invalid or unknown.
    InvalidRequestId = 0x4,
    /// Track alias already in use.
    DuplicateTrackAlias = 0x5,
    /// Key-value pair formatting error.
    KeyValueFormattingError = 0x6,
    /// Too many concurrent requests.
    TooManyRequests = 0x7,
    /// Requested path is invalid.
    InvalidPath = 0x8,
    /// Requested path is malformed.
    MalformedPath = 0x9,
    /// GOAWAY timeout elapsed.
    GoawayTimeout = 0x10,
    /// Control message timeout elapsed.
    ControlMessageTimeout = 0x11,
    /// Data stream timeout elapsed.
    DataStreamTimeout = 0x12,
    /// Auth token cache capacity exceeded.
    AuthTokenCacheOverflow = 0x13,
    /// Auth token alias already registered.
    DuplicateAuthTokenAlias = 0x14,
    /// No compatible version found during negotiation.
    VersionNegotiationFailed = 0x15,
    /// Auth token is malformed.
    MalformedAuthToken = 0x16,
    /// Auth token alias is not recognized.
    UnknownAuthTokenAlias = 0x17,
    /// Auth token has expired.
    ExpiredAuthToken = 0x18,
    /// Authority value is invalid.
    InvalidAuthority = 0x19,
    /// Authority value is malformed.
    MalformedAuthority = 0x1A,
}

/// Request-level error codes (used in SUBSCRIBE_ERROR, PUBLISH_ERROR, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RequestErrorCode {
    /// Implementation-specific internal error.
    InternalError = 0x0,
    /// Authorization failed for this request.
    Unauthorized = 0x1,
    /// Request timed out.
    Timeout = 0x2,
    /// Requested operation is not supported.
    NotSupported = 0x3,
    /// The requested track does not exist.
    TrackDoesNotExist = 0x4,
    /// The requested range is invalid.
    InvalidRange = 0x5,
    /// Auth token is malformed.
    MalformedAuthToken = 0x10,
    /// Auth token has expired.
    ExpiredAuthToken = 0x12,
}

/// PUBLISH_DONE status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PublishDoneStatusCode {
    /// Publishing completed normally.
    Normal = 0x0,
    /// Subscriber unsubscribed.
    Unsubscribed = 0x1,
    /// Internal error during publishing.
    InternalError = 0x2,
    /// Authorization failed.
    Unauthorized = 0x3,
    /// Operation not supported.
    Unsupported = 0x4,
    /// Track not found.
    NotFound = 0x5,
}

impl SessionErrorCode {
    /// Convert a raw u64 to a `SessionErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(SessionErrorCode::NoError),
            0x1 => Some(SessionErrorCode::InternalError),
            0x2 => Some(SessionErrorCode::Unauthorized),
            0x3 => Some(SessionErrorCode::ProtocolViolation),
            0x4 => Some(SessionErrorCode::InvalidRequestId),
            0x5 => Some(SessionErrorCode::DuplicateTrackAlias),
            0x6 => Some(SessionErrorCode::KeyValueFormattingError),
            0x7 => Some(SessionErrorCode::TooManyRequests),
            0x8 => Some(SessionErrorCode::InvalidPath),
            0x9 => Some(SessionErrorCode::MalformedPath),
            0x10 => Some(SessionErrorCode::GoawayTimeout),
            0x11 => Some(SessionErrorCode::ControlMessageTimeout),
            0x12 => Some(SessionErrorCode::DataStreamTimeout),
            0x13 => Some(SessionErrorCode::AuthTokenCacheOverflow),
            0x14 => Some(SessionErrorCode::DuplicateAuthTokenAlias),
            0x15 => Some(SessionErrorCode::VersionNegotiationFailed),
            0x16 => Some(SessionErrorCode::MalformedAuthToken),
            0x17 => Some(SessionErrorCode::UnknownAuthTokenAlias),
            0x18 => Some(SessionErrorCode::ExpiredAuthToken),
            0x19 => Some(SessionErrorCode::InvalidAuthority),
            0x1A => Some(SessionErrorCode::MalformedAuthority),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl RequestErrorCode {
    /// Convert a raw u64 to a `RequestErrorCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(RequestErrorCode::InternalError),
            0x1 => Some(RequestErrorCode::Unauthorized),
            0x2 => Some(RequestErrorCode::Timeout),
            0x3 => Some(RequestErrorCode::NotSupported),
            0x4 => Some(RequestErrorCode::TrackDoesNotExist),
            0x5 => Some(RequestErrorCode::InvalidRange),
            0x10 => Some(RequestErrorCode::MalformedAuthToken),
            0x12 => Some(RequestErrorCode::ExpiredAuthToken),
            _ => None,
        }
    }

    /// Return the raw u64 value of this error code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

impl PublishDoneStatusCode {
    /// Convert a raw u64 to a `PublishDoneStatusCode`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(PublishDoneStatusCode::Normal),
            0x1 => Some(PublishDoneStatusCode::Unsubscribed),
            0x2 => Some(PublishDoneStatusCode::InternalError),
            0x3 => Some(PublishDoneStatusCode::Unauthorized),
            0x4 => Some(PublishDoneStatusCode::Unsupported),
            0x5 => Some(PublishDoneStatusCode::NotFound),
            _ => None,
        }
    }

    /// Return the raw u64 value of this status code.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

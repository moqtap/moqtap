/// Maximum control message payload length: 2^16 - 1 bytes.
pub const MAX_MESSAGE_LENGTH: usize = 65535;
/// Maximum reason phrase length: 1024 bytes.
pub const MAX_REASON_PHRASE_LENGTH: usize = 1024;
/// Maximum GOAWAY new session URI length: 8192 bytes.
pub const MAX_GOAWAY_URI_LENGTH: usize = 8192;
/// Maximum full track name length: 4096 bytes.
pub const MAX_FULL_TRACK_NAME_LENGTH: usize = 4096;
/// Maximum track namespace tuple size: 32 elements.
pub const MAX_NAMESPACE_TUPLE_SIZE: usize = 32;

/// Errors produced during MoQT message encoding and decoding.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CodecError {
    /// Unknown or unsupported message type identifier.
    #[error("unknown message type: 0x{0:x}")]
    UnknownMessageType(u64),
    /// Not enough bytes in the buffer to complete decoding.
    #[error("insufficient bytes")]
    UnexpectedEnd,
    /// Control message payload exceeds [`MAX_MESSAGE_LENGTH`].
    #[error("message too long: {0} bytes (max {MAX_MESSAGE_LENGTH})")]
    MessageTooLong(usize),
    /// Variable-length integer encoding/decoding error.
    #[error("varint error: {0}")]
    VarInt(#[from] crate::varint::VarIntError),
    /// Key-value pair encoding/decoding error.
    #[error("kvp error: {0}")]
    Kvp(#[from] crate::kvp::KvpError),
    /// A decoded field value is not valid for its type.
    #[error("invalid field value")]
    InvalidField,
    /// Namespace tuple element count is outside the 1..=32 range.
    #[error("namespace tuple must have 1-{MAX_NAMESPACE_TUPLE_SIZE} elements, got {0}")]
    InvalidNamespaceTupleSize(usize),
    /// Full track name exceeds [`MAX_FULL_TRACK_NAME_LENGTH`].
    #[error("full track name exceeds {MAX_FULL_TRACK_NAME_LENGTH} bytes")]
    TrackNameTooLong,
    /// Reason phrase exceeds [`MAX_REASON_PHRASE_LENGTH`].
    #[error("reason phrase exceeds {MAX_REASON_PHRASE_LENGTH} bytes")]
    ReasonPhraseTooLong,
    /// GOAWAY URI exceeds [`MAX_GOAWAY_URI_LENGTH`].
    #[error("GOAWAY URI exceeds {MAX_GOAWAY_URI_LENGTH} bytes")]
    GoAwayUriTooLong,
    /// Draft not implemented or not enabled via feature flag.
    #[error("unsupported draft: {0}")]
    UnsupportedDraft(String),
}

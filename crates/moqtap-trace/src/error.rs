/// Errors that can occur when reading or writing `.moqtrace` files.
#[derive(Debug, thiserror::Error)]
pub enum MoqTraceError {
    /// I/O error from the underlying reader or writer.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// CBOR encoding error.
    #[error("cbor encode error: {0}")]
    CborEncode(String),
    /// CBOR decoding error.
    #[error("cbor decode error: {0}")]
    CborDecode(String),
    /// File does not start with the expected `MOQTRACE` magic bytes.
    #[error("invalid magic bytes")]
    InvalidMagic,
    /// File declares a format version this library does not support.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    /// Header is missing required fields or contains invalid values.
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    /// Event has an unknown type or is missing required fields.
    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

impl<T: std::fmt::Debug> From<ciborium::ser::Error<T>> for MoqTraceError {
    fn from(e: ciborium::ser::Error<T>) -> Self {
        MoqTraceError::CborEncode(format!("{e:?}"))
    }
}

impl<T: std::fmt::Debug> From<ciborium::de::Error<T>> for MoqTraceError {
    fn from(e: ciborium::de::Error<T>) -> Self {
        MoqTraceError::CborDecode(format!("{e:?}"))
    }
}

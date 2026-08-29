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
    /// File declares a format version this library cannot read.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    /// Header is missing required fields or contains invalid values.
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    /// Event has an unknown type or is missing required fields.
    #[error("invalid event: {0}")]
    InvalidEvent(String),
    /// The stream ended part-way through an item — the file was truncated by
    /// a crashed recorder or an interrupted transfer.
    ///
    /// Everything decoded before `offset` is valid and should be kept. Callers
    /// holding a seekable or resumable source can look for the next segment
    /// with [`resync_to_next_segment`](crate::reader::MoqTraceReader::resync_to_next_segment).
    #[error("trace truncated: the item starting at byte offset {offset} is incomplete")]
    Truncated {
        /// Byte offset, counted from the start of the stream handed to the
        /// reader, at which the incomplete item begins.
        offset: u64,
    },
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

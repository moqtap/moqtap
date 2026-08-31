//! Data stream classification shared by the forwarding paths.
//!
//! Object-level parsing lives in [`crate::framer`], which frames a whole
//! stream — header and objects — on every draft 07-19 while preserving the
//! exact wire bytes. This module keeps only what classifying a stream
//! needs before the framer is built.

pub use crate::types::DataStreamType;

/// Check if a codec error indicates incomplete data (need more bytes).
pub(crate) fn is_incomplete_error(e: &moqtap_codec::error::CodecError) -> bool {
    matches!(e, moqtap_codec::error::CodecError::UnexpectedEnd)
        || matches!(
            e,
            moqtap_codec::error::CodecError::VarInt(
                moqtap_codec::varint::VarIntError::UnexpectedEnd
            )
        )
}

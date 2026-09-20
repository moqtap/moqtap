//! Data stream classification shared by the forwarding paths.
//!
//! Object-level parsing lives in [`crate::framer`], which frames a whole
//! stream — header and objects — on every draft 07-19 while preserving the
//! exact wire bytes. This module keeps only what classifying a stream
//! needs before the framer is built.

pub use crate::types::DataStreamType;

/// Check if a codec error indicates incomplete data (need more bytes).
///
/// The list of spellings this admits lives on the error rather than here. It
/// was written out twice — once here and once in `moqtap-client`'s framed
/// readers — and the two copies disagreed: this one admitted a truncated
/// varint and that one did not, so an object still arriving read as a
/// malformed stream on every draft. One answer, in the crate that defines the
/// error.
pub(crate) fn is_incomplete_error(e: &moqtap_codec::error::CodecError) -> bool {
    e.is_incomplete()
}

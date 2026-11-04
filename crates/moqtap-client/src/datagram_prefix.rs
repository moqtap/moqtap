//! The fields of a received datagram up to its Extension Headers Length.
//!
//! On drafts 11 through 16 the codec's datagram header decoder refuses an
//! announced extension block with a length of 0 as a bare `InvalidField`,
//! which it also returns for other faults. Each draft's `recv_datagram` reads
//! the prefix again here, after that refusal, to tell whether the empty block
//! was the fault, since the drafts answer it with a session close.

use moqtap_codec::varint::VarInt;

/// Which fields a datagram Type puts before its Extension Headers Length.
pub(crate) struct Prefix {
    /// An Object ID field is present; absent, the Object ID is 0.
    pub object_id: bool,
    /// A Publisher Priority byte is present.
    pub priority: bool,
}

/// The Object ID of a datagram whose Type announces an extension block and
/// whose Extension Headers Length is 0, or `None` for any other datagram.
///
/// `prefix` answers, for the Type's value and its encoded width in bytes, the
/// fields before the length when the Type announces a block the draft's rule
/// covers, and `None` for every other Type.
pub(crate) fn empty_extension_block(
    data: &[u8],
    prefix: impl Fn(u64, usize) -> Option<Prefix>,
) -> Option<u64> {
    let mut cursor = data;
    let datagram_type = VarInt::decode(&mut cursor).ok()?.into_inner();
    let layout = prefix(datagram_type, data.len() - cursor.len())?;
    VarInt::decode(&mut cursor).ok()?;
    VarInt::decode(&mut cursor).ok()?;
    let object_id =
        if layout.object_id { VarInt::decode(&mut cursor).ok()?.into_inner() } else { 0 };
    if layout.priority {
        cursor = cursor.get(1..)?;
    }
    (VarInt::decode(&mut cursor).ok()?.into_inner() == 0).then_some(object_id)
}

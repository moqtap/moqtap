//! A whole fetch stream read through the facade reader: for the negative
//! vectors whose fault shows only across its Objects, and for the Locations a
//! stream resolves to.

use moqtap_codec::data_dispatch::{AnyFetchGroupOrder, AnyFetchObjectReader};
use moqtap_codec::dispatch::AnyFetchHeader;
use moqtap_codec::error::CodecError;
use moqtap_codec::version::DraftVersion;

/// The first refusal reading `bytes`, a fetch stream from its stream type on,
/// with its Groups in `group_order`.
pub fn first_failure(
    draft: DraftVersion,
    bytes: &[u8],
    group_order: AnyFetchGroupOrder,
) -> Option<CodecError> {
    let mut cursor = bytes;
    let header = match AnyFetchHeader::decode_stream(draft, &mut cursor) {
        Ok(header) => header,
        Err(e) => return Some(e),
    };
    let mut reader = match AnyFetchObjectReader::new(&header, group_order) {
        Ok(reader) => reader,
        Err(e) => return Some(e),
    };
    while !cursor.is_empty() {
        if let Err(e) = reader.read_object(&mut cursor) {
            return Some(e);
        }
    }
    None
}

/// The Location of every frame on the fetch stream `bytes`, read with its
/// Groups in `group_order`, or the first refusal.
pub fn locations(
    draft: DraftVersion,
    bytes: &[u8],
    group_order: AnyFetchGroupOrder,
) -> Result<Vec<(u64, u64)>, CodecError> {
    let mut cursor = bytes;
    let header = AnyFetchHeader::decode_stream(draft, &mut cursor)?;
    let mut reader = AnyFetchObjectReader::new(&header, group_order)?;
    let mut out = Vec::new();
    while !cursor.is_empty() {
        let object = reader.read_object(&mut cursor)?;
        out.push((object.group_id, object.object_id));
    }
    Ok(out)
}

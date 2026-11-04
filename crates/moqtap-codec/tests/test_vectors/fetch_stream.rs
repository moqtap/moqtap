//! A whole fetch stream read through the facade reader, for the negative
//! vectors whose fault shows only across its Objects.

use moqtap_codec::data_dispatch::{AnyFetchGroupOrder, AnyFetchObjectReader};
use moqtap_codec::dispatch::AnyFetchHeader;
use moqtap_codec::error::CodecError;
use moqtap_codec::version::DraftVersion;

/// The first refusal reading `bytes`, a fetch stream from its stream type on,
/// with its Groups in Ascending order.
pub fn first_failure(draft: DraftVersion, bytes: &[u8]) -> Option<CodecError> {
    let mut cursor = bytes;
    let header = match AnyFetchHeader::decode_stream(draft, &mut cursor) {
        Ok(header) => header,
        Err(e) => return Some(e),
    };
    let mut reader = match AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending) {
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

//! Inline data stream parser.
//!
//! Parses subgroup/fetch stream headers and object headers from
//! forwarded unidirectional stream bytes.

use bytes::{Buf, Bytes, BytesMut};

use moqtap_codec::dispatch::{AnyFetchHeader, AnyObjectHeader, AnySubgroupHeader};
use moqtap_codec::version::DraftVersion;

use crate::event::DataStreamHeaderKind;

/// The expected type of data stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStreamType {
    /// Subgroup data stream (most common).
    Subgroup,
    /// Fetch response data stream.
    Fetch,
}

/// Parsing state for a unidirectional data stream.
#[derive(Debug)]
enum DataStreamState {
    /// Waiting for the stream header.
    AwaitingHeader,
    /// Header parsed, waiting for object headers.
    InStream,
}

/// Result of parsing data stream bytes.
#[derive(Debug)]
pub enum DataParseResult {
    /// A stream header was parsed.
    Header(DataStreamHeaderKind, Bytes),
    /// An object header was parsed.
    Object(AnyObjectHeader, Bytes),
    /// Need more data.
    NeedMore,
    /// Parse error (non-fatal — forwarding continues).
    Error(String),
}

/// Stateful inline parser for a MoQT data stream.
///
/// Accepts raw byte chunks and emits parsed headers and object headers.
/// The parser buffers partial data and tries to decode when enough bytes
/// are available.
pub struct DataStreamParser {
    buf: BytesMut,
    stream_type: DataStreamType,
    state: DataStreamState,
    draft: DraftVersion,
}

impl DataStreamParser {
    /// Create a new parser for the given stream type and draft version.
    pub fn new(stream_type: DataStreamType, draft: DraftVersion) -> Self {
        Self {
            buf: BytesMut::with_capacity(4096),
            stream_type,
            state: DataStreamState::AwaitingHeader,
            draft,
        }
    }

    /// Feed raw bytes into the parser.
    ///
    /// Returns a list of parsed results. May return multiple results if
    /// the data contains several complete items.
    pub fn feed(&mut self, data: &[u8]) -> Vec<DataParseResult> {
        self.buf.extend_from_slice(data);
        let mut results = Vec::new();

        loop {
            if self.buf.is_empty() {
                break;
            }

            match self.state {
                DataStreamState::AwaitingHeader => match self.try_parse_header() {
                    Some(Ok((header, raw))) => {
                        self.state = DataStreamState::InStream;
                        results.push(DataParseResult::Header(header, raw));
                    }
                    Some(Err(e)) => {
                        results.push(DataParseResult::Error(e));
                        break;
                    }
                    None => {
                        if results.is_empty() {
                            results.push(DataParseResult::NeedMore);
                        }
                        break;
                    }
                },
                DataStreamState::InStream => match self.try_parse_object() {
                    Some(Ok((header, raw))) => {
                        results.push(DataParseResult::Object(header, raw));
                    }
                    Some(Err(e)) => {
                        results.push(DataParseResult::Error(e));
                        break;
                    }
                    None => {
                        if results.is_empty() {
                            results.push(DataParseResult::NeedMore);
                        }
                        break;
                    }
                },
            }
        }

        results
    }

    /// Try to parse the stream header from the buffer.
    fn try_parse_header(&mut self) -> Option<Result<(DataStreamHeaderKind, Bytes), String>> {
        let snapshot = &self.buf[..];
        let mut cursor = snapshot;

        match self.stream_type {
            DataStreamType::Subgroup => match AnySubgroupHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = snapshot.len() - cursor.remaining();
                    let raw = Bytes::copy_from_slice(&self.buf[..consumed]);
                    self.buf.advance(consumed);
                    Some(Ok((DataStreamHeaderKind::Subgroup(header), raw)))
                }
                Err(e) => {
                    if is_incomplete_error(&e) {
                        None
                    } else {
                        Some(Err(format!("subgroup header decode: {e}")))
                    }
                }
            },
            DataStreamType::Fetch => match AnyFetchHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = snapshot.len() - cursor.remaining();
                    let raw = Bytes::copy_from_slice(&self.buf[..consumed]);
                    self.buf.advance(consumed);
                    Some(Ok((DataStreamHeaderKind::Fetch(header), raw)))
                }
                Err(e) => {
                    if is_incomplete_error(&e) {
                        None
                    } else {
                        Some(Err(format!("fetch header decode: {e}")))
                    }
                }
            },
        }
    }

    /// Try to parse an object header from the buffer.
    fn try_parse_object(&mut self) -> Option<Result<(AnyObjectHeader, Bytes), String>> {
        let snapshot = &self.buf[..];
        let mut cursor = snapshot;

        match AnyObjectHeader::decode(self.draft, &mut cursor) {
            Ok(header) => {
                let consumed = snapshot.len() - cursor.remaining();
                let raw = Bytes::copy_from_slice(&self.buf[..consumed]);
                self.buf.advance(consumed);
                Some(Ok((header, raw)))
            }
            Err(e) => {
                if is_incomplete_error(&e) {
                    None
                } else {
                    Some(Err(format!("object header decode: {e}")))
                }
            }
        }
    }
}

/// Check if a codec error indicates incomplete data (need more bytes).
fn is_incomplete_error(e: &moqtap_codec::error::CodecError) -> bool {
    matches!(e, moqtap_codec::error::CodecError::UnexpectedEnd)
        || matches!(
            e,
            moqtap_codec::error::CodecError::VarInt(
                moqtap_codec::varint::VarIntError::UnexpectedEnd
            )
        )
}

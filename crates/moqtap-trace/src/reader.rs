use std::io::Read;

use ciborium::Value;

use crate::error::MoqTraceError;
use crate::event::TraceEvent;
use crate::header::TraceHeader;
use crate::writer::{MOQTRACE_MAGIC, MOQTRACE_VERSION};

/// Streaming reader for `.moqtrace` files.
///
/// Validates the preamble and parses the header on construction. Events
/// are then read one at a time via [`read_event`](Self::read_event) or
/// by iterating with [`into_iter`](Self::into_iter).
#[derive(Debug)]
pub struct MoqTraceReader<R: Read> {
    inner: R,
    header: TraceHeader,
}

impl<R: Read> MoqTraceReader<R> {
    /// Open a reader, validating the preamble and parsing the header.
    pub fn new(mut reader: R) -> Result<Self, MoqTraceError> {
        // 1. Magic bytes
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MOQTRACE_MAGIC {
            return Err(MoqTraceError::InvalidMagic);
        }

        // 2. Format version
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = u32::from_le_bytes(version_bytes);
        if version != MOQTRACE_VERSION {
            return Err(MoqTraceError::UnsupportedVersion(version));
        }

        // 3. Header length
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes)?;
        let header_len = u32::from_le_bytes(len_bytes) as usize;

        // 4. Read header CBOR bytes
        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;

        let header_value: Value = ciborium::from_reader(&header_bytes[..])?;
        let header = TraceHeader::try_from(header_value)?;

        Ok(Self { inner: reader, header })
    }

    /// Return a reference to the parsed header.
    pub fn header(&self) -> &TraceHeader {
        &self.header
    }

    /// Read the next event from the stream.
    ///
    /// Returns `Ok(None)` at EOF.
    pub fn read_event(&mut self) -> Result<Option<TraceEvent>, MoqTraceError> {
        match ciborium::from_reader::<Value, _>(&mut self.inner) {
            Ok(value) => {
                let event = TraceEvent::try_from(value)?;
                Ok(Some(event))
            }
            Err(ciborium::de::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Ok(None)
            }
            Err(e) => Err(MoqTraceError::CborDecode(e.to_string())),
        }
    }
}

impl<R: Read> IntoIterator for MoqTraceReader<R> {
    type Item = Result<TraceEvent, MoqTraceError>;
    type IntoIter = MoqTraceIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        MoqTraceIterator { reader: self }
    }
}

/// Iterator over events in a `.moqtrace` file.
pub struct MoqTraceIterator<R: Read> {
    reader: MoqTraceReader<R>,
}

impl<R: Read> Iterator for MoqTraceIterator<R> {
    type Item = Result<TraceEvent, MoqTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

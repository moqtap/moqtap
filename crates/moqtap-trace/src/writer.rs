use std::io::Write;

use ciborium::Value;

use crate::error::MoqTraceError;
use crate::event::TraceEvent;
use crate::header::TraceHeader;

/// Magic bytes identifying a `.moqtrace` file.
pub const MOQTRACE_MAGIC: &[u8; 8] = b"MOQTRACE";

/// Current format version.
pub const MOQTRACE_VERSION: u32 = 1;

/// Streaming writer for `.moqtrace` files.
///
/// Writes the preamble (magic, version, header) on construction, then
/// accepts events one at a time via [`write_event`](Self::write_event).
#[derive(Debug)]
pub struct MoqTraceWriter<W: Write> {
    inner: W,
}

impl<W: Write> MoqTraceWriter<W> {
    /// Create a new writer, writing the file preamble and header.
    pub fn new(mut writer: W, header: &TraceHeader) -> Result<Self, MoqTraceError> {
        // 1. Magic bytes
        writer.write_all(MOQTRACE_MAGIC)?;

        // 2. Format version (u32 LE)
        writer.write_all(&MOQTRACE_VERSION.to_le_bytes())?;

        // 3. CBOR-encode header
        let header_value: Value = header.into();
        let mut header_bytes = Vec::new();
        ciborium::into_writer(&header_value, &mut header_bytes)?;

        // 4. Header length (u32 LE)
        let header_len = header_bytes.len() as u32;
        writer.write_all(&header_len.to_le_bytes())?;

        // 5. Header CBOR bytes
        writer.write_all(&header_bytes)?;

        Ok(Self { inner: writer })
    }

    /// Append a single event to the file.
    pub fn write_event(&mut self, event: &TraceEvent) -> Result<(), MoqTraceError> {
        let value: Value = event.into();
        ciborium::into_writer(&value, &mut self.inner)?;
        Ok(())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<(), MoqTraceError> {
        self.inner.flush()?;
        Ok(())
    }

    /// Consume the writer and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

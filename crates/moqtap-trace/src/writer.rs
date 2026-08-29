use std::io::{BufWriter, Write};

use ciborium::Value;

use crate::error::MoqTraceError;
use crate::event::TraceEvent;
use crate::header::TraceHeader;

/// Magic bytes identifying a `.moqtrace` file, and each segment within one.
pub const MOQTRACE_MAGIC: &[u8; 8] = b"MOQTRACE";

/// Format version this crate writes.
pub const MOQTRACE_VERSION: u32 = 2;

/// Format versions this crate can read.
///
/// Version 1 is a version 2 file that happens to carry none of the keys this
/// revision adds and is never segmented, so reading it costs nothing and
/// keeps every capture taken before the bump openable.
pub const MOQTRACE_VERSIONS_SUPPORTED: &[u32] = &[1, MOQTRACE_VERSION];

/// Streaming writer for `.moqtrace` files.
///
/// Writes a preamble (magic, version, header) on construction, then accepts
/// events one at a time via [`write_event`](Self::write_event).
///
/// For a segmented trace — on-disk capture rotation, or a live stream carried
/// over MoQT — call [`start_segment`](Self::start_segment) to begin a new
/// segment with a fresh preamble of its own. A plain file is one segment.
///
/// The inner writer is wrapped in a [`BufWriter`] so events can be appended
/// at line rate without incurring one syscall per event. Call
/// [`flush`](Self::flush) or [`into_inner`](Self::into_inner) to drain the
/// buffer.
#[derive(Debug)]
pub struct MoqTraceWriter<W: Write> {
    inner: BufWriter<W>,
}

impl<W: Write> MoqTraceWriter<W> {
    /// Create a new writer, writing the preamble and header of the file (or
    /// of its first segment).
    pub fn new(writer: W, header: &TraceHeader) -> Result<Self, MoqTraceError> {
        let mut writer = BufWriter::new(writer);
        write_preamble(&mut writer, header)?;
        Ok(Self { inner: writer })
    }

    /// Append a single event to the current segment.
    pub fn write_event(&mut self, event: &TraceEvent) -> Result<(), MoqTraceError> {
        ciborium::into_writer(event, &mut self.inner)?;
        Ok(())
    }

    /// Begin a new segment, writing a fresh preamble immediately after the
    /// previous segment's last event.
    ///
    /// The header must carry [`segment`](TraceHeader::segment) metadata, and
    /// this returns an error if it does not. That field is what tells a
    /// reader the sequence numbers and timestamps it is about to see restart
    /// at zero; without it a reader takes each segment for a complete file
    /// and reconstructs a timeline that repeatedly jumps backwards.
    ///
    /// The new header should keep the same `protocol`, `perspective`,
    /// `detail` and `session_id` as the segments before it, and increment
    /// `segment.sequence`.
    pub fn start_segment(&mut self, header: &TraceHeader) -> Result<(), MoqTraceError> {
        if header.segment.is_none() {
            return Err(MoqTraceError::InvalidHeader(
                "a segment header must carry 'segment' metadata".into(),
            ));
        }
        write_preamble(&mut self.inner, header)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<(), MoqTraceError> {
        self.inner.flush()?;
        Ok(())
    }

    /// Consume the writer and return the inner writer.
    ///
    /// Flushes any buffered bytes. Returns an error if the flush fails.
    pub fn into_inner(self) -> Result<W, MoqTraceError> {
        self.inner.into_inner().map_err(|e| MoqTraceError::Io(e.into_error()))
    }
}

fn write_preamble<W: Write>(writer: &mut W, header: &TraceHeader) -> Result<(), MoqTraceError> {
    // 1. Magic bytes
    writer.write_all(MOQTRACE_MAGIC)?;

    // 2. Format version (u32 LE)
    writer.write_all(&MOQTRACE_VERSION.to_le_bytes())?;

    // 3. CBOR-encode header
    let header_value: Value = header.into();
    let mut header_bytes = Vec::with_capacity(128);
    ciborium::into_writer(&header_value, &mut header_bytes)?;

    // 4. Header length (u32 LE)
    let header_len = header_bytes.len() as u32;
    writer.write_all(&header_len.to_le_bytes())?;

    // 5. Header CBOR bytes
    writer.write_all(&header_bytes)?;

    Ok(())
}

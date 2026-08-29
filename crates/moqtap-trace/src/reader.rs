use std::io::Read;

use ciborium::Value;

use crate::error::MoqTraceError;
use crate::event::TraceEvent;
use crate::header::TraceHeader;
use crate::writer::{MOQTRACE_MAGIC, MOQTRACE_VERSIONS_SUPPORTED};

/// A `Read` that can look ahead without consuming, and counts what it has
/// handed out.
///
/// Both are needed for segmented traces: the lookahead is how a segment
/// boundary is spotted before an event decoder eats the magic bytes, and the
/// count is how a clean end-of-file is told apart from a stream that stopped
/// half-way through an event.
#[derive(Debug)]
struct PeekReader<R: Read> {
    inner: R,
    /// Bytes read from `inner` but not yet handed to a caller of `read`.
    lookahead: Vec<u8>,
    lookahead_pos: usize,
    /// Bytes handed out so far, excluding whatever is still in `lookahead`.
    count: u64,
}

impl<R: Read> PeekReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, lookahead: Vec::new(), lookahead_pos: 0, count: 0 }
    }

    /// Borrow the next `n` bytes without consuming them. The returned slice
    /// is shorter than `n` only at end of stream.
    fn peek(&mut self, n: usize) -> std::io::Result<&[u8]> {
        if self.lookahead_pos > 0 {
            self.lookahead.drain(..self.lookahead_pos);
            self.lookahead_pos = 0;
        }
        while self.lookahead.len() < n {
            let start = self.lookahead.len();
            self.lookahead.resize(n, 0);
            let got = self.inner.read(&mut self.lookahead[start..])?;
            self.lookahead.truncate(start + got);
            if got == 0 {
                break;
            }
        }
        Ok(&self.lookahead[..n.min(self.lookahead.len())])
    }

    /// Consume and return one byte, or `None` at end of stream.
    fn next_byte(&mut self) -> std::io::Result<Option<u8>> {
        let mut b = [0u8; 1];
        loop {
            return match self.read(&mut b) {
                Ok(0) => Ok(None),
                Ok(_) => Ok(Some(b[0])),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => Err(e),
            };
        }
    }
}

impl<R: Read> Read for PeekReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buffered = self.lookahead.len() - self.lookahead_pos;
        if buffered > 0 {
            let n = buffered.min(buf.len());
            buf[..n].copy_from_slice(&self.lookahead[self.lookahead_pos..self.lookahead_pos + n]);
            self.lookahead_pos += n;
            if self.lookahead_pos == self.lookahead.len() {
                self.lookahead.clear();
                self.lookahead_pos = 0;
            }
            self.count += n as u64;
            return Ok(n);
        }
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// One item from a `.moqtrace` stream.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadItem {
    /// An event in the current segment.
    Event(TraceEvent),
    /// A new segment began; this is its header. Every item after it belongs
    /// to that segment until the next `Segment`.
    Segment(TraceHeader),
}

/// Streaming reader for `.moqtrace` files.
///
/// Validates the preamble and parses the first segment's header on
/// construction. Use [`read_event`](Self::read_event), or the iterator it
/// backs, for code that does not care about segment boundaries — it advances
/// through them silently. Use [`read_next`](Self::read_next) to see them.
#[derive(Debug)]
pub struct MoqTraceReader<R: Read> {
    inner: PeekReader<R>,
    header: TraceHeader,
    version: u32,
}

impl<R: Read> MoqTraceReader<R> {
    /// Open a reader, validating the preamble and parsing the first segment's
    /// header.
    pub fn new(reader: R) -> Result<Self, MoqTraceError> {
        let mut inner = PeekReader::new(reader);
        let (version, header) = read_preamble(&mut inner)?;
        Ok(Self { inner, header, version })
    }

    /// The current segment's header.
    pub fn header(&self) -> &TraceHeader {
        &self.header
    }

    /// The format version the current segment declared.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Read the next item: an event in the current segment, or the header of
    /// a segment that starts here.
    ///
    /// Returns `Ok(None)` at a clean end of file. A stream that stops
    /// part-way through an item yields [`MoqTraceError::Truncated`] instead,
    /// which names the offset the incomplete item began at; everything
    /// returned before it stands.
    pub fn read_next(&mut self) -> Result<Option<ReadItem>, MoqTraceError> {
        let peek = self.inner.peek(MOQTRACE_MAGIC.len())?;
        if peek.is_empty() {
            return Ok(None);
        }
        // No event can be mistaken for a segment boundary: an event is a CBOR
        // map, and `M` (0x4d) opens a byte string.
        if peek == MOQTRACE_MAGIC.as_slice() {
            let start_offset = self.inner.count;
            let (version, header) = read_preamble(&mut self.inner).map_err(|e| match e {
                MoqTraceError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => {
                    MoqTraceError::Truncated { offset: start_offset }
                }
                other => other,
            })?;
            self.version = version;
            self.header = header.clone();
            return Ok(Some(ReadItem::Segment(header)));
        }

        let start_offset = self.inner.count;
        match ciborium::from_reader::<Value, _>(&mut self.inner) {
            Ok(value) => Ok(Some(ReadItem::Event(TraceEvent::try_from(value)?))),
            Err(ciborium::de::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if self.inner.count == start_offset {
                    Ok(None)
                } else {
                    Err(MoqTraceError::Truncated { offset: start_offset })
                }
            }
            Err(e) => Err(MoqTraceError::CborDecode(e.to_string())),
        }
    }

    /// Read the next event, advancing through segment boundaries silently.
    /// [`header`](Self::header) tracks the segment the event came from.
    ///
    /// Returns `Ok(None)` only at a clean end of file.
    pub fn read_event(&mut self) -> Result<Option<TraceEvent>, MoqTraceError> {
        loop {
            match self.read_next()? {
                Some(ReadItem::Event(event)) => return Ok(Some(event)),
                Some(ReadItem::Segment(_)) => continue,
                None => return Ok(None),
            }
        }
    }

    /// Scan forward to the next segment and resume there, returning its
    /// header — or `Ok(None)` if the stream ends before one is found.
    ///
    /// This is the recovery path a segmented trace exists to offer: after a
    /// [`Truncated`](MoqTraceError::Truncated) or a decode error, the current
    /// segment is unreadable from that point on, but the segments after it
    /// are intact and independently parseable. Everything skipped is
    /// discarded — the bytes between the failure and the next segment are the
    /// corrupt region.
    pub fn resync_to_next_segment(&mut self) -> Result<Option<TraceHeader>, MoqTraceError> {
        let mut window: Vec<u8> = Vec::with_capacity(MOQTRACE_MAGIC.len());
        while let Some(byte) = self.inner.next_byte()? {
            if window.len() == MOQTRACE_MAGIC.len() {
                window.remove(0);
            }
            window.push(byte);
            if window == MOQTRACE_MAGIC.as_slice() {
                // The magic is consumed; the rest of the preamble follows.
                let (version, header) = read_version_and_header(&mut self.inner)?;
                self.version = version;
                self.header = header.clone();
                return Ok(Some(header));
            }
        }
        Ok(None)
    }

    /// Iterate over events, advancing through segment boundaries silently.
    pub fn into_event_iter(self) -> MoqTraceEventIterator<R> {
        MoqTraceEventIterator { reader: self }
    }

    /// Iterate over items — events and segment boundaries both.
    pub fn into_item_iter(self) -> MoqTraceItemIterator<R> {
        MoqTraceItemIterator { reader: self }
    }
}

fn read_preamble<R: Read>(reader: &mut PeekReader<R>) -> Result<(u32, TraceHeader), MoqTraceError> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MOQTRACE_MAGIC {
        return Err(MoqTraceError::InvalidMagic);
    }
    read_version_and_header(reader)
}

fn read_version_and_header<R: Read>(
    reader: &mut PeekReader<R>,
) -> Result<(u32, TraceHeader), MoqTraceError> {
    let mut version_bytes = [0u8; 4];
    reader.read_exact(&mut version_bytes)?;
    let version = u32::from_le_bytes(version_bytes);
    if !MOQTRACE_VERSIONS_SUPPORTED.contains(&version) {
        return Err(MoqTraceError::UnsupportedVersion(version));
    }

    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let header_len = u32::from_le_bytes(len_bytes) as usize;

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;

    let header_value: Value = ciborium::from_reader(&header_bytes[..])?;
    Ok((version, TraceHeader::try_from(header_value)?))
}

/// Yields events, advancing through segment boundaries silently.
impl<R: Read> IntoIterator for MoqTraceReader<R> {
    type Item = Result<TraceEvent, MoqTraceError>;
    type IntoIter = MoqTraceEventIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_event_iter()
    }
}

/// Iterator over the events in a `.moqtrace` file.
pub struct MoqTraceEventIterator<R: Read> {
    reader: MoqTraceReader<R>,
}

impl<R: Read> MoqTraceEventIterator<R> {
    /// The header of the segment the last event came from.
    pub fn header(&self) -> &TraceHeader {
        self.reader.header()
    }
}

impl<R: Read> Iterator for MoqTraceEventIterator<R> {
    type Item = Result<TraceEvent, MoqTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Iterator over the items in a `.moqtrace` file, segment boundaries included.
pub struct MoqTraceItemIterator<R: Read> {
    reader: MoqTraceReader<R>,
}

impl<R: Read> Iterator for MoqTraceItemIterator<R> {
    type Item = Result<ReadItem, MoqTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_next() {
            Ok(Some(item)) => Some(Ok(item)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

use std::collections::BTreeMap;

use ciborium::Value;

use crate::error::MoqTraceError;

// ── map lookup helpers ─────────────────────────────────────

fn find<'a>(pairs: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    pairs.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
}

fn find_text(pairs: &[(Value, Value)], key: &str) -> Option<String> {
    find(pairs, key).and_then(|v| v.as_text().map(String::from))
}

fn find_uint(pairs: &[(Value, Value)], key: &str) -> Option<u64> {
    find(pairs, key).and_then(as_u64)
}

/// Read an unsigned integer, accepting the float form CBOR also permits.
///
/// An encoder may write an integral value as a float, and one of the two
/// implementations of this format does exactly that for anything past 32 bits
/// — which every epoch-millisecond timestamp is. Reading only major type 0
/// here meant `startTime` went missing from every trace that encoder wrote,
/// and the file was rejected before a single event was read.
///
/// A float carries integers exactly only up to 2^53, so one that is
/// fractional or beyond that range is not an integer this can honour, and is
/// refused rather than rounded.
pub(crate) fn as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(i) => u64::try_from(*i).ok(),
        Value::Float(f) => {
            let f = *f;
            if f.fract() == 0.0 && f >= 0.0 && f <= (2u64 << 52) as f64 {
                Some(f as u64)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Read a signed integer, accepting the float form. See [`as_u64`].
pub(crate) fn as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(i) => i64::try_from(*i).ok(),
        Value::Float(f) => {
            let f = *f;
            let limit = (2u64 << 52) as f64;
            if f.fract() == 0.0 && f >= -limit && f <= limit {
                Some(f as i64)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn find_bool(pairs: &[(Value, Value)], key: &str) -> Option<bool> {
    match find(pairs, key) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// Recording perspective — who captured the trace.
///
/// An unrecognised value is preserved as [`Perspective::Other`] rather than
/// rejected: the format admits new perspectives without a version bump, and
/// every event in such a file is still parseable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Perspective {
    /// MoQT client (initiator of the QUIC connection).
    Client,
    /// MoQT server or relay (single-session view from inside the endpoint).
    Server,
    /// Passive observer (e.g. DevTools extension, network tap).
    Observer,
    /// Active capture from inside a relay, reporting on multiple concurrent
    /// peer sessions. Distinct from [`Perspective::Server`] because events
    /// span peers and carry a peer identifier.
    RelayTap,
    /// A perspective this version of the crate does not know, kept verbatim.
    Other(String),
}

impl Perspective {
    /// The wire spelling of this perspective.
    pub fn as_str(&self) -> &str {
        match self {
            Perspective::Client => "client",
            Perspective::Server => "server",
            Perspective::Observer => "observer",
            Perspective::RelayTap => "relay-tap",
            Perspective::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "client" => Perspective::Client,
            "server" => Perspective::Server,
            "observer" => Perspective::Observer,
            "relay-tap" => Perspective::RelayTap,
            other => Perspective::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for Perspective {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Detail level — declares what was recorded.
///
/// Each known level is a strict superset of the one above it, which is what
/// the [`Ord`] impl orders by. [`DetailLevel::Other`] sorts above `Full`
/// deliberately: a level this crate does not know might reveal anything, and
/// a privacy check written as `detail >= HeadersData` should err towards
/// warning rather than towards silence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DetailLevel {
    /// Control messages only.
    Control,
    /// Control messages + data stream headers and object metadata.
    Headers,
    /// Headers + payload byte lengths.
    HeadersSizes,
    /// Headers + full payload bytes.
    HeadersData,
    /// Everything above + raw wire bytes.
    Full,
    /// A level this version of the crate does not know, kept verbatim.
    Other(String),
}

impl DetailLevel {
    /// The wire spelling of this detail level.
    pub fn as_str(&self) -> &str {
        match self {
            DetailLevel::Control => "control",
            DetailLevel::Headers => "headers",
            DetailLevel::HeadersSizes => "headers+sizes",
            DetailLevel::HeadersData => "headers+data",
            DetailLevel::Full => "full",
            DetailLevel::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "control" => DetailLevel::Control,
            "headers" => DetailLevel::Headers,
            "headers+sizes" => DetailLevel::HeadersSizes,
            "headers+data" => DetailLevel::HeadersData,
            "full" => DetailLevel::Full,
            other => DetailLevel::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for DetailLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Drop policy applied when a sampled source could not keep up.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropPolicy {
    /// Drop the oldest events first.
    Head,
    /// Drop the newest events first.
    Tail,
    /// Random sampling at the configured rate.
    Sampled,
    /// A policy this version of the crate does not know, kept verbatim.
    Other(String),
}

impl DropPolicy {
    /// The wire spelling of this drop policy.
    pub fn as_str(&self) -> &str {
        match self {
            DropPolicy::Head => "head",
            DropPolicy::Tail => "tail",
            DropPolicy::Sampled => "sampled",
            DropPolicy::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "head" => DropPolicy::Head,
            "tail" => DropPolicy::Tail,
            "sampled" => DropPolicy::Sampled,
            other => DropPolicy::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for DropPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-segment metadata.
///
/// Present only in segmented traces. A single-shot file must not carry it —
/// its absence is what tells a reader that event sequence numbers and
/// timestamps are file-global rather than segment-local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentInfo {
    /// 0-based sequence number of this segment within the stream.
    pub sequence: u64,
    /// Nominal segment duration in milliseconds. A hint; the actual duration
    /// may differ.
    pub duration_ms: Option<u64>,
    /// Opaque identifier shared by every segment of the same logical stream.
    pub stream_id: Option<String>,
    /// `true` if this segment continues a previous one with the same
    /// `stream_id`. `false` or absent for the first segment.
    pub continues: Option<bool>,
}

impl SegmentInfo {
    /// A segment carrying only its sequence number.
    pub fn new(sequence: u64) -> Self {
        SegmentInfo { sequence, duration_ms: None, stream_id: None, continues: None }
    }

    fn to_value(&self) -> Value {
        let mut pairs: Vec<(Value, Value)> =
            vec![(Value::Text("sequence".into()), Value::Integer(self.sequence.into()))];
        if let Some(d) = self.duration_ms {
            pairs.push((Value::Text("durationMs".into()), Value::Integer(d.into())));
        }
        if let Some(ref s) = self.stream_id {
            pairs.push((Value::Text("streamId".into()), Value::Text(s.clone())));
        }
        if let Some(c) = self.continues {
            pairs.push((Value::Text("continues".into()), Value::Bool(c)));
        }
        Value::Map(pairs)
    }

    fn from_value(v: &Value) -> Result<Self, MoqTraceError> {
        let pairs = match v {
            Value::Map(p) => p,
            _ => return Err(MoqTraceError::InvalidHeader("'segment' is not a CBOR map".into())),
        };
        Ok(SegmentInfo {
            sequence: find_uint(pairs, "sequence")
                .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'segment.sequence'".into()))?,
            duration_ms: find_uint(pairs, "durationMs"),
            stream_id: find_text(pairs, "streamId"),
            continues: find_bool(pairs, "continues"),
        })
    }
}

/// Sampling and filtering metadata. Present only when events were dropped or
/// filtered at the source.
///
/// Its absence means the trace is complete relative to the declared detail
/// level. Sources must not drop control messages, state changes, errors, or
/// peer and subscription events under any policy — those carry the causal
/// structure that makes the rest of the trace readable — so a source that
/// cannot keep up with them refuses the recording instead. When sampling is
/// active, `applies_to` names the event types the policy actually touched,
/// and a reader may treat every other type as complete.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SamplingInfo {
    /// Effective fraction of source events retained, in `(0.0, 1.0]`.
    pub effective_rate: Option<f64>,
    /// Per-segment cap that triggered drops, if rate-limited.
    pub max_events_per_sec: Option<u64>,
    /// Drop strategy applied when the cap was exceeded.
    pub drop_policy: Option<DropPolicy>,
    /// Cumulative events dropped since `start_time`. In a segmented trace this
    /// is the running total at the start of this segment.
    pub dropped_total: Option<u64>,
    /// Events dropped within this segment only.
    pub dropped_segment: Option<u64>,
    /// Source-side filter rule that selected events.
    pub rule: Option<String>,
    /// Filter language the rule is written in (`"prefix"`, `"glob"`, `"cel"`).
    pub rule_lang: Option<String>,
    /// Event type IDs the drop policy was applied to.
    pub applies_to: Option<Vec<u64>>,
}

impl SamplingInfo {
    fn to_value(&self) -> Value {
        let mut pairs: Vec<(Value, Value)> = Vec::new();
        if let Some(r) = self.effective_rate {
            pairs.push((Value::Text("effectiveRate".into()), Value::Float(r)));
        }
        if let Some(m) = self.max_events_per_sec {
            pairs.push((Value::Text("maxEventsPerSec".into()), Value::Integer(m.into())));
        }
        if let Some(ref p) = self.drop_policy {
            pairs.push((Value::Text("dropPolicy".into()), Value::Text(p.as_str().into())));
        }
        if let Some(d) = self.dropped_total {
            pairs.push((Value::Text("droppedTotal".into()), Value::Integer(d.into())));
        }
        if let Some(d) = self.dropped_segment {
            pairs.push((Value::Text("droppedSegment".into()), Value::Integer(d.into())));
        }
        if let Some(ref r) = self.rule {
            pairs.push((Value::Text("rule".into()), Value::Text(r.clone())));
        }
        if let Some(ref r) = self.rule_lang {
            pairs.push((Value::Text("ruleLang".into()), Value::Text(r.clone())));
        }
        if let Some(ref a) = self.applies_to {
            let arr: Vec<Value> = a.iter().map(|&i| Value::Integer(i.into())).collect();
            pairs.push((Value::Text("appliesTo".into()), Value::Array(arr)));
        }
        Value::Map(pairs)
    }

    fn from_value(v: &Value) -> Result<Self, MoqTraceError> {
        let pairs = match v {
            Value::Map(p) => p,
            _ => return Err(MoqTraceError::InvalidHeader("'sampling' is not a CBOR map".into())),
        };
        let effective_rate = find(pairs, "effectiveRate").and_then(|v| match v {
            Value::Float(f) => Some(*f),
            Value::Integer(i) => i64::try_from(*i).ok().map(|n| n as f64),
            _ => None,
        });
        let applies_to = match find(pairs, "appliesTo") {
            Some(Value::Array(items)) => Some(items.iter().filter_map(as_u64).collect()),
            _ => None,
        };
        Ok(SamplingInfo {
            effective_rate,
            max_events_per_sec: find_uint(pairs, "maxEventsPerSec"),
            drop_policy: find_text(pairs, "dropPolicy").as_deref().map(DropPolicy::parse),
            dropped_total: find_uint(pairs, "droppedTotal"),
            dropped_segment: find_uint(pairs, "droppedSegment"),
            rule: find_text(pairs, "rule"),
            rule_lang: find_text(pairs, "ruleLang"),
            applies_to,
        })
    }
}

/// Session metadata written at the start of a `.moqtrace` file, and at the
/// start of every segment in a segmented one.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceHeader {
    /// MoQT version identifier (e.g. `"moq-transport-17"`, `"moq-transport-rfc9999"`).
    pub protocol: String,
    /// Recording viewpoint.
    pub perspective: Perspective,
    /// Detail level.
    pub detail: DetailLevel,
    /// Recording start time (Unix epoch milliseconds). In a segmented trace
    /// this is the segment's start, not the stream's.
    pub start_time: u64,
    /// Recording end time (Unix epoch milliseconds). Set when the trace is
    /// finalized, so a crash-truncated file has none.
    pub end_time: Option<u64>,
    /// Transport type (e.g. `"webtransport"`, `"raw-quic"`).
    pub transport: Option<String>,
    /// Software that produced the trace. Also namespaces the source-local
    /// peer identifiers carried on events.
    pub source: Option<String>,
    /// Remote peer URI.
    pub endpoint: Option<String>,
    /// Capture-correlation identifier, grouping traces of one logical session
    /// recorded from different vantage points.
    pub session_id: Option<String>,
    /// Per-segment metadata. Present only when this header begins one segment
    /// of a segmented stream.
    pub segment: Option<SegmentInfo>,
    /// Sampling and filter metadata. Present only when events were dropped or
    /// filtered at the source.
    pub sampling: Option<SamplingInfo>,
    /// User-defined metadata. `"payloadMasked": true` here declares that
    /// payload bytes were zeroed before writing.
    pub custom: Option<BTreeMap<String, Value>>,
}

impl TraceHeader {
    /// A header carrying only the four required fields.
    ///
    /// Prefer this over a struct literal and assign the optional fields you
    /// need: a literal has to be edited every time the format gains a field,
    /// this does not.
    pub fn new(
        protocol: impl Into<String>,
        perspective: Perspective,
        detail: DetailLevel,
        start_time: u64,
    ) -> Self {
        TraceHeader {
            protocol: protocol.into(),
            perspective,
            detail,
            start_time,
            end_time: None,
            transport: None,
            source: None,
            endpoint: None,
            session_id: None,
            segment: None,
            sampling: None,
            custom: None,
        }
    }
}

impl From<&TraceHeader> for Value {
    fn from(h: &TraceHeader) -> Self {
        let mut pairs: Vec<(Value, Value)> = vec![
            (Value::Text("protocol".into()), Value::Text(h.protocol.clone())),
            (Value::Text("perspective".into()), Value::Text(h.perspective.as_str().into())),
            (Value::Text("detail".into()), Value::Text(h.detail.as_str().into())),
            (Value::Text("startTime".into()), Value::Integer(h.start_time.into())),
        ];

        if let Some(end_time) = h.end_time {
            pairs.push((Value::Text("endTime".into()), Value::Integer(end_time.into())));
        }
        if let Some(ref transport) = h.transport {
            pairs.push((Value::Text("transport".into()), Value::Text(transport.clone())));
        }
        if let Some(ref source) = h.source {
            pairs.push((Value::Text("source".into()), Value::Text(source.clone())));
        }
        if let Some(ref endpoint) = h.endpoint {
            pairs.push((Value::Text("endpoint".into()), Value::Text(endpoint.clone())));
        }
        if let Some(ref session_id) = h.session_id {
            pairs.push((Value::Text("sessionId".into()), Value::Text(session_id.clone())));
        }
        if let Some(ref segment) = h.segment {
            pairs.push((Value::Text("segment".into()), segment.to_value()));
        }
        if let Some(ref sampling) = h.sampling {
            pairs.push((Value::Text("sampling".into()), sampling.to_value()));
        }
        if let Some(ref custom) = h.custom {
            let custom_pairs: Vec<(Value, Value)> =
                custom.iter().map(|(k, v)| (Value::Text(k.clone()), v.clone())).collect();
            pairs.push((Value::Text("custom".into()), Value::Map(custom_pairs)));
        }

        Value::Map(pairs)
    }
}

impl TryFrom<Value> for TraceHeader {
    type Error = MoqTraceError;

    fn try_from(value: Value) -> Result<Self, MoqTraceError> {
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => return Err(MoqTraceError::InvalidHeader("header is not a CBOR map".into())),
        };

        let protocol = find_text(&pairs, "protocol")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'protocol'".into()))?;
        let perspective = find_text(&pairs, "perspective")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'perspective'".into()))?;
        let detail = find_text(&pairs, "detail")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'detail'".into()))?;
        let start_time = find_uint(&pairs, "startTime")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'startTime'".into()))?;

        let segment = match find(&pairs, "segment") {
            Some(v) => Some(SegmentInfo::from_value(v)?),
            None => None,
        };
        let sampling = match find(&pairs, "sampling") {
            Some(v) => Some(SamplingInfo::from_value(v)?),
            None => None,
        };

        let custom = match find(&pairs, "custom") {
            Some(Value::Map(custom_pairs)) => Some(
                custom_pairs
                    .iter()
                    .filter_map(|(ck, cv)| ck.as_text().map(|s| (s.to_string(), cv.clone())))
                    .collect(),
            ),
            _ => None,
        };

        Ok(TraceHeader {
            protocol,
            perspective: Perspective::parse(&perspective),
            detail: DetailLevel::parse(&detail),
            start_time,
            end_time: find_uint(&pairs, "endTime"),
            transport: find_text(&pairs, "transport"),
            source: find_text(&pairs, "source"),
            endpoint: find_text(&pairs, "endpoint"),
            session_id: find_text(&pairs, "sessionId"),
            segment,
            sampling,
            custom,
        })
    }
}

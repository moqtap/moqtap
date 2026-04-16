use std::collections::BTreeMap;

use ciborium::Value;

use crate::error::MoqTraceError;

/// Recording perspective — who captured the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perspective {
    /// MoQT client (initiator of the QUIC connection).
    Client,
    /// MoQT server or relay.
    Server,
    /// Passive observer (e.g. DevTools extension, network tap).
    Observer,
}

impl Perspective {
    fn as_str(self) -> &'static str {
        match self {
            Perspective::Client => "client",
            Perspective::Server => "server",
            Perspective::Observer => "observer",
        }
    }

    fn from_str(s: &str) -> Result<Self, MoqTraceError> {
        match s {
            "client" => Ok(Perspective::Client),
            "server" => Ok(Perspective::Server),
            "observer" => Ok(Perspective::Observer),
            other => Err(MoqTraceError::InvalidHeader(format!("unknown perspective: {other}"))),
        }
    }
}

/// Detail level — declares what was recorded.
///
/// Each level is a strict superset of the one above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
}

impl DetailLevel {
    fn as_str(self) -> &'static str {
        match self {
            DetailLevel::Control => "control",
            DetailLevel::Headers => "headers",
            DetailLevel::HeadersSizes => "headers+sizes",
            DetailLevel::HeadersData => "headers+data",
            DetailLevel::Full => "full",
        }
    }

    fn from_str(s: &str) -> Result<Self, MoqTraceError> {
        match s {
            "control" => Ok(DetailLevel::Control),
            "headers" => Ok(DetailLevel::Headers),
            "headers+sizes" => Ok(DetailLevel::HeadersSizes),
            "headers+data" => Ok(DetailLevel::HeadersData),
            "full" => Ok(DetailLevel::Full),
            other => Err(MoqTraceError::InvalidHeader(format!("unknown detail level: {other}"))),
        }
    }
}

/// Session metadata header written at the start of a `.moqtrace` file.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceHeader {
    /// MoQT version identifier (e.g. `"moq-transport-14"`).
    pub protocol: String,
    /// Recording viewpoint.
    pub perspective: Perspective,
    /// Detail level.
    pub detail: DetailLevel,
    /// Recording start time (Unix epoch milliseconds).
    pub start_time: u64,
    /// Recording end time (Unix epoch milliseconds). Set when trace is
    /// finalized.
    pub end_time: Option<u64>,
    /// Transport type (e.g. `"webtransport"`, `"raw-quic"`).
    pub transport: Option<String>,
    /// Software that produced the trace.
    pub source: Option<String>,
    /// Remote peer URI.
    pub endpoint: Option<String>,
    /// Opaque session correlation identifier.
    pub session_id: Option<String>,
    /// User-defined metadata.
    pub custom: Option<BTreeMap<String, Value>>,
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

        let get_text = |pairs: &[(Value, Value)], key: &str| -> Option<String> {
            pairs.iter().find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    v.as_text().map(|s| s.to_string())
                } else {
                    None
                }
            })
        };

        let get_integer = |pairs: &[(Value, Value)], key: &str| -> Option<u64> {
            pairs.iter().find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    v.as_integer().and_then(|i| u64::try_from(i).ok())
                } else {
                    None
                }
            })
        };

        let protocol = get_text(&pairs, "protocol")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'protocol'".into()))?;
        let perspective_str = get_text(&pairs, "perspective")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'perspective'".into()))?;
        let detail_str = get_text(&pairs, "detail")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'detail'".into()))?;
        let start_time = get_integer(&pairs, "startTime")
            .ok_or_else(|| MoqTraceError::InvalidHeader("missing 'startTime'".into()))?;

        let custom = pairs.iter().find_map(|(k, v)| {
            if k.as_text() == Some("custom") {
                if let Value::Map(custom_pairs) = v {
                    let map: BTreeMap<String, Value> = custom_pairs
                        .iter()
                        .filter_map(|(ck, cv)| ck.as_text().map(|s| (s.to_string(), cv.clone())))
                        .collect();
                    Some(map)
                } else {
                    None
                }
            } else {
                None
            }
        });

        Ok(TraceHeader {
            protocol,
            perspective: Perspective::from_str(&perspective_str)?,
            detail: DetailLevel::from_str(&detail_str)?,
            start_time,
            end_time: get_integer(&pairs, "endTime"),
            transport: get_text(&pairs, "transport"),
            source: get_text(&pairs, "source"),
            endpoint: get_text(&pairs, "endpoint"),
            session_id: get_text(&pairs, "sessionId"),
            custom,
        })
    }
}

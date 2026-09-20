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

/// Write a number as a CBOR integer when its value is integral, and as a float
/// only when it is not.
///
/// The format's encoding rule (SPEC.md, Interoperability) requires an integral
/// value to be written as a CBOR integer rather than a float, and is about the
/// *value* rather than the type the document gives the key.
/// `"effectiveRate"` is the one
/// key here declared a float, and its commonest value is `1.0` — "no
/// rate-based dropping" — so writing it as a float meant the two
/// implementations emitted different major types for the same trace, in the
/// case that occurs most. Both readers accept either form; the bytes still
/// differed, which is exactly what the rule exists to stop.
///
/// A value with a fractional part, one past the range a float carries integers
/// exactly, and NaN or an infinity (whose `fract()` is NaN) all stay floats.
fn number_value(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() <= (2u64 << 52) as f64 {
        Value::Integer((x as i64).into())
    } else {
        Value::Float(x)
    }
}

fn find_bool(pairs: &[(Value, Value)], key: &str) -> Option<bool> {
    match find(pairs, key) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// Read a required text key, distinguishing "absent" from "present and not
/// text".
///
/// Both are malformed — there is no header to construct without the key — but
/// they are different faults, and reporting a `"perspective": 5` as a missing
/// `"perspective"` sends whoever has to fix the file looking for something
/// that is right in front of them. `label` names the key as a reader of the
/// file would find it, which for a key inside `"segment"` is not its bare
/// name.
fn required_text(
    pairs: &[(Value, Value)],
    key: &str,
    label: &str,
) -> Result<String, MoqTraceError> {
    match find(pairs, key) {
        Some(v) => v
            .as_text()
            .map(String::from)
            .ok_or_else(|| MoqTraceError::InvalidHeader(format!("'{label}' is not a text string"))),
        None => Err(MoqTraceError::InvalidHeader(format!("missing '{label}'"))),
    }
}

/// Read a required unsigned-integer key. See [`required_text`].
fn required_uint(pairs: &[(Value, Value)], key: &str, label: &str) -> Result<u64, MoqTraceError> {
    match find(pairs, key) {
        Some(v) => as_u64(v).ok_or_else(|| {
            MoqTraceError::InvalidHeader(format!("'{label}' is not an unsigned integer"))
        }),
        None => Err(MoqTraceError::InvalidHeader(format!("missing '{label}'"))),
    }
}

// ── unrecognised-key stores ────────────────────────────────

/// Whether `key` belongs in a map's unrecognised-key store rather than in one
/// of the map's own fields, given that map's `writes_key`.
///
/// This is the writing half's question: an entry naming a key the map already
/// writes from a field is not written a second time from the store, since a
/// CBOR map carrying one key twice is a map no two readers need agree on. The
/// reading half asks a finer one — see [`unrecognised`], which has to tell two
/// entries with the same key apart.
///
/// A non-text key is unrecognised by construction: every key this format
/// defines is text.
fn goes_to_store(key: &Value, writes_key: impl Fn(&str) -> bool) -> bool {
    !key.as_text().is_some_and(writes_key)
}

/// Rewrite a value into the encoding this format requires of a writer, leaving
/// what it says alone.
///
/// The two normative encoding rules — an integral value is written as a CBOR
/// integer rather than a float, and a byte string as major type 2 rather than
/// under RFC 8746's tag 64 — bind the bytes a *writer* emits, so they bind
/// every value it emits and not only the ones it understood. A store holds
/// values this crate never looked at, and the JavaScript implementation's
/// decoder folds both shapes away before its own code sees them: it cannot
/// emit either, whatever its store holds. A Rust writer that re-emitted them
/// would produce different bytes for the same input file, which is the one
/// thing those two rules exist to stop. SPEC.md extends both rules to stored
/// values for exactly that reason — see its Interoperability section, under
/// the shapes a CBOR library may normalise before a reader sees them.
///
/// Not the header's alone: an event carries opaque values too — a control
/// message's `"msg"`, an annotation's `"data"`, an unknown event type's
/// fields and [`TraceEvent::extra`](crate::event::TraceEvent::extra) — and
/// they are written through this same function. Two copies of this rule that
/// had to agree would be the defect it exists to fix.
///
/// Applied on write and never on read: a value read into a store still
/// compares equal to what the file carried, and the house style is the
/// serialiser's business. Recursive, because a stored value may be a whole
/// tree and the rules are about every number and every byte string in it, and
/// applied to map *keys* as well as values, which are encoded by the same
/// rules as anything else.
///
/// One value changes rather than merely changing encoding: `-0.0` written as
/// `0` loses its sign. SPEC.md calls that out and accepts it — no field in a
/// trace gives negative zero a meaning — so there is deliberately no exception
/// for it here.
///
/// A map inside a stored value is deduplicated on the same terms as the store
/// itself: SPEC.md forbids a conformant tool from emitting a map with a
/// repeated key even having read one, and that binds every map a writer emits
/// rather than only the outermost. Reading such a map still hands back both
/// entries — that half is observable here and must be preserved — and writing
/// it emits the first.
pub(crate) fn normalised(value: &Value) -> Value {
    match value {
        // SPEC.md's first encoding rule: an integral value goes out as a
        // CBOR integer, not as a float. The same function the header's own
        // float-typed key is written through.
        Value::Float(f) => number_value(*f),
        // SPEC.md's second encoding rule: a byte string goes out as major
        // type 2, never wrapped in RFC 8746's typed-array tag 64. That tag
        // is `uint8 array`, whose
        // content is a byte string and whose meaning is that byte string; the
        // tag records only that some language held it as a typed array.
        Value::Tag(64, inner) if matches!(**inner, Value::Bytes(_)) => (**inner).clone(),
        Value::Tag(tag, inner) => Value::Tag(*tag, Box::new(normalised(inner))),
        Value::Array(items) => Value::Array(items.iter().map(normalised).collect()),
        Value::Map(pairs) => {
            Value::Map(deduplicated(pairs.iter().map(|(k, v)| (normalised(k), normalised(v)))))
        }
        // Integers, byte strings, text, booleans and null are already what the
        // rules ask for. `Value` is `#[non_exhaustive]`, so anything ciborium
        // adds later arrives here and is passed through untouched, which is
        // the safe direction: it is preserved rather than mangled.
        other => other.clone(),
    }
}

/// Whether two keys about to be written are one key in the file.
///
/// [`Value`]'s equality is CBOR's everywhere but on NaN, where it follows
/// IEEE 754 and answers `false` for a value compared with itself. Two NaN keys
/// encode to the same bytes, so a map carrying both is as invalid as any other
/// map with a repeated key, and equality alone would wave exactly that one
/// case through.
fn same_key(one: &Value, other: &Value) -> bool {
    match (one, other) {
        (Value::Float(a), Value::Float(b)) if a.is_nan() && b.is_nan() => true,
        _ => one == other,
    }
}

/// The entries of a map to be written, with no key twice: the first entry for
/// a key is kept in its place and the rest are dropped.
///
/// Callers pass entries that are already [`normalised`], because normalisation
/// can *create* a collision — `Float(1.0)` and `Integer(1)` are two keys in a
/// store and one key in a file, as are a byte string and the same bytes under
/// tag 64 — so a check that ran first would miss it.
///
/// **First wins, not last.** Every read in this file goes through [`find`],
/// which returns the first entry for a key, so keeping the first is what makes
/// the entry a caller is shown the entry that survives a rewrite; keeping the
/// last would hand back one value and file another. It also makes the rewrite
/// a fixed point rather than something a value can drift across.
///
/// Quadratic, and deliberately: these are the keys of one map, the comparison
/// is a `Value` equality rather than a hash of an arbitrary tree, and `Value`
/// is not `Hash` at all — a CBOR value may be a float.
fn deduplicated(entries: impl Iterator<Item = (Value, Value)>) -> Vec<(Value, Value)> {
    let mut kept: Vec<(Value, Value)> = Vec::new();
    for (key, value) in entries {
        if kept.iter().any(|(already, _)| same_key(already, &key)) {
            continue;
        }
        kept.push((key, value));
    }
    kept
}

/// Every entry of `pairs` the decoded map does not write back out of a field
/// of its own: a key this crate has never heard of, a key it knows whose value
/// it could not use — and a second entry for a key whose *first* entry a field
/// did take.
///
/// That last case is why this walks entries rather than filtering on key
/// names. Every field is read through [`find`], which returns the first entry
/// for its key, so a header carrying `"transport": "wt"` and then
/// `"transport": 42` hands `"wt"` to the field and leaves the `42`
/// unaccounted for. Filtering the store by key name dropped that entry along
/// with the one the field was holding, and a value the file carried reached
/// neither the field nor the store: reading the file deleted it outright.
/// RFC 8949 makes such a map invalid and SPEC.md leaves readers free to
/// disagree over which entry of a duplicate pair wins, but neither licenses
/// losing the other one on the way in.
///
/// The kept entry is not written back — [`store_entries`] drops it, because
/// the field writes that key and a map may not carry it twice — so a rewrite
/// of a duplicate-keyed map emits one entry of the pair, which is the most a
/// conformant writer can emit, and is a fixed point from there.
///
/// Events use this too, with their own `writes_key`. Which entry a field
/// actually took is the caller's business, not this walk's: a lookup that
/// returns the first entry for a key whatever it holds leaves the first, and
/// one that skips an entry whose value it cannot use may leave a later one.
/// This drops the first entry for a key the map writes either way, so on a
/// mixed-type duplicate the two disagree about *which* entry survives. Without
/// this walk both are lost, and SPEC.md leaves readers free to
/// disagree over which of a duplicate pair wins, so nothing may depend on it.
pub(crate) fn unrecognised(
    pairs: &[(Value, Value)],
    writes_key: impl Fn(&str) -> bool,
) -> Vec<(Value, Value)> {
    let mut taken: Vec<&str> = Vec::new();
    let mut store: Vec<(Value, Value)> = Vec::new();
    for (key, value) in pairs {
        if let Some(name) = key.as_text() {
            // The first entry for a key the map writes is the entry the field
            // is holding: `find` returned this one. Every later entry for that
            // key is a value no field took, and goes to the store.
            if writes_key(name) && !taken.contains(&name) {
                taken.push(name);
                continue;
            }
        }
        store.push((key.clone(), value.clone()));
    }
    store
}

/// Map entries a writer is about to emit out of pairs that came from a file:
/// [`normalised`] into the encoding SPEC.md requires, and with no key written
/// twice ([`deduplicated`]).
///
/// Normalising first is deliberate — it can *create* a collision, so a dedup
/// pass that ran before it would miss one. See [`deduplicated`].
///
/// A list of pairs is not a map and can hold one key twice: a caller can build
/// such a list by hand, and a file that repeated a key no field could use
/// leaves one behind (see [`unrecognised`]). Without this pass both entries go
/// into the file. RFC 8949 calls a map with a repeated key
/// invalid, the JavaScript reader silently collapses one, and SPEC.md forbids
/// emitting one at all.
///
/// Used for every such list this crate writes: the header's three stores
/// through [`store_entries`], and on the event side
/// [`TraceEvent::extra`](crate::event::TraceEvent::extra) and an unknown event
/// type's fields. `"custom"` needs only the [`normalised`] half — a
/// `BTreeMap` cannot hold one key twice, so the dedup pass has nothing to
/// find there.
pub(crate) fn written_entries<'a>(
    entries: impl Iterator<Item = &'a (Value, Value)>,
) -> Vec<(Value, Value)> {
    deduplicated(entries.map(|(key, value)| (normalised(key), normalised(value))))
}

/// The store entries to write after a map's own keys.
///
/// [`written_entries`] with one pass in front of it: an entry naming a key the
/// map writes from a field is dropped, because the field wins and writing both
/// would put that key in the map twice.
pub(crate) fn store_entries(
    extra: &[(Value, Value)],
    writes_key: impl Fn(&str) -> bool,
) -> Vec<(Value, Value)> {
    written_entries(extra.iter().filter(|(key, _)| goes_to_store(key, &writes_key)))
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
// No `Eq`: `extra` holds arbitrary CBOR, and a CBOR value may be a float, for
// which equality is not reflexive. `TraceHeader` and `SamplingInfo` have never
// had it for the same reason.
#[derive(Debug, Clone, PartialEq)]
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
    /// Keys in the `"segment"` map that this version of the crate could not
    /// use, kept verbatim and written back into that map.
    ///
    /// The store belongs to `"segment"` and not to the header: a private key
    /// on the segment and a key of the same name at the top level are
    /// different keys, and re-emitting either in the other's map changes what
    /// the file says. See [`TraceHeader::extra`].
    ///
    /// Empty for every segment this crate constructs itself.
    pub extra: Vec<(Value, Value)>,
}

impl SegmentInfo {
    /// A segment carrying only its sequence number.
    pub fn new(sequence: u64) -> Self {
        SegmentInfo {
            sequence,
            duration_ms: None,
            stream_id: None,
            continues: None,
            extra: Vec::new(),
        }
    }

    /// Whether `key` is written from one of this map's own fields —
    /// equivalently, on a segment that was decoded, whether the decode used
    /// it. See [`TraceHeader::writes_key`] for why the destructuring is
    /// exhaustive and why this is not "does the format define `key`".
    fn writes_key(&self, key: &str) -> bool {
        let SegmentInfo { sequence: _, duration_ms, stream_id, continues, extra: _ } = self;
        key == "sequence"
            || (key == "durationMs" && duration_ms.is_some())
            || (key == "streamId" && stream_id.is_some())
            || (key == "continues" && continues.is_some())
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
        // Last, so the segment's own keys keep the positions a reader expects.
        pairs.extend(store_entries(&self.extra, |k| self.writes_key(k)));
        Value::Map(pairs)
    }

    /// Decode the contents of a `"segment"` map.
    ///
    /// The caller has already established that the value is a map: a
    /// `"segment"` that is not one is an unusable optional value on the
    /// *header*, and goes to the header's store rather than failing the file.
    fn from_pairs(pairs: &[(Value, Value)]) -> Result<Self, MoqTraceError> {
        // `"sequence"` is the one key in the header whose absence or
        // unusability makes the header malformed: it is the sole ordering key
        // of a segmented stream, and a default would invent an order the file
        // never had.
        let mut info = SegmentInfo {
            sequence: required_uint(pairs, "sequence", "segment.sequence")?,
            duration_ms: find_uint(pairs, "durationMs"),
            stream_id: find_text(pairs, "streamId"),
            continues: find_bool(pairs, "continues"),
            extra: Vec::new(),
        };
        let extra = unrecognised(pairs, |k| info.writes_key(k));
        info.extra = extra;
        Ok(info)
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
    ///
    /// `None` when the file carried no `"appliesTo"` — and also when it
    /// carried one this crate could not read *whole*, in which case the array
    /// is kept verbatim in [`SamplingInfo::extra`]. An `"appliesTo"` of
    /// `[3, "x", 5]` read as `[3, 5]` would not be a partial answer: the key
    /// names the event types the drop policy touched, and a reader may treat
    /// every type absent from it as complete, so shortening the array reports
    /// a sampled event type as fully recorded.
    pub applies_to: Option<Vec<u64>>,
    /// Keys in the `"sampling"` map that this version of the crate could not
    /// use, kept verbatim and written back into that map. See
    /// [`TraceHeader::extra`].
    ///
    /// Empty for every sampling map this crate constructs itself.
    pub extra: Vec<(Value, Value)>,
}

impl SamplingInfo {
    /// Whether `key` is written from one of this map's own fields. See
    /// [`TraceHeader::writes_key`].
    fn writes_key(&self, key: &str) -> bool {
        let SamplingInfo {
            effective_rate,
            max_events_per_sec,
            drop_policy,
            dropped_total,
            dropped_segment,
            rule,
            rule_lang,
            applies_to,
            extra: _,
        } = self;
        (key == "effectiveRate" && effective_rate.is_some())
            || (key == "maxEventsPerSec" && max_events_per_sec.is_some())
            || (key == "dropPolicy" && drop_policy.is_some())
            || (key == "droppedTotal" && dropped_total.is_some())
            || (key == "droppedSegment" && dropped_segment.is_some())
            || (key == "rule" && rule.is_some())
            || (key == "ruleLang" && rule_lang.is_some())
            || (key == "appliesTo" && applies_to.is_some())
    }

    fn to_value(&self) -> Value {
        let mut pairs: Vec<(Value, Value)> = Vec::new();
        if let Some(r) = self.effective_rate {
            pairs.push((Value::Text("effectiveRate".into()), number_value(r)));
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
        // Last, so the map's own keys keep the positions a reader expects.
        pairs.extend(store_entries(&self.extra, |k| self.writes_key(k)));
        Value::Map(pairs)
    }

    /// Decode the contents of a `"sampling"` map. Infallible: the map has no
    /// required keys, so every value this cannot use goes to the store.
    ///
    /// The caller has already established that the value is a map; a
    /// `"sampling"` that is not one goes to the header's store.
    fn from_pairs(pairs: &[(Value, Value)]) -> Self {
        let effective_rate = find(pairs, "effectiveRate")
            .and_then(|v| match v {
                Value::Float(f) => Some(*f),
                Value::Integer(i) => i64::try_from(*i).ok().map(|n| n as f64),
                _ => None,
            })
            // The key is defined as a fraction in `(0.0, 1.0]`, and a value
            // outside the range its meaning allows is unusable on an optional
            // key. NaN fails this comparison too, which is the wanted answer:
            // there is no rate to report and the bytes go to the store.
            .filter(|r| *r > 0.0 && *r <= 1.0);
        let applies_to = match find(pairs, "appliesTo") {
            // All or nothing: one element that is not an event type ID makes
            // the array unusable entire, and it goes to the store from there.
            Some(Value::Array(items)) => items.iter().map(as_u64).collect::<Option<Vec<u64>>>(),
            _ => None,
        };
        let mut info = SamplingInfo {
            effective_rate,
            max_events_per_sec: find_uint(pairs, "maxEventsPerSec"),
            drop_policy: find_text(pairs, "dropPolicy").as_deref().map(DropPolicy::parse),
            dropped_total: find_uint(pairs, "droppedTotal"),
            dropped_segment: find_uint(pairs, "droppedSegment"),
            rule: find_text(pairs, "rule"),
            rule_lang: find_text(pairs, "ruleLang"),
            applies_to,
            extra: Vec::new(),
        };
        let extra = unrecognised(pairs, |k| info.writes_key(k));
        info.extra = extra;
        info
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
    ///
    /// `None` when the file carried no `"custom"` — and also when it carried
    /// one this map cannot hold exactly: a `"custom"` that is not a map, or
    /// one with a key that is not text, in which case the whole value is kept
    /// verbatim in [`TraceHeader::extra`]. Losing typed access is the smaller
    /// harm; nothing in the format gives `"custom"` keys meaning, so there is
    /// nothing to lose but convenience, and the bytes survive.
    ///
    /// A `"custom"` carrying one key twice takes the same route, a `BTreeMap`
    /// being unable to hold it either. That one is kept whole on the way in
    /// and written with the repeat dropped: a writer may not emit a map with a
    /// repeated key, so a rewrite keeps the first entry rather than both. See
    /// [`TraceHeader::extra`].
    ///
    /// `"custom"` has no store of its own. Every key in it belongs to whoever
    /// wrote the trace, so there is no such thing as an unrecognised key
    /// there: it is a passthrough, handed back key for key and written back
    /// as it was handed over — the value, not its encoding, which the two
    /// rules in [`TraceHeader::extra`] apply to here as well.
    pub custom: Option<BTreeMap<String, Value>>,
    /// Keys in the header map that this version of the crate could not use,
    /// kept verbatim.
    ///
    /// A key the format does not define lands here, and so does a key it
    /// *does* define carrying a value this crate cannot use — `"transport":
    /// 42`, an `"endTime"` with a fractional part, a `"segment"` that is not a
    /// map. Knowing more about a key must not mean preserving it less: the
    /// value is ignored for meaning, the field that would have held it reads
    /// `None`, and the entry is written back unchanged after the header's own
    /// keys.
    ///
    /// Dropping such a key instead would emit a valid file that looks as
    /// though it never carried it, and the tools that read a trace and write
    /// it back — a redaction pass, a filter, a re-segmentation — are exactly
    /// the ones a trace passes through on its way to someone else.
    ///
    /// "Unchanged" binds the value and not its encoding. On the way out, an
    /// integral float in a stored value is written as a CBOR integer and a
    /// byte string under RFC 8746's tag 64 as major type 2, at any depth,
    /// because SPEC.md's two encoding rules are about every byte this crate
    /// emits rather than only the keys it understood — the JavaScript
    /// implementation's decoder folds both shapes away before its own code
    /// sees them, so it could not emit either from a store however hard it
    /// tried. Nothing a comparison of the two values can see changes, with the
    /// single exception SPEC.md names: `-0.0` written as `0` loses its sign.
    ///
    /// A CBOR map may not carry one key twice, and this list can: it is an
    /// ordered list of pairs, not a map, whether it was populated by hand or
    /// from a file whose header repeated a key. So on the way out an entry
    /// naming a key the header writes from a field is dropped, and of two
    /// entries sharing a key the first is written — as it is for a map nested
    /// inside a stored value, which is a map this crate emits too.
    ///
    /// This is the header map's store only. [`SegmentInfo::extra`] and
    /// [`SamplingInfo::extra`] keep their own, because a private key on
    /// `"segment"` and a key of the same name at the top level are different
    /// keys.
    ///
    /// Empty for every header this crate constructs itself.
    pub extra: Vec<(Value, Value)>,
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
            extra: Vec::new(),
        }
    }

    /// Whether `key` is written from one of the header map's own fields —
    /// equivalently, on a header that was decoded, whether the decode used it.
    /// The `"segment"` and `"sampling"` maps answer for their own keys.
    ///
    /// Deliberately not "does the format define `key`". The two part company
    /// on a defined key whose value the decode could not use: such a key is
    /// treated as unrecognised, so its field stays `None` and the entry goes
    /// to [`TraceHeader::extra`], from where the encoder writes it back
    /// unchanged. Asking about the format's whole vocabulary instead would
    /// keep the key out of `extra` while no field holds it either, and merely
    /// reading the file would delete the value.
    ///
    /// The destructuring is exhaustive on purpose — no `..` — so a new field
    /// does not compile until it is answered for here. Both ways of getting
    /// the answer wrong are silent: a field left out has its key written
    /// twice, once from the field and once from `extra`, and a CBOR map with
    /// a duplicate key is malformed; a key wrongly claimed is dropped from
    /// every rewrite.
    fn writes_key(&self, key: &str) -> bool {
        let TraceHeader {
            protocol: _,
            perspective: _,
            detail: _,
            start_time: _,
            end_time,
            transport,
            source,
            endpoint,
            session_id,
            segment,
            sampling,
            custom,
            extra: _,
        } = self;
        // The four required keys are written whatever they hold.
        matches!(key, "protocol" | "perspective" | "detail" | "startTime")
            || (key == "endTime" && end_time.is_some())
            || (key == "transport" && transport.is_some())
            || (key == "source" && source.is_some())
            || (key == "endpoint" && endpoint.is_some())
            || (key == "sessionId" && session_id.is_some())
            || (key == "segment" && segment.is_some())
            || (key == "sampling" && sampling.is_some())
            || (key == "custom" && custom.is_some())
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
            // `"custom"` is a passthrough, but "handed back as it was handed
            // over" binds the value and not its encoding, exactly as it does
            // for a store: SPEC.md's two encoding rules are about every byte a
            // writer emits. The JavaScript implementation cannot emit either
            // shape from its `custom` either, its decoder having folded both
            // away, so normalising here is what keeps the two files identical.
            // A `BTreeMap<String, _>` cannot hold a duplicate or a non-text
            // key, so there is nothing else to reconcile.
            let custom_pairs: Vec<(Value, Value)> =
                custom.iter().map(|(k, v)| (Value::Text(k.clone()), normalised(v))).collect();
            pairs.push((Value::Text("custom".into()), Value::Map(custom_pairs)));
        }

        // Last, so the header's own keys keep the positions a reader expects
        // and the file stays diffable against one written without them. An
        // entry naming a key the header just wrote from a field is dropped
        // rather than written twice — a reader never produces one, but a
        // caller assembling a header by hand can.
        pairs.extend(store_entries(&h.extra, |k| h.writes_key(k)));

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

        // The four keys there is no header to construct without. An absent one
        // and an unusable one are the same fault and reported as one, with a
        // message that says which it was.
        let protocol = required_text(&pairs, "protocol", "protocol")?;
        let perspective = required_text(&pairs, "perspective", "perspective")?;
        let detail = required_text(&pairs, "detail", "detail")?;
        let start_time = required_uint(&pairs, "startTime", "startTime")?;

        // `"segment"` and `"sampling"` are optional, and an unusable optional
        // value must not fail the file: one that is not a map goes to the
        // header's store below and the reader proceeds as though the key were
        // absent — which for `"segment"` means reading the trace as
        // non-segmented. Rejecting the file instead would turn one unreadable
        // metadata value into the loss of every event behind it.
        let segment = match find(&pairs, "segment") {
            Some(Value::Map(segment_pairs)) => Some(SegmentInfo::from_pairs(segment_pairs)?),
            _ => None,
        };
        let sampling = match find(&pairs, "sampling") {
            Some(Value::Map(sampling_pairs)) => Some(SamplingInfo::from_pairs(sampling_pairs)),
            _ => None,
        };

        // `"custom"` is a passthrough with no store of its own, so it is kept
        // only when this map can hold it exactly: every key text, and no two
        // keys the same, since a `BTreeMap` would silently collapse those into
        // one. Anything else is unusable and the whole value goes to the
        // header's store, rather than handing back a `"custom"` that lost
        // something through a type that lies to every caller reading it.
        let custom = match find(&pairs, "custom") {
            Some(Value::Map(custom_pairs)) => custom_pairs
                .iter()
                .map(|(ck, cv)| ck.as_text().map(|s| (s.to_string(), cv.clone())))
                .collect::<Option<BTreeMap<String, Value>>>()
                .filter(|map| map.len() == custom_pairs.len()),
            _ => None,
        };

        let mut header = TraceHeader {
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
            extra: Vec::new(),
        };
        // Decided by what the decode above actually consumed, never by a list
        // of key names kept alongside it: the two differ exactly on a defined
        // key carrying a value no field could take, and that gap is where a
        // value gets silently deleted.
        let extra = unrecognised(&pairs, |k| header.writes_key(k));
        header.extra = extra;
        Ok(header)
    }
}

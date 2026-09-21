#[allow(dead_code)]
pub mod dispatch_check;
#[allow(dead_code)]
pub mod fields_json;

use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarIntError;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VectorFile {
    pub message_type: String,
    #[serde(default)]
    pub message_type_id: Option<String>,
    pub vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TestVector {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    pub hex: String,
    pub decoded: Option<serde_json::Value>,
    pub error: Option<String>,
    pub canonical: Option<bool>,
    /// Which conformance profiles this vector's expectation binds. `None` is
    /// the corpus's way of writing "all of them", and is what almost every
    /// vector says: a truncated frame is refused by anything that reads it.
    pub profiles: Option<Vec<String>>,
}

/// The conformance profile these runners implement.
///
/// This crate decodes a frame in order to hold it to the rules its draft
/// states for a receiver, which is what the corpus calls an endpoint. The
/// other profile belongs to something that carries bytes between endpoints
/// without terminating a session — it has to parse enough to find where each
/// frame ends and no more — and nothing in this repository runs the corpus
/// that way, so no vector here is left out for naming only that one.
#[allow(dead_code)]
pub const PROFILE: &str = "endpoint";

impl TestVector {
    #[allow(dead_code)]
    pub fn is_canonical(&self) -> bool {
        self.canonical.unwrap_or(true)
    }

    /// Whether this vector's expectation binds `profile`.
    ///
    /// A vector that names no profiles binds every one of them. A vector that
    /// names some binds those, which is how the corpus states a rule that one
    /// kind of consumer must enforce and another need not — a parameter in a
    /// message its definition does not name is a rule for a receiving
    /// endpoint, and bytes a forwarder passes through untouched.
    #[allow(dead_code)]
    pub fn applies_to(&self, profile: &str) -> bool {
        match &self.profiles {
            None => true,
            Some(named) => named.iter().any(|p| p == profile),
        }
    }

    /// Assert that `err` is the kind of failure this vector says it is.
    ///
    /// A negative vector carries an `error` field naming one of the corpus's
    /// categories. Until this existed every runner used that field as a
    /// boolean — `if vector.error.is_some() { assert!(result.is_err()) }` — so
    /// a vector built to prove that a truncated frame is refused passed just as
    /// well if the decoder rejected it for some entirely different reason, and
    /// a vector whose category was wrong could never say so.
    #[allow(dead_code)]
    pub fn assert_error(&self, err: &CodecError) {
        let Some(expected) = &self.error else {
            panic!("[{}] assert_error on a vector with no error category", self.id);
        };
        let actual = error_category(err);
        assert_eq!(
            actual, expected,
            "[{}] the decoder refused this for a different reason than the vector claims: \
             {err:?}",
            self.id
        );
    }
}

/// Which of the schema's error categories a decode failure belongs to.
///
/// The categories are the corpus's, not this crate's, and they are coarser than
/// [`CodecError`] by design: a vector says what a conforming decoder must
/// notice, and there is more than one defensible variant to notice most things
/// with. What they do pin down is the *kind* of complaint, which is what a
/// vector is evidence of.
///
/// - `incomplete` — the frame ended early. Nothing about the bytes present was
///   wrong; there were not enough of them.
/// - `unknown_message` — a type code this draft does not assign, on a control
///   message, a data stream or a datagram.
/// - `invalid_type` — a type code inside the form its draft defines, which the
///   draft separately names as invalid. Drafts 16 through 21 describe their
///   data-plane types as bit fields and then rule out particular combinations
///   within the form, so the enclosing form is assigned and the value is not.
///   One category for both spaces, because the two error variants that reach it
///   differ in which Type space was consulted and not in what went wrong.
/// - `invalid_parameter` — a parameter or property is wrong in itself: its
///   type, its length, its value's range, or its position in a delta-coded run.
///   A malformed filter value belongs here too, on both counts.
/// - `parameter_out_of_scope` — a parameter is well formed and appears in a
///   message its own definition does not name. Drafts 17, 18 and 19 require the
///   receiver to close over it; every draft before them says such a parameter
///   is ignored, so no vector on those drafts can claim it.
/// - `duplicate_parameter` — a parameter type appears twice where the draft
///   forbids repeating it.
/// - `payload_not_permitted` — an object carries a payload where its status or
///   its framing leaves no room for one.
/// - `invalid_value` — everything else a field can be wrong about, which is
///   most of the enum.
/// - `missing_parameter` — a parameter the message requires is absent. No
///   variant maps here: absence is not something this decoder detects, because
///   nothing in it knows which parameters a message requires. A vector claiming
///   it will therefore fail rather than pass quietly, which is the honest
///   outcome for a category the crate does not implement.
#[allow(dead_code)]
pub fn error_category(err: &CodecError) -> &'static str {
    match err {
        CodecError::UnexpectedEnd => "incomplete",
        CodecError::VarInt(VarIntError::UnexpectedEnd) => "incomplete",

        // A control message's declared Length is two rules in one variant, and
        // only one of the two directions is a truncation. Fields that ran past
        // the end wanted more bytes than the frame carried, which is what a
        // truncated vector is; fields that left bytes unread arrived complete
        // and disagreed with their own header, which is not. The variant keeps
        // the direction in prose because the useful number differs between
        // them, so this reads the prose.
        //
        // Reword either string in the codec and every truncated-frame vector
        // across the drafts stops being `incomplete` and starts being
        // `invalid_value`, which every one of them will say so about. The
        // coupling is real and it is loud, which is the pair of properties that
        // makes it safe to leave.
        CodecError::ControlMessageLengthMismatch { detail, .. }
            if *detail == "its fields ran past the end" =>
        {
            "incomplete"
        }

        CodecError::UnknownMessageType(_)
        | CodecError::UnknownStreamType(_)
        | CodecError::UnknownDatagramType(_) => "unknown_message",

        CodecError::DuplicateParameter(_) => "duplicate_parameter",

        // Its own category rather than a shade of `invalid_parameter`: the
        // parameter is well formed, and what is wrong is the message around
        // it. Drafts 17, 18 and 19 are the only ones that answer it with a
        // close, so it is also the one category whose absence from a draft is
        // a fact about the draft rather than about the corpus.
        CodecError::ParameterOutOfScope { .. } => "parameter_out_of_scope",

        CodecError::InvalidStreamTypeValue { .. }
        | CodecError::InvalidDatagramTypeValue { .. } => "invalid_type",

        CodecError::PayloadNotPermitted { .. } => "payload_not_permitted",

        CodecError::UnknownMessageParameter(_)
        | CodecError::ParameterLengthMismatch(_)
        | CodecError::ParameterValueOutOfRange { .. }
        | CodecError::TrackPropertyValueOutOfRange { .. }
        | CodecError::ParametersOutOfOrder(_, _)
        | CodecError::KeyDeltaOverflow(_, _)
        | CodecError::KeyValueFormatting { .. }
        // A filter parameter whose value is not the structure its type names,
        // and one whose End Group Delta carries the range out of the number
        // space, are both a parameter wrong in itself — its length in the first
        // case and its value's range in the second — which is what
        // `invalid_parameter` covers. They sat under the catch-all until
        // draft-20 gave the corpus vectors that claim the category: draft-20
        // rebuilt the LOCATION_FILTER value (Section 5.1.2) and the negative
        // vectors for its new shape are the first to reach either variant.
        | CodecError::SubscriptionFilterMalformed { .. }
        | CodecError::FilterEndGroupOverflow { .. }
        | CodecError::Kvp(_) => "invalid_parameter",

        _ => "invalid_value",
    }
}

/// Read one vector file, keeping the vectors whose expectations bind
/// [`PROFILE`].
///
/// The filter is here rather than in each of the fourteen runners because a
/// rule that one kind of consumer must enforce and another need not is a fact
/// about the corpus, not about any one suite, and fourteen copies of it would
/// drift. `tests/vector_profiles.rs` reads the same files without the filter
/// and reports what it leaves out, so what is dropped here is written down
/// somewhere that fails when it changes.
#[allow(dead_code)]
pub fn load_vectors(path: &Path) -> VectorFile {
    let data = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("cannot read {}: {e} — did you init the submodule?", path.display())
    });
    let mut file: VectorFile = serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()));
    file.vectors.retain(|vector| vector.applies_to(PROFILE));
    assert!(
        !file.vectors.is_empty(),
        "{}: every vector in this file names a profile other than {PROFILE}, so the suite \
         reading it asserts nothing at all",
        path.display()
    );
    file
}

pub fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

/// Every codec vector file in the corpus, as a path relative to
/// [`vectors_dir`].
///
/// Read from the directory tree rather than from a list, so a draft or a file
/// added upstream is swept rather than quietly ignored — and asserted to be
/// large, because a walk that lost the corpus returns an empty answer that
/// every sweep built on it reports as clean.
#[allow(dead_code)]
pub fn vector_files() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
            panic!("cannot read {}: {e} — did you init the submodule?", dir.display())
        });
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "json") {
                out.push(path);
            }
        }
    }

    let root = vectors_dir().join("transport");
    let mut found = Vec::new();
    walk(&root, &mut found);
    let mut names: Vec<String> = found
        .iter()
        .filter(|p| p.to_string_lossy().replace('\\', "/").contains("/codec/"))
        .map(|p| {
            p.strip_prefix(vectors_dir())
                .expect("under the corpus root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    names.sort();
    assert!(
        names.len() > 100,
        "{}: found {} codec vector files, which is far fewer than the corpus has — this is the \
         walk having lost the corpus, not the corpus having shrunk",
        root.display(),
        names.len()
    );
    names
}

/// Every committed **message** vector this codec refuses on purpose: `(draft
/// directory, file, vector id)`.
///
/// The list is empty, and `known_wrong_vectors.rs` holds drafts 17 through 20
/// to that: every message vector claiming a successful decode must decode, on
/// every one of them.
///
/// # What the empty list means
///
/// Neither shape that could populate it survives as a row.
///
/// One is a parameter written with an outer length its own definition does not
/// give it, which is simply wrong bytes — draft-17 Section 9.3 defines a
/// Location as "Two consecutive varints (Group, Object)", whether or not a
/// vector says otherwise — and the answer is to correct the bytes rather than
/// to record the vector here.
///
/// The other is a vector whose bytes are right and whose message is wrong: a
/// Message Parameter in a message its own definition does not name — EXPIRES in
/// a FETCH_OK, or LARGEST_OBJECT in a draft-17 PUBLISH_OK, which is a message
/// type of its own there rather than a REQUEST_OK. Draft-17 Section 9.3.1 and
/// drafts 18 through 20 Section 10.2.1: "Each Message Parameter definition
/// indicates the message types in which it can appear. If it appears in some
/// other type of message, the receiving endpoint MUST close the connection with
/// a PROTOCOL_VIOLATION." Drafts 07 through 16 end that sentence "it MUST be
/// ignored", so the rule belongs to draft-17 and later and to no older draft.
///
/// A vector like that has two honest futures: drop the parameter and keep a
/// positive vector, or keep the parameter and say what it is. The second needs
/// an error category for parameter scope in the corpus; with one, such a vector
/// is a negative vector asserting `parameter_out_of_scope` and runs in the
/// ordinary suites rather than being stepped over — which is the difference
/// between a rule being tested and a rule being tolerated.
///
/// A row comes back only to record a disagreement this repository has decided
/// to keep, and never to quiet one.
#[allow(dead_code)]
pub const KNOWN_WRONG_MESSAGE_VECTORS: &[(&str, &str, &str)] = &[];

/// Every object status in the vector's expected decode that the draft does
/// not assign, in the order the walk meets them. Empty for a vector the draft
/// permits — and equally empty for a vector carrying no status at all, which is
/// why [`statuses_in`] exists and names the JSON keys this reads.
///
/// Draft-11 Section 9.1.1.1 and draft-12 Section 9.2.1.1 assign 0x0, 0x1, 0x3
/// and 0x4 only, name 0x4 "End of Track", and say every other value SHOULD be
/// treated as a protocol error and terminate the session. A data-stream vector
/// seeded from the draft-08 numbering, where 0x4 is End of Track and Group and
/// 0x5 is End of Track, carries 0x5 on those drafts and is exactly what this
/// reports. No vector on any draft carries a status its own draft leaves
/// unassigned.
///
/// So this reports rather than excuses. `known_wrong_vectors.rs` sweeps every
/// draft's data-stream corpus through it and asserts the row set is empty, with
/// a list of documented exceptions that is itself empty — a disagreement has to
/// be written down with a reason before it can be tolerated, and writing one
/// down is what makes it visible. The runners themselves skip nothing: a vector
/// carrying an unassigned status fails its own suite as well, which is what a
/// skip would quietly prevent.
///
/// `assigned` should be the draft module's own `ObjectStatus::ALL` mapped
/// through `as_u64`, so this never becomes a second, drifting copy of the
/// assigned set.
#[allow(dead_code)]
pub fn unassigned_statuses(vector: &TestVector, assigned: &[u64]) -> Vec<u64> {
    statuses_in(vector).into_iter().filter(|code| !assigned.contains(code)).collect()
}

/// Every object status in the vector's expected decode, assigned or not, in the
/// order the walk meets them.
///
/// Separate from [`unassigned_statuses`] so a caller can tell "this vector
/// carries no status" from "this walk found no status", which are the same
/// empty answer and not the same fact. A sweep that never finds a status field
/// on a whole draft has stopped reading the corpus, and
/// `known_wrong_vectors.rs` asserts against exactly that.
///
/// # Which JSON keys count
///
/// `object_status`, which drafts 07-14 use everywhere and drafts 15-21 keep on
/// the datagram header, and `status`, which is what drafts 15-21 call the same
/// field inside a subgroup object. Drafts 15-21's `subgroup.json` and
/// `fetch-header.json` carry no `object_status` key at all, so a walk that knew
/// only the first name read none of those six drafts' subgroup objects — and
/// reported a clean sweep over a corpus it had not opened.
///
/// A wire value is read whether the corpus writes it as a decimal string, which
/// is what it does today, or as a JSON number. A status this function cannot
/// read is a status it did not check, and every caller would take that for
/// "assigned".
#[allow(dead_code)]
pub fn statuses_in(vector: &TestVector) -> Vec<u64> {
    const STATUS_KEYS: [&str; 2] = ["object_status", "status"];

    fn code_of(value: &serde_json::Value) -> Option<u64> {
        match value {
            serde_json::Value::String(s) => s.parse::<u64>().ok(),
            other => other.as_u64(),
        }
    }

    fn walk(value: &serde_json::Value, found: &mut Vec<u64>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if STATUS_KEYS.contains(&key.as_str()) {
                        if let Some(code) = code_of(child) {
                            found.push(code);
                        }
                    } else {
                        walk(child, found);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, found);
                }
            }
            _ => {}
        }
    }

    let mut found = Vec::new();
    if let Some(decoded) = &vector.decoded {
        walk(decoded, &mut found);
    }
    found
}

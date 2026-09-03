//! Writes this crate's half of the shared `.moqtrace` corpus.
//!
//! ```text
//! cargo run -p moqtap-trace --example generate_corpus
//! ```
//!
//! The JavaScript half comes from `bun run src/__tests__/corpus/generate.ts`
//! in `moqtap-js/packages/trace`. Run both after changing a case, and commit
//! the bytes: `tests/corpus_tests.rs` compares the two files, so regenerating
//! only one turns a deliberate change into a failure that names the file
//! nobody updated.
//!
//! The two files for a case are not expected to be byte-identical, and the
//! test does not ask them to be. `ciborium` writes an integer in the narrowest
//! form that holds it while `cbor-x` writes a BigInt in eight bytes, and the
//! two order map keys differently. Both are legal CBOR carrying the same
//! values, which is exactly the property the corpus is for.

// The case definitions are shared with `tests/corpus_tests.rs`, which is a
// separate crate from this example, so the module is pulled in by path rather
// than imported.
#[path = "../tests/corpus/mod.rs"]
mod corpus;

use std::fs;
use std::path::{Path, PathBuf};

use corpus::{authored_cases, v2_basic, v2_segmented, Case, CORPUS_MISSING_MESSAGE};
use moqtap_trace::writer::MoqTraceWriter;

/// Byte offset of the format version in a segment preamble.
const VERSION_OFFSET: usize = 8;

/// Serialize one case as a single-segment file.
fn encode(case: &Case) -> Vec<u8> {
    let mut writer = MoqTraceWriter::new(Vec::new(), &case.header).expect("write header");
    for event in &case.events {
        writer.write_event(event).expect("write event");
    }
    writer.into_inner().expect("flush")
}

/// Serialize several cases as one segmented stream.
fn encode_segments(cases: &[Case]) -> Vec<u8> {
    let mut iter = cases.iter();
    let first = iter.next().expect("at least one segment");
    let mut writer = MoqTraceWriter::new(Vec::new(), &first.header).expect("write header");
    for event in &first.events {
        writer.write_event(event).expect("write event");
    }
    for case in iter {
        writer.start_segment(&case.header).expect("start segment");
        for event in &case.events {
            writer.write_event(event).expect("write event");
        }
    }
    writer.into_inner().expect("flush")
}

/// Restamp a file's declared version.
///
/// A version-1 file is byte-for-byte a version-2 file that happens to carry
/// none of the keys version 2 added — SPEC.md says exactly that — so this is
/// the whole difference, not an approximation of one. The writer only emits
/// version 2, which is correct; a corpus still needs the older declaration.
fn with_version(mut bytes: Vec<u8>, version: u32) -> Vec<u8> {
    bytes[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
    bytes
}

fn write(dir: &Path, case_name: &str, bytes: &[u8]) {
    let case_dir = dir.join(case_name);
    fs::create_dir_all(&case_dir).expect("create case directory");
    fs::write(case_dir.join("rust.moqtrace"), bytes).expect("write case file");
    println!("{case_name}/rust.moqtrace  {} bytes", bytes.len());
}

fn main() {
    // An explicit output directory, or wherever the corpus is found. The
    // default writes into the pinned submodule, which is a real checkout but
    // not the one corpus development commits from; naming the path keeps both
    // generators writing into the same directory.
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .or_else(corpus::corpus_dir)
        .expect(CORPUS_MISSING_MESSAGE);
    println!("corpus: {}", dir.display());

    for (name, case) in authored_cases() {
        let bytes = encode(&case);
        let bytes = if name == "v1-basic" { with_version(bytes, 1) } else { bytes };
        write(&dir, name, &bytes);
    }

    write(&dir, "v2-segmented", &encode_segments(&v2_segmented()));

    // Three bytes short of the end. The last event is longer than that, so the
    // cut is guaranteed to land inside it rather than on a clean boundary.
    let basic = encode(&v2_basic());
    write(&dir, "v2-truncated", &basic[..basic.len() - 3]);
}

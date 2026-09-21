//! What the vector runners leave out, and on whose authority.
//!
//! Not every rule binds every consumer. An endpoint is held to everything a
//! draft states for a receiver; something that carries bytes between endpoints
//! without terminating a session is held only to what it must parse to find
//! where a frame ends. A vector asserting that some bytes MUST be refused can
//! be true of the first and not of the second, and a corpus with no way to say
//! so makes the second fail tests it was never built to pass.
//!
//! The corpus says so with a `profiles` field, and this crate answers
//! [`test_vectors::PROFILE`] — `endpoint`, because these runners decode a frame
//! in order to hold it to its draft. [`test_vectors::load_vectors`] drops what
//! does not bind that profile, in one place rather than in each of the
//! runners, and this file is the other half: it reads the same files without
//! the filter and asserts what the filter can be leaving out.
//!
//! # Why an empty answer is not trusted here
//!
//! Every assertion below is of the form "no vector does X", which is also what
//! a sweep that read nothing produces — and a `profiles` key spelled one way in
//! the corpus and another in the parser produces exactly that, silently, while
//! [`test_vectors::TestVector::applies_to`] answers `true` for everything. So
//! the sweep refuses three ways of reading nothing: a corpus with no vector
//! files, a file with no vectors, and a corpus in which the field never
//! appears.
//!
//! # What this catches, observed by making each change and running it
//!
//! Renaming the field in `TestVector` to a spelling the corpus does not use:
//!
//! ```text
//! thread 'the_profile_field_is_read_and_not_merely_declared' panicked at
//! crates\moqtap-codec\tests\vector_profiles.rs:
//! no vector in the whole corpus parsed a `profiles` field, though 4 of them
//! carry one in their JSON. The parser and the corpus disagree about the key
//! name, and every vector is being treated as binding every profile.
//! ```
//!
//! Marking one restated vector `["forwarder"]`, which is the shape of a vector
//! these runners would have to leave out:
//!
//! ```text
//! thread 'nothing_in_the_corpus_is_left_out_of_these_runs' panicked at
//! crates\moqtap-codec\tests\vector_profiles.rs:
//! assertion `left == right` failed: these runners answer "endpoint", so every
//! vector on the left is one no suite in this crate reads. Each needs a reason
//! recorded here, or the corpus is asserting something this crate cannot.
//!   left: ["transport/draft19/codec/messages/fetch-ok.json [with-params-and-properties]"]
//!  right: []
//! ```
//!
//! Putting the same field on a vector that decodes:
//!
//! ```text
//! thread 'a_profile_narrows_a_refusal_and_never_a_decode' panicked at
//! crates\moqtap-codec\tests\vector_profiles.rs:
//! transport/draft19/codec/messages/fetch-ok.json [more-data] names profiles and
//! decodes. Bytes decode to the same value for every reader, so a profile on a
//! positive vector claims something the corpus cannot mean.
//! ```

mod test_vectors;

use test_vectors::{vector_files, vectors_dir, VectorFile, PROFILE};

/// The profile names the schema admits.
///
/// Restated here rather than read from the schema because this is the list the
/// *crate* understands: a name added upstream that nothing here answers to
/// would otherwise be dropped into the "not this profile" bucket and silently
/// remove vectors from every run.
const KNOWN: &[&str] = &["endpoint", "forwarder"];

/// Load one file without the profile filter [`test_vectors::load_vectors`]
/// applies, which is the point: this file measures what that filter removes.
fn load_unfiltered(relative: &str) -> VectorFile {
    let path = vectors_dir().join(relative);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

/// The parser reads the key the corpus writes.
///
/// The failure this guards is not a wrong answer but a uniform one: a mismatched
/// key name makes `profiles` `None` for every vector, `applies_to` `true` for
/// every vector, and every other assertion in this file pass over an empty set.
#[test]
fn the_profile_field_is_read_and_not_merely_declared() {
    let mut parsed = 0usize;
    let mut in_json = 0usize;

    for relative in vector_files() {
        let raw = std::fs::read_to_string(vectors_dir().join(&relative)).expect("readable");
        in_json += raw.matches("\"profiles\"").count();
        for vector in load_unfiltered(&relative).vectors {
            if vector.profiles.is_some() {
                parsed += 1;
            }
        }
    }

    assert!(
        parsed > 0,
        "no vector in the whole corpus parsed a `profiles` field, though {in_json} of them carry \
         one in their JSON. The parser and the corpus disagree about the key name, and every \
         vector is being treated as binding every profile."
    );
    assert_eq!(
        parsed, in_json,
        "the parser read a different number of profile fields than the corpus writes"
    );
}

/// A profile narrows what a refusal claims, and a decode claims the same thing
/// for everyone.
#[test]
fn a_profile_narrows_a_refusal_and_never_a_decode() {
    for relative in vector_files() {
        for vector in load_unfiltered(&relative).vectors {
            let Some(named) = &vector.profiles else { continue };

            assert!(
                vector.decoded.is_none(),
                "{relative} [{}] names profiles and decodes. Bytes decode to the same value for \
                 every reader, so a profile on a positive vector claims something the corpus \
                 cannot mean.",
                vector.id
            );
            assert!(
                !named.is_empty(),
                "{relative} [{}] names an empty profile list, which binds nobody",
                vector.id
            );
            for name in named {
                assert!(
                    KNOWN.contains(&name.as_str()),
                    "{relative} [{}] names profile {name:?}, which this crate does not know. A \
                     profile it cannot place is one it would drop the vector for.",
                    vector.id
                );
            }
            assert_ne!(
                vector.error.as_deref(),
                Some("incomplete"),
                "{relative} [{}] restricts a truncation to some readers. A frame that ended early \
                 ended early for everyone that reads it, whatever they do with the rest.",
                vector.id
            );
        }
    }
}

/// Nothing in the corpus is outside what these runners assert.
///
/// The list is empty and that is the strong claim, not a weak one: every vector
/// the corpus ships is read by a suite here. A row appears only when the corpus
/// gains a rule this crate is not the right consumer for, and it has to be
/// written down with the reason before it can be tolerated.
#[test]
fn nothing_in_the_corpus_is_left_out_of_these_runs() {
    let mut skipped: Vec<String> = Vec::new();
    let mut read = 0usize;

    for relative in vector_files() {
        let file = load_unfiltered(&relative);
        assert!(
            !file.vectors.is_empty(),
            "{relative}: no vectors — an empty file cannot be told from a clean one"
        );
        for vector in file.vectors {
            read += 1;
            if !vector.applies_to(PROFILE) {
                skipped.push(format!("{relative} [{}]", vector.id));
            }
        }
    }

    assert!(read > 1000, "swept {read} vectors, which is far fewer than the corpus holds");
    skipped.sort();
    assert_eq!(
        skipped,
        Vec::<String>::new(),
        "these runners answer {PROFILE:?}, so every vector on the left is one no suite in this \
         crate reads. Each needs a reason recorded here, or the corpus is asserting something \
         this crate cannot."
    );
}

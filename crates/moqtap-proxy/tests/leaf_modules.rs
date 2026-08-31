//! Three modules name nothing else in this crate, and that is load-bearing.
//!
//! `instrument`, `qlog` and `types` sit below every consumer they have —
//! `instrument` is reached from nine modules, `types` from fourteen — and none
//! of the three reaches back. That is not a style preference: a module with no
//! inward edge can be read, replaced or compiled on its own, and a single
//! `use crate::…` added to one of them takes that away without changing
//! anything a reader would notice.
//!
//! Nothing in Rust records the property, so nothing enforces it either. A
//! module's position in the graph is not a declaration; it is the residue of
//! what its `use` lines happen to say. This file reads the source and checks.
//!
//! # What it does not check
//!
//! `super::` paths inside a submodule, which is how `parser::control` and
//! `shape::bucket` reach their siblings, and which is a different property.
//! And doc comments: an intra-doc link to `crate::framer::ObjectFramer` names
//! a module without depending on it, and several of these files carry one
//! deliberately, so comment lines are skipped rather than counted.

use std::path::PathBuf;

/// Every top-level module that names nothing else in this crate.
const LEAVES: &[&str] = &["instrument.rs", "qlog.rs", "types.rs"];

fn source(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", name].iter().collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The lines of `name` that are code rather than comment.
fn code_lines(name: &str) -> Vec<(usize, String)> {
    source(name)
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.to_owned()))
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .collect()
}

/// # What this catches, observed by adding one `use` line
///
/// Adding `use crate::error::ProxyError;` to `instrument.rs` fails with:
///
/// ```text
/// instrument.rs is not a leaf: it names this crate at line 32
///   use crate::error::ProxyError;
/// ```
#[test]
fn the_leaf_modules_name_nothing_in_this_crate() {
    for name in LEAVES {
        for (number, line) in code_lines(name) {
            assert!(
                !line.contains("crate::"),
                "{name} is not a leaf: it names this crate at line {number}\n  {}",
                line.trim()
            );
        }
    }
}

/// The list above is a list of leaves, not the list of modules.
///
/// Without this, a module that stopped being a leaf could be quietly struck
/// from `LEAVES` and the test above would keep passing on a shorter list. The
/// count is what a deletion has to argue with.
#[test]
fn the_leaf_list_still_has_three_entries() {
    assert_eq!(
        LEAVES.len(),
        3,
        "a module joining or leaving this list is a change to the crate's shape, \
         not a change to a test fixture"
    );
    for name in LEAVES {
        assert!(!source(name).is_empty(), "{name} is empty or missing");
    }
}

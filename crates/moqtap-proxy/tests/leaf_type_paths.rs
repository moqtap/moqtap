//! The five leaf types answer to the paths they have always answered to.
//!
//! `ProxySide`, `Leg`, `ObjectMeta`, `BypassReason` and `DataStreamType` were
//! defined in five different modules and are defined in one. A consumer holds
//! them at `event::ProxySide`, `transport::Leg`, `framer::ObjectMeta`,
//! `framer::BypassReason` and `parser::data::DataStreamType`, and every one of
//! those paths still resolves — through a re-export rather than a definition,
//! which a consumer cannot see and should not have to.
//!
//! This is written as a test rather than a promise in a doc comment because a
//! re-export is deletable and a doc comment does not notice.
//!
//! # What this catches, observed by demoting each `pub use` to a `use`
//!
//! Four re-exports carry the five types, and each was demoted in turn. Every
//! one fails here and **nowhere else** — no module of this crate reaches any of
//! the five through its old path any more, so the only thing a re-export is
//! still holding up is this file and the consumers it stands in for:
//!
//! ```text
//! error[E0603]: enum `ProxySide` is private
//!   --> tests/leaf_type_paths.rs:28:26
//! error[E0603]: enum `BypassReason` is private
//!   --> tests/leaf_type_paths.rs:29:28
//! error[E0603]: struct `ObjectMeta` is private
//!   --> tests/leaf_type_paths.rs:29:42
//! error[E0603]: enum `DataStreamType` is private
//!   --> tests/leaf_type_paths.rs:30:33
//! error[E0603]: enum `Leg` is private
//!   --> tests/leaf_type_paths.rs:31:30
//! ```
//!
//! That was not true when the gate was first run: demoting three of the four
//! failed inside the crate instead, on a `use` and two full paths that had been
//! missed. A re-export that something inside the crate still needs cannot fail
//! for the reason this file is about.
//!
//! # Why the exhaustive match
//!
//! `ProxySide` is not `#[non_exhaustive]`, so a downstream observer may match
//! it with four arms and no wildcard. That compiles only while the enum has
//! exactly those four variants **and** the path reaches the same enum, so the
//! match below restates that constraint where this crate's own test suite can
//! see it. A fifth variant breaks it here first.
//!
//! The other four are named as types rather than matched: `ObjectMeta` is a
//! struct a consumer reads fields off, `BypassReason` is `#[non_exhaustive]`
//! and cannot be matched exhaustively from outside at all, and `Leg` and
//! `DataStreamType` are keyed on rather than enumerated.

use moqtap_proxy::event::ProxySide;
use moqtap_proxy::framer::{BypassReason, ObjectMeta};
use moqtap_proxy::parser::data::DataStreamType;
use moqtap_proxy::transport::Leg;

/// Name each of the five at the path it has always had.
///
/// A function signature is enough: if any path stopped resolving this file
/// would not compile, and a test that never runs a line still has to build.
#[test]
fn every_leaf_type_still_answers_to_its_historical_path() {
    fn takes_all(_: ProxySide, _: Leg, _: DataStreamType, _: BypassReason, _: &ObjectMeta) {}

    let _ = takes_all as fn(ProxySide, Leg, DataStreamType, BypassReason, &ObjectMeta);
}

/// Four arms, no wildcard — the shape a downstream observer compiles with.
#[test]
fn proxy_side_still_has_exactly_four_variants() {
    fn name(side: ProxySide) -> &'static str {
        match side {
            ProxySide::ClientToProxy => "client to proxy",
            ProxySide::ProxyToRelay => "proxy to relay",
            ProxySide::RelayToProxy => "relay to proxy",
            ProxySide::ProxyToClient => "proxy to client",
        }
    }

    assert_eq!(name(ProxySide::ClientToProxy), "client to proxy");
    assert_eq!(name(ProxySide::ProxyToClient), "proxy to client");
}

/// `Leg` has two, and they are not the two `ProxySide` shares names with.
///
/// The two enums are the pair the crate's own docs warn about — a leg is a
/// connection, a side is a direction over one — so this pins the count that
/// makes them different rather than the names that make them look alike.
#[test]
fn leg_still_has_exactly_two_variants() {
    fn name(leg: Leg) -> &'static str {
        match leg {
            Leg::Client => "client",
            Leg::Upstream => "upstream",
        }
    }

    assert_eq!(name(Leg::Client), "client");
    assert_eq!(name(Leg::Upstream), "upstream");
}

/// A data stream is a subgroup or a fetch, and the framer keys on which.
#[test]
fn data_stream_type_still_has_exactly_two_variants() {
    fn is_fetch(kind: DataStreamType) -> bool {
        match kind {
            DataStreamType::Fetch => true,
            DataStreamType::Subgroup => false,
        }
    }

    assert!(is_fetch(DataStreamType::Fetch));
    assert!(!is_fetch(DataStreamType::Subgroup));
}

//! Numbers the engine, the socket adapter and their tests all have to agree on.
//!
//! All `pub`: an integration test is a separate crate, so a `pub(crate)`
//! constant would force each test to restate the value. The PRNG stream ids are
//! `pub` for the same reason but live beside the generator in [`crate::rng`].

/// The measured floor on `std::thread::sleep`'s wake latency, nanoseconds.
///
/// **Measured on Windows 11 build 26200, x86_64. Linux and macOS are
/// unmeasured**, and on Linux `thread::sleep` becomes `clock_nanosleep` against
/// an hrtimer, which is not tick-bound in the same way.
///
/// Reported, never enforced: a delay model finer than the wake latency is not
/// an error, only one whose fine structure this host cannot render. It exists
/// so a caller reading [`crate::stats::StatsSnapshot`] can explain a release
/// error it is already seeing, and inherits the qualifier with the number.
pub const RELEASE_FLOOR_NS: u64 = 550_000;

/// The release path's batching quantum, nanoseconds — how much work one
/// wake-up of the release thread commits to.
///
/// Distinct from [`RELEASE_FLOOR_NS`], which measures the platform where this
/// is a chosen value. It sits deliberately below the measured wake latency so
/// the quantum is never the binding constraint and an observed lateness can be
/// attributed to the platform. Re-measuring the floor does not move it.
pub const RELEASE_SLICE_NS: u64 = 500_000;

/// Bound on the shim's held-datagram queue when the direction has no
/// [`crate::model::RateModel`] to supply a bound of its own.
///
/// There is no "unbounded" option: an unbounded queue inside an adapter that
/// answers `Ok(())` is a memory leak that presents as a latency bug.
pub const DEFAULT_QUEUE_BYTES: u64 = 4 * 1024 * 1024;

/// Fields per non-header line of [`crate::log::DecisionLog::render`].
///
/// The render gate asserts against this rather than against a literal, so
/// widening a record cannot pass by editing the test's own idea of the width.
pub const RECORD_FIELDS: usize = 11;

/// The first line of [`crate::log::DecisionLog::render`], byte for byte.
///
/// Frozen so a gate fixture stays hand-writable. The determinism gate
/// byte-compares a rendered log against `tests/fixtures/pattern_mode_gate.log`,
/// which is written by hand from the model rather than by saving what the
/// engine produced — a fixture blessed from the code under test only proves
/// that code consistent with itself. A hand-written fixture can state every
/// column except the header, so the header is stated here once.
///
/// The leading `#` is load-bearing:
/// [`crate::log::DecisionLog::diff_fixture`] drops every line whose first
/// non-whitespace byte is `#` from both sides, which lets the fixture carry its
/// own derivation as comments inside the file the comparison reads. No record
/// line can collide with that rule — every [`crate::log::Record`] field renders
/// as a decimal integer.
pub const RECORD_HEADER: &str = "# quinn-netem decision-log v1 seq direction \
verdict cause wire_bytes now_ns release_ns dup_release_ns corrupt_offset \
corrupt_bit queue_backlog_bytes";

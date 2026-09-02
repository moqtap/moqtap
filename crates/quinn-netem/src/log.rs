//! The decision log: what the engine decided, as integers, and how a recorded
//! run is compared against a committed fixture.
//!
//! # Why the record holds nothing but integers
//!
//! A log is the evidence for "the same seed gives the same run", so everything
//! it records must be a function of the seed alone. Every [`Record`] field is a
//! `u8`, `u32` or `u64`, supplied by the caller or computed by integer
//! arithmetic here. That rules out:
//!
//! - **Clocks**, which differ between two runs of one seed by definition. Time
//!   here is the caller-supplied [`Tick`].
//! - **Floating point**, not because formatting is unstable but because the
//!   bits need not be: `ln`, `exp`, `powf` and `cos` are documented by std as
//!   permitted to differ between platforms.
//! - **Anything iterated out of a `HashMap`.** The default hasher is seeded per
//!   instance, so two maps in one process already iterate in different orders.
//! - **Addresses, ports, thread ids, pointers, allocation order, and the
//!   segment index inside a GSO batch** — properties of the run, not the seed.
//!
//! `wire_bytes` looks like an exception and is not: it comes from the peer's
//! address family only through [`crate::wire::wire_bytes`], which maps a family
//! onto a fixed header size. A queue depth read back from the OS would not
//! qualify; the backlog recorded here is the one this crate computed itself.
//!
//! # Rendering uses line feeds and nothing else
//!
//! A fixture is committed to git and compared on three platforms.
//! [`DecisionLog::render`] emits `\n` and never `\r\n`, and
//! [`DecisionLog::diff_fixture`] strips a trailing `\r` from both sides, so a
//! checkout that predates the repo's `.gitattributes` cannot turn the
//! acceptance criterion into a platform-dependent coin flip.
//!
//! # Comparison returns a value instead of asserting
//!
//! [`DecisionLog::diff_fixture`] returns `Result<(), FixtureMismatch>` rather
//! than asserting internally: a comparison helper returning `()` is
//! indistinguishable at every call site from one with an empty body. A returned
//! value cannot be faked that way, and a body of `Ok(())` is caught by the
//! negative tests here — every helper in this module that could pass vacuously
//! ships with a test proving it fails on bad input.

use std::fmt::Write as _;

use crate::consts::RECORD_HEADER;
use crate::engine::Decision;
use crate::{Direction, Tick};

/// One decision, as integers and enum discriminants only.
///
/// The field order below is the column order of
/// [`DecisionLog::render`] and of [`crate::consts::RECORD_HEADER`]; the three
/// are one ordering and must stay one ordering, because that is what makes a
/// fixture hand-writable and hand-readable.
///
/// The module header explains what is excluded from this struct and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The direction's own monotone datagram counter, from 0.
    pub seq: u64,
    /// [`Direction`]'s discriminant.
    pub direction: u8,
    /// [`crate::engine::Verdict`]'s discriminant.
    pub verdict: u8,
    /// [`crate::engine::DropCause`]'s discriminant. Normalised on the way in:
    /// a decision that is not a drop always records
    /// [`crate::engine::DropCause::NotDropped`], whatever the `cause` field of
    /// the [`Decision`] happened to hold.
    pub cause: u8,
    /// On-wire size: payload plus the IP and UDP headers the link charges for.
    pub wire_bytes: u32,
    /// The tick the decision was taken at.
    pub now_ns: u64,
    /// The tick the datagram was released at.
    pub release_ns: u64,
    /// `u64::MAX` when there is no duplicate.
    ///
    /// A sentinel rather than an `Option`, because the log format is one
    /// decimal integer per column and an absent value still has to occupy its
    /// column. `u64::MAX` is safe as a sentinel: it is 584 years of
    /// nanoseconds, and a release tick is nanoseconds since the profile was
    /// armed.
    pub dup_release_ns: u64,
    /// `u32::MAX` when there is no corruption.
    ///
    /// A sentinel for `dup_release_ns`'s reason. `u32::MAX` is safe: the offset
    /// is an index into a datagram payload, which cannot exceed 65 507 bytes.
    pub corrupt_offset: u32,
    /// The bit flipped, `[0, 7]`; meaningless, and recorded as `0`, when
    /// `corrupt_offset` is `u32::MAX`.
    pub corrupt_bit: u8,
    /// On-wire bytes still queued behind this datagram after this decision.
    pub queue_backlog_bytes: u64,
}

/// A recorded run of decisions.
///
/// Off by default at the live control handle, and that default is not timidity:
/// a hundred-thousand-record log is a hundred thousand records of allocation
/// growth on the datagram path, which a shim sitting in front of a production
/// proxy must not do unasked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionLog {
    records: Vec<Record>,
}

/// Where a fixture comparison first differed.
///
/// Returning this — rather than asserting inside the comparison and returning
/// `()` — is what makes the comparison testable at all; the module header gives
/// the measurement that forced it.
///
/// It names *where*, not just *whether*, because a hash would say nothing about
/// where and a hundred-thousand-record log needs where. [`Self::line`] is a
/// record index, which is the number someone re-deriving a hand-computed
/// fixture actually needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureMismatch {
    /// 0-based index of the first differing line, counted **after** comment
    /// lines, blank lines and the header have been dropped from both sides —
    /// i.e. the record index, not the file line number.
    pub line: usize,
    /// The fixture's line at `line`, or `""` past its end.
    pub expected: String,
    /// The rendered log's line at `line`, or `""` past its end.
    pub actual: String,
}

impl std::fmt::Display for FixtureMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "decision-log record {} differs\n  expected: `{}`\n    actual: `{}`",
            self.line, self.expected, self.actual
        )
    }
}

impl std::error::Error for FixtureMismatch {}

impl DecisionLog {
    /// Append one decision.
    ///
    /// `wire_bytes` is the on-wire size, computed by
    /// [`crate::wire::wire_bytes`]; passing a payload length here would make
    /// every recorded byte count disagree with what the rate models charged.
    pub fn push(&mut self, dir: Direction, seq: u64, wire_bytes: u32, now: Tick, d: &Decision) {
        // `Decision::cause` is read through the accessor, not the field. The
        // field is public so a test can build an expected `Decision`, which
        // means it can also hold a stale cause under a non-drop verdict; the
        // accessor is what defines "the cause of a decision that is not a
        // drop is `NotDropped`". Recording the raw field would let one
        // impairer emit two different logs for the same behaviour.
        let cause = d.cause();
        let (corrupt_offset, corrupt_bit) = match d.corrupt {
            Some(site) => (site.byte_offset, site.bit),
            None => (u32::MAX, 0),
        };
        self.records.push(Record {
            seq,
            direction: dir as u8,
            verdict: d.verdict as u8,
            cause: cause as u8,
            wire_bytes,
            now_ns: now.0,
            release_ns: d.release.0,
            dup_release_ns: match d.duplicate {
                Some(t) => t.0,
                None => u64::MAX,
            },
            corrupt_offset,
            corrupt_bit,
            queue_backlog_bytes: d.queue_backlog_bytes,
        });
    }

    /// Every record, in decision order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// One record per line, single-space separated, every field decimal, line
    /// terminator `\n` — never `\r\n`, whatever the platform.
    ///
    /// The first line is exactly [`crate::consts::RECORD_HEADER`], byte for
    /// byte. So `render().lines().next() == Some(RECORD_HEADER)`,
    /// `render().lines().count() == records().len() + 1`, and every non-header
    /// line has exactly [`crate::consts::RECORD_FIELDS`] fields.
    ///
    /// Those three properties are asserted together, and the reason is that the
    /// obvious single assertion — "the output contains no `\r`" — is satisfied
    /// by returning the empty string. A test of a renderer needs a lower bound
    /// on what was rendered, or it is a test of nothing.
    ///
    /// `writeln!` writes exactly `U+000A` on every target — Rust has no
    /// platform-dependent line ending, and this function does not invent one.
    /// The carriage returns a fixture can acquire come from somewhere else
    /// entirely: git's checkout filter, or an editor. That is what
    /// [`DecisionLog::diff_fixture`] and the repository's `.gitattributes`
    /// between them defend against, and it is why this function's job is
    /// simply never to be the source of one.
    pub fn render(&self) -> String {
        // 64 bytes per record is a little over the typical rendered width, so
        // the buffer is sized once and the common log never reallocates.
        let mut out = String::with_capacity(RECORD_HEADER.len() + 1 + self.records.len() * 64);
        out.push_str(RECORD_HEADER);
        out.push('\n');
        for r in &self.records {
            // Infallible: writing to a `String` cannot fail, and `fmt::Error`
            // is only reachable from a `Display` impl that returns it.
            let _ = writeln!(
                out,
                "{} {} {} {} {} {} {} {} {} {} {}",
                r.seq,
                r.direction,
                r.verdict,
                r.cause,
                r.wire_bytes,
                r.now_ns,
                r.release_ns,
                r.dup_release_ns,
                r.corrupt_offset,
                r.corrupt_bit,
                r.queue_backlog_bytes,
            );
        }
        out
    }

    /// Compare this log against a committed fixture, reporting the first
    /// differing record.
    ///
    /// Both sides are split on `\n` and each line has its trailing `\r`
    /// stripped, so a checkout made with `core.autocrlf = true` and no
    /// `.gitattributes` cannot redden this on Windows.
    ///
    /// Both sides then have every line whose first non-whitespace byte is `#`
    /// dropped. That lets a hand-computed fixture carry, inside itself, the
    /// arithmetic it was derived from and the prohibition on re-deriving it by
    /// running the code under test — which has to travel with the fixture
    /// rather than sit in a sibling document nobody would open. A record line
    /// cannot be mistaken for a comment: every [`Record`] field renders as a
    /// decimal integer. The header is dropped by the same rule and is pinned by
    /// [`DecisionLog::render`]'s own test instead.
    ///
    /// Blank lines are dropped too, so the fixture can separate its comment
    /// block from its records the way a person writes a text file. That hides
    /// nothing: a rendered record is never empty, and the exhausted-side rule
    /// below still reports a missing record as a difference.
    ///
    /// `line` in the returned [`FixtureMismatch`] indexes the filtered
    /// sequence, so a comment block above the records does not shift it.
    pub fn diff_fixture(&self, fixture: &str) -> Result<(), FixtureMismatch> {
        let rendered = self.render();
        let mut expected = record_lines(fixture);
        let mut actual = record_lines(&rendered);
        let mut line = 0usize;
        loop {
            let (e, a) = (expected.next(), actual.next());
            if e.is_none() && a.is_none() {
                return Ok(());
            }
            // Exactly one side running out is a difference, and it is reported
            // as one: the exhausted side yields `""`, which no surviving line
            // can equal.
            let (e, a) = (e.unwrap_or(""), a.unwrap_or(""));
            if e != a {
                return Err(FixtureMismatch {
                    line,
                    expected: e.to_string(),
                    actual: a.to_string(),
                });
            }
            line += 1;
        }
    }

    /// Panic unless this log matches `fixture`, printing the differing record.
    ///
    /// An ergonomic wrapper over [`DecisionLog::diff_fixture`], kept for
    /// call-site readability at the top of a test. It is **not** the
    /// surface to assert a gate through: a helper whose only outcome is "panic
    /// or return `()`" tells its caller nothing, and a test written against it
    /// passes just as happily against an empty body. Gates assert on
    /// `diff_fixture`'s `Result`.
    pub fn assert_matches_fixture(&self, fixture: &str) {
        if let Err(mismatch) = self.diff_fixture(fixture) {
            panic!("decision log does not match the fixture\n{mismatch}");
        }
    }
}

/// The record lines of `text`: `\n`-separated, trailing `\r` stripped, with
/// comment lines and blank lines removed.
///
/// Leading whitespace is *not* stripped from a surviving line. It is only
/// consulted to classify a comment, so an indented `#` is still a comment while
/// an indented record line is still a difference — indentation a fixture
/// carries is indentation `render()` did not produce.
fn record_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n').map(|line| line.trim_end_matches('\r')).filter(|line| {
        let head = line.trim_start();
        !head.is_empty() && !head.starts_with('#')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::RECORD_FIELDS;
    use crate::engine::{CorruptSite, DropCause, Verdict};

    /// Two decisions chosen so that the union of their columns pins the column
    /// *order*, not merely the column count.
    ///
    /// Every adjacent pair of columns differs in at least one of the two rows:
    /// where the first row has equal neighbours (direction 1, verdict 1) the
    /// second row does not (direction 0, verdict 3), and vice versa. Swapping
    /// any two neighbouring columns therefore changes the rendered text, which
    /// is what `render_places_every_field_in_header_column_order` needs in
    /// order to be a test of the format rather than of the field count.
    ///
    /// The first row's release tick is deliberately far from its `now`, and it
    /// carries a corruption site but no duplicate; the second row is the
    /// mirror image — a drop, with a duplicate and no corruption. Between them
    /// both sentinel columns appear in both states.
    fn sample_log() -> DecisionLog {
        let mut log = DecisionLog::default();
        log.push(
            Direction::Uplink,
            7,
            1252,
            Tick(900),
            &Decision {
                verdict: Verdict::Delay,
                cause: DropCause::NotDropped,
                release: Tick(1_500_900),
                duplicate: None,
                corrupt: Some(CorruptSite { byte_offset: 41, bit: 5 }),
                queue_backlog_bytes: 8192,
            },
        );
        log.push(
            Direction::Downlink,
            8,
            64,
            Tick(1000),
            &Decision {
                verdict: Verdict::Drop,
                cause: DropCause::RateQueueFull,
                release: Tick(1000),
                duplicate: Some(Tick(2000)),
                corrupt: None,
                queue_backlog_bytes: 0,
            },
        );
        log
    }

    /// The two rendered record lines of [`sample_log`], written out by hand
    /// from the column order the header declares. Nothing in this module
    /// derives them from `render`.
    const ROW_A: &str = "7 1 1 0 1252 900 1500900 18446744073709551615 41 5 8192";
    const ROW_B: &str = "8 0 3 4 64 1000 1000 2000 4294967295 0 0";

    /// A rendered log carries line feeds and no carriage returns, on every
    /// platform, so a committed fixture compares equal everywhere.
    ///
    /// The non-emptiness assertions are not padding. `!render().contains('\r')`
    /// on its own is satisfied by `String::new()` — the bare negative is the
    /// assertion an empty renderer passes, so a lower bound on what was
    /// rendered has to travel with it.
    #[test]
    fn render_emits_lf_and_never_cr() {
        let text = sample_log().render();
        assert!(!text.contains('\r'), "no carriage return may reach a fixture");
        assert!(!text.is_empty(), "an empty render passes the negative on its own");
        assert!(text.lines().count() > 1, "header plus at least one record");
        assert!(text.ends_with('\n'), "every record line is terminated");
    }

    /// One line per record plus the header, and exactly eleven decimal fields
    /// on every record line.
    ///
    /// Asserted as a conservation identity — `lines == records + 1` — rather
    /// than as "some lines were emitted", because the identity is what fails
    /// when a record is dropped, duplicated or silently merged into its
    /// neighbour.
    #[test]
    fn render_emits_one_line_per_record_and_eleven_fields_per_line() {
        let log = sample_log();
        let text = log.render();
        assert_eq!(text.lines().next(), Some(RECORD_HEADER), "header, byte for byte");
        assert_eq!(text.lines().count(), log.records().len() + 1, "line count");
        assert!(!log.records().is_empty(), "a log of zero records proves nothing here");
        for (i, line) in text.lines().skip(1).enumerate() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), RECORD_FIELDS, "record line {i} field count");
            for (j, f) in fields.iter().enumerate() {
                assert!(f.parse::<u64>().is_ok(), "record line {i} field {j} is decimal: {f}");
                assert_eq!(*f, f.trim_start_matches('+'), "record line {i} field {j} is unsigned");
            }
        }
    }

    /// The rendered text equals a hand-written expectation, byte for byte.
    ///
    /// This is the assertion that pins the *order* of the columns. A field
    /// count is blind to a transposition: swap `now_ns` and `release_ns` and
    /// every line still has eleven decimal fields. See [`sample_log`] for how
    /// the two rows are chosen so that no adjacent transposition survives.
    #[test]
    fn render_places_every_field_in_header_column_order() {
        let want = format!("{RECORD_HEADER}\n{ROW_A}\n{ROW_B}\n");
        assert_eq!(sample_log().render(), want);
    }

    /// The header names its eleven columns, and there are eleven of them.
    ///
    /// The header is the only documentation a hand-written fixture has. If it
    /// listed ten names for eleven columns, every fixture derived from it would
    /// be off by one from the record after the missing name — and nothing else
    /// in the suite would notice, because `render` and `records` would still
    /// agree with each other.
    #[test]
    fn the_header_names_exactly_the_rendered_columns() {
        let names: Vec<&str> = RECORD_HEADER.split_whitespace().collect();
        // "#", "quinn-netem", "decision-log", "v1", then the column names.
        assert_eq!(names.len(), 4 + RECORD_FIELDS, "header tokens");
        assert_eq!(&names[..4], &["#", "quinn-netem", "decision-log", "v1"], "format tag");
        assert_eq!(
            &names[4..],
            &[
                "seq",
                "direction",
                "verdict",
                "cause",
                "wire_bytes",
                "now_ns",
                "release_ns",
                "dup_release_ns",
                "corrupt_offset",
                "corrupt_bit",
                "queue_backlog_bytes",
            ],
            "column names, in render order"
        );
        assert!(RECORD_HEADER.starts_with('#'), "the header must be dropped as a comment");
    }

    /// An absent duplicate and an absent corruption occupy their columns as
    /// sentinels, and a present one does not.
    ///
    /// Both halves are needed. A `push` that wrote `u64::MAX` and `u32::MAX`
    /// unconditionally passes the first half; a `push` that wrote `0`
    /// unconditionally passes neither, but a `push` that wrote the site and
    /// forgot the sentinel passes the second.
    #[test]
    fn absent_duplicate_and_corruption_render_as_sentinels() {
        let r = sample_log();
        let (with_corrupt, with_dup) = (r.records()[0], r.records()[1]);

        assert_eq!(with_corrupt.dup_release_ns, u64::MAX, "absent duplicate");
        assert_eq!(with_corrupt.corrupt_offset, 41, "present corruption offset");
        assert_eq!(with_corrupt.corrupt_bit, 5, "present corruption bit");

        assert_eq!(with_dup.dup_release_ns, 2000, "present duplicate");
        assert_eq!(with_dup.corrupt_offset, u32::MAX, "absent corruption");
        assert_eq!(with_dup.corrupt_bit, 0, "absent corruption bit is zeroed, not garbage");
    }

    /// A decision that is not a drop records `NotDropped`, whatever its `cause`
    /// field says.
    ///
    /// `Decision::cause` is public so a test crate can build an expectation,
    /// which means it can also be left holding a stale value under a non-drop
    /// verdict. Two impairers with identical behaviour would then emit
    /// different logs, and a fixture would be pinning a field nobody set on
    /// purpose.
    ///
    /// The drop half is the negative twin: it proves the normalisation is
    /// conditional and not a hardcoded zero.
    #[test]
    fn a_non_drop_verdict_records_no_drop_cause() {
        let mut log = DecisionLog::default();
        log.push(
            Direction::Downlink,
            0,
            100,
            Tick(0),
            &Decision { cause: DropCause::Loss, ..Default::default() },
        );
        log.push(
            Direction::Downlink,
            1,
            100,
            Tick(0),
            &Decision { verdict: Verdict::Drop, cause: DropCause::Blackout, ..Default::default() },
        );
        assert_eq!(log.records()[0].verdict, Verdict::Pass as u8);
        assert_eq!(log.records()[0].cause, DropCause::NotDropped as u8, "a pass records no cause");
        assert_eq!(log.records()[1].cause, DropCause::Blackout as u8, "a drop records why");
    }

    /// `records()` returns exactly what was pushed, in order.
    ///
    /// The length identity is what a `push` that dropped, reordered or
    /// deduplicated records fails.
    #[test]
    fn records_are_returned_in_push_order() {
        let mut log = DecisionLog::default();
        for seq in 0..3u64 {
            log.push(
                Direction::Downlink,
                seq,
                100,
                Tick(seq),
                &Decision { queue_backlog_bytes: seq * 10, ..Default::default() },
            );
        }
        assert_eq!(log.records().len(), 3);
        assert_eq!(log.records().iter().map(|r| r.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(
            log.records().iter().map(|r| r.queue_backlog_bytes).collect::<Vec<_>>(),
            vec![0, 10, 20]
        );
    }

    /// A fixture whose lines end `\r\n` compares equal to a log rendered with
    /// `\n`.
    ///
    /// The CRLF fixture is *constructed here, in memory*. Reading one from disk
    /// would make this a test of what git did to the checkout — which varies
    /// with `core.autocrlf`, with `.gitattributes`, and with when the developer
    /// last cloned — rather than a test of the comparison.
    #[test]
    fn fixture_comparison_survives_crlf() {
        let log = sample_log();
        let crlf = log.render().replace('\n', "\r\n");
        assert!(crlf.contains("\r\n"), "the fixture under test must actually be CRLF");
        assert!(!log.render().contains('\r'), "and the log under test must not be");
        assert_eq!(log.diff_fixture(&crlf), Ok(()));
    }

    /// One changed digit on a named record reddens the comparison, and the
    /// error names that record.
    ///
    /// This is the negative twin without which the CRLF test above is not a
    /// test: an implementation returning `Ok(())` unconditionally passes that
    /// one and fails this one, and that asymmetry is the entire reason this
    /// test exists.
    #[test]
    fn fixture_comparison_reddens_on_a_one_character_difference() {
        let log = sample_log();
        // Row B, `wire_bytes` 64 -> 65: one character, on the second record.
        let bad = format!("{RECORD_HEADER}\n{ROW_A}\n8 0 3 4 65 1000 1000 2000 4294967295 0 0\n");
        let err = log.diff_fixture(&bad).expect_err("a changed digit must redden");
        assert_eq!(err.line, 1, "the second record is record 1");
        assert_eq!(err.expected, "8 0 3 4 65 1000 1000 2000 4294967295 0 0");
        assert_eq!(err.actual, ROW_B);
        assert_ne!(err.expected, err.actual);
        assert!(!err.expected.is_empty() && !err.actual.is_empty());
    }

    /// A comment block above and between the records does not shift the record
    /// index the mismatch reports.
    ///
    /// A gate fixture carries its own derivation as `#` comments, so the file
    /// line number and the record index are different numbers. The one a reader
    /// re-deriving the fixture needs is the record index, and this test is what
    /// says which one they get: the same corruption reported at record 1 in the
    /// test above must still be record 1 with six comment lines interleaved.
    #[test]
    fn comment_lines_are_dropped_and_do_not_shift_the_record_index() {
        let log = sample_log();
        let commented = format!(
            "# derivation: uplink seq 7, delay 1 500 000 ns on top of now = 900\n\
             # re-deriving this file by running the implementation proves nothing:\n\
             # it would only show that the implementation equals itself.\n\
             {RECORD_HEADER}\n\
             {ROW_A}\n\
             \t# an indented comment is still a comment\n\
             # downlink seq 8: queue full at 64 on-wire bytes, duplicate at 2000\n\
             {ROW_B}\n"
        );
        assert_eq!(log.diff_fixture(&commented), Ok(()), "comments must not be compared");

        let broken = commented.replace(ROW_B, "8 0 3 4 65 1000 1000 2000 4294967295 0 0");
        let err = log.diff_fixture(&broken).expect_err("a changed digit must still redden");
        assert_eq!(err.line, 1, "record index, not file line number");
    }

    /// Uncommenting a comment turns it into a record difference.
    ///
    /// The negative twin of the test above: it proves the filter keys on the
    /// leading `#` rather than dropping whatever it likes. Without it, a
    /// `record_lines` that dropped *every* line would pass every positive
    /// comment test in this module.
    #[test]
    fn a_line_that_is_not_a_comment_is_compared() {
        let log = sample_log();
        let smuggled = format!("{RECORD_HEADER}\n{ROW_A}\nderivation notes\n{ROW_B}\n");
        let err = log.diff_fixture(&smuggled).expect_err("a non-`#` line is a record");
        assert_eq!(err.line, 1);
        assert_eq!(err.expected, "derivation notes");
        assert_eq!(err.actual, ROW_B);
    }

    /// A fixture missing its last record, and a fixture with one record too
    /// many, both redden — and the side that ran out reports `""`.
    ///
    /// Comparing only up to the shorter side is the classic silent hole: a
    /// truncated fixture would then match any log that begins with it, so a log
    /// that stopped recording halfway through a run would be blessed.
    #[test]
    fn a_fixture_of_the_wrong_length_reddens_on_both_sides() {
        let log = sample_log();

        let short = format!("{RECORD_HEADER}\n{ROW_A}\n");
        let err = log.diff_fixture(&short).expect_err("a truncated fixture must redden");
        assert_eq!(err.line, 1, "the first record the fixture does not have");
        assert_eq!(err.expected, "", "the exhausted side reports the empty line");
        assert_eq!(err.actual, ROW_B);

        let long = format!("{RECORD_HEADER}\n{ROW_A}\n{ROW_B}\n{ROW_B}\n");
        let err = log.diff_fixture(&long).expect_err("an over-long fixture must redden");
        assert_eq!(err.line, 2);
        assert_eq!(err.expected, ROW_B);
        assert_eq!(err.actual, "");
    }

    /// An empty log does not match a populated fixture, and a populated log
    /// does not match an empty one.
    ///
    /// This is what catches the pair of stubs that would otherwise satisfy
    /// everything positive here: a `render` returning `String::new()` and a
    /// fixture consisting only of comments both filter down to zero records,
    /// and zero records equal zero records.
    #[test]
    fn an_empty_log_and_a_populated_fixture_do_not_match() {
        let empty = DecisionLog::default();
        assert_eq!(empty.render().lines().count(), 1, "an empty log renders the header only");
        assert_eq!(
            empty.diff_fixture(&format!("{RECORD_HEADER}\n# nothing but commentary\n")),
            Ok(()),
            "zero records really do equal zero records"
        );

        let err = empty
            .diff_fixture(&format!("{RECORD_HEADER}\n{ROW_A}\n"))
            .expect_err("an empty log must not match a fixture with records");
        assert_eq!(err.line, 0);
        assert_eq!(err.actual, "");

        let err = sample_log()
            .diff_fixture("")
            .expect_err("a populated log must not match an empty fixture");
        assert_eq!(err.line, 0);
        assert_eq!(err.expected, "");
        assert_eq!(err.actual, ROW_A);
    }

    /// A string that is not a decision log at all reddens at record 0.
    ///
    /// Named separately because a comparison helper returning `()` accepts it.
    #[test]
    fn an_unrelated_string_reddens_at_the_first_record() {
        let err = sample_log()
            .diff_fixture("this is not a decision log at all")
            .expect_err("prose is not a fixture");
        assert_eq!(err.line, 0);
        assert_eq!(err.expected, "this is not a decision log at all");
        assert_eq!(err.actual, ROW_A);
    }

    /// Blank lines are whitespace in a text file, not records.
    ///
    /// A hand-computed fixture opens with a block of `#` comments carrying its
    /// derivation, and whoever writes it puts an empty line between that block
    /// and the records, because that is what a person does to a text file. The
    /// same file may or may not end with a newline, depending on the editor.
    /// Neither is a difference in the run being compared, and a comparison that
    /// called either one a difference would report `expected: ""` against a
    /// perfectly correct log — a failure whose message names nothing a reader
    /// could act on.
    ///
    /// The tolerance cannot hide anything, and the second half is what says so:
    /// a rendered record is never blank, so a blank line can never stand in for
    /// a record that is missing.
    #[test]
    fn blank_lines_are_not_records() {
        let log = sample_log();
        let spaced =
            format!("{RECORD_HEADER}\n# uplink first, then downlink\n\n{ROW_A}\n\n{ROW_B}");
        assert!(!spaced.ends_with('\n'), "and no trailing newline either");
        assert_eq!(log.diff_fixture(&spaced), Ok(()));

        // Blank lines cannot stand in for a record that is not there.
        let a_record_short = format!("{RECORD_HEADER}\n{ROW_A}\n\n\n");
        let err = log.diff_fixture(&a_record_short).expect_err("blank lines are not records");
        assert_eq!(err.line, 1);
        assert_eq!(err.expected, "");
        assert_eq!(err.actual, ROW_B);
    }

    /// The mismatch's `Display` names the record index and prints both sides in
    /// full, as an exact string.
    ///
    /// Asserted by equality rather than by `contains`, because `contains` is
    /// satisfied by a formatter that prints everything it can reach and by one
    /// that prints the same blob for every mismatch. This is the text a
    /// developer reads when a hand-computed fixture disagrees, so its layout is
    /// the thing under test.
    #[test]
    fn a_mismatch_displays_the_record_index_and_both_sides() {
        let m = FixtureMismatch {
            line: 4,
            expected: "1 0 0 0 1200 0 0 18446744073709551615 4294967295 0 0".to_string(),
            actual: "1 0 3 1 1200 0 0 18446744073709551615 4294967295 0 0".to_string(),
        };
        assert_eq!(
            m.to_string(),
            "decision-log record 4 differs\n  \
             expected: `1 0 0 0 1200 0 0 18446744073709551615 4294967295 0 0`\n    \
             actual: `1 0 3 1 1200 0 0 18446744073709551615 4294967295 0 0`"
        );
        assert!(!m.to_string().contains('\r'), "the report is line-feed only too");
    }

    /// Two different mismatches display differently.
    ///
    /// The negative twin of the exact-string test: a formatter returning a
    /// constant satisfies any single equality once that constant is pasted into
    /// the test, and this is the assertion it cannot satisfy.
    #[test]
    fn two_different_mismatches_display_differently() {
        let base =
            FixtureMismatch { line: 4, expected: "1 0".to_string(), actual: "1 1".to_string() };
        let other_line = FixtureMismatch { line: 5, ..base.clone() };
        let other_text = FixtureMismatch { actual: "1 2".to_string(), ..base.clone() };
        assert_ne!(base.to_string(), other_line.to_string(), "the line index must be printed");
        assert_ne!(base.to_string(), other_text.to_string(), "the actual line must be printed");
    }

    /// The wrapper panics on a mismatch, and does not on a match.
    ///
    /// Both halves in one test, because the wrapper's failure mode is precisely
    /// that "it returned" and "it compared nothing" look identical from a call
    /// site. The panic half is what an empty body fails; the success half is
    /// what a body of `panic!()` fails.
    #[test]
    #[should_panic(expected = "decision-log record 1 differs")]
    fn the_wrapper_panics_on_a_mismatch() {
        let log = sample_log();
        // The success half runs first: if the wrapper panicked unconditionally
        // this would abort here, on the matching fixture, and the panic message
        // expected below would not be the one observed.
        log.assert_matches_fixture(&log.render());
        log.assert_matches_fixture(&format!("{RECORD_HEADER}\n{ROW_A}\n9 9 9 9 9 9 9 9 9 9 9\n"));
    }
}

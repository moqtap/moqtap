//! The structural gate over the proxy's published action matrix.
//!
//! Sweeps `DRAFTS (13) × column (8) × ActionKind (16)` = 1664 cells and, for
//! every one of them, asserts three things that must agree:
//!
//! 1. **The published support table**, transcribed by hand into [`published`]
//!    rather than read out of `capability.rs`. Without an independently
//!    written second copy the sweep would be `classify` compared against
//!    itself.
//! 2. **`classify`'s verdict**, reached through the *public* API
//!    ([`Capabilities::supports`], [`Capabilities::supports_on`],
//!    [`classify`]) — the table a caller reads.
//! 3. **What a real proxy session does**, observed end-to-end over QUIC.
//!
//! `Site::StreamEnd` is swept **twice** — `is_control_stream: false` and
//! `true` — because the verdicts differ between the end of a data stream and
//! the end of the control stream, and they differ on no other axis.
//!
//! # Silence fails
//!
//! A cell that produces no event where one is expected fails: every probe
//! waits for a fixed number of events and panics with the whole event log
//! when they do not arrive. A cell that is never *visited* fails too —
//! [`the_capability_table_matches_observed_behaviour`] names every cell with
//! no disposition and asserts the visited count is exactly 1664, and
//! [`the_sweep_reports_per_cell_coverage`] additionally fails any
//! `Conditional(p)` cell that was exercised on one side only.
//!
//! `NotAttemptable` and `Unreachable` are the only two verdicts where "no
//! event" is the correct observation, and they say so rather than being
//! skipped. The `NotAttemptable` cells are checked *negatively*: across the
//! whole sweep, no event of any kind ever named their `(site, kind)` pair.
//!
//! # Where the `compile_fail` proofs live
//!
//! Not here. Rustdoc collects doc-tests from library targets only, so a
//! ` ```compile_fail ` block in `tests/*.rs` is never compiled and never run
//! — in **either** direction, which is why a proof that a capability *is*
//! constructible could not live here either. The proof hangs on a public
//! item in `src/` — `DropMode` — and
//! `cargo test --doc -p moqtap-proxy` collects **one** of them, which is
//! the number [`the_no_constructor_proofs_are_doc_tests_on_src_items`]
//! records verbatim. It was four blocks over three items until
//! `StreamAction::OpenAfter` and `SerializeAfter` shipped; those two blocks
//! are now ordinary doc-tests that construct the variants. A block that is
//! never collected reports `0 passed`, and the count is the only thing that
//! tells that apart from success.
//!
//! # Coverage caveat on the Control column
//!
//! On drafts 17-20 the harness drives control bytes down the first
//! bidirectional stream, which is exactly the topology the proxy wrongly
//! assumes those drafts use. Harness and proxy therefore share one mistake,
//! so those cells prove the actions execute correctly on whatever the site
//! *was* shown, not that the site was shown the real control plane. They are
//! labelled *asserted-against-assumption* in the coverage report.
//!
//! # Which drafts this file sweeps
//!
//! [`DRAFTS`] is cfg-built, so the axis is the set of drafts the build
//! compiled: fourteen by default, one under `--features draftNN`. A build
//! with **no** draft has nothing to sweep — every cell is a claim about a
//! codec that is not there — so the whole file is gated below rather than
//! left to pass vacuously with a zero-length axis, which would turn the
//! `1664` cardinality assertions into `0 == 0`.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;

use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, DropMode, Gate, Interest, StreamAction, StreamEnd};
use moqtap_proxy::capability::{
    classify, ActionKind, CapCtx, Capabilities, NotAttemptable, Precondition, Refusal, Site,
    Support,
};
use moqtap_proxy::event::{Effect, ImpairmentKind, ProxySide};
use moqtap_proxy::framer::BypassReason;
use moqtap_proxy::hook::{FrameCtx, ObjectCtx, ProxyHook, StreamCtx};
use moqtap_proxy::parser::data::DataStreamType;
use moqtap_proxy::shape::StreamKey;

// ============================================================
// Axes
// ============================================================

/// Every draft this build compiled, in publication order.
///
/// Each element carries its own `#[cfg]`, so the sweep axis is the enabled
/// set and not a hardcoded fourteen. Under the default (all-drafts) build
/// that is all fourteen and every cardinality assertion below reads the
/// same number it always did; under `--features draft14` the sweep runs
/// one draft and the `DRAFTS.len() * …` products shrink with it, so the
/// counts stay claims about coverage rather than about the feature set.
const DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// All fourteen kinds — one of the sweep's three axes.
const KINDS: [ActionKind; 14] = [
    ActionKind::Pass,
    ActionKind::Replace,
    ActionKind::ReplacePayload,
    ActionKind::Delay,
    ActionKind::Hold,
    ActionKind::DropElide,
    ActionKind::Truncate,
    ActionKind::ResetStream,
    ActionKind::CloseSession,
    ActionKind::Open,
    ActionKind::Reject,
    ActionKind::ReplaceObject,
    ActionKind::OpenAfter,
    ActionKind::SerializeAfter,
];

/// One published column of the support table.
///
/// `Site` alone is not the axis: `Site::Object` is two columns, split by
/// stream kind, and `Site::StreamEnd` is two columns, split by
/// `CapCtx::is_control_stream`. Both splits change the published verdict, so
/// sweeping `Site` alone would leave half of each pair unvisited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Column {
    /// An object on a subgroup stream.
    ObjectSubgroup,
    /// An object on a fetch stream.
    ObjectFetch,
    /// A control message.
    Control,
    /// A datagram.
    Datagram,
    /// The decision taken when a stream is offered.
    StreamOpen,
    /// The decision taken when a data stream's header has been read.
    StreamHeader,
    /// The end of a data stream.
    StreamEndData,
    /// The end of the control stream.
    StreamEndControl,
}

const COLUMNS: [Column; 8] = [
    Column::ObjectSubgroup,
    Column::ObjectFetch,
    Column::Control,
    Column::Datagram,
    Column::StreamOpen,
    Column::StreamHeader,
    Column::StreamEndData,
    Column::StreamEndControl,
];

impl Column {
    fn site(self) -> Site {
        match self {
            Column::ObjectSubgroup | Column::ObjectFetch => Site::Object,
            Column::Control => Site::Control,
            Column::Datagram => Site::Datagram,
            Column::StreamOpen => Site::StreamOpen,
            Column::StreamHeader => Site::StreamHeader,
            Column::StreamEndData | Column::StreamEndControl => Site::StreamEnd,
        }
    }

    /// The `CapCtx` a *table* caller supplies for this column: the draft,
    /// plus the one fact that selects the column and nothing else.
    fn table_ctx(self, draft: DraftVersion) -> CapCtx {
        let mut cx = CapCtx::default();
        cx.draft = Some(draft);
        match self {
            Column::ObjectSubgroup => cx.stream_kind = Some(DataStreamType::Subgroup),
            Column::ObjectFetch => cx.stream_kind = Some(DataStreamType::Fetch),
            Column::StreamEndData => cx.is_control_stream = Some(false),
            Column::StreamEndControl => cx.is_control_stream = Some(true),
            _ => {}
        }
        cx
    }

    fn label(self) -> &'static str {
        match self {
            Column::ObjectSubgroup => "Object(subgroup)",
            Column::ObjectFetch => "Object(fetch)",
            Column::Control => "Control",
            Column::Datagram => "Datagram",
            Column::StreamOpen => "StreamOpen",
            Column::StreamHeader => "StreamHeader",
            Column::StreamEndData => "StreamEnd(data)",
            Column::StreamEndControl => "StreamEnd(control)",
        }
    }
}

/// One cell of the published matrix.
///
/// Ordered by *axis index* rather than by derive: neither [`DraftVersion`]
/// nor [`ActionKind`] implements `Ord`, and adding a total order to a
/// published enum for a test's benefit would be the test dictating the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    draft: DraftVersion,
    column: Column,
    kind: ActionKind,
}

impl Cell {
    fn key(&self) -> (usize, usize, usize) {
        (
            DRAFTS.iter().position(|d| *d == self.draft).expect("draft on the axis"),
            COLUMNS.iter().position(|c| *c == self.column).expect("column on the axis"),
            KINDS.iter().position(|k| *k == self.kind).expect("kind on the axis"),
        )
    }
}

impl PartialOrd for Cell {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Cell {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl std::fmt::Display for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {:?}", self.draft, self.column.label(), self.kind)
    }
}

// ============================================================
// The published table, transcribed by hand
// ============================================================

/// Whether a fetch stream on this draft can only be read by an endpoint that
/// knows the Group Order the fetch asked for.
///
/// Drafts 18 and 19. There a fetch object's Group ID is a difference and the
/// order decides its sign (draft-19 Section 11.4.4.1); nothing on the data
/// stream states it, and the wrong assumption decodes rather than failing.
/// The order is on the FETCH — draft-19 Section 10.2.8: "If omitted from
/// FETCH, the receiver uses Ascending (0x1)" — so the sweep sends one before
/// each fetch stream it pushes, which is what a publisher would have been
/// answering.
///
/// Every draft's fetch objects are addressable; this only says which of them
/// need something the stream does not carry.
fn fetch_group_order_is_needed(d: DraftVersion) -> bool {
    d.number() >= 18
}

/// The Request ID every fetch stream in this file answers.
const FETCH_REQUEST: u64 = 9;

/// Whether a fetch object opens with a Serialization Flags field that decides
/// which of its Group ID, Subgroup ID, Object ID and Priority are on the wire
/// at all.
///
/// Drafts 15-20. Read here as a **layout** fact — it decides which shape
/// [`fetch_object`] writes — and not as a verdict: an elide is allowed on
/// every draft whose fetch stream is addressed, because the framer re-encodes
/// the survivor rather than deleting bytes underneath it.
fn fetch_objects_use_serialization_flags(d: DraftVersion) -> bool {
    d.number() >= 15
}

/// Whether a fetch object of this draft can carry an Object Status.
///
/// Drafts 07-15. Drafts 16-20 removed the field from fetch objects, so a
/// zero-length fetch frame there is an object with no bytes rather than a
/// status object — which is what decides whether eliding one is refused.
fn fetch_objects_carry_a_status(d: DraftVersion) -> bool {
    d.number() <= 15
}

/// Whether this draft defines a "subgroup ID is the first object's ID"
/// stream type: every draft from 11 on.
///
/// Transcribed from the drafts rather than read off the engine, which is the
/// point of this file — and this transcription is where draft-15 went
/// missing. Its neighbours read differently enough to hide it. Drafts 11
/// through 15 give the mode as a property of the type value, draft-15
/// Section 10.4.2 putting it as "the Subgroup ID is either 0 (for Types
/// 0x10-11 and 0x18-19) or the Object ID of the first object transmitted in
/// this subgroup (for Types 0x12-13 and 0x1A-1B)"; drafts 16 through 20 name
/// a SUBGROUP_ID_MODE field and spell mode 1 out as "The Subgroup ID field is
/// absent and the Subgroup ID is the Object ID of the first Object
/// transmitted in this Subgroup". Reading for the later phrasing alone finds
/// 16 through 20 and walks straight past 11 through 15.
///
/// Draft-20 renamed the header's leading field from `Type` to `Type Flags`
/// and left every bit of it alone, so its subgroup stream types and their
/// SUBGROUP_ID_MODE values are draft-19's (Section 11.4.2).
fn has_implicit_subgroup_id_mode(d: DraftVersion) -> bool {
    matches!(d.number(), 11..=20)
}

/// Whether the draft carries its control plane on a **pair of
/// unidirectional** streams and its requests on bidirectional ones: true on
/// 17-20, false on 07-16, where the control plane is the one
/// client-initiated bidirectional stream.
///
/// Both shapes reach `Site::Control`, so no column splits on this. It is
/// here because the control probes below drive their frames down a
/// bidirectional stream, which is a *request* stream on the true side — a
/// stated limit of this harness, not of the engine.
fn control_plane_is_a_uni_pair(d: DraftVersion) -> bool {
    d.number() >= 17
}

/// Whether the draft defines a stream-reset code vocabulary: drafts 11 and
/// later do, 07-10 do not, and an `Effect` reports which case it was.
fn stream_reset_code_defined(d: DraftVersion) -> bool {
    d.number() > 10
}

/// The kinds a [`StreamAction`] can carry — the hand-transcribed twin of
/// `capability.rs`'s own `is_stream_decision`.
///
/// Written independently on purpose. `capability.rs`'s copy is a
/// `matches!`, so the compiler cannot tell it a variant is missing; this
/// list is the thing that can, through
/// [`the_published_table_and_classify_agree`].
fn is_stream_decision(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::Open | ActionKind::Reject | ActionKind::OpenAfter | ActionKind::SerializeAfter
    )
}

fn wrong_site(site: Site, action: ActionKind) -> Refusal {
    Refusal::WrongSite { site, action }
}

/// The published verdict for one cell, written out by hand.
///
/// This is the *independent* half of the structural gate: it shares no code
/// with `capability.rs`, so `the_capability_table_matches_observed_behaviour`
/// compares two separately-derived readings of the same document rather than
/// comparing `classify` against itself.
fn published(cell: Cell) -> Support {
    let Cell { draft, column, kind } = cell;
    let site = column.site();

    // 1. The two kinds with no constructor, at *every* site.
    // 2. `ReplaceObject` off the object site.
    if kind == ActionKind::ReplaceObject && site != Site::Object {
        return Support::NotAttemptable {
            why: NotAttemptable::KindNotDefinedAtThisSite,
            refusal: wrong_site(site, kind),
        };
    }

    // 3. A return-type mismatch, in whichever direction it runs.
    let site_returns_stream_action = matches!(site, Site::StreamOpen | Site::StreamHeader);
    match (site_returns_stream_action, is_stream_decision(kind)) {
        (true, false) => {
            return Support::NotAttemptable {
                why: NotAttemptable::SiteReturnsStreamAction,
                refusal: wrong_site(site, kind),
            }
        }
        (false, true) => {
            return Support::NotAttemptable {
                why: NotAttemptable::SiteReturnsAction,
                refusal: wrong_site(site, kind),
            }
        }
        _ => {}
    }

    // 4. The per-column rules. There is no fetch-shaped step here any
    //    more: a fetch stream is framed on every draft this build compiled,
    //    and the two that need the fetch's Group Order to read one are
    //    handed it by the session.
    match column {
        Column::ObjectSubgroup | Column::ObjectFetch => match kind {
            ActionKind::Pass
            | ActionKind::Delay
            | ActionKind::Hold
            | ActionKind::Truncate
            | ActionKind::ResetStream
            | ActionKind::CloseSession => Support::Yes,
            ActionKind::Replace | ActionKind::ReplaceObject => {
                Support::No(wrong_site(Site::Object, ActionKind::ReplaceObject))
            }
            ActionKind::ReplacePayload => {
                Support::Conditional(Precondition::ReplacementLengthEqualsPayload)
            }
            // `~SI` / `~SIM` on a subgroup stream with a first-object
            // mode; `~S` on everything else, a fetch stream included — a
            // fetch object names its own subgroup, so the first-object guard
            // has nothing to say about one.
            ActionKind::DropElide => {
                if column == Column::ObjectSubgroup && has_implicit_subgroup_id_mode(draft) {
                    Support::Conditional(Precondition::NotFirstObjectOfImplicitSubgroup)
                } else {
                    Support::Conditional(Precondition::NotAStatusObject)
                }
            }
            other => unreachable!("filtered above: {other:?}"),
        },
        Column::Control => match kind {
            ActionKind::Pass
            | ActionKind::Replace
            | ActionKind::Delay
            | ActionKind::Hold
            | ActionKind::DropElide
            // One value on all fourteen: whichever shape the draft gives its
            // control plane, `Site::Control` is shown it.
            | ActionKind::CloseSession => Support::Yes,
            ActionKind::ReplacePayload => Support::No(wrong_site(Site::Control, kind)),
            ActionKind::Truncate | ActionKind::ResetStream => {
                Support::No(Refusal::ControlStreamResetIllegal)
            }
            other => unreachable!("filtered above: {other:?}"),
        },
        Column::Datagram => match kind {
            ActionKind::Pass | ActionKind::DropElide | ActionKind::CloseSession => Support::Yes,
            ActionKind::Replace => Support::Conditional(Precondition::WithinMaxDatagramSize),
            ActionKind::ReplacePayload => {
                Support::Conditional(Precondition::DatagramPayloadDelimited)
            }
            ActionKind::Delay
            | ActionKind::Hold
            | ActionKind::Truncate
            | ActionKind::ResetStream => Support::No(wrong_site(Site::Datagram, kind)),
            other => unreachable!("filtered above: {other:?}"),
        },
        // The deferred-open rule, transcribed: `SerializeAfter` takes
        // exactly the verdict `Open` takes at both stream sites, and
        // `OpenAfter` takes the same except at `StreamHeader`, where the peer
        // stream already exists and there is nothing left to defer.
        Column::StreamOpen => Support::Yes,
        Column::StreamHeader => match kind {
            ActionKind::OpenAfter => {
                Support::No(wrong_site(Site::StreamHeader, ActionKind::OpenAfter))
            }
            _ => Support::Yes,
        },
        // `CloseSession` is honoured at both StreamEnd columns. Everything
        // else unsupported at a stream end refuses with `WrongSite`, except
        // `Truncate` and `ResetStream` on the control stream, which refuse
        // with `ControlStreamResetIllegal`.
        Column::StreamEndData => match kind {
            ActionKind::Pass | ActionKind::CloseSession | ActionKind::ResetStream => Support::Yes,
            ActionKind::Replace
            | ActionKind::ReplacePayload
            | ActionKind::Delay
            | ActionKind::Hold
            | ActionKind::DropElide
            | ActionKind::Truncate => Support::No(wrong_site(Site::StreamEnd, kind)),
            other => unreachable!("filtered above: {other:?}"),
        },
        Column::StreamEndControl => match kind {
            ActionKind::Pass | ActionKind::CloseSession => Support::Yes,
            ActionKind::ResetStream | ActionKind::Truncate => {
                Support::No(Refusal::ControlStreamResetIllegal)
            }
            ActionKind::Replace
            | ActionKind::ReplacePayload
            | ActionKind::Delay
            | ActionKind::Hold
            | ActionKind::DropElide => Support::No(wrong_site(Site::StreamEnd, kind)),
            other => unreachable!("filtered above: {other:?}"),
        },
    }
}

/// `classify`'s verdict for one cell, reached through the public API a
/// caller uses.
fn classified(cell: Cell) -> Support {
    let caps = Capabilities::for_draft(cell.draft);
    match cell.column {
        Column::ObjectSubgroup => {
            caps.supports_on(Site::Object, cell.kind, DataStreamType::Subgroup)
        }
        Column::ObjectFetch => caps.supports_on(Site::Object, cell.kind, DataStreamType::Fetch),
        Column::Control | Column::Datagram | Column::StreamOpen | Column::StreamHeader => {
            caps.supports(cell.column.site(), cell.kind)
        }
        Column::StreamEndData | Column::StreamEndControl => {
            classify(Site::StreamEnd, cell.kind, &cell.column.table_ctx(cell.draft))
        }
    }
}

fn all_cells() -> Vec<Cell> {
    let mut out = Vec::with_capacity(DRAFTS.len() * COLUMNS.len() * KINDS.len());
    for &draft in DRAFTS {
        for column in COLUMNS {
            for kind in KINDS {
                out.push(Cell { draft, column, kind });
            }
        }
    }
    out
}

// ============================================================
// Observations
// ============================================================

/// One thing a session reported, destructured.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Obs {
    Applied(Site, ActionKind, Effect),
    Refused(Site, ActionKind, Refusal),
    Failed(Site, ActionKind, String),
    Impairment(ImpairmentKind),
}

impl Obs {
    /// The `(site, kind)` pair an *action* event named, or `None` for an
    /// impairment (which is a property of the stream, not of a kind).
    fn pair(&self) -> Option<(Site, ActionKind)> {
        match self {
            Obs::Applied(s, k, _) | Obs::Refused(s, k, _) | Obs::Failed(s, k, _) => Some((*s, *k)),
            Obs::Impairment(_) => None,
        }
    }
}

/// Everything the sweep learned.
///
/// The per-cell assertions are made *inline*, by the driver that produced
/// the stimulus, because that is where the failure message can name the
/// stream and the object. What survives into here is what the aggregate
/// tests need: which cells were visited and how, which `(site, kind)` pairs
/// any event ever named, and which `Refusal` variants were really emitted.
#[derive(Debug, Default)]
struct Sweep {
    /// Every cell, with one label per probe that covered it. A cell with no
    /// entry was **skipped**, which
    /// [`the_sweep_reports_per_cell_coverage`] fails on.
    covered: BTreeMap<Cell, Vec<String>>,
    /// Every `(site, kind)` pair any event named, anywhere.
    observed_pairs: Vec<(Site, ActionKind)>,
    /// Every `Refusal` variant observed as a real `ActionRefused`.
    observed_refusals: BTreeSet<&'static str>,
    /// The draft number of every session the sweep ran, one entry each.
    sessions: Vec<u8>,
    /// Diagnostics printed with the coverage report.
    notes: Vec<String>,
}

impl Sweep {
    /// Record that `cell` was covered, and by what.
    fn cover(&mut self, cell: Cell, how: impl Into<String>) {
        self.covered.entry(cell).or_default().push(how.into());
    }

    /// Fold one session's events into the global sets.
    fn absorb(&mut self, events: &[Obs]) {
        for ev in events {
            if let Some(pair) = ev.pair() {
                if !self.observed_pairs.contains(&pair) {
                    self.observed_pairs.push(pair);
                }
            }
            if let Obs::Refused(_, _, r) = ev {
                self.observed_refusals.insert(refusal_label(r));
            }
        }
    }
}

/// A stable label per `Refusal` *variant* — the partition
/// `every_declared_refusal_is_reachable_or_declared_table_only` is over.
fn refusal_label(r: &Refusal) -> &'static str {
    match r {
        Refusal::WrongSite { .. } => "WrongSite",
        Refusal::WrongComposition { .. } => "WrongComposition",
        Refusal::ControlStreamResetIllegal => "ControlStreamResetIllegal",
        Refusal::LengthChanged { .. } => "LengthChanged",
        Refusal::WouldRedefineSubgroupId => "WouldRedefineSubgroupId",
        Refusal::WouldDestroyStatusObject => "WouldDestroyStatusObject",
        Refusal::ReservedHeaderMode { .. } => "ReservedHeaderMode",
        Refusal::PayloadNotDelimited { .. } => "PayloadNotDelimited",
        Refusal::StreamNotFramed { .. } => "StreamNotFramed",
        Refusal::ControlFrameNotDecodable => "ControlFrameNotDecodable",
        Refusal::ErrorCodeOutOfRange { .. } => "ErrorCodeOutOfRange",
        Refusal::SessionAlreadyClosing => "SessionAlreadyClosing",
        other => panic!(
            "a new Refusal variant reached the sweep with no label: {other:?}. \
             Add it, and decide whether it is reachable or table-only.",
        ),
    }
}

/// Every `Refusal` variant this release declares, by label. Kept as data so
/// a new variant that nothing produces is a failure rather than an omission.
/// Read only by [`every_declared_refusal_is_reachable_or_declared_table_only`],
/// which is an all-fourteen-drafts claim, so this table carries the same
/// gate rather than sitting unread on a single-draft row.
#[cfg(all(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
const ALL_REFUSAL_LABELS: [&str; 12] = [
    "WrongSite",
    "WrongComposition",
    "ControlStreamResetIllegal",
    "LengthChanged",
    "WouldRedefineSubgroupId",
    "WouldDestroyStatusObject",
    "ReservedHeaderMode",
    "PayloadNotDelimited",
    "StreamNotFramed",
    "ControlFrameNotDecodable",
    "ErrorCodeOutOfRange",
    "SessionAlreadyClosing",
];

/// The refusals that exist only inside a table verdict — they name why a
/// kind is unattemptable or unreachable, and nothing ever emits one as a
/// real `ActionRefused`.
/// Read only by [`every_declared_refusal_is_reachable_or_declared_table_only`],
/// which is an all-fourteen-drafts claim, so this table carries the same
/// gate rather than sitting unread on a single-draft row.
#[cfg(all(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
const TABLE_ONLY_REFUSALS: [&str; 2] = ["StreamNotFramed", "ControlFrameNotDecodable"];

/// The refusals the table really would hand a hook, and that no stream can
/// provoke, so the sweep cannot observe one.
///
/// `ReservedHeaderMode` is the whole of the set, and it is a *different*
/// claim from [`TABLE_ONLY_REFUSALS`]: this one is emittable, and reaching
/// it needs a stream that cannot exist. It answers for a subgroup header
/// whose SUBGROUP_ID_MODE is `0b11`, and every draft with that field lists
/// each type value carrying it as invalid, telling the receiver to close
/// the session with a PROTOCOL_VIOLATION rather than read the stream
/// (draft-19 Section 11.4.2). No such header decodes, so the framer
/// addresses no object behind one and the object site is never reached. The
/// verdict itself stays gated where it is produced, in `capability`'s own
/// tests; what no session can show is one being emitted.
///
/// This used to call drafts 17-19 the only ones carrying that field, which
/// is wrong and made the range look narrower than it is: draft-16 carries a
/// SUBGROUP_ID_MODE and the same reserved value, and refuses those type
/// values at decode exactly as its successors do. The unprovokability
/// argument is unchanged by that — it rests on the decoder's refusal, which
/// all five drafts share — but the reason now names the right range.
///
/// Kept beside the other two lists rather than folded into either, so the
/// day a draft defines mode 3 this set empties and the partition below
/// says so.
/// Read only by [`every_declared_refusal_is_reachable_or_declared_table_only`],
/// which is an all-fourteen-drafts claim, so this table carries the same
/// gate rather than sitting unread on a single-draft row.
#[cfg(all(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
const UNPROVOKABLE_REFUSALS: [&str; 1] = ["ReservedHeaderMode"];

// ============================================================
// An encoder independent of the codec under test
// ============================================================
//
// Subgroup and fetch streams are assembled here from each draft's
// documented layout, sharing no code with `moqtap-codec` — the same
// discipline `object_framing_acceptance.rs` uses. Datagram and control
// *frames* are built
// through the codec, which is stated rather than hidden: this file asserts
// on **events**, so a fixture only has to be one the parser accepts. The
// byte-level wire claims are gated by the codec's own acceptance tests,
// which do not share an encoder with the decoder they exercise.

/// QUIC variable-length integer, RFC 9000 §16.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Object IDs are absolute on drafts 07-13 and delta-encoded from draft-14.
fn delta_encoded(draft: DraftVersion) -> bool {
    draft.number() >= 14
}

/// How a subgroup stream header names its subgroup ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubgroupMode {
    /// An explicit subgroup ID follows in the header.
    Explicit,
    /// The subgroup ID is the first object's ID — the mode that makes
    /// eliding index 0 a redefinition.
    FirstObject,
    /// Drafts 17-20's reserved subgroup-ID mode 3.
    Reserved,
}

/// The stream-type octet opening a subgroup stream, per draft and mode.
///
/// Drafts 07-10 have a single subgroup type and always carry the ID
/// explicitly. Draft-11 numbers the type space 0x08-0x0D; drafts 12+ use
/// 0x10-0x15, where bit 1 selects "first object" and bit 2 "explicit".
/// Drafts 17-20 read bits 1-2 as a two-bit mode, whose value 3 is reserved.
fn subgroup_stream_type(draft: DraftVersion, mode: SubgroupMode) -> u8 {
    match (draft.number(), mode) {
        (7..=10, _) => 0x04,
        (11, SubgroupMode::Explicit) => 0x0C,
        (11, _) => 0x0A,
        (_, SubgroupMode::Explicit) => 0x14,
        (_, SubgroupMode::FirstObject) => 0x12,
        (_, SubgroupMode::Reserved) => 0x16,
    }
}

/// Track alias 1, group 0, subgroup 0, publisher priority 128, no
/// extensions — including the leading stream-type field.
fn subgroup_header(draft: DraftVersion, mode: SubgroupMode) -> Vec<u8> {
    let mut out = vec![subgroup_stream_type(draft, mode)];
    put_varint(&mut out, 1); // track alias
    put_varint(&mut out, 0); // group
    if mode == SubgroupMode::Explicit {
        put_varint(&mut out, 0); // subgroup
    }
    out.push(0x80); // publisher priority
    out
}

/// One object's wire bytes on a subgroup stream.
///
/// `payload` empty means a status object: `payload_length` is zero and an
/// Object Status varint follows, which is the layout every draft 07-20
/// shares.
fn subgroup_object(
    draft: DraftVersion,
    prev: Option<u64>,
    object_id: u64,
    payload: &[u8],
    status: Option<u64>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let id_field = match (delta_encoded(draft), prev) {
        (true, Some(prev)) => object_id - prev - 1,
        _ => object_id,
    };
    put_varint(&mut out, id_field);

    // The extension block: absent on draft-07, count-prefixed on draft-08,
    // byte-length-prefixed on 09/10, and gated on the stream type from
    // draft-11 (our headers never set that bit).
    match draft.number() {
        7 => {}
        8 => put_varint(&mut out, 0),
        9 | 10 => put_varint(&mut out, 0),
        _ => {}
    }

    match status {
        Some(code) => {
            put_varint(&mut out, 0);
            put_varint(&mut out, code);
        }
        None => {
            put_varint(&mut out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
    }
    out
}

/// A fetch stream header: type `0x05` then the request/subscribe ID.
fn fetch_header() -> Vec<u8> {
    let mut out = vec![0x05];
    put_varint(&mut out, FETCH_REQUEST);
    out
}

/// A FETCH asking for one group of one track, under [`FETCH_REQUEST`].
///
/// Built for the three drafts that need one and for no others, so a sweep
/// that sent one where it was not needed would be sending a control frame the
/// rest of the file does not account for. It carries no GROUP_ORDER parameter,
/// which is itself an answer — draft-19 Section 10.2.8 and draft-20's own
/// 10.2.8: "If omitted from FETCH, the receiver uses Ascending (0x1)".
///
/// Draft-20's arm is a different shape, and that is the point of writing it
/// out: Section 10.13 deleted the `Fetch Type` field and the Standalone Fetch
/// structure, so the namespace and name are inline and the range — which this
/// fixture does not need — would travel in a `LOCATION_FILTER` parameter.
#[allow(unused_variables, unreachable_code)]
fn fetch_frame(draft: DraftVersion) -> Option<Vec<u8>> {
    if !fetch_group_order_is_needed(draft) {
        return None;
    }
    // Typed, because a build compiling none of the three drafts leaves the
    // match with only its `_` arm and nothing to infer from.
    let msg: AnyControlMessage = match draft {
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            use moqtap_codec::draft18::message as m;
            AnyControlMessage::Draft18(m::ControlMessage::Fetch(m::Fetch {
                request_id: moqtap_codec::varint::VarInt::from_u64(FETCH_REQUEST).unwrap(),
                fetch_type: m::FetchType::Standalone,
                fetch_payload: m::FetchPayload::Standalone {
                    track_namespace: moqtap_codec::types::TrackNamespace(vec![b"ns".to_vec()]),
                    track_name: b"t".to_vec(),
                    start_group: moqtap_codec::varint::VarInt::from_u64(7).unwrap(),
                    start_object: moqtap_codec::varint::VarInt::from_u64(0).unwrap(),
                    end_group: moqtap_codec::varint::VarInt::from_u64(64).unwrap(),
                    end_object: moqtap_codec::varint::VarInt::from_u64(0).unwrap(),
                },
                parameters: vec![],
            }))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            use moqtap_codec::draft19::message as m;
            AnyControlMessage::Draft19(m::ControlMessage::Fetch(m::Fetch {
                request_id: moqtap_codec::varint::VarInt::from_u64(FETCH_REQUEST).unwrap(),
                fetch_type: m::FetchType::Standalone,
                fetch_payload: m::FetchPayload::Standalone {
                    track_namespace: moqtap_codec::types::TrackNamespace(vec![b"ns".to_vec()]),
                    track_name: b"t".to_vec(),
                    start_group: moqtap_codec::varint::VarInt::from_u64(7).unwrap(),
                    start_object: moqtap_codec::varint::VarInt::from_u64(0).unwrap(),
                    end_group: moqtap_codec::varint::VarInt::from_u64(64).unwrap(),
                    end_object: moqtap_codec::varint::VarInt::from_u64(0).unwrap(),
                },
                parameters: vec![],
            }))
        }
        #[cfg(feature = "draft20")]
        DraftVersion::Draft20 => {
            use moqtap_codec::draft20::message as m;
            AnyControlMessage::Draft20(m::ControlMessage::Fetch(m::Fetch {
                request_id: moqtap_codec::varint::VarInt::from_u64(FETCH_REQUEST).unwrap(),
                track_namespace: moqtap_codec::types::TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                parameters: vec![],
            }))
        }
        _ => return None,
    };
    let mut out = Vec::new();
    msg.encode(&mut out).expect("the codec writes what it built");
    Some(out)
}

/// One object on a fetch stream.
///
/// **Drafts 07-14.** Layout: group(vi), subgroup(vi), object(vi),
/// priority(u8), \[extension block\], payload_length(vi), \[status(vi) if
/// zero\], payload. Draft-07 carries no extension block, draft-08's is
/// count-prefixed and drafts 09-14 use a byte-length prefix — and unlike
/// subgroup objects it is never gated on the stream type.
///
/// **Drafts 15-17.** A Serialization Flags field first, then only the
/// fields it announces. Every object built here states all four outright —
/// flags `0x1F`: Subgroup ID present, Object ID present, Group ID present,
/// Priority present — which is the encoding that makes this function's
/// signature mean the same thing on both sides of draft-15, and which makes
/// removing one of them cost nothing. The stream that exercises the
/// *inheriting* encoding, where a survivor really does have to be re-encoded,
/// is in `actions_objects.rs`; what this file measures is that the published
/// cell and the engine agree, and they agree on every fetch object of those
/// drafts whatever it states.
///
/// Drafts 16 and 17 removed the Object Status field from fetch objects, so a
/// `status` asked for there comes out as an ordinary zero-length object.
fn fetch_object(
    draft: DraftVersion,
    group_id: u64,
    object_id: u64,
    payload: &[u8],
    status: Option<u64>,
) -> Vec<u8> {
    if fetch_objects_use_serialization_flags(draft) {
        let mut out = Vec::new();
        put_varint(&mut out, 0x03 | 0x04 | 0x08 | 0x10);
        put_varint(&mut out, group_id);
        put_varint(&mut out, 0); // subgroup
        put_varint(&mut out, object_id);
        out.push(0x80); // publisher priority
        match status {
            Some(code) if draft.number() == 15 => {
                put_varint(&mut out, 0);
                put_varint(&mut out, code);
            }
            _ => {
                put_varint(&mut out, payload.len() as u64);
                out.extend_from_slice(payload);
            }
        }
        return out;
    }

    let mut out = Vec::new();
    put_varint(&mut out, group_id);
    put_varint(&mut out, 0); // subgroup
    put_varint(&mut out, object_id);
    out.push(0x80); // publisher priority
    match draft.number() {
        7 => {}
        8 => put_varint(&mut out, 0),
        _ => put_varint(&mut out, 0),
    }
    match status {
        Some(code) => {
            put_varint(&mut out, 0);
            put_varint(&mut out, code);
        }
        None => {
            put_varint(&mut out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
    }
    out
}

// ============================================================
// The scripted hook
// ============================================================

/// What the hook should answer at each site, in arrival order.
///
/// One queue per site: the sweep drives one unit at a time and waits for its
/// report before sending the next, so the queues stay aligned with the
/// stimulus without any cross-site ordering assumption.
#[derive(Default)]
struct Script {
    object: Vec<Action>,
    control: Vec<Action>,
    datagram: Vec<Action>,
    stream_open: Vec<StreamAction>,
    stream_header: Vec<StreamAction>,
    stream_end: Vec<Action>,
}

/// A hook that answers from a script, and reports what it was asked.
struct ScriptedHook {
    interest: Interest,
    script: Mutex<Script>,
    /// Incremented on entry to `on_object`; the close-race probe waits on it.
    objects_entered: Arc<AtomicUsize>,
    /// When set, `on_object` blocks until `objects_entered` reaches it.
    object_barrier: Option<usize>,
    /// Every `StreamCtx::key()` this hook was shown, labelled by site.
    ///
    /// Recorded unconditionally and read by exactly one test
    /// ([`a_streams_key_is_stable_across_its_three_sites`]). Three pushes
    /// per stream on a path that is already doing QUIC I/O.
    keys: Mutex<Vec<(&'static str, u64, StreamKey)>>,
}

impl ScriptedHook {
    fn new(interest: Interest, script: Script) -> Arc<Self> {
        Arc::new(Self {
            interest,
            script: Mutex::new(script),
            objects_entered: Arc::new(AtomicUsize::new(0)),
            object_barrier: None,
            keys: Mutex::new(Vec::new()),
        })
    }

    fn with_object_barrier(interest: Interest, script: Script, n: usize) -> Arc<Self> {
        Arc::new(Self {
            interest,
            script: Mutex::new(script),
            objects_entered: Arc::new(AtomicUsize::new(0)),
            object_barrier: Some(n),
            keys: Mutex::new(Vec::new()),
        })
    }

    fn note_key(&self, site: &'static str, cx: &StreamCtx<'_>) {
        self.keys.lock().expect("keys").push((site, cx.stream_id, cx.key()));
    }

    fn keys(&self) -> Vec<(&'static str, u64, StreamKey)> {
        self.keys.lock().expect("keys").clone()
    }

    fn pop(queue: &mut Vec<Action>) -> Action {
        if queue.is_empty() {
            Action::Pass
        } else {
            queue.remove(0)
        }
    }

    fn pop_stream(queue: &mut Vec<StreamAction>) -> StreamAction {
        if queue.is_empty() {
            StreamAction::Open
        } else {
            queue.remove(0)
        }
    }
}

impl ProxyHook for ScriptedHook {
    fn interest(&self) -> Interest {
        self.interest
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        Self::pop(&mut self.script.lock().expect("script").control)
    }

    fn on_object(&self, _cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let action = Self::pop(&mut self.script.lock().expect("script").object);
        self.objects_entered.fetch_add(1, Ordering::SeqCst);
        // The `SessionAlreadyClosing` probe needs two `execute` calls to
        // race, and `SessionCloser::request` cancels the session the moment
        // the first one lands. Holding both hooks here until both have
        // arrived makes the second attempt reach the engine deterministically
        // rather than by luck. Bounded, so a broken run fails rather than
        // hangs.
        if let Some(n) = self.object_barrier {
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.objects_entered.load(Ordering::SeqCst) < n && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        action
    }

    fn on_datagram(
        &self,
        _cx: &FrameCtx<'_>,
        _header: Option<&AnyDatagramHeader>,
        _raw: &[u8],
    ) -> Action {
        Self::pop(&mut self.script.lock().expect("script").datagram)
    }

    fn on_stream_open(&self, cx: &StreamCtx<'_>) -> StreamAction {
        self.note_key("open", cx);
        Self::pop_stream(&mut self.script.lock().expect("script").stream_open)
    }

    fn on_stream_header(
        &self,
        cx: &StreamCtx<'_>,
        _header: &moqtap_proxy::event::DataStreamHeaderKind,
    ) -> StreamAction {
        self.note_key("header", cx);
        Self::pop_stream(&mut self.script.lock().expect("script").stream_header)
    }

    fn on_stream_end(&self, cx: &StreamCtx<'_>, _end: StreamEnd) -> Action {
        self.note_key("end", cx);
        Self::pop(&mut self.script.lock().expect("script").stream_end)
    }
}

/// Every site armed. `STREAMS` contains `OBJECTS` structurally.
fn all_interest() -> Interest {
    Interest::CONTROL | Interest::STREAMS | Interest::DATAGRAMS
}

// ============================================================
// Control frames
// ============================================================

/// A CLIENT_SETUP the proxy's draft detector recognises, built by hand.
///
/// Needed only on drafts 07-14, whose ALPN is `moq-00`:
/// `pipe_control_mutating` buffers and forwards nothing until
/// `detect_draft_from_setup` has picked a concrete draft, so a control-site
/// probe there has to open with one.
///
/// Framing: type `0x40` plus a varint length on drafts 07-10, type `0x20`
/// plus a `u16` big-endian length from draft-11. Payload:
/// `count(vi) ++ version(vi) ++ parameter_count(vi)`.
fn client_setup_frame(draft: DraftVersion) -> Vec<u8> {
    let mut payload = Vec::new();
    put_varint(&mut payload, 1);
    put_varint(&mut payload, 0xff00_0000 + u64::from(draft.number()));
    put_varint(&mut payload, 0);

    let mut out = Vec::new();
    if draft.number() <= 10 {
        put_varint(&mut out, 0x40);
        put_varint(&mut out, payload.len() as u64);
    } else {
        put_varint(&mut out, 0x20);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&payload);
    out
}

/// A GOAWAY frame, built through the codec.
///
/// Stated rather than hidden: the *object* fixtures in this file come from
/// an independent encoder, because a byte-level claim checked with the same
/// code that produced the bytes proves only self-consistency.
/// This file's control-site claims are about **events** — which action was
/// applied, which refusal was emitted — so the frame only has to be one the
/// parser accepts, and fourteen hand-rolled control encoders would buy
/// nothing the assertions read.
///
/// Every arm is `#[cfg(feature = "draftNN")]`, so the fixture exists for
/// exactly the drafts this build compiled — and the catch-all that reports
/// the rest is itself gated on the build *not* having all fourteen, which
/// is the only configuration where it is reachable. Blanket-`#[allow]`ing
/// `unreachable_patterns` here would silence the same lint for the fourteen
/// arms above it.
fn goaway_frame(draft: DraftVersion, uri: &[u8]) -> Vec<u8> {
    // Only the 17/18/19/20 GOAWAY layouts carry a timeout field.
    #[cfg(any(
        feature = "draft17",
        feature = "draft18",
        feature = "draft19",
        feature = "draft20"
    ))]
    use moqtap_codec::varint::VarInt;
    let uri = uri.to_vec();
    let msg = match draft {
        #[cfg(feature = "draft07")]
        DraftVersion::Draft07 => {
            AnyControlMessage::Draft07(moqtap_codec::draft07::message::ControlMessage::GoAway(
                moqtap_codec::draft07::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft08")]
        DraftVersion::Draft08 => {
            AnyControlMessage::Draft08(moqtap_codec::draft08::message::ControlMessage::GoAway(
                moqtap_codec::draft08::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft09")]
        DraftVersion::Draft09 => {
            AnyControlMessage::Draft09(moqtap_codec::draft09::message::ControlMessage::GoAway(
                moqtap_codec::draft09::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft10")]
        DraftVersion::Draft10 => {
            AnyControlMessage::Draft10(moqtap_codec::draft10::message::ControlMessage::GoAway(
                moqtap_codec::draft10::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft11")]
        DraftVersion::Draft11 => {
            AnyControlMessage::Draft11(moqtap_codec::draft11::message::ControlMessage::GoAway(
                moqtap_codec::draft11::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft12")]
        DraftVersion::Draft12 => {
            AnyControlMessage::Draft12(moqtap_codec::draft12::message::ControlMessage::GoAway(
                moqtap_codec::draft12::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft13")]
        DraftVersion::Draft13 => {
            AnyControlMessage::Draft13(moqtap_codec::draft13::message::ControlMessage::GoAway(
                moqtap_codec::draft13::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft14")]
        DraftVersion::Draft14 => {
            AnyControlMessage::Draft14(moqtap_codec::draft14::message::ControlMessage::GoAway(
                moqtap_codec::draft14::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft15")]
        DraftVersion::Draft15 => {
            AnyControlMessage::Draft15(moqtap_codec::draft15::message::ControlMessage::GoAway(
                moqtap_codec::draft15::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft16")]
        DraftVersion::Draft16 => {
            AnyControlMessage::Draft16(moqtap_codec::draft16::message::ControlMessage::GoAway(
                moqtap_codec::draft16::message::GoAway { new_session_uri: uri },
            ))
        }
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            AnyControlMessage::Draft17(moqtap_codec::draft17::message::ControlMessage::GoAway(
                moqtap_codec::draft17::message::GoAway {
                    new_session_uri: uri,
                    timeout: VarInt::from_u64(0).unwrap(),
                },
            ))
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            AnyControlMessage::Draft18(moqtap_codec::draft18::message::ControlMessage::GoAway(
                moqtap_codec::draft18::message::GoAway {
                    new_session_uri: uri,
                    timeout: VarInt::from_u64(0).unwrap(),
                    request_id: None,
                },
            ))
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            AnyControlMessage::Draft19(moqtap_codec::draft19::message::ControlMessage::GoAway(
                moqtap_codec::draft19::message::GoAway {
                    new_session_uri: uri,
                    timeout: VarInt::from_u64(0).unwrap(),
                },
            ))
        }
        #[cfg(feature = "draft20")]
        DraftVersion::Draft20 => {
            AnyControlMessage::Draft20(moqtap_codec::draft20::message::ControlMessage::GoAway(
                moqtap_codec::draft20::message::GoAway {
                    new_session_uri: uri,
                    timeout: VarInt::from_u64(0).unwrap(),
                },
            ))
        }
        #[cfg(not(all(
            feature = "draft07",
            feature = "draft08",
            feature = "draft09",
            feature = "draft10",
            feature = "draft11",
            feature = "draft12",
            feature = "draft13",
            feature = "draft14",
            feature = "draft15",
            feature = "draft16",
            feature = "draft17",
            feature = "draft18",
            feature = "draft19",
            feature = "draft20"
        )))]
        other => panic!(
            "[{other}] goaway_frame was asked for a draft this build did not compile — DRAFTS is \
             cfg-built, so nothing on the sweep axis can reach here"
        ),
    };
    let mut out = Vec::new();
    msg.encode(&mut out).unwrap_or_else(|e| panic!("[{draft}] encode GOAWAY: {e}"));
    out
}

/// Two bytes that begin an eight-byte varint and then stop, so
/// `AnyDatagramHeader::decode` fails on every draft.
///
/// The datagram site's `~D` failing side needs exactly this, and every other
/// datagram cell is indifferent to whether the header decoded — `Pass`,
/// `Replace`, `Drop` and the four `WrongSite` refusals never look at the
/// payload boundary.
const UNDECODABLE_DATAGRAM: &[u8] = &[0xC0, 0x00];

// ============================================================
// The rig: one live proxy session, with its events
// ============================================================

/// One thing the observer reported, in the shape the sweep asserts on.
///
/// **Every** impairment folds in, with no session-start exemption. That is
/// itself an assertion: a session that reported something before its first
/// unit existed would put an extra `Obs` in front of the first probe's
/// expected sequence, and the probe would fail on it rather than count it
/// separately. Drafts 17-19 used to need such an exemption.
fn obs_of(event: &moqtap_proxy::event::ProxyEvent) -> Option<Obs> {
    use moqtap_proxy::event::ProxyEvent as E;
    match event {
        E::ActionApplied { site, action, effect, .. } => {
            Some(Obs::Applied(*site, *action, effect.clone()))
        }
        E::ActionRefused { site, action, refusal, .. } => {
            Some(Obs::Refused(*site, *action, refusal.clone()))
        }
        E::ActionFailed { site, action, error, .. } => {
            Some(Obs::Failed(*site, *action, error.clone()))
        }
        E::Impairment { kind, .. } => Some(Obs::Impairment(kind.clone())),
        _ => None,
    }
}

/// A live proxy session with a client and a stand-in relay on both sides.
struct Rig {
    draft: DraftVersion,
    relay: common::FakeRelay,
    proxy: common::SpawnedProxy,
    client: quinn::Connection,
    obs: Arc<common::RecordingObserver>,
    hook: Arc<ScriptedHook>,
    /// Events already handed to a probe.
    consumed: usize,
    /// The stream this session's FETCHes go down, opened on first use.
    ///
    /// Held for the rig's whole life rather than dropped after each FETCH:
    /// dropping a `quinn::RecvStream` sends `STOP_SENDING(0)`, which the
    /// proxy notices on an idle stream, so a per-FETCH stream would race
    /// every probe after it with a teardown nobody asked for. Same
    /// discipline as `sweep_close_session`'s control halves.
    fetch_arm: Option<(quinn::SendStream, quinn::RecvStream)>,
    /// The client endpoint must outlive its connection.
    _client_ep: quinn::Endpoint,
}

impl Rig {
    async fn new(draft: DraftVersion, hook: Arc<ScriptedHook>) -> Rig {
        common::init_crypto();
        let alpn = draft.quic_alpn();
        let relay = common::FakeRelay::bind(alpn);
        let obs = Arc::new(common::RecordingObserver::new());
        let proxy = common::spawn_proxy_with(
            common::session_config(draft, relay.addr),
            alpn,
            Arc::clone(&obs) as Arc<dyn moqtap_proxy::observer::ProxyObserver>,
            Arc::clone(&hook) as Arc<dyn ProxyHook>,
        );
        let (client_ep, client) = common::connect_client(proxy.addr, alpn).await;
        // Resolve the relay's accepted connection now, unconditionally. A
        // quinn server endpoint completes no handshake unless somebody is
        // polling `accept()`, so a probe that never reads from the relay —
        // the control-stream-end cells, the datagram close — would
        // otherwise leave `connect_upstream` hanging and the session would
        // never start at all. That failure looks exactly like "the hook was
        // not called", which is the one thing this file must not confuse.
        let _ = tokio::time::timeout(Duration::from_secs(10), relay.connection())
            .await
            .unwrap_or_else(|_| panic!("[{draft}] the proxy did not connect upstream"));
        Rig {
            draft,
            relay,
            proxy,
            client,
            obs,
            hook,
            consumed: 0,
            fetch_arm: None,
            _client_ep: client_ep,
        }
    }

    /// Send the FETCH the next fetch stream will be answering, and wait for
    /// the session to have read it.
    ///
    /// A no-op on the eleven drafts whose fetch streams resolve from their
    /// own bytes. On drafts 18 and 19 it is what makes the stream readable:
    /// the session files the Group Order under the Request ID and the framer
    /// takes it out again when the response opens.
    ///
    /// The wait is not decoration. Everything the proxy is told here arrives
    /// on a different stream from the fetch response, and this harness plays
    /// both peers, so nothing orders the two for it — where a real publisher
    /// could not have opened the response before receiving the request. The
    /// `take` returns once the control frame has been through the session,
    /// which is after the order was filed.
    async fn arm_fetch(&mut self) {
        let Some(frame) = fetch_frame(self.draft) else { return };
        if self.fetch_arm.is_none() {
            self.fetch_arm = Some(self.client.open_bi().await.expect("fetch control stream"));
        }
        let (send, _) = self.fetch_arm.as_mut().expect("just opened");
        send.write_all(&frame).await.expect("FETCH");
        let events = self.take(1, "the FETCH the response answers").await;
        assert!(
            matches!(events[..], [Obs::Applied(Site::Control, ActionKind::Pass, _)]),
            "[{}] arming a fetch must cost exactly one control event: {events:#?}",
            self.draft,
        );
    }

    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.hook.script.lock().expect("script")
    }

    /// Every action event so far, in order.
    fn all_events(&self) -> Vec<Obs> {
        self.obs.events().iter().filter_map(obs_of).collect()
    }

    /// Wait for `want` further events, then take everything new.
    ///
    /// A short settle window after the count is reached is deliberate: it is
    /// what turns "at least `want`" into "exactly what this probe produced",
    /// so a stray extra event lands in *this* slice and fails the probe
    /// rather than silently shifting the next one.
    async fn take(&mut self, want: usize, what: &str) -> Vec<Obs> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let all = self.all_events();
            if all.len() >= self.consumed + want {
                tokio::time::sleep(Duration::from_millis(40)).await;
                let all = self.all_events();
                let out = all[self.consumed..].to_vec();
                self.consumed = all.len();
                return out;
            }
            if Instant::now() >= deadline {
                let out = all[self.consumed..].to_vec();
                self.consumed = all.len();
                panic!(
                    "[{}] {what}: expected {want} event(s), saw {} in 10 s: {out:#?}\n\
                     all events: {:#?}",
                    self.draft,
                    out.len(),
                    self.obs.events(),
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Everything reported that no probe has claimed yet.
    ///
    /// Empty is the only correct answer at the end of a driver: a report
    /// that belongs to no probe is a report about something the run did not
    /// ask for.
    fn unconsumed_events(&self) -> Vec<Obs> {
        self.all_events()[self.consumed..].to_vec()
    }

    fn actions_refused(&self) -> u64 {
        self.proxy.counters().actions_refused
    }

    /// Open a client unidirectional stream, write `bytes`, and FIN.
    async fn push_uni(&self, bytes: &[u8]) {
        let mut send = self.client.open_uni().await.expect("client open_uni");
        let _ = send.write_all(bytes).await;
        let _ = send.finish();
    }

    /// Accept the next forwarded stream at the relay and read it to its end.
    async fn relay_stream(&self) -> (Vec<u8>, common::Ending) {
        let recv = self.relay.accept_uni().await;
        drain_bytes(recv).await
    }

    /// Fold this session into the sweep and shut it down.
    ///
    /// The `actions_refused` counter is checked against the number of
    /// `ActionRefused` events the session emitted: the counter must move by
    /// exactly one per refused attempt, which is a per-session invariant, so
    /// asserting it here covers every refusal probe at once rather than once
    /// per cell.
    async fn finish(mut self, sweep: &mut Sweep) {
        let all = self.all_events();
        let refusals = all.iter().filter(|e| matches!(e, Obs::Refused(..))).count() as u64;
        assert_eq!(
            self.actions_refused(),
            refusals,
            "[{}] counters().actions_refused must equal the number of ActionRefused events \
             this session emitted",
            self.draft,
        );
        sweep.absorb(&all);
        sweep.sessions.push(self.draft.number());
        self.consumed = all.len();
        self.client.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

/// Read a `RecvStream` to its end, keeping both the bytes and how it ended.
async fn drain_bytes(mut recv: quinn::RecvStream) -> (Vec<u8>, common::Ending) {
    let mut buf = [0u8; 8192];
    let mut out = Vec::new();
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => out.extend_from_slice(&buf[..n]),
            Ok(None) => return (out, common::Ending::Fin),
            Err(quinn::ReadError::Reset(code)) => {
                return (out, common::Ending::Reset(code.into_inner()))
            }
            Err(e) => panic!("unexpected read error: {e:?}"),
        }
    }
}

// ============================================================
// Assertion helpers
// ============================================================

/// A `Yes` verdict, observed: exactly one `ActionApplied`, naming `kind`,
/// with the expected `Effect`.
#[track_caller]
fn one_applied(events: &[Obs], site: Site, kind: ActionKind, effect: &Effect, what: &str) {
    assert_eq!(events.len(), 1, "{what}: expected exactly one event, got {events:#?}");
    match &events[0] {
        Obs::Applied(s, k, e) => {
            assert_eq!((*s, *k), (site, kind), "{what}: wrong site/kind");
            assert_eq!(e, effect, "{what}: wrong effect");
        }
        other => panic!("{what}: expected ActionApplied, got {other:?}"),
    }
}

/// A `No(r)` verdict, observed: exactly one `ActionRefused` whose refusal
/// is `r`.
#[track_caller]
fn one_refused(events: &[Obs], site: Site, kind: ActionKind, refusal: &Refusal, what: &str) {
    assert_eq!(events.len(), 1, "{what}: expected exactly one event, got {events:#?}");
    match &events[0] {
        Obs::Refused(s, k, r) => {
            assert_eq!((*s, *k), (site, kind), "{what}: wrong site/kind");
            assert_eq!(r, refusal, "{what}: wrong refusal");
        }
        other => panic!("{what}: expected ActionRefused, got {other:?}"),
    }
}

/// A deferred action's event cardinality: `Queued` at the decision, the
/// inner effect at the release. Two events, not one.
#[track_caller]
fn queued_then(events: &[Obs], kind: ActionKind, inner: ActionKind, effect: &Effect, what: &str) {
    assert_eq!(
        events.len(),
        2,
        "{what}: a deferred action reports twice — Queued at the decision and the inner \
         effect at the release. Got {events:#?}",
    );
    match &events[0] {
        Obs::Applied(Site::Object | Site::Control, k, Effect::Queued { .. }) if *k == kind => {}
        other => panic!("{what}: expected Applied({kind:?}, Queued), got {other:?}"),
    }
    match &events[1] {
        Obs::Applied(_, k, e) => {
            assert_eq!(*k, inner, "{what}: the release names the inner kind");
            assert_eq!(e, effect, "{what}: wrong released effect");
        }
        other => panic!("{what}: expected the released ActionApplied, got {other:?}"),
    }
}

/// A decodable datagram carrying a four-byte payload, or `None` on
/// draft-14.
///
/// Draft-14's `AnyDatagramHeader` is `DatagramObject`, whose `decode`
/// consumes the payload, so no draft-14 datagram is ever
/// payload-delimited and the `~D` precondition can only fail there. Every
/// other draft's header decode stops at the payload, which is exactly what
/// `Precondition::DatagramPayloadDelimited` reads.
///
/// Every draft opens with a datagram type field. Drafts 07-10 number the
/// payload-bearing datagram `0x01`; drafts 11-13 number it `0x00` and use
/// the low bits for flags this fixture leaves clear; drafts 15-19 open with
/// one type byte, and `0x00` clears every flag there too. Asserted rather
/// than assumed — see `the_datagram_fixtures_delimit_their_payload`.
fn decodable_datagram(draft: DraftVersion) -> Option<Vec<u8>> {
    if draft == DraftVersion::Draft14 {
        return None;
    }
    let mut out = Vec::new();
    if draft.number() <= 10 {
        put_varint(&mut out, 0x01);
    } else {
        out.push(0x00);
    }
    put_varint(&mut out, 1); // track alias
    put_varint(&mut out, 0); // group
    put_varint(&mut out, 0); // object
    out.push(0x80); // publisher priority
    match draft.number() {
        7 => put_varint(&mut out, DATAGRAM_PAYLOAD.len() as u64),
        8 => {
            put_varint(&mut out, 0); // extension count
            put_varint(&mut out, DATAGRAM_PAYLOAD.len() as u64);
        }
        9 | 10 => put_varint(&mut out, 0), // extension block length
        _ => {}
    }
    out.extend_from_slice(DATAGRAM_PAYLOAD);
    Some(out)
}

const DATAGRAM_PAYLOAD: &[u8] = b"PAYL";

/// A **well-formed** draft-14 datagram: type `0x00` (payload-bearing,
/// explicit object ID, no extensions), then track alias, group, object ID,
/// publisher priority and the payload.
///
/// It exists to make the draft-14 `~D` cell falsifiable rather than merely
/// unexercised. The precondition can never hold on draft-14 — `decode` ends
/// by reading every remaining byte — so the honest probe is to show
/// that even a datagram the codec parses perfectly is still refused, and
/// with the draft-14 detail rather than the "did not decode" one.
fn draft14_datagram() -> Vec<u8> {
    let mut out = vec![0x00];
    put_varint(&mut out, 1);
    put_varint(&mut out, 0);
    put_varint(&mut out, 0);
    out.push(0x80);
    out.extend_from_slice(DATAGRAM_PAYLOAD);
    out
}

// ============================================================
// The observation sweep
// ============================================================

/// Objects the main subgroup/fetch probe stream carries, in order.
///
/// Index 0 is deliberately not an elide: the elide that must **succeed**
/// goes last, so no successor's Object ID varint is rewritten and the
/// expected wire bytes stay a plain concatenation of the survivors.
const PAYLOADS: [&[u8]; 5] = [b"aaaa", b"bbbb", b"cccc", b"dddd", b"eeee"];

/// The whole sweep, run once and shared by every test in the file.
fn sweep() -> &'static Sweep {
    static SWEEP: OnceLock<Sweep> = OnceLock::new();
    SWEEP.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("sweep runtime");
        rt.block_on(run_sweep())
    })
}

async fn run_sweep() -> Sweep {
    // One independent proxy session per compiled draft, on its own
    // ephemeral port: the drafts share nothing, so they run concurrently.
    let per_draft =
        futures_join_all(DRAFTS.iter().copied().map(sweep_draft).collect::<Vec<_>>()).await;
    let mut sweep = Sweep::default();
    for one in per_draft {
        merge(&mut sweep, one);
    }
    sweep
}

/// `futures::join_all` without the dependency.
async fn futures_join_all<F: std::future::Future<Output = Sweep> + Send + 'static>(
    futures: Vec<F>,
) -> Vec<Sweep> {
    let handles: Vec<_> = futures.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.expect("draft sweep task"));
    }
    out
}

fn merge(into: &mut Sweep, from: Sweep) {
    for (cell, how) in from.covered {
        into.covered.entry(cell).or_default().extend(how);
    }
    for pair in from.observed_pairs {
        if !into.observed_pairs.contains(&pair) {
            into.observed_pairs.push(pair);
        }
    }
    into.observed_refusals.extend(from.observed_refusals);
    into.sessions.extend(from.sessions);
    into.notes.extend(from.notes);
}

async fn sweep_draft(draft: DraftVersion) -> Sweep {
    let mut sw = Sweep::default();
    sweep_data_streams(draft, &mut sw).await;
    sweep_fetch_streams(draft, &mut sw).await;
    sweep_datagrams(draft, &mut sw).await;
    sweep_control(draft, &mut sw).await;
    sweep_stream_end_control(draft, &mut sw).await;
    sweep_close_session(draft, &mut sw).await;
    record_not_attemptable(draft, &mut sw);
    sw
}

// ── Subgroup objects, plus StreamOpen / StreamHeader / StreamEnd (data) ─

async fn sweep_data_streams(draft: DraftVersion, sw: &mut Sweep) {
    let sub = Column::ObjectSubgroup;
    let cell = |column, kind| Cell { draft, column, kind };
    let hook = ScriptedHook::new(all_interest(), Script::default());
    let mut rig = Rig::new(draft, Arc::clone(&hook)).await;
    let delta = delta_encoded(draft);

    // ── Stream 1: every non-terminal object cell, in one pass ──
    let header = subgroup_header(draft, SubgroupMode::Explicit);
    let mut stream = header.clone();
    let mut prev: Option<u64> = None;
    let mut raw_objects = Vec::new();
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let o = subgroup_object(draft, prev, i as u64, payload, None);
        prev = Some(i as u64);
        stream.extend_from_slice(&o);
        raw_objects.push(o);
    }
    for i in 5..7u64 {
        let o = subgroup_object(draft, prev, i, &[], Some(3));
        prev = Some(i);
        stream.extend_from_slice(&o);
        raw_objects.push(o);
    }
    let elided = subgroup_object(draft, prev, 7, b"hhhh", None);
    stream.extend_from_slice(&elided);

    {
        let mut s = rig.script();
        s.object = vec![
            Action::Pass,
            Action::ReplacePayload(Bytes::from_static(b"BBBB")),
            Action::ReplacePayload(Bytes::from_static(b"CC")),
            Action::Replace(Bytes::from_static(b"zz")),
            Action::Replace(Bytes::from_static(b"zz")),
            Action::ReplacePayload(Bytes::from_static(b"q")),
            Action::Drop(DropMode::Elide),
            Action::Drop(DropMode::Elide),
        ];
        s.stream_end = vec![Action::Pass];
    }
    rig.push_uni(&stream).await;
    let (got, ending) = rig.relay_stream().await;
    let events = rig.take(11, "subgroup stream 1").await;
    assert_eq!(events.len(), 11, "[{draft}] stream 1 events: {events:#?}");

    // The stream decisions this stream took on the way past.
    one_applied(
        &events[0..1],
        Site::StreamOpen,
        ActionKind::Open,
        &Effect::ForwardedVerbatim,
        "stream 1 open",
    );
    sw.cover(cell(Column::StreamOpen, ActionKind::Open), "Open: the stream is forwarded");
    one_applied(
        &events[1..2],
        Site::StreamHeader,
        ActionKind::Open,
        &Effect::ForwardedVerbatim,
        "stream 1 header",
    );
    sw.cover(cell(Column::StreamHeader, ActionKind::Open), "Open: the header is forwarded");

    // Object 0 — `Pass`.
    one_applied(
        &events[2..3],
        Site::Object,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "object 0 Pass",
    );
    sw.cover(cell(sub, ActionKind::Pass), "Pass: forwarded verbatim");

    // Object 1 — `ReplacePayload` at the declared length.
    let spliced = {
        let mut v = raw_objects[1].clone();
        let n = v.len();
        v[n - 4..].copy_from_slice(b"BBBB");
        v
    };
    one_applied(
        &events[3..4],
        Site::Object,
        ActionKind::ReplacePayload,
        &Effect::Replaced { bytes: spliced.len() },
        "object 1 ReplacePayload (precondition holds)",
    );
    sw.cover(cell(sub, ActionKind::ReplacePayload), "~L holding: length equal, no status");

    // Object 2 — the same action at the wrong length.
    one_refused(
        &events[4..5],
        Site::Object,
        ActionKind::ReplacePayload,
        &Refusal::LengthChanged { from: 4, to: 2 },
        "object 2 ReplacePayload (length changed)",
    );
    sw.cover(cell(sub, ActionKind::ReplacePayload), "~L failing: LengthChanged");

    // Objects 3 and 4 — one expression, two published rows.
    for (n, kind) in [(5usize, ActionKind::Replace), (6, ActionKind::ReplaceObject)] {
        one_refused(
            &events[n..n + 1],
            Site::Object,
            ActionKind::Replace,
            &Refusal::WrongSite { site: Site::Object, action: ActionKind::ReplaceObject },
            "Action::Replace at the object site",
        );
        sw.cover(cell(sub, kind), "✗ WrongSite { Object, ReplaceObject }");
    }

    // Object 5 — a status object is not payload-replaceable.
    one_refused(
        &events[7..8],
        Site::Object,
        ActionKind::ReplacePayload,
        &Refusal::WouldDestroyStatusObject,
        "object 5 ReplacePayload on a status object",
    );
    sw.cover(cell(sub, ActionKind::ReplacePayload), "~L failing: WouldDestroyStatusObject");

    // Object 6 — nor elidable.
    one_refused(
        &events[8..9],
        Site::Object,
        ActionKind::DropElide,
        &Refusal::WouldDestroyStatusObject,
        "object 6 Drop(Elide) on a status object",
    );
    sw.cover(cell(sub, ActionKind::DropElide), "~S failing: WouldDestroyStatusObject");

    // Object 7 — the elide that succeeds.
    one_applied(
        &events[9..10],
        Site::Object,
        ActionKind::DropElide,
        &Effect::Elided { renumbered_successor: delta },
        "object 7 Drop(Elide)",
    );
    sw.cover(cell(sub, ActionKind::DropElide), "~S/~SI holding: Elided");

    one_applied(
        &events[10..11],
        Site::StreamEnd,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "stream 1 end Pass",
    );
    sw.cover(cell(Column::StreamEndData, ActionKind::Pass), "Pass: the FIN is forwarded");

    // The wire, as one concatenation: every survivor verbatim, object 1's
    // payload spliced, object 7 gone.
    let mut want = header.clone();
    want.extend_from_slice(&raw_objects[0]);
    want.extend_from_slice(&spliced);
    for o in &raw_objects[2..] {
        want.extend_from_slice(o);
    }
    assert_eq!(ending, common::Ending::Fin, "[{draft}] stream 1 ends cleanly");
    assert_eq!(
        hex(&got),
        hex(&want),
        "[{draft}] stream 1: the wire must carry every survivor unchanged, object 1 spliced \
         and object 7 gone",
    );

    // ── Stream 2: `~SI` failing — eliding index 0 of an implicit stream ──
    if has_implicit_subgroup_id_mode(draft) {
        let events = one_object_stream(
            &mut rig,
            SubgroupMode::FirstObject,
            b"iiii",
            Action::Drop(DropMode::Elide),
            "implicit-subgroup stream",
        )
        .await;
        one_refused(
            &events[2..3],
            Site::Object,
            ActionKind::DropElide,
            &Refusal::WouldRedefineSubgroupId,
            "elide index 0 of an implicit-subgroup stream",
        );
        sw.cover(cell(sub, ActionKind::DropElide), "~SI failing: WouldRedefineSubgroupId");
    }

    // ── Stream 3: drafts 17-20's reserved header mode, which no draft
    //    decodes ──
    //
    // Draft-20 Section 11.4.2, and the same list in 19, 18 and 17, gives every
    // mode-3 type value as invalid and tells the endpoint receiving one to
    // close the session with a PROTOCOL_VIOLATION. This proxy is not that
    // endpoint. The header does not decode, so nothing on the stream is
    // addressable and the object site is never reached — no cell is
    // covered here — while the bytes reach the far side untouched, which
    // is what lets the peer be the one that answers as the draft says.
    if draft.number() >= 17 {
        let header = subgroup_header(draft, SubgroupMode::Reserved);
        let object = subgroup_object(draft, None, 0, b"jjjj", None);
        let mut bytes = header.clone();
        bytes.extend_from_slice(&object);
        {
            let mut s = rig.script();
            s.object = vec![Action::Drop(DropMode::Elide)];
            s.stream_end = vec![Action::Pass];
        }
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "reserved-mode stream").await;

        assert_eq!(ending, common::Ending::Fin, "[{draft}] reserved-mode stream ends cleanly");
        assert_eq!(
            hex(&got),
            hex(&bytes),
            "[{draft}] a header this draft forbids is still carried byte for byte",
        );
        let object_events: Vec<_> =
            events.iter().filter(|e| e.pair().map(|(s, _)| s) == Some(Site::Object)).collect();
        assert!(
            object_events.is_empty(),
            "[{draft}] an unreadable header reaches no object site, so no action event may \
             name Site::Object. Saw {object_events:#?}",
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(
                    e,
                    Obs::Impairment(ImpairmentKind::FramerBypass {
                        reason: BypassReason::DecodeError,
                        ..
                    })
                ))
                .count(),
            1,
            "[{draft}] exactly one FramerBypass per unreadable stream. Saw {events:#?}",
        );
    }

    // ── Stream 4: `Delay` ──
    let events = one_object_stream(
        &mut rig,
        SubgroupMode::Explicit,
        b"dddd",
        Action::Pass.delayed(Duration::from_millis(40)),
        "delayed stream",
    )
    .await;
    queued_then(
        &events[2..4],
        ActionKind::Delay,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "Delay at the object site",
    );
    sw.cover(cell(sub, ActionKind::Delay), "Yes: Queued at the decision, Pass at the release");

    // ── Stream 5: `Hold` ──
    let gate = Gate::new();
    let armed = gate.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        armed.release();
    });
    let events = one_object_stream(
        &mut rig,
        SubgroupMode::Explicit,
        b"hold",
        Action::Pass.held(gate),
        "held stream",
    )
    .await;
    queued_then(
        &events[2..4],
        ActionKind::Hold,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "Hold at the object site",
    );
    sw.cover(cell(sub, ActionKind::Hold), "Yes: Queued at the decision, Pass at the release");

    // ── Stream 6: `Truncate` — terminal, so it owns its stream ──
    {
        let header = subgroup_header(draft, SubgroupMode::Explicit);
        let object = subgroup_object(draft, None, 0, b"tttttttt", None);
        let mut bytes = header.clone();
        bytes.extend_from_slice(&object);
        rig.script().object = vec![Action::Truncate { bytes: 4, code: 0x2 }];
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "truncated stream").await;
        one_applied(
            &events[2..3],
            Site::Object,
            ActionKind::Truncate,
            &Effect::Truncated {
                forwarded: 4,
                code: 0x2,
                code_defined: stream_reset_code_defined(draft),
            },
            "Truncate at the object site",
        );
        assert_eq!(ending, common::Ending::Reset(0x2), "[{draft}] a truncation resets the stream");
        // A truncation forwards at most `bytes` further bytes past the
        // header, and the peer may observe none of them: `reset()` discards
        // whatever is still sitting in the local send buffer.
        assert!(
            got.len() <= header.len() + 4 && bytes.starts_with(&got),
            "[{draft}] a truncation delivers a prefix, at most 4 bytes past the header: \
             got {} bytes, header is {}",
            got.len(),
            header.len(),
        );
        sw.cover(cell(sub, ActionKind::Truncate), "Yes: prefix then RESET_STREAM(0x2)");
    }

    // ── Stream 7: `ResetStream` — terminal ──
    {
        let mut bytes = subgroup_header(draft, SubgroupMode::Explicit);
        bytes.extend_from_slice(&subgroup_object(draft, None, 0, b"rrrr", None));
        rig.script().object = vec![Action::ResetStream { code: 0x2 }];
        rig.push_uni(&bytes).await;
        let (_got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "reset stream").await;
        one_applied(
            &events[2..3],
            Site::Object,
            ActionKind::ResetStream,
            &Effect::StreamReset { code: 0x2, code_defined: stream_reset_code_defined(draft) },
            "ResetStream at the object site",
        );
        assert_eq!(ending, common::Ending::Reset(0x2), "[{draft}] the destination is reset");
        sw.cover(cell(sub, ActionKind::ResetStream), "Yes: RESET_STREAM(0x2)");
    }

    // ── Stream 8: the two refusals the executor produces, not `classify` ──
    // Not cells: `Delay` and `ResetStream` at the object site are both
    // `Yes`. These are the composition check and the varint range check,
    // and `every_declared_refusal_is_reachable_or_declared_table_only`
    // needs both variants to be observed somewhere.
    {
        let header = subgroup_header(draft, SubgroupMode::Explicit);
        let o0 = subgroup_object(draft, None, 0, b"kkkk", None);
        let o1 = subgroup_object(draft, Some(0), 1, b"llll", None);
        let mut bytes = header.clone();
        bytes.extend_from_slice(&o0);
        bytes.extend_from_slice(&o1);
        {
            let mut s = rig.script();
            s.object = vec![
                Action::ResetStream { code: 0 }.delayed(Duration::from_millis(1)),
                Action::ResetStream { code: u64::MAX },
            ];
            s.stream_end = vec![Action::Pass];
        }
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(5, "composition and range refusals").await;
        one_refused(
            &events[2..3],
            Site::Object,
            ActionKind::ResetStream,
            &Refusal::WrongComposition { detail: "Delay or Hold wrapping Truncate or ResetStream" },
            "Delay wrapping a terminal",
        );
        one_refused(
            &events[3..4],
            Site::Object,
            ActionKind::ResetStream,
            &Refusal::ErrorCodeOutOfRange { code: u64::MAX },
            "a reset code above the QUIC varint ceiling",
        );
        assert_eq!(ending, common::Ending::Fin, "[{draft}] neither refusal touches the stream");
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] a refused unit is forwarded unchanged");
    }

    // ── Stream 9: `StreamAction::Reject` at the open decision ──
    {
        rig.script().stream_open = vec![StreamAction::Reject { code: 0x7 }];
        let mut bytes = subgroup_header(draft, SubgroupMode::Explicit);
        bytes.extend_from_slice(&subgroup_object(draft, None, 0, b"nope", None));
        rig.push_uni(&bytes).await;
        let events = rig.take(1, "rejected at open").await;
        one_applied(
            &events[0..1],
            Site::StreamOpen,
            ActionKind::Reject,
            &Effect::StreamRejected { code: 0x7 },
            "Reject at StreamOpen",
        );
        common::assert_no_uni_stream_for(&rig.relay.connection().await, Duration::from_millis(400))
            .await;
        sw.cover(
            cell(Column::StreamOpen, ActionKind::Reject),
            "Yes: no peer stream is opened at all",
        );
    }

    // ── Stream 10: `StreamAction::Reject` at the header decision ──
    {
        rig.script().stream_header = vec![StreamAction::Reject { code: 0x8 }];
        let mut bytes = subgroup_header(draft, SubgroupMode::Explicit);
        bytes.extend_from_slice(&subgroup_object(draft, None, 0, b"nope", None));
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(2, "rejected at header").await;
        one_applied(
            &events[1..2],
            Site::StreamHeader,
            ActionKind::Reject,
            &Effect::StreamRejected { code: 0x8 },
            "Reject at StreamHeader",
        );
        assert!(got.is_empty(), "[{draft}] a header rejection carries zero payload bytes");
        assert_eq!(ending, common::Ending::Reset(0x8), "[{draft}] the peer stream is reset");
        sw.cover(
            cell(Column::StreamHeader, ActionKind::Reject),
            "Yes: the peer stream is reset with 0 bytes",
        );
    }

    // ── Streams 11-14: the two deferred stream decisions, at both sites ──
    //
    // Four cells, and the rule that produces them: `SerializeAfter` takes
    // exactly the verdict `Open` takes at both sites; `OpenAfter` takes the
    // same at `StreamOpen` and `No(WrongSite)` at `StreamHeader`, where the
    // peer stream already exists and there is nothing left to defer.
    //
    // **What these probes assert, and what they deliberately do not.**
    // They assert that the decision reached the engine, was classified the
    // way the table publishes it, and left every byte of the stream alone.
    // They do *not* assert the *timing*: there is no negative window here —
    // no `assert_no_uni_stream_for` — so nothing below observes that the
    // peer stream was actually held back for the requested delay or behind
    // the named target. A green run on these four cells is a claim about
    // classification and about byte-for-byte transparency, and reading it
    // as coverage of the deferral itself reads more than it says.
    //
    // A stream key that names nothing is used on purpose: an unknown
    // serialization target is defined to proceed immediately and report one
    // `SerializeTargetUnknown`, so it is the one `SerializeAfter` shape
    // whose outcome needs no second stream to set up and no timing window
    // to observe.
    let nowhere = StreamKey { side: ProxySide::ClientToProxy, id: u64::MAX };
    {
        // ── Stream 11: `OpenAfter` at the open decision ──
        rig.script().stream_open = vec![StreamAction::OpenAfter(Duration::from_millis(1))];
        let bytes = subgroup_header(draft, SubgroupMode::Explicit);
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "OpenAfter at the open decision").await;
        one_applied(
            &events[0..1],
            Site::StreamOpen,
            ActionKind::OpenAfter,
            &Effect::ForwardedVerbatim,
            "OpenAfter at StreamOpen",
        );
        assert_eq!(ending, common::Ending::Fin, "[{draft}] a deferred open still ends cleanly");
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] OpenAfter changes timing, never bytes");
        sw.cover(
            cell(Column::StreamOpen, ActionKind::OpenAfter),
            "Yes: admitted at the open decision; every byte still forwarded",
        );
    }
    {
        // ── Stream 12: `SerializeAfter` at the open decision ──
        rig.script().stream_open = vec![StreamAction::SerializeAfter(nowhere)];
        let bytes = subgroup_header(draft, SubgroupMode::Explicit);
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "SerializeAfter at the open decision").await;
        one_applied(
            &events[0..1],
            Site::StreamOpen,
            ActionKind::SerializeAfter,
            &Effect::ForwardedVerbatim,
            "SerializeAfter at StreamOpen",
        );
        assert_eq!(ending, common::Ending::Fin, "[{draft}] an unknown target does not hang");
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] SerializeAfter changes timing, never bytes");
        sw.cover(
            cell(Column::StreamOpen, ActionKind::SerializeAfter),
            "Yes: admitted at the open decision; an unknown target proceeds",
        );
    }
    {
        // ── Stream 13: `SerializeAfter` at the header decision ──
        rig.script().stream_header = vec![StreamAction::SerializeAfter(nowhere)];
        let bytes = subgroup_header(draft, SubgroupMode::Explicit);
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "SerializeAfter at the header decision").await;
        one_applied(
            &events[1..2],
            Site::StreamHeader,
            ActionKind::SerializeAfter,
            &Effect::ForwardedVerbatim,
            "SerializeAfter at StreamHeader",
        );
        assert_eq!(ending, common::Ending::Fin, "[{draft}] an unknown target does not hang");
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] the header is still forwarded whole");
        sw.cover(
            cell(Column::StreamHeader, ActionKind::SerializeAfter),
            "Yes: admitted at the header decision, exactly as `Open` is",
        );
    }
    {
        // ── Stream 14: `OpenAfter` at the header decision — the one cell
        // where the two kinds part company. Not `NotAttemptable`: the value
        // exists and really is handed to the engine, which really refuses
        // it, so a `ProxyEvent::ActionRefused` is emitted and observed.
        rig.script().stream_header = vec![StreamAction::OpenAfter(Duration::from_millis(1))];
        let bytes = subgroup_header(draft, SubgroupMode::Explicit);
        rig.push_uni(&bytes).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "OpenAfter at the header decision").await;
        one_refused(
            &events[1..2],
            Site::StreamHeader,
            ActionKind::OpenAfter,
            &Refusal::WrongSite { site: Site::StreamHeader, action: ActionKind::OpenAfter },
            "OpenAfter at StreamHeader",
        );
        assert_eq!(ending, common::Ending::Fin, "[{draft}] a refused stream decision is inert");
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] a refused unit is forwarded unchanged");
        sw.cover(
            cell(Column::StreamHeader, ActionKind::OpenAfter),
            "No(WrongSite): the peer stream already exists by the header site",
        );
    }

    // ── Streams 15+: every remaining StreamEnd (data) cell ──
    let end_cases: [(ActionKind, Action, Support); 7] = [
        (
            ActionKind::Replace,
            Action::Replace(Bytes::from_static(b"x")),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Replace)),
        ),
        (
            ActionKind::ReplacePayload,
            Action::ReplacePayload(Bytes::from_static(b"x")),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::ReplacePayload)),
        ),
        (
            ActionKind::Delay,
            Action::Pass.delayed(Duration::from_millis(1)),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Delay)),
        ),
        (
            ActionKind::Hold,
            Action::Pass.held(Gate::new()),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Hold)),
        ),
        (
            ActionKind::DropElide,
            Action::Drop(DropMode::Elide),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::DropElide)),
        ),
        (
            ActionKind::Truncate,
            Action::Truncate { bytes: 1, code: 0x0 },
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Truncate)),
        ),
        (ActionKind::ResetStream, Action::ResetStream { code: 0x5 }, Support::Yes),
    ];
    for (kind, action, want) in end_cases {
        let header = subgroup_header(draft, SubgroupMode::Explicit);
        rig.script().stream_end = vec![action];
        rig.push_uni(&header).await;
        let (got, ending) = rig.relay_stream().await;
        let events = rig.take(3, "stream end (data)").await;
        let what = format!("StreamEnd(data) × {kind:?}");
        match want {
            Support::Yes => {
                one_applied(
                    &events[2..3],
                    Site::StreamEnd,
                    kind,
                    &Effect::StreamReset {
                        code: 0x5,
                        code_defined: stream_reset_code_defined(draft),
                    },
                    &what,
                );
                assert_eq!(ending, common::Ending::Reset(0x5), "[{draft}] {what}");
                // `reset()` discards whatever is still in the local send
                // buffer and clears the peer's receive assembler, so
                // the header may or may not have made it out. A prefix is
                // the only honest claim; the reset is the observable effect.
                assert!(
                    header.starts_with(&got),
                    "[{draft}] {what}: whatever arrived must be a prefix of the header",
                );
                sw.cover(cell(Column::StreamEndData, kind), "Yes: the FIN becomes a reset");
            }
            Support::No(refusal) => {
                one_refused(&events[2..3], Site::StreamEnd, kind, &refusal, &what);
                assert_eq!(ending, common::Ending::Fin, "[{draft}] {what}: the FIN is untouched");
                assert_eq!(
                    hex(&got),
                    hex(&header),
                    "[{draft}] {what}: a refused stream end leaves the stream exactly as it was",
                );
                sw.cover(cell(Column::StreamEndData, kind), "✗ WrongSite, the FIN is untouched");
            }
            other => unreachable!("{other:?}"),
        }
    }

    rig.finish(sw).await;
}

/// Drive one subgroup stream carrying exactly one object, and return the
/// three events it produced (open, header, the object's).
async fn one_object_stream(
    rig: &mut Rig,
    mode: SubgroupMode,
    payload: &[u8],
    action: Action,
    what: &str,
) -> Vec<Obs> {
    let draft = rig.draft;
    let header = subgroup_header(draft, mode);
    let object = subgroup_object(draft, None, 0, payload, None);
    let mut bytes = header.clone();
    bytes.extend_from_slice(&object);
    let deferred = matches!(action, Action::Delay { .. } | Action::Hold { .. });
    {
        let mut s = rig.script();
        s.object = vec![action];
        s.stream_end = vec![Action::Pass];
    }
    rig.push_uni(&bytes).await;
    let (got, ending) = rig.relay_stream().await;
    let want = if deferred { 5 } else { 4 };
    let events = rig.take(want, what).await;
    assert_eq!(events.len(), want, "[{draft}] {what}: {events:#?}");
    assert_eq!(ending, common::Ending::Fin, "[{draft}] {what} ends cleanly");
    // A refused or delayed unit still reaches the wire unchanged; an elided
    // one does not, and its caller asserts the refusal instead.
    if !matches!(events[2], Obs::Applied(_, ActionKind::DropElide, _)) {
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] {what}: the wire is unchanged");
    }
    events
}

/// Lowercase hex, so a byte-level failure prints something readable.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ── Objects on a fetch stream ──────────────────────────────────────────

async fn sweep_fetch_streams(draft: DraftVersion, sw: &mut Sweep) {
    let fe = Column::ObjectFetch;
    let cell = |kind| Cell { draft, column: fe, kind };
    let hook = ScriptedHook::new(all_interest(), Script::default());
    let mut rig = Rig::new(draft, Arc::clone(&hook)).await;

    // Every draft: the framed fetch column. Same shape as the subgroup
    // sweep's stream 1, minus the subgroup-ID guard — a fetch object names
    // its own group and subgroup, so eliding one can never redefine a
    // subgroup ID. What refuses an elide differs across the boundary at
    // draft-15 and is the one branch below.
    //
    // Drafts 18 and 19 join this column rather than a bypassed one of their
    // own, and `arm_fetch` is the whole difference: their Group IDs are
    // differences the FETCH's Group Order gives a direction to, and the
    // session has now been told it. The objects below state all four of
    // their fields on those two as on 15-17, so the first object's deltas
    // are its absolute Location and every later one opens a group of its
    // own — which nothing here asserts about, because what this column
    // measures is what may be done to an object rather than where it sits.
    rig.arm_fetch().await;
    let mut bytes = fetch_header();
    let mut raw = Vec::new();
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let o = fetch_object(draft, 7, i as u64, payload, None);
        bytes.extend_from_slice(&o);
        raw.push(o);
    }
    let status = fetch_object(draft, 7, 5, &[], Some(3));
    bytes.extend_from_slice(&status);
    raw.push(status);
    let gone = fetch_object(draft, 7, 6, b"hhhh", None);
    bytes.extend_from_slice(&gone);
    {
        let mut s = rig.script();
        s.object = vec![
            Action::Pass,
            Action::ReplacePayload(Bytes::from_static(b"BBBB")),
            Action::ReplacePayload(Bytes::from_static(b"CC")),
            Action::Replace(Bytes::from_static(b"zz")),
            Action::Replace(Bytes::from_static(b"zz")),
            Action::Drop(DropMode::Elide),
            Action::Drop(DropMode::Elide),
        ];
        s.stream_end = vec![Action::Pass];
    }
    rig.push_uni(&bytes).await;
    let (got, ending) = rig.relay_stream().await;
    let events = rig.take(10, "fetch stream").await;
    assert_eq!(events.len(), 10, "[{draft}] fetch stream events: {events:#?}");

    one_applied(
        &events[2..3],
        Site::Object,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "fetch object 0 Pass",
    );
    sw.cover(cell(ActionKind::Pass), "Pass: forwarded verbatim");

    let spliced = {
        let mut v = raw[1].clone();
        let n = v.len();
        v[n - 4..].copy_from_slice(b"BBBB");
        v
    };
    one_applied(
        &events[3..4],
        Site::Object,
        ActionKind::ReplacePayload,
        &Effect::Replaced { bytes: spliced.len() },
        "fetch object 1 ReplacePayload",
    );
    sw.cover(cell(ActionKind::ReplacePayload), "~L holding");
    one_refused(
        &events[4..5],
        Site::Object,
        ActionKind::ReplacePayload,
        &Refusal::LengthChanged { from: 4, to: 2 },
        "fetch object 2 ReplacePayload",
    );
    sw.cover(cell(ActionKind::ReplacePayload), "~L failing: LengthChanged");
    for (n, kind) in [(5usize, ActionKind::Replace), (6, ActionKind::ReplaceObject)] {
        one_refused(
            &events[n..n + 1],
            Site::Object,
            ActionKind::Replace,
            &Refusal::WrongSite { site: Site::Object, action: ActionKind::ReplaceObject },
            "Action::Replace on a fetch object",
        );
        sw.cover(cell(kind), "✗ WrongSite { Object, ReplaceObject }");
    }
    // The status guard is the only one a fetch elide meets, and only the
    // drafts that still have a status field can fail it. On 16 and 17 the
    // same fixture produces an ordinary zero-length object and both elides
    // apply.
    let renumbered = fetch_objects_use_serialization_flags(draft);
    if fetch_objects_carry_a_status(draft) {
        one_refused(
            &events[7..8],
            Site::Object,
            ActionKind::DropElide,
            &Refusal::WouldDestroyStatusObject,
            "fetch status object Drop(Elide)",
        );
        sw.cover(cell(ActionKind::DropElide), "~S failing: WouldDestroyStatusObject");
    } else {
        // `~S` has no failing side on a fetch stream of these drafts, and
        // that is a claim about the draft rather than a gap in the sweep.
        // The object probed here is byte for byte the shape that *is* a
        // status object on draft-15 — zero payload length — and it is
        // elided rather than refused, which is what stops "the precondition
        // never failed here" from being indistinguishable from "the probe
        // was skipped".
        one_applied(
            &events[7..8],
            Site::Object,
            ActionKind::DropElide,
            &Effect::Elided { renumbered_successor: renumbered },
            "fetch object 5 Drop(Elide)",
        );
        sw.cover(
            cell(ActionKind::DropElide),
            "~S has no failing side here: a zero-length fetch object is not a status object",
        );
        sw.notes.push(format!(
            "[{draft}] ~S failing is unreachable on a fetch stream: this draft removed the              Object Status field from fetch objects, so a zero-length fetch frame is an object              with no bytes rather than a status object. Both probes are holding-side, and the              first one is the byte shape that refuses on draft-15"
        ));
    }
    one_applied(
        &events[8..9],
        Site::Object,
        ActionKind::DropElide,
        // A fetch object of drafts 07-14 states every field outright, so
        // nothing behind it is re-encoded; from draft-15 the next frame is,
        // and here there is none because this object is the last.
        &Effect::Elided { renumbered_successor: renumbered },
        "fetch object 6 Drop(Elide)",
    );
    sw.cover(cell(ActionKind::DropElide), "~S holding: Elided");

    // Object 6 is elided on every draft; object 5 survives only where it is
    // a status object, which is the one thing that refuses. Every object this
    // fixture writes states all four of its fields, so no survivor is
    // re-encoded and the wire is the source with the holes cut out of it.
    let mut want = fetch_header();
    want.extend_from_slice(&raw[0]);
    want.extend_from_slice(&spliced);
    for (i, o) in raw[2..].iter().enumerate() {
        if i + 2 == 5 && !fetch_objects_carry_a_status(draft) {
            continue;
        }
        want.extend_from_slice(o);
    }
    assert_eq!(ending, common::Ending::Fin);
    assert_eq!(hex(&got), hex(&want), "[{draft}] fetch stream wire");

    // Delay / Hold / Truncate / ResetStream on a fetch stream.
    for (kind, action) in [
        (ActionKind::Delay, Action::Pass.delayed(Duration::from_millis(40))),
        (ActionKind::Truncate, Action::Truncate { bytes: 4, code: 0x2 }),
        (ActionKind::ResetStream, Action::ResetStream { code: 0x2 }),
    ] {
        rig.arm_fetch().await;
        let mut bytes = fetch_header();
        bytes.extend_from_slice(&fetch_object(draft, 7, 0, b"qqqqqqqq", None));
        {
            let mut s = rig.script();
            s.object = vec![action];
            s.stream_end = vec![Action::Pass];
        }
        rig.push_uni(&bytes).await;
        let (_got, ending) = rig.relay_stream().await;
        match kind {
            ActionKind::Delay => {
                let events = rig.take(5, "fetch Delay").await;
                queued_then(
                    &events[2..4],
                    ActionKind::Delay,
                    ActionKind::Pass,
                    &Effect::ForwardedVerbatim,
                    "Delay on a fetch object",
                );
                assert_eq!(ending, common::Ending::Fin);
                sw.cover(cell(kind), "Yes: Queued then released");
            }
            ActionKind::Truncate => {
                let events = rig.take(3, "fetch Truncate").await;
                one_applied(
                    &events[2..3],
                    Site::Object,
                    ActionKind::Truncate,
                    &Effect::Truncated {
                        forwarded: 4,
                        code: 0x2,
                        code_defined: stream_reset_code_defined(draft),
                    },
                    "Truncate on a fetch object",
                );
                assert_eq!(ending, common::Ending::Reset(0x2));
                sw.cover(cell(kind), "Yes: prefix then RESET_STREAM(0x2)");
            }
            _ => {
                let events = rig.take(3, "fetch ResetStream").await;
                one_applied(
                    &events[2..3],
                    Site::Object,
                    ActionKind::ResetStream,
                    &Effect::StreamReset {
                        code: 0x2,
                        code_defined: stream_reset_code_defined(draft),
                    },
                    "ResetStream on a fetch object",
                );
                assert_eq!(ending, common::Ending::Reset(0x2));
                sw.cover(cell(kind), "Yes: RESET_STREAM(0x2)");
            }
        }
    }

    // `Hold` needs its gate released from outside, so it is spelled out.
    {
        let gate = Gate::new();
        let armed = gate.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            armed.release();
        });
        rig.arm_fetch().await;
        let mut bytes = fetch_header();
        bytes.extend_from_slice(&fetch_object(draft, 7, 0, b"held", None));
        {
            let mut s = rig.script();
            s.object = vec![Action::Pass.held(gate)];
            s.stream_end = vec![Action::Pass];
        }
        rig.push_uni(&bytes).await;
        let (_got, ending) = rig.relay_stream().await;
        let events = rig.take(5, "fetch Hold").await;
        queued_then(
            &events[2..4],
            ActionKind::Hold,
            ActionKind::Pass,
            &Effect::ForwardedVerbatim,
            "Hold on a fetch object",
        );
        assert_eq!(ending, common::Ending::Fin);
        sw.cover(cell(ActionKind::Hold), "Yes: Queued then released");
    }

    rig.finish(sw).await;
}

// ── The Datagram column ────────────────────────────────────────────────

async fn sweep_datagrams(draft: DraftVersion, sw: &mut Sweep) {
    let dg = Column::Datagram;
    let cell = |kind| Cell { draft, column: dg, kind };
    let hook = ScriptedHook::new(all_interest(), Script::default());
    let mut rig = Rig::new(draft, Arc::clone(&hook)).await;
    let relay = rig.relay.connection().await;

    // A datagram whose header does not decode is the `~D` failing side and
    // is indifferent for every other cell here: `Pass`, `Replace`, `Drop`
    // and the four `WrongSite` refusals never look at a payload boundary.
    let raw = Bytes::from_static(UNDECODABLE_DATAGRAM);

    // Pass.
    rig.script().datagram = vec![Action::Pass];
    rig.client.send_datagram(raw.clone()).expect("client datagram");
    let events = rig.take(1, "datagram Pass").await;
    one_applied(
        &events[0..1],
        Site::Datagram,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "datagram Pass",
    );
    let got = recv_datagram(&relay).await;
    assert_eq!(hex(&got), hex(&raw), "[{draft}] Pass forwards the datagram verbatim");
    sw.cover(cell(ActionKind::Pass), "Yes: forwarded verbatim");

    // Replace, within the path MTU.
    rig.script().datagram = vec![Action::Replace(Bytes::from_static(b"REPL"))];
    rig.client.send_datagram(raw.clone()).expect("client datagram");
    let events = rig.take(1, "datagram Replace").await;
    one_applied(
        &events[0..1],
        Site::Datagram,
        ActionKind::Replace,
        &Effect::Replaced { bytes: 4 },
        "datagram Replace",
    );
    let got = recv_datagram(&relay).await;
    assert_eq!(&got[..], b"REPL", "[{draft}] the replacement is what reaches the relay");
    sw.cover(cell(ActionKind::Replace), "~M holding: Replaced");

    // Replace, above it: admitted, then rejected by the transport. The
    // report is `ActionFailed`, not `ActionRefused`, and the session lives.
    //
    // Two events, and the order is the claim: `execute` admits the action
    // and reports `ActionApplied` before anything reaches the transport,
    // and `forward_datagrams` reports `ActionFailed` when `send_datagram`
    // then declines it. Neither event alone would be the whole truth.
    rig.script().datagram = vec![Action::Replace(Bytes::from(vec![0x5A; 9000]))];
    rig.client.send_datagram(raw.clone()).expect("client datagram");
    let events = rig.take(2, "datagram Replace above the MTU").await;
    assert_eq!(events.len(), 2, "[{draft}] expected admission then transport failure: {events:#?}");
    match (&events[0], &events[1]) {
        (
            Obs::Applied(Site::Datagram, ActionKind::Replace, Effect::Replaced { bytes: 9000 }),
            Obs::Failed(Site::Datagram, ActionKind::Replace, _),
        ) => {}
        other => panic!(
            "[{draft}] an oversized replacement is admitted and then fails in the transport — \
             ActionApplied then ActionFailed, never ActionRefused. Got {other:#?}",
        ),
    }
    sw.cover(cell(ActionKind::Replace), "~M failing: ActionFailed, session survives");

    // ReplacePayload, both sides of `~D`.
    if let Some(decodable) = decodable_datagram(draft) {
        let bytes = Bytes::from(decodable.clone());
        rig.script().datagram = vec![Action::ReplacePayload(Bytes::from_static(b"XYZW"))];
        rig.client.send_datagram(bytes.clone()).expect("client datagram");
        let events = rig.take(1, "datagram ReplacePayload").await;
        one_applied(
            &events[0..1],
            Site::Datagram,
            ActionKind::ReplacePayload,
            &Effect::Replaced { bytes: decodable.len() },
            "datagram ReplacePayload (delimited)",
        );
        let got = recv_datagram(&relay).await;
        let mut want = decodable.clone();
        let n = want.len();
        want[n - 4..].copy_from_slice(b"XYZW");
        assert_eq!(hex(&got), hex(&want), "[{draft}] the payload region is spliced");
        sw.cover(cell(ActionKind::ReplacePayload), "~D holding: Replaced");
    } else {
        // Draft-14's `~D` has no holding side at all, and that is a claim
        // about the draft rather than a gap in the sweep: a *well-formed*
        // draft-14 datagram is refused too, and with the draft-14 detail.
        // Asserting it is what stops "the precondition never held here"
        // from being indistinguishable from "the probe was skipped".
        let bytes = Bytes::from(draft14_datagram());
        rig.script().datagram = vec![Action::ReplacePayload(Bytes::from_static(b"XYZW"))];
        rig.client.send_datagram(bytes.clone()).expect("client datagram");
        let events = rig.take(1, "draft-14 ReplacePayload on a well-formed datagram").await;
        one_refused(
            &events[0..1],
            Site::Datagram,
            ActionKind::ReplacePayload,
            &Refusal::PayloadNotDelimited { detail: "draft-14 header decode consumes the payload" },
            "draft-14 ReplacePayload on a datagram that decodes cleanly",
        );
        let got = recv_datagram(&relay).await;
        assert_eq!(hex(&got), hex(&bytes), "[{draft}] and it is forwarded unchanged");
        sw.cover(
            cell(ActionKind::ReplacePayload),
            "~D has no holding side on draft-14: even a well-formed datagram is refused",
        );
        sw.notes.push(format!(
            "[{draft}] ~D holding is unreachable: draft-14's AnyDatagramHeader decode consumes \
             the payload, so no draft-14 datagram is ever delimited. Both probes are \
             failing-side, and the second one proves it is the draft and not the fixture",
        ));
    }

    let detail = if draft == DraftVersion::Draft14 {
        "draft-14 header decode consumes the payload"
    } else {
        "datagram header did not decode"
    };
    rig.script().datagram = vec![Action::ReplacePayload(Bytes::from_static(b"XYZW"))];
    rig.client.send_datagram(raw.clone()).expect("client datagram");
    let events = rig.take(1, "datagram ReplacePayload, undelimited").await;
    one_refused(
        &events[0..1],
        Site::Datagram,
        ActionKind::ReplacePayload,
        &Refusal::PayloadNotDelimited { detail },
        "datagram ReplacePayload (not delimited)",
    );
    let got = recv_datagram(&relay).await;
    assert_eq!(hex(&got), hex(&raw), "[{draft}] a refused datagram is forwarded unchanged");
    sw.cover(cell(ActionKind::ReplacePayload), "~D failing: PayloadNotDelimited");

    // Drop.
    rig.script().datagram = vec![Action::Drop(DropMode::Elide)];
    rig.client.send_datagram(raw.clone()).expect("client datagram");
    let events = rig.take(1, "datagram Drop").await;
    one_applied(
        &events[0..1],
        Site::Datagram,
        ActionKind::DropElide,
        &Effect::Dropped,
        "datagram Drop(Elide)",
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(400), relay.read_datagram()).await.is_err(),
        "[{draft}] a dropped datagram never reaches the relay",
    );
    sw.cover(cell(ActionKind::DropElide), "Yes: Dropped, nothing on the wire");

    // The four `WrongSite` refusals: datagrams have no queue and no stream.
    for (kind, action) in [
        (ActionKind::Delay, Action::Pass.delayed(Duration::from_millis(1))),
        (ActionKind::Hold, Action::Pass.held(Gate::new())),
        (ActionKind::Truncate, Action::Truncate { bytes: 1, code: 0x0 }),
        (ActionKind::ResetStream, Action::ResetStream { code: 0x0 }),
    ] {
        rig.script().datagram = vec![action];
        rig.client.send_datagram(raw.clone()).expect("client datagram");
        let events = rig.take(1, "datagram WrongSite").await;
        one_refused(
            &events[0..1],
            Site::Datagram,
            kind,
            &Refusal::WrongSite { site: Site::Datagram, action: kind },
            &format!("Datagram × {kind:?}"),
        );
        let got = recv_datagram(&relay).await;
        assert_eq!(hex(&got), hex(&raw), "[{draft}] a refused datagram is forwarded unchanged");
        sw.cover(cell(kind), "✗ WrongSite, forwarded unchanged");
    }

    rig.finish(sw).await;
}

async fn recv_datagram(conn: &quinn::Connection) -> Bytes {
    tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("a datagram within 5 s")
        .expect("datagram")
}

// ── The Control column, on both sides of its precondition ──────────────

async fn sweep_control(draft: DraftVersion, sw: &mut Sweep) {
    let cell = |kind| Cell { draft, column: Column::Control, kind };
    let hook = ScriptedHook::new(all_interest(), Script::default());
    let mut rig = Rig::new(draft, Arc::clone(&hook)).await;
    // What the probes below drive is a bidirectional stream. On 07-16 that
    // is the control stream itself; on 17-20 it is a *request* stream, which
    // is a second shape of the same control plane and reaches the same site
    // with the same framing. Either way the cell is `Yes`. The uni pair that
    // carries SETUP on 17-20 is driven end to end in
    // `control_plane_uni.rs`, not here. Labelled in the coverage report.
    let uni_pair = control_plane_is_a_uni_pair(draft);
    let note = if uni_pair { "Yes (probed on a request stream)" } else { "Yes" };

    let frame = goaway_frame(draft, b"moqt://one");
    let replacement = goaway_frame(draft, b"moqt://two-and-longer");

    // The opening frame is written **before** the relay accepts, and that
    // ordering is load-bearing twice over: quinn does not put a
    // bidirectional stream on the wire until the first bytes go out, and
    // `forward_control_stream` does not open its relay-side stream until it
    // has accepted the client's. On drafts 07-14 the opening frame must
    // also be a real CLIENT_SETUP — `pipe_control_mutating` forwards
    // nothing until `detect_draft_from_setup` has resolved a draft.
    // Either way, the opening frame's own decision is the `Pass` cell.
    let (mut client_send, _client_recv) =
        rig.client.open_bi().await.expect("client control stream");
    let opening = if draft.number() <= 14 { client_setup_frame(draft) } else { frame.clone() };
    rig.script().control = vec![Action::Pass];
    client_send.write_all(&opening).await.expect("write the opening control frame");

    let (_relay_send, relay_recv) = rig.relay.accept_bi().await;
    let rx = common::TimedReceiver::spawn(relay_recv);
    let mut expected: Vec<u8> = Vec::new();

    let events = rig.take(1, "control Pass").await;
    one_applied(
        &events[0..1],
        Site::Control,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "control Pass",
    );
    expected.extend_from_slice(&opening);
    assert_eq!(
        hex(&rx.wait_for_bytes(expected.len()).await),
        hex(&expected),
        "[{draft}] a passed control frame reaches the relay unchanged",
    );
    sw.cover(cell(ActionKind::Pass), note);

    // Replace.
    rig.script().control = vec![Action::Replace(Bytes::from(replacement.clone()))];
    client_send.write_all(&frame).await.expect("write GOAWAY");
    let events = rig.take(1, "control Replace").await;
    one_applied(
        &events[0..1],
        Site::Control,
        ActionKind::Replace,
        &Effect::Replaced { bytes: replacement.len() },
        "control Replace",
    );
    expected.extend_from_slice(&replacement);
    assert_eq!(
        hex(&rx.wait_for_bytes(expected.len()).await),
        hex(&expected),
        "[{draft}] the replacement frame is what the relay receives",
    );
    sw.cover(cell(ActionKind::Replace), note);

    // Delay.
    rig.script().control = vec![Action::Pass.delayed(Duration::from_millis(40))];
    client_send.write_all(&frame).await.expect("write GOAWAY");
    let events = rig.take(2, "control Delay").await;
    queued_then(
        &events[0..2],
        ActionKind::Delay,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "control Delay",
    );
    expected.extend_from_slice(&frame);
    assert_eq!(hex(&rx.wait_for_bytes(expected.len()).await), hex(&expected));
    sw.cover(cell(ActionKind::Delay), note);

    // Hold.
    let gate = Gate::new();
    let armed = gate.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        armed.release();
    });
    rig.script().control = vec![Action::Pass.held(gate)];
    client_send.write_all(&frame).await.expect("write GOAWAY");
    let events = rig.take(2, "control Hold").await;
    queued_then(
        &events[0..2],
        ActionKind::Hold,
        ActionKind::Pass,
        &Effect::ForwardedVerbatim,
        "control Hold",
    );
    expected.extend_from_slice(&frame);
    assert_eq!(hex(&rx.wait_for_bytes(expected.len()).await), hex(&expected));
    sw.cover(cell(ActionKind::Hold), note);

    // Drop.
    rig.script().control = vec![Action::Drop(DropMode::Elide)];
    client_send.write_all(&frame).await.expect("write GOAWAY");
    let events = rig.take(1, "control Drop").await;
    one_applied(
        &events[0..1],
        Site::Control,
        ActionKind::DropElide,
        &Effect::Dropped,
        "control Drop(Elide)",
    );
    common::assert_no_bytes_for(&rx, Duration::from_millis(300)).await;
    sw.cover(cell(ActionKind::DropElide), note);

    // The three refusals.
    for (kind, action, refusal) in [
        (
            ActionKind::ReplacePayload,
            Action::ReplacePayload(Bytes::from_static(b"x")),
            Refusal::WrongSite { site: Site::Control, action: ActionKind::ReplacePayload },
        ),
        (
            ActionKind::Truncate,
            Action::Truncate { bytes: 1, code: 0x0 },
            Refusal::ControlStreamResetIllegal,
        ),
        (
            ActionKind::ResetStream,
            Action::ResetStream { code: 0x0 },
            Refusal::ControlStreamResetIllegal,
        ),
    ] {
        rig.script().control = vec![action];
        client_send.write_all(&frame).await.expect("write GOAWAY");
        let events = rig.take(1, "control refusal").await;
        one_refused(
            &events[0..1],
            Site::Control,
            kind,
            &refusal,
            &format!("Control × {kind:?} on {draft}"),
        );
        expected.extend_from_slice(&frame);
        assert_eq!(
            hex(&rx.wait_for_bytes(expected.len()).await),
            hex(&expected),
            "[{draft}] a refused control frame is forwarded unchanged",
        );
        sw.cover(cell(kind), "✗: refused, bytes unchanged");
    }

    // Nothing about the control plane is impaired on any draft. This is the
    // whole-session form of that: every event this session produced was
    // claimed by a probe above, so a report emitted at session start — which
    // is where a topology complaint would be raised — has nowhere to hide.
    // `rig.finish` re-reads the same events and would fail the refusal count
    // as well.
    assert!(
        rig.unconsumed_events().is_empty(),
        "[{draft}] the control sweep must leave no event unaccounted for: {:?}",
        rig.unconsumed_events(),
    );

    drop(rx);
    rig.finish(sw).await;
}

// ── The StreamEnd (control) column ─────────────────────────────────────

async fn sweep_stream_end_control(draft: DraftVersion, sw: &mut Sweep) {
    // The control stream ends **once** per session — `forward_control_stream`
    // returns as soon as either direction finishes, and that ends the
    // session — so each cell here costs a session of its own.
    let cases: [(ActionKind, Action, Support); 8] = [
        (ActionKind::Pass, Action::Pass, Support::Yes),
        (
            ActionKind::Replace,
            Action::Replace(Bytes::from_static(b"x")),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Replace)),
        ),
        (
            ActionKind::ReplacePayload,
            Action::ReplacePayload(Bytes::from_static(b"x")),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::ReplacePayload)),
        ),
        (
            ActionKind::Delay,
            Action::Pass.delayed(Duration::from_millis(1)),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Delay)),
        ),
        (
            ActionKind::Hold,
            Action::Pass.held(Gate::new()),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::Hold)),
        ),
        (
            ActionKind::DropElide,
            Action::Drop(DropMode::Elide),
            Support::No(wrong_site(Site::StreamEnd, ActionKind::DropElide)),
        ),
        (
            ActionKind::Truncate,
            Action::Truncate { bytes: 1, code: 0x0 },
            Support::No(Refusal::ControlStreamResetIllegal),
        ),
        (
            ActionKind::ResetStream,
            Action::ResetStream { code: 0x0 },
            Support::No(Refusal::ControlStreamResetIllegal),
        ),
    ];

    for (kind, action, want) in cases {
        let hook = ScriptedHook::new(all_interest(), Script::default());
        let mut rig = Rig::new(draft, Arc::clone(&hook)).await;
        rig.script().stream_end = vec![action];
        // One byte, then FIN. The byte is what puts the bidirectional
        // stream on the wire at all — quinn creates it lazily, so a
        // `finish()` with nothing written never reaches
        // `forward_control_stream`'s `accept_bi`. It is deliberately not a
        // whole frame: `0x00` leaves every draft's parser in `NeedMore`, so
        // the only decision this session takes is the one under test.
        let (mut send, _recv) = rig.client.open_bi().await.expect("client control stream");
        send.write_all(&[0x00]).await.expect("write the stream-opening byte");
        let _ = send.finish();
        let events = rig.take(1, "stream end (control)").await;
        let what = format!("StreamEnd(control) × {kind:?}");
        match want {
            Support::Yes => {
                one_applied(
                    &events[0..1],
                    Site::StreamEnd,
                    kind,
                    &Effect::ForwardedVerbatim,
                    &what,
                );
                sw.cover(
                    Cell { draft, column: Column::StreamEndControl, kind },
                    "Yes: the control stream's FIN is forwarded",
                );
            }
            Support::No(refusal) => {
                one_refused(&events[0..1], Site::StreamEnd, kind, &refusal, &what);
                sw.cover(
                    Cell { draft, column: Column::StreamEndControl, kind },
                    "✗: refused, the FIN is untouched",
                );
            }
            other => unreachable!("{other:?}"),
        }
        rig.finish(sw).await;
    }
}

// ── `CloseSession`, which ends the session it is honoured in ───────────

async fn sweep_close_session(draft: DraftVersion, sw: &mut Sweep) {
    let mut columns = vec![
        Column::ObjectSubgroup,
        Column::Control,
        Column::Datagram,
        Column::StreamEndData,
        Column::StreamEndControl,
    ];
    columns.push(Column::ObjectFetch);

    for column in columns {
        let hook = ScriptedHook::new(all_interest(), Script::default());
        let mut rig = Rig::new(draft, Arc::clone(&hook)).await;
        let close = Action::CloseSession { code: 0x2, reason: Bytes::from_static(b"matrix") };
        let want = 1 + usize::from(matches!(
            column,
            Column::ObjectSubgroup | Column::ObjectFetch | Column::StreamEndData
        )) * 2;

        // The control-stream halves live out here, not in the match arm
        // that opens them. Dropping a `quinn::RecvStream` sends
        // `STOP_SENDING(0)`, and the proxy now *notices* one on an idle
        // stream — so a half dropped at the end of its arm would race
        // the probe's own decision with a teardown decision the probe never
        // asked for. Same discipline as `actions_teardown.rs`'s
        // `propagation_case`.
        let mut idle_send: Option<quinn::SendStream> = None;
        let mut idle_recv: Option<quinn::RecvStream> = None;

        match column {
            Column::ObjectSubgroup => {
                rig.script().object = vec![close];
                let mut bytes = subgroup_header(draft, SubgroupMode::Explicit);
                bytes.extend_from_slice(&subgroup_object(draft, None, 0, b"bye!", None));
                rig.push_uni(&bytes).await;
            }
            Column::ObjectFetch => {
                rig.arm_fetch().await;
                rig.script().object = vec![close];
                let mut bytes = fetch_header();
                bytes.extend_from_slice(&fetch_object(draft, 7, 0, b"bye!", None));
                rig.push_uni(&bytes).await;
            }
            Column::StreamEndData => {
                rig.script().stream_end = vec![close];
                rig.push_uni(&subgroup_header(draft, SubgroupMode::Explicit)).await;
            }
            Column::Datagram => {
                rig.script().datagram = vec![close];
                rig.client
                    .send_datagram(Bytes::from_static(UNDECODABLE_DATAGRAM))
                    .expect("client datagram");
            }
            Column::Control => {
                let (mut send, recv) = rig.client.open_bi().await.expect("control stream");
                if draft.number() <= 14 {
                    // The SETUP that lets the parser start, then the frame
                    // the close is taken on.
                    rig.script().control = vec![Action::Pass, close];
                    send.write_all(&client_setup_frame(draft)).await.expect("setup");
                    let _ = rig.take(1, "close: CLIENT_SETUP").await;
                } else {
                    rig.script().control = vec![close];
                }
                send.write_all(&goaway_frame(draft, b"moqt://bye")).await.expect("goaway");
                idle_send = Some(send);
                idle_recv = Some(recv);
            }
            Column::StreamEndControl => {
                rig.script().stream_end = vec![close];
                let (mut send, recv) = rig.client.open_bi().await.expect("control stream");
                send.write_all(&[0x00]).await.expect("stream-opening byte");
                let _ = send.finish();
                idle_send = Some(send);
                idle_recv = Some(recv);
            }
            other => unreachable!("{other:?}"),
        }

        let events = rig.take(want, "CloseSession").await;
        let what = format!("{} × CloseSession", column.label());
        one_applied(
            &events[want - 1..want],
            column.site(),
            ActionKind::CloseSession,
            &Effect::SessionClosing { code: 0x2 },
            &what,
        );
        // The observable effect: the proxy closes the client leg with the
        // code the hook asked for.
        match tokio::time::timeout(Duration::from_secs(5), rig.client.closed()).await {
            Ok(quinn::ConnectionError::ApplicationClosed(frame)) => assert_eq!(
                frame.error_code.into_inner(),
                0x2,
                "[{draft}] {what}: the session closes with the code the hook named",
            ),
            Ok(other) => panic!("[{draft}] {what}: expected an application close, got {other:?}"),
            Err(_) => panic!("[{draft}] {what}: the session did not close within 5 s"),
        }
        sw.cover(Cell { draft, column, kind: ActionKind::CloseSession }, "Yes: the session closes");
        drop(idle_send);
        drop(idle_recv);
        rig.finish(sw).await;
    }

    // `Refusal::SessionAlreadyClosing` — the first close wins. Two object
    // hooks are held at a barrier so that both reach the engine; without it
    // `SessionCloser::request` cancels the session before the second
    // attempt exists, and the variant would be unreachable by luck rather
    // than by design.
    if draft == DraftVersion::Draft14 {
        let script = Script {
            object: vec![
                Action::CloseSession { code: 0x2, reason: Bytes::from_static(b"first") },
                Action::CloseSession { code: 0x3, reason: Bytes::from_static(b"second") },
            ],
            ..Script::default()
        };
        let hook = ScriptedHook::with_object_barrier(all_interest(), script, 2);
        let mut rig = Rig::new(draft, Arc::clone(&hook)).await;
        let mut bytes = subgroup_header(draft, SubgroupMode::Explicit);
        bytes.extend_from_slice(&subgroup_object(draft, None, 0, b"one!", None));
        rig.push_uni(&bytes).await;
        rig.push_uni(&bytes).await;
        let events = rig.take(6, "two racing closes").await;
        let refused: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, Obs::Refused(_, _, Refusal::SessionAlreadyClosing)))
            .collect();
        assert_eq!(
            refused.len(),
            1,
            "the second CloseSession must be refused with SessionAlreadyClosing: {events:#?}",
        );
        rig.finish(sw).await;
    }
}

// ── The cells nothing can attempt ──────────────────────────────────────

/// Record every `NotAttemptable` cell's disposition.
///
/// There is no stimulus to run: no value of `Action` or `StreamAction`
/// carries the kind to the site, which is the whole content of the verdict.
/// What makes this an assertion rather than a shrug is the *negative* check
/// in `the_capability_table_matches_observed_behaviour`: across the entire
/// sweep, no event of any kind ever named one of these `(site, kind)` pairs.
fn record_not_attemptable(draft: DraftVersion, sw: &mut Sweep) {
    for column in COLUMNS {
        for kind in KINDS {
            let cell = Cell { draft, column, kind };
            if let Support::NotAttemptable { why, .. } = classified(cell) {
                let how = match why {
                    NotAttemptable::NoConstructor => {
                        "⊘ NoConstructor: proved by a compile_fail doc-test on a src/ item"
                    }
                    NotAttemptable::SiteReturnsAction => {
                        "⊘ SiteReturnsAction: this site's hook method returns Action"
                    }
                    NotAttemptable::SiteReturnsStreamAction => {
                        "⊘ SiteReturnsStreamAction: this site's hook method returns StreamAction"
                    }
                    NotAttemptable::KindNotDefinedAtThisSite => {
                        "⊘ KindNotDefinedAtThisSite: no unit here carries this kind"
                    }
                    other => panic!("a new NotAttemptable family reached the sweep: {other:?}"),
                };
                sw.cover(cell, how);
            }
        }
    }
}

// ============================================================
// Test bodies
// ============================================================

/// One forwarded stream is one [`StreamKey`], at all three stream sites.
///
/// `StreamCtx::key`'s rustdoc claims the key is *stable across the three
/// sites* and *unique for the session's lifetime*. Without this test both
/// are prose: `the_capability_table_matches_observed_behaviour` never reads
/// a key, so a `key()` that minted a fresh id per site would sweep green —
/// and `SerializeAfter` would then name a stream that no site can hand
/// back. Ablation: replacing `st.key` with a fresh `ctx.mint_key(side)` at
/// the `StreamEnd` site reddens the "one key must reach open, header and
/// end" assertion below.
///
/// **What it deliberately does not gate**, so the claim is not
/// over-read: the third half of that rustdoc — *not the transport stream
/// id* — is **invisible here**. This runs over QUIC, where transport
/// stream ids are already distinct per stream and stable across the three
/// sites, so a `key()` returning `stream_id` passes every assertion below.
/// Measured: with `key()` rewritten to `StreamKey { side, id: stream_id }`
/// this file stays 8/8 green and only
/// `hook_api::the_hook_trait_is_dyn_compatible` goes red, which is where
/// that half is gated (a `StreamCtx` built with `stream_id: 4` and
/// `id: 9`, asserted unequal). The case the distinction actually exists for
/// — WebTransport, where every stream reports id `0` — has no test in this
/// tree at all.
///
/// One draft and one session, because neither gated claim is per-draft: the
/// key is minted in the accept loop, above every codec.
#[tokio::test]
async fn a_streams_key_is_stable_across_its_three_sites() {
    let draft = DRAFTS[0];
    let hook = ScriptedHook::new(all_interest(), Script::default());
    let mut rig = Rig::new(draft, Arc::clone(&hook)).await;

    for _ in 0..2 {
        let bytes = subgroup_header(draft, SubgroupMode::Explicit);
        rig.push_uni(&bytes).await;
        let (_, ending) = rig.relay_stream().await;
        assert_eq!(ending, common::Ending::Fin, "[{draft}]");
        let _ = rig.take(3, "one uni stream, three stream sites").await;
    }

    // The control stream's own two directions register keys too, and they
    // are minted first; the two uni streams are the entries on the ingress
    // side that reached all three sites.
    let seen = hook.keys();
    let uni: Vec<_> = seen.iter().filter(|(site, _, _)| *site == "open").collect();
    assert_eq!(uni.len(), 2, "[{draft}] two uni streams were offered: {seen:#?}");

    for (i, (_, _, key)) in uni.iter().enumerate() {
        let per_stream: Vec<_> = seen.iter().filter(|(_, _, k)| k == key).collect();
        assert_eq!(
            per_stream.len(),
            3,
            "[{draft}] stream {i}: one key must reach open, header and end, not {per_stream:#?}",
        );
        let sites: BTreeSet<&str> = per_stream.iter().map(|(s, _, _)| *s).collect();
        assert_eq!(
            sites,
            ["end", "header", "open"].into_iter().collect::<BTreeSet<_>>(),
            "[{draft}] stream {i}: the same key at all three sites",
        );
    }

    assert_ne!(uni[0].2, uni[1].2, "[{draft}] two streams must not share one key");
    assert!(
        seen.iter().all(|(_, _, k)| k.side == ProxySide::ClientToProxy),
        "[{draft}] every key here was minted on the ingress side: {seen:#?}",
    );

    let mut sweep = Sweep::default();
    rig.finish(&mut sweep).await;
}

/// The `NotAttemptable { NoConstructor }` compile proofs are doc-tests on
/// public items in `src/`, because rustdoc collects doc-tests from library
/// targets only.
///
/// This test does not run them — nothing in `tests/*.rs` can. It records
/// where they live and what `cargo test --doc -p moqtap-proxy` must report,
/// so a future edit that moves one into a test file has somewhere to fail.
///
/// **Measured**, after `OpenAfter` and `SerializeAfter` shipped:
///
/// ```text
/// $ cargo test --doc -p moqtap-proxy
/// running 8 tests
/// test crates\moqtap-proxy\src\egress.rs - egress (line 19) ... ignored
/// test crates\moqtap-proxy\src\action.rs - action::DropMode (line 378) - compile fail ... ok
/// test crates\moqtap-proxy\src\event.rs - event::ProxyEvent (line 59) ... ok
/// test crates\moqtap-proxy\src\capability.rs - capability::ActionKind::OpenAfter (line 212) ... ok
/// test crates\moqtap-proxy\src\capability.rs - capability::ActionKind::OpenAfter (line 203) ... ok
/// test crates\moqtap-proxy\src\action.rs - action::Interest::STREAMS (line 52) ... ok
/// test crates\moqtap-proxy\src\capability.rs - capability::ActionKind::OpenAfter (line 231) ... ok
/// test crates\moqtap-proxy\src\action.rs - action::DropMode (line 388) ... ok
/// test result: ok. 7 passed; 0 failed; 1 ignored
/// ```
///
/// The three `ActionKind::OpenAfter` entries carry **no** `- compile fail`
/// suffix, and that suffix is the whole difference: two of them construct
/// the shipped variants and the third asserts their verdicts, so all three
/// can only report `ok` by compiling *and* running.
///
/// **Two** `compile_fail` blocks on **two** `src/` items, each with its
/// positive companion, which is what stops a block that fails for the wrong
/// reason (a mistyped path) from counting as a proof. The count is the
/// whole point: a `compile_fail` that rustdoc never collected reports
/// `0 passed`, and that is indistinguishable from success unless somebody
/// reads the number.
///
/// It was **four blocks on three items** until those two variants shipped.
/// The pair on
/// `ActionKind::OpenAfter` did not merely become wrong — it had **never
/// been able to go red**: both blocks used struct-variant syntax
/// (`OpenAfter { after: … }`) against variants that are tuples, so they
/// would have kept failing to compile, and kept reporting `ok`, after the
/// capability existed. They are now ordinary doc-tests that *construct*
/// both variants, which can only pass by compiling and running. That is
/// why this test's list shrank by one row and its per-kind loop by two
/// entries: the two are separate lists and both had to move.
///
/// # `PROOFS` is checked against the sources, not against itself
///
/// It used to end at `assert_eq!(PROOFS.len(), 2)`, which is a compile-time
/// `2` on a `[…; 2]` — there is no one-line edit that reddens it and also
/// compiles, and `PROOFS` was referenced nowhere else in the file, so the
/// item paths it records were never checked against anything.
/// The rows are now read against the two source files themselves through
/// `include_str!`, so the count is a count of real ```` ```compile_fail ````
/// fences in `src/` and the "somewhere to fail" this test promises actually
/// exists: move a block into a test file, delete one, or add a third, and
/// this row reddens rather than the doc-test total quietly changing by one.
///
/// It cannot *run* the blocks — nothing in `tests/*.rs` can — so this is a
/// bookkeeping gate over the transcript above, which is what it always
/// claimed to be.
#[test]
fn the_no_constructor_proofs_are_doc_tests_on_src_items() {
    // (proof name, the `src/` item its rustdoc hangs on)
    const PROOFS: [(&str, &str); 1] =
        [("drop_mark_missing_is_not_constructible", "action::DropMode")];
    // The two files those item paths live in, read at compile time. A
    // module path's first segment is the file stem for both of them.
    const SOURCES: [(&str, &str); 2] = [
        ("capability", include_str!("../src/capability.rs")),
        ("action", include_str!("../src/action.rs")),
    ];
    /// The fence rustdoc keys `- compile fail` off. Three backticks, so the
    /// several prose mentions of `compile_fail` in the same files do not
    /// count themselves.
    const FENCE: &str = "```compile_fail";
    // The kinds each proof stands behind must still classify as
    // `NoConstructor`, or the proof is guarding a capability that shipped.
    // `OpenAfter` and `SerializeAfter` are gone from this loop for exactly
    // that reason, and their new verdicts are asserted by `published()`.
    // Exactly two compile proofs ship, and each one is a fence in
    // the file its item path names — checked against the source rather than
    // against `PROOFS.len()`, which is a compile-time constant.
    let mut fences = 0;
    for (stem, src) in SOURCES {
        let want = PROOFS.iter().filter(|(_, item)| item.starts_with(stem)).count();
        let got = src.matches(FENCE).count();
        assert_eq!(
            got, want,
            "src/{stem}.rs must carry exactly the `{FENCE}` blocks PROOFS \
             attributes to it; a block that moved into a test file is a proof \
             rustdoc never collects"
        );
        fences += got;
    }
    assert_eq!(fences, PROOFS.len(), "one `compile_fail` fence per proof, and no others");
    for (proof, item) in PROOFS {
        let stem = item.split("::").next().expect("an item path names its module");
        let (_, src) = SOURCES
            .iter()
            .find(|(s, _)| *s == stem)
            .unwrap_or_else(|| panic!("{item}: no source is recorded for module {stem}"));
        let last = item.rsplit("::").next().expect("an item path names an item");
        assert!(src.contains(last), "{item}: src/{stem}.rs no longer defines {last}");
        assert!(
            src.contains(proof),
            "{item}: src/{stem}.rs must name {proof} inside its block — the name \
             is the only thing tying the transcript above to a fence in the source"
        );
    }
    // The other half of the same claim, and the one that would have caught
    // the shipped-but-still-guarded state: neither deferred stream decision
    // may classify as `NoConstructor` anywhere, now that both are real
    // `StreamAction` variants a caller can build.
    for kind in [ActionKind::OpenAfter, ActionKind::SerializeAfter] {
        for &draft in DRAFTS {
            for column in COLUMNS {
                let cell = Cell { draft, column, kind };
                assert!(
                    !matches!(
                        classified(cell),
                        Support::NotAttemptable { why: NotAttemptable::NoConstructor, .. }
                    ),
                    "{cell}: this capability shipped; no cell may still publish it as \
                     constructor-less",
                );
            }
        }
    }
}

#[test]
fn the_published_table_and_classify_agree() {
    let mut mismatches = String::new();
    for cell in all_cells() {
        let want = published(cell);
        let got = classified(cell);
        if want != got {
            let _ = writeln!(mismatches, "{cell}\n  published {want:?}\n  classify  {got:?}");
        }
    }
    assert!(mismatches.is_empty(), "the published table and `classify` disagree:\n{mismatches}");
}

/// The datagram fixtures really are payload-delimited, on every draft that
/// has such a thing.
///
/// `Precondition::DatagramPayloadDelimited` is decided from
/// `data.len() - cursor.len()` after `AnyDatagramHeader::decode`. A fixture
/// whose header decode swallowed the payload would make the `~D` holding
/// probe pass while measuring the wrong thing, so the fixture's own claim is
/// asserted here rather than assumed.
#[test]
fn the_datagram_fixtures_delimit_their_payload() {
    for &draft in DRAFTS {
        let Some(bytes) = decodable_datagram(draft) else {
            assert_eq!(draft, DraftVersion::Draft14, "only draft-14 has no delimited datagram");
            continue;
        };
        let mut cursor = &bytes[..];
        AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] datagram fixture must decode: {e}"));
        assert_eq!(
            cursor.len(),
            DATAGRAM_PAYLOAD.len(),
            "[{draft}] the decode must stop at the payload, leaving exactly it behind",
        );
        assert_eq!(cursor, DATAGRAM_PAYLOAD, "[{draft}] and the payload must be intact");
    }

    // The counter-fixture: two bytes that begin an eight-byte varint and
    // then stop. `header_len` is `None` on every draft, which is the `~D`
    // failing side.
    for &draft in DRAFTS {
        let mut cursor = UNDECODABLE_DATAGRAM;
        assert!(
            AnyDatagramHeader::decode(draft, &mut cursor).is_err(),
            "[{draft}] the undecodable fixture must not decode, or the `~D` failing probe is \
             measuring the holding side",
        );
    }
}

/// The structural gate: every cell visited, and the published table agreeing
/// with what a live session actually did.
#[test]
fn the_capability_table_matches_observed_behaviour() {
    let sweep = sweep();

    // Every cell was visited. A cell with no disposition was *skipped*, and
    // a skipped cell is the one failure a green sweep cannot show you: the
    // run reports success having asserted nothing about it.
    let mut missing = String::new();
    for cell in all_cells() {
        if !sweep.covered.contains_key(&cell) {
            let _ = writeln!(missing, "  {cell} — verdict {:?}", classified(cell));
        }
    }
    assert!(
        missing.is_empty(),
        "cells were skipped rather than swept — an empty result and a clean result are \
         indistinguishable:\n{missing}",
    );
    assert_eq!(
        sweep.covered.len(),
        DRAFTS.len() * COLUMNS.len() * KINDS.len(),
        "13 drafts × 8 columns × 16 kinds",
    );

    // The negative half of `NotAttemptable`: nothing anywhere in the sweep
    // ever produced an event naming one of these pairs. This is what turns
    // "no value carries this kind here" from a claim into an observation.
    let mut leaked = String::new();
    for cell in all_cells() {
        if matches!(classified(cell), Support::NotAttemptable { .. })
            && sweep.observed_pairs.contains(&(cell.column.site(), cell.kind))
        {
            let _ = writeln!(leaked, "  {cell}");
        }
    }
    assert!(
        leaked.is_empty(),
        "a `NotAttemptable` cell's (site, kind) pair was named by a real event:\n{leaked}",
    );

    // Every draft contributed at least one live session. Without this the
    // coverage claim above could be satisfied by a table read fourteen times
    // and a wire driven zero times.
    let mut drafts_run: BTreeSet<u8> = BTreeSet::new();
    drafts_run.extend(sweep.sessions.iter().copied());
    assert_eq!(
        drafts_run.len(),
        DRAFTS.len(),
        "every draft must have run at least one session: {drafts_run:?}",
    );
}

/// The structural gate's sibling check, partitioned per `Refusal`
/// **variant**: every declared variant is either observed somewhere in the
/// sweep, declared table-only or declared unprovokable, and nothing is in
/// two of the three.
///
/// This one quantifies over the whole fourteen-draft matrix rather than
/// over the compiled axis, and it cannot be relaxed to the latter: several
/// `Refusal` variants are only producible on some drafts —
/// `WouldRedefineSubgroupId` needs an implicit-subgroup stream type, and
/// `SessionAlreadyClosing`'s racing-close probe is run once on draft-14.
/// On a single-draft row the missing variants are unreachable *by
/// construction*, so the honest gate is "all fourteen compiled", not a
/// weaker assertion that would also pass against an engine that stopped
/// emitting them.
#[test]
#[cfg(all(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn every_declared_refusal_is_reachable_or_declared_table_only() {
    let sweep = sweep();

    let observed: BTreeSet<&str> = sweep.observed_refusals.iter().copied().collect();
    let declared: BTreeSet<&str> = ALL_REFUSAL_LABELS.into_iter().collect();
    let table_only: BTreeSet<&str> = TABLE_ONLY_REFUSALS.into_iter().collect();
    let unprovokable: BTreeSet<&str> = UNPROVOKABLE_REFUSALS.into_iter().collect();

    // Nothing table-only may ever be emitted as a real `ActionRefused`.
    let leaked: Vec<&str> = observed.intersection(&table_only).copied().collect();
    assert!(
        leaked.is_empty(),
        "a table-only Refusal was emitted as a real ActionRefused: {leaked:?}. \
         `StreamNotFramed` appears only inside NotAttemptable and \
         Unreachable, where nothing is ever attempted",
    );

    // Nor may an unprovokable one: it is emittable, and the stream that
    // would reach it is one no draft lets exist. Observing one means such a
    // stream now decodes, which is a change to the codec and not to this
    // file.
    let provoked: Vec<&str> = observed.intersection(&unprovokable).copied().collect();
    assert!(
        provoked.is_empty(),
        "a Refusal declared unprovokable was emitted as a real ActionRefused: {provoked:?}. \
         A stream that reaches it now decodes, so the variant belongs in the observed set \
         and the sweep needs a probe for it",
    );

    // And everything else must have been observed.
    let unreachable: Vec<&str> = declared
        .difference(&observed)
        .filter(|l| !table_only.contains(*l) && !unprovokable.contains(*l))
        .copied()
        .collect();
    assert!(
        unreachable.is_empty(),
        "these Refusal variants are neither declared table-only nor observed anywhere in the \
         sweep: {unreachable:?}. Either a cell that should emit one does not, or a variant \
         was added that nothing can produce",
    );

    // And the unobserved set is exactly the two declared sets together — no
    // wider, so a variant cannot quietly stop being emitted, and no
    // narrower.
    let mut split: Vec<&str> = declared.difference(&observed).copied().collect();
    split.sort_unstable();
    let mut want: Vec<&str> =
        TABLE_ONLY_REFUSALS.into_iter().chain(UNPROVOKABLE_REFUSALS).collect();
    want.sort_unstable();
    assert_eq!(
        split, want,
        "the unobserved set must be exactly {{StreamNotFramed, ReservedHeaderMode}}"
    );
}

/// The per-cell coverage report, printed in the test's own output, plus the
/// one claim a coverage count cannot make on its own: no `Conditional` cell
/// was exercised on a single side.
#[test]
fn the_sweep_reports_per_cell_coverage() {
    let sweep = sweep();

    let mut by_verdict: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut probes_by_verdict: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut conditional_single_sided = String::new();
    let mut assumption = 0usize;

    for cell in all_cells() {
        let verdict = classified(cell);
        let label = match &verdict {
            Support::Yes => "Yes",
            Support::No(_) => "No(r)",
            Support::Conditional(_) => "Conditional(p)",
            Support::NotAttemptable { .. } => "NotAttemptable",
            Support::Unreachable { .. } => "Unreachable",
            other => panic!("a new Support verdict reached the sweep: {other:?}"),
        };
        *by_verdict.entry(label).or_default() += 1;
        let probes = sweep.covered.get(&cell).map(Vec::len).unwrap_or(0);
        *probes_by_verdict.entry(label).or_default() += probes;

        // A `Conditional` must be exercised twice — with the precondition
        // holding and with it failing. One side alone proves only that the
        // precondition exists, not that it decides anything.
        if matches!(verdict, Support::Conditional(_)) && probes < 2 {
            let _ = writeln!(
                conditional_single_sided,
                "  {cell} — {probes} probe(s): {:?}",
                sweep.covered.get(&cell),
            );
        }
        if cell.column == Column::Control && control_plane_is_a_uni_pair(cell.draft) {
            assumption += 1;
        }
    }

    let mut report = String::new();
    let _ = writeln!(report, "\n── per-cell coverage ───────────────────────────────────");
    let _ = writeln!(
        report,
        "  cells swept: {} = {} drafts × {} columns × {} kinds",
        sweep.covered.len(),
        DRAFTS.len(),
        COLUMNS.len(),
        KINDS.len(),
    );
    for (label, count) in &by_verdict {
        let _ = writeln!(
            report,
            "  {label:<16} {count:>5} cells, {:>5} probe(s)",
            probes_by_verdict.get(label).copied().unwrap_or(0),
        );
    }
    let _ = writeln!(
        report,
        "  probed on a request stream: {assumption} Control cells on drafts 17-20 — \
         this harness drives control bytes down a bidirectional stream, which on those four \
         drafts is a request stream rather than the unidirectional control pair; the \
         compensating end-to-end assertions are in control_plane_uni.rs, which drives the \
         pair itself and reads back decoded messages",
    );
    let _ = writeln!(
        report,
        "  Refusal variants observed as real ActionRefused: {:?}",
        sweep.observed_refusals,
    );
    let _ = writeln!(report, "  sessions run: {}", sweep.sessions.len());
    for note in &sweep.notes {
        let _ = writeln!(report, "  note: {note}");
    }
    let _ = writeln!(report, "────────────────────────────────────────────────────────");
    println!("{report}");

    assert!(
        conditional_single_sided.is_empty(),
        "every `Conditional(p)` cell must be exercised twice — with `p` holding and with `p` \
         failing:\n{conditional_single_sided}\n{report}",
    );
    assert_eq!(
        by_verdict.values().sum::<usize>(),
        DRAFTS.len() * COLUMNS.len() * KINDS.len(),
        "every cell has exactly one verdict",
    );
}

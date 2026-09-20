//! Class matching — what a [`ClassRule`](super::ClassRule) claims.
//!
//! Two types live here: [`RangeSet`], the hand-rolled sorted/coalesced
//! `u64` range container the proxy uses instead of pulling in a dependency
//! (nothing in the workspace offers one), and [`Matcher`], the AND of the
//! eight keys a rule may name.
//!
//! The one rule that shapes everything below: **an absent key never
//! matches.** A unit whose `subgroup_id` the wire did not carry does not
//! match a `subgroup_id` matcher — it falls to the default class. `None`
//! as wildcard was rejected outright, because it silently widens a rule
//! aimed at video to also match audio.

use std::cmp::Ordering;
use std::ops::RangeInclusive;

use moqtap_codec::dispatch::AnyDatagramMeta;
use moqtap_codec::version::DraftVersion;

use crate::types::{DataStreamType, ObjectMeta, ProxySide};

/// A sorted, coalesced set of inclusive `u64` ranges.
///
/// Built once from a configuration and then queried per unit, so
/// construction sorts and coalesces (including *adjacent* ranges: `1..=3`
/// and `4..=6` become `1..=6`) and [`RangeSet::contains`] is a binary
/// search over the result.
///
/// Ranges whose start exceeds their end are empty and are discarded at
/// construction rather than stored as a range that can never match.
///
/// `#[non_exhaustive]` with no `Default`: the fields are private and there
/// are two constructors, so there is no meaningful zero value to derive.
///
/// # The written form is a plain list
///
/// Under the `serde` feature a range set is written as the list of ranges
/// it was built from — `[{"start": 1, "end": 3}, {"start": 4, "end": 6}]` —
/// and read back **through [`RangeSet::new`]**, which is what
/// `#[serde(from = ...)]` buys. A derived `Deserialize` would fill the private
/// `ranges` field straight from the file, and the invariant every method here
/// relies on — sorted, disjoint, non-adjacent — would then hold only for files
/// that happened to be written in order. [`RangeSet::contains`] is a binary
/// search, so on an unsorted set it does not fail: it answers `false` for
/// values that are in the set, and the class quietly stops claiming half its
/// traffic.
///
/// Two consequences of routing through the constructor are worth knowing
/// before reading a file back. The written form is *normalised*, so the two
/// ranges above are one range when they are read and the file that comes back
/// out says `[{"start": 1, "end": 6}]`. And an inverted range is dropped
/// rather than stored, so a file whose only range is `{"start": 5, "end": 1}`
/// produces an empty set — which
/// [`ShapeProfile::try_new`](super::ShapeProfile::try_new) then refuses as
/// [`ShapeError::InertMatcher`](super::ShapeError::InertMatcher) rather than
/// arming a class that can never claim anything.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "Vec<RangeInclusive<u64>>", into = "Vec<RangeInclusive<u64>>")
)]
#[non_exhaustive]
pub struct RangeSet {
    /// Disjoint, non-adjacent, ascending by start. The invariant every
    /// method below relies on.
    ranges: Vec<RangeInclusive<u64>>,
}

impl RangeSet {
    /// Build a range set from any iterator of inclusive ranges.
    ///
    /// The input needs no ordering: overlapping, adjacent and duplicated
    /// ranges are merged, and empty ranges (`start > end`) are dropped.
    pub fn new(ranges: impl IntoIterator<Item = RangeInclusive<u64>>) -> Self {
        let mut raw: Vec<RangeInclusive<u64>> =
            ranges.into_iter().filter(|r| r.start() <= r.end()).collect();
        raw.sort_by_key(|r| (*r.start(), *r.end()));

        let mut merged: Vec<RangeInclusive<u64>> = Vec::with_capacity(raw.len());
        for r in raw {
            match merged.last_mut() {
                // `+1` is what makes `1..=3` and `4..=6` one range rather
                // than two: they are adjacent, not overlapping.
                // `saturating_add` so a range ending at `u64::MAX` does not
                // panic in a debug build.
                Some(last) if *r.start() <= last.end().saturating_add(1) => {
                    if r.end() > last.end() {
                        *last = *last.start()..=*r.end();
                    }
                }
                _ => merged.push(r),
            }
        }
        Self { ranges: merged }
    }

    /// A range set holding exactly one value.
    pub fn single(v: u64) -> Self {
        Self { ranges: vec![v..=v] }
    }

    /// The ranges as a plain list, which is also the written form.
    ///
    /// Consumes the set rather than borrowing it, because this is what
    /// `#[serde(into = ...)]` calls and the alternative — serializing the
    /// private field directly — would emit `{"ranges": [...]}` while the read
    /// path expects `[...]`, so the two directions would disagree.
    #[cfg(feature = "serde")]
    fn into_ranges(self) -> Vec<RangeInclusive<u64>> {
        self.ranges
    }

    /// Whether `v` falls in any of the ranges. Binary search.
    pub fn contains(&self, v: u64) -> bool {
        self.ranges
            .binary_search_by(|r| {
                if *r.end() < v {
                    Ordering::Less
                } else if *r.start() > v {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Whether the set holds no values at all. Such a set matches nothing.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The coalesced ranges, ascending and disjoint.
    ///
    /// Exposed because coalescing is a *claim* — that `1..=3` plus `4..=6`
    /// is one range — and [`RangeSet::contains`] cannot falsify it: both
    /// shapes answer every `contains` query identically. A test that can
    /// only see `contains` cannot tell a working coalescer from none.
    pub fn ranges(&self) -> &[RangeInclusive<u64>] {
        &self.ranges
    }
}

/// Every read of a range set goes through [`RangeSet::new`], so the sorted,
/// coalesced invariant holds for a set that came from a file exactly as it
/// does for one built in Rust.
#[cfg(feature = "serde")]
impl From<Vec<RangeInclusive<u64>>> for RangeSet {
    fn from(ranges: Vec<RangeInclusive<u64>>) -> Self {
        RangeSet::new(ranges)
    }
}

#[cfg(feature = "serde")]
impl From<RangeSet> for Vec<RangeInclusive<u64>> {
    fn from(set: RangeSet) -> Self {
        set.into_ranges()
    }
}

/// What a [`Matcher`] can be aimed at.
///
/// `Datagram` exists so that aiming a rule at datagrams produces a report
/// rather than silence; datagrams are not shapeable in this release, so a
/// `Datagram` matcher never matches a unit. The report is the scheduler's
/// job once this module is wired.
///
/// `Fetch` is live on all fourteen. Drafts 18, 19 and 20 write a fetch
/// object's Group ID as a difference whose sign the fetch's Group Order
/// settles; the session reads that order off the FETCH —
/// `capability::fetch_group_order_is_needed` — and hands it to the framer, so
/// what a rule can miss is one stream at a time rather than a whole draft. A
/// stream the session cannot resolve is bypassed at its header and produces
/// no [`ObjectMeta`] for a rule to see, and says so itself as
/// `Impairment { FramerBypass { FetchGroupOrderUnknown } }`.
///
/// Being matchable is not being *mutable*, and the two are answered
/// separately: whether a rule claims a unit is [`Matcher::matches`], and what
/// may then be done to it is `capability::classify`.
///
/// `#[non_exhaustive]` with no `Default`: there is no meaningful default
/// stream kind, and a wrong one would silently narrow every rule that
/// omitted the key.
///
/// Written as `"subgroup"`, `"fetch"` or `"datagram"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum MatchKind {
    /// A subgroup data stream.
    Subgroup,
    /// A fetch response data stream.
    Fetch,
    /// A datagram.
    Datagram,
}

impl MatchKind {}

/// One [`Matcher`] key, named so a report about it is typed rather than a
/// string.
///
/// Only the keys that can be **unmatchable** are here, and that is the whole
/// point of the type: it is carried by
/// [`ImpairmentKind::ShapeRuleUnmatchable`](crate::event::ImpairmentKind::ShapeRuleUnmatchable),
/// which fires when a rule keys on something this draft and stream kind
/// cannot carry. The other four keys — `side`, `group_id`, `object_id` and
/// `every_nth` — are present on every framed unit by construction, so a rule
/// keyed on one of them that fails to match failed on its *value*, which is
/// the rule working, not a rule that cannot work.
///
/// `#[non_exhaustive]` with no `Default`: a later draft that makes another
/// key optional adds a variant, and no key is a meaningful zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MatcherField {
    /// [`Matcher::track_alias`], against a unit whose stream carried none —
    /// every fetch stream.
    TrackAlias,
    /// [`Matcher::subgroup_id`], against a unit whose header carried none —
    /// ten drafts in first-object mode, and 16-20 in reserved mode 3.
    ///
    /// Never reported about a datagram, which carries no subgroup ID on any
    /// draft. That is not a fact about one header, so it is a pre-run
    /// refusal — `Capabilities::admit_class` — rather than something a run
    /// discovers. See `Matcher::unmatchable_fields_datagram`.
    SubgroupId,
    /// [`Matcher::priority`], against a unit whose header set the
    /// default-priority bit — drafts 15-19, on a subgroup object and on a
    /// datagram alike.
    Priority,
}

impl MatcherField {
    /// This field's bit in a per-class report-once mask.
    ///
    /// A four-variant enum fits one byte, so the "reported already" state
    /// for a whole class is one `AtomicU8` and the check is one relaxed
    /// `fetch_or` — taken only when a field is *actually* absent, so a
    /// profile whose keys are all carried never touches it.
    pub(crate) const fn bit(self) -> u8 {
        match self {
            MatcherField::TrackAlias => 1,
            MatcherField::SubgroupId => 2,
            MatcherField::Priority => 4,
        }
    }
}

/// Which units a [`ClassRule`](super::ClassRule) claims.
///
/// All present fields must match (AND). An absent field matches
/// everything. A field the wire did not carry — `None` on
/// [`ObjectMeta`] — **does not match**.
///
/// `#[non_exhaustive]` *with* a [`Default`], exactly as
/// [`EgressConfig`](crate::action::EgressConfig) is. The pairing is
/// load-bearing: `#[non_exhaustive]` alone would make this type
/// unconstructible from an integration-test crate or from a caller's
/// code, because struct-expression *and* functional-update syntax
/// are both illegal outside the defining crate. Note what that leaves:
/// `..Matcher::default()` is **also** illegal there (`E0639`), so an
/// outside caller writes `let mut m = Matcher::default();` and then assigns
/// per field — which is what `tests/actions_shaping.rs` does. Inside this
/// crate both forms compile, which is why the unit tests below use the
/// shorter one. The `Default` is all-`None` — a matcher that claims every
/// unit.
///
/// In the written form every key defaults to absent, so a matcher naming one
/// field is one line, and an unknown key is refused rather than skipped — a
/// misspelled `group_id` would otherwise widen the rule to claim every unit
/// on the stream instead of the ten groups it named.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, deny_unknown_fields))]
#[non_exhaustive]
pub struct Matcher {
    /// The direction the unit arrived on.
    ///
    /// Only `ClientToProxy` and `RelayToProxy` are ever seen at a hook
    /// site; the two egress labels are used for teardown reporting. Naming
    /// an egress side here is rejected by
    /// [`ShapeProfile::try_new`](super::ShapeProfile::try_new) rather than
    /// left to match nothing.
    ///
    /// Written as the variant's own name in kebab-case —
    /// `"client-to-proxy"` — by the `side_serde` mapping below rather than
    /// by a derive, because [`ProxySide`] lives in a module that carries no
    /// serde dependency of its own.
    #[cfg_attr(feature = "serde", serde(with = "side_serde"))]
    pub side: Option<ProxySide>,
    /// Track alias from the stream header. `None` on every fetch stream,
    /// so a rule keyed here never claims fetch units.
    pub track_alias: Option<RangeSet>,
    /// Group ID. Always present on a framed object.
    pub group_id: Option<RangeSet>,
    /// Subgroup ID. `None` on ten drafts in first-object mode and on
    /// 16-20 in reserved mode 3, so a rule keyed here claims nothing there.
    pub subgroup_id: Option<RangeSet>,
    /// Absolute object ID. Always present on a framed object.
    pub object_id: Option<RangeSet>,
    /// MoQT `publisher_priority`. `None` on drafts 15-19 whenever the
    /// header set the default-priority bit.
    pub priority: Option<RangeInclusive<u8>>,
    /// Which kind of stream the unit came from.
    pub stream_kind: Option<MatchKind>,
    /// `(n, offset)` over a counter of **hook-visible units on this
    /// stream**, scoped **per stream and not per class**, never
    /// [`ObjectMeta::index_in_stream`] — which counts oversized objects
    /// that never reach the hook and would silently shift the pattern.
    ///
    /// Matches when `unit_index % n == offset % n`. `n == 0` names no
    /// units, so [`ShapeProfile::try_new`](super::ShapeProfile::try_new)
    /// rejects it as [`ShapeError::InertMatcher`](super::ShapeError::InertMatcher)
    /// rather than accepting a class that can never claim anything.
    pub every_nth: Option<(u64, u64)>,
}

impl Matcher {
    /// Whether this matcher claims one unit.
    ///
    /// `side` is the forwarding task's own direction label — [`ObjectMeta`]
    /// has no `side` field. `unit_index` is the per-stream count of
    /// hook-visible units described on [`Matcher::every_nth`], supplied by
    /// the caller for the same reason `charge` takes `now`: this function
    /// owns no state and reads no counter, so it can be tested exhaustively
    /// from a table.
    pub fn matches(&self, side: ProxySide, meta: &ObjectMeta, unit_index: u64) -> bool {
        self.claims(
            side,
            kind_of(meta.stream_kind),
            Keys {
                track_alias: meta.track_alias,
                group_id: meta.group_id,
                subgroup_id: meta.subgroup_id,
                object_id: meta.object_id,
                priority: meta.publisher_priority,
            },
            unit_index,
        )
    }

    /// Whether this matcher claims one datagram.
    ///
    /// [`Self::matches`]'s sibling, and the two answer through one
    /// conjunction — see the private `Keys` it is written over. What differs
    /// is what fills that in: a
    /// datagram states its own track alias, Group ID, Object ID and (from
    /// draft-15, conditionally) priority, and states **no subgroup ID** on
    /// any draft, so a rule keyed there claims no datagram. That last one is
    /// a fact about the carrier rather than about one header, so it is
    /// refused before the run by
    /// [`Capabilities::admit_class`](crate::capability::Capabilities::admit_class)
    /// rather than discovered from one.
    ///
    /// `unit_index` counts hook-visible datagrams **per forwarding
    /// direction**, which is the only scope a datagram has: it belongs to no
    /// stream, so [`Matcher::every_nth`]'s per-stream reading has nothing to
    /// key against here and the session's two directions count separately.
    pub fn matches_datagram(
        &self,
        side: ProxySide,
        meta: &AnyDatagramMeta,
        unit_index: u64,
    ) -> bool {
        self.claims(
            side,
            MatchKind::Datagram,
            Keys {
                track_alias: Some(meta.track_alias),
                group_id: meta.group_id,
                subgroup_id: None,
                object_id: meta.object_id,
                priority: meta.publisher_priority,
            },
            unit_index,
        )
    }

    /// The conjunction both carriers answer through.
    ///
    /// Written once rather than twice because a six-key AND copied is a
    /// sixth key forgotten: a matcher key added to this struct and to only
    /// one of the two callers would widen every rule on the other carrier,
    /// silently, in the direction of claiming more than it named.
    fn claims(&self, side: ProxySide, kind: MatchKind, keys: Keys, unit_index: u64) -> bool {
        if let Some(want) = self.side {
            if want != side {
                return false;
            }
        }
        if let Some(want) = self.stream_kind {
            if want != kind {
                return false;
            }
        }
        // A keyed field the wire did not carry never matches: the three
        // `Option` keys below take the `_ => return false` arm on `None`.
        if let Some(set) = &self.track_alias {
            match keys.track_alias {
                Some(v) if set.contains(v) => {}
                _ => return false,
            }
        }
        if let Some(set) = &self.group_id {
            if !set.contains(keys.group_id) {
                return false;
            }
        }
        if let Some(set) = &self.subgroup_id {
            match keys.subgroup_id {
                Some(v) if set.contains(v) => {}
                _ => return false,
            }
        }
        if let Some(set) = &self.object_id {
            if !set.contains(keys.object_id) {
                return false;
            }
        }
        if let Some(range) = &self.priority {
            match keys.priority {
                Some(p) if range.contains(&p) => {}
                _ => return false,
            }
        }
        if let Some((n, offset)) = self.every_nth {
            if n == 0 || unit_index % n != offset % n {
                return false;
            }
        }
        true
    }

    /// The keys this matcher names that `meta` **cannot carry**, so a
    /// non-match against them is a rule that can never fire rather than a
    /// rule that did not fire.
    ///
    /// The distinction is the whole point of this function: `None` never
    /// matches, and a silent fall to the default class is precisely the
    /// failure mode this project exists to prevent. The caller reports each
    /// `(class, field)` once per session.
    ///
    /// Returns a fixed-size array rather than a `Vec` — it is called on the
    /// data path, once per rule that failed to match, and must not
    /// allocate. `[None; 3]` is the answer for a matcher whose keys are all
    /// carried, which is the common case.
    ///
    /// Every row here is a key **this unit** did not carry, and a unit is the
    /// only scope this function answers at. No row says a key is dead for a
    /// whole draft: a `Fetch`-aimed class is matchable on every draft, and a
    /// fetch stream whose Group Order the session cannot resolve is bypassed
    /// at its header and produces no [`ObjectMeta`] for a rule to be measured
    /// against — see [`MatchKind::Fetch`].
    ///
    /// Only checked *after* [`Self::matches`] has answered `false`: a rule
    /// that matched cannot have been defeated by an absent key.
    pub(crate) fn unmatchable_fields(&self, meta: &ObjectMeta) -> [Option<MatcherField>; 3] {
        [
            (self.track_alias.is_some() && meta.track_alias.is_none())
                .then_some(MatcherField::TrackAlias),
            (self.subgroup_id.is_some() && meta.subgroup_id.is_none())
                .then_some(MatcherField::SubgroupId),
            (self.priority.is_some() && meta.publisher_priority.is_none())
                .then_some(MatcherField::Priority),
        ]
    }

    /// [`Self::unmatchable_fields`]'s datagram sibling: the keys this matcher
    /// names that **this datagram** could not carry.
    ///
    /// One of the three is answered here and two are deliberately not.
    ///
    /// * [`MatcherField::Priority`] is reported on the same terms as on a
    ///   framed object — drafts 15 and later let a datagram's type byte set a
    ///   default-priority bit and leave the field off, and a rule keyed on
    ///   priority cannot claim one that did.
    /// * [`MatcherField::TrackAlias`] never: every datagram of every draft
    ///   states one.
    /// * [`MatcherField::SubgroupId`] never, and this is the interesting
    ///   one. No datagram carries a subgroup ID on any draft, so a
    ///   *datagram-aimed* rule keyed there is refused before the session
    ///   starts — `Capabilities::admit_class`, which is where a key a
    ///   carrier never has belongs, because rejecting beats reporting
    ///   wherever the answer exists without traffic. A rule that names no
    ///   stream kind and keys on `subgroup_id` is a live subgroup rule, and
    ///   reporting it here because a datagram went past would be a
    ///   diagnostic about a rule that works.
    pub(crate) fn unmatchable_fields_datagram(
        &self,
        draft: DraftVersion,
        meta: &AnyDatagramMeta,
    ) -> [Option<MatcherField>; 3] {
        let _ = draft;
        [
            None,
            None,
            (self.priority.is_some() && meta.publisher_priority.is_none())
                .then_some(MatcherField::Priority),
        ]
    }

    /// The first key this matcher names that can **never** claim a unit —
    /// not because the wire withheld it, but because the key itself names
    /// an empty set of values.
    /// The crate-internal `unmatchable_fields`'s sibling, and the difference is
    /// where each is answerable: an unmatchable *field* depends on the draft and
    /// the unit, so it can only be reported during a run, while an inert *key*
    /// is a property of the configuration alone and is therefore
    /// [`ShapeProfile::try_new`](super::ShapeProfile::try_new)'s to reject
    /// before a session ever starts. Rejecting is strictly better than
    /// reporting: a class that can never fire is the *configuration that looks
    /// applied and does nothing* that constructor exists to prevent, and here
    /// it is knowable without a single byte of traffic.
    ///
    /// Public because a caller that builds matchers from its own configuration
    /// needs the same pre-flight refusal `try_new` gets: a matcher handed to a
    /// [`ProxyHook`](crate::hook::ProxyHook) rather than to a shaping class
    /// reaches no constructor that could check it.
    ///
    /// The three shapes this catches:
    ///
    /// - a [`RangeSet`] built from an inverted range — [`RangeSet::new`]
    ///   drops `start > end`, so the set is empty and `contains` is always
    ///   `false`;
    /// - an empty [`Matcher::priority`] range (`200..=100`);
    /// - [`Matcher::every_nth`] with `n == 0`, which
    ///   [`Self::matches`] answers `false` for unconditionally.
    ///
    /// Returns the key's field name as it is spelled on this struct, so the
    /// error message names something the author can search their own
    /// configuration for.
    pub fn inert_key(&self) -> Option<&'static str> {
        let empty_set = |set: &Option<RangeSet>| set.as_ref().is_some_and(RangeSet::is_empty);
        if empty_set(&self.track_alias) {
            return Some("track_alias");
        }
        if empty_set(&self.group_id) {
            return Some("group_id");
        }
        if empty_set(&self.subgroup_id) {
            return Some("subgroup_id");
        }
        if empty_set(&self.object_id) {
            return Some("object_id");
        }
        if self.priority.as_ref().is_some_and(RangeInclusive::is_empty) {
            return Some("priority");
        }
        if matches!(self.every_nth, Some((0, _))) {
            return Some("every_nth");
        }
        None
    }
}

/// The keys one unit carries, whichever carrier it arrived on.
///
/// The argument to [`Matcher::claims`], and the reason a datagram and a
/// framed object can be answered by one conjunction. Two of the five differ
/// between the carriers and the difference is the type's whole content: a
/// fetch object carries no track alias and a datagram carries no subgroup ID.
struct Keys {
    track_alias: Option<u64>,
    group_id: u64,
    subgroup_id: Option<u64>,
    object_id: u64,
    priority: Option<u8>,
}

/// Which [`MatchKind`] a framed object's stream is.
///
/// The `Fetch` arm is **live**, on all fourteen drafts:
/// `detect_stream_type` maps stream type `0x05` to
/// [`DataStreamType::Fetch`] and the framer produces ordinary [`ObjectMeta`]
/// for it. On drafts 18, 19 and 20 that needs the fetch's Group Order, which
/// the session reads off the FETCH before the response opens; a response
/// naming a request nobody made is bypassed and says so per stream, and
/// produces no meta for a rule to be measured against either way.
/// `the_fetch_arm_claims_a_fetch_object` is what keeps the arm from being
/// deletable without a red.
fn kind_of(stream_kind: DataStreamType) -> MatchKind {
    match stream_kind {
        DataStreamType::Subgroup => MatchKind::Subgroup,
        DataStreamType::Fetch => MatchKind::Fetch,
    }
}

/// The written form of [`ProxySide`](crate::event::ProxySide), which lives in
/// a module this schema does not add derives to.
///
/// Four names, kebab-case, exactly the variant names. Written out here rather
/// than derived so that the enum stays free of a serde dependency it has no
/// other use for; the cost is that a fifth side would compile and be
/// unwritable, which is why the mapping is exhaustive in both directions and
/// has no wildcard arm.
#[cfg(feature = "serde")]
pub(crate) mod side_serde {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::types::ProxySide;

    /// Every side, and the name it is written as.
    const NAMES: [(ProxySide, &str); 4] = [
        (ProxySide::ClientToProxy, "client-to-proxy"),
        (ProxySide::ProxyToRelay, "proxy-to-relay"),
        (ProxySide::RelayToProxy, "relay-to-proxy"),
        (ProxySide::ProxyToClient, "proxy-to-client"),
    ];

    /// The name of one side. No wildcard arm: a fifth variant is a compile
    /// error here rather than a side that writes itself as something else.
    fn name(side: ProxySide) -> &'static str {
        match side {
            ProxySide::ClientToProxy => NAMES[0].1,
            ProxySide::ProxyToRelay => NAMES[1].1,
            ProxySide::RelayToProxy => NAMES[2].1,
            ProxySide::ProxyToClient => NAMES[3].1,
        }
    }

    /// Serialize an optional side as its name.
    pub(crate) fn serialize<S: Serializer>(
        side: &Option<ProxySide>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match side {
            None => serializer.serialize_none(),
            Some(side) => serializer.serialize_some(name(*side)),
        }
    }

    /// Read an optional side, listing every accepted name if it is not one.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ProxySide>, D::Error> {
        let written = <Option<String>>::deserialize(deserializer)?;
        let Some(written) = written else { return Ok(None) };
        NAMES.iter().find(|(_, name)| *name == written).map(|(side, _)| Some(*side)).ok_or_else(
            || {
                D::Error::custom(format!(
                    "unknown side {written:?}, expected one of {:?}",
                    NAMES.map(|(_, name)| name)
                ))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moqtap_codec::version::DraftVersion;

    /// All fourteen, so a claim about "every draft" is one rather than a
    /// sample. Nothing here decodes, so an uncompiled draft is as
    /// answerable as a compiled one.
    ///
    /// The length is written out for the same reason the other draft sweeps
    /// in this crate write theirs out — `capability.rs` and `exec.rs` both
    /// hold a `[DraftVersion; 14]`. This one said `13` while claiming
    /// fourteen, and ending at `Draft19` is how every sweep below silently
    /// stopped testing draft-20: a short array is not a failing test, it is a
    /// smaller one.
    const DRAFTS: [DraftVersion; 14] = [
        DraftVersion::Draft07,
        DraftVersion::Draft08,
        DraftVersion::Draft09,
        DraftVersion::Draft10,
        DraftVersion::Draft11,
        DraftVersion::Draft12,
        DraftVersion::Draft13,
        DraftVersion::Draft14,
        DraftVersion::Draft15,
        DraftVersion::Draft16,
        DraftVersion::Draft17,
        DraftVersion::Draft18,
        DraftVersion::Draft19,
        DraftVersion::Draft20,
    ];

    /// A framed subgroup object with every optional key present, so a test
    /// can knock exactly one out and attribute the result.
    fn meta() -> ObjectMeta {
        ObjectMeta {
            draft: DraftVersion::Draft19,
            stream_kind: DataStreamType::Subgroup,
            track_alias: Some(7),
            group_id: 3,
            subgroup_id: Some(4),
            object_id: 11,
            publisher_priority: Some(128),
            index_in_stream: 0,
            payload_len: 16,
            status: None,
            end_of_range: None,
        }
    }

    /// Coalescing, boundaries and the empty set.
    ///
    /// The `ranges()` assertions are the load-bearing half: `contains`
    /// alone cannot tell `[1..=3, 4..=6]` from `[1..=6]`.
    #[test]
    fn a_range_set_contains_only_its_ranges() {
        // Empty.
        let empty = RangeSet::new([]);
        assert!(empty.is_empty());
        assert!(!empty.contains(0));
        assert!(!empty.contains(u64::MAX));

        // Single.
        let one = RangeSet::single(7);
        assert_eq!(one.ranges(), &[7..=7]);
        assert!(one.contains(7));
        assert!(!one.contains(6));
        assert!(!one.contains(8));

        // Unsorted input is sorted; disjoint ranges stay disjoint.
        let two = RangeSet::new([5..=9, 1..=3]);
        assert_eq!(two.ranges(), &[1..=3, 5..=9]);
        for v in [1, 2, 3, 5, 6, 9] {
            assert!(two.contains(v), "should contain {v}");
        }
        for v in [0, 4, 10] {
            assert!(!two.contains(v), "should not contain {v}");
        }

        // Adjacency coalesces. This is the `+1`.
        assert_eq!(RangeSet::new([1..=3, 4..=6]).ranges(), &[1..=6]);
        // Overlap coalesces, and the wider end wins.
        assert_eq!(RangeSet::new([1..=5, 3..=9]).ranges(), &[1..=9]);
        // A range wholly inside another is absorbed, not appended.
        assert_eq!(RangeSet::new([1..=9, 3..=5]).ranges(), &[1..=9]);
        // A one-value gap is NOT adjacency.
        assert_eq!(RangeSet::new([1..=3, 5..=6]).ranges(), &[1..=3, 5..=6]);

        // Empty ranges are dropped rather than stored. Bound through
        // locals: a literal `9..=1` is a clippy error at the call site,
        // which is exactly the case a configuration built at runtime can
        // still produce.
        let (lo, hi) = (9u64, 1u64);
        assert!(RangeSet::new([lo..=hi]).is_empty());
        assert_eq!(RangeSet::new([lo..=hi, 2..=4]).ranges(), &[2..=4]);

        // The top of the space does not panic and does not wrap.
        let top = RangeSet::new([u64::MAX..=u64::MAX]);
        assert!(top.contains(u64::MAX));
        assert!(!top.contains(u64::MAX - 1));
    }

    /// An absent key does not match — `None` is never a wildcard.
    #[test]
    fn an_absent_key_does_not_match() {
        let keyed = Matcher { subgroup_id: Some(RangeSet::single(4)), ..Matcher::default() };

        // Positive control: the key is present and in range.
        assert!(keyed.matches(ProxySide::ClientToProxy, &meta(), 0));

        // The wire did not carry a subgroup ID: no match, and the value the
        // codec would have stored (zero) is not consulted.
        let absent = ObjectMeta { subgroup_id: None, ..meta() };
        assert!(!keyed.matches(ProxySide::ClientToProxy, &absent, 0));

        // Present but out of range: also no match, so the assertion above
        // is about absence and not about the range.
        let other = ObjectMeta { subgroup_id: Some(5), ..meta() };
        assert!(!keyed.matches(ProxySide::ClientToProxy, &other, 0));

        // The same rule on the other two `Option` keys.
        let by_alias = Matcher { track_alias: Some(RangeSet::single(7)), ..Matcher::default() };
        assert!(by_alias.matches(ProxySide::ClientToProxy, &meta(), 0));
        let fetch = ObjectMeta { track_alias: None, ..meta() };
        assert!(!by_alias.matches(ProxySide::ClientToProxy, &fetch, 0));

        let by_priority = Matcher { priority: Some(0..=200), ..Matcher::default() };
        assert!(by_priority.matches(ProxySide::ClientToProxy, &meta(), 0));
        let defaulted = ObjectMeta { publisher_priority: None, ..meta() };
        assert!(!by_priority.matches(ProxySide::ClientToProxy, &defaulted, 0));

        // An all-absent matcher still claims everything, so "None never
        // matches" is about a *keyed* field and not about the matcher.
        let any = Matcher::default();
        assert!(any.matches(ProxySide::ClientToProxy, &absent, 0));
        assert!(any.matches(ProxySide::RelayToProxy, &fetch, 9));
    }

    /// The remaining matcher keys, so `matches` is not gated by
    /// `an_absent_key_does_not_match` alone.
    #[test]
    fn the_other_keys_and_are_ends_a_match() {
        let m = Matcher {
            side: Some(ProxySide::RelayToProxy),
            group_id: Some(RangeSet::new([0..=3])),
            object_id: Some(RangeSet::new([10..=12])),
            stream_kind: Some(MatchKind::Subgroup),
            every_nth: Some((3, 1)),
            ..Matcher::default()
        };
        assert!(m.matches(ProxySide::RelayToProxy, &meta(), 4));

        // Each key alone flips the AND to false.
        assert!(!m.matches(ProxySide::ClientToProxy, &meta(), 4));
        assert!(!m.matches(ProxySide::RelayToProxy, &ObjectMeta { group_id: 4, ..meta() }, 4));
        assert!(!m.matches(ProxySide::RelayToProxy, &ObjectMeta { object_id: 13, ..meta() }, 4));
        let fetch = ObjectMeta { stream_kind: DataStreamType::Fetch, ..meta() };
        assert!(!m.matches(ProxySide::RelayToProxy, &fetch, 4));
        assert!(!m.matches(ProxySide::RelayToProxy, &meta(), 5));

        // A datagram rule never claims a framed object, on either kind.
        let dgram = Matcher { stream_kind: Some(MatchKind::Datagram), ..Matcher::default() };
        assert!(!dgram.matches(ProxySide::ClientToProxy, &meta(), 0));
        assert!(!dgram.matches(ProxySide::ClientToProxy, &fetch, 0));

        // `n == 0` names no units.
        let never = Matcher { every_nth: Some((0, 0)), ..Matcher::default() };
        assert!(!never.matches(ProxySide::ClientToProxy, &meta(), 0));
    }

    /// **A `Fetch`-aimed rule claims a fetch object.** The positive half of
    /// `kind_matches`, which nothing exercised: `the_other_keys_and_ends_a_match`
    /// only asserts that a *Subgroup* rule rejects a fetch meta, and that
    /// stays green with the `Fetch` arm deleted.
    ///
    /// The three assertions are the three things one arm has to get right:
    /// the kind it names matches, the *other* stream kind does not, and the
    /// `Datagram` kind matches neither — so a `kind_matches` rewritten as
    /// `want != Datagram` would still redden.
    ///
    /// *Ablation, recorded:* delete `| (MatchKind::Fetch,
    /// DataStreamType::Fetch)` from `kind_matches`. Before this test the
    /// whole crate stayed green at 392 passed / 0 failed / 0 filtered out —
    /// a matcher arm with no gate at all. With it:
    ///
    /// ```text
    /// thread '...the_fetch_arm_claims_a_fetch_object' panicked at
    /// crates\moqtap-proxy\src\shape\matcher.rs:
    /// a Fetch-aimed class must claim a fetch object: the arm is live on all fourteen
    /// drafts, every one of which has a fetch object codec
    /// ```
    #[test]
    fn the_fetch_arm_claims_a_fetch_object() {
        let fetch = ObjectMeta {
            draft: DraftVersion::Draft14,
            stream_kind: DataStreamType::Fetch,
            track_alias: None,
            ..meta()
        };
        let fetch_rule = Matcher { stream_kind: Some(MatchKind::Fetch), ..Matcher::default() };

        assert!(
            fetch_rule.matches(ProxySide::ClientToProxy, &fetch, 0),
            "a Fetch-aimed class must claim a fetch object: the arm is live on all \
             fourteen drafts, every one of which has a fetch object codec"
        );
        assert!(
            !fetch_rule.matches(ProxySide::ClientToProxy, &meta(), 0),
            "and must not claim a subgroup object, or `stream_kind` is not a key"
        );
        let dgram_rule = Matcher { stream_kind: Some(MatchKind::Datagram), ..Matcher::default() };
        assert!(!dgram_rule.matches(ProxySide::ClientToProxy, &fetch, 0));
    }

    /// **Naming a stream kind never makes a rule unmatchable**, on any draft
    /// and from either carrier.
    ///
    /// A *kind* is never dead on a *draft*: what can go missing is one fetch
    /// stream at a time. A stream whose Group Order the session cannot
    /// resolve is bypassed at its header, so no `ObjectMeta` is ever built
    /// for a rule to see, and it reports itself as
    /// `Impairment { FramerBypass { FetchGroupOrderUnknown } }`.
    ///
    /// The contrast is what keeps this from being a test that nothing can
    /// fail: a key a fetch unit really cannot carry is still reported, on the
    /// same drafts, through the same call. Every fetch header carries a
    /// Request ID where a subgroup header carries a Track Alias, so a rule
    /// keyed on the alias can never claim a fetch object on any draft — and
    /// that is a fact about the *key* rather than about one header, which is
    /// what makes it hold wherever the rule is measured.
    ///
    /// *Ablation:* drop the `TrackAlias` row from
    /// [`Matcher::unmatchable_fields`]:
    ///
    /// ```text
    /// assertion `left == right` failed: a fetch header carries a request id
    /// where a subgroup header carries an alias, on every draft
    ///   left: None
    ///  right: Some(TrackAlias)
    /// ```
    #[test]
    fn naming_a_stream_kind_never_makes_a_rule_unmatchable() {
        let fetch_unit = |draft| ObjectMeta {
            draft,
            stream_kind: DataStreamType::Fetch,
            track_alias: None,
            ..meta()
        };
        let field = |m: &Matcher, unit: &ObjectMeta| {
            m.unmatchable_fields(unit).into_iter().flatten().last()
        };

        for kind in [MatchKind::Subgroup, MatchKind::Fetch, MatchKind::Datagram] {
            let rule = Matcher { stream_kind: Some(kind), ..Matcher::default() };
            for draft in DRAFTS {
                assert_eq!(
                    field(&rule, &ObjectMeta { draft, ..meta() }),
                    None,
                    "{draft:?}: a rule aimed at {kind:?} failed to match a subgroup unit, \
                     which is a rule working rather than a rule that cannot work"
                );
                assert_eq!(
                    field(&rule, &fetch_unit(draft)),
                    None,
                    "{draft:?}: nor against a fetch unit"
                );
            }
        }

        // The contrast, on every draft: a key the carrier withholds.
        let by_alias = Matcher { track_alias: Some(RangeSet::single(7)), ..Matcher::default() };
        for draft in DRAFTS {
            assert_eq!(
                field(&by_alias, &fetch_unit(draft)),
                Some(MatcherField::TrackAlias),
                "a fetch header carries a request id where a subgroup header carries an \
                 alias, on every draft"
            );
        }

        // And from the datagram carrier, where the kind row also went: a
        // datagram states its own alias and priority, so a rule aimed at any
        // kind reports nothing about one.
        let dgram = AnyDatagramMeta {
            track_alias: 7,
            group_id: 3,
            object_id: 11,
            publisher_priority: Some(128),
            status: None,
        };
        for kind in [MatchKind::Subgroup, MatchKind::Fetch, MatchKind::Datagram] {
            let rule = Matcher { stream_kind: Some(kind), ..Matcher::default() };
            for draft in DRAFTS {
                assert_eq!(
                    rule.unmatchable_fields_datagram(draft, &dgram).into_iter().flatten().last(),
                    None,
                    "{draft:?}: the answer must not depend on which carrier asked"
                );
            }
        }
    }

    /// **Every key that can name an empty set of values is detected**, one
    /// row per key, so `ShapeProfile::try_new` can reject the class rather
    /// than ship one that looks applied and claims nothing.
    ///
    /// The positive control on each row is the same key holding a
    /// *non-empty* value: without it the table would pass against an
    /// `inert_key` that answered `Some` for any key that was set at all,
    /// which would reject every working profile.
    ///
    /// *Ablation, recorded:* drop the `every_nth` arm — the `n == 0` row
    /// reddens with `left: None / right: Some("every_nth")`.
    #[test]
    fn an_empty_value_set_is_an_inert_key() {
        // A literal `9..=1` is a clippy error at the call site; a runtime
        // configuration can still produce one, which is the whole case.
        let (lo, hi) = (9u64, 1u64);
        let inverted = || RangeSet::new([lo..=hi]);
        let ok = || RangeSet::single(1);

        let (top, bottom) = (200u8, 100u8);
        // `&dyn Fn` and not a `fn` pointer: the rows close over the locals
        // above, which is what keeps a reversed literal out of the source.
        type Edit<'a> = &'a dyn Fn(&mut Matcher, bool);
        let rows: [(&str, Edit); 6] = [
            ("track_alias", &|m, bad| m.track_alias = Some(if bad { inverted() } else { ok() })),
            ("group_id", &|m, bad| m.group_id = Some(if bad { inverted() } else { ok() })),
            ("subgroup_id", &|m, bad| m.subgroup_id = Some(if bad { inverted() } else { ok() })),
            ("object_id", &|m, bad| m.object_id = Some(if bad { inverted() } else { ok() })),
            ("priority", &|m, bad| {
                m.priority = Some(if bad { top..=bottom } else { bottom..=top });
            }),
            ("every_nth", &|m, bad| m.every_nth = Some((if bad { 0 } else { 2 }, 0))),
        ];

        for (key, edit) in rows {
            let mut inert = Matcher::default();
            edit(&mut inert, true);
            assert_eq!(inert.inert_key(), Some(key), "{key} names no value at all");

            let mut live = Matcher::default();
            edit(&mut live, false);
            assert_eq!(live.inert_key(), None, "{key} holding a real value is a working rule");
        }

        // A matcher that keys on nothing claims everything, which is not
        // inert — it is the default.
        assert_eq!(Matcher::default().inert_key(), None);
    }

    /// Every side has a written form, and an unknown one is refused with the
    /// four names listed.
    #[cfg(feature = "serde")]
    #[test]
    fn sides_round_trip_by_name() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Holder {
            #[serde(with = "super::side_serde")]
            side: Option<crate::types::ProxySide>,
        }

        let holder = Holder { side: Some(crate::types::ProxySide::RelayToProxy) };
        let json = serde_json::to_string(&holder).expect("serializes");
        assert_eq!(json, r#"{"side":"relay-to-proxy"}"#);
        assert_eq!(serde_json::from_str::<Holder>(&json).expect("reads back"), holder);

        let refusal = serde_json::from_str::<Holder>(r#"{"side":"relay->proxy"}"#)
            .expect_err("an unknown side is refused");
        assert!(
            refusal.to_string().contains("relay-to-proxy"),
            "the refusal lists the accepted names: {refusal}"
        );
    }
}

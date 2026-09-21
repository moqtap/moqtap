//! A shaping rule keyed on a field the draft cannot carry is refused
//! before the run, not discovered from one.
//!
//! The failure this file gates is the crate's cardinal one: a rule arms,
//! matches nothing, and reports success. `ShapeProfile::try_new` cannot
//! catch it — that constructor validates the configuration alone and has no
//! draft — so until `Capabilities::admit_profile` existed the only signal
//! was `Impairment{ShapeRuleUnmatchable}`, which needs a session, traffic of
//! the right shape, and somebody reading the report afterwards.
//!
//! Every row below is anchored to **observed framer output** rather than to
//! a second copy of the table. Where the predicate answers `false` the
//! framer is run and produces no claimable unit; where it answers `true` the
//! framer is run and the matcher really claims the object it produced. A
//! table asserted against a table can be wrong twice and stay green.
//!
//! # Why the predicate and the refusal are separate tests
//!
//! Asserting both in one body hides half the gate: the predicate assertion
//! panics first, so a mutation that broke the refusal *and* the predicate
//! would only ever be seen as a predicate failure, and one that broke the
//! refusal alone would be invisible until the day the predicate happened to
//! be right. Each claim is its own `#[test]` and each one reddens on its
//! own, which is what the recorded ablations below show.
//!
//! # Why the file is gated on two named drafts
//!
//! Every row attributes its answer by holding the key and the site fixed and
//! changing only the draft — draft-14 frames fetch objects, draft-19 does
//! not — so a build that compiled only one of them cannot make the
//! comparison at all. Gating the file out of that row is honest; running
//! half of each pair would assert that a `false` is about the draft while
//! having nothing to contrast it with.

#![cfg(all(feature = "draft14", feature = "draft19"))]

use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::dispatch::{AnyDatagramMeta, AnyFetchGroupOrder};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::NoOpProxyObserver;

use moqtap_proxy::capability::{supports_matcher, Capabilities, MatcherKey};
use moqtap_proxy::event::ProxySide;
use moqtap_proxy::framer::{
    BypassReason, FetchGroupOrders, FramerConfig, FramerOut, ObjectFramer, ObjectMeta,
};
use moqtap_proxy::parser::data::DataStreamType;
mod common;

use moqtap_proxy::shape::{
    BucketConfig, ClassRule, Discipline, MatchKind, Matcher, QueueConfig, RangeSet, ShapeProfile,
};

// ============================================================
// Wire fixtures, encoded from each draft's layout
// ============================================================

/// A variable-length integer, in whichever of the two encodings the draft
/// uses.
///
/// Written here rather than taken from the codec for the same reason
/// `object_framing_acceptance.rs` writes its own: these tests measure the
/// framer against the wire, and a fixture built by the encoder that sits
/// under the decoder under test cannot show the two disagreeing.
fn put_varint(draft: DraftVersion, out: &mut Vec<u8>, value: u64) {
    if draft.uses_moqt_varint() {
        let width = (1..=8usize).find(|w| value < 1u64 << (7 * w)).unwrap_or(9);
        if width == 9 {
            out.push(0xFF);
            out.extend_from_slice(&value.to_be_bytes());
            return;
        }
        let prefix = (((1u16 << (width - 1)) - 1) << (9 - width)) as u8;
        let combined = (u64::from(prefix) << (8 * (width - 1))) | value;
        for i in (0..width).rev() {
            out.push((combined >> (8 * i)) as u8);
        }
    } else if value < 1 << 6 {
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

/// The stream-type field for a subgroup stream that carries an **explicit**
/// subgroup ID and no extension block.
///
/// Explicit on purpose: a first-object-mode header would leave
/// `ObjectMeta::subgroup_id` absent, and this file's `true` rows assert that
/// a `subgroup_id`-keyed rule really claims a real unit. That absence is a
/// property of one header, which is exactly the per-unit fact
/// `supports_matcher` declines to answer for.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft.number() {
        7..=10 => 0x04,
        11 => 0x0C,
        _ => 0x14,
    }
}

/// Track alias, group, subgroup and publisher priority of every subgroup
/// fixture below. Named because the assertions compare the framer's report
/// against them.
const TRACK_ALIAS: u64 = 7;
const GROUP_ID: u64 = 3;
const SUBGROUP_ID: u64 = 4;
const PRIORITY: u8 = 128;

/// A subgroup header, including the leading stream-type field.
fn subgroup_header(draft: DraftVersion) -> Vec<u8> {
    let mut out = vec![subgroup_stream_type(draft)];
    put_varint(draft, &mut out, TRACK_ALIAS);
    put_varint(draft, &mut out, GROUP_ID);
    put_varint(draft, &mut out, SUBGROUP_ID);
    out.push(PRIORITY);
    out
}

/// A whole subgroup stream: the header, then one object per `(id, payload)`.
fn subgroup_stream(draft: DraftVersion, objects: &[(u64, &[u8])]) -> Vec<u8> {
    let mut out = subgroup_header(draft);
    let mut prev: Option<u64> = None;
    for (object_id, payload) in objects {
        let id_field = match (delta_encoded(draft), prev) {
            (true, Some(prev)) => object_id - prev - 1,
            _ => *object_id,
        };
        put_varint(draft, &mut out, id_field);
        // Drafts 08-10 carry an unconditional extension block; drafts 11+
        // gate it on the stream type, and these fixtures do not set it.
        if matches!(draft.number(), 8..=10) {
            put_varint(draft, &mut out, 0);
        }
        put_varint(draft, &mut out, payload.len() as u64);
        out.extend_from_slice(payload);
        prev = Some(*object_id);
    }
    out
}

/// A fetch stream: type `0x05`, request ID 9, then three objects laid out
/// the way drafts 07-14 do.
///
/// The same bytes are fed to draft-14 and draft-19 on purpose. Draft-14
/// frames them into objects; draft-19's fetch objects are not addressed at
/// all, so the whole stream is forwarded uninterpreted and the difference
/// between the two rows is the draft and nothing else.
fn fetch_stream(draft: DraftVersion) -> Vec<u8> {
    let mut out = vec![0x05, 0x09];
    for (group_id, object_id) in [(7u64, 0u64), (7, 1), (8, 0)] {
        put_varint(draft, &mut out, group_id);
        put_varint(draft, &mut out, 0); // subgroup ID
        put_varint(draft, &mut out, object_id);
        out.push(PRIORITY);
        put_varint(draft, &mut out, 0); // extension block length
        put_varint(draft, &mut out, 4); // payload length
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    out
}

/// The Request ID every fetch stream in this file answers.
const FETCH_REQUEST: u64 = 9;

/// A draft-19 fetch stream of three objects, each stating all four of its
/// fields.
///
/// Drafts 18-21 read a stated Group ID as a *difference* from the object
/// before — draft-19 Section 11.4.4.1 — so these three sit in three groups
/// rather than one. What matters here is that each carries a Subgroup ID for
/// a rule to key on, and that reading them at all needs the fetch's Group
/// Order, which is the whole point of the fixture.
fn delta_fetch_stream() -> Vec<u8> {
    let draft = DraftVersion::Draft19;
    let mut out = vec![0x05];
    put_varint(draft, &mut out, FETCH_REQUEST);
    for (group_delta, object_id) in [(7u64, 0u64), (0, 1), (0, 2)] {
        // Serialization Flags: explicit Subgroup ID, Object ID Delta,
        // Group ID Delta and Publisher Priority all present.
        put_varint(draft, &mut out, 0x03 | 0x04 | 0x08 | 0x10);
        put_varint(draft, &mut out, group_delta);
        put_varint(draft, &mut out, 0); // subgroup ID
        put_varint(draft, &mut out, object_id);
        out.push(PRIORITY);
        put_varint(draft, &mut out, 4); // payload length
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    out
}

/// Everything the framer made of one stream: the objects a rule could
/// claim, and the bypasses that say why there are none.
#[derive(Debug)]
struct Framed {
    objects: Vec<ObjectMeta>,
    bypasses: Vec<BypassReason>,
}

fn frame(kind: DataStreamType, draft: DraftVersion, stream: &[u8]) -> Framed {
    frame_with_orders_of(kind, draft, stream, None)
}

/// [`frame`] for a fetch stream, with or without the answer its draft needs.
fn frame_with_orders(
    draft: DraftVersion,
    stream: &[u8],
    orders: Option<Arc<FetchGroupOrders>>,
) -> Framed {
    frame_with_orders_of(DataStreamType::Fetch, draft, stream, orders)
}

fn frame_with_orders_of(
    kind: DataStreamType,
    draft: DraftVersion,
    stream: &[u8],
    orders: Option<Arc<FetchGroupOrders>>,
) -> Framed {
    let mut framer = ObjectFramer::new(kind, draft, FramerConfig::default());
    if let Some(orders) = orders {
        framer = framer.with_fetch_group_orders(orders);
    }
    let mut out = Framed { objects: Vec::new(), bypasses: Vec::new() };
    framer.feed(stream);
    loop {
        match framer.poll() {
            FramerOut::NeedMore => break,
            FramerOut::Object { meta, .. } => out.objects.push(meta),
            FramerOut::Bypassed { reason, .. } => out.bypasses.push(reason),
            FramerOut::Header { .. } | FramerOut::Passthrough(_) => {}
            FramerOut::Error(e) => panic!("[{draft}] {kind:?} stream failed to frame: {e}"),
            // `FramerOut` is `#[non_exhaustive]`; a new variant carrying
            // claimable units must not be silently ignored here.
            other => panic!("[{draft}] unhandled FramerOut variant: {other:?}"),
        }
    }
    out
}

// ============================================================
// Profile fixtures
// ============================================================

/// A one-class profile the shaping constructor accepts, so every refusal
/// below is attributable to the draft rather than to the configuration.
fn profile(matcher: Matcher) -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = "b".to_string();
    bucket.rate_bps = Some(64_000);
    bucket.burst_bytes = 16_000;

    let mut class = ClassRule::default();
    class.name = "video".to_string();
    class.bucket = "b".to_string();
    class.weight = 1;
    class.matcher = matcher;

    ShapeProfile::try_new(vec![bucket], vec![class], QueueConfig::default(), Discipline::Fifo)
        .expect("the profile must be valid to `try_new` or the refusal is unattributable")
}

/// `Matcher` is `#[non_exhaustive]`, so functional-update syntax is `E0639`
/// from an integration-test crate: every matcher here is a `default()` plus
/// assignments, which is what a caller writes too.
fn keyed(kind: Option<MatchKind>, edit: impl Fn(&mut Matcher)) -> Matcher {
    let mut m = Matcher::default();
    m.stream_kind = kind;
    edit(&mut m);
    m
}

/// A `subgroup_id`-keyed rule aimed at fetch — an ordinary working rule on
/// every draft, and the subject of the first test.
fn fetch_subgroup_id_rule() -> Matcher {
    keyed(Some(MatchKind::Fetch), |m| m.subgroup_id = Some(RangeSet::single(0)))
}

/// A `track_alias`-keyed rule aimed at fetch — dead on **every** draft,
/// because a fetch header carries a Request ID where a subgroup header
/// carries an alias.
fn fetch_track_alias_rule() -> Matcher {
    keyed(Some(MatchKind::Fetch), |m| m.track_alias = Some(RangeSet::single(TRACK_ALIAS)))
}

// ============================================================
// No key is dead on a draft any more
// ============================================================

/// **A `subgroup_id` rule aimed at fetch is admitted on every draft, and
/// draft-19 really builds the units it claims.**
///
/// It was once refused on drafts 18 and 19, and the refusal was right while
/// it stood: their fetch objects write a Group ID as a difference
/// whose sign the fetch's Group Order settles, nothing carried that order to
/// the framer, and so no `ObjectMeta` was ever built for such a rule to see.
/// The session reads the order off the FETCH now, so the rule is an ordinary
/// working one and refusing it would reject a class that shapes traffic.
///
/// The reality half is the point. A predicate that says `true` and a framer
/// that produces nothing would be the same failure the predicate exists to
/// prevent, so the same draft-19 fetch stream is framed twice: once by a
/// framer that was told the order, and once by one that was not.
///
/// *Ablation, recorded:* restore the `!kind.is_matchable_on(draft)` refusal
/// to `supports_matcher` for `Fetch` on drafts 18 and 19:
///
/// ```text
/// a draft-19 fetch object carries a subgroup ID like any other, so a rule
/// keyed on one is an ordinary working rule
/// ```
#[test]
fn a_fetch_key_is_carried_on_every_draft() {
    for draft in [DraftVersion::Draft14, DraftVersion::Draft18, DraftVersion::Draft19] {
        assert!(
            supports_matcher(draft, MatchKind::Fetch, MatcherKey::SubgroupId),
            "a {draft} fetch object carries a subgroup ID like any other, so a rule \
             keyed on one is an ordinary working rule"
        );
        assert!(
            Capabilities::for_draft(draft)
                .admit_profile(&profile(fetch_subgroup_id_rule()))
                .is_ok(),
            "{draft}: and the profile built on it is admitted"
        );
    }

    // Reality, on the draft that needed the fix. The order the session would
    // have read off the FETCH is handed to the framer here directly, which
    // is the same value by a shorter road.
    let stream = delta_fetch_stream();
    let orders = Arc::new(FetchGroupOrders::default());
    orders.record(FETCH_REQUEST, AnyFetchGroupOrder::Ascending);
    let live = frame_with_orders(DraftVersion::Draft19, &stream, Some(orders));
    assert_eq!(live.objects.len(), 3, "draft-19 frames a fetch stream it knows the order of");
    assert!(live.bypasses.is_empty(), "and gives nothing up: {:?}", live.bypasses);
    let rule = fetch_subgroup_id_rule();
    assert!(
        live.objects.iter().all(|meta| rule.matches(ProxySide::ClientToProxy, meta, 0)),
        "and every one of them carries the subgroup ID the rule keys on"
    );

    // The contrast, from the same bytes: a framer that was told nothing
    // still gives the stream up, and says why. That is now a fact about one
    // stream rather than about draft-19.
    let dead = frame_with_orders(DraftVersion::Draft19, &stream, None);
    assert!(dead.objects.is_empty(), "an unanswered fetch stream builds no ObjectMeta");
    assert_eq!(
        dead.bypasses,
        vec![BypassReason::FetchGroupOrderUnknown],
        "and reports why, exactly once per stream"
    );
}

// ============================================================
// The predicate answers true, and reality agrees
// ============================================================

/// **Every key the predicate admits really claims a real framed object.**
///
/// Without this the two tests above would be satisfied by a predicate that
/// answered `false` for everything — which would refuse every profile ever
/// written and pass both refusal assertions perfectly.
///
/// One row per `MatcherKey`, each keyed on the value the framer actually
/// reported for that object, on both drafts, so the sweep covers the whole
/// axis rather than the one key the tests above use.
///
/// *Ablation, recorded:* replace `supports_matcher`'s body with `false` —
/// every row reddens, the first at the very first key:
///
/// ```text
/// track_alias is carried on draft-14 subgroup streams
/// ```
#[test]
fn every_key_the_predicate_admits_claims_a_real_object() {
    for draft in [DraftVersion::Draft14, DraftVersion::Draft19] {
        let stream = subgroup_stream(draft, &[(0, b"deadbeef"), (1, b"cafe")]);
        let framed = frame(DataStreamType::Subgroup, draft, &stream);
        assert!(framed.bypasses.is_empty(), "[{draft}] a subgroup stream must frame: {framed:?}");
        let meta = *framed.objects.first().unwrap_or_else(|| {
            panic!("[{draft}] a subgroup stream must produce a claimable object")
        });

        // The values below come from the framer's own report, so a fixture
        // that encoded something else cannot make a row pass by agreeing
        // with the constant it was built from.
        let alias = meta.track_alias.expect("a subgroup header carries a track alias");
        let subgroup = meta.subgroup_id.expect("an explicit-mode header carries a subgroup ID");
        let priority = meta.publisher_priority.expect("this header carries a publisher priority");
        assert_eq!((alias, meta.group_id, subgroup), (TRACK_ALIAS, GROUP_ID, SUBGROUP_ID));

        type Edit<'a> = &'a dyn Fn(&mut Matcher);
        let rows: [(MatcherKey, Edit); 6] = [
            (MatcherKey::TrackAlias, &|m| m.track_alias = Some(RangeSet::single(alias))),
            (MatcherKey::GroupId, &|m| m.group_id = Some(RangeSet::single(meta.group_id))),
            (MatcherKey::SubgroupId, &|m| m.subgroup_id = Some(RangeSet::single(subgroup))),
            (MatcherKey::ObjectId, &|m| m.object_id = Some(RangeSet::single(meta.object_id))),
            (MatcherKey::Priority, &|m| m.priority = Some(priority..=priority)),
            (MatcherKey::EveryNth, &|m| m.every_nth = Some((1, 0))),
        ];

        // A key published without a row here would be swept by nothing, and
        // a hand-written list cannot notice its own gap.
        assert_eq!(
            rows.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            MatcherKey::ALL.to_vec(),
            "every published key needs a row, in the order they are declared"
        );

        for (key, edit) in rows {
            let name = key.field_name();
            assert!(
                supports_matcher(draft, MatchKind::Subgroup, key),
                "{name} is carried on {draft} subgroup streams"
            );
            let rule = keyed(Some(MatchKind::Subgroup), edit);
            assert!(
                rule.matches(ProxySide::ClientToProxy, &meta, 0),
                "[{draft}] a rule keyed on {name} must claim the object the framer \
                 reported it from, or the predicate admits a rule that cannot fire"
            );
            assert_eq!(
                Capabilities::for_draft(draft)
                    .admit_profile(&profile(keyed(Some(MatchKind::Subgroup), edit))),
                Ok(()),
                "[{draft}] and the admission check must let a {name} rule through"
            );
        }
    }
}

// ============================================================
// The answer that varies by site rather than by draft
// ============================================================

/// **`track_alias` is carried on a subgroup stream and on no fetch stream,
/// on the same draft** — which is why the predicate takes the site.
///
/// A fetch header carries a request ID where a subgroup header carries a
/// track alias, so the framer builds every fetch object with
/// `track_alias: None` and an absent key never matches. Draft-14 is used for
/// both halves so the difference cannot be read as the draft's.
///
/// The `group_id` control on the same fetch objects is what makes the
/// negative attributable to the key: without it the row would also pass if
/// the fetch fixture had framed nothing at all.
///
/// *Ablation, recorded:* replace `supports_matcher`'s body with `true`:
///
/// ```text
/// a fetch header carries a request ID instead, on every draft that frames one
/// ```
///
/// and with `false`, which the subgroup half catches:
///
/// ```text
/// a subgroup header carries a track alias
/// ```
#[test]
fn track_alias_is_carried_by_site_and_not_by_draft() {
    let draft = DraftVersion::Draft14;

    assert!(
        supports_matcher(draft, MatchKind::Subgroup, MatcherKey::TrackAlias),
        "a subgroup header carries a track alias"
    );
    assert!(
        !supports_matcher(draft, MatchKind::Fetch, MatcherKey::TrackAlias),
        "a fetch header carries a request ID instead, on every draft that frames one"
    );

    // Reality: draft-14 really does frame these fetch objects, and really
    // does report no track alias on any of them.
    let framed = frame(DataStreamType::Fetch, draft, &fetch_stream(draft));
    assert_eq!(framed.objects.len(), 3, "draft-14 frames fetch objects");
    assert!(
        framed.objects.iter().all(|m| m.track_alias.is_none()),
        "a fetch header carries a request ID, so no fetch object has a track alias"
    );

    let by_alias =
        keyed(Some(MatchKind::Fetch), |m| m.track_alias = Some(RangeSet::single(TRACK_ALIAS)));
    let by_group = keyed(Some(MatchKind::Fetch), |m| m.group_id = Some(RangeSet::new([0..=99])));
    for meta in &framed.objects {
        assert!(
            !by_alias.matches(ProxySide::ClientToProxy, meta, 0),
            "an absent key never matches"
        );
        assert!(
            by_group.matches(ProxySide::ClientToProxy, meta, 0),
            "and a key the same objects do carry still claims them, so the line above \
             is about track_alias and not about the fixture"
        );
    }
}

/// **The site-scoped refusal**, on a draft that frames fetch objects
/// perfectly well.
///
/// The companion to the test above: the fetch objects are there, the draft
/// is not the problem, and the rule is still refused because no fetch object
/// on any draft carries a track alias. The same key aimed at the other site
/// is admitted in the same body, so the refusal cannot be passing because
/// `track_alias` is refused outright.
///
/// *Ablation, recorded:* replace `supports_matcher`'s body with `true`:
///
/// ```text
/// no fetch object carries a track alias, so this rule can never claim one: ()
/// ```
///
/// and with `false`, where the subgroup control is what catches it:
///
/// ```text
/// assertion `left == right` failed
///   left: Err(UnsupportedMatcherKey { class: "video", draft: Draft14,
///              kind: Some(Subgroup), key: TrackAlias })
///  right: Ok(())
/// ```
#[test]
fn a_fetch_aimed_track_alias_rule_is_refused() {
    let draft = DraftVersion::Draft14;
    let caps = Capabilities::for_draft(draft);

    let p = profile(keyed(Some(MatchKind::Fetch), |m| {
        m.track_alias = Some(RangeSet::single(TRACK_ALIAS));
    }));
    let err = caps
        .admit_profile(&p)
        .expect_err("no fetch object carries a track alias, so this rule can never claim one");
    assert_eq!(err.key, MatcherKey::TrackAlias);
    assert_eq!(err.draft, draft);
    assert_eq!(err.kind, Some(MatchKind::Fetch));
    let message = err.to_string();
    assert!(message.contains("track_alias") && message.contains("draft-14"), "{message}");

    // The same key aimed at the other site is an ordinary working rule on
    // the same draft, so the refusal is the site's and not the key's.
    let subgroup_rule = profile(keyed(Some(MatchKind::Subgroup), |m| {
        m.track_alias = Some(RangeSet::single(TRACK_ALIAS));
    }));
    assert_eq!(caps.admit_profile(&subgroup_rule), Ok(()));
}

/// **A datagram-aimed `subgroup_id` rule is refused**, on every draft, and
/// the same key is admitted for the other two kinds.
///
/// This is the one refusal in the table that is about the *carrier* rather
/// than the draft. No datagram of any of the fourteen belongs to a subgroup
/// — there is no header shape anywhere in the family that puts the field on
/// one — so the answer is knowable the moment a class names both, which is
/// what makes it a refusal here and not an
/// `Impairment{ShapeRuleUnmatchable}` from a run. Both drafts are asserted
/// so that "on every draft" is measured rather than assumed.
///
/// # The anchor, and what it is anchored to
///
/// The rest of this file drives the framer, because the keys it is about are
/// carried by framed objects. A datagram never reaches a framer, so the
/// observable here is [`Matcher::matches_datagram`] against a real
/// datagram's resolved identity: the keyed rule claims nothing, and the
/// same rule with the key removed claims it. Without that second half the
/// first would pass for a matcher that had stopped claiming datagrams
/// altogether, which is a different bug with the same table entry.
///
/// *Ablation (measured):* drop the `kind == MatchKind::Datagram && field ==
/// MatcherKey::SubgroupId` clause from `supports_matcher`.
///
/// ```text
/// ---- a_datagram_aimed_subgroup_id_rule_is_refused stdout ----
/// no datagram carries a subgroup ID, so this rule can never claim one: ()
/// ```
#[test]
fn a_datagram_aimed_subgroup_id_rule_is_refused() {
    // A datagram carrying every key one can carry. Built here rather than
    // decoded, because what is under test is which keys a rule may name and
    // not how a header is read.
    let dgram = AnyDatagramMeta {
        track_alias: TRACK_ALIAS,
        group_id: GROUP_ID,
        object_id: 0,
        publisher_priority: Some(PRIORITY),
        status: None,
    };

    for draft in [DraftVersion::Draft14, DraftVersion::Draft19] {
        let caps = Capabilities::for_draft(draft);

        let keyed_rule = keyed(Some(MatchKind::Datagram), |m| {
            m.subgroup_id = Some(RangeSet::single(SUBGROUP_ID))
        });
        let err = caps
            .admit_profile(&profile(keyed_rule.clone()))
            .expect_err("no datagram carries a subgroup ID, so this rule can never claim one");
        assert_eq!(err.key, MatcherKey::SubgroupId);
        assert_eq!(err.draft, draft);
        assert_eq!(err.kind, Some(MatchKind::Datagram));
        let message = err.to_string();
        assert!(message.contains("subgroup_id"), "{message}");

        // Reality agrees: the rule claims nothing...
        assert!(
            !keyed_rule.matches_datagram(ProxySide::ClientToProxy, &dgram, 0),
            "[{draft}] a subgroup_id key must not claim a datagram"
        );
        // ...and the same class without that one key claims it, so the
        // refusal is the key's and not the kind's.
        let bare = keyed(Some(MatchKind::Datagram), |_| {});
        assert!(
            bare.matches_datagram(ProxySide::ClientToProxy, &dgram, 0),
            "[{draft}] a datagram-aimed class with no value keys must claim a datagram"
        );

        // And the same key aimed at a subgroup stream is an ordinary
        // working rule on the same draft.
        let subgroup_rule = profile(keyed(Some(MatchKind::Subgroup), |m| {
            m.subgroup_id = Some(RangeSet::single(SUBGROUP_ID));
        }));
        assert_eq!(caps.admit_profile(&subgroup_rule), Ok(()));
    }
}

// ============================================================
// What must not be refused
// ============================================================

/// **A rule that names no stream kind is not refused for being dead on
/// fetch**, because it still claims every subgroup unit.
///
/// The over-refusal guard. Rejecting a working configuration at startup is a
/// worse failure than the silent one being fixed: a run that shapes nothing
/// can at least be observed afterwards, while a profile refused before the
/// session cannot run at all.
///
/// The second half is the same statement about the two keys a *unit* may
/// lack. `subgroup_id` is absent from a first-object-mode header and
/// `priority` from a draft-15-and-later header that set the default-priority
/// bit, but every draft also has header shapes that carry both — so those
/// are per-unit facts, reported during the run as
/// `Impairment{ShapeRuleUnmatchable}`, and refusing them here would kill
/// rules that work.
///
/// *Ablation, recorded:* replace `supports_matcher`'s body with `false` —
/// the over-refusal is what ships, and the `left` is the working profile
/// that would have been rejected at startup:
///
/// ```text
/// assertion `left == right` failed: [draft-14] a track_alias rule that names no
/// stream kind still claims every subgroup unit
///   left: Err(UnsupportedMatcherKey { class: "video", draft: Draft14, kind: None,
///              key: TrackAlias })
///  right: Ok(())
/// ```
#[test]
fn a_rule_that_can_still_fire_somewhere_is_admitted() {
    for draft in [DraftVersion::Draft14, DraftVersion::Draft19] {
        let caps = Capabilities::for_draft(draft);

        // No stream kind named: dead on fetch, live on subgroup, admitted.
        let anywhere = profile(keyed(None, |m| {
            m.track_alias = Some(RangeSet::single(TRACK_ALIAS));
        }));
        assert_eq!(
            caps.admit_profile(&anywhere),
            Ok(()),
            "[{draft}] a track_alias rule that names no stream kind still claims \
             every subgroup unit"
        );

        // And it really does claim one.
        let stream = subgroup_stream(draft, &[(0, b"deadbeef")]);
        let framed = frame(DataStreamType::Subgroup, draft, &stream);
        let meta = framed.objects[0];
        let rule = keyed(None, |m| m.track_alias = Some(RangeSet::single(TRACK_ALIAS)));
        assert!(rule.matches(ProxySide::ClientToProxy, &meta, 0), "[{draft}]");

        // The two keys a unit may lack are draft-wide `true`, on both the
        // draft that has a first-object subgroup mode and a default-priority
        // bit and the one that has neither.
        for key in [MatcherKey::SubgroupId, MatcherKey::Priority] {
            assert!(
                supports_matcher(draft, MatchKind::Subgroup, key),
                "[{draft}] {} is carried by some header on every draft, so a rule \
                 keyed on it must not be refused before the run",
                key.field_name()
            );
        }
    }
}

// ============================================================
// The refusal reaches a real session
// ============================================================

/// **A session carrying a dead-keyed profile never dials its relay.**
///
/// The tests above prove the predicate answers correctly and that
/// `admit_profile` turns a `false` into a refusal. Neither of them shows
/// that anything *calls* it, and a predicate with no call site is a check
/// that ships correct and unenforced — the rule still arms, still matches
/// nothing, and the run is still believed. That is the same failure the
/// predicate was written to prevent, moved one level out.
///
/// The observable is chosen so that it cannot be satisfied by an
/// implementation that merely returns an error somewhere: the refusal has
/// to happen **before the relay leg is opened**, so a relay that never sees
/// a connection is the evidence. Both arms use the same profile shape and
/// the same draft and differ only in the key the class names, which is the
/// one thing under test.
///
/// The dead key is `track_alias` at a fetch site rather than anything
/// draft-shaped, because no key is dead on a *draft* any more: the one that
/// was — `subgroup_id` aimed at fetch on drafts 18 and 19 — is an ordinary
/// working rule now that the session carries the fetch's Group Order.
///
/// *Ablation, recorded:* with the `admit_profile` call disabled in
/// `run_with_transport`, the dead-keyed arm dials like any other session and
/// the first assertion panics at this file with `the relay must never be
/// dialled for a session whose only class is dead on draft-19`. The relay
/// accepted the connection the refusal was supposed to prevent, and the
/// control arm below stayed green throughout — which is what makes the
/// failure attributable to the refusal rather than to the fixture.
#[tokio::test]
async fn a_dead_keyed_profile_stops_the_session_before_it_opens_the_relay_leg() {
    common::init_crypto();

    // A fetch stream carries a Request ID where a subgroup stream carries a
    // Track Alias, so a class keyed on the alias at a fetch site can never
    // claim a unit — on draft-19 or on any other draft, which is what the
    // pairs above establish.
    let dead = dial_reached_relay(DraftVersion::Draft19, fetch_track_alias_rule()).await;
    assert!(
        !dead,
        "the relay must never be dialled for a session whose only class is dead on draft-19"
    );

    // The control arm. `track_alias` is carried by every framed unit on
    // every draft, so this profile is admitted and the session proceeds
    // exactly as it always did. Without it the assertion above would also
    // pass against a build that refused every profile, or that never dialled
    // at all.
    let live = dial_reached_relay(
        DraftVersion::Draft19,
        keyed(Some(MatchKind::Subgroup), |m| m.track_alias = Some(RangeSet::single(TRACK_ALIAS))),
    )
    .await;
    assert!(
        live,
        "a profile whose keys the draft does carry must still reach the relay — otherwise the \
         assertion above is about something other than the key"
    );
}

/// Run one arm: stand a relay up, point a session at it with `matcher` as
/// its only class, connect a client, and answer whether the relay was ever
/// dialled.
///
/// The wait is bounded rather than open: a relay that is *going* to be
/// dialled is dialled as soon as the client connection lands, and a bound
/// is what stops the refusing arm hanging for the harness timeout instead
/// of reporting.
async fn dial_reached_relay(draft: DraftVersion, matcher: Matcher) -> bool {
    let (upstream, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);

    let mut config = common::session_config(draft, upstream_addr);
    config.shape = Some(profile(matcher));

    let proxy = common::spawn_proxy_with(
        config,
        draft.quic_alpn(),
        Arc::new(NoOpProxyObserver),
        Arc::new(NoOpHook),
    );
    let (_client_ep, _client) = common::connect_client(proxy.addr, draft.quic_alpn()).await;

    let dialled = tokio::time::timeout(Duration::from_millis(600), upstream.accept())
        .await
        .is_ok_and(|incoming| incoming.is_some());

    proxy.cancel.cancel();
    dialled
}

use super::*;
use crate::pack::{Head, Packer};
use crate::sampling::level;
use crate::Timing;

const NS: [&str; 2] = ["live", "ch"];

fn sent(g: u64, o: u64) -> Handoff {
    Handoff {
        g,
        sub: Some(0),
        o,
        size: 10,
        starts_group: false,
        opens_subgroup: false,
        ends_group: false,
    }
}

fn collector() -> (Collector, u64) {
    let mut c = Collector::new(15_000);
    let (id, _) = c.open("https://relay.example".into(), 0).expect("open");
    (c, id)
}

fn send(c: &mut Collector, conn: u64, track: &str, h: Handoff, at: i64) -> Wake {
    c.observe(at, None);
    c.object_sent(conn, &NS, track.as_bytes(), h, at).expect("taken")
}

fn cut(c: &mut Collector, at: i64) -> Interval {
    assert!(c.cut(at, false), "nothing to cut");
    c.cuts.pop_back().expect("interval")
}

/// `(group, subgroup, ids, gs, fo, eog)` per run.
type RunView = (u64, Option<u64>, Vec<u64>, bool, bool, bool);

fn runs(iv: &Interval) -> Vec<RunView> {
    iv.runs.iter().map(|r| (r.flow.g, r.flow.sub, r.ids.clone(), r.gs, r.fo, r.eog)).collect()
}

#[test]
fn runs_break_at_a_repeat_and_at_group_and_subgroup_starts() {
    let (mut c, id) = collector();
    let start = Handoff { starts_group: true, opens_subgroup: true, ..sent(5, 0) };
    send(&mut c, id, "v", start, 1_000);
    send(&mut c, id, "v", sent(5, 1), 2_000);
    send(&mut c, id, "v", sent(5, 3), 3_000);
    // A repeat of an id is a new publication and a new run.
    send(&mut c, id, "v", sent(5, 3), 4_000);
    send(&mut c, id, "v", Handoff { opens_subgroup: true, ..sent(5, 4) }, 5_000);
    send(&mut c, id, "v", Handoff { ends_group: true, ..sent(5, 5) }, 6_000);
    send(&mut c, id, "v", sent(5, 6), 7_000);
    let iv = cut(&mut c, 10_000);
    assert_eq!(
        runs(&iv),
        [
            (5, Some(0), vec![0, 1, 3], true, true, false),
            (5, Some(0), vec![3], false, false, false),
            (5, Some(0), vec![4, 5], false, true, true),
            (5, Some(0), vec![6], false, false, false),
        ]
    );
}

#[test]
fn a_flow_is_connection_track_group_and_subgroup() {
    let (mut c, a) = collector();
    let (b, _) = c.open("https://other.example".into(), 0).expect("open");
    send(&mut c, a, "v", sent(1, 0), 1);
    send(&mut c, a, "v", Handoff { sub: Some(1), ..sent(1, 0) }, 2);
    send(&mut c, a, "v", Handoff { sub: None, ..sent(1, 0) }, 3);
    send(&mut c, a, "w", sent(1, 0), 4);
    send(&mut c, b, "v", sent(1, 0), 5);
    send(&mut c, a, "v", sent(1, 1), 6);
    let iv = cut(&mut c, 10);
    assert_eq!(iv.runs.len(), 5);
    assert_eq!(iv.runs[0].ids, [0, 1]);
    assert_eq!(iv.tracks.len(), 2);
    assert_eq!(iv.conns.len(), 2);
}

#[test]
fn nothing_is_dropped_for_being_late_and_falling_groups_are_counted() {
    let (mut c, id) = collector();
    for (i, g) in [5u64, 3, 5, 900, 2].into_iter().enumerate() {
        send(&mut c, id, "v", sent(g, 0), i as i64 * 1000);
    }
    let iv = cut(&mut c, 10_000);
    assert_eq!(iv.runs.iter().map(|r| r.flow.g).collect::<Vec<_>>(), [5, 3, 5, 900, 2]);
    assert_eq!(iv.gdec.values().copied().collect::<Vec<_>>(), [2]);
    assert_eq!(iv.dropped_records, 0);
}

#[test]
fn pacing_splits_gaps_before_group_starts_from_the_rest() {
    let (mut c, id) = collector();
    let gs = |g| Handoff { starts_group: true, ..sent(g, 0) };
    send(&mut c, id, "v", gs(1), 0);
    send(&mut c, id, "v", sent(1, 1), 33_333);
    send(&mut c, id, "v", sent(1, 2), 66_666);
    send(&mut c, id, "v", gs(2), 250_000);
    let iv = cut(&mut c, 300_000);
    let p = iv.pace.values().next().expect("pace");
    assert_eq!(p.later.iter().map(|(k, n)| (*k, *n)).collect::<Vec<_>>(), [(72, 2)]);
    assert_eq!(p.first.iter().map(|(k, n)| (*k, *n)).collect::<Vec<_>>(), [(key_of(183_334), 1)]);
}

#[test]
fn ids_past_two_to_the_62_need_draft_17() {
    let (mut c, id) = collector();
    let big = sent(1 << 62, 0);
    c.observe(1, None);
    assert!(c.object_sent(id, &NS, b"v", big, 1).is_ok(), "no draft known");
    c.set_draft(id, 16).unwrap();
    assert_eq!(c.object_sent(id, &NS, b"v", big, 2), Err(Refused::Input));
    let big_sub = Handoff { sub: Some(u64::MAX), ..sent(1, 0) };
    assert_eq!(c.object_sent(id, &NS, b"v", big_sub, 2), Err(Refused::Input));
    c.set_draft(id, 17).unwrap();
    assert!(c.object_sent(id, &NS, b"v", sent(u64::MAX, u64::MAX), 3).is_ok());
    assert_eq!(c.set_draft(id, 0), Err(Refused::Input));
    assert_eq!(c.set_draft(id, 65_536), Err(Refused::Input));
}

#[test]
fn statuses_and_gaps_follow_the_draft() {
    let (mut c, id) = collector();
    let mark = |c: &mut Collector, kind| c.mark(id, &NS, b"v", kind, 1, 2, 3, 5);
    assert!(mark(&mut c, MarkKind::Eosg).is_ok(), "no draft known");
    for (draft, kind, ok) in [
        (7, MarkKind::Eosg, true),
        (8, MarkKind::Eosg, false),
        (7, MarkKind::Eot, false),
        (8, MarkKind::Eot, true),
        (10, MarkKind::Eotg, true),
        (11, MarkKind::Eotg, false),
        (15, MarkKind::Dne, true),
        (16, MarkKind::Dne, false),
        (10, MarkKind::Pgg, false),
        (11, MarkKind::Pgg, true),
        (13, MarkKind::Pog, false),
        (22, MarkKind::Pog, true),
        (22, MarkKind::Eog, true),
        (23, MarkKind::Eog, true),
        (23, MarkKind::Eot, true),
        (23, MarkKind::Pgg, true),
        (23, MarkKind::Pog, true),
        (23, MarkKind::Dne, false),
        (23, MarkKind::Eotg, false),
        (23, MarkKind::Eosg, false),
    ] {
        c.set_draft(id, draft).unwrap();
        assert_eq!(mark(&mut c, kind).is_ok(), ok, "{kind:?} on {draft}");
    }
    c.cut(10, false);
    let ivs: Vec<Interval> = c.cuts.drain(..).collect();
    assert_eq!(ivs.iter().map(|i| i.marks.len()).sum::<usize>(), 12);
    for iv in &ivs {
        let d = iv.conns[&id].draft;
        for m in &iv.marks {
            let (lo, hi) = m.kind.drafts();
            assert!(d.is_none_or(|d| (lo..=hi).contains(&d)), "{:?} under {d:?}", m.kind);
        }
    }
}

#[test]
fn a_draft_set_after_a_status_seals_the_status_under_the_old_draft() {
    let (mut c, id) = collector();
    c.mark(id, &NS, b"v", MarkKind::Dne, 1, 2, 3, 5).unwrap();
    c.observe(10, None);
    assert_eq!(c.set_draft(id, 16), Ok(Wake::Seal));
    let first = c.cuts.pop_front().expect("sealed");
    assert_eq!(first.conns[&id].draft, None);
    assert_eq!(first.marks.len(), 1);
    assert_eq!(c.mark(id, &NS, b"v", MarkKind::Dne, 1, 2, 3, 5), Err(Refused::Input));
    send(&mut c, id, "v", sent(1, 0), 20);
    assert_eq!(c.set_draft(id, 16), Ok(Wake::No), "the same draft again");
    let second = cut(&mut c, 30);
    assert_eq!(second.conns[&id].draft, Some(16));
    assert!(second.marks.is_empty());

    let (mut c, id) = collector();
    send(&mut c, id, "v", Handoff { o: u64::MAX, ..sent(1, 0) }, 1);
    c.observe(2, None);
    assert_eq!(c.set_draft(id, 16), Ok(Wake::Seal), "an id past 2^62 - 1 with no draft");
    assert_eq!(c.cuts.pop_front().expect("sealed").conns[&id].draft, None);
}

#[test]
fn a_draft_set_before_any_object_seals_nothing() {
    let (mut c, id) = collector();
    assert_eq!(c.set_draft(id, 14), Ok(Wake::No));
    send(&mut c, id, "v", sent(1, 0), 1);
    assert!(c.cuts.is_empty());
    assert_eq!(cut(&mut c, 2).conns[&id].draft, Some(14));
}

fn gz_len(s: &crate::pack::Sealed) -> usize {
    let probe =
        crate::wire::Clk { base_us: s.base_us, epoch: s.epoch, res_us: 1, sample: None, app: None };
    crate::wire::gzip(&crate::wire::frames(&s.batch, &probe, &s.records)).len()
}

/// The sender's part: names fixed at the first send, then the answer.
fn sent_and_answered(s: &mut crate::pack::Sealed, accepted: bool) {
    s.name_tracks();
    s.answered(accepted);
}

#[test]
fn a_long_track_list_leaves_room_for_many_objects() {
    for (tracks, name) in [
        (256, "video-{i}".to_string()),
        (
            100,
            "event-2026-11-03-final/camera-{i}/".to_string() + &"rendition-1080p60-h264-".repeat(7),
        ),
    ] {
        let mut c = Collector::new(15_000);
        let (id, _) = c.open("https://relay.example".into(), 0).expect("open");
        let ns: [&[u8]; 2] = [b"example.com", b"live"];
        let names: Vec<String> = (0..tracks).map(|i| name.replace("{i}", &i.to_string())).collect();
        let mut at = 0;
        for n in &names {
            at += 1_000;
            c.observe(at, None);
            c.object_sent(id, &ns, n.as_bytes(), sent(0, 0), at).expect("taken");
        }
        c.cut(at, false);
        let mut packer = Packer::new(head(), None);
        for iv in c.cuts.drain(..) {
            sent_and_answered(&mut packer.pack(iv, None, Timing::Object), true);
        }
        for o in 1..=3000u64 {
            at += 1_000;
            c.observe(at, None);
            c.object_sent(id, &ns, names[0].as_bytes(), sent(0, o), at).expect("taken");
        }
        c.cut(at, false);
        let bodies: Vec<_> =
            c.cuts.drain(..).map(|iv| packer.pack(iv, None, Timing::Object)).collect();
        assert!(bodies.len() <= 3, "{} bodies for {tracks} tracks", bodies.len());
        for mut b in bodies {
            sent_and_answered(&mut b, true);
            assert_eq!(b.batch.tracks.len(), tracks);
            assert!(gz_len(&b) <= SEAL_BYTES, "{}", gz_len(&b));
        }
    }
}

/// Names of `len` bytes that do not compress, 256 tracks of them. At 120
/// bytes the list alone is past the byte seal.
fn incompressible_names(len: usize) -> Vec<Vec<u8>> {
    let mut x: u64 = 0x9e37_79b9;
    (0..256)
        .map(|_| {
            (0..len)
                .map(|_| {
                    x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    (x >> 56) as u8
                })
                .collect()
        })
        .collect()
}

#[test]
fn a_track_list_past_the_seal_is_listed_by_key_once_its_names_are_accepted() {
    let mut c = Collector::new(15_000);
    let (id, _) = c.open("https://relay.example".into(), 0).expect("open");
    let names = incompressible_names(120);
    let mut at = 0;
    for n in &names {
        at += 1_000;
        c.observe(at, None);
        c.object_sent(id, &NS, n, sent(0, 0), at).expect("taken");
    }
    c.cut(at, false);
    let mut packer = Packer::new(head(), None);
    for iv in c.cuts.drain(..) {
        let mut s = packer.pack(iv, None, Timing::Object);
        sent_and_answered(&mut s, true);
        assert!(s.batch.tracks.iter().all(|t| t.named == (t.span.is_some())), "named once");
    }
    for o in 1..=3000u64 {
        at += 1_000;
        c.observe(at, None);
        c.object_sent(id, &NS, &names[0], sent(0, o), at).expect("taken");
    }
    c.cut(at, false);
    let bodies: Vec<_> = c.cuts.drain(..).map(|iv| packer.pack(iv, None, Timing::Object)).collect();
    assert_eq!(bodies.len(), 1, "3000 objects fit one body");
    for mut b in bodies {
        sent_and_answered(&mut b, true);
        assert_eq!(b.batch.tracks.len(), 256);
        assert!(b.batch.tracks.iter().all(|t| !t.named));
        assert!(gz_len(&b) <= SEAL_BYTES, "{}", gz_len(&b));
    }
}

#[test]
fn names_stay_in_every_body_until_one_carrying_them_is_accepted() {
    let (mut c, id) = collector();
    let mut packer = Packer::new(head(), None);
    let mut bodies = Vec::new();
    for b in 0..4u64 {
        send(&mut c, id, "v", sent(b, 0), b as i64 * 100);
        bodies.push(packer.pack(cut(&mut c, b as i64 * 100 + 50), None, Timing::Object));
    }
    let mut named = Vec::new();
    // Ingest is down: the first body is sent, then given up.
    for (b, accepted) in bodies.iter_mut().zip([false, true, true, true]) {
        sent_and_answered(b, accepted);
        named.push(b.batch.tracks[0].named);
    }
    assert_eq!(named, [true, true, false, false]);
}

/// Ingest refuses a larger body for good (413).
const INGEST_MAX_BODY: usize = 96 * 1024;

#[test]
fn bodies_after_a_given_up_name_list_stay_under_the_ingest_cap() {
    let mut c = Collector::new(15_000);
    let (id, _) = c.open("https://relay.example".into(), 0).expect("open");
    let names = incompressible_names(260);
    let mut at = 0;
    for n in &names {
        at += 1_000;
        c.observe(at, None);
        c.object_sent(id, &NS, n, sent(0, 0), at).expect("taken");
    }
    c.cut(at, false);
    let mut packer = Packer::new(head(), None);
    let mut largest = 0;
    for iv in c.cuts.drain(..) {
        let mut s = packer.pack(iv, None, Timing::Object);
        sent_and_answered(&mut s, false);
        largest = largest.max(gz_len(&s));
    }
    assert!(largest > 64 * 1024, "the name list alone is past 64 KiB: {largest}");
    assert!(largest <= INGEST_MAX_BODY, "{largest}");
    // Every body until one carrying the names is accepted carries them.
    let mut o = 0;
    while c.cuts.len() < 2 {
        o += 1;
        assert!(o < 50_000, "no seal");
        at += 1_000;
        c.observe(at, None);
        c.object_sent(id, &NS, &names[0], sent(0, o), at).expect("taken");
    }
    let mut sent_now: Vec<_> = Vec::new();
    for iv in c.cuts.drain(..) {
        let mut s = packer.pack(iv, None, Timing::Object);
        s.name_tracks();
        assert!(s.batch.tracks.iter().all(|t| t.named));
        assert!(gz_len(&s) <= INGEST_MAX_BODY, "{}", gz_len(&s));
        sent_now.push(s);
    }
    for s in &sent_now {
        s.answered(true);
    }
    // Accepted: the open body is measured again and fills with objects.
    for _ in 0..3000 {
        o += 1;
        at += 1_000;
        c.observe(at, None);
        c.object_sent(id, &NS, &names[0], sent(0, o), at).expect("taken");
    }
    c.cut(at, false);
    let bodies: Vec<_> = c.cuts.drain(..).map(|iv| packer.pack(iv, None, Timing::Object)).collect();
    assert_eq!(bodies.len(), 1, "3000 objects fit one body");
    for mut b in bodies {
        sent_and_answered(&mut b, true);
        assert!(b.batch.tracks.iter().all(|t| !t.named));
        assert!(gz_len(&b) <= SEAL_BYTES, "{}", gz_len(&b));
    }
}

#[test]
fn early_seals_chain_and_lose_nothing() {
    let (mut c, id) = collector();
    for g in 0..MAX_FLOWS as u64 + 1 {
        send(&mut c, id, "v", Handoff { size: 0, ..sent(g, 0) }, g as i64);
    }
    c.cut(1 << 20, false);
    let cuts: Vec<Interval> = c.cuts.drain(..).collect();
    assert!(cuts.len() >= 2);
    for w in cuts.windows(2) {
        assert_eq!(w[0].through_us, w[1].from_us, "the intervals chain");
    }
    assert!(cuts.iter().all(|i| i.runs.len() <= MAX_FLOWS));
    assert_eq!(cuts.iter().map(|i| i.runs.len()).sum::<usize>(), MAX_FLOWS + 1);
}

#[test]
fn a_body_holds_at_most_32_connections() {
    let mut c = Collector::new(15_000);
    let mut ids = Vec::new();
    for i in 0..40 {
        ids.push(c.open(format!("https://r{i}.example"), 0).expect("open").0);
    }
    let first = c.cuts.pop_front().expect("sealed at the 33rd");
    assert_eq!(first.conns.len(), MAX_BODY_CONNS);
    let rest = cut(&mut c, 1);
    assert_eq!(rest.conns.len(), 8);
}

#[test]
fn a_clock_break_seals_under_the_old_epoch() {
    let (mut c, id) = collector();
    c.observe(0, Some(1_000_000_000));
    send(&mut c, id, "v", sent(1, 0), 10);
    assert_eq!(c.observe(20, Some(1_000_000_020)), Wake::No);
    // Wall time steps 5 s.
    assert_eq!(c.observe(30, Some(1_005_000_030)), Wake::Seal);
    assert!(c.probe_due);
    assert_eq!(c.epoch, 1);
    let before = c.cuts.pop_front().expect("sealed at the break");
    assert_eq!((before.epoch, before.runs.len()), (0, 1));
    send(&mut c, id, "v", sent(1, 1), 40);
    assert_eq!(cut(&mut c, 50).epoch, 1);
}

#[test]
fn a_track_is_listed_until_publish_done() {
    let (mut c, id) = collector();
    send(&mut c, id, "v", sent(1, 0), 1);
    assert_eq!(cut(&mut c, 10).tracks.len(), 1);
    // No handoff, but the track is still published: listed.
    let idle = cut(&mut c, 20);
    assert_eq!((idle.tracks.len(), idle.runs.len()), (1, 0));
    c.event(id, Some((&NS[..], &b"v"[..])), EventKind::PublishDone, Some(0), 25).unwrap();
    assert_eq!(cut(&mut c, 30).tracks.len(), 1, "named by the event");
    assert!(!c.cut(40, false), "nothing left to seal");
}

#[test]
fn a_cleared_flow_ends_its_open_run() {
    let (mut c, id) = collector();
    send(&mut c, id, "v", sent(1, 0), 1);
    c.event(id, Some((&NS[..], &b"v"[..])), EventKind::StreamReset, Some(3), 2).unwrap();
    send(&mut c, id, "v", sent(1, 1), 3);
    let iv = cut(&mut c, 10);
    assert_eq!(iv.runs.len(), 2);
    assert_eq!(iv.clears.len(), 1);
    assert!(iv.runs[0].order < iv.clears[0].0 && iv.clears[0].0 < iv.runs[1].order);
}

#[test]
fn names_past_moqt_limits_are_refused() {
    let (mut c, id) = collector();
    let ns: Vec<&[u8]> = vec![b"x"; MAX_NAMESPACE_FIELDS + 1];
    assert_eq!(c.object_sent(id, &ns, b"v", sent(1, 0), 1), Err(Refused::Input));
    let long = vec![b'a'; MAX_FULL_NAME_BYTES + 1];
    assert_eq!(c.object_sent(id, &NS, &long, sent(1, 0), 1), Err(Refused::Input));
    let empty: &[&[u8]] = &[];
    assert!(c.object_sent(id, empty, b"", sent(1, 0), 1).is_ok());
    assert_eq!(c.rejected, 2);
}

fn head() -> Head {
    Head {
        source: "enc".into(),
        instance_id: "0".repeat(32),
        start: (0, 1_700_000_000_000),
        monitor_name: "moqtap-monitor",
        monitor_version: "0",
    }
}

#[test]
fn packed_bodies_stay_under_the_byte_seal() {
    let (mut c, id) = collector();
    for i in 0..20_000u64 {
        send(&mut c, id, "v", sent(i / 500, (i % 500) * 2), i as i64 * 3_000);
    }
    assert!(c.cuts.len() >= 2);
    let mut packer = Packer::new(head(), None);
    while let Some(iv) = c.cuts.pop_front() {
        let s = packer.pack(iv, None, Timing::Object);
        assert!(gz_len(&s) <= SEAL_BYTES, "{}", gz_len(&s));
        assert!(s.raw_len > SEAL_BYTES / 2, "{}", s.raw_len);
    }
}

/// One-object groups, `per_sec` a second for `n` groups, on track `a`.
fn one_object_groups(c: &mut Collector, id: u64, first: u64, n: u64, per_sec: u64, t0: i64) {
    for i in 0..n {
        let h = Handoff {
            starts_group: true,
            opens_subgroup: true,
            ends_group: true,
            ..sent(first + i, 0)
        };
        send(c, id, "a", h, t0 + (i * 1_000_000 / per_sec) as i64);
    }
}

#[test]
fn without_a_target_every_group_is_reported() {
    let (mut c, id) = collector();
    one_object_groups(&mut c, id, 0, 1800, 120, 0);
    c.cut(15_000_000, false);
    let mut packer = Packer::new(head(), None);
    let mut kept = 0;
    while let Some(iv) = c.cuts.pop_front() {
        let s = packer.pack(iv, None, Timing::Object);
        assert_eq!(s.batch.smp, None);
        assert!(s.batch.tracks.iter().all(|t| t.k == 0 && t.xg.is_empty()));
        kept = s.batch.tail.conn[0].1;
    }
    assert_eq!(kept, 1800);
}

#[test]
fn a_target_measures_from_the_first_handoff_or_the_body_start_to_the_seal() {
    let (mut c, id) = collector();
    // 240 groups at 120 a second from 1 ms, sealed at 2 s: about 120 a
    // second over the body, k 1 under a target of 30.
    one_object_groups(&mut c, id, 5_000, 240, 120, 1_000);
    let mut packer = Packer::new(head(), Some(30));
    let s = packer.pack(cut(&mut c, 2_000_000), None, Timing::Object);
    let t = &s.batch.tracks[0];
    let below: Vec<u64> = (5_000..5_240).filter(|&g| level(t.tk, g) < 1).collect();
    assert_eq!((s.batch.smp, t.k), (Some(30), 1));
    assert_eq!(t.xg, below);
    // A burst of 60 groups in the last 100 ms of the next 2 s body, the
    // track listed before: 30 a second over the whole body, under 9/8 of
    // the target, so k falls back to 0.
    one_object_groups(&mut c, id, 6_000, 60, 600, 3_900_000);
    let s = packer.pack(cut(&mut c, 4_000_000), None, Timing::Object);
    assert_eq!(s.batch.tracks[0].k, 0);
}

#[test]
fn a_track_new_to_the_body_measures_from_its_first_handoff() {
    use crate::sampling::{body_k, BodyGroups, LEVELS};
    let (mut c, id) = collector();
    // The same burst in the track's first body, from 0: 600 a second from
    // its first handoff, 30 a second over the whole body.
    one_object_groups(&mut c, id, 6_000, 60, 600, 1_900_000);
    let mut packer = Packer::new(head(), Some(30));
    let s = packer.pack(cut(&mut c, 2_000_000), None, Timing::Object);
    let t = &s.batch.tracks[0];
    let mut by_level = [0u32; LEVELS];
    for g in 6_000..6_060 {
        by_level[usize::from(level(t.tk, g))] += 1;
    }
    let k_over = |span_us| body_k(&BodyGroups { by_level: &by_level, span_us }, 0, 30);
    assert_eq!(k_over(2_000_000), 0);
    assert!(t.k > 0);
    assert_eq!(t.k, k_over(100_000));
    let below: Vec<u64> = (6_000..6_060).filter(|&g| level(t.tk, g) < t.k).collect();
    assert_eq!(t.xg, below);
}

#[test]
fn a_target_excludes_whole_groups_and_states_them() {
    let (mut c, id) = collector();
    // 100 one-object groups a second for 15 s.
    one_object_groups(&mut c, id, 0, 1500, 100, 0);
    c.cut(20_000_000, false);
    let mut packer = Packer::new(head(), Some(10));
    let (mut kept, mut excluded) = (0, 0);
    while let Some(iv) = c.cuts.pop_front() {
        let s = packer.pack(iv, None, Timing::Object);
        let t = &s.batch.tracks[0];
        let body_kept = s.batch.tail.conn[0].1 - kept;
        kept = s.batch.tail.conn[0].1;
        excluded += t.xg.len() as u64;
        assert!(t.xg.iter().all(|&g| level(t.tk, g) < t.k));
        if body_kept + t.xg.len() as u64 >= 500 {
            assert!(t.k >= 2, "k {}", t.k);
        }
    }
    assert!(excluded > 1000, "{excluded}");
    assert_eq!(kept + excluded, 1500, "every group is kept or stated");
}

#[test]
fn rseq_and_seq_run_on_across_bodies() {
    let (mut c, id) = collector();
    let mut packer = Packer::new(head(), None);
    let mut next = 0;
    for b in 0..3u64 {
        send(&mut c, id, "v", sent(b, 0), b as i64 * 100);
        let s = packer.pack(cut(&mut c, b as i64 * 100 + 50), None, Timing::Object);
        assert_eq!(s.seq, b);
        assert_eq!(s.batch.start.is_some(), b == 0, "start in the first body only");
        let first: u64 = s
            .preamble
            .split("\"em\":[[")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(first, next);
        let n = s.batch.tail.last_rseq.unwrap() + 1 - first;
        next = first + n;
        assert_eq!(s.batch.tail.conn, [(id, b + 1, (b + 1) * 10)]);
    }
}

#[test]
fn group_timing_writes_no_dt() {
    let body = |timing: Timing| {
        let (mut c, id) = collector();
        for o in 0..3 {
            send(&mut c, id, "v", sent(1, o), 1_000 * (o as i64 + 1));
        }
        Packer::new(head(), None).pack(cut(&mut c, 10_000), None, timing)
    };
    let (object, group) = (body(Timing::Object), body(Timing::Group));
    assert_eq!(object.batch.timing, Timing::Object);
    assert_eq!(group.batch.timing, Timing::Group);
    assert_eq!(object.records.len(), group.records.len() + 2, "two one-byte dt fewer");
}

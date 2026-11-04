//! Ingest's golden v2 source bodies, rebuilt with this crate's encoder from
//! the same inputs: every accepted body must be byte-identical. The goldens
//! are not gzipped, so the whole body is compared. `track-keys.json` pins
//! `track_key` and the sampling level.

use std::path::PathBuf;

use crate::sampling::{body_k, level, BodyGroups, LEVELS};
use crate::wire::{
    body, canonical_track_bytes, frames, hex, preamble_json, record_frames, track_key, AppOffset,
    Batch, Clk, ClockSample, ConnRec, EventKind, MarkIn, MarkKind, PaceIn, PevIn, Record, RunIn,
    Seal, Tail, TrackRec,
};
use crate::Timing;

const SOURCE: &str = "enc-fra-1";
const INSTANCE: &str = "5f0c2a9e7b1d4e3fa6c8b0d2e4f6a8c1";
const BASE: i64 = 7_200_000_000;
const SEAL_MS: u64 = 15_000;
const U64: u64 = u64::MAX;
const RELAY: &str = "https://relay-a.example.net/moq?token=never-stored";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source/v2")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(format!("{name}.bin"))).expect("fixture")
}

fn clk() -> Clk {
    Clk {
        base_us: BASE,
        epoch: 0,
        res_us: 1,
        sample: Some(ClockSample {
            o_us: 1_761_696_000_000_000 - BASE + 41_500,
            r_us: 18_250,
            at_us: BASE - 2_000_000,
            pop: Some("FRA".into()),
        }),
        app: None,
    }
}

fn track(ns: &[&[u8]], name: &[u8], k: u8) -> TrackRec {
    let ns: Vec<Vec<u8>> = ns.iter().map(|f| f.to_vec()).collect();
    TrackRec {
        tk: track_key(&ns, name),
        ns,
        name: name.to_vec(),
        named: true,
        k,
        span: None,
        xg: Vec::new(),
    }
}

fn video() -> TrackRec {
    track(&[b"example.com", b"live"], b"video", 0)
}

fn audio() -> TrackRec {
    track(&[b"example.com", b"live"], b"audio", 0)
}

fn conn(c: u64, draft: u64, relay: &str) -> ConnRec {
    ConnRec { c, draft: Some(draft), relay: relay.into() }
}

/// A connection whose relay is written as the monitor writes a connection URL.
fn conn_to(c: u64, draft: u64, url: &str) -> ConnRec {
    conn(c, draft, &crate::relay::relay_endpoint(url).expect("relay URL"))
}

struct Spec {
    seq: u64,
    first: u64,
    conns: Vec<ConnRec>,
    tracks: Vec<TrackRec>,
    records: Vec<Record>,
    clk: Clk,
    tail: Option<Tail>,
    is_final: bool,
    gdec: Vec<(u64, usize, u64)>,
    start: Option<(i64, i64)>,
    smp: Option<u32>,
    seal: Option<Seal>,
    timing: Timing,
}

impl Spec {
    fn new(conns: Vec<ConnRec>, tracks: Vec<TrackRec>, records: Vec<Record>) -> Self {
        Spec {
            seq: 0,
            first: 0,
            conns,
            tracks,
            records,
            clk: clk(),
            tail: None,
            is_final: false,
            gdec: Vec::new(),
            start: None,
            smp: None,
            seal: None,
            timing: Timing::Object,
        }
    }

    fn build(self) -> Vec<u8> {
        let n = self.records.len() as u64;
        let tail = self
            .tail
            .unwrap_or(Tail { last_rseq: (self.first + n).checked_sub(1), ..Tail::default() });
        let batch = Batch {
            source: SOURCE.into(),
            instance_id: INSTANCE.into(),
            seq: self.seq,
            is_final: self.is_final,
            monitor_name: "moqtap-reference",
            monitor_version: "2.0.0",
            tail,
            conns: self.conns,
            tracks: self.tracks,
            gdec: self.gdec,
            start: self.start,
            smp: self.smp,
            timing: self.timing,
        };
        let seal = self.seal.unwrap_or(Seal {
            seq: self.seq,
            from_us: BASE + self.seq as i64 * SEAL_MS as i64 * 1000,
            through_us: BASE + (self.seq as i64 + 1) * SEAL_MS as i64 * 1000,
            ms: SEAL_MS,
        });
        let em = if n > 0 { vec![(self.first, n)] } else { Vec::new() };
        let records = record_frames(&self.records, BASE, self.first, self.timing);
        body(&preamble_json(INSTANCE, &em, &seal), &frames(&batch, &self.clk, &records), false)
    }
}

/// `t0 + i * step`, floored, as the reference writer computes it.
fn times(t0: f64, step: f64, n: usize) -> Vec<i64> {
    (0..n).map(|i| (t0 + i as f64 * step).floor() as i64).collect()
}

fn ids(from: u64, n: u64) -> Vec<u64> {
    (from..from + n).collect()
}

fn run(
    c: u64,
    ti: usize,
    g: u64,
    sub: Option<u64>,
    ids: Vec<u64>,
    times: Vec<i64>,
    b: u64,
) -> RunIn {
    let n = ids.len() as u64;
    let sizes = (0..n).map(|i| if i < n - 1 { b / n } else { b - (n - 1) * (b / n) }).collect();
    let ends = times.clone();
    RunIn {
        cont: false,
        fo: false,
        eog: false,
        gs: false,
        c,
        ti,
        g,
        sub,
        ids,
        times,
        ends,
        sizes,
        b,
    }
}

/// The payload bytes of the `basic` video run's eight objects, 41,210 in all.
const VIDEO_SIZES: [u64; 8] = [12_000, 4_100, 4_000, 4_100, 4_300, 4_210, 4_300, 4_200];

fn base(off: f64) -> f64 {
    BASE as f64 + off
}

fn check(name: &str, built: Vec<u8>) {
    let want = fixture(name);
    if built != want {
        let at = built
            .iter()
            .zip(&want)
            .position(|(a, b)| a != b)
            .unwrap_or(built.len().min(want.len()));
        let show = |b: &[u8]| {
            String::from_utf8_lossy(&b[at.saturating_sub(40)..(at + 80).min(b.len())]).into_owned()
        };
        panic!("{name}: differs at byte {at}\n built: {}\n  want: {}", show(&built), show(&want));
    }
}

#[test]
fn basic() {
    check("basic", basic_spec(Timing::Object).build());
}

#[test]
fn group_timing() {
    check("group-timing", basic_spec(Timing::Group).build());
}

fn basic_spec(timing: Timing) -> Spec {
    let mut v = video();
    v.span = Some((BASE + 1_000, BASE + 300_000));
    let mut a = audio();
    a.span = Some((BASE + 2_000, BASE + 242_000));
    let mut s = Spec::new(
        vec![conn(0, 14, RELAY)],
        vec![v, a],
        vec![
            Record::Pev(PevIn {
                c: 0,
                ti: None,
                e: EventKind::ConnOpen,
                code: None,
                at_us: BASE - 3_000_000,
            }),
            Record::Runs(vec![
                RunIn {
                    gs: true,
                    fo: true,
                    eog: true,
                    ends: times(base(2_500.4), 33_333.3, 8),
                    sizes: VIDEO_SIZES.to_vec(),
                    ..run(0, 0, 100, Some(0), ids(0, 8), times(base(1_000.4), 33_333.3, 8), 41_210)
                },
                RunIn {
                    gs: true,
                    ..run(0, 1, 100, None, ids(0, 13), times(base(2_000.9), 20_000.0, 13), 2_080)
                },
                RunIn {
                    gs: true,
                    fo: true,
                    ..run(0, 0, 101, Some(0), ids(0, 2), times(base(267_667.0), 33_333.3, 2), 9_870)
                },
            ]),
            Record::Marks(vec![MarkIn {
                kind: MarkKind::Eot,
                c: 0,
                ti: 0,
                g: 101,
                o: 2,
                n: 0,
                t: BASE + 301_000,
            }]),
            Record::Paces(vec![
                PaceIn { c: 0, ti: 0, first: vec![(69, 1)], later: vec![(71, 7), (72, 1)] },
                PaceIn { c: 0, ti: 1, first: vec![], later: vec![(62, 12)] },
            ]),
        ],
    );
    s.start = Some((BASE - 5_000_000, 1_761_696_055_000));
    s.timing = timing;
    s
}

#[test]
fn names_as_bytes() {
    let tracks = vec![
        track(&[b"example.com"], &[0xff, 0xfe, 0x00, 0x80], 0),
        track(&[b"example.com"], b"", 0),
        track(&[b"", b"x"], b"y", 0),
        track(&[], b"", 0),
    ];
    let runs = (0..4)
        .map(|ti| run(0, ti, 7, Some(0), vec![0], vec![BASE + 500 + ti as i64 * 100], 1))
        .collect();
    check(
        "names-as-bytes",
        Spec::new(vec![conn(0, 14, RELAY)], tracks, vec![Record::Runs(runs)]).build(),
    );
}

#[test]
fn zero_length_normal() {
    let conns = vec![
        conn_to(0, 10, "https://relay-a.example.net"),
        conn_to(1, 14, "https://relay-b.example.net"),
        conn_to(2, 22, "moqt://relay-c.example.net:4443"),
    ];
    let runs = (0..3u64)
        .flat_map(|c| {
            [
                run(c, 0, 9, Some(1), ids(0, 3), times(base(100.0 + c as f64), 1_000.0, 3), 0),
                run(c, 0, 9, None, vec![3], vec![BASE + 4_000 + c as i64], 0),
            ]
        })
        .collect();
    check("zero-length-normal", Spec::new(conns, vec![video()], vec![Record::Runs(runs)]).build());
}

#[test]
fn negative_dt() {
    let t = |off: f64| base(off).floor() as i64;
    let mut s = Spec::new(
        vec![conn(0, 14, RELAY)],
        vec![video()],
        vec![Record::Runs(vec![
            run(
                0,
                0,
                1,
                Some(0),
                ids(0, 4),
                vec![t(50_000.0), t(49_950.5), t(50_301.0), t(40_000.0)],
                40,
            ),
            run(0, 0, 2, Some(0), ids(0, 2), vec![t(10_000.99), t(9_999.0)], 20),
        ])],
    );
    s.clk.app = Some(AppOffset {
        o_us: 1_761_696_000_000_000 - BASE,
        e_us: 2_500,
        at_us: BASE - 1_000_000,
    });
    check("negative-dt", s.build());
}

#[test]
fn u64_ids() {
    let mut s = Spec::new(
        vec![conn_to(7, 22, "moqt://relay-a.example.net/")],
        vec![video()],
        vec![Record::Runs(vec![
            run(
                7,
                0,
                U64,
                Some(1 << 63),
                vec![U64 - 3, U64 - 1, U64],
                times(base(1.0), 10.0, 3),
                3,
            ),
            RunIn {
                gs: true,
                ..run(7, 0, 0, Some(0), vec![0, 5, 6, 40], times(base(100.0), 10.0, 4), 4)
            },
            run(7, 0, 5, Some(0), vec![0], vec![BASE + 200], 1),
            run(7, 0, 3, Some(0), vec![2], vec![BASE + 300], 1),
            run(7, 0, 3, None, vec![4, 9, U64], times(base(400.0), 10.0, 3), 3),
        ])],
    );
    s.gdec = vec![(7, 0, 2)];
    check("u64-ids", s.build());
}

#[test]
fn sampled_cont() {
    let mut a = track(&[b"example.com", b"live"], b"audio", 2);
    a.span = Some((BASE + 60_000_000, BASE + 74_990_000));
    a.xg = vec![1001, 1002, 1004, 1003, 1100];
    let mut s = Spec::new(
        vec![conn(0, 14, RELAY)],
        vec![a],
        vec![Record::Runs(vec![
            RunIn {
                gs: true,
                cont: true,
                ..run(0, 0, 1000, None, vec![0], vec![BASE + 60_000_000], 160)
            },
            RunIn { gs: true, ..run(0, 0, 1005, None, vec![0], vec![BASE + 60_050_000], 160) },
        ])],
    );
    s.seq = 4;
    s.first = 51;
    s.gdec = vec![(0, 0, 1)];
    s.smp = Some(4);
    check("sampled-cont", s.build());
}

const HIGH_RATE_GROUPS: u64 = 240;
const HIGH_RATE_STEP_US: i64 = 8_333;
const HIGH_RATE_THROUGH: i64 = BASE + 2_000_000;

/// 240 one-object groups at 120 a second, in a body sealed after 2 s, under
/// `target`: k from this crate's rule over the first handoff to the seal.
fn high_rate(target: Option<u32>) -> (Vec<u8>, u8, usize) {
    let mut v = track(&[b"example.com", b"live"], b"video-120", 0);
    let t = |i: u64| BASE + 1_000 + i as i64 * HIGH_RATE_STEP_US;
    let groups: Vec<u64> = (0..HIGH_RATE_GROUPS).map(|i| 5_000 + i).collect();
    let mut by_level = [0u32; LEVELS];
    for &g in &groups {
        by_level[usize::from(level(v.tk, g))] += 1;
    }
    let span_us = HIGH_RATE_THROUGH - t(0);
    v.k = target.map_or(0, |tg| body_k(&BodyGroups { by_level: &by_level, span_us }, 0, tg));
    v.span = Some((t(0), t(HIGH_RATE_GROUPS - 1)));
    v.xg = groups.iter().copied().filter(|&g| level(v.tk, g) < v.k).collect();
    let (k, excluded) = (v.k, v.xg.len());
    let runs = groups
        .iter()
        .enumerate()
        .filter(|(_, &g)| level(v.tk, g) >= k)
        .map(|(i, &g)| RunIn {
            gs: true,
            fo: true,
            eog: true,
            ..run(0, 0, g, Some(0), vec![0], vec![t(i as u64)], 1_200)
        })
        .collect();
    let mut s = Spec::new(vec![conn(0, 14, RELAY)], vec![v], vec![Record::Runs(runs)]);
    s.smp = target;
    s.seal = Some(Seal { seq: 0, from_us: BASE, through_us: HIGH_RATE_THROUGH, ms: 5_000 });
    (s.build(), k, excluded)
}

#[test]
fn unsampled_high_rate() {
    let (built, k, excluded) = high_rate(None);
    assert_eq!((k, excluded), (0, 0));
    check("unsampled-high-rate", built);
}

#[test]
fn sampled_target() {
    let (built, k, excluded) = high_rate(Some(30));
    assert_eq!((k, excluded), (1, 121));
    check("sampled-target", built);
}

#[test]
fn names_elided() {
    let mut v = video();
    v.named = false;
    v.span = Some((BASE + 45_001_000, BASE + 45_001_000));
    let mut a = audio();
    a.span = Some((BASE + 45_002_000, BASE + 45_002_000));
    let mut s = Spec::new(
        vec![conn(0, 14, RELAY)],
        vec![v, a],
        vec![Record::Runs(vec![
            RunIn {
                gs: true,
                fo: true,
                ..run(0, 0, 400, Some(0), vec![0], vec![BASE + 45_001_000], 5_000)
            },
            RunIn { gs: true, ..run(0, 1, 400, None, vec![0], vec![BASE + 45_002_000], 160) },
        ])],
    );
    s.seq = 3;
    s.first = 40;
    check("names-elided", s.build());
}

#[test]
fn final_unmapped() {
    let mut s = Spec::new(vec![conn(0, 14, RELAY)], vec![video()], vec![Record::End("shutdown")]);
    s.seq = 9;
    s.first = 120;
    s.is_final = true;
    s.clk = Clk {
        base_us: BASE,
        epoch: 1,
        res_us: 1,
        sample: None,
        app: Some(AppOffset {
            o_us: 1_761_696_000_000_000 - BASE,
            e_us: 4_000,
            at_us: BASE + 9_000_000,
        }),
    };
    s.tail = Some(Tail {
        last_rseq: Some(120),
        pre_drop_records: 2,
        pre_drop_objects: 31,
        conn: vec![(0, 4_812, 3_901_224)],
    });
    check("final-unmapped", s.build());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

#[test]
fn track_keys_and_levels() {
    let text = std::fs::read_to_string(dir().join("track-keys.json")).expect("track-keys.json");
    let golden: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let cases = golden["cases"].as_array().expect("cases");
    assert!(cases.len() >= 6);
    for c in cases {
        let ns: Vec<Vec<u8>> = c["ns"]
            .as_array()
            .expect("ns")
            .iter()
            .map(|f| unhex(f.as_str().expect("hex")))
            .collect();
        let name = unhex(c["name"].as_str().expect("name"));
        assert_eq!(hex(&canonical_track_bytes(&ns, &name)), c["canonical"].as_str().unwrap());
        let tk = track_key(&ns, &name);
        assert_eq!(format!("{tk:016x}"), c["tk"].as_str().unwrap());
        for l in c["levels"].as_array().expect("levels") {
            let g: u64 = l[0].as_str().expect("group").parse().expect("u64");
            assert_eq!(u64::from(level(tk, g)), l[1].as_u64().unwrap(), "{tk:016x} {g}");
        }
    }
}

#[test]
fn every_accepted_golden_is_rebuilt() {
    let text = std::fs::read_to_string(dir().join("manifest.json")).expect("manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let accepted: Vec<&str> = manifest["fixtures"]
        .as_array()
        .expect("fixtures")
        .iter()
        .filter(|f| f["expect"]["ok"] == true)
        .map(|f| f["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        accepted,
        [
            "basic",
            "names-as-bytes",
            "zero-length-normal",
            "negative-dt",
            "u64-ids",
            "sampled-cont",
            "unsampled-high-rate",
            "sampled-target",
            "names-elided",
            "final-unmapped",
            "group-timing"
        ]
    );
}

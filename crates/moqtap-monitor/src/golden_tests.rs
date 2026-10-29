//! Ingest's golden source bodies, rebuilt with this crate's encoder from
//! the same inputs: the frame streams must be byte-identical. Gzip output is
//! not compared, since two compressors may differ; the frames under it are.

use std::io::Read as _;
use std::path::PathBuf;

use crate::wire::{
    encode_frames, BodySpec, Clock, DataRec, EventKind, GrpRow, Head, IdForm, ObjRow, PevRec,
    RelayRec, TrackRec, PREAMBLE_BYTES,
};

const T0_US: i64 = 1_761_696_000_000_000;
const WALL_MS: u64 = 1_761_696_060_000;
const INSTANCE: &str = "5f0c2a9e7b1d4e3fa6c8b0d2e4f6a8c1";
const SOURCE: &str = "enc-fra-1";
const CLOCK: Clock = Clock { o: -41.5, r: 18.0, n: 6, a: 37.0 };

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source")
}

fn manifest() -> serde_json::Value {
    let text = std::fs::read_to_string(dir().join("manifest.json")).expect("manifest.json");
    serde_json::from_str(&text).expect("manifest is JSON")
}

fn entry(name: &str) -> serde_json::Value {
    manifest()["fixtures"]
        .as_array()
        .expect("fixtures")
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not in the manifest"))
        .clone()
}

/// The fixture's frame stream: preamble stripped, gunzipped when flagged.
fn fixture_frames(name: &str) -> Vec<u8> {
    let body = std::fs::read(dir().join(format!("{name}.bin"))).expect("fixture");
    assert_eq!(&body[..4], b"MQTC");
    assert_eq!(body[4], 1);
    let rest = &body[PREAMBLE_BYTES..];
    if body[5] & 1 == 1 {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(rest).read_to_end(&mut out).expect("gzip");
        out
    } else {
        rest.to_vec()
    }
}

fn ns() -> Vec<String> {
    vec!["live".into(), "channel-7".into()]
}

fn head() -> Head<'static> {
    Head {
        ts: 720_000,
        wall: WALL_MS,
        per_object: false,
        source: SOURCE,
        instance_id: INSTANCE,
        seq: 12,
        is_final: false,
        lost: &[],
        dropped: 0,
        clock: Some(CLOCK),
        monitor_name: "moqtap-reference",
        monitor_version: "1.0.0",
    }
}

fn relay(c: usize, url: &str) -> RelayRec<'_> {
    RelayRec { c, relay: url, draft: Some(14), open_ts: None, close_ts: None, close_code: None }
}

/// A 2 s GOP video track and a 20 ms audio track, `count` groups each from `g0`.
fn group_rows(c: usize, count: i128, g0: i128, step: i128, fo: u64) -> Vec<(GrpRow, i128)> {
    let mut rows = Vec::new();
    for i in 0..count {
        let send = T0_US + i as i64 * 2_000_000 + c as i64 * 150;
        let video = GrpRow {
            c,
            tr: 1,
            g: 0,
            fo,
            send_us: send,
            span_us: 1_966_667,
            objects: 60,
            bytes: 812_000 + i as u64 * 17,
        };
        rows.push((video, g0 + i * step));
        let audio = GrpRow {
            c,
            tr: 2,
            g: 0,
            fo: 0,
            send_us: send + 40,
            span_us: 1_980_000,
            objects: 100,
            bytes: 32_000,
        };
        rows.push((audio, g0 * 100 + i * step));
    }
    rows
}

fn set_g(rows: Vec<(GrpRow, i128)>) -> Vec<GrpRow> {
    rows.into_iter().map(|(r, g)| GrpRow { g: u64::try_from(g).expect("id"), ..r }).collect()
}

/// mulberry32, as the fixtures' object rows are seeded.
fn random(seed: u32) -> impl FnMut() -> f64 {
    let mut a = seed;
    move || {
        a = a.wrapping_add(0x6d2b_79f5);
        let mut t = a;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

fn object_rows(count: usize, seed: u32) -> Vec<ObjRow> {
    let mut next = random(seed);
    let mut rows = Vec::new();
    let mut send = T0_US;
    let (mut g, mut o) = (5000u64, 0u64);
    for _ in 0..count {
        if o == 60 {
            g += 1;
            o = 0;
        }
        send += 16_000 + (next() * 2_000.0).floor() as i64;
        let bytes = 900 + (next() * 40_000.0).floor() as u64;
        rows.push(ObjRow { c: 0, tr: 1, g, o, bytes, send_us: send });
        o += 1;
    }
    rows
}

fn chunks<T: Clone>(rows: &[T]) -> Vec<Vec<T>> {
    rows.chunks(512).map(<[T]>::to_vec).collect()
}

fn object_body(n: usize, seed: u32) -> Vec<u8> {
    let objs = object_rows(n * 512, seed);
    let mut grp: Vec<GrpRow> = Vec::new();
    for r in &objs {
        match grp.last_mut() {
            Some(last) if last.g == r.g => {
                last.span_us = r.send_us - last.send_us;
                last.objects += 1;
                last.bytes += r.bytes;
            }
            _ => grp.push(GrpRow {
                c: 0,
                tr: 1,
                g: r.g,
                fo: 0,
                send_us: r.send_us,
                span_us: 0,
                objects: 1,
                bytes: r.bytes,
            }),
        }
    }
    let ns = ns();
    let mut data: Vec<DataRec> =
        chunks(&grp).into_iter().map(|r| DataRec::Grp(r, IdForm::Auto)).collect();
    data.extend(chunks(&objs).into_iter().map(|r| DataRec::Obj(r, IdForm::Auto)));
    encode_frames(&BodySpec {
        head: Head { per_object: true, ..head() },
        relays: vec![relay(0, "https://relay-a.example.net/moq")],
        tracks: vec![TrackRec { id: 1, ns: &ns, name: "video-1080p", k: 0 }],
        data,
        events: vec![],
        end: None,
    })
}

fn two_tracks(ns: &[String], audio_k: u8) -> Vec<TrackRec<'_>> {
    vec![
        TrackRec { id: 1, ns, name: "video-1080p", k: 0 },
        TrackRec { id: 2, ns, name: "audio-opus", k: audio_k },
    ]
}

fn check(name: &str, frames: Vec<u8>) {
    let want = fixture_frames(name);
    let e = entry(name);
    assert_eq!(e["frameBytes"].as_u64(), Some(want.len() as u64), "{name}: manifest");
    if frames != want {
        let at = frames.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(frames.len());
        let from = at.saturating_sub(40);
        panic!(
            "{name}: frames differ at byte {at}\n ours: {}\n want: {}",
            String::from_utf8_lossy(&frames[from..(at + 80).min(frames.len())]),
            String::from_utf8_lossy(&want[from..(at + 80).min(want.len())]),
        );
    }
}

#[test]
fn group_one_relay() {
    let ns = ns();
    let mut r = relay(0, "https://relay-a.example.net/moq?jwt=dropped");
    r.open_ts = Some(1200);
    check(
        "group-one-relay",
        encode_frames(&BodySpec {
            head: head(),
            relays: vec![r],
            tracks: two_tracks(&ns, 0),
            data: vec![DataRec::Grp(set_g(group_rows(0, 30, 1000, 1, 0)), IdForm::Auto)],
            events: vec![],
            end: None,
        }),
    );
}

#[test]
fn group_two_relays() {
    let ns = ns();
    let mut b = relay(7, "https://Relay-B.example.net:443/moq");
    b.close_ts = Some(59_000);
    b.close_code = Some(0);
    let rows: Vec<(GrpRow, i128)> = group_rows(0, 30, 1000, 1, 0)
        .into_iter()
        .chain(group_rows(7, 30, 1000, 1, 0))
        .map(|(r, g)| if r.tr == 2 { (r, g * 4) } else { (r, g) })
        .collect();
    check(
        "group-two-relays",
        encode_frames(&BodySpec {
            head: head(),
            relays: vec![relay(0, "https://relay-a.example.net/moq"), b],
            tracks: two_tracks(&ns, 2),
            data: vec![DataRec::Grp(set_g(rows), IdForm::Auto)],
            events: vec![PevRec {
                ts: 58_000,
                c: 7,
                tr: Some(1),
                e: EventKind::PublishDone,
                code: Some(0),
            }],
            end: None,
        }),
    );
}

#[test]
fn group_decimal_ids() {
    let ns = ns();
    let first = set_g(group_rows(0, 4, 4_611_686_018_427_387_000 / 100, 1, 0));
    let second: Vec<GrpRow> = group_rows(0, 4, (1i128 << 62) - 10, 1, 0)
        .into_iter()
        .filter(|(r, _)| r.tr == 1)
        .map(|(r, g)| GrpRow { g: g as u64, ..r })
        .collect();
    check(
        "group-decimal-ids",
        encode_frames(&BodySpec {
            head: head(),
            relays: vec![relay(0, "https://relay-a.example.net")],
            tracks: two_tracks(&ns, 0),
            data: vec![DataRec::Grp(first, IdForm::String), DataRec::Grp(second, IdForm::Auto)],
            events: vec![],
            end: None,
        }),
    );
}

#[test]
fn group_first_object() {
    let ns = ns();
    check(
        "group-first-object",
        encode_frames(&BodySpec {
            head: head(),
            relays: vec![relay(0, "https://relay-a.example.net")],
            tracks: two_tracks(&ns, 0),
            data: vec![DataRec::Grp(set_g(group_rows(0, 3, 1000, 1, 3)), IdForm::Auto)],
            events: vec![],
            end: None,
        }),
    );
}

#[test]
fn group_final() {
    let ns = ns();
    check(
        "group-final",
        encode_frames(&BodySpec {
            head: Head { is_final: true, lost: &[3, 9], dropped: 41, ..head() },
            relays: vec![relay(0, "https://relay-a.example.net")],
            tracks: two_tracks(&ns, 0),
            data: vec![DataRec::Grp(set_g(group_rows(0, 2, 1000, 1, 0)), IdForm::Auto)],
            events: vec![],
            end: Some("shutdown"),
        }),
    );
}

#[test]
fn group_bad_sample() {
    let ns = ns();
    let rows = [8u64, 9, 16]
        .iter()
        .enumerate()
        .map(|(i, &g)| GrpRow {
            c: 0,
            tr: 1,
            g,
            fo: 0,
            send_us: T0_US + i as i64 * 1000,
            span_us: 900,
            objects: 1,
            bytes: 100,
        })
        .collect();
    check(
        "group-bad-sample",
        encode_frames(&BodySpec {
            head: head(),
            relays: vec![relay(0, "https://relay-a.example.net")],
            tracks: vec![TrackRec { id: 1, ns: &ns, name: "video-1080p", k: 3 }],
            data: vec![DataRec::Grp(rows, IdForm::Auto)],
            events: vec![],
            end: None,
        }),
    );
}

#[test]
fn object_sealed() {
    let n = entry("object-sealed")["param"].as_u64().expect("param") as usize;
    check("object-sealed", object_body(n, 1));
}

#[test]
fn object_seal_exceeded() {
    let n = entry("object-seal-exceeded")["param"].as_u64().expect("param") as usize;
    check("object-seal-exceeded", object_body(n, 2));
}

#[test]
fn every_accepted_fixture_is_rebuilt_here() {
    let covered = [
        "group-one-relay",
        "group-two-relays",
        "group-decimal-ids",
        "group-first-object",
        "group-final",
        "group-bad-sample",
        "object-sealed",
        "object-seal-exceeded",
    ];
    for f in manifest()["fixtures"].as_array().expect("fixtures") {
        if f["expect"]["ok"] == true {
            let name = f["name"].as_str().expect("name");
            assert!(covered.contains(&name), "{name} has no rebuild test");
        }
    }
}

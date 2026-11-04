//! The monitor against a local mock of `POST /v1/source` and `/v1/clock`.

mod common;

use std::time::{Duration, Instant};

use common::{published, read_body, try_read_body, unique, Body, Mock, Reply};
use moqtap_monitor::{Delivery, Gap, Monitor, Rejected, Sent, State, Status, Timing};

const SOURCE: &str = "enc-test-1";
const KEY: &str = "mqt_sk_AAAAtestkeybody_testmac";
const NS: [&str; 2] = ["live", "channel-7"];
const UNIT: Duration = Duration::from_millis(20);

fn monitor(mock: &Mock) -> Monitor {
    builder(mock).start().expect("start")
}

fn builder(mock: &Mock) -> moqtap_monitor::MonitorBuilder {
    Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .test_timing(Duration::from_millis(150), UNIT)
}

fn long(mock: &Mock) -> Monitor {
    Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .test_timing(Duration::from_secs(3600), UNIT)
        .start()
        .expect("start")
}

fn bodies(mock: &Mock) -> Vec<Body> {
    let out: Vec<Body> = mock.uploads().iter().map(|c| read_body(&c.body, SOURCE)).collect();
    for c in out.iter().flat_map(|b| &b.conns) {
        let rest = c.relay.split_once("://").map_or("", |(_, r)| r);
        assert!(!rest.is_empty() && !rest.contains(['?', '#', '@']), "{}", c.relay);
    }
    out
}

/// Bodies ingest accepted once each, in seq order.
fn accepted(mock: &Mock) -> Vec<Body> {
    let mut out: Vec<Body> = Vec::new();
    for b in bodies(mock) {
        if !out.iter().any(|x| x.seq() == b.seq()) {
            out.push(b);
        }
    }
    out.sort_by_key(Body::seq);
    out
}

fn obj(group: u64, object: u64, size: u64) -> Sent {
    Sent {
        group,
        delivery: Delivery::Subgroup(0),
        object,
        size,
        starts_group: object == 0,
        opens_subgroup: object == 0,
        ends_group: false,
    }
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(tokio::time::Instant::now() < end, "{what} within 10 s");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn the_key_rides_only_in_the_header_and_every_body_reads_back() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let instance = m.instance_id().to_string();
    let relay = m.connection("https://user:pw@relay-a.example.net/moq?jwt=tok#x").expect("conn");
    relay.set_draft(14).expect("draft");
    let t0 = Instant::now();
    for g in 0..3u64 {
        for o in 0..5u64 {
            let at = t0 + Duration::from_millis(g * 1000 + o * 10);
            relay.object_sent(&NS, "video", obj(g, o, 100 + o), Some(at)).expect("report");
        }
    }
    relay.close(Some(0)).expect("close");
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.state, State::ShutDown);
    assert_eq!((stats.bodies_lost, stats.bodies_queued, stats.bytes_queued), (0, 0, 0));

    let captured = mock.captured();
    assert!(captured.iter().any(|c| c.uri == "/v1/clock"), "a clock probe at start");
    for c in &captured {
        assert_eq!(c.method, "POST");
        assert_eq!(c.header("authorization"), Some(format!("Bearer {KEY}").as_str()));
        assert!(c.header("origin").is_none() && c.header("sec-fetch-site").is_none());
        assert!(!String::from_utf8_lossy(&c.body).contains("mqt_sk_"));
        if c.uri == "/v1/clock" {
            assert!(c.body.is_empty());
            continue;
        }
        assert_eq!(c.uri, format!("/v1/source?i={instance}"));
        assert_eq!(c.header("content-type"), Some("application/octet-stream"));
        let body = read_body(&c.body, SOURCE);
        assert_eq!(c.header("idempotency-key"), body.batch["idempotencyKey"].as_str());
        assert_eq!(body.preamble["i"], instance.as_str());
    }

    let bodies = bodies(&mock);
    let seqs: Vec<u64> = bodies.iter().map(Body::seq).collect();
    assert_eq!(seqs, (0..bodies.len() as u64).collect::<Vec<_>>());
    assert!(bodies[0].batch["start"]["wall_ms"].as_i64().unwrap() > 1_700_000_000_000);
    assert!(bodies[1..].iter().all(|b| b.batch.get("start").is_none()));
    let last = bodies.last().unwrap();
    assert_eq!(last.batch["final"], true);
    assert_eq!(last.end.as_deref(), Some("shutdown"));

    // Bodies chain: seal intervals and record numbers.
    let mut next_rseq = 0;
    for w in bodies.windows(2) {
        assert_eq!(w[0].preamble["seal"]["through_us"], w[1].preamble["seal"]["from_us"]);
    }
    for b in &bodies {
        let mut r = b.rseqs.clone();
        r.sort_unstable();
        assert_eq!(r, (next_rseq..next_rseq + r.len() as u64).collect::<Vec<_>>());
        next_rseq += r.len() as u64;
    }

    let runs: Vec<_> = published(&bodies);
    assert_eq!(runs.len(), 3);
    for (g, (relay, track, group, ids)) in runs.iter().enumerate() {
        assert_eq!(relay, "https://relay-a.example.net/moq");
        assert_eq!(
            (track.as_slice(), *group, ids.clone()),
            (&b"video"[..], g as u64, vec![0, 1, 2, 3, 4])
        );
    }
    let all: Vec<_> = bodies.iter().flat_map(|b| b.runs.clone()).collect();
    assert!(all.iter().all(|r| r.gs && r.fo && r.b == 510 && r.q == [0, 100, 200, 300, 400]));
    assert!(all.iter().all(|r| r.os == [100, 101, 102, 103, 104] && r.de == [0; 5]));
    let events: Vec<_> = bodies.iter().flat_map(|b| b.events.clone()).collect();
    let kinds: Vec<_> = events.iter().map(|e| e["e"].as_str().unwrap().to_string()).collect();
    assert_eq!(kinds, ["conn_open", "conn_close"]);
    assert_eq!(events[1]["code"], 0);
    assert!(bodies.iter().flat_map(|b| &b.conns).all(|c| c.draft == Some(14)));
    let raw: Vec<u8> = mock.uploads().iter().flat_map(|c| c.body.clone()).collect();
    assert!(!String::from_utf8_lossy(&raw).contains("jwt"));
}

#[tokio::test]
async fn the_first_body_carries_a_clock_sample() {
    let mock = Mock::start().await;
    mock.set_clock_offset_ms(5_000.0);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), None).unwrap();
    m.shutdown(Duration::from_secs(5)).await;

    let first = &bodies(&mock)[0];
    let clk = &first.batch["clk"];
    let (o, r) = (clk["o_us"].as_i64().unwrap(), clk["r_us"].as_i64().unwrap());
    assert_eq!(clk["pop"], "FRA");
    assert_eq!(clk["epoch"], 0);
    assert!(clk["res_us"].as_u64().unwrap() >= 1);
    // Mono µs start at 0 when the monitor starts: the offset is ingest's
    // clock then, 5 s ahead of the wall clock.
    let start_us = first.batch["start"]["wall_ms"].as_i64().unwrap() * 1000;
    assert!((o - (start_us + 5_000_000)).abs() <= r / 2 + 3_000, "{clk}");
}

#[tokio::test]
async fn one_body_carries_every_relay_connection() {
    let mock = Mock::start().await;
    let m = long(&mock);
    let a = m.connection("https://relay-a.example.net").unwrap();
    let b = m.connection("moqt://relay-b.example.net:4443").unwrap();
    let t0 = Instant::now();
    for g in 0..4 {
        // Groups 250 ms apart: too slow to be sampled.
        let at = Some(t0 + Duration::from_millis(g * 250));
        a.object_sent(&NS, "video", obj(g, 0, 10), at).unwrap();
        b.object_sent(&NS, "video", obj(g, 0, 10), at).unwrap();
        b.object_sent(&NS, "audio", obj(g, 0, 10), at).unwrap();
    }
    m.shutdown(Duration::from_secs(5)).await;
    let bodies = bodies(&mock);
    assert_eq!(bodies.len(), 1);
    let origins: Vec<_> = bodies[0].conns.iter().map(|c| c.relay.as_str()).collect();
    assert_eq!(origins, ["https://relay-a.example.net/", "moqt://relay-b.example.net:4443"]);
    assert_eq!(bodies[0].runs.len(), 12);
    assert_eq!(bodies[0].tracks.len(), 2);
    let paces = &bodies[0].paces;
    assert_eq!(paces.len(), 3, "one per connection and track");
}

#[tokio::test]
async fn bodies_seal_at_32_kib_and_runs_continue_across_them() {
    let mock = Mock::start().await;
    let m = long(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let t0 = Instant::now();
    let mut x: u64 = 7;
    for i in 0..40_000u64 {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let at = t0 + Duration::from_micros(i * 16_000 + (x >> 54));
        let mut s = obj(i / 600, i % 600, 900 + (x >> 49));
        s.object = (i % 600) * 2;
        relay.object_sent(&NS, "video", s, Some(at)).unwrap();
    }
    let stats = m.shutdown(Duration::from_secs(10)).await;
    let bodies = bodies(&mock);
    assert!(bodies.len() >= 4, "{} bodies", bodies.len());
    assert_eq!(stats.bodies_sent, bodies.len() as u64);
    let mut objects = 0;
    let mut conts = 0;
    for b in &bodies {
        assert!(b.gz_bytes <= 32 * 1024, "{} B", b.gz_bytes);
        for r in &b.runs {
            objects += r.ids.len();
            conts += usize::from(r.cont);
            assert!(r.ids.windows(2).all(|w| w[1] > w[0]));
        }
    }
    assert_eq!(objects, 40_000);
    assert!(conts >= bodies.len() - 2, "a group split by a seal continues: {conts}");
    let last = bodies.last().unwrap();
    assert_eq!(last.batch["tail"]["conn"][0][1], 40_000);
}

#[tokio::test]
async fn names_are_bytes_ids_are_u64_and_statuses_are_marks() {
    let mock = Mock::start().await;
    let m = long(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.set_draft(22).unwrap();
    let ns: [&[u8]; 2] = [b"live", &[0xff, 0x00]];
    let name: &[u8] = &[0xfe, 0x80];
    let t0 = Instant::now();
    let top = Sent { group: u64::MAX, object: u64::MAX - 1, ..obj(0, 0, 0) };
    relay.object_sent(&ns, name, top, Some(t0)).unwrap();
    let next = Sent { object: u64::MAX, starts_group: false, opens_subgroup: false, ..top };
    relay.object_sent(&ns, name, next, Some(t0)).unwrap();
    let dg = Sent { delivery: Delivery::Datagram, ..obj(5, 3, 7) };
    relay.object_sent(&ns, name, dg, Some(t0 + Duration::from_secs(1))).unwrap();
    relay.status_sent(&ns, name, 5, 4, Status::EndOfGroup, None).unwrap();
    relay.gap_sent(&ns, name, 9, 0, Gap::PriorGroups(3)).unwrap();
    assert_eq!(
        relay.status_sent(&ns, name, 5, 4, Status::DoesNotExist, None),
        Err(Rejected::InvalidInput),
        "draft 22 has no Does Not Exist"
    );
    relay.publish_done(&ns, name, 0).unwrap();
    m.shutdown(Duration::from_secs(5)).await;

    let b = &bodies(&mock)[0];
    let t = &b.tracks[0];
    assert_eq!(
        (t.ns.clone(), t.name.clone()),
        (vec![b"live".to_vec(), vec![0xff, 0]], name.to_vec())
    );
    assert_eq!(b.runs[0].ids, [u64::MAX - 1, u64::MAX]);
    assert_eq!((b.runs[0].g, b.runs[0].sub, b.runs[0].b), (u64::MAX, Some(0), 0));
    assert_eq!((b.runs[1].sub, b.runs[1].ids.clone()), (None, vec![3]));
    let marks: Vec<_> = b.marks.iter().map(|m| (m.kind, m.g, m.o, m.n)).collect();
    assert_eq!(marks, [(0, 5, 4, None), (8, 9, 0, Some(3))]);
    assert!(b.events.iter().any(|e| e["e"] == "publish_done" && e["ti"] == 0));
}

#[tokio::test]
async fn a_status_reported_before_the_draft_is_known_still_reads() {
    let mock = Mock::start().await;
    let m = long(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(1, 0, 10), None).unwrap();
    relay.status_sent(&NS, "video", 1, 1, Status::DoesNotExist, None).unwrap();
    relay.set_draft(16).unwrap();
    relay.object_sent(&NS, "video", obj(2, 0, 10), None).unwrap();
    m.shutdown(Duration::from_secs(5)).await;

    let bodies = accepted(&mock);
    let marks: Vec<_> =
        bodies.iter().flat_map(|b| b.marks.iter().map(|m| (b.conns[0].draft, m.kind))).collect();
    assert_eq!(marks, [(None, 4)]);
    let runs: Vec<_> =
        bodies.iter().flat_map(|b| b.runs.iter().map(|r| (b.conns[0].draft, r.g))).collect();
    assert_eq!(runs, [(None, 1), (Some(16), 2)]);
}

#[tokio::test]
async fn a_refused_key_keeps_the_data_and_tries_again() {
    let mock = Mock::start().await;
    mock.script([Reply::status(401)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), None).unwrap();
    until("a refusal", || m.stats().state == State::Refused { status: 401 }).await;
    // Still collecting.
    relay.object_sent(&NS, "video", obj(1, 0, 1), None).unwrap();
    until("the retry accepted", || m.stats().bodies_sent >= 1).await;
    assert_eq!(m.stats().state, State::Running);
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.bodies_lost, 0);
    let up = mock.uploads();
    assert_eq!(up[0].body, up[1].body, "the same bytes again");
    let groups: Vec<u64> =
        accepted(&mock).iter().flat_map(|b| b.runs.iter().map(|r| r.g)).collect();
    assert_eq!(groups, [0, 1]);
}

#[tokio::test]
async fn a_503_and_a_429_are_retried_with_the_same_body() {
    let mock = Mock::start().await;
    let mut slow = Reply::status(429);
    slow.headers.push(("retry-after".into(), "2".into()));
    mock.script([Reply::status(503), slow]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), None).unwrap();
    let c = mock.wait_for(3, Duration::from_secs(10)).await;
    assert!(c.len() >= 3);
    assert_eq!(c[0].body, c[1].body);
    assert_eq!(c[1].body, c[2].body);
    assert_eq!(c[0].header("idempotency-key"), c[2].header("idempotency-key"));
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert!(stats.bodies_sent >= 1);
    assert_eq!(stats.bodies_lost, 0);
}

#[tokio::test]
async fn another_4xx_gives_the_body_up_and_the_gap_shows() {
    let mock = Mock::start().await;
    mock.script([Reply::status(413)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), None).unwrap();
    mock.wait_for(1, Duration::from_secs(5)).await;
    relay.object_sent(&NS, "video", obj(1, 0, 1), None).unwrap();
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.bodies_lost, 1);
    let bodies = bodies(&mock);
    let last = bodies.last().unwrap();
    // The record numbers of the lost body are below `last_rseq` and in no
    // accepted body.
    let first = last.preamble["em"][0][0].as_u64().unwrap();
    assert!(first > 0);
    assert!(last.batch["tail"]["last_rseq"].as_u64().unwrap() >= first);
}

#[tokio::test]
async fn with_buffering_off_a_failed_body_is_given_up_at_once() {
    let mock = Mock::start().await;
    mock.script([Reply::status(503)]);
    let m = builder(&mock).buffer_bytes(0).start().unwrap();
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), None).unwrap();
    until("the first body lost", || m.stats().bodies_lost == 1).await;
    relay.object_sent(&NS, "video", obj(1, 0, 1), None).unwrap();
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.bodies_lost, 1);
    assert!(stats.bodies_sent >= 1);
}

#[tokio::test]
async fn past_the_buffer_the_oldest_body_is_given_up() {
    let mock = Mock::start().await;
    mock.script((0..6).map(|_| Reply::status(503)));
    let m = builder(&mock).buffer_bytes(1).start().unwrap();
    let relay = m.connection("https://relay-a.example.net").unwrap();
    for g in 0..6 {
        relay.object_sent(&NS, "video", obj(g, 0, 1), None).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert!(stats.bodies_lost >= 1, "{stats:?}");
    assert_eq!(stats.bodies_queued, 0);
}

#[tokio::test]
async fn a_seal_directive_shortens_the_interval_until_it_lapses() {
    let mock = Mock::start().await;
    let mut d = Reply::status(202);
    d.body = r#"{"ok":true,"seal_ms":1000,"ttl_ms":60000}"#.into();
    mock.script([d]);
    let m = Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .test_timing(Duration::from_secs(3), UNIT)
        .start()
        .unwrap();
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let start = Instant::now();
    let mut g = 0;
    while mock.uploads().len() < 3 {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "sealed every second after the directive"
        );
        relay.object_sent(&NS, "video", obj(g, 0, 1), None).unwrap();
        g += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    m.shutdown(Duration::from_secs(5)).await;
    let ms: Vec<u64> =
        bodies(&mock).iter().map(|b| b.preamble["seal"]["ms"].as_u64().unwrap()).collect();
    assert_eq!(ms[0], 3_000);
    assert_eq!(ms[1], 1_000);
}

#[tokio::test]
async fn bad_input_is_refused_without_a_panic() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    assert!(m.connection("wss://relay.example").is_err());
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.set_draft(16).unwrap();
    let r = relay.object_sent(&NS, "video", obj(1 << 62, 0, 1), None);
    assert_eq!(r, Err(Rejected::InvalidInput));
    let r = relay.object_sent(&NS, "video", obj(0, 0, u64::MAX), None);
    assert_eq!(r, Err(Rejected::InvalidInput));
    let r = relay.object_sent(&[] as &[&str], "x".repeat(5000), obj(0, 0, 1), None);
    assert_eq!(r, Err(Rejected::InvalidInput));
    // A handoff time before the monitor started is a time like any other.
    let early = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), Some(early)).unwrap();
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.rejected, 3);
    let runs: Vec<_> = bodies(&mock).iter().flat_map(|b| b.runs.clone()).collect();
    assert_eq!(runs.len(), 1);
    assert!(runs[0].t0 < 0);
}

#[tokio::test]
async fn codes_past_2_53_are_refused_and_every_body_still_reads() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 10), None).unwrap();
    let big = 1u64 << 60;
    assert_eq!(relay.request_error(big), Err(Rejected::InvalidInput));
    assert_eq!(relay.stream_reset(&NS, "video", big), Err(Rejected::InvalidInput));
    assert_eq!(relay.set_draft(big), Err(Rejected::InvalidInput));
    relay.request_error(0x10).unwrap();
    assert_eq!(relay.close(Some(big)), Err(Rejected::InvalidInput));
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.rejected, 4);
    let events: Vec<_> = bodies(&mock).iter().flat_map(|b| b.events.clone()).collect();
    let errors: Vec<_> = events.iter().filter(|e| e["e"] == "request_error").collect();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["code"], 0x10);
    let close = events.iter().find(|e| e["e"] == "conn_close").expect("closed");
    assert!(close.get("code").is_none());
}

#[tokio::test]
async fn the_same_ids_twice_are_two_publications() {
    let mock = Mock::start().await;
    let m = long(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let t0 = Instant::now();
    for (i, g) in [7u64, 7, 3].into_iter().enumerate() {
        let at = Some(t0 + Duration::from_secs(i as u64));
        relay.object_sent(&NS, "video", obj(g, 0, 10), at).unwrap();
    }
    m.shutdown(Duration::from_secs(5)).await;
    let b = &bodies(&mock)[0];
    assert_eq!(b.runs.iter().map(|r| r.g).collect::<Vec<_>>(), [7, 7, 3]);
    assert_eq!(b.batch["gdec"], serde_json::json!([[0, 0, 1]]));
}

/// 240 one-object groups at 120 a second on `video`, then shutdown.
async fn high_rate(m: Monitor) {
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let t0 = Instant::now();
    for g in 0..240u64 {
        let s = Sent { ends_group: true, ..obj(g, 0, 1_000) };
        relay.object_sent(&NS, "video", s, Some(t0 + Duration::from_micros(g * 8_333))).unwrap();
    }
    m.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn every_group_is_reported_unless_a_sampling_target_is_set() {
    let mock = Mock::start().await;
    high_rate(long(&mock)).await;
    let bodies = accepted(&mock);
    assert!(bodies.iter().all(|b| b.batch.get("smp").is_none()));
    assert!(bodies.iter().flat_map(|b| &b.tracks).all(|t| t.k == 0 && t.xg.is_empty()));
    let groups: Vec<u64> = published(&bodies).into_iter().map(|(_, _, g, _)| g).collect();
    assert_eq!(groups, (0..240).collect::<Vec<_>>());

    let mock = Mock::start().await;
    let m = Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .test_timing(Duration::from_secs(3600), UNIT)
        .sample_target(30)
        .start()
        .expect("start");
    high_rate(m).await;
    let bodies = accepted(&mock);
    assert!(bodies.iter().all(|b| b.batch["smp"]["t"] == 30));
    let t = bodies.iter().flat_map(|b| &b.tracks).find(|t| t.span.is_some()).unwrap();
    assert!(t.k >= 1, "k {}", t.k);
    let mut groups: Vec<u64> = published(&bodies).into_iter().map(|(_, _, g, _)| g).collect();
    assert!(groups.iter().all(|g| !t.xg.contains(g)));
    groups.extend(&t.xg);
    groups.sort_unstable();
    assert_eq!(groups, (0..240).collect::<Vec<_>>(), "every group is kept or stated");
}

/// Whether each body uploaded, in seq order, carried the names of `video`.
fn named_video(mock: &Mock) -> Vec<bool> {
    accepted(mock)
        .iter()
        .filter_map(|b| b.tracks.iter().find(|t| !t.named || t.name == b"video"))
        .map(|t| t.named)
        .collect()
}

/// Objects on `video` until `n` bodies were accepted, one each.
async fn bodies_of_video(mock: &Mock, m: Monitor, n: usize) {
    let relay = m.connection("https://relay-a.example.net").unwrap();
    for g in 0..n as u64 {
        relay.object_sent(&NS, "video", obj(g, 0, 10), None).unwrap();
        until("a body accepted", || accepted(mock).len() > g as usize).await;
    }
    m.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn names_ride_until_a_body_carrying_them_is_accepted() {
    let mock = Mock::start().await;
    mock.script([Reply::status(503)]);
    bodies_of_video(&mock, monitor(&mock), 3).await;
    let named = named_video(&mock);
    assert!(named.len() >= 3);
    assert!(named[0] && named[1..].iter().all(|n| !n), "{named:?}");
    let bodies = accepted(&mock);
    assert!(published(&bodies).iter().all(|(_, name, ..)| name == b"video"));

    // The body carrying them is given up: the next one carries them again.
    let mock = Mock::start().await;
    mock.script([Reply::status(413)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 10), None).unwrap();
    until("the first body given up", || m.stats().bodies_lost == 1).await;
    drop(relay);
    bodies_of_video(&mock, m, 3).await;
    let named = named_video(&mock);
    assert!(named.len() >= 3);
    assert!(named[0] && named[1] && named[2..].iter().all(|n| !n), "{named:?}");
}

#[tokio::test]
async fn the_app_clock_is_stated_with_the_time_it_was_read() {
    let mock = Mock::start().await;
    let utc = |d: std::time::SystemTime| {
        d.duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as i64
    };
    let m = builder(&mock)
        .app_clock(move || Some((utc(std::time::SystemTime::now()) + 7_000_000, 250)))
        .start()
        .unwrap();
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(0, 0, 1), None).unwrap();
    m.shutdown(Duration::from_secs(5)).await;
    let first = &bodies(&mock)[0];
    let app = &first.batch["clk"]["app"];
    assert_eq!(app["e_us"], 250);
    let at_us = app["at_us"].as_i64().unwrap();
    let start_us = first.batch["start"]["wall_ms"].as_i64().unwrap() * 1000;
    // utc - mono at the read: the wall clock at start, 7 s ahead.
    let o = app["o_us"].as_i64().unwrap();
    assert!(at_us >= 0 && (o - (start_us + 7_000_000)).abs() < 50_000, "{app}");
}

async fn until_sent(m: &Monitor, n: u64) {
    until("bodies sent", || m.stats().bodies_sent >= n).await;
}

#[tokio::test]
async fn every_relay_is_reported_whatever_their_number() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let conns: Vec<_> = (0..70)
        .map(|i| m.connection(&format!("https://relay-{i:02}.example.net/moq")).unwrap())
        .collect();
    for c in &conns {
        c.object_sent(&NS, "video", obj(0, 0, 10), None).unwrap();
    }
    drop(conns);
    let stats = m.shutdown(Duration::from_secs(5)).await;

    let want: std::collections::BTreeSet<String> =
        (0..70).map(|i| format!("https://relay-{i:02}.example.net/moq")).collect();
    let bodies = bodies(&mock);
    let sent: std::collections::BTreeSet<String> =
        published(&bodies).into_iter().map(|(r, ..)| r).collect();
    assert_eq!(sent, want);
    assert!(bodies.iter().all(|b| b.conns.len() <= 32));
    assert_eq!(stats.dropped, 0);
}

#[tokio::test]
async fn an_object_handed_over_in_pieces_states_its_end() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let t0 = Instant::now();
    let end = t0 + Duration::from_micros(2_550);
    relay.object_sent_span(&NS, "video", obj(0, 0, 9_000), t0, end).unwrap();
    relay.object_sent(&NS, "video", obj(0, 1, 40), Some(t0 + Duration::from_millis(3))).unwrap();
    let back = relay.object_sent_span(&NS, "video", obj(0, 2, 1), end, t0);
    assert!(matches!(back, Err(Rejected::InvalidInput)), "{back:?}");
    drop(relay);
    m.shutdown(Duration::from_secs(5)).await;
    let runs: Vec<_> = bodies(&mock).into_iter().flat_map(|b| b.runs).collect();
    assert_eq!(runs.len(), 1);
    assert_eq!((runs[0].q.clone(), runs[0].de.clone()), (vec![0, 30], vec![25, 0]));
    assert_eq!((runs[0].os.clone(), runs[0].b), (vec![9_000, 40], 9_040));
}

fn timing_of(b: &Body) -> &str {
    b.batch.get("timing").and_then(|t| t.as_str()).unwrap_or("object")
}

#[tokio::test]
async fn the_clock_reply_lowers_timing_to_group() {
    let mock = Mock::start().await;
    mock.set_clock_body(r#"{"ok":true,"timing":"group"}"#);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    // The sender probes before its first upload: once a body is sent, the
    // clock reply is taken, and every later seal is at its timing.
    relay.object_sent(&NS, "video", obj(0, 9, 10), None).unwrap();
    until_sent(&m, 1).await;
    for o in 0..4 {
        relay.object_sent(&NS, "video", obj(1, o, 10), None).unwrap();
    }
    drop(relay);
    m.shutdown(Duration::from_secs(5)).await;
    assert!(!mock.clocks().is_empty());
    let later: Vec<_> =
        bodies(&mock).into_iter().filter(|b| b.runs.iter().any(|r| r.ids != [9])).collect();
    assert!(!later.is_empty());
    for b in &later {
        assert_eq!(timing_of(b), "group");
        assert!(b.runs.iter().all(|r| r.q == [0]), "{:?}", b.runs);
    }
    let ids = later.iter().flat_map(|b| &b.runs).filter(|r| r.ids != [9]);
    assert_eq!(ids.map(|r| r.ids.len()).sum::<usize>(), 4);
}

#[tokio::test]
async fn an_upload_reply_lowers_timing_and_never_raises_the_integrators() {
    let mock = Mock::start().await;
    mock.script([Reply { body: r#"{"ok":true,"timing":"group"}"#.into(), ..Reply::status(202) }]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(1, 0, 10), None).unwrap();
    relay.object_sent(&NS, "video", obj(1, 1, 10), None).unwrap();
    until_sent(&m, 1).await;
    relay.object_sent(&NS, "video", obj(2, 0, 10), None).unwrap();
    relay.object_sent(&NS, "video", obj(2, 1, 10), None).unwrap();
    drop(relay);
    m.shutdown(Duration::from_secs(5)).await;
    let first = bodies(&mock);
    assert_eq!(timing_of(&first[0]), "object");
    assert!(first[1..].iter().all(|b| timing_of(b) == "group"));

    let mock = Mock::start().await;
    mock.script([Reply { body: r#"{"ok":true,"timing":"object"}"#.into(), ..Reply::status(202) }]);
    let m = builder(&mock).timing(Timing::Group).start().expect("start");
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", obj(1, 0, 10), None).unwrap();
    until_sent(&m, 1).await;
    relay.object_sent(&NS, "video", obj(2, 0, 10), None).unwrap();
    drop(relay);
    m.shutdown(Duration::from_secs(5)).await;
    assert!(bodies(&mock).iter().all(|b| timing_of(b) == "group"));
}

/// The vendored goldens through this file's reader: it takes what ingest
/// takes and refuses what ingest refuses.
#[test]
fn the_test_reader_agrees_with_the_goldens() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source/v2");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    let mut checked = 0;
    for f in manifest["fixtures"].as_array().unwrap() {
        let body = std::fs::read(dir.join(f["file"].as_str().unwrap())).unwrap();
        let r = try_read_body(&body, "enc-fra-1");
        let name = f["name"].as_str().unwrap();
        if f["expect"]["ok"] == true {
            let b = r.unwrap_or_else(|e| panic!("{name}: {e}"));
            let want = &f["read"]["body"];
            let ids: Vec<u64> = b.runs.iter().flat_map(|r| r.ids.clone()).collect();
            let want_ids: Vec<u64> = want["runs"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|r| r["entries"].as_array().unwrap().clone())
                .flat_map(|e| match e["oid"].as_array() {
                    Some(o) => {
                        o.iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect::<Vec<u64>>()
                    }
                    None => {
                        let o0: u64 = e["o0"].as_str().unwrap().parse().unwrap();
                        (0..e["n"].as_u64().unwrap()).map(|i| o0 + i).collect()
                    }
                })
                .collect();
            assert_eq!(ids, want_ids, "{name}");
        } else {
            assert!(r.is_err(), "{name} reads, but ingest refuses it");
        }
        checked += 1;
    }
    assert_eq!(checked, 34);
    let _ = unique(&[1]);
}

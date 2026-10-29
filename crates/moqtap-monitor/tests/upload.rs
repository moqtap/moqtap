//! The monitor against a local mock of `POST /v1/source`.

mod common;

use std::time::{Duration, SystemTime};

use common::{read_body, Body, Mock, Reply};
use moqtap_monitor::{Detail, Monitor, Rejected, State, MAX_RELAYS_PER_MONTH};

const SOURCE: &str = "enc-test-1";
const KEY: &str = "mqt_sk_AAAAtestkeybody_testmac";
const NS: [&str; 2] = ["live", "channel-7"];

fn monitor(mock: &Mock) -> Monitor {
    builder(mock).start().expect("start")
}

fn builder(mock: &Mock) -> moqtap_monitor::MonitorBuilder {
    Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .seal_interval(Duration::from_millis(150))
}

fn bodies(mock: &Mock) -> Vec<Body> {
    mock.captured().iter().map(|c| read_body(&c.body, SOURCE)).collect()
}

#[tokio::test]
async fn the_key_rides_only_in_the_header_and_every_body_reads_back() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let instance = m.instance_id().to_string();
    let relay = m.connection("https://user:pw@relay-a.example.net/moq?jwt=tok#x").expect("conn");
    relay.set_draft(14).expect("draft");
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_761_696_000);
    for g in 0..3u64 {
        for o in 0..5u64 {
            let at = t0 + Duration::from_millis(g * 1000 + o * 10);
            relay.object_sent(&NS, "video", g, o, 100 + o, Some(at)).expect("report");
        }
    }
    relay.close(Some(0)).expect("close");
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.state, State::ShutDown);

    let captured = mock.captured();
    assert!(!captured.is_empty());
    for c in &captured {
        assert_eq!(c.method, "POST");
        assert_eq!(c.uri, format!("/v1/source?i={instance}"));
        assert!(!c.uri.contains("mqt_sk_"));
        assert_eq!(c.header("authorization"), Some(format!("Bearer {KEY}").as_str()));
        assert_eq!(c.header("content-type"), Some("application/octet-stream"));
        assert!(c.header("origin").is_none() && c.header("sec-fetch-site").is_none());
        let text = String::from_utf8_lossy(&c.body);
        assert!(!text.contains("mqt_sk_"));
        let body = read_body(&c.body, SOURCE);
        assert_eq!(c.header("idempotency-key"), body.batch["idempotencyKey"].as_str());
        assert_eq!(body.batch["instanceId"], instance.as_str());
    }
    let bodies = bodies(&mock);
    let seqs: Vec<u64> = bodies.iter().map(|b| b.batch["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, (0..bodies.len() as u64).collect::<Vec<_>>());
    let last = bodies.last().unwrap();
    assert_eq!(last.batch["final"], true);
    assert_eq!(last.end.as_deref(), Some("shutdown"));

    let groups: Vec<_> = bodies.iter().flat_map(|b| b.groups.clone()).collect();
    assert_eq!(groups.len(), 3);
    for (g, row) in groups.iter().enumerate() {
        assert_eq!(row.relay, "https://relay-a.example.net");
        assert_eq!(
            (row.track.as_str(), row.g, row.fo, row.n, row.b),
            ("video", g as u64, 0, 5, 510)
        );
        assert_eq!(row.send_us, 1_761_696_000_000_000 + g as i64 * 1_000_000);
        assert_eq!(row.span_us, 40_000);
    }
    let relays: Vec<_> = bodies.iter().flat_map(|b| b.relays.clone()).collect();
    assert!(relays.iter().all(|r| r.relay == "https://relay-a.example.net"));
    assert!(relays.iter().any(|r| r.close_ts.is_some() && r.close_code == Some(0)));
    let raw: Vec<u8> = mock.captured().iter().flat_map(|c| c.body.clone()).collect();
    assert!(!String::from_utf8_lossy(&raw).contains("jwt"));
    for b in &bodies {
        let names: Vec<_> = b.tracks.iter().map(|t| (t.ns.clone(), t.name.clone())).collect();
        assert!(names.iter().all(|(ns, n)| ns == &["live", "channel-7"] && n == "video"));
    }
}

#[tokio::test]
async fn one_body_carries_every_relay_connection() {
    let mock = Mock::start().await;
    let m = builder(&mock).seal_interval(Duration::from_secs(3600)).start().expect("start");
    let a = m.connection("https://relay-a.example.net").unwrap();
    let b = m.connection("moqt://relay-b.example.net:4443").unwrap();
    for g in 0..4 {
        a.object_sent(&NS, "video", g, 0, 10, None).unwrap();
        b.object_sent(&NS, "video", g, 0, 10, None).unwrap();
        b.object_sent(&NS, "audio", g, 0, 10, None).unwrap();
    }
    m.shutdown(Duration::from_secs(5)).await;
    let bodies = bodies(&mock);
    assert_eq!(bodies.len(), 1);
    let origins: Vec<_> = bodies[0].relays.iter().map(|r| r.relay.as_str()).collect();
    assert_eq!(origins, ["https://relay-a.example.net", "moqt://relay-b.example.net:4443"]);
    assert_eq!(bodies[0].groups.len(), 12);
    assert_eq!(bodies[0].tracks.len(), 2);
}

#[tokio::test]
async fn the_clock_offset_is_measured_against_ingest() {
    let mock = Mock::start().await;
    mock.set_clock_offset_ms(5_000.0);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", 0, 0, 1, None).unwrap();
    mock.wait_for(1, Duration::from_secs(5)).await;
    relay.object_sent(&NS, "video", 1, 0, 1, None).unwrap();
    relay.object_sent(&NS, "video", 2, 0, 1, None).unwrap();
    mock.wait_for(2, Duration::from_secs(5)).await;
    m.shutdown(Duration::from_secs(5)).await;

    let bodies = bodies(&mock);
    assert!(bodies[0].batch.get("clock").is_none(), "no exchange before the first upload");
    let clock = &bodies[1].batch["clock"];
    let (o, r, n, a) = (
        clock["o"].as_f64().unwrap(),
        clock["r"].as_f64().unwrap(),
        clock["n"].as_u64().unwrap(),
        clock["a"].as_f64().unwrap(),
    );
    assert!(n >= 1 && r >= 0.0 && a >= 0.0, "{clock}");
    // The mock rounds its stamps to 1 ms.
    assert!((o - 5_000.0).abs() <= r / 2.0 + 1.0, "{clock}");
}

#[tokio::test]
async fn per_object_bodies_seal_at_32_kib() {
    let mock = Mock::start().await;
    let m = builder(&mock)
        .detail(Detail::Object)
        .seal_interval(Duration::from_secs(3600))
        .start()
        .unwrap();
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let t0 = SystemTime::now();
    let mut x: u64 = 7;
    for i in 0..40_000u64 {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let at = t0 + Duration::from_micros(i * 16_000 + (x >> 54));
        relay.object_sent(&NS, "video", i / 60, i % 60, 900 + (x >> 49), Some(at)).unwrap();
    }
    let stats = m.shutdown(Duration::from_secs(10)).await;
    let bodies = bodies(&mock);
    assert!(bodies.len() >= 4, "{} bodies", bodies.len());
    assert_eq!(stats.bodies_sent, bodies.len() as u64);
    let mut objects = 0;
    for b in &bodies {
        assert!(b.gz_frames <= 32 * 1024, "{} B", b.gz_frames);
        if !b.objects.is_empty() {
            assert_eq!(b.batch["lvl"], "headers+sizes");
        }
        objects += b.objects.len();
    }
    assert_eq!(objects, 40_000);
    let groups: usize = bodies.iter().map(|b| b.groups.len()).sum();
    assert_eq!(groups, 40_000usize.div_ceil(60));
}

#[tokio::test]
async fn a_refused_key_stops_the_monitor() {
    let mock = Mock::start().await;
    mock.script([Reply::status(401)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", 0, 0, 1, None).unwrap();
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while m.stats().state == State::Running && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(m.stats().state, State::Stopped { status: 401 });
    assert_eq!(relay.object_sent(&NS, "video", 1, 0, 1, None), Err(Rejected::Closed));
    tokio::time::sleep(Duration::from_millis(400)).await;
    let stats = m.shutdown(Duration::from_secs(1)).await;
    assert_eq!(stats.state, State::Stopped { status: 401 });
    assert_eq!(mock.captured().len(), 1, "nothing is sent after a 401");
}

#[tokio::test]
async fn a_missing_path_stops_the_monitor() {
    let mock = Mock::start().await;
    mock.script([Reply::status(404)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", 0, 0, 1, None).unwrap();
    mock.wait_for(1, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(m.stats().state, State::Stopped { status: 404 });
    drop(relay);
    m.shutdown(Duration::from_secs(1)).await;
    assert_eq!(mock.captured().len(), 1);
}

#[tokio::test]
async fn a_503_is_retried_with_the_same_body() {
    let mock = Mock::start().await;
    mock.script([Reply::status(503), Reply::status(429)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", 0, 0, 1, None).unwrap();
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
async fn a_refused_body_is_listed_as_lost_in_the_next() {
    let mock = Mock::start().await;
    mock.script([Reply::status(413)]);
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", 0, 0, 1, None).unwrap();
    mock.wait_for(1, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    relay.object_sent(&NS, "video", 1, 0, 1, None).unwrap();
    relay.object_sent(&NS, "video", 2, 0, 1, None).unwrap();
    mock.wait_for(2, Duration::from_secs(5)).await;
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.bodies_lost, 1);
    let bodies = bodies(&mock);
    let first = bodies[0].batch["seq"].as_u64().unwrap();
    assert_eq!(bodies.last().unwrap().batch["lost"], serde_json::json!([first]));
}

#[tokio::test]
async fn bad_input_is_refused_without_a_panic() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    assert!(m.connection("wss://relay.example").is_err());
    let relay = m.connection("https://relay-a.example.net").unwrap();
    let r = relay.object_sent(&NS, "video", 1 << 62, 0, 1, None);
    assert_eq!(r, Err(Rejected::InvalidInput));
    let r = relay.object_sent(
        &NS,
        "video",
        0,
        0,
        1,
        Some(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
    );
    assert_eq!(r, Err(Rejected::InvalidInput));
    let r = relay.object_sent(&NS, "video", 0, 0, u64::MAX, None);
    assert_eq!(r, Err(Rejected::InvalidInput));
    let r = relay.object_sent(&[] as &[&str], &"x".repeat(5000), 0, 0, 1, None);
    assert_eq!(r, Err(Rejected::InvalidInput));
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.rejected, 4);
    assert!(bodies(&mock).iter().all(|b| b.groups.is_empty()));
}

#[tokio::test]
async fn a_late_object_of_an_old_group_is_not_sent_twice() {
    let mock = Mock::start().await;
    let m = builder(&mock).seal_interval(Duration::from_secs(3600)).start().expect("start");
    let relay = m.connection("https://relay-a.example.net").unwrap();
    for g in 0..70u64 {
        relay.object_sent(&NS, "video", g, 0, 10, None).unwrap();
    }
    relay.object_sent(&NS, "video", 0, 1, 10, None).unwrap();
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.dropped, 1);
    let groups: Vec<u64> =
        bodies(&mock).iter().flat_map(|b| b.groups.clone()).map(|g| g.g).collect();
    assert_eq!(groups.len(), 70);
    assert_eq!(groups.iter().collect::<std::collections::HashSet<_>>().len(), 70);
}

#[tokio::test]
async fn codes_past_2_53_are_refused_and_every_body_still_reads() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let relay = m.connection("https://relay-a.example.net").unwrap();
    relay.object_sent(&NS, "video", 0, 0, 10, None).unwrap();
    let big = 1u64 << 60;
    assert_eq!(relay.request_error(big), Err(Rejected::InvalidInput));
    assert_eq!(relay.stream_reset(&NS, "video", big), Err(Rejected::InvalidInput));
    assert_eq!(relay.set_draft(big), Err(Rejected::InvalidInput));
    relay.request_error(0x10).unwrap();
    assert_eq!(relay.close(Some(big)), Err(Rejected::InvalidInput));
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.rejected, 4);
    let bodies = bodies(&mock);
    let events: Vec<_> = bodies.iter().flat_map(|b| b.events.clone()).collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["code"], 0x10);
    let relays: Vec<_> = bodies.iter().flat_map(|b| b.relays.clone()).collect();
    assert!(relays.iter().all(|r| r.close_code.is_none()));
    assert!(relays.iter().any(|r| r.close_ts.is_some()));
}

fn origins_sent(mock: &Mock) -> std::collections::BTreeSet<String> {
    bodies(mock).iter().flat_map(|b| b.groups.iter().map(|g| g.relay.clone())).collect()
}

async fn until_sent(m: &Monitor, n: u64) {
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while m.stats().bodies_sent < n && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(m.stats().bodies_sent >= n, "{n} bodies not sent in 5 s");
}

#[tokio::test]
async fn no_body_names_a_relay_past_the_monthly_cap() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let conns: Vec<_> = (0..70)
        .map(|i| m.connection(&format!("https://relay-{i:02}.example.net/moq")).unwrap())
        .collect();
    for c in &conns {
        c.object_sent(&NS, "video", 0, 0, 10, None).unwrap();
        c.request_error(3).unwrap();
    }
    drop(conns);
    let stats = m.shutdown(Duration::from_secs(5)).await;

    let want: std::collections::BTreeSet<String> =
        (0..64).map(|i| format!("https://relay-{i:02}.example.net")).collect();
    assert_eq!(origins_sent(&mock), want);
    for b in bodies(&mock) {
        assert!(b.relays.len() <= 32);
        assert!(b.relays.iter().all(|r| want.contains(&r.relay)), "{:?}", b.relays);
    }
    assert_eq!(stats.over_relay_cap, 6 * 2);
    assert!(stats.dropped >= stats.over_relay_cap);
    assert_eq!(MAX_RELAYS_PER_MONTH, 64);
}

#[tokio::test]
async fn the_cap_restarts_when_ingest_answers_from_a_later_month() {
    let mock = Mock::start().await;
    let m = monitor(&mock);
    let conns: Vec<_> = (0..64)
        .map(|i| m.connection(&format!("https://relay-{i:02}.example.net")).unwrap())
        .collect();
    for c in &conns {
        c.object_sent(&NS, "video", 0, 0, 10, None).unwrap();
    }
    until_sent(&m, 1).await;
    let late = m.connection("https://relay-late.example.net").unwrap();
    late.object_sent(&NS, "video", 0, 0, 10, None).unwrap();
    let sent = m.stats().bodies_sent;
    conns[0].object_sent(&NS, "video", 1, 0, 10, None).unwrap();
    until_sent(&m, sent + 1).await;
    assert_eq!(m.stats().over_relay_cap, 1, "the 65th origin waits for a new month");

    // Ingest's clock in a later month: the next accepted body restarts the count.
    mock.set_clock_offset_ms(32.0 * 86_400_000.0);
    let sent = m.stats().bodies_sent;
    conns[0].object_sent(&NS, "video", 2, 0, 10, None).unwrap();
    until_sent(&m, sent + 1).await;
    late.object_sent(&NS, "video", 1, 0, 10, None).unwrap();
    drop(conns);
    drop(late);
    let stats = m.shutdown(Duration::from_secs(5)).await;

    assert_eq!(stats.over_relay_cap, 1);
    let last = bodies(&mock).into_iter().rfind(|b| !b.groups.is_empty()).unwrap();
    assert!(last.groups.iter().any(|g| g.relay == "https://relay-late.example.net" && g.g == 1));
}

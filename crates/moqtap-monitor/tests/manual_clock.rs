//! The monitor on a manual clock, as the upload kit's harness drives it.

mod common;

use std::time::Duration;

use common::{read_body, Mock, Reply};
use moqtap_monitor::{Delivery, Monitor, Sent, State, TestClock};

const SOURCE: &str = "enc-test-1";
const KEY: &str = "mqt_sk_AAAAtestkeybody_testmac";
const WALL_US: i64 = 1_761_688_800_000_000;

fn obj(group: u64, object: u64) -> Sent {
    Sent {
        group,
        delivery: Delivery::Subgroup(0),
        object,
        size: 100,
        starts_group: object == 0,
        opens_subgroup: object == 0,
        ends_group: false,
    }
}

fn start(mock: &Mock, clock: &TestClock) -> Monitor {
    Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .test_clock(clock)
        .start()
        .expect("start")
}

#[tokio::test]
async fn seals_follow_the_manual_clock() {
    seals_follow(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seals_follow_the_manual_clock_across_threads() {
    for _ in 0..20 {
        seals_follow(true).await;
    }
}

async fn seals_follow(threaded: bool) {
    let mock = Mock::start().await;
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", obj(0, 0), None).expect("report");

    if !threaded {
        clock.advance(Duration::from_millis(14_999)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(mock.uploads().is_empty(), "nothing is sealed before 15 s");
    }

    // One advance across four intervals seals four bodies, one at each 15 s.
    let rest = if threaded { 60_000 } else { 45_001 };
    clock.advance(Duration::from_millis(rest)).await;
    let ups = mock.wait_for(1, Duration::from_secs(5)).await;
    let first = read_body(&ups[0].body, SOURCE);
    assert_eq!(first.preamble["seal"]["from_us"], 0);
    assert_eq!(first.preamble["seal"]["through_us"], 15_000_000);
    assert_eq!(first.batch["start"]["wall_ms"], WALL_US / 1000);
    assert_eq!(first.batch["clk"]["res_us"], 1);
    assert_eq!(first.runs.len(), 1);
    assert_eq!(first.runs[0].ids, vec![0]);

    relay.object_sent(&["live"], "video", obj(1, 0), Some(clock.instant_at(59_000_000))).ok();
    let s = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(s.state, State::ShutDown);
    // A long advance can pass an upload's timeout while its reply is in
    // flight, so a body may be sent twice; count each seq once.
    let mut bodies: Vec<_> = mock.uploads().iter().map(|c| read_body(&c.body, SOURCE)).collect();
    bodies.dedup_by(|a, b| a.preamble["seal"]["seq"] == b.preamble["seal"]["seq"]);
    let throughs: Vec<_> =
        bodies.iter().map(|b| b.preamble["seal"]["through_us"].clone()).collect();
    assert_eq!(throughs.len(), 5, "four timed bodies and the final one: {throughs:?}");
    assert_eq!(throughs[..4], [15_000_000, 30_000_000, 45_000_000, 60_000_000]);
    let last = bodies.last().expect("final body");
    assert_eq!(last.end.as_deref(), Some("shutdown"));
    assert_eq!(last.preamble["seal"]["through_us"], 60_000_000);
    assert!(last.runs.iter().any(|r| r.g == 1), "the late report is in the final body");
}

#[tokio::test]
async fn a_retry_waits_on_the_manual_clock() {
    let mock = Mock::start().await;
    mock.script([Reply::status(503)]);
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", obj(0, 0), None).expect("report");
    clock.advance(Duration::from_secs(15)).await;
    assert_eq!(mock.wait_for(1, Duration::from_secs(5)).await.len(), 1);

    // The first retry waits up to one second, in manual time only.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(mock.uploads().len(), 1);
    clock.advance(Duration::from_secs(1)).await;
    let ups = mock.wait_for(2, Duration::from_secs(5)).await;
    assert_eq!(ups.len(), 2);
    assert_eq!(ups[0].body, ups[1].body, "a retry sends the same bytes");
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while m.stats().bodies_sent == 0 && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(m.stats().bodies_sent, 1);
    m.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_held_reply_times_out_after_thirty_manual_seconds() {
    let mock = Mock::start().await;
    mock.hold_next();
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", obj(0, 0), None).expect("report");
    clock.advance(Duration::from_secs(15)).await;
    assert_eq!(mock.wait_for(1, Duration::from_secs(5)).await.len(), 1);
    clock.advance(Duration::from_millis(29_999)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(mock.uploads().len(), 1);
    // At 30 s the request is given up and retried after its backoff.
    clock.advance(Duration::from_millis(1)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    clock.advance(Duration::from_secs(1)).await;
    let ups = mock.wait_for(2, Duration::from_secs(5)).await;
    assert!(ups.len() >= 2);
    assert_eq!(ups[0].body, ups[1].body, "the timed-out body is sent again");
    m.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_wall_step_is_a_clock_break() {
    let mock = Mock::start().await;
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", obj(0, 0), None).expect("report");
    clock.advance(Duration::from_secs(1)).await;
    clock.step_wall(-2_000_000);
    relay.object_sent(&["live"], "video", obj(0, 1), None).expect("report");
    clock.settle().await;
    let ups = mock.wait_for(1, Duration::from_secs(5)).await;
    let b = read_body(&ups[0].body, SOURCE);
    assert_eq!(b.preamble["seal"]["through_us"], 1_000_000, "sealed at the break");
    assert_eq!(b.batch["clk"]["epoch"], 0);
    m.shutdown(Duration::from_secs(5)).await;
    let last = mock.uploads().last().map(|c| read_body(&c.body, SOURCE)).expect("final");
    assert_eq!(last.batch["clk"]["epoch"], 1);
}

/// `(seq, through_us, ms, next_us)` of each body received, once per seq.
fn seals(mock: &Mock) -> Vec<(u64, i64, u64, Option<i64>)> {
    let mut out: Vec<(u64, i64, u64, Option<i64>)> = Vec::new();
    for c in mock.uploads() {
        let s = read_body(&c.body, SOURCE).preamble["seal"].clone();
        let seq = s["seq"].as_u64().unwrap();
        if out.iter().any(|x| x.0 == seq) {
            continue;
        }
        out.push((
            seq,
            s["through_us"].as_i64().unwrap(),
            s["ms"].as_u64().unwrap(),
            s.get("next_us").and_then(|v| v.as_i64()),
        ));
    }
    out.sort_by_key(|x| x.0);
    out
}

/// Advance one second at a time, letting each upload's reply land.
async fn run_to(clock: &TestClock, from_s: u64, to_s: u64) {
    for _ in from_s..to_s {
        clock.advance(Duration::from_secs(1)).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

#[tokio::test]
async fn each_body_states_its_next_seal_and_a_lapsing_directive_shows_in_it() {
    let mock = Mock::start().await;
    let mut d = Reply::status(202);
    d.body = r#"{"ok":true,"seal_ms":5000,"ttl_ms":7000}"#.into();
    mock.script([d]);
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", obj(0, 0), None).expect("report");
    run_to(&clock, 0, 41).await;
    let s = seals(&mock);
    // Sealed before any reply: the configured 15 s. The directive holds to
    // 22 s, so the body at 20 s states 25 s; the one at 25 s is sealed past
    // its lapse and states the configured interval again, though its own
    // interval was 5 s.
    assert_eq!(s[0], (0, 15_000_000, 15_000, Some(30_000_000)));
    assert_eq!(s[1], (1, 20_000_000, 5_000, Some(25_000_000)));
    assert_eq!(s[2], (2, 25_000_000, 5_000, Some(40_000_000)));
    assert_eq!(s[3], (3, 40_000_000, 15_000, Some(55_000_000)));
    m.shutdown(Duration::from_secs(5)).await;
    let last = mock.uploads().last().map(|c| read_body(&c.body, SOURCE)).expect("final");
    assert_eq!(last.batch["final"], true);
    assert!(last.preamble["seal"].get("next_us").is_none(), "a final body states no next seal");
}

#[tokio::test]
async fn a_longer_directive_never_moves_a_stated_seal_later() {
    let mock = Mock::start().await;
    let mut short = Reply::status(202);
    short.body = r#"{"ok":true,"seal_ms":5000,"ttl_ms":60000}"#.into();
    let mut longer = Reply::status(202);
    longer.body = r#"{"ok":true,"seal_ms":10000,"ttl_ms":60000}"#.into();
    mock.script([short, longer]);
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", obj(0, 0), None).expect("report");
    run_to(&clock, 0, 36).await;
    let s = seals(&mock);
    assert_eq!(s[1], (1, 20_000_000, 5_000, Some(25_000_000)));
    // The 10 s reply to the body at 20 s would seal at 30 s: the stated 25 s holds.
    assert_eq!(s[2].1, 25_000_000);
    assert_eq!(s[2].3, Some(35_000_000));
    assert_eq!(s[3].1, 35_000_000);
    m.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_due_seal_with_nothing_to_report_still_makes_a_body() {
    let mock = Mock::start().await;
    let clock = TestClock::new(WALL_US);
    let m = start(&mock, &clock);
    run_to(&clock, 0, 31).await;
    let s = seals(&mock);
    assert_eq!(s[0], (0, 15_000_000, 15_000, Some(30_000_000)));
    assert_eq!(s[1], (1, 30_000_000, 15_000, Some(45_000_000)));
    m.shutdown(Duration::from_secs(5)).await;
}

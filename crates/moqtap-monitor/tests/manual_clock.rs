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
    assert_eq!(throughs.len(), 5, "four timed bodies and the final one");
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

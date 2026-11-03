//! The clocks and timers the monitor runs on: the system's, or a manual
//! clock that a test harness moves.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

pub(crate) enum Clock {
    System,
    Manual(TestClock),
}

impl Clock {
    pub(crate) fn now(&self) -> Instant {
        match self {
            Clock::System => Instant::now(),
            Clock::Manual(m) => m.now(),
        }
    }

    /// Wall time, µs since 1970.
    pub(crate) fn wall_us(&self) -> Option<i64> {
        match self {
            Clock::System => {
                let d = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
                i64::try_from(d.as_micros()).ok()
            }
            Clock::Manual(m) => Some(m.wall_us()),
        }
    }

    pub(crate) fn resolution_us(&self) -> u64 {
        match self {
            Clock::System => crate::clock::resolution_us(),
            Clock::Manual(_) => 1,
        }
    }

    pub(crate) async fn sleep_until(&self, deadline: Instant) {
        match self {
            Clock::System => tokio::time::sleep_until(deadline.into()).await,
            Clock::Manual(m) => m.sleep_until(deadline).await,
        }
    }

    pub(crate) async fn sleep(&self, d: Duration) {
        let deadline = self.now() + d;
        self.sleep_until(deadline).await;
    }

    /// `f`'s output, or `None` once `deadline` passes.
    pub(crate) async fn until<F: Future>(&self, deadline: Instant, f: F) -> Option<F::Output> {
        tokio::select! {
            v = f => Some(v),
            _ = self.sleep_until(deadline) => None,
        }
    }

    pub(crate) async fn timeout<F: Future>(&self, d: Duration, f: F) -> Option<F::Output> {
        let deadline = self.now() + d;
        self.until(deadline, f).await
    }

    /// The sealer was asked to wake.
    pub(crate) fn seal_asked(&self) {
        if let Clock::Manual(m) = self {
            m.inner.asked.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The wake requests the sealer has taken in.
    pub(crate) fn seal_requests(&self) -> u64 {
        match self {
            Clock::System => 0,
            Clock::Manual(m) => m.inner.asked.load(Ordering::SeqCst),
        }
    }

    /// The sealer waits until `deadline`, having handled `seen` requests.
    pub(crate) fn sealer_parked(&self, deadline: Instant, seen: u64) {
        if let Clock::Manual(m) = self {
            let until = m.mono_of(deadline);
            m.inner.sealer.send_modify(|p| {
                p.until_us = Some(until);
                p.seen = seen;
            });
        }
    }

    pub(crate) fn sealer_started(&self) {
        if let Clock::Manual(m) = self {
            m.inner.sealer.send_modify(|p| p.attached = true);
        }
    }

    pub(crate) fn sealer_done(&self) {
        if let Clock::Manual(m) = self {
            m.inner.sealer.send_modify(|p| p.done = true);
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Park {
    attached: bool,
    until_us: Option<i64>,
    seen: u64,
    done: bool,
}

#[derive(Debug, Default)]
struct State {
    mono_us: i64,
    wall_step_us: i64,
    /// Pending sleeps by deadline, mono µs.
    sleepers: BTreeMap<(i64, u64), ()>,
    next_sleeper: u64,
}

#[derive(Debug)]
struct Inner {
    base: Instant,
    wall0_us: i64,
    state: Mutex<State>,
    now: watch::Sender<i64>,
    sealer: watch::Sender<Park>,
    asked: AtomicU64,
}

/// A manual monotonic and wall clock for a test harness. Not part of the
/// supported API.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct TestClock {
    inner: Arc<Inner>,
}

impl TestClock {
    /// A clock whose monotonic time reads 0 and whose wall time reads
    /// `wall_us` (µs since 1970).
    pub fn new(wall_us: i64) -> Self {
        TestClock {
            inner: Arc::new(Inner {
                base: Instant::now(),
                wall0_us: wall_us,
                state: Mutex::new(State::default()),
                now: watch::channel(0).0,
                sealer: watch::channel(Park::default()).0,
                asked: AtomicU64::new(0),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Monotonic µs since the clock was made.
    pub fn mono_us(&self) -> i64 {
        self.state().mono_us
    }

    /// Wall µs since 1970.
    pub fn wall_us(&self) -> i64 {
        let s = self.state();
        self.inner.wall0_us.saturating_add(s.mono_us).saturating_add(s.wall_step_us)
    }

    /// The instant at monotonic `mono_us`.
    pub fn instant_at(&self, mono_us: i64) -> Instant {
        let d = Duration::from_micros(mono_us.unsigned_abs());
        let at = if mono_us >= 0 {
            self.inner.base.checked_add(d)
        } else {
            self.inner.base.checked_sub(d)
        };
        at.unwrap_or(self.inner.base)
    }

    fn now(&self) -> Instant {
        self.instant_at(self.mono_us())
    }

    fn mono_of(&self, at: Instant) -> i64 {
        match at.checked_duration_since(self.inner.base) {
            Some(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
            None => -i64::try_from((self.inner.base - at).as_micros()).unwrap_or(i64::MAX),
        }
    }

    /// Move the wall clock alone by `us`, as a step of the system clock.
    pub fn step_wall(&self, us: i64) {
        let mut s = self.state();
        s.wall_step_us = s.wall_step_us.saturating_add(us);
    }

    /// Move both clocks forward by `by`, stopping at each timer due on the
    /// way, and return once the monitor has packed every seal they start.
    pub async fn advance(&self, by: Duration) {
        let target = {
            let s = self.state();
            s.mono_us.saturating_add(i64::try_from(by.as_micros()).unwrap_or(i64::MAX))
        };
        self.settle().await;
        loop {
            // The sealer's park is a stop too: its sleep registers only once
            // polled, which can be after `settle` has seen the park.
            let parked = self.inner.sealer.borrow().until_us;
            let to = {
                let mut s = self.state();
                let now = s.mono_us;
                let next = s.sleepers.range((now + 1, 0)..).next().map(|((d, _), _)| *d);
                let next = match (next, parked.filter(|&u| u > now)) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                s.mono_us = next.filter(|&d| d < target).unwrap_or(target);
                s.mono_us
            };
            self.inner.now.send_replace(to);
            self.settle().await;
            if to >= target {
                return;
            }
        }
    }

    /// Wait until the sealer has handled every request and waits on a timer
    /// not yet due, or has finished.
    pub async fn settle(&self) {
        let mut rx = self.inner.sealer.subscribe();
        loop {
            let p = *rx.borrow_and_update();
            let now = self.mono_us();
            let asked = self.inner.asked.load(Ordering::SeqCst);
            let parked = p.until_us.is_some_and(|u| u > now) && p.seen >= asked;
            if !p.attached || p.done || parked {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    async fn sleep_until(&self, deadline: Instant) {
        let d = self.mono_of(deadline);
        let id = {
            let mut s = self.state();
            s.next_sleeper += 1;
            let id = s.next_sleeper;
            s.sleepers.insert((d, id), ());
            id
        };
        let _registered = Sleeper { clock: self, key: (d, id) };
        let mut rx = self.inner.now.subscribe();
        loop {
            if *rx.borrow_and_update() >= d {
                return;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

struct Sleeper<'a> {
    clock: &'a TestClock,
    key: (i64, u64),
}

impl Drop for Sleeper<'_> {
    fn drop(&mut self) {
        self.clock.state().sleepers.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_sleep_ends_when_the_clock_reaches_it() {
        let clock = TestClock::new(1_000_000);
        let c = Clock::Manual(clock.clone());
        let at = clock.instant_at(5_000_000);
        let woke = tokio::spawn(async move { c.sleep_until(at).await });
        tokio::task::yield_now().await;
        clock.advance(Duration::from_secs(4)).await;
        assert!(!woke.is_finished());
        clock.advance(Duration::from_secs(1)).await;
        tokio::time::timeout(Duration::from_secs(5), woke).await.expect("woke").expect("task");
        assert_eq!(clock.mono_us(), 5_000_000);
        assert_eq!(clock.wall_us(), 6_000_000);
        clock.step_wall(-2_000_000);
        assert_eq!(clock.wall_us(), 4_000_000);
        assert_eq!(clock.mono_us(), 5_000_000);
    }

    #[tokio::test]
    async fn an_advance_stops_at_each_timer_on_the_way() {
        let clock = TestClock::new(0);
        let c = Arc::new(Clock::Manual(clock.clone()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (c2, clock2, seen2) = (Arc::clone(&c), clock.clone(), Arc::clone(&seen));
        c.sealer_started();
        tokio::spawn(async move {
            for i in 1..=3 {
                let deadline = clock2.instant_at(i * 1_000_000);
                c2.sealer_parked(deadline, c2.seal_requests());
                c2.sleep_until(deadline).await;
                seen2.lock().unwrap().push(clock2.mono_us());
            }
            c2.sealer_done();
        });
        clock.advance(Duration::from_secs(10)).await;
        assert_eq!(*seen.lock().unwrap(), vec![1_000_000, 2_000_000, 3_000_000]);
        assert_eq!(clock.mono_us(), 10_000_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_advance_stops_at_a_park_whose_sleep_is_not_yet_polled() {
        let clock = TestClock::new(0);
        let c = Arc::new(Clock::Manual(clock.clone()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (c2, clock2, seen2) = (Arc::clone(&c), clock.clone(), Arc::clone(&seen));
        let (go, gate) = tokio::sync::oneshot::channel::<()>();
        c.sealer_started();
        c.sealer_parked(clock.instant_at(1_000_000), 0);
        tokio::spawn(async move {
            // The first sleep is polled only after the clock has moved.
            let _ = gate.await;
            for i in 1..=3 {
                let deadline = clock2.instant_at(i * 1_000_000);
                if i > 1 {
                    c2.sealer_parked(deadline, c2.seal_requests());
                }
                c2.sleep_until(deadline).await;
                seen2.lock().unwrap().push(clock2.mono_us());
            }
            c2.sealer_done();
        });
        let adv = tokio::spawn({
            let clock = clock.clone();
            async move { clock.advance(Duration::from_secs(10)).await }
        });
        while clock.mono_us() == 0 {
            tokio::task::yield_now().await;
        }
        let _ = go.send(());
        adv.await.expect("advance");
        assert_eq!(*seen.lock().unwrap(), vec![1_000_000, 2_000_000, 3_000_000]);
        assert_eq!(clock.mono_us(), 10_000_000);
    }

    #[test]
    fn instants_and_mono_times_round_trip() {
        let clock = TestClock::new(0);
        for us in [-3_000_000, -1, 0, 1, 42_000_000] {
            assert_eq!(clock.mono_of(clock.instant_at(us)), us);
        }
    }
}

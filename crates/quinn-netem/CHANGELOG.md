# Changelog

All notable changes to quinn-netem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-08-31

No behaviour change. The SHA-256 used to pin the distribution tables reads its
input through `as_chunks` rather than `chunks_exact`, which carries the block
and word sizes in the type and lets a word be handed to `from_be_bytes`
directly instead of rebuilt index by index. Rust 1.98's
`clippy::chunks_exact_to_as_chunks` is what prompted it; the determinism gate
is what confirms the digest is unchanged.

## [0.1.0] - 2026-08-29

Initial release.

### Added

- `Impairer::decide`, a pure function of profile, seed, sequence, on-wire size
  and tick, returning a `Decision` with a `Verdict`, an optional `DropCause`,
  release ticks and a corruption site. No clock, no socket, no allocation.
- Six models: loss (Bernoulli, Gilbert-Elliott, exact pattern, every-nth), delay
  (fixed, uniform, normal, pareto, paretonormal), reorder, duplication,
  single-bit corruption, and a token bucket with a bounded byte queue.
- `Prob`, an integer probability over `[0, 2^32]` in which both endpoints are
  exactly representable, so a "drop everything" row is exact rather than
  approached.
- `Pcg32` and twelve frozen PRNG stream ids, one per `(direction, model)` pair,
  so disabling one model cannot shift another model's decisions.
- Three committed integer inverse-CDF tables — normal, pareto, paretonormal —
  with `tabledist` and `crandom`, and an offline generator kept as an example so
  no floating point appears under `src/`. The tables carry a SHA-256 that a test
  checks, and are re-derivable and diffable on demand.
- `wire_bytes`, charging the UDP and IP headers a datagram really costs, so the
  MTU black hole and the rate model measure what the link measures. An
  IPv4-mapped address is charged an IPv4 header.
- `ImpairProfile`, `DirectionProfile`, a peer filter, a timeline that replaces
  the profile wholesale at a tick boundary, and `ProfileError`: a profile that
  cannot be honoured is refused at construction rather than accepted and
  ignored.
- Seven presets in `ALL_PRESETS`: LTE, consumer Wi-Fi, a geostationary satellite
  hop, a lossy access edge, a 3G cellular link, a bufferbloated access link, and
  a clean datacentre path as the control.
- `DecisionLog` and `Record` — integers and enum discriminants only, rendered
  one line per decision under a stated header, with `diff_fixture` returning a
  typed mismatch naming the line and both sides rather than asserting.
- `BucketState`, `charge` and `RateGrant` — a deficit-based token bucket whose
  zero value is a full bucket — and a bounded byte queue that distinguishes a
  tail drop from a datagram that can never fit.
- `Stats` and `StatsSnapshot`: atomic counters and a plain-integer snapshot
  satisfying an exact conservation identity across every verdict and cause.
- `ImpairHandle`, a `Send + Sync` control surface that arms, disarms, reseeds
  and reports, sharing one state across clones. A refused profile leaves the
  previous one running rather than half-replacing it.
- `ImpairedUdpSocket` behind the non-default `quinn-socket` feature: an
  `AsyncUdpSocket` decorator that splits segmented transmits and receives, parks
  held datagrams on its own release thread, and applies every decision to the
  datagram that crosses to the inner socket.
- `Serialize` and `Deserialize` for every type reachable from `ImpairProfile`
  and `Preset`, behind the non-default `serde` feature. Unknown keys are refused
  rather than skipped, and probabilities are written as integer parts per
  billion in a key that says so — `p-ppb`, with a value above certainty refused
  rather than saturated.
- `RELEASE_FLOOR_NS`, `RELEASE_SLICE_NS`, `DEFAULT_QUEUE_BYTES`, `RECORD_FIELDS`
  and `RECORD_HEADER` as public constants, so an integration test can name a
  value instead of restating it.
- A committed send-anyway shim under `tests/fixtures/`, together with the test
  that runs all eight wire gates against it and requires every one to fail. It
  is what distinguishes a gate that observes the wire from one that observes the
  crate's own bookkeeping.
- No default feature set: the engine and everything the determinism gate needs
  compile with zero dependencies, and each feature adds exactly one dependency.

### Known limits

- **Only one platform has ever been measured.** Every timing figure comes from
  one Windows machine. The determinism claim is a claim about arithmetic and is
  expected to hold anywhere; it has not been observed anywhere else.
- **This crate reproduces a rate, not a spacing.** `std::thread::sleep` has a
  flat floor of roughly 550 µs for every requested duration from 10 µs to
  200 µs, so above roughly 1 800 releases per second the release path clumps at
  floor ÷ requested spacing. The average rate stays exact. The floor is reported
  through `RELEASE_FLOOR_NS` and the release counters, never enforced.
- **The presets have no committed decision fixture.** A retune that changed a
  preset's numbers while keeping it valid and distinct would not be caught.
- **The distribution claim is made against the committed tables**, not against a
  large sample: the sampler's end-to-end mean and variance are not measured.
- **A peer filter naming well-formed addresses no peer will present is
  accepted.** Only the forms decidable before a run exists — an empty filter,
  port 0, the unspecified address — are refused.
- **The `serde` derives are checked by compiling and by conversion**, not by a
  round trip through a data format.
- **The wire gates run only where `quinn-socket` is on.** A build without that
  feature tests the decision engine alone.

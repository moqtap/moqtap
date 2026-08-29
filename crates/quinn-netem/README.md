# quinn-netem

Deterministic UDP datagram impairment for QUIC.

This crate decides what happens to a datagram — pass it, delay it, reorder it,
duplicate it, corrupt one bit of it, or drop it — and decides the same thing
every time from the same seed, on every platform. An impairment run is a
*fixture*, not a weather report.

It attaches to a `quinn::Endpoint` through quinn's public `AsyncUdpSocket`
trait: no fork, no patched dependency, and nothing above the socket needs to
know. Because the damage happens *below* QUIC, the peer's congestion controller,
loss detection and path-MTU discovery react to it the way they would to a real
network.

## What it does

- **Six models**: loss (Bernoulli, Gilbert-Elliott, exact pattern, every-nth),
  delay (fixed, uniform, normal, pareto, paretonormal), reorder, duplication,
  single-bit corruption, and a token bucket with a bounded byte queue.
- **Blackout windows, an MTU blackhole and a timeline** that replaces the
  profile wholesale at a tick boundary.
- **Seven presets**: LTE, consumer Wi-Fi, a geostationary satellite hop, a lossy
  access edge, a 3G cellular link, a bufferbloated access link, and a clean
  datacentre path as the control.
- **A decision log** of integers and enum discriminants only, renderable to a
  line-per-decision text format and comparable against a committed fixture.

## How determinism is bought

- **No runtime float.** The delay distributions are netem's own integer
  inverse-CDF tables, computed once offline and committed as integers. `ln`,
  `exp`, `powf` and `cos` are documented by std as permitted to differ across
  platforms, so they appear nowhere.
- **No clock.** `Impairer::decide` takes a caller-supplied `Tick`: a real
  `Instant` from the socket layer, a `for` loop from a test.
- **Separate PRNG streams.** Each `(direction, model)` pair draws from its own
  PCG32, so disabling one model does not shift another model's decisions.

## Nothing is silently ignored

A profile that cannot be honoured is **refused** at construction, never
accepted-and-ignored. A reorder model with no delay model, a zero reorder gap, a
zero `every-nth` period, a zero-length blackout, a rate model whose bucket can
never grant a full-size datagram, an empty peer filter — each is a
`ProfileError` with its own message, because an impairment that is configured,
counted, logged and then not delivered is the failure this crate is written
against.

The suite is held to the same standard. `tests/fixtures/silentshim/` is a
decorator that computes every impairment, increments every counter, writes every
log record and forwards the datagram intact; the wire gates are required to be
**red** against it, so a gate that observes only this crate's own bookkeeping
cannot be mistaken for one that observes the wire.

## Features

Neither is on by default, which is what keeps the engine dependency-free.

- `quinn-socket` — the `ImpairedUdpSocket` decorator. Adds `quinn`.
- `serde` — `Serialize` and `Deserialize` for every type reachable from
  `ImpairProfile` and `Preset`, so a scenario can be a config file instead of
  Rust. Adds `serde`.

Two things about that format are worth knowing before writing one. **An unknown
key is refused, never skipped** — a misspelled `mtu-blackhole` that was quietly
ignored would give a profile that arms, reports itself applied, and impairs
nothing. And **probabilities are integer parts per billion, in a key that says
so**: `p-ppb`, not `p`, because written as a bare `p` the value `1` reads as
certainty and would mean one part in a billion. Deserializing does not validate;
a profile from a file is refused or honoured by `ImpairProfile::validate`
exactly as one written in Rust is.

## Timing: what the release path can and cannot promise

**This crate reproduces a rate. It does not reproduce a spacing.**

The decision sequence is exact and reproducible; the wire *timing* is not, and
that is a property of the host. `std::thread::sleep` has a flat floor of roughly
550 µs for every requested duration from 10 µs to 200 µs — asking for 10 µs and
asking for 200 µs cost the same. **Measured on Windows 11 build 26200, x86_64.
Linux and macOS are unmeasured**, and on Linux the call becomes
`clock_nanosleep` against a high-resolution timer, so the figure may be smaller
there by orders of magnitude. `RELEASE_FLOOR_NS` carries the qualifier in its
own documentation.

- Above roughly **1 800 releases per second** the release path clumps, at
  floor ÷ requested spacing — a mean clump of about six at 100 Mbit/s with
  1200-byte datagrams. **The average rate stays exact**: a throughput assertion
  holds, an inter-arrival assertion does not.
- The floor is **reported, never enforced**. A delay model finer than the host's
  wake latency is not invalid, only one whose fine structure this host cannot
  render, and refusing it would reject scenarios deliverable on platforms nobody
  has measured.
- The release path reports its own batching — wake-ups taken, largest batch
  released — so a caller reading a release error can attribute it to the
  platform instead of guessing.

## Status

Implemented and tested: the engine, the decision log, the profiles and presets,
the token bucket and bounded queue, the statistics, the live control handle, and
the `AsyncUdpSocket` decorator behind `quinn-socket`.

Things to know before relying on it:

- **Only one platform has ever been measured.** Every number above comes from
  one Windows machine. The determinism claim is a claim about arithmetic and is
  expected to hold anywhere; it has not been *observed* anywhere else.
- **The presets have no committed decision fixture.** They are checked for
  validity and for being seven distinct networks, but a retune that changed a
  preset's numbers while keeping it valid and distinct would not be caught.
  Recording each preset's log and diffing against it is deliberately not the
  fix: a fixture generated by running the code under test agrees with that code
  by construction.
- **The distribution claim is made against the tables, not a large sample.**
  Monotonicity, exact antisymmetry, a zero median, pinned extremes and σ-band
  occupancies at 68.27 / 95.45 / 99.73 % are asserted, and the tables are
  re-derivable from the committed generator with no tolerance. The sampler's
  end-to-end mean and variance over a large sample are not measured.
- **A peer filter naming well-formed addresses no peer will present is
  accepted.** An empty filter is refused, as is one naming port 0 or the
  unspecified address, but a mistyped octet is a well-formed address: the
  profile is valid and the run comes back clean with nothing impaired.
- **The `serde` derives are checked by compiling and by conversion, not by a
  round trip through a format.** Asserting the kebab-case keys and the unknown-
  key refusal needs a data format, and a dev-dependency there would be compiled
  by the featureless `cargo test` whose whole point is that it has none.
- **Reaching the wire is not the same as provoking a reaction.** The wire gates
  assert what crossed to the inner socket, not that a corrupted datagram then
  fails AEAD or that an over-size one provokes path-MTU discovery.
- **The wire gates run only where `quinn-socket` is on.** A build without that
  feature tests the decision engine alone.

## License

MIT

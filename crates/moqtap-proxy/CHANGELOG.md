# Changelog

All notable changes to moqtap-proxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-31

The release that turns an inspecting proxy into an acting one. 0.3.0 could
watch a session and report what it saw; this version frames objects
individually on all thirteen drafts, hands each one to a hook that returns a
decision, paces media egress from a shaping profile, sets QUIC transport
parameters per leg, and carries a datagram impairment underneath both. Drafts
17, 18 and 19 also gain the stream topology those drafts specify — a control
plane on a pair of unidirectional streams, with each request on a bidirectional
stream of its own — so a session against a conforming peer on those drafts
completes for the first time.

Under Cargo's 0.x rules the minor position is the major position, so this is
0.4.0 rather than 0.3.1: `ProxySessionConfig` and `ListenerConfig` gained
required fields and `StreamCtx::new` a seventh argument, and `^0.3.0` will not
resolve a patch away from a consumer.

### Added

- **Hook v2 — six methods, each returning a decision rather than performing
  one.** `on_control_message`, `on_stream_open`, `on_stream_header`,
  `on_object`, `on_datagram` and `on_stream_end`. Every one is defaulted, so a
  hook implements only what it cares about, and all six are synchronous and
  return data: a hook can never stall a read loop by awaiting inside one.
  `hook::LegacyProxyHook` adapts a 0.3.x hook unchanged.
- **`action::Interest`, sampled once at session start.** It decides how much of
  the session is parsed at all. `Interest::NONE` leaves the forwarding path a
  byte pump with no framer armed, which is what makes "this hook cost nothing"
  a measurable claim rather than a promise — a session that declared no
  interest ends with an all-zero `Counters`.
- **Nine actions and four stream-open decisions.** `Action::{Pass, Delay, Hold,
  Drop, Truncate, ResetStream, CloseSession, Replace, ReplacePayload}`, and
  `StreamAction::{Open, Reject, OpenAfter, SerializeAfter}`. `Delay` resolves
  below a millisecond on every platform, Windows included.
- **`capability`, a queryable table of what each draft and each site can
  express, and why not.** `Capabilities::for_draft`, `Support`, `Refusal`,
  `Instead`, `supports_matcher`. `tests/action_matrix.rs` asserts the table
  against observed behaviour on all thirteen drafts, so it cannot drift into a
  documented lie about the engine. Every refusal is reported as
  `ProxyEvent::ActionRefused` with the reason, never dropped in silence.
- **`framer::ObjectFramer` frames a unidirectional data stream into
  individually addressable objects on every draft 07-19**, preserving stream
  boundaries and extension bytes. `ProxyEvent::Object` reports each one as an
  `ObjectMeta`; a stream the framer cannot follow emits one
  `FramerOut::Bypassed` with a `BypassReason` rather than going quiet, which is
  what lets a reader tell "nothing matched" from "nothing was looked at".
- **Egress shaping.** `ShapeProfile` is token buckets plus ordered class rules
  plus a queue policy plus an arbitration discipline; `Matcher` is the AND of
  eight keys, where an absent key never matches. `ShapeProfile::try_new` is the
  only constructor and refuses seven configurations that would otherwise arm
  and do nothing — among them a class naming a bucket that does not exist, and
  a matcher naming a key that can never claim a unit. A configured `rate_bps`
  is enforced on the wire.
- **Shaping statistics, three ways.** `ShapeStats` reports one row per
  configured class plus a default row, an unshapeable row and the session
  totals; a class that saw nothing reports a zero row and never an absent one.
  Every session total appears flat and again under `uplink` and `downlink`,
  with the flat figure defined as the sum of the two, so the views cannot
  disagree.
- **`control::ProxyControl` reconfigures a proxy that is already running** —
  `set_transport`, `set_shape`, `set_shaper_enabled`, `set_impair`,
  `clear_impair`, `close_session`, `reset_stream` and `inject_control`, with
  `sessions`, `stats`, `reset_stats` and `local_addr` to read back what it did.
- **`transport::TransportProfile`, per leg.** Windows, idle timeout, keep-alive,
  loss-detection thresholds, congestion controller, MTU discovery, datagram
  buffers, both stream ceilings and the persistent-congestion threshold. Each
  field is an `Option` whose `None` means leave alone, and a leg refuses a
  profile and a raw `quinn::TransportConfig` together rather than silently
  preferring one.
- **A socket seam on both legs**, for carrying a datagram impairment beneath
  QUIC: `Listener::bind_with_socket` and `ProxySessionConfig::upstream_socket`,
  both taking an `Arc<dyn quinn::AsyncUdpSocket>`. The forwarding path stays
  agnostic — it knows nothing about impairment — and the `impair` feature adds
  only the control-plane verb that installs one.
- **`ProxyEvent::Impairment` with `ImpairmentKind`**, the evidence layer for
  everything the proxy declined to do or did differently: a framer bypass, an
  undecodable control frame, a shaping rule that cannot match on this draft, a
  class that changed mid-stream, a serialize target it never saw.
- **Always-on instrumentation.** `ProxySession::counters()` and the
  `instrument` module count the slow paths — framers created, objects elided,
  actions refused, egress items queued, release lateness.
- **A QUIC-level capture per connection, behind the off-by-default `qlog`
  feature.** Each leg config carries its own `QlogSpec`; the capture is written
  by quinn and sits underneath everything else this crate reports.
- **The configuration types can be written down, behind the new off-by-default
  `serde` feature.** `TransportProfile` and its enums, `ShapeProfile`,
  `Matcher`, `MatchKind`, `ClassRule`, `QueueConfig`, `BucketConfig`,
  `Overflow`, `Expiry`, `Discipline` and `RangeSet` gain `Serialize` and
  `Deserialize` under this feature only. It buys the derives and nothing more:
  this crate reads no file and chooses no format, so the parser is the caller's
  dependency.
  - Two are not plain derives, and both would have been silent bugs.
    `ShapeProfile` deserializes `try_from = "ShapeProfileSpec"` so that every
    read runs `try_new`; a derive onto the private fields would let a class
    naming a missing bucket arm and charge nothing. `RangeSet` reads through
    `Vec<RangeInclusive<u64>>` because its constructor sorts and coalesces, and
    a derive filling the field directly would leave it unsorted, at which point
    `contains` — a binary search — answers false for values that are in the set.
- **`Matcher::inert_key` is public.** It answers whether a matcher names a key
  that can never claim a unit, from the configuration alone and with no
  traffic. `ShapeProfile::try_new` calls it, so a shaping class gets that
  refusal for free; a caller building matchers for a hook of its own reaches no
  constructor that could run the check.
- **Thirteen `draftNN` features plus `all-drafts`**, so a build can carry one
  draft instead of all of them. A session naming a draft the build did not
  compile is refused with `ProxyError::DraftNotCompiled`.
- **`moqtap_proxy::types`**, one module holding the five leaf types the rest of
  the crate keys on — `ProxySide`, `Leg`, `ObjectMeta`, `BypassReason` and
  `DataStreamType`. Every one is still exported where it was.

### Changed (breaking)

- **`ProxySessionConfig` gains four required fields** — `shape`,
  `upstream_socket`, `upstream_transport_profile`, `upstream_installer` — and
  **`ListenerConfig` gains two**, `transport_profile` and `installer`. Under
  `qlog` each gains one more. Neither type is `#[non_exhaustive]`, so an
  exhaustive struct literal must name them; `ProxySessionConfig::default()` is
  unaffected, `ListenerConfig` has no `Default` and no escape.
- **`StreamCtx::new` takes a seventh argument**, the stream key a hook needs to
  name a serialization target.
- **The hook trait is v2.** A 0.3.x hook compiles unchanged through
  `hook::LegacyProxyHook`, which yields `DATAGRAMS`, plus `CONTROL` only when
  the wrapped hook asks for control mutation.
- **`ControlStreamParser::feed` hands back every frame it located, decoded or
  not.** `ParseResult::Messages` now carries `Vec<ParsedFrame>`. A control
  message this proxy cannot read was previously indistinguishable, to
  everything downstream, from one the peer never sent — and those two call for
  opposite conclusions.
- **`capability::Support::Unreachable`'s `instead` field is
  `capability::Instead`, not `framer::BypassReason`.**
- **`ProxyEvent::Impairment` gains a `leg: Option<Leg>` field.**
- **A rule aimed at `MatchKind::Datagram` no longer reports
  `ImpairmentKind::ShapeRuleUnmatchable`.** A datagram-aimed class now claims
  and polices datagrams, so the report would be false.
- **`capability::Refusal::WouldRenumberFetchObjects` is gone**, along with the
  refusal: fetch objects are addressable on drafts 15, 16 and 17, and an elide
  on one is carried out.
- **`ObjectMeta::subgroup_id` is `None` where a fetch frame carries no Subgroup
  ID**, rather than the placeholder zero it used to report.
- **A control-plane close is no longer reported as a hook's**, and three
  impairment reports moved to after the thing they report rather than before.
- **The declared MSRV moves from 1.83 to 1.88.** Not a consequence of this
  release's code: 1.83 had already stopped building the workspace, because
  `time` requires 1.88. The CI job that should have caught it was running
  `@stable` and therefore checking nothing.

### Fixed

- **On drafts 17-19 the control plane is the pair of unidirectional streams,
  and a bidirectional stream is a request stream.** Those drafts moved the
  control plane off the bidirectional stream every earlier draft uses; this
  proxy still treated the first bidirectional stream as the control plane and
  unidirectional control streams as data. A session against a conforming peer
  on those drafts could not complete.
- **The draft the peers name in SETUP now reaches the tasks that parse with
  it.** The session peeked at SETUP and every parsing task kept the configured
  guess, so on the drafts where one ALPN covers several versions the whole
  session was parsed against the wrong one.
- **The control stream parser frames drafts 17-19 with MoQT's own
  variable-length integer** rather than the RFC 9000 form, which disagree above
  63.
- **A default session configuration names a draft the build actually
  compiled.** `ProxySessionConfig::default()` returned a fixed draft that a
  reduced-draft build may not have, so the default was unusable there.
- **Eliding the first object of a draft-15 subgroup stream is refused**, as it
  already was on the eight other drafts that define the mode. Draft-15 was
  missing from the gate, so the guard was not narrower there — it was skipped,
  and the receiver got a stream whose subgroup ID had silently become the
  second object's.
- **A reserved subgroup-ID mode on a draft-15 or draft-16 stream is refused as
  itself**, not as a redefined Subgroup ID, and a draft-16 subgroup header
  setting that mode is no longer framed at all.
- **A control frame the decoder refuses is no longer deleted from a session
  whose hook declared `Interest::CONTROL`.** It is forwarded and reported as
  `ImpairmentKind::ControlFrameNotDecodable`. A Message Type the draft does not
  assign, a body that disagrees with its own length, and anything an extension
  adds all arrive this way.
- **A draft-18 or draft-19 fetch response is read.** Those drafts write a fetch
  object's Group ID as a difference whose sign the fetch's Group Order settles;
  the order is on the control plane and never on the data stream, so the
  session now files it under the request's ID and hands it to the framer when
  the response opens. A response naming a request the session never carried is
  forwarded untouched and reported rather than read against a guess.
- **A draft-16 namespace subscription is forwarded.** That draft puts
  SUBSCRIBE_NAMESPACE on a bidirectional stream of its own, which this proxy
  had treated as a second control stream.
- **Stream resets are no longer laundered into clean FINs**, and a peer's
  `STOP_SENDING` is forwarded to the source with its original code.
  `ProxyEvent::StreamReset` reports an observed reset.
- **An idle stream is now stopped too** on teardown, rather than only a stream
  with bytes in flight.
- **The internal release timer no longer deadlocks when it is dropped from its
  own thread.**
- **The rustdoc for this crate builds on its default feature set.**

### Limits

Things this release does not do, listed because each one is reachable through a
configuration that looks applied.

- **`ProxyControl::set_transport` can be a permanent silent no-op, and the
  return value cannot tell you.** quinn takes a transport configuration when a
  connection is made, so a profile set on the upstream leg reaches the next
  connection the proxy opens and one set on the client leg reaches the next it
  accepts — which it does not initiate and which may never arrive. The one
  instrument that makes it bite on a running session is `close_session`.
- **A WebTransport upstream cannot be given a socket**, and no version of this
  release fixes it: `wtransport` builds the upstream endpoint internally, so
  there is no seam. It is refused with `ProxyError::UpstreamSocketUnsupported`
  ahead of both feature arms rather than connected around. An upstream qlog
  spec is likewise ignored there. The client-facing leg carries both transports
  fully.
- **`set_shape` will not move a running session onto a different class list.**
  A session takes a new profile only if its class names match; otherwise the
  statistics it has already reported would stop meaning what they said.
- **`set_shaper_enabled(false)` does not promptly release a stream held by a
  class configured at zero.** The switch is read on the next release decision,
  which such a stream is not making.
- **`Overflow::Block` stops this proxy's read loop; it does not stall the
  peer.** At quinn's defaults the peer keeps writing into its receive window.
- **A shaping profile is admitted twice on the drafts sharing one ALPN, and the
  first time is against a guess.** The pre-connection check is the only one
  that can refuse before a byte moves, so it stays; a second admission runs
  against the draft the peers actually name, and a profile that clears the
  guess can still end the session once SETUP arrives.
- **A subgroup header carrying drafts 17-19's reserved SUBGROUP_ID_MODE is
  forwarded, not refused.**
- **Unshapeable bytes are not paced**, and nothing outside a data stream is
  shaped: control streams and handshake traffic move at line rate whatever the
  profile says.
- **A `MatchKind::Fetch` class is live on drafts 07-14 and dead on 15-19.**
- **This proxy sets quinn's acknowledgement-frequency parameters and the
  persistent-congestion threshold without demonstrating their effect.** Both
  are carried because refusing them would deny a caller a knob quinn has; no
  test here asserts what either does.
- **Actions are untested on WebTransport**, and every reset this crate emits is
  a plain `RESET_STREAM` with a raw integer code.
- **`Truncate` guarantees a prefix, not a byte count**, and `Delay` and `Hold`
  use a real clock rather than tokio's.

### Migration from 0.3.0

The required source changes are all fields, on the two leg configs:

```rust
let cfg = ProxySessionConfig {
    // ...existing fields...
    shape: None,                        // exactly 0.4.0 behaviour
    upstream_socket: None,              // exactly 0.4.0 behaviour
    upstream_transport_profile: None,   // exactly 0.4.0 behaviour
    upstream_installer: None,           // exactly 0.4.0 behaviour
};
// `ProxySessionConfig::default()` is unaffected.

let listener = ListenerConfig {
    // ...existing fields...
    transport_profile: None, // exactly 0.4.0 behaviour
    installer: None,         // exactly 0.4.0 behaviour
};
// `ListenerConfig` has no `Default`, so this one has no escape.
```

`ProxySessionConfig` is not `#[non_exhaustive]` and is not `Clone` — and
`ShapeProfile` is not `Copy` — so a config built per-connection from a template
clones the profile explicitly. Building with `qlog` adds `upstream_qlog: None`
and `qlog: None` to those literals.

A 0.3.x hook needs no changes: wrap it in `hook::LegacyProxyHook`. Written
against v2 directly, the two behaviours to know are that `Interest` is sampled
once at session start and decides what is parsed, and that a hook returning
`Some(bytes)` for a control message must declare `Interest::CONTROL` to be
asked at all.


## [0.3.0] - 2026-07-08

Draft-19 support, on top of 0.2.1 and nothing else.

Written retroactively from the `proxy-v0.3.0` tag. This section did not exist
while 0.3.0 was the published version, and its absence was read by later work
as evidence that 0.3.0 had never shipped — which is how the next release came
to be numbered 0.5.0 for a while. A published version with no section here is
not a bookkeeping detail; it is a missing release, to anyone reading the file
instead of the registry.

### Added

- Draft-19 across the proxy's per-draft modules, alongside drafts 07-18.
- `moqtap-client` and `moqtap-codec` dependencies bumped to their own
  draft-19 releases.

## [0.2.1] - 2026-05-13

Bumps `moqtap-client` to `0.2.1` to pick up the draft-16 / draft-17
`SetupComplete` `negotiated_version` fix. No proxy-side code changes.

### Changed

- `moqtap-client` dependency bumped from `0.2.0` to `0.2.1`.

## [0.2.0] - 2026-05-13

Adds MoQT draft-18 to the advertised ALPN set and unifies the client-facing
listener. Bumps `moqtap-codec` and `moqtap-client` to `0.2`.

### Added

- `moqt-18` ALPN is now advertised by `Listener`, so draft-18 clients can
  connect to the proxy without any further configuration.
- `AcceptedConn` enum returned by `Listener::accept` — carries either a
  raw `quinn::Connection` plus the negotiated ALPN, or a
  `wtransport::Connection` for WebTransport clients (behind the
  `webtransport` feature).
- `ProxyEvent::Connected` gains a `client_transport` field so observers
  can label per-client sessions by transport (`"QUIC"` /
  `"WebTransport"`).
- New integration tests `proxy_forward.rs` and `proxy_hook_rewrite.rs`
  covering end-to-end forwarding and `ProxyHook`-driven byte mutation
  against a fake relay; shared scaffolding lives in
  `tests/common/mod.rs`.

### Changed

- Unified the client-facing listener. `Listener` now owns a single
  `quinn::Endpoint` that advertises every supported MoQT draft ALPN
  (`moq-00`, `moqt-15`, `moqt-16`, `moqt-17`, `moqt-18`) plus `h3`
  (behind the `webtransport` feature). Each accepted connection is
  dispatched to raw QUIC or WebTransport based on the negotiated ALPN.
  No listener-mode configuration is required — clients pick their
  transport via ALPN.

### Removed

- `ListenerMode` enum and the `ProxyConfig::listener_mode` field.
- Standalone `WtListener` type. The unified `Listener` handles both
  transports when the `webtransport` feature is enabled.
- `ListenerConfig::alpn` field. ALPNs are derived from the supported
  drafts and the `webtransport` feature.

## [0.1.0] - 2026-04-16

Initial release — transparent MoQT intercepting proxy. Covers MoQT drafts
draft-07 through draft-17.

### Added

- Transparent proxy that forwards all streams and datagrams between client and relay
- Inline MoQT frame parsing for control messages, data stream headers, and datagrams
  via `moqtap-codec`'s runtime dispatch (`AnyControlMessage`,
  `AnySubgroupHeader`, `AnyFetchHeader`, `AnyDatagramHeader`). The draft
  used for parsing is selected from the observed setup exchange rather
  than a compile-time flag.
- `ProxyObserver` trait for structured event emission (11 event types)
- `ProxyHook` trait for optional frame mutation before forwarding
- QUIC listener (`Listener`) for accepting inbound client connections
- WebTransport support behind `webtransport` feature flag
- Upstream QUIC and WebTransport connection support (`UpstreamTransportType`)
- Control stream parser with draft-aware framing
- Data stream parser for subgroup and fetch stream headers
- Self-signed certificate generation behind `cert-gen` feature flag
- Graceful shutdown via `CancellationToken`

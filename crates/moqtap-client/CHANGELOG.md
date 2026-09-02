# Changelog

All notable changes to moqtap-client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-09-02

Dialling without knowing the draft, and two fetch-stream reports that were
declared and never delivered. Additive throughout: nothing public was removed,
no existing signature moved, and `^0.4.0` still resolves.

### Added

- **`transport::dial_quic`, with `QuicDialOptions` and `DialError`.** Offers a
  list of ALPNs and returns the connection together with the protocol the
  server selected. `Connection::connect` cannot answer that question — it
  derives its single ALPN from the draft it was handed — so a caller that did
  not know a peer's draft had to dial once per candidate. From draft-15 this is
  the whole of version negotiation: `ClientSetup` carries a parameter list and
  nothing else, and `DraftVersion::from_alpn` names the draft. The thirteen
  per-draft copies of the TLS and endpoint setup now delegate here.
- **`Connection::adopt`**, on every draft. Runs the setup handshake over a
  transport the caller already established, which is `dial_quic`'s other half:
  dial offering every ALPN, then bring the connection to the module the answer
  names.
- **`Connection::accept_fetch_stream`**, on every draft. The twin of
  `accept_subgroup_stream` for a fetch response stream, returning the decoded
  `AnyFetchHeader` and the framed stream behind it.

### Fixed

- **A fetch stream now reports the header it decoded.**
  `ClientEvent::FetchStreamHeader` has been defined on all thirteen drafts
  since this crate's first release and was emitted by nothing, so an observer
  learned that a fetch stream had opened and never what its header said, while
  every subgroup stream reported both. `DataStreamHeader` cannot stand in: its
  `header` field is an `AnySubgroupHeader`.
- **`FramedRecvStream::read_fetch_stream_header` works.** The typed accessor on
  drafts 15 through 19 failed on the first call against any stream whose header
  was not already buffered — which is every fresh stream, since it neither
  filled first nor recognised its own short read: the draft's `FetchHeader`
  decoder reports a truncated varint as `CodecError::VarInt(UnexpectedEnd)`
  where `AnyFetchHeader` reports the bare `CodecError::UnexpectedEnd` the loop
  matched on. On drafts 15 and 17 it also left the object reader unseeded, so a
  caller that got past that was refused by the next `read_fetch_object` with
  "fetch header not read yet" — about a header it had just read, with the bytes
  already spent and no way back.

## [0.4.0] - 2026-08-30

Control-plane and conformance release. Drafts 17, 18 and 19 gain the stream
topology those drafts specify — the control plane on a pair of unidirectional
streams, and every request on a bidirectional stream of its own — so a session
against a conforming peer completes for the first time. The client can now
serve requests a peer opens rather than only issue its own, and receive-side
rules that were read and silently accepted now close the session with the code
their draft names.

This is a behaviour change in a published crate. Traffic 0.3.0 accepted now
ends the session, calls that decided a field for the caller now take it as an
argument, and `TransportError` gained variants. Read `### Changed (breaking)`
before upgrading.

Not 0.3.1: under Cargo's 0.x rules the minor position is the major position, so
`^0.3.0` would hand these breaks to every current consumer under a patch
number.

### Added

- **Serving requests a peer opens**, on drafts 17, 18 and 19.
  `Connection::accept_request_stream` takes a stream the peer opened and reads
  the request off it, `recv_on_request_stream` routes by request kind, and the
  `respond_*` helpers write the answer back — accepting only a peer-opened
  stream, so an answer cannot be written onto a request this endpoint made.
  `accept_request_stream` takes `&mut self` and cannot run concurrently with
  other work on the connection; it is instead **cancel-safe**, so dropping the
  future mid-read (the ordinary outcome of `select!`) stashes the partially
  read stream and the next call resumes where it left off.
  `pending_inbound_count()` reports how many are waiting. A caller blocked in
  `recv_on_request_stream` is not accepting, and inbound streams queue behind
  it; one loop that never blocks indefinitely on a single read is the shape
  this asks for. Drafts 07 through 15 are untouched, because there a
  peer-opened bidirectional stream is the control plane and not a request.
- **A lifecycle for every request the peer sends.** SUBSCRIBE, FETCH,
  ANNOUNCE / PUBLISH_NAMESPACE, TRACK_STATUS and namespace subscriptions are
  recorded on arrival, answered once, and their answers kept — SUBSCRIBE on all
  thirteen drafts, PUBLISH on drafts 12 through 16, and the rest on 07 through
  16. A request the peer makes is kept as it arrived on drafts 14 through 19,
  and a cancellation now has an acceptance to revoke.
- **Drafts 12 and 13 can publish a track**, and draft-14's `publish` stops
  deciding four of the message's fields for the caller. An UNSUBSCRIBE ends a
  subscription this endpoint opened with PUBLISH on drafts 12 through 16.
- **Joining fetch across the range.** `absolute_joining_fetch` on drafts 15
  through 19, a `Connection` call that writes one on drafts 08 through 13
  (previously the message had to be built by hand and handed to
  `send_control`), and draft-14's pair. A joining fetch is judged against the
  subscription it names on drafts 08 through 19.
- **Fetch object streams.** `FramedSendStream::write_fetch_object` and
  `FramedRecvStream::read_fetch_object` on drafts 15 through 19, which had
  neither, `begin_fetch_objects` on drafts 18 and 19, and a publisher-side call
  to open the stream a FETCH's objects travel on, on all thirteen drafts.
- **Transport control on the QUIC streams.** `SendStream::reset(code)` and
  `set_priority`, `SendStream::stopped()` resolving when the send half stops
  being useful, `RecvStream::stop(code)` (instead of the hard-coded 0 a drop
  sends) and `RecvStream::received_reset()`, which waits for the peer's
  `RESET_STREAM` without reading a byte.
  `TransportError::StreamReset(u64)` and `Stopped(u64)` carry the peer's
  application error code as a typed value, and the `From<quinn::…>` conversions
  map onto them. `webtransport::WtSendStream::quic_stream()` borrows the
  underlying `quinn::SendStream`.
- **Draft-19 Setup Options that nothing read**: MAX_FILTER_RANGES (0x06) and
  MAX_REQUEST_UPDATES (0x08), with `Endpoint::filter_rejection` and the
  `FilterRejection` type that says why a request must be answered with a
  REQUEST_ERROR rather than a close. MAX_FILTER_RANGES defaults to 0, so a peer
  that sends no option forbids Range Filters entirely.
- **A session-close mapping on every draft**, where drafts 07 through 14 had
  none, with `EndpointError::session_error_code` on drafts 07 through 16 and
  `Connection::close_for_data_stream` on all thirteen. `recv_control` on drafts
  08, 09 and 10 now carries a refused control message to the wire instead of
  stopping at "this endpoint refused the frame" while the peer went on sending.
- **Stream plumbing for drafts 17, 18 and 19**: `peek_stream_type()`, which
  reads a unidirectional stream's leading type varint without consuming it;
  `CONTROL_STREAM_TYPE` (0x2F00); and `deferred_stream_count()`, reporting how
  many streams `connect` set aside while looking for the peer's control stream.
- `endpoint::Role` with `Endpoint::role()` on drafts 07 through 10;
  `subscribe_range` on the `Connection` and `Endpoint` of every draft;
  `Endpoint::receive_client_setup_and_respond_with` on drafts 07 through 10,
  the form that can answer a CLIENT_SETUP with a MAX_SUBSCRIBE_ID.
- Error variants for rules that had no way to be reported: `DuplicateTrackAlias`
  and `TrackAliasInUse`, `GoAwayUriAtServer` (drafts 08-16) and draft-07's
  distinct `GoAwayAtServer`, `PeerSubscribeIdNotIncreasing`,
  `ExtensionsOnNonNormalStatus` (drafts 15-16) and `PropertiesOnNonNormalStatus`
  (drafts 17-18), `RequestMessageOnControlStream`, `UnexpectedRequestUpdate`,
  `TrackPropertiesOnNonTrackStatus` and the `SetupError` variants
  `PathOverWebTransport`, `WrongDraftVersion` and `InvalidRole`. **Breaking**:
  no `EndpointError`, `ConnectionError` or `SetupError` is
  `#[non_exhaustive]`, so a `match` without a wildcard arm needs the new arms.

### Changed (breaking)

- **Drafts 17, 18 and 19 carry the control plane on a pair of unidirectional
  streams, and each request on a bidirectional stream of its own** whose
  response is read back off that same stream. This is the topology those drafts
  specify; the previous single bidirectional control stream could not complete
  a session against a conforming peer. Message placement follows: four message
  types on draft-19 and three on drafts 17 and 18 were being sent and expected
  on the wrong stream, and a NAMESPACE, NAMESPACE_DONE or PUBLISH_BLOCKED that
  arrives on the control stream is now session-fatal. `send_control` refuses
  the same messages it refuses to receive there, so the client cannot write a
  frame its own peer half would close the session over.
- **Draft-16 puts SUBSCRIBE_NAMESPACE on a bidirectional stream of its own**, in
  both directions, and a namespace subscription is withdrawn by closing that
  stream rather than by a message. The endpoint records the withdrawal.
- **Drafts 17, 18 and 19 record that a request was cancelled**, through
  `Endpoint::cancel_request` and `Connection::cancel_request_stream`. Five
  transitions that were named after messages those drafts do not have become
  one named after the act itself, and a peer's cancel is recorded from both
  places it can be observed.
- **A fetch's answer and its response stream settle independently**, and
  `FetchState` has a fifth variant for the ordering that used to be treated as
  impossible.
- **`TransportError` gained variants and is now `#[non_exhaustive]`**, and a
  read terminated by the peer's reset produces `StreamReset(code)` where it
  previously produced a generic error. An exhaustive match and a caller
  matching on the old error both break.
- **`Connection::send_datagram` refuses a header whose Object Status the
  framing that header names cannot carry**, on drafts 07 through 18, instead of
  sending the datagram with the status silently removed.
  `write_subgroup_header` can now fail before writing anything.
- Every draft's session-close table is exhaustive over `CodecError`, so a new
  codec variant fails to compile here rather than falling into a catch-all.
- Draft-14's `Endpoint::publish` and `Connection::publish` take a Track Alias;
  `send_publish_error` needs the PUBLISH it is rejecting; `pending_publish` and
  `pending_publish_count` on drafts 12 and 13 mean "arrived and not yet
  answered". `joining_fetch` on drafts 12 and 13 renames `joining_subscribe_id`
  to `joining_request_id`. Drafts 11, 12 and 13 name their two joining fetches
  instead of taking a Fetch Type, so the argument that could be wrong is gone.
- Draft-16's namespace-stream answer takes the code it refuses under, and
  draft-13's namespace-subscription and track-status flows are named for the
  messages draft-13 actually carries.
- MSRV is 1.88.

### Fixed

- **Roughly ninety receive-side rules that were read and accepted now close the
  session**, each with the code its own draft names. Among them: a control
  message whose declared Length disagrees with its fields, and a data stream or
  datagram announcing a Type its draft does not assign (every draft); an
  unknown control message type (drafts 15-19); a malformed Authorization Token
  (drafts 11-19); an unknown or out-of-scope Message Parameter (drafts 16-19);
  a value outside the range its draft states; an unassigned Fetch Type (drafts
  14-19); a subscription filter the draft requires a close over; a wrapped
  Object ID delta (drafts 18-19); extension headers or properties beside a
  non-Normal Object Status (drafts 15-18); a draft-19 status datagram carrying
  trailing bytes; an unknown stream type and a ContentExists of neither zero nor
  one (draft-07); and a Track Property whose value the draft answers with a
  close (drafts 16-19).
- **A session could not be closed while the Setup exchange was in progress**, on
  all thirteen drafts, and session-fatal errors on draft-19 did not close the
  QUIC connection at all. Drafts 17 and 18 reported control-stream violations to
  the caller and left the connection open.
- **Request identifiers were not held to the rules their drafts state.** A peer
  could open two requests under one Request ID on drafts 11 through 16 and the
  second took the first's place; a Request ID that was not the peer's to spend
  was refused while the session was left running; SUBSCRIBE_UPDATE and
  REQUEST_UPDATE spend an ID of their own on drafts 14, 15 and 16 and it was
  never checked; IDs increment by 2 and carry the sender's parity on drafts 11,
  12 and 13; the MAX_REQUEST_ID ceiling is exclusive on drafts 14, 15 and 16;
  and an advertised ceiling must strictly increase from its first value.
  A request at or past the ceiling this endpoint advertised now ends the
  session on drafts 07 through 16.
- **A subscription update arriving before its SUBSCRIBE was answered was
  refused**, on all thirteen drafts. A REQUEST_UPDATE on a SUBSCRIBE's or
  FETCH's stream could not be answered at all on drafts 17, 18 and 19; one from
  a side with no say over the request now closes the session on draft-19, only
  an established publication may be updated by its subscriber, and a refused
  update forces the status of the ending and no longer closes the stream its
  termination has to be written on.
- **GOAWAY was not held to its rules.** One carrying a New Session URI arriving
  at a server, and any GOAWAY at a draft-07 server, now end the session; so
  does a GOAWAY that repeats one already received, on all thirteen drafts.
  Draft-18 wrongly refused a GOAWAY on a peer-opened request stream.
- **Object framing on the write path.** A subgroup stream written on drafts 11,
  12 or 13 was unreadable whenever its header said objects carry extension
  headers; a subgroup header whose fields disagreed with its own type opened the
  stream anyway, on every draft; draft-14's `write_fetch_object` used the
  unchecked encoder; and the write path dropped a status or trusted a caller's
  length on drafts 07 through 13. The subgroup Object ID rule those drafts
  state once each is now applied as the stream is written.
- **Malformed tracks and duplicate objects.** An object claiming a track ended
  somewhere the track has already passed is refused on the six drafts that call
  that a protocol error; a track's objects may not be framed two ways, on the
  nine drafts that say so; a duplicate object contradicting the one before it
  never ends the session, on the nine drafts with a rule about it; and a
  malformed track takes its fetches with it, or is unsubscribed from, on the
  drafts whose answer to one is each of those.
- **The Setup exchange on drafts 07 through 10.** A setup parameter's value is
  read in the shape the wire gives it, a CLIENT_SETUP may grant the peer a
  subscribe budget, PATH is held to its one restriction, a SERVER_SETUP naming
  another draft's version is refused, and draft-07 requires a ROLE parameter.
  A SERVER_SETUP carrying PATH is refused on drafts 11 through 19, and a
  CLIENT_SETUP may carry MAX_REQUEST_ID on drafts 11 through 14.
- **Requests carried an empty parameter list whatever the caller passed.**
  SUBSCRIBE, FETCH, ANNOUNCE, TRACK_STATUS and namespace subscriptions on
  drafts 12, 13 and 14, and FETCH on drafts 15 through 19, now send what they
  were given. Draft-14's FETCH can say where its range ends, where it wrote
  group 0, object 0 whatever the caller asked for.
- **Overlapping namespace subscriptions are judged**, on all thirteen drafts,
  and a REQUEST_UPDATE can move a namespace subscription's prefix on drafts 18
  and 19, where the prefix it moves to is judged too. Draft-07 refuses a
  subscription for a namespace the peer has cancelled. Drafts 18 and 19 no
  longer accept a NAMESPACE, NAMESPACE_DONE, PUBLISH_BLOCKED or PUBLISH_SKIPPED
  before the answer that opens the stream.
- **Track aliases.** A publisher giving a second track an alias one of this
  session's live tracks already holds is refused on every draft, and the
  acceptance on drafts 13 and 14 no longer pins Track Alias to 0 while
  consulting no alias table.
- Drafts 17, 18 and 19 frame control messages with MoQT's variable-length
  integer rather than QUIC's.
- Around 250 doc comments quoted the wrong draft, truncated a sentence at a
  comma, or cited a section that does not exist — including 113 test comments
  citing draft-14 sections. Every cross-draft comparison now names the draft it
  compares with.
- The library builds warning-clean under any single `draftNN` feature, and
  every test target builds under every draft.

## [0.3.0] - 2026-07-08

Draft-19 support, on top of 0.2.1 and nothing else.

Written retroactively from the `client-v0.3.0` tag. The release went out
without a section here, and an undocumented published version reads, to anyone
working from this file rather than the registry, exactly like a version that
was never released — which is how `moqtap-proxy` came to number its next
release 0.5.0 for a while.

### Added

- Draft-19 across `draft19::*` — connection, endpoint, session state,
  subscription, fetch, publish, namespace and track-status flows — alongside
  drafts 07-18, and draft-19 arms in the `dispatch` facade.
- `moqtap-codec` bumped to its own draft-19 release.

## [0.2.1] - 2026-05-13

Bug-fix release. Fixes an incorrect `negotiated_version` value emitted by
the draft-16 and draft-17 `Connection::connect` flows.

### Fixed

- `draft16::Connection::connect` now emits `ClientEvent::SetupComplete`
  with `negotiated_version = 0xff000010` (draft-16).
- `draft17::Connection::connect` now emits `ClientEvent::SetupComplete`
  with `negotiated_version = 0xff000011` (draft-17).

## [0.2.0] - 2026-05-13

Adds MoQT draft-18 support and broadens the `dispatch` facade with
draft-agnostic helpers. Bumps `moqtap-codec` to `0.2`.

### Added

- New `draft18` module behind a `draft18` feature flag, with its own
  connection, endpoint, session state, per-flow state machines, event
  type, and observer trait. `all-drafts` now enables it.
- `dispatch::AnyClientConfig` and `dispatch::AnyTransportType` for
  draft-agnostic configuration; `AnyConnection::connect` constructs the
  per-draft `ClientConfig` from these and dispatches to the right draft.
- Draft-agnostic helpers on `AnyConnection`: `recv_and_dispatch`,
  `subscribe`, `unsubscribe`, `fetch`, `track_status`, `subscribe_namespace`,
  `subscribe_update`. Drafts that do not expose a given operation return
  an informative `AnyConnectionError`.
- `dispatch::NoOpObserver` for tests and bring-up code that don't need
  event delivery.
- Draft-18 client API: `Connection::subscribe_tracks` for the new
  `SUBSCRIBE_TRACKS` request type; `subscribe_namespace` no longer takes
  a `subscribe_options` argument.

### Changed

- `Connection::connect` (every draft) now buffers the CLIENT_SETUP /
  SERVER_SETUP / `SetupComplete` events that occur during the handshake
  and replays them to the observer when one is attached via
  `set_observer`. Without this, observers attached after `connect`
  returned would never see the setup exchange.

## [0.1.0] - 2026-04-16

Initial release. Covers MoQT drafts draft-07 through draft-17.

### Added

- Per-draft client modules for every MoQT draft from draft-07 through
  draft-17 (`draft07`..`draft17`), each with its own connection, endpoint,
  session state, per-flow state machines, event type, and observer trait
  (`moqtap_client::draft14::connection::Connection`, etc.). Each is behind
  its matching feature flag; `all-drafts` enables them all. `draft14` is the
  default.
- Session state machine: Connecting -> SetupExchange -> Active -> Draining -> Closed
- CLIENT_SETUP / SERVER_SETUP validation and version negotiation
- Request ID allocator with client/server parity enforcement (even/odd)
- Pure endpoint state machine with all subscribe, fetch, and namespace flows
- QUIC transport layer via quinn with TLS (rustls)
- Async `Connection` type: connect, accept, send/recv control messages
- Data stream support: subgroup streams, fetch streams, datagrams
- Framed message I/O with automatic varint-length parsing
- `dispatch` module with draft-agnostic entry-point types for downstream
  consumers: `AnyConnection`, `AnyClientEvent`, `AnyConnectionObserver`.
  Observer attachment adapts the unified observer into the per-draft trait
  on the inner connection.

# Changelog

All notable changes to moqtap-client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-09-21

### Added

- **`draft21`**, a module and a feature, in `all-drafts`. Draft-21 is draft-20's wire format under new section numbers, so everything a caller does on draft-20 it does identically here.
- `AnyClientEvent::control_frame()`, answering with a `ControlFrame<'_>`: one control message lifted out of whichever draft's event carried it, with the draft, the direction, the decoded message and the raw bytes. An observer holding an `AnyClientEvent` could otherwise read only `draft()` without writing its own cascade over every draft - the duplication this module exists to hold in one place. `ControlFrame` is `#[non_exhaustive]`, and `outbound` is a `bool` rather than a direction enum because each draft declares its own `Direction` and a shared one would exist only to be converted into.

### Changed

- **Breaking.** `FetchRange::location_filter` and `SubscribeRange::location_filter` are now `location_filter_draft20` and `location_filter_draft21`. The value they build is a per-draft type - each draft's `fill` module declares its own `LocationFilter` - so one name could serve one draft and cannot serve two.
- **Breaking.** `DraftVersion` gains `Draft21` (see `moqtap-codec`), which stops a downstream `match` over its variants compiling.

## [0.6.0] - 2026-09-20

The draft-agnostic facade gains a data plane and a peer-initiated request direction, and `AnyConnectionError` gains the reason a call stopped rather than only the text to print.

### Added

- **A data plane on `AnyConnection`**: `open_subgroup`, `accept_subgroup`, `accept_fetch`, `write_object`, `read_object` and `finish`, over `AnySubgroupWriter`, `AnySubgroupReader`, `AnyFetchReader`, `AnyObject` and `AnyFetchObject`. `Draft16FetchStream` carries the header inheritance draft-16's codec leaves to its caller.
- **Peer-initiated requests**: `recv_inbound` returns an `AnyArrival`, with `accept_subscribe` and `recv_response`. `AnyInboundRequest` is `#[must_use]` and refuses the request when dropped on drafts 17 and later.
- **Requests whose halves cannot come apart**: `subscribe_range` takes a `SubscribeRange` and `SubscribeEnd` in absolute terms and derives the delta the late drafts want, refusing `ThroughObject` on the twelve drafts that cannot express it; `fetch_joining` takes a `JoiningStart` so the Fetch Type and its value are one value. With `publish_namespace`, `publish_namespace_done` and `fetch_group_order`.
- **Setup over a transport the caller dialled**: `adopt` and `adopt_offering`, with `server_setup()`, `server_setup_raw()` and `negotiated_version()` to read what was agreed. `next_free_track_alias` keeps `subscribe` at one signature across the draft-12 alias-ownership split.
- **`dispatch::ErrorCause` and `AnyConnectionError::cause`** — ten variants covering the ten every draft's `ConnectionError` shares, plus the rules a draft states above its decoder. `Codec` carries the session error code the negotiated draft's own text names, so a caller need not hold fourteen tables.
- **`above_codec_rules`**, naming the rules an endpoint enforces that its own decoder cannot see — each stated about a frame that decodes perfectly well, so none ever reached `CodecError` and a caller reading only that channel found the peer blameless. With `AboveCodecRule`, `CodecRule`, `RuleCitation`, `EndpointFault` and `DraftSpecificCause`.
- **`EndpointError::fault`** on all fourteen drafts, dividing that type by where the variant is raised: reading what the peer sent, writing, or refusing to. Most of it is the peer's doing and was filed against this build's own state machine.
- **`Connection::draft_specific_cause` and `::codec_session_error_code` are public** on all fourteen drafts.
- **WebTransport is dialable before a draft is chosen**: `dial_webtransport` and `dial_webtransport_to`, the counterparts to the QUIC dials. Draft auto-detect could dial raw QUIC only, so it timed out against a WebTransport-only relay.
- **Transport observability**: `QuicTarget` and `dial_quic_to`; `Transport::closed()` and `peer_certificates()`; `CertificateHook` and `CertificateLog`; `HandshakeFailure` and `CodeSpace`; `TLS13_CIPHER_SUITES` and `show_cipher_suite`; `QuicDialOptions::new` with builders.
- **`transport::DialPhase`, `DialError::phase` and `::is_local`.** A dial is four stages and only the last involves the peer; `is_local` true means nothing left this machine, so the failure is not evidence about the peer.
- **`AnyConnectionError::is_local`, `::message` and `::facade`.**
- **A `wt-protocol` feature**, reading the CONNECT response for the server's half of WebTransport version negotiation. Off by default and outside `all-drafts`: it requires a patched `wtransport` and does not build without one, so the crates.io build is unaffected.

### Changed

- **Breaking. `AnyConnectionError` is no longer a tuple struct.** Construct with `::facade(msg)` or `From` on a draft's `ConnectionError`; read with `::message()` in place of `.0`. `Display` is unchanged. It now derives `Clone`, `PartialEq` and `Eq`.
- **Breaking. `QuicDialOptions` gains three public fields** — `wt_protocols`, `on_peer_certificates` and `cipher_suites` — so an existing struct-literal construction stops compiling. The builders and functional-update syntax avoid it.
- **Breaking. `TransportError` is `#[non_exhaustive]`** and gains `Handshake(HandshakeFailure)` and `SessionClosed { code, reason }`. The attribute alone ends a downstream exhaustive match.
- **Breaking. `transport::DialError::LocalSocket`.** A socket this machine would not open was spelled `InvalidAddress`, and on the WebTransport arm it arrived as `TransportError::Connect`, which `is_local` answers false for — a socket this side could not open, filed against the relay. Both dials raise `LocalSocket` now.
- **Breaking, narrowly. `EndpointError::MaxRequestIdWouldNotIncrease`** (drafts 11-16) and `::MaxSubscribeIdWouldNotIncrease` (07-10). Refusing to advertise a ceiling that does not increase raised the same variant a peer's decreasing MAX_REQUEST_ID raises, which `session_error_code` answers `PROTOCOL_VIOLATION`. The send side has its own variant and answers `None`, because nothing reached the wire.
- `dial_quic` no longer rewrites a peer's refusal while naming the address it came from, so the typed `HandshakeFailure` survives a multi-address dial.
- `SubscriptionStateMachine::on_publish_done` is idempotent on `Done` across all fourteen drafts. The end of a subscription is two events that can arrive in either order, so refusing the second read a conforming relay's last message as a protocol error against this endpoint's own bookkeeping.

## [0.5.0] - 2026-09-03

### Added

- **`draft20`**, a feature and a module, with the same files every other draft has plus one, and in `all-drafts`. The ALPN is `moqt-20`; as on every draft from 15, there is no version on the wire and the ALPN is the whole of version negotiation.
- **`draft20::fill`**, the module draft-20 needs and no earlier draft does. `LocationFilter` builds the `LOCATION_FILTER` parameter (Section 5.1.2) in each of the five shapes the draft defines, and `FillParameters` builds the `FILL_PARAMETERS` block (Section 10.2.15) whose presence on a SUBSCRIBE or a REQUEST_UPDATE asks the publisher for a fill fetch stream. Every value is handed to the codec's own decoder before it is returned, so an encoder that drifted from the decoder errors here rather than putting a frame on the wire.
- **`Connection::accept_fill_stream`** and the endpoint's fill accounting — `fill_requested`, `open_fill_streams`, `fill_streams_opened`, `on_fill_stream_opened`, `on_fill_stream_ended`. A fill fetch stream is framed exactly as a fetch response and differs only in what its Request ID names: the SUBSCRIBE that asked for the fill, not a FETCH, so a client that knew only about fetches would answer that header with "unknown request".
- **`ClientEvent::PublishStateNotify`** and **`StreamKind::Fill`**. The notify is the decoded form of the new PUBLISH_STATE_NOTIFY (Section 10.10); the stream kind is what keeps a subscription's fill from being counted as a fetch the application never made.
- **`Endpoint::receive_publish_state_notify`**, with the two refusals Section 10.10 answers with a session close: a notify for a request that is not a subscription, and one from the subscriber rather than the publisher. It is unilateral, so it spends no `MAX_REQUEST_UPDATES` credit and leaves nothing owed in reply.
- **`Endpoint::fetch_range` and `Connection::fetch_range`**, which put a `LocationFilter` into a FETCH's parameter list at the position ascending Parameter Type order requires.
- **`dispatch::FetchRange` and `dispatch::FetchEnd`**, the draft-agnostic shape of a fetch's range; see **Changed** for what they replaced and why.
- **`draft20::fill::group_order` and `FillParameters::with_group_order`.** Section 10.2.8: a `GROUP_ORDER` inside `FILL_PARAMETERS` "governs the fill fetch stream and its ordering". Nothing on the data stream carries it, so a subscriber has to resolve it from what it sent — the nested value, else the subscription's own, else Ascending, which is the Section 10.2.8 FETCH default and a choice the draft does not make for a fill. `Endpoint::fill_group_order` reports the resolved value.

### Changed

- **Breaking.** `dispatch::AnyConnection` and `dispatch::AnyRequest` gain a draft-20 variant, and neither is `#[non_exhaustive]`, so a downstream `match` enumerating their variants stops compiling. `AnyClientEvent` is `#[non_exhaustive]` and is unaffected.
- **Breaking.** `AnyConnection::fetch` takes a `FetchRange` and is wired for draft-20, because the drafts stopped agreeing about what the fourth of its four location varints means: draft-19's `end_object` is "the last Object, plus 1; or 0 to indicate the entire Group" and draft-20's is the last Object itself, so one number at a draft-agnostic boundary would have meant one of the two with nothing to say which. `FetchRange` says it instead — `FetchEnd::Object(n)` is inclusive, `n` is fetched; `FetchEnd::EntireGroup` is draft-19's `0` spelled out; `end_group` is absolute. `FetchRange::inline_end_object` converts for drafts 14 through 19 and is **the only place the `+ 1` lives**; `FetchRange::location_filter` converts for draft-20 and adds nothing. Drafts 14 through 19 send exactly the bytes they sent before, which `tests/a_fetch_range_means_one_thing_on_every_draft.rs` pins per draft. Porting: `end_object` of `N` becomes `FetchEnd::Object(N - 1)`, and `0` becomes `FetchEnd::EntireGroup`.
- **`draft20`'s FETCH takes a parameter list where draft-19's took four location varints.** Section 10.13 deleted the `Fetch Type` field, both variant structures and the whole joining mechanism; the Track Namespace and Track Name are inline and the range travels in `LOCATION_FILTER`. So `Endpoint::fetch` and `Connection::fetch` have the same three arguments `subscribe` does, and `joining_fetch` / `absolute_joining_fetch` do not exist on this draft. This is a difference between `draft19` and `draft20`, not a change to `draft19`.
- **Ranges are inclusive at both ends** (Sections 5.1.2, 10.13, 10.14). Draft-19's fetch end was "the last Object, plus 1; or 0 to indicate the entire Group"; both conventions are deleted, the bytes are identical between the two drafts and nothing on the wire distinguishes them, so a call ported from draft-19 with its `+ 1` intact fetches one object too many. `LocationFilter` carries the warning at each constructor.
- **`Connection::accept_fill_stream` starts the returned stream's object reader**, so fill objects can be read without a `begin_fetch_objects` call. It can do what `accept_fetch_stream` cannot because the endpoint kept the fill's Group Order when the subscription asked for it. A reader started in the wrong direction does not fail — it reports Group IDs that walk the wrong way — so this is the difference between an error and a wrong answer.
- **The 41 cross-draft rejection arms in `draft07`..`draft20`'s `connection` modules are no longer gated on a `cfg` naming the other thirteen drafts.** Each is now `#[allow(unreachable_patterns)] _ =>`, the form `moqtap-proxy/src/session.rs` and `moqtap-codec/src/dispatch.rs` already use. Behaviour is unchanged under every feature set — the arms match a value the same function has just decoded through its own `DraftVersion`, so 34 of the 41 cannot be reached at run time at all — but the list that had to be edited in 13 files whenever a draft was added, and was wrong in 8 places when it was not, is gone. **This removes a compile-time signal as well as a chore**: the `cfg` form errored when a draft was omitted from the list, though only under feature sets that enable no listed draft, which is not a combination CI or anyone else builds. `scripts/check-draft-cfg.py` replaces it with a check that reads the tree: a draft module holding fewer of these arms than its predecessor is a dropped arm and fails the gate.

### Fixed

- **The per-draft rejection `cfg(any(feature = "draftNN", ...))` lists were short by one draft in eight places**, so `--features draft19,draft20` did not compile: five wildcard arms in `draft20::connection` named `draft07` through `draft18` and never gained `draft19`, and three in `draft11` through `draft13` never gained `draft20`. A single-draft build cannot see this — the arm is compiled out — and the only two-draft row CI ran was `draft07,draft20`, which every short list happens to name. `scripts/check-draft-cfg.py` reads every such list in the workspace and refuses a short one; CI gained a `draft19,draft20` row beside the existing `draft07,draft20`. This crate's 41 lists have since been replaced outright — see **Changed** — so six remain for that rule to read. The same sweep found a ninth site in `moqtap-proxy`'s test suite, recorded in that crate's changelog.
- The `AnySubgroupHeader` binding in the `draft18`, `draft19` and `draft20` modules was named `d17`, copied forward three times.

### Notes

- No existing draft's module changed, and draft-20 is not a default anywhere: it is not the interop target — interop ran against draft-18 and the editors plan draft-22 next — so nothing here promotes it to a connection default, an advertised-preferred version or an auto-selected draft.
- **`tests/uni_control_plane.rs` covers draft-20.** It stopped at draft-19, because its shared macro imported `FetchPayload`, matched on it, and drove both joining fetches — none of which exists on this draft. FETCH is now two per-draft functions handed to the gate macro, the treatment SUBSCRIBE_NAMESPACE has had since draft-18 split it; the enforcing peer and 23 of the 25 gates are unchanged, and drafts 17, 18 and 19 generate the same 26 tests they did before. Draft-20's row sweeps `fetch`, `fetch_range` — whose rendering carries the decoded `LOCATION_FILTER`, so a range ported from draft-19 with its `+ 1` fails rather than fetching one object too many — and a SUBSCRIBE carrying `FILL_PARAMETERS`, which is what replaced the joining fetch. Its refusal gate opens a bidirectional stream with a PUBLISH_STATE_NOTIFY rather than the SUBSCRIBE_OK the other three use: Section 10.10 puts the notify on a subscription's existing stream, and it carries no Request ID and answers nothing, so it is the message most easily mistaken for one that opens a stream.
- `tests/draft20_fill_and_state_notify.rs` and `tests/draft20_fill_stream_objects.rs` remain the loopbacks for what the new draft added at the object level — the fill stream's own bytes, the `FILL_PARAMETERS` block, and the notify arriving on a live subscription. The second one delivers Objects on fill fetch streams and holds the Section 11.4.4.1 delta rules, including the `0x08` case where the Object ID runs on across a Group boundary rather than restarting.
- `INCLUDE_PROPERTIES` (0x35) does not reach a fill fetch stream's Objects. Section 10.2.21 makes it govern the **Track Properties** in an OK message, a fill fetch stream has no OK message, and the parameter is absent from the Section 10.2.15 Table 6 list so it cannot be nested in `FILL_PARAMETERS`. Object Properties on a fill Object answer to Serialization Flags bit 0x20 alone.

## [0.4.1] - 2026-09-02

### Added

- **`transport::dial_quic`, with `QuicDialOptions` and `DialError`.** Offers a list of ALPNs and returns the connection together with the protocol the server selected. `Connection::connect` cannot answer that question — it derives its single ALPN from the draft it was handed — so a caller that did not know a peer's draft had to dial once per candidate. From draft-15 this is the whole of version negotiation: `ClientSetup` carries a parameter list and nothing else, and `DraftVersion::from_alpn` names the draft. The thirteen per-draft copies of the TLS and endpoint setup now delegate here.
- **`Connection::adopt`**, on every draft. Runs the setup handshake over a transport the caller already established, which is `dial_quic`'s other half: dial offering every ALPN, then bring the connection to the module the answer names.
- **`Connection::accept_fetch_stream`**, on every draft. The twin of `accept_subgroup_stream` for a fetch response stream, returning the decoded `AnyFetchHeader` and the framed stream behind it.

### Fixed

- **A fetch stream now reports the header it decoded.** `ClientEvent::FetchStreamHeader` has been defined on all thirteen drafts since this crate's first release and was emitted by nothing, so an observer learned that a fetch stream had opened and never what its header said, while every subgroup stream reported both. `DataStreamHeader` cannot stand in: its `header` field is an `AnySubgroupHeader`.
- **`FramedRecvStream::read_fetch_stream_header` works.** The typed accessor on drafts 15 through 19 failed on the first call against any stream whose header was not already buffered — which is every fresh stream, since it neither filled first nor recognised its own short read: the draft's `FetchHeader` decoder reports a truncated varint as `CodecError::VarInt(UnexpectedEnd)` where `AnyFetchHeader` reports the bare `CodecError::UnexpectedEnd` the loop matched on. On drafts 15 and 17 it also left the object reader unseeded, so a caller that got past that was refused by the next `read_fetch_object` with "fetch header not read yet" — about a header it had just read, with the bytes already spent and no way back.

### Notes

- Additive throughout: nothing public was removed, no existing signature moved, and `^0.4.0` still resolves.

## [0.4.0] - 2026-08-30

### Added

- **Serving requests a peer opens**, on drafts 17, 18 and 19. `Connection::accept_request_stream` takes a stream the peer opened and reads the request off it, `recv_on_request_stream` routes by request kind, and the `respond_*` helpers write the answer back — accepting only a peer-opened stream, so an answer cannot be written onto a request this endpoint made. `accept_request_stream` takes `&mut self` and cannot run concurrently with other work on the connection; it is instead **cancel-safe**, so dropping the future mid-read (the ordinary outcome of `select!`) stashes the partially read stream and the next call resumes where it left off, and `pending_inbound_count()` reports how many are waiting. A caller blocked in `recv_on_request_stream` is not accepting, and inbound streams queue behind it; one loop that never blocks indefinitely on a single read is the shape this asks for. Drafts 07 through 15 are untouched, because there a peer-opened bidirectional stream is the control plane and not a request.
- **A lifecycle for every request the peer sends.** SUBSCRIBE, FETCH, ANNOUNCE / PUBLISH_NAMESPACE, TRACK_STATUS and namespace subscriptions are recorded on arrival, answered once, and their answers kept — SUBSCRIBE on all thirteen drafts, PUBLISH on drafts 12 through 16, and the rest on 07 through 16. A request the peer makes is kept as it arrived on drafts 14 through 19, and a cancellation now has an acceptance to revoke.
- **Drafts 12 and 13 can publish a track**, and draft-14's `publish` stops deciding four of the message's fields for the caller. An UNSUBSCRIBE ends a subscription this endpoint opened with PUBLISH on drafts 12 through 16.
- **Joining fetch across the range.** `absolute_joining_fetch` on drafts 15 through 19, a `Connection` call that writes one on drafts 08 through 13 (previously the message had to be built by hand and handed to `send_control`), and draft-14's pair. A joining fetch is judged against the subscription it names on drafts 08 through 19.
- **Fetch object streams.** `FramedSendStream::write_fetch_object` and `FramedRecvStream::read_fetch_object` on drafts 15 through 19, which had neither, `begin_fetch_objects` on drafts 18 and 19, and a publisher-side call to open the stream a FETCH's objects travel on, on all thirteen drafts.
- **Transport control on the QUIC streams.** `SendStream::reset(code)` and `set_priority`, `SendStream::stopped()` resolving when the send half stops being useful, `RecvStream::stop(code)` (instead of the hard-coded 0 a drop sends) and `RecvStream::received_reset()`, which waits for the peer's `RESET_STREAM` without reading a byte. `TransportError::StreamReset(u64)` and `Stopped(u64)` carry the peer's application error code as a typed value, and the `From<quinn::…>` conversions map onto them. `webtransport::WtSendStream::quic_stream()` borrows the underlying `quinn::SendStream`.
- **Draft-19 Setup Options that nothing read**: MAX_FILTER_RANGES (0x06) and MAX_REQUEST_UPDATES (0x08), with `Endpoint::filter_rejection` and the `FilterRejection` type that says why a request must be answered with a REQUEST_ERROR rather than a close. MAX_FILTER_RANGES defaults to 0, so a peer that sends no option forbids Range Filters entirely.
- **A session-close mapping on every draft**, where drafts 07 through 14 had none, with `EndpointError::session_error_code` on drafts 07 through 16 and `Connection::close_for_data_stream` on all thirteen. `recv_control` on drafts 08, 09 and 10 now carries a refused control message to the wire instead of stopping at "this endpoint refused the frame" while the peer went on sending.
- **Stream plumbing for drafts 17, 18 and 19**: `peek_stream_type()`, which reads a unidirectional stream's leading type varint without consuming it; `CONTROL_STREAM_TYPE` (0x2F00); and `deferred_stream_count()`, reporting how many streams `connect` set aside while looking for the peer's control stream.
- `endpoint::Role` with `Endpoint::role()` on drafts 07 through 10; `subscribe_range` on the `Connection` and `Endpoint` of every draft; `Endpoint::receive_client_setup_and_respond_with` on drafts 07 through 10, the form that can answer a CLIENT_SETUP with a MAX_SUBSCRIBE_ID.
- Error variants for rules that had no way to be reported: `DuplicateTrackAlias` and `TrackAliasInUse`, `GoAwayUriAtServer` (drafts 08-16) and draft-07's distinct `GoAwayAtServer`, `PeerSubscribeIdNotIncreasing`, `ExtensionsOnNonNormalStatus` (drafts 15-16) and `PropertiesOnNonNormalStatus` (drafts 17-18), `RequestMessageOnControlStream`, `UnexpectedRequestUpdate`, `TrackPropertiesOnNonTrackStatus` and the `SetupError` variants `PathOverWebTransport`, `WrongDraftVersion` and `InvalidRole`.

### Changed

- **Breaking.** Drafts 17, 18 and 19 carry the control plane on a pair of unidirectional streams, and each request on a bidirectional stream of its own whose response is read back off that same stream. This is the topology those drafts specify; the previous single bidirectional control stream could not complete a session against a conforming peer, so such a session completes for the first time. Message placement follows: four message types on draft-19 and three on drafts 17 and 18 were being sent and expected on the wrong stream, and a NAMESPACE, NAMESPACE_DONE or PUBLISH_BLOCKED that arrives on the control stream is now session-fatal. `send_control` refuses the same messages it refuses to receive there, so the client cannot write a frame its own peer half would close the session over.
- **Breaking.** Draft-16 puts SUBSCRIBE_NAMESPACE on a bidirectional stream of its own, in both directions, and a namespace subscription is withdrawn by closing that stream rather than by a message. The endpoint records the withdrawal.
- **Breaking.** Drafts 17, 18 and 19 record that a request was cancelled, through `Endpoint::cancel_request` and `Connection::cancel_request_stream`. Five transitions that were named after messages those drafts do not have become one named after the act itself, and a peer's cancel is recorded from both places it can be observed.
- **Breaking.** A fetch's answer and its response stream settle independently, and `FetchState` has a fifth variant for the ordering that used to be treated as impossible.
- **Breaking.** `TransportError` gained variants and is now `#[non_exhaustive]`, and a read terminated by the peer's reset produces `StreamReset(code)` where it previously produced a generic error. An exhaustive match and a caller matching on the old error both break.
- **Breaking.** `Connection::send_datagram` refuses a header whose Object Status the framing that header names cannot carry, on drafts 07 through 18, instead of sending the datagram with the status silently removed. `write_subgroup_header` can now fail before writing anything.
- **Breaking.** Every draft's session-close table is exhaustive over `CodecError`, so a new codec variant fails to compile here rather than falling into a catch-all.
- **Breaking.** Draft-14's `Endpoint::publish` and `Connection::publish` take a Track Alias; `send_publish_error` needs the PUBLISH it is rejecting; `pending_publish` and `pending_publish_count` on drafts 12 and 13 mean "arrived and not yet answered". `joining_fetch` on drafts 12 and 13 renames `joining_subscribe_id` to `joining_request_id`. Drafts 11, 12 and 13 name their two joining fetches instead of taking a Fetch Type, so the argument that could be wrong is gone.
- **Breaking.** Draft-16's namespace-stream answer takes the code it refuses under, and draft-13's namespace-subscription and track-status flows are named for the messages draft-13 actually carries.
- **Breaking.** No `EndpointError`, `ConnectionError` or `SetupError` is `#[non_exhaustive]`, so a `match` without a wildcard arm needs the new arms listed under **Added**.
- **Breaking.** MSRV is 1.88.

### Fixed

- **Roughly ninety receive-side rules that were read and accepted now close the session**, each with the code its own draft names. Among them: a control message whose declared Length disagrees with its fields, and a data stream or datagram announcing a Type its draft does not assign (every draft); an unknown control message type (drafts 15-19); a malformed Authorization Token (drafts 11-19); an unknown or out-of-scope Message Parameter (drafts 16-19); a value outside the range its draft states; an unassigned Fetch Type (drafts 14-19); a subscription filter the draft requires a close over; a wrapped Object ID delta (drafts 18-19); extension headers or properties beside a non-Normal Object Status (drafts 15-18); a draft-19 status datagram carrying trailing bytes; an unknown stream type and a ContentExists of neither zero nor one (draft-07); and a Track Property whose value the draft answers with a close (drafts 16-19).
- **A session could not be closed while the Setup exchange was in progress**, on all thirteen drafts, and session-fatal errors on draft-19 did not close the QUIC connection at all. Drafts 17 and 18 reported control-stream violations to the caller and left the connection open.
- **Request identifiers were not held to the rules their drafts state.** A peer could open two requests under one Request ID on drafts 11 through 16 and the second took the first's place; a Request ID that was not the peer's to spend was refused while the session was left running; SUBSCRIBE_UPDATE and REQUEST_UPDATE spend an ID of their own on drafts 14, 15 and 16 and it was never checked; IDs increment by 2 and carry the sender's parity on drafts 11, 12 and 13; the MAX_REQUEST_ID ceiling is exclusive on drafts 14, 15 and 16; and an advertised ceiling must strictly increase from its first value. A request at or past the ceiling this endpoint advertised now ends the session on drafts 07 through 16.
- **A subscription update arriving before its SUBSCRIBE was answered was refused**, on all thirteen drafts. A REQUEST_UPDATE on a SUBSCRIBE's or FETCH's stream could not be answered at all on drafts 17, 18 and 19; one from a side with no say over the request now closes the session on draft-19, only an established publication may be updated by its subscriber, and a refused update forces the status of the ending and no longer closes the stream its termination has to be written on.
- **GOAWAY was not held to its rules.** One carrying a New Session URI arriving at a server, and any GOAWAY at a draft-07 server, now end the session; so does a GOAWAY that repeats one already received, on all thirteen drafts. Draft-18 wrongly refused a GOAWAY on a peer-opened request stream.
- **Object framing on the write path.** A subgroup stream written on drafts 11, 12 or 13 was unreadable whenever its header said objects carry extension headers; a subgroup header whose fields disagreed with its own type opened the stream anyway, on every draft; draft-14's `write_fetch_object` used the unchecked encoder; and the write path dropped a status or trusted a caller's length on drafts 07 through 13. The subgroup Object ID rule those drafts state once each is now applied as the stream is written.
- **Malformed tracks and duplicate objects.** An object claiming a track ended somewhere the track has already passed is refused on the six drafts that call that a protocol error; a track's objects may not be framed two ways, on the nine drafts that say so; a duplicate object contradicting the one before it never ends the session, on the nine drafts with a rule about it; and a malformed track takes its fetches with it, or is unsubscribed from, on the drafts whose answer to one is each of those.
- **The Setup exchange on drafts 07 through 10.** A setup parameter's value is read in the shape the wire gives it, a CLIENT_SETUP may grant the peer a subscribe budget, PATH is held to its one restriction, a SERVER_SETUP naming another draft's version is refused, and draft-07 requires a ROLE parameter. A SERVER_SETUP carrying PATH is refused on drafts 11 through 19, and a CLIENT_SETUP may carry MAX_REQUEST_ID on drafts 11 through 14.
- **Requests carried an empty parameter list whatever the caller passed.** SUBSCRIBE, FETCH, ANNOUNCE, TRACK_STATUS and namespace subscriptions on drafts 12, 13 and 14, and FETCH on drafts 15 through 19, now send what they were given. Draft-14's FETCH can say where its range ends, where it wrote group 0, object 0 whatever the caller asked for.
- **Overlapping namespace subscriptions are judged**, on all thirteen drafts, and a REQUEST_UPDATE can move a namespace subscription's prefix on drafts 18 and 19, where the prefix it moves to is judged too. Draft-07 refuses a subscription for a namespace the peer has cancelled. Drafts 18 and 19 no longer accept a NAMESPACE, NAMESPACE_DONE, PUBLISH_BLOCKED or PUBLISH_SKIPPED before the answer that opens the stream.
- **Track aliases.** A publisher giving a second track an alias one of this session's live tracks already holds is refused on every draft, and the acceptance on drafts 13 and 14 no longer pins Track Alias to 0 while consulting no alias table.
- Drafts 17, 18 and 19 frame control messages with MoQT's variable-length integer rather than QUIC's.
- Around 250 doc comments quoted the wrong draft, truncated a sentence at a comma, or cited a section that does not exist — including 113 test comments citing draft-14 sections. Every cross-draft comparison now names the draft it compares with.
- The library builds warning-clean under any single `draftNN` feature, and every test target builds under every draft.

### Notes

- **Not 0.3.1.** This is a behaviour change in a published crate — traffic 0.3.0 accepted now ends the session, calls that decided a field for the caller now take it as an argument, and `TransportError` gained variants, so read **Changed** before upgrading — and under Cargo's 0.x rules the minor position is the major position, so `^0.3.0` would hand these breaks to every current consumer under a patch number.

## [0.3.0] - 2026-07-08

### Added

- Draft-19 across `draft19::*` — connection, endpoint, session state, subscription, fetch, publish, namespace and track-status flows — alongside drafts 07-18, and draft-19 arms in the `dispatch` facade. It sits on top of 0.2.1 and nothing else.
- `moqtap-codec` bumped to its own draft-19 release.

### Notes

- Written retroactively from the `client-v0.3.0` tag. The release went out without a section here, and an undocumented published version reads, to anyone working from this file rather than the registry, exactly like a version that was never released — which is how `moqtap-proxy` came to number its next release 0.5.0 for a while.

## [0.2.1] - 2026-05-13

### Fixed

- `draft16::Connection::connect` emitted an incorrect `negotiated_version`, and now emits `ClientEvent::SetupComplete` with `negotiated_version = 0xff000010` (draft-16).
- `draft17::Connection::connect` emitted an incorrect `negotiated_version`, and now emits `ClientEvent::SetupComplete` with `negotiated_version = 0xff000011` (draft-17).

## [0.2.0] - 2026-05-13

### Added

- New `draft18` module behind a `draft18` feature flag, with its own connection, endpoint, session state, per-flow state machines, event type, and observer trait. `all-drafts` now enables it.
- `dispatch::AnyClientConfig` and `dispatch::AnyTransportType` for draft-agnostic configuration; `AnyConnection::connect` constructs the per-draft `ClientConfig` from these and dispatches to the right draft.
- Draft-agnostic helpers on `AnyConnection`: `recv_and_dispatch`, `subscribe`, `unsubscribe`, `fetch`, `track_status`, `subscribe_namespace`, `subscribe_update`. Drafts that do not expose a given operation return an informative `AnyConnectionError`.
- `dispatch::NoOpObserver` for tests and bring-up code that don't need event delivery.
- Draft-18 client API: `Connection::subscribe_tracks` for the new `SUBSCRIBE_TRACKS` request type; `subscribe_namespace` no longer takes a `subscribe_options` argument.

### Changed

- `Connection::connect` (every draft) now buffers the CLIENT_SETUP / SERVER_SETUP / `SetupComplete` events that occur during the handshake and replays them to the observer when one is attached via `set_observer`. Without this, observers attached after `connect` returned would never see the setup exchange.
- `moqtap-codec` is bumped to `0.2`.

## [0.1.0] - 2026-04-16

### Added

- Initial release, covering MoQT drafts draft-07 through draft-17: a per-draft client module for each (`draft07`..`draft17`), with its own connection, endpoint, session state, per-flow state machines, event type, and observer trait (`moqtap_client::draft14::connection::Connection`, etc.). Each is behind its matching feature flag; `all-drafts` enables them all, and `draft14` is the default.
- Session state machine — Connecting -> SetupExchange -> Active -> Draining -> Closed — with CLIENT_SETUP / SERVER_SETUP validation and version negotiation, a Request ID allocator that enforces client/server parity (even/odd), and a pure endpoint state machine carrying all subscribe, fetch, and namespace flows.
- QUIC transport layer via quinn with TLS (rustls), under an async `Connection` type: connect, accept, send/recv control messages.
- Data stream support — subgroup streams, fetch streams, datagrams — with framed message I/O that parses varint lengths automatically.
- `dispatch` module with draft-agnostic entry-point types for downstream consumers: `AnyConnection`, `AnyClientEvent`, `AnyConnectionObserver`. Observer attachment adapts the unified observer into the per-draft trait on the inner connection.

#![deny(missing_docs)]

//! MoQT intercepting proxy — transparent stream forwarding with inline
//! frame parsing, observation and impairment.
//!
//! This crate provides a transparent proxy that sits between a MoQT client
//! and relay, forwarding all bytes bidirectionally while parsing MoQT frames
//! inline to emit structured events. It does not participate in MoQT state
//! management — it observes, and it does what a hook tells it to do, but it
//! never acts as an endpoint.
//!
//! # Observing
//!
//! [`proxy::TransparentProxy`] accepts client connections and hands each one
//! to a [`session::ProxySession`]. Every frame the session parses is reported
//! to an [`observer::ProxyObserver`] as a [`event::ProxyEvent`]. An observer
//! that answers `false` to [`observer::ProxyObserver::wants_events`] asks for
//! no parsing of its own; what the session parses then depends entirely on
//! the hook.
//!
//! # Acting — the hook API
//!
//! [`hook::ProxyHook`] is the acting side. It has one method per *site* —
//! control message, stream open, stream header, object, datagram, stream end
//! — plus [`hook::ProxyHook::interest`]. Every method is synchronous and
//! defaulted, so a hook implements only the sites it cares about, and the
//! trait stays usable as `Arc<dyn ProxyHook>`. The two stream-decision sites
//! return an [`action::StreamAction`]; every other site returns an
//! [`action::Action`] — pass, replace the frame or just its payload, delay,
//! hold behind an [`action::Gate`], elide, truncate, reset the stream, close
//! the session.
//!
//! What the session arms is decided **once**, at session start, from
//! [`hook::ProxyHook::interest`]. An [`action::Interest::NONE`] hook adds
//! nothing to the path the observer already asked for — with a no-op
//! observer that is the byte pump, bit for bit: no framing, no control
//! parse, no datagram decode, and no site is ever called. Wider interest is
//! paid for structurally — [`action::Interest::OBJECTS`] puts data streams
//! through [`framer::ObjectFramer`], which buffers an object whole, up to
//! [`framer::FramerConfig`]'s cap, before it forwards it.
//!
//! # What cannot be asked for
//!
//! Not every action is representable at every site, on every draft, on every
//! kind of stream — on the drafts where a subgroup's ID is defined by its
//! first object, eliding that object would redefine the subgroup, and
//! resetting a control stream is a protocol violation whatever the reason.
//! [`capability::Capabilities`] answers that question ahead of
//! time, per draft, and hands back a [`capability::Support`]; the engine asks
//! it again when the action arrives. An action it refuses is reported as
//! [`event::ProxyEvent::ActionRefused`] carrying the [`capability::Refusal`]
//! that explains it, and the frame is forwarded unchanged. Nothing a hook can
//! return tears a session down by accident.
//!
//! Degradation the proxy imposed on *itself* — a stream it could not frame, a
//! queue that filled, a hold it clamped, a release timer coarser than it asked
//! for — is reported as [`event::ProxyEvent::Impairment`] rather than absorbed
//! silently.
//!
//! Those reports arrive **after** the thing they describe, never before: the
//! reset has been handed to the transport, the datagram has come back
//! refused, the queue has already been abandoned. So an impairment is a fact
//! about the past, and an action a guard refuses produces none at all — which
//! matters because nothing retracts one. `ProxyEvent::ActionApplied` is the
//! deliberate exception and says so on itself: the engine emits it on
//! admission and the transport can still decline, which is what
//! [`event::ProxyEvent::ActionFailed`] is for.
//!
//! Each impairment also names *which connection* it is about, and that is not
//! the same as the direction it was noticed on. Most of them report a failure
//! to write — a queue that could not be flushed, a datagram the far side
//! refused, a destination stream that had to be reset — so they belong to the
//! opposite leg from the one the bytes arrived on. A reader who mapped
//! [`event::ProxySide`] onto a connection would attribute those to the healthy
//! leg, plausibly and silently, so the event carries the leg outright and
//! leaves it absent for the four reports that are about a profile, a draft or
//! the host rather than about a connection at all.
//!
//! # Three layers to degrade at
//!
//! Everything below is one of three, stacked, and which one a question
//! belongs to is usually the whole of the answer. Underneath the transport
//! is a **socket** the caller supplies — [`listener::Listener::bind_with_socket`]
//! for the client leg, [`session::ProxySessionConfig::upstream_socket`] for
//! the relay leg — which sees UDP datagrams before QUIC does and can lose,
//! delay, reorder or meter them. In the middle are that leg's **transport
//! parameters**, a [`transport::TransportProfile`] or a raw
//! `quinn::TransportConfig`, which decide what QUIC *does* about all that:
//! the windows, the congestion controller, the loss-detection thresholds,
//! the MTU floor. Above QUIC is the **object scheduler**, a
//! [`shape::ShapeProfile`], which paces and starves MoQT objects that QUIC
//! has already delivered intact — never reorders them, because a
//! destination stream keeps one FIFO whose head gates everything behind it.
//!
//! They compose in one direction: **the lower layer acts and the upper one
//! reacts.** A datagram the socket drops becomes a retransmission whose timing
//! the transport parameters govern, and the bytes arrive late at the framer,
//! which is where the scheduler's queue fills. Nothing runs the other way — an
//! object this crate held back or removed was never handed to QUIC at all, so
//! there is nothing for QUIC to repair and the peer's stack cannot tell it
//! apart from a relay that published less. That is also why a scenario picks a
//! layer rather than turning all three on: *does the player survive a bad
//! network?* is the bottom two, *does it survive a bad relay?* is the top one,
//! and a run with both armed cannot attribute what it saw to either.
//!
//! The one place the stack is read upwards is worth knowing, because it
//! looks like a bug from inside the top layer: [`shape::Overflow::Block`]
//! stalls this proxy's read loop and reaches the publisher only if the
//! middle layer lets it, since a receive window wide enough absorbs the
//! backpressure before the sender ever notices. Reporting is layered the
//! same way and does not aggregate — [`shape::ShapeStats`] and
//! [`event::ProxyEvent::Impairment`] describe the object layer only, and a
//! datagram lost beneath QUIC is in neither.
//!
//! # The conditions these three layers reach
//!
//! An inventory rather than a tutorial: the industry-recognised degradation
//! classes, and the type that produces each. It is here so that "can this
//! reproduce X?" is answered by a list with names in it rather than by reading
//! three modules. Every row was checked against the code.
//!
//! **Socket layer** — a `quinn_netem::DirectionProfile`, one per direction, so
//! every row below is independently settable uplink and downlink:
//!
//! | Condition | Produced by |
//! |---|---|
//! | Random loss | `LossModel::Bernoulli` |
//! | Bursty loss | `LossModel::GilbertElliott` |
//! | Deterministic loss pattern | `LossModel::Pattern` |
//! | Fixed added latency | `DelayModel` |
//! | Jitter, correlated | `DelayModel::{Uniform, Normal, Pareto, ParetoNormal}` |
//! | Latency spikes | `DirectionProfile::timeline` over `delay` |
//! | Reordering | `ReorderModel` |
//! | Duplication | `DupModel` |
//! | Corruption | `CorruptModel` |
//! | Sustained bandwidth limit | `RateModel::{bps, burst_bytes}` |
//! | Bandwidth step, ramp, oscillation | `DirectionProfile::timeline` over `rate` |
//! | Bufferbloat | `RateModel::queue_bytes` |
//! | Blackout or handover window | `DirectionProfile::blackouts` |
//! | Asymmetric uplink/downlink | `ImpairProfile::{uplink, downlink}` |
//! | High-BDP path | `Preset::Satellite`, with the windows below |
//! | MTU black hole | `DirectionProfile::mtu_blackhole` |
//!
//! **Transport layer** — a [`transport::TransportProfile`], per leg:
//!
//! | Condition | Produced by |
//! |---|---|
//! | Flow-control stall | `receive_window`, `stream_receive_window`, `send_window` |
//! | Stream-concurrency starvation | `max_concurrent_uni_streams`, `max_concurrent_bidi_streams` |
//! | Idle timeout and keep-alive | `max_idle_timeout`, `keep_alive_interval` |
//! | Congestion-controller sensitivity | `Congestion::{Cubic, Bbr, NewReno}`, `initial_rtt` |
//! | Loss-detection sensitivity | `packet_threshold`, `time_threshold`, `persistent_congestion_threshold`, `ack_frequency` |
//! | Abrupt connection close | [`control::ProxyControl::close_session`] |
//!
//! **Object layer** — an [`action::Action`] returned from a hook, or a
//! [`shape::ShapeProfile`] with no hook at all:
//!
//! | Condition | Produced by |
//! |---|---|
//! | Object drop, per track/group/subgroup/id | [`action::Action::Drop`] with [`action::DropMode`] |
//! | Object delay, group hold | [`action::Action::Delay`], [`action::Action::Hold`] |
//! | Partial object, truncated stream | [`action::Action::Truncate`] |
//! | Stream abort mid-subgroup | [`action::Action::ResetStream`] |
//! | Object payload corruption | [`action::Action::Replace`], [`action::Action::ReplacePayload`] |
//! | Cross-stream reordering | `OpenAfter` at the stream-open site |
//! | Head-of-line blocking | `SerializeAfter` |
//! | Priority inversion, track starvation | [`shape::Discipline::StrictPriority`], [`shape::Discipline::WeightedRoundRobin`] |
//! | Per-track bandwidth budgets | [`shape::ClassRule`] keyed on `track_alias` or `priority` |
//! | Control-message drop, delay, rewrite | [`hook::ProxyHook::on_control_message`] |
//! | Protocol fault injection | [`control::ProxyControl::inject_control`], raw bytes |
//! | Datagram-mode degradation | [`hook::ProxyHook::on_datagram`] |
//!
//! Two cross-cutting properties, each with a limit worth knowing:
//!
//! * **Reproducibility.** Every impairment decision comes from
//!   `Pcg32::seeded(profile.seed, stream_id)`, so a seed and a packet index
//!   reproduce a decision sequence exactly. Wall-clock packet *timing* is not
//!   reproducible and is not claimed to be — see the pacer's own docs for why a
//!   stream of deadlines reproduces a rate rather than a spacing.
//! * **Evidence.** [`event::ProxyEvent::Impairment`] with
//!   [`event::ImpairmentKind`], [`event::ShapeOutcome`] and [`event::Effect`]
//!   report the object layer; `quinn_netem::StatsSnapshot` reports the socket
//!   layer. They do not aggregate, deliberately. The counts divide on the
//!   same principle: what a **hook** decided is on [`instrument::Counters`]
//!   and what a **profile** did is on [`shape::ProxyStats`], because a hook
//!   runs whether or not a profile was configured, and a figure on the wrong
//!   side of that line can only ever be a partial count.
//!
//! # Shaping — degradation without a hook
//!
//! A [`shape::ShapeProfile`] on [`session::ProxySessionConfig::shape`] is the
//! other way to impair a session, and it is **configuration rather than hook
//! code**: named token buckets, [`shape::ClassRule`]s that aim a
//! [`shape::Matcher`] at one of them, a bounded-queue policy, and a
//! [`shape::Discipline`] arbitrating between classes that share a bucket.
//! *Starve the video track while audio flows* is then a value a caller builds,
//! with no `ProxyHook` involved at all — a profile arms object framing on its
//! own, because classification needs the [`framer::ObjectMeta`] only the
//! framing path produces. A mistyped bucket name is rejected by
//! [`shape::ShapeProfile::try_new`] rather than becoming a silently inert rule,
//! and what a run actually did is readable *while it runs* from
//! [`session::ProxySession::shape_stats`], or for a whole proxy — every session
//! it has accepted, ended ones included — from
//! [`control::ProxyControl::stats`]. The proxy-wide form is cumulative where
//! [`control::ProxyControl::sessions`] is instantaneous, and it splits its byte
//! figures across both connections and both directions, so *the shaper read
//! this from the client and wrote that to the relay* is two numbers rather than
//! one.
//!
//! Ordering is not a policy option. Each unit is classified and charged
//! individually, but a destination stream keeps one FIFO whose head gates
//! everything behind it, because object IDs are delta-encoded on drafts
//! 14-19 and the framer's re-encoding primitive handles removal, not
//! reordering. A stream carrying two classes says so, once, as
//! `ImpairmentKind::ClassChangedMidStream`.
//!
//! What shaping deliberately does **not** cover, because a limit discovered
//! from a green run is worse than one read here:
//!
//! * **Control streams are never shaped**, on any path — no scheduler is
//!   installed on them, so no control frame can reach a bucket even by
//!   accident. Pacing SUBSCRIBE behind a video bucket would make MoQT's
//!   idle steady state look like a dead session.
//! * **Datagrams are policed, not paced.** A datagram-aimed class discards
//!   what its bucket has no tokens for, on arrival, and never delays
//!   anything: there is no queue on that path and there should not be one,
//!   because a FIFO would impose a delivery order the protocol does not
//!   have. So a datagram-mode audio track can be held to a rate and cannot
//!   be smoothed, and a rule asking for [`action::Action::Delay`] or
//!   [`action::Action::Hold`] at the datagram site is refused as
//!   `Refusal::WrongSite` rather than approximated. Reordering and delay
//!   under a whole connection are `quinn-netem`'s, one layer down.
//! * **A `Fetch`-aimed class is live on drafts 07-17 and dead on 18-19**,
//!   whose fetch objects carry a Group ID *difference* the fetch's Group
//!   Order gives a direction to; that order is settled on the control plane
//!   and never reaches the data stream, so the framer abandons the stream at
//!   its header and no rule ever sees a unit. Reported the same way and for
//!   the same reason, per draft rather than unconditionally.
//! * **On drafts 15, 16 and 17 an elide on a fetch unit is paid for rather
//!   than refused.** Those drafts let a fetch object leave a field off and
//!   take the previous object's, so deleting one object's bytes would move
//!   every Location behind it while the stream still decoded. The framer
//!   re-encodes the survivor's framing against the frame now in front of it,
//!   which settles the debt in one frame exactly as the subgroup fix-up
//!   does.
//! * **There is no `Expiry::Drop`.** A unit dropped at release time cannot
//!   arm the framer's positional elide fix-up — its successors are already
//!   framed — so on drafts 14-19 it would shift every later object's
//!   absolute ID and report corruption as loss. Under the default
//!   [`shape::Expiry::Deliver`] a starved class is **late, never lossy**;
//!   [`shape::Expiry::ResetStream`] abandons the stream instead. Discarding
//!   an *arriving* unit is [`shape::Overflow::DropTail`]'s job, which runs
//!   early enough to pay the fix-up.
//! * **[`shape::Overflow::Block`] stops this proxy's read loop; it does not
//!   stall the peer.** At quinn's defaults a stream's receive window is
//!   1.25 MB and the connection-level `receive_window` is `VarInt::MAX` —
//!   effectively unlimited — so a blocked stream still absorbs its queue
//!   plus ~1.25 MB before the sender's write blocks, and blocked streams
//!   never slow the connection as a whole. Assert `Block` on this crate's
//!   own counters and event order, never on the peer's send rate. Making
//!   backpressure reach the publisher is a transport setting rather than a
//!   missing feature: put a small `stream_receive_window` on the leg that
//!   *receives* from it, through
//!   [`transport::TransportProfile`], or on the raw config directly with
//!   [`listener::ListenerConfig::transport_config`] or
//!   [`session::ProxySessionConfig::upstream_transport_config`]. Measured
//!   against one session with a two-object queue held shut: at quinn's
//!   default (a 1 250 000-byte per-stream window) the source pushed about
//!   1.25 MB before its first write pended; behind a 64 KiB window it
//!   stalled at 82 370 bytes, with the shaper's own numbers identical in
//!   both runs.
//!
//!   Note that 82 370 is *past* a 64 KiB window, by 16 834 bytes, and that
//!   is not an anomaly — it is what having a reader means. The source's
//!   allowance is the window plus everything the proxy has already drained
//!   off the wire, so with a proxy reading, the stall lands beyond the
//!   window; against a receiver that never reads at all it lands a little
//!   short of it, by however much of the final write did not fit. Both are
//!   correct, for different readers. Either way the number moves with the
//!   writer's chunk size and the reader's queue depth, so it is a property
//!   of the fixture and not a constant to assert against.
//! * **[`shape::BucketConfig::ceil_bps`] is accepted and never borrowed
//!   against.** A profile setting it above `rate_bps` measures a flat
//!   `rate_bps`. There is no runtime report for it, deliberately:
//!   `ShapeError` has no variant a bucket misconfiguration could land in,
//!   and `ImpairmentKind::ShapeRuleUnmatchable` is keyed on a *wire* field
//!   and a draft, so reusing it would make a per-draft report fire on a
//!   draft-independent fact.
//!
//! # Below QUIC — the socket seams
//!
//! Everything above shapes MoQT objects, which sit *above* QUIC: damage
//! there is indistinguishable from a relay that dropped or delayed media,
//! and QUIC will never repair it because as far as QUIC is concerned
//! nothing was lost. The other place to degrade traffic is *below* QUIC,
//! on the datagrams themselves, where damage is precisely what the peer's
//! QUIC stack is built to absorb — loss triggers retransmission, jitter
//! inflates the RTT estimate, a rate limit drives the congestion
//! controller. The two answer different questions and compose freely.
//!
//! [`listener::Listener::bind_with_socket`] builds the client-facing
//! endpoint over a socket the caller already owns, and
//! [`session::ProxySessionConfig::upstream_socket`] does the same for the
//! relay leg. Both take any `Arc<dyn quinn::AsyncUdpSocket>`, so this
//! crate stays agnostic: a tap, a counter and an impairment shim are the
//! same seam, and none of them is a dependency here.
//!
//! Three things a caller has to know:
//!
//! * **The client-facing seam reaches WebTransport clients too**, and by
//!   construction rather than by luck. The proxy never builds a
//!   WebTransport endpoint on that side — it builds the QUIC endpoint,
//!   reads the negotiated ALPN off the handshake, and hands an `h3`
//!   client's still-connecting QUIC connection to the WebTransport library
//!   to finish. That library adopts a connection already living on this
//!   endpoint rather than binding one, so there is no second datagram path.
//! * **A WebTransport *upstream* cannot honour a socket, and says so.**
//!   Setting one there returns
//!   [`error::ProxyError::UpstreamSocketUnsupported`] and connects to
//!   nothing. `upstream_transport_config` is merely ignored in the same
//!   situation, and the asymmetry is the point: a dropped transport config
//!   yields a working connection with unchosen windows, while a dropped
//!   socket yields a relay leg that bypasses the caller's decorator
//!   entirely — every impairment armed on it reported and applied to
//!   nothing, and a run that looks clean because it *is* clean.
//! * **One socket per session on the upstream seam.** Two endpoints reading
//!   one socket steal each other's datagrams, and a packet for a connection
//!   an endpoint does not own is discarded, so sessions that run
//!   concurrently need a socket each.
//!
//! Those two seams are reached by building a [`listener::Listener`] or a
//! [`session::ProxySession`] yourself. A
//! [`proxy::TransparentProxy`] binds its own listener inside `run()` and
//! copies its session template per connection, so it reaches both through
//! one call instead: `proxy::TransparentProxy::set_impaired_socket` takes
//! a leg's socket **and** the `quinn_netem::ImpairHandle` it was wrapped
//! with, together, and is what makes
//! `control::ProxyControl::set_impair` able to arm anything. Together
//! because nothing can check that a handle belongs to the socket beside it —
//! `AsyncUdpSocket` is a trait object with no downcast and the decorator
//! exposes no accessor — so taking them as two independent settings would
//! make a mismatched pair expressible, and a mismatched pair impairs traffic
//! nobody sends.
//!
//! Those two method names, and every `quinn_netem::` name on this page, are
//! in plain code font rather than linked because all of them exist only under
//! the `impair` feature, while this page is built without it. A link to one
//! would resolve to nothing, and an unresolved intra-doc link is an error
//! under the documentation build rather than a warning.
//!
//! Nothing that happens under a supplied socket appears in this crate's
//! reporting. [`shape::ShapeStats`] and
//! [`event::ProxyEvent::Impairment`] describe the object layer; a datagram
//! dropped beneath QUIC is in neither, and the socket is where to count it.
//!
//! # Transport parameters, per leg
//!
//! A [`transport::Leg`] is a *connection* — this proxy holds two, one to
//! the client and one to the relay — and each carries its own QUIC
//! transport parameters. Do not read it as
//! [`event::ProxySide`], which is a *direction of travel* over a leg and
//! therefore has four variants where `Leg` has two; both types exist in
//! this crate and the compiler will not catch the confusion.
//!
//! Each leg takes those parameters one of two ways, never both at once. A
//! raw `quinn::TransportConfig` is installed as it was given. A
//! [`transport::TransportProfile`] is a value that can be written down,
//! checked and stored, and the leg builds a config from it through a
//! [`transport::TransportInstaller`] — [`transport::DefaultInstaller`]
//! unless the caller supplies one. Either way the config is installed
//! before the endpoint is built and before anything is dialled, so a
//! refusal costs no socket and cannot be mistaken for a network fault.
//!
//! Setting both on one leg is [`error::ProxyError::TransportConfigAndProfile`]
//! rather than a merge, and that is a fact about `quinn::TransportConfig`
//! rather than a policy: it has no `Clone` and no getters, so no merge can
//! be written that does not discard the caller's config while keeping the
//! profile — the failure the tests would not see. A caller who wants both
//! applies the profile to their own config with
//! [`transport::TransportProfile::apply_to`], or supplies an installer that
//! builds the base itself.
//!
//! # Capturing the QUIC layer
//!
//! Under the off-by-default `qlog` feature, `qlog::QlogSpec` says where a
//! connection's QUIC-level capture should be written. It is written in plain
//! code font here for the same reason the `quinn_netem` names above are: this
//! page is built without that feature, and a link to an item that does not
//! exist in the build is an error rather than a warning.
//!
//! **Each leg carries a spec of its own**, beside the transport settings it
//! already carries: `ListenerConfig::qlog` for the client leg and
//! `ProxySessionConfig::upstream_qlog` for the relay leg. The leg builds its
//! `quinn::TransportConfig` once — applying its
//! [`transport::TransportProfile`] first, through its
//! [`transport::TransportInstaller`] if it has one — and installs the sink
//! on what came back, before the endpoint exists, because quinn accepts a
//! sink in exactly one place and that place is a method on a config. A spec
//! on its own is enough: the leg builds a default config for the sink to go
//! on rather than attaching the capture to a config no connection uses. A
//! leg naming a **raw** `quinn::TransportConfig` and a spec together is
//! refused with `ProxyError::TransportConfigAndQlog` naming the leg, for the
//! same reason a raw config and a profile are: the config is the caller's
//! and this crate may not mutate it behind their back.
//!
//! `QlogSpec::attach_to` is that installation step on its own, for a caller
//! building a config by hand, and `QlogSpec::into_stream` is the seam under
//! it for one being installed somewhere this crate does not reach. Both
//! write the file's preamble, so the artifact exists from that moment.
//!
//! **A spec is single-use and therefore refused on a proxy template.** It owns
//! its writer and is consumed when it becomes a sink, so it has no `Clone` and
//! there is exactly one of it, while [`proxy::TransparentProxy`] copies both
//! leg configs — once for the listener, once per accepted connection. A
//! `ProxyConfig` carrying one on either leg is refused by
//! `TransparentProxy::run` with `ProxyError::QlogOnProxyTemplate`, before it
//! binds, rather than dropped: a proxy that came up anyway would report success
//! and leave the caller's file uncreated. Capture by building the
//! [`listener::ListenerConfig`] and calling [`listener::Listener::bind`]
//! yourself, or by driving a [`session::ProxySession`] directly — which is also
//! the only shape in which *one capture per connection* is expressible, since
//! one sink shared by an endpoint's connections writes all of them into one
//! file, behind one preamble, with no record saying where one ends.
//!
//! The capture is the layer *underneath* everything else this crate reports.
//! quinn records packets sent and received, congestion and loss, and nothing
//! above QUIC — no object, no stream id, no shaping class — so a datagram
//! dropped beneath QUIC appears there and in none of the counters, while an
//! object dropped by a shaping rule appears in the counters and not there.
//! Two facts about the artifact are worth knowing before anyone builds a
//! check on one: the file and its preamble are written when the sink is
//! built, so a capture that reached no connection is still a valid, non-empty
//! file; and a connection that carried nothing still sends packets, so a
//! non-zero byte total is not by itself evidence of traffic. The module
//! documentation carries the measurements.
//!
//! # Asking a proxy that is already running
//!
//! Everything above is settled before the thing it configures exists — the
//! listener consumes its config as it binds, each session copies its own
//! before it dials, and a hook's interest is sampled once at session start.
//! That is what makes a run reproducible from the values that started it,
//! and it is also why there was no way to ask a live proxy anything.
//!
//! [`proxy::TransparentProxy::control`] hands back a
//! [`control::ProxyControl`], and it can be called before
//! [`proxy::TransparentProxy::run`] is awaited — which is the usual case,
//! because `run()` does not return until the proxy is finished. The handle
//! is therefore defined for a proxy that has not bound yet:
//! [`control::ProxyControl::local_addr`] answers
//! [`error::ProxyError::NotBound`] until the endpoint exists, which is how a
//! proxy configured with port 0 tells its caller which port it chose.
//!
//! [`control::ProxyControl::sessions`] lists the sessions that are live at
//! that instant, and it is a **census rather than a log**: an id appears
//! when its session starts running and is gone once that session ends, for
//! any reason, including the ones no teardown site could be written for. A
//! caller that wants the history reads
//! [`event::ProxyEvent::SessionStarted`] and
//! [`event::ProxyEvent::SessionEnded`] from its observer instead, and should
//! expect the two views to disagree at the edges — the events are emitted
//! around accepting a connection, the census around running the session, and
//! a session whose upstream connect fails is in the first and only briefly
//! in the second.
//!
//! Requests that *act* on a live session — as opposed to reporting on one —
//! are refused with a [`control::ControlError`] rather than by returning
//! success and doing nothing. The type is neither `Eq` nor
//! `#[non_exhaustive]`, so a caller outside this crate can match every
//! variant with no wildcard arm and find out at compile time when a new
//! refusal appears.
//!
//! Three of those requests act on one named session, and each names the
//! consequence it produces rather than the state it changes:
//!
//! * [`control::ProxyControl::close_session`] gives the session's egress
//!   queues a bounded window — [`action::EgressConfig::drain_timeout`], 100
//!   ms by default — to flush, then closes both legs with the code and
//!   reason it was given, whether or not the window was enough. Anything
//!   still queued when it expires is abandoned and named, per stream, as
//!   [`event::ImpairmentKind::QueuedBytesAtTeardown`], so what the peer
//!   received plus what the impairments name is what was queued when the
//!   close was asked for.
//! * [`control::ProxyControl::reset_stream`] resets one live forwarded
//!   stream, which the destination peer sees as `RESET_STREAM` carrying the
//!   requested code.
//! * [`control::ProxyControl::inject_control`] writes a framed control
//!   message onto the session's existing control stream, between two
//!   forwarded messages, so the peer decodes it in sequence.
//!
//! Only the first of those three produces observer events, and it produces
//! them through the session rather than from the call: a
//! [`event::ProxyEvent::SessionEnded`] whose reason names the **control
//! plane** rather than a hook — both reach the same latch, and reporting an
//! operator's close as a hook's was a sentence about the run that was simply
//! untrue — plus whatever the expired drain window abandoned. The other two
//! emit nothing, and each says why on its own page: neither has anything to
//! report that the caller does not already hold in the return value, and
//! neither may borrow an existing event without making it ambiguous for the
//! readers that already rely on it. What they produce is observable at the
//! peer, which is where a consequence belongs.
//!
//! # Reconfiguring a proxy that is already running
//!
//! The other requests change what the proxy *is*. They reach three
//! different distances, and the distances are not a matter of how they were
//! implemented — they are what the thing being changed will admit. Read
//! them as reach first and as settings second, because a caller who reads
//! them the other way round will measure the wrong connection and believe
//! the answer.
//!
//! **`control::ProxyControl::set_impair` reaches traffic already in
//! flight.** It arms a datagram impairment on one leg's socket, below QUIC,
//! so the next datagram that leg passes carries it. Datagrams already
//! handed to the operating system are gone.
//! `control::ProxyControl::clear_impair` removes it and is idempotent.
//! Both need the leg's socket **and** the `quinn_netem::ImpairHandle` it was
//! wrapped with to have been handed over together, before `run()`, through
//! `proxy::TransparentProxy::set_impaired_socket`; a leg the proxy holds
//! no handle for is refused rather than accepted and ignored, because a
//! profile armed on a socket nobody's traffic crosses is reported as applied
//! and does nothing, and the run that follows looks clean because it *is*
//! clean.
//!
//! **[`control::ProxyControl::set_shaper_enabled`] reaches the next release
//! decision each queue makes**, on every session already running. It stops
//! the token buckets and the discipline without discarding the profile, so
//! switching it back on resumes the same configuration and the same
//! counters. A stream held by a bucket that will refill resumes within one
//! pacing interval; a stream held by a bucket configured at **zero** does
//! not resume until its `max_hold` clamp, because the wait it is on is a
//! timer a per-stream queue armed and nothing session-wide reaches one.
//!
//! **[`control::ProxyControl::set_shape`] reaches the next stream** a
//! running session forwards, and every session accepted afterwards. Not the
//! next object: a stream's egress queue holds the scheduler its units were
//! admitted under, and a class is an index into that scheduler's class list,
//! so a unit classified against one profile and released against another
//! charges a class that was not the one matched. Two further limits, both
//! structural: a session that started **unshaped** stays unshaped, because
//! framing is armed at session start and there are no objects to classify;
//! and a running session takes the new profile only if its **class list is
//! unchanged** — same names, same order — because
//! [`shape::ShapeStats`] rows are pre-sized per session and charged by
//! position, so a different list would keep every number right and every
//! label on it wrong. Sessions accepted afterwards have no such limit. To
//! move a running session onto a different class list, end it with
//! `close_session`.
//!
//! **[`control::ProxyControl::set_transport`] reaches no connection that
//! already exists — ever.** A QUIC connection takes its
//! `quinn::TransportConfig` once, at setup, and keeps it for life; quinn
//! offers four setters on a live connection (two stream-count limits, two
//! windows) and no way to replace the configuration behind it. So a profile
//! set on [`transport::Leg::Upstream`] reaches the next connection this
//! proxy **opens**, which is the next session it accepts, and a profile set
//! on [`transport::Leg::Client`] reaches the next connection it
//! **accepts** — which the proxy does not initiate and which may never
//! arrive. On a proxy that never dials or accepts again, the call is a
//! permanent silent no-op that returns `Ok(())`, and nothing in the return
//! value distinguishes that from a setting that reached everything
//! afterwards. The one instrument that makes it bite on a session already
//! running is `close_session`: a leg that reconnects is a leg that installs
//! it. A WebTransport upstream cannot take one at all — that endpoint is
//! built inside the WebTransport library, which takes no transport config
//! and hands back no endpoint — and says so with
//! [`control::ControlError::Unsupported`] rather than storing it.
//!
//! # Writing the configuration down
//!
//! Everything above is configured in Rust, which is what a test wants and not
//! what an operator wants. The off-by-default `serde` feature derives
//! `Serialize` and `Deserialize` on the configuration types — the shaping
//! profile with its buckets, classes and matchers, and both legs' transport
//! parameters — so a caller can read them from a file instead of building
//! them in code. It is written in plain code font here for the reason the
//! `quinn_netem` names above are: this page is built without that feature, so
//! a link would resolve to nothing.
//!
//! The feature buys the types and nothing more. This crate reads no file,
//! interprets no run, and has no opinion about what a run *is*: a caller
//! deserializes what it wants, hands the profiles to a session, and drives
//! whatever changes part-way through against [`control::ProxyControl`]
//! itself. That is the same line [`hook::ProxyHook`] draws — the mechanism
//! and the extension point are here, and what to do with them belongs to
//! whoever wrote the consumer.
//!
//! One property is worth knowing before reading a profile from a file.
//! [`shape::ShapeProfile`]'s fields are private so that
//! [`shape::ShapeProfile::try_new`] is the only way to build one, and its
//! `Deserialize` is routed through a public-field mirror whose `TryFrom` calls
//! that constructor. A profile read from a file therefore runs the same seven
//! validations as one built in Rust, and there is no deserialization path that
//! skips them — including the one that catches a class naming a bucket that
//! does not exist, which would otherwise parse, arm, report shaping and shape
//! nothing.
//!
//! # Instrumentation
//!
//! [`instrument::Recorder`] counts the slow paths: framers created, objects
//! elided, actions refused, egress items queued, release lateness. This is
//! what makes `Interest::NONE` a falsifiable claim rather than a promise —
//! a session that declared no interest ends with an all-zero
//! [`instrument::Counters`]. [`shape::ShapeStats`] is its sibling rather
//! than an extension of it: one row per configured class plus a default
//! row, an unshapeable row and the session totals, where a class that saw
//! nothing reports a **zero row** and never an absent one. Its two
//! duration-valued fields are reported and never asserted — machine load
//! moves them, and their load-independent companion counts are what a gate
//! reads.
//!
//! Every session total is reported three times: flat, and again under
//! [`shape::ShapeStats::uplink`] and [`shape::ShapeStats::downlink`]. The
//! flat figure is **defined as the sum of the two**, so the views cannot
//! disagree and no existing reader breaks. It matters on a session that
//! shapes both legs, where one number cannot tell an uplink stall from a
//! downlink one and a report will attribute downlink starvation to the
//! uplink class.
//!
//! [`shape::ProxyStats`], read through [`control::ProxyControl::stats`], is
//! the same figures kept a second time for a whole proxy — cumulative across
//! every session it has accepted, ended ones included, and charged by the
//! same writers, so no figure can reach a session's rows and miss it. It
//! carries one axis a session's own totals do not: a **leg** as well as a
//! direction, because a proxy holds two connections and a byte crosses both.
//! Read [`shape::LegStats`] before reading a cell — a figure is charged
//! where it was measured, so `per_leg[Client].uplink` is what was read from
//! the client and `per_leg[Upstream].uplink` is what was written to the
//! relay, and the difference between them is what the shaper kept back.
//!
//! **Every field here has a producer**, and it took a deletion rather than
//! five new writers to make that true. A zero that looks like a measurement
//! is how a clean run gets believed, and five fields here were one. Two of
//! them counted what a **hook** did — a deferral and a truncation — while
//! everything on this page is gated on a configured [`shape::ShapeProfile`],
//! so in this type they could only ever have been partial counts; they are
//! [`instrument::Counters::units_delayed`] and
//! [`instrument::Counters::objects_truncated`] now, beside the elide count
//! that had already settled where a hook's decision belongs. The other three
//! were `Duration` totals a reader cannot calibrate, and the timing
//! dimension is reported as a distribution by
//! [`instrument::Counters::release_errors`] instead.
//!
//! Separately, and a different kind of zero: the three event figures on a
//! [`shape::DirectionStats`] are charged where traffic arrived, so they read
//! zero in a *departure* cell. That is stated on the fields as well.
//!
//! # Migrating
//!
//! *From 0.4*: [`session::ProxySessionConfig`] gained the `shape`,
//! `upstream_socket`, `upstream_transport_profile` and `upstream_installer`
//! fields, and [`listener::ListenerConfig`] gained `transport_profile` and
//! `installer`. Neither is `#[non_exhaustive]`, so an exhaustive struct
//! literal must name them all — `None` on each is 0.4 behaviour exactly, and
//! [`session::ProxySessionConfig::default()`](session::ProxySessionConfig)
//! is unaffected. [`listener::Listener::bind`] is unchanged and still binds
//! its own socket. `StreamCtx::new` gained a seventh argument, which only
//! affects code that builds one by hand to unit-test its own hook.
//!
//! *From 0.3*: the 0.3 hook trait survives as [`hook::LegacyProxyHook`],
//! deprecated. Wrap an existing implementation in [`hook::LegacyHook`] to run
//! it against this engine unchanged; its control-message and datagram
//! rewrites become [`action::Action::Replace`].

// Declared alphabetically, which says nothing about the graph. What does:
// `instrument`, `qlog` and `types` name nothing else in this crate, so each of
// them sits below every consumer it has and can be read, replaced or compiled
// on its own. `tests/leaf_modules.rs` is what keeps that true — a single
// `use crate::…` added to one of the three would end it silently otherwise.
pub mod action;
pub mod capability;
pub mod control;
pub mod error;
pub mod event;
pub mod framer;
pub mod hook;
pub mod instrument;
pub mod listener;
pub mod observer;
pub mod parser;
pub mod proxy;
pub mod session;
pub mod shape;
pub mod transport;
pub mod types;

// Engine internals. Not `pub mod`: the deferred-write queue, the action
// executor and the release wheel are how the sites above are implemented,
// not part of what this crate promises. Keeping them private also keeps
// them out of `#![deny(missing_docs)]` and lets any of the three be
// replaced without a breaking change.
//
mod egress;
mod exec;
mod release_timer;

#[cfg(feature = "cert-gen")]
pub mod cert;

// Behind `qlog`, which is off by default because turning it on adds a
// derive-macro toolchain to everybody's build. What it holds is a description
// of where a QUIC-layer capture should be written; the capture itself is
// written by quinn.
#[cfg(feature = "qlog")]
pub mod qlog;

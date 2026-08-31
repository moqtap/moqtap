//! The control plane — a live handle onto a running proxy.
//!
//! Everything else in this crate is configured before it starts: a
//! [`ListenerConfig`](crate::listener::ListenerConfig) is consumed when the
//! endpoint is bound, a [`ProxySessionConfig`](crate::session::ProxySessionConfig)
//! is copied once per accepted connection, and a
//! [`ProxyHook`](crate::hook::ProxyHook) declares its interest once at
//! session start. That is deliberate — it is what makes a run reproducible
//! from the values that started it — but it leaves no way to ask a proxy
//! that is *already running* anything at all.
//!
//! [`ProxyControl`] is that way. It is obtained from
//! [`TransparentProxy::control`](crate::proxy::TransparentProxy::control)
//! **before** the accept loop is awaited, because the caller that owns the
//! proxy is usually the caller that is about to give up its thread of
//! control to `run()`; a handle that could only be taken afterwards could
//! not be taken at all. Everything it reports is therefore defined for a
//! proxy that has not bound yet: [`ProxyControl::local_addr`] answers
//! [`ProxyError::NotBound`] until the listener exists, and
//! [`ProxyControl::sessions`] answers an empty list.
//!
//! # Two pieces of shared state, both released by a guard
//!
//! The handle reads two things the proxy used to keep as stack locals of
//! `run()`: the bound listener, and the set of sessions that are live right
//! now. Both are published into this module when they come into existence
//! and removed when they go, and in both cases the removal is a `Drop`
//! rather than a call at each exit site.
//!
//! That choice is the whole correctness argument for
//! [`ProxyControl::sessions`]. A session ends for at least five distinct
//! reasons — a forwarding task returned, a forwarding task errored, the peer
//! went away, a hook asked for a close, the proxy was cancelled — and a
//! sixth that no enumeration covers, the session's whole future being
//! dropped by whoever spawned it. A list of removal sites is only ever as
//! complete as the reader who wrote it, and the failure it produces is
//! silent: `sessions()` keeps naming an id nothing can act on, and every
//! later call that takes that id fails in a way that looks like a race.
//! `Drop` is complete by construction, so the registration is handed out as
//! a `SessionGuard` and lives in the frame of the function that runs the
//! session.
//!
//! A third piece is held here and released by nothing: the proxy-wide
//! shaping counters behind [`ProxyControl::stats`]. They are the one report
//! in this module that is *cumulative* rather than instantaneous, and that
//! is exactly why they cannot be assembled from the two above. A total
//! summed over the session list would fall every time a client disconnected,
//! because the list is released by a `Drop` and a session that has ended
//! leaves nothing behind — and a statistic that goes down under normal
//! operation cannot be alerted on. So each session is handed the counters
//! when it attaches, charges them as it forwards, and leaves them behind
//! when it goes.
//!
//! # Reaching a session that is already running
//!
//! Registering an id is enough to *list* a session but not to *act* on one.
//! Acting needs the session's cancellation token, its close request slot,
//! its stream registry, its two control-stream inboxes and its egress
//! knobs — and every one of those is built by the session before it dials
//! the upstream relay, which is what lets the whole entry go into the
//! registry at the top of the run function. A session spends its longest
//! single operation connecting, sometimes for as long as its connect
//! timeout allows and sometimes forever; one that only became reachable
//! afterwards would be unreachable for exactly that long.
//!
//! What is deliberately **not** in an entry is either connection. The two
//! `Transport`s are owned by the forwarding scope, and a table scanned by
//! every list call has no business holding them alive past the session that
//! owns them.
//!
//! The channels are created with the session rather than attached later
//! because a task attached after the fact could never cover the sessions
//! that were already running when it was attached — which is precisely the
//! set a control plane exists to reach.
//!
//! # Three levels of reach, and why they are not one mechanism
//!
//! [`ProxyControl::close_session`] acts on the whole session, so it goes to
//! the session's own command task: it is the only request that has to
//! *wait* for something — the bounded egress drain — and a waiting request
//! needs somewhere to wait that is not the caller's thread.
//!
//! [`ProxyControl::reset_stream`] and [`ProxyControl::inject_control`] act on
//! one stream, and neither waits. They resolve in the caller: the registry
//! entry carries the session's `StreamRegistry`, so a key that names nothing
//! live is refused synchronously, and a key that names a live stream is reached
//! by dropping a `StreamCommand` into that stream's own inbox. Routing them
//! through the session task as well would have added a hop and a second place
//! for a request to be lost, and would have made *there is no such stream* an
//! answer that arrives asynchronously — which a synchronous method signature
//! cannot deliver.
//!
//! Nothing here accepts a request and discards it. Every method either
//! delivers to a task that will act on it or answers a [`ControlError`]
//! saying why it could not.
//!
//! # Reconfiguring, and the one verb that cannot reach a live connection
//!
//! Three of the requests here change what the proxy *is* rather than what a
//! particular session is doing, and they reach three different distances.
//! The distances are not a matter of how they were written; they are what
//! the thing being changed will admit.
//!
//! `ProxyControl::set_impair` reaches traffic already in flight. It acts
//! below QUIC, on the datagrams a leg's socket is about to pass, and the
//! next one out carries the new profile.
//!
//! [`ProxyControl::set_shape`] and [`ProxyControl::set_shaper_enabled`]
//! reach a running session. The switch is read on the next release decision
//! a queue makes, which for a stream held by a bucket that will refill is
//! within one pacing interval and for a stream held by a bucket configured
//! at zero is not until the `max_hold` clamp — see the method for why
//! nothing here can do better. A new profile is taken up by a running
//! session at its next stream, because a stream's egress queue holds the
//! scheduler its units were admitted under and a class is an index into that
//! scheduler's class list.
//!
//! [`ProxyControl::set_transport`] reaches **no connection that already
//! exists, ever**. A QUIC connection takes its transport configuration once,
//! at setup, and keeps it for life — quinn offers four setters on a live
//! connection and no way to replace the configuration behind it. So a
//! profile set on the relay leg reaches the next connection this proxy
//! *opens*, which is the next session it accepts, and a profile set on the
//! client leg reaches the next connection it *accepts*, which the proxy does
//! not initiate and which may never arrive. On a proxy that never dials or
//! accepts again — every client already connected, nothing new coming — the
//! call is a permanent silent no-op that returns `Ok(())`, and no return
//! value here distinguishes that from a setting that reached everything
//! afterwards. It is written out on the method, in this module, and in the
//! crate documentation, in those words, because a caller who reads it as
//! "set the window" and measures the session in front of them will measure
//! the old window and believe the new one.
//!
//! # Two kinds of name here are deliberately not links
//!
//! `SessionGuard`, `StreamRegistry` and `StreamCommand` are crate-internal,
//! and `set_impair` and `clear_impair` exist only under the `impair` feature.
//! This page is public and is built without that feature, so a link to
//! either kind resolves to nothing — and an unresolved intra-doc link is an
//! error under the documentation build, not a warning. Both are written in
//! plain code font instead, so the prose can still name the thing it is
//! describing without breaking that build. Turning one back into a link is
//! what reddens it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::action::{EgressConfig, Gate};
use crate::egress::SessionCloser;
use crate::error::ProxyError;
use crate::event::SessionId;
use crate::listener::Listener;
use crate::shape::{ProxyRecorder, ProxyStats, ShapeError, ShapeProfile, StreamKey};
use crate::transport::{
    DefaultInstaller, TransportInstaller, TransportProfile, TransportProfileError,
};
use crate::types::Leg;

/// How many commands a session's inbox holds before a sender has to wait.
///
/// Small on purpose. A control caller issues one request and waits for its
/// answer, so depth beyond a handful only ever buys the ability to queue
/// work behind a session that has stopped serving its inbox — which is a
/// session that is on its way down, and a queued command aimed at it should
/// be refused rather than parked.
pub(crate) const COMMAND_QUEUE_DEPTH: usize = 16;

/// Why a control-plane request could not be carried out.
///
/// Distinct from [`ProxyError`], which describes a proxy that could not be
/// built or a connection that could not be made. Every variant here is a
/// request the proxy understood and declined, and each says which of the
/// three reasons applied: the thing addressed is not there, the thing asked
/// for cannot be done on that leg over that transport, or the value supplied
/// was refused by the same check that would have refused it in a
/// configuration file.
///
/// Neither `Eq` nor `#[non_exhaustive]`, and both omissions are load-bearing.
/// `Eq` is unavailable because [`TransportProfileError`] reaches an `f32`.
/// `#[non_exhaustive]` is absent so that a caller outside this crate can
/// match every variant with no wildcard arm — a match that stops compiling
/// when a variant is added, which is the one place a new refusal reliably
/// gets noticed.
///
/// One variant is `#[cfg]`-gated: `ControlError::Impairment` exists only
/// under the `impair` feature, which is also the only build in which the
/// method that returns it exists. A downstream exhaustive match therefore
/// carries the same `#[cfg(feature = "impair")]` on that arm. Reaching for a
/// `_` arm to avoid the attribute would satisfy the feature-on build as well
/// and swallow every later variant with it, which is the whole of what the
/// missing `#[non_exhaustive]` buys. It is written in plain code font rather
/// than linked, because a link from this always-compiled page would not
/// resolve in a build without the feature — the same convention the crate
/// page uses for every other feature-gated name.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ControlError {
    /// No session with this id has ever run on this proxy.
    ///
    /// Session ids are minted per [`TransparentProxy`](crate::proxy::TransparentProxy)
    /// and are not comparable across proxies, so an id from one proxy handed
    /// to another lands here rather than acting on an unrelated session.
    /// A session that ran and has since ended answers
    /// [`ControlError::SessionEnded`] instead; the two are told apart by the
    /// highest id this proxy has ever registered, which is enough because
    /// ids are minted monotonically.
    ///
    /// The one id that is here and *did* exist: a connection accepted but
    /// not yet running. `SessionStarted` is emitted at accept and
    /// registration happens when the session begins to run, so an id in that
    /// window is in no registry — see [`ProxyControl::sessions`], which says
    /// the same thing about the census. Which of the two refusals such an id
    /// gets is not fixed: the split is made on the highest id ever
    /// registered, and two connections accepted together may reach their run
    /// functions in either order, so an id awaiting registration answers
    /// this unless a *later* one registered first, in which case it answers
    /// [`ControlError::SessionEnded`]. Neither answer is retryable and
    /// neither acts on anything, so the difference is one of wording rather
    /// than of what a caller may then do.
    #[error("no session {0:?}")]
    NoSuchSession(SessionId),
    /// This proxy ran a session with this id and is no longer running it,
    /// or is running it but has stopped taking requests for it.
    ///
    /// The ordinary race, and not a fault: a session may end between the
    /// call that listed it and the call that acts on it, and a control
    /// plane that panicked there could not be driven from a timeline. Every
    /// verb that names a [`SessionId`] can answer this.
    ///
    /// Separate from [`ControlError::NoSuchSession`] because the two mean
    /// different things to a caller holding a list: a lookup miss on an id
    /// this proxy never issued says the list came from somewhere else,
    /// while this says the list was right and the session ended underneath
    /// the call. Neither is retryable.
    ///
    /// It also carries one case that is neither: a request that could not
    /// be *taken*, because the target already has
    /// [`COMMAND_QUEUE_DEPTH`](self) requests outstanding and has served
    /// none of them. That is a session or a stream that is not going to
    /// serve them, and the frozen refusal set has no "try again later"
    /// answer to give instead. Reaching it takes sixteen unanswered
    /// requests aimed at one target.
    #[error("session {0:?} has already ended")]
    SessionEnded(SessionId),
    /// The session is live but has no stream under this key.
    ///
    /// A key that names a stream which has already ended is reported the
    /// same way as one that never existed. The two are not distinguished
    /// anywhere in this crate: a stream's registration is removed as it
    /// ends, so there is no record left to tell them apart, and inventing
    /// one would mean holding every finished stream's identity for the life
    /// of the session.
    #[error("no stream {stream:?} on session {id:?}")]
    NoSuchStream {
        /// The session the stream was looked for on.
        id: SessionId,
        /// The key that matched nothing live.
        stream: StreamKey,
    },
    /// The request is meaningful in general but cannot be carried out on
    /// this leg, because of what that leg's transport is able to expose.
    ///
    /// Reported rather than ignored. A leg that quietly declined would leave
    /// the caller holding a successful return and a proxy that behaves as
    /// though nothing was asked — the failure this crate is least willing to
    /// ship, because it is invisible from the outside and survives every
    /// green run.
    #[error("{what} is unsupported on the {leg:?} leg over {transport}")]
    Unsupported {
        /// What was asked for, in the words a caller would use for it.
        what: &'static str,
        /// The leg it was asked of.
        leg: Leg,
        /// That leg's transport, named as a caller would recognise it —
        /// `"WebTransport"`, `"QUIC"`.
        transport: &'static str,
    },
    /// A [`TransportProfile`] was
    /// refused.
    ///
    /// The same check that runs when a profile is supplied in a
    /// configuration, reporting the same error, so a profile that a leg
    /// would not have started with is not one it can be moved to.
    #[error(transparent)]
    Profile(#[from] TransportProfileError),
    /// A [`ShapeProfile`] was refused.
    ///
    /// As with [`ControlError::Profile`], this is the construction-time
    /// check rather than a second, looser one.
    #[error(transparent)]
    Shape(#[from] ShapeError),
    /// A datagram impairment profile was refused by `quinn-netem`, and this
    /// is the reason it gave.
    ///
    /// Present only under the `impair` feature, which is also the only build
    /// in which [`ProxyControl::set_impair`] exists — the variant and the
    /// method that produces it are gated together, so there is no build
    /// carrying a refusal nothing can return.
    ///
    /// # Why it is not [`ControlError::Unsupported`]
    ///
    /// It was, and the loss was the whole reason. `quinn_netem::ProfileError`
    /// distinguishes thirteen ways a profile is armed and does nothing — a
    /// reorder model on a direction with no delay, a token bucket whose burst
    /// is below one datagram, a peer filter that matches no peer — and every
    /// one of them arrived here as the same sentence naming the leg. The
    /// caller was then told to re-run
    /// `quinn_netem::ImpairProfile::validate` to find out what had actually
    /// happened, which is a workaround for a type that could not express the
    /// answer, written into the documentation as though it were a workflow.
    /// `Unsupported` also says something that is not true here. That variant
    /// means the request cannot be carried out **on this leg over this
    /// transport**; a refused impairment profile is refused on every leg and
    /// every transport, because it is the profile that is wrong. A caller
    /// matching on the two now gets one arm for *this proxy cannot impair that
    /// leg*, which is fixed by supplying a socket, and one for *this profile is
    /// not armable*, which is fixed by editing the profile.
    ///
    /// A refused profile changes nothing: whatever was armed on that leg
    /// before the call is still armed.
    #[cfg(feature = "impair")]
    #[error("the impairment profile for the {leg:?} leg was refused: {source}")]
    Impairment {
        /// The leg the profile was aimed at.
        leg: Leg,
        /// Why `quinn-netem` would not arm it.
        source: quinn_netem::ProfileError,
    },
}

/// A handle onto a running proxy.
///
/// Cheap to clone — one `Arc` bump — and every clone reads and writes the
/// same state, so a handle may be moved into a task, kept beside the proxy,
/// or both. It holds no lock across an `await` and takes no part in the
/// forwarding path.
///
/// Obtained from
/// [`TransparentProxy::control`](crate::proxy::TransparentProxy::control),
/// which can be called at any point after the proxy is constructed —
/// including before
/// [`TransparentProxy::run`](crate::proxy::TransparentProxy::run) is
/// awaited, which is the usual case, because `run()` does not return until
/// the proxy is finished.
///
/// # What it reports
///
/// * [`ProxyControl::local_addr`] — the address the listener bound, or
///   [`ProxyError::NotBound`] before there is one.
/// * [`ProxyControl::sessions`] — the ids of the sessions that are live at this
///   instant.
/// * [`ProxyControl::stats`] — what this proxy's shaping has done across every
///   session it has accepted, ended ones included, cleared by
///   [`ProxyControl::reset_stats`]. The one report here that is cumulative
///   rather than instantaneous, which is why it survives the disconnect that
///   removes a session from the list above.
///
/// The first two are snapshots of a proxy that keeps moving. A session named by
/// `sessions()` may end before the next line of the caller's code runs;
/// that is not a defect in the snapshot but the reason every request that
/// takes a [`SessionId`] can answer [`ControlError::SessionEnded`].
///
/// # What it changes, and how far each change reaches
///
/// * `ProxyControl::set_impair` / `ProxyControl::clear_impair` — the next
///   datagram that leg's socket passes, in either direction. The only verb here
///   that reaches traffic already flowing over a connection that already
///   exists.
/// * [`ProxyControl::set_shaper_enabled`] — the next release decision each
///   queue makes, on every session already running.
/// * [`ProxyControl::set_shape`] — the next stream a running session forwards,
///   and every session accepted afterwards.
/// * [`ProxyControl::set_transport`] — the next connection the leg makes or
///   accepts, and **never** one that already exists.
/// * [`ProxyControl::close_session`], [`ProxyControl::reset_stream`],
///   [`ProxyControl::inject_control`] — one named session, or one stream of it,
///   immediately.
#[derive(Debug, Clone)]
pub struct ProxyControl {
    plane: Arc<ControlPlane>,
}

impl ProxyControl {
    /// Wrap a proxy's control state in a handle.
    pub(crate) fn new(plane: Arc<ControlPlane>) -> Self {
        Self { plane }
    }

    /// The address this proxy's listener is bound to.
    ///
    /// [`ProxyError::NotBound`] until
    /// [`TransparentProxy::run`](crate::proxy::TransparentProxy::run) has
    /// bound the endpoint, and again once it has returned and the endpoint
    /// is gone. Between those two points this is the address a client
    /// connects to, which is the reason the method exists: a proxy
    /// configured with port 0 chooses its port inside `run()`, and before
    /// this there was no way to learn which port that was without binding
    /// the socket in the caller and handing it in.
    ///
    /// A bound listener can still fail to report its address — the query
    /// goes to the operating system — and that failure is reported as
    /// [`ProxyError::Listener`], distinct from not being bound at all.
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        match self.plane.bound() {
            Some(listener) => listener.local_addr(),
            None => Err(ProxyError::NotBound),
        }
    }

    /// The ids of the sessions that are live right now.
    ///
    /// An id appears here when its session starts running and disappears
    /// when that session ends, for any reason at all — including the ones
    /// no teardown site could be written for. It is **not** a log: a
    /// session that has ended leaves nothing behind, so a caller that wants
    /// a history of everything the proxy handled reads
    /// [`ProxyEvent::SessionStarted`](crate::event::ProxyEvent::SessionStarted)
    /// and
    /// [`ProxyEvent::SessionEnded`](crate::event::ProxyEvent::SessionEnded)
    /// from its observer instead.
    ///
    /// Sorted ascending, which makes the value comparable between two calls
    /// without the caller sorting it first. Ids are minted monotonically per
    /// proxy, so the order is also arrival order.
    ///
    /// # This list and the event stream do not have to agree
    ///
    /// `SessionStarted` is emitted when a connection is accepted, before the
    /// session has dialled the upstream relay; registration here happens
    /// when the session begins to run. A session whose upstream connect
    /// fails is therefore reported as started, is briefly listed here, and
    /// then disappears — and a session that has been accepted but has not
    /// been polled yet is in the event stream and not in this list. Sessions
    /// driven by constructing a
    /// [`ProxySession`](crate::session::ProxySession) directly, rather than
    /// through a proxy's accept loop, appear in neither: they belong to no
    /// proxy and so to no control plane.
    pub fn sessions(&self) -> Vec<SessionId> {
        self.plane.live()
    }

    /// What this proxy's shaping has done, across every session it has
    /// accepted — including the ones that have already ended.
    ///
    /// The complement of [`Self::sessions`], and the difference between them
    /// is the whole reason this exists. That list is what is live *now* and
    /// shrinks when a client disconnects; these figures are cumulative and
    /// monotone, so a caller polling them across a disconnect sees them hold
    /// rather than fall. A total summed over the live list could not have
    /// that property: session registrations are released by a `Drop`, and a
    /// statistic that goes down under normal operation cannot be alerted on.
    ///
    /// It follows that a session which ended for any of the reasons no
    /// teardown site could be written for — its whole future dropped, its
    /// task cancelled mid-write — has still contributed everything it moved,
    /// because each unit was charged at the instant it was handled.
    ///
    /// Defined before the proxy has bound: a proxy that has accepted nothing
    /// answers `ProxyStats::default()` rather than an error, the same shape
    /// [`Self::sessions`] takes.
    ///
    /// # An all-zero answer means "no profile", not "no traffic"
    ///
    /// Every counter behind this is written by the shaping path, which a
    /// session with no [`ShapeProfile`] never enters. A proxy forwarding
    /// gigabytes with no profile configured reports
    /// `ProxyStats::default()`, and nothing in the value distinguishes that
    /// from a proxy nothing has connected to. Ask [`Self::sessions`], or an
    /// observer's event stream, which of the two it is.
    ///
    /// # Sessions driven directly are not counted
    ///
    /// A [`ProxySession`](crate::session::ProxySession) constructed by a
    /// caller instead of accepted by this proxy belongs to no control plane,
    /// so it reports only its own
    /// [`ShapeStats`](crate::shape::ShapeStats) — the same rule
    /// [`Self::sessions`] follows, and for the same reason: a proxy must not
    /// claim traffic it never accepted.
    ///
    /// # Cost
    ///
    /// A read of about forty relaxed atomics plus nine per class row, and
    /// one `Vec` and one `String` allocated per class row. Cheap, and still
    /// a reader's call rather than something to poll in a tight loop.
    pub fn stats(&self) -> ProxyStats {
        self.plane.stats.snapshot()
    }

    /// Zero every figure [`Self::stats`] reports, and start again from here.
    ///
    /// For a caller measuring a phase rather than a run: reset, drive the
    /// traffic, read. Without it the only way to get a phase figure is to
    /// subtract two snapshots, which is correct but leaves every assertion
    /// written against a difference rather than a value.
    ///
    /// # What it does not do
    ///
    /// It does not touch any session's own
    /// [`ShapeStats`](crate::shape::ShapeStats). Those are a session's for
    /// its whole life, and a proxy-level verb that silently rewrote them
    /// would make a scenario reading both see two different pasts.
    ///
    /// It does not clear the class rows themselves, only their counters. The
    /// rows are sized once, from the first shaped session this proxy
    /// accepts, because a class index means what the scheduler that produced
    /// it says it means; dropping them here would let the next session
    /// install a different class list and report figures under it.
    ///
    /// # It does not stop traffic
    ///
    /// The counters are cleared one relaxed store at a time while the
    /// forwarding tasks keep charging them, so a reset that races a live
    /// stream can land between two increments of the same unit and leave a
    /// row part-cleared. There is no atomic form of this — no primitive
    /// clears forty counters at once — and pausing the proxy to get one
    /// would be a far larger promise than the figures are worth. Reset when
    /// the traffic you are about to measure has not started.
    pub fn reset_stats(&self) {
        self.plane.stats.reset();
    }

    /// Set the QUIC transport parameters one leg uses — **for connections it
    /// has not made yet**.
    ///
    /// # This never reaches a connection that already exists
    ///
    /// Read that sentence as the whole of what this method does, because
    /// every other sentence here is a consequence of it. A QUIC connection
    /// takes its transport configuration once, at setup, and holds it for
    /// life; quinn exposes four setters on a connection that is already up —
    /// the two stream-count limits and the two windows — and no way at all
    /// to hand it a different configuration. So a profile set here reaches:
    /// * on [`Leg::Upstream`], the next connection **this proxy opens**, which
    ///   is the next session it accepts, because a session dials the relay
    ///   once and then forwards over that connection until it ends;
    ///
    /// * on [`Leg::Client`], the next connection **this proxy accepts**, which
    ///   the proxy does not initiate and which may never arrive.
    ///
    /// It follows that on a proxy which never dials or accepts again — one
    /// whose clients have all connected, one nothing is connecting to, one
    /// about to be cancelled — this call is a **permanent silent no-op that
    /// returns `Ok(())`**. Nothing about the return value distinguishes that
    /// from a setting that reached every connection made afterwards, because
    /// there is nothing to distinguish: the parameters were installed, and
    /// what did or did not happen next is traffic rather than configuration.
    /// A caller that needs the change to bite on a session already running
    /// has one instrument, and it is
    /// [`ProxyControl::close_session`] — a leg that reconnects is a leg
    /// that installs this.
    ///
    /// # Every call is absolute: `None` is a default, not "leave alone"
    ///
    /// The profile is built into a **fresh** `quinn::TransportConfig` — a
    /// `TransportConfig::default()` with the profile applied over it — and
    /// that config is installed whole. So a field left `None` is not carried
    /// over from the profile installed before it: it takes quinn's default.
    ///
    /// Two consecutive calls therefore do not compose. A call setting
    /// `stream_receive_window` followed by a call setting only
    /// `max_idle_timeout` leaves the leg with the idle timeout **and quinn's
    /// default window**, not with both settings. `TransportProfile::default()`
    /// puts a leg back on quinn's defaults entirely, which is the only way to
    /// clear a setting and is why this is worth stating: a merge would look
    /// like a convenience and would make `None` mean two different things —
    /// "unset" when a profile is built and "unchanged" when it is installed —
    /// leaving no profile that could ever clear a field, and no way for a
    /// caller restoring normal conditions to say so.
    ///
    /// # What it replaces
    ///
    /// Whatever that leg's transport parameters were, whether they came from
    /// a [`TransportProfile`] or from a raw `quinn::TransportConfig` in the
    /// configuration the proxy was built with. The two cannot be combined —
    /// see
    /// [`ProxyError::TransportConfigAndProfile`]
    /// — so a live profile that was merged with a configured raw config
    /// would be a merge that cannot be written; a live profile that sat
    /// beside one would turn every subsequent connect into that refusal.
    /// Replacing is the only answer that leaves the leg usable, and it means
    /// a caller who set a raw config at build time loses it from the first
    /// call to this.
    ///
    /// The profile is built through the leg's own
    /// [`TransportInstaller`] when the
    /// proxy was given one, so a leg keeps building its configuration the
    /// way it always did.
    ///
    /// # Errors
    ///
    /// [`ControlError::Profile`] for a profile the leg would not have
    /// started with — the same check, reporting the same error, run here
    /// rather than at the next connect, so a refusal is attached to the call
    /// that caused it instead of to a connection failure minutes later.
    ///
    /// [`ControlError::Unsupported`] on [`Leg::Upstream`] when the upstream
    /// is WebTransport. That endpoint is built inside the WebTransport
    /// library, which takes no `quinn::TransportConfig` and hands back no
    /// endpoint to install one on, so the profile could only be stored and
    /// ignored.
    pub fn set_transport(&self, leg: Leg, p: TransportProfile) -> Result<(), ControlError> {
        match leg {
            Leg::Client => {
                let config = self.plane.build_transport(leg, &p)?;
                self.plane.set_client_transport(config);
                Ok(())
            }
            Leg::Upstream if self.plane.legs.upstream_webtransport => Err(
                // Named exactly as the field on `ProxySessionConfig` names
                // it, so the refusal and the setting it refuses read as the
                // same thing.
                ControlError::Unsupported {
                    what: "transport profile",
                    leg,
                    transport: "webtransport",
                },
            ),
            Leg::Upstream => {
                // Built and thrown away: the point is the refusal, which has
                // to happen now rather than at the next dial. The profile
                // itself is what is stored, so each session still runs the
                // installer once for its own connection exactly as a
                // configured profile does.
                self.plane.build_transport(leg, &p)?;
                *self.plane.upstream_transport.lock().expect("control plane") = Some(p);
                Ok(())
            }
        }
    }

    /// Replace the shaping profile this proxy's sessions pace with.
    ///
    /// # What it reaches, and when
    ///
    /// Every session this proxy accepts afterwards shapes with `p`, whatever
    /// the profile it was configured with.
    ///
    /// A session that is **already running** picks `p` up at the next stream
    /// it forwards, not at the next object. That granularity is forced: a
    /// stream's egress queue holds the scheduler its units were admitted
    /// under, and a class is an index into that scheduler's class list, so a
    /// unit classified under one profile and released under another charges
    /// one profile's class against the other profile's buckets. Streams
    /// already forwarding therefore run to their end under the profile they
    /// started with, and on MoQT that is rarely a long wait — media arrives
    /// on a fresh unidirectional stream per subgroup.
    ///
    /// A session that started **unshaped** stays unshaped for its whole
    /// life, and nothing here changes that. Shaping classifies
    /// [`ObjectMeta`](crate::framer::ObjectMeta), which only the object
    /// framer produces, and whether a session frames at all is settled at
    /// session start from the profile it was configured with. A session that
    /// began as a byte pump has no objects to classify and no queue to pace.
    ///
    /// # A session whose class list would change keeps its own profile
    ///
    /// A running session takes `p` only if `p`'s class names are the same,
    /// in the same order, as the ones the session started with. Otherwise it
    /// keeps the profile it has until it ends, and only sessions accepted
    /// afterwards get the new one.
    ///
    /// The reason is the statistics.
    /// [`ShapeStats`](crate::shape::ShapeStats) has one row per configured
    /// class, pre-sized when the session is constructed and never resized,
    /// and a class is charged to its row **by position**. A profile with a
    /// different class list would therefore charge its classes to rows still
    /// named after the old profile's — every number in
    /// [`ProxySession::shape_stats`](crate::session::ProxySession::shape_stats)
    /// correct, and every label on it wrong — or, for a class beyond the end
    /// of the original list, silently to the default row. Refusing the swap
    /// per session is the only answer that keeps a reader's numbers
    /// attributable. To move a running session onto a different class list,
    /// end it with [`ProxyControl::close_session`]; its replacement starts
    /// on the new profile.
    ///
    /// # Buckets start full
    ///
    /// A session that takes `p` builds a scheduler for it, and a fresh
    /// scheduler's buckets are full as of that instant — the same choice a
    /// session's first scheduler makes, so that a session does not open with
    /// a burst-sized delay in front of its first object. Setting the same
    /// profile repeatedly therefore hands every class a fresh burst each
    /// time, and a caller doing that in a tight loop measures no rate limit
    /// at all. The report-once diagnostics
    /// (`ImpairmentKind::ShapeRuleUnmatchable`,
    /// `ImpairmentKind::ShapeBurstBelowUnit`) start again with the new
    /// scheduler too, so a rule that is unmatchable under both profiles is
    /// reported once per profile rather than once per session.
    ///
    /// # Errors
    ///
    /// [`ControlError::Shape`] for a profile [`ShapeProfile::try_new`]
    /// rejects. Since that constructor is the only way to build a
    /// `ShapeProfile`, a profile arriving here has already passed it and the
    /// refusal is unreachable today; the check is re-run rather than assumed
    /// so that the rules live in exactly one place and a later construction
    /// path cannot arrive here unchecked.
    pub fn set_shape(&self, p: ShapeProfile) -> Result<(), ControlError> {
        // Through the constructor, not around it: re-validating field by
        // field here would be a second copy of the rules, and the two would
        // drift in the direction that accepts something a session cannot
        // run.
        let checked = ShapeProfile::try_new(
            p.buckets().to_vec(),
            p.classes().to_vec(),
            p.queue().clone(),
            p.discipline(),
        )?;
        self.plane.shape.set(checked);
        Ok(())
    }

    /// Turn pacing off, or back on, for every session this proxy is running
    /// and every session it accepts afterwards.
    ///
    /// Off is not "no profile". The profile stays exactly where it was, the
    /// classes keep claiming units, the per-stream queue depth keeps
    /// applying and the statistics keep moving — what stops is the token
    /// bucket and the discipline, so every unit is released as soon as the
    /// queue reaches it. `set_shaper_enabled(true)` resumes with the same
    /// configuration and the same counters, which is what makes this usable
    /// as a switch in a timeline rather than as a way of throwing a profile
    /// away.
    ///
    /// # When a stream that is already held resumes
    ///
    /// The switch is read on the next release decision a queue makes, and a
    /// queue makes one when its head's wait expires. Switching pacing off
    /// therefore does not reach into a wait that is already running; it
    /// changes the answer the stream gets when that wait ends. How long that
    /// is depends on why the stream was held:
    /// * held by a bucket that will refill — one unit's worth of the
    ///   configured rate, so a stream paced at a real rate resumes within one
    ///   pacing interval;
    ///
    /// * held behind another class — as soon as that class drains, which is now
    ///   immediate;
    /// * held by a bucket configured at **zero**, or one whose burst cannot
    ///   cover a unit — there is no refill instant, so the stream's wait is the
    ///   queue's `max_hold` clamp and the switch is not read until it fires. On
    ///   a stopped class, switching pacing off does **not** promptly release
    ///   what is already queued. Nothing in this crate can: the wait is a timer
    ///   a per-stream queue armed, and there is no session-wide wake that
    ///   reaches one. Use [`ProxyControl::set_shape`] to move the session onto
    ///   a profile with a rate, or end the session, if that is what is wanted.
    ///
    /// # It changes nothing on a proxy with no profile
    ///
    /// Returns nothing, and cannot fail, so it is silent about a proxy where
    /// no session has a [`ShapeProfile`] to pace with — there is nothing to
    /// switch and no consequence to report. That is the one case where
    /// calling this has no observable effect whatever.
    pub fn set_shaper_enabled(&self, on: bool) {
        self.plane.shape.set_enabled(on);
    }

    /// Install a datagram impairment on one leg's socket.
    ///
    /// Effective from the next datagram that leg passes through its socket,
    /// in both directions. It is the only verb here that reaches traffic
    /// already in flight, because it acts below QUIC on the datagrams
    /// themselves rather than on anything a connection settled at setup.
    /// Datagrams already handed to the operating system are gone — the shim
    /// sees a datagram once, on its way through, and a profile armed after that
    /// cannot recall it. So *effective immediately* means the next datagram,
    /// not the last one.
    ///
    /// The other leg is untouched. The two are separate sockets carrying
    /// separate connections, and a profile armed on one says nothing about
    /// the other.
    ///
    /// Arming replaces whatever was armed before, resets both directions'
    /// sequence numbers and moves the tick origin to this instant, so a
    /// recorded decision log reads from the moment of the call. It does not
    /// clear the counters.
    ///
    /// # Errors
    ///
    /// [`ControlError::Unsupported`] when this proxy holds no impairment
    /// handle for `leg` — which is every leg unless the socket and its
    /// handle were handed over together before `run()`, and the refusal says
    /// so and names the call that fixes it. This is the case that must not
    /// be silent: a profile stored against a leg whose datagrams never cross
    /// an impaired socket is armed, reported as applied, and applied to
    /// nothing, and the run that follows looks clean because it *is* clean.
    ///
    /// [`ControlError::Impairment`] for a profile `quinn-netem` refuses,
    /// carrying that crate's own reason unchanged — which of the thirteen
    /// ways a profile arms and does nothing this one is. A caller therefore
    /// learns what is wrong from the answer to the call that was wrong,
    /// rather than by running `quinn_netem::ImpairProfile::validate` again
    /// to find out. A refused profile changes nothing — whatever was armed
    /// before is still armed.
    ///
    /// # No observer event, and that is a decision rather than an omission
    /// Nothing is emitted here — not on arming, not on the first datagram the
    /// profile touches. Three separate reasons, and the first alone settles it:
    /// * **there is no session to name.** Every
    ///   [`ProxyEvent`](crate::event::ProxyEvent) variant carries a
    ///   [`SessionId`], and observers dispatch on it. A leg's socket carries
    ///   every session on that leg, including the ones this proxy has not
    ///   accepted yet — and those are precisely the sessions the profile will
    ///   impair for their whole lives. Fanning one event out over the sessions
    ///   that happen to be live would be a report that is silent about the
    ///   population it most affects.
    /// * **the caller already knows.** This method is synchronous and its
    ///   return value is the answer. An event saying *the thing you just asked
    ///   for was accepted* tells an observer nothing the call site did not
    ///   have.
    /// * **the consequence is not observable from here.** The shim acts below
    ///   QUIC, on datagrams that have already been encrypted and coalesced, so
    ///   nothing in this crate can say which session or which stream lost what.
    ///   `quinn-netem`'s own counters and decision log are the report for that,
    ///   and they are read through the handle rather than through an event
    ///   stream.
    ///
    /// What an observer *does* see is the fallout: a leg impaired hard
    /// enough produces ordinary session and stream events — resets, parse
    /// errors, [`ProxyEvent::SessionEnded`](crate::event::ProxyEvent::SessionEnded)
    /// — with no marker distinguishing them from the same failures arriving
    /// from a real network. That is the honest position: the proxy cannot
    /// tell either.
    #[cfg(feature = "impair")]
    pub fn set_impair(&self, leg: Leg, p: quinn_netem::ImpairProfile) -> Result<(), ControlError> {
        let handle = self.plane.impair_handle(leg).ok_or(ControlError::Unsupported {
            what: "a datagram impairment",
            leg,
            transport: ControlPlane::NO_SOCKET,
        })?;
        handle.arm(p).map_err(|source| ControlError::Impairment { leg, source })
    }

    /// Remove the datagram impairment from one leg's socket.
    ///
    /// Effective from the next datagram that leg passes, exactly as
    /// [`ProxyControl::set_impair`] is, and idempotent: clearing a leg that
    /// is not impaired is not an error and not a state change. The other leg
    /// keeps whatever it has.
    ///
    /// The counters and the decision log are **not** cleared. A scenario
    /// that armed an impairment, cleared it and then read what it had done
    /// would otherwise find nothing, with no counter anywhere saying a phase
    /// had been discarded.
    ///
    /// A leg this proxy holds no handle for has nothing to clear and nothing
    /// happens. Unlike `set_impair` there is no refusal to give — the
    /// signature returns nothing — and none is owed: the request was to have
    /// no impairment on that leg, and that is exactly the state it is in.
    /// A caller finding out whether the proxy can impair a leg at all asks
    /// `set_impair`.
    ///
    /// # No observer event
    ///
    /// For the reasons `set_impair` gives, all of which apply unchanged: no
    /// session to name, a synchronous answer the caller already has, and a
    /// consequence — datagrams no longer being interfered with — that is
    /// invisible from above QUIC by construction. Disarming is even less
    /// reportable than arming, because what it produces is the *absence* of
    /// a loss, and there is no event for a packet that was not dropped.
    #[cfg(feature = "impair")]
    pub fn clear_impair(&self, leg: Leg) {
        if let Some(handle) = self.plane.impair_handle(leg) {
            handle.disarm();
        }
    }

    /// End one session, giving its egress queues a bounded window to flush
    /// first, and close both of its legs with `code` and `reason`.
    ///
    /// Returns as soon as the request has been taken. The drain and the
    /// close happen in the session, which is the only place that can see
    /// them through — a method that waited would have to hold the caller
    /// for as long as the drain took, and the drain is bounded precisely so
    /// that nobody has to.
    ///
    /// # The window, and what happens at the end of it
    ///
    /// The window is
    /// [`EgressConfig::drain_timeout`](crate::action::EgressConfig::drain_timeout)
    /// from the session's configuration, 100 ms by default. Within it, the
    /// session keeps running exactly as it was: units come off the
    /// per-stream queues at their release times, a shaped class keeps
    /// paying its bucket, and a hook that deferred something still gets it
    /// written. The window ends early — and this is the common case — the
    /// moment the session has nothing queued anywhere.
    ///
    /// When it ends because the timeout expired, whatever is still queued
    /// is **abandoned and reported**, once per stream, as
    /// [`ImpairmentKind::QueuedBytesAtTeardown`](crate::event::ImpairmentKind::QueuedBytesAtTeardown).
    /// It is not flushed first. A flush at that point would hand the bytes
    /// to a connection that is about to send `CONNECTION_CLOSE`, which
    /// discards whatever it had buffered — so the bytes would be neither
    /// confirmably delivered nor confirmably lost, and no count of them
    /// would add up. Abandoning them keeps the arithmetic exact: what the
    /// peer received plus what the impairments name is what was queued when
    /// this was called.
    ///
    /// Either way the session then closes with `code` and `reason`. That
    /// part is unconditional for the call that was accepted — a drain that
    /// ran out of time changes what reached the peer, never what the close
    /// says. A call that is *refused* starts nothing at all; see **Errors**,
    /// which covers the one refusal a caller can produce deliberately.
    ///
    /// # Control streams are not repaired
    ///
    /// Nothing is synthesized on a control stream to tidy up the close. If
    /// a control message was half-written when the window closed, the peer
    /// gets a truncated message and the session reports
    /// [`ImpairmentKind::ControlStreamTruncated`](crate::event::ImpairmentKind::ControlStreamTruncated).
    /// Completing the message would mean the proxy inventing control-stream
    /// bytes that neither peer wrote.
    ///
    /// # Errors
    ///
    /// [`ControlError::SessionEnded`] when the session has already ended or
    /// is already ending — the ordinary race, since a session may end
    /// between listing it and closing it — and
    /// [`ControlError::NoSuchSession`] for an id this proxy never ran.
    ///
    /// "Already ending" covers one case that is not a race at all, and a
    /// caller can produce it deliberately: **a second call while the first
    /// call's drain window is still open**. The first close fixed the code
    /// and the reason and nothing revises them, so a second call's pair
    /// would reach neither peer. It is refused here rather than accepted,
    /// because the only alternative is to take a request and drop it — the
    /// session's command task is inside the first drain and cancels when it
    /// comes out, so it never returns for a second. A caller that wants a
    /// different code has to ask before the first close, not after it.
    ///
    /// One thing can survive a refusal, and only in the direction that
    /// helps: a call that got as far as fixing the pair and then found the
    /// session unreachable still closes it with what was asked for. So a
    /// caller that sees this error was either late for everything — the two
    /// refusals above — or late only for the drain.
    ///
    /// # What an observer sees
    /// This is the one verb here that produces events, and it produces them
    /// through the session rather than from this call — after the drain, which
    /// is what makes them a record of what happened rather than of what was
    /// asked for:
    ///
    /// * one
    ///   [`ProxyEvent::SessionEnded`](crate::event::ProxyEvent::SessionEnded)
    ///   whose `reason` begins **`*control plane closed the session*`** and
    ///   quotes `code` and `reason`. That wording is the point: a hook's
    ///   `Action::CloseSession` reaches the same latch and reports `*hook
    ///   closed the session*`, and for a while both said the latter, so an
    ///   operator ending a session was recorded as the scenario under test
    ///   ending it.
    /// * one
    ///   [`ImpairmentKind::QueuedBytesAtTeardown`](crate::event::ImpairmentKind::QueuedBytesAtTeardown)
    ///   per stream the window ran out on, and none at all for the ordinary
    ///   case where everything drained.
    /// * at most one
    ///   [`ImpairmentKind::ControlStreamTruncated`](crate::event::ImpairmentKind::ControlStreamTruncated)
    ///   per control direction that was mid-message when the window closed.
    ///
    /// Nothing is emitted at the moment the request is *accepted*. The
    /// return value is that answer, and an event that duplicated it would be
    /// the only event in this enum an observer could receive for something
    /// that had not happened yet.
    pub fn close_session(
        &self,
        id: SessionId,
        code: u32,
        reason: &[u8],
    ) -> Result<(), ControlError> {
        let handle = self.plane.reach(id)?;
        // Recorded here rather than in the session task so that the pair is
        // fixed the instant the request is accepted. A session that is torn
        // down by its peer half a millisecond later still closes with the
        // code that was asked for, which is what makes this method's
        // promise independent of how long the session survives it.
        //
        // A *losing* record is a session that some other close already
        // owns — a second call inside the first one's drain window, or a
        // hook's `Action::CloseSession` that landed between the lookup above
        // and this line. The first writer keeps the pair, so this call's
        // code and reason are going nowhere, and the request is refused
        // instead of handed over. Handing it over would be this crate's
        // cardinal failure in miniature: a close accepted, reported as
        // applied, and reaching neither peer.
        if !handle.closer.record(code, Bytes::copy_from_slice(reason)) {
            return Err(ControlError::SessionEnded(id));
        }
        handle.request(id, SessionCommand::Close { drain: handle.egress.drain_timeout })
    }

    /// Reset one live forwarded stream, immediately.
    ///
    /// `stream` names a stream this session is forwarding; the key is the
    /// one carried on the events and hook contexts for that stream. `code`
    /// becomes the `RESET_STREAM` application error code on the
    /// destination, and the source is stopped with the same code, so both
    /// peers learn the stream was abandoned rather than finished.
    ///
    /// # Bytes already handed to the transport are gone
    ///
    /// A reset abandons the destination stream. Whatever the proxy had
    /// written but the transport had not yet acknowledged goes with it —
    /// QUIC does not retransmit data on a stream that has been reset — and
    /// so does everything this stream still had queued. That is what a
    /// reset *is*, and it is why the method exists, but it means the peer's
    /// view of this stream ends at an arbitrary byte and no count of what
    /// it received is predictable from what was sent.
    ///
    /// # Errors
    ///
    /// [`ControlError::NoSuchStream`] when no stream with that key is live
    /// — which is the same answer for a key that never existed and for one
    /// whose stream has already ended, because a stream's registration is
    /// removed as it ends and nothing is left to tell them apart. Plus the
    /// two session-level refusals.
    ///
    /// # One case where `Ok(())` is delivery rather than a reset
    ///
    /// The request is handed to the task that owns the stream's write half
    /// and is acted on the next time that task comes round its own loop,
    /// which is immediately in every case but one. A *control* direction on
    /// the forward-first pipe stops reading its request channel once it is
    /// holding [`COMMAND_QUEUE_DEPTH`](self) injections it has not been able
    /// to place — the backpressure that makes a further
    /// [`ProxyControl::inject_control`] answer
    /// [`ControlError::SessionEnded`] rather than queue without limit — and a
    /// reset handed over in that state waits until an injection can be
    /// written, which that method's own documentation says can be never.
    /// Below that depth, and on every data stream, the reset is served at
    /// once.
    ///
    /// # No observer event, and neither existing one may be borrowed
    ///
    /// The stream's task performs the reset and emits nothing.
    /// [`ProxyEvent::StreamReset`](crate::event::ProxyEvent::StreamReset)
    /// means a teardown this proxy *observed* a peer perform, and
    /// [`ProxyEvent::ActionApplied`](crate::event::ProxyEvent::ActionApplied)
    /// means a hook asked for one at a named site. Reusing either would make
    /// it ambiguous for every reader that already relies on it — an observer
    /// counting peer resets would start counting the operator's, with
    /// nothing in the payload to separate them — and this crate does not
    /// widen the meaning of a shipped event to save adding one.
    ///
    /// A variant of its own was considered and declined: it would carry
    /// nothing the caller does not already hold. The session, the stream and
    /// the code came from this call, and the answer to "did it happen" is
    /// the return value. What is worth observing is the *consequence*, and
    /// that is observed where consequences are — at the peer, as a
    /// `RESET_STREAM` carrying `code`, which is what this crate's own gate
    /// for the method checks.
    ///
    /// Anything the stream still had queued goes with it and is **not**
    /// reported as
    /// [`ImpairmentKind::QueuedBytesAtTeardown`](crate::event::ImpairmentKind::QueuedBytesAtTeardown).
    /// That report is about a *teardown* losing bytes it was trying to
    /// deliver; here the caller asked for the destination to be abandoned,
    /// and the bytes going with it is what the word means rather than a
    /// reduction in what the proxy could do.
    pub fn reset_stream(
        &self,
        id: SessionId,
        stream: StreamKey,
        code: u64,
    ) -> Result<(), ControlError> {
        let handle = self.plane.reach(id)?;
        let inbox =
            handle.streams.inbox_for(stream).ok_or(ControlError::NoSuchStream { id, stream })?;
        match inbox.try_send(StreamCommand::Reset { code }) {
            Ok(()) => Ok(()),
            // The task ended between the lookup and the send, so its
            // receiver is gone. Indistinguishable, to a caller, from a key
            // that was already retired — and reported the same way.
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(ControlError::NoSuchStream { id, stream })
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err(ControlError::SessionEnded(id)),
        }
    }

    /// Put a control message on one leg of a live session, in sequence.
    ///
    /// `leg` names whose decoder the message is for:
    /// [`Leg::Client`] writes toward the client, [`Leg::Upstream`] toward
    /// the relay. The bytes are written onto the **session's existing
    /// control stream**, interleaved with the messages already flowing on
    /// it, at a point the receiving decoder accepts.
    ///
    /// # What "in sequence" costs, and why it is not a fresh stream
    ///
    /// A new stream would be far simpler and would look like working code:
    /// the write succeeds, the bytes arrive. The peer reads them as
    /// whatever a new stream of that kind is — a data stream header on a
    /// fresh unidirectional stream, a request on a fresh bidirectional one
    /// — and the message is never seen as a control message at all. On the
    /// drafts that carry the control plane on unidirectional streams it
    /// would be worse than useless: a second stream announcing itself as a
    /// control stream is a second SETUP, which a peer is entitled to close
    /// the session over. So the write goes to the task that owns the
    /// control stream's write half, and lands between two forwarded
    /// messages rather than inside one — a control stream is a single
    /// framed byte sequence, and bytes spliced into the middle of a
    /// message's payload desynchronize the peer's decoder for the rest of
    /// the session.
    ///
    /// Because of that, a message injected while one is mid-flight is held
    /// until the message in flight has been written. That wait is bounded
    /// by the peer finishing the write it started, not by anything this
    /// proxy does.
    ///
    /// # A held message can wait forever, and this returns `Ok(())` anyway
    /// The call returns as soon as the request has been taken, before any write
    /// is attempted — it has to, or a caller would be held for as long as the
    /// peer took. So `Ok(())` means *accepted for writing*, and on the
    /// forward-first control pipe — the one a session takes unless a hook
    /// declared `Interest::CONTROL` — there are two ways for the write never to
    /// happen:
    /// * **the direction goes quiet mid-message.** That pipe forwards read
    ///   chunks and finds the boundaries in the bytes it is forwarding, so a
    ///   direction whose peer stopped writing part-way through a message never
    ///   reaches one. The injection waits for a peer that may never write
    ///   again.
    /// * **the proxy has lost the framing.** The boundary walk is driven by the
    ///   session's draft, which for the moq-00 cohort (drafts 07-14) is a
    ///   configured guess until a SETUP is peeked. A wrong guess makes the
    ///   lengths wrong; rather than place a message by guesswork the walk
    ///   latches to *the boundaries are unknown*, and from then on nothing is
    ///   injected on that direction at all. That is deliberate and it is the
    ///   better of the two outcomes — a misplaced injection desynchronizes the
    ///   peer's decoder for the rest of the session, while one that never
    ///   arrives leaves every other message intact.
    ///
    /// A message still held when the session ends is discarded, and nothing
    /// reports it: no event, no impairment, no error. A caller that needs to
    /// know an injection landed observes it at the peer, which is what this
    /// crate's own gate for the method does.
    ///
    /// That silence is the weakest point on this page, and it is written
    /// down rather than smoothed over. An accepted request that never
    /// reaches the wire is exactly the failure this crate refuses
    /// everywhere else, and the only thing standing in for a report is the
    /// paragraph above. An impairment for it was considered and not added:
    /// the held messages live in a local deque of the control pipe, the
    /// pipe returns from seven places, and a report wired into some of them
    /// would be a promise that is kept for some teardowns and not others —
    /// which is worse than no promise, because a scenario would then read
    /// the absence of the event as delivery. The report that would be worth
    /// having has to be raised by something whose completeness is
    /// structural, the way `SessionGuard` is for the session census, and
    /// that is not a wiring change.
    ///
    /// A hook declaring `Interest::CONTROL` puts the stream on the pipe that
    /// decodes each message before forwarding it, where every return to the
    /// select is a boundary by construction and neither case above exists.
    ///
    /// # `bytes` must already be framed, and is not checked
    ///
    /// Pass a complete, framed control message for the session's draft —
    /// what `AnyControlMessage::encode` produces, which is the type varint,
    /// the length field, and the payload. The proxy writes it verbatim: it
    /// does not frame it, does not decode it, and does not know what it
    /// says. A payload passed without its framing is the second way to get
    /// this wrong that still looks like working code — the write succeeds
    /// and the peer's decoder reads the first bytes of the payload as a
    /// message type and length, and is lost from there on.
    /// Nothing is validated because there is nothing to answer with: the
    /// refusals this method can give are about *reaching* a session, and
    /// inventing a *those bytes were not a message* refusal would mean decoding
    /// every injection on the session's forwarding path.
    ///
    /// # Which stream that is, per draft
    ///
    /// Two topologies, and the session picks between them from its draft.
    /// Through draft 16 the control plane is one client-initiated
    /// bidirectional stream and `leg` names which of its two directions to
    /// write on. From draft 17 it is a **pair of unidirectional streams**,
    /// one opened by each peer, and bidirectional streams carry requests
    /// instead — draft-17 Section 3.3. There `leg` names which of the two
    /// unidirectional control streams to write on, and a request stream is
    /// never a candidate: the session routes an injection to the control
    /// leg's channel, which only a control direction's pipe ever serves.
    ///
    /// The `leg` mapping is the same on both: the leg is the peer whose
    /// decoder reads what is written. [`Leg::Upstream`] puts the message in
    /// front of the relay, [`Leg::Client`] in front of the client.
    ///
    /// # Errors
    ///
    /// The two session-level refusals. A session whose control stream has
    /// not been established yet is **not** an error: the message waits and
    /// is written as soon as there is a stream to write it on. On drafts 17
    /// and later that wait covers a little more ground — the control stream
    /// is identified from the first varint of a unidirectional stream, so a
    /// session whose peer has not opened one yet has no control stream in
    /// that direction and the message waits for it exactly as it waits for
    /// a message boundary.
    ///
    /// # What an observer sees
    ///
    /// Nothing for the injection itself — no event on acceptance, none on
    /// the write, none on the discard described above. The bytes are written
    /// verbatim and are never decoded here, so there is no message to put on
    /// a
    /// [`ProxyEvent::ControlMessage`](crate::event::ProxyEvent::ControlMessage)
    /// and no honest way to synthesize one; and the peer's own reaction, if
    /// it has one, arrives as ordinary forwarded traffic.
    pub fn inject_control(
        &self,
        id: SessionId,
        leg: Leg,
        bytes: Vec<u8>,
    ) -> Result<(), ControlError> {
        let handle = self.plane.reach(id)?;
        handle
            .control_inbox(leg)
            .try_send(StreamCommand::Inject { bytes: Bytes::from(bytes) })
            .map_err(|_| ControlError::SessionEnded(id))
    }
}

/// The state a [`ProxyControl`] reads, owned by the proxy and shared with
/// every handle it hands out.
///
/// One per [`TransparentProxy`](crate::proxy::TransparentProxy), never
/// process-global: session ids are minted from a counter on the proxy and
/// start again at 1 for each one, so two proxies in a process would collide
/// on every id in a shared table.
pub(crate) struct ControlPlane {
    /// The client-facing leg: the listener once it exists, and the transport
    /// parameters a live request has installed on it.
    ///
    /// One lock over both because the two have to move together. A request
    /// arriving while `run()` is between binding the endpoint and publishing
    /// it must not be dropped: it stores the parameters and finds no
    /// listener, and the publish then installs them. Split across two locks
    /// there is a window in which a request stores its parameters after the
    /// publish has read them and before the listener is visible, and the
    /// setting is accepted, reported as applied, and reaches nothing.
    client: Mutex<ClientLeg>,
    /// The transport parameters a live request has set for the relay leg, or
    /// `None` while the proxy's own template is what every session dials
    /// with.
    upstream_transport: Mutex<Option<TransportProfile>>,
    /// The two legs' fixed facts, from the configuration the proxy was built
    /// with.
    legs: LegSetup,
    /// This proxy's shaping profile and its pacing switch.
    shape: ShapeControl,
    /// What every session this proxy accepts reports its shaping figures
    /// into, on top of its own.
    ///
    /// Held here rather than on the [`TransparentProxy`] because this is
    /// what a session is already handed: `attach_control` is the one call
    /// that reaches every accepted session and no directly-driven one, which
    /// is exactly the set whose traffic belongs in a proxy-wide total.
    ///
    /// Constructed with the plane and never replaced, so it outlives every
    /// session and a total taken from it never falls when one ends —
    /// unlike [`Self::sessions`], whose entries are released by a `Drop`.
    stats: Arc<ProxyRecorder>,
    /// The two legs' impairment handles, indexed by [`Self::leg_index`].
    ///
    /// `None` for a leg whose socket this proxy did not wrap, which is every
    /// leg unless the caller handed both halves over — see
    /// [`TransparentProxy::set_impaired_socket`](crate::proxy::TransparentProxy::set_impaired_socket).
    #[cfg(feature = "impair")]
    impair: Mutex<[Option<quinn_netem::ImpairHandle>; 2]>,
    /// Every session that is running right now.
    sessions: Mutex<HashMap<SessionId, SessionHandle>>,
    /// The highest id ever registered here.
    ///
    /// The only trace a finished session leaves, and it exists to separate
    /// [`ControlError::SessionEnded`] from [`ControlError::NoSuchSession`].
    /// Ids are minted monotonically from a counter on the proxy, so an id
    /// at or below this one has run; anything above it has not. A set of
    /// retired ids would answer the same question and would grow for the
    /// life of the proxy.
    ///
    /// `0` before any session registers, and no session is ever `SessionId(0)`.
    high_water: AtomicU64,
}

// Hand-written rather than derived because `Listener` has no `Debug`, and
// giving it one would widen a public type's surface for a diagnostic nobody
// reads. Nothing here prints the sessions either: the map is behind a lock
// that a formatting call has no business taking, and `sessions()` is the
// supported way to ask.
impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane").finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// An empty control plane: nothing bound, no sessions.
    pub(crate) fn new(legs: LegSetup) -> Arc<Self> {
        Arc::new(Self {
            client: Mutex::new(ClientLeg { listener: None, transport: None }),
            upstream_transport: Mutex::new(None),
            legs,
            shape: ShapeControl::new(),
            stats: Arc::new(ProxyRecorder::new()),
            #[cfg(feature = "impair")]
            impair: Mutex::new([None, None]),
            sessions: Mutex::new(HashMap::new()),
            high_water: AtomicU64::new(0),
        })
    }

    /// Publish `listener` as this proxy's bound endpoint, and hand back the
    /// guard that un-publishes it.
    ///
    /// A guard rather than a matching `clear` call because the accept loop
    /// leaves by three routes — cancellation, a fatal listener error
    /// propagated with `?`, and the whole future being dropped by whoever
    /// spawned it — and only one of them is a place a call could be
    /// written.
    ///
    /// Any transport parameters a request set before there was a listener
    /// are installed here, under the same lock the request took, which is
    /// what makes a request that arrives during the bind land on the
    /// endpoint rather than on nothing.
    pub(crate) fn publish_listener(self: &Arc<Self>, listener: Arc<Listener>) -> BoundGuard {
        let mut client = self.client.lock().expect("control plane");
        if let Some(transport) = &client.transport {
            listener.set_transport(Arc::clone(transport));
        }
        client.listener = Some(listener);
        drop(client);
        BoundGuard { plane: Arc::clone(self) }
    }

    /// The bound listener, or `None` before there is one.
    fn bound(&self) -> Option<Arc<Listener>> {
        self.client.lock().expect("control plane").listener.clone()
    }

    /// Forget the bound listener.
    fn unbind(&self) {
        self.client.lock().expect("control plane").listener = None;
    }

    /// The transport parameters the client leg should bind with, or `None`
    /// when no request has set any and the proxy's template stands.
    pub(crate) fn client_transport(&self) -> Option<Arc<quinn::TransportConfig>> {
        self.client.lock().expect("control plane").transport.clone()
    }

    /// Install `transport` on the client leg, now if there is an endpoint
    /// and at bind time if there is not.
    fn set_client_transport(&self, transport: Arc<quinn::TransportConfig>) {
        let mut client = self.client.lock().expect("control plane");
        client.transport = Some(Arc::clone(&transport));
        if let Some(listener) = &client.listener {
            listener.set_transport(transport);
        }
    }

    /// The profile every session this proxy accepts from now on dials the
    /// relay with, or `None` when the proxy's template stands.
    pub(crate) fn upstream_transport(&self) -> Option<TransportProfile> {
        self.upstream_transport.lock().expect("control plane").clone()
    }

    /// This proxy's shaping profile and pacing switch, for a session to
    /// build its scheduler from and to watch.
    pub(crate) fn shape(&self) -> &ShapeControl {
        &self.shape
    }

    /// The proxy-wide shaping counters, for a session to report into.
    ///
    /// Handed out as an `Arc` clone rather than a borrow because the session
    /// keeps it: its recorder forwards into this for the session's whole
    /// life, which outlives any borrow of the plane a call could hold.
    pub(crate) fn stats_recorder(&self) -> Arc<ProxyRecorder> {
        Arc::clone(&self.stats)
    }

    /// Turn `profile` into the config `leg` would install, refusing exactly
    /// what a configured profile on that leg would be refused for.
    ///
    /// Built through the leg's own [`TransportInstaller`] when it has one,
    /// so a caller who supplied an installer to start with gets the same
    /// step here — a live request that quietly used the default installer
    /// instead would produce a connection built differently from every one
    /// the proxy made before it, with nothing saying so.
    fn build_transport(
        &self,
        leg: Leg,
        profile: &TransportProfile,
    ) -> Result<Arc<quinn::TransportConfig>, ControlError> {
        let installer = match leg {
            Leg::Client => &self.legs.client_installer,
            Leg::Upstream => &self.legs.upstream_installer,
        };
        match installer {
            Some(installer) => installer.build(profile),
            None => DefaultInstaller.build(profile),
        }
        .map(Arc::new)
        .map_err(ControlError::Profile)
    }

    /// Which slot of the per-leg arrays `leg` owns.
    #[cfg(feature = "impair")]
    fn leg_index(leg: Leg) -> usize {
        match leg {
            Leg::Client => 0,
            Leg::Upstream => 1,
        }
    }

    /// The impairment handle for `leg`, or `None` when this proxy was never
    /// given one.
    #[cfg(feature = "impair")]
    fn impair_handle(&self, leg: Leg) -> Option<quinn_netem::ImpairHandle> {
        self.impair.lock().expect("control plane")[Self::leg_index(leg)].clone()
    }

    /// Record the handle that arms `leg`'s socket.
    #[cfg(feature = "impair")]
    pub(crate) fn set_impair_handle(&self, leg: Leg, handle: quinn_netem::ImpairHandle) {
        self.impair.lock().expect("control plane")[Self::leg_index(leg)] = Some(handle);
    }

    /// What a leg with no impairment handle is told, and how to fix it.
    ///
    /// Carried in `Unsupported::transport` because that is the only field
    /// left to say it in and a caller who cannot act on the refusal is worse
    /// off than one who was never given the verb.
    #[cfg(feature = "impair")]
    const NO_SOCKET: &'static str = "a socket this proxy did not wrap — hand that leg's socket \
                                     and the ImpairHandle it was wrapped with to \
                                     TransparentProxy::set_impaired_socket before run()";
}

/// The client-facing leg's two mutable facts, under one lock.
struct ClientLeg {
    /// The listener, from the moment `run()` binds it until `run()` returns.
    listener: Option<Arc<Listener>>,
    /// The transport parameters a live request installed, kept so that a
    /// request that arrives before the bind is not lost.
    transport: Option<Arc<quinn::TransportConfig>>,
}

/// What the control plane knows about the two legs from the configuration
/// the proxy was built with, and cannot learn any other way.
///
/// Copied out of the proxy's templates when the plane is built rather than
/// read back from them on demand, because a handle is reachable from tasks
/// that do not hold the proxy.
#[derive(Default)]
pub(crate) struct LegSetup {
    /// How a client-leg [`TransportProfile`] becomes the config the listener
    /// installs.
    pub(crate) client_installer: Option<Arc<dyn TransportInstaller>>,
    /// The same for the relay leg.
    pub(crate) upstream_installer: Option<Arc<dyn TransportInstaller>>,
    /// Whether the relay leg is a WebTransport upstream, which cannot take
    /// transport parameters at all.
    pub(crate) upstream_webtransport: bool,
}

/// This proxy's shaping profile, and whether it paces.
///
/// One per proxy, watched by every session it accepts. The generation is
/// what lets a session notice a change without comparing profiles: a session
/// caches the generation its scheduler was built at, and a mismatch is the
/// signal to look.
pub(crate) struct ShapeControl {
    /// The profile a live request installed, or `None` while the proxy's own
    /// template is what every session shapes with.
    profile: Mutex<Option<ShapeProfile>>,
    /// Bumped, under the lock above, every time the profile is replaced.
    generation: AtomicU64,
    /// Whether the schedulers built from this pace at all. Behind its own
    /// `Arc` because every scheduler holds a clone of it.
    enabled: Arc<AtomicBool>,
}

impl ShapeControl {
    /// A control with no profile of its own and pacing switched on, which is
    /// the state that leaves a proxy behaving exactly as its configuration
    /// says.
    fn new() -> Self {
        Self {
            profile: Mutex::new(None),
            generation: AtomicU64::new(0),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Replace the profile and move the generation on.
    fn set(&self, profile: ShapeProfile) {
        let mut held = self.profile.lock().expect("shape control");
        *held = Some(profile);
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// The current generation, without cloning a profile.
    ///
    /// What a session checks per stream; the clone below is paid only when
    /// this has moved.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The generation and the profile it names, read together.
    ///
    /// Read under the lock the setter writes under, so the pair cannot
    /// straddle two calls to [`Self::set`] — a session that cached a
    /// generation from one profile and a profile from another would stop
    /// noticing the newer of the two.
    pub(crate) fn snapshot(&self) -> (u64, Option<ShapeProfile>) {
        let held = self.profile.lock().expect("shape control");
        (self.generation.load(Ordering::Acquire), held.clone())
    }

    /// The switch every scheduler built from this reads.
    pub(crate) fn switch(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.enabled)
    }

    /// Turn pacing on or off for every session at once.
    fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Release);
    }
}

impl ControlPlane {
    /// Register `id` as live, and hand back the guard that ends it.
    ///
    /// See this module's own documentation for why the removal is a `Drop`
    /// and not a call on each of the session's termination paths.
    pub(crate) fn register(self: &Arc<Self>, id: SessionId, handle: SessionHandle) -> SessionGuard {
        self.sessions.lock().expect("control plane").insert(id, handle);
        self.high_water.fetch_max(id.0, Ordering::AcqRel);
        SessionGuard { plane: Arc::clone(self), id }
    }

    /// Retire `id`. Idempotent.
    fn end(&self, id: SessionId) {
        self.sessions.lock().expect("control plane").remove(&id);
    }

    /// Every live id, ascending.
    fn live(&self) -> Vec<SessionId> {
        let mut ids: Vec<SessionId> =
            self.sessions.lock().expect("control plane").keys().copied().collect();
        ids.sort_by_key(|id| id.0);
        ids
    }

    /// The handle for one live session, or `None` when it is not registered.
    ///
    /// The only correct way to read the map: a caller that held the lock
    /// itself could still be holding it while it talked to the session.
    fn session(&self, id: SessionId) -> Option<SessionHandle> {
        self.sessions.lock().expect("control plane").get(&id).cloned()
    }

    /// The handle to act on `id` through, or the refusal that says why
    /// there is none.
    /// Three answers, and the third is the one worth stating: a session that is
    /// registered but whose cancellation token has already fired is refused as
    /// ended rather than acted on. It is going down and its tasks are
    /// unwinding, so a request accepted there would be taken and then never
    /// served — which is exactly the *accepts a request and discards it*
    /// outcome this module refuses to have.
    fn reach(&self, id: SessionId) -> Result<SessionHandle, ControlError> {
        match self.session(id) {
            Some(handle) if !handle.cancel.is_cancelled() => Ok(handle),
            Some(_) => Err(ControlError::SessionEnded(id)),
            // `id.0 != 0` because the proxy's counter starts at 1, so
            // `SessionId(0)` names nothing however many sessions have run;
            // without it a proxy that has never registered anything would
            // report that id as ended.
            None if id.0 != 0 && id.0 <= self.high_water.load(Ordering::Acquire) => {
                Err(ControlError::SessionEnded(id))
            }
            None => Err(ControlError::NoSuchSession(id)),
        }
    }
}

/// The published bound listener's registration. Un-publishes on drop.
pub(crate) struct BoundGuard {
    plane: Arc<ControlPlane>,
}

impl Drop for BoundGuard {
    fn drop(&mut self) {
        self.plane.unbind();
    }
}

/// One live session's registration. Ends it on drop.
///
/// Held in the frame of the function that runs the session, so the
/// registration lasts exactly as long as the session does — including when
/// that function returns early, and including when its future is dropped
/// wholesale rather than run to completion.
pub(crate) struct SessionGuard {
    plane: Arc<ControlPlane>,
    id: SessionId,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.plane.end(self.id);
    }
}

/// What the control plane keeps for one live session.
///
/// Everything here is either a handle onto shared state the session set up
/// before it began forwarding, or a way to reach a task it spawned. Nothing
/// here is a `Transport`: the two connections are owned by the forwarding
/// scope, and putting them in a table scanned by every list call would keep
/// them alive past the session that owns them.
///
/// The entry can therefore be built at the *top* of the session's run
/// function, before the upstream relay has even been dialled — which is
/// what makes a session reachable during the one operation that can take
/// seconds.
///
/// `Clone` because a request takes a copy out from under the registry lock
/// before it does anything with it; holding that lock while talking to a
/// session would let one unresponsive session block every other request.
#[derive(Debug, Clone)]
pub(crate) struct SessionHandle {
    /// The session's own token — a child of the proxy's, so cancelling it
    /// ends this session and leaves the proxy accepting. Read, not
    /// cancelled, by this module: a session that is already going down is
    /// refused rather than asked to do more.
    cancel: CancellationToken,
    /// Where the close code and reason are fixed, and where the session's
    /// own teardown reads them back out.
    closer: SessionCloser,
    /// Every stream this session is forwarding, and each one's inbox.
    streams: Arc<StreamRegistry>,
    /// The two control-stream directions' inboxes, indexed by the leg whose
    /// peer decodes what is written there. See [`Self::control_inbox`].
    control: [mpsc::Sender<StreamCommand>; 2],
    /// The session's egress knobs, for the drain window a close is given.
    egress: EgressConfig,
    /// Where a request for the session as a whole is delivered.
    commands: mpsc::Sender<SessionCommand>,
}

impl SessionHandle {
    /// The control-stream inbox whose writes `leg`'s peer decodes.
    ///
    /// The mapping is a half-turn and is worth stating once: the pipe that
    /// forwards *from* the client writes *to* the relay, so a message meant
    /// for the relay's decoder — [`Leg::Upstream`] — goes to the
    /// client-to-proxy direction's inbox, and a message for the client goes
    /// to the relay-to-proxy direction's.
    fn control_inbox(&self, leg: Leg) -> &mpsc::Sender<StreamCommand> {
        match leg {
            Leg::Client => &self.control[0],
            Leg::Upstream => &self.control[1],
        }
    }

    /// Hand `command` to this session's command task.
    fn request(&self, id: SessionId, command: SessionCommand) -> Result<(), ControlError> {
        // Both failures are the same answer: the request was not taken.
        // `Closed` is a session whose task has stopped, `Full` is one that
        // has sixteen outstanding and has served none — see
        // `ControlError::SessionEnded`, which says why there is no third.
        self.commands.try_send(command).map_err(|_| ControlError::SessionEnded(id))
    }
}

/// A request delivered to one session's command task.
///
/// Crate-internal and not a mirror of the public surface: the two
/// stream-level verbs resolve in the caller and never appear here, and the
/// one that does reach a session arrives already validated, so the session
/// task never has to decide whether a request was well-formed.
pub(crate) enum SessionCommand {
    /// Give this session's egress queues `drain` to flush, then end it.
    ///
    /// Carries no close code, because the code and reason were recorded
    /// into the session's closer before this was sent and are read back
    /// from there at teardown. Carrying them here as well would be a second
    /// source for one fact, and the two could disagree if the session were
    /// torn down by its peer between the two steps — which is precisely the
    /// case the recording is done first to get right.
    Close {
        /// How long the queues get before whatever is left is abandoned.
        drain: Duration,
    },
}

/// A request delivered to the task that owns one forwarded stream.
///
/// A channel rather than a shared handle because both operations here need
/// `&mut SendStream`, and the stream is moved by value into its forwarding
/// task on every path this proxy takes. See
/// [`StreamEntry`] for the rest of that
/// argument.
#[derive(Debug)]
pub(crate) enum StreamCommand {
    /// Abandon this stream: reset the destination with `code` and stop the
    /// source with the same code.
    Reset {
        /// The application error code both peers are given.
        code: u64,
    },
    /// Write these bytes onto this stream at the next point the receiving
    /// decoder accepts one.
    ///
    /// Only the two control directions ever receive this. A data stream's
    /// task has no notion of a message boundary — it forwards chunks — so
    /// it could not honour the "in sequence" half of the request, and
    /// nothing routes one to it.
    Inject {
        /// A complete, framed control message, written verbatim.
        bytes: Bytes,
    },
}

/// The two ends of one control-stream direction's request channel.
///
/// Created in the session's run function, before the control stream exists,
/// so that the sending half can go into the control-plane registry at the
/// same moment as the rest of the session's entry. An injection that
/// arrives before the control stream has been established waits in this
/// channel rather than being refused — the session is live, and there will
/// be a stream.
pub(crate) struct ControlLeg {
    /// Where a request for this direction is delivered.
    pub(crate) inbox: mpsc::Sender<StreamCommand>,
    /// What the direction's pipe serves.
    pub(crate) requests: mpsc::Receiver<StreamCommand>,
}

impl ControlLeg {
    /// A fresh channel for one control-stream direction.
    pub(crate) fn new() -> Self {
        let (inbox, requests) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        Self { inbox, requests }
    }
}

/// A session's attachment to its proxy's control plane.
///
/// Built when the proxy constructs the session, which is before the session
/// runs and long before it has anything worth reaching. It holds the
/// channel's two halves apart until then: the sending half goes into the
/// registry when the session registers, and the receiving half is taken out
/// once, by the session itself, when it has the context to serve it.
///
/// A session built directly, rather than by a proxy's accept loop, has no
/// attachment at all — it belongs to no proxy, so there is no plane for it
/// to register with.
pub(crate) struct ControlAttachment {
    plane: Arc<ControlPlane>,
    commands: mpsc::Sender<SessionCommand>,
    inbox: Mutex<Option<mpsc::Receiver<SessionCommand>>>,
}

impl ControlAttachment {
    /// Attach a session to `plane`, minting its command channel.
    pub(crate) fn new(plane: Arc<ControlPlane>) -> Self {
        let (commands, inbox) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        Self { plane, commands, inbox: Mutex::new(Some(inbox)) }
    }

    /// Register this session as live under `id`, reachable through
    /// everything a request might have to touch.
    ///
    /// The returned guard is the registration; drop it and the id is gone.
    ///
    /// Every argument is state the session builds before it dials the
    /// upstream relay, which is why this can be called at the top of the
    /// run function: a session spends its longest single operation
    /// connecting, and one that only became reachable afterwards would be
    /// unreachable for exactly as long as that took.
    pub(crate) fn register(
        &self,
        id: SessionId,
        cancel: CancellationToken,
        closer: SessionCloser,
        streams: Arc<StreamRegistry>,
        control: [mpsc::Sender<StreamCommand>; 2],
        egress: EgressConfig,
    ) -> SessionGuard {
        self.plane.register(
            id,
            SessionHandle {
                cancel,
                closer,
                streams,
                control,
                egress,
                commands: self.commands.clone(),
            },
        )
    }

    /// The plane this session is attached to.
    ///
    /// Handed out so that the session can build a shaper that watches the
    /// proxy's profile. Nothing else the session does needs the plane: the
    /// registration goes through [`Self::register`] and the command channel
    /// through [`Self::take_inbox`], both of which hand back exactly what
    /// they cover.
    pub(crate) fn plane(&self) -> Arc<ControlPlane> {
        Arc::clone(&self.plane)
    }

    /// Take the receiving half of the command channel.
    ///
    /// Answers `Some` exactly once per session. A second caller gets `None`
    /// rather than a second receiver, because two tasks draining one inbox
    /// would each see half the requests and neither would know it.
    pub(crate) fn take_inbox(&self) -> Option<mpsc::Receiver<SessionCommand>> {
        self.inbox.lock().expect("control attachment").take()
    }
}

/// A spawned task that is aborted when this value is dropped.
///
/// Used for a session's command task, which has no natural end of its own:
/// it waits on a channel and on a cancellation token, and if the session's
/// future is dropped without either firing — which is what happens when
/// whoever spawned the session aborts it — the task would otherwise outlive
/// the session that owns it, holding the session's context alive with it.
pub(crate) struct AbortOnDrop {
    task: JoinHandle<()>,
}

impl AbortOnDrop {
    /// Take ownership of `task`.
    pub(crate) fn new(task: JoinHandle<()>) -> Self {
        Self { task }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── The live-stream registry ────────────────────────────────────────────
//
// A stream's entry is what a request naming it is routed through, so this
// lives beside `StreamCommand` rather than beside the shaping profile it was
// first written next to. The move is what keeps `shape` from naming anything
// in this module.

/// Every forwarded stream that is still live, and the [`Gate`] each one
/// releases when it ends.
///
/// This is what
/// [`StreamAction::SerializeAfter`](crate::action::StreamAction::SerializeAfter)
/// waits on. It is **always constructed**, independently of whether the
/// session has a [`ShapeProfile`]: `SerializeAfter` is gated by
/// `Interest::STREAMS`, and the capability table publishes it as an
/// unconditional `Yes` at both stream sites, so a registry that only existed
/// when a profile was configured would make that published cell a lie. Empty,
/// it is one `HashMap` header behind an `Arc` and allocates nothing until a
/// stream registers.
///
/// Engine-internal despite living in a `pub` module: a scenario author names
/// a [`StreamKey`], never a registry.
///
/// # Why a lookup miss is not an error
///
/// [`Self::gate_for`] answers `None` for a key that never existed **and** for
/// one whose stream has already ended, because an entry is removed as it is
/// released. Both mean the same thing to a waiter — there is nothing left to
/// wait for — and the two are deliberately not distinguished: a serialize
/// that resolves immediately is correct in both cases, and the caller reports
/// `SerializeTargetUnknown` once so the run says which streams did it.
#[derive(Debug)]
pub(crate) struct StreamRegistry {
    live: Mutex<HashMap<StreamKey, StreamEntry>>,
}

/// What the registry keeps for one live stream.
///
/// Two things, and they are here for two different callers. The [`Gate`] is
/// what a `SerializeAfter` waits on and has always been the whole of an
/// entry. The inbox is how a request that arrives from *outside* the
/// session reaches the task that owns the stream's write half.
///
/// The inbox is a channel rather than a shared handle because
/// `SendStream::write_all` and `SendStream::reset` both take `&mut self`
/// and the stream is moved by value into its forwarding task on every
/// path. Sharing it would mean a lock, and that lock would be held across
/// `write_all().await` — on the byte-pump fast path, for as long as the
/// destination's flow control took. Handing the task a message instead
/// costs one `select!` branch and keeps the write where it already is.
#[derive(Debug, Clone)]
pub(crate) struct StreamEntry {
    /// Released when the stream ends.
    gate: Gate,
    /// Where a request aimed at this stream is delivered.
    inbox: tokio::sync::mpsc::Sender<StreamCommand>,
}

impl StreamRegistry {
    /// An empty registry.
    pub(crate) fn new() -> Self {
        Self { live: Mutex::new(HashMap::new()) }
    }

    /// Register `key` as live, and hand back the guard that ends it.
    ///
    /// The guard is the whole release mechanism, and it is a guard rather
    /// than a call at each teardown site on purpose. The gate has to be
    /// released on **every** termination path without exception — FIN,
    /// mirrored reset, synthesized reset, `STOP_SENDING`, cancellation — and
    /// a missed release is not a loud failure but a `max_hold` stall on some
    /// *other* stream. An enumerated list is only as complete as the reader;
    /// `Drop` is complete by construction, and it additionally covers the
    /// paths no enumeration would have listed: a `?` return, a panicking
    /// forwarding task, and the task future being dropped wholesale by
    /// `JoinSet::shutdown` at session teardown.
    /// `inbox` is where a request naming this key is delivered; it is the
    /// sending half of a channel whose receiving half the forwarding task
    /// holds, so the entry going away and the task stopping are one event.
    pub(crate) fn register(
        self: &Arc<Self>,
        key: StreamKey,
        inbox: tokio::sync::mpsc::Sender<StreamCommand>,
    ) -> StreamGuard {
        self.live
            .lock()
            .expect("stream registry")
            .insert(key, StreamEntry { gate: Gate::new(), inbox });
        StreamGuard { registry: Arc::clone(self), key }
    }

    /// The gate to wait on for `target`, or `None` when there is nothing to
    /// wait for — see the type's own doc for why those are one answer.
    pub(crate) fn gate_for(&self, target: StreamKey) -> Option<Gate> {
        self.live.lock().expect("stream registry").get(&target).map(|e| e.gate.clone())
    }

    /// Where to deliver a request aimed at `target`, or `None` when no such
    /// stream is live.
    ///
    /// The same "never existed" / "already ended" conflation
    /// [`Self::gate_for`] makes, and for the same reason: the entry is
    /// removed as the stream ends, so nothing is left to tell the two
    /// apart. A caller reports both as "no such stream", which is what a
    /// request aimed at either can act on.
    pub(crate) fn inbox_for(
        &self,
        target: StreamKey,
    ) -> Option<tokio::sync::mpsc::Sender<StreamCommand>> {
        self.live.lock().expect("stream registry").get(&target).map(|e| e.inbox.clone())
    }

    /// Retire `key`: remove it and release its gate.
    ///
    /// Idempotent, and the removal is what makes a later `gate_for` on the
    /// same key answer `None` rather than handing out an already-released
    /// gate that would look live.
    fn end(&self, key: StreamKey) {
        let entry = self.live.lock().expect("stream registry").remove(&key);
        if let Some(entry) = entry {
            entry.gate.release();
        }
    }

    /// How many streams are live. Tests only.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.live.lock().expect("stream registry").len()
    }
}

/// One live stream's registration. Ends it on drop.
///
/// Held by the forwarding task for exactly as long as the stream is
/// forwarding; see [`StreamRegistry::register`] for why the release is a
/// `Drop` rather than a call on each teardown path.
pub(crate) struct StreamGuard {
    registry: Arc<StreamRegistry>,
    key: StreamKey,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.registry.end(self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProxySide;

    fn handle() -> SessionHandle {
        let (commands, _inbox) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let cancel = CancellationToken::new();
        SessionHandle {
            closer: SessionCloser::new(cancel.clone()),
            cancel,
            streams: Arc::new(StreamRegistry::new()),
            control: [ControlLeg::new().inbox, ControlLeg::new().inbox],
            egress: EgressConfig::default(),
            commands,
        }
    }

    /// A registration lasts exactly as long as its guard.
    ///
    /// The whole reliability claim of `sessions()` rests on this: no
    /// termination path in `session.rs` calls a removal, so if the guard's
    /// `Drop` did not remove the entry, nothing would, and the list would
    /// grow monotonically for the life of the proxy.
    #[test]
    fn a_dropped_guard_takes_its_id_out_of_the_list() {
        let plane = ControlPlane::new(LegSetup::default());
        assert!(plane.live().is_empty());

        let first = plane.register(SessionId(1), handle());
        let second = plane.register(SessionId(2), handle());
        assert_eq!(plane.live(), vec![SessionId(1), SessionId(2)]);

        drop(first);
        assert_eq!(
            plane.live(),
            vec![SessionId(2)],
            "the id that ended goes, and the one still running stays"
        );

        drop(second);
        assert!(plane.live().is_empty());
    }

    /// The list comes back ascending however the ids went in.
    #[test]
    fn the_list_is_sorted_by_id() {
        let plane = ControlPlane::new(LegSetup::default());
        let _c = plane.register(SessionId(3), handle());
        let _a = plane.register(SessionId(1), handle());
        let _b = plane.register(SessionId(2), handle());

        assert_eq!(plane.live(), vec![SessionId(1), SessionId(2), SessionId(3)]);
    }

    /// The inbox is handed out once, so two tasks cannot split one session's
    /// requests between them.
    #[test]
    fn the_command_inbox_can_only_be_taken_once() {
        let attachment = ControlAttachment::new(ControlPlane::new(LegSetup::default()));
        assert!(attachment.take_inbox().is_some());
        assert!(attachment.take_inbox().is_none());
    }

    /// The three answers a request naming a session can get before it
    /// reaches anything, and the fact that separates the first two.
    /// A caller holding a list needs "your list was stale" and *that id was
    /// never mine* to be different answers, and once a session ends nothing is
    /// left of it but its id — so the split rests entirely on the high-water
    /// mark. Without it every ended session would be reported as one that never
    /// existed, and a control plane driven from a timeline could not tell a
    /// session that finished early from a typo.
    ///
    /// *Ablation, recorded:* delete the `high_water` arm from
    /// `ControlPlane::reach`, leaving a lookup miss to answer
    /// `NoSuchSession`. This test goes red with
    ///
    /// ```text
    /// assertion `left == right` failed: a session this proxy ran and has
    /// finished is a race, not a mistake
    ///   left: NoSuchSession(SessionId(2))
    ///  right: SessionEnded(SessionId(2))
    /// ```
    #[test]
    fn an_ended_session_and_an_id_that_never_ran_are_different_answers() {
        let plane = ControlPlane::new(LegSetup::default());

        assert_eq!(
            plane.reach(SessionId(2)).err(),
            Some(ControlError::NoSuchSession(SessionId(2))),
            "nothing has ever run here"
        );

        let registration = plane.register(SessionId(2), handle());
        assert!(plane.reach(SessionId(2)).is_ok(), "a running session is reachable");

        drop(registration);
        assert_eq!(
            plane.reach(SessionId(2)).err(),
            Some(ControlError::SessionEnded(SessionId(2))),
            "a session this proxy ran and has finished is a race, not a mistake"
        );
        assert_eq!(
            plane.reach(SessionId(3)).err(),
            Some(ControlError::NoSuchSession(SessionId(3))),
            "an id above everything this proxy has minted was never its own"
        );
    }

    /// A session whose token has fired is refused rather than acted on.
    ///
    /// Its registration is still in the map — the guard lives in the
    /// session's own frame and that frame is unwinding — so a lookup finds
    /// it. Its tasks are on their way out, though, so a request accepted
    /// there would be taken and never served, which is the one outcome this
    /// module refuses to have.
    #[test]
    fn a_session_that_is_already_going_down_takes_no_more_requests() {
        let plane = ControlPlane::new(LegSetup::default());
        let entry = handle();
        let cancel = entry.cancel.clone();
        let _registration = plane.register(SessionId(1), entry);

        assert!(plane.reach(SessionId(1)).is_ok());
        cancel.cancel();
        assert_eq!(
            plane.reach(SessionId(1)).err(),
            Some(ControlError::SessionEnded(SessionId(1))),
            "still listed, no longer serving"
        );
        assert_eq!(plane.live(), vec![SessionId(1)], "and it is still listed, which is why");
    }

    /// A stream key that names nothing live is refused, and the refusal
    /// names both the session and the key so a caller with several sessions
    /// can tell which lookup missed.
    #[test]
    fn resetting_a_stream_that_is_not_live_is_refused_by_key() {
        let plane = ControlPlane::new(LegSetup::default());
        let _registration = plane.register(SessionId(1), handle());
        let control = ProxyControl::new(Arc::clone(&plane));

        let stream = StreamKey { side: crate::types::ProxySide::ClientToProxy, id: 4 };
        assert_eq!(
            control.reset_stream(SessionId(1), stream, 9),
            Err(ControlError::NoSuchStream { id: SessionId(1), stream }),
            "the session is live and the stream is not"
        );
    }

    fn key(id: u64) -> StreamKey {
        StreamKey { side: ProxySide::ClientToProxy, id }
    }

    /// The sending half of a channel whose receiver is dropped at once.
    ///
    /// These tests are about the gate and the entry's lifetime, not about
    /// delivery: a sender with no receiver still registers, still clones
    /// and still goes away with its entry, which is all the registry
    /// promises. A test that needed a request delivered would have to run a
    /// stream, and that lives in `session.rs`.
    fn inbox() -> tokio::sync::mpsc::Sender<StreamCommand> {
        tokio::sync::mpsc::channel(1).0
    }

    /// A registered stream is waitable; ending it releases the gate a waiter
    /// already took, and the entry goes away so the *next* asker is told
    /// there is nothing to wait for.
    ///
    /// *Ablation:* drop the `gate.release()` from `StreamRegistry::end` —
    /// the `is_released` assertion goes red, which is the `max_hold` stall
    /// this whole mechanism exists to avoid.
    #[test]
    fn ending_a_stream_releases_the_gate_a_waiter_already_took() {
        let registry = Arc::new(StreamRegistry::new());
        let guard = registry.register(key(1), inbox());

        let held = registry.gate_for(key(1)).expect("a live stream is waitable");
        assert!(!held.is_released(), "a live stream's gate is not released");
        assert_eq!(registry.len(), 1);

        drop(guard);

        assert!(held.is_released(), "ending the stream releases the gate a waiter already holds");
        assert!(registry.gate_for(key(1)).is_none(), "an ended stream is no longer waitable");
        assert_eq!(registry.len(), 0, "the entry is removed, not left released");
    }

    /// A key that was never registered and a key whose stream has already
    /// ended are the same answer, which is what lets the caller report
    /// `SerializeTargetUnknown` once for both.
    #[test]
    fn an_unknown_and_an_ended_key_are_the_same_answer() {
        let registry = Arc::new(StreamRegistry::new());
        assert!(registry.gate_for(key(7)).is_none(), "never registered");

        drop(registry.register(key(7), inbox()));
        assert!(registry.gate_for(key(7)).is_none(), "registered, then ended");
    }

    /// Two sides may mint the same numeric id, and the registry must keep
    /// them apart — the runtime half of
    /// `a_stream_key_is_scoped_by_side_as_well_as_id`.
    #[test]
    fn the_registry_scopes_entries_by_side() {
        let registry = Arc::new(StreamRegistry::new());
        let client = StreamKey { side: ProxySide::ClientToProxy, id: 3 };
        let relay = StreamKey { side: ProxySide::RelayToProxy, id: 3 };

        let _client_guard = registry.register(client, inbox());
        let relay_guard = registry.register(relay, inbox());
        assert_eq!(registry.len(), 2);

        drop(relay_guard);
        assert!(registry.gate_for(client).is_some(), "the client-side stream is still live");
        assert!(registry.gate_for(relay).is_none());
    }
}

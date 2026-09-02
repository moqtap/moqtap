//! Per-connection proxy session — forwards streams between client and relay.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use moqtap_client::transport::quic::QuicTransport;
use moqtap_client::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use crate::action::{Action, EgressConfig, Interest, StreamEnd};
use crate::capability::{fetch_group_order_is_needed, ActionKind, Capabilities, Site};
use crate::control::{
    AbortOnDrop, ControlAttachment, ControlLeg, ControlPlane, SessionCommand, StreamCommand,
    StreamRegistry, COMMAND_QUEUE_DEPTH,
};
use crate::egress::{self, CloseOrigin, DrainOutcome, EgressGauge, PendingQueue, SessionCloser};
use crate::error::ProxyError;
use crate::event::{
    DataStreamHeaderKind, Effect, ImpairmentKind, ProxyEvent, SessionId, ShapeOutcome,
};
use crate::exec::{self, DeferredEffects, Plan, StreamSite};
use crate::framer::{FetchGroupOrders, FramerConfig, FramerOut, ObjectFramer};
use crate::hook::{FrameCtx, ObjectCtx, ProxyHook, StreamCtx};
use crate::instrument::{Counters, Recorder};
use crate::observer::ProxyObserver;
use crate::parser::control::{ControlStreamParser, ParseResult, ParsedItem};
use crate::shape::{
    Acquire, Admission, Class, Scheduler, ShapeProfile, ShapeRecorder, ShapeStats, StreamKey,
};
use crate::transport::{self, TransportInstaller, TransportProfile};
use crate::types::{DataStreamType, Leg, ProxySide};

/// The transport type for upstream relay connections.
#[derive(Debug, Clone)]
pub enum UpstreamTransportType {
    /// Raw QUIC — `upstream_addr` is `host:port`.
    Quic,
    /// WebTransport — `url` is the full WebTransport URL.
    WebTransport {
        /// The WebTransport endpoint URL (e.g., `https://host:port/path`).
        url: String,
    },
}

/// Configuration for a proxy session's upstream connection.
pub struct ProxySessionConfig {
    /// The MoQT draft version to use for parsing.
    pub draft: DraftVersion,
    /// The transport type to use for the upstream connection.
    pub upstream_transport: UpstreamTransportType,
    /// Upstream relay address (e.g., `"192.168.1.10:4443"` for QUIC).
    pub upstream_addr: String,
    /// Whether to skip TLS verification for the upstream connection.
    pub skip_upstream_cert_verify: bool,
    /// Custom CA certificates for the upstream connection (DER-encoded).
    pub upstream_ca_certs: Vec<Vec<u8>>,
    /// Timeout in seconds for the upstream connection attempt. 0 means no timeout.
    pub upstream_connect_timeout_secs: u64,
    /// Optional QUIC transport parameters — flow-control windows, MTU,
    /// keep-alive, congestion control — applied to the upstream relay
    /// connection.
    ///
    /// `None` leaves quinn's defaults in place. Ignored for WebTransport
    /// upstreams, which build their endpoint through `wtransport`.
    ///
    /// Setting this **and** `upstream_transport_profile` is refused when
    /// the session connects, with [`ProxyError::TransportConfigAndProfile`]
    /// naming [`Leg::Upstream`] — see that variant for why the two cannot
    /// be merged. The refusal stands on a WebTransport upstream too, where
    /// both fields would have been ignored: a contradiction reported on one
    /// transport and swallowed on the other is worse than either answer.
    pub upstream_transport_config: Option<Arc<quinn::TransportConfig>>,
    /// The same parameters as `upstream_transport_config`, as a value that
    /// can be written down, checked and stored.
    ///
    /// `Some(_)` builds the relay leg's `quinn::TransportConfig` from this
    /// profile — through `upstream_installer`, or through
    /// [`crate::transport::DefaultInstaller`] when there is none — and
    /// installs it before the endpoint is built and before anything is
    /// dialled. A profile the installer refuses is
    /// [`ProxyError::TransportProfile`], and no connection is attempted.
    ///
    /// `None` is the behaviour callers had before this field existed. It is
    /// the *only* alternative to `upstream_transport_config`, never a
    /// companion to it.
    pub upstream_transport_profile: Option<TransportProfile>,
    /// How `upstream_transport_profile` becomes the config the relay leg
    /// installs.
    ///
    /// `None` uses [`crate::transport::DefaultInstaller`], which applies
    /// the profile over a fresh `quinn::TransportConfig::default()`. Supply
    /// one to start from a base of your own instead — the trait exists
    /// because a `quinn::TransportConfig` cannot be cloned, so the only way
    /// to have a base *and* a profile is to build the base again for each
    /// leg.
    ///
    /// **Inert without a profile.** [`TransportInstaller::build`] takes a
    /// profile, so an installer set beside an empty
    /// `upstream_transport_profile` is never called and the leg installs
    /// nothing.
    ///
    /// **It composes with an `upstream_qlog` spec** — named in plain code
    /// font because that field exists only under the `qlog` feature, so a
    /// link from this always-compiled one would not resolve. A leg carrying
    /// a profile, a spec and an installer builds its config here, once, and
    /// the capture sink is attached to what came back;
    /// [`TransportInstaller::build`] returns an owned
    /// `quinn::TransportConfig` precisely so that the two can stack.
    pub upstream_installer: Option<Arc<dyn TransportInstaller>>,
    /// Where this leg's QUIC-level capture is written, if it is captured at
    /// all.
    ///
    /// `Some(_)` builds the relay leg's `quinn::TransportConfig`, installs
    /// the sink built from this spec on it, and dials with it — all before
    /// the endpoint is built, because quinn accepts a sink in exactly one
    /// place and that place is a method which mutates a
    /// `quinn::TransportConfig`. It composes with
    /// `upstream_transport_profile`, which is applied to the same config
    /// first, and **not** with `upstream_transport_config`: a leg naming a
    /// raw config and a spec is refused when the session connects, with
    /// [`ProxyError::TransportConfigAndQlog`] naming [`Leg::Upstream`], for
    /// the reason written out on that variant.
    ///
    /// A spec on its own, with neither of the other two fields set, is
    /// enough: the leg builds a `quinn::TransportConfig::default()` for the
    /// sink to go on and dials with it, rather than dialling with nothing
    /// and leaving the capture attached to a config no connection uses.
    ///
    /// `None` is how a leg says it does not want a capture. A spec that
    /// names no writer is not that — it is refused with
    /// [`ProxyError::Qlog`], because a spec
    /// is how a caller *asks* for a capture.
    ///
    /// # Taken by the first connection this session dials
    ///
    /// A [`QlogSpec`](crate::qlog::QlogSpec) owns its writer and is consumed
    /// when it becomes a sink, so it has no `Clone` and there is exactly one
    /// of it. [`ProxySession::new`] moves it out of this config and the
    /// session's dial takes it, which is the only shape in which a single
    /// writer belongs to a single connection.
    ///
    /// Two consequences worth stating rather than discovering. A
    /// [`TransparentProxy`](crate::proxy::TransparentProxy) rebuilds this
    /// config per accepted connection out of a shared template, so it cannot
    /// carry a spec at all — and rather than dropping the field and coming
    /// up, its `run` **refuses** a template that holds one, with
    /// [`ProxyError::QlogOnProxyTemplate`] naming [`Leg::Upstream`]. Capture
    /// a relay leg by driving [`ProxySession`] directly, one spec and one
    /// writer per session. And a WebTransport upstream ignores this exactly as it
    /// ignores `upstream_transport_config` — `wtransport` builds that
    /// endpoint — which for a capture means a file that exists, parses,
    /// names a qlog version and will never hold an event. There is no
    /// refusal for it, because the step that builds the sink is the step
    /// shared with the client leg, which has no upstream transport to
    /// dispatch on. Capture the client leg instead — that endpoint is
    /// always QUIC, even for a WebTransport client.
    ///
    /// [`ProxyError::TransportConfigAndQlog`]: crate::error::ProxyError::TransportConfigAndQlog
    /// [`ProxyError::QlogOnProxyTemplate`]: crate::error::ProxyError::QlogOnProxyTemplate
    #[cfg(feature = "qlog")]
    pub upstream_qlog: Option<crate::qlog::QlogSpec>,
    /// The socket every datagram of the **upstream** connection is sent
    /// on and received from.
    ///
    /// `None` binds an ephemeral `0.0.0.0:0` socket, which is what this
    /// session has always done. `Some(_)` builds the upstream endpoint
    /// over the caller's socket instead, so a decorating implementation —
    /// a tap, a counter, a network-impairment shim — sees and can alter
    /// the whole relay leg. Ownership is shared, so the caller keeps its
    /// handle on the socket while the session runs, and the relay sees the
    /// supplied socket's address as this proxy's.
    ///
    /// This is the relay leg only. The client-facing leg is a separate
    /// endpoint over a separate socket, supplied — or not — when the
    /// listener is built.
    ///
    /// # A WebTransport upstream cannot honour this
    ///
    /// `upstream_transport_config` above is *ignored* for WebTransport
    /// upstreams, because `wtransport` builds their endpoint. A socket is
    /// not: it is refused. Connecting with
    /// [`UpstreamTransportType::WebTransport`] and a socket set returns
    /// [`ProxyError::UpstreamSocketUnsupported`] and connects to nothing.
    ///
    /// The two are treated differently because the consequences of
    /// ignoring them are. A dropped transport config yields quinn's
    /// defaults — a connection that works, with windows the caller did not
    /// pick. A dropped socket yields a relay leg that bypasses the
    /// caller's shim entirely, so every impairment armed on it is reported
    /// by the shim and applied to nothing, and the run looks clean because
    /// it *is* clean. That failure is invisible from the outside, so it is
    /// made loud here instead.
    ///
    /// # One socket, one session
    ///
    /// Each session builds its own endpoint over the socket it is handed.
    /// Two endpoints reading one socket take each other's datagrams —
    /// whichever polls first gets a packet, and a packet for a connection
    /// an endpoint does not own is discarded — so a socket shared across
    /// sessions running concurrently breaks all of them. Give concurrent
    /// sessions one socket each.
    pub upstream_socket: Option<Arc<dyn quinn::AsyncUdpSocket>>,
    /// Engine-side knobs for action execution — the per-stream deferred
    /// write queue's byte budget and the ceiling on a hold.
    ///
    /// Ignored when the hook's [`crate::hook::ProxyHook::interest`] is
    /// [`Interest::NONE`]: nothing is ever queued, so nothing reads them.
    pub egress: EgressConfig,
    /// How this session's **media** egress is shaped — named token
    /// buckets, the class rules that aim at them, one bounded-queue policy
    /// and the discipline that arbitrates between classes.
    ///
    /// `None` is today's behaviour exactly: no scheduler is constructed,
    /// nothing extra is queued, and no deadline is armed.
    ///
    /// `Some(_)` is **configuration, not a hook capability**, and that is
    /// the whole point of the field: it arms framing on its own, with no
    /// hook and no observer. A profile that only took effect when someone
    /// also attached a hook would let a user configure 500 kbps, get a byte
    /// pump, and read a successful run — which is the failure mode this
    /// knob exists to make impossible. Conversely, attaching an observer
    /// never arms shaping: see `shaping_enabled` on `ForwardCtx`.
    ///
    /// Control streams are never shaped, on any path.
    pub shape: Option<ShapeProfile>,
}

impl ProxySessionConfig {
    /// Returns the ALPN protocol identifiers for the upstream connection.
    ///
    /// For QUIC upstreams, mirrors the negotiated client ALPN so we connect
    /// to the relay with the same protocol the client is speaking. Falls
    /// back to `self.draft.quic_alpn()` if the client ALPN is empty
    /// (e.g., the listener didn't capture it).
    pub fn upstream_alpn(&self, client_alpn: &[u8]) -> Vec<Vec<u8>> {
        match &self.upstream_transport {
            UpstreamTransportType::Quic => {
                if client_alpn.is_empty() {
                    vec![self.draft.quic_alpn().to_vec()]
                } else {
                    vec![client_alpn.to_vec()]
                }
            }
            UpstreamTransportType::WebTransport { .. } => vec![b"h3".to_vec()],
        }
    }
}

impl Default for ProxySessionConfig {
    fn default() -> Self {
        Self {
            draft: crate::capability::DEFAULT_DRAFT,
            upstream_transport: UpstreamTransportType::Quic,
            upstream_addr: String::new(),
            skip_upstream_cert_verify: false,
            upstream_ca_certs: Vec::new(),
            upstream_connect_timeout_secs: 0,
            upstream_transport_config: None,
            upstream_transport_profile: None,
            upstream_installer: None,
            #[cfg(feature = "qlog")]
            upstream_qlog: None,
            upstream_socket: None,
            egress: EgressConfig::default(),
            shape: None,
        }
    }
}

/// A proxy session that forwards traffic between a client and an upstream
/// relay. One session is created per accepted client connection.
pub struct ProxySession {
    session_id: SessionId,
    config: ProxySessionConfig,
    /// The ALPN the client negotiated with us (empty for WebTransport or
    /// when unavailable). Drives both upstream ALPN selection and initial
    /// draft detection for drafts 15+.
    client_alpn: Vec<u8>,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
    /// This session's slow-path counters, shared with every forwarding
    /// task. One per session, not per process: a test asserting that a
    /// session touched no slow path must not be spoiled by another session
    /// running beside it.
    counters: Arc<Recorder>,
    /// This session's shaping counters, shared with every forwarding task
    /// the same way `counters` is. A **sibling** of `Recorder`, not an
    /// extension of it: `Counters` is compared whole against
    /// `Counters::default()` by `tests/interest_none.rs` and by value
    /// elsewhere, and it would lose `Copy` for a `Vec` that is empty on
    /// every unshaped session.
    ///
    /// Always constructed, including when `config.shape` is `None`, for the
    /// same reason `StreamRegistry` is: a structure that only existed when a
    /// profile was configured would make the reports that name it
    /// conditional on configuration nobody reading them can see. Its rows
    /// are pre-sized from the profile's class list at this point and never
    /// resized, so moving a running session to a different class list means
    /// building a new session-scoped recorder rather than resizing this one.
    shape_stats: Arc<ShapeRecorder>,
    /// This session's attachment to its proxy's control plane, or `None`
    /// when it has no proxy.
    ///
    /// `None` is not a degraded mode. A session constructed directly — which
    /// is how this crate's own tests drive one, and how a caller that wants
    /// one socket per session reaches the seam — belongs to no
    /// [`TransparentProxy`](crate::proxy::TransparentProxy), so there is no
    /// plane for it to register with and no
    /// [`ProxyControl`](crate::control::ProxyControl) that could name it.
    /// Making it an `Option` rather than always constructing one is what
    /// keeps that honest: an unattached session cannot appear in a list of
    /// live sessions belonging to a proxy that never accepted it.
    control: Option<ControlAttachment>,
    /// This session's relay-leg capture, until the dial takes it.
    ///
    /// Moved out of [`ProxySessionConfig::upstream_qlog`] when the session
    /// is constructed, and out of here when it connects, because a spec owns
    /// its writer and is consumed the moment it becomes a sink. It lives
    /// beside the config rather than in it because the dial happens through
    /// `&self` — a session is driven from behind an `Arc` — and there is no
    /// way to take a value out of a shared reference.
    ///
    /// A `Mutex` and not a `OnceLock` or an atomic: the value is moved *out*
    /// exactly once and the type has to allow that. The lock is taken once
    /// per session, before the relay is dialled, and is never held across an
    /// await.
    ///
    /// So a session run a second time dials without a capture. That is the
    /// truthful answer rather than a limitation to work around — the writer
    /// belongs to the connection that took it, and a second connection
    /// writing into the same file would put both of their records behind one
    /// preamble with nothing marking where either begins.
    #[cfg(feature = "qlog")]
    upstream_qlog: Mutex<Option<crate::qlog::QlogSpec>>,
}

impl ProxySession {
    /// Create a new proxy session.
    ///
    /// `client_alpn` should be the ALPN the listener negotiated with the
    /// client. Pass an empty slice if unavailable (e.g., WebTransport).
    pub fn new(
        session_id: SessionId,
        #[cfg_attr(not(feature = "qlog"), allow(unused_mut))] mut config: ProxySessionConfig,
        client_alpn: Vec<u8>,
        observer: Arc<dyn ProxyObserver>,
        hook: Arc<dyn ProxyHook>,
        cancel: CancellationToken,
    ) -> Self {
        let shape_stats = Arc::new(ShapeRecorder::for_profile(config.shape.as_ref()));
        // Taken out of the config here, and out of the session when it
        // dials. The dial has only `&self` to work with, and a spec is a
        // value that has to be moved to be used at all.
        #[cfg(feature = "qlog")]
        let upstream_qlog = Mutex::new(config.upstream_qlog.take());
        Self {
            session_id,
            config,
            client_alpn,
            observer,
            hook,
            cancel,
            counters: Arc::new(Recorder::new()),
            shape_stats,
            control: None,
            #[cfg(feature = "qlog")]
            upstream_qlog,
        }
    }

    /// Attach this session to a proxy's control plane.
    ///
    /// Called by the accept loop between constructing the session and
    /// spawning it, which is the only window in which the session is still
    /// owned exclusively. It mints the command channel but registers
    /// nothing: registration happens when the session begins to run, so that
    /// the entry's lifetime is the session's and not this call's.
    ///
    /// It also **replaces** the shaping recorder, with one that forwards
    /// everything it is charged into the proxy's own counters as well. A
    /// second recorder installed beside the first would need a second set of
    /// call sites on the data path, and a figure added to one and forgotten
    /// at the other is a divergence nothing would report; forwarding from
    /// inside means one call charges both or neither.
    ///
    /// Replacing rather than mutating is what that window buys. Nothing has
    /// run, so the recorder being discarded is all zeros, and nothing has
    /// cloned it — `ForwardCtx` takes its `Arc` when the session starts
    /// forwarding, which is after this returns — so every task will hold the
    /// recorder that reports to the proxy, not a mixture.
    pub(crate) fn attach_control(&mut self, plane: Arc<ControlPlane>) {
        self.shape_stats =
            Arc::new(ShapeRecorder::attached(self.config.shape.as_ref(), plane.stats_recorder()));
        self.control = Some(ControlAttachment::new(plane));
    }

    /// This session's slow-path counters.
    ///
    /// Replaces the deleted process-global `instrument::snapshot()`. Cheap:
    /// a read of ~12 relaxed atomics plus a 128-slot histogram scan.
    ///
    /// A session whose hook declared [`Interest::NONE`] and whose observer
    /// answers `false` to `wants_events` ends with
    /// `counters() == Counters::default()` — that is what makes the
    /// fast-path claim falsifiable rather than promised.
    pub fn counters(&self) -> Counters {
        self.counters.snapshot()
    }

    /// This session's shaping statistics.
    ///
    /// Readable **while the session runs**, which is the point: the
    /// `ProxySession` is constructed behind an `Arc` before the accept task
    /// is spawned (`tests/common/mod.rs`), so a test can sample its
    /// classes without waiting for teardown and without a control plane.
    ///
    /// A session with no [`ShapeProfile`] ends — and begins, and stays — at
    /// `shape_stats() == ShapeStats::default()`. That is a falsifiable
    /// claim rather than a promise only because the shaping path does move
    /// these counters when it is entered: see
    /// [`ShapeStats::objects_seen`].
    ///
    /// Allocates one `Vec` and one `String` per configured class. Cheap,
    /// but not free — this is a reader's call, not a data-path one.
    pub fn shape_stats(&self) -> ShapeStats {
        self.shape_stats.snapshot()
    }

    /// Run the proxy session with a raw QUIC client connection.
    pub async fn run(&self, client_conn: quinn::Connection) -> Result<(), ProxyError> {
        let client = Transport::Quic(QuicTransport::new(client_conn));
        self.run_with_transport(client).await
    }

    /// Run the proxy session with a WebTransport client connection.
    #[cfg(feature = "webtransport")]
    pub async fn run_webtransport(
        &self,
        client_conn: wtransport::Connection,
    ) -> Result<(), ProxyError> {
        use moqtap_client::transport::webtransport::WebTransportTransport;
        let client = Transport::WebTransport(WebTransportTransport::new(client_conn));
        self.run_with_transport(client).await
    }

    /// The draft this session starts on. Drafts 15+ resolve unambiguously
    /// from the client ALPN (`moqt-15` through `moqt-19`); otherwise we fall
    /// back to `config.draft`, which the control stream refines once it
    /// peeks at CLIENT_SETUP / SERVER_SETUP for the moq-00 cohort (drafts
    /// 07–14).
    ///
    /// It is the *starting* draft and not the session's draft. That lives in
    /// [`SessionDraft`], which every forwarding task reads and the control
    /// stream writes.
    fn initial_draft(&self) -> DraftVersion {
        DraftVersion::from_alpn(&self.client_alpn).unwrap_or(self.config.draft)
    }

    /// Whether the starting draft is fixed (ALPN-derived) or is still open
    /// to being named by a CLIENT_SETUP / SERVER_SETUP peek.
    fn draft_is_fixed(&self) -> bool {
        DraftVersion::from_alpn(&self.client_alpn).is_some()
    }

    /// Run the proxy session with an already-wrapped transport.
    ///
    /// Connects to the upstream relay, then forwards all streams and
    /// datagrams bidirectionally between the client and relay. Parses
    /// MoQT frames inline and emits events via the observer.
    async fn run_with_transport(&self, client: Transport) -> Result<(), ProxyError> {
        // Registered before the relay is dialled, and released by this
        // function's scope rather than by a call at each of the several
        // places the session can end. The guard covers the `?` below on a
        // failed upstream connect, every return at the bottom, and this
        // whole future being dropped by whoever spawned it — the last of
        // which no enumerated teardown site would have covered. A session
        // that stayed in the list after ending is the failure to avoid: the
        // list would grow for the life of the proxy and every request naming
        // a stale id would fail in a way that looks like a race.
        //
        // Everything the registration hands out is built here, above the
        // dial, for the same reason the registration itself is: connecting
        // to the relay is the longest single thing a session does, and a
        // session that only became reachable afterwards would be
        // unreachable for exactly as long as that took — including forever,
        // on a relay that never answers. None of these four needs the relay.

        // Two admission checks, both before the relay is dialled, before a
        // registration exists and before a byte moves.
        //
        // The first is the draft this session will frame with. `DraftVersion`
        // carries every variant under every feature set, so a build made with
        // a reduced draft set can be configured for a draft it holds no codec
        // for, and nothing about that configuration looks wrong. Such a
        // session runs: every stream is bypassed as undecodable, no object
        // reaches a hook, no class claims anything, and the run reports
        // success — a byte pump that cannot be told apart from a quiet one.
        //
        // It is checked ahead of the shaping rules because a shaping rule is
        // judged *against* a draft, and asking whether a rule suits a draft
        // this build cannot frame answers with a matcher key when what is
        // wrong is the build.
        let draft = self.initial_draft();
        if !crate::capability::draft_is_compiled(draft) {
            return Err(ProxyError::DraftNotCompiled { draft });
        }

        // The second is the shaping profile: a rule keyed on a field this
        // draft's units do not carry can never claim anything, so a session
        // that ran with one would pace nothing, report shaping, and end
        // green. The rule is dead configuration and the only useful moment to
        // say so is the one before the run rather than during it.
        //
        // Checked here against the draft the session starts on, and checked
        // a second time further down against the draft the peers name, if
        // that turns out to be a different one. Both, rather than one or the
        // other: this one is the only check that can refuse a session
        // *before* it dials, and the later one is the only check that can
        // see an answer the `moq-00` cohort does not carry in its ALPN. A
        // rule this one refuses is dead on the draft the session was about
        // to use, whatever the peers go on to say.
        if let Some(profile) = self.config.shape.as_ref() {
            Capabilities::for_draft(draft)
                .admit_profile(profile)
                .map_err(|source| ProxyError::ShapeRuleUnsupported { source })?;
        }

        let closer = SessionCloser::new(self.cancel.clone());
        let streams = Arc::new(StreamRegistry::new());
        let gauge = EgressGauge::new();
        // One request channel per control-stream direction. Created before
        // the control stream exists so that both halves have a home from
        // the first instant: the sending halves go into the registry now,
        // and the receiving halves are served by the two control pipes once
        // `forward_control_stream` has streams to pipe.
        let client_leg = ControlLeg::new();
        let upstream_leg = ControlLeg::new();

        let _registration = self.control.as_ref().map(|c| {
            c.register(
                self.session_id,
                self.cancel.clone(),
                closer.clone(),
                Arc::clone(&streams),
                [client_leg.inbox.clone(), upstream_leg.inbox.clone()],
                self.config.egress,
            )
        });

        // Connect to upstream relay
        let relay = self.connect_upstream().await?;

        let client = Arc::new(client);
        let relay = Arc::new(relay);

        let mut tasks: JoinSet<Result<(), ProxyError>> = JoinSet::new();

        let initial_draft = self.initial_draft();
        let draft_is_fixed = self.draft_is_fixed();
        // One cell, shared by every task below. Built here because this is
        // where the tasks are: the control stream learns the draft and the
        // data, datagram and request tasks have to agree with it, and they
        // are all spawned from this scope within a few lines of each other.
        let session_draft = Arc::new(SessionDraft::new(initial_draft, draft_is_fixed));

        // ── The gating expression ───────────────────────────────────
        //
        // `objects_enabled` is the *framing* gate — which pipe function
        // `pipe_data` calls — and keeps its `observer_enabled ||` term
        // because `ProxyEvent::Object` fires for an observer alone.
        // `object_hook` is the *hook* gate. Collapsing the two would make
        // an event observer attached to an `Interest::NONE` hook start
        // calling — and honouring the `Action` returned by — a hook that
        // declared no object interest.
        //
        // `shaping_enabled` is the third gate, and it deliberately has
        // **no `observer_enabled ||` term** — the same asymmetry, for the
        // same reason, as `object_hook`. A `ShapeProfile` is
        // configuration; attaching an event observer must not start pacing
        // production traffic. It is a term of `objects_enabled` because
        // classification needs `ObjectMeta`, which only the framer
        // produces: a configured profile has to arm framing on its own,
        // with `Interest::NONE` and no observer, or the user gets a byte
        // pump and a green run.
        let interest = self.hook.interest();
        let observer_enabled = self.observer.wants_events();
        let shaping_enabled = self.config.shape.is_some();
        let objects_enabled =
            observer_enabled || interest.contains(Interest::OBJECTS) || shaping_enabled;
        let object_hook = interest.contains(Interest::OBJECTS);
        let control_mutation = interest.contains(Interest::CONTROL);
        // A fourth reason to decode control frames, and the only one that is
        // not about telling somebody. Drafts 18 and 19 write a fetch Object's
        // Group ID as a difference whose sign the fetch's Group Order decides,
        // and the order is on the FETCH — so on those two a session that
        // frames data has to read its own control plane or it cannot read its
        // own fetch streams. See `capability::fetch_group_order_is_needed`.
        //
        // The initial draft is exact here for the same reason it is in
        // `bidi_streams_carry_requests`: drafts 18 and 19 have an ALPN each,
        // and the one cohort that is a guess, `moq-00`, spans drafts 07 to 14
        // and answers `false` for every member.
        let fetch_orders_wanted = objects_enabled && fetch_group_order_is_needed(initial_draft);
        let control_parse = observer_enabled || control_mutation;
        let streams_enabled = interest.contains(Interest::STREAMS);
        let datagram_hook = interest.contains(Interest::DATAGRAMS);

        let base_ctx =
            ForwardCtx {
                session_id: self.session_id,
                draft: Arc::clone(&session_draft),
                draft_is_fixed,
                observer: Arc::clone(&self.observer),
                hook: Arc::clone(&self.hook),
                cancel: self.cancel.clone(),
                counters: Arc::clone(&self.counters),
                shape_stats: Arc::clone(&self.shape_stats),
                closer: closer.clone(),
                egress: self.config.egress,
                observer_enabled,
                objects_enabled,
                object_hook,
                shaping_enabled,
                // One shaper per session, shared by every forwarding task
                // through the `Arc` — the class rules, the queue policy and
                // the report-once state for `ShapeRuleUnmatchable` are all
                // session-scoped, and a per-task copy would report the same
                // unmatchable rule once per stream.
                //
                // Wrapped rather than held directly because a proxy can replace
                // its profile while this session runs; see [`SessionShaper`] for
                // what that costs and where the replacement is allowed to land.
                shape: self.config.shape.clone().map(|p| {
                    Arc::new(SessionShaper::new(p, self.control.as_ref().map(|c| c.plane())))
                }),
                control_mutation,
                control_parse,
                fetch_orders_wanted,
                // Always constructed, like `streams` and for the same reason:
                // an empty table allocates nothing and touches no counter, so
                // an `Option` here would buy nothing and would give the two
                // control pipes a second thing to be conditional about.
                fetch_orders: Arc::new(FetchGroupOrders::default()),
                streams_enabled,
                datagram_hook,
                next_stream_id: Arc::new(AtomicU64::new(0)),
                streams: Arc::clone(&streams),
                gauge: Arc::clone(&gauge),
            };

        // The command task for this session's control-plane requests.
        //
        // Spawned here, and not into `tasks`, on purpose: the `JoinSet`
        // below treats the *first* task to finish as the end of the session,
        // so a task that returns when its channel closes would tear down a
        // perfectly healthy session. It is deliberately spawned from inside
        // this scope rather than beside the session's construction, because
        // this is the first point at which the session's closer, its stream
        // registry and both transport handles exist at once — everything a
        // request could want to touch is reachable from the context cloned
        // into it. `AbortOnDrop` ends it if this future is dropped without
        // the cancellation token ever firing.
        let _commands = self.control.as_ref().and_then(|c| c.take_inbox()).map(|inbox| {
            let ctx = base_ctx.clone();
            AbortOnDrop::new(tokio::spawn(serve_session_commands(inbox, ctx)))
        });

        // ── The shaping profile, judged again against the wire's draft ──
        //
        // The check above ran before the dial, on the draft the session
        // started with. For the `moq-00` cohort that is a configured guess,
        // because drafts 07 to 14 share one ALPN — and the peers name the
        // real one in their SETUP a few milliseconds later. This is the same
        // question asked of that answer.
        //
        // It runs *only* where the two can differ, so an ALPN-fixed session
        // spawns nothing here and pays nothing. It is spawned into `tasks`
        // rather than beside them because the `JoinSet` reads the first
        // completion as the end of the session, which is exactly the
        // treatment a dead profile deserves: the session ends naming the
        // class and the key, instead of pacing nothing and reporting
        // success. Having judged, it holds its slot until the session ends
        // some other way.
        if !draft_is_fixed {
            if let Some(profile) = self.config.shape.clone() {
                let ctx = base_ctx.clone();
                tasks.spawn(async move {
                    let draft = ctx.resolved_draft().await;
                    // A session already going down is not judged. The wait
                    // above ends on cancellation as well as on an answer,
                    // and a refusal returned there would replace whatever
                    // actually ended the session with a verdict on a profile
                    // that is no longer going to shape anything.
                    if draft != initial_draft && !ctx.cancel.is_cancelled() {
                        Capabilities::for_draft(draft)
                            .admit_profile(&profile)
                            .map_err(|source| ProxyError::ShapeRuleUnsupported { source })?;
                    }
                    ctx.cancel.cancelled().await;
                    Ok(())
                });
            }
        }

        // ── Where the control plane is ──────────────────────────────
        //
        // Two questions, not one, and the draft answers them separately —
        // see `control_plane_is_unidirectional` and
        // `bidi_streams_carry_requests`, which quote the sections. On 07-15
        // the control stream is the first client-initiated bidirectional
        // stream and nothing else uses a bidirectional stream at all, so one
        // task owns it. On 17-19 the control plane is a pair of
        // unidirectional streams, one opened by each peer, and bidirectional
        // streams carry requests — so the control legs travel with the
        // unidirectional accept loops, which are the loops the control
        // streams arrive on, and the bidirectional streams get accept loops
        // of their own in both directions.
        //
        // Draft-16 answers one question each way and is the only draft that
        // does: a bidirectional control stream, and request streams beside
        // it. It takes the first branch's shape for the control stream and
        // the second's for the requests.
        //
        // The mapping of a leg to a loop is the same half-turn
        // `forward_control_stream` makes for its two pipes: a message the
        // relay is meant to decode — `Leg::Upstream`, the `upstream_leg` —
        // is written by the pipe forwarding *from* the client, so it goes
        // to the client-to-relay loop.
        let (client_uni_leg, relay_uni_leg) = if control_plane_is_unidirectional(initial_draft) {
            for (source, dest, side) in [
                (Arc::clone(&client), Arc::clone(&relay), ProxySide::ClientToProxy),
                (Arc::clone(&relay), Arc::clone(&client), ProxySide::RelayToProxy),
            ] {
                let ctx = base_ctx.clone();
                tasks.spawn(
                    async move { forward_request_streams(&source, &dest, side, &ctx).await },
                );
            }
            (Some(upstream_leg), Some(client_leg))
        } else {
            // Draft-16 has request streams beside its bidirectional control
            // stream, and either endpoint opens one. The relay's are taken
            // here; the client's are taken inside `forward_control_stream`,
            // after it has taken the control stream, because that is the same
            // transport and only one accept may be outstanding on it.
            if bidi_streams_carry_requests(initial_draft) {
                let source = Arc::clone(&relay);
                let dest = Arc::clone(&client);
                let ctx = base_ctx.clone();
                tasks.spawn(async move {
                    forward_request_streams(&source, &dest, ProxySide::RelayToProxy, &ctx).await
                });
            }
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_control_stream(&client, &relay, &ctx, client_leg, upstream_leg).await
            });
            (None, None)
        };

        // Client → Relay uni streams
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_uni_streams(&client, relay, ProxySide::ClientToProxy, &ctx, client_uni_leg)
                    .await
            });
        }

        // Relay → Client uni streams
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_uni_streams(&relay, client, ProxySide::RelayToProxy, &ctx, relay_uni_leg)
                    .await
            });
        }

        // Datagram forwarding: client → relay
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_datagrams(&client, &relay, ProxySide::ClientToProxy, &ctx).await
            });
        }

        // Datagram forwarding: relay → client
        {
            let client = Arc::clone(&client);
            let relay = Arc::clone(&relay);
            let ctx = base_ctx.clone();
            tasks.spawn(async move {
                forward_datagrams(&relay, &client, ProxySide::RelayToProxy, &ctx).await
            });
        }

        // Wait for first task to finish (signals session is done)
        let first_result = tasks.join_next().await;

        // Cancel remaining tasks
        self.cancel.cancel();
        tasks.shutdown().await;

        // A hook that asked for a close is the reason, whatever the task
        // that noticed the cancellation reported.
        let reason = match closer.requested() {
            Some((code, why, origin)) => {
                // Named, not assumed. A close reaches the same latch from a
                // hook's `Action::CloseSession` and from
                // `ProxyControl::close_session`, and reporting both as the
                // hook's told an observer that the run under test ended
                // the session when the operator outside it had.
                let who = match origin {
                    CloseOrigin::Hook => "hook",
                    CloseOrigin::ControlPlane => "control plane",
                };
                format!(
                    "{who} closed the session: code {code}, reason {:?}",
                    String::from_utf8_lossy(&why)
                )
            }
            None => match &first_result {
                Some(Ok(Ok(()))) => "completed".to_string(),
                Some(Ok(Err(e))) => format!("{e}"),
                Some(Err(e)) => format!("task panic: {e}"),
                None => "no tasks".to_string(),
            },
        };
        if self.observer.wants_events() {
            self.observer
                .on_event(&ProxyEvent::SessionEnded { session_id: self.session_id, reason });
        }

        // Close both sides. `close_args` is the pair a hook's
        // `Action::CloseSession` recorded, or the proxy's own default when
        // no hook asked for anything.
        let (close_code, close_reason) = closer.close_args();
        client.close(close_code, &close_reason);
        relay.close(close_code, &close_reason);

        match first_result {
            Some(Ok(Ok(()))) | None => Ok(()),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(ProxyError::SessionClosed(format!("task panic: {e}"))),
        }
    }

    /// Connect to the upstream relay (with optional timeout).
    async fn connect_upstream(&self) -> Result<Transport, ProxyError> {
        let timeout_secs = self.config.upstream_connect_timeout_secs;
        if timeout_secs > 0 {
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                self.connect_upstream_inner(),
            )
            .await
            .map_err(|_| {
                ProxyError::UpstreamConnect(format!("connection timed out after {timeout_secs}s"))
            })?
        } else {
            self.connect_upstream_inner().await
        }
    }

    async fn connect_upstream_inner(&self) -> Result<Transport, ProxyError> {
        // Resolved out here rather than inside the QUIC arm, and ahead of
        // every other refusal below, because naming both a raw config and a
        // profile is a contradiction in what the caller wrote — it is not a
        // fact about the transport they picked, and it is answerable
        // without touching the network. A WebTransport upstream reaches
        // this line too, where both fields would then be ignored: a
        // contradiction reported on one transport and swallowed on the
        // other would be a rule that holds only where someone happened to
        // test it.
        //
        // A capture is the one thing this line has a side effect for. The
        // sink is built here, which writes the capture's preamble, so a
        // WebTransport upstream carrying a spec leaves a file that exists
        // and holds no event — `wtransport` builds that endpoint and never
        // sees the config the sink went on. That is documented on the field
        // rather than refused, and this is the reason it cannot be refused
        // cheaply: the step that builds the sink is the step shared with
        // the client leg, which has no transport to dispatch on, and moving
        // it below the match to gain one would take the contradiction check
        // down there with it — where a WebTransport upstream would stop
        // hearing about the pair it is being refused for today.
        let transport_config = transport::resolve(
            Leg::Upstream,
            self.config.upstream_transport_config.clone(),
            self.config.upstream_transport_profile.as_ref(),
            self.config.upstream_installer.as_ref(),
            // Taken, not cloned: there is one writer and it belongs to this
            // dial. A session dialled twice therefore captures the first
            // connection and not the second, which is the only division of
            // one writer between two connections that produces a readable
            // file.
            #[cfg(feature = "qlog")]
            self.upstream_qlog.lock().expect("no session holds this across a panic").take(),
        )?;

        match &self.config.upstream_transport {
            UpstreamTransportType::Quic => self.connect_upstream_quic(transport_config).await,
            // Ahead of both `webtransport` arms on purpose: whether the
            // feature is compiled in changes which *other* error a
            // WebTransport upstream produces, and this refusal is about
            // the socket rather than about the transport being reachable.
            // A caller who supplied a socket must hear that it cannot be
            // honoured, in either build.
            UpstreamTransportType::WebTransport { .. } if self.config.upstream_socket.is_some() => {
                Err(ProxyError::UpstreamSocketUnsupported)
            }
            #[cfg(feature = "webtransport")]
            UpstreamTransportType::WebTransport { url } => {
                let url = url.clone();
                self.connect_upstream_webtransport(&url).await
            }
            #[cfg(not(feature = "webtransport"))]
            UpstreamTransportType::WebTransport { .. } => {
                Err(ProxyError::UpstreamConnect("webtransport feature not enabled".to_string()))
            }
        }
    }

    /// Connect to the upstream relay via QUIC.
    ///
    /// `transport_config` is what this leg resolved to before anything was
    /// built — the caller's raw config, or one built from their profile, or
    /// `None` for quinn's defaults. It arrives as an argument rather than
    /// being read from `self.config` here so that there is exactly one
    /// place the two fields are reconciled, and so that the reconciliation
    /// happens before the transport is even dispatched on.
    async fn connect_upstream_quic(
        &self,
        transport_config: Option<Arc<quinn::TransportConfig>>,
    ) -> Result<Transport, ProxyError> {
        let server_addr =
            self.config.upstream_addr.parse().map_err(|e: std::net::AddrParseError| {
                ProxyError::UpstreamConnect(e.to_string())
            })?;

        let mut tls_config = self.build_upstream_tls_config()?;
        tls_config.alpn_protocols = self.config.upstream_alpn(&self.client_alpn);

        let quic_config: quinn::crypto::rustls::QuicClientConfig =
            tls_config.try_into().map_err(|e| ProxyError::TlsConfig(format!("{e}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        if let Some(transport) = transport_config {
            client_config.transport_config(transport);
        }

        // A supplied socket replaces the bind, and nothing else: the same
        // client config, the same ALPN and the same `connect` follow. The
        // endpoint takes no `ServerConfig` on either branch — this one
        // only ever dials.
        let mut endpoint = match &self.config.upstream_socket {
            Some(socket) => {
                let runtime = quinn::default_runtime().ok_or_else(|| {
                    ProxyError::UpstreamConnect("no async runtime found".to_string())
                })?;
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    Arc::clone(socket),
                    runtime,
                )
                .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?
            }
            None => quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?,
        };
        endpoint.set_default_client_config(client_config);

        let server_name =
            self.config.upstream_addr.split(':').next().unwrap_or("localhost").to_string();

        let conn = endpoint
            .connect(server_addr, &server_name)
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?
            .await
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

        Ok(Transport::Quic(QuicTransport::new(conn)))
    }

    /// Connect to the upstream relay via WebTransport.
    #[cfg(feature = "webtransport")]
    async fn connect_upstream_webtransport(&self, url: &str) -> Result<Transport, ProxyError> {
        use moqtap_client::transport::webtransport::WebTransportTransport;

        let wt_config = if self.config.skip_upstream_cert_verify {
            wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build()
        } else {
            wtransport::ClientConfig::builder().with_bind_default().with_native_certs().build()
        };

        let endpoint = wtransport::Endpoint::client(wt_config)
            .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

        let connection =
            endpoint.connect(url).await.map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

        Ok(Transport::WebTransport(WebTransportTransport::new(connection)))
    }

    /// Build a rustls `ClientConfig` for the upstream connection.
    fn build_upstream_tls_config(&self) -> Result<rustls::ClientConfig, ProxyError> {
        if self.config.skip_upstream_cert_verify {
            Ok(rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerification))
                .with_no_client_auth())
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for der in &self.config.upstream_ca_certs {
                roots
                    .add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|e| ProxyError::TlsConfig(format!("bad CA cert: {e}")))?;
            }
            Ok(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
        }
    }
}

// ── Forwarding helpers ──────────────────────────────────────────

/// One session's shaper, and the proxy profile it watches.
///
/// A session builds a [`Scheduler`] from the profile it was configured with
/// and shares it through the whole forwarding scope. That much has not
/// changed. What this adds is a place to notice that the proxy has been
/// given a *different* profile while the session runs, and a rule about when
/// the session is allowed to act on it.
///
/// # The swap happens between streams, never inside one
///
/// [`Self::current`] is read once per forwarded stream, and the
/// `Arc<Scheduler>` it hands back is what that stream classifies with, queues
/// under and paces against for the whole of its life. A stream that is
/// already forwarding keeps the scheduler it started with even after the
/// profile has moved on.
///
/// That is forced rather than chosen. A `Class` is an index into a
/// scheduler's class list, and a stream's egress queue holds the scheduler
/// its units were admitted under. Swapping mid-stream would classify a unit
/// against one profile's rules and release it against another profile's
/// buckets and demand rows — charging a class that is not the one that was
/// matched, or, where the new list is shorter, a class that does not exist.
/// Reading it per stream costs one `Mutex` acquisition where a `PendingQueue`
/// is already being built.
///
/// # A profile with a different class list is not taken up at all
///
/// The session's [`ShapeRecorder`] has one row per configured class,
/// pre-sized when the session is constructed and never resized, and a class
/// is charged to its row by position. A profile whose class list differs
/// from the one those rows were named after would therefore keep every
/// number correct and make every label on it wrong. So a live profile is
/// taken up only when its class names match, in order, the ones this session
/// started with; otherwise the session keeps its own until it ends. Changing
/// the class list of a running session is done by ending it.
struct SessionShaper {
    /// The proxy this session belongs to, or `None` for a session driven
    /// directly rather than through an accept loop — which has no proxy, so
    /// no profile can be installed on it and this never looks.
    plane: Option<Arc<ControlPlane>>,
    /// The class names this session's statistics rows were pre-sized from,
    /// and the test a live profile has to pass to be taken up.
    classes: Vec<String>,
    /// The scheduler in force, and the profile generation it was built at.
    current: Mutex<CachedShaper>,
}

/// What [`SessionShaper`] keeps behind its lock.
struct CachedShaper {
    /// The proxy profile generation this scheduler was built from. A
    /// mismatch against the plane's is the whole of the "something changed"
    /// signal — comparing profiles would clone one per stream.
    generation: u64,
    /// The scheduler every stream opened since the last swap is using.
    scheduler: Arc<Scheduler>,
}

impl SessionShaper {
    /// Build the shaper for a session configured with `profile`.
    ///
    /// `profile` is what the session's statistics rows were pre-sized from,
    /// so its class list is the one every later swap is measured against. A
    /// profile installed on the proxy between the session's configuration
    /// being copied and this call is taken up here, under the same rule a
    /// later one would be — that window is short, but a session that ignored
    /// it would run on a profile the proxy had already replaced with no way
    /// to notice.
    fn new(profile: ShapeProfile, plane: Option<Arc<ControlPlane>>) -> Self {
        let classes: Vec<String> = profile.classes().iter().map(|c| c.name.clone()).collect();
        let (generation, scheduler) = match &plane {
            Some(plane) => {
                let shape = plane.shape();
                let (generation, live) = shape.snapshot();
                let chosen = match live {
                    Some(live) if same_classes(&live, &classes) => live,
                    _ => profile,
                };
                (generation, Scheduler::with_switch(chosen, shape.switch()))
            }
            // No proxy, so no switch to share and no generation to watch.
            // Pacing is on and stays on, which is what a session driven
            // directly has always done.
            None => (0, Scheduler::new(profile)),
        };
        Self {
            plane,
            classes,
            current: Mutex::new(CachedShaper { generation, scheduler: Arc::new(scheduler) }),
        }
    }

    /// The scheduler the next stream should run under.
    ///
    /// Takes up a profile installed since the last call when its class list
    /// matches; otherwise hands back what this session already had. Either
    /// way the generation is recorded, so a profile this session declined is
    /// not re-examined once per stream for the rest of the run — and a
    /// *later* profile that does match is still taken up, because the
    /// comparison is always against the class list the session started with.
    fn current(&self) -> Arc<Scheduler> {
        let mut cached = self.current.lock().expect("session shaper");
        if let Some(plane) = &self.plane {
            let shape = plane.shape();
            if shape.generation() != cached.generation {
                let (generation, live) = shape.snapshot();
                cached.generation = generation;
                if let Some(live) = live {
                    if same_classes(&live, &self.classes) {
                        cached.scheduler = Arc::new(Scheduler::with_switch(live, shape.switch()));
                    }
                }
            }
        }
        Arc::clone(&cached.scheduler)
    }
}

/// Whether `profile` names exactly `classes`, in the same order.
///
/// Names and order, because that pair is what makes a `Class::Rule(index)`
/// mean the same thing to the scheduler that produced it and to the
/// statistics row it is charged to. Same names in a different order would
/// charge each class to another one's row without a single count going
/// missing.
fn same_classes(profile: &ShapeProfile, classes: &[String]) -> bool {
    profile.classes().len() == classes.len()
        && profile.classes().iter().zip(classes).all(|(rule, name)| &rule.name == name)
}

/// How long a task that needs the session's draft waits for the control
/// stream to name one before running on the draft the session started with.
///
/// The wait exists for one race, and the race is a small one. Drafts 07 to
/// 14 all negotiate the same ALPN, so those sessions start on a configured
/// guess and learn the real answer from CLIENT_SETUP — which every draft in
/// that cohort puts first on the wire, ahead of the subscription exchange
/// any data stream comes out of. So the bytes that settle the draft have
/// already arrived by the time a data stream exists, and what is left to
/// wait for is one task being polled rather than a round trip. The window is
/// sized well above that and is not a latency budget: it is the point at
/// which the session stops believing a SETUP is coming.
///
/// It has to end, because a peer that opens a data stream having sent no
/// SETUP at all is not a session any draft describes, and such a session
/// still has to run rather than stall. When the window expires the session
/// settles on the draft it started with — at the lowest [`DraftSource`]
/// rank, so a SETUP that turns up afterwards still refines the streams that
/// come after it.
///
/// A session with no control stream at all never reaches the window; see
/// [`SessionDraft::control_stream_open`].
const DRAFT_SETTLE_WINDOW: Duration = Duration::from_millis(100);

/// Where a session's draft came from, ranked by how much it is worth.
///
/// A later answer replaces an earlier one only if it outranks it, which is
/// what makes the order here the whole policy and keeps it in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DraftSource {
    /// Nobody named a draft, so the session kept the one it was configured
    /// for. Two things produce it: [`DRAFT_SETTLE_WINDOW`] expiring, and a
    /// control stream whose first message is readable enough to say it is
    /// not a SETUP — in both cases there is nothing to learn from and the
    /// tasks waiting on an answer are better off with the starting draft
    /// than with the wait.
    ///
    /// The lowest rank, because it is not an answer at all: it is the
    /// absence of one, and a SETUP that turns up afterwards — on this
    /// direction or the other — must still be able to replace it.
    Fallback,
    /// The highest draft in the `moq-00` cohort that CLIENT_SETUP offered.
    /// An offer rather than an agreement: a server is free to select a lower
    /// version out of the same list.
    Offered,
    /// The version SERVER_SETUP selected. This is the one the two peers are
    /// actually speaking, so it outranks the client's offer.
    Selected,
    /// The ALPN, which names exactly one draft from 15 on and is known
    /// before a byte is read. Nothing can improve on it, so it outranks
    /// everything and the session never waits.
    Alpn,
}

/// The draft this session frames with, and the one place every task reads it
/// from.
///
/// # Why a shared cell rather than a field
///
/// Drafts 07 to 14 all negotiate the same ALPN, so a session in that cohort
/// starts on the draft its configuration named and learns the wire's answer
/// from the first SETUP on the control stream. Everything that has to agree
/// with that answer — the object framer on every data stream, the datagram
/// header decoder, the control-frame walker that places an injection, and
/// the capability table each hook site is shown — lives in a task that was
/// spawned before the control stream was even accepted. A draft copied into
/// each of those tasks is a copy of the guess, and no later correction can
/// reach it.
///
/// # Reading it
///
/// [`Self::now`] is the non-blocking read: the best answer so far, or the
/// starting draft while there is none. [`Self::resolved`] is the ordering
/// edge — it waits for an answer, and is what a task calls when running on
/// the wrong draft would produce a wrong result rather than a stale label.
///
/// # Writing it
///
/// [`Self::settle`] takes the first write of each rank and keeps the highest
/// (see [`DraftSource`]). Both control directions write: the client's
/// direction from CLIENT_SETUP and the relay's from SERVER_SETUP, so the
/// pair converges on the version the peers agreed rather than on whichever
/// direction was read first.
struct SessionDraft {
    /// The draft chosen before the relay was dialled — the ALPN's answer
    /// where there is one, and the configured draft otherwise. What
    /// [`Self::now`] answers while nothing has settled, and what the
    /// deadline settles on.
    initial: DraftVersion,
    /// The best answer so far, or `None` while the session is still running
    /// on `initial`. A `watch` rather than an atomic because the waiters are
    /// the point: this is what [`Self::resolved`] parks on.
    settled: watch::Sender<Option<(DraftVersion, DraftSource)>>,
    /// The instant [`Self::resolved`] stops waiting. Absolute, and shared by
    /// every waiter, so a session pays this window once rather than once per
    /// stream: the first waiter to reach it settles the cell, and every
    /// waiter after that returns immediately.
    deadline: tokio::time::Instant,
    /// Whether this session has a control stream at all yet.
    ///
    /// The only thing that can name a draft is a SETUP, and the only place a
    /// SETUP arrives is a control stream. Until one exists there is nothing
    /// to wait for, so [`Self::resolved`] does not wait — which is what
    /// keeps the window off the timing of a session that never opens one.
    ///
    /// It is a latch and not a promise. A peer that opened a data stream
    /// before its control stream gets the starting draft on that one stream,
    /// which is the same answer it would have got with no cell at all; every
    /// draft in the cohort puts the setup exchange first, so a session in
    /// which that happens is not one they describe.
    control_stream_open: AtomicBool,
}

impl SessionDraft {
    /// The cell for a session starting on `initial`.
    ///
    /// `fixed` is whether that draft came from the ALPN. A fixed session is
    /// born settled, so it never waits and no SETUP peek can move it — which
    /// is the right reading of drafts 15 and later, where the SETUP message
    /// carries no version at all.
    fn new(initial: DraftVersion, fixed: bool) -> Self {
        let (settled, _) = watch::channel(fixed.then_some((initial, DraftSource::Alpn)));
        Self {
            initial,
            settled,
            deadline: tokio::time::Instant::now() + DRAFT_SETTLE_WINDOW,
            control_stream_open: AtomicBool::new(false),
        }
    }

    /// Record that this session now has a control stream.
    ///
    /// Called where one starts being forwarded, in both topologies. What it
    /// buys is the *absence* of a wait everywhere else: see
    /// [`Self::control_stream_open`].
    fn note_control_stream(&self) {
        self.control_stream_open.store(true, Ordering::Release);
    }

    /// The best answer so far, without waiting for a better one.
    fn now(&self) -> DraftVersion {
        self.settled.borrow().map_or(self.initial, |(draft, _)| draft)
    }

    /// Record `draft` as this session's, if `source` outranks what is held.
    ///
    /// Answers whether it landed, so a caller that has work to do only when
    /// the session's draft actually moved can ask rather than compare.
    fn settle(&self, draft: DraftVersion, source: DraftSource) -> bool {
        self.settled.send_if_modified(|held| match held {
            Some((_, ranked)) if *ranked >= source => false,
            _ => {
                *held = Some((draft, source));
                true
            }
        })
    }

    /// The draft, waited for.
    ///
    /// Returns at once when the session already has an answer, which is
    /// every session whose ALPN named a draft and every session whose
    /// control stream has already been read. It also returns at once when
    /// the session has no control stream yet, because nothing else can
    /// answer and waiting would put [`DRAFT_SETTLE_WINDOW`] on the front of
    /// every stream of a session that never opens one.
    ///
    /// Otherwise it waits for one of three things: a SETUP naming the draft,
    /// [`DRAFT_SETTLE_WINDOW`] expiring, or the session being cancelled —
    /// the last of which is why a teardown is not held up by a window that
    /// has barely started.
    async fn resolved(&self, cancel: &CancellationToken) -> DraftVersion {
        let mut changed = self.settled.subscribe();
        if let Some((draft, _)) = *changed.borrow_and_update() {
            return draft;
        }
        if !self.control_stream_open.load(Ordering::Acquire) {
            return self.initial;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => {}
            _ = changed.changed() => {}
            () = tokio::time::sleep_until(self.deadline) => {
                self.settle(self.initial, DraftSource::Fallback);
            }
        }
        self.now()
    }
}

/// Shared context for forwarding helpers, avoiding repeated parameter lists.
#[derive(Clone)]
struct ForwardCtx {
    session_id: SessionId,
    /// The draft this session frames with, shared by every task rather than
    /// copied into each — see [`SessionDraft`] for why that matters and for
    /// what settles it. Read through [`ForwardCtx::draft`], or through
    /// [`ForwardCtx::resolved_draft`] where the answer has to be right
    /// rather than current.
    draft: Arc<SessionDraft>,
    /// Whether `draft` is fixed (from ALPN) and should not be refined by
    /// peeking at SETUP messages.
    draft_is_fixed: bool,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
    cancel: CancellationToken,
    /// This session's slow-path counters.
    counters: Arc<Recorder>,
    /// This session's shaping counters. Cloned per task exactly as
    /// `counters` is, and carried unconditionally: an unshaped
    /// session's recorder has no class rows and no writer, so the cost of
    /// carrying it is one `Arc` clone per forwarding task and the cost of
    /// *not* carrying it would be an `Option` branch on the data path.
    shape_stats: Arc<ShapeRecorder>,
    /// Where an `Action::CloseSession` lands, and what `run_with_transport`
    /// reads its close code and reason back out of.
    closer: SessionCloser,
    /// Engine knobs for the per-stream deferred write queues.
    egress: EgressConfig,
    /// Cached `observer.wants_events()` — gates event construction and
    /// emission in the hot forwarding loop. When `false`, the proxy can
    /// skip parsing for observation purposes and run as a byte pump.
    observer_enabled: bool,
    /// Whether data streams are framed into objects — the *framing* gate,
    /// which decides whether `pipe_data` calls `pipe_data_framed` or
    /// `pipe_data_passthrough`. Keeps its `observer_enabled ||` term
    /// because `ProxyEvent::Object` is an observer-only guarantee. This is
    /// **not** the gate on calling `on_object`; see `object_hook`.
    objects_enabled: bool,
    /// Whether `ProxyHook::on_object` is consulted. `Interest::OBJECTS`
    /// alone, with no `observer_enabled ||` term: an event observer must
    /// not hand a hook that declared no object interest the power to drop,
    /// delay and rewrite traffic.
    object_hook: bool,
    /// Whether this session was configured with a
    /// [`ShapeProfile`].
    ///
    /// `config.shape.is_some()` alone, with **no `observer_enabled ||`
    /// term** — the same asymmetry as `object_hook` and for the same
    /// reason: shaping is configuration, so attaching an observer must not
    /// arm it. It *is* a term of `objects_enabled`, because a profile has
    /// to arm framing on its own.
    ///
    /// The read below is what makes that implication checkable rather than
    /// merely written down.
    ///
    /// Exactly `shape.is_some()`, and the two are kept as separate fields
    /// on purpose: this one is a `bool` a `debug_assert!` and a hot-path
    /// branch can read without touching an `Arc`, and `shape` is the
    /// engine. The equivalence is checked in `pipe_data`, where the
    /// framing decision is taken.
    shaping_enabled: bool,
    /// This session's shaper, or `None` when no
    /// [`ShapeProfile`] was configured.
    ///
    /// Unlike `shape_stats` and `streams`, which are always constructed,
    /// this is genuinely optional — there is nothing for an unshaped
    /// session to share, and an `Option` here is what makes "a session with
    /// `shape: None` adds nothing to the shaping path" a fact the type
    /// system carries rather than a claim a reviewer checks.
    ///
    /// `Some` or `None` is fixed for the session's life. A profile installed
    /// on the proxy afterwards can replace what is *inside* this, and cannot
    /// put something here: framing is armed at session start and a session
    /// that began as a byte pump produces no `ObjectMeta` to classify.
    shape: Option<Arc<SessionShaper>>,
    /// Whether `ProxyHook::on_control_message` is consulted, which also
    /// routes the control stream through the parse-then-forward pipe: the
    /// pass-through pipe writes before it parses, so a hook return there
    /// would be unexecutable by construction.
    control_mutation: bool,
    /// Whether a `ControlStreamParser` is built for somebody to *read*.
    /// `Interest::NONE` with no observer builds none, which is what makes
    /// `control_parsers_created == 0` unconditional on that path.
    ///
    /// Not the whole answer to "is there a parser": `fetch_orders_wanted` is
    /// the other, and it builds one for the session's own use. Ask
    /// [`ForwardCtx::control_frames_are_decoded`] rather than either alone.
    control_parse: bool,
    /// Whether this session has to decode control frames to read its own
    /// fetch streams — drafts 18 and 19, framing data.
    ///
    /// Unlike `control_parse` this arms no report and calls no hook. It is
    /// the one case where the proxy parses the control plane for itself, and
    /// it is why a hook declaring `Interest::OBJECTS` alone can still see a
    /// draft-19 fetch Object.
    fetch_orders_wanted: bool,
    /// What each FETCH this session carried asked for, waiting for the
    /// response stream that answers it.
    ///
    /// Written by both control pipes and read by the object framer; see
    /// [`FetchGroupOrders`].
    fetch_orders: Arc<FetchGroupOrders>,
    /// Whether `on_stream_open`, `on_stream_header` and `on_stream_end` are
    /// consulted. `Interest::STREAMS` contains `Interest::OBJECTS`
    /// structurally, so this implies `objects_enabled`.
    streams_enabled: bool,
    /// Whether `ProxyHook::on_datagram` is consulted.
    datagram_hook: bool,
    /// The session's [`StreamKey`] mint.
    /// One counter per session, shared by every forwarding task through the
    /// `Arc` — `ForwardCtx` is cloned per task and per stream, so a plain
    /// `AtomicU64` would give each clone its own sequence and two streams would
    /// collide on id 0. The `Arc` is what makes *unique for the session's
    /// lifetime* true rather than aspirational.
    next_stream_id: Arc<AtomicU64>,
    /// Every forwarded stream that is still live, and the gate each one
    /// releases when it ends.
    ///
    /// **Always constructed**, for every session, exactly like
    /// `next_stream_id` and unlike anything a `ShapeProfile` will later
    /// arm: `StreamAction::SerializeAfter` is gated by `Interest::STREAMS`
    /// and the capability table publishes it as an unconditional `Yes` at
    /// both stream sites, so a registry that only existed when a profile
    /// was configured would make that published cell a lie. An empty
    /// registry allocates nothing and touches no counter, so
    /// `interest_none.rs`'s whole-struct `Counters::default()` comparison
    /// and its `!release_timer_started()` companion stay falsifiable.
    streams: Arc<StreamRegistry>,
    /// How many bytes this session's egress queues are holding, summed
    /// across every stream.
    /// Always constructed, like `streams` and for a related reason: a gauge
    /// that only some queues reported into would answer *this session has
    /// nothing left to flush* while another stream still held a deferred frame,
    /// and the one caller that reads it — a requested close deciding whether it
    /// may stop waiting — would act on that answer.
    ///
    /// Costs one `Arc` clone per forwarding task and two relaxed atomic
    /// updates per *queued* unit. A session that queues nothing, which is
    /// every session with no timing action and no profile, never touches
    /// it: the counters only move inside `PendingQueue::push` and its
    /// releases.
    gauge: Arc<EgressGauge>,
}

impl ForwardCtx {
    /// The draft this session frames with, as it stands now.
    fn draft(&self) -> DraftVersion {
        self.draft.now()
    }

    /// Whether a control frame gets decoded on this session at all.
    ///
    /// Two unrelated reasons, deliberately summed in one place rather than
    /// spelled `a || b` at each of the pipes: `control_parse` is somebody
    /// asking to be told, and `fetch_orders_wanted` is the session needing
    /// the answer itself. A pipe that tested only the first left a
    /// draft-19 fetch stream unaddressable on an `Interest::OBJECTS`
    /// session, which is the shape of hook the object site exists for.
    fn control_frames_are_decoded(&self) -> bool {
        self.control_parse || self.fetch_orders_wanted
    }

    /// What this session's draft can be asked for.
    ///
    /// Built here, at each site that needs one, rather than cached on this
    /// struct. [`Capabilities`] is a `Copy` newtype over a draft, so
    /// constructing it costs a move of one enum and answers for the draft
    /// the session is framing with *at that moment* — while a cached copy
    /// would have been built beside the guess and would go on answering for
    /// it after the peer named something else. One draft in one cell has one
    /// consumer to keep correct; a cached table beside it would be a second.
    fn caps(&self) -> Capabilities {
        Capabilities::for_draft(self.draft())
    }

    /// The draft this session frames with, waited for.
    ///
    /// The ordering edge between the control stream, which learns the draft,
    /// and the tasks that have to agree with it. Called where the wrong
    /// draft produces a wrong result rather than a stale label: the object
    /// framer decides where an object ends, and a datagram header decoder
    /// decides what a datagram says. See [`SessionDraft::resolved`] for what
    /// bounds the wait.
    async fn resolved_draft(&self) -> DraftVersion {
        self.draft.resolved(&self.cancel).await
    }

    /// Mint this stream's session-local identity.
    ///
    /// Called **once** per forwarded stream, at accept, and handed to every
    /// hook site that stream reaches. Monotonic, never reused, and
    /// deliberately not the transport stream id: on the WebTransport arm
    /// that is the constant `0` for every stream, so a transport-keyed
    /// identity collapses a whole side onto one entry.
    fn mint_key(&self, side: ProxySide) -> StreamKey {
        StreamKey { side, id: self.next_stream_id.fetch_add(1, Ordering::Relaxed) }
    }

    /// Emit a proxy event only if the observer wants events.
    ///
    /// Takes a closure so the `ProxyEvent` is not constructed when
    /// observation is disabled — avoiding clones of message payloads in
    /// the hot path.
    fn emit(&self, event: impl FnOnce() -> ProxyEvent) {
        if self.observer_enabled {
            self.observer.on_event(&event());
        }
    }

    /// A reporter for one stream direction, or for a datagram path
    /// (`stream_id: None`).
    fn reporter<'a>(&'a self, side: ProxySide, stream_id: Option<u64>) -> exec::Reporter<'a> {
        exec::Reporter::new(
            &*self.observer,
            self.observer_enabled,
            &self.counters,
            self.session_id,
            side,
            stream_id,
        )
    }
}

/// Serve one session's control-plane requests until the session ends.
///
/// Runs beside the forwarding tasks rather than among them, because the
/// `JoinSet` in `run_with_transport` reads the first completion as the end
/// of the session and this loop finishes on its own terms — when the inbox
/// closes, or when the session is cancelled.
///
/// The cancellation branch is what makes the loop terminate for a session
/// that ends normally: the inbox's sender lives in the control plane's
/// registry entry, which is released by the registration guard *after* this
/// function's spawner has already returned, so waiting only on the channel
/// would keep the task alive past the session it belongs to.
///
/// The select is `biased` so that branch is polled first. That makes
/// cancellation the single exit for a session that is going down, whichever
/// way it was asked: a request that ends the session cancels and goes round
/// again, and the next poll leaves through the same door as a session that
/// was cancelled from outside. The alternative — returning from the request
/// arm — would give the same event two exits to keep correct.
async fn serve_session_commands(mut inbox: mpsc::Receiver<SessionCommand>, ctx: ForwardCtx) {
    loop {
        tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => return,
            command = inbox.recv() => match command {
                Some(SessionCommand::Close { drain }) => close_after_draining(drain, &ctx).await,
                // Every sender is gone, which can only happen once the
                // registry entry has been released. Nothing further can
                // arrive.
                None => return,
            },
        }
    }
}

/// Give this session's egress queues `drain` to empty, then end it.
///
/// The close code and reason are already in the session's closer — a
/// requested close records them before it sends the request, so that a
/// session torn down by its peer half a millisecond later still closes with
/// what was asked for. This function's only job is the window, and what
/// happens at the end of it.
///
/// # Draining means the queues emptied, not that the timer expired
///
/// The wait ends the moment `EgressGauge` reads zero, which on a session
/// with nothing deferred is the first poll. Waiting out the full window
/// unconditionally would put a fixed cost on every close, and the cost is
/// the wrong one: it is paid by the sessions that had nothing to flush.
///
/// # And what is left is abandoned rather than flushed
///
/// The queues are put into discarding mode before the cancellation, so the
/// cancel arm of every pipe writes nothing and reports its whole remainder
/// as `Impairment { QueuedBytesAtTeardown }`. That is the opposite of what
/// an unrequested teardown does, and the difference is the deadline: an
/// ordinary teardown's best-effort flush is the last chance those bytes
/// have, while a close that was given a window and spent it has already
/// decided. Flushing past that point would hand the bytes to a connection
/// about to send `CONNECTION_CLOSE`, which discards its buffer — so they
/// would be neither confirmably delivered nor confirmably lost, and the one
/// arithmetic a caller can check would stop closing.
///
/// The cancellation is unconditional and comes last, so a session whose
/// drain completed and one whose drain expired end the same way and with
/// the same close arguments.
async fn close_after_draining(drain: Duration, ctx: &ForwardCtx) {
    tokio::select! {
        biased;
        // Already going down for some other reason. Its queues will be
        // handled by the ordinary teardown, which is the right treatment:
        // this close never got as far as setting a deadline.
        () = ctx.cancel.cancelled() => {}
        stranded = ctx.gauge.wait_idle(drain) => {
            if stranded > 0 {
                ctx.gauge.begin_discarding();
            }
        }
    }
    ctx.cancel.cancel();
}

/// The deferred-write state of one stream direction, plus the two facts
/// every teardown helper needs about it.
///
/// Bundled because `PendingQueue` and `DeferredEffects` are only correct
/// when they move together, and because `propagate_reset` needs both the
/// stream's identity and its queue.
struct StreamState<'a> {
    stream_id: u64,
    /// This stream's session-local identity, minted once at accept and
    /// carried to every site it reaches. Distinct from `stream_id`, which
    /// is the transport id and is `0` on every WebTransport stream.
    key: StreamKey,
    /// `true` selects the control-stream rules at `Site::StreamEnd`, where
    /// a synthesized reset is a session-level protocol violation and is
    /// refused rather than executed.
    is_control_stream: bool,
    pending: &'a mut PendingQueue,
    deferred: &'a mut DeferredEffects,
}

/// Whether a stream direction may keep running after a helper returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Keep forwarding.
    Continue,
    /// The stream is over — reset, terminated or torn down. Return `Ok`.
    StreamOver,
}

// ── Abnormal teardown propagation ───────────────────────────────

/// The egress side paired with an ingress side.
///
/// Forwarding helpers are handed the side bytes arrive on; a teardown
/// observed on the *destination* stream is reported against the side
/// those bytes leave on.
fn egress_side(side: ProxySide) -> ProxySide {
    match side {
        ProxySide::ClientToProxy => ProxySide::ProxyToRelay,
        ProxySide::RelayToProxy => ProxySide::ProxyToClient,
        // Already an egress side — forwarders never pass these in.
        other => other,
    }
}

/// Whether a pipe error is an abnormal teardown the proxy already
/// mirrored and reported as [`ProxyEvent::StreamReset`].
///
/// Callers use this to avoid double-reporting one teardown — notably as a
/// `ParseError`, which means a *codec* failure.
fn is_mirrored_teardown(err: &ProxyError) -> bool {
    matches!(
        err,
        ProxyError::Transport(TransportError::StreamReset(_) | TransportError::Stopped(_))
    )
}

/// Whether the draft defines a stream-reset error code vocabulary.
///
/// Drafts 07-10 do not, so a reset still carries the code but
/// [`Effect::StreamReset`] reports `code_defined: false` — the code is a
/// choice there rather than a claim. `exec` makes the same judgement for
/// the actions it executes; this copy exists because the two callers are
/// in different modules and neither owns the other's privacy.
const fn stream_reset_code_defined(draft: DraftVersion) -> bool {
    !matches!(
        draft,
        DraftVersion::Draft07
            | DraftVersion::Draft08
            | DraftVersion::Draft09
            | DraftVersion::Draft10
    )
}

/// The application error code to reset a forwarded data stream with when
/// the source read failed for a reason that is not a peer `RESET_STREAM`.
///
/// `0x3` (SESSION_CLOSED on drafts 11-19) for a connection-level failure —
/// literally true when the relay dies mid-subgroup, and the code a real
/// publisher would send. `0x0` (INTERNAL_ERROR) for everything else, which
/// is verbatim what a proxy-internal failure is. Deliberately **not**
/// `0x1 CANCELLED`: its text asserts a control-plane event that never
/// happened and points the receiver at a PUBLISH_DONE that will never
/// arrive.
///
/// **The `0x3` arm is unreachable through the QUIC transport today, and
/// that is a defect one level down, not here.**
/// `moqtap-client/src/transport/quic.rs:87-92` maps `quinn::ReadError` with
/// one typed arm — `Reset(code)` — and collapses everything else, including
/// `ReadError::ConnectionLost(_)`, into `TransportError::Read(String)`.
/// Nothing in the workspace ever constructs `TransportError::ConnectionLost`
/// from a real read, so a relay that dies mid-subgroup arrives here as
/// `Read(..)` and is reset with `0x0` rather than `0x3`. The stream is still
/// **reset rather than FINed**, which is the substance of the guarantee —
/// a truncated group never looks complete — and only the code is less
/// specific than it should be. Closing it is one arm
/// in that `From` impl (`ReadError::ConnectionLost(_) =>
/// TransportError::ConnectionLost`), in a crate this one does not own.
fn synthesized_reset_code(err: &ProxyError) -> u64 {
    match err {
        ProxyError::Transport(TransportError::ConnectionLost | TransportError::Connection(_)) => {
            0x3
        }
        _ => 0x0,
    }
}

/// What one poll of the source stream saw.
///
/// The two pipe loops that queue what they read — [`pipe_control_mutating`]
/// and [`pipe_data_framed`] — poll their source through
/// [`observe_source`] rather than calling `recv.read` directly, and this is
/// what it hands back.
enum Source {
    /// `recv.read`'s own result, verbatim: `Ok(Some(n))` bytes into the
    /// caller's buffer, `Ok(None)` a clean FIN, `Err` a failure.
    ///
    /// **A reset seen by the reset-only observer arrives here too**, as
    /// `Err(TransportError::StreamReset(code))` — byte-identical to what
    /// `recv.read` would have produced — so `propagate_reset` mirrors the
    /// same code down the same path and neither pipe loop has to know
    /// which observer was live.
    Read(Result<Option<usize>, TransportError>),
    /// The source can no longer be reset, and the reset-only observer must
    /// not be polled again: it resolves immediately every time (see
    /// [`RecvStream::received_reset`]), so re-polling it spins. The caller
    /// latches it off and the branch parks for the rest of the stream,
    /// which is exactly the disabled read branch this replaced.
    ResetUnobservable,
}

/// Observe the source stream, **whatever the egress queue is doing**.
///
/// # The defect this exists to close
///
/// Both queueing pipe loops gate their read branch on
/// `PendingQueue::accepts_more()`, and that is the backpressure mechanism:
/// when it is false tokio does not evaluate the branch's expression, so
/// `recv.read` is not polled and nothing is consumed. Under
/// `Overflow::Block` a dry bucket holds the queue at `depth_objects`
/// indefinitely, so the gate stays shut for as long as `max_hold` — 30 s in
/// the shipped default posture.
///
/// A peer's `RESET_STREAM` surfaces **only** as `Err` from `recv.read`.
/// With the read branch shut it was therefore not observed at all:
/// `propagate_reset` was unreachable, and the mirrored reset that should
/// follow the peer's within microseconds arrived up to `max_hold` late.
/// The other
/// three branches cannot cover it — `StopWatcher` watches the
/// *destination's* `stopped()`, the release branch watches this proxy's own
/// clock, and `cancel` is session teardown.
///
/// # Why this does not delete `Overflow::Block`
///
/// `can_read` still gates **`recv.read`**, which is the only call that
/// consumes bytes. Nothing about the queue's depth, the admission decision,
/// or the once-per-stream backpressure latch moves. What changes is that
/// the shut state is no longer *silent*: instead of parking on nothing, the
/// loop parks on [`RecvStream::received_reset`], which reads no bytes and
/// therefore grants no `MAX_STREAM_DATA` credit. The peer stays blocked at
/// exactly the same offset it was blocked at before.
///
/// That is the discriminating property, and it is why the fix is not "poll
/// `recv.read` anyway and park the chunk": a look-ahead slot consumes a
/// chunk, and — worse — it only re-opens when the queue drains, so under a
/// dry bucket the *next* reset waits out `max_hold` all the same.
///
/// # Cancel safety
///
/// Every path awaits exactly one future and does nothing before it:
/// `RecvStream::read` and `RecvStream::received_reset` are both
/// cancel-safe, and `pending()` never completes. Dropping this future —
/// which `select!` does on every iteration another branch wins — loses
/// nothing.
async fn observe_source(
    recv: &mut PeekedRecv,
    buf: &mut [u8],
    can_read: bool,
    reset_observable: bool,
) -> Source {
    if can_read {
        return Source::Read(recv.read(buf).await);
    }
    if !reset_observable {
        // Nothing left to watch for on a queue-blocked stream. Park, which
        // is precisely the `if can_read` branch this replaced.
        return std::future::pending().await;
    }
    match recv.received_reset().await {
        // Synthesized into the error `recv.read` would have returned, so
        // the mirrored code is identical whichever observer saw it.
        Ok(Some(code)) => Source::Read(Err(TransportError::StreamReset(code))),
        Ok(None) => Source::ResetUnobservable,
        Err(e) => Source::Read(Err(e)),
    }
}

/// Call `ProxyHook::on_stream_end` and execute what it returns.
///
/// Fires only when the hook declared [`Interest::STREAMS`]. The plan is
/// returned so the caller can honour a queued terminal
/// ([`Action::ResetStream`], the one non-`Pass` action admitted at a data
/// stream's end) or a session close, which is honoured at a control
/// stream's end too, because a close is session-scoped.
fn run_stream_end(
    end: StreamEnd,
    st: &mut StreamState<'_>,
    side: ProxySide,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) -> Plan {
    if !ctx.streams_enabled {
        return Plan::Nothing;
    }
    let draft = ctx.draft();
    let caps = ctx.caps();
    let scx = StreamCtx::new(
        ctx.session_id,
        side,
        st.stream_id,
        draft,
        st.is_control_stream,
        &caps,
        st.key,
    );
    let action = ctx.hook.on_stream_end(&scx, end);
    let unit = exec::Unit {
        target: exec::Target::StreamEnd { is_control_stream: st.is_control_stream },
        draft,
        arrived_at: Instant::now(),
    };
    let mut engine = exec::Engine {
        queue: Some(exec::Queue { pending: st.pending, deferred: st.deferred }),
        closer: &ctx.closer,
    };
    exec::execute(&unit, action, &mut engine, report).plan
}

/// Mirror a source-side read failure onto the destination stream.
///
/// If the source peer sent `RESET_STREAM`, the destination stream must be
/// reset with the *same* application code. Letting the `SendStream` drop
/// instead sends a FIN — quinn's `SendStream::drop` calls `finish()` — so
/// the far end would see an abandoned, truncated stream as one that ended
/// cleanly, and the peer's code would never arrive.
///
/// **Every other read failure now resets the destination too**, with
/// a synthesized code from [`synthesized_reset_code`], reported as
/// `ActionApplied { effect: StreamReset { code, code_defined } }`. Before
/// this the destination was dropped, and quinn's `finish()`-on-drop made a
/// truncated group look complete to the peer.
///
/// **Except on a control stream.** Synthesizing a reset there is a
/// session-level protocol violation on every draft, so the destination
/// still ends with a FIN and the truncation is reported as
/// `Impairment { ControlStreamTruncated }` instead. `ProxySide` does not
/// carry the control/data distinction, so `StreamState` does.
///
/// Anything the hook deferred is drained **ignoring release times before**
/// the reset, which is what keeps "data, then reset" true.
async fn propagate_reset(
    err: &ProxyError,
    send: &mut SendStream,
    st: &mut StreamState<'_>,
    side: ProxySide,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) {
    let mirrored = match err {
        ProxyError::Transport(TransportError::StreamReset(code)) => Some(*code),
        _ => None,
    };
    let end = match mirrored {
        Some(code) => StreamEnd::Reset { code },
        None => StreamEnd::Cancelled,
    };

    // The hook is told the stream ended before anything is torn down, so a
    // refusal it earns is reported against a stream that still exists. A
    // terminal it queues carries its own code and replaces ours; every
    // other plan leaves the peer's code — or the synthesized one — in
    // charge, which is what keeps the mirrored-reset guarantee true for
    // every hook that does not explicitly ask otherwise.
    let plan = run_stream_end(end, st, side, ctx, report);
    if matches!(plan, Plan::Terminal) {
        let _ = st.pending.drain_ignoring_release_times(send).await;
        report_unconfirmed(st, report);
        st.deferred.clear();
        return;
    }

    if let Some(code) = mirrored {
        let _ = st.pending.drain_ignoring_release_times(send).await;
        report_unconfirmed(st, report);
        st.deferred.clear();
        let _ = send.reset(code);
        ctx.emit(|| ProxyEvent::StreamReset { session_id: ctx.session_id, side, code });
        return;
    }

    if st.is_control_stream {
        report.impairment(ImpairmentKind::ControlStreamTruncated { error: err.to_string() });
        return;
    }

    let code = synthesized_reset_code(err);
    let _ = st.pending.drain_ignoring_release_times(send).await;
    report_unconfirmed(st, report);
    st.deferred.clear();
    let _ = send.reset(code);
    report.applied(
        Site::StreamEnd,
        ActionKind::ResetStream,
        Effect::StreamReset { code, code_defined: stream_reset_code_defined(ctx.draft()) },
    );
}

/// Report whatever a teardown drain could not vouch for, once.
///
/// The pairing `ImpairmentKind::QueuedBytesAtTeardown` was always meant to
/// have: a queue that was flushed best-effort into a transport that is
/// going away has delivered nothing it can prove, and reporting only what
/// stayed queued reports zero for exactly the case that loses data. See
/// `PendingQueue::unconfirmed_bytes`.
///
/// Zero, and therefore silent, on every stream that had nothing queued —
/// which is every stream in a session with no timing action.
fn report_unconfirmed(st: &StreamState<'_>, report: &exec::Reporter<'_>) {
    let stranded = st.pending.unconfirmed_bytes();
    if stranded > 0 {
        report.impairment(ImpairmentKind::QueuedBytesAtTeardown {
            stream_id: st.stream_id,
            bytes: stranded,
        });
    }
}

/// Mirror a destination-side write failure onto the source stream.
///
/// If the destination peer sent `STOP_SENDING`, the source stream must be
/// stopped with the *same* application code. Letting the `RecvStream`
/// drop instead emits `STOP_SENDING` with a hard-coded 0 — quinn's
/// `RecvStream::drop` calls `stop(0)` — silently replacing the peer's
/// reason with "unspecified". Any other write failure is left to the
/// default teardown.
///
/// Two triggers reach here, and they are not interchangeable. The first
/// is a failed write: every inline `send.write_all` and the deferred
/// release branch route their error through this function. That trigger
/// alone leaves a source that has gone quiet unstopped indefinitely,
/// because nothing writes to notice. The second is [`StopWatcher`], a
/// `select!` branch over `SendStream::stopped()` that races the read, so
/// an idle stream learns about the peer's decision when the peer makes
/// it rather than when the proxy next produces.
///
/// Nothing queued can be delivered once the destination has stopped us, so
/// the queue is reported and cleared rather than drained.
fn propagate_stop(
    err: &ProxyError,
    recv: &mut PeekedRecv,
    st: &mut StreamState<'_>,
    side: ProxySide,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) {
    if let ProxyError::Transport(TransportError::Stopped(code)) = *err {
        let _ = recv.stop(code);
        let reported_side = egress_side(side);
        ctx.emit(|| ProxyEvent::StreamReset {
            session_id: ctx.session_id,
            side: reported_side,
            code,
        });
        let _ = run_stream_end(StreamEnd::Stopped { code }, st, side, ctx, report);
        // Measured, then abandoned, then reported — in that order. The
        // figure has to be read before the queue is cleared and the event
        // has to follow the clearing, because it says these bytes are gone;
        // between the two lines it is still true that they might yet be
        // written by something else on the way out.
        let stranded = st.pending.queued_bytes();
        st.pending.clear();
        st.deferred.clear();
        if stranded > 0 {
            report.impairment(ImpairmentKind::QueuedBytesAtTeardown {
                stream_id: st.stream_id,
                bytes: stranded,
            });
        }
    }
}

/// A boxed `SendStream::stopped()` future.
///
/// Boxed because `stopped()` returns an opaque `impl Future` that cannot be
/// named, and [`StopWatcher`] has to *store* one across `select!`
/// iterations rather than rebuild it. One allocation per forwarded stream.
type StoppedFuture = Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send>>;

/// A destination-side `STOP_SENDING` watcher, hoisted once per forwarded
/// stream and used as a fourth `tokio::select!` branch.
///
/// # Why it is hoisted
///
/// `tokio::select!` drops and rebuilds every branch future each time round
/// the loop. Rebuilding `SendStream::stopped()` takes quinn's connection
/// state lock and inserts into a per-connection map
/// (`quinn-0.11.9/src/send_stream.rs:258-263`), which is per-*wake* work on
/// loops documented as doing none. So the future is built once, lives here
/// across iterations, and [`Self::watch`] *borrows* it rather than moving
/// it — a `select!` iteration that cancels this branch therefore loses
/// nothing and resumes the same future next time round.
///
/// # Why it is fused
///
/// Building it once means it can only resolve once: polling a completed
/// future panics with "`async fn` resumed after completion". [`Self::watch`]
/// clears the slot the instant the future returns, which both disables the
/// branch (through [`Self::is_watching`]) and makes a re-poll structurally
/// unreachable. The fuse is not belt and braces — without it the very next
/// `select!` iteration panics inside the forwarding task.
///
/// [`Self::armed`] is what keeps the fuse one-way: a retired watcher has an
/// empty slot, and without the flag the next [`Self::arm`] would rebuild it.
///
/// # Cost
///
/// One `Box::pin` per forwarded stream, allocated at the first `select!`
/// iteration and never again. Per stream, never per object.
struct StopWatcher {
    /// The hoisted `stopped()` future. `None` before [`Self::arm`], and
    /// again once it has resolved or [`Self::retire`] was called.
    watching: Option<StoppedFuture>,
    /// Set by the first [`Self::arm`], so a retired watcher stays retired.
    armed: bool,
}

impl StopWatcher {
    /// An unarmed watcher. Allocates nothing.
    fn new() -> Self {
        Self { watching: None, armed: false }
    }

    /// Build the watcher over `send`, once.
    /// Called from the top of each pipe's loop rather than before it, so
    /// `pipe_data_passthrough` — whose contract is *a stack buffer and a write*
    /// — allocates on its first `select!` iteration and not at function entry.
    /// Idempotent: a second call is a no-op, and a call after [`Self::retire`]
    /// does *not* re-arm.
    fn arm(&mut self, send: &SendStream) {
        if !self.armed {
            self.armed = true;
            self.watching = Some(Box::pin(send.stopped()));
        }
    }

    /// Build a watcher over an arbitrary future.
    ///
    /// The fuse is a property of [`Self::watch`], not of quinn. A real
    /// `SendStream::stopped()` cannot be made to resolve on demand, and —
    /// this being the whole point — cannot be made to resolve twice, so
    /// the claim is proven against a future this crate controls.
    #[cfg(test)]
    fn watching_over(
        fut: impl Future<Output = Result<(), TransportError>> + Send + 'static,
    ) -> Self {
        Self { watching: Some(Box::pin(fut)), armed: true }
    }

    /// Whether the `select!` branch should be enabled this iteration.
    fn is_watching(&self) -> bool {
        self.watching.is_some()
    }

    /// Drop the watcher without polling it again.
    ///
    /// Called before every local `send.reset`: quinn keeps no
    /// stopped-notification for a stream it has locally reset, so a
    /// watcher held across a reset stays pending until the connection ends
    /// (see `SendStream::stopped`'s own docs). Every reset site returns
    /// from its pipe immediately afterwards, so this is about saying what
    /// the code means as much as about the residue.
    fn retire(&mut self) {
        self.watching = None;
    }

    /// Resolve when the destination stops being useful — then never again.
    ///
    /// Stays pending forever once retired, so an enabled-but-retired
    /// branch cannot spin; the `if` guard is the fast path and this is the
    /// backstop.
    ///
    /// Cancellation-safe: the fuse below is reached only on completion, so
    /// a `select!` iteration that drops this future mid-poll leaves the
    /// hoisted future exactly where it was.
    async fn watch(&mut self) -> Result<(), TransportError> {
        let Some(fut) = self.watching.as_mut() else {
            return std::future::pending().await;
        };
        let outcome = fut.as_mut().await;
        // THE FUSE.
        self.watching = None;
        outcome
    }
}

/// The one [`StopWatcher`] outcome that ends a stream.
///
/// Only an explicit peer `STOP_SENDING` is terminal. `Ok(())` cannot fire
/// on a live stream — quinn reports it only once the send state is gone —
/// and treating it as end-of-stream would race the FIN path's own
/// `send.finish()`. A lost connection is already the read side's business
/// and every pipe already has a teardown for it. Everything that is not a
/// `STOP_SENDING` therefore retires the watcher and the loop carries on
/// byte-for-byte as before.
///
/// This is what makes the watcher safe on a **control** stream, where an
/// idle stream is MoQT's normal steady state: idleness never resolves
/// `stopped()`, and no outcome except the peer's own decision can tear a
/// healthy session down.
fn stop_error(outcome: Result<(), TransportError>) -> Option<ProxyError> {
    match outcome {
        Err(e @ TransportError::Stopped(_)) => Some(ProxyError::Transport(e)),
        _ => None,
    }
}

/// The label [`ProxyEvent::Shaped`] reports a class under.
///
/// An empty string for [`Class::Default`] and [`Class::Unshapeable`],
/// matching
/// [`ShapeStats::default_class`](crate::shape::ShapeStats::default_class)
/// and [`ShapeStats::unshapeable`](crate::shape::ShapeStats::unshapeable),
/// whose rows are unnamed for the same reason: a user-written class name is
/// unique by `ShapeError::DuplicateClassName`, so an empty label cannot
/// collide with one and "no rule claimed it" needs no invented name.
///
/// Allocates one `String`, and is called only from an event that is capped
/// at once per stream per outcome — never per unit.
fn class_label(shaper: &Scheduler, class: Class) -> String {
    match class {
        Class::Rule(index) => shaper.class_name(index),
        Class::Default | Class::Unshapeable => String::new(),
    }
}

/// Flush anything the hook deferred, honouring its release times, as a
/// race against session cancellation.
///
/// The drain sits inside a `select!` arm body, which is not preemptible, so
/// writing it as a plain loop would let a `Hold` on a gate nobody releases
/// pin session teardown for up to `EgressConfig::max_hold`.
///
/// # `shaped`, and why it is a parameter rather than a `None`
///
/// This is the **FIN path**, and on the framed pipe the FIN path is the
/// ordinary MoQT subgroup shape: header, a handful of objects, FIN. Every
/// unit still queued when the source finishes is released by the drain
/// below, which means every clamp and every expiry those units earn is
/// decided there — so `shaped` is what turns those decisions into
/// `HoldClamped` and `Shaped { Expired }` instead of into nothing. It was
/// `None`-by-omission once, and the whole profile applied
/// itself to the normal case in silence; `shaping_reports_do_not_depend_on_a_fin`
/// is the gate.
///
/// `None` at the four callers that cannot produce a report: both control
/// pipes install no scheduler, `pipe_data_passthrough` installs no
/// scheduler, and `write_in_order` is reachable only behind
/// `pipe_data_framed`'s `shape.is_some()` guard taking the other branch.
async fn drain_pending(
    send: &mut SendStream,
    st: &mut StreamState<'_>,
    site: Site,
    shaped: Option<&ShapedStream>,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) -> Result<Flow, ProxyError> {
    if st.pending.is_empty() {
        return Ok(Flow::Continue);
    }
    let outcome = egress::drain_honouring_release_times(st.pending, send, &ctx.cancel, |outcome| {
        report_shaping(Some(outcome), shaped, ctx, report);
    })
    .await?;
    match outcome {
        DrainOutcome::Complete => {
            for owed in st.deferred.take_all() {
                report.applied_deferred(site, owed);
            }
            Ok(Flow::Continue)
        }
        DrainOutcome::Terminated { .. } => {
            st.pending.clear();
            st.deferred.clear();
            Ok(Flow::StreamOver)
        }
        DrainOutcome::CancelledMidDrain | DrainOutcome::WriteFailed | DrainOutcome::Discarded => {
            st.deferred.clear();
            // `unconfirmed_bytes`, not `queued_bytes`: the cancel fallback
            // may have handed everything to a transport `run_with_transport`
            // is closing, in which case nothing is left queued and nothing
            // reached the peer. See `PendingQueue::unconfirmed_bytes`.
            //
            // On `Discarded` the two are equal and both are exact: the
            // fallback wrote nothing, so nothing was handed anywhere and
            // the figure below is precisely what was abandoned.
            let stranded = st.pending.unconfirmed_bytes();
            if stranded > 0 {
                report.impairment(ImpairmentKind::QueuedBytesAtTeardown {
                    stream_id: st.stream_id,
                    bytes: stranded,
                });
            }
            Ok(Flow::StreamOver)
        }
    }
}

/// Write bytes the hook was never shown, keeping wire order — on an
/// **unshaped** stream.
///
/// `session.rs` cannot enqueue on its own — `DeferredEffects`'s push is
/// `exec`'s, so the ledger and the deque can only move together — so when
/// something is already waiting the queue is drained at its release times
/// first. The three callers are a stream header, an oversized object's
/// passthrough chunk and a bypassed stream's bytes: none is addressable,
/// and none may be reordered against an object the hook did defer.
///
/// On an empty queue — every session with no timing action, which is every
/// `Interest::NONE` session — this is one `is_empty()` and the same
/// `send.write_all(&raw).await` the byte pump does.
///
/// A **shaped** stream calls [`exec::enqueue_unshown`] instead, and must:
/// this function would let these bytes escape the pacer, and the drain it
/// runs first honours release times, so on a paced queue it would block the
/// read arm for as long as the bucket took, inside a `select!` arm body that
/// polls no other branch.
async fn write_in_order(
    raw: &[u8],
    send: &mut SendStream,
    st: &mut StreamState<'_>,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) -> Result<Flow, ProxyError> {
    // `None`: `pipe_data_framed` routes every shaped stream to
    // `exec::enqueue_unshown` before it can reach here, so this queue has no
    // scheduler and no shaping decision to report.
    if drain_pending(send, st, Site::Object, None, ctx, report).await? == Flow::StreamOver {
        return Ok(Flow::StreamOver);
    }
    send.write_all(raw).await?;
    Ok(Flow::Continue)
}

/// Forward the control stream on the drafts whose control stream is the
/// first client-initiated bidirectional stream — drafts 07 through 16.
///
/// Drafts 17 and later do not reach this function at all: they put the
/// control plane on a pair of unidirectional streams and use bidirectional
/// streams for requests, so their two control directions are picked out of
/// the unidirectional accept loop by [`classify_uni_stream`] and their
/// bidirectional streams are forwarded by [`forward_request_streams`]. See
/// [`control_plane_is_unidirectional`] for which drafts those are and what
/// the drafts say.
///
/// Draft-16 reaches it *and* has request streams. The first bidirectional
/// stream this function accepts is its control stream, and every one after it
/// is a request stream taken by
/// [`request_streams_beside_the_control_stream`], which runs as a branch of
/// the `select!` at the end rather than as a task of its own — see there for
/// why the ordering has to be settled by the code.
///
/// `client_leg` and `upstream_leg` are the two request channels the control
/// plane reaches this session's control stream through, and the mapping
/// between them and the two pipes is a half-turn worth stating: a message
/// the **client** is meant to decode is written by the pipe that forwards
/// *from* the relay, because that is the pipe holding the client-facing
/// write half. The registry gets the same senders under the two direction
/// keys, so a `reset_stream` naming either control direction reaches the
/// same task an injection would.
async fn forward_control_stream(
    client: &Transport,
    relay: &Transport,
    ctx: &ForwardCtx,
    client_leg: ControlLeg,
    upstream_leg: ControlLeg,
) -> Result<(), ProxyError> {
    debug_assert!(
        !control_plane_is_unidirectional(ctx.draft.initial),
        "a draft whose control plane is a pair of unidirectional streams must not have its \
         first bidirectional stream forwarded as the control stream",
    );

    // Accept bi from client
    let (client_send, client_recv) = client.accept_bi().await?;
    // From here the session has somewhere a SETUP can arrive, so a task
    // that needs the draft has something to wait for. Recorded before the
    // relay leg is opened, because the client's CLIENT_SETUP is the message
    // that names the draft and it is already on its way.
    ctx.draft.note_control_stream();
    ctx.emit(|| ProxyEvent::BiStreamOpened {
        session_id: ctx.session_id,
        side: ProxySide::ClientToProxy,
    });

    // Open bi to relay
    let (relay_send, relay_recv) = relay.open_bi().await?;
    ctx.emit(|| ProxyEvent::BiStreamOpened {
        session_id: ctx.session_id,
        side: ProxySide::ProxyToRelay,
    });

    // Pipe client→relay and relay→client concurrently
    let ctx1 = ForwardCtx { ..ctx.clone() };
    let ctx2 = ForwardCtx { ..ctx.clone() };

    // The control stream's two directions are two forwarded streams, so
    // they take two keys — the same rule every uni stream takes.
    let client_key = ctx1.mint_key(ProxySide::ClientToProxy);
    let relay_key = ctx2.mint_key(ProxySide::RelayToProxy);

    // Registered like every other forwarded stream, so "live" means the
    // same thing for all of them. A hook can learn a control direction's
    // key at `Site::StreamEnd`, and a `SerializeAfter` naming a *live*
    // control direction must wait rather than be told it does not exist.
    // The client-to-proxy pipe writes toward the relay, so it serves the
    // upstream leg's requests; the relay-to-proxy pipe writes toward the
    // client and serves the client leg's.
    let ControlLeg { inbox: client_inbox, requests: client_requests } = client_leg;
    let ControlLeg { inbox: upstream_inbox, requests: upstream_requests } = upstream_leg;
    let client_guard = ctx.streams.register(client_key, upstream_inbox);
    let relay_guard = ctx.streams.register(relay_key, client_inbox);

    let client_to_relay = tokio::spawn(async move {
        let _guard = client_guard;
        pipe_control(
            PeekedRecv::new(client_recv),
            relay_send,
            ProxySide::ClientToProxy,
            client_key,
            upstream_requests,
            &ctx1,
        )
        .await
    });

    let relay_to_client = tokio::spawn(async move {
        let _guard = relay_guard;
        pipe_control(
            PeekedRecv::new(relay_recv),
            client_send,
            ProxySide::RelayToProxy,
            relay_key,
            client_requests,
            &ctx2,
        )
        .await
    });

    tokio::select! {
        r = client_to_relay => r.map_err(|e| ProxyError::SessionClosed(e.to_string()))?,
        r = relay_to_client => r.map_err(|e| ProxyError::SessionClosed(e.to_string()))?,
        r = request_streams_beside_the_control_stream(client, relay, ctx) => r,
        _ = ctx.cancel.cancelled() => Ok(()),
    }
}

/// The client-to-relay request-stream loop, for a draft whose control stream
/// is bidirectional and which has request streams as well — draft-16 alone.
/// See [`bidi_streams_carry_requests`].
///
/// # Why it is a branch of the control stream's `select!` and not a task
///
/// Because both take bidirectional streams off the same transport, and only one
/// accept may be outstanding if *the first one is the control stream* is to
/// mean anything. Running here, the loop starts after
/// [`forward_control_stream`] has already taken the control stream, so the
/// order is fixed by the code rather than by which task the runtime polled
/// first. A separate task racing the same `accept_bi` would forward the control
/// stream as a request stream on whichever runs of whichever build happened to
/// lose.
///
/// The relay-to-client direction has no such constraint — nothing else
/// accepts a relay-initiated bidirectional stream — so it is spawned as an
/// ordinary loop beside this function's caller.
///
/// On every other draft this never completes, which leaves the `select!`
/// above decided by the two control pipes exactly as it was before draft-16
/// had anywhere else to put a request.
async fn request_streams_beside_the_control_stream(
    client: &Transport,
    relay: &Transport,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    if !bidi_streams_carry_requests(ctx.draft.initial) {
        std::future::pending::<()>().await;
    }
    forward_request_streams(client, relay, ProxySide::ClientToProxy, ctx).await
}

/// Whether this draft carries control messages on a **pair of
/// unidirectional streams**, making a bidirectional stream a *request*
/// stream rather than the control stream.
///
/// True on drafts 17, 18 and 19; false on 07 through 16.
///
/// # What the drafts say
///
/// Draft-16 Section 3.3 (Session initialization): "The first stream opened
/// is a client-initiated bidirectional control stream where the endpoints
/// exchange Setup messages (Section 9.3), followed by other messages defined
/// in Section 9." One stream, opened by the client, carrying both directions.
///
/// Draft-17 Section 3.3, and identically draft-18 and draft-19 Section 3.3:
/// "MOQT uses a pair of unidirectional streams for creating the session and
/// exchanging control messages. Each peer opens one control stream beginning
/// with a SETUP message. Using a pair of unidirectional streams rather than
/// a single bidirectional stream allows either peer to send data as soon as
/// it is able." The same section then says what the bidirectional streams
/// are for: "In addition to the control streams, this specification uses
/// bidirectional streams to carry requests. A request stream begins with one
/// of these six message types: TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH,
/// PUBLISH_NAMESPACE, and SUBSCRIBE_NAMESPACE" — seven from draft-18, which
/// adds SUBSCRIBE_TRACKS.
///
/// So on 17-19 each direction of the control plane is a separate stream,
/// opened by the peer that writes on it: the client's control stream carries
/// client-to-relay control messages and the relay's carries the other
/// direction. Neither is closed for the session's lifetime.
///
/// # How a control stream is told apart from a data stream
///
/// By its first varint. Draft-17 Section 3.4 (Unidirectional Stream Types):
/// "All unidirectional MOQT streams start with a variable-length integer
/// indicating the type of the stream", and the table gives 0x05 for
/// FETCH_HEADER, 0x10-0x1D for SUBGROUP_HEADER and **0x2F00 for SETUP**.
/// Draft-18 and draft-19 keep the same table and add PADDING (0x132B3E28).
/// That 0x2F00 is also the SETUP *message* type (draft-17 Section 9.4), so
/// the control stream's type varint is the first field of its first message
/// and nothing has to be stripped before forwarding: see
/// [`CONTROL_STREAM_TYPE`].
const fn control_plane_is_unidirectional(draft: DraftVersion) -> bool {
    matches!(draft, DraftVersion::Draft17 | DraftVersion::Draft18 | DraftVersion::Draft19)
}

/// Whether this draft puts **requests** on bidirectional streams of their
/// own, so that a bidirectional stream beyond the control stream is a stream
/// this proxy has to forward.
///
/// True on drafts 16 through 19; false on 07 through 15.
///
/// # Why this is not [`control_plane_is_unidirectional`]
///
/// Because draft-16 answers the two questions differently, and it is the only
/// draft that does. Its control plane is one client-initiated bidirectional
/// stream, exactly as on 07 through 15. Draft-16 Section 3.3: "The first
/// stream opened is a client-initiated bidirectional control stream where the
/// endpoints exchange Setup messages (Section 9.3), followed by other
/// messages defined in Section 9."
/// The same section then adds a second use: "This specification only specifies
/// two uses of bidirectional streams, the control stream, which begins with
/// CLIENT_SETUP, and SUBSCRIBE_NAMESPACE. Bidirectional streams MUST NOT begin
/// with any other message type unless negotiated."
///
/// Draft-16 Section 6.1 says who opens one: "The subscriber sends
/// SUBSCRIBE_NAMESPACE on a new bidirectional stream and the publisher MUST
/// send a single
/// REQUEST_OK or REQUEST_ERROR as the first message on the bidirectional
/// stream in response". Either endpoint of a session can be that subscriber,
/// so the streams arrive in both directions and each direction needs an accept
/// loop of its own.
///
/// Drafts 07 through 15 have no second use to forward: none of them puts any
/// message on a bidirectional stream other than the control stream. Drafts 17
/// through 19 moved the control plane off bidirectional streams entirely, so
/// there every bidirectional stream is a request stream and the first one is
/// no different from the rest.
///
/// # Why the initial draft is enough to decide it
///
/// Because this question is asked before any SETUP has been read, and the
/// answer cannot change once it is. Draft-16 has an ALPN of its own, so a
/// session that begins as draft-16 is draft-16; the one cohort where the
/// initial draft is a guess refined by the SETUP peek is `moq-00`, which
/// spans drafts 07 to 14 and answers `false` for every member. There is no
/// refinement that could turn this answer over.
///
/// # What the proxy does with one
///
/// Forwards it, and nothing more. Draft-16 withdraws a namespace subscription
/// by ending its stream. Draft-16 Section 6.1: "A SUBSCRIBE_NAMESPACE can be
/// cancelled by closing the stream with either a FIN or RESET_STREAM" — both
/// are already mirrored onto the far side by the pipes, because they are what
/// a forwarded stream ending looks like. Which of the two arrived is the
/// endpoints' business; this proxy holds neither end's request state and must
/// not start reading a cancellation into one.
const fn bidi_streams_carry_requests(draft: DraftVersion) -> bool {
    matches!(
        draft,
        DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
    )
}

/// The unidirectional stream type that marks a control stream on the drafts
/// [`control_plane_is_unidirectional`] names, and the SETUP message type on
/// the same drafts. They are one number, 0x2F00.
///
/// A control stream therefore starts with the first field of a SETUP message
/// and carries no separate stream header, which is why a control stream can
/// be forwarded byte for byte onto a fresh unidirectional stream: the type
/// varint the classifier read is the type varint the peer needs to read.
///
/// Encoded with the varint the draft uses — from draft-17 that is MoQT's
/// leading-ones form, in which 0x2F00 is the two bytes `AF 00` — so the
/// classifier decodes through [`DraftVersion`] rather than assuming a width.
const CONTROL_STREAM_TYPE: u64 = 0x2F00;

/// The most bytes a unidirectional stream's type varint can occupy: nine,
/// which is MoQT's widest form from draft-17 (RFC 9000's is eight).
const MAX_UNI_TYPE_LEN: usize = 9;

/// What a unidirectional stream's leading varint says the stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniStreamKind {
    /// One direction of the control plane: [`CONTROL_STREAM_TYPE`].
    Control,
    /// Anything else — a subgroup or fetch header, padding, or a type this
    /// crate does not know. All of them are forwarded as data.
    Data,
}

/// Read a unidirectional stream's type varint and say what the stream is.
///
/// The bytes it reads are handed back inside the returned [`PeekedRecv`], so
/// the pipe that takes the stream sees them exactly as if they had never
/// been taken off it. Nothing is stripped: on these drafts the type varint
/// *is* the SETUP message's type field.
///
/// # It reads, so it can block — which is why it runs per stream
///
/// A stream that is opened and then stays silent produces no varint, and
/// this waits for one. That is why the call site is inside the per-stream
/// task rather than in the accept loop: a peer that opens a stream and
/// writes nothing must not stop the session accepting the *next* one.
///
/// # A stream that ends or fails before its type arrives is data
///
/// Not because it is one, but because there is nothing left to decide with
/// and the pipe is the honest place to surface the end: it sees the same EOF
/// or the same reset one read later and reports it the way it reports every
/// other one. Answering `Control` on no evidence would hand the session's
/// injection channel to a stream that carried nothing.
async fn classify_uni_stream(
    mut recv: RecvStream,
    draft: DraftVersion,
) -> (PeekedRecv, UniStreamKind) {
    let mut head: Vec<u8> = Vec::new();
    let mut buf = [0u8; MAX_UNI_TYPE_LEN];
    let kind = loop {
        // One byte is enough to learn the varint's width, and the width is
        // enough to know when to stop reading.
        let want = head.first().map_or(1, |&first| draft.varint_len(first)).min(MAX_UNI_TYPE_LEN);
        if head.len() >= want {
            let mut cursor = &head[..want];
            break match draft.decode_varint(&mut cursor) {
                Ok(v) if v.into_inner() == CONTROL_STREAM_TYPE => UniStreamKind::Control,
                _ => UniStreamKind::Data,
            };
        }
        match recv.read(&mut buf[..want - head.len()]).await {
            Ok(Some(n)) if n > 0 => head.extend_from_slice(&buf[..n]),
            _ => break UniStreamKind::Data,
        }
    };
    (PeekedRecv::with_prefix(recv, Bytes::from(head)), kind)
}

/// A receive stream with bytes already taken off it.
///
/// Nothing says what a unidirectional stream is for until its first varint
/// has been read, and reading it consumes it. The classifier hands those
/// bytes back here, and the pipe that takes the stream reads them first and
/// the transport afterwards, so a stream that was classified is
/// indistinguishable from one that was not.
///
/// On drafts whose streams are never classified the prefix is empty and this
/// is a [`RecvStream`] with one extra branch on the read path.
struct PeekedRecv {
    inner: RecvStream,
    /// Bytes taken off `inner` before it was handed over, not yet handed to
    /// a reader.
    prefix: Bytes,
}

impl PeekedRecv {
    /// A stream nothing has been read from.
    fn new(inner: RecvStream) -> Self {
        Self { inner, prefix: Bytes::new() }
    }

    /// A stream `prefix` was read from, to be replayed before the rest.
    fn with_prefix(inner: RecvStream, prefix: Bytes) -> Self {
        Self { inner, prefix }
    }

    /// See [`RecvStream::stream_id`].
    fn stream_id(&self) -> u64 {
        self.inner.stream_id()
    }

    /// See [`RecvStream::read`], with the replayed prefix ahead of it.
    ///
    /// Cancel-safe for the same reason `RecvStream::read` is, and the prefix
    /// branch adds nothing to worry about: it awaits nothing, so it either
    /// runs to completion on its first poll or is never entered at all.
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[..n]);
            let _ = self.prefix.split_to(n);
            return Ok(Some(n));
        }
        self.inner.read(buf).await
    }

    /// See [`RecvStream::received_reset`].
    ///
    /// Not affected by the prefix: a peer's `RESET_STREAM` is about the
    /// stream, and bytes already taken off it were taken before it was sent.
    async fn received_reset(&mut self) -> Result<Option<u64>, TransportError> {
        self.inner.received_reset().await
    }

    /// See [`RecvStream::stop`]. The unread prefix goes with everything else
    /// that was in flight.
    fn stop(&mut self, code: u64) -> Result<(), TransportError> {
        self.prefix = Bytes::new();
        self.inner.stop(code)
    }
}

/// The ingress side of the other direction of the same stream.
///
/// A bidirectional stream is forwarded by two pipes, and the second one
/// carries bytes the other way. `ClientToProxy` and `RelayToProxy` are the
/// two ingress sides; this is the turn between them.
fn paired_ingress_side(side: ProxySide) -> ProxySide {
    match side {
        ProxySide::ClientToProxy => ProxySide::RelayToProxy,
        ProxySide::RelayToProxy => ProxySide::ClientToProxy,
        // Egress sides; forwarders never pass these in.
        other => other,
    }
}

/// Forward bidirectional **request** streams, on the drafts where that is
/// what a bidirectional stream is — see [`control_plane_is_unidirectional`].
///
/// One accept loop per direction, because on these drafts either endpoint
/// opens request streams: a subscriber opens one to SUBSCRIBE and a
/// publisher opens one to PUBLISH, so a proxy that only accepted the
/// client's would drop every request the relay ever made. Each accepted
/// stream is paired with one opened on the far side and forwarded by two
/// pipes, one per direction.
///
/// # Why the control pipe and not the data pipe
///
/// Because a request stream carries the same framing the control stream does.
/// Draft-17 Section 9 (draft-18 and draft-19 Section 10): "Every message on a
/// control or request stream is formatted as follows", and the figure beneath
/// it gives Message Type, Message Length and Message Payload. So the messages
/// on a request stream are decodable, and a hook that asked for
/// [`Interest::CONTROL`] is shown them at [`Site::Control`] exactly as it is
/// shown the control stream's. Handing them to the object framer instead would
/// produce a bypass and a stream of nothing.
///
/// # What an injection cannot reach
///
/// This registers each direction under a fresh per-stream channel, which is
/// the one the registry hands a `reset_stream` to. The two channels an
/// injection is routed to belong to the session's control legs and go to the
/// two unidirectional control streams, so a request stream's pipe can never
/// be handed an `Inject` — which is the whole point of separating them.
///
/// # One conservatism, stated
///
/// Both pipes run with the control stream's end-of-stream rules, under which
/// a hook's `ResetStream` is refused as a session-level protocol violation.
/// On a request stream that is stricter than the draft: draft-17 Section
/// 3.3.1 says a request MAY be cancelled by either endpoint and that
/// implementations SHOULD do it by resetting the stream. Refusing is the
/// conservative direction — nothing is destroyed that the draft would have
/// kept — and it is what this crate's published capability table says
/// happens, so it is left alone here rather than changed silently.
async fn forward_request_streams(
    source: &Transport,
    dest: &Transport,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    debug_assert!(
        bidi_streams_carry_requests(ctx.draft.initial),
        "a draft that puts no message on a bidirectional stream beyond the control stream has \
         no request stream to forward",
    );
    loop {
        // No cancellation branch, which is deliberate and is the shape
        // `forward_control_stream` has always had: this loop is ended by the
        // session aborting it, and by `accept_bi` failing when the
        // connection goes, not by returning on its own.
        //
        // Measured rather than assumed. An earlier version raced this accept
        // against `ctx.cancel`, and returning first on cancellation moved
        // `run_with_transport` past `tasks.shutdown()` and into
        // `client.close()` / `relay.close()` before the *per-stream* tasks
        // had run their own teardown drains — the drain in
        // `pipe_data_framed`'s cancel branch that writes what a hook was
        // holding and fires a queued terminal. On a current-thread runtime
        // that reordering is deterministic, and
        // `actions_timing::cancelling_while_an_object_is_held_tears_down_promptly`
        // failed on it every run: no `RESET_STREAM` at the relay within a
        // second, the connection closing out from under the drain instead.
        // A task the session has to abort is a task whose abort yields, and
        // the drains get their turn.
        let (source_send, source_recv) = source.accept_bi().await?;
        ctx.emit(|| ProxyEvent::BiStreamOpened { session_id: ctx.session_id, side });

        let (dest_send, dest_recv) = dest.open_bi().await?;
        ctx.emit(|| ProxyEvent::BiStreamOpened {
            session_id: ctx.session_id,
            side: egress_side(side),
        });

        // Two directions, two keys, two registrations — the rule every
        // forwarded stream takes, and the one `forward_control_stream`
        // takes for the control stream's two directions.
        let back_side = paired_ingress_side(side);
        let forward_key = ctx.mint_key(side);
        let back_key = ctx.mint_key(back_side);
        let (forward_inbox, forward_requests) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let (back_inbox, back_requests) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let forward_guard = ctx.streams.register(forward_key, forward_inbox);
        let back_guard = ctx.streams.register(back_key, back_inbox);

        let forward_ctx = ctx.clone();
        tokio::spawn(async move {
            let _guard = forward_guard;
            let result = pipe_control(
                PeekedRecv::new(source_recv),
                dest_send,
                side,
                forward_key,
                forward_requests,
                &forward_ctx,
            )
            .await;
            report_request_stream_end(result, side, &forward_ctx);
        });

        let back_ctx = ctx.clone();
        tokio::spawn(async move {
            let _guard = back_guard;
            let result = pipe_control(
                PeekedRecv::new(dest_recv),
                source_send,
                back_side,
                back_key,
                back_requests,
                &back_ctx,
            )
            .await;
            report_request_stream_end(result, back_side, &back_ctx);
        });
    }
}

/// Report a request-stream pipe that ended badly, on the same terms
/// [`forward_uni_streams`] reports one.
///
/// An abnormal teardown is an ordinary protocol event: it was already
/// mirrored onto the far side and already reported as
/// [`ProxyEvent::StreamReset`], and repeating it as a `ParseError` would
/// claim the codec failed on bytes that were forwarded.
fn report_request_stream_end(result: Result<(), ProxyError>, side: ProxySide, ctx: &ForwardCtx) {
    if let Err(e) = result {
        if !is_mirrored_teardown(&e) {
            ctx.emit(|| ProxyEvent::ParseError {
                session_id: ctx.session_id,
                side,
                error: format!("request stream pipe: {e}"),
            });
        }
    }
}

/// Hand one control leg's requests to the stream that turned out to be that
/// direction's control stream.
///
/// The leg's channel exists from the moment the session registers, which is
/// before any stream has arrived, so an injection can be accepted for a
/// session whose control stream has not been established yet — that is the
/// promise [`crate::control::ProxyControl::inject_control`] makes. On the
/// drafts where the control stream is picked out of the unidirectional
/// accept loop, the task that will serve it is not known until its first
/// varint has been read, so the leg is pumped into that stream's own inbox
/// once it is: the same inbox the registry hands a `reset_stream` to, so one
/// task serves both verbs and they stay in the order they were asked for.
///
/// The returned guard ends the pump when the stream's task ends. A request
/// still in the leg's channel at that point stays there and is discarded
/// with the session, which is the outcome `inject_control` documents for
/// every message it accepts and cannot place.
fn pump_control_leg(leg: ControlLeg, inbox: mpsc::Sender<StreamCommand>) -> AbortOnDrop {
    let ControlLeg { inbox: _leg_inbox, mut requests } = leg;
    AbortOnDrop::new(tokio::spawn(async move {
        while let Some(command) = requests.recv().await {
            if inbox.send(command).await.is_err() {
                return;
            }
        }
    }))
}

/// The largest control-message header this crate can meet: an eight-byte
/// type varint followed by an eight-byte length varint.
const MAX_CONTROL_HEADER: usize = 16;

/// A declared control-message payload length above which
/// [`ControlFrameWalker`] stops believing what it is reading.
///
/// Not a protocol limit and not enforced on anything — the bytes are
/// forwarded either way. It is a sanity bound on the walker's *own*
/// arithmetic: drafts 11 and later cap a control payload at 65535 by
/// framing it in sixteen bits, and drafts 07-10 frame it as a varint that
/// can say 2^62 but never does. A length that large is not a large message,
/// it is a length field read at the wrong offset — most likely because the
/// session's draft guess is wrong for the moq-00 cohort, where the framing
/// style changed at draft 11.
///
/// Without the bound the walker would count down through that number for
/// the rest of the session, hold every injection, and claim at teardown
/// that a message was half-written. With it, the walker says it does not
/// know where the boundaries are, which is the truth and which suppresses
/// both.
const MAX_CONTROL_PAYLOAD: usize = 1024 * 1024;

/// Where the message boundaries are on a control stream being forwarded
/// verbatim.
///
/// A control stream is one framed byte sequence — type, length, payload,
/// repeated — and a byte injected into the middle of a payload is read by
/// the peer as part of that payload, leaving its decoder wrong about every
/// message after it. So an injection has to be placed *between* messages,
/// and on the pass-through pipe nothing else knows where that is: that pipe
/// forwards whatever `recv.read` returned, and read boundaries are not
/// message boundaries.
///
/// This walks the framing without decoding anything. It reads a type
/// varint's length from its first byte, reads the payload length, and then
/// counts payload bytes down to zero — one varint decode per message and no
/// per-byte work beyond the header. It allocates nothing and never holds a
/// message; the bytes go straight out as they always did.
///
/// # Why not the control parser
///
/// [`ControlStreamParser`] already knows this framing and is already built
/// on the pipes that observe or mutate. It also buffers each message whole
/// and decodes it into an `AnyControlMessage`, which is the cost the
/// pass-through pipe exists not to pay — and on an `Interest::NONE` session
/// with no observer it is not built at all, so a stream that has never been
/// parsed has no idea where it stands.
///
/// # It is only as right as the draft it was given
///
/// The framing changed at draft 11: earlier drafts write the payload length
/// as a QUIC varint, later ones as a fixed 16-bit big-endian field. This
/// walker is built from the session's current draft, which for the moq-00
/// cohort (drafts 07-14) is a configured guess until a SETUP is peeked. A
/// wrong guess makes the lengths wrong and the boundaries wrong with them.
/// It is the same exposure the object framer already documents for the same
/// cohort, and it fails the same way: [`Self::at_boundary`] latches to
/// `false` as soon as a header cannot be made sense of, so an injection on
/// a stream whose framing has been lost is held rather than written into
/// the middle of something.
struct ControlFrameWalker {
    draft: DraftVersion,
    /// Payload bytes still owed on the message being forwarded.
    remaining: usize,
    /// Header bytes of the next message collected so far.
    header: [u8; MAX_CONTROL_HEADER],
    /// How many of `header` are populated.
    header_len: usize,
    /// Set once the framing stops making sense, and never cleared. A
    /// walker that has lost the stream reports no boundaries at all, which
    /// holds every later injection instead of placing it by guesswork.
    lost: bool,
}

/// What one more header byte told [`ControlFrameWalker`].
enum HeaderStep {
    /// The header is not complete yet.
    NeedMore,
    /// The header is complete and the message's payload is this long.
    Payload(usize),
    /// The header cannot be read on this draft.
    Lost,
}

impl ControlFrameWalker {
    /// A walker positioned at the start of a control stream, which is a
    /// message boundary.
    fn new(draft: DraftVersion) -> Self {
        Self { draft, remaining: 0, header: [0; MAX_CONTROL_HEADER], header_len: 0, lost: false }
    }

    /// Whether everything written so far ends on a message boundary, so
    /// another message may be written now.
    fn at_boundary(&self) -> bool {
        !self.lost && self.remaining == 0 && self.header_len == 0
    }

    /// Whether a message has been started and not finished.
    ///
    /// Distinct from `!at_boundary()`: a walker that has lost the framing
    /// is at no boundary but also cannot claim a message is half-written,
    /// and reporting a truncation it cannot see would be a fabrication.
    fn is_mid_message(&self) -> bool {
        !self.lost && (self.remaining > 0 || self.header_len > 0)
    }

    /// Account for `data` being forwarded, and answer the offset within it
    /// of the first message boundary it reaches.
    ///
    /// `None` when no message completes inside `data` — either because it
    /// is a middle slice of a long message, or because the framing has been
    /// lost. The *first* boundary rather than the last, so an injection
    /// held over from an earlier chunk goes out as early as this chunk
    /// allows.
    fn advance(&mut self, data: &[u8]) -> Option<usize> {
        if self.lost {
            return None;
        }
        let mut first = None;
        let mut i = 0;
        while i < data.len() {
            if self.remaining > 0 {
                let take = self.remaining.min(data.len() - i);
                self.remaining -= take;
                i += take;
                if self.remaining == 0 && first.is_none() {
                    first = Some(i);
                }
                continue;
            }
            if self.header_len == MAX_CONTROL_HEADER {
                self.lost = true;
                return first;
            }
            self.header[self.header_len] = data[i];
            self.header_len += 1;
            i += 1;
            match self.header_step() {
                HeaderStep::NeedMore => {}
                HeaderStep::Lost => {
                    self.lost = true;
                    return first;
                }
                HeaderStep::Payload(len) => {
                    self.header_len = 0;
                    self.remaining = len;
                    // A zero-length payload is a whole message in its
                    // header, so the boundary is here rather than after
                    // some later byte.
                    if len == 0 && first.is_none() {
                        first = Some(i);
                    }
                }
            }
        }
        first
    }

    /// Read the header collected so far, if it is complete.
    fn header_step(&self) -> HeaderStep {
        let type_len = self.draft.varint_len(self.header[0]);
        if type_len > MAX_CONTROL_HEADER {
            return HeaderStep::Lost;
        }
        if self.header_len < type_len {
            return HeaderStep::NeedMore;
        }
        if self.draft.uses_fixed_length_framing() {
            if self.header_len < type_len + 2 {
                return HeaderStep::NeedMore;
            }
            let hi = self.header[type_len] as usize;
            let lo = self.header[type_len + 1] as usize;
            return HeaderStep::Payload((hi << 8) | lo);
        }
        if self.header_len <= type_len {
            return HeaderStep::NeedMore;
        }
        let len_len = self.draft.varint_len(self.header[type_len]);
        if type_len + len_len > MAX_CONTROL_HEADER {
            return HeaderStep::Lost;
        }
        if self.header_len < type_len + len_len {
            return HeaderStep::NeedMore;
        }
        let mut cursor = &self.header[type_len..type_len + len_len];
        match self.draft.decode_varint(&mut cursor) {
            Ok(v) if v.into_inner() as usize <= MAX_CONTROL_PAYLOAD => {
                HeaderStep::Payload(v.into_inner() as usize)
            }
            // A length no control message has, so the field was read at the
            // wrong offset — see `MAX_CONTROL_PAYLOAD`.
            Ok(_) => HeaderStep::Lost,
            Err(_) => HeaderStep::Lost,
        }
    }
}

/// Write one forwarded chunk with any held injections spliced in at
/// `split`.
///
/// `split` is the offset within `data` at which the destination stream is
/// between messages; `None` means it is not, so the chunk goes out whole
/// and the injections keep waiting. Injections are written in the order
/// they were requested, and each is written verbatim: the control plane's
/// contract is that they are already framed.
async fn write_with_injections(
    send: &mut SendStream,
    data: &[u8],
    split: Option<usize>,
    injections: &mut std::collections::VecDeque<Bytes>,
) -> Result<(), TransportError> {
    let Some(split) = split else {
        return send.write_all(data).await;
    };
    let (head, tail) = data.split_at(split);
    if !head.is_empty() {
        send.write_all(head).await?;
    }
    while let Some(bytes) = injections.pop_front() {
        send.write_all(&bytes).await?;
    }
    if !tail.is_empty() {
        send.write_all(tail).await?;
    }
    Ok(())
}

/// Pipe one direction of a stream carrying MoQT control-message framing.
///
/// Three kinds of stream reach here, and they are the same shape on the
/// wire: the two directions of a bidirectional control stream on drafts
/// 07-16, one unidirectional control stream on drafts 17-19, and either
/// direction of a request stream on drafts 17-19 — draft-17 Section 9 says
/// "Every message on a control or request stream is formatted as follows",
/// one framing for both.
///
/// What separates them is not this function but what reaches its `requests`
/// channel: a control direction's channel is one of the session's two
/// control legs, so it carries injections; a request stream's is the
/// per-stream channel the registry hands a `reset_stream` to, and nothing
/// routes an injection there.
///
/// Bytes are forwarded to the peer immediately upon receipt — the parser
/// runs on a cloned copy purely to emit observer events. A stuck or
/// erroring parser can never block forwarding. This matches the
/// pass-through semantics of the data-stream and datagram paths.
///
/// If `ctx.draft_is_fixed` is false (moq-00 cohort, drafts 07–14), the
/// parser start is deferred until enough bytes arrive to peek the first
/// SETUP message and pick a concrete draft. Bytes observed during that
/// detection window are still forwarded immediately.
async fn pipe_control(
    recv: PeekedRecv,
    send: SendStream,
    side: ProxySide,
    key: StreamKey,
    requests: mpsc::Receiver<StreamCommand>,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    if ctx.control_mutation {
        pipe_control_mutating(recv, send, side, key, requests, ctx).await
    } else {
        pipe_control_passthrough(recv, send, side, key, requests, ctx).await
    }
}

/// Build a non-capturing control parser and count it.
fn new_control_parser(draft: DraftVersion, ctx: &ForwardCtx) -> ControlStreamParser {
    ctx.counters.note_control_parser_created();
    ControlStreamParser::new(draft)
}

/// Build a capturing control parser and count it.
fn new_capturing_control_parser(draft: DraftVersion, ctx: &ForwardCtx) -> ControlStreamParser {
    ctx.counters.note_control_parser_created();
    ControlStreamParser::new_capturing(draft)
}

/// Forward-first control stream pipe.
///
/// Bytes are forwarded to the peer the instant they arrive; the parser
/// runs on a cloned copy purely to drive observer events. No hook can
/// rewrite frames on this path because the bytes are already in flight.
///
/// # What it tracks even with nothing observing
///
/// Two things, and each only because nothing else on this path could.
///
/// A [`ControlFrameWalker`], which counts message lengths so a control-plane
/// injection can be placed between two messages rather than inside one. It
/// decodes no message, buffers no message and allocates nothing — one
/// varint read per message and a running byte count — so the "pure byte
/// pump" claim survives it in every sense a counter can see. It is not a
/// [`ControlStreamParser`] and does not touch `control_parsers_created`.
///
/// And the SETUP peek that settles the session's draft, on the `moq-00`
/// cohort where the ALPN does not. It is deliberately **not** behind
/// `observer_enabled`: the draft is what the object framer frames with, what
/// a datagram header decodes as, what the walker above measures with, and
/// what the capability table each hook site is shown answers for. A session
/// carrying a shaping profile with no observer and no interests needs every
/// one of those and would, behind that gate, have detected nothing at all —
/// so the profile would have been judged against the guess, armed against
/// the guess, and reported success. The peek costs one varint read per chunk
/// until it answers, and it answers on the chunk carrying the first SETUP.
async fn pipe_control_passthrough(
    mut recv: PeekedRecv,
    mut send: SendStream,
    side: ProxySide,
    key: StreamKey,
    mut requests: mpsc::Receiver<StreamCommand>,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let stream_id = recv.stream_id();
    let mut buf = [0u8; 8192];

    // Where the destination stream's message boundaries are — the only
    // thing on this pipe that knows, because this pipe forwards read
    // chunks and read chunks end wherever the transport said. Injections
    // are held until it says the stream is between messages; see
    // `ControlFrameWalker` for what it costs and what it cannot promise.
    let mut walker = ControlFrameWalker::new(ctx.draft());
    let mut injections: std::collections::VecDeque<Bytes> = std::collections::VecDeque::new();
    // Whether the request channel still has senders. It has one for as
    // long as this stream is registered, which is this task's whole life,
    // so the latch is a guard against a `None` that would otherwise make
    // the branch complete immediately and spin the loop.
    let mut serving_requests = true;

    // Built only when somebody is going to read the frames. An
    // `Interest::NONE` session with no observer allocates no parser at all,
    // which is what makes `control_parsers_created == 0` unconditional
    // rather than a claim about the read loop.
    let mut parser: Option<ControlStreamParser> =
        if ctx.control_frames_are_decoded() && ctx.draft_is_fixed {
            Some(new_control_parser(ctx.draft(), ctx))
        } else {
            None
        };
    // Refused frames already reported on this direction. Alongside the
    // parser rather than inside it, and reset by neither: a parser rebuilt
    // once the draft settles inherits this direction's acknowledgement, so
    // the once-per-direction impairment stays once per direction.
    let mut refused_seen: u64 = 0;

    // Never non-empty on this path: `Site::Control` is not reached here, and
    // `Site::StreamEnd`'s only queueing action, `ResetStream`, is refused on
    // a control stream. `PendingQueue::new` allocates nothing.
    let mut pending =
        PendingQueue::new(ctx.egress, Arc::clone(&ctx.counters)).with_gauge(Arc::clone(&ctx.gauge));
    let mut deferred = DeferredEffects::new();
    let report = ctx.reporter(side, Some(stream_id));

    // Every byte forwarded on this stream so far, held only while the draft
    // is still unsettled and released the instant it settles. Two things
    // read it, and both need it from byte zero: the peek that names the
    // draft, and the walker rebuilt around that name, which has to be walked
    // forward over what was already forwarded or it would think the stream
    // starts where the SETUP ended.
    let mut detect_buf = BytesMut::new();
    // Whether the draft is still open to being named by this direction's
    // SETUP. `false` from the first instant on an ALPN-fixed session, which
    // is where nothing below runs at all.
    let mut detecting = !ctx.draft_is_fixed;

    let mut stop = StopWatcher::new();

    loop {
        stop.arm(&send);
        let watching = stop.is_watching();

        tokio::select! {
            result = recv.read(&mut buf) => {
                let chunk = match result {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        let e = ProxyError::from(e);
                        stop.retire();
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: true,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        propagate_reset(&e, &mut send, &mut st, side, ctx, &report).await;
                        return Err(e);
                    }
                };
                match chunk {
                    Some(n) => {
                        let data = &buf[..n];

                        // ── The SETUP peek, ahead of everything ─────────
                        //
                        // First because the two things below it are built
                        // from the draft: the walker decides where a message
                        // ends, which is the framing that changed at draft
                        // 11, and the parser decodes with the draft's codec.
                        // Settling after the write would place this chunk's
                        // injection by the guess it was about to stop
                        // believing.
                        //
                        // `Some` exactly on the chunk that ends the peek,
                        // carrying every byte forwarded on this stream so
                        // far — because the parser built below has seen
                        // none of them and the walker has to be re-walked
                        // over the ones this chunk does not contain.
                        let settled: Option<Bytes> = if !detecting {
                            None
                        } else {
                            detect_buf.extend_from_slice(data);
                            match peek_draft(&detect_buf, side) {
                                DraftPeek::Named(named) => {
                                    detecting = false;
                                    ctx.draft.settle(named, setup_rank(side));
                                    Some(detect_buf.split().freeze())
                                }
                                // Nothing on this stream can name a draft,
                                // so waiting for more of it only delays
                                // every task parked on the answer. The
                                // session keeps the draft it started with,
                                // and says so at the rank that lets the
                                // other direction still improve on it.
                                DraftPeek::NotSetup => {
                                    detecting = false;
                                    ctx.draft.settle(ctx.draft.initial, DraftSource::Fallback);
                                    Some(detect_buf.split().freeze())
                                }
                                DraftPeek::NeedMore if detect_buf.len() >= DETECT_BUF_MAX => {
                                    detecting = false;
                                    ctx.emit(|| ProxyEvent::ParseError {
                                        session_id: ctx.session_id,
                                        side,
                                        error: format!(
                                            "control draft detection gave up after {} bytes; \
                                             falling back to {}",
                                            detect_buf.len(),
                                            ctx.draft(),
                                        ),
                                    });
                                    ctx.draft.settle(ctx.draft.initial, DraftSource::Fallback);
                                    Some(detect_buf.split().freeze())
                                }
                                DraftPeek::NeedMore => None,
                            }
                        };

                        // The walker, re-armed around the settled draft.
                        //
                        // It was built from the session's starting draft and
                        // has been counting message lengths in that draft's
                        // framing ever since — which, on the cohort that
                        // reaches this line, may have been the wrong framing
                        // from the first byte. A walker that read a length
                        // field at the wrong offset latches and stays
                        // latched, and a latched walker places no injection
                        // ever again on this direction. So it is rebuilt
                        // from byte zero rather than corrected: replaying
                        // the bytes already forwarded leaves it exactly
                        // where the old one stood, and right this time.
                        //
                        // Only the bytes *before* this chunk are replayed.
                        // This chunk is the one the split below is computed
                        // over, and advancing it twice would consume it.
                        if let Some(forwarded) = settled.as_ref() {
                            walker = ControlFrameWalker::new(ctx.draft());
                            let prior = forwarded.len() - data.len();
                            let _ = walker.advance(&forwarded[..prior]);
                        }

                        // Where an injection may go, decided before the
                        // write and from this chunk alone: offset 0 when
                        // the previous chunk left the stream between
                        // messages, otherwise the first boundary this
                        // chunk reaches, and `None` when it reaches none.
                        let split = if injections.is_empty() {
                            let _ = walker.advance(data);
                            None
                        } else if walker.at_boundary() {
                            let _ = walker.advance(data);
                            Some(0)
                        } else {
                            walker.advance(data)
                        };

                        // ── Forward immediately — no gating on parse ────
                        if let Err(e) =
                            write_with_injections(&mut send, data, split, &mut injections).await
                        {
                            let e = ProxyError::from(e);
                            let mut st = StreamState {
                                stream_id,
                                key,
                                is_control_stream: true,
                                pending: &mut pending,
                                deferred: &mut deferred,
                            };
                            propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                            return Err(e);
                        }

                        // ── Observer-only parse (side path) ─────────────
                        // Skip parsing when nobody is observing: the proxy
                        // becomes a pure byte pump on the control stream.
                        // The parser is built on the chunk that settled the
                        // draft, and is fed everything buffered up to that
                        // point, so it starts at the stream's first byte
                        // however many chunks the peek took.
                        if let Some(forwarded) = settled {
                            if ctx.control_frames_are_decoded() && parser.is_none() {
                                parser = Some(new_control_parser(ctx.draft(), ctx));
                            }
                            if let Some(p) = parser.as_mut() {
                                emit_parsed_frames(
                                    p,
                                    &forwarded,
                                    &mut refused_seen,
                                    side,
                                    ctx,
                                    &report,
                                );
                            }
                        } else if let Some(p) = parser.as_mut() {
                            emit_parsed_frames(p, data, &mut refused_seen, side, ctx, &report);
                        }
                    }
                    None => {
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: true,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        if let Plan::CloseSession { .. } =
                            run_stream_end(StreamEnd::Fin, &mut st, side, ctx, &report)
                        {
                            return Ok(());
                        }
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            command = requests.recv(),
                if serving_requests && injections.len() < COMMAND_QUEUE_DEPTH =>
            {
                match command {
                    Some(StreamCommand::Reset { code }) => {
                        stop.retire();
                        let _ = send.reset(code);
                        let _ = recv.stop(code);
                        // No event, for the reason `pipe_data_passthrough`
                        // gives at its copy of this arm: the peer's
                        // `RESET_STREAM` is the consequence, and neither
                        // existing reset event means *the control plane asked
                        // for this*.
                        return Ok(());
                    }
                    Some(StreamCommand::Inject { bytes }) => {
                        // Written now only when the stream is between
                        // messages *and* nothing is already waiting;
                        // otherwise it queues behind what is, so injections
                        // reach the peer in the order they were requested.
                        if injections.is_empty() && walker.at_boundary() {
                            if let Err(e) = send.write_all(&bytes).await {
                                let e = ProxyError::from(e);
                                let mut st = StreamState {
                                    stream_id,
                                    key,
                                    is_control_stream: true,
                                    pending: &mut pending,
                                    deferred: &mut deferred,
                                };
                                propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                                return Err(e);
                            }
                        } else {
                            injections.push_back(bytes);
                        }
                    }
                    None => serving_requests = false,
                }
            }
            outcome = stop.watch(), if watching => {
                // An idle control stream is MoQT's steady state, so this
                // branch has the largest blast radius in the session: a
                // false positive tears down a healthy connection. It is
                // safe because `stop_error` makes the peer's own
                // `STOP_SENDING` the only terminal outcome — see its docs.
                if let Some(e) = stop_error(outcome) {
                    let mut st = StreamState {
                        stream_id,
                        key,
                        is_control_stream: true,
                        pending: &mut pending,
                        deferred: &mut deferred,
                    };
                    propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                    return Err(e);
                }
            }
            _ = ctx.cancel.cancelled() => {
                // A requested close whose drain window ran out, cutting a
                // control message in half. Reported and left alone: writing
                // the rest of the message would mean the proxy inventing
                // control-stream bytes neither peer wrote, and the peer's
                // decoder is going to see a truncated message either way.
                //
                // Conditioned on the session discarding — that is, on a
                // close that was given a deadline and spent it — because
                // every other teardown reaches this branch too, and on
                // those the peer is the one that went away.
                if ctx.gauge.is_discarding() && walker.is_mid_message() {
                    report.impairment(ImpairmentKind::ControlStreamTruncated {
                        error: "the drain window for a requested close expired with a control \
                                message part-written"
                            .to_string(),
                    });
                }
                // Session teardown: drop the streams, which sends a FIN.
                // `cancel` also fires on a *clean* session end — the
                // first forwarding task to finish cancels the rest — so
                // resetting here would turn every orderly disconnect
                // into a RESET_STREAM no peer asked for, and MoQT treats
                // a reset control stream as a session-level error.
                return Ok(());
            }
        }
    }
}

/// Parse-then-forward control stream pipe.
///
/// Bytes are withheld until a complete control message has been parsed, at
/// which point the hook's `on_control_message` is consulted and the
/// [`Action`] it returns is executed — forwarded verbatim, replaced,
/// dropped, or deferred behind the stream's queue. This adds a per-frame
/// latency cost; a hook that only observes should leave `interest()`
/// without [`Interest::CONTROL`] and take the pass-through path instead.
async fn pipe_control_mutating(
    mut recv: PeekedRecv,
    mut send: SendStream,
    side: ProxySide,
    key: StreamKey,
    mut requests: mpsc::Receiver<StreamCommand>,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let stream_id = recv.stream_id();
    let mut buf = [0u8; 8192];

    // No `ControlFrameWalker` here, and none is needed: this pipe withholds
    // bytes until a whole message has been parsed and writes one message
    // per write, so control returning to the `select!` below is by itself
    // the statement that the destination stream is between messages. That
    // is what makes an injection sound on this path with no extra
    // bookkeeping.
    let mut serving_requests = true;

    // Capturing parser — we need the original raw bytes so the hook can
    // choose to pass them through unchanged.
    let mut parser: Option<ControlStreamParser> = if ctx.draft_is_fixed {
        Some(new_capturing_control_parser(ctx.draft(), ctx))
    } else {
        None
    };
    // As on the pass-through pipe: this direction's acknowledgement,
    // outliving the parser that may be rebuilt under it.
    let mut refused_seen: u64 = 0;

    let mut pending =
        PendingQueue::new(ctx.egress, Arc::clone(&ctx.counters)).with_gauge(Arc::clone(&ctx.gauge));
    let mut deferred = DeferredEffects::new();
    let report = ctx.reporter(side, Some(stream_id));

    let mut detect_buf = BytesMut::new();

    let mut stop = StopWatcher::new();
    // Whether the reset-only observer still has an answer for this stream.
    // See [`Source::ResetUnobservable`]: once it says no, it says no
    // immediately and forever, so it is latched off rather than re-polled.
    let mut reset_observable = true;

    loop {
        stop.arm(&send);
        let watching = stop.is_watching();
        let can_read = pending.accepts_more();
        let head_release = pending.head_release();

        tokio::select! {
            source = observe_source(&mut recv, &mut buf, can_read, reset_observable) => {
                let result = match source {
                    Source::Read(result) => result,
                    Source::ResetUnobservable => {
                        reset_observable = false;
                        continue;
                    }
                };
                let chunk = match result {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        let e = ProxyError::from(e);
                        stop.retire();
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: true,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        propagate_reset(&e, &mut send, &mut st, side, ctx, &report).await;
                        return Err(e);
                    }
                };
                match chunk {
                    Some(n) => {
                        let data = &buf[..n];

                        let parsed = match parser.as_mut() {
                            Some(p) => {
                                forward_mutated_frames(
                                    p,
                                    data,
                                    &mut refused_seen,
                                    &mut send,
                                    stream_id,
                                    key,
                                    &mut pending,
                                    &mut deferred,
                                    side,
                                    ctx,
                                    &report,
                                )
                                .await
                            }
                            None => {
                                detect_buf.extend_from_slice(data);
                                // The same peek the pass-through pipe makes,
                                // and it publishes to the same cell: this
                                // pipe is the control stream of a session
                                // whose hook declared `Interest::CONTROL`,
                                // and its data streams need the draft just
                                // as much as any other session's.
                                let new_parser = match peek_draft(&detect_buf, side) {
                                    DraftPeek::Named(named) => {
                                        ctx.draft.settle(named, setup_rank(side));
                                        Some(new_capturing_control_parser(ctx.draft(), ctx))
                                    }
                                    // Nothing here will ever name a draft.
                                    // Stop holding bytes for an answer that
                                    // is not coming — on this pipe that is
                                    // the whole stream, not just the peek.
                                    DraftPeek::NotSetup => {
                                        ctx.draft.settle(ctx.draft.initial, DraftSource::Fallback);
                                        Some(new_capturing_control_parser(ctx.draft(), ctx))
                                    }
                                    DraftPeek::NeedMore
                                        if detect_buf.len() >= DETECT_BUF_MAX =>
                                    {
                                        ctx.emit(|| ProxyEvent::ParseError {
                                            session_id: ctx.session_id,
                                            side,
                                            error: format!(
                                                "control draft detection gave up after {} bytes; \
                                                 falling back to {}",
                                                detect_buf.len(),
                                                ctx.draft(),
                                            ),
                                        });
                                        ctx.draft.settle(ctx.draft.initial, DraftSource::Fallback);
                                        Some(new_capturing_control_parser(ctx.draft(), ctx))
                                    }
                                    // Still detecting; nothing to forward yet.
                                    DraftPeek::NeedMore => None,
                                };

                                match new_parser {
                                    Some(mut p) => {
                                        let buffered = detect_buf.split().freeze();
                                        let out = forward_mutated_frames(
                                            &mut p,
                                            &buffered,
                                            &mut refused_seen,
                                            &mut send,
                                            stream_id,
                                            key,
                                            &mut pending,
                                            &mut deferred,
                                            side,
                                            ctx,
                                            &report,
                                        )
                                        .await;
                                        parser = Some(p);
                                        out
                                    }
                                    None => Ok(Flow::Continue),
                                }
                            }
                        };

                        match parsed {
                            Ok(Flow::Continue) => {}
                            Ok(Flow::StreamOver) => return Ok(()),
                            Err(e) => {
                                let mut st = StreamState {
                                    stream_id,
                                    key,
                                    is_control_stream: true,
                                    pending: &mut pending,
                                    deferred: &mut deferred,
                                };
                                propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: true,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        if drain_pending(&mut send, &mut st, Site::Control, None, ctx, &report).await?
                            == Flow::StreamOver
                        {
                            return Ok(());
                        }
                        if let Plan::CloseSession { .. } =
                            run_stream_end(StreamEnd::Fin, &mut st, side, ctx, &report)
                        {
                            return Ok(());
                        }
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            () = egress::wait_release(head_release.clone(), &ctx.cancel),
                if head_release.is_some() =>
            {
                // The write that pays back a `Delay` or a `Hold` can fail
                // with the destination peer's `STOP_SENDING` exactly like
                // the seven inline write sites — and on a stream whose
                // hook defers, it is the *only* write there is. A bare `?`
                // here returns without mirroring, `recv` is dropped, and
                // quinn's `RecvStream::drop` stops the source with a
                // hard-coded 0: the peer's reason silently replaced by
                // "unspecified" on the one path built to carry it.
                //
                // The stream-level `StopWatcher` branch does not cover
                // this. Once `select!` has picked this branch, its arm body
                // runs to completion with no branch polling at all, so a
                // `STOP_SENDING` that lands while `release_due_units` is
                // inside `write_all` surfaces here and nowhere else.
                let released = release_due_units(
                    &mut pending,
                    &mut deferred,
                    &mut send,
                    Site::Control,
                    // The control pipes are never shaped. This queue was
                    // built without a scheduler, so it can produce no shaping
                    // decision; passing `None` here means it could not report
                    // one either.
                    None,
                    ctx,
                    &report,
                )
                .await;
                match released {
                    Ok(Flow::StreamOver) => return Ok(()),
                    Ok(Flow::Continue) => {}
                    Err(e) => {
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: true,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                        return Err(e);
                    }
                }
            }
            command = requests.recv(), if serving_requests => {
                match command {
                    Some(StreamCommand::Reset { code }) => {
                        // Everything queued goes with the stream, which is
                        // what a reset means: the destination is abandoned,
                        // so units still waiting for a release time have
                        // nowhere to be written.
                        pending.clear();
                        deferred.clear();
                        stop.retire();
                        let _ = send.reset(code);
                        let _ = recv.stop(code);
                        // No event, for the reason `pipe_data_passthrough`
                        // gives at its copy of this arm: the peer's
                        // `RESET_STREAM` is the consequence, and neither
                        // existing reset event means *the control plane asked
                        // for this*.
                        return Ok(());
                    }
                    Some(StreamCommand::Inject { bytes }) => {
                        // Behind whatever a hook has deferred, when it has
                        // deferred anything. Writing inline past a
                        // non-empty queue would put the injected message
                        // ahead of messages the hook explicitly asked to
                        // hold back, reordering the control stream against
                        // the one decision that exists to order it.
                        if pending.is_empty() {
                            if let Err(e) = send.write_all(&bytes).await {
                                let e = ProxyError::from(e);
                                let mut st = StreamState {
                                    stream_id,
                                    key,
                                    is_control_stream: true,
                                    pending: &mut pending,
                                    deferred: &mut deferred,
                                };
                                propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                                return Err(e);
                            }
                        } else {
                            exec::enqueue_unshown(&mut pending, &mut deferred, bytes, &report);
                        }
                    }
                    None => serving_requests = false,
                }
            }
            outcome = stop.watch(), if watching => {
                // See `pipe_control_passthrough`'s copy of this branch for
                // why an idle control stream is not endangered by it.
                if let Some(e) = stop_error(outcome) {
                    let mut st = StreamState {
                        stream_id,
                        key,
                        is_control_stream: true,
                        pending: &mut pending,
                        deferred: &mut deferred,
                    };
                    propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                    return Err(e);
                }
            }
            _ = ctx.cancel.cancelled() => {
                let _ = pending.drain_ignoring_release_times(&mut send).await;
                // See `PendingQueue::unconfirmed_bytes`: a flush into a
                // transport that is being closed leaves nothing queued and
                // delivers nothing, so `queued_bytes` reports zero for a
                // stream whose bytes are gone.
                let stranded = pending.unconfirmed_bytes();
                if stranded > 0 {
                    report.impairment(ImpairmentKind::QueuedBytesAtTeardown {
                        stream_id,
                        bytes: stranded,
                    });
                }
                // Session teardown: drop the streams, which sends a FIN.
                // `cancel` also fires on a *clean* session end — the
                // first forwarding task to finish cancels the rest — so
                // resetting here would turn every orderly disconnect
                // into a RESET_STREAM no peer asked for, and MoQT treats
                // a reset control stream as a session-level error.
                return Ok(());
            }
        }
    }
}

/// Which stream a shaped release is happening on, for the events it owes.
///
/// `None` at the two control call sites, and that `None` is what makes *control
/// streams are never shaped* structural rather than remembered: a control pipe
/// installs no scheduler on its queue *and* has nothing to report a shaping
/// decision against, so neither the decision nor its event can appear there.
///
/// Carries the stream's **own** scheduler rather than reaching for the
/// session's current one. The two differ from the moment a profile is
/// installed on the proxy while this stream is forwarding: this stream was
/// classified, queued and paced by the scheduler recorded here, so a report
/// about one of its units has to be labelled and deduplicated against that
/// scheduler. Asking the session for its current shaper instead would name
/// the report after whatever class sits at that index in the *new* profile —
/// a correct number under a wrong label, which is the one failure the whole
/// shaping surface is written to avoid.
#[derive(Clone)]
struct ShapedStream {
    side: ProxySide,
    key: StreamKey,
    stream_id: u64,
    /// The scheduler this stream runs under, for the life of the stream.
    shaper: Arc<Scheduler>,
}

/// Write every unit whose release time has arrived, in order.
///
/// The body of the `select!` release branch, shared by the control and data
/// pipes. Each released unit pays back exactly one ledger entry — the
/// second half of a `Delay` / `Hold`, whose first half reported
/// `Effect::Queued` when the decision was taken.
///
/// On a shaped data stream this is also where the pacer runs: every
/// `pop_next_due` below is a `Scheduler::acquire`, so a class whose bucket is
/// dry simply stops yielding units and the loop ends with the queue intact.
/// Nothing about the shape of this function changes — that is the point of
/// putting the seam in `pop_next_due` rather than beside it.
async fn release_due_units(
    pending: &mut PendingQueue,
    deferred: &mut DeferredEffects,
    send: &mut SendStream,
    site: Site,
    shaped: Option<&ShapedStream>,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) -> Result<Flow, ProxyError> {
    // A release timer coarser than the engine asked for is reported once
    // per session, on its first deferred release, rather than silently
    // absorbed into the lateness distribution.
    if let Some(backend) = crate::release_timer::backend() {
        if !backend.is_high_resolution() && ctx.counters.claim_coarse_timer_report() {
            report.impairment(ImpairmentKind::CoarseReleaseTimer { backend, detail: None });
        }
    }

    let now = Instant::now();
    while let Some(unit) = pending.pop_next_due(now) {
        pending.record_release(&unit, now);
        let outcome = pending.take_shape_report();
        if matches!(outcome, Some(egress::ShapeReport::Expired)) {
            // An expiry replaces the whole queue with the reset it decided
            // on, so the ledger's entries went with the units that owed
            // them. Clearing it here keeps `DeferredEffects::len() ==
            // PendingQueue::len()` — the invariant `exec::push_unit` exists
            // to hold — and stops the synthesized terminal paying back a
            // `Delay` that never reached the wire.
            deferred.clear();
        }
        report_shaping(outcome, shaped, ctx, report);
        if let Some(owed) = deferred.pop() {
            report.applied_deferred(site, owed);
        }
        if let egress::Written::Terminated { .. } = egress::write_unit(unit, send).await? {
            pending.clear();
            deferred.clear();
            return Ok(Flow::StreamOver);
        }
    }
    // A refusal reports too: the clamp is decided when the head is *not*
    // yielded, so reading the report only after a successful pop would lose
    // the one case that matters.
    report_shaping(pending.take_shape_report(), shaped, ctx, report);
    Ok(Flow::Continue)
}

/// Emit whatever a shaped release decided, if anything.
///
/// Nothing at all on an unshaped stream and on both control pipes: the queue
/// only ever produces a report when a scheduler was installed on it.
fn report_shaping(
    outcome: Option<egress::ShapeReport>,
    shaped: Option<&ShapedStream>,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) {
    let (Some(outcome), Some(stream)) = (outcome, shaped) else { return };
    match outcome {
        // `HoldClamped`'s cardinality is already *once per clamped unit*, and a
        // shaping clamp is exactly that: a unit released at `max_hold` because
        // the bucket would not have released it at all.
        egress::ShapeReport::Clamped { requested, applied } => {
            report.impairment(ImpairmentKind::HoldClamped { requested, applied });
        }
        // Once per session per class, and the scheduler owns the latch
        // because the burst is the profile's rather than this stream's: the
        // queue re-decides it on every refusal, and every stream carrying the
        // class re-decides it too. `None` means somebody has already said it.
        egress::ShapeReport::BurstBelowUnit { class, burst_bytes, unit_bytes } => {
            if let Some(name) = stream.shaper.claim_burst_report(class) {
                report.impairment(ImpairmentKind::ShapeBurstBelowUnit {
                    class: name,
                    burst_bytes,
                    unit_bytes,
                });
            }
        }
        egress::ShapeReport::Expired => ctx.emit(|| ProxyEvent::Shaped {
            session_id: ctx.session_id,
            side: stream.side,
            key: stream.key,
            stream_id: stream.stream_id,
            // An expiry abandons the whole destination stream, so like a
            // policy reset it is about the stream and not about the unit
            // that happened to outlive its clamp.
            class: String::new(),
            outcome: ShapeOutcome::Expired,
        }),
    }
}

/// Feed bytes into the capturing control parser, then execute the hook's
/// decision on each completed frame.
///
/// This pipe owns the forwarding path: nothing reaches the far side except
/// what this function writes. A frame the decoder refuses is therefore
/// written verbatim rather than skipped — no hook can be consulted about a
/// message that did not decode, but dropping it would remove a control
/// message from a session neither peer knows is missing one.
#[allow(clippy::too_many_arguments)]
async fn forward_mutated_frames(
    parser: &mut ControlStreamParser,
    data: &[u8],
    refused_seen: &mut u64,
    send: &mut SendStream,
    stream_id: u64,
    key: StreamKey,
    pending: &mut PendingQueue,
    deferred: &mut DeferredEffects,
    side: ProxySide,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) -> Result<Flow, ProxyError> {
    if let ParseResult::Framed(items) = parser.feed(data) {
        // Ahead of the hook, for the same reason the observation-only pipe
        // reports ahead of its events: the frame that was lost preceded the
        // frames the hook is about to be handed.
        report_refused_frames(&items, refused_seen, ctx, report);

        for item in items {
            // A frame this proxy could not read still has a peer that may
            // be able to. On this pipe the parser *is* the forwarding path,
            // so bytes it kept to itself never reach the far side at all:
            // the message would be deleted from the session, and every
            // Request ID and state transition it carried with it. No hook
            // is consulted, because there is no decoded message to offer
            // one, and no action can be taken on bytes nobody can read.
            let mut frame = match item {
                ParsedItem::Frame(frame) => frame,
                ParsedItem::Refused(refused) => {
                    let raw = refused.raw_bytes.expect("capturing parser must populate raw_bytes");
                    send.write_all(&raw).await?;
                    continue;
                }
            };
            let raw = frame.raw_bytes.take().expect("capturing parser must populate raw_bytes");

            let arrived_at = Instant::now();
            let draft = ctx.draft();
            let caps = ctx.caps();
            let cx = FrameCtx::new(ctx.session_id, side, draft, Some(stream_id), arrived_at, &caps);
            let action = ctx.hook.on_control_message(&cx, &frame.message, &raw);
            let unit = exec::Unit { target: exec::Target::Control { raw }, draft, arrived_at };
            let mut engine = exec::Engine {
                queue: Some(exec::Queue { pending, deferred }),
                closer: &ctx.closer,
            };
            let out = exec::execute(&unit, action, &mut engine, report);

            match out.plan {
                Plan::WriteNow(bytes) => {
                    // Read off what is going out rather than off what came
                    // in, and only here rather than beside the decode above:
                    // a hook on this pipe may rewrite a FETCH, and the
                    // publisher answers the request it receives. A frame the
                    // hook dropped reaches `Plan::Nothing` and files nothing,
                    // because no response stream will ever come for it.
                    note_fetch_order(&bytes, ctx);
                    send.write_all(&bytes).await?;
                }
                Plan::Nothing => {}
                // `Truncate` and `ResetStream` are refused on every control
                // stream on every draft, so no terminal can be queued here;
                // handled rather than `unreachable!()`d because a panicking
                // forwarding task is worse than a redundant arm.
                Plan::Terminal => {
                    let mut st =
                        StreamState { stream_id, key, is_control_stream: true, pending, deferred };
                    let _ = drain_pending(send, &mut st, Site::Control, None, ctx, report).await?;
                    return Ok(Flow::StreamOver);
                }
                // Stream-shaped plans; only `execute_stream` produces
                // them and it is never called from the control path.
                Plan::RejectStream { .. }
                | Plan::OpenStreamAfter { .. }
                | Plan::SerializeStreamAfter { .. } => {}
                Plan::CloseSession { .. } => return Ok(Flow::StreamOver),
            }

            if ctx.observer_enabled {
                ctx.observer.on_event(&control_event(ctx.session_id, side, frame.message));
            }
        }
    }
    Ok(Flow::Continue)
}

/// Feed bytes to the control parser and emit observer events for any
/// completed frames.
///
/// The hook is deliberately not invoked here — on the pass-through path
/// the bytes have already been forwarded, so an [`Action`] returned there
/// would be unexecutable. Hooks that need to see control messages without
/// rewriting them should be implemented as a [`ProxyObserver`]; hooks that
/// need to rewrite them declare [`Interest::CONTROL`], which routes traffic
/// through `pipe_control_mutating` instead.
fn emit_parsed_frames(
    parser: &mut ControlStreamParser,
    data: &[u8],
    refused_seen: &mut u64,
    side: ProxySide,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) {
    match parser.feed(data) {
        ParseResult::Framed(items) => {
            // What the session needs for itself, before anything about
            // telling somebody: a parser exists on this path for two
            // unrelated reasons and only one of them is an observer. The
            // bytes went out verbatim on this pipe, so the message decoded
            // here is exactly the one the peer will act on.
            note_fetch_orders(&items, ctx);

            // Before the events, because a chunk carrying a refused frame
            // ahead of a good one lost the first and delivered the second,
            // and an observer reading in order should learn of the loss
            // where it happened rather than after everything that survived
            // it. Outside the observer gate because the counter it moves is
            // the proxy's own record of what it could not read; the report
            // beside it is gated within.
            report_refused_frames(&items, refused_seen, ctx, report);

            if !ctx.observer_enabled {
                return;
            }
            for item in items {
                // A refused frame has no message to report as one. Its
                // bytes were forwarded before this function was called, so
                // the impairment above is the whole of what is owed here.
                if let ParsedItem::Frame(frame) = item {
                    ctx.observer.on_event(&control_event(ctx.session_id, side, frame.message));
                }
            }
        }
        ParseResult::NeedMore => {}
    }
}

/// File the Group Order every FETCH in this batch asked for.
///
/// For the pass-through pipe, whose frames reach the peer unchanged, so the
/// message decoded from them is the one the publisher will answer.
fn note_fetch_orders(items: &[ParsedItem], ctx: &ForwardCtx) {
    if !ctx.fetch_orders_wanted {
        return;
    }
    for item in items {
        if let ParsedItem::Frame(frame) = item {
            if let Some((request_id, order)) = frame.message.fetch_group_order() {
                ctx.fetch_orders.record(request_id, order);
            }
        }
    }
}

/// File the Group Order a FETCH asked for, from the bytes leaving the proxy.
///
/// For the mutating pipe, where the frame the hook returned is the one the
/// peer receives and therefore the one that settles the response's order. It
/// is decoded a second time here for that reason alone: the message decoded
/// on the way in is what *arrived*, and on this pipe those are allowed to
/// differ. Bytes the hook returned that no longer decode file nothing, and
/// the stream they were about is bypassed rather than read against an order
/// the publisher never agreed to.
fn note_fetch_order(outgoing: &[u8], ctx: &ForwardCtx) {
    if !ctx.fetch_orders_wanted {
        return;
    }
    let Ok(message) = AnyControlMessage::decode(ctx.draft(), &mut &outgoing[..]) else {
        return;
    };
    if let Some((request_id, order)) = message.fetch_group_order() {
        ctx.fetch_orders.record(request_id, order);
    }
}

/// Report the control frames the decoder refused in one feed.
///
/// Called from both control pipes: one parser refusing a frame is one
/// parser, and a helper wired into a single site would have left the other
/// pipe as silent as neither was.
///
/// The counter takes every refusal; the impairment goes out once per
/// direction and carries the count it went out with. `seen` is that
/// direction's running acknowledgement, and it is a caller's local because
/// the parser deliberately holds no reporting state - how often to say a
/// thing is a property of the event stream, not of the framing.
fn report_refused_frames(
    items: &[ParsedItem],
    seen: &mut u64,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) {
    let mut refused = items.iter().filter_map(|item| match item {
        ParsedItem::Refused(r) => Some(r),
        ParsedItem::Frame(_) => None,
    });
    let Some(head) = refused.next() else { return };
    let count = 1 + refused.count() as u64;

    ctx.counters.note_control_frames_not_decodable(count);

    // Read before `seen` moves: this is the first report on this direction
    // exactly when nothing had been acknowledged before it.
    let first = *seen == 0;
    *seen += count;
    if first {
        report.impairment(ImpairmentKind::ControlFrameNotDecodable {
            type_id: head.type_id,
            total: *seen,
        });
    }
}

/// The observer event one parsed control frame produces.
//
// `AnyControlMessage::is_setup` is `unreachable!()` in a build with no
// draft feature enabled — the enum has no variants there, so it is
// uninhabited and every expression after the call is genuinely dead. The
// allow is scoped to exactly that build so a real unreachable branch in a
// normal build is still an error.
#[cfg_attr(
    not(any(
        feature = "draft07",
        feature = "draft08",
        feature = "draft09",
        feature = "draft10",
        feature = "draft11",
        feature = "draft12",
        feature = "draft13",
        feature = "draft14",
        feature = "draft15",
        feature = "draft16",
        feature = "draft17",
        feature = "draft18",
        feature = "draft19"
    )),
    allow(unreachable_code)
)]
fn control_event(
    session_id: SessionId,
    side: ProxySide,
    message: moqtap_codec::dispatch::AnyControlMessage,
) -> ProxyEvent {
    if message.is_setup() {
        ProxyEvent::SetupMessage { session_id, side, message }
    } else {
        ProxyEvent::ControlMessage { session_id, side, message }
    }
}

/// Forward unidirectional streams from source to destination.
///
/// # Why `dest` is an `Arc` and `source` is not
///
/// [`StreamAction::OpenAfter`](crate::action::StreamAction::OpenAfter)
/// defers `dest.open_uni()` past the accept
/// loop, into the spawned per-stream task, so the destination transport has
/// to be *shared* rather than borrowed for the loop's lifetime. Both call
/// sites already hold an `Arc<Transport>` and `Transport` is not `Clone`,
/// so this is the only shape available. `source` stays a borrow: nothing is
/// ever done with it outside the loop.
///
/// # The two open topologies, and why the default one did not move
///
/// [`StreamAction::Open`](crate::action::StreamAction::Open)
/// — and therefore every session that never returns
/// `OpenAfter` — keeps `dest.open_uni()` **in the accept loop**, between the
/// `Site::StreamOpen` decision and the spawn, exactly where it has always
/// been. That is what keeps the two reject sites observably different: a
/// reject at the open site creates no peer stream at all, while a reject at
/// the header site resets a peer stream that already exists having carried
/// nothing. Opening lazily for every stream would collapse that difference
/// into one behaviour and silently retire a published capability
/// distinction.
///
/// The `OpenAfter` arm spawns first and opens inside the task, after the
/// delay — and it opens *before* the first byte is read, so by the time the
/// header site is reached the peer stream exists there too and a reject
/// there still resets it.
async fn forward_uni_streams(
    source: &Transport,
    dest: Arc<Transport>,
    side: ProxySide,
    ctx: &ForwardCtx,
    control: Option<ControlLeg>,
) -> Result<(), ProxyError> {
    // `Some` only on the drafts whose control plane is a pair of
    // unidirectional streams, where one of the streams this loop accepts is
    // this direction's control stream. Shared rather than owned because
    // which one it is cannot be known until a stream's first varint has been
    // read, and that read happens inside the per-stream task: whichever task
    // reads `CONTROL_STREAM_TYPE` first takes the leg, and a second one — a
    // peer opening two control streams, which the drafts forbid — finds it
    // gone and is forwarded as a control stream the control plane cannot
    // reach, rather than stealing the channel from the first.
    let control = Arc::new(Mutex::new(control));
    debug_assert!(
        control.lock().expect("nothing holds this yet").is_none()
            || control_plane_is_unidirectional(ctx.draft.initial),
        "a control leg belongs on the unidirectional accept loop only where the control plane \
         is a pair of unidirectional streams",
    );
    loop {
        tokio::select! {
            result = source.accept_uni() => {
                let mut recv = result?;
                let stream_id = recv.stream_id();
                // Minted before the open decision, so the key a hook is
                // shown at `Site::StreamOpen` is the key it will see again
                // at the header and at the end.
                let key = ctx.mint_key(side);
                ctx.emit(|| ProxyEvent::UniStreamOpened {
                    session_id: ctx.session_id,
                    side,
                });

                // What the `Site::StreamOpen` decision changed about how
                // this stream starts. Both stay `None` for `Open`, for a
                // hook that declared no stream interest, and for every
                // refused action — so the default topology below is the
                // one every existing test still takes.
                let mut open_after: Option<Duration> = None;
                let mut serialize_after: Option<StreamKey> = None;

                // The reject decision is taken between `accept_uni` and
                // `open_uni`, so a rejected stream never exists on the far
                // side at all.
                if ctx.streams_enabled {
                    let report = ctx.reporter(side, Some(stream_id));
                    let draft = ctx.draft();
                    let caps = ctx.caps();
                    let scx = StreamCtx::new(
                        ctx.session_id,
                        side,
                        stream_id,
                        draft,
                        false,
                        &caps,
                        key,
                    );
                    let action = ctx.hook.on_stream_open(&scx);
                    let out = exec::execute_stream(
                        StreamSite::Open,
                        draft,
                        action,
                        &report,
                    );
                    // An exhaustive `match`, not an `if let`:
                    // `OpenStreamAfter` and `SerializeStreamAfter` are
                    // decided here and honoured further down, and a
                    // wildcard would let a plan this site forgets to carry
                    // become a silent no-op instead of a compile error.
                    match out.plan {
                        Plan::RejectStream { code } => {
                            let _ = recv.stop(code);
                            continue;
                        }
                        Plan::OpenStreamAfter { after } => open_after = Some(after),
                        Plan::SerializeStreamAfter { target } => {
                            serialize_after = Some(target);
                        }
                        Plan::Nothing => {}
                        Plan::WriteNow(_) | Plan::Terminal | Plan::CloseSession { .. } => {}
                    }
                }

                // Registered *before* the open, and released by dropping
                // the guard. Before, because `open_uni().await` is a
                // suspension point and a stream this one might be
                // serialized behind must be waitable from the moment its
                // key exists. A stream rejected above never gets here, so
                // a key naming one answers "nothing to wait for", which is
                // the truth: it was never forwarded.
                // The stream's request channel is minted with its
                // registration and dies with it: the sending half lives in
                // the registry entry, the receiving half in the task
                // below, so a key that has been retired cannot be reached
                // and a task that is running always can be.
                let (inbox, requests) = mpsc::channel(COMMAND_QUEUE_DEPTH);
                // A second sender, kept only where a stream on this loop
                // might turn out to be a control stream, so that the
                // session's control leg can be pumped into the same inbox
                // the registry already reaches this stream through. `None`
                // everywhere else, which is every draft through 16.
                let control_inbox =
                    control_plane_is_unidirectional(ctx.draft.initial).then(|| inbox.clone());
                let guard = ctx.streams.register(key, inbox);

                // The default topology, unmoved: open between the decision
                // and the spawn. `OpenAfter` is the only arm that defers,
                // and it opens inside the task instead.
                let opened = match open_after {
                    None => Some(dest.open_uni().await?),
                    Some(_) => None,
                };

                let ctx = ctx.clone();
                let dest = Arc::clone(&dest);
                let control = Arc::clone(&control);

                tokio::spawn(async move {
                    // Moved in, and dropped on every exit from this task —
                    // returns, `?`, panics, and the task future being dropped
                    // wholesale at session teardown. That is what makes *the
                    // gate is released on every termination path* a structural
                    // claim rather than a list.
                    let _guard = guard;

                    let send = match opened {
                        Some(send) => send,
                        None => {
                            let after = open_after.unwrap_or_default();
                            tokio::select! {
                                () = tokio::time::sleep(after) => {}
                                () = ctx.cancel.cancelled() => return,
                            }
                            match dest.open_uni().await {
                                Ok(send) => send,
                                Err(e) => {
                                    // The destination connection went away
                                    // during the delay. The four other
                                    // top-level tasks fail on it too and
                                    // end the session; this is the
                                    // diagnostic, reported through the same
                                    // channel and with the same
                                    // already-mirrored guard as a pipe
                                    // failure.
                                    let e = ProxyError::from(e);
                                    if !is_mirrored_teardown(&e) {
                                        ctx.emit(|| ProxyEvent::ParseError {
                                            session_id: ctx.session_id,
                                            side,
                                            error: format!("deferred uni stream open: {e}"),
                                        });
                                    }
                                    return;
                                }
                            }
                        }
                    };

                    // What this stream is, on the drafts where a
                    // unidirectional stream can be either half of the
                    // control plane or a data stream. Everywhere else the
                    // question does not arise and nothing is read here.
                    //
                    // The *starting* draft, here and at the other four
                    // topology reads, and not the session's current one:
                    // where the control plane lives was decided once, in
                    // `run_with_transport`, and the tasks that implement
                    // that decision were spawned from it. A SETUP peek that
                    // moved the answer afterwards would leave one loop
                    // forwarding request streams and another expecting a
                    // control stream on a topology nobody built.
                    let (recv, kind) = if control_plane_is_unidirectional(ctx.draft.initial) {
                        classify_uni_stream(recv, ctx.draft.initial).await
                    } else {
                        (PeekedRecv::new(recv), UniStreamKind::Data)
                    };

                    let result = match kind {
                        UniStreamKind::Control => {
                            // The other topology's copy of the same latch:
                            // this session has a control stream, so a task
                            // waiting on the draft has something to wait
                            // for. See `SessionDraft::control_stream_open`.
                            ctx.draft.note_control_stream();
                            // Held for the pipe's whole life and dropped
                            // with it, so the leg stops being pumped the
                            // moment there is nothing to pump it into. The
                            // leg is taken only when there is an inbox to
                            // pump it into, so a build that somehow reached
                            // this arm without one leaves the leg where it
                            // is rather than dropping the session's only
                            // route for an injection.
                            //
                            // A `SerializeAfter` returned for this stream at
                            // `Site::StreamOpen` is not honoured here, and
                            // was not on the drafts where the control stream
                            // is a bidirectional stream either: holding a
                            // control stream's first write behind another
                            // stream would hold SETUP, and the session with
                            // it.
                            let _pump = control_inbox.and_then(|inbox| {
                                control
                                    .lock()
                                    .expect("no task holds the control leg across a panic")
                                    .take()
                                    .map(|leg| pump_control_leg(leg, inbox))
                            });
                            pipe_control(recv, send, side, key, requests, &ctx).await
                        }
                        UniStreamKind::Data => {
                            pipe_data(recv, send, side, key, serialize_after, requests, &ctx)
                                .await
                        }
                    };

                    if let Err(e) = result {
                        // An abnormal teardown is an ordinary protocol
                        // event, already reported as `StreamReset` and
                        // already mirrored onto the far side. Reporting
                        // it again as `ParseError` would claim the codec
                        // failed and that the bytes were still forwarded,
                        // both of which are false.
                        if !is_mirrored_teardown(&e) {
                            ctx.emit(|| ProxyEvent::ParseError {
                                session_id: ctx.session_id,
                                side,
                                error: format!("uni stream pipe: {e}"),
                            });
                        }
                    }
                });
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Determine the data stream type from the first varint on the stream.
///
/// MoQT data streams start with a stream type varint:
/// - 0x04 = Subgroup
/// - 0x05 = Fetch
///
/// The varint itself is not consumed here: the framer is fed the stream
/// from its first byte and the header decoder owns the type field.
fn detect_stream_type(first_byte: u8) -> DataStreamType {
    // The stream type varint is a single byte for values < 64.
    // Subgroup = 0x04, Fetch = 0x05.
    match first_byte {
        0x05 => DataStreamType::Fetch,
        // Default to Subgroup for 0x04 and anything else
        _ => DataStreamType::Subgroup,
    }
}

/// Pipe a unidirectional data stream.
///
/// The choice made here is the whole cost model of the data path:
/// `pipe_data_passthrough` never allocates and never decodes, while
/// `pipe_data_framed` buffers each object whole so it can be reported.
async fn pipe_data(
    recv: PeekedRecv,
    send: SendStream,
    side: ProxySide,
    key: StreamKey,
    serialize_after: Option<StreamKey>,
    requests: mpsc::Receiver<StreamCommand>,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    if let Some(target) = serialize_after {
        let report = ctx.reporter(side, Some(recv.stream_id()));
        await_serialize_target(target, key, ctx, &report).await;
    }
    // The whole claim, checked where the framing decision is actually
    // taken rather than only where it is computed: a configured
    // `ShapeProfile` implies framing. Classification needs `ObjectMeta`,
    // and only `pipe_data_framed` produces it — so a shaped session that
    // reached the pass-through pipe would be a byte pump reporting
    // success, which is the one outcome the assertion exists to prevent.
    debug_assert!(
        !ctx.shaping_enabled || ctx.objects_enabled,
        "a session with a ShapeProfile must be framed: shaping cannot classify a byte pump"
    );
    // And the two shaping fields agree. They are separate so the hot path
    // can test a `bool` without touching an `Arc`, which is exactly the
    // kind of duplication that drifts: a session that armed framing for a
    // profile it then failed to build a shaper for would classify nothing
    // and report success.
    debug_assert_eq!(
        ctx.shaping_enabled,
        ctx.shape.is_some(),
        "shaping_enabled is the cached `shape.is_some()`, not a second decision"
    );
    if ctx.objects_enabled {
        pipe_data_framed(recv, send, side, key, requests, ctx).await
    } else {
        pipe_data_passthrough(recv, send, side, key, requests, ctx).await
    }
}

/// What a data stream's task does with a control-plane request.
///
/// Shared by both data pipes because the answer is the same on each: a
/// reset ends the stream, and an injection cannot happen here.
///
/// The caller does the resetting, because it holds `&mut send` and
/// `&mut recv`; this only says what to do.
enum StreamRequest {
    /// Reset the destination and stop the source with this code.
    Reset(u64),
    /// Nothing to do — keep forwarding.
    Ignore,
    /// The channel has no senders left; stop polling it.
    Closed,
}

/// Interpret one request delivered to a data stream's task.
fn data_stream_request(command: Option<StreamCommand>) -> StreamRequest {
    match command {
        Some(StreamCommand::Reset { code }) => StreamRequest::Reset(code),
        // Injection is a control-stream operation and is routed by leg to
        // one of the two control directions, so nothing sends this here.
        // Handled rather than `unreachable!()`d, because a panicking
        // forwarding task is worse than a branch that does nothing — the
        // same ruling the plan matches in this file already take.
        Some(StreamCommand::Inject { .. }) => StreamRequest::Ignore,
        None => StreamRequest::Closed,
    }
}

/// Hold this stream until `target` ends —
/// [`StreamAction::SerializeAfter`](crate::action::StreamAction::SerializeAfter).
///
/// The peer stream is already open (that is what the action says: *open now,
/// write nothing until*), so what is being held is the first write on it. This
/// function holds the whole pipe rather than gating one queued unit: the effect
/// on the wire is identical — nothing is written — and the read is held with
/// it, which is `Overflow::Block`'s own answer to *the destination is not
/// ready*, not a new mechanism.
///
/// # Three ways this cannot hang the session
///
/// 1. **Session cancellation** is one of the three racers, so teardown is
///    never waiting on a hook's bookkeeping.
/// 2. **[`EgressConfig::max_hold`]** is the ceiling, so a target whose gate
///    is somehow never released costs a bounded delay rather than a stream
///    that lives forever. It is the same ceiling a `Hold` gets, for the same
///    reason — a caller may not make a stream unkillable.
/// 3. **A target that cannot end later than now resolves immediately** and
///    says so once. Three cases are one report: a key that was never
///    forwarded, a stream that has already ended, and *this* stream. The
///    third is the interesting one — a self-serialize is unsatisfiable by
///    construction, and left unguarded it would be a `max_hold` stall
///    attributed to the pacer rather than to the hook that asked for it.
async fn await_serialize_target(
    target: StreamKey,
    key: StreamKey,
    ctx: &ForwardCtx,
    report: &exec::Reporter<'_>,
) {
    let gate = if target == key { None } else { ctx.streams.gate_for(target) };
    match gate {
        None => report.impairment(ImpairmentKind::SerializeTargetUnknown { key, target }),
        Some(gate) => {
            tokio::select! {
                () = gate.wait() => {}
                () = tokio::time::sleep(ctx.egress.max_hold) => {}
                () = ctx.cancel.cancelled() => {}
            }
        }
    }
}

/// Forward a unidirectional data stream without interpreting it.
///
/// A stack buffer, a write and one boxed stop-watcher per stream — no
/// parser and still no per-object work. This is the path every session
/// takes when nothing is observing and no hook declared object or stream
/// interest.
///
/// The watcher is the single heap allocation this function makes, and it
/// is made lazily on the first `select!` iteration (see [`StopWatcher`]),
/// once per forwarded stream. `Counters` has no allocation field, so
/// `interest_none.rs`'s whole-struct `Counters::default()` comparison
/// cannot see this cost — this sentence is the only gate it has, which is
/// why it is stated rather than quietly dropped.
async fn pipe_data_passthrough(
    mut recv: PeekedRecv,
    mut send: SendStream,
    side: ProxySide,
    key: StreamKey,
    mut requests: mpsc::Receiver<StreamCommand>,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let stream_id = recv.stream_id();
    let mut buf = [0u8; 8192];
    let mut serving_requests = true;

    // `Interest::STREAMS` contains `Interest::OBJECTS`, so a session that
    // reaches this function has `streams_enabled == false` and never
    // queues anything. The queue is here because the teardown helpers take
    // one; `PendingQueue::new` allocates nothing.
    let mut pending =
        PendingQueue::new(ctx.egress, Arc::clone(&ctx.counters)).with_gauge(Arc::clone(&ctx.gauge));
    let mut deferred = DeferredEffects::new();
    let report = ctx.reporter(side, Some(stream_id));

    let mut stop = StopWatcher::new();

    loop {
        stop.arm(&send);
        let watching = stop.is_watching();

        tokio::select! {
            result = recv.read(&mut buf) => {
                let chunk = match result {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        let e = ProxyError::from(e);
                        stop.retire();
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: false,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        propagate_reset(&e, &mut send, &mut st, side, ctx, &report).await;
                        return Err(e);
                    }
                };
                match chunk {
                    Some(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            let e = ProxyError::from(e);
                            let mut st = StreamState {
                                stream_id,
                                key,
                                is_control_stream: false,
                                pending: &mut pending,
                                deferred: &mut deferred,
                            };
                            propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                            return Err(e);
                        }
                    }
                    None => {
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: false,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        match run_stream_end(StreamEnd::Fin, &mut st, side, ctx, &report) {
                            Plan::Terminal => {
                                // `None`: the pass-through pipe installs no
                                // scheduler on its queue, so no shaping
                                // decision can be taken here.
                                let _ = drain_pending(
                                    &mut send, &mut st, Site::Object, None, ctx, &report,
                                )
                                .await?;
                                return Ok(());
                            }
                            Plan::CloseSession { .. } => return Ok(()),
                            _ => {}
                        }
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            command = requests.recv(), if serving_requests => {
                match data_stream_request(command) {
                    StreamRequest::Reset(code) => {
                        stop.retire();
                        let _ = send.reset(code);
                        let _ = recv.stop(code);
                        // No event. `ProxyEvent::StreamReset` means a
                        // teardown this proxy *observed* on a peer, and
                        // `ActionApplied` means a hook asked for one; a
                        // control-plane reset is neither, and borrowing
                        // either would make an existing event ambiguous
                        // for every reader that already relies on it. What
                        // it produces is a `RESET_STREAM` carrying `code`
                        // at the destination peer, which is the
                        // consequence worth observing.
                        return Ok(());
                    }
                    StreamRequest::Ignore => {}
                    StreamRequest::Closed => serving_requests = false,
                }
            }
            outcome = stop.watch(), if watching => {
                // The idle case: nothing is being written on this stream,
                // so no `write_all` can surface the peer's `STOP_SENDING`
                // and without this branch the source is never stopped.
                if let Some(e) = stop_error(outcome) {
                    let mut st = StreamState {
                        stream_id,
                        key,
                        is_control_stream: false,
                        pending: &mut pending,
                        deferred: &mut deferred,
                    };
                    propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                    return Err(e);
                }
            }
            _ = ctx.cancel.cancelled() => {
                // Session teardown: drop the streams, which sends a FIN.
                // `cancel` also fires on a *clean* session end — the
                // first forwarding task to finish cancels the rest — so
                // resetting here would turn every orderly disconnect
                // into a RESET_STREAM no peer asked for, and MoQT treats
                // a reset control stream as a session-level error.
                return Ok(());
            }
        }
    }
}

/// Forward a unidirectional data stream through the object framer.
///
/// Every byte written to the destination comes out of
/// [`ObjectFramer::poll`], so a forwarded stream on which no action was
/// taken is byte-identical to the received one — the framer only decides
/// where the boundaries are. The cost is latency: an object is not
/// forwarded until it is buffered whole, or until the framer gives up on
/// it and streams it through.
///
/// # The draft this frames with
///
/// Taken once, at the top, from the session's shared cell and **waited
/// for** — see [`SessionDraft::resolved`]. Once, because the draft decides
/// where an object ends: a stream framed half under one draft and half under
/// another would report object boundaries that were never on the wire.
/// Waited for, because on drafts 07 to 14 the ALPN names no draft and the
/// answer arrives on the control stream, in a task this one was spawned
/// alongside — so reading the cell without waiting is a race the session
/// loses whenever the two tasks are polled in the other order, and losing it
/// means framing every object on this stream against the configured guess.
///
/// A wrong draft is not a fidelity failure — the framer latches a bypass and
/// forwards the rest of the stream byte for byte — but it is a silent
/// failure of everything built on the framing: no object reaches a hook, no
/// shaping class claims one, and the session reports success.
async fn pipe_data_framed(
    mut recv: PeekedRecv,
    mut send: SendStream,
    side: ProxySide,
    key: StreamKey,
    mut requests: mpsc::Receiver<StreamCommand>,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    // The ordering edge. Ahead of the first read, so no byte of this stream
    // is interpreted before the draft it is interpreted under is known, and
    // held in a local for the stream's whole life: every hook site, every
    // report and the framer itself answer for the same draft, whatever the
    // control stream learns later.
    let draft = ctx.resolved_draft().await;
    let caps = Capabilities::for_draft(draft);
    let stream_id = recv.stream_id();
    let mut buf = [0u8; 8192];
    let mut serving_requests = true;
    let mut framer: Option<ObjectFramer> = None;
    // The drafts 17-19 subgroup-ID mode from this stream's header, which
    // separates a reserved header mode from the *subgroup ID is the first
    // object's ID* mode when an elide is judged.
    let mut subgroup_id_mode: Option<u8> = None;
    let mut not_addressable_reported = false;
    // A separate latch from `not_addressable_reported`, because the two
    // reports have different audiences and different conditions: that one
    // fires on every session with a framer, this one only on a session with a
    // profile, where the same object additionally escapes a configured rate.
    let mut unpaced_reported = false;

    // The session's shaper, or `None`. Everything below that reads it is
    // behind this one binding, so an unshaped stream's admission cost is a
    // single `Option` test per object and nothing else.
    //
    // Read **once**, here, and held for the whole stream. That is what makes
    // a profile installed on the proxy while this stream runs land on the
    // next stream rather than in the middle of this one: the classification
    // below, the queue built from it and every release decision it makes all
    // come from this one `Arc`, so a unit cannot be classified against one
    // profile's rules and charged against another's buckets.
    let shaper = ctx.shape.as_ref().map(|s| s.current());
    let shape = shaper.as_deref();
    // The one construction site in the crate that installs a scheduler. Both
    // control pipes and `pipe_data_passthrough` call `PendingQueue::new` and
    // stop there, so *the control pipes are never shaped* is a property of
    // which queue got a shaper and not of a rule anyone has to remember.
    let mut pending = PendingQueue::new(ctx.egress, Arc::clone(&ctx.counters))
        .with_gauge(Arc::clone(&ctx.gauge))
        .with_shape_depth(shape.and_then(Scheduler::blocking_depth))
        .with_shaper(shaper.clone(), Arc::clone(&ctx.shape_stats), side);
    let mut deferred = DeferredEffects::new();
    let report = ctx.reporter(side, Some(stream_id));
    // What a shaping decision on this stream is reported against, and `None`
    // when there is nothing to decide. Carries the same `Arc` the queue got,
    // so a report is labelled by the scheduler that produced it.
    let shaped_stream = shaper.clone().map(|shaper| ShapedStream { side, key, stream_id, shaper });

    let mut stop = StopWatcher::new();
    // Admission state, all per stream.
    //
    // `shaped_units` is the counter `Matcher::every_nth` is defined
    // against: hook-visible units on *this stream*, never
    // `ObjectMeta::index_in_stream` (which counts oversized objects the
    // hook never sees) and never anything wider (which the tokio scheduler
    // orders, destroying reproducibility).
    let mut shaped_units: u64 = 0;
    // The class of the most recently classified unit. What a *stream*-level
    // report — a block episode — is charged to, because a stream has no
    // single class of its own.
    let mut last_class = Class::Default;
    // Whether any unit on this stream has been classified yet, and whether
    // two of them disagreed. Head-gating makes configured shaping and
    // head-of-line blocking indistinguishable from outside, so a stream that
    // carries two classes has to say so — once.
    let mut first_class: Option<Class> = None;
    let mut mixed_reported = false;
    // Edge triggers. `blocked` re-arms when the queue drains, so
    // `blocked_episodes` counts episodes rather than `select!` iterations;
    // `drop_reported` never re-arms, because `ProxyEvent::Shaped` is capped
    // at once per stream per outcome.
    let mut blocked = false;
    let mut drop_reported = false;
    // Whether the reset-only observer still has an answer for this stream;
    // see [`Source::ResetUnobservable`]. This is the stream whose read
    // branch a shaping profile can hold shut for `max_hold`, so it is the
    // stream the observer exists for.
    let mut reset_observable = true;

    loop {
        stop.arm(&send);
        let watching = stop.is_watching();
        let can_read = pending.accepts_more();
        let head_release = pending.head_release();

        // `Overflow::Block`, measured where it actually happens: `can_read`
        // false means `observe_source` does not call `recv.read()`, so
        // nothing is consumed off the wire and no flow-control credit is
        // granted. (It parks on the peer's reset instead, which reads no
        // bytes — see `observe_source`. The episode is the same episode.)
        // Counted only when a blocking depth was installed — engine
        // backpressure is not shaping, and charging it here would make
        // `blocked_episodes` non-zero under `DropTail`, where nothing
        // blocks.
        if shape.and_then(Scheduler::blocking_depth).is_some() {
            if !can_read {
                if !blocked {
                    blocked = true;
                    ctx.shape_stats.note_blocked(last_class);
                }
            } else {
                blocked = false;
            }
        }

        tokio::select! {
            source = observe_source(&mut recv, &mut buf, can_read, reset_observable) => {
                let result = match source {
                    Source::Read(result) => result,
                    Source::ResetUnobservable => {
                        reset_observable = false;
                        continue;
                    }
                };
                let chunk = match result {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        let e = ProxyError::from(e);
                        stop.retire();
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: false,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        propagate_reset(&e, &mut send, &mut st, side, ctx, &report).await;
                        return Err(e);
                    }
                };
                match chunk {
                    Some(n) => {
                        let data = &buf[..n];
                        if data.is_empty() {
                            continue;
                        }
                        // The framer sees the stream from its first byte;
                        // the stream-type field belongs to the header
                        // decoder, not to this loop.
                        let framer = framer.get_or_insert_with(|| {
                            let framer = ObjectFramer::with_recorder(
                                detect_stream_type(data[0]),
                                draft,
                                FramerConfig::default(),
                                Arc::clone(&ctx.counters),
                            );
                            // Handed over only where a fetch stream cannot be
                            // read without it, so that a framer holding one on
                            // a draft that needs none could not quietly become
                            // the way the answer is expected to arrive.
                            if fetch_group_order_is_needed(draft) {
                                framer.with_fetch_group_orders(Arc::clone(&ctx.fetch_orders))
                            } else {
                                framer
                            }
                        });
                        framer.feed(data);

                        loop {
                            let arrived_at = Instant::now();
                            // Every arm but `Object` yields bytes no rule can
                            // see — a stream header, an oversized object's
                            // passthrough chunk, a bypassed stream's tail —
                            // so the default tag is `Unshapeable` and only
                            // the object arm overwrites it. They still take
                            // an ordering slot; they just charge no bucket.
                            pending.tag_unit(Class::Unshapeable);
                            let raw = match framer.poll() {
                                FramerOut::NeedMore => break,
                                FramerOut::Header { header, raw } => {
                                    ctx.emit(|| ProxyEvent::DataStreamHeader {
                                        session_id: ctx.session_id,
                                        side,
                                        header: header.clone(),
                                    });
                                    if let DataStreamHeaderKind::Subgroup(h) = &header {
                                        subgroup_id_mode = h.subgroup_id_mode();
                                    }
                                    if ctx.streams_enabled {
                                        let scx = StreamCtx::new(
                                            ctx.session_id,
                                            side,
                                            stream_id,
                                            draft,
                                            false,
                                            &caps,
                                            key,
                                        );
                                        let action =
                                            ctx.hook.on_stream_header(&scx, &header);
                                        let out = exec::execute_stream(
                                            StreamSite::Header,
                                            draft,
                                            action,
                                            &report,
                                        );
                                        // The peer stream already exists, so
                                        // it is reset having carried zero
                                        // payload bytes, and the source is
                                        // stopped. No header byte is
                                        // forwarded.
                                        match out.plan {
                                            Plan::RejectStream { code } => {
                                                stop.retire();
                                                let _ = send.reset(code);
                                                let _ = recv.stop(code);
                                                return Ok(());
                                            }
                                            // Nothing has been written on
                                            // this stream yet — the header's
                                            // own bytes go out below, after
                                            // the match — so holding here
                                            // is the same "write nothing
                                            // until" the open site gives.
                                            // Awaiting inside a `select!`
                                            // arm body suspends the other
                                            // branches, which is why the
                                            // wait races cancellation; the
                                            // release branch already has
                                            // exactly this property.
                                            Plan::SerializeStreamAfter { target } => {
                                                await_serialize_target(
                                                    target, key, ctx, &report,
                                                )
                                                .await;
                                            }
                                            // `OpenAfter` cannot reach here:
                                            // the header site refuses it
                                            // with `WrongSite`, so `admit`
                                            // returned `Err` and the plan is
                                            // `Nothing`.
                                            Plan::OpenStreamAfter { .. } => {}
                                            Plan::Nothing => {}
                                            Plan::WriteNow(_)
                                            | Plan::Terminal
                                            | Plan::CloseSession { .. } => {}
                                        }
                                    }
                                    raw
                                }
                                FramerOut::Object { meta, raw } => {
                                    // ── ADMISSION ──────────────────────
                                    //
                                    // The shaping path's entry point.
                                    // Gated on `ctx.shape`, which is
                                    // `Some` exactly when a profile was
                                    // configured — with no
                                    // `observer_enabled ||` term, exactly
                                    // as the arming gate — so a session
                                    // with no profile adds nothing here
                                    // and its `ShapeStats` stays
                                    // `default()` for the same reason its
                                    // `Counters` do.
                                    //
                                    // `note_object_seen` is taken before
                                    // anything decides: it counts what the
                                    // shaper *saw* on the wire, which must
                                    // not depend on whether a hook was
                                    // also consulted, on what that hook
                                    // returned, or on what a policy did to
                                    // the unit. The class rows below are
                                    // charged from the same `raw.len()`,
                                    // so the conservation identity the
                                    // release side completes is an
                                    // identity over one measurement and
                                    // not two.
                                    if let Some(shaper) = shape {
                                        ctx.shape_stats.note_object_seen(side, raw.len() as u64);
                                        let unit_index = shaped_units;
                                        shaped_units += 1;
                                        last_class = shaper.classify(
                                            side,
                                            &meta,
                                            unit_index,
                                            |class, field| {
                                                report.impairment(
                                                    ImpairmentKind::ShapeRuleUnmatchable {
                                                        class: shaper.class_name(class),
                                                        field,
                                                        draft,
                                                    },
                                                );
                                            },
                                        );
                                        // The class rides with the unit from
                                        // here: `PendingQueue::push` reads
                                        // this tag, so `exec`'s own pushes —
                                        // a `Delay`, a `Hold`, an elided
                                        // ordering slot — are charged to the
                                        // same class without `exec` ever
                                        // naming one.
                                        pending.tag_unit(last_class);
                                        // Two classes on one stream means the
                                        // head decides the whole stream's
                                        // throughput. Said once, with a
                                        // counter behind it, or a caller
                                        // reads head-of-line blocking as
                                        // their configured shaping.
                                        match first_class {
                                            None => first_class = Some(last_class),
                                            Some(first)
                                                if first != last_class && !mixed_reported =>
                                            {
                                                mixed_reported = true;
                                                ctx.shape_stats.note_mixed_class_stream(side);
                                                report.impairment(
                                                    ImpairmentKind::ClassChangedMidStream {
                                                        key,
                                                        stream_id,
                                                    },
                                                );
                                            }
                                            Some(_) => {}
                                        }
                                        // Admission runs **before** the
                                        // hook, and that is the coherent
                                        // choice rather than an accident:
                                        // under `Overflow::Block` a unit
                                        // the queue has no room for is
                                        // never read off the wire at all,
                                        // so the hook never sees it. A
                                        // `DropTail` that showed the hook
                                        // an object the engine had already
                                        // decided to discard would let it
                                        // return `Replace` and report an
                                        // `ActionApplied { Replaced }` for
                                        // a wire change that never
                                        // happened.
                                        match shaper.admit(
                                            raw.len(),
                                            pending.queued_bytes(),
                                            pending.len(),
                                        ) {
                                            Admission::Admit => {}
                                            Admission::DropTail => {
                                                let unit = exec::Unit {
                                                    target: exec::Target::Object {
                                                        meta: &meta,
                                                        subgroup_id_mode,
                                                        raw: raw.clone(),
                                                    },
                                                    draft,
                                                    arrived_at,
                                                };
                                                // A guard that refuses
                                                // leaves the unit admitted
                                                // and the queue one over
                                                // depth: a shaper may not
                                                // corrupt a stream's
                                                // absolute object IDs to
                                                // honour a depth limit.
                                                if exec::shape_elide(&unit, &report) {
                                                    framer.note_elided(&meta);
                                                    ctx.shape_stats
                                                        .note_dropped(last_class, raw.len() as u64);
                                                    if !drop_reported {
                                                        drop_reported = true;
                                                        ctx.emit(|| ProxyEvent::Shaped {
                                                            session_id: ctx.session_id,
                                                            side,
                                                            key,
                                                            stream_id,
                                                            class: class_label(shaper, last_class),
                                                            outcome: ShapeOutcome::Dropped,
                                                        });
                                                    }
                                                    continue;
                                                }
                                            }
                                            Admission::ResetStream { code } => {
                                                ctx.shape_stats.note_stream_reset_by_shaping(side);
                                                // Everything queued is
                                                // discarded by design, not
                                                // lost: the destination is
                                                // gone. The same shape the
                                                // `ElideFixupLost` teardown
                                                // takes — including the
                                                // order, which is reset
                                                // first and report second.
                                                // The event names the code
                                                // the stream was reset with,
                                                // and an event that names a
                                                // reset the transport has
                                                // not been asked for yet is
                                                // a claim rather than a
                                                // record.
                                                pending.clear();
                                                deferred.clear();
                                                stop.retire();
                                                let _ = send.reset(code);
                                                ctx.emit(|| ProxyEvent::Shaped {
                                                    session_id: ctx.session_id,
                                                    side,
                                                    key,
                                                    stream_id,
                                                    // A stream reset is
                                                    // about the stream, not
                                                    // about the unit that
                                                    // tripped it, so it
                                                    // carries no class.
                                                    class: String::new(),
                                                    outcome: ShapeOutcome::StreamReset { code },
                                                });
                                                return Ok(());
                                            }
                                        }
                                    }
                                    ctx.emit(|| ProxyEvent::Object {
                                        session_id: ctx.session_id,
                                        side,
                                        meta,
                                    });
                                    if !ctx.object_hook {
                                        raw
                                    } else {
                                        let ocx = ObjectCtx::new(
                                            ctx.session_id,
                                            side,
                                            stream_id,
                                            &meta,
                                            arrived_at,
                                            &caps,
                                        );
                                        let action = ctx.hook.on_object(&ocx, &raw);
                                        let unit = exec::Unit {
                                            target: exec::Target::Object {
                                                meta: &meta,
                                                subgroup_id_mode,
                                                raw: raw.clone(),
                                            },
                                            draft,
                                            arrived_at,
                                        };
                                        let mut engine = exec::Engine {
                                            queue: Some(exec::Queue {
                                                pending: &mut pending,
                                                deferred: &mut deferred,
                                            }),
                                            closer: &ctx.closer,
                                        };
                                        let out =
                                            exec::execute(&unit, action, &mut engine, &report);
                                        if out.note_elided {
                                            framer.note_elided(&meta);
                                        }
                                        match out.plan {
                                            Plan::WriteNow(bytes) => {
                                                if let Err(e) =
                                                    send.write_all(&bytes).await
                                                {
                                                    let e = ProxyError::from(e);
                                                    let mut st = StreamState {
                                                        stream_id,
                                                        key,
                                                        is_control_stream: false,
                                                        pending: &mut pending,
                                                        deferred: &mut deferred,
                                                    };
                                                    propagate_stop(
                                                        &e, &mut recv, &mut st, side, ctx,
                                                        &report,
                                                    );
                                                    return Err(e);
                                                }
                                            }
                                            Plan::Nothing => {}
                                            Plan::Terminal => {
                                                let mut st = StreamState {
                                                    stream_id,
                                                    key,
                                                    is_control_stream: false,
                                                    pending: &mut pending,
                                                    deferred: &mut deferred,
                                                };
                                                let drained = drain_pending(
                                                    &mut send,
                                                    &mut st,
                                                    Site::Object,
                                                    shaped_stream.as_ref(),
                                                    ctx,
                                                    &report,
                                                )
                                                .await;
                                                // The source has not FINed, so
                                                // a `STOP_SENDING` surfacing on
                                                // the terminal's own write must
                                                // still be mirrored upstream.
                                                if let Err(e) = drained {
                                                    let mut st = StreamState {
                                                        stream_id,
                                                        key,
                                                        is_control_stream: false,
                                                        pending: &mut pending,
                                                        deferred: &mut deferred,
                                                    };
                                                    propagate_stop(
                                                        &e, &mut recv, &mut st, side, ctx,
                                                        &report,
                                                    );
                                                    return Err(e);
                                                }
                                                // The destination is reset;
                                                // dropping `recv` stops the
                                                // source, which is what the
                                                // pass-through path has
                                                // always done.
                                                return Ok(());
                                            }
                                            // Only `execute_stream` can
                                            // produce these three, and it is
                                            // called from the two stream
                                            // decision sites, never here.
                                            // Handled rather than
                                            // `unreachable!()`d: a panicking
                                            // forwarding task is worse than a
                                            // redundant arm.
                                            Plan::RejectStream { .. }
                                            | Plan::OpenStreamAfter { .. }
                                            | Plan::SerializeStreamAfter { .. } => {}
                                            Plan::CloseSession { .. } => return Ok(()),
                                        }
                                        continue;
                                    }
                                }
                                FramerOut::Passthrough(raw) => {
                                    // A `Passthrough` on a stream the framer
                                    // is still parsing is an object too big
                                    // to buffer: its `ObjectMeta` was decoded
                                    // and discarded, so nothing outside the
                                    // framer can address it. Said once per
                                    // stream; the counter keeps the total.
                                    if !not_addressable_reported && !framer.is_bypassed() {
                                        not_addressable_reported = true;
                                        report.impairment(
                                            ImpairmentKind::ObjectNotAddressable {
                                                stream_id,
                                                total: 1,
                                            },
                                        );
                                    }
                                    // ...and on a shaped session it is not
                                    // merely unaddressable, it is unpaced.
                                    // These bytes carry no `ObjectMeta`, so
                                    // no rule claims them and the release
                                    // seam grants them without asking a
                                    // bucket — one object crosses a class's
                                    // rate whole. `ShapeStats::unshapeable`
                                    // already holds the figure; what it
                                    // cannot say is whose ceiling it went
                                    // over, so the report names the class
                                    // this stream's classified units are
                                    // charged to. Once per stream, like the
                                    // report above and for the same reason.
                                    if let Some(shaper) = shape {
                                        if !unpaced_reported {
                                            unpaced_reported = true;
                                            report.impairment(
                                                ImpairmentKind::ShapeUnpacedObject {
                                                    class: class_label(shaper, last_class),
                                                    stream_id,
                                                    bytes: raw.len() as u64,
                                                },
                                            );
                                        }
                                    }
                                    raw
                                }
                                FramerOut::Bypassed { reason, fixup_owed } => {
                                    report.impairment(ImpairmentKind::FramerBypass {
                                        stream_id,
                                        draft,
                                        reason,
                                    });
                                    // `FramerBypass` is the whole report, and
                                    // that is a change. A fetch stream on
                                    // drafts 18 and 19 used to bypass on
                                    // every session, so a `Fetch`-aimed class
                                    // there could never fire and was told so
                                    // once per session as
                                    // `ShapeRuleUnmatchable`. Such a stream
                                    // is framed now whenever the session
                                    // carried its FETCH, so the same report
                                    // would claim a working class is dead on
                                    // the strength of one stream that named a
                                    // request nobody made.
                                    if fixup_owed {
                                        // An elide fix-up was still owed when
                                        // parsing stopped, so every later
                                        // object on this stream would carry a
                                        // stale delta. The destination is
                                        // reset rather than fed bytes that
                                        // decode to the wrong Object IDs.
                                        //
                                        // The reset goes first and the report
                                        // second. The event names the code the
                                        // destination was reset with, so
                                        // emitting it above `send.reset` would
                                        // be describing a wire change that had
                                        // not been made yet — and this arm has
                                        // no second event to correct it with.
                                        pending.clear();
                                        deferred.clear();
                                        stop.retire();
                                        let _ = send.reset(0);
                                        report.impairment(ImpairmentKind::ElideFixupLost {
                                            stream_id,
                                            reason,
                                            code: 0,
                                        });
                                        return Ok(());
                                    }
                                    // Carries no bytes: nothing to forward.
                                    continue;
                                }
                                FramerOut::Error(error) => {
                                    ctx.emit(|| ProxyEvent::ParseError {
                                        session_id: ctx.session_id,
                                        side,
                                        error: error.clone(),
                                    });
                                    continue;
                                }
                            };

                            // On a shaped stream every byte is queued, never
                            // written inline. `write_in_order` would do two
                            // wrong things here: let these bytes escape the
                            // pacer, and — because it drains honouring
                            // release times first — block this arm body for
                            // as long as the bucket took, with no other
                            // branch polled.
                            if shape.is_some() {
                                exec::enqueue_unshown(
                                    &mut pending,
                                    &mut deferred,
                                    raw,
                                    &report,
                                );
                                continue;
                            }
                            let mut st = StreamState {
                                stream_id,
                                key,
                                is_control_stream: false,
                                pending: &mut pending,
                                deferred: &mut deferred,
                            };
                            match write_in_order(&raw, &mut send, &mut st, ctx, &report).await {
                                Ok(Flow::Continue) => {}
                                Ok(Flow::StreamOver) => return Ok(()),
                                Err(e) => {
                                    let mut st = StreamState {
                                        stream_id,
                                        key,
                                        is_control_stream: false,
                                        pending: &mut pending,
                                        deferred: &mut deferred,
                                    };
                                    propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                                    return Err(e);
                                }
                            }
                        }
                    }
                    None => {
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: false,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        // Anything the hook deferred goes out at its release
                        // time, as a race against cancellation.
                        if drain_pending(&mut send, &mut st, Site::Object, shaped_stream.as_ref(), ctx, &report).await?
                            == Flow::StreamOver
                        {
                            return Ok(());
                        }
                        // Anything still buffered belongs to a truncated
                        // final object. Forward it, or the peer's clean
                        // FIN silently loses bytes.
                        if let Some(framer) = framer.as_mut() {
                            if let Some(tail) = framer.finish() {
                                if let Err(e) = send.write_all(&tail).await {
                                    let e = ProxyError::from(e);
                                    let mut st = StreamState {
                                        stream_id,
                                        key,
                                        is_control_stream: false,
                                        pending: &mut pending,
                                        deferred: &mut deferred,
                                    };
                                    propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                                    return Err(e);
                                }
                            }
                        }
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: false,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        match run_stream_end(StreamEnd::Fin, &mut st, side, ctx, &report) {
                            // `ResetStream` at the data stream's end: the
                            // clean FIN becomes a reset carrying the code.
                            Plan::Terminal => {
                                let _ = drain_pending(
                                    &mut send,
                                    &mut st,
                                    Site::Object,
                                    shaped_stream.as_ref(),
                                    ctx,
                                    &report,
                                )
                                .await?;
                                return Ok(());
                            }
                            Plan::CloseSession { .. } => return Ok(()),
                            _ => {}
                        }
                        ctx.emit(|| ProxyEvent::StreamClosed {
                            session_id: ctx.session_id,
                            side,
                        });
                        let _ = send.finish();
                        return Ok(());
                    }
                }
            }
            () = egress::wait_release(head_release.clone(), &ctx.cancel),
                if head_release.is_some() =>
            {
                // The deferred-release half of stop propagation, and
                // structurally the same gap:
                // this write can fail with the destination peer's
                // `STOP_SENDING` exactly like the seven inline write sites,
                // and on a stream whose hook defers it is the *only* write
                // there is. A bare `?` returns without mirroring, `recv` is
                // dropped, and quinn's `RecvStream::drop` stops the source
                // with a hard-coded 0.
                //
                // The stream-level `StopWatcher` branch does not cover
                // this. Once `select!` has picked this branch its arm body
                // runs to completion with no branch polling at all, so a
                // `STOP_SENDING` that lands while `release_due_units` is
                // inside `write_all` surfaces here and nowhere else.
                let released = release_due_units(
                    &mut pending,
                    &mut deferred,
                    &mut send,
                    Site::Object,
                    shaped_stream.as_ref(),
                    ctx,
                    &report,
                )
                .await;
                match released {
                    Ok(Flow::StreamOver) => return Ok(()),
                    Ok(Flow::Continue) => {}
                    Err(e) => {
                        let mut st = StreamState {
                            stream_id,
                            key,
                            is_control_stream: false,
                            pending: &mut pending,
                            deferred: &mut deferred,
                        };
                        propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                        return Err(e);
                    }
                }
            }
            command = requests.recv(), if serving_requests => {
                match data_stream_request(command) {
                    StreamRequest::Reset(code) => {
                        // The same shape the shaping reset and the
                        // `ElideFixupLost` teardown take: everything queued
                        // is discarded by design rather than lost, because
                        // the destination is being abandoned.
                        pending.clear();
                        deferred.clear();
                        stop.retire();
                        let _ = send.reset(code);
                        let _ = recv.stop(code);
                        return Ok(());
                    }
                    StreamRequest::Ignore => {}
                    StreamRequest::Closed => serving_requests = false,
                }
            }
            outcome = stop.watch(), if watching => {
                // The idle case on the framed path: a hook that holds or
                // delays leaves long stretches with no write at all, and
                // without this branch the source is not stopped until the
                // next one.
                if let Some(e) = stop_error(outcome) {
                    let mut st = StreamState {
                        stream_id,
                        key,
                        is_control_stream: false,
                        pending: &mut pending,
                        deferred: &mut deferred,
                    };
                    propagate_stop(&e, &mut recv, &mut st, side, ctx, &report);
                    return Err(e);
                }
            }
            _ = ctx.cancel.cancelled() => {
                // Session teardown. Delivered late beats lost silently:
                // everything queued goes out ignoring release times, then
                // whatever the framer holds, so a mid-object cancel does
                // not drop bytes the peer already sent. Then fall through
                // to the same FIN-on-drop the pass-through path takes.
                let _ = pending.drain_ignoring_release_times(&mut send).await;
                // `unconfirmed_bytes`, not `queued_bytes`. The drain above
                // hands its units to quinn, which buffers them and returns
                // `Ok`; `run_with_transport` then closes the connection and
                // they never reach the peer. Reporting the residue reports
                // zero and the object is silently gone — see
                // `PendingQueue::unconfirmed_bytes`.
                let stranded = pending.unconfirmed_bytes();
                if stranded > 0 {
                    report.impairment(ImpairmentKind::QueuedBytesAtTeardown {
                        stream_id,
                        bytes: stranded,
                    });
                }
                if let Some(framer) = framer.as_mut() {
                    if let Some(tail) = framer.finish() {
                        let _ = send.write_all(&tail).await;
                    }
                }
                return Ok(());
            }
        }
    }
}

/// The [`ActionKind`] a returned [`Action`] will be reported as.
///
/// Needed only on the datagram path, where the transport can reject an
/// action the engine admitted and `ActionFailed` has to name it.
///
/// Exhaustive on purpose, with no catch-all: `Action` is
/// `#[non_exhaustive]` only for other crates, so a variant added here
/// stops this file compiling rather than being silently reported as
/// `Pass`.
fn action_kind(action: &Action) -> ActionKind {
    match action {
        Action::Pass => ActionKind::Pass,
        Action::Replace(_) => ActionKind::Replace,
        Action::ReplacePayload(_) => ActionKind::ReplacePayload,
        Action::Drop(_) => ActionKind::DropElide,
        Action::Delay { .. } => ActionKind::Delay,
        Action::Hold { .. } => ActionKind::Hold,
        Action::Truncate { .. } => ActionKind::Truncate,
        Action::ResetStream { .. } => ActionKind::ResetStream,
        Action::CloseSession { .. } => ActionKind::CloseSession,
    }
}

/// Whether a `send_datagram` failure ends the session.
///
/// Only connection-level failures do. A datagram the transport refused —
/// a payload above the path MTU is the obvious one — is reported and
/// forgotten: the session survives, on every interest, hooked or not.
fn is_connection_level(err: &TransportError) -> bool {
    matches!(err, TransportError::ConnectionLost | TransportError::Connection(_))
}

/// Whether a decoded datagram header carries an Object Status.
///
/// A status datagram has no payload slot at all, so `ReplacePayload` has
/// nothing to splice after and is refused there. There is no uniform
/// codec accessor for this yet — `AnyDatagramHeader`'s per-draft types
/// disagree on both the field's name and its shape — so the match is here,
/// one arm per enabled draft feature, in the same shape
/// `dispatch.rs`'s own accessors generate. Drafts 07-13 each answer for
/// themselves, because where a status can be stated moves twice across
/// them: draft-07 hangs it off a declared payload length of zero, draft-08
/// accepts that and adds a dedicated status message, and draft-09 drops
/// the zero-length form and keeps only the message.
#[allow(unused_variables)]
fn datagram_is_status(header: &AnyDatagramHeader) -> bool {
    match header {
        #[cfg(feature = "draft07")]
        AnyDatagramHeader::Draft07(h) => h.is_status(),
        #[cfg(feature = "draft08")]
        AnyDatagramHeader::Draft08(h) => h.is_status(),
        #[cfg(feature = "draft09")]
        AnyDatagramHeader::Draft09(h) => h.is_status(),
        #[cfg(feature = "draft10")]
        AnyDatagramHeader::Draft10(h) => h.is_status(),
        #[cfg(feature = "draft11")]
        AnyDatagramHeader::Draft11(h) => h.is_status(),
        #[cfg(feature = "draft12")]
        AnyDatagramHeader::Draft12(h) => h.is_status(),
        #[cfg(feature = "draft13")]
        AnyDatagramHeader::Draft13(h) => h.is_status(),
        #[cfg(feature = "draft14")]
        AnyDatagramHeader::Draft14(h) => h.status.is_some(),
        #[cfg(feature = "draft15")]
        AnyDatagramHeader::Draft15(h) => h.object_status.is_some(),
        #[cfg(feature = "draft16")]
        AnyDatagramHeader::Draft16(h) => h.object_status.is_some(),
        #[cfg(feature = "draft17")]
        AnyDatagramHeader::Draft17(h) => h.object_status.is_some(),
        #[cfg(feature = "draft18")]
        AnyDatagramHeader::Draft18(h) => h.object_status.is_some(),
        #[cfg(feature = "draft19")]
        AnyDatagramHeader::Draft19(h) => h.object_status.is_some(),
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Forward datagrams from source to destination.
///
/// Datagrams have no queue: they are per-connection and unordered by
/// definition, so a FIFO would impose ordering the protocol does not have.
/// `Delay` and `Hold` are refused at this site.
///
/// # Datagrams are policed, not paced
///
/// A datagram is admitted or discarded on arrival, against its class's
/// bucket, and never queued. That is not a reduced form of what the stream
/// path does — it is the only sound form for this carrier. A queue would
/// impose a delivery order the protocol does not have, and there is nothing
/// a delay could protect: a datagram carries one Object whole, has no
/// successor whose framing is written against it and no stream whose object
/// IDs would need renumbering behind a hole. So the two things that make a
/// stream unit's discard expensive are both absent, and the arriving unit is
/// the right one to drop.
///
/// The decision is taken **before** the hook, exactly as stream admission
/// is, and for the same reason: showing a hook a unit the engine has already
/// decided to discard would let it return `Replace` and report an
/// `ActionApplied` for a wire change that never happened.
///
/// [`Class::Default`] and [`Class::Unshapeable`] name no bucket, so an
/// unclaimed datagram and one whose header did not decode are both admitted
/// unconditionally — which is what makes a configured class's figures mean
/// something rather than absorbing everything the session sent.
///
/// Cost to an unshaped session: one `Option::as_ref` per datagram, and no
/// header decode it was not already doing — `tests/interest_none.rs`
/// compares a whole `Counters` and a byte pump, and this must not move
/// either.
async fn forward_datagrams(
    source: &Transport,
    dest: &Transport,
    side: ProxySide,
    ctx: &ForwardCtx,
) -> Result<(), ProxyError> {
    let report = ctx.reporter(side, None);

    // The same ordering edge the framed data pipe takes, and here for the
    // same reason: a datagram header decodes under one draft's codec, and on
    // the `moq-00` cohort the draft is named on the control stream by a task
    // this one was spawned alongside. Taken before the report below as well
    // as before the loop, because that report names the draft it judged the
    // profile against and a report naming the guess would send an author
    // looking at the wrong column.
    let draft = ctx.resolved_draft().await;
    let caps = Capabilities::for_draft(draft);

    // Shaper-visible datagrams on this direction, which is the only scope a
    // datagram has: it belongs to no stream, so `Matcher::every_nth` counts
    // per forwarding task and the session's two directions count apart.
    let mut shaped_units: u64 = 0;
    // Edge-triggering for `note_tokens_exhausted`, which counts episodes
    // rather than units — the per-direction analogue of the per-stream latch
    // the queue keeps. Without it a class configured below the arrival rate
    // reports one episode per datagram, which is a throughput figure wearing
    // an episode's name.
    let mut tokens_dry = false;
    // `ProxyEvent::ShapedDatagram` is once per direction per outcome, for the
    // reason the event says: a per-datagram event would drown an observer at
    // line rate, and the running totals are in `ShapeStats`.
    let mut policed_reported = false;

    loop {
        tokio::select! {
            result = source.recv_datagram() => {
                let data = result?;
                let arrived_at = Instant::now();

                // Decode only when someone will read it: an observer, or a
                // hook that asked for datagrams.
                let mut header: Option<AnyDatagramHeader> = None;
                let mut header_len: Option<usize> = None;
                let mut is_status = false;
                // `shaping_enabled` joins the two readers here because a
                // class keyed on a track alias, a Location or a priority
                // needs the header to have been read. A profile with no such
                // class still pays for it, which is the same bargain the
                // framed path takes: `objects_enabled` frames every stream
                // for a profile that might key on nothing.
                if ctx.observer_enabled || ctx.datagram_hook || ctx.shaping_enabled {
                    let mut cursor = &data[..];
                    if let Ok(decoded) = AnyDatagramHeader::decode(draft, &mut cursor) {
                        ctx.counters.note_datagram_header_decoded();
                        header_len = Some(data.len() - cursor.len());
                        is_status = datagram_is_status(&decoded);
                        if ctx.observer_enabled {
                            ctx.observer.on_event(&ProxyEvent::Datagram {
                                session_id: ctx.session_id,
                                side,
                                header: decoded.clone(),
                                payload_len: cursor.len(),
                            });
                        }
                        header = Some(decoded);
                    }
                }


                // ── POLICING ────────────────────────────────────────
                //
                // Gated on `ctx.shape`, which is `Some` exactly when a
                // profile was configured, with no `observer_enabled ||`
                // term — attaching an observer must not arm shaping.
                let unit_len = data.len() as u64;
                let mut policed_class = None;
                if let Some(shaper) = ctx.shape.as_ref().map(|s| s.current()) {
                    let class = match header.as_ref() {
                        Some(decoded) => {
                            // `note_object_seen` before anything decides,
                            // exactly as the framed path takes it: it counts
                            // what the shaper saw, which must not depend on
                            // what a rule or a bucket then did with it.
                            ctx.shape_stats.note_object_seen(side, unit_len);
                            let meta = decoded.meta();
                            let unit_index = shaped_units;
                            shaped_units += 1;
                            shaper.classify_datagram(
                                side,
                                draft,
                                &meta,
                                unit_index,
                                |class, field| {
                                    report.impairment(ImpairmentKind::ShapeRuleUnmatchable {
                                        class: shaper.class_name(class),
                                        field,
                                        draft,
                                    });
                                },
                            )
                        }
                        // A datagram whose header did not decode has no
                        // identity for a rule to name, so no rule can claim
                        // it and no bucket charges it — the same answer, and
                        // the same row, an object too large for the framer to
                        // buffer gets.
                        None => {
                            ctx.shape_stats.note_unshapeable_seen(side, unit_len);
                            Class::Unshapeable
                        }
                    };

                    match shaper.acquire(class, unit_len, arrived_at) {
                        Acquire::Now => {
                            tokens_dry = false;
                            policed_class = Some(class);
                        }
                        refusal => {
                            // Four refusals, two causes, and the crate keeps
                            // them apart everywhere else: a bucket that had
                            // nothing is not a class held back by a rival.
                            if matches!(refusal, Acquire::Starved(_)) {
                                ctx.shape_stats.note_starved(class);
                            } else if !tokens_dry {
                                tokens_dry = true;
                                ctx.shape_stats.note_tokens_exhausted(class);
                            }
                            ctx.shape_stats.note_dropped(class, unit_len);
                            if !policed_reported {
                                policed_reported = true;
                                let label = class_label(&shaper, class);
                                ctx.emit(|| ProxyEvent::ShapedDatagram {
                                    session_id: ctx.session_id,
                                    side,
                                    class: label,
                                    outcome: ShapeOutcome::Policed,
                                });
                            }
                            continue;
                        }
                    }
                }
                if !ctx.datagram_hook {
                    // The un-hooked branch, which is what an
                    // `Interest::NONE` session takes. A rejected datagram
                    // is reported and forgotten rather than ending the
                    // session: `ActionFailed` cannot be used, because
                    // nobody took an action on it.
                    if let Some(class) = policed_class {
                        ctx.shape_stats.note_delivered(side, class, unit_len);
                    }
                    if let Err(e) = dest.send_datagram(data) {
                        if is_connection_level(&e) {
                            return Err(ProxyError::from(e));
                        }
                        report.impairment(ImpairmentKind::DatagramNotSent {
                            error: e.to_string(),
                        });
                    }
                    continue;
                }

                // The hook fires even when the header did not decode: an
                // undecodable datagram is exactly the case a hook wants
                // to see, and `header: None` is what tells it apart.
                let cx = FrameCtx::new(
                    ctx.session_id,
                    side,
                    draft,
                    None,
                    arrived_at,
                    &caps,
                );
                let action = ctx.hook.on_datagram(&cx, header.as_ref(), &data);
                let kind = action_kind(&action);
                let unit = exec::Unit {
                    target: exec::Target::Datagram {
                        raw: data.clone(),
                        header_len,
                        is_status,
                    },
                    draft,
                    arrived_at,
                };
                let mut engine = exec::Engine { queue: None, closer: &ctx.closer };
                let out = exec::execute(&unit, action, &mut engine, &report);
                let admitted = out.is_applied();

                match out.plan {
                    Plan::WriteNow(bytes) => {
                        // Charged where the shaper hands the unit onward,
                        // which is where the queue charges a stream unit —
                        // before the write, so a transport that refuses the
                        // datagram is one impairment rather than also a hole
                        // in the conservation identity. A datagram the *hook*
                        // dropped is never charged, exactly as an object the
                        // hook dropped never reaches the queue.
                        if let Some(class) = policed_class {
                            ctx.shape_stats.note_delivered(side, class, bytes.len() as u64);
                        }
                        if let Err(e) = dest.send_datagram(bytes) {
                            if is_connection_level(&e) {
                                return Err(ProxyError::from(e));
                            }
                            if admitted {
                                // The action was admitted and the transport
                                // rejected it. Neither applied nor refused
                                // would be true.
                                report.failed(Site::Datagram, kind, e.to_string());
                            } else {
                                report.impairment(ImpairmentKind::DatagramNotSent {
                                    error: e.to_string(),
                                });
                            }
                        }
                    }
                    Plan::Nothing => {}
                    Plan::CloseSession { .. } => return Ok(()),
                    // Stream-shaped plans; `execute` at the datagram site
                    // cannot produce one, and a panic here would be worse
                    // than a redundant arm.
                    Plan::Terminal
                    | Plan::RejectStream { .. }
                    | Plan::OpenStreamAfter { .. }
                    | Plan::SerializeStreamAfter { .. } => {}
                }
            }
            _ = ctx.cancel.cancelled() => {
                return Ok(());
            }
        }
    }
}

/// Determine the encoded length of a QUIC varint from its first byte.
fn varint_len(first_byte: u8) -> usize {
    1 << (first_byte >> 6)
}

/// The most bytes a control stream is buffered for while its first message
/// is peeked at.
///
/// Not a protocol limit. It bounds how long a session that opened a control
/// stream and wrote something unreadable on it keeps the tasks waiting for
/// its draft: past this, the session keeps the draft it started with and
/// says so.
const DETECT_BUF_MAX: usize = 64 * 1024;

/// What [`peek_draft`] made of a control stream's opening bytes.
///
/// Three answers rather than an `Option`, because "not yet" and "not ever"
/// have opposite consequences: one says keep buffering and keep the tasks
/// waiting, the other says stop both. Collapsing them is what made a stream
/// that opens with anything but a SETUP buffer 64 KiB before giving up, and
/// a stream that never sends that much never gave up at all.
enum DraftPeek {
    /// The first message names this draft.
    Named(DraftVersion),
    /// Too few bytes so far. Buffer more and ask again.
    NeedMore,
    /// The first message is not a SETUP this peek can read, and no number
    /// of further bytes will change that: the type varint is already whole
    /// and it is not one of the four this function knows.
    NotSetup,
}

/// Which [`DraftSource`] a SETUP peeked at on `side` carries.
///
/// A CLIENT_SETUP lists what the client will accept; a SERVER_SETUP names
/// the one the server picked out of that list. The second is the session's
/// actual version, so it outranks the first — see [`DraftSource`].
fn setup_rank(side: ProxySide) -> DraftSource {
    match side {
        ProxySide::ClientToProxy | ProxySide::ProxyToRelay => DraftSource::Offered,
        ProxySide::RelayToProxy | ProxySide::ProxyToClient => DraftSource::Selected,
    }
}

/// Try to name the concrete draft by peeking at the first SETUP message on a
/// control stream.
///
/// - On the `ClientToProxy` direction, looks at CLIENT_SETUP's
///   `supported_versions` list and returns the highest draft in the 07–14
///   range we support.
/// - On the `RelayToProxy` direction, looks at SERVER_SETUP's
///   `selected_version` and returns the matching draft.
/// - For draft-15+ the SETUP carries no version, but those cases don't
///   reach this function because the caller only invokes it when the
///   draft isn't already fixed by ALPN.
fn peek_draft(buf: &[u8], side: ProxySide) -> DraftPeek {
    if buf.is_empty() {
        return DraftPeek::NeedMore;
    }

    // Decode the message type varint. The first byte's top two bits give
    // the varint length. For drafts 07–10 the type is 0x40/0x41, encoded
    // as a 2-byte varint. For drafts 11–16 it's 0x20/0x21, a 1-byte varint.
    //
    // This peek only ever resolves a draft in the moq-00 cohort (07–14), so
    // RFC 9000 is the right encoding throughout. Draft-15+ are settled by
    // ALPN before any bytes arrive, and from draft-17 both the type id
    // (0x2F00) and the varint encoding itself changed; such a SETUP falls out
    // of the match below as an unrecognized type.
    let type_len = varint_len(buf[0]);
    if buf.len() < type_len {
        return DraftPeek::NeedMore;
    }
    let mut cur = &buf[..type_len];
    let Ok(type_id) = VarInt::decode(&mut cur).map(VarInt::into_inner) else {
        return DraftPeek::NotSetup;
    };

    // Distinguish framing by the type id:
    //   0x40 = CLIENT_SETUP (drafts 07–10, varint length)
    //   0x41 = SERVER_SETUP (drafts 07–10, varint length)
    //   0x20 = CLIENT_SETUP (drafts 11+, u16-BE length)
    //   0x21 = SERVER_SETUP (drafts 11+, u16-BE length)
    //
    // Anything else is `NotSetup` rather than `NeedMore`, and that is the
    // whole reason for the distinction: the type varint is decided by bytes
    // that have already arrived, so a stream opening with something else
    // will never open with a SETUP however long it is buffered.
    let (is_client_setup, is_server_setup, uses_u16_length) = match type_id {
        0x40 => (true, false, false),
        0x41 => (false, true, false),
        0x20 => (true, false, true),
        0x21 => (false, true, true),
        _ => return DraftPeek::NotSetup,
    };

    // The message we peek at is the one we'd expect to see first on this
    // direction. Anything else is bytes this direction cannot read a version
    // out of — the other direction's SETUP, most likely — and no amount of
    // further buffering makes it readable here.
    match side {
        ProxySide::ClientToProxy | ProxySide::ProxyToRelay if !is_client_setup => {
            return DraftPeek::NotSetup
        }
        ProxySide::RelayToProxy | ProxySide::ProxyToClient if !is_server_setup => {
            return DraftPeek::NotSetup
        }
        _ => {}
    }

    let (payload_start, payload_len) = if uses_u16_length {
        if buf.len() < type_len + 2 {
            return DraftPeek::NeedMore;
        }
        let len = ((buf[type_len] as usize) << 8) | (buf[type_len + 1] as usize);
        (type_len + 2, len)
    } else {
        if buf.len() <= type_len {
            return DraftPeek::NeedMore;
        }
        let vl = varint_len(buf[type_len]);
        if buf.len() < type_len + vl {
            return DraftPeek::NeedMore;
        }
        let mut cur = &buf[type_len..type_len + vl];
        let Ok(v) = VarInt::decode(&mut cur) else {
            return DraftPeek::NotSetup;
        };
        (type_len + vl, v.into_inner() as usize)
    };

    if buf.len() < payload_start + payload_len {
        return DraftPeek::NeedMore;
    }
    let payload = &buf[payload_start..payload_start + payload_len];

    // From here the message is whole, so every remaining failure is a
    // property of its contents: a version list this build has no draft for
    // is `NotSetup`, not `NeedMore`.
    if is_client_setup {
        // CLIENT_SETUP (draft 07–14): number_of_supported_versions (varint)
        // then that many version varints. Pick the highest draft we
        // support in the moq-00 cohort (07–14).
        let mut cur = payload;
        let Ok(count) = VarInt::decode(&mut cur).map(VarInt::into_inner) else {
            return DraftPeek::NotSetup;
        };
        let mut best: Option<DraftVersion> = None;
        for _ in 0..count {
            let Ok(v) = VarInt::decode(&mut cur).map(VarInt::into_inner) else {
                return DraftPeek::NotSetup;
            };
            if let Some(d) = version_varint_to_draft(v) {
                if (7..=14).contains(&d.number()) {
                    best = Some(match best {
                        Some(b) if b.number() >= d.number() => b,
                        _ => d,
                    });
                }
            }
        }
        best.map_or(DraftPeek::NotSetup, DraftPeek::Named)
    } else {
        // SERVER_SETUP (draft 07–14): selected_version (varint) then
        // parameters. We only need the first varint.
        let mut cur = payload;
        let Ok(v) = VarInt::decode(&mut cur).map(VarInt::into_inner) else {
            return DraftPeek::NotSetup;
        };
        match version_varint_to_draft(v) {
            Some(d) if (7..=14).contains(&d.number()) => DraftPeek::Named(d),
            _ => DraftPeek::NotSetup,
        }
    }
}

/// Convert an on-wire MoQT version varint (`0xff000000 + draft`) to a
/// `DraftVersion`, or `None` if the value is malformed or unsupported.
fn version_varint_to_draft(v: u64) -> Option<DraftVersion> {
    const BASE: u64 = 0xff000000;
    if !(BASE..=BASE + 255).contains(&v) {
        return None;
    }
    DraftVersion::from_number((v - BASE) as u8)
}

/// TLS certificate verifier that skips all verification (testing only).
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures build SETUP bytes with a local varint encoder rather
    // than through `moqtap_codec::draftNN::message`. Two reasons, and they
    // are the same two the acceptance suite gives: a test that encodes with
    // the decoder it is testing cannot see a shared misunderstanding of the
    // wire format, and naming a per-draft codec module here would break every
    // reduced-draft build of this crate.

    /// Encode a QUIC variable-length integer.
    fn varint(v: u64, out: &mut Vec<u8>) {
        match v {
            0..=63 => out.push(v as u8),
            64..=16_383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
            16_384..=1_073_741_823 => {
                out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
            }
            _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
        }
    }

    /// `[type varint][payload length varint][payload]` — drafts 07–10.
    fn frame_varint_length(type_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint(type_id, &mut out);
        varint(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    /// `[type varint][payload length u16-BE][payload]` — drafts 11+.
    fn frame_u16_length(type_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint(type_id, &mut out);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    // ── Control-stream message boundaries ───────────────────────────
    //
    // `ControlFrameWalker` is the only thing on the pass-through control
    // pipe that knows where one message ends and the next begins, and an
    // injection placed anywhere else desynchronizes the peer's decoder for
    // the rest of the session. These tests are byte-level on purpose: the
    // walker's whole job is arithmetic over the framing, and driving a live
    // session to check it would test the transport's chunking instead.

    /// Two messages, fed as one read, and the walker names the seam.
    ///
    /// The fixed-length framing (drafts 11 and later): type varint, then a
    /// sixteen-bit big-endian length.
    ///
    /// *Ablation, recorded:* have `advance` return the **last** boundary in
    /// the chunk rather than the first — change `if first.is_none()` to an
    /// unconditional assignment. The `Some(first.len())` assertion below
    /// goes red with the real message
    ///
    /// ```text
    /// assertion `left == right` failed: the seam is where the first message
    /// ends, so an injection goes between the two rather than after both
    ///   left: Some(13)
    ///  right: Some(7)
    /// ```
    ///
    /// which is the injection arriving one message later than it could
    /// have — correct on the wire, and later than the caller asked for.
    #[test]
    fn the_walker_names_the_seam_between_two_messages() {
        let first = frame_u16_length(0x40, &[1, 2, 3]);
        let second = frame_u16_length(0x41, &[9, 9]);
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let mut walker = ControlFrameWalker::new(DraftVersion::Draft14);
        assert!(walker.at_boundary(), "the start of a control stream is a boundary");
        assert_eq!(
            walker.advance(&stream),
            Some(first.len()),
            "the seam is where the first message ends, so an injection goes between the two \
             rather than after both"
        );
        assert!(walker.at_boundary(), "both messages are whole, so the stream ends on a boundary");
        assert!(!walker.is_mid_message());
    }

    /// A message split across two reads has its boundary found on the read
    /// that completes it, and none on the read that does not.
    ///
    /// This is the case the walker exists for. The pass-through pipe writes
    /// whatever `recv.read` returned, so without this the byte after any
    /// chunk would be taken for a message boundary — and half of them are
    /// in the middle of a payload.
    #[test]
    fn a_message_split_across_reads_offers_no_boundary_until_it_completes() {
        let message = frame_u16_length(0x40, &[7; 40]);
        let cut = 12;

        let mut walker = ControlFrameWalker::new(DraftVersion::Draft14);
        assert_eq!(walker.advance(&message[..cut]), None, "a partial message reaches no seam");
        assert!(!walker.at_boundary(), "an injection here would land inside the payload");
        assert!(walker.is_mid_message(), "and a teardown here truncates a message");

        assert_eq!(walker.advance(&message[cut..]), Some(message.len() - cut));
        assert!(walker.at_boundary());
        assert!(!walker.is_mid_message());
    }

    /// The earlier framing — a varint payload length, drafts 07 to 10 — is
    /// walked too, and the walker is built from the session's draft rather
    /// than assuming one.
    #[test]
    fn the_walker_reads_the_varint_length_framing() {
        let first = frame_varint_length(0x40, &[1, 2, 3, 4]);
        let second = frame_varint_length(0x41, &[]);
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let mut walker = ControlFrameWalker::new(DraftVersion::Draft09);
        assert_eq!(walker.advance(&stream), Some(first.len()));
        assert!(walker.at_boundary(), "an empty payload is a whole message in its header");

        // The same bytes under the later framing are read as one enormous
        // message, which is the mis-framing `MAX_CONTROL_PAYLOAD` catches.
        let mut wrong = ControlFrameWalker::new(DraftVersion::Draft14);
        assert_eq!(wrong.advance(&stream), None);
    }

    /// A length no control message has means the length field was read at
    /// the wrong offset, and the walker says so by offering nothing.
    ///
    /// Silence rather than a guess is the point: a walker that kept
    /// counting would hold every injection for the rest of the session and
    /// would claim at teardown that a message was half-written, neither of
    /// which it can actually see.
    #[test]
    fn an_impossible_length_stops_the_walker_claiming_anything() {
        let mut stream = Vec::new();
        varint(0x40, &mut stream);
        varint(MAX_CONTROL_PAYLOAD as u64 + 1, &mut stream);
        stream.extend_from_slice(&[0u8; 8]);

        let mut walker = ControlFrameWalker::new(DraftVersion::Draft09);
        assert_eq!(walker.advance(&stream), None);
        assert!(!walker.at_boundary(), "nothing may be injected onto a stream it cannot follow");
        assert!(
            !walker.is_mid_message(),
            "and nothing may be reported as truncated either — it has no idea whether it was"
        );

        // Latched: a later chunk that would have parsed cleanly on its own
        // changes nothing, because the stream position is already lost.
        assert_eq!(walker.advance(&frame_varint_length(0x41, &[1])), None);
        assert!(!walker.at_boundary());
    }

    /// CLIENT_SETUP's payload: version count, versions, then no parameters.
    fn client_setup_payload(drafts: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        varint(drafts.len() as u64, &mut payload);
        for &n in drafts {
            varint(0xff00_0000 + u64::from(n), &mut payload);
        }
        varint(0, &mut payload);
        payload
    }

    /// SERVER_SETUP's payload: the selected version, then no parameters.
    fn server_setup_payload(draft: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        varint(0xff00_0000 + u64::from(draft), &mut payload);
        varint(0, &mut payload);
        payload
    }

    /// Build a draft-07 CLIENT_SETUP on the wire (type 0x40, varint length).
    fn encode_client_setup_d07(drafts: &[u8]) -> Vec<u8> {
        frame_varint_length(0x40, &client_setup_payload(drafts))
    }

    /// Build a draft-14 CLIENT_SETUP on the wire (type 0x20, u16-BE length).
    fn encode_client_setup_d14(drafts: &[u8]) -> Vec<u8> {
        frame_u16_length(0x20, &client_setup_payload(drafts))
    }

    /// Build a draft-07 SERVER_SETUP on the wire (type 0x41, varint length).
    fn encode_server_setup_d07(draft: u8) -> Vec<u8> {
        frame_varint_length(0x41, &server_setup_payload(draft))
    }

    /// Build a draft-14 SERVER_SETUP on the wire (type 0x21, u16-BE length).
    fn encode_server_setup_d14(draft: u8) -> Vec<u8> {
        frame_u16_length(0x21, &server_setup_payload(draft))
    }

    /// The draft [`peek_draft`] named, or `None` for either non-answer.
    ///
    /// The rows below that care *which* non-answer it was say so with
    /// `matches!` instead; this is for the rows that only care that a draft
    /// was named.
    fn named(buf: &[u8], side: ProxySide) -> Option<DraftVersion> {
        match peek_draft(buf, side) {
            DraftPeek::Named(d) => Some(d),
            DraftPeek::NeedMore | DraftPeek::NotSetup => None,
        }
    }

    #[test]
    fn the_local_encoder_agrees_with_the_framing_detect_reads() {
        // 0x40 is a two-byte varint, 0x20 a one-byte one — the whole
        // reason `peek_draft` branches on the type id.
        let d07 = encode_client_setup_d07(&[7]);
        assert_eq!(&d07[..2], &[0x40, 0x40], "0x40 encodes as a 2-byte varint");
        assert_eq!(varint_len(d07[0]), 2);

        let d14 = encode_client_setup_d14(&[14]);
        assert_eq!(d14[0], 0x20, "0x20 encodes as a 1-byte varint");
        assert_eq!(varint_len(d14[0]), 1);
        // Payload length is u16-BE and covers exactly the payload.
        let declared = ((d14[1] as usize) << 8) | (d14[2] as usize);
        assert_eq!(declared, d14.len() - 3);
    }

    #[test]
    fn detect_picks_highest_draft_from_07_10_varint_framing() {
        // Drafts 07 and 09 offered; expect 09.
        let bytes = encode_client_setup_d07(&[7, 9]);
        assert_eq!(named(&bytes, ProxySide::ClientToProxy), Some(DraftVersion::Draft09));
    }

    #[test]
    fn detect_picks_highest_draft_from_11_14_u16_framing() {
        // Drafts 11, 13, 14 offered; expect 14.
        let bytes = encode_client_setup_d14(&[11, 13, 14]);
        assert_eq!(named(&bytes, ProxySide::ClientToProxy), Some(DraftVersion::Draft14));
    }

    #[test]
    fn detect_from_server_setup_varint_framing() {
        let bytes = encode_server_setup_d07(10);
        assert_eq!(named(&bytes, ProxySide::RelayToProxy), Some(DraftVersion::Draft10));
    }

    #[test]
    fn detect_from_server_setup_u16_framing() {
        let bytes = encode_server_setup_d14(14);
        assert_eq!(named(&bytes, ProxySide::RelayToProxy), Some(DraftVersion::Draft14));
    }

    /// **A short buffer is asked again; a wrong one is not.**
    ///
    /// The two non-answers are separate variants because they have opposite
    /// consequences for everything waiting on the draft. `NeedMore` says the
    /// bytes to decide on have not arrived, so the pipe keeps buffering and
    /// the waiters keep waiting. `NotSetup` says they have arrived and they
    /// decided against: the type varint is whole and it is not a SETUP, so
    /// no further byte can change the answer and the session must stop
    /// waiting for one. Collapsed into a single `None`, the second case
    /// buffered 64 KiB before giving up — and a control stream that never
    /// carries that much never gave up at all.
    #[test]
    fn a_short_buffer_needs_more_and_a_wrong_first_message_never_will() {
        let bytes = encode_client_setup_d14(&[14]);
        // One byte in: the type varint is read, but the u16 length field
        // that follows it is not there yet.
        assert!(matches!(peek_draft(&bytes[..1], ProxySide::ClientToProxy), DraftPeek::NeedMore));
        // Whole, and the answer is a draft.
        assert_eq!(named(&bytes, ProxySide::ClientToProxy), Some(DraftVersion::Draft14));

        // 0x10 is GOAWAY. The type varint is one byte and it has arrived,
        // so this stream will never open with a SETUP.
        assert!(matches!(
            peek_draft(&[0x10u8, 0x00, 0x00], ProxySide::ClientToProxy),
            DraftPeek::NotSetup
        ));
        // Even one byte of it is enough to say so.
        assert!(matches!(peek_draft(&[0x10u8], ProxySide::ClientToProxy), DraftPeek::NotSetup));
    }

    #[test]
    fn detect_ignores_15_plus_versions_in_moq_00_setup() {
        // A malformed CLIENT_SETUP advertising only draft-15 over moq-00
        // (which shouldn't happen in practice). We refuse to pick 15 here
        // because 15+ uses ALPN, not CLIENT_SETUP — and the message is
        // whole, so the refusal is final rather than a request for more.
        let bytes = encode_client_setup_d14(&[15]);
        assert!(matches!(peek_draft(&bytes, ProxySide::ClientToProxy), DraftPeek::NotSetup));
    }

    #[test]
    fn detect_setup_wrong_direction_is_final() {
        // CLIENT_SETUP peeked as SERVER_SETUP. The type id says which one it
        // is, so this is decided and not pending.
        let bytes = encode_client_setup_d14(&[14]);
        assert!(matches!(peek_draft(&bytes, ProxySide::RelayToProxy), DraftPeek::NotSetup));
    }

    /// **The ranking is the policy, and the cell enforces it.**
    ///
    /// A CLIENT_SETUP lists what the client will take; a SERVER_SETUP names
    /// what the two agreed. So the relay's direction must be able to correct
    /// the client's, and the client's must not be able to undo it — which is
    /// the only ordering under which the two control directions racing each
    /// other converges on the version actually in use.
    #[test]
    fn a_selected_version_outranks_an_offered_one_whichever_lands_first() {
        for (first, second) in [
            (
                (DraftVersion::Draft14, DraftSource::Offered),
                (DraftVersion::Draft11, DraftSource::Selected),
            ),
            (
                (DraftVersion::Draft11, DraftSource::Selected),
                (DraftVersion::Draft14, DraftSource::Offered),
            ),
        ] {
            let cell = SessionDraft::new(DraftVersion::Draft07, false);
            assert!(cell.settle(first.0, first.1), "the first answer lands on an empty cell");
            cell.settle(second.0, second.1);
            assert_eq!(
                cell.now(),
                DraftVersion::Draft11,
                "SERVER_SETUP's selected version wins whichever direction was read first",
            );
        }
    }

    /// **Giving up is a floor, not an answer.**
    ///
    /// A session that stopped waiting keeps the draft it started with, and a
    /// SETUP that arrives afterwards still refines every stream opened after
    /// it. The opposite — a fallback that settled the question — would make
    /// a slow client permanently misframed, which is the failure this whole
    /// cell exists to end.
    #[test]
    fn a_late_setup_still_outranks_a_fallback() {
        let cell = SessionDraft::new(DraftVersion::Draft14, false);
        assert_eq!(
            cell.now(),
            DraftVersion::Draft14,
            "the starting draft, before anything settles"
        );
        assert!(cell.settle(DraftVersion::Draft14, DraftSource::Fallback));
        assert!(cell.settle(DraftVersion::Draft11, DraftSource::Offered));
        assert_eq!(cell.now(), DraftVersion::Draft11);
    }

    /// **A walker built on the wrong draft holds every injection, and the
    /// rebuild lets them go.**
    ///
    /// The framing changed at draft 11: earlier drafts write a control
    /// message's payload length as a varint, later ones as a fixed 16-bit
    /// field. So a walker built from a session's *configured* draft and fed
    /// the other cohort's bytes reads the length field at the wrong offset —
    /// here it reads 3073 where 12 was written — and then counts down
    /// through a message that ends nowhere. `at_boundary()` answers `false`
    /// from that point on, forever, and an injection is only ever written
    /// when it answers `true`. The consequence is silent: the control plane
    /// accepts the injection, the session reports success, and nothing is
    /// ever placed on that direction again.
    ///
    /// The rebuild is what ends it. Replaying the same bytes under the draft
    /// the client named leaves the walker where the old one stood and right
    /// about it, so the next injection goes out.
    #[test]
    fn a_walker_rebuilt_on_the_named_draft_finds_the_boundary_the_guess_lost() {
        let setup = encode_client_setup_d07(&[7]);

        let mut guessed = ControlFrameWalker::new(DraftVersion::Draft14);
        let _ = guessed.advance(&setup);
        assert!(
            !guessed.at_boundary(),
            "a draft-14 walker reads draft-07's varint length field as sixteen bits of \
             something else, so it never reaches the end of the first message and every \
             injection waits behind it",
        );

        let mut rebuilt = ControlFrameWalker::new(DraftVersion::Draft07);
        let _ = rebuilt.advance(&setup);
        assert!(
            rebuilt.at_boundary(),
            "rebuilt on the draft the client named and replayed over the same bytes, the \
             walker is between messages and an injection may be written",
        );
    }

    /// **An ALPN-fixed session is born settled and cannot be peeked out of
    /// it.**
    ///
    /// Drafts 15 and later carry no version in their SETUP at all, so a
    /// peek that thought it had found one there found something else.
    #[test]
    fn an_alpn_fixed_session_ignores_every_setup() {
        let cell = SessionDraft::new(DraftVersion::Draft17, true);
        assert!(!cell.settle(DraftVersion::Draft11, DraftSource::Selected));
        assert_eq!(cell.now(), DraftVersion::Draft17);
    }

    #[test]
    fn a_non_reset_read_failure_picks_a_code_the_draft_defines() {
        // The synthesized-code vocabulary: `0x3` for a connection-level
        // failure, `0x0` for
        // anything else, and never `0x1 CANCELLED`.
        let lost = ProxyError::Transport(TransportError::ConnectionLost);
        assert_eq!(synthesized_reset_code(&lost), 0x3);
        let conn = ProxyError::Transport(TransportError::Connection("gone".into()));
        assert_eq!(synthesized_reset_code(&conn), 0x3);
        let read = ProxyError::Transport(TransportError::Read("boom".into()));
        assert_eq!(synthesized_reset_code(&read), 0x0);
        assert!(!stream_reset_code_defined(DraftVersion::Draft07));
        assert!(stream_reset_code_defined(DraftVersion::Draft11));
    }

    // ── the stop-watcher's fuse ────────────────────────────────────────

    /// The watcher resolves once and is never polled again.
    ///
    /// The fuse is mandatory, not defensive. The watcher is hoisted
    /// across `select!` iterations precisely so quinn's `stopped()` is not
    /// rebuilt per wake, and the price of hoisting is that the *same*
    /// future is offered to `select!` every time round the loop. A
    /// completed future polled again panics with "`async fn` resumed after
    /// completion", inside a spawned forwarding task, where a dropped
    /// `JoinHandle` swallows the message and the symptom is a stream that
    /// silently stops forwarding.
    ///
    /// The positive half comes first and is what makes the negative half
    /// mean anything: "it did not panic" is green by default over a
    /// watcher that never resolved, so the test asserts that it *did*
    /// resolve — with the value it was given, and by observing
    /// `is_watching()` flip — before asserting that a second poll is inert.
    ///
    /// *Ablation (run, and it fails):* delete `self.watching = None;` —
    /// the line marked `THE FUSE` in [`StopWatcher::watch`]. The
    /// `is_watching()` assertion below goes red immediately, and the
    /// second `watch()` panics with "`async fn` resumed after completion"
    /// rather than staying pending.
    #[tokio::test]
    async fn the_watcher_is_not_repolled_after_it_resolves() {
        let mut watcher = StopWatcher::watching_over(async { Err(TransportError::Stopped(0x2a)) });
        assert!(watcher.is_watching(), "a freshly armed watcher must enable its branch");

        // Positive proof that it resolved, and to what.
        let outcome = watcher.watch().await;
        assert!(
            matches!(outcome, Err(TransportError::Stopped(0x2a))),
            "the watcher must hand back the peer's code verbatim, got {outcome:?}"
        );
        assert!(
            !watcher.is_watching(),
            "a resolved watcher must retire itself, or the next select! iteration re-polls a \
             completed future and the forwarding task panics"
        );

        // What the next `select!` iteration does: the branch is disabled by
        // `is_watching()`, and even if it were not, `watch()` is inert.
        let repoll =
            tokio::time::timeout(std::time::Duration::from_millis(200), watcher.watch()).await;
        assert!(repoll.is_err(), "a retired watcher must stay pending forever, not resolve again");
    }

    /// `stop_error` is the safety argument for the control-path watcher,
    /// asserted rather than described.
    ///
    /// An idle control stream is MoQT's normal steady state, so the only
    /// outcome allowed to tear a session down is the peer's own
    /// `STOP_SENDING`. `Ok(())` cannot fire on a live stream and a lost
    /// connection is the read side's business; both must be inert here.
    ///
    /// *Ablation:* make `stop_error` return `Some` for any `Err`. The
    /// `Connection` row goes red — and end to end, every session whose
    /// destination connection ends would mirror a stop it never received.
    #[test]
    fn only_a_peer_stop_ends_a_stream() {
        assert!(matches!(
            stop_error(Err(TransportError::Stopped(7))),
            Some(ProxyError::Transport(TransportError::Stopped(7)))
        ));
        assert!(stop_error(Ok(())).is_none(), "a finished-and-acked stream is not a teardown");
        assert!(
            stop_error(Err(TransportError::Connection("gone".into()))).is_none(),
            "a lost connection is the read side's teardown, not a mirrored STOP_SENDING"
        );
    }

    // ── The relay leg's transport configuration ────────────────────

    /// A session pointed at an address that cannot be parsed.
    ///
    /// Every test below asserts about what happens *before* a socket
    /// exists, so an unparseable address is the cheapest way to prove the
    /// resolution ran first: a run that reaches the address at all reports
    /// `UpstreamConnect`, and one that was refused earlier reports its own
    /// refusal. Neither ever touches the network, so none of these can
    /// hang or flake.
    fn unroutable_session(config: ProxySessionConfig) -> ProxySession {
        ProxySession::new(
            SessionId(1),
            config,
            Vec::new(),
            Arc::new(crate::observer::NoOpProxyObserver),
            Arc::new(crate::hook::NoOpHook),
            CancellationToken::new(),
        )
    }

    fn unroutable_config() -> ProxySessionConfig {
        ProxySessionConfig { upstream_addr: "not an address".to_string(), ..Default::default() }
    }

    /// Counts the builds and returns a config built the default way.
    struct CountingInstaller(Arc<std::sync::atomic::AtomicUsize>);

    impl TransportInstaller for CountingInstaller {
        fn build(
            &self,
            profile: &TransportProfile,
        ) -> Result<quinn::TransportConfig, crate::transport::TransportProfileError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            profile.into_config()
        }
    }

    #[tokio::test]
    async fn an_upstream_leg_naming_both_a_config_and_a_profile_is_refused_before_it_dials() {
        let mut config = unroutable_config();
        config.upstream_transport_config = Some(Arc::new(quinn::TransportConfig::default()));
        config.upstream_transport_profile = Some(TransportProfile::default());

        let err = unroutable_session(config)
            .connect_upstream()
            .await
            .err()
            .expect("a contradiction is not a connection");
        assert!(
            matches!(err, ProxyError::TransportConfigAndProfile { leg: Leg::Upstream }),
            "the relay leg's contradiction has to be reported as the relay leg's: {err}"
        );
    }

    /// The same contradiction, on a WebTransport upstream that would have
    /// ignored both fields.
    ///
    /// Ignoring them is exactly why this matters: a rule enforced only on
    /// the transport someone happened to test is a rule a caller finds out
    /// about by changing an unrelated setting.
    #[tokio::test]
    async fn the_refusal_does_not_depend_on_the_upstream_transport() {
        let mut config = unroutable_config();
        config.upstream_transport =
            UpstreamTransportType::WebTransport { url: "https://127.0.0.1:1/".to_string() };
        config.upstream_transport_config = Some(Arc::new(quinn::TransportConfig::default()));
        config.upstream_transport_profile = Some(TransportProfile::default());

        let err = unroutable_session(config)
            .connect_upstream()
            .await
            .err()
            .expect("a contradiction is not a connection");
        assert!(
            matches!(err, ProxyError::TransportConfigAndProfile { leg: Leg::Upstream }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_upstream_profile_that_cannot_be_honoured_stops_the_session_connecting() {
        let mut config = unroutable_config();
        config.upstream_transport_profile =
            Some(TransportProfile { initial_mtu: Some(900), ..Default::default() });

        let err = unroutable_session(config)
            .connect_upstream()
            .await
            .err()
            .expect("an unhonourable profile is not a connection");
        assert!(
            matches!(
                err,
                ProxyError::TransportProfile {
                    leg: Leg::Upstream,
                    source: crate::transport::TransportProfileError::MtuBelowFloor { .. },
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_upstream_profile_is_built_through_the_installer_before_anything_is_dialled() {
        let builds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut config = unroutable_config();
        config.upstream_transport_profile =
            Some(TransportProfile { initial_mtu: Some(1350), ..Default::default() });
        config.upstream_installer = Some(Arc::new(CountingInstaller(Arc::clone(&builds))));

        let err = unroutable_session(config)
            .connect_upstream()
            .await
            .err()
            .expect("the address is deliberately unparseable");
        assert!(
            matches!(err, ProxyError::UpstreamConnect(_)),
            "the profile was accepted, so the session must have got as far as the address: {err}"
        );
        assert_eq!(
            builds.load(Ordering::Relaxed),
            1,
            "the leg builds its config through the installer, once, before the endpoint exists"
        );
    }
}

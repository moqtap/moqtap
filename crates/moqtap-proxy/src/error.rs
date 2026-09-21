//! Proxy error types.

use moqtap_client::transport::TransportError;
use moqtap_codec::error::CodecError;
use moqtap_codec::version::DraftVersion;

use crate::transport::TransportProfileError;
use crate::types::Leg;

/// Errors from the proxy layer.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Error from the QUIC/WebTransport listener.
    #[error("listener error: {0}")]
    Listener(String),
    /// Something was asked of a proxy's listener before there was one.
    ///
    /// A [`TransparentProxy`](crate::proxy::TransparentProxy) binds its
    /// endpoint inside `run()`, so a
    /// [`ProxyControl`](crate::control::ProxyControl) taken beforehand —
    /// which is the usual case, since `run()` does not return until the
    /// proxy is finished — is live before the endpoint is. This is the
    /// answer during that window, and again after `run()` has returned and
    /// the endpoint is gone.
    ///
    /// Distinct from [`ProxyError::Listener`] on purpose: that one means a
    /// listener existed and something about it failed, and the two call for
    /// opposite responses. A caller waiting for a proxy to come up retries
    /// on this and gives up on the other.
    #[error("the proxy has not bound a listener")]
    NotBound,
    /// Error from the underlying transport.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// Error decoding a MoQT frame.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    /// Failed to connect to the upstream relay.
    #[error("upstream connection failed: {0}")]
    UpstreamConnect(String),
    /// A socket was supplied for an upstream connection that cannot be
    /// made over it.
    ///
    /// Distinct from [`ProxyError::UpstreamConnect`] because nothing was
    /// attempted: the session refuses to connect at all rather than
    /// connecting over a socket the caller did not supply. Silently
    /// ignoring the socket would let a caller arm loss, delay or a
    /// bandwidth cap on the relay leg, watch a clean run, and conclude the
    /// impairment had no effect — when in fact it never reached the wire.
    #[error(
        "upstream socket unsupported: a WebTransport upstream builds its endpoint inside the \
         WebTransport library, which exposes no way to supply a userspace socket, so the socket \
         supplied for this session cannot be honoured"
    )]
    UpstreamSocketUnsupported,
    /// One leg was given both a raw `quinn::TransportConfig` and a
    /// [`TransportProfile`](crate::transport::TransportProfile).
    ///
    /// Refused where the leg is built, rather than merged, and the reason
    /// is a missing trait rather than a policy anyone chose.
    /// `quinn::TransportConfig` has no `Clone` and no getter for any field,
    /// so nothing in this crate can take the caller's config and hand back
    /// a modified copy of it. Code that looked like a merge would in fact
    /// be starting from `quinn::TransportConfig::default()` and discarding
    /// everything the embedding program configured — and the tests would
    /// stay green while it happened, because every field set *in the
    /// profile* does arrive. Only the fields set in the config vanish, and
    /// nothing reports that.
    ///
    /// A caller who wants both writes the base config and applies the
    /// profile over it with `TransportProfile::apply_to(&mut base)`, then
    /// sets the result as this leg's `transport_config`. Where the base has
    /// to be rebuilt for each connection,
    /// [`TransportInstaller`](crate::transport::TransportInstaller) is that
    /// same call behind a trait the leg can hold.
    #[error(
        "the {leg:?} leg was given both a transport_config and a transport_profile, which cannot \
         be combined: quinn::TransportConfig can be neither cloned nor read back, so a merge \
         would silently discard the config and keep only the profile. Apply the profile to your \
         own config with TransportProfile::apply_to(&mut base) and set the result as this leg's \
         transport_config, or supply a TransportInstaller that builds the base itself"
    )]
    TransportConfigAndProfile {
        /// The leg holding the contradiction.
        leg: Leg,
    },
    /// One leg was given both a raw `quinn::TransportConfig` and a
    /// [`QlogSpec`](crate::qlog::QlogSpec).
    ///
    /// Its own variant rather than a widening of
    /// [`ProxyError::TransportConfigAndProfile`], because the two refusals
    /// have different fixes and a caller — or a test — that could not tell
    /// them apart would be sent to the wrong half of its configuration. A
    /// single variant carrying a string to say which pair was named is not
    /// something a `match` can check.
    ///
    /// # Why the pair cannot be honoured
    ///
    /// quinn accepts a capture sink in exactly one place: a method that
    /// **mutates** a `quinn::TransportConfig`. There is no setter on an
    /// endpoint, none on a `quinn::ServerConfig` or a `quinn::ClientConfig`,
    /// and none on a live connection. A leg's raw config arrives as an
    /// `Arc<quinn::TransportConfig>`, and that type has no `Clone`, so it
    /// cannot be copied and mutated; `Arc::get_mut` is the only other way in
    /// and it hands back nothing whenever a second handle exists — which it
    /// does on this crate's own path, since
    /// [`TransparentProxy`](crate::proxy::TransparentProxy) clones the `Arc`
    /// into the listener config it builds while the original stays in its
    /// template.
    ///
    /// So a leg holding both could do exactly one thing: take the spec,
    /// count it as configured, and deliver it nowhere. The connection would
    /// come up, the leg would report success, and the file the caller was
    /// watching would never be written to at all — the failure this crate
    /// exists to make impossible, in the one place a caller has no way of
    /// noticing it.
    ///
    /// A caller who wants both attaches the sink to their own config with
    /// `QlogSpec::attach_to(&mut base)` *before* the `Arc` is made — that is
    /// the last moment a mutable reference to it exists — and sets the
    /// result as this leg's raw config. A caller who has no config of their
    /// own drops the field and lets the leg build one, which is what a leg
    /// carrying a spec alone does.
    #[cfg(feature = "qlog")]
    #[error(
        "the {leg:?} leg was given both a transport_config and a qlog spec, which cannot be \
         combined: quinn installs a capture sink by mutating a quinn::TransportConfig, and this \
         leg's config arrives behind an Arc that can be neither cloned nor mutated, so the spec \
         would be accepted and delivered nowhere. Attach the sink to your own config with \
         QlogSpec::attach_to(&mut base) before wrapping it in an Arc and set the result as this \
         leg's transport_config, or drop the transport_config and let the leg build one"
    )]
    TransportConfigAndQlog {
        /// The leg holding the contradiction.
        leg: Leg,
    },
    /// A leg's [`QlogSpec`](crate::qlog::QlogSpec) could not become a
    /// capture.
    ///
    /// The leg is refused rather than opened without the sink, for the
    /// reason every refusal in this area exists: a connection that came up
    /// anyway would run, report success, and leave the caller's capture
    /// empty — and an empty capture is indistinguishable from a capture of
    /// a connection that carried nothing, which is exactly the question a
    /// capture is usually read to answer.
    ///
    /// Both of [`QlogError`](crate::qlog::QlogError)'s variants reach here.
    /// `NoWriter` is a spec nobody finished writing, refused before a sink
    /// is built or an endpoint exists; `NotStarted` is a writer that refused
    /// the preamble, which is the first thing written and therefore the
    /// first place a full disk or an unwritable path shows up.
    #[cfg(feature = "qlog")]
    #[error("the {leg:?} leg's qlog capture could not be started: {source}")]
    Qlog {
        /// The leg holding the spec.
        leg: Leg,
        /// Why the spec could not become a capture.
        source: crate::qlog::QlogError,
    },
    /// A [`TransparentProxy`](crate::proxy::TransparentProxy) was built from
    /// a template carrying a [`QlogSpec`](crate::qlog::QlogSpec), which it
    /// cannot deliver to any leg.
    ///
    /// # Why a proxy template cannot carry one
    ///
    /// A `TransparentProxy` holds its two configurations as a **template**
    /// and copies them: the listener's once, when it binds, and the
    /// session's once per accepted connection. A `QlogSpec` owns a
    /// `Box<dyn Write>`, has no `Clone`, and is consumed the moment it
    /// becomes a sink, so there is nothing a copy could hand over — and one
    /// writer cannot be divided between the connections a proxy accepts in
    /// any case. One sink shared by two connections writes both into one
    /// file, behind one preamble, with no record saying where the first ends.
    ///
    /// # Why it is refused rather than dropped
    /// Because the alternative is this crate's cardinal failure with nothing to
    /// give it away. A proxy that quietly left the field behind would bind,
    /// accept, forward and report success, and the only symptom would be a file
    /// that was never created — which a caller reads as *the run produced no
    /// events* rather than as *the capture was never installed*. The
    /// contradiction is knowable before a socket exists, so it is answered
    /// there.
    ///
    /// The fix is to capture the leg where one writer per connection is
    /// expressible: build the
    /// [`ListenerConfig`](crate::listener::ListenerConfig) and call
    /// [`Listener::bind`](crate::listener::Listener::bind) for the client
    /// leg, or drive a [`ProxySession`](crate::session::ProxySession) with
    /// its own spec for the relay leg.
    #[cfg(feature = "qlog")]
    #[error(
        "a TransparentProxy template was given a qlog spec for the {leg:?} leg, which it cannot \
         deliver: a proxy copies its configuration — the listener's once, the session's once per \
         accepted connection — and a QlogSpec owns its writer, has no Clone and is consumed when \
         it becomes a sink, so the copy would carry nothing and the capture would never be \
         installed. Capture the client leg by building a ListenerConfig and calling \
         Listener::bind, or the relay leg by driving a ProxySession, one spec per connection"
    )]
    QlogOnProxyTemplate {
        /// The leg whose template holds the spec.
        leg: Leg,
    },
    /// A leg's [`TransportProfile`](crate::transport::TransportProfile)
    /// could not be turned into a `quinn::TransportConfig`.
    ///
    /// The leg is refused rather than opened with quinn's defaults: a
    /// connection that came up anyway would run with parameters nobody
    /// chose and report success, and the profile that was ignored is
    /// precisely the record of what the run was supposed to be.
    #[error("the {leg:?} leg's transport profile was refused: {source}")]
    TransportProfile {
        /// The leg holding the profile.
        leg: Leg,
        /// Why the profile could not be honoured.
        source: TransportProfileError,
    },
    /// A shaping class keys on a field this session's draft does not carry,
    /// so the class could never claim a unit.
    ///
    /// Refused before the session dials, rather than left to be discovered
    /// from a report during the run. The rule is not merely unlikely to
    /// match — on this draft there is no traffic at all that could satisfy
    /// it, so a session carrying one would pace nothing the author asked
    /// for, count itself as shaping, and finish clean. That is the whole
    /// failure this crate exists to make impossible, arrived at through a
    /// configuration file rather than a bug.
    ///
    /// Distinct from
    /// [`ShapeError::InertMatcher`](crate::shape::ShapeError::InertMatcher),
    /// and the distinction is where the answer lives: an empty value set is
    /// a property of the configuration alone, so the constructor rejects it
    /// with no draft in hand; a key the draft does not carry needs a draft
    /// to judge, which only exists once a session is being started.
    #[error("{source}")]
    ShapeRuleUnsupported {
        /// The class, the draft, the stream kind and the key.
        #[from]
        source: crate::capability::UnsupportedMatcherKey,
    },
    /// The session is configured for a MoQT draft this build did not
    /// compile a codec for.
    ///
    /// [`DraftVersion`] carries all variants under every feature
    /// set, so a draft that was never compiled is still a value a
    /// configuration can hold — and
    /// `ProxySessionConfig::default().draft` holds one of them. On a build
    /// made with a reduced draft set, nothing about such a configuration
    /// looks wrong.
    ///
    /// # What the session would do instead
    ///
    /// Run, and forward everything uninterpreted. The dispatch enums fall
    /// through to their catch-all arm and answer
    /// `CodecError::UnsupportedDraft`, which is not an
    /// incomplete-input error, so the object framer takes its terminal
    /// arm, latches [`BypassReason::DecodeError`](crate::framer::BypassReason)
    /// and pumps the stream through as bytes. No object reaches a hook, no
    /// shaping class claims anything, no `ProxyEvent::Object` is emitted —
    /// and the run completes, reports success, and produces a stream of
    /// zeroes that is indistinguishable from a session nothing was sent on.
    /// Control frames fare no better and are quieter still: the control
    /// parser skips a frame it cannot decode and emits nothing at all.
    ///
    /// So it is refused where the session starts, beside the shaping
    /// admission check and before the relay is dialled, because a byte pump
    /// reporting success is precisely what this crate exists to make
    /// impossible.
    ///
    /// # It names the draft that was resolved, not the one configured
    ///
    /// Drafts 15 and later are settled by the client's ALPN, so the draft a
    /// session will actually frame with may not be the one in its
    /// configuration. This carries the resolved one, which is the one that
    /// is missing.
    ///
    /// The fix is a build that carries the draft — the `draftNN` feature of
    /// this crate, which forwards to both the codec and the client — or a
    /// configuration naming one this build has.
    #[error(
        "this session is configured for {draft:?}, which this build did not compile: it would \
         forward every stream uninterpreted, surface no object to any hook, claim nothing with \
         any shaping class, and report success. Build with the matching draftNN feature, or \
         configure a draft this build carries"
    )]
    DraftNotCompiled {
        /// The draft this build cannot frame.
        draft: DraftVersion,
    },
    /// TLS configuration error.
    #[error("TLS config error: {0}")]
    TlsConfig(String),
    /// Certificate generation error.
    #[error("certificate generation error: {0}")]
    CertGen(String),
    /// Session was closed.
    #[error("session closed: {0}")]
    SessionClosed(String),
    /// Proxy is shutting down.
    #[error("proxy shutdown")]
    Shutdown,
}

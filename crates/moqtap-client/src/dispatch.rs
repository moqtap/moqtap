//! Unified multi-draft entry-point types.
//!
//! This module is the facade downstream consumers use to hold a MoQT
//! connection without caring which draft was negotiated.
//! It mirrors [`moqtap_codec::dispatch`]: one enum variant per enabled draft,
//! gated on its feature flag.
//!
//! Four types live here:
//!
//! - `AnyConnection` — wraps a draft-specific `Connection`.
//! - `AnyClientEvent` — wraps a draft-specific `ClientEvent`.
//! - `AnyConnectionObserver` — a trait that receives `AnyClientEvent`s.
//!   Attached to an `AnyConnection` via `AnyConnection::set_observer`,
//!   which installs a per-draft adapter on the inner connection.
//! - `AnyRequest` — what a request made through `AnyConnection` leaves the
//!   caller holding. Drafts 07-16 put every request on the one control
//!   stream and hand back only a request ID; from draft-17 on each request
//!   owns a bidirectional stream, and the handle owns that stream.
//!
//! `AnyConnection` carries only the handful of protocol methods whose
//! arguments can be reconciled across every draft (`subscribe`, `fetch`,
//! `track_status`, `subscribe_namespace`). The rest differ too much in
//! signature — match on the variant to reach them.

use std::sync::Arc;

use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::version::DraftVersion;

/// Generates the `AnyConnection` and `AnyClientEvent` enums plus the per-draft
/// observer adapter, with one variant per enabled draft feature.
macro_rules! dispatch_all {
    (
        $(
            #[cfg(feature = $feat:literal)]
            $variant:ident => $module:ident,
        )+
    ) => {
        /// A MoQT client connection of any enabled draft version.
        ///
        /// Wraps the draft-specific `Connection` type. Methods common to all
        /// drafts are forwarded; for draft-specific protocol calls, match on
        /// the variant.
        pub enum AnyConnection {
            $(
                #[cfg(feature = $feat)]
                #[doc = concat!("A draft-", $feat, " connection.")]
                $variant(crate::$module::connection::Connection),
            )+
        }

        impl AnyConnection {
            /// Returns the draft version this connection is using.
            #[allow(unreachable_code)]
            pub fn draft(&self) -> DraftVersion {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(_) => DraftVersion::$variant,
                    )+
                    #[allow(unreachable_patterns)]
                    _ => unreachable!("AnyConnection has no enabled variants"),
                }
            }

            /// The SETUP message the server answered the handshake with.
            ///
            /// `SERVER_SETUP` through draft-16, the server's half of the
            /// unified `SETUP` from draft-17.
            /// [`fields`](moqtap_codec::dispatch::AnyControlMessage::fields)
            /// renders its parameters under the negotiated draft's own names,
            /// in the order they arrived — which is what makes one relay's
            /// setup response comparable to another's.
            #[allow(unreachable_code)]
            pub fn server_setup(&self) -> &moqtap_codec::dispatch::AnyControlMessage {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(c) => c.server_setup(),
                    )+
                    #[allow(unreachable_patterns)]
                    _ => unreachable!("AnyConnection has no enabled variants"),
                }
            }

            /// The framed wire bytes of [`Self::server_setup`], as they
            /// arrived.
            pub fn server_setup_raw(&self) -> Option<&[u8]> {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(c) => c.server_setup_raw(),
                    )+
                    #[allow(unreachable_patterns)]
                    _ => None,
                }
            }

            /// Attach an observer. The observer is adapted into the
            /// draft-specific observer trait and installed on the inner
            /// connection; events are forwarded as [`AnyClientEvent`].
            ///
            /// Replaces any previously attached observer.
            #[allow(unused_variables)]
            pub fn set_observer(&mut self, observer: Arc<dyn AnyConnectionObserver>) {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(c) => {
                            c.set_observer(Box::new($variant::Adapter(observer)));
                        }
                    )+
                    #[allow(unreachable_patterns)]
                    _ => {}
                }
            }

            /// Remove any attached observer.
            pub fn clear_observer(&mut self) {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(c) => c.clear_observer(),
                    )+
                    #[allow(unreachable_patterns)]
                    _ => {}
                }
            }

            /// Close the connection with the given application error code
            /// and reason.
            #[allow(unused_variables)]
            pub fn close(&self, code: u32, reason: &[u8]) {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(c) => c.close(code, reason),
                    )+
                    #[allow(unreachable_patterns)]
                    _ => {}
                }
            }
        }

        /// An event from a MoQT connection of any enabled draft version.
        ///
        /// Event shapes differ across drafts (e.g. draft-17's
        /// `SubgroupObjectReceived` carries header types, while earlier
        /// drafts carry decoded objects). Match on the variant to inspect
        /// the draft-specific event.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub enum AnyClientEvent {
            $(
                #[cfg(feature = $feat)]
                #[doc = concat!("A draft-", $feat, " event.")]
                $variant(crate::$module::event::ClientEvent),
            )+
        }

        impl AnyClientEvent {
            /// Returns the draft version this event belongs to.
            #[allow(unreachable_code)]
            pub fn draft(&self) -> DraftVersion {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(_) => DraftVersion::$variant,
                    )+
                    #[allow(unreachable_patterns)]
                    _ => unreachable!("AnyClientEvent has no enabled variants"),
                }
            }

            /// This event as a [`ControlFrame`], or `None` if it is not a
            /// control message.
            ///
            /// The wildcard arm is over the *other* event variants — a stream
            /// opening, an object arriving — and not over drafts, so it stays
            /// reachable in every build and says nothing about which drafts are
            /// enabled.
            ///
            /// `stream_id` is deliberately not carried. Drafts 07 through 15
            /// have no such field on this event, request streams arriving with
            /// draft-16, so one arm cannot read it from every draft — and a
            /// second accessor split across two draft lists is a cost to pay
            /// when something needs the correlation, not before.
            pub fn control_frame(&self) -> Option<ControlFrame<'_>> {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        Self::$variant(crate::$module::event::ClientEvent::ControlMessage {
                            direction,
                            message,
                            raw,
                            ..
                        }) => Some(ControlFrame {
                            draft: DraftVersion::$variant,
                            outbound: matches!(
                                direction,
                                crate::$module::event::Direction::Send
                            ),
                            message,
                            raw: raw.as_deref(),
                        }),
                    )+
                    _ => None,
                }
            }
        }

        // The classification, written once and instantiated per draft.
        //
        // Per draft rather than generic because the two facts worth keeping are
        // both the draft's: `ConnectionError` is a distinct type on each, and
        // `close` comes from `codec_session_error_code`, which is the draft's
        // own reading of its own text. A blanket impl could reach neither.
        $(
            #[cfg(feature = $feat)]
            impl From<crate::$module::connection::ConnectionError> for AnyConnectionError {
                fn from(err: crate::$module::connection::ConnectionError) -> Self {
                    use crate::above_codec_rules::{DraftSpecificCause, EndpointFault};
                    use crate::$module::connection::{Connection, ConnectionError};
                    use crate::transport::TransportError;

                    let message = err.to_string();
                    // Read before the match below moves `err`. Answers `None`
                    // for every variant that match names, so the two tables
                    // partition this draft's error type between them.
                    let own = Connection::draft_specific_cause(&err);
                    let cause = match err {
                        ConnectionError::Codec(error) => ErrorCause::Codec {
                            close: Connection::codec_session_error_code(&error)
                                .map(|code| code.as_u64()),
                            error,
                        },
                        // A varint that would not decode is a decode failure
                        // like any other, and every draft's `CodecError` has a
                        // variant that says so — so it is reported as the codec
                        // error it is rather than as a class of its own.
                        ConnectionError::VarInt(e) => {
                            let error = moqtap_codec::error::CodecError::VarInt(e);
                            ErrorCause::Codec {
                                close: Connection::codec_session_error_code(&error)
                                    .map(|code| code.as_u64()),
                                error,
                            }
                        }
                        // The endpoint's error type holds both findings at
                        // once. `fault` says which end,
                        // `session_error_code` says what the draft requires be
                        // done about it, and the pair is read here rather than
                        // guessed at from either half alone.
                        ConnectionError::Endpoint(e) => match e.fault() {
                            EndpointFault::Peer(rule) => ErrorCause::PeerViolation {
                                rule,
                                close: e.session_error_code().map(|code| code.as_u64()),
                            },
                            EndpointFault::ThisEndpoint | EndpointFault::EitherEnd => {
                                ErrorCause::Endpoint
                            }
                        },
                        ConnectionError::Transport(TransportError::StreamReset(code)) => {
                            ErrorCause::StreamReset(code)
                        }
                        ConnectionError::Transport(TransportError::Stopped(code)) => {
                            ErrorCause::Stopped(code)
                        }
                        ConnectionError::Transport(TransportError::SessionClosed {
                            code, ..
                        }) => ErrorCause::SessionClosed(code),
                        ConnectionError::Transport(TransportError::StreamClosed) => {
                            ErrorCause::StreamEnded
                        }
                        ConnectionError::Transport(_) => ErrorCause::Transport,
                        ConnectionError::UnexpectedEnd | ConnectionError::StreamFinished => {
                            ErrorCause::StreamEnded
                        }
                        // Nothing was written: no control stream to write on, an
                        // address that is not one — or a socket this machine
                        // would not open, which `From<DialError>` folds in here
                        // for exactly this reason — a TLS config this build will
                        // not build, an object asked for before the header it is
                        // framed against. `DataStreamState` is the caller
                        // reaching for a data stream out of order, which is this
                        // side's mistake.
                        ConnectionError::NoControlStream
                        | ConnectionError::InvalidAddress(_)
                        | ConnectionError::TlsConfig(_)
                        | ConnectionError::DataStreamState(_) => ErrorCause::Facade,
                        // Whatever this draft adds of its own, read by the draft
                        // rather than guessed at here.
                        #[allow(unreachable_patterns)]
                        _ => match own {
                            Some(DraftSpecificCause::LocalRefusal) => ErrorCause::Facade,
                            Some(DraftSpecificCause::PeerViolation { rule, close }) => {
                                ErrorCause::PeerViolation { rule, close }
                            }
                            None => ErrorCause::Unclassified,
                        },
                    };
                    AnyConnectionError { message, cause }
                }
            }
        )+

        // Per-draft adapter modules. Each holds an `Adapter` struct that
        // implements the draft's `ConnectionObserver` trait by forwarding to
        // an `AnyConnectionObserver`.
        $(
            #[cfg(feature = $feat)]
            #[allow(non_snake_case)]
            mod $variant {
                use super::{AnyClientEvent, AnyConnectionObserver};
                use std::sync::Arc;

                pub(super) struct Adapter(pub(super) Arc<dyn AnyConnectionObserver>);

                impl crate::$module::observer::ConnectionObserver for Adapter {
                    fn on_event(&self, event: &crate::$module::event::ClientEvent) {
                        self.0.on_event(&AnyClientEvent::$variant(event.clone()));
                    }

                    fn on_event_owned(&self, event: crate::$module::event::ClientEvent) {
                        self.0.on_event(&AnyClientEvent::$variant(event));
                    }
                }
            }
        )+
    };
}

dispatch_all! {
    #[cfg(feature = "draft07")]
    Draft07 => draft07,
    #[cfg(feature = "draft08")]
    Draft08 => draft08,
    #[cfg(feature = "draft09")]
    Draft09 => draft09,
    #[cfg(feature = "draft10")]
    Draft10 => draft10,
    #[cfg(feature = "draft11")]
    Draft11 => draft11,
    #[cfg(feature = "draft12")]
    Draft12 => draft12,
    #[cfg(feature = "draft13")]
    Draft13 => draft13,
    #[cfg(feature = "draft14")]
    Draft14 => draft14,
    #[cfg(feature = "draft15")]
    Draft15 => draft15,
    #[cfg(feature = "draft16")]
    Draft16 => draft16,
    #[cfg(feature = "draft17")]
    Draft17 => draft17,
    #[cfg(feature = "draft18")]
    Draft18 => draft18,
    #[cfg(feature = "draft19")]
    Draft19 => draft19,
    #[cfg(feature = "draft20")]
    Draft20 => draft20,
    #[cfg(feature = "draft21")]
    Draft21 => draft21,
}

/// Draft-agnostic transport choice for [`AnyConnection::connect`].
#[derive(Debug, Clone)]
pub enum AnyTransportType {
    /// Raw QUIC via quinn. The `addr` passed to `connect` should be `host:port`.
    Quic,
    /// WebTransport via wtransport. The `url` is the WebTransport endpoint.
    WebTransport {
        /// The WebTransport endpoint URL (e.g., `https://host:port/path`).
        url: String,
    },
}

/// Draft-agnostic client configuration. The exact per-draft `ClientConfig`
/// is constructed internally by [`AnyConnection::connect`] based on `draft`.
///
/// Fields that aren't meaningful for the selected draft are ignored:
/// `additional_versions` is not carried by drafts 15–17 (single-version
/// setup) and drafts 07–13 always offer their own draft first.
#[derive(Debug, Clone)]
pub struct AnyClientConfig {
    /// Primary draft version for the connection.
    pub draft: DraftVersion,
    /// Additional draft versions to offer in CLIENT_SETUP.
    pub additional_versions: Vec<DraftVersion>,
    /// Transport type (QUIC or WebTransport).
    pub transport: AnyTransportType,
    /// Whether to skip TLS certificate verification (for testing).
    pub skip_cert_verification: bool,
    /// Custom CA certificates to trust (DER-encoded).
    pub ca_certs: Vec<Vec<u8>>,
    /// Setup parameters to include in CLIENT_SETUP (e.g., auth tokens).
    pub setup_parameters: Vec<KeyValuePair>,
}

/// Why a call through this facade stopped, kept as a value rather than as
/// words.
///
/// # What flattening cost, and what it bought
///
/// The drafts each state their own `ConnectionError`, and this facade
/// exists so that a caller never has to branch on which. Rendering every draft
/// through `Display` bought exactly that — at the price of the *variant*, which
/// is the half a caller most often needs. Three questions could not be asked of
/// a sentence:
///
/// - **Did the peer reset this stream, or finish it?** A subgroup ends when its
///   stream ends, so every reader's last read fails; whether it failed because
///   the peer abandoned the stream or because there was nothing more to send is
///   the difference between two entirely different findings, and both arrived
///   spelled as prose.
/// - **Which rule stopped a decode?** A decoder built for the negotiated draft
///   refusing a frame is sometimes this build failing to keep up and sometimes
///   this build doing what the draft *requires*. [`Self::Codec`] carries the
///   error itself and the code the draft answers it with, so the two are
///   separable without reading the message.
/// - **Was it the peer's fault at all?** [`AnyConnectionError::is_local`].
///
/// # The ten every draft shares, and the ones only some do
///
/// The first ten variants of `ConnectionError` are identical across all
/// drafts — `Endpoint`, `Codec`, `Transport`, `VarInt`,
/// `NoControlStream`, `UnexpectedEnd`, `StreamFinished`, `InvalidAddress`,
/// `TlsConfig`, `DataStreamState` — and those are classified here, once, rather
/// than fourteen times.
///
/// Six of the drafts add variants of their own, and those are read by
/// `Connection::draft_specific_cause` on each draft, beside the doc comment
/// quoting the sentence it enforces. They divide into this endpoint refusing to
/// write something ([`Self::Facade`]) and a peer breaking a rule the decoder
/// could not see ([`Self::PeerViolation`]) — two opposite findings that reached
/// a caller as prose and read exactly alike. See
/// [`crate::above_codec_rules`].
///
/// # The same split, one layer in
///
/// `ConnectionError::Endpoint` wraps a fifteenth type per draft — that draft's
/// `EndpointError`, twenty-six to forty-one variants holding the same two
/// findings under one name. `EndpointError::fault` divides it the same way and
/// by the same rule: a variant raised while **reading** what the peer sent is
/// the peer's, and one raised while **writing**, or refusing to, is this
/// side's. A handful are raised on both paths and the variant cannot say which;
/// those stay on this side, where they already were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCause {
    /// A decoder built for the negotiated draft refused what arrived.
    ///
    /// `close` is the session error code **that draft's own text** requires be
    /// sent for this error, where it names one — which is the whole of what
    /// separates a relay's defect from this build's shortfall. A decoder
    /// stopping is not by itself a finding about the peer; a decoder stopping on
    /// a rule the draft answers with "MUST close the session" is.
    ///
    /// `None` covers both a rule the draft states without a close and an error
    /// the draft says nothing about, and deliberately does not distinguish
    /// them: neither is grounds to name a relay.
    Codec {
        /// The decoder's own error, unflattened.
        error: moqtap_codec::error::CodecError,
        /// The code the negotiated draft answers it with, where it names one.
        close: Option<u64>,
    },
    /// A message that did not fit the session's state, and the fault is not the
    /// peer's.
    ///
    /// Two things reach here, and `EndpointError::fault` tells them apart on
    /// each draft. Most are this endpoint refusing on the way out — a response
    /// offered for a request the draft says to refuse, an alias it was asked to
    /// give to a second track, a session that has closed — where nothing
    /// reached the wire. The rest are variants raised on **both** a receive path
    /// and a send path, which the variant alone cannot tell apart: the state
    /// machines, which render as *invalid transition from X on event Y*
    /// whichever end asked for the transition, and the unknown-request errors.
    ///
    /// Those land here because that is the safe direction: a failure that has
    /// not been told apart is not evidence against a relay. The peer's half
    /// does not land here at all — it is [`Self::PeerViolation`], which
    /// [`AnyConnectionError::is_local`] answers false for.
    ///
    /// The draft's `EndpointError` is not carried through because it is one of
    /// fourteen unrelated types with no shared spine; the message has it.
    Endpoint,
    /// The peer abandoned this stream by resetting it, with the application
    /// error code it named.
    ///
    /// Distinct from [`Self::StreamEnded`] and the distinction is the point: a
    /// reset says the peer stopped on purpose, and several of the drafts' rules
    /// turn on exactly that. Section 2.2 forbids one Subgroup's Objects on
    /// different streams "unless one of the streams was reset prematurely" —
    /// a sentence no caller can apply without being able to see a reset.
    StreamReset(u64),
    /// The peer stopped reading this stream (`STOP_SENDING`), with its code.
    Stopped(u64),
    /// The peer closed the whole session, with the code it named.
    ///
    /// Over MoQT that code is a draft's own session error, which is the
    /// sharpest thing a refusal says.
    SessionClosed(u64),
    /// The stream ended and the peer did not reset it.
    ///
    /// Every way a stream can run out short of a reset: a clean FIN with a read
    /// still wanting bytes, a truncation, a closed stream. They are together
    /// because no layer below this one tells them apart — `ConnectionError`
    /// raises `UnexpectedEnd` for the first two alike — and putting a name on a
    /// distinction that is not observable would invent it.
    StreamEnded,
    /// A transport error naming none of the above — a lost connection, a write
    /// that failed, a datagram that would not send.
    Transport,
    /// This facade refused the call itself. Nothing was written and nothing
    /// reached the wire.
    ///
    /// A value that will not fit the field the draft puts it in, a request
    /// handle from a different draft than the connection, a draft whose feature
    /// this build was compiled without, an object asked for before the header it
    /// is framed against, a message handed to the control stream that belongs on
    /// a request stream of its own. Local by construction, which is why
    /// [`AnyConnectionError::is_local`] counts it: without a value saying so, a
    /// facade refusal carries no prefix and reads to a caller exactly like a
    /// relay hanging up.
    Facade,
    /// The peer broke a rule this endpoint enforces **above** its decoder.
    ///
    /// The frame read perfectly well and is forbidden anyway, and the fact that
    /// forbids it is one of two kinds. Some are a comparison inside the frame:
    /// properties on an Object whose status permits none, a payload after a
    /// datagram header that permits none, a bidirectional stream opened with a
    /// message type the draft does not let one open with. The rest are a
    /// comparison against the session — a second GOAWAY, a Request ID out of
    /// the peer's own sequence, a Track Alias already naming another track, an
    /// Object past the one the track ended at.
    ///
    /// A decoder can see none of it, so none of it ever reaches [`Self::Codec`]
    /// and a caller reading only that would find the peer blameless. Without
    /// this variant the second group arrives as [`Self::Endpoint`], which
    /// [`AnyConnectionError::is_local`] counts as **this** side's fault, so a
    /// relay breaking one of these rules is filed against this build's own
    /// state machine.
    ///
    /// `close` has exactly [`Self::Codec`]'s contract — the code **this draft's
    /// own text** names for the rule, or `None` where it states the rule and
    /// attaches no consequence. It comes from the draft's own
    /// `EndpointError::session_error_code` or
    /// `Connection::codec_session_error_code`, so the rule and its consequence
    /// are never two readings of one sentence.
    PeerViolation {
        /// Which rule, named the same way on every draft that states it.
        rule: crate::above_codec_rules::AboveCodecRule,
        /// The code the negotiated draft answers it with, where it names one.
        close: Option<u64>,
    },
    /// A variant neither this facade nor its draft has classified.
    ///
    /// Reachable only if the two tables disagree: a variant the match above does
    /// not name, and that the draft's own `draft_specific_cause` answered `None`
    /// for. Both are exhaustive today — neither has a wildcard arm — so adding a
    /// variant to a draft's `ConnectionError` is a compile error in that draft's
    /// file rather than a silent arrival here.
    ///
    /// Kept because the alternative in that arm is a panic, and a facade that
    /// panics on an error is worse than one that declines to characterise it.
    /// It answers [`AnyConnectionError::is_local`] false, which is the safe
    /// direction: an unclassified failure is not evidence about anybody.
    Unclassified,
}

/// Error returned by [`AnyConnection::connect`], [`AnyConnection::recv_response`]
/// and the rest of this facade.
///
/// Renders as the draft-specific error it came from, so nothing that read the
/// message reads anything different. What is new beside it is
/// [`Self::cause`] — the same failure as a value, so a caller can ask which
/// kind of failure it was without branching on draft and without parsing the
/// sentence. See [`ErrorCause`] for why the sentence was not enough.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct AnyConnectionError {
    message: String,
    cause: ErrorCause,
}

impl AnyConnectionError {
    /// A refusal by this facade itself: nothing was written, nothing reached
    /// the wire. [`ErrorCause::Facade`].
    pub fn facade(message: impl Into<String>) -> Self {
        Self { message: message.into(), cause: ErrorCause::Facade }
    }

    /// The draft-specific error's own words, unedited.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// What stopped the call, as a value.
    pub fn cause(&self) -> &ErrorCause {
        &self.cause
    }

    /// Whether the failure was on **this** side rather than the peer's.
    ///
    /// True for a decode this build would not complete, a message that did not
    /// fit the state machine this side drives, and a call this facade refused
    /// before writing anything. False for every way a peer can end a stream or
    /// a session — which is what an unimplemented message type or an unwelcome
    /// parameter looks like from here — and false for
    /// [`ErrorCause::PeerViolation`], which is the peer's doing by definition.
    ///
    /// [`ErrorCause::Endpoint`] answers **true**, and it is a narrow claim: the
    /// peer's half of the endpoint's error type leaves through
    /// [`ErrorCause::PeerViolation`] before it gets here. What reaches this
    /// answer is this endpoint refusing on the way out, plus the variants
    /// raised on both paths that no table can tell apart. Those answer true
    /// because that is the safe direction, not because they have been shown to
    /// be this side's.
    ///
    /// [`ErrorCause::Unclassified`] answers false, which is the safe direction:
    /// a failure that has not been classified is not evidence of anything.
    pub fn is_local(&self) -> bool {
        matches!(self.cause, ErrorCause::Codec { .. } | ErrorCause::Endpoint | ErrorCause::Facade)
    }
}

/// Where a FETCH's range ends, said once in a way no draft can read two ways.
///
/// The drafts do not agree about what a number in an "end object" field means,
/// and the disagreement is silent: draft-19 Section 10.13 defines `End
/// Location` as "the last Object, plus 1; or 0 to indicate the entire Group",
/// while draft-20 Sections 5.1.2 and 10.13 make the `LOCATION_FILTER` range
/// "inclusive" at both ends and delete both conventions without a note in the
/// change log. The same `end_object = 10` therefore asks for objects 0 through
/// 9 on one draft and 0 through 10 on the other, and nothing on the wire says
/// which was meant.
///
/// So this enum, not a number. [`FetchEnd::Object`] is the last Object the
/// fetch covers and the range **holds** it; [`FetchEnd::EntireGroup`] is
/// draft-19's `0` spelled out. [`AnyConnection::fetch`] converts to whichever
/// the negotiated draft writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchEnd {
    /// Through this Object ID, **inclusive** — it is the last Object the fetch
    /// covers, and the range holds it.
    ///
    /// `Object(0)` is a range ending at Object 0, one object long if it also
    /// starts there. It is not "the whole group"; that is
    /// [`FetchEnd::EntireGroup`].
    Object(u64),
    /// Through the last Object of the end Group, however many it turns out to
    /// hold.
    ///
    /// Drafts 14-19 write this as `End Location.Object = 0`. Draft-20 writes it
    /// as a three-field `LOCATION_FILTER`, which Section 5.1.2 defines as
    /// covering all Objects in the end Group.
    EntireGroup,
}

/// The range one [`AnyConnection::fetch`] asks for.
///
/// Four numbers on drafts 14 through 19, a `LOCATION_FILTER` parameter on
/// draft-20, and one meaning here. The end Group is **absolute** on both sides
/// of that split — draft-20's `EndGroupDelta` is derived from it, not asked for
/// — and the end Object is [`FetchEnd`], which is the whole point of the type.
///
/// # Porting a draft-19 call
///
/// A caller that wrote `end_object` as "the last Object plus one" writes
/// [`FetchEnd::Object`] with the last Object, and one that wrote `0` for a whole
/// group writes [`FetchEnd::EntireGroup`]. Both send exactly the bytes they sent
/// before on drafts 14 through 19, and the same request on draft-20.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchRange {
    /// The Group the range starts in.
    pub start_group: u64,
    /// The Object within `start_group` the range starts at, inclusive.
    pub start_object: u64,
    /// The Group the range ends in, absolute. Must not be below
    /// `start_group`: draft-20 encodes it as an unsigned delta from the start
    /// and has no way to say "backwards".
    pub end_group: u64,
    /// Where the range stops inside `end_group`.
    pub end: FetchEnd,
}

impl FetchRange {
    /// A range ending at `end_object` in `end_group`, **inclusive** — that
    /// Object is fetched.
    pub fn through_object(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> Self {
        Self { start_group, start_object, end_group, end: FetchEnd::Object(end_object) }
    }

    /// A range covering every Object of `end_group`, however many there are.
    pub fn through_end_of_group(start_group: u64, start_object: u64, end_group: u64) -> Self {
        Self { start_group, start_object, end_group, end: FetchEnd::EntireGroup }
    }

    /// A range holding exactly one Object.
    ///
    /// The shape an off-by-one is loudest in: a draft-19 encoder writing
    /// `end_object = object` rather than `object + 1` asks for nothing at all,
    /// and one that ports that arithmetic to draft-20 unchanged asks for two.
    pub fn one_object(group: u64, object: u64) -> Self {
        Self::through_object(group, object, group, object)
    }

    /// The `End Location.Object` drafts 14 through 19 carry inline in FETCH.
    ///
    /// Their field is "The end Location, plus 1. A Location.Object value of 0
    /// means the entire group is requested." — draft-19 Section 10.12.1, and
    /// drafts 14 through 18 in the same words. So [`FetchEnd::Object`] gains
    /// one here and
    /// [`FetchEnd::EntireGroup`] is `0`. **This is the only place that `+ 1`
    /// lives**, which is what keeps it from reaching draft-20.
    ///
    /// # Errors
    ///
    /// `FetchEnd::Object(u64::MAX)` has no encoding in that field — the plus
    /// one leaves the number space — and is the one range these drafts cannot
    /// express that draft-20 can. Refused rather than wrapped to `0`, which
    /// would silently ask for the whole group.
    pub fn inline_end_object(&self) -> Result<u64, AnyConnectionError> {
        match self.end {
            FetchEnd::EntireGroup => Ok(0),
            FetchEnd::Object(last) => last.checked_add(1).ok_or_else(|| {
                AnyConnectionError::facade(format!(
                    "fetch: a range ending at Object {last} cannot be expressed on drafts 14 \
                     through 19, whose End Location.Object is the last Object plus 1"
                ))
            }),
        }
    }

    /// The draft-20 `LOCATION_FILTER` that carries this range.
    ///
    /// Draft-20 Section 10.13 deleted `Start Location` and `End Location` from
    /// FETCH and moved the range into the parameter, whose ranges Section 5.1.2
    /// calls inclusive. So [`FetchEnd::Object`] is written **as it stands** —
    /// nothing here adds one — and [`FetchEnd::EntireGroup`] becomes the
    /// three-field filter, which Section 5.1.2 defines as covering all Objects
    /// in the end Group. The end Group travels as `EndGroupDelta`, "delta
    /// encoded from StartGroup", so it is `end_group - start_group`.
    ///
    /// # Errors
    ///
    /// [`AnyConnectionError`] when `end_group` is below `start_group`: the
    /// delta is unsigned and there is no such filter. Drafts 14 through 19 have
    /// two absolute fields and would put such a range on the wire, where the
    /// publisher answers it with `INVALID_RANGE`; the difference is where the
    /// refusal happens, not whether the fetch is legal.
    /// The name carries the draft because the type does: `LOCATION_FILTER`
    /// is draft-20's and later's, and each draft's `fill` module declares its
    /// own `LocationFilter`. An unsuffixed name would be two inherent methods
    /// of one name the moment a second draft defines the parameter.
    #[cfg(feature = "draft20")]
    pub fn location_filter_draft20(
        &self,
    ) -> Result<crate::draft20::fill::LocationFilter, AnyConnectionError> {
        use crate::draft20::fill::LocationFilter;

        let delta = self.end_group.checked_sub(self.start_group).ok_or_else(|| {
            AnyConnectionError::facade(format!(
                "fetch: a range from Group {} to Group {} runs backwards, and draft-20 \
                 Section 5.1.2 encodes the end Group as an unsigned delta from the start",
                self.start_group, self.end_group
            ))
        })?;
        let filter = match self.end {
            FetchEnd::EntireGroup => {
                LocationFilter::range(self.start_group, self.start_object, delta)
            }
            FetchEnd::Object(last) => {
                LocationFilter::range_to(self.start_group, self.start_object, delta, last)
            }
        };
        filter.map_err(|e| AnyConnectionError::facade(e.to_string()))
    }
    /// The draft-21 `LOCATION_FILTER` that carries this range.
    ///
    /// Draft-21 Section 9.11 deleted `Start Location` and `End Location` from
    /// FETCH and moved the range into the parameter, whose ranges Section 3.3.1
    /// calls inclusive. So [`FetchEnd::Object`] is written **as it stands** —
    /// nothing here adds one — and [`FetchEnd::EntireGroup`] becomes the
    /// three-field filter, which Section 9.20.10 defines as covering all Objects
    /// in the end Group. The end Group travels as `EndGroupDelta`, "delta
    /// encoded from StartGroup", so it is `end_group - start_group`.
    ///
    /// # Errors
    ///
    /// [`AnyConnectionError`] when `end_group` is below `start_group`: the
    /// delta is unsigned and there is no such filter. Drafts 14 through 19 have
    /// two absolute fields and would put such a range on the wire, where the
    /// publisher answers it with `INVALID_RANGE`; the difference is where the
    /// refusal happens, not whether the fetch is legal.
    /// The name carries the draft because the type does: `LOCATION_FILTER`
    /// is draft-21's and later's, and each draft's `fill` module declares its
    /// own `LocationFilter`. An unsuffixed name would be two inherent methods
    /// of one name the moment a second draft defines the parameter.
    #[cfg(feature = "draft21")]
    pub fn location_filter_draft21(
        &self,
    ) -> Result<crate::draft21::fill::LocationFilter, AnyConnectionError> {
        use crate::draft21::fill::LocationFilter;

        let delta = self.end_group.checked_sub(self.start_group).ok_or_else(|| {
            AnyConnectionError::facade(format!(
                "fetch: a range from Group {} to Group {} runs backwards, and draft-21 \
                 Section 9.20.10 encodes the end Group as an unsigned delta from the start",
                self.start_group, self.end_group
            ))
        })?;
        let filter = match self.end {
            FetchEnd::EntireGroup => {
                LocationFilter::range(self.start_group, self.start_object, delta)
            }
            FetchEnd::Object(last) => {
                LocationFilter::range_to(self.start_group, self.start_object, delta, last)
            }
        };
        filter.map_err(|e| AnyConnectionError::facade(e.to_string()))
    }
}

/// Where a **Joining** FETCH starts, said once for the two forms the drafts
/// give it.
///
/// A Joining FETCH names no track and no end. Draft-19 Section 10.12.2: "A
/// Joining Fetch is associated with a Subscribe request by specifying the
/// Request ID of an active subscription. A publisher receiving a Joining Fetch
/// uses properties of the associated Subscribe to determine the Track
/// Namespace, Track Name and End Location such that it is contiguous with the
/// associated Subscribe." So the only thing a subscriber still has to say is
/// where the range *begins* — and the field that says it is one varint called
/// Joining Start, which means two different things depending on a **Fetch
/// Type** written six bytes earlier.
///
/// That is why this is an enum and not a `u64`. Section 10.12.2.1 gives the
/// publisher two sentences for the same field: for a Relative Joining Fetch it
/// sets the Start Location to "{Subscribe Largest Location.Group - Joining
/// Start, 0}", and for an Absolute Joining Fetch it sets the Start Location "to
/// Joining Start". A caller handing `3` to a single-number entry point would be
/// asking for three groups of history on one call and for the whole track from
/// Group 3 on the other, with nothing in the argument to say which was meant.
///
/// [`AnyConnection::fetch_joining`] turns the variant into the Fetch Type as
/// well as the number, so the two cannot come apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoiningStart {
    /// Start this many Groups **before** the joined subscription's Largest
    /// Location — Fetch Type `0x2`, Relative Joining.
    ///
    /// `GroupsBefore(0)` is the subscription's own current Group and nothing
    /// earlier; `GroupsBefore(1)` adds the Group before it. The publisher
    /// clamps at zero — "{Subscribe Largest Location.Group - Joining Start,
    /// 0}" — so an offset larger than the track is long asks for the whole of
    /// it rather than being an error.
    ///
    /// This is the form a subscriber that has **not** been told a Largest
    /// Location can still use, which is most of them: it is the publisher that
    /// does the subtraction.
    GroupsBefore(u64),
    /// Start at this Group, absolutely — Fetch Type `0x3`, Absolute Joining.
    ///
    /// The Start Location is `{Group, 0}`. Drafts 08 through 10 have no such
    /// Fetch Type — their FETCH offers Standalone and one Joining kind, and
    /// draft-11 is where the pair arrives — so this variant is refused there
    /// rather than sent as the relative one, which would ask a completely
    /// different question.
    Group(u64),
}

/// Where a subscription's range stops, said once in a way no draft can read two
/// ways.
///
/// A SUBSCRIBE that names a start location may also name an end, and the
/// drafts spell that end three different ways. Draft-07 Section 6.4
/// gives the AbsoluteRange filter an End Group **and** an End Object, with
/// FETCH's own conventions — "the end Object ID, plus 1. A value of 0 means the
/// entire group is requested." Draft-08 deleted the End Object and redefined
/// the End Group as "the end Group ID, inclusive", and drafts 09 through 19
/// kept it that way. Draft-20 Section 5.1.2 then brought an end Object back, as
/// the fourth field of a `LOCATION_FILTER` whose range is **inclusive** at both
/// ends with no plus one anywhere.
///
/// One `end_object: u64` at this boundary would therefore have meant the last
/// Object on two drafts, the last Object plus one on one of them, and nothing
/// at all on the other eleven — which is [`FetchEnd`]'s problem a second time,
/// in a place where it is worse: there, every draft could at least carry the
/// field.
///
/// So [`SubscribeEnd::EndOfGroup`] is the end every draft with a range can
/// express, and [`SubscribeEnd::ThroughObject`] is the one only draft-07 and
/// drafts 20 and 21 can. The twelve drafts between them **refuse** it rather than
/// rounding it up to the whole group, because a subscription that quietly
/// covers more than it asked for is one whose extra objects look like a relay
/// ignoring the range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeEnd {
    /// No end at all — the AbsoluteStart filter. Every draft has it.
    ///
    /// On draft-20 alone this is not expressible from the start location
    /// `{0, 0}`; see [`SubscribeRange::location_filter_draft20`] for the collision and
    /// for the two ways round it.
    Open,
    /// Through the whole of this Group, however many Objects it turns out to
    /// hold. The Group is **absolute** on every draft, including the ones that
    /// put a delta on the wire.
    EndOfGroup(u64),
    /// Through this Object of this Group, **inclusive** — it is the last Object
    /// the subscription covers, and the range holds it.
    ///
    /// Expressible on draft-07 and draft-20 and on nothing between them. See
    /// [`SubscribeEnd`] for why those two and not the twelve in the middle, and
    /// [`SubscribeRange::inline_end_location`] for the plus one draft-07 needs
    /// and draft-20 must not have.
    ThroughObject {
        /// The Group the range ends in, absolute.
        end_group: u64,
        /// The last Object of `end_group` the range covers.
        end_object: u64,
    },
}

/// The range one [`AnyConnection::subscribe_range`] asks for.
///
/// The start is a plain Location on all the drafts and needs no type; the
/// end is [`SubscribeEnd`], which is the whole point. What the drafts do to the
/// **end Group** is handled here rather than by the caller: drafts 08 through 16
/// write it out in full, drafts 17 through 20 write it as a delta from the start
/// Group, and this type takes the absolute value and derives the delta — the
/// same split, and the same direction of travel, as [`FetchRange`].
///
/// # Which filter this is
///
/// [`SubscribeEnd::Open`] is the AbsoluteStart filter and everything else is
/// AbsoluteRange. The Filter Type is never taken as an argument beside the
/// fields, because that is the bug this type exists to make unavailable: a
/// SUBSCRIBE naming AbsoluteStart with no Start Location beside it is a frame
/// whose declared length is short by the fields its own type promised, and the
/// publisher reading it runs off the end of the message with nothing local to
/// complain. See `AnyConnection::subscribe`, which refuses both filters for
/// exactly that reason and points here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeRange {
    /// The Group the range starts in.
    pub start_group: u64,
    /// The Object within `start_group` the range starts at, inclusive.
    pub start_object: u64,
    /// Where the range stops.
    pub end: SubscribeEnd,
}

impl SubscribeRange {
    /// From this Location onward, with no end: the AbsoluteStart filter.
    pub fn starting_at(start_group: u64, start_object: u64) -> Self {
        Self { start_group, start_object, end: SubscribeEnd::Open }
    }

    /// From this Location through the whole of `end_group`.
    ///
    /// `end_group` is absolute and must not be below `start_group` — drafts 17
    /// and later encode it as an unsigned delta from the start and have no way
    /// to say "backwards".
    pub fn through_end_of_group(start_group: u64, start_object: u64, end_group: u64) -> Self {
        Self { start_group, start_object, end: SubscribeEnd::EndOfGroup(end_group) }
    }

    /// From this Location through `end_object` of `end_group`, **inclusive**.
    ///
    /// Drafts 07 and 20 only. See [`SubscribeEnd::ThroughObject`].
    pub fn through_object(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> Self {
        Self {
            start_group,
            start_object,
            end: SubscribeEnd::ThroughObject { end_group, end_object },
        }
    }

    /// The whole of one Group, from its first Object.
    ///
    /// The shape a caller asking "what has this track carried in group N"
    /// wants, and the one that is expressible on all the drafts.
    pub fn whole_group(group: u64) -> Self {
        Self::through_end_of_group(group, 0, group)
    }

    /// Which of the two filters this range names.
    pub fn filter_type(&self) -> moqtap_codec::types::FilterType {
        match self.end {
            SubscribeEnd::Open => moqtap_codec::types::FilterType::AbsoluteStart,
            _ => moqtap_codec::types::FilterType::AbsoluteRange,
        }
    }

    /// The Start Location every draft carrying this range puts on the wire.
    pub fn start_location(&self) -> moqtap_codec::types::Location {
        moqtap_codec::types::Location {
            group: moqtap_codec::varint::VarInt::from_u64_moqt(self.start_group),
            object: moqtap_codec::varint::VarInt::from_u64_moqt(self.start_object),
        }
    }

    /// The end Group in full, or `None` for an open-ended range.
    pub fn end_group(&self) -> Option<u64> {
        match self.end {
            SubscribeEnd::Open => None,
            SubscribeEnd::EndOfGroup(group)
            | SubscribeEnd::ThroughObject { end_group: group, .. } => Some(group),
        }
    }

    /// The `End Location` draft-07 carries inline: the end Group, and the end
    /// Object **plus one**, with `0` meaning the whole Group.
    ///
    /// Draft-07 Section 6.4 gives its AbsoluteRange filter FETCH's two fields
    /// and FETCH's two conventions, in the same words, which is why
    /// `moqtap_codec::types::check_location_range` checks both. So this is
    /// [`FetchRange::inline_end_object`]'s arithmetic on the one draft where a
    /// *subscription* needs it, and it lives here rather than being reached for
    /// from there so that the two cannot drift into disagreeing about a
    /// sentence they share.
    ///
    /// # Errors
    ///
    /// [`SubscribeEnd::ThroughObject`] with `end_object` at `u64::MAX`: the plus
    /// one leaves the number space, and wrapping it to `0` would silently widen
    /// the range to the whole Group. Draft-20 can express that range and
    /// draft-07 cannot.
    pub fn inline_end_location(
        &self,
    ) -> Result<Option<moqtap_codec::types::Location>, AnyConnectionError> {
        let raw = match self.end {
            SubscribeEnd::Open => return Ok(None),
            SubscribeEnd::EndOfGroup(group) => (group, 0),
            SubscribeEnd::ThroughObject { end_group, end_object } => {
                let plus_one = end_object.checked_add(1).ok_or_else(|| {
                    AnyConnectionError::facade(format!(
                        "subscribe_range: a range ending at Object {end_object} cannot be \
                         expressed on draft-07, whose End Location.Object is the last Object plus 1"
                    ))
                })?;
                (end_group, plus_one)
            }
        };
        Ok(Some(moqtap_codec::types::Location {
            group: moqtap_codec::varint::VarInt::from_u64_moqt(raw.0),
            object: moqtap_codec::varint::VarInt::from_u64_moqt(raw.1),
        }))
    }

    /// The end Group drafts 08 through 19 carry, which is a Group and never a
    /// Location.
    ///
    /// # Errors
    ///
    /// [`SubscribeEnd::ThroughObject`], which those twelve drafts deleted the
    /// field for. Refused rather than widened to the whole Group: see
    /// [`SubscribeEnd`].
    fn group_only_end(&self, draft: DraftVersion) -> Result<Option<u64>, AnyConnectionError> {
        match self.end {
            SubscribeEnd::Open => Ok(None),
            SubscribeEnd::EndOfGroup(group) => Ok(Some(group)),
            SubscribeEnd::ThroughObject { .. } => Err(AnyConnectionError::facade(format!(
                "subscribe_range: draft-{:02} carries no End Object on SUBSCRIBE — draft-08 \
                 deleted the field and draft-20 restored it inside LOCATION_FILTER, so a range \
                 ending inside a group is expressible on draft-07 and draft-20 alone. Ask for \
                 the whole group with SubscribeEnd::EndOfGroup",
                draft.number()
            ))),
        }
    }

    /// The end Group as drafts 17 and later write it: a delta from the start
    /// Group.
    ///
    /// # Errors
    ///
    /// An `end_group` below `start_group`. The delta is unsigned and there is no
    /// such filter; drafts 08 through 16 have an absolute field and would put
    /// the range on the wire, where the publisher refuses it. The difference is
    /// where the refusal happens, not whether the range is legal.
    pub fn end_group_delta(&self) -> Result<Option<u64>, AnyConnectionError> {
        let Some(end_group) = self.end_group() else {
            return Ok(None);
        };
        end_group.checked_sub(self.start_group).map(Some).ok_or_else(|| {
            AnyConnectionError::facade(format!(
                "subscribe_range: a range from Group {} to Group {end_group} runs backwards, and \
                 drafts 17 and later encode the end Group as an unsigned delta from the start",
                self.start_group
            ))
        })
    }

    /// This range as the filter parameter drafts 15 through 19 carry it in.
    ///
    /// `delta` is what those drafts disagree about among themselves: 15 and 16
    /// write the End Group out in full, and 17 introduced the delta. The codec's
    /// [`SubscriptionFilter`](moqtap_codec::subscription_filter::SubscriptionFilter)
    /// refuses a filter whose end is spelled the other draft's way, so the two
    /// cannot be mixed up silently here.
    ///
    /// # Errors
    ///
    /// [`SubscribeEnd::ThroughObject`], which these five drafts have no field
    /// for — the same wall drafts 08 through 14 hit, one layer along. It is
    /// worth saying twice because it is not obvious from the shape of the code:
    /// the filter these drafts carry has a Start *Location* and an End *Group*,
    /// so a range ending inside a group has nowhere to put its Object and would
    /// otherwise be written out as the whole group with nothing to say it had
    /// been widened.
    ///
    /// And an `end_group` below `start_group` on the drafts that write a delta.
    pub fn subscription_filter(
        &self,
        draft: DraftVersion,
        delta: bool,
    ) -> Result<moqtap_codec::subscription_filter::SubscriptionFilter, AnyConnectionError> {
        use moqtap_codec::subscription_filter::{FilterEnd, SubscriptionFilter};

        let end_group = match (self.group_only_end(draft)?, delta) {
            (None, _) => None,
            (Some(group), false) => Some(FilterEnd::Group(group)),
            (Some(_), true) => {
                Some(FilterEnd::GroupDelta(self.end_group_delta()?.unwrap_or_default()))
            }
        };
        Ok(SubscriptionFilter {
            filter_type: self.filter_type(),
            start_location: Some(self.start_location()),
            end_group,
        })
    }

    /// This range as the draft-20 `LOCATION_FILTER` that carries it.
    ///
    /// Two fields for an open-ended range, three for one through the end of a
    /// Group, four for one ending at an Object — Section 5.1.2 selects the shape
    /// by how many fields the value holds, so each of the three is a different
    /// constructor rather than the same one with values left out.
    ///
    /// # `{0, 0}` means the opposite here, and is refused
    ///
    /// On drafts 07 through 19 an AbsoluteStart at `{0, 0}` is the beginning of
    /// the track. Draft-20 Section 5.1.2 gives the two-field filter `{0, 0}` to
    /// **Next Object** — `{Largest Object.Group, Largest Object.Object + 1}`,
    /// or `{0,0}` where nothing has been delivered — which is the live edge and
    /// not the beginning. The identical call would therefore ask thirteen drafts
    /// for everything and draft-20 for nothing that has already happened, and
    /// nothing on the wire says which was meant.
    ///
    /// So it is refused, and the error names both ways round it: a range
    /// (`through_end_of_group`, which is three fields and unambiguous) for the
    /// beginning of the track, and
    /// [`LocationFilter::next_object`](crate::draft20::fill::LocationFilter::next_object)
    /// through the draft-20 variant for the live edge. This is the only value on
    /// the only draft where the two readings collide: a `{0, 0}` start with an
    /// end beside it is three or four fields and means what it says, and any
    /// other start location is unambiguous with or without one.
    ///
    /// # Errors
    ///
    /// The `{0, 0}` collision above, and an `end_group` below `start_group`, for
    /// which see [`Self::end_group_delta`].
    /// The name carries the draft because the type does: `LOCATION_FILTER`
    /// is draft-20's and later's, and each draft's `fill` module declares its
    /// own `LocationFilter`. An unsuffixed name would be two inherent methods
    /// of one name the moment a second draft defines the parameter.
    #[cfg(feature = "draft20")]
    pub fn location_filter_draft20(
        &self,
    ) -> Result<crate::draft20::fill::LocationFilter, AnyConnectionError> {
        use crate::draft20::fill::LocationFilter;

        let filter = match self.end {
            SubscribeEnd::Open if self.start_group == 0 && self.start_object == 0 => {
                return Err(AnyConnectionError::facade(
                    "subscribe_range: draft-20 Section 5.1.2 reads a two-field LOCATION_FILTER of \
                     {0, 0} as Next Object — the live edge — where drafts 07 through 19 read an \
                     AbsoluteStart at {0, 0} as the beginning of the track. For the beginning, \
                     give the range an end: SubscribeRange::through_end_of_group. For the live \
                     edge, LocationFilter::next_object through the Draft20 variant",
                ));
            }
            SubscribeEnd::Open => {
                Ok(LocationFilter::absolute_start(self.start_group, self.start_object))
            }
            SubscribeEnd::EndOfGroup(_) => LocationFilter::range(
                self.start_group,
                self.start_object,
                self.end_group_delta()?.unwrap_or_default(),
            ),
            SubscribeEnd::ThroughObject { end_object, .. } => LocationFilter::range_to(
                self.start_group,
                self.start_object,
                self.end_group_delta()?.unwrap_or_default(),
                end_object,
            ),
        };
        filter.map_err(|e| AnyConnectionError::facade(e.to_string()))
    }
    /// This range as the draft-21 `LOCATION_FILTER` that carries it.
    ///
    /// Two fields for an open-ended range, three for one through the end of a
    /// Group, four for one ending at an Object — Section 9.20.10 selects the shape
    /// by how many fields the value holds, so each of the three is a different
    /// constructor rather than the same one with values left out.
    ///
    /// # `{0, 0}` means the opposite here, and is refused
    ///
    /// On drafts 07 through 19 an AbsoluteStart at `{0, 0}` is the beginning of
    /// the track. Draft-21 Section 9.20.10 gives the two-field filter `{0, 0}` to
    /// **Next Object** — `{Largest Object.Group, Largest Object.Object + 1}`,
    /// or `{0,0}` where nothing has been delivered — which is the live edge and
    /// not the beginning. The identical call would therefore ask thirteen drafts
    /// for everything and draft-21 for nothing that has already happened, and
    /// nothing on the wire says which was meant.
    ///
    /// So it is refused, and the error names both ways round it: a range
    /// (`through_end_of_group`, which is three fields and unambiguous) for the
    /// beginning of the track, and
    /// [`LocationFilter::next_object`](crate::draft21::fill::LocationFilter::next_object)
    /// through the draft-21 variant for the live edge. This is the only value on
    /// the only draft where the two readings collide: a `{0, 0}` start with an
    /// end beside it is three or four fields and means what it says, and any
    /// other start location is unambiguous with or without one.
    ///
    /// # Errors
    ///
    /// The `{0, 0}` collision above, and an `end_group` below `start_group`, for
    /// which see [`Self::end_group_delta`].
    /// The name carries the draft because the type does: `LOCATION_FILTER`
    /// is draft-21's and later's, and each draft's `fill` module declares its
    /// own `LocationFilter`. An unsuffixed name would be two inherent methods
    /// of one name the moment a second draft defines the parameter.
    #[cfg(feature = "draft21")]
    pub fn location_filter_draft21(
        &self,
    ) -> Result<crate::draft21::fill::LocationFilter, AnyConnectionError> {
        use crate::draft21::fill::LocationFilter;

        let filter = match self.end {
            SubscribeEnd::Open if self.start_group == 0 && self.start_object == 0 => {
                return Err(AnyConnectionError::facade(
                    "subscribe_range: draft-21 Section 9.20.10 reads a two-field LOCATION_FILTER of \
                     {0, 0} as Next Object — the live edge — where drafts 07 through 19 read an \
                     AbsoluteStart at {0, 0} as the beginning of the track. For the beginning, \
                     give the range an end: SubscribeRange::through_end_of_group. For the live \
                     edge, LocationFilter::next_object through the Draft21 variant",
                ));
            }
            SubscribeEnd::Open => {
                Ok(LocationFilter::absolute_start(self.start_group, self.start_object))
            }
            SubscribeEnd::EndOfGroup(_) => LocationFilter::range(
                self.start_group,
                self.start_object,
                self.end_group_delta()?.unwrap_or_default(),
            ),
            SubscribeEnd::ThroughObject { end_object, .. } => LocationFilter::range_to(
                self.start_group,
                self.start_object,
                self.end_group_delta()?.unwrap_or_default(),
                end_object,
            ),
        };
        filter.map_err(|e| AnyConnectionError::facade(e.to_string()))
    }
}

/// A request made through [`AnyConnection`], in whichever form the negotiated
/// draft carries it.
///
/// Drafts 07-15 put every request on the single bidirectional control stream,
/// so all a requester keeps is the request ID it was allocated. Draft-16 moved
/// one request off it: Section 3.3 there names "two uses of bidirectional
/// streams, the control stream, which begins with CLIENT_SETUP, and
/// SUBSCRIBE_NAMESPACE", so a namespace subscription on that draft owns a
/// stream and everything else does not. From draft-17 on every request does,
/// and the stream *is* the correlation — responses on those drafts carry no
/// request ID at all. The variants reflect that split rather than hiding it.
///
/// Hold on to this value for as long as the request is live. Dropping a
/// per-request variant resets its stream, which the peer reads as a
/// cancellation; dropping [`AnyRequest::ControlPlane`] does nothing, because
/// there is no stream to reset.
///
/// The per-request variants are large — a `RequestStream` holds both halves of
/// a QUIC stream — and `ControlPlane` is two small fields. That disparity is
/// only visible when a single draft from 17 on is the only one enabled; with
/// more than one, the largest variants are the same size as each other.
/// Boxing them to close it would put an allocation on every request of every
/// draft to flatter a build no released configuration uses.
#[allow(clippy::large_enum_variant)]
#[must_use = "dropping a request stream cancels the request"]
pub enum AnyRequest {
    /// Drafts 07-16: the request was written on the control stream and is
    /// identified only by its request ID.
    ControlPlane {
        /// The request ID the endpoint allocated.
        request_id: moqtap_codec::varint::VarInt,
        /// The draft that allocated it.
        draft: DraftVersion,
    },
    /// Draft-16: a namespace subscription, the one request on that draft that
    /// owns a bidirectional stream. Every other draft-16 request comes back as
    /// [`AnyRequest::ControlPlane`].
    #[cfg(feature = "draft16")]
    Draft16(crate::draft16::connection::NamespaceStream),
    /// Draft-17: the request owns a bidirectional stream.
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::connection::RequestStream),
    /// Draft-18: the request owns a bidirectional stream.
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::connection::RequestStream),
    /// Draft-19: the request owns a bidirectional stream.
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::connection::RequestStream),
    /// Draft-20: the request owns a bidirectional stream.
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::connection::RequestStream),
    /// Draft-21: the request owns a bidirectional stream.
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::connection::RequestStream),
}

impl AnyRequest {
    /// The request ID this request was allocated.
    pub fn request_id(&self) -> moqtap_codec::varint::VarInt {
        match self {
            Self::ControlPlane { request_id, .. } => *request_id,
            #[cfg(feature = "draft16")]
            Self::Draft16(r) => r.request_id(),
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => r.request_id(),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => r.request_id(),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => r.request_id(),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => r.request_id(),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => r.request_id(),
        }
    }

    /// The draft that carries this request.
    pub fn draft(&self) -> DraftVersion {
        match self {
            Self::ControlPlane { draft, .. } => *draft,
            #[cfg(feature = "draft16")]
            Self::Draft16(r) => r.draft(),
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => r.draft(),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => r.draft(),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => r.draft(),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => r.draft(),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => r.draft(),
        }
    }

    /// Which stream this request owns, or `None` on a draft that carries
    /// requests on the shared control stream.
    ///
    /// This is the observable difference between the two variants: a caller
    /// that needs to correlate a response by stream — which is the only
    /// correlation drafts 17-19 offer — gets `Some` exactly when the draft
    /// provides one.
    ///
    /// The number is quinn's `StreamId::index()`, an ordinal within the
    /// stream's own (initiator, directionality) class rather than the QUIC
    /// stream number; every request stream is client-initiated and
    /// bidirectional, so within that use the ordinals separate cleanly. See
    /// [`AnySubgroupWriter::stream_id`], where the distinction matters because
    /// data streams and control streams are not of one class.
    pub fn stream_id(&self) -> Option<u64> {
        match self {
            Self::ControlPlane { .. } => None,
            #[cfg(feature = "draft16")]
            Self::Draft16(r) => Some(r.stream_id()),
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => Some(r.stream_id()),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => Some(r.stream_id()),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => Some(r.stream_id()),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => Some(r.stream_id()),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => Some(r.stream_id()),
        }
    }

    /// Cancel the request by resetting its stream with `code`.
    ///
    /// Only a request that owns a stream can do this, which is a draft-16
    /// namespace subscription and every request from draft-17 on. Cancelling a
    /// request that lives on the control stream means sending a message
    /// (UNSUBSCRIBE, FETCH_CANCEL, and so on), which needs the connection and
    /// is therefore not reachable from the request handle alone. There this
    /// refuses rather than silently doing nothing.
    #[allow(unused_variables)]
    pub fn cancel(&mut self, code: u64) -> Result<(), AnyConnectionError> {
        match self {
            Self::ControlPlane { draft, .. } => Err(AnyConnectionError::facade(format!(
                "cancel: draft {draft:?} carries this request on the control stream, so the \
                 request handle has no stream to reset; send the draft's own cancellation \
                 message instead"
            ))),
            #[cfg(feature = "draft16")]
            Self::Draft16(r) => r.cancel(code).map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => r.cancel(code).map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => r.cancel(code).map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => r.cancel(code).map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => r.cancel(code).map_err(AnyConnectionError::from),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => r.cancel(code).map_err(AnyConnectionError::from),
        }
    }
}

/// A request the **peer** made, and the handle this side answers it through.
///
/// The mirror of [`AnyRequest`], and split the same way and for the same
/// reason: drafts 07 through 16 carry every request on one shared control
/// stream and identify it by its Request ID, and from draft-17 each request
/// owns a bidirectional stream that *is* its identity. What differs is who
/// allocated the ID — here the peer did, so it is read off the message rather
/// than out of this endpoint's own sequence.
///
/// There is no `Draft16` stream variant, unlike [`AnyRequest`]. Draft-16 gave a
/// stream to namespace *subscriptions* alone, and an inbound SUBSCRIBE on that
/// draft still arrives on the control stream.
///
/// Dropping an unanswered request from draft-17 on resets its stream, which the
/// peer reads as a refusal. Dropping a [`AnyInboundRequest::ControlPlane`] does
/// nothing at all, and the peer is left waiting — refusing there means sending
/// the draft's own error message through the variant.
#[allow(clippy::large_enum_variant)]
#[must_use = "dropping an unanswered request refuses it on the drafts that can"]
pub enum AnyInboundRequest {
    /// Drafts 07-16: identified only by the Request ID the peer allocated.
    ControlPlane {
        /// The Request ID the peer put on the message.
        request_id: moqtap_codec::varint::VarInt,
        /// The draft that carried it.
        draft: DraftVersion,
    },
    /// Draft-17: the request arrived on a bidirectional stream of its own.
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::connection::RequestStream),
    /// Draft-18: the request arrived on a bidirectional stream of its own.
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::connection::RequestStream),
    /// Draft-19: the request arrived on a bidirectional stream of its own.
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::connection::RequestStream),
    /// Draft-20: the request arrived on a bidirectional stream of its own.
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::connection::RequestStream),
    /// Draft-21: the request arrived on a bidirectional stream of its own.
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::connection::RequestStream),
}

impl AnyInboundRequest {
    /// The Request ID the peer allocated for this request.
    pub fn request_id(&self) -> moqtap_codec::varint::VarInt {
        match self {
            Self::ControlPlane { request_id, .. } => *request_id,
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => r.request_id(),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => r.request_id(),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => r.request_id(),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => r.request_id(),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => r.request_id(),
        }
    }

    /// The draft that carries this request.
    pub fn draft(&self) -> DraftVersion {
        match self {
            Self::ControlPlane { draft, .. } => *draft,
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => r.draft(),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => r.draft(),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => r.draft(),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => r.draft(),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => r.draft(),
        }
    }

    /// The transport stream this request arrived on, or `None` on a draft that
    /// carries inbound requests on the shared control stream.
    ///
    /// The same observable difference [`AnyRequest::stream_id`] exposes, in the
    /// other direction.
    pub fn stream_id(&self) -> Option<u64> {
        match self {
            Self::ControlPlane { .. } => None,
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => Some(r.stream_id()),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => Some(r.stream_id()),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => Some(r.stream_id()),
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => Some(r.stream_id()),
            #[cfg(feature = "draft21")]
            Self::Draft21(r) => Some(r.stream_id()),
        }
    }
}

/// What arrived from the peer, and whether this facade has a handle for it.
///
/// [`AnyConnection::recv_inbound`] returns one of these per message. Everything
/// is returned rather than filtered, because on drafts 07 through 16 the same
/// stream carries the peer's requests *and* the answers to this side's own —
/// a reader that quietly dropped what it was not looking for would swallow a
/// SUBSCRIBE_OK somebody was waiting on.
///
/// The variants differ in size for the reason [`AnyRequest`]'s do — one of them
/// carries a request stream and the other does not — and boxing to close the
/// gap would put an allocation on every message of every draft to flatter a
/// build no released configuration uses.
#[allow(clippy::large_enum_variant)]
pub enum AnyArrival {
    /// The peer subscribed to a track this session publishes.
    ///
    /// Answer it with [`AnyConnection::accept_subscribe`]. The message is the
    /// SUBSCRIBE as it arrived, which is where the track it names lives — and,
    /// on drafts 07 through 11, the Track Alias the subscriber chose.
    Subscribe {
        /// The SUBSCRIBE, decoded by the negotiated draft.
        message: moqtap_codec::dispatch::AnyControlMessage,
        /// The handle to answer it through.
        request: AnyInboundRequest,
    },
    /// Anything else the peer sent.
    ///
    /// On drafts 07 through 16 that is any control message which is not a
    /// SUBSCRIBE: a response to one of this side's own requests, or something
    /// sent unprompted such as MAX_REQUEST_ID. It has already been dispatched
    /// into the endpoint by the time it arrives here, so the session's state is
    /// correct whether the caller reads it or not.
    ///
    /// From draft-17 it is a request of a kind this facade has no entry point
    /// for, and **its stream has already been reset** — there is no handle in
    /// this variant to hold it open with, and a stream nobody holds is one the
    /// peer is owed an answer on forever. That asymmetry is real: on the older
    /// drafts this variant is passive, and on the newer ones producing it
    /// refuses something.
    Other(moqtap_codec::dispatch::AnyControlMessage),
}

/// One object on a subgroup stream, in the terms every draft shares.
///
/// The drafts give a subgroup object five different struct shapes, and
/// what varies between them is bookkeeping rather than content: whether the
/// extension block is counted or measured, whether the status is a field that
/// is always present or an `Option`, whether the declared length is stored
/// beside the payload or derived from it. None of that is a choice a caller
/// makes. What a caller has is an ID and some bytes.
///
/// The extension block is absent here for a different reason than the rest. It
/// is a property of the **stream**, not of the object — the header settles it
/// once, and an object with nothing to put in the block still writes a length
/// of zero on a stream that carries one, which is why
/// [`moqtap_codec::dispatch::AnySubgroupHeader::carries_extension_block`] is
/// asked of the header. [`AnyConnection::open_subgroup`] opens streams that
/// carry none wherever a draft has a way to say so — eleven of the drafts;
/// [`AnyConnection::accept_subgroup`] reads whichever kind the peer opened, and
/// hands the header over so a caller can ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyObject {
    /// The Object ID, resolved.
    ///
    /// Drafts 14 and later encode it as a delta against the object before it on
    /// the same stream. The per-draft reader has already undone that, so this
    /// is the absolute ID on every draft and a caller never sees the encoding.
    pub object_id: u64,
    /// The payload. Empty when `status` is `Some`.
    pub payload: Vec<u8>,
    /// The Object Status wire code, or `None` when the object carried a payload
    /// instead.
    ///
    /// `None` means the same thing on all the drafts, which is why this is
    /// an `Option` even though half of them model the status as a field that is
    /// always there. Every draft writes the status **only** when the declared
    /// payload length is zero, because the status and the payload occupy the
    /// same position on the wire: no sequence of bytes states both. So the
    /// question "did this object carry a status?" has one answer per object,
    /// and it is the answer the wire gives rather than the one a particular
    /// draft's struct happens to hold.
    pub status: Option<u64>,
}

/// A subgroup stream this endpoint opened and is writing objects to.
///
/// Returned by [`AnyConnection::open_subgroup`]. The header is already on the
/// wire by the time this exists — opening the stream and framing it are one
/// step, because a unidirectional stream with no header on it is not a subgroup
/// stream and there is nothing a caller could do with one.
///
/// Unlike [`AnyRequest`], there is no era split here and no variant that stands
/// for "the draft has no stream for this". Every draft from 07 on carries
/// subgroup objects on a unidirectional stream of their own, and this is the
/// first part of the facade that spans all fourteen without a footnote. The
/// walls that stop the control plane at draft-11 — no ANNOUNCE, no
/// TRACK_STATUS_REQUEST, a request ceiling granted by a message this crate
/// cannot send — are all about *requests*, and none of them touches a data
/// stream.
#[allow(clippy::large_enum_variant)]
pub enum AnySubgroupWriter {
    /// Draft-07's subgroup stream.
    #[cfg(feature = "draft07")]
    Draft07(crate::draft07::connection::FramedSendStream),
    /// Draft-08's subgroup stream.
    #[cfg(feature = "draft08")]
    Draft08(crate::draft08::connection::FramedSendStream),
    /// Draft-09's subgroup stream.
    #[cfg(feature = "draft09")]
    Draft09(crate::draft09::connection::FramedSendStream),
    /// Draft-10's subgroup stream.
    #[cfg(feature = "draft10")]
    Draft10(crate::draft10::connection::FramedSendStream),
    /// Draft-11's subgroup stream.
    #[cfg(feature = "draft11")]
    Draft11(crate::draft11::connection::FramedSendStream),
    /// Draft-12's subgroup stream.
    #[cfg(feature = "draft12")]
    Draft12(crate::draft12::connection::FramedSendStream),
    /// Draft-13's subgroup stream.
    #[cfg(feature = "draft13")]
    Draft13(crate::draft13::connection::FramedSendStream),
    /// Draft-14's subgroup stream.
    #[cfg(feature = "draft14")]
    Draft14(crate::draft14::connection::FramedSendStream),
    /// Draft-15's subgroup stream.
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::connection::FramedSendStream),
    /// Draft-16's subgroup stream.
    #[cfg(feature = "draft16")]
    Draft16(crate::draft16::connection::FramedSendStream),
    /// Draft-17's subgroup stream.
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::connection::FramedSendStream),
    /// Draft-18's subgroup stream.
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::connection::FramedSendStream),
    /// Draft-19's subgroup stream.
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::connection::FramedSendStream),
    /// Draft-20's subgroup stream.
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::connection::FramedSendStream),
    /// Draft-21's subgroup stream.
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::connection::FramedSendStream),
}

/// Expands one body per group of drafts that share a shape, over
/// [`AnySubgroupWriter`], [`AnySubgroupReader`] or [`AnyFetchReader`].
///
/// Every arm is `#[cfg]`-gated on its own draft feature and a catch-all closes
/// the match, so a single-draft build compiles with thirteen arms removed and a
/// no-draft build compiles with all of them removed. The same shape
/// `moqtap_codec`'s `subgroup_header_accessor!` generates, and for the same
/// reason: the alternative is a hand-written arm per draft per method, of which
/// at most five differ.
///
/// Named for data streams rather than for subgroups because a fetch stream is
/// the other kind and reads through the same shape. Every variant it is used
/// over therefore holds **exactly one** field — which is why
/// [`AnyFetchReader::Draft16`] wraps its stream and its resolver in a
/// [`Draft16FetchStream`] instead of being a two-field variant.
macro_rules! data_stream_dispatch {
    (
        $enum:ident, $self:expr,
        $( [ $( $variant:ident @ $feat:literal ),+ $(,)? ] => |$s:ident, $draft:ident| $body:expr ),+ $(,)?
    ) => {
        match $self {
            $($(
                #[cfg(feature = $feat)]
                $enum::$variant($s) => {
                    #[allow(unused_variables)]
                    let $draft = DraftVersion::$variant;
                    $body
                }
            )+)+
            #[allow(unreachable_patterns)]
            _ => unreachable!("no draft feature is enabled"),
        }
    };
}

impl AnySubgroupWriter {
    /// The draft framing this stream.
    pub fn draft(&self) -> DraftVersion {
        data_stream_dispatch! {
            AnySubgroupWriter, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |_s, draft| draft,
        }
    }

    /// Which stream this subgroup is being written on.
    ///
    /// Bare rather than an `Option`, unlike [`AnyRequest::stream_id`]: a
    /// subgroup stream *is* a stream on every draft, so there is no era for the
    /// option to describe.
    ///
    /// The number is the transport's own, and it is quinn's `StreamId::index()`
    /// — the stream's ordinal **within its (initiator, directionality) class**
    /// rather than the QUIC stream number. So the first unidirectional stream
    /// this side opens reports `0` whatever else is open, and a number from
    /// here identifies a stream only alongside who opened it and which way it
    /// runs. That is what [`AnyRequest::stream_id`] reports too, where all the
    /// streams being compared are of one class and the ordinal separates them
    /// cleanly.
    pub fn stream_id(&self) -> u64 {
        data_stream_dispatch! {
            AnySubgroupWriter, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |s, _draft| s.stream_id(),
        }
    }

    /// Append one object carrying `payload` under `object_id`.
    ///
    /// # What this fills in, and why none of it is an argument
    ///
    /// The declared payload length is `payload.len()`, always. Drafts 15 and
    /// later store it as a field of the object and refuse an object whose
    /// field disagrees with the bytes beside it — the length is already on the
    /// wire ahead of the payload, so a disagreement produces a frame no reader
    /// can parse and no writer can repair. Drafts 07 through 14 overwrite the
    /// field for the same reason. A caller has no way to want a third answer.
    ///
    /// The status is `Normal` when the payload is empty and absent when it is
    /// not, which is the only pair the wire can express: the status field and
    /// the payload occupy the same position. An object with bytes and a
    /// non-Normal status is asking for two framings at once, and the per-draft
    /// writers refuse it. Sending a real status — END_OF_GROUP, END_OF_TRACK —
    /// is a different call with different rules about where on the track it may
    /// appear, and is reached through the draft's own `Connection` rather than
    /// invented here.
    ///
    /// The extension block is empty, and whether one is written at all was
    /// settled by the header [`AnyConnection::open_subgroup`] put on the
    /// stream. That is not this method's to change: an object that guessed
    /// differently from its header would misframe every object after it.
    // `length` is read by every family but draft-14's, which derives it, and
    // `empty` by draft-14's and later alone, where the status is an `Option`.
    // A single-draft build keeps one arm and so leaves one of them unread.
    #[allow(unused_variables)]
    pub async fn write_object(
        &mut self,
        object_id: u64,
        payload: &[u8],
    ) -> Result<(), AnyConnectionError> {
        use moqtap_codec::varint::VarInt;
        let id = VarInt::from_u64(object_id)
            .map_err(|e| AnyConnectionError::facade(format!("object id {object_id}: {e}")))?;
        let length = VarInt::from_usize(payload.len());
        let empty = payload.is_empty();
        // Five shapes across the drafts, and each one is written once
        // as a macro taking the draft's module. A macro rather than a shared
        // arm because the stream in hand is a different concrete type in every
        // variant: `FramedSendStream` names fourteen structs, not one, so a
        // body written once and matched against several variants type-checks
        // against none of them.
        #[allow(unused_macros)]
        macro_rules! bare {
            // Draft-07 is the one draft with no extension block anywhere, so
            // its object header has no field for one.
            ($s:ident, $m:ident) => {{
                let object = crate::$m::event::SubgroupObject {
                    header: moqtap_codec::$m::data_stream::ObjectHeader {
                        object_id: id,
                        payload_length: length,
                        object_status: moqtap_codec::$m::types::ObjectStatus::Normal,
                    },
                    payload: payload.to_vec(),
                };
                $s.write_subgroup_object(&object).await.map_err(AnyConnectionError::from)
            }};
        }
        #[allow(unused_macros)]
        macro_rules! counted {
            // Draft-08 counts its extensions rather than measuring them.
            ($s:ident, $m:ident) => {{
                let object = crate::$m::event::SubgroupObject {
                    header: moqtap_codec::$m::data_stream::ObjectHeader {
                        object_id: id,
                        extension_count: VarInt::from_usize(0),
                        extensions: Vec::new(),
                        payload_length: length,
                        object_status: moqtap_codec::$m::types::ObjectStatus::Normal,
                    },
                    payload: payload.to_vec(),
                };
                $s.write_subgroup_object(&object).await.map_err(AnyConnectionError::from)
            }};
        }
        #[allow(unused_macros)]
        macro_rules! measured {
            // Draft-09 changed that count to a byte length, and every draft
            // through 13 kept it that way.
            ($s:ident, $m:ident) => {{
                let object = crate::$m::event::SubgroupObject {
                    header: moqtap_codec::$m::data_stream::ObjectHeader {
                        object_id: id,
                        extension_headers_length: VarInt::from_usize(0),
                        extensions: Vec::new(),
                        payload_length: length,
                        object_status: moqtap_codec::$m::types::ObjectStatus::Normal,
                    },
                    payload: payload.to_vec(),
                };
                $s.write_subgroup_object(&object).await.map_err(AnyConnectionError::from)
            }};
        }
        #[allow(unused_macros)]
        macro_rules! derived {
            // Draft-14 takes the declared length from the payload and so has no
            // field for it, and is the one draft to name the status field
            // `status` rather than `object_status`.
            ($s:ident, $m:ident) => {{
                let object = moqtap_codec::$m::data_stream::SubgroupObject {
                    object_id: id,
                    extension_headers: Vec::new(),
                    status: empty.then_some(moqtap_codec::$m::types::ObjectStatus::Normal),
                    payload: payload.to_vec(),
                };
                $s.write_subgroup_object(&object).await.map_err(AnyConnectionError::from)
            }};
        }
        #[allow(unused_macros)]
        macro_rules! declared {
            // Drafts 15 and later put the length back and refuse an object
            // whose field disagrees with the bytes beside it.
            ($s:ident, $m:ident) => {{
                let object = moqtap_codec::$m::data_stream::SubgroupObject {
                    object_id: id,
                    extension_headers: Vec::new(),
                    payload_length: length,
                    object_status: empty.then_some(moqtap_codec::$m::types::ObjectStatus::Normal),
                    payload: payload.to_vec(),
                };
                $s.write_subgroup_object(&object).await.map_err(AnyConnectionError::from)
            }};
        }

        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(s) => bare!(s, draft07),
            #[cfg(feature = "draft08")]
            Self::Draft08(s) => counted!(s, draft08),
            #[cfg(feature = "draft09")]
            Self::Draft09(s) => measured!(s, draft09),
            #[cfg(feature = "draft10")]
            Self::Draft10(s) => measured!(s, draft10),
            #[cfg(feature = "draft11")]
            Self::Draft11(s) => measured!(s, draft11),
            #[cfg(feature = "draft12")]
            Self::Draft12(s) => measured!(s, draft12),
            #[cfg(feature = "draft13")]
            Self::Draft13(s) => measured!(s, draft13),
            #[cfg(feature = "draft14")]
            Self::Draft14(s) => derived!(s, draft14),
            #[cfg(feature = "draft15")]
            Self::Draft15(s) => declared!(s, draft15),
            #[cfg(feature = "draft16")]
            Self::Draft16(s) => declared!(s, draft16),
            #[cfg(feature = "draft17")]
            Self::Draft17(s) => declared!(s, draft17),
            #[cfg(feature = "draft18")]
            Self::Draft18(s) => declared!(s, draft18),
            #[cfg(feature = "draft19")]
            Self::Draft19(s) => declared!(s, draft19),
            #[cfg(feature = "draft20")]
            Self::Draft20(s) => declared!(s, draft20),
            #[cfg(feature = "draft21")]
            Self::Draft21(s) => declared!(s, draft21),
            #[allow(unreachable_patterns)]
            _ => Err(AnyConnectionError::facade("no draft feature is enabled")),
        }
    }

    /// Close the stream, which ends the subgroup.
    ///
    /// A subgroup has no terminator message on any draft: the stream ending
    /// *is* the end of it. So this is not a courtesy — a reader on the far side
    /// is waiting for either another object or the end, and cannot tell which
    /// is coming until one of them arrives.
    pub async fn finish(&mut self) -> Result<(), AnyConnectionError> {
        data_stream_dispatch! {
            AnySubgroupWriter, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |s, _draft| {
                s.finish().await.map_err(AnyConnectionError::from)
            },
        }
    }
}

/// A subgroup stream the **peer** opened, that this endpoint is reading.
///
/// The mirror of [`AnySubgroupWriter`], returned by
/// [`AnyConnection::accept_subgroup`] beside the header the peer framed it
/// with.
#[allow(clippy::large_enum_variant)]
pub enum AnySubgroupReader {
    /// Draft-07's subgroup stream.
    #[cfg(feature = "draft07")]
    Draft07(crate::draft07::connection::FramedRecvStream),
    /// Draft-08's subgroup stream.
    #[cfg(feature = "draft08")]
    Draft08(crate::draft08::connection::FramedRecvStream),
    /// Draft-09's subgroup stream.
    #[cfg(feature = "draft09")]
    Draft09(crate::draft09::connection::FramedRecvStream),
    /// Draft-10's subgroup stream.
    #[cfg(feature = "draft10")]
    Draft10(crate::draft10::connection::FramedRecvStream),
    /// Draft-11's subgroup stream.
    #[cfg(feature = "draft11")]
    Draft11(crate::draft11::connection::FramedRecvStream),
    /// Draft-12's subgroup stream.
    #[cfg(feature = "draft12")]
    Draft12(crate::draft12::connection::FramedRecvStream),
    /// Draft-13's subgroup stream.
    #[cfg(feature = "draft13")]
    Draft13(crate::draft13::connection::FramedRecvStream),
    /// Draft-14's subgroup stream.
    #[cfg(feature = "draft14")]
    Draft14(crate::draft14::connection::FramedRecvStream),
    /// Draft-15's subgroup stream.
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::connection::FramedRecvStream),
    /// Draft-16's subgroup stream.
    #[cfg(feature = "draft16")]
    Draft16(crate::draft16::connection::FramedRecvStream),
    /// Draft-17's subgroup stream.
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::connection::FramedRecvStream),
    /// Draft-18's subgroup stream.
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::connection::FramedRecvStream),
    /// Draft-19's subgroup stream.
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::connection::FramedRecvStream),
    /// Draft-20's subgroup stream.
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::connection::FramedRecvStream),
    /// Draft-21's subgroup stream.
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::connection::FramedRecvStream),
}

impl AnySubgroupReader {
    /// The draft framing this stream.
    pub fn draft(&self) -> DraftVersion {
        data_stream_dispatch! {
            AnySubgroupReader, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |_s, draft| draft,
        }
    }

    /// Which stream this subgroup arrived on, on the terms
    /// [`AnySubgroupWriter::stream_id`] describes.
    pub fn stream_id(&self) -> u64 {
        data_stream_dispatch! {
            AnySubgroupReader, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |s, _draft| s.stream_id(),
        }
    }

    /// Read the next object on this subgroup.
    ///
    /// # The stream's end arrives as an error, not as `None`
    ///
    /// A subgroup ends when its stream ends, and none of the per-draft
    /// readers can tell that end from a truncation: both leave the reader
    /// wanting bytes that never come, and both surface as
    /// `ConnectionError::UnexpectedEnd`. Returning `Option` here would have to
    /// invent the distinction, and inventing it means reporting a stream the
    /// peer cut off mid-object as a subgroup that finished — which is exactly
    /// the case a caller most needs to know about.
    ///
    /// So a caller that expects a known number of objects reads that many, and
    /// one that does not treats the error as the end and keeps whatever it read
    /// before it. Neither has to guess.
    pub async fn read_object(&mut self) -> Result<AnyObject, AnyConnectionError> {
        data_stream_dispatch! {
            AnySubgroupReader, self,
            // Drafts 07 through 13 model the status as a field that is always
            // present. The wire does not: it carries one only when the declared
            // length is zero, and the per-draft decoder fills in `Normal` for
            // every object it read a payload for. Reporting that filled-in value
            // as though the peer had sent it would make `AnyObject::status` mean
            // something different on these seven drafts than on the other seven.
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13",
            ] => |s, _draft| {
                let object = s.read_subgroup_object().await
                    .map_err(AnyConnectionError::from)?;
                Ok(AnyObject {
                    object_id: object.header.object_id.into_inner(),
                    status: object
                        .payload
                        .is_empty()
                        .then_some(object.header.object_status as u64),
                    payload: object.payload,
                })
            },
            [Draft14 @ "draft14"] => |s, _draft| {
                let object = s.read_subgroup_object().await
                    .map_err(AnyConnectionError::from)?;
                Ok(AnyObject {
                    object_id: object.object_id.into_inner(),
                    status: object.status.map(|s| s as u64),
                    payload: object.payload,
                })
            },
            [
                Draft15 @ "draft15", Draft16 @ "draft16", Draft17 @ "draft17",
                Draft18 @ "draft18", Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |s, _draft| {
                let object = s.read_subgroup_object().await
                    .map_err(AnyConnectionError::from)?;
                Ok(AnyObject {
                    object_id: object.object_id.into_inner(),
                    status: object.object_status.map(|s| s as u64),
                    payload: object.payload,
                })
            },
        }
    }
}

/// One object on a **fetch** stream, in the terms every draft shares.
///
/// [`AnyObject`]'s twin, and it needs three fields that one does not, because a
/// fetch stream is not a subgroup stream with a different header on it. A
/// subgroup stream's header names the Group and the Subgroup once and every
/// object on it belongs to them; a fetch stream carries a whole range, so each
/// object states its own Location — and from draft-15 it states it by
/// *inheritance*, leaving fields off the wire that the object before it
/// supplies. Every value here is resolved: what a caller gets is where the
/// object is, never what the wire happened to write down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyFetchObject {
    /// The Group this object belongs to, resolved.
    pub group_id: u64,
    /// The Subgroup, resolved, and `None` where the draft lets an object on a
    /// fetch stream have none.
    ///
    /// Drafts 07 through 15 always carry it. From draft-16 an object whose
    /// Forwarding Preference is Datagram omits it — draft-16 Section 10.2.1 —
    /// and so does an end-of-range marker, which is a span rather than an
    /// object.
    pub subgroup_id: Option<u64>,
    /// The Object ID, resolved. Drafts 15 and later may encode it as a step
    /// from the object before it on the stream, and the reader has undone that.
    pub object_id: u64,
    /// The payload. Empty when `status` is `Some`, and empty on every
    /// end-of-range marker.
    pub payload: Vec<u8>,
    /// The Object Status wire code, on the same terms as [`AnyObject::status`]:
    /// `Some` exactly when the object carried no payload, because the two
    /// occupy the same position on the wire.
    ///
    /// **Always `None` from draft-16 on**, and that is the drafts talking
    /// rather than this type giving up: draft-16 deleted the Object Status
    /// field from a fetch object and put [`Self::end_of_range`] in its place.
    /// The pair covers one question between them — *is this an object, or a
    /// statement about objects that are not here* — and which of the two answers
    /// it depends on the draft.
    pub status: Option<u64>,
    /// The end-of-range marker's own wire code, where this "object" is one.
    ///
    /// Drafts 16 through 20 end a fetch that cannot serve part of its range
    /// with a marker rather than with silence, and the marker covers the whole
    /// span from the last serialized object to this Location inclusive:
    /// `0x8C` for a span known not to exist, `0x10C` for one whose status is
    /// unknown, and draft-20 adds `0x20C` for one the publisher abandoned.
    ///
    /// A number rather than an enum for the reason [`crate::dispatch`]'s
    /// neighbours are: the code is the fingerprint, and a fifteenth draft
    /// assigning a fourth marker should widen a report rather than fail to
    /// parse. `None` on drafts 07 through 15, which have no such marker — there
    /// the same news arrives, when it arrives at all, as a [`Self::status`].
    pub end_of_range: Option<u64>,
}

/// Draft-16's fetch stream, carried with the resolver its objects need.
///
/// The one variant of [`AnyFetchReader`] that is not a bare stream, and the
/// reason is a gap one draft wide. All but one of the per-draft
/// `FramedRecvStream`s resolve a fetch object's elided fields themselves —
/// drafts 07 through 14 have nothing to resolve, and 15, 17, 18, 19 and 20 each
/// hold a `FetchObjectReader` on the stream. Draft-16's does not, though
/// `moqtap_codec::draft16::data_stream::FetchObjectReader` exists and does
/// exactly the job.
///
/// So the state lives here. It has to live *somewhere* per stream: a draft-16
/// object may leave out its Group ID, its Subgroup ID, its Object ID and its
/// Priority, and Table 5 gives each absent field a meaning drawn from the
/// object before it. A reader without the object before it does not get a worse
/// answer, it gets no answer at all.
#[cfg(feature = "draft16")]
pub struct Draft16FetchStream {
    stream: crate::draft16::connection::FramedRecvStream,
    reader: moqtap_codec::draft16::data_stream::FetchObjectReader,
}

#[cfg(feature = "draft16")]
impl Draft16FetchStream {
    /// Which stream this fetch arrived on, on the terms
    /// [`AnySubgroupWriter::stream_id`] describes.
    pub fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }
}

/// The Group Order a FETCH_OK named, for handing to
/// [`AnyConnection::accept_fetch`].
///
/// # Why this is a function and not a field lookup at the call site
///
/// Because the field moved twice and the answer is silent when it is wrong.
/// Drafts 07 through 14 put Group Order on FETCH_OK outright. Drafts 15 and 16
/// deleted it from the message. Drafts 17 through 20 brought it back as
/// **Track Property `0x22`**, `DEFAULT PUBLISHER GROUP ORDER`, which is
/// optional — so on the three drafts where the value decides how every Group ID
/// after the first is resolved, the commonest FETCH_OK does not carry it at all.
///
/// [`moqtap_codec::types::GroupOrder::Ascending`] is the answer in that case, and
/// it is the draft's answer rather than this function's: draft-20 Section 10.2.8
/// makes Ascending the default for an omitted property.
///
/// A message that is not a FETCH_OK answers `Ascending` too, and that is not a
/// claim about it — nothing else here has a Group Order to report, and a caller
/// holding the wrong message has a different problem than this can name.
///
/// Written against [`moqtap_codec::dispatch::AnyControlMessage::fields`] rather
/// than as an arm per draft, so a draft that moves the field again is one entry
/// here rather than a match that still compiles.
pub fn fetch_group_order(
    message: &moqtap_codec::dispatch::AnyControlMessage,
) -> moqtap_codec::types::GroupOrder {
    use moqtap_codec::fields::FieldValue;
    use moqtap_codec::types::GroupOrder;

    let named = |code: u64| match code {
        0x2 => GroupOrder::Descending,
        0x1 => GroupOrder::Ascending,
        // Including `0x0`, Publisher — which says the publisher decides and so
        // states no direction. Every consumer of this value needs one.
        _ => GroupOrder::Ascending,
    };

    let fields = message.fields();
    // Drafts 07 through 14, where it is a field of the message.
    if let Some(FieldValue::Uint(code)) = fields.get("group_order") {
        return named(*code);
    }
    // Drafts 17 through 20, where it is one entry of a property list that need
    // not contain it.
    if let Some(FieldValue::Array(properties)) = fields.get("track_properties") {
        for property in properties {
            let FieldValue::Map(entry) = property else { continue };
            if entry.get("name") != Some(&FieldValue::Text("default_publisher_group_order".into()))
            {
                continue;
            }
            if let Some(FieldValue::Uint(code)) = entry.get("value") {
                return named(*code);
            }
        }
    }
    GroupOrder::Ascending
}

/// A fetch stream the **peer** opened, that this endpoint is reading.
///
/// [`AnySubgroupReader`]'s twin, returned by [`AnyConnection::accept_fetch`]
/// beside the FETCH_HEADER the peer framed it with.
///
/// The two are separate types for the reason the per-draft connections keep
/// `accept_fetch_stream` and `accept_subgroup_stream` separate: the header
/// decides how every object after it is framed, so a caller has to know which
/// kind it is expecting before the first byte is read. Nothing here can be
/// handed a subgroup stream and cope.
#[allow(clippy::large_enum_variant)]
pub enum AnyFetchReader {
    /// Draft-07's fetch stream.
    #[cfg(feature = "draft07")]
    Draft07(crate::draft07::connection::FramedRecvStream),
    /// Draft-08's fetch stream.
    #[cfg(feature = "draft08")]
    Draft08(crate::draft08::connection::FramedRecvStream),
    /// Draft-09's fetch stream.
    #[cfg(feature = "draft09")]
    Draft09(crate::draft09::connection::FramedRecvStream),
    /// Draft-10's fetch stream.
    #[cfg(feature = "draft10")]
    Draft10(crate::draft10::connection::FramedRecvStream),
    /// Draft-11's fetch stream.
    #[cfg(feature = "draft11")]
    Draft11(crate::draft11::connection::FramedRecvStream),
    /// Draft-12's fetch stream.
    #[cfg(feature = "draft12")]
    Draft12(crate::draft12::connection::FramedRecvStream),
    /// Draft-13's fetch stream.
    #[cfg(feature = "draft13")]
    Draft13(crate::draft13::connection::FramedRecvStream),
    /// Draft-14's fetch stream.
    #[cfg(feature = "draft14")]
    Draft14(crate::draft14::connection::FramedRecvStream),
    /// Draft-15's fetch stream.
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::connection::FramedRecvStream),
    /// Draft-16's fetch stream, and the resolver its objects need. See
    /// [`Draft16FetchStream`].
    #[cfg(feature = "draft16")]
    Draft16(Draft16FetchStream),
    /// Draft-17's fetch stream.
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::connection::FramedRecvStream),
    /// Draft-18's fetch stream.
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::connection::FramedRecvStream),
    /// Draft-19's fetch stream.
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::connection::FramedRecvStream),
    /// Draft-20's fetch stream.
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::connection::FramedRecvStream),
    /// Draft-21's fetch stream.
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::connection::FramedRecvStream),
}

impl AnyFetchReader {
    /// The draft framing this stream.
    pub fn draft(&self) -> DraftVersion {
        data_stream_dispatch! {
            AnyFetchReader, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |_s, draft| draft,
        }
    }

    /// Which stream this fetch arrived on, on the terms
    /// [`AnySubgroupWriter::stream_id`] describes.
    pub fn stream_id(&self) -> u64 {
        data_stream_dispatch! {
            AnyFetchReader, self,
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
                Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
                Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |s, _draft| s.stream_id(),
        }
    }

    /// Read the next object on this fetch stream.
    ///
    /// # The stream's end arrives as an error, not as `None`
    ///
    /// For the reason [`AnySubgroupReader::read_object`] gives, and one more of
    /// its own: a fetch stream ends when the range it was serving runs out, and
    /// the only thing that says so is the FIN. Returning `Option` would have to
    /// tell that FIN from a peer that stopped mid-object, which no per-draft
    /// reader can.
    ///
    /// # Errors
    ///
    /// Everything [`AnySubgroupReader::read_object`] can raise, and on drafts 15
    /// through 20 one more class of its own: an object that inherits from an
    /// object that does not exist. The first object of a stream may not leave
    /// out its Group ID or its Object ID, and a stream whose first object does
    /// is refused here rather than resolved against zero — draft-16 Section
    /// 10.4.4.1 makes it a PROTOCOL_VIOLATION, and there is no value to produce
    /// even where it does not.
    pub async fn read_object(&mut self) -> Result<AnyFetchObject, AnyConnectionError> {
        data_stream_dispatch! {
            AnyFetchReader, self,
            // Drafts 07 through 13 model the status as a field that is always
            // present, exactly as their subgroup objects do, and the same rule
            // applies for the same reason: the wire carries a status only where
            // the declared length is zero, so a filled-in `Normal` beside a
            // payload is the decoder talking and not the peer.
            [
                Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
                Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
                Draft13 @ "draft13",
            ] => |s, _draft| {
                let object = s.read_fetch_object().await
                    .map_err(AnyConnectionError::from)?;
                Ok(AnyFetchObject {
                    group_id: object.header.group_id.into_inner(),
                    subgroup_id: Some(object.header.subgroup_id.into_inner()),
                    object_id: object.header.object_id.into_inner(),
                    status: object
                        .payload
                        .is_empty()
                        .then_some(object.header.object_status as u64),
                    payload: object.payload,
                    end_of_range: None,
                })
            },
            [Draft14 @ "draft14"] => |s, _draft| {
                let object = s.read_fetch_object().await
                    .map_err(AnyConnectionError::from)?;
                Ok(AnyFetchObject {
                    group_id: object.group_id.into_inner(),
                    subgroup_id: Some(object.subgroup_id.into_inner()),
                    object_id: object.object_id.into_inner(),
                    status: object.status.map(|s| s as u64),
                    payload: object.payload,
                    end_of_range: None,
                })
            },
            // Draft-15 elides fields too, and its own reader resolves them, so
            // what comes back is a header whose every field is a value.
            [Draft15 @ "draft15"] => |s, _draft| {
                let (header, payload) = s.read_fetch_object().await
                    .map_err(AnyConnectionError::from)?;
                Ok(AnyFetchObject {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: Some(header.subgroup_id.into_inner()),
                    object_id: header.object_id.into_inner(),
                    status: header.object_status.map(|s| s as u64),
                    payload,
                    end_of_range: None,
                })
            },
            // The one arm that resolves rather than reads a resolution. See
            // `Draft16FetchStream` for why the state is here and not on the
            // stream.
            [Draft16 @ "draft16"] => |s, _draft| {
                let (header, payload) = s.stream.read_fetch_object().await
                    .map_err(AnyConnectionError::from)?;
                let at = s.reader.resolve(&header)
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                Ok(AnyFetchObject {
                    group_id: at.group_id,
                    subgroup_id: at.subgroup_id,
                    object_id: at.object_id,
                    status: None,
                    payload,
                    end_of_range: at.end_of_range.map(|marker| marker.as_u64()),
                })
            },
            // Drafts 17 through 20 hand back the resolved Location beside the
            // header the wire carried, and the marker is read off the flags
            // rather than off the enum: three drafts name two markers and
            // draft-20 names three, so a shared body naming them would not
            // compile on all four.
            [
                Draft17 @ "draft17", Draft19 @ "draft19", Draft20 @ "draft20", Draft21 @ "draft21",
            ] => |s, _draft| {
                let (object, payload) = s.read_fetch_object().await
                    .map_err(AnyConnectionError::from)?;
                let flags = object.header.serialization_flags.into_inner();
                Ok(AnyFetchObject {
                    group_id: object.group_id,
                    subgroup_id: object.subgroup_id,
                    object_id: object.object_id,
                    status: None,
                    payload,
                    end_of_range: object.header.end_of_range().map(|_| flags),
                })
            },
            // Identical but for the flags field's type, which draft-18 alone
            // holds as a bare `u64`.
            [Draft18 @ "draft18"] => |s, _draft| {
                let (object, payload) = s.read_fetch_object().await
                    .map_err(AnyConnectionError::from)?;
                let flags = object.header.serialization_flags;
                Ok(AnyFetchObject {
                    group_id: object.group_id,
                    subgroup_id: object.subgroup_id,
                    object_id: object.object_id,
                    status: None,
                    payload,
                    end_of_range: object.header.end_of_range().map(|_| flags),
                })
            },
        }
    }
}

impl AnyConnection {
    /// Connect to a MoQT server using the requested draft. Builds the
    /// draft-specific `ClientConfig` from the provided [`AnyClientConfig`]
    /// and dispatches to the appropriate `Connection::connect`.
    pub async fn connect(addr: &str, config: AnyClientConfig) -> Result<Self, AnyConnectionError> {
        // Every arm of the match below is `#[cfg(feature = "draftNN")]`. A build
        // with no draft feature enabled keeps only the catch-all, which never
        // dials anything, so `addr` is genuinely unread in exactly that build.
        #[cfg(not(any(
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
            feature = "draft19",
            feature = "draft20",
            feature = "draft21"
        )))]
        let _ = addr;
        match config.draft {
            #[cfg(feature = "draft07")]
            DraftVersion::Draft07 => {
                use crate::draft07::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft07(c))
            }
            #[cfg(feature = "draft08")]
            DraftVersion::Draft08 => {
                use crate::draft08::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft08(c))
            }
            #[cfg(feature = "draft09")]
            DraftVersion::Draft09 => {
                use crate::draft09::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft09(c))
            }
            #[cfg(feature = "draft10")]
            DraftVersion::Draft10 => {
                use crate::draft10::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft10(c))
            }
            #[cfg(feature = "draft11")]
            DraftVersion::Draft11 => {
                use crate::draft11::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft11(c))
            }
            #[cfg(feature = "draft12")]
            DraftVersion::Draft12 => {
                use crate::draft12::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft12(c))
            }
            #[cfg(feature = "draft13")]
            DraftVersion::Draft13 => {
                use crate::draft13::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft13(c))
            }
            #[cfg(feature = "draft14")]
            DraftVersion::Draft14 => {
                use crate::draft14::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    additional_versions: config.additional_versions,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft14(c))
            }
            #[cfg(feature = "draft15")]
            DraftVersion::Draft15 => {
                use crate::draft15::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft15(c))
            }
            #[cfg(feature = "draft16")]
            DraftVersion::Draft16 => {
                use crate::draft16::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft16(c))
            }
            #[cfg(feature = "draft17")]
            DraftVersion::Draft17 => {
                use crate::draft17::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft17(c))
            }
            #[cfg(feature = "draft18")]
            DraftVersion::Draft18 => {
                use crate::draft18::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft18(c))
            }
            #[cfg(feature = "draft19")]
            DraftVersion::Draft19 => {
                use crate::draft19::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft19(c))
            }
            #[cfg(feature = "draft20")]
            DraftVersion::Draft20 => {
                use crate::draft20::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft20(c))
            }
            #[cfg(feature = "draft21")]
            DraftVersion::Draft21 => {
                use crate::draft21::connection::{ClientConfig, Connection, TransportType};
                let transport = match config.transport {
                    AnyTransportType::Quic => TransportType::Quic,
                    AnyTransportType::WebTransport { url } => TransportType::WebTransport { url },
                };
                let inner = ClientConfig {
                    draft: config.draft,
                    transport,
                    skip_cert_verification: config.skip_cert_verification,
                    ca_certs: config.ca_certs,
                    setup_parameters: config.setup_parameters,
                };
                let c = Connection::connect(addr, inner).await.map_err(AnyConnectionError::from)?;
                Ok(AnyConnection::Draft21(c))
            }
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "draft {other:?} not enabled in this build",
            ))),
        }
    }

    /// Run the MoQT setup handshake over a transport somebody else established.
    ///
    /// [`connect`](Self::connect) dials its own socket, which is right for a
    /// caller that wants a connection and wrong for one that wants to *measure*
    /// how a peer behaves: choosing the address, the SNI, the ALPN offer or the
    /// certificate policy all mean dialling first and adopting after. Every
    /// draft module has `Connection::adopt` for exactly this, and this wrapper
    /// is how a caller reaches it without re-implementing the per-draft
    /// match over `AnyConnection` for itself.
    ///
    /// `config.draft` selects the module. Nothing here re-checks it against the
    /// ALPN the transport was negotiated with: adopting a transport under a
    /// draft the peer did not agree to is a legitimate probe, and refusing it
    /// would remove the ability to ask.
    pub async fn adopt(
        transport: crate::transport::Transport,
        config: AnyClientConfig,
    ) -> Result<Self, AnyConnectionError> {
        Self::adopt_offering(transport, config, None).await
    }

    /// [`Self::adopt`], offering exactly `versions` in CLIENT_SETUP.
    ///
    /// `None` offers what `config` implies. `Some` replaces the list outright,
    /// and takes raw varints rather than [`DraftVersion`]s because the reason
    /// to reach for this is to offer a version no draft assigns — which an enum
    /// of drafts cannot name.
    ///
    /// Drafts 07-14 only. Drafts 15-21 settle the version by ALPN and put no
    /// version list on the wire, so there is nothing there to offer and a
    /// `Some` on one of them is refused rather than quietly ignored: silently
    /// sending the ordinary handshake would answer a question that was never
    /// asked.
    // Both `transport` and `versions` are read only by the per-draft arms, so
    // the `<zero drafts>` build reaches none of them. Allowed rather than
    // underscore-prefixed because the names are part of the public signature
    // and appear in the docs above; renaming them to satisfy a build that
    // enables no draft would make the documentation wrong for every build that
    // enables one.
    #[allow(unused_variables)]
    pub async fn adopt_offering(
        transport: crate::transport::Transport,
        config: AnyClientConfig,
        versions: Option<Vec<moqtap_codec::varint::VarInt>>,
    ) -> Result<Self, AnyConnectionError> {
        // Three shapes, not one, because `ClientConfig` is not the same struct
        // in every era and a single arm cannot spell all three:
        //
        //   07-13  no `draft` field (the module is the draft), offers a
        //          version list through `additional_versions`
        //   14     both — the last draft that can offer several versions at once
        //   15-21  `draft` only. One connection offers exactly one version,
        //          which is why enumerating these costs a connection each.
        macro_rules! adopt_dispatch {
            (
                legacy: [ $( ($lf:literal, $lv:ident, $lm:ident) ),* $(,)? ],
                versioned: [ $( ($vf:literal, $vv:ident, $vm:ident) ),* $(,)? ],
                single: [ $( ($sf:literal, $sv:ident, $sm:ident) ),* $(,)? ],
            ) => {
                match config.draft {
                    $(
                        #[cfg(feature = $lf)]
                        DraftVersion::$lv => {
                            use crate::$lm::connection::{ClientConfig, Connection, TransportType};
                            let inner = ClientConfig {
                                additional_versions: config.additional_versions,
                                transport: match config.transport {
                                    AnyTransportType::Quic => TransportType::Quic,
                                    AnyTransportType::WebTransport { url } => {
                                        TransportType::WebTransport { url }
                                    }
                                },
                                skip_cert_verification: config.skip_cert_verification,
                                ca_certs: config.ca_certs,
                                setup_parameters: config.setup_parameters,
                            };
                            let c = Connection::adopt_offering(transport, inner, versions)
                                .await
                                .map_err(AnyConnectionError::from)?;
                            Ok(AnyConnection::$lv(c))
                        }
                    )*
                    $(
                        #[cfg(feature = $vf)]
                        DraftVersion::$vv => {
                            use crate::$vm::connection::{ClientConfig, Connection, TransportType};
                            let inner = ClientConfig {
                                draft: config.draft,
                                additional_versions: config.additional_versions,
                                transport: match config.transport {
                                    AnyTransportType::Quic => TransportType::Quic,
                                    AnyTransportType::WebTransport { url } => {
                                        TransportType::WebTransport { url }
                                    }
                                },
                                skip_cert_verification: config.skip_cert_verification,
                                ca_certs: config.ca_certs,
                                setup_parameters: config.setup_parameters,
                            };
                            let c = Connection::adopt_offering(transport, inner, versions)
                                .await
                                .map_err(AnyConnectionError::from)?;
                            Ok(AnyConnection::$vv(c))
                        }
                    )*
                    $(
                        #[cfg(feature = $sf)]
                        DraftVersion::$sv => {
                            use crate::$sm::connection::{ClientConfig, Connection, TransportType};
                            if versions.is_some() {
                                return Err(AnyConnectionError::facade(format!(
                                    "draft {:?} settles its version by ALPN and puts no version \
                                     list on the wire, so there is nothing to offer",
                                    config.draft
                                )));
                            }
                            let inner = ClientConfig {
                                draft: config.draft,
                                transport: match config.transport {
                                    AnyTransportType::Quic => TransportType::Quic,
                                    AnyTransportType::WebTransport { url } => {
                                        TransportType::WebTransport { url }
                                    }
                                },
                                skip_cert_verification: config.skip_cert_verification,
                                ca_certs: config.ca_certs,
                                setup_parameters: config.setup_parameters,
                            };
                            let c = Connection::adopt(transport, inner)
                                .await
                                .map_err(AnyConnectionError::from)?;
                            Ok(AnyConnection::$sv(c))
                        }
                    )*
                    #[allow(unreachable_patterns)]
                    other => Err(AnyConnectionError::facade(format!(
                        "draft {other:?} not enabled in this build"
                    ))),
                }
            };
        }

        adopt_dispatch! {
            legacy: [
                ("draft07", Draft07, draft07),
                ("draft08", Draft08, draft08),
                ("draft09", Draft09, draft09),
                ("draft10", Draft10, draft10),
                ("draft11", Draft11, draft11),
                ("draft12", Draft12, draft12),
                ("draft13", Draft13, draft13),
            ],
            versioned: [
                ("draft14", Draft14, draft14),
            ],
            single: [
                ("draft15", Draft15, draft15),
                ("draft16", Draft16, draft16),
                ("draft17", Draft17, draft17),
                ("draft18", Draft18, draft18),
                ("draft19", Draft19, draft19),
                ("draft20", Draft20, draft20),
            ],
        }
    }

    /// The version SERVER_SETUP selected, when the draft has a version list to
    /// select from.
    ///
    /// Not the same question as [`draft`](Self::draft), and the difference is
    /// the whole point for a caller enumerating what a relay supports:
    /// `draft()` reports the module the connection is running, which is the one
    /// the *client* chose, while this reports what the *server* picked out of
    /// the versions offered. Offer 11 through 14 and a server that settles on
    /// 12 leaves `draft()` saying 14 and this saying 12.
    ///
    /// `None` for drafts 15-21, which is a fact about those drafts rather than
    /// a gap here: they carry no `additional_versions`, so a connection offers
    /// exactly one version and there is nothing for a server to choose between.
    /// What a peer supports there is discovered by ALPN instead.
    pub fn negotiated_version(&self) -> Option<moqtap_codec::varint::VarInt> {
        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => c.negotiated_version(),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => c.negotiated_version(),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => c.negotiated_version(),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => c.negotiated_version(),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c.negotiated_version(),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c.negotiated_version(),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c.negotiated_version(),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c.negotiated_version(),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Read and dispatch one control message on the active draft. Draft-specific
    /// control-message return values are discarded because event delivery goes
    /// through the attached observer; callers only care about success/failure.
    pub async fn recv_and_dispatch(&mut self) -> Result<(), AnyConnectionError> {
        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => {
                c.recv_and_dispatch().await.map(|_| ()).map_err(AnyConnectionError::from)
            }
            #[allow(unreachable_patterns)]
            _ => Err(AnyConnectionError::facade("AnyConnection has no enabled variants")),
        }
    }

    /// Read the next control message that could answer `request`, wherever the
    /// negotiated draft carries it.
    ///
    /// This is the read half of the split [`AnyRequest`] describes, and without
    /// it the facade can send a request on drafts 17-21 and then has no way to
    /// hear the answer: those drafts put every response on the request's own
    /// bidirectional stream, which [`recv_and_dispatch`](Self::recv_and_dispatch)
    /// — a control-stream read — never touches.
    ///
    /// # What "could answer" means, and why it is not "does answer"
    ///
    /// Which of the two happens depends on the draft, and the difference is the
    /// protocol's, not this method's:
    ///
    /// - **Drafts 07-16, [`AnyRequest::ControlPlane`].** Every request shares
    ///   the one control stream, so this returns *the next control message on
    ///   it*, which is the answer only if nothing else was in flight. A peer is
    ///   free to send MAX_REQUEST_ID or a PUBLISH_NAMESPACE of its own first.
    ///   Correlate on the `request_id` the response carries against
    ///   [`AnyRequest::request_id`], and read again if it is not this one.
    /// - **Draft-16 namespace subscriptions and drafts 17-21.** The read is on
    ///   the request's own stream, so nothing else can arrive on it. Those
    ///   drafts' responses carry no request id at all — the stream *is* the
    ///   correlation — which is exactly why the read has to be addressed by the
    ///   handle rather than by the connection.
    ///
    /// # `Ok(None)`
    ///
    /// The peer ended the stream cleanly without a message on it. Reachable
    /// today only on a draft-16 namespace stream, whose reader distinguishes a
    /// FIN from a message; drafts 17-21 report the same event as an error. A
    /// distinct value rather than an error because a peer that answered nothing
    /// and closed is a different fact from a read that failed, and a caller
    /// that has to tell them apart should not be reading either one out of a
    /// message string. Neither phrase carries quotation marks and neither may:
    /// they are this crate naming two outcomes, and the marks would hand them
    /// to the drafts the line above names.
    ///
    /// # Errors
    ///
    /// Whatever the underlying read or dispatch produced, flattened to a
    /// string like every other error here — a transport failure, a peer reset,
    /// or an endpoint refusing a message that does not fit the request's
    /// state. A message the endpoint refuses has still been emitted to any
    /// attached observer by the time this returns, so an observer is the way to
    /// see *what arrived* when the return value only says that something did
    /// not fit.
    ///
    /// A `request` from a different draft than this connection is refused
    /// rather than silently read on the wrong stream.
    #[allow(unused_variables)]
    pub async fn recv_response(
        &mut self,
        request: &mut AnyRequest,
    ) -> Result<Option<moqtap_codec::dispatch::AnyControlMessage>, AnyConnectionError> {
        // Used only by the per-draft arms below, so a build with no draft
        // feature enabled — the `<zero drafts>` row of `just draft-matrix`,
        // which exists to prove the crate still compiles with nothing
        // selected — compiles this import and reaches no arm that reads it.
        #[allow(unused_imports)]
        use moqtap_codec::dispatch::AnyControlMessage;

        match (self, request) {
            #[cfg(feature = "draft07")]
            (Self::Draft07(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft07(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft08")]
            (Self::Draft08(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft08(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft09")]
            (Self::Draft09(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft09(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft10")]
            (Self::Draft10(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft10(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft11")]
            (Self::Draft11(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft11(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            (Self::Draft12(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft12(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            (Self::Draft13(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft13(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            (Self::Draft14(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft14(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            (Self::Draft15(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft15(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            (Self::Draft16(c), AnyRequest::ControlPlane { .. }) => c
                .recv_and_dispatch()
                .await
                .map(|m| Some(AnyControlMessage::Draft16(m)))
                .map_err(AnyConnectionError::from),
            // The one request draft-16 moved off the control stream, and so the
            // one place on that draft where this reads a stream instead.
            #[cfg(feature = "draft16")]
            (Self::Draft16(c), AnyRequest::Draft16(s)) => c
                .recv_on_namespace_stream(s)
                .await
                .map(|m| m.map(AnyControlMessage::Draft16))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            (Self::Draft17(c), AnyRequest::Draft17(s)) => c
                .recv_on_request_stream(s)
                .await
                .map(|m| Some(AnyControlMessage::Draft17(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            (Self::Draft18(c), AnyRequest::Draft18(s)) => c
                .recv_on_request_stream(s)
                .await
                .map(|m| Some(AnyControlMessage::Draft18(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            (Self::Draft19(c), AnyRequest::Draft19(s)) => c
                .recv_on_request_stream(s)
                .await
                .map(|m| Some(AnyControlMessage::Draft19(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            (Self::Draft20(c), AnyRequest::Draft20(s)) => c
                .recv_on_request_stream(s)
                .await
                .map(|m| Some(AnyControlMessage::Draft20(m)))
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft21")]
            (Self::Draft21(c), AnyRequest::Draft21(s)) => c
                .recv_on_request_stream(s)
                .await
                .map(|m| Some(AnyControlMessage::Draft21(m)))
                .map_err(AnyConnectionError::from),
            // A handle from another draft, or a build with no drafts enabled.
            // Refused rather than read on whatever stream happens to be at
            // hand: the two kinds of handle address different streams, so
            // guessing here would read the control stream for a request that is
            // waiting on its own.
            #[allow(unreachable_patterns)]
            (connection, request) => Err(AnyConnectionError::facade(format!(
                "recv_response: a draft {:?} request cannot be read on a draft {:?} connection",
                request.draft(),
                connection.draft(),
            ))),
        }
    }

    // ── Unified control-message helpers ──────────────────────────────────
    //
    // Draft-agnostic shorthands. Each dispatches to the active variant and
    // defaults fields not expressible in the unified shape; drafts that
    // lack the operation return an `AnyConnectionError`. Match on the
    // variant directly when full per-draft control is needed.

    /// Send an UNSUBSCRIBE for the given request ID. Drafts 07 through 16.
    ///
    /// # Drafts 17 through 20 have no such message
    ///
    /// Draft-17 deleted UNSUBSCRIBE, and drafts 18, 19 and 20 keep it deleted:
    /// a subscriber ends a subscription by **resetting its request stream**,
    /// which is [`AnyRequest::cancel`], or waits for PUBLISH_DONE. So the error
    /// those four return is not a gap to be filled later — there is nothing to
    /// wire — and a caller reaching for it on one of them wants `cancel` on the
    /// handle `subscribe` returned.
    #[allow(unused_variables)]
    pub async fn unsubscribe(
        &mut self,
        request_id: moqtap_codec::varint::VarInt,
    ) -> Result<(), AnyConnectionError> {
        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c.unsubscribe(request_id).await.map_err(AnyConnectionError::from),
            // The text names the protocol reason and an alternative rather than
            // reporting the draft as unimplemented: there is nothing here left
            // to wire, and an error that contradicts this method's own docs is
            // worse than no error text at all, because the next reader believes
            // the error.
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "unsubscribe: draft-{:02} has no UNSUBSCRIBE — draft-17 deleted it and the drafts \
                 after it keep it deleted. End the subscription with AnyRequest::cancel on the \
                 handle subscribe returned, or wait for PUBLISH_DONE",
                other.draft().number()
            ))),
        }
    }

    /// Send a SUBSCRIBE with the given filter, priority, and group order.
    /// Supported on **every draft this build carries**. Drafts 15 onward
    /// carry priority/order/filter as parameters rather than fields;
    /// this helper passes an empty parameter list, so on those drafts all three
    /// take the protocol default and the three arguments here are ignored.
    ///
    /// # The Track Alias, and why it is not an argument
    ///
    /// Drafts 07 through 11 carry a Track Alias on SUBSCRIBE and make it the
    /// **subscriber's** to choose; draft-12 moved the field to SUBSCRIBE_OK and
    /// made it the publisher's. An argument here would therefore do nothing on
    /// nine of the drafts, and a fixed value would collide the moment
    /// a caller subscribed to a second track.
    ///
    /// So the value is read off the endpoint —
    /// `Connection::next_free_track_alias`, the lowest alias no live binding
    /// holds — rather than asked of the caller. That table is the same one the
    /// endpoint checks before writing, so a caller mixing these calls with a
    /// draft's own `Connection::subscribe` and aliases of its own is correct by
    /// construction rather than by convention, and a genuine duplicate is still
    /// refused with `EndpointError::TrackAliasInUse` before anything reaches
    /// the wire.
    ///
    /// There is no range to get wrong *here*: a subscription with no filter is
    /// one that starts where the draft says it starts, and nothing is
    /// converted. The two filters that name a Start Location —
    /// `AbsoluteStart` and `AbsoluteRange` — are refused by this call on every
    /// draft that takes a Filter Type as an argument, because it has no start
    /// location to put beside them; [`AnyConnection::subscribe_range`] is the
    /// entry point that takes one.
    /// A draft-20 caller that wants a Location filter, a fill, or anything else
    /// from Section 10.2 reaches
    /// [`draft20::connection::Connection::subscribe`](crate::draft20::connection::Connection::subscribe)
    /// through the variant with the parameters it wants.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-21 it owns the bidirectional stream the request went out on
    /// and dropping it cancels the subscription. See [`AnyRequest`] for how
    /// the two kinds of handle differ.
    #[allow(unused_variables)]
    pub async fn subscribe(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: moqtap_codec::types::GroupOrder,
        filter_type: moqtap_codec::types::FilterType,
    ) -> Result<AnyRequest, AnyConnectionError> {
        // Only the draft-11 and draft-12 arms below convert `filter_type` by
        // hand: those two draw that field as a variable-length integer, where
        // the drafts on either side of them take the typed value straight
        // through. So the import is dead outside those builds.
        #[cfg(any(feature = "draft11", feature = "draft12"))]
        use moqtap_codec::varint::VarInt;
        let draft = self.draft();
        match self {
            // Drafts 07 through 11 put the Track Alias on SUBSCRIBE and leave
            // its choice to the subscriber, and have no parameter block. The
            // alias comes from the endpoint's own table of live bindings; see
            // this method's docs for why it is not an argument.
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => {
                let alias = c.next_free_track_alias();
                c.subscribe(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => {
                let alias = c.next_free_track_alias();
                c.subscribe(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => {
                let alias = c.next_free_track_alias();
                c.subscribe(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => {
                let alias = c.next_free_track_alias();
                c.subscribe(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => {
                let ft = VarInt::from_u64(filter_type as u64)
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                let alias = c.next_free_track_alias();
                c.subscribe(alias, namespace, track_name, subscriber_priority, group_order, ft)
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => {
                let ft = VarInt::from_u64(filter_type as u64)
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, subscriber_priority, group_order, ft, Vec::new())
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .subscribe(
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .subscribe(
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft17)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft21)
                .map_err(AnyConnectionError::from),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "subscribe: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a SUBSCRIBE that names where the subscription starts, and
    /// optionally where it stops. Wired on **every draft this build carries**.
    ///
    /// This is the half of SUBSCRIBE [`AnyConnection::subscribe`] cannot reach.
    /// The two filters that ask a relay for anything it has **already carried**
    /// — AbsoluteStart and AbsoluteRange — both put a Start Location on the
    /// wire, and a call taking the Filter Type beside the other arguments has
    /// none to give. So `subscribe` refuses them and this takes a
    /// [`SubscribeRange`] instead, from which the Filter Type is **derived**:
    /// the message cannot name a filter whose fields it does not carry, because
    /// nothing here gets to name one.
    ///
    /// Without it there is no way to ask whether a relay holds a cache at all,
    /// which is a question about relays and not about ranges.
    ///
    /// # What each draft is handed
    ///
    /// Four wire shapes for one range, and the conversions are
    /// [`SubscribeRange`]'s rather than each arm's:
    ///
    /// * **draft-07** — a Start Location and an End *Location*, whose Object is
    ///   the last one plus 1 with `0` for the whole Group, exactly as FETCH
    ///   words it. [`SubscribeRange::inline_end_location`].
    /// * **drafts 08 through 14** — a Start Location and an absolute End
    ///   *Group*, the End Object having been deleted in draft-08.
    /// * **drafts 15 and 16** — the same two, moved into the
    ///   `SUBSCRIPTION_FILTER` parameter draft-15 introduced.
    /// * **drafts 17 through 19** — the same parameter, with the End Group
    ///   written as a delta from the start.
    /// * **draft-20** — `LOCATION_FILTER`, whose shape comes from its field
    ///   count rather than from a Filter Type, and whose ranges are inclusive.
    ///   [`SubscribeRange::location_filter_draft20`], which is also where the one value
    ///   this facade refuses on one draft is documented.
    ///
    /// # What this does not carry
    ///
    /// An empty parameter list on every draft that has one beside the filter,
    /// and the same priority and group order defaults
    /// [`AnyConnection::subscribe`] passes: those are fields of SUBSCRIBE on
    /// drafts 07 through 14 and parameters on drafts 15 and later, so they are
    /// taken here for the drafts that have the fields and ignored by the six
    /// that do not — which is the arrangement `subscribe` already documents.
    ///
    /// # Errors
    ///
    /// A range the negotiated draft cannot express, before anything is written.
    /// There are three, and each is a genuine difference between the drafts
    /// rather than a limitation of this call:
    /// [`SubscribeEnd::ThroughObject`] on drafts 08 through 19; an `end_group`
    /// below `start_group` on drafts 17 through 20; and a `{0, 0}`
    /// [`SubscribeEnd::Open`] on draft-20, which reads as the live edge there
    /// and as the beginning of the track everywhere else.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-21 it owns the bidirectional stream the request went out on
    /// and dropping it cancels the subscription.
    #[allow(unused_variables)]
    pub async fn subscribe_range(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: moqtap_codec::types::GroupOrder,
        range: SubscribeRange,
    ) -> Result<AnyRequest, AnyConnectionError> {
        // The Start Location every arm below 15 puts on the wire directly, and
        // every arm from 15 puts inside a parameter. Built once because it is
        // the one field none of the drafts disagree about.
        let start = range.start_location();
        let draft = self.draft();
        match self {
            // Draft-07 alone carries an End Location rather than an End Group,
            // and carries it with FETCH's plus-one convention. The arithmetic
            // is `inline_end_location`'s, in one place, so it cannot reach the
            // drafts that must not have it.
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => {
                let end = range.inline_end_location()?;
                let alias = c.next_free_track_alias();
                c.subscribe_range(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            // Drafts 08 through 11 put the Track Alias on SUBSCRIBE and make it
            // the subscriber's to choose, and have no parameter block; see
            // `subscribe` for why the alias is read off the endpoint rather
            // than taken as an argument.
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                let alias = c.next_free_track_alias();
                c.subscribe_range(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                let alias = c.next_free_track_alias();
                c.subscribe_range(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                let alias = c.next_free_track_alias();
                c.subscribe_range(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                let alias = c.next_free_track_alias();
                c.subscribe_range(
                    alias,
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            // Drafts 12 through 14: the alias moved to SUBSCRIBE_OK and a
            // parameter block arrived, and the range is still two fields on
            // SUBSCRIBE itself.
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                c.subscribe_range(
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                c.subscribe_range(
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => {
                let end =
                    range.group_only_end(draft)?.map(moqtap_codec::varint::VarInt::from_u64_moqt);
                c.subscribe_range(
                    namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start,
                    end,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from)
            }
            // From draft-15 the whole filter is a parameter value, so the
            // range does not reach the endpoint as arguments at all and there
            // is no `subscribe_range` under here to call. `group_only_end`
            // still runs, inside `subscription_filter`, because these drafts
            // deleted the End Object along with drafts 08 through 14.
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => {
                let filter = range
                    .subscription_filter(draft, false)?
                    .parameter()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => {
                let filter = range
                    .subscription_filter(draft, false)?
                    .parameter()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from)
            }
            // Draft-17 introduced the End Group Delta and its own integer
            // encoding, in which the 7-byte length is an invalid code point.
            // Draft-18 restored that length, which is why the profile differs
            // between this arm and the two below it.
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => {
                let filter = range
                    .subscription_filter(draft, true)?
                    .parameter_moqt::<moqtap_codec::varint::Moqt17>()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(AnyRequest::Draft17)
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => {
                let filter = range
                    .subscription_filter(draft, true)?
                    .parameter_moqt::<moqtap_codec::varint::Moqt18>()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(AnyRequest::Draft18)
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => {
                let filter = range
                    .subscription_filter(draft, true)?
                    .parameter_moqt::<moqtap_codec::varint::Moqt18>()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(AnyRequest::Draft19)
                    .map_err(AnyConnectionError::from)
            }
            // Draft-20 deleted the Filter Type enum and reads the shape off the
            // field count, so this arm builds a different value from the same
            // range rather than the same value with a different integer
            // encoding.
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => {
                let filter = range
                    .location_filter_draft20()?
                    .parameter()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(AnyRequest::Draft20)
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => {
                let filter = range
                    .location_filter_draft21()?
                    .parameter()
                    .map_err(|e| AnyConnectionError::facade(e.to_string()))?;
                c.subscribe(namespace, track_name, vec![filter])
                    .await
                    .map(AnyRequest::Draft21)
                    .map_err(AnyConnectionError::from)
            }
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "subscribe_range: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a standalone FETCH for `range`. Wired on **every draft this build
    /// carries**.
    ///
    /// # What the range means here
    ///
    /// **[`FetchEnd::Object`] is the last Object the fetch covers, and the
    /// range holds it. [`FetchEnd::EntireGroup`] covers the whole end Group.
    /// `end_group` is absolute.** That is the whole contract, and it is stated
    /// in [`FetchEnd`] as well because it is the one thing about this call a
    /// caller can get wrong without being told.
    ///
    /// The drafts do not agree, which is why the argument is a
    /// [`FetchRange`] rather than four numbers. Drafts 07 through 19 carry the
    /// start and the end inline in FETCH and all thirteen word the end alike —
    /// draft-19 Section 10.12.1: "The end Location, plus 1. A Location.Object
    /// value of 0 means the entire group is requested." The section number
    /// moves between drafts and the fields are regrouped into a `Location`
    /// along the way; the sentence does not change, which is why
    /// `moqtap_codec::types::check_location_range` is one shared function
    /// rather than thirteen.
    /// Draft-20 Section 10.13 deleted both fields and
    /// moved the range into the `LOCATION_FILTER` parameter, whose ranges
    /// Section 5.1.2 calls **inclusive** — the `+ 1` and the `0`-means-whole-
    /// group convention are both gone, and neither deletion is in the draft's
    /// own change log. A single `end_object: u64` at this boundary would have
    /// meant one of those two things and looked like the other.
    ///
    /// The conversion is [`FetchRange::inline_end_object`] for the first group
    /// and [`FetchRange::location_filter_draft20`] for draft-20. **The `+ 1` exists in
    /// exactly one place**, the first of those, so it cannot reach draft-20 by
    /// being ported.
    ///
    /// # What this does not carry
    ///
    /// An empty parameter list, on every draft that has one — drafts 07 through
    /// 11 have no parameter field on FETCH at all. Drafts 07 through 14 carry
    /// subscriber priority and group order as fields of FETCH and no later
    /// draft does, so those arms send the defaults rather than widening an
    /// entry point shared with six drafts that have no such fields. Reach a
    /// draft's own `Connection::fetch` through the variant for anything past a
    /// plain range.
    ///
    /// # Errors
    ///
    /// A range the negotiated draft cannot express, before anything is written:
    /// `FetchEnd::Object(u64::MAX)` on drafts 14 through 19, and an `end_group`
    /// below `start_group` on draft-20. See the two conversions for why each is
    /// inexpressible rather than merely unusual.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-21 it owns the bidirectional stream the request went out on
    /// and dropping it cancels the fetch.
    #[allow(unused_variables)]
    pub async fn fetch(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
        range: FetchRange,
    ) -> Result<AnyRequest, AnyConnectionError> {
        // The three fields drafts 14 through 19 carry unchanged, built once for
        // whichever arm runs. `from_u64_moqt` rather than `from_u64` because
        // MoQT's varint reaches the full 64-bit range (Section 1.4.1) and the
        // newtype *is* the value: a `VarInt` a caller could have handed the old
        // four-argument form is the same `VarInt` this makes, so every draft
        // that was wired before writes the bytes it wrote before. The fourth
        // field is the one that differs, and it is built inside each arm from
        // `inline_end_object`.
        let start_group = moqtap_codec::varint::VarInt::from_u64_moqt(range.start_group);
        let start_object = moqtap_codec::varint::VarInt::from_u64_moqt(range.start_object);
        let end_group = moqtap_codec::varint::VarInt::from_u64_moqt(range.end_group);
        // The fourth field, which is the one that differs: draft-19 Section
        // 10.13 makes `End Location.Object` the last Object plus 1, or 0 for
        // the whole Group. Built here so the six arms that need it stay
        // identical, and lazily so that draft-20 — which can express a range
        // those six cannot — is not refused on their behalf.
        let inline_end_object = || -> Result<moqtap_codec::varint::VarInt, AnyConnectionError> {
            Ok(moqtap_codec::varint::VarInt::from_u64_moqt(range.inline_end_object()?))
        };
        let draft = self.draft();
        match self {
            // Drafts 07 through 11 take the four location fields and nothing
            // else: FETCH gained its parameter block in draft-12. The
            // priority and the order are fields of FETCH on every draft up to
            // and including 14 and of no later draft's, so these arms send the
            // defaults rather than widening an entry point shared with six
            // drafts that have no such fields.
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .fetch(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .fetch(
                    namespace,
                    track_name,
                    // The last draft that carries these two on FETCH; see the
                    // comment above the draft-07 arm.
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft17)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft18)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft19)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => {
                // Draft-20 Section 10.13 has no location fields to fill in:
                // `fetch_range` puts the whole range in the `LOCATION_FILTER`
                // parameter, at the position ascending Parameter Type order
                // requires. Nothing here adds one to the end — Section 5.1.2
                // makes the filter's range inclusive, and the `+ 1` the six
                // arms above apply lives in `inline_end_object` alone.
                let filter = range.location_filter_draft20()?;
                c.fetch_range(namespace, track_name, &filter, Vec::new())
                    .await
                    .map(AnyRequest::Draft20)
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => {
                // Draft-21 Section 9.11 has no location fields to fill in:
                // `fetch_range` puts the whole range in the `LOCATION_FILTER`
                // parameter, at the position ascending Parameter Type order
                // requires. Nothing here adds one to the end — Section 3.3.1
                // makes the filter's range inclusive, and the `+ 1` the six
                // arms above apply lives in `inline_end_object` alone.
                let filter = range.location_filter_draft21()?;
                c.fetch_range(namespace, track_name, &filter, Vec::new())
                    .await
                    .map(AnyRequest::Draft21)
                    .map_err(AnyConnectionError::from)
            }
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "fetch: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a **Joining** FETCH against a subscription this session already
    /// holds. Drafts 08 through 19.
    ///
    /// [`AnyConnection::fetch`]'s other half, and a different question rather
    /// than a shorthand for the same one. A standalone FETCH names a track and
    /// a range and asks a relay's store for it. A Joining FETCH names **a
    /// subscription** and asks for the part of that subscription's track that
    /// precedes it, and the publisher fills in the namespace, the name and the
    /// end from the subscription itself. So a subscriber that wants "what I am
    /// watching, plus the run-up to it" has one request for the pair instead of
    /// a subscription and a fetch whose range it had to compute — and, on a
    /// live track, could not compute, because the run-up ends wherever the
    /// subscription happened to start.
    ///
    /// `joining_request_id` is the Request ID of that subscription, which is
    /// [`AnyRequest::request_id`] on the handle [`AnyConnection::subscribe`]
    /// returned. Nothing here checks that it names one: draft-19 Section
    /// 10.12.2 puts that check at the publisher — "it MUST respond with a Fetch
    /// Error with code Invalid Joining Request ID" — and this side is the
    /// subscriber. The subscription must still be live when the FETCH
    /// *arrives*, which is a thing about ordering rather than about this call.
    ///
    /// `start` is [`JoiningStart`], and it carries the Fetch Type as well as
    /// the number for the reason that type documents.
    ///
    /// # The two drafts at the ends, and what each of them deleted
    ///
    /// **Draft-07 has no Joining Fetch at all.** Its FETCH has no Fetch Type
    /// field, so there is no bit in the message that could ask for one; the
    /// field and the second Fetch Type both arrive in draft-08.
    ///
    /// **Draft-20 deleted the whole mechanism** — Section 10.13 removed the
    /// Fetch Type field, both payload structures and the Fetch Type registry
    /// together, and promoted the namespace and the name to fields of FETCH
    /// itself. There is no joining form to fall back to and no parameter that
    /// restores one, so this refuses on draft-20 rather than sending something
    /// adjacent. **This is the entry point that makes "one suite run per draft"
    /// concrete**: a relay speaking both 14 and 20 answers this question on one
    /// of them and cannot be asked it on the other, and a probe that tested only
    /// the newest draft would never learn that the relay implements it.
    ///
    /// Drafts 08 through 10 carry only the relative form, so
    /// [`JoiningStart::Group`] is refused there — see that variant.
    ///
    /// # What this does not carry
    ///
    /// The same three things [`AnyConnection::fetch`] leaves out, for the same
    /// reasons: an empty parameter list on every draft that has one (drafts 08
    /// through 11 have no parameter field on FETCH), and the subscriber
    /// priority and group order as defaults on drafts 08 through 14, which are
    /// the only drafts carrying them as fields of FETCH.
    ///
    /// The returned [`AnyRequest`] must be held while the fetch is live: on
    /// drafts 17 through 19 it owns the bidirectional stream the request went
    /// out on and dropping it cancels the fetch.
    #[allow(unused_variables)]
    pub async fn fetch_joining(
        &mut self,
        joining_request_id: moqtap_codec::varint::VarInt,
        start: JoiningStart,
    ) -> Result<AnyRequest, AnyConnectionError> {
        let draft = self.draft();
        let joining_start = moqtap_codec::varint::VarInt::from_u64_moqt(match start {
            JoiningStart::GroupsBefore(n) => n,
            JoiningStart::Group(g) => g,
        });
        // Refused once, here, rather than in three arms: drafts 08 through 10
        // define Fetch Types 0x1 and 0x2 and nothing else, and sending the
        // relative form with an absolute number in it would ask for the last
        // `g` Groups of the track when the caller asked for everything from
        // Group `g`.
        // The return type is spelled out because a single-draft build can
        // compile this closure without ever calling it: with only draft-20
        // enabled every arm that would have pinned `T` is gone, and inference
        // has nothing left to work from. Annotating it keeps `just draft-matrix`
        // green on all single-draft rows.
        let absolute_unavailable = || -> Result<AnyRequest, AnyConnectionError> {
            Err(AnyConnectionError::facade(format!(
                "fetch_joining: draft {draft:?} has no Absolute Joining Fetch — its FETCH offers \
                 Fetch Types 0x1 and 0x2, and 0x3 arrives in draft-11. Ask relatively, or reach \
                 the draft's own Connection::joining_fetch"
            )))
        };
        // The two fields drafts 08 through 14 carry on FETCH and no later draft
        // does. Sent as defaults for `fetch`'s reason: widening an entry point
        // shared with five drafts that have no such fields would give a caller
        // two arguments that are silently dropped on more than a third of them.
        //
        // Both are read only by the draft-08 through draft-14 arms, so a build
        // that enables none of those seven — `--features draft07,draft20` is
        // the pair `just draft-pairs` picks — compiles them and never reaches
        // them. Allowing the dead code is preferred to a seven-feature `cfg`
        // here: the `cfg` would have to be repeated and kept in step with the
        // arms below, and the day a draft joined or left that range the two
        // would drift apart silently, where an unused constant costs nothing
        // and cannot be wrong.
        #[allow(dead_code)]
        const PRIORITY: u8 = 128;
        #[allow(unused_variables)]
        let order = moqtap_codec::types::GroupOrder::Ascending;
        match self {
            // Draft-07's FETCH has no Fetch Type field, so this is not a gap to
            // be filled later — there is nothing in the message to set.
            #[cfg(feature = "draft07")]
            Self::Draft07(_) => Err(AnyConnectionError::facade(
                "fetch_joining: draft-07's FETCH has no Fetch Type field and no Joining Fetch; \
                 draft-08 is where both arrive",
            )),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => match start {
                JoiningStart::Group(_) => absolute_unavailable(),
                JoiningStart::GroupsBefore(_) => c
                    .joining_fetch(PRIORITY, order, joining_request_id, joining_start)
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from),
            },
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => match start {
                JoiningStart::Group(_) => absolute_unavailable(),
                JoiningStart::GroupsBefore(_) => c
                    .joining_fetch(PRIORITY, order, joining_request_id, joining_start)
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from),
            },
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => match start {
                JoiningStart::Group(_) => absolute_unavailable(),
                JoiningStart::GroupsBefore(_) => c
                    .joining_fetch(PRIORITY, order, joining_request_id, joining_start)
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(AnyConnectionError::from),
            },
            // Draft-11 splits Joining into the relative and absolute pair and
            // has no parameter block on FETCH; draft-12 adds the block.
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(PRIORITY, order, joining_request_id, joining_start).await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(PRIORITY, order, joining_request_id, joining_start)
                        .await
                }
            }
            .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
            .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(PRIORITY, order, joining_request_id, joining_start, Vec::new())
                        .await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(
                        PRIORITY,
                        order,
                        joining_request_id,
                        joining_start,
                        Vec::new(),
                    )
                    .await
                }
            }
            .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
            .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(PRIORITY, order, joining_request_id, joining_start, Vec::new())
                        .await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(
                        PRIORITY,
                        order,
                        joining_request_id,
                        joining_start,
                        Vec::new(),
                    )
                    .await
                }
            }
            .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
            .map_err(AnyConnectionError::from),
            // The last draft carrying the priority and the order on FETCH; see
            // the constants above.
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(PRIORITY, order, joining_request_id, joining_start, Vec::new())
                        .await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(
                        PRIORITY,
                        order,
                        joining_request_id,
                        joining_start,
                        Vec::new(),
                    )
                    .await
                }
            }
            .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
            .map_err(AnyConnectionError::from),
            // From draft-15 the two fields are gone from FETCH and the request
            // is three varints and a parameter block.
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
            }
            .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
            .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
            }
            .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
            .map_err(AnyConnectionError::from),
            // From draft-17 the request travels on a bidirectional stream of its
            // own, so the handle owns that stream rather than naming an id on a
            // shared one.
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
            }
            .map(AnyRequest::Draft17)
            .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
            }
            .map(AnyRequest::Draft18)
            .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => match start {
                JoiningStart::GroupsBefore(_) => {
                    c.joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
                JoiningStart::Group(_) => {
                    c.absolute_joining_fetch(joining_request_id, joining_start, Vec::new()).await
                }
            }
            .map(AnyRequest::Draft19)
            .map_err(AnyConnectionError::from),
            // Not a gap either. Draft-20 Section 10.13 deleted the Fetch Type
            // field, both Fetch payload structures and the Fetch Type registry
            // in one rewrite, and its change log does not mention the joining
            // mechanism at all.
            #[cfg(feature = "draft20")]
            Self::Draft20(_) => Err(AnyConnectionError::facade(
                "fetch_joining: draft-20 deleted the Fetch Type field and the whole Joining Fetch \
                 mechanism (Section 10.13); a fetch there names its own track and range, which is \
                 AnyConnection::fetch",
            )),
            #[cfg(feature = "draft21")]
            Self::Draft21(_) => Err(AnyConnectionError::facade(
                "fetch_joining: draft-20 deleted the Fetch Type field and the whole Joining Fetch \
                 mechanism and draft-21 keeps it gone (Section 9.11); a fetch there names its own \
                 track and range, which is AnyConnection::fetch",
            )),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "fetch_joining: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a TRACK_STATUS query for the given track. Supported on drafts 11
    /// through 20. From draft-15 on, passes an empty parameter list.
    ///
    /// # Which message this sends, and why the name moved
    ///
    /// Up to draft-12 the query is TRACK_STATUS_REQUEST and `track_status` is
    /// the *response* to it; draft-13 renamed the request to TRACK_STATUS and
    /// gave the answer its own TRACK_STATUS_OK. So this method reaches
    /// `Connection::track_status_request` on drafts 11 and 12 and
    /// `Connection::track_status` from draft-13 on — **the same question under
    /// two names, not the same name for two things.** Calling the
    /// same-named method on a draft-11 `Connection` would send a reply to a
    /// question nobody asked, which is why the naming test
    /// `an_unsent_request_is_not_named_from_the_drafts_table` exists.
    ///
    /// # Drafts 07 through 10
    ///
    /// Not supported here, and not for want of a match arm. Their
    /// TRACK_STATUS_REQUEST carries **no Request ID** — `Connection::
    /// track_status_request` returns `()` on those drafts, because the answer
    /// is matched by track namespace and name rather than by an identifier.
    /// [`AnyRequest`] is a handle to a request the endpoint numbered, so there
    /// is nothing for this method to return, and fabricating an ID would put a
    /// number in [`AnyRequest::request_id`] that was never on the wire. Send
    /// the query through the variant's own `Connection` and read the reply with
    /// [`AnyConnection::recv_response`] against any other outstanding request,
    /// or match it by name off `recv_and_dispatch`.
    ///
    /// The returned [`AnyRequest`] must be held until the answer arrives: on
    /// drafts 17-21 it owns the bidirectional stream the query went out on and
    /// dropping it cancels the query.
    #[allow(unused_variables)]
    pub async fn track_status(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<AnyRequest, AnyConnectionError> {
        let draft = self.draft();
        match self {
            // Drafts 11 and 12: TRACK_STATUS_REQUEST, which is this question's
            // name before draft-13 renames it. Both drafts carry a parameter
            // block — it arrives with draft-11 — and the two arms differ only
            // because this build's draft-11 entry point takes no parameter list
            // of its own and sends an empty one.
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c
                .track_status_request(namespace, track_name)
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .track_status_request(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            // Draft-13 is where the request takes the name and the four
            // SUBSCRIBE-shaped fields, exactly as draft-14 carries them.
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .track_status(
                    namespace,
                    track_name,
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    moqtap_codec::types::Forward::Forward,
                    moqtap_codec::types::FilterType::LargestObject,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .track_status(
                    namespace,
                    track_name,
                    // Drafts 13 and 14 word TRACK_STATUS like a SUBSCRIBE and
                    // no later draft does, so these four are sent as they
                    // always were rather than widening an entry point shared
                    // with six drafts that have no such fields.
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    moqtap_codec::types::Forward::Forward,
                    moqtap_codec::types::FilterType::LargestObject,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft17)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft21)
                .map_err(AnyConnectionError::from),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "track_status: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a SUBSCRIBE_NAMESPACE (or SUBSCRIBE_ANNOUNCES on drafts 11–12).
    /// Supported on drafts 11 through 20. Drafts 16 and 17 pass default
    /// subscribe options; every draft from 12 on passes an empty parameter
    /// list.
    ///
    /// From draft-18 this is the renumbered SUBSCRIBE_NAMESPACE (0x50), which
    /// asks for NAMESPACE and NAMESPACE_DONE only. SUBSCRIBE_TRACKS, the other
    /// half of the draft-18 split, has no entry point here — reach a draft's
    /// own `Connection::subscribe_tracks` through the variant.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-21 it owns the bidirectional stream the request went out on
    /// and dropping it cancels the namespace subscription.
    #[allow(unused_variables)]
    pub async fn subscribe_namespace(
        &mut self,
        namespace_prefix: moqtap_codec::types::TrackNamespace,
    ) -> Result<AnyRequest, AnyConnectionError> {
        // Only the draft-16 and draft-17 arms below build a subscribe-options
        // varint; the other drafts' wrappers take no such argument, so the
        // import is dead outside those two builds.
        #[cfg(any(feature = "draft16", feature = "draft17"))]
        use moqtap_codec::varint::VarInt;
        let draft = self.draft();
        match self {
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c
                .subscribe_announces(namespace_prefix)
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .subscribe_announces(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => {
                let opts = VarInt::from_u64(0).expect("0 fits in VarInt");
                c.subscribe_namespace(namespace_prefix, opts, Vec::new())
                    .await
                    .map(AnyRequest::Draft16)
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => {
                let opts = VarInt::from_u64(0).expect("0 fits in VarInt");
                c.subscribe_namespace(namespace_prefix, opts, Vec::new())
                    .await
                    .map(AnyRequest::Draft17)
                    .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft21)
                .map_err(AnyConnectionError::from),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "subscribe_namespace: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Offer a namespace to the peer: PUBLISH_NAMESPACE, or ANNOUNCE on the
    /// drafts that called it that. Supported on drafts 11 through 20. From
    /// draft-12 on, passes an empty parameter list.
    ///
    /// This is the first entry point here that asks the peer to **hold state**
    /// rather than to answer a question and forget it. A relay that accepts it
    /// records this session as the publisher for that namespace and will route
    /// matching subscriptions back down this connection, so a caller that
    /// announces owes the peer either a withdrawal — see
    /// [`AnyConnection::publish_namespace_done`] — or a closed session.
    ///
    /// # One request under two names
    ///
    /// Drafts 07 through 13 call it ANNOUNCE; draft-14 renamed it
    /// PUBLISH_NAMESPACE and every later draft keeps that name. The rename is
    /// the whole of the difference — the same namespace goes out and the same
    /// acceptance comes back — so this is one method rather than two, on the
    /// same reasoning as [`AnyConnection::track_status`], where the *request*
    /// changed names in the other direction.
    ///
    /// # Drafts 07 through 10
    ///
    /// Not supported here, and for the reason drafts 07 through 10 have no
    /// [`AnyConnection::track_status`] either: their ANNOUNCE carries **no
    /// Request ID**. `Connection::announce` returns `()` on those four drafts
    /// because ANNOUNCE_OK is matched by track namespace rather than by an
    /// identifier, so there is nothing for this method to hand back and a
    /// fabricated ID would put a number in [`AnyRequest::request_id`] that was
    /// never on the wire. Draft-11 is where the request ID arrives, and where
    /// this method starts. Send the announcement through the variant's own
    /// `Connection` if an older draft is the target.
    ///
    /// The returned [`AnyRequest`] must be held while the announcement is live:
    /// on drafts 17-21 it owns the bidirectional stream the request went out on
    /// and dropping it withdraws the namespace, which on those drafts is the
    /// only way to withdraw one.
    #[allow(unused_variables)]
    pub async fn publish_namespace(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
    ) -> Result<AnyRequest, AnyConnectionError> {
        let draft = self.draft();
        match self {
            // Draft-11 is the first draft to number the request, and the last
            // to take no parameter block.
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c
                .announce(namespace)
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .announce(namespace, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .announce(namespace, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            // Draft-14 is the rename. Nothing else about the request moved.
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            // Draft-16 gave a bidirectional stream to namespace *subscriptions*
            // and to nothing else, so this one stays on the control stream —
            // which is why the handle is a `ControlPlane` here and a stream one
            // line down.
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(AnyRequest::Draft17)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => c
                .publish_namespace(namespace, Vec::new())
                .await
                .map(AnyRequest::Draft21)
                .map_err(AnyConnectionError::from),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "publish_namespace: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Withdraw a namespace this session announced: PUBLISH_NAMESPACE_DONE, or
    /// UNANNOUNCE on the drafts that called it that. Drafts 11 through 16.
    ///
    /// # Why this takes both the handle and the namespace
    ///
    /// Because the drafts disagree about which of the two identifies the
    /// announcement being withdrawn, and they disagree twice:
    ///
    /// - **Drafts 11 through 15** name the namespace. UNANNOUNCE and, from
    ///   draft-14, PUBLISH_NAMESPACE_DONE carry the tuple itself.
    /// - **Draft-16** names the request ID, having moved the whole message onto
    ///   the identifier the announcement was allocated.
    /// - **Drafts 17 through 20** name neither, because there is no message: the
    ///   announcement lives exactly as long as its bidirectional stream, so
    ///   withdrawing one is [`AnyRequest::cancel`] or simply dropping the
    ///   handle. Those four return an error here rather than silently doing
    ///   nothing, on the same terms as [`AnyConnection::unsubscribe`] — it is
    ///   not a gap waiting to be wired, there is nothing to send.
    ///
    /// A signature taking only the namespace would be wrong on draft-16 and one
    /// taking only the handle would be wrong on the five drafts before it.
    /// Taking both keeps the caller from having to know which era it is in,
    /// which is the entire point of this facade.
    ///
    /// `request` is borrowed rather than consumed: on drafts 11 through 16 it
    /// carries no stream, so the caller keeps a handle that is still good for
    /// [`AnyRequest::request_id`] afterwards.
    #[allow(unused_variables)]
    pub async fn publish_namespace_done(
        &mut self,
        request: &AnyRequest,
        namespace: moqtap_codec::types::TrackNamespace,
    ) -> Result<(), AnyConnectionError> {
        match self {
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c.unannounce(namespace).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c.unannounce(namespace).await.map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c.unannounce(namespace).await.map_err(AnyConnectionError::from),
            // Draft-14 renamed UNANNOUNCE to PUBLISH_NAMESPACE_DONE and kept
            // the namespace on it; draft-16 swapped the namespace for the
            // request ID.
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => {
                c.publish_namespace_done(namespace).await.map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => {
                c.publish_namespace_done(namespace).await.map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .publish_namespace_done(request.request_id())
                .await
                .map_err(AnyConnectionError::from),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "publish_namespace_done: draft {:?} withdraws a namespace by ending the \
                 announcement's own stream, so there is no message to send; cancel or drop \
                 the request handle instead",
                other.draft()
            ))),
        }
    }

    /// Wait for the peer to send something, and say whether it is a request
    /// this facade can answer. Supported on **every draft this build carries**.
    ///
    /// This is the direction [`AnyConnection::recv_response`] does not cover: a
    /// relay that accepted a namespace from [`AnyConnection::publish_namespace`]
    /// will send a SUBSCRIBE *down* this connection when somebody asks for a
    /// track under it, and that message answers nothing this side asked for.
    ///
    /// # What "wait" means on either side of draft-17
    ///
    /// Two different waits for one question. Drafts 07 through 16 read the
    /// shared control stream, so every message the peer sends — its requests
    /// and its answers to this side's — arrives through here and is returned,
    /// tagged. From draft-17 this waits on a **new bidirectional stream**, so
    /// only the peer's own requests arrive and an answer to something this side
    /// asked is read with [`AnyConnection::recv_response`] instead.
    ///
    /// That is why [`AnyArrival::Other`] exists rather than a filter. On the
    /// older drafts a reader that dropped what it was not looking for would
    /// swallow a SUBSCRIBE_OK somebody was waiting on; see that variant for
    /// what it costs on the newer ones.
    ///
    /// Every message is dispatched into the endpoint before it is returned, so
    /// the session's state is correct whether the caller inspects it or not.
    #[allow(unused_variables)]
    pub async fn recv_inbound(&mut self) -> Result<AnyArrival, AnyConnectionError> {
        // Used only by the per-draft arms below, so a build with no draft
        // feature enabled — the `<zero drafts>` row of `just draft-matrix`,
        // which exists to prove the crate still compiles with nothing
        // selected — compiles this import and reaches no arm that reads it.
        #[allow(unused_imports)]
        use moqtap_codec::dispatch::AnyControlMessage;

        let draft = self.draft();

        // The shared-control-stream drafts, whose only difference here is what
        // their SUBSCRIBE calls the field holding the peer's Request ID:
        // `subscribe_id` up to draft-10 and `request_id` from draft-11. The id
        // is read out before the message is wrapped, because wrapping moves it.
        #[allow(unused_macros)]
        macro_rules! control_plane {
            ($conn:ident, $version:ident, $module:ident, $id_field:ident) => {{
                let message = $conn.recv_and_dispatch().await.map_err(AnyConnectionError::from)?;
                let request_id = match &message {
                    moqtap_codec::$module::message::ControlMessage::Subscribe(s) => {
                        Some(s.$id_field)
                    }
                    _ => None,
                };
                let message = AnyControlMessage::$version(message);
                Ok(match request_id {
                    Some(request_id) => AnyArrival::Subscribe {
                        message,
                        request: AnyInboundRequest::ControlPlane { request_id, draft },
                    },
                    None => AnyArrival::Other(message),
                })
            }};
        }

        // The request-stream drafts. A request this facade cannot answer has
        // its stream dropped, which resets it — see [`AnyArrival::Other`].
        #[allow(unused_macros)]
        macro_rules! request_stream {
            ($conn:ident, $version:ident, $module:ident) => {{
                let (message, stream) =
                    $conn.accept_request_stream().await.map_err(AnyConnectionError::from)?;
                let subscribe =
                    matches!(message, moqtap_codec::$module::message::ControlMessage::Subscribe(_));
                let message = AnyControlMessage::$version(message);
                Ok(if subscribe {
                    AnyArrival::Subscribe { message, request: AnyInboundRequest::$version(stream) }
                } else {
                    drop(stream);
                    AnyArrival::Other(message)
                })
            }};
        }

        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => control_plane!(c, Draft07, draft07, subscribe_id),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => control_plane!(c, Draft08, draft08, subscribe_id),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => control_plane!(c, Draft09, draft09, subscribe_id),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => control_plane!(c, Draft10, draft10, subscribe_id),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => control_plane!(c, Draft11, draft11, request_id),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => control_plane!(c, Draft12, draft12, request_id),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => control_plane!(c, Draft13, draft13, request_id),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => control_plane!(c, Draft14, draft14, request_id),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => control_plane!(c, Draft15, draft15, request_id),
            // Draft-16 gave a stream to namespace subscriptions and to nothing
            // else, so an inbound SUBSCRIBE is still a control-stream message
            // here and the handle is still a `ControlPlane`.
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => control_plane!(c, Draft16, draft16, request_id),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => request_stream!(c, Draft17, draft17),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => request_stream!(c, Draft18, draft18),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => request_stream!(c, Draft19, draft19),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => request_stream!(c, Draft20, draft20),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => request_stream!(c, Draft21, draft21),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "recv_inbound: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Answer a peer's SUBSCRIBE with SUBSCRIBE_OK. Supported on **every draft
    /// this build carries**.
    ///
    /// `request` is the handle from [`AnyArrival::Subscribe`]. What the unified
    /// shape cannot express is defaulted: no expiry, ascending group order, and
    /// no parameters, properties or track extensions — every draft's own
    /// `Connection::subscribe_ok` is reachable through the variant for a
    /// responder that wants any of them.
    ///
    /// # The Track Alias, and why it *is* an argument here
    ///
    /// The opposite of [`AnyConnection::subscribe`], and not by inconsistency.
    /// Sending a SUBSCRIBE, the alias is bookkeeping the caller has no opinion
    /// about — any free one names the track locally — so it is read off the
    /// endpoint. Answering one, the alias is what **this side's objects will
    /// carry on the wire**, and Sections 9.8 and 9.13 require one alias to name
    /// one track: two subscriptions to the same track must be answered with the
    /// *same* alias, and a fresh one per subscription would be wrong. The
    /// endpoint cannot know which track a caller considers this to be, so the
    /// choice is the caller's and cannot be inferred.
    ///
    /// **Drafts 07 through 11 ignore it.** Those drafts put the Track Alias on
    /// SUBSCRIBE and make it the subscriber's, so their SUBSCRIBE_OK has no
    /// such field and the value that counts already arrived — it is on the
    /// message in [`AnyArrival::Subscribe`]. The argument is accepted and
    /// dropped there rather than the signature splitting in two.
    ///
    /// # Drafts 07 through 10 have an arm here and no way to be reached
    ///
    /// Not a gap in this call. A request is legal only below the ceiling its
    /// recipient granted, and a ceiling nobody granted is zero, which forbids
    /// every request. Drafts 11 and later let this side grant one in
    /// CLIENT_SETUP, as Setup Parameter `0x02`; drafts 07 through 10 grant it
    /// with the MAX_SUBSCRIBE_ID **message**, type `0x15`, and no `Connection`
    /// in this crate has an entry point for sending one. So a peer's SUBSCRIBE
    /// on those four drafts is refused for exceeding a ceiling of zero long
    /// before it reaches here.
    ///
    /// The arms stay because they are right and become reachable the day that
    /// message can be sent, without being touched.
    #[allow(unused_variables)]
    pub async fn accept_subscribe(
        &mut self,
        request: &mut AnyInboundRequest,
        track_alias: moqtap_codec::varint::VarInt,
    ) -> Result<(), AnyConnectionError> {
        use moqtap_codec::varint::VarInt;

        // No expiry, which every draft carrying the field spells as zero.
        let never_expires = VarInt::from_u64(0).expect("0 fits in VarInt");

        match (self, request) {
            // Drafts 07 through 11: the subscriber chose the alias, so
            // SUBSCRIBE_OK has nowhere to put one.
            #[cfg(feature = "draft07")]
            (Self::Draft07(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft08")]
            (Self::Draft08(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft09")]
            (Self::Draft09(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft10")]
            (Self::Draft10(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft11")]
            (Self::Draft11(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            // Draft-12 moved the alias here, and it stays until draft-17 moves
            // the whole response onto the request's own stream.
            #[cfg(feature = "draft12")]
            (Self::Draft12(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    track_alias,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft13")]
            (Self::Draft13(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    track_alias,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft14")]
            (Self::Draft14(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(
                    *request_id,
                    track_alias,
                    never_expires,
                    moqtap_codec::types::GroupOrder::Ascending,
                    Vec::new(),
                )
                .await
                .map_err(AnyConnectionError::from),
            // Draft-15 turned expiry and group order into parameters, so the
            // two arguments above become an empty list rather than defaults.
            #[cfg(feature = "draft15")]
            (Self::Draft15(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(*request_id, track_alias, Vec::new())
                .await
                .map_err(AnyConnectionError::from),
            // Draft-16 added a Track Extensions list beside the parameters.
            #[cfg(feature = "draft16")]
            (Self::Draft16(c), AnyInboundRequest::ControlPlane { request_id, .. }) => c
                .subscribe_ok(*request_id, track_alias, Vec::new(), Vec::new())
                .await
                .map_err(AnyConnectionError::from),
            // Drafts 17 through 20: the response goes back on the request's own
            // stream, which is why it carries no Request ID — the stream is the
            // correlation.
            #[cfg(feature = "draft17")]
            (Self::Draft17(c), AnyInboundRequest::Draft17(s)) => {
                use moqtap_codec::draft17::message::SubscribeOk;
                c.respond_subscribe_ok(
                    s,
                    SubscribeOk {
                        track_alias,
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    },
                )
                .await
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft18")]
            (Self::Draft18(c), AnyInboundRequest::Draft18(s)) => {
                use moqtap_codec::draft18::message::SubscribeOk;
                c.respond_subscribe_ok(
                    s,
                    SubscribeOk {
                        track_alias,
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    },
                )
                .await
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft19")]
            (Self::Draft19(c), AnyInboundRequest::Draft19(s)) => {
                use moqtap_codec::draft19::message::SubscribeOk;
                c.respond_subscribe_ok(
                    s,
                    SubscribeOk {
                        track_alias,
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    },
                )
                .await
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft20")]
            (Self::Draft20(c), AnyInboundRequest::Draft20(s)) => {
                use moqtap_codec::draft20::message::SubscribeOk;
                c.respond_subscribe_ok(
                    s,
                    SubscribeOk {
                        track_alias,
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    },
                )
                .await
                .map_err(AnyConnectionError::from)
            }
            #[cfg(feature = "draft21")]
            (Self::Draft21(c), AnyInboundRequest::Draft21(s)) => {
                use moqtap_codec::draft21::message::SubscribeOk;
                c.respond_subscribe_ok(
                    s,
                    SubscribeOk {
                        track_alias,
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    },
                )
                .await
                .map_err(AnyConnectionError::from)
            }
            // A handle from another draft, refused rather than answered on
            // whatever stream happens to be at hand — the same rule
            // [`AnyConnection::recv_response`] follows, for the same reason.
            #[allow(unreachable_patterns)]
            (connection, request) => Err(AnyConnectionError::facade(format!(
                "accept_subscribe: a draft {:?} request cannot be answered on a draft {:?} \
                 connection",
                request.draft(),
                connection.draft(),
            ))),
        }
    }

    /// Open a subgroup stream and frame it, ready for objects.
    ///
    /// The first thing a relay can be asked that is not a question about
    /// control messages. Answering SUBSCRIBE is not delivering a track, and
    /// until something puts an object on the wire there is no way to tell the
    /// two apart from outside.
    ///
    /// # The header this writes, and the four shapes it takes
    ///
    /// An explicit Subgroup ID, no extension block where a draft can say so,
    /// and a publisher priority on the wire — the plainest conforming subgroup
    /// stream each draft can carry. The struct that says so is different four
    /// times over:
    ///
    /// * **Drafts 07 through 10** put the stream type outside the header
    ///   entirely, so the header is four fields and nothing selects a layout.
    /// * **Drafts 11 through 13** name a `StreamType` variant per layout, and
    ///   `SubgroupExplicit` is the one that carries an ID and no extensions.
    /// * **Draft-14** folds the type into the header as a flag word, and the
    ///   Subgroup ID becomes an `Option` that must agree with it — a type
    ///   saying a field follows, with no field, is refused.
    /// * **Drafts 15 through 20** replace the flags with a type byte:
    ///   `0x14` is the subgroup base `0x10`, plus `0x04` for an explicit
    ///   Subgroup ID, with the extension bit `0x01` clear, the end-of-group
    ///   bit `0x08` clear, and the no-priority bit `0x20` clear. Drafts 15 and
    ///   16 read those two ID bits as a pair of table columns and drafts 17
    ///   through 20 call them a SUBGROUP_ID_MODE field, which is a difference
    ///   in wording and not in bytes.
    ///
    /// # Why the extension block is not an argument
    ///
    /// It is not a property of any object, so there is nothing an object-level
    /// caller could be asked. The header settles it for the whole stream, and
    /// an object that disagreed with its header would misframe every object
    /// after it — the missing length is read out of the next field along. A
    /// caller that needs to put extensions on a stream needs to say so when the
    /// stream opens, which is a second entry point rather than an argument
    /// here.
    ///
    /// Three drafts do not offer the choice at all, and in opposite
    /// directions. Draft-07 has no extension block anywhere, so its streams
    /// carry none because there is none to carry. Drafts 08 through 10 have one
    /// on every object and **no header field that could say otherwise**: their
    /// subgroup header is four values with no type byte, so every object writes
    /// a length whether it has anything to put after it or not. On those three
    /// [`moqtap_codec::dispatch::AnySubgroupHeader::carries_extension_block`]
    /// answers without consulting the header, and a caller asking for a stream
    /// without one is asking for a stream the draft does not define.
    ///
    /// Nothing checks that `track_alias` names a track this session agreed to
    /// publish, because a probe measuring a relay may want to send objects for
    /// one it did not.
    #[allow(unused_variables)]
    pub async fn open_subgroup(
        &self,
        track_alias: u64,
        group_id: u64,
        subgroup_id: u64,
        publisher_priority: u8,
    ) -> Result<AnySubgroupWriter, AnyConnectionError> {
        // Used only by the per-draft arms below, so a build with no draft
        // feature enabled — the `<zero drafts>` row of `just draft-matrix`,
        // which exists to prove the crate still compiles with nothing
        // selected — compiles this import and reaches no arm that reads it.
        #[allow(unused_imports)]
        use moqtap_codec::dispatch::AnySubgroupHeader;
        use moqtap_codec::varint::VarInt;
        let alias = VarInt::from_u64(track_alias)
            .map_err(|e| AnyConnectionError::facade(format!("track alias {track_alias}: {e}")))?;
        let group = VarInt::from_u64(group_id)
            .map_err(|e| AnyConnectionError::facade(format!("group id {group_id}: {e}")))?;
        let subgroup = VarInt::from_u64(subgroup_id)
            .map_err(|e| AnyConnectionError::facade(format!("subgroup id {subgroup_id}: {e}")))?;

        #[allow(unused_macros)]
        macro_rules! open {
            ($c:ident, $variant:ident, $header:expr) => {{
                let header = AnySubgroupHeader::$variant($header);
                $c.open_subgroup_stream(&header)
                    .await
                    .map(AnySubgroupWriter::$variant)
                    .map_err(AnyConnectionError::from)
            }};
        }

        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => open!(
                c,
                Draft07,
                moqtap_codec::draft07::data_stream::SubgroupHeader {
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => open!(
                c,
                Draft08,
                moqtap_codec::draft08::data_stream::SubgroupHeader {
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => open!(
                c,
                Draft09,
                moqtap_codec::draft09::data_stream::SubgroupHeader {
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => open!(
                c,
                Draft10,
                moqtap_codec::draft10::data_stream::SubgroupHeader {
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => open!(
                c,
                Draft11,
                moqtap_codec::draft11::data_stream::SubgroupHeader {
                    stream_type: moqtap_codec::draft11::data_stream::StreamType::SubgroupExplicit,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => open!(
                c,
                Draft12,
                moqtap_codec::draft12::data_stream::SubgroupHeader {
                    stream_type: moqtap_codec::draft12::data_stream::StreamType::SubgroupExplicit,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => open!(
                c,
                Draft13,
                moqtap_codec::draft13::data_stream::SubgroupHeader {
                    stream_type: moqtap_codec::draft13::data_stream::StreamType::SubgroupExplicit,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => open!(
                c,
                Draft14,
                moqtap_codec::draft14::data_stream::SubgroupHeader {
                    // Subgroup ID field present, not taken from the first
                    // object, no extensions, not the end of the group.
                    stream_type: moqtap_codec::draft14::data_stream::SubgroupStreamType::from_flags(
                        true, false, false, false,
                    ),
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: Some(subgroup),
                    publisher_priority,
                }
            ),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => open!(
                c,
                Draft15,
                moqtap_codec::draft15::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => open!(
                c,
                Draft16,
                moqtap_codec::draft16::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => open!(
                c,
                Draft17,
                moqtap_codec::draft17::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => open!(
                c,
                Draft18,
                moqtap_codec::draft18::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => open!(
                c,
                Draft19,
                moqtap_codec::draft19::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => open!(
                c,
                Draft20,
                moqtap_codec::draft20::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => open!(
                c,
                Draft21,
                moqtap_codec::draft21::data_stream::SubgroupHeader {
                    header_type: 0x14,
                    track_alias: alias,
                    group_id: group,
                    subgroup_id: subgroup,
                    publisher_priority: Some(publisher_priority),
                }
            ),
            #[allow(unreachable_patterns)]
            _ => Err(AnyConnectionError::facade("no draft feature is enabled")),
        }
    }

    /// Accept the next subgroup stream the peer opens, and read its header.
    ///
    /// The header comes back beside the reader because it is the only place
    /// several things are said: which track the objects belong to (by Track
    /// Alias), which group, and — through
    /// [`carries_extension_block`](moqtap_codec::dispatch::AnySubgroupHeader::carries_extension_block)
    /// — whether the objects on this stream write an extension block at all. A
    /// reader that did not know the last of those could not frame a single
    /// object.
    ///
    /// Reading the header is not separable from accepting the stream, and the
    /// per-draft connections do both in one call for a reason beyond
    /// convenience: the header settles the track's forwarding preference and
    /// binds the stream to the endpoint's object bookkeeping for that alias, so
    /// a stream accepted without its header read would be a stream whose
    /// objects nothing is measuring.
    ///
    /// This waits on the *next* unidirectional stream, whatever it carries. A
    /// draft that sends something else on one — and every draft does, for
    /// fetches — will fail to parse a subgroup header out of it, which is the
    /// same wall [`AnyConnection::accept_fetch`] hits from the other side.
    /// Nothing here reads the stream type first and branches: a caller that
    /// could receive either has to know which it is expecting, because the
    /// header decides how every object after it is framed.
    pub async fn accept_subgroup(
        &self,
    ) -> Result<(moqtap_codec::dispatch::AnySubgroupHeader, AnySubgroupReader), AnyConnectionError>
    {
        #[allow(unused_macros)]
        macro_rules! accept {
            ($c:ident, $variant:ident) => {{
                $c.accept_subgroup_stream()
                    .await
                    .map(|(header, stream)| (header, AnySubgroupReader::$variant(stream)))
                    .map_err(AnyConnectionError::from)
            }};
        }

        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => accept!(c, Draft07),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => accept!(c, Draft08),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => accept!(c, Draft09),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => accept!(c, Draft10),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => accept!(c, Draft11),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => accept!(c, Draft12),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => accept!(c, Draft13),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => accept!(c, Draft14),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => accept!(c, Draft15),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => accept!(c, Draft16),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => accept!(c, Draft17),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => accept!(c, Draft18),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => accept!(c, Draft19),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => accept!(c, Draft20),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => accept!(c, Draft21),
            #[allow(unreachable_patterns)]
            _ => Err(AnyConnectionError::facade("no draft feature is enabled")),
        }
    }

    /// Accept the next fetch stream the peer opens, and read its FETCH_HEADER.
    ///
    /// [`AnyConnection::accept_subgroup`]'s twin, and it waits on the same
    /// queue: the *next* unidirectional stream, whatever it carries. A subgroup
    /// stream arriving here fails to parse as a FETCH_HEADER, and a fetch stream
    /// arriving there fails the other way. A caller reading both kinds on one
    /// session has to know which is next, and this facade will not guess for it
    /// — see `accept_subgroup` for why guessing is the wrong shape.
    ///
    /// The header comes back because it names the request: everything on the
    /// stream after it answers the FETCH whose Request ID it carries, and a
    /// caller with more than one fetch in flight has no other way to tell the
    /// streams apart.
    ///
    /// # Why this takes a Group Order and `accept_subgroup` takes nothing
    ///
    /// Because on four drafts the reader cannot be started without it, and
    /// starting it wrong is silent. Drafts 18 through 21 encode an object's
    /// Group ID as a **delta**, and draft-18 Section 11.4.4.1 makes that delta
    /// count upward under Ascending and downward under Descending. A reader
    /// started in the wrong direction still parses every frame and reports Group
    /// IDs that walk the wrong way — the same trap
    /// `Connection::accept_fill_stream` documents on draft-20, where the
    /// endpoint happens to know the answer and this facade does not.
    ///
    /// Here nothing on this side holds it: the order is on the FETCH_OK, which
    /// is a control message a data stream never sees, and which the caller has
    /// already read. [`fetch_group_order`] takes it off that message so the
    /// lookup is written once rather than per caller.
    ///
    /// On the other drafts the argument is inert, and it is an argument
    /// rather than an `Option` because a caller that has a FETCH_OK in hand can
    /// always answer it, and one that cannot has not read the answer yet.
    #[allow(unused_variables)]
    pub async fn accept_fetch(
        &self,
        group_order: moqtap_codec::types::GroupOrder,
    ) -> Result<(moqtap_codec::dispatch::AnyFetchHeader, AnyFetchReader), AnyConnectionError> {
        #[allow(unused_macros)]
        macro_rules! accept {
            ($c:ident, $variant:ident) => {{
                $c.accept_fetch_stream()
                    .await
                    .map(|(header, stream)| (header, AnyFetchReader::$variant(stream)))
                    .map_err(AnyConnectionError::from)
            }};
            // The three drafts whose object reader has to be pointed in a
            // direction before it will read anything. Each of them declares its
            // own two-valued `GroupOrder` beside the reader that consumes it,
            // because a delta either adds or subtracts and there is no third
            // thing it could do. `Publisher` — the third value of the control
            // plane's own enum, and the one a FETCH_OK omitting the property
            // leaves — becomes Ascending here, which is what draft-20 Section
            // 10.2.8 makes the default.
            ($c:ident, $variant:ident, $module:ident) => {{
                let order = match group_order {
                    moqtap_codec::types::GroupOrder::Descending => {
                        moqtap_codec::$module::data_stream::GroupOrder::Descending
                    }
                    _ => moqtap_codec::$module::data_stream::GroupOrder::Ascending,
                };
                $c.accept_fetch_stream()
                    .await
                    .map(|(header, mut stream)| {
                        stream.begin_fetch_objects(order);
                        (header, AnyFetchReader::$variant(stream))
                    })
                    .map_err(AnyConnectionError::from)
            }};
        }

        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => accept!(c, Draft07),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => accept!(c, Draft08),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => accept!(c, Draft09),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => accept!(c, Draft10),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => accept!(c, Draft11),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => accept!(c, Draft12),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => accept!(c, Draft13),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => accept!(c, Draft14),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => accept!(c, Draft15),
            // The resolver is created here rather than seeded from the header,
            // because draft-16's first object supplies its own Location and
            // every later one inherits from the object before it.
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .accept_fetch_stream()
                .await
                .map(|(header, stream)| {
                    (
                        header,
                        AnyFetchReader::Draft16(Draft16FetchStream {
                            stream,
                            reader: moqtap_codec::draft16::data_stream::FetchObjectReader::new(),
                        }),
                    )
                })
                .map_err(AnyConnectionError::from),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => accept!(c, Draft17),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => accept!(c, Draft18, draft18),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => accept!(c, Draft19, draft19),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => accept!(c, Draft20, draft20),
            #[cfg(feature = "draft21")]
            Self::Draft21(c) => accept!(c, Draft21, draft21),
            #[allow(unreachable_patterns)]
            _ => Err(AnyConnectionError::facade("no draft feature is enabled")),
        }
    }

    /// Send a SUBSCRIBE_UPDATE for an active subscription. Draft-14 only.
    ///
    /// # Why no later draft is wired, and why that is not this call's to fix
    ///
    /// Draft-15 renamed the message REQUEST_UPDATE and rebuilt it, and from
    /// draft-17 it travels **on the request's own bidirectional stream** rather
    /// than on a control stream — so an update needs the [`AnyRequest`] the
    /// original request returned, which this signature does not take and cannot
    /// be given without becoming a different call. Draft-20 goes further and
    /// has no `start_location` / `end_group` pair at all: Section 10.9 carries
    /// the new range as a `LOCATION_FILTER` parameter, on the same inclusive
    /// terms [`FetchRange`] describes. Reach a draft's own
    /// `Connection::send_on_request_stream` through the variant.
    #[allow(unused_variables)]
    pub async fn subscribe_update(
        &mut self,
        subscription_request_id: moqtap_codec::varint::VarInt,
        start_location: moqtap_codec::types::Location,
        end_group: moqtap_codec::varint::VarInt,
        subscriber_priority: u8,
        forward: moqtap_codec::types::Forward,
    ) -> Result<(), AnyConnectionError> {
        match self {
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .subscribe_update(
                    subscription_request_id,
                    start_location,
                    end_group,
                    subscriber_priority,
                    forward,
                    Vec::new(),
                )
                .await
                .map(|_| ())
                .map_err(AnyConnectionError::from),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError::facade(format!(
                "subscribe_update: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }
}

/// Trait for receiving events from an [`AnyConnection`].
///
/// Implementations must be `Send + Sync` because the adapter installed on
/// the inner draft-specific connection may emit events from async tasks.
/// `on_event` takes `&self` — implementations that need mutation should use
/// interior mutability (e.g. `Mutex`, `mpsc::Sender`).
///
/// The per-draft adapter clones the draft-specific event into the matching
/// [`AnyClientEvent`] variant before invoking `on_event`.
pub trait AnyConnectionObserver: Send + Sync {
    /// Called when a connection event occurs on any draft.
    fn on_event(&self, event: &AnyClientEvent);
}

/// A no-op observer that discards all events.
pub struct NoOpObserver;

impl AnyConnectionObserver for NoOpObserver {
    fn on_event(&self, _event: &AnyClientEvent) {}
}

/// One control message as it crossed the wire, lifted out of whichever draft's
/// event carried it.
///
/// [`AnyClientEvent`] wraps a draft's own `ClientEvent`, so an observer holding
/// one can read [`draft`](AnyClientEvent::draft) and nothing else without
/// matching every enabled variant — which means a consumer outside this crate
/// writing its own cascade over every draft, the exact duplication this module
/// exists to hold in one place. [`AnyClientEvent::control_frame`] answers with
/// this instead.
///
/// Everything here borrows from the event, so it is a view rather than a
/// record: a consumer that wants to keep a frame copies the bytes out.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ControlFrame<'a> {
    /// The draft whose rules were used to decode it.
    pub draft: DraftVersion,
    /// Whether this endpoint sent it, as opposed to receiving it.
    ///
    /// A `bool` rather than a shared direction enum because each draft declares
    /// its own `Direction` and there is no cross-draft one to lift them into;
    /// inventing a sixteenth to convert the other fifteen into would be a type
    /// whose only purpose is to be converted.
    pub outbound: bool,
    /// The decoded message. [`message_type_id`] and [`message_type_name`] name
    /// the codepoint it arrived under.
    ///
    /// [`message_type_id`]: moqtap_codec::dispatch::AnyControlMessage::message_type_id
    /// [`message_type_name`]: moqtap_codec::dispatch::AnyControlMessage::message_type_name
    pub message: &'a moqtap_codec::dispatch::AnyControlMessage,
    /// The framed wire bytes — type, length and payload — as they arrived.
    ///
    /// `None` when the connection was reading without an observer attached and
    /// therefore never cloned them. That cannot happen for an event an observer
    /// is being handed, so in practice this is `None` only for a frame built by
    /// hand.
    ///
    /// Kept because the encoding is evidence the decoding discards: two peers
    /// sending the same field can still disagree on how wide a varint they
    /// wrote it in, and the decoded form answers the same either way.
    pub raw: Option<&'a [u8]>,
}

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
        }

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

/// Error returned by [`AnyConnection::connect`] and
/// [`AnyConnection::recv_and_dispatch`]. Draft-specific errors are flattened
/// to strings so callers don't have to branch on draft to inspect errors.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct AnyConnectionError(pub String);

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
        }
    }

    /// The transport stream ID this request owns, or `None` on a draft that
    /// carries requests on the shared control stream.
    ///
    /// This is the observable difference between the two variants: a caller
    /// that needs to correlate a response by stream — which is the only
    /// correlation drafts 17-19 offer — gets `Some` exactly when the draft
    /// provides one.
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
            Self::ControlPlane { draft, .. } => Err(AnyConnectionError(format!(
                "cancel: draft {draft:?} carries this request on the control stream, so the \
                 request handle has no stream to reset; send the draft's own cancellation \
                 message instead"
            ))),
            #[cfg(feature = "draft16")]
            Self::Draft16(r) => r.cancel(code).map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(r) => r.cancel(code).map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(r) => r.cancel(code).map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft19")]
            Self::Draft19(r) => r.cancel(code).map_err(|e| AnyConnectionError(e.to_string())),
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
            feature = "draft19"
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                Ok(AnyConnection::Draft19(c))
            }
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!("draft {other:?} not enabled in this build",))),
        }
    }

    /// Read and dispatch one control message on the active draft. Draft-specific
    /// control-message return values are discarded because event delivery goes
    /// through the attached observer; callers only care about success/failure.
    pub async fn recv_and_dispatch(&mut self) -> Result<(), AnyConnectionError> {
        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .recv_and_dispatch()
                .await
                .map(|_| ())
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            _ => Err(AnyConnectionError("AnyConnection has no enabled variants".into())),
        }
    }

    // ── Unified control-message helpers ──────────────────────────────────
    //
    // Draft-agnostic shorthands. Each dispatches to the active variant and
    // defaults fields not expressible in the unified shape; drafts that
    // lack the operation return an `AnyConnectionError`. Match on the
    // variant directly when full per-draft control is needed.

    /// Send an UNSUBSCRIBE for the given request ID. Identical across all drafts.
    #[allow(unused_variables)]
    pub async fn unsubscribe(
        &mut self,
        request_id: moqtap_codec::varint::VarInt,
    ) -> Result<(), AnyConnectionError> {
        match self {
            #[cfg(feature = "draft07")]
            Self::Draft07(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft08")]
            Self::Draft08(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft09")]
            Self::Draft09(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft10")]
            Self::Draft10(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => {
                c.unsubscribe(request_id).await.map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "unsubscribe: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a SUBSCRIBE with the given filter, priority, and group order.
    /// Supported on drafts 12–17. Drafts 15–17 carry priority/order/filter via
    /// parameters; this helper passes an empty parameter list, so those fields
    /// default to protocol-defined values on those drafts.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-19 it owns the bidirectional stream the request went out on
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
        // Only the draft-12 arm below converts `filter_type` by hand: draft-12
        // draws that field as a variable-length integer, where the drafts on
        // either side of it take the typed value straight through. So the
        // import is dead outside that build.
        #[cfg(feature = "draft12")]
        use moqtap_codec::varint::VarInt;
        let draft = self.draft();
        match self {
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => {
                let ft = VarInt::from_u64(filter_type as u64)
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                c.subscribe(namespace, track_name, subscriber_priority, group_order, ft, Vec::new())
                    .await
                    .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                    .map_err(|e| AnyConnectionError(e.to_string()))
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
                .map_err(|e| AnyConnectionError(e.to_string())),
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
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft17)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "subscribe: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a standalone FETCH. Wired on drafts 14 through 19; every earlier
    /// draft returns the error at the end of the match.
    ///
    /// The end of the range reaches every draft that is wired. It used to be
    /// dropped on draft-14, whose own `fetch` had nowhere to put it, and that
    /// is no longer so.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-19 it owns the bidirectional stream the request went out on
    /// and dropping it cancels the fetch.
    #[allow(unused_variables)]
    pub async fn fetch(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
        start_group: moqtap_codec::varint::VarInt,
        start_object: moqtap_codec::varint::VarInt,
        end_group: moqtap_codec::varint::VarInt,
        end_object: moqtap_codec::varint::VarInt,
    ) -> Result<AnyRequest, AnyConnectionError> {
        let draft = self.draft();
        match self {
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .fetch(
                    namespace,
                    track_name,
                    // The priority and the order are fields of draft-14's FETCH
                    // and of no later draft's, so this entry point does not
                    // carry them and sends what it always sent. The end of the
                    // range it does carry, and used to drop here.
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft17)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft18)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .fetch(
                    namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft19)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "fetch: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a TRACK_STATUS query for the given track. Supported on drafts 14–17.
    /// On drafts 15–17, passes an empty parameter list.
    ///
    /// The returned [`AnyRequest`] must be held until the answer arrives: on
    /// drafts 17-19 it owns the bidirectional stream the query went out on and
    /// dropping it cancels the query.
    #[allow(unused_variables)]
    pub async fn track_status(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<AnyRequest, AnyConnectionError> {
        let draft = self.draft();
        match self {
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .track_status(
                    namespace,
                    track_name,
                    // Draft-14 words TRACK_STATUS like a SUBSCRIBE and no
                    // later draft does, so these four are sent as they always
                    // were rather than widening an entry point shared with six
                    // drafts that have no such fields.
                    128,
                    moqtap_codec::types::GroupOrder::Ascending,
                    moqtap_codec::types::Forward::Forward,
                    moqtap_codec::types::FilterType::LargestObject,
                    Vec::new(),
                )
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft17)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "track_status: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a SUBSCRIBE_NAMESPACE (or SUBSCRIBE_ANNOUNCES on drafts 11–12).
    /// Supported on drafts 11–17. Drafts 16–17 pass default subscribe options
    /// and an empty parameter list.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-19 it owns the bidirectional stream the request went out on
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
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .subscribe_announces(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(|request_id| AnyRequest::ControlPlane { request_id, draft })
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => {
                let opts = VarInt::from_u64(0).expect("0 fits in VarInt");
                c.subscribe_namespace(namespace_prefix, opts, Vec::new())
                    .await
                    .map(AnyRequest::Draft16)
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => {
                let opts = VarInt::from_u64(0).expect("0 fits in VarInt");
                c.subscribe_namespace(namespace_prefix, opts, Vec::new())
                    .await
                    .map(AnyRequest::Draft17)
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft18)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft19")]
            Self::Draft19(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft19)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "subscribe_namespace: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a SUBSCRIBE_UPDATE for an active subscription. Draft 14 only —
    /// earlier/later drafts either don't expose a matching client wrapper or
    /// use a different message shape.
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
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
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

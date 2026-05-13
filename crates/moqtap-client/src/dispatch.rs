//! Unified multi-draft entry-point types.
//!
//! This module is the facade downstream consumers (e.g. a CLI or desktop app)
//! use to hold a MoQT connection without caring which draft was negotiated.
//! It mirrors [`moqtap_codec::dispatch`]: one enum variant per enabled draft,
//! gated on its feature flag.
//!
//! Three types live here:
//!
//! - `AnyConnection` — wraps a draft-specific `Connection`.
//! - `AnyClientEvent` — wraps a draft-specific `ClientEvent`.
//! - `AnyConnectionObserver` — a trait that receives `AnyClientEvent`s.
//!   Attached to an `AnyConnection` via `AnyConnection::set_observer`,
//!   which installs a per-draft adapter on the inner connection.
//!
//! Draft-specific protocol methods (e.g. `subscribe`, `fetch`) are not on
//! `AnyConnection` because their signatures differ across drafts — match
//! on the variant to reach them.

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

impl AnyConnection {
    /// Connect to a MoQT server using the requested draft. Builds the
    /// draft-specific `ClientConfig` from the provided [`AnyClientConfig`]
    /// and dispatches to the appropriate `Connection::connect`.
    pub async fn connect(addr: &str, config: AnyClientConfig) -> Result<Self, AnyConnectionError> {
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
    #[allow(unused_variables)]
    pub async fn subscribe(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: moqtap_codec::types::GroupOrder,
        filter_type: moqtap_codec::types::FilterType,
    ) -> Result<moqtap_codec::varint::VarInt, AnyConnectionError> {
        use moqtap_codec::varint::VarInt;
        match self {
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => {
                let go = VarInt::from_u64(group_order as u64)
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                let ft = VarInt::from_u64(filter_type as u64)
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                c.subscribe(namespace, track_name, subscriber_priority, go, ft)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => {
                let go = VarInt::from_u64(group_order as u64)
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                let ft = VarInt::from_u64(filter_type as u64)
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                c.subscribe(namespace, track_name, subscriber_priority, go, ft)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .subscribe(namespace, track_name, subscriber_priority, group_order, filter_type)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "subscribe: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a standalone FETCH. Supported on drafts 14–17. On draft 14 the
    /// `end_group`/`end_object` are ignored (draft 14's wrapper only accepts
    /// a start location).
    #[allow(unused_variables)]
    pub async fn fetch(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
        start_group: moqtap_codec::varint::VarInt,
        start_object: moqtap_codec::varint::VarInt,
        end_group: moqtap_codec::varint::VarInt,
        end_object: moqtap_codec::varint::VarInt,
    ) -> Result<moqtap_codec::varint::VarInt, AnyConnectionError> {
        match self {
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .fetch(namespace, track_name, start_group, start_object)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .fetch(namespace, track_name, start_group, start_object, end_group, end_object)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .fetch(namespace, track_name, start_group, start_object, end_group, end_object)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .fetch(namespace, track_name, start_group, start_object, end_group, end_object)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .fetch(namespace, track_name, start_group, start_object, end_group, end_object)
                .await
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
    #[allow(unused_variables)]
    pub async fn track_status(
        &mut self,
        namespace: moqtap_codec::types::TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<moqtap_codec::varint::VarInt, AnyConnectionError> {
        match self {
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .track_status(namespace, track_name)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
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
    #[allow(unused_variables)]
    pub async fn subscribe_namespace(
        &mut self,
        namespace_prefix: moqtap_codec::types::TrackNamespace,
    ) -> Result<moqtap_codec::varint::VarInt, AnyConnectionError> {
        use moqtap_codec::varint::VarInt;
        match self {
            #[cfg(feature = "draft11")]
            Self::Draft11(c) => c
                .subscribe_announces(namespace_prefix)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft12")]
            Self::Draft12(c) => c
                .subscribe_announces(namespace_prefix)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft13")]
            Self::Draft13(c) => c
                .subscribe_namespace(namespace_prefix)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft14")]
            Self::Draft14(c) => c
                .subscribe_namespace(namespace_prefix)
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft15")]
            Self::Draft15(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft16")]
            Self::Draft16(c) => {
                let opts = VarInt::from_u64(0).expect("0 fits in VarInt");
                c.subscribe_namespace(namespace_prefix, opts, Vec::new())
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft17")]
            Self::Draft17(c) => {
                let opts = VarInt::from_u64(0).expect("0 fits in VarInt");
                c.subscribe_namespace(namespace_prefix, opts, Vec::new())
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[cfg(feature = "draft18")]
            Self::Draft18(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
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

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
    #[cfg(feature = "draft20")]
    Draft20 => draft20,
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
                AnyConnectionError(format!(
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
    #[cfg(feature = "draft20")]
    pub fn location_filter(
        &self,
    ) -> Result<crate::draft20::fill::LocationFilter, AnyConnectionError> {
        use crate::draft20::fill::LocationFilter;

        let delta = self.end_group.checked_sub(self.start_group).ok_or_else(|| {
            AnyConnectionError(format!(
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
        filter.map_err(|e| AnyConnectionError(e.to_string()))
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
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => Some(r.stream_id()),
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
            #[cfg(feature = "draft20")]
            Self::Draft20(r) => r.cancel(code).map_err(|e| AnyConnectionError(e.to_string())),
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
            feature = "draft20"
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
                let c = Connection::connect(addr, inner)
                    .await
                    .map_err(|e| AnyConnectionError(e.to_string()))?;
                Ok(AnyConnection::Draft20(c))
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
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
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
    /// Supported on drafts 12 through 20. Drafts 15 onward carry
    /// priority/order/filter as parameters rather than fields; this helper
    /// passes an empty parameter list, so on those drafts all three take the
    /// protocol default and the three arguments here are ignored.
    ///
    /// There is no range to get wrong: a subscription with no filter is one
    /// that starts where the draft says it starts, and nothing is converted.
    /// A draft-20 caller that wants a Location filter, a fill, or anything else
    /// from Section 10.2 reaches
    /// [`draft20::connection::Connection::subscribe`](crate::draft20::connection::Connection::subscribe)
    /// through the variant with the parameters it wants.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-20 it owns the bidirectional stream the request went out on
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
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .subscribe(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "subscribe: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a standalone FETCH for `range`. Wired on drafts 14 through 20;
    /// every earlier draft returns the error at the end of the match.
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
    /// [`FetchRange`] rather than four numbers. Drafts 14 through 19 carry
    /// `Start Location` and `End Location` inline in FETCH, and all six word
    /// the end alike — draft-19 Section 10.12.1: "The end Location, plus 1. A
    /// Location.Object value of 0 means the entire group is requested." The
    /// section number moves between drafts; the sentence does not.
    /// Draft-20 Section 10.13 deleted both fields and
    /// moved the range into the `LOCATION_FILTER` parameter, whose ranges
    /// Section 5.1.2 calls **inclusive** — the `+ 1` and the `0`-means-whole-
    /// group convention are both gone, and neither deletion is in the draft's
    /// own change log. A single `end_object: u64` at this boundary would have
    /// meant one of those two things and looked like the other.
    ///
    /// The conversion is [`FetchRange::inline_end_object`] for the first group
    /// and [`FetchRange::location_filter`] for draft-20. **The `+ 1` exists in
    /// exactly one place**, the first of those, so it cannot reach draft-20 by
    /// being ported.
    ///
    /// # What this does not carry
    ///
    /// An empty parameter list, on every draft. Draft-14's subscriber priority
    /// and group order are fields of its FETCH and of no later draft's, so they
    /// are sent as they always were. Reach a draft's own `Connection::fetch`
    /// through the variant for anything past a plain range.
    ///
    /// # Errors
    ///
    /// A range the negotiated draft cannot express, before anything is written:
    /// `FetchEnd::Object(u64::MAX)` on drafts 14 through 19, and an `end_group`
    /// below `start_group` on draft-20. See the two conversions for why each is
    /// inexpressible rather than merely unusual.
    ///
    /// The returned [`AnyRequest`] must be held while the request is live: on
    /// drafts 17-20 it owns the bidirectional stream the request went out on
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
                    inline_end_object()?,
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
                    inline_end_object()?,
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
                    inline_end_object()?,
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
                    inline_end_object()?,
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
                    inline_end_object()?,
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
                    inline_end_object()?,
                    Vec::new(),
                )
                .await
                .map(AnyRequest::Draft19)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => {
                // Draft-20 Section 10.13 has no location fields to fill in:
                // `fetch_range` puts the whole range in the `LOCATION_FILTER`
                // parameter, at the position ascending Parameter Type order
                // requires. Nothing here adds one to the end — Section 5.1.2
                // makes the filter's range inclusive, and the `+ 1` the six
                // arms above apply lives in `inline_end_object` alone.
                let filter = range.location_filter()?;
                c.fetch_range(namespace, track_name, &filter, Vec::new())
                    .await
                    .map(AnyRequest::Draft20)
                    .map_err(|e| AnyConnectionError(e.to_string()))
            }
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "fetch: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
        }
    }

    /// Send a TRACK_STATUS query for the given track. Supported on drafts 14
    /// through 20. From draft-15 on, passes an empty parameter list.
    ///
    /// The returned [`AnyRequest`] must be held until the answer arrives: on
    /// drafts 17-20 it owns the bidirectional stream the query went out on and
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
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .track_status(namespace, track_name, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
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
    /// drafts 17-20 it owns the bidirectional stream the request went out on
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
            #[cfg(feature = "draft20")]
            Self::Draft20(c) => c
                .subscribe_namespace(namespace_prefix, Vec::new())
                .await
                .map(AnyRequest::Draft20)
                .map_err(|e| AnyConnectionError(e.to_string())),
            #[allow(unreachable_patterns)]
            other => Err(AnyConnectionError(format!(
                "subscribe_namespace: not yet wired up for draft {:?} via AnyConnection",
                other.draft()
            ))),
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

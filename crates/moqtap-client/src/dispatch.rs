//! Unified multi-draft entry-point types.
//!
//! This module is the facade downstream consumers (e.g. a CLI or desktop app)
//! use to hold a MoQT connection without caring which draft was negotiated.
//! It mirrors [`moqtap_codec::dispatch`]: one enum variant per enabled draft,
//! gated on its feature flag.
//!
//! Three types live here:
//!
//! - [`AnyConnection`] — wraps a draft-specific `Connection`.
//! - [`AnyClientEvent`] — wraps a draft-specific `ClientEvent`.
//! - [`AnyConnectionObserver`] — a trait that receives [`AnyClientEvent`]s.
//!   Attached to an [`AnyConnection`] via [`AnyConnection::set_observer`],
//!   which installs a per-draft adapter on the inner connection.
//!
//! Draft-specific protocol methods (e.g. `subscribe`, `fetch`) are not on
//! [`AnyConnection`] because their signatures differ across drafts — match
//! on the variant to reach them.

use std::sync::Arc;

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

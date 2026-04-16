//! Proxy observer trait for receiving proxy events.

use crate::event::ProxyEvent;

/// Observer that receives events from the proxy's inline parser.
///
/// Implementations must be `Send + Sync` because the observer is shared
/// across multiple forwarding tasks. Use interior mutability (e.g.,
/// `Mutex`, `mpsc::Sender`) if you need mutable state.
pub trait ProxyObserver: Send + Sync {
    /// Called for each event emitted by the proxy.
    fn on_event(&self, event: &ProxyEvent);

    /// Whether this observer cares about events.
    ///
    /// When this returns `false`, the proxy can skip constructing
    /// `ProxyEvent` values and, in some cases, skip parsing entirely —
    /// turning the proxy into a true byte-for-byte pass-through. Default
    /// is `true` (preserve existing behavior for custom observers).
    fn wants_events(&self) -> bool {
        true
    }
}

/// A no-op observer that discards all events.
pub struct NoOpProxyObserver;

impl ProxyObserver for NoOpProxyObserver {
    fn on_event(&self, _event: &ProxyEvent) {}

    fn wants_events(&self) -> bool {
        false
    }
}

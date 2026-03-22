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
}

/// A no-op observer that discards all events.
pub struct NoOpProxyObserver;

impl ProxyObserver for NoOpProxyObserver {
    fn on_event(&self, _event: &ProxyEvent) {}
}

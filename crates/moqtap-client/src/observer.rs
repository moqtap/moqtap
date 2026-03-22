//! Connection observer trait for receiving structured events.

use crate::event::ClientEvent;

/// Trait for receiving events from a MoQT connection.
///
/// Implementations must be `Send + Sync` because the connection may emit
/// events from async tasks. The `on_event` method takes `&self` (not
/// `&mut self`) — implementations that need mutation should use interior
/// mutability (e.g., `Mutex`, `mpsc::Sender`).
///
/// The callback is synchronous to keep the hot path simple. Implementations
/// that need async processing should send to an internal channel.
pub trait ConnectionObserver: Send + Sync {
    /// Called when a connection event occurs.
    fn on_event(&self, event: &ClientEvent);
}

/// A no-op observer that discards all events.
pub struct NoOpObserver;

impl ConnectionObserver for NoOpObserver {
    fn on_event(&self, _event: &ClientEvent) {}
}

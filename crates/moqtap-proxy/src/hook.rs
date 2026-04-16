//! Proxy hook trait for optional frame mutation.

use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};

use crate::event::{ProxySide, SessionId};

/// Hook for optionally mutating frames before forwarding.
///
/// By default all methods return `None`, meaning the original bytes pass
/// through unchanged. Return `Some(bytes)` to replace the forwarded frame
/// with the provided bytes.
///
/// Implementations must be `Send + Sync` because the hook is shared across
/// multiple forwarding tasks.
pub trait ProxyHook: Send + Sync {
    /// Whether this hook may rewrite control messages.
    ///
    /// Returning `true` switches the proxy's control-stream handling from
    /// the default forward-first / parse-side-path mode to a slower
    /// parse-then-forward mode that honors the `Some(bytes)` return value
    /// of [`Self::on_control_message`]. Defaults to `false` so hooks used
    /// only for observation do not pay the latency cost.
    fn wants_control_mutation(&self) -> bool {
        false
    }

    /// Called before forwarding a control message.
    ///
    /// `raw_bytes` contains the original wire bytes (type + scope +
    /// payload_length + payload). Return `Some(bytes)` to forward modified
    /// bytes, or `None` to forward unchanged.
    ///
    /// Return values are only honored when [`Self::wants_control_mutation`]
    /// returns `true`; otherwise this method is invoked purely for
    /// observation and the return value is discarded.
    fn on_control_message(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _message: &AnyControlMessage,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        None
    }

    /// Called before forwarding a datagram.
    ///
    /// `raw_bytes` contains the full datagram payload (header + object
    /// data). Return `Some(bytes)` to forward modified bytes, or `None`
    /// to forward unchanged.
    fn on_datagram(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _header: &AnyDatagramHeader,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        None
    }
}

/// A no-op hook that passes all frames through unchanged.
pub struct NoOpHook;

impl ProxyHook for NoOpHook {}

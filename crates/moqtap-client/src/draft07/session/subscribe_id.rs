use moqtap_codec::varint::VarInt;

/// Errors from subscribe ID allocation or validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscribeIdError {
    /// The subscribe ID exceeds the current MAX_SUBSCRIBE_ID.
    #[error("subscribe ID {0} exceeds max {1}")]
    ExceedsMax(u64, u64),
    /// MAX_SUBSCRIBE_ID must only increase; it decreased.
    #[error("max subscribe ID can only increase: was {0}, got {1}")]
    Decreased(u64, u64),
    /// No subscribe IDs are available (max is 0 or exhausted).
    #[error("no subscribe IDs available (blocked)")]
    Blocked,
}

/// Allocates and validates subscribe IDs per the MoQT draft-07 spec.
///
/// Draft-07 has no client/server parity rule for subscribe IDs (unlike
/// the draft-14 request ID allocator). The subscriber allocates IDs
/// monotonically starting at 0; FETCH and SUBSCRIBE share the same
/// namespace since each carries a `subscribe_id` field.
pub struct SubscribeIdAllocator {
    next_id: u64,
    max_id: u64,
}

impl Default for SubscribeIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscribeIdAllocator {
    /// Create a new allocator starting at subscribe_id 0 with max_id = 0
    /// (blocked until the peer sends MAX_SUBSCRIBE_ID).
    pub fn new() -> Self {
        Self { next_id: 0, max_id: 0 }
    }

    /// Allocate the next subscribe ID.
    pub fn allocate(&mut self) -> Result<VarInt, SubscribeIdError> {
        if self.max_id == 0 || self.next_id >= self.max_id {
            return Err(SubscribeIdError::Blocked);
        }
        let id = VarInt::from_u64(self.next_id).unwrap();
        self.next_id += 1;
        Ok(id)
    }

    /// Update the maximum allowed subscribe ID (can only increase).
    pub fn update_max(&mut self, new_max: u64) -> Result<(), SubscribeIdError> {
        if new_max <= self.max_id {
            return Err(SubscribeIdError::Decreased(self.max_id, new_max));
        }
        self.max_id = new_max;
        Ok(())
    }

    /// Validate a subscribe ID received from the peer.
    pub fn validate_peer_id(&self, id: u64) -> Result<(), SubscribeIdError> {
        if id >= self.max_id {
            return Err(SubscribeIdError::ExceedsMax(id, self.max_id));
        }
        Ok(())
    }

    /// Check if we are blocked (max_id is 0 or next_id >= max_id).
    pub fn is_blocked(&self) -> bool {
        self.max_id == 0 || self.next_id >= self.max_id
    }

    /// Get the current maximum subscribe ID.
    pub fn max_id(&self) -> u64 {
        self.max_id
    }
}

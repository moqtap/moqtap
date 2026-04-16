use moqtap_codec::varint::VarInt;

/// Errors from request ID allocation or validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestIdError {
    /// The request ID exceeds the current MAX_REQUEST_ID.
    #[error("request ID {0} exceeds max {1}")]
    ExceedsMax(u64, u64),
    /// MAX_REQUEST_ID must only increase; it decreased.
    #[error("max request ID can only increase: was {0}, got {1}")]
    Decreased(u64, u64),
    /// No request IDs are available (max is 0 or exhausted).
    #[error("no request IDs available (blocked)")]
    Blocked,
}

/// Allocates and validates request IDs per the MoQT draft-12 spec.
///
/// Draft-12 uses the same monotonic allocation rules as draft-11. The
/// subscriber allocates IDs monotonically starting at 0; SUBSCRIBE, FETCH,
/// PUBLISH, ANNOUNCE, etc. all share the same namespace since each carries a
/// `request_id` field.
pub struct RequestIdAllocator {
    next_id: u64,
    max_id: u64,
}

impl Default for RequestIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestIdAllocator {
    /// Create a new allocator starting at request_id 0 with max_id = 0
    /// (blocked until the peer sends MAX_REQUEST_ID).
    pub fn new() -> Self {
        Self { next_id: 0, max_id: 0 }
    }

    /// Allocate the next request ID.
    pub fn allocate(&mut self) -> Result<VarInt, RequestIdError> {
        if self.max_id == 0 || self.next_id >= self.max_id {
            return Err(RequestIdError::Blocked);
        }
        let id = VarInt::from_u64(self.next_id).unwrap();
        self.next_id += 1;
        Ok(id)
    }

    /// Update the maximum allowed request ID (can only increase).
    pub fn update_max(&mut self, new_max: u64) -> Result<(), RequestIdError> {
        if new_max <= self.max_id {
            return Err(RequestIdError::Decreased(self.max_id, new_max));
        }
        self.max_id = new_max;
        Ok(())
    }

    /// Validate a request ID received from the peer.
    pub fn validate_peer_id(&self, id: u64) -> Result<(), RequestIdError> {
        if id >= self.max_id {
            return Err(RequestIdError::ExceedsMax(id, self.max_id));
        }
        Ok(())
    }

    /// Check if we are blocked (max_id is 0 or next_id >= max_id).
    pub fn is_blocked(&self) -> bool {
        self.max_id == 0 || self.next_id >= self.max_id
    }

    /// Get the current maximum request ID.
    pub fn max_id(&self) -> u64 {
        self.max_id
    }
}

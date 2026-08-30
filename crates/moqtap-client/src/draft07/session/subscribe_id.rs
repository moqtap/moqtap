use moqtap_codec::varint::VarInt;

/// Errors from subscribe ID allocation or validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscribeIdError {
    /// The subscribe ID reaches or exceeds the Maximum Subscribe ID in force.
    #[error("subscribe ID {0} exceeds max {1}")]
    ExceedsMax(u64, u64),
    /// MAX_SUBSCRIBE_ID must only increase; it did not.
    #[error("max subscribe ID can only increase: was {0}, got {1}")]
    Decreased(u64, u64),
    /// No subscribe IDs are available under the ceiling in force.
    #[error("no subscribe IDs available (blocked)")]
    Blocked,
}

/// Allocates the Subscribe IDs this endpoint sends.
///
/// Section 6.4 defines the field: "Subscribe ID is a variable length
/// integer that MUST be unique and monotonically increasing within a session and
/// MUST be less than the session's Maximum Subscribe ID." SUBSCRIBE and FETCH
/// draw from the same sequence, so one allocator serves both.
///
/// This draft states no parity rule - the client's and the server's ids are not
/// separated by their least significant bit, as they are from draft-11 on - so
/// the sequence simply starts at 0 and steps by one.
///
/// The ceiling is exclusive. Section 6.20 gives the Maximum Subscribe ID a
/// starting value of 0 and reads that as "the peer MUST NOT create
/// subscriptions", which holds only if a ceiling of 0 forbids the id 0 as well.
///
/// The ceiling here is the one the **peer** granted this endpoint. The ceiling
/// a peer's ids are measured against is the one this endpoint advertised, which
/// is a different number and lives on the endpoint rather than here.
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
    /// Create an allocator starting at subscribe ID 0, blocked until a peer
    /// raises the maximum.
    pub fn new() -> Self {
        Self { next_id: 0, max_id: 0 }
    }

    /// Allocate the next Subscribe ID.
    ///
    /// # Errors
    ///
    /// [`SubscribeIdError::Blocked`] if the next id would reach the ceiling.
    pub fn allocate(&mut self) -> Result<VarInt, SubscribeIdError> {
        if self.is_blocked() {
            return Err(SubscribeIdError::Blocked);
        }
        let id = VarInt::from_u64(self.next_id).unwrap();
        self.next_id += 1;
        Ok(id)
    }

    /// Raise the maximum Subscribe ID this endpoint may use.
    ///
    /// Section 6.20: "The Maximum Subscribe ID MUST only increase within a
    /// session, and receipt of a MAX_SUBSCRIBE_ID message with an equal or
    /// smaller Subscribe ID value is a 'Protocol Violation'."
    ///
    /// # Errors
    ///
    /// [`SubscribeIdError::Decreased`] if the value does not strictly increase.
    pub fn update_max(&mut self, new_max: u64) -> Result<(), SubscribeIdError> {
        if new_max <= self.max_id {
            return Err(SubscribeIdError::Decreased(self.max_id, new_max));
        }
        self.max_id = new_max;
        Ok(())
    }

    /// Whether the next allocation would reach the ceiling.
    pub fn is_blocked(&self) -> bool {
        self.next_id >= self.max_id
    }

    /// The maximum Subscribe ID the peer has granted this endpoint.
    pub fn max_id(&self) -> u64 {
        self.max_id
    }
}

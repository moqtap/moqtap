use moqtap_codec::varint::VarInt;

/// Role of the endpoint (determines request ID parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client uses even request IDs: 0, 2, 4, ...
    Client,
    /// Server uses odd request IDs: 1, 3, 5, ...
    Server,
}

/// Errors from request ID allocation or validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestIdError {
    /// The request ID exceeds the current MAX_REQUEST_ID.
    #[error("request ID {0} exceeds max {1}")]
    ExceedsMax(u64, u64),
    /// The request ID has the wrong parity for the given role.
    #[error("request ID {0} has wrong parity for {1:?}")]
    WrongParity(u64, Role),
    /// MAX_REQUEST_ID must only increase; it decreased.
    #[error("max request ID can only increase: was {0}, got {1}")]
    Decreased(u64, u64),
    /// No request IDs are available (max is 0 or exhausted).
    #[error("no request IDs available (blocked)")]
    Blocked,
}

/// Allocates and validates request IDs per the MoQT spec.
///
/// - Client: even IDs (0, 2, 4, ...)
/// - Server: odd IDs (1, 3, 5, ...)
/// - Default MAX_REQUEST_ID: 0 (no requests until increased)
/// - MAX_REQUEST_ID can only increase
pub struct RequestIdAllocator {
    role: Role,
    next_id: u64,
    max_id: u64,
}

impl RequestIdAllocator {
    /// Create a new allocator for the given role, starting at ID 0 or 1.
    pub fn new(role: Role) -> Self {
        let next_id = match role {
            Role::Client => 0,
            Role::Server => 1,
        };
        Self { role, next_id, max_id: 0 }
    }

    /// Allocate the next request ID.
    pub fn allocate(&mut self) -> Result<VarInt, RequestIdError> {
        if self.max_id == 0 || self.next_id > self.max_id {
            return Err(RequestIdError::Blocked);
        }
        let id = VarInt::from_u64(self.next_id).unwrap();
        self.next_id += 2;
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
        // Peer has opposite parity
        let expected_even = match self.role {
            Role::Client => false, // peer is Server, expects odd
            Role::Server => true,  // peer is Client, expects even
        };
        let is_even = id % 2 == 0;
        if is_even != expected_even {
            let peer_role = match self.role {
                Role::Client => Role::Server,
                Role::Server => Role::Client,
            };
            return Err(RequestIdError::WrongParity(id, peer_role));
        }
        if id > self.max_id {
            return Err(RequestIdError::ExceedsMax(id, self.max_id));
        }
        Ok(())
    }

    /// Check if we are blocked (max_id is 0 or next_id > max_id).
    pub fn is_blocked(&self) -> bool {
        self.max_id == 0 || self.next_id > self.max_id
    }

    /// Get the current maximum request ID.
    pub fn max_id(&self) -> u64 {
        self.max_id
    }
}

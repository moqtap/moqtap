use moqtap_codec::varint::VarInt;

/// Which end of the session this endpoint is, which fixes the parity of the
/// request IDs it may allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client: even request IDs, 0, 2, 4, ...
    Client,
    /// Server: odd request IDs, 1, 3, 5, ...
    Server,
}

/// Errors from request ID allocation or validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestIdError {
    /// The request ID is not below the current MAX_REQUEST_ID.
    #[error("request ID {0} exceeds max {1}")]
    ExceedsMax(u64, u64),
    /// The request ID has the wrong parity for the endpoint that sent it.
    #[error("request ID {0} has wrong parity for {1:?}")]
    WrongParity(u64, Role),
    /// MAX_REQUEST_ID must only increase; it decreased.
    #[error("max request ID can only increase: was {0}, got {1}")]
    Decreased(u64, u64),
    /// No request IDs are available (max is 0 or exhausted).
    #[error("no request IDs available (blocked)")]
    Blocked,
    /// A new request carried an ID other than the next one in the peer's own
    /// sequence.
    #[error("request ID {got} is not the peer's next in sequence, which is {expected}")]
    OutOfSequence {
        /// The ID the request carried.
        got: u64,
        /// The ID the peer's next new request had to carry.
        expected: u64,
    },
}

/// Allocates this endpoint's request IDs and checks the parity of the peer's.
///
/// Draft-13 Section 8.1: "The client's Request ID starts at 0 and are even and
/// the server's Request ID starts at 1 and are odd. The Request ID increments
/// by 2 with ANNOUNCE, FETCH, SUBSCRIBE, SUBSCRIBE_NAMESPACE or TRACK_STATUS
/// request." The step of two is what keeps the two endpoints' ID spaces
/// disjoint, so it is not a spacing convention an implementation may tighten:
/// one that steps by one starts issuing the IDs reserved for its peer on its
/// second request, and the same section makes that a session close with
/// Invalid Request ID.
///
/// The ceiling is exclusive. Section 8.5 describes the MAX_REQUEST_ID
/// message's Request ID field as "The new Maximum Request ID for the session
/// plus one", and closes the session with 'Too Many Requests' on a request ID
/// "equal or larger than this". Section 8.3.2.2 gives the setup parameter of
/// the same name a default of 0 and reads that as "the peer MUST NOT send
/// requests", which only holds if a ceiling of 0 forbids the ID 0 as well.
pub struct RequestIdAllocator {
    role: Role,
    next_id: u64,
    max_id: u64,
    peer_next_id: u64,
}

impl RequestIdAllocator {
    /// Create an allocator for the given role, starting at ID 0 or 1 with a
    /// ceiling of 0 - blocked until the peer raises it.
    pub fn new(role: Role) -> Self {
        let next_id = match role {
            Role::Client => 0,
            Role::Server => 1,
        };
        // The peer's sequence is the other half of the space, and starts at
        // the other end for the same reason this one does.
        let peer_next_id = match role {
            Role::Client => 1,
            Role::Server => 0,
        };
        Self { role, next_id, max_id: 0, peer_next_id }
    }

    /// The role this allocator allocates for.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Allocate the next request ID.
    ///
    /// # Errors
    ///
    /// [`RequestIdError::Blocked`] when the next ID would reach the ceiling.
    pub fn allocate(&mut self) -> Result<VarInt, RequestIdError> {
        if self.is_blocked() {
            return Err(RequestIdError::Blocked);
        }
        let id = VarInt::from_u64(self.next_id).unwrap();
        self.next_id += 2;
        Ok(id)
    }

    /// Update the maximum allowed request ID (can only increase).
    ///
    /// # Errors
    ///
    /// [`RequestIdError::Decreased`] if the new value is not strictly greater
    /// than the current one, which Section 8.5 calls a protocol
    /// violation.
    pub fn update_max(&mut self, new_max: u64) -> Result<(), RequestIdError> {
        if new_max <= self.max_id {
            return Err(RequestIdError::Decreased(self.max_id, new_max));
        }
        self.max_id = new_max;
        Ok(())
    }

    /// Check the parity of a request ID the peer put on the wire.
    ///
    /// The parity checked here is the **peer's**, the opposite of this
    /// allocator's own, so a client accepts only odd IDs.
    ///
    /// This deliberately does not check the ID against a ceiling. The ceiling
    /// that applies to a peer's request ID is the MAX_REQUEST_ID *this*
    /// endpoint advertised, which the allocator does not hold - `max_id` here
    /// is the budget the peer granted us, a different number that may be
    /// larger or smaller. The endpoint owns that check.
    ///
    /// # Errors
    ///
    /// [`RequestIdError::WrongParity`] carrying the ID and the **peer's**
    /// role, so the message names the endpoint that broke the rule rather than
    /// the one that caught it.
    pub fn validate_peer_id(&self, id: u64) -> Result<(), RequestIdError> {
        let peer_role = match self.role {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        };
        let peer_sends_even = peer_role == Role::Client;
        if id.is_multiple_of(2) != peer_sends_even {
            return Err(RequestIdError::WrongParity(id, peer_role));
        }
        Ok(())
    }

    /// Whether the next allocation would reach the ceiling.
    ///
    /// A ceiling of 0 needs no special case: the client's first ID is 0 and
    /// the server's is 1, and neither is below 0.
    pub fn is_blocked(&self) -> bool {
        self.next_id >= self.max_id
    }

    /// The Request ID the peer's next **new** request must carry.
    ///
    /// Section 8.1 starts each endpoint's sequence at 0 or 1 by role and
    /// steps it by 2 per request, so the whole sequence is fixed from the
    /// outset and the next value is a number rather than a guess.
    pub fn peer_next_id(&self) -> u64 {
        self.peer_next_id
    }

    /// Take the Request ID of a new request the peer sent, holding it to the
    /// sequence Section 8.1 fixes.
    ///
    /// "If an endpoint receives a Request ID that is not valid for the peer,
    /// or a new request with a Request ID that is not expected, it MUST
    /// close the session with Invalid Request ID."
    ///
    /// One counter answers both halves of that. A repeat is below the next
    /// value and a skip is above it, and neither is the value the peer's own
    /// step of two produces, so nothing further has to be remembered: the set
    /// of IDs already spent is every value of this parity below the counter.
    ///
    /// Only a **new** request advances this. A message that names a request
    /// already open - a response, a cancellation, an update that carries the
    /// original's ID rather than one of its own - reuses an ID on purpose, and
    /// passing one here would refuse it.
    ///
    /// # Errors
    ///
    /// [`RequestIdError::OutOfSequence`] carrying the ID that arrived and the
    /// one the sequence called for.
    pub fn record_peer_id(&mut self, id: u64) -> Result<(), RequestIdError> {
        if id != self.peer_next_id {
            return Err(RequestIdError::OutOfSequence { got: id, expected: self.peer_next_id });
        }
        self.peer_next_id += 2;
        Ok(())
    }

    /// Get the current maximum request ID.
    pub fn max_id(&self) -> u64 {
        self.max_id
    }
}

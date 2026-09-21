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
        // Draft-17 removed MAX_REQUEST_ID and draft-21 keeps it gone;
        // allocator is never blocked.
        Self { role, next_id, max_id: u64::MAX }
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

    /// Validate a request ID the peer put on the wire.
    ///
    /// Draft-21 Section 6.4.2.1: "The client generates even numbered Request IDs,
    /// starting at 0, and the server generates odd numbered Request IDs,
    /// starting at 1." The parity checked here is therefore the **peer's**,
    /// the opposite of this allocator's own — a client validates odd ids.
    ///
    /// The same section makes a wrong bit fatal to the session: "If an
    /// endpoint receives a Request ID where the least significant bit is
    /// incorrect for the sender, or a duplicate Request ID, it MUST close the
    /// session with INVALID_REQUEST_ID." Only the first half is answered here.
    /// Duplicate detection needs memory of every id the peer has already
    /// spent, which this allocator does not keep and cannot keep without
    /// taking `&mut self`; it lives on the endpoint instead.
    ///
    /// The parity rule is also what makes one `HashMap` per request kind
    /// enough for both directions: an id this endpoint allocates and an id the
    /// peer allocates can never be equal, so a peer's request cannot collide
    /// with one of ours.
    ///
    /// # Errors
    ///
    /// - [`RequestIdError::WrongParity`] carrying the id and the **peer's**
    ///   role, so the message names the endpoint that broke the rule rather
    ///   than the one that caught it.
    /// - [`RequestIdError::ExceedsMax`] if the id is past the current
    ///   MAX_REQUEST_ID. Draft-17 removed MAX_REQUEST_ID and draft-21 keeps it
    ///   gone, and [`RequestIdAllocator::new`] sets the ceiling to `u64::MAX`,
    ///   so on this draft the check cannot fire for any id a varint can carry.
    pub fn validate_peer_id(&self, id: u64) -> Result<(), RequestIdError> {
        // Peer has opposite parity
        let expected_even = match self.role {
            Role::Client => false, // peer is Server, expects odd
            Role::Server => true,  // peer is Client, expects even
        };
        let is_even = id.is_multiple_of(2);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A client allocates the even ids and must accept only odd ones from the
    /// peer; a server is the mirror. The two are checked together against the
    /// ids each allocator actually hands out, so a parity that is inverted in
    /// both places at once — which would let a client talk to itself — still
    /// fails.
    ///
    /// Inverting `expected_even` in `validate_peer_id` fails with:
    ///
    /// ```text
    /// a Client refused 1, which a Server allocates
    /// ```
    #[test]
    fn each_role_accepts_only_the_ids_the_other_role_allocates() {
        for (role, peer_role) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
            let mut allocator = RequestIdAllocator::new(role);
            let mut peer = RequestIdAllocator::new(peer_role);
            for _ in 0..4 {
                let peer_id = peer.allocate().unwrap().into_inner();
                assert!(
                    allocator.validate_peer_id(peer_id).is_ok(),
                    "a {role:?} refused {peer_id}, which a {peer_role:?} allocates",
                );
                let own_id = allocator.allocate().unwrap().into_inner();
                assert_eq!(
                    allocator.validate_peer_id(own_id),
                    Err(RequestIdError::WrongParity(own_id, peer_role)),
                    "a {role:?} accepted {own_id} from the peer, an id it allocates itself",
                );
            }
        }
    }

    /// The error names the peer, not the endpoint that caught it. Draft-21
    /// Section 6.4.2.1 makes this a session close, so the reason phrase a peer
    /// reads has to say whose bit was wrong.
    #[test]
    fn wrong_parity_names_the_peer_that_sent_the_id() {
        let client = RequestIdAllocator::new(Role::Client);
        let err = client.validate_peer_id(4).unwrap_err();
        assert_eq!(err.to_string(), "request ID 4 has wrong parity for Server");

        let server = RequestIdAllocator::new(Role::Server);
        let err = server.validate_peer_id(7).unwrap_err();
        assert_eq!(err.to_string(), "request ID 7 has wrong parity for Client");
    }

    /// Draft-17 removed MAX_REQUEST_ID and draft-21 has not brought it back,
    /// so the ceiling check in `validate_peer_id` is unreachable on this
    /// draft: the largest id a MoQT varint can carry is still accepted.
    #[test]
    fn no_ceiling_rejects_a_peer_id_on_this_draft() {
        let client = RequestIdAllocator::new(Role::Client);
        let largest_odd = moqtap_codec::varint::MAX_MOQT_VARINT | 1;
        assert_eq!(client.validate_peer_id(largest_odd), Ok(()));
    }
}

use std::collections::BTreeSet;

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
    /// A new request carried an ID the peer has already used.
    #[error("request ID {0} was already used by the peer")]
    Duplicate(u64),
}

/// How many skipped peer IDs are remembered as still unused. A skipped ID that
/// falls out of this window is treated as used.
const MAX_SKIPPED_PEER_IDS: usize = 1024;

/// Allocates this endpoint's request IDs and checks the parity of the peer's.
///
/// Draft-16 Section 9.1: "The client's Request ID starts at 0 and are even and
/// the server's Request ID starts at 1 and are odd. The Request ID increments
/// by 2 with each FETCH, SUBSCRIBE, REQUEST_UPDATE, SUBSCRIBE_NAMESPACE,
/// PUBLISH, PUBLISH_NAMESPACE or TRACK_STATUS request." The step of two is
/// what keeps the two endpoints' ID spaces disjoint, so it is not a spacing
/// convention an implementation may tighten: one that steps by one starts
/// issuing the IDs reserved for its peer on its second request, and the same
/// section makes that a session close with INVALID_REQUEST_ID.
///
/// The ceiling is exclusive. Section 9.5 describes the MAX_REQUEST_ID
/// message's Max Request ID field as "The new Maximum Request ID for the
/// session plus 1", and closes the session with TOO_MANY_REQUESTS on a request
/// ID "equal to or larger than this". Section 9.3.1.3 gives the setup
/// parameter of the same name a default of 0 and reads that as "the peer MUST
/// NOT send requests", which only holds if a ceiling of 0 forbids the ID 0 as
/// well.
pub struct RequestIdAllocator {
    role: Role,
    next_id: u64,
    max_id: u64,
    peer_next_id: u64,
    peer_skipped: BTreeSet<u64>,
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
        Self { role, next_id, max_id: 0, peer_next_id, peer_skipped: BTreeSet::new() }
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
    /// than the current one, which Section 9.5 calls a protocol
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
    /// Parity is the half that needs no history. The duplicate half is
    /// [`Self::record_peer_id`], which does.
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

    /// The ID after the highest one the peer has used: its first ID until it
    /// sends a request, then the highest seen plus 2.
    pub fn peer_next_id(&self) -> u64 {
        self.peer_next_id
    }

    /// Take the Request ID of a new request the peer sent, refusing one it has
    /// already used.
    ///
    /// The sequence is not enforced. Draft-16 opens SUBSCRIBE_NAMESPACE on its
    /// own stream, so requests can arrive out of order across streams; the
    /// editors' guidance for draft-16 (moq-wg/moq-transport#1459) is to check
    /// parity, the ceiling and duplicates only. IDs jumped over are remembered
    /// as unused, up to a fixed number of the highest.
    ///
    /// Only a **new** request is passed here. A message that names a request
    /// already open reuses its ID on purpose.
    ///
    /// # Errors
    ///
    /// [`RequestIdError::WrongParity`] for an ID from this endpoint's half,
    /// [`RequestIdError::Duplicate`] for one already used or no longer
    /// remembered as skipped.
    pub fn record_peer_id(&mut self, id: u64) -> Result<(), RequestIdError> {
        self.validate_peer_id(id)?;
        if id < self.peer_next_id {
            return if self.peer_skipped.remove(&id) {
                Ok(())
            } else {
                Err(RequestIdError::Duplicate(id))
            };
        }
        let window = 2 * MAX_SKIPPED_PEER_IDS as u64;
        let mut skipped = id.saturating_sub(window).max(self.peer_next_id);
        while skipped < id {
            self.peer_skipped.insert(skipped);
            skipped += 2;
        }
        while self.peer_skipped.len() > MAX_SKIPPED_PEER_IDS {
            self.peer_skipped.pop_first();
        }
        self.peer_next_id = id.saturating_add(2);
        Ok(())
    }

    /// Get the current maximum request ID.
    pub fn max_id(&self) -> u64 {
        self.max_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_skip_past_the_window_forgets_the_oldest_skipped_ids() {
        let mut ids = RequestIdAllocator::new(Role::Server);
        let far = 2 * (MAX_SKIPPED_PEER_IDS as u64 + 10);
        ids.record_peer_id(far).unwrap();
        assert_eq!(ids.peer_skipped.len(), MAX_SKIPPED_PEER_IDS);
        assert_eq!(ids.record_peer_id(0), Err(RequestIdError::Duplicate(0)));
        ids.record_peer_id(far - 2).unwrap();
        assert_eq!(ids.peer_next_id(), far + 2);
    }
}

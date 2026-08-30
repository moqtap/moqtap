#![cfg(feature = "draft14")]

use moqtap_client::draft14::session::request_id::*;

// ============================================================
// Allocation
// ============================================================

/// Draft-14 Section 9.1: a client's request IDs are even - 0, 2, 4, ...
#[test]
fn client_allocates_even_ids() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();

    let id0 = alloc.allocate().expect("allocate 0");
    let id2 = alloc.allocate().expect("allocate 2");
    let id4 = alloc.allocate().expect("allocate 4");

    assert_eq!(id0.into_inner(), 0);
    assert_eq!(id2.into_inner(), 2);
    assert_eq!(id4.into_inner(), 4);
}

/// Draft-14 Section 9.1: a server's request IDs are odd - 1, 3, 5, ...
#[test]
fn server_allocates_odd_ids() {
    let mut alloc = RequestIdAllocator::new(Role::Server);
    alloc.update_max(10).unwrap();

    let id1 = alloc.allocate().expect("allocate 1");
    let id3 = alloc.allocate().expect("allocate 3");
    let id5 = alloc.allocate().expect("allocate 5");

    assert_eq!(id1.into_inner(), 1);
    assert_eq!(id3.into_inner(), 3);
    assert_eq!(id5.into_inner(), 5);
}

/// Draft-14 Section 9.5 describes the MAX_REQUEST_ID field as "The new Maximum
/// Request ID for the session plus 1" and closes the session with
/// TOO_MANY_REQUESTS on a request ID "equal to or larger than this". So a
/// ceiling of 4 leaves a client the two IDs 0 and 2, and 4 is the first it may
/// not send.
#[test]
fn allocate_respects_max_request_id() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(4).unwrap();

    alloc.allocate().expect("allocate 0");
    alloc.allocate().expect("allocate 2");

    let result = alloc.allocate();
    assert!(result.is_err(), "4 is the ceiling itself and may not be allocated");
}

/// Draft-14 Section 9.3.2.3: the ceiling defaults to 0, and "if not specified,
/// the peer MUST NOT send requests".
#[test]
fn allocate_blocked_when_default_max_is_zero() {
    let alloc = &mut RequestIdAllocator::new(Role::Client);
    // Default max is 0; per spec, max_request_id=0 means no requests allowed.
    let result = alloc.allocate();
    assert!(result.is_err(), "allocation should be blocked when max is 0 (default)");
}

/// Draft-14 Section 9.5: allocation resumes once the ceiling rises.
#[test]
fn allocate_unblocked_after_max_increase() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    // Default max is 0, so blocked.
    assert!(alloc.is_blocked(), "should be blocked at default max");

    alloc.update_max(2).unwrap();
    assert!(!alloc.is_blocked(), "should be unblocked after max increase");

    let id = alloc.allocate().expect("should allocate after unblock");
    assert_eq!(id.into_inner(), 0);
}

// ============================================================
// Max updates
// ============================================================

/// Draft-14 Section 9.5: the ceiling may rise.
#[test]
fn max_request_id_can_increase() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    let result = alloc.update_max(10);
    assert!(result.is_ok(), "increasing max should succeed");
    assert_eq!(alloc.max_id(), 10);
}

/// Draft-14 Section 9.5: "The Maximum Request ID MUST only increase within a
/// session", and a smaller value is a PROTOCOL_VIOLATION.
#[test]
fn max_request_id_cannot_decrease() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();

    let result = alloc.update_max(5);
    assert!(result.is_err(), "decreasing max should fail");
    match result.unwrap_err() {
        RequestIdError::Decreased(was, got) => {
            assert_eq!(was, 10);
            assert_eq!(got, 5);
        }
        other => panic!("expected Decreased error, got: {other:?}"),
    }
}

/// Draft-14 Section 9.5: an equal value is a PROTOCOL_VIOLATION too - the rule
/// is a strict increase.
#[test]
fn max_request_id_cannot_stay_same() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();

    let result = alloc.update_max(10);
    assert!(result.is_err(), "setting max to equal value should fail (must strictly increase)");
    match result.unwrap_err() {
        RequestIdError::Decreased(was, got) => {
            assert_eq!(was, 10);
            assert_eq!(got, 10);
        }
        other => panic!("expected Decreased error, got: {other:?}"),
    }
}

/// Draft-14 Section 9.3.2.3: the ceiling starts at 0.
#[test]
fn max_request_id_default_is_zero() {
    let alloc = RequestIdAllocator::new(Role::Server);
    assert_eq!(alloc.max_id(), 0);
}

// ============================================================
// Parity validation
// ============================================================

/// Draft-14 Section 9.1: a client accepts only the odd IDs a server allocates.
#[test]
fn client_validates_peer_sends_odd() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();
    // Client expects peer (server) IDs to be odd.
    let result = alloc.validate_peer_id(1);
    assert!(result.is_ok(), "client should accept odd peer id: {result:?}");
}

/// Draft-14 Section 9.1: a request ID "not valid for the peer" is an
/// INVALID_REQUEST_ID session close. A client refuses even peer IDs.
#[test]
fn client_rejects_peer_even_id() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();
    // Client's peer is server, which should send odd IDs. Even ID is wrong parity.
    let result = alloc.validate_peer_id(2);
    assert!(result.is_err(), "client should reject even peer id");
    match result.unwrap_err() {
        RequestIdError::WrongParity(id, _role) => {
            assert_eq!(id, 2);
        }
        other => panic!("expected WrongParity error, got: {other:?}"),
    }
}

/// Draft-14 Section 9.1: the mirror - a server refuses odd peer IDs.
#[test]
fn server_rejects_peer_odd_id() {
    let mut alloc = RequestIdAllocator::new(Role::Server);
    alloc.update_max(10).unwrap();
    // Server's peer is client, which should send even IDs. Odd ID is wrong parity.
    let result = alloc.validate_peer_id(1);
    assert!(result.is_err(), "server should reject odd peer id");
    match result.unwrap_err() {
        RequestIdError::WrongParity(id, _role) => {
            assert_eq!(id, 1);
        }
        other => panic!("expected WrongParity error, got: {other:?}"),
    }
}

/// The allocator's own ceiling is the budget the *peer* granted *us*, and it
/// says nothing about what the peer may send. The ceiling that binds a peer's
/// request ID is the MAX_REQUEST_ID this endpoint advertised, a different
/// number, so this check is deliberately parity-only and the endpoint owns the
/// other half.
#[test]
fn the_allocators_own_ceiling_does_not_bind_the_peer() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();
    assert_eq!(
        alloc.validate_peer_id(101),
        Ok(()),
        "101 is odd, so it is a server's to allocate, whatever budget we were given",
    );
}

/// Draft-14 Section 9.1: a server accepts only the even IDs a client allocates.
#[test]
fn server_validates_peer_sends_even() {
    let mut alloc = RequestIdAllocator::new(Role::Server);
    alloc.update_max(10).unwrap();
    // Server expects peer (client) IDs to be even.
    let result = alloc.validate_peer_id(2);
    assert!(result.is_ok(), "server should accept even peer id: {result:?}");
}

/// Draft-14 Section 9.6: REQUESTS_BLOCKED is for when an endpoint wants an ID
/// and the ceiling has none left.
#[test]
fn is_blocked_reflects_capacity() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    // Default max is 0, client first ID would be 0, but max=0 means blocked.
    assert!(alloc.is_blocked(), "should be blocked at default max=0");

    alloc.update_max(0).ok(); // May fail since equal, that's fine
                              // Still blocked since max hasn't increased
    assert!(alloc.is_blocked(), "should still be blocked");

    alloc.update_max(4).unwrap();
    assert!(!alloc.is_blocked(), "should be unblocked after max increase to 4");

    // A ceiling of 4 covers 0 and 2; 4 itself is out of reach.
    alloc.allocate().unwrap(); // 0
    alloc.allocate().unwrap(); // 2
    assert!(alloc.is_blocked(), "should be blocked once the ceiling is reached");
}

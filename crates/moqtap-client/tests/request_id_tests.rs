#![cfg(feature = "draft14")]

use moqtap_client::draft14::session::request_id::*;

// ============================================================
// Allocation
// ============================================================

/// draft-14 section 6.3: Client request IDs are even (0, 2, 4, ...).
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

/// draft-14 section 6.3: Server request IDs are odd (1, 3, 5, ...).
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

/// draft-14 section 6.3: Request ID exceeding MAX_REQUEST_ID results in
/// TOO_MANY_REQUESTS (session error 0x7).
#[test]
fn allocate_respects_max_request_id() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(4).unwrap();

    // Client IDs: 0, 2, 4
    alloc.allocate().expect("allocate 0");
    alloc.allocate().expect("allocate 2");
    alloc.allocate().expect("allocate 4");

    // Next would be 6, which exceeds max of 4.
    let result = alloc.allocate();
    assert!(result.is_err(), "allocation beyond max should be blocked");
}

/// draft-14 section 6.3: Default MAX_REQUEST_ID is 0 (no requests allowed until increased).
#[test]
fn allocate_blocked_when_default_max_is_zero() {
    let alloc = &mut RequestIdAllocator::new(Role::Client);
    // Default max is 0; per spec, max_request_id=0 means no requests allowed.
    let result = alloc.allocate();
    assert!(result.is_err(), "allocation should be blocked when max is 0 (default)");
}

/// draft-14 section 6.3: Allocation unblocked after MAX_REQUEST_ID increase.
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

/// draft-14 section 6.3: MAX_REQUEST_ID can increase.
#[test]
fn max_request_id_can_increase() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    let result = alloc.update_max(10);
    assert!(result.is_ok(), "increasing max should succeed");
    assert_eq!(alloc.max_id(), 10);
}

/// draft-14 section 6.3: MAX_REQUEST_ID can only increase; smaller value = PROTOCOL_VIOLATION.
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

/// draft-14 section 6.3: MAX_REQUEST_ID can only increase; equal value = PROTOCOL_VIOLATION.
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

/// draft-14 section 6.3: Default MAX_REQUEST_ID is 0.
#[test]
fn max_request_id_default_is_zero() {
    let alloc = RequestIdAllocator::new(Role::Server);
    assert_eq!(alloc.max_id(), 0);
}

// ============================================================
// Parity validation
// ============================================================

/// draft-14 section 6.3: Client validates that peer (server) sends odd IDs.
#[test]
fn client_validates_peer_sends_odd() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();
    // Client expects peer (server) IDs to be odd.
    let result = alloc.validate_peer_id(1);
    assert!(result.is_ok(), "client should accept odd peer id: {result:?}");
}

/// draft-14 section 6.3: Receiving request ID with wrong parity = INVALID_REQUEST_ID
/// (session error 0x4). Client rejects even peer IDs.
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

/// draft-14 section 6.3: Receiving request ID with wrong parity = INVALID_REQUEST_ID
/// (session error 0x4). Server rejects odd peer IDs.
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

/// draft-14 section 6.3: Request ID exceeding MAX = TOO_MANY_REQUESTS (session error 0x7).
/// Use an odd ID (correct parity for server peer) that exceeds max.
#[test]
fn validate_peer_id_exceeds_max() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    alloc.update_max(10).unwrap();
    // Peer id 101 is odd (correct parity for server peer) but exceeds max of 10.
    let result = alloc.validate_peer_id(101);
    assert!(result.is_err(), "peer id exceeding max should fail");
    match result.unwrap_err() {
        RequestIdError::ExceedsMax(id, max) => {
            assert_eq!(id, 101);
            assert_eq!(max, 10);
        }
        other => panic!("expected ExceedsMax error, got: {other:?}"),
    }
}

/// draft-14 section 6.3: Server validates that peer (client) sends even IDs.
#[test]
fn server_validates_peer_sends_even() {
    let mut alloc = RequestIdAllocator::new(Role::Server);
    alloc.update_max(10).unwrap();
    // Server expects peer (client) IDs to be even.
    let result = alloc.validate_peer_id(2);
    assert!(result.is_ok(), "server should accept even peer id: {result:?}");
}

/// draft-14 section 6.3: REQUESTS_BLOCKED sent when endpoint wants to send but is at max.
#[test]
fn is_blocked_reflects_capacity() {
    let mut alloc = RequestIdAllocator::new(Role::Client);
    // Default max is 0, client first ID would be 0, but max=0 means blocked.
    assert!(alloc.is_blocked(), "should be blocked at default max=0");

    alloc.update_max(0).ok(); // May fail since equal, that's fine
                              // Still blocked since max hasn't increased
    assert!(alloc.is_blocked(), "should still be blocked");

    alloc.update_max(2).unwrap();
    assert!(!alloc.is_blocked(), "should be unblocked after max increase to 2");

    // Allocate 0 and 2, then should be blocked again
    alloc.allocate().unwrap(); // 0
    alloc.allocate().unwrap(); // 2
    assert!(alloc.is_blocked(), "should be blocked after exhausting IDs up to max");
}

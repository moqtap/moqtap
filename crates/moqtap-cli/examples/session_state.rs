//! Example: Session state machine and request ID allocation.
//!
//! Run with: cargo run --example session_state

use moqtap_client::session::request_id::{RequestIdAllocator, Role};
use moqtap_client::session::state::SessionStateMachine;

fn main() {
    // Session lifecycle
    let mut session = SessionStateMachine::new();
    println!("Initial state: {:?}", session.state());

    session.on_connect().unwrap();
    println!("After connect: {:?}", session.state());

    session.on_setup_complete().unwrap();
    println!("After setup:   {:?}", session.state());

    session.on_goaway().unwrap();
    println!("After goaway:  {:?}", session.state());

    session.on_close().unwrap();
    println!("After close:   {:?}", session.state());

    println!();

    // Request ID allocation — client (even IDs)
    let mut client_ids = RequestIdAllocator::new(Role::Client);
    println!("Client is blocked (no MAX_REQUEST_ID yet): {}", client_ids.is_blocked());

    client_ids.update_max(10).unwrap();
    println!("After MAX_REQUEST_ID=10: blocked={}", client_ids.is_blocked());

    for _ in 0..6 {
        match client_ids.allocate() {
            Ok(id) => println!("  Allocated client request ID: {}", id.into_inner()),
            Err(e) => {
                println!("  Blocked: {e}");
                break;
            }
        }
    }

    println!();

    // Request ID allocation — server (odd IDs)
    let mut server_ids = RequestIdAllocator::new(Role::Server);
    server_ids.update_max(10).unwrap();

    for _ in 0..6 {
        match server_ids.allocate() {
            Ok(id) => println!("  Allocated server request ID: {}", id.into_inner()),
            Err(e) => {
                println!("  Blocked: {e}");
                break;
            }
        }
    }
}

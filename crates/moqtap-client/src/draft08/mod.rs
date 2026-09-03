//! MoQT client implementation for draft-08.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft08` feature.
//!
//! # Differences from draft-07
//!
//! * `SubscribesBlocked` (type 0x1A) is a new control message.
//! * `Subscribe` AbsoluteRange filter drops `end_object`; only `end_group`.
//! * `SubscribeUpdate` drops `end_object`.
//! * `SubscribeDone` is restructured: it now carries `stream_count` instead
//!   of the conditional `final_group` / `final_object` pair.
//! * `Fetch` has two modes (Standalone = 1, Joining = 2). Joining mode takes
//!   `joining_subscribe_id` + `preceding_group_offset`.
//! * `FetchOk` always includes `largest_group_id` and `largest_object_id`.
//! * Subgroup / datagram / fetch object headers carry `extension_count` +
//!   opaque extension bytes.
//! * New `DatagramStatus` stream type (0x02) for status-only datagrams.
//! * `ObjectStatus` value 5 changes meaning: draft-07 Section 7.1.1.1 assigns
//!   it "end of Subgroup", and draft-08 Section 7.1.1.1 reassigns it "end of
//!   Track" — Group ID one greater than the largest produced, Object ID zero.
//!   Value 4 is "end of Track and Group" in both drafts; what draft-08 adds
//!   there is the receiver's protocol-error check on the two ids.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
/// Unified endpoint state machine orchestrating all MoQT protocol flows.
pub mod endpoint;
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
/// Announce / SubscribeAnnounces state machines.
pub mod namespace;
pub mod observer;
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

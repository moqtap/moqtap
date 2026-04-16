//! MoQT client implementation for draft-12.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft12` feature.
//!
//! # Differences from draft-11
//!
//! Draft-12 is a small, targeted revision of draft-11. The visible shifts:
//!
//! - `track_alias` moves out of `Subscribe` and is instead returned by the
//!   publisher in `SubscribeOk`. The subscribe API no longer takes a
//!   client-chosen alias; the alias becomes available once SUBSCRIBE_OK
//!   arrives.
//! - `SubscribeError` loses its trailing `track_alias` field (there is no
//!   alias to echo since the client never sent one).
//! - New publisher-initiated messages: `Publish` (0x1D), `PublishOk` (0x1E),
//!   and `PublishError` (0x1F). A publisher can actively offer a track to
//!   the peer without waiting for a SUBSCRIBE; the peer responds with
//!   PUBLISH_OK (accepting with a filter/range) or PUBLISH_ERROR.
//! - Subgroup data-stream type ids shift from the 0x08–0x0D range to
//!   0x10–0x15. Datagram ids (0x00–0x03) and fetch ids (0x05) are unchanged.
//!   This is handled inside `AnySubgroupHeader::decode` when called with
//!   `DraftVersion::Draft12`.
//!
//! The version varint is `0xff000000 + 12`.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
/// Unified endpoint state machine orchestrating all MoQT protocol flows.
pub mod endpoint;
/// Client event types emitted via the observer.
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
/// Announce / SubscribeAnnounces state machines.
pub mod namespace;
/// Connection observer trait for receiving client events.
pub mod observer;
/// Session state, setup validation, and request ID allocation.
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

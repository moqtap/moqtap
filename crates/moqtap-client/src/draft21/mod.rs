//! MoQT client implementation for draft-21.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, publish, namespace,
//! track status). No code is shared across drafts — each draft carries its
//! own copy because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft21` feature.
//!
//! # What changed from draft-19, in the places a caller can feel it
//!
//! * **FETCH was rebuilt** (Section 9.11). The `Fetch Type` field, the
//!   Standalone and Joining Fetch structures and the whole joining mechanism
//!   are gone; the Track Namespace and Track Name are inline fields, and the
//!   range travels in the `LOCATION_FILTER` parameter. So
//!   [`Connection::fetch`](connection::Connection::fetch) takes a parameter
//!   list where draft-19's took four location varints, and
//!   `joining_fetch` / `absolute_joining_fetch` no longer exist. A fill fetch
//!   stream is what replaces them; see [`fill`].
//! * **`FILL_PARAMETERS` (0x23) is new** (Section 9.20.16). Its presence on a
//!   SUBSCRIBE or a REQUEST_UPDATE asks the publisher to open a fill fetch
//!   stream — a unidirectional stream beginning with a FETCH_HEADER that
//!   carries the *subscription's* Request ID. [`fill::FillParameters`] builds
//!   the parameter and
//!   [`Endpoint::fill_requested`](endpoint::Endpoint::fill_requested) is what
//!   tells an arriving FETCH_HEADER apart from a fetch's.
//! * **`PUBLISH_STATE_NOTIFY` (0x22) is new** (Section 9.10): a unilateral
//!   report from the publisher on a subscription's stream, answered with
//!   nothing and not counted against `MAX_REQUEST_UPDATES`. It arrives as
//!   [`ClientEvent::PublishStateNotify`](event::ClientEvent::PublishStateNotify).
//! * **Ranges are inclusive at both ends** (Sections 3.3.1, 9.11, 9.12).
//!   Draft-19's fetch end was "the last Object, plus 1; or 0 to indicate the
//!   entire Group"; both conventions are deleted, and nothing in this module
//!   carries the arithmetic forward.
//! * **`INCLUDE_PROPERTIES` (0x35) is new** (Section 9.20.22): a uint8 opt-out
//!   from Track Properties on the responding OK, default 1.
//! * Three code points went: `SUBSCRIPTION_ENDED` (PUBLISH_DONE 0x3),
//!   `VERSION_NEGOTIATION_FAILED` (session 0x15) and
//!   `INVALID_JOINING_REQUEST_ID` (REQUEST_ERROR 0x32).
//! * There is still **no version on the wire**. The negotiated draft is the
//!   ALPN, `moqt-21` on raw QUIC, exactly as on drafts 15 through 19.
//!
//! Draft-21 restructures draft-20 and changes none of it — same code points,
//! same fields, same rules — so the list above is what a caller feels on this
//! draft too. What draft-21 did change is the numbering, comprehensively:
//! every citation in this module is draft-21's own.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
pub mod endpoint;
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
pub mod fill;
/// Subscribe/Publish namespace state machines.
pub mod namespace;
pub mod observer;
/// Publish lifecycle state machine.
pub mod publish;
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

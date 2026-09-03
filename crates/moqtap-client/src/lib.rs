#![deny(missing_docs)]

//! MoQT client library.
//!
//! Provides a full MoQT client stack with per-draft modules. Each enabled
//! draft lives under its own module (e.g. [`draft14`]) containing its own
//! connection, endpoint state machine, and per-flow state machines.
//!
//! The [`transport`] module is shared across drafts because it sits below
//! the MoQT protocol layer (raw QUIC / WebTransport streams and datagrams).
//!
//! # Feature flags
//!
//! Enable a draft with `--features draft14` (or any of `draft07`..`draft20`).
//! The default is `all-drafts`, which enables every one; select individual
//! drafts with `default-features = false`. `webtransport` adds the
//! WebTransport transport.
//!
//! # Modules
//!
//! - [`dispatch`] — Multi-draft entry-point types (`AnyConnection`,
//!   `AnyClientEvent`, `AnyConnectionObserver`, `AnyRequest`)
//! - [`transport`] — Transport abstraction (QUIC, WebTransport)
//! - `forwarding_preference` — The Object Forwarding Preference each track's
//!   objects have been framed as, on the drafts where that is a property of
//!   the track
//! - `track_locations` — How far each track's objects have reached, on the
//!   drafts that make an end-of-track object's placement a protocol error
//! - `malformed_tracks` — Which tracks this endpoint has withdrawn from, on
//!   the drafts that answer a malformed one with control messages
//! - `draft07`..`draft20` — One module per supported MoQT draft, each
//!   enabled via the matching `draftNN` feature flag.

#[cfg(feature = "draft07")]
pub mod draft07;

#[cfg(feature = "draft08")]
pub mod draft08;

#[cfg(feature = "draft09")]
pub mod draft09;

#[cfg(feature = "draft10")]
pub mod draft10;

#[cfg(feature = "draft11")]
pub mod draft11;

#[cfg(feature = "draft12")]
pub mod draft12;

#[cfg(feature = "draft13")]
pub mod draft13;

#[cfg(feature = "draft14")]
pub mod draft14;

#[cfg(feature = "draft15")]
pub mod draft15;

#[cfg(feature = "draft16")]
pub mod draft16;

#[cfg(feature = "draft17")]
pub mod draft17;

#[cfg(feature = "draft18")]
pub mod draft18;

#[cfg(feature = "draft19")]
pub mod draft19;

#[cfg(feature = "draft20")]
pub mod draft20;

pub mod transport;

/// What a track's objects have been framed as, for the nine drafts that make
/// the Object Forwarding Preference a property of the track rather than of one
/// object. Shared across those drafts because the observation is identical on
/// all nine and only the answer to it differs.
#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15"
))]
pub mod forwarding_preference;

/// How far each track's objects have reached, and where each one ended.
///
/// **Two rules, and the drafts that state them are not the same set.** Drafts
/// 08 through 13 make an end-of-track object's Group and Object ID a protocol
/// error when they name a place the track has already passed, which takes a
/// record of where the track has reached; drafts 07 and 14 through 20 have no
/// such sentence, draft-07 having no ordering condition on the status at all
/// and draft-14 having replaced it with a prohibition on the publisher. Drafts
/// 12 through 20 make an object *past* where an end-of-track object put the end
/// a Malformed Track, which takes a record of that place instead.
///
/// So the module is compiled wherever either rule is, and which of its two
/// entry points a draft calls is what says which rule it states. The overlap is
/// drafts 12 and 13, where both hold.
#[cfg(any(
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
pub mod track_locations;

/// What a Malformed Track is, for the drafts whose answer to one is a control
/// message.
///
/// Drafts 12 and 13 Section 2.5 list the conditions that make a track
/// malformed and give all of them one answer: "When a subscriber detects a
/// Malformed Track, it MUST UNSUBSCRIBE from the Track and SHOULD deliver an
/// error to the application." Drafts 14, 15 and 16 widen the same sentence to
/// fetches — "it MUST UNSUBSCRIBE any subscription and FETCH_CANCEL any fetch
/// for that Track from that publisher" — which is a second message and the
/// same record. Drafts 17 through 20 replace both with a cancellation of the
/// request's own stream — a reset rather than a message — and the record is
/// compiled there too, because what it holds is *which track was given up and
/// what for*, which is the same question whichever shape the answer takes. It
/// is the conditions that vary by draft, not the record of them; the answer
/// lives on each draft's connection.
#[cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
pub mod malformed_tracks;

pub mod dispatch;

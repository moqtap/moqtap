//! The name a draft gives a control message type ID.
//!
//! A recorded trace stores a control message as a wire type ID and the draft it
//! was read under — `mt` and the header's `protocol: moq-transport-NN` in a
//! `.moqtrace` file. Both halves are needed to name it, because the ids are
//! reused rather than retired: 0x07 is ANNOUNCE_OK through draft-13,
//! PUBLISH_NAMESPACE_OK on draft-14 and REQUEST_OK from draft-15 on, and 0x0E
//! moves TRACK_STATUS → TRACK_STATUS_OK → NAMESPACE_DONE across the same range.
//! A table keyed on the id alone can only hedge — `SUBSCRIBE_DONE/PUBLISH_DONE`
//! — and the hedge holds exactly while a rename keeps the number, which is not
//! what happened to 0x07, 0x08, 0x0E or 0x11.
//!
//! So the lookup is per draft, and the per-draft half of it lives on each
//! draft's own `MessageType::name`. Nothing here derives one draft's names from
//! another's. [`message_type_name`] is re-exported at the crate root.
//!
//! # The names are the corpus's
//!
//! Each `name()` answers with the `message_type` field of that draft's
//! `transport/draftNN/codec/messages/*.json` vectors — `subscribe`,
//! `publish_namespace`, `goaway` — which is the same string the JavaScript
//! codec's `MESSAGE_TYPE_MAP` answers with for the same id. That shared
//! spelling is the point: a trace named by either implementation reads the same
//! way, and `tests/message_type_names.rs` compares all fourteen drafts against
//! the corpus in both directions so the two tables cannot drift apart quietly.
//!
//! The corpus is test-only — `Cargo.toml` excludes it from the package — so
//! nothing here reads it at runtime. The names are transcribed into the draft
//! modules and the test is what holds the transcription honest.

use crate::version::DraftVersion;

/// The name draft `draft` gives control message type `id`, or `None` if that
/// draft assigns the id nothing.
///
/// `draft` is the draft number as the IETF writes it — 7 through 20 — which is
/// what a trace header's `moq-transport-NN` carries and what
/// [`DraftVersion::number`] returns. A number outside the range this crate
/// implements answers `None`, as does an id the named draft leaves unassigned,
/// and so does a draft whose feature flag is off in this build.
///
/// ```
/// use moqtap_codec::message_type_name;
///
/// // A draft left out of the build answers `None` for every id, which is the
/// // documented behaviour and also indistinguishable from a wrong table — so
/// // the per-draft half of this example runs only where all of the drafts it
/// // names are compiled in. The default feature set is `all-drafts`.
/// # #[cfg(all(
/// #     feature = "draft07",
/// #     feature = "draft14",
/// #     feature = "draft16",
/// #     feature = "draft17",
/// #     feature = "draft19",
/// #     feature = "draft20"
/// # ))]
/// # {
/// // 0x07 is three different messages across the range.
/// assert_eq!(message_type_name(7, 0x07), Some("announce_ok"));
/// assert_eq!(message_type_name(14, 0x07), Some("publish_namespace_ok"));
/// assert_eq!(message_type_name(19, 0x07), Some("request_ok"));
/// // 0x22 is PUBLISH_STATE_NOTIFY, and draft-20 is the first to assign it.
/// assert_eq!(message_type_name(19, 0x22), None);
/// assert_eq!(message_type_name(20, 0x22), Some("publish_state_notify"));
///
/// // The unified SETUP exists from draft-17 and nowhere before it.
/// assert_eq!(message_type_name(16, 0x2F00), None);
/// assert_eq!(message_type_name(17, 0x2F00), Some("setup"));
/// # }
///
/// // A draft number outside the range answers `None` in every build.
/// assert_eq!(message_type_name(6, 0x03), None);
/// ```
#[allow(unused_variables)]
pub fn message_type_name(draft: u8, id: u64) -> Option<&'static str> {
    match DraftVersion::from_number(draft)? {
        #[cfg(feature = "draft07")]
        DraftVersion::Draft07 => {
            crate::draft07::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft08")]
        DraftVersion::Draft08 => {
            crate::draft08::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft09")]
        DraftVersion::Draft09 => {
            crate::draft09::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft10")]
        DraftVersion::Draft10 => {
            crate::draft10::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft11")]
        DraftVersion::Draft11 => {
            crate::draft11::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft12")]
        DraftVersion::Draft12 => {
            crate::draft12::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft13")]
        DraftVersion::Draft13 => {
            crate::draft13::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft14")]
        DraftVersion::Draft14 => {
            crate::draft14::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft15")]
        DraftVersion::Draft15 => {
            crate::draft15::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft16")]
        DraftVersion::Draft16 => {
            crate::draft16::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17 => {
            crate::draft17::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18 => {
            crate::draft18::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19 => {
            crate::draft19::message::MessageType::from_id(id).map(|t| t.name())
        }
        #[cfg(feature = "draft20")]
        DraftVersion::Draft20 => {
            crate::draft20::message::MessageType::from_id(id).map(|t| t.name())
        }
        // A draft this build did not enable. The number is one this crate
        // implements, so it is not `from_number`'s `None`, and the honest answer
        // is still that no name is available here.
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids that moved, stated as the sequence they moved through. The
    /// corpus sweep in `tests/message_type_names.rs` is what checks every id on
    /// every draft; this is the handful that a draft-blind table gets wrong,
    /// written out so the reason this function takes a draft is visible in the
    /// crate itself.
    ///
    /// Gated on the three drafts it names. [`message_type_name`] answers `None`
    /// for a draft no feature flag compiled in, which is the right answer and
    /// not one this test can tell from a wrong table — so under a feature set
    /// missing any of the three it would fail for a reason that has nothing to
    /// do with the ids.
    #[cfg(all(feature = "draft07", feature = "draft14", feature = "draft20"))]
    #[test]
    fn reused_ids_answer_per_draft() {
        let reused: [(u64, [(u8, &str); 3]); 4] = [
            (0x07, [(7, "announce_ok"), (14, "publish_namespace_ok"), (20, "request_ok")]),
            (0x08, [(7, "announce_error"), (14, "publish_namespace_error"), (20, "namespace")]),
            (0x0E, [(7, "track_status"), (14, "track_status_ok"), (20, "namespace_done")]),
            (0x0B, [(7, "subscribe_done"), (14, "publish_done"), (20, "publish_done")]),
        ];
        for (id, expected) in reused {
            for (draft, name) in expected {
                assert_eq!(message_type_name(draft, id), Some(name), "draft-{draft} {id:#x}");
            }
        }
    }

    #[test]
    fn none_outside_the_implemented_drafts() {
        for draft in [0u8, 6, 21, 255] {
            assert_eq!(message_type_name(draft, 0x03), None, "draft {draft}");
        }
    }

    /// An id no draft in the range assigns. 0x3F is what the corpus's
    /// `unknown-type.json` vectors put on the wire for exactly this.
    ///
    /// Needs no feature gate: a draft that is not compiled in answers `None`
    /// for every id, which is what this asserts anyway.
    #[test]
    fn none_for_an_unassigned_id() {
        for draft in 7..=20u8 {
            assert_eq!(message_type_name(draft, 0x3F), None, "draft-{draft}");
        }
    }
}

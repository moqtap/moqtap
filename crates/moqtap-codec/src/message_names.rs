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
//! The dispatch itself is `crate::draft_table::by_draft` — private, so not a
//! link — which
//! [`crate::setup_option_names`] uses for the other registry. The shared shape
//! has no catch-all in it at all, so a draft nobody has added yet is a compile
//! error here rather than the same quiet `None` a build that left a draft out
//! gets; see that module for what that buys and what it costs.
//!
//! # A name is not a concept either
//!
//! The names are reused as well as the ids, and `track_status` swaps which side
//! of the exchange it names at draft-13:
//!
//! | | Request | Response |
//! |---|---|---|
//! | **Drafts 07-12** | `track_status_request` (0x0D) | `track_status` (0x0E) |
//! | **Drafts 13-21** | `track_status` (0x0D) | `track_status_ok` (0x0E) |
//!
//! Every answer is right about its own draft, so comparing two of them by name
//! yields a wrong conclusion out of two correct lookups.
//!
//! # The names are the corpus's
//!
//! Each `name()` answers with the `message_type` field of that draft's
//! `transport/draftNN/codec/messages/*.json` vectors — `subscribe`,
//! `publish_namespace`, `goaway` — which is the same string the JavaScript
//! codec's `MESSAGE_TYPE_MAP` answers with for the same id. That shared
//! spelling is the point: a trace named by either implementation reads the same
//! way, and `tests/message_type_names.rs` compares all the drafts against
//! the corpus in both directions so the two tables cannot drift apart quietly.
//!
//! The corpus is test-only — `Cargo.toml` excludes it from the package — so
//! nothing here reads it at runtime. The names are transcribed into the draft
//! modules and the test is what holds the transcription honest.

/// The name draft `draft` gives control message type `id`, or `None` if that
/// draft assigns the id nothing.
///
/// `draft` is the draft number as the IETF writes it — 7 through 20 — which is
/// what a trace header's `moq-transport-NN` carries and what
/// [`crate::version::DraftVersion::number`] returns. A number outside the range
/// this crate
/// implements answers `None`, as does an id the named draft leaves unassigned,
/// and so does a draft whose feature flag is off in this build.
///
/// Two drafts' answers are not comparable just because they match:
/// `message_type_name(11, 0x0E)` and `message_type_name(14, 0x0D)` both answer
/// `track_status` and name opposite sides of an exchange. See the module docs.
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
// `id` is read by every arm in any build that has a draft, and by none in the
// zero-draft build, where every arm takes its `#[cfg(not(feature = ...))]`
// form. See `crate::draft_table` for why both forms are spelled out.
#[allow(unused_variables)]
pub fn message_type_name(draft: u8, id: u64) -> Option<&'static str> {
    crate::draft_table::by_draft! { draft, None,
        ("draft07", Draft07) => crate::draft07::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft08", Draft08) => crate::draft08::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft09", Draft09) => crate::draft09::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft10", Draft10) => crate::draft10::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft11", Draft11) => crate::draft11::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft12", Draft12) => crate::draft12::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft13", Draft13) => crate::draft13::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft14", Draft14) => crate::draft14::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft15", Draft15) => crate::draft15::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft16", Draft16) => crate::draft16::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft17", Draft17) => crate::draft17::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft18", Draft18) => crate::draft18::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft19", Draft19) => crate::draft19::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft20", Draft20) => crate::draft20::message::MessageType::from_id(id).map(|t| t.name()),
        ("draft21", Draft21) => crate::draft21::message::MessageType::from_id(id).map(|t| t.name()),
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

    /// `track_status` names opposite sides of the exchange either side of
    /// draft-13, and the two ids swap under it. What keeps the module's table
    /// from drifting.
    #[cfg(all(feature = "draft11", feature = "draft14"))]
    #[test]
    fn one_name_reverses_role_at_draft13() {
        assert_eq!(message_type_name(11, 0x0D), Some("track_status_request"));
        assert_eq!(message_type_name(11, 0x0E), Some("track_status"));

        assert_eq!(message_type_name(14, 0x0D), Some("track_status"));
        assert_eq!(message_type_name(14, 0x0E), Some("track_status_ok"));
    }

    /// The draft above the newest is derived, not written down. A literal
    /// here names a supported draft the day that draft is added, and the case
    /// then asserts the absent answer about a table that exists — it fails for
    /// no real reason, which is what 21 did. `DraftVersion::from_number` is
    /// this crate's own statement of the range, so the first number it refuses
    /// is the first number this should.
    #[test]
    fn none_outside_the_implemented_drafts() {
        let beyond = (7u8..=255)
            .find(|n| crate::version::DraftVersion::from_number(*n).is_none())
            .expect("the implemented range is bounded");
        for draft in [0u8, 6, beyond, 255] {
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
        for draft in 7..=21u8 {
            assert_eq!(message_type_name(draft, 0x3F), None, "draft-{draft}");
        }
    }
}

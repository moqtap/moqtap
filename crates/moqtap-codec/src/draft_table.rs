//! One shape for a per-draft lookup, shared by the tables that need it.
//!
//! Two functions in this crate answer the same kind of question — *what does
//! draft N call this number?* — for two different registries:
//! [`crate::message_names::message_type_name`] for control message type IDs and
//! [`crate::setup_option_names::setup_option_name`] for setup parameters. Both
//! have to take the draft as well as the codepoint, because the codepoints are
//! reused and retired rather than reserved, and each one's per-draft half lives
//! in that draft's own module. So both are the same one-arm-per-draft dispatch
//! over [`crate::version::DraftVersion`], and the interesting part is not the
//! arms but what
//! happens at the end of them.
//!
//! # The arm that is not written here, and why it is the whole point
//!
//! A `match` over [`crate::version::DraftVersion`] has to answer for every
//! variant, and the
//! obvious way to end one is `_ => None`. That reads as *a draft this build did
//! not compile has no name for anything*, which is true and is not the whole of
//! what it does: it also answers for a draft **nobody has added yet**. The day a
//! `Draft21` variant lands, a table that ends in a catch-all goes on compiling
//! and starts answering "no name" for every draft-21 codepoint — which is
//! indistinguishable from a correct answer about an unassigned number, and which
//! nothing in the build says a word about.
//!
//! That is the drift `scripts/check-draft-parity.py` rule 3 exists to catch: a
//! match that answers for two or more drafts, reaches the newest, and then
//! falls through to a `_` arm that is not loud. [`by_draft`] answers it
//! structurally rather than with a louder arm: spell **both** feature states
//! for every draft and the match has no catch-all left to fall into, so a
//! fifteenth variant stops this crate compiling instead of being answered
//! quietly.
//!
//! # What that trades away, stated rather than assumed
//!
//! A macro invocation lists its drafts as bare identifiers — `Draft07`, not
//! `DraftVersion::Draft07` — so `check-draft-parity.py` does not recognise
//! either table as a draft-enumerating construct, and rules 2 and 3 do not
//! count them. That is a smaller census and a stronger guarantee: rule 2 asks
//! whether a list reaches the newest draft, and here a list that does not is a
//! non-exhaustive `match`, which is a compile error in fourteen feature
//! configurations. A textual gate is what you need when the compiler cannot see
//! the omission; it is not an improvement on the compiler seeing it.
//!
//! The script's own summary already excludes "anything a macro spells by token
//! concatenation", and both [`crate::setup_option_names`] and its sibling rely
//! on exactly this, with the argument living in one place instead of being
//! restated beside each table.
//!
//! # Why the answer is not shared, only the shape
//!
//! The two tables do not have the same signature and are not meant to. One takes
//! a `u64` and answers `Option<&'static str>`; the other takes a whole
//! [`crate::kvp::KeyValuePair`], because drafts 11 through 13 name a setup
//! parameter from its key *and the shape of its value*, and answers
//! `Option<String>` out of the draft's own field renderer. Folding those into
//! one function would mean inventing a common type that neither registry has.
//!
//! So what is shared is the dispatch and nothing else: the draft lookup, the
//! per-draft cfg pair, and the absent answer. Each table keeps its own
//! signature, its own doctest and its own rationale for what its codepoints
//! mean.

/// Answer a question per draft, with an arm for every draft and no catch-all.
///
/// ```text
/// by_draft! { draft, <absent>,
///     ("draft07", Draft07) => <the answer draft-07 gives>,
///     ...
///     ("draft21", Draft21) => <the answer draft-21 gives>,
/// }
/// ```
///
/// `draft` is the draft number as the IETF writes it — 7 through 21, matching
/// [`crate::version::DraftVersion::number`]. `<absent>` is the answer for a
/// draft this crate does not implement **and** for one whose feature flag is off
/// in this build, which are two different facts with one honest answer: this
/// build has no table to consult. It is an expression rather than a value, so a
/// caller that needs to leave the function early can pass `return None` and a
/// caller that is already returning the right type can pass it directly.
///
/// Each row names its feature string and its [`crate::version::DraftVersion`]
/// variant, and the expansion writes two arms for the pair — one under
/// `#[cfg(feature = ...)]` carrying the answer, one under `#[cfg(not(...))]`
/// carrying `<absent>`. Every variant is therefore matched under every feature
/// set, which is what leaves the `match` with no `_` arm and makes a new
/// `DraftVersion` variant a compile error here rather than a silent `<absent>`.
///
/// The answer expressions are transcribed at the invocation, so they read the
/// invocation's own bindings — `id`, or a slice built above the call — exactly
/// as if they had been written into the `match` by hand.
macro_rules! by_draft {
    ( $number:expr, $absent:expr, $( ($feat:literal, $variant:ident) => $named:expr ),+ $(,)? ) => {
        match $crate::version::DraftVersion::from_number($number) {
            // A draft number this crate does not implement at all. Separate
            // from the arms below only in why it has no answer, which is why
            // both give the same one.
            None => $absent,
            Some(implemented) => match implemented {
                $(
                    #[cfg(feature = $feat)]
                    $crate::version::DraftVersion::$variant => $named,
                    #[cfg(not(feature = $feat))]
                    $crate::version::DraftVersion::$variant => $absent,
                )+
            },
        }
    };
}

pub(crate) use by_draft;

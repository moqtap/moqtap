//! Every draft's fetch state machine answers in either order.
//!
//! `fetch_tests.rs` drives draft-14's machine through the whole transition
//! table. There is one of those machines per draft module, and they
//! are separate types with separate copies of the same graph — so a change made
//! to one of them and not to its thirteen siblings compiles, passes that file, and
//! ships. This file drives the two orders and the late close on every draft the
//! build has, so the odd sibling is a failure rather than a silence.
//!
//! # Ablation, run
//!
//! Deleting the `FetchState::Unanswered` arm from draft-07's `on_fetch_ok` and
//! nothing else — one sibling of the fourteen put back the way it was — leaves
//! `fetch_tests.rs` entirely green and fails one row here:
//!
//! ```text
//! draft-07 refused an answer after delivery: invalid transition from
//! Unanswered on event on_fetch_ok
//! ```
//!
//! Every draft carries the sentence the two orders come from, differing only in
//! how it names the far end of the range. draft-14 Section 9.17: "A publisher
//! MAY send Objects in response to a FETCH before the FETCH_OK message is sent,
//! but the FETCH_OK MUST NOT be sent until the End Location is known." Drafts 12
//! through 20 word it exactly so; draft-11 waits on "the end group and object",
//! and drafts 07 through 10 on "the latest group and object".

macro_rules! fetch_answer_order {
    ($name:ident, $draft:literal, $module:path) => {
        #[test]
        fn $name() {
            use $module::{FetchState, FetchStateMachine};

            // The answer first, then the objects it described.
            let mut sm = FetchStateMachine::new();
            sm.on_fetch_sent().unwrap();
            sm.on_fetch_ok().unwrap();
            assert_eq!(sm.state(), FetchState::Receiving, "{} after its FETCH_OK", $draft);
            sm.on_stream_fin().unwrap();
            assert_eq!(sm.state(), FetchState::Done, "{} after its stream ended", $draft);

            // The objects first, and the answer describing them after.
            let mut sm = FetchStateMachine::new();
            sm.on_fetch_sent().unwrap();
            sm.on_stream_fin()
                .unwrap_or_else(|e| panic!("{} refused a stream ending first: {e}", $draft));
            assert_eq!(
                sm.state(),
                FetchState::Unanswered,
                "{} owes an answer once its stream has ended",
                $draft
            );
            sm.on_fetch_ok()
                .unwrap_or_else(|e| panic!("{} refused an answer after delivery: {e}", $draft));
            assert_eq!(sm.state(), FetchState::Done, "{} after its answer landed", $draft);

            // The close a fetch that ended early leaves behind.
            let mut sm = FetchStateMachine::new();
            sm.on_fetch_sent().unwrap();
            sm.on_fetch_error().unwrap();
            sm.on_stream_reset()
                .unwrap_or_else(|e| panic!("{} refused the reset after its error: {e}", $draft));
            assert_eq!(sm.state(), FetchState::Done, "{} after a trailing reset", $draft);
        }
    };
}

#[cfg(feature = "draft07")]
fetch_answer_order!(draft07_answers_in_either_order, "draft-07", moqtap_client::draft07::fetch);
#[cfg(feature = "draft08")]
fetch_answer_order!(draft08_answers_in_either_order, "draft-08", moqtap_client::draft08::fetch);
#[cfg(feature = "draft09")]
fetch_answer_order!(draft09_answers_in_either_order, "draft-09", moqtap_client::draft09::fetch);
#[cfg(feature = "draft10")]
fetch_answer_order!(draft10_answers_in_either_order, "draft-10", moqtap_client::draft10::fetch);
#[cfg(feature = "draft11")]
fetch_answer_order!(draft11_answers_in_either_order, "draft-11", moqtap_client::draft11::fetch);
#[cfg(feature = "draft12")]
fetch_answer_order!(draft12_answers_in_either_order, "draft-12", moqtap_client::draft12::fetch);
#[cfg(feature = "draft13")]
fetch_answer_order!(draft13_answers_in_either_order, "draft-13", moqtap_client::draft13::fetch);
#[cfg(feature = "draft14")]
fetch_answer_order!(draft14_answers_in_either_order, "draft-14", moqtap_client::draft14::fetch);
#[cfg(feature = "draft15")]
fetch_answer_order!(draft15_answers_in_either_order, "draft-15", moqtap_client::draft15::fetch);
#[cfg(feature = "draft16")]
fetch_answer_order!(draft16_answers_in_either_order, "draft-16", moqtap_client::draft16::fetch);
#[cfg(feature = "draft17")]
fetch_answer_order!(draft17_answers_in_either_order, "draft-17", moqtap_client::draft17::fetch);
#[cfg(feature = "draft18")]
fetch_answer_order!(draft18_answers_in_either_order, "draft-18", moqtap_client::draft18::fetch);
#[cfg(feature = "draft19")]
fetch_answer_order!(draft19_answers_in_either_order, "draft-19", moqtap_client::draft19::fetch);
#[cfg(feature = "draft20")]
fetch_answer_order!(draft20_answers_in_either_order, "draft-20", moqtap_client::draft20::fetch);
#[cfg(feature = "draft21")]
fetch_answer_order!(draft21_answers_in_either_order, "draft-21", moqtap_client::draft21::fetch);

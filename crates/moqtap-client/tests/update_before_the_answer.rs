//! An update that arrives before the subscription's own answer, on all
//! fourteen drafts.
//!
//! No draft orders a subscription update against the SUBSCRIBE_OK. Every one of
//! them orders it against the SUBSCRIBE: drafts 07 through 10 ask only that the
//! identifier "MUST match an existing Subscribe ID", drafts 11 through 15 say
//! the same of a Request ID, and drafts 16 through 20 put the update on the
//! request's own stream "later" than the request. An identifier exists, and a
//! stream is open, from the moment the SUBSCRIBE is sent.
//!
//! So a subscriber that sends SUBSCRIBE and its update back to back is
//! conforming. That is the shape this file exists for: the state machines are
//! fourteen copies of one graph, so a change applied to one of them and not the
//! rest reads exactly like a change applied to all of them, and only a gate on
//! every draft tells the two apart. A module ported from a corrected original is
//! indistinguishable from one nobody checked, which is the same hazard from the
//! other side.
//!
//! The rest of the edge is asserted too. `Idle` and `Done` still refuse an
//! update, because in neither does the subscription an update names exist.

/// The three gates for one draft.
macro_rules! update_before_the_answer_gates {
    ($module:ident, $feat:literal, $draft:ident, $message:literal) => {
        #[cfg(feature = $feat)]
        mod $module {
            use moqtap_client::$draft::subscription::{
                SubscriptionError, SubscriptionState, SubscriptionStateMachine,
            };

            /// The update arrives while the SUBSCRIBE is still unanswered, and
            /// leaves the subscription where it found it.
            ///
            /// The SUBSCRIBE_OK afterwards is what says so: it is the
            /// transition out of `Subscribing` and succeeds only from there, so
            /// an update that had moved the subscription — or been refused —
            /// would fail on the line after it rather than on its own.
            ///
            /// # Ablation
            ///
            /// The `Subscribing` arm removed from `on_subscribe_update`, which
            /// is what thirteen of the fourteen shipped, measured on draft-19:
            ///
            /// ```text
            /// thread 'draft19::an_update_may_precede_the_subscriptions_own_answer'
            /// panicked at crates\moqtap-client\tests\update_before_the_answer.rs:
            /// a REQUEST_UPDATE may precede the subscription's own answer: InvalidTransition { from: Subscribing, event: "on_subscribe_update" }
            /// ```
            ///
            /// The same cut was made again in draft-20's `on_subscribe_update`
            /// when this file gained its arm. It reddens this gate on draft-20
            /// and nothing else — 41 passed, 1 failed — the two gates below
            /// staying green because `Idle` and `Done` refuse an update either
            /// way, which is what makes them controls rather than repetitions.
            #[test]
            fn an_update_may_precede_the_subscriptions_own_answer() {
                let mut sm = SubscriptionStateMachine::new();
                sm.on_subscribe_sent().expect("the SUBSCRIBE is sent");
                sm.on_subscribe_update().unwrap_or_else(|e| {
                    panic!(
                        concat!("a ", $message, " may precede the subscription's own answer: {:?}"),
                        e
                    )
                });
                sm.on_subscribe_ok()
                    .expect("the answer still reaches a subscription that is Subscribing");
            }

            /// An update before the SUBSCRIBE names an identifier no SUBSCRIBE
            /// has established.
            #[test]
            fn an_update_from_idle_names_nothing() {
                let mut sm = SubscriptionStateMachine::new();
                match sm.on_subscribe_update() {
                    Ok(()) => {
                        panic!(concat!("a ", $message, " was accepted with no SUBSCRIBE to name"))
                    }
                    Err(SubscriptionError::InvalidTransition { from, .. }) => {
                        assert_eq!(from, SubscriptionState::Idle)
                    }
                }
            }

            /// An update after the subscription has ended names one that no
            /// longer exists.
            #[test]
            fn an_update_from_done_names_a_subscription_that_has_ended() {
                let mut sm = SubscriptionStateMachine::new();
                sm.on_subscribe_sent().expect("the SUBSCRIBE is sent");
                sm.on_subscribe_error().expect("the SUBSCRIBE is refused");
                match sm.on_subscribe_update() {
                    Ok(()) => panic!(concat!(
                        "a ",
                        $message,
                        " was accepted for a subscription that has ended"
                    )),
                    Err(SubscriptionError::InvalidTransition { from, .. }) => {
                        assert_eq!(from, SubscriptionState::Done)
                    }
                }
            }
        }
    };
}

update_before_the_answer_gates!(draft07, "draft07", draft07, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft08, "draft08", draft08, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft09, "draft09", draft09, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft10, "draft10", draft10, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft11, "draft11", draft11, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft12, "draft12", draft12, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft13, "draft13", draft13, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft14, "draft14", draft14, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft15, "draft15", draft15, "SUBSCRIBE_UPDATE");
update_before_the_answer_gates!(draft16, "draft16", draft16, "REQUEST_UPDATE");
update_before_the_answer_gates!(draft17, "draft17", draft17, "REQUEST_UPDATE");
update_before_the_answer_gates!(draft18, "draft18", draft18, "REQUEST_UPDATE");
update_before_the_answer_gates!(draft19, "draft19", draft19, "REQUEST_UPDATE");
update_before_the_answer_gates!(draft20, "draft20", draft20, "REQUEST_UPDATE");

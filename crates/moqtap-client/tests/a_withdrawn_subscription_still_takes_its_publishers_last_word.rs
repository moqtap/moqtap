//! A subscription this endpoint withdrew still accepts the message that ends
//! it, on all the drafts.
//!
//! # The bug this pins, and how it was found
//!
//! The subscription state machine put a subscription in `Done` the moment
//! UNSUBSCRIBE went out, and then refused the publisher's SUBSCRIBE_DONE —
//! PUBLISH_DONE from draft-14 — as an invalid transition. Which is exactly
//! backwards: a publisher answering a withdrawal with that message is doing what
//! the draft asks of it, and it carries the status code saying the subscriber's
//! own UNSUBSCRIBE is why. The end of a subscription is **two events**, one from
//! each end, and a machine that treats the first as terminal cannot take the
//! second.
//!
//! It surfaces as a wall rather than as a bug report, which is what makes it
//! expensive. A caller that classifies failures by the `endpoint error` prefix
//! reads `endpoint error: subscription error: invalid transition from Done on
//! event on_publish_done` as this stack's own fault — correctly — and records
//! only that a measurement could not be taken. Against moq-rs on draft-14 that
//! costs the whole fetch measurement on the session: the history subscription
//! is given back, moq-rs answers with PUBLISH_DONE as it should, and the
//! FETCH's own answer is never reached.
//!
//! # What is still refused
//!
//! `Idle` and `Subscribing`. In neither is there an active subscription for the
//! message to end, and a peer sending one there is saying something about a
//! subscription that does not exist yet. Only the *terminal* state became
//! tolerant, and it stays terminal — nothing here reopens anything.
//!
//! # Why fourteen gates and not one
//!
//! Because the machine is fourteen machines. They agree today and have not
//! always: the message is SUBSCRIBE_DONE on drafts 07 through 13 and PUBLISH_DONE
//! from draft-14, and drafts 17 through 20 have no UNSUBSCRIBE at all — there a
//! subscriber withdraws by resetting its own request stream. The last of those is
//! why the gates below reach `Done` through SUBSCRIBE_ERROR as well as through
//! UNSUBSCRIBE where the draft has one: the tolerance is about the state, not
//! about the road to it.

/// One draft's subscription machine.
///
/// `$done` is the receiving transition, `$done_sent` the publishing mirror where
/// the draft has one, and `$withdraw` the subscriber's own withdrawal where the
/// draft has one — drafts 17 through 20 have neither UNSUBSCRIBE nor a mirror.
macro_rules! withdrawal_gate {
    ($module:ident, $feat:literal, $done:ident $(, unsubscribe: $withdraw:ident)?
     $(, mirror: $done_sent:ident, $withdraw_received:ident)? $(,)?) => {
        #[cfg(feature = $feat)]
        mod $module {
            use moqtap_client::$module::subscription::*;

            fn active() -> SubscriptionStateMachine {
                let mut sm = SubscriptionStateMachine::new();
                sm.on_subscribe_sent().expect("Idle takes a SUBSCRIBE");
                sm.on_subscribe_ok().expect("Subscribing takes the answer");
                assert_eq!(sm.state(), SubscriptionState::Active);
                sm
            }

            /// The publisher's last word arrives after the subscriber's, and is
            /// taken.
            $(
                #[test]
                fn a_withdrawn_subscription_takes_the_message_that_ends_it() {
                    let mut sm = active();
                    sm.$withdraw().expect("an active subscription can be withdrawn");
                    assert_eq!(sm.state(), SubscriptionState::Done);
                    sm.$done().expect(
                        "a publisher answering a withdrawal is doing what the draft asks",
                    );
                    assert_eq!(
                        sm.state(),
                        SubscriptionState::Done,
                        "the state does not move, because there is nowhere past Done"
                    );
                }
            )?

            /// And a second one after that, because a relay repeating itself is
            /// not a reason for a subscriber to fall over.
            #[test]
            fn the_same_message_twice_is_still_taken() {
                let mut sm = active();
                sm.$done().expect("an active subscription ends on this message");
                sm.$done().expect("and a repeat of it changes nothing");
                assert_eq!(sm.state(), SubscriptionState::Done);
            }

            /// The publishing mirror needs the same tolerance for the mirror
            /// reason: this endpoint answers a peer's UNSUBSCRIBE with exactly
            /// this message, and the withdrawal it is answering has already put
            /// the subscription in Done.
            $(
                #[test]
                fn the_publishing_side_can_answer_a_withdrawal_it_has_already_recorded() {
                    let mut sm = SubscriptionStateMachine::new();
                    sm.on_subscribe_received().expect("a peer's SUBSCRIBE arrives");
                    sm.on_subscribe_ok_sent().expect("and is answered");
                    sm.$withdraw_received().expect("the peer withdraws");
                    assert_eq!(sm.state(), SubscriptionState::Done);
                    sm.$done_sent().expect(
                        "and this endpoint answers the withdrawal, which is what the draft \
                         asks a publisher to do",
                    );
                    assert_eq!(sm.state(), SubscriptionState::Done);
                }
            )?

            /// What stayed refused. A subscription that does not exist yet has
            /// nothing for this message to end, and both states before Active
            /// say so.
            #[test]
            fn a_subscription_that_never_stood_still_refuses_it() {
                let mut idle = SubscriptionStateMachine::new();
                assert!(idle.$done().is_err(), "Idle has no subscription to end");
                let mut asking = SubscriptionStateMachine::new();
                asking.on_subscribe_sent().expect("Idle takes a SUBSCRIBE");
                assert!(asking.$done().is_err(), "an unanswered SUBSCRIBE is not a subscription");
            }

            /// Done stays terminal. Tolerating the end twice is not reopening
            /// anything, and the state that proves it is the one every draft
            /// refuses from there.
            #[test]
            fn done_is_still_terminal() {
                let mut sm = active();
                sm.$done().expect("an active subscription ends on this message");
                assert!(sm.on_subscribe_sent().is_err(), "nothing reopens a subscription");
                assert!(sm.on_subscribe_ok().is_err(), "and nothing re-answers one");
            }
        }
    };
}

// Drafts 07 through 13: SUBSCRIBE_DONE, and an UNSUBSCRIBE to precede it.
withdrawal_gate!(
    draft07,
    "draft07",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft08,
    "draft08",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft09,
    "draft09",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft10,
    "draft10",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft11,
    "draft11",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft12,
    "draft12",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft13,
    "draft13",
    on_subscribe_done,
    unsubscribe: on_unsubscribe,
    mirror: on_subscribe_done_sent,
    on_unsubscribe_received,
);

// Drafts 14 through 16: the message was renamed PUBLISH_DONE; the sequence is
// the same one.
withdrawal_gate!(
    draft14,
    "draft14",
    on_publish_done,
    unsubscribe: on_unsubscribe,
    mirror: on_publish_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft15,
    "draft15",
    on_publish_done,
    unsubscribe: on_unsubscribe,
    mirror: on_publish_done_sent,
    on_unsubscribe_received,
);
withdrawal_gate!(
    draft16,
    "draft16",
    on_publish_done,
    unsubscribe: on_unsubscribe,
    mirror: on_publish_done_sent,
    on_unsubscribe_received,
);

// Drafts 17 through 20: UNSUBSCRIBE is gone and so is the publishing mirror. A
// subscriber withdraws by resetting its own request stream, which is not a
// transition this machine sees — so what is left to gate is that the terminal
// state takes the message rather than refusing it.
withdrawal_gate!(draft17, "draft17", on_publish_done);
withdrawal_gate!(draft18, "draft18", on_publish_done);
withdrawal_gate!(draft19, "draft19", on_publish_done);
withdrawal_gate!(draft20, "draft20", on_publish_done);
withdrawal_gate!(draft21, "draft21", on_publish_done);

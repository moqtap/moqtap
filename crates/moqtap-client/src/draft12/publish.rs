/// Where a subscription a PUBLISH opened has got to, whichever end sent it.
///
/// Section 4.1: "A subscription can be initiated by either a publisher or a
/// subscriber. A publisher initiates a subscription to a track by sending the
/// PUBLISH message. The subscriber either accepts or rejects the subscription
/// using PUBLISH_OK or PUBLISH_ERROR." Both sides of that sentence are here.
/// The transitions are named for who acted rather than for the state they
/// reach, so the two directions have two names for each step and a refused
/// transition names the event the caller actually attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishState {
    /// No PUBLISH has been sent or received yet.
    Idle,
    /// A PUBLISH is outstanding: sent and not answered, or arrived and not
    /// answered.
    Publishing,
    /// A PUBLISH_OK has been sent or received: the subscription is live.
    Active,
    /// The subscription is over, by refusal or by either end ending it.
    Done,
}

/// Errors that can occur during publish state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublishError {
    /// An event was received that is not valid for the current state.
    #[error("invalid transition from {from:?} on event {event}")]
    InvalidTransition {
        /// The state the machine was in when the invalid event arrived.
        from: PublishState,
        /// The name of the event that was rejected.
        event: String,
    },
}

/// Pure state machine for a subscription a PUBLISH opened.
/// Transitions: Idle -> Publishing -> Active -> Done.
///
/// The two ends of the flow are the two halves of Section 4.1's sentence: "A
/// subscriber MUST send exactly one PUBLISH_OK or PUBLISH_ERROR in response to
/// a PUBLISH", and "the subscription can be ... terminated by the subscriber
/// using UNSUBSCRIBE, or terminated by the publisher using SUBSCRIBE_DONE".
/// Each event has a transition of its own even where two of them land in the
/// same state, so that a refusal names the event that was refused, and so that
/// each direction of the flow names its own half of it.
pub struct PublishStateMachine {
    state: PublishState,
}

impl Default for PublishStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishStateMachine {
    /// Creates a new state machine in the [`PublishState::Idle`] state.
    pub fn new() -> Self {
        Self { state: PublishState::Idle }
    }

    /// Returns the current state of the subscription.
    pub fn state(&self) -> PublishState {
        self.state
    }

    fn step(
        &mut self,
        from: PublishState,
        to: PublishState,
        event: &str,
    ) -> Result<(), PublishError> {
        if self.state == from {
            self.state = to;
            Ok(())
        } else {
            Err(PublishError::InvalidTransition { from: self.state, event: event.to_string() })
        }
    }

    /// Idle -> Publishing (PUBLISH received from the peer).
    pub fn on_publish_received(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Idle, PublishState::Publishing, "on_publish_received")
    }

    /// Publishing -> Active (this endpoint answered PUBLISH_OK).
    pub fn on_publish_ok_sent(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Publishing, PublishState::Active, "on_publish_ok_sent")
    }

    /// Publishing -> Done (this endpoint answered PUBLISH_ERROR).
    pub fn on_publish_error_sent(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Publishing, PublishState::Done, "on_publish_error_sent")
    }

    /// Active -> Done (this endpoint sent UNSUBSCRIBE).
    ///
    /// Only from Active: the draft gives the subscriber UNSUBSCRIBE for a
    /// subscription that is established, and a PUBLISH it has not answered yet
    /// is refused with PUBLISH_ERROR instead.
    pub fn on_unsubscribe_sent(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Active, PublishState::Done, "on_unsubscribe_sent")
    }

    /// Active -> Done (the publishing peer sent SUBSCRIBE_DONE).
    pub fn on_subscribe_done_received(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Active, PublishState::Done, "on_subscribe_done_received")
    }

    /// Idle -> Publishing (PUBLISH sent to the peer).
    ///
    /// The mirror of [`Self::on_publish_received`], and the same step: Section
    /// 4.1 opens with "A subscription can be initiated by either a publisher
    /// or a subscriber", so an offer looks the same from both ends and only
    /// the event name says which end made it.
    pub fn on_publish_sent(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Idle, PublishState::Publishing, "on_publish_sent")
    }

    /// Publishing -> Active (the subscribing peer answered PUBLISH_OK).
    pub fn on_publish_ok(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Publishing, PublishState::Active, "on_publish_ok")
    }

    /// Publishing -> Done (the subscribing peer answered PUBLISH_ERROR).
    ///
    /// The offer is over rather than pending. Section 4.1: "Objects MUST NOT
    /// be sent for requests that end with an error."
    pub fn on_publish_error(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Publishing, PublishState::Done, "on_publish_error")
    }

    /// Active -> Done (this endpoint, as the publisher, sent SUBSCRIBE_DONE).
    pub fn on_subscribe_done_sent(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Active, PublishState::Done, "on_subscribe_done_sent")
    }

    /// Active -> Done (the subscribing peer sent UNSUBSCRIBE).
    ///
    /// The mirror of [`Self::on_unsubscribe_sent`] and the same step, on a
    /// subscription this endpoint opened rather than one it took. Section 8.11
    /// gives the message to the subscriber alone, so which end sends it
    /// follows from which end made the offer.
    pub fn on_unsubscribe_received(&mut self) -> Result<(), PublishError> {
        self.step(PublishState::Active, PublishState::Done, "on_unsubscribe_received")
    }
}

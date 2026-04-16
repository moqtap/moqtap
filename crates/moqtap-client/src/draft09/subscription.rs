/// Subscription lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Initial state before any SUBSCRIBE message is sent.
    Idle,
    /// SUBSCRIBE has been sent; awaiting OK or ERROR.
    Subscribing,
    /// Subscription is accepted and data may be flowing.
    Active,
    /// Subscription has ended (error, unsubscribe, or subscribe done).
    Done,
}

/// Errors that can occur during subscription state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscriptionError {
    /// An event was received that is not valid for the current state.
    #[error("invalid transition from {from:?} on event {event}")]
    InvalidTransition {
        /// The state the machine was in when the invalid event arrived.
        from: SubscriptionState,
        /// The name of the event that was rejected.
        event: String,
    },
}

/// Pure state machine for a MoQT subscription (draft-09).
/// Transitions: Idle → Subscribing → Active → Done.
pub struct SubscriptionStateMachine {
    state: SubscriptionState,
}

impl Default for SubscriptionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriptionStateMachine {
    /// Creates a new state machine in the [`SubscriptionState::Idle`] state.
    pub fn new() -> Self {
        Self { state: SubscriptionState::Idle }
    }

    /// Returns the current state of the subscription.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// Idle → Subscribing (SUBSCRIBE sent).
    pub fn on_subscribe_sent(&mut self) -> Result<(), SubscriptionError> {
        if self.state == SubscriptionState::Idle {
            self.state = SubscriptionState::Subscribing;
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_subscribe_sent".to_string(),
            })
        }
    }

    /// Subscribing → Active (SUBSCRIBE_OK received).
    pub fn on_subscribe_ok(&mut self) -> Result<(), SubscriptionError> {
        if self.state == SubscriptionState::Subscribing {
            self.state = SubscriptionState::Active;
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_subscribe_ok".to_string(),
            })
        }
    }

    /// Subscribing → Done (SUBSCRIBE_ERROR received).
    pub fn on_subscribe_error(&mut self) -> Result<(), SubscriptionError> {
        if self.state == SubscriptionState::Subscribing {
            self.state = SubscriptionState::Done;
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_subscribe_error".to_string(),
            })
        }
    }

    /// Active → Done (UNSUBSCRIBE sent).
    pub fn on_unsubscribe(&mut self) -> Result<(), SubscriptionError> {
        if self.state == SubscriptionState::Active {
            self.state = SubscriptionState::Done;
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_unsubscribe".to_string(),
            })
        }
    }

    /// Active → Active (SUBSCRIBE_UPDATE sent/received — self-transition).
    pub fn on_subscribe_update(&mut self) -> Result<(), SubscriptionError> {
        if self.state == SubscriptionState::Active {
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_subscribe_update".to_string(),
            })
        }
    }

    /// Active → Done (SUBSCRIBE_DONE received — publisher finished).
    pub fn on_subscribe_done(&mut self) -> Result<(), SubscriptionError> {
        if self.state == SubscriptionState::Active {
            self.state = SubscriptionState::Done;
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_subscribe_done".to_string(),
            })
        }
    }
}

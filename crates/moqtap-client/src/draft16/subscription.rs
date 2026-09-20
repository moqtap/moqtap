/// Subscription lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Initial state before any SUBSCRIBE message is sent.
    Idle,
    /// SUBSCRIBE has been sent; awaiting OK or ERROR.
    Subscribing,
    /// Subscription is accepted and data may be flowing.
    Active,
    /// Subscription has ended (error, unsubscribe, or publish done).
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

/// Pure state machine for a MoQT subscription.
/// Transitions: Idle -> Subscribing -> Active -> Done.
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

    /// Idle -> Subscribing (SUBSCRIBE sent).
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

    /// Subscribing -> Active (SUBSCRIBE_OK received).
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

    /// Subscribing -> Done (REQUEST_ERROR received).
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

    /// Active -> Done (UNSUBSCRIBE sent).
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

    /// REQUEST_UPDATE received -- a self-transition, from Subscribing as well as
    /// from Active.
    ///
    /// Section 9.11 orders an update against the request rather than against
    /// the request's answer: the sender of a SUBSCRIBE "can later send a
    /// REQUEST_UPDATE to modify it", where later is later than the SUBSCRIBE.
    /// The message names what it updates in its own Existing Request ID field,
    /// which the SUBSCRIBE has already established.
    ///
    /// So a peer that sends SUBSCRIBE and REQUEST_UPDATE back to back breaks no
    /// rule this draft states, and an update arriving before the answer leaves
    /// the subscription where it found it. `Idle` and `Done` are still refused:
    /// in neither does the subscription an update names exist.
    pub fn on_subscribe_update(&mut self) -> Result<(), SubscriptionError> {
        if matches!(self.state, SubscriptionState::Subscribing | SubscriptionState::Active) {
            Ok(())
        } else {
            Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_subscribe_update".to_string(),
            })
        }
    }

    /// Active -> Done (PUBLISH_DONE received, and `Done` unchanged).
    ///
    /// # Why `Done` is not refused
    ///
    /// Because UNSUBSCRIBE is usually what put the subscription there, and this
    /// message is what a publisher is meant to answer one with. A subscriber
    /// that withdraws is told the subscription has ended, with a code saying it
    /// was its own doing — so `on_unsubscribe` followed by `on_publish_done` is
    /// the ordinary end of a subscription rather than a peer misbehaving.
    ///
    /// Refusing the second half would make a conforming relay's last message
    /// read as a protocol error against this endpoint's own bookkeeping — an
    /// `invalid transition from Done` raised against this endpoint, not the
    /// relay, and so a wall rather than a finding about the peer.
    ///
    /// `Idle` and `Subscribing` are still refused. In neither is there an active
    /// subscription for this message to end.
    pub fn on_publish_done(&mut self) -> Result<(), SubscriptionError> {
        match self.state {
            SubscriptionState::Active => {
                self.state = SubscriptionState::Done;
                Ok(())
            }
            SubscriptionState::Done => Ok(()),
            _ => Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_publish_done".to_string(),
            }),
        }
    }
}

/// The same six transitions, named for the end that sees them.
///
/// A subscription this endpoint publishes runs through the states in the same
/// order as one it subscribes to, with every message going the other way: the
/// SUBSCRIBE arrives instead of leaving, the answer leaves instead of
/// arriving. Sharing the transitions and not the names is what lets a refusal
/// say which event was refused, rather than naming the mirror image of it.
impl SubscriptionStateMachine {
    /// Idle -> Subscribing (SUBSCRIBE received from a subscribing peer).
    pub fn on_subscribe_received(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_sent().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_subscribe_received".to_string(),
        })
    }

    /// Subscribing -> Active (SUBSCRIBE_OK sent to the subscribing peer).
    pub fn on_subscribe_ok_sent(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_ok().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_subscribe_ok_sent".to_string(),
        })
    }

    /// Subscribing -> Done (REQUEST_ERROR sent to the subscribing peer).
    pub fn on_request_error_sent(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_error().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_request_error_sent".to_string(),
        })
    }

    /// Active -> Done (UNSUBSCRIBE received from the subscribing peer).
    pub fn on_unsubscribe_received(&mut self) -> Result<(), SubscriptionError> {
        self.on_unsubscribe().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_unsubscribe_received".to_string(),
        })
    }

    /// Active -> Done (PUBLISH_DONE sent to the subscribing peer), and `Done`
    /// unchanged — this endpoint answers a peer's UNSUBSCRIBE with this
    /// message, and the withdrawal it answers has already recorded the end.
    /// See [`SubscriptionStateMachine::on_publish_done`], whose tolerance this inherits.
    pub fn on_publish_done_sent(&mut self) -> Result<(), SubscriptionError> {
        self.on_publish_done().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_publish_done_sent".to_string(),
        })
    }

    /// Subscribing or Active, unchanged (REQUEST_UPDATE received from the subscribing peer).
    pub fn on_request_update_received(&mut self) -> Result<(), SubscriptionError> {
        self.on_subscribe_update().map_err(|_| SubscriptionError::InvalidTransition {
            from: self.state(),
            event: "on_request_update_received".to_string(),
        })
    }
}

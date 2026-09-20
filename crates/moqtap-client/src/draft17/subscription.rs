/// Subscription lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Initial state before any SUBSCRIBE message is sent.
    Idle,
    /// SUBSCRIBE has been sent; awaiting OK or ERROR.
    Subscribing,
    /// Subscription is accepted and data may be flowing.
    Active,
    /// Subscription has ended (error, cancellation, or PUBLISH_DONE).
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

    /// Subscribing | Active -> Done, Done -> Done (this subscription's request
    /// stream was cancelled).
    ///
    /// This draft has no UNSUBSCRIBE message. Section 3.3.1: "Once a request
    /// stream has been opened, the request MAY be cancelled by either endpoint."
    ///
    /// `Subscribing` is accepted because the precondition is the stream being
    /// open, and it is open from the SUBSCRIBE that opened it: a subscription
    /// can be withdrawn before it is ever answered.
    ///
    /// `Idle` is refused, on the other half of the same sentence: nothing has
    /// been written, so there is no stream to terminate. `Done` stays `Done` —
    /// nothing finishes a request stream's send half on the ordinary path, so a
    /// caller that walks away from a request that has already ended still
    /// resets the stream, and that reset is an ordinary end rather than a
    /// fault.
    pub fn on_request_cancelled(&mut self) -> Result<(), SubscriptionError> {
        match self.state {
            SubscriptionState::Subscribing | SubscriptionState::Active => {
                self.state = SubscriptionState::Done;
                Ok(())
            }
            SubscriptionState::Done => Ok(()),
            SubscriptionState::Idle => Err(SubscriptionError::InvalidTransition {
                from: self.state,
                event: "on_request_cancelled".to_string(),
            }),
        }
    }

    /// REQUEST_UPDATE received -- a self-transition, from Subscribing as well as
    /// from Active.
    ///
    /// Section 9.10 orders an update against the request rather than against
    /// the request's answer: the sender of a SUBSCRIBE "can later send a
    /// REQUEST_UPDATE on the same bidi stream as the request to modify it",
    /// where later is later than the SUBSCRIBE. The stream is open from the
    /// moment the SUBSCRIBE opens it.
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
    /// Because this draft has no UNSUBSCRIBE — a subscriber ends a subscription
    /// by resetting its own request stream — and a publisher that was already
    /// sending PUBLISH_DONE when that happened is not misbehaving. The same
    /// tolerance the drafts with the message need, for the same reason: the end
    /// of a subscription is two events and they can arrive in either order.
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

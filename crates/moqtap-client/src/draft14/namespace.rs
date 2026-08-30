/// SUBSCRIBE_NAMESPACE lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeNamespaceState {
    /// Initial state before any message is sent.
    Idle,
    /// SUBSCRIBE_NAMESPACE has been sent; awaiting OK or ERROR.
    Pending,
    /// Namespace subscription is accepted and active.
    Active,
    /// Namespace subscription has ended.
    Done,
}

/// PUBLISH_NAMESPACE lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishNamespaceState {
    /// Initial state before any message is sent.
    Idle,
    /// PUBLISH_NAMESPACE has been sent; awaiting OK or ERROR.
    Pending,
    /// Namespace publication is accepted and active.
    Active,
    /// Namespace publication has ended.
    Done,
}

/// Errors that can occur during namespace state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NamespaceError {
    /// An event was received that is not valid for the current state.
    #[error("invalid transition from {from} on event {event}")]
    InvalidTransition {
        /// The state the machine was in when the invalid event arrived.
        from: String,
        /// The name of the event that was rejected.
        event: String,
    },
}

/// State machine for SUBSCRIBE_NAMESPACE flow.
/// Idle → Pending → Active → Done.
pub struct SubscribeNamespaceStateMachine {
    state: SubscribeNamespaceState,
}

impl Default for SubscribeNamespaceStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscribeNamespaceStateMachine {
    /// Creates a new machine in [`SubscribeNamespaceState::Idle`].
    pub fn new() -> Self {
        Self { state: SubscribeNamespaceState::Idle }
    }

    /// Returns the current state of the subscribe-namespace flow.
    pub fn state(&self) -> SubscribeNamespaceState {
        self.state
    }

    /// Idle → Pending.
    pub fn on_subscribe_namespace_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Idle {
            self.state = SubscribeNamespaceState::Pending;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_namespace_sent".to_string(),
            })
        }
    }

    /// Pending → Active.
    pub fn on_subscribe_namespace_ok(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Pending {
            self.state = SubscribeNamespaceState::Active;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_namespace_ok".to_string(),
            })
        }
    }

    /// Pending → Done.
    pub fn on_subscribe_namespace_error(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Pending {
            self.state = SubscribeNamespaceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_namespace_error".to_string(),
            })
        }
    }

    /// Active → Done.
    pub fn on_unsubscribe_namespace(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Active {
            self.state = SubscribeNamespaceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_unsubscribe_namespace".to_string(),
            })
        }
    }

    /// Idle → Pending (a SUBSCRIBE_NAMESPACE arrived from the peer).
    ///
    /// The mirror of
    /// [`on_subscribe_namespace_sent`](Self::on_subscribe_namespace_sent),
    /// named for the direction it runs in rather than shared with it: the two
    /// state edges coincide, so a message dispatched to the wrong one of them
    /// would move the record silently instead of naming the event it was not.
    pub fn on_subscribe_namespace_received(&mut self) -> Result<(), NamespaceError> {
        self.on_subscribe_namespace_sent().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_subscribe_namespace_received".to_string(),
        })
    }

    /// Pending → Active (this endpoint accepted the peer's request with a
    /// SUBSCRIBE_NAMESPACE_OK).
    ///
    /// Section 6.1: "A publisher MUST send exactly one SUBSCRIBE_NAMESPACE_OK
    /// or SUBSCRIBE_NAMESPACE_ERROR in response to a SUBSCRIBE_NAMESPACE."
    ///
    /// One answer and no second one: the record leaves Pending on the first,
    /// and a second call finds it somewhere else.
    pub fn on_subscribe_namespace_ok_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_subscribe_namespace_ok().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_subscribe_namespace_ok_sent".to_string(),
        })
    }

    /// Pending → Done (this endpoint refused the peer's request with a
    /// SUBSCRIBE_NAMESPACE_ERROR).
    ///
    /// The other half of the same sentence: one message back, and this is the
    /// other one it can be.
    pub fn on_subscribe_namespace_error_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_subscribe_namespace_error().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_subscribe_namespace_error_sent".to_string(),
        })
    }

    /// Active → Done (the peer withdrew the namespace subscription with an
    /// UNSUBSCRIBE_NAMESPACE).
    ///
    /// Section 6.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous
    /// SUBSCRIBE_NAMESPACE."
    ///
    /// Active is the acceptance, which is the state a namespace subscription
    /// reaches by being answered SUBSCRIBE_NAMESPACE_OK and no other way, so
    /// a withdrawal of one never answered is refused here.
    pub fn on_unsubscribe_namespace_received(&mut self) -> Result<(), NamespaceError> {
        self.on_unsubscribe_namespace().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_unsubscribe_namespace_received".to_string(),
        })
    }
}

/// State machine for PUBLISH_NAMESPACE flow.
/// Idle → Pending → Active → Done.
pub struct PublishNamespaceStateMachine {
    state: PublishNamespaceState,
}

impl Default for PublishNamespaceStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishNamespaceStateMachine {
    /// Creates a new machine in [`PublishNamespaceState::Idle`].
    pub fn new() -> Self {
        Self { state: PublishNamespaceState::Idle }
    }

    /// Returns the current state of the publish-namespace flow.
    pub fn state(&self) -> PublishNamespaceState {
        self.state
    }

    /// Idle → Pending.
    pub fn on_publish_namespace_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == PublishNamespaceState::Idle {
            self.state = PublishNamespaceState::Pending;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_publish_namespace_sent".to_string(),
            })
        }
    }

    /// Pending → Active.
    pub fn on_publish_namespace_ok(&mut self) -> Result<(), NamespaceError> {
        if self.state == PublishNamespaceState::Pending {
            self.state = PublishNamespaceState::Active;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_publish_namespace_ok".to_string(),
            })
        }
    }

    /// Pending → Done.
    pub fn on_publish_namespace_error(&mut self) -> Result<(), NamespaceError> {
        if self.state == PublishNamespaceState::Pending {
            self.state = PublishNamespaceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_publish_namespace_error".to_string(),
            })
        }
    }

    /// Active → Done (publisher withdrawing).
    pub fn on_publish_namespace_done(&mut self) -> Result<(), NamespaceError> {
        if self.state == PublishNamespaceState::Active {
            self.state = PublishNamespaceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_publish_namespace_done".to_string(),
            })
        }
    }

    /// Active → Done (subscriber cancelling).
    pub fn on_publish_namespace_cancel(&mut self) -> Result<(), NamespaceError> {
        if self.state == PublishNamespaceState::Active {
            self.state = PublishNamespaceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_publish_namespace_cancel".to_string(),
            })
        }
    }
}

/// The same transitions, named for the end the advertisement arrives at.
///
/// An announcement this endpoint accepts passes through the states in the same
/// order as one it makes, with every message going the other way: the PUBLISH_NAMESPACE
/// arrives instead of leaving, the answer leaves instead of arriving, the
/// withdrawal arrives and the cancellation leaves. Sharing the transitions and
/// not the names is what lets a refusal say which event was refused, rather
/// than naming the mirror image of it.
impl PublishNamespaceStateMachine {
    /// Idle -> Pending (PUBLISH_NAMESPACE received from the peer).
    pub fn on_publish_namespace_received(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_sent().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_received".to_string(),
        })
    }

    /// Pending -> Active (PUBLISH_NAMESPACE_OK sent, accepting the announcement).
    pub fn on_publish_namespace_ok_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_ok().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_ok_sent".to_string(),
        })
    }

    /// Pending -> Done (PUBLISH_NAMESPACE_ERROR sent, refusing the announcement).
    pub fn on_publish_namespace_error_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_error().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_error_sent".to_string(),
        })
    }

    /// Active -> Done (PUBLISH_NAMESPACE_DONE received, the peer withdrawing).
    pub fn on_publish_namespace_done_received(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_done().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_done_received".to_string(),
        })
    }

    /// Active -> Done (PUBLISH_NAMESPACE_CANCEL sent, revoking an acceptance).
    ///
    /// Active is the acceptance: it is the state an announcement reaches by
    /// being answered PUBLISH_NAMESPACE_OK and no other way, which is why a cancellation
    /// of one never answered is refused here rather than sent.
    pub fn on_publish_namespace_cancel_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_cancel().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_cancel_sent".to_string(),
        })
    }
}

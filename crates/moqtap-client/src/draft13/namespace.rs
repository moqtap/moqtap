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

/// ANNOUNCE lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceState {
    /// Initial state before any message is sent.
    Idle,
    /// ANNOUNCE has been sent; awaiting ANNOUNCE_OK or ANNOUNCE_ERROR.
    Pending,
    /// Namespace publication is accepted and active.
    Active,
    /// Namespace publication has ended (UNANNOUNCE or cancel).
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

/// State machine for the SUBSCRIBE_NAMESPACE flow.
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

    /// Returns the current state.
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

    /// Active → Done (UNSUBSCRIBE_ANNOUNCES sent).
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
    /// Section 5.1: "A publisher MUST send exactly one SUBSCRIBE_NAMESPACE_OK
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
    /// Section 5.1: "An UNSUBSCRIBE_NAMESPACE withdraws a previous
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

/// State machine for the ANNOUNCE flow.
/// Idle → Pending → Active → Done.
pub struct AnnounceStateMachine {
    state: AnnounceState,
}

impl Default for AnnounceStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnnounceStateMachine {
    /// Creates a new machine in [`AnnounceState::Idle`].
    pub fn new() -> Self {
        Self { state: AnnounceState::Idle }
    }

    /// Returns the current state.
    pub fn state(&self) -> AnnounceState {
        self.state
    }

    /// Idle → Pending (ANNOUNCE sent).
    pub fn on_announce_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Idle {
            self.state = AnnounceState::Pending;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_sent".to_string(),
            })
        }
    }

    /// Pending → Active (ANNOUNCE_OK received).
    pub fn on_announce_ok(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Pending {
            self.state = AnnounceState::Active;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_ok".to_string(),
            })
        }
    }

    /// Pending → Done (ANNOUNCE_ERROR received).
    pub fn on_announce_error(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Pending {
            self.state = AnnounceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_error".to_string(),
            })
        }
    }

    /// Active → Done (UNANNOUNCE sent — publisher withdrawing).
    pub fn on_unannounce(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Active {
            self.state = AnnounceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_unannounce".to_string(),
            })
        }
    }

    /// Active → Done (ANNOUNCE_CANCEL received — subscriber cancelling).
    pub fn on_announce_cancel(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Active {
            self.state = AnnounceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_cancel".to_string(),
            })
        }
    }
}

/// The same transitions, named for the end the advertisement arrives at.
///
/// An announcement this endpoint accepts passes through the states in the same
/// order as one it makes, with every message going the other way: the ANNOUNCE
/// arrives instead of leaving, the answer leaves instead of arriving, the
/// withdrawal arrives and the cancellation leaves. Sharing the transitions and
/// not the names is what lets a refusal say which event was refused, rather
/// than naming the mirror image of it.
impl AnnounceStateMachine {
    /// Idle -> Pending (ANNOUNCE received from the peer).
    pub fn on_announce_received(&mut self) -> Result<(), NamespaceError> {
        self.on_announce_sent().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_announce_received".to_string(),
        })
    }

    /// Pending -> Active (ANNOUNCE_OK sent, accepting the announcement).
    pub fn on_announce_ok_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_announce_ok().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_announce_ok_sent".to_string(),
        })
    }

    /// Pending -> Done (ANNOUNCE_ERROR sent, refusing the announcement).
    pub fn on_announce_error_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_announce_error().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_announce_error_sent".to_string(),
        })
    }

    /// Active -> Done (UNANNOUNCE received, the peer withdrawing).
    pub fn on_unannounce_received(&mut self) -> Result<(), NamespaceError> {
        self.on_unannounce().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_unannounce_received".to_string(),
        })
    }

    /// Active -> Done (ANNOUNCE_CANCEL sent, revoking an acceptance).
    ///
    /// Active is the acceptance: it is the state an announcement reaches by
    /// being answered ANNOUNCE_OK and no other way, which is why a cancellation
    /// of one never answered is refused here rather than sent.
    pub fn on_announce_cancel_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_announce_cancel().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_announce_cancel_sent".to_string(),
        })
    }
}

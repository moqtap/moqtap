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
/// Idle -> Pending -> Active -> Done.
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

    /// Idle -> Pending.
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

    /// Pending -> Active.
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

    /// Pending -> Done.
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

    /// Pending | Active -> Done, Done -> Done (this request's stream was
    /// cancelled).
    ///
    /// This draft has no UNSUBSCRIBE_NAMESPACE message. Section 3.3.1: "Once a request
    /// stream has been opened, the request MAY be cancelled by either endpoint."
    ///
    /// `Idle` is refused, on the other half of the same sentence: nothing has
    /// been written, so there is no stream to terminate. `Done` stays `Done` —
    /// nothing finishes a request stream's send half on the ordinary path, so a
    /// caller that walks away from a request that has already ended still
    /// resets the stream, and that reset is an ordinary end rather than a
    /// fault.
    pub fn on_request_cancelled(&mut self) -> Result<(), NamespaceError> {
        match self.state {
            SubscribeNamespaceState::Pending | SubscribeNamespaceState::Active => {
                self.state = SubscribeNamespaceState::Done;
                Ok(())
            }
            SubscribeNamespaceState::Done => Ok(()),
            SubscribeNamespaceState::Idle => Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_request_cancelled".to_string(),
            }),
        }
    }
}

/// State machine for PUBLISH_NAMESPACE flow.
/// Idle -> Pending -> Active -> Done.
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

    /// Idle -> Pending.
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

    /// Pending -> Active.
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

    /// Pending -> Done.
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

    /// Pending | Active -> Done, Done -> Done (this request's stream was
    /// cancelled).
    ///
    /// This draft has neither PUBLISH_NAMESPACE_DONE nor
    /// PUBLISH_NAMESPACE_CANCEL: a publisher withdraws its advertisement, and a
    /// receiver refuses one, by terminating the stream the PUBLISH_NAMESPACE
    /// opened. Section 3.3.1: "Once a request
    /// stream has been opened, the request MAY be cancelled by either endpoint."
    ///
    /// `Idle` is refused, on the other half of the same sentence: nothing has
    /// been written, so there is no stream to terminate. `Done` stays `Done` —
    /// nothing finishes a request stream's send half on the ordinary path, so a
    /// caller that walks away from a request that has already ended still
    /// resets the stream, and that reset is an ordinary end rather than a
    /// fault.
    pub fn on_request_cancelled(&mut self) -> Result<(), NamespaceError> {
        match self.state {
            PublishNamespaceState::Pending | PublishNamespaceState::Active => {
                self.state = PublishNamespaceState::Done;
                Ok(())
            }
            PublishNamespaceState::Done => Ok(()),
            PublishNamespaceState::Idle => Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_request_cancelled".to_string(),
            }),
        }
    }
}

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

    /// Pending | Active -> Done, Done -> Done (this subscription's stream was
    /// closed).
    ///
    /// Draft-16 has no UNSUBSCRIBE_NAMESPACE. The subscription is withdrawn by
    /// ending the stream it was made on — Section 6.1: "A SUBSCRIBE_NAMESPACE
    /// can be cancelled by closing the stream with either a FIN or
    /// RESET_STREAM." Either form is a withdrawal, so both arrive here.
    ///
    /// `Pending` is accepted because the stream is open from the
    /// SUBSCRIBE_NAMESPACE that opened it, and the sentence asks for nothing
    /// more: a namespace subscription can be withdrawn before it is ever
    /// answered.
    ///
    /// `Idle` is refused, on the other half of the same sentence: nothing has
    /// been written, so there is no stream to close. `Done` stays `Done` — a
    /// subscription that has already ended is still carried on a stream, and
    /// closing that stream afterwards is the ordinary end rather than a fault.
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

    /// Idle -> Pending (the peer opened a stream with a SUBSCRIBE_NAMESPACE on
    /// it).
    ///
    /// The mirror of [`on_subscribe_namespace_sent`](Self::on_subscribe_namespace_sent),
    /// named for the direction it runs in rather than sharing that one: the
    /// state edges coincide, so a mis-dispatch would succeed silently instead
    /// of naming the wrong event in an `InvalidTransition`.
    pub fn on_subscribe_namespace_received(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Idle {
            self.state = SubscribeNamespaceState::Pending;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_namespace_received".to_string(),
            })
        }
    }

    /// Pending -> Active (this endpoint answered the peer's request with a
    /// REQUEST_OK).
    pub fn on_subscribe_namespace_ok_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Pending {
            self.state = SubscribeNamespaceState::Active;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_namespace_ok_sent".to_string(),
            })
        }
    }

    /// Pending -> Done (this endpoint refused the peer's request).
    pub fn on_subscribe_namespace_error_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeNamespaceState::Pending {
            self.state = SubscribeNamespaceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_namespace_error_sent".to_string(),
            })
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

    /// Active -> Done (publisher withdrawing).
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

    /// Active -> Done (subscriber cancelling).
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

    /// Pending -> Active (REQUEST_OK sent, accepting the announcement).
    pub fn on_publish_namespace_ok_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_ok().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_ok_sent".to_string(),
        })
    }

    /// Pending -> Done (REQUEST_ERROR sent, refusing the announcement).
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
    /// being answered REQUEST_OK and no other way, which is why a cancellation
    /// of one never answered is refused here rather than sent.
    pub fn on_publish_namespace_cancel_sent(&mut self) -> Result<(), NamespaceError> {
        self.on_publish_namespace_cancel().map_err(|_| NamespaceError::InvalidTransition {
            from: format!("{:?}", self.state()),
            event: "on_publish_namespace_cancel_sent".to_string(),
        })
    }
}

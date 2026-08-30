/// Publish lifecycle states (publisher side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishState {
    /// Initial state before any PUBLISH message is sent.
    Idle,
    /// PUBLISH has been sent; awaiting OK or ERROR.
    Publishing,
    /// PUBLISH_OK received; the track is being published.
    Active,
    /// Publish has ended (error, cancellation, or PUBLISH_DONE sent).
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

/// Pure state machine for a MoQT publish request (publisher side).
/// Transitions: Idle -> Publishing -> Active -> Done.
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

    /// Returns the current state of the publish request.
    pub fn state(&self) -> PublishState {
        self.state
    }

    /// Idle -> Publishing (PUBLISH sent).
    pub fn on_publish_sent(&mut self) -> Result<(), PublishError> {
        if self.state == PublishState::Idle {
            self.state = PublishState::Publishing;
            Ok(())
        } else {
            Err(PublishError::InvalidTransition {
                from: self.state,
                event: "on_publish_sent".to_string(),
            })
        }
    }

    /// Publishing -> Active (PUBLISH_OK received).
    pub fn on_publish_ok(&mut self) -> Result<(), PublishError> {
        if self.state == PublishState::Publishing {
            self.state = PublishState::Active;
            Ok(())
        } else {
            Err(PublishError::InvalidTransition {
                from: self.state,
                event: "on_publish_ok".to_string(),
            })
        }
    }

    /// Publishing -> Done (REQUEST_ERROR received).
    pub fn on_publish_error(&mut self) -> Result<(), PublishError> {
        if self.state == PublishState::Publishing {
            self.state = PublishState::Done;
            Ok(())
        } else {
            Err(PublishError::InvalidTransition {
                from: self.state,
                event: "on_publish_error".to_string(),
            })
        }
    }

    /// Active -> Done (PUBLISH_DONE sent by publisher).
    pub fn on_publish_done_sent(&mut self) -> Result<(), PublishError> {
        if self.state == PublishState::Active {
            self.state = PublishState::Done;
            Ok(())
        } else {
            Err(PublishError::InvalidTransition {
                from: self.state,
                event: "on_publish_done_sent".to_string(),
            })
        }
    }

    /// Publishing | Active -> Done, Done -> Done (this request's stream was
    /// cancelled).
    ///
    /// PUBLISH_DONE ends a publication the receiver accepted. This is the
    /// request itself being withdrawn, which this draft puts at the stream —
    /// Section 3.3.1: "Once a request
    /// stream has been opened, the request MAY be cancelled by either endpoint."
    ///
    /// `Idle` is refused, on the other half of the same sentence: nothing has
    /// been written, so there is no stream to terminate. `Done` stays `Done` —
    /// nothing finishes a request stream's send half on the ordinary path, so a
    /// caller that walks away from a request that has already ended still
    /// resets the stream, and that reset is an ordinary end rather than a
    /// fault.
    pub fn on_request_cancelled(&mut self) -> Result<(), PublishError> {
        match self.state {
            PublishState::Publishing | PublishState::Active => {
                self.state = PublishState::Done;
                Ok(())
            }
            PublishState::Done => Ok(()),
            PublishState::Idle => Err(PublishError::InvalidTransition {
                from: self.state,
                event: "on_request_cancelled".to_string(),
            }),
        }
    }
}

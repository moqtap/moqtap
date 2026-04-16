/// Fetch lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchState {
    /// Initial state before any FETCH message is sent.
    Idle,
    /// FETCH has been sent; awaiting OK or ERROR.
    Pending,
    /// FETCH_OK received; data is being received on the stream.
    Receiving,
    /// Fetch has ended (error, cancel, FIN, or reset).
    Done,
}

/// Errors that can occur during fetch state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FetchError {
    /// An event was received that is not valid for the current state.
    #[error("invalid transition from {from:?} on event {event}")]
    InvalidTransition {
        /// The state the machine was in when the invalid event arrived.
        from: FetchState,
        /// The name of the event that was rejected.
        event: String,
    },
}

/// Pure state machine for a MoQT fetch request.
/// Transitions: Idle -> Pending -> Receiving -> Done.
pub struct FetchStateMachine {
    state: FetchState,
}

impl Default for FetchStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl FetchStateMachine {
    /// Creates a new state machine in the [`FetchState::Idle`] state.
    pub fn new() -> Self {
        Self { state: FetchState::Idle }
    }

    /// Returns the current state of the fetch request.
    pub fn state(&self) -> FetchState {
        self.state
    }

    /// Idle -> Pending (FETCH sent).
    pub fn on_fetch_sent(&mut self) -> Result<(), FetchError> {
        if self.state == FetchState::Idle {
            self.state = FetchState::Pending;
            Ok(())
        } else {
            Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_sent".to_string(),
            })
        }
    }

    /// Pending -> Receiving (FETCH_OK received).
    pub fn on_fetch_ok(&mut self) -> Result<(), FetchError> {
        if self.state == FetchState::Pending {
            self.state = FetchState::Receiving;
            Ok(())
        } else {
            Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_ok".to_string(),
            })
        }
    }

    /// Pending -> Done (REQUEST_ERROR received).
    pub fn on_fetch_error(&mut self) -> Result<(), FetchError> {
        if self.state == FetchState::Pending {
            self.state = FetchState::Done;
            Ok(())
        } else {
            Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_error".to_string(),
            })
        }
    }

    /// Pending|Receiving -> Done (FETCH_CANCEL sent).
    pub fn on_fetch_cancel(&mut self) -> Result<(), FetchError> {
        if self.state == FetchState::Pending || self.state == FetchState::Receiving {
            self.state = FetchState::Done;
            Ok(())
        } else {
            Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_cancel".to_string(),
            })
        }
    }

    /// Receiving -> Done (stream FIN received).
    pub fn on_stream_fin(&mut self) -> Result<(), FetchError> {
        if self.state == FetchState::Receiving {
            self.state = FetchState::Done;
            Ok(())
        } else {
            Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_stream_fin".to_string(),
            })
        }
    }

    /// Receiving -> Done (stream RESET received).
    pub fn on_stream_reset(&mut self) -> Result<(), FetchError> {
        if self.state == FetchState::Receiving {
            self.state = FetchState::Done;
            Ok(())
        } else {
            Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_stream_reset".to_string(),
            })
        }
    }
}

/// TrackStatus lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackStatusState {
    /// Initial state before any TRACK_STATUS message is sent.
    Idle,
    /// TRACK_STATUS has been sent; awaiting OK or ERROR.
    Pending,
    /// Track status request has completed.
    Done,
}

/// Errors that can occur during track status state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrackStatusError {
    /// An event was received that is not valid for the current state.
    #[error("invalid transition from {from:?} on event {event}")]
    InvalidTransition {
        /// The state the machine was in when the invalid event arrived.
        from: TrackStatusState,
        /// The name of the event that was rejected.
        event: String,
    },
}

/// Pure state machine for a MoQT track status request.
/// Transitions: Idle -> Pending -> Done.
pub struct TrackStatusStateMachine {
    state: TrackStatusState,
}

impl Default for TrackStatusStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl TrackStatusStateMachine {
    /// Creates a new state machine in the [`TrackStatusState::Idle`] state.
    pub fn new() -> Self {
        Self { state: TrackStatusState::Idle }
    }

    /// Returns the current state of the track status request.
    pub fn state(&self) -> TrackStatusState {
        self.state
    }

    /// Idle -> Pending (TRACK_STATUS sent).
    pub fn on_track_status_sent(&mut self) -> Result<(), TrackStatusError> {
        if self.state == TrackStatusState::Idle {
            self.state = TrackStatusState::Pending;
            Ok(())
        } else {
            Err(TrackStatusError::InvalidTransition {
                from: self.state,
                event: "on_track_status_sent".to_string(),
            })
        }
    }

    /// Pending -> Done (REQUEST_OK received).
    pub fn on_track_status_ok(&mut self) -> Result<(), TrackStatusError> {
        if self.state == TrackStatusState::Pending {
            self.state = TrackStatusState::Done;
            Ok(())
        } else {
            Err(TrackStatusError::InvalidTransition {
                from: self.state,
                event: "on_track_status_ok".to_string(),
            })
        }
    }

    /// Pending -> Done (REQUEST_ERROR received).
    pub fn on_track_status_error(&mut self) -> Result<(), TrackStatusError> {
        if self.state == TrackStatusState::Pending {
            self.state = TrackStatusState::Done;
            Ok(())
        } else {
            Err(TrackStatusError::InvalidTransition {
                from: self.state,
                event: "on_track_status_error".to_string(),
            })
        }
    }
}

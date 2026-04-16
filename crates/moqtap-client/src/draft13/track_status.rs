/// TrackStatus lifecycle states (draft-12).
///
/// TRACK_STATUS is a single request/response pair:
/// the requester sends TRACK_STATUS_REQUEST, and the publisher
/// replies with TRACK_STATUS. There are no OK / ERROR variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackStatusState {
    /// Initial state before any TRACK_STATUS_REQUEST is sent.
    Idle,
    /// TRACK_STATUS_REQUEST has been sent; awaiting TRACK_STATUS reply.
    Pending,
    /// Track status reply received.
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

/// Pure state machine for a MoQT track status request (draft-12).
/// Transitions: Idle → Pending → Done.
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

    /// Idle → Pending (TRACK_STATUS_REQUEST sent).
    pub fn on_track_status_request_sent(&mut self) -> Result<(), TrackStatusError> {
        if self.state == TrackStatusState::Idle {
            self.state = TrackStatusState::Pending;
            Ok(())
        } else {
            Err(TrackStatusError::InvalidTransition {
                from: self.state,
                event: "on_track_status_request_sent".to_string(),
            })
        }
    }

    /// Pending → Done (TRACK_STATUS received).
    pub fn on_track_status(&mut self) -> Result<(), TrackStatusError> {
        if self.state == TrackStatusState::Pending {
            self.state = TrackStatusState::Done;
            Ok(())
        } else {
            Err(TrackStatusError::InvalidTransition {
                from: self.state,
                event: "on_track_status".to_string(),
            })
        }
    }
}

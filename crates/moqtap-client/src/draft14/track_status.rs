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

    /// Idle → Pending (TRACK_STATUS sent).
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

    /// Pending → Done (TRACK_STATUS_OK received).
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

    /// Pending → Done (TRACK_STATUS_ERROR received).
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

/// The same transitions, named for the end the request arrives at.
///
/// A track status the peer asks for passes through the states in the same
/// order as one this endpoint asks for, with every message going the other
/// way: the request arrives instead of leaving and the answer leaves instead
/// of arriving. Sharing the transitions and not the names is what lets a
/// refusal say which event was refused rather than the mirror image of it.
///
/// Section 9.20 says what the arriving request is: the receiver "treats it
/// identically as if it had received a SUBSCRIBE message, except it does not
/// create downstream subscription state or send any Objects". Identical
/// treatment and no subscription state is why the request gets a machine of
/// this kind rather than a subscription's, and why what it opens is a record
/// of its own rather than an entry among the subscriptions the peer holds.
impl TrackStatusStateMachine {
    /// Idle → Pending (TRACK_STATUS received).
    pub fn on_track_status_received(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_sent().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_received".to_string(),
        })
    }

    /// Pending → Done (TRACK_STATUS_OK sent).
    pub fn on_track_status_ok_sent(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_ok().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_ok_sent".to_string(),
        })
    }

    /// Pending → Done (TRACK_STATUS_ERROR sent).
    pub fn on_track_status_error_sent(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_error().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_error_sent".to_string(),
        })
    }
}

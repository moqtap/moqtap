/// TrackStatus lifecycle states (draft-10).
///
/// Draft-10 TRACK_STATUS is a single request/response pair:
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

/// Pure state machine for a MoQT track status request (draft-10).
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

/// The same transitions, named for the end the request arrives at.
///
/// A track status the peer asks for passes through the states in the same
/// order as one this endpoint asks for, with both messages going the other
/// way: the request arrives instead of leaving, and the answer leaves instead
/// of arriving. Sharing the transitions and not the names is what lets a
/// refusal say which event was refused rather than the mirror image of it.
///
/// Section 8.16 leaves the answering end no discretion about whether to
/// answer: "A TRACK_STATUS message MUST be sent in response to each
/// TRACK_STATUS_REQUEST." What it bounds is how many, and that is what `Done`
/// is for: a second answer finds a request that has already left `Pending`.
impl TrackStatusStateMachine {
    /// Idle → Pending (TRACK_STATUS_REQUEST received).
    pub fn on_track_status_request_received(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status_request_sent().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_request_received".to_string(),
        })
    }

    /// Pending → Done (TRACK_STATUS sent).
    pub fn on_track_status_sent(&mut self) -> Result<(), TrackStatusError> {
        self.on_track_status().map_err(|_| TrackStatusError::InvalidTransition {
            from: self.state(),
            event: "on_track_status_sent".to_string(),
        })
    }
}

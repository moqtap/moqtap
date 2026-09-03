/// Fetch lifecycle states.
///
/// A fetch settles two things and settles them independently: the publisher's
/// answer, which arrives on the control stream, and the response stream that
/// carries the objects. Section 10.14: "A publisher MAY send Objects in
/// response to a FETCH before the FETCH_OK message is sent, but the FETCH_OK
/// MUST NOT be sent until the End Location is known."
///
/// Section 10.13 states the other direction of the same freedom: "The
/// FETCH_OK or REQUEST_ERROR can come at any time relative to object delivery."
/// So the fetch is over when both have settled, in whichever order they settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchState {
    /// Initial state before any FETCH message is sent.
    Idle,
    /// FETCH has been sent; the answer is owed and the response stream
    /// has not ended.
    Pending,
    /// FETCH_OK received; data is being received on the stream.
    Receiving,
    /// The response stream has ended and the answer is still owed.
    Unanswered,
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
/// Transitions: Idle -> Pending -> Receiving -> Done when the answer comes
/// first, and Idle -> Pending -> Unanswered -> Done when the response stream
/// ends first.
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
        match self.state {
            FetchState::Idle => {
                self.state = FetchState::Pending;
                Ok(())
            }
            _ => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_sent".to_string(),
            }),
        }
    }

    /// Pending -> Receiving, Unanswered -> Done (FETCH_OK received).
    ///
    /// From Unanswered the objects have already been delivered, so the FETCH_OK
    /// describing them is the last thing the fetch was waiting for.
    pub fn on_fetch_ok(&mut self) -> Result<(), FetchError> {
        match self.state {
            FetchState::Pending => {
                self.state = FetchState::Receiving;
                Ok(())
            }
            FetchState::Unanswered => {
                self.state = FetchState::Done;
                Ok(())
            }
            _ => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_ok".to_string(),
            }),
        }
    }

    /// Pending | Unanswered -> Done (REQUEST_ERROR received).
    pub fn on_fetch_error(&mut self) -> Result<(), FetchError> {
        match self.state {
            FetchState::Pending | FetchState::Unanswered => {
                self.state = FetchState::Done;
                Ok(())
            }
            _ => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_error".to_string(),
            }),
        }
    }

    /// Pending | Receiving | Unanswered -> Done, Done -> Done (this fetch's
    /// request stream was cancelled).
    ///
    /// This draft carries no FETCH_CANCEL message. Section 3.3.3: "Once a request
    /// stream has been opened, the request MAY be cancelled by either endpoint."
    ///
    /// `Idle` is refused, on the other half of the same sentence: nothing has
    /// been written, so there is no stream to terminate. `Done` stays `Done` —
    /// nothing finishes a request stream's send half on the ordinary path, so a
    /// caller that walks away from a request that has already ended still
    /// resets the stream, and that reset is an ordinary end rather than a
    /// fault.
    pub fn on_request_cancelled(&mut self) -> Result<(), FetchError> {
        match self.state {
            FetchState::Pending | FetchState::Receiving | FetchState::Unanswered => {
                self.state = FetchState::Done;
                Ok(())
            }
            FetchState::Done => Ok(()),
            FetchState::Idle => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_request_cancelled".to_string(),
            }),
        }
    }

    /// Receiving -> Done, Pending -> Unanswered (stream FIN received).
    ///
    /// A fetch that has already ended ignores the close of its response stream,
    /// whichever of QUIC's two endings it is. Section 10.13: a relay whose
    /// upstream FETCH failed "sends a REQUEST_ERROR and can reset the
    /// unidirectional stream", and may "wait until the cached objects have been
    /// delivered before resetting the stream", so that close arrives after the
    /// error ended the fetch. This draft has no FETCH_CANCEL message; Section
    /// 3.3.3 cancels a request by terminating the directions of its stream,
    /// which reaches this machine the same way.
    pub fn on_stream_fin(&mut self) -> Result<(), FetchError> {
        match self.state {
            FetchState::Receiving => {
                self.state = FetchState::Done;
                Ok(())
            }
            FetchState::Pending => {
                self.state = FetchState::Unanswered;
                Ok(())
            }
            FetchState::Done => Ok(()),
            _ => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_stream_fin".to_string(),
            }),
        }
    }

    /// Receiving -> Done, Pending -> Unanswered (stream RESET received).
    ///
    /// The same tolerance of a late close as
    /// [`FetchStateMachine::on_stream_fin`], for the same reason.
    pub fn on_stream_reset(&mut self) -> Result<(), FetchError> {
        match self.state {
            FetchState::Receiving => {
                self.state = FetchState::Done;
                Ok(())
            }
            FetchState::Pending => {
                self.state = FetchState::Unanswered;
                Ok(())
            }
            FetchState::Done => Ok(()),
            _ => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_stream_reset".to_string(),
            }),
        }
    }
}

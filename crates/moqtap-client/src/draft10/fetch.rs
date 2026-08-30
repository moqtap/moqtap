/// Fetch lifecycle states.
///
/// A fetch settles two things and settles them independently: the publisher's
/// answer, which arrives on the control stream, and the response stream that
/// carries the objects. Section 8.13: "A publisher MAY send Objects in response
/// to a FETCH before the FETCH_OK message is sent, but the FETCH_OK MUST NOT be
/// sent until the latest group and object are known."
///
/// Section 8.12 says what that freedom is for: a relay "MAY start sending
/// objects immediately in response to a FETCH, even if sending the FETCH_OK
/// takes longer because it requires going upstream to populate the latest
/// object." So the fetch is over when both have settled, in whichever order
/// they settle.
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
/// Transitions: Idle → Pending → Receiving → Done when the answer comes first,
/// and Idle → Pending → Unanswered → Done when the response stream ends first.
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

    /// Idle → Pending (FETCH sent).
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

    /// Pending → Receiving, Unanswered → Done (FETCH_OK received).
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

    /// Pending | Unanswered → Done (FETCH_ERROR received).
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

    /// Pending | Receiving | Unanswered → Done (FETCH_CANCEL sent).
    pub fn on_fetch_cancel(&mut self) -> Result<(), FetchError> {
        match self.state {
            FetchState::Pending | FetchState::Receiving | FetchState::Unanswered => {
                self.state = FetchState::Done;
                Ok(())
            }
            _ => Err(FetchError::InvalidTransition {
                from: self.state,
                event: "on_fetch_cancel".to_string(),
            }),
        }
    }

    /// Receiving → Done, Pending → Unanswered (stream FIN received).
    ///
    /// A fetch that has already ended ignores the close of its response stream,
    /// whichever of QUIC's two endings it is. Section 8.15: the publisher of a
    /// cancelled fetch "SHOULD close the unidirectional stream as soon as
    /// possible", and the cancel is what ended the fetch, so that close arrives
    /// afterwards.
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

    /// Receiving → Done, Pending → Unanswered (stream RESET received).
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

/// The same transitions, named for the end that serves the fetch.
///
/// A fetch this endpoint answers passes through the states in the same order
/// as one it makes, with every message going the other way: the FETCH arrives
/// instead of leaving, the answer leaves instead of arriving. Sharing the
/// transitions and not the names is what lets a refusal say which event was
/// refused, rather than naming the mirror image of it.
impl FetchStateMachine {
    /// Idle -> Pending (FETCH received from the peer).
    pub fn on_fetch_received(&mut self) -> Result<(), FetchError> {
        self.on_fetch_sent().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_received".to_string(),
        })
    }

    /// Pending -> Receiving, Unanswered -> Done (FETCH_OK sent).
    ///
    /// The state is named for the requester's view; for the end answering, the
    /// same node means the objects are being served rather than received. It is
    /// the same node in the graph, with the same edges, so it keeps its name.
    pub fn on_fetch_ok_sent(&mut self) -> Result<(), FetchError> {
        self.on_fetch_ok().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_ok_sent".to_string(),
        })
    }

    /// Pending | Unanswered -> Done (FETCH_ERROR sent).
    pub fn on_fetch_error_sent(&mut self) -> Result<(), FetchError> {
        self.on_fetch_error().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_error_sent".to_string(),
        })
    }

    /// Pending | Receiving | Unanswered -> Done (FETCH_CANCEL received).
    pub fn on_fetch_cancel_received(&mut self) -> Result<(), FetchError> {
        self.on_fetch_cancel().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_fetch_cancel_received".to_string(),
        })
    }

    /// Receiving -> Done, Pending -> Unanswered (this endpoint finished the
    /// fetch data stream).
    pub fn on_stream_fin_sent(&mut self) -> Result<(), FetchError> {
        self.on_stream_fin().map_err(|_| FetchError::InvalidTransition {
            from: self.state(),
            event: "on_stream_fin_sent".to_string(),
        })
    }
}

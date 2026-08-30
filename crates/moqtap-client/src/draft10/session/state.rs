/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state before the QUIC connection is established.
    Connecting,
    /// Exchanging CLIENT_SETUP and SERVER_SETUP messages.
    SetupExchange,
    /// Session is fully established and can exchange data.
    Active,
    /// GOAWAY received; finishing in-flight requests before closing.
    Draining,
    /// Session is terminated.
    Closed,
}

/// Errors arising from invalid session state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    /// Attempted a state transition that is not allowed.
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// The state the session was in.
        from: SessionState,
        /// The state the transition targeted.
        to: SessionState,
    },
}

/// Pure state machine for MoQT session lifecycle.
/// Transitions: Connecting → SetupExchange → Active → Draining → Closed.
pub struct SessionStateMachine {
    state: SessionState,
}

impl Default for SessionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStateMachine {
    /// Create a new state machine starting in the `Connecting` state.
    pub fn new() -> Self {
        Self { state: SessionState::Connecting }
    }

    /// Returns the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Transition: Connecting → SetupExchange.
    pub fn on_connect(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Connecting {
            self.state = SessionState::SetupExchange;
            Ok(())
        } else {
            Err(SessionError::InvalidTransition {
                from: self.state,
                to: SessionState::SetupExchange,
            })
        }
    }

    /// Transition: SetupExchange → Active.
    pub fn on_setup_complete(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::SetupExchange {
            self.state = SessionState::Active;
            Ok(())
        } else {
            Err(SessionError::InvalidTransition { from: self.state, to: SessionState::Active })
        }
    }

    /// Transition: Active → Draining (GOAWAY received).
    pub fn on_goaway(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Active {
            self.state = SessionState::Draining;
            Ok(())
        } else {
            Err(SessionError::InvalidTransition { from: self.state, to: SessionState::Draining })
        }
    }

    /// Transition: SetupExchange|Active|Draining -> Closed.
    ///
    /// draft-10 Section 3.4: "The Transport Session can be terminated at any point."
    /// Section 8.2.1 obliges an endpoint to do so during the Setup exchange itself:
    /// "If the server does not support any of the versions offered by the client, or
    /// the client receives a server version that it did not offer, the corresponding
    /// peer MUST close the session." That failure is reachable only from
    /// SetupExchange, so a session that cannot close there cannot record the one
    /// outcome the draft requires of it.
    ///
    /// Connecting is still refused: no transport session has been established, so there
    /// is nothing to terminate.
    pub fn on_close(&mut self) -> Result<(), SessionError> {
        if matches!(
            self.state,
            SessionState::SetupExchange | SessionState::Active | SessionState::Draining
        ) {
            self.state = SessionState::Closed;
            Ok(())
        } else {
            Err(SessionError::InvalidTransition { from: self.state, to: SessionState::Closed })
        }
    }
}

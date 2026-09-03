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
/// Transitions: Connecting -> SetupExchange -> Active -> Draining -> Closed.
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

    /// Transition: Connecting -> SetupExchange.
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

    /// Transition: SetupExchange -> Active.
    pub fn on_setup_complete(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::SetupExchange {
            self.state = SessionState::Active;
            Ok(())
        } else {
            Err(SessionError::InvalidTransition { from: self.state, to: SessionState::Active })
        }
    }

    /// Transition: Active -> Draining (GOAWAY received).
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
    /// draft-20 Section 3.5: "The Transport Session can be terminated at any point."
    ///
    /// SetupExchange is accepted, and draft-20 removes the code that made the
    /// case obvious rather than the case itself. Draft-19's Section 3.5 listed
    /// VERSION_NEGOTIATION_FAILED (0x15), "The client didn't offer a version
    /// supported by the server" — a failure reachable only from SetupExchange,
    /// before any session is Active. Draft-20 deleted the row, because from
    /// draft-15 on there is no version on the wire to fail to negotiate: the
    /// draft is the ALPN and a mismatch ends the TLS handshake before a MoQT
    /// session exists. What survives is every other reason a setup exchange can
    /// end — a PATH from a server, a malformed SETUP, a peer that goes away —
    /// and a session that could not close in SetupExchange could record none of
    /// them.
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

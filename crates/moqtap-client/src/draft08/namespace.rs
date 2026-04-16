/// SUBSCRIBE_ANNOUNCES lifecycle states (draft-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeAnnouncesState {
    /// Initial state before any message is sent.
    Idle,
    /// SUBSCRIBE_ANNOUNCES has been sent; awaiting OK or ERROR.
    Pending,
    /// Namespace subscription is accepted and active.
    Active,
    /// Namespace subscription has ended.
    Done,
}

/// ANNOUNCE lifecycle states (draft-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceState {
    /// Initial state before any message is sent.
    Idle,
    /// ANNOUNCE has been sent; awaiting ANNOUNCE_OK or ANNOUNCE_ERROR.
    Pending,
    /// Namespace publication is accepted and active.
    Active,
    /// Namespace publication has ended (UNANNOUNCE or cancel).
    Done,
}

/// Errors that can occur during namespace state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NamespaceError {
    /// An event was received that is not valid for the current state.
    #[error("invalid transition from {from} on event {event}")]
    InvalidTransition {
        /// The state the machine was in when the invalid event arrived.
        from: String,
        /// The name of the event that was rejected.
        event: String,
    },
}

/// State machine for the SUBSCRIBE_ANNOUNCES flow (draft-08).
/// Idle → Pending → Active → Done.
pub struct SubscribeAnnouncesStateMachine {
    state: SubscribeAnnouncesState,
}

impl Default for SubscribeAnnouncesStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscribeAnnouncesStateMachine {
    /// Creates a new machine in [`SubscribeAnnouncesState::Idle`].
    pub fn new() -> Self {
        Self { state: SubscribeAnnouncesState::Idle }
    }

    /// Returns the current state.
    pub fn state(&self) -> SubscribeAnnouncesState {
        self.state
    }

    /// Idle → Pending.
    pub fn on_subscribe_announces_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeAnnouncesState::Idle {
            self.state = SubscribeAnnouncesState::Pending;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_announces_sent".to_string(),
            })
        }
    }

    /// Pending → Active.
    pub fn on_subscribe_announces_ok(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeAnnouncesState::Pending {
            self.state = SubscribeAnnouncesState::Active;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_announces_ok".to_string(),
            })
        }
    }

    /// Pending → Done.
    pub fn on_subscribe_announces_error(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeAnnouncesState::Pending {
            self.state = SubscribeAnnouncesState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_subscribe_announces_error".to_string(),
            })
        }
    }

    /// Active → Done (UNSUBSCRIBE_ANNOUNCES sent).
    pub fn on_unsubscribe_announces(&mut self) -> Result<(), NamespaceError> {
        if self.state == SubscribeAnnouncesState::Active {
            self.state = SubscribeAnnouncesState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_unsubscribe_announces".to_string(),
            })
        }
    }
}

/// State machine for the ANNOUNCE flow (draft-08).
/// Idle → Pending → Active → Done.
pub struct AnnounceStateMachine {
    state: AnnounceState,
}

impl Default for AnnounceStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnnounceStateMachine {
    /// Creates a new machine in [`AnnounceState::Idle`].
    pub fn new() -> Self {
        Self { state: AnnounceState::Idle }
    }

    /// Returns the current state.
    pub fn state(&self) -> AnnounceState {
        self.state
    }

    /// Idle → Pending (ANNOUNCE sent).
    pub fn on_announce_sent(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Idle {
            self.state = AnnounceState::Pending;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_sent".to_string(),
            })
        }
    }

    /// Pending → Active (ANNOUNCE_OK received).
    pub fn on_announce_ok(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Pending {
            self.state = AnnounceState::Active;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_ok".to_string(),
            })
        }
    }

    /// Pending → Done (ANNOUNCE_ERROR received).
    pub fn on_announce_error(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Pending {
            self.state = AnnounceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_error".to_string(),
            })
        }
    }

    /// Active → Done (UNANNOUNCE sent — publisher withdrawing).
    pub fn on_unannounce(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Active {
            self.state = AnnounceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_unannounce".to_string(),
            })
        }
    }

    /// Active → Done (ANNOUNCE_CANCEL received — subscriber cancelling).
    pub fn on_announce_cancel(&mut self) -> Result<(), NamespaceError> {
        if self.state == AnnounceState::Active {
            self.state = AnnounceState::Done;
            Ok(())
        } else {
            Err(NamespaceError::InvalidTransition {
                from: format!("{:?}", self.state),
                event: "on_announce_cancel".to_string(),
            })
        }
    }
}

use std::collections::HashMap;

use crate::draft09::fetch::{FetchError, FetchStateMachine};
use crate::draft09::namespace::{
    AnnounceStateMachine, NamespaceError, SubscribeAnnouncesStateMachine,
};
use crate::draft09::session::setup::{self, SetupError};
use crate::draft09::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft09::session::subscribe_id::{SubscribeIdAllocator, SubscribeIdError};
use crate::draft09::subscription::{SubscriptionError, SubscriptionStateMachine};
use crate::draft09::track_status::{TrackStatusError, TrackStatusStateMachine};
use moqtap_codec::draft09::message::{
    self, Announce, AnnounceCancel, AnnounceError, AnnounceOk, ClientSetup, ControlMessage, Fetch,
    FetchCancel, FetchType, GoAway, MaxSubscribeId, ServerSetup, Subscribe, SubscribeAnnounces,
    SubscribeAnnouncesError, SubscribeAnnouncesOk, SubscribeDone, SubscribeError, SubscribeOk,
    SubscribeUpdate, SubscribesBlocked, TrackStatus, TrackStatusRequest, Unannounce, Unsubscribe,
    UnsubscribeAnnounces,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Key identifying a namespace (used for Announce / SubscribeAnnounces maps).
type NamespaceKey = Vec<Vec<u8>>;

/// Key identifying a track (namespace + track name).
type TrackKey = (Vec<Vec<u8>>, Vec<u8>);

/// Errors that can occur during draft-09 endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A session-level state machine error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    /// A subscribe ID allocation or validation error.
    #[error("subscribe ID error: {0}")]
    SubscribeId(#[from] SubscribeIdError),
    /// A subscription state machine error.
    #[error("subscription error: {0}")]
    Subscription(#[from] SubscriptionError),
    /// A fetch state machine error.
    #[error("fetch error: {0}")]
    Fetch(#[from] FetchError),
    /// A namespace state machine error.
    #[error("namespace error: {0}")]
    Namespace(#[from] NamespaceError),
    /// A track status state machine error.
    #[error("track status error: {0}")]
    TrackStatus(#[from] TrackStatusError),
    /// A setup negotiation error.
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),
    /// The subscribe ID does not match any known state machine.
    #[error("unknown subscribe ID: {0}")]
    UnknownSubscribe(u64),
    /// The track namespace does not match any known state machine.
    #[error("unknown namespace")]
    UnknownNamespace,
    /// The (namespace, track) pair does not match any known track status request.
    #[error("unknown track status request")]
    UnknownTrackStatus,
    /// The session is not in the Active state.
    #[error("session not active")]
    NotActive,
    /// The session is draining and cannot accept new requests.
    #[error("session is draining, no new requests allowed")]
    Draining,
}

/// Unified draft-09 MoQT endpoint wrapping session lifecycle, subscribe ID
/// allocation, and all per-flow state machines (subscriptions, fetches,
/// announces, subscribe-announces, track statuses).
pub struct Endpoint {
    session: SessionStateMachine,
    subscribe_ids: SubscribeIdAllocator,
    /// Tracks the MAX_SUBSCRIBE_ID we have advertised to the peer.
    advertised_max_id: u64,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_announces: HashMap<NamespaceKey, SubscribeAnnouncesStateMachine>,
    announces: HashMap<NamespaceKey, AnnounceStateMachine>,
    track_statuses: HashMap<TrackKey, TrackStatusStateMachine>,
    negotiated_version: Option<VarInt>,
    offered_versions: Vec<VarInt>,
    goaway_uri: Option<Vec<u8>>,
    /// The most recent `maximum_subscribe_id` reported by the peer via a
    /// `SUBSCRIBES_BLOCKED` message (draft-09 only).
    peer_reported_max_subscribe_id: Option<VarInt>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl Endpoint {
    /// Create a new draft-09 endpoint.
    pub fn new() -> Self {
        Self {
            session: SessionStateMachine::new(),
            subscribe_ids: SubscribeIdAllocator::new(),
            advertised_max_id: 0,
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            subscribe_announces: HashMap::new(),
            announces: HashMap::new(),
            track_statuses: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
            peer_reported_max_subscribe_id: None,
        }
    }

    // ── Accessors ──────────────────────────────────────────────

    /// Returns the current session state.
    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    /// Returns the negotiated MoQT version, if setup is complete.
    pub fn negotiated_version(&self) -> Option<VarInt> {
        self.negotiated_version
    }

    /// Returns the URI from a received GOAWAY message, if any.
    pub fn goaway_uri(&self) -> Option<&[u8]> {
        self.goaway_uri.as_deref()
    }

    /// Returns whether this endpoint is blocked on subscribe ID allocation.
    pub fn is_blocked(&self) -> bool {
        self.subscribe_ids.is_blocked()
    }

    /// Returns the number of active subscription state machines.
    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns the number of active fetch state machines.
    pub fn active_fetch_count(&self) -> usize {
        self.fetches.len()
    }

    /// Returns the number of active subscribe-announces state machines.
    pub fn active_subscribe_announces_count(&self) -> usize {
        self.subscribe_announces.len()
    }

    /// Returns the number of active announce state machines.
    pub fn active_announce_count(&self) -> usize {
        self.announces.len()
    }

    /// Returns the number of active track status state machines.
    pub fn active_track_status_count(&self) -> usize {
        self.track_statuses.len()
    }

    // ── Session lifecycle ──────────────────────────────────────

    /// Transition from Connecting to SetupExchange.
    pub fn connect(&mut self) -> Result<(), EndpointError> {
        self.session.on_connect()?;
        Ok(())
    }

    /// Close the session (Active or Draining -> Closed).
    pub fn close(&mut self) -> Result<(), EndpointError> {
        self.session.on_close()?;
        Ok(())
    }

    // ── Client setup ───────────────────────────────────────────

    /// Generate a CLIENT_SETUP message (client-side).
    pub fn send_client_setup(
        &mut self,
        versions: Vec<VarInt>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        self.offered_versions = versions.clone();
        let msg = ClientSetup { supported_versions: versions, parameters };
        setup::validate_client_setup(&msg)?;
        Ok(ControlMessage::ClientSetup(msg))
    }

    /// Process a SERVER_SETUP message (client-side). Transitions to Active.
    /// If the server includes a MAX_SUBSCRIBE_ID parameter (key 0x02), the
    /// subscribe ID allocator is initialized with that value.
    pub fn receive_server_setup(&mut self, msg: &ServerSetup) -> Result<(), EndpointError> {
        setup::validate_server_setup(msg)?;
        let version = setup::negotiate_version(&self.offered_versions, msg.selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        // Extract MAX_SUBSCRIBE_ID (key 0x02) from setup parameters if present
        for param in &msg.parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                if let KvpValue::Varint(v) = &param.value {
                    self.subscribe_ids.update_max(v.into_inner())?;
                }
            }
        }
        Ok(())
    }

    // ── Server setup ───────────────────────────────────────────

    /// Process CLIENT_SETUP and generate SERVER_SETUP (server-side).
    pub fn receive_client_setup_and_respond(
        &mut self,
        client_setup: &ClientSetup,
        selected_version: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        setup::validate_client_setup(client_setup)?;
        let version = setup::negotiate_version(&client_setup.supported_versions, selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        let msg = ServerSetup { selected_version: version, parameters: vec![] };
        Ok(ControlMessage::ServerSetup(msg))
    }

    // ── MAX_SUBSCRIBE_ID ───────────────────────────────────────

    /// Process an incoming MAX_SUBSCRIBE_ID message.
    pub fn receive_max_subscribe_id(&mut self, msg: &MaxSubscribeId) -> Result<(), EndpointError> {
        self.subscribe_ids.update_max(msg.subscribe_id.into_inner())?;
        Ok(())
    }

    /// Generate a MAX_SUBSCRIBE_ID message (typically server-side).
    /// The value must strictly increase over previous sends.
    pub fn send_max_subscribe_id(
        &mut self,
        max_id: VarInt,
    ) -> Result<ControlMessage, EndpointError> {
        let new_val = max_id.into_inner();
        if new_val <= self.advertised_max_id && self.advertised_max_id > 0 {
            return Err(EndpointError::SubscribeId(SubscribeIdError::Decreased(
                self.advertised_max_id,
                new_val,
            )));
        }
        self.advertised_max_id = new_val;
        Ok(ControlMessage::MaxSubscribeId(MaxSubscribeId { subscribe_id: max_id }))
    }

    // ── GoAway ─────────────────────────────────────────────────

    /// Process an incoming GOAWAY message. Transitions to Draining.
    pub fn receive_goaway(&mut self, msg: &GoAway) -> Result<(), EndpointError> {
        self.session.on_goaway()?;
        self.goaway_uri = Some(msg.new_session_uri.clone());
        Ok(())
    }

    // ── Subscribe flow ─────────────────────────────────────────

    fn require_active_or_err(&self) -> Result<(), EndpointError> {
        match self.session.state() {
            SessionState::Active => Ok(()),
            SessionState::Draining => Err(EndpointError::Draining),
            _ => Err(EndpointError::NotActive),
        }
    }

    /// Send a SUBSCRIBE message. Allocates a subscribe ID and creates a
    /// subscription state machine.
    #[allow(clippy::too_many_arguments)]
    pub fn subscribe(
        &mut self,
        track_alias: VarInt,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let sub_id = self.subscribe_ids.allocate()?;

        let mut sm = SubscriptionStateMachine::new();
        sm.on_subscribe_sent()?;
        self.subscriptions.insert(sub_id.into_inner(), sm);

        let msg = ControlMessage::Subscribe(Subscribe {
            subscribe_id: sub_id,
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            start_location: None,
            end_group: None,
            parameters: vec![],
        });
        Ok((sub_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ERROR.
    pub fn receive_subscribe_error(&mut self, msg: &SubscribeError) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE message for an active subscription.
    pub fn unsubscribe(&mut self, subscribe_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_unsubscribe()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { subscribe_id }))
    }

    /// Process an incoming SUBSCRIBE_UPDATE.
    pub fn receive_subscribe_update(&mut self, msg: &SubscribeUpdate) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_update()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_DONE (subscriber side — publisher finished).
    pub fn receive_subscribe_done(&mut self, msg: &SubscribeDone) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_subscribe_done()?;
        Ok(())
    }

    // ── Fetch flow ─────────────────────────────────────────────

    /// Send a FETCH message. Allocates a subscribe ID and creates a fetch state machine.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        end_object: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let sub_id = self.subscribe_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(sub_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            subscribe_id: sub_id,
            subscriber_priority,
            group_order,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(track_namespace),
            track_name: Some(track_name),
            start_group: Some(start_group),
            start_object: Some(start_object),
            end_group: Some(end_group),
            end_object: Some(end_object),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        });
        Ok((sub_id, msg))
    }

    /// Send a joining FETCH message that attaches to an existing subscription.
    /// Allocates a new subscribe ID for the fetch and tracks it in its own
    /// fetch state machine.
    pub fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_subscribe_id: VarInt,
        preceding_group_offset: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let sub_id = self.subscribe_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(sub_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            subscribe_id: sub_id,
            subscriber_priority,
            group_order,
            fetch_type: FetchType::Joining,
            track_namespace: None,
            track_name: None,
            start_group: None,
            start_object: None,
            end_group: None,
            end_object: None,
            joining_subscribe_id: Some(joining_subscribe_id),
            preceding_group_offset: Some(preceding_group_offset),
            parameters: vec![],
        });
        Ok((sub_id, msg))
    }

    /// Process an incoming FETCH_OK.
    pub fn receive_fetch_ok(&mut self, msg: &message::FetchOk) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    /// Process an incoming FETCH_ERROR.
    pub fn receive_fetch_error(&mut self, msg: &message::FetchError) -> Result<(), EndpointError> {
        let id = msg.subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_fetch_error()?;
        Ok(())
    }

    /// Send a FETCH_CANCEL message.
    pub fn fetch_cancel(&mut self, subscribe_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_fetch_cancel()?;
        Ok(ControlMessage::FetchCancel(FetchCancel { subscribe_id }))
    }

    /// Notify that a fetch data stream received FIN.
    pub fn on_fetch_stream_fin(&mut self, subscribe_id: VarInt) -> Result<(), EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    /// Notify that a fetch data stream was reset.
    pub fn on_fetch_stream_reset(&mut self, subscribe_id: VarInt) -> Result<(), EndpointError> {
        let id = subscribe_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownSubscribe(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // ── Subscribe Announces flow ───────────────────────────────

    /// Send a SUBSCRIBE_ANNOUNCES message.
    pub fn subscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let key = track_namespace_prefix.0.clone();
        let mut sm = SubscribeAnnouncesStateMachine::new();
        sm.on_subscribe_announces_sent()?;
        self.subscribe_announces.insert(key, sm);
        Ok(ControlMessage::SubscribeAnnounces(SubscribeAnnounces {
            track_namespace_prefix,
            parameters: vec![],
        }))
    }

    /// Process an incoming SUBSCRIBE_ANNOUNCES_OK.
    pub fn receive_subscribe_announces_ok(
        &mut self,
        msg: &SubscribeAnnouncesOk,
    ) -> Result<(), EndpointError> {
        let sm = self
            .subscribe_announces
            .get_mut(&msg.track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_subscribe_announces_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_ANNOUNCES_ERROR.
    pub fn receive_subscribe_announces_error(
        &mut self,
        msg: &SubscribeAnnouncesError,
    ) -> Result<(), EndpointError> {
        let sm = self
            .subscribe_announces
            .get_mut(&msg.track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_subscribe_announces_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE_ANNOUNCES message.
    pub fn unsubscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let sm = self
            .subscribe_announces
            .get_mut(&track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_unsubscribe_announces()?;
        Ok(ControlMessage::UnsubscribeAnnounces(UnsubscribeAnnounces { track_namespace_prefix }))
    }

    // ── Announce flow ──────────────────────────────────────────

    /// Send an ANNOUNCE message.
    pub fn announce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let key = track_namespace.0.clone();
        let mut sm = AnnounceStateMachine::new();
        sm.on_announce_sent()?;
        self.announces.insert(key, sm);
        Ok(ControlMessage::Announce(Announce { track_namespace, parameters: vec![] }))
    }

    /// Process an incoming ANNOUNCE_OK.
    pub fn receive_announce_ok(&mut self, msg: &AnnounceOk) -> Result<(), EndpointError> {
        let sm = self
            .announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_announce_ok()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_ERROR.
    pub fn receive_announce_error(&mut self, msg: &AnnounceError) -> Result<(), EndpointError> {
        let sm = self
            .announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_announce_error()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_CANCEL.
    pub fn receive_announce_cancel(&mut self, msg: &AnnounceCancel) -> Result<(), EndpointError> {
        let sm = self
            .announces
            .get_mut(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        sm.on_announce_cancel()?;
        Ok(())
    }

    /// Send an UNANNOUNCE message (publisher withdrawing).
    pub fn unannounce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let sm =
            self.announces.get_mut(&track_namespace.0).ok_or(EndpointError::UnknownNamespace)?;
        sm.on_unannounce()?;
        Ok(ControlMessage::Unannounce(Unannounce { track_namespace }))
    }

    // ── Track Status flow ──────────────────────────────────────

    /// Send a TRACK_STATUS_REQUEST message.
    pub fn track_status_request(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        self.require_active_or_err()?;
        let key = (track_namespace.0.clone(), track_name.clone());
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_request_sent()?;
        self.track_statuses.insert(key, sm);
        Ok(ControlMessage::TrackStatusRequest(TrackStatusRequest { track_namespace, track_name }))
    }

    /// Process an incoming TRACK_STATUS reply.
    pub fn receive_track_status(&mut self, msg: &TrackStatus) -> Result<(), EndpointError> {
        let key = (msg.track_namespace.0.clone(), msg.track_name.clone());
        let sm = self.track_statuses.get_mut(&key).ok_or(EndpointError::UnknownTrackStatus)?;
        sm.on_track_status()?;
        Ok(())
    }

    // ── Subscribes blocked (draft-09 new) ──────────────────────

    /// Process an incoming SUBSCRIBES_BLOCKED.
    ///
    /// Draft-09 adds this message so the peer can explicitly report that a
    /// new subscribe id would exceed our advertised maximum. The endpoint
    /// records the peer's reported maximum; acting on it (issuing a new
    /// `MAX_SUBSCRIBE_ID`) is up to the caller.
    pub fn receive_subscribes_blocked(
        &mut self,
        msg: &SubscribesBlocked,
    ) -> Result<(), EndpointError> {
        self.peer_reported_max_subscribe_id = Some(msg.maximum_subscribe_id);
        Ok(())
    }

    /// The maximum subscribe id that the peer most recently reported in a
    /// `SUBSCRIBES_BLOCKED` message, if any.
    pub fn peer_reported_max_subscribe_id(&self) -> Option<VarInt> {
        self.peer_reported_max_subscribe_id
    }

    // ── Unified message dispatch ───────────────────────────────

    /// Dispatch an incoming control message to the appropriate handler.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::MaxSubscribeId(ref m) => self.receive_max_subscribe_id(m),
            ControlMessage::SubscribesBlocked(ref m) => self.receive_subscribes_blocked(m),
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(m),
            ControlMessage::SubscribeError(ref m) => self.receive_subscribe_error(m),
            ControlMessage::SubscribeUpdate(ref m) => self.receive_subscribe_update(m),
            ControlMessage::SubscribeDone(ref m) => self.receive_subscribe_done(m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(m),
            ControlMessage::FetchError(ref m) => self.receive_fetch_error(m),
            ControlMessage::SubscribeAnnouncesOk(ref m) => self.receive_subscribe_announces_ok(m),
            ControlMessage::SubscribeAnnouncesError(ref m) => {
                self.receive_subscribe_announces_error(m)
            }
            ControlMessage::AnnounceOk(ref m) => self.receive_announce_ok(m),
            ControlMessage::AnnounceError(ref m) => self.receive_announce_error(m),
            ControlMessage::AnnounceCancel(ref m) => self.receive_announce_cancel(m),
            ControlMessage::TrackStatus(ref m) => self.receive_track_status(m),
            _ => Ok(()),
        }
    }
}

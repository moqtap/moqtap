use std::collections::HashMap;

use crate::draft13::fetch::{FetchError, FetchStateMachine};
use crate::draft13::namespace::{
    AnnounceStateMachine, NamespaceError, SubscribeAnnouncesStateMachine,
};
use crate::draft13::session::request_id::{RequestIdAllocator, RequestIdError};
use crate::draft13::session::setup::{self, SetupError};
use crate::draft13::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft13::subscription::{SubscriptionError, SubscriptionStateMachine};
use crate::draft13::track_status::{TrackStatusError, TrackStatusStateMachine};
use moqtap_codec::draft13::message::{
    self, Announce, AnnounceCancel, AnnounceError, AnnounceOk, ClientSetup, ControlMessage, Fetch,
    FetchCancel, FetchPayload, FetchType, GoAway, MaxRequestId, Publish, PublishError, PublishOk,
    RequestsBlocked, ServerSetup, Subscribe, SubscribeDone, SubscribeError, SubscribeNamespace,
    SubscribeNamespaceError, SubscribeNamespaceOk, SubscribeOk, SubscribeUpdate, TrackStatus,
    TrackStatusError as TrackStatusErrorMsg, TrackStatusOk, Unannounce, Unsubscribe,
    UnsubscribeNamespace,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Key identifying a namespace (used for Announce maps).
type NamespaceKey = Vec<Vec<u8>>;

/// Errors that can occur during draft-13 endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A session-level state machine error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    /// A request ID allocation or validation error.
    #[error("request ID error: {0}")]
    RequestId(#[from] RequestIdError),
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
    /// The request ID does not match any known state machine.
    #[error("unknown request ID: {0}")]
    UnknownRequest(u64),
    /// The track namespace does not match any known state machine.
    #[error("unknown namespace")]
    UnknownNamespace,
    /// The session is not in the Active state.
    #[error("session not active")]
    NotActive,
    /// The session is draining and cannot accept new requests.
    #[error("session is draining, no new requests allowed")]
    Draining,
}

/// Unified draft-13 MoQT endpoint wrapping session lifecycle, request ID
/// allocation, and all per-flow state machines (subscriptions, fetches,
/// announces, subscribe-namespaces, track statuses).
pub struct Endpoint {
    session: SessionStateMachine,
    request_ids: RequestIdAllocator,
    /// Tracks the MAX_REQUEST_ID we have advertised to the peer.
    advertised_max_id: u64,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_namespaces: HashMap<u64, SubscribeAnnouncesStateMachine>,
    announces: HashMap<u64, AnnounceStateMachine>,
    /// Maps namespace tuple -> request_id, so callers can UNANNOUNCE / cancel
    /// by namespace without threading the id through every API.
    announce_ids: HashMap<NamespaceKey, u64>,
    /// Maps namespace prefix tuple -> request_id for subscribe-namespaces.
    subscribe_namespace_ids: HashMap<NamespaceKey, u64>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    /// Track aliases assigned by the publisher in SUBSCRIBE_OK, keyed by
    /// the subscriber-chosen request id.
    subscribe_track_aliases: HashMap<u64, VarInt>,
    /// Inbound PUBLISH requests received from the peer, keyed by their
    /// request id. Tracked so the application can respond with
    /// PUBLISH_OK / PUBLISH_ERROR using the correct id.
    inbound_publishes: HashMap<u64, Publish>,
    negotiated_version: Option<VarInt>,
    offered_versions: Vec<VarInt>,
    goaway_uri: Option<Vec<u8>>,
    /// The most recent `maximum_request_id` reported by the peer via a
    /// `REQUESTS_BLOCKED` message.
    peer_reported_max_request_id: Option<VarInt>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl Endpoint {
    /// Create a new draft-13 endpoint.
    pub fn new() -> Self {
        Self {
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(),
            advertised_max_id: 0,
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            subscribe_namespaces: HashMap::new(),
            announces: HashMap::new(),
            announce_ids: HashMap::new(),
            subscribe_namespace_ids: HashMap::new(),
            track_statuses: HashMap::new(),
            subscribe_track_aliases: HashMap::new(),
            inbound_publishes: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
            peer_reported_max_request_id: None,
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

    /// Returns whether this endpoint is blocked on request ID allocation.
    pub fn is_blocked(&self) -> bool {
        self.request_ids.is_blocked()
    }

    /// Returns the number of active subscription state machines.
    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns the number of active fetch state machines.
    pub fn active_fetch_count(&self) -> usize {
        self.fetches.len()
    }

    /// Returns the number of active subscribe-namespace state machines.
    pub fn active_subscribe_namespace_count(&self) -> usize {
        self.subscribe_namespaces.len()
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
    /// If the server includes a MAX_REQUEST_ID parameter (key 0x02), the
    /// request ID allocator is initialized with that value.
    pub fn receive_server_setup(&mut self, msg: &ServerSetup) -> Result<(), EndpointError> {
        setup::validate_server_setup(msg)?;
        let version = setup::negotiate_version(&self.offered_versions, msg.selected_version)?;
        self.negotiated_version = Some(version);
        self.session.on_setup_complete()?;
        // Extract MAX_REQUEST_ID (key 0x02) from setup parameters if present
        for param in &msg.parameters {
            if param.key == VarInt::from_u64(0x02).unwrap() {
                if let KvpValue::Varint(v) = &param.value {
                    self.request_ids.update_max(v.into_inner())?;
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

    // ── MAX_REQUEST_ID ─────────────────────────────────────────

    /// Process an incoming MAX_REQUEST_ID message.
    pub fn receive_max_request_id(&mut self, msg: &MaxRequestId) -> Result<(), EndpointError> {
        self.request_ids.update_max(msg.request_id.into_inner())?;
        Ok(())
    }

    /// Generate a MAX_REQUEST_ID message (typically server-side).
    /// The value must strictly increase over previous sends.
    pub fn send_max_request_id(&mut self, max_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let new_val = max_id.into_inner();
        if new_val <= self.advertised_max_id && self.advertised_max_id > 0 {
            return Err(EndpointError::RequestId(RequestIdError::Decreased(
                self.advertised_max_id,
                new_val,
            )));
        }
        self.advertised_max_id = new_val;
        Ok(ControlMessage::MaxRequestId(MaxRequestId { request_id: max_id }))
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

    /// Send a SUBSCRIBE message. Allocates a request ID and creates a
    /// subscription state machine. The `filter_type` must be a valid
    /// varint filter-type discriminant (see the draft-13 codec for
    /// definitions). `LargestObject` (2) is a reasonable default.
    ///
    /// Draft-13 note: the track alias is no longer chosen by the subscriber
    /// — it is returned by the publisher in `SUBSCRIBE_OK`. Callers that
    /// need the alias should inspect `track_alias_for` after the OK arrives.
    #[allow(clippy::too_many_arguments)]
    pub fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: VarInt,
        filter_type: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscriptionStateMachine::new();
        sm.on_subscribe_sent()?;
        self.subscriptions.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: req_id,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            forward: VarInt::from_u64(1).unwrap(),
            filter_type,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
    ///
    /// Draft-13 carries the publisher-assigned `track_alias` on SUBSCRIBE_OK,
    /// which is recorded here so callers can retrieve it via
    /// [`Endpoint::track_alias_for`].
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_ok()?;
        self.subscribe_track_aliases.insert(id, msg.track_alias);
        Ok(())
    }

    /// Returns the publisher-assigned track alias for a subscription, if
    /// SUBSCRIBE_OK has been processed for the given request id.
    pub fn track_alias_for(&self, request_id: VarInt) -> Option<VarInt> {
        self.subscribe_track_aliases.get(&request_id.into_inner()).copied()
    }

    /// Process an incoming SUBSCRIBE_ERROR.
    pub fn receive_subscribe_error(&mut self, msg: &SubscribeError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE message for an active subscription.
    pub fn unsubscribe(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Process an incoming SUBSCRIBE_UPDATE.
    pub fn receive_subscribe_update(&mut self, msg: &SubscribeUpdate) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_update()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_DONE (subscriber side — publisher finished).
    pub fn receive_subscribe_done(&mut self, msg: &SubscribeDone) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_done()?;
        Ok(())
    }

    // ── Fetch flow ─────────────────────────────────────────────

    /// Send a standalone FETCH message. Allocates a request ID and creates a
    /// fetch state machine.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: VarInt,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        end_object: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority,
            group_order,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace,
                track_name,
                start_group,
                start_object,
                end_group,
                end_object,
            },
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Send a joining FETCH message that attaches to an existing subscription.
    /// Allocates a new request ID for the fetch and tracks it in its own
    /// fetch state machine. `joining_start` is interpreted per `fetch_type`
    /// (relative offset vs absolute group id).
    pub fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: VarInt,
        fetch_type: FetchType,
        joining_subscribe_id: VarInt,
        joining_start: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        if !matches!(fetch_type, FetchType::RelativeJoining | FetchType::AbsoluteJoining) {
            // Caller used the wrong API for a standalone fetch.
            return Err(EndpointError::NotActive);
        }
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority,
            group_order,
            fetch_type,
            fetch_payload: FetchPayload::Joining { joining_subscribe_id, joining_start },
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming FETCH_OK.
    pub fn receive_fetch_ok(&mut self, msg: &message::FetchOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    /// Process an incoming FETCH_ERROR.
    pub fn receive_fetch_error(&mut self, msg: &message::FetchError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_error()?;
        Ok(())
    }

    /// Send a FETCH_CANCEL message.
    pub fn fetch_cancel(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_cancel()?;
        Ok(ControlMessage::FetchCancel(FetchCancel { request_id }))
    }

    /// Notify that a fetch data stream received FIN.
    pub fn on_fetch_stream_fin(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    /// Notify that a fetch data stream was reset.
    pub fn on_fetch_stream_reset(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // ── Subscribe Namespace flow ──────────────────────────────

    /// Send a SUBSCRIBE_NAMESPACE message. Returns the allocated request ID
    /// alongside the control message so the caller can correlate replies.
    pub fn subscribe_namespace(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let key = track_namespace_prefix.0.clone();
        let mut sm = SubscribeAnnouncesStateMachine::new();
        sm.on_subscribe_announces_sent()?;
        self.subscribe_namespaces.insert(req_id.into_inner(), sm);
        self.subscribe_namespace_ids.insert(key, req_id.into_inner());
        Ok((
            req_id,
            ControlMessage::SubscribeNamespace(SubscribeNamespace {
                request_id: req_id,
                track_namespace_prefix,
                parameters: vec![],
            }),
        ))
    }

    /// Process an incoming SUBSCRIBE_NAMESPACE_OK.
    pub fn receive_subscribe_namespace_ok(
        &mut self,
        msg: &SubscribeNamespaceOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_announces_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_NAMESPACE_ERROR.
    pub fn receive_subscribe_namespace_error(
        &mut self,
        msg: &SubscribeNamespaceError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_announces_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE_NAMESPACE message.
    pub fn unsubscribe_namespace(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id = *self
            .subscribe_namespace_ids
            .get(&track_namespace_prefix.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe_announces()?;
        Ok(ControlMessage::UnsubscribeNamespace(UnsubscribeNamespace { track_namespace_prefix }))
    }

    // ── Announce flow ──────────────────────────────────────────

    /// Send an ANNOUNCE message. Returns the allocated request ID alongside
    /// the control message.
    pub fn announce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let key = track_namespace.0.clone();
        let mut sm = AnnounceStateMachine::new();
        sm.on_announce_sent()?;
        self.announces.insert(req_id.into_inner(), sm);
        self.announce_ids.insert(key, req_id.into_inner());
        Ok((
            req_id,
            ControlMessage::Announce(Announce {
                request_id: req_id,
                track_namespace,
                parameters: vec![],
            }),
        ))
    }

    /// Process an incoming ANNOUNCE_OK.
    pub fn receive_announce_ok(&mut self, msg: &AnnounceOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_announce_ok()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_ERROR.
    pub fn receive_announce_error(&mut self, msg: &AnnounceError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_announce_error()?;
        Ok(())
    }

    /// Process an incoming ANNOUNCE_CANCEL.
    pub fn receive_announce_cancel(&mut self, msg: &AnnounceCancel) -> Result<(), EndpointError> {
        let id = *self
            .announce_ids
            .get(&msg.track_namespace.0)
            .ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_announce_cancel()?;
        Ok(())
    }

    /// Send an UNANNOUNCE message (publisher withdrawing).
    pub fn unannounce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id =
            *self.announce_ids.get(&track_namespace.0).ok_or(EndpointError::UnknownNamespace)?;
        let sm = self.announces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unannounce()?;
        Ok(ControlMessage::Unannounce(Unannounce { track_namespace }))
    }

    // ── Track Status flow ──────────────────────────────────────

    /// Send a TRACK_STATUS message (draft-13: subscribe-like request).
    /// Returns the allocated request ID alongside the control message.
    #[allow(clippy::too_many_arguments)]
    pub fn track_status_request(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: VarInt,
        forward: VarInt,
        filter_type: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_request_sent()?;
        self.track_statuses.insert(req_id.into_inner(), sm);
        Ok((
            req_id,
            ControlMessage::TrackStatus(TrackStatus {
                request_id: req_id,
                track_namespace,
                track_name,
                subscriber_priority,
                group_order,
                forward,
                filter_type,
                parameters: vec![],
            }),
        ))
    }

    /// Process an incoming TRACK_STATUS_OK reply (draft-13).
    pub fn receive_track_status_ok(&mut self, msg: &TrackStatusOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status()?;
        Ok(())
    }

    /// Process an incoming TRACK_STATUS_ERROR reply (draft-13).
    pub fn receive_track_status_error(
        &mut self,
        msg: &TrackStatusErrorMsg,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status()?;
        Ok(())
    }

    // ── Requests blocked ───────────────────────────────────────

    /// Process an incoming REQUESTS_BLOCKED message.
    ///
    /// The peer explicitly reports that a new request id would exceed our
    /// advertised maximum. The endpoint records the peer's reported maximum;
    /// acting on it (issuing a new `MAX_REQUEST_ID`) is up to the caller.
    pub fn receive_requests_blocked(&mut self, msg: &RequestsBlocked) -> Result<(), EndpointError> {
        self.peer_reported_max_request_id = Some(msg.maximum_request_id);
        Ok(())
    }

    /// The maximum request id that the peer most recently reported in a
    /// `REQUESTS_BLOCKED` message, if any.
    pub fn peer_reported_max_request_id(&self) -> Option<VarInt> {
        self.peer_reported_max_request_id
    }

    // ── Publish flow (draft-13) ────────────────────────────────

    /// Process an incoming PUBLISH message. The message is recorded so the
    /// application can respond with [`Endpoint::send_publish_ok`] or
    /// [`Endpoint::send_publish_error`] using the same request id. This is a
    /// pass-through: no full state machine is modelled here — the codec
    /// struct carries everything the application needs to decide.
    pub fn receive_publish(&mut self, msg: &Publish) -> Result<(), EndpointError> {
        self.require_active_or_err()?;
        self.inbound_publishes.insert(msg.request_id.into_inner(), msg.clone());
        Ok(())
    }

    /// Returns the inbound PUBLISH message for a given request id, if any.
    pub fn pending_publish(&self, request_id: VarInt) -> Option<&Publish> {
        self.inbound_publishes.get(&request_id.into_inner())
    }

    /// Number of PUBLISH requests received but not yet responded to.
    pub fn pending_publish_count(&self) -> usize {
        self.inbound_publishes.len()
    }

    /// Generate a PUBLISH_OK response for a previously received PUBLISH.
    /// Removes the pending publish entry on success.
    #[allow(clippy::too_many_arguments)]
    pub fn send_publish_ok(
        &mut self,
        request_id: VarInt,
        forward: VarInt,
        subscriber_priority: u8,
        group_order: VarInt,
        filter_type: VarInt,
        start_group: Option<VarInt>,
        start_object: Option<VarInt>,
        end_group: Option<VarInt>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        if !self.inbound_publishes.contains_key(&id) {
            return Err(EndpointError::UnknownRequest(id));
        }
        self.inbound_publishes.remove(&id);
        Ok(ControlMessage::PublishOk(PublishOk {
            request_id,
            forward,
            subscriber_priority,
            group_order,
            filter_type,
            start_group,
            start_object,
            end_group,
            parameters: vec![],
        }))
    }

    /// Generate a PUBLISH_ERROR response for a previously received PUBLISH.
    /// Removes the pending publish entry on success.
    pub fn send_publish_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        if !self.inbound_publishes.contains_key(&id) {
            return Err(EndpointError::UnknownRequest(id));
        }
        self.inbound_publishes.remove(&id);
        Ok(ControlMessage::PublishError(PublishError { request_id, error_code, reason_phrase }))
    }

    /// Process an incoming PUBLISH_OK (publisher side — peer accepted our
    /// PUBLISH offer). Pass-through: no state machine is currently modelled.
    pub fn receive_publish_ok(&mut self, _msg: &PublishOk) -> Result<(), EndpointError> {
        Ok(())
    }

    /// Process an incoming PUBLISH_ERROR (publisher side — peer rejected our
    /// PUBLISH offer). Pass-through: no state machine is currently modelled.
    pub fn receive_publish_error(&mut self, _msg: &PublishError) -> Result<(), EndpointError> {
        Ok(())
    }

    // ── Unified message dispatch ───────────────────────────────

    /// Dispatch an incoming control message to the appropriate handler.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::MaxRequestId(ref m) => self.receive_max_request_id(m),
            ControlMessage::RequestsBlocked(ref m) => self.receive_requests_blocked(m),
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(m),
            ControlMessage::SubscribeError(ref m) => self.receive_subscribe_error(m),
            ControlMessage::SubscribeUpdate(ref m) => self.receive_subscribe_update(m),
            ControlMessage::SubscribeDone(ref m) => self.receive_subscribe_done(m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(m),
            ControlMessage::FetchError(ref m) => self.receive_fetch_error(m),
            ControlMessage::SubscribeNamespaceOk(ref m) => self.receive_subscribe_namespace_ok(m),
            ControlMessage::SubscribeNamespaceError(ref m) => {
                self.receive_subscribe_namespace_error(m)
            }
            ControlMessage::AnnounceOk(ref m) => self.receive_announce_ok(m),
            ControlMessage::AnnounceError(ref m) => self.receive_announce_error(m),
            ControlMessage::AnnounceCancel(ref m) => self.receive_announce_cancel(m),
            ControlMessage::TrackStatusOk(ref m) => self.receive_track_status_ok(m),
            ControlMessage::TrackStatusError(ref m) => self.receive_track_status_error(m),
            ControlMessage::Publish(ref m) => self.receive_publish(m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(m),
            ControlMessage::PublishError(ref m) => self.receive_publish_error(m),
            _ => Ok(()),
        }
    }
}

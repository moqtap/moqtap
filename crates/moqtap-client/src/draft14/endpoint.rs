use std::collections::HashMap;

use crate::draft14::fetch::{FetchError, FetchStateMachine};
use crate::draft14::namespace::{
    NamespaceError, PublishNamespaceStateMachine, SubscribeNamespaceStateMachine,
};
use crate::draft14::publish::{PublishError as PublishFlowError, PublishStateMachine};
use crate::draft14::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft14::session::setup::{self, SetupError};
use crate::draft14::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft14::subscription::{SubscriptionError, SubscriptionStateMachine};
use crate::draft14::track_status::{TrackStatusError, TrackStatusStateMachine};
use moqtap_codec::draft14::message::{
    self, ClientSetup, ControlMessage, Fetch, FetchCancel, GoAway, MaxRequestId, PublishDone,
    PublishNamespace, PublishNamespaceCancel, PublishNamespaceDone, PublishNamespaceError,
    PublishNamespaceOk, RequestsBlocked, ServerSetup, Subscribe, SubscribeError,
    SubscribeNamespace, SubscribeNamespaceError, SubscribeNamespaceOk, SubscribeOk,
    SubscribeUpdate, Unsubscribe, UnsubscribeNamespace,
};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Errors that can occur during endpoint operations.
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
    /// A publish flow state machine error.
    #[error("publish flow error: {0}")]
    PublishFlow(#[from] PublishFlowError),
    /// A setup negotiation error.
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),
    /// The request ID does not match any known state machine.
    #[error("unknown request ID: {0}")]
    UnknownRequest(u64),
    /// The session is not in the Active state.
    #[error("session not active")]
    NotActive,
    /// The session is draining and cannot accept new requests.
    #[error("session is draining, no new requests allowed")]
    Draining,
}

/// Unified MoQT endpoint wrapping session lifecycle, request ID allocation,
/// and all per-request state machines (subscriptions, fetches, namespaces).
pub struct Endpoint {
    role: Role,
    session: SessionStateMachine,
    request_ids: RequestIdAllocator,
    /// Tracks the MAX_REQUEST_ID we have advertised to the peer (for monotonic enforcement).
    advertised_max_id: u64,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_namespaces: HashMap<u64, SubscribeNamespaceStateMachine>,
    publish_namespaces: HashMap<u64, PublishNamespaceStateMachine>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    publishes: HashMap<u64, PublishStateMachine>,
    negotiated_version: Option<VarInt>,
    offered_versions: Vec<VarInt>,
    goaway_uri: Option<Vec<u8>>,
}

impl Endpoint {
    /// Create a new endpoint with the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(role),
            advertised_max_id: 0,
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            subscribe_namespaces: HashMap::new(),
            publish_namespaces: HashMap::new(),
            track_statuses: HashMap::new(),
            publishes: HashMap::new(),
            negotiated_version: None,
            offered_versions: Vec::new(),
            goaway_uri: None,
        }
    }

    // ── Accessors ──────────────────────────────────────────────

    /// Returns the role (client or server) of this endpoint.
    pub fn role(&self) -> Role {
        self.role
    }

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

    /// Returns the number of active publish-namespace state machines.
    pub fn active_publish_namespace_count(&self) -> usize {
        self.publish_namespaces.len()
    }

    /// Returns the number of active track status state machines.
    pub fn active_track_status_count(&self) -> usize {
        self.track_statuses.len()
    }

    /// Returns the number of active publish state machines.
    pub fn active_publish_count(&self) -> usize {
        self.publishes.len()
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

    /// Generate a REQUESTS_BLOCKED message indicating that this endpoint
    /// wants to create a new request but is blocked by the current
    /// MAX_REQUEST_ID. Per draft-14 §6.3.2.
    pub fn send_requests_blocked(&self) -> Result<ControlMessage, EndpointError> {
        let max_id = self.request_ids.max_id();
        Ok(ControlMessage::RequestsBlocked(RequestsBlocked {
            maximum_request_id: VarInt::from_u64(max_id).unwrap(),
        }))
    }

    /// Process an incoming REQUESTS_BLOCKED message from the peer.
    /// This signals that the peer wants to issue new requests but is
    /// limited by the MAX_REQUEST_ID we advertised.
    pub fn receive_requests_blocked(&self, _msg: &RequestsBlocked) -> Result<(), EndpointError> {
        // The peer is telling us they're blocked. This is informational;
        // the application layer should decide whether to increase MAX_REQUEST_ID.
        Ok(())
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
    /// subscription state machine.
    pub fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
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
            forward: Forward::Forward,
            filter_type,
            start_location: None,
            end_group: None,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK.
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_ok()?;
        Ok(())
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
        let id = msg.subscription_request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_update()?;
        Ok(())
    }

    /// Send a SUBSCRIBE_UPDATE for an active subscription. Allocates a fresh
    /// request ID for the update message and returns it alongside the message.
    pub fn subscribe_update(
        &mut self,
        subscription_request_id: VarInt,
        start_location: Location,
        end_group: VarInt,
        subscriber_priority: u8,
        forward: Forward,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let sub_id = subscription_request_id.into_inner();
        let sm =
            self.subscriptions.get_mut(&sub_id).ok_or(EndpointError::UnknownRequest(sub_id))?;
        sm.on_subscribe_update()?;
        let req_id = self.request_ids.allocate()?;
        let msg = ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: req_id,
            subscription_request_id,
            start_location,
            end_group,
            subscriber_priority,
            forward,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_DONE (subscriber side — publisher finished).
    pub fn receive_publish_done(&mut self, msg: &PublishDone) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done()?;
        Ok(())
    }

    // ── Fetch flow ─────────────────────────────────────────────

    /// Send a FETCH message. Allocates a request ID and creates a fetch state machine.
    pub fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        start_group: VarInt,
        start_object: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: message::FetchType::Standalone,
            fetch_payload: message::FetchPayload::Standalone {
                track_namespace,
                track_name,
                start_group,
                start_object,
                end_group: VarInt::from_u64(0).unwrap(),
                end_object: VarInt::from_u64(0).unwrap(),
            },
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

    // ── Subscribe Namespace flow ───────────────────────────────

    /// Send a SUBSCRIBE_NAMESPACE message.
    pub fn subscribe_namespace(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscribeNamespaceStateMachine::new();
        sm.on_subscribe_namespace_sent()?;
        self.subscribe_namespaces.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: req_id,
            track_namespace,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_NAMESPACE_OK.
    pub fn receive_subscribe_namespace_ok(
        &mut self,
        msg: &SubscribeNamespaceOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_namespace_ok()?;
        Ok(())
    }

    /// Process an incoming SUBSCRIBE_NAMESPACE_ERROR.
    pub fn receive_subscribe_namespace_error(
        &mut self,
        msg: &SubscribeNamespaceError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_namespace_error()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE_NAMESPACE message.
    pub fn unsubscribe_namespace(
        &mut self,
        request_id: VarInt,
        _track_namespace: TrackNamespace,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscribe_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe_namespace()?;
        let _ = request_id;
        Ok(ControlMessage::UnsubscribeNamespace(UnsubscribeNamespace {
            track_namespace_prefix: _track_namespace,
        }))
    }

    // ── Publish Namespace flow ─────────────────────────────────

    /// Send a PUBLISH_NAMESPACE message.
    pub fn publish_namespace(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = PublishNamespaceStateMachine::new();
        sm.on_publish_namespace_sent()?;
        self.publish_namespaces.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::PublishNamespace(PublishNamespace {
            request_id: req_id,
            track_namespace,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_NAMESPACE_OK.
    pub fn receive_publish_namespace_ok(
        &mut self,
        msg: &PublishNamespaceOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_ok()?;
        Ok(())
    }

    /// Process an incoming PUBLISH_NAMESPACE_ERROR.
    pub fn receive_publish_namespace_error(
        &mut self,
        msg: &PublishNamespaceError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_error()?;
        Ok(())
    }

    /// Process an incoming PUBLISH_NAMESPACE_DONE.
    ///
    /// Draft-14 PUBLISH_NAMESPACE_DONE is keyed by `track_namespace`
    /// rather than a request ID, so the endpoint advances every
    /// currently tracked publish-namespace state machine. Callers that
    /// need per-namespace tracking should match on `msg.track_namespace`
    /// directly.
    pub fn receive_publish_namespace_done(
        &mut self,
        _msg: &PublishNamespaceDone,
    ) -> Result<(), EndpointError> {
        for sm in self.publish_namespaces.values_mut() {
            // Best-effort: ignore state-machine errors for machines
            // that are already past the Done transition.
            let _ = sm.on_publish_namespace_done();
        }
        Ok(())
    }

    /// Send a PUBLISH_NAMESPACE_CANCEL message.
    pub fn publish_namespace_cancel(
        &mut self,
        request_id: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_cancel()?;
        Ok(ControlMessage::PublishNamespaceCancel(PublishNamespaceCancel {
            track_namespace: TrackNamespace(Vec::new()),
            error_code: VarInt::from_u64(0).unwrap(),
            reason_phrase,
        }))
    }

    // ── Track Status flow ────────────────────────────────────

    /// Send a TRACK_STATUS message. Allocates a request ID.
    pub fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = TrackStatusStateMachine::new();
        sm.on_track_status_sent()?;
        self.track_statuses.insert(req_id.into_inner(), sm);
        let msg = ControlMessage::TrackStatus(message::TrackStatus {
            request_id: req_id,
            track_namespace,
            track_name,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming TRACK_STATUS_OK.
    pub fn receive_track_status_ok(
        &mut self,
        msg: &message::TrackStatusOk,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status_ok()?;
        Ok(())
    }

    /// Process an incoming TRACK_STATUS_ERROR.
    pub fn receive_track_status_error(
        &mut self,
        msg: &message::TrackStatusError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.track_statuses.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_track_status_error()?;
        Ok(())
    }

    // ── Publish flow (publisher side) ─────────────────────────

    /// Send a PUBLISH message (publisher side). Allocates a request ID.
    pub fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        forward: Forward,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = PublishStateMachine::new();
        sm.on_publish_sent()?;
        self.publishes.insert(req_id.into_inner(), sm);
        let msg = ControlMessage::Publish(message::Publish {
            request_id: req_id,
            track_namespace,
            track_name,
            track_alias: VarInt::from_u64(0).unwrap(),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            forward,
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_OK (publisher side).
    pub fn receive_publish_ok(&mut self, msg: &message::PublishOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_ok()?;
        Ok(())
    }

    /// Send a PUBLISH_DONE message (publisher finishing).
    pub fn send_publish_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done_sent()?;
        Ok(ControlMessage::PublishDone(PublishDone {
            request_id,
            status_code,
            stream_count: VarInt::from_u64(0).unwrap(),
            reason_phrase,
        }))
    }

    // ── Publish error ─────────────────────────────────────────

    /// Generate a PUBLISH_ERROR message (draft-14 §6.5.3).
    /// Used by the server/relay to reject a publish request.
    pub fn send_publish_error(
        &self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        Ok(ControlMessage::PublishError(message::PublishError {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    /// Process an incoming PUBLISH_ERROR (draft-14 §6.5.3).
    /// Checks publisher-side publishes first, then subscriber-side subscriptions,
    /// then silently ignores unknown IDs.
    pub fn receive_publish_error(
        &mut self,
        msg: &message::PublishError,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // Check publisher-side publishes first
        if let Some(sm) = self.publishes.get_mut(&id) {
            sm.on_publish_error()?;
            return Ok(());
        }
        // Then check subscriber-side subscriptions
        if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_subscribe_error()?;
        }
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
            ControlMessage::PublishDone(ref m) => self.receive_publish_done(m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(m),
            ControlMessage::PublishError(ref m) => self.receive_publish_error(m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(m),
            ControlMessage::FetchError(ref m) => self.receive_fetch_error(m),
            ControlMessage::SubscribeNamespaceOk(ref m) => self.receive_subscribe_namespace_ok(m),
            ControlMessage::SubscribeNamespaceError(ref m) => {
                self.receive_subscribe_namespace_error(m)
            }
            ControlMessage::PublishNamespaceOk(ref m) => self.receive_publish_namespace_ok(m),
            ControlMessage::PublishNamespaceError(ref m) => self.receive_publish_namespace_error(m),
            ControlMessage::PublishNamespaceDone(ref m) => self.receive_publish_namespace_done(m),
            ControlMessage::TrackStatusOk(ref m) => self.receive_track_status_ok(m),
            ControlMessage::TrackStatusError(ref m) => self.receive_track_status_error(m),
            _ => Ok(()),
        }
    }
}

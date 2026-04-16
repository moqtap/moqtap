use std::collections::HashMap;

use crate::draft16::fetch::{FetchError, FetchStateMachine};
use crate::draft16::namespace::{
    NamespaceError, PublishNamespaceStateMachine, SubscribeNamespaceStateMachine,
};
use crate::draft16::publish::{PublishError as PublishFlowError, PublishStateMachine};
use crate::draft16::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft16::session::setup::{self, SetupError};
use crate::draft16::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft16::subscription::{SubscriptionError, SubscriptionStateMachine};
use crate::draft16::track_status::{TrackStatusError, TrackStatusStateMachine};
use moqtap_codec::draft16::message::{
    self, ClientSetup, ControlMessage, Fetch, FetchCancel, FetchPayload, FetchType, GoAway,
    MaxRequestId, PublishDone, PublishNamespace, PublishNamespaceCancel, PublishNamespaceDone,
    RequestError, RequestOk, RequestUpdate, RequestsBlocked, ServerSetup, Subscribe,
    SubscribeNamespace, SubscribeOk, Unsubscribe,
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
    /// Tracks the MAX_REQUEST_ID we have advertised to the peer (monotonic).
    advertised_max_id: u64,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_namespaces: HashMap<u64, SubscribeNamespaceStateMachine>,
    publish_namespaces: HashMap<u64, PublishNamespaceStateMachine>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    publishes: HashMap<u64, PublishStateMachine>,
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
            goaway_uri: None,
        }
    }

    // -- Accessors --------------------------------------------------

    /// Returns the role (client or server) of this endpoint.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the current session state.
    pub fn session_state(&self) -> SessionState {
        self.session.state()
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

    // -- Session lifecycle ------------------------------------------

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

    // -- Client setup (draft-16: no versions) -----------------------

    /// Generate a CLIENT_SETUP message (client-side).
    /// Draft-16 uses ALPN for version negotiation -- no versions field.
    pub fn send_client_setup(
        &mut self,
        parameters: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let msg = ClientSetup { parameters };
        setup::validate_client_setup(&msg)?;
        Ok(ControlMessage::ClientSetup(msg))
    }

    /// Process a SERVER_SETUP message (client-side). Transitions to Active.
    /// If the server includes a MAX_REQUEST_ID parameter (key 0x02), the
    /// request ID allocator is initialized with that value.
    pub fn receive_server_setup(&mut self, msg: &ServerSetup) -> Result<(), EndpointError> {
        setup::validate_server_setup(msg)?;
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

    // -- Server setup -----------------------------------------------

    /// Process CLIENT_SETUP and generate SERVER_SETUP (server-side).
    /// Draft-16 uses ALPN for version negotiation -- just transition and
    /// respond.
    pub fn receive_client_setup_and_respond(
        &mut self,
        client_setup: &ClientSetup,
    ) -> Result<ControlMessage, EndpointError> {
        setup::validate_client_setup(client_setup)?;
        self.session.on_setup_complete()?;
        let msg = ServerSetup { parameters: vec![] };
        Ok(ControlMessage::ServerSetup(msg))
    }

    // -- MAX_REQUEST_ID ---------------------------------------------

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
    /// MAX_REQUEST_ID.
    pub fn send_requests_blocked(&self) -> Result<ControlMessage, EndpointError> {
        let max_id = self.request_ids.max_id();
        Ok(ControlMessage::RequestsBlocked(RequestsBlocked {
            maximum_request_id: VarInt::from_u64(max_id).unwrap(),
        }))
    }

    /// Process an incoming REQUESTS_BLOCKED message from the peer.
    pub fn receive_requests_blocked(&self, _msg: &RequestsBlocked) -> Result<(), EndpointError> {
        Ok(())
    }

    // -- GoAway -----------------------------------------------------

    /// Process an incoming GOAWAY message. Transitions to Draining.
    pub fn receive_goaway(&mut self, msg: &GoAway) -> Result<(), EndpointError> {
        self.session.on_goaway()?;
        self.goaway_uri = Some(msg.new_session_uri.clone());
        Ok(())
    }

    // -- Subscribe flow ---------------------------------------------

    fn require_active_or_err(&self) -> Result<(), EndpointError> {
        match self.session.state() {
            SessionState::Active => Ok(()),
            SessionState::Draining => Err(EndpointError::Draining),
            _ => Err(EndpointError::NotActive),
        }
    }

    /// Send a SUBSCRIBE message. Allocates a request ID and creates a
    /// subscription state machine. Draft-16: simplified, no group_order/
    /// filter_type/forward args.
    pub fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
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
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK. Draft-16: has request_id,
    /// track_alias, parameters.
    pub fn receive_subscribe_ok(&mut self, msg: &SubscribeOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_ok()?;
        Ok(())
    }

    /// Send an UNSUBSCRIBE message for an active subscription.
    pub fn unsubscribe(&mut self, request_id: VarInt) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_unsubscribe()?;
        Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
    }

    /// Process an incoming REQUEST_UPDATE. Draft-16 renamed SUBSCRIBE_UPDATE
    /// to REQUEST_UPDATE and renamed `subscription_request_id` to
    /// `existing_request_id`.
    pub fn receive_request_update(&mut self, msg: &RequestUpdate) -> Result<(), EndpointError> {
        let id = msg.existing_request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_update()?;
        Ok(())
    }

    /// Process an incoming PUBLISH_DONE (subscriber side -- publisher
    /// finished). Draft-16: has request_id, status_code, stream_count,
    /// reason_phrase.
    pub fn receive_publish_done(&mut self, msg: &PublishDone) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done()?;
        Ok(())
    }

    // -- Fetch flow -------------------------------------------------

    /// Send a standalone FETCH message. Allocates a request ID and creates a
    /// fetch state machine. Draft-16: has end_object.
    pub fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
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

    /// Send a joining FETCH message. Allocates a request ID.
    pub fn joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = FetchStateMachine::new();
        sm.on_fetch_sent()?;
        self.fetches.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Fetch(Fetch {
            request_id: req_id,
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: FetchPayload::Joining { joining_request_id, joining_start },
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    /// Process an incoming FETCH_OK. Draft-16: has request_id, end_of_track,
    /// end_group, end_object, parameters.
    pub fn receive_fetch_ok(&mut self, msg: &message::FetchOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_ok()?;
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

    // -- Subscribe Namespace flow -----------------------------------

    /// Send a SUBSCRIBE_NAMESPACE message. Draft-16 adds `subscribe_options`
    /// (0=PUBLISH, 1=NAMESPACE, 2=both).
    pub fn subscribe_namespace(
        &mut self,
        namespace_prefix: TrackNamespace,
        subscribe_options: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = SubscribeNamespaceStateMachine::new();
        sm.on_subscribe_namespace_sent()?;
        self.subscribe_namespaces.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: req_id,
            namespace_prefix,
            subscribe_options,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Publish Namespace flow -------------------------------------

    /// Send a PUBLISH_NAMESPACE message.
    pub fn publish_namespace(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;

        let mut sm = PublishNamespaceStateMachine::new();
        sm.on_publish_namespace_sent()?;
        self.publish_namespaces.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::PublishNamespace(PublishNamespace {
            request_id: req_id,
            track_namespace,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_NAMESPACE_DONE. Draft-16: keyed by
    /// request_id (not track_namespace as in draft-15).
    pub fn receive_publish_namespace_done(
        &mut self,
        msg: &PublishNamespaceDone,
    ) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_done()?;
        Ok(())
    }

    /// Send a PUBLISH_NAMESPACE_CANCEL message. Draft-16: request_id +
    /// error_code + reason_phrase.
    pub fn publish_namespace_cancel(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.publish_namespaces.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_namespace_cancel()?;
        Ok(ControlMessage::PublishNamespaceCancel(PublishNamespaceCancel {
            request_id,
            error_code,
            reason_phrase,
        }))
    }

    // -- Track Status flow ------------------------------------------

    /// Send a TRACK_STATUS message. Allocates a request ID. Draft-16:
    /// simplified with parameters.
    pub fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
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
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Publish flow (publisher side) ------------------------------

    /// Send a PUBLISH message (publisher side). Allocates a request ID.
    /// Draft-16: takes track_alias, no forward.
    pub fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        track_extensions: Vec<KeyValuePair>,
        parameters: Vec<KeyValuePair>,
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
            track_alias,
            track_extensions,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming PUBLISH_OK (publisher side). Draft-16: has
    /// request_id, parameters.
    pub fn receive_publish_ok(&mut self, msg: &message::PublishOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_ok()?;
        Ok(())
    }

    /// Send a PUBLISH_DONE message (publisher finishing). Draft-16: has
    /// stream_count.
    pub fn send_publish_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        stream_count: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<ControlMessage, EndpointError> {
        let id = request_id.into_inner();
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done_sent()?;
        Ok(ControlMessage::PublishDone(PublishDone {
            request_id,
            status_code,
            stream_count,
            reason_phrase,
        }))
    }

    // -- Consolidated responses (draft-16) --------------------------

    /// Process an incoming REQUEST_OK (consolidated ok for namespace/
    /// track-status flows).
    pub fn receive_request_ok(&mut self, msg: &RequestOk) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // Check subscribe_namespaces first
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_subscribe_namespace_ok()?;
            return Ok(());
        }
        // Then publish_namespaces
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_publish_namespace_ok()?;
            return Ok(());
        }
        // Then track_statuses
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_track_status_ok()?;
            return Ok(());
        }
        Err(EndpointError::UnknownRequest(id))
    }

    /// Process an incoming REQUEST_ERROR (consolidated error).
    pub fn receive_request_error(&mut self, msg: &RequestError) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        // Check subscriptions
        if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_subscribe_error()?;
            return Ok(());
        }
        // Check fetches
        if let Some(sm) = self.fetches.get_mut(&id) {
            sm.on_fetch_error()?;
            return Ok(());
        }
        // Check publishes
        if let Some(sm) = self.publishes.get_mut(&id) {
            sm.on_publish_error()?;
            return Ok(());
        }
        // Check subscribe_namespaces
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_subscribe_namespace_error()?;
            return Ok(());
        }
        // Check publish_namespaces
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_publish_namespace_error()?;
            return Ok(());
        }
        // Check track_statuses
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_track_status_error()?;
            return Ok(());
        }
        // Unknown ID -- silently ignore per spec
        Ok(())
    }

    // -- Unified message dispatch -----------------------------------

    /// Dispatch an incoming control message to the appropriate handler.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::MaxRequestId(ref m) => self.receive_max_request_id(m),
            ControlMessage::RequestsBlocked(ref m) => self.receive_requests_blocked(m),
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(m),
            ControlMessage::RequestUpdate(ref m) => self.receive_request_update(m),
            ControlMessage::PublishDone(ref m) => self.receive_publish_done(m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(m),
            ControlMessage::RequestOk(ref m) => self.receive_request_ok(m),
            ControlMessage::RequestError(ref m) => self.receive_request_error(m),
            ControlMessage::PublishNamespaceDone(ref m) => self.receive_publish_namespace_done(m),
            _ => Ok(()),
        }
    }
}

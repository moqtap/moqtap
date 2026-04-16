#![allow(missing_docs)]
//! Draft-17 MoQT endpoint.
//!
//! Major architectural differences from earlier drafts:
//!
//! * Unified [`Setup`] message (no separate CLIENT_SETUP / SERVER_SETUP).
//! * Response messages (`SubscribeOk`, `PublishOk`, `FetchOk`, `PublishDone`,
//!   `RequestOk`, `RequestError`) do NOT carry a `request_id`. Each request
//!   opens its own bidirectional stream and its response arrives as the
//!   first message on that stream (spec §3.3, §9.7, §9.9). The transport
//!   layer knows which `request_id` each bidi stream belongs to; callers
//!   must supply that `request_id` via [`Endpoint::receive_response_on_stream`].
//! * No `Unsubscribe`, `FetchCancel`, `MaxRequestId`, `RequestsBlocked`,
//!   `PublishNamespaceDone`, or `PublishNamespaceCancel` messages.
//! * Request-producing messages (`Subscribe`, `Publish`, `Fetch`,
//!   `PublishNamespace`, `SubscribeNamespace`, `TrackStatus`, `RequestUpdate`)
//!   gain a `required_request_id_delta` field.
//! * New `PublishBlocked` message notifies subscribers a publisher is blocked.
//! * `Namespace` and `NamespaceDone` are unsolicited announcements of
//!   namespace suffixes.

use std::collections::HashMap;

use crate::draft17::fetch::{FetchError, FetchStateMachine};
use crate::draft17::namespace::{
    NamespaceError, PublishNamespaceStateMachine, SubscribeNamespaceStateMachine,
};
use crate::draft17::publish::{PublishError as PublishFlowError, PublishStateMachine};
use crate::draft17::session::request_id::{RequestIdAllocator, RequestIdError, Role};
use crate::draft17::session::setup::{self, SetupError};
use crate::draft17::session::state::{SessionError, SessionState, SessionStateMachine};
use crate::draft17::subscription::{SubscriptionError, SubscriptionStateMachine};
use crate::draft17::track_status::{TrackStatusError, TrackStatusStateMachine};
use moqtap_codec::draft17::message::{
    self, ControlMessage, Fetch, FetchPayload, FetchType, GoAway, Publish, PublishBlocked,
    PublishDone, PublishNamespace, RequestError, RequestOk, RequestUpdate, Setup, Subscribe,
    SubscribeNamespace, SubscribeOk,
};
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Errors that can occur during endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("request ID error: {0}")]
    RequestId(#[from] RequestIdError),
    #[error("subscription error: {0}")]
    Subscription(#[from] SubscriptionError),
    #[error("fetch error: {0}")]
    Fetch(#[from] FetchError),
    #[error("namespace error: {0}")]
    Namespace(#[from] NamespaceError),
    #[error("track status error: {0}")]
    TrackStatus(#[from] TrackStatusError),
    #[error("publish flow error: {0}")]
    PublishFlow(#[from] PublishFlowError),
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),
    #[error("unknown request ID: {0}")]
    UnknownRequest(u64),
    #[error(
        "response message received on control stream; d17 responses belong on bidi request streams"
    )]
    ResponseOnControlStream,
    #[error("session not active")]
    NotActive,
    #[error("session is draining, no new requests allowed")]
    Draining,
}

pub struct Endpoint {
    role: Role,
    session: SessionStateMachine,
    request_ids: RequestIdAllocator,
    subscriptions: HashMap<u64, SubscriptionStateMachine>,
    fetches: HashMap<u64, FetchStateMachine>,
    subscribe_namespaces: HashMap<u64, SubscribeNamespaceStateMachine>,
    publish_namespaces: HashMap<u64, PublishNamespaceStateMachine>,
    track_statuses: HashMap<u64, TrackStatusStateMachine>,
    publishes: HashMap<u64, PublishStateMachine>,
    goaway_uri: Option<Vec<u8>>,
}

impl Endpoint {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            session: SessionStateMachine::new(),
            request_ids: RequestIdAllocator::new(role),
            subscriptions: HashMap::new(),
            fetches: HashMap::new(),
            subscribe_namespaces: HashMap::new(),
            publish_namespaces: HashMap::new(),
            track_statuses: HashMap::new(),
            publishes: HashMap::new(),
            goaway_uri: None,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    pub fn goaway_uri(&self) -> Option<&[u8]> {
        self.goaway_uri.as_deref()
    }

    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn active_fetch_count(&self) -> usize {
        self.fetches.len()
    }

    pub fn active_subscribe_namespace_count(&self) -> usize {
        self.subscribe_namespaces.len()
    }

    pub fn active_publish_namespace_count(&self) -> usize {
        self.publish_namespaces.len()
    }

    pub fn active_track_status_count(&self) -> usize {
        self.track_statuses.len()
    }

    pub fn active_publish_count(&self) -> usize {
        self.publishes.len()
    }

    // -- Session lifecycle ------------------------------------------

    pub fn connect(&mut self) -> Result<(), EndpointError> {
        self.session.on_connect()?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), EndpointError> {
        self.session.on_close()?;
        Ok(())
    }

    // -- Unified SETUP (draft-17) -----------------------------------

    /// Generate a SETUP message. Both client and server use the same message
    /// type; only the role (and the order of send/receive) distinguishes them.
    pub fn send_setup(
        &mut self,
        options: Vec<KeyValuePair>,
    ) -> Result<ControlMessage, EndpointError> {
        let msg = Setup { options };
        setup::validate_setup(&msg)?;
        Ok(ControlMessage::Setup(msg))
    }

    /// Process an incoming SETUP message. Transitions the session to Active.
    pub fn receive_setup(&mut self, msg: &Setup) -> Result<(), EndpointError> {
        setup::validate_setup(msg)?;
        self.session.on_setup_complete()?;
        Ok(())
    }

    // -- GoAway -----------------------------------------------------

    pub fn receive_goaway(&mut self, msg: &GoAway) -> Result<(), EndpointError> {
        self.session.on_goaway()?;
        self.goaway_uri = Some(msg.new_session_uri.clone());
        Ok(())
    }

    // -- Request ID delta helper ------------------------------------

    /// `required_request_id_delta` is the distance between this request_id
    /// and the lowest still-pending one. For simplicity we always emit 0
    /// (tells the peer "no earlier requests need a response before this one").
    fn delta() -> VarInt {
        VarInt::from_u64(0).unwrap()
    }

    fn require_active_or_err(&self) -> Result<(), EndpointError> {
        match self.session.state() {
            SessionState::Active => Ok(()),
            SessionState::Draining => Err(EndpointError::Draining),
            _ => Err(EndpointError::NotActive),
        }
    }

    // -- Subscribe flow ---------------------------------------------

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
            required_request_id_delta: Self::delta(),
            track_namespace,
            track_name,
            parameters,
        });
        Ok((req_id, msg))
    }

    /// Process an incoming SUBSCRIBE_OK. Draft-17: no request_id on wire; the
    /// caller supplies the `request_id` of the bidi stream on which the
    /// response arrived.
    pub fn receive_subscribe_ok(
        &mut self,
        request_id: VarInt,
        _msg: &SubscribeOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_ok()?;
        Ok(())
    }

    /// Process REQUEST_UPDATE. Draft-17: renames draft-16's
    /// `existing_request_id` to `request_id` (the one being updated).
    pub fn receive_request_update(&mut self, msg: &RequestUpdate) -> Result<(), EndpointError> {
        let id = msg.request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_subscribe_update()?;
        Ok(())
    }

    /// Process an incoming PUBLISH_DONE (subscriber side). Draft-17: no
    /// request_id on wire; `request_id` identifies the subscription's
    /// bidi stream.
    pub fn receive_publish_done(
        &mut self,
        request_id: VarInt,
        _msg: &PublishDone,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.subscriptions.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_done()?;
        Ok(())
    }

    // -- Fetch flow -------------------------------------------------

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
            required_request_id_delta: Self::delta(),
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
            required_request_id_delta: Self::delta(),
            fetch_type: FetchType::RelativeJoining,
            fetch_payload: FetchPayload::Joining { joining_request_id, joining_start },
            parameters: vec![],
        });
        Ok((req_id, msg))
    }

    pub fn receive_fetch_ok(
        &mut self,
        request_id: VarInt,
        _msg: &message::FetchOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_fetch_ok()?;
        Ok(())
    }

    pub fn on_fetch_stream_fin(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_fin()?;
        Ok(())
    }

    pub fn on_fetch_stream_reset(&mut self, request_id: VarInt) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.fetches.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_stream_reset()?;
        Ok(())
    }

    // -- Subscribe Namespace flow -----------------------------------

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
            required_request_id_delta: Self::delta(),
            namespace_prefix,
            subscribe_options,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Publish Namespace flow -------------------------------------

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
            required_request_id_delta: Self::delta(),
            track_namespace,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Track Status flow ------------------------------------------

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
            required_request_id_delta: Self::delta(),
            track_namespace,
            track_name,
            parameters,
        });
        Ok((req_id, msg))
    }

    // -- Publish flow (publisher side) ------------------------------

    pub fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        parameters: Vec<KeyValuePair>,
        track_properties: Vec<KeyValuePair>,
    ) -> Result<(VarInt, ControlMessage), EndpointError> {
        self.require_active_or_err()?;
        let req_id = self.request_ids.allocate()?;
        let mut sm = PublishStateMachine::new();
        sm.on_publish_sent()?;
        self.publishes.insert(req_id.into_inner(), sm);

        let msg = ControlMessage::Publish(Publish {
            request_id: req_id,
            required_request_id_delta: Self::delta(),
            track_namespace,
            track_name,
            track_alias,
            parameters,
            track_properties,
        });
        Ok((req_id, msg))
    }

    pub fn receive_publish_ok(
        &mut self,
        request_id: VarInt,
        _msg: &message::PublishOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        let sm = self.publishes.get_mut(&id).ok_or(EndpointError::UnknownRequest(id))?;
        sm.on_publish_ok()?;
        Ok(())
    }

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
        Ok(ControlMessage::PublishDone(PublishDone { status_code, stream_count, reason_phrase }))
    }

    // -- Consolidated responses (draft-17: per-bidi-stream routing) -

    /// Process an incoming REQUEST_OK on the bidi stream identified by
    /// `request_id`. Used by PublishNamespace, SubscribeNamespace, and
    /// TrackStatus flows.
    pub fn receive_request_ok(
        &mut self,
        request_id: VarInt,
        _msg: &RequestOk,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_subscribe_namespace_ok()?;
            return Ok(());
        }
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_publish_namespace_ok()?;
            return Ok(());
        }
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_track_status_ok()?;
            return Ok(());
        }
        Err(EndpointError::UnknownRequest(id))
    }

    /// Process an incoming REQUEST_ERROR on the bidi stream identified by
    /// `request_id`.
    pub fn receive_request_error(
        &mut self,
        request_id: VarInt,
        _msg: &RequestError,
    ) -> Result<(), EndpointError> {
        let id = request_id.into_inner();
        if let Some(sm) = self.subscriptions.get_mut(&id) {
            sm.on_subscribe_error()?;
            return Ok(());
        }
        if let Some(sm) = self.fetches.get_mut(&id) {
            sm.on_fetch_error()?;
            return Ok(());
        }
        if let Some(sm) = self.publishes.get_mut(&id) {
            sm.on_publish_error()?;
            return Ok(());
        }
        if let Some(sm) = self.subscribe_namespaces.get_mut(&id) {
            sm.on_subscribe_namespace_error()?;
            return Ok(());
        }
        if let Some(sm) = self.publish_namespaces.get_mut(&id) {
            sm.on_publish_namespace_error()?;
            return Ok(());
        }
        if let Some(sm) = self.track_statuses.get_mut(&id) {
            sm.on_track_status_error()?;
            return Ok(());
        }
        Err(EndpointError::UnknownRequest(id))
    }

    // -- PublishBlocked / Namespace announcements -------------------

    /// Receive an unsolicited NAMESPACE announcement. Informational — no
    /// state machine is involved.
    pub fn receive_namespace(&mut self, _msg: &message::Namespace) -> Result<(), EndpointError> {
        Ok(())
    }

    /// Receive an unsolicited NAMESPACE_DONE announcement.
    pub fn receive_namespace_done(
        &mut self,
        _msg: &message::NamespaceDone,
    ) -> Result<(), EndpointError> {
        Ok(())
    }

    /// Receive a PUBLISH_BLOCKED notification.
    pub fn receive_publish_blocked(&mut self, _msg: &PublishBlocked) -> Result<(), EndpointError> {
        Ok(())
    }

    // -- Unified message dispatch -----------------------------------

    /// Dispatch a message that arrived on the *control stream* (SETUP,
    /// GOAWAY, unsolicited announcements, RequestUpdate). Response messages
    /// belong on bidi request streams — they are rejected here.
    pub fn receive_message(&mut self, msg: ControlMessage) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::Setup(ref m) => self.receive_setup(m),
            ControlMessage::GoAway(ref m) => self.receive_goaway(m),
            ControlMessage::RequestUpdate(ref m) => self.receive_request_update(m),
            ControlMessage::Namespace(ref m) => self.receive_namespace(m),
            ControlMessage::NamespaceDone(ref m) => self.receive_namespace_done(m),
            ControlMessage::PublishBlocked(ref m) => self.receive_publish_blocked(m),
            ControlMessage::SubscribeOk(_)
            | ControlMessage::PublishDone(_)
            | ControlMessage::PublishOk(_)
            | ControlMessage::FetchOk(_)
            | ControlMessage::RequestOk(_)
            | ControlMessage::RequestError(_) => Err(EndpointError::ResponseOnControlStream),
            _ => Ok(()),
        }
    }

    /// Dispatch a response message that arrived on the bidi request stream
    /// identified by `request_id` (draft-17 §3.3). Accepts only the
    /// response-bearing message types.
    pub fn receive_response_on_stream(
        &mut self,
        request_id: VarInt,
        msg: ControlMessage,
    ) -> Result<(), EndpointError> {
        match msg {
            ControlMessage::SubscribeOk(ref m) => self.receive_subscribe_ok(request_id, m),
            ControlMessage::PublishDone(ref m) => self.receive_publish_done(request_id, m),
            ControlMessage::PublishOk(ref m) => self.receive_publish_ok(request_id, m),
            ControlMessage::FetchOk(ref m) => self.receive_fetch_ok(request_id, m),
            ControlMessage::RequestOk(ref m) => self.receive_request_ok(request_id, m),
            ControlMessage::RequestError(ref m) => self.receive_request_error(request_id, m),
            _ => Err(EndpointError::ResponseOnControlStream),
        }
    }
}

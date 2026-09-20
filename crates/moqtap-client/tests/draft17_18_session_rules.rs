#![cfg(all(feature = "draft17", feature = "draft18"))]

//! The rules drafts 17 and 18 answer with a session close, and the one
//! draft-18 answers by migrating a single request.
//!
//! Each gate observes a consequence: the endpoint's session state after the
//! message, and the close code the connection layer would put on the wire. None
//! of them reads a configured value back.

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|s| s.to_vec()).collect())
}

// ─────────────────────────────────────────────────────────────
// GOAWAY at a server, drafts 17 and 18
// ─────────────────────────────────────────────────────────────

/// A GOAWAY carrying a New Session URI ends the session when it arrives at a
/// server.
///
/// Draft-17 Section 9.5 and draft-18 Section 10.4, identically: "If a server
/// receives a GOAWAY with a non-zero New Session URI Length it MUST close the
/// session with a PROTOCOL_VIOLATION." Migration is something a server offers a
/// client, never the other way round.
///
/// The gate is what the endpoint does next, not the error text: the session must
/// be Closed, the close code must be PROTOCOL_VIOLATION, and `goaway_uri()` must
/// still be empty — an application that could read the URI back would reconnect
/// to somewhere a client chose.
///
/// # Observed with the fix reverted
///
/// Deleting the `role == Role::Server` guard from draft-17's `receive_goaway`:
///
/// ```text
/// ---- a_goaway_uri_at_a_server_closes_the_session stdout ----
///
/// thread 'a_goaway_uri_at_a_server_closes_the_session' (6868) panicked at crates\moqtap-client\tests\draft17_18_session_rules.rs:
/// draft-17 accepted a client-supplied migration URI at a server: ()
/// ```
#[test]
fn a_goaway_uri_at_a_server_closes_the_session() {
    {
        use moqtap_client::draft17::endpoint::{Endpoint, EndpointError};
        use moqtap_client::draft17::session::request_id::Role;
        use moqtap_client::draft17::session::state::SessionState;
        use moqtap_codec::draft17::error_codes::SessionErrorCode;
        use moqtap_codec::draft17::message::{GoAway, Setup};

        let mut ep = Endpoint::new(Role::Server);
        ep.connect().unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();

        let goaway =
            GoAway { new_session_uri: b"https://elsewhere.example".to_vec(), timeout: varint(0) };
        let err = ep
            .receive_goaway(&goaway)
            .expect_err("draft-17 accepted a client-supplied migration URI at a server");
        assert!(matches!(err, EndpointError::GoAwayUriAtServer), "got {err:?}");
        assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
        assert_eq!(ep.session_state(), SessionState::Closed);
        assert_eq!(ep.goaway_uri(), None, "the refused URI was stored anyway");

        // A client is the side that may be redirected, so the same message is
        // accepted there and the URI is kept.
        let mut client = Endpoint::new(Role::Client);
        client.connect().unwrap();
        client.receive_setup(&Setup { options: vec![] }).unwrap();
        client.receive_goaway(&goaway).expect("a client may be redirected");
        assert_eq!(client.goaway_uri(), Some(&b"https://elsewhere.example"[..]));
    }

    {
        use moqtap_client::draft18::endpoint::{Endpoint, EndpointError};
        use moqtap_client::draft18::session::request_id::Role;
        use moqtap_client::draft18::session::state::SessionState;
        use moqtap_codec::draft18::error_codes::SessionErrorCode;
        use moqtap_codec::draft18::message::{GoAway, Setup};

        let mut ep = Endpoint::new(Role::Server);
        ep.connect().unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();

        let goaway = GoAway {
            new_session_uri: b"https://elsewhere.example".to_vec(),
            timeout: varint(0),
            request_id: None,
        };
        let err = ep
            .receive_goaway(&goaway)
            .expect_err("draft-18 accepted a client-supplied migration URI at a server");
        assert!(matches!(err, EndpointError::GoAwayUriAtServer), "got {err:?}");
        assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
        assert_eq!(ep.session_state(), SessionState::Closed);
        assert_eq!(ep.goaway_uri(), None, "the refused URI was stored anyway");
    }
}

// ─────────────────────────────────────────────────────────────
// Draft-18 Section 10.4 — GOAWAY on one request stream
// ─────────────────────────────────────────────────────────────

/// A GOAWAY on a request stream migrates that request and leaves the session
/// running.
///
/// Draft-18 Table 5 gives GOAWAY the Stream value "Control, Request", and
/// Section 10.4 says why: "A GOAWAY MAY also be sent on a request stream to
/// initiate migration of that individual request." The session keeps running —
/// only this request is being moved.
///
/// Two consequences are gated. The message must be accepted at all: before the
/// fix `receive_response_on_stream` had no GOAWAY arm and fell into the
/// catch-all, so a relay migrating one subscription had its GOAWAY refused as
/// ResponseOnControlStream and the client neither re-issued nor closed
/// anything. And the session must still be Active afterwards — routing it to the
/// session-wide handler instead would take the whole session to Draining over
/// something the draft scopes to one request.
///
/// # Observed with the fix reverted
///
/// Removing the GOAWAY arm from draft-18's `receive_response_on_stream`:
///
/// ```text
/// ---- a_goaway_on_a_request_stream_migrates_only_that_request stdout ----
///
/// thread 'a_goaway_on_a_request_stream_migrates_only_that_request' (46112) panicked at crates\moqtap-client\tests\draft17_18_session_rules.rs:
/// a per-request GOAWAY was refused: ResponseOnControlStream
/// ```
#[test]
fn a_goaway_on_a_request_stream_migrates_only_that_request() {
    use moqtap_client::draft18::endpoint::Endpoint;
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::session::state::SessionState;
    use moqtap_codec::draft18::message::{ControlMessage, GoAway, Setup, SubscribeOk};

    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_setup(vec![]).unwrap();
    ep.receive_setup(&Setup { options: vec![] }).unwrap();

    let (id, _) = ep.subscribe(ns(&[b"live"]), b"video".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(
        id,
        ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: varint(1),
            parameters: vec![],
            track_properties: vec![],
        }),
    )
    .unwrap();

    let goaway = ControlMessage::GoAway(GoAway {
        new_session_uri: b"https://other.example".to_vec(),
        timeout: varint(0),
        request_id: None,
    });
    ep.receive_response_on_stream(id, goaway).expect("a per-request GOAWAY was refused");

    assert_eq!(
        ep.session_state(),
        SessionState::Active,
        "a per-request GOAWAY drained the whole session"
    );
    assert_eq!(ep.goaway_uri(), None, "a per-request GOAWAY set the session's migration URI");
}

// ─────────────────────────────────────────────────────────────
// Draft-18 Section 10.5 — Track Properties belong to TRACK_STATUS_OK
// ─────────────────────────────────────────────────────────────

/// Track Properties on a REQUEST_OK that answers anything but a TRACK_STATUS end
/// the session.
///
/// Draft-18 Section 10.5: they "are populated in TRACK_STATUS_OK; they are empty
/// in PUBLISH_OK, REQUEST_UPDATE_OK, SUBSCRIBE_NAMESPACE_OK and
/// PUBLISH_NAMESPACE_OK. If an endpoint receives Track Properties in one of
/// these messages it MUST close the session with a PROTOCOL_VIOLATION."
///
/// The codec cannot make this check: REQUEST_OK is one wire form, and only the
/// request stream says which of the five shapes it is. The same message on a
/// TRACK_STATUS's stream is accepted, which is what makes this a rule about the
/// request rather than about the bytes.
#[test]
fn track_properties_are_refused_on_a_request_ok_that_answers_no_track_status() {
    use moqtap_client::draft18::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::session::state::SessionState;
    use moqtap_codec::draft18::error_codes::SessionErrorCode;
    use moqtap_codec::draft18::message::{ControlMessage, RequestOk, Setup};
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    fn active() -> Endpoint {
        let mut ep = Endpoint::new(Role::Client);
        ep.connect().unwrap();
        let _ = ep.send_setup(vec![]).unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();
        ep
    }
    fn with_properties() -> ControlMessage {
        ControlMessage::RequestOk(RequestOk {
            parameters: vec![],
            track_properties: vec![KeyValuePair {
                key: VarInt::from_u64_moqt(0x02),
                value: KvpValue::Varint(VarInt::from_u64_moqt(1)),
            }],
        })
    }

    // A PUBLISH_NAMESPACE's REQUEST_OK must carry none.
    let mut ep = active();
    let (id, _) = ep.publish_namespace(ns(&[b"live"]), vec![]).unwrap();
    let err = ep
        .receive_response_on_stream(id, with_properties())
        .expect_err("track properties were accepted on a PUBLISH_NAMESPACE_OK");
    assert!(matches!(err, EndpointError::TrackPropertiesOnNonTrackStatus(_)), "got {err:?}");
    assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
    assert_eq!(ep.session_state(), SessionState::Closed);

    // A TRACK_STATUS's REQUEST_OK is where they belong.
    let mut ep = active();
    let (id, _) = ep.track_status(ns(&[b"live"]), b"video".to_vec(), vec![]).unwrap();
    ep.receive_response_on_stream(id, with_properties())
        .expect("track properties were refused on a TRACK_STATUS_OK");
    assert_eq!(ep.session_state(), SessionState::Active);
}

// ─────────────────────────────────────────────────────────────
// Draft-18 Section 10.6.1 — Redirect
// ─────────────────────────────────────────────────────────────

/// A Redirect is refused at a server when it names a Connect URI, and refused
/// anywhere when it puts a Track Name on a namespace-scoped request.
///
/// Draft-18 Section 10.6.1: "If a server receives a Redirect with a non-zero
/// Connect URI Length it MUST close the session with a PROTOCOL_VIOLATION." And:
/// "Track Name is not meaningful for namespace-scoped requests
/// (SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE) and MUST be empty; an endpoint that
/// receives a non-empty Track Name in a Redirect for a namespace-scoped request
/// MUST close the session with a PROTOCOL_VIOLATION."
///
/// Both rules are conditional on which request the response answers, which is
/// known only at the endpoint — the codec sees one REQUEST_ERROR shape either
/// way. Unchecked, a Redirect sends a server chasing a URI a client picked.
#[test]
fn a_redirect_is_held_to_the_rules_of_the_request_it_answers() {
    use moqtap_client::draft18::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::session::state::SessionState;
    use moqtap_codec::draft18::error_codes::SessionErrorCode;
    use moqtap_codec::draft18::message::{
        request_error_codes, ControlMessage, Redirect, RequestError, Setup,
    };

    fn active(role: Role) -> Endpoint {
        let mut ep = Endpoint::new(role);
        ep.connect().unwrap();
        if role == Role::Client {
            let _ = ep.send_setup(vec![]).unwrap();
        }
        ep.receive_setup(&Setup { options: vec![] }).unwrap();
        ep
    }
    fn redirect(connect_uri: &[u8], track_name: &[u8]) -> ControlMessage {
        ControlMessage::RequestError(RequestError {
            error_code: VarInt::from_u64_moqt(request_error_codes::REDIRECT),
            retry_interval: varint(0),
            reason_phrase: b"moved".to_vec(),
            redirect: Some(Redirect {
                connect_uri: connect_uri.to_vec(),
                track_namespace: ns(&[b"live"]),
                track_name: track_name.to_vec(),
            }),
        })
    }

    // A server may not be handed a Connect URI.
    let mut server = active(Role::Server);
    let (id, _) = server.subscribe(ns(&[b"live"]), b"video".to_vec(), vec![]).unwrap();
    let err = server
        .receive_response_on_stream(id, redirect(b"https://elsewhere.example", b"video"))
        .expect_err("a server followed a client-chosen Connect URI");
    assert!(matches!(err, EndpointError::RedirectUriAtServer), "got {err:?}");
    assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
    assert_eq!(server.session_state(), SessionState::Closed);

    // A client may: the same message is what redirection is for.
    let mut client = active(Role::Client);
    let (id, _) = client.subscribe(ns(&[b"live"]), b"video".to_vec(), vec![]).unwrap();
    client
        .receive_response_on_stream(id, redirect(b"https://elsewhere.example", b"video"))
        .expect("a client was refused a Redirect");

    // A namespace-scoped request's Redirect must carry no Track Name.
    let mut client = active(Role::Client);
    let (id, _) = client.subscribe_namespace(ns(&[b"live"]), vec![]).unwrap();
    let err = client
        .receive_response_on_stream(id, redirect(b"", b"video"))
        .expect_err("a namespace-scoped Redirect carried a track name");
    assert!(matches!(err, EndpointError::RedirectTrackNameOnNamespaceRequest(_)), "got {err:?}");
    assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
    assert_eq!(client.session_state(), SessionState::Closed);

    // With the Track Name empty the same Redirect is fine.
    let mut client = active(Role::Client);
    let (id, _) = client.subscribe_namespace(ns(&[b"live"]), vec![]).unwrap();
    client
        .receive_response_on_stream(id, redirect(b"", b""))
        .expect("an empty-name namespace Redirect was refused");
    assert_eq!(client.session_state(), SessionState::Active);
}

// ─────────────────────────────────────────────────────────────
// Draft-18 Sections 10.1 and 10.9 — REQUEST_UPDATE placement
// ─────────────────────────────────────────────────────────────

/// A REQUEST_UPDATE names its target by the stream it arrives on, and arriving
/// on the control stream ends the session.
///
/// Draft-18 Table 5 marks REQUEST_UPDATE (0x2) "Request", and Section 10.9 says
/// it is sent "on the same bidi stream as the request to modify it". Section
/// 10.1 lists REQUEST_UPDATE among the messages that consume a Request ID of
/// their own, so the id in the body is the update's, not the target's — reading
/// it as the target means every conforming peer's update names a request that by
/// construction does not exist.
///
/// The update below carries an id naming nothing and still has to land on the
/// subscription whose stream it came in on.
#[test]
fn a_request_update_is_correlated_by_its_stream_and_refused_on_the_control_stream() {
    use moqtap_client::draft18::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::session::state::SessionState;
    use moqtap_codec::draft18::message::{ControlMessage, RequestUpdate, Setup, SubscribeOk};

    fn active_with_subscription() -> (Endpoint, VarInt) {
        let mut ep = Endpoint::new(Role::Client);
        ep.connect().unwrap();
        let _ = ep.send_setup(vec![]).unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();
        let (id, _) = ep.subscribe(ns(&[b"live"]), b"video".to_vec(), vec![]).unwrap();
        ep.receive_response_on_stream(
            id,
            ControlMessage::SubscribeOk(SubscribeOk {
                track_alias: varint(1),
                parameters: vec![],
                track_properties: vec![],
            }),
        )
        .unwrap();
        (ep, id)
    }

    let (mut ep, id) = active_with_subscription();
    let update = ControlMessage::RequestUpdate(RequestUpdate {
        request_id: varint(id.into_inner() + 100),
        parameters: vec![],
    });
    ep.receive_response_on_stream(id, update)
        .expect("an update whose own id names nothing was refused");

    let (mut ep, id) = active_with_subscription();
    let update =
        ControlMessage::RequestUpdate(RequestUpdate { request_id: id, parameters: vec![] });
    let err = ep
        .receive_message(update)
        .expect_err("a REQUEST_UPDATE was accepted on the control stream");
    assert!(matches!(err, EndpointError::RequestUpdateOnControlStream), "got {err:?}");

    // Refused, and the session runs on. This asserted
    // `Some(ProtocolViolation)` and `SessionState::Closed` until 2026-09-10,
    // on the reading that Section 3.3's opener sentence reaches a message
    // arriving on the control stream. It does not — that sentence is about
    // what a bidirectional stream may *begin* with. Draft-18 Section 10.9
    // describes where a REQUEST_UPDATE travels and attaches no consequence to
    // one that arrives elsewhere; draft-19 is the first to add
    // "An endpoint that receives a REQUEST_UPDATE other than in the two cases
    // above MUST close the session with a PROTOCOL_VIOLATION." So on this
    // draft the close was this build's model, and it is gone.
    assert_eq!(
        err.session_error_code(),
        None,
        "draft-18 states no close for a REQUEST_UPDATE on the control stream"
    );
    assert_eq!(ep.session_state(), SessionState::Active);
}

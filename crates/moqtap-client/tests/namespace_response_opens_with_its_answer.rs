//! A namespace subscription's response half opens with the answer, from draft-18.
//!
//! SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS are the two requests whose response
//! half carries traffic of its own after the answer — NAMESPACE and
//! NAMESPACE_DONE for the first, PUBLISH_BLOCKED for the second — so they are
//! the two where a message could arrive before the answer and be taken for a
//! stream that had been accepted. Sections 10.18 and 10.19 close that:
//!
//! > The publisher will respond with REQUEST_OK or REQUEST_ERROR on the
//! > response half of the stream. If the subscriber receives any message other
//! > than a REQUEST_OK or a REQUEST_ERROR as the first message on the response
//! > half of the stream, then it MUST close the session with a
//! > PROTOCOL_VIOLATION.
//!
//! # Why draft-17 is here refusing nothing
//!
//! The rule enters at draft-18. Its own change log lists "Enforce
//! REQUEST_OK/ERROR as first message on the response stream (#1499)" among the
//! changes from draft-17, and the sentence is absent from every draft before
//! it. Draft-17 has the same request, the same response stream and the same
//! NAMESPACE messages on it, and says nothing about which comes first — so a
//! draft-17 endpoint that refused this would be closing sessions over traffic
//! that draft permits. The gate below asserts the acceptance rather than
//! leaving the exclusion unwritten, because an absent check leaves no trace of
//! whether it was considered.

#![cfg(all(feature = "draft17", feature = "draft18", feature = "draft19"))]

use moqtap_codec::types::TrackNamespace;

fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

// -- draft-18 ---------------------------------------------------------------

mod draft18 {
    use super::ns;
    use moqtap_client::draft18::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::session::state::SessionState;
    use moqtap_codec::draft18::error_codes::SessionErrorCode;
    use moqtap_codec::draft18::message::{self, ControlMessage, PublishBlocked, RequestOk, Setup};
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        let _ = endpoint.send_setup(vec![]).unwrap();
        endpoint.receive_setup(&Setup { options: vec![] }).unwrap();
        endpoint
    }

    fn request_ok() -> ControlMessage {
        ControlMessage::RequestOk(RequestOk { parameters: vec![], track_properties: vec![] })
    }

    fn namespace() -> ControlMessage {
        ControlMessage::Namespace(message::Namespace { namespace_suffix: ns() })
    }

    fn publish_blocked() -> ControlMessage {
        ControlMessage::PublishBlocked(PublishBlocked {
            namespace_suffix: ns(),
            track_name: b"video".to_vec(),
        })
    }

    /// A NAMESPACE before the answer closes the session.
    ///
    /// The message is otherwise perfectly placed: Table 5 puts NAMESPACE on
    /// this very stream, and the endpoint accepts it there once the answer has
    /// arrived. What the draft refuses is the order, and the order is the whole
    /// of the rule.
    ///
    /// Ablation: dropping the `require_the_first_response_first` call from
    /// `receive_response_on_stream` fails with
    ///
    /// ```text
    /// a NAMESPACE before the REQUEST_OK must close the session: Ok(())
    /// ```
    #[test]
    fn a_namespace_before_the_answer_closes_the_session() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_namespace(ns(), vec![]).unwrap();

        let result = endpoint.receive_response_on_stream(id, namespace());
        let err = match result {
            Err(e) => e,
            Ok(()) => panic!("a NAMESPACE before the REQUEST_OK must close the session: Ok(())"),
        };
        assert!(
            matches!(err, EndpointError::ResponseBeforeTheFirstResponse(got, _) if got == id.into_inner()),
            "the error must name the request whose stream it arrived on: {err:?}",
        );
        assert_eq!(
            err.session_error_code(),
            Some(SessionErrorCode::ProtocolViolation),
            "the draft names PROTOCOL_VIOLATION, and an error the caller may ignore is not a close",
        );
        assert_eq!(
            endpoint.session_state(),
            SessionState::Closed,
            "the endpoint must have moved its own session state, not only reported",
        );
    }

    /// The same message, after the answer, is accepted.
    ///
    /// Without this half the gate above would pass just as well against an
    /// endpoint that refused NAMESPACE outright, which is a different and wrong
    /// implementation of the same sentence.
    #[test]
    fn the_same_message_after_the_answer_is_accepted() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_namespace(ns(), vec![]).unwrap();
        endpoint
            .receive_response_on_stream(id, request_ok())
            .expect("REQUEST_OK answers the subscription");

        endpoint
            .receive_response_on_stream(id, namespace())
            .expect("a NAMESPACE after the answer is what this stream is for");
        assert_eq!(endpoint.session_state(), SessionState::Active);
    }

    /// SUBSCRIBE_TRACKS is held to it too, and with its own message.
    ///
    /// Section 10.19 states the sentence separately from 10.18, and the two
    /// requests keep separate maps, so an implementation that checked one and
    /// not the other would pass a gate written only against SUBSCRIBE_NAMESPACE.
    #[test]
    fn subscribe_tracks_is_held_to_the_same_rule() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_tracks(ns(), vec![]).unwrap();

        let result = endpoint.receive_response_on_stream(id, publish_blocked());
        assert!(
            matches!(result, Err(EndpointError::ResponseBeforeTheFirstResponse(..))),
            "a PUBLISH_BLOCKED before the REQUEST_OK must close the session: {result:?}",
        );
    }

    /// A REQUEST_ERROR opens the stream just as well as a REQUEST_OK.
    ///
    /// The draft names both, and an implementation that took only the success
    /// case would close the session on every namespace subscription that was
    /// refused - the case where the peer did exactly what it was told to.
    #[test]
    fn a_request_error_is_an_answer_too() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_namespace(ns(), vec![]).unwrap();
        let err = ControlMessage::RequestError(message::RequestError {
            error_code: VarInt::from_u64(1).unwrap(),
            retry_interval: VarInt::from_u64(0).unwrap(),
            reason_phrase: b"no".to_vec(),
            redirect: None,
        });

        endpoint.receive_response_on_stream(id, err).expect("REQUEST_ERROR answers it as well");
        assert_eq!(endpoint.session_state(), SessionState::Active);
    }

    /// A request of another kind is not this rule's subject.
    ///
    /// SUBSCRIBE has SUBSCRIBE_OK as its own first message, and the sentence is
    /// written in the two namespace sections rather than in Section 10.1, so a
    /// check that reached every request stream would be a rule this draft does
    /// not state.
    #[test]
    fn a_subscription_stream_is_not_held_to_it() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe(ns(), b"video".to_vec(), vec![]).unwrap();

        // Not a valid message on this stream either, but it fails as an
        // unrecognised response rather than as an out-of-order one.
        let result = endpoint.receive_response_on_stream(id, namespace());
        assert!(
            !matches!(result, Err(EndpointError::ResponseBeforeTheFirstResponse(..))),
            "the first-message rule belongs to the two namespace requests: {result:?}",
        );
    }
}

// -- draft-19 ---------------------------------------------------------------

mod draft19 {
    use super::ns;
    use moqtap_client::draft19::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft19::session::request_id::Role;
    use moqtap_client::draft19::session::state::SessionState;
    use moqtap_codec::draft19::error_codes::SessionErrorCode;
    use moqtap_codec::draft19::message::{self, ControlMessage, PublishSkipped, RequestOk, Setup};

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        let _ = endpoint.send_setup(vec![]).unwrap();
        endpoint.receive_setup(&Setup { options: vec![] }).unwrap();
        endpoint
    }

    fn namespace() -> ControlMessage {
        ControlMessage::Namespace(message::Namespace { namespace_suffix: ns() })
    }

    /// Draft-19 keeps the sentence, under the message's new name.
    ///
    /// PUBLISH_BLOCKED became PUBLISH_SKIPPED at the same message type, which
    /// changes what the gate below builds and nothing about the rule.
    #[test]
    fn a_namespace_before_the_answer_closes_the_session() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_namespace(ns(), vec![]).unwrap();

        let result = endpoint.receive_response_on_stream(id, namespace());
        let err = match result {
            Err(e) => e,
            Ok(()) => panic!("a NAMESPACE before the REQUEST_OK must close the session: Ok(())"),
        };
        assert_eq!(err.session_error_code(), Some(SessionErrorCode::ProtocolViolation));
        assert_eq!(endpoint.session_state(), SessionState::Closed);
    }

    #[test]
    fn the_same_message_after_the_answer_is_accepted() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_namespace(ns(), vec![]).unwrap();
        endpoint
            .receive_response_on_stream(
                id,
                ControlMessage::RequestOk(RequestOk {
                    parameters: vec![],
                    track_properties: vec![],
                }),
            )
            .expect("REQUEST_OK answers the subscription");

        endpoint
            .receive_response_on_stream(id, namespace())
            .expect("a NAMESPACE after the answer is what this stream is for");
    }

    #[test]
    fn subscribe_tracks_is_held_to_the_same_rule() {
        let mut endpoint = active();
        let (id, _) = endpoint.subscribe_tracks(ns(), vec![]).unwrap();

        let skipped = ControlMessage::PublishSkipped(PublishSkipped {
            namespace_suffix: ns(),
            track_name: b"video".to_vec(),
        });
        let result = endpoint.receive_response_on_stream(id, skipped);
        assert!(
            matches!(result, Err(EndpointError::ResponseBeforeTheFirstResponse(..))),
            "a PUBLISH_SKIPPED before the REQUEST_OK must close the session: {result:?}",
        );
    }
}

// -- draft-17, which does not state the rule --------------------------------

mod draft17 {
    use super::ns;
    use moqtap_client::draft17::endpoint::Endpoint;
    use moqtap_client::draft17::session::request_id::Role;
    use moqtap_client::draft17::session::state::SessionState;
    use moqtap_codec::draft17::message::{self, ControlMessage, Setup};
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        let _ = endpoint.send_setup(vec![]).unwrap();
        endpoint.receive_setup(&Setup { options: vec![] }).unwrap();
        endpoint
    }

    /// The same sequence draft-18 closes the session over is accepted here.
    ///
    /// Not an oversight carried forward: draft-17 Section 9.18 describes the
    /// same stream and the same NAMESPACE messages on it without saying which
    /// message comes first, and draft-18 lists the enforcement as a change it
    /// made. So this is the behaviour draft-17 asks for, and the gate exists so
    /// that a later reader finds the exclusion written down rather than
    /// inferring it from an absence.
    #[test]
    fn a_namespace_before_the_answer_is_accepted() {
        let mut endpoint = active();
        let (id, _) =
            endpoint.subscribe_namespace(ns(), VarInt::from_u64(0).unwrap(), vec![]).unwrap();

        endpoint
            .receive_response_on_stream(
                id,
                ControlMessage::Namespace(message::Namespace { namespace_suffix: ns() }),
            )
            .expect("draft-17 states no rule about which message opens the response half");
        assert_eq!(endpoint.session_state(), SessionState::Active);
    }
}

//! Which endpoint may send which setup parameter, on every draft that says.
//!
//! Exactly one setup parameter has a sender restriction, and it is PATH: "It
//! MUST NOT be used by the server, or when WebTransport is used. If the peer
//! receives a PATH parameter from the server, or when WebTransport is used, it
//! MUST close the connection." The parameter that carries the peer's request
//! budget - MAX_SUBSCRIBE_ID before draft-11, MAX_REQUEST_ID after - has no
//! restriction at all: it "communicates an initial value ... to the receiving
//! endpoint", which is something either end may do.
//!
//! The first gate below decodes a canonical vector rather than building a
//! message, because that is where a disagreement between the two shows: a
//! CLIENT_SETUP the corpus carries and the validator will not accept is
//! invisible to a gate that builds its own message, which exercises only one of
//! them. Every draft is driven, because the sentence is in every draft.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// A PATH parameter, key 0x01, holding a path a client might really send.
fn path() -> KeyValuePair {
    KeyValuePair { key: varint(0x01), value: KvpValue::Bytes(b"/moq".to_vec()) }
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{path, varint};
    use moqtap_client::draft07::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft07::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-subscribe-id
    const VECTOR: &[u8] = &[
        0x40, 0x40, 0x17, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x07, 0x03, 0x00, 0x01,
        0x03, 0x01, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x02, 0x40, 0x64,
    ];

    /// The ROLE parameter draft-07 requires of both endpoints, in the shape
    /// this era gives a setup parameter value. Section 6.2.2.1 closes the
    /// session on its absence, so a SERVER_SETUP under test here carries one:
    /// without it the refusal below could be the missing ROLE rather than the
    /// PATH.
    fn role() -> KeyValuePair {
        KeyValuePair { key: varint(0x00), value: KvpValue::Bytes(vec![0x03]) }
    }

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup =
            ServerSetup { selected_version: varint(0xff000007), parameters: vec![role(), path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{path, varint};
    use moqtap_client::draft08::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft08::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-subscribe-id
    const VECTOR: &[u8] = &[
        0x40, 0x40, 0x14, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x08, 0x02, 0x01, 0x04,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x02, 0x40, 0x64,
    ];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff000008), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{path, varint};
    use moqtap_client::draft09::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft09::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-subscribe-id
    const VECTOR: &[u8] = &[
        0x40, 0x40, 0x14, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x09, 0x02, 0x01, 0x04,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x02, 0x40, 0x64,
    ];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff000009), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{path, varint};
    use moqtap_client::draft10::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft10::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-subscribe-id
    const VECTOR: &[u8] = &[
        0x40, 0x40, 0x14, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0a, 0x02, 0x01, 0x04,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x02, 0x40, 0x64,
    ];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff00000a), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{path, varint};
    use moqtap_client::draft11::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft11::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-request-id
    const VECTOR: &[u8] = &[
        0x20, 0x00, 0x13, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0b, 0x02, 0x01, 0x04,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x40, 0xc8,
    ];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff00000b), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{path, varint};
    use moqtap_client::draft12::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft12::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-request-id
    const VECTOR: &[u8] = &[
        0x20, 0x00, 0x13, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0c, 0x02, 0x01, 0x04,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x40, 0xc8,
    ];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff00000c), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{path, varint};
    use moqtap_client::draft13::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft13::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / with-path-and-max-request-id
    const VECTOR: &[u8] = &[
        0x20, 0x00, 0x13, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0d, 0x02, 0x01, 0x04,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x40, 0xc8,
    ];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff00000d), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::{path, varint};
    use moqtap_client::draft14::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft14::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / max-request-id-param
    const VECTOR: &[u8] =
        &[0x20, 0x00, 0x0c, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0e, 0x01, 0x02, 0x00];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { selected_version: varint(0xff00000e), parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{path, varint};
    use moqtap_client::draft15::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft15::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / max-request-id-param
    const VECTOR: &[u8] = &[0x20, 0x00, 0x03, 0x01, 0x02, 0x00];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{path, varint};
    use moqtap_client::draft16::session::setup::{
        validate_client_path_transport, validate_client_setup, validate_server_setup, SetupError,
    };
    use moqtap_codec::draft16::message::{ClientSetup, ControlMessage, ServerSetup};
    #[allow(unused_imports)]
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// client-setup.json / max-request-id-param
    const VECTOR: &[u8] = &[0x20, 0x00, 0x03, 0x01, 0x02, 0x00];

    fn client_setup_from_corpus() -> ClientSetup {
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ClientSetup(setup) => setup,
            other => panic!("the vector is a CLIENT_SETUP, got {other:?}"),
        }
    }

    /// A canonical CLIENT_SETUP from this repository's own corpus, carrying the
    /// parameter that grants the peer a budget.
    ///
    /// Refusing key 0x02 in `validate_client_setup` again fails with:
    ///
    /// ```text
    /// a CLIENT_SETUP that grants a budget must be accepted: Err(WrongParameterRole(2))
    /// ```
    #[test]
    fn a_client_setup_may_grant_the_peer_a_budget() {
        let setup = client_setup_from_corpus();
        assert!(
            setup.parameters.iter().any(|p| p.key == varint(0x02)),
            "the vector must still be the one that carries the budget parameter",
        );

        let result = validate_client_setup(&setup);
        assert!(result.is_ok(), "a CLIENT_SETUP that grants a budget must be accepted: {result:?}");
    }

    /// PATH from a server closes the session, so it must not get past
    /// validation. The error is pinned rather than merely being an error: on
    /// the drafts that require other parameters, "some error" would pass on the
    /// wrong one.
    ///
    /// Dropping the check from `validate_server_setup` fails with:
    ///
    /// ```text
    /// a SERVER_SETUP carrying PATH must be refused for being a PATH: Ok(())
    /// ```
    #[test]
    fn a_server_setup_may_not_carry_path() {
        let setup = ServerSetup { parameters: vec![path()] };
        let result = validate_server_setup(&setup);
        assert!(
            matches!(result, Err(SetupError::WrongParameterRole(0x01))),
            "a SERVER_SETUP carrying PATH must be refused for being a PATH: {result:?}",
        );
    }

    /// The other half of the same sentence. PATH is for native QUIC, and the
    /// second assertion is what keeps the first from being satisfied by an
    /// implementation that refuses PATH everywhere.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let parameters = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&parameters, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&parameters, false).is_ok(),
            "PATH over native QUIC is what the parameter is for",
        );
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use moqtap_client::draft17::session::request_id::Role;
    use moqtap_client::draft17::session::setup::{
        validate_client_path_transport, validate_setup, SetupError,
    };
    use moqtap_codec::draft17::message::Setup;

    use super::path;

    /// This draft merges the two setup messages into one, so nothing in the
    /// message says which end sent it and the sender is an argument. The rule
    /// is unchanged: a server may not send PATH, a client may.
    ///
    /// Dropping the role check from `validate_setup` fails with:
    ///
    /// ```text
    /// a SETUP from a server carrying PATH must be refused
    /// ```
    #[test]
    fn a_setup_from_a_server_may_not_carry_path() {
        let setup = Setup { options: vec![path()] };
        assert!(
            matches!(
                validate_setup(&setup, Role::Server),
                Err(SetupError::WrongOptionRole(0x01, _))
            ),
            "a SETUP from a server carrying PATH must be refused",
        );
        assert!(
            validate_setup(&setup, Role::Client).is_ok(),
            "the same option from a client is what PATH is for",
        );
    }

    /// The transport half of the same sentence.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let options = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&options, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&options, false).is_ok(),
            "PATH over native QUIC is what the option is for",
        );
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use moqtap_client::draft18::session::request_id::Role;
    use moqtap_client::draft18::session::setup::{
        validate_client_path_transport, validate_setup, SetupError,
    };
    use moqtap_codec::draft18::message::Setup;

    use super::path;

    /// This draft merges the two setup messages into one, so nothing in the
    /// message says which end sent it and the sender is an argument. The rule
    /// is unchanged: a server may not send PATH, a client may.
    ///
    /// Dropping the role check from `validate_setup` fails with:
    ///
    /// ```text
    /// a SETUP from a server carrying PATH must be refused
    /// ```
    #[test]
    fn a_setup_from_a_server_may_not_carry_path() {
        let setup = Setup { options: vec![path()] };
        assert!(
            matches!(
                validate_setup(&setup, Role::Server),
                Err(SetupError::WrongOptionRole(0x01, _))
            ),
            "a SETUP from a server carrying PATH must be refused",
        );
        assert!(
            validate_setup(&setup, Role::Client).is_ok(),
            "the same option from a client is what PATH is for",
        );
    }

    /// The transport half of the same sentence.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let options = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&options, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&options, false).is_ok(),
            "PATH over native QUIC is what the option is for",
        );
    }
}

#[cfg(feature = "draft20")]
mod draft20 {
    use moqtap_client::draft20::session::request_id::Role;
    use moqtap_client::draft20::session::setup::{
        validate_client_path_transport, validate_setup, SetupError,
    };
    use moqtap_codec::draft20::message::Setup;

    use super::path;

    /// Draft-20 Section 10.3.1.2 is draft-19's sentence unchanged, and so is
    /// the one message both directions use: nothing in a SETUP says which end
    /// sent it, so the sender is an argument. A server may not send PATH, a
    /// client may.
    #[test]
    fn a_setup_from_a_server_may_not_carry_path() {
        let setup = Setup { options: vec![path()] };
        assert!(
            matches!(
                validate_setup(&setup, Role::Server),
                Err(SetupError::WrongOptionRole(0x01, _))
            ),
            "a SETUP from a server carrying PATH must be refused",
        );
        assert!(
            validate_setup(&setup, Role::Client).is_ok(),
            "the same option from a client is what PATH is for",
        );
    }

    /// The transport half of the same sentence.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let options = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&options, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&options, false).is_ok(),
            "PATH over native QUIC is what the option is for",
        );
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use moqtap_client::draft19::session::request_id::Role;
    use moqtap_client::draft19::session::setup::{
        validate_client_path_transport, validate_setup, SetupError,
    };
    use moqtap_codec::draft19::message::Setup;

    use super::path;

    /// This draft merges the two setup messages into one, so nothing in the
    /// message says which end sent it and the sender is an argument. The rule
    /// is unchanged: a server may not send PATH, a client may.
    ///
    /// Dropping the role check from `validate_setup` fails with:
    ///
    /// ```text
    /// a SETUP from a server carrying PATH must be refused
    /// ```
    #[test]
    fn a_setup_from_a_server_may_not_carry_path() {
        let setup = Setup { options: vec![path()] };
        assert!(
            matches!(
                validate_setup(&setup, Role::Server),
                Err(SetupError::WrongOptionRole(0x01, _))
            ),
            "a SETUP from a server carrying PATH must be refused",
        );
        assert!(
            validate_setup(&setup, Role::Client).is_ok(),
            "the same option from a client is what PATH is for",
        );
    }

    /// The transport half of the same sentence.
    #[test]
    fn path_is_refused_over_webtransport_and_allowed_over_quic() {
        let options = vec![path()];
        assert!(
            matches!(
                validate_client_path_transport(&options, true),
                Err(SetupError::PathOverWebTransport),
            ),
            "PATH over WebTransport must be refused",
        );
        assert!(
            validate_client_path_transport(&options, false).is_ok(),
            "PATH over native QUIC is what the option is for",
        );
    }
}

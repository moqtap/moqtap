//! A setup parameter's value has to be read in the shape the wire gives it.
//!
//! Drafts 07 through 10 frame every setup parameter as {Type, Length, Value},
//! and the codec has no per-key table telling it which values are numbers, so
//! every parameter it decodes carries bytes. The client matched on a varint
//! value instead, and that arm never once matched something a peer had sent -
//! only something the process had built itself. The ceiling stayed 0, and a
//! ceiling of 0 means "the peer MUST NOT create subscriptions", so every
//! subscribe and every fetch answered Blocked against a server that had done
//! exactly what the draft asks.
//!
//! The fixture that hid it built its SERVER_SETUP by hand with a varint value -
//! a shape the draft-07-to-10 decoder cannot produce - so the assertion that
//! the endpoint was unblocked was reading back a value the test itself wrote.
//! These gates decode the corpus instead. There is nothing to get wrong about
//! the shape of a byte string.

use moqtap_codec::varint::VarInt;

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::varint;
    use moqtap_client::draft07::endpoint::{Endpoint, Role};
    use moqtap_codec::draft07::message::{ControlMessage, ServerSetup};
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    /// The ROLE parameter draft-07 requires of both endpoints, in the shape
    /// this era's wire format produces: a length-prefixed byte string holding
    /// one varint. Section 6.2.2.1 assigns three values and closes the session
    /// on anything else, or on its absence.
    fn role() -> KeyValuePair {
        KeyValuePair { key: varint(0x00), value: KvpValue::Bytes(vec![0x03]) }
    }

    /// server-setup.json / with-max-subscribe-id, decoded rather than built.
    fn server_setup_from_corpus() -> ServerSetup {
        const VECTOR: &[u8] = &[
            0x40, 0x41, 0x10, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x07, 0x02, 0x00, 0x01,
            0x01, 0x02, 0x02, 0x40, 0xc8,
        ];
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ServerSetup(setup) => setup,
            other => panic!("the vector is a SERVER_SETUP, got {other:?}"),
        }
    }

    /// The parameter grants a budget, and the endpoint has to be able to spend
    /// it. `is_blocked` is a consequence rather than a stored value: it is what
    /// the next `subscribe` will do.
    ///
    /// Reading only a varint-shaped value fails with:
    ///
    /// ```text
    /// called `Result::unwrap()` on an `Err` value: MalformedSetupParameter(2)
    /// ```
    ///
    /// which is the refusal added beside this fix rather than the assertion
    /// below. That ordering is the point: the original code skipped the
    /// parameter in silence, so the only symptom was a ceiling that never
    /// rose. Now an unreadable value has a name.
    #[test]
    fn a_max_subscribe_id_parameter_off_the_wire_grants_a_budget() {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000007)], vec![role()]).unwrap();
        assert!(endpoint.is_blocked(), "nothing has been granted yet");

        endpoint.receive_server_setup(&server_setup_from_corpus()).unwrap();

        assert!(
            !endpoint.is_blocked(),
            "the peer granted a budget in its SERVER_SETUP and it must be spendable",
        );
    }

    /// A value the key's type cannot read is a malformed parameter, not a
    /// parameter to skip. A skipped parameter leaves the ceiling at its default
    /// and says nothing about why, which is how an unreadable value goes
    /// unnoticed for a whole session.
    #[test]
    fn a_max_subscribe_id_parameter_with_an_unreadable_value_is_refused() {
        let mut setup = server_setup_from_corpus();
        // Two bytes that are not one varint: 0x40 opens a two-byte varint and
        // 0x00 closes it, leaving a third byte over. The ROLE beside it stays,
        // so the refusal under test is the malformed value and not a setup
        // this draft would have closed for another reason.
        setup.parameters = vec![
            role(),
            KeyValuePair { key: varint(0x02), value: KvpValue::Bytes(vec![0x40, 0x00, 0x00]) },
        ];

        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000007)], vec![role()]).unwrap();
        assert!(
            endpoint.receive_server_setup(&setup).is_err(),
            "a parameter value that is not the type its key implies must be refused",
        );
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::varint;
    use moqtap_client::draft08::endpoint::{Endpoint, Role};
    use moqtap_codec::draft08::message::{ControlMessage, ServerSetup};

    /// server-setup.json / with-max-subscribe-id, decoded rather than built.
    fn server_setup_from_corpus() -> ServerSetup {
        const VECTOR: &[u8] = &[
            0x40, 0x41, 0x0d, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x08, 0x01, 0x02, 0x02,
            0x40, 0xc8,
        ];
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ServerSetup(setup) => setup,
            other => panic!("the vector is a SERVER_SETUP, got {other:?}"),
        }
    }

    /// The parameter grants a budget, and the endpoint has to be able to spend
    /// it. `is_blocked` is a consequence rather than a stored value: it is what
    /// the next `subscribe` will do.
    ///
    /// Reading only a varint-shaped value fails with:
    ///
    /// ```text
    /// called `Result::unwrap()` on an `Err` value: MalformedSetupParameter(2)
    /// ```
    ///
    /// which is the refusal added beside this fix rather than the assertion
    /// below. That ordering is the point: the original code skipped the
    /// parameter in silence, so the only symptom was a ceiling that never
    /// rose. Now an unreadable value has a name.
    #[test]
    fn a_max_subscribe_id_parameter_off_the_wire_grants_a_budget() {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000008)], vec![]).unwrap();
        assert!(endpoint.is_blocked(), "nothing has been granted yet");

        endpoint.receive_server_setup(&server_setup_from_corpus()).unwrap();

        assert!(
            !endpoint.is_blocked(),
            "the peer granted a budget in its SERVER_SETUP and it must be spendable",
        );
    }

    /// A value the key's type cannot read is a malformed parameter, not a
    /// parameter to skip. A skipped parameter leaves the ceiling at its default
    /// and says nothing about why, which is how an unreadable value goes
    /// unnoticed for a whole session.
    #[test]
    fn a_max_subscribe_id_parameter_with_an_unreadable_value_is_refused() {
        use moqtap_codec::kvp::{KeyValuePair, KvpValue};

        let mut setup = server_setup_from_corpus();
        // Two bytes that are not one varint: 0x40 opens a two-byte varint and
        // 0x00 closes it, leaving a third byte over.
        setup.parameters = vec![KeyValuePair {
            key: varint(0x02),
            value: KvpValue::Bytes(vec![0x40, 0x00, 0x00]),
        }];

        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000008)], vec![]).unwrap();
        assert!(
            endpoint.receive_server_setup(&setup).is_err(),
            "a parameter value that is not the type its key implies must be refused",
        );
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::varint;
    use moqtap_client::draft09::endpoint::{Endpoint, Role};
    use moqtap_codec::draft09::message::{ControlMessage, ServerSetup};

    /// server-setup.json / with-max-subscribe-id, decoded rather than built.
    fn server_setup_from_corpus() -> ServerSetup {
        const VECTOR: &[u8] = &[
            0x40, 0x41, 0x0d, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x09, 0x01, 0x02, 0x02,
            0x40, 0xc8,
        ];
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ServerSetup(setup) => setup,
            other => panic!("the vector is a SERVER_SETUP, got {other:?}"),
        }
    }

    /// The parameter grants a budget, and the endpoint has to be able to spend
    /// it. `is_blocked` is a consequence rather than a stored value: it is what
    /// the next `subscribe` will do.
    ///
    /// Reading only a varint-shaped value fails with:
    ///
    /// ```text
    /// called `Result::unwrap()` on an `Err` value: MalformedSetupParameter(2)
    /// ```
    ///
    /// which is the refusal added beside this fix rather than the assertion
    /// below. That ordering is the point: the original code skipped the
    /// parameter in silence, so the only symptom was a ceiling that never
    /// rose. Now an unreadable value has a name.
    #[test]
    fn a_max_subscribe_id_parameter_off_the_wire_grants_a_budget() {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000009)], vec![]).unwrap();
        assert!(endpoint.is_blocked(), "nothing has been granted yet");

        endpoint.receive_server_setup(&server_setup_from_corpus()).unwrap();

        assert!(
            !endpoint.is_blocked(),
            "the peer granted a budget in its SERVER_SETUP and it must be spendable",
        );
    }

    /// A value the key's type cannot read is a malformed parameter, not a
    /// parameter to skip. A skipped parameter leaves the ceiling at its default
    /// and says nothing about why, which is how an unreadable value goes
    /// unnoticed for a whole session.
    #[test]
    fn a_max_subscribe_id_parameter_with_an_unreadable_value_is_refused() {
        use moqtap_codec::kvp::{KeyValuePair, KvpValue};

        let mut setup = server_setup_from_corpus();
        // Two bytes that are not one varint: 0x40 opens a two-byte varint and
        // 0x00 closes it, leaving a third byte over.
        setup.parameters = vec![KeyValuePair {
            key: varint(0x02),
            value: KvpValue::Bytes(vec![0x40, 0x00, 0x00]),
        }];

        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000009)], vec![]).unwrap();
        assert!(
            endpoint.receive_server_setup(&setup).is_err(),
            "a parameter value that is not the type its key implies must be refused",
        );
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::varint;
    use moqtap_client::draft10::endpoint::{Endpoint, Role};
    use moqtap_codec::draft10::message::{ControlMessage, ServerSetup};

    /// server-setup.json / with-max-subscribe-id, decoded rather than built.
    fn server_setup_from_corpus() -> ServerSetup {
        const VECTOR: &[u8] = &[
            0x40, 0x41, 0x0d, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x02,
            0x40, 0xc8,
        ];
        let msg = ControlMessage::decode(&mut &VECTOR[..]).expect("the corpus vector must decode");
        match msg {
            ControlMessage::ServerSetup(setup) => setup,
            other => panic!("the vector is a SERVER_SETUP, got {other:?}"),
        }
    }

    /// The parameter grants a budget, and the endpoint has to be able to spend
    /// it. `is_blocked` is a consequence rather than a stored value: it is what
    /// the next `subscribe` will do.
    ///
    /// Reading only a varint-shaped value fails with:
    ///
    /// ```text
    /// called `Result::unwrap()` on an `Err` value: MalformedSetupParameter(2)
    /// ```
    ///
    /// which is the refusal added beside this fix rather than the assertion
    /// below. That ordering is the point: the original code skipped the
    /// parameter in silence, so the only symptom was a ceiling that never
    /// rose. Now an unreadable value has a name.
    #[test]
    fn a_max_subscribe_id_parameter_off_the_wire_grants_a_budget() {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000a)], vec![]).unwrap();
        assert!(endpoint.is_blocked(), "nothing has been granted yet");

        endpoint.receive_server_setup(&server_setup_from_corpus()).unwrap();

        assert!(
            !endpoint.is_blocked(),
            "the peer granted a budget in its SERVER_SETUP and it must be spendable",
        );
    }

    /// A value the key's type cannot read is a malformed parameter, not a
    /// parameter to skip. A skipped parameter leaves the ceiling at its default
    /// and says nothing about why, which is how an unreadable value goes
    /// unnoticed for a whole session.
    #[test]
    fn a_max_subscribe_id_parameter_with_an_unreadable_value_is_refused() {
        use moqtap_codec::kvp::{KeyValuePair, KvpValue};

        let mut setup = server_setup_from_corpus();
        // Two bytes that are not one varint: 0x40 opens a two-byte varint and
        // 0x00 closes it, leaving a third byte over.
        setup.parameters = vec![KeyValuePair {
            key: varint(0x02),
            value: KvpValue::Bytes(vec![0x40, 0x00, 0x00]),
        }];

        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000a)], vec![]).unwrap();
        assert!(
            endpoint.receive_server_setup(&setup).is_err(),
            "a parameter value that is not the type its key implies must be refused",
        );
    }
}

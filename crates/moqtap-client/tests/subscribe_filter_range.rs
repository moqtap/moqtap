//! A SUBSCRIBE the client sends must carry the fields its Filter Type names.
//!
//! Two of the filters - AbsoluteStart and AbsoluteRange - put a Start Location
//! on the wire. A `subscribe` that takes the Filter Type beside the other
//! arguments has no start location to give, so asking for either of those
//! produced a frame whose declared length was short by the missing fields, and
//! a publisher reading it ran off the end of the payload. Nothing local
//! complained, because the codec agreed with the client about what it had
//! written.
//!
//! So `subscribe` refuses the two filters it cannot serve, and `subscribe_range`
//! derives the Filter Type from a start location it is actually given. Both
//! halves are gated on every draft that carries a Filter Type argument, because
//! the rule is the same on all of them and it was implemented on two.
//!
//! That is drafts 07 through 14, and the gates stop there for a reason rather
//! than by oversight. Draft-15 moved the whole filter into a parameter, so
//! `subscribe` on drafts 15 and later takes a parameter list and no Filter Type
//! at all — there is no argument to disagree with the fields beside it. The same
//! mistake is still available there, one layer down, to a caller assembling the
//! parameter value by hand; `SubscriptionFilter::parameter` in the codec is what
//! assembles it instead, and it refuses a filter whose fields disagree with its
//! own type for exactly the reason this file exists.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{ns, varint};
    use moqtap_client::draft07::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_codec::draft07::message::{ControlMessage, MaxSubscribeId, ServerSetup};
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    /// The ROLE parameter draft-07 requires of both endpoints, in the shape
    /// this era gives a setup parameter value: a length-prefixed byte string
    /// holding one varint. Section 6.2.2.1 assigns three values and closes the
    /// session on anything else, or on its absence.
    fn role() -> KeyValuePair {
        KeyValuePair { key: varint(0x00), value: KvpValue::Bytes(vec![0x03]) }
    }

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000007)], vec![role()]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff000007),
                parameters: vec![role()],
            })
            .unwrap();
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                varint(1),
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(Location { group: varint(9), object: varint(0) })] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    varint(1),
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{ns, varint};
    use moqtap_client::draft08::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_codec::draft08::message::{ControlMessage, MaxSubscribeId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000008)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff000008),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                varint(1),
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    varint(1),
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{ns, varint};
    use moqtap_client::draft09::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_codec::draft09::message::{ControlMessage, MaxSubscribeId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff000009)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff000009),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                varint(1),
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    varint(1),
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{ns, varint};
    use moqtap_client::draft10::endpoint::{Endpoint, EndpointError, Role};
    use moqtap_codec::draft10::message::{ControlMessage, MaxSubscribeId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000a)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000a),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_subscribe_id(&MaxSubscribeId { subscribe_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                varint(1),
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    varint(1),
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{ns, varint};
    use moqtap_client::draft11::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft11::session::request_id::Role;
    use moqtap_codec::draft11::message::{ControlMessage, MaxRequestId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000b)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000b),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [varint(3), varint(4)] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                varint(1),
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    varint(1),
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{ns, varint};
    use moqtap_client::draft12::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft12::session::request_id::Role;
    use moqtap_codec::draft12::message::{ControlMessage, MaxRequestId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000c)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000c),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [varint(3), varint(4)] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
                Vec::new(),
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                    Vec::new(),
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{ns, varint};
    use moqtap_client::draft13::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft13::session::request_id::Role;
    use moqtap_codec::draft13::message::{ControlMessage, MaxRequestId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000d)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000d),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
                Vec::new(),
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                    Vec::new(),
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::{ns, varint};
    use moqtap_client::draft14::endpoint::{Endpoint, EndpointError};
    use moqtap_client::draft14::session::request_id::Role;
    use moqtap_codec::draft14::message::{ControlMessage, MaxRequestId, ServerSetup};
    use moqtap_codec::types::*;
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn active() -> Endpoint {
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect().unwrap();
        endpoint.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
        // No MAX_SUBSCRIBE_ID among the setup parameters: the budget arrives as
        // a message, so the fixture makes no assumption about how a parameter
        // value is shaped on the wire.
        endpoint
            .receive_server_setup(&ServerSetup {
                selected_version: varint(0xff00000e),
                parameters: vec![],
            })
            .unwrap();
        endpoint.receive_max_request_id(&MaxRequestId { request_id: varint(100) }).unwrap();
        endpoint
    }

    /// A filter that names a Start Location is refused by the call that has
    /// none to give.
    ///
    /// Dropping the refusal fails with:
    ///
    /// ```text
    /// a filter that names a Start Location must be refused here, got Ok((VarInt(0), Subscribe(Subscribe { .. })))
    /// ```
    #[test]
    fn subscribe_refuses_the_filters_it_cannot_carry() {
        for filter in [FilterType::AbsoluteStart, FilterType::AbsoluteRange] {
            let mut endpoint = active();
            let result = endpoint.subscribe(
                ns(),
                b"video".to_vec(),
                128,
                GroupOrder::Ascending,
                filter,
                Vec::new(),
            );
            assert!(
                matches!(result, Err(EndpointError::FilterNeedsRange)),
                "a filter that names a Start Location must be refused here, got {result:?}",
            );
        }
    }

    /// The range form carries the location, so what it builds encodes. This
    /// is the half that shows the refusal above is a redirection rather than a
    /// removal: the request is still expressible.
    #[test]
    fn subscribe_range_builds_a_message_that_encodes() {
        for end in [None, Some(varint(9))] {
            let mut endpoint = active();
            let (_, msg) = endpoint
                .subscribe_range(
                    ns(),
                    b"video".to_vec(),
                    128,
                    GroupOrder::Ascending,
                    Location { group: varint(7), object: varint(3) },
                    end,
                    Vec::new(),
                )
                .expect("a range subscribe is expressible");
            assert!(matches!(msg, ControlMessage::Subscribe(_)));
            let mut buf = Vec::new();
            msg.encode(&mut buf).expect("the message must agree with its own Filter Type");
        }
    }
}

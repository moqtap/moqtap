//! A fetch response's Group Order comes off the FETCH that asked for it.
//!
//! Drafts 18 and 19 write a fetch Object's Group ID as a difference from the
//! Object before it, and the Group Order decides whether the difference is
//! added or subtracted — draft-19 Section 11.4.4.1. Nothing on the data stream
//! says which, so a reader has to be told, and until now nothing in this
//! workspace could work out what to tell it from the traffic it had already
//! decoded.
//!
//! One message settles it. Draft-19 Section 10.12.3: "The publisher responding
//! to a FETCH is responsible for delivering all available Objects in the
//! requested range in the requested order (see Section 10.2.8)." And draft-19
//! Section 10.2.8 states both halves of what the request says: the GROUP_ORDER
//! parameter carries the order, and "If omitted from FETCH, the receiver uses
//! Ascending (0x1)". So a FETCH answers the question whether or not it carries
//! the parameter, and `AnyControlMessage::fetch_group_order` is that answer.
//!
//! Drafts 15, 16 and 17 state the same rule about the same parameter — draft-15
//! words its default sentence differently, "If omitted from SUBSCRIBE_OK,
//! REQUEST_OK, PUBLISH or FETCH, the receiver uses Ascending (0x1)", and means
//! the same thing — so all five are gated here rather than only the two whose
//! data streams need the answer.
//!
//! Drafts 07 to 14 are excluded, and the exclusion is gated too. There the
//! order is a field of the FETCH rather than a parameter, and the value 0x0
//! means the subscriber expressed no preference, which leaves the answer to the
//! publisher's FETCH_OK. That is two messages, and this accessor is handed one.
//! Draft-14 stands for the cohort because it is the boundary: its FETCH is the
//! last to carry the field and the first whose successor carries the parameter,
//! so an arm added by someone reading only the later drafts would land there.
//!
//! Every message below is encoded and read back before it is asked, so what the
//! accessor answers for is a message that came off a wire rather than one built
//! in memory beside it.

#![allow(clippy::items_after_test_module)]
// Gated on the drafts it drives rather than on `test` alone: a build
// compiling none of them has nothing here to compile, and an unused import
// or macro is a `-D warnings` failure rather than a quiet no-op.
#![cfg(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

/// The four gates each of drafts 15 to 20 gets, and the one thing that differs
/// between them: draft-17 puts a Required Request ID Delta on every request.
///
/// Gated on the same five, because a build with draft-14 alone reaches the
/// module below and none of these — and a `macro_rules!` nothing expands is a
/// `-D warnings` failure.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
macro_rules! fetch_group_order_gates {
    (
        $draft:ident, $variant:ident, $version:expr,
        // The fields that locate the track in this draft's FETCH, spelled by
        // the caller. Drafts 15-19 put them inside a Standalone Fetch behind a
        // Fetch Type; draft-20 deleted both and made them inline fields of the
        // message (Section 10.13). The rule under test is the same either way
        // — a FETCH's GROUP_ORDER parameter settles its Group Order — so the
        // shape is a parameter rather than a reason for a second macro.
        fetch { $($fetch_field:ident : $fetch_value:expr),* $(,)? }
        $(, $extra:ident : $extra_value:expr)?
    ) => {
        use moqtap_codec::dispatch::{AnyControlMessage, AnyFetchGroupOrder};
        use moqtap_codec::$draft::message::*;
        use moqtap_codec::kvp::{KeyValuePair, KvpValue};
        use moqtap_codec::types::TrackNamespace;
        use moqtap_codec::varint::VarInt;

        /// GROUP_ORDER, Parameter Type 0x22.
        const GROUP_ORDER: u64 = 0x22;
        /// SUBSCRIBER_PRIORITY, a parameter the same messages may carry and
        /// this accessor must not read.
        const SUBSCRIBER_PRIORITY: u64 = 0x20;
        /// The Request ID every message here is sent under, chosen so that a
        /// wrong one is visible rather than a coincidence of zero.
        const REQUEST: u64 = 7;

        fn varint(v: u64) -> VarInt {
            VarInt::from_u64(v).expect("in range")
        }

        fn param(key: u64, value: u64) -> KeyValuePair {
            KeyValuePair { key: varint(key), value: KvpValue::Varint(varint(value)) }
        }

        /// A FETCH for one group of one track, carrying `parameters`.
        fn fetch(parameters: Vec<KeyValuePair>) -> ControlMessage {
            ControlMessage::Fetch(Fetch {
                request_id: varint(REQUEST),
                $($extra: $extra_value,)?
                $($fetch_field: $fetch_value,)*
                parameters,
            })
        }

        /// A SUBSCRIBE for the same track, carrying `parameters`.
        ///
        /// The other message the draft lets GROUP_ORDER appear on, so a
        /// parameter list identical to a FETCH's is legal here.
        fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
            ControlMessage::Subscribe(Subscribe {
                request_id: varint(REQUEST),
                $($extra: $extra_value,)?
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                parameters,
            })
        }

        /// Encode `message`, read it back through the draft-neutral decoder,
        /// and answer what it says about a fetch's Group Order.
        fn round_trip(message: ControlMessage) -> Option<(u64, AnyFetchGroupOrder)> {
            let any = AnyControlMessage::$variant(message);
            let mut buf = Vec::new();
            any.encode(&mut buf).expect("the codec writes what it built");
            let back = AnyControlMessage::decode($version, &mut &buf[..])
                .expect("the codec reads back what it wrote");
            back.fetch_group_order()
        }

        /// The parameter is read, not assumed.
        ///
        /// This is the gate the whole accessor exists for: a descending fetch
        /// response read as ascending decodes every Object and every field of
        /// it, under Group IDs walking the wrong way, so an accessor that
        /// answered the default whatever the request said would be wrong
        /// exactly where being wrong costs the most and says nothing.
        ///
        /// *Ablation:* answering `AnyFetchGroupOrder::Ascending` for a present
        /// parameter instead of reading its value:
        ///
        /// ```text
        /// assertion `left == right` failed: a FETCH asking for Descending
        /// must answer Descending
        ///   left: Some((7, Ascending))
        ///  right: Some((7, Descending))
        /// ```
        #[test]
        fn a_fetch_asking_for_descending_answers_descending() {
            assert_eq!(
                round_trip(fetch(vec![param(GROUP_ORDER, 0x2)])),
                Some((REQUEST, AnyFetchGroupOrder::Descending)),
                "a FETCH asking for Descending must answer Descending"
            );
        }

        /// An absent parameter is an answer, not a silence.
        ///
        /// Draft-19 Section 10.2.8 states the default of the message rather than
        /// of the reader, so a FETCH that omits GROUP_ORDER has asked for
        /// Ascending as
        /// surely as one that names it. A `None` here would be read one layer
        /// up as "the order is unknown", which would leave every conforming
        /// fetch that did not bother to write the parameter unaddressed.
        ///
        /// *Ablation:* answering `None` when no GROUP_ORDER parameter is
        /// present:
        ///
        /// ```text
        /// assertion `left == right` failed: a FETCH that omits GROUP_ORDER
        /// has asked for Ascending
        ///   left: None
        ///  right: Some((7, Ascending))
        /// ```
        #[test]
        fn a_fetch_that_omits_the_parameter_answers_the_stated_default() {
            assert_eq!(
                round_trip(fetch(vec![])),
                Some((REQUEST, AnyFetchGroupOrder::Ascending)),
                "a FETCH that omits GROUP_ORDER has asked for Ascending"
            );
            assert_eq!(
                round_trip(fetch(vec![param(SUBSCRIBER_PRIORITY, 128)])),
                Some((REQUEST, AnyFetchGroupOrder::Ascending)),
                "another parameter beside it changes nothing"
            );
        }

        /// The message type decides, not the parameter.
        ///
        /// GROUP_ORDER means something on a SUBSCRIBE too — how to prioritise
        /// Objects from different groups within one subscription — and a
        /// subscription's Objects are never on a fetch stream. An accessor that
        /// keyed on the parameter would hand a subscription's preference to a
        /// fetch reader under whatever Request ID happened to match.
        ///
        /// *Ablation:* answering from a SUBSCRIBE's parameters as well:
        ///
        /// ```text
        /// assertion `left == right` failed: a SUBSCRIBE settles no fetch's
        /// Group Order
        ///   left: Some((7, Descending))
        ///  right: None
        /// ```
        #[test]
        fn a_subscribe_carrying_the_same_parameter_answers_nothing() {
            assert_eq!(
                round_trip(subscribe(vec![param(GROUP_ORDER, 0x2)])),
                None,
                "a SUBSCRIBE settles no fetch's Group Order"
            );
        }

        /// The Request ID answered is the one the FETCH was sent under.
        ///
        /// It is what the answer is filed against, and a fetch data stream
        /// names its request in the header. An answer under the wrong id is
        /// worse than no answer: it addresses some other fetch's stream with
        /// this one's order.
        ///
        /// *Ablation:* answering a constant `0` for the Request ID:
        ///
        /// ```text
        /// assertion `left == right` failed: the answer is filed under the
        /// FETCH's own Request ID
        ///   left: 0
        ///  right: 7
        /// ```
        ///
        /// The same cut also fails the two gates above, which compare the whole
        /// pair. It is kept as a gate of its own because those two would still
        /// pass an answer that carried the order and lost the id, if either had
        /// been written to assert only what it was named for.
        #[test]
        fn the_answer_carries_the_requests_own_id() {
            let (id, _) = round_trip(fetch(vec![param(GROUP_ORDER, 0x2)])).expect("a FETCH answers");
            assert_eq!(id, REQUEST, "the answer is filed under the FETCH's own Request ID");
        }
    };
}

#[cfg(feature = "draft15")]
mod draft15 {
    fetch_group_order_gates!(
        draft15,
        Draft15,
        moqtap_codec::version::DraftVersion::Draft15,
        fetch {
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(0),
                start_object: varint(0),
                end_group: varint(1),
                end_object: varint(0),
            },
        }
    );
}

#[cfg(feature = "draft16")]
mod draft16 {
    fetch_group_order_gates!(
        draft16,
        Draft16,
        moqtap_codec::version::DraftVersion::Draft16,
        fetch {
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(0),
                start_object: varint(0),
                end_group: varint(1),
                end_object: varint(0),
            },
        }
    );
}

#[cfg(feature = "draft17")]
mod draft17 {
    fetch_group_order_gates!(
        draft17,
        Draft17,
        moqtap_codec::version::DraftVersion::Draft17,
    fetch {
        fetch_type: FetchType::Standalone,
        fetch_payload: FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(1),
            end_object: varint(0),
        },
    },
        required_request_id_delta: varint(0)
    );
}

#[cfg(feature = "draft18")]
mod draft18 {
    fetch_group_order_gates!(
        draft18,
        Draft18,
        moqtap_codec::version::DraftVersion::Draft18,
        fetch {
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(0),
                start_object: varint(0),
                end_group: varint(1),
                end_object: varint(0),
            },
        }
    );
}

#[cfg(feature = "draft19")]
mod draft19 {
    fetch_group_order_gates!(
        draft19,
        Draft19,
        moqtap_codec::version::DraftVersion::Draft19,
        fetch {
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(0),
                start_object: varint(0),
                end_group: varint(1),
                end_object: varint(0),
            },
        }
    );
}

#[cfg(feature = "draft20")]
mod draft20 {
    // Draft-20's FETCH names the track inline: no Fetch Type, no Standalone
    // Fetch, and no inline range — that travels in LOCATION_FILTER now
    // (Section 10.13). GROUP_ORDER still settles the fetch's Group Order, so
    // every assertion the macro makes carries over unchanged.
    fetch_group_order_gates!(
        draft20,
        Draft20,
        moqtap_codec::version::DraftVersion::Draft20,
        fetch { track_namespace: TrackNamespace(vec![b"ns".to_vec()]), track_name: b"t".to_vec() }
    );
}

/// The cohort whose FETCH does not settle the order on its own.
#[cfg(feature = "draft14")]
mod draft14 {
    use moqtap_codec::dispatch::AnyControlMessage;
    use moqtap_codec::draft14::message::*;
    use moqtap_codec::types::{GroupOrder, TrackNamespace};
    use moqtap_codec::varint::VarInt;
    use moqtap_codec::version::DraftVersion;

    fn varint(v: u64) -> VarInt {
        VarInt::from_u64(v).expect("in range")
    }

    /// A draft-14 FETCH asking for Descending still answers nothing.
    ///
    /// The field is on the message and its value is unambiguous, which is
    /// exactly why this has to be a gate rather than a comment: reading it
    /// would look correct and would be, for this one frame. It is the *other*
    /// value that makes the cohort a different rule — Group Order 0x0 on drafts
    /// 07 to 14 means the subscriber expressed no preference, and the answer
    /// then comes from the publisher's FETCH_OK. An accessor handed one message
    /// cannot tell the two apart afterwards, so it answers for neither.
    ///
    /// *Ablation:* adding a draft-14 arm that reads the field:
    ///
    /// ```text
    /// assertion `left == right` failed: a draft-14 FETCH settles no order by
    /// itself
    ///   left: Some((7, Descending))
    ///  right: None
    /// ```
    #[test]
    fn a_fetch_on_the_negotiating_cohort_answers_nothing() {
        let message = ControlMessage::Fetch(Fetch {
            request_id: varint(7),
            subscriber_priority: 128,
            group_order: GroupOrder::Descending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(0),
                start_object: varint(0),
                end_group: varint(1),
                end_object: varint(0),
            },
            parameters: vec![],
        });
        let any = AnyControlMessage::Draft14(message);
        let mut buf = Vec::new();
        any.encode(&mut buf).expect("the codec writes what it built");
        let back = AnyControlMessage::decode(DraftVersion::Draft14, &mut &buf[..])
            .expect("the codec reads back what it wrote");
        assert_eq!(back.fetch_group_order(), None, "a draft-14 FETCH settles no order by itself");
    }
}

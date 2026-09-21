//! `AnyClientEvent::control_frame` hands a consumer the fields of a control
//! message event without it writing a cascade over every draft.
//!
//! [`AnyClientEvent`] wraps a draft's own `ClientEvent`, and every variant is
//! `#[cfg]`-gated on its draft's feature. So a consumer outside this crate that
//! wants the direction, the message and the framed bytes off one has to match
//! every enabled variant — a per-draft cascade in every consumer, which is the
//! duplication `dispatch.rs` exists to hold in one place. `control_frame`
//! answers with a [`ControlFrame`] instead, and this is what says it answers
//! correctly.
//!
//! # What it catches
//!
//! **The direction, above everything else.** `ControlFrame::outbound` is a
//! `bool`, so a mapping that inverted it — `Direction::Send` to `false` — would
//! compile, would pass every type check, and would relabel every frame a peer
//! sent as one this endpoint sent. A consumer building a record of what a
//! *server* put on the wire would file all of it under itself and have no way to
//! notice. There is no type here to be wrong on its behalf, so the assertion is
//! the only thing standing where a type usually would, and it is made in both
//! directions rather than one: a mapping that answered `true` unconditionally
//! passes a test that only ever sends.
//!
//! **The bytes surviving the lift.** `raw` is the whole reason a consumer reads
//! these events rather than the decoded message it already has — two peers
//! sending the same field can still disagree on how wide a varint they wrote it
//! in, and the decoded form answers the same either way. A lift that dropped
//! them, or handed back a borrow of something else, leaves a consumer with a
//! record it believes is evidence.
//!
//! **A frame that genuinely has no bytes staying distinguishable from one that
//! is not a control message at all.** Both are `None`-shaped at a call site that
//! is not careful, and they mean different things: the first is a message whose
//! encoding was not captured, the second is a stream opening.
//!
//! # Why two drafts, and why these two
//!
//! Drafts 07 through 15 have no `stream_id` on this event — request streams
//! arrive with draft-16 — so the field set differs across the range the one
//! macro arm covers, and `control_frame` reads the fields it shares with `..`.
//! A test on one draft could not tell a body that happened to suit that draft
//! from one that suits the whole range. Draft-14 and draft-20 are one on each
//! side of that split.
//!
//! Neither is asserted to carry a stream id, because [`ControlFrame`]
//! deliberately does not offer one: no arm could read it from every draft, and
//! a second accessor split across two draft lists is a cost to pay when
//! something needs the correlation.

use moqtap_client::dispatch::AnyClientEvent;
// Every use of this type sits under one of the two drafts below.
#[cfg(any(feature = "draft14", feature = "draft20"))]
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::version::DraftVersion;

/// A message's own bytes, which is how two of them are compared here.
///
/// `AnyControlMessage` has no `PartialEq`, and giving it one to make an
/// assertion easier would be a published trait impl bought for a test. Encoding
/// both and comparing is the stronger claim anyway: two messages that encode
/// identically are the same message on the wire, which is the level this
/// accessor is about.
///
/// Gated on the drafts whose tests call it, because a build carrying neither
/// compiles it with no caller and `-D warnings` makes that an error.
#[cfg(any(feature = "draft14", feature = "draft20"))]
fn encoded(message: &AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    message.encode(&mut out).expect("a message this test built encodes");
    out
}

/// A draft-14 SERVER_SETUP and the bytes it frames to.
#[cfg(feature = "draft14")]
fn draft14_setup() -> (AnyControlMessage, Vec<u8>) {
    use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
    use moqtap_codec::varint::VarInt;

    let message = AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
        selected_version: VarInt::from_u64(0xff00_000e).expect("a version is a varint"),
        parameters: Vec::new(),
    }));
    let mut raw = Vec::new();
    message.encode(&mut raw).expect("a setup this test built encodes");
    (message, raw)
}

/// A draft-20 SETUP — unified across both sides from draft-17 — and its bytes.
#[cfg(feature = "draft20")]
fn draft20_setup() -> (AnyControlMessage, Vec<u8>) {
    use moqtap_codec::draft20::message::{ControlMessage, Setup};

    let message = AnyControlMessage::Draft20(ControlMessage::Setup(Setup { options: Vec::new() }));
    let mut raw = Vec::new();
    message.encode(&mut raw).expect("a setup this test built encodes");
    (message, raw)
}

/// Both directions survive the lift, on a draft with no `stream_id` on the
/// event.
#[cfg(feature = "draft14")]
#[test]
fn a_draft14_control_message_keeps_its_direction_and_its_bytes() {
    use moqtap_client::draft14::event::{ClientEvent, Direction};

    let (message, raw) = draft14_setup();

    for (direction, outbound) in [(Direction::Send, true), (Direction::Receive, false)] {
        let event = AnyClientEvent::Draft14(ClientEvent::ControlMessage {
            direction,
            message: message.clone(),
            raw: Some(raw.clone()),
        });

        let frame = event.control_frame().expect("a control message is a control frame");
        assert_eq!(frame.draft, DraftVersion::Draft14);
        assert_eq!(frame.draft, event.draft(), "the two accessors agree on the draft");
        assert_eq!(frame.outbound, outbound, "{direction:?} is outbound={outbound}");
        assert_eq!(frame.raw, Some(raw.as_slice()), "the framed bytes arrived whole");
        assert_eq!(encoded(frame.message), raw, "the same message came through");
        assert_eq!(frame.message.message_type_name(), "server_setup");
    }
}

/// The same, on a draft whose event carries a `stream_id` the lift does not
/// read.
#[cfg(feature = "draft20")]
#[test]
fn a_draft20_control_message_keeps_its_direction_and_its_bytes() {
    use moqtap_client::draft20::event::{ClientEvent, Direction};

    let (message, raw) = draft20_setup();

    for (direction, outbound) in [(Direction::Send, true), (Direction::Receive, false)] {
        for stream_id in [None, Some(4)] {
            let event = AnyClientEvent::Draft20(ClientEvent::ControlMessage {
                direction,
                message: message.clone(),
                stream_id,
                raw: Some(raw.clone()),
            });

            let frame = event.control_frame().expect("a control message is a control frame");
            assert_eq!(frame.draft, DraftVersion::Draft20);
            assert_eq!(frame.outbound, outbound, "{direction:?} is outbound={outbound}");
            assert_eq!(frame.raw, Some(raw.as_slice()));
            assert_eq!(encoded(frame.message), raw, "the same message came through");
            // The stream the message travelled on does not change what the
            // message was, which is the claim that lets one arm ignore the
            // field on the six drafts that have it.
            assert_eq!(frame.message.message_type_name(), "setup");
        }
    }
}

/// A control message whose bytes were not captured says so, and is still a
/// control frame.
///
/// The connection clones them only when an observer is attached, so this is a
/// real state and not a hypothetical one. Folding it into "not a control
/// message" would hand a consumer an absence where there is a message.
#[cfg(feature = "draft20")]
#[test]
fn a_control_message_with_no_captured_bytes_is_still_a_control_frame() {
    use moqtap_client::draft20::event::{ClientEvent, Direction};

    let (message, _) = draft20_setup();
    let event = AnyClientEvent::Draft20(ClientEvent::ControlMessage {
        direction: Direction::Receive,
        message: message.clone(),
        stream_id: None,
        raw: None,
    });

    let frame = event.control_frame().expect("a message with no bytes is still a message");
    assert_eq!(encoded(frame.message), encoded(&message), "the message survived");
    assert!(frame.raw.is_none(), "no bytes were captured, and the frame says so");
    assert!(!frame.outbound);
}

/// An event that is not a control message is not a control frame.
///
/// The wildcard arm is over the other event variants and not over drafts, so it
/// has to stay reachable in every build. A stream opening is the nearest thing
/// to a control message the enum carries — it has a direction too — which makes
/// it the one worth asserting on.
#[cfg(feature = "draft20")]
#[test]
fn an_event_that_is_not_a_control_message_is_not_a_control_frame() {
    use moqtap_client::draft20::event::{ClientEvent, Direction, StreamKind};

    let opened = AnyClientEvent::Draft20(ClientEvent::StreamOpened {
        direction: Direction::Receive,
        stream_kind: StreamKind::Subgroup,
        stream_id: 4,
    });
    assert!(opened.control_frame().is_none(), "a stream opening carries no message");

    let complete = AnyClientEvent::Draft20(ClientEvent::SetupComplete {
        negotiated_version: 0xff00_0000 + 20,
    });
    assert!(complete.control_frame().is_none(), "a handshake milestone carries no message");
}

/// The draft on the frame is the draft of the variant it came out of, on every
/// enabled draft rather than on the two exercised above.
///
/// `control_frame` names the draft in each arm separately from `draft()`, so the
/// two can disagree — an arm copied from its neighbour and not renamed reports a
/// message under a draft whose rules did not decode it. Only a sweep over all of
/// them can see that, and this is cheap because the events are built rather than
/// exchanged.
#[test]
fn every_arm_names_its_own_draft() {
    let mut checked = 0;

    macro_rules! check {
        ($($feat:literal => $variant:ident, $module:ident;)+) => {
            $(
                #[cfg(feature = $feat)]
                {
                    use moqtap_client::$module::event::ClientEvent;
                    let event = AnyClientEvent::$variant(ClientEvent::SetupComplete {
                        negotiated_version: 0,
                    });
                    assert_eq!(event.draft(), DraftVersion::$variant);
                    assert!(event.control_frame().is_none());
                    checked += 1;
                }
            )+
        };
    }

    check! {
        "draft07" => Draft07, draft07;
        "draft08" => Draft08, draft08;
        "draft09" => Draft09, draft09;
        "draft10" => Draft10, draft10;
        "draft11" => Draft11, draft11;
        "draft12" => Draft12, draft12;
        "draft13" => Draft13, draft13;
        "draft14" => Draft14, draft14;
        "draft15" => Draft15, draft15;
        "draft16" => Draft16, draft16;
        "draft17" => Draft17, draft17;
        "draft18" => Draft18, draft18;
        "draft19" => Draft19, draft19;
        "draft20" => Draft20, draft20;
        "draft21" => Draft21, draft21;
    }

    // A build with no draft feature has no arms, so nothing was checked and
    // nothing is claimed — that configuration is real and CI builds it. Under
    // `all-drafts` the count is held against the enum's own length instead of
    // against zero, so a draft added to `DraftVersion::ALL` and not to the list
    // above fails here rather than going quietly unexercised.
    #[cfg(feature = "all-drafts")]
    assert_eq!(
        checked,
        DraftVersion::ALL.len(),
        "every draft in the enum needs a row in the list above"
    );
    let _ = checked;
}

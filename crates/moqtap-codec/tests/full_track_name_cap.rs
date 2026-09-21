//! The Full Track Name cap binds the reader, on every draft that states it.
//!
//! Drafts 11 through 20 all carry the same sentence: the maximum total length
//! of a Full Track Name is 4,096 bytes, computed as the sum of the Track
//! Namespace field lengths and the Track Name length, and an endpoint that
//! receives one longer MUST close the session. Drafts 07 through 10 state no
//! such cap, so they are deliberately absent from this file — adding the check
//! there would refuse names those drafts permit.
//!
//! The gates here read SUBSCRIBE, because all ten open that message with a
//! Request ID, a Track Namespace and a length-prefixed Track Name, in that
//! order, and all ten assign it type 0x03. Drafts 17 through 20 write those
//! fields in the variable-length integer encoding draft-17 introduced, so they
//! get their own payload builder rather than a different test.
//!
//! The payload stops after the name. It does not need to be a complete
//! SUBSCRIBE, because the cap is checked as soon as the name has been read —
//! and a decoder that got as far as complaining about the *rest* of the
//! message is a decoder that let an over-long name through.
//!
//! # What is not covered here
//!
//! The encode side, which `full_track_name_cap_on_encode.rs` takes: it builds
//! each draft's own structs, so it reaches every message that carries a Full
//! Track Name rather than only the one whose payload can be written by hand.
//!
//! And on the decode side, only SUBSCRIBE. The other messages that carry a Full
//! Track Name put different fields in front of it - a fetch type and its branch,
//! a required-delta, a namespace with no request id at all - and three of them
//! read fields *behind* it before the check runs, so each needs its own payload
//! builder. `full_track_name_cap_beyond_subscribe.rs` has those thirty-one, one
//! for every other decode arm on every draft that reads a Full Track Name.

#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
use moqtap_codec::error::CodecError;
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
use moqtap_codec::types::TrackNamespace;
#[cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
use moqtap_codec::varint::MoqtProfile;
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
use moqtap_codec::varint::VarInt;

/// Frame a control message payload the way drafts 11 onward do: type, 16-bit
/// Length, payload.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn framed(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![type_id];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

/// The opening fields of SUBSCRIBE, with a namespace and a name of given sizes.
///
/// The namespace is a single field, so the Full Track Name length the drafts
/// define is exactly `namespace_bytes + name_bytes`.
///
/// `leading_varints` counts the fields before the namespace: a Request ID on
/// its own for most drafts, and a Request ID followed by a Track Alias on
/// draft-11, which is the only one here that puts the alias in SUBSCRIBE.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn subscribe_prefix(leading_varints: usize, namespace_bytes: usize, name_bytes: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..leading_varints {
        VarInt::from_u64(1).expect("leading field fits").encode(&mut payload);
    }
    TrackNamespace(vec![vec![b'n'; namespace_bytes]]).encode(&mut payload);
    VarInt::from_usize(name_bytes).encode(&mut payload);
    payload.extend(std::iter::repeat_n(b't', name_bytes));
    payload
}

/// The same opening fields, in the encoding drafts 17 and later use.
///
/// Draft-17 replaced the RFC 9000 variable-length integer with one whose length
/// comes from the leading 1 bits of the first byte. The values here are all
/// small enough to occupy one byte in either encoding, but the namespace and
/// name lengths are not - 4,000 needs two bytes under one scheme and three
/// under the other - so the payload has to be written with the draft's own
/// profile rather than reused from above.
#[cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn subscribe_prefix_moqt<P: MoqtProfile>(
    leading_varints: usize,
    namespace_bytes: usize,
    name_bytes: usize,
) -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..leading_varints {
        VarInt::from_u64(0).expect("leading field fits").encode_moqt::<P>(&mut payload);
    }
    TrackNamespace(vec![vec![b'n'; namespace_bytes]]).encode_moqt::<P>(&mut payload);
    VarInt::from_usize(name_bytes).encode_moqt::<P>(&mut payload);
    payload.extend(std::iter::repeat_n(b't', name_bytes));
    payload
}

/// Build one gate for a draft that states the 4,096-byte cap.
///
/// # What this catches, observed by removing the check from each draft and running it
///
/// Without it the name is accepted and decoding continues into whatever
/// follows, so the refusal that eventually arrives is about the wrong thing
/// entirely — the missing remainder of the SUBSCRIBE, reported on drafts 11,
/// 12 and 13 as:
///
/// ```text
/// a 4,097-byte Full Track Name must be refused, got Err(UnexpectedEnd)
/// ```
///
/// and on drafts 15 and 16, which reach the parameter list first, as:
///
/// ```text
/// a 4,097-byte Full Track Name must be refused, got Err(Kvp(VarInt(UnexpectedEnd)))
/// ```
///
/// and on drafts 17, 18 and 19, whose framing carries a declared length, as:
///
/// ```text
/// a 4,097-byte Full Track Name must be refused, got
/// Err(ControlMessageLengthMismatch { declared: 4102, detail: "its fields ran past the end" })
/// ```
///
/// Every one of them tells the caller the message was truncated or misframed,
/// which is a claim about the sender rather than about the name, and is wrong.
macro_rules! full_track_name_cap_gate {
    ($fname:ident, $feat:literal, $draft:ident, $leading:expr) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::message::ControlMessage;

            let over = framed(0x03, &subscribe_prefix($leading, 4000, 97));
            let decoded = ControlMessage::decode(&mut &over[..]);
            assert!(
                matches!(decoded, Err(CodecError::TrackNameTooLong)),
                "a 4,097-byte Full Track Name must be refused, got {decoded:?}"
            );

            // One byte under, and the name is no longer what stops the decoder.
            // It still fails — the payload ends where the name ends — but on
            // the remainder of the message, which is what tells us the gate
            // above observed the cap and not the size of the buffer.
            let at_cap = framed(0x03, &subscribe_prefix($leading, 4000, 96));
            let decoded = ControlMessage::decode(&mut &at_cap[..]);
            assert!(
                !matches!(decoded, Err(CodecError::TrackNameTooLong)),
                "a 4,096-byte Full Track Name is within the cap, got {decoded:?}"
            );
        }
    };
}

// Draft-11 carries a Track Alias between the Request ID and the namespace.
full_track_name_cap_gate!(draft11_caps_the_full_track_name, "draft11", draft11, 2);
full_track_name_cap_gate!(draft12_caps_the_full_track_name, "draft12", draft12, 1);
full_track_name_cap_gate!(draft13_caps_the_full_track_name, "draft13", draft13, 1);
full_track_name_cap_gate!(draft14_caps_the_full_track_name, "draft14", draft14, 1);
full_track_name_cap_gate!(draft15_caps_the_full_track_name, "draft15", draft15, 1);
full_track_name_cap_gate!(draft16_caps_the_full_track_name, "draft16", draft16, 1);

/// The same gate for a draft that writes its fields in draft-17's encoding.
///
/// `$profile` is the variable-length integer revision the draft uses, and
/// `$leading` the number of fields before the Track Namespace: draft-17 puts a
/// Required Request ID Delta after the Request ID, and drafts 18 and 19 removed
/// it again.
macro_rules! full_track_name_cap_gate_moqt {
    ($fname:ident, $feat:literal, $draft:ident, $profile:ty, $leading:expr) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::message::ControlMessage;

            let over = framed(0x03, &subscribe_prefix_moqt::<$profile>($leading, 4000, 97));
            let decoded = ControlMessage::decode(&mut &over[..]);
            assert!(
                matches!(decoded, Err(CodecError::TrackNameTooLong)),
                "a 4,097-byte Full Track Name must be refused, got {decoded:?}"
            );

            let at_cap = framed(0x03, &subscribe_prefix_moqt::<$profile>($leading, 4000, 96));
            let decoded = ControlMessage::decode(&mut &at_cap[..]);
            assert!(
                !matches!(decoded, Err(CodecError::TrackNameTooLong)),
                "a 4,096-byte Full Track Name is within the cap, got {decoded:?}"
            );
        }
    };
}

// Draft-17 carries a Required Request ID Delta between the Request ID and the
// namespace; drafts 18 and 19 dropped it.
full_track_name_cap_gate_moqt!(
    draft17_caps_the_full_track_name,
    "draft17",
    draft17,
    moqtap_codec::varint::Moqt17,
    2
);
full_track_name_cap_gate_moqt!(
    draft18_caps_the_full_track_name,
    "draft18",
    draft18,
    moqtap_codec::varint::Moqt18,
    1
);
full_track_name_cap_gate_moqt!(
    draft19_caps_the_full_track_name,
    "draft19",
    draft19,
    moqtap_codec::varint::Moqt18,
    1
);
// Draft-20's SUBSCRIBE is byte-identical to draft-19's, and Section 2.4.1's cap
// is unchanged.
full_track_name_cap_gate_moqt!(
    draft20_caps_the_full_track_name,
    "draft20",
    draft20,
    moqtap_codec::varint::Moqt18,
    1
);
full_track_name_cap_gate_moqt!(
    draft21_caps_the_full_track_name,
    "draft21",
    draft21,
    moqtap_codec::varint::Moqt18,
    1
);

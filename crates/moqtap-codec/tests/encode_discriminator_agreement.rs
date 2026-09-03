#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
//! An encoder must derive a conditional field's presence from the same field
//! the decoder does.
//!
//! SUBSCRIBE's Start Location is on the wire because the Filter Type says so.
//! SUBSCRIBE_OK's Largest Location is there because Content Exists says so.
//! FETCH's range fields are there because the Fetch Type says so. A codec that
//! reads presence from the discriminator but writes it from whether a Rust
//! `Option` happens to be `Some` will emit a frame its own reader refuses -
//! short by the missing fields, so the declared length runs out mid-payload, or
//! long by the surplus ones, so bytes are left over. Both are a session close.
//!
//! Nothing in the corpus can find this. Vectors are generated from the encoder
//! and read back by the decoder, and a message whose discriminator and fields
//! agree exercises neither side of the disagreement. So each gate takes a
//! canonical vector, moves the discriminator alone, and requires the encoder to
//! refuse the result.
//!
//! Every draft that has the rule is driven, not one: this is the same sentence
//! in eight documents and it was enforced in two of them.
//!
//! Those eight are drafts 07 through 14, and they are the drafts the first two
//! gates hold on. Draft-15 removed both of the fields those gates move: its
//! SUBSCRIBE carries no Filter Type, the filter having become the SUBSCRIPTION
//! FILTER parameter of Section 9.2.1.7, and its SUBSCRIBE_OK has no Content
//! Exists. Neither gate has anything left to take hold of.
//!
//! The third field outlived them. A FETCH carries a Fetch Type beside a typed
//! payload on every draft from 08 to 19, so drafts 15 through 19 are driven
//! here too, by a suite whose SUBSCRIBE arms are left out. Those five encoders
//! refuse the disagreement already, which is the answer the gate wants and not
//! a reason to leave it unasked: two of the first eight refused it already too,
//! and that is exactly what made the other six worth looking at.
//!
//! **Draft-20 ends the range, and it is worth saying why rather than leaving a
//! gap in the numbering.** Section 10.13 deleted the Fetch Type field along
//! with the Standalone Fetch and Joining Fetch structures it chose between, so
//! a draft-20 FETCH has one shape and no discriminator at all — there is
//! nothing for a suite here to move. The one discriminator draft-20 still has
//! is REQUEST_ERROR's Error Code, which puts a Redirect body on the wire under
//! code 0x34, and `late_draft_rule_coverage.rs` drives that on draft-20 in
//! both directions. This file's crate gate deliberately stops at draft-19: a
//! build enabling only draft-20 compiles it away entirely rather than leaving
//! an empty suite behind.
//!
//! Draft-07 is the other end of the same asymmetry: it has no FETCH message at
//! all, so it is the one draft here driven by two gates rather than three.

mod test_vectors;

// The discriminator values below are written at the macro call sites, so they
// resolve here rather than inside the generated modules.
#[allow(unused_imports)]
use moqtap_codec::types::FilterType;
#[allow(unused_imports)]
use moqtap_codec::varint::VarInt;
use test_vectors::{load_vectors, vectors_dir, TestVector};

/// The first canonical vector in `file` whose decoded JSON satisfies `pick`.
fn find(relative_path: &str, pick: impl Fn(&serde_json::Value) -> bool) -> TestVector {
    let file = load_vectors(&vectors_dir().join(relative_path));
    file.vectors
        .into_iter()
        .find(|v| v.is_canonical() && v.decoded.as_ref().is_some_and(&pick) && v.error.is_none())
        .unwrap_or_else(|| panic!("{relative_path}: no canonical vector matched"))
}

fn bytes(vector: &TestVector) -> Vec<u8> {
    hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id))
}

macro_rules! discriminator_suite {
    (
        $feature:literal,
        $draft:ident,
        $dir:literal,
        $(absolute_start = $absolute_start:expr,)?
        $(fetch_joining = $fetch_joining:expr,)?
    ) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use super::{bytes, find};
            use moqtap_codec::$draft::message::ControlMessage;
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;

            $(
            /// A SUBSCRIBE whose Filter Type names a Start Location it does not
            /// carry. The vector is a legal one; only the discriminator moves,
            /// so the fields around it are exactly what the corpus says they
            /// should be.
            ///
            /// Writing the optional fields from `Option` instead fails with:
            ///
            /// ```text
            /// a Filter Type that names a Start Location must not encode without one
            /// ```
            #[test]
            fn subscribe_filter_type_must_agree_with_its_start_location() {
                let vector = find(concat!($dir, "subscribe.json"), |d| {
                    d.get("start_location").is_none() && d.get("start_group").is_none()
                });
                let mut msg = ControlMessage::decode(&mut &bytes(&vector)[..])
                    .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));

                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the corpus vector must encode as it stands");

                let ControlMessage::Subscribe(ref mut m) = msg else {
                    panic!("[{}] is not a SUBSCRIBE", vector.id);
                };
                m.filter_type = $absolute_start;

                let mut buf = Vec::new();
                assert!(
                    msg.encode(&mut buf).is_err(),
                    "a Filter Type that names a Start Location must not encode without one",
                );
            }

            /// A SUBSCRIBE_OK whose Content Exists claims a Largest Location it
            /// does not carry.
            ///
            /// Writing the Largest Location from `Option` instead fails with:
            ///
            /// ```text
            /// Content Exists must not encode without the location it promises
            /// ```
            #[test]
            fn subscribe_ok_content_exists_must_agree_with_its_largest_location() {
                let vector = find(concat!($dir, "subscribe-ok.json"), |d| {
                    d.get("content_exists").and_then(|c| c.as_u64()) == Some(0)
                        || d.get("content_exists").and_then(|c| c.as_str()) == Some("0")
                });
                let mut msg = ControlMessage::decode(&mut &bytes(&vector)[..])
                    .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));

                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the corpus vector must encode as it stands");

                let ControlMessage::SubscribeOk(ref mut m) = msg else {
                    panic!("[{}] is not a SUBSCRIBE_OK", vector.id);
                };
                m.content_exists = ContentExists::HasLargestLocation;

                let mut buf = Vec::new();
                assert!(
                    msg.encode(&mut buf).is_err(),
                    "Content Exists must not encode without the location it promises",
                );
            }
            )?

            $(
                /// A FETCH whose Fetch Type names one shape while its fields
                /// are the other shape.
                ///
                /// Writing the fields independently of the type fails with:
                ///
                /// ```text
                /// a Fetch Type must not encode beside the other type's fields
                /// ```
                ///
                /// The check is written out once per draft rather than shared,
                /// so each gate is held by its own and none of them is standing
                /// on a neighbour: removing it from any one of drafts 15
                /// through 19 fails that draft and leaves the other
                /// twenty-seven tests in this file passing.
                #[test]
                fn fetch_type_must_agree_with_the_fields_it_names() {
                    let vector = find(concat!($dir, "fetch.json"), |d| {
                        d.get("fetch_type").and_then(|t| t.as_u64()) == Some(1)
                            || d.get("fetch_type").and_then(|t| t.as_str()) == Some("1")
                    });
                    let mut msg = ControlMessage::decode(&mut &bytes(&vector)[..])
                        .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));

                    let mut buf = Vec::new();
                    msg.encode(&mut buf).expect("the corpus vector must encode as it stands");

                    let ControlMessage::Fetch(ref mut m) = msg else {
                        panic!("[{}] is not a FETCH", vector.id);
                    };
                    m.fetch_type = $fetch_joining;

                    let mut buf = Vec::new();
                    assert!(
                        msg.encode(&mut buf).is_err(),
                        "a Fetch Type must not encode beside the other type's fields",
                    );
                }
            )?
        }
    };
}

discriminator_suite!(
    "draft07",
    draft07,
    "transport/draft07/codec/messages/",
    absolute_start = FilterType::AbsoluteStart,
);
discriminator_suite!(
    "draft08",
    draft08,
    "transport/draft08/codec/messages/",
    absolute_start = FilterType::AbsoluteStart,
    fetch_joining = moqtap_codec::draft08::message::FetchType::Joining,
);
discriminator_suite!(
    "draft09",
    draft09,
    "transport/draft09/codec/messages/",
    absolute_start = FilterType::AbsoluteStart,
    fetch_joining = moqtap_codec::draft09::message::FetchType::Joining,
);
discriminator_suite!(
    "draft10",
    draft10,
    "transport/draft10/codec/messages/",
    absolute_start = FilterType::AbsoluteStart,
    fetch_joining = moqtap_codec::draft10::message::FetchType::Joining,
);
discriminator_suite!(
    "draft11",
    draft11,
    "transport/draft11/codec/messages/",
    absolute_start = VarInt::from_u64(3).unwrap(),
    fetch_joining = moqtap_codec::draft11::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft12",
    draft12,
    "transport/draft12/codec/messages/",
    absolute_start = VarInt::from_u64(3).unwrap(),
    fetch_joining = moqtap_codec::draft12::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft13",
    draft13,
    "transport/draft13/codec/messages/",
    absolute_start = FilterType::AbsoluteStart,
    fetch_joining = moqtap_codec::draft13::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft14",
    draft14,
    "transport/draft14/codec/messages/",
    absolute_start = FilterType::AbsoluteStart,
    fetch_joining = moqtap_codec::draft14::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft15",
    draft15,
    "transport/draft15/codec/messages/",
    fetch_joining = moqtap_codec::draft15::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft16",
    draft16,
    "transport/draft16/codec/messages/",
    fetch_joining = moqtap_codec::draft16::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft17",
    draft17,
    "transport/draft17/codec/messages/",
    fetch_joining = moqtap_codec::draft17::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft18",
    draft18,
    "transport/draft18/codec/messages/",
    fetch_joining = moqtap_codec::draft18::message::FetchType::RelativeJoining,
);
discriminator_suite!(
    "draft19",
    draft19,
    "transport/draft19/codec/messages/",
    fetch_joining = moqtap_codec::draft19::message::FetchType::RelativeJoining,
);

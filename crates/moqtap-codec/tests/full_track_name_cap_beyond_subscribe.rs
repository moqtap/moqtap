//! The Full Track Name cap binds every message that carries one, not only
//! SUBSCRIBE.
//!
//! Drafts 11 through 19 all state it once, of the name rather than of a message:
//! the maximum total length of a Full Track Name is 4,096 bytes, computed as the
//! sum of the Track Namespace field lengths and the Track Name length, and an
//! endpoint that receives one longer MUST close the session. Drafts 07 through
//! 10 state no such cap and are deliberately absent.
//!
//! `full_track_name_cap.rs` drives SUBSCRIBE on all nine, which is one message
//! reachable by one payload builder. This file is the rest of them, and there is
//! no way to share a builder: each message puts different fields in front of the
//! name, and three of them put fields *behind* it that are read before the check
//! runs.
//!
//! # What the field orders turn out to be
//!
//! Reading them out of the decoders rather than assuming, three groups appear
//! that a single test would have got wrong.
//!
//! A **PUBLISH on drafts 17, 18 and 19** reads its Track Alias between the name
//! and the check, so a payload that stops after the name never reaches the cap
//! at all. Drafts 12 through 16 check first and read the alias after.
//!
//! A **FETCH on drafts 17, 18 and 19** reads Start Group, Start Object, End
//! Group and End Object before the check — four varints past the end of the
//! name. Drafts 11 through 16 check as soon as the name is read.
//!
//! **PUBLISH_BLOCKED (0x0F on drafts 17 and 18) and PUBLISH_SKIPPED (the same
//! type on draft-19)** carry no Request ID at all: the namespace suffix is the
//! first field of the message. They also allow an empty namespace, which no
//! other carrier does.
//!
//! And the **Redirect inside a REQUEST_ERROR on drafts 18 and 19** is reached
//! only when the error code is REDIRECT (0x34), behind a retry interval, a
//! reason phrase and a Connect URI. It is the only carrier that is not a message
//! of its own.
//!
//! # Why this is coverage and not a second implementation
//!
//! Every one of these arms reaches the same `check_full_track_name`. Checking
//! that was the first thing done here, by enumerating every decode arm on every
//! draft that reads a namespace field and a track name: forty of them across the
//! nine drafts, and all forty call it. So what these gates hold is the *wiring* —
//! that the check is on the path each message takes, and stays there when a
//! decoder is rearranged.
//!
//! Thirty-one gates here and nine in `full_track_name_cap.rs` is forty, one for
//! each.

#[cfg(any(
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
    feature = "draft19"
))]
use moqtap_codec::types::TrackNamespace;
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
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
    feature = "draft19"
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
    feature = "draft19"
))]
fn framed(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![type_id];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

/// One variable-length integer in the RFC 9000 encoding drafts 11 through 16
/// use.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn vi(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(v).expect("fixture value fits").encode(&mut out);
    out
}

/// One variable-length integer in the encoding draft-17 introduced.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn vi_moqt<P: MoqtProfile>(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(v).expect("fixture value fits").encode_moqt::<P>(&mut out);
    out
}

/// A single-field Track Namespace and a Track Name, in the RFC 9000 encoding.
///
/// One namespace field, so the Full Track Name length the drafts define is
/// exactly `namespace_bytes + name_bytes`.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn ns_name(namespace_bytes: usize, name_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    TrackNamespace(vec![vec![b'n'; namespace_bytes]]).encode(&mut out);
    VarInt::from_usize(name_bytes).encode(&mut out);
    out.extend(std::iter::repeat_n(b't', name_bytes));
    out
}

/// The same pair in the encoding drafts 17 and later use.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn ns_name_moqt<P: MoqtProfile>(namespace_bytes: usize, name_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    TrackNamespace(vec![vec![b'n'; namespace_bytes]]).encode_moqt::<P>(&mut out);
    VarInt::from_usize(name_bytes).encode_moqt::<P>(&mut out);
    out.extend(std::iter::repeat_n(b't', name_bytes));
    out
}

/// Build one gate for one message on one draft.
///
/// `$payload` takes the namespace and name byte counts and returns the whole
/// message payload, so each message's own field order lives beside the message
/// rather than inside a shared builder that would have to know all of them.
///
/// Both halves are asserted. The over-cap frame must be refused *as a name*, and
/// the at-cap frame must not be: a decoder that refused everything, or one whose
/// buffer simply ran out, would pass the first assertion on its own.
///
/// # What it catches
///
/// Ablation: deleting the `check_full_track_name` call from one arm leaves the
/// decoder reading on into whatever follows the name, so what comes back is a
/// complaint about the rest of the message. Measured by removing it from
/// draft-19's TRACK_STATUS arm:
///
/// ```text
/// a 4,097-byte Full Track Name must be refused, got Err(ControlMessageLengthMismatch
/// { declared: 4102, detail: "its fields ran past the end" })
/// ```
///
/// which says the sender misframed the message. The sender framed it exactly as
/// it meant to.
macro_rules! cap_gate {
    ($fname:ident, $feat:literal, $draft:ident, $type_id:expr, $payload:expr) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::message::ControlMessage;

            let build: fn(usize, usize) -> Vec<u8> = $payload;

            let over = framed($type_id, &build(4000, 97));
            let decoded = ControlMessage::decode(&mut &over[..]);
            assert!(
                matches!(decoded, Err(CodecError::TrackNameTooLong)),
                "a 4,097-byte Full Track Name must be refused, got {decoded:?}"
            );

            let at_cap = framed($type_id, &build(4000, 96));
            let decoded = ControlMessage::decode(&mut &at_cap[..]);
            assert!(
                !matches!(decoded, Err(CodecError::TrackNameTooLong)),
                "a 4,096-byte Full Track Name is within the cap, got {decoded:?}"
            );
        }
    };
}

// ── Drafts 11 through 16: the RFC 9000 encoding ──────────────────────────────
//
// TRACK_STATUS_REQUEST on drafts 11 and 12, renamed to TRACK_STATUS at draft-13
// and given type 0x0D, which is the type the old request had. Same two fields in
// front of the name either way.

cap_gate!(draft11_caps_a_track_status_request, "draft11", draft11, 0x0D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft12_caps_a_track_status_request, "draft12", draft12, 0x0D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft13_caps_a_track_status, "draft13", draft13, 0x0D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft14_caps_a_track_status, "draft14", draft14, 0x0D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft15_caps_a_track_status, "draft15", draft15, 0x0D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft16_caps_a_track_status, "draft16", draft16, 0x0D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});

// PUBLISH, type 0x1D, from draft-12 on. Request ID, then the name.
cap_gate!(draft12_caps_a_publish, "draft12", draft12, 0x1D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft13_caps_a_publish, "draft13", draft13, 0x1D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft14_caps_a_publish, "draft14", draft14, 0x1D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft15_caps_a_publish, "draft15", draft15, 0x1D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft16_caps_a_publish, "draft16", draft16, 0x1D, |ns, name| {
    [vi(1), ns_name(ns, name)].concat()
});

// FETCH, type 0x16. Drafts 11 through 14 put a Subscriber Priority byte and a
// Group Order byte between the Request ID and the Fetch Type; draft-15 dropped
// both to parameters. The name is inside the Standalone branch, which is Fetch
// Type 0x1 — the other two branches carry a Request ID to join and no name.
cap_gate!(draft11_caps_a_fetch, "draft11", draft11, 0x16, |ns, name| {
    [vi(1), vec![128, 1], vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft12_caps_a_fetch, "draft12", draft12, 0x16, |ns, name| {
    [vi(1), vec![128, 1], vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft13_caps_a_fetch, "draft13", draft13, 0x16, |ns, name| {
    [vi(1), vec![128, 1], vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft14_caps_a_fetch, "draft14", draft14, 0x16, |ns, name| {
    [vi(1), vec![128, 1], vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft15_caps_a_fetch, "draft15", draft15, 0x16, |ns, name| {
    [vi(1), vi(1), ns_name(ns, name)].concat()
});
cap_gate!(draft16_caps_a_fetch, "draft16", draft16, 0x16, |ns, name| {
    [vi(1), vi(1), ns_name(ns, name)].concat()
});

// ── Drafts 17 through 19: draft-17's encoding ────────────────────────────────
//
// Draft-17 carries a Required Request ID Delta after every Request ID, and
// checks it before the name — so it is 0 against a Request ID of 0 here, which
// is the one pair where twice the delta is no larger than the id. Drafts 18
// and 19 dropped the field.

#[cfg(feature = "draft17")]
type M17 = moqtap_codec::varint::Moqt17;
#[cfg(any(feature = "draft18", feature = "draft19"))]
type M18 = moqtap_codec::varint::Moqt18;

cap_gate!(draft17_caps_a_track_status, "draft17", draft17, 0x0D, |ns, name| {
    [vi_moqt::<M17>(0), vi_moqt::<M17>(0), ns_name_moqt::<M17>(ns, name)].concat()
});
cap_gate!(draft18_caps_a_track_status, "draft18", draft18, 0x0D, |ns, name| {
    [vi_moqt::<M18>(0), ns_name_moqt::<M18>(ns, name)].concat()
});
cap_gate!(draft19_caps_a_track_status, "draft19", draft19, 0x0D, |ns, name| {
    [vi_moqt::<M18>(0), ns_name_moqt::<M18>(ns, name)].concat()
});

// PUBLISH, and the Track Alias that follows the name on these three drafts. A
// payload that stopped after the name would be refused for running out rather
// than for the name, and the at-cap half of the gate would still pass — so the
// alias is what makes this arm reachable at all.
cap_gate!(draft17_caps_a_publish, "draft17", draft17, 0x1D, |ns, name| {
    [vi_moqt::<M17>(0), vi_moqt::<M17>(0), ns_name_moqt::<M17>(ns, name), vi_moqt::<M17>(4)]
        .concat()
});
cap_gate!(draft18_caps_a_publish, "draft18", draft18, 0x1D, |ns, name| {
    [vi_moqt::<M18>(0), ns_name_moqt::<M18>(ns, name), vi_moqt::<M18>(4)].concat()
});
cap_gate!(draft19_caps_a_publish, "draft19", draft19, 0x1D, |ns, name| {
    [vi_moqt::<M18>(0), ns_name_moqt::<M18>(ns, name), vi_moqt::<M18>(4)].concat()
});

// FETCH, with the four range fields these drafts read before the check.
cap_gate!(draft17_caps_a_fetch, "draft17", draft17, 0x16, |ns, name| {
    [
        vi_moqt::<M17>(0),
        vi_moqt::<M17>(0),
        vi_moqt::<M17>(1),
        ns_name_moqt::<M17>(ns, name),
        vi_moqt::<M17>(0),
        vi_moqt::<M17>(0),
        vi_moqt::<M17>(1),
        vi_moqt::<M17>(0),
    ]
    .concat()
});
cap_gate!(draft18_caps_a_fetch, "draft18", draft18, 0x16, |ns, name| {
    [
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(1),
        ns_name_moqt::<M18>(ns, name),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(1),
        vi_moqt::<M18>(0),
    ]
    .concat()
});
cap_gate!(draft19_caps_a_fetch, "draft19", draft19, 0x16, |ns, name| {
    [
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(1),
        ns_name_moqt::<M18>(ns, name),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(1),
        vi_moqt::<M18>(0),
    ]
    .concat()
});

// PUBLISH_BLOCKED on drafts 17 and 18 and PUBLISH_SKIPPED on draft-19, type 0x0F
// on all three: the same message under two names, and the only carrier whose
// first field is the namespace.
cap_gate!(draft17_caps_a_publish_blocked, "draft17", draft17, 0x0F, |ns, name| {
    ns_name_moqt::<M17>(ns, name)
});
cap_gate!(draft18_caps_a_publish_blocked, "draft18", draft18, 0x0F, |ns, name| {
    ns_name_moqt::<M18>(ns, name)
});
cap_gate!(draft19_caps_a_publish_skipped, "draft19", draft19, 0x0F, |ns, name| {
    ns_name_moqt::<M18>(ns, name)
});

// The Redirect inside a REQUEST_ERROR, type 0x05, on drafts 18 and 19. Error
// code 0x34 is REDIRECT and is what puts the structure on the wire at all; the
// retry interval, the empty reason phrase and the empty Connect URI are the
// three fields in front of the namespace.
cap_gate!(draft18_caps_a_redirect, "draft18", draft18, 0x05, |ns, name| {
    [
        vi_moqt::<M18>(0x34),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(0),
        ns_name_moqt::<M18>(ns, name),
    ]
    .concat()
});
cap_gate!(draft19_caps_a_redirect, "draft19", draft19, 0x05, |ns, name| {
    [
        vi_moqt::<M18>(0x34),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(0),
        vi_moqt::<M18>(0),
        ns_name_moqt::<M18>(ns, name),
    ]
    .concat()
});

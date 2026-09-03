#![cfg(any(feature = "draft17", feature = "draft18", feature = "draft19", feature = "draft20"))]

//! Drafts 17 through 20 carry control messages on a **pair of
//! unidirectional streams**, and a bidirectional stream is a request stream.
//! These tests drive `Connection::connect` and the request helpers at a peer
//! that enforces exactly that, and assert a session is completed and requests
//! are answered.
//!
//! # The one thing draft-20 does not share
//!
//! Draft-20's Section 3.3 is draft-19's sentence unchanged, so the 400-line
//! enforcing peer below needed no change at all for it and neither did 23 of
//! the 25 gates. **FETCH is the whole of the divergence.** Section 10.13
//! deleted the Fetch Type field, both payload structures and the joining
//! mechanism, promoted the namespace and the track name to fields of FETCH
//! itself, and moved the range into the `LOCATION_FILTER` parameter. So the
//! FETCH rendering and the fetch half of the request sweep are per-draft
//! functions handed to the gate macro, exactly as SUBSCRIBE_NAMESPACE has been
//! since draft-18 split it in two. Drafts 17, 18 and 19 share one body for
//! both — their `Fetch` and their three helpers are identical — and draft-20
//! has its own.
//!
//! Where draft-19 opens a joining FETCH, draft-20 asks for a **fill**: a
//! `FILL_PARAMETERS` parameter on a SUBSCRIBE, answered by a unidirectional
//! fill fetch stream (Section 5.1.3). The half of that which is a request
//! belongs here and is swept with the rest; the stream that answers it is a
//! data stream, and is gated in `draft20_fill_stream_objects.rs` and
//! `draft20_fill_and_state_notify.rs` rather than repeated here.
//!
//! # Why the peer has to enforce it
//!
//! A permissive peer — one that reads SETUP off whatever stream it turns up
//! on — completes a session against a client that puts SETUP on a
//! bidirectional stream just as happily as against one that gets the topology
//! right, so it proves nothing about either. The peer here refuses, in both
//! directions:
//!
//! * it reads the leading message type of every bidirectional stream, and
//!   closes the session with PROTOCOL_VIOLATION if that type is not one of the
//!   request types Section 3.3 permits. SETUP is not one of them.
//! * it reads every message that follows SETUP on the client's control stream,
//!   and closes the session with PROTOCOL_VIOLATION if one of them *is* a
//!   request type. Section 3.3 gives requests streams of their own, so a
//!   SUBSCRIBE on the control stream is as wrong as a SETUP on a bidirectional
//!   one.
//!
//! Both halves of that are gated on the peer itself, because a peer that
//! quietly stopped enforcing would let every other test here pass for the
//! wrong reason:
//!
//! * `enforcement_closes_the_session` opens a bidirectional stream, writes
//!   SETUP on it with raw quinn, and asserts the session is closed with
//!   PROTOCOL_VIOLATION.
//! * `control_stream_enforcement_closes_the_session` completes the setup
//!   exchange with raw quinn, writes a TRACK_STATUS on the same unidirectional
//!   control stream, and asserts the same.
//!
//! # The response has to come back on the stream the request went out on
//!
//! Draft-17 responses carry no request id — the stream *is* the correlation —
//! so a test that only checked "a response arrived" would pass against an
//! implementation that correlated by luck. The peer therefore answers each
//! SUBSCRIBE with a SUBSCRIBE_OK whose track alias is derived from the track
//! name that was asked for, and it **staggers the answers so the later request
//! is answered first**. A client that handed back whichever answer arrived
//! first would give the wrong one to the wrong handle, and
//! `two_requests_are_answered_on_their_own_streams` would fail.
//!
//! # The peer also opens request streams of its own
//!
//! Section 3.3 lets **either** endpoint open a request stream, so a client
//! that only ever asks is half an implementation. On command from a test the
//! peer opens a bidirectional stream toward the client, writes a request as
//! its first message, and then reads that stream's own receive half. An
//! answer read there came back where it belongs by construction: nothing the
//! client wrote anywhere else can reach that reader. The peer reports the
//! answer's message type and a mark taken from its body, so an answer written
//! on the wrong one of two open request streams is caught as well as one
//! written on the control stream — and every message the peer allows on the
//! control stream is reported too, so "somewhere else" is not silent either.
//!
//! Three consequences of the accept path are only visible from this side and
//! are asserted here rather than through a return value:
//!
//! * a bidirectional stream that begins with something other than a request
//!   must be answered with a CONNECTION_CLOSE carrying PROTOCOL_VIOLATION;
//! * a request id with the parity this endpoint allocates from must be
//!   answered with INVALID_REQUEST_ID, which is a different code and so
//!   cannot be satisfied by the same close; and
//! * a peer-opened request stream that is abandoned resets with a different
//!   code from one this endpoint opened.
//!
//! An `Err` returned to a caller proves none of those: it is returned just as
//! readily by an implementation that closes nothing.
//!
//! This half is opt-in. A test that never sends a [`PeerCommand`] sees exactly
//! the event stream it saw before the accept path existed, which is what keeps
//! `every_request_helper_opens_its_own_stream` free of interleaving.
//!
//! Both halves of that are gated on the peer as well —
//! `the_peer_opens_a_request_stream_and_requires_the_answer_on_it` and
//! `the_peer_reports_the_close_the_client_sends` drive it with raw quinn, for
//! the same reason as the two enforcement gates above.
//!
//! # The peer is built on raw quinn
//!
//! It buffers and decodes with its own code and `moqtap-codec`, and never
//! calls the framing helpers in `moqtap-client` — a peer assembled out of the
//! stream-classification code under test could not disagree with it.

mod common;

use common::{namespace_text, render, text};

use std::collections::HashMap;
use std::time::Duration;

use moqtap_codec::dispatch::{AnyControlMessage, AnySubgroupHeader};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Session termination code `PROTOCOL_VIOLATION` (Section 14.5.1 on
/// draft-17, Section 15.5.1 on drafts 18 and 19, Section 15.11.1 on draft-20;
/// the value is 0x3 on all four).
const PROTOCOL_VIOLATION: u32 = 0x3;

/// Session termination code `INVALID_REQUEST_ID`, 0x4 on all four drafts:
/// "The endpoint received a Request ID with an incorrect least significant bit
/// for the sender, or a duplicate Request ID."
///
/// A different number from [`PROTOCOL_VIOLATION`] on purpose, and the reason
/// the parity gate cannot be satisfied by the close the refusal gate expects.
const INVALID_REQUEST_ID: u64 = 0x4;

/// The unidirectional stream type of a control stream, which is also the
/// SETUP message type (Sections 3.4 and 9.4 on draft-17, 3.4 and 10.3 on
/// drafts 18, 19 and 20).
///
/// Spelled out here rather than imported from `moqtap-client` so the peer
/// agrees with the draft rather than with the code it is testing.
const SETUP_STREAM_TYPE: u64 = 0x2F00;

/// SUBSCRIBE's message type, 0x03 on all four drafts. The type a request
/// stream opened by [`Connection::subscribe`] has to lead with.
const SUBSCRIBE_TYPE: u64 = 0x03;

/// TRACK_STATUS's message type, 0x0D on all four drafts. The request the
/// peer's own gate writes in the wrong place, and the one
/// `every_request_helper_opens_its_own_stream` expects from
/// `Connection::track_status`.
const TRACK_STATUS_TYPE: u64 = 0x0D;

/// FETCH's message type, 0x16 on all four drafts, and the codepoint that
/// makes draft-20 dangerous: the number did not move, but the body behind it
/// was rebuilt, so a draft-19 decoder reads a draft-20 FETCH as a
/// well-formed request for something else.
///
/// On drafts 17, 18 and 19 all three of `Connection::fetch`,
/// `Connection::joining_fetch` and `Connection::absolute_joining_fetch` lead
/// with it — a joining FETCH is a FETCH and gets a request stream of its own
/// rather than sharing the subscription's. Draft-20 has neither joining
/// helper; `Connection::fetch` and `Connection::fetch_range` are the two that
/// lead with it there.
const FETCH_TYPE: u64 = 0x16;

/// AUTHORIZATION TOKEN's parameter key, 0x03 on all four drafts. See
/// [`attached`].
const AUTHORIZATION_TOKEN: u64 = 0x03;

/// Alias Type USE_ALIAS (0x2), the shortest well-formed Token structure:
/// an Alias Type and a Session-specific Alias, and no Token Type or Token
/// Value after them.
///
/// The value of an AUTHORIZATION TOKEN is not opaque — a receiver that cannot
/// decode the Token closes the session — so the parameter the sweep attaches
/// has to be a Token and not a byte string. Written out as bytes rather than
/// built with the codec because that is what the rest of this peer does, and
/// because both varint encodings in this range spell a value under 64 as the
/// same single byte: they differ only in the seven- and eight-byte lengths.
const USE_ALIAS: u8 = 0x2;

/// The Session-specific Alias in that Token. Any number; it stands for a
/// Token Value registered earlier in a session that never registered one,
/// which no rule in this file is about.
const TOKEN_ALIAS: u8 = 0x7;

/// The Fetch Type of a standalone FETCH, 0x1 on drafts 17, 18 and 19.
///
/// The three Fetch Types are one field of one message, which is why they are
/// numbers here rather than message types: a helper that sends the wrong one
/// has written a well-formed FETCH asking for something else.
///
/// Draft-20 deleted the field and the registry behind it (Section 10.13), so
/// this and its two siblings are gated off there rather than left to render a
/// number no draft-20 FETCH carries.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const STANDALONE_FETCH: u64 = 0x1;

/// The Fetch Type of a Relative Joining Fetch, 0x2 on drafts 17, 18 and 19.
/// See [`STANDALONE_FETCH`].
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const RELATIVE_JOINING_FETCH: u64 = 0x2;

/// The Fetch Type of an Absolute Joining Fetch, 0x3 on drafts 17, 18 and 19.
/// See [`STANDALONE_FETCH`].
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const ABSOLUTE_JOINING_FETCH: u64 = 0x3;

/// SUBSCRIBE_OK's message type, 0x04 on all four drafts. Two things use it:
/// the answer the client is expected to write on a request stream the peer
/// opened, and — because it is a *response* and so begins no request stream —
/// the message drafts 17, 18 and 19 have the refusal gate open a bidirectional
/// stream with. Draft-20 opens that stream with a PUBLISH_STATE_NOTIFY
/// instead; see [`PUBLISH_STATE_NOTIFY_TYPE`].
const SUBSCRIBE_OK_TYPE: u64 = 0x04;

/// PUBLISH_STATE_NOTIFY's message type, 0x22, new in draft-20 (Section 10.10).
///
/// It is the newest thing a bidirectional stream may **not** begin with, and
/// the one most easily mistaken for something that may: it carries no Request
/// ID, it answers nothing, and it is not a response, so the two properties an
/// implementation usually classifies by both point the wrong way. Section 10.10
/// puts it "on a subscription's bidirectional stream" — a stream a SUBSCRIBE or
/// a PUBLISH has already opened — so it opens none of its own, and the refusal
/// gate holds draft-20 to that.
#[cfg(feature = "draft20")]
const PUBLISH_STATE_NOTIFY_TYPE: u64 = 0x22;

/// `LARGEST_OBJECT`, Parameter Type 0x09: the parameter Section 10.10 says a
/// publisher MUST put on a PUBLISH_STATE_NOTIFY when it knows the value.
///
/// The refusal gate's notify carries one, so what is refused is a message the
/// rule recognises rather than an empty frame no publisher would send.
#[cfg(feature = "draft20")]
const LARGEST_OBJECT: u64 = 0x09;

/// PUBLISH's message type, 0x1D on all four drafts.
const PUBLISH_TYPE: u64 = 0x1D;

/// PUBLISH_NAMESPACE's message type, 0x06 on all four drafts.
const PUBLISH_NAMESPACE_TYPE: u64 = 0x06;

/// SUBSCRIBE_NAMESPACE's message type on draft-17, before draft-18 split the
/// message in two and renumbered what was left.
#[cfg(feature = "draft17")]
const DRAFT17_SUBSCRIBE_NAMESPACE_TYPE: u64 = 0x11;

/// SUBSCRIBE_NAMESPACE's message type on drafts 18, 19 and 20.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
const SUBSCRIBE_NAMESPACE_TYPE: u64 = 0x50;

/// SUBSCRIBE_TRACKS's message type, the seventh request type and the one
/// draft-17 does not have at all.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
const SUBSCRIBE_TRACKS_TYPE: u64 = 0x51;

/// The message types draft-17 Section 3.3 allows a bidirectional stream to
/// begin with: TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE and
/// SUBSCRIBE_NAMESPACE.
#[cfg(feature = "draft17")]
const DRAFT17_REQUEST_TYPES: &[u64] = &[0x0D, 0x03, 0x1D, 0x16, 0x06, 0x11];

/// The same list for drafts 18, 19 and 20, where SUBSCRIBE_NAMESPACE moved to
/// 0x50 and SUBSCRIBE_TRACKS (0x51) joined it, making seven.
///
/// Draft-20 recites the same seven in Section 3.3 and adds nothing to them:
/// PUBLISH_STATE_NOTIFY (0x22) is the message it added and is deliberately
/// **not** here, which is what the refusal gate holds the client to.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
const DRAFT18_REQUEST_TYPES: &[u64] = &[0x0D, 0x03, 0x1D, 0x16, 0x06, 0x50, 0x51];

/// How long a test waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// Track alias and group ID on the data stream the peer sends ahead of its
/// control stream. Arbitrary, and only there so the header that comes back
/// out of the client can be recognised as the one that went in.
const EARLY_TRACK_ALIAS: u64 = 7;
/// See [`EARLY_TRACK_ALIAS`].
const EARLY_GROUP_ID: u64 = 3;

/// The track names the request tests subscribe to. Each ends in the digit
/// the peer echoes back as the SUBSCRIBE_OK's track alias, which is what ties
/// an answer to the request that asked for it.
const TRACK_ONE: &[u8] = b"track-1";
/// See [`TRACK_ONE`].
const TRACK_TWO: &[u8] = b"track-2";

/// A third track, whose name ends in the **same** digit as [`TRACK_ONE`].
///
/// The peer takes a SUBSCRIBE_OK's Track Alias from the last digit of the
/// track name it was asked for, so this is a second track the peer hands the
/// alias it has already given [`TRACK_ONE`] - which is the one thing Section
/// 11.1 forbids a publisher to do. No change to the peer is needed to produce
/// it: the alias it would have chosen anyway is the violation.
const CLASHING_TRACK: &[u8] = b"other-1";

/// The session termination code drafts 17 through 20 name for two tracks
/// under one Track Alias (Section 9.9 on draft-17, Section 11.1 on 18, 19 and
/// 20; the value is 0x5 on all four).
const DUPLICATE_TRACK_ALIAS: u64 = 0x5;

/// The track name on the requests the **peer** makes. Deliberately not one of
/// the two above: an answer to a peer's request is marked by its Request ID,
/// not by its track name, and a name ending in a digit would let the peer's
/// own `answer_subscribe` be mistaken for the client's answer.
const PEER_TRACK: &[u8] = b"peer-track";

/// The mark [`TRACK_ONE`] and [`TRACK_TWO`] carry, and the highest mark the
/// peer staggers its answers against.
const MARK_ONE: u64 = 1;
/// See [`MARK_ONE`].
const MARK_TWO: u64 = 2;

/// How much later the peer answers a request marked one lower.
///
/// The answer to [`TRACK_ONE`] is held back by this while the answer to
/// [`TRACK_TWO`] goes out at once, so the answers arrive in the opposite
/// order to the requests. Long enough that the second answer is comfortably
/// in the client's hands before the first is written, short enough not to
/// slow the suite.
const RESPONSE_STAGGER: Duration = Duration::from_millis(150);

/// How long an operation that must **not** finish is given to prove it.
///
/// Only the cancel-safety gate uses it, and only to bound each of its attempts
/// to drive an accept into its read and then drop it. A too-short slice there
/// costs an extra attempt, not a failure — the gate loops until the accept has
/// demonstrably taken the peer's stream — so this is a pacing figure and not a
/// timing assumption.
const BRIEF: Duration = Duration::from_millis(200);

/// How many attempts the cancel-safety gate makes before it gives up waiting
/// for a cancelled accept to have taken the peer's stream. At [`BRIEF`] each,
/// well inside [`PATIENCE`].
const CANCEL_ATTEMPTS: usize = 20;

/// `CANCELLED`, 0x1: the application error code draft-17 assigns for "the
/// subscriber or publisher cancelled the Request", and the one a request
/// stream's reset carries when the requester walks away from it.
///
/// Spelled out rather than imported for the same reason as
/// [`SETUP_STREAM_TYPE`].
const CANCELLED: u64 = 0x1;

/// An error code no default could produce, used by the explicit-cancel gate
/// so its assertion cannot be satisfied by the [`CANCELLED`] a dropped handle
/// sends.
const CHOSEN_CANCEL_CODE: u64 = 0x1234;

/// `INTERNAL_ERROR`, 0x0: the code a request stream the **peer** opened is
/// reset with when this endpoint walks away from it without serving it.
///
/// The whole point of it is that it is not [`CANCELLED`]. A requester
/// withdraws its own request; a responder abandons one that was asked of it,
/// and a peer that saw the same code for both could not tell which had
/// happened.
const UNANSWERED: u64 = 0x0;

/// Request IDs the peer puts on the requests it opens streams with.
///
/// The client under test is a client, so draft-17 Section 9.1 (Section 10.1 on
/// drafts 18, 19 and 20) has it allocate **even** ids and accept only **odd**
/// ones from its peer. These are odd.
const PEER_REQUEST_ID: u64 = 1;
/// See [`PEER_REQUEST_ID`]. A second odd id, for the gate that has an inbound
/// and an outbound request open at once.
const OTHER_PEER_REQUEST_ID: u64 = 3;

/// An **even** request id: the parity this endpoint allocates from, and so one
/// no conforming peer can send. Section 9.1 answers it with
/// [`INVALID_REQUEST_ID`].
const WRONG_PARITY_REQUEST_ID: u64 = 2;

/// The peer's own name for the *second* stream in the repeated-id gate.
///
/// A label is how the peer keys the streams it opens; the Request ID on the
/// wire is a separate number, and in that gate it is [`PEER_REQUEST_ID`] on
/// both streams on purpose. Labelling the second stream the same would have the
/// peer's map replace the first stream's send half with the second's, resetting
/// a stream the client is still holding open and confusing "the id was
/// repeated" with "the first request went away".
const SECOND_STREAM_LABEL: u64 = 5;

/// The mark the peer reports for an answer that is not a SUBSCRIBE_OK, whose
/// body therefore carries no track alias to take one from. Outside the range
/// of every request id these tests use, so it can never be mistaken for one.
const NO_MARK: u64 = u64::MAX;

/// The code the raw quinn client of
/// `the_peer_reports_the_close_the_client_sends` closes with.
///
/// `DUPLICATE_TRACK_ALIAS` (0x5), chosen only because it is neither of the two
/// codes the accept path itself produces: a peer that reported a hard-coded
/// [`PROTOCOL_VIOLATION`] would satisfy that gate if it used one of those.
const RAW_CLOSE_CODE: u32 = 0x5;

/// The reason phrase that same raw client sends, for the same reason.
const RAW_CLOSE_REASON: &[u8] = b"raw client close";

/// The namespace every request in these tests names. Its content does not
/// matter; only that both ends agree it is well formed.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"uni-control-plane".to_vec()])
}

/// A parameter the request sweep attaches to every helper it calls.
///
/// What it is for is that the rendering the peer reports then has something in
/// it only the caller could have put there: a helper that dropped the list it
/// was given renders `parameters=0` where the gate asked for `parameters=1`.
///
/// AUTHORIZATION TOKEN because it is the one parameter every request type
/// admits, and these drafts refuse a message carrying a parameter its own
/// definition does not place there. Draft-17 Section 9.3.2: "It MAY appear in
/// a PUBLISH, SUBSCRIBE, REQUEST_UPDATE, SUBSCRIBE_NAMESPACE,
/// PUBLISH_NAMESPACE, TRACK_STATUS or FETCH message." Drafts 18, 19 and 20 say
/// the same in Section 10.2.2 with SUBSCRIBE_TRACKS added to the list, which
/// is the request type they added.
fn attached() -> KeyValuePair {
    KeyValuePair {
        key: VarInt::from_u64_moqt(AUTHORIZATION_TOKEN),
        value: KvpValue::Bytes(vec![USE_ALIAS, TOKEN_ALIAS]),
    }
}

/// A SUBSCRIBE, rendered.
fn subscribe_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    parameters: usize,
) -> String {
    render(
        "SUBSCRIBE",
        SUBSCRIBE_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("namespace", namespace_text(track_namespace)),
            ("track", text(track_name)),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// A standalone FETCH, rendered. `range` is the Start and End Locations in
/// the order the message carries them.
///
/// Drafts 17, 18 and 19 only: draft-20 has no Fetch Type and no inline range,
/// and renders through [`draft20_fetch_request`] instead.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn standalone_fetch_request(
    request_id: u64,
    fetch_type: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    range: (u64, u64, u64, u64),
    parameters: usize,
) -> String {
    let (start_group, start_object, end_group, end_object) = range;
    render(
        "FETCH",
        FETCH_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("fetch type", fetch_type.to_string()),
            ("namespace", namespace_text(track_namespace)),
            ("track", text(track_name)),
            ("start group", start_group.to_string()),
            ("start object", start_object.to_string()),
            ("end group", end_group.to_string()),
            ("end object", end_object.to_string()),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// A joining FETCH of either type, rendered.
///
/// The Fetch Type is a field here rather than part of the name, because the
/// relative form and the absolute form are one message and differ in it. It
/// is the difference two connection helpers exist to make.
///
/// Drafts 17, 18 and 19 only. Draft-20 Section 10.13 deleted the joining
/// fetch outright; what replaced it is a `FILL_PARAMETERS` parameter on a
/// SUBSCRIBE, which renders as a SUBSCRIBE.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn joining_fetch_request(
    request_id: u64,
    fetch_type: u64,
    joining_request_id: u64,
    joining_start: u64,
    parameters: usize,
) -> String {
    render(
        "FETCH",
        FETCH_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("fetch type", fetch_type.to_string()),
            ("joining request id", joining_request_id.to_string()),
            ("joining start", joining_start.to_string()),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// A draft-20 FETCH, rendered.
///
/// The same four fields a SUBSCRIBE carries — Section 10.13 made FETCH
/// byte-identical to SUBSCRIBE apart from the type code — plus the range,
/// which is no longer a field of the message at all. `range` is
/// [`draft20_range_text`] over the message's own parameters, so a helper that
/// forgot the filter, wrote it under the wrong type, or shifted an end
/// location by one renders differently from one that got it right.
///
/// Keeping the range in the rendering is what carries decision D4 into this
/// file: draft-19 wrote "the last Object, plus 1", draft-20 Sections 5.1.2 and
/// 10.13 make the range inclusive, and a ported `+ 1` is invisible in a
/// parameter count.
#[cfg(feature = "draft20")]
fn draft20_fetch_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    range: &str,
    parameters: usize,
) -> String {
    render(
        "FETCH",
        FETCH_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("namespace", namespace_text(track_namespace)),
            ("track", text(track_name)),
            ("range", range.to_string()),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// The `LOCATION_FILTER` fields of a draft-20 message, rendered for
/// [`draft20_fetch_request`].
///
/// `none` when the message carries no filter, which Section 10.13 defines as
/// `{0,0}` through Largest Object. Otherwise the `vi64` fields in wire order,
/// decoded by the codec's own decoder rather than by anything here: the shape
/// of a filter comes from how many varints its value holds (decision D3), and
/// a peer that guessed from the byte length would agree with a wrong encoder.
///
/// A value that is not a well-formed filter renders as its own complaint
/// instead of panicking. The peer is reporting what arrived, and a filter it
/// cannot read is a fact about the client under test rather than about this
/// function.
#[cfg(feature = "draft20")]
fn draft20_range_text(parameters: &[KeyValuePair]) -> String {
    use moqtap_codec::draft20::message::{decode_location_filter, LOCATION_FILTER};

    let Some(filter) = parameters.iter().find(|p| p.key.into_inner() == LOCATION_FILTER) else {
        return "none".to_string();
    };
    let KvpValue::Bytes(value) = &filter.value else {
        return "not length-prefixed".to_string();
    };
    match decode_location_filter(value) {
        Ok(fields) => fields.iter().map(u64::to_string).collect::<Vec<_>>().join(","),
        Err(e) => format!("undecodable ({e:?})"),
    }
}

/// A PUBLISH_NAMESPACE, rendered.
fn publish_namespace_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    parameters: usize,
) -> String {
    render(
        "PUBLISH_NAMESPACE",
        PUBLISH_NAMESPACE_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("namespace", namespace_text(track_namespace)),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// A TRACK_STATUS, rendered.
fn track_status_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    parameters: usize,
) -> String {
    render(
        "TRACK_STATUS",
        TRACK_STATUS_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("namespace", namespace_text(track_namespace)),
            ("track", text(track_name)),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// A PUBLISH, rendered. Its two lists are counted separately: an endpoint
/// that put the caller's parameters where the track properties go would
/// otherwise render the same either way.
fn publish_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    track_alias: u64,
    parameters: usize,
    track_properties: usize,
) -> String {
    render(
        "PUBLISH",
        PUBLISH_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("namespace", namespace_text(track_namespace)),
            ("track", text(track_name)),
            ("track alias", track_alias.to_string()),
            ("parameters", parameters.to_string()),
            ("track properties", track_properties.to_string()),
        ],
    )
}

/// Draft-17's SUBSCRIBE_NAMESPACE, rendered: a different type number from
/// drafts 18, 19 and 20, and the `subscribe_options` field they dropped.
#[cfg(feature = "draft17")]
fn draft17_subscribe_namespace_request(
    request_id: u64,
    namespace_prefix: &TrackNamespace,
    subscribe_options: u64,
    parameters: usize,
) -> String {
    render(
        "SUBSCRIBE_NAMESPACE",
        DRAFT17_SUBSCRIBE_NAMESPACE_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("prefix", namespace_text(namespace_prefix)),
            ("options", subscribe_options.to_string()),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// SUBSCRIBE_NAMESPACE on drafts 18, 19 and 20, rendered.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
fn subscribe_namespace_request(
    request_id: u64,
    namespace_prefix: &TrackNamespace,
    parameters: usize,
) -> String {
    render(
        "SUBSCRIBE_NAMESPACE",
        SUBSCRIBE_NAMESPACE_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("prefix", namespace_text(namespace_prefix)),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// SUBSCRIBE_TRACKS, rendered. The seventh request type, and the one that
/// carries the same two fields as the message it was split out of — which is
/// why a helper that wrote the wrong one of the two is worth catching.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
fn subscribe_tracks_request(
    request_id: u64,
    namespace_prefix: &TrackNamespace,
    parameters: usize,
) -> String {
    render(
        "SUBSCRIBE_TRACKS",
        SUBSCRIBE_TRACKS_TYPE,
        &[
            ("request id", request_id.to_string()),
            ("prefix", namespace_text(namespace_prefix)),
            ("parameters", parameters.to_string()),
        ],
    )
}

/// Builds the peer's answer to a request: the mark that ties the answer to
/// its request, and the encoded response message.
///
/// Returning `None` leaves the request unanswered, which is what the peer
/// does with anything it has no reply for.
type Responder = fn(&AnyControlMessage) -> Option<(u64, Vec<u8>)>;

/// Reads a message the client wrote on a request stream the **peer** opened,
/// and reports its message type together with a mark taken from its body.
///
/// The mark is a SUBSCRIBE_OK's Track Alias, which the answering tests set to
/// the Request ID being answered. That is what turns "an answer arrived" into
/// "*this* request's answer arrived": with two peer-opened streams in flight,
/// an answer written on the wrong one carries the wrong mark and the two
/// disagree. Anything that is not a SUBSCRIBE_OK is reported with [`NO_MARK`],
/// so a client that answered with the wrong *message* is caught too.
///
/// Per draft, because the mark lives in a draft's own message struct.
type AnswerMark = fn(&AnyControlMessage) -> Option<(u64, u64)>;

/// Renders a request the client made, for the peer's report. See [`render`].
///
/// Per draft, because the fields live in a draft's own message structs. The
/// four request types every draft in this range spells the same way are
/// rendered inside the gate macro; the namespace requests and FETCH are not
/// one message across the four and are rendered by functions of their own —
/// `$describe_namespace` and `$describe_fetch`.
type Describe = fn(&AnyControlMessage) -> String;

/// Everything the peer needs to know about the draft it is speaking.
///
/// Carried as one value rather than as four parameters because every half of
/// the peer needs some of it and two need all of it: the halves are
/// [`enforce_bidi_streams`], [`serve_peer_requests`], [`report_client_close`]
/// and [`serve_control_stream`], and threading four arguments through each is
/// how the two request-type lists drift apart.
#[derive(Clone, Copy)]
struct PeerRules {
    /// How to frame and decode. Varints are not spelled the same on every
    /// draft in this range.
    draft: DraftVersion,
    /// The message types this draft's Section 3.3 lets a bidirectional stream
    /// begin with. Refused on the control stream and required on a
    /// bidirectional one — the same list judges both, which is what makes the
    /// two halves inverses rather than two opinions.
    request_types: &'static [u64],
    /// How to answer a request the client made. See [`Responder`].
    responder: Responder,
    /// How to read an answer the client owed. See [`AnswerMark`].
    answer_mark: AnswerMark,
    /// How to render a request the client made. See [`Describe`].
    describe: Describe,
}

/// What a test asks the peer to do on its own initiative.
///
/// Everything else the peer does is a reaction to the client. This is the one
/// thing it cannot decide for itself, and it is a command rather than a
/// standing behaviour so that a test which sends none sees an event stream
/// with nothing extra in it.
#[derive(Debug)]
enum PeerCommand {
    /// Open a bidirectional stream toward the client, write `bytes` on it as
    /// that stream's first message, and report everything that comes back on
    /// it under `label`.
    ///
    /// `label` is the peer's name for the stream, and is compared against the
    /// mark in whatever the client writes there.
    ///
    /// `bytes` need not be a whole message. A prefix opens the stream and
    /// leaves the message unfinished, which is what the cancel-safety gate
    /// needs; the rest is sent with [`WriteOnRequestStream`].
    ///
    /// [`WriteOnRequestStream`]: PeerCommand::WriteOnRequestStream
    OpenRequestStream { label: u64, bytes: Vec<u8> },
    /// Write more bytes on the stream already opened under `label`.
    ///
    /// Two uses, and they are why the peer keeps its send halves rather than
    /// handing them to the per-stream watcher: finishing a request that was
    /// deliberately sent in pieces, and sending a *second* message on a
    /// request stream after the client has answered the first.
    WriteOnRequestStream { label: u64, bytes: Vec<u8> },
    /// Cancel the request the peer made under `label`, by resetting the send
    /// half of its stream with `code`.
    ///
    /// The peer withdrawing a request it made. Draft-17 Section 3.3.1,
    /// draft-18 Section 3.3.2 and drafts 19 and 20 Section 3.3.3 all say
    /// "Senders cancel requests if the response is no longer of interest"; the
    /// sentence runs on to say the same of receivers. Explicit rather than
    /// done by dropping the send half, so the code the client reads is one
    /// this test chose and not one quinn picked.
    CancelRequest { label: u64, code: u64 },
}

/// What the peer saw. Reported over a channel so a test can assert on the
/// peer's own observations and not only on the client's return value.
#[derive(Debug, PartialEq, Eq)]
enum PeerEvent {
    /// A SETUP arrived on a unidirectional stream — the topology Section 3.3
    /// requires — and the peer answered with a SETUP on a unidirectional
    /// control stream of its own.
    SetupOnUniStream,
    /// A bidirectional stream began with this message type, which is not one
    /// of the request types Section 3.3 permits, so the session was closed
    /// with PROTOCOL_VIOLATION.
    ClosedBidiStream(u64),
    /// A message of this type followed SETUP on the client's control stream
    /// and is one of the request types, which Section 3.3 gives streams of
    /// their own, so the session was closed with PROTOCOL_VIOLATION.
    ClosedControlStream(u64),
    /// A request arrived where it belongs: alone at the front of a
    /// bidirectional stream of its own, rendered by [`render`].
    ///
    /// The whole message rather than its type. The type says which helper
    /// wrote it and nothing about what it asked for: two Fetch Types are one
    /// message type, so are a subscription to one track and a subscription to
    /// another, and so are a request carrying the caller's parameters and one
    /// that dropped them.
    RequestOnBidiStream(String),
    /// The peer answered a request on the same bidirectional stream it came
    /// in on, with the answer carrying this mark.
    AnsweredRequest(u64),
    /// A request stream was reset by the client with this application error
    /// code — the draft's way of cancelling a request.
    RequestStreamReset(u64),
    /// A bidirectional stream began with this request type and the peer could
    /// not then read a request off it: the bytes did not decode, or the
    /// stream ended before the message did.
    ///
    /// Reported rather than passed over, because a request the peer cannot
    /// read is a request that never arrived as far as every other event here
    /// is concerned, and a test waiting for one would have nothing to fail on
    /// but a timeout.
    UnreadableRequest(u64),
    /// A message of this type followed SETUP on the client's control stream
    /// and is one the peer allows there.
    ///
    /// Nothing about a request the peer opened may appear here: the answer
    /// belongs on that request's own stream. Reported so a client that wrote
    /// its answer in the wrong place is caught by an assertion rather than by
    /// a silence that a hung peer would produce too.
    MessageOnControlStream(u64),
    /// The peer opened a bidirectional stream toward the client and wrote a
    /// request on it under this label.
    RequestSentToClient(u64),
    /// The client wrote a message back on the stream the peer opened under
    /// `label`: its message type, and the mark its body carries. See
    /// [`AnswerMark`].
    ClientAnsweredOnRequestStream { label: u64, message_type: u64, mark: u64 },
    /// The client reset the stream the peer opened under `label`, with this
    /// application error code.
    PeerRequestStreamReset { label: u64, code: u64 },
    /// The stream the peer opened under this label stopped carrying messages
    /// without being reset — a FIN, or bytes that would not decode.
    ClientEndedRequestStream(u64),
    /// The **client** closed the session, with this code and reason phrase.
    ///
    /// The only way a test can see a CONNECTION_CLOSE the client sent: quinn
    /// hands the client's own side a `LocallyClosed` that carries neither, so
    /// an assertion made there would be an assertion about nothing.
    SessionClosedByClient { code: u64, reason: String },
}

/// Wait for the first event the peer reports that `wanted` accepts,
/// discarding the ones before it.
///
/// `None` once the peer has dropped every sender without reporting one.
async fn wait_for_event(
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
    wanted: impl Fn(&PeerEvent) -> bool,
) -> Option<PeerEvent> {
    loop {
        let event = seen.recv().await?;
        if wanted(&event) {
            return Some(event);
        }
    }
}

/// Require the peer's next verdict on a stream to be "this request arrived
/// alone at the front of a bidirectional stream".
///
/// `expected` is the whole request, rendered by [`render`] from what the
/// caller asked for. Asserting on the rendering rather than on the message
/// type is what makes a helper that opened the right stream, wrote the right
/// message type and filled it in wrongly a failure here.
///
/// The wait accepts the peer's two refusals as well, so a helper that wrote
/// its request on the control stream fails naming the type the peer refused
/// and not merely by running out of time.
async fn saw_request(
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
    draft_label: &str,
    what: &str,
    expected: &str,
) {
    let verdict = tokio::time::timeout(
        PATIENCE,
        wait_for_event(seen, |e| {
            matches!(
                e,
                PeerEvent::RequestOnBidiStream(_)
                    | PeerEvent::ClosedBidiStream(_)
                    | PeerEvent::ClosedControlStream(_)
                    | PeerEvent::UnreadableRequest(_)
            )
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("{draft_label}: the peer never reached a verdict on the {what}"));

    assert_eq!(
        verdict,
        Some(PeerEvent::RequestOnBidiStream(expected.to_string())),
        "{draft_label}: the {what} must arrive alone at the front of a bidirectional \
         stream of its own, and must be the request the helper was asked for"
    );
}

/// Drive one request helper to its handle, or panic naming the helper and what
/// the peer made of the session.
///
/// The same three things the `request!` macro inside
/// `every_request_helper_opens_its_own_stream` does — bound the call by
/// [`PATIENCE`], name the helper in the timeout, and put the peer's own report
/// in the failure — for the per-draft hooks that live outside the gate macro
/// and so cannot reach that macro. A hook that used a bare `.expect()` would
/// hang for the full patience and then say nothing about why.
///
/// Generic over the handle and its error rather than per draft: every draft's
/// `RequestStream` and `ConnectionError` differ, and nothing here needs more
/// of either than `Debug`.
async fn made<S, E: std::fmt::Debug>(
    draft_label: &str,
    what: &str,
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
    call: impl std::future::Future<Output = Result<S, E>>,
) -> S {
    let outcome = tokio::time::timeout(PATIENCE, call)
        .await
        .unwrap_or_else(|_| panic!("{draft_label}: {what} did not finish"));
    outcome.unwrap_or_else(|e| {
        panic!("{draft_label}: {what} failed with {e:?}; the peer reported {:?}", reported(seen))
    })
}

/// Everything the peer has reported so far, for a panic message.
///
/// The transport error a client sees when a peer closes the session is
/// quinn's "connection lost" and carries neither the close code nor a reason,
/// so without this the message would not say why the session died.
fn reported(seen: &mut mpsc::UnboundedReceiver<PeerEvent>) -> Vec<PeerEvent> {
    let mut events = Vec::new();
    while let Ok(event) = seen.try_recv() {
        events.push(event);
    }
    events
}

/// A quinn receive stream with a buffer in front of it, so the leading type
/// varint can be read and still be there for the message decoder.
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
    /// The application error code the far end reset this stream with, once
    /// [`fill`](Self::fill) has run into it.
    ///
    /// Still `None` after the stream has ended means it ended with a FIN. The
    /// difference is the whole content of the two abandonment gates: a reset
    /// says the request was walked away from and carries a code saying by
    /// which side, a FIN says it ran its course.
    reset_code: Option<u64>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, buf: Vec::new(), reset_code: None }
    }

    /// Pull more bytes in. `false` once the stream has ended or failed.
    async fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 2048];
        match self.recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
            Err(quinn::ReadError::Reset(code)) => {
                self.reset_code = Some(code.into_inner());
                false
            }
            _ => false,
        }
    }

    /// The leading varint of whatever comes next, left in the buffer for the
    /// next reader.
    ///
    /// On a stream nothing has been read off yet that is the stream's own
    /// type; called again after [`read_control`](Self::read_control) it is the
    /// next message's type field, which is how the peer judges each message
    /// on the control stream in turn.
    async fn stream_type(&mut self, draft: DraftVersion) -> Option<u64> {
        while self.buf.is_empty() {
            if !self.fill().await {
                return None;
            }
        }
        let width = draft.varint_len(self.buf[0]);
        while self.buf.len() < width {
            if !self.fill().await {
                return None;
            }
        }
        let mut cursor = &self.buf[..width];
        draft.decode_varint(&mut cursor).ok().map(|v| v.into_inner())
    }

    /// Decode one whole control message, type field included.
    async fn read_control(&mut self, draft: DraftVersion) -> Option<AnyControlMessage> {
        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                Err(CodecError::UnexpectedEnd) => {
                    if !self.fill().await {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// Read until the client resets this stream, reporting the code it chose.
    ///
    /// Draft-17 removed UNSUBSCRIBE and FETCH_CANCEL: a request is withdrawn
    /// by resetting the stream it was made on, so the reset — and the code on
    /// it — is the only thing on the wire that says a request was cancelled.
    /// A clean end or any other failure is not a cancellation and is not
    /// reported.
    async fn report_reset(mut self, events: &mpsc::UnboundedSender<PeerEvent>) {
        let mut tmp = [0u8; 2048];
        loop {
            match self.recv.read(&mut tmp).await {
                Ok(Some(_)) => continue,
                Err(quinn::ReadError::Reset(code)) => {
                    let _ = events.send(PeerEvent::RequestStreamReset(code.into_inner()));
                    return;
                }
                _ => return,
            }
        }
    }
}

/// Run a peer that enforces the draft's stream topology until the session
/// ends.
///
/// `rules` is everything the peer knows about the draft it is speaking; see
/// [`PeerRules`].
///
/// `setup_reply` is an encoded SETUP for that draft, written verbatim onto the
/// peer's own unidirectional control stream: the message's type field is the
/// stream's type field, so no stream header precedes it.
///
/// `early_data`, when given, is written on a unidirectional stream of its own
/// before anything else — a data stream that reaches the client ahead of the
/// peer's control stream, which Section 3.3 permits.
///
/// `commands` is how a test asks the peer to open a request stream of its own.
/// A peer whose command sender has been dropped never opens one, which is what
/// keeps that half out of the way of the tests that predate it.
async fn run_enforcing_peer(
    conn: quinn::Connection,
    rules: PeerRules,
    setup_reply: Vec<u8>,
    early_data: Option<Vec<u8>>,
    commands: mpsc::UnboundedReceiver<PeerCommand>,
    events: mpsc::UnboundedSender<PeerEvent>,
) {
    if let Some(bytes) = early_data {
        let mut send = conn.open_uni().await.expect("open early data stream");
        send.write_all(&bytes).await.expect("write early data");
        send.finish().expect("finish early data stream");
    }
    tokio::join!(
        enforce_bidi_streams(conn.clone(), rules, events.clone()),
        serve_peer_requests(conn.clone(), rules, commands, events.clone()),
        report_client_close(conn.clone(), events.clone()),
        serve_control_stream(conn, rules, setup_reply, events),
    );
}

/// Open a bidirectional stream toward the client for every command that asks
/// for one, and watch each for the answer it is owed.
///
/// Section 3.3 lets either endpoint open a request stream. This is the peer
/// doing so, and it is the only thing the peer ever initiates.
///
/// Each stream is watched by a task of its own, so an answer that is held back
/// does not stop a later one being seen — the same reason
/// [`enforce_bidi_streams`] spawns per stream.
///
/// The send halves stay here, keyed by label, rather than moving into the
/// watchers: a test may write on a stream again after the client has answered
/// on it, and dropping a quinn send stream resets the stream, which would tell
/// the client the request had been withdrawn. Holding them for the life of this
/// loop is what keeps that from happening early.
async fn serve_peer_requests(
    conn: quinn::Connection,
    rules: PeerRules,
    mut commands: mpsc::UnboundedReceiver<PeerCommand>,
    events: mpsc::UnboundedSender<PeerEvent>,
) {
    // The command channel stays open for as long as a test holds its sender,
    // which is past the end of the session. Without the second arm the peer
    // task would outlive every test that used it by the full patience.
    let serve = async {
        let mut open: HashMap<u64, quinn::SendStream> = HashMap::new();
        while let Some(command) = commands.recv().await {
            match command {
                PeerCommand::OpenRequestStream { label, bytes } => {
                    let Ok((mut send, recv)) = conn.open_bi().await else { return };
                    // quinn does not put a stream on the wire until something
                    // is written on it, so the request and the stream arrive
                    // together.
                    if send.write_all(&bytes).await.is_err() {
                        return;
                    }
                    open.insert(label, send);
                    let _ = events.send(PeerEvent::RequestSentToClient(label));
                    tokio::spawn(watch_peer_request_stream(
                        PeerStream::new(recv),
                        rules,
                        label,
                        events.clone(),
                    ));
                }
                PeerCommand::WriteOnRequestStream { label, bytes } => {
                    let Some(send) = open.get_mut(&label) else {
                        panic!("no request stream is open under label {label}")
                    };
                    if send.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                PeerCommand::CancelRequest { label, code } => {
                    let Some(mut send) = open.remove(&label) else {
                        panic!("no request stream is open under label {label}")
                    };
                    let code = quinn::VarInt::from_u64(code).expect("a chosen reset code");
                    let _ = send.reset(code);
                }
            }
        }
    };
    tokio::select! {
        _ = serve => {}
        _ = conn.closed() => {}
    }
}

/// Report everything the client writes on one stream the peer opened, and then
/// how that stream ended.
///
/// Reading the answer off this stream's own receive half is the whole of the
/// placement assertion: a response written on the control stream, or on
/// another request stream, cannot arrive here. The label travels with every
/// report so a test can say which stream it was.
async fn watch_peer_request_stream(
    mut stream: PeerStream,
    rules: PeerRules,
    label: u64,
    events: mpsc::UnboundedSender<PeerEvent>,
) {
    loop {
        // The type varint first, as the control-stream reader does and for the
        // same reason: `read_control` decodes what is already buffered and
        // only pulls more in when the decoder says the message is short, so on
        // an empty buffer it gives up rather than waits.
        if stream.stream_type(rules.draft).await.is_none() {
            break;
        }
        let Some(msg) = stream.read_control(rules.draft).await else { break };
        if let Some((message_type, mark)) = (rules.answer_mark)(&msg) {
            let _ =
                events.send(PeerEvent::ClientAnsweredOnRequestStream { label, message_type, mark });
        }
    }
    let _ = events.send(match stream.reset_code {
        Some(code) => PeerEvent::PeerRequestStreamReset { label, code },
        None => PeerEvent::ClientEndedRequestStream(label),
    });
}

/// Report the CONNECTION_CLOSE the client sends, if it sends one.
///
/// A close the *peer* made resolves `closed()` with `LocallyClosed` and is not
/// reported: this exists to say what the client did.
async fn report_client_close(conn: quinn::Connection, events: mpsc::UnboundedSender<PeerEvent>) {
    if let quinn::ConnectionError::ApplicationClosed(frame) = conn.closed().await {
        let _ = events.send(PeerEvent::SessionClosedByClient {
            code: frame.error_code.into_inner(),
            reason: String::from_utf8_lossy(&frame.reason).into_owned(),
        });
    }
}

/// Close the session with PROTOCOL_VIOLATION on the first bidirectional
/// stream that does not begin with a request message type, decode the ones
/// that do, and answer them.
///
/// A stream that ends before its type arrives is ignored rather than
/// punished: there is nothing to judge it on.
///
/// # Why the whole message is read here
///
/// The type is read first because it is what the topology rule is about — a
/// stream that begins with something else is refused before anything else
/// happens to it. But a type alone is not a request: the peer reports what
/// the client asked for, and that is only knowable once the message is
/// decoded. Reading it here rather than in [`answer_request`] keeps the
/// report in the accept loop, so requests are reported in the order their
/// streams arrived rather than in the order tasks happen to be scheduled.
async fn enforce_bidi_streams(
    conn: quinn::Connection,
    rules: PeerRules,
    events: mpsc::UnboundedSender<PeerEvent>,
) {
    while let Ok((send, recv)) = conn.accept_bi().await {
        let mut stream = PeerStream::new(recv);
        let Some(ty) = stream.stream_type(rules.draft).await else { continue };
        if !rules.request_types.contains(&ty) {
            let _ = events.send(PeerEvent::ClosedBidiStream(ty));
            conn.close(
                quinn::VarInt::from_u32(PROTOCOL_VIOLATION),
                b"bidirectional stream did not begin with a request message",
            );
            return;
        }
        // Two ways to get no request off a stream that began with a
        // request type, and they are different faults: a reset is the client
        // withdrawing what it asked for, anything else is a request this peer
        // could not read.
        let Some(request) = stream.read_control(rules.draft).await else {
            let _ = events.send(match stream.reset_code {
                Some(code) => PeerEvent::RequestStreamReset(code),
                None => PeerEvent::UnreadableRequest(ty),
            });
            continue;
        };
        let _ = events.send(PeerEvent::RequestOnBidiStream((rules.describe)(&request)));
        // One task per request stream. Answering inline would make the peer
        // answer requests strictly in arrival order, which is the very thing
        // `two_requests_are_answered_on_their_own_streams` needs it not to do.
        tokio::spawn(answer_request(stream, send, request, rules, events.clone()));
    }
}

/// Write the answer to a request back on the stream it came in on, then
/// watch that stream for a cancellation.
///
/// `request` was decoded by [`enforce_bidi_streams`], which is also where a
/// stream reset before its request was whole is reported.
///
/// A cancellation that beats the answer is reported here. A request stream may
/// be reset from the moment it is open, so a peer that only watched after
/// answering would report nothing at all for the earliest cancels.
///
/// The answer is held back by [`RESPONSE_STAGGER`] for every mark below
/// [`MARK_TWO`], so a client with two requests in flight is answered in the
/// opposite order to the one it asked in.
async fn answer_request(
    stream: PeerStream,
    mut send: quinn::SendStream,
    request: AnyControlMessage,
    rules: PeerRules,
    events: mpsc::UnboundedSender<PeerEvent>,
) {
    let Some((mark, bytes)) = (rules.responder)(&request) else { return };
    tokio::time::sleep(RESPONSE_STAGGER * (MARK_TWO.saturating_sub(mark)) as u32).await;
    if send.write_all(&bytes).await.is_err() {
        stream.report_reset(&events).await;
        return;
    }
    let _ = events.send(PeerEvent::AnsweredRequest(mark));
    stream.report_reset(&events).await;
}

/// Accept unidirectional streams, pick the control stream out by its leading
/// varint, read the client's SETUP, answer with one on a control stream of
/// this peer's own, and then hold the client's control stream to the rule
/// that no request may travel on it.
///
/// The reply stream is held for the rest of the session: a control stream
/// must not be closed at the transport layer while the session is alive, and
/// dropping a quinn send stream sends a FIN.
async fn serve_control_stream(
    conn: quinn::Connection,
    rules: PeerRules,
    setup_reply: Vec<u8>,
    events: mpsc::UnboundedSender<PeerEvent>,
) {
    let (mut control_send, mut control_recv) = loop {
        let Ok(recv) = conn.accept_uni().await else { return };
        let mut stream = PeerStream::new(recv);
        let Some(ty) = stream.stream_type(rules.draft).await else { continue };
        if ty != SETUP_STREAM_TYPE {
            // A data stream. Nothing in these tests sends objects, so it is
            // enough to let it fall out of scope.
            continue;
        }
        if stream.read_control(rules.draft).await.is_none() {
            continue;
        }
        let Ok(mut send) = conn.open_uni().await else { return };
        if send.write_all(&setup_reply).await.is_err() {
            return;
        }
        let _ = events.send(PeerEvent::SetupOnUniStream);
        break (send, stream);
    };
    tokio::select! {
        _ = refuse_requests_on_control_stream(&conn, &mut control_recv, rules, &events) => {}
        _ = conn.closed() => {}
    }
    let _ = control_send.finish();
}

/// Close the session with PROTOCOL_VIOLATION on the first message after
/// SETUP whose type is one a request stream begins with.
///
/// This is the inverse of [`enforce_bidi_streams`] and the reason a client
/// that keeps requests on the control plane cannot pass: Section 3.3 gives
/// each request a bidirectional stream, so the control stream carries only
/// what belongs to the session as a whole.
///
/// The type is read without consuming it and the whole message is then
/// decoded, so a message the peer allows still leaves the stream positioned
/// on the next one.
async fn refuse_requests_on_control_stream(
    conn: &quinn::Connection,
    stream: &mut PeerStream,
    rules: PeerRules,
    events: &mpsc::UnboundedSender<PeerEvent>,
) {
    loop {
        let Some(ty) = stream.stream_type(rules.draft).await else { return };
        if rules.request_types.contains(&ty) {
            let _ = events.send(PeerEvent::ClosedControlStream(ty));
            conn.close(
                quinn::VarInt::from_u32(PROTOCOL_VIOLATION),
                b"a request message arrived on the control stream",
            );
            return;
        }
        // Reported, not only allowed. A response the client owes a peer-opened
        // request stream is not a request type and so is not refused here, but
        // it has no business on the control stream either; the answering gates
        // assert this never names one.
        let _ = events.send(PeerEvent::MessageOnControlStream(ty));
        if stream.read_control(rules.draft).await.is_none() {
            return;
        }
    }
}

/// One set of gates per draft. `$draft_mod` is the draft's module in both
/// crates and `$variant` its [`AnyControlMessage`] variant; `$version` is its
/// [`DraftVersion`] and `$request_types` the message types that draft lets a
/// bidirectional stream begin with. `$stray_request` is a TRACK_STATUS built
/// for that draft — the drafts do not share a shape for it, since draft-17
/// carries a `required_request_id_delta` that drafts 18, 19 and 20 dropped —
/// and is written where it does not belong by the peer's own gate.
///
/// `$peer_subscribe` builds the SUBSCRIBE the **peer** opens a request stream
/// toward the client with, from a Request ID. It is a per-draft expression for
/// the same reason `$stray_request` is: draft-17's SUBSCRIBE carries a
/// `required_request_id_delta` that drafts 18, 19 and 20 dropped.
///
/// `$describe_fetch` renders a FETCH and `$fetch_requests` drives the fetch
/// helpers, both outside this macro and both for the same reason
/// `$describe_namespace` and `$namespace_requests` are: draft-20 Section 10.13
/// rebuilt FETCH, so there is no `FetchPayload` to match on, no Fetch Type to
/// render and no joining helper to call. Drafts 17, 18 and 19 get one shared
/// body for the pair from [`joining_fetch_hooks`]; draft-20 writes its own.
///
/// `$non_opener` is a message that begins **no** request stream, built for
/// that draft, and `$non_opener_type` is the type number the client must name
/// when it refuses one. Drafts 17, 18 and 19 use a SUBSCRIBE_OK — a response,
/// which answers a request stream rather than opening one. Draft-20 uses
/// PUBLISH_STATE_NOTIFY, the message it added: Section 10.10 puts it on a
/// subscription's existing stream, and it is the harder case, because unlike a
/// response it carries no Request ID and answers nothing.
macro_rules! uni_control_plane_gates {
    (
        $draft_mod:ident,
        $variant:ident,
        $version:expr,
        $request_types:expr,
        $draft_label:literal,
        $stray_request:expr,
        $peer_subscribe:expr,
        $peer_publish:expr,
        $respond_to_publish:ident,
        $publish_ok:expr,
        $namespace_requests:path,
        $describe_namespace:path,
        $describe_fetch:path,
        $fetch_requests:path,
        $non_opener:expr,
        $non_opener_type:expr
    ) => {
        mod $draft_mod {
            use super::*;

            use moqtap_client::$draft_mod::connection::{
                ClientConfig, Connection, ConnectionError, RequestOrigin, RequestStream,
                TransportType,
            };
            use moqtap_client::$draft_mod::session::state::SessionState;
            use moqtap_client::transport::TransportError;
            use moqtap_codec::$draft_mod::data_stream::SubgroupHeader;
            // `FetchPayload` is deliberately absent: draft-20 has no such type,
            // and importing it here is what stopped this macro covering
            // draft-20 at all — an `E0432` on the first expansion, before any
            // gate had a chance to fail on the merits. The FETCH arm went to
            // `$describe_fetch` instead.
            use moqtap_codec::$draft_mod::message::{
                ControlMessage, PublishDone, Setup, SubscribeOk,
            };

            /// An encoded SETUP with no options, for this draft.
            fn setup_bytes() -> Vec<u8> {
                let msg = AnyControlMessage::$variant(ControlMessage::Setup(Setup {
                    options: Vec::new(),
                }));
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("encode SETUP");
                buf
            }

            /// An encoded TRACK_STATUS for this draft, which a request stream
            /// may begin with and the control stream may not carry.
            fn stray_request_bytes() -> Vec<u8> {
                let msg = AnyControlMessage::$variant($stray_request);
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("encode TRACK_STATUS");
                buf
            }

            /// Answer a SUBSCRIBE with a SUBSCRIBE_OK whose track alias is the
            /// digit the requested track name ends in.
            ///
            /// Draft-17 responses carry no request id, so nothing on the wire
            /// says which request a SUBSCRIBE_OK answers. The alias is what
            /// lets a test say it anyway: an answer that came back on the
            /// wrong stream carries the wrong mark and is caught.
            ///
            /// Anything that is not a SUBSCRIBE goes unanswered.
            fn answer_subscribe(request: &AnyControlMessage) -> Option<(u64, Vec<u8>)> {
                let AnyControlMessage::$variant(ControlMessage::Subscribe(sub)) = request else {
                    return None;
                };
                let mark = u64::from(sub.track_name.last()?.checked_sub(b'0')?);
                let ok = AnyControlMessage::$variant(ControlMessage::SubscribeOk(SubscribeOk {
                    track_alias: VarInt::from_u64_moqt(mark),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                }));
                let mut buf = Vec::new();
                ok.encode(&mut buf).ok()?;
                Some((mark, buf))
            }

            /// A SUBSCRIBE the peer writes on a bidirectional stream it opens
            /// toward the client, carrying `request_id`.
            fn peer_subscribe_bytes(request_id: u64) -> Vec<u8> {
                let build: fn(VarInt) -> ControlMessage = $peer_subscribe;
                let msg =
                    AnyControlMessage::$variant(build(VarInt::from_u64_moqt(request_id)));
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("encode the peer's SUBSCRIBE");
                buf
            }

            /// An encoded PUBLISH from the peer, carrying `request_id`.
            ///
            /// A peer that PUBLISHes toward this endpoint is the case the
            /// accept path exists for — a relay offering a track to a
            /// subscriber — and it is the one request kind whose stream then
            /// carries a second message *from the peer*, which is what makes
            /// it the shape that tells the two dispatchers apart.
            fn peer_publish_bytes(request_id: u64) -> Vec<u8> {
                let build: fn(VarInt) -> ControlMessage = $peer_publish;
                let msg = AnyControlMessage::$variant(build(VarInt::from_u64_moqt(request_id)));
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("encode the peer's PUBLISH");
                buf
            }

            /// An encoded PUBLISH_DONE, which the peer writes on its own
            /// PUBLISH's stream to end the subscription it established.
            ///
            /// The message has the same three fields and no Request ID on all
            /// four drafts: the stream it arrives on is the correlation.
            fn peer_publish_done_bytes() -> Vec<u8> {
                let msg = AnyControlMessage::$variant(ControlMessage::PublishDone(PublishDone {
                    status_code: VarInt::from_u64_moqt(0),
                    stream_count: VarInt::from_u64_moqt(0),
                    reason_phrase: Vec::new(),
                }));
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("encode PUBLISH_DONE");
                buf
            }

            /// A message that begins **no** request stream, encoded for this
            /// draft, which the refusal gate opens a bidirectional stream
            /// with. See `$non_opener`.
            ///
            /// Drafts 17, 18 and 19 use a SUBSCRIBE_OK. A response is the
            /// realistic mistake there — an implementation that put an answer
            /// on a stream of its own rather than on the request's would
            /// produce exactly this — and it is a message this file already
            /// knows the client can decode. Draft-20 uses the
            /// PUBLISH_STATE_NOTIFY it added instead, for the reason given at
            /// [`PUBLISH_STATE_NOTIFY_TYPE`].
            fn non_opener_bytes() -> Vec<u8> {
                let msg = AnyControlMessage::$variant($non_opener);
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("encode the non-opening message");
                buf
            }

            /// The answer the client is asked to write on a peer-opened
            /// request stream: a SUBSCRIBE_OK whose Track Alias is the Request
            /// ID it answers.
            ///
            /// Echoing the id is what makes a misdelivered answer visible. The
            /// peer knows which stream it opened under which label and reports
            /// the alias it read there; the two agree only if the answer went
            /// out on the stream the request came in on.
            fn answer_for(request_id: u64) -> SubscribeOk {
                SubscribeOk {
                    track_alias: VarInt::from_u64_moqt(request_id),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                }
            }

            /// See [`AnswerMark`]. A SUBSCRIBE_OK reports its Track Alias;
            /// anything else reports its own type and [`NO_MARK`], so a client
            /// that answered with the wrong message is caught rather than
            /// ignored.
            fn answer_mark(msg: &AnyControlMessage) -> Option<(u64, u64)> {
                let msg = match msg {
                    AnyControlMessage::$variant(msg) => msg,
                    // A build enabling one draft leaves this catch-all nothing to match.
                    #[allow(unreachable_patterns)]
                    _ => return None,
                };
                match msg {
                    ControlMessage::SubscribeOk(ok) => {
                        Some((SUBSCRIBE_OK_TYPE, ok.track_alias.into_inner()))
                    }
                    other => Some((other.message_type().id(), NO_MARK)),
                }
            }

            /// See [`Describe`]. The four request types spelled the same
            /// way on all four drafts; FETCH and the namespace requests,
            /// which are not, go to functions of this draft's own.
            ///
            /// A message that is not a request reaches here only if the type
            /// list and this match disagree, and is rendered by its own
            /// Debug so that the disagreement is visible rather than silent.
            fn describe(msg: &AnyControlMessage) -> String {
                let msg = match msg {
                    AnyControlMessage::$variant(msg) => msg,
                    // A build enabling one draft leaves this catch-all
                    // nothing to match.
                    #[allow(unreachable_patterns)]
                    other => return format!("a message of another draft: {other:?}"),
                };
                match msg {
                    ControlMessage::Subscribe(m) => subscribe_request(
                        m.request_id.into_inner(),
                        &m.track_namespace,
                        &m.track_name,
                        m.parameters.len(),
                    ),
                    ControlMessage::Fetch(m) => $describe_fetch(m),
                    ControlMessage::Publish(m) => publish_request(
                        m.request_id.into_inner(),
                        &m.track_namespace,
                        &m.track_name,
                        m.track_alias.into_inner(),
                        m.parameters.len(),
                        m.track_properties.len(),
                    ),
                    ControlMessage::PublishNamespace(m) => publish_namespace_request(
                        m.request_id.into_inner(),
                        &m.track_namespace,
                        m.parameters.len(),
                    ),
                    ControlMessage::TrackStatus(m) => track_status_request(
                        m.request_id.into_inner(),
                        &m.track_namespace,
                        &m.track_name,
                        m.parameters.len(),
                    ),
                    other => $describe_namespace(other),
                }
            }

            /// This draft's [`PeerRules`].
            fn peer_rules() -> PeerRules {
                PeerRules {
                    draft: $version,
                    request_types: $request_types,
                    responder: answer_subscribe,
                    answer_mark,
                    describe,
                }
            }

            /// The Request ID a SUBSCRIBE carries, or a panic naming what
            /// turned up instead.
            fn subscribe_id(msg: &ControlMessage) -> u64 {
                match msg {
                    ControlMessage::Subscribe(sub) => sub.request_id.into_inner(),
                    other => {
                        panic!("{}: expected the peer's SUBSCRIBE, got {other:?}", $draft_label)
                    }
                }
            }

            /// The mark a SUBSCRIBE_OK carries, or a panic naming what turned
            /// up instead.
            fn mark_of(msg: &ControlMessage) -> u64 {
                match msg {
                    ControlMessage::SubscribeOk(ok) => ok.track_alias.into_inner(),
                    other => {
                        panic!("{}: expected a SUBSCRIBE_OK, got {other:?}", $draft_label)
                    }
                }
            }

            /// A subgroup stream's header bytes for this draft: header type
            /// 0x14, which is the base subgroup bit (0x10) plus subgroup-ID
            /// mode 2, an explicit ID. The type byte is also the stream's
            /// leading varint, so this stream announces itself as a data
            /// stream and not as [`SETUP_STREAM_TYPE`].
            fn subgroup_stream_bytes() -> Vec<u8> {
                let header = SubgroupHeader {
                    header_type: 0x14,
                    track_alias: VarInt::from_u64_moqt(EARLY_TRACK_ALIAS),
                    group_id: VarInt::from_u64_moqt(EARLY_GROUP_ID),
                    subgroup_id: VarInt::from_u64_moqt(1),
                    publisher_priority: Some(128),
                };
                let mut buf = Vec::new();
                header.encode(&mut buf);
                buf
            }

            fn client_config() -> ClientConfig {
                ClientConfig {
                    draft: $version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                }
            }

            /// A connected client, the task running the peer that serves it,
            /// and the channel the peer's observations arrive on. See
            /// [`connected`].
            type Connected = (Connection, JoinHandle<()>, mpsc::UnboundedReceiver<PeerEvent>);

            /// [`Connected`], plus the channel a test drives the peer's own
            /// request streams over. See [`connected_with_commands`].
            type ConnectedWithCommands = (
                Connection,
                JoinHandle<()>,
                mpsc::UnboundedReceiver<PeerEvent>,
                mpsc::UnboundedSender<PeerCommand>,
            );

            /// Bring up an enforcing peer and connect a client to it.
            ///
            /// The command sender is dropped here, so the peer opens no
            /// request streams of its own and every test that uses this sees
            /// the event stream it saw before the accept path existed. A test
            /// that wants the other half calls
            /// [`connected_with_commands`] instead.
            async fn connected() -> Connected {
                let (conn, peer, seen, _commands) = connected_with_commands().await;
                (conn, peer, seen)
            }

            /// Bring up an enforcing peer, connect a client to it, and keep the
            /// channel that asks the peer to open request streams toward that
            /// client.
            async fn connected_with_commands() -> ConnectedWithCommands {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[$version.quic_alpn()]);
                let (events, mut seen) = mpsc::unbounded_channel();
                let (commands, orders) = mpsc::unbounded_channel();

                let reply = setup_bytes();
                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");
                    run_enforcing_peer(conn, peer_rules(), reply, None, orders, events).await;
                    // `endpoint` is captured by this block and so lives to
                    // here; dropping it earlier would kill the session.
                });

                let outcome = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish");
                let conn = match outcome {
                    Ok(conn) => conn,
                    Err(e) => panic!(
                        "{}: connect failed with {e:?}; the peer reported {:?}",
                        $draft_label,
                        reported(&mut seen)
                    ),
                };
                (conn, peer, seen, commands)
            }

            /// An enforcing peer with nothing connected to it yet, for the
            /// gates that drive it with raw quinn rather than with the client
            /// under test.
            ///
            /// Gives back the address to connect to, the peer's task, the
            /// channel it reports on, and the channel it takes orders on.
            fn raw_peer() -> (
                std::net::SocketAddr,
                JoinHandle<()>,
                mpsc::UnboundedReceiver<PeerEvent>,
                mpsc::UnboundedSender<PeerCommand>,
            ) {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[$version.quic_alpn()]);
                let (events, seen) = mpsc::unbounded_channel();
                let (commands, orders) = mpsc::unbounded_channel();

                let reply = setup_bytes();
                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");
                    run_enforcing_peer(conn, peer_rules(), reply, None, orders, events).await;
                });
                (addr, peer, seen, commands)
            }

            /// Ask the peer to open a request stream toward the client under
            /// `label`, carrying `bytes`, and wait until it reports having
            /// done so.
            ///
            /// Waiting matters: the gates below assert on what the client does
            /// with a stream, and a test that raced ahead of the stream being
            /// opened would be asserting on nothing.
            async fn peer_opens_request_stream(
                commands: &mpsc::UnboundedSender<PeerCommand>,
                seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
                label: u64,
                bytes: Vec<u8>,
            ) {
                commands
                    .send(PeerCommand::OpenRequestStream { label, bytes })
                    .expect("the peer stopped taking commands");
                let sent = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(seen, |e| matches!(e, PeerEvent::RequestSentToClient(_))),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("{}: the peer never opened a request stream", $draft_label)
                });
                assert_eq!(
                    sent,
                    Some(PeerEvent::RequestSentToClient(label)),
                    "{}: the peer opened a stream for a request nobody asked for",
                    $draft_label
                );
            }

            /// Write more bytes on a stream the peer already opened.
            ///
            /// There is nothing to wait for: the peer reports only what the
            /// *client* does on that stream, and this is the peer speaking.
            fn peer_writes_on_request_stream(
                commands: &mpsc::UnboundedSender<PeerCommand>,
                label: u64,
                bytes: Vec<u8>,
            ) {
                commands
                    .send(PeerCommand::WriteOnRequestStream { label, bytes })
                    .expect("the peer stopped taking commands");
            }

            /// Wait for the client to close the session, and give back the
            /// code and reason phrase the peer read off the CONNECTION_CLOSE.
            ///
            /// `what` names the rule the client was supposed to be enforcing,
            /// for the panic when it closes nothing.
            async fn close_the_client_sent(
                seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
                what: &str,
            ) -> (u64, String) {
                let closed = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(seen, |e| {
                        matches!(e, PeerEvent::SessionClosedByClient { .. })
                    }),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{}: the client refused the {what} but never closed the session; \
                         a returned error is not a CONNECTION_CLOSE",
                        $draft_label
                    )
                });
                match closed {
                    Some(PeerEvent::SessionClosedByClient { code, reason }) => (code, reason),
                    other => panic!("{}: {other:?} is not a close", $draft_label),
                }
            }

            /// Read `what`'s answer off its own request stream, or panic
            /// naming what the peer made of the session.
            ///
            /// A client whose request went somewhere the peer refuses sees
            /// only quinn's "connection lost", which carries neither the close
            /// code nor a reason, so the peer's own report has to be in the
            /// message or a failure here says nothing about its cause.
            async fn answer_to(
                conn: &mut Connection,
                request: &mut RequestStream,
                seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
                what: &str,
            ) -> ControlMessage {
                let outcome = tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(request))
                    .await
                    .expect("the answer never arrived");
                match outcome {
                    Ok(answer) => answer,
                    Err(e) => panic!(
                        "{}: no answer to the {what} SUBSCRIBE: {e:?}; \
                         the peer reported {:?}",
                        $draft_label,
                        reported(seen)
                    ),
                }
            }

            /// The session completes: `connect` returns, the endpoint state
            /// machine reaches `Active`, and the peer reports that the SETUP
            /// it read came off a unidirectional stream.
            ///
            /// The peer would have closed the session with PROTOCOL_VIOLATION
            /// had the SETUP arrived on a bidirectional stream, which is what
            /// makes `Active` here mean the topology was right and not merely
            /// that some peer tolerated it.
            ///
            /// # What it catches
            ///
            /// Putting the control stream back on a bidirectional stream —
            /// `transport.open_bi()` in `Connection::connect`, with the
            /// control plane read back off the same stream — fails every draft
            /// here. Recorded when the file covered three; draft-20 fails it
            /// the same way, because its Section 3.3 is the same sentence:
            ///
            /// ```text
            /// draft-17: connect failed with Transport(Read("connection lost")); the peer reported Ok(ClosedBidiStream(12032))
            /// draft-18: connect failed with Transport(Read("connection lost")); the peer reported Ok(ClosedBidiStream(12032))
            /// draft-19: connect failed with Transport(Read("connection lost")); the peer reported Ok(ClosedBidiStream(12032))
            /// ```
            ///
            /// 12032 is 0x2F00, SETUP's message type: the peer read it off a
            /// bidirectional stream, found it was not a request message type,
            /// and closed the session. The client's own error is quinn's
            /// "connection lost" and says nothing about why, which is why the
            /// peer's report is in the message too.
            #[tokio::test]
            async fn session_completes_against_an_enforcing_peer() {
                let (conn, peer, mut seen) = connected().await;

                assert_eq!(
                    conn.endpoint().session_state(),
                    SessionState::Active,
                    "{} session should be active once SETUP has been exchanged",
                    $draft_label
                );
                assert_eq!(
                    conn.deferred_stream_count(),
                    0,
                    "the peer opened no data streams, so none should be held back"
                );
                assert_eq!(
                    seen.recv().await,
                    Some(PeerEvent::SetupOnUniStream),
                    "{}: the peer should have read SETUP off a unidirectional stream",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A request goes out on a bidirectional stream of its own and is
            /// answered there.
            ///
            /// This is the inverse of
            /// [`session_completes_against_an_enforcing_peer`]: that one says
            /// SETUP may not travel on a bidirectional stream, this one says a
            /// request may not travel on the control stream. The peer reads
            /// every message after SETUP on the client's control stream and
            /// closes the session with PROTOCOL_VIOLATION if one of them is a
            /// request type, so a SUBSCRIBE_OK arriving here means the
            /// SUBSCRIBE went where Section 3.3 puts it.
            ///
            /// # What it catches
            ///
            /// Writing the request on the control stream instead of on the
            /// bidirectional stream that was opened for it — `begin_request`
            /// in `draft18/connection.rs` writing to `self.control_send`
            /// rather than to the request stream's own send half — fails
            /// draft-18's copy of this and of the three request gates below
            /// it. All four carry the peer's own account of the session, in
            /// one of two forms:
            ///
            /// ```text
            /// draft-18: no answer to the only SUBSCRIBE: Transport(Read("connection lost")); the peer reported [SetupOnUniStream, ClosedControlStream(3)]
            /// draft-18: no answer to the first SUBSCRIBE: Transport(Read("connection lost")); the peer reported [SetupOnUniStream, ClosedControlStream(3)]
            /// ```
            ///
            /// 3 is SUBSCRIBE's message type: the peer read it off the
            /// control stream, found a request where Section 3.3 does not
            /// allow one, and closed the session. The client's own error is
            /// quinn's "connection lost" and names neither the close code nor
            /// a reason, which is why the peer's report is in the message too
            /// — see [`answer_to`].
            #[tokio::test]
            async fn a_request_completes_on_its_own_bidirectional_stream() {
                let (mut conn, peer, mut seen) = connected().await;

                let request = tokio::time::timeout(
                    PATIENCE,
                    conn.subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new()),
                )
                .await
                .expect("subscribe did not finish");
                let mut request = match request {
                    Ok(request) => request,
                    Err(e) => panic!(
                        "{}: subscribe failed with {e:?}; the peer reported {:?}",
                        $draft_label,
                        reported(&mut seen)
                    ),
                };

                let answer = answer_to(&mut conn, &mut request, &mut seen, "only").await;
                assert_eq!(
                    mark_of(&answer),
                    MARK_ONE,
                    "{}: the answer should be the one this request asked for",
                    $draft_label
                );

                assert_eq!(
                    wait_for_event(&mut seen, |e| matches!(e, PeerEvent::RequestOnBidiStream(_)))
                        .await,
                    Some(PeerEvent::RequestOnBidiStream(subscribe_request(
                        request.request_id().into_inner(),
                        &namespace(),
                        TRACK_ONE,
                        0,
                    ))),
                    "{}: the peer should have seen the SUBSCRIBE lead a bidirectional stream",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// Two requests in flight at once are each answered on their own
            /// stream.
            ///
            /// Draft-17 responses carry no request id, so "a response
            /// arrived" says nothing about which request it answers. Two
            /// things make this a real test of the correlation:
            ///
            /// * the answers carry different marks, taken from the track name
            ///   each request asked for, so an answer read off the wrong
            ///   stream is visible; and
            /// * the peer answers the **second** request first. The first
            ///   request's answer is read first, while the second's is
            ///   already sitting in the connection, so an implementation that
            ///   handed back whichever answer arrived first would return
            ///   [`MARK_TWO`] here.
            ///
            /// The ablation recorded on
            /// [`a_request_completes_on_its_own_bidirectional_stream`] fails
            /// this one too.
            #[tokio::test]
            async fn two_requests_are_answered_on_their_own_streams() {
                let (mut conn, peer, mut seen) = connected().await;

                let mut first = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .expect("first subscribe");
                let mut second = conn
                    .subscribe(namespace(), TRACK_TWO.to_vec(), Vec::new())
                    .await
                    .expect("second subscribe");
                assert_ne!(
                    first.stream_id(),
                    second.stream_id(),
                    "{}: each request needs a bidirectional stream of its own",
                    $draft_label
                );

                // Read the request that is answered last first. Its answer is
                // still RESPONSE_STAGGER away, and the other request's answer
                // has already arrived.
                let first_answer = answer_to(&mut conn, &mut first, &mut seen, "first").await;
                assert_eq!(
                    mark_of(&first_answer),
                    MARK_ONE,
                    "{}: the first request was handed the answer to the second",
                    $draft_label
                );

                let second_answer = answer_to(&mut conn, &mut second, &mut seen, "second").await;
                assert_eq!(
                    mark_of(&second_answer),
                    MARK_TWO,
                    "{}: the second request was handed the answer to the first",
                    $draft_label
                );

                // The two assertions above only mean something if the answers
                // really did arrive in the opposite order to the requests, so
                // the peer is held to that as well. Were it to answer in
                // arrival order, reading the answers in arrival order would
                // pass no matter how the client correlated them.
                let mut answered = Vec::new();
                for _ in 0..2 {
                    answered.push(
                        tokio::time::timeout(
                            PATIENCE,
                            wait_for_event(&mut seen, |e| {
                                matches!(e, PeerEvent::AnsweredRequest(_))
                            }),
                        )
                        .await
                        .expect("the peer never reported answering"),
                    );
                }
                assert_eq!(
                    answered,
                    vec![
                        Some(PeerEvent::AnsweredRequest(MARK_TWO)),
                        Some(PeerEvent::AnsweredRequest(MARK_ONE)),
                    ],
                    "{}: the peer should have answered the second request first",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A second track answered with a live track's Track Alias ends
            /// the session, and the peer reads the code off the wire.
            ///
            /// Drafts 18, 19 and 20 Section 11.1, in the same words on all
            /// three: "The same Track Alias MUST NOT be used by a publisher to
            /// refer to two different Tracks simultaneously in the same
            /// session. If a subscriber receives a PUBLISH or SUBSCRIBE_OK
            /// that uses the same Track Alias as a different Track with an
            /// Established subscription, it MUST close the session with error
            /// DUPLICATE_TRACK_ALIAS." Draft-17 Section 9.9 states the
            /// SUBSCRIBE_OK half of that on its own.
            ///
            /// The peer needs no arrangement to break it. It answers every
            /// SUBSCRIBE with the digit the track name ends in, so a
            /// subscription to [`CLASHING_TRACK`] beside one to [`TRACK_ONE`]
            /// is answered with the alias the first one already holds.
            ///
            /// The first answer is read and accepted before the second is
            /// asked for, which is what makes the second one the violation
            /// rather than the pair: a client that refused both would satisfy
            /// a gate built on the second alone.
            ///
            /// # Why the code is read and not just the close
            ///
            /// PROTOCOL_VIOLATION answers most of the neighbouring rules on
            /// these drafts and this one answers to a number of its own.
            /// A gate that observed only that the session ended would pass
            /// with either, and which rule was broken is the whole of what the
            /// peer is being told.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `conflicting_alias_for_subscribe_ok` call from
            /// `receive_subscribe_ok`:
            ///
            /// ```text
            /// draft-19: the second answer reused a live track's alias and was accepted
            /// ```
            #[tokio::test]
            async fn one_alias_for_two_tracks_closes_the_session() {
                let (mut conn, peer, mut seen) = connected().await;

                let mut first = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .expect("first subscribe");
                let first_answer = answer_to(&mut conn, &mut first, &mut seen, "first").await;
                assert_eq!(
                    mark_of(&first_answer),
                    MARK_ONE,
                    "{}: the first subscription has to be established before the \
                     second can collide with it",
                    $draft_label
                );

                let mut second = conn
                    .subscribe(namespace(), CLASHING_TRACK.to_vec(), Vec::new())
                    .await
                    .expect("second subscribe");
                let outcome =
                    tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut second))
                        .await
                        .expect("the second answer never arrived");
                assert!(
                    outcome.is_err(),
                    "{}: the second answer reused a live track's alias and was accepted",
                    $draft_label
                );

                let (code, reason) =
                    close_the_client_sent(&mut seen, "second SUBSCRIBE_OK").await;
                assert_eq!(
                    code,
                    DUPLICATE_TRACK_ALIAS,
                    "{}: the close should carry DUPLICATE_TRACK_ALIAS and carried {code}",
                    $draft_label
                );
                assert!(
                    reason.contains("track alias"),
                    "{}: the close reason should name the rule that was broken; \
                     got {reason:?}",
                    $draft_label
                );

                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// Cancelling a request resets its stream, and the code the
            /// caller chose is the one the peer reads off the wire.
            ///
            /// Draft-17 removed UNSUBSCRIBE and FETCH_CANCEL, so this reset
            /// is the whole of the cancellation. The answer is read first, so
            /// the peer has certainly taken the request off the stream before
            /// the reset arrives and cannot mistake one for the other.
            ///
            /// [`CHOSEN_CANCEL_CODE`] is deliberately not the code a dropped
            /// handle sends: the same assertion against [`CANCELLED`] would
            /// hold even if `cancel` ignored its argument.
            ///
            /// The ablation recorded on
            /// [`a_request_completes_on_its_own_bidirectional_stream`] fails
            /// this one too: a request that never reached a bidirectional
            /// stream has no stream to reset.
            #[tokio::test]
            async fn cancelling_a_request_resets_its_stream() {
                let (mut conn, peer, mut seen) = connected().await;

                let mut request = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .expect("subscribe");
                let _ = answer_to(&mut conn, &mut request, &mut seen, "only").await;

                request.cancel(CHOSEN_CANCEL_CODE).expect("cancel");

                let reset = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| matches!(e, PeerEvent::RequestStreamReset(_))),
                )
                .await
                .expect("the peer never saw the request stream reset");
                assert_eq!(
                    reset,
                    Some(PeerEvent::RequestStreamReset(CHOSEN_CANCEL_CODE)),
                    "{}: cancelling must reset the request stream with the chosen code",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// Dropping a request stream cancels the request rather than
            /// ending it cleanly.
            ///
            /// The default drop of a quinn send stream sends a FIN, which
            /// tells the peer the request finished. What the peer must see
            /// instead is a reset carrying [`CANCELLED`] — the difference
            /// between a subscription that ran its course and one the caller
            /// walked away from.
            ///
            /// The ablation recorded on
            /// [`a_request_completes_on_its_own_bidirectional_stream`] fails
            /// this one too.
            #[tokio::test]
            async fn dropping_a_request_stream_cancels_the_request() {
                let (mut conn, peer, mut seen) = connected().await;

                let mut request = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .expect("subscribe");
                let _ = answer_to(&mut conn, &mut request, &mut seen, "only").await;

                drop(request);

                let reset = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| matches!(e, PeerEvent::RequestStreamReset(_))),
                )
                .await
                .expect("the peer never saw the request stream reset");
                assert_eq!(
                    reset,
                    Some(PeerEvent::RequestStreamReset(CANCELLED)),
                    "{}: a dropped request stream must be reset as CANCELLED, not finished",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// Wait until the peer has read a request off a bidirectional
            /// stream of its own.
            ///
            /// A cancel discards whatever the stream had not yet put on the
            /// wire, so a test that reset the stream the instant it opened it
            /// would be racing its own request: the peer would see a stream
            /// that was reset before its first varint arrived, which is not the
            /// withdrawal of a request it ever received.
            async fn peer_read_a_request(seen: &mut mpsc::UnboundedReceiver<PeerEvent>) {
                tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(seen, |e| matches!(e, PeerEvent::RequestOnBidiStream(_))),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("{}: the peer never read the request", $draft_label)
                });
            }

            /// The SUBSCRIBE_OK this draft's endpoint takes, for the gates
            /// that hand one to the endpoint rather than to the wire.
            fn subscribe_ok() -> SubscribeOk {
                SubscribeOk {
                    track_alias: VarInt::from_u64_moqt(1),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                }
            }

            /// Cancelling through the connection resets the stream **and**
            /// ends the request in the endpoint.
            ///
            /// The reset half is what `cancelling_a_request_resets_its_stream`
            /// already asserts. The half that is this gate's own is the second
            /// one: an answer arriving afterwards is refused, because the
            /// request it would answer is over. `RequestStream::cancel` on its
            /// own leaves that answer acceptable, which is the whole reason
            /// this method exists rather than the handle's.
            ///
            /// The subscription is cancelled **before** it has been answered,
            /// which is the state a request stream is in for as long as the
            /// peer takes to reply. Section 3.3.1 and its equivalents put the
            /// cancel from the moment the stream is open.
            ///
            /// # Ablation, run
            ///
            /// Leaving `Connection::cancel_request_stream` on draft-17 with
            /// nothing but the `RequestStream::cancel` it wraps, so the stream
            /// is reset and the endpoint hears nothing. The reset half of this
            /// gate still passes; the second half is what fails:
            ///
            /// ```text
            /// draft-17: a SUBSCRIBE_OK answering a cancelled request must be
            /// refused, got Ok(())
            /// ```
            #[tokio::test]
            async fn cancelling_a_request_records_it_at_the_endpoint() {
                let (mut conn, peer, mut seen) = connected().await;

                let mut request = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .expect("subscribe");
                let id = request.request_id();
                peer_read_a_request(&mut seen).await;

                conn.cancel_request_stream(&mut request, CHOSEN_CANCEL_CODE)
                    .expect("a request that has not been answered yet can be cancelled");

                let reset = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| matches!(e, PeerEvent::RequestStreamReset(_))),
                )
                .await
                .expect("the peer never saw the request stream reset");
                assert_eq!(
                    reset,
                    Some(PeerEvent::RequestStreamReset(CHOSEN_CANCEL_CODE)),
                    "{}: cancelling through the connection must still reset the stream",
                    $draft_label
                );

                let late = conn.endpoint_mut().receive_subscribe_ok(id, &subscribe_ok());
                assert!(
                    late.is_err(),
                    "{}: a SUBSCRIBE_OK answering a cancelled request must be refused, \
                     got {late:?}",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A dropped handle resets the stream and tells the endpoint
            /// nothing.
            ///
            /// [`Drop`] holds the stream and not the session, so this is what
            /// it can do and the limit of it. Asserted rather than left
            /// unwritten: it is the reason
            /// `cancelling_a_request_records_it_at_the_endpoint` has a method
            /// of its own to gate, and a change that made a drop record the
            /// cancel would be a change worth noticing here.
            #[tokio::test]
            async fn dropping_a_request_stream_leaves_the_endpoints_record() {
                let (mut conn, peer, mut seen) = connected().await;

                let request = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .expect("subscribe");
                let id = request.request_id();
                peer_read_a_request(&mut seen).await;
                drop(request);

                let reset = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| matches!(e, PeerEvent::RequestStreamReset(_))),
                )
                .await
                .expect("the peer never saw the request stream reset");
                assert_eq!(
                    reset,
                    Some(PeerEvent::RequestStreamReset(CANCELLED)),
                    "{}: a dropped request stream must still reset as cancelled",
                    $draft_label
                );

                let late = conn.endpoint_mut().receive_subscribe_ok(id, &subscribe_ok());
                assert!(
                    late.is_ok(),
                    "{}: a drop cannot reach the endpoint, so the request is still open \
                     there; got {late:?}",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A peer that resets a request stream cancels the request on it,
            /// and the read that finds the reset records that.
            ///
            /// Section 3.3.1 and its equivalents give the cancel to either
            /// endpoint. This is the other one: the peer opened a request
            /// stream, this endpoint owes it an answer, and the peer withdraws
            /// it. The read fails with the peer's own code — the caller has to
            /// see that rather than a state error — and the response this
            /// endpoint owed is refused afterwards.
            ///
            /// # Ablation, run
            ///
            /// Dropping the `StreamReset` arm from draft-18's
            /// `recv_on_request_stream`, so the read still reports the peer's
            /// code and the endpoint still believes the request is live:
            ///
            /// ```text
            /// draft-18: the answer owed on a request the peer withdrew must
            /// be refused, got Ok(())
            /// ```
            #[tokio::test]
            async fn a_peers_reset_records_the_cancel() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    peer_subscribe_bytes(PEER_REQUEST_ID),
                )
                .await;

                let (_, mut inbound) = tokio::time::timeout(
                    PATIENCE,
                    conn.accept_request_stream(),
                )
                .await
                .expect("the peer's request never arrived")
                .expect("accepting the peer's request");
                let id = inbound.request_id();

                commands
                    .send(PeerCommand::CancelRequest {
                        label: PEER_REQUEST_ID,
                        code: CHOSEN_CANCEL_CODE,
                    })
                    .expect("the peer stopped taking commands");

                let read =
                    tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut inbound))
                        .await
                        .expect("the read never ended");
                assert!(
                    matches!(
                        read,
                        Err(ConnectionError::Transport(TransportError::StreamReset(code)))
                            if code == CHOSEN_CANCEL_CODE
                    ),
                    "{}: a read on a stream the peer reset must carry the peer's code, \
                     got {read:?}",
                    $draft_label
                );

                let owed = conn
                    .endpoint_mut()
                    .send_response_on_stream(id, &ControlMessage::SubscribeOk(subscribe_ok()));
                assert!(
                    owed.is_err(),
                    "{}: the answer owed on a request the peer withdrew must be refused, \
                     got {owed:?}",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A caller waiting on the peer's cancel instead of reading records
            /// it too.
            ///
            /// A responder applying backpressure is deliberately not reading,
            /// so the read path above never runs for it. Without this the
            /// request would end on the wire and stay open in the endpoint for
            /// as long as the backpressure lasted.
            ///
            /// # Ablation, run
            ///
            /// Dropping the record from draft-19's
            /// `peer_cancelled_on_request_stream`, so it becomes the handle's
            /// own wait under a longer name. The code it reports is still
            /// right, and only the record is missing:
            ///
            /// ```text
            /// draft-19: the answer owed on a request the peer withdrew must
            /// be refused, got Ok(())
            /// ```
            #[tokio::test]
            async fn waiting_for_the_peers_cancel_records_it() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    peer_subscribe_bytes(PEER_REQUEST_ID),
                )
                .await;

                let (_, mut inbound) = tokio::time::timeout(
                    PATIENCE,
                    conn.accept_request_stream(),
                )
                .await
                .expect("the peer's request never arrived")
                .expect("accepting the peer's request");
                let id = inbound.request_id();

                commands
                    .send(PeerCommand::CancelRequest {
                        label: PEER_REQUEST_ID,
                        code: CHOSEN_CANCEL_CODE,
                    })
                    .expect("the peer stopped taking commands");

                let waited = tokio::time::timeout(
                    PATIENCE,
                    conn.peer_cancelled_on_request_stream(&mut inbound),
                )
                .await
                .expect("the wait never ended")
                .expect("waiting for a peer cancel is not itself an error");
                assert_eq!(
                    waited,
                    Some(CHOSEN_CANCEL_CODE),
                    "{}: the wait must report the code the peer reset with",
                    $draft_label
                );

                let owed = conn
                    .endpoint_mut()
                    .send_response_on_stream(id, &ControlMessage::SubscribeOk(subscribe_ok()));
                assert!(
                    owed.is_err(),
                    "{}: the answer owed on a request the peer withdrew must be refused, \
                     got {owed:?}",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A data stream that reaches the client before the peer's
            /// control stream is kept, not discarded.
            ///
            /// Section 3.3 allows it: "Unidirectional streams containing
            /// Objects ... could arrive prior to the control streams". The
            /// search for the control stream therefore has to look past it,
            /// and what it looks past must still come out of
            /// `accept_subgroup_stream` afterwards — with the type varint the
            /// search read still on the front, or the header would not
            /// decode.
            ///
            /// The ordering is not a race. The peer writes the data stream
            /// before it accepts anything, and opens its own control stream
            /// only after it has read the client's SETUP — a full round trip
            /// later — so the data stream is always the first unidirectional
            /// stream the client sees.
            #[tokio::test]
            async fn a_data_stream_ahead_of_the_control_stream_is_kept() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[$version.quic_alpn()]);
                let (events, mut seen) = mpsc::unbounded_channel();

                let reply = setup_bytes();
                let early = subgroup_stream_bytes();
                let (_commands, orders) = mpsc::unbounded_channel();
                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");
                    run_enforcing_peer(conn, peer_rules(), reply, Some(early), orders, events)
                        .await;
                });

                let conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                assert_eq!(
                    conn.endpoint().session_state(),
                    SessionState::Active,
                    "{}: a data stream in front of the control stream must not \
                     stop the handshake",
                    $draft_label
                );
                assert_eq!(
                    conn.deferred_stream_count(),
                    1,
                    "{}: the data stream should have been set aside",
                    $draft_label
                );

                let (header, _stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("accept_subgroup_stream did not finish")
                        .expect("accept_subgroup_stream");
                match header {
                    AnySubgroupHeader::$variant(header) => {
                        assert_eq!(header.track_alias.into_inner(), EARLY_TRACK_ALIAS);
                        assert_eq!(header.group_id.into_inner(), EARLY_GROUP_ID);
                    }
                    // A build enabling one draft leaves this catch-all nothing to match.
                    #[allow(unreachable_patterns)]
                    other => panic!("{}: wrong draft's header: {other:?}", $draft_label),
                }
                assert_eq!(
                    conn.deferred_stream_count(),
                    0,
                    "{}: the set-aside stream should have been handed back once",
                    $draft_label
                );
                assert_eq!(seen.recv().await, Some(PeerEvent::SetupOnUniStream));

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// **Every** request helper opens a bidirectional stream of its
            /// own, not just [`Connection::subscribe`].
            ///
            /// One helper's worth of coverage says nothing about the other
            /// six: each opens its own stream in its own body, and a helper
            /// that wrote its request on the control stream instead would
            /// leave the rest of this file green. So this walks the whole set
            /// the draft names — the six of draft-17 Section 3.3, and on
            /// drafts 18, 19 and 20 the seventh, SUBSCRIBE_TRACKS — and
            /// requires the peer to report each one arriving alone at the
            /// front of a bidirectional stream.
            ///
            /// The check is on the peer's side and on the request the peer
            /// **decoded**, so three separable mistakes fail here: the wrong
            /// stream, the wrong message on the right stream, and the right
            /// message asking for the wrong thing.
            ///
            /// That third one is why the assertion is not on a message type.
            /// A helper that wrote a FETCH with the other Fetch Type, or
            /// named another track, or dropped the caller's parameters, has
            /// written a well-formed request of exactly the expected type.
            /// Every request here therefore carries a parameter of the
            /// caller's — see [`attached`] — and every field a caller chooses
            /// is in the rendering.
            ///
            /// Requests go out one at a time, each waited for before the next
            /// is made, so the peer's reports arrive in a known order and
            /// name the helper that caused them.
            ///
            /// The walk is over helpers rather than over messages, which is
            /// why FETCH appears more than once: on drafts 17, 18 and 19 a
            /// standalone fetch, a relative joining fetch and an absolute one
            /// are three bodies that each open a stream of their own, and one
            /// written later would be a fourth place to get it wrong. On
            /// draft-20 those three helpers are two — `fetch` and
            /// `fetch_range` — and the joining pair is replaced by a SUBSCRIBE
            /// carrying `FILL_PARAMETERS`, which is what Section 5.1.3 turned
            /// "give me what I missed" into. The set is per draft, so it lives
            /// in `$fetch_requests` rather than here.
            ///
            /// # What it catches
            ///
            /// Draft-17's `absolute_joining_fetch` left calling the
            /// endpoint's *relative* builder. **This cut reddened nothing at
            /// all until the peer decoded what it was sent** — it was made
            /// once before, against this very sweep, and passed:
            ///
            /// ```text
            /// assertion `left == right` failed: draft-17: the absolute joining FETCH must arrive alone at the front of a bidirectional stream of its own, and must be the request the helper was asked for
            ///   left: Some(RequestOnBidiStream("FETCH 0x16 request id=6 fetch type=2 joining request id=0 joining start=9 parameters=1"))
            ///  right: Some(RequestOnBidiStream("FETCH 0x16 request id=6 fetch type=3 joining request id=0 joining start=9 parameters=1"))
            /// ```
            ///
            /// And draft-19's `subscribe_tracks` writing its request on the
            /// control stream as well as on its own stream — the mistake the
            /// rest of this file cannot see:
            ///
            /// ```text
            /// assertion `left == right` failed: draft-19: the SUBSCRIBE_TRACKS must arrive alone at the front of a bidirectional stream of its own, and must be the request the helper was asked for
            ///   left: Some(ClosedControlStream(81))
            ///  right: Some(RequestOnBidiStream("SUBSCRIBE_TRACKS 0x51 request id=16 prefix=uni-control-plane parameters=1"))
            /// ```
            ///
            /// 81 is 0x51, SUBSCRIBE_TRACKS: the peer found a request on the
            /// control stream and closed the session. That cut has to write
            /// on the control stream directly, because `send_control` refuses
            /// a request message — which is the guard
            /// `send_control_refuses_a_request_and_writes_nothing` is about,
            /// and the reason the obvious form of this ablation is a no-op.
            #[tokio::test]
            async fn every_request_helper_opens_its_own_stream() {
                let (mut conn, peer, mut seen) = connected().await;

                // Every handle is held to the end. Dropping one resets its
                // stream, and the peer reports that reset, which would put
                // events between the ones being asserted on here.
                let mut held: Vec<RequestStream> = Vec::new();

                // The expectation is a closure over the Request ID the
                // helper allocated: the id is part of what arrived and is
                // not known until the call has returned.
                macro_rules! request {
                    ($what:literal, $call:expr, $expected:expr) => {{
                        let outcome =
                            tokio::time::timeout(PATIENCE, $call).await.unwrap_or_else(|_| {
                                panic!("{}: {} did not finish", $draft_label, $what)
                            });
                        let stream = outcome.unwrap_or_else(|e| {
                            panic!(
                                "{}: {} failed with {e:?}; the peer reported {:?}",
                                $draft_label,
                                $what,
                                reported(&mut seen)
                            )
                        });
                        let expected = $expected;
                        let expected = expected(stream.request_id().into_inner());
                        saw_request(&mut seen, $draft_label, $what, &expected).await;
                        held.push(stream);
                    }};
                }

                request!(
                    "SUBSCRIBE",
                    conn.subscribe(namespace(), TRACK_ONE.to_vec(), vec![attached()]),
                    |id| subscribe_request(id, &namespace(), TRACK_ONE, 1)
                );

                // The fetch helpers, which are not one set across the range —
                // draft-20 Section 10.13 deleted the Fetch Type field and both
                // joining helpers — so they are made by a per-draft function
                // rather than here, in the position they occupied when they
                // were. It runs immediately after the SUBSCRIBE because the
                // joining FETCHes of drafts 17, 18 and 19 name that
                // subscription's Request ID, which it reads off `held[0]`.
                $fetch_requests(&mut conn, &mut held, &mut seen).await;

                request!(
                    "PUBLISH_NAMESPACE",
                    conn.publish_namespace(namespace(), vec![attached()]),
                    |id| publish_namespace_request(id, &namespace(), 1)
                );
                request!(
                    "TRACK_STATUS",
                    conn.track_status(namespace(), TRACK_ONE.to_vec(), vec![attached()]),
                    |id| track_status_request(id, &namespace(), TRACK_ONE, 1)
                );
                request!(
                    "PUBLISH",
                    conn.publish(
                        namespace(),
                        TRACK_ONE.to_vec(),
                        VarInt::from_u64_moqt(7),
                        vec![attached()],
                        Vec::new(),
                    ),
                    |id| publish_request(id, &namespace(), TRACK_ONE, 7, 1, 0)
                );

                // The namespace requests differ across the range — draft-17's
                // SUBSCRIBE_NAMESPACE carries a `subscribe_options` field that
                // drafts 18, 19 and 20 split out into SUBSCRIBE_TRACKS — so
                // they are made by a per-draft function rather than here.
                $namespace_requests(&mut conn, &mut held, &mut seen).await;

                drop(held);
                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// `send_control` refuses a request message and writes nothing.
            ///
            /// Section 3.3 gives requests streams of their own, so a request
            /// handed to the control-stream writer is a mistake with a wire
            /// consequence: an enforcing peer that saw it would close the
            /// session with PROTOCOL_VIOLATION. The refusal is therefore not
            /// checked by reading the error alone — a SUBSCRIBE is made
            /// afterwards and its answer read, and that answer can only come
            /// back on a session the peer did not close.
            ///
            /// # What it catches
            ///
            /// Deleting the `starts_a_request_stream` guard from
            /// `send_control`, so the TRACK_STATUS reaches the control stream:
            ///
            /// ```text
            /// draft-17: send_control must refuse a request message, got Ok(())
            /// ```
            ///
            /// and, with the guard's error kept but moved after the write so
            /// the bytes still go out, the session is gone by the time the
            /// SUBSCRIBE would be answered:
            ///
            /// ```text
            /// draft-17: no answer to the only SUBSCRIBE: Transport(Read("connection lost")); the peer reported [SetupOnUniStream, RequestOnBidiStream(3), ClosedControlStream(13)]
            /// ```
            ///
            /// 13 is 0x0D, TRACK_STATUS: the peer took the SUBSCRIBE on its
            /// own stream (3) and then found the TRACK_STATUS on the control
            /// stream and closed the session. That second form is why the
            /// error alone is not enough — it is the half of the guard that
            /// says **nothing was written**.
            #[tokio::test]
            async fn send_control_refuses_a_request_and_writes_nothing() {
                let (mut conn, peer, mut seen) = connected().await;

                let outcome = conn.send_control(&$stray_request).await;
                match outcome {
                    Err(ConnectionError::RequestOnControlStream(ty)) => assert_eq!(
                        ty.id(),
                        TRACK_STATUS_TYPE,
                        "{}: the refusal should name the type it refused",
                        $draft_label
                    ),
                    other => panic!(
                        "{}: send_control must refuse a request message, got {other:?}",
                        $draft_label
                    ),
                }

                // Nothing was written, so the session is intact and a request
                // made the right way is still answered.
                let mut request = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: subscribe after the refusal failed with {e:?}; \
                             the peer reported {:?}",
                            $draft_label,
                            reported(&mut seen)
                        )
                    });
                let answer = answer_to(&mut conn, &mut request, &mut seen, "only").await;
                assert_eq!(
                    mark_of(&answer),
                    MARK_ONE,
                    "{}: the answer should be the one this request asked for",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// An observer can tell a request stream from the control stream.
            ///
            /// A response on these drafts carries no request id, so a trace
            /// that recorded only the message would show a SUBSCRIBE_OK with
            /// nothing to say which SUBSCRIBE it answers. Two things fix that
            /// and both are asserted here: the bidirectional stream a request
            /// opens is announced as [`StreamKind::Request`], and every
            /// control message carries the stream it travelled on —
            /// `Some(id)` on a request stream, `None` on the control stream.
            ///
            /// The control-stream half comes from the handshake events
            /// `set_observer` replays, which are the SETUP exchange and are
            /// on the control stream by construction.
            ///
            /// # What it catches
            ///
            /// Emitting `stream_id: None` in `begin_request`:
            ///
            /// ```text
            /// draft-17: the SUBSCRIBE should be reported on the stream it went out on; the observer saw [StreamOpened(Request, 0), ControlMessage(Send, None)]
            /// ```
            ///
            /// Dropping the `StreamOpened` emission from `begin_request`:
            ///
            /// ```text
            /// draft-17: the request stream should have been announced as a request stream; the observer saw [ControlMessage(Send, Some(0))]
            /// ```
            #[tokio::test]
            async fn an_observer_sees_which_stream_a_control_message_used() {
                use moqtap_client::$draft_mod::event::{ClientEvent, Direction, StreamKind};
                use moqtap_client::$draft_mod::observer::ConnectionObserver;
                use std::sync::{Arc, Mutex};

                /// One line per event, in the order the connection emitted
                /// them. Only the two kinds this gate is about are recorded.
                #[derive(Debug, PartialEq, Eq)]
                enum Seen {
                    StreamOpened(StreamKind, u64),
                    ControlMessage(Direction, Option<u64>),
                }

                struct Recorder(Arc<Mutex<Vec<Seen>>>);

                impl ConnectionObserver for Recorder {
                    fn on_event(&self, event: &ClientEvent) {
                        let line = match event {
                            ClientEvent::StreamOpened { stream_kind, stream_id, .. } => {
                                Seen::StreamOpened(*stream_kind, *stream_id)
                            }
                            ClientEvent::ControlMessage { direction, stream_id, .. } => {
                                Seen::ControlMessage(*direction, *stream_id)
                            }
                            _ => return,
                        };
                        self.0.lock().expect("recorder lock").push(line);
                    }
                }

                let (mut conn, peer, mut seen) = connected().await;
                let log = Arc::new(Mutex::new(Vec::new()));
                conn.set_observer(Box::new(Recorder(log.clone())));

                // The replayed handshake: SETUP out and SETUP back, both on
                // the control stream and so both without a stream id.
                {
                    let recorded = log.lock().expect("recorder lock");
                    let control: Vec<&Seen> = recorded
                        .iter()
                        .filter(|line| matches!(line, Seen::ControlMessage(..)))
                        .collect();
                    assert_eq!(
                        control,
                        vec![
                            &Seen::ControlMessage(Direction::Send, None),
                            &Seen::ControlMessage(Direction::Receive, None),
                        ],
                        "{}: the SETUP exchange is on the control stream and carries no \
                         stream id; the observer saw {recorded:?}",
                        $draft_label
                    );
                }
                log.lock().expect("recorder lock").clear();

                let mut request = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: subscribe failed with {e:?}; the peer reported {:?}",
                            $draft_label,
                            reported(&mut seen)
                        )
                    });
                let sid = request.stream_id();
                let _ = answer_to(&mut conn, &mut request, &mut seen, "only").await;

                // Taken out of the mutex rather than read through the guard,
                // so nothing is held across the awaits that end this test.
                let recorded = std::mem::take(&mut *log.lock().expect("recorder lock"));
                assert!(
                    recorded.contains(&Seen::StreamOpened(StreamKind::Request, sid)),
                    "{}: the request stream should have been announced as a request \
                     stream; the observer saw {recorded:?}",
                    $draft_label
                );
                assert!(
                    recorded.contains(&Seen::ControlMessage(Direction::Send, Some(sid))),
                    "{}: the SUBSCRIBE should be reported on the stream it went out on; \
                     the observer saw {recorded:?}",
                    $draft_label
                );
                assert!(
                    recorded.contains(&Seen::ControlMessage(Direction::Receive, Some(sid))),
                    "{}: the answer should be reported on the stream it came back on; \
                     the observer saw {recorded:?}",
                    $draft_label
                );
                assert!(
                    !recorded
                        .iter()
                        .any(|line| line == &Seen::ControlMessage(Direction::Send, None)
                            || line == &Seen::ControlMessage(Direction::Receive, None)),
                    "{}: nothing in a request exchange belongs on the control stream; \
                     the observer saw {recorded:?}",
                    $draft_label
                );

                drop(request);
                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A request the **peer** opens a stream with is accepted and
            /// answered on that same stream.
            ///
            /// Section 3.3 lets either endpoint open a request stream, so this
            /// is the mirror of
            /// [`a_request_completes_on_its_own_bidirectional_stream`] and the
            /// only gate in this file that exercises the client as a
            /// responder.
            ///
            /// Three separate things have to be right and each is asserted on
            /// its own:
            ///
            /// * the request is *taken* — `accept_request_stream` hands back
            ///   the peer's SUBSCRIBE, with the Request ID the peer chose and a
            ///   handle that knows the peer opened it;
            /// * the answer goes out on **that stream**. The peer reads it off
            ///   the receive half of the stream it opened, which nothing
            ///   written anywhere else can reach, and the Track Alias echoes
            ///   the Request ID so the peer can say the answer belongs to the
            ///   request it made; and
            /// * abandoning the handle afterwards resets that stream with
            ///   [`UNANSWERED`] and not with the [`CANCELLED`] that
            ///   [`dropping_a_request_stream_cancels_the_request`] sees on a
            ///   stream this endpoint opened. A peer cannot tell "I gave up on
            ///   your request" from "I withdrew mine" if both codes are the
            ///   same number.
            ///
            /// # What it catches
            ///
            /// Making the accept path never take a peer-opened stream —
            /// `std::future::pending::<()>().await` in place of the
            /// `self.transport.accept_bi()` in draft-17's
            /// `accept_request_stream` — fails this and the three responder
            /// gates below it, and nothing else in the file:
            ///
            /// ```text
            /// thread 'draft17::a_peers_request_is_answered_on_the_stream_it_arrived_on' (38500) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2714:1:
            /// draft-17: the client never accepted the request the peer opened a stream with
            /// thread 'draft17::an_inbound_request_is_served_while_an_outbound_one_is_in_flight' (13992) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2714:1:
            /// draft-17: the client never accepted the peer's request while one of its own was outstanding
            /// thread 'draft17::a_peer_request_id_with_our_own_parity_closes_the_session' (31456) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2714:1:
            /// draft-17: the accept never reached a verdict
            /// thread 'draft17::a_stream_that_opens_no_request_closes_the_session' (41532) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2714:1:
            /// draft-17: the accept never reached a verdict
            /// ```
            ///
            /// The line number is draft-17's macro invocation site and moves
            /// whenever this file is edited; the messages are what identify
            /// the failures.
            #[tokio::test]
            async fn a_peers_request_is_answered_on_the_stream_it_arrived_on() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    peer_subscribe_bytes(PEER_REQUEST_ID),
                )
                .await;

                let accepted = tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "{}: the client never accepted the request the peer opened a \
                             stream with",
                            $draft_label
                        )
                    });
                let (request, mut inbound) = accepted.unwrap_or_else(|e| {
                    panic!(
                        "{}: accepting the peer's request failed with {e:?}; \
                         the peer reported {:?}",
                        $draft_label,
                        reported(&mut seen)
                    )
                });

                assert_eq!(
                    subscribe_id(&request),
                    PEER_REQUEST_ID,
                    "{}: the accepted request should be the one the peer sent",
                    $draft_label
                );
                assert_eq!(
                    inbound.request_id().into_inner(),
                    PEER_REQUEST_ID,
                    "{}: the handle should be keyed to the Request ID on the wire",
                    $draft_label
                );
                assert_eq!(
                    inbound.origin(),
                    RequestOrigin::Peer,
                    "{}: a stream the peer opened is one this endpoint owes an answer on",
                    $draft_label
                );

                conn.respond_subscribe_ok(&mut inbound, answer_for(PEER_REQUEST_ID))
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: answering the peer's SUBSCRIBE failed with {e:?}; \
                             the peer reported {:?}",
                            $draft_label,
                            reported(&mut seen)
                        )
                    });

                // Whichever place the answer went, the first of these two is
                // where it went; there is no window in which both could be
                // reported and the wrong one read.
                let landed = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| {
                        matches!(
                            e,
                            PeerEvent::ClientAnsweredOnRequestStream { .. }
                                | PeerEvent::MessageOnControlStream(_)
                        )
                    }),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("{}: the peer never saw an answer to its request", $draft_label)
                });
                assert_eq!(
                    landed,
                    Some(PeerEvent::ClientAnsweredOnRequestStream {
                        label: PEER_REQUEST_ID,
                        message_type: SUBSCRIBE_OK_TYPE,
                        mark: PEER_REQUEST_ID,
                    }),
                    "{}: the answer belongs on the stream the request arrived on, and must \
                     name the request it answers",
                    $draft_label
                );

                drop(inbound);

                let ended = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| {
                        matches!(
                            e,
                            PeerEvent::PeerRequestStreamReset { .. }
                                | PeerEvent::ClientEndedRequestStream(_)
                        )
                    }),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("{}: the abandoned request stream never ended", $draft_label)
                });
                assert_eq!(
                    ended,
                    Some(PeerEvent::PeerRequestStreamReset {
                        label: PEER_REQUEST_ID,
                        code: UNANSWERED,
                    }),
                    "{}: a peer's request this endpoint walks away from must reset as \
                     unanswered, not as cancelled and not with a FIN",
                    $draft_label
                );

                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A bidirectional stream the peer opens with something that is not
            /// a request closes the session with PROTOCOL_VIOLATION, **on the
            /// wire**.
            ///
            /// Section 3.3: "Bidirectional streams MUST NOT begin with any
            /// other message type unless negotiated. If they do, the peer MUST
            /// close the Session with a PROTOCOL_VIOLATION." What the peer
            /// sends is `$non_opener`: a SUBSCRIBE_OK on drafts 17, 18 and 19
            /// — a response, which answers a request stream rather than
            /// opening one — and on draft-20 a PUBLISH_STATE_NOTIFY, the
            /// message that draft added. The notify is the harder case and the
            /// reason draft-20 does not simply reuse the response: it is not a
            /// response, it carries no Request ID and it answers nothing, so
            /// the two properties a classifier usually leans on both point at
            /// "this opens a stream". Section 10.10 says it does not — it
            /// travels on a subscription's existing stream.
            ///
            /// The returned `Err` is checked too, but it is the weaker half.
            /// An implementation that reported the violation to its caller and
            /// left the session running would satisfy it and leave the peer
            /// talking to an endpoint that had silently stopped playing by the
            /// rules; only the close the peer reads off the connection says
            /// otherwise.
            ///
            /// # What it catches
            ///
            /// Deleting the `self.close_for(&err)` call from draft-17's
            /// `accept_request_stream`, so the violation is returned to the
            /// caller and nothing goes out — the `Err` half of this gate still
            /// passes, and only the wire half fails:
            ///
            /// ```text
            /// thread 'draft17::a_stream_that_opens_no_request_closes_the_session' (49352) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2714:1:
            /// draft-17: the client refused the non-request opener but never closed the session; a returned error is not a CONNECTION_CLOSE
            /// ```
            #[tokio::test]
            async fn a_stream_that_opens_no_request_closes_the_session() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    non_opener_bytes(),
                )
                .await;

                let outcome = tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{}: the accept never reached a verdict", $draft_label)
                    });
                match outcome {
                    Err(ConnectionError::NonRequestOnRequestStream(ty)) => assert_eq!(
                        ty.id(),
                        $non_opener_type,
                        "{}: the refusal should name the type it refused",
                        $draft_label
                    ),
                    other => panic!(
                        "{}: a stream opened with a message that begins no request stream \
                         must be refused, got {}",
                        $draft_label,
                        match other {
                            Ok((msg, _)) => format!("an accepted {msg:?}"),
                            Err(e) => format!("{e:?}"),
                        }
                    ),
                }

                let (code, reason) = close_the_client_sent(&mut seen, "non-request opener").await;
                assert_eq!(
                    code,
                    u64::from(PROTOCOL_VIOLATION),
                    "{}: Section 3.3 answers a non-request opener with PROTOCOL_VIOLATION; \
                     the close said {reason:?}",
                    $draft_label
                );
                assert!(
                    reason.contains("does not begin a request stream"),
                    "{}: the close should say which rule was broken; got {reason:?}",
                    $draft_label
                );

                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A request id with **this** endpoint's parity closes the session
            /// with INVALID_REQUEST_ID.
            ///
            /// Section 9.1 on draft-17, Section 10.1 on drafts 18, 19 and 20:
            /// "The client generates even numbered Request IDs, starting at 0, and
            /// the server generates odd numbered Request IDs, starting at 1",
            /// and "If an endpoint receives a Request ID where the least
            /// significant bit is incorrect for the sender ... it MUST close
            /// the session with INVALID_REQUEST_ID."
            ///
            /// The client under test is a client, so it allocates the even ids
            /// and the peer here sends one — an id that could only ever collide
            /// with one of the client's own. The parity rule is why the
            /// endpoint keeps a single map per request kind for both
            /// directions, so accepting this would not merely be lax: it would
            /// let a peer overwrite a request this endpoint had made.
            ///
            /// The code is what makes this a different gate from
            /// [`a_stream_that_opens_no_request_closes_the_session`] rather
            /// than a second copy of it. Both close; they must not close alike.
            ///
            /// # What it catches
            ///
            /// Deleting the `validate_peer_id` call and its `fail_session` arm
            /// from draft-17's `Endpoint::receive_request_on_stream`, so
            /// nothing checks the least significant bit:
            ///
            /// ```text
            /// thread 'draft17::a_peer_request_id_with_our_own_parity_closes_the_session' (60144) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2714:1:
            /// draft-17: an even Request ID from a server peer must be refused, got an accepted request on stream 0
            /// ```
            ///
            /// The request is simply taken, on a stream whose id collides with
            /// the client's own first stream — see the note in
            /// [`an_inbound_request_is_served_while_an_outbound_one_is_in_flight`].
            #[tokio::test]
            async fn a_peer_request_id_with_our_own_parity_closes_the_session() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    WRONG_PARITY_REQUEST_ID,
                    peer_subscribe_bytes(WRONG_PARITY_REQUEST_ID),
                )
                .await;

                let outcome = tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{}: the accept never reached a verdict", $draft_label)
                    });
                if let Ok((_, stream)) = outcome {
                    panic!(
                        "{}: an even Request ID from a server peer must be refused, got an \
                         accepted request on stream {}",
                        $draft_label,
                        stream.stream_id()
                    );
                }

                let (code, reason) = close_the_client_sent(&mut seen, "mis-parity id").await;
                assert_eq!(
                    code,
                    INVALID_REQUEST_ID,
                    "{}: a wrong least significant bit is INVALID_REQUEST_ID and not the \
                     PROTOCOL_VIOLATION a non-request opener gets; the close said {reason:?}",
                    $draft_label
                );
                assert!(
                    reason.contains("wrong parity"),
                    "{}: the close should say which rule was broken; got {reason:?}",
                    $draft_label
                );

                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A Request ID the peer has already spent closes the session with
            /// INVALID_REQUEST_ID, **on the wire**.
            ///
            /// The other half of the sentence
            /// [`a_peer_request_id_with_our_own_parity_closes_the_session`]
            /// tests: Section 9.1 on draft-17, Section 10.1 on drafts 18, 19
            /// and 20, "If an endpoint receives a Request ID where the least
            /// significant bit is incorrect for the sender, or a duplicate
            /// Request ID, it MUST close the session with INVALID_REQUEST_ID."
            /// **The duplicate is the half this gate is about.**
            ///
            /// The peer opens two bidirectional streams and puts
            /// [`PEER_REQUEST_ID`] on the SUBSCRIBE that begins each. The first
            /// is accepted and its handle is held for the rest of the test, so
            /// the id is still in use rather than merely remembered — a client
            /// that only rejected ids belonging to *live* requests would pass a
            /// gate that dropped the first handle, and one that pruned its
            /// record on completion would pass either way.
            ///
            /// What is asserted is the close and its code. Nothing here reads a
            /// counter or asks the endpoint what it thinks: a duplicate is a
            /// statement about what the peer may send, so the peer is what has
            /// to hear about it. The code is what makes this a different gate
            /// from [`a_stream_that_opens_no_request_closes_the_session`], which
            /// closes too and closes with PROTOCOL_VIOLATION.
            ///
            /// # What it catches
            ///
            /// Deleting the duplicate check from draft-17's
            /// `Endpoint::receive_request_on_stream` — leaving
            /// `self.peer_request_ids.insert(id);` with nothing testing its
            /// answer — fails this gate and no other in this file:
            ///
            /// ```text
            /// thread 'draft17::a_repeated_peer_request_id_closes_the_session' (52620) panicked at crates\moqtap-client\tests\uni_control_plane.rs:3205:1:
            /// draft-17: a Request ID the peer has already spent must be refused, got a second accepted request on stream 1
            ///
            /// test result: FAILED. 59 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s
            /// ```
            ///
            /// The line number is draft-17's macro invocation site and moves
            /// whenever this file is edited; the message is what identifies the
            /// failure.
            ///
            /// Before this gate existed that same deletion left the whole file
            /// green — `test result: ok. 57 passed; 0 failed` — which is the
            /// coverage hole it was written to fill. The endpoint's own unit
            /// test caught the deletion in-process; nothing on the wire did.
            #[tokio::test]
            async fn a_repeated_peer_request_id_closes_the_session() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    peer_subscribe_bytes(PEER_REQUEST_ID),
                )
                .await;

                let (first, held) = tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "{}: the client never accepted the peer's first request",
                            $draft_label
                        )
                    })
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: the peer's first request was refused with {e:?}; \
                             the peer reported {:?}",
                            $draft_label,
                            reported(&mut seen)
                        )
                    });
                assert_eq!(
                    subscribe_id(&first),
                    PEER_REQUEST_ID,
                    "{}: the first request should be the one the peer sent",
                    $draft_label
                );

                // The same Request ID a second time, on a stream of its own.
                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    SECOND_STREAM_LABEL,
                    peer_subscribe_bytes(PEER_REQUEST_ID),
                )
                .await;

                let outcome = tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{}: the second accept never reached a verdict", $draft_label)
                    });
                if let Ok((_, stream)) = outcome {
                    panic!(
                        "{}: a Request ID the peer has already spent must be refused, got a \
                         second accepted request on stream {}",
                        $draft_label,
                        stream.stream_id()
                    );
                }

                let (code, reason) = close_the_client_sent(&mut seen, "repeated id").await;
                assert_eq!(
                    code,
                    INVALID_REQUEST_ID,
                    "{}: a duplicate Request ID is INVALID_REQUEST_ID and not the \
                     PROTOCOL_VIOLATION a non-request opener gets; the close said {reason:?}",
                    $draft_label
                );
                assert!(
                    reason.contains("already used by the peer"),
                    "{}: the close should say which rule was broken; got {reason:?}",
                    $draft_label
                );

                // Held to here so the first request is still open while the
                // second is refused.
                drop(held);
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// An inbound request is served while an outbound one of this
            /// endpoint's is still waiting for its answer, and neither answer
            /// goes to the other's stream.
            ///
            /// Two request streams are open at once and they run in opposite
            /// directions: the client owes an answer on one and is owed an
            /// answer on the other. Nothing on the wire distinguishes them but
            /// the stream, because responses on these drafts carry no Request
            /// ID, so a connection that kept one queue for "the next response"
            /// would hand the peer's answer to its own subscription or the
            /// other way about.
            ///
            /// The outbound request asks for [`TRACK_ONE`], whose answer the
            /// peer holds back by [`RESPONSE_STAGGER`], so it is genuinely
            /// outstanding while the inbound one is being served. The two
            /// answers carry marks that cannot be confused: the outbound one is
            /// [`MARK_ONE`], taken from the track name, and the inbound one is
            /// [`OTHER_PEER_REQUEST_ID`], echoed from the Request ID the peer
            /// chose.
            ///
            /// The ablation recorded on
            /// [`a_peers_request_is_answered_on_the_stream_it_arrived_on`]
            /// fails this one too.
            #[tokio::test]
            async fn an_inbound_request_is_served_while_an_outbound_one_is_in_flight() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                let mut outbound = conn
                    .subscribe(namespace(), TRACK_ONE.to_vec(), Vec::new())
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: subscribe failed with {e:?}; the peer reported {:?}",
                            $draft_label,
                            reported(&mut seen)
                        )
                    });
                saw_request(
                    &mut seen,
                    $draft_label,
                    "outbound SUBSCRIBE",
                    &subscribe_request(
                        outbound.request_id().into_inner(),
                        &namespace(),
                        TRACK_ONE,
                        0,
                    ),
                )
                .await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    OTHER_PEER_REQUEST_ID,
                    peer_subscribe_bytes(OTHER_PEER_REQUEST_ID),
                )
                .await;

                let (request, mut inbound) =
                    tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "{}: the client never accepted the peer's request while one \
                                 of its own was outstanding",
                                $draft_label
                            )
                        })
                        .unwrap_or_else(|e| {
                            panic!(
                                "{}: accepting the peer's request failed with {e:?}; \
                                 the peer reported {:?}",
                                $draft_label,
                                reported(&mut seen)
                            )
                        });
                assert_eq!(subscribe_id(&request), OTHER_PEER_REQUEST_ID);
                // The two handles are deliberately not compared by
                // `stream_id`. `RequestStream::stream_id` reports quinn's
                // `StreamId::index`, which counts within a (direction,
                // initiator) class and so numbers the first stream each side
                // opens 0 — the outbound request and the inbound one both
                // answer 0 here. That the two are distinct streams is asserted
                // where it is observable instead: the peer reads the inbound
                // answer off the receive half of the stream it opened, and the
                // outbound answer arrives through the handle this endpoint
                // opened.
                //
                // The parity rule is what lets one map per request kind serve
                // both directions: the ids can never collide.
                assert_eq!(
                    outbound.request_id().into_inner() % 2,
                    0,
                    "{}: this endpoint is a client and allocates even ids",
                    $draft_label
                );
                assert_eq!(
                    inbound.request_id().into_inner() % 2,
                    1,
                    "{}: its peer is a server and allocates odd ones",
                    $draft_label
                );

                conn.respond_subscribe_ok(&mut inbound, answer_for(OTHER_PEER_REQUEST_ID))
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: answering the peer's SUBSCRIBE failed with {e:?}; \
                             the peer reported {:?}",
                            $draft_label,
                            reported(&mut seen)
                        )
                    });

                let landed = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| {
                        matches!(
                            e,
                            PeerEvent::ClientAnsweredOnRequestStream { .. }
                                | PeerEvent::MessageOnControlStream(_)
                        )
                    }),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("{}: the peer never saw an answer to its request", $draft_label)
                });
                assert_eq!(
                    landed,
                    Some(PeerEvent::ClientAnsweredOnRequestStream {
                        label: OTHER_PEER_REQUEST_ID,
                        message_type: SUBSCRIBE_OK_TYPE,
                        mark: OTHER_PEER_REQUEST_ID,
                    }),
                    "{}: the inbound answer went somewhere other than the stream the inbound \
                     request arrived on",
                    $draft_label
                );

                let answer = answer_to(&mut conn, &mut outbound, &mut seen, "outbound").await;
                assert_eq!(
                    mark_of(&answer),
                    MARK_ONE,
                    "{}: the outbound request was handed something other than its own answer",
                    $draft_label
                );

                drop(inbound);
                drop(outbound);
                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// A second message from the peer, on a stream the peer opened,
            /// reaches the responder dispatch and not the requester one.
            ///
            /// PUBLISH is the request kind that makes this observable. Every
            /// other inbound request ends at its answer, so a handle that
            /// routed by nothing at all would look correct. A PUBLISH
            /// establishes a subscription, and the publisher then sends
            /// PUBLISH_DONE on that same stream to end it — so the stream
            /// carries traffic in the peer-to-us direction *after* we have
            /// answered, and that traffic is a request-side message arriving
            /// on a stream we did not open.
            ///
            /// Dispatching it as a response is the mistake this catches, and
            /// the error it produces names the wrong thing: the requester
            /// dispatch looks up the Request ID among the requests *we* made,
            /// finds nothing, and reports an unknown request. Someone reading
            /// that would go looking for a bookkeeping bug in the id
            /// allocator rather than for a stream routed to the wrong half.
            ///
            /// # What it catches
            ///
            /// Collapsing the `origin` match in `recv_on_request_stream` to
            /// the requester arm alone — draft-17's `connection.rs`, which is
            /// where this was actually run — fails this gate and no other in
            /// the file. Drafts 18 and 19 kept their routing and kept passing,
            /// which is what shows the gate is per-draft and not incidental:
            ///
            /// ```text
            /// thread 'draft17::a_peers_publish_carries_a_second_message_from_the_peer' (14612) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2948:1:
            /// draft-17: the PUBLISH_DONE the peer sent on its own stream came back as Endpoint(UnknownRequest(1)) instead of being dispatched as a request-side message
            ///
            /// test result: FAILED. 53 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
            /// ```
            #[tokio::test]
            async fn a_peers_publish_carries_a_second_message_from_the_peer() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    peer_publish_bytes(PEER_REQUEST_ID),
                )
                .await;

                let (request, mut inbound) =
                    tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "{}: the client never accepted the peer's PUBLISH",
                                $draft_label
                            )
                        })
                        .unwrap_or_else(|e| {
                            panic!(
                                "{}: accepting the peer's PUBLISH failed with {e:?}; \
                                 the peer reported {:?}",
                                $draft_label,
                                reported(&mut seen)
                            )
                        });

                assert!(
                    matches!(request, ControlMessage::Publish(_)),
                    "{}: the accepted request should be the peer's PUBLISH, got {request:?}",
                    $draft_label
                );
                assert_eq!(
                    inbound.origin(),
                    RequestOrigin::Peer,
                    "{}: a stream the peer opened must be marked as such",
                    $draft_label
                );

                conn.$respond_to_publish(&mut inbound, $publish_ok)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("{}: answering the peer's PUBLISH failed with {e:?}", $draft_label)
                    });

                // The peer now ends the subscription its PUBLISH established,
                // on the stream it opened. Nothing waits on this: the peer
                // reports only what the *client* writes, and this is the peer
                // speaking.
                peer_writes_on_request_stream(
                    &commands,
                    PEER_REQUEST_ID,
                    peer_publish_done_bytes(),
                );

                let second = tokio::time::timeout(
                    PATIENCE,
                    conn.recv_on_request_stream(&mut inbound),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{}: the PUBLISH_DONE the peer sent on its own stream never arrived",
                        $draft_label
                    )
                })
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: the PUBLISH_DONE the peer sent on its own stream came back as \
                         {e:?} instead of being dispatched as a request-side message",
                        $draft_label
                    )
                });

                assert!(
                    matches!(second, ControlMessage::PublishDone(_)),
                    "{}: the second message on the peer's stream should be PUBLISH_DONE, \
                     got {second:?}",
                    $draft_label
                );

                drop(inbound);
                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// An accept that is dropped part-way through reading loses
            /// neither the peer's stream nor the bytes already read off it.
            ///
            /// This is what makes `accept_request_stream` usable at all. It
            /// takes `&mut self`, so a caller cannot hold it open in one task
            /// while working in another — the only way to serve inbound
            /// requests *and* make progress on anything else is to
            /// `select!` the accept against other work, which drops the
            /// accept future whenever the other arm wins. If that dropped a
            /// stream the transport had already handed over, a caller doing
            /// the one thing the API leaves them would silently lose peers'
            /// requests, and the peer would run out of bidirectional stream
            /// credit with nothing to show for it.
            ///
            /// The peer opens a request stream carrying all but the last byte
            /// of its SUBSCRIBE, so the accept blocks in its read rather than
            /// completing. Each attempt is bounded by [`BRIEF`] and the
            /// dropped future is the cancellation. The loop runs until
            /// `pending_inbound_count` shows the stream has actually been
            /// taken off the transport — polling once and hoping is a race,
            /// and the count is a loop condition here, not the assertion.
            /// The assertion is the consequence: after the peer sends the
            /// final byte, a fresh accept produces the *whole* request, with
            /// the Request ID intact. Bytes read before the cancellation had
            /// to have survived it for that to decode at all.
            ///
            /// # What it catches
            ///
            /// Making the accept never *consult* the stash — replacing
            /// `self.take_pending_inbound()` with `None` in draft-17's
            /// `connection.rs`, which is where this was run — fails this gate
            /// and no other in the file:
            ///
            /// ```text
            /// thread 'draft17::a_cancelled_accept_does_not_lose_the_peers_stream' (42568) panicked at crates\moqtap-client\tests\uni_control_plane.rs:3062:1:
            /// draft-17: the stream survived cancellation but the request on it never completed
            ///
            /// test result: FAILED. 56 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
            /// ```
            ///
            /// Note which assertion fired. The stash is still *written* under
            /// that ablation — the cancellation guard's `Drop` runs either
            /// way — so `pending_inbound_count` still rises and the loop above
            /// still breaks. What breaks is the resumption: the second accept
            /// goes back to `accept_bi` for a stream the peer already sent,
            /// and waits out `PATIENCE` for a request that is sitting in a
            /// queue nobody reads. A gate that asserted only on the count
            /// would have passed.
            #[tokio::test]
            async fn a_cancelled_accept_does_not_lose_the_peers_stream() {
                let (mut conn, peer, mut seen, commands) = connected_with_commands().await;

                let whole = peer_subscribe_bytes(PEER_REQUEST_ID);
                let (head, tail) = whole.split_at(whole.len() - 1);

                peer_opens_request_stream(&commands, &mut seen, PEER_REQUEST_ID, head.to_vec())
                    .await;

                let mut taken = false;
                for _ in 0..CANCEL_ATTEMPTS {
                    // The timeout expiring IS the cancellation: the accept
                    // future is dropped where it sits, inside its read.
                    let outcome = tokio::time::timeout(BRIEF, conn.accept_request_stream()).await;
                    assert!(
                        outcome.is_err(),
                        "{}: an accept completed on a request the peer has not finished sending",
                        $draft_label
                    );
                    if conn.pending_inbound_count() > 0 {
                        taken = true;
                        break;
                    }
                }
                assert!(
                    taken,
                    "{}: twenty cancelled accepts and the peer's stream was never taken off \
                     the transport",
                    $draft_label
                );

                peer_writes_on_request_stream(&commands, PEER_REQUEST_ID, tail.to_vec());

                let (request, inbound) =
                    tokio::time::timeout(PATIENCE, conn.accept_request_stream())
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "{}: the stream survived cancellation but the request on it \
                                 never completed",
                                $draft_label
                            )
                        })
                        .unwrap_or_else(|e| {
                            panic!(
                                "{}: the request resumed after cancellation failed to decode \
                                 with {e:?} — bytes read before the drop were lost",
                                $draft_label
                            )
                        });

                assert_eq!(
                    subscribe_id(&request),
                    PEER_REQUEST_ID,
                    "{}: the resumed request should be the one the peer began before the \
                     accept was cancelled",
                    $draft_label
                );
                assert_eq!(
                    inbound.origin(),
                    RequestOrigin::Peer,
                    "{}: a stream recovered from the stash is still one the peer opened",
                    $draft_label
                );

                drop(inbound);
                conn.close(0, b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// The peer really does open a request stream and really does
            /// require the answer on it.
            ///
            /// The gate on the *new* half of the peer's enforcement, and it
            /// exists for the same reason as
            /// [`enforcement_closes_the_session`]: a peer that quietly stopped
            /// opening streams, or stopped reading the ones it opened, would
            /// let the four responder gates above pass against a client with no
            /// accept path at all — every one of them would simply never be
            /// reached, and a hung test is not a passing one only because a
            /// timeout says so.
            ///
            /// A raw quinn client completes the setup exchange, accepts the
            /// stream the peer opens, reads the SUBSCRIBE off it, and then
            /// writes the SUBSCRIBE_OK on its **control stream** instead of on
            /// that stream's send half — the exact mistake
            /// [`a_peers_request_is_answered_on_the_stream_it_arrived_on`]
            /// forbids. The peer must report the answer where it actually went
            /// and not where it was owed.
            ///
            /// # What it catches
            ///
            /// Stopping the peer from opening the stream at all — returning
            /// before the `conn.open_bi()` in [`serve_peer_requests`] — fails
            /// these three and the four responder gates, and nothing else:
            ///
            /// ```text
            /// thread 'draft17::the_peer_opens_a_request_stream_and_requires_the_answer_on_it' (54980) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2716:1:
            /// draft-17: the peer never opened a request stream
            /// thread 'draft18::the_peer_opens_a_request_stream_and_requires_the_answer_on_it' (67764) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2742:1:
            /// draft-18: the peer never opened a request stream
            /// thread 'draft19::the_peer_opens_a_request_stream_and_requires_the_answer_on_it' (65256) panicked at crates\moqtap-client\tests\uni_control_plane.rs:2766:1:
            /// draft-19: the peer never opened a request stream
            /// ```
            ///
            /// Which is the whole point of gating the peer: with it no longer
            /// opening streams, a client with no accept path at all would sail
            /// through the four responder gates on a timeout apiece.
            #[tokio::test]
            async fn the_peer_opens_a_request_stream_and_requires_the_answer_on_it() {
                let (addr, peer, mut seen, commands) = raw_peer();

                let client = common::client_endpoint(&[$version.quic_alpn()]);
                let conn = client
                    .connect(addr, "localhost")
                    .expect("connect")
                    .await
                    .expect("tls handshake");
                let mut control = conn.open_uni().await.expect("open_uni");
                control.write_all(&setup_bytes()).await.expect("write SETUP");
                assert_eq!(
                    tokio::time::timeout(PATIENCE, seen.recv())
                        .await
                        .expect("the peer never answered the SETUP"),
                    Some(PeerEvent::SetupOnUniStream),
                    "{}: the setup exchange should have completed first",
                    $draft_label
                );

                peer_opens_request_stream(
                    &commands,
                    &mut seen,
                    PEER_REQUEST_ID,
                    peer_subscribe_bytes(PEER_REQUEST_ID),
                )
                .await;

                let (_send, recv) = tokio::time::timeout(PATIENCE, conn.accept_bi())
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "{}: the peer opened no bidirectional stream toward us",
                            $draft_label
                        )
                    })
                    .expect("accept_bi");
                let mut stream = PeerStream::new(recv);
                assert_eq!(
                    tokio::time::timeout(PATIENCE, stream.stream_type($version))
                        .await
                        .expect("the peer wrote nothing on the stream it opened"),
                    Some(SUBSCRIBE_TYPE),
                    "{}: the peer's request stream should lead with its request",
                    $draft_label
                );

                // The answer, in the wrong place.
                let answer = AnyControlMessage::$variant(ControlMessage::SubscribeOk(
                    answer_for(PEER_REQUEST_ID),
                ));
                let mut bytes = Vec::new();
                answer.encode(&mut bytes).expect("encode SUBSCRIBE_OK");
                control.write_all(&bytes).await.expect("write the answer");

                let landed = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| {
                        matches!(
                            e,
                            PeerEvent::ClientAnsweredOnRequestStream { .. }
                                | PeerEvent::MessageOnControlStream(_)
                        )
                    }),
                )
                .await
                .expect("the peer noticed the answer nowhere at all");
                assert_eq!(
                    landed,
                    Some(PeerEvent::MessageOnControlStream(SUBSCRIBE_OK_TYPE)),
                    "{}: the peer must report an answer where it was written, not where it \
                     was owed",
                    $draft_label
                );

                conn.close(quinn::VarInt::from_u32(0), b"bye");
                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// The peer really does report a CONNECTION_CLOSE the client sends.
            ///
            /// [`a_stream_that_opens_no_request_closes_the_session`] and
            /// [`a_peer_request_id_with_our_own_parity_closes_the_session`]
            /// both rest entirely on this: their whole content is a code and a
            /// reason phrase read off a close. A peer that reported no close,
            /// or reported a fixed one, would turn both into assertions about
            /// nothing.
            ///
            /// A raw quinn client closes with [`RAW_CLOSE_CODE`] — neither of
            /// the two codes the accept path produces, so a hard-coded report
            /// cannot pass — and a reason phrase of its own.
            #[tokio::test]
            async fn the_peer_reports_the_close_the_client_sends() {
                let (addr, peer, mut seen, _commands) = raw_peer();

                let client = common::client_endpoint(&[$version.quic_alpn()]);
                let conn = client
                    .connect(addr, "localhost")
                    .expect("connect")
                    .await
                    .expect("tls handshake");
                let mut control = conn.open_uni().await.expect("open_uni");
                control.write_all(&setup_bytes()).await.expect("write SETUP");
                assert_eq!(
                    tokio::time::timeout(PATIENCE, seen.recv())
                        .await
                        .expect("the peer never answered the SETUP"),
                    Some(PeerEvent::SetupOnUniStream),
                    "{}: the setup exchange should have completed first",
                    $draft_label
                );

                conn.close(quinn::VarInt::from_u32(RAW_CLOSE_CODE), RAW_CLOSE_REASON);

                let reported_close = tokio::time::timeout(
                    PATIENCE,
                    wait_for_event(&mut seen, |e| {
                        matches!(e, PeerEvent::SessionClosedByClient { .. })
                    }),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("{}: the peer reported no close at all", $draft_label)
                });
                assert_eq!(
                    reported_close,
                    Some(PeerEvent::SessionClosedByClient {
                        code: u64::from(RAW_CLOSE_CODE),
                        reason: String::from_utf8_lossy(RAW_CLOSE_REASON).into_owned(),
                    }),
                    "{}: the peer must report the code and reason the client actually sent",
                    $draft_label
                );

                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// The peer really does refuse a bidirectional stream that does
            /// not begin with a request.
            ///
            /// A raw quinn client opens a bidirectional stream and writes the
            /// same SETUP bytes on it. The peer must close the session with
            /// PROTOCOL_VIOLATION, which is the answer draft-17 Section 3.3
            /// requires and the answer the client under test would get if it
            /// went back to putting SETUP on a bidirectional stream.
            #[tokio::test]
            async fn enforcement_closes_the_session() {
                let (addr, peer, mut seen, _commands) = raw_peer();

                let client = common::client_endpoint(&[$version.quic_alpn()]);
                let conn = client
                    .connect(addr, "localhost")
                    .expect("connect")
                    .await
                    .expect("tls handshake");
                let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
                send.write_all(&setup_bytes()).await.expect("write SETUP");

                let closed = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the peer never closed the session");
                let code = match closed {
                    quinn::ConnectionError::ApplicationClosed(close) => {
                        close.error_code.into_inner()
                    }
                    other => {
                        panic!("{}: expected an application close, got {other:?}", $draft_label)
                    }
                };
                assert_eq!(
                    code,
                    u64::from(PROTOCOL_VIOLATION),
                    "{}: SETUP on a bidirectional stream must be answered with PROTOCOL_VIOLATION",
                    $draft_label
                );
                assert_eq!(
                    seen.recv().await,
                    Some(PeerEvent::ClosedBidiStream(SETUP_STREAM_TYPE)),
                    "{}: the peer should have rejected the stream on its SETUP type",
                    $draft_label
                );

                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }

            /// The peer really does refuse a request on the control stream.
            ///
            /// This is the gate on the *other* half of the peer's
            /// enforcement, and it exists for the same reason as
            /// [`enforcement_closes_the_session`]: without it the peer could
            /// quietly stop reading past SETUP, and
            /// [`a_request_completes_on_its_own_bidirectional_stream`] would
            /// pass against a client that had put its requests back on the
            /// control plane.
            ///
            /// A raw quinn client completes the setup exchange the way the
            /// draft asks — SETUP on a unidirectional stream — and only then
            /// writes a TRACK_STATUS on that same stream. Waiting for the
            /// peer's own SETUP first is what makes the TRACK_STATUS a
            /// separate message on an established control stream rather than
            /// something that might be read as part of the handshake.
            ///
            /// # What it catches
            ///
            /// Stopping `refuse_requests_on_control_stream` from acting on
            /// the types it recognises leaves every other test in this file
            /// passing and fails only these three, one per draft:
            ///
            /// ```text
            /// thread 'draft17::control_stream_enforcement_closes_the_session' panicked at crates\moqtap-client\tests\uni_control_plane.rs:1170:1:
            /// the peer never closed the session: Elapsed(())
            /// thread 'draft18::control_stream_enforcement_closes_the_session' panicked at crates\moqtap-client\tests\uni_control_plane.rs:1186:1:
            /// the peer never closed the session: Elapsed(())
            /// thread 'draft19::control_stream_enforcement_closes_the_session' panicked at crates\moqtap-client\tests\uni_control_plane.rs:1201:1:
            /// the peer never closed the session: Elapsed(())
            /// ```
            ///
            /// The line numbers are the macro invocation sites, which move
            /// whenever this file is edited; the message above them is what
            /// identifies the failure.
            ///
            /// Which is the whole point of this gate: with the peer no longer
            /// enforcing, a client that had put its requests back on the
            /// control plane would sail through everything else here.
            #[tokio::test]
            async fn control_stream_enforcement_closes_the_session() {
                let (addr, peer, mut seen, _commands) = raw_peer();

                let client = common::client_endpoint(&[$version.quic_alpn()]);
                let conn = client
                    .connect(addr, "localhost")
                    .expect("connect")
                    .await
                    .expect("tls handshake");
                let mut control = conn.open_uni().await.expect("open_uni");
                control.write_all(&setup_bytes()).await.expect("write SETUP");
                assert_eq!(
                    tokio::time::timeout(PATIENCE, seen.recv())
                        .await
                        .expect("the peer never answered the SETUP"),
                    Some(PeerEvent::SetupOnUniStream),
                    "{}: the setup exchange should have completed first",
                    $draft_label
                );

                control.write_all(&stray_request_bytes()).await.expect("write TRACK_STATUS");

                let closed = tokio::time::timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the peer never closed the session");
                let code = match closed {
                    quinn::ConnectionError::ApplicationClosed(close) => {
                        close.error_code.into_inner()
                    }
                    other => {
                        panic!("{}: expected an application close, got {other:?}", $draft_label)
                    }
                };
                assert_eq!(
                    code,
                    u64::from(PROTOCOL_VIOLATION),
                    "{}: a request on the control stream must be answered with \
                     PROTOCOL_VIOLATION",
                    $draft_label
                );
                assert_eq!(
                    wait_for_event(&mut seen, |e| matches!(e, PeerEvent::ClosedControlStream(_)))
                        .await,
                    Some(PeerEvent::ClosedControlStream(TRACK_STATUS_TYPE)),
                    "{}: the peer should have rejected the message on its TRACK_STATUS type",
                    $draft_label
                );

                let _ = tokio::time::timeout(PATIENCE, peer).await;
            }
        }
    };
}

/// The FETCH rendering and the fetch half of the request sweep, for a draft
/// that still has the Fetch Type field and the joining fetch.
///
/// Drafts 17, 18 and 19 spell `Fetch` identically — a Request ID, a Fetch
/// Type, a two-variant `FetchPayload` and a parameter list — and give
/// `Connection` the same three helpers over it, so this is one body stamped
/// three times rather than three bodies that could drift apart. Draft-20 has
/// none of those types and writes its own pair below, which is the whole
/// reason the gate macro takes both as parameters.
///
/// Gated rather than left to be unused: a draft-20-only build has no draft
/// left to stamp it for, and an unused macro is a warning `-D warnings` turns
/// into a failure.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
macro_rules! joining_fetch_hooks {
    ($draft_mod:ident, $label:literal, $describe:ident, $requests:ident) => {
        /// This draft's FETCH, rendered. See [`Describe`].
        ///
        /// The Fetch Type is a rendered field rather than part of the message
        /// name, because a helper that sent the wrong one has written a
        /// well-formed FETCH asking for something else — the cut recorded on
        /// `every_request_helper_opens_its_own_stream`, which reddened nothing
        /// until the peer decoded what it was sent.
        fn $describe(m: &moqtap_codec::$draft_mod::message::Fetch) -> String {
            use moqtap_codec::$draft_mod::message::FetchPayload;
            match &m.fetch_payload {
                FetchPayload::Standalone {
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                } => standalone_fetch_request(
                    m.request_id.into_inner(),
                    m.fetch_type as u64,
                    track_namespace,
                    track_name,
                    (
                        start_group.into_inner(),
                        start_object.into_inner(),
                        end_group.into_inner(),
                        end_object.into_inner(),
                    ),
                    m.parameters.len(),
                ),
                FetchPayload::Joining { joining_request_id, joining_start } => {
                    joining_fetch_request(
                        m.request_id.into_inner(),
                        m.fetch_type as u64,
                        joining_request_id.into_inner(),
                        joining_start.into_inner(),
                        m.parameters.len(),
                    )
                }
            }
        }

        /// The three fetch helpers this draft has, each of which has to open a
        /// bidirectional stream of its own.
        ///
        /// `held[0]` is the SUBSCRIBE the sweep made immediately before this,
        /// and its Request ID is what the two joining FETCHes join to. Read
        /// off the handle rather than counted, so it stays right if the
        /// endpoint changes how it allocates.
        async fn $requests(
            conn: &mut moqtap_client::$draft_mod::connection::Connection,
            held: &mut Vec<moqtap_client::$draft_mod::connection::RequestStream>,
            seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
        ) {
            let subscription = held[0].request_id();

            let stream = made(
                $label,
                "FETCH",
                seen,
                conn.fetch(
                    namespace(),
                    TRACK_ONE.to_vec(),
                    VarInt::from_u64_moqt(0),
                    VarInt::from_u64_moqt(0),
                    VarInt::from_u64_moqt(1),
                    VarInt::from_u64_moqt(1),
                    vec![attached()],
                ),
            )
            .await;
            saw_request(
                seen,
                $label,
                "FETCH",
                &standalone_fetch_request(
                    stream.request_id().into_inner(),
                    STANDALONE_FETCH,
                    &namespace(),
                    TRACK_ONE,
                    (0, 0, 1, 1),
                    1,
                ),
            )
            .await;
            held.push(stream);

            let stream = made(
                $label,
                "joining FETCH",
                seen,
                conn.joining_fetch(subscription, VarInt::from_u64_moqt(2), vec![attached()]),
            )
            .await;
            saw_request(
                seen,
                $label,
                "joining FETCH",
                &joining_fetch_request(
                    stream.request_id().into_inner(),
                    RELATIVE_JOINING_FETCH,
                    subscription.into_inner(),
                    2,
                    1,
                ),
            )
            .await;
            held.push(stream);

            let stream = made(
                $label,
                "absolute joining FETCH",
                seen,
                conn.absolute_joining_fetch(
                    subscription,
                    VarInt::from_u64_moqt(9),
                    vec![attached()],
                ),
            )
            .await;
            saw_request(
                seen,
                $label,
                "absolute joining FETCH",
                &joining_fetch_request(
                    stream.request_id().into_inner(),
                    ABSOLUTE_JOINING_FETCH,
                    subscription.into_inner(),
                    9,
                    1,
                ),
            )
            .await;
            held.push(stream);
        }
    };
}

#[cfg(feature = "draft17")]
joining_fetch_hooks!(draft17, "draft-17", draft17_describe_fetch, draft17_fetch_requests);
#[cfg(feature = "draft18")]
joining_fetch_hooks!(draft18, "draft-18", draft18_describe_fetch, draft18_fetch_requests);
#[cfg(feature = "draft19")]
joining_fetch_hooks!(draft19, "draft-19", draft19_describe_fetch, draft19_fetch_requests);

/// Draft-20's FETCH, rendered. See [`Describe`].
///
/// There is no Fetch Type to render and no payload to switch on: Section 10.13
/// made FETCH byte-identical to SUBSCRIBE apart from the type code. What is
/// left is the four fields the message now carries, plus the range read back
/// out of the parameter list by [`draft20_range_text`].
///
/// The range belongs in the rendering because it is still something the
/// *caller* chose. Rendering only `parameters=N` would let a FETCH for the
/// wrong range — or one whose end location carried draft-19's `+ 1` — pass the
/// sweep with the right count.
#[cfg(feature = "draft20")]
fn draft20_describe_fetch(m: &moqtap_codec::draft20::message::Fetch) -> String {
    draft20_fetch_request(
        m.request_id.into_inner(),
        &m.track_namespace,
        &m.track_name,
        &draft20_range_text(&m.parameters),
        m.parameters.len(),
    )
}

/// Draft-20's fetch helpers, and the fill that replaced the joining fetch.
///
/// Three requests, and each is a separate thing to get wrong:
///
/// * **`fetch` with no filter** — the unfiltered FETCH Section 10.13 defines
///   as `{0,0}` through Largest Object. Its meaning is the *absence* of a
///   parameter, so the rendering says `range=none` and a helper that invented
///   a filter is caught.
/// * **`fetch_range`** — the same message with the caller's range carried as
///   `LOCATION_FILTER`. This is where decision D4 reaches the wire: the range
///   ends at object 1 and the filter must say 1. A draft-19 encoder ported
///   forward would write 2 there, and with the range in the rendering that is
///   a failure rather than a fetch of one object too many.
/// * **a SUBSCRIBE carrying `FILL_PARAMETERS`** — what draft-20 turned the
///   joining fetch into. Sections 5.1.3 and 10.2.15: the parameter's presence
///   asks the publisher to open a fill fetch stream carrying the Objects
///   behind the live edge, which is the job `joining_fetch` did on drafts 17,
///   18 and 19. The request half of that is a request stream and so is swept
///   here. The stream that answers it is a data stream, and its bytes — the
///   nested block, its count prefix and its restarted delta chain — are gated
///   in `draft20_fill_and_state_notify.rs`; what this asserts is only what
///   this file is about, that the request went out alone at the front of a
///   bidirectional stream of its own still carrying both parameters.
///
/// # What it catches, observed by making the change and running it
///
/// The ported `+ 1` — building the ranged FETCH's filter with `range_to(0, 0,
/// 1, 2)`, which is what a draft-19 encoder carried forward writes for a range
/// whose last object is 1. The message is well formed, the type is right, the
/// parameter count is right, and the FETCH asks for one object too many:
///
/// ```text
/// assertion `left == right` failed: draft-20: the ranged FETCH must arrive alone at the front of a bidirectional stream of its own, and must be the request the helper was asked for
///   left: Some(RequestOnBidiStream("FETCH 0x16 request id=4 namespace=uni-control-plane track=track-1 range=0,0,1,2 parameters=2"))
///  right: Some(RequestOnBidiStream("FETCH 0x16 request id=4 namespace=uni-control-plane track=track-1 range=0,0,1,1 parameters=2"))
/// ```
///
/// A rendering that stopped at `parameters=2` would print the same on both
/// sides, which is why the filter is decoded into it.
#[cfg(feature = "draft20")]
async fn draft20_fetch_requests(
    conn: &mut moqtap_client::draft20::connection::Connection,
    held: &mut Vec<moqtap_client::draft20::connection::RequestStream>,
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
) {
    use moqtap_client::draft20::fill::{FillParameters, LocationFilter};

    let stream = made(
        "draft-20",
        "FETCH",
        seen,
        conn.fetch(namespace(), TRACK_ONE.to_vec(), vec![attached()]),
    )
    .await;
    saw_request(
        seen,
        "draft-20",
        "FETCH",
        &draft20_fetch_request(
            stream.request_id().into_inner(),
            &namespace(),
            TRACK_ONE,
            "none",
            1,
        ),
    )
    .await;
    held.push(stream);

    // Group 0 object 0 through group 0 + 1 object 1, inclusive at both ends.
    let range = LocationFilter::range_to(0, 0, 1, 1).expect("the end group is in range");
    let stream = made(
        "draft-20",
        "ranged FETCH",
        seen,
        conn.fetch_range(namespace(), TRACK_ONE.to_vec(), &range, vec![attached()]),
    )
    .await;
    saw_request(
        seen,
        "draft-20",
        "ranged FETCH",
        &draft20_fetch_request(
            stream.request_id().into_inner(),
            &namespace(),
            TRACK_ONE,
            "0,0,1,1",
            2,
        ),
    )
    .await;
    held.push(stream);

    // A fill relative to the live edge, which is the shape the joining FETCH
    // of drafts 17, 18 and 19 had. Section 5.1.2 resolves a one-field filter
    // to `{Largest Object.Group + 1 - StartGroup, 0}`, so 2 starts one group
    // before the current one. The number is not draft-19's Joining Start and
    // is not meant to be: the two drafts count from different places, which is
    // half of why one message could not become the other.
    let fill = FillParameters::inherited()
        .with_range(&LocationFilter::relative(2))
        .expect("a LOCATION_FILTER may be nested inside FILL_PARAMETERS")
        .parameter()
        .expect("the fill block encodes");
    let stream = made(
        "draft-20",
        "SUBSCRIBE asking for a fill",
        seen,
        conn.subscribe(namespace(), TRACK_TWO.to_vec(), vec![attached(), fill]),
    )
    .await;
    saw_request(
        seen,
        "draft-20",
        "SUBSCRIBE asking for a fill",
        &subscribe_request(stream.request_id().into_inner(), &namespace(), TRACK_TWO, 2),
    )
    .await;
    held.push(stream);
}

/// Draft-17's namespace requests: a SUBSCRIBE_NAMESPACE that still carries
/// the `subscribe_options` field. Draft-17 has no SUBSCRIBE_TRACKS.
///
/// Written out per draft rather than inside the gate macro because the
/// signature moved between drafts and there is no shape the four share.
#[cfg(feature = "draft17")]
async fn draft17_namespace_requests(
    conn: &mut moqtap_client::draft17::connection::Connection,
    held: &mut Vec<moqtap_client::draft17::connection::RequestStream>,
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
) {
    let stream = conn
        .subscribe_namespace(namespace(), VarInt::from_u64_moqt(0), vec![attached()])
        .await
        .expect("draft-17 subscribe_namespace");
    saw_request(
        seen,
        "draft-17",
        "SUBSCRIBE_NAMESPACE",
        &draft17_subscribe_namespace_request(stream.request_id().into_inner(), &namespace(), 0, 1),
    )
    .await;
    held.push(stream);
}

/// Draft-17's namespace request, rendered. See [`Describe`].
///
/// The one request type this draft does not spell the way drafts 18, 19 and 20
/// do, and the reason the rendering is not written once inside the gate
/// macro: SUBSCRIBE_NAMESPACE is 0x11 here rather than 0x50, and carries a
/// `subscribe_options` field the split at draft-18 took away.
#[cfg(feature = "draft17")]
fn draft17_describe_namespace(msg: &moqtap_codec::draft17::message::ControlMessage) -> String {
    use moqtap_codec::draft17::message::ControlMessage;
    match msg {
        ControlMessage::SubscribeNamespace(m) => draft17_subscribe_namespace_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.subscribe_options.into_inner(),
            m.parameters.len(),
        ),
        other => render(&format!("{:?}", other.message_type()), other.message_type().id(), &[]),
    }
}

/// Draft-18's namespace requests: the renumbered SUBSCRIBE_NAMESPACE and the
/// SUBSCRIBE_TRACKS the split created, which is the seventh request type and
/// the one draft-17 does not have.
#[cfg(feature = "draft18")]
async fn draft18_namespace_requests(
    conn: &mut moqtap_client::draft18::connection::Connection,
    held: &mut Vec<moqtap_client::draft18::connection::RequestStream>,
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
) {
    let stream = conn
        .subscribe_namespace(namespace(), vec![attached()])
        .await
        .expect("draft-18 subscribe_namespace");
    saw_request(
        seen,
        "draft-18",
        "SUBSCRIBE_NAMESPACE",
        &subscribe_namespace_request(stream.request_id().into_inner(), &namespace(), 1),
    )
    .await;
    held.push(stream);

    let stream = conn
        .subscribe_tracks(namespace(), vec![attached()])
        .await
        .expect("draft-18 subscribe_tracks");
    saw_request(
        seen,
        "draft-18",
        "SUBSCRIBE_TRACKS",
        &subscribe_tracks_request(stream.request_id().into_inner(), &namespace(), 1),
    )
    .await;
    held.push(stream);
}

/// Draft-18's namespace requests, rendered. See [`Describe`].
///
/// The two carry the same two fields, so the message type in the rendering is
/// the only thing that tells them apart — which is the point: a
/// `subscribe_tracks` that wrote a SUBSCRIBE_NAMESPACE would ask the
/// publisher for namespace announcements rather than for the PUBLISHes the
/// caller wanted, and every other field would be right.
#[cfg(feature = "draft18")]
fn draft18_describe_namespace(msg: &moqtap_codec::draft18::message::ControlMessage) -> String {
    use moqtap_codec::draft18::message::ControlMessage;
    match msg {
        ControlMessage::SubscribeNamespace(m) => subscribe_namespace_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.parameters.len(),
        ),
        ControlMessage::SubscribeTracks(m) => subscribe_tracks_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.parameters.len(),
        ),
        other => render(&format!("{:?}", other.message_type()), other.message_type().id(), &[]),
    }
}

/// Draft-19's namespace requests. Same two as draft-18 and the same numbers.
#[cfg(feature = "draft19")]
async fn draft19_namespace_requests(
    conn: &mut moqtap_client::draft19::connection::Connection,
    held: &mut Vec<moqtap_client::draft19::connection::RequestStream>,
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
) {
    let stream = conn
        .subscribe_namespace(namespace(), vec![attached()])
        .await
        .expect("draft-19 subscribe_namespace");
    saw_request(
        seen,
        "draft-19",
        "SUBSCRIBE_NAMESPACE",
        &subscribe_namespace_request(stream.request_id().into_inner(), &namespace(), 1),
    )
    .await;
    held.push(stream);

    let stream = conn
        .subscribe_tracks(namespace(), vec![attached()])
        .await
        .expect("draft-19 subscribe_tracks");
    saw_request(
        seen,
        "draft-19",
        "SUBSCRIBE_TRACKS",
        &subscribe_tracks_request(stream.request_id().into_inner(), &namespace(), 1),
    )
    .await;
    held.push(stream);
}

/// Draft-19's namespace requests, rendered. Same two as draft-18's and the
/// same numbers. See [`draft18_describe_namespace`].
#[cfg(feature = "draft19")]
fn draft19_describe_namespace(msg: &moqtap_codec::draft19::message::ControlMessage) -> String {
    use moqtap_codec::draft19::message::ControlMessage;
    match msg {
        ControlMessage::SubscribeNamespace(m) => subscribe_namespace_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.parameters.len(),
        ),
        ControlMessage::SubscribeTracks(m) => subscribe_tracks_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.parameters.len(),
        ),
        other => render(&format!("{:?}", other.message_type()), other.message_type().id(), &[]),
    }
}

/// Draft-20's namespace requests. The split draft-18 made is untouched by
/// draft-20 — same two messages, same numbers — and is checked rather than
/// assumed to be.
#[cfg(feature = "draft20")]
async fn draft20_namespace_requests(
    conn: &mut moqtap_client::draft20::connection::Connection,
    held: &mut Vec<moqtap_client::draft20::connection::RequestStream>,
    seen: &mut mpsc::UnboundedReceiver<PeerEvent>,
) {
    let stream = made(
        "draft-20",
        "SUBSCRIBE_NAMESPACE",
        seen,
        conn.subscribe_namespace(namespace(), vec![attached()]),
    )
    .await;
    saw_request(
        seen,
        "draft-20",
        "SUBSCRIBE_NAMESPACE",
        &subscribe_namespace_request(stream.request_id().into_inner(), &namespace(), 1),
    )
    .await;
    held.push(stream);

    let stream = made(
        "draft-20",
        "SUBSCRIBE_TRACKS",
        seen,
        conn.subscribe_tracks(namespace(), vec![attached()]),
    )
    .await;
    saw_request(
        seen,
        "draft-20",
        "SUBSCRIBE_TRACKS",
        &subscribe_tracks_request(stream.request_id().into_inner(), &namespace(), 1),
    )
    .await;
    held.push(stream);
}

/// Draft-20's namespace requests, rendered. Same two as draft-18's and the
/// same numbers. See [`draft18_describe_namespace`].
#[cfg(feature = "draft20")]
fn draft20_describe_namespace(msg: &moqtap_codec::draft20::message::ControlMessage) -> String {
    use moqtap_codec::draft20::message::ControlMessage;
    match msg {
        ControlMessage::SubscribeNamespace(m) => subscribe_namespace_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.parameters.len(),
        ),
        ControlMessage::SubscribeTracks(m) => subscribe_tracks_request(
            m.request_id.into_inner(),
            &m.namespace_prefix,
            m.parameters.len(),
        ),
        other => render(&format!("{:?}", other.message_type()), other.message_type().id(), &[]),
    }
}

/// The numbers the renderings carry are the ones this draft assigns.
///
/// Every other field in a rendering is a claim about one side checked against
/// the other: the peer fills it in from the message it decoded and a gate from
/// what it asked for. The message type is not — both sides read it from the
/// constants above, so a wrong one would agree with itself and print a number
/// no draft uses in every failure message this file can produce. The codec's
/// registry is where these numbers are read against the draft, so it is what
/// they are held to.
///
/// # What it catches
///
/// A digit wrong in one of them:
///
/// ```text
/// assertion `left == right` failed: FETCH
///   left: 22
///  right: 23
/// ```
#[cfg(feature = "draft17")]
#[test]
fn the_numbers_the_renderings_carry_are_draft17s() {
    use moqtap_codec::draft17::message::{FetchType, MessageType};
    assert_eq!(MessageType::Subscribe.id(), SUBSCRIBE_TYPE, "SUBSCRIBE");
    assert_eq!(MessageType::TrackStatus.id(), TRACK_STATUS_TYPE, "TRACK_STATUS");
    assert_eq!(MessageType::Fetch.id(), FETCH_TYPE, "FETCH");
    assert_eq!(MessageType::SubscribeOk.id(), SUBSCRIBE_OK_TYPE, "SUBSCRIBE_OK");
    assert_eq!(MessageType::Publish.id(), PUBLISH_TYPE, "PUBLISH");
    assert_eq!(MessageType::PublishNamespace.id(), PUBLISH_NAMESPACE_TYPE, "PUBLISH_NAMESPACE");
    assert_eq!(
        MessageType::SubscribeNamespace.id(),
        DRAFT17_SUBSCRIBE_NAMESPACE_TYPE,
        "SUBSCRIBE_NAMESPACE, which draft-18 renumbered"
    );
    assert_eq!(MessageType::Setup.id(), SETUP_STREAM_TYPE, "SETUP");
    assert_eq!(FetchType::Standalone as u64, STANDALONE_FETCH, "a standalone FETCH");
    assert_eq!(
        FetchType::RelativeJoining as u64,
        RELATIVE_JOINING_FETCH,
        "a Relative Joining Fetch"
    );
    assert_eq!(
        FetchType::AbsoluteJoining as u64,
        ABSOLUTE_JOINING_FETCH,
        "an Absolute Joining Fetch"
    );
}

/// See [`the_numbers_the_renderings_carry_are_draft17s`]. Draft-18 renumbered
/// SUBSCRIBE_NAMESPACE and added SUBSCRIBE_TRACKS beside it.
#[cfg(feature = "draft18")]
#[test]
fn the_numbers_the_renderings_carry_are_draft18s() {
    use moqtap_codec::draft18::message::{FetchType, MessageType};
    assert_eq!(MessageType::Subscribe.id(), SUBSCRIBE_TYPE, "SUBSCRIBE");
    assert_eq!(MessageType::TrackStatus.id(), TRACK_STATUS_TYPE, "TRACK_STATUS");
    assert_eq!(MessageType::Fetch.id(), FETCH_TYPE, "FETCH");
    assert_eq!(MessageType::SubscribeOk.id(), SUBSCRIBE_OK_TYPE, "SUBSCRIBE_OK");
    assert_eq!(MessageType::Publish.id(), PUBLISH_TYPE, "PUBLISH");
    assert_eq!(MessageType::PublishNamespace.id(), PUBLISH_NAMESPACE_TYPE, "PUBLISH_NAMESPACE");
    assert_eq!(
        MessageType::SubscribeNamespace.id(),
        SUBSCRIBE_NAMESPACE_TYPE,
        "SUBSCRIBE_NAMESPACE"
    );
    assert_eq!(MessageType::SubscribeTracks.id(), SUBSCRIBE_TRACKS_TYPE, "SUBSCRIBE_TRACKS");
    assert_eq!(MessageType::Setup.id(), SETUP_STREAM_TYPE, "SETUP");
    assert_eq!(FetchType::Standalone as u64, STANDALONE_FETCH, "a standalone FETCH");
    assert_eq!(
        FetchType::RelativeJoining as u64,
        RELATIVE_JOINING_FETCH,
        "a Relative Joining Fetch"
    );
    assert_eq!(
        FetchType::AbsoluteJoining as u64,
        ABSOLUTE_JOINING_FETCH,
        "an Absolute Joining Fetch"
    );
}

/// See [`the_numbers_the_renderings_carry_are_draft17s`]. Draft-19 keeps
/// draft-18's numbers, and is checked rather than assumed to.
#[cfg(feature = "draft19")]
#[test]
fn the_numbers_the_renderings_carry_are_draft19s() {
    use moqtap_codec::draft19::message::{FetchType, MessageType};
    assert_eq!(MessageType::Subscribe.id(), SUBSCRIBE_TYPE, "SUBSCRIBE");
    assert_eq!(MessageType::TrackStatus.id(), TRACK_STATUS_TYPE, "TRACK_STATUS");
    assert_eq!(MessageType::Fetch.id(), FETCH_TYPE, "FETCH");
    assert_eq!(MessageType::SubscribeOk.id(), SUBSCRIBE_OK_TYPE, "SUBSCRIBE_OK");
    assert_eq!(MessageType::Publish.id(), PUBLISH_TYPE, "PUBLISH");
    assert_eq!(MessageType::PublishNamespace.id(), PUBLISH_NAMESPACE_TYPE, "PUBLISH_NAMESPACE");
    assert_eq!(
        MessageType::SubscribeNamespace.id(),
        SUBSCRIBE_NAMESPACE_TYPE,
        "SUBSCRIBE_NAMESPACE"
    );
    assert_eq!(MessageType::SubscribeTracks.id(), SUBSCRIBE_TRACKS_TYPE, "SUBSCRIBE_TRACKS");
    assert_eq!(MessageType::Setup.id(), SETUP_STREAM_TYPE, "SETUP");
    assert_eq!(FetchType::Standalone as u64, STANDALONE_FETCH, "a standalone FETCH");
    assert_eq!(
        FetchType::RelativeJoining as u64,
        RELATIVE_JOINING_FETCH,
        "a Relative Joining Fetch"
    );
    assert_eq!(
        FetchType::AbsoluteJoining as u64,
        ABSOLUTE_JOINING_FETCH,
        "an Absolute Joining Fetch"
    );
}

/// See [`the_numbers_the_renderings_carry_are_draft17s`]. Draft-20 keeps every
/// number drafts 18 and 19 assign — FETCH included, which is the trap — and
/// adds one.
///
/// The three `FetchType` assertions its siblings carry are absent, because
/// there is no such type on this draft to assert about. Section 10.13 deleted
/// the field and its registry while leaving FETCH on 0x16, which is why the
/// FETCH assertion above is the one worth reading: the codepoint is the same
/// and the body behind it is not, so a draft-19 decoder reads a draft-20 FETCH
/// as a well-formed request for something else and nothing on the wire says
/// otherwise.
///
/// PUBLISH_STATE_NOTIFY is checked against the number the refusal gate refuses,
/// and against the request-type list it must **not** be in: Section 10.10 puts
/// it on a subscription's existing stream, and Section 3.3 still names seven
/// request types.
#[cfg(feature = "draft20")]
#[test]
fn the_numbers_the_renderings_carry_are_draft20s() {
    use moqtap_codec::draft20::message::MessageType;
    assert_eq!(MessageType::Subscribe.id(), SUBSCRIBE_TYPE, "SUBSCRIBE");
    assert_eq!(MessageType::TrackStatus.id(), TRACK_STATUS_TYPE, "TRACK_STATUS");
    assert_eq!(MessageType::Fetch.id(), FETCH_TYPE, "FETCH");
    assert_eq!(MessageType::SubscribeOk.id(), SUBSCRIBE_OK_TYPE, "SUBSCRIBE_OK");
    assert_eq!(MessageType::Publish.id(), PUBLISH_TYPE, "PUBLISH");
    assert_eq!(MessageType::PublishNamespace.id(), PUBLISH_NAMESPACE_TYPE, "PUBLISH_NAMESPACE");
    assert_eq!(
        MessageType::SubscribeNamespace.id(),
        SUBSCRIBE_NAMESPACE_TYPE,
        "SUBSCRIBE_NAMESPACE"
    );
    assert_eq!(MessageType::SubscribeTracks.id(), SUBSCRIBE_TRACKS_TYPE, "SUBSCRIBE_TRACKS");
    assert_eq!(MessageType::Setup.id(), SETUP_STREAM_TYPE, "SETUP");
    assert_eq!(
        MessageType::PublishStateNotify.id(),
        PUBLISH_STATE_NOTIFY_TYPE,
        "PUBLISH_STATE_NOTIFY, which draft-20 added"
    );
    assert!(
        !DRAFT18_REQUEST_TYPES.contains(&PUBLISH_STATE_NOTIFY_TYPE),
        "Section 3.3 names seven request types and PUBLISH_STATE_NOTIFY is not one of them; \
         a peer that allowed it on a bidirectional stream would make the refusal gate \
         assert nothing"
    );
}

#[cfg(feature = "draft17")]
uni_control_plane_gates!(
    draft17,
    Draft17,
    DraftVersion::Draft17,
    DRAFT17_REQUEST_TYPES,
    "draft-17",
    moqtap_codec::draft17::message::ControlMessage::TrackStatus(
        moqtap_codec::draft17::message::TrackStatus {
            request_id: VarInt::from_u64_moqt(0),
            required_request_id_delta: VarInt::from_u64_moqt(0),
            track_namespace: namespace(),
            track_name: b"stray".to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft17::message::ControlMessage::Subscribe(
        moqtap_codec::draft17::message::Subscribe {
            request_id,
            required_request_id_delta: VarInt::from_u64_moqt(0),
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft17::message::ControlMessage::Publish(
        moqtap_codec::draft17::message::Publish {
            request_id,
            required_request_id_delta: VarInt::from_u64_moqt(0),
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            track_alias: VarInt::from_u64_moqt(EARLY_TRACK_ALIAS),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    // Draft-17 answers a PUBLISH with PUBLISH_OK (0x1E). Drafts 18, 19 and 20
    // collapsed it into REQUEST_OK, so the method and the body both differ
    // and neither can be written once and copied.
    respond_publish_ok,
    moqtap_codec::draft17::message::PublishOk { parameters: Vec::new() },
    draft17_namespace_requests,
    draft17_describe_namespace,
    draft17_describe_fetch,
    draft17_fetch_requests,
    moqtap_codec::draft17::message::ControlMessage::SubscribeOk(
        moqtap_codec::draft17::message::SubscribeOk {
            track_alias: VarInt::from_u64_moqt(NO_MARK),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    SUBSCRIBE_OK_TYPE
);
#[cfg(feature = "draft18")]
uni_control_plane_gates!(
    draft18,
    Draft18,
    DraftVersion::Draft18,
    DRAFT18_REQUEST_TYPES,
    "draft-18",
    moqtap_codec::draft18::message::ControlMessage::TrackStatus(
        moqtap_codec::draft18::message::TrackStatus {
            request_id: VarInt::from_u64_moqt(0),
            track_namespace: namespace(),
            track_name: b"stray".to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft18::message::ControlMessage::Subscribe(
        moqtap_codec::draft18::message::Subscribe {
            request_id,
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft18::message::ControlMessage::Publish(
        moqtap_codec::draft18::message::Publish {
            request_id,
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            track_alias: VarInt::from_u64_moqt(EARLY_TRACK_ALIAS),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    respond_ok,
    moqtap_codec::draft18::message::RequestOk {
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    draft18_namespace_requests,
    draft18_describe_namespace,
    draft18_describe_fetch,
    draft18_fetch_requests,
    moqtap_codec::draft18::message::ControlMessage::SubscribeOk(
        moqtap_codec::draft18::message::SubscribeOk {
            track_alias: VarInt::from_u64_moqt(NO_MARK),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    SUBSCRIBE_OK_TYPE
);
#[cfg(feature = "draft19")]
uni_control_plane_gates!(
    draft19,
    Draft19,
    DraftVersion::Draft19,
    DRAFT18_REQUEST_TYPES,
    "draft-19",
    moqtap_codec::draft19::message::ControlMessage::TrackStatus(
        moqtap_codec::draft19::message::TrackStatus {
            request_id: VarInt::from_u64_moqt(0),
            track_namespace: namespace(),
            track_name: b"stray".to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft19::message::ControlMessage::Subscribe(
        moqtap_codec::draft19::message::Subscribe {
            request_id,
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft19::message::ControlMessage::Publish(
        moqtap_codec::draft19::message::Publish {
            request_id,
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            track_alias: VarInt::from_u64_moqt(EARLY_TRACK_ALIAS),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    respond_ok,
    moqtap_codec::draft19::message::RequestOk {
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    draft19_namespace_requests,
    draft19_describe_namespace,
    draft19_describe_fetch,
    draft19_fetch_requests,
    moqtap_codec::draft19::message::ControlMessage::SubscribeOk(
        moqtap_codec::draft19::message::SubscribeOk {
            track_alias: VarInt::from_u64_moqt(NO_MARK),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    SUBSCRIBE_OK_TYPE
);
// Draft-20's row. Everything above it is draft-19's, unchanged, and that is
// the finding: draft-20 kept the whole uni-control-plane topology and rebuilt
// only FETCH, so the four parameters that differ are the two fetch hooks and
// the pair naming a message that opens no request stream.
#[cfg(feature = "draft20")]
uni_control_plane_gates!(
    draft20,
    Draft20,
    DraftVersion::Draft20,
    DRAFT18_REQUEST_TYPES,
    "draft-20",
    moqtap_codec::draft20::message::ControlMessage::TrackStatus(
        moqtap_codec::draft20::message::TrackStatus {
            request_id: VarInt::from_u64_moqt(0),
            track_namespace: namespace(),
            track_name: b"stray".to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft20::message::ControlMessage::Subscribe(
        moqtap_codec::draft20::message::Subscribe {
            request_id,
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            parameters: Vec::new(),
        }
    ),
    |request_id| moqtap_codec::draft20::message::ControlMessage::Publish(
        moqtap_codec::draft20::message::Publish {
            request_id,
            track_namespace: namespace(),
            track_name: PEER_TRACK.to_vec(),
            track_alias: VarInt::from_u64_moqt(EARLY_TRACK_ALIAS),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    ),
    respond_ok,
    moqtap_codec::draft20::message::RequestOk {
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    draft20_namespace_requests,
    draft20_describe_namespace,
    draft20_describe_fetch,
    draft20_fetch_requests,
    // The one message here that is not draft-19's. A `LARGEST_OBJECT` rides on
    // it because Section 10.10 says a publisher MUST send one when it knows the
    // value, so what the refusal gate refuses is a notify a publisher would
    // really write. Its value is a Location, which Section 10.2.17 encodes as
    // two bare varints with no length in front of them; both of these fit one
    // byte.
    moqtap_codec::draft20::message::ControlMessage::PublishStateNotify(
        moqtap_codec::draft20::message::PublishStateNotify {
            parameters: vec![KeyValuePair {
                key: VarInt::from_u64_moqt(LARGEST_OBJECT),
                value: KvpValue::Bytes(vec![EARLY_GROUP_ID as u8, 0]),
            }],
        }
    ),
    PUBLISH_STATE_NOTIFY_TYPE
);

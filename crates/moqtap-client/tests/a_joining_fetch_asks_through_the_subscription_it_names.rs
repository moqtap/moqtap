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
    feature = "draft19",
    feature = "draft20",
))]

//! `AnyConnection::fetch_joining` names a subscription and a starting point,
//! and every draft that has a Joining Fetch writes both the way that draft
//! writes them.
//!
//! # What a Joining Fetch does not say, and why that is the point
//!
//! A standalone FETCH names a track and a range. A Joining Fetch names
//! **neither** — draft-19 Section 10.12.2: "A Joining Fetch is associated with
//! a Subscribe request by specifying the Request ID of an active subscription.
//! A publisher receiving a Joining Fetch uses properties of the associated
//! Subscribe to determine the Track Namespace, Track Name and End Location such
//! that it is contiguous with the associated Subscribe." So the message is a
//! Request ID and one varint, and the gates below read both off the wire and
//! check that the namespace and the name were left for the publisher to supply.
//!
//! On drafts 08 through 10 that check has something to fail on: their FETCH is
//! one flat struct with an `Option` per field of both kinds, so a sender that
//! filled the track in on a joining request would produce a message that still
//! encodes and still decodes. From draft-11 the payload is an enum whose joining
//! arm has no namespace field to fill, so there the claim is structural and the
//! gate states it rather than testing it.
//!
//! # One varint, two meanings, and a Fetch Type six bytes earlier that says
//! which
//!
//! Section 10.12.2.1 gives the publisher two sentences for the same Joining
//! Start field. For a Relative Joining Fetch it sets the Start Location to
//! "{Subscribe Largest Location.Group - Joining Start, 0}"; for an Absolute
//! Joining Fetch it sets the Start Location "to Joining Start". So the same
//! number asks for a count of Groups of run-up under one Fetch Type and for
//! everything from a Group under the other, and nothing in the field
//! distinguishes them.
//!
//! That is why `JoiningStart` is an enum, and it is why every gate here sends
//! **both** forms and asserts the Fetch Type beside the number. A facade that
//! dropped the distinction — mapping both variants to the relative call, or both
//! to the absolute one — would send well-formed messages asking a different
//! question, and a gate sending one form would stay green under half of that.
//! The two constants differ for the same reason: sending `3` both ways would put
//! the same varint on the wire either way, leaving only the Fetch Type to give
//! the swap away.
//!
//! # The drafts that have no answer to give
//!
//! Draft-07's FETCH has no Fetch Type field at all, so there is nothing in the
//! message that could ask for a join; draft-08 introduces the field and the
//! second type together. **Draft-20 deleted the whole mechanism** — Section
//! 10.13 removed the Fetch Type field, both payload structures and the Fetch
//! Type registry in one rewrite. And drafts 08 through 10 have Fetch Types `0x1`
//! and `0x2` only, so the *absolute* form has no encoding there; draft-11 is
//! where the pair arrives.
//!
//! All five refusals have gates, and they are why this file spans fourteen
//! drafts rather than twelve. A refusal is the measurement on those drafts:
//! **this is the entry point behind "one suite run per draft rather than one
//! against the newest"**, because a relay speaking 14 and 20 can be asked this
//! question on one of them and not on the other, and a probe testing only the
//! newest would report a feature the relay implements as absent.
//!
//! # Why it is a loopback and not a call to a conversion
//!
//! `a_fetch_range_means_one_thing_on_every_draft.rs`'s reason, unchanged: the
//! conversion being right is not the claim; the entry point applying it on the
//! draft actually negotiated is. Every gate runs a real session, sends a real
//! SUBSCRIBE first, and reads the FETCH off the wire at a peer that decodes it
//! with the codec — so the Request ID asserted is the one the endpoint really
//! allocated to that subscription and not a number this file chose. The gate
//! that checks the handle and the wire agree about it is what makes the rest of
//! the assertion mean anything.
//!
//! # Ablations, measured
//!
//! Three cuts, run and reverted:
//!
//! * Mapping `JoiningStart::Group` to the relative call on drafts 11 through 19
//!   — **9 redden and 8 stay green**, and every one of the nine would have
//!   stayed green too had its gate sent the relative form alone. That is the
//!   half a one-form gate misses, and the reason each gate sends both.
//! * Sending `JoiningStart::GroupsBefore` as the absolute form — the mirror,
//!   **9 redden**.
//! * Letting drafts 08 through 10 answer `JoiningStart::Group` with the relative
//!   call instead of refusing — **3 redden**, and they are the three that say a
//!   well-formed wrong question is worse than a refusal.
//!
//! # Why the shared items below carry `allow` and not `cfg`
//!
//! Two of the fourteen gates here — draft-07 and draft-20 — are refusals, and a
//! refusal needs almost nothing: a session, a call, and the sentence that comes
//! back. Everything this file holds for reading a FETCH off the wire is used
//! only by the twelve drafts in between. So a build enabling **only** the two
//! refusing drafts compiles the whole file and reads none of it, and that build
//! is not hypothetical: `just draft-pairs` runs `--features draft07,draft20`
//! under `RUSTFLAGS="-D warnings"` precisely because it is the pair that
//! exercises the dispatch path, and `just draft-matrix` compiles `draft07`
//! alone and `draft20` alone as two of its fourteen rows.
//!
//! The obvious repair is `#[cfg(any(feature = "draft08", …, feature =
//! "draft19"))]` on each shared item. **It is not available here**, and the
//! reason is a gate rather than a preference: that list names twelve drafts,
//! and `scripts/check-draft-cfg.py` rule 1 fails any draft-only `cfg(any(...))`
//! in a draft-neutral file that names exactly twelve. Its docstring sets out
//! why — of the long lists in this workspace the fourteens are "any draft at
//! all", the thirteens are rejection lists, and the only twelve ever found was
//! a rejection list with a draft missing from it. This file would be the second
//! twelve and `just draft-cfg` would go red, trading one broken gate for
//! another.
//!
//! And twelve is not even the only list these items would need. `absolute_gate!`
//! is read by drafts 08 through 16, nine; `setup_parameters` by drafts 07
//! through 16, ten; `refusal` by drafts 07, 08, 09, 10 **and** 20, which is not
//! a contiguous range at all. Four different lists across one family of shared
//! helpers, each restating some part of the invocation table at the foot of this
//! file, with nothing holding any of them level with it. That is the drift the
//! `PRIORITY` note in `moqtap-client/src/dispatch.rs::fetch_joining` describes,
//! four times over.
//!
//! An `allow` has no second copy to fall out of step with, and it conceals
//! nothing that matters: any build enabling one of the twelve drafts in the
//! middle reads every item below, so the lints are live on twelve of the
//! fourteen matrix rows and on the default all-drafts build that `just test`
//! and `just clippy` run. What they cover is the build in which these items are
//! *correctly* unread.

#![allow(clippy::items_after_test_module)]

mod common;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyRequest, AnyTransportType, JoiningStart,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
// `FilterType` and `GroupOrder` are read only by the SUBSCRIBE that every
// joining gate sends first, and the two refusing drafts send no SUBSCRIBE. Split
// from the line above so that the allow covers the two dead names and not
// `TrackNamespace`, which `namespace()` reads under every feature set. See "Why
// the shared items below carry `allow` and not `cfg`" in the module docs.
#[allow(unused_imports)]
use moqtap_codec::types::{FilterType, GroupOrder};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The track the subscription every joining fetch names is for.
///
/// Unread by the draft-07 and draft-20 gates, which refuse before a SUBSCRIBE
/// is sent; see the module docs.
#[allow(dead_code)]
const TRACK: &[u8] = b"video";

/// Groups of run-up asked for relatively — Fetch Type `0x2`.
const GROUPS_BEFORE: u64 = 3;

/// The Group asked for absolutely — Fetch Type `0x3`. Deliberately not
/// [`GROUPS_BEFORE`]; see the module docs.
const FROM_GROUP: u64 = 9;

/// Fetch Type `0x2`, Relative Joining, with the offset it must carry.
///
/// Read by `expected!`, and so by the twelve drafts that have a join to write;
/// see the module docs.
#[allow(dead_code)]
const RELATIVE: (u64, u64) = (2, GROUPS_BEFORE);

/// Fetch Type `0x3`, Absolute Joining, with the Group it must carry.
///
/// [`RELATIVE`]'s reason, unchanged.
#[allow(dead_code)]
const ABSOLUTE: (u64, u64) = (3, FROM_GROUP);

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("fixture value fits a varint")
}

/// The namespace the subscription every joining gate names is opened under.
///
/// [`TRACK`]'s reason, unchanged: the two refusing drafts subscribe to nothing.
#[allow(dead_code)]
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn encoded(msg: AnyControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out).expect("encode a control message");
    out
}

/// The sentence a refused `fetch_joining` came back with.
///
/// Spelled out rather than reached through `expect_err`, which needs the `Ok`
/// side to be `Debug` and an [`AnyRequest`] is not: it owns a stream on the
/// drafts from 17, and a handle that could be printed is not what that is.
///
/// Read by the five gates that expect a refusal: draft-07 and draft-20 through
/// `no_joining_gate!`, and drafts 08, 09 and 10 through `absolute_gate!`. That
/// set is not a range — it is the oldest four drafts and the newest one — so
/// the `cfg` this would otherwise take is not even a contiguous list to read,
/// which is the clearest case in this file for the `allow` the module docs
/// argue for.
#[allow(dead_code)]
fn refusal(
    result: Result<AnyRequest, moqtap_client::dispatch::AnyConnectionError>,
    claim: &str,
) -> String {
    match result {
        Ok(_) => panic!("{claim}"),
        Err(e) => e.to_string(),
    }
}

/// The request ceiling drafts 07 through 16 are granted.
///
/// Setup Parameter `0x02` — `max_subscribe_id` through draft-10 and
/// `max_request_id` from draft-11, which is a rename and not a move. Without it
/// the client has no identifier to spend and the SUBSCRIBE never goes out, so
/// the gate would fail before reaching what it is about. Draft-17 deleted the
/// parameter and left the number unassigned, which is why the drafts above it
/// are handed nothing.
///
/// Its readers are exactly the drafts named in the first line — draft-07
/// through `setup_parameters_with_role` below, and drafts 08 through 16 through
/// `control_stream_gate!` — so `--features draft19,draft20`, the newest-two row
/// of `just draft-pairs`, compiles it and calls it nowhere. The `cfg` would be
/// a ten-draft list, and the third distinct list this file's shared items would
/// need between them; see the module docs.
#[allow(dead_code)]
fn setup_parameters() -> Vec<KeyValuePair> {
    vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }]
}

/// Draft-07 alone requires a ROLE; draft-08 withdrew it.
///
/// One draft, one reader, one feature — so this is the one shared item here
/// that takes a `cfg` rather than an `allow`. There is no list to fall out of
/// step with: the sentence above and the condition below say the same thing,
/// and the `no_joining_gate!` invocation that reads it is gated on the same
/// feature.
#[cfg(feature = "draft07")]
fn setup_parameters_with_role() -> Vec<KeyValuePair> {
    let mut value = Vec::new();
    // PubSub: this endpoint both publishes and subscribes.
    v(3).encode(&mut value);
    let mut params = setup_parameters();
    params.push(KeyValuePair { key: v(0x00), value: KvpValue::Bytes(value) });
    params
}

/// A reader that pulls whole control messages off one quinn stream, framed for
/// whichever draft it was built with.
struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream, draft: DraftVersion) -> Self {
        Self { recv, draft, buf: Vec::new() }
    }

    async fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 2048];
        match self.recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
            _ => false,
        }
    }

    async fn read_control(&mut self) -> Option<AnyControlMessage> {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(self.draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    if !self.fill().await {
                        return None;
                    }
                }
                Err(e) => panic!("the peer could not decode what the client wrote: {e}"),
            }
        }
    }
}

/// The setup exchange, in the three shapes the fourteen drafts give it.
///
/// `a_fetch_stream_reads_back_through_the_facade`'s macro, and held for the same
/// reason: dropping the peer's half of the control stream resets it, and the
/// session with it, before the client's requests have been read.
macro_rules! peer_setup {
    (versioned, $conn:ident, $version:ident, $module:ident, $params:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut control = PeerStream::new(recv, DRAFT);
        let client_setup = control.read_control().await.expect("read the client's CLIENT_SETUP");
        let selected = match &client_setup {
            AnyControlMessage::$version(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        send.write_all(&encoded(AnyControlMessage::$version(ControlMessage::ServerSetup(
            ServerSetup { selected_version: selected, parameters: $params },
        ))))
        .await
        .expect("write SERVER_SETUP");
        (send, control)
    }};
    (plain, $conn:ident, $version:ident, $module:ident, $params:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (mut send, recv) = $conn.accept_bi().await.expect("accept_bi");
        let mut control = PeerStream::new(recv, DRAFT);
        control.read_control().await.expect("read the client's CLIENT_SETUP");
        send.write_all(&encoded(AnyControlMessage::$version(ControlMessage::ServerSetup(
            ServerSetup { parameters: $params },
        ))))
        .await
        .expect("write SERVER_SETUP");
        (send, control)
    }};
    (uni, $conn:ident, $version:ident, $module:ident, $params:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, Setup};
        let mut control = PeerStream::new($conn.accept_uni().await.expect("accept_uni"), DRAFT);
        control.read_control().await.expect("read the client's SETUP");
        let mut ours = $conn.open_uni().await.expect("open the peer's control stream");
        ours.write_all(&encoded(AnyControlMessage::$version(ControlMessage::Setup(Setup {
            options: $params,
        }))))
        .await
        .expect("write the peer's SETUP");
        (ours, control)
    }};
}

/// The Request ID a decoded SUBSCRIBE carries, under the name its draft gives
/// the field: `subscribe_id` through draft-10, `request_id` from draft-11.
///
/// Invoked from `control_stream_gate!` and `request_stream_gate!` only, so a
/// build carrying neither defines it and never expands it; see the module docs.
#[allow(unused_macros)]
macro_rules! subscribed_id {
    (subscribe_id, $module:ident, $version:ident, $msg:expr) => {
        match $msg {
            Some(AnyControlMessage::$version(
                moqtap_codec::$module::message::ControlMessage::Subscribe(s),
            )) => s.subscribe_id.into_inner(),
            other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
        }
    };
    (request_id, $module:ident, $version:ident, $msg:expr) => {
        match $msg {
            Some(AnyControlMessage::$version(
                moqtap_codec::$module::message::ControlMessage::Subscribe(s),
            )) => s.request_id.into_inner(),
            other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
        }
    };
}

/// What a decoded FETCH said about the join: its Fetch Type, the Request ID it
/// named and the Joining Start it asked from.
///
/// `flat` is drafts 08 through 10, whose FETCH is one struct with an `Option`
/// per field — so the namespace and the name are asserted absent, because on
/// those drafts a sender could have filled them in. The other arm is drafts 11
/// through 19, where the joining arm of the enum has no such field.
///
/// `subscribed_id!`'s reason for the `allow`, unchanged.
#[allow(unused_macros)]
macro_rules! joining_of {
    (flat, $module:ident, $version:ident, $msg:expr) => {
        match $msg {
            Some(AnyControlMessage::$version(
                moqtap_codec::$module::message::ControlMessage::Fetch(f),
            )) => {
                assert!(
                    f.track_namespace.is_none() && f.track_name.is_none(),
                    "a Joining Fetch leaves the track to the publisher, which takes it from the \
                     subscription this names"
                );
                (
                    f.fetch_type as u64,
                    f.joining_subscribe_id
                        .expect("a joining FETCH names a subscription")
                        .into_inner(),
                    f.preceding_group_offset.expect("a joining FETCH names a start").into_inner(),
                )
            }
            other => panic!("expected a FETCH from the client, got {other:?}"),
        }
    };
    ($field:ident, $module:ident, $version:ident, $msg:expr) => {
        match $msg {
            Some(AnyControlMessage::$version(
                moqtap_codec::$module::message::ControlMessage::Fetch(f),
            )) => match f.fetch_payload {
                moqtap_codec::$module::message::FetchPayload::Joining { $field, joining_start } => {
                    (f.fetch_type as u64, $field.into_inner(), joining_start.into_inner())
                }
                other => panic!("expected a joining FETCH, got {other:?}"),
            },
            other => panic!("expected a FETCH from the client, got {other:?}"),
        }
    };
}

/// One [`JoiningStart`] per form this draft can ask for, in wire order.
macro_rules! forms {
    (relative_only) => {
        vec![JoiningStart::GroupsBefore(GROUPS_BEFORE)]
    };
    (both) => {
        vec![JoiningStart::GroupsBefore(GROUPS_BEFORE), JoiningStart::Group(FROM_GROUP)]
    };
}

/// What those forms must reach the wire as.
///
/// `forms!` above is invoked by the refusing gates too — they ask in both forms
/// and are refused in both — but nothing is read back off the wire there, so
/// this half has no caller on those two drafts. That asymmetry is why one of
/// this pair carries an `allow` and the other does not.
#[allow(unused_macros)]
macro_rules! expected {
    (relative_only) => {
        vec![RELATIVE]
    };
    (both) => {
        vec![RELATIVE, ABSOLUTE]
    };
}

/// The extra gate drafts 08 through 10 carry and no later draft needs.
///
/// Their FETCH offers Fetch Types `0x1` and `0x2`, so the absolute form has no
/// encoding. Refused rather than sent as the relative one, which would ask for
/// the last nine Groups of the track where the caller asked for everything from
/// Group nine — a well-formed message asking a different question, which is what
/// a silent fallback produces.
///
/// Invoked from `control_stream_gate!` alone — by all nine of drafts 08 through
/// 16, since the `both` arm expands to nothing and an invocation that produces
/// no items is still an invocation. So this is unread on a narrower set than
/// the other three shared macros: drafts 17 through 19 leave it defined and
/// uncalled as surely as drafts 07 and 20 do. That second list is the concrete
/// form of the drift argument in the module docs — a `cfg` here would not even
/// be the same `cfg` as the ones above it.
#[allow(unused_macros)]
macro_rules! absolute_gate {
    (relative_only, $handshake:tt, $version:ident, $module:ident) => {
        /// A session with nothing sent on it yet. The refusal happens before a
        /// byte reaches the wire, so the peer has nothing to read and only has
        /// to stay alive: dropping its half of the control stream would end the
        /// session under the call being measured.
        async fn idle_session() -> (AnyConnection, tokio::task::JoinHandle<()>) {
            common::init_crypto();
            let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
            let peer = tokio::spawn(async move {
                let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!($handshake, conn, $version, $module, setup_parameters());
                conn.closed().await;
            });
            let conn = tokio::time::timeout(
                PATIENCE,
                AnyConnection::connect(&addr.to_string(), client_config()),
            )
            .await
            .expect("connect did not finish")
            .expect("connect");
            (conn, peer)
        }

        #[tokio::test]
        async fn an_absolute_join_has_no_fetch_type_on_this_draft() {
            let (mut conn, peer) = idle_session().await;
            let err = refusal(
                tokio::time::timeout(
                    PATIENCE,
                    conn.fetch_joining(v(0), JoiningStart::Group(FROM_GROUP)),
                )
                .await
                .expect("fetch_joining did not finish"),
                "Fetch Type 0x3 arrives in draft-11, so this draft has no absolute form to send",
            );
            assert!(err.contains("Absolute Joining Fetch"), "{err}");
            conn.close(0, b"gate complete");
            tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").ok();
        }
    };
    (both, $handshake:tt, $version:ident, $module:ident) => {};
}

/// One draft that has a Joining Fetch, on the bidirectional control stream:
/// drafts 08 through 16.
///
/// `$handshake` picks the setup exchange, `$sub_id` names the SUBSCRIBE's own id
/// field, `$field` names the FETCH's joining-id field (or `flat` for the three
/// drafts with no payload enum), and `$forms` is what this draft can be asked.
macro_rules! control_stream_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, $sub_id:tt, $field:tt,
     $forms:tt) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn client_config() -> AnyClientConfig {
                AnyClientConfig {
                    draft: DRAFT,
                    additional_versions: Vec::new(),
                    transport: AnyTransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: setup_parameters(),
                }
            }

            /// Complete the handshake, read the SUBSCRIBE and then one FETCH per
            /// form, and report the subscription's id beside what each join
            /// said.
            async fn serve(server: quinn::Endpoint, sends: usize) -> (u64, Vec<(u64, u64, u64)>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (_send, mut control) =
                    peer_setup!($handshake, conn, $version, $module, setup_parameters());

                let subscribed =
                    subscribed_id!($sub_id, $module, $version, control.read_control().await);
                let mut joins = Vec::new();
                for _ in 0..sends {
                    joins.push(joining_of!(
                        $field,
                        $module,
                        $version,
                        control.read_control().await
                    ));
                }
                (subscribed, joins)
            }

            /// Every form of the join this draft has reaches the wire as this
            /// draft writes it.
            #[tokio::test]
            async fn a_joining_fetch_names_the_subscription_and_the_start_it_was_given() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let asked: Vec<JoiningStart> = forms!($forms);
                let peer = tokio::spawn(serve(endpoint, asked.len()));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                // Held for the whole gate: an `AnyRequest` is a live request,
                // and from draft-17 it owns the stream its message went out on.
                let mut held: Vec<AnyRequest> = Vec::new();
                held.push(
                    tokio::time::timeout(
                        PATIENCE,
                        conn.subscribe(
                            namespace(),
                            TRACK.to_vec(),
                            128,
                            GroupOrder::Ascending,
                            FilterType::LargestObject,
                        ),
                    )
                    .await
                    .expect("subscribe did not finish")
                    .expect("subscribe"),
                );
                let joined = held[0].request_id();

                for start in asked {
                    held.push(
                        tokio::time::timeout(PATIENCE, conn.fetch_joining(joined, start))
                            .await
                            .expect("fetch_joining did not finish")
                            .expect("fetch_joining"),
                    );
                }

                let (subscribed, joins) = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    subscribed,
                    joined.into_inner(),
                    "the handle's Request ID is the one the SUBSCRIBE put on the wire, which is \
                     what makes the assertion below about a real subscription"
                );
                for (_, names, _) in &joins {
                    assert_eq!(
                        *names, subscribed,
                        "every join names the subscription the caller passed, and a publisher \
                         takes the track and the end from it"
                    );
                }
                assert_eq!(
                    joins.iter().map(|(kind, _, start)| (*kind, *start)).collect::<Vec<_>>(),
                    expected!($forms),
                    "{DRAFT:?} writes the Fetch Type beside the Joining Start, and the same \
                     varint means Groups of run-up under 0x2 and a Group number under 0x3"
                );
            }

            absolute_gate!($forms, $handshake, $version, $module);
        }
    };
}

/// One draft whose control plane is a pair of unidirectional streams and whose
/// every request owns a bidirectional stream of its own: drafts 17 through 19.
macro_rules! request_stream_gate {
    ($module:ident, $feat:literal, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn client_config() -> AnyClientConfig {
                AnyClientConfig {
                    draft: DRAFT,
                    additional_versions: Vec::new(),
                    transport: AnyTransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                }
            }

            /// Complete the handshake, then read the SUBSCRIBE off one request
            /// stream and a FETCH off each of the next two.
            async fn serve(server: quinn::Endpoint) -> (u64, Vec<(u64, u64, u64)>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!(uni, conn, $version, $module, Vec::new());

                let (_answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request, DRAFT);
                let subscribed =
                    subscribed_id!(request_id, $module, $version, request.read_control().await);

                let mut joins = Vec::new();
                for _ in 0..2 {
                    let (_answer, request) = conn.accept_bi().await.expect("accept_bi");
                    let mut request = PeerStream::new(request, DRAFT);
                    joins.push(joining_of!(
                        joining_request_id,
                        $module,
                        $version,
                        request.read_control().await
                    ));
                }
                (subscribed, joins)
            }

            #[tokio::test]
            async fn a_joining_fetch_names_the_subscription_and_the_start_it_was_given() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                // Held for the whole gate, and on these drafts that is
                // load-bearing rather than tidy: dropping the subscription's
                // handle resets its stream, which is how a subscriber ends a
                // subscription from draft-17 — and would end the very
                // subscription the two fetches name.
                let mut held: Vec<AnyRequest> = Vec::new();
                held.push(
                    tokio::time::timeout(
                        PATIENCE,
                        conn.subscribe(
                            namespace(),
                            TRACK.to_vec(),
                            128,
                            GroupOrder::Ascending,
                            FilterType::LargestObject,
                        ),
                    )
                    .await
                    .expect("subscribe did not finish")
                    .expect("subscribe"),
                );
                let joined = held[0].request_id();

                for start in forms!(both) {
                    held.push(
                        tokio::time::timeout(PATIENCE, conn.fetch_joining(joined, start))
                            .await
                            .expect("fetch_joining did not finish")
                            .expect("fetch_joining"),
                    );
                }

                let (subscribed, joins) = tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                assert_eq!(
                    subscribed,
                    joined.into_inner(),
                    "the handle's Request ID is the one the SUBSCRIBE put on the wire"
                );
                for (_, names, _) in &joins {
                    assert_eq!(
                        *names, subscribed,
                        "every join names the subscription the caller passed"
                    );
                }
                assert_eq!(
                    joins.iter().map(|(kind, _, start)| (*kind, *start)).collect::<Vec<_>>(),
                    expected!(both),
                    "{DRAFT:?} writes the Fetch Type beside the Joining Start, and the same \
                     varint means Groups of run-up under 0x2 and a Group number under 0x3"
                );
            }
        }
    };
}

/// One draft with no Joining Fetch to send, and the sentence that says why.
///
/// A gate rather than an omission: "this draft cannot" is the measurement on
/// draft-07 and draft-20, and an entry point that quietly sent something
/// adjacent would be worse than one that refuses.
macro_rules! no_joining_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, $params:expr,
     $because:literal, $claim:literal) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            fn client_config() -> AnyClientConfig {
                AnyClientConfig {
                    draft: DRAFT,
                    additional_versions: Vec::new(),
                    transport: AnyTransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: $params,
                }
            }

            /// Complete the handshake and hold the session open. Nothing is read
            /// because nothing is sent: the refusal happens before a byte.
            async fn serve(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!($handshake, conn, $version, $module, $params);
                conn.closed().await;
            }

            #[tokio::test]
            async fn this_draft_has_no_joining_fetch_to_send() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                for start in forms!(both) {
                    let err = refusal(
                        tokio::time::timeout(PATIENCE, conn.fetch_joining(v(0), start))
                            .await
                            .expect("fetch_joining did not finish"),
                        $claim,
                    );
                    assert!(err.contains($because), "{err}");
                }

                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer).await.expect("the peer hung").ok();
            }
        }
    };
}

// ── The two drafts with nothing to send ─────────────────────────────────────

no_joining_gate!(
    draft07,
    "draft07",
    Draft07,
    versioned,
    setup_parameters_with_role(),
    "no Fetch Type field",
    "draft-07's FETCH cannot ask for a join"
);

no_joining_gate!(
    draft20,
    "draft20",
    Draft20,
    uni,
    Vec::new(),
    "Section 10.13",
    "draft-20 deleted the joining mechanism"
);

// ── Drafts 08 through 10: one joining Fetch Type, and a flat FETCH ──────────

control_stream_gate!(draft08, "draft08", Draft08, versioned, subscribe_id, flat, relative_only);
control_stream_gate!(draft09, "draft09", Draft09, versioned, subscribe_id, flat, relative_only);
control_stream_gate!(draft10, "draft10", Draft10, versioned, subscribe_id, flat, relative_only);

// ── Drafts 11 through 16: both forms, on the bidirectional control stream ───
//
// Draft-11 alone spells the field `joining_subscribe_id`; draft-12 renamed it
// with the rest of the Subscribe ID to Request ID sweep, and the name is all
// that changed.

control_stream_gate!(
    draft11,
    "draft11",
    Draft11,
    versioned,
    request_id,
    joining_subscribe_id,
    both
);
control_stream_gate!(draft12, "draft12", Draft12, versioned, request_id, joining_request_id, both);
control_stream_gate!(draft13, "draft13", Draft13, versioned, request_id, joining_request_id, both);
control_stream_gate!(draft14, "draft14", Draft14, versioned, request_id, joining_request_id, both);
control_stream_gate!(draft15, "draft15", Draft15, plain, request_id, joining_request_id, both);
control_stream_gate!(draft16, "draft16", Draft16, plain, request_id, joining_request_id, both);

// ── Drafts 17 through 19: a request stream per request ──────────────────────

request_stream_gate!(draft17, "draft17", Draft17);
request_stream_gate!(draft18, "draft18", Draft18);
request_stream_gate!(draft19, "draft19", Draft19);

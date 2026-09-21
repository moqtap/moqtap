#![cfg(any(
    feature = "draft07",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]

//! An object that says a track ended somewhere the track has already passed,
//! over QUIC, at the eight drafts that permit it.
//!
//! Six drafts call that a protocol error and end the session over it. Draft-13
//! Section 9.2.1.1 is the last of them: "An object with this status that has a
//! Group ID less than any other GroupID, or an ObjectID less than or equal to
//! the largest in the specified group, is a protocol error, and the receiver
//! MUST terminate the session."
//! `an_end_of_track_object_says_where_the_track_ended.rs` enforces that on every
//! one of the six. Here the same traffic is asserted to be **accepted**: the
//! object comes back to the caller, and no session ends.
//!
//! The eight divide into one draft that never had the rule and seven that
//! withdrew it. They are in one file because what is asserted of them is
//! identical; how they came to permit it is not.
//!
//! # Draft-07, which the condition was added *to*
//!
//! Draft-07 Section 7.1.1.1 describes where a 0x4 sits and stops there:
//! "Indicates end of Track and Group. GroupID is one greater than the largest
//! group produced in this track and the ObjectId is one greater than the largest
//! object produced in that group." Draft-08 keeps the status number and adds the
//! sentence that makes a placement wrong. **The drafts a rule is absent from are
//! not the drafts that dropped it**, and this is the one where the mistaken
//! commit is likeliest, because the status code is the same as the neighbouring
//! draft's and that is exactly what invites its wiring to be carried back.
//!
//! Read the description before deciding what conforming looks like here: it asks
//! for the Group ID one greater *and* the Object ID one greater than the largest
//! in that group, where draft-08 splits those across two statuses — so the group
//! it names is one nothing has been produced in, and there is no placement
//! either neighbouring draft would call conforming to copy.
//!
//! # Drafts 14 through 20: two withdrawals, and neither deleted the paragraph
//!
//! Drafts 14 and 15 keep the description and drop the consequence. Draft-14
//! Section 10.2.1.1 still says where an end-of-track object sits — "Group ID is
//! either the largest Group produced in this Track with Object ID one greater
//! than the largest Object produced in that Group, or Group ID is one greater
//! than the largest Group produced in this Track with Object ID zero" — and then
//! says, in place of the protocol error, "Publishers MUST NOT publish an Object
//! with a Location larger than this Location". That is a rule about the objects
//! that come *after* the end, addressed to the publisher, and the section it
//! points at answers it with Malformed Tracks rather than with a close.
//!
//! Drafts 16 through 20 drop the description too. Draft-16 Section 10.2.1.1,
//! word for word on draft-19 Section 11.2.1.1: "Indicates End of Track.
//! Indicates that no objects with the location that is equal to or greater than
//! the one specified exist." No ordering, no receiver, no consequence.
//!
//! # The bullet that survives both, and the four words draft-18 took out of it
//!
//! All six carry a Malformed Tracks condition that reads like this rule and is
//! not. Draft-14 Section 2.5, renumbered to Section 2.4.2 from draft-15: "An
//! Object is received on a Track whose Group and Object ID are larger than the
//! final Object in the Track." *Larger* — it is about objects arriving after the
//! end-of-track object, where this file's traffic ends with one. Draft-18
//! Section 2.4.2 then shortens it to "An Object is received whose Group and
//! Object ID are larger than the final Object in the Track", losing the words
//! that scoped it to a track.
//!
//! That is the second time a Malformed Tracks bullet has lost its scope in a
//! draft that withdrew the rule beside it, and the first was missed too: draft-16
//! took "from the same Track" out of the forwarding-preference bullet in the
//! same draft as it made the preference the Object's.
//! `an_object_carries_its_own_forwarding_preference.rs` is what makes that a
//! failing test rather than a plausible commit, and this file is the same thing
//! for this rule.
//!
//! # Why the alias is bound though nothing records it
//!
//! Every gate takes the subscription to its answer, which is what binds the
//! Track Alias the objects carry, even though on these drafts nothing is
//! written down about the track afterwards. A rule of this shape is reached by
//! resolving an object's alias to the track a live subscription gave it to, so
//! an alias no binding names settles nothing — and a gate that never bound one
//! would go on passing after somebody added the rule here. The ablation below is
//! what says this one can fail.
//!
//! # Two topologies, one assertion
//!
//! Draft-07 and drafts 14, 15 and 16 put SETUP and every request on one
//! bidirectional stream. Drafts 17 through 20 put control on a pair of
//! unidirectional streams
//! and every request at the front of a bidirectional stream of its own. A peer
//! that reads a SUBSCRIBE off the control stream reads nothing at all on the
//! second group, so there are two peers here — and the three tests are written
//! once, against whatever each peer has connected. The assertion is shared and
//! the peer cannot be.
//!
//! # Both paths, and why the track never mixes them
//!
//! An end-of-track object arrives on a subgroup stream or in a datagram, and one
//! gate per draft runs the whole track on datagrams. The whole track, not just
//! the ending: draft-07 and drafts 14 and 15 still hold a track to a single
//! Object Forwarding Preference, so a datagram for a track whose objects have
//! used a subgroup stream is refused there by that rule before this one is
//! reached.
//! A track's record is only ever fed by one framing.
//!
//! # Ablation, measured
//!
//! The cut is the commit this file exists to stop: the end-of-track placement
//! record drafts 08 through 13 carry, wired into a draft from each topology
//! exactly as they wire it — draft-15's endpoint and both of its readers, and
//! draft-18's. One draft from each, because a peer is only proved by a draft it
//! serves. Applied to the working tree, run, and reverted with every file
//! compared byte for byte afterwards; `scratchpad/r84_ablate.py` runs it, and
//! `scratchpad/r85_ablate.py` runs the same cut against draft-07.
//!
//! Draft-07, where the wiring is carried back one draft rather than forward six,
//! and `object_role` reads 0x4 the way drafts 11 through 13 read it:
//!
//! ```text
//! Section 7.1.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 4, object: 0, placement: GroupBehind { largest_group: 5 } })
//! Section 7.1.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 5, object: 2, placement: ObjectBehind { largest_object: 2 } })
//! Section 7.1.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 4, object: 0, placement: GroupBehind { largest_group: 5 } })
//! ```
//!
//! Draft-15: the Group ID half of the withdrawn condition, then the Object ID
//! half, then the same track carried by datagrams.
//!
//! ```text
//! Section 10.2.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 4, object: 0, placement: GroupBehind { largest_group: 5 } })
//! Section 10.2.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 5, object: 2, placement: ObjectBehind { largest_object: 2 } })
//! Section 10.2.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 4, object: 0, placement: GroupBehind { largest_group: 5 } })
//! ```
//!
//! Draft-18, the same three against the other peer:
//!
//! ```text
//! Section 11.2.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 4, object: 0, placement: GroupBehind { largest_group: 5 } })
//! Section 11.2.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 5, object: 2, placement: ObjectBehind { largest_object: 2 } })
//! Section 11.2.1.1 states no condition on where an end-of-track object sits, so one naming a group the track has already carried is legal here: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 4, object: 0, placement: GroupBehind { largest_group: 5 } })
//! ```
//!
//! Every one of the nine names alias 7, which is the alias the SUBSCRIBE's
//! answer bound — on draft-07 too, where the SUBSCRIBE carries the alias itself
//! and the answer is what establishes the subscription that keeps it live. That is the other half of the ablation: a rule reached by resolving an
//! alias to a track can only report one it resolved, so a gate that had skipped
//! the answer would have stayed green under the same cut.

mod common;

use std::time::Duration;

/// How long a test waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough that a close on its way would have arrived, short enough that a
/// gate expecting none does not sit on it.
const BRIEF: Duration = Duration::from_millis(400);

/// The alias the track is known by on the wire.
const ALIAS: u64 = 7;

const TRACK: &[u8] = b"one-track";

/// The group and object the track reaches before anything says it ended.
///
/// Both are above zero so that an object naming a group or an object below them
/// has somewhere to go.
const REACHED_GROUP: u64 = 5;
const REACHED_OBJECT: u64 = 2;

/// Object Status 0x4, end of Track, on every draft here.
const END_OF_TRACK: u64 = 0x4;

/// What the peer puts on the wire once the subscription is bound.
///
/// Plain numbers, so one description serves both topologies and the per-draft
/// macro only has to know how to spell an object.
#[derive(Debug, Clone, Copy)]
struct Traffic {
    /// The end-of-track object's Group ID and Object ID. Its status is
    /// [`END_OF_TRACK`] in every gate here — the placement is what varies.
    ending: (u64, u64),
    /// Whether the whole track is carried by datagrams rather than by subgroup
    /// streams.
    ///
    /// Both objects or neither: two of these drafts hold a track to one
    /// framing, so a gate that settled the track with a stream and ended it
    /// with a datagram would be refused there by that rule instead of reaching
    /// this one.
    on_datagrams: bool,
}

impl Traffic {
    /// A track that says it ended at `group`, `object`, on subgroup streams.
    const fn ending_at(group: u64, object: u64) -> Self {
        Self { ending: (group, object), on_datagrams: false }
    }

    /// The same track, carried by datagrams from end to end.
    const fn on_datagrams(self) -> Self {
        Self { on_datagrams: true, ..self }
    }
}

/// A quinn receive stream with a buffer in front of it, for the peer that
/// serves the drafts whose control plane is unidirectional.
///
/// It decodes with `moqtap-codec` and never calls the framing helpers in
/// `moqtap-client`: a peer assembled out of the code under test could not
/// disagree with it.
///
/// `allow(dead_code)` rather than a `cfg` naming those drafts. Only the
/// `unidirectional_control_gates!` invocations below use it, and a second list
/// of the same drafts is one nothing checks: it was `draft17`–`draft19` when
/// draft-20 joined them, and the build broke on the draft nobody added here.
/// Nothing in this type is draft-specific — `AnyControlMessage::decode` takes
/// the draft as an argument — so it compiles wherever it is left standing.
#[allow(dead_code)]
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

#[allow(dead_code)]
impl PeerStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, buf: Vec::new() }
    }

    /// Pull more bytes in. `false` once the stream has ended or failed.
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

    /// Decode one whole control message, type field included.
    ///
    /// On these drafts a control stream's leading varint *is* its first
    /// message's type field, so this reads the SETUP off the front of the
    /// stream with nothing skipped — and the SUBSCRIBE off the front of a
    /// request stream the same way.
    async fn read_control(
        &mut self,
        draft: moqtap_codec::version::DraftVersion,
    ) -> Option<moqtap_codec::dispatch::AnyControlMessage> {
        use moqtap_codec::dispatch::AnyControlMessage;
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                // Two errors mean "not enough bytes yet", and which one it is
                // depends on where the message ran out. A body that stops short
                // is `UnexpectedEnd`; a message whose leading type varint has
                // not arrived fails inside the varint decoder before there is a
                // message to be short, which is what every read before the
                // first one gives.
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    if !self.fill().await {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

/// Everything that does not depend on the topology: the traffic, the wait that
/// says no session ended, the read that says the object arrived, and the three
/// gates.
///
/// `$obj` names how this draft's subgroup object is spelled, `$eot` the name it
/// gives Object Status 0x4 — draft-07 calls it end of Track *and Group* — and
/// `$section` the section carrying the Object Status table.
#[macro_export]
macro_rules! ends_common {
    ($obj:tt, $eot:ident, $section:literal) => {
        /// Put the track on the wire: the object it reaches, and then the
        /// object that says where it ended.
        ///
        /// The two subgroup streams carry different Subgroup IDs. A group may
        /// be carried by several subgroups and the two objects can share a
        /// group here, so one ID for both would be two streams for one
        /// subgroup, which is a different rule.
        async fn send_the_track(conn: &quinn::Connection, traffic: Traffic) {
            let (group, object) = traffic.ending;
            if traffic.on_datagrams {
                conn.send_datagram(datagram_bytes(REACHED_GROUP, REACHED_OBJECT, None).into())
                    .expect("send the object the track reached");
                conn.send_datagram(datagram_bytes(group, object, Some(ObjectStatus::$eot)).into())
                    .expect("send the end-of-track object");
            } else {
                // The first stream is written and finished before the second is
                // opened, so the two arrive in the order the client reads them
                // in.
                let mut reached = conn.open_uni().await.expect("open the first data stream");
                reached
                    .write_all(&subgroup_stream_bytes(REACHED_GROUP, 0, REACHED_OBJECT, None, b"x"))
                    .await
                    .expect("write the object the track reached");
                reached.finish().expect("finish the first data stream");

                let mut ending = conn.open_uni().await.expect("open the second data stream");
                ending
                    .write_all(&subgroup_stream_bytes(
                        group,
                        1,
                        object,
                        Some(ObjectStatus::$eot),
                        b"",
                    ))
                    .await
                    .expect("write the end-of-track object");
                ending.finish().expect("finish the second data stream");
            }
        }

        /// The peer's half of every gate: the session is still standing when
        /// the traffic has been read.
        async fn expect_no_close(conn: &quinn::Connection) {
            if let Ok(reason) = tokio::time::timeout(BRIEF, conn.closed()).await {
                panic!(
                    concat!(
                        "Section ",
                        $section,
                        " states no condition on where an end-of-track object sits, so \
                         nothing here ends a session; it ended with {:?}"
                    ),
                    reason
                );
            }
        }

        /// Drive one gate: connect, subscribe, read the object the track
        /// reached, and then read the object that says where it ended.
        ///
        /// The second read is the assertion. It is `expect` rather than a
        /// discarded result because an endpoint that had this rule would refuse
        /// there, and it names the object it got back so that a gate cannot
        /// pass on a client that accepted *something*.
        async fn read_the_track(traffic: Traffic) -> (Connection, tokio::task::JoinHandle<()>) {
            let (conn, peer) = connected(traffic).await;
            let (group, object) = traffic.ending;

            if traffic.on_datagrams {
                let (reached, _) = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the peer's first datagram never arrived")
                    .expect("an ordinary object breaks no rule here");
                let meta = reached.meta();
                assert_eq!(
                    (meta.track_alias, meta.group_id, meta.object_id),
                    (ALIAS, REACHED_GROUP, REACHED_OBJECT),
                    "the first datagram is the one carrying the object the track reached"
                );

                let (ending, _) = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the peer's second datagram never arrived")
                    .expect(concat!(
                        "Section ",
                        $section,
                        " states no condition on where an end-of-track object sits, so one \
                         naming a group the track has already carried is legal here"
                    ));
                let meta = ending.meta();
                assert_eq!(
                    (meta.track_alias, meta.group_id, meta.object_id, meta.status),
                    (ALIAS, group, object, Some(END_OF_TRACK)),
                    "the datagram that came back is not the end-of-track object the peer sent"
                );
            } else {
                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the peer's first data stream never arrived")
                        .expect("read the first subgroup header");
                assert_eq!(
                    (header.track_alias(), header.group_id()),
                    (ALIAS, REACHED_GROUP),
                    "the first stream is the one carrying the object the track reached"
                );
                tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                    .await
                    .expect("the object the track reached never arrived")
                    .expect("an ordinary object breaks no rule here");

                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the peer's second data stream never arrived")
                        .expect("read the second subgroup header");
                assert_eq!(
                    header.group_id(),
                    group,
                    "the second stream is the one carrying the end-of-track object"
                );
                let ending = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                    .await
                    .expect("the end-of-track object never arrived")
                    .expect(concat!(
                        "Section ",
                        $section,
                        " states no condition on where an end-of-track object sits, so one \
                         naming a group the track has already carried is legal here"
                    ));
                assert_eq!(
                    $crate::ends_read_back!($obj, ending),
                    (object, Some(ObjectStatus::$eot)),
                    "the object that came back is not the end-of-track object the peer sent"
                );
            }

            (conn, peer)
        }

        async fn finish(peer: tokio::task::JoinHandle<()>) {
            tokio::time::timeout(PATIENCE * 3, peer)
                .await
                .expect("peer task hung")
                .expect("peer task panicked");
        }

        /// An end-of-track object naming a group the track has already carried
        /// is accepted.
        ///
        /// The Group ID half of the condition six earlier drafts state, and the
        /// traffic they end a session over.
        #[tokio::test]
        async fn an_end_of_track_object_behind_the_track_is_accepted() {
            let (_conn, peer) = read_the_track(Traffic::ending_at(REACHED_GROUP - 1, 0)).await;
            finish(peer).await;
        }

        /// An end-of-track object at the largest object in its own group is
        /// accepted.
        ///
        /// The other half of the same condition, and the half a Group ID check
        /// alone would miss: this one names the right group.
        #[tokio::test]
        async fn an_end_of_track_object_inside_its_own_group_is_accepted() {
            let (_conn, peer) =
                read_the_track(Traffic::ending_at(REACHED_GROUP, REACHED_OBJECT)).await;
            finish(peer).await;
        }

        /// The whole track again, carried by datagrams.
        ///
        /// The second data path, and the one a connection can see whole. Both
        /// objects are datagrams because two of these drafts still hold a track
        /// to one framing — see the module documentation.
        #[tokio::test]
        async fn a_track_carried_by_datagrams_is_accepted_the_same_way() {
            let (_conn, peer) =
                read_the_track(Traffic::ending_at(REACHED_GROUP - 1, 0).on_datagrams()).await;
            finish(peer).await;
        }
    };
}

/// One draft's gates, where SETUP and every request travel on one bidirectional
/// stream.
///
/// `$draft` is the draft's module in both crates, `$version` its [`DraftVersion`]
/// and dispatch variant, and `$section` the section carrying the Object Status
/// table. The rest name the shapes that differ across the four: `$cfg`,
/// `$setup` and `$params` for the session, `$sub`, `$ok` and `$idfield` for the
/// subscription that binds the alias, and `$hdr`, `$obj`, `$dgram` and `$eot`
/// for the four things a track's objects are spelled with.
macro_rules! bidirectional_control_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt, $ok:tt,
     $idfield:tt, $params:tt, $hdr:tt, $obj:tt, $dgram:tt, $eot:ident,
     $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            #[allow(unused_imports)]
            use moqtap_codec::types::{ContentExists, GroupOrder};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};
            use moqtap_codec::$draft::types::ObjectStatus;

            use crate::{
                Traffic, ALIAS, BRIEF, END_OF_TRACK, PATIENCE, REACHED_GROUP, REACHED_OBJECT, TRACK,
            };

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            /// A ceiling large enough that no refusal here can be the
            /// ceiling's, plus whatever else the draft insists on.
            fn setup_parameters() -> Vec<KeyValuePair> {
                // Nothing to add on three of the four, and nothing that needs a
                // second `Vec` on the one that does.
                #[allow(unused_mut)]
                let mut out = vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }];
                crate::ends_extra_setup_parameters!($params, out);
                out
            }

            fn client_config() -> ClientConfig {
                crate::ends_config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::ends_server_setup_for!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// The Request ID the client's SUBSCRIBE carried, or a panic naming
            /// what arrived instead.
            fn request_id_of(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => {
                        crate::ends_request_id_of!($idfield, s)
                    }
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// A subgroup stream for one group of the track, carrying one
            /// object.
            ///
            /// The object goes through the codec's own writer, so the delta
            /// encoding these drafts give an Object ID is the codec's and not
            /// this test's idea of it.
            fn subgroup_stream_bytes(
                group: u64,
                subgroup: u64,
                object: u64,
                object_status: Option<ObjectStatus>,
                payload: &[u8],
            ) -> Vec<u8> {
                let header =
                    crate::ends_subgroup_header_for!($hdr, $draft, v(ALIAS), v(group), v(subgroup));
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header.clone())
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                crate::ends_write_object!(
                    $obj,
                    $draft,
                    header,
                    buf,
                    v(object),
                    object_status,
                    payload
                );
                buf
            }

            /// The same object, carried by a datagram.
            fn datagram_bytes(
                group: u64,
                object: u64,
                object_status: Option<ObjectStatus>,
            ) -> Vec<u8> {
                let header = crate::ends_datagram_for!(
                    $dgram,
                    $draft,
                    v(ALIAS),
                    v(group),
                    v(object),
                    object_status
                );
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                buf
            }

            /// Serve one connection: complete the setup exchange, answer the
            /// client's SUBSCRIBE with the Track Alias, carry the track as far
            /// as [`REACHED_GROUP`] and [`REACHED_OBJECT`], and then say it
            /// ended where `traffic` says.
            async fn serve(server: quinn::Endpoint, traffic: Traffic) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                let reply = crate::ends_subscribe_ok_for!($ok, request_id_of(&request), v(ALIAS));
                send.write_all(&encode(ControlMessage::SubscribeOk(reply)))
                    .await
                    .expect("write SUBSCRIBE_OK");

                send_the_track(&conn, traffic).await;
                expect_no_close(&conn).await;
            }

            /// A connected client whose SUBSCRIBE has been answered, and the
            /// task serving it.
            async fn connected(traffic: Traffic) -> (Connection, tokio::task::JoinHandle<()>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, traffic));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                crate::ends_subscribe_for!($sub, conn, namespace(), TRACK, v(ALIAS))
                    .await
                    .expect("subscribe");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("the answer carrying the alias never arrived")
                    .expect("dispatch SUBSCRIBE_OK");
                (conn, peer)
            }

            crate::ends_common!($obj, $eot, $section);
        }
    };
}

/// One draft's gates, where control travels on a pair of unidirectional streams
/// and every request opens a bidirectional stream of its own.
///
/// These three share every shape a gate needs, so the only thing that varies is
/// the draft itself and the section its Object Status table is numbered under.
macro_rules! unidirectional_control_gates {
    ($draft:ident, $feat:literal, $version:ident, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, Setup, SubscribeOk};
            use moqtap_codec::$draft::types::ObjectStatus;

            use crate::{
                PeerStream, Traffic, ALIAS, BRIEF, END_OF_TRACK, PATIENCE, REACHED_GROUP,
                REACHED_OBJECT, TRACK,
            };

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            fn client_config() -> ClientConfig {
                ClientConfig {
                    draft: DraftVersion::$version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                }
            }

            /// The peer's SETUP. Its message type is also its stream's type, so
            /// these bytes go on a fresh unidirectional stream with no header in
            /// front of them.
            fn setup_bytes() -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::Setup(Setup { options: Vec::new() }))
                    .encode(&mut out)
                    .expect("encode SETUP");
                out
            }

            /// The answer that binds the alias. On these drafts a response
            /// carries no Request ID — the stream it comes back on is the
            /// correlation — so this is the whole of it.
            fn subscribe_ok_bytes() -> Vec<u8> {
                let ok = SubscribeOk {
                    track_alias: v(ALIAS),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                };
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::SubscribeOk(ok))
                    .encode(&mut out)
                    .expect("encode SUBSCRIBE_OK");
                out
            }

            /// A subgroup stream for one group of the track, carrying one
            /// object.
            ///
            /// The object goes through the codec's own writer, so the delta
            /// encoding these drafts give an Object ID is the codec's and not
            /// this test's idea of it.
            fn subgroup_stream_bytes(
                group: u64,
                subgroup: u64,
                object: u64,
                object_status: Option<ObjectStatus>,
                payload: &[u8],
            ) -> Vec<u8> {
                let header =
                    crate::ends_subgroup_header_for!(byte, $draft, v(ALIAS), v(group), v(subgroup));
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header.clone())
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                crate::ends_write_object!(
                    measured,
                    $draft,
                    header,
                    buf,
                    v(object),
                    object_status,
                    payload
                );
                buf
            }

            /// The same object, carried by a datagram.
            fn datagram_bytes(
                group: u64,
                object: u64,
                object_status: Option<ObjectStatus>,
            ) -> Vec<u8> {
                let header = crate::ends_datagram_for!(
                    prop,
                    $draft,
                    v(ALIAS),
                    v(group),
                    v(object),
                    object_status
                );
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                buf
            }

            /// Serve one connection: complete the setup exchange, answer the
            /// client's SUBSCRIBE with the Track Alias, carry the track as far
            /// as [`REACHED_GROUP`] and [`REACHED_OBJECT`], and then say it
            /// ended where `traffic` says.
            ///
            /// Every stream the peer opened or accepted is held until this
            /// returns. Dropping a quinn send stream resets it, and on these
            /// drafts a request stream's reset is how a request is withdrawn —
            /// so letting the SUBSCRIBE's stream fall out of scope early would
            /// cancel the subscription, free the alias, and leave the objects
            /// naming a track that no longer resolves.
            async fn serve(server: quinn::Endpoint, traffic: Traffic) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"));
                control
                    .read_control(DraftVersion::$version)
                    .await
                    .expect("read the client's SETUP");

                let mut our_control =
                    conn.open_uni().await.expect("open the peer's control stream");
                our_control.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request);
                match request.read_control(DraftVersion::$version).await {
                    Some(AnyControlMessage::$version(ControlMessage::Subscribe(_))) => {}
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
                answer.write_all(&subscribe_ok_bytes()).await.expect("write SUBSCRIBE_OK");

                send_the_track(&conn, traffic).await;
                expect_no_close(&conn).await;
            }

            /// A connected client whose SUBSCRIBE has been answered, and the
            /// task serving it.
            ///
            /// The answer is read off the request stream it went out on, which
            /// is what carries it into the endpoint and binds the alias. Its
            /// Track Alias is asserted here rather than taken on trust: a peer
            /// that answered with a different one would leave every later
            /// assertion about a track this client never heard of.
            async fn connected(traffic: Traffic) -> (Connection, tokio::task::JoinHandle<()>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, traffic));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut request = tokio::time::timeout(
                    PATIENCE,
                    conn.subscribe(namespace(), TRACK.to_vec(), Vec::new()),
                )
                .await
                .expect("subscribe did not finish")
                .expect("subscribe");

                let answer =
                    tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
                        .await
                        .expect("the answer carrying the alias never arrived")
                        .expect("read SUBSCRIBE_OK");
                match answer {
                    ControlMessage::SubscribeOk(ok) => assert_eq!(
                        ok.track_alias.into_inner(),
                        ALIAS,
                        "the alias the objects name is the one this answer bound"
                    ),
                    other => panic!("expected a SUBSCRIBE_OK, got {other:?}"),
                }
                (conn, peer)
            }

            crate::ends_common!(measured, EndOfTrack, $section);
        }
    };
}

/// `ClientConfig`, in the two shapes it takes across the three drafts whose
/// control plane is bidirectional.
#[macro_export]
macro_rules! ends_config_for {
    (early, $version:expr, $params:expr) => {
        ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (both, $version:expr, $params:expr) => {
        ClientConfig {
            draft: $version,
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (late, $version:expr, $params:expr) => {
        ClientConfig {
            draft: $version,
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
}

/// The setup parameters a draft insists on beyond the request ceiling.
///
/// Draft-07 alone requires a ROLE of both endpoints in both directions before a
/// session is usable — draft-08 withdrew it — so a session there never reaches
/// the point where a data stream could arrive without one.
#[macro_export]
macro_rules! ends_extra_setup_parameters {
    (with_role, $out:expr) => {{
        let mut value = Vec::new();
        VarInt::from_usize(3).encode(&mut value); // PubSub
        $out.push(KeyValuePair { key: VarInt::from_usize(0x00), value: KvpValue::Bytes(value) });
    }};
    (plain, $out:expr) => {{
        let _ = &$out;
    }};
}

/// SERVER_SETUP, with and without the Selected Version drafts 15 and 16
/// dropped.
#[macro_export]
macro_rules! ends_server_setup_for {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// What a SUBSCRIBE calls the identifier it carries.
#[macro_export]
macro_rules! ends_request_id_of {
    (subscribe_id, $s:expr) => {
        $s.subscribe_id
    };
    (request_id, $s:expr) => {
        $s.request_id
    };
}

/// `Connection::subscribe`, in the three shapes it takes across those four.
///
/// Draft-07 carries the Track Alias in the SUBSCRIBE itself; the rest wait for
/// it in the answer, and take `$alias` only to be ignored.
#[macro_export]
macro_rules! ends_subscribe_for {
    (alias_ft, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {
        $conn.subscribe(
            $alias,
            $ns,
            $name.to_vec(),
            128,
            GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
        )
    };
    (filter, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    }};
    (params, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe($ns, $name.to_vec(), Vec::new())
    }};
}

/// SUBSCRIBE_OK, in the three shapes those three drafts give the answer that
/// carries the alias.
#[macro_export]
macro_rules! ends_subscribe_ok_for {
    (split, $id:expr, $alias:expr) => {{
        // Draft-07 names the largest location in two fields rather than one,
        // and its SUBSCRIBE_OK carries no Track Alias at all: the SUBSCRIBE
        // this answers is what bound it.
        let _ = $alias;
        SubscribeOk {
            subscribe_id: $id,
            expires: VarInt::from_u64(0).unwrap(),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_group_id: None,
            largest_object_id: None,
            parameters: Vec::new(),
        }
    }};
    (rich, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            expires: VarInt::from_u64(0).unwrap(),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $alias:expr) => {
        SubscribeOk { request_id: $id, track_alias: $alias, parameters: Vec::new() }
    };
    (ext, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// A conforming subgroup header, in the two shapes it takes across these drafts.
///
/// Every one names an explicit Subgroup ID and carries neither extensions nor
/// properties, which is the plainest stream each draft can carry.
#[macro_export]
macro_rules! ends_subgroup_header_for {
    (plain, $draft:ident, $alias:expr, $group:expr, $subgroup:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            track_alias: $alias,
            group_id: $group,
            subgroup_id: $subgroup,
            publisher_priority: 128,
        }
    };
    (opt, $draft:ident, $alias:expr, $group:expr, $subgroup:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::SubgroupStreamType::from_flags(
                true, false, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            subgroup_id: Some($subgroup),
            publisher_priority: 128,
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr, $subgroup:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            // The subgroup base (0x10) with the explicit Subgroup ID bit
            // (0x04): nothing per-object, no end-of-group, priority present.
            header_type: 0x14,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: $subgroup,
            publisher_priority: Some(128),
        }
    };
}

/// One object onto the stream `$header` opened, in the three shapes it takes.
///
/// Two of them go through the codec's own `SubgroupObjectReader`, so the delta
/// encoding those drafts give an Object ID is the codec's and not this test's
/// idea of it. Draft-07 has no such reader and needs none: its Object IDs are
/// absolute, so the object is a header and a payload written straight out.
#[macro_export]
macro_rules! ends_write_object {
    (staged, $draft:ident, $header:expr, $buf:expr, $object:expr, $status:expr, $payload:expr) => {{
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&$header);
        writer
            .write_object(
                &moqtap_codec::$draft::data_stream::SubgroupObject {
                    object_id: $object,
                    extension_headers: Vec::new(),
                    status: $status,
                    payload: $payload.to_vec(),
                },
                &mut $buf,
            )
            .expect("encode the object");
    }};
    (measured, $draft:ident, $header:expr, $buf:expr, $object:expr, $status:expr, $payload:expr) => {{
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&$header);
        writer
            .write_object(
                &moqtap_codec::$draft::data_stream::SubgroupObject {
                    object_id: $object,
                    extension_headers: Vec::new(),
                    payload_length: VarInt::from_usize($payload.len()),
                    object_status: $status,
                    payload: $payload.to_vec(),
                },
                &mut $buf,
            )
            .expect("encode the object");
    }};
    (bare, $draft:ident, $header:expr, $buf:expr, $object:expr, $status:expr, $payload:expr) => {{
        let _ = &$header;
        moqtap_codec::$draft::data_stream::ObjectHeader {
            object_id: $object,
            payload_length: VarInt::from_usize($payload.len()),
            // The status field is not optional on this draft, and Normal is
            // what an object carrying a payload has.
            object_status: $status.unwrap_or(ObjectStatus::Normal),
        }
        .encode_checked(&mut $buf)
        .expect("encode the object header");
        $buf.extend_from_slice($payload);
    }};
}

/// The Object ID and status of an object the client decoded, in the shapes the
/// four drafts hand back.
///
/// Draft-07 returns the header beside the payload and types its status
/// unconditionally; the rest flatten the two and leave the status optional,
/// because an object carrying a payload has no status field on the wire.
#[macro_export]
macro_rules! ends_read_back {
    (staged, $object:expr) => {
        ($object.object_id.into_inner(), $object.status)
    };
    (measured, $object:expr) => {
        ($object.object_id.into_inner(), $object.object_status)
    };
    (bare, $object:expr) => {
        ($object.header.object_id.into_inner(), Some($object.header.object_status))
    };
}

/// A datagram, in the three shapes it takes across these drafts.
///
/// One helper for both of the objects a gate sends: a status turns a payload
/// datagram into a status one, which is a different framing on every draft
/// here, and an object with a status other than Normal may carry no payload.
#[macro_export]
macro_rules! ends_datagram_for {
    (status_len, $draft:ident, $alias:expr, $group:expr, $object:expr, $status:expr) => {{
        let status: Option<ObjectStatus> = $status;
        // Draft-07 has one datagram layout and hangs the status off a declared
        // payload length of zero, so there is no second framing to choose here
        // and no type field to set.
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                object_status: status.unwrap_or(ObjectStatus::Normal),
                payload_length: VarInt::from_usize(0),
            },
        )
    }};
    (typed, $draft:ident, $alias:expr, $group:expr, $object:expr, $status:expr) => {{
        let status: Option<ObjectStatus> = $status;
        moqtap_codec::$draft::data_stream::DatagramObject {
            datagram_type: match status {
                Some(_) => moqtap_codec::$draft::data_stream::DatagramType::status(false),
                None => {
                    moqtap_codec::$draft::data_stream::DatagramType::payload(true, false, false)
                }
            },
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers: Vec::new(),
            status,
            payload: Vec::new(),
        }
    }};
    (byte, $draft:ident, $alias:expr, $group:expr, $object:expr, $status:expr) => {{
        let status: Option<ObjectStatus> = $status;
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // A payload datagram with the Object ID written, the priority
            // present and no extensions; the status bit (0x20) is what puts a
            // status code on the wire in place of a payload.
            datagram_type: if status.is_some() { 0x20 } else { 0x00 },
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(128),
            extension_headers: Vec::new(),
            object_status: status,
        }
    }};
    (prop, $draft:ident, $alias:expr, $group:expr, $object:expr, $status:expr) => {{
        let status: Option<ObjectStatus> = $status;
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // The same byte, against a draft that calls the per-object block
            // properties rather than extension headers.
            datagram_type: if status.is_some() { 0x20 } else { 0x00 },
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(128),
            properties: Vec::new(),
            object_status: status,
        }
    }};
}

bidirectional_control_gates!(
    draft07,
    "draft07",
    Draft07,
    early,
    versioned,
    alias_ft,
    split,
    subscribe_id,
    with_role,
    plain,
    bare,
    status_len,
    EndOfTrackAndGroup,
    "7.1.1.1"
);
bidirectional_control_gates!(
    draft14, "draft14", Draft14, both, versioned, filter, rich, request_id, plain, opt, staged,
    typed, EndOfTrack, "10.2.1.1"
);
bidirectional_control_gates!(
    draft15, "draft15", Draft15, late, plain, params, plain, request_id, plain, byte, measured,
    byte, EndOfTrack, "10.2.1.1"
);
bidirectional_control_gates!(
    draft16, "draft16", Draft16, late, plain, params, ext, request_id, plain, byte, measured, byte,
    EndOfTrack, "10.2.1.1"
);

unidirectional_control_gates!(draft17, "draft17", Draft17, "10.2.1.1");
unidirectional_control_gates!(draft18, "draft18", Draft18, "11.2.1.1");
unidirectional_control_gates!(draft19, "draft19", Draft19, "11.2.1.1");
unidirectional_control_gates!(draft20, "draft20", Draft20, "11.2.1.1");
unidirectional_control_gates!(draft21, "draft21", Draft21, "11.1.2");

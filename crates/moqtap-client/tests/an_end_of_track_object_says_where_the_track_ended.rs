#![cfg(any(
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13"
))]

//! An object that says a track ended somewhere the track has already passed,
//! over QUIC, at the six drafts that call that a protocol error.
//!
//! Draft-11 Section 9.1.1.1 states it, and drafts 12 and 13 repeat it word for
//! word: Object Status 0x4 "Indicates end of Track. GroupID is either the
//! largest group produced in this track and the ObjectID is one greater than the
//! largest object produced in that group, or GroupID is one greater than the
//! largest group produced in this track and the ObjectID is zero. This status
//! also indicates the last group has ended. An object with this status that has
//! a Group ID less than any other GroupID, or an ObjectID less than or equal to
//! the largest in the specified group, is a protocol error, and the receiver
//! MUST terminate the session."
//!
//! Drafts 08, 09 and 10 spell the same prohibition against a 0x4 that means end
//! of Track *and Group*, and carry a second status beside it — 0x5, end of Track
//! — whose Group ID condition is one notch stricter: "a Group ID less than or
//! equal to any other Group ID". Draft-11 folded the two statuses together and
//! kept the looser condition, which is why three drafts here have four gates and
//! three have six.
//!
//! # Two streams, because the rule is the track's and not the stream's
//!
//! A subgroup stream names one group for everything on it, so an object that
//! ends the track at a group behind where the track reached cannot be on the
//! same stream as the object it is behind. Every gate here therefore opens two
//! subgroup streams for one track: the first carries an ordinary object and is
//! what the track has reached, the second carries the end-of-track object. A
//! record kept per stream would find nothing to measure the second against and
//! would accept all of this.
//!
//! # What is asserted, and why the accepting gates are not padding
//!
//! Two of the six drafts' gates assert an *acceptance* — an end-of-track object
//! exactly one past the largest object in the largest group, and on drafts 08
//! through 10 a 0x5 at the group after the last. A check that refused every
//! end-of-track object would pass every refusing gate in this file. Those two
//! are what say the line is where the draft puts it rather than somewhere
//! stricter.
//!
//! The refusing gates assert three things and none implies the others: the
//! report names which half of the condition was broken *and* what it was
//! measured against; `close_for_data_stream` carries it; and the peer reads
//! PROTOCOL_VIOLATION off the wire.
//!
//! # Both paths, and why they are never crossed
//!
//! An end-of-track object arrives on a subgroup stream or in a datagram, and the
//! two reach the record differently — a datagram is a whole object the
//! connection can see, and a subgroup object is read off a stream handle the
//! caller owns. So one gate per draft runs the whole thing on datagrams.
//!
//! It runs on datagrams *entirely*, and the first cut of it did not: it settled
//! where the track had reached with a subgroup stream and then sent the
//! end-of-track object as a datagram, which is the crossing the two paths could
//! differ on. That traffic cannot happen. These same six drafts state that
//! "Every Track has a single 'Object Forwarding Preference' and the Original
//! Publisher MUST NOT mix different forwarding preferences within a single
//! track", so a datagram for a track whose objects have used a subgroup stream
//! is refused before this rule is reached — the gate failed with a
//! mixed-framing report rather than a placement one. **A track's record is only
//! ever fed by one framing**, on every draft that has a record at all, and the
//! crossing is unreachable rather than untested.
//!
//! # Drafts 07 and 14 through 20
//!
//! Not here, and not by omission. Draft-07's 0x4 has no ordering condition at
//! all and its 0x5 is end of Subgroup, a different status. Draft-14 replaced the
//! condition with a forward-looking prohibition on the publisher — "Publishers
//! MUST NOT publish an Object with a Location larger than this Location" —
//! answered through Malformed Tracks rather than by ending the session, and
//! drafts 16 through 20 rewrote the entry as a bare statement of absence with no
//! condition in it.
//!
//! # Ablations, measured
//!
//! Each cut was applied to the working tree, run under the one draft it
//! concerns, and reverted with the file compared byte for byte afterwards;
//! `scratchpad/r83_ablate.py` runs them.
//!
//! Dropping the call that measures a subgroup stream's objects, in draft-09's
//! `read_subgroup_object` — and, separately, the call in draft-12's
//! `accept_subgroup_stream` that hands the stream the record in the first place.
//! Two different edits, one message, which is the point of keeping them apart:
//! having the check is not having anything to check against.
//!
//! ```text
//! Section 8.1.1.1 calls an end-of-track object behind the track a protocol error, and it was accepted: ()
//! Section 9.2.1.1 calls an end-of-track object behind the track a protocol error, and it was accepted: ()
//! ```
//!
//! Dropping the datagram half, in draft-10's `recv_datagram`:
//!
//! ```text
//! Section 9.1.1.1 calls an end-of-track object behind the track a protocol error, and it was accepted: ()
//! ```
//!
//! Dropping the Group ID half of the condition. The object is still refused —
//! by the *other* half, which is why the gate asserts on which half fired and
//! not merely that something did:
//!
//! ```text
//! assertion `left == right` failed: the report should name which half of the condition was broken, and what the object was measured against
//!   left: ObjectBehind { largest_object: 2 }
//!  right: GroupBehind { largest_group: 5 }
//! ```
//!
//! Reading the Object ID half as "less than" where the draft says "less than or
//! equal to", which is the whole of the boundary:
//!
//! ```text
//! Section 9.1.1.1 calls an end-of-track object behind the track a protocol error, and it was accepted: ()
//! ```
//!
//! And one notch the other way, refusing an object exactly where the draft puts
//! the end of a track — the cut only the accepting gate can see:
//!
//! ```text
//! Section 9.2.1.1 puts the end of a track one past the largest object in its largest group: Endpoint(EndOfTrackOutOfPlace { alias: 7, group: 5, object: 3, placement: ObjectBehind { largest_object: 2 } })
//! ```
//!
//! Giving the stricter of drafts 08 through 10's two statuses the looser
//! condition, which is the merge draft-11 made and these three had not:
//!
//! ```text
//! Section 8.1.1.1 calls an end-of-track object behind the track a protocol error, and it was accepted: ()
//! ```
//!
//! Taking the rule out of draft-13's close table:
//!
//! ```text
//! Section 9.2.1.1 answers this with a protocol error, but close_for_data_stream declined
//! ```

mod common;

use std::time::Duration;

/// How long a test waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough that a close on its way would have arrived, short enough that a
/// gate expecting none does not sit on it.
const BRIEF: Duration = Duration::from_millis(400);

/// Session termination code `Protocol Violation`.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// The alias the track is known by on the wire.
const ALIAS: u64 = 7;

const TRACK: &[u8] = b"one-track";

/// The group and object the track reaches before anything says it ended.
///
/// Both are above zero so that a gate naming a group or object below them has
/// somewhere to go.
const REACHED_GROUP: u64 = 5;
const REACHED_OBJECT: u64 = 2;

/// Object Status 0x4: end of Track and Group on drafts 08 through 10, end of
/// Track from draft-11.
const ENDS_AT_LAST_GROUP: u64 = 0x4;

/// Object Status 0x5, end of Track, which only drafts 08, 09 and 10 assign.
///
/// Unread in a build enabling one of the three drafts that folded it into 0x4.
#[allow(dead_code)]
const ENDS_AFTER_LAST_GROUP: u64 = 0x5;

/// What the peer puts on the wire once the subscription is bound.
///
/// Plain numbers, so one description serves all six drafts and the per-draft
/// macro only has to know how to spell an object.
#[derive(Debug, Clone, Copy)]
struct Traffic {
    /// The end-of-track object: its Group ID, its Object ID, and its status.
    ending: (u64, u64, u64),
    /// Whether the whole track is carried by datagrams rather than by subgroup
    /// streams.
    ///
    /// Both objects or neither: a track may not mix the two framings on these
    /// drafts, so a gate that settled the track with a stream and ended it with
    /// a datagram would be refused by that rule before reaching this one.
    on_datagrams: bool,
    /// Whether the peer should expect the session to end.
    closes: bool,
}

impl Traffic {
    /// An end-of-track object on a stream, expected to be refused.
    const fn refused(group: u64, object: u64, status: u64) -> Self {
        Self { ending: (group, object, status), on_datagrams: false, closes: true }
    }

    /// An end-of-track object on a stream, expected to be accepted.
    const fn accepted(group: u64, object: u64, status: u64) -> Self {
        Self { ending: (group, object, status), on_datagrams: false, closes: false }
    }

    /// The same track, carried by datagrams from end to end.
    const fn on_datagrams(self) -> Self {
        Self { on_datagrams: true, ..self }
    }
}

/// One draft's gates. `$draft` is the draft's module in both crates, `$version`
/// its [`DraftVersion`] and dispatch variant, and `$section` the section
/// carrying the Object Status table.
///
/// The rest name the shapes that differ across the six: `$cfg` and `$setup` for
/// the session, `$sub`, `$bind`, `$ok` and `$idfield` for the subscription that
/// binds the alias, and `$hdr`, `$obj`, `$status_dgram` for the three things a
/// track's objects are spelled with. `$statuses` says whether this draft has
/// one end-of-track status or two.
macro_rules! end_of_track_gate {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt, $bind:tt,
     $ok:tt, $idfield:tt, $hdr:tt, $obj:tt, $payload_dgram:tt, $status_dgram:tt,
     $statuses:tt, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::track_locations::EndOfTrackPlacement;
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, TransportType,
            };
            use moqtap_client::$draft::endpoint::EndpointError;
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::data_stream::{
                Datagram, DatagramHeader, DatagramStatusHeader, ObjectHeader,
            };
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};
            use moqtap_codec::$draft::types::ObjectStatus;

            /// `ENDS_AFTER_LAST_GROUP` is read only by the two gates drafts 11
            /// through 13 do not have.
            #[allow(unused_imports)]
            use crate::{
                Traffic, ALIAS, BRIEF, ENDS_AFTER_LAST_GROUP, ENDS_AT_LAST_GROUP, PATIENCE,
                PROTOCOL_VIOLATION, REACHED_GROUP, REACHED_OBJECT, TRACK,
            };

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            /// A ceiling large enough that no refusal here can be the
            /// ceiling's.
            fn setup_parameters() -> Vec<KeyValuePair> {
                vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }]
            }

            fn client_config() -> ClientConfig {
                crate::eot_config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::eot_server_setup_for!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            fn request_id_of(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => {
                        crate::eot_request_id_of!($idfield, s)
                    }
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            fn status(code: u64) -> ObjectStatus {
                ObjectStatus::from_u64(code).expect("a status this draft assigns")
            }

            /// A subgroup stream for one group of the track, carrying one
            /// object.
            ///
            /// `subgroup` distinguishes the two streams a gate opens for the
            /// same group: a group may be carried by several subgroups, and two
            /// streams for one subgroup would break a different rule.
            fn subgroup_stream_bytes(
                group: u64,
                subgroup: u64,
                object: u64,
                object_status: u64,
                payload: &[u8],
            ) -> Vec<u8> {
                let header =
                    crate::eot_subgroup_header_for!($hdr, $draft, v(ALIAS), v(group), v(subgroup));
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header)
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                let header = crate::eot_object_for!(
                    $obj,
                    v(object),
                    v(payload.len() as u64),
                    status(object_status)
                );
                header.encode_checked(&mut buf).expect("encode the object header");
                buf.extend_from_slice(payload);
                buf
            }

            /// An ordinary object, carried by a datagram: what the track
            /// reaches on the gate that runs entirely on datagrams.
            fn payload_datagram_bytes(group: u64, object: u64) -> Vec<u8> {
                let header = crate::eot_payload_datagram_for!(
                    $payload_dgram,
                    $draft,
                    v(ALIAS),
                    v(group),
                    v(object)
                );
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(Datagram::Payload(header))
                    .encode(&mut buf)
                    .expect("encode the datagram");
                buf
            }

            /// The same end-of-track object, carried by a datagram.
            ///
            /// A status datagram and not a payload one: an object with a status
            /// other than Normal MUST have an empty payload, and on every draft
            /// here that is a framing of its own.
            fn datagram_bytes(group: u64, object: u64, object_status: u64) -> Vec<u8> {
                let header = crate::eot_status_datagram_for!(
                    $status_dgram,
                    v(ALIAS),
                    v(group),
                    v(object),
                    status(object_status)
                );
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(Datagram::Status(header))
                    .encode(&mut buf)
                    .expect("encode the datagram");
                buf
            }

            /// Serve one connection: complete the setup exchange, bind the
            /// alias, carry the track as far as [`REACHED_GROUP`] and
            /// [`REACHED_OBJECT`], and then say it ended where `traffic` says.
            async fn serve(server: quinn::Endpoint, traffic: Traffic) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                crate::eot_answer_subscribe!($bind, $ok, send, request_id_of(&request));

                let (group, object, object_status) = traffic.ending;
                if traffic.on_datagrams {
                    conn.send_datagram(
                        payload_datagram_bytes(REACHED_GROUP, REACHED_OBJECT).into(),
                    )
                    .expect("send the object the track reached");
                    conn.send_datagram(datagram_bytes(group, object, object_status).into())
                        .expect("send the end-of-track object");
                } else {
                    // The first stream is written and finished before the second
                    // is opened, so the two arrive in the order the client reads
                    // them in.
                    let mut reached = conn.open_uni().await.expect("open the first data stream");
                    reached
                        .write_all(&subgroup_stream_bytes(
                            REACHED_GROUP,
                            0,
                            REACHED_OBJECT,
                            0x0,
                            b"x",
                        ))
                        .await
                        .expect("write the object the track reached");
                    reached.finish().expect("finish the first data stream");

                    let mut ending = conn.open_uni().await.expect("open the second data stream");
                    ending
                        .write_all(&subgroup_stream_bytes(group, 1, object, object_status, b""))
                        .await
                        .expect("write the end-of-track object");
                    ending.finish().expect("finish the second data stream");
                }

                if traffic.closes {
                    let reason = tokio::time::timeout(PATIENCE, conn.closed()).await.expect(
                        "the client was told the track ended in the wrong place and \
                                 never closed",
                    );
                    match reason {
                        quinn::ConnectionError::ApplicationClosed(frame) => {
                            assert_eq!(
                                u64::from(frame.error_code),
                                PROTOCOL_VIOLATION,
                                concat!(
                                    "Section ",
                                    $section,
                                    " answers this with a protocol error; the close carried \
                                     {} instead"
                                ),
                                u64::from(frame.error_code)
                            );
                            let text = String::from_utf8_lossy(&frame.reason).to_string();
                            assert!(
                                text.contains("out of place"),
                                "the close reason should name the rule that was broken; \
                                 got {text:?}"
                            );
                        }
                        other => panic!("expected an application close, got {other:?}"),
                    }
                } else if let Ok(reason) = tokio::time::timeout(BRIEF, conn.closed()).await {
                    panic!(
                        concat!(
                            "Section ",
                            $section,
                            " puts this end-of-track object where the track ended, so nothing \
                             here ends a session; it ended with {:?}"
                        ),
                        reason
                    );
                }
            }

            /// Drive one gate: connect, subscribe, read the object the track
            /// reached, and then read the object that says where it ended.
            ///
            /// The two objects are read in the order the peer wrote them. The
            /// first stream is finished before the second is opened, and the
            /// group each header names is checked on the way past, so a
            /// transport that delivered them the other way round fails saying so
            /// rather than by reporting nothing.
            async fn read_the_track(
                traffic: Traffic,
            ) -> (Connection, tokio::task::JoinHandle<()>, Result<(), ConnectionError>) {
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

                crate::eot_subscribe_for!($sub, conn, namespace(), TRACK, v(ALIAS))
                    .await
                    .expect("subscribe");
                crate::eot_await_binding!($bind, conn);

                let outcome = if traffic.on_datagrams {
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
                    tokio::time::timeout(PATIENCE, conn.recv_datagram())
                        .await
                        .expect("the peer's second datagram never arrived")
                        .map(|_| ())
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
                        traffic.ending.0,
                        "the second stream is the one carrying the end-of-track object"
                    );
                    tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                        .await
                        .expect("the end-of-track object never arrived")
                        .map(|_| ())
                };
                (conn, peer, outcome)
            }

            /// The report, with the half of the condition it broke and what it
            /// was measured against.
            fn expect_placement(
                outcome: Result<(), ConnectionError>,
                expected: EndOfTrackPlacement,
            ) -> ConnectionError {
                let err = outcome.expect_err(concat!(
                    "Section ",
                    $section,
                    " calls an end-of-track object behind the track a protocol error, and it \
                     was accepted"
                ));
                match &err {
                    ConnectionError::Endpoint(EndpointError::EndOfTrackOutOfPlace {
                        alias,
                        placement,
                        ..
                    }) => {
                        assert_eq!(
                            *alias, ALIAS,
                            "the report should name the alias the object \
                                                   carried"
                        );
                        assert_eq!(
                            *placement, expected,
                            "the report should name which half of the condition was broken, and \
                             what the object was measured against"
                        );
                    }
                    other => panic!("expected an end-of-track placement report, got {other:?}"),
                }
                err
            }

            async fn finish(peer: tokio::task::JoinHandle<()>) {
                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// An end-of-track object one past the largest object in the largest
            /// group is where the track ended, and is accepted.
            ///
            /// The gate the refusing ones cannot do without: a check that
            /// refused every end-of-track object would pass all of those and
            /// fail only this.
            #[tokio::test]
            async fn a_track_that_ends_where_it_reached_is_accepted() {
                let (_conn, peer, outcome) = read_the_track(Traffic::accepted(
                    REACHED_GROUP,
                    REACHED_OBJECT + 1,
                    ENDS_AT_LAST_GROUP,
                ))
                .await;
                outcome.expect(concat!(
                    "Section ",
                    $section,
                    " puts the end of a track one past the largest object in its largest group"
                ));
                finish(peer).await;
            }

            /// An end-of-track object naming a group the track has already
            /// carried is refused.
            #[tokio::test]
            async fn an_end_of_track_object_behind_the_track_is_refused() {
                let (conn, peer, outcome) =
                    read_the_track(Traffic::refused(REACHED_GROUP - 1, 0, ENDS_AT_LAST_GROUP))
                        .await;
                let err = expect_placement(
                    outcome,
                    EndOfTrackPlacement::GroupBehind { largest_group: REACHED_GROUP },
                );
                assert!(
                    conn.close_for_data_stream(&err),
                    concat!(
                        "Section ",
                        $section,
                        " answers this with a protocol error, but close_for_data_stream declined"
                    )
                );
                finish(peer).await;
            }

            /// An end-of-track object at or behind the largest object in its own
            /// group is refused.
            ///
            /// The other half of the condition, and the half a Group ID check
            /// alone would miss: this one names the right group.
            #[tokio::test]
            async fn an_end_of_track_object_inside_its_own_group_is_refused() {
                let (conn, peer, outcome) = read_the_track(Traffic::refused(
                    REACHED_GROUP,
                    REACHED_OBJECT,
                    ENDS_AT_LAST_GROUP,
                ))
                .await;
                let err = expect_placement(
                    outcome,
                    EndOfTrackPlacement::ObjectBehind { largest_object: REACHED_OBJECT },
                );
                assert!(
                    conn.close_for_data_stream(&err),
                    concat!(
                        "Section ",
                        $section,
                        " answers this with a protocol error, but close_for_data_stream declined"
                    )
                );
                finish(peer).await;
            }

            /// The whole rule again, with the track carried by datagrams.
            ///
            /// The second data path, and the one the connection can measure
            /// without help from the caller. Both objects are datagrams because
            /// a track may not mix the two framings on these drafts - see the
            /// module documentation.
            #[tokio::test]
            async fn a_track_carried_by_datagrams_is_measured_the_same_way() {
                let (conn, peer, outcome) = read_the_track(
                    Traffic::refused(REACHED_GROUP - 1, 0, ENDS_AT_LAST_GROUP).on_datagrams(),
                )
                .await;
                let err = expect_placement(
                    outcome,
                    EndOfTrackPlacement::GroupBehind { largest_group: REACHED_GROUP },
                );
                assert!(
                    conn.close_for_data_stream(&err),
                    concat!(
                        "Section ",
                        $section,
                        " answers this with a protocol error, but close_for_data_stream declined"
                    )
                );
                finish(peer).await;
            }

            crate::eot_second_status_gates!($statuses, $section);
        }
    };
}

/// The two gates for the second end-of-track status, on the three drafts that
/// have one.
///
/// Draft-11 folded status 0x5 into 0x4 and kept 0x4's looser condition, so on
/// drafts 11 through 13 there is no status whose Group ID must be *past* every
/// group — and asserting one there would be this file inventing a rule those
/// drafts merged away.
#[macro_export]
macro_rules! eot_second_status_gates {
    (one, $section:literal) => {};
    (two, $section:literal) => {
        /// Status 0x5 may not reuse the track's last group, where 0x4 may.
        ///
        /// The same Group ID that
        /// [`a_track_that_ends_where_it_reached_is_accepted`] carries on a 0x4,
        /// refused here because this status names the group *after* the last.
        /// Two statuses, one record, two lines.
        #[tokio::test]
        async fn the_second_end_of_track_status_may_not_reuse_the_last_group() {
            let (conn, peer, outcome) =
                read_the_track(Traffic::refused(REACHED_GROUP, 0, ENDS_AFTER_LAST_GROUP)).await;
            let err = expect_placement(
                outcome,
                EndOfTrackPlacement::GroupBehind { largest_group: REACHED_GROUP },
            );
            assert!(
                conn.close_for_data_stream(&err),
                concat!(
                    "Section ",
                    $section,
                    " answers this with a protocol error, but close_for_data_stream declined"
                )
            );
            finish(peer).await;
        }

        /// Status 0x5 at the group after the last is where the track ended.
        #[tokio::test]
        async fn the_second_end_of_track_status_after_the_last_group_is_accepted() {
            let (_conn, peer, outcome) =
                read_the_track(Traffic::accepted(REACHED_GROUP + 1, 0, ENDS_AFTER_LAST_GROUP))
                    .await;
            outcome.expect(concat!(
                "Section ",
                $section,
                " puts this status one group past the largest the track produced"
            ));
            finish(peer).await;
        }
    };
}

/// `ClientConfig`, in the one shape these six drafts share.
#[macro_export]
macro_rules! eot_config_for {
    (early, $version:expr, $params:expr) => {
        ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
}

/// SERVER_SETUP.
#[macro_export]
macro_rules! eot_server_setup_for {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
}

/// What a SUBSCRIBE calls the identifier it carries.
#[macro_export]
macro_rules! eot_request_id_of {
    (subscribe_id, $s:expr) => {
        $s.subscribe_id
    };
    (request_id, $s:expr) => {
        $s.request_id
    };
}

/// `Connection::subscribe`, in the four shapes it takes across the six drafts.
///
/// The first two carry the Track Alias; the rest wait for it in the answer.
#[macro_export]
macro_rules! eot_subscribe_for {
    (alias_ft, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {
        $conn.subscribe(
            $alias,
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
        )
    };
    (alias_varint, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {
        $conn.subscribe(
            $alias,
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
        )
    };
    (varint, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            Vec::new(),
        )
    }};
    (filter, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    }};
}

/// SUBSCRIBE_OK, for the two drafts that carry the alias in it.
#[macro_export]
macro_rules! eot_subscribe_ok_for {
    (rich, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            expires: VarInt::from_u64(0).unwrap(),
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            content_exists: moqtap_codec::types::ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
}

/// The peer's half of binding the alias.
#[macro_export]
macro_rules! eot_answer_subscribe {
    (in_subscribe, $ok:tt, $send:expr, $id:expr) => {{
        let _ = $id;
    }};
    (in_answer, $ok:tt, $send:expr, $id:expr) => {{
        let reply = $crate::eot_subscribe_ok_for!($ok, $id, v(ALIAS));
        $send
            .write_all(&encode(ControlMessage::SubscribeOk(reply)))
            .await
            .expect("write SUBSCRIBE_OK");
    }};
}

/// The client's half of the same.
#[macro_export]
macro_rules! eot_await_binding {
    (in_subscribe, $conn:expr) => {{}};
    (in_answer, $conn:expr) => {{
        tokio::time::timeout(PATIENCE, $conn.recv_and_dispatch())
            .await
            .expect("the answer carrying the alias never arrived")
            .expect("dispatch SUBSCRIBE_OK");
    }};
}

/// A conforming subgroup header, in the two shapes it takes across the six.
///
/// Every one names an explicit Subgroup ID and no extensions, which is the
/// plainest stream each draft can carry.
#[macro_export]
macro_rules! eot_subgroup_header_for {
    (plain, $draft:ident, $alias:expr, $group:expr, $subgroup:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            track_alias: $alias,
            group_id: $group,
            subgroup_id: $subgroup,
            publisher_priority: 128,
        }
    };
    (typed, $draft:ident, $alias:expr, $group:expr, $subgroup:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::StreamType::SubgroupExplicit,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: $subgroup,
            publisher_priority: 128,
        }
    };
}

/// A subgroup object header, in the two shapes it takes: draft-08 counts its
/// extensions and the rest measure them in bytes.
#[macro_export]
macro_rules! eot_object_for {
    (counted, $object:expr, $len:expr, $status:expr) => {
        ObjectHeader {
            object_id: $object,
            extension_count: VarInt::from_usize(0),
            extensions: Vec::new(),
            payload_length: $len,
            object_status: $status,
        }
    };
    (measured, $object:expr, $len:expr, $status:expr) => {
        ObjectHeader {
            object_id: $object,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            payload_length: $len,
            object_status: $status,
        }
    };
}

/// A payload datagram - an ordinary object - in the three shapes it takes.
///
/// Every one carries no extensions and an empty payload, so nothing about it can
/// be refused for a reason that is not this rule.
#[macro_export]
macro_rules! eot_payload_datagram_for {
    (counted, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        DatagramHeader {
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_count: VarInt::from_usize(0),
            extensions: Vec::new(),
            object_status: moqtap_codec::$draft::types::ObjectStatus::Normal,
            payload_length: VarInt::from_usize(0),
        }
    };
    (measured, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        DatagramHeader {
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
        }
    };
    (grouped, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        DatagramHeader {
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            end_of_group: false,
        }
    };
}

/// A status datagram, in the same two shapes.
#[macro_export]
macro_rules! eot_status_datagram_for {
    (counted, $alias:expr, $group:expr, $object:expr, $status:expr) => {
        DatagramStatusHeader {
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            object_status: $status,
        }
    };
    (measured, $alias:expr, $group:expr, $object:expr, $status:expr) => {
        DatagramStatusHeader {
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            object_status: $status,
        }
    };
}

end_of_track_gate!(
    draft08,
    "draft08",
    Draft08,
    early,
    versioned,
    alias_ft,
    in_subscribe,
    none,
    subscribe_id,
    plain,
    counted,
    counted,
    counted,
    two,
    "8.1.1.1"
);
end_of_track_gate!(
    draft09,
    "draft09",
    Draft09,
    early,
    versioned,
    alias_ft,
    in_subscribe,
    none,
    subscribe_id,
    plain,
    measured,
    measured,
    measured,
    two,
    "8.1.1.1"
);
end_of_track_gate!(
    draft10,
    "draft10",
    Draft10,
    early,
    versioned,
    alias_ft,
    in_subscribe,
    none,
    subscribe_id,
    plain,
    measured,
    measured,
    measured,
    two,
    "9.1.1.1"
);
end_of_track_gate!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    alias_varint,
    in_subscribe,
    none,
    request_id,
    typed,
    measured,
    measured,
    measured,
    one,
    "9.1.1.1"
);
end_of_track_gate!(
    draft12, "draft12", Draft12, early, versioned, varint, in_answer, rich, request_id, typed,
    measured, grouped, measured, one, "9.2.1.1"
);
end_of_track_gate!(
    draft13, "draft13", Draft13, early, versioned, filter, in_answer, rich, request_id, typed,
    measured, grouped, measured, one, "9.2.1.1"
);

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
    feature = "draft16"
))]

//! A publisher that sends one track's objects on a subgroup stream and then in
//! a datagram, over QUIC, at ten drafts that answer it three different ways.
//!
//! Draft-11 Section 9 states the rule: "Every Track has a single 'Object
//! Forwarding Preference' and the Original Publisher MUST NOT mix different
//! forwarding preferences within a single track." Nine drafts say that in those
//! words. What separates them is the sentence after it, and the separation is
//! the whole reason this is one file rather than nine.
//!
//! # Three eras, and the era is what the gate measures
//!
//! Drafts 07 through 11 finish the paragraph with a close and a code — "it
//! SHOULD close the session with an error of 'Protocol Violation'" — so there
//! the peer reads a CONNECTION_CLOSE carrying 0x3 off the wire.
//!
//! Drafts 12 through 15 replace that sentence with a cross-reference to
//! Malformed Tracks, where the answer is "it MUST UNSUBSCRIBE from the Track
//! and SHOULD deliver an error to the application" rather than a close. There
//! the client reports the mixing and the peer observes that the session is
//! still standing.
//!
//! Draft-16 withdraws the rule outright, so the mixing is accepted and nothing
//! is reported at all. That is not this file guessing at a silence: draft-16
//! Section 10.2.1 replaced draft-15's "Note that the Original Publisher
//! determines the Forwarding Preference for the entire Track" with "Object
//! Forwarding Preference is a property of an individual Object and can vary
//! among Objects in the same Track", and in the same draft the Malformed Tracks
//! bullet lost its scope, becoming "An Object is received with a different
//! Forwarding Preference than previously observed" where draft-15 had "...
//! than previously observed from the same Track". Both edits arrived together
//! and both point the same way.
//!
//! # Why the peer answers the SUBSCRIBE on some drafts and not others
//!
//! The record is keyed on the *track*, which means the Track Alias in an
//! arriving header has to resolve to one. On drafts 07 through 11 the alias
//! travels in the SUBSCRIBE, so it is bound the moment the client sends one and
//! the peer need not answer. From draft-12 it travels in the answer, so there
//! the peer must send a SUBSCRIBE_OK carrying it or the client has an alias
//! that names nothing and the rule is never reached — which would be a gate
//! passing over a track it never identified.
//!
//! # Why both halves of the report are asserted
//!
//! The error names the framing the track settled on and the framing that
//! disagreed with it. A gate that only asked whether *something* was reported
//! would pass on an endpoint that had noticed a difference without knowing
//! which way round it was, and the two are not interchangeable: the first
//! object's framing is the track's property and every later one is measured
//! against it.
//!
//! # Drafts 17, 18 and 19
//!
//! Not here. They withdraw the rule exactly as draft-16 does, so the assertion
//! would be draft-16's, but their control plane is a pair of unidirectional
//! streams with every request on a bidirectional stream of its own — the
//! topology `uni_control_plane.rs`'s peer serves and this one does not.
//!
//! # Ablations, measured
//!
//! Seven cuts, each applied to the working tree, run under the one draft it
//! concerns, and reverted with the file compared byte for byte afterwards. The
//! two that move a draft between eras are the ones worth having: an era is a
//! claim about a sentence, and a claim nothing can contradict is not measured.
//!
//! Dropping the call that records an arriving datagram's framing, in draft-11's
//! `recv_datagram`:
//!
//! ```text
//! Section 9 forbids one track's objects being framed two ways, and the second framing was accepted
//! ```
//!
//! Dropping the call that records an arriving subgroup header's, in draft-13's
//! `accept_subgroup_stream` — the same message, because a track whose first
//! framing was never written down has nothing for the second to disagree with:
//!
//! ```text
//! Section 9 forbids one track's objects being framed two ways, and the second framing was accepted
//! ```
//!
//! Dropping the same call from draft-15's `open_subgroup_stream`, which is the
//! writer half:
//!
//! ```text
//! Section 10 forbids one track's objects being framed two ways, and the second framing was accepted
//! ```
//!
//! Taking the rule out of draft-09's close table, and — separately — taking
//! `close_for_data_stream`'s route to that table out of draft-07's connection.
//! Two different edits, one message, which is the point of the two being
//! separate: having the code is not having the route:
//!
//! ```text
//! Section 8 answers this with a close, but close_for_data_stream declined
//! Section 7 answers this with a close, but close_for_data_stream declined
//! ```
//!
//! Giving draft-14 the close-table arm its own draft withdrew:
//!
//! ```text
//! Section 10 sends this to Malformed Tracks rather than ending the session, but close_for_data_stream closed it
//! ```
//!
//! Reporting the two framings the wrong way round, in draft-12's endpoint:
//!
//! ```text
//! assertion `left == right` failed: the track's first object was on a subgroup stream, so that is what the datagram disagreed with
//!   left: (Datagram, Subgroup)
//!  right: (Subgroup, Datagram)
//! ```

mod common;

/// One draft's loopback gate.
macro_rules! forwarding_preference_gate {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt, $bind:tt,
     $ok:tt, $idfield:tt, $params:tt, $hdr:tt, $dgram:tt, $era:tt, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            /// Unread on a draft that withdrew the rule and so reports nothing.
            #[allow(unused_imports)]
            use moqtap_client::$draft::connection::ConnectionError;
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            #[allow(unused_imports)]
            use moqtap_client::$draft::endpoint::EndpointError;
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            #[allow(unused_imports)]
            use moqtap_codec::types::{ContentExists, GroupOrder};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};

            /// Session termination code `Protocol Violation`, which the drafts
            /// that answer this rule with a close name in the same sentence.
            #[allow(dead_code)]
            const PROTOCOL_VIOLATION: u64 = 0x3;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// Long enough that a close on its way would have arrived, short
            /// enough that a gate expecting none does not sit on it.
            #[allow(dead_code)]
            const BRIEF: Duration = Duration::from_millis(400);

            /// The alias the track is known by on the wire.
            const ALIAS: u64 = 7;

            const TRACK: &[u8] = b"one-track";

            const GROUP_ID: u64 = 3;
            const OBJECT_ID: u64 = 0;

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            /// A ceiling large enough that no refusal here can be the
            /// ceiling's, plus whatever else the draft insists on.
            fn setup_parameters() -> Vec<KeyValuePair> {
                // Nothing to add on thirteen of the fourteen, and nothing that
                // needs a second `Vec` on the one that does.
                #[allow(unused_mut)]
                let mut out = vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }];
                crate::fp_extra_setup_parameters!($params, out);
                out
            }

            fn client_config() -> ClientConfig {
                crate::fp_config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::fp_server_setup_for!($setup, DraftVersion::$version, setup_parameters())
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
                        crate::fp_request_id_of!($idfield, s)
                    }
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// The subgroup stream that settles the track's framing, written
            /// through the codec's own writer because it is conforming and
            /// there is nothing to hand-build.
            fn subgroup_stream_bytes() -> Vec<u8> {
                let header = crate::fp_subgroup_header_for!($hdr, $draft, v(ALIAS), v(GROUP_ID));
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header)
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                buf
            }

            /// A datagram for the same track — the second framing, and the
            /// whole of what the rule forbids.
            fn datagram_bytes() -> Vec<u8> {
                let header =
                    crate::fp_datagram_for!($dgram, $draft, v(ALIAS), v(GROUP_ID), v(OBJECT_ID));
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                buf
            }

            /// Serve one connection: complete the setup exchange, read the
            /// client's SUBSCRIBE and — where the alias travels in the answer —
            /// answer it, then send the track's objects both ways.
            async fn mixing_peer(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                crate::fp_answer_subscribe!($bind, $ok, send, request_id_of(&request));

                let mut data = conn.open_uni().await.expect("open the data stream");
                data.write_all(&subgroup_stream_bytes()).await.expect("write the subgroup header");
                data.finish().expect("finish the data stream");

                conn.send_datagram(datagram_bytes().into()).expect("send the datagram");

                crate::fp_peer_outcome!($era, conn, $section);
            }

            /// A track whose objects arrive framed two ways is answered the way
            /// this draft answers it, and the peer sees the answer.
            ///
            /// Three things are asserted and none implies the others. The
            /// subgroup header comes back naming the track, so a gate cannot
            /// pass because the peer's stream never arrived. The report — where
            /// the draft has one — names both framings, so it cannot pass on an
            /// endpoint that noticed a difference without knowing which way
            /// round. And the peer sees a close, or sees none, which is the
            /// only part of any of this that is about the wire.
            #[tokio::test]
            async fn a_second_framing_for_one_track_is_answered() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(mixing_peer(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                crate::fp_subscribe_for!($sub, conn, namespace(), TRACK, v(ALIAS))
                    .await
                    .expect("subscribe");
                crate::fp_await_binding!($bind, conn);

                let (header, _stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the peer's data stream never arrived")
                        .expect("read the subgroup header");
                assert_eq!(
                    header.track_alias(),
                    ALIAS,
                    "the header that came back is not the one the peer sent"
                );

                let arrival = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the peer's datagram never arrived");
                crate::fp_expect_mixed!($era, conn, arrival, $section);

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// Serve one connection as far as the alias and no further: the
            /// objects the second gate is about are the client's own.
            async fn binding_peer(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                crate::fp_answer_subscribe!($bind, $ok, send, request_id_of(&request));

                if let Ok(reason) = tokio::time::timeout(BRIEF, conn.closed()).await {
                    panic!(
                        "a publisher that declines to mix a track's framings has put nothing \
                         on the wire to close over; the session ended with {reason:?}"
                    );
                }
            }

            /// The other end of the same sentence: this endpoint will not
            /// *write* one track's objects two ways either.
            ///
            /// The rule names the Original Publisher, so the writers are where
            /// it binds. An endpoint subscribed to a track and publishing that
            /// track's objects is a relay, which is the topology the drafts are
            /// written around, and the record is the track's rather than any one
            /// subscription's — so the datagram meets the framing the subgroup
            /// stream established.
            ///
            /// Nothing closes here on any draft. A subscriber that *receives*
            /// two framings is told to end the session on drafts 07 through 11;
            /// a publisher that would send them has put nothing on the wire and
            /// has nothing to end a session over, so the header is refused and
            /// the session goes on.
            #[tokio::test]
            async fn one_track_is_not_written_two_ways() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(binding_peer(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                crate::fp_subscribe_for!($sub, conn, namespace(), TRACK, v(ALIAS))
                    .await
                    .expect("subscribe");
                crate::fp_await_binding!($bind, conn);

                let header = AnySubgroupHeader::$version(crate::fp_subgroup_header_for!(
                    $hdr,
                    $draft,
                    v(ALIAS),
                    v(GROUP_ID)
                ));
                tokio::time::timeout(PATIENCE, conn.open_subgroup_stream(&header))
                    .await
                    .expect("opening the subgroup stream did not finish")
                    .expect("the track's first framing is the one it settles on");

                let datagram = AnyDatagramHeader::$version(crate::fp_datagram_for!(
                    $dgram,
                    $draft,
                    v(ALIAS),
                    v(GROUP_ID),
                    v(OBJECT_ID)
                ));
                let written = conn.send_datagram(&datagram, b"");
                crate::fp_expect_written!($era, written, $section);

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }
        }
    };
}

/// What the writer makes of a second framing for a track it has already
/// written, per era. Two of the three answer it the same way: the drafts differ
/// on what a *receiver* does, and on nothing a sender does.
#[macro_export]
macro_rules! fp_expect_written {
    (closes, $written:expr, $section:literal) => {
        $crate::fp_assert_report!($written, $section);
    };
    (reports, $written:expr, $section:literal) => {
        $crate::fp_assert_report!($written, $section);
    };
    (silent, $written:expr, $section:literal) => {
        $written.expect(concat!(
            "Section ",
            $section,
            " makes the forwarding preference a property of the Object, so a publisher may \
             send one track's objects both ways"
        ));
    };
}

/// `ClientConfig`, in each of the three shapes it takes across the ten drafts.
#[macro_export]
macro_rules! fp_config_for {
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

/// SERVER_SETUP, with and without the Selected Version drafts 15 and 16 dropped.
#[macro_export]
macro_rules! fp_server_setup_for {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// `Connection::subscribe`, in the five shapes it takes across the ten drafts.
///
/// The first two carry the Track Alias; the rest wait for it in the answer.
#[macro_export]
macro_rules! fp_subscribe_for {
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
    (params, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe($ns, $name.to_vec(), Vec::new())
    }};
}

/// The setup parameters a draft insists on beyond the request ceiling.
///
/// Draft-07 alone requires a ROLE of both endpoints in both directions before a
/// session is usable — draft-08 withdrew it — so a session there never reaches
/// the point where a data stream could arrive without one.
#[macro_export]
macro_rules! fp_extra_setup_parameters {
    (with_role, $out:expr) => {{
        let mut value = Vec::new();
        VarInt::from_usize(3).encode(&mut value); // PubSub
        $out.push(KeyValuePair { key: VarInt::from_usize(0x00), value: KvpValue::Bytes(value) });
    }};
    (plain, $out:expr) => {{
        let _ = &$out;
    }};
}

/// What a SUBSCRIBE calls the identifier it carries. Drafts 07 through 10 name
/// it a Subscribe ID; from draft-11 every request draws from one sequence and
/// it is a Request ID.
#[macro_export]
macro_rules! fp_request_id_of {
    (subscribe_id, $s:expr) => {
        $s.subscribe_id
    };
    (request_id, $s:expr) => {
        $s.request_id
    };
}

/// SUBSCRIBE_OK, in the three shapes the drafts that carry the alias in it use.
#[macro_export]
macro_rules! fp_subscribe_ok_for {
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

/// The peer's half of binding the alias: nothing where the SUBSCRIBE already
/// carried it, a SUBSCRIBE_OK where the answer does.
#[macro_export]
macro_rules! fp_answer_subscribe {
    (in_subscribe, $ok:tt, $send:expr, $id:expr) => {{
        let _ = $id;
    }};
    (in_answer, $ok:tt, $send:expr, $id:expr) => {{
        let reply = $crate::fp_subscribe_ok_for!($ok, $id, v(ALIAS));
        $send
            .write_all(&encode(ControlMessage::SubscribeOk(reply)))
            .await
            .expect("write SUBSCRIBE_OK");
    }};
}

/// The client's half of the same: read the answer that carries the alias,
/// where there is one to read.
#[macro_export]
macro_rules! fp_await_binding {
    (in_subscribe, $conn:expr) => {{}};
    (in_answer, $conn:expr) => {{
        tokio::time::timeout(PATIENCE, $conn.recv_and_dispatch())
            .await
            .expect("the answer carrying the alias never arrived")
            .expect("dispatch SUBSCRIBE_OK");
    }};
}

/// A conforming subgroup header, in the four shapes it takes across the ten
/// drafts. Every one names an explicit Subgroup ID and no extensions, which is
/// the plainest stream each draft can carry.
#[macro_export]
macro_rules! fp_subgroup_header_for {
    (plain, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: 128,
        }
    };
    (typed, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::StreamType::SubgroupExplicit,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: 128,
        }
    };
    (opt, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::SubgroupStreamType::from_flags(
                true, false, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            subgroup_id: Some(VarInt::from_usize(0)),
            publisher_priority: 128,
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            // The subgroup base (0x10) with the explicit Subgroup ID bit
            // (0x04): no extensions, no end-of-group, priority present.
            header_type: 0x14,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: Some(128),
        }
    };
}

/// A conforming payload datagram, in the six shapes it takes across the ten
/// drafts. Every one carries no extensions and an empty payload, so nothing
/// about it can be refused for a reason that is not this rule.
///
/// Drafts 07 through 13 keep the type field outside the header, in a `Datagram`
/// that names which layout follows it; from draft-14 the type is a field of the
/// header itself.
#[macro_export]
macro_rules! fp_datagram_for {
    (status_len, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                object_status: moqtap_codec::$draft::types::ObjectStatus::Normal,
                payload_length: VarInt::from_usize(0),
            },
        )
    };
    (counted, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                extension_count: VarInt::from_usize(0),
                extensions: Vec::new(),
                object_status: moqtap_codec::$draft::types::ObjectStatus::Normal,
                payload_length: VarInt::from_usize(0),
            },
        )
    };
    (measured, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
            },
        )
    };
    (grouped, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
                end_of_group: false,
            },
        )
    };
    (typed, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::DatagramObject {
            datagram_type: moqtap_codec::$draft::data_stream::DatagramType::payload(
                true, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers: Vec::new(),
            status: None,
            payload: Vec::new(),
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // A payload datagram with the Object ID written, the priority
            // present, no extensions and no status.
            datagram_type: 0x00,
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(128),
            extension_headers: Vec::new(),
            object_status: None,
        }
    };
}

/// What the client makes of the second framing, per era.
#[macro_export]
macro_rules! fp_expect_mixed {
    (closes, $conn:expr, $arrival:expr, $section:literal) => {{
        let err = $crate::fp_assert_report!($arrival, $section);
        assert!(
            $conn.close_for_data_stream(err),
            concat!(
                "Section ",
                $section,
                " answers this with a close, but close_for_data_stream declined"
            )
        );
    }};
    (reports, $conn:expr, $arrival:expr, $section:literal) => {{
        let err = $crate::fp_assert_report!($arrival, $section);
        assert!(
            !$conn.close_for_data_stream(err),
            concat!(
                "Section ",
                $section,
                " sends this to Malformed Tracks rather than ending the session, but \
                 close_for_data_stream closed it"
            )
        );
    }};
    (silent, $conn:expr, $arrival:expr, $section:literal) => {{
        let (header, _payload) = $arrival.expect(concat!(
            "Section ",
            $section,
            " makes the forwarding preference a property of the Object, so a datagram for \
             a track whose objects have used subgroup streams is legal here"
        ));
        assert_eq!(
            header.meta().track_alias,
            ALIAS,
            "the datagram that came back is not the one the peer sent"
        );
    }};
}

/// The report both answering eras produce, with both framings named.
///
/// `ConnectionError` and `EndpointError` are the invoking module's, which is
/// the draft's, so this names the two without knowing which draft it is in.
#[macro_export]
macro_rules! fp_assert_report {
    ($arrival:expr, $section:literal) => {{
        use moqtap_client::forwarding_preference::ObjectForwardingPreference as Pref;
        let err = $arrival.as_ref().err().unwrap_or_else(|| {
            panic!(concat!(
                "Section ",
                $section,
                " forbids one track's objects being framed two ways, and the second framing \
                 was accepted"
            ))
        });
        match err {
            ConnectionError::Endpoint(EndpointError::MixedForwardingPreference {
                alias,
                established,
                offered,
            }) => {
                assert_eq!(*alias, ALIAS, "the report should name the alias the object carried");
                assert_eq!(
                    (*established, *offered),
                    (Pref::Subgroup, Pref::Datagram),
                    "the track's first object was on a subgroup stream, so that is what the \
                     datagram disagreed with"
                );
            }
            other => panic!("expected a mixed-framing report, got {other:?}"),
        }
        err
    }};
}

/// What the peer sees afterwards, per era.
#[macro_export]
macro_rules! fp_peer_outcome {
    (closes, $conn:expr, $section:literal) => {{
        let reason = tokio::time::timeout(PATIENCE, $conn.closed())
            .await
            .expect("the client was sent two framings for one track and never closed");
        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    concat!(
                        "Section ",
                        $section,
                        " names 'Protocol Violation' for this; the close carried {} instead"
                    ),
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("framed as"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    }};
    (reports, $conn:expr, $section:literal) => {{
        if let Ok(reason) = tokio::time::timeout(BRIEF, $conn.closed()).await {
            panic!(
                concat!(
                    "Section ",
                    $section,
                    " answers this with Malformed Track handling and no close, but the \
                     session ended: {:?}"
                ),
                reason
            );
        }
    }};
    (silent, $conn:expr, $section:literal) => {{
        if let Ok(reason) = tokio::time::timeout(BRIEF, $conn.closed()).await {
            panic!(
                concat!(
                    "Section ",
                    $section,
                    " lets one track's Objects vary, so nothing here ends a session; it \
                     ended with {:?}"
                ),
                reason
            );
        }
    }};
}

forwarding_preference_gate!(
    draft07,
    "draft07",
    Draft07,
    early,
    versioned,
    alias_ft,
    in_subscribe,
    none,
    subscribe_id,
    with_role,
    plain,
    status_len,
    closes,
    "7"
);
forwarding_preference_gate!(
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
    plain,
    counted,
    closes,
    "8"
);
forwarding_preference_gate!(
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
    plain,
    measured,
    closes,
    "8"
);
forwarding_preference_gate!(
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
    plain,
    measured,
    closes,
    "9"
);
forwarding_preference_gate!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    alias_varint,
    in_subscribe,
    none,
    request_id,
    plain,
    typed,
    measured,
    closes,
    "9"
);
forwarding_preference_gate!(
    draft12, "draft12", Draft12, early, versioned, varint, in_answer, rich, request_id, plain,
    typed, grouped, reports, "9"
);
forwarding_preference_gate!(
    draft13, "draft13", Draft13, early, versioned, filter, in_answer, rich, request_id, plain,
    typed, grouped, reports, "9"
);
forwarding_preference_gate!(
    draft14, "draft14", Draft14, both, versioned, filter, in_answer, rich, request_id, plain, opt,
    typed, reports, "10"
);
forwarding_preference_gate!(
    draft15, "draft15", Draft15, late, plain, params, in_answer, plain, request_id, plain, byte,
    byte, reports, "10"
);
forwarding_preference_gate!(
    draft16, "draft16", Draft16, late, plain, params, in_answer, ext, request_id, plain, byte,
    byte, silent, "10"
);

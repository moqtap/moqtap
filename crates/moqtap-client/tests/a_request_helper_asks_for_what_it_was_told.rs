#![cfg(any(feature = "draft15", feature = "draft16"))]

//! A connection helper writes the request it was told to write, on the two
//! drafts where every request travels on one control stream.
//!
//! A helper is a few lines: allocate a Request ID, build a message, write it.
//! Each of those lines is a place to write the wrong thing — the wrong Fetch
//! Type, the wrong track, the caller's parameters dropped — and the result is
//! a well-formed request asking for something the caller did not ask for. The
//! session stays up, the peer answers, and nothing returns an error.
//!
//! # Why this file exists
//!
//! Measured. On drafts 15 through 18 a `Connection::absolute_joining_fetch`
//! was cut to call the endpoint's *relative* builder, and the whole suite
//! stayed green. The cut compiles, writes a FETCH and asks for the wrong one.
//! Nothing on drafts 15 and 16 drove a connection helper as far as the wire at
//! all, so there was nothing there to notice.
//!
//! # What the peer does
//!
//! It reads every message the client writes on the control stream, decodes it,
//! and renders it with [`common::render`] — the message's name, the type
//! number the draft assigns it, and the fields inside it a caller chooses.
//! The gate renders what it asked for the same way. The two strings agree only
//! if the helper wrote the request it was told to.
//!
//! Rendering rather than comparing whole messages because a failure has to be
//! readable: one field differs, and the two lines differ in that field and
//! nowhere else.
//!
//! # Where draft-16 puts one of the eight
//!
//! Seven of the eight requests are written on the control stream on both
//! drafts. Draft-16 Section 6.1 moves the eighth: "The subscriber sends
//! SUBSCRIBE_NAMESPACE on a new bidirectional stream and the publisher MUST
//! send a single REQUEST_OK or REQUEST_ERROR as the first message on the
//! bidirectional stream in response to a SUBSCRIBE_NAMESPACE." So the peer
//! here reads seven and then one, where on draft-15 it reads eight and then
//! none — which is why the counts are per draft and stated at the invocation
//! rather than derived. It is also why the sweep asks for the namespace
//! subscription last: the request is in the same place in both drafts' reports
//! whichever stream carried it.
//!
//! Draft-16 gives that message a `subscribe_options` field draft-15 has no
//! room for, and its PUBLISH carries a Track Extensions list draft-15's does
//! not. Both are rendered where they exist and absent where they do not,
//! rather than rendered as empty: a field a draft does not have is not a field
//! that arrived empty.

mod common;

use std::time::Duration;

use common::{namespace_text, render, text};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// How long a gate waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// The track every request in the sweep names.
const TRACK: &[u8] = b"track-1";

/// A second track name, for the gate that holds the rendering to telling two
/// requests apart. Never sent.
const OTHER_TRACK: &[u8] = b"track-2";

/// The Track Alias the PUBLISH offers. Its value does not matter; that it
/// reaches the peer as it was given does.
const ALIAS: u64 = 7;

/// SUBSCRIBE's message type, 0x03 on both drafts.
const SUBSCRIBE_TYPE: u64 = 0x03;

/// PUBLISH_NAMESPACE's message type, 0x06 on both drafts.
const PUBLISH_NAMESPACE_TYPE: u64 = 0x06;

/// TRACK_STATUS's message type, 0x0D on both drafts.
const TRACK_STATUS_TYPE: u64 = 0x0D;

/// SUBSCRIBE_NAMESPACE's message type, 0x11 on both drafts — the number
/// draft-18 later moved to 0x50.
const SUBSCRIBE_NAMESPACE_TYPE: u64 = 0x11;

/// FETCH's message type, 0x16 on both drafts. All three of `fetch`,
/// `joining_fetch` and `absolute_joining_fetch` write it, which is the whole
/// reason the Fetch Type has to be rendered.
const FETCH_TYPE: u64 = 0x16;

/// PUBLISH's message type, 0x1D on both drafts.
const PUBLISH_TYPE: u64 = 0x1D;

/// The Fetch Type of a standalone FETCH, 0x1 on both drafts.
const STANDALONE_FETCH: u64 = 0x1;

/// The Fetch Type of a Relative Joining Fetch, 0x2 on both drafts.
const RELATIVE_JOINING_FETCH: u64 = 0x2;

/// The Fetch Type of an Absolute Joining Fetch, 0x3 on both drafts.
const ABSOLUTE_JOINING_FETCH: u64 = 0x3;

/// AUTHORIZATION TOKEN's parameter key, 0x03 on both drafts. See [`attached`].
const AUTHORIZATION_TOKEN: u64 = 0x03;

/// Alias Type USE_ALIAS (0x2), the shortest well-formed Token structure: an
/// Alias Type and a Session-specific Alias, and no Token Type or Token Value
/// after them.
const USE_ALIAS: u8 = 0x2;

/// The Session-specific Alias in that Token. Any number.
const TOKEN_ALIAS: u8 = 0x7;

/// Draft-16's Subscribe Options on the namespace subscription: 0x02, both
/// PUBLISH and NAMESPACE. Its value does not matter; that a field draft-15
/// does not have reaches the peer as it was given does.
///
/// Behind the feature because it is a field draft-15 has no room for, and a
/// build of draft-15 alone would otherwise carry a constant nothing reads.
#[cfg(feature = "draft16")]
const NAMESPACE_OPTIONS: u64 = 0x02;

/// The peer's MAX_REQUEST_ID, granted as a SETUP parameter (key 0x02) so the
/// client has ids to spend on eight requests.
const REQUEST_BUDGET: u64 = 100;

/// The namespace every request names.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"one-control-stream".to_vec()])
}

/// A second namespace, for the gate that holds the rendering to telling two
/// requests apart. Never sent.
fn other_namespace() -> TrackNamespace {
    TrackNamespace(vec![b"one-control-stream".to_vec(), b"and-a-suffix".to_vec()])
}

/// A parameter the sweep attaches to every helper it calls, so what the peer
/// reports has something in it only the caller could have put there.
///
/// AUTHORIZATION TOKEN because it is the one parameter every request type
/// admits. Its value is a Token structure rather than opaque bytes — a
/// receiver that cannot decode the Token closes the session — so this is a
/// Token: USE_ALIAS and an alias, which is the shortest one there is.
fn attached() -> KeyValuePair {
    KeyValuePair {
        key: VarInt::from_u64_moqt(AUTHORIZATION_TOKEN),
        value: KvpValue::Bytes(vec![USE_ALIAS, TOKEN_ALIAS]),
    }
}

/// The SETUP parameters both ends send: a MAX_REQUEST_ID and nothing else.
fn setup_parameters() -> Vec<KeyValuePair> {
    vec![KeyValuePair {
        key: VarInt::from_u64_moqt(0x02),
        value: KvpValue::Varint(VarInt::from_u64_moqt(REQUEST_BUDGET)),
    }]
}

/// A varint, spelled the short way.
fn v(n: u64) -> VarInt {
    VarInt::from_u64_moqt(n)
}

// -- the renderings ----------------------------------------------------------
//
// Each takes every field it renders. The peer passes what it decoded and a
// gate passes what it asked for, so the values are two claims and the format
// is one.

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
/// The Fetch Type is a field rather than part of the name because the relative
/// form and the absolute form are one message and differ in it. It is exactly
/// the difference two connection helpers exist to make.
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

/// A PUBLISH, rendered.
///
/// `track_extensions` is `None` on draft-15, whose PUBLISH has no such list,
/// and `Some(count)` on draft-16, which added one. A field a draft does not
/// have is left out rather than rendered as zero: the two are different
/// claims, and an endpoint that stopped writing the list would render zero.
fn publish_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    track_alias: u64,
    parameters: usize,
    track_extensions: Option<usize>,
) -> String {
    let mut fields = vec![
        ("request id", request_id.to_string()),
        ("namespace", namespace_text(track_namespace)),
        ("track", text(track_name)),
        ("track alias", track_alias.to_string()),
        ("parameters", parameters.to_string()),
    ];
    if let Some(count) = track_extensions {
        fields.push(("track extensions", count.to_string()));
    }
    render("PUBLISH", PUBLISH_TYPE, &fields)
}

/// A SUBSCRIBE_NAMESPACE, rendered.
///
/// `subscribe_options` is `None` on draft-15 and `Some(value)` on draft-16,
/// which added the field. See [`publish_request`] for why an absent field is
/// absent rather than zero.
fn subscribe_namespace_request(
    request_id: u64,
    namespace_prefix: &TrackNamespace,
    subscribe_options: Option<u64>,
    parameters: usize,
) -> String {
    let mut fields =
        vec![("request id", request_id.to_string()), ("prefix", namespace_text(namespace_prefix))];
    if let Some(options) = subscribe_options {
        fields.push(("options", options.to_string()));
    }
    fields.push(("parameters", parameters.to_string()));
    render("SUBSCRIBE_NAMESPACE", SUBSCRIBE_NAMESPACE_TYPE, &fields)
}

// -- the two shapes the eight helpers take across these drafts ---------------

/// PUBLISH, which draft-16 gave a Track Extensions list.
///
/// The same selector token drives the call, the peer's rendering of what
/// arrived and the gate's expectation, so those three cannot disagree about
/// which draft they are on.
#[macro_export]
macro_rules! helper_publish {
    (plain, $conn:expr) => {
        $conn.publish(namespace(), TRACK.to_vec(), v(ALIAS), vec![attached()])
    };
    (with_extensions, $conn:expr) => {
        $conn.publish(namespace(), TRACK.to_vec(), v(ALIAS), Vec::new(), vec![attached()])
    };
}

/// See [`helper_publish`]. The peer's side.
#[macro_export]
macro_rules! describe_publish {
    (plain, $m:expr) => {
        publish_request(
            $m.request_id.into_inner(),
            &$m.track_namespace,
            &$m.track_name,
            $m.track_alias.into_inner(),
            $m.parameters.len(),
            None,
        )
    };
    (with_extensions, $m:expr) => {
        publish_request(
            $m.request_id.into_inner(),
            &$m.track_namespace,
            &$m.track_name,
            $m.track_alias.into_inner(),
            $m.parameters.len(),
            Some($m.track_extensions.len()),
        )
    };
}

/// See [`helper_publish`]. The gate's side.
#[macro_export]
macro_rules! expected_publish {
    (plain, $id:expr) => {
        publish_request($id, &namespace(), TRACK, ALIAS, 1, None)
    };
    (with_extensions, $id:expr) => {
        publish_request($id, &namespace(), TRACK, ALIAS, 1, Some(0))
    };
}

/// SUBSCRIBE_NAMESPACE, which draft-16 gave a Subscribe Options field and a
/// bidirectional stream of its own.
///
/// The handle comes back with the rendering because draft-16's helper returns
/// one and closing it withdraws the subscription, so the gate has to hold it
/// until the peer has read the request.
#[macro_export]
macro_rules! helper_subscribe_namespace {
    (plain, $conn:expr) => {{
        let id = $conn
            .subscribe_namespace(namespace(), vec![attached()])
            .await
            .expect("subscribe_namespace");
        (subscribe_namespace_request(id.into_inner(), &namespace(), None, 1), None::<()>)
    }};
    (with_options, $conn:expr) => {{
        let stream = $conn
            .subscribe_namespace(namespace(), v(NAMESPACE_OPTIONS), vec![attached()])
            .await
            .expect("subscribe_namespace");
        let rendered = subscribe_namespace_request(
            stream.request_id().into_inner(),
            &namespace(),
            Some(NAMESPACE_OPTIONS),
            1,
        );
        (rendered, Some(stream))
    }};
}

/// See [`helper_subscribe_namespace`]. The peer's side.
#[macro_export]
macro_rules! describe_subscribe_namespace {
    (plain, $m:expr) => {
        subscribe_namespace_request(
            $m.request_id.into_inner(),
            &$m.namespace_prefix,
            None,
            $m.parameters.len(),
        )
    };
    (with_options, $m:expr) => {
        subscribe_namespace_request(
            $m.request_id.into_inner(),
            &$m.namespace_prefix,
            Some($m.subscribe_options.into_inner()),
            $m.parameters.len(),
        )
    };
}

/// The rendering tells two requests apart, which is what the sweep rests on.
///
/// The peer's report and the sweep's expectation are built by the same
/// functions, so a rendering that dropped its fields would drop them on both
/// sides and the sweep would pass against a peer that could not tell one
/// request from another. That is the one thing the sweep cannot assert about
/// itself, and it is asserted here instead — once, because the format is
/// shared with the request-stream drafts' own sweep.
///
/// Every field is varied on its own. A rendering that kept four of five
/// fields would still be wrong about the fifth, and a single pair of unlike
/// requests would not say which.
///
/// # What it catches
///
/// Making [`common::render`] return the name and type alone, which is the
/// degenerate rendering the sweep would not notice:
///
/// ```text
/// assertion `left != right` failed: the Fetch Type has to reach the rendering: the relative and absolute forms are one message and differ in it
///   left: "FETCH 0x16"
///  right: "FETCH 0x16"
/// ```
#[test]
fn a_rendering_that_dropped_a_field_would_hide_a_helper_asking_for_the_wrong_thing() {
    assert_ne!(
        joining_fetch_request(4, RELATIVE_JOINING_FETCH, 0, 9, 1),
        joining_fetch_request(4, ABSOLUTE_JOINING_FETCH, 0, 9, 1),
        "the Fetch Type has to reach the rendering: the relative and absolute \
         forms are one message and differ in it"
    );
    assert_ne!(
        subscribe_request(4, &namespace(), TRACK, 1),
        subscribe_request(5, &namespace(), TRACK, 1),
        "the Request ID has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(4, &namespace(), TRACK, 1),
        subscribe_request(4, &other_namespace(), TRACK, 1),
        "the namespace has to reach the rendering, every field of it"
    );
    assert_ne!(
        subscribe_request(4, &namespace(), TRACK, 1),
        subscribe_request(4, &namespace(), OTHER_TRACK, 1),
        "the track name has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(4, &namespace(), TRACK, 1),
        subscribe_request(4, &namespace(), TRACK, 0),
        "the parameter count has to reach the rendering: a helper that dropped \
         the caller's list is the defect this file was opened for"
    );
    assert_ne!(
        publish_request(4, &namespace(), TRACK, ALIAS, 1, None),
        publish_request(4, &namespace(), TRACK, ALIAS, 1, Some(0)),
        "a field a draft does not have must not render as one that arrived empty"
    );
    assert_ne!(
        subscribe_request(4, &namespace(), TRACK, 1),
        track_status_request(4, &namespace(), TRACK, 1),
        "two requests with the same fields and different names must not render alike"
    );
}

/// One draft's gates.
macro_rules! request_helper_gates {
    (
        $draft:ident,
        $variant:ident,
        $version:expr,
        $feature:literal,
        $label:literal,
        $publish_shape:tt,
        $namespace_shape:tt,
        $on_control:expr,
        $on_own_streams:expr
    ) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use super::*;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::$draft::message::{ControlMessage, FetchPayload, ServerSetup};

            /// The client's own SETUP, granting the peer the same budget the
            /// peer grants it.
            fn client_config() -> ClientConfig {
                ClientConfig {
                    draft: $version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: setup_parameters(),
                }
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$variant(msg).encode(&mut out).expect("encode");
                out
            }

            /// Render a request the client wrote.
            ///
            /// A message that is not one of the eight reaches here only if a
            /// helper wrote something else entirely, and is rendered by its
            /// own Debug so that it is visible rather than silently unlike
            /// everything the gate expected.
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
                    ControlMessage::Fetch(m) => match &m.fetch_payload {
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
                    },
                    ControlMessage::Publish(m) => {
                        crate::describe_publish!($publish_shape, m)
                    }
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
                    ControlMessage::SubscribeNamespace(m) => {
                        crate::describe_subscribe_namespace!($namespace_shape, m)
                    }
                    other => format!("a message that is not a request: {other:?}"),
                }
            }

            /// Complete the setup, then read and render every request.
            ///
            /// The counts are the peer's own: `$on_control` messages on the
            /// control stream and `$on_own_streams` on bidirectional streams
            /// the client opened for them. Counted rather than drained on a
            /// timer so that a helper which wrote nothing fails by running out
            /// of patience with a message, rather than by the gate quietly
            /// comparing a short list.
            async fn reading_peer(server: quinn::Endpoint) -> Vec<String> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = crate::common::frame_uni_recv(recv, $version);
                control.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(ServerSetup {
                    parameters: setup_parameters(),
                })))
                .await
                .expect("write SERVER_SETUP");

                let mut seen = Vec::new();
                for n in 0..$on_control {
                    let (msg, _) = tokio::time::timeout(PATIENCE, control.read_control(false))
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "{}: request {} never reached the control stream; {} did",
                                $label,
                                n + 1,
                                seen.len()
                            )
                        })
                        .expect("read a request off the control stream");
                    seen.push(describe(&msg));
                }

                // Draft-16 moved one of the eight onto a bidirectional
                // stream of its own; on draft-15 there is none and this loop
                // does not run.
                while seen.len() < $on_control + $on_own_streams {
                    let (_send, recv) = tokio::time::timeout(PATIENCE, conn.accept_bi())
                        .await
                        .unwrap_or_else(|_| {
                            panic!("{}: the request's own stream never arrived", $label)
                        })
                        .expect("accept the request's own stream");
                    let mut framed = crate::common::frame_uni_recv(recv, $version);
                    let (msg, _) = tokio::time::timeout(PATIENCE, framed.read_control(false))
                        .await
                        .unwrap_or_else(|_| {
                            panic!("{}: nothing arrived on the request's own stream", $label)
                        })
                        .expect("read the request off its own stream");
                    seen.push(describe(&msg));
                }

                seen
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
            #[test]
            fn the_numbers_the_renderings_carry_are_this_drafts() {
                use moqtap_codec::$draft::message::{FetchType, MessageType};
                assert_eq!(MessageType::Subscribe.id(), SUBSCRIBE_TYPE, "SUBSCRIBE");
                assert_eq!(
                    MessageType::PublishNamespace.id(),
                    PUBLISH_NAMESPACE_TYPE,
                    "PUBLISH_NAMESPACE"
                );
                assert_eq!(MessageType::TrackStatus.id(), TRACK_STATUS_TYPE, "TRACK_STATUS");
                assert_eq!(
                    MessageType::SubscribeNamespace.id(),
                    SUBSCRIBE_NAMESPACE_TYPE,
                    "SUBSCRIBE_NAMESPACE"
                );
                assert_eq!(MessageType::Fetch.id(), FETCH_TYPE, "FETCH");
                assert_eq!(MessageType::Publish.id(), PUBLISH_TYPE, "PUBLISH");
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

            /// Every request helper writes the request it was told to write.
            ///
            /// Eight helpers, each asked for something no other one of them
            /// would produce, and all eight compared at once so a failure
            /// names every helper that got it wrong rather than only the
            /// first. The Request IDs come from the helpers' own return
            /// values, so the gate stays right if the endpoint changes how it
            /// allocates — and a helper that allocated the wrong id still
            /// fails, because the id the peer read is the one on the wire.
            ///
            /// # What it catches
            ///
            /// Three cuts, run on these two drafts and reverted. Each prints
            /// both lists whole — eight requests each — so only the element
            /// that differs is reproduced here, and the assertion line above
            /// it is verbatim.
            ///
            /// Draft-16's `absolute_joining_fetch` left calling the
            /// endpoint's *relative* builder, which is the cut that opened
            /// this file and that nothing on these two drafts could see:
            ///
            /// ```text
            /// assertion `left == right` failed: draft-16: every helper must write the request it was told to
            ///   left: … "FETCH 0x16 request id=6 fetch type=2 joining request id=0 joining start=9 parameters=1" …
            ///  right: … "FETCH 0x16 request id=6 fetch type=3 joining request id=0 joining start=9 parameters=1" …
            /// ```
            ///
            /// Draft-15's `track_status` passing an empty list to the
            /// endpoint instead of the caller's, which is a request that asks
            /// for the right track without the authorization it was given:
            ///
            /// ```text
            ///   left: … "TRACK_STATUS 0x0d request id=10 namespace=one-control-stream track=track-1 parameters=0" …
            ///  right: … "TRACK_STATUS 0x0d request id=10 namespace=one-control-stream track=track-1 parameters=1" …
            /// ```
            ///
            /// And draft-16's `joining_fetch` naming the wrong request — the
            /// fetch's own Joining Start where the subscription's id belongs,
            /// which is the kind of mistake two adjacent varint arguments
            /// invite:
            ///
            /// ```text
            ///   left: … "FETCH 0x16 request id=4 fetch type=2 joining request id=2 joining start=2 parameters=1" …
            ///  right: … "FETCH 0x16 request id=4 fetch type=2 joining request id=0 joining start=2 parameters=1" …
            /// ```
            #[tokio::test]
            async fn every_request_helper_asks_for_what_it_was_told() {
                crate::common::init_crypto();
                let (endpoint, addr) = crate::common::spawn_server(&[$version.quic_alpn()]);
                let peer = tokio::spawn(reading_peer(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut expected: Vec<String> = Vec::new();

                let subscription = conn
                    .subscribe(namespace(), TRACK.to_vec(), vec![attached()])
                    .await
                    .expect("subscribe");
                expected.push(subscribe_request(subscription.into_inner(), &namespace(), TRACK, 1));

                let fetch = conn
                    .fetch(namespace(), TRACK.to_vec(), v(0), v(0), v(1), v(1), vec![attached()])
                    .await
                    .expect("fetch");
                expected.push(standalone_fetch_request(
                    fetch.into_inner(),
                    STANDALONE_FETCH,
                    &namespace(),
                    TRACK,
                    (0, 0, 1, 1),
                    1,
                ));

                let relative = conn
                    .joining_fetch(subscription, v(2), vec![attached()])
                    .await
                    .expect("joining_fetch");
                expected.push(joining_fetch_request(
                    relative.into_inner(),
                    RELATIVE_JOINING_FETCH,
                    subscription.into_inner(),
                    2,
                    1,
                ));

                let absolute = conn
                    .absolute_joining_fetch(subscription, v(9), vec![attached()])
                    .await
                    .expect("absolute_joining_fetch");
                expected.push(joining_fetch_request(
                    absolute.into_inner(),
                    ABSOLUTE_JOINING_FETCH,
                    subscription.into_inner(),
                    9,
                    1,
                ));

                let announcement = conn
                    .publish_namespace(namespace(), vec![attached()])
                    .await
                    .expect("publish_namespace");
                expected.push(publish_namespace_request(
                    announcement.into_inner(),
                    &namespace(),
                    1,
                ));

                let status = conn
                    .track_status(namespace(), TRACK.to_vec(), vec![attached()])
                    .await
                    .expect("track_status");
                expected.push(track_status_request(status.into_inner(), &namespace(), TRACK, 1));

                let publication =
                    crate::helper_publish!($publish_shape, conn).await.expect("publish");
                expected.push(crate::expected_publish!($publish_shape, publication.into_inner()));

                // Last, so that the request draft-16 moved off the control
                // stream is in the same place in both drafts' reports.
                let (rendered, _held) = crate::helper_subscribe_namespace!($namespace_shape, conn);
                expected.push(rendered);

                let seen = tokio::time::timeout(PATIENCE, peer)
                    .await
                    .expect("the peer did not finish")
                    .expect("the peer panicked");

                assert_eq!(
                    seen, expected,
                    "{}: every helper must write the request it was told to",
                    $label
                );

                // `_held` is draft-16's namespace stream, whose closing
                // withdraws the subscription; it stays bound to the end of
                // the gate so the peer reads the request before that happens.
                conn.close(0, b"bye");
            }
        }
    };
}

request_helper_gates!(
    draft15,
    Draft15,
    DraftVersion::Draft15,
    "draft15",
    "draft-15",
    plain,
    plain,
    8,
    0
);
request_helper_gates!(
    draft16,
    Draft16,
    DraftVersion::Draft16,
    "draft16",
    "draft-16",
    with_extensions,
    with_options,
    7,
    1
);

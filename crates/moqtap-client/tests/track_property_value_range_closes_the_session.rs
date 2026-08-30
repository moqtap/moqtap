#![cfg(any(feature = "draft16", feature = "draft17", feature = "draft18", feature = "draft19"))]
//! A Track Property outside its range, hidden one level down, ends the session.
//!
//! Draft-16 Section 11.1.1.3, restated by drafts 17, 18 and 19 of the Property
//! registry that replaced the extension header one: "The allowed values are 0 or
//! 1... If an endpoint receives a value larger than 1, it MUST close the session
//! with PROTOCOL_VIOLATION."
//!
//! # Why the close is under test and not the refusal
//!
//! Because a codec test cannot tell the two apart. Nothing read these values at
//! all before, so the frame was carried and the rule was silent; a decoder that
//! refuses the frame and leaves the session open looks identical from inside the
//! codec, and the peer that broke the rule goes on sending either way. Only the
//! wire says which happened.
//!
//! # Why the value is sent inside the Immutable block
//!
//! Because that is the placement a check written the obvious way misses, and
//! the drafts name it as one an implementation has to look in: "When looking for
//! the value of a property, processors MUST search both the mutable properties
//! and the contents of Immutable Properties."
//!
//! Immutable Properties is where an Original Publisher puts what relays must not
//! rewrite — which is where a track's group order and its dynamic-group support
//! belong. A peer whose value is refused beside the block and accepted inside it
//! has not been stopped from anything; it has been told where to put it. So the
//! wire gate drives the nested form on every draft that states the rule, and the
//! flat form is left to the codec's own gate, which drives both.

mod common;

use std::time::Duration;

#[allow(unused_imports)]
use moqtap_codec::varint::{Moqt17, Moqt18, MoqtProfile, VarInt};
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION. Draft-16 Section 13.4.1, and
/// Section 15.11.1 from draft-17 on; the number does not move.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// DYNAMIC_GROUPS: Extension Header Type 0x30 on draft-16, Property Type 0x30
/// from draft-17.
const DYNAMIC_GROUPS: u64 = 0x30;

/// Immutable Extensions on draft-16, Immutable Properties from draft-17. Type
/// 0xB either way, and odd, so its value is length-prefixed bytes holding
/// another Key-Value-Pair run.
const IMMUTABLE: u64 = 0x0B;

/// The value the rule forbids, one past the largest it allows.
const TOO_MANY_DYNAMIC_GROUPS: u64 = 2;

/// SUBSCRIBE_OK.
const SUBSCRIBE_OK: u64 = 0x04;

const PATIENCE: Duration = Duration::from_secs(10);

/// Build one draft's gate.
///
/// The offending frame is hand-built rather than produced by this codec's
/// encoder, because the encoder refuses the value under test — which is the
/// other half of the same fix, gated in the codec's own
/// `a_value_the_decoder_refuses_is_never_written`. Everything around the one
/// value is what the encoder writes: the message type, the sixteen-bit payload
/// length, an empty Parameters list, and on draft-16 a Request ID.
macro_rules! nested_property_closes_the_session {
    (
        $module:ident,
        $feature:literal,
        $draft:ident,
        $version:ident,
        put_varint = $put_varint:item,
        prelude = $prelude:expr,
        setup = $setup:expr,
        handshake = $handshake:path
    ) => {
        #[cfg(feature = $feature)]
        mod $module {
            #[allow(unused_imports)]
            use super::{
                common, DraftVersion, Moqt17, Moqt18, MoqtProfile, VarInt, DYNAMIC_GROUPS,
                IMMUTABLE, PATIENCE, PROTOCOL_VIOLATION, SUBSCRIBE_OK, TOO_MANY_DYNAMIC_GROUPS,
            };
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};

            $put_varint

            fn client_config() -> ClientConfig {
                ClientConfig {
                    draft: DraftVersion::$version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                }
            }

            /// A SUBSCRIBE_OK whose tail holds an Immutable block, and whose
            /// block holds a DYNAMIC_GROUPS of 2.
            fn subscribe_ok_hiding_a_dynamic_groups_of_two() -> Vec<u8> {
                let mut nested = Vec::new();
                put_varint(DYNAMIC_GROUPS, &mut nested);
                put_varint(TOO_MANY_DYNAMIC_GROUPS, &mut nested);

                let mut tail = Vec::new();
                put_varint(IMMUTABLE, &mut tail);
                put_varint(nested.len() as u64, &mut tail);
                tail.extend_from_slice(&nested);

                let mut payload: Vec<u8> = Vec::new();
                $prelude(&mut payload);
                payload.extend_from_slice(&tail);

                let mut wire = Vec::new();
                put_varint(SUBSCRIBE_OK, &mut wire);
                wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                wire.extend_from_slice(&payload);
                wire
            }

            /// A DYNAMIC_GROUPS of 2 inside the Immutable block closes the QUIC
            /// connection with PROTOCOL_VIOLATION.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Both messages below were measured on draft-19.
            ///
            /// Removing the descent into the Immutable block — a check that
            /// walks the outer run only, which is what a first reading of the
            /// rule produces. The block reaches the application whole, with the
            /// forbidden value inside it:
            ///
            /// ```text
            /// a DYNAMIC_GROUPS of 2 must be refused wherever it is carried: SubscribeOk(SubscribeOk { track_alias: VarInt(4), parameters: [], track_properties: [KeyValuePair { key: VarInt(11), value: Bytes([48, 2]) }] })
            /// ```
            ///
            /// Sending `CodecError::TrackPropertyValueOutOfRange` to the
            /// no-close arm of this draft's `codec_session_error_code` instead —
            /// which is the shape every rule reported under a shared variant
            /// ends up in, the frame refused and the peer none the wiser:
            ///
            /// ```text
            /// the client refused the frame but never closed the connection: Elapsed(())
            /// ```
            #[tokio::test]
            async fn a_dynamic_groups_hidden_in_the_immutable_block_closes_the_quic_connection() {
                common::init_crypto();
                let (endpoint, addr) =
                    common::spawn_server(&[DraftVersion::$version.quic_alpn()]);

                let peer = tokio::spawn(async move {
                    let conn =
                        endpoint.accept().await.expect("accept").await.expect("tls handshake");

                    let mut control = $handshake(&conn).await;
                    control.write_all(&$setup).await.expect("write the setup");
                    control
                        .write_all(&subscribe_ok_hiding_a_dynamic_groups_of_two())
                        .await
                        .expect("write the offending SUBSCRIBE_OK");

                    let reason = tokio::time::timeout(PATIENCE, conn.closed())
                        .await
                        .expect("the client refused the frame but never closed the connection");

                    match reason {
                        quinn::ConnectionError::ApplicationClosed(frame) => {
                            let code = u64::from(frame.error_code);
                            assert_eq!(
                                code, PROTOCOL_VIOLATION,
                                "the rule answers a value larger than 1 with \
                                 PROTOCOL_VIOLATION; the close carried {code}",
                            );
                            let text = String::from_utf8_lossy(&frame.reason).to_string();
                            assert!(
                                text.contains("outside the range"),
                                "the close reason should name the rule that was broken; \
                                 got {text:?}",
                            );
                        }
                        other => panic!("expected an application close, got {other:?}"),
                    }
                });

                let mut conn = Connection::connect(&addr.to_string(), client_config())
                    .await
                    .expect("client connect");

                let err = conn
                    .recv_control()
                    .await
                    .expect_err("a DYNAMIC_GROUPS of 2 must be refused wherever it is carried");
                let text = err.to_string();
                assert!(
                    text.contains("track property"),
                    "the error should say which registry the type is in; got {text:?}",
                );

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }
        }
    };
}

/// Draft-16 opens the control stream as a bidirectional pair.
#[cfg(feature = "draft16")]
async fn accept_bidi_control(conn: &quinn::Connection) -> quinn::SendStream {
    let (send, recv) = conn.accept_bi().await.expect("accept_bi");
    let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft16);
    framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
    send
}

/// Drafts 17 and later give each direction its own unidirectional stream.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
async fn accept_uni_control(conn: &quinn::Connection) -> quinn::SendStream {
    let mut client_control = conn.accept_uni().await.expect("accept_uni");
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while seen.len() < 3 {
        match client_control.read(&mut chunk).await.expect("read SETUP") {
            Some(n) => seen.extend_from_slice(&chunk[..n]),
            None => break,
        }
    }
    assert!(!seen.is_empty(), "the client sent no SETUP");
    conn.open_uni().await.expect("open_uni")
}

#[cfg(feature = "draft16")]
fn draft16_setup() -> Vec<u8> {
    use moqtap_codec::dispatch::AnyControlMessage;
    use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
    let mut buf = Vec::new();
    AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SERVER_SETUP");
    buf
}

#[cfg(feature = "draft17")]
fn draft17_setup() -> Vec<u8> {
    use moqtap_codec::dispatch::AnyControlMessage;
    use moqtap_codec::draft17::message::{ControlMessage, Setup};
    let mut buf = Vec::new();
    AnyControlMessage::Draft17(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

#[cfg(feature = "draft18")]
fn draft18_setup() -> Vec<u8> {
    use moqtap_codec::dispatch::AnyControlMessage;
    use moqtap_codec::draft18::message::{ControlMessage, Setup};
    let mut buf = Vec::new();
    AnyControlMessage::Draft18(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

#[cfg(feature = "draft19")]
fn draft19_setup() -> Vec<u8> {
    use moqtap_codec::dispatch::AnyControlMessage;
    use moqtap_codec::draft19::message::{ControlMessage, Setup};
    let mut buf = Vec::new();
    AnyControlMessage::Draft19(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

#[cfg(feature = "draft16")]
nested_property_closes_the_session!(
    draft16,
    "draft16",
    draft16,
    Draft16,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64(v).expect("fixture value fits a varint").encode(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        // Request ID, Track Alias, then an empty Parameters list.
        put_varint(0, payload);
        put_varint(4, payload);
        put_varint(0, payload);
    },
    setup = super::draft16_setup(),
    handshake = super::accept_bidi_control
);

#[cfg(feature = "draft17")]
nested_property_closes_the_session!(
    draft17,
    "draft17",
    draft17,
    Draft17,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt17>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        // Draft-17 dropped SUBSCRIBE_OK's Request ID.
        put_varint(4, payload);
        put_varint(0, payload);
    },
    setup = super::draft17_setup(),
    handshake = super::accept_uni_control
);

#[cfg(feature = "draft18")]
nested_property_closes_the_session!(
    draft18,
    "draft18",
    draft18,
    Draft18,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        put_varint(4, payload);
        put_varint(0, payload);
    },
    setup = super::draft18_setup(),
    handshake = super::accept_uni_control
);

#[cfg(feature = "draft19")]
nested_property_closes_the_session!(
    draft19,
    "draft19",
    draft19,
    Draft19,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        put_varint(4, payload);
        put_varint(0, payload);
    },
    setup = super::draft19_setup(),
    handshake = super::accept_uni_control
);

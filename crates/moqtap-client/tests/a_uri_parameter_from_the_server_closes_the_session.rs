//! PATH and AUTHORITY are the client's, for native QUIC only, on drafts 14-23.
//!
//! Each draft forbids both "by the server, or when WebTransport is used", and
//! closes the session with INVALID_PATH (0x8) on a PATH and INVALID_AUTHORITY
//! (0x19) on an AUTHORITY received from the server. The AUTHORITY sections:
//! draft-14 Section 9.3.2.1,
//! draft-15 Section 9.3.1.1,
//! draft-16 Section 9.3.1.1,
//! draft-17 Section 9.4.1.1,
//! draft-18 Section 10.3.1.1,
//! draft-19 Section 10.3.1.1,
//! draft-20 Section 10.3.1.1,
//! draft-21 Section 9.1.1,
//! draft-22 Section 9.1.1,
//! draft-23 Section 9.1.1.
//!
//! The client refuses either over WebTransport before it dials, and closes
//! with the named code when the server's SETUP carries one.
//!
//! Draft-14 is the exception for AUTHORITY from the server: its Parameter Type
//! 0x05 is also MOQT_IMPLEMENTATION (draft-14 Section 9.3.2.6), so a server's
//! 0x05 completes the handshake there.

#![cfg(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

mod common;
#[macro_use]
mod data_stream_peer;

use std::time::Duration;

use moqtap_client::dispatch::{AnyClientConfig, AnyConnection, AnyTransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// How long any one step may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

const PATH: u64 = 0x01;
const AUTHORITY: u64 = 0x05;
const INVALID_PATH: u32 = 0x8;
const INVALID_AUTHORITY: u32 = 0x19;

fn parameter(key: u64, value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: VarInt::from_u64(key).unwrap(), value: KvpValue::Bytes(value.to_vec()) }
}

/// The application code the client closed the session with.
fn close_code(reason: quinn::ConnectionError) -> u32 {
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            u32::try_from(close.error_code.into_inner()).expect("a code this test names")
        }
        other => panic!("the client did not close with a code: {other:?}"),
    }
}

macro_rules! uri_parameter_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, authority_closes: $closes:literal) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;
            use moqtap_client::$module::session::setup::{
                validate_client_authority_transport, validate_client_path_transport, SetupError,
            };

            const DRAFT: DraftVersion = DraftVersion::$version;

            /// A peer whose SETUP carries `$key`. Its `serve` returns how the
            /// session ended.
            macro_rules! server_sending {
                ($server:ident, $key:expr) => {
                    mod $server {
                        use super::*;

                        fn setup_parameters() -> Vec<KeyValuePair> {
                            vec![parameter($key, b"relay.example")]
                        }

                        pub async fn serve(server: quinn::Endpoint) -> quinn::ConnectionError {
                            let conn = server
                                .accept()
                                .await
                                .expect("accept")
                                .await
                                .expect("tls handshake");
                            let _control = peer_setup!($handshake, conn, $version, $module);
                            conn.closed().await
                        }
                    }
                };
            }

            server_sending!(path_server, PATH);
            server_sending!(authority_server, AUTHORITY);

            /// Connect to a server whose SETUP carries `key`. Returns whether
            /// the handshake completed and how the session ended.
            async fn connect_to_server_sending(key: u64) -> (bool, quinn::ConnectionError) {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = if key == PATH {
                    tokio::spawn(path_server::serve(endpoint))
                } else {
                    tokio::spawn(authority_server::serve(endpoint))
                };
                let config = AnyClientConfig::new(DRAFT, AnyTransportType::Quic)
                    .with_skip_cert_verification(true);
                let connected = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), config),
                )
                .await
                .expect("connect waited");
                let completed = match connected {
                    Ok(conn) => {
                        conn.close(0, b"gate complete");
                        true
                    }
                    Err(_) => false,
                };
                let reason = tokio::time::timeout(PATIENCE, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
                (completed, reason)
            }

            #[tokio::test]
            async fn a_server_path_closes_with_invalid_path() {
                let (completed, reason) = connect_to_server_sending(PATH).await;
                assert!(!completed, "a SETUP carrying PATH must be refused");
                assert_eq!(close_code(reason), INVALID_PATH);
            }

            #[tokio::test]
            async fn a_server_authority_is_answered_by_the_draft() {
                let (completed, reason) = connect_to_server_sending(AUTHORITY).await;
                if $closes {
                    assert!(!completed, "a SETUP carrying AUTHORITY must be refused");
                    assert_eq!(close_code(reason), INVALID_AUTHORITY);
                } else {
                    assert!(completed, "a draft-14 0x05 may be MOQT_IMPLEMENTATION");
                    assert_eq!(close_code(reason), 0);
                }
            }

            /// The second assertion keeps the first from being satisfied by a
            /// client that refuses AUTHORITY everywhere.
            #[test]
            fn authority_is_refused_over_webtransport_and_allowed_over_quic() {
                let parameters = vec![parameter(AUTHORITY, b"relay.example")];
                assert_eq!(
                    validate_client_authority_transport(&parameters, true),
                    Err(SetupError::AuthorityOverWebTransport),
                );
                assert_eq!(validate_client_authority_transport(&parameters, false), Ok(()));
                assert_eq!(
                    validate_client_path_transport(&parameters, true),
                    Ok(()),
                    "an AUTHORITY is not a PATH",
                );
            }
        }
    };
}

uri_parameter_gate!(draft14, "draft14", Draft14, versioned, authority_closes: false);
uri_parameter_gate!(draft15, "draft15", Draft15, plain, authority_closes: true);
uri_parameter_gate!(draft16, "draft16", Draft16, plain, authority_closes: true);
uri_parameter_gate!(draft17, "draft17", Draft17, uni, authority_closes: true);
uri_parameter_gate!(draft18, "draft18", Draft18, uni, authority_closes: true);
uri_parameter_gate!(draft19, "draft19", Draft19, uni, authority_closes: true);
uri_parameter_gate!(draft20, "draft20", Draft20, uni, authority_closes: true);
uri_parameter_gate!(draft21, "draft21", Draft21, uni, authority_closes: true);
uri_parameter_gate!(draft22, "draft22", Draft22, uni, authority_closes: true);
uri_parameter_gate!(draft23, "draft23", Draft23, uni, authority_closes: true);

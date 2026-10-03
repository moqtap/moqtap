//! `AnyConnection::adopt` completes the handshake on every draft this build
//! compiles, and each connection reports the version of the draft it runs.
//!
//! `adopt` reaches a draft through a macro row list in `dispatch.rs`, and a
//! draft missing from it falls to an arm that answers "not enabled in this
//! build" at runtime. Nothing at compile time can see that: the arm is there
//! for a build that leaves a feature off, so it is legal for every draft. The
//! loop below is over `DraftVersion::ALL` rather than a list of its own, so a
//! draft added to the enum and not to the facade is a failure here.
//!
//! The version check is the second half for the same reason. `SetupComplete`
//! carries a literal per draft module, and a module copied from its predecessor
//! keeps the predecessor's number unless someone edits it. The expected value
//! comes from `DraftVersion::version_varint`, not from the module.
//!
//! # What this catches, observed by making each change and running it
//!
//! Removing the `("draft22", Draft22, draft22)` row from `adopt_dispatch!`:
//!
//! ```text
//! Draft22 is compiled into this build and adopt refused it as not enabled:
//! draft Draft22 not enabled in this build
//! ```
//!
//! Writing `0xff000000 + 20` in draft-21's `Connection::adopt`:
//!
//! ```text
//! assertion `left == right` failed: Draft21 reported another draft's version in SetupComplete
//!   left: Some(4278190100)
//!  right: Some(4278190101)
//! ```

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyClientEvent, AnyConnection, AnyConnectionObserver, AnyTransportType,
    ErrorCause,
};
use moqtap_client::transport::{dial_quic, QuicDialOptions};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A failure ceiling, never spent by a correct build.
const PATIENCE: Duration = Duration::from_secs(10);

/// The server's answer to each shape of client SETUP.
///
/// `selected` is drafts 08-14: SERVER_SETUP echoes a version from the client's
/// list. `role` is draft-07, which requires a ROLE parameter of both endpoints
/// (Section 6.2.2.1), so the server answers with the one the client sent. `server` is drafts 15 and 16: SERVER_SETUP with no
/// version. `unified` is draft-17 on: the same SETUP both ways, on a
/// unidirectional stream.
macro_rules! answer {
    (role, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let (selected, parameters) = match $client {
            AnyControlMessage::$variant(ControlMessage::ClientSetup(c)) => {
                (c.supported_versions[0], c.parameters.clone())
            }
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::$variant(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters,
        }))
    }};
    (selected, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        let selected = match $client {
            AnyControlMessage::$variant(ControlMessage::ClientSetup(c)) => c.supported_versions[0],
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        };
        AnyControlMessage::$variant(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: Vec::new(),
        }))
    }};
    (server, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, ServerSetup};
        match $client {
            AnyControlMessage::$variant(ControlMessage::ClientSetup(_)) => {}
            other => panic!("expected a CLIENT_SETUP, got {other:?}"),
        }
        AnyControlMessage::$variant(ControlMessage::ServerSetup(ServerSetup {
            parameters: Vec::new(),
        }))
    }};
    (unified, $variant:ident, $module:ident, $client:expr) => {{
        use moqtap_codec::$module::message::{ControlMessage, Setup};
        match $client {
            AnyControlMessage::$variant(ControlMessage::Setup(_)) => {}
            other => panic!("expected a SETUP, got {other:?}"),
        }
        AnyControlMessage::$variant(ControlMessage::Setup(Setup { options: Vec::new() }))
    }};
}

/// One row per draft. `compiled` is an exhaustive match with no wildcard, so a
/// draft added to `DraftVersion` does not compile here until it has a row.
macro_rules! drafts {
    ($( $feat:literal => $variant:ident, $module:ident, $kind:ident; )+) => {
        /// Whether this build carries `draft`. Spelled out per feature rather
        /// than read from the facade, which is the thing under test.
        fn compiled(draft: DraftVersion) -> bool {
            match draft {
                $( DraftVersion::$variant => cfg!(feature = $feat), )+
            }
        }

        /// Whether `draft` runs its control plane on a pair of unidirectional
        /// streams rather than one bidirectional stream.
        fn unidirectional_control(draft: DraftVersion) -> bool {
            match draft {
                $( DraftVersion::$variant => stringify!($kind) == "unified", )+
            }
        }

        /// The framed bytes the peer answers `client` with.
        #[allow(unused_variables)]
        fn answer(draft: DraftVersion, client: &AnyControlMessage) -> Vec<u8> {
            let reply = match draft {
                $(
                    #[cfg(feature = $feat)]
                    DraftVersion::$variant => answer!($kind, $variant, $module, client),
                )+
                #[allow(unreachable_patterns)]
                other => panic!("{other:?} is not compiled, so no setup for it arrives"),
            };
            #[allow(unreachable_code)]
            {
                let mut out = Vec::new();
                reply.encode(&mut out).expect("a setup this test built encodes");
                out
            }
        }

        /// The version a `SetupComplete` event reports, if `event` is one.
        fn setup_complete(event: &AnyClientEvent) -> Option<u64> {
            match event {
                $(
                    #[cfg(feature = $feat)]
                    AnyClientEvent::$variant(
                        moqtap_client::$module::event::ClientEvent::SetupComplete {
                            negotiated_version,
                        },
                    ) => Some(*negotiated_version),
                )+
                #[allow(unreachable_patterns)]
                _ => None,
            }
        }
    };
}

drafts! {
    "draft07" => Draft07, draft07, role;
    "draft08" => Draft08, draft08, selected;
    "draft09" => Draft09, draft09, selected;
    "draft10" => Draft10, draft10, selected;
    "draft11" => Draft11, draft11, selected;
    "draft12" => Draft12, draft12, selected;
    "draft13" => Draft13, draft13, selected;
    "draft14" => Draft14, draft14, selected;
    "draft15" => Draft15, draft15, server;
    "draft16" => Draft16, draft16, server;
    "draft17" => Draft17, draft17, unified;
    "draft18" => Draft18, draft18, unified;
    "draft19" => Draft19, draft19, unified;
    "draft20" => Draft20, draft20, unified;
    "draft21" => Draft21, draft21, unified;
    "draft22" => Draft22, draft22, unified;
}

/// A peer's view of one stream: bytes in, one decoded control message out.
struct PeerStream {
    recv: quinn::RecvStream,
    draft: DraftVersion,
    buf: Vec<u8>,
}

impl PeerStream {
    async fn read_control(&mut self) -> Option<AnyControlMessage> {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(self.draft, &mut cursor) {
                Ok(msg) => return Some(msg),
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    let mut tmp = [0u8; 2048];
                    match self.recv.read(&mut tmp).await {
                        Ok(Some(n)) => self.buf.extend_from_slice(&tmp[..n]),
                        _ => return None,
                    }
                }
                Err(e) => panic!("the peer could not decode what the client wrote: {e}"),
            }
        }
    }
}

/// Answer one client's setup the way `draft` does, then hold the connection
/// open until the client goes.
async fn serve(endpoint: quinn::Endpoint, draft: DraftVersion) {
    let Some(incoming) = endpoint.accept().await else { return };
    let Ok(conn) = incoming.await else { return };
    if unidirectional_control(draft) {
        let Ok(recv) = conn.accept_uni().await else { return };
        let mut control = PeerStream { recv, draft, buf: Vec::new() };
        let Some(setup) = control.read_control().await else { return };
        let mut ours = conn.open_uni().await.expect("open the peer's control stream");
        ours.write_all(&answer(draft, &setup)).await.expect("write the peer's SETUP");
    } else {
        let Ok((mut send, recv)) = conn.accept_bi().await else { return };
        let mut control = PeerStream { recv, draft, buf: Vec::new() };
        let Some(setup) = control.read_control().await else { return };
        send.write_all(&answer(draft, &setup)).await.expect("write SERVER_SETUP");
    }
    conn.closed().await;
}

#[derive(Default)]
struct Collect(Mutex<Vec<AnyClientEvent>>);

impl AnyConnectionObserver for Collect {
    fn on_event(&self, event: &AnyClientEvent) {
        self.0.lock().expect("observer lock").push(event.clone());
    }
}

fn config(draft: DraftVersion) -> AnyClientConfig {
    // Draft-07 Section 6.2.2.1 requires ROLE of both endpoints, and the client
    // sends what it is given; PubSub (0x03). No later draft has the parameter.
    let setup_parameters = if draft == DraftVersion::Draft07 {
        vec![KeyValuePair {
            key: VarInt::from_u64(0x00).expect("a key is a varint"),
            value: KvpValue::Bytes(vec![0x03]),
        }]
    } else {
        Vec::new()
    };
    AnyClientConfig {
        draft,
        additional_versions: Vec::new(),
        transport: AnyTransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters,
    }
}

/// Every compiled draft is adopted and says which draft it negotiated; every
/// draft the build leaves out is refused by the facade before anything is
/// written.
///
/// The second half is what makes the first worth reading: it shows the
/// refusal this test looks for is the one a missing row produces.
#[tokio::test]
async fn adopt_accepts_every_compiled_draft_and_reports_its_version() {
    common::init_crypto();

    for draft in DraftVersion::ALL {
        let (endpoint, addr) = common::spawn_server(&[draft.quic_alpn()]);
        let peer = tokio::spawn(serve(endpoint, draft));

        let (transport, _) = tokio::time::timeout(
            PATIENCE,
            dial_quic(
                &addr.to_string(),
                &QuicDialOptions::new(vec![draft.quic_alpn().to_vec()]).insecure(true),
            ),
        )
        .await
        .expect("the dial completes within the timeout")
        .expect("dial");

        let adopted =
            tokio::time::timeout(PATIENCE, AnyConnection::adopt(transport, config(draft)))
                .await
                .unwrap_or_else(|_| panic!("{draft:?}: adopt did not finish"));

        if !compiled(draft) {
            let err = adopted.err().unwrap_or_else(|| {
                panic!("{draft:?} is not compiled into this build and adopt accepted it")
            });
            assert_eq!(err.cause(), &ErrorCause::Facade, "{draft:?}: {err}");
            assert!(err.message().contains("not enabled in this build"), "{draft:?}: {err}");
            peer.abort();
            continue;
        }

        let mut conn = match adopted {
            Ok(conn) => conn,
            Err(err) if err.message().contains("not enabled in this build") => panic!(
                "{draft:?} is compiled into this build and adopt refused it as not enabled: \
                 {err}"
            ),
            Err(err) => panic!("{draft:?}: adopt failed: {err}"),
        };
        assert_eq!(conn.draft(), draft, "adopt ran another draft's module");

        let events = Arc::new(Collect::default());
        conn.set_observer(events.clone());
        let reported: Vec<u64> =
            events.0.lock().expect("observer lock").iter().filter_map(setup_complete).collect();
        assert_eq!(
            reported.first().copied(),
            Some(draft.version_varint().into_inner()),
            "{draft:?} reported another draft's version in SetupComplete"
        );

        conn.close(0, b"");
        drop(conn);
        let _ = tokio::time::timeout(PATIENCE, peer).await;
    }
}

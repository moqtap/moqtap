#![cfg(feature = "draft16")]

//! What `dial_quic` learns from the handshake, and what `adopt` does with it.
//!
//! From draft-15 the ALPN *is* the version negotiation. Draft-16's
//! `ClientSetup` and `ServerSetup` carry a parameter list and nothing else,
//! where draft-14's `ClientSetup` carries `supported_versions` — so on those
//! drafts the protocol the server selected is the only thing that names the
//! draft, and `DraftVersion::from_alpn` answers for `moqt-15` through
//! `moqt-19` and nothing else. Drafts 07 through 14 share `moq-00` and settle
//! their version inside CLIENT_SETUP instead.
//!
//! `Connection::connect` cannot ask the question: it derives its single ALPN
//! from the draft it was handed, so a caller that does not know a peer's draft
//! has to dial once per candidate. `dial_quic` offers a list and returns what
//! came back; `Connection::adopt` runs the setup handshake over a transport
//! somebody else established. The pair is the feature and neither half is
//! reachable through `connect`.
//!
//! Draft-16 rather than draft-14 because the discrimination does not exist
//! below draft-15: a server answering `moq-00` has told a client nothing about
//! which of eight drafts it speaks, so a gate written there would assert that
//! a constant came back.
//!
//! # What the negotiated value is worth asserting against
//!
//! `dial_quic` reads it through
//! `handshake_data()?.downcast::<HandshakeData>().ok()?.protocol` — three
//! fallible steps collapsing to one `None`, which the return type documents as
//! "the server selected none". A downcast that stopped matching would report
//! exactly that, on every dial, and `adopt` would then be handed whichever
//! draft the caller guessed. The first test below is what separates the two
//! readings of `None`: it names a protocol the server really did select, so
//! `None` there cannot be explained as an honest silence.
//!
//! # Ablation, measured
//!
//! Replacing the body of `transport::quic::negotiated_alpn` with `None` — the
//! shape a quinn release that renamed `HandshakeData` would produce silently:
//!
//! ```text
//! the_dial_reports_the_protocol_the_server_selected
//!   the server selected a protocol, so the dial must report one rather than None
//!
//! a_dialled_transport_completes_the_handshake_through_adopt
//!   the dial must name a draft, which is the whole reason to dial this way
//! ```
//!
//! `a_server_sharing_no_protocol_refuses_the_dial` stays green under that cut,
//! which is correct and is why it is a third test rather than another
//! assertion in the first: it is about the dial failing, not about the value a
//! successful dial reports. The file was restored byte for byte afterwards.

mod common;

use std::time::Duration;

use moqtap_client::draft16::connection::{ClientConfig, Connection, TransportType};
use moqtap_client::transport::{dial_quic, QuicDialOptions};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
use moqtap_codec::version::DraftVersion;

const PATIENCE: Duration = Duration::from_secs(10);

/// Every ALPN this crate can offer, in the order a caller with no idea which
/// draft a peer speaks would offer them.
fn every_alpn() -> Vec<Vec<u8>> {
    [
        DraftVersion::Draft19,
        DraftVersion::Draft18,
        DraftVersion::Draft17,
        DraftVersion::Draft16,
        DraftVersion::Draft15,
        DraftVersion::Draft14,
    ]
    .iter()
    .map(|d| d.quic_alpn().to_vec())
    .collect()
}

fn options(alpn: Vec<Vec<u8>>) -> QuicDialOptions {
    QuicDialOptions { skip_cert_verification: true, ca_certs: Vec::new(), alpn }
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft16,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

/// The protocol the server selected is the one the dial reports.
///
/// The server offers exactly one and the client offers six, so a return value
/// that merely echoed the client's first preference would be `moqt-19` and a
/// value read off the handshake is `moqt-16`. They are different on purpose:
/// an implementation that returned its own request rather than the answer
/// would pass a test where the two agree.
#[tokio::test]
async fn the_dial_reports_the_protocol_the_server_selected() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let server = tokio::spawn(async move {
        let _ = endpoint.accept().await.expect("accept").await;
    });

    let (_transport, negotiated) =
        tokio::time::timeout(PATIENCE, dial_quic(&addr.to_string(), &options(every_alpn())))
            .await
            .expect("the dial completes within the timeout")
            .expect("the dial succeeds against a server sharing a protocol");

    let negotiated = negotiated
        .expect("the server selected a protocol, so the dial must report one rather than None");
    assert_eq!(
        negotiated,
        DraftVersion::Draft16.quic_alpn(),
        "the reported protocol must be the server's choice, not the client's first preference"
    );
    assert_eq!(
        DraftVersion::from_alpn(&negotiated),
        Some(DraftVersion::Draft16),
        "the reported protocol has to be one a draft can be resolved from, or the value is \
         useless to the caller it was added for"
    );

    let _ = tokio::time::timeout(PATIENCE, server).await;
}

/// A peer with no protocol in common refuses the connection outright.
///
/// The alternative worth ruling out is a dial that succeeds with nothing
/// agreed and reports `None`, which a caller would then have to tell apart
/// from a peer that negotiated no ALPN at all.
#[tokio::test]
async fn a_server_sharing_no_protocol_refuses_the_dial() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let server = tokio::spawn(async move {
        // The handshake fails on the server side too; the accept is here so
        // the failure is the ALPN mismatch and not an unreachable port.
        if let Some(incoming) = endpoint.accept().await {
            let _ = incoming.await;
        }
    });

    let alpn = vec![DraftVersion::Draft19.quic_alpn().to_vec()];
    let outcome = tokio::time::timeout(PATIENCE, dial_quic(&addr.to_string(), &options(alpn)))
        .await
        .expect("the dial resolves within the timeout");

    match outcome {
        Err(_) => {}
        Ok((_, negotiated)) => panic!(
            "a dial sharing no protocol with the server must fail rather than connect with \
             nothing agreed; it returned {negotiated:?}"
        ),
    }

    let _ = tokio::time::timeout(PATIENCE, server).await;
}

/// The pair, doing the job it was added for: dial without knowing the draft,
/// then bring the transport to the module the answer names.
///
/// `Connection::connect` is not reachable from here — it would have had to be
/// told a draft before the dial that decides it.
#[tokio::test]
async fn a_dialled_transport_completes_the_handshake_through_adopt() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let server = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft16);

        let (msg, _) = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        assert!(
            matches!(msg, AnyControlMessage::Draft16(ControlMessage::ClientSetup(_))),
            "adopt must run the same setup exchange connect does, got {msg:?}"
        );
        let server_setup = AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup {
            parameters: Vec::new(),
        }));
        framed_send.write_control(&server_setup).await.expect("write SERVER_SETUP");
        let _ = conn.closed().await;
    });

    let (transport, negotiated) =
        tokio::time::timeout(PATIENCE, dial_quic(&addr.to_string(), &options(every_alpn())))
            .await
            .expect("the dial completes within the timeout")
            .expect("dial");

    let draft = negotiated
        .as_deref()
        .and_then(DraftVersion::from_alpn)
        .expect("the dial must name a draft, which is the whole reason to dial this way");
    assert_eq!(draft, DraftVersion::Draft16);

    let conn = tokio::time::timeout(PATIENCE, Connection::adopt(transport, client_config()))
        .await
        .expect("the handshake completes within the timeout")
        .expect("adopt must complete the setup over a transport it did not dial");

    drop(conn);
    let _ = tokio::time::timeout(PATIENCE, server).await;
}
